"""Offline prompt regressions with temporary evidence and in-memory task data."""

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from intent_limits import INTENT_MAX, clip_intent
from orchestrator import agent_actions as actions


class AgentPromptContextTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ('CAPABILITY_LOG', 'TASK_WORK_BASE', 'REPORT_DIR'):
            patcher = patch.object(actions, name, self.root / name)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        actions.ensure_schema(self.db)
        actions.fact_state.ensure_schema(self.db)
        self.db.executescript('''
            CREATE TABLE tasks(id INTEGER PRIMARY KEY, target TEXT);
            INSERT INTO tasks VALUES(11, '203.0.113.10');
            CREATE TABLE task_scope_settings(task_id INTEGER, initial_target TEXT);
            INSERT INTO task_scope_settings VALUES(11, '203.0.113.10');
            CREATE TABLE pm_task_intents(task_id INTEGER PRIMARY KEY, intent TEXT);
        ''')

    def context(self, intent):
        self.db.execute('INSERT OR REPLACE INTO pm_task_intents VALUES(11, ?)', (intent,))
        return actions.task_context(self.db, 11)

    def prompts(self, context, role='access', objective='Check the observed HTTP endpoint'):
        args = (self.db, context, role, objective, 2, 7, 15)
        return actions.build_prompt(*args), actions.compact_prompt(*args, reason='test recovery')

    def test_operator_goal_constraints_and_multiline_hints_survive_compaction(self):
        intents = (
            'Найди и подтверди флаги. Ограничения: без брутфорса; не менять данные.\n'
            'Подсказки:\n  Начни с /status.\n\n  print("проверка")\n  Сохрани отступы.\n',
            'Find and verify flags. Constraints: no brute force; do not modify data.\n'
            'Hints:\n  Start with /status.\n\n  print("check")\n  Keep indentation.\n',
        )
        for intent in intents:
            for role in actions.ROLES:
                with self.subTest(language=intent[:12], role=role):
                    context = self.context(intent)
                    self.assertEqual(context['intent'], intent)
                    full, compact = self.prompts(context, role)
                    for prompt in (full, compact):
                        self.assertIn('Objective from the operator (authoritative scope and goal):\n'
                                      + intent + '\n', prompt)
                        self.assertIn('objective of this round: check the observed http endpoint',
                                      prompt.lower())

    def test_intent_near_limit_is_not_clipped_again(self):
        for size in (INTENT_MAX - 1, INTENT_MAX, INTENT_MAX + 1):
            for filler in ('я', 'x'):
                with self.subTest(size=size, filler=filler):
                    head = 'Goal: verify flags / найти флаги.\nHints:\n  first\n\n  second\n'
                    tail = '\nбез брутфорса / no brute force'
                    intent = head + filler * (size - len(head) - len(tail)) + tail
                    context = self.context(intent)
                    self.assertEqual(context['intent'], clip_intent(intent))
                    for prompt in self.prompts(context, objective=''):
                        self.assertIn(context['intent'] + '\n', prompt)
                        self.assertIn('advance the assessment as far as the evidence allows', prompt)

    def test_empty_and_partial_intent_use_same_default(self):
        default = 'Find and verify the flags on the target, then report impact.'
        for extra in ({}, {'intent': ''}, {'intent': None}):
            with self.subTest(context=extra):
                for prompt in self.prompts({'task_id': 11, **extra}):
                    self.assertIn(default, prompt)
                    self.assertIn('unknown', prompt)

    def test_compaction_retains_history_state_and_report_contract(self):
        actions.CAPABILITY_LOG.mkdir()
        records = [{'id': f'{index:024x}', 'task_id': 11, 'tool': 'net_exec',
                    'result': {'status': 'completed', 'stdout': f'evidence {index}'}}
                   for index in range(8)]
        (actions.CAPABILITY_LOG / 'task_11.jsonl').write_text(
            ''.join(json.dumps(record) + '\n' for record in records), encoding='utf-8')
        actions.fact_state.save_hypotheses(self.db, 11, 'test', {'hypotheses': [
            {'claim': 'refuted endpoint', 'kind': 'hypothesis', 'result': 'refuted',
             'probe_result_id': records[0]['id'], 'quote': 'evidence 0'},
            {'claim': 'open question', 'kind': 'hypothesis', 'result': 'untested'},
        ]})
        actions.fact_state.record_asset(self.db, 11, 'port', '8080', 'dead',
                                        records[0]['id'], 'evidence 0',
                                        {records[0]['id']: {'text': 'evidence 0'}})
        notes = actions.TASK_WORK_BASE / '11' / 'NOTES.md'
        notes.parent.mkdir(parents=True)
        notes.write_text('Сохранённая заметка', encoding='utf-8')
        full, compact = self.prompts(self.context('Find flags; no brute force'))
        for prompt in (full, compact):
            self.assertIn(actions.REPORT_CONTRACT, prompt)
            for expected in ('Сохранённая заметка', 'refuted endpoint', 'open question',
                             '8080', 'dead', records[0]['id']):
                self.assertIn(expected, prompt)
        for record in records:
            self.assertIn(record['id'], compact)
        self.assertIn('evidence 7', compact)
        self.assertIn('Access state (a previous prose claim is not proof):', full)

    def section(self, prompt, heading):
        self.assertIn(heading + '\n', prompt)
        return json.JSONDecoder().raw_decode(prompt.split(heading + '\n', 1)[1])[0]

    def saved_access(self, task_id=11, level='user', categories=('who',)):
        report = {'access_level': level, 'access_signal': 'shell',
                  'access_probe_result_id': f'access-{task_id}-{level}',
                  'triage': {category: {'summary': f'{level}: {category}',
                                       'result_id': f'{task_id}-{level}-{category}',
                                       'quote': f'exact {category} output'}
                             for category in categories}}
        actions.fact_state.save_access_report(self.db, task_id, report)
        return report

    def test_access_and_current_level_triage_survive_compaction(self):
        for categories in ((), ('who', 'where'), actions.fact_state.TRIAGE_FIELDS):
            with self.subTest(categories=categories):
                self.db.execute('DELETE FROM pm_access_triage')
                self.db.execute('DELETE FROM pm_access_state')
                report = self.saved_access(categories=categories)
                expected = actions.fact_state.access_state(self.db, 11)
                self.assertEqual(expected['triage_done'], len(categories) == 6)
                self.assertEqual(expected['pending'], len(categories) != 6)
                context = self.context('без брутфорса')
                before = list(self.db.iterdump())
                for prompt in reversed(self.prompts(context)):
                    self.assertEqual(self.section(prompt, 'Access state (a previous prose claim is not proof):'),
                                     expected)
                    triage = self.section(prompt, 'Saved triage for current access level (evidence-linked):')
                    self.assertEqual(triage, {'level': 'user', 'categories': report['triage']})
                self.assertEqual(list(self.db.iterdump()), before)

    def test_no_access_and_unverified_claim_are_not_upgraded(self):
        for signal in ('none', 'claimed_unverified'):
            with self.subTest(signal=signal):
                if signal != 'none':
                    self.db.execute('INSERT INTO pm_access_state '
                                    '(task_id,level,signal,updated_at) VALUES (11,?,?,?)',
                                    ('none', signal, 'before'))
                expected = actions.fact_state.access_state(self.db, 11)
                for prompt in self.prompts(self.context('Find flags')):
                    self.assertEqual(self.section(prompt, 'Access state (a previous prose claim is not proof):'),
                                     expected)
                    self.assertEqual(self.section(prompt, 'Saved triage for current access level (evidence-linked):'),
                                     {'level': 'none', 'categories': {}})

    def observation(self, claim, task_id=11, kind='observation', status='confirmed',
                    quote='exact output', result_id='old-result'):
        actions.fact_state.save_hypotheses(self.db, task_id, 'test', {'hypotheses': [
            {'claim': claim, 'kind': kind, 'result': status,
             'probe_result_id': result_id, 'quote': quote}]})

    def test_old_observation_is_structured_and_task_and_level_scoped(self):
        self.saved_access(level='exec', categories=actions.fact_state.TRIAGE_FIELDS)
        report = self.saved_access(level='user', categories=('who',))
        self.saved_access(task_id=22, level='privileged', categories=actions.fact_state.TRIAGE_FIELDS)
        self.observation('Старое подтверждённое наблюдение')
        self.observation('FOREIGN observation', task_id=22)
        self.observation('unverified hypothesis', kind='hypothesis', status='untested')
        self.observation('confirmed inference', kind='inference')
        self.observation('missing quote', quote='')
        self.observation('missing result', result_id='')
        actions.CAPABILITY_LOG.mkdir()
        records = [{'id': 'old-result' if i == 0 else f'result-{i}', 'task_id': 11,
                    'tool': 'net_exec', 'result': {'status': 'completed', 'stdout': 'exact output'}}
                   for i in range(8)]
        (actions.CAPABILITY_LOG / 'task_11.jsonl').write_text(
            ''.join(json.dumps(record) + '\n' for record in records), encoding='utf-8')
        context = self.context('Find flags; no brute force')
        before = list(self.db.iterdump())
        history = actions.compact_history(self.db, 11)
        self.assertNotIn('old-result', [item['result_id'] for item in history['full_results']])
        self.assertIn('essential_state', history)
        for prompt in self.prompts(context):
            observations = self.section(prompt, 'Confirmed observations (evidence-linked; bounded selection):')
            self.assertEqual(observations['items'], [
                {'claim': 'Старое подтверждённое наблюдение', 'probe_result_id': 'old-result',
                 'quote': 'exact output'}])
            self.assertEqual(observations['omitted'], 0)
            self.assertEqual(observations, history['essential_state']['observations'])
            self.assertEqual(self.section(prompt, 'Access state (a previous prose claim is not proof):'),
                             history['essential_state']['access_state'])
            self.assertNotIn('FOREIGN', prompt)
            self.assertNotIn('access-22', prompt)
            self.assertEqual(self.section(prompt, 'Saved triage for current access level (evidence-linked):'),
                             {'level': 'user', 'categories': report['triage']})
        self.assertEqual(list(self.db.iterdump()), before)

    def test_observation_limit_reports_omissions_and_filters_before_limiting(self):
        # More recent open hypotheses must not displace proved observations.
        for index in range(15):
            self.observation(f'confirmed {index}')
        for index in range(110):
            self.observation(f'open {index}', kind='hypothesis', status='untested')
        self.db.execute("UPDATE pm_hypotheses SET updated_at='2020-01-01' WHERE kind='observation'")
        context = self.context('Find flags')
        for prompt in self.prompts(context):
            observations = self.section(prompt, 'Confirmed observations (evidence-linked; bounded selection):')
            self.assertEqual(len(observations['items']), 12)
            self.assertEqual(observations['total'], 15)
            self.assertEqual(observations['omitted'], 3)
            self.assertEqual(observations['limit'], 12)
        # Repeated builds select the same records even when timestamps tie.
        self.assertEqual(self.prompts(context), self.prompts(context))


if __name__ == '__main__':
    unittest.main()
