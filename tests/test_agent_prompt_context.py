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


if __name__ == '__main__':
    unittest.main()
