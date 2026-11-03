"""Objective completion and attribution regressions using offline evidence."""

import json
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from orchestrator import attack_loop, flag_verify, objectives


class ObjectiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / 'tasks.db'
        with self.db() as db:
            objectives.ensure_schema(db)

    def connect(self):
        return sqlite3.connect(self.database)

    @contextmanager
    def db(self):
        db = self.connect()
        try:
            yield db
            db.commit()
        finally:
            db.close()

    def goals(self, mode='goal-first', count=6):
        with self.db() as db:
            objectives.save_objectives(db, 1, 'Критическое событие на платформе', 2500,
                                       mode == 'goal-exclusive',
                                       [f'{400 - index * 50}:Побочная позиция {index + 1}'
                                        for index in range(count)], mode=mode)

    def set_goal(self, status):
        with self.db() as db:
            db.execute('UPDATE pm_objectives SET status=? WHERE task_id=1 AND key=?',
                       (status, 'goal'))

    def state(self):
        with self.db() as db:
            return objectives.objective_status(db, 1)

    def finish(self, reason, values, expected):
        stage_path = self.root / 'stage.json'
        stage_path.write_text('{}', encoding='utf-8')
        with patch.object(attack_loop.agent_actions, 'connect', self.connect), \
             patch.object(attack_loop.agent_actions, 'REPORT_DIR', self.root), \
             patch.object(attack_loop, 'confirmed_values', return_value=values), \
             patch.object(attack_loop, 'transferred_candidates', return_value=[]), \
             patch.object(attack_loop.fact_state, 'access_state', return_value={}), \
             patch.object(attack_loop.fact_state, 'list_hypotheses', return_value=[]), \
             patch.object(attack_loop.flag_verify, 'listing', return_value=[]):
            return attack_loop.finish(1, [{'iteration': 1, 'role': 'recon',
                                           'status': 'completed', 'report_path': str(stage_path)}],
                                      reason, {}, expected)

    def flag(self, status):
        with self.db() as db:
            db.execute('INSERT INTO pm_verified_flags '
                       '(task_id,value,status,evidence_count,reported_by,sources_json,created_at,updated_at) '
                       'VALUES (1,?,?,?,?,?,?,?)',
                       ('THM{goal_value}', status, 2 if status == 'confirmed' else 1,
                        'recon', '{}', 'now', 'now'))

    def test_01_exclusive_goal_stops_and_succeeds(self):
        self.goals('goal-exclusive')
        self.set_goal('confirmed')
        reason = attack_loop.objective_stop_reason(self.state(), 1, 7)
        result = self.finish(reason, ['THM{goal_value}'], 7)
        self.assertEqual(reason, 'goal_confirmed')
        self.assertTrue(result['succeeded'])

    def test_02_goal_first_continues_to_seven(self):
        self.goals()
        self.set_goal('confirmed')
        self.assertIsNone(attack_loop.objective_stop_reason(self.state(), 2, 7))
        self.assertEqual(attack_loop.objective_stop_reason(self.state(), 7, 7),
                         'objectives_done')

    def test_03_seven_side_flags_cannot_win(self):
        self.goals()
        reason = attack_loop.objective_stop_reason(self.state(), 7, 7)
        result = self.finish(reason, [f'THM{{side_{i}}}' for i in range(7)], 7)
        self.assertEqual(reason, 'flags_without_goal')
        self.assertFalse(result['succeeded'])
        self.assertIn('основная цель не подтверждена', result['problems'])

    def test_04_one_side_flag_cannot_win(self):
        self.goals()
        reason = attack_loop.objective_stop_reason(self.state(), 1, 1)
        self.assertEqual(reason, 'flags_without_goal')
        self.assertFalse(self.finish(reason, ['THM{side_value}'], 1)['succeeded'])

    def test_05_legacy_threshold(self):
        self.assertIsNone(attack_loop.objective_stop_reason(self.state(), 1, 2))
        self.assertEqual(attack_loop.objective_stop_reason(self.state(), 2, 2),
                         'flag_confirmed')

    def test_06_missing_result_id_leaves_goal_open(self):
        self.goals(count=0)
        self.flag('confirmed')
        registry = {'confirmed': [{'value': 'THM{goal_value}', 'status': 'confirmed',
                                   'independent_sources': 2}], 'candidates': []}
        report = {'flags': [{'value': 'THM{goal_value}', 'objective_key': 'goal',
                             'goal_confirmed': True, 'goal_evidence': 'absent'}]}
        with self.db() as db:
            result = objectives.process_report(db, 1, report, registry)
        self.assertEqual(result['primary']['status'], 'open')
        self.assertEqual(registry['candidates'][0]['status'], 'candidate')

    def test_07_one_network_source_marks_attempted(self):
        self.goals(count=0)
        self.flag('candidate')
        log = self.root / 'task_1.jsonl'
        log.write_text(json.dumps({'task_id': 1, 'id': 'probe-1', 'provenance': 'network',
                                   'result': {'status': 'completed',
                                              'stdout': 'THM{goal_value}'}}) + '\n')
        registry = {'confirmed': [], 'candidates': [
            {'value': 'THM{goal_value}', 'status': 'candidate', 'independent_sources': 1}]}
        report = {'flags': [{'value': 'THM{goal_value}', 'objective_key': 'goal',
                             'goal_confirmed': True, 'goal_evidence': 'probe-1'}]}
        with patch.object(flag_verify, 'CAPABILITY_LOG', self.root), self.db() as db:
            result = objectives.process_report(db, 1, report, registry)
        self.assertEqual(result['primary']['status'], 'attempted')
        self.assertEqual(registry['candidates'][0]['status'], 'candidate')

    def test_08_weighted_spec_preserves_slashes(self):
        self.assertEqual(objectives.parse_objective_spec('400:LPE — выполнить /home/peflag'),
                         (400, 'LPE — выполнить /home/peflag'))

    def test_09_escaped_semicolon_and_colon(self):
        self.assertEqual(objectives.split_specs(r'400:LPE\; особое: условие;100:SQLi'),
                         ['400:LPE; особое: условие', '100:SQLi'])

    def test_10_repeat_save_keeps_confirmation(self):
        self.goals(count=1)
        self.set_goal('confirmed')
        with self.db() as db:
            objectives.save_objectives(db, 1, 'Критическое событие на платформе', 2500,
                                       False, ['400:Побочная позиция 1'])
            rows = objectives.list_objectives(db, 1)
            objectives.transfer_objectives(db, 1, 2)
            transferred = objectives.list_objectives(db, 2)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['status'], 'confirmed')
        self.assertEqual(rows[1]['key'], 'obj-1')
        self.assertEqual(transferred[0]['status'], 'attempted')

    def test_11_primary_question_precedes_cheaper_secondary(self):
        self.goals(count=1)
        claims = [
            {'status': 'untested', 'claim': 'Проверить побочную позицию', 'cost': 1,
             'claim_key': 'side', 'objective_key': 'obj-1'},
            {'status': 'untested', 'claim': 'Проверить критическое событие', 'cost': 3,
             'claim_key': 'goal', 'objective_key': 'goal'},
        ]
        text = attack_loop.objective_for('vuln', {}, claims=claims, objectives=self.state())
        self.assertLess(text.index('Проверить критическое событие'),
                        text.index('Проверить побочную позицию'))


if __name__ == '__main__':
    unittest.main()
