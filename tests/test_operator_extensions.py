"""Offline checks for intent limits, hint files, and brokered preflight."""

import argparse
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pm
from orchestrator import agent_actions


class OperatorExtensionsTests(unittest.TestCase):
    def test_oversized_intent_stops_before_planner(self):
        args = argparse.Namespace(target='10.10.10.10', task='x' * 7000, hints=None)
        with patch.object(pm, 'session_api_key', return_value='key'), patch.object(
                pm, 'run_planner_with_validation_retry') as planner:
            with self.assertRaisesRegex(pm.OperatorError, 'сократите на 1000'):
                pm.op_new(args)
            planner.assert_not_called()

    def test_full_intent_reaches_agent_and_multiline_hints_survive(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.execute('CREATE TABLE tasks(id INTEGER PRIMARY KEY,target TEXT)')
        db.execute("INSERT INTO tasks VALUES(1,'10.10.10.10')")
        db.execute('CREATE TABLE pm_task_intents(task_id INTEGER PRIMARY KEY,intent TEXT,created_at TEXT)')
        with patch('orchestrator.network_workflow.load_task_target', return_value='10.10.10.10'):
            pm.save_task_intent(db, 1, 'x' * 5900)
            self.assertEqual(agent_actions.task_context(db, 1)['intent'], 'x' * 5900)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'hint.txt'
                code = 'print("hello")\nprint(\'world\')\n'
                path.write_text(code, encoding='utf-8')
                text = pm.compose_task_description('Задача', '', pm.read_hints(
                    argparse.Namespace(hints=None, hints_file=str(path))))
                pm.restore_task_intent(db, 1, text, 'test')
                self.assertIn(code.strip(), agent_actions.task_context(db, 1)['intent'])

    def test_preflight_uses_broker_exec_and_audits_failure(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.execute('CREATE TABLE pm_tcp_full_scan_attempts('
                   'id INTEGER PRIMARY KEY,task_id INTEGER,target TEXT,status TEXT,error TEXT,created_at TEXT)')
        db.execute('CREATE TABLE pm_tcp_full_scans(task_id INTEGER,target TEXT,last_seen_at TEXT)')
        db.execute("INSERT INTO pm_tcp_full_scans VALUES(1,'127.0.0.1',NULL)")
        def broker(command, **kwargs):
            self.assertEqual(command[:5], ['run', '--task-id', '1', '--profile', 'exec'])
            argv = [item[7:] for item in command if item.startswith('--argv=')]
            result = subprocess.run(argv, capture_output=True, text=True, timeout=12)
            return {'status': 'completed', 'exit_code': result.returncode,
                    'stdout': result.stdout, 'stderr': result.stderr}, 0
        with patch.object(pm, 'sudo_checked', broker):
            result = pm.preflight_target(db, 1, '127.0.0.1', [1], timeout=0.1)
        self.assertEqual(result['reachable'], [])
        self.assertEqual(result['unreachable'], [1])
        self.assertEqual(db.execute('SELECT status FROM pm_tcp_full_scan_attempts').fetchone()[0],
                         'preflight_fail')

    def test_unreachable_stops_before_scheduler_without_changing_scan(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.execute('CREATE TABLE pm_tcp_full_scans(task_id INTEGER,target TEXT,status TEXT,'
                   'open_ports_json TEXT,last_seen_at TEXT,created_at TEXT)')
        db.execute("INSERT INTO pm_tcp_full_scans VALUES(1,'10.10.10.10','completed','[80,443]',NULL,'earlier')")
        args = argparse.Namespace(max_jobs=8, force_unreachable=False)
        with patch.object(pm, 'run_full_tcp_scan', return_value=0), patch.object(
                pm, 'preflight_target', return_value={'reachable': [], 'unreachable': [80, 443],
                                                      'checked_at': 'now'}), patch.object(
                pm, 'call_scheduler') as scheduler:
            with self.assertRaisesRegex(pm.OperatorError, '80, 443'):
                pm.launch_configured_task(db, 1, '10.10.10.10', args)
            scheduler.assert_not_called()
        self.assertEqual(db.execute('SELECT status FROM pm_tcp_full_scans').fetchone()[0],
                         'completed')


if __name__ == '__main__':
    unittest.main()
