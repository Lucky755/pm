"""Unit tests are offline: no sudo, VPN, GLM, target traffic or real SQLite."""
import importlib.util
import io
import json
import os
import sqlite3
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pm_under_test', ROOT / 'pm.py')
pm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pm)

class Tests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.execute('CREATE TABLE tasks (id INTEGER PRIMARY KEY, target TEXT)')
        self.db.execute('CREATE TABLE task_scope_settings (task_id INTEGER PRIMARY KEY, initial_target TEXT)')
        self.db.execute("INSERT INTO tasks VALUES(10,'10.10.10.161')")
        self.db.execute("INSERT INTO task_scope_settings VALUES(10,'10.10.10.161')")
        self.db.execute('''CREATE TABLE pm_operator_approvals (
            task_id INTEGER PRIMARY KEY,target TEXT, allowed TEXT, egress TEXT,
            approved_at TEXT, closed_at TEXT)''')
        self.db.commit()
    def tearDown(self): self.db.close()

    def test_target_validation(self):
        self.assertEqual(pm.validate_target('10.10.10.161'), '10.10.10.161')
        for bad in ('127.0.0.1', '192.0.2.10', '8.8.8.8/32', 'whatever'):
            with self.assertRaises(pm.OperatorError): pm.validate_target(bad)

    def test_reject_scope_mismatch(self):
        self.db.execute("UPDATE task_scope_settings SET initial_target='10.1.1.1'")
        with self.assertRaisesRegex(pm.OperatorError, 'не совпадает'):
            pm.ensure_task_scope(self.db, 10, '10.10.10.161')

    def test_confirm_exact_target(self):
        with patch('builtins.input', return_value='не подтверждаю'):
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(pm.OperatorError):
                    pm.ask_approval(self.db, 10, '10.10.10.161', 'tun0')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM pm_operator_approvals').fetchone()[0], 0)
        with patch('builtins.input', return_value='10.10.10.161'):
            with redirect_stdout(io.StringIO()):
                self.assertTrue(pm.ask_approval(self.db, 10, '10.10.10.161', 'tun0'))
        self.assertFalse(pm.ask_approval(self.db, 10, '10.10.10.161', 'tun0', show=False))

    def test_change_of_interface_rejected_after_approval(self):
        with patch('builtins.input', return_value='10.10.10.161'), redirect_stdout(io.StringIO()):
            pm.ask_approval(self.db, 10, '10.10.10.161', 'tun0')
        with self.assertRaisesRegex(pm.OperatorError, 'изменились'):
            pm.ask_approval(self.db, 10, '10.10.10.161', 'eth0', show=False)

    def test_reprobe_reject_injection_and_repeat(self):
        for bad in ('22; rm -rf', '22,22', '0', '65536', '1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33'):
            with self.assertRaises(pm.OperatorError): pm.plan_reprobe(self.db, 10, '10.10.10.161', bad)

    def test_docker_policy_check_fail_closed(self):
        with patch.object(pm.subprocess, 'run', return_value=types.SimpleNamespace(returncode=1)):
            with self.assertRaises(pm.OperatorError): pm.docker_forward_drop()

    def test_human_report_no_raw_json(self):
        result = {'task_id': 10, 'target': '10.10.10.161', 'total_jobs': 2,
                  'network_observations': 0, 'burp_observations': 0,
                  'stop_reason': 'job_budget', 'bootstrap_progress': {
                      'attempted_ranked_ports': 100, 'ranked_pool': 1024}}
        module = types.ModuleType('orchestrator.evidence_pipeline')
        module.make_snapshot = lambda db, task_id: ('hash', {'network_observations': []})
        module.saved_reports = lambda db, task_id, digest: {}
        package = types.ModuleType('orchestrator')
        package.evidence_pipeline = module
        with patch.dict('sys.modules', {'orchestrator': package,
                                      'orchestrator.evidence_pipeline': module}):
            out = io.StringIO()
            with redirect_stdout(out): pm.render_results(self.db, result)
            self.assertIn('достигнут лимит', out.getvalue())
            self.assertNotIn('"network_observations"', out.getvalue())

    def test_netguard_existing_mismatch_does_not_run_setup(self):
        wrong = ({'status':'configured', 'allowed':['10.1.1.1/32'], 'egress':'tun0'},0)
        with patch.object(pm, 'broker_is_trusted'), patch.object(pm, 'sudo_authenticate'), \
             patch.object(pm, 'sudo_checked', return_value=wrong) as sudo:
            with self.assertRaisesRegex(pm.OperatorError, 'не соответствует'):
                pm.ensure_netguard(10, '10.10.10.161', 'tun0')
            self.assertEqual(sudo.call_count, 1)


    def test_planner_pty_parses_id_and_hides_raw_json(self):
        script = "import json; print('[1] Requesting plan', flush=True); print('Task ID: 17', flush=True); print('Status: pending_review', flush=True); print(json.dumps({'summary':'Lab test','tasks':[{'agent':'recon','instruction':'Inspect services'}]}), flush=True)"
        out = io.StringIO()
        with redirect_stdout(out):
            task_id, plan = pm.read_planner_stream(['python', '-u', '-c', script])
        self.assertEqual(task_id, 17)
        self.assertEqual(plan['tasks'][0]['agent'], 'recon')
        self.assertIn('Task ID: 17', out.getvalue())
        self.assertNotIn('"tasks":', out.getvalue())

    def test_existing_netguard_with_managed_docker_passes(self):
        data = {'status':'configured','allowed':['10.10.10.161/32'],
                'egress':'tun0','docker_forward_managed':True}
        with patch.object(pm, 'broker_is_trusted'), patch.object(pm, 'sudo_authenticate'), \
             patch.object(pm, 'sudo_checked', return_value=(data, 0)) as broker, \
             patch.object(pm, 'docker_forward_drop', return_value=True), \
             redirect_stdout(io.StringIO()):
            pm.ensure_netguard(10, '10.10.10.161', 'tun0')
        self.assertEqual(broker.call_count, 2)
        self.assertEqual(broker.call_args_list[0].args[0][:1], ['status'])

    def test_docker_drop_without_managed_rules_fails(self):
        data = {'status':'configured','allowed':['10.10.10.161/32'], 'egress':'tun0',
                'docker_forward_managed':False}
        with patch.object(pm, 'broker_is_trusted'), patch.object(pm, 'sudo_authenticate'), \
             patch.object(pm, 'sudo_checked', return_value=(data, 0)), \
             patch.object(pm, 'docker_forward_drop', return_value=True), \
             redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(pm.OperatorError, 'изоляцию'):
                pm.ensure_netguard(10, '10.10.10.161', 'tun0')

    def test_broker_root_owner_check(self):
        with patch.object(pm.Path, 'stat', return_value=types.SimpleNamespace(st_uid=1000,st_mode=0o755)), \
             patch.object(pm.Path, 'is_file', return_value=True), patch.object(pm.Path, 'is_symlink', return_value=False):
            with self.assertRaises(pm.OperatorError): pm.broker_is_trusted()

if __name__ == '__main__': unittest.main(verbosity=2)
