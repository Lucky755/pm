"""Offline tests for manual bounded auto loop; no API/network actions."""
import importlib.util
import ipaddress
import sqlite3
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

# Offline stubs allow this test to run without importing any network executor,
# Experiential SDK, or production database. Patch the seam, not the implementation.
package = types.ModuleType('orchestrator')
package.__path__ = [str(ROOT / 'orchestrator')]
sys.modules['orchestrator'] = package
for name in ('evidence_pipeline', 'network_workflow', 'network_enrichment',
             'network_jobs', 'decision_agent'):
    fake = types.ModuleType('orchestrator.' + name)
    setattr(package, name, fake)
    sys.modules['orchestrator.' + name] = fake

spec = importlib.util.spec_from_file_location('auto_scheduler_under_test', ROOT / 'orchestrator/master_scheduler.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class AutoTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.state = {'observations': 1, 'queue': [], 'agent_calls': [],
                      'decisions': 0, 'results_change': True}
        self.patches = []
        def set_attr(obj, attr, value):
            patcher = patch.object(obj, attr, value, create=True)
            patcher.start()
            self.patches.append(patcher)

        set_attr(s, 'validate_task', lambda db, task_id: '127.0.0.1')
        set_attr(s.workflow, 'create_followups', lambda db, task_id: [])
        set_attr(s.enrichment, 'plan_followups', lambda db, task_id, **kwargs: [])
        def snap(db, task_id):
            count = self.state['observations']
            return ('hash_' + str(count), {
                'task_id': task_id, 'authorized_target': '127.0.0.1',
                'network_observations': [{'observation_id': i} for i in range(count)],
                'burp_http_metadata': [],
            })
        set_attr(s.evidence, 'make_snapshot', snap)
        def agents(db, task_id, digest, bundle):
            self.state['agent_calls'].append(digest)
        set_attr(s.evidence, 'run_agents', agents)
        def pend(db, task_id, profiles):
            return [dict(item) for item in self.state['queue']
                    if item['profile'] in profiles]
        set_attr(s, 'pending', pend)
        def exec_pending(db, task_id, profiles, remaining):
            eligible = [x for x in self.state['queue'] if x['profile'] in profiles][:remaining]
            for item in eligible:
                self.state['queue'].remove(item)
                if self.state['results_change']:
                    self.state['observations'] += 1
            return [{'plan_id': x['plan_id'], 'status': 'completed'} for x in eligible]
        set_attr(s, 'execute_pending', exec_pending)
        set_attr(s, 'compact_status', lambda db, task_id: {'task_id': task_id})
        set_attr(s, 'emit', lambda value: None)

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.db.close()

    def test_dry_run_does_not_execute(self):
        self.state['queue'] = [{'plan_id': 42, 'profile': 'http_headers'}]
        result = s.auto(self.db, 9, False, False, True, 3, False, 4)
        self.assertEqual(result['total_jobs'], 0)
        self.assertEqual(result['stop_reason'], 'plan_only')
        self.assertEqual(len(result['rounds']), 1)
        self.assertEqual(len(self.state['queue']), 1)

    def test_budget_across_rounds_and_final_analysis(self):
        def decide(db, task_id):
            self.state['decisions'] += 1
            n = self.state['decisions']
            self.state['queue'].append({'plan_id': n, 'profile': 'http_headers'})
            return {'status': 'completed', 'new_plans': [{'plan_id': n}]}
        patcher = patch.object(s.decisions, 'plan', decide, create=True)
        patcher.start(); self.patches.append(patcher)
        result = s.auto(self.db, 9, True, False, False, 2, True, 5)
        self.assertEqual(result['total_jobs'], 2)
        self.assertEqual(result['stop_reason'], 'job_budget')
        self.assertEqual(len(result['rounds']), 2)
        self.assertIn('hash_3', self.state['agent_calls'])
        self.assertEqual(self.state['decisions'], 2)

    def test_stops_without_new_evidence(self):
        self.state['queue'] = [{'plan_id': 5, 'profile': 'http_headers'}]
        self.state['results_change'] = False
        result = s.auto(self.db, 9, True, False, True, 5, False, 5)
        self.assertEqual(result['total_jobs'], 1)
        self.assertEqual(result['stop_reason'], 'no_new_evidence')
        self.assertEqual(len(result['rounds']), 1)

    def test_cached_decision_never_loops(self):
        def cached(db, task_id):
            return {'status': 'cached', 'new_plans': []}
        patcher = patch.object(s.decisions, 'plan', cached, create=True)
        patcher.start(); self.patches.append(patcher)
        result = s.auto(self.db, 9, True, False, True, 5, True, 5)
        self.assertEqual(result['stop_reason'], 'no_progress')
        self.assertEqual(result['total_jobs'], 0)
        self.assertEqual(len(result['rounds']), 1)

    def test_documentation_target_live_is_blocked(self):
        patcher = patch.object(s, 'validate_task', lambda db, task_id: '192.0.2.10')
        patcher.start(); self.patches.append(patcher)
        with self.assertRaisesRegex(ValueError, 'documentation targets'):
            s.auto(self.db, 7, True, False, True, 1, True, 1)
        self.assertFalse(self.db.execute("SELECT name FROM sqlite_master WHERE name='master_auto_runs'").fetchone())

    def test_failed_model_run_is_audited_and_resumable(self):
        def broken(db, task_id):
            raise ValueError('fake model error')
        patcher = patch.object(s.decisions, 'plan', broken, create=True)
        patcher.start(); self.patches.append(patcher)
        with self.assertRaisesRegex(ValueError, 'fake model error'):
            s.auto(self.db, 9, True, False, True, 2, True, 2)
        status = self.db.execute("SELECT status FROM master_auto_runs").fetchone()[0]
        self.assertEqual(status, 'failed')
        rows = self.db.execute("SELECT status FROM master_auto_rounds").fetchall()
        self.assertEqual(rows, [('failed',)])

if __name__ == '__main__':
    unittest.main(verbosity=2)
