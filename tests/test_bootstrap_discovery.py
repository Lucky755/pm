import importlib.util
import json
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
ORCH = ROOT / 'orchestrator'
package = types.ModuleType('orchestrator')
package.__path__ = [str(ORCH)]
sys.modules['orchestrator'] = package
for name in ('network_workflow', 'network_enrichment'):
    module = types.ModuleType('orchestrator.' + name)
    sys.modules['orchestrator.' + name] = module
    setattr(package, name, module)

spec = importlib.util.spec_from_file_location('bootstrap_under_test', ORCH / 'bootstrap_discovery.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'nmap-services'
        rows = [f'service{i}\t{i}/tcp\t{(2000-i)/2000:.6f}' for i in range(1, 1300)]
        self.path.write_text('\n'.join(rows))
        self.patch = patch.object(b, 'ranking', lambda source=None: b.ranking_original(self.path))
        b.ranking_original = b.ranking
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.db = sqlite3.connect(':memory:')
        self.db.executescript('''CREATE TABLE network_phase_plans (id INTEGER PRIMARY KEY,
         task_id INTEGER,goal TEXT,profile TEXT,target TEXT,parameters_json TEXT,
         argv_json TEXT,model_summary TEXT,status TEXT,created_at TEXT);
         CREATE TABLE network_job_runs (id INTEGER PRIMARY KEY, plan_id INTEGER,status TEXT);
         CREATE TABLE network_observations (id INTEGER PRIMARY KEY, run_id INTEGER,task_id INTEGER,kind TEXT);''')
        self.addCleanup(self.db.close)
        self.scope = patch.object(b, 'safe_task_target', return_value='10.10.10.161')
        self.scope.start()
        self.addCleanup(self.scope.stop)
        self.exec = patch.object(b, 'validate_plan', side_effect=lambda tid,tgt,ports: ['/usr/bin/nmap','-p',ports,tgt])
        self.exec.start()
        self.addCleanup(self.exec.stop)

    def test_nmap_frequency_order(self):
        ranked = b.ranking()
        self.assertEqual(ranked[:3], [1,2,3])
        self.assertEqual(len(ranked),1024)

    def test_batches_are_bounded_and_idempotent(self):
        new = b.queue_next(self.db,10)
        self.assertEqual(len(new),2)
        self.assertEqual([p['ports'] for p in new],[32,32])
        self.assertEqual(b.queue_next(self.db,10), [])
        state = b.progress(self.db,10)
        self.assertEqual(state['planned_ranked_ports'],64)
        self.assertEqual(state['pending_tcp_batches'],2)

    def test_empty_scan_can_continue(self):
        b.queue_next(self.db,10)
        for (plan_id,) in self.db.execute('SELECT id FROM network_phase_plans'):
            self.db.execute('INSERT INTO network_job_runs(plan_id,status) VALUES (?,?)', (plan_id,'completed'))
        self.assertTrue(b.has_more(self.db,10))
        self.assertEqual(len(b.queue_next(self.db,10)),2)
        self.assertEqual(b.progress(self.db,10)['planned_ranked_ports'],128)

    def test_known_open_port_stops_new_scans(self):
        b.queue_next(self.db,10)
        self.db.execute("INSERT INTO network_job_runs(id,plan_id,status) VALUES (5,1,'completed')")
        self.db.execute("INSERT INTO network_observations(run_id,task_id,kind) VALUES (5,10,'tcp_port_open')")
        self.assertFalse(b.has_more(self.db,10))
        self.assertEqual(b.queue_next(self.db,10),[])

    def test_dedup_already_planned_ports(self):
        self.db.execute('''INSERT INTO network_phase_plans (task_id,profile,target,parameters_json,status)
                         VALUES (10,'tcp_ports','10.10.10.161',?,'planned')''',
                        (json.dumps({'ports':'1,2,3'},sort_keys=True),))
        new = b.queue_next(self.db,10)
        self.assertEqual(len(new),0) # Old batch still pending, don't queue over it.
        self.db.execute("INSERT INTO network_job_runs(plan_id,status) VALUES (1,'completed')")
        new = b.queue_next(self.db,10)
        self.assertEqual(len(new),2)
        row=self.db.execute('SELECT parameters_json FROM network_phase_plans WHERE id=2').fetchone()
        self.assertNotIn('1,2,3,',json.loads(row[0])['ports'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
