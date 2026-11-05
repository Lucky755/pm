"""Real PM/scheduler/SQLite first run; only executor IO and optional Burp are fake."""
from contextlib import closing, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pm
from executor import task_scope
from orchestrator import bootstrap_discovery, coordinated_attack, diagnostics, evidence_pipeline as evidence
from orchestrator import http_artifacts, http_discovery, master_scheduler as scheduler, network_jobs
from orchestrator import task_runtime


class ExecutorProcess:
    """subprocess.run stays real, including functions retaining it as a default."""
    def __init__(self, args, payload, **kwargs):
        self.args = args
        self.returncode = 0
        body = json.dumps(payload)
        self.stdout = body if kwargs.get('text') else body.encode()
        self.stderr = '' if kwargs.get('text') else b''

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def communicate(self, input=None, timeout=None):
        return self.stdout, self.stderr

    def poll(self):
        return self.returncode


class SchedulerFirstRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pm-scheduler-first-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.database = self.root / 'tasks.db'
        self.target = '10.0.0.80'
        self.console = io.StringIO()
        self.calls = []
        self.burp_reads = []
        for manager in (redirect_stdout(self.console), redirect_stderr(self.console)):
            manager.__enter__(); self.addCleanup(manager.__exit__, None, None, None)
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('CREATE TABLE tasks(id INTEGER PRIMARY KEY,target TEXT)')
            db.execute('INSERT INTO tasks VALUES(1,?)', (self.target,))
            task_scope.initialize(db)
            task_scope.init_task_scope(db, 1)
        services = self.root / 'nmap-services'
        services.write_text('\n'.join(f'service{p}\t{p}/tcp\t{1/p:.8f}' for p in range(1, 1300)))
        burp = SimpleNamespace(list_history=self.burp_history)
        for patcher in (
                patch.object(pm, 'DB', self.database),
                patch.object(evidence, 'DB_PATH', self.database),
                patch.object(evidence, 'load_burp', return_value=burp),
                patch.object(scheduler, 'ROOT', self.root),
                patch.object(coordinated_attack, 'LOCK_DIR', self.root / 'locks'),
                patch.object(diagnostics, 'EVENT_DIR', self.root / 'events'),
                patch.object(http_artifacts, 'ROOT', self.root / 'http'),
                patch.object(bootstrap_discovery, 'SERVICES', (services,)),
                patch.dict(os.environ, {key: '' for key in diagnostics.ENV_KEYS}),
                patch.object(subprocess, 'Popen', side_effect=self.executor_process),
                patch.object(coordinated_attack, 'choose_with_model', side_effect=AssertionError('model called'))):
            patcher.start(); self.addCleanup(patcher.stop)
        self.db = pm.connect()
        self.addCleanup(self.db.close)
        pm.ask_approval(self.db, 1, self.target, 'tun0', show=False, auto=True)

    def burp_history(self, task_id, limit=50):
        self.assertEqual(task_id, 1)
        self.burp_reads.append(task_id)
        return {'host': self.target, 'observations': []}

    def executor_process(self, command, **kwargs):
        self.calls.append(list(command))
        if command == [http_discovery.BROKER, 'capabilities']:
            return ExecutorProcess(command, {'capture_protocol': 1, 'profiles': ['http_capture'],
                                   'capture_limits': [2*1024*1024, 8*1024*1024]}, **kwargs)
        if command[:3] == ['sudo', '-n', pm.BROKER]:
            profile = command[command.index('--profile') + 1]
            if profile == 'tcp_full':
                body = '22/tcp open ssh\n8080/tcp open http-proxy\nNmap done: fixture complete'
                payload = {'status': 'completed', 'exit_code': 0, 'output_truncated': False, 'stdout': body}
            else:
                self.assertEqual(profile, 'exec')  # Real preflight parses the fake broker response.
                argv = [item[7:] for item in command if item.startswith('--argv=')]
                self.assertEqual((argv[-3], json.loads(argv[-2])), (self.target, [22, 8080]))
                payload = {'status': 'completed', 'exit_code': 0, 'stdout': json.dumps(
                    {'reachable': [22, 8080], 'unreachable': [], 'unchecked': []})}
            return ExecutorProcess(command, payload, **kwargs)
        self.assertEqual(Path(command[1]).name, 'network_executor_isolated.py')
        profile = command[command.index('--profile') + 1]
        self.assertIn(profile, ('tcp_ports', 'http_headers', 'service_versions'))
        self.assertEqual(command[command.index('--target') + 1], self.target)
        self.assertEqual(command[command.index('--task-id') + 1], '1')
        body = ('22/tcp open ssh\n8080/tcp open http-proxy\nNmap done: fixture complete'
                if profile == 'tcp_ports' else 'HTTP/1.1 200 OK\nContent-Type: text/plain\n')
        return ExecutorProcess(command, {'status': 'completed' if '--execute' in command else 'planned',
                               'task_id': 1, 'target': self.target, 'profile': profile,
                               'argv': ['/usr/bin/nmap', '-sT', self.target],
                               'exit_code': 0, 'stdout': body, 'stderr': ''}, **kwargs)

    def launch(self, jobs=2):
        with patch.object(sys, 'argv', ['pm', 'resume', '1', '--coordinated', '--continue-coordinated',
                                        '--max-jobs', str(jobs), '--max-rounds', '2']):
            args = pm.parser_main()[1]
        return pm.launch_coordinated_task(self.db, 1, self.target, args)

    def test_successful_preflight_reaches_real_scheduler_round_and_snapshot(self):
        self.assertFalse(self.db.execute("SELECT name FROM sqlite_master WHERE name LIKE 'evidence_%'").fetchall())
        with diagnostics.run('first scheduler launch', 1):
            result = self.launch()
        self.assertEqual(result['stop_reason'], 'reconnaissance_job_budget')
        self.assertFalse(result['succeeded'])
        self.assertEqual(self.db.execute('SELECT status,open_ports_json,followup_status FROM pm_tcp_full_scans').fetchone(),
                         ('completed', '[22, 8080]', 'completed'))
        self.assertEqual(self.db.execute('SELECT status FROM pm_tcp_full_scan_attempts ORDER BY id').fetchall(),
                         [('completed',), ('preflight_ok',)])
        self.assertEqual(self.db.execute('SELECT status FROM network_job_runs').fetchall(), [('completed',)])
        self.assertEqual(self.db.execute('SELECT status,stop_reason FROM master_auto_runs').fetchone(),
                         ('completed', 'job_budget'))
        self.assertEqual(self.db.execute('SELECT status FROM master_auto_rounds').fetchall(), [('completed',)])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM network_observations').fetchone()[0], 2)
        self.assertGreaterEqual(self.db.execute('SELECT COUNT(*) FROM evidence_snapshots').fetchone()[0], 2)
        digest, bundle = evidence.make_snapshot(self.db, 1)
        self.assertEqual(len(bundle['network_observations']), 2)
        self.assertEqual(evidence.saved_reports(self.db, 1, digest), {})
        self.assertGreaterEqual(len(self.burp_reads), 4)
        self.assertEqual(len([c for c in self.calls if 'tcp_full' in c]), 1)
        self.assertEqual(len([c for c in self.calls if '--execute' in c and 'tcp_ports' in c]), 1)
        required = {'network_phase_plans', 'network_job_runs', 'network_observations',
                    'evidence_snapshots', 'evidence_agent_reports', 'master_auto_runs', 'master_auto_rounds',
                    'pm_http_discovery', 'pm_http_size_recovery', 'pm_http_metadata_refresh',
                    'pm_http_document_refresh', 'pm_http_capture_refresh', 'pm_http_capture_upgrades',
                    'pm_http_artifacts', 'pm_http_capture_policy'}
        tables = {r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue(required <= tables, required - tables)

    def test_resume_after_old_missing_schema_failure_keeps_scan_and_queue(self):
        # Reproduce the durable state left by 67ea6d5, using the real scan/queue path.
        self.assertEqual(pm.run_full_tcp_scan(self.db, 1, self.target), 1)
        self.assertEqual(pm.preflight_target(self.db, 1, self.target, [22, 8080])['reachable'], [22, 8080])
        task_runtime.save_mode(self.db, 1, 'coordinated')
        task_runtime.reconnaissance(self.db, 1, 'waiting_operator', 'reconnaissance_failed')
        plans = self.db.execute('SELECT * FROM network_phase_plans').fetchall()
        self.assertFalse(self.db.execute("SELECT name FROM sqlite_master WHERE name LIKE 'evidence_%'").fetchall())
        self.db.close(); self.db = pm.connect(); self.addCleanup(self.db.close)
        result = self.launch(jobs=1)
        self.assertEqual(result['stop_reason'], 'reconnaissance_job_budget')
        self.assertEqual(self.db.execute('SELECT * FROM network_phase_plans').fetchall(), plans)
        self.assertEqual(self.db.execute('SELECT status,open_ports_json FROM pm_tcp_full_scans').fetchone(),
                         ('completed', '[22, 8080]'))
        self.assertEqual(len([c for c in self.calls if 'tcp_full' in c]), 1)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM network_job_runs').fetchone()[0], 1)
        self.assertEqual(self.db.execute('SELECT status FROM master_auto_rounds').fetchall(), [('completed',)])

    def test_continue_uses_saved_scan_and_deduplicates_real_followup_planners(self):
        self.launch()
        # Preflight legitimately refreshes last_seen_at; the original scan must survive.
        scan_fields = 'id,task_id,target,status,open_ports_json,error,created_at,followup_status,followup_error'
        scan = self.db.execute('SELECT ' + scan_fields + ' FROM pm_tcp_full_scans').fetchall()
        original_plan = self.db.execute('SELECT id FROM network_phase_plans').fetchone()[0]
        self.db.close(); self.db = pm.connect(); self.addCleanup(self.db.close)
        result = self.launch(jobs=1)
        self.assertEqual(result['stop_reason'], 'reconnaissance_job_budget')
        self.assertEqual(self.db.execute('SELECT ' + scan_fields + ' FROM pm_tcp_full_scans').fetchall(), scan)
        self.assertEqual(len([c for c in self.calls if 'tcp_full' in c]), 1)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM network_job_runs WHERE plan_id=?', (original_plan,)).fetchone()[0], 1)
        self.assertEqual(self.db.execute('SELECT status FROM master_auto_rounds ORDER BY run_id').fetchall(),
                         [('completed',), ('completed',)])
        self.assertFalse(self.db.execute('SELECT profile,target,parameters_json FROM network_phase_plans '
                                        'GROUP BY profile,target,parameters_json HAVING COUNT(*)>1').fetchall())

    def test_evidence_initialize_and_connect_preserve_existing_rows(self):
        self.launch()
        digest, _ = evidence.make_snapshot(self.db, 1)
        report = {'summary': 'Saved test report', 'observations_used': [],
                  'uncertainties': [], 'recommended_checks': []}
        with self.db:
            self.db.execute('INSERT INTO evidence_agent_reports VALUES(?,?,?,?,?)',
                            (1, digest, 'recon', json.dumps(report), evidence.now()))
        tables = ('tasks', 'pm_tcp_full_scans', 'pm_tcp_full_scan_attempts', 'network_phase_plans',
                  'network_job_runs', 'network_observations', 'evidence_snapshots', 'evidence_agent_reports',
                  'master_auto_runs', 'master_auto_rounds')
        before = [self.db.execute('SELECT * FROM ' + table).fetchall() for table in tables]
        for _ in range(2):
            evidence.initialize(self.db)
            network_jobs.initialize(self.db)
            pm.initialize_tcp_scans(self.db)
            with closing(evidence.connect()) as other:
                self.assertEqual(evidence.saved_reports(other, 1, digest), {'recon': report})
        self.assertEqual(before, [self.db.execute('SELECT * FROM ' + table).fetchall() for table in tables])


if __name__ == '__main__':
    unittest.main()
