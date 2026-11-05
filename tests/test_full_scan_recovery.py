"""First-run/recovery regressions using real SQLite planners, fake executor IO only."""
from contextlib import closing, redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pm
from executor import task_scope
from orchestrator import bootstrap_discovery, coordinated_attack, diagnostics, network_jobs, network_phase, task_runtime


class FullScanRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pm-first-scan-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.target = '10.0.0.80'
        self.database = self.root / 'tasks.db'
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('CREATE TABLE tasks(id INTEGER PRIMARY KEY,target TEXT)')
            db.execute('INSERT INTO tasks VALUES(1,?)', (self.target,))
            task_scope.initialize(db)
            with redirect_stdout(io.StringIO()):
                task_scope.init_task_scope(db, 1)
        self.console = io.StringIO()
        self.broker_calls = []
        self.executor_calls = []
        self.scan_ports = [22, 8080]
        self.scan_status = 'completed'
        for manager in (redirect_stdout(self.console), redirect_stderr(self.console)):
            manager.__enter__(); self.addCleanup(manager.__exit__, None, None, None)
        for patcher in (
                patch.object(pm, 'DB', self.database),
                patch.object(diagnostics, 'EVENT_DIR', self.root / 'events'),
                patch.object(coordinated_attack, 'LOCK_DIR', self.root / 'locks'),
                patch.dict(os.environ, {key: '' for key in diagnostics.ENV_KEYS}),
                patch.object(pm, 'sudo_checked', side_effect=self.broker),
                patch.object(bootstrap_discovery.subprocess, 'run', side_effect=self.executor),
                patch.object(coordinated_attack, 'choose_with_model', side_effect=AssertionError('model called'))):
            patcher.start(); self.addCleanup(patcher.stop)
        self.db = pm.connect()
        self.addCleanup(self.db.close)

    def stdout(self):
        return '\n'.join(f'{p}/tcp open unknown' for p in self.scan_ports) + '\nNmap done: fixture complete'

    def broker(self, command, **kwargs):
        self.broker_calls.append(command)
        profile = command[command.index('--profile') + 1]
        if profile == 'tcp_full':
            return {'status': self.scan_status, 'stdout': self.stdout(), 'stderr': '',
                    'output_truncated': False}, 0
        self.assertEqual(profile, 'exec')  # The preflight script is NOT executed.
        return {'status': 'completed', 'exit_code': 0, 'stdout': json.dumps(
            {'reachable': [], 'unreachable': self.scan_ports, 'unchecked': []})}, 0

    def executor(self, command, **kwargs):
        """Only the isolated executor's process boundary may be substituted."""
        self.assertEqual(Path(command[1]).name, 'network_executor_isolated.py')
        self.executor_calls.append(command)
        target = command[command.index('--target') + 1]
        task = int(command[command.index('--task-id') + 1])
        profile = command[command.index('--profile') + 1]
        reply = {'status': 'completed' if '--execute' in command else 'planned',
                 'task_id': task, 'target': target, 'profile': profile,
                 'argv': ['/usr/bin/nmap', '-sT', target], 'exit_code': 0,
                 'stdout': 'Nmap done: no new open-port observations', 'stderr': ''}
        return subprocess.CompletedProcess(command, 0, json.dumps(reply), '')

    def initialize_network(self):
        network_phase.initialize_database(self.db)
        network_jobs.initialize(self.db)

    def fail_queue(self, port_string=None):
        self.initialize_network()
        condition = '' if port_string is None else "WHEN NEW.parameters_json = '" + json.dumps({'ports': port_string}) + "'"
        self.db.execute(f'''CREATE TRIGGER fail_followup BEFORE INSERT ON network_phase_plans
            {condition} BEGIN SELECT RAISE(ABORT, 'fixture queue unavailable'); END''')
        self.db.commit()

    def plans(self):
        return self.db.execute('SELECT id,task_id,target,parameters_json FROM network_phase_plans ORDER BY id').fetchall()

    def scan(self):
        return self.db.execute('SELECT status,open_ports_json,error FROM pm_tcp_full_scans WHERE task_id=1').fetchone()

    def launch(self):
        with patch.object(sys, 'argv', ['pm', 'resume', '1', '--coordinated', '--continue-coordinated']):
            args = pm.parser_main()[1]
        return pm.launch_coordinated_task(self.db, 1, self.target, args)

    def test_clean_first_scan_persists_ports_and_queues_real_plan(self):
        self.assertFalse(self.db.execute("SELECT name FROM sqlite_master WHERE name LIKE 'network_%'").fetchall())
        self.assertEqual(pm.run_full_tcp_scan(self.db, 1, self.target), 1)
        self.assertEqual(self.scan(), ('completed', '[22, 8080]', None))
        self.assertEqual(json.loads(self.plans()[0][3]), {'ports': '22,8080'})
        result = json.loads(self.db.execute('SELECT result_json FROM pm_tcp_full_scan_attempts').fetchone()[0])
        self.assertEqual(result['stdout'], self.stdout())
        self.assertEqual(pm.run_full_tcp_scan(self.db, 1, self.target), 0)
        self.assertEqual(len(self.plans()), 1)
        self.assertEqual(len(self.broker_calls), 1)
        self.assertEqual(len(self.executor_calls), 1)

    def test_clean_coordinated_launch_gets_past_scan_and_followup(self):
        result = self.launch()
        self.assertEqual(self.scan(), ('completed', '[22, 8080]', None))
        self.assertEqual(len(self.plans()), 1)
        self.assertEqual(result['stop_reason'], 'reconnaissance_target_unreachable')
        self.assertEqual([cmd[cmd.index('--profile') + 1] for cmd in self.broker_calls], ['tcp_full', 'exec'])

    def test_both_initializers_preserve_all_network_records(self):
        # Jobs/workflow initialization must also work before the model planner ever ran.
        network_jobs.initialize(self.db)
        plan = pm.plan_reprobe(self.db, 1, self.target, '22,8080')
        network_jobs.execute_job(self.db, plan)
        with self.db:
            run = self.db.execute('SELECT id FROM network_job_runs').fetchone()[0]
            self.db.execute('INSERT INTO network_observations(run_id,task_id,target,kind,data_json,observed_at) '
                            "VALUES(?,1,?,'tcp_port_open',?,?)", (run, self.target, '{"port":22}', network_jobs.now()))
        tables = ('network_phase_plans', 'network_job_runs', 'network_observations')
        before = [self.db.execute('SELECT * FROM ' + t).fetchall() for t in tables]
        for _ in range(2):
            self.initialize_network()
        self.assertEqual(before, [self.db.execute('SELECT * FROM ' + t).fetchall() for t in tables])

    def test_direct_reprobe_initializes_network_schema(self):
        plan = pm.plan_reprobe(self.db, 1, self.target, '22')
        self.assertEqual(self.plans()[0][0], plan)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM network_job_runs').fetchone()[0], 0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM network_observations').fetchone()[0], 0)

    def test_additive_scan_migration_preserves_legacy_evidence_and_cache(self):
        with closing(sqlite3.connect(':memory:')) as db, db:
            db.executescript('''CREATE TABLE pm_tcp_full_scans(id INTEGER PRIMARY KEY,task_id INTEGER,
                target TEXT,status TEXT,open_ports_json TEXT,error TEXT,created_at TEXT);
                CREATE TABLE pm_tcp_full_scan_attempts(id INTEGER PRIMARY KEY,task_id INTEGER,
                target TEXT,status TEXT,error TEXT,created_at TEXT);
                INSERT INTO pm_tcp_full_scans VALUES(5,1,'10.0.0.80','completed','[22, 8080]',NULL,'saved');
                INSERT INTO pm_tcp_full_scan_attempts VALUES(6,1,'10.0.0.80','completed',NULL,'saved');''')
            for _ in range(2):
                pm.initialize_tcp_scans(db)
            self.assertEqual(db.execute('SELECT id,status,open_ports_json,error,created_at,followup_status '
                                        'FROM pm_tcp_full_scans').fetchone(),
                             (5, 'completed', '[22, 8080]', None, 'saved', None))
            self.assertEqual(db.execute('SELECT id,status,error,created_at,result_json '
                                        'FROM pm_tcp_full_scan_attempts').fetchone(),
                             (6, 'completed', None, 'saved', None))
            # The old implementation only saved completed after queuing every batch.
            self.assertEqual(pm.run_full_tcp_scan(db, 1, self.target), 0)
            self.assertEqual(self.broker_calls, [])
            self.assertEqual(self.executor_calls, [])

    def test_queue_failure_does_not_fail_successful_scan_or_lose_output(self):
        self.fail_queue()
        with diagnostics.run('queue failure', 1):
            with self.assertRaisesRegex(sqlite3.IntegrityError, 'fixture queue unavailable'):
                pm.run_full_tcp_scan(self.db, 1, self.target)
            events = diagnostics.read_events()
        self.assertEqual(self.scan(), ('completed', '[22, 8080]', None))
        attempt = self.db.execute('SELECT status,error,result_json FROM pm_tcp_full_scan_attempts').fetchone()
        self.assertEqual(attempt[:2], ('completed', None))
        self.assertEqual(json.loads(attempt[2])['stdout'], self.stdout())
        self.assertEqual(self.db.execute('SELECT followup_status FROM pm_tcp_full_scans').fetchone()[0], 'failed')
        self.assertTrue(any(e['kind'] == 'scan.result' and e['status'] == 'completed' for e in events))
        self.assertTrue(any(e['kind'] == 'scan.followups' and e['status'] == 'failed' for e in events))
        self.assertFalse(any(e['kind'] == 'scan.result' and e['status'] == 'failed' for e in events))
        self.assertNotIn('Nmap done:', json.dumps(events))

    def test_explicit_coordinated_resume_repairs_queue_without_scanning(self):
        self.fail_queue()
        task_runtime.save_mode(self.db, 1, 'coordinated')
        with self.assertRaisesRegex(sqlite3.IntegrityError, 'fixture queue unavailable'):
            self.launch()
        self.assertEqual(task_runtime.saved(self.db, 1)['pause_reason'], 'reconnaissance_followup_planning_failed')
        self.db.execute('DROP TRIGGER fail_followup'); self.db.commit()
        # A separate invocation/connection must use the durable checkpoint.
        self.db.close(); self.db = pm.connect(); self.addCleanup(self.db.close)
        self.launch()
        self.assertEqual(len(self.plans()), 1)
        self.assertEqual(len([c for c in self.broker_calls if 'tcp_full' in c]), 1)
        self.assertEqual(len(self.executor_calls), 2)  # Refused insert + successful repair, both plan-only.
        self.assertFalse(any('--execute' in command for command in self.executor_calls))
        self.assertEqual(self.db.execute('SELECT followup_status,followup_error FROM pm_tcp_full_scans').fetchone(),
                         ('completed', None))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM pm_tcp_full_scan_attempts WHERE status=\'completed\'').fetchone()[0], 1)
        self.launch()
        self.assertEqual(len(self.plans()), 1)
        self.assertEqual(len(self.executor_calls), 2)
        # Normal pause preview must stay offline, even with queue/schema repair available.
        with patch.object(sys, 'argv', ['pm', 'resume', '1']):
            args = pm.parser_main()[1]
        before = (len(self.broker_calls), len(self.executor_calls))
        result = pm.op_resume(args)
        self.assertEqual(result['status'], 'waiting_operator')
        self.assertEqual(before, (len(self.broker_calls), len(self.executor_calls)))

    def test_cached_scan_entry_also_repairs_failed_queue(self):
        self.fail_queue()
        with self.assertRaisesRegex(sqlite3.IntegrityError, 'fixture queue unavailable'):
            pm.run_full_tcp_scan(self.db, 1, self.target)
        self.db.execute('DROP TRIGGER fail_followup'); self.db.commit()
        self.assertEqual(pm.run_full_tcp_scan(self.db, 1, self.target), 0)
        self.assertEqual(pm.run_full_tcp_scan(self.db, 1, self.target), 0)
        self.assertEqual(len(self.plans()), 1)
        self.assertEqual(len(self.broker_calls), 1)

    def test_partial_queue_recovery_does_not_duplicate_completed_checks(self):
        self.scan_ports = list(range(1, 34))
        self.fail_queue('33')
        with self.assertRaisesRegex(sqlite3.IntegrityError, 'fixture queue unavailable'):
            pm.run_full_tcp_scan(self.db, 1, self.target)
        first = self.plans()[0][0]
        network_jobs.execute_job(self.db, first)
        self.db.execute('DROP TRIGGER fail_followup'); self.db.commit()
        # The known-port coordinated branch bypasses run_full_tcp_scan().
        self.launch()
        self.assertEqual([json.loads(row[3])['ports'] for row in self.plans()],
                         [','.join(map(str, range(1, 33))), '33'])
        self.assertEqual(self.db.execute('SELECT plan_id,attempt,status FROM network_job_runs').fetchall(),
                         [(first, 1, 'completed')])
        self.assertEqual(len([c for c in self.broker_calls if 'tcp_full' in c]), 1)
        self.launch()
        self.assertEqual(len(self.plans()), 2)
        self.assertEqual(len([c for c in self.executor_calls if '--execute' in c]), 1)

    def test_recovery_subtracts_overlapping_batches_but_not_foreign_plans(self):
        # These plans do not cover port 22 in this task/address.
        pm.plan_reprobe(self.db, 2, self.target, '22')
        pm.plan_reprobe(self.db, 1, '10.0.0.81', '22')
        first = pm.plan_reprobe(self.db, 1, self.target, '8080')
        network_jobs.execute_job(self.db, first)
        self.fail_queue('22')
        with self.assertRaisesRegex(sqlite3.IntegrityError, 'fixture queue unavailable'):
            pm.run_full_tcp_scan(self.db, 1, self.target)
        self.db.execute('DROP TRIGGER fail_followup'); self.db.commit()
        self.launch()
        local = [json.loads(params)['ports'] for _, task, target, params in self.plans()
                 if task == 1 and target == self.target]
        self.assertEqual(local, ['8080', '22'])
        self.assertEqual(self.db.execute('SELECT plan_id,attempt FROM network_job_runs').fetchall(), [(first, 1)])
        self.assertEqual(len([c for c in self.broker_calls if 'tcp_full' in c]), 1)

    def test_failed_and_running_checks_are_not_implicitly_requeued(self):
        self.initialize_network()
        for port, status in ((22, 'failed'), (8080, 'running')):
            plan = pm.plan_reprobe(self.db, 1, self.target, str(port))
            with self.db:
                self.db.execute('INSERT INTO network_job_runs(plan_id,attempt,status,command_json,started_at) '
                                "VALUES(?,1,?,'[]',?)", (plan, status, network_jobs.now()))
        self.assertEqual(pm.run_full_tcp_scan(self.db, 1, self.target), 1)
        self.assertEqual(len(self.plans()), 2)
        self.assertEqual(self.db.execute('SELECT status FROM network_job_runs ORDER BY id').fetchall(),
                         [('failed',), ('running',)])
        self.assertEqual(len(self.executor_calls), 2)  # Only original plan validation.
        self.assertEqual(self.db.execute('SELECT followup_status FROM pm_tcp_full_scans').fetchone()[0], 'completed')

    def test_pre_fix_lost_ports_are_not_invented_on_explicit_retry(self):
        with self.db:
            self.db.execute('INSERT INTO pm_tcp_full_scans(task_id,target,status,error,created_at) '
                            "VALUES(1,?,'failed','no such table: network_phase_plans',?)", (self.target, network_jobs.now()))
        self.assertEqual(pm.run_full_tcp_scan(self.db, 1, self.target), 1)
        self.assertEqual(len(self.broker_calls), 1)
        self.assertEqual(self.scan(), ('completed', '[22, 8080]', None))
        self.assertEqual(len(self.plans()), 1)

    def test_scan_failure_is_not_reported_as_followup_failure(self):
        self.scan_status = 'timeout'
        with diagnostics.run('scan failure', 1):
            with self.assertRaises(pm.OperatorError):
                pm.run_full_tcp_scan(self.db, 1, self.target)
            events = diagnostics.read_events()
        self.assertEqual(self.scan()[0], 'failed')
        self.assertTrue(any(e['kind'] == 'scan.result' and e['status'] == 'failed' for e in events))
        self.assertFalse(any(e['kind'] == 'scan.followups' for e in events))
        self.assertEqual(self.executor_calls, [])


if __name__ == '__main__':
    unittest.main()
