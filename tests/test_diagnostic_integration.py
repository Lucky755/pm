"""Offline integration regressions: real planner PTY, fake executor boundaries."""
import base64
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import pm
from orchestrator import diagnostics as d, http_discovery as web, network_enrichment as enrichment

TARGET = '10.0.0.1'


def frame(task_id=11, plan=None):
    data = {'task_id': task_id, 'plan': {'tasks': []} if plan is None else plan}
    return 'PM_PLANNER_RESULT_V1:' + base64.b64encode(json.dumps(data).encode()).decode()


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pm-integration-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.console = io.StringIO()
        for patcher in (patch.object(d, 'EVENT_DIR', self.root / 'events'),
                        patch.dict(os.environ, {key: '' for key in d.ENV_KEYS}),
                        redirect_stderr(self.console), redirect_stdout(self.console)):
            patcher.__enter__()
            self.addCleanup(patcher.__exit__, None, None, None)

    def events(self, kind=None):
        rows = [json.loads(line) for path in (self.root / 'events').glob('*.jsonl')
                for line in path.read_text().splitlines()]
        return sorted((r for r in rows if kind is None or r['kind'] == kind), key=lambda r: r['timestamp'])

    def pair(self, count=1):
        starts, ends = self.events('tool.start'), self.events('tool.end')
        self.assertEqual(len(starts), count)
        self.assertEqual(len(ends), count)
        self.assertEqual({r['action_id'] for r in starts}, {r['action_id'] for r in ends})
        self.assertTrue(all(r['task_id'] == 11 and r['run_id'] for r in starts + ends))
        self.assertTrue(all('duration_seconds' in r for r in ends))
        return ends

    def planner(self, text, code=0):
        script = 'import sys; print(' + repr(text) + ', flush=True); sys.exit(' + str(code) + ')'
        return pm.read_planner_stream([sys.executable, '-u', '-c', script])

    def test_planner_pty_diagnostic_braces_cannot_replace_plan(self):
        for diagnostic in ('', "[EVENT] state.change identifiers={'id': 11}\n"):
            with self.subTest(diagnostic=bool(diagnostic)):
                text = diagnostic + 'Task ID: 11\nStatus: pending_review\n{"tasks": []}\n' + frame()
                self.assertEqual(self.planner(text), (11, {'tasks': []}))

    def test_planner_accepts_only_explicit_reply_and_keeps_validation(self):
        for text in ('Task ID: 11\n[EVENT] random {"tasks": []}',
                     'Task ID: 11\n{"tasks": []}',
                     'Task ID: 11\n' + frame(12),
                     'Task ID: 11\n' + frame(plan={'tasks': 'wrong'}),
                     'Task ID: 11\n' + frame() + '\n' + frame(),
                     'Task ID: 11\nTask ID: 12\n' + frame(),
                     'Task ID: 11\nPM_PLANNER_RESULT_V1:bad-base64'):
            with self.subTest(text=text), self.assertRaises(pm.OperatorError):
                self.planner(text)
        with self.assertRaises(pm.PlannerValidationError):
            self.planner('PM_PLAN_VALIDATION_ERROR: invalid\nTask ID: 11\n' + frame(), 2)
        with self.assertRaises(pm.OperatorError):
            self.planner('Task ID: 11\n' + frame(), 1)

    def test_actual_planner_entrypoint_over_pty_with_stubbed_model_and_storage(self):
        script = """from pathlib import Path
from unittest.mock import patch
from orchestrator import planner, diagnostics as d
import sys
d.EVENT_DIR = Path(sys.argv[1])
plan = {'target': '10.0.0.1', 'tasks': [{'agent': 'recon', 'instruction': 'Inspect services'}]}
with patch.object(sys, 'argv', ['planner', '--target', '10.0.0.1', '--task', 'Inspect']), patch.object(planner.getpass, 'getpass', return_value='fake-key'), patch.object(planner, 'plan_with_context', return_value=plan), patch.object(planner, 'save_plan', return_value=11):
    planner.main()
"""
        task_id, plan = pm.read_planner_stream([sys.executable, '-c', script, str(self.root / 'planner-events')])
        self.assertEqual(task_id, 11)
        self.assertEqual(plan['tasks'][0]['agent'], 'recon')
        self.assertIn("identifiers={'id': 11}", self.console.getvalue())
        self.assertNotIn('PM_PLANNER_RESULT_V1:', self.console.getvalue())

    def test_mcp_failure_reasons_are_safe_and_visible(self):
        @d.tool
        def fake_tool(task_id, mode):
            if mode == 'scope':
                return json.dumps({'status': 'blocked', 'error': 'Target outside task scope; Authorization: Bearer TEST-SECRET'})
            if mode == 'unavailable':
                return json.dumps({'status': 'error', 'kind': 'broker', 'error': 'Executor unavailable'})
            if mode == 'timeout':
                return json.dumps({'status': 'timeout', 'timeout_seconds': 12, 'stdout': 'RAW-SECRET'})
            raise RuntimeError('worker could not start; Cookie: TEST-SECRET')
        with d.run('failure reasons', 11), d.relay():
            for mode in ('scope', 'unavailable', 'timeout'):
                fake_tool(11, mode)
            with self.assertRaisesRegex(RuntimeError, 'worker could not start'):
                fake_tool(11, 'exception')
        ends = self.pair(4)
        self.assertEqual([r['reason_category'] for r in ends],
                         ['scope_denied', 'executor_unavailable', 'timeout', 'exception'])
        self.assertIn('worker could not start', ends[-1]['reason_summary'])
        self.assertIn('scope_denied', self.console.getvalue())
        self.assertNotIn('TEST-SECRET', self.console.getvalue() + json.dumps(self.events()))
        self.assertNotIn('RAW-SECRET', json.dumps(self.events()))

    def test_interrupt_keeps_original_exception_after_failure_metadata(self):
        interrupt = KeyboardInterrupt()
        @d.tool
        def interrupted(task_id):
            d.record_result({'status': 'blocked', 'error': 'outside task scope'})
            raise interrupt
        with d.run('interrupt handled', 11):
            with self.assertRaises(KeyboardInterrupt) as caught:
                interrupted(11)
            self.assertIs(caught.exception, interrupt)
        end = self.pair()[0]
        self.assertEqual(end['status'], 'interrupted')
        self.assertEqual(end['reason_category'], 'interrupted')

    def db(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        pm.initialize_tcp_scans(db)
        return db

    def test_full_scan_and_preflight_use_one_action_per_broker_call(self):
        db = self.db()
        scan = {'status': 'completed', 'exit_code': 0, 'stdout': 'Nmap done: 1 IP address scanned'}
        probe = {'status': 'completed', 'exit_code': 0,
                 'stdout': json.dumps({'reachable': [80], 'unreachable': [], 'unchecked': []})}
        broker = Mock(side_effect=[(scan, 0), (probe, 0)])
        with d.run('direct broker', 11), patch.object(pm, 'sudo_checked', broker):
            self.assertEqual(pm.run_full_tcp_scan(db, 11, TARGET), 1)
            self.assertEqual(pm.preflight_target(db, 11, TARGET, [80])['reachable'], [80])
        self.assertEqual(broker.call_count, 2)
        self.pair(2)

    def test_preflight_correlation_reaches_subprocess_without_executing_sudo(self):
        payload = {'status': 'completed', 'exit_code': 0,
                   'stdout': json.dumps({'reachable': [80], 'unreachable': [], 'unchecked': []})}
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), ''))
        with d.run('preflight process boundary', 11), patch.object(pm.subprocess, 'run', runner):
            pm.preflight_target(self.db(), 11, TARGET, [80])
        self.assertEqual(runner.call_count, 1)
        end = self.pair()[0]
        environment = runner.call_args.kwargs['env']
        self.assertEqual(environment['PM_RUN_ID'], end['run_id'])
        self.assertEqual(environment['PM_ACTION_ID'], end['action_id'])
        self.assertEqual(environment['PM_TASK_ID'], '11')

    def test_full_scan_failure_has_one_action_and_no_retry(self):
        for failure in (None, subprocess.TimeoutExpired('hidden-command', 270)):
            broker = Mock(return_value=({'status': 'blocked', 'error': 'Target outside task scope'}, 1), side_effect=failure)
            with d.run('full scan refused', 11), patch.object(pm, 'sudo_checked', broker), self.assertRaises(Exception):
                pm.run_full_tcp_scan(self.db(), 11, TARGET)
            self.assertEqual(broker.call_count, 1)
        self.assertEqual([r['reason_category'] for r in self.pair(2)], ['scope_denied', 'timeout'])

    def test_direct_refusal_and_exception_keep_operation_behavior(self):
        for mode in ('scope', 'exception'):
            with self.subTest(mode=mode):
                with d.run(mode, 11):
                    broker = Mock(return_value=({'status': 'blocked', 'error': 'outside task scope'}, 1))
                    if mode == 'exception':
                        broker.side_effect = FileNotFoundError('executor unavailable')
                    with patch.object(pm, 'sudo_checked', broker), self.assertRaises(Exception):
                        pm.preflight_target(self.db(), 11, TARGET, [80])
                    self.assertEqual(broker.call_count, 1)
        ends = self.pair(2)
        self.assertEqual([r['reason_category'] for r in ends], ['scope_denied', 'executor_unavailable'])

    def test_enrichment_executor_boundary_records_reply_and_exception(self):
        command = ['fake', 'run', '--task-id', '11', '--target', TARGET, '--profile', 'service_versions', '--execute']
        payload = {'status': 'blocked', 'error': 'Target outside task scope'}
        runner = Mock(return_value=subprocess.CompletedProcess(command, 1, json.dumps(payload), ''))
        with d.run('enrichment', 11), patch.object(enrichment.subprocess, 'run', runner):
            self.assertEqual(enrichment.executor_call(command, 60), (1, payload))
            runner.side_effect = FileNotFoundError('executor unavailable')
            with self.assertRaises(FileNotFoundError):
                enrichment.executor_call(command, 60)
        self.assertEqual(runner.call_count, 2)
        ends = self.pair(2)
        self.assertEqual(runner.call_args.kwargs['env']['PM_ACTION_ID'], ends[-1]['action_id'])

    def test_nonzero_helper_exit_is_not_reported_as_completed(self):
        payload = {'status': 'completed', 'exit_code': 0}
        runner = Mock(return_value=subprocess.CompletedProcess([], 7, json.dumps(payload), ''))
        with d.run('helper failed', 11), patch.object(enrichment.subprocess, 'run', runner):
            self.assertEqual(enrichment.executor_call(['fake', '--task-id', '11'], 60), (7, payload))
        end = self.pair()[0]
        self.assertEqual(end['status'], 'nonzero_exit')
        self.assertEqual(end['executor_exit_code'], 7)
        self.assertEqual(end['exit_code'], 0)
        self.assertEqual(runner.call_count, 1)

    def test_enrichment_run_plan_keeps_refusal_and_caught_failure_semantics(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        enrichment.initialize(db)
        db.execute('INSERT INTO network_phase_plans(id,task_id,profile,target,parameters_json,status,'
                   "goal,argv_json,model_summary,created_at) VALUES(1,11,?,?,?,?, 'fixture','[]','fixture','saved')",
                   ('service_versions', TARGET, '{"ports":"80"}', 'planned'))
        db.commit()
        runner = Mock(side_effect=FileNotFoundError('executor unavailable'))
        with d.run('refused plan', 11), patch.object(enrichment, 'verify_scope', side_effect=ValueError('Target outside task scope')), patch.object(enrichment.subprocess, 'run', runner):
            with self.assertRaisesRegex(ValueError, 'outside task scope'):
                enrichment.run_plan(db, 1)
            runner.assert_not_called()
        with d.run('failed plan', 11), patch.object(enrichment, 'verify_scope'), patch.object(enrichment.subprocess, 'run', runner):
            result = enrichment.run_plan(db, 1)
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(runner.call_count, 1)
        end = self.pair()[0]
        self.assertEqual(end['reason_category'], 'executor_unavailable')
        self.assertEqual(db.execute('SELECT COUNT(*) FROM network_job_runs').fetchone()[0], 1)
        self.assertEqual(db.execute('SELECT status FROM network_job_runs').fetchone()[0], 'failed')

    def test_http_scope_refusal_from_stderr_never_copies_it(self):
        payload = {'status': 'blocked', 'stderr': 'Destination outside authorized scope; RAW-SECRET', 'exit_code': 1}
        runner = Mock(return_value=subprocess.CompletedProcess([], 1, json.dumps(payload), ''))
        with d.run('HTTP refused', 11), self.assertRaises(ValueError):
            web.request(11, TARGET, 'http', TARGET, 80, '/', runner=runner)
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(self.pair()[0]['reason_category'], 'scope_denied')
        self.assertNotIn('RAW-SECRET', json.dumps(self.events()) + self.console.getvalue())

    def test_http_discovery_document_and_capture_boundaries(self):
        wire = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nevidence'
        for profile, function in (('http_path', web.request), ('http_document', web.request_document),
                                  ('http_capture', web.request_capture)):
            with self.subTest(profile=profile):
                payload = dict(status='completed', exit_code=0, task_id=11, target=TARGET,
                               profile=profile, stdout=wire.decode(), scheme='http', hostname=TARGET,
                               port=80, path='/', capture_protocol=1, response_bytes=len(wire),
                               response_b64=base64.b64encode(wire).decode())
                runner = Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), ''))
                with d.run(profile, 11):
                    self.assertIn('evidence', function(11, TARGET, 'http', TARGET, 80, '/', runner=runner))
                self.assertEqual(runner.call_count, 1)
                end = self.events('tool.end')[-1]
                self.assertEqual(runner.call_args.kwargs['env']['PM_ACTION_ID'], end['action_id'])
        self.pair(3)

    def test_capture_capabilities_check_is_an_executor_action(self):
        payload = {'capture_protocol': 1, 'profiles': ['http_capture'],
                   'capture_limits': [2*1024*1024, 8*1024*1024]}
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), ''))
        with d.run('capture support', 11):
            web.require_capture_support(runner=runner)
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(self.pair()[0]['status'], 'completed')

    def test_http_failures_are_traced_once(self):
        for function in (web.request, web.request_capture):
            for failure in (subprocess.TimeoutExpired('hidden-command', 60), RuntimeError('worker could not start')):
                runner = Mock(side_effect=failure)
                with d.run('http failure', 11), self.assertRaises(type(failure)):
                    function(11, TARGET, 'http', TARGET, 80, '/', runner=runner)
                self.assertEqual(runner.call_count, 1)
        self.pair(4)


def demo():
    @d.tool
    def scope_probe(task_id):
        return json.dumps({'status': 'blocked', 'stderr': 'Destination outside authorized scope'})
    with tempfile.TemporaryDirectory(prefix='pm-integration-demo-') as directory:
        with patch.object(d, 'EVENT_DIR', Path(directory)), d.run('scope refusal demo', 11), d.relay():
            scope_probe(11)
            d.stop('demo_finished')


if __name__ == '__main__':
    if sys.argv[1:] == ['--demo']:
        demo()
    else:
        unittest.main()
