"""Offline diagnostic integration: real process/MCP boundaries, fake execution."""
from contextlib import redirect_stderr
import importlib.util
import io
import json
import os
import shutil
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from orchestrator import diagnostics as d, agent_actions as actions, fact_state
from orchestrator.harness_env import harness_env
import pm

spec = importlib.util.spec_from_file_location('diagnostic_mcp_server', ROOT / 'mcp/server.py')
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pm-diag-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.console = io.StringIO()
        patcher = patch.object(d, 'EVENT_DIR', self.root / 'events')
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in d.ENV_KEYS:
            patcher = patch.dict(os.environ, {name: ''})
            patcher.start()
            self.addCleanup(patcher.stop)
        self.stderr = redirect_stderr(self.console)
        self.stderr.__enter__()
        self.addCleanup(self.stderr.__exit__, None, None, None)

    def events(self):
        return [json.loads(line) for path in sorted(d.EVENT_DIR.glob('*.jsonl'))
                for line in path.read_text().splitlines()]

    def ends(self, kind='tool.end'):
        return [event for event in self.events() if event['kind'] == kind]

    def test_success_nonzero_and_evidence_unchanged(self):
        @d.tool
        def fake_tool(task_id, argv_json):
            return server.run_capability(['fake-helper'], 1, 'net_exec', task_id)
        log = self.root / 'capabilities'
        secret = 'TEST-SECRET-authorization-123'
        with d.run('scenario', 11), patch.object(server, 'CAPABILITY_LOG', log):
            for code in (0, 7):
                payload = {'status': 'completed', 'exit_code': code, 'stdout': 'RAW-' + secret}
                with patch.object(server.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), '')):
                    response = json.loads(fake_tool(11, json.dumps(['curl', '-H', 'Authorization: ' + secret])))
                    self.assertEqual(response['stdout'], payload['stdout'])
                    self.assertTrue(response['result_id'])
        self.assertEqual([e['status'] for e in self.ends()], ['completed', 'nonzero_exit'])
        self.assertEqual([e['exit_code'] for e in self.ends()], [0, 7])
        self.assertTrue(all(e['result_id'] for e in self.ends()))
        records = [json.loads(line) for line in (log / 'task_11.jsonl').read_text().splitlines()]
        self.assertEqual(len(records), 2)
        self.assertEqual(records[1]['result']['stdout'], 'RAW-' + secret)
        self.assertIn('argv_sha256', records[0])
        self.assertNotIn(secret, json.dumps(self.events()) + self.console.getvalue())

    def test_refusal_timeout_exception_and_original_exception_on_write_failure(self):
        @d.tool
        def fake_tool(task_id, mode):
            if mode == 'blocked':
                return json.dumps({'status': 'blocked', 'error': 'Authorization: TEST-SECRET'})
            if mode == 'exception':
                raise RuntimeError('Cookie: TEST-SECRET')
            return server.run_capability(['fake'], 1, 'net_exec', task_id)
        with d.run('failure cases', 11), patch.object(server, 'CAPABILITY_LOG', self.root / 'caps'):
            fake_tool(11, 'blocked')
            with patch.object(server.subprocess, 'run', side_effect=subprocess.TimeoutExpired('fake', 1, output=b'partial evidence')):
                fake_tool(11, 'timeout')
            with self.assertRaisesRegex(RuntimeError, 'Cookie: TEST-SECRET'):
                fake_tool(11, 'exception')
            with patch.object(d.os, 'open', side_effect=OSError('TEST-SECRET')):
                with self.assertRaisesRegex(RuntimeError, 'Cookie: TEST-SECRET'):
                    fake_tool(11, 'exception')
        self.assertEqual([e['status'] for e in self.ends()], ['blocked', 'timeout', 'error'])
        self.assertTrue(self.ends()[1]['result_id'])
        self.assertIn('[DIAG-ERROR]', self.console.getvalue())
        self.assertNotIn('TEST-SECRET', self.console.getvalue() + json.dumps(self.events()))

    def test_model_retry_cache_compaction_sdk_refusal_and_no_duplicate_mcp(self):
        @d.tool
        def pm_fake(task_id):
            return json.dumps({'status': 'completed', 'exit_code': 0, 'result_id': 'a' * 24})
        def notification(kind, data):
            return SimpleNamespace(method='session.event', payload={'event': {'type': kind, 'data': data}})
        class Session:
            def run(inner, prompt, on_notification):
                on_notification(notification('step/start', {}))
                on_notification(notification('llm/retry-started', {}))
                on_notification(notification('llm/retry', {'failure': {'code': 'TRANSPORT', 'message': 'SECRET'}}))
                on_notification(notification('assistant/message', {'usage': {'cacheReadTokens': 17}}))
                for name in ('pm_fake', 'pm_denied'):
                    on_notification(notification('tool/call', {'name': name, 'arguments': {'task_id': 11}}))
                    if name == 'pm_fake':
                        pm_fake(11)
                    on_notification(notification('tool/result', {'message': {'content': [{'text': json.dumps({'status': 'blocked'})}]}}))
                return SimpleNamespace(finish_reason='completed', events=[])
        with d.run('model scenario', 11):
            d.model_call(Session(), '\nCompact history (full outputs stay stored by result_id):')
            d.emit('cache.hit', name='decision', evidence_sha256='f' * 64)
        self.assertEqual(len(self.ends()), 2)
        self.assertEqual([e['name'] for e in self.ends()], ['pm_fake', 'pm_denied'])
        self.assertEqual(self.console.getvalue().count('tool.start pm_fake'), 1)
        self.assertEqual(self.console.getvalue().count('tool.end pm_fake'), 1)
        kinds = [e['kind'] for e in self.events()]
        self.assertIn('model.retry', kinds)
        self.assertIn('context.switch', kinds)
        self.assertIn('cache.hit', kinds)
        self.assertEqual(next(e for e in self.events() if e['kind'] == 'model.usage')['cache_read_tokens'], 17)
        self.assertFalse(d.unfinished(self.events()))

    def test_interrupt_and_crash_recognizable_and_distinct_runs(self):
        with self.assertRaises(KeyboardInterrupt):
            with d.run('interrupted', 11):
                with d.Action('tool', 'sleep'):
                    raise KeyboardInterrupt()
        self.assertEqual(self.ends()[0]['status'], 'interrupted')
        self.assertEqual(self.ends('run.summary')[0]['reason'], 'interrupted')
        with d.run('next manual invocation', 11):
            env = {**os.environ, **d.child_env()}
            subprocess.run([sys.executable, '-c',
                            "from orchestrator import diagnostics as d; import os; d.emit('tool.start', name='crashed', action_id='lost'); os._exit(9)"],
                           env=env, cwd=ROOT, check=False, capture_output=True)
            self.assertIn('lost', [e['action_id'] for e in d.unfinished(d.read_events())])
        self.assertEqual(len({e['run_id'] for e in self.events()}), 2)
        self.assertEqual(next(e for e in self.ends('run.summary') if e['name'] == 'next manual invocation')['unfinished'], ['lost'])
        self.assertEqual(next(e for e in self.ends() if e['action_id'] == 'lost')['status'], 'abandoned')

    def test_concise_progress_redaction_and_ansi(self):
        d.register_secret('test-api-key')
        with d.run('redaction', 11):
            d.emit('model.retry', reason='\x1b[31mAuthorization: Bearer test-api-key\x1b[0m')
        text = self.console.getvalue()
        output = io.StringIO()
        progress = pm.ConciseProgress(output)
        progress.write(text)
        progress.flush()
        self.assertIn('[EVENT]', output.getvalue())
        self.assertNotIn('test-api-key', output.getvalue())
        self.assertNotIn('\x1b', output.getvalue() + json.dumps(self.events()))

    def test_process_mcp_correlation_and_explicit_sdk_environment(self):
        fixture = self.root / 'mcp_fixture.py'
        fixture.write_text("""import importlib.util, os
from pathlib import Path
import sys, json
checkout = Path(os.environ['PYTHONPATH']).resolve()
sys.path.insert(0, str(checkout))
spec = importlib.util.spec_from_file_location('pm_server_fixture', checkout / 'mcp/server.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
from executor import tool_catalog
assert Path(tool_catalog.__file__).resolve().is_relative_to(checkout), 'Executor imported from a different checkout'
s.CAPABILITY_LOG = Path(os.environ['TEST_CAP_LOG'])
# A minimal MCP peer: dispatch the project's actual wrapped tool on JSON-RPC.
# No model runtime, executor, target network, or production task storage.
for line in sys.stdin:
    request = json.loads(line)
    method = request.get('method')
    if method == 'initialize':
        result = {'protocolVersion': request['params']['protocolVersion'], 'capabilities': {'tools': {}},
                  'serverInfo': {'name': 'diagnostic-fixture', 'version': '1'}}
    elif method == 'tools/call':
        payload = s.pm_capability_read(**request['params']['arguments'])
        result = {'content': [{'type': 'text', 'text': payload}], 'isError': False}
    else:
        continue
    print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': result}), flush=True)
""")
        def call(env):
            self.assertEqual(env.get('PYTHONPATH'), str(ROOT))
            messages = [
                {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                 'params': {'protocolVersion': '2024-11-05', 'capabilities': {},
                            'clientInfo': {'name': 'diagnostic-test', 'version': '1'}}},
                {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
                {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                 'params': {'name': 'pm_capability_read', 'arguments': {'task_id': 11, 'result_id': 'bad'}}},
            ]
            result = subprocess.run([sys.executable, str(fixture)], env={**os.environ, **env},
                                    cwd=ROOT, input='\n'.join(json.dumps(m) for m in messages) + '\n',
                                    text=True, capture_output=True, timeout=8, check=True)
            responses = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual([r['id'] for r in responses], [1, 2])
            self.assertIn('blocked', responses[1]['result']['content'][0]['text'])
        with d.run('MCP integration', 11), d.scope(role='recon', iteration=2):
            with d.Action('model', 'fake request') as request:
                env = {**d.child_env(), 'PYTHONPATH': str(ROOT), 'TEST_CAP_LOG': str(self.root / 'caps')}
                with d.relay():
                    call(env)
                self.assertEqual(self.ends()[0]['parent_action_id'], request.id)
                self.assertEqual(self.ends()[0]['role'], 'recon')
                self.assertEqual(self.ends()[0]['iteration'], 2)
                self.assertNotEqual(self.ends()[0]['pid'], os.getpid())
                self.assertEqual(harness_env()['PM_RUN_ID'], d.context()['run_id'])
                with actions.action_policy_patch(3) as policy:
                    overlays = json.loads(Path(policy).read_text())
                    forwarded=harness_env()
                    for key,value in d.child_env().items():
                        self.assertEqual(forwarded[key],value)
                    self.assertFalse(any(item.get('id')=='mcp-pentest-master' for item in overlays),
                                     'env-only config replacement disables the real MCP client')
        self.assertEqual(self.console.getvalue().count('tool.start pm_capability_read'), 1)
        self.assertEqual(self.console.getvalue().count('tool.end pm_capability_read'), 1)

    def test_mcp_fixture_runs_in_relocated_checkout_without_external_pythonpath(self):
        checkout = self.root / 'relocated-checkout'
        for directory in ('orchestrator', 'executor', 'mcp'):
            for source in (ROOT / directory).rglob('*'):
                if source.suffix not in ('.py', '.mjs') or '__pycache__' in source.parts:
                    continue
                destination = checkout / source.relative_to(ROOT)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
        for source in ROOT.glob('*.py'):
            shutil.copyfile(source, checkout / source.name)
        (checkout / 'tests').mkdir()
        shutil.copyfile(Path(__file__), checkout / 'tests/test_run_diagnostics.py')
        environment = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH' and key not in d.ENV_KEYS}
        result = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests',
                                 '-p', 'test_run_diagnostics.py', '-k', 'process_mcp'],
                                cwd=checkout, env=environment, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Ran 1 test', result.stderr)

    def test_saved_report_state_changes_are_identified_after_commit(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        actions.ensure_schema(db)
        fact_state.ensure_schema(db)
        report = {'summary': 'done', 'hypotheses': [{'claim': 'observed /health',
                  'kind': 'observation', 'result': 'confirmed', 'probe_result_id': 'a' * 24,
                  'quote': 'SECRET raw quote'}]}
        with d.run('state', 11), patch.object(actions, 'REPORT_DIR', self.root / 'reports'):
            actions.save_report(db, {'task_id': 11, 'target': '203.0.113.10'}, 'recon', 1, report, 1)
        changes = [e for e in self.events() if e['kind'] == 'state.change']
        self.assertIn('pm_hypotheses', [e['table'] for e in changes])
        self.assertTrue(all('identifiers' in e for e in changes))
        self.assertNotIn('SECRET', json.dumps(self.events()))
        self.assertFalse(db.in_transaction)

    def test_later_model_request_reparents_child_with_fixed_environment(self):
        fixture = self.root / 'tool_process.py'
        fixture.write_text("from orchestrator import diagnostics as d\n"
                           "@d.tool\ndef pm_fake(task_id):\n    return '{\"status\": \"completed\"}'\n"
                           "pm_fake(11)\n")
        with d.run('two requests', 11), d.scope(role='access', iteration=3):
            static_env = {**os.environ, **d.child_env(), 'PYTHONPATH': str(ROOT)}
            class Session:
                def run(inner, prompt, on_notification):
                    subprocess.run([sys.executable, str(fixture)], env=static_env,
                                   capture_output=True, check=True, timeout=8)
                    return SimpleNamespace(finish_reason='completed', events=[])
            d.model_call(Session(), 'first')
            d.model_call(Session(), 'second')
        parents = [e['parent_action_id'] for e in self.ends()]
        self.assertEqual(len(set(parents)), 2)
        self.assertEqual(set(parents), {e['action_id'] for e in self.ends('model.end')})

    def test_entrypoint_propagates_run_and_reports_nonzero_return(self):
        @d.entrypoint
        def command():
            child = subprocess.run([sys.executable, '-c',
                                    "from orchestrator import diagnostics as d; d.emit('process.probe', console=False)"],
                                   cwd=ROOT, text=True, capture_output=True, check=True)
            return 3
        self.assertEqual(command(), 3)
        events = self.events()
        self.assertEqual(len({e['run_id'] for e in events}), 1)
        self.assertEqual(sum(e['kind'] == 'run.start' for e in events), 1)
        self.assertIn('process.probe', [e['kind'] for e in events])
        self.assertEqual(self.ends('run.summary')[0]['status'], 'error')


def demo():
    """Reproduce console output using fake helper replies and temporary evidence."""
    @d.tool
    def pm_demo(task_id, target):
        return server.run_capability(['fake-helper'], 1, 'net_exec', task_id)
    with tempfile.TemporaryDirectory(prefix='pm-diagnostics-demo-') as directory:
        root = Path(directory)
        with patch.object(d, 'EVENT_DIR', root / 'events'), patch.object(server, 'CAPABILITY_LOG', root / 'caps'):
            with d.run('offline-demo', 11), d.scope(role='recon', iteration=1), d.relay():
                for code in (0, 7):
                    payload = {'status': 'completed', 'exit_code': code, 'stdout': 'offline evidence'}
                    with patch.object(server.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), '')):
                        pm_demo(11, '203.0.113.10')
                d.stop('demo_finished')


if __name__ == '__main__':
    if sys.argv[1:] == ['--demo']:
        demo()
    else:
        unittest.main()
