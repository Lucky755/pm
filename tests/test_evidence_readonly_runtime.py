"""Real SDK smoke checks against a loopback-only fake API. No GLM calls or key.

Run with the project's .venv/bin/python. The SDK must already be installed.
Supports the runtime's Anthropic messages and OpenAI chat streaming adapters.
"""
import importlib.util
import json
import shlex
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('evidence_runtime_test', ROOT / 'orchestrator/evidence_pipeline.py')
ev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev)
try:
    from deepseek_harness import DeepSeekHarness
except ImportError:
    DeepSeekHarness = None

REPORT = {'summary': 'Анализ сохранённых наблюдений.', 'observations_used': [],
          'uncertainties': ['Дополнительные проверки не выполнялись.'],
          'recommended_checks': []}


class LocalAPI:
    def __init__(self, marker, tool_first=False, responder=None):
        self.marker = marker
        self.tool_first = tool_first
        self.requests = []
        api = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                api.requests.append(body)
                # Bound the fake provider too, so a runtime regression cannot loop.
                if len(api.requests) > 4:
                    self.send_error(500, 'local test request budget exhausted')
                    return
                reply = (responder(body) if responder else {
                    'tool_name': 'bash' if api.tool_first and len(api.requests)==1 else None,
                    'arguments': {'command': 'touch ' + shlex.quote(str(api.marker))},
                    'text': json.dumps(REPORT,ensure_ascii=False)})
                tool = reply.get('tool_name')
                args = json.dumps(reply.get('arguments',{}))
                text = reply.get('text','')
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Connection', 'close')
                self.end_headers()

                def send(data, event=None):
                    prefix = ('event: ' + event + '\n') if event else ''
                    self.wfile.write((prefix + 'data: ' + json.dumps(data) + '\n\n').encode())

                if self.path.rstrip('/').endswith('/messages'):
                    def event(kind, **data):
                        send({'type': kind, **data}, kind)
                    event('message_start', message={
                        'id': 'local-test', 'type': 'message', 'role': 'assistant',
                        'model': 'deepseek-chat', 'content': [], 'stop_reason': None,
                        'stop_sequence': None, 'usage': {'input_tokens': 1, 'output_tokens': 0}})
                    if tool:
                        event('content_block_start', index=0, content_block={
                            'type': 'tool_use', 'id': 'denied-test', 'name': tool, 'input': {}})
                        event('content_block_delta', index=0, delta={
                            'type': 'input_json_delta', 'partial_json': args})
                        stop = 'tool_use'
                    else:
                        event('content_block_start', index=0, content_block={'type': 'text', 'text': ''})
                        event('content_block_delta', index=0, delta={'type': 'text_delta', 'text': text})
                        stop = 'end_turn'
                    event('content_block_stop', index=0)
                    event('message_delta', delta={'stop_reason': stop, 'stop_sequence': None},
                          usage={'output_tokens': 40})
                    event('message_stop')
                else:
                    delta = ({'tool_calls': [{'index': 0, 'id': 'denied-test', 'type': 'function',
                              'function': {'name': tool, 'arguments': args}}]} if tool else {'content': text})
                    for content, stop in [(delta, None), ({}, 'tool_calls' if tool else 'stop')]:
                        send({'id': 'local-test', 'object': 'chat.completion.chunk', 'created': 1,
                              'model': 'deepseek-chat', 'choices': [
                                  {'index': 0, 'delta': content, 'finish_reason': stop}]})
                    self.wfile.write(b'data: [DONE]\n\n')
                self.wfile.flush()
                self.close_connection = True

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    @property
    def url(self):
        return f'http://127.0.0.1:{self.server.server_port}/v1'


@unittest.skipIf(DeepSeekHarness is None, 'deepseek_harness not installed; use project .venv/bin/python')
class RuntimePolicyTests(unittest.TestCase):
    def exercise(self, tool_first):
        with tempfile.TemporaryDirectory(prefix='pm-runtime-test-') as directory:
            marker = Path(directory) / 'must not exist'
            # Paths with spaces must work for both the patch and policy module.
            module = Path(directory) / 'policy with spaces.mjs'
            module.write_bytes(ev.READONLY_PLUGIN.read_bytes())
            original_plugin = ev.READONLY_PLUGIN
            ev.READONLY_PLUGIN = module
            try:
                with LocalAPI(marker, tool_first=tool_first) as api, ev.read_only_analysis_patch() as policy:
                    with DeepSeekHarness(
                        profile='sdk-minimal', patches=(policy,),
                        dsh_home=str(Path(directory) / 'home'), cwd=directory,
                        provider='deepseek-official', model='deepseek-chat',
                        api_key='local-test-only', base_url=api.url,
                        initialize_timeout_seconds=20, request_timeout_seconds=20,
                        max_tokens=400,
                    ) as harness:
                        result = harness.start_session('local-readonly-test').run(
                            'Analyze supplied observations only. Return a short JSON report. No tools.')
                    self.assertEqual(result.finish_reason, 'completed')
                    self.assertEqual(ev.parse_report(result.final_response), REPORT)
                    self.assertFalse(marker.exists(), 'tool body must never execute')
                    self.assertTrue(api.requests, 'the real SDK must contact the loopback fake API')
                    for request in api.requests:
                        self.assertFalse(request.get('tools'), 'model-facing tool schemas must be empty')
                    if tool_first:
                        self.assertTrue(ev._has_tool_calls(result))
                        denials = [event for event in result.events if event.get('type') == 'tool/result']
                        self.assertTrue(denials)
                        self.assertIn('PM_EVIDENCE_READ_ONLY', json.dumps(denials))
                        self.assertEqual(len(api.requests), 2)
                    else:
                        self.assertFalse(ev._has_tool_calls(result))
                        self.assertEqual(len(api.requests), 1)
            finally:
                ev.READONLY_PLUGIN = original_plugin

    def test_normal_report_has_no_tools(self):
        self.exercise(tool_first=False)

    def test_unsolicited_shell_call_is_denied_before_dispatch(self):
        self.exercise(tool_first=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
