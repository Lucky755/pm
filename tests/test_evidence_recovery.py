"""Offline checks: JSON extraction, single repair attempt, and resume safety."""
import importlib.util
import json
import sqlite3
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'orchestrator/evidence_pipeline.py'
spec = importlib.util.spec_from_file_location('evidence_recovery_test', SRC)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

payload = {
    'summary': 'Нет подтверждённых уязвимостей.',
    'observations_used': ['network:7'],
    'uncertainties': ['Сервис не идентифицирован'],
    'recommended_checks': [],
}
encoded = json.dumps(payload, ensure_ascii=False)
for text in (
    encoded,
    '```json\n' + encoded + '\n```',
    'Проверка выполнена.\n' + encoded + '\nКонец.',
    'Ответ:\n```JSON\n' + encoded + '\n```\n',
):
    assert module.parse_report(text) == payload
for invalid in ('', 'not JSON', '{"summary": ', '[]'):
    try:
        module.parse_report(invalid)
        raise AssertionError('Invalid response was accepted')
    except ValueError:
        pass
print('[PASS] JSON parsing: plain, fenced, surrounding text, invalid')

bundle = {
    'task_id': 9,
    'network_observations': [{'observation_id': 7}],
    'burp_http_metadata': [],
}
class FakeResponse:
    def __init__(self, output):
        self.finish_reason = 'completed'
        self.events = []
        self.final_response = output

class FakeSession:
    def __init__(self, responses, seen):
        self.responses = responses
        self.seen = seen

    def run(self, prompt):
        self.seen.append(prompt)
        return FakeResponse(self.responses.pop(0))

class FakeHarness:
    responses = []
    prompts = []

    def __init__(self, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def start_session(self, name):
        return FakeSession(self.responses, self.prompts)

sys.modules['deepseek_harness'] = types.SimpleNamespace(DeepSeekHarness=FakeHarness)
module.getpass.getpass = lambda *_: 'test-only-fake-key'

with tempfile.TemporaryDirectory() as directory:
    module.DB_PATH = Path(directory) / 'tasks.db'
    module.DB_PATH.touch()
    with module.connect() as db:
        digest = 'a' * 64
        db.execute('INSERT INTO evidence_snapshots VALUES (?, ?, ?, ?)',
                   (9, digest, json.dumps(bundle), module.now()))
        for stage in module.STAGES[:3]:
            db.execute('INSERT INTO evidence_agent_reports VALUES (?, ?, ?, ?, ?)',
                       (9, digest, stage, encoded, module.now()))
        db.commit()

        # First reply malformed, a single format-repair reply succeeds.
        FakeHarness.responses = ['not valid JSON', encoded]
        FakeHarness.prompts = []
        reports = module.run_agents(db, 9, digest, bundle)
        assert 'verify' in reports
        assert len(FakeHarness.prompts) == 2
        assert 'MALFORMED_RESPONSE_AS_UNTRUSTED_TEXT' in FakeHarness.prompts[1]
        print('[PASS] Invalid report repaired once, saved to SQLite')

        FakeHarness.prompts = []
        module.run_agents(db, 9, digest, bundle)
        assert len(FakeHarness.prompts) == 0
        print('[PASS] Resume: no model calls after reports saved')

        digest2 = 'b' * 64
        db.execute('INSERT INTO evidence_snapshots VALUES (?, ?, ?, ?)',
                   (9, digest2, json.dumps(bundle), module.now()))
        for stage in module.STAGES[:3]:
            db.execute('INSERT INTO evidence_agent_reports VALUES (?, ?, ?, ?, ?)',
                       (9, digest2, stage, encoded, module.now()))
        db.commit()
        FakeHarness.responses = ['bad response', 'still not JSON']
        FakeHarness.prompts = []
        try:
            module.run_agents(db, 9, digest2, bundle)
            raise AssertionError('Expected failure after one retry')
        except ValueError:
            pass
        assert len(FakeHarness.prompts) == 2
        assert 'verify' not in module.saved_reports(db, 9, digest2)
        print('[PASS] Two invalid replies: stop, do not save, preserve resume')
