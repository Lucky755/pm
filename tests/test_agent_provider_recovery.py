"""Offline tests for bounded model retry; no API, network, or privileged operations."""
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
SRC = ROOT / 'orchestrator/evidence_pipeline.py'
spec = importlib.util.spec_from_file_location('evidence_recovery_test', SRC)
ev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev)

BUNDLE = {'task_id': 11, 'network_observations': [{'observation_id': 13}],
          'burp_http_metadata': [], 'web_observations': []}
REPORT = {'summary': 'Обнаружена доступная служба.', 'observations_used': ['network:13'],
          'uncertainties': ['Версия не проверена'], 'recommended_checks': []}


class Response:
    def __init__(self, reason, events=None, content=None):
        self.finish_reason = reason
        self.events = events or []
        self.final_response = content or json.dumps(REPORT, ensure_ascii=False)


class FakeHarness:
    responses = []
    count = 0
    prompts = []
    sessions = []

    def __init__(self, **kwargs):
        policy = kwargs.get('patches', ())
        assert len(policy) == 1 and Path(policy[0]).is_file(), 'runtime policy required'
        self.policy = json.loads(Path(policy[0]).read_text())

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def start_session(self, name):
        harness = self
        type(harness).sessions.append(name)
        class Session:
            def run(self, prompt):
                type(harness).count += 1
                type(harness).prompts.append(prompt)
                return harness.responses.pop(0)
        return Session()


class ProviderRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.db.executescript('''
            CREATE TABLE evidence_snapshots (
               task_id INTEGER, evidence_sha256 TEXT, evidence_json TEXT, created_at TEXT,
               PRIMARY KEY(task_id, evidence_sha256));
            CREATE TABLE evidence_agent_reports (
               task_id INTEGER, evidence_sha256 TEXT, stage TEXT, report_json TEXT,
               created_at TEXT, PRIMARY KEY(task_id, evidence_sha256, stage));
        ''')
        self.digest = 'a' * 64
        self.db.execute('INSERT INTO evidence_snapshots VALUES (?,?,?,?)',
                        (11, self.digest, json.dumps(BUNDLE), ev.now()))
        for stage in ('vuln', 'access', 'verify'):
            self.db.execute('INSERT INTO evidence_agent_reports VALUES (?,?,?,?,?)',
                            (11, self.digest, stage, json.dumps(REPORT), ev.now()))
        self.db.commit()
        self.patcher = patch.dict(sys.modules, {'deepseek_harness': types.SimpleNamespace(DeepSeekHarness=FakeHarness)})
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.patcher2 = patch.object(ev.getpass, 'getpass', return_value='fake-test-only')
        self.patcher2.start()
        self.addCleanup(self.patcher2.stop)
        FakeHarness.responses = []
        FakeHarness.count = 0
        FakeHarness.prompts = []
        FakeHarness.sessions = []

    def test_single_transient_error_is_recovered(self):
        FakeHarness.responses = [Response('error', [{'type': 'provider/error', 'status_code': 503}]),
                                 Response('completed')]
        reports = ev.run_agents(self.db, 11, self.digest, BUNDLE)
        self.assertEqual(FakeHarness.count, 2)
        self.assertEqual(set(reports), set(ev.STAGES))
        ev.run_agents(self.db, 11, self.digest, BUNDLE)
        self.assertEqual(FakeHarness.count, 2)  # resumed, no extra token use

    def test_second_error_stops_without_saving_false_report(self):
        FakeHarness.responses = [Response('error'), Response('error')]
        with self.assertRaisesRegex(RuntimeError, 'saved evidence retained'):
            ev.run_agents(self.db, 11, self.digest, BUNDLE)
        self.assertEqual(FakeHarness.count, 2)
        self.assertNotIn('recon', ev.saved_reports(self.db, 11, self.digest))

    def test_tool_request_retried_in_fresh_read_only_session(self):
        FakeHarness.responses = [Response('completed', [{'type': 'tool/call',
                                   'arguments': 'UNTRUSTED_TOOL_PAYLOAD'}]), Response('completed')]
        reports = ev.run_agents(self.db, 11, self.digest, BUNDLE)
        self.assertIn('recon', reports)
        self.assertEqual(FakeHarness.count, 2)
        self.assertNotEqual(*FakeHarness.sessions)
        self.assertNotIn('UNTRUSTED_TOOL_PAYLOAD', FakeHarness.prompts[1])
        self.assertIn('READ-ONLY RETRY', FakeHarness.prompts[1])

    def test_repeated_tool_requests_keep_previous_reports(self):
        FakeHarness.responses = [Response('completed', [{'type': 'tool/call'}]),
                                 Response('completed', [{'type': 'tool/call'}])]
        with self.assertRaisesRegex(RuntimeError, 'recovery budget exhausted'):
            ev.run_agents(self.db, 11, self.digest, BUNDLE)
        self.assertEqual(FakeHarness.count, 2)
        self.assertEqual(set(ev.saved_reports(self.db, 11, self.digest)),
                         {'vuln', 'access', 'verify'})

    def test_verify_resume_skips_all_completed_stages(self):
        self.db.execute("DELETE FROM evidence_agent_reports WHERE stage='verify'")
        self.db.execute('INSERT INTO evidence_agent_reports VALUES (?,?,?,?,?)',
                        (11, self.digest, 'recon', json.dumps(REPORT), ev.now()))
        self.db.commit()
        FakeHarness.responses = [Response('completed', [{'type': 'tool/call'}]), Response('completed')]
        reports = ev.run_agents(self.db, 11, self.digest, BUNDLE)
        self.assertEqual(set(reports), set(ev.STAGES))
        self.assertEqual(FakeHarness.count, 2)
        self.assertTrue(all('-verify-' in name for name in FakeHarness.sessions))
        ev.run_agents(self.db, 11, self.digest, BUNDLE)
        self.assertEqual(FakeHarness.count, 2)

    def test_tool_and_provider_failures_share_one_retry_budget(self):
        FakeHarness.responses = [Response('error'), Response('completed', [{'type': 'tool/call'}])]
        with self.assertRaisesRegex(RuntimeError, 'recovery budget exhausted'):
            ev.run_agents(self.db, 11, self.digest, BUNDLE)
        self.assertEqual(FakeHarness.count, 2)
        self.assertNotIn('recon', ev.saved_reports(self.db, 11, self.digest))

    def test_format_repair_still_cannot_request_tools(self):
        FakeHarness.responses = [Response('completed', content='invalid JSON'),
                                 Response('completed', [{'type': 'tool/call'}])]
        with self.assertRaisesRegex(RuntimeError, 'format repair requested tools'):
            ev.run_agents(self.db, 11, self.digest, BUNDLE)
        self.assertNotIn('recon', ev.saved_reports(self.db, 11, self.digest))
        self.assertEqual(FakeHarness.count, 2)

    def test_format_repair_validates_observation_ids(self):
        bad = dict(REPORT, observations_used=['network:9999'])
        FakeHarness.responses = [Response('completed', content='invalid JSON'),
                                 Response('completed', content=json.dumps(bad))]
        with self.assertRaisesRegex(ValueError, 'Unknown observation'):
            ev.run_agents(self.db, 11, self.digest, BUNDLE)
        self.assertNotIn('recon', ev.saved_reports(self.db, 11, self.digest))

    def test_missing_policy_stops_before_model_calls(self):
        with patch.object(ev, 'READONLY_PLUGIN', Path(self.tmp.name) / 'missing.mjs'):
            with self.assertRaisesRegex(ValueError, 'policy missing'):
                ev.run_agents(self.db, 11, self.digest, BUNDLE)
        self.assertEqual(FakeHarness.count, 0)

    def test_error_event_text_not_leaked(self):
        result = Response('error', [{'type': 'provider/error', 'error': 'api-key SECRET-123',
                                    'message': 'response contents'}])
        brief = ev._harness_error_brief(result)
        self.assertIn('provider/error', brief)
        self.assertNotIn('SECRET-123', brief)
        self.assertNotIn('response contents', brief)

    def test_nontransient_stop_is_not_retried(self):
        FakeHarness.responses = [Response('stopped')]
        with self.assertRaisesRegex(RuntimeError, 'finish_reason=stopped'):
            ev.run_agents(self.db, 11, self.digest, BUNDLE)
        self.assertEqual(FakeHarness.count, 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
