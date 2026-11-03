"""Offline integration: cached decisions, advisory reports, true stop reasons.

No model, network, sudo, or production task DB. Run as a standalone test file.
"""
import contextlib
import importlib.util
import io
import json
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location('decision_v2_test', ROOT / 'orchestrator/decision_agent.py')
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)
DIGEST = 'a' * 64
BUNDLE = {'task_id': 11, 'authorized_target': '127.0.0.1',
          'network_observations': [], 'burp_http_metadata': [],
          'web_observations': [{'observation_id': 6, 'path': '/app/style.css',
                                'error': 'curl: (63) Maximum file size exceeded'}]}
CANDIDATE = {'id': 'c1', 'profile': 'service_versions', 'target': '127.0.0.1',
             'parameters': {'ports': '5038'}, 'source': 'network:4', 'reason': 'Open port'}
REPORT = {'summary': 'Полный вывод: ' + 'доказательство ' * 80,
          'observations_used': [], 'uncertainties': ['Версия не установлена'],
          'recommended_checks': ['Повторить HTTP-пробу после выяснения причины ошибки.']}


class DecisionTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.db.executescript('''
          CREATE TABLE network_phase_plans (id INTEGER PRIMARY KEY,task_id INTEGER,
            goal TEXT,profile TEXT,target TEXT,parameters_json TEXT,argv_json TEXT,
            model_summary TEXT,status TEXT,created_at TEXT);
          CREATE TABLE evidence_snapshots (task_id INTEGER,evidence_sha256 TEXT,
            evidence_json TEXT,created_at TEXT);
          CREATE TABLE evidence_agent_reports (task_id INTEGER,evidence_sha256 TEXT,
            stage TEXT,report_json TEXT,created_at TEXT);
          CREATE TABLE pm_task_intents (task_id INTEGER,intent TEXT);
          CREATE TABLE pm_http_discovery (id INTEGER PRIMARY KEY,task_id INTEGER,path TEXT,error TEXT);
        ''')
        self.db.execute('INSERT INTO evidence_snapshots VALUES (?,?,?,?)', (11,DIGEST,json.dumps(BUNDLE),'now'))
        self.db.execute('INSERT INTO evidence_agent_reports VALUES (?,?,?,?,?)',
                        (11,DIGEST,'verify',json.dumps(REPORT),'now'))
        self.db.execute('INSERT INTO evidence_agent_reports VALUES (?,?,?,?,?)',
                        (11,'old','vuln',json.dumps({'summary':'STALE_REPORT'}),'before'))
        self.db.execute('INSERT INTO pm_task_intents VALUES (?,?)', (11,'Проверить учебную машину; ограничения задачи'))
        self.db.execute('INSERT INTO pm_http_discovery VALUES (?,?,?,?)',
                        (6,11,'/app/style.css','curl: (63) Maximum file size exceeded'))
        self.db.commit()
        package = types.ModuleType('orchestrator')
        evidence = types.ModuleType('orchestrator.evidence_pipeline')
        evidence.make_snapshot = lambda db, task: (DIGEST, BUNDLE)
        package.evidence_pipeline = evidence
        self.evidence = evidence
        self.add_patch(patch.dict(sys.modules, {'orchestrator':package,
                       'orchestrator.evidence_pipeline':evidence}))
        self.scope = self.add_patch(patch.object(d,'scope_check'))
        self.catalog = self.add_patch(patch.object(d,'candidates_from_evidence',return_value=[]))
        self.choose = self.add_patch(patch.object(d,'choose_with_model',return_value=[]))
        self.executor = self.add_patch(patch.object(d,'executor_plan',return_value=['mock-plan-only']))
        self.output = io.StringIO()
        self.add_patch(contextlib.redirect_stdout(self.output))

    def add_patch(self, patcher):
        if hasattr(patcher,'start'):
            result = patcher.start()
            self.addCleanup(patcher.stop)
            return result
        patcher.__enter__()
        self.addCleanup(patcher.__exit__, None,None,None)

    def test_empty_catalog_is_distinguished_and_never_calls_model(self):
        result = d.plan(self.db,11)
        self.assertEqual(result['diagnostics']['reason'],'no_candidates')
        self.assertEqual(result['diagnostics']['recommendation_count'],1)
        self.assertEqual(result['diagnostics']['web_errors'][0]['path'],'/app/style.css')
        self.choose.assert_not_called(); self.executor.assert_not_called()
        self.assertIn('нет новых проверок',self.output.getvalue())
        self.assertIn('Maximum file size exceeded',self.output.getvalue())

    def test_model_decline_is_distinguished_from_empty_catalog(self):
        self.catalog.return_value = [CANDIDATE]
        result = d.plan(self.db,11)
        self.assertEqual(result['diagnostics']['reason'],'model_selected_none')
        self.assertTrue(result['api_called']); self.executor.assert_not_called()

    def test_model_receives_task_and_current_reports_and_web(self):
        self.catalog.return_value = [CANDIDATE]
        d.plan(self.db,11)
        bundle = self.choose.call_args.args[0]
        self.assertIn('ограничения',bundle['operator_task'])
        self.assertEqual(bundle['agent_reports'],{'verify':REPORT})
        self.assertEqual(bundle['web_observations'],BUNDLE['web_observations'])
        prompt = d.decision_prompt(bundle,[CANDIDATE])
        self.assertIn('Версия не установлена',prompt)
        self.assertNotIn('STALE_REPORT',prompt)

    def test_existing_cache_upgraded_once_then_no_new_model_call(self):
        self.db.execute('''CREATE TABLE decision_agent_runs (
            task_id INTEGER,evidence_sha256 TEXT,selected_json TEXT,created_at TEXT,
            PRIMARY KEY(task_id,evidence_sha256))''')
        self.db.execute('INSERT INTO decision_agent_runs VALUES (?,?,?,?)',(11,DIGEST,'[]','old'))
        self.db.commit(); self.catalog.return_value=[CANDIDATE]
        first=d.plan(self.db,11); second=d.plan(self.db,11)
        self.assertEqual(first['status'],'completed')
        self.assertEqual(second['status'],'cached')
        self.assertEqual(self.choose.call_count,1)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM decision_agent_runs').fetchone()[0],1)

    def test_changed_report_refreshes_context_once(self):
        self.catalog.return_value=[CANDIDATE]
        d.plan(self.db,11)
        changed=dict(REPORT,recommended_checks=['Другая рекомендация'])
        self.db.execute('UPDATE evidence_agent_reports SET report_json=? WHERE evidence_sha256=?',
                        (json.dumps(changed),DIGEST)); self.db.commit()
        d.plan(self.db,11); d.plan(self.db,11)
        self.assertEqual(self.choose.call_count,2)

    def test_scope_rechecked_even_for_cached_decision(self):
        d.plan(self.db,11)
        self.scope.side_effect=ValueError('outside scope')
        with self.assertRaisesRegex(ValueError,'outside scope'):
            d.plan(self.db,11)
        self.choose.assert_not_called(); self.executor.assert_not_called()

    def test_diagnose_reads_only_and_does_not_request_a_model(self):
        self.db.execute('PRAGMA query_only=ON')
        d.diagnose(self.db,11)
        output=self.output.getvalue()
        self.assertIn('Maximum file size exceeded',output)
        self.assertIn(REPORT['summary'],output)
        self.assertIn('Диагностика завершена',output)
        self.choose.assert_not_called(); self.executor.assert_not_called()

    def test_display_removes_terminal_escape_sequences(self):
        self.assertEqual(d._display('ok\x1b[31mred\x1b[0m\x1b]0;title\x07'),'okred')

    def test_decision_model_process_requires_read_only_patch(self):
        calls=[]
        class Harness:
            def __init__(self,**kwargs):
                calls.append(kwargs)
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def start_session(self,name):
                return types.SimpleNamespace(run=lambda prompt: types.SimpleNamespace(
                    finish_reason='completed',events=[],final_response='{"select":[]}'))
        @contextlib.contextmanager
        def policy():yield '/tmp/test-policy.yml'
        self.evidence.read_only_analysis_patch=policy
        self.evidence.DSH_HOME=Path('/tmp/test-home')
        self.evidence.WORKSPACE=Path('/tmp/test-workspace')
        # Load clean code so the model mock above does not mask this path.
        clean_spec=importlib.util.spec_from_file_location('decision_policy_test',ROOT/'orchestrator/decision_agent.py')
        clean=importlib.util.module_from_spec(clean_spec);clean_spec.loader.exec_module(clean)
        with patch.dict(sys.modules,{'deepseek_harness':types.SimpleNamespace(DeepSeekHarness=Harness)}), \
             patch.object(clean.getpass,'getpass',return_value='fake-local-test'):
            self.assertEqual(clean.choose_with_model(BUNDLE,[CANDIDATE]),[])
        self.assertEqual(calls[0]['patches'],('/tmp/test-policy.yml',))

if __name__=='__main__':unittest.main(verbosity=2)
