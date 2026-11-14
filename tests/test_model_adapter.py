"""Adapter contract, decision authority and source inventory. No network/model."""
import ast
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from orchestrator import model_adapter as m, coordinated_attack as c, agent_actions as a
from orchestrator import check_environment
from tests import test_coordinated_attack as fixture

ROOT=Path(__file__).resolve().parents[1]


class AdapterTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='pm-adapter-unit-');self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        env=patch.dict(os.environ,{'PM_MODEL_AUDIT_DIR':str(self.root)})
        env.start();self.addCleanup(env.stop)

    def test_only_adapter_owns_production_model_transport(self):
        sources=[* (ROOT/'orchestrator').glob('*.py'), ROOT/'pm.py']
        owners=[]
        for path in sources:
            tree=ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='DeepSeekHarness':
                    owners.append(path.name)
                if isinstance(node,ast.Constant) and isinstance(node.value,str):
                    self.assertNotIn('/chat/completions',node.value,path.name)
                    self.assertNotIn('https://api.experientiallabs.ai',node.value,path.name)
        self.assertEqual(owners,['model_adapter.py'])

    def test_rejection_preserves_original_redacted_raw_and_hash(self):
        record=m.save_record({'request_id':'test','mode':'analysis'},'bad JSON PRIVATE-KEY',key='PRIVATE-KEY')
        value=m.ModelResult('session','bad JSON PRIVATE-KEY','completed',[],[],record)
        rejected=m.reject_response(value,'invalid_json',1)
        raw=Path(rejected['raw_response_ref']).read_text()
        self.assertEqual(raw,'bad JSON [REDACTED]')
        self.assertEqual(rejected['raw_response_sha256'],hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(Path(rejected['raw_response_ref']).stat().st_mode & 0o777,0o600)
        self.assertEqual(json.loads((self.root/'test.json').read_text())['recovery_attempt'],1)

    def test_modes_configuration_and_recovery_cannot_grant_tools(self):
        with self.assertRaises(ValueError):m.HarnessAdapter(mode='execute')
        with m.configuration(request_timeout_seconds=17,model='local-model'):
            adapter=m.HarnessAdapter(mode='analysis',model='ignored')
        self.assertEqual(adapter.timeout,17);self.assertEqual(adapter.options['model'],'local-model')
        self.assertNotEqual(m.HarnessAdapter(mode='analysis').options['model'],'local-model')
        session=m.AdapterSession(SimpleNamespace(mode='execute'),None,'test')
        with self.assertRaisesRegex(ValueError,'analysis mode'):session.run('repair',recovery_attempt=1)

    def test_token_stats_use_actual_sdk_message_event_not_context_sum(self):
        events=[{'type':'assistant/message','data':{'usage':{'inputTokens':12,'outputTokens':3,
                                                         'cacheReadTokens':4,'totalTokens':19}}},
                {'type':'assistant/message','data':{'usage':{'inputTokens':1,'outputTokens':2,'totalTokens':22}}}]
        self.assertEqual(m.statistics(events),{'input_tokens':13,'output_tokens':5,
                        'cache_read_tokens':None,'peak_context_tokens':22})

    def test_original_transport_exception_is_retained_without_secrets_in_message(self):
        owner=SimpleNamespace(mode='analysis',options={'provider':'test','model':'test'},
                              timeout=2,cancelled=False,timed_out=False,key='secret')
        original=OSError('Authorization: secret')
        with patch.object(m.diagnostics,'model_call',side_effect=original):
            with self.assertRaises(m.HarnessCallError) as caught:m.AdapterSession(owner,None,'session').run('analyze')
        self.assertIs(caught.exception.original,original)
        self.assertNotIn('secret',str(caught.exception))
        self.assertEqual(caught.exception.code,'transport_error')
        self.assertEqual(len(list(self.root.glob('*.json'))),1,'no automatic adapter replay')

    def test_echoed_api_key_cannot_reach_report_consumers_or_audit(self):
        owner=SimpleNamespace(mode='analysis',options={'provider':'test','model':'test'},
                              timeout=2,cancelled=False,timed_out=False,key='PRIVATE-KEY')
        response=SimpleNamespace(finish_reason='completed',final_response='Echo PRIVATE-KEY',events=[],notifications=[])
        with patch.object(m.diagnostics,'model_call',return_value=response):
            result=m.AdapterSession(owner,None,'session').run('analyze')
        self.assertEqual(result.final_response,'Echo [REDACTED]')
        self.assertNotIn('PRIVATE-KEY',Path(result.metadata['raw_response_ref']).read_text())

    def test_unavailable_audit_stops_before_any_model_or_tool_execution(self):
        owner=SimpleNamespace(mode='analysis',options={'provider':'test','model':'test'})
        with patch.object(m,'save_record',side_effect=PermissionError('private directory')), \
             patch.object(m.diagnostics,'model_call') as dispatch:
            with self.assertRaises(m.HarnessCallError) as caught:m.AdapterSession(owner,None,'session').run('analyze')
        self.assertEqual(caught.exception.code,'audit_error');dispatch.assert_not_called()

    def test_environment_check_is_read_only_and_reports_untested_versions(self):
        with patch.object(check_environment,'version',return_value='other-version'):
            result=check_environment.check()
        self.assertFalse(result['compatible'])
        self.assertEqual(len([e for e in result['errors'] if e.startswith('untested_version:')]),4)
        self.assertFalse(list(self.root.iterdir()))


class DecisionAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        with self.case.connect() as db:self.state=c.snapshot(db,11,2)

    def test_valid_narrow_known_service_and_inputs(self):
        decision=fixture.decision('vuln',references=['service:10.0.0.1:tcp:22'])
        decision['boundaries']['resource_refs']=['service:10.0.0.1:tcp:22']
        self.assertEqual(c.parse_decision(decision,self.state,a.ROLES),decision)

    def test_unknown_resources_foreign_task_and_expanded_authority_are_rejected(self):
        cases=[('task_id',12,'invalid_boundaries'),('target','10.0.0.2','invalid_boundaries'),
               ('resource_refs',['service:10.0.0.1:tcp:9999'],'resource_not_authorized'),
               ('resource_refs',['scope:10.0.0.2'],'resource_not_authorized'),
               ('allow_pivot',True,'invalid_boundaries')]
        for field,value,error in cases:
            with self.subTest(field=field,value=value):
                choice=fixture.decision('vuln');choice['boundaries'][field]=value
                with self.assertRaisesRegex(ValueError,error):c.parse_decision(choice,self.state,a.ROLES)

    def test_unresolved_input_and_unknown_profile_do_not_dispatch_role(self):
        for change,error in (({'inputs':[{'reference':'result:missing'}]},'invalid_inputs'),
                             ({'profile':'unlimited-shell'},'unknown_profile')):
            result=self.case.run_mode([{**fixture.decision('vuln'),**change}],decision_retries=0)
            self.assertIn(error,result['stop_reason']);self.assertFalse(self.case.calls)

    def test_legacy_planned_decision_is_not_silently_granted_new_fields(self):
        choice=fixture.decision('vuln');del choice['boundaries']
        with self.assertRaisesRegex(ValueError,'decision_fields'):c.parse_decision(choice,self.state,a.ROLES)


if __name__=='__main__':unittest.main(verbosity=2)
