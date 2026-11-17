"""Real role/SQLite/registered MCP; fake model and executor IO, temporary only."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from orchestrator import agent_actions as a,research_budgets,fact_state,task_memory
from tests import test_coordinated_attack as fixture


class ResultOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        spec=importlib.util.spec_from_file_location('ownership_mcp',Path(__file__).resolve().parents[1]/'mcp/server.py')
        self.server=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.server)
        self.executions=[];self.generated=[];self.on_model=lambda:None;self.on_format=lambda:None
        self.response={'summary':'Saved operation result only.','findings':[],'flags':[]}
        self.format_response=self.response
        owner=self
        class Harness:
            def __init__(self,**kwargs):self.env=kwargs['env']
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def start_session(self,name):
                def run(prompt,**kwargs):
                    if self.env.get('PM_BUDGET_ROLE'):
                        owner.on_model();value=owner.response
                    else:owner.on_format();value=owner.format_response
                    return SimpleNamespace(finish_reason='completed',events=[],
                        final_response=json.dumps(value) if isinstance(value,dict) else value)
                return SimpleNamespace(run=run)
        for p in (patch.object(self.server,'ASSET_DB',self.case.database),
                  patch.object(self.server,'CAPABILITY_LOG',a.CAPABILITY_LOG),
                  patch.object(self.server,'ROOT',self.case.root),
                  patch.dict(sys.modules,{'deepseek_harness':SimpleNamespace(DeepSeekHarness=Harness)}),
                  patch.object(subprocess,'run',side_effect=self.executor)):
            p.start();self.addCleanup(p.stop)

    def executor(self,argv,**kwargs):
        if 'session' in argv:return subprocess.CompletedProcess(argv,0,json.dumps({'sessions':[]}),'')
        self.executions.append(argv)
        return subprocess.CompletedProcess(argv,0,json.dumps(self.payload),'')

    def emit(self,step,role='vuln',status='completed',**extra):
        self.payload={'task_id':11,'target':'10.0.0.1','status':status,
            'exit_code':0 if status=='completed' else None,'stdout':'/status uid=1000(student)',**extra}
        with patch.dict(os.environ,{'PM_BUDGET_ROLE':role,'PM_TASK_ID':'11','PM_COORDINATOR_STEP_ID':str(step) if step else ''}):
            reply=json.loads(self.server.pm_net_exec(11,'10.0.0.1',json.dumps(
                ['/usr/bin/curl','--head',f'http://10.0.0.1/owner-{step}-{len(self.generated)}'])))
        self.assertIn('result_id',reply,reply)
        self.generated.append(reply['result_id']);return reply['result_id']

    def role(self,step=10,role='vuln',iteration=1):
        question='Inspect the specific saved evidence; do not repeat checks'
        assignment={'coordinator_step_id':step,'question':question,'expected_result':'Exact cited result or uncertainty',
            'references':[],'data':[]}
        result=a.run_role(11,role,question,iteration,api_key='fake-only',assignment=assignment)
        with self.case.connect() as db:
            saved=json.loads(db.execute('SELECT report_json FROM pm_agent_action_reports WHERE role=? AND iteration=?',(role,iteration)).fetchone()[0])
        self.assertEqual(saved,result['report']);return saved

    def test_projection_preserves_owner_and_operation_identity(self):
        rid=self.emit(10)
        original=json.loads((a.CAPABILITY_LOG/'task_11.jsonl').read_text().splitlines()[-1])
        captured=a.report_probe_records(11)[rid]['capture_record']
        for key in ('id','task_id','coordinator_step_id','actor_role','memory_operation_id'):
            self.assertEqual(captured[key],original[key])

    def test_own_success_is_not_changed_by_foreign_unknown_refusal_or_success(self):
        def execute():
            self.own=self.emit(10)
            for status in ('timeout','blocked','cancelled','completed'):
                self.emit(20,'access',status)
        self.on_model=execute
        report=self.role()
        self.assertEqual(report['execution_outcome']['status'],'executed')
        self.assertEqual([r['result_id'] for r in report['execution_outcome']['results']],[self.own])
        with self.case.connect() as db:
            self.assertEqual(research_budgets.step_usage(db,11,'specialist','vuln',10),1)
            self.assertEqual(research_budgets.step_usage(db,11,'specialist','access',20),4)

    def test_foreign_success_is_not_own_execution_access_or_hypothesis_closure(self):
        def execute():
            rid=self.emit(20,'access')
            self.response.update(access_level='user',access_signal='shell',access_probe_result_id=rid,
                access_quote='uid=1000(student)',hypotheses=[{'claim':'/status exists','result':'confirmed',
                    'probe_result_id':rid,'quote':'/status uid=1000(student)'}])
        self.on_model=execute
        report=self.role()
        self.assertEqual(report['execution_outcome']['results'],[])
        self.assertEqual(report['access_level'],'none')
        self.assertEqual(report['hypotheses'][0]['result'],'untested')
        with self.case.connect() as db:self.assertEqual(fact_state.access_state(db,11)['level'],'none')

    def test_ownerless_result_is_readable_but_not_assigned_to_current_step(self):
        def execute():self.rid=self.emit(None)
        self.on_model=execute
        report=self.role()
        self.assertEqual(report['execution_outcome']['results'],[])
        count=len(self.executions)
        reply=json.loads(self.server.pm_capability_read(11,self.rid))
        self.assertIn('uid=1000',json.dumps(reply));self.assertEqual(len(self.executions),count)
        self.assertEqual(reply['owner']['ownership_status'],'unestablished')
        self.assertFalse(reply['fresh_observation'])
        self.assertEqual(report['execution_outcome']['unattributed_results'][0]['result_id'],self.rid)
        self.assertIsNone(a.report_probe_records(11)[self.rid]['capture_record'].get('coordinator_step_id'))

    def test_shared_old_stdout_cannot_become_a_new_probe_after_readback(self):
        rid=self.emit(20,'access')
        count=len(self.executions)
        def read():
            self.server.pm_capability_read(11,rid)
            self.response.update(access_level='user',access_signal='shell',access_probe_result_id=rid,
                access_quote='uid=1000(student)',findings=[{'title':'/status exists','quote':'/status uid=1000(student)',
                    'kind':'observation','probe':{'result_id':rid}}])
        self.on_model=read
        report=self.role()
        self.assertEqual(len(self.executions),count)
        self.assertEqual(report['execution_outcome']['results'],[])
        self.assertEqual(report['access_signal'],'none');self.assertFalse(report['findings'])

    def test_saved_report_owner_survives_reopening_database(self):
        self.on_model=lambda:self.emit(10)
        report=self.role()
        record=report['execution_outcome']['results'][0]
        self.assertEqual(record['coordinator_step_id'],10)
        self.assertEqual(record['actor_role'],'vuln')
        self.assertEqual(record['ownership_status'],'known')
        with self.case.connect() as db:
            memory=task_memory.context(db,11,a.CAPABILITY_LOG/'task_11.jsonl')
            ref='result:'+record['result_id']
            group=next(g for g in memory['state']['checks']['groups'] if ref in g['references'])
            self.assertEqual(group['owners'][ref]['coordinator_step_id'],10)
            self.assertEqual(memory['material_index'][ref]['owner']['coordinator_step_id'],10)
        reply=json.loads(self.server.pm_capability_read(11,record['result_id']))
        self.assertEqual(reply['owner']['coordinator_step_id'],10)
        self.assertFalse(reply['fresh_observation'])

    def test_previous_current_step_record_does_not_become_new_on_resume(self):
        self.emit(10)
        report=self.role()
        self.assertEqual(report['execution_outcome']['results'],[])

    def test_unknown_remains_in_its_own_role_report(self):
        def execute():
            self.own=self.emit(10)
            self.on_model=lambda:self.emit(20,'access','timeout')
            self.other=self.role(20,'access',2)
        self.on_model=execute
        report=self.role()
        self.assertEqual(report['execution_outcome']['status'],'executed')
        self.assertEqual(self.other['execution_outcome']['status'],'unknown')
        self.assertEqual({r['coordinator_step_id'] for r in self.other['execution_outcome']['results']},{20})

    def test_foreign_result_arriving_during_format_repair_is_not_own_evidence(self):
        self.response='{"summary":'
        self.on_model=lambda:self.emit(10)
        def foreign():
            rid=self.emit(20,'access')
            self.format_response={'summary':'Saved data only.','findings':[],'flags':[],
                'hypotheses':[{'claim':'/status exists','result':'confirmed','probe_result_id':rid,
                    'quote':'/status uid=1000(student)'}]}
        self.on_format=foreign
        report=self.role()
        self.assertEqual(report['report_quality']['status'],'reformatted')
        self.assertEqual(report['execution_outcome']['status'],'executed')
        self.assertEqual({r['coordinator_step_id'] for r in report['execution_outcome']['results']},{10})
        self.assertEqual(report['hypotheses'][0]['result'],'untested')

    def test_conflicting_role_metadata_is_not_adopted_by_matching_step_id(self):
        self.on_model=lambda:self.emit(10,'access')
        self.assertEqual(self.role()['execution_outcome']['results'],[])

    def test_interrupted_role_preserves_only_its_own_receipts(self):
        def interrupted():
            self.own=self.emit(10)
            self.emit(20,'access','timeout')
            raise RuntimeError('Local simulated model interruption')
        self.on_model=interrupted
        with self.assertRaises(RuntimeError):self.role()
        with self.case.connect() as db:
            report=json.loads(db.execute('SELECT report_json FROM pm_agent_action_reports').fetchone()[0])
        self.assertTrue(report['stage_aborted'])
        self.assertEqual(report['execution_outcome']['status'],'unknown')
        self.assertEqual([r['result_id'] for r in report['execution_outcome']['results']],[self.own])


class SharedCaptureOwnershipTests(unittest.TestCase):
    def test_foreign_capture_is_audited_by_another_role_without_new_observation(self):
        from tests import test_verify_saved_capture as captures
        case=captures.SavedCaptureVerifyTests();case.setUp();self.addCleanup(case.doCleanups)
        (a.CAPABILITY_LOG/'task_11.jsonl').unlink()
        case.on_model=lambda:case.set_record(coordinator_step_id=20,actor_role='access')
        case.report['hypotheses']=[{'claim':'/status.txt contains alpha=42','result':'confirmed',
            'probe_result_id':case.rid,'quote':'alpha=42'}]
        question='Audit shared capture locally'
        result=a.run_role(11,'vuln',question,1,api_key='fake-only',assignment={
            'coordinator_step_id':10,'question':question,'expected_result':'Cited original only'})
        report=result['report']
        self.assertEqual(report['execution_outcome']['results'],[])
        case.assert_accepted(report)
        self.assertEqual(report['hypotheses'][0]['result'],'untested')
        with case.case.connect() as db:
            self.assertFalse(any(h['status']=='confirmed' for h in fact_state.list_hypotheses(db,11)))
        self.assertEqual(len((a.CAPABILITY_LOG/'task_11.jsonl').read_text().splitlines()),1)


if __name__=='__main__':unittest.main(verbosity=2)
