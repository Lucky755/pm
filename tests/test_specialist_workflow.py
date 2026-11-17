"""PM concurrency contracts with fake agents; not SDK/MCP runtime coverage."""
import contextvars
import json
import os
import sqlite3
import threading
import time
import unittest
from unittest.mock import Mock,patch
from tests import test_coordinated_attack as fixture
from orchestrator import coordinated_attack as c,model_adapter as adapter,task_memory,task_sessions


def branch(role,question,port,**kwargs):
    d=fixture.decision(role,question,**kwargs);ref='service:10.0.0.1:tcp:'+str(port)
    d['branch_id']=ref;d['boundaries']['resource_refs']=[ref]
    return d


def awaiting():
    value=fixture.decision(action='await_specialists');value['stop_kind']=None;return value


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)

    def test_publication_starts_access_while_web_specialist_is_still_running(self):
        accessed=threading.Event();web_live=threading.Event();overlap=[];chosen=[]
        def role(*args,**kwargs):
            if args[1]=='vuln':
                web_live.set()
                with self.case.connect() as db:
                    head=task_memory.current(db,11)
                    task_memory.apply(db,11,head['version'],[{'section':'credentials','key':'candidate:offline','value':{
                        'trust':'candidate','username':'alice','secret':'offline','service_ref':'service:10.0.0.1:tcp:22'}}],reason='fake agent publication')
                if not accessed.wait(8):raise AssertionError('ACCESS was not concurrent')
            else:
                overlap.append(web_live.is_set());accessed.set()
            self.case.role(*args,**kwargs)
        def model(prompt,key):
            state=json.loads(prompt.rsplit('\n',1)[1]);active=state['active_specialists']
            if not chosen:value=branch('vuln','Explore web without blocking SSH',80);chosen.append('web')
            elif 'candidate:offline' in state['references'] and 'access' not in chosen:
                value=branch('access','Check the published exact candidate',22,references=['candidate:offline']);chosen.append('access')
            elif active:value=awaiting()
            else:value=fixture.decision()
            return json.dumps(value)
        result=c.run(11,api_key='fake-only',model=model,role_runner=role,max_specialists=2,max_steps=8)
        self.assertEqual(overlap,[True]);self.assertFalse(result['succeeded'])
        roles=[s for s in result['steps'] if s['decision'].get('action')=='run_role']
        self.assertEqual(len(roles),2);self.assertEqual(len({s['report_iteration'] for s in roles}),2)
        self.assertTrue(all(s['status']=='completed' for s in roles))

    def test_waiting_one_service_does_not_block_other_service(self):
        q=branch(None,'Need operator input for SSH route',22,action='wait_operator')
        result=c.run(11,api_key='fake-only',max_specialists=2,
            model=Mock(side_effect=[json.dumps(q),json.dumps(branch('vuln','Inspect independent web evidence',80)),json.dumps(fixture.decision())]),role_runner=self.case.role)
        self.assertEqual([r[0] for r in self.case.calls],['vuln'])
        self.assertEqual(result['status'],'waiting_operator');self.assertFalse(result['succeeded'])

    def test_running_checkpoint_is_not_restarted(self):
        first=c.run(11,api_key='fake-only',model=Mock(return_value=json.dumps(fixture.decision())),max_specialists=2)
        with self.case.connect() as db:
            state=c.snapshot(db,11,2)
            one=c.insert_step(db,first['coordinator_run_id'],11,branch('vuln','Interrupted check',80),state,{},status='running')
            c.insert_step(db,first['coordinator_run_id'],11,branch('access','Interrupted independent check',22),state,{},status='running')
        model=Mock(side_effect=AssertionError('No automatic replay'))
        result=c.run(11,api_key='fake-only',model=model,max_specialists=2)
        self.assertEqual(result['stop_reason'],'interrupted_running_step');model.assert_not_called()
        result=c.run(11,api_key='fake-only',model=model,max_specialists=2,abandon_running_step=one)
        self.assertEqual(result['stop_reason'],'interrupted_running_step');model.assert_not_called()
        self.assertEqual(len([s for s in result['steps'] if s['status']=='running']),1)
        self.assertEqual(result['specialist_limit'],2)

    def test_completed_question_is_not_reexecuted_after_resume(self):
        value=branch('vuln','One fixed check',80)
        first=c.run(11,api_key='fake-only',model=Mock(return_value=json.dumps(value)),role_runner=self.case.role,
            max_specialists=2,max_steps=1)
        second=c.run(11,api_key='fake-only',model=Mock(return_value=json.dumps(value)),role_runner=self.case.role,
            max_specialists=2,decision_retries=0)
        self.assertEqual(len(self.case.calls),1)
        self.assertEqual(first['coordinator_run_id'],second['coordinator_run_id'])
        self.assertIn('repeated_question_without_new_evidence',second['stop_reason'])

    def test_planned_cancellation_is_not_a_failed_executed_operation(self):
        from orchestrator.specialist_workflow import request_cancel
        result=c.run(11,api_key='fake-only',model=Mock(return_value=json.dumps(fixture.decision())),max_specialists=1)
        with self.case.connect() as db:
            step=c.insert_step(db,result['coordinator_run_id'],11,branch('access','Not yet executed',22),c.snapshot(db,11,2),{})
            request_cancel(db,11,step)
            row=next(r for r in c.steps(db,11) if r['id']==step)
        self.assertFalse(row['outcome_uncertain']);self.assertEqual(c.step_view(row)['execution_outcome']['status'],'not_started')
        self.assertFalse(self.case.calls)

    def test_limits_and_overlapping_work_are_rejected(self):
        from orchestrator.specialist_workflow import conflicts,unresolved_conflict
        web=branch('vuln','web question',80)
        self.assertTrue(conflicts(branch('access','same service',80),{1:{'decision':web}}))
        self.assertFalse(conflicts(branch('access','different service',22),{1:{'decision':web}}))
        row={'status':'failed','error':'interrupted_unknown_outcome','outcome_uncertain':1,'decision_json':json.dumps(web)}
        self.assertTrue(unresolved_conflict(branch('verify','Same operation with new wording',80),[row]))
        self.assertFalse(unresolved_conflict(branch('access','Independent operation',22),[row]))
        for value in (0,11,True):
            with self.assertRaises(ValueError):adapter.OwnedWorkflow(value)

    def test_unknown_check_in_other_branch_does_not_damage_completed_report(self):
        from orchestrator import check_series
        result=c.run(11,api_key='fake-only',model=Mock(return_value=json.dumps(fixture.decision())),max_specialists=1)
        decision=branch('vuln','Independent web check',80)
        with self.case.connect() as db:
            state=c.snapshot(db,11,2)
            step=c.insert_step(db,result['coordinator_run_id'],11,decision,state,{})
            iteration=next(r for r in c.steps(db,11) if r['id']==step)['report_iteration']
            check_series.initialize(db)
            db.execute('INSERT INTO pm_check_directions VALUES(?,?,?,?,?,?,?)',
                ('other',11,'authentication','ssh:22','unknown',0,step+100))
        self.case.role(11,'vuln',decision['question'],iteration,15,25)
        with self.case.connect() as db:
            _,reason=c.complete_specialist(db,11,result['coordinator_run_id'],step,decision,iteration,2,branch_local=True)
            self.assertIsNone(reason)
            self.assertEqual(next(r for r in c.steps(db,11) if r['id']==step)['status'],'completed')
            self.assertEqual(check_series.state(db,11)[0]['state'],'unknown')

    def test_cas_and_distinct_annotations_are_not_lost_between_writers(self):
        barrier=threading.Barrier(2);out=[]
        def write(index):
            with self.case.connect() as db:
                barrier.wait(3)
                with task_memory.atomic(db):
                    head=task_memory.current(db,11)
                    task_memory.apply(db,11,head['version'],[{'section':'questions','key':'branch'+str(index),'value':{'question':str(index)}}],reason='parallel local annotation')
                out.append(index)
        with adapter.OwnedWorkflow(2) as workflow:
            for index in (1,2):workflow.submit(index,write,index)
            for worker in workflow.workers.values():worker.future.result(5)
        with self.case.connect() as db:state=task_memory.current(db,11)
        self.assertEqual(sorted(out),[1,2]);self.assertEqual(len(state['state']['questions']),2)
        with self.case.connect() as db,self.assertRaises(task_memory.VersionConflict):
            task_memory.apply(db,11,0,[],reason='stale writer')

    def test_terminal_owner_context_is_isolated_between_threads(self):
        barrier=threading.Barrier(2);owners=[]
        def role(index):
            with self.case.connect() as db:
                with task_sessions.role_scope(db,11,str(index)):
                    before=task_sessions.owner();barrier.wait(3);time.sleep(.01)
                    self.assertEqual(before,task_sessions.owner());owners.append(before)
        with adapter.OwnedWorkflow(2) as workflow:
            for index in (1,2):workflow.submit(index,role,index)
            for worker in workflow.workers.values():worker.future.result(5)
        self.assertEqual(len(set(owners)),2)

    def test_cancellation_does_not_cancel_the_other_owned_worker(self):
        ready=threading.Event();other=threading.Event()
        def hold():
            ready.set()
            while True:adapter.check_cancelled();time.sleep(.01)
        with adapter.OwnedWorkflow(2) as workflow:
            first=workflow.submit(1,hold);self.assertTrue(ready.wait(2))
            second=workflow.submit(2,lambda:other.set())
            first.cancel()
            with self.assertRaises(adapter.HarnessCallError):first.future.result(2)
            second.future.result(2);self.assertTrue(other.is_set())

    def test_cli_default_and_explicit_limit(self):
        import pm,sys
        with patch.object(sys,'argv',['pm','attack','11','--coordinated','--max-specialists','2']):
            self.assertEqual(pm.parser_main()[1].max_specialists,2)
        with patch.object(sys,'argv',['pm','new','--target','10.0.0.1','--task','test','--legacy','--max-specialists','2']):
            args=pm.parser_main()[1]
        with self.assertRaises(pm.OperatorError):pm.validate_launch_options(args,'legacy',new=True)
        from orchestrator import task_runtime
        with self.case.connect() as db:
            self.assertEqual(task_runtime.specialist_limit(db,11),2)
            task_runtime.specialist_limit(db,11,1)
        with self.case.connect() as db:
            before=db.total_changes
            self.assertEqual(task_runtime.specialist_limit(db,11),1)
            self.assertEqual(db.total_changes,before)

    def test_child_tool_policy_cannot_broaden_inherited_restriction(self):
        from orchestrator import agent_actions as a
        from types import SimpleNamespace
        import sys
        seen=[]
        class Harness:
            def __init__(self,**options):seen.append(json.loads(options['env']['PM_AGENT_ALLOWED_TOOLS']))
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def start_session(self,name):
                return SimpleNamespace(run=lambda *args,**kw:SimpleNamespace(finish_reason='completed',events=[],final_response=json.dumps({
                    'summary':'Saved data reviewed, no target action.','findings':[],'flags':[],'verified':[],'uncertainties':[],'proposed_actions':[]})))
        with patch.dict(os.environ,{'PM_AGENT_ALLOWED_TOOLS':'["pm_capability_read"]'}),patch.dict(sys.modules,{'deepseek_harness':SimpleNamespace(DeepSeekHarness=Harness)}):
            with adapter.OwnedWorkflow(2) as workflow:
                worker=workflow.submit(1,a.run_role,11,'vuln','Read saved data',1,api_key='fake-only')
                worker.future.result(5)
            self.assertEqual(os.environ['PM_AGENT_ALLOWED_TOOLS'],'["pm_capability_read"]')
        self.assertEqual(seen,[['pm_capability_read']])


class MCPConcurrencyTests(unittest.TestCase):
    def setUp(self):
        from tests import test_research_budgets as fixture
        self.case=fixture.LaunchBudgetTests();self.case.setUp();self.addCleanup(self.case.doCleanups)

    def test_identical_public_executor_requests_launch_only_once(self):
        import subprocess
        calls=[];gate=threading.Barrier(2);repeat_refused=threading.Event()
        def executor(argv,**kw):
            calls.append(argv);repeat_refused.wait(3)
            return subprocess.CompletedProcess(argv,0,json.dumps({'status':'completed','exit_code':0,'stdout':'one actual stub dispatch'}),'')
        def run():
            gate.wait(3)
            result=self.case.call('pm_net_exec',target='10.0.0.1',argv_json=json.dumps(['/usr/bin/curl','http://10.0.0.1/one-check']))
            if result['status']=='blocked':repeat_refused.set()
            return result
        with patch.object(self.case.server.subprocess,'run',side_effect=executor),adapter.OwnedWorkflow(2) as workflow:
            workers=[workflow.submit(i,run) for i in (1,2)]
            results=[w.future.result(5) for w in workers]
        self.assertEqual(len(calls),1)
        self.assertEqual(sorted(r['status'] for r in results),['blocked','completed'])
        self.assertEqual(next(r for r in results if r['status']=='blocked')['reason'],'previous_outcome_unknown')

    def test_two_publications_keep_both_candidates_and_explicit_cas_conflict(self):
        from orchestrator import material_processing
        gate=threading.Barrier(2)
        with patch.object(material_processing,'ROOT',self.case.case.root/'materials'):
            with self.case.case.connect() as db:
                source=material_processing.save(db,11,b'alice=local1\nbob=local2',name='saved candidates',source_ref='operator:offline')
            def publish(user,secret,version=-1):
                return self.case.call('pm_publish_candidate',service_ref='service:10.0.0.1:tcp:22',username=user,secret=secret,
                    source_ref=source['reference'],quote=user+'='+secret,expected_version=version)
            def run(user,secret):gate.wait(3);return publish(user,secret)
            with adapter.OwnedWorkflow(2) as workflow:
                first=workflow.submit(1,run,'alice','local1');second=workflow.submit(2,run,'bob','local2')
                results=[w.future.result(5) for w in (first,second)]
            self.assertTrue(all(r['status']=='completed' for r in results))
            with self.case.case.connect() as db:head=task_memory.current(db,11)
            self.assertEqual(len(head['state']['credentials']),2)
            self.assertEqual(publish('alice','local1',0)['status'],'blocked')
            self.assertEqual(publish('alice','local1')['version'],head['version'])


if __name__=='__main__':unittest.main()
