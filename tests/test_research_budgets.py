"""Persistent budgets and bounded internal checks, temporary data only."""
import json
import sqlite3
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from orchestrator import research_budgets as budgets


class BudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'task.db';self.db=sqlite3.connect(self.path);self.addCleanup(self.db.close)
        self.db.execute('CREATE TABLE tasks(id INTEGER PRIMARY KEY,target TEXT)');self.db.execute("INSERT INTO tasks VALUES(11,'10.0.0.1')");self.db.commit()

    def test_extension_is_exactly_five_and_survives_reopening(self):
        budgets.ensure(self.db,11,'coordinator')
        for _ in range(15):budgets.consume(self.db,11,'coordinator')
        with self.assertRaises(budgets.Exhausted):budgets.consume(self.db,11,'coordinator')
        question=budgets.request(self.db,11,'coordinator')
        self.assertEqual(question['budget_request']['amount'],5)
        from orchestrator import operator_questions
        operator_questions.answer(self.db,11,question['id'],'approve');self.db.commit()
        with sqlite3.connect(self.path) as db:
            self.assertEqual(budgets.get(db,11,'coordinator')['remaining'],5)
            budgets.ensure(db,11,'coordinator',base=1)
            self.assertEqual(budgets.get(db,11,'coordinator')['limit'],20)

    def test_decline_and_duplicate_answer_do_not_grant_or_reset(self):
        from orchestrator import operator_questions
        for _ in range(15):budgets.consume(self.db,11,'coordinator')
        q=budgets.request(self.db,11,'coordinator')
        declined=operator_questions.answer(self.db,11,q['id'],'decline')
        self.assertIn('no budget increase',declined['answer']['permission_effect'])
        self.assertEqual(budgets.get(self.db,11,'coordinator')['remaining'],0)
        self.assertEqual(budgets.request(self.db,11,'coordinator')['id'],q['id'])
        with self.assertRaises(ValueError):operator_questions.answer(self.db,11,q['id'],'approve')

    def test_poc_ceiling_and_retry_identity_are_distinct_units(self):
        for index in range(15):budgets.consume(self.db,11,'poc','vuln',unit='poc_executor_dispatch',event_id=str(index))
        budgets.consume(self.db,11,'poc','vuln',event_id='14')
        self.assertEqual(budgets.get(self.db,11,'poc','vuln')['used'],15)
        with self.assertRaises(budgets.Exhausted):budgets.consume(self.db,11,'poc','vuln')
        with self.assertRaises(budgets.Exhausted):budgets.request(self.db,11,'poc','vuln')

    def test_profiles_and_long_operation_do_not_silently_restore_old_caps(self):
        from orchestrator import instructions
        from executor import netguard_root as broker
        self.assertEqual(instructions.limits(instructions.profile('vuln','http-surface'),{'step_limit':30,'poc_budget':15})['step_limit'],30)
        self.assertEqual(broker.operation_timeout('poc_run',600,'One measured long computation'),600)
        self.assertEqual(broker.operation_timeout('exec',600,'Bounded necessary operation'),600)
        for profile in ('poc_run','exec'):
            with self.assertRaises(ValueError):broker.operation_timeout(profile,600)
            with self.assertRaises(ValueError):broker.operation_timeout(profile,601,'not unlimited')

    def test_recon_round_grant_exceeds_old_eight_without_reset(self):
        from orchestrator import operator_questions
        budgets.ensure(self.db,11,'recon','rounds',base=4)
        for _ in range(4):budgets.consume(self.db,11,'recon','rounds',unit='round')
        q=budgets.request(self.db,11,'recon','rounds');operator_questions.answer(self.db,11,q['id'],'approve')
        self.assertEqual(budgets.ensure(self.db,11,'recon','rounds',base=4)['limit'],9)

    def test_large_intent_transports_as_file_without_6000_character_loss(self):
        import pm
        from unittest.mock import patch
        from intent_limits import clip_intent
        text='Задание\n'+'data\n'*3000+'Ограничение: без брутфорса'
        self.assertEqual(clip_intent(text),text);pm.validate_intent(text)
        paths=[]
        def planner(command,**kwargs):
            self.assertNotIn(text,command);self.assertNotIn('--task',command)
            path=Path(command[command.index('--task-file')+1]);paths.append(path)
            self.assertEqual(path.read_text(),text);self.assertEqual(path.stat().st_mode&0o777,0o600)
            return 11,{'tasks':[]}
        with patch.object(pm,'read_planner_stream',side_effect=planner):pm.run_planner_with_validation_retry('10.0.0.1',text,'fake-key')
        self.assertFalse(paths[0].exists())

    def test_js_gate_uses_every_granted_main_step_and_keeps_local_reads_separate(self):
        stats=Path(self.temp.name)/'stats.json';stats.write_text(json.dumps({'calls':24}))
        plugin=Path(__file__).resolve().parents[1]/'orchestrator/agent_actions.mjs'
        script='''
import {pathToFileURL} from 'node:url';
const [path,stats]=process.argv.slice(1);
process.env.PM_AGENT_STATS_FILE=stats;process.env.PM_AGENT_STEP_LIMIT='25';
const first=await import(pathToFileURL(path).href+'?limit=25');
const hooks={};first.apply({on:(name,fn)=>hooks[name]=fn});const agent={};
const call=(a,name='pm_net_exec')=>hooks['tools/pre-execute']({agent:a,name});
if(call(agent).kind!=='allow'||call(agent).kind!=='deny')throw Error('25th main step must be usable, 26th must stop');
process.env.PM_AGENT_STEP_LIMIT='30';
const extended=await import(pathToFileURL(path).href+'?limit=30');extended.apply({on:(name,fn)=>hooks[name]=fn});
const resumed={};for(let i=0;i<5;i++)if(call(resumed).kind!=='allow')throw Error('grant lost');
if(call(resumed).kind!=='deny')throw Error('restart refilled budget');
if(call(resumed,'pm_budget_status').kind!=='allow')throw Error('saved reads consumed main quota');
'''
        subprocess.run(['node','--input-type=module','-e',script,str(plugin),str(stats)],check=True,capture_output=True,text=True)
        self.assertEqual(json.loads(stats.read_text())['calls'],30)


class LaunchBudgetTests(unittest.TestCase):
    def setUp(self):
        from tests import test_coordinated_attack as fixture
        from orchestrator import agent_actions
        import importlib.util
        from unittest.mock import patch
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        spec=importlib.util.spec_from_file_location('budget_mcp',Path(__file__).resolve().parents[1]/'mcp/server.py')
        self.server=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.server)
        for p in (patch.object(self.server,'ASSET_DB',self.case.database),patch.object(self.server,'CAPABILITY_LOG',agent_actions.CAPABILITY_LOG),
                  patch.object(self.server,'POC_ROOT',self.case.root/'pocs'),patch.dict(os.environ,{'PM_BUDGET_ROLE':'vuln','PM_TASK_ID':'11'})):
            p.start();self.addCleanup(p.stop)

    def call(self,name,**kwargs):
        import asyncio
        reply=asyncio.run(self.server.mcp.call_tool(name,{'task_id':11,**kwargs}))
        blocks=reply[0] if isinstance(reply,tuple) else reply
        return json.loads(next(b.text for b in blocks if getattr(b,'type',None)=='text'))

    def test_specialist_extension_after_25_uses_public_mcp_and_persists(self):
        from orchestrator import operator_questions
        for index in range(25):self.assertEqual(self.call('pm_write_poc',filename='note.py',content='print(1)')['status'],'completed')
        refusal=self.call('pm_write_poc',filename='note.py',content='print(2)')
        self.assertEqual(refusal['status'],'waiting_operator')
        with self.case.connect() as db:operator_questions.answer(db,11,refusal['question_id'],'approve')
        for index in range(5):self.assertEqual(self.call('pm_write_poc',filename='note.py',content='print(2)')['status'],'completed')
        next_question=self.call('pm_write_poc',filename='note.py',content='print(3)')
        self.assertEqual(next_question['status'],'waiting_operator');self.assertNotEqual(refusal['question_id'],next_question['question_id'])
        with self.case.connect() as db:
            self.assertEqual(budgets.get(db,11,'specialist','vuln')['used'],30)
            self.assertEqual(budgets.get(db,11,'specialist','vuln')['limit'],30)

    def test_coordinator_15_then_five_survives_resume_without_extra_model(self):
        from tests.test_coordinated_attack import decision
        from orchestrator import coordinated_attack as coordinator,operator_questions
        from unittest.mock import Mock
        first=self.case.run_mode([decision('vuln','Concrete check '+str(i)) for i in range(15)])
        self.assertEqual(first['stop_reason'],'coordinator_budget_exhausted');self.assertEqual(len(self.case.calls),15)
        with self.case.connect() as db:
            q=operator_questions.listing(db,11,pending=True)[0]
            operator_questions.answer(db,11,q['id'],'approve')
        second=self.case.run_mode([decision('vuln','Additional check '+str(i)) for i in range(5)],continue_run=True)
        self.assertEqual(second['stop_reason'],'coordinator_budget_exhausted');self.assertEqual(len(self.case.calls),20)
        model=Mock(side_effect=AssertionError('Waiting consumes no model'))
        coordinator.run(11,api_key='fake-only',model=model,role_runner=self.case.role);model.assert_not_called()
        with self.case.connect() as db:self.assertEqual(budgets.get(db,11,'coordinator')['used'],20)
        from orchestrator import task_runtime
        with self.case.connect() as db:
            changes=db.total_changes;paused=task_runtime.pause(db,11)
            self.assertEqual(db.total_changes,changes)
        self.assertEqual(next(a for a in paused['research_budgets'] if a['category']=='coordinator')['limit'],20)

    def test_unknown_internal_check_stops_planning_and_resume_does_not_replay(self):
        from tests.test_coordinated_attack import decision
        from orchestrator import coordinated_attack as coordinator,check_series
        from unittest.mock import Mock
        def role(*args,**kwargs):
            self.case.role(*args,**kwargs)
            with self.case.connect() as db:
                check_series.initialize(db)
                db.execute("INSERT INTO pm_check_directions VALUES('offline-check',11,'paths','saved origin','unknown',0,?)",
                    (kwargs['assignment']['coordinator_step_id'],))
        model=Mock(return_value=json.dumps(decision('vuln','One bounded check')))
        result=coordinator.run(11,api_key='fake-only',model=model,role_runner=role)
        self.assertEqual(result['stop_reason'],'internal_check_outcome_unknown');self.assertEqual(model.call_count,1)
        self.assertEqual(result['steps'][0]['status'],'failed');self.assertTrue(result['steps'][0]['outcome_uncertain'])
        no_model=Mock(side_effect=AssertionError('No planning during paused preview'))
        coordinator.run(11,api_key='fake-only',model=no_model,role_runner=role);no_model.assert_not_called()
        self.assertEqual(len(self.case.calls),1)

    def test_exhausted_directions_allow_one_replan_then_give_concise_incomplete_result(self):
        from tests.test_coordinated_attack import decision
        from orchestrator import coordinated_attack as coordinator,check_series
        from unittest.mock import Mock
        def role(*args,**kwargs):
            self.case.role(*args,**kwargs)
            with self.case.connect() as db:
                check_series.initialize(db)
                db.execute("INSERT OR IGNORE INTO pm_check_directions VALUES('offline-check',11,'paths','saved origin','exhausted',5,?)",
                    (kwargs['assignment']['coordinator_step_id'],))
        model=Mock(side_effect=[json.dumps(decision('vuln','One bounded series')),json.dumps(decision('verify','Assess saved outcomes'))])
        result=coordinator.run(11,api_key='fake-only',model=model,role_runner=role)
        self.assertEqual(result['stop_reason'],'all_directions_exhausted');self.assertFalse(result['succeeded'])
        self.assertEqual(model.call_count,2);self.assertEqual(len(self.case.calls),2)

    def test_large_poc_and_streamed_stdin_use_files_not_command_arguments(self):
        from executor import netguard_root as broker
        code='print("large")\n'+'# padded source\n'*20000
        result=self.call('pm_write_poc',filename='large.py',content=code)
        self.assertEqual(result['status'],'completed');self.assertGreater(result['bytes'],256*1024)
        source=self.server.POC_ROOT/'task_11'/'large.py'
        data=self.server.POC_ROOT/'task_11'/'input.txt';payload=b'data\x00'*70000;data.write_bytes(payload);data.chmod(0o600)
        work=self.case.root/'work-local';work.mkdir(mode=0o700)
        details=broker.poc_stdin(str(data),str(source),os.getuid(),os.getgid(),work)
        with open(details['local'],'rb') as stream:
            proc=subprocess.run([sys.executable,'-c','import sys; print(len(sys.stdin.buffer.read()))'],stdin=stream,capture_output=True,text=True,check=True)
        self.assertEqual(int(proc.stdout),len(payload));self.assertNotIn(payload.decode('latin-1'),proc.args)
        data.write_bytes(b'new input; passwd is data, not an executed command')
        changed=broker.poc_stdin(str(data),str(source),os.getuid(),os.getgid(),work)
        self.assertEqual(changed['local'].read_bytes(),data.read_bytes())
        self.assertNotEqual(changed['poc_sha256'],details['poc_sha256'])
        self.assertEqual(details['local'].read_bytes(),payload)

    def test_poc_stdin_content_is_a_condition_but_readback_is_not_a_new_execution(self):
        from unittest.mock import patch
        folder=self.server.POC_ROOT/'task_11';folder.mkdir(parents=True)
        code=folder/'reader.py';code.write_text('import sys;print(sys.stdin.read())');code.chmod(0o600)
        data=folder/'input.txt';data.write_text('one');data.chmod(0o600)
        payload={'status':'completed','exit_code':0,'stdout':'stubbed target boundary'}
        with patch.object(self.server.subprocess,'run',return_value=subprocess.CompletedProcess([],0,json.dumps(payload),'')) as execute:
            self.assertEqual(self.call('pm_poc_run',target='10.0.0.1',poc_file='reader.py',interp='python3',stdin_file='input.txt')['status'],'completed')
            self.assertEqual(self.call('pm_poc_run',target='10.0.0.1',poc_file='reader.py',interp='python3',stdin_file='input.txt')['status'],'blocked')
            data.write_text('two')
            self.assertEqual(self.call('pm_poc_run',target='10.0.0.1',poc_file='reader.py',interp='python3',stdin_file='input.txt')['status'],'completed')
        self.assertEqual(execute.call_count,2)

    def test_generated_python_publishes_checks_and_plain_poc_is_unmeasured(self):
        from orchestrator.check_series import poc_events
        code='from __future__ import annotations\npm_check_start("one","local_test")\npm_check_end("one","negative")\n'
        result=self.call('pm_write_poc',filename='instrumented.py',content=code,instrument_checks=True)
        self.assertTrue(result['instrumented'])
        path=self.server.POC_ROOT/'task_11'/'instrumented.py'
        process=subprocess.run([sys.executable,str(path)],capture_output=True,text=True,check=True)
        measured=poc_events({'stdout':process.stdout})
        self.assertEqual((measured['started'],measured['finished']),(1,1));self.assertFalse(measured['universal_measurement'])
        self.assertEqual(poc_events({'stdout':'plain output'})['source'],'unmeasured')

    def test_public_poc_fifteenth_dispatch_is_last_and_sixteenth_does_not_execute(self):
        from unittest.mock import patch
        folder=self.server.POC_ROOT/'task_11';folder.mkdir(parents=True)
        calls=[]
        def executor(argv,**kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv,0,json.dumps({'status':'completed','exit_code':0,'task_id':11,'target':'10.0.0.1','stdout':'local stub execution '+str(len(calls))}), '')
        with patch.object(self.server.subprocess,'run',side_effect=executor):
            for index in range(16):
                name='check'+str(index)+'.py';file=folder/name;file.write_text('print('+str(index)+')');file.chmod(0o600)
                response=self.call('pm_poc_run',target='10.0.0.1',poc_file=name,interp='python3')
                self.assertEqual(response['status'],'completed' if index<15 else 'blocked',response)
        self.assertEqual(len(calls),15)
        self.assertFalse(response['execution_started'])
        with self.case.connect() as db:self.assertEqual(budgets.get(db,11,'poc','vuln')['used'],15)


class ReconQueueTests(unittest.TestCase):
    def test_exhausted_recon_resumes_saved_job_after_grant_without_duplicate_execution(self):
        from tests import test_full_scan_recovery as fixture
        from orchestrator import network_jobs,port_research,operator_questions
        case=fixture.FullScanRecoveryTests();case.setUp();self.addCleanup(case.doCleanups)
        ident=port_research.queue(case.db,1,case.target,'tcp',[22])[0]
        for _ in range(8):budgets.consume(case.db,1,'recon',unit='prior_test_operation')
        case.db.commit()
        with self.assertRaises(budgets.Exhausted):network_jobs.execute_job(case.db,ident)
        self.assertEqual(case.db.execute('SELECT COUNT(*) FROM network_job_runs').fetchone()[0],0)
        q=operator_questions.listing(case.db,1,pending=True)[0]
        operator_questions.answer(case.db,1,q['id'],'approve');case.db.commit()
        network_jobs.execute_job(case.db,ident)
        self.assertEqual(budgets.get(case.db,1,'recon')['used'],9)
        with self.assertRaisesRegex(ValueError,'already completed'):network_jobs.execute_job(case.db,ident)
        self.assertEqual(budgets.get(case.db,1,'recon')['used'],9)


if __name__=='__main__':unittest.main()
