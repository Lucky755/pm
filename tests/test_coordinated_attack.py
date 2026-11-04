"""Durable coordinator integration with fake model/roles and temporary evidence."""
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
import io
import json
import os
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import pm
from orchestrator import coordinated_attack as c, agent_actions as a, objectives, diagnostics as d


def decision(role=None, question='Inspect the current evidence?', action=None, references=None, stop_kind=None):
    return {'action':action or ('run_role' if role else 'stop'),'role':role,'question':question,
            'reason':'Use the saved service and evidence records.', 'references':references or ['intent'],
            'expected_result':'An evidence-linked observation or an explicit unverified result.',
            'stop_kind':stop_kind if stop_kind else ('incomplete' if not role and action!='wait_operator' else None)}


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='pm-coordinator-test-');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.database=self.root/'tasks.db'
        self.patches=[patch.object(a,'connect',self.connect),patch.object(c,'LOCK_DIR',self.root/'locks'),
                      patch.object(a,'ROLE_LOCK_DIR',self.root/'report-locks'),
                      patch.object(a,'REPORT_DIR',self.root/'reports'),patch.object(a,'CAPABILITY_LOG',self.root/'caps'),
                      patch.object(c.flag_verify,'CAPABILITY_LOG',self.root/'caps'),
                      patch.object(c.flag_verify,'POC_ROOT',self.root/'pocs'),
                      patch.object(a,'TASK_WORK_BASE',self.root/'work'),patch.object(d,'EVENT_DIR',self.root/'events'),
                      patch.dict(os.environ,{key:'' for key in d.ENV_KEYS})]
        for p in self.patches:p.start();self.addCleanup(p.stop)
        self.console=io.StringIO()
        for manager in (redirect_stdout(self.console),redirect_stderr(self.console)):
            manager.__enter__();self.addCleanup(manager.__exit__,None,None,None)
        with self.connect() as db:
            a.ensure_schema(db);a.fact_state.ensure_schema(db);objectives.ensure_schema(db)
            db.executescript('''
                CREATE TABLE tasks(id INTEGER PRIMARY KEY,target TEXT);
                INSERT INTO tasks VALUES(11,'10.0.0.1');
                CREATE TABLE task_scope_settings(task_id INTEGER PRIMARY KEY,initial_target TEXT,
                    allow_pivot INTEGER,allow_port_forward INTEGER);
                INSERT INTO task_scope_settings VALUES(11,'10.0.0.1',0,0);
                CREATE TABLE pm_operator_approvals(task_id INTEGER,target TEXT,allowed TEXT,closed_at TEXT);
                INSERT INTO pm_operator_approvals VALUES(11,'10.0.0.1','10.0.0.1/32',NULL);
                CREATE TABLE pm_task_intents(task_id INTEGER PRIMARY KEY,intent TEXT);
                INSERT INTO pm_task_intents VALUES(11,'Найти флаги; без брутфорса\nHints:\n  /status');
                CREATE TABLE pm_tcp_full_scans(id INTEGER PRIMARY KEY,task_id INTEGER,target TEXT,
                    status TEXT,open_ports_json TEXT,created_at TEXT,last_seen_at TEXT);
            ''')
            db.execute("INSERT INTO pm_tcp_full_scans VALUES(1,11,'10.0.0.1','completed','[22,80]',?,?)",(c.now(),c.now()))
        self.calls=[];self.prompts=[];self.emit_evidence=True;self.report_extra={}

    def connect(self):return sqlite3.connect(self.database)

    def model(self, replies):
        queue=list(replies)
        def choose(prompt,key):
            self.prompts.append(json.loads(prompt.rsplit('\n',1)[1]))
            self.assertEqual(key,'fake-only')
            self.assertTrue(queue,'Unexpected extra model request')
            value=queue.pop(0)
            return value if isinstance(value,str) else json.dumps(value,ensure_ascii=False)
        return choose

    def role(self,task,role,question,iteration,poc,steps,**kwargs):
        self.calls.append((role,question,iteration,poc,steps,kwargs))
        if self.emit_evidence:
            a.CAPABILITY_LOG.mkdir(exist_ok=True)
            record={'id':f'{len(self.calls):024x}','task_id':11,'tool':'net_exec','provenance':'network',
                    'result':{'status':'completed','exit_code':0,'stdout':f'probe {len(self.calls)} for {role}'}}
            with (a.CAPABILITY_LOG/'task_11.jsonl').open('a') as stream:stream.write(json.dumps(record)+'\n')
        report={'summary':'Saved role result; no goal claim is proof.','findings':[],'flags':[],
                'verified':[],'uncertainties':[],'proposed_actions':[],**self.report_extra}
        with self.connect() as db:
            a.save_report(db,{'task_id':11,'target':'10.0.0.1'},role,iteration,report,1)
        return {'report':{'summary':'THIS RETURN VALUE MUST NOT BECOME STATE'}}

    def run_mode(self,replies=None,**kwargs):
        return c.run(11,api_key='fake-only',model=self.model(replies or [decision()]),role_runner=self.role,**kwargs)

    def rows(self):
        with self.connect() as db:return c.steps(db,11)

    def test_known_services_skip_recon_and_state_is_reloaded_after_vuln(self):
        result=self.run_mode([decision('vuln','What is served on port 80?',references=['service:10.0.0.1:tcp:80']),
                              decision('verify','Verify the observed response?',references=['result:'+'0'*23+'1']),decision()])
        self.assertEqual([v[0] for v in self.calls],['vuln','verify'])
        self.assertFalse(result['succeeded'])
        self.assertEqual(self.prompts[0]['service_map']['scan_mode'],'spot_check')
        self.assertIn('без брутфорса',self.prompts[0]['task']['intent'])
        self.assertIn('  /status',self.prompts[0]['task']['intent'])
        self.assertEqual(self.prompts[1]['recent_results'][0]['result_id'],'0'*23+'1')
        self.assertTrue(all(call[3:5]==(7,15) for call in self.calls))
        self.assertTrue(all(call[5]['max_tokens']==24000 for call in self.calls))

    def test_false_role_goal_claim_cannot_complete_primary_goal(self):
        with self.connect() as db:objectives.save_objectives(db,11,'Primary flag',exclusive=True)
        self.report_extra={'flags':[{'value':'FLAG{claimed_only}','objective_key':'goal','goal_confirmed':True,'goal_evidence':'not-existing'}]}
        result=self.run_mode([decision('vuln','Check the flag candidate?'),decision()])
        self.assertFalse(result['succeeded'])
        with self.connect() as db:self.assertEqual(objectives.objective_status(db,11)['primary']['status'],'open')

    def test_unverified_success_stop_is_rejected_with_bounded_repair(self):
        result=self.run_mode([decision(stop_kind='success'),decision(stop_kind='success')])
        self.assertEqual(len(self.prompts),2)
        self.assertEqual(self.calls,[])
        self.assertIn('success_not_evidence_backed',result['stop_reason'])
        self.assertFalse(result['succeeded'])

    def test_verified_goal_uses_existing_stop_checks_without_model_or_roles(self):
        with self.connect() as db:
            objectives.save_objectives(db,11,'Primary flag',exclusive=True)
            db.execute("UPDATE pm_objectives SET status='confirmed',evidence_ref='operator-reviewed' WHERE task_id=11")
        result=self.run_mode([])
        self.assertTrue(result['succeeded']);self.assertEqual(self.prompts,[]);self.assertEqual(self.calls,[])

    def test_goal_requires_existing_evidence_checks_then_operator_review(self):
        with self.connect() as db:objectives.save_objectives(db,11,'Primary flag',exclusive=True)
        self.report_extra={'flags':[{'value':'FLAG{offline_proof}','objective_key':'goal',
                                    'goal_evidence':'0'*23+'2'}]}
        def role(*args,**kwargs):
            self.role(*args,**kwargs)
            path=a.CAPABILITY_LOG/'task_11.jsonl'
            records=[]
            for number in (1,2):
                records.append({'id':f'{number:024x}','task_id':11,'tool':'net_exec','provenance':'network',
                                'argv':['offline-fixture',f'check-{number}'],
                                'result':{'status':'completed','exit_code':0,'stdout':'FLAG{offline_proof}'}})
            path.write_text(''.join(json.dumps(record)+'\n' for record in records))
        result=c.run(11,api_key='fake-only',model=self.model([decision('verify','Verify flag evidence?')]),role_runner=role)
        self.assertEqual(result['stop_reason'],'confirmed_flag_found')
        self.assertEqual(result['status'],'waiting_operator')
        self.assertFalse(result['succeeded'])
        with self.connect() as db:self.assertEqual(objectives.objective_status(db,11)['primary']['status'],'confirmed')
        result=self.run_mode([],continue_run=True)
        self.assertTrue(result['succeeded'])
        self.assertEqual(len(self.calls),1)

    def test_wait_and_resume_do_not_repeat_completed_role(self):
        result=self.run_mode([decision('vuln','Check the service?'),decision(action='wait_operator')])
        self.assertEqual(result['status'],'waiting_operator')
        self.run_mode([])
        self.assertEqual(len(self.calls),1)
        result=self.run_mode([decision('verify','Verify the service evidence?'),decision()],continue_run=True)
        self.assertEqual([v[0] for v in self.calls],['vuln','verify'])
        self.assertTrue(all(row['status']=='completed' for row in self.rows()))

    def test_step_budget_resume_and_repeat_role_report_numbers(self):
        self.run_mode([decision('vuln','Check port 80?')],max_steps=1)
        first=a.REPORT_DIR/'task_11'/'vuln-01.json'
        saved=first.read_bytes()
        self.run_mode([decision('vuln','Check port 22?')],max_steps=1)
        self.assertEqual([v[2] for v in self.calls],[1,2])
        self.assertEqual(first.read_bytes(),saved)
        self.assertTrue((a.REPORT_DIR/'task_11'/'vuln-02.json').is_file())
        with self.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM pm_agent_action_reports').fetchone()[0],2)

    def test_access_is_reviewed_and_significant_state_change_pauses(self):
        result=self.run_mode([decision('access','Prove the authorized low-privilege access?')])
        step=result['steps'][0]['id']
        self.assertEqual(self.calls,[])
        self.run_mode([])
        self.assertEqual(self.calls,[])
        self.report_extra={'access_level':'user','access_signal':'shell','access_probe_result_id':'0'*23+'1'}
        result=self.run_mode([],approve_step=step,max_steps=1)
        self.assertEqual(result['stop_reason'],'access_state_changed')
        self.assertEqual(result['steps'][0]['status'],'completed')
        self.run_mode([])
        self.assertEqual(len(self.calls),1)

    def test_running_checkpoint_is_never_replayed_even_with_continue(self):
        def interrupt(*args,**kwargs):raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            c.run(11,api_key='fake-only',model=self.model([decision('vuln','Check once?')]),role_runner=interrupt)
        self.assertEqual(self.rows()[0]['status'],'running')
        result=self.run_mode([],continue_run=True)
        self.assertEqual(result['stop_reason'],'interrupted_running_step');self.assertEqual(self.calls,[])
        step=self.rows()[0]['id']
        self.run_mode([decision()],abandon_running_step=step)
        self.assertEqual(self.rows()[0]['status'],'failed')
        self.assertTrue(self.rows()[0]['outcome_uncertain'])

    def test_invalid_json_unknown_reference_and_exhaustion(self):
        result=self.run_mode(['not JSON',decision('vuln',references=['result:foreign'])])
        self.assertEqual(len(self.prompts),2);self.assertEqual(self.calls,[])
        self.assertIn('unknown_reference',result['stop_reason'])
        self.assertEqual(json.loads(self.rows()[0]['decision_json']),{})

    def test_repeat_question_without_evidence_cannot_switch_role_to_bypass_guard(self):
        self.emit_evidence=False
        result=self.run_mode([decision('vuln','Check port 80?'),decision('verify','Check port 80?')],decision_retries=0)
        self.assertEqual(len(self.calls),1)
        self.assertIn('repeated_question_without_new_evidence',result['stop_reason'])

    def test_repair_can_choose_a_different_check_without_new_evidence(self):
        self.emit_evidence=False
        self.run_mode([decision('vuln','Check port 80?'),decision('vuln','Check port 80?'),
                       decision('vuln','Check port 22?'),decision()])
        self.assertEqual([v[1] for v in self.calls],['Check port 80?','Check port 22?'])

    def test_missing_scope_approval_blocks_all_calls(self):
        with self.connect() as db:db.execute('DELETE FROM pm_operator_approvals')
        result=self.run_mode([])
        self.assertEqual(result['stop_reason'],'scope_approval_required')
        self.assertEqual(self.calls,[]);self.assertEqual(self.prompts,[])

    def test_pending_triage_rejects_other_roles_before_execution(self):
        with self.connect() as db:
            a.fact_state.save_access_report(db,11,{'access_level':'user','access_signal':'shell','access_probe_result_id':'source'})
        result=self.run_mode([decision('vuln'),decision('access','ТРИАЖ: кто я и где нахожусь?')])
        self.assertEqual(result['stop_reason'],'role_approval_required')
        self.assertEqual(self.calls,[])

    def test_existing_report_slot_is_guarded_before_api_import(self):
        self.role(11,'vuln','seed',7,7,15)
        with self.assertRaisesRegex(ValueError,'already exists'):
            a.run_role(11,'vuln','do not overwrite',7,7,15,api_key='fake-only')
        with self.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM pm_agent_action_reports').fetchone()[0],1)

    def test_planned_step_resumes_without_model_and_occupied_number_is_reallocated(self):
        with self.connect() as db:
            c.ensure_schema(db);state=c.snapshot(db,11,2)
            db.execute("INSERT INTO pm_coordinator_runs VALUES(1,11,'10.0.0.1','running','',NULL,?,?)",(c.now(),c.now()))
            db.commit()
            c.insert_step(db,1,11,decision('vuln','Check planned endpoint?'),state,{'poc_budget':7,'step_limit':15,'max_tokens':24000})
        self.emit_evidence=False
        self.role(11,'vuln','legacy saved report',1,7,15)
        self.calls.clear()
        result=self.run_mode([],max_steps=1)
        self.assertEqual(len(self.prompts),0)
        self.assertEqual(self.calls[0][2],2)
        self.assertEqual(result['steps'][0]['status'],'completed')

    def test_provider_uses_read_only_policy_and_rejects_tool_events(self):
        responses=[SimpleNamespace(finish_reason='completed',events=[{'type':'tool/call'}],final_response='{}'),
                   SimpleNamespace(finish_reason='completed',events=[],final_response=json.dumps(decision()))]
        seen=[]
        class Harness:
            def __init__(inner,**kwargs):
                seen.append(kwargs)
                policy=json.loads(Path(kwargs['patches'][0]).read_text())
                self.assertEqual(policy[0]['insert'][0]['id'],'pm-evidence-readonly')
            def __enter__(inner):return inner
            def __exit__(inner,*_):return False
            def start_session(inner,name):
                return SimpleNamespace(run=lambda prompt,**kwargs:responses.pop(0))
        with patch.dict(sys.modules,{'deepseek_harness':SimpleNamespace(DeepSeekHarness=Harness)}),patch.dict(os.environ,{},clear=False):
            result=c.run(11,api_key='fake-only',role_runner=self.role,max_tokens=1000)
        self.assertEqual(len(seen),2);self.assertEqual(self.calls,[])
        self.assertEqual(seen[0]['provider'],'experiential')
        self.assertTrue(all(item['max_tokens']==1000 for item in seen))
        self.assertEqual(result['stop_reason'],'model_stopped_incomplete')

    def test_cli_dispatches_coordinated_and_preserves_legacy_mode(self):
        with patch.object(sys,'argv',['pm','attack','11','--coordinated','--coordinator-steps','2']):
            _,args=pm.parser_main()
        output={'status':'completed','succeeded':False,'stop_reason':'coordinator_step_limit','steps':[]}
        with patch.object(pm,'connect',self.connect),patch.object(c,'run',return_value=output) as coordinated:
            self.assertEqual(pm.op_attack(args),output)
            self.assertEqual(coordinated.call_args.kwargs['max_steps'],2)
        with patch.object(sys,'argv',['pm','attack','11']):_,legacy=pm.parser_main()
        with patch.object(pm,'connect',self.connect),patch.object(pm,'session_api_key',return_value='fake-only'),\
             patch.object(pm,'netguard_live_tasks',return_value=[]),\
             patch.object(c.attack_loop,'run',return_value={'stop_reason':'iterations_done','stages':[]}) as old:
            pm.op_attack(legacy)
            self.assertEqual(old.call_count,1)

    def test_stale_access_approval_requires_replan(self):
        result=self.run_mode([decision('access','Check authorized access?')])
        step=result['steps'][0]['id']
        with self.connect() as db:db.execute("UPDATE pm_task_intents SET intent='Changed restriction' WHERE task_id=11")
        result=self.run_mode([],approve_step=step)
        self.assertEqual(result['stop_reason'],'approval_state_changed_use_continue_to_replan')
        self.assertEqual(self.calls,[])
        self.run_mode([decision()],continue_run=True)
        self.assertEqual(self.rows()[0]['status'],'failed')

    def test_failed_role_requires_review_and_is_not_retried(self):
        runner=Mock(side_effect=RuntimeError('failed after possible work'))
        result=c.run(11,api_key='fake-only',model=self.model([decision('vuln','Check once?')]),role_runner=runner)
        self.assertEqual(result['status'],'waiting_operator')
        self.assertTrue(result['steps'][0]['outcome_uncertain'])
        self.run_mode([])
        self.assertEqual(self.calls,[])
        self.run_mode([decision()],continue_run=True)
        self.assertEqual(runner.call_count,1)

    def test_budget_and_operator_action_validation(self):
        for kwargs in ({'max_steps':0},{'decision_retries':3},{'continue_run':True,'approve_step':1}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):self.run_mode([],**kwargs)
        with patch.object(sys,'argv',['pm','attack','11','--approve-step','1']):_,args=pm.parser_main()
        with self.assertRaisesRegex(pm.OperatorError,'--coordinated'):pm.op_attack(args)

    def test_interactive_attack_selects_coordinator(self):
        answers=['7','11','','1','2','','','','','','0']
        with patch.object(pm,'session_api_key',return_value='fake-only'),\
             patch('builtins.input',side_effect=answers),patch.object(pm,'op_attack') as launch:
            pm.interactive()
        self.assertTrue(launch.call_args.args[0].coordinated)
        self.assertEqual(launch.call_args.args[0].coordinator_steps,2)

    def test_decision_diagnostics_include_expected_result_without_thoughts(self):
        with d.run('coordinator test',11):
            self.run_mode([decision('vuln','Check port 80?'),decision()])
            events=[e for e in d.read_events() if e['kind']=='coordinator.decision']
            self.assertEqual(events[0]['role'],'vuln')
            self.assertIn('expected_result',events[0])
            self.assertNotIn('reasoning',json.dumps(events))
            changes=[e for e in d.read_events() if e['kind']=='coordinator.state_changed']
            self.assertIn('result:'+'0'*23+'1',changes[0]['identifiers']['added']['references'])
        self.assertIn('expected_result=',self.console.getvalue())


def demo():
    case=CoordinatorTests();case.setUp()
    try:
        with d.run('offline coordinated demo',11):
            result=case.run_mode([decision('vuln','What is served on port 80?',references=['service:10.0.0.1:tcp:80']),
                                  decision('verify','Verify the saved response?',references=['result:'+'0'*23+'1']),decision()])
        output=case.console.getvalue()
    finally:case.doCleanups()
    for line in output.splitlines():
        if any(kind in line for kind in ('coordinator.decision','coordinator.state_changed','run.stop')):
            print(line)
    print('Selected roles:', [call[0] for call in case.calls], 'goal confirmed:',result['succeeded'])


if __name__=='__main__':
    if sys.argv[1:]==['--demo']:demo()
    else:unittest.main()
