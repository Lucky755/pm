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

    def identical_role(self,*args,**kwargs):
        self.role(*args,**kwargs)
        path=a.CAPABILITY_LOG/'task_11.jsonl'
        records=[json.loads(line) for line in path.read_text().splitlines()]
        records[-1]['result']['stdout']='80/tcp open; identical saved response'
        path.write_text(''.join(json.dumps(record)+'\n' for record in records))

    def test_identical_stdout_with_new_ids_stops_after_first_check(self):
        choose=decision('vuln','Check the same port?')
        result=c.run(11,api_key='fake-only',model=self.model([choose]*3),role_runner=self.identical_role,
                     max_steps=3,decision_retries=0)
        self.assertEqual(len(self.calls),1)
        self.assertIn('repeated_question_without_new_evidence',result['stop_reason'])

    def test_identical_check_cannot_be_repeated_through_another_role(self):
        result=c.run(11,api_key='fake-only',model=self.model([
            decision('vuln','Check the same port?'),decision('verify','Check the same port?')]),
            role_runner=self.identical_role,max_steps=2,decision_retries=0)
        self.assertEqual(len(self.calls),1)
        self.assertIn('repeated_question_without_new_evidence',result['stop_reason'])

    def test_rereading_data_and_duplicate_capture_do_not_change_knowledge(self):
        self.run_mode([decision('vuln','Check once?')],max_steps=1)
        with self.connect() as db:before=c.snapshot(db,11,2)
        path=a.CAPABILITY_LOG/'task_11.jsonl'
        original=json.loads(path.read_text().splitlines()[0])
        duplicate={**original,'id':'f'*24,'timestamp':'2099-01-01'}
        read={'id':'e'*24,'task_id':11,'tool':'capability_read','provenance':'local',
              'result':{'status':'completed','stdout':json.dumps(original)}}
        with path.open('a') as stream:
            stream.write(json.dumps(duplicate)+'\n'+json.dumps(read)+'\n')
        with self.connect() as db:after=c.snapshot(db,11,2)
        self.assertEqual(before['knowledge_sha256'],after['knowledge_sha256'])
        self.assertNotEqual(before['history_sha256'],after['history_sha256'])
        self.assertIn('result:'+'f'*24,after['references'])
        result=self.run_mode([decision('vuln','Check once?')],max_steps=1,decision_retries=0)
        self.assertEqual(len(self.calls),1)
        self.assertIn('repeated_question_without_new_evidence',result['stop_reason'])

    def test_metadata_only_updates_of_saved_sources_do_not_change_knowledge(self):
        self.run_mode([decision('vuln','Check once?')],max_steps=1)
        with self.connect() as db:
            before=c.snapshot(db,11,2)
            db.execute("UPDATE pm_tcp_full_scans SET id=17,created_at='2099-01-01',last_seen_at='2099-01-01'")
            db.commit()
            after=c.snapshot(db,11,2)
        self.assertEqual(before['knowledge_sha256'],after['knowledge_sha256'])
        result=self.run_mode([decision('vuln','Check once?')],decision_retries=0)
        self.assertEqual(len(self.calls),1)
        self.assertIn('repeated_question_without_new_evidence',result['stop_reason'])

    def test_new_distinct_evidence_after_a_step_allows_a_revised_check(self):
        self.run_mode([decision('vuln','Check once?')],max_steps=1)
        with self.connect() as db:before=c.snapshot(db,11,2)
        record={'id':'f'*24,'task_id':11,'tool':'http_path','provenance':'network',
                'result':{'status':'completed','exit_code':0,'stdout':'New captured HTTP/1.1 403 Forbidden'}}
        with (a.CAPABILITY_LOG/'task_11.jsonl').open('a') as stream:stream.write(json.dumps(record)+'\n')
        with self.connect() as db:after=c.snapshot(db,11,2)
        self.assertNotEqual(before['knowledge_sha256'],after['knowledge_sha256'])
        self.run_mode([decision('vuln','Check once?',references=['result:'+'f'*24])],max_steps=1)
        self.assertEqual(len(self.calls),2)

    def test_assignment_expectation_cannot_bypass_pending_access_triage(self):
        with self.connect() as db:
            a.fact_state.save_access_report(db,11,{'access_level':'user','access_signal':'shell','access_probe_result_id':'source'})
            state=c.snapshot(db,11,2)
        choice=decision('access','ТРИАЖ: кто я и где нахожусь?')
        choice['expected_result']='Escalate to root and capture the privileged flag.'
        with self.assertRaises(ValueError):c.parse_decision(choice,state,a.ROLES)
        assignment={'question':choice['question'],'expected_result':choice['expected_result'],
                    'references':['intent'],'data':[]}
        with self.assertRaises(ValueError):
            a.run_role(11,'access',choice['question'],9,api_key='fake-only',assignment=assignment)

    def test_distinct_independent_verify_uses_existing_probe_as_basis(self):
        verify=decision('verify','Use an independent HTTP request to test the port-80 claim?',
                        references=['result:'+'0'*23+'1'])
        verify['expected_result']='A separately captured HTTP status and headers, or a quoted failure.'
        result=c.run(11,api_key='fake-only',model=self.model([
            decision('vuln','Check the port-80 claim?'),verify,decision()]),role_runner=self.identical_role)
        self.assertEqual([call[0] for call in self.calls],['vuln','verify'])
        self.assertFalse(result['succeeded'])

    def test_incomplete_saved_report_requires_review_without_next_model_call(self):
        self.report_extra={'report_incomplete':True,'report_warning':'verify не выполнил прямой зонд'}
        result=self.run_mode([decision('verify','Check evidence?'),decision()])
        self.assertEqual(result['status'],'waiting_operator')
        self.assertEqual(result['stop_reason'],'role_report_incomplete_requires_review')
        self.assertEqual(len(self.prompts),1)
        row=result['steps'][0]
        self.assertEqual(row['status'],'failed');self.assertTrue(row['outcome_uncertain'])
        self.assertEqual(row['error'],'report_incomplete')
        self.assertTrue(Path(row['report_path']).is_file())
        self.run_mode([])
        self.assertEqual(len(self.calls),1)

    def test_valid_negative_report_is_completed_and_continues(self):
        self.report_extra={'summary':'The probe returned no vulnerable behavior.','verified':[],
                           'uncertainties':['No impact demonstrated.']}
        result=self.run_mode([decision('verify','Test the negative observation?'),decision()])
        self.assertEqual(result['steps'][0]['status'],'completed')
        self.assertEqual(len(self.prompts),2)
        self.assertFalse(result['succeeded'])

    def test_specialist_receives_assignment_in_actual_full_and_compact_prompts(self):
        seen=[]
        a.CAPABILITY_LOG.mkdir()
        record={'id':'f'*24,'task_id':11,'tool':'net_exec','provenance':'network',
                'result':{'status':'completed','exit_code':0,'stdout':'Saved reference response'}}
        (a.CAPABILITY_LOG/'task_11.jsonl').write_text(json.dumps(record)+'\n')
        class Harness:
            def __init__(inner,**kwargs):pass
            def __enter__(inner):return inner
            def __exit__(inner,*args):return False
            def start_session(inner,name):
                def run(prompt,**kwargs):
                    seen.append(prompt)
                    report={'summary':'An honest negative result.','findings':[], 'flags':[],
                            'verified':[], 'uncertainties':[], 'proposed_actions':[]}
                    return SimpleNamespace(finish_reason='completed',events=[],final_response=json.dumps(report))
                return SimpleNamespace(run=run)
        for iteration,threshold in ((1,10**9),(2,1)):
            choice=decision('vuln',f'Inspect service evidence variant {iteration}?',
                            references=['service:10.0.0.1:tcp:80'])
            if iteration==2:choice['references'].append('result:'+'f'*24)
            choice['expected_result']='ASSIGNMENT_EXPECTED: exact status with evidence, without brute force.'
            choose=self.model([choice])
            def current_model(prompt,key):
                result=choose(prompt,key)
                if iteration==2:
                    with self.connect() as db:
                        db.execute("UPDATE pm_tcp_full_scans SET id=17,created_at='2099-01-01'")
                return result
            with patch.dict(sys.modules,{'deepseek_harness':SimpleNamespace(DeepSeekHarness=Harness)}),\
                 patch.object(a,'close_task_sessions'),patch.object(a,'CONTEXT_PRESSURE_TOKENS',threshold):
                c.run(11,api_key='fake-only',model=current_model,max_steps=1)
            prompt=seen[-1]
            self.assertIn(choice['expected_result'],prompt)
            self.assertIn('Specialist assignment',prompt)
            block=prompt.split('<specialist_assignment>\n',1)[1].split('\n</specialist_assignment>',1)[0]
            assignment=json.loads(block)
            self.assertEqual(assignment['question'],choice['question'])
            self.assertEqual(assignment['references'],choice['references'])
            self.assertEqual(assignment['data'][0]['value']['port'],80)
            if iteration==2:
                self.assertEqual(assignment['data'][0]['value']['sources'][0]['key']['id'],17)
                self.assertIn('Saved reference response',assignment['data'][1]['value']['excerpt_untrusted'])
            self.assertEqual(json.loads(self.rows()[-1]['assignment_json']),assignment)
            self.assertIn('без брутфорса',prompt)
            self.assertEqual('resuming its stage' in prompt,iteration==2)
        with patch.dict(sys.modules,{'deepseek_harness':SimpleNamespace(DeepSeekHarness=Harness)}),\
             patch.object(a,'close_task_sessions'):
            a.run_role(11,'vuln','Legacy check without assignment',99,api_key='fake-only')
        self.assertIn('Current objective of this round: Legacy check without assignment',seen[-1])
        self.assertNotIn('<specialist_assignment>',seen[-1])

    def test_actual_verify_negative_probe_is_not_an_incomplete_report(self):
        class Harness:
            def __init__(inner,**kwargs):pass
            def __enter__(inner):return inner
            def __exit__(inner,*args):return False
            def start_session(inner,name):
                def run(prompt,**kwargs):
                    a.CAPABILITY_LOG.mkdir(exist_ok=True)
                    record={'id':'e'*24,'task_id':11,'tool':'net_exec','provenance':'network',
                            'result':{'status':'completed','exit_code':0,'stdout':'HTTP/1.1 404 Not Found'}}
                    (a.CAPABILITY_LOG/'task_11.jsonl').write_text(json.dumps(record)+'\n')
                    report={'summary':'HTTP check returned 404; no impact demonstrated.',
                            'findings':[],'flags':[],'verified':[],'uncertainties':[],
                            'proposed_actions':[],'probe':{'result_id':'e'*24}}
                    return SimpleNamespace(finish_reason='completed',events=[],final_response=json.dumps(report))
                return SimpleNamespace(run=run)
        with patch.dict(sys.modules,{'deepseek_harness':SimpleNamespace(DeepSeekHarness=Harness)}),\
             patch.object(a,'close_task_sessions'):
            result=c.run(11,api_key='fake-only',model=self.model([
                decision('verify','Test the negative HTTP result?'),decision()]))
        self.assertEqual(result['steps'][0]['status'],'completed')
        self.assertEqual(result['stop_reason'],'model_stopped_incomplete')
        with self.connect() as db:
            report=json.loads(db.execute('SELECT report_json FROM pm_agent_action_reports').fetchone()[0])
        self.assertFalse(report.get('report_incomplete'))

    def test_large_selected_report_is_bounded_and_unknown_reference_is_rejected(self):
        self.emit_evidence=False
        self.report_extra={'summary':'UNTRUSTED report content '*1000}
        self.role(11,'recon','seed',1,7,15)
        with self.connect() as db:
            state=c.snapshot(db,11,2)
            assignment=c.resolve_assignment(db,decision('vuln',references=['report:recon:1']),state)
            item=assignment['data'][0]
            self.assertTrue(item['truncated'])
            self.assertLessEqual(len(item['excerpt_untrusted']),1800)
            self.assertGreater(item['original_characters'],1800)
            self.assertEqual(item['reference'],'report:recon:1')
            with self.assertRaisesRegex(ValueError,'unknown_reference'):
                c.resolve_assignment(db,decision('vuln',references=['report:recon:999']),state)

    def test_selected_observation_and_goal_resolve_data_and_recheck_ownership(self):
        with self.connect() as db:
            objectives.save_objectives(db,11,'Confirm the operator objective',exclusive=True)
            db.executescript('''
                CREATE TABLE network_phase_plans(id INTEGER PRIMARY KEY,task_id INTEGER,target TEXT,
                    profile TEXT,parameters_json TEXT);
                CREATE TABLE network_job_runs(id INTEGER PRIMARY KEY,plan_id INTEGER,status TEXT,result_json TEXT);
                CREATE TABLE network_observations(id INTEGER PRIMARY KEY,run_id INTEGER,task_id INTEGER,
                    target TEXT,kind TEXT,data_json TEXT,observed_at TEXT);
                INSERT INTO network_phase_plans VALUES(1,11,'10.0.0.1','service_versions','{}');
                INSERT INTO network_job_runs VALUES(1,1,'completed','{}');
                INSERT INTO network_observations VALUES(1,1,11,'10.0.0.1','service_probe',
                    '{"port":80,"state":"open","service_hint":"HTTP","identification_uncertain":true}','2026-11-01');
            ''')
            state=c.snapshot(db,11,2)
            choice=decision('vuln',references=['observation:1','objective:goal'])
            assignment=c.resolve_assignment(db,choice,state)
            self.assertEqual(assignment['data'][0]['value']['observation_untrusted']['port'],80)
            self.assertTrue(assignment['data'][0]['value']['observation_untrusted']['identification_uncertain'])
            self.assertEqual(assignment['data'][1]['value']['title'],'Confirm the operator objective')
            db.execute("UPDATE network_observations SET task_id=22 WHERE id=1")
            with self.assertRaisesRegex(ValueError,'unknown_reference'):c.resolve_assignment(db,choice,state)
            db.execute('UPDATE network_observations SET task_id=11 WHERE id=1')
            db.execute("UPDATE network_job_runs SET status='running' WHERE id=1")
            with self.assertRaisesRegex(ValueError,'unknown_reference'):c.resolve_assignment(db,choice,state)

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

    def test_completed_goal_uses_capture_proof_without_operator_verify_round(self):
        from orchestrator import http_artifacts
        with self.connect() as db:objectives.save_objectives(db,11,'Primary flag',exclusive=True)
        def role(*args,**kwargs):
            with self.connect() as db:
                aid=http_artifacts.save(db,11,'10.0.0.1','http','10.0.0.1',80,'/flag.txt',
                    {'body':b'FLAG{offline_proof}','status':200,'complete':True,
                     'headers':{'content-type':'text/plain'},'metadata':{}},c.now())
            self.report_extra={'flags':[{'value':'FLAG{offline_proof}','objective_key':'goal',
                                        'goal_evidence':f'http_artifact:{aid}'}]}
            self.role(*args,**kwargs)
        with patch.object(http_artifacts,'ROOT',self.root/'http'):
            result=c.run(11,api_key='fake-only',model=self.model([decision('recon','Read target capture?')]),role_runner=role)
        self.assertEqual(result['stop_reason'],'goal_confirmed')
        self.assertEqual(result['status'],'completed')
        self.assertTrue(result['succeeded'])
        with self.connect() as db:self.assertEqual(objectives.objective_status(db,11)['primary']['status'],'confirmed')
        with patch.object(http_artifacts,'ROOT',self.root/'http'):
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

    def test_cli_explains_incomplete_report_pause(self):
        with patch.object(sys,'argv',['pm','attack','11','--coordinated']):_,args=pm.parser_main()
        output={'status':'waiting_operator','succeeded':False,
                'stop_reason':'role_report_incomplete_requires_review','steps':[]}
        with patch.object(pm,'connect',self.connect),patch.object(c,'run',return_value=output):
            pm.op_attack(args)
        self.assertIn('Отчёт неполон',self.console.getvalue())
        self.assertIn('проверки оператором',self.console.getvalue())

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


def demo(repeat=False):
    case=CoordinatorTests();case.setUp()
    try:
        with d.run('offline coordinated demo',11):
            if repeat:
                result=c.run(11,api_key='fake-only',
                             model=case.model([decision('vuln','Check the same port?')]*3),
                             role_runner=case.identical_role,max_steps=3)
            else:
                result=case.run_mode([decision('vuln','What is served on port 80?',references=['service:10.0.0.1:tcp:80']),
                                      decision('verify','Verify the saved response?',references=['result:'+'0'*23+'1']),decision()])
        output=case.console.getvalue()
    finally:case.doCleanups()
    for line in output.splitlines():
        if any(kind in line for kind in ('coordinator.decision','coordinator.state_changed','model.retry','run.stop')):
            print(line)
    print('Selected roles:', [call[0] for call in case.calls], 'goal confirmed:',result['succeeded'])


if __name__=='__main__':
    if sys.argv[1:]==['--demo']:demo()
    elif sys.argv[1:]==['--demo-repeat']:demo(repeat=True)
    else:unittest.main()
