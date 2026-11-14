"""Offline autonomy, branch questions and legacy pause migration."""
import json
import importlib.util
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import Mock, patch
from tests import test_coordinated_attack as fixture
from tests import test_coordinator_checkpoints as captures
from orchestrator import coordinated_attack as c, task_runtime, task_memory, objectives


def branch_decision(role=None, question='Inspect saved evidence', branch='task', kind=None):
    value=fixture.decision(role,question,action='wait_operator' if kind else None)
    value['branch_id']=branch
    if branch!='task':value['boundaries']['resource_refs']=[branch]
    if kind:value['operator_question']={'kind':kind}
    return value


class AutonomousWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)

    def test_access_chain_needs_no_approval(self):
        result=self.case.run_mode([fixture.decision('access','Use the saved credential candidate'),
            fixture.decision('access','Inspect the resulting access boundary'),fixture.decision()])
        self.assertEqual([call[0] for call in self.case.calls],['access','access'])
        self.assertEqual(result['stop_reason'],'model_stopped_incomplete')
        self.assertTrue(all(row['approved_at'] is None for row in self.case.rows()))

    def test_classifier_is_not_an_execution_gate(self):
        with patch.object(c.checkpoints,'collect',side_effect=AssertionError('classifier must not gate')):
            result=self.case.run_mode([fixture.decision('vuln','Interpret unusual protocol response'),fixture.decision()])
        self.assertEqual(result['stop_reason'],'model_stopped_incomplete')

    def test_legacy_access_wait_is_cancelled_before_replanning(self):
        with self.case.connect() as db:
            c.ensure_schema(db);state=c.snapshot(db,11,2)
            run=db.execute("INSERT INTO pm_coordinator_runs(task_id,target,status,stop_reason,created_at,updated_at) "
                "VALUES(11,'10.0.0.1','waiting_operator','role_approval_required',?,?)",(c.now(),c.now())).lastrowid
            sid=c.insert_step(db,run,11,fixture.decision('access','Old request'),state,
                {'poc_budget':7,'step_limit':15,'max_tokens':24000},'waiting_operator','role_approval_required')
        with self.case.connect() as db:self.assertIsNone(task_runtime.pause(db,11))
        result=self.case.run_mode([fixture.decision()])
        old=next(s for s in result['steps'] if s['id']==sid)
        self.assertEqual(old['status'],'failed')
        self.assertEqual(old['execution_outcome']['status'],'not_started')
        self.assertIsNone(old['approved_at']);self.assertEqual(self.case.calls,[])

    def test_question_blocks_only_its_resource_and_survives_restart(self):
        blocked='service:10.0.0.1:tcp:22';independent='service:10.0.0.1:tcp:80'
        model=self.case.model([
            branch_decision(question='Need documentation for SSH',branch=blocked,kind='tool'),
            branch_decision('vuln','Interpret HTTP response',independent),fixture.decision()])
        result=c.run(11,api_key='fake-only',model=model,role_runner=self.case.role)
        self.assertEqual([call[0] for call in self.case.calls],['vuln'])
        self.assertEqual(result['status'],'waiting_operator')
        question=result['operator_questions'][0]
        self.assertEqual(question['branch_id'],blocked);self.assertEqual(question['kind'],'tool')
        no_model=Mock(side_effect=AssertionError('idle question must not poll model'))
        again=c.run(11,model=no_model,role_runner=self.case.role)
        no_model.assert_not_called();self.assertEqual(again['operator_questions'][0]['id'],question['id'])
        from orchestrator import operator_questions
        with self.case.connect() as db:
            operator_questions.answer(db,11,question['id'],'information','Documentation supplied locally')
            self.assertIn('operator_question:'+str(question['id']),task_memory.source_state(
                db,11,self.case.root/'caps/task_11.jsonl')['questions'])
        result=self.case.run_mode([fixture.decision('access','Use supplied SSH documentation'),fixture.decision()])
        self.assertEqual([call[0] for call in self.case.calls],['vuln','access'])
        self.assertEqual(result['operator_questions'][0]['status'],'answered')
        self.assertEqual([call[2] for call in self.case.calls],[1,2])

    def test_pending_question_cannot_be_bypassed_by_global_scope(self):
        model=self.case.model([branch_decision(question='Need a tool',kind='tool'),fixture.decision('access')])
        result=c.run(11,api_key='fake-only',model=model,role_runner=self.case.role)
        self.assertEqual(len(self.case.prompts),1)
        self.assertEqual(result['status'],'waiting_operator');self.assertEqual(self.case.calls,[])

    def test_git_secret_and_unclassified_answer_continue(self):
        evidence=captures.CheckpointTests();evidence.setUp();self.addCleanup(evidence.doCleanups)
        result,model=evidence.run_mode([fixture.decision('recon','source capture'),
            fixture.decision('vuln','secret capture'),fixture.decision('verify','interpret unusual links'),fixture.decision()])
        self.assertEqual(result['stop_reason'],'model_stopped_incomplete')
        self.assertEqual(model.call_count,4)
        self.assertEqual([call[0] for call in evidence.case.calls],['recon','vuln','verify'])

    def test_all_question_kinds_keep_answers_without_granting_permissions(self):
        from orchestrator import operator_questions as questions
        with self.case.connect() as db:
            c.ensure_schema(db)
            original=db.execute('SELECT * FROM pm_operator_approvals').fetchall()
            for kind in sorted(questions.KINDS):
                request=branch_decision(question='Need operator input: '+kind,kind=kind)
                if kind=='flag_confirmation':
                    from orchestrator import flag_review
                    proposal=flag_review.propose(db,11,'THM{task_linked_candidate}',source='saved test result')
                    request['references']=['flag_proposal:'+str(proposal['id'])]
                question=questions.request(db,11,'10.0.0.1',request,None)
                self.assertEqual(questions.request(db,11,'10.0.0.1',request,None)['id'],question['id'])
                questions.answer(db,11,question['id'],'approve' if kind=='flag_confirmation' else 'information','Requested input supplied')
                with self.assertRaises(ValueError):questions.answer(db,11,question['id'],'decline')
            self.assertEqual(len(questions.listing(db,11)),4)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pm_operator_question_events').fetchone()[0],8)
            self.assertEqual(db.execute('SELECT * FROM pm_operator_approvals').fetchall(),original)
            self.assertFalse(c.snapshot(db,11,2)['success_verified'])
            db.execute("UPDATE tasks SET target='10.0.0.2' WHERE id=11")
            self.assertEqual(questions.listing(db,11),[])

    def test_question_event_failure_rolls_back_request_and_answer(self):
        from orchestrator import operator_questions as questions
        with self.case.connect() as db:
            c.ensure_schema(db)
            question=questions.request(db,11,'10.0.0.1',branch_decision(question='Need a tool',kind='tool'),None)
            db.execute("CREATE TRIGGER no_events BEFORE INSERT ON pm_operator_question_events BEGIN SELECT RAISE(ABORT,'offline'); END")
            with self.assertRaises(sqlite3.IntegrityError):questions.answer(db,11,question['id'],'approve')
            self.assertEqual(questions.listing(db,11)[0]['status'],'pending')
            with self.assertRaises(sqlite3.IntegrityError):questions.request(db,11,'10.0.0.1',branch_decision(question='Need budget',kind='budget'),None)
            self.assertEqual(len(questions.listing(db,11)),1)

    def test_unknown_legacy_access_outcome_is_not_replayed(self):
        with self.case.connect() as db:
            c.ensure_schema(db);state=c.snapshot(db,11,2)
            run=db.execute("INSERT INTO pm_coordinator_runs(task_id,target,status,stop_reason,created_at,updated_at) "
                "VALUES(11,'10.0.0.1','waiting_operator','role_approval_required',?,?)",(c.now(),c.now())).lastrowid
            sid=c.insert_step(db,run,11,fixture.decision('access','Possibly dispatched'),state,
                {'poc_budget':7,'step_limit':15,'max_tokens':24000},'waiting_operator','role_approval_required')
            db.execute('UPDATE pm_coordinator_steps SET outcome_uncertain=1 WHERE id=?',(sid,))
        model=Mock(side_effect=AssertionError('Unknown dispatch must not repeat'))
        result=c.run(11,model=model,role_runner=self.case.role)
        self.assertEqual(result['stop_reason'],'interrupted_running_step');model.assert_not_called()
        self.assertEqual(self.case.calls,[]);self.assertTrue(result['steps'][0]['outcome_uncertain'])

    def test_unusual_response_is_interpreted_by_real_role_path(self):
        from tests.test_report_integrity import ReportIntegrityTests
        from orchestrator import agent_actions
        runtime=ReportIntegrityTests();runtime.setUp();self.addCleanup(runtime.doCleanups)
        runtime.operation={'status':'completed','exit_code':0,'stdout':'ODD/0.7 response 299; meaning unresolved'}
        runtime.initial_text=json.dumps({'summary':'Unusual protocol response retained for interpretation.',
            'findings':[],'hypotheses':[{'claim':'Protocol meaning unresolved','kind':'hypothesis','result':'untested',
                'probe_result_id':'a'*24,'quote':runtime.operation['stdout']}],
            'flags':[],'verified':[],'uncertainties':['Need interpretation, no access claimed'],'proposed_actions':[]})
        model=Mock(side_effect=[fixture.decision('access','Interpret the authorized protocol response'),fixture.decision()])
        result=c.run(11,api_key='fake-only',model=model)
        self.assertEqual(result['stop_reason'],'model_stopped_incomplete');self.assertEqual(model.call_count,2)
        self.assertEqual(runtime.executions,1);self.assertEqual(result['steps'][0]['status'],'completed')
        with runtime.case.connect() as db:
            original=task_memory.material(db,11,'result:'+'a'*24,agent_actions.CAPABILITY_LOG/'task_11.jsonl')
            self.assertIn(b'ODD/0.7',original)
            self.assertEqual(agent_actions.fact_state.access_state(db,11)['level'],'none')

    def test_candidate_acceptance_and_access_are_separate(self):
        from orchestrator import fact_state
        with self.case.connect() as db:
            fact_state.record_asset(db,11,'credential','candidate-source','discovered')
            records={'auth':{'status':'completed','text':'Authenticated successfully; command channel unavailable',
                             'capture_record':{'provenance':'network','result':{'status':'completed'}}}}
            report=fact_state.validate_access_report({'access_level':'user','access_signal':'credential',
                'access_probe_result_id':'auth','access_quote':records['auth']['text']},records)
            fact_state.save_access_report(db,11,report)
            state=task_memory.source_state(db,11,self.case.root/'caps/task_11.jsonl')
            self.assertEqual({r['trust'] for r in state['credentials'].values()},{'candidate','server_accepted'})
            self.assertEqual(fact_state.access_state(db,11)['level'],'none')
            self.assertFalse(fact_state.access_state(db,11)['pending'])
            self.assertEqual(report['access_level'],'none')
            readback=fact_state.validate_access_report(dict(report),records,prior_ids=('auth',))
            fact_state.save_access_report(db,11,readback)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pm_credential_acceptance').fetchone()[0],1)
            fact_state.save_access_report(db,11,{'access_level':'user','access_signal':'shell','access_probe_result_id':'shell-proof'})
            self.assertEqual(fact_state.access_state(db,11)['level'],'user')
            self.assertEqual(len(task_memory.source_state(db,11,self.case.root/'caps/task_11.jsonl')['credentials']),2)

    def test_unverified_credential_acceptance_is_planning_data_not_a_pause(self):
        from orchestrator import fact_state, report_integrity
        assertions={'summary':'No access obtained.','access_signal':'credential','access_level':'user',
                    'access_probe_result_id':'local','access_quote':'accepted'}
        records={'local':{'status':'completed','text':'accepted','capture_record':{'provenance':'local'}}}
        report=fact_state.validate_access_report(dict(assertions),records)
        report=report_integrity.check_consistency(report,assertions)
        self.assertEqual(report['credential_assessment']['status'],'unverified')
        self.assertEqual(report['access_signal'],'none');self.assertFalse(report.get('report_incomplete'))
        self.assertEqual(report_integrity.quality(report)['status'],'valid')
        self.case.report_extra=report
        result=self.case.run_mode([fixture.decision('access','Interpret authentication data'),fixture.decision()])
        self.assertEqual(result['stop_reason'],'model_stopped_incomplete')
        with self.case.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pm_credential_acceptance').fetchone()[0],0)
            self.assertTrue(any(key.startswith('credential_assessment:') for key in task_memory.source_state(
                db,11,self.case.root/'caps/task_11.jsonl')['questions']))

    def test_flag_confirmation_answer_uses_existing_operator_path_atomically(self):
        from orchestrator import flag_verify, operator_questions
        from orchestrator import agent_actions
        agent_actions.CAPABILITY_LOG.mkdir(exist_ok=True)
        with self.case.connect() as db:objectives.save_objectives(db,11,'Capture a flag',expected_flags=1)
        value='THM{operator_review_candidate}'
        (agent_actions.CAPABILITY_LOG/'task_11.jsonl').write_text(json.dumps({'id':'b'*24,'task_id':11,
            'tool':'poc_run','provenance':'unknown','result':{'status':'completed','exit_code':0,'stdout':value}})+'\n')
        with self.case.connect() as db:
            registry=flag_verify.scan(11,db=db)
            self.assertEqual(registry['confirmed'],[])
        choice=branch_decision(question='Confirm the recorded flag candidate',kind='flag_confirmation')
        choice['references']=['flag:'+c.digest(value)];choice['inputs']=[{'reference':choice['references'][0]}]
        result=c.run(11,expect_flags=1,model=Mock(side_effect=AssertionError('Question is queued without model')))
        qid=result['operator_questions'][0]['id']
        with self.case.connect() as db:
            operator_questions.answer(db,11,qid,'approve','Operator checked the room response',
                capability_log=agent_actions.CAPABILITY_LOG/'task_11.jsonl')
            item=db.execute('SELECT status,operator_confirmed,sources_json FROM pm_verified_flags WHERE task_id=11').fetchone()
            self.assertEqual(item[:2],('confirmed',1))
            self.assertFalse(json.loads(item[2]).get('verified_evidence'))
        model=Mock(side_effect=AssertionError('Goal already confirmed; no extra model'))
        result=c.run(11,expect_flags=1,model=model)
        self.assertTrue(result['succeeded']);model.assert_not_called()

    def test_question_console_and_paused_resume_need_no_api_or_executor(self):
        import pm
        import sys
        self.case.run_mode([branch_decision(question='Need documentation',kind='tool')])
        with self.case.connect() as db:task_runtime.save_mode(db,11,'coordinated')
        def args(*values):
            with patch.object(sys,'argv',['pm',*values]):return pm.parser_main()[1]
        with patch.object(pm,'connect',self.case.connect),\
             patch.object(pm,'session_api_key',side_effect=AssertionError('No key')) ,\
             patch.object(pm,'sudo_checked',side_effect=AssertionError('No privileged executor')),\
             patch.object(c,'choose_with_model',side_effect=AssertionError('No model')):
            result=pm.op_resume(args('resume','11'))
            self.assertEqual(result['stop_reason'],'operator_questions_pending')
            self.assertEqual(pm.op_attack(args('attack','11'))['stop_reason'],'operator_questions_pending')
            with patch('builtins.input',side_effect=['9','11','','0']):pm.interactive()
            rows=pm.op_questions(args('questions','11','--answer','1','--decision','information'))
        self.assertEqual(rows[0]['status'],'answered');self.assertEqual(self.case.calls,[])

    def test_legacy_harness_access_events_are_descriptive_not_approval_gates(self):
        from orchestrator import scheduler_harness as legacy
        with self.case.connect() as db:
            legacy.init_runtime(db)
            for index,status in enumerate(('pending','denied')):
                event='legacy-event-'+str(index)
                db.execute('INSERT INTO checkpoint_events VALUES(?,11,?,?,?,?,?,NULL)',
                    (event,'approval','privilege_escalation','Historical ACCESS label',status,c.now()))
                db.execute('INSERT INTO agent_event_receipts VALUES(11,?,?,?,?)',(index,'hash'+str(index),event,c.now()))
            db.commit()
            self.assertTrue(legacy.handle_open_approvals(db,11))
            self.assertEqual(db.execute('SELECT status FROM checkpoint_events ORDER BY id').fetchall(),[('pending',),('denied',)])


class PasswordRuleTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        from orchestrator import agent_actions
        spec=importlib.util.spec_from_file_location('autonomy_mcp',Path(__file__).resolve().parents[1]/'mcp/server.py')
        self.server=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.server)
        for item in (patch.object(self.server,'ASSET_DB',self.case.database),
                     patch.object(self.server,'CAPABILITY_LOG',agent_actions.CAPABILITY_LOG),
                     patch.object(self.server,'POC_ROOT',self.case.root/'pocs'),patch.object(self.server,'ROOT',self.case.root)):
            item.start();self.addCleanup(item.stop)

    def test_supported_password_changes_are_rejected_before_executor(self):
        commands=[['/usr/bin/passwd','user'],['/usr/sbin/chpasswd'],['/usr/sbin/usermod','--password=hash','user'],
                  ['/usr/sbin/usermod','-phash','user'],['/usr/bin/ssh','user@10.0.0.1','passwd user'],
                  ['/bin/sh','-c','printf x | chpasswd'],['/usr/bin/net','rpc','password','user','value']]
        with patch.object(self.server.subprocess,'run',side_effect=AssertionError('No privileged executor')):
            for argv in commands:
                with self.subTest(argv=argv):
                    result=json.loads(self.server.pm_net_exec(11,'10.0.0.1',json.dumps(argv)))
                    self.assertEqual(result['status'],'blocked');self.assertIn('password changes',result['stderr'])
            self.assertEqual(json.loads(self.server.pm_session(11,'send',session_id='abcd1234',data='passwd user\n'))['status'],'blocked')
            self.assertEqual(json.loads(self.server.pm_session(11,'open',argv_json=json.dumps(['/usr/bin/passwd'])))['status'],'blocked')
            self.server.pm_write_poc(11,'change.sh','#!/bin/sh\npasswd user\n')
            self.assertEqual(json.loads(self.server.pm_poc_run(11,'10.0.0.1','change.sh'))['status'],'blocked')

    def test_broker_guard_and_wrapper_share_policy_without_claiming_shell_completeness(self):
        from executor import netguard_root as broker
        with self.assertRaises(ValueError):broker.safe_exec_argv(['/usr/bin/passwd'])
        with patch.object(broker,'ensure_root',side_effect=AssertionError('No root')):
            with self.assertRaises(ValueError):broker.session_send(11,'abcd1234','chpasswd',0)
        self.assertEqual(broker.safe_exec_argv(['/bin/cat','/etc/passwd']),['/bin/cat','/etc/passwd'])
        broker.reject_password_change(text='print("opaque program is not proven safe")')


if __name__=='__main__':unittest.main()
