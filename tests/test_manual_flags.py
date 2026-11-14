"""Manual CTF submissions: real temporary persistence, no target/API calls."""
import json
import importlib.util
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch
from tests import test_coordinated_attack as fixture
from orchestrator import agent_actions as a, coordinated_attack as c, objectives, flag_verify, operator_questions
from orchestrator import flag_review, task_memory, task_runtime


class ManualFlagTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        with self.case.connect() as db:
            objectives.save_objectives(db,11,'user.txt',specs=['root.txt'],expected_flags=2)

    def save(self,value='unusual candidate\nwith all bytes\n',key='goal',iteration=1,path='/home/user/user.txt'):
        report={'summary':'A task-linked candidate; platform acceptance is unknown.',
            'findings':[],'flags':[{'value':value,'source':path,'method':'SSH cat of task file',
                'objective_key':key,'goal_evidence':'saved-result-no-capture'}]}
        with self.case.connect() as db:a.save_report(db,{'task_id':11,'target':'10.0.0.1'},'access',iteration,report,1)
        return report

    def test_unknown_format_is_queued_without_capture_or_model(self):
        value='unusual candidate\nwith all bytes\n';self.save(value)
        self.save('another unknown root value',key='obj-1',iteration=2,path='/root/root.txt')
        model=Mock(side_effect=AssertionError('Waiting for platform answer must not invoke model'))
        result=c.run(11,expect_flags=2,model=model)
        self.assertEqual(result['stop_reason'],'operator_questions_pending');model.assert_not_called()
        question=result['operator_questions'][0]
        self.assertEqual(question['flag_candidate']['value'],value)
        self.assertEqual(question['flag_candidate']['objective_key'],'goal')
        self.assertIn('CTF',question['question'])

    def test_yes_confirms_only_its_goal_even_without_capture(self):
        value='THM{one_platform_submission}';self.save(value)
        with self.case.connect() as db:
            flag_verify.scan(11,db=db)
            c.ensure_schema(db)
            state=c.snapshot(db,11,2)
            decision=fixture.decision(action='wait_operator',references=['flag:'+c.digest(value)])
            decision['operator_question']={'kind':'flag_confirmation'}
            question=operator_questions.request(db,11,'10.0.0.1',decision,None)
            operator_questions.answer(db,11,question['id'],'approve','Accepted on the CTF platform')
            states=objectives.objective_status(db,11)
            self.assertEqual([(g['key'],g['status']) for g in states['objectives']],
                             [('goal','confirmed'),('obj-1','open')])
            self.assertEqual(states['expected_flags'],2)

    def one_goal(self):
        with self.case.connect() as db:objectives.save_objectives(db,11,'user.txt',expected_flags=1)

    def question(self,db,key='goal'):
        return next(q for q in operator_questions.listing(db,11,pending=True)
                    if q.get('flag_candidate',{}).get('objective_key')==key)

    def test_rejected_value_is_not_reoffered_for_new_ids_or_readback(self):
        self.one_goal();value='unknown exact platform value';self.save(value)
        with self.case.connect() as db:
            first=self.question(db);operator_questions.answer(db,11,first['id'],'decline','Platform rejected it')
            self.assertEqual(flag_review.listing(db,11)[0]['status'],'rejected')
            self.assertEqual(objectives.objective_status(db,11)['primary']['status'],'open')
        self.save(value,iteration=2)
        with self.case.connect() as db:
            flag_verify.scan(11,db=db);flag_review.reconcile(db,11,a.CAPABILITY_LOG/'task_11.jsonl')
            self.assertEqual(operator_questions.listing(db,11,pending=True),[])
            self.assertEqual(len(operator_questions.listing(db,11)),1)
            self.assertEqual(db.execute('SELECT status FROM pm_verified_flags WHERE value=?',(value,)).fetchone()[0],'rejected')
        result=self.case.run_mode([fixture.decision('vuln','Find a different candidate'),fixture.decision()])
        self.assertEqual([call[0] for call in self.case.calls],['vuln'])
        self.assertFalse(result['succeeded'])

    def test_explicit_reconsideration_preserves_no_then_accepts_without_new_material(self):
        self.one_goal();value='no special FLAG format';self.save(value)
        with self.case.connect() as db:
            old=self.question(db);pid=old['flag_candidate']['id']
            operator_questions.answer(db,11,old['id'],'decline','Incorrect platform input')
            with self.assertRaises(ValueError):flag_review.reconsider(db,11,pid,'')
            new=flag_review.reconsider(db,11,pid,'Operator corrected a platform submission mistake')
            self.assertNotEqual(old['id'],new['id'])
            operator_questions.answer(db,11,new['id'],'approve','Accepted on the platform')
            history=operator_questions.listing(db,11)
            self.assertEqual([q['answer']['decision'] for q in history],['decline','approve'])
            self.assertEqual([q['status'] for q in history],['answered','answered'])
            self.assertEqual(flag_review.listing(db,11)[0]['value'],value)
            self.assertEqual(flag_review.completion(db,11),'objectives_done')
            self.assertEqual([r[0] for r in db.execute('SELECT event FROM pm_flag_proposal_events ORDER BY id')],
                             ['proposed','rejected','operator_reconsidered','accepted'])

    def test_offline_answers_and_resume_complete_without_preflight_or_model(self):
        import pm
        self.save('user-value-with-unknown-format')
        self.save('root-value-with-unknown-format',key='obj-1',iteration=2,path='/root/root.txt')
        with self.case.connect() as db:task_runtime.save_mode(db,11,'coordinated')
        def args(*values):
            with patch.object(sys,'argv',['pm',*values]):return pm.parser_main()[1]
        with patch.object(pm,'connect',self.case.connect),\
             patch.object(pm,'configure',side_effect=AssertionError('No namespace or scope repair')),\
             patch.object(pm,'preflight_target',side_effect=AssertionError('Machine is off')),\
             patch.object(pm,'session_api_key',side_effect=AssertionError('No API key')),\
             patch.object(pm,'sudo_checked',side_effect=AssertionError('No privileged executor')),\
             patch.object(c,'choose_with_model',side_effect=AssertionError('No model')):
            with self.case.connect() as db:
                db.execute("UPDATE pm_operator_approvals SET closed_at='machine-off'")
                questions=operator_questions.listing(db,11,pending=True)
            for question in questions:pm.op_questions(args('questions','11','--answer',str(question['id']),'--decision','approve'))
            result=pm.op_resume(args('resume','11'))
        self.assertTrue(result['succeeded']);self.assertEqual(result['expected_flags'],2)
        self.assertIn('CTF',self.case.console.getvalue());self.assertIn('user-value-with-unknown-format',self.case.console.getvalue())
        with self.case.connect() as db:
            self.assertEqual(db.execute('SELECT closed_at FROM pm_operator_approvals').fetchone()[0],'machine-off')
            self.assertEqual(len(objectives.objective_status(db,11)['confirmed']),2)

    def test_complete_goals_stop_coordinator_before_another_model_decision(self):
        self.save('user literal');self.save('root literal',key='obj-1',iteration=2,path='/root/root.txt')
        with self.case.connect() as db:
            for question in operator_questions.listing(db,11,pending=True):operator_questions.answer(db,11,question['id'],'approve','CTF accepted')
        model=Mock(side_effect=AssertionError('All goals are done'))
        result=c.run(11,expect_flags=2,model=model)
        self.assertTrue(result['succeeded']);self.assertEqual(result['stop_reason'],'objectives_done');model.assert_not_called()

    def test_restart_during_wait_is_readonly_and_does_not_poll_model(self):
        self.one_goal();self.save('unknown whole-file value\n')
        first=c.run(11,expect_flags=1,model=Mock(side_effect=AssertionError('No polling')))
        script=('import json,sqlite3,sys; from orchestrator.task_runtime import pause; '
                'db=sqlite3.connect("file:"+sys.argv[1]+"?mode=ro",uri=True); '
                'print(json.dumps(pause(db,11))); db.close()')
        env={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1])}
        saved=subprocess.run([sys.executable,'-c',script,str(self.case.database)],env=env,capture_output=True,text=True,check=True,timeout=10)
        paused=json.loads(saved.stdout)
        self.assertEqual(paused['operator_questions'][0]['id'],first['operator_questions'][0]['id'])
        self.assertEqual(paused['operator_questions'][0]['flag_candidate']['value'],'unknown whole-file value\n')
        again=c.run(11,expect_flags=1,model=Mock(side_effect=AssertionError('Still no polling')))
        self.assertEqual(again['status'],'waiting_operator')

    def test_pending_user_flag_allows_independent_root_work(self):
        self.save('user pending value')
        def role(*args,**kwargs):
            self.case.report_extra={'flags':[{'value':'root pending value','objective_key':'obj-1',
                'source':'/root/root.txt','method':'saved shell output'}]}
            return self.case.role(*args,**kwargs)
        model=self.case.model([fixture.decision('access','Find root.txt without repeating user.txt')])
        result=c.run(11,expect_flags=2,api_key='fake-only',model=model,role_runner=role)
        self.assertEqual(len(self.case.prompts),1);self.assertEqual([call[0] for call in self.case.calls],['access'])
        self.assertEqual(len([q for q in result['operator_questions'] if q['status']=='pending']),2)
        self.assertFalse(result['succeeded'])

    def test_known_capture_is_technical_material_not_automatic_goal_confirmation(self):
        from tests.test_flag_evidence import FlagEvidenceTests
        evidence=FlagEvidenceTests();evidence.setUp();self.addCleanup(evidence.doCleanups)
        with evidence.case.connect() as db:objectives.save_objectives(db,11,'Capture the flag',expected_flags=1)
        artifact=evidence.capture();evidence.record(tool='http_capture',result={'status':'completed','exit_code':0,'artifact_id':artifact})
        with evidence.case.connect() as db:
            registry=flag_verify.scan(11,db=db)
            self.assertEqual(registry['confirmed'],[])
            self.assertTrue(registry['candidates'][0]['verified_evidence'])
        result=c.run(11,expect_flags=1,model=Mock(side_effect=AssertionError('Ask operator, not VERIFY')))
        with evidence.case.connect() as db:
            q=operator_questions.listing(db,11,pending=True)[0]
            operator_questions.answer(db,11,q['id'],'approve','Accepted by the CTF platform')
        self.assertEqual(result['status'],'waiting_operator')
        self.assertTrue(c.run(11,expect_flags=1,model=Mock(side_effect=AssertionError('No model')))['succeeded'])

    def test_passwords_and_tokens_without_task_link_are_not_proposals(self):
        self.one_goal()
        a.CAPABILITY_LOG.mkdir(exist_ok=True)
        (a.CAPABILITY_LOG/'task_11.jsonl').write_text(json.dumps({'id':'a'*24,'task_id':11,'tool':'net_exec',
            'provenance':'network','result':{'status':'completed','exit_code':0,'stdout':'password=secret\ntoken=opaque_token_0123456789abcdef'}})+'\n')
        with self.case.connect() as db:
            flag_verify.scan(11,db=db);flag_review.reconcile(db,11,a.CAPABILITY_LOG/'task_11.jsonl')
            self.assertEqual(flag_review.listing(db,11),[])
            self.assertEqual(operator_questions.listing(db,11,pending=True),[])

    def test_saved_single_file_cat_can_propose_full_unknown_contents(self):
        spec=importlib.util.spec_from_file_location('manual_flags_mcp',Path(__file__).resolve().parents[1]/'mcp/server.py')
        server=importlib.util.module_from_spec(spec);spec.loader.exec_module(server)
        value='entire root file\nsecond line\n'
        payload={'task_id':11,'target':'10.0.0.1','status':'completed','exit_code':0,'stdout':value}
        with patch.object(server,'ASSET_DB',self.case.database),patch.object(server,'CAPABILITY_LOG',a.CAPABILITY_LOG),\
             patch.object(server,'ROOT',self.case.root),patch.object(server.subprocess,'run',
                 return_value=subprocess.CompletedProcess([],0,json.dumps(payload),'')) as execute:
            result=json.loads(server.pm_net_exec(11,'10.0.0.1',json.dumps(['/bin/cat','/root/root.txt'])))
        self.assertEqual(execute.call_count,1)
        with self.case.connect() as db:
            flag_review.reconcile(db,11,a.CAPABILITY_LOG/'task_11.jsonl')
            proposal=flag_review.listing(db,11)[0]
            self.assertEqual(proposal['value'],value);self.assertEqual(proposal['objective_key'],'obj-1')
            self.assertIn('result:'+result['result_id'],proposal['materials'])

    def test_expected_count_is_not_reduced_when_one_of_two_goals_is_accepted(self):
        self.save('user value')
        with self.case.connect() as db:
            q=self.question(db);operator_questions.answer(db,11,q['id'],'approve','CTF yes')
            self.assertIsNone(flag_review.completion(db,11,1))
            self.assertEqual(objectives.objective_status(db,11)['expected_flags'],2)
            self.assertEqual(flag_review.progress(db,11)['expected_flags'],2)

    def test_answer_failure_rolls_back_flag_goal_and_question(self):
        self.one_goal();self.save('unknown rollback candidate')
        with self.case.connect() as db:
            q=self.question(db)
            db.execute("CREATE TRIGGER deny_answer BEFORE UPDATE ON pm_operator_questions BEGIN SELECT RAISE(ABORT,'offline'); END")
            with self.assertRaises(sqlite3.IntegrityError):operator_questions.answer(db,11,q['id'],'approve','CTF yes')
            self.assertEqual(flag_review.listing(db,11)[0]['status'],'pending')
            self.assertEqual(operator_questions.listing(db,11)[0]['status'],'pending')
            self.assertEqual(objectives.objective_status(db,11)['primary']['status'],'open')
            self.assertEqual(db.execute('SELECT operator_confirmed FROM pm_verified_flags').fetchone()[0],0)

    def test_identical_values_for_two_goals_need_two_platform_answers(self):
        value='same exact bytes accepted in two separate submissions'
        self.save(value)
        with self.case.connect() as db:
            operator_questions.answer(db,11,self.question(db)['id'],'approve','User submission accepted')
        self.save(value,key='obj-1',iteration=2,path='/root/root.txt')
        with self.case.connect() as db:
            self.assertEqual(objectives.objective_status(db,11)['objectives'][1]['status'],'open')
            self.assertIsNone(flag_review.completion(db,11))
            operator_questions.answer(db,11,self.question(db,'obj-1')['id'],'approve','Root submission accepted')
            self.assertEqual(flag_review.progress(db,11)['accepted_count'],2)
            self.assertEqual(flag_review.completion(db,11),'objectives_done')
            self.assertEqual(objectives.objective_status(db,11)['expected_flags'],2)

    def test_legacy_operator_confirmation_keeps_its_original_provenance(self):
        self.one_goal()
        with self.case.connect() as db:
            flag_verify.operator_confirm(11,'THM{previous_operator_answer}','Previously accepted on platform',db=db)
            original=db.execute('SELECT value,status,operator_confirmed,sources_json FROM pm_verified_flags').fetchone()
            flag_review.activate(db,11,1);flag_verify.scan(11,db=db)
            preserved=flag_review.policy(db,11)['legacy_flags'][0]
            self.assertEqual((preserved['value'],preserved['status'],preserved['operator_confirmed'],preserved['sources_json']),original)
            self.assertEqual(flag_review.progress(db,11)['accepted_count'],1)
            self.assertEqual(db.execute('SELECT operator_confirmed FROM pm_verified_flags').fetchone()[0],1)

    def test_legacy_technical_confirmation_is_preserved_but_not_a_platform_answer(self):
        self.one_goal()
        with self.case.connect() as db:
            # Migration fixture representing the published capture-only policy.
            db.execute("INSERT INTO pm_verified_flags(task_id,value,status,evidence_count,reported_by,sources_json,created_at,updated_at,objective_key) "
                "VALUES(11,'THM{old_capture_only}','confirmed',1,'recon',?, 'original','original','goal')",
                (json.dumps({'verified_evidence':[{'capture_ref':'http_artifact:91'}],'evidence_source':'network'}),))
            db.execute("UPDATE pm_objectives SET status='confirmed',evidence_ref='http_artifact:91' WHERE task_id=11")
            original=db.execute('SELECT * FROM pm_objectives').fetchall()
            flag_review.activate(db,11,1);flag_review.reconcile(db,11)
            self.assertEqual(flag_review.progress(db,11)['accepted_count'],0)
            self.assertIsNone(flag_review.completion(db,11))
            self.assertEqual(objectives.objective_status(db,11)['primary']['status'],'awaiting_operator')
            self.assertEqual(db.execute('SELECT * FROM pm_objectives').fetchall(),original)
            self.assertEqual(db.execute('SELECT status FROM pm_verified_flags').fetchone()[0],'confirmed')
            q=self.question(db);operator_questions.answer(db,11,q['id'],'approve','CTF accepted, old capture unavailable')
            self.assertEqual(flag_review.completion(db,11),'objectives_done')

    def test_cli_explicit_reconsideration_works_offline(self):
        import pm
        self.one_goal();self.save('previously rejected exact value')
        with self.case.connect() as db:
            q=self.question(db);pid=q['flag_candidate']['id']
            operator_questions.answer(db,11,q['id'],'decline','Platform no')
        reason=self.case.root/'review-reason.txt';reason.write_text('Operator corrected the chosen platform objective')
        with patch.object(sys,'argv',['pm','questions','11','--reconsider',str(pid),'--note-file',str(reason)]):args=pm.parser_main()[1]
        with patch.object(pm,'connect',self.case.connect),patch.object(pm,'sudo_checked',side_effect=AssertionError('No network')):
            rows=pm.op_questions(args)
        self.assertEqual([q['status'] for q in rows],['answered','pending'])
        self.assertEqual(rows[0]['answer']['decision'],'decline')
        self.assertEqual(rows[1]['flag_candidate']['revision'],2)

    def test_previously_answered_platform_question_closes_its_saved_goal_without_resubmission(self):
        self.one_goal();value='THM{previous_platform_answer}'
        with self.case.connect() as db:
            c.ensure_schema(db)
            flag_verify.operator_confirm(11,value,'CTF accepted earlier',db=db)
            # Published-format history: answer existed but goal attribution did not.
            report={'summary':'Historical candidate','flags':[{'value':value,'objective_key':'goal','source':'old SSH stdout'}]}
            db.execute('INSERT INTO pm_agent_action_reports VALUES(11,?,?,?, ?,1,?)',
                       ('access',1,'10.0.0.1',json.dumps(report),c.now()))
            db.execute('INSERT INTO pm_operator_questions(task_id,target,kind,branch_id,question,reason,boundaries_json,references_json,'
                'fingerprint,status,answer_json,created_at,answered_at) VALUES(11,?,?,?,?,?,?,?,?,?,?,?,?)',
                ('10.0.0.1','flag_confirmation','task','Confirm saved candidate','Operator platform check',
                 json.dumps({'task_id':11,'target':'10.0.0.1','intent_ref':'intent','resource_refs':['scope:10.0.0.1']}),
                 json.dumps(['flag:'+c.digest(value)]),'published-question','answered',
                 json.dumps({'decision':'approve','text':'CTF platform accepted'}),c.now(),c.now()))
            original=db.execute('SELECT * FROM pm_operator_questions').fetchall()
        model=Mock(side_effect=AssertionError('Previous explicit answer is sufficient'))
        result=c.run(11,expect_flags=1,model=model)
        self.assertTrue(result['succeeded']);model.assert_not_called()
        with self.case.connect() as db:
            self.assertEqual(db.execute('SELECT * FROM pm_operator_questions').fetchall(),original)
            self.assertEqual(len(operator_questions.listing(db,11)),1)
            self.assertEqual(objectives.objective_status(db,11)['primary']['status'],'confirmed')

    def test_conflicting_question_options_are_rejected_before_database_access(self):
        import pm
        with patch.object(sys,'argv',['pm','questions','11','--answer','1','--reconsider','2','--decision','approve']):
            args=pm.parser_main()[1]
        with patch.object(pm,'connect',side_effect=AssertionError('No writes for invalid options')):
            with self.assertRaisesRegex(pm.OperatorError,'ответ.*пересмотр'):pm.op_questions(args)


if __name__=='__main__':unittest.main()
