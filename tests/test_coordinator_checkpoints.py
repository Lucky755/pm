"""Offline coordinated checkpoints: real evidence/SQLite, fake model and roles."""
from argparse import Namespace
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import Mock
import zlib

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
if __package__:
    from . import test_flag_evidence as fixtures
    from .test_coordinated_attack import decision
else:
    import test_flag_evidence as fixtures
    from test_coordinated_attack import decision
import pm
from orchestrator import agent_actions as a, coordinated_attack as c, objectives, task_runtime


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.evidence=fixtures.FlagEvidenceTests();self.evidence.setUp()
        self.addCleanup(self.evidence.doCleanups)
        self.case=self.evidence.case;self.case.emit_evidence=False
        self.number=0;self.source_body=b'# /internal.py\ndef internal_route():\n    return 7\n'

    def role(self,task,role,question,iteration,poc,steps,**kwargs):
        self.number+=1
        category='routine';flags=[]
        if 'source' in question:
            body=self.source_body
            raw=b'blob '+str(len(body)).encode()+b'\0'+body
            oid=hashlib.sha1(raw).hexdigest()
            path=f'/.git/objects/{oid[:2]}/{oid[2:]}'
            aid=self.evidence.capture(zlib.compress(raw),path)
            category='source_disclosure';quote='def internal_route():'
            title='Исходный код /internal.py из Git'
        elif 'secret' in question:
            body=b'DB_PASSWORD="private-secret-123"\n'
            path='/.env';aid=self.evidence.capture(body,path)
            category='secret_disclosure';quote=body.decode().strip();title='Database password'
        elif 'flag' in question:
            body=('flag: '+self.evidence.value+'\n').encode()
            path='/flag.txt';aid=self.evidence.capture(body,path)
            quote=self.evidence.value;title='Flag captured'
            flags=[{'value':self.evidence.value,'objective_key':'goal','goal_evidence':f'http_artifact:{aid}'}]
        else:
            path='/booking' if '404' in question else '/'
            body=b'404 Not Found /booking' if path=='/booking' else b'<a href="/booking">Booking</a> Server 1.2.3'
            aid=self.evidence.capture(body,path,status=404 if path=='/booking' else 200)
            quote='/booking';title='Observed /booking'
        rid=f'{self.number:024x}'
        self.evidence.record(id=rid,tool='http_capture',result={'task_id':11,'target':'10.0.0.1',
            'status':'completed','exit_code':0,'artifact_id':aid,'stdout':path+'\n'+body.decode(errors='replace')})
        report={'findings':[{'title':title,'claim':title,'kind':'observation','category':category,
            'artifact_ref':f'http_artifact:{aid}','result_id':rid,'probe':{'result_id':rid},'quote':quote,
            'confidence':'high','severity':'critical','impact':'Непустой подробный impact'}],
            'flags':flags,'probe':{'result_id':rid}}
        self.case.report_extra=a.validate_report_probes(report,task,role)
        self.case.role(task,role,question,iteration,poc,steps,**kwargs)

    def run_mode(self,replies,**kwargs):
        model=Mock(side_effect=replies)
        result=c.run(11,model=model,role_runner=self.role,expect_flags=1,**kwargs)
        return result,model

    def labels(self,step_id=1):
        with self.case.connect() as db:
            state=c.snapshot(db,11,1)
            return c.checkpoints.register(db,11,'10.0.0.1',step_id,c.checkpoints.collect(db,11,state,state))

    def test_routine_recon_vuln_verify_are_automatic_despite_high_confidence_and_impact(self):
        result,model=self.run_mode([decision('recon','links'),decision('vuln','404 response'),
                                   decision('verify','check links locally'),decision()])
        self.assertEqual([r[0] for r in self.case.calls],['recon','vuln','verify'])
        self.assertEqual(result['stop_reason'],'model_stopped_incomplete')
        self.assertEqual(model.call_count,4)
        self.assertFalse(result['succeeded'])

    def test_full_story_is_automatic_and_survives_restart(self):
        with self.case.connect() as db:
            objectives.save_objectives(db,11,'Capture the flag',exclusive=True,expected_flags=1)
        result,model=self.run_mode([decision('recon','links'),decision('vuln','404 response'),
            decision('verify','check links locally'),decision('recon','source capture')],max_steps=4)
        self.assertEqual(len(self.case.calls),4);self.assertEqual(result['stop_reason'],'coordinator_step_limit')
        original=(a.REPORT_DIR/'task_11/recon-04.json').read_bytes()
        with sqlite3.connect('file:'+str(self.case.database)+'?mode=ro',uri=True) as db:
            self.assertIsNone(task_runtime.pause(db,11))
        result,model=self.run_mode([decision('verify','repeat source capture with another result id'),decision('vuln','flag capture')])
        self.assertTrue(result['succeeded']);self.assertEqual(result['stop_reason'],'goal_confirmed')
        self.assertEqual(model.call_count,2);self.assertEqual([r[2] for r in self.case.calls],[1,2,3,4,5,6])
        self.assertEqual((a.REPORT_DIR/'task_11/recon-04.json').read_bytes(),original)
        with self.case.connect() as db:
            self.assertEqual(objectives.objective_status(db,11)['expected_flags'],1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pm_coordinator_checkpoints').fetchone()[0],0)
            verify=json.loads(db.execute('SELECT report_json FROM pm_agent_action_reports WHERE iteration=5').fetchone()[0])
            self.assertFalse(verify.get('report_incomplete'))

    def test_legacy_significant_pause_is_retired_without_rewriting_evidence(self):
        first,_=self.run_mode([decision('recon','source capture')],max_steps=1)
        with self.case.connect() as db:
            db.execute("UPDATE pm_coordinator_runs SET status='waiting_operator',stop_reason='significant_finding',pause_step_id=1")
            db.execute('DROP TABLE pm_coordinator_checkpoints')
        with sqlite3.connect('file:'+str(self.case.database)+'?mode=ro',uri=True) as db:self.assertIsNone(task_runtime.pause(db,11))
        log=(a.CAPABILITY_LOG/'task_11.jsonl').read_bytes()
        resumed,model=self.run_mode([decision()])
        self.assertEqual(resumed['stop_reason'],'model_stopped_incomplete');self.assertEqual(model.call_count,1)
        self.assertEqual((a.CAPABILITY_LOG/'task_11.jsonl').read_bytes(),log)
        with self.case.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pm_operator_policy_events').fetchone()[0],1)
            self.assertEqual(c.steps(db,11)[0]['status'],'completed')

    def test_review_does_not_promote_hypotheses_or_change_evidence(self):
        first,_=self.run_mode([decision('recon','source capture')],max_steps=1)
        with self.case.connect() as db:
            before=db.execute('SELECT * FROM pm_hypotheses ORDER BY claim_key').fetchall()
            flags=db.execute('SELECT * FROM pm_verified_flags ORDER BY value').fetchall()
            state=c.snapshot(db,11,1)
        log=a.CAPABILITY_LOG.joinpath('task_11.jsonl').read_bytes()
        result,_=self.run_mode([decision()],continue_run=True)
        with self.case.connect() as db:
            self.assertEqual(db.execute('SELECT * FROM pm_hypotheses ORDER BY claim_key').fetchall(),before)
            self.assertEqual(db.execute('SELECT * FROM pm_verified_flags ORDER BY value').fetchall(),flags)
            self.assertEqual(c.snapshot(db,11,1)['knowledge_sha256'],state['knowledge_sha256'])
        self.assertEqual(a.CAPABILITY_LOG.joinpath('task_11.jsonl').read_bytes(),log)

    def test_new_secret_can_have_a_descriptive_label_without_pause(self):
        self.run_mode([decision('recon','source capture')],max_steps=1)
        first=self.labels()
        self.source_body+=b'DB_PASSWORD="new-repository-secret-456"\n'
        second,_=self.run_mode([decision('vuln','new source bytes'),decision()])
        labels=self.labels()
        self.assertEqual(second['stop_reason'],'model_stopped_incomplete')
        self.assertGreater(len(labels),len(first))
        self.assertTrue(any(label['category']=='secret_disclosure' for label in labels))
        self.assertFalse(c.checkpoints.BLOCKING)

    def test_more_files_share_a_descriptive_disclosure_label(self):
        self.run_mode([decision('recon','source capture')],max_steps=1);self.labels()
        self.source_body+=b'def additional_internal_route(): return 9\n'
        second,_=self.run_mode([decision('vuln','more source bytes'),decision()])
        self.assertEqual(second['stop_reason'],'model_stopped_incomplete')
        self.assertEqual(len(self.labels()),1)
        with self.case.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM pm_coordinator_checkpoints').fetchone()[0],1)

    def test_secret_label_has_no_plaintext_secret_and_cannot_pause(self):
        result,_=self.run_mode([decision('recon','secret capture'),decision()])
        points=self.labels();self.assertEqual(points[0]['category'],'secret_disclosure')
        pm.render_coordinator_result(result,Namespace(json=False))
        self.assertNotIn('private-secret-123',json.dumps(points)+self.case.console.getvalue())
        self.assertEqual(result['stop_reason'],'model_stopped_incomplete')

    def test_unbacked_category_is_not_a_checkpoint(self):
        def unbacked(*args,**kwargs):
            self.case.report_extra={'findings':[{'title':'Claimed leak','kind':'observation',
                'category':'source_disclosure','artifact_ref':'http_artifact:999',
                'confidence':'high','impact':'critical','severity':'critical','quote':'invented'}]}
            self.case.role(*args,**kwargs)
        result=c.run(11,model=Mock(side_effect=[decision('vuln','Check the claim'),decision()]),
                     role_runner=unbacked,expect_flags=1)
        self.assertEqual(result['stop_reason'],'model_stopped_incomplete')

    def test_access_runs_without_step_approval(self):
        result,model=self.run_mode([decision('access','Check authorized access?'),decision()])
        self.assertEqual([r[0] for r in self.case.calls],['access'])
        self.assertIsNone(result['steps'][0]['approved_at'])
        self.assertEqual(result['stop_reason'],'model_stopped_incomplete')

    def test_disclosure_does_not_expand_scope_for_access(self):
        self.run_mode([decision('recon','source capture')],max_steps=1);self.labels()
        with self.case.connect() as db:db.execute('DELETE FROM pm_operator_approvals')
        result,model=self.run_mode([decision('access','Test access?')])
        self.assertEqual(result['stop_reason'],'scope_approval_required');model.assert_not_called()
        self.assertEqual([r[0] for r in self.case.calls],['recon'])

    def test_pending_classifier_label_cannot_block_after_restart(self):
        self.run_mode([decision('recon','source capture')],max_steps=1)
        first=self.labels()
        with self.case.connect() as db:db.execute("UPDATE pm_coordinator_runs SET status='running',pause_step_id=NULL")
        result,model=self.run_mode([decision()])
        self.assertEqual(result['stop_reason'],'model_stopped_incomplete');self.assertEqual(model.call_count,1)
        with self.case.connect() as db:
            saved=c.checkpoints.pending(db,11)
            self.assertEqual(saved[0]['id'],first[0]['id']);self.assertEqual(saved[0]['status'],'pending')

    def test_git_metadata_and_invalid_objects_are_routine_not_disclosed_source(self):
        self.evidence.capture(b'ref: refs/heads/main\n','/.git/HEAD')
        self.evidence.capture(b'[core]\nrepositoryformatversion = 0\n','/.git/config')
        self.evidence.capture(b'invalid compressed Git data','/.git/objects/aa/'+'b'*38)
        result,_=self.run_mode([decision('vuln','Inspect repository metadata'),decision()])
        self.assertEqual(result['stop_reason'],'model_stopped_incomplete')

    def test_triage_completion_alone_is_not_significant_access_change(self):
        before={'essential_state':{'access_state':{'level':'user','signal':'shell','triage_done':False,'pending':True}},
                'confirmed_flags':[],'objectives':{'confirmed':[]}}
        after={**before,'essential_state':{'access_state':{**before['essential_state']['access_state'],
                                                         'triage_done':True,'pending':False}}}
        self.assertIsNone(c.significant(before,after,{'findings':[]}))


if __name__=='__main__':unittest.main()
