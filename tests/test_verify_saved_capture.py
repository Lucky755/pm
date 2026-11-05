"""Real run_role validation/storage, fake model boundary, no executor or network."""
import hashlib
import json
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zlib

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
if __package__:
    from . import test_flag_evidence as fixtures
    from .test_coordinated_attack import decision
else:
    import test_flag_evidence as fixtures
    from test_coordinated_attack import decision
from orchestrator import agent_actions as a, coordinated_attack as c, flag_evidence, http_artifacts


class SavedCaptureVerifyTests(unittest.TestCase):
    def setUp(self):
        self.evidence=fixtures.FlagEvidenceTests();self.evidence.setUp()
        self.addCleanup(self.evidence.doCleanups)
        self.case=self.evidence.case
        self.rid='a'*24;self.body=b'Original /status.txt\nalpha=42\n'
        self.aid=self.evidence.capture(self.body,'/status.txt')
        self.set_record()
        self.report=self.audit_report()
        self.requests=[]
        owner=self

        class Harness:
            def __init__(self,**kwargs):pass
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def start_session(self,name):
                def run(prompt,**kwargs):
                    owner.requests.append(prompt)
                    if owner.on_model:
                        owner.on_model()
                    return SimpleNamespace(finish_reason='completed',events=[],
                                           final_response=json.dumps(owner.report))
                return SimpleNamespace(run=run)

        self.on_model=None
        for p in (
            patch.dict(sys.modules,{'deepseek_harness':SimpleNamespace(DeepSeekHarness=Harness)}),
            patch.object(a,'close_task_sessions'),  # privileged executor lifecycle boundary
            patch.object(socket.socket,'connect',side_effect=AssertionError('Network forbidden')),
            patch.object(a.subprocess,'run',side_effect=AssertionError('Executor forbidden')),
            patch.object(a,'DSH_HOME',self.case.root/'dsh'),
            patch.object(a,'WORKSPACE',self.case.root/'workspace'),
            patch.object(a,'POC_DIR',self.case.root/'pocs'),
        ):
            p.start();self.addCleanup(p.stop)

    def set_record(self,**overrides):
        payload={'status':'completed','exit_code':0,'task_id':11,'target':'10.0.0.1',
                 'artifact_id':self.aid,'stdout':'Capture metadata only; no body excerpt.'}
        self.evidence.record(id=self.rid,tool='http_capture',result=payload,**overrides)

    def audit_report(self,quote='alpha=42',path='/status.txt'):
        return {'summary':'Локально проверен сохранённый capture; нового запроса нет.',
                'findings':[{'title':path,'claim':path+' contains '+quote,'kind':'observation',
                             'artifact_ref':f'http_artifact:{self.aid}','quote':quote,
                             'result_id':self.rid,'probe':{'result_id':self.rid}}],
                'probe':{'result_id':self.rid},'flags':[],'verified':[],
                'hypotheses':[],'uncertainties':[],'proposed_actions':[]}

    def run_verify(self,iteration=1):
        # Do not pass or mock prior_ids: run_role must compute them itself.
        self.assertIn(self.rid,a.report_probe_records(11))
        result=a.run_role(11,'verify','Audit saved original bytes locally',iteration,api_key='fake-only')
        with self.case.connect() as db:
            stored=json.loads(db.execute('SELECT report_json FROM pm_agent_action_reports '
                                          'WHERE task_id=11 AND role=? AND iteration=?',
                                          ('verify',iteration)).fetchone()[0])
        self.assertEqual(stored,result['report'])
        return stored

    def assert_accepted(self,report):
        self.assertFalse(report.get('report_incomplete'),report.get('report_warning'))
        self.assertEqual(len(report['findings']),1)
        self.assertTrue(report['findings'][0]['evidence_reused'])
        self.assertEqual(report['findings'][0]['verification_status'],'local_audit')
        self.assertEqual(report['local_audits'][0]['result_id'],self.rid)
        self.assertEqual(report['local_audits'][0]['artifact_ref'],f'http_artifact:{self.aid}')
        self.assertNotIn('прямой зонд',report.get('report_warning',''))

    def assert_rejected(self,report):
        self.assertTrue(report.get('report_incomplete'))
        self.assertEqual(report['findings'],[])
        self.assertEqual(len(report['unverified_findings']),1)
        self.assertNotEqual(report['unverified_findings'][0]['verification_reason'],
                            'нет действительного probe.result_id и артефакта из claim в выводе')
        self.assertFalse(report.get('local_audits'))

    def test_prior_http_capture_is_a_complete_local_audit_without_get(self):
        log=(a.CAPABILITY_LOG/'task_11.jsonl').read_bytes()
        with self.case.connect() as db:
            rows=db.execute('SELECT * FROM pm_http_artifacts').fetchall()
        report=self.run_verify()
        self.assert_accepted(report)
        self.assertEqual(len(self.requests),1)
        self.assertEqual((a.CAPABILITY_LOG/'task_11.jsonl').read_bytes(),log)
        with self.case.connect() as db:
            self.assertEqual(db.execute('SELECT * FROM pm_http_artifacts').fetchall(),rows)

    def test_prior_404_response_is_a_complete_local_audit(self):
        self.aid=self.evidence.capture(b'404 Not Found /booking','/booking',status=404)
        self.set_record();self.report=self.audit_report('404 Not Found','/booking')
        self.assert_accepted(self.run_verify())

    def test_original_result_id_can_resolve_an_omitted_artifact_reference(self):
        self.report['findings'][0].pop('artifact_ref')
        self.assert_accepted(self.run_verify())

    def test_prior_git_blob_checks_decoded_bytes_and_object_hash(self):
        self.body=b'# /internal.py\ndef internal_route(): return 7\n'
        raw=b'blob '+str(len(self.body)).encode()+b'\0'+self.body
        oid=hashlib.sha1(raw).hexdigest()
        path=f'/.git/objects/{oid[:2]}/{oid[2:]}'
        self.aid=self.evidence.capture(zlib.compress(raw),path)
        self.set_record()
        self.report=self.audit_report('def internal_route():',path)
        report=self.run_verify()
        self.assert_accepted(report)
        self.assertEqual(report['local_audits'][0]['kind'],'git_blob')
        self.assertEqual(report['local_audits'][0]['sha256'],hashlib.sha256(self.body).hexdigest())

    def test_invalid_git_object_hash_is_rejected(self):
        raw=b'blob '+str(len(self.body)).encode()+b'\0'+self.body
        self.aid=self.evidence.capture(zlib.compress(raw),'/.git/objects/aa/'+'b'*38)
        self.set_record();self.report=self.audit_report()
        report=self.run_verify()
        self.assert_rejected(report)
        self.assertEqual(report['unverified_findings'][0]['verification_reason'],'git_object_hash_mismatch')

    def test_corrupted_capture_is_rejected_even_when_old_stdout_matches(self):
        self.evidence.record(id=self.rid,tool='http_capture',result={'status':'completed',
            'exit_code':0,'task_id':11,'target':'10.0.0.1','artifact_id':self.aid,'stdout':self.body.decode()})
        with self.case.connect() as db:
            sha=db.execute('SELECT sha256 FROM pm_http_artifacts WHERE id=?',(self.aid,)).fetchone()[0]
        (http_artifacts.ROOT/'task-11'/(sha+'.body')).write_bytes(b'Tampered body')
        self.assert_rejected(self.run_verify())

    def test_missing_capture_file_is_rejected(self):
        with self.case.connect() as db:
            sha=db.execute('SELECT sha256 FROM pm_http_artifacts WHERE id=?',(self.aid,)).fetchone()[0]
        (http_artifacts.ROOT/'task-11'/(sha+'.body')).unlink()
        self.assert_rejected(self.run_verify())

    def test_missing_capture_row_is_rejected(self):
        with self.case.connect() as db:db.execute('DELETE FROM pm_http_artifacts WHERE id=?',(self.aid,))
        self.assert_rejected(self.run_verify())

    def test_foreign_task_capture_is_rejected(self):
        with self.case.connect() as db:
            db.execute('UPDATE pm_http_artifacts SET task_id=99 WHERE id=?',(self.aid,))
        self.assert_rejected(self.run_verify())

    def test_previous_target_capture_is_rejected(self):
        with self.case.connect() as db:
            db.execute("UPDATE pm_http_artifacts SET target='10.0.0.99' WHERE id=?",(self.aid,))
        self.assert_rejected(self.run_verify())

    def test_capture_result_with_foreign_task_payload_is_rejected(self):
        self.evidence.record(id=self.rid,tool='http_capture',result={'status':'completed',
            'exit_code':0,'artifact_id':self.aid,'task_id':99,'target':'10.0.0.1'})
        self.assert_rejected(self.run_verify())

    def test_capture_result_with_wrong_target_is_rejected(self):
        self.evidence.record(id=self.rid,tool='http_capture',result={'status':'completed',
            'exit_code':0,'artifact_id':self.aid,'task_id':11,'target':'10.0.0.99'})
        self.assert_rejected(self.run_verify())

    def test_result_and_artifact_must_identify_the_same_capture(self):
        other=self.evidence.capture(self.body,'/other.txt')
        self.report['findings'][0]['artifact_ref']=f'http_artifact:{other}'
        self.assert_rejected(self.run_verify())

    def test_quote_must_match_original_bytes_not_stdout(self):
        self.report['findings'][0]['quote']='Capture metadata only; no body excerpt.'
        self.assert_rejected(self.run_verify())

    def test_conflicting_finding_result_ids_are_rejected(self):
        self.report['findings'][0]['result_id']='b'*24
        self.assert_rejected(self.run_verify())

    def test_probe_only_local_audit_requires_exact_quote(self):
        self.report['findings']=[]
        self.report['probe'].update(artifact_ref=f'http_artifact:{self.aid}',quote='alpha=42')
        report=self.run_verify()
        self.assertFalse(report.get('report_incomplete'))
        self.assertEqual(report['local_audits'][0]['quote'],'alpha=42')
        self.report['probe'].pop('quote')
        self.assertTrue(self.run_verify(iteration=2).get('report_incomplete'))

    def test_old_poc_stdout_cannot_become_a_local_capture_audit(self):
        self.evidence.record(id=self.rid,tool='poc_run',result={'status':'completed',
            'exit_code':0,'artifact_id':self.aid,'task_id':11,'target':'10.0.0.1',
            'stdout':self.body.decode()})
        self.assert_rejected(self.run_verify())

    def test_fresh_readback_id_cannot_promote_an_old_claim_or_access(self):
        readback_id='b'*24
        def readback():
            self.evidence.record(id=readback_id,tool='capability_read',provenance='local',
                result={'status':'completed','stdout':self.body.decode()})
        self.on_model=readback
        finding=self.report['findings'][0]
        finding.update(result_id=readback_id,probe={'result_id':readback_id})
        self.report['probe']['result_id']=readback_id
        self.report['hypotheses']=[{'claim':finding['claim'],'result':'confirmed',
                                  'probe_result_id':readback_id,'quote':'alpha=42'}]
        self.report.update(access_level='user',access_signal='shell',
                           access_probe_result_id=readback_id,access_quote='alpha=42')
        report=self.run_verify()
        self.assert_rejected(report)
        with self.case.connect() as db:
            self.assertEqual(db.execute('SELECT DISTINCT status FROM pm_hypotheses').fetchall(),[('untested',)])
            self.assertEqual(a.fact_state.access_state(db,11)['level'],'none')

    def test_local_poc_readback_is_not_an_original_capture(self):
        rid='c'*24
        self.on_model=lambda: self.evidence.record(id=rid,tool='poc_run',provenance='local',
            result={'status':'completed','exit_code':0,'stdout':self.body.decode()})
        self.report['findings'][0].update(result_id=rid,probe={'result_id':rid})
        self.report['probe']['result_id']=rid
        self.assert_rejected(self.run_verify())

    def test_local_audit_does_not_promote_claims_or_add_witnesses(self):
        claim=self.report['findings'][0]['claim']
        with self.case.connect() as db:
            a.fact_state.save_hypotheses(db,11,'seed',{'hypotheses':[{'claim':claim,'result':'untested'}]})
            a.fact_state.save_hypotheses(db,11,'seed',{'hypotheses':[{'claim':'other claim','result':'refuted',
                                              'probe_result_id':self.rid,'quote':'alpha=42'}]})
            before=db.execute('SELECT * FROM pm_hypotheses ORDER BY claim_key').fetchall()
            c.ensure_schema(db);state=c.snapshot(db,11,2)
            proofs=flag_evidence.collect(db,11)[0]
        self.report['hypotheses']=[{'claim':claim,'result':'confirmed','probe_result_id':self.rid,'quote':'alpha=42'}]
        self.assert_accepted(self.run_verify())
        self.assert_accepted(self.run_verify(iteration=2))
        with self.case.connect() as db:
            after=db.execute('SELECT claim,status,probe_result_id,quote FROM pm_hypotheses ORDER BY claim_key').fetchall()
            self.assertEqual(after,[(r[2],r[4],r[5],r[6]) for r in before])
            self.assertEqual(flag_evidence.collect(db,11)[0],proofs)
            self.assertEqual(c.snapshot(db,11,2)['knowledge_sha256'],state['knowledge_sha256'])

    def test_local_audit_does_not_overwrite_an_existing_refutation(self):
        claim=self.report['findings'][0]['claim']
        with self.case.connect() as db:
            a.fact_state.save_hypotheses(db,11,'seed',{'hypotheses':[{'claim':claim,'result':'refuted',
                                              'probe_result_id':'b'*24,'quote':'previous decisive evidence'}]})
            before=db.execute('SELECT * FROM pm_hypotheses').fetchall()
        self.assert_accepted(self.run_verify())
        with self.case.connect() as db:
            self.assertEqual(db.execute('SELECT * FROM pm_hypotheses').fetchall(),before)

    def test_model_cannot_forge_backend_local_audit_markers(self):
        self.report['findings'][0].update(evidence_reused=True,verification_status='local_audit',
                                          artifact_ref='http_artifact:999')
        self.assert_rejected(self.run_verify())

    def test_coordinator_continues_after_actual_verify_local_audit(self):
        result=c.run(11,api_key='fake-only',model=self.case.model([
            decision('verify','Audit the saved status capture locally'),decision()]))
        self.assertEqual(result['steps'][0]['status'],'completed')
        self.assertEqual(result['stop_reason'],'model_stopped_incomplete')
        self.assertFalse(result['succeeded'])
        self.assertEqual(len(self.case.prompts),2)
        self.assertEqual(len(self.requests),1)


if __name__=='__main__':unittest.main()
