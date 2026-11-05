"""Offline proof validation and coordinator decisions; all evidence is temporary."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if __package__:
    from . import test_coordinated_attack as fixtures
else:
    import test_coordinated_attack as fixtures
from orchestrator import agent_actions as a, coordinated_attack as c, diagnostics as d
from orchestrator import flag_verify as flags, http_artifacts as artifacts, objectives


class FlagEvidenceTests(unittest.TestCase):
    value = 'THM{offline_captured_proof}'

    def setUp(self):
        self.case = fixtures.CoordinatorTests(); self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        patcher = patch.object(artifacts, 'ROOT', self.case.root / 'http')
        patcher.start(); self.addCleanup(patcher.stop)

    def capture(self, body=None, path='/flag.txt', task=11, target='10.0.0.1', status=200):
        body = body if body is not None else ('flag: ' + self.value + '\n').encode()
        with self.case.connect() as db:
            return artifacts.save(db, task, target, 'http', target, 80, path,
                                  {'body': body, 'headers': {'content-type': 'text/plain'},
                                   'metadata': {}, 'status': status, 'complete': True}, c.now())

    def record(self, value=None, **extra):
        a.CAPABILITY_LOG.mkdir(exist_ok=True)
        record = {'id': 'a'*24, 'task_id': 11, 'tool': 'poc_run', 'provenance': 'network',
                  'result': {'status': 'completed', 'exit_code': 0, 'stdout': value or self.value}, **extra}
        with (a.CAPABILITY_LOG/'task_11.jsonl').open('a') as stream:
            stream.write(json.dumps(record)+'\n')

    def registry(self):
        with self.case.connect() as db:
            return flags.scan(11, db=db)

    def test_single_saved_target_response_is_enough(self):
        aid = self.capture()
        result = self.registry()
        self.assertEqual([f['value'] for f in result['confirmed']], [self.value])
        proof = result['confirmed'][0]['verified_evidence'][0]
        self.assertEqual(proof['capture_ref'], f'http_artifact:{aid}')
        self.assertEqual(proof['target'], '10.0.0.1')
        self.assertEqual(proof['path'], '/flag.txt')
        self.assertIn(self.value, proof['quote'])
        self.assertEqual(proof['sha256'], hashlib.sha256(('flag: '+self.value+'\n').encode()).hexdigest())

    def test_original_http_status_is_preserved_instead_of_claiming_200(self):
        self.capture(status=404)
        proof = self.registry()['confirmed'][0]['verified_evidence'][0]
        self.assertEqual(proof['status_code'],404)

    def test_model_claim_and_two_arbitrary_outputs_are_not_proof(self):
        self.case.report_extra = {'flags': [{'value': self.value}]}
        self.case.emit_evidence = False
        self.case.role(11, 'verify', 'Inspect data', 1, 1, 1)
        self.record(argv=['echo', self.value])
        self.record(id='b'*24, argv=['python3', '-c', 'print(bytes.fromhex("00"))'])
        result = self.registry()
        self.assertEqual(result['confirmed'], [])
        item = result['candidates'][0]
        self.assertTrue(item['confirmation_reasons'])
        self.assertEqual(item['verified_evidence'], [])

    def test_readback_is_not_new_proof(self):
        self.record(tool='capability_read', provenance='local')
        self.record(id='b'*24, tool='read_file', provenance='local')
        self.assertEqual(self.registry()['confirmed'], [])
        self.capture()
        first = self.registry()['confirmed'][0]['verified_evidence']
        self.record(id='c'*24, tool='capability_read', provenance='local')
        self.assertEqual(self.registry()['confirmed'][0]['verified_evidence'], first)

    def test_duplicate_capture_preserves_both_references_without_extra_witness(self):
        first, second = self.capture(), self.capture()
        result = self.registry()
        proof = result['confirmed'][0]['verified_evidence']
        self.assertEqual(len(proof), 1)
        self.assertEqual(proof[0]['capture_refs'], [f'http_artifact:{first}', f'http_artifact:{second}'])
        with self.case.connect() as db:
            objectives.save_objectives(db,11,'Capture the flag',exclusive=True)
            report = {'flags':[{'value':self.value,'objective_key':'goal','goal_evidence':f'http_artifact:{second}'}]}
            state = objectives.process_report(db,11,report,result)
        self.assertEqual(state['primary']['status'],'confirmed')

    def test_typed_capture_result_id_keeps_the_existing_report_contract(self):
        aid = self.capture()
        self.record(tool='http_capture',result={'status':'completed','exit_code':0,'task_id':11,
                                               'target':'10.0.0.1','artifact_id':aid})
        registry = self.registry()
        with self.case.connect() as db:
            objectives.save_objectives(db,11,'Capture the flag',exclusive=True)
            report = {'flags':[{'value':self.value,'objective_key':'goal','goal_evidence':'a'*24}]}
            state = objectives.process_report(db,11,report,registry)
        self.assertEqual(state['primary']['status'],'confirmed')

    def test_poc_cannot_claim_a_capture_link_to_complete_a_goal(self):
        aid = self.capture()
        self.record(result={'status':'completed','task_id':11,'target':'10.0.0.1','artifact_id':aid})
        registry = self.registry()
        with self.case.connect() as db:
            objectives.save_objectives(db,11,'Capture the flag',exclusive=True)
            report = {'flags':[{'value':self.value,'objective_key':'goal','goal_evidence':'a'*24}]}
            state = objectives.process_report(db,11,report,registry)
        self.assertNotEqual(state['primary']['status'],'confirmed')
        self.assertEqual(registry['confirmed'][0]['status'],'confirmed')

    def test_git_blob_is_redecoded_and_hash_checked(self):
        body = ('# README\n'+self.value+'\n').encode()
        raw = b'blob '+str(len(body)).encode()+b'\0'+body
        oid = hashlib.sha1(raw).hexdigest()
        aid = self.capture(zlib.compress(raw), f'/.git/objects/{oid[:2]}/{oid[2:]}')
        proof = self.registry()['confirmed'][0]['verified_evidence'][0]
        self.assertEqual(proof['kind'], 'git_blob')
        self.assertEqual(proof['object_id'], oid)
        self.assertEqual(proof['capture_ref'], f'http_artifact:{aid}')
        self.assertEqual(proof['sha256'], hashlib.sha256(body).hexdigest())

    def test_bad_git_hash_or_length_does_not_confirm(self):
        bad_length = b'blob 999\0'+self.value.encode()
        oid = hashlib.sha1(bad_length).hexdigest()
        self.capture(zlib.compress(bad_length), f'/.git/objects/{oid[:2]}/{oid[2:]}')
        raw = b'blob '+str(len(self.value)).encode()+b'\0'+self.value.encode()
        self.capture(zlib.compress(raw), '/.git/objects/'+'0'*2+'/'+'0'*38)
        self.record(provenance='local')
        result = self.registry()
        self.assertEqual(result['confirmed'], [])
        self.assertEqual({e['reason'] for e in result['evidence_errors']},
                         {'git_object_size_mismatch','git_object_hash_mismatch'})

    def test_flag_validation_does_not_modify_capture_files_or_directories(self):
        self.capture()
        with self.case.connect() as db:
            before = db.total_changes
            paths = [artifacts.ROOT, artifacts.ROOT/'task-11', *artifacts.ROOT.rglob('*.body')]
            stats = [(p.stat().st_mode,p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in paths]
            from orchestrator import flag_evidence
            flag_evidence.collect(db, 11)
            self.assertEqual(db.total_changes, before)
            self.assertEqual(stats, [(p.stat().st_mode,p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in paths])

    def test_one_capture_does_not_lower_requested_flag_count(self):
        self.capture()
        with self.case.connect() as db:
            objectives.save_objectives(db, 11, 'Find two flags', mode='all-flags', expected_flags=2)
        result = self.case.run_mode([fixtures.decision()], expect_flags=2)
        self.assertFalse(result['succeeded'])
        self.assertEqual(result['expected_flags'], 2)

    def test_old_candidate_result_reference_survives_the_recent_window(self):
        self.record(provenance='local')
        for n in range(25):
            self.record(value='ordinary readback',id=f'{n:024x}',tool='capability_read',provenance='local')
        self.case.run_mode([fixtures.decision()])
        self.assertIn('result:'+'a'*24,self.case.prompts[0]['references'])

    def test_tampered_capture_and_wrong_task_or_address_do_not_confirm(self):
        self.record(provenance='local')
        self.capture(task=22)
        self.capture(target='10.0.0.9')
        aid = self.capture()
        with self.case.connect() as db:
            sha = db.execute('SELECT sha256 FROM pm_http_artifacts WHERE id=?', (aid,)).fetchone()[0]
        (artifacts.ROOT/'task-11'/(sha+'.body')).write_bytes(b'corrupted')
        self.assertEqual(self.registry()['confirmed'], [])

    def test_completed_goal_stops_without_another_model_call(self):
        with self.case.connect() as db:
            objectives.save_objectives(db, 11, 'Capture the flag', exclusive=True, expected_flags=1)
        def role(*args, **kwargs):
            aid = self.capture()
            self.case.report_extra = {'flags': [{'value': self.value, 'objective_key': 'goal',
                                                'goal_confirmed': True, 'goal_evidence': f'http_artifact:{aid}'}]}
            self.case.emit_evidence = False
            self.case.role(*args, **kwargs)
        model = Mock(return_value=fixtures.decision('recon', 'Capture the saved target response?'))
        result = c.run(11, api_key='fake-only', model=model, role_runner=role, max_steps=1, expect_flags=1)
        self.assertTrue(result['succeeded'])
        self.assertEqual(result['stop_reason'], 'goal_confirmed')
        self.assertEqual(model.call_count, 1)
        with self.case.connect() as db:
            self.assertEqual(objectives.objective_status(db, 11)['expected_flags'], 1)

    def test_saved_report_is_rechecked_before_first_model_request(self):
        aid = self.capture()
        with self.case.connect() as db:
            objectives.save_objectives(db, 11, 'Capture the flag', exclusive=True, expected_flags=1)
        self.case.emit_evidence = False
        self.case.report_extra = {'flags':[{'value':self.value,'objective_key':'goal',
                                         'goal_evidence':f'http_artifact:{aid}'}]}
        self.case.role(11,'recon','Capture evidence',1,1,1)
        model = Mock(side_effect=AssertionError('unneeded model request'))
        result = c.run(11,model=model,expect_flags=1)
        self.assertTrue(result['succeeded'])
        model.assert_not_called()
        sha = hashlib.sha256(('flag: '+self.value+'\n').encode()).hexdigest()
        (artifacts.ROOT/'task-11'/(sha+'.body')).write_bytes(b'corrupted capture')
        result = self.case.run_mode([fixtures.decision()],expect_flags=1)
        self.assertFalse(result['succeeded'])

    def test_candidates_and_specific_blockers_reach_actual_coordinator_prompt(self):
        self.record(provenance='local')
        self.case.run_mode([fixtures.decision()])
        state = self.case.prompts[0]
        self.assertEqual(state['flag_candidates'][0]['value'], self.value)
        self.assertTrue(state['flag_candidates'][0]['confirmation_reasons'])
        self.assertIn('result:'+'a'*24, state['references'])

    def test_fenced_json_is_validated_as_a_whole(self):
        value = '```json\n'+json.dumps(fixtures.decision())+'\n```'
        result = self.case.run_mode([value], decision_retries=0)
        self.assertEqual(result['stop_reason'], 'model_stopped_incomplete')

    def test_rejection_reason_and_attempt_are_durable_and_not_executor_error(self):
        secret = 'sk-SECRET-DO-NOT-LOG'
        with d.run('invalid decision', 11):
            result = self.case.run_mode(['{'+secret, fixtures.decision(references=['missing'])], decision_retries=1)
            events = d.read_events()
        self.assertEqual(result['stop_reason'], 'decision_budget_exhausted:unknown_reference')
        with self.case.connect() as db:
            rows = db.execute('SELECT attempt,reason_code FROM pm_coordinator_decision_attempts ORDER BY id').fetchall()
        self.assertEqual(rows, [(1, 'invalid_json'), (2, 'unknown_reference')])
        rejected = [e for e in events if e['kind']=='coordinator.decision_rejected']
        self.assertEqual([e['attempt'] for e in rejected], [1, 2])
        self.assertNotIn(secret, json.dumps(events))
        self.assertNotIn(secret.encode(), self.case.database.read_bytes())
        ends = [e for e in events if e['kind']=='stage.end' and e.get('name')=='run']
        self.assertEqual(ends[-1]['reason_category'], 'coordinator_decision')


if __name__ == '__main__':
    unittest.main()
