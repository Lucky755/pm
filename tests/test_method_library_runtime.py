"""Real registered MCP, local HTTP worker and file processor; no model/API.

Only the privileged broker/namespace boundary is replaced by the existing
loopback fixture. The new library never dispatches a command or changes task DB.
"""
import copy
import json
import os
import sqlite3
from contextlib import closing
import unittest
from unittest.mock import patch
from orchestrator import method_library as methods,agent_actions as actions,material_processing as files
from tests import test_work_series_runtime as fixture
from tests.test_method_library import specification


class MethodLibraryRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.series=fixture.SeriesRuntimeTests();self.series.setUp();self.addCleanup(self.series.doCleanups)
        self.http=self.series.http;self.case=self.http.case
        self.library=methods.Library(self.case.root/'methods')
        p=patch.dict(os.environ,{'PM_METHOD_LIBRARY_DIR':str(self.library.root)});p.start();self.addCleanup(p.stop)
        original=self.http.http.RequestHandlerClass.do_GET;owner=self
        def get(request):
            if request.path=='/method-source':
                owner.http.requests.append({'path':request.path});request.respond(200,b'ORIGINAL METHOD SOURCE BYTES')
            else:original(request)
        self.http.http.RequestHandlerClass.do_GET=get
        self.log=actions.CAPABILITY_LOG/'task_11.jsonl'

    def readonly(self):
        return closing(sqlite3.connect(self.case.database.resolve().as_uri()+'?mode=ro',uri=True))

    def test_real_http_action_is_retained_without_another_request_or_db_write(self):
        reply=self.http.call('/method-source')
        evidence={'kind':'http_response','result_id':reply['result_id'],'artifact_ref':reply['artifact_ref'],'quote':'METHOD SOURCE'}
        before=self.case.database.read_bytes();count=len(self.http.requests)
        with self.readonly() as db:item=self.library.save(db,11,specification(),evidence,self.log)
        self.assertEqual(item['observed_result']['kind'],'http_capture')
        self.assertEqual(len(self.http.requests),count);self.assertEqual(count,1)
        self.assertEqual(self.case.database.read_bytes(),before)
        self.assertNotIn('ORIGINAL METHOD SOURCE BYTES',(self.library.root/'catalog.json').read_text())

    def test_typed_success_is_reaudited_and_negative_or_reflected_response_is_not_advice(self):
        plan=self.series.paths(['/method-source'],marker='METHOD SOURCE')
        reply=self.series.call(plan);self.assertTrue(reply['criterion_matched'])
        evidence={'kind':'http_criterion','series_id':reply['series_id'],'result_id':reply['result_id'],
            'artifact_ref':reply['checks'][0]['artifact_ref'],'quote':'METHOD SOURCE'}
        spec=specification();spec['tools']=['pm_check_series']
        with self.readonly() as db:item=self.library.save(db,11,spec,evidence,self.log)
        self.assertEqual(item['observed_result']['criterion'],'find_file')
        self.assertEqual(len(self.http.requests),1)
        # Reopening and reevaluating the same original does not create a second
        # method/evidence or make another target observation.
        with self.readonly() as db:again=self.library.save(db,11,spec,evidence,self.log)
        self.assertEqual(again['version'],1);self.assertEqual(len(self.http.requests),1)
        bad=self.http.call('/denied')
        reflected=self.http.call('/reflect?marker=REFLECTED_METHOD_MARKER')
        for source,quote in ((bad,'denied'),(reflected,'REFLECTED_METHOD_MARKER')):
            with self.readonly() as db,self.assertRaises(ValueError):
                self.library.save(db,11,specification(),{'kind':'http_response','result_id':source['result_id'],
                    'artifact_ref':source['artifact_ref'],'quote':quote},self.log)
        self.assertEqual(len(self.library.read()['methods']),1)

    def test_real_local_transform_is_saved_and_binary_advice_does_not_enter_web_prompt(self):
        with self.case.connect() as db:
            original=files.save(db,11,'def decoded(): return 42\n'.encode('utf-16'),name='downloaded.bin',source_ref='operator:offline')
        result=self.http.tool('pm_material_process',reference=original['reference'])
        self.assertEqual(result['status'],'completed',result)
        output=next(out for out in result['outputs'] if out['metadata'].get('kind')!='analyzer_stderr')
        spec=specification('decode-source-file',['material-analysis'],['encoding','code'])
        spec.update(title='Decode a saved source file',tools=['pm_material_process'],
            conditions='A complete saved code file has a supported byte encoding.',
            method=['Select processing by actual file bytes.','Read the decoded output with its original lineage.'])
        evidence={'kind':'material_transform','result_id':result['result_id'],'artifact_ref':output['reference'],'quote':'return 42'}
        with self.readonly() as db:item=self.library.save(db,11,spec,evidence,self.log)
        self.assertEqual(item['observed_result']['kind'],'material_transform');self.assertFalse(self.http.requests)
        self.assertTrue(self.library.select('material-analysis','Interpret code encoding')['items'])
        context={'task_id':11,'specialist_assignment':{'profile':'http-surface'}}
        self.assertEqual(methods.prompt_block(context,'vuln','Read ordinary web links'), '')
        self.assertEqual(self.library.select('http-surface','Interpret code encoding')['items'],[])

    def test_authentication_success_stays_narrow_and_session_secrets_are_not_exported(self):
        reply=self.series.call(self.series.pairs(['secret3']))
        self.assertTrue(reply['criterion_matched'])
        evidence={'kind':'http_criterion','series_id':reply['series_id'],'result_id':reply['result_id'],
            'artifact_ref':reply['checks'][0]['artifact_ref'],'quote':'SERVER AUTHENTICATED'}
        spec=specification('bounded-basic-check',['access'],['authentication','basic']);spec['tools']=['pm_check_series']
        with self.readonly() as db:item=self.library.save(db,11,spec,evidence,self.log)
        self.assertEqual(item['observed_result']['criterion'],'authenticated')
        self.assertIn('does not establish shell/access',item['observed_result']['meaning'])
        contaminated=copy.deepcopy(spec);contaminated['method'].append('Use secret3 again')
        with self.readonly() as db,self.assertRaisesRegex(ValueError,'parameterization'):
            self.library.save(db,11,contaminated,evidence,self.log,expected_version=1,reason='Wrong export')
        # A new cached wrapper result ID is not another successful execution.
        readback=self.series.call(self.series.pairs(['secret3']))
        with self.readonly() as db:again=self.library.save(db,11,spec,{**evidence,'result_id':readback['result_id']},self.log)
        self.assertEqual(again['version'],1);self.assertEqual(len(again['origins']),1)
        self.assertEqual(len(self.http.requests),1)


if __name__=='__main__':unittest.main(verbosity=2)
