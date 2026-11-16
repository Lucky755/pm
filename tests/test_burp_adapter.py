"""PM bridge v3 contract only; these are not tests of a real Burp instance."""
import asyncio
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from orchestrator import agent_actions,browser,burp_adapter,http_artifacts,resources,task_memory,flag_evidence
from executor import netguard_root as broker
from tests import test_coordinated_attack as fixture


class BurpAdapterTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.calls=[];self.edition='PROFESSIONAL';self.missing=False
        self.instance='12345678-1234-1234-1234-123456789abc'
        self.entry={'id':4,'target':'10.0.0.1','url':'http://app.lab:8080/private','method':'GET',
            'observed_at':'2026-11-16T00:00:00Z','format':'montoya_http_message',
            'request_b64':base64.b64encode(b'GET /private HTTP/1.1\r\nAuthorization: test-private-secret\r\n\r\n').decode(),
            'response_b64':base64.b64encode(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata').decode()}
        scope=resources.resolve('http://app.lab:8080/',addresses=['10.0.0.1'])
        with self.case.connect() as db:resources.save(db,11,scope)
        module=importlib.util.spec_from_file_location('burp_adapter_mcp',Path(__file__).resolve().parents[1]/'mcp/server.py')
        self.server=importlib.util.module_from_spec(module);module.loader.exec_module(self.server)
        for replacement in (patch.object(subprocess,'run',side_effect=self.boundary),
                patch.object(self.server,'ASSET_DB',self.case.database),patch.object(http_artifacts,'ROOT',self.case.root/'http')):
            replacement.start();self.addCleanup(replacement.stop)

    def boundary(self,argv,**kw):
        self.assertEqual(argv[:4],['sudo','-n','/usr/local/sbin/pm-netguard','burp-read'])
        value=json.loads(kw['input']);self.calls.append(value)
        if self.missing:raise FileNotFoundError('No Burp')
        if value['action']=='status':
            payload={'status':'running','protocol':3,'edition':self.edition,'guarded_proxy':True,'instance_id':self.instance,'montoya':'2026.7'}
        else:payload={'status':'ok','protocol':3,'instance_id':self.instance,'entries':[self.entry]}
        return subprocess.CompletedProcess(argv,0,json.dumps(payload),'')

    def call(self,action,**kw):
        result=asyncio.run(self.server.mcp.call_tool('pm_burp',{'task_id':11,'action':action,**kw}))
        blocks=result[0] if isinstance(result,tuple) else result
        return json.loads(next(b.text for b in blocks if getattr(b,'type',None)=='text'))

    def test_missing_or_wrong_edition_is_unavailable_not_integrated(self):
        self.missing=True;self.assertEqual(self.call('status')['status'],'unavailable')
        self.missing=False;self.edition='COMMUNITY_EDITION'
        self.assertEqual(self.call('status')['status'],'unavailable')

    def test_import_is_passive_idempotent_and_originals_are_in_memory(self):
        first=self.call('import',url='http://app.lab:8080/')
        self.assertEqual(first['imported'],1);self.assertFalse(first['fresh_target_request'])
        self.assertEqual(self.call('import',url='http://app.lab:8080/')['imported'],0)
        before=len(self.calls);saved=self.call('read');self.assertEqual(len(self.calls),before)
        with self.case.connect() as db:
            ref=saved['messages'][0]['request_material']
            raw=task_memory.material(db,11,ref,agent_actions.CAPABILITY_LOG/'task_11.jsonl')
            self.assertIn(b'Authorization: test-private-secret',raw)
            memory=task_memory.current(db,11)
            self.assertNotIn('test-private-secret',json.dumps(memory))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pm_agent_action_reports').fetchone()[0],0)
        self.assertIn('association unknown',saved['messages'][0]['authentication'])

    def test_foreign_origin_or_target_is_rejected(self):
        self.assertEqual(self.call('import',url='http://outside.invalid/')['status'],'blocked')
        self.assertEqual(self.calls,[])
        self.entry['target']='10.0.0.2'
        self.assertEqual(self.call('import',url='http://app.lab:8080/')['status'],'blocked')
        with self.case.connect() as db,self.assertRaisesRegex(ValueError,'task/session mismatch'):
            browser.import_network(db,11,'local-session',[{'task_id':12,'session_id':'local-session'}])

    def test_history_cannot_be_used_as_send_api(self):
        self.assertEqual(self.call('send',url='http://app.lab:8080/')['status'],'blocked')
        self.assertEqual(self.calls,[])

    def test_browser_launcher_is_unprivileged_without_shared_network(self):
        config={'owner':'offline','uid':1000,'gid':1000,'browser':{'runtime':'/opt/offline-venv'}}
        with patch.object(broker,'owned_config',return_value=({'name':'task-offline'},config)), \
             patch.object(broker,'task_workdir',return_value=Path('/tmp/offline-work')):
            argv=broker.browser_engine_command(11,config)
        self.assertIn('--unshare-all',argv);self.assertNotIn('--share-net',argv)
        self.assertIn('--bounding-set=-all',argv);self.assertIn('--clearenv',argv)
        offset=argv.index('/opt/offline-venv')
        self.assertEqual(argv[offset-1:offset+2],['--ro-bind','/opt/offline-venv','/opt/pm-browser'])
        self.assertEqual(argv[-3:],['/opt/pm-browser/bin/python','/usr/local/sbin/pm-netguard','browser-engine'])

    def test_proxy_bytes_are_not_automatically_original_target_proof(self):
        with self.case.connect() as db:
            capture={'body':b'THM{proxy_contract_bytes}','headers':{'content-type':'text/plain'},'status':200,'complete':True,
                'metadata':{'transport_proxy':'burp'}}
            proxy_id=http_artifacts.save(db,11,'10.0.0.1','http','10.0.0.1',80,'/flag.txt',capture,'2026-11-16')
            witnesses,errors=flag_evidence.collect(db,11)
            self.assertEqual(witnesses,[])
            self.assertIn({'capture_ref':'http_artifact:'+str(proxy_id),
                'reason':'proxy_target_provenance_requires_original_history_correlation'},errors)
            capture['metadata']={}
            direct=http_artifacts.save(db,11,'10.0.0.1','http','10.0.0.1',80,'/flag.txt',capture,'2026-11-16')
            witnesses,_=flag_evidence.collect(db,11)
            self.assertEqual([w['capture_ref'] for w,text in witnesses],['http_artifact:'+str(direct)])


if __name__=='__main__':unittest.main()
