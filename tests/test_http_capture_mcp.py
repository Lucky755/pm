"""Registered FastMCP -> real capture protocol/store -> real coordinator, offline."""
import asyncio
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch
from urllib.parse import quote
import zlib
import hashlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
if __package__:
    from . import test_coordinated_attack as fixtures
else:
    import test_coordinated_attack as fixtures
from orchestrator import agent_actions as a, coordinated_attack as c, diagnostics as d
from orchestrator import http_artifacts as artifacts, flag_verify, objectives, http_discovery as web

spec=importlib.util.spec_from_file_location('capture_mcp_server',ROOT/'mcp/server.py')
server=importlib.util.module_from_spec(spec);spec.loader.exec_module(server)


class CaptureMCPTests(unittest.TestCase):
    value='THM{captured_through_registered_mcp}'

    def setUp(self):
        self.case=fixtures.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        for p in (patch.object(server,'ASSET_DB',self.case.database),
                  patch.object(server,'CAPABILITY_LOG',a.CAPABILITY_LOG),
                  patch.object(server,'ROOT',self.case.root),
                  patch.object(artifacts,'ROOT',self.case.root/'http'),
                  patch.object(subprocess,'Popen',side_effect=self.broker)):
            p.start();self.addCleanup(p.stop)
        self.calls=[];self.body=self.value.encode();self.ctype='text/plain';self.truncated=False
        with self.case.connect() as db:
            # The actual HTTP scope guard checks exact operator authorization.
            self.assertEqual(web.validate_scope(db,11),'10.0.0.1')

    def broker(self,command,**kwargs):
        self.assertEqual(command[:4],['sudo','-n',web.BROKER,'run'])
        self.calls.append(command)
        def arg(name):return command[command.index('--'+name)+1]
        self.assertEqual(arg('profile'),'http_capture')
        self.assertEqual(arg('target'),'10.0.0.1')
        wire=(f'HTTP/1.1 200 OK\r\nContent-Type: {self.ctype}\r\nContent-Length: {len(self.body)}\r\n\r\n').encode()+self.body
        payload={'capture_protocol':1,'task_id':11,'target':arg('target'),'profile':'http_capture',
                 'port':int(arg('port')),'scheme':arg('scheme'),'hostname':arg('hostname'),'path':arg('path'),
                 'status':'completed','exit_code':0,'response_bytes':len(wire),
                 'response_b64':base64.b64encode(wire).decode(),'capture_truncated':self.truncated}
        class Process:
            args=command
            returncode=0
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def communicate(self,input=None,timeout=None):return json.dumps(payload),''
            def poll(self):return 0
        return Process()

    def call(self,name='pm_http_capture',**overrides):
        args={'task_id':11,'target':'10.0.0.1','port':80,'path':'/flag.txt',**overrides}
        # Dispatch through FastMCP registration and its argument validation.
        blocks=asyncio.run(server.mcp.call_tool(name,args))
        if isinstance(blocks,tuple):
            blocks=blocks[0]  # Current FastMCP returns (content, structured result).
        return json.loads(next(b.text for b in blocks if getattr(b,'type',None)=='text'))

    def test_registered_tool_to_artifact_to_goal_without_verify_or_second_request(self):
        model=Mock(return_value=fixtures.decision('recon','Capture /flag.txt once'))
        def role(*args,**kwargs):
            reply=self.call()
            self.assertEqual(reply['status'],'completed')
            self.assertRegex(reply['result_id'],r'^[0-9a-f]{24}$')
            self.assertEqual(reply['artifact_ref'],f"http_artifact:{reply['artifact_id']}")
            self.case.emit_evidence=False
            self.case.report_extra={'flags':[{'value':self.value,'objective_key':'goal',
                                            'goal_evidence':reply['result_id']}]}
            self.case.role(*args,**kwargs)
        with self.case.connect() as db:
            objectives.save_objectives(db,11,'Capture the flag',exclusive=True,expected_flags=1)
        with d.run('registered capture',11):
            result=c.run(11,model=model,role_runner=role,expect_flags=1,max_steps=1)
            events=d.read_events()
        self.assertTrue(result['succeeded']);self.assertEqual(result['stop_reason'],'goal_confirmed')
        self.assertEqual(len(self.calls),1);self.assertEqual(model.call_count,1)
        self.assertEqual([r[0] for r in self.case.calls],['recon'])
        record=json.loads((a.CAPABILITY_LOG/'task_11.jsonl').read_text().splitlines()[0])
        self.assertEqual((record['tool'],record['provenance']),('http_capture','network'))
        with self.case.connect() as db:
            aid=record['result']['artifact_id']
            body,meta=artifacts.load(db,11,aid)
            self.assertEqual(body,self.body)
            self.assertEqual(meta['request']['path'],'/flag.txt')
            self.assertEqual(web.attempts_used(db,11),1)
            self.assertEqual(flag_verify.scan(11,db=db)['confirmed'][0]['value'],self.value)
        tools=[e for e in events if e['kind']=='tool.start']
        self.assertEqual([t['name'] for t in tools],['pm_http_capture'])

    def test_registered_capture_cache_and_readback_do_not_repeat_request(self):
        first=self.call();second=self.call()
        self.assertEqual(first['artifact_id'],second['artifact_id'])
        self.assertTrue(second['cached'])
        asyncio.run(server.mcp.call_tool('pm_capability_read',{'task_id':11,'result_id':first['result_id']}))
        self.assertEqual(len(self.calls),1)
        with self.case.connect() as db:
            reg=flag_verify.scan(11,db=db)
            self.assertEqual(len(reg['confirmed'][0]['verified_evidence']),1)

    def test_registered_git_capture_is_verified_from_binary_bytes(self):
        raw=b'blob '+str(len(self.body)).encode()+b'\0'+self.body
        oid=hashlib.sha1(raw).hexdigest()
        self.body=zlib.compress(raw);self.ctype='application/octet-stream'
        reply=self.call(path=f'/.git/objects/{oid[:2]}/{oid[2:]}')
        self.assertEqual(reply['stdout'],self.value)
        self.assertEqual(reply['decoded_artifact']['object_id'],oid)
        with self.case.connect() as db:
            reg=flag_verify.scan(11,db=db)
        self.assertEqual(reg['confirmed'][0]['verified_evidence'][0]['object_id'],oid)
        self.assertEqual(len(self.calls),1)

    def test_scope_and_unsafe_paths_are_refused_before_broker(self):
        for args in ({'target':'10.0.0.2'},{'hostname':'outside.example'},
                     {'path':'/logout'},{'path':'/../secret'},{'path':'/x?flag=known'}):
            with self.subTest(args=args):
                self.assertEqual(self.call(**args)['status'],'blocked')
        self.assertEqual(self.calls,[])

    def test_registered_reflection_is_not_discovery_and_does_not_cancel_good_capture(self):
        reflected=self.call(path='/echo/'+quote(self.value,safe=''))
        with self.case.connect() as db:
            self.assertEqual(flag_verify.scan(11,db=db)['confirmed'],[])
        result=self.case.run_mode([fixtures.decision()],expect_flags=1)
        self.assertFalse(result['succeeded'])
        self.assertEqual(len(self.calls),1)
        genuine=self.call()
        with self.case.connect() as db:
            proofs=flag_verify.scan(11,db=db)['confirmed'][0]['verified_evidence']
        self.assertEqual([p['capture_ref'] for p in proofs],[genuine['artifact_ref']])

    def test_http_request_budget_is_shared_with_discovery(self):
        with self.case.connect() as db:
            web.init(db)
            for n in range(web.MAX_TOTAL):
                db.execute('INSERT INTO pm_http_discovery(task_id,target,port,scheme,hostname,path,created_at) '
                           "VALUES(11,'10.0.0.1',80,'http','10.0.0.1',?,?)",(f'/prior-{n}',c.now()))
        self.assertEqual(self.call()['status'],'blocked')
        self.assertEqual(self.calls,[])

    def test_broker_protocol_error_is_a_failed_attempt_without_auto_retry(self):
        original=self.broker
        def malformed(command,**kwargs):
            result=original(command,**kwargs)
            result.communicate=lambda input=None,timeout=None:('{"status":"completed"}','')
            return result
        with patch.object(subprocess,'Popen',side_effect=malformed):
            self.assertEqual(self.call()['status'],'error')
        self.assertEqual(self.call()['status'],'blocked')
        self.assertEqual(len(self.calls),1)
        with self.case.connect() as db:
            self.assertEqual(web.attempts_used(db,11),1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pm_http_artifacts').fetchone()[0],0)

    def test_closed_asset_prevents_probe_but_does_not_prevent_cached_read(self):
        first=self.call()
        with self.case.connect() as db:
            db.execute("INSERT INTO pm_assets(task_id,kind,key,status,origin_task_id,origin_target,updated_at) "
                       "VALUES(11,'port','80','dead',11,'10.0.0.1',?)",(c.now(),))
        self.assertTrue(self.call()['cached'])
        self.assertEqual(self.call(path='/new-path')['status'],'blocked')
        self.assertEqual(len(self.calls),1)

    def test_static_budget_is_shared_with_discovery(self):
        for n in range(web.MAX_STATIC_TOTAL):
            self.assertEqual(self.call(path=f'/script-{n}.js')['status'],'completed')
        self.assertEqual(self.call(path='/one-more.css')['status'],'blocked')
        self.assertEqual(len(self.calls),web.MAX_STATIC_TOTAL)

    def test_capture_limit_and_partial_response_are_preserved(self):
        with self.case.connect() as db:
            artifacts.set_response_limit(db,11,artifacts.MAX_BODY,c.now())
        self.truncated=True
        reply=self.call()
        self.assertEqual(reply['status'],'incomplete')
        self.assertFalse(reply['download_complete'])
        command=self.calls[0]
        self.assertEqual(command[command.index('--capture-limit')+1],str(artifacts.MAX_BODY))
        with self.case.connect() as db:
            self.assertEqual(flag_verify.scan(11,db=db)['confirmed'],[])
        self.assertTrue(self.call()['cached'])
        self.assertEqual(len(self.calls),1)


if __name__=='__main__':unittest.main()
