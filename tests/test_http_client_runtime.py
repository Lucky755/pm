"""Registered MCP -> real worker process -> loopback HTTP -> original artifacts.

Only the privileged broker boundary is replaced. No mocked HTTP/socket/store,
no installed broker changes, target traffic, sudo or model provider.
"""
import asyncio
import base64
import importlib.util
import json
import hashlib
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs,urlsplit

from executor import netguard_root as broker
from orchestrator import agent_actions as actions,diagnostics,http_artifacts as artifacts,http_client,resources,task_memory,flag_verify
from tests import test_coordinated_attack as fixture


class HTTPRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.requests=[];self.inner_hits=[];self.counter=0;self.broker_calls=[]
        owner=self
        class Handler(BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*args):pass
            def respond(self,status,body=b'ok',headers=()):
                self.send_response(status)
                self.send_header('Content-Type','text/plain')
                self.send_header('Content-Length',str(len(body)))
                for key,value in headers:self.send_header(key,value)
                self.end_headers()
                try:self.wfile.write(body)
                except (BrokenPipeError,ConnectionResetError):pass
            def do_GET(self):self.handle_request()
            def do_HEAD(self):self.handle_request()
            def do_POST(self):self.handle_request()
            def do_PUT(self):self.handle_request()
            def do_PATCH(self):self.handle_request()
            def do_DELETE(self):self.handle_request()
            def do_OPTIONS(self):self.handle_request()
            def handle_request(self):
                body=self.rfile.read(int(self.headers.get('Content-Length','0')))
                owner.requests.append({'method':self.command,'path':self.path,'headers':dict(self.headers),'body':body})
                path=urlsplit(self.path).path
                if path=='/login':self.respond(200,b'login result requires interpretation',[('Set-Cookie','sid=accepted; Path=/; HttpOnly')])
                elif path=='/cookie-path':self.respond(200,headers=[('Set-Cookie','limited=path; Path=/echo'),('Set-Cookie','tls=private; Path=/; Secure')])
                elif path=='/current':
                    owner.counter+=1;self.respond(200,str(owner.counter).encode())
                elif path=='/redirect':self.respond(302,headers=[('Location','/current?q=redirect#browser')])
                elif path=='/post-redirect':self.respond(303,headers=[('Location','/echo')])
                elif path=='/keep-method':self.respond(307,headers=[('Location','/echo')])
                elif path=='/outside':self.respond(302,headers=[('Location',owner.inner_url+'/private')])
                elif path=='/alias':self.respond(302,headers=[('Location',owner.url.replace('app.lab','alias.lab')+'/echo')])
                elif path=='/large-header':self.respond(200,b'header accepted',[('X-Large','x'*(900*1024))])
                elif path=='/exact-header':
                    prefix=b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Large: '
                    self.connection.sendall(prefix+b'x'*(broker.HTTP_HEADER_LIMIT-len(prefix)-4)+b'\r\n\r\nok')
                elif path=='/too-large-header':self.respond(200,b'no',[('X-Large','x'*(1024*1024))])
                elif path=='/large-body':self.respond(200,b'x'*(2*1024*1024+8192))
                elif path=='/chunked':
                    self.connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\nX-Trailer: saved\r\n\r\n')
                elif path=='/broken-chunks':
                    self.connection.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n')
                    self.close_connection=True
                elif path=='/fetch':
                    if self.command=='POST' and self.headers.get('Content-Type','').startswith('application/json'):destination=json.loads(body).get('url','')
                    elif self.command=='POST':destination=parse_qs(body.decode()).get('url',[''])[0]
                    else:destination=parse_qs(urlsplit(self.path).query).get('url',[''])[0]
                    # The test application, not PM's HTTP component, reaches its
                    # own internal service. Never point it outside this fixture.
                    if destination!=owner.inner_url+'/private':self.respond(400,b'bad destination');return
                    import http.client
                    inner=http.client.HTTPConnection('127.0.0.1',owner.inner.server_port)
                    inner.request('GET','/private');response=inner.getresponse();data=response.read();inner.close()
                    self.respond(200,data)
                elif path=='/denied':self.respond(403,b'denied')
                elif path=='/reflect':self.respond(200,body or urlsplit(self.path).query.encode())
                elif path=='/same-flag':self.respond(200,b'THM{offline_same_url_flag}')
                else:self.respond(200,body or b'ok')
        class Internal(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                owner.inner_hits.append(self.path);body=b'internal offline marker'
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        self.inner=ThreadingHTTPServer(('127.0.0.1',0),Internal)
        self.http=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        for server in (self.inner,self.http):
            self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
            threading.Thread(target=server.serve_forever,daemon=True).start()
        self.url=f'http://app.lab:{self.http.server_port}';self.inner_url=f'http://127.0.0.1:{self.inner.server_port}'
        self.configure()
        module=importlib.util.spec_from_file_location('http_client_mcp',Path(__file__).resolve().parents[1]/'mcp/server.py')
        self.server=importlib.util.module_from_spec(module);module.loader.exec_module(self.server)
        # Replace the task namespace route at the privileged boundary: the
        # saved logical address maps to this fixture's real loopback socket.
        # No HTTP result, socket object, parsing or artifact write is mocked.
        driver=self.case.root/'http-worker.py'
        driver.write_text('''import sys,socket
sys.path.insert(0,sys.argv[1])
from executor import netguard_root as b
connect=socket.create_connection
def local(address,*a,**kw):
 if address[0]!='10.0.0.1':raise ValueError('Fixture network outside logical test target')
 return connect(('127.0.0.1',address[1]),*a,**kw)
socket.create_connection=local
sys.argv=['pm-netguard','http-worker']
b.main()
''')
        real_run=subprocess.run
        def boundary(argv,**kwargs):
            if argv==[broker_path,'capabilities']:
                return real_run([sys.executable,str(Path(broker.__file__)),'capabilities'],**kwargs)
            self.assertEqual(argv[:4],['sudo','-n',broker_path,'http'])
            spec=json.loads(kwargs['input']);self.broker_calls.append(spec)
            broker.http_spec(spec)
            route=spec['ssrf'] or {}
            broker.authorize_resource(self.scope['policy'],'ssrf' if route else 'http',spec['target'],
                scheme=spec['scheme'],hostname=spec['hostname'],port=spec['port'],path=spec['path'],
                destination=route.get('destination',''),context=route.get('context',''))
            self.assertEqual(spec['target'],'10.0.0.1')
            return real_run([sys.executable,str(driver),str(Path(broker.__file__).resolve().parents[1])],**kwargs)
        self.boundary=boundary
        broker_path='/usr/local/sbin/pm-netguard'
        for replacement in (patch.object(self.server,'ASSET_DB',self.case.database),
                patch.object(self.server,'CAPABILITY_LOG',actions.CAPABILITY_LOG),
                patch.object(artifacts,'ROOT',self.case.root/'http'),patch.object(subprocess,'run',side_effect=boundary)):
            replacement.start();self.addCleanup(replacement.stop)

    def configure(self,**kwargs):
        self.scope=resources.resolve(self.url+'/',addresses=['10.0.0.1'],aliases=['alias.lab'],
            ssrf=[self.inner_url+'/private'],deny=[self.url+'/private'],**kwargs)
        with self.case.connect() as db:
            db.execute('UPDATE pm_operator_approvals SET allowed=? WHERE task_id=11',(','.join(resources.grants(self.scope['policy'])),))
            resources.save(db,11,self.scope)
            self.scope['policy']=resources.saved(db,11)['policy']

    def call(self,path='/echo',session='default',**request):
        return self.tool('pm_http_request',request_json=json.dumps({'url':self.url+path,**request}),session_id=session)

    def tool(self,name,**arguments):
        result=asyncio.run(self.server.mcp.call_tool(name,{'task_id':11,**arguments}))
        blocks=result[0] if isinstance(result,tuple) else result
        return json.loads(next(b.text for b in blocks if getattr(b,'type',None)=='text'))

    def test_real_post_query_custom_headers_and_originals(self):
        reply=self.call('/echo?existing=1#browser',method='POST',query=[['q','a/b'],['q','second']],
            headers={'X-Test':'offline'},json={'hello':'мир'})
        self.assertEqual(reply['status'],'completed',reply)
        self.assertEqual(self.requests[0]['path'],'/echo?existing=1&q=a%2Fb&q=second')
        self.assertEqual(self.requests[0]['method'],'POST');self.assertEqual(self.requests[0]['headers']['X-Test'],'offline')
        wire=self.tool('pm_http_read',exchange_id=reply['exchange_id'],part='request')
        self.assertIn('мир'.encode(),base64.b64decode(wire['data_b64']))
        self.assertEqual(wire['sha256'],hashlib.sha256(base64.b64decode(wire['data_b64'])).hexdigest())

    def test_cookie_login_session_isolated_and_persists_restart(self):
        first=self.call('/login',method='POST',form={'username':'student','password':'candidate'})
        self.assertEqual(first['server_outcome'],'uninterpreted; HTTP status does not establish authentication or goal success')
        self.call('/echo');self.call('/echo',session='other')
        self.assertEqual(self.requests[1]['headers']['Cookie'],'sid=accepted')
        self.assertNotIn('Cookie',self.requests[2]['headers'])
        with self.case.connect() as db:
            _,state,_=http_client.session_state(db,11,'default');self.assertEqual(state['cookies'][0]['value'],'accepted')
        self.call('/echo')
        self.assertEqual(self.requests[-1]['headers']['Cookie'],'sid=accepted')

    def test_fresh_same_url_and_saved_read_are_different_operations(self):
        a=self.call('/current');b=self.call('/current')
        self.assertEqual((a['stdout'],b['stdout']),('1','2'))
        before=len(self.requests)
        data=self.tool('pm_http_read',exchange_id=a['exchange_id'])
        self.assertEqual(base64.b64decode(data['data_b64']),b'1');self.assertFalse(data['fresh_observation'])
        self.assertEqual(len(self.requests),before)

    def test_multipart_uses_task_file_and_does_not_repeat_from_new_boundary(self):
        work=actions.TASK_WORK_BASE/'11';work.mkdir(parents=True,exist_ok=True);(work/'proof.bin').write_bytes(b'\x00OFFLINE\xff')
        args={'method':'POST','form':{'title':'proof'},'files':[{'field':'upload','path':'/work/proof.bin'}]}
        reply=self.call('/echo',**args);self.assertEqual(reply['status'],'completed',reply)
        self.assertIn(b'\x00OFFLINE\xff',self.requests[0]['body']);self.assertIn(b'name="title"',self.requests[0]['body'])
        repeated=self.call('/echo',**args)
        self.assertEqual(repeated['status'],'blocked');self.assertEqual(len(self.requests),1)

    def test_auto_redirect_preserves_query_and_has_original_chain(self):
        reply=self.call('/redirect')
        self.assertEqual(reply['status'],'completed',reply);self.assertEqual(len(reply['chain']),2)
        self.assertEqual([r['path'] for r in self.requests],['/redirect','/current?q=redirect'])
        for eid in reply['chain']:self.assertEqual(self.tool('pm_http_read',exchange_id=eid,part='response')['status'],'completed')

    def test_redirect_cannot_expand_scope(self):
        reply=self.call('/outside')
        self.assertEqual(reply['stop_reason'],'redirect_outside_scope');self.assertEqual(self.inner_hits,[])
        self.assertEqual(len(self.requests),1)

    def test_303_changes_post_to_get_but_307_preserves_body(self):
        a=self.call('/post-redirect',method='POST',body='first');b=self.call('/keep-method',method='POST',body='second')
        self.assertEqual(a['status'],'completed',a);self.assertEqual(b['status'],'completed',b)
        self.assertEqual([(r['method'],r['body']) for r in self.requests],[('POST',b'first'),('GET',b''),('POST',b'second'),('POST',b'second')])

    def test_actual_transport_accepts_headers_above_curl_limit_but_caps_one_mib(self):
        good=self.call('/large-header');bad=self.call('/too-large-header')
        self.assertEqual(good['status'],'completed',good)
        saved=self.tool('pm_http_read',exchange_id=good['exchange_id'],part='response',limit=65536)
        self.assertGreater(saved['bytes'],900*1024);self.assertTrue(saved['has_more'])
        self.assertEqual(bad['status'],'incomplete',bad);self.assertFalse(bad['transport_complete'])

    def test_body_limit_saves_partial_separately_and_marks_incomplete(self):
        reply=self.call('/large-body')
        self.assertEqual(reply['status'],'incomplete',reply);self.assertTrue(reply['body_truncated'])
        saved=self.tool('pm_http_read',exchange_id=reply['exchange_id']);self.assertEqual(saved['bytes'],2*1024*1024)
        self.assertLessEqual(len(reply['stdout']),4096)

    def test_ssrf_via_local_application_get_and_form_with_explicit_route(self):
        a=self.call('/fetch',ssrf={'destination':self.inner_url+'/private'})
        b=self.call('/fetch',method='POST',ssrf={'destination':self.inner_url+'/private','location':'form'})
        self.assertEqual(a['status'],'completed',a);self.assertEqual(b['status'],'completed',b)
        self.assertEqual(self.inner_hits,['/private','/private'])
        self.assertEqual(len(self.broker_calls),2)
        with self.case.connect() as db:
            _,meta=artifacts.load(db,11,a['artifact_id'])
            self.assertIn('unverified',meta['route']['destination_contact'])
        denied=self.call('/fetch',ssrf={'destination':self.inner_url+'/elsewhere'})
        self.assertEqual(denied['status'],'blocked');self.assertEqual(len(self.inner_hits),2)

    def test_traversal_allowed_but_explicit_room_exclusion_and_password_change_block(self):
        reply=self.call('/a/../../etc/passwd?file=..%2Fsecret')
        self.assertEqual(reply['status'],'completed',reply)
        self.assertEqual(self.requests[0]['path'],'/a/../../etc/passwd?file=..%2Fsecret')
        for path in ('/private','/a/%2e%2e/private'):
            self.assertEqual(self.call(path)['status'],'blocked')
        self.assertEqual(self.call(method='POST',form={'new_password':'not allowed'})['status'],'blocked')
        self.assertEqual(self.call('/change-password')['status'],'completed') # read form, do not submit
        self.assertEqual(self.call('/change-password',method='POST')['status'],'blocked')
        self.assertEqual(self.call('/echo?new_password=not_allowed')['status'],'blocked')
        self.assertEqual(len(self.requests),2)

    def test_403_is_transport_completed_without_login_or_goal_claim(self):
        reply=self.call('/denied')
        self.assertEqual(reply['status'],'completed',reply);self.assertEqual(reply['status_code'],403)
        self.assertIn('uninterpreted',reply['server_outcome'])

    def test_reflected_body_is_not_new_flag_evidence(self):
        flag='THM{offline_reflected_payload}'
        reply=self.call('/reflect',method='POST',body=flag)
        self.assertEqual(reply['status'],'completed',reply)
        with self.case.connect() as db:
            registry=flag_verify.scan(11,db=db)
            self.assertEqual(registry['confirmed'],[])

    def test_diagnostics_do_not_dump_session_credentials(self):
        with diagnostics.run('local HTTP',11):
            self.call(auth={'type':'bearer','token':'OFFLINE_HTTP_SECRET'},cookies={'sid':'OFFLINE_COOKIE_SECRET'})
            events=json.dumps(diagnostics.read_events())
        self.assertNotIn('OFFLINE_HTTP_SECRET',events);self.assertNotIn('OFFLINE_COOKIE_SECRET',events)

    def test_methods_json_null_binary_and_distinct_bodies_are_not_url_cached(self):
        for method in ('PUT','PATCH','DELETE','OPTIONS','HEAD'):
            self.assertEqual(self.call(method=method)['status'],'completed')
        self.call(method='POST',json=None)
        self.assertEqual(self.requests[-1]['body'],b'null')
        self.call(method='POST',body_b64=base64.b64encode(b'\x00\xff').decode())
        self.assertEqual(self.requests[-1]['body'],b'\x00\xff')
        self.call(method='POST',body='different')
        self.assertEqual(len(self.requests),8)

    def test_one_mib_total_headers_is_accepted_exactly(self):
        reply=self.call('/exact-header');self.assertEqual(reply['status'],'completed',reply)
        saved=self.tool('pm_http_read',exchange_id=reply['exchange_id'],part='response')
        self.assertEqual(saved['bytes'],broker.HTTP_HEADER_LIMIT+2)

    def test_redirect_cross_origin_does_not_forward_auth_cookie_or_secret_header(self):
        reply=self.call('/alias',auth={'type':'bearer','token':'OFFLINE_CROSS_SECRET'},
            cookies={'sid':'OFFLINE_CROSS_COOKIE'},headers={'X-Secret':'private'})
        self.assertEqual(reply['status'],'completed',reply)
        self.assertIn('Authorization',self.requests[0]['headers'])
        for key in ('Authorization','Cookie','X-Secret'):self.assertNotIn(key,self.requests[1]['headers'])
        self.call('/echo')
        self.assertEqual(self.requests[-1]['headers']['Authorization'],'Bearer OFFLINE_CROSS_SECRET')

    def test_timeout_after_real_post_does_not_reexecute_after_resume(self):
        def lost(argv,**kw):
            if argv==['/usr/local/sbin/pm-netguard','capabilities']:return self.boundary(argv,**kw)
            self.boundary(argv,**kw)
            raise subprocess.TimeoutExpired('offline HTTP reply lost',30)
        with patch.object(subprocess,'run',side_effect=lost):reply=self.call(method='POST',body='only once')
        self.assertEqual(reply['status'],'unknown',reply)
        self.assertEqual(self.call(method='POST',body='only once')['status'],'blocked')
        self.assertEqual(len(self.requests),1)
        self.assertEqual(self.call('/current')['status'],'completed')

    def test_injected_and_genuine_same_url_flag_sources_are_not_merged(self):
        flag='THM{offline_same_url_flag}'
        injected=self.call('/same-flag',method='POST',body=flag)
        with self.case.connect() as db:self.assertEqual(flag_verify.scan(11,db=db)['confirmed'],[])
        real=self.call('/same-flag')
        with self.case.connect() as db:
            proof=flag_verify.scan(11,db=db)['candidates'][0]['verified_evidence']
            self.assertEqual([p['capture_ref'] for p in proof],[real['artifact_ref']])
        self.assertNotEqual(injected['artifact_id'],real['artifact_id'])

    def test_cookie_path_and_secure_and_header_framing_are_checked(self):
        self.call('/cookie-path');self.call('/echo');self.call('/other')
        self.assertEqual(self.requests[1]['headers'].get('Cookie'),'limited=path')
        self.assertNotIn('Cookie',self.requests[2]['headers'])
        before=len(self.requests)
        for headers in ({'X-Bad':'a\r\nInjected: true'}, {'Host':'outside.invalid'}, {'Transfer-Encoding':'chunked'}):
            self.assertEqual(self.call(headers=headers)['status'],'blocked')
        self.assertEqual(self.call(method='CONNECT')['status'],'blocked')
        self.assertEqual(len(self.requests),before)

    def test_password_change_guard_checks_structured_fields_not_file_contents(self):
        work=actions.TASK_WORK_BASE/'11';work.mkdir(parents=True,exist_ok=True)
        (work/'notes.txt').write_text('example code: {"new_password":"not executed"}')
        files=[{'field':'upload','path':'/work/notes.txt'}]
        self.assertEqual(self.call(method='POST',files=files)['status'],'completed')
        for request in ({'json':{'account':{'newPassword':'prohibited'}}},{'form':{'new_password':'prohibited'},'files':files}):
            self.assertEqual(self.call(method='POST',**request)['status'],'blocked')
        self.assertEqual(len(self.requests),1)

    def test_ssrf_json_parameter_uses_the_same_real_application_transport(self):
        reply=self.call('/fetch',method='POST',ssrf={'destination':self.inner_url+'/private','location':'json'})
        self.assertEqual(reply['status'],'completed',reply)
        self.assertEqual(json.loads(self.requests[0]['body'])['url'],self.inner_url+'/private')
        self.assertEqual(self.inner_hits,['/private'])

    def test_original_chunk_framing_and_decoded_entity_are_saved_separately(self):
        reply=self.call('/chunked');self.assertEqual(reply['status'],'completed',reply)
        response=base64.b64decode(self.tool('pm_http_read',exchange_id=reply['exchange_id'],part='response')['data_b64'])
        self.assertIn(b'3\r\nabc\r\n2\r\nde\r\n0\r\nX-Trailer: saved',response)
        body=base64.b64decode(self.tool('pm_http_read',exchange_id=reply['exchange_id'],part='body')['data_b64'])
        self.assertEqual(body,b'abcde')
        broken=self.call('/broken-chunks');self.assertEqual(broken['status'],'incomplete',broken)

    def test_session_rename_or_response_limit_does_not_replay_identical_post(self):
        first=self.call(method='POST',body='once',session='original')
        self.assertEqual(first['status'],'completed',first)
        self.assertEqual(self.call(method='POST',body='once',session='renamed')['status'],'blocked')
        with self.case.connect() as db:artifacts.set_response_limit(db,11,artifacts.MAX_BODY,'offline policy change')
        self.assertEqual(self.call(method='POST',body='once',session='original')['status'],'blocked')
        self.assertEqual(len(self.requests),1)


if __name__=='__main__':unittest.main()
