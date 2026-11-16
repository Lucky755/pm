"""Real HTTP forward proxy / CONNECT sockets; NOT a live Burp Professional test."""
import base64
import asyncio
import importlib.util
import json
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import select
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from urllib.parse import urlsplit
from unittest.mock import patch

from executor import netguard_root as broker
from orchestrator import agent_actions,resources,http_artifacts
from tests import test_coordinated_attack as fixture


class ProxyTransportTests(unittest.TestCase):
    def setUp(self):
        self.requests=[];self.proxy_requests=[];self.sni=[];owner=self
        class Target(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):self.do_POST()
            def do_POST(self):
                body=self.rfile.read(int(self.headers.get('Content-Length',0)))
                owner.requests.append((self.command,self.path,dict(self.headers),body))
                if self.path.startswith('/redirect'):
                    self.send_response(302);self.send_header('Location','/destination');self.send_header('Content-Length','0');self.end_headers();return
                response=b'actual target bytes: '+body
                self.send_response(200);self.send_header('Content-Length',str(len(response)));self.end_headers();self.wfile.write(response)
        self.target=self.server(Target)
        class Proxy(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):self.do_POST()
            def do_POST(self):
                uri=urlsplit(self.path)
                if uri.hostname not in ('127.0.0.1','10.0.0.1') or uri.port!=owner.target.server_port:
                    self.send_error(403);return
                owner.proxy_requests.append((self.command,self.path,dict(self.headers)))
                body=self.rfile.read(int(self.headers.get('Content-Length',0)))
                headers={k:v for k,v in self.headers.items() if k.lower()!='x-pentest-master-scope'}
                connection=http.client.HTTPConnection('127.0.0.1',uri.port,timeout=3)
                try:
                    connection.request(self.command,uri.path+('?' +uri.query if uri.query else ''),body,headers)
                    response=connection.getresponse();raw=response.read()
                    self.send_response(response.status);self.send_header('Content-Length',str(len(raw)))
                    if response.getheader('Location'):self.send_header('Location',response.getheader('Location'))
                    self.end_headers();self.wfile.write(raw)
                finally:connection.close()
            def do_CONNECT(self):
                host,port=self.path.rsplit(':',1)
                if host!='127.0.0.1' or int(port)!=owner.tls.server_port:
                    self.send_error(403);return
                owner.proxy_requests.append((self.command,self.path,dict(self.headers)))
                with socket.create_connection((host,int(port)),timeout=3) as upstream:
                    self.send_response(200);self.end_headers();self.wfile.flush()
                    endpoints=[self.connection,upstream]
                    while True:
                        ready,_,_=select.select(endpoints,[],[],4)
                        if not ready:return
                        for source in ready:
                            data=source.recv(65536)
                            if not data:return
                            (upstream if source is self.connection else self.connection).sendall(data)
        self.proxy=self.server(Proxy)
        self.temporary=tempfile.TemporaryDirectory(prefix='pm-proxy-contract-');self.addCleanup(self.temporary.cleanup)
        self.directory=Path(self.temporary.name)
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=app.lab',
            '-addext','subjectAltName=DNS:app.lab','-keyout',str(self.directory/'key.pem'),'-out',str(self.directory/'ca.pem')],
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.tls=ThreadingHTTPServer(('127.0.0.1',0),Target)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(self.directory/'ca.pem',self.directory/'key.pem')
        context.set_servername_callback(lambda connection,name,ctx:owner.sni.append(name))
        self.tls.socket=context.wrap_socket(self.tls.socket,server_side=True)
        self.start(self.tls)

    def start(self,server):
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        return server

    def server(self,handler):return self.start(ThreadingHTTPServer(('127.0.0.1',0),handler))

    def spec(self,tls=False):
        return broker.http_spec({'method':'POST','target':'127.0.0.1','scheme':'https' if tls else 'http','hostname':'app.lab',
            'port':self.tls.server_port if tls else self.target.server_port,'path':'/form?q=kept','headers':[['Cookie','sid=alice']],
            'body_b64':base64.b64encode(b'form body').decode(),'session_id':'browser-contract','limit_bytes':2*1024*1024,
            'timeout':5,'tls_verify':True,'ssrf':None,'proxy':'burp'})

    def test_pinned_forward_proxy_with_original_virtual_host_and_body(self):
        spec=self.spec();grant,nonce=broker.burp_grant(spec,'offline-secret')
        reply=broker.http_transport(spec,{'port':self.proxy.server_port,'grant':grant,'nonce':nonce,'instance_id':'contract-proxy'})
        self.assertTrue(reply['transport_complete'],reply)
        self.assertEqual(base64.b64decode(reply['body_b64']),b'actual target bytes: form body')
        self.assertTrue(self.proxy_requests[0][1].startswith('http://127.0.0.1:'))
        self.assertEqual(self.requests[0][2]['Host'],'app.lab:'+str(self.target.server_port))
        self.assertNotIn('X-Pentest-Master-Scope',self.requests[0][2])
        self.assertEqual(self.requests[0][3],b'form body');self.assertEqual(reply['transport_proxy'],'burp')

    def test_connect_pins_ip_and_verifies_certificate_with_original_sni(self):
        spec=self.spec(True);grant,nonce=broker.burp_grant(spec,'offline-secret')
        reply=broker.http_transport(spec,{'port':self.proxy.server_port,'grant':grant,'nonce':nonce,'ca':str(self.directory/'ca.pem')})
        self.assertTrue(reply['transport_complete'],reply)
        self.assertEqual(self.proxy_requests[0][0:2],('CONNECT','127.0.0.1:'+str(self.tls.server_port)))
        self.assertEqual(self.sni,['app.lab'])

    def test_proxy_requires_explicit_configuration(self):
        with self.assertRaisesRegex(ValueError,'not configured'):broker.http_transport(self.spec())
        self.assertEqual(self.requests,[]);self.assertEqual(self.proxy_requests,[])

    def test_public_http_retains_proxy_on_redirect_and_does_not_repeat_by_switching_transport(self):
        case=fixture.CoordinatorTests();case.setUp();self.addCleanup(case.doCleanups)
        url=f'http://app.lab:{self.target.server_port}'
        with case.connect() as db:resources.save(db,11,resources.resolve(url+'/',addresses=['10.0.0.1']))
        module=importlib.util.spec_from_file_location('burp_proxy_mcp',Path(broker.__file__).resolve().parents[1]/'mcp/server.py')
        server=importlib.util.module_from_spec(module);module.loader.exec_module(server)
        original_run=subprocess.run;http_calls=[]
        def boundary(argv,**kw):
            if argv==['/usr/local/sbin/pm-netguard','capabilities']:
                return original_run([__import__('sys').executable,str(Path(broker.__file__)),'capabilities'],**kw)
            self.assertEqual(argv[:3],['sudo','-n','/usr/local/sbin/pm-netguard'])
            if argv[3]=='burp-read':
                value={'status':'running','protocol':3,'edition':'PROFESSIONAL','guarded_proxy':True,'instance_id':'offline-proxy-contract'}
            else:
                self.assertEqual(argv[3],'http');spec=json.loads(kw['input']);http_calls.append(spec)
                self.assertEqual(spec['proxy'],'burp')
                grant,nonce=broker.burp_grant(spec,'offline-secret')
                value=broker.http_transport(spec,{'port':self.proxy.server_port,'grant':grant,'nonce':nonce})
            return subprocess.CompletedProcess(argv,0,json.dumps(value),'')
        def invoke(request):
            result=asyncio.run(server.mcp.call_tool('pm_http_request',{'task_id':11,'request_json':json.dumps(request)}))
            blocks=result[0] if isinstance(result,tuple) else result
            return json.loads(next(b.text for b in blocks if getattr(b,'type',None)=='text'))
        with patch.object(server,'ASSET_DB',case.database),patch.object(server,'CAPABILITY_LOG',agent_actions.CAPABILITY_LOG), \
             patch.object(http_artifacts,'ROOT',case.root/'http'),patch.object(subprocess,'run',side_effect=boundary):
            reply=invoke({'url':url+'/redirect','proxy':'burp'})
            self.assertEqual(reply['status'],'completed',reply);self.assertEqual(len(reply['chain']),2)
            self.assertEqual([s['path'] for s in http_calls],['/redirect','/destination'])
            self.assertEqual(invoke({'url':url+'/submit','method':'POST','body':'once','proxy':'burp'})['status'],'completed')
            before=len(http_calls)
            repeated=invoke({'url':url+'/submit','method':'POST','body':'once'})
            self.assertEqual(repeated['status'],'blocked',repeated);self.assertEqual(len(http_calls),before)


if __name__=='__main__':unittest.main()
