"""Real Chromium/Playwright + real Unix IPC + local JS/CSRF application.

Only privileged namespace/broker setup is replaced. No fake page, browser,
socket objects, HTTP responses or artifact persistence.
"""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from unittest.mock import patch

from executor import netguard_root as root
from orchestrator import agent_actions,resources,task_sessions,browser,task_memory,diagnostics
from orchestrator import http_artifacts as artifacts
from tests import test_coordinated_attack as fixture

ROOT=Path(__file__).resolve().parents[1]


class BrowserRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.records=[];self.children=[];self.tokens={};owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def reply(self,status,body,headers=(),ctype='text/html'):
                self.send_response(status);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(body)))
                for k,v in headers:self.send_header(k,v)
                self.end_headers();self.wfile.write(body)
            def do_GET(self):
                owner.records.append((self.command,self.path,self.headers.get('Cookie','')))
                if self.path=='/csrf':
                    token='csrf-'+str(len(owner.tokens));sid='anonymous-'+str(len(owner.tokens));owner.tokens[sid]=token
                    self.reply(200,json.dumps({'csrf':token}).encode(),[('Set-Cookie',f'sid={sid}; Path=/; HttpOnly'),('Set-Cookie','hint=ready; Path=/')],'application/json')
                elif self.path=='/account':
                    cookie=self.headers.get('Cookie','');user='alice' if 'user-alice' in cookie else 'bob' if 'user-bob' in cookie else 'anonymous'
                    self.reply(200,('<div id="account">Hello '+user+'</div>').encode())
                elif self.path=='/outside':
                    self.reply(200,b'<div id="result"></div><script>fetch("http://outside.invalid/private").then(()=>result.textContent="bad").catch(()=>result.textContent="blocked")</script>')
                elif self.path=='/redirect':
                    self.reply(302,b'',[('Location','http://outside.invalid/private')])
                elif self.path=='/local-redirect':
                    self.reply(302,b'',[('Location','/account')])
                else:
                    self.reply(200,b'''<form id="login"><input id="user"><input id="password" type="password"><input id="csrf" type="hidden"><button id="submit">Login</button></form><div id="ready"></div>
<script>localStorage.setItem('javascript','ran');fetch('/csrf').then(r=>r.json()).then(data=>{document.querySelector('#csrf').value=data.csrf;ready.textContent='ready';});
login.addEventListener('submit',async e=>{e.preventDefault();let r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user.value,password:password.value,csrf:csrf.value})});let data=await r.json();if(data.ok)location.href='/account';else ready.textContent='denied';});</script>''')
            def do_POST(self):
                data=json.loads(self.rfile.read(int(self.headers['Content-Length'])));cookie=self.headers.get('Cookie','')
                owner.records.append((self.command,self.path,cookie))
                valid=any(sid in cookie and token==data.get('csrf') for sid,token in owner.tokens.items()) and data.get('password')=='candidate'
                if valid:
                    self.reply(200,b'{"ok":true}',[('Set-Cookie','sid=user-'+data['username']+'; Path=/; HttpOnly')],'application/json')
                else:self.reply(403,b'{"ok":false}',ctype='application/json')
        self.http=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.addCleanup(self.http.server_close);self.addCleanup(self.http.shutdown)
        threading.Thread(target=self.http.serve_forever,daemon=True).start()
        self.url=f'http://app.lab:{self.http.server_port}'
        self.s=self.case.root/'s';self.s.mkdir(mode=0o700)
        self.work=agent_actions.TASK_WORK_BASE/'11';self.work.mkdir(parents=True,mode=0o700)
        self.base=self.case.root/'broker';self.base.mkdir(mode=0o700)
        scope=resources.resolve(self.url+'/',addresses=['10.0.0.1'])
        with self.case.connect() as db:
            resources.save(db,11,scope);scope['policy']=resources.saved(db,11)['policy']
        self.config={'uid':os.getuid(),'gid':os.getgid(),'owner':'offline','allowed':['10.0.0.1/32'],
            'resource_policy':scope['policy'],'browser':{'runtime':str(ROOT/'.venv'),'chromium':'/usr/lib/chromium/chromium'}}
        (self.case.root/'config.json').write_text(json.dumps(self.config))
        self.driver=self.case.root/'worker.py'
        self.driver.write_text('''import sys,json,os
from pathlib import Path
sys.path.insert(0,sys.argv[1]);from executor import netguard_root as b
root=Path(sys.argv[2]);mode=sys.argv[3]
config=json.loads((root/'config.json').read_text());b.ensure_root=lambda:None
b.owned_config=lambda task:({'name':'offline'},config)
b.session_dir=lambda task:root/'s'
b.task_workdir=lambda task,c:root/'work'/'11'
b.browser_engine_command=lambda task,c:[sys.executable,str(root/'worker.py'),sys.argv[1],str(root),'browser-engine']
if mode=='browser-worker':b.browser_worker(11,sys.argv[sys.argv.index('--session-id')+1])
else:
 original=sys.stdin
 class Input:
  first=True
  def readline(self,*a):
   if not self.first:return original.readline(*a)
   self.first=False
   value=json.loads(original.readline());value['directory']=str(root/'work'/'11')+value['directory'].removeprefix('/work');return json.dumps(value)+'\\n'
  def __iter__(self):return iter(original)
 sys.stdin=Input();b.browser_engine()
''')
        original_popen=subprocess.Popen;original_run=subprocess.run;realpath=os.path.realpath
        def spawn(argv,**kw):
            if argv[0]=='/usr/local/sbin/pm-netguard' and argv[1]=='browser-worker':
                child=original_popen([sys.executable,str(self.driver),str(ROOT),str(self.case.root),*argv[1:]],**kw)
                self.children.append(child);return child
            return original_popen(argv,**kw)
        def http(task,spec):
            # Same logical target mapped to an actual loopback socket; this is
            # the namespace/privilege boundary, not a mocked HTTP response.
            connect=socket.create_connection
            def local(address,*a,**kw):
                self.assertEqual(address[0],'10.0.0.1');return connect(('127.0.0.1',address[1]),*a,**kw)
            with patch.object(socket,'create_connection',side_effect=local):return root.http_transport(spec)
        def execute(argv,**kw):
            if argv[:3]!=['sudo','-n','/usr/local/sbin/pm-netguard']:return original_run(argv,**kw)
            def arg(key,default=''):return argv[argv.index('--'+key)+1] if '--'+key in argv else default
            action=arg('action');sid=arg('session-id');uid=arg('owner');pid=int(arg('owner-pid','0'))
            if argv[3]=='browser':
                value=json.loads(kw.get('input','{}'))
                if action=='open':reply=root.browser_open(11,value,uid,pid)
                elif action=='restore':reply=root.browser_restore(11,sid,uid,pid)
                else:reply=root.browser_action(11,sid,value,uid,pid,int(arg('max-requests','0')))
            elif argv[3]=='session':
                if action=='list':reply=root.session_list(11)
                elif action=='close':reply=root.session_close(11,sid,uid,pid)
                else:reply=root.session_access(11,sid,action,owner=uid,owner_pid=pid)
            else:raise AssertionError(argv)
            return subprocess.CompletedProcess(argv,0,json.dumps(reply),'')
        module=importlib.util.spec_from_file_location('browser_runtime_mcp',ROOT/'mcp/server.py')
        self.server=importlib.util.module_from_spec(module);module.loader.exec_module(self.server)
        for replacement in (patch.object(root,'BASE',self.base),patch.object(root,'ensure_root'),
            patch.object(root,'owned_config',return_value=({'name':'offline'},self.config)),
            patch.object(root,'session_dir',return_value=self.s),patch.object(root,'task_workdir',return_value=self.work),
            patch.object(root,'http_run',side_effect=http),patch.object(subprocess,'Popen',side_effect=spawn),
            patch.object(subprocess,'run',side_effect=execute),
            patch.object(os.path,'realpath',side_effect=lambda value,*a,**kw:'/usr/local/sbin/pm-netguard' if str(value)==sys.argv[0] else realpath(value,*a,**kw)),
            patch.object(self.server,'ASSET_DB',self.case.database),patch.object(self.server,'CAPABILITY_LOG',agent_actions.CAPABILITY_LOG),
            patch.object(artifacts,'ROOT',self.case.root/'artifacts')):
            replacement.start();self.addCleanup(replacement.stop)
        self.addCleanup(self.stop)

    def stop(self):
        for meta in root.session_list(11)['sessions']:
            try:root.session_close(11,meta['session_id'],meta.get('owner',''),os.getpid())
            except (OSError,ValueError):pass
        for child in self.children:
            if child.poll() is None:child.terminate()
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:child.kill();child.wait()

    def call(self,tool='pm_browser',**args):
        result=asyncio.run(self.server.mcp.call_tool(tool,{'task_id':11,**args}))
        blocks=result[0] if isinstance(result,tuple) else result
        return json.loads(next(b.text for b in blocks if getattr(b,'type',None)=='text'))

    def open(self,user='alice',proxy=''):
        reply=self.call(action='open',url=self.url+'/',username=user,purpose='Offline JS login',proxy=proxy)
        if reply['status']!='opened':
            self.fail(str(reply)+'\n'+''.join(p.read_text(errors='replace')[-4000:] for p in self.s.glob('*.log')))
        self.assertEqual(reply['status'],'opened',reply);return reply['session_id']

    def control(self,sid,action,**kw):
        return self.call(action='control',session_id=sid,action_json=json.dumps({'action':action,**kw}))

    def login(self,sid,user='alice'):
        opened=self.control(sid,'open',url=self.url+'/')
        self.assertEqual(opened['status'],'completed',opened)
        self.control(sid,'wait',selector='#ready')
        self.control(sid,'fill',selector='#user',value=user)
        self.control(sid,'fill',selector='#password',value='candidate')
        self.control(sid,'click',selector='#submit')
        return self.control(sid,'wait',selector='#account')

    def test_actual_js_csrf_login_and_saved_network(self):
        with diagnostics.run('browser-smoke',task_id=11):
            sid=self.open();reply=self.login(sid)
            events=diagnostics.read_events()
            self.assertEqual(len({event['run_id'] for event in events}),1)
            self.assertTrue(any(e['kind']=='browser.end' and e.get('session_id')==sid for e in events))
            self.assertNotIn('candidate',json.dumps(events))
        self.assertEqual(reply['status'],'completed',reply);self.assertIn('Hello alice',reply['text'])
        self.assertTrue(any(method=='POST' for method,path,cookie in self.records))
        with self.case.connect() as db:
            self.assertGreaterEqual(db.execute('SELECT COUNT(*) FROM pm_http_exchanges WHERE task_id=11').fetchone()[0],3)
            saved=browser.observations(db,11,sid)
            self.assertEqual(saved[-1]['status'],'completed')
            original=task_memory.material(db,11,'browser_dom:'+str(saved[-1]['id']),agent_actions.CAPABILITY_LOG/'task_11.jsonl')
            self.assertIn(b'Hello alice',original)
            captures=[json.loads(line) for line in (agent_actions.CAPABILITY_LOG/'task_11.jsonl').read_text().splitlines()]
            captures=[r for r in captures if r.get('tool')=='http_capture']
            self.assertGreaterEqual(len(captures),3)
            for record in captures:
                self.assertTrue(record['result']['artifact_ref'].startswith('http_artifact:'))
        self.assertIn('not authentication',reply['interpretation'])

    def test_contexts_do_not_mix_users(self):
        a=self.open();self.login(a)
        b=self.open('bob');reply=self.control(b,'open',url=self.url+'/account')
        self.assertIn('anonymous',reply['text']);self.assertIn('alice',self.control(a,'read')['text'])

    def test_role_handoff_keeps_session_and_requires_observation(self):
        with self.case.connect() as db:
            with task_sessions.role_scope(db,11,'First role'):
                sid=self.open();self.assertIn('alice',self.login(sid)['text'])
            with task_sessions.role_scope(db,11,'Second role'):
                self.assertEqual(self.control(sid,'click',selector='#anything')['status'],'blocked')
                self.assertIn('alice',self.control(sid,'read')['text'])
        self.assertEqual(len(self.children),1)

    def test_outside_javascript_request_is_denied_and_saved_read_is_passive(self):
        sid=self.open();self.control(sid,'open',url=self.url+'/outside')
        reply=self.control(sid,'wait',selector='#result')
        self.assertIn('blocked',reply['text'])
        before=list(self.records)
        with self.case.connect() as db:rows=browser.observations(db,11,sid)
        self.assertTrue(rows);self.assertEqual(self.records,before)
        saved=self.call(tool='pm_browser_read',session_id=sid)
        self.assertEqual(saved['status'],'completed');self.assertEqual(saved['provenance'],'local')
        self.assertEqual(self.records,before)

    def test_redirect_is_checked_and_non_http_navigation_is_not_dispatched(self):
        sid=self.open();result=self.control(sid,'open',url=self.url+'/redirect')
        self.assertNotEqual(result['status'],'completed');self.assertTrue(result['network_denials'])
        self.assertEqual([path for _,path,_ in self.records],['/redirect'])
        self.assertEqual(self.control(sid,'open',url='file:///etc/passwd')['status'],'blocked')
        with self.assertRaises(ValueError):
            root.browser_action(11,sid,{'action':'open','url':'file:///etc/passwd'},'operator',os.getpid(),24)

    def test_in_scope_redirect_preserves_final_url_and_records_every_hop(self):
        sid=self.open();result=self.control(sid,'open',url=self.url+'/local-redirect')
        self.assertEqual(result['status'],'completed',result)
        self.assertEqual(result['observed_url'],self.url+'/account');self.assertIn('anonymous',result['text'])
        paths=[path for _,path,_ in self.records]
        self.assertEqual(paths[:2],['/local-redirect','/account'])
        self.assertTrue(set(paths[2:])<={'/favicon.ico'})
        self.assertGreaterEqual(len(result['network_result_ids']),2)

    def test_absent_burp_is_not_a_successful_proxy_session(self):
        reply=self.call(action='open',url=self.url+'/',username='alice',purpose='Burp absent',proxy='burp')
        self.assertNotEqual(reply['status'],'opened');self.assertEqual(self.children,[])

    def test_storage_failure_after_transport_is_not_a_pre_execution_refusal(self):
        sid=self.open();directory=artifacts._directory(11)
        # A real sparse file fills the actual task artifact quota. No mocked
        # saver/HTTP/browser, and no real disk allocation of 64 MiB is needed.
        with (directory/'quota-reservation').open('wb') as reserve:reserve.truncate(artifacts.MAX_TASK_BYTES)
        result=self.control(sid,'open',url=self.url+'/account')
        self.assertEqual(result['status'],'unknown',result)
        self.assertEqual(result['reason_category'],'capture_import_failed')
        self.assertEqual(result['execution_outcome'],'completed')
        self.assertTrue(self.records)
        receipt=root.tool_load(self.s/f'{sid}.browser-result')
        self.assertTrue(receipt['network'][0]['response']['transport_complete'])
        original=result['root_http_receipts'][0]
        before=root.browser_result(11,sid,original)
        self.control(sid,'read')
        self.assertEqual(root.browser_result(11,sid,original),before)
        with self.case.connect() as db:
            saved=next(r for r in browser.observations(db,11,sid) if r['id']==result['browser_action_id'])
            self.assertEqual(saved['status'],'unknown');self.assertEqual(saved['result']['execution_outcome'],'completed')

    def test_restore_retains_login_but_does_not_replay_navigation(self):
        sid=self.open();self.login(sid)
        # Simulate an engine/worker shutdown, retaining the root receipt, not
        # an explicit operator deletion of the session with action=close.
        root.session_request(root.session_meta(11,sid),{'op':'close'})
        self.children[0].wait(timeout=8)
        before=list(self.records)
        restored=self.call(action='restore',session_id=sid)
        self.assertEqual(restored['status'],'opened',restored)
        self.assertEqual(self.records,before)
        # Explicit fresh navigation, not a replay of the completed form submit.
        result=self.control(sid,'open',url=self.url+'/account')
        self.assertEqual(result['status'],'completed',result);self.assertIn('alice',result['text'])
        self.assertEqual(sum(method=='POST' for method,_,_ in self.records),1)

    def test_unknown_action_is_not_automatically_restored_or_repeated(self):
        sid=self.open();self.control(sid,'open',url=self.url+'/account')
        meta=root.session_meta(11,sid);meta['pending_unknown']=True
        root.tool_store(self.s/f'{sid}.json',meta)
        before=list(self.records)
        blocked=self.control(sid,'click',selector='#anything')
        self.assertEqual(blocked['status'],'blocked',blocked);self.assertEqual(self.records,before)
        self.assertIn('anonymous',self.control(sid,'read')['text'])
        # Reading a DOM is not evidence that a lost submission did not execute.
        self.assertTrue(root.session_meta(11,sid)['pending_unknown'])

    def test_busy_owner_and_unsafe_workspace_are_rejected_before_execution(self):
        sid=self.open();before=list(self.records)
        reply=root.browser_action(11,sid,{'action':'open','url':self.url+'/'},'another-agent',os.getpid(),24)
        self.assertEqual(reply['kind'],'session_busy');self.assertEqual(self.records,before)
        self.call(action='close',session_id=sid);self.children[0].wait(timeout=8)
        # A task-user symlink must not redirect the privileged profile creation.
        import shutil
        shutil.rmtree(self.work/'browser');(self.work/'browser').symlink_to(self.case.root/'elsewhere')
        with self.assertRaises(OSError):
            root.browser_open(11,{'url':self.url+'/','username':'bob','purpose':'symlink test','proxy':None},'operator',os.getpid())


if __name__=='__main__':unittest.main()
