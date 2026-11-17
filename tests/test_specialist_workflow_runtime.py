"""Real Harness -> real MCP stdio -> loopback HTTP and unprivileged OpenSSH.

Only provider (local fake SSE), task data/config and the namespace/broker
boundary are replaced. No mocked Harness, MCP client, session.run or SSH result.
"""
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from orchestrator import agent_actions as a,coordinated_attack as c,diagnostics as d,resources,task_memory,objectives,operator_questions,specialist_workflow
from tests import test_model_adapter_runtime as adapter_fixture
from tests.test_coordinated_runtime import MCP_ENTRY,strings
from tests.test_specialist_workflow import branch,awaiting
from tests.test_coordinated_attack import decision

ROOT=Path(__file__).resolve().parents[1]

MCP_BOUNDARY='''
from orchestrator import agent_actions as a,http_artifacts,material_processing
server.POC_ROOT=temporary/'pocs';server.ISOLATED_EXECUTOR=temporary/'executor_boundary.py'
a.CAPABILITY_LOG=temporary/'caps';a.DB_PATH=temporary/'tasks.db';a.TASK_WORK_BASE=temporary/'work'
http_artifacts.ROOT=temporary/'http';material_processing.ROOT=temporary/'materials'
import subprocess
real_run=subprocess.run
def boundary(argv,**kw):
    if argv==['/usr/local/sbin/pm-netguard','capabilities']:
        return real_run([sys.executable,str(project/'executor/netguard_root.py'),'capabilities'],**kw)
    if argv[:4]==['sudo','-n','/usr/local/sbin/pm-netguard','http']:
        return real_run([sys.executable,str(temporary/'http_worker.py'),str(project)],**kw)
    if len(argv)>1 and argv[1]==str(temporary/'executor_boundary.py'):
        return real_run(argv,**kw)
    raise AssertionError('Unexpected broker/external dispatch')
subprocess.run=boundary
server.mcp.run(transport='stdio')
'''


def tool_payload(body):
    message=[m for m in body['messages'] if m.get('role')=='tool'][-1]
    def walk(value):
        if isinstance(value,dict):
            if 'status' in value:yield value
            for item in value.values():yield from walk(item)
        elif isinstance(value,list):
            for item in value:yield from walk(item)
        elif isinstance(value,str):
            try:decoded=json.loads(value)
            except ValueError:return
            if decoded!=value:yield from walk(decoded)
    return next(walk(message['content']))


class SpecialistRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.host=adapter_fixture.AdapterRuntimeTests();self.host.setUp();self.addCleanup(self.host.doCleanups)
        self.root=self.host.root;self.case=self.host.case;self.release=threading.Event();self.addCleanup(self.release.set)
        self.user=pwd.getpwuid(os.getuid()).pw_name
        for name in ('host-key','client-key'):
            subprocess.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(self.root/name)],check=True,capture_output=True)
        self.private=(self.root/'client-key').read_text()
        self.web_hits=[]
        owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_GET(self):
                owner.web_hits.append(self.path)
                if self.path=='/key':body=('username='+owner.user+'\n'+owner.private+'\nuser.txt=LOCAL_PLATFORM_CANDIDATE\n').encode()
                else:
                    (owner.root/'web-continuation-started').write_text(str(time.monotonic()))
                    marker=owner.root/('goal-cancel-recorded' if getattr(owner,'mode','')=='goal' else 'ssh-completed')
                    deadline=time.monotonic()+12
                    while not marker.exists() and not owner.release.is_set() and time.monotonic()<deadline:time.sleep(.02)
                    # Guarantee cross-over: the SSH result must be committed
                    # before the web tool returns, not just the executor exited.
                    if getattr(owner,'mode','') in ('normal','same-role'):
                        while time.monotonic()<deadline:
                            log=a.CAPABILITY_LOG/'task_11.jsonl'
                            rows=list(task_memory.capability_records(11,log,'10.0.0.1'))
                            if any(r.get('tool')=='net_exec' and r.get('coordinator_step_id') for r in rows):break
                            time.sleep(.02)
                        else:raise AssertionError('SSH receipt was not committed during WEB work')
                    body=b'Independent web investigation continued while SSH was checked.'
                self.send_response(200);self.send_header('Content-Type','text/plain');self.send_header('Content-Length',str(len(body)));self.end_headers()
                try:self.wfile.write(body)
                except (BrokenPipeError,ConnectionResetError):pass
        self.http=ThreadingHTTPServer(('127.0.0.1',0),Handler);self.addCleanup(self.http.server_close);self.addCleanup(self.http.shutdown)
        threading.Thread(target=self.http.serve_forever,daemon=True).start()
        self.url=f'http://app.lab:{self.http.server_port}'
        sock=socket.socket();sock.bind(('127.0.0.1',0));self.ssh_port=sock.getsockname()[1];sock.close()
        conf=self.root/'sshd.conf'
        conf.write_text(f'''Port {self.ssh_port}
ListenAddress 127.0.0.1
HostKey {self.root/'host-key'}
PidFile {self.root/'sshd.pid'}
AuthorizedKeysFile {self.root/'client-key.pub'}
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
AllowUsers {self.user}
LogLevel VERBOSE
''')
        self.sshlog=(self.root/'sshd.stderr').open('wb');self.addCleanup(self.sshlog.close)
        self.sshd=subprocess.Popen(['/usr/sbin/sshd','-D','-e','-f',str(conf)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=self.sshlog)
        self.addCleanup(self.stop_sshd)
        for _ in range(50):
            if self.sshd.poll() is not None:self.fail('Local unprivileged sshd failed: '+(self.root/'sshd.stderr').read_text())
            try:
                with socket.create_connection(('127.0.0.1',self.ssh_port),timeout=.1):break
            except OSError:time.sleep(.03)
        else:self.fail('Local sshd did not start')
        config=resources.resolve(self.url+'/',area='host',addresses=['10.0.0.1'])
        with self.case.connect() as db:
            resources.save(db,11,config)
            db.execute('UPDATE pm_tcp_full_scans SET open_ports_json=?',(json.dumps([22,self.http.server_port]),))
        self.host.entry.write_text(MCP_ENTRY[:MCP_ENTRY.index('def denied(')]+MCP_BOUNDARY)
        (self.root/'http_worker.py').write_text('''import sys,socket
sys.path.insert(0,sys.argv[1])
from executor import netguard_root as b
connect=socket.create_connection
def local(address,*args,**kw):
 if address[0]!='10.0.0.1':raise ValueError('Outside fixture')
 return connect(('127.0.0.1',address[1]),*args,**kw)
socket.create_connection=local
sys.argv=['pm-netguard','http-worker'];b.main()
''')
        self.logical=['/usr/bin/ssh','-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=no',
            '-o','UserKnownHostsFile=/dev/null','-i','/work/poc/id.txt','-p','22',self.user+'@10.0.0.1','/usr/bin/id']
        (self.root/'fixture.json').write_text(json.dumps({'argv':self.logical,'port':self.ssh_port,'user':self.user}))
        (self.root/'executor_boundary.py').write_text('''import json,sys,time,subprocess
from pathlib import Path
root=Path(__file__).parent;spec=json.loads((root/'fixture.json').read_text());args=sys.argv
assert args[1]=='run' and args[args.index('--profile')+1]=='exec'
assert json.loads(args[args.index('--argv-json')+1])==spec['argv']
deadline=time.monotonic()+10
while not (root/'web-continuation-started').exists() and time.monotonic()<deadline:time.sleep(.02)
assert (root/'web-continuation-started').exists()
(root/'ssh-started').write_text(str(time.monotonic()))
argv=spec['argv'][:];argv[argv.index('-i')+1]=str(root/'pocs/task_11/id.txt');argv[argv.index('-p')+1]=str(spec['port']);argv[-2]=spec['user']+'@127.0.0.1'
result=subprocess.run(argv,capture_output=True,text=True,timeout=10,stdin=subprocess.DEVNULL)
(root/'ssh-completed').write_text(str(time.monotonic()))
print(json.dumps({'status':'completed','task_id':11,'target':'10.0.0.1','exit_code':result.returncode,'stdout':result.stdout,'stderr':result.stderr,'network_contact':True}))
''')

    def stop_sshd(self):
        if self.sshd.poll() is None:self.sshd.terminate()
        try:self.sshd.wait(3)
        except subprocess.TimeoutExpired:self.sshd.kill();self.sshd.wait()

    def run_chain(self,mode='normal'):
        self.mode=mode;self.chosen=[];self.observer_errors=[];self.prompts=[]
        if mode=='goal':
            with self.case.connect() as db:objectives.save_objectives(db,11,'user.txt',expected_flags=1)
        def responder(body):
            self.assertEqual(body['model'],'glm-5.3-uncensored')
            prompts=[s for m in body['messages'] if m.get('role')=='user' for s in strings(m.get('content'))]
            prompt=next(s for s in prompts if s.startswith(('You coordinate','You are the')))
            self.prompts.append(prompt)
            if prompt.startswith('You coordinate'):
                self.assertFalse(body.get('tools'));state=json.loads(prompt.rsplit('\n',1)[1]);active=state.get('active_specialists',[])
                candidates=[r for r in state['references'] if r.startswith('candidate:')]
                if not self.chosen:
                    value=branch('vuln','WEB_PIPELINE: find the saved SSH candidate and continue web research',self.http.server_port)
                    value['profile']='http-surface';self.chosen.append('web')
                elif candidates and 'access' not in self.chosen:
                    value=branch('vuln' if mode=='same-role' else 'access','SSH_PIPELINE: test the one published identity only',22,references=[candidates[0]])
                    self.chosen.append('access')
                elif active:value=awaiting()
                else:value=decision()
                return {'text':json.dumps(value)}
            names=[t['function']['name'] for t in body.get('tools',[])]
            self.assertTrue(names);self.assertTrue(all(n.startswith('mcp__pentest_master__') for n in names),names)
            self.assertIn('без брутфорса',prompt)
            count=sum(m.get('role')=='tool' for m in body['messages'])
            assignment=json.loads(prompt.split('<specialist_assignment>\n',1)[1].split('\n</specialist_assignment>',1)[0])
            def tool(name,arguments):
                return {'tool_name':next(n for n in names if n.endswith('__'+name)),'arguments':{'task_id':11,**arguments}}
            if assignment['question'].startswith('WEB_PIPELINE'):
                self.assertFalse(any(n.endswith('__pm_net_exec') for n in names))
                if count==0:return tool('pm_http_request',{'request_json':json.dumps({'url':self.url+'/key'})})
                if count==1:
                    source=tool_payload(body);self.assertIn(self.private,source['stdout'])
                    return tool('pm_publish_candidate',{'service_ref':'service:10.0.0.1:tcp:22','username':self.user,'secret':self.private,
                        'source_ref':source['artifact_ref'],'quote':'username='+self.user+'\n'+self.private})
                if count==2:
                    self.assertTrue(tool_payload(body)['reference'].startswith('candidate:'))
                    return tool('pm_http_request',{'request_json':json.dumps({'url':self.url+'/continue'})})
                report={'summary':'Web investigation continued; published only a credential candidate.','findings':[],'flags':[],'verified':[],'uncertainties':[],'proposed_actions':[]}
            else:
                self.assertTrue(prompt.startswith('You are the VULN' if mode=='same-role' else 'You are the ACCESS'))
                candidate=next(entry['value'] for entry in assignment['data'] if entry['reference'].startswith('candidate:'))
                self.assertEqual(candidate['secret'],self.private);self.assertEqual(candidate['trust'],'candidate')
                if count==0:return tool('pm_write_poc',{'filename':'id.txt','content':self.private})
                if count==1:return tool('pm_net_exec',{'target':'10.0.0.1','argv_json':json.dumps(self.logical)})
                source=tool_payload(body)
                self.assertIn('exit_code',source,{k:source.get(k) for k in ('status','reason','reason_category','error_type','stderr')})
                self.assertEqual(source['exit_code'],0,source);self.assertIn('uid='+str(os.getuid()),source['stdout'])
                if mode in ('normal','same-role'):
                    deadline=time.monotonic()+10
                    while time.monotonic()<deadline:
                        records=list(task_memory.capability_records(11,a.CAPABILITY_LOG/'task_11.jsonl','10.0.0.1'))
                        if len([r for r in records if r.get('tool')=='http_capture' and r.get('coordinator_step_id')
                                and r['coordinator_step_id']!=assignment['coordinator_step_id']])==2:break
                        time.sleep(.02)
                    else:raise AssertionError('WEB receipt was not committed during SSH work')
                report={'summary':'SSH execution returned the exact identity below.','findings':[],'flags':[],
                    'access_level':'root' if os.getuid()==0 else 'user','access_signal':'execution','access_probe_result_id':source['result_id'],
                    'access_quote':source['stdout'].strip(),'verified':[],'uncertainties':[],'proposed_actions':[]}
                if mode=='goal':report['flags']=[{'value':'LOCAL_PLATFORM_CANDIDATE','source':'user.txt from saved web material',
                    'method':'saved HTTP material','objective_key':'goal','goal_evidence':source['result_id']}]
            return {'text':json.dumps(report)}
        self.responder_errors=[]
        def checked_responder(body):
            try:return responder(body)
            except Exception as exc:
                import traceback
                detail=({k:tool_payload(body).get(k) for k in ('status','reason','reason_category','error_type','stderr')} if any(m.get('role')=='tool' for m in body['messages']) else {})
                self.responder_errors.append({'type':type(exc).__name__,'detail':detail,'frames':[(f.name,f.lineno,f.line) for f in traceback.extract_tb(exc.__traceback__)]})
                self.release.set()
                return {'text':json.dumps({'summary':'Test responder rejected this request; no success claimed.','findings':[],'flags':[]})}
        api=self.host.setup_api(checked_responder,max_requests=30)
        def observe():
            try:
                deadline=time.monotonic()+25
                while time.monotonic()<deadline:
                    with self.case.connect() as db:
                        if not task_memory.exists(db,'pm_coordinator_steps'):continue
                        rows=c.steps(db,11)
                        if mode=='cancel' and (self.root/'ssh-started').exists():
                            web=next(r for r in rows if json.loads(r['decision_json']).get('role')=='vuln')
                            specialist_workflow.request_cancel(db,11,web['id']);return
                        if mode=='goal' and any(r['status']=='completed' and json.loads(r['decision_json']).get('role')=='access' for r in rows):
                            q=next(q for q in operator_questions.listing(db,11,pending=True) if q['kind']=='flag_confirmation')
                            operator_questions.answer(db,11,q['id'],'approve','Offline test: simulated platform accepted');db.commit()
                            (self.root/'operator-accepted').write_text('explicit operator test answer')
                            for _ in range(200):
                                with self.case.connect() as control:
                                    web=next(r for r in c.steps(control,11) if json.loads(r['decision_json']).get('role')=='vuln')
                                    if web['cancel_requested_at']:
                                        (self.root/'goal-cancel-recorded').write_text('controller cancellation observed');return
                                time.sleep(.03)
                            raise AssertionError('Goal completion did not cancel active web work')
                    time.sleep(.03)
                raise AssertionError('Operator observer timeout')
            except Exception as exc:self.observer_errors.append(exc)
        observer=threading.Thread(target=observe,daemon=True) if mode in ('cancel','goal') else None
        if observer:observer.start()
        with d.run('concurrent SDK/MCP '+mode,11),d.process_environment():
            result=c.run(11,api_key='local-test-only',max_specialists=2,max_steps=10,max_tokens=1000,expect_flags=1 if mode=='goal' else 2)
            events=d.read_events()
        if observer:observer.join(3)
        self.assertFalse(self.responder_errors,self.responder_errors)
        self.assertFalse(self.observer_errors,self.observer_errors)
        self.assertEqual(self.web_hits,['/key','/continue'])
        self.assertEqual(self.chosen,['web','access'])
        self.assertTrue((self.root/'ssh-started').exists());self.assertTrue((self.root/'ssh-completed').exists())
        self.assertLessEqual(float((self.root/'web-continuation-started').read_text()),float((self.root/'ssh-started').read_text()))
        self.assertIn('Accepted publickey',(self.root/'sshd.stderr').read_text())
        with self.case.connect() as db:
            state=task_memory.context(db,11,a.CAPABILITY_LOG/'task_11.jsonl')
            self.assertEqual(a.fact_state.access_state(db,11)['signal'],'execution')
            self.assertTrue(any(v.get('trust')=='candidate' for v in state['state']['credentials'].values()))
            sessions=[json.loads(r[0]) for r in db.execute('SELECT runtime_sessions_json FROM pm_coordinator_steps WHERE runtime_sessions_json IS NOT NULL')]
        self.assertEqual(len(sessions),2);self.assertEqual(len({s[0]['session_id'] for s in sessions}),2)
        for file in self.root.glob('mcp-*.stdout'):
            for line in file.read_bytes().splitlines():self.assertEqual(json.loads(line)['jsonrpc'],'2.0')
        self.assertTrue(any(e['kind']=='specialist.start' for e in events))
        self.assertNotIn('local-test-only',json.dumps(events)+self.case.console.getvalue())
        self.assertNotIn('BEGIN OPENSSH PRIVATE KEY',json.dumps(events)+self.case.console.getvalue())
        ends=[e for e in events if e['kind']=='tool.end']
        self.assertTrue(all(e.get('source')=='mcp' and e.get('role') in ('vuln','access') for e in ends),
            [(e.get('name'),e.get('source'),e.get('role')) for e in ends])
        if mode=='normal':
            self.assertEqual(len(ends),5,'An SDK fallback must not duplicate the MCP action')
            self.assertEqual(len([e for e in events if e['kind']=='tool.start']),5)
        self.assertFalse((self.root/'forbidden-shell').exists())
        self.assertEqual(json.loads((self.root/'capabilities.json').read_text()),{'subagents':{'available':False},'workflow':{'available':False}})
        return result,api

    def test_real_concurrent_web_publish_and_ssh_access(self):
        result,_=self.run_chain()
        self.assertFalse(result['succeeded'])
        self.assertEqual(len([s for s in result['steps'] if s['decision'].get('action')=='run_role' and s['status']=='completed']),2)
        self.assert_execution_owners(result)

    def assert_execution_owners(self,result):
        from orchestrator import research_budgets
        records={r['id']:r for r in (json.loads(line) for line in (a.CAPABILITY_LOG/'task_11.jsonl').read_text().splitlines())}
        with self.case.connect() as db:
            for step in result['steps']:
                if step['decision']['action']!='run_role':continue
                raw=db.execute('SELECT report_json FROM pm_agent_action_reports WHERE task_id=11 AND role=? AND iteration=?',
                    (step['decision']['role'],step['report_iteration'])).fetchone()[0]
                report=json.loads(raw)
                actual={r['result_id'] for r in report['execution_outcome']['results']}
                expected={rid for rid,r in records.items() if r.get('coordinator_step_id')==step['id'] and r['tool'] in ('http_capture','net_exec')}
                self.assertTrue(expected)
                self.assertEqual(actual,expected,(step['id'],actual,expected))
                self.assertEqual(report['tool_calls'],3 if step['decision']['question'].startswith('WEB_PIPELINE') else 2)
                self.assertEqual(report['tool_calls'],research_budgets.step_usage(db,11,'specialist',step['decision']['role'],step['id']))
                for entry in report['execution_outcome']['results']:
                    self.assertEqual(records[entry['result_id']]['coordinator_step_id'],step['id'])
                    self.assertEqual(entry['coordinator_step_id'],step['id'])
                    self.assertEqual(entry['actor_role'],step['decision']['role'])
                self.assertEqual(report['execution_outcome']['status'],'executed')

    def test_cancel_web_runtime_does_not_interrupt_ssh_specialist(self):
        result,_=self.run_chain('cancel')
        web=next(s for s in result['steps'] if s['decision'].get('role')=='vuln')
        access=next(s for s in result['steps'] if s['decision'].get('role')=='access')
        self.assertEqual(web['status'],'failed');self.assertTrue(web['outcome_uncertain'])
        self.assertEqual(access['status'],'completed')

    def test_same_role_profiles_share_quota_without_double_attribution(self):
        from orchestrator import research_budgets
        result,_=self.run_chain('same-role')
        with self.case.connect() as db:
            reports=[json.loads(r[0]) for r in db.execute("SELECT report_json FROM pm_agent_action_reports WHERE task_id=11 AND role='vuln'")]
            self.assertEqual(sorted(r['tool_calls'] for r in reports),[2,3])
            self.assertEqual(research_budgets.get(db,11,'specialist','vuln')['used'],5)
        self.assertEqual(len(reports),2);self.assertFalse(result['succeeded'])
        self.assert_execution_owners(result)

    def test_explicit_goal_completion_cancels_unneeded_runtime(self):
        result,api=self.run_chain('goal')
        self.assertTrue(result['succeeded'])
        web=next(s for s in result['steps'] if s['decision'].get('role')=='vuln')
        self.assertEqual(web['error'],'goals_completed_cancelled_unneeded_work')
        count=len(api.requests)
        result=c.run(11,max_specialists=2,expect_flags=1,model=lambda *_:self.fail('No model after completed goals'))
        self.assertTrue(result['succeeded']);self.assertEqual(len(api.requests),count)


if __name__=='__main__':unittest.main(verbosity=2)
