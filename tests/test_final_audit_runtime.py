"""Final vertical slice: real PM/Planner/SQLite/Harness/MCP stdio + local HTTP.

Only temporary configuration, the fake model endpoint and privileged IO are
replaced. No coordinator, role, validator, planner or SQLite scheduler mocks.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import pm
from orchestrator import operator_questions,objectives
from tests import test_specialist_workflow_runtime as fixture
from tests.test_coordinated_runtime import strings
from tests.test_coordinated_attack import decision

ROOT=Path(__file__).resolve().parents[1]


class FinalRuntimeTests(unittest.TestCase):
    def setUp(self):
        guard_pythonpath=os.environ.get('PYTHONPATH')
        self.real=fixture.SpecialistRuntimeTests();self.real.setUp();self.addCleanup(self.real.doCleanups)
        self.host=self.real.host;self.root=self.real.root;self.case=self.real.case
        if guard_pythonpath:
            # The reusable SDK fixture clears environment credentials. Preserve
            # the offline runner's guard for our real planner/MCP subprocesses.
            item=patch.dict(os.environ,{'PYTHONPATH':guard_pythonpath})
            item.start();self.addCleanup(item.stop)
        # This is disposable fixture data, not a copy of working storage.
        self.case.database.unlink();self.case.database.touch()
        self.hits=[];self.auth=[];self.coordinator_calls=0;self.roles=[];self.responder_errors=[]
        owner=self
        handler=self.real.http.RequestHandlerClass
        def get(request):
            owner.hits.append(request.path)
            if request.path=='/':body=b'UNUSUAL/9 ^ source /credentials';status=200
            elif request.path=='/credentials':body=b'/credentials username=alice; passwords=bad1,bad2,secret3,unused4,unused5';status=200
            elif request.path=='/auth-check':
                pair=base64.b64decode(request.headers.get('Authorization','').removeprefix('Basic ')).decode()
                owner.auth.append(pair);status=200 if pair=='alice:secret3' else 401
                body=b'/auth-check SERVER AUTHENTICATED; user.txt=UNKNOWN-CANDIDATE-1' if status==200 else b'Login rejected'
            elif request.path=='/another':body=b'/another user.txt=UNKNOWN-CANDIDATE-2';status=200
            else:raise AssertionError('Unplanned fixture request: '+request.path)
            request.send_response(status);request.send_header('Content-Type','text/plain');request.send_header('Content-Length',str(len(body)));request.end_headers()
            request.wfile.write(body)
        handler.do_GET=get
        self.entry=self.root/'planner-python'
        # Entry-point configuration only. The real pipe-key entrypoint and real
        # planner main/request/save/validation are executed in a child process.
        self.entry.write_text('#!'+sys.executable+'\n'+'''import json,runpy,sys
from pathlib import Path
project=Path('''+repr(str(ROOT))+''');temporary=Path('''+repr(str(self.root))+''')
sys.path.insert(0,str(project))
from orchestrator import planner,model_adapter
planner.DATABASE=temporary/'tasks.db';planner.RAW_DIR=temporary/'planner_raw'
original=runpy.run_path
def configured(path,*args,**kw):
 if Path(path).resolve()==project/'orchestrator/planner.py':
  with model_adapter.configuration(**json.loads((temporary/'planner-options.json').read_text())):return planner.main()
 return original(path,*args,**kw)
runpy.run_path=configured
sys.argv=sys.argv[1:]
original(sys.argv[0],run_name='__main__')
''');self.entry.chmod(0o700)
        self.broker_calls=[];self.broker_state=None
        # Legacy initial capture uses the real local HTTP bytes and the existing
        # capture protocol; namespace setup itself is deliberately not executed.
        capture=self.root/'initial-capture.py'
        capture.write_text('''import base64,http.client,json,sys
args=sys.argv[1:]
def arg(k):return args[args.index('--'+k)+1]
assert arg('target')=='10.0.0.1' and arg('hostname')=='app.lab'
connection=http.client.HTTPConnection('127.0.0.1',int(arg('port')),timeout=4)
connection.request('GET',arg('path'),headers={'Host':'app.lab'});response=connection.getresponse();body=response.read()
wire=('HTTP/1.1 '+str(response.status)+' OK\\r\\n'+''.join(k+': '+v+'\\r\\n' for k,v in response.getheaders())+'\\r\\n').encode()+body
print(json.dumps({'capture_protocol':1,'task_id':int(arg('task-id')),'target':arg('target'),'profile':'http_capture',
 'scheme':arg('scheme'),'hostname':arg('hostname'),'port':int(arg('port')),'path':arg('path'),
 'status':'completed','exit_code':0,'response_b64':base64.b64encode(wire).decode(),'response_bytes':len(wire),'capture_truncated':False}))
''')
        original_popen=subprocess.Popen
        def boundary(argv,*args,**kwargs):
            if argv==['/usr/local/sbin/pm-netguard','capabilities']:
                return original_popen([sys.executable,str(ROOT/'executor/netguard_root.py'),'capabilities'],*args,**kwargs)
            if argv[:3]==['sudo','-n',pm.BROKER]:
                self.broker_calls.append(list(argv))
                self.assertEqual(argv[3],'run');self.assertEqual(argv[argv.index('--profile')+1],'http_capture')
                return original_popen([sys.executable,str(capture),*argv[4:]],*args,**kwargs)
            return original_popen(argv,*args,**kwargs)
        def checked(command,**kwargs):
            self.broker_calls.append(list(command));action=command[0]
            if action=='capabilities':return {'resource_policy_protocol':1},0
            if action=='status':return (self.broker_state or {'error':'not configured'},0 if self.broker_state else 1)
            if action=='setup':
                policy=json.loads(command[command.index('--resource-policy')+1]);self.broker_state={'status':'configured','resource_policy':policy,
                    'allowed':[command[i+1] for i,v in enumerate(command) if v=='--allow'],'approved_egress':'tun-test','docker_forward_managed':True}
                return self.broker_state,0
            if action=='hosts':return {'status':'hosts_ready','destination':'10.0.0.1'},0
            raise AssertionError('Unexpected privileged boundary: '+str(command))
        for item in (patch.object(pm,'DB',self.case.database),patch.object(pm,'PYTHON',self.entry),
                     patch.object(pm,'get_egress',return_value='tun-test'),patch.object(pm,'broker_is_trusted'),patch.object(pm,'sudo_authenticate'),
                     patch.object(pm,'sudo_checked',side_effect=checked),patch.object(pm.getpass,'getpass',return_value='local-test-only'),
                     patch.object(subprocess,'Popen',side_effect=boundary),
                     patch.dict(os.environ,{'PM_METHOD_LIBRARY_DIR':str(self.root/'method-library')})):
            item.start();self.addCleanup(item.stop)

    def choose(self,state,role,question,ref,profile):
        value=decision(role,question,references=[ref]);value['profile']=profile
        value['boundaries']={'task_id':1,'target':'10.0.0.1','intent_ref':'intent','resource_refs':['scope:10.0.0.1']}
        return value

    def respond(self,body):
        user=next(text for m in body['messages'] if m.get('role')=='user' for text in strings(m.get('content'))
            if text.startswith(('You coordinate','You are the')) or "Convert the operator's natural-language task" in text)
        if 'Convert the operator\'s natural-language task into a structured plan.' in user:
            self.assertFalse(body.get('tools'))
            return {'text':json.dumps({'summary':'Inspect the supplied website only.','target':'10.0.0.1','objectives':['user.txt'],
                'tasks':[{'agent':'recon','instruction':'Inspect the authorized website on 10.0.0.1','depends_on':[]}],'checkpoints':[]})}
        if user.startswith('You coordinate'):
            self.assertFalse(body.get('tools'));self.coordinator_calls+=1
            state=json.loads(user.rsplit('\n',1)[1]);self.assertIn('без брутфорса',state['task']['intent'])
            self.assertIn('essential_state',state);self.assertIn('task_memory',state)
            if self.coordinator_calls==1:return {'text':'{"action":'}
            if self.coordinator_calls==2:
                self.assertIn('rejected_response_untrusted',user)
                value=self.choose(state,'recon','AUDIT RECON: interpret the unusual page and retrieve the linked candidate file','intent','http-surface')
            elif self.coordinator_calls==3:
                source=next(ref for ref,value in state['references'].items() if ref.startswith('http_artifact:') and value.get('path')=='/credentials')
                value=self.choose(state,'access','AUDIT ACCESS: check the five saved pairs, stop on the explicit authentication criterion',source,'access')
            elif self.coordinator_calls==4:
                self.assertTrue(any(p['status']=='rejected' for p in state['flag_proposals']))
                value=self.choose(state,'vuln','AUDIT OTHER: retrieve another task-linked candidate after platform rejection','intent','http-surface')
            else:raise AssertionError('Unnecessary coordinator/model request')
            return {'text':json.dumps(value)}
        self.assertTrue(user.startswith(('You are the RECON','You are the ACCESS','You are the VULN')),user[:80])
        assignment=json.loads(user.split('<specialist_assignment>\n',1)[1].split('\n</specialist_assignment>',1)[0])
        self.assertIn('без брутфорса',user);self.assertIn(assignment['expected_result'],user)
        names=[t['function']['name'] for t in body.get('tools',[])];self.assertTrue(all(n.startswith('mcp__pentest_master__') for n in names))
        tool_messages=[m for m in body['messages'] if m.get('role')=='tool']
        question=assignment['question']
        def tool(name,arguments):return {'tool_name':next(n for n in names if n.endswith('__'+name)),'arguments':{'task_id':1,**arguments}}
        if not tool_messages:
            if question.startswith('AUDIT RECON'):self.roles.append('recon');return tool('pm_http_request',{'request_json':json.dumps({'url':self.real.url+'/credentials'})})
            if question.startswith('AUDIT ACCESS'):
                self.roles.append('access');source=assignment['references'][0]
                plan={'kind':'authentication','url':self.real.url+'/auth-check','hypothesis':'Use only explicitly discovered pairs',
                    'max_requests':5,'seconds':20,'criterion':{'kind':'authenticated','status':[200],'body_contains':'SERVER AUTHENTICATED'},
                    'pairs':[{'username':'alice','password':p,'source_ref':source} for p in ('bad1','bad2','secret3','unused4','unused5')]}
                return tool('pm_check_series',{'plan_json':json.dumps(plan)})
            self.roles.append('vuln');return tool('pm_http_request',{'request_json':json.dumps({'url':self.real.url+'/another'})})
        payload=fixture.tool_payload(body)
        if question.startswith('AUDIT ACCESS'):
            self.assertTrue(payload['criterion_matched']);self.assertEqual(payload['checks_started'],3)
            original=payload['checks'][-1];rid=original['result_id'];ref=original['artifact_ref'];quote='/auth-check SERVER AUTHENTICATED'
        else:rid=payload['result_id'];ref=payload['artifact_ref'];quote='/credentials username=alice' if question.startswith('AUDIT RECON') else '/another user.txt=UNKNOWN-CANDIDATE-2'
        report={'summary':'Only the cited saved response is reported.','findings':[{'title':quote,'claim':quote,
            'kind':'observation','quote':quote,'result_id':rid,'artifact_ref':ref,'probe':{'result_id':rid}}],
            'flags':[],'verified':[],'hypotheses':[],'uncertainties':[],'proposed_actions':[]}
        if question.startswith('AUDIT ACCESS'):
            report.update(access_level='none',access_signal='credential',access_probe_result_id=rid,access_quote=quote)
            report['flags']=[{'value':'UNKNOWN-CANDIDATE-1','source':'/auth-check user.txt','method':'saved HTTP response','objective_key':'goal','goal_evidence':rid}]
        if question.startswith('AUDIT OTHER'):
            report['flags']=[{'value':'UNKNOWN-CANDIDATE-2','source':'/another user.txt','method':'saved HTTP response','objective_key':'goal','goal_evidence':rid}]
        return {'text':json.dumps(report)}

    def main(self,*argv):
        with patch.object(sys,'argv',['pm',*argv]):return pm.main()

    def test_empty_database_new_discovery_access_reject_another_accept_offline_and_resume(self):
        def checked(body):
            try:return self.respond(body)
            except Exception as exc:
                import traceback
                self.responder_errors.append((type(exc).__name__,str(exc)[:200],[(f.name,f.lineno) for f in traceback.extract_tb(exc.__traceback__)]));return {'text':'{"action":"invalid"}'}
        api=self.host.setup_api(checked,max_requests=20)
        (self.root/'planner-options.json').write_text(json.dumps(self.host.options))
        self.main('new','--target',self.real.url+'/','--address','10.0.0.1','--task','Найти флаг user.txt; без брутфорса',
            '--goal-first','--expect-flags','1','--coordinated','--max-specialists','1','--coordinator-steps','2')
        self.assertFalse(self.responder_errors,self.responder_errors)
        self.assertEqual(self.roles,['recon','access']);self.assertEqual(self.auth,['alice:bad1','alice:bad2','alice:secret3'])
        with self.case.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM tasks').fetchone()[0],1)
            questions=operator_questions.listing(db,1,pending=True)
            self.assertTrue(questions,self.case.console.getvalue()+'\n'+str(db.execute('SELECT report_json FROM pm_agent_action_reports').fetchall()))
            first=questions[0]
            self.assertEqual(first['flag_candidate']['value'],'UNKNOWN-CANDIDATE-1')
            old_run=db.execute('SELECT id FROM pm_coordinator_runs').fetchone()[0]
            self.assertEqual(db.execute('SELECT status FROM pm_coordinator_steps ORDER BY id').fetchall(),[('completed',),('completed',)])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pm_credential_acceptance').fetchone()[0],1)
            for (raw,) in db.execute('SELECT report_json FROM pm_agent_action_reports'):
                report=json.loads(raw)
                self.assertTrue(report['findings'],report)
                self.assertEqual(report['execution_outcome']['status'],'executed',report)
        self.main('questions','1','--answer',str(first['id']),'--decision','decline')
        self.main('resume','1','--coordinator-steps','1')
        self.assertFalse(self.responder_errors,self.responder_errors)
        with self.case.connect() as db:
            second=operator_questions.listing(db,1,pending=True)[0]
            self.assertEqual(second['flag_candidate']['value'],'UNKNOWN-CANDIDATE-2')
            self.assertEqual(db.execute('SELECT id FROM pm_coordinator_runs').fetchone()[0],old_run)
            self.assertEqual(db.execute('SELECT report_iteration FROM pm_coordinator_steps ORDER BY id').fetchall(),[(1,),(2,),(3,)])
        self.main('target-state','1','--state','deactivated','--reason','Offline final acceptance')
        requests=len(api.requests);hits=list(self.hits);broker=len(self.broker_calls)
        self.main('questions','1','--answer',str(second['id']),'--decision','approve')
        self.main('resume','1','--diagnostic')
        self.assertEqual(len(api.requests),requests);self.assertEqual(self.hits,hits);self.assertEqual(len(self.broker_calls),broker)
        with self.case.connect() as db:
            self.assertEqual(objectives.objective_status(db,1)['objectives'][0]['status'],'confirmed')
            self.assertEqual(objectives.objective_status(db,1)['expected_flags'],1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pm_coordinator_steps').fetchone()[0],3)
        self.assertFalse(any('--profile' in call and call[call.index('--profile')+1]=='tcp_full' for call in self.broker_calls))
        events=[json.loads(line) for p in (self.root/'events').glob('*.jsonl') for line in p.read_text().splitlines()]
        self.assertFalse(any(e.get('reason') in ('significant_finding','role_approval_required') for e in events))
        self.assertTrue(any(e['kind']=='coordinator.decision_rejected' for e in events))
        tools=[e for e in events if e['kind']=='tool.end']
        self.assertTrue(tools)
        self.assertTrue(all(e['run_id'] and e['action_id'] and e['task_id']==1 for e in tools))
        self.assertGreaterEqual(len({e['run_id'] for e in events}),3)
        transcripts=list(self.root.glob('mcp-*.stdout'));self.assertTrue(transcripts)
        for trace in transcripts:
            for line in trace.read_bytes().splitlines():self.assertEqual(json.loads(line)['jsonrpc'],'2.0')
        self.assertNotIn('local-test-only',json.dumps(events)+self.case.database.read_bytes().decode(errors='replace'))
        print('LOCAL AUDIT: empty DB -> planner -> RECON -> ACCESS (3/5 pairs, success) -> reject flag #1 -> VULN -> target off -> accept flag #2 -> resume: goal complete; no extra model/HTTP',file=sys.__stdout__)


if __name__=='__main__':unittest.main(verbosity=2)
