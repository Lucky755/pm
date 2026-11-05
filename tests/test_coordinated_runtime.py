"""Real installed Harness + production FastMCP stdio, loopback fake provider only.

Run: .venv/bin/python -m unittest tests.test_coordinated_runtime -v
Requires loopback sockets. Missing SDK is a skip; runtime/protocol errors fail.
"""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import signal
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
if __package__:
    from . import test_coordinated_attack as fixture
    from .test_evidence_readonly_runtime import LocalAPI, DeepSeekHarness
else:
    import test_coordinated_attack as fixture
    from test_evidence_readonly_runtime import LocalAPI, DeepSeekHarness
import pm
from orchestrator import agent_actions as a, coordinated_attack as c, diagnostics as d, task_runtime


# The real MCP implementation and transport are untouched. Tee its stdout bytes
# for protocol assertions; diagnostics must go to stderr/JSONL. No fake client.
MCP_ENTRY = '''
import importlib.util, io, json, os, sys
from pathlib import Path
project, temporary = map(Path,sys.argv[1:])
sys.path.insert(0,str(project))
assert os.environ['PM_SMOKE_CONFIG']=='retained'
class Tee(io.RawIOBase):
    def __init__(self, original, trace): self.original,self.trace=original,trace
    def writable(self): return True
    def write(self,data):
        self.trace.write(data)
        count=self.original.write(data)
        self.original.flush()
        return count
    def flush(self): self.trace.flush(); self.original.flush()
trace=(temporary/f'mcp-{os.getpid()}.stdout').open('wb',buffering=0)
sys.stdout=io.TextIOWrapper(io.BufferedWriter(Tee(sys.stdout.buffer,trace)),encoding='utf-8',write_through=True)
spec=importlib.util.spec_from_file_location('pm_runtime_server',project/'mcp/server.py')
server=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=server
spec.loader.exec_module(server)
server.ROOT=temporary
server.CAPABILITY_LOG=temporary/'caps'
server.ASSET_DB=temporary/'tasks.db'
def denied(*args,**kwargs):
    (temporary/'forbidden-executor').write_text('unexpected executor dispatch')
    raise AssertionError('Privileged executor is forbidden in runtime smoke')
server.run_capability=denied
server.mcp.run(transport='stdio')
'''


def strings(value):
    if isinstance(value,str):
        yield value
    elif isinstance(value,list):
        for item in value:yield from strings(item)
    elif isinstance(value,dict):
        for item in value.values():yield from strings(item)


class SmokeDeadline(BaseException):
    """Do not let the coordinator interpret the test deadline as a provider retry."""


@unittest.skipIf(DeepSeekHarness is None,'deepseek_harness not installed; use project .venv/bin/python')
class CoordinatedRuntimeTests(unittest.TestCase):
    def test_real_coordinator_specialist_mcp_and_saved_pause(self):
        production_connect=a.connect
        case=fixture.CoordinatorTests();case.setUp();self.addCleanup(case.doCleanups)
        root=case.root
        captured='SMOKE_CAPTURE: saved HTTP status 403, no vulnerability claimed'
        result_id='a'*24
        a.CAPABILITY_LOG.mkdir()
        capability=a.CAPABILITY_LOG/'task_11.jsonl'
        capability.write_text(json.dumps({'id':result_id,'task_id':11,'tool':'net_exec','provenance':'network',
            'result':{'status':'completed','exit_code':0,'stdout':captured}})+'\n')
        original_evidence=capability.read_bytes()
        question='Прочитай сохранённый ответ по result_id; не выполняй новые проверки.'
        expected='Верни статус из сохранённого ответа и ссылку на него; это не подтверждение цели.'
        choice=fixture.decision('vuln',question,references=['result:'+result_id])
        choice['expected_result']=expected
        requests=[];coordinator_states=[];assignments=[];tool_messages=[]
        def respond(body):
            requests.append(body)
            user_texts=[text for message in body.get('messages',[]) if message.get('role')=='user'
                        for text in strings(message.get('content'))]
            if len(requests) in (1,4):
                prompt=next(text for text in user_texts if text.startswith('You coordinate'))
                state=json.loads(prompt.rsplit('\n',1)[1]);coordinator_states.append(state)
                self.assertIn('без брутфорса',state['task']['intent'])
                self.assertEqual(state['service_map']['entries'][0]['port'],22)
                self.assertIn('result:'+result_id,state['references'])
                self.assertIn('essential_state',state)
                self.assertFalse(body.get('tools'),'coordinator must have no tools in the real runtime')
                if len(requests)==1:
                    self.assertNotIn('report:vuln:1',state['references'])
                    answer=choice
                else:
                    self.assertIn('report:vuln:1',state['references'])
                    answer=fixture.decision(action='wait_operator',references=['report:vuln:1'])
                return {'text':json.dumps(answer,ensure_ascii=False)}
            if len(requests)==2:
                prompt=next(text for text in user_texts if text.startswith('You are the VULN agent'))
                self.assertIn('без брутфорса',prompt)
                block=prompt.split('<specialist_assignment>\n',1)[1].split('\n</specialist_assignment>',1)[0]
                assignment=json.loads(block);assignments.append(assignment)
                self.assertEqual(assignment['question'],question)
                self.assertEqual(assignment['expected_result'],expected)
                self.assertEqual(assignment['references'],choice['references'])
                self.assertIn(captured,json.dumps(assignment,ensure_ascii=False))
                names=[tool['function']['name'] for tool in body['tools']]
                self.assertTrue(any(name.endswith('pm_capability_read') for name in names),f'Actual SDK tools: {names}')
                name=next(name for name in names if name.endswith('pm_capability_read'))
                return {'tool_name':name,'arguments':{'task_id':11,'result_id':result_id,'offset':0}}
            self.assertEqual(len(requests),3,'unexpected model request/retry')
            messages=[message for message in body['messages'] if message.get('role')=='tool']
            tool_messages.extend(messages)
            self.assertIn(captured,json.dumps(messages,ensure_ascii=False),'MCP result must reach the SDK/provider')
            return {'text':json.dumps({'summary':'Прочитан сохранённый ответ. Цель не подтверждена.',
                    'findings':[],'flags':[],'verified':[],'uncertainties':['Новых проверок не было.'],
                    'proposed_actions':[]},ensure_ascii=False)}
        entry=root/'mcp_entry.py';entry.write_text(MCP_ENTRY)
        executor=root/'fake_privileged_boundary.py'
        executor.write_text("import json,sys\nassert sys.argv[1]=='session' and '--action' in sys.argv\n"
                            "assert sys.argv[sys.argv.index('--action')+1]=='list'\nprint(json.dumps({'sessions':[]}))\n")
        home=root/'harness-home';profile=home/'profiles/sdk-minimal';profile.mkdir(parents=True)
        (profile/'package.json').write_bytes((ROOT/'runtime/harness-home/profiles/sdk-minimal/package.json').read_bytes())
        (profile/'cordis.yml').write_text('[]\n')
        workspace=root/'workspace';workspace.mkdir()
        safe_env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'LANG':'C.UTF-8',
                  'HTTP_PROXY':'','HTTPS_PROXY':'','ALL_PROXY':'','NO_PROXY':'127.0.0.1,localhost'}
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ,safe_env,clear=True))
            for p in (patch.object(a,'DSH_HOME',home),patch.object(a,'WORKSPACE',workspace),
                      patch.object(a,'ISOLATED_EXECUTOR',executor),patch.object(a,'POC_DIR',root/'pocs'),
                      patch.object(a,'DB_PATH',case.database),patch.object(a,'connect',production_connect),
                      patch.object(pm,'DB',case.database)):
                stack.enter_context(p)
            def deadline(*_):raise SmokeDeadline('Real coordinated SDK/MCP smoke exceeded 45 seconds')
            previous=signal.signal(signal.SIGALRM,deadline);signal.setitimer(signal.ITIMER_REAL,45)
            stack.callback(signal.signal,signal.SIGALRM,previous)
            stack.callback(signal.setitimer,signal.ITIMER_REAL,0)
            api=stack.enter_context(LocalAPI(root/'unused',responder=respond))
            # Same runtime profile/plugins as production, with local provider URL
            # and a temporary entry point for the real production MCP server.
            (profile/'cordis.patch.yml').write_text(json.dumps([
                {'id':'session-log-deepseek','config':{'enabled':False}},
                {'id':'plugin-package-inventory-deepseek','config':{'enabled':False}},
                {'id':'persistent-bash','disabled':True},{'id':'persistent-pwsh','disabled':True},
                {'insert':[{'id':'llm-pi-ai','name':'@deepseek-ai/dsh-llm-pi-ai','config':{'providers':{
                    'experiential':{'apiKeyEnv':'DEEPSEEK_API_KEY','api':'openai-completions','baseURL':api.url,
                        'compat':{'supportsDeveloperRole':False,'maxTokensField':'max_tokens'},
                        'models':[{'id':'glm-5.3-uncensored','name':'local smoke','contextWindow':1048576,
                                   'maxTokens':131000,'input':['text']}]}}}}]},
                {'insert':[{'id':'mcp-pentest-master','name':'@deepseek-ai/dsh-mcp-client','config':{
                    'serverName':'pentest_master','transport':'stdio','command':sys.executable,
                    'args':[str(entry),str(ROOT),str(root)],'cwd':str(root),
                    'env':{'PM_SMOKE_CONFIG':'retained'},
                    'toolCallTimeoutMs':10000,'failOnStartupError':True}}]}]))
            profile_before=(profile/'cordis.patch.yml').read_bytes()
            with case.connect() as db:
                task_runtime.save_mode(db,11,'coordinated')
                task_runtime.reconnaissance(db,11,'completed')
            with d.run('real coordinated smoke',11), d.process_environment():
                result=c.run(11,api_key='local-test-only',max_steps=3,max_tokens=1000)
                events=d.read_events()
                self.assertEqual(result['status'],'waiting_operator',case.console.getvalue())
                self.assertEqual([step['status'] for step in result['steps']],['completed','waiting_operator'],
                                 json.dumps(result,ensure_ascii=False)+'\n'+case.console.getvalue()
                                 +'\nMCP stdout: '+repr({p.name:p.read_text()[:1200] for p in root.glob('mcp-*.stdout')}))
                self.assertFalse(result['succeeded'])
                self.assertEqual(len(requests),4)
                run_id=d.context()['run_id']
            with d.run('view saved runtime pause',11), d.process_environment():
                with patch.object(sys,'argv',['pm','resume','11']):args=pm.parser_main()[1]
                with patch.object(pm,'configure',side_effect=AssertionError('namespace')),\
                     patch.object(pm,'preflight_target',side_effect=AssertionError('preflight')),\
                     patch.object(pm,'session_api_key',side_effect=AssertionError('key')):
                    paused=pm.op_resume(args)
                self.assertEqual(paused['coordinator_run_id'],result['coordinator_run_id'])
                self.assertEqual(len(api.requests),4,'pause view called the real model again')
                self.assertNotEqual(d.context()['run_id'],run_id)
            self.assertEqual((profile/'cordis.patch.yml').read_bytes(),profile_before)
            self.assertEqual(capability.read_bytes(),original_evidence)
            self.assertFalse((root/'forbidden-executor').exists())
            self.assertEqual(len(assignments),1);self.assertTrue(tool_messages)
            tools=[event for event in events if event['kind']=='tool.end' and event.get('source')=='mcp']
            self.assertEqual(len(tools),1)
            self.assertEqual(len([e for e in events if e['kind']=='tool.end']),1,'SDK/MCP duplicated the action')
            self.assertEqual(len([e for e in events if e['kind']=='tool.start']),1)
            self.assertEqual(tools[0]['name'],'pm_capability_read')
            self.assertEqual(tools[0]['status'],'completed')
            self.assertEqual((tools[0]['task_id'],tools[0]['role'],tools[0]['iteration']),(11,'vuln',1))
            self.assertEqual(len({event['run_id'] for event in events}),1)
            self.assertTrue(any(e['kind']=='model.start' and e['action_id']==tools[0]['parent_action_id'] for e in events))
            transcripts=list(root.glob('mcp-*.stdout'))
            self.assertTrue(transcripts,'real MCP process did not write protocol output')
            messages=[json.loads(line) for path in transcripts for line in path.read_bytes().splitlines()]
            self.assertTrue(messages)
            self.assertTrue(all(message.get('jsonrpc')=='2.0' for message in messages))
            from mcp.types import JSONRPCMessage
            for message in messages:JSONRPCMessage.model_validate(message)
            self.assertIn(captured,json.dumps(messages,ensure_ascii=False))
            self.assertNotIn('[EVENT]',b''.join(path.read_bytes() for path in transcripts).decode())
            self.assertNotIn('local-test-only',json.dumps(events)+case.console.getvalue())


if __name__=='__main__':unittest.main(verbosity=2)
