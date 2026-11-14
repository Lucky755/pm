"""Installed SDK + actual PM MCP stdio; loopback provider and temporary data only.

No Harness/client/session.run substitutes. The privileged executor is forbidden.
The two-specialist prototype uses owned runtimes, not a claimed native workflow.
"""
from contextlib import ExitStack
import contextvars
import json
import os
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

from tests import test_coordinated_attack as fixture
from tests.test_coordinated_runtime import MCP_ENTRY, strings
from tests.test_evidence_readonly_runtime import LocalAPI, DeepSeekHarness
from orchestrator import agent_actions as a, coordinated_attack as c, diagnostics as d, model_adapter as m

ROOT=Path(__file__).resolve().parents[1]

# Probe services on the real running profile. Binary contents alone do not prove
# that a service is installed or available to the SDK's selected profile.
PROBE='''
import fs from 'node:fs';
export const name='pm-capability-probe';
export function apply(ctx) {
  ctx.on('agent/created', ({agent}) => {
    if (typeof agent.ctx.get!=='function') throw new Error('Service probe unsupported: ctx.get missing');
    const services={};
    for (const key of ['subagents','workflow']) {
      try { const s=agent.ctx.get(key); services[key]=s ? {available:true,
        prompt:typeof s.prompt==='function',interruptByParent:typeof s.interruptByParent==='function'}
        : {available:false}; } catch {services[key]={available:false};}
    }
    fs.writeFileSync(process.env.PM_CAPABILITY_PROBE,JSON.stringify(services));
  });
}
'''


@unittest.skipIf(DeepSeekHarness is None,'installed SDK required; use .venv/bin/python')
class AdapterRuntimeTests(unittest.TestCase):
    def setUp(self):
        production_connect=a.connect
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.root=self.case.root
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ,{'PATH':os.environ.get('PATH','/usr/bin:/bin'),
            'LANG':'C.UTF-8','NO_PROXY':'127.0.0.1,localhost',
            'PM_MODEL_AUDIT_DIR':str(self.root/'model-audit')},clear=True))
        self.rid='a'*24;self.captured='HTTP/1.1 403 Forbidden; saved response, no goal claim'
        a.CAPABILITY_LOG.mkdir()
        self.capability=a.CAPABILITY_LOG/'task_11.jsonl'
        self.capability.write_text(json.dumps({'id':self.rid,'task_id':11,'tool':'net_exec','provenance':'network',
             'result':{'status':'completed','exit_code':0,'stdout':self.captured}})+'\n')
        self.original=self.capability.read_bytes()
        entry=self.root/'mcp_entry.py';entry.write_text(MCP_ENTRY)
        executor=self.root/'executor_boundary.py'
        executor.write_text("import json,sys\nassert sys.argv[1]=='session' and '--action' in sys.argv\n"
            "assert sys.argv[sys.argv.index('--action')+1]=='list'\nprint(json.dumps({'sessions':[]}))\n")
        for p in (patch.object(a,'connect',production_connect),patch.object(a,'DB_PATH',self.case.database),
                  patch.object(a,'ISOLATED_EXECUTOR',executor),patch.object(a,'POC_DIR',self.root/'pocs')):
            self.stack.enter_context(p)
        self.home=self.root/'home';self.profile=self.home/'profiles/sdk-minimal';self.profile.mkdir(parents=True)
        (self.profile/'package.json').write_bytes((ROOT/'runtime/harness-home/profiles/sdk-minimal/package.json').read_bytes())
        (self.profile/'cordis.yml').write_text('[]\n')
        self.workspace=self.root/'workspace';self.workspace.mkdir()
        self.entry=entry

    def setup_api(self,responder,max_requests=8):
        api=self.stack.enter_context(LocalAPI(self.root/'forbidden-shell',responder=responder,max_requests=max_requests))
        probe=self.root/'probe.mjs';probe.write_text(PROBE)
        layers=[{'id':'session-log-deepseek','config':{'enabled':False}},
                {'id':'plugin-package-inventory-deepseek','config':{'enabled':False}},
                {'id':'persistent-bash','disabled':True},{'id':'persistent-pwsh','disabled':True},
                {'insert':[{'id':'llm-pi-ai','name':'@deepseek-ai/dsh-llm-pi-ai','config':{'providers':{
                    'experiential':{'apiKeyEnv':'DEEPSEEK_API_KEY','api':'openai-completions','baseURL':api.url,
                        'compat':{'supportsDeveloperRole':False,'maxTokensField':'max_tokens'},
                        'models':[{'id':'glm-5.3-uncensored','name':'local only','contextWindow':1048576,
                                   'maxTokens':131000,'input':['text']}]}}}}]},
                {'insert':[{'id':'mcp-pentest-master','name':'@deepseek-ai/dsh-mcp-client','config':{
                    'serverName':'pentest_master','transport':'stdio','command':sys.executable,
                    'args':[str(self.entry),str(ROOT),str(self.root)],'cwd':str(self.root),
                    'env':{'PM_SMOKE_CONFIG':'retained'},'toolCallTimeoutMs':10000,'failOnStartupError':True}}]},
                {'insert':[{'id':'pm-capability-probe','name':str(probe)}]}]
        (self.profile/'cordis.patch.yml').write_text(json.dumps(layers))
        self.options=dict(dsh_home=str(self.home),cwd=str(self.workspace),request_timeout_seconds=20,
            initialize_timeout_seconds=20,shutdown_timeout_seconds=2,
            env={'PM_CAPABILITY_PROBE':str(self.root/'capabilities.json')})
        self.stack.enter_context(m.configuration(**self.options))
        return api

    def audits(self):return [json.loads(p.read_text()) for p in (self.root/'model-audit').glob('*.json')]

    def assert_preserved(self):
        self.assertEqual(self.capability.read_bytes(),self.original)
        self.assertFalse((self.root/'forbidden-executor').exists())
        self.assertFalse((self.root/'forbidden-shell').exists())
        transcripts=list(self.root.glob('mcp-*.stdout'));self.assertTrue(transcripts)
        for path in transcripts:
            for line in path.read_bytes().splitlines():self.assertEqual(json.loads(line)['jsonrpc'],'2.0')

    def test_real_decision_role_and_tool_free_format_recovery_do_not_replay(self):
        number=0;question='Read the saved response only; do not make another request.'
        choice=fixture.decision('vuln',question,references=['result:'+self.rid])
        report={'summary':'Saved 403 response read; goal unconfirmed.','findings':[],
                'flags':[],'verified':[],'uncertainties':[],'proposed_actions':[]}
        def respond(body):
            nonlocal number
            number+=1
            content='\n'.join(strings(body.get('messages',[])))
            if number in (1,2,5,6):self.assertFalse(body.get('tools'))
            if number==1:
                self.assertIn('essential_state',content);self.assertIn('без брутфорса',content)
                return {'text':'{"action":'}
            if number==2:
                self.assertIn('rejected_response_untrusted',content)
                return {'text':json.dumps(choice)}
            if number==3:
                self.assertIn('<specialist_assignment>',content)
                self.assertIn(choice['expected_result'],content)
                self.assertIn('result:'+self.rid,content)
                name=next(t['function']['name'] for t in body['tools']
                          if t['function']['name'].endswith('pm_capability_read'))
                return {'tool_name':name,'arguments':{'task_id':11,'result_id':self.rid,'offset':0}}
            if number==4:
                self.assertIn(self.captured,content)
                return {'text':'{"summary": "operation was read", "findings": ['}
            if number==5:
                self.assertIn('Reformat saved results only',content)
                self.assertIn(self.captured,content)
                return {'text':json.dumps(report)}
            self.assertEqual(number,6,'unexpected retry/replay')
            return {'text':json.dumps(fixture.decision(action='wait_operator'))}
        api=self.setup_api(respond)
        with d.run('adapter recovery smoke',11), d.process_environment():
            result=c.run(11,api_key='local-test-only',max_steps=3,decision_retries=1,max_tokens=1000)
            events=d.read_events();run_id=d.context()['run_id']
        self.assertEqual(result['stop_reason'],'model_waiting_operator',self.case.console.getvalue())
        self.assertEqual([s['status'] for s in result['steps']],['completed','waiting_operator'])
        self.assertEqual(number,6)
        self.assertEqual(len([e for e in events if e['kind']=='tool.end']),1)
        records=self.audits();self.assertEqual(len(records),5) # one SDK turn contains both tool/model exchanges
        self.assertEqual({r['run_id'] for r in records},{run_id})
        self.assertTrue(all(r['session_id'] and r.get('runtime_message_id') for r in records))
        repairs=[r for r in records if r['recovery_attempt']==1]
        self.assertEqual(len(repairs),2);self.assertTrue(all(r['mode']=='analysis' for r in repairs))
        self.assertEqual(len([r for r in records if r['status']=='rejected']),2)
        self.assert_preserved()

    def test_exhausted_damaged_decision_saves_original_without_dispatch(self):
        api=self.setup_api(lambda _: {'text':'{"action":'})
        with d.run('invalid decision smoke',11),d.process_environment():
            result=c.run(11,api_key='local-test-only',decision_retries=1,max_tokens=1000)
        self.assertEqual(result['stop_reason'],'decision_budget_exhausted:invalid_json')
        self.assertEqual(len(api.requests),2)
        self.assertFalse(list(a.REPORT_DIR.rglob('*.json')))
        for record in self.audits():
            self.assertEqual(record['status'],'rejected')
            self.assertEqual(Path(record['raw_response_ref']).read_text(),'{"action":')
            self.assertEqual(record['rejection_reason'],'invalid_json')
        self.assert_preserved()

    def test_memory_reaches_real_sdk_material_stdio_and_observed_cache_usage(self):
        from orchestrator import task_memory
        with self.case.connect() as db:
            db.execute('UPDATE pm_tcp_full_scans SET open_ports_json=?',(json.dumps(list(range(1,14))+[9999]),))
        number=0;choice=fixture.decision('vuln','Read original saved material; no target operations.',references=['result:'+self.rid])
        choice['boundaries']['resource_refs']=['service:10.0.0.1:tcp:9999']
        usage={'prompt_tokens':100,'completion_tokens':20,'total_tokens':120,
               'prompt_tokens_details':{'cached_tokens':80}}
        def respond(body):
            nonlocal number
            number+=1
            content='\n'.join(strings(body.get('messages',[])))
            if number==1:
                prompt=next(s for s in strings(body['messages']) if s.startswith('You coordinate'))
                state=json.loads(prompt.rsplit('\n',1)[1])
                self.assertIn('service:10.0.0.1:tcp:9999',state['references'])
                self.assertIn(9999,[port for group in state['task_memory']['service_groups'] for port in group['ports']])
                return {'text':json.dumps(choice),'usage':usage}
            if number==2:
                self.assertIn('<task_memory>',content);self.assertIn('без брутфорса',content)
                self.assertIn('service:10.0.0.1:tcp:9999',content)
                name=next(t['function']['name'] for t in body['tools'] if t['function']['name'].endswith('pm_material_read'))
                return {'tool_name':name,'arguments':{'task_id':11,'reference':'result:'+self.rid,'offset':0,'limit':16},'usage':usage}
            if number==3:
                self.assertIn('HTTP/1.1 403 Forb',content)
                return {'text':json.dumps({'summary':'Original bytes read locally; no fresh network observation.',
                        'findings':[],'flags':[],'verified':[],'uncertainties':[],'proposed_actions':[]}), 'usage':usage}
            self.assertEqual(number,4)
            return {'text':json.dumps(fixture.decision(action='wait_operator')),'usage':usage}
        api=self.setup_api(respond)
        with d.run('real task memory',11),d.process_environment():
            result=c.run(11,api_key='local-test-only',max_tokens=1000)
            events=d.read_events()
        self.assertEqual(result['stop_reason'],'model_waiting_operator',self.case.console.getvalue())
        self.assertEqual(len(api.requests),4)
        records=self.audits();self.assertTrue(any(r.get('prefix_cache')=='hit_observed' for r in records),records)
        self.assertTrue(all(r['statistics']['output_tokens'] is not None for r in records))
        with self.case.connect() as db:
            self.assertGreater(task_memory.current(db,11)['version'],0)
        self.assertEqual(len([e for e in events if e['kind']=='tool.end' and e.get('source')=='mcp']),1)
        self.assert_preserved()

    def test_specialist_profile_hides_unrelated_tools_and_denies_unsolicited_call(self):
        number=0;choice=fixture.decision('vuln',references=['result:'+self.rid])
        choice['profile']='http-surface'
        def respond(body):
            nonlocal number
            number+=1
            content='\n'.join(strings(body.get('messages',[])))
            if number==1:
                self.assertIn('http-surface',content)
                return {'text':json.dumps(choice)}
            if number==2:
                self.assertIn('<pm_common_rules>',content)
                self.assertIn('<procedure id="http-capture">',content)
                self.assertNotIn('<procedure id="capture-audit">',content)
                names=[t['function']['name'] for t in body['tools']]
                self.assertTrue(any(n.endswith('pm_http_capture') for n in names))
                self.assertTrue(any(n.endswith('pm_capability_read') for n in names))
                self.assertFalse(any(n.endswith('pm_session') or n.endswith('pm_net_exec') for n in names),names)
                return {'tool_name':'mcp__pentest_master__pm_session',
                        'arguments':{'task_id':11,'action':'open','argv_json':'["/usr/bin/ssh"]'}}
            if number==3:
                self.assertIn('PM_PROFILE_TOOL_DENIED',content)
                return {'text':json.dumps({'summary':'Unrequested operation was denied; no access claimed.',
                    'findings':[],'flags':[],'verified':[],'uncertainties':[],'proposed_actions':[]})}
            self.assertEqual(number,4)
            return {'text':json.dumps(fixture.decision(action='wait_operator'))}
        api=self.setup_api(respond)
        with d.run('specialist policy smoke',11),d.process_environment():
            result=c.run(11,api_key='local-test-only',max_tokens=1000)
            events=d.read_events()
        self.assertEqual(result['stop_reason'],'model_waiting_operator',self.case.console.getvalue())
        self.assertEqual(len(api.requests),4)
        self.assertFalse([e for e in events if e['kind']=='tool.start' and e.get('source')=='mcp'])
        self.assert_preserved()

    def test_unsolicited_mcp_call_in_format_recovery_is_denied_without_replay(self):
        number=0;tool=None
        def respond(body):
            nonlocal number,tool
            number+=1
            if number==1:return {'text':json.dumps(fixture.decision('vuln',references=['result:'+self.rid]))}
            if number==2:
                tool=next(t['function']['name'] for t in body['tools'] if t['function']['name'].endswith('pm_capability_read'))
                return {'tool_name':tool,'arguments':{'task_id':11,'result_id':self.rid}}
            if number==3:return {'text':'{"summary":'}
            self.assertFalse(body.get('tools'),'formatting must hide even MCP read tools')
            if number==4:return {'tool_name':tool,'arguments':{'task_id':11,'result_id':self.rid}}
            self.assertEqual(number,5,'no next planning after damaged repair')
            self.assertIn('PM_EVIDENCE_READ_ONLY','\n'.join(strings(body['messages'])))
            return {'text':json.dumps({'summary':'No new observation.','findings':[],'flags':[],'proposed_actions':[]})}
        api=self.setup_api(respond)
        with d.run('tool disabled recovery',11),d.process_environment():
            result=c.run(11,api_key='local-test-only',max_tokens=1000)
            events=d.read_events()
        self.assertEqual(result['status'],'waiting_operator',self.case.console.getvalue())
        self.assertIn('damaged',result['stop_reason'])
        self.assertEqual(len(api.requests),5)
        self.assertEqual(len([e for e in events if e['kind']=='tool.end' and e.get('source')=='mcp']),1)
        self.assertTrue(any(r.get('finish_reason')=='completed' and r.get('mode')=='analysis'
                            and r['status']=='policy_violation' for r in self.audits()))
        self.assert_preserved()

    def test_initial_planning_and_auxiliary_analysis_use_real_adapter(self):
        from orchestrator import planner, scheduler
        number=0
        def respond(body):
            nonlocal number
            number+=1;self.assertFalse(body.get('tools'))
            if number==1:return {'text':'{bad JSON'}
            if number==2:return {'text':json.dumps({'summary':'Local plan','target':'10.0.0.1',
                                                  'tasks':[],'objectives':[],'checkpoints':[]})}
            content='\n'.join(strings(body.get('messages',[])))
            self.assertIn('metadata_only',content);self.assertIn('source_state_sha256',content)
            return {'text':'Analysis of saved evidence only.'}
        api=self.setup_api(respond)
        with patch.object(planner,'RAW_DIR',self.root/'planner-raw'):
            plan=planner.request_plan('local-test-only','10.0.0.1','No external action')
        self.assertEqual(plan['tasks'],[])
        from orchestrator import task_memory
        with self.case.connect() as db:memory_view=task_memory.analysis_context(db,11)
        self.assertIn('saved evidence',scheduler.ask_agent('local-test-only','vuln','Review only',[],'10.0.0.1',memory_view=memory_view))
        self.assertEqual(len(api.requests),3)
        self.assertEqual(len(self.audits()),3)
        self.assert_preserved()

    def test_two_owned_specialists_events_mcp_and_independent_cancel(self):
        waiting=threading.Event();release=threading.Event();number=0
        self.addCleanup(release.set)
        def respond(body):
            nonlocal number
            number+=1
            content='\n'.join(strings(body.get('messages',[])))
            if 'hold-specialist' in content:
                waiting.set();release.wait(8)
                return {'text':'cancelled response must not be accepted'}
            messages=[msg for msg in body['messages'] if msg.get('role')=='tool']
            if not messages:
                name=next(t['function']['name'] for t in body['tools']
                          if t['function']['name'].endswith('pm_capability_read'))
                return {'tool_name':name,'arguments':{'task_id':11,'result_id':self.rid,'offset':0}}
            return {'text':'specialist read the saved evidence'}
        api=self.setup_api(respond)
        outcomes=[]
        with a.action_policy_patch(3,1) as policy, d.run('two specialist prototype',11),d.process_environment():
            with m.HarnessAdapter(mode='execute',patches=(policy,),api_key='local-test-only') as first, \
                 m.HarnessAdapter(mode='execute',patches=(policy,),api_key='local-test-only') as second:
                session=second.start_session('hold-specialist')
                def work():
                    try:outcomes.append(session.run('hold-specialist'))
                    except m.HarnessCallError as exc:outcomes.append(exc)
                thread=threading.Thread(target=contextvars.copy_context().run,args=(work,),daemon=True)
                thread.start();self.assertTrue(waiting.wait(5))
                second.cancel();release.set();thread.join(5);self.assertFalse(thread.is_alive())
                result=first.run('read-specialist: read saved evidence only',session_id='read-specialist')
                self.assertEqual(result.finish_reason,'completed')
                self.assertIn('saved evidence',result.final_response)
            events=d.read_events()
        self.assertEqual(len(outcomes),1)
        self.assertIsInstance(outcomes[0],m.HarnessCallError)
        self.assertEqual(outcomes[0].code,'cancelled')
        self.assertEqual(len(api.requests),3)
        self.assertTrue(any(e['kind']=='tool.end' and e['status']=='completed' for e in events))
        services=json.loads((self.root/'capabilities.json').read_text())
        # Record the tested sdk-minimal profile, not capabilities inferred from
        # bundles or the separate ACP/CLI protocol.
        self.assertEqual(services,{'subagents':{'available':False},'workflow':{'available':False}})
        names=[tool['function']['name'] for request in api.requests for tool in request.get('tools',[])]
        self.assertFalse(any('subagent' in name.lower() or 'workflow' in name.lower() for name in names))
        self.assert_preserved()

    def test_timeout_and_transport_failure_are_not_replayed(self):
        release=threading.Event();entered=threading.Event();self.addCleanup(release.set)
        def respond(_):
            entered.set();release.wait(6);return {'text':'late'}
        api=self.setup_api(respond)
        with m.configuration(request_timeout_seconds=0.3), \
             m.HarnessAdapter(mode='analysis',api_key='local-test-only') as harness:
            with self.assertRaises(m.HarnessCallError) as caught:harness.run('timeout once')
        release.set();self.assertTrue(entered.is_set());self.assertEqual(caught.exception.code,'timeout')
        self.assertEqual(len(api.requests),1)
        # A closed loopback endpoint, never a provider/CTF destination.
        api.server.shutdown();api.server.server_close()
        with m.configuration(base_url=api.url,provider='deepseek-official',model='deepseek-chat',
                             request_timeout_seconds=3), \
             m.HarnessAdapter(mode='analysis',api_key='local-test-only') as harness:
            try:result=harness.run('transport failure only')
            except m.HarnessCallError as exc:self.assertIn(exc.code,('transport_error','timeout'))
            else:self.assertNotEqual(result.finish_reason,'completed')
        self.assertEqual(len(api.requests),1)
        self.assert_preserved()


if __name__=='__main__':unittest.main(verbosity=2)
