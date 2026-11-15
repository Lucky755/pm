"""Task session lifecycle uses real temporary SQLite and the public MCP path."""
import unittest
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import tempfile
import io
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch
from executor import netguard_root as broker
from tests import test_verify_saved_capture as capture_fixture
from tests import test_coordinated_attack as fixture
from orchestrator import agent_actions,task_sessions as sessions,operator_questions,resources,pivoting,task_memory


class SessionLifecycleRegressionTests(unittest.TestCase):
    def test_ten_sessions_are_supported(self):
        self.assertEqual(broker.SESSION_MAX,10)

    def test_valid_role_does_not_close_useful_sessions(self):
        case=capture_fixture.SavedCaptureVerifyTests();case.setUp();self.addCleanup(case.doCleanups)
        case.run_verify()
        self.assertEqual(agent_actions.close_task_sessions.call_count,0)

    def test_pivot_cli_rejects_combined_operator_actions_before_side_effects(self):
        import pm
        args=SimpleNamespace(task_id=11,answer=None,reconsider=None,apply_tool=1,apply_pivot=2)
        with patch.object(pm,'connect') as connection,self.assertRaises(pm.OperatorError):
            pm.op_questions(args)
        connection.assert_not_called()


class TaskSessionTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        spec=importlib.util.spec_from_file_location('session_manager_mcp',Path(__file__).resolve().parents[1]/'mcp/server.py')
        self.server=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.server)
        self.directory=self.case.root/'sessions';self.directory.mkdir(mode=0o700)
        self.work=self.case.root/'work';self.work.mkdir(mode=0o700)
        self.base=self.case.root/'broker';self.base.mkdir(mode=0o700)
        self.config={'task_id':11,'uid':os.getuid(),'gid':os.getgid(),'owner':'offline',
                     'allowed':['10.0.0.1/32','10.2.0.0/24'],'resource_policy':None}
        self.calls=[];self.alive={};self.counter=0;self.health_failure=False;self.tunnel_commands=[]
        self.socket_handles=[];self.addCleanup(lambda:[s.close() for s in self.socket_handles])
        realpath=os.path.realpath
        for p in (patch.object(self.server,'ASSET_DB',self.case.database),patch.object(self.server,'CAPABILITY_LOG',agent_actions.CAPABILITY_LOG),
                patch.object(broker,'BASE',self.base),patch.object(broker,'ensure_root'),
                patch.object(broker,'owned_config',return_value=({'name':'pmns11'},self.config)),
                patch.object(broker,'session_dir',return_value=self.directory),patch.object(broker,'task_workdir',return_value=self.work),
                patch.object(broker,'session_alive',side_effect=lambda m:self.alive.get(m.get('session_id'),False)),
                patch.object(broker,'session_request',side_effect=self.worker),patch.object(broker.subprocess,'run',side_effect=self.boundary),
                patch.object(broker.subprocess,'Popen',side_effect=self.spawn),
                patch.object(broker.os.path,'realpath',side_effect=lambda path,*args,**kwargs:
                    '/usr/local/sbin/pm-netguard' if str(path)==sys.argv[0] else realpath(path,*args,**kwargs))):
            p.start();self.addCleanup(p.stop)

    def worker(self,meta,payload,**kwargs):
        if self.health_failure:raise TimeoutError('Offline control socket did not answer')
        sid=meta['session_id'];op=payload['op']
        if op=='close':self.alive[sid]=False;return {'status':'closed','running':False}
        if op=='status':return {'status':'running','running':self.alive[sid],'prompt_seen':True}
        return {'status':'ok','output':'offline response','prompt_seen':True,'running':True}

    def spawn(self,argv,**kwargs):
        sid=argv[argv.index('--session-id')+1];self.counter+=1
        meta=json.loads((self.directory/f'{sid}.json').read_text());Path(meta['socket']).touch()
        self.alive[sid]=True
        if meta.get('ssh'):
            # A local AF_UNIX fixture is supplied in the runtime suite. Here the
            # privileged worker boundary reports its authenticated control path.
            pass
        return SimpleNamespace(pid=900000+self.counter,poll=lambda:None,kill=lambda:None)

    def boundary(self,argv,**kwargs):
        try:return self.dispatch(argv,**kwargs)
        except (ValueError,PermissionError) as exc:
            return subprocess.CompletedProcess(argv,1,json.dumps({'status':'blocked','error':str(exc),'execution_started':False}),'')

    def dispatch(self,argv,**kwargs):
        self.calls.append(argv)
        def opt(name,default=''):
            return argv[argv.index('--'+name)+1] if '--'+name in argv else default
        root=argv[:4]==['sudo','-n',sessions.BROKER,'session']
        if root or 'session' in argv:
            action=opt('action');sid=opt('session-id');owner=opt('owner');pid=int(opt('owner-pid','0'))
            if action=='open':
                args=json.loads(opt('argv-json','[]')) if '--argv-json' in argv else None
                reply=broker.session_open(11,args,int(opt('idle','1800')),owner,pid,
                    json.loads(opt('ssh-json')) if opt('ssh-json') else None,opt('resource'),opt('username'),opt('purpose'))
            elif action=='list':reply=broker.session_list(11,bool(int(opt('check-remote','0'))))
            elif action=='release':reply=broker.session_access(11,sid,'release',owner=owner,owner_pid=pid)
            elif action=='close':reply=broker.session_close(11,sid,owner,pid)
            else:reply=broker.session_access(11,sid,action,owner=owner,owner_pid=pid,data=opt('data'),wait=opt('wait','0'))
        elif argv[:4]==['sudo','-n',sessions.BROKER,'pivot']:
            reply=broker.pivot_prepare(11,json.loads(opt('spec-json'))) if opt('action')=='prepare' else broker.pivot_action(11,opt('action'),opt('request-id'))
        else:raise AssertionError('Unexpected privileged/external operation: '+str(argv))
        return subprocess.CompletedProcess(argv,0,json.dumps(reply),'')

    def call(self,name='pm_session',**kwargs):
        blocks=asyncio.run(self.server.mcp.call_tool(name,{'task_id':11,**kwargs}))
        if isinstance(blocks,tuple):blocks=blocks[0]
        return json.loads(next(b.text for b in blocks if getattr(b,'type',None)=='text'))

    def open(self,**kwargs):return self.call(action='open',resource='10.0.0.1',username='candidate-user',purpose='retained shell',**kwargs)

    def test_session_handoff_releases_owner_without_closing_connection(self):
        with self.case.connect() as db:
            with sessions.role_scope(db,11,'first role'):
                sid=self.open()['session_id']
                first=broker.session_meta(11,sid)['owner']
            self.assertEqual(broker.session_meta(11,sid)['owner'],'')
            self.assertTrue(self.alive[sid])
            with sessions.role_scope(db,11,'second role'):
                reply=self.call(action='read',session_id=sid)
                self.assertEqual(reply['output'],'offline response')
                self.assertNotEqual(broker.session_meta(11,sid)['owner'],first)
            self.assertTrue(self.alive[sid]);self.assertEqual(sessions.listing(db,11)[0]['liveness'],'unknown')

    def test_second_live_owner_cannot_send_or_consume_the_terminal(self):
        with patch.dict(os.environ,{'PM_SESSION_OWNER':'agent:first'}):sid=self.open()['session_id']
        count=len(self.calls)
        with patch.dict(os.environ,{'PM_SESSION_OWNER':'agent:second'}):
            reply=self.call(action='send',session_id=sid,data='echo second\n')
            self.assertEqual(reply['kind'],'session_busy');self.assertFalse(reply['execution_started'])
            self.assertEqual(self.call(action='read',session_id=sid)['kind'],'session_busy')
        self.assertEqual(len(self.calls),count+2)

    def test_unknown_input_is_not_sent_again_and_failed_health_is_not_alive(self):
        sid=self.open()['session_id'];self.health_failure=True
        reply=self.call(action='send',session_id=sid,data='do_not_repeat\n')
        self.assertEqual(reply['status'],'unknown')
        self.health_failure=False
        again=self.call(action='send',session_id=sid,data='other command\n')
        self.assertEqual(again['reason_category'],'outcome_unknown')
        self.health_failure=True
        with self.case.connect() as db:
            sessions.reconcile(db,11)
            self.assertEqual(sessions.listing(db,11)[0]['state'],'unknown')

    def test_unused_session_closes_but_route_dependency_keeps_source(self):
        with self.case.connect() as db:
            with sessions.role_scope(db,11,'short lived'):
                sid=self.open(retain=False)['session_id']
            self.assertFalse(self.alive[sid])
            with sessions.role_scope(db,11,'dependent work'):
                sid=self.open(retain=False)['session_id']
                db.execute('INSERT INTO pm_session_dependencies VALUES(?,?,?,?)',(11,sid,'pivot:1','active'));db.commit()
            self.assertTrue(self.alive[sid])

    def test_quota_ten_and_disconnect_updates_dependent_routes(self):
        sids=[self.open()['session_id'] for _ in range(10)]
        reply=self.open();self.assertEqual(reply['status'],'blocked');self.assertIn('Too many',reply['error'])
        with self.case.connect() as db:
            db.execute('INSERT INTO pm_session_dependencies VALUES(?,?,?,?)',(11,sids[0],'pivot:1','active'))
            self.alive[sids[0]]=False;sessions.reconcile(db,11)
            item=next(s for s in sessions.listing(db,11) if s['session_id']==sids[0])
            self.assertEqual(item['state'],'disconnected');self.assertEqual(item['dependencies'][0]['state'],'broken_source')

    def test_true_run_role_passes_one_connection_to_the_next_role(self):
        owner=self;seen=[];sid=[]
        class Harness:
            def __init__(self,**options):self.options=options
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def start_session(self,name):
                def run(prompt,**kwargs):
                    owner.assertEqual(self.options['env']['PM_SESSION_OWNER'],sessions.owner())
                    seen.append(prompt)
                    if not sid:sid.append(owner.open()['session_id'])
                    else:owner.assertEqual(owner.call(action='read',session_id=sid[0])['output'],'offline response')
                    Path(self.options['env']['PM_AGENT_STATS_FILE']).write_text(json.dumps({'calls':1,'tool_events':1,'reads':0,'denied':0,'sessions':1}))
                    return SimpleNamespace(finish_reason='completed',events=[],final_response=json.dumps({
                        'summary':'Saved connection retained; no goal claim.','findings':[],'hypotheses':[], 'flags':[],
                        'verified':[],'uncertainties':[],'proposed_actions':[]}))
                return SimpleNamespace(run=run)
        with patch.dict(sys.modules,{'deepseek_harness':SimpleNamespace(DeepSeekHarness=Harness)}),\
             patch.object(agent_actions,'DSH_HOME',self.case.root/'dsh'),patch.object(agent_actions,'WORKSPACE',self.case.root/'sdk'):
            agent_actions.run_role(11,'recon','Retain useful connection',1,api_key='fake-only')
            agent_actions.run_role(11,'vuln','Use the saved connection',2,api_key='fake-only')
        self.assertEqual(self.counter,1);self.assertTrue(self.alive[sid[0]])
        self.assertIn('retained shell',seen[1]);self.assertEqual(broker.session_meta(11,sid[0])['owner'],'')

    def prepare_pivot(self):
        configured=resources.resolve('10.0.0.1',area='lab',networks=['10.2.0.0/24'])
        with self.case.connect() as db:
            resources.save(db,11,configured);db.execute('UPDATE task_scope_settings SET allow_pivot=1,allow_port_forward=1 WHERE task_id=11')
            db.execute('UPDATE pm_operator_approvals SET allowed=? WHERE task_id=11',
                       (','.join(resources.grants(configured['policy'])),))
            self.ref=resources.node(db,11,'address','10.2.0.5',configured['policy']['machine'])
        self.config['resource_policy']=configured['policy']
        sid=self.open(ssh_json=json.dumps({'target':'10.0.0.1','port':22,'user':'student','identity':''}))['session_id']
        control=Path(broker.session_meta(11,sid)['ssh']['control_root'])/'control'
        # is_socket validation is exercised without a privileged process.
        sock=socket.socket(socket.AF_UNIX);sock.bind(str(control));self.socket_handles.append(sock)
        return {'source_session':sid,'resource_ref':self.ref,'destination':'10.2.0.5','port':8080,
            'local_port':18888,'probe':'http_headers','purpose':'Reach internal saved web service'}

    def test_pivot_decline_does_not_create_tunnel_or_reask(self):
        spec=self.prepare_pivot()
        reply=self.call('pm_pivot_request',spec_json=json.dumps(spec))
        with self.case.connect() as db:operator_questions.answer(db,11,reply['question_id'],'decline','Use another known host')
        self.assertEqual(self.call('pm_pivot',route_id=reply['route']['id'],action='apply')['state'],'declined')
        self.assertEqual(self.call('pm_pivot_request',spec_json=json.dumps(spec))['question_id'],reply['question_id'])
        from orchestrator import coordinated_attack
        model=self.case.model([fixture.decision('vuln','Use the known HTTP service instead of the refused pivot'),fixture.decision()])
        result=coordinated_attack.run(11,api_key='fake-only',model=model,role_runner=self.case.role)
        self.assertEqual([r[0] for r in self.case.calls],['vuln'])
        self.assertEqual(self.case.prompts[0]['pivot_routes'][0]['state'],'declined')
        self.assertFalse(result['succeeded'])
        with self.case.connect() as db:state=coordinated_attack.snapshot(db,11,1)
        decision=fixture.decision(action='wait_operator',references=['intent','session:'+spec['source_session']])
        decision.update(operator_question={'kind':'pivoting','request':spec},branch_id=spec['resource_ref'])
        decision['boundaries']['resource_refs']=[spec['resource_ref']]
        with self.assertRaisesRegex(ValueError,'pivot_previously_declined'):
            coordinated_attack.parse_decision(decision,state,agent_actions.ROLES)

    def test_pivot_approval_is_scoped_idempotent_and_breaks_with_its_source(self):
        spec=self.prepare_pivot()
        def command(*argv,**kwargs):
            self.tunnel_commands.append(argv)
            if '/usr/bin/ssh' in argv:return subprocess.CompletedProcess(argv,0,'','')
            return subprocess.CompletedProcess(argv,0,'HTTP/1.1 404 Not Found\r\n\r\n','')
        reply=self.call('pm_pivot_request',spec_json=json.dumps(spec));rid=reply['route']['id']
        self.assertEqual(self.call('pm_pivot',route_id=rid,action='apply')['state'],'pending')
        with patch.object(broker,'cmd',side_effect=command),self.case.connect() as db:
            operator_questions.answer(db,11,reply['question_id'],'approve');db.commit()
            installed=pivoting.apply(db,11,rid,authorize=True)
            self.assertEqual(installed['state'],'active',installed)
            pivoting.apply(db,11,rid);pivoting.apply(db,11,rid)
            self.assertEqual(sum('/usr/bin/ssh' in a for a in self.tunnel_commands),1)
            self.alive[spec['source_session']]=False;sessions.reconcile(db,11)
            self.assertEqual(pivoting.listing(db,11)[0]['state'],'broken_source')
            self.assertEqual(pivoting.apply(db,11,rid)['state'],'broken_source')
        self.assertEqual(len(self.tunnel_commands),2)

    def test_pivot_does_not_expand_scope_or_reinterpret_an_address(self):
        spec=self.prepare_pivot()
        reply=self.call('pm_pivot_request',spec_json=json.dumps({**spec,'destination':'10.9.0.1'}))
        self.assertEqual(reply['status'],'blocked')
        with self.case.connect() as db:db.execute('UPDATE task_scope_settings SET allow_port_forward=0 WHERE task_id=11')
        self.assertEqual(self.call('pm_pivot_request',spec_json=json.dumps(spec))['status'],'blocked')
        with self.case.connect() as db:
            db.execute('UPDATE task_scope_settings SET allow_pivot=0 WHERE task_id=11')
        self.assertEqual(self.call('pm_pivot_request',spec_json=json.dumps(spec))['status'],'blocked')

    def test_status_does_not_apply_an_authorized_but_unstarted_forward(self):
        spec=self.prepare_pivot();reply=self.call('pm_pivot_request',spec_json=json.dumps(spec));rid=reply['route']['id']
        with self.case.connect() as db:
            operator_questions.answer(db,11,reply['question_id'],'approve')
        broker.pivot_action(11,'authorize',reply['route']['receipt']['request_id'])
        with patch.object(broker,'cmd',side_effect=AssertionError('Status must never create/probe a forward')):
            current=self.call('pm_pivot',route_id=rid,action='status')
        self.assertEqual(current['state'],'approved')

    def test_ssh_restart_checks_existing_connection_without_fallback_authentication(self):
        spec=self.prepare_pivot();commands=[]
        def run(*argv,**kwargs):
            commands.append(argv);return subprocess.CompletedProcess(argv,0,'','')
        with patch.object(broker,'cmd',side_effect=run),self.case.connect() as db:
            sessions.reconcile(db,11)
            item=sessions.listing(db,11)[0]
            self.assertTrue(item['details']['connection_ready'])
        self.assertIn('ProxyCommand=/usr/bin/false',commands[0]);self.assertEqual(commands[0][-1],'true')
        with patch.object(broker,'cmd',side_effect=subprocess.TimeoutExpired('existing connection',3)),self.case.connect() as db:
            sessions.reconcile(db,11)
            self.assertEqual(sessions.listing(db,11)[0]['state'],'unknown')

    def test_new_owner_does_not_bypass_duplicate_command_guard(self):
        with patch.dict(os.environ,{'PM_SESSION_OWNER':'agent:first'}):
            sid=self.open()['session_id'];self.call(action='send',session_id=sid,data='same-check\n')
        broker.session_access(11,sid,'release',owner='agent:first',owner_pid=os.getpid())
        count=len(self.calls)
        with patch.dict(os.environ,{'PM_SESSION_OWNER':'agent:second'}):
            again=self.call(action='send',session_id=sid,data='same-check\n')
        self.assertEqual(again['kind'],'repeat_guard');self.assertEqual(len(self.calls),count)

    def test_local_terminal_output_is_not_asserted_to_be_remote_access(self):
        sid=self.open()['session_id'];self.call(action='send',session_id=sid,data='whoami\n')
        records=[json.loads(line) for line in (agent_actions.CAPABILITY_LOG/'task_11.jsonl').read_text().splitlines()]
        self.assertEqual(records[0]['provenance'],'local');self.assertEqual(records[-1]['provenance'],'unknown')

    def test_dead_actor_is_reclaimed_even_if_birth_stamp_was_not_saved(self):
        sid=self.open()['session_id'];path=self.directory/f'{sid}.json';meta=json.loads(path.read_text())
        meta.update(owner='dead:actor',owner_pid=999999,owner_birth='');path.write_text(json.dumps(meta))
        with patch.dict(os.environ,{'PM_SESSION_OWNER':'agent:recovered'}):
            result=self.call(action='read',session_id=sid)
        self.assertEqual(result['status'],'ok');self.assertEqual(result['owner'],'agent:recovered')

    def test_scope_change_keeps_history_but_forbids_old_peer_input_and_health_exec(self):
        spec=self.prepare_pivot();sid=spec['source_session']
        self.config['allowed']=['10.0.0.9/32','10.2.0.0/24']
        self.config['resource_policy']=resources.resolve('10.0.0.9',area='lab',networks=['10.2.0.0/24'])['policy']
        with patch.object(broker,'cmd',side_effect=AssertionError('Must not execute outside current scope')):
            result=broker.session_send(11,sid,'do-not-send',0,sessions.owner(),os.getpid())
            self.assertEqual(result['status'],'blocked');self.assertFalse(result['execution_started'])
            self.assertEqual(broker.ssh_health(11,broker.session_meta(11,sid))['status'],'unverified')
            self.assertEqual(broker.session_read(11,sid,0,sessions.owner(),os.getpid())['status'],'ok')

    def test_interactive_repeat_requires_changed_stream_state_not_own_identical_reply(self):
        sid=self.open()['session_id'];executed=[]
        def worker(meta,request,**kwargs):
            executed.append(request['op'])
            text='' if request['op']=='read' else 'context changed' if request.get('data')=='cd /work\n' else 'same inspection'
            return {'status':'ok','running':True,'output':text,'prompt_seen':True}
        with patch.object(broker,'session_request',side_effect=worker):
            first=self.call(action='send',session_id=sid,data='inspect\n')
            self.assertEqual(first['status'],'ok')
            self.assertEqual(self.call(action='send',session_id=sid,data='inspect\n')['kind'],'repeat_guard')
            self.call(action='read',session_id=sid)
            self.assertEqual(self.call(action='send',session_id=sid,data='inspect\n')['kind'],'repeat_guard')
            self.call(action='send',session_id=sid,data='cd /work\n')
            self.assertEqual(self.call(action='send',session_id=sid,data='inspect\n')['status'],'ok')
        self.assertEqual(executed.count('send'),3)
        with self.case.connect() as db:
            saved=sessions.listing(db,11)[0]
            self.assertNotIn('output',saved['details'])
            self.assertIn('stream_state_sha256',saved['details'])


class CallbackPolicyTests(unittest.TestCase):
    def test_broker_status_preserves_saved_resource_policy_for_pm_reconciliation(self):
        policy={'version':1,'area':'lab','machine':'task:11:machine'}
        config={'allowed':['10.0.0.1/32'],'egress':'tun0','host_ip':'172.31.11.1','resource_policy':policy}
        output=io.StringIO()
        with patch.object(sys,'argv',['pm-netguard','status','--task-id','11']),\
             patch.object(broker,'owned_config',return_value=({},config)),redirect_stdout(output):broker.main()
        self.assertEqual(json.loads(output.getvalue())['resource_policy'],policy)

    def test_manual_callback_override_survives_restart_without_changing_scope(self):
        with tempfile.TemporaryDirectory(prefix='pm-callback-config-') as directory:
            path=Path(directory)/'task.json';path.write_text(json.dumps({'uid':os.getuid(),'allowed':['10.0.0.1/32']}))
            def config(task):return {'config':path},json.loads(path.read_text())
            def ip(*argv,**kwargs):
                value=[{'dev':'ens33','prefsrc':'192.168.1.10'}] if 'route' in argv else [{'addr_info':[{'local':'10.8.0.42'}]}]
                return subprocess.CompletedProcess(argv,0,json.dumps(value),'')
            with patch.object(broker,'ensure_root'),patch.object(broker,'owned_config',side_effect=config),patch.object(broker,'cmd',side_effect=ip):
                broker.callback_configure(11,'10.8.0.42','taplab','198.51.100.20','Explicit laboratory NAT mapping',5)
                selected=broker.callback_selection(11)
                self.assertEqual(selected['source'],'operator');self.assertEqual(selected['advertise'],'198.51.100.20')
                saved=json.loads(path.read_text());self.assertEqual(saved['allowed'],['10.0.0.1/32'])
                self.assertEqual(saved['callback_override']['variant_limit'],5);self.assertEqual(len(saved['callback_override_history']),1)

    def test_callback_variants_have_a_persisted_finite_budget(self):
        with tempfile.TemporaryDirectory(prefix='pm-callback-budget-') as directory:
            root=Path(directory);out=root/'out';state=root/'state'
            config={'uid':os.getuid(),'allowed':['10.0.0.1/32']}
            selection={'target':'10.0.0.1','bind':'10.8.0.42','advertise':'10.8.0.42','interface':'tun0','source':'route','route_fingerprint':'same-route'}
            def launch(argv,**kwargs):
                port=argv[argv.index('--port')+1];(state/(port+'.ready')).write_text(json.dumps({'pid':999999}))
                return SimpleNamespace(pid=999999,poll=lambda:None)
            with patch.object(broker,'ensure_root'),patch.object(broker,'owned_config',return_value=({},config)),\
                 patch.object(broker,'callback_selection',return_value=selection),patch.object(broker,'callback_paths',return_value=(out,state)),\
                 patch.object(broker.os.path,'realpath',return_value='/usr/local/sbin/pm-netguard'),patch.object(broker.subprocess,'Popen',side_effect=launch) as spawn:
                for port in (18001,18002,18003):self.assertEqual(broker.callback_open(11,port,'',30)['status'],'listening')
                with self.assertRaisesRegex(ValueError,'variant_budget_exhausted'):broker.callback_open(11,18004,'',30)
                self.assertEqual(spawn.call_count,3)

    def test_current_tun_route_is_used_and_nat_or_old_vpn_is_not_guessed(self):
        config={'allowed':['10.0.0.1/32']}
        route={'dev':'tun0','prefsrc':'10.8.0.42'};addresses=['10.8.0.42']
        def ip(*argv,**kwargs):
            value=[route] if 'route' in argv else [{'addr_info':[{'local':a} for a in addresses]}]
            return subprocess.CompletedProcess(argv,0,json.dumps(value),'')
        with patch.object(broker,'owned_config',return_value=({},config)),patch.object(broker,'cmd',side_effect=ip):
            chosen=broker.callback_selection(11);self.assertEqual(chosen['bind'],'10.8.0.42');self.assertEqual(chosen['interface'],'tun0')
            route['dev']='ens33';route['prefsrc']='192.168.152.10'
            with self.assertRaisesRegex(ValueError,'NAT/VMware'):broker.callback_selection(11)
            route.update(dev='tun0',prefsrc='10.8.0.3')
            with self.assertRaisesRegex(ValueError,'no longer configured'):broker.callback_selection(11)

    def test_callback_network_diagnosis_uses_only_fresh_current_task_preflight(self):
        case=fixture.CoordinatorTests();case.setUp();self.addCleanup(case.doCleanups)
        with case.connect() as db:
            db.execute('CREATE TABLE pm_tcp_full_scan_attempts(id INTEGER PRIMARY KEY,task_id INTEGER,target TEXT,status TEXT,error TEXT,created_at TEXT)')
            db.execute('INSERT INTO pm_tcp_full_scan_attempts VALUES(1,11,?,?,?,?)',('10.0.0.1','preflight_fail',
                json.dumps({'reachable':[],'unreachable':[22,80],'unchecked':[]}),sessions.now()))
            waiting={'diagnosis':'waiting_no_callback','status':'listening'}
            result=sessions.callback_assessment(db,11,waiting)
            self.assertIn('checked_target_ports_unreachable',result['diagnosis'])
            db.execute('UPDATE pm_tcp_full_scan_attempts SET error=?',(json.dumps({'reachable':[],'unreachable':[22],'unchecked':[80]}),))
            self.assertIn('preflight_incomplete',sessions.callback_assessment(db,11,waiting)['diagnosis'])
            db.execute('UPDATE pm_tcp_full_scan_attempts SET error=?',(json.dumps({'reachable':[80],'unreachable':[],'unchecked':[]}),))
            self.assertIn('egress_restrictions_possible_not_proven',sessions.callback_assessment(db,11,waiting)['diagnosis'])
            self.assertEqual(sessions.callback_assessment(db,11,{'diagnosis':'receiver_unavailable'})['diagnosis'],'receiver_unavailable')
            db.execute("UPDATE pm_tcp_full_scan_attempts SET target='10.9.9.9'")
            self.assertEqual(sessions.callback_assessment(db,11,waiting)['saved_preflight']['status'],'unknown')


if __name__=='__main__':unittest.main()
