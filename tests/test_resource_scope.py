"""Offline resource scope: no DNS, target, privileged broker or model traffic."""
import importlib.util
import asyncio
import base64
import argparse
import json
from pathlib import Path
import sqlite3
import tempfile
import subprocess
import sys
import os
import unittest
from unittest.mock import patch, Mock

import pm
from executor import netguard_root as broker
from orchestrator import resources,task_memory,task_runtime,agent_actions as actions,coordinated_attack as coordinator
from tests import test_http_capture_mcp as capture_fixture
from tests import test_coordinated_attack as coordinator_fixture
from urllib.parse import urlencode


class ResourceRegressionTests(unittest.TestCase):
    def test_ipv6_is_accepted_as_a_concrete_target(self):
        self.assertEqual(pm.validate_target('fd20::80'),'fd20::80')

    def test_domain_and_url_are_preserved_at_input(self):
        self.assertEqual(pm.validate_target('app.lab'),'app.lab')
        value='https://app.lab:8443/a/b?q=a%2Fb&next=2#tab'
        self.assertEqual(pm.validate_target(value),value)

    def test_http_query_survives_and_fragment_is_browser_only(self):
        args=broker.tool_args('http_capture','10.10.1.5',8443,'','https',
                              '/a?q=one%2Ftwo#section','app.lab')
        self.assertEqual(args[-1],'https://app.lab:8443/a?q=one%2Ftwo')

    def test_ipv6_curl_pins_address_and_preserves_sni(self):
        args=broker.tool_args('http_capture','fd20::80',443,'','https','/','app.lab')
        self.assertIn('app.lab:443:[fd20::80]',args)
        self.assertEqual(args[-1],'https://app.lab:443/')
        self.assertIn('--globoff',args)

    def test_invalid_ports_and_malformed_ipv6_are_not_silently_normalized(self):
        for value in ('https://app.lab:0/','https://user:secret@app.lab/','[fd20::80','[[fd20::80]]','fd20::80%tun0'):
            with self.subTest(value=value),self.assertRaises(pm.OperatorError):pm.validate_target(value)

    def test_bare_domain_grants_standard_web_origins_but_never_host_scan(self):
        config=resources.resolve('app.lab',addresses=['10.0.0.1'],aliases=['other.lab'])
        self.assertEqual({o['origin'] for o in config['policy']['origins']},
                         {'http://app.lab:80','https://app.lab:443','http://other.lab:80','https://other.lab:443'})
        with self.assertRaises(ValueError):broker.authorize_resource(config['policy'],'tcp_full','10.0.0.1')

    def test_literal_ip_url_cannot_be_reinterpreted_as_another_vhost_or_kali_loopback(self):
        for value in ('http://127.0.0.1/','http://[::1]/','http://10.0.0.1/'):
            with self.subTest(value=value),self.assertRaises(ValueError):resources.resolve(value,addresses=['10.0.0.2'])

    def test_explicit_host_area_for_literal_ip_url_needs_no_dns_or_duplicate_pin(self):
        with patch.object(resources.socket,'getaddrinfo',side_effect=AssertionError('No DNS for IP URL')):
            config=resources.resolve('https://[fd20::80]:8443/a?q=1#b',area='host')
        self.assertEqual(config['policy']['host_addresses'],['fd20::80'])
        self.assertFalse(resources.web_entry(config['entry'],'host'))

    def test_executor_scope_import_works_in_child_without_external_pythonpath(self):
        checkout=Path(__file__).resolve().parents[1]
        code=('import sys,sqlite3;sys.path.insert(0,sys.argv[1]);from task_scope import check_action;'
              'db=sqlite3.connect(":memory:");db.executescript('
              '"CREATE TABLE task_scope_settings(task_id,initial_target,allow_pivot,allow_port_forward);'
              "INSERT INTO task_scope_settings VALUES(11,'10.0.0.1',1,1);"+'"'+');'
              'print(check_action(db,11,"connect","10.0.0.1")["decision"])')
        env={k:v for k,v in os.environ.items() if k!='PYTHONPATH'}
        with tempfile.TemporaryDirectory(prefix='pm-resource-import-') as directory:
            result=subprocess.run([sys.executable,'-c',code,str(checkout/'executor')],cwd=directory,env=env,
                                  capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout.strip(),'ALLOW')

    def test_idna_and_unicode_uri_keep_original_input_and_encode_request_bytes(self):
        original='https://пример.рф/путь?q=текст#раздел'
        parsed=resources.parse(original)
        self.assertEqual(parsed['input'],original)
        self.assertEqual(parsed['host'],'xn--e1afmkfd.xn--p1ai')
        self.assertIn('/%D0%BF',parsed['request_path'])
        self.assertEqual(parsed['fragment'],'раздел');self.assertNotIn('#',parsed['request_url'])


class ResourceIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.capture=capture_fixture.CaptureMCPTests()
        self.capture.broker=self.broker
        self.capture.setUp();self.addCleanup(self.capture.doCleanups)
        self.case=self.capture.case;self.calls=[]
        self.server=capture_fixture.server
        self.body=b'<html><a href="/next?q=2#part">next</a><script src="https://cdn.example/lib.js"></script></html>'
        with self.case.connect() as db:
            db.execute("ALTER TABLE pm_operator_approvals ADD COLUMN egress TEXT DEFAULT 'tun0'")
            db.execute('ALTER TABLE pm_operator_approvals ADD COLUMN approved_at TEXT')
            db.execute('ALTER TABLE pm_task_intents ADD COLUMN created_at TEXT')
            db.execute('CREATE TABLE pm_task_hostnames(task_id INTEGER PRIMARY KEY,hostnames_json TEXT)')
            pm.initialize_tcp_scans(db)

    def configure(self,raw='http://app.lab/start?q=a%2Fb#tab',**kwargs):
        config=resources.resolve(raw,addresses=kwargs.pop('addresses',['10.0.0.1']),**kwargs)
        with self.case.connect() as db:
            db.execute('UPDATE tasks SET target=?',(config['target'],))
            db.execute('UPDATE task_scope_settings SET initial_target=?',(config['target'],))
            db.execute('UPDATE pm_operator_approvals SET target=?,allowed=?',
                       (config['target'],','.join(config['networks'])))
            resources.save(db,11,config)
        return config

    def broker(self,command,**kwargs):
        """Only privileged subprocess boundary is replaced; apply the real policy."""
        if command[-1]=='capabilities':
            class Capabilities:
                args=command;returncode=0
                def __enter__(self):return self
                def __exit__(self,*args):return False
                def communicate(self,input=None,timeout=None):return json.dumps({'capture_protocol':1,'profiles':['http_capture'],'capture_limits':[2*1024*1024,8*1024*1024]}),''
                def poll(self):return 0
            return Capabilities()
        def arg(name,default=''):
            return command[command.index('--'+name)+1] if '--'+name in command else default
        target=arg('target');scheme=arg('scheme');host=arg('hostname');port=int(arg('port'));path=arg('path')
        with self.capture.case.connect() as db:
            scope=resources.saved(db,11)
            if scope:
                broker.authorize_resource(scope['policy'],'ssrf' if arg('ssrf-destination') else 'http',target,
                    scheme=scheme,hostname=host,port=port,path=path,destination=arg('ssrf-destination'),context=arg('ssrf-context'))
        if arg('ssrf-destination'):path+=('&' if '?' in path else '?')+urlencode({arg('ssrf-parameter'):arg('ssrf-destination')})
        self.calls.append(command)
        wire=b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '+str(len(self.body)).encode()+b'\r\n\r\n'+self.body
        payload={'capture_protocol':1,'task_id':11,'target':target,'profile':'http_capture','scheme':scheme,
            'hostname':host,'port':port,'path':path,'status':'completed','exit_code':0,'response_bytes':len(wire),
            'response_b64':base64.b64encode(wire).decode(),'capture_truncated':False}
        class Process:
            args=command;returncode=0
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def communicate(self,input=None,timeout=None):return json.dumps(payload),''
            def poll(self):return 0
        return Process()

    def tool(self,name='pm_http_capture',**kwargs):
        args={'task_id':11,**kwargs}
        if name=='pm_http_capture':args={'target':'10.0.0.1','hostname':'app.lab','port':80,'path':'/start?q=a%2Fb#tab',**args}
        blocks=asyncio.run(self.server.mcp.call_tool(name,args))
        if isinstance(blocks,tuple):blocks=blocks[0]
        return json.loads(next(b.text for b in blocks if getattr(b,'type',None)=='text'))

    def args(self,*values):
        import sys
        with patch.object(sys,'argv',['pm',*values]):return pm.parser_main()[1]

    def test_url_capture_retains_query_fragment_and_external_relationship_without_permission(self):
        self.configure()
        result=self.tool();self.assertEqual(result['status'],'completed')
        self.assertEqual(len(self.calls),1)
        self.assertIn('/start?q=a%2Fb',self.calls[0]);self.assertNotIn('/start?q=a%2Fb#tab',self.calls[0])
        with self.case.connect() as db:
            graph=resources.graph(db,11)
            self.assertEqual(graph['entry']['fragment'],'tab')
            self.assertEqual(graph['entry']['query'],'q=a%2Fb')
            cdn=next(r for r in graph['resources'] if r['value']=='https://cdn.example:443/lib.js')
            self.assertNotIn(cdn['id'],graph['authorized_resources'])
            self.assertTrue(any(r['relation']=='page_dependency' and r['destination']==cdn['id'] for r in graph['relations']))
            self.assertIn(result['artifact_ref'],[r['evidence'] for r in graph['relations']])
            with self.assertRaises(ValueError):resources.authorize(db,11,'scan','10.0.0.1')
        self.assertEqual(self.tool(hostname='cdn.example')['status'],'blocked')
        self.assertEqual(len(self.calls),1)

    def test_generic_exec_and_poc_cannot_turn_web_dns_into_host_permission(self):
        self.configure()
        result=self.tool('pm_net_exec',target='10.0.0.1',argv_json=json.dumps(['/usr/bin/nmap','-p','22','10.0.0.1']))
        self.assertEqual(result['status'],'blocked');self.assertEqual(self.calls,[])
        policy=self.configure_policy()
        for operation in ('poc_run','tcp_full','exec','session'):
            with self.subTest(operation=operation),self.assertRaises(ValueError):broker.authorize_resource(policy,operation,'10.0.0.1')

    def configure_policy(self):
        with self.case.connect() as db:return resources.saved(db,11)['policy']

    def test_multiple_addresses_and_vhosts_have_pinned_origin_specific_grants(self):
        answers=[(2,1,6,'',('10.0.0.1',0)),(10,1,6,'',('fd20::80',0,0,0)),(2,1,6,'',('10.0.0.2',0))]
        config=resources.resolve('https://app.lab:8443/?x=1',aliases=['other.lab'],resolver=Mock(return_value=answers))
        self.assertEqual(config['policy']['addresses'],['10.0.0.1','10.0.0.2','fd20::80'])
        with self.case.connect() as db:
            resources.save(db,11,config)
            db.execute('UPDATE pm_operator_approvals SET allowed=?',(','.join(config['networks']),))
        result=self.tool(target='fd20::80',scheme='https',port=8443,hostname='other.lab',path='/?x=1')
        self.assertEqual(result['status'],'completed')
        self.assertEqual(self.tool(target='fd20::81',scheme='https',port=8443)['status'],'blocked')
        self.assertEqual(self.tool(scheme='https',port=443)['status'],'blocked')
        self.assertEqual(len(self.calls),1)
        with self.case.connect() as db:
            resources.rebind(db,11,'fd20::80',[22,80])
            current=resources.saved(db,11)
            self.assertEqual(current['policy']['addresses'],['fd20::80','10.0.0.2'])
            self.assertEqual(current['policy']['origins'][0]['addresses'],['fd20::80','10.0.0.2'])

    def test_allowed_ssrf_reaches_target_loopback_via_app_without_kali_contact_and_reuses_capture(self):
        self.configure(ssrf=['http://127.0.0.1:8080/private?x=1'])
        result=self.tool('pm_http_ssrf',application='http://app.lab/fetch?kind=text#browser',
                         destination='http://127.0.0.1:8080/private?x=1')
        self.assertEqual(result['status'],'completed');self.assertEqual(len(self.calls),1)
        command=self.calls[0]
        self.assertEqual(command[command.index('--target')+1],'10.0.0.1')
        self.assertIn('task:11:machine',command)
        again=self.tool('pm_http_ssrf',application='http://app.lab/fetch?kind=text',destination='http://127.0.0.1:8080/private?x=1')
        self.assertTrue(again['cached']);self.assertEqual(len(self.calls),1)
        with self.case.connect() as db:
            row=db.execute('SELECT metadata_json FROM pm_http_artifacts').fetchone()
            self.assertEqual(json.loads(row[0])['route']['context'],'task:11:machine')
            self.assertNotIn('#',json.loads(row[0])['request']['path'])

    def test_ssrf_outside_grant_wrong_context_and_explicit_room_exclusion_are_denied(self):
        self.configure(ssrf=['http://127.0.0.1:8080/private'])
        for dest,context in [('http://127.0.0.1:8081/private',''),('http://10.9.9.9/private',''),('http://127.0.0.1:8080/private','kali')]:
            with self.subTest(dest=dest,context=context):
                self.assertEqual(self.tool('pm_http_ssrf',application='http://app.lab/fetch',destination=dest,context=context)['status'],'blocked')
        self.assertEqual(self.calls,[])
        policy=self.configure_policy();policy['denied']=['127.0.0.1/32']
        with self.assertRaises(ValueError):broker.authorize_resource(policy,'ssrf','10.0.0.1',hostname='app.lab',
            destination='http://127.0.0.1:8080/private',context=policy['machine'])

    def test_laboratory_ssrf_is_allowed_within_explicit_network_and_not_outside_it(self):
        self.configure(area='lab',networks=['10.44.0.0/24'])
        result=self.tool('pm_http_ssrf',application='http://app.lab/fetch',destination='http://10.44.0.9/admin')
        self.assertEqual(result['status'],'completed')
        self.assertEqual(self.tool('pm_http_ssrf',application='http://app.lab/fetch',destination='http://10.45.0.9/admin')['status'],'blocked')
        self.assertEqual(len(self.calls),1)

    def test_pivot_question_is_persistent_and_does_not_expand_authority_on_answer(self):
        self.configure()
        from orchestrator import operator_questions
        with self.case.connect() as db:
            reference=resources.observe_link(db,11,'http://app.lab/','http://internal.lab/',evidence='saved-link')
            question=resources.pivot_question(db,11,reference,'Resource requires a route through the application')
        with self.case.connect() as db:
            self.assertEqual(operator_questions.listing(db,11,pending=True)[0]['references'],[reference])
            operator_questions.answer(db,11,question['id'],'information','Route described; no new scope')
            with self.assertRaises(ValueError):resources.authorize(db,11,'http','10.9.0.1',hostname='internal.lab')
        self.assertEqual(self.calls,[])

    def test_graph_is_idempotent_readonly_and_in_full_and_compact_prompts(self):
        self.configure();self.tool()
        with self.case.connect() as db:
            resources.initialize(db);before=db.total_changes
            context=actions.task_context(db,11)
            full=actions.build_prompt(db,context,'vuln','Investigate the saved URL',1,7)
            short=actions.compact_prompt(db,context,'vuln','Investigate the saved URL',1,7,15)
            self.assertEqual(db.total_changes,before)
            for prompt in (full,short):
                self.assertIn('q=a%2Fb',prompt);self.assertIn('app.lab',prompt);self.assertIn('cdn.example',prompt)
                self.assertIn('Investigate the saved URL',prompt);self.assertIn('без брутфорса',prompt)

    def test_rebind_preserves_old_reports_goals_files_and_pending_flag_question(self):
        self.configure(area='host')
        from orchestrator import objectives,operator_questions
        with self.case.connect() as db:
            objectives.save_objectives(db,11,'user.txt',expected_flags=1)
            actions.save_report(db,{'task_id':11,'target':'10.0.0.1'},'access',1,{'summary':'Saved data',
                'flags':[{'value':'opaque old flag','objective_key':'goal','source':'user.txt'}]},1)
            before=db.execute('SELECT * FROM pm_agent_action_reports').fetchall()
            question=operator_questions.listing(db,11,pending=True)[0]
            report=(actions.REPORT_DIR/'task_11'/'access-01.json').read_bytes()
            resources.rebind(db,11,'10.0.0.2',[22,80])
            self.assertEqual(db.execute('SELECT * FROM pm_agent_action_reports').fetchall(),before)
            self.assertEqual(operator_questions.listing(db,11,pending=True)[0]['id'],question['id'])
            operator_questions.answer(db,11,question['id'],'approve','Platform accepted while target off')
            self.assertEqual(objectives.objective_status(db,11)['primary']['status'],'confirmed')
            self.assertEqual((actions.REPORT_DIR/'task_11'/'access-01.json').read_bytes(),report)
            self.assertEqual(resources.machine_targets(db,11),['10.0.0.1','10.0.0.2'])

    def test_same_machine_address_change_does_not_reoffer_a_rejected_flag(self):
        self.configure(area='host')
        from orchestrator import objectives,operator_questions,flag_review
        report={'summary':'Existing candidate','flags':[{'value':'opaque rejected value',
            'objective_key':'goal','source':'user.txt'}]}
        with self.case.connect() as db:
            objectives.save_objectives(db,11,'user.txt',expected_flags=1)
            actions.save_report(db,{'task_id':11,'target':'10.0.0.1'},'access',1,report,1)
            question=operator_questions.listing(db,11,pending=True)[0]
            operator_questions.answer(db,11,question['id'],'decline','Platform rejected this exact value')
            resources.rebind(db,11,'10.0.0.2',[22,80])
            actions.save_report(db,{'task_id':11,'target':'10.0.0.2'},'access',2,report,1)
            self.assertEqual(operator_questions.listing(db,11,pending=True),[])
            proposals=flag_review.listing(db,11)
            self.assertEqual(len(proposals),1)
            self.assertEqual((proposals[0]['status'],proposals[0]['target']),('rejected','10.0.0.1'))

    def console_broker(self,command,**kwargs):
        """Stub only root/network boundary for real PM configuration/preflight."""
        name=command[0]
        if name=='capabilities':return {'resource_policy_protocol':1,'capture_protocol':1,'profiles':['http_capture']},0
        if name=='teardown':self.root_config=None;return {'status':'removed'},0
        if name=='status':return (self.root_config,0) if getattr(self,'root_config',None) else ({'error':'not configured'},1)
        if name=='setup':
            allow=[command[i+1] for i,item in enumerate(command) if item=='--allow']
            policy=json.loads(command[command.index('--resource-policy')+1])
            broker.validate_resource_policy(policy,broker.allow_networks(allow))
            self.root_config={'status':'configured','allowed':allow,'resource_policy':policy,'egress':'tun0','docker_forward_managed':True}
            return self.root_config,0
        if name=='hosts':return {'status':'hosts_ready','destination':self.root_config['resource_policy']['addresses'][0]},0
        if name=='run':
            self.assertEqual(command[command.index('--profile')+1],'exec')
            tokens=[x[7:] for x in command if x.startswith('--argv=')]
            ports=json.loads(tokens[-2]);self.connection_checks=getattr(self,'connection_checks',0)+1
            return {'status':'completed','exit_code':0,'stdout':json.dumps({'reachable':ports,'unreachable':[],'unchecked':[]})},0
        raise AssertionError('Unexpected privileged boundary: '+str(command))

    def console_patches(self):
        from contextlib import ExitStack
        stack=ExitStack();self.addCleanup(stack.close)
        stack.enter_context(patch.object(pm,'connect',self.case.connect))
        stack.enter_context(patch.object(pm,'sudo_checked',side_effect=self.console_broker))
        stack.enter_context(patch.object(pm,'broker_is_trusted'))
        stack.enter_context(patch.object(pm,'sudo_authenticate'))
        stack.enter_context(patch.object(pm,'get_egress',return_value='tun0'))
        stack.enter_context(patch.object(pm,'session_api_key',return_value='fake-only'))
        stack.enter_context(patch.object(pm,'run_full_tcp_scan',side_effect=AssertionError('No repeated full scan')))
        stack.enter_context(patch.object(pm,'call_scheduler',side_effect=AssertionError('No old discovery/analysis pipeline')))
        return stack

    def test_real_new_url_to_capture_to_coordinator_and_role_without_host_scan(self):
        self.console_patches()
        url='http://app.lab/start?q=a%2Fb#tab'
        def planner(target,text,key,context):
            self.assertEqual(target,'10.0.0.1')
            self.assertEqual(context['resource_scope']['entry']['input'],url)
            return 11,{'tasks':[]}
        model=self.case.model([coordinator_fixture.decision('vuln','Inspect the scoped URL'),coordinator_fixture.decision()])
        def role(*args,**kwargs):
            self.assertTrue(self.tool()['cached'])
            return self.case.role(*args,**kwargs)
        with patch.object(pm,'run_planner_with_validation_retry',side_effect=planner),\
             patch.object(coordinator,'choose_with_model',side_effect=lambda prompt,key,tokens:model(prompt,key)),\
             patch.object(actions,'run_role',side_effect=role):
            task=pm.op_new(self.args('new','--target',url,'--address','10.0.0.1','--task','Find flags; no brute force'))
        self.assertEqual(task,11);self.assertEqual(len(self.calls),1)
        self.assertEqual([c[0] for c in self.case.calls],['vuln'])
        self.assertEqual(self.case.prompts[0]['resource_graph']['entry']['input'],url)
        self.assertEqual(self.case.prompts[0]['resource_graph']['policy']['area'],'web')

    def test_web_menu_does_not_offer_an_ignored_legacy_mode(self):
        values=['1','https://app.lab/path?q=1#b','1','Find flags']+['']*8+['0']
        with patch('builtins.input',side_effect=values),patch.object(pm,'op_new') as create,\
             patch.object(pm,'interactive_mode',side_effect=AssertionError('Web has one execution route')):
            pm.interactive()
        self.assertTrue(create.call_args.args[0].coordinated)
        self.assertEqual(create.call_args.args[0].area,'web')

    def test_host_domain_menu_collects_explicit_addresses(self):
        values=['1','app.lab','2','10.0.0.1,fd20::80','1','Find flags']+['']*8+['0']
        with patch('builtins.input',side_effect=values),patch.object(pm,'op_new') as create:
            pm.interactive()
        self.assertEqual(create.call_args.args[0].address,['10.0.0.1','fd20::80'])
        self.assertEqual(create.call_args.args[0].area,'host')

    def test_real_change_ip_checks_connections_once_and_resumes_same_task_without_scan_or_planner(self):
        self.configure('10.0.0.1',area='host')
        with self.case.connect() as db:task_runtime.save_mode(db,11,'coordinated')
        self.console_patches()
        stop=coordinator_fixture.decision();stop['boundaries']['target']='10.0.0.2'
        stop['boundaries']['resource_refs']=['scope:10.0.0.2']
        model=self.case.model([stop])
        with patch.object(pm,'run_planner_with_validation_retry',side_effect=AssertionError('No new task/model plan')),\
             patch.object(coordinator,'choose_with_model',side_effect=lambda prompt,key,tokens:model(prompt,key)):
            result=pm.op_change_ip(self.args('change-ip','11','--target','10.0.0.2'))
        self.assertEqual(result['task_id'],11);self.assertEqual(self.connection_checks,1)
        with self.case.connect() as db:
            self.assertEqual(db.execute('SELECT id,target FROM tasks').fetchall(),[(11,'10.0.0.2')])
            self.assertEqual(db.execute('SELECT target,open_ports_json FROM pm_tcp_full_scans').fetchall(),[('10.0.0.1','[22,80]')])
            self.assertEqual(resources.saved(db,11)['migration']['status'],'connections_checked')
        # A subsequent explicit resume uses the saved route and never rediscovers the host.
        with patch.object(coordinator,'choose_with_model',return_value=json.dumps(stop)):
            pm.op_resume(self.args('resume','11'))
        self.assertEqual(self.connection_checks,1)

    def test_room_exclusions_and_invalid_combinations_fail_before_task_creation(self):
        with patch.object(pm,'session_api_key',side_effect=AssertionError('No API')),\
             patch.object(pm,'run_planner_with_validation_retry',side_effect=AssertionError('No planner')):
            with self.assertRaises((ValueError,pm.OperatorError)):
                pm.op_new(self.args('new','--target','10.0.0.1','--area','web','--allow-network','10.0.0.0/24','--task','CTF'))
        config=resources.resolve('https://app.lab/',addresses=['10.0.0.1'],deny=['10.0.0.1/32'])
        with self.assertRaisesRegex(ValueError,'excluded'):broker.authorize_resource(config['policy'],'http','10.0.0.1',scheme='https',hostname='app.lab',port=443)

    def test_ipv6_rules_and_profiles_remain_narrow_and_use_ipv6_transport(self):
        policy=resources.resolve('https://[fd20::80]:8443/x?q=1#b',area='web')['policy']
        self.assertEqual(policy['addresses'],['fd20::80'])
        rules=broker.filter_rules(broker.task_values(11),broker.allow_networks(['fd20::80/128']),'tun0')
        self.assertIn('ip6 daddr { fd20::80/128 } oifname "tun0" accept',rules)
        self.assertIn('iifname "pmh11" counter drop',rules)
        self.assertIn('add table ip6 pm_nat611',rules)
        self.assertIn('-6',broker.tool_args('tcp_ports','fd20::80',80,'22,80','http'))
        self.assertEqual(broker.tool_args('http_capture','fd20::80',8443,'','https','/x?q=1#b')[-1],
                         'https://[fd20::80]:8443/x?q=1')

    def test_page_dependency_grants_one_file_and_never_host_investigation(self):
        with patch.object(resources.socket,'getaddrinfo',return_value=[(2,1,6,'',('10.0.0.9',0))]):
            self.configure(page=['https://cdn.example/lib.js?v=1'])
        reply=self.tool(target='10.0.0.9',scheme='https',hostname='cdn.example',port=443,path='/lib.js?v=1#browser')
        self.assertEqual(reply['status'],'completed')
        for path in ('/admin','/lib.js?v=2','/lib.js/extra'):
            self.assertEqual(self.tool(target='10.0.0.9',scheme='https',hostname='cdn.example',port=443,path=path)['status'],'blocked')
        with self.assertRaises(ValueError):broker.authorize_resource(self.configure_policy(),'tcp_ports','10.0.0.9')
        self.assertEqual(len(self.calls),1)

    def test_root_session_cannot_bypass_origin_only_grants_in_host_area(self):
        with patch.object(resources.socket,'getaddrinfo',return_value=[(2,1,6,'',('10.0.0.9',0))]):
            self.configure(area='host',page=['https://cdn.example/lib.js'])
        policy=self.configure_policy()
        config={'resource_policy':policy,'allowed':resources.grants(policy)}
        with patch.object(broker,'ensure_root'),patch.object(broker,'owned_config',return_value=(broker.task_values(11),config)),\
             patch.object(broker,'session_dir',side_effect=AssertionError('No files before permission check')):
            with self.assertRaisesRegex(ValueError,'origin-only'):broker.session_open(11,[],60)

    def test_path_boundary_room_exclusion_and_firewall_drop_precede_grants(self):
        self.configure('https://app.lab/app/?x=1',path_prefix='/app/',deny=['https://app.lab/app/secrets','10.0.0.9/32'])
        policy=self.configure_policy()
        broker.authorize_resource(policy,'http','10.0.0.1',scheme='https',hostname='app.lab',port=443,path='/app/read?x=2')
        for path in ('/administrator','/app2/read','/app/secrets'):
            with self.subTest(path=path),self.assertRaises(ValueError):broker.authorize_resource(policy,'http','10.0.0.1',scheme='https',hostname='app.lab',port=443,path=path)
        rules=broker.resource_filter_rules(broker.task_values(11),['10.0.0.0/24'],'tun0',policy)
        self.assertLess(rules.index('ip daddr 10.0.0.9/32 counter drop'),rules.index('oifname "tun0" accept'))

    def test_same_origin_can_be_captured_via_two_pinned_addresses_without_overwriting(self):
        self.configure(addresses=['10.0.0.1','fd20::80'])
        first=self.tool()
        second=self.tool(target='fd20::80')
        self.assertEqual(first['status'],second['status']);self.assertEqual(second['status'],'completed')
        self.assertNotEqual(first['artifact_ref'],second['artifact_ref'])
        self.assertEqual(len(self.calls),2)
        self.assertTrue(self.tool(target='fd20::80')['cached']);self.assertEqual(len(self.calls),2)
        with self.case.connect() as db:
            self.assertEqual(db.execute('SELECT target FROM pm_http_discovery ORDER BY id').fetchall(),[('10.0.0.1',),('fd20::80',)])

    def test_legacy_http_route_migration_preserves_ids_columns_auxiliary_and_refresh_history(self):
        web=capture_fixture.web
        with sqlite3.connect(':memory:') as template:
            web.init(template)
            sql=template.execute("SELECT sql FROM sqlite_master WHERE name='pm_http_discovery'").fetchone()[0]
        with sqlite3.connect(':memory:') as db:
            db.execute(sql.replace('UNIQUE(task_id,target,port,scheme,hostname,path)','UNIQUE(task_id,port,scheme,hostname,path)'))
            db.execute("INSERT INTO pm_http_discovery(id,task_id,target,port,scheme,hostname,path,title,created_at) VALUES(7,11,'10.0.0.1',80,'http','app.lab','/?q=1','saved','old')")
            db.execute('CREATE INDEX route_saved_title ON pm_http_discovery(title)')
            db.execute('CREATE TABLE route_updates(observation_id INTEGER)')
            db.execute('CREATE TRIGGER route_saved_trigger AFTER UPDATE ON pm_http_discovery BEGIN INSERT INTO route_updates VALUES(new.id); END')
            before=db.execute('SELECT * FROM pm_http_discovery').fetchall()
            web.init(db);web.init(db)
            self.assertEqual(db.execute('SELECT * FROM pm_http_discovery').fetchall(),before)
            self.assertTrue(db.execute("SELECT 1 FROM sqlite_master WHERE name='route_saved_title'").fetchone())
            self.assertTrue(db.execute("SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='route_saved_trigger'").fetchone())
            self.assertEqual(db.execute('SELECT * FROM route_updates').fetchall(),[])
            db.execute("INSERT INTO pm_http_discovery(task_id,target,port,scheme,hostname,path,created_at) VALUES(11,'fd20::80',80,'http','app.lab','/?q=1','new')")
            self.assertEqual(db.execute('SELECT count(*) FROM pm_http_discovery').fetchone()[0],2)
            db.execute("UPDATE pm_http_discovery SET title='changed after migration' WHERE id=7")
            self.assertEqual(db.execute('SELECT * FROM route_updates').fetchall(),[(7,)])

    def test_real_new_ipv6_url_reaches_coordinator_with_correct_scope(self):
        self.console_patches()
        url='http://[fd20::80]:8080/path?q=1#browser'
        def planner(target,text,key,context):
            with self.case.connect() as db:
                db.execute('UPDATE tasks SET target=?',(target,));db.execute('DELETE FROM task_scope_settings')
                db.execute('DELETE FROM pm_operator_approvals')
            return 11,{'tasks':[]}
        stop=coordinator_fixture.decision();stop['boundaries'].update(target='fd20::80',resource_refs=['scope:fd20::80'])
        model=self.case.model([stop])
        with patch.object(pm,'run_planner_with_validation_retry',side_effect=planner),\
             patch.object(coordinator,'choose_with_model',side_effect=lambda prompt,key,tokens:model(prompt,key)):
            pm.op_new(self.args('new','--target',url,'--task','Find flags'))
        self.assertEqual(len(self.calls),1)
        self.assertEqual(self.case.prompts[0]['task']['target'],'fd20::80')
        self.assertEqual(self.root_config['allowed'],['fd20::80/128'])
        self.assertEqual(self.case.prompts[0]['resource_graph']['entry']['query'],'q=1')

    def test_web_address_change_keeps_old_capture_and_caches_new_route_after_one_check(self):
        self.configure();self.tool()
        with self.case.connect() as db:task_runtime.save_mode(db,11,'coordinated')
        self.console_patches()
        stop=coordinator_fixture.decision();stop['boundaries'].update(target='10.0.0.2',resource_refs=['scope:10.0.0.2'])
        with patch.object(coordinator,'choose_with_model',return_value=json.dumps(stop)):
            pm.op_change_ip(self.args('change-ip','11','--target','10.0.0.2'))
        self.assertEqual(len(self.calls),2)
        self.assertTrue(self.tool(target='10.0.0.2')['cached']);self.assertEqual(len(self.calls),2)
        with self.case.connect() as db:
            self.assertEqual(db.execute('SELECT target FROM pm_http_artifacts ORDER BY id').fetchall(),[('10.0.0.1',),('10.0.0.2',)])
            self.assertEqual(actions.service_map(db,11,1)['scan_mode'],'web_only')

    def test_running_unknown_action_prevents_address_change_without_side_effects(self):
        self.configure(area='host')
        with self.assertRaises(KeyboardInterrupt):
            coordinator.run(11,api_key='fake-only',model=self.case.model([coordinator_fixture.decision('vuln','One check')]),
                role_runner=Mock(side_effect=KeyboardInterrupt))
        with patch.object(pm,'connect',self.case.connect),patch.object(pm,'sudo_checked',side_effect=AssertionError('No network')):
            with self.assertRaisesRegex(pm.OperatorError,'running'):pm.op_change_ip(self.args('change-ip','11','--target','10.0.0.2'))
        with self.case.connect() as db:self.assertEqual(db.execute('SELECT target FROM tasks').fetchone()[0],'10.0.0.1')

    def test_successor_only_option_is_rejected_before_same_machine_side_effects(self):
        self.configure(area='host')
        with patch.object(pm,'connect',self.case.connect),patch.object(pm,'get_egress',side_effect=AssertionError('No route action')),\
             patch.object(pm,'sudo_checked',side_effect=AssertionError('No namespace action')):
            with self.assertRaisesRegex(pm.OperatorError,'--archive-work'):
                pm.op_change_ip(self.args('change-ip','11','--target','10.0.0.2','--archive-work'))

    def test_address_change_cancellation_is_not_an_executed_failure(self):
        from orchestrator import report_integrity
        outcome=report_integrity.step_execution({'status':'failed','error':'address_changed_not_started',
            'outcome_uncertain':0,'approved_at':None})
        self.assertEqual(outcome['status'],'not_started')

    def test_old_broker_refusal_retains_new_task_intent_goals_and_resource_scope(self):
        self.console_patches()
        with self.case.connect() as db:db.execute('DELETE FROM pm_task_intents')
        url='https://app.lab:8443/app?q=1#tab'
        original_broker=self.console_broker
        def older(command,**kwargs):
            if command[0]=='capabilities':return {'capture_protocol':1},0
            return original_broker(command,**kwargs)
        with patch.object(pm,'run_planner_with_validation_retry',return_value=(11,{'tasks':[]})),\
             patch.object(pm,'sudo_checked',side_effect=older):
            with self.assertRaisesRegex(pm.OperatorError,'обновление брокера'):
                pm.op_new(self.args('new','--target',url,'--address','10.0.0.1','--task','Find flags; no brute force','--goal-first'))
        self.assertEqual(self.calls,[])
        with self.case.connect() as db:
            self.assertEqual('Find flags; no brute force',db.execute('SELECT intent FROM pm_task_intents').fetchone()[0])
            self.assertEqual(resources.saved(db,11)['entry']['input'],url)
            self.assertEqual(db.execute('SELECT count(*) FROM pm_objectives').fetchone()[0],1)


if __name__=='__main__':unittest.main()
