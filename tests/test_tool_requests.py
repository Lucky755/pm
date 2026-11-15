"""Tool requests use the actual inbox, MCP registration and standalone broker logic.

All roots are temporary; only privileged/external process boundaries are replaced.
"""
import asyncio
import importlib.util
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_coordinated_attack as fixture
from executor import netguard_root as broker
from orchestrator import tool_requests as tools, operator_questions as questions
from orchestrator import agent_actions, coordinated_attack, task_memory


class ToolRequestRegressionTests(unittest.TestCase):
    def test_privileged_scans_are_fixed_supported_profiles(self):
        for profile, flag in [('nmap_syn', '-sS'), ('nmap_udp', '-sU'), ('nmap_os', '-O')]:
            with self.subTest(profile=profile):
                argv = broker.tool_args(profile, '10.0.0.1', 80, '22,8080', 'http')
                self.assertIn(flag, argv)
                self.assertNotIn('--script', argv)

    def test_registered_tool_request_has_actionable_permission(self):
        spec = importlib.util.spec_from_file_location('tool_request_regression_mcp',
            Path(__file__).resolve().parents[1] / 'mcp/server.py')
        server = importlib.util.module_from_spec(spec); spec.loader.exec_module(server)
        registered = asyncio.run(server.mcp.list_tools())
        self.assertIn('pm_tool_request', [tool.name for tool in registered])


class ToolAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.source=self.case.root/'download.py';self.source.write_text("print('offline tool')\n")
        self.workspace=self.case.root/'tasks'/'11';self.workspace.mkdir(mode=0o700,parents=True)
        self.receipts=self.case.root/'broker';self.receipts.mkdir(mode=0o700)
        self.config={'task_id':11,'name':'pmns11','uid':os.getuid(),'gid':os.getgid(),'allowed':['10.0.0.1/32']}
        spec=importlib.util.spec_from_file_location('tool_acquisition_mcp',Path(__file__).resolve().parents[1]/'mcp/server.py')
        self.server=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.server)
        for replacement in (patch.object(self.server,'ASSET_DB',self.case.database),
                patch.object(self.server,'CAPABILITY_LOG',agent_actions.CAPABILITY_LOG),
                patch.object(broker,'BASE',self.receipts),patch.object(broker,'WORK_BASE',self.case.root/'tasks'),
                patch.object(broker,'ensure_root'),patch.object(broker,'owned_config',return_value=({},self.config)),
                patch.object(broker,'task_workdir',return_value=self.workspace)):
            replacement.start();self.addCleanup(replacement.stop)
        self.calls=[]
        replacement=patch.object(subprocess,'run',side_effect=self.boundary);replacement.start();self.addCleanup(replacement.stop)

    def spec(self,**changes):
        return {'kind':'user_tool','name':'offline-helper','purpose':'Parse a saved task file',
                'version':'test-1','source':self.source.as_uri(),'channel':'local_file','filename':'helper.py',
                'sha256':'','interpreter':'python3',**changes}

    def boundary(self,argv,**kwargs):
        self.calls.append(argv)
        self.assertEqual(argv[:4],['sudo','-n',tools.BROKER,'tool'])
        def arg(name):return argv[argv.index('--'+name)+1]
        tid=int(arg('task-id'));action=arg('action')
        try:
            result=broker.tool_prepare(tid,json.loads(arg('spec-json'))) if action=='prepare' else broker.tool_action(tid,action,arg('request-id'))
            return subprocess.CompletedProcess(argv,0,json.dumps(result),'')
        except broker.ToolError as exc:
            return subprocess.CompletedProcess(argv,1,json.dumps({'status':'blocked','reason_category':exc.category,'error':str(exc)}),'')

    def call(self,name,**args):
        blocks=asyncio.run(self.server.mcp.call_tool(name,{'task_id':11,**args}))
        if isinstance(blocks,tuple):blocks=blocks[0]
        return json.loads(next(b.text for b in blocks if getattr(b,'type',None)=='text'))

    def request(self,**changes):return self.call('pm_tool_request',spec_json=json.dumps(self.spec(**changes)))

    def approve(self,item):
        with self.case.connect() as db:
            questions.answer(db,11,item['question_id'],'approve')
            db.commit()
            return tools.acquire(db,11,item['tool_request']['id'],authorize=True)

    def test_approval_install_reuse_and_restart_are_durable(self):
        reply=self.request()
        self.assertEqual(reply['status'],'waiting_operator')
        manifest=reply['tool_request']['manifest']
        self.assertEqual(manifest['destination'],'/work/tools/offline-helper/helper.py')
        self.assertEqual(manifest['spec']['source'],self.source.as_uri())
        # MCP cannot authorize an operator permission, including after forged SQLite state.
        denied=self.call('pm_tool_acquire',request_id=reply['tool_request']['id'])
        self.assertEqual(denied['status'],'pending')
        result=self.approve(reply)
        self.assertEqual(result['status'],'completed')
        saved=self.workspace/'tools/offline-helper/helper.py'
        self.assertEqual(saved.read_bytes(),self.source.read_bytes())
        self.assertEqual(saved.stat().st_uid,os.getuid())
        self.assertEqual(result['receipt']['result']['sha256'],hashlib.sha256(saved.read_bytes()).hexdigest())
        calls=len(self.calls)
        again=self.request(purpose='A different formulation is the same permission')
        self.assertEqual(again['question_id'],reply['question_id']);self.assertEqual(again['status'],'completed')
        self.assertEqual(len(self.calls),calls)
        with self.case.connect() as db:
            self.assertEqual(len(questions.listing(db,11)),1)
            state=coordinated_attack.snapshot(db,11,1)
            self.assertEqual(state['tool_requests'][0]['status'],'completed')
            self.assertIn('tool_request:'+str(result['id']),state['references'])
            memory=task_memory.context(db,11,agent_actions.CAPABILITY_LOG/'task_11.jsonl')
            self.assertIn('tool_request:'+str(result['id']),memory['state']['resources'])
        # Restart/re-apply reads the root completed receipt, never runs an installer twice.
        self.assertEqual(self.call('pm_tool_acquire',request_id=result['id'])['status'],'completed')
        self.assertEqual(saved.read_bytes(),self.source.read_bytes())

    def test_decline_is_visible_to_coordinator_and_does_not_install_or_reask(self):
        reply=self.request()
        with self.case.connect() as db:questions.answer(db,11,reply['question_id'],'decline','Use the installed Python instead')
        count=len(self.calls)
        denied=self.call('pm_tool_acquire',request_id=reply['tool_request']['id'])
        self.assertEqual(denied['status'],'declined');self.assertEqual(len(self.calls),count)
        self.assertEqual(self.request()['question_id'],reply['question_id'])
        with self.case.connect() as db:
            state=coordinated_attack.snapshot(db,11,1)
            self.assertIn('Use the installed Python',json.dumps(state))
            self.assertEqual(state['tool_requests'][0]['status'],'declined')
        self.assertFalse((self.workspace/'tools').exists())

    def test_changed_local_bytes_fail_without_overwrite_or_automatic_retry(self):
        reply=self.request();self.source.write_text('changed after permission request')
        result=self.approve(reply)
        self.assertEqual(result['status'],'failed')
        self.assertEqual(result['receipt']['result']['reason_category'],'integrity_error')
        count=len(self.calls)
        self.assertEqual(self.call('pm_tool_acquire',request_id=result['id'])['status'],'failed')
        self.assertEqual(len(self.calls),count)
        self.assertFalse((self.workspace/'tools').exists())

    def test_information_or_sqlite_alone_does_not_grant_root_permission(self):
        reply=self.request()
        with self.case.connect() as db:
            with self.assertRaises(ValueError):questions.answer(db,11,reply['question_id'],'information','Maybe')
            self.assertEqual(questions.listing(db,11)[0]['status'],'pending')
            # Even a DB approval cannot make MCP authorize a receipt.
            questions.answer(db,11,reply['question_id'],'approve')
        result=self.call('pm_tool_acquire',request_id=reply['tool_request']['id'])
        self.assertEqual(result['status'],'approved')
        self.assertFalse((self.workspace/'tools').exists())

    def test_source_and_task_boundaries(self):
        for source,channel in [('https://10.0.0.1/tool','internet'),('http://cdn.example/tool','internet'),
                ('http://10.0.0.1/tool','kali_local'),('https://user:secret@example.com/a','internet')]:
            with self.subTest(source=source):
                result=self.request(source=source,channel=channel)
                self.assertEqual(result['status'],'blocked')
        with patch.dict(os.environ,{'PM_TASK_ID':'22'}):self.assertEqual(self.request()['status'],'blocked')
        self.assertFalse(self.calls)

    def test_documentation_saved_as_data_not_root_code(self):
        reply=self.request(kind='documentation',filename='manual.txt',interpreter='none')
        result=self.approve(reply)
        self.assertEqual(result['status'],'completed');self.assertEqual(result['receipt']['result']['invocation'],[])
        self.assertEqual((self.workspace/'docs/offline-helper/manual.txt').read_bytes(),self.source.read_bytes())
        count=len(self.calls)
        first=self.call('pm_tool_read',request_id=result['id'],limit=5)
        second=self.call('pm_tool_read',request_id=result['id'],offset=5)
        self.assertEqual(first['text_untrusted']+second['text_untrusted'],self.source.read_text())
        self.assertTrue(first['has_more']);self.assertFalse(second['has_more'])
        self.assertEqual(first['provenance'],'local_read');self.assertEqual(len(self.calls),count)
        (self.workspace/'docs/offline-helper/manual.txt').write_text('changed')
        self.assertEqual(self.call('pm_tool_read',request_id=result['id'])['status'],'blocked')

    def test_interrupted_install_is_not_automatically_replayed(self):
        reply=self.request();root_id=next(p.stem.split('-')[-1] for p in self.receipts.glob('tool-*.json'))
        with self.case.connect() as db:questions.answer(db,11,reply['question_id'],'approve')
        broker.tool_action(11,'authorize',root_id)
        with patch.object(broker,'tool_read_local',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):broker.tool_action(11,'apply',root_id)
        with patch.object(broker,'tool_read_local',side_effect=AssertionError('Must not repeat')):
            result=self.call('pm_tool_acquire',request_id=reply['tool_request']['id'])
        self.assertEqual(result['status'],'running')
        self.assertFalse((self.workspace/'tools').exists())

    def test_lost_reply_reconciles_completed_receipt_without_second_install(self):
        reply=self.request();calls=[]
        original=self.boundary
        def lose_apply_reply(argv,**kwargs):
            calls.append(argv)
            result=original(argv,**kwargs)
            if argv[argv.index('--action')+1]=='apply':raise subprocess.TimeoutExpired(argv,240)
            return result
        with patch.object(subprocess,'run',side_effect=lose_apply_reply):result=self.approve(reply)
        self.assertEqual(result['status'],'unknown')
        self.assertEqual(result['receipt']['request_id'],tools.tool_digest(reply['tool_request']['manifest']))
        after=self.call('pm_tool_acquire',request_id=result['id'])
        self.assertEqual(after['status'],'completed')
        self.assertEqual(sum(a[a.index('--action')+1]=='apply' for a in self.calls),1)

    def test_non_cached_package_uses_approved_archive_hash_and_temp_cache(self):
        import base64
        body=b'offline package bytes';sha=hashlib.sha256(body).hexdigest();executed=[]
        def fakecmd(*argv,**kwargs):
            executed.append(argv)
            if argv[:2]==('/usr/bin/apt-cache','policy'):text=' Candidate: 1.7-test\n'
            elif argv[0]=='/usr/bin/apt-get':text=f"'https://packages.example/jq_1.7-test_amd64.deb' jq_1.7-test_amd64.deb {len(body)} MD5Sum:unused\n"
            elif argv[:2]==('/usr/bin/apt-cache','show'):text=f'Package: jq\nVersion: 1.7-test\nFilename: pool/jq_1.7-test_amd64.deb\nSize: {len(body)}\nSHA256: {sha}\n'
            elif argv[0]=='/usr/bin/dpkg-query':text='1.7-test'
            else:
                self.assertEqual(argv[0],'/usr/bin/unshare')
                self.assertEqual((cache/'jq_1.7-test_amd64.deb').read_bytes(),body)
                self.assertIn('--no-download',argv);text='installed'
            return subprocess.CompletedProcess(argv,0,text,'')
        def transfer(argv,limit,**kwargs):
            self.assertEqual(argv[-1],'https://packages.example/jq_1.7-test_amd64.deb')
            self.assertIn('packages.example:443:93.184.216.34',argv)
            return {'exit_code':0,'response_b64':base64.b64encode(b'HTTP/1.1 200 OK\r\n\r\n'+body).decode()}
        cache=self.case.root/'apt-cache';cache.mkdir(mode=0o700)
        with patch.object(broker,'APT_CACHE',cache),patch.object(broker,'cmd',side_effect=fakecmd),\
             patch.object(broker,'capture_process',side_effect=transfer),\
             patch.object(broker.socket,'getaddrinfo',return_value=[(2,1,6,'',('93.184.216.34',443))]):
            reply=self.call('pm_tool_request',spec_json=json.dumps({'kind':'system_package','name':'jq',
                'purpose':'Offline parsing','version':'candidate'}))
            self.assertEqual(reply['tool_request']['manifest']['package_plan']['archives'][0]['sha256'],sha)
            result=self.approve(reply)
        self.assertEqual(result['status'],'completed',result)
        self.assertEqual(result['receipt']['result']['source']['archives'][0]['url'],'https://packages.example/jq_1.7-test_amd64.deb')
        self.assertEqual(sum(a[0]=='/usr/bin/unshare' for a in executed),1)

    def test_unreadable_apply_reply_is_unknown_and_does_not_erase_root_reference(self):
        reply=self.request();original=self.boundary
        def unreadable(argv,**kwargs):
            result=original(argv,**kwargs)
            if argv[argv.index('--action')+1]=='apply':return subprocess.CompletedProcess(argv,1,'{broken','')
            return result
        with patch.object(subprocess,'run',side_effect=unreadable):result=self.approve(reply)
        self.assertEqual(result['status'],'unknown')
        self.assertEqual(result['receipt']['reason_category'],'outcome_unknown')
        self.assertEqual(self.call('pm_tool_acquire',request_id=result['id'])['status'],'completed')
        self.assertEqual(sum(a[a.index('--action')+1]=='apply' for a in self.calls),1)

    def test_failed_system_install_keeps_permission_and_error(self):
        def fakecmd(*argv,**kwargs):
            if argv[:2]==('/usr/bin/apt-cache','policy'):return subprocess.CompletedProcess(argv,0,'  Candidate: 1.7-test\n','')
            if argv[0]=='/usr/bin/apt-get':
                self.assertIn('--print-uris',argv);self.assertIn('--download-only',argv)
                return subprocess.CompletedProcess(argv,0,'Already in the root cache.\n','')
            self.assertEqual(argv[0],'/usr/bin/unshare');self.assertIn('--net',argv)
            self.assertIn('--no-download',argv);self.assertIn('jq=1.7-test',argv)
            raise subprocess.CalledProcessError(1,argv)
        cache=self.case.root/'apt-cache';cache.mkdir(mode=0o700)
        with patch.object(broker,'APT_CACHE',cache),patch.object(broker,'cmd',side_effect=fakecmd):
            reply=self.call('pm_tool_request',spec_json=json.dumps({
                    'kind':'system_package','name':'jq','purpose':'Parse saved JSON','version':'candidate'}))
            result=self.approve(reply)
        self.assertEqual(result['status'],'failed')
        self.assertEqual(result['receipt']['result']['reason_category'],'installation_failed')
        self.assertEqual(result['receipt']['manifest']['package_plan'],{'package':'jq','version':'1.7-test','archives':[]})

    def test_successful_cached_package_install_is_not_repeated_after_restart(self):
        calls=[]
        def fakecmd(*argv,**kwargs):
            calls.append(argv)
            self.assertEqual(kwargs['env']['LC_ALL'],'C')
            self.assertNotIn('APT_CONFIG',kwargs['env']);self.assertNotIn('EXPERIENTIAL_API_KEY',kwargs['env'])
            if argv[:2]==('/usr/bin/apt-cache','policy'):text='  Candidate: 1.7-test\n'
            elif argv[0]=='/usr/bin/apt-get':text='Already cached\n'
            elif argv[0]=='/usr/bin/dpkg-query':text='1.7-test'
            else:
                self.assertEqual(argv[0],'/usr/bin/unshare');self.assertIn('--no-download',argv);text='Installed'
            return subprocess.CompletedProcess(argv,0,text,'')
        cache=self.case.root/'apt-cache';cache.mkdir(mode=0o700)
        with patch.object(broker,'APT_CACHE',cache),patch.object(broker,'cmd',side_effect=fakecmd):
            reply=self.call('pm_tool_request',spec_json=json.dumps({'kind':'system_package','name':'jq',
                            'purpose':'Parse a saved file','version':'candidate'}))
            result=self.approve(reply)
            self.assertEqual(result['status'],'completed')
            self.assertEqual(result['receipt']['result']['version_provenance'],'dpkg-query')
            self.call('pm_tool_acquire',request_id=result['id'])
        self.assertEqual(sum(argv[0]=='/usr/bin/unshare' for argv in calls),1)

    def test_apt_plan_binds_exact_archives_to_metadata(self):
        body=b'not a real package';sha=hashlib.sha256(body).hexdigest()
        def fakecmd(*argv,**kwargs):
            if argv[:2]==('/usr/bin/apt-cache','policy'):text=' Candidate: 1.7-test\n'
            elif argv[0]=='/usr/bin/apt-get':text=f"'https://packages.example/jq_1.7-test_amd64.deb' jq_1.7-test_amd64.deb {len(body)} MD5Sum:ignored\n"
            else:text=f'Package: jq\nVersion: 1.7-test\nFilename: pool/jq_1.7-test_amd64.deb\nSize: {len(body)}\nSHA256: {sha}\n'
            return subprocess.CompletedProcess(argv,0,text,'')
        with patch.object(broker,'cmd',side_effect=fakecmd):
            plan=broker.tool_package_plan('jq','candidate')
        self.assertEqual(plan['archives'],[{'url':'https://packages.example/jq_1.7-test_amd64.deb',
            'filename':'jq_1.7-test_amd64.deb','bytes':len(body),'sha256':sha,'package':'jq','version':'1.7-test'}])

    def test_explicit_cli_approval_installs_and_plain_view_does_not_call_broker(self):
        import pm
        reply=self.request()
        def args(*argv):
            with patch.object(sys,'argv',['pm',*argv]):return pm.parser_main()[1]
        with patch.object(pm,'connect',self.case.connect):
            pm.op_questions(args('questions','11','--answer',str(reply['question_id']),'--decision','approve'))
            calls=len(self.calls)
            pm.op_questions(args('questions','11'))
        self.assertEqual(calls,len(self.calls))
        self.assertTrue((self.workspace/'tools/offline-helper/helper.py').is_file())
        output=self.case.console.getvalue()
        self.assertIn('Место:',output);self.assertIn('Права:',output);self.assertIn('Источник:',output)

    def test_fixed_scan_builder_drops_general_root_and_leaves_work_readonly(self):
        args=broker.tool_args('nmap_syn','10.0.0.1',80,'22,8080','http')
        argv=broker.privileged_scan_command('pmns11',args,self.workspace)
        self.assertIn('CAP_NET_RAW',argv);self.assertIn('--cap-drop',argv)
        self.assertNotIn('--unshare-all',argv);self.assertNotIn('--unshare-user',argv)
        self.assertNotIn('--bind',argv);self.assertIn('--ro-bind',argv)
        plain=broker.isolated_command('pmns11','test',os.getuid(),os.getgid(),['/bin/bash','/work/check.sh'])
        self.assertIn('--bounding-set=-all',plain);self.assertNotIn('--cap-add',plain)
        for profile in broker.RAW_SCAN_PROFILES:
            with self.assertRaises(ValueError):broker.tool_args(profile,'10.0.0.1',80,'80;sh','http')

    def test_real_role_dependency_is_not_damaged_verify_and_resumes_without_replaying(self):
        owner=self;model_prompts=[]
        class Harness:
            def __init__(self,**options):self.options=options
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def start_session(self,name):
                def run(prompt,**kwargs):
                    model_prompts.append(prompt)
                    reply=owner.request(kind='documentation',filename='guide.txt',interpreter='none')
                    owner.assertEqual(reply['status'],'waiting_operator')
                    Path(self.options['env']['PM_AGENT_STATS_FILE']).write_text(json.dumps(
                        {'calls':1,'tool_events':1,'reads':0,'denied':0,'sessions':0}))
                    return SimpleNamespace(finish_reason='completed',events=[],final_response=json.dumps({
                        'summary':'No target action was started. Documentation is required for this audit.',
                        'findings':[],'hypotheses':[],'flags':[],'verified':[],'uncertainties':[], 'proposed_actions':[]}))
                return SimpleNamespace(run=run)
        with patch.dict(sys.modules,{'deepseek_harness':SimpleNamespace(DeepSeekHarness=Harness)}),\
             patch.object(agent_actions,'DSH_HOME',self.case.root/'dsh'),\
             patch.object(agent_actions,'WORKSPACE',self.case.root/'sdk-work'),\
             patch.object(agent_actions,'close_task_sessions'):
            result=coordinated_attack.run(11,api_key='fake-only',model=self.case.model([
                fixture.decision('verify','Read the requested manual before auditing original saved evidence')]),
                role_runner=agent_actions.run_role)
        self.assertEqual(result['stop_reason'],'operator_questions_pending',result)
        step=self.case.rows()[0]
        self.assertEqual(step['status'],'waiting_operator');self.assertFalse(step['outcome_uncertain'])
        with self.case.connect() as db:
            report=json.loads(db.execute('SELECT report_json FROM pm_agent_action_reports WHERE task_id=11').fetchone()[0])
            self.assertFalse(report.get('report_incomplete'),report)
            self.assertEqual(report['execution_outcome']['status'],'not_started')
            self.assertTrue(report['operator_dependencies'])
            question=questions.listing(db,11,pending=True)[0]
        before=len(self.calls)
        # A plain resumed view does not query a model or re-prepare/re-run work.
        paused=coordinated_attack.run(11,model=lambda *args: self.fail('Unexpected model call'))
        self.assertEqual(paused['stop_reason'],'operator_questions_pending')
        self.assertEqual(len(self.calls),before)
        with self.case.connect() as db:questions.answer(db,11,question['id'],'decline','Use saved documentation instead')
        result=coordinated_attack.run(11,api_key='fake-only',model=self.case.model([fixture.decision()]),
            role_runner=lambda *args,**kwargs:self.fail('Must replan rather than replay the role'))
        self.assertEqual(result['stop_reason'],'model_stopped_incomplete')
        self.assertEqual(self.case.rows()[0]['error'],'tool_dependency_resolved_replan')
        self.assertEqual(len(model_prompts),1)

    def test_registered_raw_scan_retains_task_and_repeat_guards(self):
        original_boundary=self.boundary
        def execute(argv,**kwargs):
            if argv[3]=='tool':return original_boundary(argv,**kwargs)
            self.calls.append(argv)
            return subprocess.CompletedProcess(argv,0,json.dumps({'task_id':11,'target':'10.0.0.1',
                'status':'completed','exit_code':0,'stdout':'22/tcp open ssh'}),'')
        with patch.object(subprocess,'run',side_effect=execute):
            first=self.call('pm_privileged_scan',target='10.0.0.1',profile='nmap_syn',ports='22')
            second=self.call('pm_privileged_scan',target='10.0.0.1',profile='nmap_syn',ports='22')
        self.assertEqual(first['status'],'completed');self.assertEqual(second['kind'],'repeat_guard')
        self.assertEqual(len(self.calls),1)
        records=[json.loads(line) for line in (agent_actions.CAPABILITY_LOG/'task_11.jsonl').read_text().splitlines()]
        self.assertEqual(records[0]['provenance'],'network');self.assertIn('result_id',first)

    def test_raw_scope_refusal_occurs_before_executor_and_error_categories_are_distinct(self):
        from orchestrator import diagnostics
        with patch.object(broker,'cmd',side_effect=AssertionError('Must refuse before any external operation')):
            with self.assertRaisesRegex(ValueError,'outside|allowed|scope'):
                broker.run(11,'nmap_syn','10.0.0.99',80,'22','http')
        for category in ('tool_missing','permission_denied','network_denied','download_failed',
                         'installation_failed','utility_failed','outcome_unknown'):
            self.assertEqual(diagnostics.failure_details({'status':'error','reason_category':category})['reason_category'],category)

    def test_changed_conditions_create_one_new_permission(self):
        first=self.request()
        with self.case.connect() as db:questions.answer(db,11,first['question_id'],'decline')
        second=self.request(version='test-2',filename='helper-2.py')
        self.assertNotEqual(first['question_id'],second['question_id'])
        self.assertEqual(self.request(version='test-2',filename='helper-2.py',purpose='Rephrased')['question_id'],second['question_id'])

    def test_one_permission_can_hold_multiple_dependent_branches(self):
        first=self.call('pm_tool_request',spec_json=json.dumps(self.spec()),branch_id='service:10.0.0.1:tcp:22')
        second=self.call('pm_tool_request',spec_json=json.dumps(self.spec()),branch_id='service:10.0.0.1:tcp:80')
        self.assertEqual(first['question_id'],second['question_id'])
        with self.case.connect() as db:
            inbox=questions.listing(db,11)
            self.assertEqual(len(inbox),1)
            state={'operator_questions':inbox,'known_resources':['scope:10.0.0.1',
                'service:10.0.0.1:tcp:22','service:10.0.0.1:tcp:80','service:10.0.0.1:tcp:443']}
            self.assertEqual(questions.available(state),['service:10.0.0.1:tcp:443'])
            questions.answer(db,11,first['question_id'],'decline','Use a built-in tool on both branches')
            state['operator_questions']=questions.listing(db,11)
            self.assertEqual(questions.available(state),state['known_resources'])

    def test_workspace_symlink_is_never_used_for_root_writes(self):
        reply=self.request();outside=self.case.root/'outside';outside.mkdir()
        (self.workspace/'tools').symlink_to(outside,target_is_directory=True)
        result=self.approve(reply)
        self.assertEqual(result['status'],'failed');self.assertEqual(list(outside.iterdir()),[])


if __name__ == '__main__':
    unittest.main()
