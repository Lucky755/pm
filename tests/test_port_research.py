"""Temporary SQLite and real loopback sockets, no target/API/root execution."""
import json
import socket
import sqlite3
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import pm
from executor import netguard_root as broker
from orchestrator import port_research as ports,target_availability as availability
from tests import test_full_scan_recovery as fixture


class PortResearchTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.FullScanRecoveryTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.db=self.case.db

    def test_queue_distinguishes_protocols_and_resumes_without_duplicates(self):
        tcp=ports.queue(self.db,1,self.case.target,'tcp',[22,8080])
        udp=ports.queue(self.db,1,self.case.target,'udp',[22,53])
        self.assertNotEqual(tcp,udp)
        self.assertEqual(ports.queue(self.db,1,self.case.target,'udp',[22,53]),udp)
        before=self.db.execute('SELECT * FROM network_phase_plans').fetchall()
        ports.initialize(self.db);ports.initialize(self.db)
        self.assertEqual(before,self.db.execute('SELECT * FROM network_phase_plans').fetchall())

    def test_states_include_partial_timeout_and_unchecked_without_product_claim(self):
        data=ports.parse('1/tcp open ssh\n2/tcp closed unknown\n3/tcp filtered unknown\n', 'tcp',[1,2,3,4],complete=False)
        self.assertEqual([r['state'] for r in data],['open','closed','filtered','unchecked'])
        self.assertFalse(data[0]['service_verified'])
        self.assertEqual(ports.parse('53/udp open|filtered domain\n','udp',[53,54])[0]['state'],'open|filtered')

    def test_preflight_checks_beyond_old_deadline_and_saves_queue(self):
        seen=[]
        def boundary(command,**kw):
            argv=[s.removeprefix('--argv=') for s in command if s.startswith('--argv=')]
            selected=json.loads(argv[-2]);seen.extend(selected)
            self.assertNotIn('limit=time.monotonic()+10',argv[2])
            return {'status':'completed','exit_code':0,'stdout':json.dumps({'reachable':selected[-1:], 'unreachable':selected[:-1],'unchecked':[]})},0
        with patch.object(pm,'sudo_checked',side_effect=boundary):
            checked=pm.preflight_target(self.db,1,self.case.target,list(range(1,64)))
        self.assertIn(63,checked['reachable']);self.assertEqual(set(seen),set(range(1,64)))
        self.assertEqual(checked['unchecked'],[])
        self.assertEqual(ports.preflight_progress(self.db,1,self.case.target)['checked'],63)

    def test_explicit_offline_does_not_change_scope_or_delete_materials(self):
        availability.set_state(self.db,1,'deactivated','Operator: machine stopped',source='operator')
        with self.assertRaisesRegex(ValueError,'target_offline'):availability.require_network(self.db,1)
        self.assertEqual(availability.saved(self.db,1)['state'],'deactivated')
        with patch.object(pm,'configure',side_effect=AssertionError('network configuration')), \
             patch.object(pm,'run_task_coordinator',return_value={'status':'local_analysis'}) as coordinator:
            with patch.object(pm.sys,'argv',['pm','resume','1','--coordinated','--continue-coordinated']):args=pm.parser_main()[1]
            result=pm.op_resume(args)
        self.assertEqual(result['status'],'local_analysis');coordinator.assert_called_once()

    def test_fifty_tcp_ports_are_supported_but_fifty_one_are_not(self):
        broker.tool_args('tcp_ports',self.case.target,80,','.join(map(str,range(1,51))),'http')
        with self.assertRaises(ValueError):broker.tool_args('tcp_ports',self.case.target,80,','.join(map(str,range(1,52))),'http')

    def test_partial_preflight_resumes_only_unchecked_ports(self):
        batches=[]
        def execute(command,**kwargs):
            argv=[s.removeprefix('--argv=') for s in command if s.startswith('--argv=')]
            selected=json.loads(argv[-2]);batches.append(selected)
            if len(batches)==1:
                reply={'reachable':[selected[0]],'unreachable':[],'unchecked':selected[1:]}
            else:reply={'reachable':selected,'unreachable':[],'unchecked':[]}
            return {'status':'completed','exit_code':0,'stdout':json.dumps(reply)},0
        with patch.object(pm,'sudo_checked',side_effect=execute):
            first=pm.preflight_target(self.db,1,self.case.target,[22,80,443])
            self.assertEqual(first['unchecked'],[80,443])
            second=pm.preflight_target(self.db,1,self.case.target,[22,80,443])
        self.assertEqual(batches,[[22,80,443],[80,443]]);self.assertEqual(second['unchecked'],[])

    def test_timeout_retains_checked_batches_and_requires_explicit_restoration(self):
        import subprocess
        batches=[]
        def execute(command,**kwargs):
            argv=[s.removeprefix('--argv=') for s in command if s.startswith('--argv=')]
            selected=json.loads(argv[-2]);batches.append(selected)
            if len(batches)==2:raise subprocess.TimeoutExpired('temporary broker timeout',10)
            return {'status':'completed','exit_code':0,'stdout':json.dumps({'reachable':selected,'unreachable':[],'unchecked':[]})},0
        with patch.object(pm,'sudo_checked',side_effect=execute):
            with self.assertRaises(pm.OperatorError):pm.preflight_target(self.db,1,self.case.target,list(range(1,64)))
            self.assertEqual(availability.saved(self.db,1)['state'],'temporary_error')
            availability.set_state(self.db,1,'active','Operator fixed VPN',source='operator')
            result=pm.preflight_target(self.db,1,self.case.target,list(range(1,64)))
        self.assertEqual(batches[-1],list(range(51,64)));self.assertEqual(len(result['reachable']),63)

    def test_grouped_nmap_partition_and_partial_output_are_not_equivalent(self):
        text='22/tcp open ssh\nNot shown: 2 closed tcp ports (conn-refused)\nNmap done:'
        self.assertEqual([r['state'] for r in ports.parse(text,'tcp',[22,23,24])],['open','closed','closed'])
        self.assertEqual([r['state'] for r in ports.parse(text,'tcp',[22,23,24],complete=False)],['open','unchecked','unchecked'])

    def test_resuming_partial_queue_does_not_refresh_previous_open_evidence(self):
        from datetime import datetime,timezone,timedelta
        ports.initialize(self.db);old=(datetime.now(timezone.utc)-timedelta(minutes=1)).isoformat()
        with self.db:
            self.db.execute("INSERT INTO pm_tcp_full_scans(task_id,target,status,open_ports_json,created_at,last_seen_at) VALUES(1,?,'completed','[22]',?,?)",(self.case.target,old,old))
            self.db.execute("INSERT INTO pm_port_preflight VALUES(1,?,22,'open','{}',?)",(self.case.target,old))
            self.db.execute("INSERT INTO pm_port_preflight VALUES(1,?,80,'unchecked','{}',NULL)",(self.case.target,))
        result=pm.preflight_target(self.db,1,self.case.target,[22,80])
        self.assertEqual(result['reachable'],[22]);self.assertEqual(self.db.execute('SELECT last_seen_at FROM pm_tcp_full_scans').fetchone()[0],old)

    def test_failed_followup_can_be_repaired_without_rescanning(self):
        self.case.fail_queue()
        with self.assertRaises(sqlite3.IntegrityError):pm.run_full_tcp_scan(self.db,1,self.case.target)
        before=self.db.execute('SELECT result_json FROM pm_tcp_full_scan_attempts').fetchone()[0]
        self.db.execute('DROP TRIGGER fail_followup');self.db.commit()
        self.assertEqual(pm.run_full_tcp_scan(self.db,1,self.case.target),0)
        self.assertEqual(self.db.execute('SELECT result_json FROM pm_tcp_full_scan_attempts').fetchone()[0],before)
        self.assertEqual(len([c for c in self.case.broker_calls if 'tcp_full' in c]),1)

    def test_completed_udp_jobs_only_run_remaining_queue_on_next_invocation(self):
        import subprocess
        from orchestrator import network_jobs
        def execute(command,**kwargs):
            selected=[int(p) for p in command[command.index('--ports')+1].split(',')]
            result={'task_id':1,'target':self.case.target,'profile':'udp_ports','status':'completed','exit_code':0,
                'stdout':json.dumps({'observations':[{'port':p,'protocol':'udp','state':'open|filtered','service_verified':False} for p in selected]})}
            return subprocess.CompletedProcess(command,0,json.dumps(result),'')
        with patch.object(network_jobs.subprocess,'run',side_effect=execute):
            first=ports.run(self.db,1,self.case.target,'udp',list(range(1,20)),1)
            self.assertEqual((first['executed'],first['pending']),(1,2))
            second=ports.run(self.db,1,self.case.target,'udp',list(range(1,20)),8)
            self.assertEqual((second['executed'],second['pending']),(2,0))
            self.assertEqual(ports.run(self.db,1,self.case.target,'udp',list(range(1,20)),8)['executed'],0)
            self.assertEqual(ports.run(self.db,1,self.case.target,'udp',[1,2,3],8)['executed'],0)
        self.assertEqual(second['summary']['counts'],{'open|filtered':19})
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM network_job_runs').fetchone()[0],3)

    def test_web_scope_does_not_create_udp_or_tcp_scan_queue(self):
        from orchestrator import resources
        resources.save(self.db,1,resources.resolve('http://app.lab/',addresses=[self.case.target]))
        for protocol in ('tcp','udp'):
            with self.assertRaisesRegex(ValueError,'outside host scope'):ports.queue(self.db,1,self.case.target,protocol,[80])

    def test_temporary_service_failure_is_not_an_operator_shutdown(self):
        result=pm.preflight_target(self.db,1,self.case.target,[22,8080])
        state=availability.saved(self.db,1)
        self.assertEqual(state['state'],'services_unavailable');self.assertNotIn(state['state'],('deactivated','confirmed_unavailable'))
        self.assertIn('unknown',result['host_state']);self.assertEqual(self.case.broker_calls[-1][0],'network-diagnostic')
        with self.assertRaises(ValueError):availability.set_state(self.db,1,'deactivated','not inferred from ping',source='model')

    def test_closed_tcp_service_does_not_block_other_protocols(self):
        data={'reachable':[],'unreachable':[22],'unchecked':[],
            'port_states':[{'port':22,'protocol':'tcp','state':'closed','service_verified':False}]}
        with patch.object(pm,'sudo_checked',return_value=({'status':'completed','exit_code':0,'stdout':json.dumps(data)},0)):
            result=pm.preflight_target(self.db,1,self.case.target,[22])
        self.assertTrue(result['negative_transport_response_observed'])
        self.assertTrue(availability.saved(self.db,1)['network_allowed'])


class LocalPortRuntimeTests(unittest.TestCase):
    def test_real_tcp_open_and_closed(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1',0));server.listen()
            port=server.getsockname()[1]
            self.assertEqual(broker.port_probe('127.0.0.1',port,'tcp',.2)['state'],'open')
        self.assertEqual(broker.port_probe('127.0.0.1',port,'tcp',.2)['state'],'closed')

    def test_real_udp_response_and_silence_are_different(self):
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1',0));port=server.getsockname()[1]
            def echo():
                value,peer=server.recvfrom(1024);server.sendto(value or b'reply',peer)
            worker=threading.Thread(target=echo);worker.start()
            self.assertEqual(broker.port_probe('127.0.0.1',port,'udp',.2)['state'],'open');worker.join(timeout=1)
            self.assertEqual(broker.port_probe('127.0.0.1',port,'udp',.05)['state'],'open|filtered')

    def test_real_tcp_connection_timeout_is_not_closed(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1',0));server.listen(0);port=server.getsockname()[1]
            with socket.create_connection(('127.0.0.1',port)):
                result=broker.port_probe('127.0.0.1',port,'tcp',.05)
        self.assertEqual(result['state'],'timeout');self.assertEqual(result['error_type'],'TimeoutError')

    def test_real_udp_through_public_mcp_queue_and_no_replay_after_restart(self):
        import asyncio,importlib.util,subprocess
        from orchestrator import network_jobs,service_inventory
        case=fixture.FullScanRecoveryTests();case.setUp();self.addCleanup(case.doCleanups)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1',0));port=server.getsockname()[1]
            def echo():
                value,peer=server.recvfrom(1024);server.sendto(value or b'proof',peer)
            worker=threading.Thread(target=echo);worker.start()
            module=importlib.util.spec_from_file_location('port_test_mcp',Path(__file__).resolve().parents[1]/'mcp/server.py')
            mcp=importlib.util.module_from_spec(module);module.loader.exec_module(mcp);seen=[]
            def execute(argv,**kwargs):
                seen.append(argv);self.assertEqual(argv[:4],['sudo','-n','/usr/local/sbin/pm-netguard','run'])
                value={'task_id':1,'target':case.target,'profile':'udp_ports','status':'completed','exit_code':0,
                    'stdout':json.dumps({'observations':[broker.port_probe('127.0.0.1',port,'udp',.2)]})}
                return subprocess.CompletedProcess(argv,0,json.dumps(value),'')
            def call(**extra):
                result=asyncio.run(mcp.mcp.call_tool('pm_port_survey',{'task_id':1,'protocol':'udp','ports':str(port),**extra}))
                blocks=result[0] if isinstance(result,tuple) else result
                return json.loads(next(b.text for b in blocks if getattr(b,'type',None)=='text'))
            with patch.object(mcp,'ASSET_DB',case.database),patch.object(mcp,'CAPABILITY_LOG',case.root/'caps'),patch.object(network_jobs.subprocess,'run',side_effect=execute):
                self.assertEqual(call(max_jobs=2)['status'],'blocked');self.assertEqual(seen,[])
                first=call();self.assertEqual(first['executed'],1);self.assertRegex(first['result_id'],r'^[a-f0-9]{24}$');worker.join(timeout=1)
                self.assertEqual(call()['executed'],0);self.assertEqual(len(seen),1)
                with sqlite3.connect(case.database) as db:
                    inventory=service_inventory.collect_full(db,1)
                    self.assertEqual(inventory['port_states'][0]['state'],'open')
                    self.assertEqual(inventory['entries'][0]['protocol'],'udp')
                    with patch.object(pm,'run_full_tcp_scan',side_effect=AssertionError('Known UDP; no new full scan')), \
                         patch.object(pm,'run_task_coordinator',return_value={'udp_entry':True}) as coordinator:
                        from types import SimpleNamespace
                        self.assertTrue(pm.launch_coordinated_task(db,1,case.target,SimpleNamespace())['udp_entry'])
                        coordinator.assert_called_once()
                    availability.set_state(db,1,'deactivated','Stopped by operator',source='operator')
                result=call();self.assertEqual(result['reason_category'],'target_offline');self.assertEqual(len(seen),1)


class OfflineCoordinatorTests(unittest.TestCase):
    def setUp(self):
        from tests import test_coordinated_attack as fixture
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        with self.case.connect() as db:availability.set_state(db,11,'deactivated','Operator stopped target',source='operator')

    def test_local_analysis_once_and_restart_without_model_or_repeated_role(self):
        from tests.test_coordinated_attack import decision
        from orchestrator import coordinated_attack
        from unittest.mock import Mock
        choice=decision('recon','Interpret saved services without new traffic');choice['profile']='saved-analysis'
        self.case.emit_evidence=False
        result=self.case.run_mode([choice],max_steps=3)
        self.assertEqual(result['stop_reason'],'target_restoration_required');self.assertEqual(len(self.case.calls),1)
        model=Mock(side_effect=AssertionError('No useful new material; no model'))
        result=coordinated_attack.run(11,api_key='fake-only',model=model,role_runner=self.case.role,continue_run=True)
        self.assertEqual(result['stop_reason'],'target_restoration_required');model.assert_not_called();self.assertEqual(len(self.case.calls),1)

    def test_actual_specialist_prompt_and_sdk_policy_are_local_only(self):
        import os,sys
        from types import SimpleNamespace
        from orchestrator import agent_actions as a,task_sessions
        seen=[];allowed=[]
        class Harness:
            def __init__(self,**kwargs):allowed.append(json.loads(os.environ['PM_AGENT_ALLOWED_TOOLS']))
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def start_session(self,name):
                def run(prompt,**kwargs):
                    seen.append(prompt)
                    return SimpleNamespace(events=[],finish_reason='completed',final_response=json.dumps({'summary':'Saved-data interpretation only',
                        'findings':[],'flags':[],'verified':[],'uncertainties':[],'proposed_actions':[]}))
                return SimpleNamespace(run=run)
        with patch.dict(sys.modules,{'deepseek_harness':SimpleNamespace(DeepSeekHarness=Harness)}), \
             patch.object(task_sessions,'role_scope',side_effect=AssertionError('No session reconciliation/network')), \
             patch.object(a.subprocess,'run',side_effect=AssertionError('No executor')):
            a.run_role(11,'recon','Interpret saved data',api_key='fake-only')
        self.assertEqual(len(seen),1);self.assertIn('deactivated',seen[0]);self.assertIn('без брутфорса',seen[0])
        self.assertTrue(set(allowed[0])<=availability.LOCAL_TOOLS);self.assertNotIn('pm_net_exec(',seen[0])

    def test_negative_discovery_changes_knowledge_but_readback_does_not(self):
        from orchestrator import coordinated_attack as c,network_jobs
        import subprocess
        with self.case.connect() as db:
            availability.set_state(db,11,'active','Operator enabled lab checks',source='operator')
            before=c.snapshot(db,11,2)['knowledge_sha256']
            def execute(command,**kwargs):
                result={'task_id':11,'target':'10.0.0.1','profile':'udp_ports','status':'completed','exit_code':0,
                    'stdout':json.dumps({'observations':[{'port':53,'protocol':'udp','state':'open|filtered','service_verified':False}]})}
                return subprocess.CompletedProcess(command,0,json.dumps(result),'')
            with patch.object(network_jobs.subprocess,'run',side_effect=execute):ports.run(db,11,'10.0.0.1','udp',[53])
            after=c.snapshot(db,11,2)['knowledge_sha256'];self.assertNotEqual(before,after)
            ports.summary(db,11,'10.0.0.1')
            self.assertEqual(c.snapshot(db,11,2)['knowledge_sha256'],after)

    def test_offline_flag_acceptance_without_capture_completes_before_model(self):
        from tests import test_manual_flags
        from orchestrator import coordinated_attack as c,operator_questions,flag_review
        from unittest.mock import Mock
        case=test_manual_flags.ManualFlagTests();case.setUp();self.addCleanup(case.doCleanups)
        case.one_goal();case.save('unknown-format-user-file-content')
        with case.case.connect() as db:
            availability.set_state(db,11,'deactivated','Machine stopped',source='operator')
            flag_review.reconcile(db,11,__import__('orchestrator.agent_actions',fromlist=['CAPABILITY_LOG']).CAPABILITY_LOG/'task_11.jsonl')
            question=operator_questions.listing(db,11,pending=True)[0]
            operator_questions.answer(db,11,question['id'],'approve','Accepted by CTF platform while target off')
        model=Mock(side_effect=AssertionError('Goal is already complete'))
        result=c.run(11,expect_flags=1,model=model)
        self.assertTrue(result['succeeded']);model.assert_not_called()


if __name__=='__main__':unittest.main()
