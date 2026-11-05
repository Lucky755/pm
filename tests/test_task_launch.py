"""Offline new/resume integration: temporary SQLite, fake planner/model/executor."""
from contextlib import nullcontext, ExitStack
import json
import os
import subprocess
from pathlib import Path
import sys
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
if __package__:
    from . import test_coordinated_attack as fixtures
else:
    import test_coordinated_attack as fixtures
decision=fixtures.decision
import pm
from orchestrator import coordinated_attack as c, task_runtime as runtime, diagnostics as d
from orchestrator import master_scheduler as scheduler


class TaskLaunchTests(unittest.TestCase):
    def setUp(self):
        self.case=fixtures.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.trace=[]
        self.scheduler_adapter=pm.call_scheduler
        self.preflight_adapter=pm.preflight_target
        with self.case.connect() as db:
            db.execute('ALTER TABLE pm_task_intents ADD COLUMN created_at TEXT')
        def configured(db,task,args,**kwargs):
            self.assertIn((os.getpid(),task),c._held_tasks.get())
            self.trace.append('scope/NetGuard')
            with db:
                db.execute("INSERT OR IGNORE INTO task_scope_settings VALUES(11,'10.0.0.1',0,0)")
                db.execute("INSERT INTO pm_operator_approvals SELECT 11,'10.0.0.1','10.0.0.1/32',NULL "
                           'WHERE NOT EXISTS(SELECT 1 FROM pm_operator_approvals WHERE task_id=11)')
            return '10.0.0.1'
        def scan(db,task,target):
            self.trace.append('scan')
            db.execute("INSERT INTO pm_tcp_full_scans VALUES(1,11,?,'completed','[22,80]',?,?)",(target,c.now(),c.now()))
            db.commit();return 1
        def preflight(*args):
            self.trace.append('preflight');return {'reachable':[22,80],'unreachable':[]}
        def scout(*args,**kwargs):
            self.trace.append('recon');return {'stop_reason':'queue_empty'}
        def planner(*args):
            self.trace.append('new')
            with self.case.connect() as db:db.execute("INSERT INTO tasks VALUES(11,'10.0.0.1')")
            return 11,{'tasks':[]}
        for p in (patch.object(pm,'connect',self.case.connect),patch.object(pm,'configure',side_effect=configured),
                  patch.object(pm,'run_planner_with_validation_retry',side_effect=planner),
                  patch.object(pm,'run_full_tcp_scan',side_effect=scan),patch.object(pm,'preflight_target',side_effect=preflight),
                  patch.object(pm,'call_scheduler',side_effect=scout),patch.object(pm.getpass,'getpass',return_value='fake-only'),
                  patch.object(c.actions,'run_role',side_effect=self.case.role),patch.object(scheduler,'ROOT',self.case.root)):
            p.start();self.addCleanup(p.stop)

    def args(self,*argv):
        with patch.object(sys,'argv',['pm',*argv]):return pm.parser_main()[1]

    def new(self,via_main=False):
        with self.case.connect() as db:
            for table in ('pm_tcp_full_scans','tasks','pm_task_intents','pm_operator_approvals','task_scope_settings'):
                db.execute('DELETE FROM '+table)
        command=['new','--target','10.0.0.1','--task','Найти флаги; без брутфорса','--coordinated']
        args=self.args(*command)
        model=self.case.model([decision('vuln','Inspect port 80?'),decision(action='wait_operator')])
        with patch.object(c,'choose_with_model',side_effect=lambda prompt,key,tokens:model(prompt,key)):
            if via_main:
                with patch.object(sys,'argv',['pm',*command]),patch('orchestrator.harness_env.ensure_process_env'):
                    pm.main()
            else:
                self.assertEqual(pm.op_new(args),11)
        return args

    def test_real_main_dispatches_new_and_read_only_resume(self):
        self.new(via_main=True)
        self.trace.clear()
        with patch.object(sys,'argv',['pm','resume','11']),patch('orchestrator.harness_env.ensure_process_env'),\
             patch.object(pm,'session_api_key',side_effect=AssertionError('unneeded key')):
            pm.main()
        self.assertEqual(self.trace,[])
        self.assertEqual(len(list(d.EVENT_DIR.glob('*.jsonl'))),2)

    def test_new_recon_role_pause_and_read_only_resume(self):
        self.new()
        self.assertEqual(self.trace,['new','scope/NetGuard','scan','preflight','recon'])
        self.assertEqual([v[0] for v in self.case.calls],['vuln'])
        with self.case.connect() as db:
            self.assertEqual(runtime.saved(db,11)['mode'],'coordinated')
            self.assertEqual(runtime.saved(db,11)['recon_status'],'completed')
        self.trace.clear()
        with patch.object(pm,'session_api_key',side_effect=AssertionError('key requested')),\
             patch.object(c,'run',side_effect=AssertionError('coordinator started')),\
             patch.object(pm,'sudo_checked',side_effect=AssertionError('sudo')):
            result=pm.op_resume(self.args('resume','11'))
        self.assertEqual(result['status'],'waiting_operator')
        self.assertEqual(self.trace,[])
        self.assertFalse(result['succeeded'])
        self.assertEqual(pm.getpass.getpass.call_count,1)
        self.assertNotIn(b'fake-only',self.case.database.read_bytes())

    def test_continue_keeps_run_and_report_numbers_without_rescanning(self):
        self.new()
        with self.case.connect() as db:run_id=runtime.pause(db,11)['coordinator_run_id']
        self.trace.clear()
        model=self.case.model([decision('verify','Verify through an independent HTTP probe?'),decision(action='wait_operator')])
        with patch.object(c,'choose_with_model',side_effect=lambda prompt,key,tokens:model(prompt,key)):
            result=pm.op_resume(self.args('resume','11','--continue-coordinated'))
        self.assertEqual(result['coordinator_run_id'],run_id)
        self.assertEqual(self.trace,['scope/NetGuard','preflight'])
        self.assertEqual([(v[0],v[2]) for v in self.case.calls],[('vuln',1),('verify',2)])

    def test_cached_map_enters_coordinator_without_full_scan_or_old_scheduler(self):
        model=self.case.model([decision()])
        with patch.object(c,'choose_with_model',side_effect=lambda prompt,key,tokens:model(prompt,key)):
            result=pm.op_resume(self.args('resume','11','--coordinated'))
        self.assertEqual(self.trace,['scope/NetGuard','preflight'])
        self.assertEqual(result['stop_reason'],'model_stopped_incomplete')

    def full_preflight_fixture(self, *, reachable=(), unchecked=()):
        """Fake only the broker boundary; never execute its socket script."""
        ports=list(range(1,13))+[9999]
        with self.case.connect() as db:
            db.execute('UPDATE pm_tcp_full_scans SET open_ports_json=?',(json.dumps(ports),))
            db.execute('CREATE TABLE IF NOT EXISTS pm_tcp_full_scan_attempts('
                       'id INTEGER PRIMARY KEY,task_id INTEGER,target TEXT,status TEXT,error TEXT,created_at TEXT)')
        calls=[]
        def broker(command,**kwargs):
            argv=[item[7:] for item in command if item.startswith('--argv=')]
            selected=json.loads(argv[-2]);calls.append(selected)
            self.assertEqual(command[:5],['run','--task-id','11','--profile','exec'])
            self.assertEqual(kwargs['timeout'],20)
            self.assertEqual(command[command.index('--timeout')+1],'12')
            self.assertIn('time.monotonic()+10',argv[2])
            payload={'reachable':[p for p in selected if p in reachable],
                     'unreachable':[p for p in selected if p not in reachable and p not in unchecked],
                     'unchecked':[p for p in selected if p in unchecked]}
            return {'status':'completed','exit_code':0,'stdout':json.dumps(payload)},0
        return ports,calls,broker

    def test_preflight_reaches_port_outside_model_context_selection(self):
        ports,calls,broker=self.full_preflight_fixture(reachable=[9999])
        model=self.case.model([decision('vuln','Inspect the reachable service on port 9999?'),decision(action='wait_operator')])
        with patch.object(pm,'preflight_target',self.preflight_adapter),patch.object(pm,'sudo_checked',side_effect=broker),\
             patch.object(c,'choose_with_model',side_effect=lambda prompt,key,tokens:model(prompt,key)):
            result=pm.op_resume(self.args('resume','11','--coordinated'))
        self.assertEqual(calls,[ports])
        self.assertEqual(result['stop_reason'],'model_waiting_operator')
        self.assertEqual([v[0] for v in self.case.calls],['vuln'])
        self.assertNotIn('scan',self.trace)
        mapped=self.case.prompts[0]['service_map']
        self.assertEqual(len(mapped['entries']),12)
        self.assertEqual(mapped['omitted_entries'],1)
        self.assertNotIn(9999,[entry['port'] for entry in mapped['entries']])

    def test_partial_preflight_does_not_claim_target_unreachable(self):
        ports,calls,broker=self.full_preflight_fixture(unchecked=[9999])
        with d.run('partial preflight',11),patch.object(pm,'preflight_target',self.preflight_adapter),\
             patch.object(pm,'sudo_checked',side_effect=broker),\
             patch.object(pm,'session_api_key',side_effect=AssertionError('model key')):
            result=pm.op_resume(self.args('resume','11','--coordinated'))
            summaries=[e for e in d.read_events() if e['kind']=='preflight.summary']
        self.assertEqual(result['stop_reason'],'reconnaissance_preflight_incomplete')
        self.assertEqual(calls,[ports])
        self.assertFalse(result['succeeded'])
        self.assertEqual(len(summaries),1)
        self.assertEqual([summaries[0][k] for k in ('known_ports','checked_ports','unchecked_ports')],[13,12,1])
        with self.case.connect() as db:
            self.assertEqual(db.execute('SELECT status FROM pm_tcp_full_scan_attempts').fetchone()[0],'preflight_incomplete')
        self.trace.clear()
        with patch.object(pm,'session_api_key',side_effect=AssertionError('key')),\
             patch.object(pm,'sudo_checked',side_effect=AssertionError('network')):
            self.assertEqual(pm.op_resume(self.args('resume','11'))['stop_reason'],'reconnaissance_preflight_incomplete')
        self.assertEqual(self.trace,[])

    def test_all_known_ports_checked_unreachable_is_definitive(self):
        ports,calls,broker=self.full_preflight_fixture()
        with d.run('negative preflight',11),patch.object(pm,'preflight_target',self.preflight_adapter),\
             patch.object(pm,'sudo_checked',side_effect=broker):
            result=pm.op_resume(self.args('resume','11','--coordinated'))
            summaries=[e for e in d.read_events() if e['kind']=='preflight.summary']
        self.assertEqual(calls,[ports])
        self.assertEqual(result['stop_reason'],'reconnaissance_target_unreachable')
        self.assertEqual([summaries[0][k] for k in ('known_ports','checked_ports','unchecked_ports')],[13,13,0])

    def test_unchecked_ports_with_a_reachable_port_still_allow_coordinator(self):
        ports,calls,broker=self.full_preflight_fixture(reachable=[1],unchecked=list(range(2,13))+[9999])
        model=self.case.model([decision()])
        with d.run('reachable partial',11),patch.object(pm,'preflight_target',self.preflight_adapter),\
             patch.object(pm,'sudo_checked',side_effect=broker),\
             patch.object(c,'choose_with_model',side_effect=lambda prompt,key,tokens:model(prompt,key)):
            result=pm.op_resume(self.args('resume','11','--coordinated'))
            summary=next(e for e in d.read_events() if e['kind']=='preflight.summary')
        self.assertEqual(result['stop_reason'],'model_stopped_incomplete')
        self.assertEqual(calls,[ports])
        self.assertEqual([summary[k] for k in ('known_ports','checked_ports','unchecked_ports','reachable_ports')],[13,1,12,1])
        self.assertEqual(summary['reason'],'at_least_one_port_reachable')

    def test_legacy_partial_preflight_does_not_claim_target_unreachable(self):
        _,calls,broker=self.full_preflight_fixture(unchecked=[9999])
        with self.case.connect() as db,patch.object(pm,'run_full_tcp_scan',return_value=0),\
             patch.object(pm,'preflight_target',self.preflight_adapter),patch.object(pm,'sudo_checked',side_effect=broker):
            with self.assertRaisesRegex(pm.OperatorError,'ещё не проверены; недоступность цели не установлена'):
                pm.launch_configured_task(db,11,'10.0.0.1',self.args('resume','11'))
        self.assertEqual(len(calls),1)
        pm.call_scheduler.assert_not_called()

    def test_preflight_uses_tcp_only_and_excludes_foreign_task_and_old_ip(self):
        ports,calls,broker=self.full_preflight_fixture(reachable=[9999])
        with self.case.connect() as db:
            db.executescript('''
                CREATE TABLE network_phase_plans(id INTEGER PRIMARY KEY,task_id INTEGER,target TEXT,
                    profile TEXT,parameters_json TEXT);
                CREATE TABLE network_job_runs(id INTEGER PRIMARY KEY,plan_id INTEGER,status TEXT,result_json TEXT);
                CREATE TABLE network_observations(id INTEGER PRIMARY KEY,run_id INTEGER,task_id INTEGER,
                    target TEXT,kind TEXT,data_json TEXT,observed_at TEXT);
            ''')
            for number,task,target,protocol,port,status in (
                    (1,11,'10.0.0.1','udp',53,'completed'),(2,11,'10.0.0.1','tcp',8080,'completed'),
                    (3,22,'10.0.0.1','tcp',4444,'completed'),(4,11,'10.0.0.9','tcp',5555,'completed'),
                    (5,11,'10.0.0.1','tcp',7777,'running')):
                db.execute("INSERT INTO network_phase_plans VALUES(?,?,?,'service_versions','{}')",(number,task,target))
                db.execute("INSERT INTO network_job_runs VALUES(?,?,?,'{}')",(number,number,status))
                db.execute("INSERT INTO network_observations VALUES(?,?,?,?, 'service_probe',?,?)",
                           (number,number,task,target,json.dumps({'port':port,'protocol':protocol,'state':'open'}),c.now()))
            db.execute("INSERT INTO pm_tcp_full_scans VALUES(2,22,'10.0.0.1','completed','[8888]',?,?)",(c.now(),c.now()))
            db.execute("INSERT INTO pm_tcp_full_scans VALUES(3,11,'10.0.0.9','completed','[6666]',?,?)",(c.now(),c.now()))
        model=self.case.model([decision()])
        with patch.object(pm,'preflight_target',self.preflight_adapter),patch.object(pm,'sudo_checked',side_effect=broker),\
             patch.object(c,'choose_with_model',side_effect=lambda prompt,key,tokens:model(prompt,key)):
            pm.op_resume(self.args('resume','11','--coordinated'))
        self.assertEqual(calls,[sorted(ports+[8080])])
        self.assertNotIn('scan',self.trace)

    def test_running_step_is_only_displayed_even_with_continue(self):
        def interrupt(*args,**kwargs):raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            c.run(11,api_key='fake-only',model=self.case.model([decision('vuln','Check once?')]),role_runner=interrupt)
        with self.case.connect() as db:runtime.save_mode(db,11,'coordinated')
        with patch.object(pm,'session_api_key',side_effect=AssertionError('key')):
            result=pm.op_resume(self.args('resume','11','--continue-coordinated'))
        self.assertEqual(result['stop_reason'],'interrupted_running_step')
        self.assertEqual(self.trace,[])

    def test_interrupted_full_scan_is_not_replayed_or_reconfigured(self):
        with self.case.connect() as db:
            runtime.save_mode(db,11,'coordinated')
            runtime.reconnaissance(db,11,'running')
            db.execute("UPDATE pm_tcp_full_scans SET status='running'")
        for flags in ([],['--continue-coordinated']):
            with self.subTest(flags=flags):
                result=pm.op_resume(self.args('resume','11',*flags))
                self.assertEqual(result['stop_reason'],'interrupted_full_tcp_scan')
        self.assertEqual(self.trace,[])

    def test_incompatible_options_fail_before_planner_or_network(self):
        for command in (
            ['new','--target','10.0.0.1','--task','Test','--coordinated','--no-agents'],
            ['new','--target','10.0.0.1','--task','Test','--coordinator-steps','8'],
            ['new','--target','10.0.0.1','--task','Test','--coordinated','--approve-step','1'],
            ['new','--target','10.0.0.1','--task','Test','--coordinated','--step-limit','0'],
            ['resume','11','--coordinated','--no-decide'],
            ['resume','11','--roles','vuln'],
            ['new','--target','10.0.0.1','--task','Test','--coordinated','--flag-pattern','['],
            ['new','--target','10.0.0.1','--task','Test','--coordinated','--egress','auto'],
            ['resume','11','--coordinated','--expect-flags','bad'],
            ['resume','11','--coordinated','--reprobe','80,80'],
            ['resume','11','--coordinated','--continue-coordinated','--approve-step','1']):
            with self.subTest(command=command),self.assertRaises(pm.OperatorError):
                args=self.args(*command)
                (pm.op_new if command[0]=='new' else pm.op_resume)(args)
        self.assertEqual(self.trace,[])
        self.assertEqual(self.case.calls,[])
        with self.case.connect() as db:self.assertIsNone(runtime.saved(db,11))

    def test_access_approval_and_bad_id_are_explicit_before_network(self):
        model=self.case.model([decision('access','Prove the authorized user boundary?')])
        with patch.object(c,'choose_with_model',side_effect=lambda prompt,key,tokens:model(prompt,key)):
            result=pm.op_resume(self.args('resume','11','--coordinated'))
        step=result['steps'][0]['id'];self.trace.clear()
        with self.assertRaises(pm.OperatorError):pm.op_resume(self.args('resume','11','--approve-step',str(step+10)))
        self.assertEqual(self.trace,[]);self.assertEqual(self.case.calls,[])
        model=self.case.model([decision(action='wait_operator')])
        with patch.object(c,'choose_with_model',side_effect=lambda prompt,key,tokens:model(prompt,key)):
            result=pm.op_resume(self.args('resume','11','--approve-step',str(step)))
        self.assertEqual(result['steps'][0]['status'],'completed')
        self.assertEqual([v[0] for v in self.case.calls],['access'])

    def test_pending_pause_cannot_be_bypassed_by_legacy_or_mutating_flags(self):
        self.new();self.trace.clear()
        for flags in (['--legacy'],['--reprobe','80'],['--coordinator-steps','2'],['--flag-pattern','FLAG']):
            with self.subTest(flags=flags),self.assertRaises(pm.OperatorError):
                pm.op_resume(self.args('resume','11',*flags))
        self.assertEqual(self.trace,[])
        with self.case.connect() as db:self.assertEqual(runtime.saved(db,11)['mode'],'coordinated')

    def test_task_lock_is_borrowed_and_blocks_a_second_process(self):
        with patch.object(c.fcntl,'flock',wraps=c.fcntl.flock) as flock:
            self.new()
        self.assertEqual(flock.call_count,2)  # one acquisition and one release
        script="import fcntl,sys\nf=open(sys.argv[1],'a+')\ntry:\n fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\n print('unsafe')\nexcept BlockingIOError:\n print('blocked')\n"
        with c.task_lock(11):
            output=subprocess.check_output([sys.executable,'-c',script,str(c.LOCK_DIR/'11.lock')],text=True)
        self.assertEqual(output.strip(),'blocked')

    def test_resume_menu_shows_saved_pause_without_key_or_network(self):
        self.new();self.trace.clear()
        with patch('builtins.input',side_effect=['2','11','','','0']),\
             patch.object(pm,'session_api_key',side_effect=AssertionError('key')):
            pm.interactive()
        self.assertEqual(self.trace,[])
        self.assertIn('Сохранённый режим: coordinated',self.case.console.getvalue())
        self.assertIn('model_waiting_operator',self.case.console.getvalue())

    def test_budget_types_are_independent(self):
        with self.case.connect() as db:db.execute('DELETE FROM pm_tcp_full_scans')
        args=self.args('resume','11','--coordinated','--max-jobs','3','--max-rounds','2',
                       '--coordinator-steps','2','--poc-budget','2','--step-limit','4','--max-tokens','600')
        model=self.case.model([decision('vuln','Inspect a saved service?'),decision(action='wait_operator')])
        with patch.object(c,'choose_with_model',side_effect=lambda prompt,key,tokens:model(prompt,key)):
            pm.op_resume(args)
        self.assertEqual(pm.call_scheduler.call_args.args[3].max_jobs,2)
        self.assertEqual(pm.call_scheduler.call_args.args[3].max_rounds,2)
        self.assertEqual(self.case.calls[0][3:5],(2,4))
        self.assertEqual(self.case.calls[0][5]['max_tokens'],600)

    def test_legacy_task_stays_on_legacy_route(self):
        with patch.object(pm,'launch_legacy_task',return_value='legacy') as old:
            self.assertEqual(pm.op_resume(self.args('resume','11')),'legacy')
        old.assert_called_once()

    def test_old_task_does_not_infer_launch_mode_from_coordinator_history(self):
        c.run(11,api_key='fake-only',model=self.case.model([decision(action='wait_operator')]),role_runner=self.case.role)
        with self.case.connect() as db:self.assertIsNone(runtime.saved(db,11))
        with patch.object(pm,'launch_legacy_task',return_value='legacy'):
            self.assertEqual(pm.op_resume(self.args('resume','11')),'legacy')

    def test_recon_budget_pause_is_not_success_and_is_read_only_on_resume(self):
        with self.case.connect() as db:db.execute('DELETE FROM pm_tcp_full_scans')
        result=pm.op_resume(self.args('resume','11','--coordinated','--max-jobs','1'))
        self.assertEqual(result['stop_reason'],'reconnaissance_job_budget')
        self.assertFalse(result['succeeded']);self.assertEqual(self.case.calls,[])
        self.trace.clear()
        result=pm.op_resume(self.args('resume','11'))
        self.assertEqual(self.trace,[])
        self.assertEqual(result['status'],'waiting_operator')

    def test_two_menu_operations_have_distinct_runs_and_one_lazy_key(self):
        from unittest.mock import Mock
        def first(args):
            pm.session_api_key(args,required=True)
            self.assertEqual(os.environ['PM_RUN_ID'],d.context()['run_id'])
            child=subprocess.check_output([sys.executable,'-c',"import os;print(os.environ['PM_RUN_ID'])"],text=True).strip()
            self.assertEqual(child,d.context()['run_id'])
            d.emit('fixture.operation',task_id=11,reason='new')
        def second(args):
            pm.session_api_key(args,required=True)
            self.assertEqual(os.environ['PM_RUN_ID'],d.context()['run_id'])
            d.emit('fixture.operation',task_id=11,reason='resume')
        answers=['1','10.0.0.1','1','Find flags','','','','','','','','',
                 '2','11','','','','0']
        # New: IP/mode/task/side/exclusive/expect/limits/hints/pattern/force/hosts.
        with patch('builtins.input',side_effect=answers),patch.object(pm,'op_new',side_effect=first),\
             patch.object(pm,'op_resume',side_effect=second),patch.object(pm.getpass,'getpass',return_value='fake-only') as key:
            pm.interactive()
        events=[json.loads(line) for path in d.EVENT_DIR.glob('*.jsonl') for line in path.read_text().splitlines()]
        actions=[e for e in events if e['kind']=='fixture.operation']
        self.assertEqual(len(actions),2)
        self.assertEqual(len({e['run_id'] for e in actions}),2)
        self.assertEqual(key.call_count,1)
        self.assertNotIn('fake-only',json.dumps(events))

    def test_one_run_spans_creation_to_pause_and_continuation_keeps_coordinator_id(self):
        with d.run('new fixture',fresh=True):self.new()
        model=self.case.model([decision('verify','Verify with an independent probe?'),decision(action='wait_operator')])
        with d.run('resume fixture',11,fresh=True),\
             patch.object(c,'choose_with_model',side_effect=lambda prompt,key,tokens:model(prompt,key)):
            pm.op_resume(self.args('resume','11','--continue-coordinated'))
        journals=[[json.loads(line) for line in path.read_text().splitlines()] for path in d.EVENT_DIR.glob('*.jsonl')]
        self.assertEqual(len(journals),2)
        for events in journals:
            self.assertEqual(len({e['run_id'] for e in events}),1)
            self.assertTrue(any(e['kind']=='cache.hit' or e['kind']=='state.change' and e.get('table')=='pm_task_runtime' for e in events))
            self.assertTrue(any(e['kind']=='coordinator.decision' for e in events))
        ids={e['coordinator_run_id'] for events in journals for e in events if e['kind']=='coordinator.decision'}
        self.assertEqual(ids,{1})

    def test_menu_exit_does_not_request_key(self):
        with patch('builtins.input',return_value='0'),patch.object(pm,'session_api_key',side_effect=AssertionError('key')):
            pm.interactive()

    def test_interactive_legacy_attack_keeps_working(self):
        answers=['7','11','','2','','','','','','0']
        with patch('builtins.input',side_effect=answers),patch.object(pm,'netguard_live_tasks',return_value=[]),\
             patch.object(c.attack_loop,'run',return_value={'stop_reason':'iterations_done','stages':[]}) as old:
            pm.interactive()
        old.assert_called_once()

    def test_attack_rejects_flags_for_the_other_mode(self):
        for flags in (['--coordinator-steps','8'],['--coordinated','--iterations','7']):
            with self.subTest(flags=flags),self.assertRaises(pm.OperatorError):
                pm.op_attack(self.args('attack','11',*flags))

    def test_discovery_calls_real_scheduler_without_analysis_or_decide(self):
        # Restore the real adapter; keep its deterministic executor and sources fake.
        args=self.args('resume','11','--coordinated')
        bundle={'network_observations':[{'observation_id':1}],'burp_http_metadata':[],'web_observations':[]}
        from orchestrator import evidence_pipeline as ev, decision_agent as dec, network_jobs as jobs
        from orchestrator import bootstrap_discovery as boot, http_discovery as web
        agents=Mock();decide=Mock()
        patches=[patch.object(scheduler,'exclusive_run_lock',return_value=nullcontext()),
                 patch.object(jobs,'initialize'),patch.object(scheduler,'validate_task',return_value='10.0.0.1'),
                 patch.object(scheduler,'pending',return_value=[]),patch.object(scheduler,'execute_pending',return_value=[]),
                 patch.object(scheduler,'compact_status',return_value={'task_id':11}),
                 patch.object(boot,'safe_task_target'),patch.object(boot,'queue_next',return_value=[]),patch.object(boot,'has_more',return_value=False),patch.object(boot,'progress',return_value={}),
                 patch.object(scheduler.workflow,'create_followups',return_value=[]),patch.object(scheduler.enrichment,'plan_followups',return_value=[]),
                 patch.object(ev,'make_snapshot',return_value=('same',bundle)),patch.object(ev,'run_agents',agents),
                 patch.object(dec,'plan',decide),patch.object(web,'require_capture_support'),patch.object(web,'validate_scope'),
                 patch.object(web,'execute_round',return_value=[]),patch.object(web,'has_more',return_value=False),
                 patch.object(web,'evidence_rows',return_value=[]),patch.object(web,'queue_status',return_value={}),
                 patch.object(pm,'session_api_key',side_effect=AssertionError('unneeded key')),
                 patch.object(pm,'offer_cleanup_if_verified',side_effect=AssertionError('cleanup'))]
        with ExitStack() as stack, self.case.connect() as db:
            for p in patches:stack.enter_context(p)
            result=self.scheduler_adapter(db,11,'10.0.0.1',args)
        self.assertEqual(result['stop_reason'],'no_progress')
        agents.assert_not_called();decide.assert_not_called()


def demo():
    case=TaskLaunchTests();case.setUp()
    try:
        with d.run('offline new',fresh=True):case.new()
        first=list(case.trace);case.trace.clear()
        with d.run('offline resume',11,fresh=True):result=pm.op_resume(case.args('resume','11'))
        view=list(case.trace);case.trace.clear()
        model=case.case.model([decision('verify','Verify independently?'),decision(action='wait_operator')])
        with d.run('offline continue',11,fresh=True),patch.object(c,'choose_with_model',side_effect=lambda prompt,key,tokens:model(prompt,key)):
            result=pm.op_resume(case.args('resume','11','--continue-coordinated'))
        paths=sorted(d.EVENT_DIR.glob('*.jsonl'))
        events=[json.loads(line) for path in paths for line in path.read_text().splitlines()]
        runs={e['run_id'] for e in events if e['kind']=='run.start'}
    finally:case.doCleanups()
    print('new -> '+ ' -> '.join(first[1:])+' -> VULN report 1 -> waiting_operator')
    print('resume -> saved coordinated pause; network calls:',view)
    print('resume --continue-coordinated -> '+' -> '.join(case.trace)+' -> VERIFY report 2 -> waiting_operator')
    print('diagnostic runs:',len(runs),'coordinator_run_id:',result['coordinator_run_id'],'goal confirmed:',result['succeeded'])


def demo_ports():
    case=TaskLaunchTests();case.setUp()
    try:
        ports,calls,broker=case.full_preflight_fixture(reachable=[9999])
        model=case.case.model([decision('vuln','Inspect the reachable port 9999?'),decision(action='wait_operator')])
        with d.run('offline full inventory',11),patch.object(pm,'preflight_target',case.preflight_adapter),\
             patch.object(pm,'sudo_checked',side_effect=broker),\
             patch.object(c,'choose_with_model',side_effect=lambda prompt,key,tokens:model(prompt,key)):
            result=pm.op_resume(case.args('resume','11','--coordinated'))
            summary=next(e for e in d.read_events() if e['kind']=='preflight.summary')
        mapped=case.case.prompts[0]['service_map']
    finally:case.doCleanups()
    print('preflight ports:',calls[0],'reachable: [9999]')
    print('preflight.summary '+' '.join(f'{key}={summary[key]}' for key in
          ('known_ports','checked_ports','unchecked_ports','reachable_ports','reason')))
    print('model context: entries=',len(mapped['entries']),'omitted=',mapped['omitted_entries'])
    print('roles:',[call[0] for call in case.case.calls],'stop:',result['stop_reason'],
          'full scans:',case.trace.count('scan'),'goal confirmed:',result['succeeded'])


if __name__=='__main__':
    if sys.argv[1:]==['--demo']:demo()
    elif sys.argv[1:]==['--demo-ports']:demo_ports()
    else:unittest.main()
