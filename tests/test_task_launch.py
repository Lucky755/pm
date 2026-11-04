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


if __name__=='__main__':
    if sys.argv[1:]==['--demo']:demo()
    else:unittest.main()
