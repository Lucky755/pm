"""Offline tests for explicit-task scope, one-shot TCP full scan and IP lineage."""
import argparse
import importlib.util
import io
import json
import sqlite3
import tempfile
import types
import unittest
from contextlib import nullcontext, redirect_stdout
from pathlib import Path
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pm_v5', ROOT / 'pm.py')
pm = importlib.util.module_from_spec(spec); spec.loader.exec_module(pm)
spec2 = importlib.util.spec_from_file_location('pm_v5_broker', ROOT / 'executor/netguard_root.py')
broker = importlib.util.module_from_spec(spec2); spec2.loader.exec_module(broker)


def db_test(path=':memory:'):
    db = sqlite3.connect(path)
    db.executescript('''
    CREATE TABLE tasks(id INTEGER PRIMARY KEY,target TEXT);
    CREATE TABLE task_scope_settings(task_id INTEGER PRIMARY KEY,initial_target TEXT);
    CREATE TABLE pm_operator_approvals(task_id INTEGER PRIMARY KEY,target TEXT,allowed TEXT,egress TEXT,approved_at TEXT,closed_at TEXT);
    CREATE TABLE pm_task_intents(task_id INTEGER PRIMARY KEY,intent TEXT,created_at TEXT);
    CREATE TABLE pm_task_lineage(previous_task_id INTEGER NOT NULL UNIQUE,successor_task_id INTEGER NOT NULL UNIQUE,previous_target TEXT NOT NULL,successor_target TEXT NOT NULL,changed_at TEXT NOT NULL);
    CREATE TABLE pm_tcp_full_scans(id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER NOT NULL,target TEXT NOT NULL,status TEXT NOT NULL,open_ports_json TEXT NOT NULL DEFAULT '[]',error TEXT,created_at TEXT NOT NULL, UNIQUE(task_id,target));
    CREATE TABLE pm_tcp_full_scan_attempts(id INTEGER PRIMARY KEY AUTOINCREMENT,task_id INTEGER,target TEXT,status TEXT,error TEXT,created_at TEXT);
    INSERT INTO tasks VALUES(11,'10.10.10.65');
    INSERT INTO task_scope_settings VALUES(11,'10.10.10.65');
    ''')
    return db

class Tests(unittest.TestCase):
    def test_new_task_is_scoped_without_second_ip_input(self):
        db=db_test()
        with patch('builtins.input', side_effect=AssertionError('unexpected confirmation')), redirect_stdout(io.StringIO()):
            self.assertTrue(pm.ask_approval(db,11,'10.10.10.65','tun0',auto=True,show=False))
        self.assertFalse(pm.ask_approval(db,11,'10.10.10.65','tun0',auto=False,show=False))
        self.assertEqual(db.execute('SELECT allowed FROM pm_operator_approvals').fetchone()[0],'10.10.10.65/32')
        with self.assertRaises(pm.OperatorError): pm.ask_approval(db,11,'10.10.10.66','tun0',auto=True)
        db.close()

    def test_old_task_requires_exact_confirmation(self):
        db=db_test()
        with patch('builtins.input',return_value='no'), redirect_stdout(io.StringIO()):
            with self.assertRaises(pm.OperatorError): pm.ask_approval(db,11,'10.10.10.65','tun0',show=False)
        self.assertFalse(db.execute('SELECT 1 FROM pm_operator_approvals').fetchone())
        db.close()

    def test_full_scan_command_is_bounded_and_no_nse(self):
        argv=broker.tool_args('tcp_full','10.10.10.65','80','','http')
        self.assertEqual(argv[:4],['/usr/bin/nmap','-sT','-Pn','-n'])
        self.assertIn('-p-',argv)
        self.assertEqual(argv[argv.index('--min-rate')+1],'1000')
        self.assertNotIn('-sC',argv)
        self.assertNotIn('-sV',argv)
        self.assertEqual(argv[-1], '10.10.10.65')
        with self.assertRaises(ValueError): broker.check_target('10.10.10.66',['10.10.10.65/32'])

    def test_parse_open_ports_only(self):
        output='''Starting Nmap 7.99\nPORT STATE SERVICE\n22/tcp open ssh\n80/tcp open http\n443/tcp closed https\n3306/tcp open mysql\nNmap done: 1 IP address (1 host up) scanned in 9.5 seconds'''
        self.assertEqual(pm.full_scan_open_ports(output),[22,80,3306])
        with self.assertRaises(pm.OperatorError): pm.full_scan_open_ports('22/tcp open ssh')

    def test_full_scan_once_and_reprobe(self):
        db=db_test()
        response={'status':'completed','stdout':'22/tcp open ssh\n80/tcp open http\nNmap done: done','stderr':'','output_truncated':False}
        with patch.object(pm,'sudo_checked',return_value=(response,0)) as broker_call, \
             patch.object(pm,'plan_reprobe',return_value=101) as plans,redirect_stdout(io.StringIO()):
            self.assertEqual(pm.run_full_tcp_scan(db,11,'10.10.10.65'),1)
            self.assertEqual(pm.run_full_tcp_scan(db,11,'10.10.10.65'),0)
        self.assertEqual(broker_call.call_count,1)
        plans.assert_called_once_with(db,11,'10.10.10.65','22,80')
        self.assertEqual(json.loads(db.execute('SELECT open_ports_json FROM pm_tcp_full_scans').fetchone()[0]),[22,80])
        db.close()

    def test_failed_scan_fails_closed_and_is_audited(self):
        db=db_test()
        with patch.object(pm,'sudo_checked',return_value=({'status':'timeout','stderr':'host timeout'},0)) as calls,redirect_stdout(io.StringIO()):
            with self.assertRaises(pm.OperatorError): pm.run_full_tcp_scan(db,11,'10.10.10.65')
            # A second EXPLICIT invocation may retry, but never retries within
            # the first call or automatically on a background schedule.
            with self.assertRaises(pm.OperatorError): pm.run_full_tcp_scan(db,11,'10.10.10.65')
        self.assertEqual(calls.call_count,2)
        self.assertEqual(db.execute('SELECT status FROM pm_tcp_full_scans').fetchone()[0],'failed')
        self.assertEqual(db.execute('SELECT COUNT(*) FROM pm_tcp_full_scan_attempts').fetchone()[0],2)
        db.close()

    def test_successor_retains_old_task_and_closes_rules(self):
        temporary=tempfile.TemporaryDirectory(prefix='pm-lineage-fixture-')
        self.addCleanup(temporary.cleanup)
        database=Path(temporary.name)/'tasks.db'
        db_test(database).close()
        # Apply the real migrations, rather than duplicating an old lineage schema.
        with patch.object(pm,'DB',database):db=pm.connect()
        self.addCleanup(db.close)
        transitions=Path(temporary.name)/'transitions'
        save_transition=pm.save_transition_snapshot
        complete_transition=pm.complete_pending_transition
        def create_successor(args,*,defer_execution):
            with db:
                db.execute('INSERT INTO tasks VALUES(?,?)',(12,args.target))
                db.execute('INSERT INTO task_scope_settings VALUES(?,?)',(12,args.target))
                db.execute('INSERT INTO pm_operator_approvals VALUES(?,?,?,?,?,NULL)',
                           (12,args.target,args.target+'/32','tun0','2026-10-31'))
                db.execute('INSERT INTO pm_task_intents VALUES(?,?,?)',(12,args.task,'2026-10-31'))
            return 12
        with db:
            db.execute('INSERT INTO pm_operator_approvals VALUES(?,?,?,?,?,NULL)',
                       (11,'10.10.10.65','10.10.10.65/32','tun0','2026-10-31'))
            db.execute('INSERT INTO pm_task_intents VALUES(?,?,?)',
                       (11,'Find flags, no brute force','2026-10-31'))
        args=argparse.Namespace(task_id=11,target='10.10.10.70',egress=None,max_jobs=8,max_rounds=4,
                                no_agents=False,no_decide=False,sync_burp=False,json=False,verbose=False)
        mod=types.ModuleType('orchestrator.master_scheduler')
        mod.exclusive_run_lock=lambda:nullcontext()
        orch=types.ModuleType('orchestrator');orch.master_scheduler=mod
        responses=[({'status':'configured','allowed':['10.10.10.65/32']},0),({'status':'removed'},0)]
        with patch.dict('sys.modules',{'orchestrator':orch,'orchestrator.master_scheduler':mod}),\
             patch.object(pm,'connect',return_value=db),patch.object(pm,'broker_is_trusted'),\
             patch.object(pm,'sudo_authenticate'),patch.object(pm,'sudo_checked',side_effect=responses) as sudo,\
             patch.object(pm,'op_new',side_effect=create_successor) as newborn,\
             patch.object(pm,'save_transition_snapshot',side_effect=lambda *a,**kw:save_transition(*a,**kw,transition_root=transitions)),\
             patch.object(pm,'complete_pending_transition',side_effect=lambda *a:complete_transition(*a,transition_root=transitions)),\
             patch('builtins.input',return_value='no'),\
             patch.object(pm,'launch_configured_task') as launch,\
             patch.object(pm,'get_egress',return_value='tun0'),redirect_stdout(io.StringIO()):
            pm.op_change_ip(args)
        self.assertEqual(db.execute('SELECT target FROM tasks WHERE id=11').fetchone()[0],'10.10.10.65')
        self.assertEqual(db.execute('SELECT successor_task_id FROM pm_task_lineage').fetchone()[0],12)
        self.assertIsNotNone(db.execute('SELECT closed_at FROM pm_operator_approvals WHERE task_id=11').fetchone()[0])
        self.assertEqual(db.execute('SELECT transfer_state FROM pm_task_lineage').fetchone()[0],'done')
        self.assertFalse((transitions/'12.json').exists())
        self.assertTrue(newborn.call_args.kwargs['defer_execution'])
        self.assertEqual(newborn.call_args.args[0].task,'Find flags, no brute force')
        self.assertEqual(sudo.call_args_list[-1].args[0][:3],['teardown','--task-id','11'])
        launch.assert_called_once()
        db.close()

if __name__=='__main__': unittest.main(verbosity=2)
