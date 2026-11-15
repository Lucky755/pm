"""Public MCP + temporary SQLite; only the privileged broker boundary is replaced.

No socket/PTY/netlink substitution: this suite needs none of them. Actual local
workers are exercised separately by test_session_runtime on Kali.
"""
import asyncio
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
from contextlib import redirect_stdout
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import pm
from executor.netguard_root import tool_digest
from orchestrator import agent_actions,operator_questions,pivoting,resources,task_memory,task_sessions
from tests import test_coordinated_attack as fixture


class PivotCloseTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        module=importlib.util.spec_from_file_location('pivot_close_mcp',Path(__file__).resolve().parents[1]/'mcp/server.py')
        self.server=importlib.util.module_from_spec(module);module.loader.exec_module(self.server)
        for replacement in (patch.object(self.server,'ASSET_DB',self.case.database),
                patch.object(self.server,'CAPABILITY_LOG',agent_actions.CAPABILITY_LOG),
                patch.object(subprocess,'run',side_effect=self.broker)):
            replacement.start();self.addCleanup(replacement.stop)
        self.calls=[];self.close_response=None;self.status_response=None;self.close_returncode=0
        self.sid='0123abcd'
        with self.case.connect() as db:
            configured=resources.resolve('10.0.0.1',area='lab',networks=['10.2.0.0/24'])
            resources.save(db,11,configured)
            db.execute('UPDATE task_scope_settings SET allow_pivot=1,allow_port_forward=1 WHERE task_id=11')
            ref=resources.node(db,11,'address','10.2.0.5',configured['policy']['machine'])
            task_sessions.save(db,11,self.sid,{'status':'running','running':True,'owner':'',
                'transport':'ssh'},resource='10.0.0.1',username='student',purpose='Internal service',retain=False)
        spec={'source_session':self.sid,'resource_ref':ref,'destination':'10.2.0.5',
            'port':8080,'local_port':18888,'probe':'http_headers','purpose':'Inspect saved internal web service'}
        question=self.call('pm_pivot_request',spec_json=json.dumps(spec))
        self.qid=question['question_id'];self.route_id=question['route']['id']
        with self.case.connect() as db:
            operator_questions.answer(db,11,self.qid,'approve')
            pivoting.apply(db,11,self.route_id,authorize=True)
            task_memory.sync(db,11,self.log,reason='fixture_route_active')
        self.original=self.route()['receipt'];self.rid=self.original['request_id']
        self.calls.clear()

    @property
    def log(self):return agent_actions.CAPABILITY_LOG/'task_11.jsonl'

    def broker(self,argv,**kwargs):
        self.assertEqual(argv[:3],['sudo','-n',task_sessions.BROKER])
        def option(key,default=''):
            return argv[argv.index('--'+key)+1] if '--'+key in argv else default
        action=option('action');self.calls.append((argv[3],action,option('request-id')))
        if argv[3]=='session':
            if action=='list':reply={'status':'ok','sessions':[{'session_id':self.sid,'running':True,'owner':'','transport':'ssh'}]}
            elif action=='release':reply={'status':'released','running':True,'owner':''}
            elif action=='close':reply={'status':'closed','running':False}
            else:raise AssertionError(action)
        elif action=='prepare':
            spec=json.loads(option('spec-json'))
            manifest={'task_id':11,'owner_uid':os.getuid(),'protocol':1,'spec':spec,
                'source_ssh':{'target':'10.0.0.1','user':'student','port':22,'control':'/run/pm-control/control',
                    'control_root':'/broker/private/control','argv':['/usr/bin/ssh']},
                'listener':'127.0.0.1:18888','listener_context':'task_namespace',
                'rights':'task user, fixed SSH forward through existing ControlMaster',
                'actions':['one scoped TCP forward','one bounded destination probe']}
            self.broker_receipt={'request_id':tool_digest(manifest),'manifest':manifest,'status':'prepared'}
            reply=self.broker_receipt
        else:
            self.assertEqual(option('request-id'),self.broker_receipt['request_id'])
            if action=='authorize':self.broker_receipt['status']='approved'
            elif action=='apply':self.broker_receipt.update(status='active',exit_code=0)
            elif action=='close':
                if self.close_response is not None:
                    if isinstance(self.close_response,BaseException):raise self.close_response
                    return subprocess.CompletedProcess(argv,self.close_returncode,json.dumps(self.close_response),'')
                self.broker_receipt.update(status='closed',exit_code=0)
            elif action=='status':
                if self.status_response is not None:return subprocess.CompletedProcess(argv,0,json.dumps(self.status_response),'')
            else:raise AssertionError(action)
            reply=copy.deepcopy(self.broker_receipt)
            if action=='apply':reply.update(status='completed',route_state='active',probe_performed=True)
        return subprocess.CompletedProcess(argv,0,json.dumps(reply),'')

    def call(self,name='pm_pivot',**kwargs):
        if name=='pm_pivot':kwargs={'route_id':self.route_id,**kwargs}
        blocks=asyncio.run(self.server.mcp.call_tool(name,{'task_id':11,**kwargs}))
        if isinstance(blocks,tuple):blocks=blocks[0]
        return json.loads(next(block.text for block in blocks if getattr(block,'type',None)=='text'))

    def route(self):
        with self.case.connect() as db:return pivoting.listing(db,11)[0]

    def dependency(self,db):
        return db.execute('SELECT state FROM pm_session_dependencies WHERE task_id=11 AND session_id=? AND dependent_ref=?',
            (self.sid,'pivot:'+str(self.route_id))).fetchone()[0]

    def assert_identity(self):
        saved=self.route()['receipt']
        self.assertEqual(saved['request_id'],self.rid)
        self.assertEqual(saved['manifest'],self.original['manifest'])

    def render_questions(self):
        output=io.StringIO()
        with patch.object(pm,'connect',self.case.connect),redirect_stdout(output):
            pm.op_questions(SimpleNamespace(task_id=11,json=False))
        return output.getvalue()

    def test_timeout_close_preserves_identity_dependency_and_memory(self):
        self.close_response=subprocess.TimeoutExpired('offline broker',35)
        self.call(action='close');self.assert_identity()
        with self.case.connect() as db:
            self.assertNotEqual(self.dependency(db),'closed')
            head=task_memory.current(db,11)['state']
            self.assertEqual(head['resources']['pivot:'+str(self.route_id)],{'source_owned':True,**self.route()})
            self.assertEqual(head['sessions']['session:'+self.sid]['dependencies'][0]['state'],self.dependency(db))
        self.assertEqual(self.route()['state'],'unknown')

    def test_unknown_close_keeps_unused_source_at_role_end(self):
        self.close_response=subprocess.TimeoutExpired('offline broker',35)
        with self.case.connect() as db:
            with task_sessions.role_scope(db,11,'Keep pivot source'):
                task_sessions.save(db,11,self.sid,{'status':'running','running':True,'owner':task_sessions.owner()},retain=False)
                self.call(action='close')
        self.assertIn(('session','release',''),self.calls)
        self.assertNotIn(('session','close',''),self.calls)

    def test_status_after_unknown_close_uses_original_id_without_replay(self):
        self.close_response=subprocess.TimeoutExpired('offline broker',35)
        self.call(action='close');self.call(action='status')
        self.assertEqual(self.calls,[('pivot','close',self.rid),('pivot','status',self.rid)])
        self.assert_identity();self.assertEqual(self.route()['state'],'active')
        self.assertIn('18888',self.render_questions())

    def test_confirmed_close_updates_dependency_and_memory(self):
        self.call(action='close');self.assert_identity()
        with self.case.connect() as db:
            self.assertEqual(self.dependency(db),'closed')
            state=task_memory.current(db,11)['state']
            self.assertEqual(state['resources']['pivot:'+str(self.route_id)]['state'],'closed')
            self.assertEqual(state['sessions']['session:'+self.sid]['dependencies'][0]['state'],'closed')

    def test_incomplete_or_mismatched_close_is_not_confirmation(self):
        for reply in ({'status':'closed'}, {'status':'closed','request_id':'f'*64,'manifest':self.original['manifest']},
                {**self.original,'status':'closed','exit_code':1},
                {**self.original,'status':'unknown'}, ['unexpected'], 'unexpected'):
            with self.subTest(reply=reply):
                self.close_response=reply
                self.call(action='close');self.assert_identity()
                self.assertEqual(self.route()['state'],'unknown')
                with self.case.connect() as db:self.assertNotEqual(self.dependency(db),'closed')
                self.assertIn('Маршрут',self.render_questions())

    def test_status_can_resolve_closed_after_lost_close_reply(self):
        self.close_response=subprocess.TimeoutExpired('offline broker',35)
        self.call(action='close')
        self.broker_receipt.update(status='closed',exit_code=0)
        self.call(action='status')
        with self.case.connect() as db:self.assertEqual(self.dependency(db),'closed')
        self.assertEqual([action for _,action,_ in self.calls],['close','status'])

    def test_partial_status_does_not_borrow_stale_active_route_state(self):
        self.status_response={'status':'unknown','error':'Offline broker unavailable'}
        self.call(action='status');self.assert_identity()
        self.assertEqual(self.route()['state'],'unknown')

    def test_old_damaged_receipt_is_diagnostic_not_reconstructed(self):
        for receipt in ({'status':'unknown','error':'TimeoutExpired'},
                        {'status':'unknown','request_id':self.rid}, ['unexpected'], '{invalid JSON'):
            with self.subTest(receipt=receipt):
                raw=receipt if isinstance(receipt,str) else json.dumps(receipt)
                with self.case.connect() as db:db.execute('UPDATE pm_pivot_routes SET state=?,receipt_json=? WHERE id=?',('unknown',raw,self.route_id))
                self.calls.clear()
                for action in ('status','apply','probe','close'):
                    reply=self.call(action=action)
                    self.assertEqual(reply['reason_category'],'pivot_receipt_incomplete')
                self.assertEqual(self.calls,[])
                self.assertIn('pivot_receipt_incomplete',self.render_questions())
                with self.case.connect() as db:
                    self.assertEqual(db.execute('SELECT receipt_json FROM pm_pivot_routes WHERE id=?',(self.route_id,)).fetchone()[0],raw)

    def test_memory_failure_rolls_back_route_and_dependency_together(self):
        with self.case.connect() as db:
            before=task_memory.current(db,11)
            db.execute("CREATE TRIGGER reject_pivot_memory BEFORE UPDATE ON pm_memory_heads BEGIN SELECT RAISE(ABORT,'injected memory failure'); END")
        with self.assertRaisesRegex(Exception,'injected memory failure'):self.call(action='close')
        self.assertEqual(self.route()['state'],'active');self.assert_identity()
        with self.case.connect() as db:
            self.assertEqual(self.dependency(db),'active')
            self.assertEqual(task_memory.current(db,11),before)
            db.execute('DROP TRIGGER reject_pivot_memory')
        self.call(action='status')
        self.assertEqual(self.route()['state'],'closed')

    def test_legacy_lost_receipt_and_false_closed_dependency_still_hold_source(self):
        with self.case.connect() as db:
            db.execute('UPDATE pm_pivot_routes SET state=?,receipt_json=? WHERE id=?',
                ('unknown',json.dumps({'status':'unknown'}),self.route_id))
            db.execute("UPDATE pm_session_dependencies SET state='closed' WHERE task_id=11")
        with self.case.connect() as db:
            with task_sessions.role_scope(db,11,'Review lost receipt'):
                task_sessions.save(db,11,self.sid,{'status':'running','running':True,'owner':task_sessions.owner()},retain=False)
                self.call(action='status')
        self.assertIn(('session','release',''),self.calls)
        self.assertNotIn(('session','close',''),self.calls)

    def test_confirmed_closed_dependency_survives_source_cleanup(self):
        self.call(action='close')
        with self.case.connect() as db:
            task_sessions.save(db,11,self.sid,{'status':'closed','running':False})
            self.assertEqual(self.dependency(db),'closed')

    def test_already_closed_route_does_not_repeat_close(self):
        self.call(action='close');self.call(action='status');self.call(action='close')
        self.assertEqual(self.calls,[('pivot','close',self.rid)])

    def test_broker_exit_error_is_not_success_even_with_closed_json(self):
        self.close_response={**self.original,'status':'closed','exit_code':0};self.close_returncode=1
        reply=self.call(action='close');self.assert_identity()
        self.assertEqual(reply['status'],'unknown')
        with self.case.connect() as db:self.assertNotEqual(self.dependency(db),'closed')


if __name__=='__main__':unittest.main()
