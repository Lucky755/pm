"""Real local PTY input/output and real Harness cancellation; temporary data only."""
from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import pty
import select
import sqlite3
import threading
import time
import unittest
from unittest.mock import patch
from orchestrator import operator_console as ui,model_adapter as adapter,coordinated_attack as c,operator_questions
from tests import test_coordinated_attack as fixture
from tests import test_specialist_workflow_runtime as sdk_fixture
from tests.test_operator_console import question


@contextmanager
def terminal():
    master,slave=pty.openpty();output=os.fdopen(os.dup(slave),'w',buffering=1);input_stream=os.fdopen(os.dup(slave),'r')
    collected=bytearray();stop=threading.Event()
    def consume():
        while not stop.is_set():
            if not select.select([master],[],[],.05)[0]:continue
            try:raw=os.read(master,65536)
            except OSError as exc:
                if exc.errno==errno.EIO:return
                raise
            if not raw:return
            collected.extend(raw)
    reader=threading.Thread(target=consume);reader.start()
    try:yield master,input_stream,output,collected
    finally:
        stop.set();reader.join();input_stream.close();output.close();os.close(slave);os.close(master)


class ConsolePTYTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)

    def test_partial_input_survives_parallel_output_and_answers_only_selected_question(self):
        with self.case.connect() as db:
            operator_questions.initialize(db)
            for qid in (1,2):
                q=question(qid);db.execute('INSERT INTO pm_operator_questions(id,task_id,target,kind,branch_id,question,reason,boundaries_json,references_json,fingerprint,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                    (qid,11,q['target'],q['kind'],q['branch_id'],q['question'],q['reason'],json.dumps(q['boundaries']),'[]',str(qid),'pending','now'))
        answered=threading.Event()
        def questions():
            with self.case.connect() as db:return operator_questions.listing(db,11,pending=True)
        def answer(qid,decision):
            with self.case.connect() as db:operator_questions.answer(db,11,qid,decision,'Explicit local console test')
            answered.set()
        with terminal() as (master,inp,out,transcript),adapter.execution_control() as control:
            live=ui.LiveSession(control,questions,answer,input_stream=inp,output=out);live.start()
            try:
                os.write(master,'да '.encode());time.sleep(.1)
                workers=[threading.Thread(target=lambda name=name:[live.say(name+' progress '+str(i)) for i in range(10)]) for name in ('WEB','ACCESS')]
                for worker in workers:worker.start()
                for worker in workers:worker.join()
                os.write(master,b'2\n');self.assertTrue(answered.wait(4))
            finally:live.close()
            text=transcript.decode(errors='replace')
            self.assertIn('WEB progress 9',text);self.assertIn('ACCESS progress 9',text);self.assertIn('да 2',text)
        with self.case.connect() as db:
            rows=operator_questions.listing(db,11)
            self.assertEqual([q['status'] for q in rows],['pending','answered'])

    def test_flag_literal_is_not_redacted_and_exit_restores_terminal(self):
        import termios
        from orchestrator import agent_actions,objectives,target_availability
        with self.case.connect() as db:
            objectives.save_objectives(db,11,'root.txt',expected_flags=1)
            agent_actions.save_report(db,{'task_id':11,'target':'10.0.0.1'},'access',1,{
                'summary':'A saved candidate requires platform acceptance.','findings':[],
                'flags':[{'value':'token=UNKNOWN_COPYABLE_FLAG','source':'/root/root.txt','method':'saved shell read',
                          'objective_key':'goal','goal_evidence':'saved-result-without-capture'}]},1)
            target_availability.set_state(db,11,'deactivated','Offline test machine is deactivated',source='operator')
            q=operator_questions.listing(db,11,pending=True)[0]
        answered=threading.Event()
        def questions():
            with self.case.connect() as db:return operator_questions.listing(db,11,pending=True)
        def answer(qid,decision):
            with self.case.connect() as db:operator_questions.answer(db,11,qid,decision,'Operator checked the flag on the test platform')
            answered.set()
        with terminal() as (master,inp,out,transcript),adapter.execution_control() as control:
            before=termios.tcgetattr(inp.fileno())
            live=ui.LiveSession(control,questions,answer,input_stream=inp,output=out);live.start()
            try:
                deadline=time.monotonic()+4
                while b'UNKNOWN_COPYABLE_FLAG' not in transcript and time.monotonic()<deadline:time.sleep(.02)
                os.write(master,('да '+str(q['id'])+'\n').encode());self.assertTrue(answered.wait(3))
                os.write(master,b'exit\n');self.assertTrue(control.stopped.wait(3))
            finally:live.close()
            self.assertEqual(termios.tcgetattr(inp.fileno()),before)
            self.assertIn('Для копирования: token=UNKNOWN_COPYABLE_FLAG',transcript.decode())
        with self.case.connect() as db:
            self.assertEqual(objectives.objective_status(db,11)['objectives'][0]['status'],'confirmed')
        result=c.run(11,expect_flags=1,model=lambda *_:self.fail('No model/GET after operator acceptance'))
        self.assertTrue(result['succeeded'])


class ConsoleHarnessRuntimeTests(unittest.TestCase):
    def test_exit_during_real_concurrent_harness_stops_requests_and_preserves_unknown_steps(self):
        real=sdk_fixture.SpecialistRuntimeTests();real.setUp();self.addCleanup(real.doCleanups)
        actor_errors=[]
        with terminal() as (master,inp,out,transcript),adapter.execution_control() as control:
            live=ui.LiveSession(control,lambda:[],lambda *_:None,input_stream=inp,output=out);live.start()
            def exit_when_active():
                deadline=time.monotonic()+25
                while not (real.root/'ssh-started').exists() and time.monotonic()<deadline:time.sleep(.02)
                if not (real.root/'ssh-started').exists():actor_errors.append('Two real specialists did not start')
                os.write(master,b'exit\n')
            actor=threading.Thread(target=exit_when_active);actor.start()
            try:
                with self.assertRaises(adapter.OperatorStop):real.run_chain()
            finally:
                live.close();actor.join(3);real.release.set()
        self.assertFalse(actor_errors,actor_errors)
        with real.case.connect() as db:
            rows=c.steps(db,11);self.assertTrue(any(s['outcome_uncertain'] for s in rows))
            self.assertFalse(any(s['status']=='running' for s in rows))
            from orchestrator import task_runtime
            self.assertEqual(task_runtime.pause(db,11)['stop_reason'],'interrupted')
        paused=c.run(11,max_specialists=2,model=lambda *_:self.fail('Paused view must not call model'))
        self.assertEqual(paused['status'],'waiting_operator')
        # The fake provider is local, but SDK, MCP, HTTP/SSH and owned close are real.
        count=len(real.host.api.requests) if hasattr(real.host,'api') else len(real.prompts)
        time.sleep(.2)
        self.assertEqual(len(real.prompts),count)


if __name__=='__main__':unittest.main(verbosity=2)
