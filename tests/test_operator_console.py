"""Human summaries, retained diagnostics and explicit question selection; offline."""
from contextlib import redirect_stderr,redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import subprocess
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from orchestrator import diagnostics as d,operator_console as ui,model_adapter as adapter
import pm


def question(qid=1,kind='budget'):
    return {'id':qid,'task_id':11,'target':'10.0.0.1','kind':kind,'status':'pending','branch_id':'service:10.0.0.1:tcp:80',
        'question':'Allow the concrete saved dependency?','reason':'The named branch needs a decision.',
        'boundaries':{'task_id':11,'target':'10.0.0.1','resource_refs':['service:10.0.0.1:tcp:80']},'references':['result:'+ 'a'*24]}


class OperatorConsoleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='pm-console-');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        for manager in (patch.object(d,'EVENT_DIR',self.root/'events'),patch.dict(os.environ,{**{k:'' for k in d.ENV_KEYS},'PM_DIAGNOSTIC':''}),d.presentation('human')):
            manager.__enter__();self.addCleanup(manager.__exit__,None,None,None)

    def test_human_default_keeps_journal_and_hides_internal_events_and_json(self):
        out=io.StringIO()
        with redirect_stderr(out),d.run('test',11):
            d.emit('coordinator.decision',role='vuln',question='Inspect one scoped HTTP hypothesis',expected_result='Saved original bytes')
            with d.Action('tool','pm_http_request') as action:
                d.record_result({'status':'completed','status_code':200,'result_id':'a'*24})
            d.emit('state.change',table='internal',identifiers={'id':1})
        value=out.getvalue()
        for text in ('Следующий шаг','Действие','операция выполнена','HTTP 200','Журнал запуска'):self.assertIn(text,value)
        self.assertNotIn('[EVENT]',value);self.assertNotIn("{'id'",value)
        events=[json.loads(line) for p in d.EVENT_DIR.glob('*.jsonl') for line in p.read_text().splitlines()]
        self.assertTrue(any(e['kind']=='state.change' for e in events));self.assertFalse(d.unfinished(events))

    def test_debug_is_explicit_and_progress_preserves_it(self):
        out=io.StringIO()
        with d.presentation('debug'),redirect_stderr(out),d.run('debug',11):d.emit('state.change',identifiers={'id':1})
        progress=pm.ConciseProgress(io.StringIO(),diagnostic=True);progress.write(out.getvalue());progress.flush()
        self.assertIn('[EVENT]',progress.stream.getvalue())
        human=pm.ConciseProgress(io.StringIO());human.write(out.getvalue());human.write('[PM] Результат сохранён\n');human.flush()
        self.assertNotIn('[EVENT]',human.stream.getvalue());self.assertIn('Результат сохранён',human.stream.getvalue())

    def test_different_operation_outcomes_are_not_goal_success(self):
        expected={'completed':'операция выполнена','nonzero_exit':'ненулевым','blocked':'отказ до исполнения',
            'timeout':'исход неизвестен','unknown':'исход неизвестен','error':'ошибка исполнителя'}
        for status,label in expected.items():
            lines=ui.event_lines({'kind':'tool.end','name':'probe','status':status,'duration_seconds':1,'result_id':'a'*24,'evidence_path':'/tmp/full.jsonl'})
            self.assertIn(label,' '.join(lines));self.assertIn('/tmp/full.jsonl',' '.join(lines))
        self.assertIn('сервер отказал',' '.join(ui.event_lines({'kind':'tool.end','status':'completed','name':'probe','server_outcome':'refused'})))
        self.assertIn('повреждён',' '.join(ui.event_lines({'kind':'report.saved','quality':'damaged','report_path':'/tmp/report.json'})))
        self.assertIn('исчерпан бюджет',ui.reason('budget_exhausted'));self.assertIn('сохранённые',ui.reason('target_offline'))

    def test_only_explicit_question_id_receives_answer(self):
        rows=[question(1),question(2)];answers=[]
        control=adapter.ExecutionControl();live=ui.LiveSession(control,lambda:rows,lambda *args:answers.append(args),enabled=False,output=io.StringIO())
        live.command('да');live.command('yes');live.command('да 99');self.assertFalse(answers)
        live.command('да 2');self.assertEqual(answers,[(2,'approve')])
        live.command('нет 1');self.assertEqual(answers[-1],(1,'decline'))
        text='\n'.join(ui.question_lines(rows[0]))
        for value in ('Вопрос #1','Причина','Границы','Да:','Нет:','ID обязателен'):self.assertIn(value,text)

    def test_flag_value_is_exact_and_key_is_never_displayed(self):
        q=question(2,'flag_confirmation');q['flag_candidate']={'value':'token=UNKNOWN_FORMAT_FLAG','objective_key':'root',
            'objective_title':'root.txt','sources':[{'source':'saved shell result','method':'file read'}],'materials':['result:a']}
        text='\n'.join(ui.question_lines(q));self.assertIn('Для копирования: token=UNKNOWN_FORMAT_FLAG',text)
        self.assertIn('платформе',text);self.assertIn('без повторного GET',text)
        d.register_secret('API-SECRET-FOR-CONSOLE-TEST');q['flag_candidate']['value']='API-SECRET-FOR-CONSOLE-TEST'
        self.assertNotIn(q['flag_candidate']['value'],'\n'.join(ui.question_lines(q)))

    def test_concurrent_partial_lines_are_not_spliced(self):
        out=io.StringIO();progress=pm.ConciseProgress(out);barrier=threading.Barrier(2)
        def write(label):
            progress.write('[PM] '+label);barrier.wait(2);progress.write(' done\n')
        workers=[threading.Thread(target=write,args=(name,)) for name in ('WEB','SSH')]
        for worker in workers:worker.start()
        for worker in workers:worker.join(3)
        progress.flush();self.assertIn('WEB done',out.getvalue());self.assertIn('SSH done',out.getvalue())

    def test_exit_stops_all_owned_runtimes_and_future_model_calls(self):
        calls=[]
        class Runtime:
            def __init__(self,name):self.name=name
            def cancel(self):calls.append(self.name)
        with adapter.execution_control() as control:
            for name in ('coordinator','web','access'):
                control.attach(Runtime(name))
            live=ui.LiveSession(control,lambda:[],lambda *_:self.fail('No answer'),enabled=False,output=io.StringIO())
            live.command('выход')
            with self.assertRaises(adapter.OperatorStop):adapter.check_cancelled()
        self.assertEqual(sorted(calls),['access','coordinator','web'])
        failed_control=adapter.ExecutionControl()
        broken=ui.LiveSession(failed_control,lambda:[],lambda *_:None,enabled=False,output=io.StringIO())
        with patch.object(broken,'draw',side_effect=OSError('TTY lost')),patch.object(broken,'say',side_effect=OSError('TTY lost')):
            broken.read_loop()
        self.assertTrue(failed_control.stopped.is_set())

    def test_poc_check_summary_does_not_claim_universal_measurement(self):
        text=' '.join(ui.event_lines({'kind':'poc.checks','started':3,'finished':2}))
        self.assertIn('не все исходы известны',text);self.assertIn('самоотчёт',text)

    def test_cli_diagnostic_flag_is_available_for_coordinated_mode(self):
        import sys
        with patch.object(sys,'argv',['pm','attack','11','--coordinated','--diagnostic']):_,args=pm.parser_main()
        self.assertTrue(args.diagnostic);self.assertTrue(args.coordinated)

    def test_offline_and_completed_render_do_not_dispatch_or_implicitly_cleanup(self):
        result={'task_id':11,'succeeded':False,'stop_reason':'target_restoration_required','status':'waiting_operator',
            'steps':[],'target_availability':{'network_allowed':False,'state':'deactivated','reason':'Operator notice'}}
        output=io.StringIO()
        with redirect_stdout(output),patch.object(pm,'sudo_checked',side_effect=AssertionError('No network/cleanup')):
            pm.render_coordinator_result(result,SimpleNamespace(json=False))
            pm.render_coordinator_result({**result,'succeeded':True,'stop_reason':'objectives_done','status':'completed','target_availability':{}},SimpleNamespace(json=False))
        text=output.getvalue();self.assertIn('сохранённые',text);self.assertIn('цели выполнены',text)
        self.assertIn('Исследовательская цель подтверждена: False',text)
        self.assertIn('methods retain',text)

    def test_short_display_preserves_the_only_full_result_in_capability_artifact(self):
        from tests import test_run_diagnostics as fixture
        payload={'status':'completed','exit_code':0,'stdout':'FULL-ORIGINAL-'*10000}
        @d.tool
        def safe_call(task_id):return fixture.server.run_capability(['fake-helper'],1,'net_exec',task_id)
        output=io.StringIO();caps=self.root/'caps'
        with redirect_stderr(output),d.run('full original',11),d.relay(),patch.object(fixture.server,'CAPABILITY_LOG',caps),patch.object(fixture.server.subprocess,'run',return_value=subprocess.CompletedProcess([],0,json.dumps(payload),'')):
            safe_call(11)
        self.assertNotIn('FULL-ORIGINAL-',output.getvalue())
        record=json.loads((caps/'task_11.jsonl').read_text())
        self.assertEqual(record['result']['stdout'],payload['stdout']);self.assertIn(str(caps),output.getvalue())


if __name__=='__main__':unittest.main(verbosity=2)
