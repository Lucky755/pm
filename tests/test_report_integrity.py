"""Offline role/report recovery, real coordinator/SQLite and runtime policies."""
import json
import hashlib
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
if __package__:
    from . import test_coordinated_attack as fixtures
else:
    import test_coordinated_attack as fixtures
decision=fixtures.decision
import pm
from orchestrator import agent_actions as a, coordinated_attack as c, task_runtime

BROKEN='{"summary": "Unclosed damaged ACCESS report; preserve executed results", "findings": ['


class ReportIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.case=fixtures.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.repair_response=BROKEN;self.repair_events=[];self.requests=[];self.executions=0
        self.operation={'status':'completed','exit_code':1,'stdout':'22/tcp Permission denied'}
        self.initial_finish='completed'
        self.initial_text=BROKEN
        owner=self
        class Harness:
            def __init__(self,**kwargs):
                layers=json.loads(Path(kwargs['patches'][0]).read_text())
                self.readonly=any('evidence_readonly.mjs' in str(item) for item in layers)
                self.limit=kwargs['max_tokens']
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def start_session(self,name):
                def run(prompt,**kwargs):
                    owner.requests.append((self.readonly,prompt,self.limit))
                    if self.readonly:
                        if isinstance(owner.repair_response,Exception):
                            raise owner.repair_response
                        return SimpleNamespace(finish_reason='completed',events=owner.repair_events,
                                               final_response=owner.repair_response)
                    owner.executions+=1
                    a.CAPABILITY_LOG.mkdir(exist_ok=True)
                    record={'id':'a'*24,'task_id':11,'tool':'net_exec','provenance':'network',
                            'result':owner.operation}
                    with (a.CAPABILITY_LOG/'task_11.jsonl').open('a') as stream:
                        stream.write(json.dumps(record)+'\n')
                    return SimpleNamespace(finish_reason=owner.initial_finish,events=[],final_response=owner.initial_text)
                return SimpleNamespace(run=run)
        for p in (patch.dict(sys.modules,{'deepseek_harness':SimpleNamespace(DeepSeekHarness=Harness)}),
                  patch.object(a,'close_task_sessions'),
                  patch.object(socket.socket,'connect',side_effect=AssertionError('Network forbidden')),
                  patch.object(a.subprocess,'run',side_effect=AssertionError('Executor forbidden'))):
            p.start();self.addCleanup(p.stop)

    def structured(self):
        return json.dumps({'summary':'One authorized check returned a refusal; no access obtained.',
            'findings':[{'title':'22/tcp SSH denied','claim':'22/tcp SSH denied','kind':'observation',
                         'quote':'22/tcp Permission denied','probe':{'result_id':'a'*24}}],
            'hypotheses':[],'flags':[],'verified':[],'uncertainties':[],'proposed_actions':[]})

    def role(self):
        return a.run_role(11,'access','One authorized check only; no brute force',1,api_key='fake-only')

    def approved_run(self):
        first=c.run(11,api_key='fake-only',model=Mock(return_value=decision('access','One authorized check only')))
        step=first['steps'][0]['id'];model=Mock(return_value=decision())
        result=c.run(11,api_key='fake-only',model=model,approve_step=step)
        return result,model

    def test_damaged_access_report_is_saved_as_damaged_not_completed(self):
        result=self.role();report=result['report']
        self.assertEqual(report['report_quality']['status'],'damaged')
        self.assertTrue(report['report_quality']['reason'])
        self.assertEqual(Path(report['raw_report_path']).read_text(),BROKEN)
        with self.case.connect() as db:
            stored=json.loads(db.execute('SELECT report_json FROM pm_agent_action_reports').fetchone()[0])
        self.assertEqual(stored,report)
        self.assertNotEqual(result['status'],'completed')

    def test_one_readonly_reformat_attempt_never_repeats_execution(self):
        self.role()
        self.assertEqual(self.executions,1)
        self.assertEqual([r[0] for r in self.requests],[False,True])
        self.assertLessEqual(self.requests[1][2],4096)
        self.assertIn('22/tcp Permission denied',self.requests[1][1])
        self.assertEqual(json.loads(self.requests[1][1].rsplit('\n',1)[1])['raw_response_excerpt'],BROKEN)

    def test_full_original_and_format_responses_are_preserved_with_checksums(self):
        self.initial_text=BROKEN+'x'*10000
        report=self.role()['report'];quality=report['report_quality']
        raw=Path(report['raw_report_path']).read_bytes()
        self.assertEqual(raw,self.initial_text.encode())
        self.assertEqual(quality['raw_response_sha256'],hashlib.sha256(raw).hexdigest())
        formatted=Path(quality['format_response_ref']).read_bytes()
        self.assertEqual(formatted,BROKEN.encode())
        self.assertEqual(quality['format_response_sha256'],hashlib.sha256(formatted).hexdigest())

    def test_successful_reformat_preserves_validated_structured_results(self):
        self.repair_response=self.structured()
        report=self.role()['report']
        self.assertEqual(report['report_quality']['status'],'reformatted')
        self.assertEqual(len(report['findings']),1)
        self.assertEqual(report['findings'][0]['quote'],'22/tcp Permission denied')
        self.assertEqual(report['access_level'],'none')
        self.assertEqual(Path(report['raw_report_path']).read_text(),BROKEN)
        self.assertEqual(self.executions,1)

    def test_wrapping_broken_json_inside_summary_does_not_count_as_repair(self):
        self.repair_response=json.dumps({'summary':'{"findings": [still broken response fragment',
                                         'findings':[],'hypotheses':[]})
        report=self.role()['report']
        self.assertEqual(report['report_quality']['status'],'damaged')
        self.assertEqual(report['report_quality']['reason'],'format_response_invalid')

    def test_truncated_report_with_unknown_counters_only_uses_readonly_formatting(self):
        self.initial_finish='max-tokens'
        report=self.role()['report']
        self.assertEqual([r[0] for r in self.requests],[False,True])
        self.assertEqual(self.executions,1)
        self.assertEqual(report['report_quality']['original_error']['code'],'output_truncated')

    def test_legacy_loop_also_stops_on_damaged_report(self):
        from orchestrator import attack_loop, flag_verify
        with patch.object(flag_verify,'connect',self.case.connect):
            result=attack_loop.run(11,roles=('access','verify'),api_key='fake-only')
        self.assertEqual(result['stop_reason'],'report_damaged')
        self.assertEqual(len(result['stages']),1)
        self.assertFalse(result['succeeded'])
        self.assertEqual(self.executions,1)

    def test_failed_reformat_stops_coordinator_before_next_planning(self):
        result,model=self.approved_run()
        self.assertEqual(result['stop_reason'],'role_report_damaged_requires_review')
        self.assertEqual(result['status'],'waiting_operator')
        self.assertEqual(result['steps'][0]['status'],'failed')
        self.assertEqual(result['steps'][0]['error'],'report_damaged')
        model.assert_not_called()
        again=Mock(side_effect=AssertionError('Planning forbidden'))
        paused=c.run(11,api_key='fake-only',model=again)
        again.assert_not_called();self.assertEqual(paused['stop_reason'],result['stop_reason'])
        with self.case.connect() as db:
            self.assertEqual(task_runtime.pause(db,11)['stop_reason'],result['stop_reason'])

    def test_successful_reformat_allows_next_planning_without_new_target_action(self):
        self.repair_response=self.structured()
        result,model=self.approved_run()
        self.assertEqual(result['steps'][0]['status'],'completed')
        self.assertEqual(result['stop_reason'],'model_stopped_incomplete')
        self.assertEqual(model.call_count,1);self.assertEqual(self.executions,1)

    def test_unsolicited_tools_in_format_response_are_rejected(self):
        self.repair_response=self.structured()
        self.repair_events=[{'type':'tool/call','name':'pm_net_exec'}]
        report=self.role()['report']
        self.assertEqual(report['report_quality']['status'],'damaged')
        self.assertEqual(report['report_quality']['reason'],'format_requested_tools')
        self.assertEqual(self.executions,1)

    def test_format_exception_preserves_operation_and_original_response(self):
        self.repair_response=RuntimeError('Fake format provider failed')
        report=self.role()['report']
        self.assertEqual(report['report_quality']['reason'],'format_request_failed')
        self.assertEqual(report['execution_outcome']['status'],'nonzero_exit')
        self.assertEqual(Path(report['raw_report_path']).read_text(),BROKEN)

    def test_explicit_continuation_acknowledges_incomplete_report_without_replay(self):
        first,_=self.approved_run()
        path=Path(first['steps'][0]['report_path']);original=path.read_bytes()
        result=c.run(11,api_key='fake-only',continue_run=True,model=Mock(return_value=decision()))
        self.assertEqual(result['steps'][0]['error'],'report_damaged')
        self.assertEqual(result['steps'][0]['status'],'failed')
        self.assertTrue(result['steps'][0]['report_reviewed_at'])
        self.assertEqual(self.executions,1)
        self.assertEqual(path.read_bytes(),original)

    def test_acknowledging_report_damage_does_not_allow_repeating_the_executed_check(self):
        first,_=self.approved_run()
        repeated=decision('access','One authorized check only')
        result=c.run(11,api_key='fake-only',continue_run=True,model=Mock(return_value=repeated),decision_retries=0)
        self.assertIn('repeated_question_without_new_evidence',result['stop_reason'])
        self.assertEqual(self.executions,1)

    def test_cancelling_before_execution_does_allow_a_new_explicit_approval_request(self):
        choice=decision('access','One authorized check only')
        first=c.run(11,api_key='fake-only',model=Mock(return_value=choice))
        result=c.run(11,api_key='fake-only',continue_run=True,model=Mock(return_value=choice))
        self.assertEqual(result['stop_reason'],'role_approval_required')
        self.assertEqual(result['steps'][0]['execution_outcome']['status'],'not_started')
        self.assertIsNone(result['steps'][-1]['approved_at'])
        self.assertEqual(self.executions,0)

    def test_legacy_completed_damage_is_visible_without_rewriting_history(self):
        self.repair_response=self.structured()
        result,_=self.approved_run();step=result['steps'][0]
        with self.case.connect() as db:
            report=json.loads(db.execute('SELECT report_json FROM pm_agent_action_reports').fetchone()[0])
            report.pop('report_quality');report.pop('execution_outcome')
            report.update(summary=BROKEN,findings=[],hypotheses=[])
            db.execute('UPDATE pm_agent_action_reports SET report_json=?',(json.dumps(report),))
        path=Path(report['report_path']);path.write_text(json.dumps(report));original=path.read_bytes()
        with self.case.connect() as db:
            before=db.execute('SELECT * FROM pm_coordinator_steps').fetchall()
            pause=task_runtime.pause(db,11)
            self.assertEqual(pause['stop_reason'],'role_report_damaged_requires_review')
            self.assertEqual(pause['steps'][0]['status'],'completed')
            self.assertEqual(db.execute('SELECT * FROM pm_coordinator_steps').fetchall(),before)
        model=Mock(side_effect=AssertionError('Planning forbidden'))
        paused=c.run(11,api_key='fake-only',model=model)
        model.assert_not_called()
        self.assertEqual(paused['stop_reason'],'role_report_damaged_requires_review')
        self.assertEqual(path.read_bytes(),original)

    def test_console_separates_report_damage_from_execution_status(self):
        from orchestrator import report_integrity
        outcomes=[]
        for status,code in (('completed',0),('blocked',None),('error',None)):
            self.operation.update(status=status,exit_code=code)
            self.case.calls=[]
            # Classifier uses saved records, never model descriptions of SSH.
            records={'a'*24:{'tool':'net_exec','status':status,
                'capture_record':{'provenance':'network','result':{'exit_code':code}}}}
            outcomes.append(report_integrity.execution(records,set())['status'])
        self.assertEqual(outcomes,['executed','refused','unknown'])
        result,_=self.approved_run()
        pm.render_coordinator_result(result,SimpleNamespace(json=False))
        for status in ('executed','nonzero_exit','refused'):
            result['steps'][0]['execution_outcome']={'status':status,'results':[]}
            pm.render_coordinator_result(result,SimpleNamespace(json=False))
        output=self.case.console.getvalue()
        self.assertIn('Отчёт повреждён',output)
        self.assertIn('Исход операции неизвестен',output)
        self.assertIn('Вызов исполнен; достижение цели этим не подтверждено',output)
        self.assertIn('Вызов исполнен с ненулевым exit_code',output)
        self.assertIn('Действие получило отказ до исполнения',output)

    def test_cancelled_unapproved_step_is_not_an_executed_failure(self):
        first=c.run(11,api_key='fake-only',model=Mock(return_value=decision('access','A single scoped attempt?')))
        result=c.run(11,api_key='fake-only',continue_run=True,model=Mock(return_value=decision()))
        row=result['steps'][0]
        self.assertEqual(row['error'],'operator_requested_replan')
        self.assertIsNone(row['approved_at'])
        self.assertEqual(row['execution_outcome']['status'],'not_started')
        self.assertEqual(self.executions,0)
        prompt_model=Mock(return_value=decision())
        c.run(11,api_key='fake-only',model=prompt_model)
        previous=json.loads(prompt_model.call_args[0][0].rsplit('\n',1)[1])['previous_steps'][0]
        self.assertEqual(previous['error'],'operator_requested_replan')
        self.assertEqual(previous['execution_outcome']['status'],'not_started')
        self.assertIsNone(previous['approved_at'])
        pm.render_coordinator_result(result,SimpleNamespace(json=False))
        self.assertIn('не запускалось',self.case.console.getvalue())


if __name__=='__main__':unittest.main()
