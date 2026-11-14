"""Offline regressions for scoped evidence, contradictions and report lifecycle."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

if __package__:
    from . import test_report_integrity as fixtures
else:
    import test_report_integrity as fixtures
from orchestrator import agent_actions as a, coordinated_attack as c, report_integrity, task_runtime
import pm


class ReportSemanticsTests(unittest.TestCase):
    def setUp(self):
        self.fx=fixtures.ReportIntegrityTests();self.fx.setUp();self.addCleanup(self.fx.doCleanups)
        self.case=self.fx.case

    def finding(self,claim='/ok exists',quote='/ok 200 OK'):
        return {'title':claim,'claim':claim,'kind':'observation','quote':quote,
                'probe':{'result_id':'a'*24}}

    def run_report(self,report,output='/ok 200 OK\n/missing 404 Not Found'):
        self.fx.initial_text=json.dumps({'summary':'Scoped checks completed; no goal claimed.',
            'findings':[],'hypotheses':[],'flags':[],**report})
        self.fx.operation.update(stdout=output,exit_code=0)
        return self.fx.role()['report']

    def test_unrelated_not_found_does_not_refute_successful_operation(self):
        report=self.run_report({'findings':[self.finding()]})
        self.assertEqual(len(report['findings']),1)
        self.assertEqual(report['findings'][0]['kind'],'observation')

    def test_a_multiline_quote_is_scoped_to_the_named_operation(self):
        output='/ok 200 OK\n/missing 404 Not Found'
        report=self.run_report({'findings':[self.finding(quote=output)]},output)
        self.assertEqual(len(report['findings']),1)

    def test_unrelated_denial_does_not_refute_hypothesis_or_access(self):
        report=self.run_report({'access_level':'user','access_signal':'shell','access_probe_result_id':'a'*24,
            'access_quote':'uid=1000(user)',
            'hypotheses':[{'claim':'/ok exists','result':'confirmed','probe_result_id':'a'*24,'quote':'/ok 200 OK'}]},
            output='/ok 200 OK\nuid=1000(user)\n/root: Permission denied')
        self.assertEqual(report['access_level'],'user')
        self.assertEqual(report['hypotheses'][0]['result'],'confirmed')

    def test_scoped_summary_denial_does_not_cancel_another_success(self):
        report=self.run_report({'summary':'No access obtained on /root; user shell obtained.',
            'access_level':'user','access_signal':'shell','access_probe_result_id':'a'*24,
            'access_quote':'uid=1000(user)'},output='uid=1000(user)\n/root: Permission denied')
        self.assertFalse((report.get('report_consistency') or {}).get('blocking'))
        self.assertEqual(report['access_level'],'user')

    def test_denial_quote_cannot_establish_shell(self):
        report=self.run_report({'access_level':'user','access_signal':'shell','access_probe_result_id':'a'*24,
                               'access_quote':'/root: Permission denied'},output='/root: Permission denied')
        self.assertEqual(report['access_level'],'none')
        with self.case.connect() as db:self.assertEqual(a.fact_state.access_state(db,11)['level'],'none')

    def test_quote_from_a_different_operation_is_not_evidence_for_claim(self):
        report=self.run_report({'findings':[self.finding(quote='/missing 404 Not Found')]})
        self.assertFalse(report['findings'])

    def test_summary_access_contradiction_is_preserved_and_blocks_publication(self):
        report=self.run_report({'summary':'User shell obtained.', 'access_level':'none','access_signal':'none'})
        self.assertTrue(report['report_consistency']['blocking'])
        self.assertEqual(report['reported_assertions']['summary'],'User shell obtained.')
        self.assertTrue(report['report_incomplete'])
        with self.case.connect() as db:self.assertEqual(a.fact_state.access_state(db,11)['level'],'none')

    def test_opposing_structured_claims_do_not_overwrite_each_other(self):
        claim='/ok exists'
        report=self.run_report({'findings':[self.finding(claim)],'hypotheses':[
            {'claim':claim,'result':'refuted','probe_result_id':'a'*24,'quote':'/missing 404 Not Found'}]})
        self.assertTrue(report['report_consistency']['blocking'])
        self.assertEqual(report['reported_assertions']['hypotheses'][0]['result'],'refuted')
        with self.case.connect() as db:
            self.assertFalse(db.execute("SELECT 1 FROM pm_hypotheses WHERE status='confirmed'").fetchone())

    def test_contradiction_stops_coordinator_without_changing_execution_outcome(self):
        self.fx.initial_text=json.dumps({'summary':'User shell obtained.','access_level':'none',
                                        'access_signal':'none','findings':[],'hypotheses':[]})
        with a.diagnostics.run('contradictory report',11):
            result,model=self.fx.approved_run()
        self.assertEqual(result['status'],'waiting_operator');model.assert_not_called()
        self.assertEqual(result['steps'][0]['execution_outcome']['status'],'nonzero_exit')
        self.assertFalse(result['steps'][0]['outcome_uncertain'])
        events=[json.loads(line) for path in a.diagnostics.EVENT_DIR.glob('*.jsonl') for line in path.read_text().splitlines()]
        pause=next(e for e in events if e.get('kind')=='coordinator.pause' and e.get('reason')=='report_incomplete')
        self.assertFalse(pause['outcome_uncertain'])
        pm.render_coordinator_result(result,SimpleNamespace(json=False))
        self.assertIn('summary_access_disagrees',self.case.console.getvalue())

    def test_reserved_report_is_not_presented_as_saved(self):
        result=c.run(11,api_key='fake-only',model=Mock(return_value=fixtures.decision('access','One attempt')))
        step=result['steps'][0]
        self.assertEqual(step['report_state'],'reserved');self.assertIsNone(step['report_path'])
        pm.render_coordinator_result(result,SimpleNamespace(json=False))
        self.assertIn('зарезервирован',self.case.console.getvalue())
        self.assertNotIn('Сохранённый отчёт:',self.case.console.getvalue())
        self.assertFalse(result['succeeded'])

    def test_execution_and_server_outcomes_are_separate(self):
        cases=[({'status':'error','exit_code':None,'error_type':'executor_unavailable'},'executor_error'),
               ({'status':'completed','exit_code':0,'server_outcome':'refused'},'executed'),
               ({'status':'timeout','exit_code':None},'unknown')]
        for payload,expected in cases:
            records={'r':{'tool':'net_exec','status':payload['status'],
                          'capture_record':{'provenance':'network','result':payload}}}
            outcome=report_integrity.execution(records,set())
            self.assertEqual(outcome['status'],expected)
            if payload.get('server_outcome'):
                self.assertEqual(outcome['results'][0]['server_outcome'],'refused')

    def test_real_mcp_executor_launch_error_is_retained_in_history(self):
        if __package__:
            from .test_run_diagnostics import server
        else:
            from test_run_diagnostics import server
        with patch.object(server,'CAPABILITY_LOG',a.CAPABILITY_LOG),patch.object(
                server.subprocess,'run',side_effect=FileNotFoundError('missing fixture executor')):
            response=json.loads(server.run_capability(['missing-fixture'],1,'net_exec',11))
        self.assertEqual(response['error_type'],'executor_unavailable')
        outcome=report_integrity.execution(a.report_probe_records(11),set())
        self.assertEqual(outcome['status'],'executor_error')

    def test_corrupted_canonical_json_is_not_an_empty_completed_report(self):
        self.fx.repair_response=self.fx.structured()
        result,_=self.fx.approved_run()
        with self.case.connect() as db:
            db.execute('UPDATE pm_agent_action_reports SET report_json=?',('{"summary":',))
            self.assertEqual(task_runtime.pause(db,11)['stop_reason'],'role_report_damaged_requires_review')
        model=Mock(side_effect=AssertionError('Planning forbidden'))
        result=c.run(11,api_key='fake-only',model=model)
        self.assertEqual(result['stop_reason'],'role_report_damaged_requires_review')
        model.assert_not_called();self.assertFalse(result['succeeded'])

    def test_mixed_http_responses_do_not_make_the_whole_execution_a_refusal(self):
        records={'r':{'tool':'net_exec','status':'completed',
            'outputs':{'stdout':'HTTP/1.1 404 Not Found\nHTTP/1.1 200 OK'},
            'capture_record':{'provenance':'network','result':{'exit_code':0}}}}
        outcome=report_integrity.execution(records,set())
        self.assertEqual(outcome['status'],'executed')
        self.assertEqual(outcome['results'][0]['server_outcome'],'mixed')
        self.assertEqual([r['status_code'] for r in outcome['results'][0]['server_responses']],[404,200])

    def test_unrelated_negative_output_cannot_refute_another_hypothesis(self):
        report=self.run_report({'hypotheses':[{'claim':'/ok exists','result':'refuted',
                           'probe_result_id':'a'*24,'quote':'/missing 404 Not Found'}]})
        self.assertEqual(report['hypotheses'][0]['result'],'untested')
        self.assertEqual(report['hypotheses'][0]['reported_result'],'refuted')

    def test_malformed_structure_is_not_silently_replaced_with_empty_findings(self):
        self.fx.initial_text=json.dumps({'summary':'Structured report','findings':{'broken':'shape'}})
        result=self.fx.role()
        self.assertEqual(result['status'],'report_damaged')
        self.assertEqual(result['report']['report_quality']['status'],'damaged')

    def test_opposing_hypotheses_are_preserved_without_selecting_a_winner(self):
        hypotheses=[{'claim':'/ok exists','result':status,'probe_result_id':'a'*24,'quote':'/ok 200 OK'}
                    for status in ('confirmed','refuted')]
        report=self.run_report({'hypotheses':hypotheses})
        self.assertEqual([h['result'] for h in report['reported_assertions']['hypotheses']],['confirmed','refuted'])
        self.assertTrue(report['report_consistency']['blocking'])


if __name__=='__main__':unittest.main()
