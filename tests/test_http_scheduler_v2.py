"""New web loop checks with fake in-memory evidence and HTTP runner only."""
import sys
import types
import unittest
from unittest.mock import Mock, patch
from test_auto_scheduler import AutoTests, s


class WebAutoTests(AutoTests):
    def _mock_web(self, response_status='completed'):
        web = types.ModuleType('orchestrator.http_discovery')
        self.state['web_count'] = 0
        self.state['web_calls'] = 0
        web.init = lambda db: None
        web.require_capture_support = lambda: None
        web.validate_scope = lambda db, task_id: '127.0.0.1'
        web.evidence_rows = lambda db, task_id: [{'observation_id': 1}] if self.state['web_count'] else []
        def run(db, task_id, max_requests=2, capture=False):
            self.state['web_calls'] += 1
            if self.state['web_count']:
                return []
            self.state['web_count'] += 1
            return [{'status':response_status,'path':'/mbilling'}]
        web.execute_round = run
        web.has_more = lambda db, task_id, **kwargs: False
        web.queue_status = lambda db, task_id, **kwargs: {'state':'catalog_exhausted','pending':0}
        pkg = sys.modules['orchestrator']
        self.patches.append(patch.dict(sys.modules, {'orchestrator.http_discovery': web}))
        self.patches[-1].start()
        self.patches.append(patch.object(pkg, 'http_discovery', web, create=True))
        self.patches[-1].start()
        def snapshot(db, task_id):
            count = self.state['web_count']
            return f'hash_{count}', {'network_observations':[{'observation_id':1}],
                   'burp_http_metadata':[],
                   'web_observations':[{'observation_id':1}] if count else []}
        self.patches.append(patch.object(s.evidence, 'make_snapshot', snapshot, create=True))
        self.patches[-1].start()
        return web

    def test_web_jobs_count_against_budget_and_are_not_repeated(self):
        self._mock_web()
        result = s.auto(self.db,9,True,False,True,5,False,4,False,True)
        self.assertEqual(result['total_jobs'],1)
        self.assertEqual(self.state['web_calls'],2)  # second sees no new links
        self.assertEqual(result['web_observations'],1)
        self.assertEqual(result['stop_reason'],'no_progress')
        self.assertEqual(result['rounds'][0]['new_observations'],1)
        self.assertEqual(result['rounds'][1]['new_observations'],0)

    def test_broker_block_stops_discovery(self):
        self._mock_web('blocked')
        result = s.auto(self.db,9,True,False,True,5,False,4,False,True)
        self.assertEqual(result['stop_reason'],'http_job_failed')
        self.assertEqual(result['total_jobs'],1)
        self.assertEqual(self.state['web_calls'],1)

    def test_remaining_http_queue_survives_unchanged_evidence(self):
        web = self._mock_web()
        def run(db, task_id, max_requests=2, capture=False):
            self.state['web_calls'] += 1
            # Metadata refresh can leave the evidence digest unchanged.
            return [{'status': 'completed', 'path': '/next'}]
        web.execute_round = run
        web.has_more = lambda db, task_id, **kwargs: True
        result = s.auto(self.db,9,True,False,True,2,False,4,False,True)
        self.assertEqual(result['total_jobs'],2)
        self.assertEqual(result['stop_reason'],'job_budget')

    def test_capture_queue_owns_get_instead_of_legacy_truncated_profile(self):
        self._mock_web()
        self.state['queue'] = [{'plan_id': 42,'profile':'http_get'}]
        with patch.object(s.enrichment,'plan_followups',return_value=[]) as planner:
            result=s.auto(self.db,9,True,False,True,5,False,4,False,True)
        self.assertEqual(result['total_jobs'],1)
        self.assertEqual(self.state['queue'],[{'plan_id':42,'profile':'http_get'}])
        self.assertTrue(all(call.kwargs=={'include_http_get':False} for call in planner.call_args_list))

    def test_model_decision_waits_for_deterministic_http_queue(self):
        web=self._mock_web();web.has_more=lambda db,task_id,**kwargs: True
        with patch.object(s.decisions,'plan',Mock(),create=True) as decide:
            s.auto(self.db,9,True,False,True,5,True,1,False,True)
        decide.assert_not_called()

if __name__ == '__main__': unittest.main(verbosity=2)
