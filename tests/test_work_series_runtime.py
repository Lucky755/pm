"""Real loopback HTTP/internal units; only the privileged broker is replaced."""
import base64
import json
import os
import unittest
from unittest.mock import patch
from orchestrator import research_budgets,material_processing,check_series
from tests import test_http_client_runtime as fixture


class SeriesRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.http=fixture.HTTPRuntimeTests();self.http.setUp();self.addCleanup(self.http.doCleanups)
        for p in (patch.object(material_processing,'ROOT',self.http.case.root/'materials'),
                  patch.dict(os.environ,{'PM_BUDGET_ROLE':'access','PM_TASK_ID':'11'})):
            p.start();self.addCleanup(p.stop)
        handler=self.http.http.RequestHandlerClass;original=handler.do_GET;owner=self
        def get(request):
            if request.path=='/auth-check':
                owner.http.requests.append({'path':request.path,'auth':request.headers.get('Authorization')})
                value=request.headers.get('Authorization','').removeprefix('Basic ')
                pair=base64.b64decode(value).decode()
                request.respond(200,b'SERVER AUTHENTICATED' if pair=='alice:secret3' else b'Login rejected')
            elif request.path=='/auth-refused':
                owner.http.requests.append({'path':request.path})
                request.respond(401,b'Authentication required')
            elif request.path=='/slow-chain':
                import time
                owner.http.requests.append({'path':request.path})
                time.sleep(.7)
                request.respond(302,headers=[('Location','/slow-chain')])
            else:original(request)
        handler.do_GET=get

    def call(self,plan):return self.http.tool('pm_check_series',plan_json=json.dumps(plan))

    def paths(self,paths,kind='find_file',marker='DECISIVE CONTENT'):
        return {'kind':'paths','url':self.http.url+'/','hypothesis':'One explicit saved-file hypothesis',
            'max_requests':len(paths),'seconds':20,'paths':paths,
            'criterion':{'kind':kind,'status':[200],**({'body_contains':marker} if kind!='inventory' else {})}}

    def pairs(self,values):
        with self.http.case.connect() as db:
            source=material_processing.save(db,11,json.dumps({'username':'alice','passwords':values}).encode(),name='found pairs',source_ref='operator:offline')
        return {'kind':'authentication','url':self.http.url+'/auth-check','hypothesis':'Check exact pairs from saved material',
            'max_requests':5,'seconds':30,'criterion':{'kind':'authenticated','status':[200],'body_contains':'SERVER AUTHENTICATED'},
            'pairs':[{'username':'alice','password':value,'source_ref':source['reference']} for value in values]}

    def test_success_on_third_pair_stops_and_preserves_actual_internal_units(self):
        plan=self.pairs(['secret1','secret2','secret3','secret4','secret5'])
        result=self.call(plan)
        self.assertEqual(result['checks_started'],3);self.assertTrue(result['criterion_matched']);self.assertFalse(result['goal_confirmed'])
        self.assertEqual([r['outcome'] for r in result['checks']],['negative','negative','criterion_matched'])
        self.assertEqual(len(self.http.requests),3)
        with self.http.case.connect() as db:
            self.assertEqual(research_budgets.get(db,11,'specialist','access')['used'],1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pm_internal_checks').fetchone()[0],3)
        self.assertTrue(self.call(plan)['cached']);self.assertEqual(len(self.http.requests),3)
        session=result['checks'][-1]['session_id']
        followup=self.http.call('/echo',session=session)
        self.assertEqual(followup['status'],'completed')
        self.assertEqual(self.http.requests[-1]['headers']['Authorization'],'Basic '+base64.b64encode(b'alice:secret3').decode())

    def test_five_rejections_survive_restart_without_identical_next_batch(self):
        plan=self.pairs(['bad1','bad2','bad3','bad4','bad5'])
        first=self.call(plan);self.assertEqual(first['direction_result'],'replan_required');self.assertEqual(first['failures'],5)
        second=self.call({**plan,'hypothesis':'Same checks with new wording'})
        self.assertTrue(second['cached']);self.assertEqual(len(self.http.requests),5)
        alternative=self.pairs(['another1','another2'])
        self.assertEqual(self.call(alternative)['status'],'replan_required');self.assertEqual(len(self.http.requests),5)

    def test_five_unproductive_path_series_return_to_coordinator(self):
        for index in range(5):
            result=self.call(self.paths(['/missing-'+str(index)]))
            self.assertEqual(result['failures'],index+1)
        self.assertEqual(result['direction_result'],'replan_required')
        self.assertEqual(self.call(self.paths(['/one-more']))['status'],'replan_required')
        self.assertEqual(len(self.http.requests),5)

    def test_file_criterion_stops_after_matching_body_not_first_200(self):
        result=self.call(self.paths(['/echo','/same-flag','/large-body'],marker='offline_same_url_flag'))
        self.assertEqual(result['checks_started'],2);self.assertEqual(result['unchecked'],1)
        self.assertTrue(result['criterion_matched']);self.assertFalse(result['goal_confirmed'])

    def test_inventory_continues_past_first_200(self):
        result=self.call(self.paths(['/echo','/current','/same-flag'],kind='inventory'))
        self.assertEqual(result['checks_started'],3);self.assertEqual(result['direction_result'],'inventory_completed')
        self.assertEqual(len(self.http.requests),3)

    def test_bounds_and_scope_rejected_before_any_requests(self):
        plan=self.paths(['/echo']);plan['criterion']={'kind':'find_file','status':[200]}
        self.assertEqual(self.call(plan)['status'],'blocked')
        plan=self.paths(['/echo','/private'])
        self.assertEqual(self.call(plan)['status'],'blocked');self.assertEqual(self.http.requests,[])

    def test_interrupted_check_is_not_replayed(self):
        plan=self.paths(['/echo'])
        with self.http.case.connect() as db:
            resource,items=check_series.validate(db,11,plan,None);check_series.initialize(db)
            from orchestrator import task_memory
            direction=task_memory.digest([11,'paths',resource]);identities=check_series.identities_for(db,11,plan,items)
            series=task_memory.digest([direction,identities,plan['criterion']])
            db.execute("INSERT INTO pm_check_directions VALUES(?,11,'paths',?,'active',0,NULL)",(direction,resource))
            db.execute("INSERT INTO pm_check_series VALUES(?,11,?,?,'running',0,NULL)",(series,direction,json.dumps(plan)))
        self.assertEqual(self.call(plan)['status'],'outcome_unknown');self.assertEqual(self.http.requests,[])

    def test_redirect_hops_count_against_predeclared_request_limit(self):
        result=self.call(self.paths(['/redirect']))
        self.assertEqual(len(self.http.requests),1)
        self.assertEqual(result['requests_sent'],1)
        self.assertFalse(result['criterion_matched'])
        self.assertEqual(result['checks'][0]['http_stop_reason'],'redirect_limit')

    def test_old_inventory_success_does_not_satisfy_a_new_file_criterion(self):
        inventory=self.call(self.paths(['/echo'],kind='inventory'))
        self.assertTrue(inventory['criterion_matched'])
        result=self.call(self.paths(['/echo'],marker='ABSENT SECRET'))
        self.assertFalse(result['criterion_matched']);self.assertEqual(result['checks_started'],0)
        self.assertTrue(result['checks'][0]['reused']);self.assertEqual(len(self.http.requests),1)

    def test_renaming_kind_or_empty_session_does_not_reset_checks(self):
        plan=self.paths(['/echo'])
        self.call(plan)
        result=self.call({**plan,'kind':'traversal','session_id':'other-empty-session'})
        self.assertTrue(result['cached']);self.assertEqual(len(self.http.requests),1)

    def test_direct_basic_five_server_refusals_stop_next_pair(self):
        for index in range(5):
            result=self.http.call('/auth-refused',auth={'type':'basic','username':'alice','password':'bad'+str(index)})
            self.assertEqual(result['internal_check']['outcome'],'server_refusal')
        result=self.http.call('/auth-refused',auth={'type':'basic','username':'alice','password':'sixth'})
        self.assertEqual(result['status'],'replan_required');self.assertFalse(result['execution_started'])
        self.assertEqual(len(self.http.requests),5)

    def test_new_saved_coordinator_plan_can_change_checks_but_cannot_replay_old_pairs(self):
        from orchestrator import coordinated_attack as coordinator
        from tests.test_coordinated_attack import decision
        old=self.pairs(['bad1','bad2','bad3','bad4','bad5']);self.call(old)
        with self.http.case.connect() as db:
            coordinator.ensure_schema(db)
            db.execute("INSERT INTO pm_coordinator_runs(task_id,target,status,created_at,updated_at) VALUES(11,'10.0.0.1','running',?,?)",(coordinator.now(),coordinator.now()))
            step=coordinator.insert_step(db,1,11,decision('access','Check newly found credential pairs'),coordinator.snapshot(db,11,2),{},status='running')
        with patch.dict(os.environ,{'PM_COORDINATOR_STEP_ID':str(step)}):
            self.assertTrue(self.call({**old,'replan':True})['cached'])
            self.assertEqual(len(self.http.requests),5)
            revised=self.call({**self.pairs(['bad6','secret3']),'replan':True})
        self.assertTrue(revised['criterion_matched']);self.assertEqual(len(self.http.requests),7)

    def test_changed_cookie_state_is_a_substantive_new_condition(self):
        plan=self.paths(['/echo'],kind='inventory')
        self.call(plan);self.http.call('/login')
        fresh=self.call(plan)
        self.assertEqual(fresh['checks_started'],1);self.assertEqual(len(self.http.requests),3)
        self.assertIn('sid=accepted',self.http.requests[-1]['headers'].get('Cookie',''))

    def test_series_deadline_is_shared_across_redirect_hops(self):
        plan=self.paths(['/slow-chain']);plan.update(seconds=2,max_requests=6)
        result=self.call(plan)
        self.assertEqual(result['checks'][0]['http_stop_reason'],'series_time_limit')
        self.assertLess(len(self.http.requests),3);self.assertGreaterEqual(len(self.http.requests),1)
        self.assertTrue(all(call['timeout']<=1 for call in self.http.broker_calls))


if __name__=='__main__':unittest.main()
