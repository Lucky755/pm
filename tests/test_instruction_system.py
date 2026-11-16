"""Canonical instructions in real full/compact prompts, temporary task data only."""
import json
import ast
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

from tests import test_agent_prompt_context as fixture
from orchestrator import agent_actions as a, instructions as rules, coordinated_attack as c
from tests import test_coordinated_attack as coordinator_fixture


class InstructionTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.AgentPromptContextTests();self.case.setUp();self.addCleanup(self.case.doCleanups)

    def test_generic_roles_do_not_receive_binary_ctf_assumptions(self):
        context=self.case.context('Inspect the HTTP endpoint; no brute force.\nDo not change passwords.')
        for role in a.ROLES:
            for prompt in self.case.prompts(context,role):
                for irrelevant in ('out-of-bounds write','server, libc and ld','--min-rate','a page of reasoning',
                                   '/.git/objects/aa/','gdb attached','counter that turns a bounded write'):
                    self.assertNotIn(irrelevant,prompt)

    def test_common_rules_survive_every_role_and_compaction(self):
        context=self.case.context('Исходная цель.\nОграничения: без брутфорса; не менять пароли.')
        for role in a.ROLES:
            for prompt in self.case.prompts(context,role):
                self.assertIn('<pm_common_rules>',prompt)
                self.assertIn(context['intent'],prompt)
                block=prompt.split('<pm_common_rules>\n',1)[1].split('\n</pm_common_rules>',1)[0]
                self.assertEqual(block,(rules.ROOT/'PM.md').read_text().strip())
                self.assertEqual(prompt.count('<pm_common_rules>'),1)

    def test_only_explicit_procedure_is_loaded_in_both_prompt_forms(self):
        context=self.case.context('Find evidence, no brute force; no password changes.')
        assignment={'question':'Audit these saved bytes','expected_result':'Exact original quotation',
                    'references':['result:original'],'data':[{'reference':'result:original','value':'saved data'}],
                    'profile':'capture-audit'}
        context['specialist_assignment']=assignment
        for prompt in self.case.prompts(context,'verify',assignment['question']):
            self.assertIn('<procedure id="capture-audit">',prompt)
            self.assertNotIn('<procedure id="http-capture">',prompt)
            self.assertNotIn('<procedure id="access-triage">',prompt)
            self.assertNotIn('pm_http_capture(',prompt)
            self.assertNotIn('pm_poc_run(',prompt)
            self.assertIn('Exact original quotation',prompt)
            self.assertIn('saved data',prompt)
        del context['specialist_assignment']
        for prompt in self.case.prompts(context,'verify'):
            self.assertNotIn('<procedure ',prompt)
            self.assertNotIn('/.git/objects/aa/',prompt)

    def test_invalid_profile_or_wrong_role_cannot_inject_a_procedure(self):
        for role,profile in (('recon','capture-audit'),('access','../reference/binary-analysis'),
                             ('verify',''),('verify',{'tools':['*']})):
            with self.subTest(role=role,profile=profile),self.assertRaisesRegex(ValueError,'unknown_profile'):
                rules.profile(role,profile)

    def test_browser_assignment_keeps_task_and_only_its_procedure(self):
        context=self.case.context('Investigate app.lab only; no brute force or password changes.')
        context['specialist_assignment']={'profile':'browser-web','question':'Submit the CSRF form as alice',
            'expected_result':'Quote the account DOM and original HTTP references',
            'references':['http_artifact:7'],'data':[{'reference':'http_artifact:7','value':'known scoped form'}]}
        for prompt in self.case.prompts(context,'access',context['specialist_assignment']['question']):
            for text in (context['intent'],'Submit the CSRF form as alice','Quote the account DOM',
                         'http_artifact:7','pm_browser(','pm_browser_read(','<procedure id="browser-web">'):
                self.assertIn(text,prompt)
            self.assertNotIn('<procedure id="http-capture">',prompt)
            self.assertNotIn('pm_poc_run(',prompt)

    def test_documented_tools_exist_and_all_profiles_define_the_contract(self):
        tree=ast.parse((rules.ROOT.parent/'mcp/server.py').read_text())
        actual={node.name for node in tree.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))
                and any(isinstance(d,ast.Call) and isinstance(d.func,ast.Attribute)
                        and d.func.attr=='tool' for d in node.decorator_list)}
        documented=json.loads((rules.ROOT/'tools.json').read_text())
        self.assertFalse(set(documented)-actual)
        expected={'roles','purpose','inputs','procedures','tools','budget','expected_result'}
        for name,spec in rules.catalog().items():
            self.assertEqual(set(spec),expected,name)
            for role in spec['roles']:
                effective=rules.limits(rules.profile(role,name),{'step_limit':2,'poc_budget':1,'max_tokens':1000})
                self.assertEqual(effective,{'step_limit':2,'poc_budget':1,'max_tokens':1000})

    def test_runtime_tool_restriction_is_an_intersection_and_restores_environment(self):
        with patch.dict(os.environ,{'PM_AGENT_ALLOWED_TOOLS':json.dumps(['pm_capability_read'])}):
            with a.action_policy_patch(2,1,allowed_tools=['pm_capability_read','pm_http_capture']):
                self.assertEqual(json.loads(os.environ['PM_AGENT_ALLOWED_TOOLS']),['pm_capability_read'])
            self.assertEqual(json.loads(os.environ['PM_AGENT_ALLOWED_TOOLS']),['pm_capability_read'])

    def test_analytical_paths_share_rules_without_inheriting_execution_rights(self):
        from orchestrator import planner,evidence_pipeline,decision_agent,scheduler,lab_end_to_end,scheduler_harness,network_phase
        prompts=[planner.SYSTEM_PROMPT,
            evidence_pipeline.agent_prompt('access',{'task_id':11},{}),
            evidence_pipeline.repair_prompt('access',{'task_id':11},{},'bad','invalid'),
            decision_agent.decision_prompt({'task_id':11,'authorized_target':'203.0.113.10'},[]),
            scheduler.AGENT_SYSTEM,lab_end_to_end.agent_prompt('access',{},{}),
            scheduler_harness.build_prompt('access','192.0.2.10','Analysis only',{},False)]
        for prompt in prompts:
            self.assertIn((rules.ROOT/'PM.md').read_text().strip(),prompt)
            self.assertIn('Tools are disabled by Harness',prompt)
            self.assertNotIn('<procedure ',prompt)
        self.assertIs(network_phase.instructions,rules)


class SpecialistExecutionTests(unittest.TestCase):
    def setUp(self):
        self.case=coordinator_fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)

    def test_coordinator_selects_registered_specialization_and_actual_prompts_keep_assignment(self):
        seen=[];limits=[];allowed=[]
        class Harness:
            def __init__(self,**options):
                limits.append(options['max_tokens'])
                allowed.append(json.loads(os.environ['PM_AGENT_ALLOWED_TOOLS']))
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def start_session(self,name):
                def run(prompt,**kwargs):
                    seen.append(prompt)
                    return SimpleNamespace(finish_reason='completed',events=[],final_response=json.dumps({
                        'summary':'No fresh probe or access claimed.','findings':[],'flags':[],
                        'verified':[],'uncertainties':[],'proposed_actions':[]}))
                return SimpleNamespace(run=run)
        choice=coordinator_fixture.decision('vuln','Read the saved HTTP information',references=['service:10.0.0.1:tcp:80'])
        choice['profile']='http-surface';choice['expected_result']='A quoted response or a precise evidence gap.'
        with patch.dict(sys.modules,{'deepseek_harness':SimpleNamespace(DeepSeekHarness=Harness)}), \
             patch.object(a,'close_task_sessions'),patch.object(a.subprocess,'run',side_effect=AssertionError('No executor')):
            result=c.run(11,api_key='fake-only',model=self.case.model([choice]),max_steps=1,
                         max_tokens=16000,step_limit=15,poc_budget=7)
        self.assertEqual(len(seen),1)
        self.assertIn('<procedure id="http-capture">',seen[0])
        self.assertNotIn('<procedure id="capture-audit">',seen[0])
        self.assertIn('без брутфорса',seen[0])
        self.assertIn(choice['question'],seen[0]);self.assertIn(choice['expected_result'],seen[0])
        self.assertIn('service:10.0.0.1:tcp:80',seen[0])
        self.assertEqual(limits,[8192]);self.assertNotIn('pm_net_exec',allowed[0])
        with self.case.connect() as db:
            assignment=json.loads(c.steps(db,11)[0]['assignment_json'])
        self.assertEqual(assignment['inherited_limits'],{'step_limit':6,'poc_budget':1,'max_tokens':8192})
        self.assertEqual(result['steps'][0]['status'],'completed');self.assertFalse(result['succeeded'])

    def test_specialization_keeps_triage_without_access_approval(self):
        choice=coordinator_fixture.decision('access','ТРИАЖ: определить пользователя')
        choice['profile']='access-triage'
        result=self.case.run_mode([choice],max_steps=1)
        self.assertEqual(result['stop_reason'],'coordinator_step_limit');self.assertEqual(len(self.case.calls),1)
        self.assertIsNone(result['steps'][0]['approved_at'])
        with self.case.connect() as db:
            a.fact_state.save_access_report(db,11,{'access_level':'user','access_signal':'shell','access_probe_result_id':'source'})
            state=c.snapshot(db,11,2)
        choice['question']='Escalate before triage'
        with self.assertRaisesRegex(ValueError,'triage_objective_rejected'):c.parse_decision(choice,state,a.ROLES)


if __name__=='__main__':unittest.main(verbosity=2)
