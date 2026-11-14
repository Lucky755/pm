"""Versioned memory and real prompt assembly. Temporary DB/files, no network."""
import json
import hashlib
import sqlite3
from pathlib import Path
import subprocess
import sys
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from tests import test_coordinated_attack as fixture
from orchestrator import coordinated_attack as c, agent_actions as a, task_memory as memory, model_adapter


class TaskMemoryTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)

    def test_services_beyond_context_window_are_known_to_coordinator(self):
        with self.case.connect() as db:
            db.execute('UPDATE pm_tcp_full_scans SET open_ports_json=?',(json.dumps(list(range(1,14))+[9999]),))
            state=c.snapshot(db,11,2)
        self.assertIn('service:10.0.0.1:tcp:9999',state['references'])

    def test_old_reports_remain_addressable_without_recent_report_limit(self):
        with self.case.connect() as db:
            for iteration in range(1,18):
                a.save_report(db,{'task_id':11,'target':'10.0.0.1'},'vuln',iteration,
                              {'summary':f'Question {iteration}', 'findings':[],'flags':[]},0)
            state=c.snapshot(db,11,2)
        self.assertIn('report:vuln:1',state['references'])

    @property
    def log(self):return a.CAPABILITY_LOG/'task_11.jsonl'

    def record(self,text='old response',**extra):
        a.CAPABILITY_LOG.mkdir(exist_ok=True)
        record={'id':'a'*24,'task_id':11,'tool':'net_exec','provenance':'network',
                'result':{'status':'completed','exit_code':0,'stdout':text},**extra}
        with self.log.open('a') as stream:stream.write(json.dumps(record)+'\n')
        return 'result:'+record['id']

    def test_migration_is_additive_and_idempotent(self):
        with self.case.connect() as db:
            legacy=db.execute('SELECT * FROM pm_tcp_full_scans').fetchall()
            before=db.execute('PRAGMA user_version').fetchone()
            memory.initialize(db);memory.initialize(db)
            version=memory.sync(db,11,self.log,reason='first import')
            self.assertEqual(version,1)
            self.assertEqual(memory.sync(db,11,self.log,reason='same sources'),version)
            self.assertEqual(db.execute('SELECT * FROM pm_tcp_full_scans').fetchall(),legacy)
            self.assertEqual(db.execute('PRAGMA user_version').fetchone(),before)

    def test_agent_selftest_keeps_a_valid_task_fixture_after_memory_migration(self):
        self.assertEqual(a.self_test()['status'],'completed')

    def test_version_conflict_and_batch_failure_never_apply_partial_changes(self):
        with self.case.connect() as db:
            memory.sync(db,11,self.log,reason='initial')
            head=memory.current(db,11)
            change={'section':'questions','key':'operator:q','value':{'question':'Which endpoint?'}}
            v=memory.apply(db,11,head['version'],[change],reason='operator question',actor='operator')
            with self.assertRaises(memory.VersionConflict):memory.apply(db,11,head['version'],[change],reason='stale')
            with self.assertRaises(ValueError):memory.apply(db,11,v,[{
                'section':'constraints','key':'intent','value':{'text':'expanded authority'}}],reason='cannot replace source')
            with self.assertRaises(ValueError):memory.apply(db,11,v,[
                {'section':'plan','key':'operator:next','value':{'question':'must roll back'}},
                {'section':'unknown','key':'bad','value':{}}],reason='bad batch')
            self.assertEqual(memory.current(db,11)['version'],v)
            self.assertNotIn('operator:next',memory.current(db,11)['state']['plan'])

    def test_correction_keeps_reason_old_version_and_recovers_after_reopen(self):
        with self.case.connect() as db:
            v=memory.sync(db,11,self.log,reason='initial')
            key='operator:claim'
            v=memory.apply(db,11,v,[{'section':'questions','key':key,'value':{'claim':'Version 1','trust':'hypothesis'}}],reason='initial interpretation')
            original=memory.current(db,11,v)
            correction={'supersedes':key,'reason':'Original quote contradicts version claim','status':'refuted',
                        'evidence_refs':['result:original']}
            latest=memory.apply(db,11,v,[{'section':'corrections','key':'operator:correction','value':correction}],reason=correction['reason'])
        with self.case.connect() as db:
            self.assertEqual(memory.current(db,11,latest)['state']['corrections']['operator:correction'],correction)
            self.assertEqual(memory.current(db,11,v),original)
            self.assertEqual(memory.current(db,11,v)['state']['questions'][key]['trust'],'hypothesis')

    def test_snapshot_build_is_readonly_all_services_and_refutations_survive(self):
        with self.case.connect() as db:
            db.execute('UPDATE pm_tcp_full_scans SET open_ports_json=?',(json.dumps(list(range(1,21))+[9999]),))
            for n in range(17):
                a.fact_state.save_hypotheses(db,11,'vuln',{'hypotheses':[{'claim':f'refutation {n}',
                    'kind':'hypothesis','result':'refuted','probe_result_id':'old','quote':f'quote {n}'}]})
            db.commit();before=list(db.iterdump());db.execute('PRAGMA query_only=ON')
            view=memory.context(db,11,self.log)
            ports=[p for group in view['service_groups'] for p in group['ports']]
            self.assertIn(9999,ports);self.assertEqual(len(ports),21)
            self.assertEqual(len(view['state']['refutations']),17)
            self.assertEqual(list(db.iterdump()),before)

    def test_auxiliary_analysis_gets_current_memory_metadata_not_raw_bodies(self):
        with self.case.connect() as db:
            db.execute('UPDATE pm_tcp_full_scans SET open_ports_json=?',(json.dumps(list(range(1,14))+[9999]),))
            view=memory.analysis_context(db,11)
            self.assertIn(9999,[p for group in view['service_groups'] for p in group['ports']])
            self.assertIn('без брутфорса',view['constraints']['intent']['text'])
            self.assertEqual(view['mode'],'metadata_only');self.assertNotIn('relevant_materials',view)

    def test_full_scan_original_is_addressable_by_database_reference(self):
        raw=json.dumps({'status':'completed','exit_code':0,'stdout':'22/tcp open\n80/tcp open'})
        with self.case.connect() as db:
            db.execute('CREATE TABLE pm_tcp_full_scan_attempts(id INTEGER PRIMARY KEY,task_id INTEGER,target TEXT,status TEXT,result_json TEXT,created_at TEXT)')
            db.execute('INSERT INTO pm_tcp_full_scan_attempts VALUES(1,11,?,?,?,?)',('10.0.0.1','completed',raw,memory.now()))
            view=memory.context(db,11,self.log,references=['service:10.0.0.1:tcp:22'])
            self.assertIn('tcp_scan_attempt:1',view['material_index'])
            chunk=next(c for c in view['relevant_materials'] if c['reference']=='tcp_scan_attempt:1')
            self.assertEqual(chunk['text_untrusted'],raw)

    def test_foreign_task_old_target_and_credentials_are_not_confirmed_access(self):
        self.record('foreign bytes',task_id=22)
        self.record('old IP bytes',id='b'*24,result={'status':'completed','target':'10.0.0.2','stdout':'old IP'})
        with self.case.connect() as db:
            a.fact_state.record_asset(db,11,'credential','candidate:password','discovered')
            state=memory.source_state(db,11,self.log)
            self.assertFalse(state['materials'])
            credential=next(iter(state['credentials'].values()))
            self.assertEqual(credential['trust'],'candidate')
            self.assertNotIn('candidate:password',json.dumps(credential))
            self.assertEqual(state['access'],{})

    def test_large_material_chunks_preserve_original_and_analysis_coverage(self):
        original=('начало\n'+'data '*3000+'\nend').encode();ref=self.record(original.decode())
        saved=self.log.read_bytes()
        with self.case.connect() as db:
            memory.sync(db,11,self.log,reason='capture')
            view=memory.context(db,11,self.log,references=[ref]);first=view['relevant_materials'][0]
            self.assertTrue(first['has_more']);self.assertLess(first['end'],first['total_bytes'])
            memory.record_coverage(db,11,first,kind='delivered')
            again=memory.context(db,11,self.log,references=[ref])['relevant_materials'][0]
            self.assertEqual(again['offset'],0,'delivery alone is not analysis')
            memory.record_coverage(db,11,first,kind='agent_reported_analysis',report_ref='report:vuln:1')
            second=memory.context(db,11,self.log,references=[ref])['relevant_materials'][0]
            self.assertEqual(second['offset'],first['end'])
            self.assertEqual(memory.material(db,11,ref,self.log),original)
        self.assertEqual(self.log.read_bytes(),saved)

    def test_material_checksum_conflict_and_foreign_reference_fail(self):
        ref=self.record('saved bytes')
        with self.case.connect() as db:
            with self.assertRaises(memory.VersionConflict):memory.read_chunk(db,11,ref,self.log,sha256='0'*64)
            with self.assertRaises(ValueError):memory.read_chunk(db,11,'report:verify:999',self.log)
            with self.assertRaises(ValueError):memory.read_chunk(db,11,ref,self.log,offset=1000)

    def test_unreceived_analysis_range_is_rejected_without_covering_material(self):
        ref=self.record('unread bytes')
        with self.case.connect() as db:
            checksum=hashlib.sha256(memory.material(db,11,ref,self.log)).hexdigest()
            report={'summary':'Unverified analysis claim','findings':[],'flags':[],
                    'material_analysis':[{'reference':ref,'sha256':checksum,'offset':0,'end':12,'assessment':'Not actually supplied'}]}
            a.save_report(db,{'task_id':11,'target':'10.0.0.1'},'vuln',1,report,0)
            self.assertTrue(report['material_analysis_rejected'])
            self.assertFalse(memory.coverage(db,11,ref,checksum))

    def test_utf8_split_keeps_exact_bytes_for_reassembly(self):
        import base64
        ref=self.record('я'*10)
        with self.case.connect() as db:
            first=memory.read_chunk(db,11,ref,self.log,limit=3)
            self.assertEqual(base64.b64decode(first['data_b64']),('я'*10).encode()[:3])
            second=memory.read_chunk(db,11,ref,self.log,offset=3,limit=3,sha256=first['sha256'])
            self.assertEqual(base64.b64decode(second['data_b64']),('я'*10).encode()[3:6])

    def test_canonical_checks_ignore_question_role_sink_and_port_order(self):
        def desc(argv):return memory.canonical_operation('net_exec',
            ['helper','run','--task-id','11','--target','10.0.0.1','--argv-json',json.dumps(argv),'--execute'],'10.0.0.1')
        first=desc(['/usr/bin/nmap','-p','22,80','-oN','/work/a','10.0.0.1'])
        second=desc(['/usr/bin/nmap','-p80,22','-oN','/work/b','10.0.0.1'])
        self.assertEqual(first['signature'],second['signature'])
        with self.case.connect() as db:
            operation=memory.begin_operation(db,11,first)
            memory.transition(db,11,operation['operation_id'],'started',expected_phase='intent')
            memory.transition(db,11,operation['operation_id'],'finished',expected_phase='started',outcome='completed')
            repeated=memory.begin_operation(db,11,second)
            self.assertFalse(repeated['allowed'])
            self.assertTrue(memory.begin_operation(db,11,second,conditions={'new_access':'user'})['allowed'])
            self.assertTrue(memory.begin_operation(db,11,second,require_fresh=True,reason='Operator needs fresh state')['allowed'])

    def test_cancel_before_start_unknown_and_explicit_review_are_distinct(self):
        description=memory.canonical_operation('net_exec',['helper','--target','10.0.0.1'],'10.0.0.1')
        with self.case.connect() as db:
            op=memory.begin_operation(db,11,description)['operation_id']
            memory.transition(db,11,op,'cancelled',expected_phase='intent',outcome='operator_cancelled')
            row=memory.rows(db,'pm_memory_operations',11)[0]
            self.assertIsNone(row['started_at'])
            op=memory.begin_operation(db,11,description)['operation_id']
            memory.transition(db,11,op,'started',expected_phase='intent')
            memory.transition(db,11,op,'unknown',expected_phase='started')
            self.assertFalse(memory.begin_operation(db,11,description)['allowed'])
            self.assertTrue(memory.begin_operation(db,11,description,allow_unknown=True,reason='Operator reviewed saved evidence')['allowed'])

    def test_local_readback_is_repeatable_and_not_network_observation(self):
        description=memory.canonical_operation('session',['helper','session','--action','read','--session-id','abcd1234'],'10.0.0.1')
        self.assertTrue(description['local'])
        with self.case.connect() as db:
            op=memory.begin_operation(db,11,description)['operation_id']
            memory.transition(db,11,op,'started',expected_phase='intent')
            memory.transition(db,11,op,'finished',expected_phase='started')
            self.assertTrue(memory.begin_operation(db,11,description)['allowed'])

    def test_real_run_role_receives_current_memory_and_keeps_stable_prefix(self):
        ref=self.record('old original response\n'+'long '*2000)
        prompts=[]
        class Harness:
            def __init__(self,**kw):pass
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def start_session(self,name):
                def run(prompt,**kw):
                    prompts.append(prompt)
                    view=json.loads(prompt.split('<task_memory>\n')[1].split('\n</task_memory>')[0])
                    chunk=view['relevant_materials'][0]
                    report={'summary':'Analyzed supplied bytes only.','findings':[],'flags':[],
                        'verified':[],'uncertainties':[],'proposed_actions':[],
                        'material_analysis':[{**{k:chunk[k] for k in ('reference','sha256','offset','end')},'assessment':'Relevant saved response'}]}
                    return SimpleNamespace(finish_reason='completed',events=[],final_response=json.dumps(report))
                return SimpleNamespace(run=run)
        assignment={'profile':'vuln','question':'Read the original response','expected_result':'A quote or an evidence gap',
                    'references':[ref],'data':[{'reference':ref}]}
        with patch.dict(sys.modules,{'deepseek_harness':SimpleNamespace(DeepSeekHarness=Harness)}), \
             patch.object(a,'close_task_sessions'),patch.object(a.subprocess,'run',side_effect=AssertionError('No executor')):
            result=a.run_role(11,'vuln',assignment['question'],1,api_key='fake-only',assignment=assignment)
        self.assertIn('без брутфорса',prompts[0]);self.assertIn(ref,prompts[0])
        self.assertIsNone(result['input_tokens']);self.assertIsNone(result['cache_read_tokens'])
        with self.case.connect() as db:
            self.assertTrue(any(key.startswith('harness:') for key in memory.source_state(db,11,self.log)['sessions']))
            self.assertTrue(any(r['kind']=='agent_reported_analysis' for r in memory.coverage(db,11,ref,
                hashlib.sha256(memory.material(db,11,ref,self.log)).hexdigest())))
            context=a.task_context(db,11);context['specialist_assignment']=assignment
            full=a.build_prompt(db,context,'vuln',assignment['question'],2,7)
            compact=a.compact_prompt(db,context,'vuln',assignment['question'],2,7,15,'different reason')
        self.assertEqual(full.split('<pm_dynamic_context>')[0],compact.split('<pm_dynamic_context>')[0])

    def test_unknown_token_metrics_and_observed_cache_are_not_assumed(self):
        self.assertTrue(all(v is None for v in model_adapter.statistics([]).values()))
        usage=model_adapter.statistics([{'type':'assistant/message','data':{'usage':{
            'inputTokens':100,'outputTokens':20,'cacheReadTokens':80,'totalTokens':200}}}])
        self.assertEqual(usage['cache_read_tokens'],80)
        self.assertEqual(model_adapter.combine_statistics([usage,model_adapter.statistics([])])['input_tokens'],None)

    def test_report_original_versions_remain_readable_after_correction(self):
        context={'task_id':11,'target':'10.0.0.1'}
        with self.case.connect() as db:
            a.save_report(db,context,'vuln',1,{'summary':'Original interpretation','findings':[],'flags':[]},0)
            first=memory.current(db,11)['state']['materials']['report:vuln:1']
            a.save_report(db,context,'vuln',1,{'summary':'Corrected interpretation','findings':[],'flags':[]},0)
            old=memory.read_chunk(db,11,'report:vuln:1',self.log,sha256=first['sha256'])
            self.assertIn('Original interpretation',old['text_untrusted'])
            self.assertIn('Corrected interpretation',memory.material(db,11,'report:vuln:1',self.log).decode())

    def test_memory_failure_rolls_back_report_and_validated_facts_together(self):
        with self.case.connect() as db:
            memory.initialize(db)
            db.execute("CREATE TRIGGER deny_memory_revision BEFORE INSERT ON pm_memory_revisions BEGIN SELECT RAISE(ABORT,'offline failure'); END")
            with self.assertRaises(sqlite3.IntegrityError):
                a.save_report(db,{'task_id':11,'target':'10.0.0.1'},'vuln',1,{
                    'summary':'Must roll back','findings':[],'flags':[],'hypotheses':[
                    {'claim':'must not survive','kind':'hypothesis','result':'untested'}]},0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pm_agent_action_reports').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pm_hypotheses').fetchone()[0],0)
            self.assertFalse(list(a.REPORT_DIR.rglob('*.json')))

    def test_competing_connections_and_future_schema_are_rejected(self):
        with self.case.connect() as first,self.case.connect() as second:
            v=memory.sync(first,11,self.log,reason='first snapshot');first.commit()
            self.assertEqual(memory.current(second,11)['version'],v)
            memory.apply(first,11,v,[{'section':'plan','key':'operator:next','value':{'question':'new plan'}}],reason='new plan');first.commit()
            with self.assertRaises(memory.VersionConflict):memory.apply(second,11,v,[],reason='stale writer')
            first.execute('UPDATE pm_memory_schema SET version=999');first.commit()
            with self.assertRaisesRegex(ValueError,'Unsupported'):memory.initialize(second)


class MCPMemoryTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        import importlib.util
        spec=importlib.util.spec_from_file_location('memory_mcp_test',Path(__file__).resolve().parents[1]/'mcp/server.py')
        self.server=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.server)
        for p in (patch.object(self.server,'ASSET_DB',self.case.database),patch.object(self.server,'CAPABILITY_LOG',a.CAPABILITY_LOG),
                  patch.object(self.server,'ROOT',self.case.root)):
            p.start();self.addCleanup(p.stop)
        self.command=['helper','run','--task-id','11','--target','10.0.0.1','--profile','exec',
                      '--argv-json',json.dumps(['/usr/bin/nmap','-p','80','10.0.0.1']),'--execute']

    def test_repeat_guard_runs_executor_once_and_keeps_result_id(self):
        payload={'task_id':11,'target':'10.0.0.1','status':'completed','exit_code':0,'stdout':'80/tcp open'}
        with patch.object(self.server.subprocess,'run',return_value=subprocess.CompletedProcess([],0,json.dumps(payload),'')) as execute:
            first=json.loads(self.server.run_capability(self.command,1,'net_exec',11))
            second=json.loads(self.server.run_capability(self.command,1,'net_exec',11))
        self.assertEqual(execute.call_count,1)
        self.assertTrue(first['result_id']);self.assertEqual(second['kind'],'repeat_guard')
        self.assertFalse(second['execution_started'])
        with self.case.connect() as db:
            row=memory.rows(db,'pm_memory_operations',11)[0]
            self.assertEqual(row['phase'],'finished');self.assertEqual(row['result_id'],first['result_id'])
            revisions=db.execute('SELECT reason FROM pm_memory_revisions WHERE task_id=11').fetchall()
            self.assertIn(('operation_intent',),revisions);self.assertIn(('operation_dispatching',),revisions)

    def test_memory_tools_cannot_switch_out_of_active_sdk_task(self):
        with patch.dict(os.environ,{'PM_TASK_ID':'11'}):
            for call in (lambda:self.server.pm_task_memory(22),
                         lambda:self.server.pm_material_read(22,'result:'+'a'*24)):
                self.assertEqual(json.loads(call())['status'],'blocked')

    def test_executor_unavailable_timeout_and_interruption_keep_distinct_outcomes(self):
        for mode in ('unavailable','timeout','interrupt'):
            with self.subTest(mode=mode):
                command=self.command+['--meaningful-variant',mode]
                exc=FileNotFoundError('offline executor missing') if mode=='unavailable' else subprocess.TimeoutExpired('offline',1) if mode=='timeout' else KeyboardInterrupt()
                with patch.object(self.server.subprocess,'run',side_effect=exc):
                    if mode=='interrupt':
                        with self.assertRaises(KeyboardInterrupt):self.server.run_capability(command,1,'net_exec',11)
                    else:self.server.run_capability(command,1,'net_exec',11)
        with self.case.connect() as db:
            rows=memory.rows(db,'pm_memory_operations',11)
            cancelled=[r for r in rows if r['phase']=='cancelled']
            self.assertEqual(len(cancelled),1);self.assertIsNone(cancelled[0]['started_at'])
            unknown=[r for r in rows if r['phase']=='unknown']
            self.assertEqual(len(unknown),2);self.assertTrue(any(r['started_at'] is not None for r in unknown))

    def test_real_registered_memory_tools_page_and_read_without_executor(self):
        import asyncio
        a.CAPABILITY_LOG.mkdir()
        ref='result:'+'a'*24
        path=a.CAPABILITY_LOG/'task_11.jsonl'
        path.write_text(json.dumps({'id':'a'*24,'task_id':11,'tool':'net_exec','provenance':'network',
                    'result':{'status':'completed','stdout':'source bytes only'}})+'\n')
        with self.case.connect() as db:
            memory.sync(db,11,path,reason='setup')
            db.execute('UPDATE pm_tcp_full_scans SET open_ports_json=?',(json.dumps(list(range(1,20))+[9999]),))
        def call(name,params):
            blocks=asyncio.run(self.server.mcp.call_tool(name,params))
            if isinstance(blocks,tuple):blocks=blocks[0]
            return json.loads(next(b.text for b in blocks if getattr(b,'type',None)=='text'))
        with patch.object(self.server.subprocess,'run',side_effect=AssertionError('No executor')):
            page=call('pm_task_memory',{'task_id':11,'section':'resources','offset':0,'limit':10})
            later=call('pm_task_memory',{'task_id':11,'section':'resources','offset':10,'limit':10})
            chunk=call('pm_material_read',{'task_id':11,'reference':ref,'offset':0,'limit':6})
        self.assertEqual(page['total'],20);self.assertEqual(page['next_offset'],10)
        self.assertTrue(any(item['reference'].endswith(':9999') for item in later['items']))
        self.assertEqual(chunk['text_untrusted'],'source');self.assertEqual(chunk['provenance'],'local_read')
        with self.case.connect() as db:
            self.assertEqual(len(memory.coverage(db,11,ref,chunk['sha256'])),1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pm_hypotheses').fetchone()[0],0)

    def test_resume_recovers_exact_saved_result_after_state_commit_failure_without_execution(self):
        payload={'task_id':11,'target':'10.0.0.1','status':'completed','exit_code':0,'stdout':'saved original result'}
        actual_sync=memory.sync
        def sync(*args,**kwargs):
            if kwargs.get('reason')=='operation_finished':raise sqlite3.OperationalError('offline final commit failure')
            return actual_sync(*args,**kwargs)
        with patch.object(self.server.subprocess,'run',return_value=subprocess.CompletedProcess([],0,json.dumps(payload),'')) as execute, \
             patch.object(memory,'sync',side_effect=sync):
            result=json.loads(self.server.run_capability(self.command,1,'net_exec',11))
        self.assertEqual(execute.call_count,1);self.assertTrue(result['result_id'])
        self.assertIn('memory_warning',result)
        with self.case.connect() as db:
            before=memory.rows(db,'pm_memory_operations',11)[0]
            self.assertEqual(before['phase'],'dispatching')
            memory.sync(db,11,a.CAPABILITY_LOG/'task_11.jsonl',reason='explicit resume recovery')
            recovered=memory.rows(db,'pm_memory_operations',11)[0]
            self.assertEqual(recovered['phase'],'finished');self.assertEqual(recovered['result_id'],result['result_id'])

    def test_stale_check_can_refresh_and_parameters_do_not_duplicate_credentials(self):
        payload={'task_id':11,'target':'10.0.0.1','status':'completed','exit_code':1,'stdout':'negative result'}
        with patch.object(self.server.subprocess,'run',return_value=subprocess.CompletedProcess([],0,json.dumps(payload),'')) as execute:
            self.server.run_capability(self.command,1,'net_exec',11)
            with self.case.connect() as db:db.execute("UPDATE pm_memory_operations SET created_at='2000-01-01T00:00:00+00:00'")
            self.server.run_capability(self.command,1,'net_exec',11)
        self.assertEqual(execute.call_count,2)
        description=memory.canonical_operation('session',['helper','--action','send','--data','Authorization: TEST-SECRET'],'10.0.0.1')
        with self.case.connect() as db:
            memory.begin_operation(db,11,description)
            self.assertNotIn('TEST-SECRET',json.dumps(memory.rows(db,'pm_memory_operations',11)))

    def test_migration_indexes_old_completed_execution_before_dispatch(self):
        a.CAPABILITY_LOG.mkdir()
        path=a.CAPABILITY_LOG/'task_11.jsonl'
        old={'id':'c'*24,'task_id':11,'timestamp':memory.now(),'tool':'net_exec','provenance':'network',
             'argv':self.command,'argv_truncated':False,'result':{'status':'completed','exit_code':0,
                                                              'target':'10.0.0.1','stdout':'80/tcp open'}}
        path.write_text(json.dumps(old)+'\n')
        with patch.object(self.server.subprocess,'run',side_effect=AssertionError('Old check must not replay')):
            result=json.loads(self.server.run_capability(self.command,1,'net_exec',11))
        self.assertEqual(result['kind'],'repeat_guard')
        with self.case.connect() as db:
            imported=memory.rows(db,'pm_memory_operations',11)[0]
            self.assertEqual(imported['id'],'legacy:'+'c'*24)
            self.assertEqual(imported['result_id'],'c'*24)


if __name__=='__main__':unittest.main(verbosity=2)
