"""Read-only service context regressions; in-memory data, no executor/model."""
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from orchestrator import agent_actions as a, attack_loop, diagnostics as d, fact_state, service_inventory


class ServiceInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pm-services-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.now = datetime.now(timezone.utc)
        self.stamp = self.now.isoformat()
        policy = patch.dict(os.environ, {'PM_TCP_SCAN_STALE_MINUTES': '30'})
        policy.start(); self.addCleanup(policy.stop)
        for name in ('CAPABILITY_LOG', 'TASK_WORK_BASE', 'REPORT_DIR'):
            p = patch.object(a, name, self.root / name)
            p.start(); self.addCleanup(p.stop)
        a.ensure_schema(self.db)
        fact_state.ensure_schema(self.db)
        self.db.executescript('''
            CREATE TABLE tasks(id INTEGER PRIMARY KEY,target TEXT);
            INSERT INTO tasks VALUES(11,'10.0.0.1'),(22,'10.0.0.2');
            CREATE TABLE task_scope_settings(task_id INTEGER PRIMARY KEY,initial_target TEXT,
                                             allow_pivot INTEGER,allow_port_forward INTEGER);
            INSERT INTO task_scope_settings VALUES(11,'10.0.0.1',0,0),(22,'10.0.0.2',0,0);
            CREATE TABLE pm_tcp_full_scans(id INTEGER PRIMARY KEY,task_id INTEGER,target TEXT,
                status TEXT,open_ports_json TEXT,created_at TEXT,last_seen_at TEXT);
            CREATE TABLE pm_tcp_full_scan_attempts(id INTEGER PRIMARY KEY,task_id INTEGER,
                target TEXT,status TEXT,created_at TEXT);
            CREATE TABLE network_phase_plans(id INTEGER PRIMARY KEY,task_id INTEGER,target TEXT,
                profile TEXT,parameters_json TEXT);
            CREATE TABLE network_job_runs(id INTEGER PRIMARY KEY,plan_id INTEGER,status TEXT,
                result_json TEXT,finished_at TEXT);
            CREATE TABLE network_observations(id INTEGER PRIMARY KEY,run_id INTEGER,task_id INTEGER,
                target TEXT,kind TEXT,data_json TEXT,observed_at TEXT);
        ''')

    def scan(self, status='completed', ports=(22, 80), task=11, target='10.0.0.1', when=None):
        self.db.execute('INSERT INTO pm_tcp_full_scans(task_id,target,status,open_ports_json,created_at,last_seen_at) '
                        'VALUES(?,?,?,?,?,?)', (task,target,status,json.dumps(ports),when or self.stamp,self.stamp))

    def observation(self, port=80, *, task=11, target='10.0.0.1', run_status='completed',
                    plan_task=None, plan_target=None, kind='tcp_port_open', when=None, **data):
        plan_id = self.db.execute('INSERT INTO network_phase_plans(task_id,target,profile,parameters_json) VALUES(?,?,?,?)',
                                 (task if plan_task is None else plan_task,plan_target or target,
                                  'service_versions' if kind=='service_probe' else 'tcp_ports',json.dumps({'ports':str(port)}))).lastrowid
        run_id = self.db.execute('INSERT INTO network_job_runs(plan_id,status,result_json,finished_at) VALUES(?,?,?,?)',
                                (plan_id,run_status,'{}',when or self.stamp)).lastrowid
        oid = self.db.execute('INSERT INTO network_observations(run_id,task_id,target,kind,data_json,observed_at) '
                             'VALUES(?,?,?,?,?,?)', (run_id,task,target,kind,json.dumps(
                                 {'port':port,'protocol':'tcp','state':'open',**data}),when or self.stamp)).lastrowid
        return oid

    def note(self, text):
        path = a.TASK_WORK_BASE / '11/NOTES.md'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')

    def mapped(self, **kwargs):
        return a.service_map(self.db, 11, 1, **kwargs)

    def test_fresh_full_scan_without_role_reports_is_the_map(self):
        self.scan()
        mapped = self.mapped()
        self.assertEqual([e['port'] for e in mapped['entries']], [22,80])
        self.assertEqual(mapped['scan_mode'], 'spot_check')
        self.assertTrue(mapped['fresh'])
        for entry in mapped['entries']:
            self.assertEqual((entry['target'],entry['protocol']), ('10.0.0.1','tcp'))
            self.assertEqual(entry['sources'][0]['table'], 'pm_tcp_full_scans')
            self.assertEqual(entry['sources'][0]['observed_at'], self.stamp)
            self.assertNotIn('result_id', entry['sources'][0])
            self.assertEqual(entry['identifications'], [])
        with patch.object(a, 'connect', return_value=self.db):
            self.assertTrue(attack_loop.has_service_map(11, 1))

    def test_noncompleted_and_empty_scans_do_not_populate_the_map(self):
        for status, ports in (('failed',[22]),('running',[22]),('empty',[22]),('completed',[])):
            with self.subTest(status=status, ports=ports):
                self.db.execute('DELETE FROM pm_tcp_full_scans')
                self.scan(status=status, ports=ports)
                self.assertEqual(self.mapped()['entries'], [])
                self.assertEqual(self.mapped()['scan_mode'], 'full_scan')

    def test_completed_job_scope_and_current_address_are_required(self):
        good = self.observation(port=80)
        self.observation(port=81,run_status='running')
        self.observation(port=82,run_status='failed')
        self.observation(port=83,task=22,target='10.0.0.2')
        self.observation(port=84,target='10.0.0.9')
        self.observation(port=85,plan_task=22)
        self.observation(port=86,plan_target='10.0.0.9')
        mapped = self.mapped()
        self.assertEqual([e['port'] for e in mapped['entries']], [80])
        self.assertEqual(mapped['entries'][0]['sources'][0]['key']['id'], good)
        self.db.execute("UPDATE task_scope_settings SET initial_target='10.0.0.9' WHERE task_id=11")
        self.assertEqual(self.mapped()['entries'], [])

    def test_notes_never_override_structured_sources_and_references_merge(self):
        self.scan(ports=[80])
        first = self.observation(service_hint='http')
        second = self.observation(kind='service_probe',service_hint='apache',version_hint='2.4',
                                  identification_uncertain=True,verified_product=False)
        self.note('80/tcp nginx 9.9\n')
        mapped = self.mapped()
        self.assertEqual(len(mapped['entries']), 1)
        entry = mapped['entries'][0]
        self.assertEqual(len(entry['sources']), 3)
        self.assertEqual({s['key']['id'] for s in entry['sources'] if s['table']=='network_observations'}, {first,second})
        self.assertTrue(entry['identification_uncertain'])
        self.assertNotIn('nginx', json.dumps(entry))
        self.assertIn('nginx', json.dumps(mapped['hints']))
        self.assertTrue(all(h['requires_verification'] for h in mapped['hints']))

    def test_conflicting_identifications_remain_unverified_and_separate_protocols(self):
        self.observation(port=53,kind='service_probe',service_hint='dns',version_hint='1',verified_product=False)
        self.observation(port=53,kind='service_probe',service_hint='other',version_hint='2',verified_product=False)
        self.observation(port=53,kind='service_probe',protocol='udp',service_hint='dns',verified_product=False)
        entries = self.mapped()['entries']
        self.assertEqual([(e['protocol'],e['port']) for e in entries], [('tcp',53),('udp',53)])
        self.assertTrue(entries[0]['identification_conflict'])
        self.assertEqual({i['service_hint'] for i in entries[0]['identifications']}, {'dns','other'})
        self.assertTrue(all(i['verified_product'] is False for e in entries for i in e['identifications']))

    def test_stale_scan_is_not_refreshed_by_preflight_timestamp(self):
        old = (self.now - timedelta(hours=2)).isoformat()
        self.scan(when=old)
        mapped = self.mapped()
        self.assertEqual(mapped['scan_mode'], 'full_scan')
        self.assertFalse(mapped['fresh'])
        self.assertEqual([e['port'] for e in mapped['entries']], [22,80])
        self.db.execute('INSERT INTO pm_tcp_full_scan_attempts VALUES(1,11,?,?,?)',
                        ('10.0.0.1','completed',self.stamp))
        self.assertEqual(self.mapped()['scan_mode'], 'spot_check')

    def test_note_selection_has_absolute_references_and_explicit_omissions(self):
        self.note(''.join(f'{1000+index}/tcp nginx\n' for index in range(50)))
        mapped = self.mapped()
        self.assertEqual(mapped['notes_selection']['lines_omitted'], 10)
        self.assertEqual(mapped['notes_selection']['lines_total'], 50)
        self.assertEqual(mapped['hints_total'], 40)
        self.assertEqual(mapped['hints_omitted'], 28)
        self.assertEqual(mapped['hints'][0]['reference']['line'], 11)
        self.assertEqual(mapped['entries'], [])

    def test_limits_are_deterministic_with_explicit_omissions(self):
        self.scan(ports=list(range(1,31)))
        mapped = self.mapped(keep=3)
        self.assertEqual([e['port'] for e in mapped['entries']], [1,2,3])
        self.assertEqual(mapped['total_entries'], 30)
        self.assertEqual(mapped['omitted_entries'], 27)
        self.assertEqual(mapped, self.mapped(keep=3))

    def test_full_execution_inventory_and_bounded_context_share_sources(self):
        self.scan(ports=list(range(1,13))+[9999])
        for _ in range(20):self.observation(port=1,kind='service_probe',service_hint='http')
        self.db.commit()
        before=list(self.db.iterdump())
        self.db.execute('PRAGMA query_only=ON')
        full=service_inventory.collect_full(self.db,11,at=self.now)
        prompt=service_inventory.collect(self.db,11,keep=10000,at=self.now)
        self.assertEqual([e['port'] for e in full['entries']],list(range(1,13))+[9999])
        self.assertEqual(full['omitted_entries'],0)
        self.assertEqual(len(full['entries'][0]['sources']),21)
        self.assertEqual(len(full['entries'][0]['identifications']),20)
        self.assertEqual(len(prompt['entries']),12)
        self.assertEqual(prompt['omitted_entries'],1)
        self.assertEqual(len(prompt['entries'][0]['sources']),8)
        self.assertEqual(prompt['entries'][0]['sources_omitted'],13)
        self.assertEqual(prompt['entries'][0]['identifications_omitted'],12)
        self.assertEqual(prompt['entries'][0]['sources'],full['entries'][0]['sources'][:8])
        self.assertEqual(list(self.db.iterdump()),before)

    def test_full_inventory_filters_protocol_task_old_ip_and_unfinished_jobs(self):
        self.scan(ports=list(range(1,13))+[9999])
        self.scan(task=22,target='10.0.0.2',ports=[4444])
        self.scan(task=11,target='10.0.0.9',ports=[5555])
        self.observation(port=53,kind='service_probe',protocol='udp',service_hint='dns')
        self.observation(port=8080)
        self.observation(port=8080)  # one service, both proof row references
        self.observation(port=9998,run_status='running')
        self.observation(port=9997,run_status='failed')
        self.observation(port=9996,task=22,target='10.0.0.2')
        self.observation(port=9995,target='10.0.0.9')
        self.observation(port=9994,plan_task=22)
        self.observation(port=9993,plan_target='10.0.0.9')
        full=service_inventory.collect_full(self.db,11)
        tcp=[e['port'] for e in full['entries'] if e['protocol']=='tcp']
        self.assertEqual(tcp,list(range(1,13))+[8080,9999])
        self.assertEqual([(e['protocol'],e['port']) for e in full['entries'] if e['protocol']=='udp'],[('udp',53)])
        self.assertEqual(len(next(e for e in full['entries'] if e['port']==8080)['sources']),2)
        self.db.execute("UPDATE task_scope_settings SET initial_target='10.0.0.9' WHERE task_id=11")
        self.assertEqual(service_inventory.collect_full(self.db,11)['entries'],[])

    def test_provenance_limits_and_real_capability_reference(self):
        for index in range(20):
            oid = self.observation(kind='service_probe',service_hint='http',version_hint='1',verified_product=False)
        self.db.execute('UPDATE network_job_runs SET result_json=? WHERE id=(SELECT run_id FROM network_observations WHERE id=?)',
                        (json.dumps({'result_id':'a'*24}),oid))
        entry = self.mapped()['entries'][0]
        self.assertEqual(entry['sources_total'], 20)
        self.assertEqual(entry['sources_omitted'], 12)
        self.assertEqual(len(entry['sources']), 8)
        self.assertEqual(entry['identifications_total'], 20)
        self.assertEqual(entry['identifications_omitted'], 12)
        self.assertEqual(len(entry['identifications']), 8)
        # Read with just that source: copy the stored result_id rather than deriving one from row IDs.
        self.db.execute('DELETE FROM network_observations WHERE id<>?',(oid,))
        self.assertEqual(self.mapped()['entries'][0]['sources'][0]['result_id'], 'a'*24)

    def test_invalid_future_and_failed_results_do_not_become_fresh_evidence(self):
        future = (self.now + timedelta(hours=2)).isoformat()
        self.observation(port=22,when=future)
        self.observation(port=23,when='unknown')
        self.observation(port='80')
        self.observation(port=True)
        bad = self.observation(port=81)
        self.db.execute('UPDATE network_job_runs SET result_json=? WHERE id=(SELECT run_id FROM network_observations WHERE id=?)',
                        ('{"status":"error","exit_code":1}',bad))
        mapped = self.mapped()
        self.assertEqual([e['port'] for e in mapped['entries']], [22,23])
        self.assertFalse(mapped['fresh'])
        self.assertEqual(mapped['scan_mode'], 'full_scan')
        self.assertIsNone(mapped['entries'][1]['sources'][0]['observed_at'])

    def test_freshness_policy_and_failed_attempt_do_not_refresh_a_scan(self):
        self.scan(when=(self.now-timedelta(minutes=10)).isoformat())
        self.db.execute('INSERT INTO pm_tcp_full_scan_attempts VALUES(1,11,?,?,?)',
                        ('10.0.0.1','failed',self.stamp))
        with patch.dict(os.environ, {'PM_TCP_SCAN_STALE_MINUTES':'5'}):
            self.assertEqual(self.mapped()['scan_mode'], 'full_scan')
        with patch.dict(os.environ, {'PM_TCP_SCAN_STALE_MINUTES':'30'}):
            self.assertEqual(self.mapped()['scan_mode'], 'spot_check')

    def test_http_observation_uses_the_saved_plan_port_without_inventing_a_product(self):
        oid = self.observation(port=8080,kind='http_response',status_line='HTTP/1.1 200 OK')
        self.db.execute('UPDATE network_phase_plans SET profile=?,parameters_json=?',
                        ('http_headers','{"port":8080}'))
        entry = self.mapped()['entries'][0]
        self.assertEqual(entry['port'],8080)
        self.assertEqual(entry['identifications'],[])
        self.assertEqual(entry['sources'][0]['key']['id'],oid)

    def test_truncated_identifications_still_retain_conflicts(self):
        self.observation(kind='service_probe',service_hint='http',version_hint='x'*300+'a')
        self.observation(kind='service_probe',service_hint='http',version_hint='x'*300+'b')
        entry = self.mapped()['entries'][0]
        self.assertTrue(entry['identification_conflict'])
        self.assertTrue(entry['identification_uncertain'])
        self.assertTrue(all(i['text_truncated'] for i in entry['identifications']))
        self.assertTrue(all(len(i['version_hint'])==240 for i in entry['identifications']))

    def test_old_address_remains_only_a_hint_in_every_role_and_compact_prompt(self):
        self.db.execute('CREATE TABLE pm_task_lineage(previous_task_id INTEGER, successor_task_id INTEGER,'
                        'previous_target TEXT,successor_target TEXT,transfer_enabled INTEGER)')
        self.db.execute("INSERT INTO pm_task_lineage VALUES(22,11,'10.0.0.2','10.0.0.1',1)")
        self.scan(task=22,target='10.0.0.2')
        self.db.commit()
        before = list(self.db.iterdump())
        mapped = self.mapped()
        self.assertEqual(mapped['entries'],[])
        self.assertFalse(mapped['fresh'])
        self.assertTrue(mapped['hints'])
        self.assertTrue(all(h['kind']=='previous_ip' and h['target']=='10.0.0.2' and h['requires_verification']
                            for h in mapped['hints']))
        context = {'task_id':11,'target':'10.0.0.1','intent':'Find flags'}
        for role in a.ROLES:
            for prompt in (a.build_prompt(self.db,context,role,'check prior ports',1,7),
                           a.compact_prompt(self.db,context,role,'check prior ports',1,7,15)):
                actual = json.JSONDecoder().raw_decode(prompt.split(a.SERVICE_MAP_HEADING+'\n',1)[1])[0]
                self.assertEqual(actual,mapped)
        self.assertEqual(list(self.db.iterdump()), before)

    def test_text_report_provenance_and_transfer_notes_remain_available(self):
        import pm
        report = {'findings':[{'title':'53/udp nginx 1.2', 'evidence':'unverified report',
                              'probe':{'result_id':'b'*24}}]}
        self.db.execute('INSERT INTO pm_agent_action_reports VALUES(11,?,?,?,?,?,?)',
                        ('recon',1,'10.0.0.9',json.dumps(report),1,self.stamp))
        mapped = self.mapped()
        self.assertEqual(mapped['entries'],[])
        hint = mapped['hints'][0]
        self.assertEqual(hint['reference']['target'],'10.0.0.9')
        self.assertEqual(hint['reference']['result_id'],'b'*24)
        self.assertEqual(hint['when'],self.stamp)
        payload = pm.build_transfer_notes({'old_id':11,'old_ip':'10.0.0.1','notes_bytes':b'',
                                           'service_map':mapped},'10.0.0.2').decode()
        self.assertIn('53/udp nginx 1.2',payload)
        self.assertIn('перепроверь',payload)

    def test_unknown_protocol_hint_survives_transfer_without_becoming_tcp_evidence(self):
        import pm
        self.note('порт 8080 nginx\n')
        payload = pm.build_transfer_notes({'old_id':11,'old_ip':'10.0.0.1','notes_bytes':b'',
                                           'service_map':self.mapped()},'10.0.0.2').decode()
        self.assertIn('порт 8080 nginx',payload)
        self.assertNotIn('8080/tcp',payload)
        self.note(payload)
        mapped = self.mapped()
        self.assertEqual(mapped['entries'],[])
        self.assertTrue(any(h['port']==8080 and h['protocol']=='unknown' for h in mapped['hints']))

    def test_same_map_reaches_all_roles_and_compaction_without_db_or_network_changes(self):
        self.scan()
        self.db.commit()
        before = list(self.db.iterdump())
        context = {'task_id':11,'target':'10.0.0.1','intent':'Без брутфорса\nПодсказка: /status'}
        maps = []
        # PRAGMA query_only also forbids schema/data writes if the collector tries any.
        with patch.object(a.subprocess, 'run', side_effect=AssertionError('Network/subprocess during prompt')):
            for role in a.ROLES:
                for prompt in (a.build_prompt(self.db,context,role,'Check known ports',1,7),
                               a.compact_prompt(self.db,context,role,'Check known ports',1,7,15)):
                    label = 'Port and service map (structured evidence; text and prior-IP records are hints):\n'
                    self.assertIn(label, prompt)
                    maps.append(json.JSONDecoder().raw_decode(prompt.split(label,1)[1])[0])
                    self.assertIn(context['intent'], prompt)
                    self.assertIn(a.REPORT_CONTRACT, prompt)
        self.assertTrue(all(mapped == maps[0] for mapped in maps))
        self.assertEqual(list(self.db.iterdump()), before)
        self.db.execute('PRAGMA query_only=ON')
        self.assertEqual(self.mapped(), maps[0])

    def test_source_and_scan_mode_diagnostics_have_no_raw_outputs(self):
        self.scan()
        with patch.object(d, 'EVENT_DIR', self.root/'events'), redirect_stderr(io.StringIO()), d.run('map',11):
            self.mapped()
            events = [e for e in d.read_events() if e['kind']=='service_map.selected']
            self.assertEqual(len(events),1)
            self.assertEqual(events[0]['reason'], 'fresh_full_tcp_scan')
            self.assertNotIn('stdout', json.dumps(events))


if __name__ == '__main__':
    unittest.main()
