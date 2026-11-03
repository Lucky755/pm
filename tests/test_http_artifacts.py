"""Offline varied-target capture/storage/reparse checks; no target/API traffic."""
import base64
import gzip
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from orchestrator import http_artifacts as store, http_discovery as web
from executor import netguard_root as broker

TARGET='10.0.0.1'


def payload_for(wire, status='completed', exit_code=0, **extra):
    return dict(capture_protocol=1, task_id=11,target=TARGET,profile='http_capture',port=80,
                scheme='http',hostname=TARGET,path='/',status=status,exit_code=exit_code,
                response_b64=base64.b64encode(wire).decode(),response_bytes=len(wire),capture_truncated=False,**extra)


def captured(wire,limit_bytes=store.DEFAULT_BODY,**extra):
    payload=payload_for(wire,**extra)
    def runner(command,**kwargs):
        return subprocess.CompletedProcess(command,0,json.dumps(payload),'')
    return web.request_capture(11,TARGET,'http',TARGET,80,'/',runner=runner,limit_bytes=limit_bytes)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        p=patch.object(store,'ROOT',Path(self.tmp.name)/'http');p.start();self.addCleanup(p.stop)
        self.db=sqlite3.connect(':memory:');self.addCleanup(self.db.close);web.init(self.db)
        for p in (patch.object(web,'validate_scope',return_value=TARGET),
                  patch.object(web,'_observed_http_ports',return_value=({80:'http'},[]))):
            p.start();self.addCleanup(p.stop)

    def run_capture(self,raw):
        with redirect_stdout(io.StringIO()):
            return web.execute_round(self.db,11,1,capture=True,capture_requester=Mock(return_value=raw))

    def test_full_css_independent_of_stdout_preview_and_binary_exact_storage(self):
        body=b'/* css */'+b'x'*100000
        raw=captured(b'HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\n'+body)
        result=self.run_capture(raw)
        self.assertFalse(result[0]['response_limited'])
        row=web.evidence_rows(self.db,11)[0]
        self.assertEqual(row['artifact']['bytes_saved'],len(body))
        self.assertTrue(row['artifact']['download_complete'])
        loaded,_=store.load(self.db,11,result[0]['artifact_id'])
        self.assertEqual(loaded,body)
        self.assertFalse(web.has_more(self.db,11,capture=True))

    def test_private_artifact_metadata_only_evidence_and_redacted_diagnostic(self):
        body=b'<html><input value="PRIVATE_VALUE"><script>var token="SECRET";</script></html>'
        raw=captured(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: SESSION=HIDDEN\r\n\r\n'+body)
        self.run_capture(raw)
        rows=web.evidence_rows(self.db,11)
        self.assertNotIn('PRIVATE_VALUE',json.dumps(rows));self.assertNotIn('SECRET',json.dumps(rows))
        self.assertNotIn('HIDDEN',json.dumps(rows));self.assertNotIn('SESSION',self.db.execute('SELECT metadata_json FROM pm_http_artifacts').fetchone()[0])
        file=next(store.ROOT.glob('task-11/*.body'))
        self.assertEqual(file.stat().st_mode&0o777,0o600)
        self.assertEqual(file.parent.stat().st_mode&0o777,0o700)
        view=store.diagnostic_text(body.decode())
        self.assertNotIn('PRIVATE_VALUE',view);self.assertNotIn('SECRET',view)

    def test_utf16_latin_and_unknown_charset(self):
        for body,headers in [('<html>Привет</html>'.encode('utf-16'),{'content-type':'text/html'}),
                             ('café'.encode('latin-1'),{'content-type':'text/css; charset=iso-8859-1'})]:
            text,flags=store.decode_body(body,headers)
            self.assertTrue(text);self.assertFalse(flags['decode_errors'])
        _,flags=store.decode_body(b'bad\xff',{'content-type':'text/html; charset=unavailable'})
        self.assertTrue(flags['decode_errors'])

    def test_gzip_and_bomb_are_bounded_and_invalid_gzip_is_explicit(self):
        headers={'content-type':'text/html','content-encoding':'gzip'}
        text,flags=store.decode_body(gzip.compress(b'<html>Hello</html>'),headers)
        self.assertIn('Hello',text);self.assertFalse(flags['decode_limit'])
        with patch.object(store,'MAX_BODY',1024):
            text,flags=store.decode_body(gzip.compress(b'x'*2000),headers)
            self.assertEqual(len(text),1024);self.assertTrue(flags['decode_limit'])
        _,flags=store.decode_body(b'not gzip',headers)
        self.assertEqual(flags['text_skipped'],'invalid_or_incomplete_gzip')

    def test_binary_body_is_preserved_but_not_parsed_as_html(self):
        body=b'\x00\xff<script>fetch("/fake")</script>'
        self.run_capture(captured(b'HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n'+body))
        row=web.evidence_rows(self.db,11)[0]
        self.assertEqual(row['script_references'],[])
        self.assertEqual(row['response_metrics']['text_skipped'],'binary_or_unknown_content_type')
        self.assertEqual(store.load(self.db,11,row['artifact']['artifact_id'])[0],body)

    def test_informational_response_and_empty_headers(self):
        status,headers,body=store.split_response(b'HTTP/1.1 103 Early Hints\r\nLink: </foo>\r\n\r\nHTTP/1.1 200 OK\r\n\r\nbody')
        self.assertEqual((status,headers,body),(200,{},b'body'))
        with self.assertRaises(ValueError):store.split_response(b'HTTP/1.1 200 OK\r\nUnfinished')

    def test_partial_download_is_saved_and_not_refetched(self):
        raw=captured(b'HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nContent-Length: 5000000\r\n\r\npartial',status='error',exit_code=63)
        self.run_capture(raw)
        row=web.evidence_rows(self.db,11)[0]
        self.assertFalse(row['artifact']['download_complete'])
        self.assertEqual(web.queue_status(self.db,11,capture=True)['state'],'incomplete_responses')
        with redirect_stdout(io.StringIO()):
            self.assertEqual(web.execute_round(self.db,11,1,capture=True,capture_requester=Mock(side_effect=AssertionError('retry'))),[])

    def test_timeout_partial_body_survives_failure(self):
        raw=captured(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\npartial',status='timeout',exit_code=124)
        result=self.run_capture(raw)
        self.assertEqual(result[0]['status'],'blocked')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM pm_http_artifacts').fetchone()[0],1)

    def test_checksum_task_boundary_and_symlink_rejection(self):
        self.run_capture(captured(b'HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\nbody'))
        row=web.evidence_rows(self.db,11)[0];aid=row['artifact']['artifact_id']
        with self.assertRaises(ValueError):store.load(self.db,12,aid)
        file=next(store.ROOT.glob('task-11/*.body'));file.write_bytes(b'changed')
        with self.assertRaises(ValueError):store.load(self.db,11,aid)
        file.unlink();file.symlink_to(Path(self.tmp.name)/'external')
        with self.assertRaises(OSError):store.load(self.db,11,aid)

    def test_task_storage_budget_reports_failure(self):
        raw=captured(b'HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\nbody')
        with patch.object(store,'MAX_TASK_BYTES',1):
            result=self.run_capture(raw)
        self.assertEqual(result[0]['status'],'blocked')
        self.assertIn('storage budget',result[0]['error'])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM pm_http_artifacts').fetchone()[0],0)

    def test_explicit_local_reparse_does_not_request_network_or_change_attempts(self):
        self.run_capture(captured(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>fetch("/info");</script>'))
        before=web.attempts_used(self.db,11)
        with patch.object(web,'request_capture',side_effect=AssertionError('network')),patch.object(web.subprocess,'run',side_effect=AssertionError('process')):
            results=web.reparse_saved(self.db,11)
        self.assertEqual(results[0]['references'],1)
        self.assertEqual(web.attempts_used(self.db,11),before)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM pm_http_local_reparse').fetchone()[0],1)

    def test_legacy_success_is_upgraded_once_with_archived_record(self):
        self.db.execute("INSERT INTO pm_http_discovery(task_id,target,scheme,hostname,port,path,status,content_type,created_at) VALUES(11,?,'http',?,80,'/',200,'text/css','old')",(TARGET,TARGET));self.db.commit()
        self.run_capture(captured(b'HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\nwhole CSS'))
        history=json.loads(self.db.execute('SELECT previous_record_json FROM pm_http_capture_refresh').fetchone()[0])
        self.assertEqual(history['created_at'],'old')
        self.assertFalse(web.has_more(self.db,11,capture=True))
        self.assertEqual(web.attempts_used(self.db,11),2)

    def test_stale_broker_is_detected_before_attempt_claim(self):
        def old_runner(*args,**kwargs):return subprocess.CompletedProcess(args,1,'{}','unknown command')
        with self.assertRaises(ValueError):web.require_capture_support(runner=old_runner)
        self.assertEqual(web.attempts_used(self.db,11),0)

    def test_capture_protocol_scope_and_byte_count_are_validated(self):
        data=payload_for(b'HTTP/1.1 200 OK\r\n\r\n')
        for key,value in [('target','10.0.0.2'),('path','/outside'),('response_bytes',999),('response_b64','invalid%')]:
            broken={**data,key:value}
            def runner(*args,**kwargs):return subprocess.CompletedProcess(args,0,json.dumps(broken),'')
            with self.subTest(key=key),self.assertRaises(ValueError):
                web.request_capture(11,TARGET,'http',TARGET,80,'/',runner=runner)

    def test_broker_binary_capture_real_local_process_is_bounded(self):
        result=broker.capture_process([sys.executable,'-c','import sys;sys.stdout.buffer.write(bytes(range(256)))'])
        self.assertEqual(result['exit_code'],0)
        self.assertEqual(base64.b64decode(result['response_b64']),bytes(range(256)))
        with patch.object(broker,'HTTP_CAPTURE_WIRE_LIMIT',1024):
            result=broker.capture_process([sys.executable,'-c','import sys;sys.stdout.buffer.write(b"x"*100000)'])
        self.assertTrue(result['capture_truncated']);self.assertEqual(result['response_bytes'],1024)
        self.assertEqual(result['exit_code'],63)

    def test_generic_metadata_reports_unsupported_resources_and_parser_limits(self):
        body=('<html>'+''.join(f'<script src="/s{i}.js?v=1"></script>' for i in range(20))+'</html>').encode()
        self.run_capture(captured(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'+body))
        row=web.evidence_rows(self.db,11)[0]
        self.assertEqual(row['response_metrics']['assets_seen'],20)
        self.assertEqual(row['response_metrics']['assets_not_queued'],20)
        self.assertIn('html_assets',row['response_metrics']['metadata_limits'])
        self.assertEqual(web.queue_status(self.db,11,capture=True)['state'],'analysis_incomplete')

    def test_task_policy_upgrade_is_explicit_bounded_and_archived(self):
        self.db.execute('CREATE TABLE tasks(id INTEGER PRIMARY KEY)');self.db.execute('INSERT INTO tasks VALUES(11)');self.db.commit()
        self.run_capture(captured(b'HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\npartial',status='error',exit_code=63))
        self.assertFalse(web.has_more(self.db,11,capture=True))
        store.set_response_limit(self.db,11,store.MAX_BODY,'now')
        self.assertTrue(web.has_more(self.db,11,capture=True))
        raw=captured(b'HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\n'+b'x'*(3*1024*1024),limit_bytes=store.MAX_BODY)
        self.run_capture(raw)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM pm_http_capture_upgrades').fetchone()[0],1)
        self.assertFalse(web.has_more(self.db,11,capture=True))
        self.assertTrue(web.evidence_rows(self.db,11)[0]['artifact']['download_complete'])
        self.assertEqual(web.attempts_used(self.db,11),2)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM pm_http_capture_policy_history').fetchone()[0],1)
        with self.assertRaises(ValueError):store.set_response_limit(self.db,12,store.MAX_BODY,'now')
        with self.assertRaises(ValueError):store.set_response_limit(self.db,11,999999999,'now')

    def test_broker_profile_limit_is_selected_from_fixed_presets(self):
        args=broker.tool_args('http_capture',TARGET,80,'','http','/',capture_limit=8*1024*1024)
        self.assertEqual(args[args.index('--max-filesize')+1],str(8*1024*1024))
        with self.assertRaises(ValueError):broker.tool_args('http_capture',TARGET,80,'','http','/',capture_limit=999999999)

    def test_js_token_budget_is_explicit_instead_of_unbounded_memory(self):
        from orchestrator import application_discovery as app
        diagnostics={}
        with patch.object(app,'MAX_TOKENS',10):
            app.references('; '*1000,diagnostics)
        self.assertTrue(diagnostics['token_limit'])

    def test_broker_timeout_kills_local_process_and_keeps_prefix(self):
        with patch.object(broker,'HTTP_CAPTURE_TIMEOUT',0.15):
            result=broker.capture_process([sys.executable,'-c','import sys,time;print("prefix",flush=True);time.sleep(10)'])
        self.assertEqual(result['status'],'timeout');self.assertEqual(result['exit_code'],124)
        self.assertIn(b'prefix',base64.b64decode(result['response_b64']))

    def test_local_cli_diagnostic_needs_no_key_or_network_and_preserves_lines(self):
        import pm
        from argparse import Namespace
        body=b'<html>\n<input value="PRIVATE_VALUE">\n<script>var token="SECRET";</script>\n</html>'
        self.run_capture(captured(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'+body))
        out=io.StringIO()
        with patch.object(pm,'connect',return_value=self.db),patch.object(pm,'session_api_key',side_effect=AssertionError('key')), \
             patch.object(web.subprocess,'run',side_effect=AssertionError('network')),redirect_stdout(out):
            pm.op_http_artifacts(Namespace(task_id=11,path='/',show=True,offset=0,max_chars=12000))
        self.assertIn('artifact=',out.getvalue());self.assertIn('\n</html>',out.getvalue())
        self.assertNotIn('PRIVATE_VALUE',out.getvalue());self.assertNotIn('SECRET',out.getvalue())

    def test_html_base_resolution_is_scoped_and_does_not_invent_local_paths(self):
        for base,expected in [('/ui/','/ui/app.js'),('https://outside.invalid/',None)]:
            with self.subTest(base=base):
                raw=captured(('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'
                              f'<base href="{base}"><script src="app.js"></script>').encode())
                parsed=web.analyze_http(raw,TARGET,'http',TARGET,80,'/',[TARGET],store.MAX_BODY,'http_capture')
                self.assertEqual([a['path'] for a in parsed['assets']], [expected] if expected else [])
                if not expected:self.assertIn('relative_urls_skipped',parsed['metrics'])

    def test_url_fragments_and_truncated_paths_are_not_saved_as_new_destinations(self):
        body=b'<html><a href="/info#token=PRIVATE_VALUE">Info</a><script src="/app.js#SECRET"></script></html>'
        self.run_capture(captured(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'+body))
        row=web.evidence_rows(self.db,11)[0]
        self.assertEqual(row['links'],['/info'])
        self.assertEqual(row['assets'][0]['path'],'/app.js')
        self.assertNotIn('PRIVATE_VALUE',json.dumps(row));self.assertNotIn('SECRET',json.dumps(row))

    def test_decision_does_not_repeat_root_get_already_captured(self):
        from orchestrator import decision_agent as decisions
        self.db.execute('CREATE TABLE network_phase_plans '
                        '(id INTEGER,task_id INTEGER,profile TEXT,target TEXT,parameters_json TEXT)')
        self.db.execute('INSERT INTO network_phase_plans VALUES(1,11,?,?,?)',('http_headers',TARGET,json.dumps({'port':80})))
        bundle={'authorized_target':TARGET,'network_observations':[
            {'observation_id':1,'plan_id':1,'target':TARGET,'kind':'http_response','data':{'status_line':'HTTP/1.1 200 OK'}}],
            'web_observations':[{'path':'/','hostname':TARGET,'port':80,'status_code':200,'error':None}]}
        self.assertEqual(decisions.candidate_catalog(self.db,11,bundle),[])
        bundle['web_observations']=[]
        self.assertEqual(decisions.candidate_catalog(self.db,11,bundle)[0]['profile'],'http_get')

if __name__=='__main__':unittest.main(verbosity=2)
