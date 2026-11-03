"""Offline regression checks for intent restoration and bounded HTTP evidence."""
import io
import json
import sqlite3
import subprocess
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pm
from orchestrator import http_discovery as web


class ContinuationTests(unittest.TestCase):
    def test_model_disabled_resume_needs_no_api_key(self):
        from argparse import Namespace
        with patch.object(pm.getpass, 'getpass', side_effect=AssertionError('Unexpected key prompt')):
            self.assertIsNone(pm.session_api_key(Namespace(command='resume', no_agents=True, no_decide=True)))

    def test_change_ip_new_task_planner_still_requires_key(self):
        from argparse import Namespace
        args=Namespace(command='change-ip',no_agents=True,no_decide=True)
        with patch.object(pm.getpass,'getpass',return_value='test-only') as prompt:
            self.assertEqual(pm.session_api_key(args,required=True),'test-only')
            self.assertEqual(pm.session_api_key(args,required=True),'test-only')
        prompt.assert_called_once()

    def test_encoded_state_changing_paths_are_rejected(self):
        for path in ('/%6cogout', '/%2564elete', '/%2572eset'):
            self.assertIsNone(web.normalize_href(path, 'http://10.0.0.1/', '10.0.0.1', ['10.0.0.1']))

    def test_form_fields_stay_inside_their_form(self):
        parser = web.PageMetadata()
        parser.feed('<form><input name="inside"></form><input name="outside">')
        self.assertEqual([f['name'] for f in parser.forms[0]['fields']], ['inside'])

    def test_body_limit_excludes_headers(self):
        prefix = 'HTTP/1.1 200 OK\r\nServer: demo\r\n\r\n'
        body = web._headers_and_body(prefix + 'x' * web.MAX_BODY_PARSE)[2]
        self.assertFalse(body.limited)
        body = web._headers_and_body(prefix + 'x' * (web.MAX_BODY_PARSE + 1))[2]
        self.assertTrue(body.limited)
        self.assertEqual(len(body), web.MAX_BODY_PARSE)

    def test_malformed_broker_results_fail_cleanly(self):
        for payload in ([], None, {'stdout': []}, {'stdout': 'no HTTP headers', 'status': 'error',
                         'exit_code': 63, 'profile': 'http_path', 'target': '10.0.0.1', 'task_id': 11}):
            def runner(*args, **kwargs):
                return subprocess.CompletedProcess(args, 0, json.dumps(payload), '')
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                web.request(11,'10.0.0.1','http','10.0.0.1',80,'/',runner=runner)

    def test_application_version_claims_require_product_and_remain_unverified(self):
        from orchestrator.application_metadata import extract
        self.assertEqual(extract('version: 7.4; library 7.4', 'text/javascript'), [])
        self.assertEqual(extract('MagnusBilling v7.4', 'application/octet-stream'), [])
        hints = extract('MagnusBilling version: 7.4; MagnusBilling v7.4', 'text/javascript')
        self.assertEqual(len(hints), 1)
        self.assertEqual(hints[0]['version_claim'], '7.4')
        self.assertFalse(hints[0]['verified_product'])

    def test_application_hints_persist_without_response_body(self):
        db = sqlite3.connect(':memory:'); self.addCleanup(db.close); web.init(db)
        def requester(*args):
            return ('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'
                    '<html>MagnusBilling v7.4 <input value="secret-body"></html>')
        with patch.object(web,'validate_scope',return_value='10.0.0.1'), \
             patch.object(web,'_observed_http_ports',return_value=({80:'http'},[])), \
             redirect_stdout(io.StringIO()):
            web.execute_round(db,11,1,requester=requester)
        rows = web.evidence_rows(db,11)
        self.assertEqual(rows[0]['application_hints'][0]['version_claim'], '7.4')
        self.assertNotIn('secret-body', json.dumps(rows))
        self.assertFalse(rows[0]['response_limited'])

    def test_size_recovery_obeys_total_budget(self):
        db = sqlite3.connect(':memory:'); self.addCleanup(db.close); web.init(db)
        db.execute('INSERT INTO pm_http_discovery '
                   '(task_id,target,port,scheme,hostname,path,error,created_at) VALUES '
                   "(11,'10.0.0.1',80,'http','10.0.0.1','/large.css',?, 'before')",
                   ('curl: (63) Maximum file size exceeded',))
        db.commit()
        requester = unittest.mock.Mock(return_value=web.HTTPResult(
            'HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\n', True))
        with patch.object(web,'validate_scope',return_value='10.0.0.1'), \
             patch.object(web,'_observed_http_ports',return_value=({80:'http'},[])), \
             patch.object(web,'MAX_TOTAL',2), redirect_stdout(io.StringIO()):
            web.execute_round(db,11,2,requester=requester)
            self.assertEqual(requester.call_count,1)
            self.assertFalse(web.has_more(db,11))
            self.assertEqual(web.execute_round(db,11,2,requester=requester), [])

    def test_intent_history_and_unknown_task(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.executescript('CREATE TABLE tasks(id INTEGER); INSERT INTO tasks VALUES(11);'
                         'CREATE TABLE pm_task_intents(task_id INTEGER PRIMARY KEY,intent TEXT,created_at TEXT);')
        self.assertTrue(pm.restore_task_intent(db,11,'Find flags; no brute force','operator screenshot'))
        self.assertFalse(pm.restore_task_intent(db,11,'Find flags; no brute force','operator screenshot'))
        pm.restore_task_intent(db,11,'Updated constraints','operator correction')
        self.assertEqual(db.execute('SELECT previous_intent FROM pm_task_intent_history ORDER BY id DESC').fetchone()[0],
                         'Find flags; no brute force')
        with self.assertRaises(pm.OperatorError):
            pm.restore_task_intent(db,12,'Task','source')
        self.assertEqual(db.execute('SELECT count(*) FROM pm_task_intent_history').fetchone()[0],2)

    def test_observed_get_forms_use_scoped_discovery_without_submitting_fields(self):
        db = sqlite3.connect(':memory:'); self.addCleanup(db.close); web.init(db)
        calls = []
        def requester(task, target, scheme, host, port, path):
            calls.append(path)
            return ('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'
                    '<form action="/login"><input name="password" value="secret"></form>'
                    '<form method="POST" action="/submit"></form>'
                    '<form action="https://other.invalid/login"></form>')
        with patch.object(web,'validate_scope',return_value='10.0.0.1'), \
             patch.object(web,'_observed_http_ports',return_value=({80:'http'},[])), \
             redirect_stdout(io.StringIO()):
            web.execute_round(db,11,1,requester=requester)
            web.execute_round(db,11,2,requester=requester)
        self.assertEqual(calls,['/','/login'])
        self.assertNotIn('secret',json.dumps(web.evidence_rows(db,11)))

    def test_size_response_preserves_headers_but_scope_failures_rejected(self):
        payload = dict(task_id=11,target='10.0.0.1',profile='http_path',status='error',exit_code=63,
                       stdout='HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\n',stderr='curl: (63) Maximum file size exceeded')
        def runner(*args, **kwargs):
            return subprocess.CompletedProcess(args,0,json.dumps(payload),'')
        raw = web.request(11,'10.0.0.1','http','10.0.0.1',80,'/',runner=runner)
        self.assertTrue(raw.limited)
        self.assertEqual(web._headers_and_body(raw)[0],200)
        payload['task_id'] = 12
        with self.assertRaises(ValueError):
            web.request(11,'10.0.0.1','http','10.0.0.1',80,'/',runner=runner)
        payload.update(task_id=11,exit_code=7)
        with self.assertRaises(ValueError):
            web.request(11,'10.0.0.1','http','10.0.0.1',80,'/',runner=runner)

    def test_size_recovery_once_and_previous_error_preserved(self):
        for fails in (False, True):
            with self.subTest(fails=fails):
                db = sqlite3.connect(':memory:'); self.addCleanup(db.close); web.init(db)
                db.execute('INSERT INTO pm_http_discovery '
                           '(task_id,target,port,scheme,hostname,path,error,created_at) VALUES '
                           "(11,'10.0.0.1',80,'http','10.0.0.1','/large.css',?, 'before')",
                           ('NetGuard HTTP probe blocked or failed: curl: (63) Maximum file size exceeded',))
                db.commit()
                def requester(*args):
                    if fails:
                        raise ValueError('firewall blocked')
                    return web.HTTPResult('HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\n', True)
                with patch.object(web,'validate_scope',return_value='10.0.0.1'), \
                     patch.object(web,'_observed_http_ports',return_value=({80:'http'},[])), \
                     redirect_stdout(io.StringIO()):
                    web.execute_round(db,11,1,requester=requester)
                    self.assertNotIn(('http','10.0.0.1',80,'/large.css'),web._candidates(db,11,'10.0.0.1',['10.0.0.1']))
                saved = json.loads(db.execute('SELECT previous_record_json FROM pm_http_size_recovery').fetchone()[0])
                self.assertIn('curl: (63)',saved['error'])
                evidence = web.evidence_rows(db,11)[0]
                self.assertEqual(evidence['response_limited'],not fails)
                self.assertEqual(evidence['error'],'firewall blocked' if fails else None)

if __name__ == '__main__':
    unittest.main()
