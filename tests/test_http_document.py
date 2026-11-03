"""Offline limited HTML recovery through a fixed broker profile."""
import io
import json
import sqlite3
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from orchestrator import http_discovery as web
from executor import netguard_root as broker

TARGET = '10.0.0.1'


class DocumentTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:'); self.addCleanup(self.db.close); web.init(self.db)
        self.db.execute('INSERT INTO pm_http_discovery '
                        '(task_id,target,port,scheme,hostname,path,status,content_type,response_limited,parser_version,created_at) '
                        "VALUES (11,?,80,'http',?,'/',200,'text/html',1,1,'before')",(TARGET,TARGET))
        self.db.commit()
        for p in (patch.object(web,'validate_scope',return_value=TARGET),
                  patch.object(web,'_observed_http_ports',return_value=({80:'http'},[]))):
            p.start(); self.addCleanup(p.stop)

    def test_tail_is_parsed_and_previous_record_archived(self):
        raw = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n' + (' '*40000) + '<script src="/app.js"></script><script>fetch("/info");</script>'
        requester = Mock(return_value=raw)
        with redirect_stdout(io.StringIO()):
            result = web.execute_round(self.db,11,1,requester=Mock(side_effect=AssertionError('normal GET')),
                                       document_requester=requester)
        self.assertTrue(result[0]['document_refresh']); self.assertFalse(result[0]['response_limited'])
        row = web.evidence_rows(self.db,11)[0]
        self.assertEqual(row['assets'][0]['path'],'/app.js')
        self.assertEqual(row['script_references'][0]['path'],'/info')
        self.assertGreater(row['response_metrics']['body_chars_parsed'],40000)
        self.assertEqual(row['response_metrics']['parse_limit'],web.MAX_DOCUMENT_PARSE)
        history = json.loads(self.db.execute('SELECT previous_record_json FROM pm_http_document_refresh').fetchone()[0])
        self.assertEqual(history['created_at'],'before')
        self.assertEqual(web.attempts_used(self.db,11),2)

    def test_second_truncation_is_explicit_and_not_retried(self):
        raw = web.HTTPResult('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 300000\r\n\r\n', True)
        raw.download_limited = True
        with redirect_stdout(io.StringIO()):
            web.execute_round(self.db,11,1,document_requester=lambda *args:raw)
            self.assertEqual(web.execute_round(self.db,11,1,document_requester=Mock(side_effect=AssertionError('retry'))),[])
        row = web.evidence_rows(self.db,11)[0]
        self.assertTrue(row['response_limited'])
        self.assertTrue(row['response_metrics']['download_limited'])
        self.assertEqual(row['response_metrics']['content_length_bytes'],300000)
        self.assertEqual(web.queue_status(self.db,11)['state'],'limited_documents')

    def test_failure_or_interruption_is_claimed_once(self):
        for exception in (ValueError('blocked'), KeyboardInterrupt()):
            with self.subTest(exception=exception):
                self.db.execute('DELETE FROM pm_http_document_refresh')
                self.db.execute("UPDATE pm_http_discovery SET error=NULL,response_limited=1,status=200,content_type='text/html'")
                self.db.commit()
                with redirect_stdout(io.StringIO()):
                    if isinstance(exception,KeyboardInterrupt):
                        with self.assertRaises(KeyboardInterrupt):
                            web.execute_round(self.db,11,1,document_requester=Mock(side_effect=exception))
                    else:
                        self.assertEqual(web.execute_round(self.db,11,1,document_requester=Mock(side_effect=exception))[0]['status'],'blocked')
                    self.assertEqual(web.execute_round(self.db,11,1,document_requester=Mock(side_effect=AssertionError('retry'))),[])

    def test_document_profile_is_fixed_get_without_redirects_or_payloads(self):
        args = broker.tool_args('http_document',TARGET,80,'','http','/mbilling/','billing.lab')
        self.assertEqual(args[args.index('--max-filesize')+1],str(web.MAX_DOCUMENT_PARSE))
        self.assertIn('--resolve',args)
        self.assertEqual(args[-1],'http://billing.lab:80/mbilling/')
        for option in ('--location','--data','--cookie','--request'):
            self.assertNotIn(option,args)
        with self.assertRaises(ValueError):
            broker.tool_args('http_document',TARGET,80,'','http','/x?token=secret')
        normal = broker.tool_args('http_path',TARGET,80,'','http','/')
        self.assertEqual(normal[normal.index('--max-filesize')+1],'32768')

    def test_broker_output_preserves_bounded_document_and_enforces_hostname(self):
        config = {'uid':1000,'gid':1000,'owner':'lucky','allowed':[TARGET+'/32'],'egress':'auto','hostnames':[]}
        process = Mock(returncode=0)
        process.communicate.return_value = ('x'*270337,'')
        with patch.object(broker,'ensure_root'), patch.object(broker,'owned_config',return_value=(broker.task_values(11),config)), \
             patch.dict(broker.os.environ,{'SUDO_UID':'1000'}), patch.object(broker,'docker_policy_drops_forward',return_value=False), \
             patch.object(broker,'cmd'), patch.object(broker.subprocess,'Popen',return_value=process), patch.object(broker,'output') as out:
            broker.run(11,'http_document',TARGET,80,'','http','/')
            payload = out.call_args.args[0]
            self.assertEqual(len(payload['stdout']),270336)
            self.assertTrue(payload['stdout_truncated'])
            with self.assertRaises(ValueError):
                broker.run(11,'http_document',TARGET,80,'','http','/','other.invalid')

    def test_document_request_validates_profile_and_identity(self):
        payload = {'status':'completed','exit_code':0,'profile':'http_document','target':TARGET,'task_id':11,
                   'stdout':'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n','stdout_truncated':False}
        def runner(command, **kwargs):
            self.assertIn('http_document',command)
            return subprocess.CompletedProcess(command,0,json.dumps(payload),'')
        self.assertFalse(web.request_document(11,TARGET,'http',TARGET,80,'/',runner=runner).limited)
        payload['profile'] = 'http_path'
        with self.assertRaises(ValueError):
            web.request_document(11,TARGET,'http',TARGET,80,'/',runner=runner)

    def test_total_budget_prevents_document_request(self):
        with patch.object(web,'MAX_TOTAL',1), redirect_stdout(io.StringIO()):
            self.assertEqual(web.execute_round(self.db,11,1,document_requester=Mock(side_effect=AssertionError('over budget'))),[])
            self.assertEqual(web.queue_status(self.db,11)['state'],'request_budget')

if __name__ == '__main__':
    unittest.main(verbosity=2)
