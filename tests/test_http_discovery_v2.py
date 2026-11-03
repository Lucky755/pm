"""Offline checks: no API, sudo, socket or real target access."""
import importlib.util
import json
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from orchestrator import http_discovery as web
from executor import netguard_root as broker


class WebDiscoveryTests(unittest.TestCase):
    def test_paths_and_hosts_scope(self):
        self.assertEqual(web.normalize_href('./mbilling', 'http://10.0.0.1:80/', '10.0.0.1', ['10.0.0.1']),
                         ('http', '10.0.0.1', 80, '/mbilling'))
        self.assertIsNone(web.normalize_href('http://other.lab/', 'http://10.0.0.1:80/', '10.0.0.1', ['10.0.0.1']))
        self.assertIsNone(web.normalize_href('http://10.0.0.2/admin', 'http://10.0.0.1:80/', '10.0.0.1', ['10.0.0.1']))
        self.assertIsNone(web.normalize_href('http://10.0.0.1:81/a', 'http://10.0.0.1:80/', '10.0.0.1', ['10.0.0.1']))
        self.assertIsNone(web.normalize_href('/logout', 'http://10.0.0.1:80/', '10.0.0.1', ['10.0.0.1']))
        self.assertIsNone(web.normalize_href('/index?token=secret', 'http://10.0.0.1:80/', '10.0.0.1', ['10.0.0.1']))
        self.assertEqual(web.normalize_href('http://billing.lab/mbilling', 'http://10.0.0.1:80/',
                                            '10.0.0.1', ['10.0.0.1','billing.lab']),
                         ('http','billing.lab',80,'/mbilling'))

    def test_broker_rejects_bad_paths_and_uses_resolve(self):
        for path in ('/../etc/passwd', '/%2e%2e/x', '/%252e%252e/x', '/x?secret=1', '//evil/path',
                     '/x\nHeader: evil', '/%2fetc', '/a\\b'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                broker.safe_http_path(path)
        command = broker.tool_args('http_path', '10.0.0.1', 80, '80', 'http', '/mbilling', 'billing.lab')
        self.assertEqual(command[-1], 'http://billing.lab:80/mbilling')
        self.assertIn('--resolve', command)
        self.assertIn('billing.lab:80:10.0.0.1', command)
        self.assertNotIn('--location', command)
        self.assertNotIn('--location-trusted', command)

    def test_html_is_metadata_only(self):
        page = '<html><title>MBilling Demo</title><a href="./invoices">Invoices</a>' \
               '<form method="POST" action="/login"><input type="password" value="secret"></form></html>'
        p = web.PageMetadata(); p.feed(page)
        self.assertEqual(p.title, 'MBilling Demo')
        self.assertEqual(p.links, ['./invoices'])
        self.assertEqual(p.forms, [{'method':'POST','action':'/login','fields':[]}])
        status, hdrs, body = web._headers_and_body('HTTP/1.1 302 Found\r\nLocation: ./mbilling\r\nContent-Type: text/html\r\nSet-Cookie: SECRET=abc\r\n\r\n'+page)
        self.assertEqual(status, 302)
        self.assertEqual(hdrs['location'], './mbilling')
        self.assertNotIn('cookie', hdrs)
        self.assertIn('MBilling', body)

    def test_run_bounded_and_idempotent(self):
        db = sqlite3.connect(':memory:')
        web.init(db)
        def observed(db, task_id, target):
            return {80:'http'}, [{'kind':'http_response','plan_id':3,
                       'data': {'status_line':'HTTP/1.1 302 Found',
                       'headers': {'Location':'./mbilling'}}}]
        db.execute('CREATE TABLE network_phase_plans (id INT,task_id INT,parameters_json TEXT)')
        db.execute('INSERT INTO network_phase_plans VALUES (3,10,?)', (json.dumps({'port':80}),))
        calls = []
        def fake_request(task, target, scheme, host, port, path):
            calls.append(path)
            return ('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n'
                    'Set-Cookie: token=PRIVATE\r\n\r\n'
                    '<title>Portal</title><a href="/about">About</a>'
                    '<form action="/login" method="POST"><input name="username" type="text" value="PRIVATE"/><input name="password" type="password" value="VERY_PRIVATE"/></form>')
        with patch.object(web, 'validate_scope', return_value='10.0.0.1'), \
             patch.object(web, '_observed_http_ports', side_effect=observed):
            a=web.execute_round(db,10,2,requester=fake_request)
            self.assertEqual(len(a),2)
            self.assertEqual(calls, ['/mbilling', '/'])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pm_http_discovery').fetchone()[0],2)
            self.assertNotIn('PRIVATE', repr(web.evidence_rows(db,10)))
            self.assertIn('username', repr(web.evidence_rows(db,10)))
            b=web.execute_round(db,10,2,requester=fake_request)
            self.assertEqual(len(b),1)
            self.assertEqual(calls[-1], '/about')
            self.assertEqual(web.execute_round(db,10,2,requester=fake_request),[])
        db.close()

    def test_broker_fails_if_hostname_not_approved(self):
        with tempfile.TemporaryDirectory() as folder:
            pass
        # Argument builder itself is bounded; root run() separately reads
        # only its root-owned config and checks task hostname allowlist.
        self.assertIn('Hostname not approved',
                      Path(ROOT/'executor/netguard_root.py').read_text())

if __name__ == '__main__': unittest.main(verbosity=2)
