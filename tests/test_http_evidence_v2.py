"""Offline web evidence joins old observations without touching target/API."""
import importlib.util
import json
import sqlite3
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from orchestrator import http_discovery as web


class WebEvidenceTests(unittest.TestCase):
    def test_digest_changes_only_after_web_evidence(self):
        from orchestrator import evidence_pipeline as ev
        network = types.ModuleType('orchestrator.network_workflow')
        network.build_evidence_bundle = lambda db, task_id: {
            'authorized_target':'10.0.0.1',
            'observations':[{'observation_id':1, 'kind':'http_response', 'target':'10.0.0.1',
                 'plan_id':3,'data':{'status_line':'HTTP/1.1 302 Found','headers':{'Location':'./mbilling'}}}]}
        with patch.dict(sys.modules, {'orchestrator.network_workflow':network}), \
             patch.object(ev, 'load_burp', return_value=types.SimpleNamespace(
                 list_history=lambda task_id,limit=50: {'host':'10.0.0.1','observations':[]})):
            db = sqlite3.connect(':memory:')
            # Prepare evidence tables without using production file.
            db.executescript('''CREATE TABLE evidence_snapshots(task_id INT,evidence_sha256 TEXT,
                 evidence_json TEXT,created_at TEXT,PRIMARY KEY(task_id,evidence_sha256));
                 CREATE TABLE evidence_agent_reports(task_id INT,evidence_sha256 TEXT,stage TEXT,
                 report_json TEXT,created_at TEXT,PRIMARY KEY(task_id,evidence_sha256,stage));''')
            before, bundle_before = ev.make_snapshot(db,10)
            self.assertNotIn('web_observations',bundle_before)
            web.init(db)
            still, _ = ev.make_snapshot(db,10)
            self.assertEqual(before,still)
            db.execute('''INSERT INTO pm_http_discovery
              (task_id,target,port,scheme,hostname,path,status,location,content_type,server,title,
               links_json,forms_json,error,created_at)
              VALUES (10,'10.0.0.1',80,'http','10.0.0.1','/mbilling',200,NULL,'text/html',
                       'Apache','MBilling','["/login"]',
                       '[{"method":"POST","action":"/login","fields":[{"name":"username","type":"text"}]}]',
                       NULL,'2026-10-31')''')
            after, bundle_after = ev.make_snapshot(db,10)
            self.assertNotEqual(before,after)
            self.assertEqual(len(bundle_after['web_observations']),1)
            self.assertEqual(bundle_after['web_observations'][0]['path'],'/mbilling')
            ev.validate_report({'summary':'HTTP 200 /mbilling', 'observations_used':['web:1'],
                     'uncertainties':[], 'recommended_checks':[]}, bundle_after)
            db.execute('CREATE TABLE pm_task_intents(task_id INTEGER PRIMARY KEY,intent TEXT,created_at TEXT)')
            db.execute("INSERT INTO pm_task_intents VALUES (10,'Find flags; no brute force','now')")
            intent_digest, intent_bundle = ev.make_snapshot(db,10)
            self.assertNotEqual(after,intent_digest)
            self.assertEqual(intent_bundle['operator_task'],'Find flags; no brute force')
            self.assertEqual(ev.make_snapshot(db,10)[0],intent_digest)
            db.close()

if __name__ == '__main__': unittest.main(verbosity=2)
