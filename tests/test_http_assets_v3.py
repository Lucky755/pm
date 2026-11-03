"""Offline tests for passive first-party asset discovery and v2 migration."""
import json
import sqlite3
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from orchestrator import http_discovery as web
from pm import ConciseProgress
from io import StringIO

TARGET='10.0.0.1'
HTML=('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'
      '<html><head><title>Billing Panel</title>'
      '<meta name="generator" content="Demo Generator">'
      '<script src="/mbilling/static/app.js"></script>'
      '<script src="https://evil.invalid/payload.js"></script>'
      '<link rel="stylesheet" href="./css/main.css"></head>'
      '<body><form method="POST" action="/login">'
      '<input name="password" type="password" value="never-persist"></form></body></html>')

def observed(db, task_id, target):
    return {80:'http'}, []

class AssetsTests(unittest.TestCase):
    def setup_db(self):
        db=sqlite3.connect(':memory:')
        web.init(db)
        return db

    def test_parser_restricts_metadata(self):
        parser=web.PageMetadata(); parser.feed(HTML)
        self.assertEqual(len(parser.assets),3)
        self.assertEqual(parser.meta,[{'name':'generator','content':'Demo Generator'}])
        self.assertNotIn('never-persist',repr(parser.forms))

    def test_asset_discovery_bounded_and_never_crosses_target(self):
        db=self.setup_db()
        called=[]
        def requester(task, target, scheme, host, port, path):
            called.append(path)
            return HTML if path=='/' else 'HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nconsole.log(1)'
        with patch.object(web,'validate_scope',return_value=TARGET),patch.object(web,'_observed_http_ports',side_effect=observed):
            web.execute_round(db,7,2,requester=requester)
            row=web.evidence_rows(db,7)[0]
            self.assertEqual(row['public_meta'],[{'name':'generator','content':'Demo Generator'}])
            self.assertEqual([a['path'] for a in row['assets']],['/mbilling/static/app.js','/css/main.css'])
            web.execute_round(db,7,2,requester=requester)
            self.assertEqual(called,['/','/mbilling/static/app.js','/css/main.css'])
            self.assertEqual(web.execute_round(db,7,2,requester=requester),[])
            self.assertNotIn('evil.invalid',json.dumps(web.evidence_rows(db,7)))
            self.assertNotIn('never-persist',json.dumps(web.evidence_rows(db,7)))
        db.close()

    def test_v2_html_is_refreshed_once_without_duplicate_records(self):
        db=sqlite3.connect(':memory:')
        db.execute('''CREATE TABLE pm_http_discovery (
            id INTEGER PRIMARY KEY AUTOINCREMENT,task_id INTEGER NOT NULL,
            target TEXT NOT NULL,port INTEGER NOT NULL,scheme TEXT NOT NULL,
            hostname TEXT NOT NULL,path TEXT NOT NULL,status INTEGER,location TEXT,
            content_type TEXT,server TEXT,title TEXT,
            links_json TEXT NOT NULL DEFAULT '[]',forms_json TEXT NOT NULL DEFAULT '[]',
            error TEXT,created_at TEXT NOT NULL,
            UNIQUE(task_id,port,scheme,hostname,path))''')
        db.execute('''INSERT INTO pm_http_discovery
            (task_id,target,port,scheme,hostname,path,status,content_type,title,created_at)
            VALUES (7,?,80,'http',?,'/',200,'text/html','Billing Panel','before')''',(TARGET,TARGET))
        db.commit(); web.init(db)
        self.assertIsNone(db.execute('SELECT assets_json FROM pm_http_discovery').fetchone()[0])
        requested=[]
        def requester(task,target,scheme,host,port,path):
            requested.append(path)
            return HTML
        with patch.object(web,'validate_scope',return_value=TARGET),patch.object(web,'_observed_http_ports',side_effect=observed):
            result=web.execute_round(db,7,1,requester=requester)
            self.assertEqual(len(result),1)
            self.assertEqual(requested,['/'])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pm_http_discovery').fetchone()[0],1)
            self.assertIsNotNone(db.execute('SELECT assets_json FROM pm_http_discovery').fetchone()[0])
            self.assertEqual(web._candidates(db,7,TARGET,[TARGET])[0][3],'/mbilling/static/app.js')
        db.close()

    def test_failed_legacy_refresh_is_not_retried(self):
        db=sqlite3.connect(':memory:')
        db.execute('''CREATE TABLE pm_http_discovery (
            id INTEGER PRIMARY KEY AUTOINCREMENT,task_id INTEGER NOT NULL,
            target TEXT NOT NULL,port INTEGER NOT NULL,scheme TEXT NOT NULL,
            hostname TEXT NOT NULL,path TEXT NOT NULL,status INTEGER,location TEXT,
            content_type TEXT,server TEXT,title TEXT,
            links_json TEXT NOT NULL DEFAULT '[]',forms_json TEXT NOT NULL DEFAULT '[]',
            error TEXT,created_at TEXT NOT NULL,
            UNIQUE(task_id,port,scheme,hostname,path))''')
        db.execute('''INSERT INTO pm_http_discovery
            (task_id,target,port,scheme,hostname,path,status,content_type,created_at)
            VALUES (7,?,80,'http',?,'/',200,'text/html','before')''',(TARGET,TARGET))
        db.commit();web.init(db)
        with patch.object(web,'validate_scope',return_value=TARGET),patch.object(web,'_observed_http_ports',side_effect=observed):
            x=web.execute_round(db,7,1,requester=lambda *a: (_ for _ in ()).throw(ValueError('blocked')))
            self.assertEqual(x[0]['status'],'blocked')
            self.assertEqual(web.execute_round(db,7,1,requester=lambda *a: self.fail('repeated')),[])
        db.close()

    def test_decide_prefix_not_repeated(self):
        output=StringIO()
        progress=ConciseProgress(output)
        progress.write('[DECIDE] completed; new plans=0\n')
        self.assertEqual(output.getvalue().count('[DECIDE]'),1)

if __name__=='__main__':unittest.main(verbosity=2)
