"""Offline public application discovery: source lineage, scope and bounded upgrades."""
import io
import json
import sqlite3
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from orchestrator import application_discovery as app
from orchestrator import http_discovery as web

TARGET = '10.0.0.1'


def response(body, kind='text/html'):
    return f'HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\n\r\n' + body


class ApplicationTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:'); self.addCleanup(self.db.close)
        web.init(self.db)
        for patcher in (patch.object(web,'validate_scope',return_value=TARGET),
                        patch.object(web,'_observed_http_ports',return_value=({80:'http'},[]))):
            patcher.start(); self.addCleanup(patcher.stop)
        self.calls = []

    def run_round(self, pages, slots=2):
        def requester(task, target, scheme, host, port, path):
            self.assertEqual((task,target,scheme,host,port), (11,TARGET,'http',TARGET,80))
            self.calls.append(path)
            return pages[path]
        with redirect_stdout(io.StringIO()):
            return web.execute_round(self.db,11,slots,requester=requester)

    def old(self, path, kind='text/html', assets='[]'):
        self.db.execute('INSERT INTO pm_http_discovery '
                        '(task_id,target,port,scheme,hostname,path,status,content_type,assets_json,created_at) '
                        "VALUES(11,?,80,'http',?,?,200,?,?, 'before')", (TARGET,TARGET,path,kind,assets))
        self.db.commit()

    def test_literal_syntax_does_not_evaluate_expressions(self):
        source = '''// fetch('/comment');
        /* import('/hidden.js'); */
        const template = `fetch('/template')`;
        const pattern = /fetch\\('\\/regex'\\)/;
        fetch('/get'); fetch('/post',{method:'POST'});
        fetch('/explicit', {method:'GET'});
        fetch('/prefix/' + variable); fetch(`/template/${name}`);
        fetch('/auth', {headers: {Authorization: secret}});
        import('./next.js'); import name from './module.js';
        '''
        refs = app.references(source)
        eligible = {r['href'] for r in refs if r['eligible']}
        self.assertEqual(eligible, {'/get','/explicit','./next.js','./module.js'})
        self.assertFalse(next(r for r in refs if r['href']=='/post')['eligible'])
        self.assertNotIn('/comment', repr(refs))
        self.assertNotIn('/prefix/', repr(refs))

    def test_unterminated_comments_and_templates_are_never_code(self):
        for source in ("/* fetch('/fake')", "`fetch('/fake')", "'unterminated\nfetch(\"/fake\")"):
            self.assertFalse(any(r['eligible'] for r in app.references(source)))

    def test_references_same_origin_and_methods(self):
        refs = web.script_references('''fetch('/api/info'); fetch('/api/submit',{method:'POST'});
            fetch('relative'); fetch('/%64elete.php'); fetch('/x?token=secret');
            fetch('http://other.invalid/path'); fetch('http://10.0.0.1:81/path');
            import('./child.js');''', 'http://10.0.0.1/js/app.js', TARGET)
        self.assertEqual({r['path'] for r in refs}, {'/api/info','/api/submit','/js/child.js'})
        self.assertNotIn('secret',json.dumps(refs))

    def test_html_js_get_chain_provenance_and_no_post(self):
        pages = {
            '/': response('<script src="/js/app.js"></script><script>fetch("./info");</script>'),
            '/info': response('{}','application/json'),
            '/js/app.js': response('MagnusBilling v7.4; import("./child.js"); fetch("/api/info");'
                                   'fetch("/api/submit",{method:"POST"});', 'text/javascript'),
            '/api/info': response('{}','application/json'),
            '/js/child.js': response('console.log("not executed")','text/javascript'),
        }
        for _ in range(5):
            self.run_round(pages)
        self.assertEqual(set(self.calls), set(pages))
        self.assertEqual(len(self.calls),len(pages))
        rows = {r['path']:r for r in web.evidence_rows(self.db,11)}
        self.assertEqual(rows['/js/child.js']['discovered_from'][0]['observation'],
                         f"web:{rows['/js/app.js']['observation_id']}")
        self.assertEqual(rows['/js/app.js']['discovered_from'][0]['kind'],'html_asset')
        self.assertFalse(rows['/js/app.js']['application_hints'][0]['verified_product'])
        self.assertNotIn('console.log',json.dumps(rows))
        self.assertFalse(web.has_more(self.db,11))

    def test_old_public_pages_refresh_once_with_history(self):
        self.old('/'); self.old('/js/app.js', 'text/javascript')
        self.run_round({'/': response('<script src="/js/app.js"></script>'),
                        '/js/app.js': response('fetch("/api/info");','text/javascript')})
        self.assertEqual(self.calls, ['/','/js/app.js'])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM pm_http_metadata_refresh').fetchone()[0],2)
        self.assertEqual(web.attempts_used(self.db,11),4)
        self.run_round({'/api/info': response('{}','application/json')})
        self.assertEqual(self.calls, ['/','/js/app.js','/api/info'])
        before = json.loads(self.db.execute('SELECT previous_record_json FROM pm_http_metadata_refresh LIMIT 1').fetchone()[0])
        self.assertEqual(before['created_at'],'before')
        self.assertEqual(before['parser_version'],0)
        self.assertEqual(self.run_round({}),[])

    def test_refresh_interruption_is_claimed_once_even_for_v2_html(self):
        schema = self.db.execute("SELECT sql FROM sqlite_master WHERE name='pm_http_discovery'").fetchone()[0]
        self.db.execute('DROP TABLE pm_http_discovery')
        self.db.execute(schema.replace('assets_json TEXT NOT NULL', 'assets_json TEXT'))
        self.old('/', assets=None)
        def interrupt(*args):
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt), redirect_stdout(io.StringIO()):
            web.execute_round(self.db,11,1,requester=interrupt)
        self.assertEqual(self.run_round({}), [])
        self.assertFalse(web.has_more(self.db,11))
        self.assertEqual(self.db.execute('SELECT created_at FROM pm_http_discovery').fetchone()[0],'before')

    def test_refresh_failure_stops_round_and_is_not_retried(self):
        self.old('/'); self.old('/other')
        with redirect_stdout(io.StringIO()):
            result = web.execute_round(self.db,11,2,requester=lambda *a: (_ for _ in ()).throw(ValueError('blocked')))
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]['status'],'blocked')
        self.assertNotIn(('http',TARGET,80,'/'),web._candidates(self.db,11,TARGET,[TARGET]))

    def test_refresh_limits_and_total_budget(self):
        for i in range(6):
            self.old('/page'+str(i))
        self.old('/')
        with patch.object(web,'MAX_TOTAL',8):
            self.run_round({'/page0':response(''),'/page1':response('')})
            self.assertEqual(len(self.calls),1)
            self.assertFalse(web.has_more(self.db,11))
        with patch.object(web,'MAX_METADATA_REFRESH',1):
            self.assertEqual(self.run_round({}), [])

    def test_metadata_and_literal_counts_are_bounded(self):
        source = ';'.join(f'fetch("/api/{i}")' for i in range(100))
        self.assertEqual(len(app.references(source)),16)
        self.assertEqual(app.references(' '*app.MAX_SOURCE + 'fetch("/beyond")'), [])

    def test_inline_script_collection_stops_at_end_tag(self):
        parser = web.PageMetadata()
        parser.feed('<script>fetch("/real")</script><div>fetch("/fake")</div>'
                    '<script type="application/json">{"url":"/not-code"}</script>')
        self.assertEqual(parser.script_blocks, ['fetch("/real")'])

    def test_static_budget_also_applies_to_fetch_references(self):
        pages = {'/': response('<script src="/app.js"></script>'),
                 '/app.js': response('import("./child.js");fetch("/another.js");fetch("/api/info");','text/javascript'),
                 '/api/info': response('{}','application/json')}
        with patch.object(web,'MAX_STATIC_TOTAL',1):
            for _ in range(4):
                self.run_round(pages)
            self.assertFalse(web.has_more(self.db,11))
        self.assertEqual(set(self.calls),set(pages))

    def test_bare_module_specifiers_are_not_guessed(self):
        refs = web.script_references('import "framework.js"; import("./observed.js");',
                                     'http://10.0.0.1/js/app.js', TARGET)
        self.assertEqual([r['path'] for r in refs], ['/js/observed.js'])

    def test_explicit_ext_ajax_get_is_supported_without_params_or_auth(self):
        refs = web.script_references('''
            Ext.Ajax.request({url:'/index.php/info',method:'GET'});
            Ext.Ajax.request({'method':'GET','url':'/index.php/status'});
            Ext.Ajax.request({url:'/index.php/submit',method:'POST'});
            Ext.Ajax.request({url:'/with-params',method:'GET',params:{password:secret}});
            Ext.Ajax.request({url:'/dynamic/'+name,method:'GET'});
            Ext.Ajax.request({url:'/default-method'});
        ''', 'http://10.0.0.1/js/app.js', TARGET)
        eligible = {r['path'] for r in refs if r['eligible']}
        self.assertEqual(eligible, {'/index.php/info','/index.php/status'})
        self.assertFalse(next(r for r in refs if r['path']=='/index.php/submit')['eligible'])
        self.assertNotIn('password',json.dumps(refs))

if __name__ == '__main__':
    unittest.main(verbosity=2)
