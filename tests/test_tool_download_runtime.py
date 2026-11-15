"""Real loopback HTTP/curl + registered MCP + temp broker receipts, no sudo/APT."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import unittest
from unittest.mock import patch

from tests import test_tool_requests as fixture
from executor import netguard_root as broker


class ToolDownloadRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.ToolAcquisitionTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        owner=self;self.paths=[];self.body=b"print('downloaded offline tool')\n"
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                owner.paths.append(self.path)
                if self.path=='/redirect':
                    self.send_response(302);self.send_header('Location','/not-authorized');self.end_headers();return
                self.send_response(200);self.send_header('Content-Length',str(len(owner.body)));self.end_headers();self.wfile.write(owner.body)
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        self.url=f'http://127.0.0.1:{server.server_port}'

    def test_explicit_source_download_keeps_query_and_reuses_installed_bytes(self):
        reply=self.case.request(source=self.url+'/tool.py?release=1',channel='kali_local',
            sha256=hashlib.sha256(self.body).hexdigest())
        self.assertEqual(self.paths,[]) # asking/approval planning performs no download
        result=self.case.approve(reply)
        self.assertEqual(result['status'],'completed',result)
        self.assertEqual(self.paths,['/tool.py?release=1'])
        self.assertEqual((self.case.workspace/'tools/offline-helper/helper.py').read_bytes(),self.body)
        self.case.call('pm_tool_acquire',request_id=result['id'])
        self.assertEqual(self.paths,['/tool.py?release=1'])

    def test_redirect_does_not_broaden_grant_and_failed_transfer_is_not_replayed(self):
        result=self.case.approve(self.case.request(source=self.url+'/redirect',channel='kali_local'))
        self.assertEqual(result['status'],'failed')
        self.assertEqual(result['receipt']['result']['reason_category'],'download_failed')
        self.assertEqual(self.paths,['/redirect'])
        self.case.call('pm_tool_acquire',request_id=result['id'])
        self.assertEqual(self.paths,['/redirect'])

    def test_public_download_cannot_resolve_to_lab_or_kali(self):
        with patch.object(broker.socket,'getaddrinfo',return_value=[(2,1,6,'',('10.0.0.1',443))]):
            with self.assertRaisesRegex(broker.ToolError,'outside the granted'):
                broker.tool_download('https://packages.example/tool','internet',self.case.config)
        self.assertEqual(self.paths,[])


if __name__=='__main__':unittest.main()
