"""Public MCP repeat policy, real temporary SQLite/logs; only executor replaced."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from tests import test_coordinated_attack as fixture
from orchestrator import agent_actions, task_memory


class OperationRepeatPolicyTests(unittest.TestCase):
    def setUp(self):
        self.case = fixture.CoordinatorTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        spec = importlib.util.spec_from_file_location(
            'repeat_policy_mcp', Path(__file__).resolve().parents[1] / 'mcp/server.py')
        self.server = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.server)
        for replacement in (
            patch.object(self.server, 'ASSET_DB', self.case.database),
            patch.object(self.server, 'CAPABILITY_LOG', agent_actions.CAPABILITY_LOG),
            patch.object(self.server, 'POC_ROOT', self.case.root / 'pocs'),
            patch.object(self.server, 'ROOT', self.case.root),
        ):
            replacement.start()
            self.addCleanup(replacement.stop)

    def result(self, **extra):
        payload = {'task_id': 11, 'target': '10.0.0.1', 'status': 'completed',
                   'exit_code': 0, 'stdout': 'saved response', **extra}
        return subprocess.CompletedProcess([], 0, json.dumps(payload), '')

    def records(self):
        return [json.loads(line) for line in
                (agent_actions.CAPABILITY_LOG / 'task_11.jsonl').read_text().splitlines()]

    def expire(self):
        with self.case.connect() as db:
            db.execute("UPDATE pm_memory_operations SET created_at='2000-01-01T00:00:00+00:00'")

    def net_exec(self, argv):
        return json.loads(self.server.pm_net_exec(11, '10.0.0.1', json.dumps(argv)))

    def write_poc(self):
        created = json.loads(self.server.pm_write_poc(11, 'check.sh', '#!/bin/sh\nprintf test'))
        self.assertEqual(created['status'], 'completed')
        return created['path']

    def test_poc_timeout_blocks_repeat_without_claiming_network_contact(self):
        poc = self.write_poc()
        with patch.object(self.server.subprocess, 'run',
                          side_effect=subprocess.TimeoutExpired('offline executor', 60)) as execute:
            first = json.loads(self.server.pm_poc_run(11, '10.0.0.1', poc))
            self.expire()
            second = json.loads(self.server.pm_poc_run(11, '10.0.0.1', poc))
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(first['status'], 'timeout')
        self.assertEqual(second['reason'], 'previous_outcome_unknown')
        self.assertFalse(second['execution_started'])
        record = next(r for r in self.records() if r['tool'] == 'poc_run')
        self.assertEqual(record['provenance'], 'unknown')
        with self.case.connect() as db:
            operation = task_memory.rows(db, 'pm_memory_operations', 11)[0]
            self.assertEqual(operation['phase'], 'unknown')
            self.assertEqual(operation['outcome'], 'timeout')
            self.assertEqual(record['memory_operation_id'], operation['id'])

    def test_local_poc_result_does_not_grant_repeat_permission(self):
        poc = self.write_poc()
        with patch.object(self.server.subprocess, 'run', return_value=self.result(
                network_isolated=True, network_contact=False)) as execute:
            first = json.loads(self.server.pm_poc_run(11, '10.0.0.1', poc))
            self.expire()
            second = json.loads(self.server.pm_poc_run(11, '10.0.0.1', poc))
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(second['reason'], 'repeated_operation_without_new_conditions')
        self.assertEqual(next(r for r in self.records() if r['id'] == first['result_id'])['provenance'], 'local')

    def test_curl_mutations_cannot_be_repeated_by_expiring_ttl(self):
        cases = [
            ['-d', 'x'], ['-dx'], ['--data', 'x'], ['--data=x'],
            ['--data-raw', 'x'], ['--data-raw=x'],
            ['--data-binary', '@/work/body'], ['--data-binary=@/work/body'],
            ['--data-urlencode', 'x=y'], ['--data-urlencode=x=y'],
            ['-F', 'file=@/work/file'], ['-Ffile=@/work/file'],
            ['--form', 'file=@/work/file'], ['--form=file=@/work/file'],
            ['-X', 'DELETE'], ['-XDELETE'], ['--request', 'POST'], ['--request=POST'],
            ['-T', '/work/file'], ['-T/work/file'],
            ['--upload-file', '/work/file'], ['--upload-file=/work/file'],
        ]
        for index, flags in enumerate(cases):
            with self.subTest(flags=flags), patch.object(
                    self.server.subprocess, 'run', return_value=self.result()) as execute:
                argv = ['/usr/bin/curl', *flags, f'http://10.0.0.1/check/{index}']
                self.assertEqual(self.net_exec(argv)['status'], 'completed')
                self.expire()
                second = self.net_exec(argv)
                self.assertEqual(execute.call_count, 1)
                self.assertEqual(second['reason'], 'repeated_operation_without_new_conditions')

    def test_generic_exec_name_alone_does_not_allow_automatic_refresh(self):
        cases = [
            ['/usr/bin/curl', '--head', 'http://10.0.0.1/'],
            ['/usr/bin/curl', '-q', '--request=GET', 'http://10.0.0.1/'],
            ['/usr/bin/nmap', '--script', '/work/check.nse', '-p', '80', '10.0.0.1'],
            ['/work/poc/nmap', '-p', '80', '10.0.0.1'],
            ['/usr/bin/nmap', '-p', '80', '10.0.0.1', '10.0.0.2'],
        ]
        for argv in cases:
            with self.subTest(argv=argv), patch.object(
                    self.server.subprocess, 'run', return_value=self.result()) as execute:
                self.assertEqual(self.net_exec(argv)['status'], 'completed')
                self.expire()
                self.assertEqual(self.net_exec(argv)['status'], 'blocked')
                self.assertEqual(execute.call_count, 1)

    def test_callback_read_can_poll_updated_buffer_without_new_network_evidence(self):
        with patch.object(self.server.subprocess, 'run', side_effect=[
                self.result(stdout='first bytes'), self.result(stdout='first bytes\nnew bytes')]) as execute:
            first = json.loads(self.server.pm_callback(11, 'read'))
            second = json.loads(self.server.pm_callback(11, 'read'))
        self.assertEqual(execute.call_count, 2)
        self.assertEqual(first['stdout'], 'first bytes')
        self.assertEqual(second['stdout'], 'first bytes\nnew bytes')
        self.assertNotEqual(first['result_id'], second['result_id'])
        self.assertEqual([r['provenance'] for r in self.records()], ['local', 'local'])
        with self.case.connect() as db:
            checks = task_memory.source_state(db, 11, agent_actions.CAPABILITY_LOG / 'task_11.jsonl')['checks']
            self.assertFalse(any(check.get('provenance') == 'network' for check in checks.values()))

    def test_callback_buffer_read_timeout_can_be_retried(self):
        with patch.object(self.server.subprocess, 'run', side_effect=[
                subprocess.TimeoutExpired('offline buffer read', 60),
                self.result(stdout='late bytes')]) as execute:
            self.assertEqual(json.loads(self.server.pm_callback(11, 'read'))['status'], 'timeout')
            second = json.loads(self.server.pm_callback(11, 'read'))
            self.assertEqual(second['status'], 'completed')
            self.assertEqual(second['stdout'], 'late bytes')
        self.assertEqual(execute.call_count, 2)

    def test_callback_open_still_has_repeat_guard(self):
        with patch.object(self.server.subprocess, 'run', return_value=self.result()) as execute:
            self.assertEqual(json.loads(self.server.pm_callback(11, 'open', target='10.0.0.1'))['status'], 'completed')
            second = json.loads(self.server.pm_callback(11, 'open', target='10.0.0.1'))
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(second['kind'], 'repeat_guard')

    def test_session_read_and_list_remain_repeatable_local_reads(self):
        with patch.object(self.server.subprocess, 'run', return_value=self.result()) as execute:
            for action in ('read', 'list'):
                for _ in range(2):
                    result = json.loads(self.server.pm_session(11, action, session_id='abcd1234'))
                    self.assertEqual(result['status'], 'completed')
        self.assertEqual(execute.call_count, 4)
        self.assertEqual([r['provenance'] for r in self.records()], ['local'] * 4)

    def test_supported_tcp_check_refreshes_after_ttl_but_not_before(self):
        for ports in (['-p', '80'], ['-p22,80']):
            with self.subTest(ports=ports), patch.object(
                    self.server.subprocess, 'run', return_value=self.result()) as execute:
                argv = ['/usr/bin/nmap', *ports, '10.0.0.1']
                self.assertEqual(self.net_exec(argv)['status'], 'completed')
                self.assertEqual(self.net_exec(argv)['status'], 'blocked')
                self.expire()
                self.assertEqual(self.net_exec(argv)['status'], 'completed')
                self.assertEqual(execute.call_count, 2)

    def test_unknown_outcome_of_supported_read_probe_is_not_ttl_permission(self):
        argv = ['/usr/bin/nmap', '-p', '443', '10.0.0.1']
        with patch.object(self.server.subprocess, 'run',
                          side_effect=subprocess.TimeoutExpired('offline TCP probe', 60)) as execute:
            self.assertEqual(self.net_exec(argv)['status'], 'timeout')
            self.expire()
            second = self.net_exec(argv)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(second['reason'], 'previous_outcome_unknown')


if __name__ == '__main__':
    unittest.main()
