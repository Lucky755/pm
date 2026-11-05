"""Offline checks for flag provenance and opt-in matching."""

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from orchestrator import flag_verify as flags
from orchestrator import attack_loop


class FlagExtensionsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name)
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.db.execute('CREATE TABLE tasks(id INTEGER PRIMARY KEY,target TEXT)')
        self.db.execute("INSERT INTO tasks VALUES(1,'10.10.10.10')")
        flags.ensure_schema(self.db)
        self.patcher = patch.object(flags, 'CAPABILITY_LOG', self.log)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def record(self, tool, output, provenance=None, argv=None):
        item = {'tool': tool, 'task_id': 1, 'result': {'stdout': output}, 'argv': argv or []}
        if provenance is not None:
            item['provenance'] = provenance
        with (self.log / 'task_1.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(item) + '\n')

    def state(self, value):
        result = flags.scan(1, db=self.db)
        return next((item for item in result['confirmed'] + result['candidates']
                     if item['value'] == value), None)

    def test_local_poc_and_unknown_are_not_confirmed(self):
        value = 'THM{local_file_flag}'
        self.record('poc_run', value, 'local')
        self.record('net_exec', value)
        state = self.state(value)
        self.assertEqual(state['status'], 'candidate')
        self.assertTrue(state['local_only'])
        self.assertEqual(state['evidence_source'], 'local')
        self.assertEqual(len(state['local_hits']), 2)

    def test_two_unverified_network_outputs_do_not_confirm_keyed_uuid(self):
        value = '557f6da6-dd18-4421-8cbd-b8197fba9d2b'
        self.record('net_exec', '{"flag":"' + value + '"}', 'network', ['/usr/bin/curl'])
        first = self.state(value)
        self.assertEqual(first['status'], 'candidate')
        self.assertEqual(first['matched_by'], 'kv')
        self.record('session', 'FLAG=' + value, 'network', ['/usr/bin/nc'])
        self.assertEqual(self.state(value)['status'], 'candidate')

    def test_agent_claim_for_keyed_value_uses_task_patterns(self):
        value = '557f6da6-dd18-4421-8cbd-b8197fba9d2b'
        self.db.execute('CREATE TABLE pm_agent_action_reports('
                        'task_id INTEGER,role TEXT,iteration INTEGER,report_json TEXT)')
        self.db.execute('INSERT INTO pm_agent_action_reports VALUES(?,?,?,?)',
                        (1, 'verify', 1, json.dumps({'flags': [{'value': value}]})))
        self.assertEqual(self.state(value)['status'], 'candidate')

    def test_shapes_are_opt_in(self):
        value = '557f6da6-dd18-4421-8cbd-b8197fba9d2b'
        self.record('net_exec', 'session ' + value, 'network')
        self.assertIsNone(self.state(value))
        flags.save_patterns(self.db, 1, shapes=['uuid'])
        self.assertEqual(self.state(value)['status'], 'candidate')

    def test_exact_absent_and_argv_self_generated(self):
        flags.save_patterns(self.db, 1, expects=['plain-expected-value'])
        self.assertEqual(self.state('plain-expected-value')['status'], 'candidate')
        self.record('net_exec', 'flag: plain-expected-value', 'network',
                    ['/usr/bin/printf', 'plain-expected-value'])
        state = self.state('plain-expected-value')
        self.assertEqual(state['status'], 'candidate')
        self.assertEqual(state['raw_hits'], 0)
        self.assertTrue(state['self_generated'])

    def test_default_and_custom_forms(self):
        value = 'a1b2c3d4e5f60718293a4b5c6d7e8f90'
        flags.save_patterns(self.db, 1, shapes=['hex32'])
        self.record('net_exec', value + ' flag{lowercase_flag} THM{known_flag}', 'network')
        for item in (value, 'flag{lowercase_flag}', 'THM{known_flag}'):
            self.assertEqual(self.state(item)['status'], 'candidate')

    def test_unreachable_uses_structured_outcome(self):
        with patch.object(attack_loop.agent_actions, 'CAPABILITY_LOG', self.log):
            self.record('net_exec', 'локальная ошибка без слова timeout', 'network')
            self.assertFalse(attack_loop.network_unreachable_since(1, 0))
            (self.log / 'task_1.jsonl').write_text(json.dumps({
                'tool': 'net_exec', 'result': {'status': 'timeout', 'exit_code': 124,
                                               'stderr': 'любой текст'}}) + '\n')
            self.assertTrue(attack_loop.network_unreachable_since(1, 0))


if __name__ == '__main__':
    unittest.main()
