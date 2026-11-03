"""Offline regression tests: no real VPN, sudo, API or target traffic."""
import importlib.util
import io
import os
import sqlite3
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

pm = load('pm_v2_test', BASE / 'pm.py')
broker = load('broker_v2_test', BASE / 'executor/netguard_root.py')

class ConsoleV2Tests(unittest.TestCase):
    def test_key_planner_inherited_fd_once_without_printing_secret(self):
        import shutil
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            (project / 'orchestrator').mkdir()
            (project / 'runtime').mkdir()
            shutil.copy(BASE / 'runtime/planner_entry.py',
                        project / 'runtime/planner_entry.py')
            planner = project / 'orchestrator/planner.py'
            planner.write_text(
                "import getpass, json\n"
                "key = getpass.getpass('Experiential API key: ')\n"
                "assert key == 'secret_for_unit_test'\n"
                "print('Task ID: 12', flush=True)\n"
                "print(json.dumps({'tasks':[{'agent':'recon','instruction':'inspect'}]}), flush=True)\n"
            )
            out = io.StringIO()
            with patch.object(pm, 'ROOT', project), redirect_stdout(out):
                task_id, plan = pm.read_planner_stream([sys.executable, str(planner)],
                                                       api_key='secret_for_unit_test')
            self.assertEqual(task_id, 12)
            self.assertEqual(plan['tasks'][0]['agent'], 'recon')
            self.assertNotIn('secret_for_unit_test', out.getvalue())

    def test_agent_key_is_reused_without_prompts_and_restored(self):
        old = pm.getpass.getpass
        with pm.session_getpass('some_test_key'):
            self.assertEqual(pm.getpass.getpass('prompt'), 'some_test_key')
        self.assertIs(pm.getpass.getpass, old)

    def test_session_api_key_is_asked_once(self):
        args = types.SimpleNamespace()
        with patch.object(pm.getpass, 'getpass', return_value='fakeKey') as prompt:
            self.assertEqual(pm.session_api_key(args), 'fakeKey')
            self.assertEqual(pm.session_api_key(args), 'fakeKey')
        self.assertEqual(prompt.call_count, 1)

    def test_empty_flags_no_cleanup(self):
        db = sqlite3.connect(':memory:')
        self.assertFalse(pm.flags_confirmed_by_evidence(db, 10))
        out = io.StringIO()
        with redirect_stdout(out):
            pm.offer_cleanup_if_verified(db, 10, {})
        self.assertIn('не подтверждены', out.getvalue())
        db.close()

    def test_only_confirmed_user_root_evidence_enables_cleanup(self):
        db = sqlite3.connect(':memory:')
        db.execute('''CREATE TABLE pm_verified_flags (
            task_id INTEGER, flag_kind TEXT, verified INTEGER, evidence_id TEXT)''')
        db.execute("INSERT INTO pm_verified_flags VALUES (10,'user',1,'evidence-1')")
        db.execute("INSERT INTO pm_verified_flags VALUES (10,'root',0,'evidence-2')")
        self.assertFalse(pm.flags_confirmed_by_evidence(db, 10))
        db.execute("UPDATE pm_verified_flags SET verified=1 WHERE flag_kind='root'")
        self.assertTrue(pm.flags_confirmed_by_evidence(db, 10))
        with patch('builtins.input', return_value='no'), redirect_stdout(io.StringIO()):
            with patch.object(pm, 'op_close') as close:
                pm.offer_cleanup_if_verified(db, 10, {})
                close.assert_not_called()
        with patch('builtins.input', return_value='yes'), redirect_stdout(io.StringIO()):
            with patch.object(pm, 'op_close') as close:
                pm.offer_cleanup_if_verified(db, 10, {})
                self.assertEqual(close.call_count, 1)
        db.close()

    def test_hostnames_reject_unsafe_aliases(self):
        self.assertEqual(pm.validate_hostnames('mbilling.htb, admin.mbilling.htb'),
                         ['mbilling.htb', 'admin.mbilling.htb'])
        for invalid in ['localhost', '127.0.0.1', 'foo:80', '../wrong',
                        'foo.com,foo.com', 'hello bar', '-bad.site', '']:
            if invalid == '':
                self.assertEqual(pm.validate_hostnames(invalid), [])
                continue
            with self.assertRaises(pm.OperatorError): pm.validate_hostnames(invalid)
        self.assertEqual(broker.validate_hostnames(['www.lab.test']), ['www.lab.test'])
        for invalid in [['localhost'], ['127.0.0.1'], ['bad/name'],
                        ['x']*13, ['foo.local','foo.local']]:
            with self.assertRaises(ValueError): broker.validate_hostnames(invalid)

    def test_bwrap_explicit_hosts_file_mount(self):
        args = broker.isolated_command('pmns10', 'lucky', 1000, 1000, ['/usr/bin/curl'])
        i = args.index('/etc/hosts')
        self.assertEqual(args[i-1:i+2], ['--ro-bind-try','/etc/hosts','/etc/hosts'])

    def test_root_owned_task_hosts_created_and_scoped(self):
        # The production broker intentionally requires root-owned /etc/netns.
        # TemporaryDirectory belongs to the test runner (e.g. user lucky),
        # so simulate *only* the ownership metadata for files in this fixture.
        # Never weaken the production root-ownership check to make this pass.
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            v = {'name': 'pmns10'}
            config = {'task_id': 10, 'name': 'pmns10',
                      'uid': 1000, 'allowed': ['10.10.10.161/32']}
            output = io.StringIO()
            real_stat = Path.stat

            def root_owned_fixture_stat(path, *args, **kwargs):
                result = real_stat(path, *args, **kwargs)
                if path == base or base in path.parents:
                    fields = list(result)
                    fields[4] = 0  # st_uid: simulate root ownership
                    return os.stat_result(fields)
                return result

            with patch.object(broker, 'HOSTS_BASE', base), \
                 patch.object(Path, 'stat', root_owned_fixture_stat), \
                 patch.object(broker, 'owned_config', return_value=(v, config)), \
                 patch.object(broker, 'ensure_root'), \
                 patch.object(broker, 'replace_config') as store, \
                 redirect_stdout(output):
                broker.set_hostnames(10, ['mbilling.lab.test'])
            hosts = base / 'pmns10/hosts'
            self.assertIn('10.10.10.161 mbilling.lab.test', hosts.read_text())
            self.assertNotIn('8.8.8.8', hosts.read_text())
            self.assertTrue(store.call_args.args[1]['hosts_managed'])
            self.assertEqual(store.call_args.args[1]['hostnames'], ['mbilling.lab.test'])

    def test_untrusted_hosts_directory_is_rejected(self):
        # A normal user's temporary directory is not a safe root-managed /etc/netns.
        # The test must retain this fail-closed behavior.
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            v = {'name': 'pmns10'}
            config = {'task_id': 10, 'name': 'pmns10',
                      'uid': 1000, 'allowed': ['10.10.10.161/32']}
            # Explicitly make this test's directory unsafe, even if the
            # offline test suite itself happens to be run as root.
            base.chmod(0o777)
            with patch.object(broker, 'HOSTS_BASE', base), \
                 patch.object(broker, 'owned_config', return_value=(v, config)), \
                 patch.object(broker, 'ensure_root'):
                with self.assertRaisesRegex(ValueError, 'Unsafe netns hosts directory'):
                    broker.set_hostnames(10, ['mbilling.lab.test'])

    def test_cleanup_no_means_no_teardown(self):
        db = sqlite3.connect(':memory:')
        db.execute('CREATE TABLE tasks (id INTEGER PRIMARY KEY, target TEXT)')
        db.execute("INSERT INTO tasks VALUES (10,'10.10.10.161')")
        db.execute('''CREATE TABLE pm_operator_approvals
            (task_id INTEGER, target TEXT, allowed TEXT, egress TEXT, approved_at TEXT, closed_at TEXT)''')
        with patch.object(pm, 'connect', return_value=db), \
             patch('builtins.input', return_value='no'), \
             patch.object(pm, 'sudo_checked') as sudo, \
             redirect_stdout(io.StringIO()):
            pm.op_close(types.SimpleNamespace(task_id=10))
            sudo.assert_not_called()
        db.close()

if __name__ == '__main__': unittest.main(verbosity=2)
