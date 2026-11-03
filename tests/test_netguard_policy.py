import importlib.util
from pathlib import Path
import unittest

SRC = Path(__file__).resolve().parents[1] / 'executor/netguard_root.py'
spec = importlib.util.spec_from_file_location('netguard_root', SRC)
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)

class NetGuardTests(unittest.TestCase):
    def test_narrow_scopes_only(self):
        self.assertEqual(broker.allow_networks(['10.10.0.0/16']), ['10.10.0.0/16'])
        for cidr in ('0.0.0.0/0', '127.0.0.0/8', '192.0.2.1/32'):
            with self.assertRaises(ValueError):
                broker.allow_networks([cidr])

    def test_cross_scope_blocked(self):
        self.assertEqual(broker.check_target('10.10.5.4', ['10.10.0.0/16']), '10.10.5.4')
        for addr in ('8.8.8.8', '127.0.0.1', '192.0.2.10'):
            with self.assertRaises(ValueError):
                broker.check_target(addr, ['10.10.0.0/16'])

    def test_restricted_tool_arguments(self):
        self.assertIn('-sV', broker.tool_args('service_versions','10.10.1.5','80','80','http'))
        with self.assertRaises(ValueError):
            broker.tool_args('service_versions','10.10.1.5','80','80;uname','http')
        with self.assertRaises(ValueError):
            broker.tool_args('arbitrary_command','10.10.1.5','80','80','http')

    def test_firewall_fail_closed(self):
        v = broker.task_values(9)
        rules = broker.filter_rules(v, ['10.10.0.0/16'], 'tun0')
        self.assertIn('oifname "tun0" accept', rules)
        self.assertIn('iifname "pmh9" counter drop', rules)
        self.assertIn('oifname "pmh9" counter drop', rules)
        self.assertNotIn('flush ruleset', rules)
        self.assertNotIn('10.10.0.0/16 accept\n', rules.replace('oifname "tun0"', ''))

    def test_non_root_process(self):
        args = broker.isolated_command('pmns9', 'lucky', 1000, 1000, ['/usr/bin/curl'])
        self.assertIn('--reuid', args)
        self.assertIn('--bounding-set=-all', args)
        self.assertIn('--share-net', args)

if __name__ == '__main__': unittest.main(verbosity=2)
