import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / 'executor/netguard_root.py'
spec = importlib.util.spec_from_file_location('netguard_root', SRC)
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)

class DockerFirewallTests(unittest.TestCase):
    def setUp(self):
        self.v = broker.task_values(10)
        self.config = {'task_id': 10, 'name': 'pmns10',
                       'allowed': ['10.10.10.161/32'], 'egress': 'tun0',
                       'peer_ip': '10.253.10.2'}

    def test_rules_are_exactly_scoped(self):
        forward, reverse = broker.docker_forward_rules(self.v, self.config)
        self.assertEqual(forward, ['-i', 'pmh10', '-o', 'tun0', '-s', '10.253.10.2/32',
                                   '-d', '10.10.10.161/32', '-j', 'ACCEPT'])
        self.assertEqual(reverse, ['-i', 'tun0', '-o', 'pmh10', '-s', '10.10.10.161/32',
                                   '-d', '10.253.10.2/32', '-m', 'conntrack', '--ctstate',
                                   'ESTABLISHED,RELATED', '-j', 'ACCEPT'])

    def test_reject_auto_egress_and_broad_scope(self):
        for allowed, egress in [(['10.0.0.0/8'], 'tun0'),
                                (['10.1.1.1/32','10.1.1.2/32'], 'tun0'),
                                (['10.1.1.1/32'], 'auto')]:
            with self.assertRaises(ValueError):
                broker.docker_forward_rules(self.v, {'allowed': allowed, 'egress': egress})

    def test_docker_drop_detected(self):
        response = type('Response', (), {'stdout': '-P FORWARD DROP\n-A FORWARD -j DOCKER-USER\n'})()
        with patch.object(broker, 'cmd', return_value=response):
            self.assertTrue(broker.docker_policy_drops_forward())
        response.stdout = '-P FORWARD ACCEPT\n'
        with patch.object(broker, 'cmd', return_value=response):
            self.assertFalse(broker.docker_policy_drops_forward())

    def test_adoption_does_not_duplicate_rules(self):
        rules = broker.docker_forward_rules(self.v, self.config)
        with patch.object(broker, 'docker_chain_exists', return_value=True), \
             patch.object(broker, 'docker_rule_exists', return_value=True), \
             patch.object(broker, 'cmd') as command:
            inserted = broker.add_docker_rules(rules, adopt_existing=True)
            self.assertEqual(inserted, [])
            command.assert_not_called()

    def test_fails_if_existing_not_explicitly_adopted(self):
        rules = broker.docker_forward_rules(self.v, self.config)
        with patch.object(broker, 'docker_chain_exists', return_value=True), \
             patch.object(broker, 'docker_rule_exists', return_value=True):
            with self.assertRaises(ValueError):
                broker.add_docker_rules(rules)

    def test_forward_rule_installation_and_rollback(self):
        rules = broker.docker_forward_rules(self.v, self.config)
        with patch.object(broker, 'docker_chain_exists', return_value=True), \
             patch.object(broker, 'docker_rule_exists', return_value=False), \
             patch.object(broker, 'cmd') as command:
            self.assertEqual(broker.add_docker_rules(rules), rules)
            self.assertEqual(command.call_count, 2)
            self.assertIn('DOCKER-USER', command.call_args.args)

    def test_empty_chain_fails_closed(self):
        with patch.object(broker, 'docker_chain_exists', return_value=False):
            with self.assertRaises(RuntimeError):
                broker.add_docker_rules(broker.docker_forward_rules(self.v, self.config))

if __name__ == '__main__':
    unittest.main(verbosity=2)
