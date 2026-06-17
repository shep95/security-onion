"""Theory 7: Security regression tests for elite hardening."""

import importlib.util
import os
import sys
import unittest


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', '..'))


def repo_path(*parts):
    return os.path.normpath(os.path.join(ROOT, *parts))


class TestAnalyzerSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        helpers_path = repo_path('salt', 'sensoroni', 'files', 'analyzers', 'helpers.py')
        security_path = repo_path('salt', 'common', 'tools', 'sbin', 'so_security_utils.py')
        if os.path.isfile(helpers_path):
            cls.helpers = load_module('helpers', helpers_path)
        if os.path.isfile(security_path):
            cls.security = load_module('so_security_utils', security_path)

    def test_parse_artifact_valid(self):
        if not hasattr(self, 'helpers'):
            self.skipTest('helpers not found')
        data = self.helpers.parseArtifact('{"artifactType":"ip","value":"1.2.3.4"}')
        self.assertEqual(data['value'], '1.2.3.4')

    def test_parse_artifact_oversized(self):
        if not hasattr(self, 'helpers'):
            self.skipTest('helpers not found')
        blob = '{"artifactType":"ip","value":"' + ('a' * 5000) + '"}'
        with self.assertRaises(SystemExit):
            self.helpers.parseArtifact(blob)

    def test_escape_wildcard(self):
        if not hasattr(self, 'helpers'):
            self.skipTest('helpers not found')
        self.assertIn('\\*', self.helpers.escapeWildcard('*'))

    def test_vm_config_valid(self):
        if not hasattr(self, 'security'):
            self.skipTest('security utils not found')
        ok, err = self.security.validate_vm_config({
            'hostname': 'node1', 'role': 'sensor', 'network_mode': 'dhcp4', 'cpu': 4, 'memory': 16,
        })
        self.assertTrue(ok, err)

    def test_vm_config_invalid_role(self):
        if not hasattr(self, 'security'):
            self.skipTest('security utils not found')
        ok, _ = self.security.validate_vm_config({'hostname': 'node1', 'role': 'evil'})
        self.assertFalse(ok)

    def test_cmd_allowlist(self):
        if not hasattr(self, 'security'):
            self.skipTest('security utils not found')
        self.assertTrue(self.security.is_allowed_cmd(
            '/usr/sbin/so-yaml.py replace /opt/so/saltstack/local/pillar/kafka/soc_kafka.sls kafka.enabled True'))
        self.assertFalse(self.security.is_allowed_cmd('rm -rf /'))


if __name__ == '__main__':
    unittest.main()
