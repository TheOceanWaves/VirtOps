from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skill/windows-vm-sandbox/scripts'
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def load(name: str):
    path = SCRIPTS / f'{name}.py'
    spec = importlib.util.spec_from_file_location(f'virtops_{name}_logs_test', path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


host = load('host')
remote = load('host_remote')


PROFILE = {
    'name': 'alpha-vm', 'uuid': '11111111-1111-4111-8111-111111111111',
    'root': '/srv/alpha-vm', 'ssh': {'host': 'host', 'user': 'root'},
    'network': {'rdp_port': 23389, 'winrm_port': 25986},
}


class HostLogEntrypointTests(unittest.TestCase):
    def invoke(self, argv):
        completed = SimpleNamespace(stdout='', stderr='', returncode=0)
        with mock.patch.object(host, 'load', return_value=PROFILE), \
             mock.patch.object(host.subprocess, 'run', return_value=completed) as run, \
             mock.patch.object(sys, 'argv', ['host.py', *argv]):
            code = host.main()
        return code, run.call_args.kwargs['input']

    def decode_request(self, source):
        marker = 'REQUEST=json.loads(base64.b64decode('
        encoded = source.split(marker, 1)[1].split('))', 1)[0]
        return json.loads(base64.b64decode(eval(encoded)).decode())

    def test_logs_network_only_is_forwarded(self):
        code, source = self.invoke(['logs', '--profile', 'profile.json', '--network-only'])
        self.assertEqual(code, 0)
        request = self.decode_request(source)
        self.assertTrue(request['network_only'])

    def test_flags_are_scoped_to_their_actions(self):
        with mock.patch.object(host, 'load', return_value=PROFILE), \
             mock.patch.object(sys, 'argv', ['host.py', 'status', '--profile', 'profile.json', '--network-only']):
            self.assertEqual(host.main(), 2)


class HostRemoteLogTests(unittest.TestCase):
    def test_network_only_removes_lifecycle_events(self):
        result = SimpleNamespace(stdout=json.dumps({
            'events': [{'event': 'start'}],
            'network_path': '/srv/alpha-vm/vol/logs/network-blocks.jsonl',
            'network_samples': [{'route': 'egress', 'ip': {'dst': '203.0.113.10'}}],
        }))
        self.assertEqual(remote.network_only_logs(result), {
            'network_samples': [{'route': 'egress', 'ip': {'dst': '203.0.113.10'}}],
        })



if __name__ == '__main__':
    unittest.main()
