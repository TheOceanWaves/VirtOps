import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'skill/windows-vm-sandbox/scripts/configure.py'
SPEC = importlib.util.spec_from_file_location('virtops_configure', SCRIPT)
configure = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(configure)


class ConfigureTests(unittest.TestCase):
    def profile(self, root):
        return {'schema_version': 1, 'name': 'alpha-vm', 'uuid': '11111111-1111-4111-8111-111111111111',
                'root': root.as_posix(), 'host_root': root.parent.as_posix(),
                'ssh': {'host': 'host', 'user': 'root'},
                'network': {'bridge': 'vopsbr0', 'subnet': '172.31.40.0/30', 'bridge_ip': '172.31.40.1', 'guest_ip': '172.31.40.2', 'publish_ip': '192.0.2.10', 'client_cidr': '192.0.2.0/24', 'rdp_port': 23389, 'winrm_port': 25986},
                'windows': {'computer_name': 'ALPHA-VM', 'admin_user': 'alice'},
                'credentials': {'mode': 'existing'}, 'gpu': {}, 'media': {},
                'resources': {'memory_gib': 8, 'host_limit_gib': 10, 'vcpus': 4, 'storage_gib': 64, 'cpu_set': '0-3'},
                'limits': {'root_free_gib': 16, 'start_free_gib': 12, 'resume_free_gib': 12, 'watch_free_gib': 8}}

    def test_dry_run_does_not_invoke_ssh(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'p.json'; data = self.profile(Path('/srv/alpha-vm')); path.write_text(json.dumps(data), encoding='utf-8')
            args = mock.Mock(desired_profile=None, memory_gib=16, vcpus=8, host_limit_gib=18, cpu_set='0-3,4-7', start_free_gib=20)
            desired = configure.desired_profile(data, args)
            self.assertEqual(desired['resources']['memory_gib'], 16)
            self.assertFalse(mock.Mock().called)

    def test_resource_only_change_rejects_identity_change(self):
        data = self.profile(Path('/srv/alpha-vm'))
        candidate = dict(data); candidate['name'] = 'other-vm'; candidate['windows'] = dict(data['windows']); candidate['windows']['computer_name'] = 'OTHER-VM'
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'desired.json'; p.write_text(json.dumps(candidate), encoding='utf-8')
            args = mock.Mock(desired_profile=p, memory_gib=None, vcpus=None, host_limit_gib=None, cpu_set=None, start_free_gib=None)
            with self.assertRaisesRegex(ValueError, 'resources only'):
                configure.desired_profile(data, args)

    def test_remote_requires_stop_before_apply(self):
        data = self.profile(Path('/srv/alpha-vm')); desired = json.loads(json.dumps(data)); desired['resources']['memory_gib'] = 16
        xml = '<domain><uuid>11111111-1111-4111-8111-111111111111</uuid><memory unit="KiB">8388608</memory><currentMemory unit="KiB">8388608</currentMemory><vcpu>4</vcpu><devices><disk><source file="/srv/alpha-vm/vol/current.qcow2"/></disk></devices></domain>'
        remote_spec = importlib.util.spec_from_file_location('virtops_configure_remote', ROOT / 'skill/windows-vm-sandbox/scripts/configure_remote.py')
        remote = importlib.util.module_from_spec(remote_spec); assert remote_spec and remote_spec.loader; remote_spec.loader.exec_module(remote)
        with mock.patch.object(remote, 'verify_identity', return_value=(mock.Mock(), 'running')), mock.patch.object(remote, 'host_admission'):
            with self.assertRaisesRegex(RuntimeError, 'requires_stop'):
                remote.configure(data, desired, apply=True, stop=False)

    def test_actual_ssh_payload_compiles_and_has_no_file_dependency(self):
        data=self.profile(Path('/srv/alpha-vm'))
        def execute(argv,**kwargs):
            self.assertEqual(argv[-1],'-')
            compile(kwargs['input'],'remote-configure','exec')
            return SimpleNamespace(stdout='',stderr='',returncode=0)
        with mock.patch.object(configure.subprocess,'run',side_effect=execute):
            self.assertEqual(configure.invoke(data,data,apply=False,stop=False,restart=False),0)


if __name__ == '__main__':
    unittest.main()
