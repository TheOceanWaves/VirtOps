from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / 'skill/windows-vm-sandbox/assets/runtime/instance_registry.py'


def load_registry():
    spec = importlib.util.spec_from_file_location('virtops_instance_registry_test', REGISTRY_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def profile(root: Path, *, name='alpha-vm', uuid='11111111-1111-4111-8111-111111111111',
            subnet='172.31.40.0/30', rdp=23389, winrm=25986):
    return {
        'host_root': str(root), 'name': name, 'uuid': uuid,
        'root': str(root / name),
        'owner': 'alice', 'purpose': 'coding',
        'network': {'bridge': 'vopsbr0', 'subnet': subnet,
                    'publish_ip': '192.168.50.10', 'rdp_port': rdp,
                    'winrm_port': winrm},
        'windows': {'admin_user': 'alice'},
        'resources': {'memory_gib': 16, 'host_limit_gib': 20,
                      'vcpus': 4, 'storage_gib': 80, 'cpu_set': '0-3'},
        'credentials': {'secret_file': '/root/private/alpha.json'},
    }


class RegistryTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0,
                         'requires POSIX ownership and mode checks')
    def test_reservation_rejects_writable_existing_host_ancestor(self):
        registry = load_registry()
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            host = Path(temp) / 'host'
            host.mkdir()
            host.chmod(0o777)
            try:
                with self.assertRaises(ValueError):
                    registry.reserve(profile(host / 'instances'))
            finally:
                host.chmod(0o755)

    def test_reservation_is_atomic_and_contains_no_password(self):
        registry = load_registry()
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            root = Path(temp)
            item = registry.reserve(profile(root))
            self.assertEqual(registry.reserve(profile(root)), item)
            self.assertEqual(item['name'], 'alpha-vm')
            stored = root / 'registry/alpha-vm.json'
            self.assertTrue(stored.is_file())
            text = stored.read_text(encoding='utf-8')
            self.assertNotIn('password', text.lower())
            self.assertIn(registry.list_entries(root)[0]['runtime_state'], {'unknown', 'undefined'})

    def test_conflicts_cover_name_uuid_root_subnet_and_global_ports(self):
        registry = load_registry()
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            root = Path(temp)
            registry.reserve(profile(root))
            shared_ip = profile(root, name='beta-vm', uuid='22222222-2222-4222-8222-222222222222',
                                subnet='172.31.41.0/30', rdp=23390, winrm=25990)
            shared_ip['network']['bridge'] = 'vopsbr1'
            registry.reserve(shared_ip)
            cases = [
                profile(root, name='alpha-vm', rdp=23999),
                profile(root, name='gamma-vm', uuid='11111111-1111-4111-8111-111111111111', subnet='172.31.42.0/30', rdp=23391, winrm=25991),
                profile(root, name='delta-vm', uuid='33333333-3333-4333-8333-333333333333', subnet='172.31.41.0/30', rdp=23392, winrm=25992),
                profile(root, name='epsilon-vm', uuid='44444444-4444-4444-8444-444444444444', subnet='172.31.43.0/30', rdp=23390, winrm=25993),
            ]
            for candidate in cases:
                with self.assertRaises(ValueError):
                    registry.reserve(candidate)

    def test_failed_storage_does_not_release_reservation(self):
        registry = load_registry()
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            root = Path(temp)
            registry.claim(profile(root))
            with self.assertRaises(ValueError):
                registry.claim(profile(root, name='beta-vm', uuid='22222222-2222-4222-8222-222222222222',
                                       subnet='172.31.41.0/30', rdp=23390, winrm=25990))
            self.assertTrue((root / 'registry/alpha-vm.json').exists())

    def test_update_owner_changes_only_owner_fields(self):
        registry = load_registry()
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            root = Path(temp)
            original = profile(root)
            registry.reserve(original)
            changed = profile(root)
            changed['labels'] = {'owner': 'bob', 'purpose': 'graphics'}
            changed['windows']['admin_user'] = 'bobadmin'
            updated = registry.update_owner(changed)
            self.assertEqual(updated['owner'], 'bob')
            self.assertEqual(updated['purpose'], 'graphics')
            self.assertEqual(updated['admin_user'], 'bobadmin')
            changed['resources']['memory_gib'] = 32
            with self.assertRaises(ValueError):
                registry.update_owner(changed)


if __name__ == '__main__':
    unittest.main()
