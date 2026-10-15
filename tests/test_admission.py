from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'skill/windows-vm-sandbox/assets/runtime'


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


registry = load('admission_registry_test', RUNTIME / 'instance_registry.py')
admission = load('admission_test', RUNTIME / 'admission.py')


def vm(root: Path, name: str, *, host_limit=140, memory=128, number=1):
    return {
        'host_root': str(root), 'name': name,
        'uuid': f'11111111-1111-4111-8111-{number:012d}',
        'root': str(root / name),
        'labels': {'owner': 'test', 'purpose': 'admission'},
        'network': {'bridge': f'br{name}', 'subnet': f'172.31.{40 + number}.0/30',
                    'publish_ip': '192.168.50.5', 'rdp_port': 23000 + number,
                    'winrm_port': 24000 + number},
        'windows': {'admin_user': 'vmadmin'},
        'resources': {'memory_gib': memory, 'host_limit_gib': host_limit,
                      'vcpus': 4, 'storage_gib': 80, 'cpu_set': '0-3'},
        'limits': {'start_free_gib': 204},
    }


class AdmissionTests(unittest.TestCase):
    def test_two_128gib_guests_with_140gib_host_limits_are_rejected_on_256gib_host(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            root = Path(temp)
            existing = vm(root, 'alpha-vm', number=1)
            registry.reserve(existing)
            candidate = vm(root, 'beta-vm', number=2)
            with patch.object(admission, '_active_names', return_value=['alpha-vm']), \
                 patch.object(admission, '_mem_total', return_value=256 * admission.GIB):
                with self.assertRaises(RuntimeError):
                    admission.check(root, candidate)

    def test_paused_domain_is_counted_from_active_name_enumeration(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            root = Path(temp)
            existing = vm(root, 'paused-vm', number=1, host_limit=64, memory=56)
            registry.reserve(existing)
            candidate = vm(root, 'new-vm', number=2, host_limit=64, memory=56)
            with patch.object(admission, '_active_names', return_value=['paused-vm']), \
                 patch.object(admission, '_mem_total', return_value=512 * admission.GIB):
                result = admission.check(root, candidate)
            self.assertEqual(result['active_vm_count'], 1)
            self.assertEqual(result['active_vm_names'], ['paused-vm'])

    def test_unregistered_active_domain_is_counted(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            root = Path(temp)
            registry.registry_dir(root, create=True)
            candidate = vm(root, 'new-vm', number=1, host_limit=64, memory=56)
            with patch.object(admission, '_active_names', return_value=['manual-vm']), \
                 patch.object(admission, '_xml_ram', return_value=128 * admission.GIB), \
                 patch.object(admission, '_mem_total', return_value=512 * admission.GIB):
                result = admission.check(root, candidate)
            self.assertEqual(result['unregistered_active_vms'], ['manual-vm'])
            self.assertEqual(result['active_vm_count'], 1)

    def test_unknown_ram_for_unregistered_active_domain_fails_closed(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            root = Path(temp)
            registry.registry_dir(root, create=True)
            candidate = vm(root, 'new-vm', number=1, host_limit=64, memory=56)
            with patch.object(admission, '_active_names', return_value=['manual-vm']), \
                 patch.object(admission, '_xml_ram', return_value=None), \
                 patch.object(admission, '_mem_total', return_value=512 * admission.GIB):
                with self.assertRaisesRegex(RuntimeError, 'memory limit'):
                    admission.check(root, candidate)

    def test_admission_lock_creates_distinct_serialization_lock(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            root = Path(temp)
            registry.registry_dir(root, create=True)
            with admission.lock(root):
                self.assertTrue((root / 'registry/.admission.lock').is_file())


if __name__ == '__main__':
    unittest.main()
