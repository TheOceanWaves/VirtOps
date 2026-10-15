#!/usr/bin/env python3
"""Host-wide memory admission check for multiple registered VM instances."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
from typing import Any, Iterator

try:
    import instance_registry as registry
except ModuleNotFoundError:  # direct execution from a source/runtime directory
    import importlib.util
    _spec = importlib.util.spec_from_file_location(
        'instance_registry', Path(__file__).with_name('instance_registry.py'))
    if _spec is None or _spec.loader is None:
        raise
    registry = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(registry)

GIB = 1024 ** 3


@contextmanager
def lock(host_root: str | Path) -> Iterator[None]:
    """Hold the host admission lock across check and the actual VM start."""
    directory = registry.registry_dir(host_root)
    with registry._lock(directory, name='.admission.lock'):
        yield


def _mem_total() -> int:
    for line in Path('/proc/meminfo').read_text(encoding='ascii').splitlines():
        if line.startswith('MemTotal:'):
            return int(line.split()[1]) * 1024
    raise RuntimeError('MemTotal is unavailable')


def _state(name: str) -> str:
    virsh = registry.shutil_which('virsh')
    if not virsh:
        return 'unknown'
    result = subprocess.run([virsh, '--readonly', '-c', 'qemu:///system', 'domstate', name],
                            text=True, capture_output=True, check=False)
    return result.stdout.strip().lower() if result.returncode == 0 else 'undefined'


def _active_names() -> list[str]:
    virsh = registry.shutil_which('virsh')
    if not virsh:
        raise RuntimeError('cannot enumerate all active libvirt VMs: virsh is missing')
    result = subprocess.run([virsh, '--readonly', '-c', 'qemu:///system', 'list', '--name'],
                            text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError('cannot enumerate all active libvirt VMs')
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _xml_ram(name: str) -> int | None:
    virsh = registry.shutil_which('virsh')
    if not virsh:
        return None
    result = subprocess.run([virsh, '--readonly', '-c', 'qemu:///system', 'dumpxml', name],
                            text=True, capture_output=True, check=False)
    if result.returncode:
        return None
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(result.stdout)
        memory = root.findtext('memory')
        unit = (root.find('memory').get('unit', 'KiB') if root.find('memory') is not None else 'KiB')
        if memory is None:
            return None
        scale = {'KiB': 1024, 'MiB': 1024 ** 2, 'GiB': GIB, 'bytes': 1}.get(unit)
        return int(memory) * scale if scale else None
    except (ET.ParseError, TypeError, ValueError):
        return None


def _configured_limit(item: dict[str, Any]) -> int:
    resources = item.get('resources') or {}
    value = resources.get('host_limit_gib')
    if isinstance(value, int) and value > 0:
        return value * GIB
    ram = _xml_ram(item['name'])
    if ram is None:
        memory = resources.get('memory_gib')
        if not isinstance(memory, int) or memory <= 0:
            raise RuntimeError(f"cannot determine memory limit for active VM {item['name']}")
        ram = memory * GIB
    return ram + 8 * GIB


def check(host_root: str | Path, candidate: dict[str, Any]) -> dict[str, Any]:
    directory = registry.registry_dir(host_root)
    rows = registry._records(directory)
    registered = {item['name']: item for _, item in rows}
    active_names = _active_names()
    active_set = set(active_names)
    active = []
    for name, item in registered.items():
        if item.get('uuid') == candidate.get('uuid'):
            continue
        # `virsh list --name` is the active-domain enumeration.  Count every
        # listed state, including paused, shutdown-transition and pmsuspended;
        # do not rely on a small, version-specific state vocabulary.
        if name in active_set:
            active.append((item, 'active', _configured_limit(item)))

    # Include active libvirt domains that have no registry reservation. This
    # prevents a new managed VM from overcommitting around another colleague's
    # manually-created VM. An active domain with unreadable RAM is a hard stop.
    unregistered = []
    for name in active_names:
        if name in registered or name == candidate.get('name'):
            continue
        item = {'name': name, 'resources': {}}
        unregistered.append((item, 'active', _configured_limit(item)))
    active.extend(unregistered)
    candidate_limit = _configured_limit(candidate)
    active_total = sum(limit for _, _, limit in active)
    reserve_values = []
    for item, _, limit in active:
        resources = item.get('resources') or {}
        reserve_values.append(max(0, int((item.get('start_free_gib') or 0) -
                                        (resources.get('host_limit_gib') or limit // GIB)) * GIB))
    candidate_reserve = max(0, int((candidate.get('limits') or {}).get('start_free_gib', 0) -
                                   (candidate.get('resources') or {}).get('host_limit_gib', 0)) * GIB)
    reserve = max(reserve_values + [candidate_reserve], default=0)
    total = active_total + candidate_limit + reserve
    mem_total = _mem_total()
    result = {
        'allowed': total < mem_total,
        'mem_total_bytes': mem_total,
        'active_vm_count': len(active),
        'active_vm_names': [item['name'] for item, _, _ in active],
        'configured_limits_bytes': active_total + candidate_limit,
        'max_start_reserve_bytes': reserve,
        'admission_bytes': total,
        'unregistered_active_vms': [item['name'] for item, _, _ in unregistered],
    }
    if not result['allowed']:
        raise RuntimeError(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host-root', required=True, type=Path)
    parser.add_argument('--candidate-json', required=True, type=Path)
    args = parser.parse_args()
    candidate = json.loads(args.candidate_json.read_text(encoding='utf-8'))
    print(json.dumps(check(args.host_root, candidate), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
