"""SSH stdin payload used by host.py; REQUEST is injected as data."""
import json
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET


def run(arguments, timeout=15, check=True):
    result = subprocess.run(arguments, text=True, capture_output=True, timeout=timeout, env=dict(os.environ, LC_ALL='C'))
    if check and result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip())
    return result


def inspect(data):
    memory = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, _, value = line.partition(':')
        if key in {'MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree'}:
            memory[key] = int(value.split()[0]) * 1024
    root = Path(data['root'])
    domain = run(['virsh', '--readonly', '-c', 'qemu:///system', 'dumpxml', data['name']], check=False)
    identity = None
    if domain.returncode == 0:
        xml = ET.fromstring(domain.stdout)
        identity = {'uuid': xml.findtext('uuid'), 'matches_profile': xml.findtext('uuid') == data['uuid'],
                    'memory_KiB': xml.findtext('currentMemory'), 'vcpus': xml.findtext('vcpu'),
                    'state': run(['virsh', '--readonly', '-c', 'qemu:///system', 'domstate', data['name']]).stdout.strip(),
                    'memory_stats': run(['virsh', '--readonly', '-c', 'qemu:///system', 'dommemstat', data['name']], check=False).stdout.strip()}
    tools = ['virsh', 'qemu-system-x86_64', 'qemu-img', 'qemu-nbd', 'swtpm', 'xorriso', 'wimlib-imagex', 'mkntfs', 'ntfscp', 'iptables-nft', 'systemd-escape']
    return {'status': 'inspected', 'target': data['name'], 'domain': identity,
            'all_vms': run(['virsh', '--readonly', '-c', 'qemu:///system', 'list', '--all'], check=False).stdout,
            'host_memory_bytes': memory, 'root_available_bytes': os.statvfs('/').f_bavail * os.statvfs('/').f_frsize,
            'instance_root_exists': root.exists(), 'volume_is_mount': os.path.ismount(root / 'vol'),
            'reset_acceptance_exists': (root / 'vol/recovery/reset-enabled.json').is_file(),
            'recovery_marker_exists': (root / 'vol/recovery/c-reset-in-progress.json').is_file(),
            'logical_cpus_online': os.cpu_count(),
            'requested_ports': {str(port):[line for line in run(['ss','-ltn']).stdout.splitlines() if ':'+str(port)+' ' in line] for port in [data['network']['rdp_port'],data['network']['winrm_port']]},
            'tools': {tool: shutil.which(tool) is not None for tool in tools},
            'memory_note': 'VM ceilings are not reservations; pause does not release QEMU RSS.'}


def network_only_logs(result):
    """Strip lifecycle events at the host boundary, retaining VM network records."""
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError('logs command did not return JSON') from exc
    if not isinstance(payload, dict):
        raise RuntimeError('logs command returned an invalid payload')
    return {'network_samples': payload.get('network_samples', [])}


def main(request):
    data, action = request['profile'], request['action']
    if action == 'inspect':
        print(json.dumps(inspect(data), ensure_ascii=False, indent=2))
        return 0
    if action == 'status' and request.get('all'):
        host_root = Path(data.get('host_root') or data['root'])
        helper = host_root / 'scripts/lib/instance_registry.py'
        if helper.is_symlink() or not helper.is_file():
            raise RuntimeError('host catalog helper is missing; run fresh initialization catalog stage')
        spec = importlib.util.spec_from_file_location('instance_registry', helper)
        if spec is None or spec.loader is None:
            raise RuntimeError('host catalog helper cannot be loaded')
        registry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(registry)
        print(json.dumps(registry.list_entries(host_root), ensure_ascii=False, indent=2))
        return 0
    domain = run(['virsh', '--readonly', '-c', 'qemu:///system', 'dumpxml', data['name']], check=False)
    if action == 'recreate':
        xml_path = Path(data['root']) / 'vol' / (data['name'] + '.xml')
        actual = ET.fromstring(xml_path.read_text()).findtext('uuid')
    else:
        if domain.returncode:
            raise RuntimeError('VM not defined; inspect and use the initialization/recreate workflow')
        actual = ET.fromstring(domain.stdout).findtext('uuid')
    if actual != data['uuid']:
        raise RuntimeError('VM UUID differs from profile; refusing lifecycle operation')
    script = Path(data['root']) / 'scripts' / (action + '.sh')
    owner = script.stat()
    if script.is_symlink() or owner.st_uid != 0 or owner.st_mode & 0o022:
        raise RuntimeError('unsafe management wrapper ownership/path')
    arguments = [str(script)]
    if action == 'reset':
        if not request['discard']:
            raise RuntimeError('C reset requires explicit --discard')
        arguments += ['--discard']
        if request.get('owner_profile'):
            arguments += ['--owner-profile', request['owner_profile']]
        if request.get('discard_data'):
            arguments += ['--discard-data']
    result = run(arguments, timeout=3700 if action == 'reset' else 150, check=False)
    if action == 'logs' and request.get('network_only'):
        if result.returncode:
            output = result.stdout
        else:
            output = json.dumps(network_only_logs(result), ensure_ascii=False, indent=2, sort_keys=True) + '\n'
        print(output, end='')
        if result.stderr:
            import sys
            print(result.stderr, file=sys.stderr, end='')
        return result.returncode
    print(result.stdout, end='')
    if result.stderr:
        import sys
        print(result.stderr, file=sys.stderr, end='')
    return result.returncode


if __name__ == '__main__':
    try:
        raise SystemExit(main(REQUEST))
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(json.dumps({'status': 'blocked', 'reason': str(exc)}, ensure_ascii=False))
        raise SystemExit(2)
