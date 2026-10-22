"""Root-side implementation for configure.py (REQUEST is injected by caller)."""
from __future__ import annotations
import copy
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager
try:
    import fcntl
except ImportError:
    fcntl = None

GIB = 1024 ** 3

def run(argv, *, timeout=120, check=True):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip() or 'command failed')
    return result

def cpu_ids(text):
    result = set()
    for part in str(text).split(','):
        if not re.fullmatch(r'\d+(?:-\d+)?', part):
            raise RuntimeError('invalid CPU set')
        bits = [int(x) for x in part.split('-')]
        result.update(range(bits[0], bits[-1] + 1 if len(bits) == 2 else bits[0] + 1))
    return result

def _json(path):
    return json.loads(path.read_text(encoding='utf-8'))

def verify_identity(data):
    root = Path(data['root'])
    if root.is_symlink() or not root.is_absolute():
        raise RuntimeError('instance root is symlinked or not absolute')
    if os.name == 'posix':
        for parent in (root, *root.parents):
            st = parent.stat()
            if parent.is_symlink() or st.st_uid != 0 or st.st_mode & 0o022:
                raise RuntimeError(f'unsafe instance path ancestor: {parent}')
    instance = root / 'instance.json'
    if instance.is_symlink() or not instance.is_file():
        raise RuntimeError('instance configuration is absent or symlinked')
    actual = _json(instance)
    for field in ('name', 'uuid', 'root'):
        if actual.get(field) != data.get(field):
            raise RuntimeError(f'profile identity mismatch: instance.{field}')
    for field in ('resources','limits','network','windows'):
        if actual.get(field)!=data.get(field):raise RuntimeError('current profile is stale: '+field)
    domain = run(['virsh', '--readonly', '-c', 'qemu:///system', 'dumpxml', data['name']], check=False)
    if domain.returncode:
        raise RuntimeError('VM is not defined')
    xml = ET.fromstring(domain.stdout)
    if xml.findtext('uuid') != data['uuid']:
        raise RuntimeError('libvirt UUID differs from profile')
    # Ensure the resource transaction cannot silently point at another disk,
    # NVRAM, TPM state, or an unexpected qcow2 backing chain.
    approved_root = (root / 'vol').resolve()
    disk_paths = []
    for source in xml.findall("./devices/disk/source"):
        path = source.get('file') or source.get('dev')
        if path:
            disk_paths.append(Path(path).resolve())
    if not disk_paths or any(not p.is_relative_to(approved_root) for p in disk_paths):
        raise RuntimeError('libvirt disk path is outside the approved instance store')
    for node in xml.findall("./os/nvram"):
        path = node.text
        if path and not Path(path).resolve().is_relative_to(approved_root):
            raise RuntimeError('NVRAM path is outside the approved instance store')
    tpm = xml.find("./devices/tpm/backend/device")
    if tpm is not None and tpm.get('path') and not Path(tpm.get('path')).resolve().is_relative_to(approved_root):
        raise RuntimeError('TPM path is outside the approved instance store')
    registry = Path(data.get('host_root') or root.parent) / 'registry' / (data['name'] + '.json')
    if registry.is_symlink() or not registry.is_file():raise RuntimeError('managed registry entry is missing')
    row = _json(registry)
    for field in ('name', 'uuid', 'root'):
        if row.get(field) != data.get(field):raise RuntimeError(f'registry identity mismatch: {field}')
    manifest_path=root/'vol/state/private/runtime-files.json'
    manifest=_json(manifest_path)
    if manifest.get('uuid')!=data['uuid'] or not manifest.get('sha256'):raise RuntimeError('managed runtime hash manifest is missing')
    for relative,digest in manifest['sha256'].items():
        path=root/relative
        if Path(relative).is_absolute() or '..' in Path(relative).parts or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise RuntimeError('managed runtime hash differs: '+relative)
    return xml, run(['virsh', '--readonly', '-c', 'qemu:///system', 'domstate', data['name']]).stdout.strip().lower()

def host_admission(data, desired):
    mem = next((int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines()
                if line.startswith('MemTotal:')), 0)
    available = next((int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines()
                      if line.startswith('MemAvailable:')), 0)
    need = desired['limits']['start_free_gib'] * GIB
    if available < need:
        raise RuntimeError(f'host MemAvailable below start-free gate ({available} < {need})')
    reserve = max(0, need - desired['resources']['host_limit_gib'] * GIB)
    if desired['resources']['host_limit_gib'] * GIB + reserve > mem:
        raise RuntimeError('desired host limit plus start-free reserve exceeds host capacity')
    ids = cpu_ids(desired['resources'].get('cpu_set', ''))
    if len(ids) != desired['resources']['vcpus']:
        raise RuntimeError('desired CPU set is not available on this host')
    registry=Path(data.get('host_root') or Path(data['root']).parent)/'registry'
    for path in registry.glob('*.json'):
        other=_json(path)
        if other.get('uuid')==data['uuid']:continue
        reserved=(other.get('resources') or {}).get('cpu_set')
        if reserved and ids & cpu_ids(reserved):raise RuntimeError('desired CPUs overlap another registered instance')
    groups={}
    for line in run(['lscpu','-p=CPU,CORE,SOCKET,ONLINE']).stdout.splitlines():
        if not line or line.startswith('#'):continue
        cpu,core,socket,online=line.split(',')[:4]
        if online=='Y' and int(cpu) in ids:groups.setdefault((int(socket),int(core)),[]).append(int(cpu))
    if {cpu for group in groups.values() for cpu in group}!=ids or len({len(group) for group in groups.values()})!=1:
        raise RuntimeError('CPU mapping must select uniform online threads per physical core')
    desired['resources']['cpu_order']=[cpu for _,group in sorted(groups.items()) for cpu in sorted(group)]
    desired['resources']['threads_per_core']=len(next(iter(groups.values())))
    # Prefer the installed admission helper, which accounts for all registered
    # and manually defined active domains.
    helper = Path(data.get('host_root') or Path(data['root']).parent) / 'scripts/lib/admission.py'
    if helper.is_file():
        result = subprocess.run(['/usr/bin/python3', str(helper), '--host-root', str(data.get('host_root') or Path(data['root']).parent),
                      '--candidate-json', '/dev/stdin'], input=json.dumps(desired), text=True,
                      capture_output=True, timeout=60)
        if result.returncode:
            raise RuntimeError('host-wide admission rejected desired resources')
    else:
        raise RuntimeError('installed host-wide admission helper is missing; inspect the managed runtime')

@contextmanager
def admission_lock(data):
    if fcntl is None:
        yield; return
    path = Path(data.get('host_root') or Path(data['root']).parent) / 'registry' / '.admission.lock'
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with path.open('a+') as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

@contextmanager
def lifecycle_lock(data):
    if fcntl is None:yield;return
    path=Path('/run/lock')/(data['name']+'.lock')
    if path.is_symlink():raise RuntimeError('unsafe lifecycle lock')
    with path.open('a+') as stream:
        fcntl.flock(stream,fcntl.LOCK_EX)
        yield

@contextmanager
def registry_lock(data):
    if fcntl is None:yield;return
    path=Path(data.get('host_root') or Path(data['root']).parent)/'registry/.registry.lock'
    if path.is_symlink():raise RuntimeError('unsafe registry lock')
    with path.open('a+') as stream:
        fcntl.flock(stream,fcntl.LOCK_EX)
        yield

def _replace_assignment(text, name, value):
    pattern = re.compile(r'(?m)^(\s*' + re.escape(name) + r'\s*=\s*).*$')
    if not pattern.search(text):
        raise RuntimeError(f'installed controller lacks resource constant {name}')
    return pattern.sub(lambda m: m.group(1) + value, text, count=1)

def mutate_text(path, changes):
    text = path.read_text(encoding='utf-8')
    for name, value in changes.items():
        text = _replace_assignment(text, name, value)
    return text

def inspect(data, desired):
    xml, state = verify_identity(data)
    current = {'memory': xml.findtext('memory'), 'currentMemory': xml.findtext('currentMemory'),
               'vcpu': xml.findtext('vcpu'), 'state': state}
    return {'status': 'ready', 'target': data['name'], 'identity': {'uuid': data['uuid'], 'root': data['root']},
            'current': current, 'desired': desired['resources'],
            'requires_stop': state not in {'shut off', 'shutoff'}, 'remote': 'read-only'}

def _configure_locked(data, desired, *, apply=False, stop=False, restart=False):
    host_admission(data, desired)
    xml, state = verify_identity(data)
    report = inspect(data, desired)
    if not apply:
        return report
    if state == 'paused':
        raise RuntimeError('paused VM cannot be resized; refusing resume or forced power-off')
    was_running = state == 'running'
    if was_running and not stop:
        raise RuntimeError('requires_stop: pass --stop to authorize clean controller shutdown')
    root = Path(data['root'])
    vmctl = root / 'scripts/lib/vmctl.py'
    prepare_hook = root / 'scripts/lib/prepare_host.py'
    slice_path = Path('/etc/systemd/system') / ('machine-' + data['name'].replace('-', r'\x2d') + '.slice')
    instance = root / 'instance.json'
    registry = Path(data.get('host_root') or root.parent) / 'registry' / (data['name'] + '.json')
    manifest = root / 'vol/state/private/runtime-files.json'
    hook_path = Path('/etc/libvirt/hooks/qemu.d') / ('50-' + data['name'] + '-guard')
    saved_xml = root / 'vol' / (data['name'] + '.xml')
    targets = [instance, vmctl, slice_path, hook_path, saved_xml]
    if prepare_hook.exists(): targets.append(prepare_hook)
    if manifest.exists(): targets.append(manifest)
    if registry.exists(): targets.append(registry)
    for target in targets:
        if target.is_symlink() or not target.is_file():
            raise RuntimeError(f'unsafe or missing managed target: {target}')
    txn = root / '.configure-txn' / time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    txn.mkdir(mode=0o700, parents=True, exist_ok=False)
    backups = []
    original_xml = ET.tostring(xml, encoding='unicode')
    try:
        store_guard = root / 'scripts/lib' / (data['name'] + '_store_guard.py')
        if store_guard.is_symlink() or not store_guard.is_file():
            raise RuntimeError('installed store guard is missing or unsafe')
        run(['/usr/bin/python3', str(store_guard)])
        if was_running:
            stop_script = root / 'scripts/stop.sh'
            if stop_script.is_symlink() or not stop_script.is_file():
                raise RuntimeError('installed stop controller is missing')
            if fcntl is not None:
                spec=importlib.util.spec_from_file_location('virtops_configure_ctl',vmctl)
                controller=importlib.util.module_from_spec(spec);spec.loader.exec_module(controller)
                controller.stop_locked()
            else:
                run([str(stop_script)], timeout=180)
            state = run(['virsh', '--readonly', '-c', 'qemu:///system', 'domstate', data['name']]).stdout.strip().lower()
            if state not in {'shut off', 'shutoff'}:
                raise RuntimeError('clean stop did not reach shut off; transaction not applied')
        for target in targets:
            backup = txn / target.name
            shutil.copy2(target, backup)
            backups.append((target, backup))
        # Update only resource fields in persistent records.
        new_instance = _json(instance)
        new_instance['resources'] = copy.deepcopy(desired['resources'])
        new_instance['limits']['start_free_gib'] = desired['limits']['start_free_gib']
        instance.write_text(json.dumps(new_instance, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        if registry.exists():
            row = _json(registry); row['resources'] = {k: desired['resources'].get(k) for k in ('memory_gib','host_limit_gib','vcpus','storage_gib','cpu_set')}; row['start_free_gib'] = desired['limits']['start_free_gib']
            registry.write_text(json.dumps(row, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        constants={'MEMORY_MAX': str(desired['resources']['host_limit_gib']) + ' * GIB',
            'CPU_MAX': repr(str(desired['resources']['vcpus'] * 100000) + ' 100000'),
            'ALLOWED_CPUS': repr(desired['resources']['cpu_set'])}
        if re.search(r'^START_MEM_AVAILABLE_MIN\s*=',vmctl.read_text(),re.M):
            constants['START_MEM_AVAILABLE_MIN']=str(desired['limits']['start_free_gib'])+' * GIB'
        vmctl.write_text(mutate_text(vmctl, constants), encoding='utf-8')
        if prepare_hook.exists():
            # Installed prepare hooks use the same bounded assignment names;
            # preserve unrelated newer runtime code.
            try:
                prepare_hook.write_text(mutate_text(prepare_hook, {
                    'START_MEM_AVAILABLE_MIN': str(desired['limits']['start_free_gib']) + ' * GIB'}), encoding='utf-8')
            except RuntimeError:
                pass
        if hook_path.exists():
            hook = hook_path.read_text(encoding='utf-8')
            hook = re.sub(r'(\$2\s*<\s*)\d+', r'\g<1>' + str(desired['limits']['start_free_gib'] * 1024**2), hook)
            hook_path.write_text(hook, encoding='utf-8')
        slice_text = slice_path.read_text(encoding='utf-8')
        replacements = {'AllowedCPUs': desired['resources']['cpu_set'], 'CPUQuota': str(desired['resources']['vcpus'] * 100) + '%',
                        'CPUQuotaPeriodSec': '100ms', 'MemoryMax': str(desired['resources']['host_limit_gib']) + 'G', 'MemorySwapMax': '0'}
        for key, value in replacements.items():
            if re.search(r'(?m)^' + key + r'=', slice_text):
                slice_text = re.sub(r'(?m)^' + key + r'=.*$', key + '=' + value, slice_text)
            else:
                slice_text += key + '=' + value + '\n'
        slice_path.write_text(slice_text, encoding='utf-8')
        xml.find('memory').text = str(desired['resources']['memory_gib'] * 1024 * 1024)
        xml.find('currentMemory').text = str(desired['resources']['memory_gib'] * 1024 * 1024)
        xml.find('vcpu').text = str(desired['resources']['vcpus'])
        memtune = xml.find('memtune')
        if memtune is not None:
            for node in memtune:
                node.text = str(desired['resources']['host_limit_gib'] * 1024 * 1024)
        cputune = xml.find('cputune')
        if cputune is not None:
            cputune.clear()
            for index, cpu in enumerate(desired['resources'].get('cpu_order') or sorted(cpu_ids(desired['resources']['cpu_set']))):
                ET.SubElement(cputune, 'vcpupin', {'vcpu': str(index), 'cpuset': str(cpu)})
            ET.SubElement(cputune, 'emulatorpin', {'cpuset': desired['resources']['cpu_set']})
            ET.SubElement(cputune, 'global_quota').text = str(desired['resources']['vcpus'] * 100000)
            ET.SubElement(cputune, 'global_period').text = '100000'
        topology = xml.find('cpu/topology')
        if topology is not None:
            threads = int(desired['resources'].get('threads_per_core') or topology.get('threads', '1'))
            if desired['resources']['vcpus'] % threads:
                threads = 1
            topology.set('cores', str(desired['resources']['vcpus'] // threads)); topology.set('threads', str(threads))
        # Use a private transaction XML path so virsh never reads a partial file.
        rendered_xml = ET.tostring(xml, encoding='unicode')
        xml_path = txn / ('new-' + data['name'] + '.xml'); xml_path.write_text(rendered_xml, encoding='utf-8')
        saved_xml.write_text(rendered_xml, encoding='utf-8')
        result = run(['virsh', '-c', 'qemu:///system', 'define', str(xml_path)], check=False)
        if result.returncode: raise RuntimeError((result.stderr or result.stdout).strip())
        if manifest.exists():
            saved = _json(manifest)
            if saved.get('uuid') not in (None, data['uuid']):
                raise RuntimeError('runtime manifest identity mismatch')
            saved['uuid'] = data['uuid']; saved['resources'] = copy.deepcopy(desired['resources'])
            saved['limits'] = copy.deepcopy(desired['limits'])
            hashes = saved.setdefault('sha256', {})
            hashes['scripts/lib/vmctl.py'] = hashlib.sha256(vmctl.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(saved, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'set-property', '--runtime', 'machine-' + data['name'].replace('-', r'\x2d') + '.slice',
             'AllowedCPUs=' + desired['resources']['cpu_set'],
             'CPUQuota=' + str(desired['resources']['vcpus'] * 100) + '%',
             'MemoryMax=' + str(desired['resources']['host_limit_gib']) + 'G', 'MemorySwapMax=0'])
        run(['systemctl','restart',data['name']+'-capguard.service'])
        if was_running:
            report['restart_required'] = True
        report.update(status='applied', changed=True, restarted=False)
        return report
    except Exception:
        for target, backup in reversed(backups):
            shutil.copy2(backup, target)
        try:
            old_xml = txn / (data['name'] + '.rollback.xml')
            old_xml.write_text(original_xml, encoding='utf-8')
            run(['virsh', '-c', 'qemu:///system', 'define', str(old_xml)], check=False)
            run(['systemctl','daemon-reload'],check=False)
            run(['systemctl', 'set-property', '--runtime', 'machine-' + data['name'].replace('-', r'\x2d') + '.slice',
                 'AllowedCPUs=' + str(data['resources'].get('cpu_set', '')), 'CPUQuota=' + str(data['resources'].get('vcpus', 0) * 100) + '%',
                 'MemoryMax=' + str(data['resources'].get('host_limit_gib', 0)) + 'G', 'MemorySwapMax=0'], check=False)
            run(['systemctl','restart',data['name']+'-capguard.service'],check=False)
        except Exception:
            pass
        raise

def configure(data, desired, *, apply=False, stop=False, restart=False):
    """Serialize admission, stop, definition changes and registry writes."""
    if not apply:return _configure_locked(data,desired,apply=False)
    # Same order as vmctl.start and destroy: lifecycle -> admission -> registry.
    with lifecycle_lock(data),admission_lock(data),registry_lock(data):
        result=_configure_locked(data, desired, apply=apply, stop=stop, restart=restart)
    # The installed start controller acquires admission itself. Never wait on a
    # child controller while holding the same advisory lock in this process.
    if apply and restart and result.get('restart_required'):
        run([str(Path(data['root'])/'scripts/start.sh')],timeout=180)
        result.update(restarted=True,restart_required=False)
    return result

def main(request):
    return print(json.dumps(configure(request['profile'], request['desired'], apply=request.get('apply', False),
                                      stop=request.get('stop', False), restart=request.get('restart', False)),
                            ensure_ascii=False, sort_keys=True, indent=2)) or 0

if 'REQUEST' in globals():
    try:
        raise SystemExit(main(REQUEST))
    except (OSError, RuntimeError, ValueError, KeyError, ET.ParseError, subprocess.SubprocessError) as exc:
        print(json.dumps({'status': 'blocked', 'reason': str(exc)}, ensure_ascii=False))
        raise SystemExit(2)
