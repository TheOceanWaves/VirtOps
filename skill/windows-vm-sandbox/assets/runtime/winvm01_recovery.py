"""Root controller integration for the bounded, C-only Windows recovery."""
from __future__ import annotations

import importlib.util
import hashlib
import json
import pathlib
import time
from contextlib import nullcontext

ROOT = pathlib.Path('/home/vm_run/scripts/lib')
RECOVERY = pathlib.Path('/home/vm_run/vol/recovery')
CONTEXT = RECOVERY / 'guest-context.json'
MARKER = RECOVERY / 'c-reset-in-progress.json'
HELPER = ROOT / 'winvm01_c_reset.py'


class PostbootValidationFailed(RuntimeError):
    pass


def qga_module(controller):
    path = ROOT / 'winvm01_qga.py'
    controller.require_root_helper(path)
    spec = importlib.util.spec_from_file_location('winvm01_qga', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def save_context(context):
    RECOVERY.mkdir(mode=0o700, exist_ok=True)
    temporary = CONTEXT.with_suffix('.tmp')
    if temporary.is_symlink() or CONTEXT.is_symlink():
        raise RuntimeError('unsafe recovery context path')
    temporary.write_text(json.dumps(context, indent=2) + '\n')
    temporary.chmod(0o600)
    temporary.replace(CONTEXT)


def collect_context(controller):
    qga = qga_module(controller)
    for attempt in range(3):
        try:
            context = json.loads(qga.powershell(
                r'& C:\ProgramData\WinVM01\winvm01_reset_context.ps1', timeout=120))
            break
        except Exception:
            if attempt == 2:
                raise
            time.sleep(3)
    if context.get('vm') != controller.VM or context.get('disk_path') != str(controller.ACTIVE):
        raise RuntimeError('guest recovery context identity mismatch')
    if context['disk']['size_bytes'] != controller.STORE_BYTES:
        raise RuntimeError('guest disk size differs from the approved budget')
    context['qga_verified'] = True
    context['collected_unix'] = time.time()
    save_context(context)
    return context


def merge_offline_evidence(controller, context, *, recovery_retry=False):
    controller.require_root_helper(HELPER)
    probe = json.loads(controller.run([
        str(controller.PYTHON3), str(HELPER), 'probe-gpt', '--bootstrap',
        ], timeout=300).stdout)
    if probe.get('gpt_primary_backup_verified') is not True:
        raise RuntimeError('offline probe did not verify both GPT copies')
    if (context['disk']['disk_guid'] != probe['disk_guid'] or
            context['disk']['size_bytes'] != probe['size_bytes']):
        raise RuntimeError('offline GPT and guest disk identity disagree')
    for letter, part in context['disk']['partitions'].items():
        candidates = [x for x in probe['ntfs_partitions'] if x['unique_guid'] == part['unique_guid']]
        if len(candidates) != 1:
            raise RuntimeError(f'offline {letter} GUID does not identify one NTFS partition')
        observed = candidates[0]
        for field in ('unique_guid', 'start_bytes', 'size_bytes', 'ntfs_serial'):
            if recovery_retry and letter == 'C' and field == 'ntfs_serial':
                continue
            if part[field] != observed[field]:
                raise RuntimeError(f'offline {letter} {field} differs from QGA evidence')
        # Windows can retain an old device partition number until reboot after
        # inserting D. The on-disk GPT entry index is authoritative offline.
        part.setdefault('windows_index_observed', part['index'])
        part['index'] = observed['index']
    for field in ('index', 'unique_guid', 'start_bytes', 'size_bytes'):
        if context['efi_observed'][field] != probe['efi'][field]:
            raise RuntimeError('offline EFI geometry differs from guest evidence')
    context['disk']['gpt_header_crc32'] = probe['gpt_header_crc32']
    context['efi'] = probe['efi']
    save_context(context)
    return context


def read_guest_json(qga, path):
    handle = qga.call('guest-file-open', {'path': path, 'mode': 'rb'})
    try:
        import base64
        response = qga.call('guest-file-read', {'handle': handle, 'count': 65536})
        data = base64.b64decode(response['buf-b64'])
        if len(data) >= 65536:
            raise RuntimeError('oversized guest recovery result')
        return json.loads(data.decode('utf-8-sig'))
    finally:
        qga.call('guest-file-close', {'handle': handle})


def validate_boot(controller):
    controller.require_root_helper(MARKER)
    marker = json.loads(MARKER.read_text())
    if marker.get('phase') != 'restore-applied-controller-validation' or not marker.get('reset_request_id'):
        raise RuntimeError('recovery marker does not authorize validation boot')
    qga = qga_module(controller)
    deadline = time.monotonic() + 180
    last_error = 'guest agent not ready'
    while time.monotonic() < deadline:
        try:
            qga.call('guest-ping', timeout=5)
            result = read_guest_json(qga, r'C:\ProgramData\WinVM01\reset-result.json')
            if result.get('request_id') == marker['reset_request_id']:
                if result.get('state') != 'success':
                    raise PostbootValidationFailed('Windows postboot validation failed: ' + str(result.get('error', 'unknown')))
                services = json.loads(qga.powershell(
                    r"@{RDP=(Get-Service TermService).Status.ToString();WinRM=(Get-Service WinRM).Status.ToString()}|ConvertTo-Json -Compress"))
                if services != {'RDP': 'Running', 'WinRM': 'Running'}:
                    raise RuntimeError('Windows management services are not ready')
                controller.verify_running_cgroup()
                controller.verify_services_and_network()
                report = {'validated_unix': time.time(), 'postboot': result, 'services': services}
                target = RECOVERY / 'last-reset-verified.json'
                target.write_text(json.dumps(report, indent=2) + '\n')
                target.chmod(0o600)
                MARKER.unlink()
                controller.event('C_reset_verified_D_preserved', request_id=marker['reset_request_id'])
                return report
        except Exception as exc:
            if isinstance(exc, PostbootValidationFailed):
                raise
            last_error = str(exc)[:400]
        time.sleep(3)
    raise RuntimeError('recovery boot was not verified: ' + last_error)


def reset(controller, discard, *, locked=False):
    if not discard:
        raise RuntimeError('reset clears C only; explicit --discard is required')
    with (nullcontext() if locked else controller.lifecycle_lock()):
        controller.require_root_helper(HELPER)
        for name in ('initial-C.wim', 'initial-C.json'):
            controller.require_root_helper(RECOVERY / name)
        if controller.domstate() == 'running' and not MARKER.exists():
            controller.verify_services_and_network()
            context = collect_context(controller)
            controller.stop_locked()
            try:
                merge_offline_evidence(controller, context)
            except Exception:
                if not MARKER.exists():
                    controller.start_locked(owner_validation=locked)
                raise
        elif controller.domstate() in {'shut off', 'shutoff'} and MARKER.exists():
            controller.require_root_helper(CONTEXT)
            controller.require_root_helper(MARKER)
            pending = json.loads(MARKER.read_text())
            if pending.get('context_sha256') != hashlib.sha256(CONTEXT.read_bytes()).hexdigest():
                raise RuntimeError('pending recovery context hash differs; refusing stale context')
            context = json.loads(CONTEXT.read_text())
            if pending.get('context_collected_unix') != context.get('collected_unix'):
                raise RuntimeError('pending recovery context timestamp differs')
            merge_offline_evidence(controller, context, recovery_retry=True)
        else:
            raise RuntimeError('reset needs a running guest or a stopped, marked recovery retry')
        controller.event('C_reset_requested_D_retained')
        controller.run([str(controller.PYTHON3), str(HELPER), 'reset', '--discard',
                        '--context', str(CONTEXT)], timeout=3600)
        controller.start_locked(recovery_validation=True, owner_validation=locked)
        try:
            report = validate_boot(controller)
        except Exception:
            # Retain the marker and stop safely. Never expose an unverified
            # restored guest as a completed factory reset.
            try:
                controller.stop_locked()
            except Exception:
                if controller.domstate() == 'running':
                    controller.run(['virsh', 'suspend', controller.VM], check=False)
            raise
        return {'actual_state': controller.domstate(), 'C_reset': 'verified',
                'D': 'retained', 'evidence': report}
