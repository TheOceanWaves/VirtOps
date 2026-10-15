#!/usr/bin/env python3
"""Root-only lifecycle controller template for the isolated winvm01 VM.

Install this file root-owned at /home/vm_run/scripts/lib/vmctl.py (0755).  The
unprivileged wrapper may only call that installed path through sudo; this
controller never executes a script below /home/llm_run.

The only guest disk is the standalone current.qcow2.  It is deliberately not
a qcow2 backing chain: user-created D: data and its partition layout must
survive C: recovery. The C-only recovery helper is installed at
/home/vm_run/scripts/lib/winvm01_c_reset.py and must recover a C baseline WIM in place
after validating the current GPT, C partition identity/index, QGA and D:
MountedDevices mapping. Reset requires a baseline-bound acceptance record.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import pathlib
import re
import subprocess
import sys
import time
from contextlib import contextmanager
from typing import Any, Iterator

VM = "winvm01"
DOMAIN_UUID = "8cb9f0f6-3d77-4c1c-8d0b-5ab70ac5f201"
STORE = pathlib.Path("/home/vm_run/vol")
STORE_FILE = pathlib.Path("/home/vm_run/.storage/winvm01.store")
ACTIVE = STORE / "current.qcow2"
TPM_SOURCE = STORE / "state/tpm"
TPM_TARGET = pathlib.Path("/var/lib/libvirt/swtpm") / DOMAIN_UUID
LOGS = STORE / "logs"
LIFECYCLE_LOG = LOGS / "lifecycle.jsonl"
LOCK = pathlib.Path("/run/lock/winvm01.lock")
NETWORK = pathlib.Path("/home/vm_run/scripts/lib/winvm01_network.py")
PYTHON3 = pathlib.Path("/usr/bin/python3").resolve()
LIBVIRT_GUARD = pathlib.Path("/etc/libvirt/hooks/qemu.d/50-winvm01-guard")

GIB = 1024**3
STORE_BYTES = 150 * GIB
START_STORE_FREE_MIN = 10 * GIB
START_ROOT_FREE_MIN = 250 * GIB
START_MEM_AVAILABLE_MIN = 204 * GIB
WATCH_STORE_FREE_MIN = 5 * GIB
WATCH_MEM_AVAILABLE_MIN = 64 * GIB
_memory_warning_at: float | None = None
MEMORY_MAX = 140 * GIB
CPU_MAX = "9600000 100000"
ALLOWED_CPUS = "0-15,24-31,48-55,72-87,96-111,120-127,144-151,168-183"
REQUIRED_UNITS = (
    "winvm01-firewall.service",
    "winvm01-log-collector.service",
    "winvm01-capguard.service",
)


class ControllerError(RuntimeError):
    pass


def run(argv: list[str], *, timeout: int = 120, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise ControllerError(f"command failed ({' '.join(argv)}): {(result.stderr or result.stdout).strip()}")
    return result


def require_root() -> None:
    if os.geteuid() != 0:
        raise ControllerError("root is required; use the installed sudo-controlled backend")


def require_root_helper(path: pathlib.Path) -> None:
    try:
        stat = path.stat()
    except FileNotFoundError as exc:
        raise ControllerError(f"required installed helper is absent: {path}") from exc
    if path.is_symlink() or stat.st_uid != 0 or stat.st_mode & 0o022:
        raise ControllerError(f"unsafe helper ownership/mode: {path}")


@contextmanager
def lifecycle_lock() -> Iterator[None]:
    require_root()
    LOCK.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def event(event_name: str, **metadata: Any) -> None:
    """Bounded host lifecycle metadata; never copies guest contents or logs."""
    if not os.path.ismount(STORE):
        return
    if not LOGS.is_dir() or LOGS.is_symlink() or not LOGS.resolve().is_relative_to(STORE.resolve()):
        return
    if LIFECYCLE_LOG.exists() and (LIFECYCLE_LOG.is_symlink() or not LIFECYCLE_LOG.is_file()):
        return
    if LIFECYCLE_LOG.exists() and LIFECYCLE_LOG.stat().st_size >= 512 * 1024:
        backup = LIFECYCLE_LOG.with_suffix(".jsonl.1")
        backup.unlink(missing_ok=True)
        os.replace(LIFECYCLE_LOG, backup)
    payload = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "vm": VM,
        "event": event_name,
        **metadata,
    }
    with LIFECYCLE_LOG.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, sort_keys=True, ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def free_bytes(path: pathlib.Path) -> int:
    value = os.statvfs(path)
    return value.f_bavail * value.f_frsize


def mem_available() -> int:
    for line in pathlib.Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    raise ControllerError("MemAvailable is absent from /proc/meminfo")


def domstate() -> str:
    result = run(["virsh", "-c", "qemu:///system", "domstate", VM], check=False)
    if result.returncode:
        raise ControllerError(f"{VM} is not defined: {(result.stderr or result.stdout).strip()}")
    return result.stdout.strip().lower()


def verify_store_mount() -> dict[str, str]:
    if STORE.is_symlink() or not STORE.is_dir() or STORE_FILE.is_symlink() or not STORE_FILE.is_file():
        raise ControllerError("bounded store or backing file is absent/symlinked")
    result = run(["findmnt", "-rn", "--mountpoint", str(STORE), "-o", "SOURCE,FSTYPE,UUID"], check=False)
    fields = result.stdout.strip().split()
    if result.returncode or len(fields) != 3:
        raise ControllerError(f"bounded store is not mounted at {STORE}")
    source, fstype, uuid = fields
    if not source.startswith("/dev/") or fstype != "ext4" or not uuid:
        raise ControllerError(f"unexpected store mount: {result.stdout.strip()}")
    loops = json.loads(run(["losetup", "--list", "--json", "--output", "NAME,BACK-FILE"]).stdout)
    matching = [entry for entry in loops.get("loopdevices", []) if entry.get("name") == source]
    if len(matching) != 1:
        raise ControllerError(f"store source is not one exact loop device: {source}")
    backing = pathlib.Path(str(matching[0].get("back-file", "")))
    if backing.resolve() != STORE_FILE.resolve():
        raise ControllerError(f"store loop backing mismatch: {backing}")
    backing_stat = STORE_FILE.stat()
    if backing_stat.st_size != STORE_BYTES:
        raise ControllerError("store backing is not exactly 150 GiB")
    if backing_stat.st_blocks * 512 < STORE_BYTES:
        raise ControllerError("store backing is sparse; exact 150 GiB host capacity is not reserved")
    return {
        "source": source,
        "uuid": uuid,
        "backing_inode": str(backing_stat.st_ino),
        "backing_size": str(backing_stat.st_size),
        "backing_allocated": str(backing_stat.st_blocks * 512),
    }


def verify_tpm_bind() -> dict[str, str]:
    if TPM_SOURCE.is_symlink() or not TPM_SOURCE.is_dir():
        raise ControllerError(f"bounded TPM state source is absent: {TPM_SOURCE}")
    result = run(["findmnt", "-rn", "--mountpoint", str(TPM_TARGET), "-o", "SOURCE,FSTYPE,TARGET"], check=False)
    fields = result.stdout.strip().split()
    if result.returncode or len(fields) != 3 or fields[2] != str(TPM_TARGET):
        raise ControllerError(f"TPM bind mount is absent or malformed: {TPM_TARGET}")
    source_stat, target_stat = os.stat(TPM_SOURCE), os.stat(TPM_TARGET)
    if (source_stat.st_dev, source_stat.st_ino) != (target_stat.st_dev, target_stat.st_ino):
        raise ControllerError("TPM target is not bound to the bounded state/tpm directory")
    return {"source": fields[0], "fstype": fields[1], "target": fields[2]}


def verify_current_disk() -> dict[str, Any]:
    """Require the one physical guest disk, with no qcow2 backing chain."""
    if ACTIVE.is_symlink() or not ACTIVE.is_file():
        raise ControllerError(f"guest disk is absent/unsafe: {ACTIVE}")
    files = sorted(path for path in STORE.glob("*.qcow2") if path.is_file() and not path.is_symlink())
    if files != [ACTIVE]:
        raise ControllerError("expected exactly one standalone current.qcow2; refusing additional qcow2 layers")
    result = run(["qemu-img", "info", "--force-share", "--backing-chain", "--output=json", str(ACTIVE)], timeout=300)
    raw_chain = json.loads(result.stdout)
    chain = raw_chain if isinstance(raw_chain, list) else [raw_chain]
    if len(chain) != 1:
        raise ControllerError("current.qcow2 must be standalone and have no backing image")
    paths = [pathlib.Path(str(item.get("filename", ""))).resolve() for item in chain]
    if paths != [ACTIVE.resolve()]:
        raise ControllerError("current.qcow2 chain does not resolve to the approved store disk")
    data = json.loads(run(["qemu-img", "info", "--force-share", "--output=json", str(ACTIVE)], timeout=120).stdout)
    if data.get("format") != "qcow2" or int(data.get("virtual-size", -1)) != STORE_BYTES:
        raise ControllerError(f"unexpected guest disk format/size: {ACTIVE}")
    return {"disk": str(ACTIVE), "actual_size": int(data.get("actual-size", 0)),
            "virtual_size": int(data.get("virtual-size", 0)), "backing_chain_length": 1}


def unit_active(unit: str) -> bool:
    return run(["systemctl", "is-active", "--quiet", unit], check=False).returncode == 0


def services() -> dict[str, bool]:
    return {unit: unit_active(unit) for unit in REQUIRED_UNITS}


def verify_services_and_network() -> dict[str, bool]:
    state = services()
    inactive = [unit for unit, active in state.items() if not active]
    if inactive:
        raise ControllerError("required per-VM service inactive: " + ", ".join(inactive))
    require_root_helper(PYTHON3)
    require_root_helper(NETWORK)
    require_root_helper(LIBVIRT_GUARD)
    if not os.access(LIBVIRT_GUARD, os.X_OK):
        raise ControllerError(f"installed libvirt start guard is not executable: {LIBVIRT_GUARD}")
    run([str(PYTHON3), str(NETWORK), "verify", "--backend", "iptables-nft"], timeout=60)
    return state


def verify_start_preconditions() -> dict[str, Any]:
    mount = verify_store_mount()
    tpm = verify_tpm_bind()
    disk = verify_current_disk()
    service_state = verify_services_and_network()
    root_free, store_free, available = free_bytes(pathlib.Path("/")), free_bytes(STORE), mem_available()
    if root_free < START_ROOT_FREE_MIN:
        raise ControllerError(f"root free below 250 GiB: {root_free / GIB:.2f} GiB")
    if store_free < START_STORE_FREE_MIN:
        raise ControllerError(f"store free below 10 GiB: {store_free / GIB:.2f} GiB")
    if available < START_MEM_AVAILABLE_MIN:
        raise ControllerError(f"MemAvailable below 204 GiB: {available / GIB:.2f} GiB")
    if domstate() not in {"shut off", "shutoff"}:
        raise ControllerError(f"start requires shut off VM, current state is {domstate()}")
    return {
        "mount": mount, "tpm": tpm, "disk": disk, "services": service_state,
        "capacity": {"root_free": root_free, "store_free": store_free, "mem_available": available},
    }


def qemu_cgroup() -> tuple[int, pathlib.Path]:
    pid_file = pathlib.Path("/run/libvirt/qemu") / f"{VM}.pid"
    pid_text = pid_file.read_text(encoding="utf-8").strip() if pid_file.is_file() else ""
    if not pid_text.isdigit() or int(pid_text) <= 0:
        raise ControllerError(f"cannot locate running QEMU PID: {pid_file}")
    pid = int(pid_text)
    cgroup_line = next(
        (line for line in pathlib.Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8").splitlines()
         if line.startswith("0::")),
        "",
    )
    if not cgroup_line:
        raise ControllerError("QEMU has no unified cgroup")
    path = pathlib.Path("/sys/fs/cgroup") / cgroup_line.split("::", 1)[1].lstrip("/")
    if not path.is_dir():
        raise ControllerError(f"QEMU cgroup is absent: {path}")
    return pid, path


def cpu_set(text: str) -> set[int]:
    result: set[int] = set()
    for item in text.strip().split(","):
        if not item:
            continue
        first, *rest = item.split("-", 1)
        start, end = int(first), int(rest[0]) if rest else int(first)
        result.update(range(start, end + 1))
    return result


def cgroup_status() -> dict[str, Any]:
    pid, path = qemu_cgroup()
    # libvirt uses threaded emulator/vCPU leaves without memory controllers.
    # Limits on the domain/slice ancestors apply to every child thread.
    ancestry = [path, *path.parents]
    ancestry = [p for p in ancestry if p.is_relative_to('/sys/fs/cgroup')]
    limits = {}
    for ancestor in ancestry:
        limits[str(ancestor)] = {name: (ancestor / name).read_text().strip()
            for name in ('memory.max', 'memory.swap.max', 'cpu.max') if (ancestor / name).is_file()}
    values = {}
    for name in ('memory.max', 'memory.swap.max'):
        finite = [(int(v[name]), p) for p,v in limits.items() if v.get(name, 'max') != 'max']
        if not finite:
            raise ControllerError('No inherited finite '+name+' for VM')
        value, origin = min(finite)
        values[name], values[name+'_source'] = str(value), origin
    cpu_limits = []
    for origin, entries in limits.items():
        fields = entries.get('cpu.max', 'max 100000').split()
        if fields[0] != 'max':
            cpu_limits.append((int(fields[0])/int(fields[1]), fields, origin))
    if not cpu_limits:
        raise ControllerError('No inherited CPU limit for VM')
    _, fields, origin = min(cpu_limits)
    values['cpu.max'], values['cpu.max_source'] = ' '.join(fields), origin
    values['limits_by_cgroup'] = limits
    values['cpuset.cpus.effective'] = next((p/'cpuset.cpus.effective' for p in ancestry
        if (p/'cpuset.cpus.effective').is_file())).read_text().strip()
    allowed = next(
        (line.split(":", 1)[1].strip()
         for line in pathlib.Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines()
         if line.startswith("Cpus_allowed_list:")),
        "",
    )
    return {"pid": pid, "path": str(path), **values, "AllowedCPUs": allowed, "allowed_cpu_count": len(cpu_set(allowed))}


def verify_running_cgroup() -> dict[str, Any]:
    values = cgroup_status()
    if values["memory.max"] != str(MEMORY_MAX):
        raise ControllerError(f"memory.max must be {MEMORY_MAX}, got {values['memory.max']}")
    if values["memory.swap.max"] != "0":
        raise ControllerError(f"memory.swap.max must be 0, got {values['memory.swap.max']}")
    if values["cpu.max"] != CPU_MAX:
        raise ControllerError(f"cpu.max must be {CPU_MAX}, got {values['cpu.max']}")
    if cpu_set(values["AllowedCPUs"]) != cpu_set(ALLOWED_CPUS):
        raise ControllerError(f"QEMU AllowedCPUs is not approved 96-thread set: {values['AllowedCPUs']}")
    return values


def instance_config() -> dict[str, Any]:
    path = STORE.parent / 'instance.json'
    require_root_helper(path)
    data = json.loads(path.read_text())
    if data.get('name') != VM or data.get('uuid') != DOMAIN_UUID or data.get('root') != str(STORE.parent):
        raise ControllerError('Installed instance configuration identity mismatch')
    return data


def owner_pending() -> bool:
    import maintenance
    return maintenance.active(STORE / 'recovery/owner-transition.json')


def start_locked(*, recovery_validation: bool = False, owner_validation: bool = False) -> dict[str, Any]:
    import admission
    data = instance_config()
    with admission.lock(data['host_root']):
        admission.check(data['host_root'], data)
        return _start_admitted(recovery_validation=recovery_validation, owner_validation=owner_validation)


def _start_admitted(*, recovery_validation: bool = False, owner_validation: bool = False) -> dict[str, Any]:
    if owner_pending() and not owner_validation:
        raise ControllerError('Owner recovery is pending; resume the same reset request')
    marker = STORE / 'recovery/c-reset-in-progress.json'
    if marker.exists():
        require_root_helper(marker)
        evidence = json.loads(marker.read_text())
        if not recovery_validation or evidence.get('phase') != 'restore-applied-controller-validation':
            raise ControllerError('C recovery is pending; use reset --discard to retry or validate recovery')
    require_root_helper(pathlib.Path('/home/vm_run/scripts/lib/winvm01_store_guard.py'))
    run([str(PYTHON3), '/home/vm_run/scripts/lib/winvm01_store_guard.py'])
    run(['systemctl','start','machine-winvm01.slice'])
    preflight = verify_start_preconditions()
    event("start_requested", mount=preflight["mount"], capacity=preflight["capacity"])
    run(["virsh", "-c", "qemu:///system", "start", VM], timeout=120)
    try:
        time.sleep(1)
        cgroup = verify_running_cgroup()
    except Exception as exc:
        run(["virsh", "-c", "qemu:///system", "destroy", VM], check=False, timeout=120)
        event("start_rejected_destroyed", reason=str(exc))
        raise ControllerError(f"post-start acceptance failed; destroyed only {VM}: {exc}") from exc
    event("started", cgroup=cgroup)
    return {"actual_state": domstate(), "preflight": preflight, "cgroup": cgroup}


def start() -> dict[str, Any]:
    with lifecycle_lock():
        if owner_pending():
            raise ControllerError('Owner recovery is pending; ordinary start/resume is blocked')
        if (STORE / 'recovery/c-reset-in-progress.json').exists():
            raise ControllerError('C recovery is pending; ordinary start is blocked')
        state = domstate()
        if state in {'running', 'paused'}:
            verify_store_mount(); verify_tpm_bind(); verify_current_disk()
            verify_services_and_network(); limits = verify_running_cgroup()
            if state == 'paused':
                if (mem_available() < 80 * GIB or free_bytes(STORE) < START_STORE_FREE_MIN or
                        free_bytes(pathlib.Path('/')) < START_ROOT_FREE_MIN):
                    raise ControllerError('paused VM resume needs 80 GiB available RAM and normal disk reserves')
                run(['virsh', 'resume', VM])
                event('resumed_after_guard_checks')
            return {'actual_state': domstate(), 'changed': state == 'paused', 'cgroup': limits}
        return start_locked()


def stop_locked() -> dict[str, Any]:
    state = domstate()
    if state in {"shut off", "shutoff"}:
        event("stop_noop_already_shutoff")
        return {"actual_state": state, "changed": False}
    if state == "paused":
        raise ControllerError("VM is paused; refusing resume or forced power-off")
    if state != "running":
        raise ControllerError(f"safe stop supports only running/shut off, got {state}")
    event("shutdown_requested", modes="agent,acpi")
    result = run(["virsh", "-c", "qemu:///system", "shutdown", VM, "--mode", "agent,acpi"], check=False)
    if result.returncode:
        raise ControllerError(f"clean shutdown request failed: {(result.stderr or result.stdout).strip()}")
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if domstate() in {"shut off", "shutoff"}:
            event("stopped_cleanly")
            return {"actual_state": domstate(), "changed": True}
        time.sleep(2)
    run(["virsh", "-c", "qemu:///system", "suspend", VM], check=False, timeout=60)
    event("shutdown_timeout_paused", actual_state=domstate())
    raise ControllerError("guest did not stop within 120 seconds; paused only, never force-powered-off")


def stop() -> dict[str, Any]:
    with lifecycle_lock():
        return stop_locked()


def reset(discard: bool, owner_profile=None, discard_data=False) -> dict[str, Any]:
    if not discard:
        raise ControllerError("reset requires explicit --discard")
    enabled = STORE / 'recovery/reset-enabled.json'
    require_root_helper(enabled)
    proof = json.loads(enabled.read_text())
    meta = STORE / 'recovery/initial-C.json'
    require_root_helper(meta)
    if proof.get('verified') is not True or proof.get('baseline_sha256') != json.loads(meta.read_text()).get('wim_sha256'):
        raise ControllerError('this baseline has not passed the C reset/D preservation acceptance')
    import importlib.util
    path = pathlib.Path('/home/vm_run/scripts/lib/winvm01_recovery.py')
    require_root_helper(path)
    spec = importlib.util.spec_from_file_location('winvm01_recovery', path)
    recovery = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recovery)
    if owner_profile or discard_data or owner_pending() or (STORE / 'state/private/owner.json').exists():
        import owner_environment
        return owner_environment.reset(sys.modules[__name__], recovery, discard, owner_profile, discard_data)
    return recovery.reset(sys.modules[__name__], discard)


def disk_summary() -> dict[str, Any]:
    try:
        return verify_current_disk()
    except Exception as exc:
        return {"error": str(exc)}


def status() -> dict[str, Any]:
    result: dict[str, Any] = {
        "vm": VM,
        "store_budget_bytes": STORE_BYTES,
        "store_budget_GiB": STORE_BYTES / GIB,
        "services": services(),
        "guest_disk": disk_summary(),
    }
    try:
        config = instance_config()
        net = config['network']
        result['owner'] = config.get('labels', {}).get('owner', '')
        result['purpose'] = config.get('labels', {}).get('purpose', '')
        result['admin_user'] = config['windows']['admin_user']
        result['rdp'] = f"{net['publish_ip']}:{net['rdp_port']}"
        result['winrm'] = f"https://{net['publish_ip']}:{net['winrm_port']}/wsman"
        result['resources'] = config['resources']
        result['owner_recovery_pending'] = owner_pending()
    except Exception as exc:
        result['instance_config_error'] = str(exc)
    try:
        result["actual_state"] = domstate()
    except Exception as exc:
        result["domain_error"] = str(exc)
        return result
    try:
        result["mount"] = verify_store_mount()
        result["capacity"] = {
            "root_free": free_bytes(pathlib.Path("/")),
            "store_free": free_bytes(STORE),
            "mem_available": mem_available(),
        }
    except Exception as exc:
        result["storage_error"] = str(exc)
    if result["actual_state"] in {"running", "paused", "pmsuspended"}:
        try:
            result["cgroup"] = cgroup_status()
        except Exception as exc:
            result["cgroup_error"] = str(exc)
    return result


def logs() -> dict[str, Any]:
    if not LIFECYCLE_LOG.is_file() or LIFECYCLE_LOG.is_symlink():
        return {"path": str(LIFECYCLE_LOG), "events": []}
    events: list[dict[str, Any]] = []
    for line in LIFECYCLE_LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-100:]:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            events.append(item)
    network_path = LOGS / 'network-blocks.jsonl'
    samples = []
    if network_path.is_file() and not network_path.is_symlink():
        for line in network_path.read_text(encoding='utf-8', errors='replace').splitlines()[-100:]:
            try:
                samples.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return {"path": str(LIFECYCLE_LOG), "events": events,
            "network_path": str(network_path), "network_samples": samples}


def counters() -> dict[str, Any]:
    require_root_helper(NETWORK)
    require_root_helper(PYTHON3)
    output = run([str(PYTHON3), str(NETWORK), "counters", "--backend", "iptables-nft"], timeout=60)
    try:
        network = json.loads(output.stdout)
    except json.JSONDecodeError as exc:
        raise ControllerError("network counters did not return JSON") from exc
    return {"network": network, "guest_disk": disk_summary()}


def pause_for_guard(reason: str, **detail: Any) -> None:
    state = domstate()
    if state == "running":
        run(["virsh", "-c", "qemu:///system", "suspend", VM], timeout=60)
        event("guard_paused", reason=reason, **detail)
    elif state in {"shut off", "shutoff"}:
        event("guard_no_active_vm", reason=reason, actual_state=state, **detail)
    else:
        event("guard_left_existing_pause", reason=reason, actual_state=state, **detail)


def report_memory_pressure(available: int) -> None:
    """Host pressure is diagnostic; suspending a VM does not release its RAM."""
    global _memory_warning_at
    if available < WATCH_MEM_AVAILABLE_MIN:
        now = time.monotonic()
        if _memory_warning_at is None or now - _memory_warning_at >= 60:
            event("host_memory_pressure", mem_available=available, action="log_only")
            _memory_warning_at = now
    elif _memory_warning_at is not None:
        event("host_memory_recovered", mem_available=available)
        _memory_warning_at = None


def watch_once() -> None:
    """One bounded guarded sample.  The watch loop never holds flock between samples."""
    with lifecycle_lock():
        if run(['virsh','dominfo',VM],check=False).returncode:
            return
        try:
            if owner_pending():
                pause_for_guard('owner_transition_needs_resume')
                return
            mount = verify_store_mount()
            if not unit_active("winvm01-log-collector.service"):
                raise ControllerError("winvm01-log-collector.service inactive")
            # Network failure prevents a new start and pauses a running guest.
            verify_services_and_network()
            store_free, root_free, available = free_bytes(STORE), free_bytes(pathlib.Path("/")), mem_available()
            report_memory_pressure(available)
            hazards = []
            if store_free < WATCH_STORE_FREE_MIN:
                hazards.append("store_free_below_5GiB")
            if root_free < START_ROOT_FREE_MIN:
                hazards.append("root_free_below_250GiB")
            if hazards:
                pause_for_guard(",".join(hazards), mount=mount, store_free=store_free,
                                root_free=root_free, mem_available=available)
        except Exception as exc:
            try:
                pause_for_guard("guard_prerequisite_failure", error=str(exc))
            except Exception as pause_error:
                event("guard_pause_failed", reason=str(exc), pause_error=str(pause_error))
            raise


def watch() -> None:
    require_root()
    while True:
        try:
            watch_once()
        except Exception as exc:
            event("guard_cycle_failed", error=str(exc))
            print(f"winvm01 capguard: {exc}", file=sys.stderr, flush=True)
        time.sleep(5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("start", "stop", "logs", "counters", "delete", "recreate"):
        sub.add_parser(name)
    status_parser = sub.add_parser('status')
    status_parser.add_argument('--all', action='store_true')
    reset_parser = sub.add_parser("reset")
    reset_parser.add_argument("--discard", action="store_true")
    reset_parser.add_argument('--owner-profile', type=pathlib.Path)
    reset_parser.add_argument('--discard-data', action='store_true')
    sub.add_parser("watch")
    args = parser.parse_args()
    require_root()
    if args.command == "start":
        output: Any = start()
    elif args.command == "stop":
        output = stop()
    elif args.command == "status":
        if args.all:
            import instance_registry
            output = instance_registry.list_entries(instance_config()['host_root'])
        else:
            output = status()
    elif args.command == "reset":
        output = reset(args.discard, args.owner_profile, args.discard_data)
    elif args.command == 'delete':
        with lifecycle_lock():
            if owner_pending():
                raise ControllerError('Resume the pending owner operation before deleting the VM definition')
            stop_locked()
            xml=run(['virsh','dumpxml','--inactive',VM]).stdout
            import xml.etree.ElementTree as ET
            assert ET.fromstring(xml).findtext('uuid')==DOMAIN_UUID
            (STORE/'winvm01.xml').write_text(xml)
            run(['virsh','undefine',VM,'--keep-nvram','--keep-tpm'])
            event('definition_deleted_volumes_retained')
            output={'definition':'deleted','disk_and_D_data':'retained'}
    elif args.command == 'recreate':
        with lifecycle_lock():
            if owner_pending():
                raise ControllerError('Resume the pending owner operation before recreating the VM definition')
            if run(['virsh','dominfo',VM],check=False).returncode==0:
                raise ControllerError('VM already defined; use start')
            verify_store_mount();verify_tpm_bind();verify_current_disk()
            path=STORE/'winvm01.xml'
            require_root_helper(path)
            import xml.etree.ElementTree as ET
            root=ET.fromstring(path.read_text())
            if root.findtext('uuid')!=DOMAIN_UUID or root.findtext('name')!=VM:
                raise ControllerError('Saved VM definition identity changed')
            run(['virsh','define','--validate',str(path)])
            event('definition_recreated_volumes_retained')
            output={'definition':'recreated','actual_state':domstate(),'next':'start'}
    elif args.command == "logs":
        output = logs()
    elif args.command == "counters":
        output = counters()
    else:
        watch()
        return 0
    print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ControllerError, RuntimeError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(2)
