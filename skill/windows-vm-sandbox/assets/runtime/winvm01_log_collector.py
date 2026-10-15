#!/usr/bin/env python3
"""Collect sampled winvm01 firewall drops from the host kernel journal.

Only journal MESSAGE values beginning with ``WINVM01 DROP`` are accepted.
The resulting JSONL contains UTC time, route, source/destination IPs and
ports, interfaces, and a sanitized kernel message.  It deliberately does not
copy packet payloads or arbitrary journal text.  Firewall DROP counters remain
available separately through ``winvm01_network.py counters``.

The output path is expected to be a symlink into the VM storage mount:
``/home/vm_run/logs`` -> ``/home/vm_run/vol/logs``.  The collector
exits before writing if the exact mount is absent, the symlink resolves
elsewhere, ownership is not root, or the mount's free space is abnormal.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


LOG_LINK = Path("/home/vm_run/logs")
EXPECTED_MOUNT = Path("/home/vm_run/vol")
EXPECTED_LOG_DIR = EXPECTED_MOUNT / "logs"
MAX_BYTES = 10 * 1024 * 1024
MAX_FILES = 5  # base file plus .1 through .4: 50 MiB maximum
DEFAULT_MIN_FREE_BYTES = 1 * 1024 * 1024 * 1024
MOUNT_CHECK_SECONDS = 5.0
MESSAGE_PREFIX = "WINVM01 DROP"
SAFE_FIELDS = ("IN", "OUT", "SRC", "DST", "PROTO", "SPT", "DPT")
KEY_VALUE = re.compile(r"(?P<key>[A-Z][A-Z0-9_]*)=(?P<value>[^\s]+)")


class CollectorError(RuntimeError):
    pass


def require_root() -> None:
    if os.geteuid() != 0:
        raise CollectorError("the kernel journal collector must run as root")


def mountpoints() -> set[str]:
    """Read mountpoint names without invoking a shell or trusting mount output."""

    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise CollectorError(f"cannot read /proc/self/mountinfo: {exc}") from exc
    found: set[str] = set()
    for line in lines:
        fields = line.split(" - ", 1)[0].split()
        if len(fields) < 6:
            continue
        # mountinfo escapes spaces as octal sequences.
        found.add(fields[4].replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\"))
    return found


def verify_log_mount() -> None:
    """Reject every path fallback that could write logs to the root filesystem."""

    if str(EXPECTED_MOUNT) not in mountpoints():
        raise CollectorError(f"required exact mount is absent: {EXPECTED_MOUNT}")
    if not EXPECTED_MOUNT.is_dir():
        raise CollectorError(f"required mount is not a directory: {EXPECTED_MOUNT}")
    if not LOG_LINK.exists() or not LOG_LINK.is_dir():
        raise CollectorError(f"log path is missing or not a directory: {LOG_LINK}")
    try:
        resolved_log = LOG_LINK.resolve(strict=True)
    except OSError as exc:
        raise CollectorError(f"cannot resolve log path {LOG_LINK}: {exc}") from exc
    if resolved_log != EXPECTED_LOG_DIR:
        raise CollectorError(f"log path resolves to {resolved_log}, expected {EXPECTED_LOG_DIR}")
    try:
        mount_stat = EXPECTED_MOUNT.stat()
        log_stat = resolved_log.stat()
    except OSError as exc:
        raise CollectorError(f"cannot stat storage mount/log directory: {exc}") from exc
    if mount_stat.st_dev != log_stat.st_dev:
        raise CollectorError("log directory is outside the expected storage mount device")
    if mount_stat.st_uid != 0 or log_stat.st_uid != 0:
        raise CollectorError("storage mount and log directory must be root-owned")


def check_free_space(min_free_bytes: int) -> None:
    try:
        free = shutil.disk_usage(EXPECTED_MOUNT).free
    except OSError as exc:
        raise CollectorError(f"cannot read storage free space: {exc}") from exc
    if free < min_free_bytes:
        raise CollectorError(f"storage free space {free} is below guard {min_free_bytes}")


def ensure_log_dir(min_free_bytes: int) -> None:
    verify_log_mount()
    # Creation is allowed only after the mount and resolved destination have
    # been validated; there is intentionally no root-filesystem fallback.
    verify_log_mount()
    check_free_space(min_free_bytes)
    os.chmod(EXPECTED_LOG_DIR, 0o750)


def utc_datetime(entry: dict[str, Any]) -> str:
    raw = entry.get("__REALTIME_TIMESTAMP") or entry.get("_SOURCE_REALTIME_TIMESTAMP")
    try:
        timestamp = int(str(raw)) / 1_000_000
        value = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError):
        value = datetime.now(timezone.utc)
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_message(entry: dict[str, Any]) -> dict[str, Any] | None:
    message = entry.get("MESSAGE")
    if not isinstance(message, str) or not message.startswith(MESSAGE_PREFIX):
        return None
    match = re.match(r"^(WINVM01 DROP \S+)(?:\s|$)", message)
    if not match:
        return None
    route = match.group(1).split()[2]
    fields: dict[str, str] = {}
    safe_tokens: list[str] = []
    for field in KEY_VALUE.finditer(message):
        key = field.group("key")
        if key in SAFE_FIELDS:
            value = field.group("value")
            fields[key] = value
            safe_tokens.append(f"{key}={value}")

    def port(name: str) -> int | None:
        value = fields.get(name)
        return int(value) if value and value.isdigit() and int(value) <= 65535 else None

    # rawmessage is deliberately reconstructed from a fixed prefix and safe
    # kernel metadata, so packet payloads/password-like arbitrary text cannot
    # be copied into the log.
    safe_raw = match.group(1)
    if safe_tokens:
        safe_raw += " " + " ".join(safe_tokens)
    return {
        "datetime": utc_datetime(entry),
        "route": route,
        "ip": {"src": fields.get("SRC"), "dst": fields.get("DST")},
        "ports": {"src": port("SPT"), "dst": port("DPT")},
        "interfaces": {"in": fields.get("IN"), "out": fields.get("OUT")},
        "rawmessage": safe_raw[:2048],
    }


def rotate_files() -> None:
    oldest = EXPECTED_LOG_DIR / f"network-blocks.jsonl.{MAX_FILES - 1}"
    try:
        if oldest.exists() or oldest.is_symlink():
            oldest.unlink()
        for index in range(MAX_FILES - 2, 0, -1):
            source = EXPECTED_LOG_DIR / f"network-blocks.jsonl.{index}"
            target = EXPECTED_LOG_DIR / f"network-blocks.jsonl.{index + 1}"
            if source.exists() or source.is_symlink():
                os.replace(source, target)
        current = EXPECTED_LOG_DIR / "network-blocks.jsonl"
        if current.exists() or current.is_symlink():
            os.replace(current, EXPECTED_LOG_DIR / "network-blocks.jsonl.1")
    except OSError as exc:
        raise CollectorError(f"log rotation failed: {exc}") from exc


def append_record(record: dict[str, Any], min_free_bytes: int) -> None:
    ensure_log_dir(min_free_bytes)
    payload = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    path = EXPECTED_LOG_DIR / "network-blocks.jsonl"
    try:
        current_size = path.stat().st_size if path.exists() else 0
    except OSError as exc:
        raise CollectorError(f"cannot stat log file: {exc}") from exc
    if current_size and current_size + len(payload) > MAX_BYTES:
        rotate_files()
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o640)
        try:
            os.fchmod(fd, 0o640)
            with os.fdopen(fd, "ab", closefd=True) as handle:
                handle.write(payload)
        except Exception:
            os.close(fd)
            raise
    except OSError as exc:
        raise CollectorError(f"cannot append network log: {exc}") from exc


def guard_loop(
    stop: threading.Event,
    error: list[BaseException],
    min_free_bytes: int,
    process_holder: list[subprocess.Popen[str]],
) -> None:
    while not stop.wait(MOUNT_CHECK_SECONDS):
        try:
            verify_log_mount()
            check_free_space(min_free_bytes)
        except BaseException as exc:  # propagate any guard failure to main loop
            error.append(exc)
            if process_holder and process_holder[0].poll() is None:
                process_holder[0].terminate()
            return


def journal_lines(process_holder: list[subprocess.Popen[str]]) -> Iterable[str]:
    try:
        process = subprocess.Popen(
            ["journalctl", "-k", "-f", "-ojson", "--no-pager"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except OSError as exc:
        raise CollectorError(f"cannot start journalctl: {exc}") from exc
    process_holder.append(process)
    try:
        if process.stdout is None:
            raise CollectorError("journalctl did not provide stdout")
        for line in process.stdout:
            yield line
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def run(min_free_bytes: int) -> None:
    require_root()
    ensure_log_dir(min_free_bytes)
    stop = threading.Event()
    guard_errors: list[BaseException] = []
    process_holder: list[subprocess.Popen[str]] = []
    guard = threading.Thread(
        target=guard_loop,
        args=(stop, guard_errors, min_free_bytes, process_holder),
        daemon=True,
    )
    guard.start()
    try:
        for line in journal_lines(process_holder):
            if guard_errors:
                raise CollectorError(str(guard_errors[0]))
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue
            record = parse_message(entry)
            if record is not None:
                append_record(record, min_free_bytes)
        if guard_errors:
            raise CollectorError(str(guard_errors[0]))
    finally:
        stop.set()
        guard.join(timeout=MOUNT_CHECK_SECONDS + 1)


def print_systemd_unit() -> None:
    print("""[Unit]
Description=Collect winvm01 firewall drop samples
After=systemd-journald.service
Requires=systemd-journald.service

[Service]
Type=simple
User=root
Group=root
UMask=027
ExecStart=/usr/bin/python3 /home/vm_run/scripts/lib/winvm01_log_collector.py run
Restart=always
RestartSec=2
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/home/vm_run/logs /home/vm_run/vol/logs

[Install]
WantedBy=multi-user.target
""")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "systemd-unit"), nargs="?", default="run")
    parser.add_argument("--min-free-bytes", type=int, default=DEFAULT_MIN_FREE_BYTES)
    args = parser.parse_args()
    try:
        if args.min_free_bytes < MAX_BYTES:
            raise CollectorError("--min-free-bytes must exceed one 10 MiB log file")
        if args.action == "systemd-unit":
            print_systemd_unit()
        else:
            run(args.min_free_bytes)
        return 0
    except (CollectorError, KeyboardInterrupt) as exc:
        if isinstance(exc, KeyboardInterrupt):
            return 130
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
