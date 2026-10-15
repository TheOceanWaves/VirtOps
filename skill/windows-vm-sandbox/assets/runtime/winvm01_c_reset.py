#!/usr/bin/env python3
"""Offline C-partition capture/reset for winvm01.

This helper never mounts NTFS in the Linux kernel and never edits the GPT.
It exports an exact C-partition byte range through qemu-nbd, so mkntfs and
wimlib can only address C.  D, ESP, GPT and TPM/NVRAM are outside that range.

The controller must first write a root-owned context JSON under the bounded
store.  Required shape (values are examples)::

    {
      "vm": "winvm01",
      "disk_path": "/home/vm_run/vol/current.qcow2",
      "qga_verified": true,
      "security": {"c_fully_decrypted": true,
                    "c_protection_off": true,
                    "c_efs_encrypted": false, "d_encrypted": false},
      "disk": {"disk_guid": "...", "gpt_header_crc32": "0x...",
                "partitions": {"C": {"index": 3, "start_bytes": 1048576,
                "size_bytes": 100000, "unique_guid": "...",
                "ntfs_serial": "0123456789abcdef"}, "D": {
                "index": 4, "start_bytes": 200000, "size_bytes": 100000,
                "unique_guid": "...", "ntfs_serial": "..."}}},
      "d_validation": {"sentinels": [{"path": "D:\\...",
                                        "sha256": "64-hex-digest"}]},
      "efi": {"start_bytes": 1048576, "size_bytes": 1048576,
              "sentinel_hash": "..."}
    }

The context is evidence supplied by QGA/controller code; this file does not
guess partition indexes or drive letters.  ``reset --discard`` intentionally
does not back up the current C files.  A failed reset leaves a recovery marker
and the VM stopped; rerunning reset retries the baseline WIM.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import time
import uuid
import zlib
import xml.etree.ElementTree as ET


VM = "winvm01"
DOMAIN_UUID = "8cb9f0f6-3d77-4c1c-8d0b-5ab70ac5f201"
STORE = pathlib.Path("/home/vm_run/vol")
STORE_FILE = pathlib.Path("/home/vm_run/.storage/winvm01.store")
CURRENT = STORE / "current.qcow2"
RECOVERY = STORE / "recovery"
BASELINE_WIM = RECOVERY / "initial-C.wim"
BASELINE_META = RECOVERY / "initial-C.json"
MARKER = RECOVERY / "c-reset-in-progress.json"
WIM_CONFIG = RECOVERY / "initial-C-excludes.conf"
STORE_FREE_MIN = 10 * 1024**3
STORE_BYTES = 150 * 1024**3
DISK_BYTES = 150 * 1024**3
SECTOR = 512
MAX_QEMU_DD_TEMP_BYTES = 1 * 1024**3


def fail(message: str) -> "NoReturn":
    raise RuntimeError(message)


def run(argv: list[str], *, check: bool = True, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=check, text=True, capture_output=True, timeout=timeout)


def run_bytes(argv: list[str], *, timeout: int = 120) -> bytes:
    return subprocess.run(argv, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout).stdout


def low_priority(argv: list[str]) -> list[str]:
    prefix: list[str] = []
    if shutil.which("ionice"):
        prefix.extend(["ionice", "-c2", "-n7"])
    if shutil.which("nice"):
        prefix.extend(["nice", "-n", "10"])
    return prefix + argv


def root_only() -> None:
    if os.geteuid() != 0:
        fail("root is required")


def bounded_file(path: pathlib.Path) -> None:
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(STORE.resolve()):
        fail(f"path is absent, symlinked, or outside the bounded store: {path}")


def check_store() -> None:
    if not STORE.is_dir() or not RECOVERY.is_dir():
        fail("bounded VM store/recovery directory is absent")
    mount = run(["findmnt", "-rn", "--mountpoint", str(STORE), "-o", "SOURCE,FSTYPE"], check=False)
    fields = mount.stdout.strip().split()
    if mount.returncode or len(fields) != 2 or fields[1] != "ext4" or not fields[0].startswith("/dev/"):
        fail("VM store is not the approved ext4 mount")
    loops = json.loads(run(["losetup", "--list", "--json", "--output", "NAME,BACK-FILE"]).stdout)
    matches = [item for item in loops.get("loopdevices", []) if item.get("name") == fields[0]]
    if len(matches) != 1 or pathlib.Path(matches[0].get("back-file", "")).resolve() != STORE_FILE.resolve():
        fail("VM store is not backed by the approved loop file")
    if STORE_FILE.stat().st_size != STORE_BYTES:
        fail("VM store backing file is not exactly 150 GiB")
    free = os.statvfs(STORE).f_bavail * os.statvfs(STORE).f_frsize
    if free < STORE_FREE_MIN:
        fail(f"outer store free space is below 10 GiB: {free / 1024**3:.2f} GiB")


def load_context(path: pathlib.Path) -> dict[str, object]:
    bounded_file(path)
    stat = path.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o022:
        fail("context must be root-owned and not group/other writable")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read context: {exc}")
    if data.get("vm") != VM or data.get("disk_path") != str(CURRENT):
        fail("context does not identify winvm01/current.qcow2")
    if data.get("qga_verified") is not True:
        fail("context is not marked QGA-verified")
    return data


def security(context: dict[str, object]) -> dict[str, object]:
    value = context.get("security")
    if not isinstance(value, dict):
        fail("context.security is required")
    if value.get("c_fully_decrypted") is not True or value.get("c_protection_off") is not True:
        fail("QGA must confirm C is fully decrypted and BitLocker protection is off")
    if value.get("c_efs_encrypted") is not False:
        fail("QGA must confirm C has no EFS-encrypted files")
    return value


def partitions(context: dict[str, object], *, require_d: bool = False) -> dict[str, dict[str, object]]:
    disk = context.get("disk")
    if not isinstance(disk, dict) or not isinstance(disk.get("partitions"), dict):
        fail("context.disk.partitions is required")
    value = disk["partitions"]
    result: dict[str, dict[str, object]] = {}
    for letter in ("C", "D"):
        item = value.get(letter)
        if not isinstance(item, dict):
            if letter == "D" and not require_d:
                continue
            fail(f"context is missing partition {letter}")
        fields = ("index", "start_bytes", "size_bytes", "unique_guid", "ntfs_serial")
        for field in fields:
            if field not in item:
                fail(f"partition {letter} is missing {field}")
        result[letter] = item
    return result


def disk_meta(context: dict[str, object]) -> dict[str, object]:
    disk = context.get("disk")
    if not isinstance(disk, dict) or not disk.get("disk_guid") or disk.get("gpt_header_crc32") is None:
        fail("context disk_guid and gpt_header_crc32 are required")
    return disk


def immutable_evidence(context: dict[str, object], *, require_d: bool) -> tuple[str | None, dict[str, object]]:
    parts = partitions(context, require_d=require_d)
    d_hash = parts.get("D", {}).get("sentinel_hash")
    if require_d and (not isinstance(d_hash, str) or not d_hash):
        fail("trusted reset context must contain D sentinel evidence")
    efi = context.get("efi")
    if not isinstance(efi, dict) or not isinstance(efi.get("sentinel_hash"), str):
        fail("trusted context must contain EFI geometry and sentinel hash")
    for field in ("start_bytes", "size_bytes"):
        if field not in efi:
            fail(f"context.efi is missing {field}")
    return d_hash if isinstance(d_hash, str) else None, efi


def reset_request(context: dict[str, object], baseline: dict[str, object]) -> dict[str, object]:
    """Build the postboot projection consumed by the Windows SYSTEM task."""
    disk = context.get("disk")
    if not isinstance(disk, dict) or not isinstance(disk.get("partitions"), dict):
        fail("context.disk.partitions is required for reset request")
    source_parts = disk["partitions"]
    c_source = source_parts.get("C")
    if not isinstance(c_source, dict):
        fail("context is missing C for reset request")
    c = dict(c_source)
    c["ntfs_serial"] = normalize_ntfs_serial(baseline["c_ntfs_serial"])
    projected_parts: dict[str, object] = {"C": c}
    d_source = source_parts.get("D")
    if isinstance(d_source, dict):
        d_validation = require_d_validation(context)
        projected_parts["D"] = dict(d_source)
    projected_disk: dict[str, object] = {
        "disk_guid": disk.get("disk_guid"),
        "size_bytes": DISK_BYTES,
        "partitions": projected_parts,
    }
    request: dict[str, object] = {
        "schema_version": 1,
        "request_id": uuid.uuid4().hex,
        "reason": "winvm01-c-factory-reset",
        "created_unix": time.time(),
        "disk": projected_disk,
    }
    if isinstance(d_source, dict):
        request["d_validation"] = d_validation
    return request


def require_d_validation(context: dict[str, object]) -> dict[str, object]:
    value = context.get("d_validation")
    sentinels = value.get("sentinels") if isinstance(value, dict) else None
    if not isinstance(value, dict) or not isinstance(sentinels, list) or not sentinels:
        fail("D exists but trusted d_validation.sentinels are missing")
    for item in sentinels:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not item["path"].upper().startswith("D:\\"):
            fail("D validation sentinel path is invalid")
        digest = item.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdefABCDEF" for char in digest):
            fail("D validation sentinel sha256 is invalid")
    return value


def normalize_guid(value: object) -> str:
    try:
        return str(uuid.UUID(str(value))).lower()
    except ValueError as exc:
        fail(f"invalid GUID: {value}: {exc}")


def number(value: object) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def qemu_info() -> dict[str, object]:
    bounded_file(CURRENT)
    data = json.loads(run(["qemu-img", "info", "--output=json", str(CURRENT)]).stdout)
    if data.get("format") != "qcow2" or int(data.get("virtual-size", -1)) != DISK_BYTES:
        fail("current.qcow2 is not the expected 150 GiB qcow2")
    if data.get("backing-filename") or data.get("full-backing-filename"):
        fail("current.qcow2 must have no backing file")
    return data


def domain_disk_guard() -> None:
    xml = run(["virsh", "-c", "qemu:///system", "dumpxml", "--inactive", VM]).stdout
    root = ET.fromstring(xml)
    uuid_node = root.find("uuid")
    if uuid_node is None or uuid_node.text.strip().lower() != DOMAIN_UUID:
        fail("libvirt domain UUID does not match winvm01")
    sources = []
    for disk in root.findall("./devices/disk"):
        if disk.get("device") != "disk":
            continue
        source = disk.find("source")
        if source is not None and source.get("file"):
            sources.append(pathlib.Path(source.get("file")).resolve())
    if len(sources) != 1 or sources[0] != CURRENT.resolve():
        fail("inactive XML does not point exactly one system disk at current.qcow2")


def domain_off() -> None:
    result = run(["virsh", "-c", "qemu:///system", "domstate", VM], check=False)
    if result.returncode or result.stdout.strip().lower() not in {"shut off", "shutoff"}:
        fail(f"{VM} must be shut off")


def nbd_candidates() -> list[pathlib.Path]:
    parameter = pathlib.Path("/sys/module/nbd/parameters/max_part")
    if not parameter.exists():
        # The module is unused if absent. Load it safely after a host reboot;
        # never unload or reconfigure an existing user's NBD devices.
        run(['modprobe', 'nbd', 'max_part=0'])
    if not parameter.is_file() or parameter.read_text(encoding="ascii").strip() != "0":
        fail("nbd max_part must be 0; kernel partition probing is forbidden")
    result = []
    for sysdev in sorted(pathlib.Path("/sys/block").glob("nbd*")):
        name = sysdev.name
        pid = sysdev / "pid"
        holders = sysdev / "holders"
        if pid.exists() and pid.read_text(encoding="ascii").strip():
            continue
        if holders.exists() and any(holders.iterdir()):
            continue
        result.append(pathlib.Path("/dev") / name)
    if not result:
        fail("no free /dev/nbd device")
    return result


@contextlib.contextmanager
def clipped_nbd(offset: int, size: int, *, readonly: bool):
    if offset < 0 or size <= 0 or offset % SECTOR or size % SECTOR:
        fail("NBD clip must be positive and sector aligned")
    device = nbd_candidates()[0]
    options = f"driver=raw,file.driver=qcow2,file.file.filename={CURRENT},offset={offset},size={size}"
    command = ["qemu-nbd", "--connect", str(device), "--image-opts", options]
    if readonly:
        command.insert(1, "--read-only")
    run(command, timeout=60)
    try:
        deadline = time.monotonic() + 10
        actual = 0
        while time.monotonic() < deadline:
            actual = int(run(["blockdev", "--getsize64", str(device)]).stdout.strip())
            if actual == size:
                break
            if actual not in (0, size):
                break
            time.sleep(0.1)
        if actual != size:
            fail(f"NBD clip size mismatch: {actual} != {size}; D write boundary unsafe")
        yield device
    finally:
        run(["qemu-nbd", "--disconnect", str(device)], check=False, timeout=60)


@contextlib.contextmanager
def qemu_clip_file(offset_sectors: int, count_sectors: int, *, timeout: int = 120):
    """Read an exact qcow2 byte clip into a bounded regular file, never a pipe."""
    if offset_sectors < 0 or count_sectors <= 0:
        fail("qemu-img clip range is invalid")
    expected = count_sectors * SECTOR
    if expected > MAX_QEMU_DD_TEMP_BYTES:
        fail("qemu-img clip temporary range exceeds the 1 GiB safety bound")
    RECOVERY.mkdir(parents=True, exist_ok=True)
    path = RECOVERY / f".qemu-dd-{os.getpid()}-{time.time_ns()}-{uuid.uuid4().hex}.bin"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    os.close(descriptor)
    try:
        offset_bytes = offset_sectors * SECTOR
        image_options = (f"driver=raw,file.driver=qcow2,file.file.filename={CURRENT},"
                         f"offset={offset_bytes},size={expected}")
        run(["qemu-img", "convert", "--image-opts", image_options, "-O", "raw", str(path)],
            timeout=timeout)
        bounded_file(path)
        if path.stat().st_size != expected:
            fail(f"qemu-img clip output size mismatch: {path.stat().st_size} != {expected}")
        yield path
    finally:
        path.unlink(missing_ok=True)


def gpt_bytes(offset_sectors: int, count_sectors: int) -> bytes:
    with qemu_clip_file(offset_sectors, count_sectors) as path:
        return path.read_bytes()


def hash_virtual_range(offset: int, size: int) -> str:
    if offset < 0 or size <= 0 or offset % SECTOR or size % SECTOR:
        fail("EFI range is not sector aligned")
    digest = hashlib.sha256()
    with qemu_clip_file(offset // SECTOR, size // SECTOR, timeout=600) as path:
        with path.open("rb", buffering=1024 * 1024) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def read_gpt(context: dict[str, object]) -> dict[str, object]:
    primary, discovered = read_gpt_pair()
    disk_guid = str(primary["disk_guid"])
    stored_crc = int(primary["header_crc32"])
    parts: dict[str, dict[str, object]] = {}
    expected = partitions(context)
    for letter, wanted in expected.items():
        index = number(wanted["index"])
        matches = [item for item in discovered if int(item["index"]) == index]
        if len(matches) != 1:
            fail(f"partition {letter} index is outside GPT")
        observed = {key: matches[0][key] for key in ("index", "unique_guid", "start_bytes", "size_bytes")}
        for key in ("unique_guid", "start_bytes", "size_bytes"):
            expected_value = normalize_guid(wanted[key]) if key == "unique_guid" else number(wanted[key])
            if observed[key] != expected_value:
                fail(f"GPT partition {letter} {key} mismatch: {observed[key]} != {expected_value}")
        parts[letter] = observed
    disk = disk_meta(context)
    if disk_guid != normalize_guid(disk["disk_guid"]):
        fail("GPT disk GUID mismatch")
    expected_crc = number(disk["gpt_header_crc32"])
    if stored_crc != expected_crc:
        fail(f"GPT header CRC differs from trusted context: {stored_crc:#x} != {expected_crc:#x}")
    return {"disk_guid": disk_guid, "header_crc32": stored_crc, "partitions": parts}


def parse_gpt_header(header: bytes, expected_lba: int, label: str) -> dict[str, object]:
    if header[:8] != b"EFI PART":
        fail(f"{label} GPT signature is absent")
    header_size = struct.unpack_from("<I", header, 12)[0]
    if header_size < 92 or header_size > SECTOR:
        fail(f"invalid {label} GPT header size")
    stored_crc = struct.unpack_from("<I", header, 16)[0]
    crc_header = bytearray(header[:header_size])
    struct.pack_into("<I", crc_header, 16, 0)
    actual_crc = zlib.crc32(crc_header) & 0xffffffff
    if actual_crc != stored_crc:
        fail(f"{label} GPT header CRC mismatch: {actual_crc:#x} != {stored_crc:#x}")
    current_lba, backup_lba = struct.unpack_from("<QQ", header, 24)
    if current_lba != expected_lba or backup_lba >= DISK_BYTES // SECTOR:
        fail(f"{label} GPT header locations are invalid")
    entries_lba, count, entry_size, array_crc = struct.unpack_from("<QIII", header, 72)
    array_sectors = (count * entry_size + SECTOR - 1) // SECTOR
    if count < 1 or count > 4096 or entry_size < 128 or entry_size > 1024:
        fail(f"{label} GPT partition table dimensions are unsafe")
    if array_sectors * SECTOR > 4 * 1024**2 or (entries_lba + array_sectors) * SECTOR > DISK_BYTES:
        fail(f"{label} GPT partition table lies outside the 150 GiB disk")
    return {"disk_guid": str(uuid.UUID(bytes_le=header[56:72])).lower(),
            "current_lba": current_lba, "backup_lba": backup_lba,
            "entries_lba": entries_lba, "count": count, "entry_size": entry_size,
            "array_crc": array_crc, "header_crc32": stored_crc,
            "array_sectors": array_sectors}


def parse_gpt_entries(entries: bytes, metadata: dict[str, object]) -> list[dict[str, object]]:
    count = int(metadata["count"]); entry_size = int(metadata["entry_size"])
    max_lba = DISK_BYTES // SECTOR - 1
    intervals: list[tuple[int, int, int]] = []
    partitions_out: list[dict[str, object]] = []
    for position in range(count):
        entry = entries[position * entry_size:(position + 1) * entry_size]
        if len(entry) < entry_size or entry[:16] == b"\x00" * 16:
            continue
        first_lba, last_lba = struct.unpack_from("<QQ", entry, 32)
        if first_lba > last_lba or last_lba > max_lba:
            fail("GPT partition lies outside the virtual disk")
        intervals.append((first_lba, last_lba, position + 1))
        name = entry[56:entry_size].decode("utf-16le", errors="ignore").rstrip("\x00")
        partitions_out.append({
            "index": position + 1,
            "type_guid": str(uuid.UUID(bytes_le=entry[:16])).lower(),
            "unique_guid": str(uuid.UUID(bytes_le=entry[16:32])).lower(),
            "start_bytes": first_lba * SECTOR,
            "size_bytes": (last_lba - first_lba + 1) * SECTOR,
            "name": name,
        })
    for left, right in zip(sorted(intervals), sorted(intervals)[1:]):
        if right[0] <= left[1]:
            fail(f"GPT partitions overlap: {left[2]} and {right[2]}")
    return partitions_out


def read_gpt_pair() -> tuple[dict[str, object], list[dict[str, object]]]:
    """Read and cross-check both GPT headers and both partition arrays."""
    primary = parse_gpt_header(gpt_bytes(1, 1), 1, "primary")
    backup_lba = int(primary["backup_lba"])
    if backup_lba != DISK_BYTES // SECTOR - 1:
        fail("GPT backup header is not at the end of the 150 GiB disk")
    backup = parse_gpt_header(gpt_bytes(backup_lba, 1), backup_lba, "backup")
    if int(backup["backup_lba"]) != 1 or backup["disk_guid"] != primary["disk_guid"]:
        fail("GPT primary/backup header identity mismatch")
    for key in ("count", "entry_size", "array_crc"):
        if backup[key] != primary[key]:
            fail(f"GPT primary/backup {key} mismatch")
    primary_entries = gpt_bytes(int(primary["entries_lba"]), int(primary["array_sectors"]))
    backup_entries = gpt_bytes(int(backup["entries_lba"]), int(backup["array_sectors"]))
    for label, entries, metadata in (("primary", primary_entries, primary), ("backup", backup_entries, backup)):
        if (zlib.crc32(entries[:int(metadata["count"]) * int(metadata["entry_size"])]) & 0xffffffff) != int(metadata["array_crc"]):
            fail(f"{label} GPT partition array CRC mismatch")
    if primary_entries != backup_entries:
        fail("GPT primary/backup partition arrays differ")
    return primary, parse_gpt_entries(primary_entries, primary)


def virtual_range_bytes(offset: int, size: int) -> bytes:
    if offset < 0 or size <= 0 or offset % SECTOR or size % SECTOR:
        fail("virtual range is not sector aligned")
    with qemu_clip_file(offset // SECTOR, size // SECTOR) as path:
        return path.read_bytes()


def probe_gpt_bootstrap(c_index: int | None) -> None:
    """Produce first evidence without requiring a pre-populated trusted context."""
    root_only(); check_store(); domain_off(); domain_disk_guard(); qemu_info()
    primary, discovered = read_gpt_pair()
    ntfs_partitions: list[dict[str, object]] = []
    efi_partition: dict[str, object] | None = None
    efi_type = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
    for item in discovered:
        start = int(item["start_bytes"]); size = int(item["size_bytes"])
        boot = virtual_range_bytes(start, SECTOR)
        if boot[3:11] == b"NTFS    ":
            serial = struct.unpack_from("<Q", boot, 72)[0]
            ntfs_partitions.append({**item, "ntfs_serial": f"{serial:016x}"})
        if str(item["type_guid"]) == efi_type:
            efi_partition = {**item, "sentinel_hash": hash_virtual_range(start, size)}
    selected_c: dict[str, object] | None = None
    if c_index is not None:
        selected = [item for item in ntfs_partitions if int(item["index"]) == c_index]
        if len(selected) != 1:
            fail("--c-index does not identify exactly one NTFS partition")
        selected_c = selected[0]
    elif len(ntfs_partitions) == 1:
        selected_c = ntfs_partitions[0]
    result: dict[str, object] = {
        "disk_guid": primary["disk_guid"], "size_bytes": DISK_BYTES,
        "gpt_header_crc32": int(primary["header_crc32"]),
        "gpt_primary_backup_verified": True,
        "partitions": discovered, "ntfs_partitions": ntfs_partitions,
        "c_ntfs_serial": selected_c.get("ntfs_serial") if selected_c else None,
        "c_partition": selected_c,
        "efi": efi_partition,
    }
    result["disk"] = {"disk_guid": primary["disk_guid"], "size_bytes": DISK_BYTES,
                       "partitions": discovered}
    print(json.dumps(result, ensure_ascii=False, indent=2))


def ntfs_serial(device: pathlib.Path) -> str:
    with device.open("rb", buffering=0) as stream:
        stream.seek(72)
        raw = stream.read(8)
    if len(raw) != 8:
        fail(f"could not read NTFS boot-sector serial from {device}")
    return f"{struct.unpack('<Q', raw)[0]:016x}"


def require_plain_ntfs(device: pathlib.Path) -> None:
    with device.open("rb", buffering=0) as stream:
        stream.seek(3)
        signature = stream.read(8)
    if signature != b"NTFS    ":
        fail("C clipped device is not an ordinary NTFS volume; encrypted or unknown format refused")


def normalize_ntfs_serial(value: object) -> str:
    serial = str(value).strip().lower()
    if serial.startswith("0x"):
        serial = serial[2:]
    if len(serial) not in (8, 16) or any(char not in "0123456789abcdef" for char in serial):
        fail(f"invalid NTFS serial value: {value}")
    return serial.zfill(16)


def ntfs_serial_matches(expected: object, observed_full64: str) -> bool:
    """Accept Win32's 32-bit VolumeSerialNumber against the full NTFS value."""
    raw_expected = str(expected).strip().lower()
    if raw_expected.startswith("0x"):
        raw_expected = raw_expected[2:]
    expected_serial = normalize_ntfs_serial(raw_expected)
    observed_serial = normalize_ntfs_serial(observed_full64)
    if len(raw_expected) == 8:
        return expected_serial[-8:] == observed_serial[-8:]
    return expected_serial == observed_serial


def parse_wim_total_bytes(xml_bytes: bytes) -> int:
    root = ET.fromstring(xml_bytes)
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1].upper() == "TOTALBYTES" and element.text:
            return int(element.text)
    fail("WIM XML has no total uncompressed byte count")


def wim_total_bytes(path: pathlib.Path = BASELINE_WIM) -> int:
    result = run_bytes(["wimlib-imagex", "info", str(path), "--xml"], timeout=120)
    return parse_wim_total_bytes(result)


def selftest_wim_xml(path: pathlib.Path) -> None:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024**2:
        fail("WIM XML self-test path is absent, symlinked, or exceeds 64 MiB")
    total = parse_wim_total_bytes(path.read_bytes())
    print(json.dumps({"ok": True, "total_bytes": total}, ensure_ascii=False))


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: pathlib.Path, data: dict[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def ensure_wim_config() -> None:
    WIM_CONFIG.write_text(
        "[ExclusionList]\n\\hiberfil.sys\n\\pagefile.sys\n\\swapfile.sys\n"
        "\\System Volume Information\n\\RECYCLER\n",
        encoding="utf-8",
    )
    os.chmod(WIM_CONFIG, 0o600)


def progress(phase: str, detail: str) -> None:
    print(json.dumps({"phase": phase, "detail": detail}, ensure_ascii=False), flush=True)


def capture(context_path: pathlib.Path, replace_baseline: bool = False) -> None:
    root_only(); check_store(); domain_off(); domain_disk_guard()
    context = load_context(context_path); security(context); parts = partitions(context)
    d_sentinel, efi = immutable_evidence(context, require_d=False)
    if replace_baseline:
        bounded_file(BASELINE_WIM); bounded_file(BASELINE_META)
        old_meta = json.loads(BASELINE_META.read_text())
        if sha256(BASELINE_WIM) != old_meta.get('wim_sha256'):
            fail('existing baseline hash is invalid; refusing replacement')
    elif BASELINE_WIM.exists() or BASELINE_META.exists():
        fail("initial C baseline already exists; refusing to overwrite")
    qemu_info(); before = read_gpt(context)
    efi_sentinel = hash_virtual_range(number(efi["start_bytes"]), number(efi["size_bytes"]))
    if efi_sentinel != str(efi["sentinel_hash"]).lower():
        fail("EFI sentinel hash differs from trusted context")
    c = parts["C"]; c_size = number(c["size_bytes"]); c_start = number(c["start_bytes"])
    if c_start % SECTOR or c_size % SECTOR:
        fail("C partition geometry is not sector aligned")
    temp_wim = RECOVERY / f".initial-C-{os.getpid()}-{time.time_ns()}-{uuid.uuid4().hex}.wim"
    installed = False
    try:
        progress("capture", "exporting the exact C byte range read-only")
        with clipped_nbd(c_start, c_size, readonly=True) as device:
            require_plain_ntfs(device)
            observed_serial = ntfs_serial(device)
            if not ntfs_serial_matches(c["ntfs_serial"], observed_serial):
                fail("C NTFS serial differs from trusted QGA context")
            ensure_wim_config()
            run(low_priority(["wimlib-imagex", "capture", str(device), str(temp_wim), "initial-C",
                              "--config", str(WIM_CONFIG), "--check", "--compress=XPRESS",
                              "--threads=4"]), timeout=3600)
        progress("capture", "verifying temporary WIM and GPT after capture")
        bounded_file(temp_wim)
        run(["wimlib-imagex", "verify", str(temp_wim)], timeout=600)
        after = read_gpt(context)
        if after != before:
            fail("GPT changed during read-only capture")
        total = wim_total_bytes(temp_wim)
        if c_size < int(total * 1.2):
            fail("C partition is smaller than baseline uncompressed data plus 20% margin")
        temp_sha256 = sha256(temp_wim)
        if not replace_baseline and (BASELINE_WIM.exists() or BASELINE_META.exists()):
            fail("initial C baseline appeared during capture; refusing to replace it")
        os.chmod(temp_wim, 0o600)
        os.replace(temp_wim, BASELINE_WIM)
        installed = True
        write_json(BASELINE_META, {"vm": VM, "disk": before, "c_size_bytes": c_size,
                                    "c_start_bytes": c_start, "c_ntfs_serial": observed_serial,
                                    "wim_total_bytes": total, "wim_sha256": temp_sha256,
                                    "d_sentinel_hash": d_sentinel, "efi_sentinel_hash": efi_sentinel})
        progress("capture", "baseline initial-C.wim committed")
    except Exception:
        temp_wim.unlink(missing_ok=True)
        if installed and not BASELINE_META.exists():
            BASELINE_WIM.unlink(missing_ok=True)
        raise


def reset(context_path: pathlib.Path, discard: bool) -> None:
    if not discard:
        fail("reset removes the current C contents; repeat with explicit --discard")
    root_only(); check_store(); domain_off(); domain_disk_guard()
    context = load_context(context_path); sec = security(context)
    parts = partitions(context, require_d=False); d_sentinel, efi = immutable_evidence(context, require_d=False)
    if "D" in parts:
        if sec.get("d_encrypted") is not False:
            fail("D encryption status is unsafe or missing; refusing automatic C reset")
        require_d_validation(context)
    qemu_info(); bounded_file(BASELINE_WIM); bounded_file(BASELINE_META)
    baseline = json.loads(BASELINE_META.read_text(encoding="utf-8"))
    baseline_serial = normalize_ntfs_serial(baseline.get("c_ntfs_serial"))
    context_sha256 = sha256(context_path)
    context_collected_unix = context.get("collected_unix")
    if not isinstance(context_collected_unix, (int, float)) or context_collected_unix <= 0:
        fail("trusted context is missing collected_unix for recovery binding")
    before = read_gpt(context)
    baseline_disk = baseline.get("disk")
    if not isinstance(baseline_disk, dict) or baseline_disk.get("disk_guid") != before.get("disk_guid"):
        fail("current GPT disk GUID differs from the captured baseline")
    baseline_c = baseline_disk.get("partitions", {}).get("C", {})
    current_c = before.get("partitions", {}).get("C", {})
    for key in ("unique_guid", "start_bytes"):
        if baseline_c.get(key) != current_c.get(key):
            fail(f"C partition {key} differs from the captured baseline")
    if baseline.get("d_sentinel_hash") is not None and not d_sentinel:
        fail("D sentinel evidence is missing")
    efi_before = hash_virtual_range(number(efi["start_bytes"]), number(efi["size_bytes"]))
    if efi_before != str(efi["sentinel_hash"]).lower():
        fail("EFI content differs from the trusted current context")
    c = parts["C"]; c_size = number(c["size_bytes"]); c_start = number(c["start_bytes"])
    if c_size < int(number(baseline["wim_total_bytes"]) * 1.2):
        fail("C is too small for baseline plus 20% margin")
    free = os.statvfs(STORE).f_bavail * os.statvfs(STORE).f_frsize
    required_free = max(STORE_FREE_MIN, int(number(baseline["wim_total_bytes"]) * 1.2))
    if free < required_free:
        fail(f"outer store free space is insufficient for WIM apply: {free} < {required_free}")
    write_json(MARKER, {"vm": VM, "phase": "recovery-in-progress", "started": time.time(),
                         "discard": True, "baseline": str(BASELINE_WIM), "c_partition": c,
                         "context_sha256": context_sha256,
                         "context_collected_unix": context_collected_unix})
    reset_request_id: str | None = None
    try:
        run(["wimlib-imagex", "verify", str(BASELINE_WIM)], timeout=600)
        if sha256(BASELINE_WIM) != baseline.get("wim_sha256"):
            fail("baseline WIM SHA-256 does not match its trusted metadata")
        progress("reset", "formatting only the clipped C block device")
        with clipped_nbd(c_start, c_size, readonly=False) as device:
            actual = int(run(["blockdev", "--getsize64", str(device)]).stdout.strip())
            if actual != c_size:
                fail("C clip size changed before format; D boundary unsafe")
            require_plain_ntfs(device)
            run(["mkntfs", "-Q", "-L", "Windows", "-p", str(c_start // SECTOR), str(device)], timeout=600)
            run(["ntfslabel", "--new-serial=" + baseline_serial, str(device)], timeout=120)
            if ntfs_serial(device) != baseline_serial:
                fail("C NTFS serial could not be restored to baseline")
            progress("reset", "applying initial-C.wim to C")
            run(["wimlib-imagex", "apply", str(BASELINE_WIM), "1", str(device)], timeout=3600)
            if ntfs_serial(device) != baseline_serial:
                fail("C NTFS serial changed during WIM apply")
            request_path = RECOVERY / f".reset-request-{os.getpid()}-{time.time_ns()}.json"
            try:
                request = reset_request(context, baseline)
                reset_request_id = str(request["request_id"])
                write_json(request_path, request)
                run(["ntfscp", str(device), str(request_path),
                     "/ProgramData/WinVM01/reset-request.json"], timeout=120)
            finally:
                request_path.unlink(missing_ok=True)
        progress("reset", "verifying GPT and C baseline")
        after = read_gpt(context)
        if after.get("disk_guid") != before.get("disk_guid") or after.get("partitions", {}).get("C") != before.get("partitions", {}).get("C"):
            fail("GPT/C partition evidence changed during C reset")
        if "D" in before.get("partitions", {}) and after.get("partitions", {}).get("D") != before.get("partitions", {}).get("D"):
            fail("D partition geometry changed during C reset")
        efi_after = hash_virtual_range(number(efi["start_bytes"]), number(efi["size_bytes"]))
        if efi_after != efi_before:
            fail("EFI content changed during C reset")
        write_json(MARKER, {"vm": VM, "phase": "restore-applied-controller-validation", "completed": time.time(),
                             "gpt": after, "reset_request_id": reset_request_id,
                             "context_sha256": context_sha256,
                             "context_collected_unix": context_collected_unix,
                             "d_qga_evidence_required": True})
        progress("reset", "C restored; controller may perform its EFI/BCD and D QGA validation")
    except Exception as exc:
        write_json(MARKER, {"vm": VM, "phase": "recovery-failed", "error": str(exc), "failed": time.time(),
                             "context_sha256": context_sha256,
                             "context_collected_unix": context_collected_unix})
        raise


def status(context_path: pathlib.Path) -> None:
    root_only(); check_store(); context = load_context(context_path)
    data = {"vm": VM, "domain_state": run(["virsh", "-c", "qemu:///system", "domstate", VM], check=False).stdout.strip(),
            "marker": json.loads(MARKER.read_text(encoding="utf-8")) if MARKER.exists() else None,
            "baseline": str(BASELINE_WIM) if BASELINE_WIM.exists() else None,
            "gpt": read_gpt(context)}
    print(json.dumps(data, ensure_ascii=False, indent=2))


def probe_gpt(context_path: pathlib.Path) -> None:
    root_only(); check_store(); domain_off(); domain_disk_guard()
    context = load_context(context_path)
    print(json.dumps(read_gpt(context), ensure_ascii=False, indent=2))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    cap = sub.add_parser("capture")
    cap.add_argument("--context", required=True, type=pathlib.Path)
    cap.add_argument('--replace-baseline', action='store_true',
                     help='replace an existing verified baseline only after new capture verifies')
    rst = sub.add_parser("reset")
    rst.add_argument("--discard", action="store_true")
    rst.add_argument("--context", required=True, type=pathlib.Path)
    st = sub.add_parser("status")
    st.add_argument("--context", required=True, type=pathlib.Path)
    test_wim = sub.add_parser("selftest-wim-xml")
    test_wim.add_argument("--path", required=True, type=pathlib.Path)
    probe = sub.add_parser("probe-gpt")
    probe.add_argument("--context", type=pathlib.Path)
    probe.add_argument("--bootstrap", action="store_true",
                       help="read-only initial GPT/EFI evidence without trusted CRC context")
    probe.add_argument("--c-index", type=int,
                       help="identify the C NTFS candidate by GPT entry index during --bootstrap")
    args = parser.parse_args()
    if args.command == "capture":
        capture(args.context, args.replace_baseline)
    elif args.command == "reset":
        reset(args.context, args.discard)
    elif args.command == "status":
        status(args.context)
    elif args.command == "selftest-wim-xml":
        selftest_wim_xml(args.path)
    else:
        if args.bootstrap:
            if args.context is not None:
                fail("--bootstrap cannot be combined with --context")
            probe_gpt_bootstrap(args.c_index)
        else:
            if args.context is None or args.c_index is not None:
                fail("probe-gpt requires --context unless --bootstrap is used")
            probe_gpt(args.context)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(2)
