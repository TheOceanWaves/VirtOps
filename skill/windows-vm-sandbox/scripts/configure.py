#!/usr/bin/env python3
"""Resize an existing VM through the installed VirtOps agent backend.

The command is deliberately a dry-run unless ``--apply`` is supplied.  It
changes resource reservations only; guest accounts and disks are outside its
scope.  No password is accepted on the command line.
"""
from __future__ import annotations

import argparse
import base64
import copy
import json
from pathlib import Path
import subprocess
import sys

import importlib.util

_profile_spec = importlib.util.spec_from_file_location("virtops_profile", Path(__file__).with_name("profile.py"))
if _profile_spec is None or _profile_spec.loader is None:
    raise RuntimeError("profile helper is unavailable")
_profile_module = importlib.util.module_from_spec(_profile_spec)
_profile_spec.loader.exec_module(_profile_module)
load = _profile_module.load


def _profile(path: Path) -> dict:
    return load(path, new=False)


def desired_profile(current: dict, args: argparse.Namespace) -> dict:
    result = copy.deepcopy(current)
    if args.desired_profile:
        candidate = _profile(args.desired_profile)
        for key in ("name", "uuid", "root", "host_root", "ssh", "network", "windows", "credentials", "gpu", "media"):
            if candidate.get(key) != current.get(key):
                raise ValueError(f"desired profile may change resources only: {key}")
        result["resources"] = copy.deepcopy(candidate["resources"])
        result["limits"] = copy.deepcopy(candidate["limits"])
        if result['resources']['storage_gib']!=current['resources']['storage_gib']:
            raise ValueError('configure does not resize instance disks or storage budgets')
        if any(result['limits'][key]!=current['limits'][key] for key in current['limits'] if key!='start_free_gib'):
            raise ValueError('configure only changes the cold-start memory gate; other limits remain unchanged')
    resources = result["resources"]
    limits = result["limits"]
    for option, field in (("memory_gib", "memory_gib"), ("vcpus", "vcpus"),
                          ("host_limit_gib", "host_limit_gib"), ("cpu_set", "cpu_set")):
        value = getattr(args, option)
        if value is not None:
            resources[field] = value
    if args.start_free_gib is not None:
        limits["start_free_gib"] = args.start_free_gib
    if resources.get("cpu_set"):
        resources["cpu_order"] = _profile_module.cpus(resources["cpu_set"])
    if resources == current["resources"] and limits == current["limits"]:
        raise ValueError("no resource changes requested")
    # profile validation catches host-limit, CPU-set and admission invariants.
    _profile_module.validate(result, new=False)
    return result


def ssh_command(data: dict) -> list[str]:
    ssh = data["ssh"]
    command = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-p", str(ssh.get("port", 22))]
    if ssh.get("bind_address"):
        command += ["-o", "BindAddress=" + ssh["bind_address"]]
    if ssh.get("identity_file"):
        command += ["-i", ssh["identity_file"]]
    command += [ssh["user"] + "@" + ssh["host"]]
    command += ["sudo", "-n", "python3", "-"] if ssh.get("sudo", True) else ["python3", "-"]
    return command


def invoke(data: dict, desired: dict, *, apply: bool, stop: bool, restart: bool) -> int:
    request = {"profile": data, "desired": desired, "action": "configure",
               "apply": apply, "stop": stop, "restart": restart}
    payload = base64.b64encode(json.dumps(request, sort_keys=True).encode()).decode()
    source = "from __future__ import annotations\nimport base64,json\nREQUEST=json.loads(base64.b64decode(" + repr(payload) + "))\n"
    source += (Path(__file__).with_name("configure_remote.py")).read_text(encoding="utf-8").replace('from __future__ import annotations\n','',1)
    result = subprocess.run(ssh_command(data), input=source, text=True, capture_output=True,
                             timeout=3800 if apply else 180, check=False)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--desired-profile", type=Path)
    parser.add_argument("--memory-gib", type=int)
    parser.add_argument("--vcpus", type=int)
    parser.add_argument("--host-limit-gib", type=int)
    parser.add_argument("--cpu-set")
    parser.add_argument("--start-free-gib", type=int)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--stop", action="store_true", help="authorize clean stop when offline resize requires it")
    parser.add_argument("--restart", action="store_true", help="restart only if the VM was running before resize")
    args = parser.parse_args()
    try:
        current = _profile(args.profile)
        desired = desired_profile(current, args)
        if not args.apply:
            return invoke(current, desired, apply=False, stop=False, restart=False)
        return invoke(current, desired, apply=True, stop=args.stop, restart=args.restart)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "blocked", "reason": str(exc)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
