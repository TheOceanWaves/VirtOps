"""Offline tests for the owner transition coordinator and maintenance gate.

These tests replace the QGA, virsh, recovery, and iptables runners with small
fakes.  They never contact a VM, create a real firewall rule, or mutate an
account or disk.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import sys
import types
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "skill" / "windows-vm-sandbox" / "assets" / "runtime"
sys.path.insert(0, str(RUNTIME))


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


oe = load("owner_environment_tested", RUNTIME / "owner_environment.py")
maintenance = load("maintenance_tested", RUNTIME / "maintenance.py")


class Lock:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class FakeQga:
    VM = "testvm"

    def call(self, command, *args, **kwargs):
        if command == "guest-ping":
            return {}
        raise AssertionError(f"unexpected QGA call: {command}")


class FakeRecovery:
    CONTEXT = "context.json"

    def __init__(self, root: Path):
        self.reset_calls = 0
        self.context = root / "context.json"
        self.context.write_text(json.dumps({
            "disk": {"disk_guid": "disk-guid", "partitions": {
                "D": {"unique_guid": "part-guid", "start_bytes": 4096,
                       "size_bytes": 8192, "ntfs_serial": "serial"}
            }}
        }), encoding="utf-8")
        self.CONTEXT = str(self.context)

    def reset(self, ctl, discard, locked=False):
        self.reset_calls += 1

    def collect_context(self, ctl):
        return json.loads(self.context.read_text(encoding="utf-8"))

    def qga_module(self, ctl):
        return FakeQga()


class FakeGate:
    def __init__(self, fail_remove=False):
        self.events = []
        self.fail_remove = fail_remove

    def install(self):
        self.events.append("install")

    def verify(self):
        self.events.append("verify")

    def remove(self):
        self.events.append("remove")
        if self.fail_remove:
            raise RuntimeError("simulated release failure")


class FakeNetwork:
    def __init__(self, gate):
        self.gate = gate

    def maintenance_gate(self):
        return self.gate


class FakeCtl:
    VM = "testvm"
    DOMAIN_UUID = "11111111-1111-4111-8111-111111111111"
    NETWORK = "network.py"

    def __init__(self, root: Path):
        self.STORE = root / "vol"
        (self.STORE / "state" / "private").mkdir(parents=True)
        (self.STORE / "recovery").mkdir()
        (self.STORE.parent / "instance.json").write_text(json.dumps({
            "network": {"winrm_port": 15986}, "windows": {}
        }), encoding="utf-8")
        self.state = "running"
        self.events = []

    def lifecycle_lock(self):
        return Lock()

    def verify_store_mount(self): self.events.append("store")
    def verify_tpm_bind(self): self.events.append("tpm")
    def verify_current_disk(self): self.events.append("disk")
    def verify_services_and_network(self): self.events.append("network")
    def verify_running_cgroup(self): self.events.append("cgroup")
    def domstate(self): return self.state
    def start_locked(self, owner_validation=False): self.state = "running"; self.events.append("start")
    def stop_locked(self): self.state = "shut off"; self.events.append("stop")
    def run(self, args, check=True): self.events.append(tuple(args)); return types.SimpleNamespace(returncode=0)
    def event(self, name, **fields): self.events.append((name, fields))


def owner_profile(ctl, policy="preserve"):
    return {
        "schema_version": 1, "name": ctl.VM, "uuid": ctl.DOMAIN_UUID,
        "admin_user": "alice", "credentials": {"mode": "generate", "secret_file": None},
        "data_policy": policy,
    }


class OwnerEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.root = ROOT / "tests" / ".validation" / ("owner-environment-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.ctl = FakeCtl(self.root)
        self.recovery = FakeRecovery(self.root)
        self.gate = FakeGate()
        self.original = {
            "load_module": oe.load_module, "private_json": oe.private_json,
            "write_json": oe.write_json, "pending": oe.pending,
            "invoke_guest": oe.invoke_guest, "host_tls_pin": oe.host_tls_pin,
            "wait_guest": oe.wait_guest,
        }
        self.registry_module = sys.modules.get("instance_registry")
        fake_registry = types.ModuleType("instance_registry")
        fake_registry.update_owner = lambda config: None
        sys.modules["instance_registry"] = fake_registry
        self.requests = []
        self.oe_private = {}

        def private_json(path):
            path = Path(path)
            if path in self.oe_private:
                return self.oe_private[path]
            return json.loads(path.read_text(encoding="utf-8"))

        def write_json(path, data, mode=0o600):
            path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data), encoding="utf-8")

        def load_module(path, name):
            return FakeNetwork(self.gate)

        def invoke_guest(ctl, qga, request, helper):
            self.requests.append((helper, request.copy()))
            if getattr(self, "fail_guest", False) and not request.get("preflight_only"):
                raise RuntimeError("simulated guest failure")
            if helper == "owner_apply.ps1":
                if request.get("preflight_only"):
                    return {"state": "succeeded", "preflight_only": True, "request_id": request["request_id"]}
                return {"state": "succeeded", "request_id": request["request_id"]}
            return {"state": "success", "request_id": request["request_id"],
                    "thumbprint": "A" * 40, "rdp_service_running": True}

        oe.private_json = private_json
        oe.write_json = write_json
        oe.load_module = load_module
        oe.invoke_guest = invoke_guest
        oe.host_tls_pin = lambda *_: None
        oe.wait_guest = lambda qga: None
        oe.pending = lambda ctl: (ctl.STORE / "recovery" / "owner-transition.json").exists() and json.loads((ctl.STORE / "recovery" / "owner-transition.json").read_text())["phase"] != "complete"

    def tearDown(self):
        for key, value in self.original.items():
            setattr(oe, key, value)
        if self.registry_module is None:
            sys.modules.pop("instance_registry", None)
        else:
            sys.modules["instance_registry"] = self.registry_module
        shutil.rmtree(self.root, ignore_errors=True)

    def test_profile_requires_explicit_d_policy_and_discard_agreement(self):
        with self.assertRaisesRegex(RuntimeError, "Explicit D policy"):
            oe.validate_owner({"schema_version": 1, "name": "testvm", "uuid": self.ctl.DOMAIN_UUID,
                               "admin_user": "alice", "credentials": {"mode": "generate"}}, "testvm", self.ctl.DOMAIN_UUID, False)
        profile = owner_profile(self.ctl, "clear")
        with self.assertRaisesRegex(RuntimeError, "--discard-data"):
            oe.validate_owner(profile, self.ctl.VM, self.ctl.DOMAIN_UUID, False)
        with self.assertRaisesRegex(RuntimeError, "disagree"):
            oe.validate_owner(owner_profile(self.ctl), self.ctl.VM, self.ctl.DOMAIN_UUID, True)

    def test_pending_request_hash_mismatch_is_rejected(self):
        profile_path = self.root / "profile.json"
        profile_path.write_text(json.dumps(owner_profile(self.ctl)), encoding="utf-8")
        marker = self.ctl.STORE / "recovery" / "owner-transition.json"
        marker.write_text(json.dumps({"phase": "failed", "profile_hash": "wrong"}), encoding="utf-8")
        (self.ctl.STORE / "state" / "private" / "owner-pending.json").write_text(json.dumps({"admin_user": "alice"}), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "different request"):
            oe.reset(self.ctl, self.recovery, True, str(profile_path), False)
        self.assertEqual(self.recovery.reset_calls, 0)

    def test_normal_reset_forces_d_preserve(self):
        configured = self.ctl.STORE / "state" / "private" / "owner.json"
        configured.write_text(json.dumps({"name": "testvm", "uuid": self.ctl.DOMAIN_UUID,
                                          "admin_user": "alice", "password": "x" * 20,
                                          "data_policy": "clear"}), encoding="utf-8")
        result = oe.reset(self.ctl, self.recovery, True)
        self.assertEqual(result["D"], "preserve")
        self.assertEqual(self.requests[0][1]["data_policy"], "preserve")
        self.assertEqual(self.recovery.reset_calls, 1)

    def test_guest_failure_stops_vm_and_keeps_maintenance(self):
        configured = self.ctl.STORE / "state" / "private" / "owner.json"
        configured.write_text(json.dumps({"name": "testvm", "uuid": self.ctl.DOMAIN_UUID,
                                          "admin_user": "alice", "password": "x" * 20}), encoding="utf-8")
        self.fail_guest = True
        with self.assertRaisesRegex(RuntimeError, "retain maintenance"):
            oe.reset(self.ctl, self.recovery, True)
        marker = json.loads((self.ctl.STORE / "recovery" / "owner-transition.json").read_text())
        self.assertEqual(marker["phase"], "failed")
        self.assertIn("stop", self.ctl.events)
        self.assertIn("install", self.gate.events)

    def test_preflight_failure_does_not_restore_c(self):
        configured = self.ctl.STORE / "state" / "private" / "owner.json"
        configured.write_text(json.dumps({"name": "testvm", "uuid": self.ctl.DOMAIN_UUID,
                                          "admin_user": "alice", "password": "x" * 20}), encoding="utf-8")
        original_invoke = oe.invoke_guest
        def fail_preflight(ctl, qga, request, helper):
            if request.get("preflight_only"):
                raise RuntimeError("simulated preflight failure")
            return original_invoke(ctl, qga, request, helper)
        oe.invoke_guest = fail_preflight
        with self.assertRaisesRegex(RuntimeError, "retain maintenance"):
            oe.reset(self.ctl, self.recovery, True)
        self.assertEqual(self.recovery.reset_calls, 0)

    def test_failed_apply_retry_does_not_repeat_c_restore(self):
        configured = self.ctl.STORE / "state" / "private" / "owner.json"
        configured.write_text(json.dumps({"name": "testvm", "uuid": self.ctl.DOMAIN_UUID,
                                          "admin_user": "alice", "password": "x" * 20}), encoding="utf-8")
        self.fail_guest = True
        with self.assertRaises(RuntimeError): oe.reset(self.ctl, self.recovery, True)
        self.fail_guest = False
        oe.reset(self.ctl, self.recovery, True)
        self.assertEqual(self.recovery.reset_calls, 1)

    def test_release_failure_can_be_retried(self):
        configured = self.ctl.STORE / "state" / "private" / "owner.json"
        configured.write_text(json.dumps({"name": "testvm", "uuid": self.ctl.DOMAIN_UUID,
                                          "admin_user": "alice", "password": "x" * 20}), encoding="utf-8")
        self.gate.fail_remove = True
        with self.assertRaises(RuntimeError): oe.reset(self.ctl, self.recovery, True)
        marker = json.loads((self.ctl.STORE / "recovery" / "owner-transition.json").read_text())
        self.assertEqual(marker["resume_from"], "releasing")
        self.gate.fail_remove = False
        result = oe.reset(self.ctl, self.recovery, True)
        self.assertEqual(result["actual_state"], "running")
        self.assertEqual(json.loads((self.ctl.STORE / "recovery" / "owner-transition.json").read_text())["phase"], "complete")


class MaintenanceGateTests(unittest.TestCase):
    def fake_runner(self, listing, calls):
        def run(args):
            calls.append(list(args))
            if "-S" in args:
                target = args[args.index("-S") + 1]
                return types.SimpleNamespace(returncode=0, stdout=listing.get(target, ""), stderr="")
            if "-C" in args:
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        return run

    def test_private_gate_precedes_established_and_does_not_touch_shared_chain(self):
        calls = []
        listing = {
            "WINVM01_MAINT": "-A WINVM01_MAINT -j RETURN\n-A WINVM01_MAINT -j DROP\n",
            "WINVM01_FWD_TO": "-A WINVM01_FWD_TO -j WINVM01_MAINT\n-A WINVM01_FWD_TO -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n",
            "WINVM01_OUTPUT": "-A WINVM01_OUTPUT -j WINVM01_MAINT\n-A WINVM01_OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n",
        }
        gate = maintenance.Gate("winvm01", ((13389,3389),), "WINVM01_FWD_TO", "WINVM01_OUTPUT", self.fake_runner(listing, calls))
        gate.verify()
        self.assertTrue(all("DOCKER" not in " ".join(c) and "LIBVIRT" not in " ".join(c) for c in calls))

    def test_partial_private_chain_is_rejected(self):
        listing = {"WINVM01_MAINT": "-A WINVM01_MAINT -j DROP\n"}
        gate = maintenance.Gate("winvm01", ((13389,3389),), "WINVM01_FWD_TO", "WINVM01_OUTPUT", self.fake_runner(listing, []))
        with self.assertRaisesRegex(RuntimeError, "Partial maintenance chain"):
            gate.verify_chain()


if __name__ == "__main__":
    unittest.main()
