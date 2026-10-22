from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "skill/windows-vm-sandbox/assets/runtime"
SCRIPTS = ROOT / "skill/windows-vm-sandbox/scripts"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def make_profile(root: Path, *, admin: str = "alice") -> dict:
    return {
        "schema_version": 1,
        "name": "alpha-vm",
        "uuid": "11111111-1111-4111-8111-111111111111",
        "root": str(root),
        "host_root": str(root.parent),
        "ssh": {"host": "host", "user": "root"},
        "network": {
            "bridge": "vopsbr0", "subnet": "172.31.40.0/30", "bridge_ip": "172.31.40.1",
            "guest_ip": "172.31.40.2", "publish_ip": "192.0.2.10", "client_cidr": "192.0.2.0/24",
            "rdp_port": 23389, "winrm_port": 25986,
        },
        "windows": {"computer_name": "ALPHA-VM", "admin_user": admin},
        "credentials": {"mode": "existing"}, "gpu": {}, "media": {},
        "resources": {"memory_gib": 8, "host_limit_gib": 10, "vcpus": 4, "storage_gib": 64, "cpu_set": "0-3"},
        "limits": {"root_free_gib": 16, "start_free_gib": 12, "resume_free_gib": 12, "watch_free_gib": 8},
    }


class ConfigureIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.remote = load_module(SCRIPTS / "configure_remote.py", f"configure_remote_{id(self)}")

    def _tree(self, td: str):
        root = Path(td) / "alpha-vm"
        (root / "scripts/lib").mkdir(parents=True)
        (root / "vol/state/private").mkdir(parents=True)
        (root / "vol").mkdir(exist_ok=True)
        (root / "instance.json").write_text(json.dumps(make_profile(root), indent=2), encoding="utf-8")
        (root / "scripts/lib/vmctl.py").write_text("MEMORY_MAX = 10 * GIB\nCPU_MAX = '400000 100000'\nALLOWED_CPUS = '0-3'\n", encoding="utf-8")
        (root / "scripts/lib/prepare_host.py").write_text("START_MEM_AVAILABLE_MIN = 12 * GIB\n", encoding="utf-8")
        (root / "scripts/lib/alpha-vm_store_guard.py").write_text("# guard\n", encoding="utf-8")
        (root / "vol/state/private/runtime-files.json").write_text(json.dumps({"uuid": make_profile(root)["uuid"],"sha256":{"scripts/lib/vmctl.py":hashlib.sha256((root/'scripts/lib/vmctl.py').read_bytes()).hexdigest()}}), encoding="utf-8")
        (Path(td)/'registry').mkdir()
        (Path(td)/'registry/alpha-vm.json').write_text(json.dumps({'name':'alpha-vm','uuid':make_profile(root)['uuid'],'root':str(root)}))
        self.slice_path = Path(td) / "etc/systemd/system/machine-alpha\\x2dvm.slice"
        self.hook_path = Path(td) / "etc/libvirt/hooks/qemu.d/50-alpha-vm-guard"
        self.slice_path.parent.mkdir(parents=True)
        self.hook_path.parent.mkdir(parents=True)
        self.slice_path.write_text("AllowedCPUs=0-3\nCPUQuota=400%\nMemoryMax=10G\nMemorySwapMax=0\n", encoding="utf-8")
        self.hook_path.write_text("if [ \"$2\" -lt 12582912 ]; then exit 1; fi\n", encoding="utf-8")
        xml = f'''<domain><name>alpha-vm</name><uuid>{make_profile(root)["uuid"]}</uuid>
<memory unit="KiB">8388608</memory><currentMemory unit="KiB">8388608</currentMemory><vcpu>4</vcpu>
<memtune><hard_limit>10485760</hard_limit><soft_limit>10485760</soft_limit></memtune>
<cputune><vcpupin vcpu="0" cpuset="0-3"/><emulatorpin cpuset="0-3"/><global_quota>400000</global_quota><global_period>100000</global_period></cputune>
<cpu><topology sockets="1" cores="2" threads="2"/></cpu><devices><disk><source file="{root / 'vol/current.qcow2'}"/></disk></devices></domain>'''
        (root / "vol/current.qcow2").write_bytes(b"disk")
        (root / "vol/alpha-vm.xml").write_text(xml, encoding="utf-8")
        return root, make_profile(root), xml

    def _run_factory(self, xml: str, *, fail_set_property=False):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(list(argv))
            if argv[:4] == ["virsh", "--readonly", "-c", "qemu:///system"] and argv[4] == "dumpxml":
                return SimpleNamespace(returncode=0, stdout=xml, stderr="")
            if argv[:4] == ["virsh", "--readonly", "-c", "qemu:///system"] and argv[4] == "domstate":
                return SimpleNamespace(returncode=0, stdout="shut off\n", stderr="")
            if argv[:2] == ["virsh", "-c"] and argv[2] == "qemu:///system" and argv[3] == "define":
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if argv[:2] == ["systemctl", "set-property"] and fail_set_property:
                result = SimpleNamespace(returncode=1, stdout="", stderr="set-property failed")
            else:
                result = SimpleNamespace(returncode=0, stdout="", stderr="")
            if result.returncode and kwargs.get("check", True):
                raise RuntimeError(result.stderr)
            return result

        return fake_run, calls

    def test_identity_mismatch_rejects_without_writes(self):
        with tempfile.TemporaryDirectory() as td:
            root, data, xml = self._tree(td)
            instance = root / "instance.json"
            before = instance.read_bytes()
            wrong = json.loads(before); wrong["uuid"] = str(uuid.uuid4()); instance.write_text(json.dumps(wrong), encoding="utf-8")
            fake_run, calls = self._run_factory(xml)
            with mock.patch.object(self.remote, "run", side_effect=fake_run), mock.patch.object(self.remote, "host_admission"):
                with self.assertRaisesRegex(RuntimeError, "profile identity mismatch"):
                    self.remote.configure(data, {**data, "resources": {**data["resources"], "memory_gib": 16}}, apply=True)
            self.assertEqual(instance.read_bytes(), json.dumps(wrong).encode())
            self.assertFalse((root / ".configure-txn").exists())

    def test_success_updates_xml_files_and_manifest_hash(self):
        with tempfile.TemporaryDirectory() as td:
            root, data, xml = self._tree(td)
            fake_run, calls = self._run_factory(xml)
            data["resources"] = {**data["resources"], "memory_gib": 16, "host_limit_gib": 18, "vcpus": 8, "cpu_set": "0-7"}
            data["limits"] = {**data["limits"], "start_free_gib": 20}
            with mock.patch.object(self.remote, "Path", side_effect=lambda value: Path(td) / str(value).lstrip("/") if str(value).startswith("/etc/") else Path(value)), mock.patch.object(self.remote, "run", side_effect=fake_run), mock.patch.object(self.remote, "host_admission"):
                result = self.remote.configure(make_profile(root), data, apply=True)
            self.assertEqual(result["status"], "applied")
            instance = json.loads((root / "instance.json").read_text(encoding="utf-8"))
            self.assertEqual(instance["resources"]["vcpus"], 8)
            rendered = (root / "vol/alpha-vm.xml").read_text(encoding="utf-8")
            self.assertIn("<memory unit=\"KiB\">16777216</memory>", rendered)
            self.assertIn("<vcpu>8</vcpu>", rendered)
            self.assertIn('cores="4" threads="2"', rendered)
            self.assertIn("cpuset=\"7\"", rendered)
            self.assertIn("MemoryMax=18G", self.slice_path.read_text(encoding="utf-8"))
            manifest = json.loads((root / "vol/state/private/runtime-files.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["resources"]["memory_gib"], 16)
            self.assertEqual(manifest["sha256"]["scripts/lib/vmctl.py"], hashlib.sha256((root / "scripts/lib/vmctl.py").read_bytes()).hexdigest())
            self.assertTrue(any("define" in call for call in calls))

    def test_failure_restores_xml_slice_and_all_managed_files(self):
        with tempfile.TemporaryDirectory() as td:
            root, data, xml = self._tree(td)
            managed = [root / "instance.json", root / "scripts/lib/vmctl.py", root / "scripts/lib/prepare_host.py", root / "vol/alpha-vm.xml", root / "vol/state/private/runtime-files.json", self.slice_path, self.hook_path]
            before = {path: path.read_bytes() for path in managed}
            fake_run, calls = self._run_factory(xml, fail_set_property=True)
            desired = make_profile(root); desired["resources"] = {**desired["resources"], "memory_gib": 16, "host_limit_gib": 18, "vcpus": 8, "cpu_set": "0-7"}
            with mock.patch.object(self.remote, "Path", side_effect=lambda value: Path(td) / str(value).lstrip("/") if str(value).startswith("/etc/") else Path(value)), mock.patch.object(self.remote, "run", side_effect=fake_run), mock.patch.object(self.remote, "host_admission"):
                with self.assertRaisesRegex(RuntimeError, "set-property failed"):
                    self.remote.configure(data, desired, apply=True)
            for path, content in before.items():
                self.assertEqual(path.read_bytes(), content, path.name)
            rollback = [call for call in calls if "rollback.xml" in " ".join(call)]
            self.assertTrue(rollback, "failed transaction must redefine original XML")


class AccountIntegrationTests(unittest.TestCase):
    @contextlib.contextmanager
    def _safe_metadata(self, root: Path):
        """Windows temp ACLs report world-writable bits; emulate root-owned 0700 metadata."""
        original_stat = Path.stat
        original_lstat = Path.lstat
        def safe(method, path, *args, **kwargs):
            result = method(path, *args, **kwargs)
            values = list(result)
            values[0] = (values[0] & ~0o077) | 0o700
            return os.stat_result(values)

        def safe_stat(path, *args, **kwargs):
            return safe(original_stat, path, *args, **kwargs)

        def safe_lstat(path, *args, **kwargs):
            return safe(original_lstat, path, *args, **kwargs)

        with mock.patch.object(Path, "stat", new=safe_stat), mock.patch.object(Path, "lstat", new=safe_lstat):
            yield

    def _fixture(self, td: str):
        host = Path(td) / "host"; root = host / "alpha-vm"; private = root / "vol/state/private"
        (root / "scripts/lib").mkdir(parents=True); private.mkdir(parents=True)
        data = make_profile(root)
        (root / "instance.json").write_text(json.dumps(data), encoding="utf-8")
        for name in ("alpha-vm_qga.py", "owner_environment.py", "maintenance.py", "instance_registry.py"):
            shutil.copy2(RUNTIME / ("winvm01_qga.py" if name.endswith("_qga.py") else name), root / "scripts/lib" / name)
        (private/'runtime-files.json').write_text(json.dumps({'uuid':data['uuid'],'sha256':{str(p.relative_to(root)).replace('\\','/'):hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/'scripts/lib').iterdir()}}))
        (private / "credentials.json").write_text(json.dumps({"alice": "Old!Password123"}), encoding="utf-8")
        (private / "owner.json").write_text(json.dumps({"admin_user": "alice", "password": "Old!Password123"}), encoding="utf-8")
        registry = host / "registry"; registry.mkdir()
        item = {"schema_version": 1, "name": "alpha-vm", "uuid": data["uuid"], "root": str(root), "bridge": "vopsbr0", "subnet": data["network"]["subnet"], "publish_ip": data["network"]["publish_ip"], "rdp_port": 23389, "winrm_port": 25986, "owner": "alice", "purpose": "test", "admin_user": "alice", "resources": {k: data["resources"].get(k) for k in ("memory_gib", "host_limit_gib", "vcpus", "storage_gib", "cpu_set")}, "start_free_gib": 12}
        (registry / "alpha-vm.json").write_text(json.dumps(item), encoding="utf-8")
        for p in [root, root / "vol", private, host, registry, root / "scripts", root / "scripts/lib"]:
            try: p.chmod(0o700)
            except OSError: pass
        for p in (root / "scripts/lib").iterdir():
            try: p.chmod(0o700)
            except OSError: pass
        for p in [private / "credentials.json", private / "owner.json", root / "instance.json"]:
            try: p.chmod(0o600)
            except OSError: pass
        return data, root, private

    def _run(self, argv, **kwargs):
        if argv[:4] == ["virsh", "--readonly", "-c", "qemu:///system"] and argv[4] == "dumpxml":
            return SimpleNamespace(returncode=0, stdout=f'<domain><uuid>11111111-1111-4111-8111-111111111111</uuid><devices><disk device="disk"><source file="{self.active_root / "vol/current.qcow2"}"/></disk></devices></domain>', stderr="")
        if argv[:4] == ["virsh", "--readonly", "-c", "qemu:///system"] and argv[4] == "domstate":
            return SimpleNamespace(returncode=0, stdout="running\n", stderr="")
        raise AssertionError(argv)

    def _account_remote(self, data, *, guest_error=None, registry_error=False):
        remote = load_module(SCRIPTS / "account_remote.py", f"account_remote_{id(self)}")
        self.active_root=Path(data['root'])
        class FakeQga:
            VM = "alpha-vm"
            def __init__(self): self.writes = []; self.scripts = []
            def call(self, command, arguments=None, timeout=15):
                if command == "guest-file-open": return 7
                if command == "guest-file-write":
                    self.writes.append(arguments); return {"count": len(__import__('base64').b64decode(arguments["buf-b64"]))}
                return {}
            def powershell(self, script, timeout=180):
                self.scripts.append(script)
                if "account-update.ps1" in script:
                    if guest_error: raise RuntimeError(guest_error)
                    return json.dumps({"request_id": data.get("request_id", ""), "state": "succeeded", "sid": "S-1-5-21-42", "is_admin": True})
                return ""
        fake = FakeQga()
        real_loader = remote.load_mod
        reg_calls = {"n": 0}
        def loader(path, name):
            module = real_loader(path, name)
            if name == "account_qga": return fake
            if name == "account_owner_environment":
                module.private_rpc = lambda vm, command, arguments: {"count": len(__import__('base64').b64decode(arguments["buf-b64"]))}
                return module
            if name == "account_registry" and registry_error:
                original = module.update_owner
                def fail_once(value):
                    reg_calls["n"] += 1
                    if reg_calls["n"] == 1: raise RuntimeError("registry interrupted after host commit")
                    return original(value)
                module.update_owner = fail_once
            return module
        remote.load_mod = loader
        return remote, fake

    def test_same_sid_preserved_and_host_records_commit_without_secret_output(self):
        with tempfile.TemporaryDirectory() as td:
            data, root, private = self._fixture(td); data["request_id"] = "request"
            remote, fake = self._account_remote(data)
            request = {"profile": data, "new_admin_user": "bob", "credentials_mode": "generate", "helper_source": "Set-StrictMode", "secret_file": None, "resume": False, "request_id": "request", "apply": True}
            out = io.StringIO()
            with self._safe_metadata(root), mock.patch.object(remote.subprocess, "run", side_effect=self._run), contextlib.redirect_stdout(out):
                result = remote.main(request)
            self.assertEqual(result["sid"], "S-1-5-21-42")
            self.assertEqual(json.loads((private / "owner.json").read_text())["admin_user"], "bob")
            self.assertEqual(json.loads((root / "instance.json").read_text())["windows"]["admin_user"], "bob")
            self.assertEqual(json.loads((root.parent / "registry/alpha-vm.json").read_text())["admin_user"], "bob")
            self.assertNotIn("Vm9!", out.getvalue())
            self.assertNotIn("Old!Password123", out.getvalue())
            self.assertTrue(any("guest-file-write" if False else True for _ in fake.writes))

    def test_guest_collision_leaves_host_secrets_unchanged_and_records_pending(self):
        with tempfile.TemporaryDirectory() as td:
            data, root, private = self._fixture(td)
            remote, _ = self._account_remote(data, guest_error="ACCOUNT_NAME_COLLISION")
            request = {"profile": data, "new_admin_user": "bob", "credentials_mode": "generate", "helper_source": "Set-StrictMode", "secret_file": None, "resume": False, "request_id": "request", "apply": True}
            with self._safe_metadata(root), mock.patch.object(remote.subprocess, "run", side_effect=self._run):
                with self.assertRaisesRegex(RuntimeError, "ACCOUNT_NAME_COLLISION"):
                    remote.main(request)
            self.assertEqual(json.loads((private / "credentials.json").read_text()), {"alice": "Old!Password123"})
            self.assertEqual(json.loads((private / "owner.json").read_text())["admin_user"], "alice")
            self.assertEqual(json.loads((root / "instance.json").read_text())["windows"]["admin_user"], "alice")
            self.assertTrue((private / "account-transition.json").exists())

    def test_partial_host_commit_resumes_from_verified_marker(self):
        with tempfile.TemporaryDirectory() as td:
            data, root, private = self._fixture(td)
            remote, _ = self._account_remote(data, registry_error=True)
            request = {"profile": data, "new_admin_user": "bob", "credentials_mode": "generate", "helper_source": "Set-StrictMode", "secret_file": None, "resume": False, "request_id": "request", "apply": True}
            with self._safe_metadata(root), mock.patch.object(remote.subprocess, "run", side_effect=self._run):
                with self.assertRaisesRegex(RuntimeError, "registry interrupted"):
                    remote.main(request)
            marker = json.loads((private / "account-transition.json").read_text())
            self.assertEqual(marker["phase"], "verified")
            resumed = {**request, "resume": True}
            remote2, _ = self._account_remote(data)
            with self._safe_metadata(root), mock.patch.object(remote2.subprocess, "run", side_effect=self._run):
                result = remote2.main(resumed)
            self.assertEqual(result["status"], "applied")
            self.assertFalse((private / "account-transition.json").exists())
            self.assertFalse((private / "account-pending.json").exists())


if __name__ == "__main__":
    unittest.main()
