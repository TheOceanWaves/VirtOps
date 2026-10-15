import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skill/windows-vm-sandbox/scripts/upgrade_runtime.py"
SPEC = importlib.util.spec_from_file_location("upgrade_runtime", SCRIPT)
upgrade = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(upgrade)


class UpgradeRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = Path(tempfile.mkdtemp(dir=ROOT))
        self.root = self.temp / "vm"
        (self.root / "scripts/lib").mkdir(parents=True)
        self.source = Path(self.temp.name) / "source.sh"
        self.source.write_text("#!/bin/sh\nnew\n", encoding="utf-8")
        self.old = self.root / "scripts/start.sh"
        self.old.write_text("#!/bin/sh\nold\n", encoding="utf-8")
        self.profile = {
            "name": "winvm01", "uuid": "00000000-0000-4000-8000-000000000001",
            "root": str(self.root), "host_root": str(self.root),
            "windows": {"admin_user": "admin"},
            "resources": {"storage_gib": 1, "cpu_order": [0, 1], "threads_per_core": 2, "amd": False},
        }

    def tearDown(self):
        shutil.rmtree(self.temp, ignore_errors=True)

    def patch_checks(self, expected):
        return mock.patch.multiple(
            upgrade,
            load_profile=mock.Mock(return_value=self.profile),
            manifest_hashes=mock.Mock(return_value=expected),
            validate_source=mock.Mock(return_value=(expected, {})),
            render_runtime=mock.Mock(return_value={Path("scripts/start.sh"): self.source.read_bytes()}),
            store_identity=mock.Mock(return_value={"uuid": "store", "inode": 7}),
            domain_facts=mock.Mock(return_value=("running", "<domain/>")),
            validate_network_helper=mock.Mock(),
            validate_instance_config=mock.Mock(),
            check_owner_state=mock.Mock(),
            check_registry=mock.Mock(),
            ensure_owner=mock.Mock(),
            ensure_instance=mock.Mock(),
            register_catalog=mock.Mock(),
            post_apply_verify=mock.Mock(),
            installed_hashes=mock.Mock(return_value={}),
            save_installed_hashes=mock.Mock(),
        )

    def test_check_is_default_and_does_not_modify_files(self):
        expected = {"start.sh": {upgrade.sha256(self.old)}}
        with self.patch_checks(expected):
            result = upgrade.inspect(Path("profile.json"), apply=False, lock_dir=Path(self.temp.name) / "lock")
        self.assertEqual(result["status"], "ready")
        self.assertIn("old", self.old.read_text(encoding="utf-8"))

    def test_apply_replaces_only_managed_file_and_preserves_unknown(self):
        expected = {"start.sh": {upgrade.sha256(self.old)}}
        unknown = self.root / "scripts/lib/operator-note.txt"
        unknown.write_text("keep", encoding="utf-8")
        with self.patch_checks(expected):
            result = upgrade.inspect(Path("profile.json"), apply=True, lock_dir=Path(self.temp.name) / "lock")
        self.assertEqual(result["status"], "applied")
        self.assertIn("new", self.old.read_text(encoding="utf-8"))
        self.assertEqual(unknown.read_text(encoding="utf-8"), "keep")
        self.assertFalse(result["restarted"])
        self.assertFalse(result["network_changed"])

    def test_external_edit_is_fail_closed(self):
        expected = {"start.sh": {hashlib.sha256(b"approved").hexdigest()}}
        with self.patch_checks(expected):
            with self.assertRaisesRegex(RuntimeError, "external edits detected"):
                upgrade.inspect(Path("profile.json"), apply=False, lock_dir=Path(self.temp.name) / "lock")

    def test_owner_json_carries_existing_password_for_reset(self):
        private = self.root / "vol/state/private"
        private.mkdir(parents=True)
        (private / "credentials.json").write_text(json.dumps({"admin": "A-strong-password-1"}), encoding="utf-8")
        profile = dict(self.profile)
        profile["windows"] = {"admin_user": "admin"}
        upgrade.ensure_owner(self.root, profile)
        state = json.loads((private / "owner.json").read_text(encoding="utf-8"))
        self.assertEqual(state["admin_user"], "admin")
        self.assertEqual(state["password"], "A-strong-password-1")

    def test_atomic_copy_writes_bytes_and_uses_target_suffix(self):
        target = self.root / "scripts/lib/example.py"
        upgrade.atomic_copy(b"print('ok')\n", target)
        self.assertEqual(target.read_bytes(), b"print('ok')\n")
        if os.name == "posix":
            self.assertEqual(target.stat().st_mode & 0o777, 0o755)

    def test_previous_managed_runtime_is_accepted_by_private_manifest(self):
        with self.patch_checks({}):
            with mock.patch.object(upgrade, 'installed_hashes', return_value={'scripts/start.sh': upgrade.sha256(self.old)}):
                result = upgrade.inspect(Path('profile.json'), apply=False)
        self.assertEqual(result['status'], 'ready')

    def test_saved_runtime_manifest_binds_identity_and_hashes(self):
        upgrade.save_installed_hashes(self.root, self.profile, {Path('scripts/start.sh'): b'new'})
        path = self.root / 'vol/state/private/runtime-files.json'
        data = json.loads(path.read_text())
        self.assertEqual(data['uuid'], self.profile['uuid'])
        self.assertEqual(data['sha256']['scripts/start.sh'], hashlib.sha256(b'new').hexdigest())
        if os.name == 'posix':
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_network_helper_must_match_profile(self):
        helper = self.root / "scripts/lib/winvm01_network.py"
        helper.write_text(
            "BRIDGE='br0'\nVM_NAME='winvm01'\nBRIDGE_IP='10.0.0.1'\n"
            "GUEST_IP='10.0.0.2'\nPUBLISH_IP='192.0.2.1'\nCLIENT_NET='192.0.2.0/24'\n"
            "PUBLISHED=((13389,3389),(15986,5986))\n", encoding="utf-8")
        profile = dict(self.profile)
        profile["network"] = {"bridge": "br0", "bridge_ip": "10.0.0.1", "guest_ip": "10.0.0.2",
                               "publish_ip": "192.0.2.1", "client_cidr": "192.0.2.0/24",
                               "rdp_port": 13389, "winrm_port": 15986}
        upgrade.validate_network_helper(self.root, profile)
        helper.write_text(helper.read_text(encoding="utf-8").replace("13389", "13390"), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "PUBLISHED"):
            upgrade.validate_network_helper(self.root, profile)

    @unittest.skipUnless(os.name == "posix", "Linux privilege gate")
    def test_apply_requires_root(self):
        with mock.patch.object(upgrade.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(RuntimeError, "requires Linux root"):
                upgrade.inspect(Path("profile.json"), apply=False)


if __name__ == "__main__":
    unittest.main()
