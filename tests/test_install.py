import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('virtops_install',ROOT/'install.py')
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)


class InstallTests(unittest.TestCase):
    def test_install_verify_and_repeat(self):
        with tempfile.TemporaryDirectory() as d:
            target=installer.install(Path(d),upgrade=False)
            self.assertEqual(installer.installed_inventory(target),installer.check_source())
            self.assertEqual(installer.install(Path(d),upgrade=False),target)

    def test_local_edit_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            target=installer.install(Path(d),upgrade=False)
            path=target/'SKILL.md';path.write_text('local edit')
            with self.assertRaisesRegex(ValueError,'local changes'):installer.install(Path(d),upgrade=True)
            self.assertEqual(path.read_text(),'local edit')

    def test_unknown_folder_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)/installer.NAME;target.mkdir();(target/'keep.txt').write_text('keep')
            with self.assertRaisesRegex(ValueError,'not a VirtOps'):installer.install(Path(d),upgrade=True)
            self.assertEqual((target/'keep.txt').read_text(),'keep')

    def test_upgrade_managed_old_version(self):
        with tempfile.TemporaryDirectory() as d:
            target=installer.install(Path(d),upgrade=False)
            path=target/'SKILL.md';path.write_text('old managed version')
            receipt=target/installer.RECEIPT;data=json.loads(receipt.read_text())
            data['files']=installer.inventory(target);receipt.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,'--upgrade'):installer.install(Path(d),upgrade=False)
            installer.install(Path(d),upgrade=True)
            self.assertEqual(installer.installed_inventory(target),installer.check_source())

    def test_no_packaged_runtime_data(self):
        files=installer.check_source()
        self.assertIn('assets/profiles/new-vm.example.json',files)
        self.assertFalse(any(Path(p).suffix in {'.iso','.wim','.qcow2','.clixml','.store'} for p in files))


if __name__=='__main__':unittest.main()
