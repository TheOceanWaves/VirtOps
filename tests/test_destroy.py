import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).parents[1]
SPEC=importlib.util.spec_from_file_location('virtops_destroy_test',ROOT/'skill/windows-vm-sandbox/scripts/destroy.py')
destroy=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(destroy)

class Runner:
    def __init__(self,state='shut off',domain=None,fail_network=False):self.state,self.domain,self.calls,self.fail_network=state,domain,[],fail_network
    def __call__(self,argv,**kwargs):
        self.calls.append(argv)
        if 'dumpxml' in argv:return SimpleNamespace(returncode=0 if self.domain else 1,stdout=self.domain or '',stderr='')
        if 'domstate' in argv:return SimpleNamespace(returncode=0,stdout=self.state+'\n',stderr='')
        if argv[0]=='fuser' or argv[0]=='findmnt':return SimpleNamespace(returncode=1,stdout='',stderr='')
        if argv[0]=='systemd-escape':return SimpleNamespace(returncode=0,stdout=argv[-1].strip('/').replace('/','-')+('.slice' if 'slice' in argv[2] else '.mount'),stderr='')
        if argv[:2]==['ip','-j']:return SimpleNamespace(returncode=0,stdout='[]',stderr='')
        if self.fail_network and 'remove' in argv:raise destroy.DestroyError('network cleanup failed')
        return SimpleNamespace(returncode=0,stdout='',stderr='')

class DestroyTests(unittest.TestCase):
    def make_profile(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        base=Path(temp.name);host=base/'vms';root=host/'instances/alpha-vm'
        (root/'vol').mkdir(parents=True)
        p={'name':'alpha-vm','uuid':'11111111-1111-4111-8111-111111111111','root':str(root),'host_root':str(host),'network':{'bridge':'vopsbr0'}}
        (root/'instance.json').write_text(json.dumps(p));(host/'registry').mkdir()
        (host/'registry/alpha-vm.json').write_text(json.dumps({**p,'bridge':'vopsbr0'}))
        xml=f'<domain><name>alpha-vm</name><uuid>{p["uuid"]}</uuid><devices><disk device="disk"><source file="{root / "vol/current.qcow2"}"/></disk></devices></domain>'
        return p,host,root,xml
    def mapped_paths(self,base):
        original=Path
        return mock.patch.object(destroy,'Path',side_effect=lambda x:original(base)/str(x).lstrip('/') if str(x).startswith(('/etc/','/run/','/var/')) else original(x))
    def test_dry_run_is_read_only(self):
        p,h,r,x=self.make_profile()
        with mock.patch.object(destroy,'verify_store',return_value='/dev/loop7'):
            result=destroy.destroy(p,command=Runner(domain=x))
        self.assertEqual(result['identity'],'validated');self.assertTrue(r.exists());self.assertFalse((h/'operations').exists())
    def test_legacy_root_is_blocked(self):
        p,h,r,x=self.make_profile();p['root']=p['host_root']
        with self.assertRaisesRegex(destroy.DestroyError,'legacy'):destroy.destroy(p,command=Runner(domain=x))
    def test_identity_mismatch_is_blocked_before_delete(self):
        p,h,r,x=self.make_profile();changed={**p,'name':'other'};(r/'instance.json').write_text(json.dumps(changed))
        with self.assertRaises(destroy.DestroyError):destroy.destroy(p,apply=True,discard=True,command=Runner(domain=x))
        self.assertTrue(r.exists());self.assertFalse((h/'operations').exists())
    def test_busy_vm_has_no_forced_poweroff(self):
        p,h,r,x=self.make_profile();runner=Runner(state='running',domain=x)
        with mock.patch.object(destroy,'verify_store',return_value='/dev/loop7'),mock.patch.object(destroy.time,'monotonic',side_effect=[0,181]):
            with self.assertRaisesRegex(destroy.DestroyError,'did not stop'):destroy.destroy(p,apply=True,discard=True,command=runner)
        self.assertTrue(r.exists());self.assertFalse(any('destroy' in call or 'undefine' in call for call in runner.calls))
    def test_success_unmounts_before_data_delete_and_preserves_other_instances(self):
        p,h,r,x=self.make_profile();other=h/'instances/beta';other.mkdir();(other/'data').write_text('keep');image=h/'images/base';image.mkdir(parents=True);(image/'disk.qcow2').write_bytes(b'base')
        runner=Runner(domain=x)
        with mock.patch.object(destroy,'verify_store',return_value='/dev/loop7'),self.mapped_paths(h):
            result=destroy.destroy(p,apply=True,discard=True,command=runner)
        self.assertEqual(result['status'],'deleted');self.assertFalse(r.exists());self.assertFalse((h/'registry/alpha-vm.json').exists())
        self.assertEqual((other/'data').read_text(),'keep');self.assertEqual((image/'disk.qcow2').read_bytes(),b'base')
        self.assertTrue(Path(result['journal']).exists())
        unmounts=[i for i,c in enumerate(runner.calls) if c[0]=='umount'];undefine=next(i for i,c in enumerate(runner.calls) if 'undefine' in c)
        self.assertEqual(len(unmounts),2);self.assertLess(max(unmounts),undefine)
    def test_cleanup_failure_preserves_store_and_registry_with_journal(self):
        p,h,r,x=self.make_profile();runner=Runner(domain=x,fail_network=True)
        with mock.patch.object(destroy,'verify_store',return_value='/dev/loop7'),self.mapped_paths(h):
            with self.assertRaisesRegex(destroy.DestroyError,'network cleanup failed'):destroy.destroy(p,apply=True,discard=True,command=runner)
        self.assertTrue(r.exists());self.assertTrue((h/'registry/alpha-vm.json').exists())
        self.assertEqual(len(list((h/'operations').glob('destroy-*.json'))),1)
    def test_other_domain_storage_reference_blocks_before_side_effects(self):
        p,h,r,x=self.make_profile();runner=Runner(domain=x)
        def command(args,**kwargs):
            if args[-1]=='--name':return SimpleNamespace(returncode=0,stdout='beta\n',stderr='')
            return runner(args,**kwargs)
        with self.assertRaisesRegex(destroy.DestroyError,'another domain'):destroy.destroy(p,apply=True,discard=True,command=command)
        self.assertTrue(r.exists());self.assertFalse((h/'operations').exists())

if __name__=='__main__':unittest.main()
