import ast
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/windows-vm-sandbox/scripts')]
from profile import validate
from prepare_host import verify_gpu,verify_saved
from render import domain_xml,runtime_files
from test_runtime import render_profile


class SafetyTests(unittest.TestCase):
    def test_new_vm_must_answer_gpu_question(self):
        p=render_profile('alpha',1);p['gpu']['mode']=None
        with self.assertRaisesRegex(ValueError,'gpu.mode'):validate(p,new=True)

    def test_gpu_no_silent_vgpu_fallback(self):
        p=render_profile('alpha',1);p['gpu']['mode']='vgpu'
        with self.assertRaisesRegex(RuntimeError,'NEEDS_GPU_INTEGRATION'):verify_gpu(p)
        with self.assertRaisesRegex(ValueError,'NEEDS_GPU_INTEGRATION'):domain_xml(p,installing=False)

    def test_passthrough_needs_dedicated_valid_device(self):
        p=render_profile('alpha',1);p['gpu']={'mode':'passthrough','pci_devices':['0000:01:00.0'],'dedicated':False}
        with self.assertRaisesRegex(ValueError,'dedicated'):validate(p,new=True)
        p['gpu']['dedicated']=True;validate(p,new=True)
        xml=__import__('xml.etree.ElementTree',fromlist=['']).fromstring(domain_xml(p,installing=False))
        self.assertEqual(xml.find('devices/hostdev').get('managed'),'no')
        self.assertEqual(xml.find('devices/hostdev/source/address').get('slot'),'0x00')
        self.assertGreaterEqual(len(xml.findall("devices/controller[@model='pcie-root-port']")),6)
        p['gpu']['mode']='none'
        with self.assertRaisesRegex(ValueError,'cannot have PCI'):validate(p,new=True)

    def test_saved_profile_cannot_silently_change_resources(self):
        p=render_profile('alpha',1);saved=copy.deepcopy(p);saved['resources']['cpu_order']=[0,1,2,3]
        verify_saved(p,saved)
        p['network']['rdp_port']+=1
        with self.assertRaisesRegex(RuntimeError,'Profile changed'):verify_saved(p,saved)

    def test_hyphen_name_uses_systemd_literal_escape(self):
        p=render_profile('alpha-vm',1)
        source=runtime_files(p,'22222222-2222-4222-8222-222222222222',50001)['scripts/lib/vmctl.py']
        values={n.value for n in ast.walk(ast.parse(source)) if isinstance(n,ast.Constant) and isinstance(n.value,str)}
        self.assertIn(r'machine-alpha\x2dvm.slice',values)

    def test_none_gpu_does_not_touch_host_gpu(self):
        p=render_profile('alpha',1)
        with patch('prepare_host.run',side_effect=AssertionError('no GPU command needed')):
            self.assertEqual(verify_gpu(p),{'mode':'none'})
        self.assertNotIn('<hostdev',domain_xml(p,installing=True))


if __name__=='__main__':unittest.main()
