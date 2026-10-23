import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'skill/windows-vm-sandbox/assets/runtime/winvm01_log_collector.py'


def load_collector():
    spec = importlib.util.spec_from_file_location('tested_collector', SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CollectorPolicyTests(unittest.TestCase):
    def setUp(self):
        self.collector = load_collector()

    def parse(self, route, fields):
        return self.collector.parse_message({'MESSAGE': 'WINVM01 DROP ' + route + ' ' + fields})

    def test_records_guest_public_private_and_host_attempts(self):
        for dst, port in [('1.1.1.1', 443), ('192.168.20.30', 1080)]:
            self.assertIsNotNone(self.parse('fwd-from', f'IN=winbr01 OUT=eno2 SRC=172.30.61.2 DST={dst} PROTO=TCP SPT=40000 DPT={port} SYN'))
        self.assertIsNotNone(self.parse('input', 'IN=winbr01 SRC=172.30.61.2 DST=172.30.61.1 PROTO=TCP SPT=40000 DPT=22 SYN'))

    def test_bridge_ingress_identifies_spoofed_guest_source(self):
        self.assertIsNotNone(self.parse('fwd-from', 'IN=winbr01 SRC=10.99.0.2 DST=1.1.1.1 PROTO=TCP DPT=443 SYN'))
        self.assertIsNone(self.parse('fwd-from', 'IN=eno2 SRC=172.30.61.2 DST=1.1.1.1 PROTO=TCP DPT=443'))

    def test_omits_host_output_and_incoming_traffic(self):
        self.assertIsNone(self.parse('output', 'OUT=winbr01 SRC=172.30.61.1 DST=1.1.1.1 PROTO=UDP DPT=11010'))
        self.assertIsNone(self.parse('fwd-to', 'IN=eno2 OUT=winbr01 SRC=192.168.20.1 DST=172.30.61.2 PROTO=TCP DPT=3389'))

    def test_omits_broadcast_and_multicast_noise(self):
        for dst in ['172.30.61.3', '255.255.255.255', '239.255.255.250', 'ff02::1']:
            self.assertIsNone(self.parse('input', f'IN=winbr01 SRC=172.30.61.2 DST={dst} PROTO=UDP DPT=137'))

    def test_omits_management_replies_but_records_new_syn(self):
        common = 'IN=winbr01 SRC=172.30.61.2 DST=172.30.61.1 PROTO=TCP SPT=5986 DPT=50000'
        self.assertIsNone(self.parse('input', common + ' ACK RST'))
        self.assertIsNotNone(self.parse('input', common + ' SYN'))

    def test_ipv6_unicast_and_payload_redaction(self):
        record = self.parse('fwd-from6', 'IN=winbr01 SRC=fe80::2 DST=2606:4700:4700::1111 PROTO=TCP DPT=443 SYN PAYLOAD=hidden-password')
        self.assertIsNotNone(record)
        self.assertNotIn('hidden-password', json.dumps(record))
        self.assertEqual(record['result'], 'blocked')

    def test_journal_follows_new_entries_without_replaying_last_ten(self):
        process = mock.Mock(stdout=iter([]))
        process.poll.return_value = 0
        with mock.patch.object(self.collector.subprocess, 'Popen', return_value=process) as start:
            self.assertEqual(list(self.collector.journal_lines([])), [])
        self.assertIn('--lines=0', start.call_args.args[0])

    def test_rendered_nondefault_instance_filters_its_own_bridge_and_subnet(self):
        from test_profile import profile_for
        data = profile_for('alpha-vm', 2)
        data['resources'].update(cpu_order=[0, 1, 2, 3], threads_per_core=1, amd=False)
        data['network']['bridge'] = 'alpha-br'
        spec = importlib.util.spec_from_file_location('test_render_logs', ROOT / 'skill/windows-vm-sandbox/scripts/render.py')
        render = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(render)
        source = render.runtime_files(data, '22222222-2222-4222-8222-222222222222', 42)['scripts/lib/alpha-vm_log_collector.py']
        namespace = {'__name__': 'rendered_collector'}
        exec(compile(source, 'rendered_collector.py', 'exec'), namespace)
        parse = namespace['parse_message']
        self.assertIsNotNone(parse({'MESSAGE': 'ALPHA-VM DROP fwd-from IN=alpha-br SRC=10.22.0.2 DST=1.1.1.1 PROTO=TCP DPT=443 SYN'}))
        self.assertIsNone(parse({'MESSAGE': 'ALPHA-VM DROP input IN=alpha-br SRC=10.22.0.2 DST=10.22.0.3 PROTO=UDP DPT=137'}))
        self.assertEqual(namespace['VM_BRIDGE'], 'alpha-br')
