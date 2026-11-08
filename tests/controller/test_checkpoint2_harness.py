"""Offline regression tests; importing the harness does not access Mininet or BMv2."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location(
    'checkpoint2_harness',
    Path(__file__).resolve().parents[1] / 'topology/checkpoint2_migration.py',
)
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)

RECORD = ('21:15:22.886386 02:00:00:00:00:01 > 00:00:00:00:00:13, '
          'ethertype IPv4 (0x0800), length 74: '
          '10.0.0.1.40009 > 10.0.1.100.9000: UDP, length 32\n')
SUMMARY = ('tcpdump: verbose output suppressed, use -v[v]... for full protocol decode\n'
           'listening on d3-eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n'
           '10 packets captured\n10 packets received by filter\n0 packets dropped by kernel\n')


class PacketCountingTests(unittest.TestCase):
    def test_zero_packets(self):
        for stdout in ('', '\n', '\n\n', ' \n\t\n'):
            with self.subTest(stdout=stdout):
                self.assertEqual(harness.count_packet_records(stdout), 0)

    def test_one_packet(self):
        self.assertEqual(harness.count_packet_records(RECORD + '\n'), 1)

    def test_ten_packets(self):
        self.assertEqual(harness.count_packet_records(RECORD * 10 + '\n'), 10)

    def test_summary_output(self):
        self.assertEqual(harness.count_packet_records(SUMMARY), 0)
        self.assertEqual(harness.count_packet_records(RECORD * 10 + '\n' + SUMMARY), 10)

    def test_reject_nonrecords_and_other_flows(self):
        for line in ('arbitrary nonempty text\n', 'UDP, length 32\n',
                     RECORD.replace('40009', '40010'),
                     RECORD.replace('UDP', 'TCP'),
                     RECORD.replace('02:00:00:00:00:01', 'invalid-mac')):
            with self.subTest(line=line):
                self.assertEqual(harness.count_packet_records(line), 0)


class RestorationTests(unittest.TestCase):
    def test_capture_startup_failure_preserves_diagnostics(self):
        net = Mock()
        capture = Mock()
        capture.poll.return_value = 1
        capture.communicate.return_value = ('\n', 'tcpdump: capture startup failed\n')
        net.get.return_value.popen.return_value = capture
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / 'logs').mkdir()
            with patch.object(harness, 'PROJECT', project), \
                 patch.object(harness.time, 'sleep'), \
                 patch.object(harness.subprocess, 'check_output', return_value='12866\n'), \
                 patch.object(harness, 'rpc', side_effect=[{}, {}]), \
                 patch('builtins.print'):
                with self.assertRaisesRegex(RuntimeError, 'tcpdump exited before traffic'):
                    harness.exercise(net)
            report = json.loads((project / 'logs/checkpoint2-integration.json').read_text())
        self.assertEqual(report['status'], 'FAILED')
        for name in ('d1', 'd2', 'd3'):
            self.assertEqual(report['phases'][0][name], {
                'packets': 0, 'stdout': '\n', 'stderr': 'tcpdump: capture startup failed\n',
            })

    def test_original_and_cleanup_failures_are_both_preserved(self):
        original = {str(b): f'd{b % 3 + 1}' for b in range(64)}
        counters = {str(b): 0 for b in range(64)}
        after = dict(counters, **{'59': 10})
        net = Mock()
        captures = []
        # Discovery works; initial-owner verification fails before migration.
        for phase in range(2):
            for name in ('d1', 'd2', 'd3'):
                capture = Mock()
                capture.poll.return_value = None
                stdout = RECORD * 10 if name == 'd3' else '\n'
                if phase == 1 and name == 'd1':
                    stdout = RECORD.replace('00:00:00:00:00:13', '00:00:00:00:00:11')
                capture.communicate.return_value = (stdout, SUMMARY)
                captures.append(capture)
        sender = Mock()
        sender.wait.return_value = 0
        host_captures = {name: iter(captures[i::3]) for i, name in enumerate(('d1', 'd2', 'd3'))}
        def host(name):
            node = Mock()
            node.popen.side_effect = lambda *a, **kw: sender if name == 'h1' else next(host_captures[name])
            return node
        net.get.side_effect = host
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / 'logs').mkdir()
            with patch.object(harness, 'PROJECT', project), \
                 patch.object(harness.time, 'sleep'), \
                 patch.object(harness.subprocess, 'check_output', return_value='12866\n'), \
                 patch.object(harness, 'rpc', side_effect=[original, counters, after, RuntimeError('restore failed')]) as rpc, \
                 patch('builtins.print'):
                with self.assertRaisesRegex(AssertionError, 'd1: expected 0'):
                    harness.exercise(net)
            report = json.loads((project / 'logs/checkpoint2-integration.json').read_text())
        self.assertEqual(report['status'], 'FAILED')
        self.assertIn('d1: expected 0', report['error'])
        self.assertIn('restore failed', report['cleanup_error'])
        self.assertNotIn('restored', report)
        self.assertEqual(rpc.call_args.args[0], "c.migrate(59, 'd3')")
        # Raw diagnostics remain intact; only packet counting is normalized.
        self.assertEqual(report['phases'][0]['d1']['stdout'], '\n')
        self.assertEqual(report['phases'][0]['d1']['stderr'], SUMMARY)
        for capture in captures:
            capture.send_signal.assert_called_once()
            capture.communicate.assert_called_once()


if __name__ == '__main__':
    unittest.main()
