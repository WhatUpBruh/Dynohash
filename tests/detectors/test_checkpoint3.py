import http.client
import contextlib
import io
import json
from pathlib import Path
import socket
import runpy
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from detectors.collector import Store, make_server, MAX_BODY
from detectors.minimal_detector import parse_frame
from detectors.statistics import Statistics, validate_config
from detectors.telemetry import Sender, validate

CONFIG = json.loads(Path('config/checkpoint3.json').read_text())


def payload(timestamp=100):
    return Statistics(CONFIG, now=0).snapshot('d1', now=5, timestamp=timestamp)


class StatisticsTests(unittest.TestCase):
    def setUp(self):
        self.config = dict(CONFIG, threshold_pps=2, minimum_packets=3,
                           minimum_window_seconds=2, max_flows=2, max_sources=2)
        self.stats = Statistics(self.config, now=0)
        self.flow = ('10.0.0.1', '10.0.1.100', 1234, 9000, 17)

    def test_rates_flows_sources_and_bytes(self):
        for _ in range(3):
            self.stats.observe(self.flow, 100, now=1)
        self.stats.observe((*self.flow[:2], 1235, 9000, 17), 100, now=1)
        result = self.stats.snapshot('d1', now=2, timestamp=100)
        self.assertEqual(result['packet_rate_pps'], 2)
        self.assertEqual(result['byte_rate_bps'], 1600)
        self.assertEqual(result['active_flows'], 2)
        self.assertEqual(result['per_source'], {'10.0.0.1': 4})
        self.assertFalse(result['suspicious'])  # strictly greater than threshold

    def test_minimum_samples_and_window(self):
        self.stats.observe(self.flow, 100, now=0)
        self.assertFalse(self.stats.snapshot('d1', now=.01)['suspicious'])
        self.assertFalse(self.stats.snapshot('d1', now=2)['suspicious'])
        for _ in range(6):
            self.stats.observe(self.flow, 100, now=2)
        self.assertTrue(self.stats.snapshot('d1', now=2)['suspicious'])

    def test_cooldown_and_idle_expiry(self):
        for _ in range(100):
            self.stats.observe(self.flow, 100, now=2)
        first = self.stats.snapshot('d1', now=3)
        second = self.stats.snapshot('d1', now=4)
        self.assertEqual(len(first['alerts']), 1)
        self.assertEqual(len(second['alerts']), 1)
        idle = self.stats.snapshot('d1', now=10)
        self.assertEqual(idle['packet_rate_pps'], 0)
        self.assertEqual(idle['active_flows'], 0)
        self.assertEqual(idle['per_source'], {})
        self.assertFalse(idle['suspicious'])
        self.assertEqual(idle['packets_processed_total'], 100)
        for _ in range(100):
            self.stats.observe(self.flow, 100, now=13)
        self.assertEqual(len(self.stats.snapshot('d1', now=14)['alerts']), 2)

    def test_bounded_state_and_lower_bound(self):
        for second in range(100):
            for index in range(10):
                self.stats.observe((f'10.0.0.{index+1}', *self.flow[1:]), 100, now=second)
            result = self.stats.snapshot('d1', now=second+.5)
        self.assertLessEqual(len(self.stats.bins), 5)
        self.assertTrue(result['tracking_limited'])
        self.assertEqual(result['packets_processed_total'], 1000)
        self.assertEqual(sum(b['packets'] for b in self.stats.bins), 50)
        self.assertTrue(all(len(b['flows']) <= 2 and len(b['sources']) <= 2 for b in self.stats.bins))
        json.dumps(result, allow_nan=False)
        json.dumps(list(self.stats.bins), allow_nan=False)

    def test_aligned_window_boundary(self):
        self.stats.observe(self.flow, 100, now=.2)
        self.stats.observe(self.flow, 100, now=1.2)
        before = self.stats.snapshot('d1', now=4.9)
        after = self.stats.snapshot('d1', now=5)
        self.assertEqual(before['packet_rate_pps'], 2 / 4.9)
        self.assertEqual(after['packet_rate_pps'], 1 / 4)
        self.assertEqual(after['window_seconds'], 4)

    def test_identity_limit_does_not_reduce_global_counts(self):
        for second in range(3):
            for i in range(2):
                self.stats.observe((f'10.0.0.{2*second+i+1}', *self.flow[1:]), 100, now=second)
        reading = self.stats.snapshot('d1', now=3)
        self.assertTrue(reading['tracking_limited'])
        self.assertEqual(reading['active_flows'], 2)
        self.assertEqual(len(reading['per_source']), 2)
        self.assertEqual(reading['packet_rate_pps'], 2)
        self.assertEqual(reading['packets_processed_total'], 6)

    def test_alert_history_is_bounded(self):
        for index in range(50):
            now = 20 * index + 3
            for _ in range(100):
                self.stats.observe(self.flow, 100, now=now)
            reading = self.stats.snapshot('d1', now=now+.1, timestamp=1000+index)
        self.assertEqual(len(reading['alerts']), 32)
        self.assertEqual(reading['alerts'][-1]['id'], 50)

    def test_configuration_validation(self):
        for changes in ({'window_seconds': 0}, {'threshold_pps': float('nan')},
                        {'minimum_packets': True}, {'max_flows': 5000},
                        {'collector_url': 'https://example.com'}, {'publish_seconds': 100},
                        {'collector_url': None}, {'collector_url': 'http://127.0.0.1:99999/api/v1/telemetry'},
                        {'minimum_window_seconds': 5}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_config(dict(CONFIG, **changes))


class ValidationTests(unittest.TestCase):
    def test_serialization_and_nulls(self):
        reading = validate(payload(), {'d1'}, 100)
        self.assertEqual(json.loads(json.dumps(reading)), reading)
        for field in ('cpu_percent', 'queue_depth', 'queue_capacity', 'packets_dropped_total', 'per_bucket'):
            self.assertIsNone(reading[field])

    def test_bad_fields(self):
        for field, value in [('server_id', 'd4'), ('server_id', []), ('timestamp', 102),
                             ('timestamp', 0), ('packet_rate_pps', -1), ('packet_rate_pps', float('inf')), ('packet_rate_pps', 10**1000),
                             ('cpu_percent', 101), ('active_flows', True), ('active_flows', 1.5),
                             ('alerts', [None]), ('per_bucket', {}), ('per_source', {'bad': 2}),
                             ('suspicious', 1), ('extra', 1)]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                validate(dict(payload(), **{field: value}), {'d1'}, 100)
        missing = payload()
        del missing['cpu_percent']
        with self.assertRaises(ValueError):
            validate(missing, {'d1'}, 100)
        with self.assertRaises(ValueError):
            validate(dict(payload(), queue_depth=3, queue_capacity=2), {'d1'}, 100)

    def test_stale_missing_and_out_of_order(self):
        store = Store(['d1', 'd2'])
        self.assertTrue(store.view(now=100, monotonic=0)['servers']['d2']['stale'])
        store.accept(payload(), now=100, monotonic=0)
        self.assertFalse(store.view(now=103, monotonic=3)['servers']['d1']['stale'])
        self.assertTrue(store.view(now=103.01, monotonic=3.01)['servers']['d1']['stale'])
        # A wall-clock rollback cannot keep readings fresh forever.
        self.assertTrue(store.view(now=99, monotonic=4)['servers']['d1']['stale'])
        with self.assertRaises(ValueError):
            store.accept(payload(99), now=100)
        stale = Store(['d1'])
        stale.accept(payload(96), now=100, monotonic=0)
        self.assertTrue(stale.view(now=100, monotonic=0)['servers']['d1']['stale'])

    def test_history_events_bounded_and_deduplicated(self):
        store = Store(['d1'], history_size=2, event_size=3)
        for index in range(10):
            reading = payload(100+index)
            reading['alerts'] = [dict(id=index, timestamp=100+index, packet_rate_pps=3)]
            store.accept(reading, now=100+index)
        self.assertEqual(len(store.history['d1']), 2)
        self.assertEqual(len(store.events), 3)
        reading['timestamp'] += 1
        store.accept(reading, now=110)
        self.assertEqual(len(store.events), 3)
        self.assertEqual(store.events[-1]['id'], 9)

    def test_rollback_preserves_age_already_present_at_receipt(self):
        for timestamp, elapsed, expected_age in ((96, 1, 5), (98, 1.1, 3.1)):
            with self.subTest(timestamp=timestamp):
                store = Store(['d1'])
                store.accept(payload(timestamp), now=100, monotonic=10)
                reading = store.view(now=97, monotonic=10 + elapsed)['servers']['d1']
                self.assertAlmostEqual(reading['age_seconds'], expected_age)
                self.assertTrue(reading['stale'])


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(['d1', 'd2', 'd3'])
        self.server = make_server(('127.0.0.1', 0), self.store)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .02})
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.assertFalse(self.thread.is_alive())

    def request(self, method, body=None, headers=None, path='/api/v1/telemetry'):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=3)
        try:
            connection.request(method, path, body, headers or {})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_sender_real_http_all_three_and_get(self):
        sender = Sender(f'http://127.0.0.1:{self.port}/api/v1/telemetry')
        for name in ('d1', 'd2', 'd3'):
            reading = payload(time.time())
            reading['server_id'] = name
            self.assertTrue(sender.send(reading))
        status, result = self.request('GET')
        self.assertEqual(status, 200)
        self.assertTrue(all(not s['stale'] for s in result['servers'].values()))
        self.assertEqual(sender.failures, 0)

    def test_malformed_http(self):
        cases = [(b'{', {'Content-Type': 'application/json'}, 400),
                 (b'[]', {'Content-Type': 'application/json'}, 400),
                 (b'{"x":1,"x":2}', {'Content-Type': 'application/json'}, 400),
                 (b'{}', {'Content-Type': 'text/plain'}, 400),
                 (b'', {'Content-Type': 'application/json', 'Content-Length': str(MAX_BODY+1)}, 413)]
        for body, headers, expected in cases:
            with self.subTest(body=body):
                self.assertEqual(self.request('POST', body, headers)[0], expected)
        self.assertEqual(self.request('GET', path='/missing')[0], 404)
        self.assertEqual(self.request('POST', b'{}', path='/missing')[0], 404)

    def test_outage_and_recovery(self):
        # Closed ephemeral port gives a real connection-refused failure.
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        sender = Sender(f'http://127.0.0.1:{port}/api/v1/telemetry', timeout=.1)
        self.assertFalse(sender.send(payload(time.time())))
        # Recover the same endpoint; the sender has no outage backlog to replay.
        recovered = make_server(('127.0.0.1', port), self.store)
        worker = threading.Thread(target=recovered.serve_forever, kwargs={'poll_interval': .02})
        worker.start()
        try:
            self.assertTrue(sender.send(payload(time.time())))
        finally:
            recovered.shutdown()
            recovered.server_close()
            worker.join(timeout=3)
        self.assertEqual(sender.failures, 1)
        self.assertEqual(len(self.store.history['d1']), 1)

    def test_invalid_payload_rejected_over_http(self):
        reading = payload(time.time())
        reading['packet_rate_pps'] = float('nan')
        self.assertEqual(self.request('POST', json.dumps(reading), {'Content-Type': 'application/json'})[0], 400)
        self.assertEqual(len(self.store.history['d1']), 0)

    def test_stale_and_duplicate_readings_over_http(self):
        reading = payload(time.time()-4)
        body = json.dumps(reading)
        headers = {'Content-Type': 'application/json'}
        self.assertEqual(self.request('POST', body, headers)[0], 202)
        self.assertTrue(self.request('GET')[1]['servers']['d1']['stale'])
        self.assertEqual(self.request('POST', body, headers)[0], 400)
        reading['timestamp'] = time.time()
        self.assertEqual(self.request('POST', json.dumps(reading), headers)[0], 202)
        self.assertFalse(self.request('GET')[1]['servers']['d1']['stale'])

    def test_sender_http_failure_and_recovery(self):
        sender = Sender(f'http://127.0.0.1:{self.port}/api/v1/telemetry')
        invalid = payload(time.time())
        invalid['server_id'] = 'unknown'
        self.assertFalse(sender.send(invalid))
        self.assertTrue(sender.send(payload(time.time())))
        self.assertEqual(sender.failures, 1)

    def test_http_stale_reading_stays_stale_after_clock_rollback(self):
        with patch('detectors.collector.time') as clock:
            clock.time.return_value = 100
            clock.monotonic.return_value = 10
            status, _ = self.request('POST', json.dumps(payload(96)),
                                     {'Content-Type': 'application/json'})
            self.assertEqual(status, 202)
            clock.time.return_value = 97
            clock.monotonic.return_value = 11
            status, result = self.request('GET')
            self.assertEqual(status, 200)
            self.assertEqual(result['servers']['d1']['age_seconds'], 5)
            self.assertTrue(result['servers']['d1']['stale'])

    def test_sender_handles_malformed_response(self):
        sender = Sender(f'http://127.0.0.1:{self.port}/api/v1/telemetry')
        with patch.object(sender.opener, 'open', side_effect=http.client.BadStatusLine('invalid')):
            self.assertFalse(sender.send(payload(time.time())))
        self.assertTrue(sender.send(payload(time.time())))

    def test_collector_process_graceful_shutdown(self):
        import select
        process = subprocess.Popen([sys.executable, '-m', 'detectors.collector',
                                    '--bind', '127.0.0.1', '--port', '0'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            ready, _, _ = select.select([process.stdout], [], [], 5)
            self.assertTrue(ready, 'collector startup timed out')
            self.assertIn('Collector listening', process.stdout.readline())
            process.terminate()
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=3)


class CaptureTests(unittest.TestCase):
    def frame(self):
        return (bytes.fromhex('0000000000110200000000010800') +
                struct.pack('!BBHHHBBH4s4s', 69, 0, 28, 1, 0, 64, 17, 0,
                            socket.inet_aton('10.0.0.1'), socket.inet_aton('10.0.1.100')) +
                struct.pack('!HHHH', 1234, 9000, 8, 0))

    def test_parse_supported_frame(self):
        frame = self.frame()
        self.assertEqual(parse_frame(frame, bytes.fromhex('000000000011')),
                         (('10.0.0.1', '10.0.1.100', 1234, 9000, 17), len(frame)))

    def test_tcp_and_padding(self):
        frame = self.frame()
        ip = bytearray(frame[14:34])
        ip[2:4] = struct.pack('!H', 40)
        ip[9] = 6
        tcp = struct.pack('!HHIIBBHHH', 1234, 80, 0, 0, 0x50, 2, 1024, 0, 0)
        valid = frame[:14] + ip + tcp + b'padding'
        result = parse_frame(valid, bytes.fromhex('000000000011'))
        self.assertEqual(result[0][-1], 6)
        self.assertEqual(result[1], len(valid))
        malformed = valid[:46] + b'\x10' + valid[47:]
        self.assertIsNone(parse_frame(malformed, bytes.fromhex('000000000011')))

    def test_ignore_malformed_fragment_options_wrong_mac(self):
        frame = self.frame()
        mac = bytes.fromhex('000000000011')
        for candidate in (b'', frame[:35], b'xxxxxx'+frame[6:],
                          frame[:14]+b'\x46'+frame[15:],
                          frame[:20]+b'\x20\x00'+frame[22:],
                          frame[:38]+b'\x00\x07'+frame[40:]):
            with self.subTest(candidate=candidate):
                self.assertIsNone(parse_frame(candidate, mac))


class HarnessEvidenceTests(unittest.TestCase):
    def test_migration_recheck_preserves_history_even_on_failure(self):
        wrapper = runpy.run_path('tests/topology/checkpoint3_detection.py')['recheck_migration']
        for fails in (False, True):
            with self.subTest(fails=fails), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'logs').mkdir()
                historical = root / 'logs/checkpoint2-integration.json'
                historical.write_text('{"status":"PASSED","historical":true}')
                original = historical.read_bytes()

                def fake_exercise(net):
                    historical.write_text('{"status":"FAILED"}' if fails else '{"status":"PASSED"}')
                    if fails:
                        raise RuntimeError('simulated live test failure')

                with patch.dict(wrapper.__globals__, PROJECT=root), \
                     patch('runpy.run_path', return_value={'exercise': fake_exercise}), \
                     contextlib.redirect_stdout(io.StringIO()):
                    if fails:
                        with self.assertRaises(RuntimeError):
                            wrapper(None)
                    else:
                        wrapper(None)
                self.assertEqual(historical.read_bytes(), original)
                reports = list((root / 'logs').glob('checkpoint3-migration-*/report.json'))
                self.assertEqual(len(reports), 1)
                self.assertEqual(json.loads(reports[0].read_text())['status'], 'FAILED' if fails else 'PASSED')


if __name__ == '__main__':
    unittest.main()
