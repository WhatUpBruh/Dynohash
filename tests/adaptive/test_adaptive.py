import contextlib
import io
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from controller.adaptive import (AdaptiveController, Snapshot, bucket_rates, imbalance,
                                 load_settings, select_candidate, validate_counters)
from controller.adaptive_cli import main
from controller.core import BucketController, ControllerError, load_config
from controller.telemetry_client import TelemetryClient, TelemetryError, validate_view
from detectors.collector import Store, make_server
from detectors.telemetry import Sender

CONFIG = load_settings()
DETECTORS = load_config()


def view(loads=(900, 300, 100), now=1000):
    return {'servers': {name: {'stale': False, 'age_seconds': 0,
            'telemetry': dict(server_id=name, timestamp=now, cpu_percent=None,
                              packet_rate_pps=load, queue_depth=None, queue_capacity=None,
                              packets_processed_total=100000, packets_dropped_total=None,
                              active_flows=1, window_seconds=4, per_bucket=None)}
            for name, load in zip(('d1', 'd2', 'd3'), loads)}, 'events': []}


class Clock:
    def __init__(self):
        self.now = 10.0

    def monotonic(self):
        return self.now

    def wall(self):
        return 1000 + self.now


class RuntimeFake:
    def __init__(self):
        self.owners = {b: ('d1', 'd2', 'd3')[b % 3] for b in range(64)}
        self.counts = dict.fromkeys(range(64), 10000)
        self.rates = dict.fromkeys(range(64), 0)
        self.rates.update({0: 300, 3: 600, 1: 300, 2: 100})
        self.writes = []
        self.fail_write = False
        self.corrupt_readback = False
        self.on_read = None

    def read_buckets(self):
        if self.on_read:
            self.on_read()
        return [(b, *DETECTORS[n]) for b, n in self.owners.items()]

    def counters(self):
        return dict(self.counts)

    def modify_bucket(self, bucket, port, mac):
        self.writes.append((bucket, port, mac))
        if self.fail_write:
            raise RuntimeError('injected write failure')
        self.owners[bucket] = next(n for n, pair in DETECTORS.items() if pair == (port, mac))
        if self.corrupt_readback:
            self.owners[63] = 'd2'

    def advance(self, seconds=1):
        for bucket in self.counts:
            self.counts[bucket] += self.rates[bucket] * seconds


class CollectorFake:
    def __init__(self, runtime, clock):
        self.runtime, self.clock = runtime, clock
        self.change = None
        self.calls = 0

    def read(self):
        self.calls += 1
        loads = [sum(self.runtime.rates[b] for b in range(64) if self.runtime.owners[b] == n)
                 for n in ('d1', 'd2', 'd3')]
        data = view(loads, self.clock.wall())
        if self.change:
            self.change(data, self.calls)
        return data


class TelemetryTests(unittest.TestCase):
    def test_valid_load_and_unknown_metrics(self):
        statuses = validate_view(view(), CONFIG, 1000)
        self.assertEqual(statuses['d1']['load_pps'], 900)
        for status in statuses.values():
            self.assertTrue(status['fresh'])
            for field in ('cpu_percent', 'queue_depth', 'queue_capacity', 'packets_dropped_total', 'per_bucket'):
                self.assertIsNone(status[field])

    def test_stale_missing_malformed_future_and_identity(self):
        mutations = [lambda d: d['servers'].pop('d3'),
                     lambda d: d['servers']['d1'].update(stale=True),
                     lambda d: d['servers']['d1'].update(age_seconds=3.1),
                     lambda d: d['servers']['d1'].update(telemetry=None),
                     lambda d: d['servers']['d1']['telemetry'].update(timestamp=1000.3),
                     lambda d: d['servers']['d1']['telemetry'].update(timestamp=996),
                     lambda d: d['servers']['d1']['telemetry'].update(server_id='d2'),
                     lambda d: d['servers']['d1']['telemetry'].update(packet_rate_pps=None),
                     lambda d: d['servers']['d1']['telemetry'].update(packet_rate_pps=True),
                     lambda d: d['servers']['d1']['telemetry'].update(packet_rate_pps=float('nan')),
                     lambda d: d['servers']['d1']['telemetry'].pop('queue_depth'),
                     lambda d: d['servers']['d1']['telemetry'].update(window_seconds=2),
                     lambda d: d['servers']['d1'].update(age_seconds=None)]
        for change in mutations:
            with self.subTest(change=change):
                data = view()
                change(data)
                with self.assertRaises(TelemetryError):
                    validate_view(data, CONFIG, 1000)

    def test_age_boundary_and_age_during_confirmation(self):
        data = view(now=997)
        self.assertTrue(validate_view(data, CONFIG, 1000)['d1']['fresh'])
        with self.assertRaises(TelemetryError):
            validate_view(data, CONFIG, 1000.01)
        data = view()
        for entry in data['servers'].values():
            entry['age_seconds'] = 2.9
        with self.assertRaises(TelemetryError):
            validate_view(data, CONFIG, 999, extra_age=.2)

    def test_timestamp_skew(self):
        data = view()
        data['servers']['d3']['telemetry']['timestamp'] = 998
        with self.assertRaisesRegex(TelemetryError, 'unsynchronized'):
            validate_view(data, CONFIG, 1000)

    def test_client_rejects_malformed_duplicate_and_oversized_json(self):
        from unittest.mock import MagicMock
        for raw in (b'{', b'{"servers":{},"servers":{}}', b'x' * (TelemetryClient.MAX_RESPONSE + 1)):
            client = TelemetryClient(CONFIG['collector_url'])
            response = MagicMock()
            response.status = 200
            response.headers.get_content_type.return_value = 'application/json'
            response.read.return_value = raw
            response.__enter__.return_value = response
            with self.subTest(size=len(raw)), patch.object(client.opener, 'open', return_value=response):
                with self.assertRaises(TelemetryError):
                    client.read()


class CounterTests(unittest.TestCase):
    def setUp(self):
        self.owners = RuntimeFake().owners
        self.a = Snapshot(1, self.owners, dict.fromkeys(range(64), 100))
        self.b = Snapshot(3, self.owners, dict.fromkeys(range(64), 110))

    def test_rates(self):
        self.assertEqual(bucket_rates(self.a, self.b, CONFIG), dict.fromkeys(range(64), 5))

    def test_missing_invalid_counters(self):
        for counters in ({}, {**self.a.counters, 0: -1}, {**self.a.counters, 0: True},
                         {**self.a.counters, 0: 1.5}, {**self.a.counters, 0: 2**64}):
            with self.subTest(counters=counters), self.assertRaises(ValueError):
                validate_counters(counters)

    def test_reset_and_unknown_wrap(self):
        self.b.counters[0] = 2
        with self.assertRaisesRegex(ValueError, 'reset'):
            bucket_rates(self.a, self.b, CONFIG)

    def test_known_boundary_wrap(self):
        self.a.counters[0] = 250
        self.b.counters[0] = 4
        self.assertEqual(bucket_rates(self.a, self.b, dict(CONFIG, counter_bits=8, maximum_bucket_pps=100))[0], 5)
        self.a.counters[0] = 100
        with self.assertRaises(ValueError):
            bucket_rates(self.a, self.b, dict(CONFIG, counter_bits=8, maximum_bucket_pps=100))

    def test_ambiguous_multiple_wraps_rejected(self):
        with self.assertRaisesRegex(ValueError, 'multiple wraps'):
            bucket_rates(self.a, self.b, dict(CONFIG, counter_bits=8))

    def test_zero_negative_short_long_elapsed(self):
        for timestamp in (1, 0, 1.01, 100):
            with self.subTest(timestamp=timestamp), self.assertRaises(ValueError):
                bucket_rates(self.a, Snapshot(timestamp, self.owners, self.b.counters), CONFIG)

    def test_ownership_change_rejected(self):
        with self.assertRaises(ControllerError):
            bucket_rates(self.a, Snapshot(3, self.owners | {0: 'd3'}, self.b.counters), CONFIG)

    def test_implausible_rate(self):
        self.b.counters[0] = 100000000
        with self.assertRaisesRegex(ValueError, 'implausible'):
            bucket_rates(self.a, self.b, CONFIG)


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.runtime = RuntimeFake()
        self.loads = dict(zip(('d1', 'd2', 'd3'), (900, 300, 100)))

    def select(self, **overrides):
        return select_candidate(overrides.get('loads', self.loads),
                                overrides.get('rates', self.runtime.rates), self.runtime.owners,
                                overrides.get('config', CONFIG), 100, overrides.get('actions', {}))

    def test_best_benefit_and_numeric_example(self):
        candidate = self.select()
        self.assertEqual(candidate['bucket'], 0)
        self.assertEqual(candidate['destination'], 'd3')
        self.assertEqual(candidate['predicted_loads'], {'d1': 600, 'd2': 300, 'd3': 400})
        self.assertEqual(candidate['improvement_pps'], 500)

    def test_balanced_and_idle(self):
        self.assertIsNone(self.select(loads=dict.fromkeys(('d1', 'd2', 'd3'), 100)))
        self.assertIsNone(self.select(rates=dict.fromkeys(range(64), 0)))

    def test_overshoot_and_insufficient_benefit(self):
        self.assertIsNone(self.select(config=dict(CONFIG, minimum_improvement_pps=1000)))
        rates = dict.fromkeys(range(64), 0)
        rates[0] = 900
        self.assertIsNone(self.select(rates=rates))
        rates[0] = 901
        self.assertIsNone(self.select(rates=rates))

    def test_bucket_cooldown_avoids_ping_pong(self):
        candidate = self.select(actions={0: 99})
        self.assertEqual(candidate['bucket'], 3)
        self.assertIsNone(self.select(actions={0: 99, 3: 99}))

    def test_only_source_owned_buckets(self):
        self.runtime.rates[1] = 400
        self.assertEqual(self.select()['source'], 'd1')
        self.assertNotEqual(self.select()['bucket'], 1)


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.runtime = RuntimeFake()
        self.collector = CollectorFake(self.runtime, self.clock)
        self.config = dict(CONFIG, sustained_seconds=2)

    def controller(self, **kwargs):
        return AdaptiveController(self.runtime, self.collector, self.config, DETECTORS,
                                  monotonic=self.clock.monotonic, wall=self.clock.wall, **kwargs)

    def tick(self, controller, seconds=1):
        self.clock.now += seconds
        self.runtime.advance(seconds)
        return controller.step()

    def ready(self, controller):
        self.assertIn('baseline', controller.step()['reason'])
        self.tick(controller)
        self.tick(controller)
        return self.tick(controller)

    def test_sustain_and_dry_run_zero_writes(self):
        controller = self.controller()
        decision = self.ready(controller)
        self.assertEqual(decision['status'], 'proposed')
        self.assertEqual(decision['candidate']['bucket'], 0)
        self.assertEqual(self.runtime.writes, [])
        self.assertEqual(controller.action_count, 1)

    def test_live_acknowledgement_gate(self):
        with self.assertRaisesRegex(ValueError, 'acknowledgement'):
            self.controller(live=True)

    def test_live_success_one_write_and_restoration_via_existing_transaction(self):
        original = dict(self.runtime.owners)
        controller = self.controller(live=True, acknowledge_state_loss=True)
        decision = self.ready(controller)
        self.assertEqual(decision['status'], 'migrated')
        expected = dict(original)
        expected[0] = 'd3'
        self.assertEqual(self.runtime.owners, expected)
        self.assertEqual(len(self.runtime.writes), 1)
        BucketController(self.runtime, DETECTORS).migrate(0, original[0], expected_assignments=expected)
        self.assertEqual(self.runtime.owners, original)

    def test_write_failure_latches_no_retry(self):
        self.runtime.fail_write = True
        controller = self.controller(live=True, acknowledge_state_loss=True)
        decision = self.ready(controller)
        self.assertEqual(decision['status'], 'fault')
        self.assertIn('write failure', decision['reason'])
        self.assertEqual(self.tick(controller)['status'], 'fault')
        self.assertEqual(len(self.runtime.writes), 1)

    def test_lost_primary_at_write_fails_closed(self):
        def denied(*args):
            raise ControllerError('PERMISSION_DENIED: another writer is primary')
        self.runtime.modify_bucket = denied
        controller = self.controller(live=True, acknowledge_state_loss=True)
        decision = self.ready(controller)
        self.assertEqual(decision['status'], 'fault')
        self.assertIn('another writer', decision['reason'])
        self.assertEqual(self.tick(controller)['status'], 'fault')

    def test_live_window_settling_no_second_write(self):
        self.config['max_migrations'] = 2
        controller = self.controller(live=True, acknowledge_state_loss=True)
        self.ready(controller)
        results = [self.tick(controller) for _ in range(7)]
        self.assertTrue(any('windows to settle' in s['reason'] for s in results))
        self.assertEqual(len(self.runtime.writes), 1)

    def test_readback_mismatch_latches(self):
        self.runtime.corrupt_readback = True
        controller = self.controller(live=True, acknowledge_state_loss=True)
        decision = self.ready(controller)
        self.assertEqual(decision['status'], 'fault')
        self.assertIn('readback', decision['reason'])
        self.assertTrue(decision['requires_operator_inspection'])

    def test_stale_confirmation_no_write(self):
        def change(data, calls):
            if calls == 5:
                data['servers']['d1']['stale'] = True
        self.collector.change = change
        controller = self.controller(live=True, acknowledge_state_loss=True)
        self.assertEqual(self.ready(controller)['status'], 'inhibited')
        self.assertEqual(self.runtime.writes, [])

    def test_benefit_disappears_before_write(self):
        def change(data, calls):
            if calls == 5:
                for name in ('d1', 'd2', 'd3'):
                    data['servers'][name]['telemetry']['packet_rate_pps'] = 450
        self.collector.change = change
        self.config.update(load_tolerance_pps=1000)
        controller = self.controller(live=True, acknowledge_state_loss=True)
        decision = self.ready(controller)
        self.assertIn('changed during confirmation', decision['reason'])
        self.assertFalse(self.runtime.writes)

    def test_telemetry_expiring_in_transaction_preread_never_writes(self):
        controller = self.controller(live=True, acknowledge_state_loss=True)
        def slow_read():
            if controller.attempted_candidate is not None:
                self.clock.now += 4
                self.runtime.on_read = None
        self.runtime.on_read = slow_read
        decision = self.ready(controller)
        self.assertEqual(decision['status'], 'inhibited')
        self.assertFalse(self.runtime.writes)

    def test_external_assignment_change_fails_closed(self):
        controller = self.controller()
        controller.step()
        self.runtime.owners[0] = 'd2'
        self.assertEqual(self.tick(controller)['status'], 'fault')
        self.assertFalse(self.runtime.writes)

    def test_stale_resets_sustained_duration_then_recovers(self):
        controller = self.controller()
        controller.step()
        self.tick(controller)
        self.collector.change = lambda d, _: d['servers']['d1'].update(stale=True)
        self.assertEqual(self.tick(controller)['status'], 'inhibited')
        self.assertIsNone(controller.since)
        self.collector.change = None
        self.assertIn('baseline', self.tick(controller)['reason'])
        self.assertIn('sustained', self.tick(controller)['reason'])
        self.assertFalse(self.runtime.writes)

    def test_counter_reset_rebaselines_without_write(self):
        controller = self.controller()
        controller.step()
        self.runtime.counts[0] = 0
        result = self.tick(controller)
        self.assertIn('reset', result['reason'])
        self.assertIsNone(controller.previous)
        self.assertFalse(self.runtime.writes)

    def test_counter_telemetry_mismatch(self):
        controller = self.controller()
        controller.step()
        self.collector.change = lambda d, _: d['servers']['d1']['telemetry'].update(packet_rate_pps=10)
        self.assertIn('disagreement', self.tick(controller)['reason'])
        self.assertFalse(self.runtime.writes)

    def test_balanced_no_migration(self):
        self.runtime.rates.update({0: 100, 3: 0, 1: 100, 2: 100})
        controller = self.controller()
        controller.step()
        for _ in range(6):
            self.assertIn('balanced', self.tick(controller)['reason'])
        self.assertFalse(self.runtime.writes)

    def test_global_cooldown_and_budget(self):
        controller = self.controller()
        self.ready(controller)
        self.assertIn('sustained', self.tick(controller, 3)['reason'])
        self.assertIn('budget', self.tick(controller, 2)['reason'])
        controller.config['max_migrations'] = 2
        controller.settling_until = 0
        self.assertIn('cooldown', self.tick(controller)['reason'])

    def test_hysteresis_band_and_exit(self):
        controller = self.controller()
        controller.step()
        self.tick(controller)
        since = controller.since
        # Same pair, above exit but below entry: retain latch and original start.
        self.runtime.rates.update({0: 130, 3: 0, 1: 100, 2: 70})
        self.tick(controller)
        self.assertEqual(controller.since, since)
        self.runtime.rates.update({0: 100, 1: 100, 2: 100})
        self.tick(controller)
        self.assertIsNone(controller.since)

    def test_expected_assignment_guard_zero_writes(self):
        expected = dict(self.runtime.owners)
        self.runtime.owners[63] = 'd2'
        with self.assertRaisesRegex(ControllerError, 'changed since decision'):
            BucketController(self.runtime, DETECTORS).migrate(0, 'd3', expected_assignments=expected)
        self.assertFalse(self.runtime.writes)


class CLITests(unittest.TestCase):
    def test_default_dry_cli_is_bounded_and_closes_session(self):
        runtime = RuntimeFake()
        closed = []
        class Context:
            def __enter__(self):
                return runtime
            def __exit__(self, *args):
                closed.append(True)
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / 'adaptive.json'
            config_path.write_text(json.dumps(dict(CONFIG, poll_seconds=.1)))
            output = io.StringIO()
            with patch('controller.adaptive_cli.TelemetryClient') as factory, contextlib.redirect_stdout(output):
                factory.return_value.read.side_effect = lambda: view(now=time.time())
                result = main(['--iterations', '2', '--config', str(config_path)],
                              runtime_factory=lambda *args: Context())
            self.assertEqual(result, 0)
            records = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(len(records), 2)
            self.assertTrue(all(r['mode'] == 'dry-run' for r in records))
            self.assertFalse(runtime.writes)
            self.assertEqual(closed, [True])

    def test_live_requires_both_flags_before_runtime(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(['--live'])

    def test_writer_conflict_diagnostic(self):
        def conflict(*args):
            raise ControllerError('not primary: equal-election controller owns switch')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(['--iterations', '1'], runtime_factory=conflict), 1)
        self.assertIn('not primary', json.loads(output.getvalue())['reason'])

    def test_invalid_settings(self):
        for key, value in [('poll_seconds', 0), ('counter_bits', True), ('max_migrations', 0),
                           ('imbalance_exit_ratio', 1), ('max_telemetry_age_seconds', 4)]:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'config.json'
                path.write_text(json.dumps(dict(CONFIG, **{key: value})))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    load_settings(path)


class HTTPIntegrationTests(unittest.TestCase):
    def test_existing_collector_sender_to_adaptive_dry_run(self):
        store = Store(('d1', 'd2', 'd3'))
        server = make_server(('127.0.0.1', 0), store)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02})
        thread.start()
        try:
            endpoint = 'http://127.0.0.1:%s/api/v1/telemetry' % server.server_address[1]
            clock, runtime = Clock(), RuntimeFake()
            sender = Sender(endpoint)
            controller = AdaptiveController(runtime, TelemetryClient(endpoint), dict(CONFIG, sustained_seconds=1),
                                            DETECTORS, monotonic=clock.monotonic, wall=time.time)
            statuses = []
            for index in range(3):
                for entry in view(now=time.time())['servers'].values():
                    self.assertTrue(sender.send(entry['telemetry']))
                statuses.append(controller.step()['status'])
                runtime.advance()
                clock.now += 1
            self.assertEqual(statuses[-1], 'proposed')
            self.assertFalse(runtime.writes)
            with self.assertRaises(TelemetryError):
                TelemetryClient(endpoint + '/missing').read()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())


class RestorationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import runpy
        cls.worker_module = runpy.run_path('tests/topology/checkpoint4_worker.py')

    def test_restore_only_our_bucket_with_full_readback(self):
        runtime = RuntimeFake()
        original = dict(runtime.owners)
        runtime.owners[0] = 'd3'
        result = self.worker_module['restore_assignments'](BucketController(runtime, DETECTORS), original, {0: 'd3'})
        self.assertTrue(result['restored'])
        self.assertEqual(runtime.owners, original)
        self.assertEqual(len(runtime.writes), 1)

    def test_restoration_refuses_unrelated_and_unknown_owner_changes(self):
        for updates in ({0: 'd3', 63: 'd2'}, {0: 'd2'}):
            runtime = RuntimeFake()
            original = dict(runtime.owners)
            runtime.owners.update(updates)
            with self.subTest(updates=updates), self.assertRaises(ControllerError):
                self.worker_module['restore_assignments'](BucketController(runtime, DETECTORS), original, {0: 'd3'})
            self.assertFalse(runtime.writes)

    def test_finally_restoration_and_separate_cleanup_errors(self):
        import sys
        for fail_restore in (False, True):
            with self.subTest(fail_restore=fail_restore), tempfile.TemporaryDirectory() as directory:
                runtime = RuntimeFake()
                original = dict(runtime.owners)
                class Context:
                    def __enter__(self):
                        return runtime
                    def __exit__(self, *args):
                        pass
                class Engine:
                    attempted_candidate = None
                    def step(self):
                        runtime.owners[0] = 'd3'
                        runtime.fail_write = fail_restore
                        self.attempted_candidate = dict(bucket=0, destination='d3')
                        return dict(status='migrated', candidate=dict(bucket=0, destination='d3'))
                destination = Path(directory) / 'report.json'
                argv = ['worker', '--config', 'config/checkpoint4.json', '--report', str(destination),
                        '--live', '--acknowledge-state-loss']
                execute = self.worker_module['main']
                # The live step is followed by a simulated parent/test error. Even
                # that failure must enter the restoration finally block.
                with patch('controller.runtime.Runtime', return_value=Context()), \
                     patch.dict(execute.__globals__, AdaptiveController=lambda *args, **kwargs: Engine()), \
                     patch.object(sys, 'argv', argv), patch.object(sys, 'stdin',
                     io.StringIO('{"command":"live-step"}\n{"command":"invalid"}\n')), \
                     patch('signal.signal'), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(execute(), 1)
                result = json.loads(destination.read_text())
                self.assertIn('error', result)
                if fail_restore:
                    self.assertTrue(result['cleanup_errors'])
                    self.assertEqual(result['status'], 'FAILED')
                else:
                    self.assertEqual(result['cleanup_errors'], [])
                    self.assertTrue(result['restoration']['restored'])
                    self.assertEqual(runtime.owners, original)


if __name__ == '__main__':
    unittest.main()
