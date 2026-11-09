import copy
import http.client
import json
from pathlib import Path
import runpy
import tempfile
import threading
import unittest
import uuid
from unittest.mock import patch

from controller.core import load_config, BucketController, ControllerError
from controller.state_transfer import StateClient, StateCoordinator, StateHTTPError, StateTransferError, validate_live_pipeline
from detectors.bucket_hash import bucket_for, check_layout, verify_evidence
from detectors.bucket_state import StateStore, digest, load_state_config, validate_snapshot
from detectors.state_api import make_state_server

STATE = load_state_config()
DETECTOR = json.loads(Path('config/checkpoint3.json').read_text())
DETECTORS = load_config()
FLOW = ('10.0.0.1', '10.0.1.100', 40009, 9000, 17)
BUCKET = 59
ATTRIBUTION = 'test-attribution'


def tid():
    return str(uuid.uuid4())


class Clock:
    now = 10.0
    def mono(self):
        return self.now
    def wall(self):
        return 1000 + self.now


class Runtime:
    def __init__(self):
        self.owners = {b: 'd' + str(b % 3 + 1) for b in range(64)}
        self.writes = []
        self.failure = None
    def read_buckets(self):
        return [(b, *DETECTORS[n]) for b, n in self.owners.items()]
    def modify_bucket(self, bucket, port, mac):
        self.writes.append(bucket)
        if self.failure == 'reject':
            raise ControllerError('write rejected')
        self.owners[bucket] = next(n for n, value in DETECTORS.items() if value == (port, mac))
        if self.failure == 'applied_timeout':
            raise TimeoutError('write response lost after apply')
        if self.failure == 'unrelated':
            self.owners[0] = 'd2'


class LocalClient:
    def __init__(self, stores):
        self.stores = stores
        self.before = None
        self.after = None
    def call(self, server, operation, body=None):
        if self.before:
            self.before(server, operation, body)
        store = self.stores[server]
        if operation == 'health':
            result = dict(server_id=server, boot_id=store.boot_id, attribution_id=store.attribution_id, enabled=True)
        else:
            try:
                result = store.handle(operation, body)
            except KeyError as exc:
                raise StateHTTPError(str(exc), 404)
        if self.after:
            self.after(server, operation, body, result)
        return result


class Fixture(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.config = dict(STATE, enabled=True)
        self.detector = dict(DETECTOR, threshold_pps=1, minimum_packets=1,
                             max_flows=STATE['max_flows_per_bin'], max_sources=STATE['max_flows_per_bin'])
        self.stores = {n: StateStore(n, self.config, self.detector, ATTRIBUTION,
                                  wall=self.clock.wall, monotonic=self.clock.mono) for n in DETECTORS}
        for _ in range(7):
            self.stores['d3'].observe(FLOW, 74)
        self.clock.now += 3.1
        self.stores['d3'].tick()
        self.runtime = Runtime()
        self.original = dict(self.runtime.owners)
        self.client = LocalClient(self.stores)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.coordinator = StateCoordinator(self.runtime, DETECTORS, self.client, self.config,
                                            ATTRIBUTION, journal=self.directory.name)
    def body(self, server, transaction, **extra):
        return dict(server_id=server, bucket_id=BUCKET, transfer_id=transaction, **extra)
    def exported(self, transaction):
        return self.stores['d3'].handle('export', self.body('d3', transaction, destination='d1'))['snapshot']


class AttributionTests(unittest.TestCase):
    def test_actual_compiled_layout_and_recorded_flow(self):
        check_layout()
        self.assertEqual(bucket_for(FLOW), BUCKET)
    def test_strict_tuple_validation(self):
        for flow in (FLOW[:4], FLOW[:2]+(True, 9000, 17), FLOW[:2]+(65536, 9000, 17), FLOW[:4]+(1,)):
            with self.subTest(flow=flow), self.assertRaises(ValueError):
                bucket_for(flow)
    def test_oracle_evidence_matches_current_artifacts(self):
        evidence = verify_evidence('logs/checkpoint5-hash.json')
        self.assertEqual(len(evidence), 64)

    def test_live_pipeline_must_match_verified_json(self):
        from unittest.mock import Mock
        runtime = Mock(device_id=0, timeout=.5)
        pipeline = json.loads(Path('p4/dynohash.json').read_text())
        runtime.stub.GetForwardingPipelineConfig.return_value.config.p4_device_config = json.dumps(pipeline).encode()
        validate_live_pipeline(runtime, digest(pipeline))
        runtime.stub.GetForwardingPipelineConfig.return_value.config.p4_device_config = b'{}'
        with self.assertRaises(StateTransferError):
            validate_live_pipeline(runtime, digest(pipeline))


class StoreTests(Fixture):
    def test_export_serializable_real_flow_bins_and_heuristic(self):
        snapshot = self.exported(tid())
        self.assertEqual(snapshot['state']['packets_total'], 7)
        self.assertEqual(sum(sum(b['flows'].values()) for b in snapshot['state']['bins']), 7)
        self.assertEqual(len(snapshot['state']['alerts']), 1)
        json.dumps(snapshot, allow_nan=False)
        validate_snapshot(snapshot, self.config, self.detector, ATTRIBUTION, self.clock.wall())
    def test_prepare_does_not_activate_commit_merges_only_post_prepare_delta(self):
        transaction = tid()
        snapshot = self.exported(transaction)
        for _ in range(2):
            self.stores['d1'].observe(FLOW, 74)
        prepared = self.stores['d1'].handle('prepare', self.body('d1', transaction, snapshot=snapshot))
        self.assertEqual(prepared['bucket_state']['packets_total'], 2)
        for _ in range(3):
            self.stores['d1'].observe(FLOW, 74)
        committed = self.stores['d1'].handle('commit', self.body('d1', transaction, owner='d1', ownership_digest='a'*64))
        self.assertEqual(committed['bucket_state']['packets_total'], 10)
        again = self.stores['d1'].handle('commit', self.body('d1', transaction, owner='d1', ownership_digest='a'*64))
        self.assertEqual(again['bucket_state']['packets_total'], 10)
        self.assertEqual(committed['proof']['imported_packets_total'], 7)
    def test_duplicate_export_prepare_are_stable(self):
        transaction = tid()
        first = self.exported(transaction)
        self.stores['d3'].observe(FLOW, 74)
        self.assertEqual(self.exported(transaction), first)
        a = self.stores['d1'].handle('prepare', self.body('d1', transaction, snapshot=first))
        b = self.stores['d1'].handle('prepare', self.body('d1', transaction, snapshot=first))
        self.assertEqual(a, b)
    def test_conflicting_duplicate_and_overlap_rejected(self):
        transaction = tid()
        snapshot = self.exported(transaction)
        with self.assertRaises(RuntimeError):
            self.exported(tid())
        self.stores['d1'].handle('prepare', self.body('d1', transaction, snapshot=snapshot))
        changed = copy.deepcopy(snapshot)
        changed['state']['packets_total'] += 1
        with self.assertRaises(RuntimeError):
            self.stores['d1'].handle('prepare', self.body('d1', transaction, snapshot=changed))
    def test_invalid_age_schema_bucket_identity_and_flow(self):
        snapshot = self.exported(tid())
        for field, value in [('version', 2), ('bucket_id', True), ('source', 'd4'), ('created_at', 0),
                             ('created_at', self.clock.wall()+1), ('attribution_id', 'wrong')]:
            bad = copy.deepcopy(snapshot)
            bad[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_snapshot(bad, self.config, self.detector, ATTRIBUTION, self.clock.wall())
        bad = copy.deepcopy(snapshot)
        bad['bucket_id'] = 0
        with self.assertRaises(ValueError):
            validate_snapshot(bad, self.config, self.detector, ATTRIBUTION, self.clock.wall())
        bad = copy.deepcopy(snapshot)
        bad['statistics_config']['cooldown_seconds'] += 1
        with self.assertRaises(ValueError):
            self.stores['d1'].handle('prepare', self.body('d1', bad['transfer_id'], snapshot=bad))
    def test_expiry_and_clock_rollback_never_rejuvenates_imported_bins(self):
        transaction = tid()
        snapshot = self.exported(transaction)
        self.stores['d1'].handle('prepare', self.body('d1', transaction, snapshot=snapshot))
        self.clock.now += 10
        self.stores['d1'].wall = lambda: snapshot['created_at']-1
        self.stores['d1'].handle('commit', self.body('d1', transaction, owner='d1', ownership_digest='a'*64))
        self.assertEqual(len(self.stores['d1'].buckets[BUCKET]['stats'].bins), 0)
        self.assertEqual(self.stores['d1'].summary(BUCKET)['packets_total'], 7)
    def test_abort_retains_source_and_old_duplicate_cannot_release_new_lock(self):
        old = tid()
        self.exported(old)
        self.stores['d3'].handle('abort', self.body('d3', old))
        new = tid()
        self.exported(new)
        self.stores['d3'].handle('abort', self.body('d3', old))
        self.assertEqual(self.stores['d3'].locks[BUCKET], new)
        self.assertEqual(self.stores['d3'].summary(BUCKET)['packets_total'], 7)
    def test_active_records_bounded_and_not_evicted(self):
        self.stores['d3'].config = dict(self.config, max_records=1)
        self.exported(tid())
        self.clock.now += 1000
        with self.assertRaises(RuntimeError):
            self.exported(tid())
        self.assertEqual(len(self.stores['d3'].records), 1)
    def test_bucket_and_flow_memory_bounds(self):
        store = StateStore('d1', dict(self.config, max_flows_per_bin=2), self.detector, ATTRIBUTION,
                           wall=self.clock.wall, monotonic=self.clock.mono)
        for port in range(1000, 2000):
            store.observe(FLOW[:2]+(port, 9000, 17), 74)
        self.assertLessEqual(len(store.buckets), 64)
        self.assertTrue(all(len(b['flows']) <= 2 for r in store.buckets.values() for b in r['stats'].bins))
    def test_finalization_retains_source_history(self):
        transaction = tid()
        snapshot = self.exported(transaction)
        result = self.stores['d3'].handle('finalize', self.body('d3', transaction, owner='d1', destination_digest=digest(snapshot)))
        self.assertEqual(result['status'], 'finalized')
        self.assertEqual(result['bucket_state']['packets_total'], 7)

    def test_duplicate_old_finalize_does_not_unlock_new_transfer(self):
        old = tid()
        snapshot = self.exported(old)
        body = self.body('d3', old, owner='d1', destination_digest=digest(snapshot))
        self.stores['d3'].handle('finalize', body)
        new = tid()
        self.exported(new)
        self.stores['d3'].handle('finalize', body)
        self.assertEqual(self.stores['d3'].locks[BUCKET], new)

    def test_invalid_window_numbers_and_counter_consistency(self):
        snapshot = self.exported(tid())
        for field, value in [('packets_total', True), ('bytes_total', -1), ('started_age_seconds', float('nan'))]:
            bad = copy.deepcopy(snapshot)
            bad['state'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_snapshot(bad, self.config, self.detector, ATTRIBUTION, self.clock.wall())
        bad = copy.deepcopy(snapshot)
        bad['state']['bins'][0]['sources'] = {'10.0.0.99': 7}
        with self.assertRaises(ValueError):
            validate_snapshot(bad, self.config, self.detector, ATTRIBUTION, self.clock.wall())


class CoordinationTests(Fixture):
    def test_invalid_destination_noop_and_changed_baseline(self):
        with self.assertRaises(StateTransferError):
            self.coordinator.migrate(BUCKET, 'd4')
        self.assertFalse(self.coordinator.migrate(BUCKET, 'd3'))
        self.runtime.owners[BUCKET] = 'd1'
        with self.assertRaises(StateTransferError):
            self.coordinator.migrate(BUCKET, 'd1', expected_assignments=self.original)
        self.assertFalse(self.runtime.writes)
        self.assertTrue(all(not s.records for s in self.stores.values()))
    def test_disabled_feature_rejects_coordinator(self):
        with self.assertRaises(ValueError):
            StateCoordinator(self.runtime, DETECTORS, self.client, dict(self.config, enabled=False), ATTRIBUTION)

    def test_adaptive_live_hook_and_dry_run_no_state_mutations(self):
        base = runpy.run_path('tests/adaptive/test_adaptive.py')
        from controller.adaptive import AdaptiveController, load_settings
        for live in (False, True):
            with self.subTest(live=live):
                runtime = base['RuntimeFake']()
                runtime.rates = dict.fromkeys(range(64), 0)
                runtime.rates.update({59: 300, 2: 600, 0: 300, 1: 100})
                client = base['CollectorFake'](runtime, self.clock)
                coordinator = StateCoordinator(runtime, DETECTORS, self.client, self.config, ATTRIBUTION,
                                                journal=Path(self.directory.name) / str(live))
                adaptive = AdaptiveController(runtime, client, dict(load_settings(), sustained_seconds=1), DETECTORS,
                    live=live, acknowledge_state_loss=live, monotonic=self.clock.mono,
                    wall=self.clock.wall, migrator=coordinator)
                result = adaptive.step()
                for _ in range(3):
                    self.clock.now += 1
                    runtime.advance()
                    self.stores['d3'].observe(FLOW, 74)
                    result = adaptive.step()
                    if result['status'] in ('proposed', 'migrated'):
                        break
                if live:
                    self.assertEqual(result['status'], 'migrated', result)
                    self.assertEqual(result['candidate']['bucket'], BUCKET)
                    self.assertEqual(result['state_transfer']['status'], 'complete')
                    self.assertEqual(len(runtime.writes), 1)
                else:
                    self.assertEqual(result['status'], 'proposed', result)
                    self.assertFalse(runtime.writes)
                    self.assertTrue(all(not s.records for s in self.stores.values()))
    def test_success_exactly_one_modify_and_full_readback(self):
        transaction = tid()
        self.assertTrue(self.coordinator.migrate(BUCKET, 'd1', expected_assignments=self.original, transfer_id_value=transaction))
        self.assertEqual(self.runtime.writes, [BUCKET])
        self.assertEqual(self.coordinator.last_event['status'], 'complete')
        self.assertEqual(self.stores['d1'].summary(BUCKET)['packets_total'], 7)
        self.assertEqual(self.stores['d3'].summary(BUCKET)['packets_total'], 7)
        self.assertTrue(self.coordinator.migrate(BUCKET, 'd1', transfer_id_value=transaction))
        self.assertEqual(self.runtime.writes, [BUCKET])
    def test_destination_unavailable_leaves_p4_unchanged(self):
        def unavailable(server, operation, body):
            if server == 'd1':
                raise StateHTTPError('destination unavailable')
        self.client.before = unavailable
        with self.assertRaises(StateTransferError):
            self.coordinator.migrate(BUCKET, 'd1')
        self.assertEqual(self.runtime.owners, self.original)
        self.assertFalse(self.runtime.writes)
        self.assertEqual(self.stores['d3'].summary(BUCKET)['packets_total'], 7)
    def test_invalid_prepared_payload_aborts_before_write(self):
        def corrupt(server, operation, body):
            if operation == 'prepare':
                body['snapshot']['version'] = 99
        self.client.before = corrupt
        with self.assertRaises(StateTransferError):
            self.coordinator.migrate(BUCKET, 'd1')
        self.assertFalse(self.runtime.writes)
        self.assertNotIn(BUCKET, self.stores['d3'].locks)
    def test_failed_p4_write_aborts_staging_and_preserves_history(self):
        self.runtime.failure = 'reject'
        with self.assertRaises(StateTransferError):
            self.coordinator.migrate(BUCKET, 'd1')
        self.assertEqual(self.runtime.owners, self.original)
        self.assertEqual(self.runtime.writes, [BUCKET])
        self.assertEqual(self.coordinator.last_event['status'], 'aborted')
        self.assertEqual(self.stores['d3'].summary(BUCKET)['packets_total'], 7)
    def test_write_applied_response_lost_reconciles_without_second_modify(self):
        self.runtime.failure = 'applied_timeout'
        transaction = tid()
        with self.assertRaises(StateTransferError):
            self.coordinator.migrate(BUCKET, 'd1', transfer_id_value=transaction)
        self.assertEqual(self.coordinator.last_event['status'], 'uncertain')
        self.assertEqual(self.stores['d1'].records[transaction]['status'], 'prepared')
        self.runtime.failure = None
        self.assertTrue(self.coordinator.migrate(BUCKET, 'd1', transfer_id_value=transaction))
        self.assertEqual(self.runtime.writes, [BUCKET])
    def test_commit_response_timeout_retries_idempotently(self):
        transaction = tid()
        def timeout_after_commit(server, operation, body, result):
            if operation == 'commit':
                raise StateHTTPError('commit response timed out')
        self.client.after = timeout_after_commit
        with self.assertRaises(StateTransferError):
            self.coordinator.migrate(BUCKET, 'd1', transfer_id_value=transaction)
        self.assertEqual(self.stores['d1'].summary(BUCKET)['packets_total'], 7)
        self.client.after = None
        self.assertTrue(self.coordinator.migrate(BUCKET, 'd1', transfer_id_value=transaction))
        self.assertEqual(self.stores['d1'].summary(BUCKET)['packets_total'], 7)
        self.assertEqual(self.runtime.writes, [BUCKET])
    def test_prewrite_freshness_failure_no_modify(self):
        def stale():
            raise ValueError('telemetry expired')
        with self.assertRaises(StateTransferError):
            self.coordinator.migrate(BUCKET, 'd1', before_write=stale)
        self.assertFalse(self.runtime.writes)
        self.assertFalse(self.stores['d3'].locks)
    def test_unrelated_changes_never_blindly_rolled_back(self):
        self.runtime.failure = 'unrelated'
        with self.assertRaises(StateTransferError):
            self.coordinator.migrate(BUCKET, 'd1')
        self.assertEqual(self.runtime.owners[0], 'd2')
        self.assertEqual(self.coordinator.last_event['status'], 'uncertain')
        self.assertIn(BUCKET, self.stores['d3'].locks)
    def test_destination_restart_after_prepare_blocks_source_finalization(self):
        def restart(server, operation, body, result):
            if operation == 'prepare':
                self.stores['d1'].boot_id = tid()
        self.client.after = restart
        with self.assertRaises(StateTransferError):
            self.coordinator.migrate(BUCKET, 'd1')
        self.assertIn(BUCKET, self.stores['d3'].locks)
    def test_reverse_transfer_restores_original_owner_and_state(self):
        self.coordinator.migrate(BUCKET, 'd1')
        self.stores['d1'].observe(FLOW, 74)
        self.coordinator.migrate(BUCKET, 'd3')
        self.assertEqual(self.runtime.owners, self.original)
        self.assertEqual(self.stores['d3'].summary(BUCKET)['packets_total'], 8)

    def test_explicit_abort_requires_verified_original_ownership(self):
        transaction = tid()
        snapshot = self.exported(transaction)
        self.stores['d1'].handle('prepare', self.body('d1', transaction, snapshot=snapshot))
        event = dict(version=1, transfer_id=transaction, bucket_id=BUCKET, source='d3', destination='d1',
                     original_assignments=self.original, status='uncertain', timings_seconds={}, cleanup_errors=[])
        self.coordinator.save(event)
        self.runtime.owners[BUCKET] = 'd1'
        with self.assertRaises(StateTransferError):
            self.coordinator.abort(transaction)
        self.assertIn(BUCKET, self.stores['d1'].locks)
        self.runtime.owners = dict(self.original)
        result = self.coordinator.abort(transaction)
        self.assertEqual(result['status'], 'aborted')
        self.assertFalse(self.stores['d1'].locks)
        self.assertFalse(self.stores['d3'].locks)
        self.assertFalse(self.runtime.writes)


class HTTPTests(Fixture):
    def setUp(self):
        super().setUp()
        self.servers, self.threads = [], []
        self.addCleanup(self.close_servers)
        endpoints = {}
        for name, store in self.stores.items():
            server = make_state_server(('127.0.0.1', 0), store, ['127.0.0.1'])
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02})
            thread.start()
            self.servers.append(server); self.threads.append(thread)
            endpoints[name] = 'http://127.0.0.1:%s' % server.server_address[1]
        self.http = StateClient(endpoints)
    def close_servers(self):
        for server in self.servers:
            server.shutdown(); server.server_close()
        for thread in self.threads:
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
    def test_actual_http_transfer_and_duplicate_commit(self):
        self.coordinator.client = self.http
        transaction = tid()
        self.coordinator.migrate(BUCKET, 'd1', transfer_id_value=transaction)
        status = self.http.call('d1', 'status', self.body('d1', transaction))
        self.assertEqual(status['status'], 'committed')
        self.assertEqual(status['bucket_state']['packets_total'], 7)
        self.coordinator.migrate(BUCKET, 'd1', transfer_id_value=transaction)
        self.assertEqual(self.runtime.writes, [BUCKET])
        self.assertEqual(self.http.call('d1', 'buckets/59')['bucket_state']['packets_total'], 7)
    def test_malformed_request_and_identity_rejected(self):
        for body in ({}, [], {'server_id': 'd4', 'bucket_id': BUCKET, 'transfer_id': tid()}):
            with self.subTest(body=body), self.assertRaises(StateHTTPError):
                self.http.call('d3', 'status', body)
        port = self.servers[2].server_address[1]
        connection = http.client.HTTPConnection('127.0.0.1', port)
        connection.request('POST', '/api/v1/state/export', b'{"x":1,"x":2}', {'Content-Type': 'application/json'})
        result = connection.getresponse()
        self.assertEqual(result.status, 400)
        result.read(); connection.close()
    def test_oversized_body_rejected(self):
        port = self.servers[2].server_address[1]
        connection = http.client.HTTPConnection('127.0.0.1', port)
        connection.request('POST', '/api/v1/state/prepare', b'', {'Content-Type': 'application/json', 'Content-Length': str(STATE['max_body_bytes']+1)})
        result = connection.getresponse()
        self.assertEqual(result.status, 413)
        result.read(); connection.close()
    def test_private_bind_and_peer_allowlist(self):
        for address in ('0.0.0.0', '0', '', '::', '224.0.0.1'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                make_state_server((address, 0), self.stores['d1'], ['127.0.0.1'])
        blocked = make_state_server(('127.0.0.1', 0), self.stores['d1'], [])
        thread = threading.Thread(target=blocked.serve_forever, kwargs={'poll_interval': .02})
        thread.start()
        try:
            client = StateClient({'d1': 'http://127.0.0.1:%s' % blocked.server_address[1]})
            with self.assertRaises(StateHTTPError) as caught:
                client.call('d1', 'health')
            self.assertEqual(caught.exception.status, 403)
        finally:
            blocked.shutdown(); blocked.server_close(); thread.join(timeout=3)

    def test_real_http_commit_timeout_recovery(self):
        import time
        self.coordinator.client = self.http
        self.http.timeout = .05
        original = self.stores['d1'].handle
        def slow_commit(operation, body):
            result = original(operation, body)
            if operation == 'commit':
                time.sleep(.2)
            return result
        transaction = tid()
        with patch.object(self.stores['d1'], 'handle', side_effect=slow_commit):
            with self.assertRaises(StateTransferError):
                self.coordinator.migrate(BUCKET, 'd1', transfer_id_value=transaction)
            time.sleep(.25)
        self.http.timeout = .5
        self.coordinator.migrate(BUCKET, 'd1', transfer_id_value=transaction)
        self.assertEqual(self.runtime.writes, [BUCKET])
        self.assertEqual(self.stores['d1'].summary(BUCKET)['packets_total'], 7)


if __name__ == '__main__':
    unittest.main()
