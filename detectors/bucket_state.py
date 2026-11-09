"""Bounded bucket history and idempotent in-memory staging; no raw packets retained."""
from collections import Counter, deque
import copy
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import threading
import time
import uuid

from .bucket_hash import ROOT, bucket_for
from .statistics import Statistics, validate_config

IDS = ('d1', 'd2', 'd3')
STAT_KEYS = ('window_seconds', 'threshold_pps', 'minimum_window_seconds', 'minimum_packets',
             'cooldown_seconds', 'max_flows', 'max_sources')


def load_state_config(path=ROOT / 'config/checkpoint5.json'):
    config = json.loads(Path(path).read_text())
    defaults = json.loads((ROOT / 'config/checkpoint5.json').read_text())
    if not isinstance(config, dict) or set(config) != set(defaults) or type(config['enabled']) is not bool:
        raise ValueError('invalid checkpoint5 settings')
    for key in ('port', 'max_snapshot_age_seconds', 'max_body_bytes', 'max_records',
                'record_retention_seconds', 'max_flows_per_bin'):
        if type(config[key]) is not int or config[key] <= 0:
            raise ValueError('positive integer required: ' + key)
    if not 1024 <= config['port'] <= 65535 or not 4096 <= config['max_body_bytes'] <= 131072:
        raise ValueError('unsupported API port/body limit')
    if config['max_records'] > 128 or config['max_flows_per_bin'] > 128 or config['max_snapshot_age_seconds'] > 30:
        raise ValueError('state bounds exceed supported limits')
    if not 0 < config['http_timeout_seconds'] <= 2 or type(config['http_timeout_seconds']) is bool:
        raise ValueError('invalid state HTTP timeout')
    for key in ('attribution_evidence', 'journal_directory'):
        if not isinstance(config[key], str) or not config[key]:
            raise ValueError('path required: ' + key)
    return config


def number(value, maximum=2**63-1, integer=False):
    if (isinstance(value, bool) or not isinstance(value, (int, float)) or
            not 0 <= value <= maximum or not math.isfinite(value) or
            (integer and type(value) is not int)):
        raise ValueError('invalid finite nonnegative state number')
    return value


def transfer_id(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError('canonical UUID transfer_id required')
    return value


def bucket_id(value):
    if type(value) is not int or not 0 <= value < 64:
        raise ValueError('bucket_id must be 0..63')
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def encode_stats(stats, now):
    return dict(packets_total=stats.total, bytes_total=stats.total_bytes,
                started_age_seconds=min(now-stats.started, stats.config['window_seconds']),
                last_alert_age_seconds=None if stats.last_alert == -math.inf else max(0, now-stats.last_alert),
                alert_count=stats.alert_count, alerts=list(stats.alerts),
                bins=[dict(age_seconds=max(0, now-b['second']), packets=b['packets'], bytes=b['bytes'],
                           flows=dict(b['flows']), sources=dict(b['sources']), limited=b['limited']) for b in stats.bins])


def validate_snapshot(snapshot, config, detector_config, attribution_id, now):
    expected = {'version', 'transfer_id', 'bucket_id', 'source', 'destination', 'source_boot_id',
                'created_at', 'attribution_id', 'first_seen', 'last_seen', 'state', 'statistics_config'}
    if not isinstance(snapshot, dict) or set(snapshot) != expected or type(snapshot['version']) is not int or snapshot['version'] != 1:
        raise ValueError('unsupported state schema')
    transfer_id(snapshot['transfer_id'])
    transfer_id(snapshot['source_boot_id'])
    bucket = bucket_id(snapshot['bucket_id'])
    if snapshot['source'] not in IDS or snapshot['destination'] not in IDS or snapshot['source'] == snapshot['destination']:
        raise ValueError('invalid source/destination')
    if snapshot['attribution_id'] != attribution_id:
        raise ValueError('hash attribution evidence differs')
    if digest(snapshot['statistics_config']) != digest({k: detector_config[k] for k in STAT_KEYS}):
        raise ValueError('bucket statistics/heuristic configuration differs')
    number(snapshot['created_at'])
    if not -.25 <= now-snapshot['created_at'] <= config['max_snapshot_age_seconds']:
        raise ValueError('snapshot timestamp is stale/future')
    number(snapshot['first_seen']); number(snapshot['last_seen'])
    if not snapshot['first_seen'] <= snapshot['last_seen'] <= snapshot['created_at'] + .25:
        raise ValueError('invalid observation timestamps')
    state = snapshot['state']
    if not isinstance(state, dict) or set(state) != {'packets_total', 'bytes_total', 'started_age_seconds', 'last_alert_age_seconds', 'alert_count', 'alerts', 'bins'}:
        raise ValueError('invalid bucket state')
    for key in ('packets_total', 'bytes_total', 'alert_count'):
        number(state[key], integer=True)
    number(state['started_age_seconds'], detector_config['window_seconds'])
    if state['last_alert_age_seconds'] is not None:
        number(state['last_alert_age_seconds'])
    if not isinstance(state['alerts'], list) or len(state['alerts']) > 32:
        raise ValueError('invalid alert history')
    seen_alerts = set()
    for alert in state['alerts']:
        if not isinstance(alert, dict) or set(alert) != {'id', 'timestamp', 'packet_rate_pps'}:
            raise ValueError('invalid heuristic alert')
        number(alert['id'], state['alert_count'], integer=True)
        number(alert['timestamp']); number(alert['packet_rate_pps'])
        if alert['id'] in seen_alerts or alert['timestamp'] > snapshot['created_at'] + .25:
            raise ValueError('invalid alert sequence/time')
        seen_alerts.add(alert['id'])
    if not isinstance(state['bins'], list) or len(state['bins']) > detector_config['window_seconds']:
        raise ValueError('invalid rolling window')
    ages = set()
    for entry in state['bins']:
        if not isinstance(entry, dict) or set(entry) != {'age_seconds', 'packets', 'bytes', 'flows', 'sources', 'limited'}:
            raise ValueError('invalid window bin')
        number(entry['age_seconds'], detector_config['window_seconds'])
        slot = math.floor(entry['age_seconds'])
        if slot in ages:
            raise ValueError('duplicate window bin')
        ages.add(slot)
        number(entry['packets'], integer=True); number(entry['bytes'], integer=True)
        if type(entry['limited']) is not bool:
            raise ValueError('invalid limit flag')
        for key in ('flows', 'sources'):
            if not isinstance(entry[key], dict) or len(entry[key]) > config['max_flows_per_bin']:
                raise ValueError('state identity bound exceeded')
        for key, count in entry['flows'].items():
            flow = json.loads(key)
            if not isinstance(flow, list) or len(flow) != 5 or not all(isinstance(ip, str) for ip in flow[:2]) or bucket_for(flow) != bucket:
                raise ValueError('flow does not belong to exported bucket')
            number(count, integer=True)
        for source, count in entry['sources'].items():
            ipaddress.IPv4Address(source)
            number(count, integer=True)
        tracked_sources = Counter()
        for key, count in entry['flows'].items():
            tracked_sources[json.loads(key)[0]] += count
        if any(entry['sources'].get(source, 0) < count for source, count in tracked_sources.items()):
            raise ValueError('flow/source counters disagree')
        if entry['bytes'] < entry['packets'] or any(sum(entry[k].values()) > entry['packets'] for k in ('flows', 'sources')):
            raise ValueError('window counters are inconsistent')
        if not entry['limited'] and any(sum(entry[k].values()) != entry['packets'] for k in ('flows', 'sources')):
            raise ValueError('complete identity counters do not sum to packet count')
    if sum(b['packets'] for b in state['bins']) > state['packets_total'] or sum(b['bytes'] for b in state['bins']) > state['bytes_total']:
        raise ValueError('rolling counters exceed lifetime counters')
    return copy.deepcopy(snapshot)


def decode_stats(state, detector_config, mono, elapsed):
    stats = Statistics(detector_config, now=mono)
    stats.total, stats.total_bytes = state['packets_total'], state['bytes_total']
    stats.started = mono - min(state['started_age_seconds'] + elapsed, detector_config['window_seconds'])
    stats.last_alert = -math.inf if state['last_alert_age_seconds'] is None else mono-state['last_alert_age_seconds']-elapsed
    stats.alert_count = state['alert_count']
    stats.alerts = deque(copy.deepcopy(state['alerts']), maxlen=32)
    for b in sorted(state['bins'], key=lambda b: -b['age_seconds']):
        stats.bins.append(dict(second=math.floor(mono-b['age_seconds']-elapsed), packets=b['packets'], bytes=b['bytes'],
                               flows=Counter(b['flows']), sources=Counter(b['sources']), limited=b['limited']))
    stats.expire(mono)
    return stats


def merge_stats(base, delta, now):
    base.expire(now); delta.expire(now)
    base.total += delta.total; base.total_bytes += delta.total_bytes
    base.started = min(base.started, delta.started)
    base.last_alert = max(base.last_alert, delta.last_alert)
    alerts = sorted(list(base.alerts)+list(delta.alerts), key=lambda a: a['timestamp'])[-32:]
    base.alert_count += delta.alert_count
    base.alerts = deque([dict(a, id=base.alert_count-len(alerts)+i+1) for i, a in enumerate(alerts)], maxlen=32)
    bins = {b['second']: copy.deepcopy(b) for b in base.bins}
    for b in delta.bins:
        if b['second'] not in bins:
            bins[b['second']] = copy.deepcopy(b)
            continue
        target = bins[b['second']]
        target['packets'] += b['packets']; target['bytes'] += b['bytes']
        target['limited'] |= b['limited']
        for field in ('flows', 'sources'):
            for key, count in b[field].items():
                if key in target[field] or len(target[field]) < base.config['max_flows' if field == 'flows' else 'max_sources']:
                    target[field][key] += count
                else:
                    target['limited'] = True
    base.bins = deque(bins[k] for k in sorted(bins))
    return base


class StateStore:
    def __init__(self, server_id, config, detector_config, attribution_id, *, wall=time.time, monotonic=time.monotonic):
        if server_id not in IDS:
            raise ValueError('unknown detector')
        if detector_config['window_seconds'] > 10:
            raise ValueError('state transfer supports up to ten one-second bins')
        self.server_id, self.config, self.attribution_id = server_id, config, attribution_id
        self.detector_config = dict(detector_config, max_flows=config['max_flows_per_bin'], max_sources=config['max_flows_per_bin'])
        validate_config(self.detector_config)
        self.wall, self.monotonic = wall, monotonic
        self.boot_id = str(uuid.uuid4())
        self.buckets, self.records, self.locks = {}, {}, {}
        self.lock = threading.RLock()

    def new_bucket(self):
        return dict(stats=Statistics(self.detector_config, now=self.monotonic()),
                    first_seen=self.wall(), last_seen=self.wall())

    def observe(self, flow, size):
        bucket = bucket_for(flow)
        with self.lock:
            if bucket not in self.buckets:
                self.buckets[bucket] = self.new_bucket()
            record = self.buckets[bucket]
            record['stats'].observe(flow, size, now=self.monotonic())
            record['last_seen'] = self.wall()
            active = self.records.get(self.locks.get(bucket))
            if active and active['status'] == 'prepared':
                active['delta'].observe(flow, size, now=self.monotonic())
        return bucket

    def tick(self):
        with self.lock:
            for record in self.buckets.values():
                record['stats'].snapshot(self.server_id, now=self.monotonic(), timestamp=self.wall())
            for record in self.records.values():
                if record['status'] == 'prepared':
                    record['delta'].snapshot(self.server_id, now=self.monotonic(), timestamp=self.wall())

    def summary(self, bucket):
        record = self.buckets.get(bucket)
        if record is None:
            return dict(packets_total=0, bytes_total=0, flow_bin_records=0)
        stats = record['stats']
        return dict(packets_total=stats.total, bytes_total=stats.total_bytes,
                    flow_bin_records=sum(len(b['flows']) for b in stats.bins),
                    alerts=list(stats.alerts))

    def response(self, record):
        return dict(server_id=self.server_id, boot_id=self.boot_id, transfer_id=record['transfer_id'],
                    bucket_id=record['bucket_id'], status=record['status'],
                    snapshot_digest=record['digest'], proof=record.get('proof'),
                    bucket_state=self.summary(record['bucket_id']))

    def handle(self, operation, body):
        extras = {'export': {'destination'}, 'prepare': {'snapshot'}, 'status': set(),
                  'commit': {'owner', 'ownership_digest'}, 'finalize': {'owner', 'destination_digest'}, 'abort': set()}
        if operation not in extras or not isinstance(body, dict) or set(body) != {'server_id', 'bucket_id', 'transfer_id'} | extras[operation]:
            raise ValueError('invalid operation/request fields')
        if body['server_id'] != self.server_id:
            raise ValueError('wrong detector identity')
        bucket, tid = bucket_id(body['bucket_id']), transfer_id(body['transfer_id'])
        with self.lock:
            now = self.monotonic()
            # Active/uncertain records are NEVER evicted automatically. Exhaustion
            # refuses new work rather than dropping a possibly needed snapshot.
            for old_id, old in list(self.records.items()):
                if old['status'] in ('aborted', 'committed', 'finalized') and now-old['updated'] > self.config['record_retention_seconds']:
                    del self.records[old_id]
            record = self.records.get(tid)
            if record and record['bucket_id'] != bucket:
                raise ValueError('transfer ID reused for another bucket')
            if operation in ('export', 'prepare') and record is None:
                if len(self.records) >= self.config['max_records']:
                    raise RuntimeError('state transaction capacity exhausted')
                if bucket in self.locks:
                    raise RuntimeError('bucket already has an active transfer')
                if operation == 'export':
                    if body['destination'] not in IDS or body['destination'] == self.server_id:
                        raise ValueError('invalid destination')
                    if bucket not in self.buckets:
                        raise ValueError('no observed state for bucket')
                    self.tick()
                    observed = self.buckets[bucket]
                    snapshot = dict(version=1, transfer_id=tid, bucket_id=bucket, source=self.server_id,
                                    destination=body['destination'], source_boot_id=self.boot_id, created_at=self.wall(),
                                    attribution_id=self.attribution_id, first_seen=observed['first_seen'], last_seen=observed['last_seen'],
                                    statistics_config={k: self.detector_config[k] for k in STAT_KEYS},
                                    state=encode_stats(observed['stats'], now))
                else:
                    snapshot = validate_snapshot(body['snapshot'], self.config, self.detector_config, self.attribution_id, self.wall())
                    if snapshot['destination'] != self.server_id or snapshot['transfer_id'] != tid or snapshot['bucket_id'] != bucket:
                        raise ValueError('snapshot destination/transaction differs')
                if len(json.dumps(snapshot, allow_nan=False).encode()) > self.config['max_body_bytes'] - 1024:
                    raise ValueError('snapshot exceeds API body budget')
                record = dict(transfer_id=tid, bucket_id=bucket, snapshot=snapshot, digest=digest(snapshot),
                              status='exported' if operation == 'export' else 'prepared', updated=now)
                if operation == 'prepare':
                    record['delta'] = Statistics(self.detector_config, now=now)
                    record['prepared_at'] = now
                    record['age_at_prepare'] = max(0, self.wall()-snapshot['created_at'])
                self.records[tid] = record
                self.locks[bucket] = tid
            if record is None:
                raise KeyError('unknown transfer')
            if operation == 'export':
                if record['snapshot']['source'] != self.server_id or record['snapshot']['destination'] != body['destination']:
                    raise ValueError('transfer ID reused with different identities')
                return dict(self.response(record), snapshot=copy.deepcopy(record['snapshot']))
            if operation == 'prepare':
                if digest(body['snapshot']) != record['digest'] or record['status'] not in ('prepared', 'committed'):
                    raise RuntimeError('prepare conflicts with existing transaction')
            elif operation == 'abort':
                if record['status'] in ('committed', 'finalized'):
                    raise RuntimeError('cannot abort finalized/active imported history')
                record['status'] = 'aborted'
                if self.locks.get(bucket) == tid:
                    self.locks.pop(bucket)
            elif operation == 'commit':
                if (body['owner'] != self.server_id or not isinstance(body['ownership_digest'], str)
                        or len(body['ownership_digest']) != 64 or any(c not in '0123456789abcdef' for c in body['ownership_digest'])):
                    raise ValueError('verified ownership attestation required')
                if record['status'] not in ('prepared', 'committed'):
                    raise RuntimeError('state is not prepared')
                if record['status'] == 'prepared':
                    elapsed = max(0, self.wall()-record['snapshot']['created_at'],
                                  record['age_at_prepare'] + now-record['prepared_at'])
                    stats = decode_stats(record['snapshot']['state'], self.detector_config, now, elapsed)
                    self.buckets[bucket] = dict(stats=merge_stats(stats, record['delta'], now),
                                               first_seen=record['snapshot']['first_seen'], last_seen=self.wall())
                    record['proof'] = dict(imported_packets_total=record['snapshot']['state']['packets_total'],
                                           imported_bytes_total=record['snapshot']['state']['bytes_total'],
                                           imported_flow_bin_records=sum(len(b['flows']) for b in record['snapshot']['state']['bins']))
                    record['status'] = 'committed'
                    if self.locks.get(bucket) == tid:
                        self.locks.pop(bucket)
                    del record['delta']
            elif operation == 'finalize':
                if record['snapshot']['source'] != self.server_id or body['owner'] != record['snapshot']['destination'] or body['destination_digest'] != record['digest']:
                    raise ValueError('destination verification differs')
                if record['status'] not in ('exported', 'finalized'):
                    raise RuntimeError('source transfer is not exported')
                record['status'] = 'finalized'
                if self.locks.get(bucket) == tid:
                    self.locks.pop(bucket)
                # Source bucket history is intentionally preserved, never deleted.
            record['updated'] = now
            return self.response(record)
