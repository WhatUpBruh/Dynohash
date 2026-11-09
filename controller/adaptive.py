"""Deterministic adaptive policy and fail-closed orchestration; no pipeline provisioning."""
from dataclasses import dataclass
import json
from pathlib import Path
import time
from urllib.parse import urlparse

from .core import BucketController, ControllerError, ROOT
from .telemetry_client import IDS, TelemetryError, finite, validate_view

DEFAULT_PATH = ROOT / 'config/checkpoint4.json'


def load_settings(path=DEFAULT_PATH):
    config = json.loads(Path(path).read_text())
    expected = set(json.loads(DEFAULT_PATH.read_text()))
    if not isinstance(config, dict) or set(config) != expected:
        raise ValueError('adaptive configuration keys must match checkpoint4.json')
    for key, value in config.items():
        if key not in ('collector_url', 'counter_bits') and not finite(value):
            raise ValueError('invalid setting: ' + key)
    url = urlparse(config['collector_url'])
    if (url.scheme != 'http' or not url.hostname or url.username or url.password or
            url.path != '/api/v1/telemetry' or url.query or url.fragment):
        raise ValueError('collector must be the existing HTTP telemetry endpoint')
    if url.port is not None and not 1 <= url.port <= 65535:
        raise ValueError('invalid collector port')
    if not .1 <= config['poll_seconds'] <= 10 or not .05 <= config['http_timeout_seconds'] <= 2:
        raise ValueError('poll/HTTP interval outside supported range')
    if not 0 < config['max_telemetry_age_seconds'] <= 3 or not 0 <= config['future_tolerance_seconds'] <= 1:
        raise ValueError('invalid freshness bounds')
    if not 0 <= config['imbalance_exit_ratio'] < config['imbalance_enter_ratio'] <= 3:
        raise ValueError('hysteresis ratios must be ordered')
    if not 0 <= config['imbalance_exit_pps'] < config['imbalance_enter_pps']:
        raise ValueError('hysteresis PPS bounds must be ordered')
    if not 0 <= config['minimum_improvement_fraction'] <= 1:
        raise ValueError('invalid benefit fraction')
    for key in ('minimum_bucket_pps', 'minimum_improvement_pps', 'minimum_window_seconds',
                'maximum_bucket_pps', 'maximum_read_seconds', 'max_timestamp_skew_seconds'):
        if config[key] <= 0:
            raise ValueError('positive setting required: ' + key)
    if not 0 < config['minimum_counter_seconds'] < config['maximum_counter_seconds'] <= 60:
        raise ValueError('invalid counter sample interval')
    if type(config['max_migrations']) is not int or not 1 <= config['max_migrations'] <= 100:
        raise ValueError('max_migrations must be 1..100')
    if config['counter_bits'] is not None and (type(config['counter_bits']) is not int or not 1 <= config['counter_bits'] <= 64):
        raise ValueError('counter_bits must be null or a known width 1..64')
    return config


def validate_counters(counters, bits=None):
    if not isinstance(counters, dict) or set(counters) != set(range(64)) or any(type(k) is not int for k in counters):
        raise ValueError('require all 64 uniquely indexed bucket counters')
    maximum = (1 << (bits or 64)) - 1
    if any(type(v) is not int or not 0 <= v <= maximum for v in counters.values()):
        raise ValueError('invalid packet counter value')


@dataclass
class Snapshot:
    timestamp: float
    owners: dict
    counters: dict


def bucket_rates(before, after, config):
    validate_counters(before.counters, config['counter_bits'])
    validate_counters(after.counters, config['counter_bits'])
    if before.owners != after.owners:
        raise ControllerError('bucket ownership changed during measurement')
    elapsed = after.timestamp - before.timestamp
    if not config['minimum_counter_seconds'] <= elapsed <= config['maximum_counter_seconds']:
        raise ValueError('invalid counter elapsed time')
    if config['counter_bits'] is not None and config['maximum_bucket_pps'] * elapsed >= 1 << config['counter_bits']:
        raise ValueError('counter interval/rate bound allows ambiguous multiple wraps')
    rates = {}
    for bucket in range(64):
        old, new = before.counters[bucket], after.counters[bucket]
        delta = new - old
        if delta < 0:
            bits = config['counter_bits']
            modulus = 1 << bits if bits is not None else None
            # A known width alone cannot distinguish resets from wrapping. Accept
            # only boundary-crossing samples, still bounded by the plausible PPS cap.
            if modulus is None or old < .75 * modulus or new > .25 * modulus:
                raise ValueError('counter reset or unproven wraparound')
            delta += modulus
        rate = delta / elapsed
        if rate > config['maximum_bucket_pps']:
            raise ValueError('implausible bucket packet rate')
        rates[bucket] = rate
    return rates


def imbalance(loads):
    gap = max(loads.values()) - min(loads.values())
    return gap, gap / max(sum(loads.values()) / len(loads), 1)


def select_candidate(loads, rates, owners, config, now, bucket_actions):
    source = max(IDS, key=lambda n: (loads[n], n))
    target = min(IDS, key=lambda n: (loads[n], n))
    gap, _ = imbalance(loads)
    candidates = []
    for bucket, owner in owners.items():
        rate = rates[bucket]
        if (owner != source or rate < config['minimum_bucket_pps'] or rate > loads[source] or
                now - bucket_actions.get(bucket, -float('inf')) < config['bucket_cooldown_seconds']):
            continue
        predicted = dict(loads)
        predicted[source] -= rate
        predicted[target] += rate
        new_gap, _ = imbalance(predicted)
        improvement = gap - new_gap
        if improvement < max(config['minimum_improvement_pps'], gap * config['minimum_improvement_fraction']):
            continue
        candidates.append(dict(bucket=bucket, source=source, destination=target,
                               bucket_pps=rate, before_loads=dict(loads), predicted_loads=predicted,
                               before_gap_pps=gap, predicted_gap_pps=new_gap,
                               improvement_pps=improvement))
    if not candidates:
        return None
    return max(candidates, key=lambda c: (c['improvement_pps'], -c['bucket_pps'], -c['bucket']))


class AdaptiveController:
    def __init__(self, runtime, collector, config, detectors, *, live=False,
                 acknowledge_state_loss=False, monotonic=time.monotonic, wall=time.time, migrator=None):
        if live and not acknowledge_state_loss:
            raise ValueError('live migration requires explicit acknowledgement of detector state loss')
        self.runtime, self.collector, self.config = runtime, collector, config
        self.buckets = BucketController(runtime, detectors)
        self.migrator = migrator if migrator is not None else self.buckets
        self.live = live
        self.monotonic, self.wall = monotonic, wall
        self.previous = None
        self.expected = None
        self.pair = None
        self.since = None
        self.last_action = None
        self.settling_until = 0
        self.bucket_actions = {}
        self.action_count = 0
        self.fault = None
        self.last_readings = None
        self.attempted_candidate = None

    def reset_sustain(self):
        self.pair = None
        self.since = None

    def snapshot(self):
        start = self.monotonic()
        owners = self.buckets.assignments()
        counters = self.runtime.counters()
        if self.buckets.assignments() != owners:
            raise ControllerError('ownership changed across counter read')
        end = self.monotonic()
        if end < start or end - start > self.config['maximum_read_seconds']:
            raise ValueError('switch read took too long or clock moved backward')
        validate_counters(counters, self.config['counter_bits'])
        if self.expected is not None and self.expected != owners:
            raise ControllerError('external ownership change; inspect single-writer discipline')
        self.expected = dict(owners)
        return Snapshot((start + end) / 2, owners, dict(counters))

    def telemetry(self):
        view = self.collector.read()
        received = self.monotonic()
        readings = validate_view(view, self.config, self.wall())
        if self.last_readings:
            for name in IDS:
                if (readings[name]['timestamp'] < self.last_readings[name]['timestamp'] or
                        readings[name]['packets_processed_total'] < self.last_readings[name]['packets_processed_total']):
                    raise TelemetryError('detector restarted or timestamp went backward', readings)
        self.last_readings = readings
        return view, received, readings

    def consistent(self, readings, rates, owners):
        for name in IDS:
            observed = sum(rates[b] for b in range(64) if owners[b] == name)
            reported = readings[name]['load_pps']
            tolerance = max(self.config['load_tolerance_pps'],
                            self.config['load_tolerance_fraction'] * max(observed, reported))
            if abs(observed - reported) > tolerance:
                raise TelemetryError('counter/telemetry rate disagreement for ' + name, readings)

    def step(self):
        write_attempted = False
        result = dict(timestamp=self.wall(), mode='live' if self.live else 'dry-run',
                      status='inhibited', reason='', detectors={}, candidate=None,
                      action_count=self.action_count)
        if self.fault:
            result.update(status='fault', reason='latched fault: ' + self.fault)
            return result
        try:
            current = self.snapshot()
            view, received, readings = self.telemetry()
            result['detectors'] = readings
            prior, self.previous = self.previous, current
            if prior is None:
                self.reset_sustain()
                result['reason'] = 'warming counter baseline'
                return result
            rates = bucket_rates(prior, current, self.config)
            self.consistent(readings, rates, current.owners)
            result['bucket_rates_pps'] = rates
            now = self.monotonic()
            if now < current.timestamp or now - current.timestamp > self.config['maximum_read_seconds'] + self.config['max_telemetry_age_seconds']:
                raise ValueError('counter snapshot expired before decision')
            loads = {name: s['load_pps'] for name, s in readings.items()}
            gap, ratio = imbalance(loads)
            result.update(gap_pps=gap, imbalance_ratio=ratio)
            source = max(IDS, key=lambda n: (loads[n], n))
            target = min(IDS, key=lambda n: (loads[n], n))
            pair = (source, target)
            if (gap <= self.config['imbalance_exit_pps'] or ratio <= self.config['imbalance_exit_ratio']):
                self.reset_sustain()
                result['reason'] = 'balanced or below hysteresis exit'
                return result
            if self.pair != pair:
                self.reset_sustain()
                if gap < self.config['imbalance_enter_pps'] or ratio < self.config['imbalance_enter_ratio']:
                    result['reason'] = 'below imbalance entry threshold'
                    return result
                self.pair, self.since = pair, now
            result['sustained_seconds'] = now - self.since
            if now - self.since < self.config['sustained_seconds']:
                result['reason'] = 'waiting for sustained imbalance'
                return result
            if self.action_count >= self.config['max_migrations']:
                result['reason'] = 'migration/proposal budget exhausted'
                return result
            if now < self.settling_until:
                self.reset_sustain()
                result['reason'] = 'waiting for detector windows to settle'
                return result
            if self.last_action is not None and now - self.last_action < self.config['global_cooldown_seconds']:
                result['reason'] = 'global migration cooldown'
                return result
            candidate = select_candidate(loads, rates, current.owners, self.config, now, self.bucket_actions)
            if candidate is None:
                result['reason'] = 'no active eligible bucket gives sufficient benefit'
                return result
            result['candidate'] = candidate
            if self.live:
                # Refresh BOTH inputs. Reuse the preceding interval baseline to
                # avoid estimating PPS from an arbitrarily short confirmation read.
                fresh_view, fresh_at, fresh_readings = self.telemetry()
                confirmed = self.snapshot()
                if confirmed.timestamp < current.timestamp:
                    raise ValueError('counter clock moved backward during confirmation')
                confirmed_rates = bucket_rates(prior, confirmed, self.config)
                fresh_readings = validate_view(fresh_view, self.config, self.wall(),
                                              extra_age=max(0, self.monotonic() - fresh_at))
                self.consistent(fresh_readings, confirmed_rates, confirmed.owners)
                fresh_loads = {n: s['load_pps'] for n, s in fresh_readings.items()}
                fresh_gap, fresh_ratio = imbalance(fresh_loads)
                final = select_candidate(fresh_loads, confirmed_rates, confirmed.owners,
                                         self.config, self.monotonic(), self.bucket_actions)
                if (fresh_gap <= self.config['imbalance_exit_pps'] or
                        fresh_ratio <= self.config['imbalance_exit_ratio'] or final is None or
                        any(final[k] != candidate[k] for k in ('bucket', 'source', 'destination'))):
                    self.reset_sustain()
                    result['reason'] = 'candidate or benefit changed during confirmation; no write'
                    return result
                candidate = final
                result.update(candidate=candidate, detectors=fresh_readings)
                def final_guard():
                    latest = validate_view(fresh_view, self.config, self.wall(),
                                           extra_age=max(0, self.monotonic() - fresh_at))
                    if self.monotonic() - confirmed.timestamp > self.config['maximum_read_seconds']:
                        raise TelemetryError('counter estimate expired during pre-write ownership read', latest)
                    latest_loads = {n: s['load_pps'] for n, s in latest.items()}
                    eligible = select_candidate(latest_loads, confirmed_rates, confirmed.owners,
                                                self.config, self.monotonic(), self.bucket_actions)
                    if eligible is None or any(eligible[k] != candidate[k] for k in ('bucket', 'source', 'destination')):
                        raise TelemetryError('benefit no longer valid at write boundary', latest)
                # CP2 guards the expected baseline, writes one MODIFY, validates
                # the whole table and preserves unrelated entries. No auto retry.
                write_attempted = True
                self.attempted_candidate = dict(candidate)
                changed = self.migrator.migrate(candidate['bucket'], candidate['destination'],
                                               expected_assignments=confirmed.owners, before_write=final_guard)
                if not changed:
                    raise ControllerError('unexpected migration no-op after confirmation')
                expected = dict(confirmed.owners)
                expected[candidate['bucket']] = candidate['destination']
                if self.buckets.assignments() != expected:
                    raise ControllerError('adaptive final full-table readback mismatch')
                self.expected = expected
                self.previous = None
                result.update(status='migrated', reason='one MODIFY; full-table readback verified')
                if self.migrator is not self.buckets:
                    result['state_transfer'] = self.migrator.last_event
            else:
                result.update(status='proposed', reason='dry-run: no write performed')
            now = self.monotonic()
            self.last_action = now
            self.bucket_actions[candidate['bucket']] = now
            self.action_count += 1
            self.reset_sustain()
            # Flush old ownership contributions from rolling detector telemetry.
            self.settling_until = now + max(self.config['settling_seconds'],
                                           max(s['window_seconds'] for s in result['detectors'].values())) + self.config['max_telemetry_age_seconds']
            result.update(action_count=self.action_count, completed_timestamp=self.wall())
            return result
        except TelemetryError as exc:
            self.previous = None
            self.last_readings = None
            self.reset_sustain()
            result.update(reason=str(exc), detectors=exc.detectors or result['detectors'])
        except ValueError as exc:
            self.previous = None
            self.reset_sustain()
            result['reason'] = str(exc)
            if write_attempted:
                self.fault = str(exc)
                result.update(status='fault', requires_operator_inspection=True)
        except Exception as exc:
            # Writes may have applied despite failure: latch and stop. Automatic
            # rollback could overwrite a concurrent operator's change.
            self.fault = str(exc) or type(exc).__name__
            self.reset_sustain()
            result.update(status='fault', reason=self.fault,
                          requires_operator_inspection=True)
        return result
