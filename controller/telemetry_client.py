"""Read the existing collector; reuse its v1 schema without inventing measurements."""
from http.client import HTTPException
import json
import math
from urllib.error import URLError
from urllib.request import build_opener, ProxyHandler, HTTPRedirectHandler

from detectors.telemetry import validate

IDS = ('d1', 'd2', 'd3')


class TelemetryError(ValueError):
    def __init__(self, message, detectors=None):
        super().__init__(message)
        self.detectors = detectors or {}


def finite(value):
    return (not isinstance(value, bool) and isinstance(value, (int, float)) and
            0 <= value <= 1e18 and math.isfinite(value))


def validate_view(view, config, now, extra_age=0):
    """Validate every detector, including collector freshness and local timestamp age."""
    if not isinstance(view, dict) or not isinstance(view.get('servers'), dict) or set(view['servers']) != set(IDS):
        raise TelemetryError('collector must contain exactly d1/d2/d3')
    statuses = {}
    timestamps = []
    for name in IDS:
        status = dict(load_pps=None, fresh=False, reason='missing reading')
        statuses[name] = status
        try:
            entry = view['servers'][name]
            if not isinstance(entry, dict) or type(entry.get('stale')) is not bool:
                raise ValueError('malformed collector freshness')
            reading = validate(entry.get('telemetry'), IDS, now)
            if reading['server_id'] != name:
                raise ValueError('server ID does not match collector key')
            if not finite(entry.get('age_seconds')):
                raise ValueError('missing or invalid collector age')
            timestamp = reading['timestamp']
            if timestamp > now + config['future_tolerance_seconds']:
                raise ValueError('future timestamp')
            age = max(0, now - timestamp, entry['age_seconds'] + extra_age)
            status.update(load_pps=reading['packet_rate_pps'], timestamp=timestamp,
                          age_seconds=age, cpu_percent=reading['cpu_percent'],
                          queue_depth=reading['queue_depth'], queue_capacity=reading['queue_capacity'],
                          packets_dropped_total=reading['packets_dropped_total'],
                          packets_processed_total=reading['packets_processed_total'],
                          per_bucket=reading.get('per_bucket'))
            if entry['stale'] or age > config['max_telemetry_age_seconds']:
                raise ValueError('stale telemetry')
            if not finite(reading.get('window_seconds')) or reading['window_seconds'] < config['minimum_window_seconds']:
                raise ValueError('insufficient detector window')
            status['window_seconds'] = reading['window_seconds']
            status.update(fresh=True, reason='fresh')
            timestamps.append(timestamp)
        except (ValueError, TypeError, KeyError, OverflowError) as exc:
            status['reason'] = str(exc)
    if not all(s['fresh'] for s in statuses.values()):
        raise TelemetryError('incomplete or invalid telemetry', statuses)
    if max(timestamps) - min(timestamps) > config['max_timestamp_skew_seconds']:
        for status in statuses.values():
            status.update(fresh=False, reason='detector timestamps are too far apart')
        raise TelemetryError('unsynchronized detector snapshots', statuses)
    return statuses


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise TelemetryError('collector redirect refused')


class TelemetryClient:
    MAX_RESPONSE = 1048576

    def __init__(self, url, timeout=.5):
        self.url = url
        self.timeout = timeout
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def read(self):
        try:
            with self.opener.open(self.url, timeout=self.timeout) as response:
                if response.status != 200 or response.headers.get_content_type() != 'application/json':
                    raise TelemetryError('collector requires HTTP 200 application/json')
                raw = response.read(self.MAX_RESPONSE + 1)
                if len(raw) > self.MAX_RESPONSE:
                    raise TelemetryError('collector response exceeds limit')
                def unique_pairs(pairs):
                    result = {}
                    for key, value in pairs:
                        if key in result:
                            raise ValueError('duplicate JSON key')
                        result[key] = value
                    return result
                return json.loads(raw, object_pairs_hook=unique_pairs)
        except TelemetryError:
            raise
        except (OSError, URLError, HTTPException, ValueError, RecursionError) as exc:
            raise TelemetryError('collector read failed: ' + str(exc)) from exc
