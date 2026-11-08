"""Bounded, one-second-bin rolling statistics; no bucket hash assumptions."""
from collections import Counter, deque
import json
import math
import time


def validate_config(config):
    required = {'window_seconds', 'threshold_pps', 'minimum_window_seconds',
                'minimum_packets', 'cooldown_seconds', 'max_flows', 'max_sources',
                'collector_url', 'publish_seconds', 'http_timeout_seconds'}
    if set(config) != required:
        raise ValueError('configuration keys must match checkpoint3.json')
    for key in required - {'collector_url'}:
        value = config[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 1e18 or not math.isfinite(value):
            raise ValueError('positive finite configuration value required: ' + key)
    for key in ('window_seconds', 'minimum_packets', 'max_flows', 'max_sources'):
        if type(config[key]) is not int:
            raise ValueError('integer required: ' + key)
    if not 2 <= config['window_seconds'] <= 60 or config['minimum_window_seconds'] > config['window_seconds'] - 1:
        raise ValueError('window must be 2..60 seconds; minimum must fit the shortest aligned window (window-1)')
    if config['max_flows'] > 4096 or config['max_sources'] > 1024:
        raise ValueError('tracking limits exceed supported bounds')
    if not .1 <= config['publish_seconds'] <= 3 or not .05 <= config['http_timeout_seconds'] <= 2:
        raise ValueError('invalid publish interval or HTTP timeout')
    from urllib.parse import urlparse
    if not isinstance(config['collector_url'], str):
        raise ValueError('collector_url must be a string')
    url = urlparse(config['collector_url'])
    if (url.scheme != 'http' or not url.hostname or url.path != '/api/v1/telemetry'
            or url.username or url.password or url.query or url.fragment):
        raise ValueError('collector must be an HTTP /api/v1/telemetry URL')
    if url.port is not None and not 1 <= url.port <= 65535:
        raise ValueError('invalid collector port')
    return config


class Statistics:
    """Caller serializes access. Each bin has bounded flow/source identities."""
    def __init__(self, config, now=None):
        self.config = validate_config(dict(config))
        self.started = time.monotonic() if now is None else now
        self.bins = deque()
        self.total = 0
        self.total_bytes = 0
        self.last_alert = -math.inf
        self.alert_count = 0
        self.alerts = deque(maxlen=32)

    def expire(self, now):
        # At most window_seconds bins, including current partial second.
        first = math.floor(now) - self.config['window_seconds'] + 1
        while self.bins and self.bins[0]['second'] < first:
            self.bins.popleft()

    def observe(self, flow, size, now=None):
        now = time.monotonic() if now is None else now
        self.expire(now)
        second = math.floor(now)
        if not self.bins or self.bins[-1]['second'] != second:
            self.bins.append(dict(second=second, packets=0, bytes=0,
                                  flows=Counter(), sources=Counter(), limited=False))
        entry = self.bins[-1]
        entry['packets'] += 1
        entry['bytes'] += size
        self.total += 1
        self.total_bytes += size
        # JSON array string keys keep each bin serializable, including flow counts.
        # No state transfer or persistence is performed in this checkpoint.
        flow_key = json.dumps(flow, separators=(',', ':'))
        if flow_key in entry['flows'] or len(entry['flows']) < self.config['max_flows']:
            entry['flows'][flow_key] += 1
        else:
            entry['limited'] = True
        if flow[0] in entry['sources'] or len(entry['sources']) < self.config['max_sources']:
            entry['sources'][flow[0]] += 1
        else:
            entry['limited'] = True

    def snapshot(self, server_id, now=None, timestamp=None):
        now = time.monotonic() if now is None else now
        timestamp = time.time() if timestamp is None else timestamp
        self.expire(now)
        # Aligned rolling interval: oldest eligible second through now.
        duration = max(.001, now - max(self.started, math.floor(now) - self.config['window_seconds'] + 1))
        packets = sum(b['packets'] for b in self.bins)
        byte_count = sum(b['bytes'] for b in self.bins)
        flows = set()
        sources = Counter()
        limited = any(b['limited'] for b in self.bins)
        for entry in self.bins:
            for flow in entry['flows']:
                if flow in flows or len(flows) < self.config['max_flows']:
                    flows.add(flow)
                else:
                    limited = True
            for source, count in entry['sources'].items():
                if source in sources or len(sources) < self.config['max_sources']:
                    sources[source] += count
                else:
                    limited = True
        suspicious = (duration >= self.config['minimum_window_seconds'] and
                      packets >= self.config['minimum_packets'] and
                      packets / duration > self.config['threshold_pps'])
        if suspicious and now - self.last_alert >= self.config['cooldown_seconds']:
            self.last_alert = now
            self.alert_count += 1
            self.alerts.append(dict(id=self.alert_count, timestamp=timestamp,
                                    packet_rate_pps=packets / duration))
        return dict(server_id=server_id, timestamp=timestamp,
                    cpu_percent=None, queue_depth=None, queue_capacity=None,
                    packets_processed_total=self.total, packets_dropped_total=None,
                    packet_rate_pps=packets / duration, byte_rate_bps=8 * byte_count / duration,
                    active_flows=len(flows), per_source=dict(sources),
                    tracking_limited=limited, window_seconds=duration,
                    suspicious=suspicious, alerts=list(self.alerts), per_bucket=None)
