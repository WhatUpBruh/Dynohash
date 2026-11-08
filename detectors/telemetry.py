"""Version 1 telemetry validation and best-effort HTTP delivery."""
import ipaddress
from http.client import HTTPException
import json
import math
from urllib.error import URLError
from urllib.request import Request, build_opener, ProxyHandler

REQUIRED = {'server_id', 'timestamp', 'cpu_percent', 'packet_rate_pps',
            'queue_depth', 'queue_capacity', 'packets_processed_total',
            'packets_dropped_total', 'active_flows'}
OPTIONAL = {'byte_rate_bps', 'suspicious', 'alerts', 'per_bucket', 'per_source',
            'tracking_limited', 'window_seconds'}


def number(value, name, integer=False, nullable=False, maximum=1e18):
    if value is None and nullable:
        return
    if (isinstance(value, bool) or not isinstance(value, (int, float)) or
            (integer and type(value) is not int) or not 0 <= value <= maximum or
            not math.isfinite(value)):
        raise ValueError('invalid ' + name)


def validate(payload, server_ids, now):
    if not isinstance(payload, dict) or not REQUIRED <= payload.keys() or payload.keys() - REQUIRED - OPTIONAL:
        raise ValueError('missing or unknown fields')
    if not isinstance(payload['server_id'], str) or payload['server_id'] not in server_ids:
        raise ValueError('unknown server_id')
    number(payload['timestamp'], 'timestamp')
    if payload['timestamp'] > now + 1:
        raise ValueError('timestamp more than one second in future')
    if now - payload['timestamp'] > 60:
        raise ValueError('timestamp older than retention horizon')
    for key in ('packet_rate_pps', 'byte_rate_bps', 'window_seconds'):
        if key in payload:
            number(payload[key], key)
    number(payload['cpu_percent'], 'cpu_percent', nullable=True, maximum=100)
    for key in ('queue_depth', 'queue_capacity', 'packets_processed_total',
                'packets_dropped_total', 'active_flows'):
        number(payload[key], key, integer=True,
               nullable=key in ('queue_depth', 'queue_capacity', 'packets_dropped_total'))
    if (payload['queue_depth'] is not None and payload['queue_capacity'] is not None and
            payload['queue_depth'] > payload['queue_capacity']):
        raise ValueError('queue depth exceeds capacity')
    for key in ('suspicious', 'tracking_limited'):
        if key in payload and type(payload[key]) is not bool:
            raise ValueError('invalid ' + key)
    if payload.get('per_bucket') is not None:
        raise ValueError('bucket attribution is unavailable in checkpoint 3')
    sources = payload.get('per_source', {})
    if not isinstance(sources, dict) or len(sources) > 1024:
        raise ValueError('invalid per_source')
    for source, count in sources.items():
        try:
            ipaddress.IPv4Address(source)
        except (ValueError, TypeError):
            raise ValueError('invalid source address') from None
        number(count, 'source packets', integer=True)
    alerts = payload.get('alerts', [])
    if not isinstance(alerts, list) or len(alerts) > 32:
        raise ValueError('invalid alerts')
    for alert in alerts:
        if not isinstance(alert, dict) or set(alert) != {'id', 'timestamp', 'packet_rate_pps'}:
            raise ValueError('invalid alert')
        number(alert['id'], 'alert id', integer=True)
        number(alert['timestamp'], 'alert timestamp')
        number(alert['packet_rate_pps'], 'alert rate')
        if alert['timestamp'] > payload['timestamp']:
            raise ValueError('alert newer than reading')
    # Return a detached JSON-safe copy; reject NaN and infinity everywhere.
    return json.loads(json.dumps(payload, allow_nan=False))


class Sender:
    def __init__(self, url, timeout=.5):
        self.url = url
        self.timeout = timeout
        self.failures = 0
        # Management traffic must never be diverted by inherited proxy variables.
        self.opener = build_opener(ProxyHandler({}))

    def send(self, payload):
        request = Request(self.url, json.dumps(payload, allow_nan=False).encode(),
                          {'Content-Type': 'application/json'}, method='POST')
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                if response.status != 202:
                    self.failures += 1
                    return False
                response.read(1024)
            return True
        except (OSError, URLError, HTTPException):
            self.failures += 1
            return False
