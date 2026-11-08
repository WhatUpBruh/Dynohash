"""Small bounded telemetry API, intended for the isolated VM management network."""
import argparse
from collections import deque
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import signal
import threading
import time

from .telemetry import validate

ROOT = Path(__file__).resolve().parents[1]
MAX_BODY = 262144


class Store:
    def __init__(self, server_ids, history_size=10, event_size=128):
        self.server_ids = frozenset(server_ids)
        self.history = {name: deque(maxlen=history_size) for name in server_ids}
        self.events = deque(maxlen=event_size)
        self.received = {}

    def accept(self, payload, now=None, monotonic=None):
        now = time.time() if now is None else now
        monotonic = time.monotonic() if monotonic is None else monotonic
        payload = validate(payload, self.server_ids, now)
        name = payload['server_id']
        readings = self.history[name]
        if readings and payload['timestamp'] <= readings[-1]['timestamp']:
            raise ValueError('out of order or duplicate timestamp')
        previous = readings[-1] if readings else None
        readings.append(payload)
        # Keep the reading's age at receipt as well as the monotonic anchor.
        # Otherwise a wall-clock rollback can make an already-old reading fresh.
        self.received[name] = (monotonic, max(0, now - payload['timestamp']))
        # Store only newly observed alert timestamps; detector restarts reset IDs.
        old_alerts = {(a['id'], a['timestamp']) for a in previous.get('alerts', [])} if previous else set()
        for alert in payload.get('alerts', []):
            if (alert['id'], alert['timestamp']) not in old_alerts:
                self.events.append(dict(server_id=name, **alert))

    def view(self, now=None, monotonic=None):
        now = time.time() if now is None else now
        monotonic = time.monotonic() if monotonic is None else monotonic
        servers = {}
        for name, history in self.history.items():
            latest = history[-1] if history else None
            age = None
            if latest:
                received_at, age_at_receipt = self.received[name]
                age = max(0, now - latest['timestamp'],
                          age_at_receipt + monotonic - received_at)
            servers[name] = dict(telemetry=latest, age_seconds=age,
                                 stale=age is None or age > 3)
        return dict(servers=servers, events=list(self.events))


def make_server(address, store):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(2)

        def log_message(self, *args):
            pass

        def reply(self, status, body):
            data = json.dumps(body, allow_nan=False).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(data)
            self.close_connection = True

        def do_POST(self):
            if self.path != '/api/v1/telemetry':
                self.reply(404, {'error': 'unknown endpoint'})
                return
            try:
                if self.headers.get_content_type() != 'application/json' or self.headers.get('Transfer-Encoding'):
                    raise ValueError('requires JSON with Content-Length')
                lengths = self.headers.get_all('Content-Length', [])
                if len(lengths) != 1:
                    raise ValueError('requires one Content-Length')
                size = int(lengths[0])
                if not 0 < size <= MAX_BODY:
                    self.reply(413, {'error': 'body size outside bounds'})
                    return
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError('incomplete body')
                def unique_pairs(pairs):
                    result = {}
                    for key, value in pairs:
                        if key in result:
                            raise ValueError('duplicate JSON key')
                        result[key] = value
                    return result
                payload = json.loads(raw, object_pairs_hook=unique_pairs)
                store.accept(payload)
            except (ValueError, TypeError, UnicodeError, RecursionError, OSError) as exc:
                self.reply(400, {'error': str(exc)[:160]})
                return
            self.reply(202, {'accepted': True})

        def do_GET(self):
            if self.path != '/api/v1/telemetry':
                self.reply(404, {'error': 'unknown endpoint'})
                return
            self.reply(200, store.view())

    # Deliberately single-threaded: bounded connections/memory, serialized store access.
    return HTTPServer(address, Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bind', default='172.18.50.1')
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--network-config', type=Path, default=ROOT / 'config/dynohash.json')
    args = parser.parse_args()
    ids = [d['id'] for d in json.loads(args.network_config.read_text())['detectors']]
    with make_server((args.bind, args.port), Store(ids)) as server:
        def stop(*_):
            threading.Thread(target=server.shutdown, daemon=True).start()
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        print('Collector listening on %s:%s' % server.server_address, flush=True)
        server.serve_forever(poll_interval=.2)


if __name__ == '__main__':
    main()
