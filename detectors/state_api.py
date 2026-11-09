"""Bounded lab management API. Private bind + explicit peer allowlist; no public listener."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json

from .bucket_state import bucket_id, encode_stats


def make_state_server(address, store, allowed_peers):
    ip = ipaddress.IPv4Address(address[0])
    if ip.is_unspecified or ip.is_multicast:
        raise ValueError('state API requires a specific management address')
    allowed = frozenset(allowed_peers)
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(2)
        def log_message(self, *args):
            pass
        def reply(self, status, value):
            raw = json.dumps(value, allow_nan=False).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Connection', 'close')
            self.end_headers()
            try:
                self.wfile.write(raw)
            except OSError:
                pass  # A timed-out caller can query/retry the same transfer ID.
            self.close_connection = True
        def trusted(self):
            if self.client_address[0] not in allowed:
                self.reply(403, {'error': 'peer outside trusted management network'})
                return False
            return True
        def do_GET(self):
            if not self.trusted():
                return
            if self.path == '/api/v1/state/health':
                self.reply(200, dict(server_id=store.server_id, boot_id=store.boot_id,
                                     attribution_id=store.attribution_id, enabled=True))
                return
            if self.path.startswith('/api/v1/state/buckets/'):
                try:
                    text = self.path.rsplit('/', 1)[-1]
                    bucket = bucket_id(int(text))
                    if str(bucket) != text:
                        raise ValueError('noncanonical bucket')
                    with store.lock:
                        state = store.buckets.get(bucket)
                        value = dict(server_id=store.server_id, boot_id=store.boot_id, bucket_id=bucket,
                                     bucket_state=store.summary(bucket),
                                     state=None if state is None else encode_stats(state['stats'], store.monotonic()))
                    self.reply(200, value)
                except ValueError as exc:
                    self.reply(400, {'error': str(exc)})
                return
            self.reply(404, {'error': 'unknown state endpoint'})
        def do_POST(self):
            if not self.trusted():
                return
            operation = self.path.removeprefix('/api/v1/state/')
            if not self.path.startswith('/api/v1/state/') or operation not in ('export', 'prepare', 'status', 'commit', 'finalize', 'abort'):
                self.reply(404, {'error': 'unknown state operation'})
                return
            try:
                lengths = self.headers.get_all('Content-Length', [])
                if self.headers.get_content_type() != 'application/json' or self.headers.get('Transfer-Encoding') or len(lengths) != 1:
                    raise ValueError('JSON body with one Content-Length required')
                length = int(lengths[0])
                if not 0 < length <= store.config['max_body_bytes']:
                    self.reply(413, {'error': 'state body exceeds bounds'})
                    return
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError('truncated state body')
                def pairs(items):
                    result = {}
                    for key, value in items:
                        if key in result:
                            raise ValueError('duplicate JSON key')
                        result[key] = value
                    return result
                result = store.handle(operation, json.loads(raw, object_pairs_hook=pairs))
            except KeyError as exc:
                self.reply(404, {'error': str(exc)})
                return
            except RuntimeError as exc:
                self.reply(409, {'error': str(exc)})
                return
            except (ValueError, TypeError, UnicodeError, RecursionError, OSError) as exc:
                self.reply(400, {'error': str(exc)[:160]})
                return
            self.reply(200, result)
    return HTTPServer(address, Handler)
