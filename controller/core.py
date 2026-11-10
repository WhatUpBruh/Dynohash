"""Validated configuration and manual migration, independent of transport."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ControllerError(RuntimeError):
    pass


def bucket_id(value):
    if type(value) is not int or not 0 <= value < 64:
        raise ControllerError('bucket must be an integer from 0 through 63')
    return value


def load_config(path=ROOT / 'config/dynohash.json'):
    try:
        data = json.loads(Path(path).read_text())
        if data['bucket_count'] != 64 or data['hash_algorithm'] != 'crc32' or data['hash_input'] != 'ipv4_5tuple':
            raise ValueError('expected 64 CRC32 IPv4 five-tuple buckets')
        detectors = {}
        for d in data['detectors']:
            if d['id'] not in ('d1', 'd2', 'd3') or d['id'] in detectors:
                raise ValueError('invalid or duplicate detector ID')
            if type(d['port']) is not int or not 1 <= d['port'] <= 511:
                raise ValueError('invalid detector port')
            if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', d['mac']):
                raise ValueError('invalid detector MAC')
            detectors[d['id']] = (d['port'], d['mac'].lower())
        if set(detectors) != {'d1', 'd2', 'd3'} or len({v[0] for v in detectors.values()}) != 3 or len({v[1] for v in detectors.values()}) != 3:
            raise ValueError('require three distinct detector ports and MACs')
        return detectors
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ControllerError(f'invalid configuration: {exc}') from exc


class BucketController:
    def __init__(self, transport, detectors):
        self.transport = transport
        self.detectors = detectors
        self.last_event = None

    def assignments(self):
        result = {}
        for bucket, port, mac in self.transport.read_buckets():
            bucket_id(bucket)
            if bucket in result:
                raise ControllerError(f'duplicate bucket {bucket}')
            owners = [name for name, mapping in self.detectors.items() if mapping == (port, mac)]
            if len(owners) != 1:
                raise ControllerError(f'bucket {bucket}: unknown port/MAC {port}/{mac}')
            result[bucket] = owners[0]
        missing = set(range(64)) - result.keys()
        if missing:
            raise ControllerError(f'missing buckets: {sorted(missing)}')
        return result

    def owner(self, bucket):
        return self.assignments()[bucket_id(bucket)]

    def migrate(self, bucket, detector, *, expected_assignments=None, before_write=None):
        bucket_id(bucket)
        if detector not in self.detectors:
            raise ControllerError(f'unknown detector {detector!r}; choose d1, d2, d3')
        before = self.assignments()
        if expected_assignments is not None and before != expected_assignments:
            raise ControllerError('assignments changed since decision; no write performed')
        if before[bucket] == detector:
            return False
        if before_write is not None:
            before_write()
        try:
            self.transport.modify_bucket(bucket, *self.detectors[detector])
            after = self.assignments()
        except Exception as exc:
            raise ControllerError(f'migration failed; switch state must be inspected: {exc}') from exc
        expected = dict(before)
        expected[bucket] = detector
        if after != expected:
            raise ControllerError('migration readback failed: target or unrelated assignments changed; inspect switch')
        return True
