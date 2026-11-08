import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from controller.core import BucketController, ControllerError, bucket_id, load_config
from controller.runtime import Runtime
from p4.config.v1 import p4info_pb2
from p4.v1 import p4runtime_pb2 as pb
from google.protobuf import text_format


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.detectors = load_config()
        self.rows = [(b, *self.detectors[f'd{b % 3 + 1}']) for b in range(64)]
        self.transport = Mock()
        self.transport.read_buckets.side_effect = lambda: iter(self.rows)
        def update(b, port, mac):
            self.rows[b] = (b, port, mac)
        self.transport.modify_bucket.side_effect = update
        self.controller = BucketController(self.transport, self.detectors)

    def test_configuration(self):
        self.assertEqual(self.detectors, {'d1': (2, '00:00:00:00:00:11'), 'd2': (3, '00:00:00:00:00:12'), 'd3': (4, '00:00:00:00:00:13')})

    def test_bad_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.json'
            for data in ({}, {'bucket_count': 63}, {'bucket_count': 64, 'hash_algorithm': 'crc32', 'hash_input': 'ipv4_5tuple', 'detectors': []}):
                path.write_text(json.dumps(data))
                with self.assertRaises(ControllerError):
                    load_config(path)

    def test_boundaries(self):
        self.assertEqual(bucket_id(0), 0)
        self.assertEqual(bucket_id(63), 63)

    def test_invalid_buckets(self):
        for b in (-1, 64, True, 1.5, '9', None):
            with self.subTest(bucket=b), self.assertRaises(ControllerError):
                self.controller.migrate(b, 'd2')
        self.transport.modify_bucket.assert_not_called()

    def test_unknown_detector(self):
        with self.assertRaises(ControllerError):
            self.controller.migrate(9, 'd4')

    def test_read_assignments(self):
        self.assertEqual(len(self.controller.assignments()), 64)
        self.assertEqual(self.controller.owner(9), 'd1')
        self.transport.read_buckets.assert_called()

    def test_update_and_preservation(self):
        before = copy.deepcopy(self.rows)
        self.assertTrue(self.controller.migrate(9, 'd2'))
        self.transport.modify_bucket.assert_called_once_with(9, 3, '00:00:00:00:00:12')
        self.assertEqual(self.controller.owner(9), 'd2')
        self.assertEqual(self.rows[:9] + self.rows[10:], before[:9] + before[10:])

    def test_noop(self):
        self.assertFalse(self.controller.migrate(9, 'd1'))
        self.transport.modify_bucket.assert_not_called()

    def test_failed_write(self):
        self.transport.modify_bucket.side_effect = RuntimeError('write rejected')
        with self.assertRaisesRegex(ControllerError, 'write rejected'):
            self.controller.migrate(9, 'd2')

    def test_failed_readback(self):
        self.transport.modify_bucket.side_effect = None
        with self.assertRaisesRegex(ControllerError, 'readback failed'):
            self.controller.migrate(9, 'd2')

    def test_unrelated_change(self):
        update = self.transport.modify_bucket.side_effect
        def corrupt(*args):
            update(*args)
            self.rows[0] = (0, *self.detectors['d3'])
        self.transport.modify_bucket.side_effect = corrupt
        with self.assertRaisesRegex(ControllerError, 'unrelated'):
            self.controller.migrate(9, 'd2')

    def test_missing(self):
        self.rows.pop()
        with self.assertRaisesRegex(ControllerError, 'missing'):
            self.controller.migrate(9, 'd2')
        self.transport.modify_bucket.assert_not_called()

    def test_duplicate(self):
        self.rows.append(self.rows[0])
        with self.assertRaisesRegex(ControllerError, 'duplicate'):
            self.controller.assignments()

    def test_wrong_mac(self):
        self.rows[0] = (0, 2, '00:00:00:00:00:12')
        with self.assertRaisesRegex(ControllerError, 'unknown port/MAC'):
            self.controller.assignments()


class WireTests(unittest.TestCase):
    def setUp(self):
        self.runtime = Runtime()
        info = p4info_pb2.P4Info()
        text_format.Merge(Path('p4/dynohash.p4info.txt').read_text(), info)
        self.runtime.table = info.tables[0]
        self.runtime.action = info.actions[0]
        self.runtime.key = self.runtime.table.match_fields[0]
        self.runtime.stub = Mock()

    def test_modify_wire_and_decode(self):
        self.runtime.modify_bucket(9, 3, '00:00:00:00:00:12')
        req = self.runtime.stub.Write.call_args.args[0]
        self.assertEqual(req.device_id, 0)
        self.assertEqual(req.election_id.low, 1)
        self.assertEqual(len(req.updates), 1)
        self.assertEqual(req.updates[0].type, pb.Update.MODIFY)
        self.assertEqual(req.updates[0].entity.table_entry.match[0].exact.value, b'\x09')
        response = pb.ReadResponse()
        response.entities.append(req.updates[0].entity)
        self.runtime.stub.Read.return_value = [response]
        self.assertEqual(list(self.runtime.read_buckets()), [(9, 3, '00:00:00:00:00:12')])

    def test_write_error_propagates(self):
        self.runtime.stub.Write.side_effect = RuntimeError('RPC failure')
        with self.assertRaises(RuntimeError):
            self.runtime.modify_bucket(9, 3, '00:00:00:00:00:12')


if __name__ == '__main__':
    unittest.main()
