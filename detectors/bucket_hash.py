"""Verified fixed-layout BMv2 crc32 attribution for this repository's IPv4 path."""
import hashlib
import ipaddress
import json
from pathlib import Path
import struct
import zlib

ROOT = Path(__file__).resolve().parents[1]


def flow_key(flow):
    if not isinstance(flow, (tuple, list)) or len(flow) != 5:
        raise ValueError('five tuple required')
    src, dst, sport, dport, protocol = flow
    if any(type(p) is not int or not 0 <= p <= 65535 for p in (sport, dport)) or protocol not in (6, 17) or type(protocol) is not int:
        raise ValueError('supported IPv4 TCP/UDP tuple required')
    return ipaddress.IPv4Address(src).packed + ipaddress.IPv4Address(dst).packed + struct.pack('!HHB', sport, dport, protocol)


def bucket_for(flow):
    return zlib.crc32(flow_key(flow)) % 64


def fingerprint(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check_layout(path=ROOT / 'p4/dynohash.json'):
    pipeline = json.loads(Path(path).read_text())
    calculations = pipeline['calculations']
    if len(calculations) != 2 or any(c['algo'] != 'crc32' for c in calculations):
        raise ValueError('unsupported hash calculations')
    widths = {h['name']: {f[0]: f[1] for f in h['fields']} for h in pipeline['header_types']}
    headers = {h['name']: widths[h['header_type']] for h in pipeline['headers']}
    for calc, transport in zip(calculations, ('tcp', 'udp')):
        fields = [item['value'] for item in calc['input']]
        if [headers[h][f] for h, f in fields] != [32, 32, 16, 16, 8]:
            raise ValueError('hash field widths differ')
        actions = [a for a in pipeline['actions'] if any(p['op'] == 'modify_field_with_hash_based_offset' and p['parameters'][2].get('value') == calc['name'] for p in a['primitives'])]
        if len(actions) != 1:
            raise ValueError('hash action missing or ambiguous')
        primitives = actions[0]['primitives']
        expected = [['ipv4', 'srcAddr'], ['ipv4', 'dstAddr'], [transport, 'srcPort'], [transport, 'dstPort'], ['ipv4', 'protocol']]
        assignments = {tuple(p['parameters'][0]['value']): p['parameters'][1]['value'] for p in primitives if p['op'] == 'assign'}
        if [assignments[tuple(f)] for f in fields] != expected:
            raise ValueError('hash field order differs')
        hashes = [p for p in primitives if p['op'] == 'modify_field_with_hash_based_offset']
        if len(hashes) != 1 or int(hashes[0]['parameters'][1]['value'], 16) != 0 or int(hashes[0]['parameters'][3]['value'], 16) != 64:
            raise ValueError('hash base or bucket count differs')


def verify_evidence(path):
    check_layout()
    evidence = json.loads(Path(path).read_text())
    if evidence.get('status') != 'PASSED' or evidence.get('vectors', 0) < 10107 or evidence.get('buckets_covered') != 64:
        raise ValueError('BMv2 attribution evidence missing/incomplete')
    for name, digest in evidence['fingerprints'].items():
        if fingerprint(name) != digest:
            raise ValueError('attribution artifact changed: ' + name)
    required = {str(ROOT / 'p4/dynohash.json'), str(ROOT / 'p4/dynohash.p4'), '/usr/bin/simple_switch_grpc', '/usr/lib/x86_64-linux-gnu/libbmall.so.0.0.0'}
    if not required <= evidence['fingerprints'].keys():
        raise ValueError('evidence does not identify pipeline and BMv2 artifacts')
    return fingerprint(path)
