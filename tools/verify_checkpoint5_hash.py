"""Offline BMv2 serialization/CRC oracle; never opens a switch or namespace."""
import argparse
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from detectors.bucket_hash import check_layout, fingerprint


def verify():
    check_layout()
    rng = random.Random(5105)
    vectors = [(0, 0, 0, 0, 0), (2**32-1, 2**32-1, 65535, 65535, 255),
               (0x0a000001, 0x0a000164, 40009, 9000, 17)]
    vectors += [struct.unpack('!IIHHB', (1 << bit).to_bytes(13, 'big')) for bit in range(104)]
    vectors += [(rng.getrandbits(32), rng.getrandbits(32), rng.getrandbits(16), rng.getrandbits(16), rng.choice((6, 17))) for _ in range(10000)]
    with tempfile.TemporaryDirectory(prefix='dynohash-parity-') as directory:
        binary = str(Path(directory) / 'oracle')
        subprocess.run(['g++', '-std=c++14', str(ROOT / 'tests/state/bmv2_crc_oracle.cpp'), '-o', binary, '-lbmall', '-lgmp', '-pthread'], check=True)
        response = subprocess.run([binary], input=''.join(' '.join(map(str, v))+'\n' for v in vectors), text=True, capture_output=True, check=True)
    lines = response.stdout.splitlines()
    if len(lines) != len(vectors):
        raise ValueError('oracle output length differs')
    buckets = set()
    for vector, line in zip(vectors, lines):
        serialized, crc = line.split()
        key = struct.pack('!IIHHB', *vector)
        if serialized != key.hex() or int(crc) != zlib.crc32(key):
            raise ValueError('BMv2 field serialization or full CRC mismatch')
        buckets.add(int(crc) % 64)
    paths = [ROOT / 'p4/dynohash.json', ROOT / 'p4/dynohash.p4', ROOT / 'detectors/bucket_hash.py',
             ROOT / 'tests/state/bmv2_crc_oracle.cpp', Path('/usr/bin/simple_switch_grpc'),
             Path('/usr/lib/x86_64-linux-gnu/libbmall.so.0.0.0')]
    return dict(status='PASSED', vectors=len(vectors), buckets_covered=len(buckets),
                method='installed BMv2 PHV + BufBuilder + registered crc32 compared to Python full key/CRC',
                live_verified=False, fingerprints={str(p): fingerprint(p) for p in paths})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = verify()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as destination:
        json.dump(result, destination, indent=2)
    print(json.dumps(result, indent=2))
