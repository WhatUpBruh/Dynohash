#!/usr/bin/env python3
"""Receive BMv2 Ethernet frames and publish bounded heuristic traffic statistics."""
import argparse
import json
from pathlib import Path
import signal
import socket
import struct
import threading
import time

# Preserve direct script invocation used by existing lab commands.
if __package__ in (None, ''):
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from detectors.statistics import Statistics, validate_config
from detectors.telemetry import Sender

ROOT = Path(__file__).resolve().parents[1]
SWITCH_MAC = bytes.fromhex('020000000001')


def parse_frame(frame, detector_mac):
    """Accept only switch-origin unfragmented IPv4 TCP/UDP, like the P4 pipeline.

    Return (five_tuple, Ethernet length), or None. No packet bytes are retained.
    """
    if len(frame) < 34 or frame[:6] != detector_mac or frame[6:12] != SWITCH_MAC or frame[12:14] != b'\x08\x00':
        return None
    if frame[14] != 0x45:
        return None
    total = struct.unpack_from('!H', frame, 16)[0]
    fragment = struct.unpack_from('!H', frame, 20)[0]
    protocol = frame[23]
    if fragment & 0x3fff or protocol not in (6, 17):
        return None
    minimum = 40 if protocol == 6 else 28
    if total < minimum or len(frame) < 14 + total:
        return None
    sport, dport = struct.unpack_from('!HH', frame, 34)
    if protocol == 17:
        udp_len = struct.unpack_from('!H', frame, 38)[0]
        if udp_len < 8 or udp_len > total - 20:
            return None
    else:
        header_size = (frame[46] >> 4) * 4
        if header_size < 20 or header_size > total - 20:
            return None
    flow = (socket.inet_ntoa(frame[26:30]), socket.inet_ntoa(frame[30:34]),
            sport, dport, protocol)
    return flow, len(frame)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server-id', required=True)
    parser.add_argument('--interface', required=True)
    parser.add_argument('--config', type=Path, default=ROOT / 'config/checkpoint3.json')
    parser.add_argument('--network-config', type=Path, default=ROOT / 'config/dynohash.json')
    parser.add_argument('--collector-url', help='Override management HTTP endpoint')
    parser.add_argument('--state-config', type=Path, default=ROOT / 'config/checkpoint5.json')
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    if args.collector_url:
        config['collector_url'] = args.collector_url
    validate_config(config)
    network = json.loads(args.network_config.read_text())
    detectors = {d['id']: d for d in network['detectors']}
    if args.server_id not in detectors:
        parser.error('server ID must be configured in network config')
    # Prevent accidental capture of management-plane HTTP traffic.
    expected = detectors[args.server_id]['host'] + '-eth0'
    if args.interface != expected:
        parser.error('use configured detector data interface: ' + expected)
    mac = bytes.fromhex(detectors[args.server_id]['mac'].replace(':', ''))
    stopped = threading.Event()
    lock = threading.Lock()
    stats = Statistics(config)
    sender = Sender(config['collector_url'], config['http_timeout_seconds'])
    state, state_server, state_thread = None, None, None
    from detectors.bucket_state import StateStore, load_state_config
    state_config = load_state_config(args.state_config)
    if state_config['enabled']:
        from detectors.bucket_hash import verify_evidence
        from detectors.state_api import make_state_server
        evidence = Path(state_config['attribution_evidence'])
        if not evidence.is_absolute():
            evidence = ROOT / evidence
        attribution = verify_evidence(evidence)
        state = StateStore(args.server_id, state_config, config, attribution)
        address = detectors[args.server_id]['management_ip']
        peers = [network['management_bridge_ip']] + [d['management_ip'] for d in detectors.values()]
        state_server = make_state_server((address, state_config['port']), state, peers)
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())

    def publish():
        while not stopped.is_set():
            start = time.monotonic()
            with lock:
                payload = stats.snapshot(args.server_id)
            if state is not None:
                state.tick()
            delivered = sender.send(payload)
            print(json.dumps(dict(telemetry=payload, delivered=delivered,
                                  telemetry_failures=sender.failures), allow_nan=False), flush=True)
            stopped.wait(max(0, config['publish_seconds'] - (time.monotonic() - start)))

    # AF_PACKET is receive-only here; no interface, routing or switch changes.
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as capture:
        capture.bind((args.interface, 0))
        capture.settimeout(.2)
        worker = threading.Thread(target=publish, name='telemetry', daemon=True)
        worker.start()
        if state_server is not None:
            state_thread = threading.Thread(target=state_server.serve_forever,
                                            kwargs={'poll_interval': .2}, daemon=True)
            state_thread.start()
        print('[%s] Listening on %s' % (args.server_id, args.interface), flush=True)
        try:
            while not stopped.is_set():
                try:
                    frame, address = capture.recvfrom(65549)
                except socket.timeout:
                    continue
                if address[2] == socket.PACKET_OUTGOING:
                    continue
                parsed = parse_frame(frame, mac)
                if parsed:
                    with lock:
                        stats.observe(*parsed)
                    if state is not None:
                        state.observe(*parsed)
        finally:
            stopped.set()
            worker.join(timeout=config['http_timeout_seconds'] + 3)
            if state_thread is not None:
                state_server.shutdown()
                state_server.server_close()
                state_thread.join(timeout=3)
    print('[%s] Stopped' % args.server_id, flush=True)


if __name__ == '__main__':
    main()
