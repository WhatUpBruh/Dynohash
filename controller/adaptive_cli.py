"""Bounded adaptive loop; dry-run unless BOTH live safety flags are supplied."""
import argparse
import json
import signal
import sys
import threading
import time

from .adaptive import DEFAULT_PATH, AdaptiveController, load_settings
from .core import ROOT, load_config
from .telemetry_client import TelemetryClient


def main(argv=None, runtime_factory=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default=str(DEFAULT_PATH))
    parser.add_argument('--network-config', default=str(ROOT / 'config/dynohash.json'))
    parser.add_argument('--state-config', default=str(ROOT / 'config/checkpoint5.json'))
    parser.add_argument('--address', default='127.0.0.1:50051')
    parser.add_argument('--device-id', type=int, default=0)
    parser.add_argument('--iterations', type=int, default=60)
    parser.add_argument('--live', action='store_true')
    parser.add_argument('--acknowledge-state-loss', action='store_true',
                        help='Accept imperfect detector-state continuity; optional transfer is best-effort')
    args = parser.parse_args(argv)
    if not 1 <= args.iterations <= 10000:
        parser.error('iterations must be 1..10000')
    if args.live and not args.acknowledge_state_loss:
        parser.error('--live also requires --acknowledge-state-loss')
    stopped = threading.Event()
    old_signals = {}
    try:
        config = load_settings(args.config)
        detectors = load_config(args.network_config)
        from detectors.bucket_state import load_state_config
        state_config = load_state_config(args.state_config)
        client = TelemetryClient(config['collector_url'], config['http_timeout_seconds'])
        if runtime_factory is None:
            from .runtime import Runtime
            runtime_factory = Runtime
        for sig in (signal.SIGINT, signal.SIGTERM):
            old_signals[sig] = signal.signal(sig, lambda *_: stopped.set())
        with runtime_factory(args.address, args.device_id) as runtime:
            migrator = None
            if state_config['enabled'] and args.live:
                from .state_transfer import make_coordinator
                migrator = make_coordinator(runtime, detectors, args.network_config, state_config)
            adaptive = AdaptiveController(runtime, client, config, detectors, live=args.live,
                                          acknowledge_state_loss=args.acknowledge_state_loss, migrator=migrator)
            for _ in range(args.iterations):
                if stopped.is_set():
                    break
                start = time.monotonic()
                result = adaptive.step()
                print(json.dumps(result, allow_nan=False, sort_keys=True), flush=True)
                if result['status'] == 'fault':
                    return 1
                if stopped.wait(max(0, config['poll_seconds'] - (time.monotonic() - start))):
                    break
        return 0
    except Exception as exc:
        print(json.dumps(dict(status='fault', reason=str(exc), mode='live' if args.live else 'dry-run')),
              flush=True)
        return 1
    finally:
        for sig, handler in old_signals.items():
            signal.signal(sig, handler)


if __name__ == '__main__':
    sys.exit(main())
