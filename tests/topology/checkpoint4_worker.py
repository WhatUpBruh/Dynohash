"""Test-only venv worker: one P4Runtime owner, existing adaptive code, safe restoration.

The Mininet CLI may use system Python without grpc installed. This child keeps
one normal-election session while its parent operates existing host namespaces.
"""
import argparse
from collections import deque
import json
from pathlib import Path
import signal
import sys
import time

PROJECT = Path(__file__).resolve().parents[2]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))
from controller.adaptive import AdaptiveController, load_settings, validate_counters
from controller.core import BucketController, ControllerError, load_config
from controller.telemetry_client import TelemetryClient


def restore_assignments(buckets, original, touched):
    """Restore only our one known bucket; never overwrite unrelated/unknown changes."""
    current = buckets.assignments()
    changed = {b for b in original if original[b] != current[b]}
    if not changed:
        return {'restored': True, 'changed_buckets': []}
    if len(changed) != 1 or not changed <= touched.keys():
        raise ControllerError('restoration refused: unrelated assignments changed; inspect manually')
    bucket = next(iter(changed))
    if current[bucket] != touched[bucket]:
        raise ControllerError('restoration refused: unexpected bucket owner')
    buckets.migrate(bucket, original[bucket], expected_assignments=current)
    if buckets.assignments() != original:
        raise ControllerError('restoration full-table readback failed')
    return {'restored': True, 'changed_buckets': [bucket]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('--live', action='store_true')
    parser.add_argument('--acknowledge-state-loss', action='store_true')
    args = parser.parse_args()
    if args.live and not args.acknowledge_state_loss:
        parser.error('live test requires detector state-loss acknowledgement')
    report = dict(status='FAILED', events=[], cleanup_errors=[],
                  scope='worker lifecycle/restoration; overall test result is in parent report.json')
    events = deque(maxlen=512)
    touched = {}
    original = None
    def reply(value):
        print(json.dumps(value, allow_nan=False), flush=True)
    def stop(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        from controller.runtime import Runtime
        config = load_settings(args.config)
        with Runtime() as runtime:
            buckets = BucketController(runtime, load_config())
            original = buckets.assignments()
            report['original_assignments'] = original
            client = TelemetryClient(config['collector_url'], config['http_timeout_seconds'])
            dry = AdaptiveController(runtime, client, config, load_config())
            live = AdaptiveController(runtime, client, config, load_config(), live=True,
                                      acknowledge_state_loss=True) if args.live else None
            reply(dict(status='ready', assignments=original, pipeline_schema_validated=True))
            try:
                for _ in range(2000):
                    line = sys.stdin.readline(65537)
                    if not line:
                        break
                    if len(line) > 65536:
                        raise ValueError('oversized worker request')
                    command = json.loads(line)['command']
                    if command == 'sample':
                        owners = buckets.assignments()
                        counts = runtime.counters()
                        validate_counters(counts, config['counter_bits'])
                        if buckets.assignments() != owners:
                            raise ControllerError('ownership changed across sample')
                        result = dict(status='sample', assignments=owners, counters=counts,
                                      monotonic=time.monotonic())
                    elif command in ('dry-step', 'live-step'):
                        engine = dry if command == 'dry-step' else live
                        if engine is None:
                            raise ValueError('live test not enabled')
                        result = engine.step()
                        if command == 'live-step' and result.get('candidate') is not None:
                            candidate = result['candidate']
                            touched[candidate['bucket']] = candidate['destination']
                    elif command in ('restore', 'quit'):
                        result = restore_assignments(buckets, original, touched)
                    else:
                        raise ValueError('unknown worker command')
                    events.append(dict(command=command, result=result))
                    reply(result)
                    if command == 'quit':
                        break
            finally:
                # Runs on assertions in the parent, EOF, SIGTERM or worker errors.
                try:
                    if live is not None and live.attempted_candidate is not None:
                        attempted = live.attempted_candidate
                        touched[attempted['bucket']] = attempted['destination']
                    report['restoration'] = restore_assignments(buckets, original, touched)
                    report['final_assignments'] = buckets.assignments()
                    report['status'] = 'PASSED'
                except Exception as exc:
                    report['cleanup_errors'].append(repr(exc))
    except BaseException as exc:
        report['error'] = repr(exc)
        reply(dict(status='fault', reason=str(exc)))
    finally:
        report['events'] = list(events)
        Path(args.report).write_text(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASSED' and 'error' not in report else 1


if __name__ == '__main__':
    raise SystemExit(main())
