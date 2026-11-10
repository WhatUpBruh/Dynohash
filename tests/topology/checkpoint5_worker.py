"""Test-only single P4Runtime owner for the existing-Mininet state-transfer harness."""
import argparse
import json
from pathlib import Path
import signal
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from controller.core import BucketController, load_config, ControllerError
from controller.adaptive import validate_counters
from controller.state_transfer import make_coordinator, StateHTTPError
from detectors.bucket_state import load_state_config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-config', required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('--failure', choices=('unavailable_destination', 'invalid_payload', 'duplicate_request', 'timeout', 'p4_failure'))
    args = parser.parse_args()
    report = dict(status='FAILED', scope='worker protocol/restoration only', cleanup_errors=[], events=[])
    def reply(value):
        print(json.dumps(value, allow_nan=False), flush=True)
    def stop(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    original, touched, coordinator = None, None, None
    transaction = str(uuid.uuid4())
    try:
        from controller.runtime import Runtime
        restoration = __import__('runpy').run_path(str(ROOT / 'tests/topology/checkpoint4_worker.py'))['restore_assignments']
        config = load_state_config(args.state_config)
        if not config['enabled']:
            raise ValueError('state-transfer config must be enabled explicitly')
        with Runtime() as runtime:
            buckets = BucketController(runtime, load_config())
            original = buckets.assignments()
            coordinator = make_coordinator(runtime, load_config(), ROOT / 'config/dynohash.json', config)
            real_call = coordinator.client.call
            duplicate_done = False
            timeout_done = False
            def injected_call(server, operation, body=None):
                nonlocal duplicate_done, timeout_done
                if args.failure == 'unavailable_destination' and operation == 'prepare':
                    raise StateHTTPError('injected destination outage before prepare')
                if args.failure == 'invalid_payload' and operation == 'prepare':
                    body = dict(body, snapshot=dict(body['snapshot'], version=99))
                value = real_call(server, operation, body)
                if args.failure == 'duplicate_request' and operation == 'prepare' and not duplicate_done:
                    second = real_call(server, operation, body)
                    if second != value:
                        raise AssertionError('duplicate prepare changed staged state')
                    duplicate_done = True
                if args.failure == 'timeout' and operation == 'commit' and not timeout_done:
                    timeout_done = True
                    raise StateHTTPError('injected lost commit response AFTER real commit')
                return value
            coordinator.client.call = injected_call
            actual_modify = runtime.modify_bucket
            def failed_modify(*args):
                raise ControllerError('injected failure BEFORE sending P4 MODIFY')
            if args.failure == 'p4_failure':
                runtime.modify_bucket = failed_modify
            reply(dict(status='ready', assignments=original, pipeline_verified=True, transfer_id=transaction))
            try:
                for _ in range(256):
                    line = sys.stdin.readline(8193)
                    if not line:
                        break
                    if len(line) > 8192:
                        raise ValueError('worker input limit')
                    request = json.loads(line)
                    command = request['command']
                    if command == 'sample':
                        owners = buckets.assignments()
                        counters = runtime.counters()
                        validate_counters(counters)
                        if buckets.assignments() != owners:
                            raise ControllerError('ownership changed across counter read')
                        value = dict(status='sample', assignments=owners, counters=counters)
                    elif command == 'migrate':
                        bucket, destination = request['bucket_id'], request['destination']
                        touched = (bucket, destination)
                        try:
                            coordinator.migrate(bucket, destination, expected_assignments=original,
                                                transfer_id_value=transaction)
                            value = dict(status='migrated', event=coordinator.last_event)
                        except Exception as exc:
                            if args.failure not in ('unavailable_destination', 'invalid_payload', 'timeout', 'p4_failure'):
                                raise
                            value = dict(status='injected_failure', error=str(exc), event=coordinator.last_event)
                    elif command == 'reconcile':
                        if touched is None:
                            value = dict(status='error', error='reconcile requested before any migrate')
                        else:
                            try:
                                coordinator.migrate(touched[0], touched[1], transfer_id_value=transaction)
                                value = dict(status='migrated', event=coordinator.last_event)
                            except Exception as exc:
                                value = dict(status='injected_failure', error=str(exc), event=coordinator.last_event)
                    elif command == 'quit':
                        value = dict(status='quitting')
                    else:
                        raise ValueError('unsupported worker command')
                    report['events'].append(dict(command=command, result=value))
                    reply(value)
                    if command == 'quit':
                        break
            finally:
                runtime.modify_bucket = actual_modify
                try:
                    current = buckets.assignments()
                    if current != original and touched is not None:
                        allowed = dict(original)
                        allowed[touched[0]] = touched[1]
                        if current != allowed:
                            raise ControllerError('unrelated ownership changed; restoration refused')
                        try:
                            # Prefer reverse state transfer. It preserves the new
                            # destination history while returning forwarding ownership.
                            coordinator.client.call = real_call
                            coordinator.migrate(touched[0], original[touched[0]], expected_assignments=current)
                            report['state_restoration'] = coordinator.last_event
                        except Exception as exc:
                            report['cleanup_errors'].append('reverse state transfer: ' + str(exc))
                            # If the forward transfer is uncertain, preserve both
                            # histories, restore only the known table delta, and
                            # report degraded state recovery rather than success.
                            restoration(buckets, original, {touched[0]: touched[1]})
                    report['restored'] = buckets.assignments() == original
                    report['final_assignments'] = buckets.assignments()
                    if not report['restored']:
                        raise ControllerError('restoration readback mismatch')
                    report['status'] = 'PASSED' if not report['cleanup_errors'] else 'FAILED'
                except Exception as exc:
                    report['cleanup_errors'].append(str(exc))
    except BaseException as exc:
        report['error'] = repr(exc)
        reply(dict(status='fault', error=str(exc)))
    finally:
        Path(args.report).write_text(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASSED' and 'error' not in report else 1


if __name__ == '__main__':
    raise SystemExit(main())
