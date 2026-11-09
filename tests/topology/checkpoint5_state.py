"""Checkpoint 5 in an EXISTING Mininet session; explicit live opt-in required.

Requires already-running, state-enabled detector processes. Never restarts services,
reinitializes a switch, or launches a topology. Owns only its worker/test senders.
"""
import argparse
import json
from pathlib import Path
import runpy
import select
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from controller.state_transfer import network_client
from detectors.bucket_hash import bucket_for, verify_evidence, fingerprint
from detectors.bucket_state import load_state_config

FLOW = ('10.0.0.1', '10.0.1.100', 40009, 9000, 17)


def exercise(net, *, state_config, allow_live=False, failure=None):
    directory = Path(tempfile.mkdtemp(prefix='checkpoint5-live-', dir=ROOT / 'logs'))
    report = dict(status='BLOCKED', failure_injection=failure, phases={}, cleanup_errors=[],
                  worker_report=str(directory / 'worker-report.json'))
    worker = None
    children, files = [], []
    initial = None
    cp3 = runpy.run_path(str(ROOT / 'tests/topology/checkpoint3_detection.py'))
    stream_code = runpy.run_path(str(ROOT / 'tests/topology/checkpoint4_adaptive.py'))['STREAM']
    def response(timeout=25):
        if not select.select([worker.stdout], [], [], timeout)[0]:
            raise RuntimeError('worker response timeout')
        line = worker.stdout.readline()
        if not line:
            raise RuntimeError('worker exited; inspect worker stderr/report')
        value = json.loads(line)
        if value.get('status') == 'fault':
            raise RuntimeError(value.get('error', 'worker fault'))
        return value
    def request(command, **extra):
        worker.stdin.write(json.dumps(dict(command=command, **extra))+'\n')
        worker.stdin.flush()
        return response()
    def send(count, label):
        # Reuse the existing bounded raw UDP fixture, with CP2's source port and
        # CP4's destination port 9002. Expected tuple is adjusted below accordingly.
        log = open(directory / (label + '.log'), 'w')
        files.append(log)
        child = net.get('h1').popen(['/usr/bin/python3', '-c', stream_code,
                                    json.dumps({str(flow[2]): 20}), str(count/20)],
                                    stdout=log, stderr=subprocess.STDOUT)
        children.append(child)
        if child.wait(timeout=10):
            raise RuntimeError('test stream failed')
        return json.loads((directory / (label + '.log')).read_text())['counts'][str(flow[2])]
    def bucket_state(name):
        return client.call(name, 'buckets/' + str(bucket))
    def wait_count(name, count):
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            value = bucket_state(name)
            if value['bucket_state']['packets_total'] >= count:
                return value
            time.sleep(.1)
        raise AssertionError(name + ': captured/imported state did not reach expected count')
    try:
        if not allow_live:
            raise PermissionError('explicit allow_live=True required for migration/restoration test')
        config = load_state_config(state_config)
        if not config['enabled']:
            raise PermissionError('state config must be enabled')
        evidence = Path(config['attribution_evidence'])
        if not evidence.is_absolute():
            evidence = ROOT / evidence
        attribution = verify_evidence(evidence)
        environment = cp3['environment']()
        report['environment'] = environment
        if environment['status'] != 'READY':
            raise PermissionError('; '.join(environment['reasons']))
        for pid in environment['switch_pids']:
            if fingerprint('/proc/' + pid + '/exe') != fingerprint('/usr/bin/simple_switch_grpc'):
                raise PermissionError('running BMv2 differs from parity-tested executable')
        client = network_client(ROOT / 'config/dynohash.json', config)
        report['detectors'] = {}
        for name in ('d1', 'd2', 'd3'):
            try:
                health = client.call(name, 'health')
            except Exception as exc:
                raise PermissionError(name + ': state-enabled service required: ' + str(exc)) from exc
            if health.get('attribution_id') != attribution or health.get('enabled') is not True:
                raise PermissionError(name + ': state API attribution mismatch')
            report['detectors'][name] = health
        # This harness only reuses state-enabled services; it never duplicates or
        # restarts existing detector processes. Health failure is a blocking setup issue.
        log = open(directory / 'worker.log', 'w')
        files.append(log)
        command = [str(ROOT / '.venv/bin/python'), str(ROOT / 'tests/topology/checkpoint5_worker.py'),
                   '--state-config', str(Path(state_config).resolve()), '--report', str(directory / 'worker-report.json')]
        if failure is not None:
            command += ['--failure', failure]
        worker = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
                                  text=True, cwd=ROOT)
        ready = response()
        if ready['status'] != 'ready' or not ready.get('pipeline_verified'):
            raise PermissionError('verified P4 pipeline unavailable')
        initial = ready['assignments']
        report['initial_assignments'] = initial
        report['switch_pids_before'] = environment['switch_pids']
        flow = FLOW[:3]+(9002, 17)
        bucket = bucket_for(flow)
        source = initial[str(bucket)]
        destination = next(n for n in ('d1', 'd2', 'd3') if n != source)
        report.update(flow=list(flow), bucket_id=bucket, source=source, destination=destination)
        before = request('sample')
        before_total = bucket_state(source)['bucket_state']['packets_total']
        count = send(20, 'before-migration')
        after = request('sample')
        deltas = {b: after['counters'][b]-before['counters'][b] for b in before['counters']}
        if deltas[str(bucket)] != count or sum(deltas.values()) != count:
            raise AssertionError('actual P4 counter deltas do not match attributed test tuple')
        observed = wait_count(source, before_total+count)
        flow_key = json.dumps(list(flow), separators=(',', ':'))
        if not any(flow_key in b['flows'] for b in observed['state']['bins']):
            raise AssertionError('source lacks relevant per-flow rolling state')
        report['phases']['before'] = dict(packets=count, actual_bucket_deltas=deltas, state=observed)
        migration = request('migrate', bucket_id=bucket, destination=destination)
        report['phases']['migration'] = migration
        if failure in ('unavailable_destination', 'invalid_payload', 'p4_failure'):
            if migration['status'] != 'injected_failure' or request('sample')['assignments'] != initial:
                raise AssertionError('injected pre-write failure changed P4 ownership or did not fail')
            if bucket_state(source)['bucket_state']['packets_total'] < before_total+count:
                raise AssertionError('failure removed source history')
            report['status'] = 'PASSED'
        else:
            if failure == 'timeout':
                if migration['status'] != 'injected_failure':
                    raise AssertionError('lost-response injection did not occur')
                migration = request('reconcile')
                report['phases']['reconciled'] = migration
            if migration['status'] != 'migrated' or migration['event']['status'] != 'complete' or migration['event']['p4_modify_calls'] != 1:
                raise AssertionError('state/P4 migration was not fully verified with exactly one MODIFY call')
            expected = dict(initial)
            expected[str(bucket)] = destination
            if request('sample')['assignments'] != expected:
                raise AssertionError('P4 ownership readback or unrelated assignments differ')
            imported = bucket_state(destination)
            exported = migration['event']['snapshot']['state']
            if imported['bucket_state']['packets_total'] < exported['packets_total']:
                raise AssertionError('destination did not retain exported history')
            if not any(flow_key in b['flows'] for b in imported['state']['bins']):
                raise AssertionError('destination lacks the transferred stateful flow')
            baseline = imported['bucket_state']['packets_total']
            before = request('sample')
            continuing = send(20, 'after-migration')
            after = request('sample')
            if after['counters'][str(bucket)]-before['counters'][str(bucket)] != continuing:
                raise AssertionError('continuing traffic did not use the same P4 bucket')
            continued = wait_count(destination, baseline+continuing)
            if bucket_state(source)['bucket_state']['packets_total'] != observed['bucket_state']['packets_total']:
                raise AssertionError('source continued to receive the migrated test flow')
            report['phases']['after'] = dict(packets=continuing, imported=imported, continued=continued)
            report['status'] = 'PASSED'
    except PermissionError as exc:
        report.update(status='BLOCKED', error=str(exc))
    except Exception as exc:
        report.update(status='FAILED', error=repr(exc))
    finally:
        if worker is not None:
            try:
                if worker.poll() is None:
                    request('quit')
                worker.wait(timeout=15)
                if worker.returncode:
                    raise RuntimeError('worker/restore exit code ' + str(worker.returncode))
                worker_report = json.loads((directory / 'worker-report.json').read_text())
                report['restoration'] = worker_report
                if not worker_report.get('restored') or worker_report['cleanup_errors']:
                    raise RuntimeError('restoration not fully verified')
            except Exception as exc:
                report['cleanup_errors'].append(str(exc))
                if worker.poll() is None:
                    worker.terminate()
                    try:
                        worker.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        worker.kill(); worker.wait(timeout=3)
                        report['cleanup_errors'].append('worker killed; restoration cannot be guaranteed')
            worker.stdin.close(); worker.stdout.close()
        for child in children:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)
        for file in files:
            file.close()
        if initial is not None:
            try:
                report['switch_pids_after'] = cp3['environment']()['switch_pids']
                if report['switch_pids_after'] != report['switch_pids_before']:
                    raise AssertionError('BMv2 PID changed')
            except Exception as exc:
                report['cleanup_errors'].append(str(exc))
        if report['cleanup_errors']:
            report['status'] = 'FAILED'
        (directory / 'report.json').write_text(json.dumps(report, indent=2))
        print(json.dumps({k: v for k, v in report.items() if k not in ('phases', 'restoration')}, indent=2))
        print('Evidence:', directory / 'report.json')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-environment', action='store_true', required=True)
    parser.parse_args()
    result = runpy.run_path(str(ROOT / 'tests/topology/checkpoint3_detection.py'))['environment']()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status'] == 'READY' else 2)
