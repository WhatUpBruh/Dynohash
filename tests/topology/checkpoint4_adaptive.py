"""Live Checkpoint 4 test in the EXISTING Mininet CLI; no topology/provisioning.

Default is dry-run. Explicit live=True AND acknowledge_state_loss=True permit one
adaptive migration, followed by guarded restoration even when assertions fail.
"""
import argparse
from collections import Counter
import errno
import json
import os
from pathlib import Path
import runpy
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time

PROJECT = Path(__file__).resolve().parents[2]
PYTHON = str(PROJECT / '.venv/bin/python')
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))
from controller.adaptive import load_settings
from controller.telemetry_client import TelemetryClient, validate_view

IDS = ('d1', 'd2', 'd3')

# Test-only raw Ethernet stimulus. Ports are discovered through actual bucket
# counter deltas, never a guessed Python hash. A finite lifetime bounds orphan risk.
STREAM = '''import json,signal,socket,struct,sys,time
pattern=json.loads(sys.argv[1]); duration=float(sys.argv[2]); running=True
def stop(*args):
 global running
 running=False
signal.signal(signal.SIGTERM,stop); signal.signal(signal.SIGINT,stop)
ip=struct.pack('!BBHHHBBH4s4s',69,0,60,1,0,64,17,0,socket.inet_aton('10.0.0.1'),socket.inet_aton('10.0.1.100'))
total=sum(struct.unpack('!10H',ip))
while total>>16: total=(total&65535)+(total>>16)
ip=ip[:10]+struct.pack('!H',(~total)&65535)+ip[12:]
frames={p:bytes.fromhex('0200000000010000000000010800')+ip+struct.pack('!HHHH',int(p),9002,40,0)+b'DynoHash-checkpoint4'.ljust(32,b'.') for p in pattern}
counts={p:0 for p in pattern}; start=time.monotonic(); next_send=dict.fromkeys(pattern,start)
with socket.socket(socket.AF_PACKET,socket.SOCK_RAW) as sock:
 sock.bind(('h1-eth0',0))
 while running and time.monotonic()-start<duration:
  port=min(next_send,key=next_send.get); delay=next_send[port]-time.monotonic()
  if delay>0: time.sleep(min(delay,.01)); continue
  sock.send(frames[port]); counts[port]+=1; next_send[port]+=1/float(pattern[port])
print(json.dumps(dict(counts=counts,elapsed_seconds=time.monotonic()-start)),flush=True)
'''


class Blocked(RuntimeError):
    pass


def detector_processes(host, name):
    """Read-only identity check in the matching network namespace; do not kill any."""
    namespace = os.readlink('/proc/%s/ns/net' % host.pid)
    found = []
    for path in Path('/proc').glob('[0-9]*/cmdline'):
        try:
            words = path.read_bytes().decode(errors='replace').split('\0')
            if not any(w.endswith('minimal_detector.py') or w == 'detectors.minimal_detector' for w in words):
                continue
            if not any(w == '--server-id=' + name or (w == '--server-id' and words[i+1] == name)
                       for i, w in enumerate(words[:-1])):
                continue
            if os.readlink(str(path.parent / 'ns/net')) == namespace:
                found.append(int(path.parent.name))
        except (OSError, IndexError):
            continue
    return found


def exercise(net, *, live=False, acknowledge_state_loss=False, port=8080):
    if live and not acknowledge_state_loss:
        raise ValueError('live=True also requires acknowledge_state_loss=True')
    log_root = PROJECT / 'logs'
    log_root.mkdir(exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='checkpoint4-', dir=log_root))
    report = dict(status='FAILED', mode='live' if live else 'dry-run', phases={}, cleanup_errors=[],
                  log_directory=str(directory), verified_live_migrations=0,
                  live_test_requested=live)
    children, logs = [], []
    worker = None
    stream = None
    initial = None
    cp3 = runpy.run_path(str(PROJECT / 'tests/topology/checkpoint3_detection.py'))
    settings = load_settings()
    bridge_ip = json.loads((PROJECT / 'config/dynohash.json').read_text())['management_bridge_ip']
    settings.update(collector_url=f'http://{bridge_ip}:{port}/api/v1/telemetry', sustained_seconds=2,
                    minimum_improvement_pps=30, max_migrations=1)
    client = TelemetryClient(settings['collector_url'], timeout=1)

    def spawn(command, label, host=None, pipes=False):
        log = open(directory / (label + '.log'), 'w')
        logs.append(log)
        options = dict(cwd=str(PROJECT), stderr=log,
                       stdout=subprocess.PIPE if pipes else log, text=pipes)
        if pipes:
            options['stdin'] = subprocess.PIPE
        child = (subprocess.Popen(command, **options) if host is None
                 else net.get(host).popen(command, **options))
        children.append((label, child))
        return child

    def terminate(child):
        if child is None:
            return
        if child.poll() is None:
            child.send_signal(signal.SIGTERM)
        try:
            child.wait(timeout=6)
        except subprocess.TimeoutExpired:
            child.kill()  # only a child this harness created
            child.wait(timeout=3)
            raise RuntimeError('owned child required forced termination')

    def read_worker(timeout=25):
        if not select.select([worker.stdout], [], [], timeout)[0]:
            raise RuntimeError('worker response timeout')
        line = worker.stdout.readline()
        if not line:
            raise RuntimeError('worker exited; inspect worker.log')
        result = json.loads(line)
        if result.get('status') == 'fault':
            raise RuntimeError('worker fault: ' + result.get('reason', 'unknown'))
        return result

    def request(command):
        worker.stdin.write(json.dumps({'command': command}) + '\n')
        worker.stdin.flush()
        return read_worker()

    def fresh():
        return validate_view(client.read(), settings, time.time())

    def wait_fresh(timeout=12):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                return fresh()
            except Exception:
                time.sleep(.25)
        raise Blocked('fresh telemetry for all three detectors unavailable')

    def start_stream(pattern, label, duration=90):
        return spawn(['/usr/bin/python3', '-c', STREAM, json.dumps(pattern), str(duration)],
                     label, host='h1')

    def totals():
        return {n: s['packets_processed_total'] for n, s in fresh().items()}

    def drain():
        # Do not compare a new burst with a telemetry total published before the
        # preceding stream stopped. Require new post-idle snapshots from all IDs.
        after = time.time() + 1
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            readings = fresh()
            if all(s['timestamp'] >= after for s in readings.values()):
                return
            time.sleep(.2)
        raise AssertionError('detector publications did not drain after test traffic')

    def isolated_burst(pattern, label, owners, discovered):
        drain()
        before = request('sample')
        before_totals = totals()
        child = start_stream(pattern, label, duration=2)
        if child.wait(timeout=8):
            raise AssertionError('burst failed')
        sent = json.loads((directory / (label + '.log')).read_text())
        after = request('sample')
        deltas = {b: after['counters'][b] - before['counters'][b] for b in before['counters']}
        expected_buckets = Counter()
        for source_port, count in sent['counts'].items():
            expected_buckets[str(discovered[int(source_port)])] += count
        if any(deltas[b] != expected_buckets[b] for b in deltas):
            raise AssertionError('burst bucket counters differ from discovered flow mapping')
        expected = Counter()
        for bucket, count in deltas.items():
            expected[owners[bucket]] += count
        deadline = time.monotonic() + 5
        while True:
            captured = {n: v - before_totals[n] for n, v in totals().items()}
            if all(captured[n] == expected[n] for n in IDS):
                break
            if time.monotonic() >= deadline:
                raise AssertionError('misrouting/capture loss: %s vs %s' % (captured, dict(expected)))
            time.sleep(.25)
        report['phases'][label] = dict(sent=sent, bucket_deltas=deltas,
                                       expected=dict(expected), captured=captured)

    try:
        environment = cp3['environment']()
        report['environment'] = environment
        if environment['status'] != 'READY':
            raise Blocked('; '.join(environment['reasons']))
        report['switch_pids_before'] = environment['switch_pids']
        try:
            existing = client.read()
            if (not isinstance(existing, dict) or not isinstance(existing.get('servers'), dict)
                    or set(existing['servers']) != set(IDS)):
                raise Blocked('existing service does not expose the expected collector API')
            report['collector'] = 'reused existing API'
        except Exception as exc:
            with socket.socket() as probe:
                probe.settimeout(1)
                code = probe.connect_ex((bridge_ip, port))
            if code != errno.ECONNREFUSED:
                raise Blocked('collector port occupied/unreachable; refusing duplicate service: ' + str(exc))
            owned_collector = spawn([PYTHON, '-m', 'detectors.collector', '--bind', bridge_ip,
                                     '--port', str(port)], 'collector')
            report['collector'] = 'test-owned'
            for _ in range(30):
                if owned_collector.poll() is not None:
                    raise Blocked('test collector exited; refusing to attach to a possible competing service')
                try:
                    client.read()
                    break
                except Exception:
                    time.sleep(.2)
            else:
                raise Blocked('test collector did not become ready')
        report['detectors'] = {}
        report['routes'] = {}
        for name in IDS:
            host = net.get(name)
            route = host.popen(['ip', '-j', 'route', 'get', bridge_ip], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
            children.append((name + '-route', route))
            output, errors = route.communicate(timeout=4)
            if route.returncode or not json.loads(output) or json.loads(output)[0].get('dev') != name + '-mgmt0':
                raise Blocked(name + ': management route invalid: ' + errors)
            report['routes'][name] = json.loads(output)
            check = ('from urllib.request import build_opener,ProxyHandler; '
                     f'r=build_opener(ProxyHandler({{}})).open({settings["collector_url"]!r},timeout=2); '
                     'assert r.status==200; r.close()')
            probe = host.popen([PYTHON, '-c', check], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            children.append((name + '-http', probe))
            _, errors = probe.communicate(timeout=4)
            if probe.returncode:
                raise Blocked(name + ': management HTTP failed: ' + errors.decode(errors='replace'))
            pids = detector_processes(host, name)
            if len(pids) > 1:
                raise Blocked(name + ': duplicate existing detectors; resolve manually')
            if pids:
                report['detectors'][name] = dict(reused_pids=pids)
            else:
                try:
                    entry = client.read()['servers'][name]
                    if entry.get('stale') is False:
                        raise Blocked(name + ': fresh telemetry from an unidentified service; refusing duplicate')
                except (KeyError, TypeError):
                    pass
                child = spawn([PYTHON, '-m', 'detectors.minimal_detector', '--server-id', name,
                               '--interface', name + '-eth0', '--collector-url', settings['collector_url']], name, host=name)
                report['detectors'][name] = dict(test_owned_pid=child.pid)
        report['ready_telemetry'] = wait_fresh()
        config_path = directory / 'adaptive-config.json'
        config_path.write_text(json.dumps(settings, indent=2))
        report['settings'] = settings
        command = [PYTHON, str(PROJECT / 'tests/topology/checkpoint4_worker.py'), '--config', str(config_path),
                   '--report', str(directory / 'worker-report.json')]
        if live:
            command += ['--live', '--acknowledge-state-loss']
        worker = spawn(command, 'worker', pipes=True)
        ready = read_worker()
        if ready.get('status') != 'ready' or len(ready['assignments']) != 64:
            raise Blocked('P4Runtime worker not ready')
        initial = ready['assignments']
        report['switch_readiness'] = ready
        report['original_assignments'] = initial
        quiet_before = request('sample')
        time.sleep(1.2)
        quiet_after = request('sample')
        if quiet_before['counters'] != quiet_after['counters']:
            raise Blocked('test requires an idle data plane; existing traffic detected')
        # Discover two distinct usable buckets per detector using real P4 behavior.
        mapping, found = {}, {n: {} for n in IDS}
        for source_port in range(42000, 42128):
            before = request('sample')
            child = start_stream({source_port: 5}, 'probe-' + str(source_port), duration=.4)
            if child.wait(timeout=4):
                raise AssertionError('hash discovery packet send failed')
            sent = json.loads((directory / ('probe-' + str(source_port) + '.log')).read_text())['counts'][str(source_port)]
            time.sleep(.1)
            after = request('sample')
            delta = {b: after['counters'][b] - before['counters'][b] for b in before['counters']}
            changed = [b for b, value in delta.items() if value]
            if len(changed) != 1 or delta[changed[0]] != sent or sent <= 0:
                raise Blocked('cannot isolate flow bucket from actual counters: ' + str(delta))
            bucket = int(changed[0])
            mapping[source_port] = bucket
            found[initial[str(bucket)]].setdefault(bucket, source_port)
            if all(len(v) >= 2 for v in found.values()):
                break
        if not all(len(v) >= 2 for v in found.values()):
            raise Blocked('discovery did not find two usable buckets per detector; current assignments may prevent test')
        report['discovered_ports_to_buckets'] = mapping
        source, middle, destination = IDS
        source_ports = list(found[source].values())[:2]
        balanced = {next(iter(found[n].values())): 150 for n in IDS}
        high = {source_ports[0]: 600, source_ports[1]: 300,
                next(iter(found[middle].values())): 300,
                next(iter(found[destination].values())): 100}
        # Allow discovery packets and telemetry publication to drain before exact comparisons.
        time.sleep(2)
        isolated_burst(balanced, 'balanced-delivery', initial, mapping)
        stream = start_stream(balanced, 'balanced-stream')
        time.sleep(6)
        balanced_steps = []
        for _ in range(5):
            balanced_steps.append(request('dry-step'))
            time.sleep(settings['poll_seconds'])
        if any(s['status'] in ('proposed', 'migrated', 'fault') for s in balanced_steps):
            raise AssertionError('balanced traffic caused migration or a fault')
        if not any('balanced' in s['reason'] for s in balanced_steps):
            raise AssertionError('balanced phase never produced a validated balanced measurement')
        report['phases']['balanced_decisions'] = balanced_steps
        terminate(stream)
        stream = start_stream(high, 'imbalanced-stream')
        time.sleep(6)
        dry_steps = []
        for _ in range(12):
            decision = request('dry-step')
            dry_steps.append(decision)
            if decision['status'] == 'proposed':
                break
            time.sleep(settings['poll_seconds'])
        if dry_steps[-1]['status'] != 'proposed' or dry_steps[-1]['candidate']['improvement_pps'] < settings['minimum_improvement_pps']:
            raise AssertionError('dry run did not propose a beneficial migration')
        if request('sample')['assignments'] != initial:
            raise AssertionError('dry run changed assignments')
        report['phases']['dry_run'] = dry_steps
        if live:
            live_steps = []
            for _ in range(12):
                decision = request('live-step')
                live_steps.append(decision)
                if decision['status'] == 'migrated':
                    break
                time.sleep(settings['poll_seconds'])
            if live_steps[-1]['status'] != 'migrated':
                raise AssertionError('live test did not perform one verified migration')
            report['phases']['live'] = live_steps
            report['verified_live_migrations'] = 1
            candidate = live_steps[-1]['candidate']
            expected = dict(initial)
            expected[str(candidate['bucket'])] = candidate['destination']
            if request('sample')['assignments'] != expected:
                raise AssertionError('target/unrelated assignment mismatch after migration')
            terminate(stream)
            stream = None
            time.sleep(2)
            isolated_burst(high, 'post-migration-delivery', expected, mapping)
        terminate(stream)
        stream = None
        report['restoration'] = request('restore')
        if request('sample')['assignments'] != initial:
            raise AssertionError('restoration mismatch')
        report['status'] = 'PASSED'
    except Blocked as exc:
        report.update(status='BLOCKED', error=str(exc))
    except Exception as exc:
        report.update(status='FAILED', error=repr(exc))
    finally:
        try:
            terminate(stream)
        except Exception as exc:
            report['cleanup_errors'].append('stream: ' + repr(exc))
        if worker is not None and worker.poll() is None:
            try:
                report['finally_restoration'] = request('quit')
                if not report['finally_restoration'].get('restored'):
                    raise AssertionError('worker did not confirm restoration')
                worker.wait(timeout=8)
            except Exception as exc:
                report['cleanup_errors'].append('restoration: ' + repr(exc))
        for label, child in reversed(children):
            try:
                terminate(child)
                if label == 'worker' and child.returncode:
                    report['cleanup_errors'].append('worker exit code ' + str(child.returncode))
            except Exception as exc:
                report['cleanup_errors'].append(label + ': ' + repr(exc))
        for log in logs:
            log.close()
        try:
            report['switch_pids_after'] = cp3['environment']()['switch_pids']
            if report.get('switch_pids_before') and report['switch_pids_before'] != report['switch_pids_after']:
                raise AssertionError('BMv2 PID changed')
        except Exception as exc:
            report['cleanup_errors'].append(repr(exc))
        if report['cleanup_errors']:
            report['status'] = 'FAILED'
        if worker is not None:
            for pipe in (worker.stdin, worker.stdout):
                if pipe is not None:
                    pipe.close()
        (directory / 'report.json').write_text(json.dumps(report, indent=2))
        print(json.dumps({k: v for k, v in report.items() if k != 'phases'}, indent=2))
        print('Evidence:', directory / 'report.json')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-environment', action='store_true')
    args = parser.parse_args()
    if not args.check_environment:
        parser.error('use exercise(net) inside the existing Mininet CLI')
    result = runpy.run_path(str(PROJECT / 'tests/topology/checkpoint3_detection.py'))['environment']()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status'] == 'READY' else 2)
