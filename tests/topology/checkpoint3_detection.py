"""Checkpoint 3 live checks inside the EXISTING Mininet CLI; never provisions a switch.

Run --check-environment for a read-only prerequisite report. See docs/checkpoint3.md.
The small inline UDP stimulus is test-only, not a production packet generator.
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import runpy
import signal
import subprocess
import tempfile
import time
from urllib.request import build_opener, ProxyHandler

PROJECT = Path(__file__).resolve().parents[2]
PYTHON = str(PROJECT / '.venv/bin/python')
NAMES = ('d1', 'd2', 'd3')


def environment():
    bridge = subprocess.run(['ip', '-j', 'address', 'show', 'dev', 'dh-mgmt-br'],
                            capture_output=True, text=True, timeout=3)
    switch = subprocess.run(['pgrep', '-x', 'simple_switch_g'],
                            capture_output=True, text=True, timeout=3)
    reasons = []
    if os.geteuid() != 0:
        reasons.append('Mininet host namespace access requires the existing root Mininet CLI')
    if bridge.returncode:
        reasons.append('management bridge unavailable: ' + bridge.stderr.strip())
    if switch.returncode:
        reasons.append('no visible running BMv2 simple_switch_grpc process')
    return dict(status='BLOCKED' if reasons else 'READY', reasons=reasons,
                uid=os.geteuid(), bridge=bridge.stdout.strip(), switch_pids=switch.stdout.split())


# Build fixed Ethernet UDP test frames without relying on a route to the victim.
# Vary 256 source ports to exercise current assignments; no hash implementation.
STIMULUS = '''import json,socket,struct,sys,time
rate=float(sys.argv[1]); duration=float(sys.argv[2])
ip=struct.pack('!BBHHHBBH4s4s',69,0,60,1,0,64,17,0,socket.inet_aton('10.0.0.1'),socket.inet_aton('10.0.1.100'))
total=sum(struct.unpack('!10H',ip))
while total>>16: total=(total&65535)+(total>>16)
ip=ip[:10]+struct.pack('!H',(~total)&65535)+ip[12:]
frames=[bytes.fromhex('0200000000010000000000010800')+ip+struct.pack('!HHHH',41000+i,9001,40,0)+b'DynoHash-checkpoint3'.ljust(32,b'.') for i in range(256)]
with socket.socket(socket.AF_PACKET,socket.SOCK_RAW) as sock:
 sock.bind(('h1-eth0',0))
 start=time.monotonic(); count=0
 while time.monotonic()-start<duration:
  sock.send(frames[count%256]); count+=1
  delay=start+count/rate-time.monotonic()
  if delay>0: time.sleep(delay)
 elapsed=time.monotonic()-start
print(json.dumps(dict(packets_sent=count,elapsed_seconds=elapsed,actual_pps=count/elapsed)))
'''


def exercise(net, port=8080):
    """Start only owned collector/detectors, exercise captures, then stop owned children.

    Requires idle traffic and programmed entries spanning all three detectors. Does
    not migrate; run the existing Checkpoint 2 harness separately to recheck migration.
    """
    log_root = PROJECT / 'logs'
    log_root.mkdir(exist_ok=True)
    log_dir = Path(tempfile.mkdtemp(prefix='checkpoint3-', dir=log_root))
    report = dict(status='FAILED', log_directory=str(log_dir), phases={}, cleanup_errors=[])
    children = []
    files = []
    original = None
    rpc = runpy.run_path(str(PROJECT / 'tests/topology/checkpoint2_migration.py'))['rpc']
    opener = build_opener(ProxyHandler({}))
    network_config = json.loads((PROJECT / 'config/dynohash.json').read_text())
    bridge_ip = network_config['management_bridge_ip']
    url = f'http://{bridge_ip}:{port}/api/v1/telemetry'

    def fetch():
        with opener.open(url, timeout=2) as response:
            return json.load(response)

    def spawn(command, host=None, name='process'):
        log = open(log_dir / (name + '.log'), 'w')
        files.append(log)
        runner = subprocess if host is None else net.get(host)
        process = (runner.Popen(command, cwd=PROJECT, stdout=log, stderr=subprocess.STDOUT)
                   if host is None else runner.popen(command, cwd=str(PROJECT), stdout=log,
                                                    stderr=subprocess.STDOUT))
        children.append((name, process))
        return process

    def healthy():
        for name, child in children:
            if child.poll() is not None:
                raise RuntimeError(f'{name} exited with {child.returncode}; see {log_dir}')

    def host_command(host, command, label, timeout=4):
        process = net.get(host).popen(command, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
        children.append((label, process))
        stdout, stderr = process.communicate(timeout=timeout)
        children.remove((label, process))
        if process.returncode:
            raise RuntimeError(label + ': ' + stderr)
        return stdout

    def wait_ready(predicate, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            healthy()
            try:
                value = fetch()
                if predicate(value):
                    return value
            except OSError:
                pass
            time.sleep(.2)
        raise RuntimeError('collector/detector readiness timed out')

    def readings(view):
        result = {}
        for name in NAMES:
            entry = view['servers'][name]
            if entry['stale'] or entry['telemetry'] is None:
                raise AssertionError(name + ': missing or stale telemetry')
            result[name] = entry['telemetry']
        return result

    def phase(name, rate):
        before = readings(fetch())
        counters_before = rpc('r.counters()')
        process = spawn(['/usr/bin/python3', '-c', STIMULUS, str(rate), '10'],
                        host='h1', name=name + '-stimulus')
        deadline = time.monotonic() + 15
        samples = []
        while process.poll() is None:
            if time.monotonic() > deadline:
                raise RuntimeError('UDP stimulus timed out')
            # Ignore the completed stimulus in healthy checks after exit.
            for child_name, child in children:
                if child is not process and child_name.endswith('-stimulus'):
                    continue
                if child is not process and child.poll() is not None:
                    raise RuntimeError(child_name + ' exited unexpectedly')
            samples.append(fetch())
            time.sleep(.5)
        if process.returncode:
            raise RuntimeError('UDP stimulus failed; inspect its log')
        children.remove((name + '-stimulus', process))
        time.sleep(1.2)  # one publish after the last captured frame
        after = readings(fetch())
        counters_after = rpc('r.counters()')
        stimulus = json.loads((log_dir / (name + '-stimulus.log')).read_text())
        deltas = {b: counters_after[b] - counters_before[b] for b in counters_before}
        expected = Counter()
        for bucket, count in deltas.items():
            expected[original[str(bucket)]] += count
        captured = {n: after[n]['packets_processed_total'] - before[n]['packets_processed_total'] for n in NAMES}
        report['phases'][name] = dict(stimulus=stimulus, captured=captured,
                                     expected_by_live_assignment=dict(expected),
                                     bucket_counter_deltas=deltas, samples=samples, final=after)
        if sum(deltas.values()) != stimulus['packets_sent']:
            raise AssertionError('switch counters differ from sent traffic; isolate background traffic')
        for detector in NAMES:
            if captured[detector] <= 0 or captured[detector] != expected[detector]:
                raise AssertionError(f'{detector}: captured {captured[detector]}, expected {expected[detector]}')
        if name == 'normal':
            if any(readings(sample)[n]['suspicious'] or readings(sample)[n]['alerts']
                   for sample in samples for n in NAMES):
                raise AssertionError('normal traffic generated an alert')
        else:
            for detector in NAMES:
                if not any(readings(s)[detector]['suspicious'] and readings(s)[detector]['alerts'] for s in samples):
                    raise AssertionError(detector + ': high-rate traffic did not generate an observed alert')

    try:
        report['environment'] = environment()
        if report['environment']['status'] != 'READY':
            report['status'] = 'BLOCKED'
            raise RuntimeError('; '.join(report['environment']['reasons']))
        original = rpc('c.assignments()')
        report['original_assignments'] = original
        report['switch_pids_before'] = report['environment']['switch_pids']
        if set(original.values()) != set(NAMES):
            report['status'] = 'BLOCKED'
            raise RuntimeError('existing assignments do not permit testing all three detectors')
        # Fail rather than attach to or terminate a pre-existing collector.
        collector = spawn([PYTHON, '-m', 'detectors.collector', '--bind', bridge_ip,
                           '--port', str(port)], name='collector')
        wait_ready(lambda _: 'Collector listening' in (log_dir / 'collector.log').read_text())
        if collector.poll() is not None:
            raise RuntimeError('collector could not bind; choose an unused port')
        report['routes'] = {}
        for name in NAMES:
            stdout = host_command(name, ['ip', '-j', 'route', 'get', bridge_ip],
                                  name + '-route', timeout=3)
            routes = json.loads(stdout)
            report['routes'][name] = routes
            if not routes or routes[0].get('dev') != name + '-mgmt0':
                raise AssertionError(name + ': collector route does not use management interface')
            code = ('from urllib.request import build_opener,ProxyHandler; '
                    f'r=build_opener(ProxyHandler({{}})).open({url!r},timeout=2); '
                    'assert r.status==200; r.close()')
            host_command(name, [PYTHON, '-c', code], name + '-reachability')
        test_config = json.loads((PROJECT / 'config/checkpoint3.json').read_text())
        test_config.update(threshold_pps=100, minimum_packets=30, collector_url=url)
        config_path = log_dir / 'detector-config.json'
        config_path.write_text(json.dumps(test_config, indent=2))
        report['test_config'] = test_config
        for name in NAMES:
            spawn([PYTHON, '-m', 'detectors.minimal_detector', '--server-id', name,
                   '--interface', name + '-eth0', '--config', str(config_path)],
                  host=name, name=name)
        ready = wait_ready(lambda v: all(not v['servers'][n]['stale'] for n in NAMES))
        report['initial'] = ready
        phase('normal', 30)
        phase('high_rate', 3000)
        time.sleep(7)  # expire the entire rolling window while publishers continue
        idle = readings(fetch())
        report['idle'] = idle
        if any(r['packet_rate_pps'] != 0 or r['active_flows'] != 0 or r['suspicious'] for r in idle.values()):
            raise AssertionError('idle traffic did not expire')
        report['status'] = 'PASSED'
    except Exception as exc:
        report['error'] = repr(exc)
    finally:
        for name, child in reversed(children):
            try:
                if child.poll() is None:
                    child.send_signal(signal.SIGTERM)
                try:
                    child.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    child.kill()  # only this harness's owned child
                    child.wait(timeout=2)
                    report['cleanup_errors'].append(name + ': required forced termination')
            except Exception as exc:
                report['cleanup_errors'].append(name + ': ' + repr(exc))
        for log in files:
            log.close()
        if original is not None:
            try:
                report['final_assignments'] = rpc('c.assignments()')
                report['switch_pids_after'] = environment()['switch_pids']
                if report['final_assignments'] != original:
                    raise AssertionError('bucket assignments changed unexpectedly')
                if report['switch_pids_after'] != report['switch_pids_before']:
                    raise AssertionError('BMv2 PID changed')
            except Exception as exc:
                report['cleanup_errors'].append(repr(exc))
        if report['cleanup_errors']:
            report['status'] = 'FAILED'
        evidence = log_dir / 'report.json'
        evidence.write_text(json.dumps(report, indent=2))
        print(json.dumps({k: v for k, v in report.items() if k not in ('phases', 'idle')}, indent=2))
        print('Evidence:', evidence)
    return report


def recheck_migration(net):
    """Explicit optional live migration recheck; preserve Checkpoint 2 evidence.

    The existing harness temporarily migrates and restores one bucket. Invoke only
    when you authorize that test, after the telemetry test has stopped its children.
    """
    from unittest.mock import patch
    log_root = PROJECT / 'logs'
    log_root.mkdir(exist_ok=True)
    destination = Path(tempfile.mkdtemp(prefix='checkpoint3-migration-', dir=log_root)) / 'report.json'
    historical = PROJECT / 'logs/checkpoint2-integration.json'
    write_text = Path.write_text

    def preserve_history(path, data, *args, **kwargs):
        return write_text(destination if path == historical else path, data, *args, **kwargs)

    harness = runpy.run_path(str(PROJECT / 'tests/topology/checkpoint2_migration.py'))
    try:
        # Only redirect this one output path in this Python process. The existing
        # migration/capture/restoration implementation runs without modifications.
        with patch.object(Path, 'write_text', preserve_history):
            harness['exercise'](net)
    finally:
        print('New migration evidence:', destination)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-environment', action='store_true')
    args = parser.parse_args()
    if not args.check_environment:
        parser.error('use exercise(net) in the existing Mininet CLI')
    report = environment()
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report['status'] == 'READY' else 2)
