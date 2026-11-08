"""Execute inside the existing Mininet CLI; see docs/checkpoint2.md.
Requires an already programmed pipeline and 64 entries. Never restarts BMv2.
"""
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

PROJECT = Path(__file__).resolve().parents[2]
PYTHON = str(PROJECT / '.venv/bin/python')


PACKET_RECORD = re.compile(
    r'^\d{2}:\d{2}:\d{2}\.\d+ '
    r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2} > '
    r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}, '
    r'ethertype IPv4 \(0x0800\), length \d+: '
    r'10\.0\.0\.1\.40009 > 10\.0\.1\.100\.9000: UDP, length \d+$',
    re.IGNORECASE,
)


def count_packet_records(stdout):
    """Count matching flow records from tcpdump -n -e, excluding diagnostics/blanks."""
    return sum(PACKET_RECORD.fullmatch(line.strip()) is not None
               for line in stdout.splitlines())


def rpc(expression):
    code = ('import json; from controller.runtime import Runtime; '
            'from controller.core import BucketController, load_config\n'
            'with Runtime() as r:\n'
            ' c = BucketController(r, load_config())\n'
            f' print(json.dumps({expression}))\n')
    return json.loads(subprocess.check_output([PYTHON, '-c', code], cwd=PROJECT, text=True))


def exercise(net):
    evidence = PROJECT / 'logs/checkpoint2-integration.json'
    report = {'status': 'FAILED', 'phases': []}
    original = None
    bucket = None
    def phase(owner):
        captures = {}
        try:
            for name in ('d1', 'd2', 'd3'):
                captures[name] = net.get(name).popen([
                    'tcpdump', '-l', '-n', '-e', '-i', f'{name}-eth0',
                    'udp and src host 10.0.0.1 and dst host 10.0.1.100 and src port 40009 and dst port 9000'],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            time.sleep(1)
            for process in captures.values():
                if process.poll() is not None:
                    raise RuntimeError('tcpdump exited before traffic')
            # Send fixed Ethernet/IP/UDP frames without requiring a route to the simulated victim.
            code = '''import socket,struct,time
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW); s.bind(('h1-eth0',0))
ip=struct.pack('!BBHHHBBH4s4s',69,0,60,1,0,64,17,0,socket.inet_aton('10.0.0.1'),socket.inet_aton('10.0.1.100'))
words=struct.unpack('!10H',ip); total=sum(words)
while total>>16: total=(total&65535)+(total>>16)
ip=ip[:10]+struct.pack('!H',(~total)&65535)+ip[12:]
frame=bytes.fromhex('0200000000010000000000010800')+ip+struct.pack('!HHHH',40009,9000,40,0)+b'DynoHash-checkpoint2'.ljust(32,b'.')
for i in range(10): s.send(frame); time.sleep(.02)
'''
            sender = net.get('h1').popen(['/usr/bin/python3', '-c', code])
            if sender.wait(timeout=10):
                raise RuntimeError('traffic generator failed')
            time.sleep(1)
        finally:
            for process in captures.values():
                if process.poll() is None:
                    process.send_signal(signal.SIGINT)
            # Drain and preserve diagnostics even when startup or sending failed.
            output = {}
            for name, process in captures.items():
                stdout, stderr = process.communicate(timeout=5)
                output[name] = {'packets': count_packet_records(stdout), 'stdout': stdout, 'stderr': stderr}
            report['phases'].append(output)
        if owner is None:
            return
        for name, capture in output.items():
            expected = 10 if name == owner else 0
            if capture['packets'] != expected:
                raise AssertionError(f'{name}: expected {expected}, got {capture}')
            if expected and ('02:00:00:00:00:01 > ' + {'d1':'00:00:00:00:00:11','d2':'00:00:00:00:00:12','d3':'00:00:00:00:00:13'}[name]) not in capture['stdout']:
                raise AssertionError('MAC rewrite missing')

    try:
        report['switch_pids_before'] = subprocess.check_output(['pgrep', '-x', 'simple_switch_g'], text=True).split()
        original = rpc('c.assignments()')
        report['original_assignments'] = original
        before = rpc('r.counters()')
        phase(None)
        after = rpc('r.counters()')
        deltas = {key: after[key] - before[key] for key in before}
        report['discovery_counter_deltas'] = deltas
        changed = [key for key, delta in deltas.items() if delta]
        if len(changed) != 1 or deltas[changed[0]] != 10:
            raise AssertionError(f'cannot identify isolated flow bucket: {deltas}')
        bucket = int(changed[0])
        owner = original[str(bucket)]
        target = next(name for name in ('d1','d2','d3') if name != owner)
        report.update(bucket=bucket, original_owner=owner, target=target)
        phase(owner)
        rpc(f'c.migrate({bucket}, {target!r})')
        expected = dict(original)
        expected[str(bucket)] = target
        assert rpc('c.assignments()') == expected
        phase(target)
    except Exception as exc:
        report['error'] = repr(exc)
        raise
    finally:
        try:
            if bucket is not None:
                rpc(f'c.migrate({bucket}, {original[str(bucket)]!r})')
                assert rpc('c.assignments()') == original
                phase(original[str(bucket)])
                report['restored'] = True
            report['switch_pids_after'] = subprocess.check_output(['pgrep', '-x', 'simple_switch_g'], text=True).split()
            assert report['switch_pids_before'] == report['switch_pids_after']
            if 'error' not in report and report.get('restored'):
                report['status'] = 'PASSED'
        except Exception as exc:
            report['cleanup_error'] = repr(exc)
            # Preserve the original failure when restoration or the final PID check also fails.
            if 'error' not in report:
                raise
        finally:
            evidence.write_text(json.dumps(report, indent=2))
            print(json.dumps(report, indent=2))


if __name__ == '__main__':
    raise SystemExit('Run exercise(net) inside the existing Mininet CLI; see docs/checkpoint2.md')
