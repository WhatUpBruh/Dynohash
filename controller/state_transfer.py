"""Best-effort staged state transfer coordinated with the existing P4 transaction."""
from http.client import HTTPException
import fcntl
import json
from pathlib import Path
import tempfile
import threading
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, ProxyHandler

from .core import BucketController, ControllerError, ROOT
from .telemetry_client import NoRedirect
from detectors.bucket_hash import verify_evidence
from detectors.bucket_state import bucket_id, digest, transfer_id


class StateTransferError(ControllerError):
    pass


class StateHTTPError(StateTransferError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class StateClient:
    def __init__(self, endpoints, timeout=.5, max_body=131072):
        self.endpoints, self.timeout, self.max_body = endpoints, timeout, max_body
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def call(self, server, operation, body=None):
        if server not in self.endpoints:
            raise StateTransferError('unknown detector endpoint')
        raw = None if body is None else json.dumps(body, allow_nan=False).encode()
        if raw is not None and len(raw) > self.max_body:
            raise StateTransferError('state request exceeds size budget')
        request = Request(self.endpoints[server] + '/api/v1/state/' + operation, raw,
                          {'Content-Type': 'application/json'}, method='GET' if body is None else 'POST')
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                data = response.read(self.max_body + 16385)
                if len(data) > self.max_body + 16384 or response.status != 200 or response.headers.get_content_type() != 'application/json':
                    raise StateTransferError('invalid state HTTP response')
                result = json.loads(data)
                if not isinstance(result, dict) or result.get('server_id') != server:
                    raise StateTransferError('state response detector identity differs')
                return result
        except HTTPError as exc:
            raise StateHTTPError('state HTTP error %s: %s' % (exc.code, exc.read(512).decode(errors='replace')), exc.code) from exc
        except (OSError, URLError, HTTPException, ValueError) as exc:
            raise StateHTTPError('state HTTP unavailable/malformed: ' + str(exc)) from exc


def network_client(network_path, config):
    network = json.loads(Path(network_path).read_text())
    endpoints = {d['id']: 'http://%s:%s' % (d['management_ip'], config['port']) for d in network['detectors']}
    return StateClient(endpoints, config['http_timeout_seconds'], config['max_body_bytes'])


class _CoordinatorLock:
    """Excludes overlapping migrations both within this process and across
    separate processes sharing the same journal directory, by backing the
    in-process lock with an flock on a file inside that journal."""

    def __init__(self, journal):
        self._thread_lock = threading.Lock()
        self._lock_path = journal / '.coordinator.lock'
        self._file = None

    def acquire(self, blocking=False):
        if not self._thread_lock.acquire(blocking=blocking):
            return False
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        file = open(self._lock_path, 'w')
        try:
            fcntl.flock(file.fileno(), fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except OSError:
            file.close()
            self._thread_lock.release()
            return False
        self._file = file
        return True

    def release(self):
        fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        self._file.close()
        self._file = None
        self._thread_lock.release()


class StateCoordinator:
    def __init__(self, runtime, detectors, client, config, attribution_id, *, journal=None, pipeline_validator=None):
        if config['enabled'] is not True:
            raise ValueError('state transfer is disabled')
        self.runtime, self.detectors, self.client, self.config = runtime, detectors, client, config
        self.attribution_id = attribution_id
        self.journal = Path(journal if journal is not None else config['journal_directory'])
        if not self.journal.is_absolute():
            self.journal = ROOT / self.journal
        self.last_event = None
        self.lock = _CoordinatorLock(self.journal)
        self.pipeline_validator = pipeline_validator

    def save(self, event):
        self.journal.mkdir(parents=True, exist_ok=True)
        destination = self.journal / (event['transfer_id'] + '.json')
        if not destination.exists() and len(list(self.journal.glob('*.json'))) >= self.config['max_records']:
            raise StateTransferError('journal capacity exhausted; preserve/archive evidence before new work')
        with tempfile.NamedTemporaryFile(mode='w', dir=self.journal, prefix='.state-', delete=False) as file:
            json.dump(event, file, allow_nan=False, indent=2)
            temporary = Path(file.name)
        temporary.replace(destination)
        self.last_event = event

    def rpc(self, event, server, operation, **extra):
        start = time.monotonic()
        failure = None
        try:
            result = self.client.call(server, operation, dict(server_id=server, bucket_id=event['bucket_id'],
                                      transfer_id=event['transfer_id'], **extra))
            if result.get('transfer_id') != event['transfer_id'] or result.get('bucket_id') != event['bucket_id']:
                raise StateTransferError('response transaction/bucket differs')
            return result
        except Exception as exc:
            failure = str(exc)
            raise
        finally:
            elapsed = time.monotonic()-start
            key = server + ':' + operation
            event['timings_seconds'][key] = event['timings_seconds'].get(key, 0) + elapsed
            operations = event.setdefault('operations', [])
            operations.append(dict(server_id=server, operation=operation, elapsed_seconds=elapsed, error=failure))
            del operations[:-64]

    def verify_destination(self, event):
        status = self.rpc(event, event['destination'], 'status')
        proof = status.get('proof')
        state = event['snapshot']['state']
        expected_proof = dict(imported_packets_total=state['packets_total'], imported_bytes_total=state['bytes_total'],
                              imported_flow_bin_records=sum(len(b['flows']) for b in state['bins']))
        if (status['status'] != 'committed' or status['snapshot_digest'] != event['snapshot_digest'] or
                status['boot_id'] != event['destination_boot_id'] or proof != expected_proof or
                status['bucket_state']['packets_total'] < state['packets_total']):
            raise StateTransferError('destination state proof does not match exported snapshot')
        event['verification'] = dict(ownership=True, state=True, destination=status)
        return status

    def migrate(self, bucket, destination, *, expected_assignments=None, before_write=None, transfer_id_value=None):
        bucket_id(bucket)
        tid = transfer_id(transfer_id_value) if transfer_id_value is not None else str(uuid.uuid4())
        if not self.lock.acquire(blocking=False):
            raise StateTransferError('overlapping state migration in this coordinator')
        event = None
        try:
            if self.pipeline_validator is not None:
                self.pipeline_validator()
            buckets = BucketController(self.runtime, self.detectors)
            current = buckets.assignments()
            path = self.journal / (tid + '.json')
            if path.exists():
                event = json.loads(path.read_text())
                if event['bucket_id'] != bucket or event['destination'] != destination:
                    raise StateTransferError('transfer ID reused with different migration')
                event['original_assignments'] = {int(b): n for b, n in event['original_assignments'].items()}
                if event['status'] == 'aborted':
                    raise StateTransferError('transfer was aborted; retry with a new ID after inspection')
            else:
                if destination not in self.detectors:
                    raise StateTransferError('unknown destination detector')
                if expected_assignments is not None and current != expected_assignments:
                    raise StateTransferError('ownership changed before state export')
                if current[bucket] == destination:
                    return False
                event = dict(version=1, transfer_id=tid, bucket_id=bucket, source=current[bucket], destination=destination,
                             started_at=time.time(), status='starting', original_assignments=current,
                             p4_modify_calls=0, timings_seconds={}, cleanup_errors=[], verification={})
                self.save(event)  # Journal capacity failure occurs before any remote mutation.
                for name in (event['source'], destination):
                    health = self.client.call(name, 'health')
                    if health.get('attribution_id') != self.attribution_id or health.get('enabled') is not True:
                        raise StateTransferError('detector hash attribution/state service mismatch')
                exported = self.rpc(event, event['source'], 'export', destination=destination)
                event.update(snapshot=exported['snapshot'], snapshot_digest=exported['snapshot_digest'],
                             source_boot_id=exported['boot_id'], exported_packets=exported['snapshot']['state']['packets_total'],
                             exported_flow_bin_records=sum(len(b['flows']) for b in exported['snapshot']['state']['bins']))
                if digest(event['snapshot']) != event['snapshot_digest']:
                    raise StateTransferError('export digest mismatch')
                event['status'] = 'exported'
                self.save(event)
            expected = dict(event['original_assignments'])
            expected[bucket] = destination
            current = buckets.assignments()
            if current == event['original_assignments']:
                if event['p4_modify_calls']:
                    raise StateTransferError('P4 was already attempted; refusing another MODIFY for this ID')
                prepared = self.rpc(event, destination, 'prepare', snapshot=event['snapshot'])
                if prepared['snapshot_digest'] != event['snapshot_digest'] or prepared['status'] not in ('prepared', 'committed'):
                    raise StateTransferError('destination preparation proof differs')
                event.update(destination_boot_id=prepared['boot_id'], status='prepared')
                self.save(event)
                def guarded_write():
                    # Run the caller's own freshness/benefit guard first. Only once it
                    # passes do we journal "a write is about to be attempted" — right
                    # before BucketController.migrate sends the real MODIFY. This way a
                    # guard rejection never marks p4_modify_calls, so the transfer is not
                    # wrongly treated as "P4 was already attempted" and does not need to
                    # be aborted/retried under a new transfer ID.
                    if before_write is not None:
                        before_write()
                    event['p4_modify_calls'] += 1
                    event['status'] = 'p4_attempted'
                    self.save(event)
                # guarded_write is invoked exactly once, by BucketController.migrate itself
                # (core.py), immediately before the real switch write. It is called outside
                # this method's own try/except, and outside core.py's write try/except, so a
                # guard rejection keeps its original exception type (see the except clause
                # below) instead of being laundered.
                p4_started = time.monotonic()
                try:
                    BucketController(self.runtime, self.detectors).migrate(bucket, destination,
                        expected_assignments=event['original_assignments'], before_write=guarded_write)
                finally:
                    event['timings_seconds']['p4_transaction'] = time.monotonic()-p4_started
                event['status'] = 'p4_verified'
                self.save(event)
            elif current != expected:
                raise StateTransferError('ownership uncertain/unrelated assignments changed; reconcile manually')
            # An already-applied write is reconciled by actual readback, not retried.
            if self.pipeline_validator is not None:
                self.pipeline_validator()
            if buckets.assignments() != expected:
                raise StateTransferError('ownership differs before destination activation')
            status = self.rpc(event, destination, 'status')
            if status['boot_id'] != event['destination_boot_id'] or status['snapshot_digest'] != event['snapshot_digest']:
                raise StateTransferError('prepared destination restarted or changed')
            if status['status'] == 'prepared':
                self.rpc(event, destination, 'commit', owner=destination, ownership_digest=digest(expected))
            self.verify_destination(event)
            if buckets.assignments() != expected:
                raise StateTransferError('ownership changed after destination activation')
            source = self.rpc(event, event['source'], 'status')
            if source['boot_id'] != event['source_boot_id'] or source['snapshot_digest'] != event['snapshot_digest']:
                raise StateTransferError('source export restarted or changed; retained state not verified')
            self.rpc(event, event['source'], 'finalize', owner=destination, destination_digest=event['snapshot_digest'])
            if 'error' in event:
                event['recovered_from_error'] = event.pop('error')
            if event['cleanup_errors']:
                event['recovery_warnings'] = list(event['cleanup_errors'])
                event['cleanup_errors'] = []
            event.update(status='complete', completed_at=time.time())
            self.save(event)
            return True
        except Exception as exc:
            if event is not None:
                event['error'] = str(exc)
                try:
                    actual = BucketController(self.runtime, self.detectors).assignments()
                    event['reconciled_assignments'] = actual
                    if actual == event['original_assignments']:
                        # Only abort staging when actual full-table ownership is
                        # confirmed unchanged. Source history is never removed.
                        for name in (event['destination'], event['source']):
                            try:
                                self.rpc(event, name, 'abort')
                            except StateHTTPError as cleanup:
                                if cleanup.status != 404:
                                    event['cleanup_errors'].append(str(cleanup))
                            except Exception as cleanup:
                                event['cleanup_errors'].append(str(cleanup))
                        event['status'] = 'aborted'
                    else:
                        event['status'] = 'uncertain'
                except Exception as read_error:
                    event['status'] = 'uncertain'
                    event['cleanup_errors'].append('ownership readback: ' + str(read_error))
                self.save(event)
            # Only coerce genuine switch/transport failures (ControllerError and its
            # StateTransferError subclass) into StateTransferError. A guard rejection
            # (e.g. adaptive.py's TelemetryError raised from before_write) never reached
            # the switch, so it must keep its original exception type so callers that
            # branch on exception type (e.g. AdaptiveController.step's except TelemetryError)
            # see it correctly instead of a generic fault.
            if isinstance(exc, ControllerError):
                raise StateTransferError(str(exc)) from exc
            raise
        finally:
            self.lock.release()

    def abort(self, identifier):
        """Explicit recovery only while the full original table is still verified."""
        identifier = transfer_id(identifier)
        if not self.lock.acquire(blocking=False):
            raise StateTransferError('another transfer is in progress')
        try:
            event = json.loads((self.journal / (identifier + '.json')).read_text())
            original = {int(b): n for b, n in event['original_assignments'].items()}
            buckets = BucketController(self.runtime, self.detectors)
            if buckets.assignments() != original:
                raise StateTransferError('abort refused: actual ownership is not the original full table')
            for name in (event['destination'], event['source']):
                try:
                    self.rpc(event, name, 'abort')
                except StateHTTPError as exc:
                    if exc.status != 404:
                        raise
            if buckets.assignments() != original:
                raise StateTransferError('ownership changed during abort; inspect manually')
            event.update(status='aborted', aborted_at=time.time())
            self.save(event)
            return event
        finally:
            self.lock.release()


def make_coordinator(runtime, detectors, network_path, config):
    evidence = Path(config['attribution_evidence'])
    if not evidence.is_absolute():
        evidence = ROOT / evidence
    attribution = verify_evidence(evidence)
    expected_pipeline = digest(json.loads((ROOT / 'p4/dynohash.json').read_text()))
    validator = lambda: validate_live_pipeline(runtime, expected_pipeline)
    validator()
    return StateCoordinator(runtime, detectors, network_client(network_path, config), config, attribution,
                            pipeline_validator=validator)


def validate_live_pipeline(runtime, expected_digest):
    """Read only: refuse state transfer unless live device JSON is the verified one."""
    from p4.v1 import p4runtime_pb2 as pb
    request = pb.GetForwardingPipelineConfigRequest(device_id=runtime.device_id,
                    response_type=pb.GetForwardingPipelineConfigRequest.ALL)
    response = runtime.stub.GetForwardingPipelineConfig(request, timeout=runtime.timeout)
    try:
        if digest(json.loads(response.config.p4_device_config)) != expected_digest:
            raise ValueError('live pipeline differs from parity-verified JSON')
    except (ValueError, TypeError, UnicodeError) as exc:
        raise StateTransferError('cannot verify live bucket hash: ' + str(exc)) from exc
