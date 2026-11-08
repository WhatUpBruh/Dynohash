"""P4Runtime protobuf/gRPC adapter. Never reloads the pipeline."""
import queue
import grpc
from p4.v1 import p4runtime_pb2 as pb, p4runtime_pb2_grpc
from .core import ControllerError


class Runtime:
    def __init__(self, address='127.0.0.1:50051', device_id=0, election_id=(0, 1), timeout=5):
        self.address, self.device_id = address, device_id
        self.election_id, self.timeout = election_id, timeout
        self.channel = None
        self.stream = None
        self.outgoing = queue.Queue()

    def __enter__(self):
        try:
            self.channel = grpc.insecure_channel(self.address)
            grpc.channel_ready_future(self.channel).result(timeout=self.timeout)
            self.stub = p4runtime_pb2_grpc.P4RuntimeStub(self.channel)
            def requests():
                while True:
                    item = self.outgoing.get()
                    if item is None:
                        return
                    yield item
            request = pb.StreamMessageRequest()
            request.arbitration.device_id = self.device_id
            request.arbitration.election_id.high, request.arbitration.election_id.low = self.election_id
            self.outgoing.put(request)
            self.stream = self.stub.StreamChannel(requests(), timeout=3600)
            # Bound the initial arbitration wait without imposing a short session lifetime.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(next, self.stream)
                try:
                    response = future.result(timeout=self.timeout)
                except concurrent.futures.TimeoutError:
                    self.stream.cancel()
                    raise ControllerError('arbitration timed out')
            if not response.HasField('arbitration') or response.arbitration.status.code != 0:
                raise ControllerError('not primary: close existing P4Runtime shell/controller; do not increase election ID to preempt it')
            request = pb.GetForwardingPipelineConfigRequest(device_id=self.device_id, response_type=pb.GetForwardingPipelineConfigRequest.P4INFO_AND_COOKIE)
            self.info = self.stub.GetForwardingPipelineConfig(request, timeout=self.timeout).config.p4info
            self.table = next(t for t in self.info.tables if t.preamble.name == 'MyIngress.bucket_to_detector')
            self.action = next(a for a in self.info.actions if a.preamble.name == 'MyIngress.forward_to_detector')
            self.key = next(m for m in self.table.match_fields if m.name == 'meta.bucket_id')
            if self.key.bitwidth != 6 or len(self.table.match_fields) != 1 or {p.name: p.bitwidth for p in self.action.params} != {'port': 9, 'detector_mac': 48}:
                raise ControllerError('incompatible live P4Info')
            return self
        except Exception as exc:
            self.__exit__(None, None, None)
            detail = str(exc) or type(exc).__name__
            raise ControllerError(f'P4Runtime connection failed at {self.address}: {detail}') from exc

    def __exit__(self, *_):
        self.outgoing.put(None)
        if self.stream is not None:
            self.stream.cancel()
        if self.channel is not None:
            self.channel.close()

    def read(self, entity):
        request = pb.ReadRequest(device_id=self.device_id)
        request.entities.append(entity)
        for response in self.stub.Read(request, timeout=self.timeout):
            yield from response.entities

    def read_buckets(self):
        entity = pb.Entity()
        entity.table_entry.table_id = self.table.preamble.id
        for entity in self.read(entity):
            entry = entity.table_entry
            if entry.is_default_action:
                continue
            if len(entry.match) != 1 or entry.match[0].field_id != self.key.id or entry.match[0].WhichOneof('field_match_type') != 'exact' or entry.action.action.action_id != self.action.preamble.id:
                raise ControllerError('unexpected bucket entry schema or action')
            params = {p.param_id: int.from_bytes(p.value, 'big') for p in entry.action.action.params}
            if len(params) != 2 or len(entry.action.action.params) != 2:
                raise ControllerError('invalid action parameters')
            values = {p.name: params[p.id] for p in self.action.params}
            mac = values['detector_mac'].to_bytes(6, 'big').hex(':')
            yield int.from_bytes(entry.match[0].exact.value, 'big'), values['port'], mac

    def modify_bucket(self, bucket, port, mac):
        request = pb.WriteRequest(device_id=self.device_id)
        request.election_id.high, request.election_id.low = self.election_id
        update = request.updates.add(type=pb.Update.MODIFY)
        entry = update.entity.table_entry
        entry.table_id = self.table.preamble.id
        match = entry.match.add(field_id=self.key.id)
        match.exact.value = bucket.to_bytes(1, 'big')
        entry.action.action.action_id = self.action.preamble.id
        values = {'port': port, 'detector_mac': int(mac.replace(':', ''), 16)}
        for param in self.action.params:
            entry.action.action.params.add(param_id=param.id, value=values[param.name].to_bytes((param.bitwidth + 7) // 8, 'big'))
        self.stub.Write(request, timeout=self.timeout)

    def counters(self):
        counter = next(c for c in self.info.counters if c.preamble.name == 'MyIngress.bucket_counter')
        entity = pb.Entity()
        entity.counter_entry.counter_id = counter.preamble.id
        return {e.counter_entry.index.index: e.counter_entry.data.packet_count for e in self.read(entity)}
