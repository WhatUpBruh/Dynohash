"""Explicit initialization for a NEW, empty disposable topology only.
Reloads pipeline; never invoke against a working Checkpoint 1 switch.
"""
import argparse
from controller.core import ROOT, load_config
from controller.runtime import Runtime
from p4.v1 import p4runtime_pb2 as pb
from p4runtime_sh import shell

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--new-empty-switch', action='store_true', required=True)
parser.parse_args()
shell.setup(device_id=0, grpc_addr='127.0.0.1:50051', election_id=(0, 1),
            config=shell.FwdPipeConfig(str(ROOT / 'p4/dynohash.p4info.txt'), str(ROOT / 'p4/dynohash.json')))
shell.teardown()
with Runtime() as runtime:
    # Build INSERT requests with the same wire encoding as MODIFY, only for initial provisioning.
    original_write = runtime.stub.Write
    def insert(request, **kwargs):
        request.updates[0].type = pb.Update.INSERT
        return original_write(request, **kwargs)
    runtime.stub.Write = insert
    detectors = load_config()
    for bucket in range(64):
        runtime.modify_bucket(bucket, *detectors[f'd{bucket % 3 + 1}'])
