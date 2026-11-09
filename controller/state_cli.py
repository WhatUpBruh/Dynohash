"""Inspect/reconcile a journaled transfer. Recovery never issues a fresh P4 MODIFY."""
import argparse
import json
from pathlib import Path

from .core import BucketController, ROOT, load_config
from .state_transfer import make_coordinator, StateTransferError
from detectors.bucket_state import load_state_config, transfer_id


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('status', 'reconcile', 'abort'))
    parser.add_argument('--transfer-id', required=True)
    parser.add_argument('--state-config', default=str(ROOT / 'config/checkpoint5.json'))
    parser.add_argument('--allow-state-mutations', action='store_true')
    args = parser.parse_args()
    config = load_state_config(args.state_config)
    identifier = transfer_id(args.transfer_id)
    directory = Path(config['journal_directory'])
    if not directory.is_absolute():
        directory = ROOT / directory
    record = json.loads((directory / (identifier + '.json')).read_text())
    if args.command == 'status':
        print(json.dumps(record, indent=2))
        return
    if not config['enabled'] or not args.allow_state_mutations:
        parser.error('recovery needs enabled state config and --allow-state-mutations')
    from .runtime import Runtime
    with Runtime() as runtime:
        coordinator = make_coordinator(runtime, load_config(), ROOT / 'config/dynohash.json', config)
        if args.command == 'abort':
            print(json.dumps(coordinator.abort(identifier), indent=2))
            return
        expected = {int(b): n for b, n in record['original_assignments'].items()}
        expected[record['bucket_id']] = record['destination']
        if BucketController(runtime, load_config()).assignments() != expected:
            raise StateTransferError('actual ownership is not the intended destination; no recovery write issued')
        coordinator.migrate(record['bucket_id'], record['destination'], transfer_id_value=identifier)
        print(json.dumps(coordinator.last_event, indent=2))


if __name__ == '__main__':
    main()
