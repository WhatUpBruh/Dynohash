"""Run with .venv/bin/python -m controller.cli."""
import argparse
import json
import sys
from .core import BucketController, ControllerError, load_config, ROOT
from .runtime import Runtime


def main(argv=None):
    parser = argparse.ArgumentParser(description='Manual live DynoHash bucket controller (never reloads pipeline)')
    parser.add_argument('--config', default=str(ROOT / 'config/dynohash.json'))
    parser.add_argument('--address', default='127.0.0.1:50051')
    parser.add_argument('--device-id', type=int, default=0)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('list')
    commands.add_parser('verify')
    show = commands.add_parser('show')
    show.add_argument('--bucket', type=int, required=True)
    migrate = commands.add_parser('migrate')
    migrate.add_argument('--bucket', type=int, required=True)
    migrate.add_argument('--to', choices=['d1', 'd2', 'd3'], required=True)
    args = parser.parse_args(argv)
    try:
        detectors = load_config(args.config)
        if args.command in ('show', 'migrate'):
            from .core import bucket_id
            bucket_id(args.bucket)
        with Runtime(args.address, args.device_id) as runtime:
            controller = BucketController(runtime, detectors)
            if args.command == 'list':
                print(json.dumps(controller.assignments(), indent=2, sort_keys=True))
            elif args.command == 'verify':
                controller.assignments()
                print('Verified all 64 live bucket assignments, including ports and MACs')
            elif args.command == 'show':
                print(f'{args.bucket}: {controller.owner(args.bucket)}')
            else:
                changed = controller.migrate(args.bucket, args.to)
                print(f'Bucket {args.bucket}: {args.to}; ' + ('migration verified; other 63 unchanged' if changed else 'already assigned; no-op'))
        return 0
    except Exception as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
