# Checkpoint 2: manual bucket migration

Status: PARTIALLY PASSED. Controller unit tests pass. Live migration is unverified:
the execution sandbox cannot connect to the endpoint and prevents privilege elevation
(`sudo`: no new privileges). No live migration, continuous BMv2 uptime, or restoration
is claimed. The checkout has no Git metadata, so `git diff` is unavailable.

## Architecture

`controller/core.py` validates configuration and implements the migration transaction.
`controller/runtime.py` uses the installed p4runtime protobufs and grpcio, reads the
**live** P4Info, discovers table/action/parameter IDs, and owns a bounded connection
and arbitration lifecycle. It never loads a pipeline. `controller/cli.py` provides
short-lived commands. Configuration paths resolve relative to the repository, not cwd.
No dependencies were upgraded. P4, compiled artifacts, topology and detector were
not changed.

The controller requires the existing 64 exact-match entries. It validates every
entry's port and destination MAC against config, rejects incomplete/duplicate or
unknown entries, and performs one P4Runtime MODIFY (never INSERT) for a migration.
It reads the full table afterward and compares against the original snapshot with
only the target changed. A no-op performs a validated read and no write.
Errors after writes mean the live state may have changed; inspect before retrying.
There is deliberately no automatic rollback against potentially concurrent edits.

Election ID is `(0, 1)`. Close any existing P4Runtime shell/controller first. An
existing equal/higher election prevents access; the controller refuses backup status.
Do not raise the election ID to force takeover. A controller with a higher ID could
still preempt this client; BMv2 rejects unauthorized writes. Readback detects changes
observed during migration, but does not provide locking or a consistent transactional
snapshot. Use a single writer; low fixed IDs cannot detect another lower-ID writer.
The channel is insecure localhost gRPC, appropriate only for the local VM lab.

## CLI and unit tests

From `~/dynohash`:

```bash
.venv/bin/python -m controller.cli list
.venv/bin/python -m controller.cli show --bucket 9
.venv/bin/python -m controller.cli migrate --bucket 9 --to d2
.venv/bin/python -m controller.cli verify
.venv/bin/python -m unittest discover -s tests/controller -v
.venv/bin/python -m compileall -q controller tests/controller tests/topology/checkpoint2_migration.py tools/initialize_checkpoint2.py
```

Global options `--config`, `--address`, and `--device-id` precede the subcommand.
Commands return nonzero on failure, including failed readback.

## Real integration test on the VM

The harness is provided but has not been validated on a running topology. It requires
root Mininet host namespace access, tcpdump and the existing virtual environment.
Reuse the working topology when available. Do not run `mn -c` or start a second
copy against existing interfaces. Close the P4Runtime shell, leaving Mininet/BMv2 up.

If no topology exists, start one in terminal A (this explicitly creates network
interfaces and a management bridge; review before running with sudo):

```bash
cd ~/dynohash
sudo /usr/bin/python3 tests/topology/dynohash_detectors.py
```

Only for this NEW empty switch, initialize the pipeline and round-robin assignments
in terminal B. This explicit provisioning command reloads the pipeline; never use
it against the existing working switch or during the migration test:

```bash
cd ~/dynohash
PYTHONPATH=. .venv/bin/python tools/initialize_checkpoint2.py --new-empty-switch
.venv/bin/python -m controller.cli verify
```

In the existing Mininet CLI in terminal A run:

```text
py __import__('runpy').run_path('/home/dynohash/dynohash/tests/topology/checkpoint2_migration.py')['exercise'](net)
```

The harness invokes the venv controller from the root Mininet process. It records
all initial assignments, sends ten raw Ethernet UDP packets with five-tuple
`10.0.0.1:40009 -> 10.0.1.100:9000, protocol 17`, and uses actual per-bucket counter
deltas to identify the bucket (no assumed CRC implementation). It requires exactly
one counter to increase by ten. Isolate other traffic during discovery.

It captures matching traffic on all three `d*-eth0` interfaces, verifies the initial
owner, migrates to another detector, verifies all 64 assignments, sends the identical
flow, checks ten packets only at the new detector and checks rewritten Ethernet MACs.
In `finally` it restores the original owner, verifies all original assignments and
sends again. BMv2 PID equality is checked across the test. Capture output, counter
deltas, assignments and restoration outcome go to `logs/checkpoint2-integration.json`.
No BMv2 restart or pipeline reload occurs in the harness. A crash or lost connection
can prevent restoration; consult recorded initial assignments and restore with CLI.

Preserve terminal output too if a failure interrupts evidence collection:

```bash
script -a logs/checkpoint2-terminal.txt
```

Start this terminal recording before launching or attaching to the Mininet CLI.
A full pass requires JSON status PASSED, successful initial/migrated/restored packet
captures, identical before/after switch PIDs and restored=true. Unit tests alone do
not establish Checkpoint 1 preservation or Checkpoint 2 completion.

## Limitations and Peer 3

This changes forwarding only. It has no detector-state transfer, automatic load
balancing, detector algorithm or telemetry API. Peer 3 should call the validated
migration service through a single serialized writer, define ownership/state transfer
ordering and failure recovery, coordinate telemetry collection and stabilize load
measurements before adding policy. Repeated table reads are not atomic snapshots.
Pipeline installation and initial assignments are separate provisioning operations.
