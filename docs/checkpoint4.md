# Checkpoint 4: adaptive load evaluation and bucket migration

## Repository audit and implementation plan

Branch verified: feature/checkpoint4-adaptive-controller. Working tree was clean
before this checkpoint. User confirms Checkpoints 1–3 passed live; earlier audit
limitations remain historical in their original documents and evidence.

Existing interfaces reused:
- `BucketController.assignments()`: validates all 64 ownership entries against config.
- `BucketController.migrate()`: one MODIFY and complete table readback; no pipeline load.
- `Runtime.counters()`: bucket -> cumulative packet count through existing P4Runtime.
- Collector GET `/api/v1/telemetry`: `servers[id]` contains telemetry, age_seconds and
  stale. Reuse `detectors.telemetry.validate` for the existing v1 payload schema.
- Existing topology: root bridge 172.18.50.1, detector dN-mgmt0 vs data dN-eth0.

Integration gaps: detector per_bucket remains null (CRC parity is not established);
use live switch counter deltas instead. Counter width is not advertised by the
existing adapter; do not assume wrapping by default. Detector histories are local,
so live mode must require explicit acceptance of detection discontinuity. The manual
migration transaction needs an optional expected-assignment guard to reject a changed
decision baseline before any write, while preserving existing API calls.

Implementation sequence: validated polling client; pure counter/load/selection logic;
bounded coordinator/CLI defaulting to dry run; fakes plus real local HTTP regression;
existing-topology live harness with explicit write opt-in and finally restoration;
full Checkpoint 2/3 regressions and documented evidence. No P4 or detector rewrite,
new service API, pipeline provisioning, state transfer or external dependencies.

## Architecture and files

`detector capture -> existing collector -> TelemetryClient -> AdaptiveController`

`existing P4Runtime -> ownership + counter snapshots -> bucket PPS -> prediction`

`confirmed live decision -> BucketController.migrate -> one MODIFY -> full readback`

Added files:
- `controller/telemetry_client.py`: bounded GET, proxies/redirects disabled, existing
  v1 payload validator reused; checks each wrapper's identity, age and freshness.
- `controller/adaptive.py`: counter sampling, sustained/hysteretic evaluation,
  candidate scoring, cooldowns, write-boundary checks and fault handling.
- `controller/adaptive_cli.py`: bounded JSON-lines loop, normal-election Runtime
  lifecycle, signal handling, explicit live flags. No new telemetry/controller API.
- `config/checkpoint4.json`: separate adaptive settings.
- `tests/adaptive/test_adaptive.py`: deterministic fakes, safe restoration tests and
  real localhost sender -> existing collector -> adaptive-reader integration.
- `tests/topology/checkpoint4_adaptive.py`: existing-topology harness, discovery by
  counters, packet-delivery checks, service ownership and structured reports.
- `tests/topology/checkpoint4_worker.py`: test-only venv subprocess holding ONE normal
  P4Runtime session, so Mininet's system Python need not import grpc. Calls the same
  production policy and transaction, plus guarded test restoration.

Modified `controller/core.py` only adds two optional keyword guards to `migrate`:
`expected_assignments` rejects a changed baseline, and `before_write` runs after the
last ownership read but before MODIFY. Existing two-argument calls are unchanged.
The automatic path uses both. `AGENTS.md` records current progress. Test evidence
is under `logs/checkpoint4-*`; Checkpoint 2/3 evidence/documents remain untouched.
No changes to P4, compiled artifacts, runtime adapter, manual CLI or detectors.
No packages installed: new code uses the standard library and existing grpc/protobufs.

## Telemetry and sustained overload

Load is **observed packet_rate_pps**, not CPU utilization, queue occupancy or proof
of DDoS. Require exactly d1/d2/d3 with valid required v1 fields, matching server IDs,
finite nonnegative rates, sufficient detector window, valid timestamp/collector age,
and fresh readings. Unknown CPU/queue/drop/per_bucket values remain null in status.
A missing packet rate cannot be replaced by zero. Require both local timestamp age
and collector age <=3 seconds; reject stale flags even when the timestamp looks new.
Check timestamps are not too far in the future and within the configured inter-server
skew. Decreasing timestamps/process totals invalidate the interval (possible restart),
clear sustained history and require a new baseline and sustained evaluation.

For loads L, define `gap = max(L)-min(L)` and
`ratio = gap / max(mean(L), 1 PPS)`. Enter an imbalance episode only when both entry
thresholds hold. Retain it through the hysteresis band; exit if either exit threshold
is reached. The most/least-loaded pair must stay the same throughout the sustained
period. Missing/stale/invalid inputs clear sustained history. A single burst cannot
trigger immediately. Balanced traffic and idle traffic produce no migration.

Each JSON status includes mode, Unix-second timestamp, status, reason, per-detector
load/age/freshness and unknown metrics. Once sampled it also includes bucket PPS,
gap, ratio, sustained duration, candidate source/destination/bucket, predicted loads,
expected improvement and action count. Statuses:
- `inhibited`: warmup, balanced, pending sustained interval, stale input, limits,
  settling, invalid sample or insufficient benefit; no write.
- `proposed`: dry-run candidate; no write.
- `migrated`: one actual MODIFY with full ownership readback verified.
- `fault`: inconsistent state or runtime/transaction failure; latched, stop and inspect.

GET responses are capped at 1 MiB and parsed with duplicate-key rejection. Each
request has a socket timeout. The bounded loop retains only one prior snapshot,
three last readings and at most 64 per-bucket cooldown entries. Output can be
redirected to an operator-owned JSONL file; no unbounded in-process event history.

## Bucket PPS and candidate choice

Read ownership, all counters, and ownership again under the existing Runtime.
Reject a changed table, excessive read duration or any missing/invalid counter.
For two monotonic timestamps, `bucket_pps = (new_count-old_count)/elapsed_seconds`.
Require the same ownership throughout the interval and a supported positive duration.
A decrease with unknown width is a reset/unproven wrap: inhibit and rebaseline.
No width is inferred from protobuf storage type. If the operator supplies a *known*
width, permit only a high-quarter -> low-quarter wrap with a plausible PPS bound;
reject intervals whose maximum possible traffic allows multiple wraps. Small decreases
are treated as resets, not wraps. A reset that overtakes its previous value cannot
be distinguished from normal increase using two samples alone.
Even a known width cannot distinguish a reset at the wrap boundary from a genuine
wrap. Opting into known-width wrap handling assumes no resets during that interval;
leave counter_bits=null for conservative rejection of every observed decrease.

Reject implausible bucket rates and large disagreement between each owner's summed
counter PPS and detector PPS. Their windows differ: counters use the last polling
interval, detectors use a rolling aligned window, so agreement has explicit tolerance.
Only nonidle buckets owned by the most-loaded detector and outside cooldown qualify.
Predict subtracting that bucket's observed PPS from source and adding it to the
least-loaded detector. Reject negative predictions or insufficient global gap reduction.
Choose greatest improvement, then smaller bucket PPS, then bucket ID as deterministic
ties. IDs alone never determine which active bucket to move.

Example: loads d1=900, d2=300, d3=100 PPS, gap=800. Moving d1's 300-PPS bucket to d3
predicts 600/300/400, gap=300, improvement=500 PPS. Moving a 600-PPS bucket predicts
300/300/700, gap=400, improvement=400. Choose the 300-PPS bucket. An idle bucket or a
900-PPS bucket is rejected. Flow affinity remains bucket-based; an indivisible large
bucket can make perfect balance impossible.

This does NOT establish Python CRC32 parity. Switch counters directly measure bucket
traffic; the live harness discovers each test tuple's bucket by isolated real counter
deltas. Detector per_bucket stays null. Rates are observations, not guarantees about
future demand, equal packet cost, CPU capacity or capture loss. Counter reads are
not atomic; bounded read duration and tolerances limit, but do not eliminate, skew.

## Configuration defaults

All settings are in `config/checkpoint4.json`. Strict key validation catches typos.

| Parameter | Default | Meaning |
| --- | --- | --- |
| collector_url | http://172.18.50.1:8080/api/v1/telemetry | Existing collector GET URL |
| poll_seconds | 1 | Poll/decision cadence (0.1..10 seconds) |
| http_timeout_seconds | 0.5 | HTTP socket timeout (0.05..2 seconds) |
| max_telemetry_age_seconds | 3 | Freshness ceiling, cannot exceed collector's 3 seconds |
| future_tolerance_seconds | 0.25 | Maximum allowed future clock skew (0..1 seconds) |
| max_timestamp_skew_seconds | 1.5 | Maximum difference among detector timestamps |
| minimum_window_seconds | 3 | Minimum producer window before trusting its rate |
| imbalance_enter_ratio / exit_ratio | 0.25 / 0.15 | Relative entry/exit hysteresis |
| imbalance_enter_pps / exit_pps | 100 / 50 | Absolute gap entry/exit hysteresis |
| sustained_seconds | 5 | Continuous same-pair imbalance required |
| minimum_bucket_pps | 1 | Ignore idle/negligible buckets |
| minimum_improvement_pps | 50 | Minimum predicted reduction of global load gap |
| minimum_improvement_fraction | 0.05 | Also require 5% of original gap improvement |
| bucket_cooldown_seconds | 60 | Minimum time between decisions for the same bucket |
| global_cooldown_seconds | 10 | Minimum time between actions/proposals |
| settling_seconds | 6 | Minimum post-action detector settling period |
| minimum_counter_seconds / maximum_counter_seconds | 0.2 / 10 | Valid counter sample separation |
| maximum_read_seconds | 1 | Maximum switch read span / final estimate age |
| maximum_bucket_pps | 10000000 | Plausibility bound; also constrains wrap ambiguity |
| counter_bits | null | Unknown; decreases invalidate the sample by default |
| load_tolerance_fraction / load_tolerance_pps | 0.5 / 100 | Allowed owner counter/telemetry difference: larger of the two |
| max_migrations | 1 | Maximum actions/proposals per process (1..100) |

Use `--config` with a separate JSON file to tune. Cooldowns use monotonic seconds.
After an action, wait at least `max(settling_seconds, reported_window_seconds) +
max_telemetry_age_seconds` before another action, so old ownership contributions have
time to leave telemetry. A new sustained episode is still required. Dry-run proposals
consume the same budget/cooldowns to avoid logging repeated moves every poll.
Cooldowns/budgets are process-local, not persistent across restarts; do not restart
controllers to evade them. Share single-writer ownership and deployment discipline.

## Running the controller

Use the already programmed topology and running Checkpoint 3 services. Collector is
on management bridge 172.18.50.1, not detector localhost. See Checkpoint 3 startup
instructions if services are missing. Do not start a second topology or initialize
an existing switch. Close other P4Runtime shells/controllers first.

Regular VM terminal, repository cwd, default dry-run:

```bash
cd ~/dynohash
.venv/bin/python -m controller.adaptive_cli --iterations 60
```

Explicit live automatic migration, at most one by default:

```bash
.venv/bin/python -m controller.adaptive_cli --iterations 60 --live --acknowledge-state-loss
```

Other options: `--config`, `--network-config`, `--address`, `--device-id`.
Iterations are bounded to 1..10000. Signals request shutdown at a loop boundary;
an already executing operation must reach its safe completion/failure path. Runtime
uses the existing election ID (0,1), never raises it to seize a higher/equal controller,
and closes its session on exit. CLI exits 1 on fault and 2 for argument errors.
Exit 0 means the bounded loop completed, not proof that telemetry was good or a
migration happened; inspect statuses/reasons. Inhibited iterations keep polling.

### Live safety gate and failure handling

Both `--live` and `--acknowledge-state-loss` are required. The latter explicitly
accepts that **detector flow/alert history is not transferred**. Mid-window migration
can split observations, reset destination flow knowledge and affect alert continuity.
This is suitable only where that risk is acceptable (the VM lab/stateless workloads).
There is no exactly-once handoff or assurance of uninterrupted detection. Coordinate
with the detection-server owner before enabling this on stateful production traffic.

At most one MODIFY is possible per decision. Before it, refresh telemetry and the
switch snapshot, recompute benefit and verify the same candidate/pair remains best.
The transaction then re-reads all assignments, requires the expected baseline, and
calls the final freshness/estimate-age/benefit guard immediately before writing.
It verifies all 64 assignments afterward; the adaptive layer checks them again.
Unrelated entries must match the expected table. Arbitration loss or write rejection
fails closed; the server enforces election authorization even if ownership changes
between our checks. There is no atomic lock against external writers: never run two.

Write errors/readback mismatches can mean the write applied: latch a fault, exit,
inspect `controller.cli list/verify` and captured evidence, and restore manually as
appropriate. No production retry/rollback can silently overwrite another operator.
Telemetry outages/invalid counter intervals instead inhibit, clear sustained history
and rebaseline before further consideration. No path loads a pipeline, INSERTs an
entry, restarts BMv2 or reconfigures an interface.

## Existing-Mininet end-to-end procedure

From a regular terminal, safe prerequisite inspection only:

```bash
cd ~/dynohash
.venv/bin/python tests/topology/checkpoint4_adaptive.py --check-environment
```

Run the following in the **existing root Mininet CLI**, leaving BMv2 and its current
64 assignments running. Close other P4Runtime writers; isolate unrelated data-plane
traffic. There must be at least two discoverable buckets on every detector for the
harness pattern. It does not change the initial distribution to make the test pass.

First dry-run test (no switch writes):

```text
py __import__('runpy').run_path('/home/dynohash/dynohash/tests/topology/checkpoint4_adaptive.py')['exercise'](net)
```

Then, if you explicitly accept temporary migration and detection-state discontinuity:

```text
py __import__('runpy').run_path('/home/dynohash/dynohash/tests/topology/checkpoint4_adaptive.py')['exercise'](net, live=True, acknowledge_state_loss=True)
```

An alternate existing/free collector port can be selected with `port=8081`; existing
detectors must publish there or the test reports BLOCKED instead of restarting them.
The harness reuses a valid collector and identifiable detector processes in the correct
namespaces. It starts only missing services and stops only children it created.
Conflicting/duplicate/unidentifiable services are not killed. It checks dN-mgmt0 routes
and real HTTP reachability from each namespace. If a writer owns the device, the
normal-election worker refuses access; never raise election IDs to force the test.

The test then:
1. Validates the live P4Runtime schema, all 64 assignments/counters, same BMv2 PID,
   fresh telemetry and an idle data plane before probing.
2. Sends isolated fixed Ethernet IPv4/UDP tuples (source ports 42000..42127,
   destination 10.0.1.100:9002) and reads actual deltas to discover buckets. No
   approximate hash or preselected bucket ID is used.
3. Uses distinct discovered buckets to send reproducible balanced traffic (150 PPS
   per detector), checks exact finite-burst capture/counter agreement, then requires
   validated balanced dry decisions with zero proposals/migrations.
4. Sends an imbalanced pattern: d1 two buckets at 600+300 PPS, d2=300, d3=100.
   After rolling windows settle, requires a beneficial dry proposal and unchanged table.
5. Only in live-test mode, runs the same policy with opt-in and a one-migration budget,
   verifies target and all unrelated ownership, then sends a new finite burst through
   the same discovered tuples. Requires exact per-bucket sent/counter counts and
   per-detector captured totals at the new owners, ruling out observed misrouting/loss.
6. Stops owned streams, restores the original assignment through the existing
   transaction and complete readback, and compares BMv2 PIDs. Finally restoration
   runs even after a parent assertion/error, with cleanup errors recorded separately.

The harness uses test-only sustained duration 2 seconds and minimum improvement
30 PPS; production defaults remain unchanged. Actual packet counts/timing, telemetry,
all decisions, discovery mappings and before/after tables are recorded. Test streams
have a finite 90-second maximum lifetime and are stopped on normal/error cleanup.
No standalone traffic generator or forwarding application is added.

Each run writes a unique `logs/checkpoint4-*/report.json` plus service/stimulus logs,
settings and `worker-report.json`. The **parent report** is the test result; the worker
report describes only worker lifecycle/restoration. Parent status is PASSED only when
all requested assertions complete; dry-mode PASSED does not verify live migration
(`verified_live_migrations=0`). Live pass requires exactly one verified migration,
post-move delivery, full restoration and unchanged PIDs, with no cleanup errors.

Restoration will NOT overwrite unrelated or unexpected-owner changes. If an external
writer violates exclusivity or primary ownership is lost, it may fail and must be
reported as FAILED with cleanup errors, never hidden. Abrupt root-process kill,
connection loss or interruption of an in-flight write can prevent restoration; preserve
the report and inspect all assignments before retrying. No destructive `mn -c`, net.stop,
interface cleanup or pipeline reinitialization is performed by this harness.

## Automated verification and actual evidence

```bash
cd ~/dynohash
.venv/bin/python -m unittest discover -s tests/adaptive -v
.venv/bin/python -m unittest discover -s tests/controller -v
.venv/bin/python -m unittest discover -s tests/detectors -v
.venv/bin/python -m compileall -q controller detectors tests/controller tests/detectors tests/adaptive tests/topology/checkpoint2_migration.py tests/topology/checkpoint3_detection.py tests/topology/checkpoint4_adaptive.py tests/topology/checkpoint4_worker.py tools/initialize_checkpoint2.py
git diff --check
```

Current automated results: **44 Checkpoint 4 tests passed**, **23 existing Checkpoint 2
controller tests passed**, **26 Checkpoint 3 tests passed**; zero final failures/errors
(93 total). Syntax and whitespace checks pass. Local HTTP tests ran outside the
sandbox with approval because socket creation is blocked inside it. They use the
real existing collector and sender plus fake switch/telemetry inputs: they do not
prove live packet capture. Restoration tests inject failures after a fake migration
and verify restoration or separately reported cleanup failure. No live switch state
was touched by automated tests. Test output/summary files are saved separately as
`logs/checkpoint4-unit-tests.txt`, `checkpoint4-controller-tests.txt`,
`checkpoint4-detector-tests.txt`, and `checkpoint4-validation.json`.

Live Checkpoint 4: **LIVE NOT VERIFIED — BLOCKED**. Approved read-only inspection
outside the sandbox returned exit 2, uid 1000, no dh-mgmt-br and no visible BMv2:

```json
{
  "status": "BLOCKED",
  "reasons": [
    "Mininet host namespace access requires the existing root Mininet CLI",
    "management bridge unavailable: Device \"dh-mgmt-br\" does not exist.",
    "no visible running BMv2 simple_switch_grpc process"
  ],
  "uid": 1000,
  "bridge": "",
  "switch_pids": []
}
```

No privileged live exercise, automatic migration or restoration was run here. The
user-confirmed Checkpoint 1/2/3 baseline is retained; it is not evidence that the new
Checkpoint 4 live harness has passed. Send both new parent reports and logs from the
existing VM session for review. No commit, push, merge or branch change was made.

## Checkpoint 5 and teammate handoff

Coordinate a portable, versioned per-bucket detection-state model and ownership
handoff with the detection-server owner before claiming state-preserving migration.
Decide how to establish exact bucket attribution, serialize portable ages/cooldowns,
handle losses/duplicates, coordinate writers and recover failed handoffs. None of
that state transfer is implemented here. CPU/queue/drop telemetry remains unknown;
packet PPS balances traffic count rather than computational cost. Further work needs
live workload calibration, durable cooldown/audit state, authenticated telemetry and
production concurrency/failure protocols. There is no dashboard, ML or new detector
algorithm in this checkpoint.
