# Checkpoint 3: detector and telemetry

Current verification is recorded in [the audit below](#audit-after-the-live-migration-recheck).
The manual migration recheck is PASSED according to the user's live report; this
does not establish a Checkpoint 3 capture/telemetry pass. The audit fixed one
confirmed stale-data defect and reran safe local tests.

## Architecture inspected before implementation

The existing P4 v1model pipeline hashes IPv4 TCP/UDP five-tuples into 64 buckets,
counts packets/bytes and rewrites Ethernet addresses toward d1/d2/d3 on ports
2/3/4. It rejects IPv4 options and fragments. Packets do not carry bucket metadata.
The existing detector uses Scapy sniff on a data interface and an unbounded flow
set. The controller validates all assignments and verifies manual migration by
full-table readback. These forwarding/controller components will remain unchanged.

The existing topology provides d1/d2/d3 data interfaces and separate management
interfaces at 172.18.50.11/.12/.13, connected to root bridge 172.18.50.1/24.
This supports collector HTTP without routing telemetry through the P4 pipeline.
Namespace routes and actual reachability still require verification on the VM.

Historical evidence: logs/checkpoint2-integration.json records PASSED, bucket 59,
d3 -> d1 -> d3, with matching capture counts and restoration. The user's live
confirmation supersedes the older blocked narrative in docs/checkpoint2.md;
that historical document and evidence are preserved.

Python/BMv2 CRC32 parity is not established by existing code or that single flow.
Checkpoint 3 therefore reports per_bucket=null, never guessed bucket attribution.

## Implementation and files

- `detectors/minimal_detector.py`: retains `--server-id` and `--interface` (and
  direct script invocation); replaces repeated Scapy sniff calls with one persistent
  Linux AF_PACKET receive socket. It accepts incoming switch-origin Ethernet frames
  addressed to that detector, validates IPv4 TCP/UDP headers, and never transmits.
  A separate thread publishes snapshots; slow/unavailable HTTP does not perform
  network I/O while holding the capture/statistics lock. SIGINT/SIGTERM stop capture
  and the sender. CLI summary output is now JSON rather than the old text summary.
- `detectors/statistics.py`: validated configuration, rolling packet/byte/flow/source
  statistics, heuristic state and capped alert history. No controller dependency.
- `detectors/telemetry.py`: version 1 schema validation and HTTP sender. Explicitly
  bypasses inherited HTTP proxies to keep management requests on the local route.
- `detectors/collector.py`: standard-library HTTP API and bounded in-memory storage.
- `config/checkpoint3.json`: detector settings, separate from forwarding config.
- `tests/detectors/test_checkpoint3.py`: focused unit tests and real localhost HTTP.
- `tests/topology/checkpoint3_detection.py`: live harness for the existing Mininet
  session, plus read-only prerequisite inspection and optional Checkpoint 2 recheck.
- `AGENTS.md`: progress and boundaries. This document: architecture, contract,
  commands, evidence and limitations.

No packages were installed. Runtime requires Python 3.10+ on Linux and only the
standard library; raw capture requires existing root/CAP_NET_RAW privileges inside
Mininet. Scapy is no longer required by the detector. Existing controller/live test
requirements remain unchanged. No P4, compiled pipeline, forwarding configuration,
controller module, existing topology or Checkpoint 2 harness was edited.

## Data flow and measurement

`h1 -> BMv2 -> dN-eth0 -> receive socket -> bounded statistics -> heuristic -> snapshot`

`dN-mgmt0 -> management bridge 172.18.50.1:8080 -> collector validation -> recent storage`

Only unfragmented IPv4 with IHL=5 and well-formed TCP/UDP headers is counted.
The source Ethernet MAC must be `02:00:00:00:00:01`; destination must match the
configured detector MAC. Outgoing frames are ignored. Captured five-tuples contain
source IP, destination IP, source port, destination port, numeric IP protocol (6/17).
The receiver does not enable promiscuous mode or change interfaces/routes. The kernel
socket buffer is separate from HTTP; there is no application work queue.

Statistics use monotonic time and one-second aligned bins. With window size W,
the window starts at `max(process_start, floor(now)-W+1)` and ends at now.
The actual duration is reported in `window_seconds`, with a 1ms startup floor.
After warmup, the default W=5 covers **4 to less than 5 seconds**, not an exact
sliding five-second interval. Rates divide counts by this actual duration. Each
packet contributes captured Ethernet length including padding, excluding FCS.
`byte_rate_bps` uses **bits per second** (8 times Ethernet bytes / elapsed seconds).
Idle publishers expire old bins and report zero current rates/flows/sources while
process lifetime totals stay unchanged. No raw packet contents are retained.

Each bin holds exact observed packet/byte counts and capped identity counters:
default maximum 4096 flows and 1024 sources per bin. Snapshot identity aggregates
are capped at those same limits. `tracking_limited=true` means flow uniqueness and
source counts are lower bounds; global observed packet/byte counts remain intact.
Expired identities leave the window. State is bounded by W bins and 32 alerts,
independent of packet count. Max supported W=60, max flows=4096, max sources=1024.
These are observation statistics, not guarantees that all switch traffic was seen.

## Heuristic configuration

Defaults in `config/checkpoint3.json`:

| Setting | Default | Meaning |
| --- | --- | --- |
| `window_seconds` | 5 | Number of one-second bins, integer 2..60 |
| `threshold_pps` | 1000 | Flag only when measured packet rate is strictly greater |
| `minimum_window_seconds` | 3 | Require this observed duration before detection |
| `minimum_packets` | 100 | Require this many packets in the current window |
| `cooldown_seconds` | 10 | Minimum monotonic interval between new alerts |
| `max_flows` | 4096 | Maximum retained flow identities per bin and snapshot |
| `max_sources` | 1024 | Maximum retained sources per bin and snapshot |
| `publish_seconds` | 1 | HTTP publication interval; supported range 0.1..3 |
| `http_timeout_seconds` | 0.5 | HTTP socket timeout; supported range 0.05..2 |
| `collector_url` | `http://172.18.50.1:8080/api/v1/telemetry` | Management endpoint |

All numeric settings must be positive and finite. Counts/capacities above are
integers; minimum duration must be <= W-1 so it fits the shortest mature window.
Use an alternate JSON file with `--config`; forwarding config is unchanged.

`suspicious` remains true while rate and minimum requirements hold, including during
cooldown. Only creation of new alerts is suppressed by cooldown. Old alerts remain
in the capped history even when current traffic is normal. This is a traffic-volume
heuristic, **not proof of DDoS**: legitimate bursts can alert, distributed or low-rate
attacks can evade it, and capture losses can hide high traffic. Thresholds need VM
measurements and workload-specific tuning. Defaults are lab starting values.

## Telemetry v1 contract

POST `/api/v1/telemetry`, `Content-Type: application/json`, one `Content-Length`.
No chunked request bodies. Success: 202 `{"accepted":true}`. Invalid fields,
malformed/truncated JSON, duplicate JSON keys, unsupported content types, stale beyond
60 seconds, future/out-of-order timestamps: 400 JSON error. Body limit is 262144 bytes;
empty/oversized declared bodies return 413. Unknown paths return 404. NaN, infinity,
booleans used as numbers, unknown fields and negative measurements are rejected.
Finite numeric measurements are capped at 1e18 (CPU additionally capped at 100).

| Field | Type/nullability | Units and source |
| --- | --- | --- |
| `server_id` | required string | One configured ID: d1, d2, d3 |
| `timestamp` | required number, non-null | Unix UTC seconds at snapshot creation, fractional allowed |
| `cpu_percent` | required number or null | 0..100; detector sends null: CPU sampler not implemented |
| `packet_rate_pps` | required number, non-null | Observed qualifying packets per actual window second |
| `queue_depth` | required integer or null | Pending application packets; null: no measured application queue |
| `queue_capacity` | required integer or null | Application queue capacity in packets; null: no application queue |
| `packets_processed_total` | required integer, non-null | Qualifying captured packets since detector process started |
| `packets_dropped_total` | required integer or null | null: kernel/NIC/capture drops are not measured |
| `active_flows` | required integer, non-null | Distinct observed five-tuples in window; lower bound if limited |
| `byte_rate_bps` | optional number, non-null when present | Observed Ethernet **bits/second** |
| `suspicious` | optional boolean, non-null | Current heuristic result |
| `alerts` | optional array, non-null | Latest <=32 heuristic events; schema below |
| `per_source` | optional object, non-null | IPv4 string -> nonnegative integer observed window packet count, <=1024 keys |
| `tracking_limited` | optional boolean, non-null | Identity tracking reached a bound; flows/sources may be incomplete |
| `window_seconds` | optional number, non-null | Actual aligned interval duration, seconds |
| `per_bucket` | optional, null only | Attribution unavailable: no verified Python/BMv2 hash parity |

Each alert is exactly `{"id":integer,"timestamp":number,"packet_rate_pps":number}`;
all values are nonnegative, timestamp is Unix UTC seconds no newer than its containing
reading, ID is a process-local sequence number. Collector events add `server_id`.
Alerts are global to the detector, not attributed to a bucket. No CPU/queue surrogate
values are inferred from packet rate. Do not treat null as zero or safe spare capacity
in future controller code. Lifetime counters and alert IDs reset on detector restart.

Example body (illustrative, not a live capture result):

```json
{
  "server_id": "d1",
  "timestamp": 1794074400.25,
  "cpu_percent": null,
  "packet_rate_pps": 1200.0,
  "queue_depth": null,
  "queue_capacity": null,
  "packets_processed_total": 6000,
  "packets_dropped_total": null,
  "active_flows": 3,
  "byte_rate_bps": 710400.0,
  "suspicious": true,
  "alerts": [{"id": 1, "timestamp": 1794074400.25, "packet_rate_pps": 1200.0}],
  "per_source": {"10.0.0.1": 5100},
  "tracking_limited": false,
  "window_seconds": 4.25,
  "per_bucket": null
}
```

GET `/api/v1/telemetry` returns
`{"servers":{"d1":{"telemetry":object_or_null,"age_seconds":number_or_null,"stale":boolean},...},"events":[...]}`.
No reading means `telemetry=null`, `age_seconds=null`, `stale=true`.
Readings older than **3 seconds** are stale; exactly 3 is fresh. Age uses the greater
of wall-clock reading age and **age at receipt plus monotonic elapsed time since
receipt**, so rolling the collector clock backward cannot erase age already present
when a reading arrived. Accept readings up to
60 seconds old (marked stale when >3) and at most one second in the future. Equal
or decreasing timestamps per server are rejected. Detector and collector clocks
must be synchronized; wall-clock rollback can delay acceptance until time catches up.

The collector retains 10 recent bodies per server and 128 recent alert events in
memory, with deduplication against the preceding reading's alerts. These are count
limits, not a durable/time-indexed database; stopped servers' last readings remain
visible and stale, and events may remain until displaced. Data resets on collector
restart. GET exposes latest readings and events; history stays internal for a future
API. A single HTTP worker serializes store access; connection read timeout is 2 seconds.
This intentionally small unauthenticated HTTP service is for the isolated lab
management network, not an Internet-facing production endpoint.

The sender attempts once per configured interval, with no backlog or tight retries.
Connection failures, HTTP errors and malformed responses increment a local delivery
failure count (printed with JSON snapshots). Capture continues. The next attempt
sends current statistics and retained alerts; a long outage can lose alert history.

## Startup in the existing VM session

From a regular terminal, in the repository:

```bash
cd ~/dynohash
.venv/bin/python -m detectors.collector --bind 172.18.50.1 --port 8080
```

Keep that terminal open. In the **existing** Mininet CLI, verify management routes
and collector reachability before starting detectors:

```text
d1 ip route get 172.18.50.1
d2 ip route get 172.18.50.1
d3 ip route get 172.18.50.1
d1 /home/dynohash/dynohash/.venv/bin/python -c "from urllib.request import build_opener,ProxyHandler; print(build_opener(ProxyHandler({})).open('http://172.18.50.1:8080/api/v1/telemetry',timeout=2).read().decode())"
d2 /home/dynohash/dynohash/.venv/bin/python -c "from urllib.request import build_opener,ProxyHandler; print(build_opener(ProxyHandler({})).open('http://172.18.50.1:8080/api/v1/telemetry',timeout=2).read().decode())"
d3 /home/dynohash/dynohash/.venv/bin/python -c "from urllib.request import build_opener,ProxyHandler; print(build_opener(ProxyHandler({})).open('http://172.18.50.1:8080/api/v1/telemetry',timeout=2).read().decode())"
```

Each route must use `dN-mgmt0`, not the data interface. Detector namespaces must
use `172.18.50.1`; localhost there is their own namespace. Do not reconfigure a failed
route automatically. Diagnose with the existing topology's addresses and routes.

For manually managed detectors, open separate namespace terminals if already
available and run the matching command in the matching namespace:

```bash
/home/dynohash/dynohash/.venv/bin/python -m detectors.minimal_detector --server-id d1 --interface d1-eth0
/home/dynohash/dynohash/.venv/bin/python -m detectors.minimal_detector --server-id d2 --interface d2-eth0
/home/dynohash/dynohash/.venv/bin/python -m detectors.minimal_detector --server-id d3 --interface d3-eth0
```

Module commands require repository cwd. Direct script paths also work from other
working directories, e.g. `/home/dynohash/dynohash/.venv/bin/python
/home/dynohash/dynohash/detectors/minimal_detector.py --server-id d1 --interface d1-eth0`.
Use Ctrl-C in those terminals for graceful shutdown. For automated startup and cleanup
inside Mininet, use the harness below instead of manually launching background jobs.
Do not start duplicate detectors or collectors for that harness run.

## Initial implementation tests and results (2026-11-07, historical)

```bash
cd ~/dynohash
.venv/bin/python -m unittest discover -s tests/detectors -v
.venv/bin/python -m unittest discover -s tests/controller -v
.venv/bin/python -m compileall -q controller detectors tests/controller tests/detectors tests/topology/checkpoint2_migration.py tests/topology/checkpoint3_detection.py tools/initialize_checkpoint2.py
.venv/bin/python tests/topology/checkpoint3_detection.py --check-environment
```

Checkpoint 3 unit/HTTP tests: **24 passed, 0 failures, 0 errors**. These include
real POST/GET requests for d1/d2/d3 IDs on localhost, malformed bodies/schema,
stale/duplicate readings, exact window boundary arithmetic, minimum samples/duration,
cooldown, idle expiry, bounded statistics/events, unavailable-then-recovered collector
at the same endpoint, rejected/malformed responses, and a real collector subprocess
SIGTERM/shutdown test and historical-evidence preservation on success/failure.
HTTP fixtures close their servers and join their threads.
No namespace packet capture is implied by these tests. Initial sandbox execution
was blocked by `PermissionError: [Errno 1] Operation not permitted` creating sockets;
the approved execution outside the sandbox passed the real HTTP tests.

Existing Checkpoint 2/controller suite: **23 passed, 0 failures, 0 errors**.
Syntax check: **PASSED**, exit 0. Test output is saved in
`logs/checkpoint3-unit-tests.txt` and `logs/checkpoint3-controller-tests.txt`;
`logs/checkpoint3-validation.json` summarizes validation and the blocked environment.
Unmodified protected source files were checked
against the existing Git index. Existing staged repository content was not changed
or committed. Generated Python bytecode can change during required checks.

At initial implementation, live Mininet capture/detection, namespace telemetry, and
the fresh forwarding/migration recheck were **BLOCKED**, not passed. A read-only
check outside the sandbox returned:

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

No sudo, package installation, topology creation/cleanup, switch writes or pipeline
reload was attempted. Historical Checkpoint 2 PASSED evidence remains intact;
unit results cannot establish current live forwarding or migration preservation.

## Live harness in your existing Mininet CLI

Close any manually started Checkpoint 3 detector/collector processes you own first.
Leave the programmed BMv2 switch and Mininet running. Close the P4Runtime shell or
other controller as for Checkpoint 2; do not increase election IDs to preempt it.
The harness uses existing controller reads with its normal arbitration safeguards.
Use an idle lab: unrelated packets invalidate exact counter/capture comparisons.

In the existing Mininet CLI run:

```text
py __import__('runpy').run_path('/home/dynohash/dynohash/tests/topology/checkpoint3_detection.py')['exercise'](net)
```

It creates a uniquely named `logs/checkpoint3-*/` directory, starts its own collector
on the configured bridge address, verifies HTTP reachability and management routes
from all three namespaces, starts all detectors, then sends real UDP frames from h1:
10 seconds at 30 packets/s total, then 10 seconds at 3000 packets/s total, across
256 source ports. Actual sent counts and timing are recorded. The test-only config
uses threshold 100 packets/s, 30 minimum packets, and the normal 3-second minimum
window; production defaults are not modified. It requires nonzero captures at all
three detectors, no normal-traffic alerts, high-rate alerts on every detector, and
zero window traffic after seven idle seconds. If assignments or VM performance do
not allow those conditions, it reports a failure/block rather than inventing results.

For each phase it compares captured totals with actual bucket-counter deltas summed
by current live assignment. That validates forwarding without claiming per-packet
Python bucket attribution. It checks unchanged assignments and BMv2 PIDs at the end.
Counters naturally increment for test traffic. It stops only processes it started,
including on exceptions, and records cleanup errors as failures. It never restarts
BMv2, changes routes/interfaces or migrates a bucket. Collector port conflicts fail;
choose a free port with `exercise(net, port=8081)` if necessary. Background termination
is not guaranteed if the root Mininet process itself is forcibly killed.

After that, to explicitly authorize a temporary manual migration/restoration recheck:

```text
py __import__('runpy').run_path('/home/dynohash/dynohash/tests/topology/checkpoint3_detection.py')['recheck_migration'](net)
```

This runs the original, unmodified Checkpoint 2 exercise and redirects only its JSON
evidence write to a new `logs/checkpoint3-migration-*/report.json`. It preserves
`logs/checkpoint2-integration.json` even on test failure. Its existing finally block
restores the original bucket and checks packet delivery/PIDs; inspect the report if
restoration fails. This optional command **does temporarily modify a bucket**; the
telemetry harness above does not. The audit agent has not run either command live;
the user subsequently confirmed that `recheck_migration(net)` PASSED.

A full live pass needs `status=PASSED` in both new reports, all detector alerts and
capture/counter matches, no cleanup errors, unchanged telemetry-harness assignments,
and migration `restored=true` with unchanged PIDs. Send the new report directories
and relevant terminal errors for review; retain historical Checkpoint 2 evidence.

## Checkpoint 4 handoff and remaining limits

Internal bins use JSON-serializable dictionaries and string-encoded five-tuple keys
with flow counts, source counts and limit flags. Lifetime totals, alert sequence,
recent alerts and cooldown timing are organized separately in `Statistics`. That is
a basis for a future versioned state schema; no save/load/export/import endpoint,
state-transfer protocol or detector-state migration is implemented. Checkpoint 4
must translate monotonic bin ages/cooldown into portable durations, define restart
and ownership semantics, and establish exact bucket attribution before claiming
per-bucket migration. A single observed bucket-59 mapping is not CRC parity proof.

Other current limits: Linux-only raw socket capture; IPv4 TCP/UDP only; VLANs,
fragments/options, malformed transport headers and packets with other MACs excluded;
no measured capture-loss/CPU/queue telemetry; count-limited in-memory retention;
unauthenticated lab HTTP with a single worker; best-effort alert delivery; clock
synchronization required; no throughput/overhead tuning or live validation yet.
No known failing unit tests remain. The detector/telemetry live exercise remains
unverified by accessible evidence; the migration wrapper has a user-reported pass.
There is no adaptive policy, automatic migration, dashboard, standalone
packet-generator tool, machine learning or state transfer in this checkpoint.

## Audit after the live migration recheck

This audit read AGENTS.md, this document, all detector/telemetry modules, the tests,
the P4 parser/hash fields, forwarding configuration and the Checkpoint 3 live harness.
It did not start Mininet, capture live namespace traffic, send live test traffic,
reload a pipeline or modify switch state. No Checkpoint 4 feature was implemented.

Evidence levels below are deliberately separate:

- **PASSED**: a named local test/source check passed, or the user explicitly reported
  a live result. The evidence column states which; a unit pass is not a live pass.
- **FAILED**: a concrete unsuccessful check, including runtime availability. One
  code defect was reproduced and fixed; no known local test failures remain. The
  live collector availability probe below failed and needs a running collector.
- **NOT TESTED**: no usable verification evidence in this audit, including a blocked
  execution or unreadable live report. This does not assert that the user never ran it.

The user reports that `recheck_migration(net)` **PASSED**: bucket 59 d3 -> d1 -> d3,
four phases of ten packets, restored assignment, BMv2 PID unchanged. The original
harness code includes full-table validation and readback. This verifies the reported
forwarding/migration exercise, **not** execution of `minimal_detector.py`, telemetry,
high-rate alerts, or hash parity.

Four new live-report directories exist: `checkpoint3-4v6vrbrh`,
`checkpoint3-t4i6l38p`, `checkpoint3-awz0z8wd`, and
`checkpoint3-migration-d9vsd6fs`, all under `logs/`. Their mode is 0700 and ownership
is displayed as nobody:nogroup here. Reading their reports was denied both inside
and outside the sandbox. An explicitly approved read-only `sudo -n cat` attempt
returned `sudo: a password is required`. No permissions were changed. Therefore
the detector/telemetry reports cannot be classified as PASSED or FAILED from their
contents yet; the migration pass is attributed to the user's report.

A fresh read-only prerequisite check outside the sandbox now sees `dh-mgmt-br`
UP at 172.18.50.1/24 and BMv2 PID 5823. It returns BLOCKED (exit 2) only because
the audit process is uid 1000 rather than the existing root Mininet CLI. Thus the
initial "no bridge/no switch" limitation above is historical, not the current
environment. One approved read-only GET to
`http://172.18.50.1:8080/api/v1/telemetry` returned connection refused: no collector
was reachable on that address/port at probe time. This is not a failed unit/API
implementation test or proof of a namespace routing failure. No collector was
started against the live management network. The temporary localhost HTTP tests
passed independently.

### Requirement-by-requirement verification

| Requirement | Status | Evidence / remaining work |
| --- | --- | --- |
| Inspect and document the repository architecture before editing | PASSED | Initial architecture notes and this source audit |
| Preserve 64 CRC32 IPv4 five-tuple buckets, ports/MAC rewriting, counters and controller behavior | PASSED | Protected sources unchanged against the index; 23 existing tests pass; live migration pass reported by user |
| Use actual captured packets in detector statistics | NOT TESTED | Receive-only AF_PACKET implementation inspected; parser fixtures pass, but no readable live detector report |
| Capture BMv2 data traffic on d1, d2 and d3 data interfaces | NOT TESTED | All three are launched by the existing exercise; actual captures still need evidence |
| Maintain correct packet and byte rates | PASSED | `test_rates_flows_sources_and_bytes`, aligned-boundary tests; bits/s and actual duration documented; local evidence only |
| Count distinct five-tuples and per-source packets | PASSED | Flow/source tests plus parser TCP/UDP fixtures; local evidence only |
| Bound window, flow/source identities and alert state | PASSED | State/alert bounds and aggregate-limit tests; global counts retained under identity saturation |
| Handle idle periods without stale active flows/rates | PASSED | Unit expiry/cooldown tests; live idle observation remains outstanding |
| Configurable packet-rate heuristic, minimum samples and minimum window | PASSED | Threshold equality/greater-than, sample/window and configuration tests |
| Simple alert cooldown and bounded alerts | PASSED | Cooldown and 32-alert history tests |
| Real normal traffic stays below detection threshold | NOT TESTED | Existing live exercise checks this; no readable result |
| Controlled high-rate traffic creates alerts on every detector | NOT TESTED | Existing live exercise checks this with test-only settings; no readable result |
| Explain heuristic detection rather than definitive DDoS proof | PASSED | Threshold and limitations sections |
| Publish approximately once per second | NOT TESTED | Default/configured scheduling inspected; sustained live timing/cadence has not been measured |
| Sender -> collector delivery using real HTTP | PASSED | Localhost POST/GET tests for d1/d2/d3 IDs; actual namespace delivery is separate |
| Collector currently reachable at the configured live management endpoint | FAILED | Root-namespace GET to 172.18.50.1:8080 returned connection refused at audit time; runtime availability, not a demonstrated code defect |
| Versioned POST /api/v1/telemetry and required fields | PASSED | Serialization, schema and HTTP acceptance tests |
| Correct types, units, timestamps and explicit nullability | PASSED | Schema/range/null tests and contract table |
| Never fabricate CPU, queue or drop measurements | PASSED | All unavailable measurements are null in snapshots; explicit metric sources documented |
| Validate configured server IDs, timestamps and numeric ranges | PASSED | Invalid-ID, old/future/duplicate timestamp and numeric-range tests |
| Reject malformed telemetry/requests safely | PASSED | JSON/schema/content-type/body-size/duplicate-key HTTP tests |
| Mark readings older than 3 seconds stale, including missing data | PASSED | Exact boundary, missing-reading and real HTTP stale/duplicate tests |
| Preserve stale age during collector clock rollback | PASSED | Confirmed defect fixed; two new regression tests including real HTTP; details below |
| Bounded centralized recent telemetry and event storage | PASSED | Store history/event tests; 10 bodies per server, 128 events; memory-only retention |
| Collector GET API exposes latest readings, staleness and events | PASSED | Real GET tests and store view checks; internal history is not a public history API |
| Collector outage/recovery and malformed response handling | PASSED | Same-endpoint recovery, HTTP failure/recovery and malformed-response tests; namespace outage behavior not exercised |
| Graceful collector shutdown and local test cleanup | PASSED | Real collector subprocess SIGTERM test; fixture servers close and threads join |
| Graceful shutdown of actual capturing detector processes | NOT TESTED | Signal/event/socket-timeout code inspected; requires live detector evidence |
| Reuse existing management bridge and detector management addresses | PASSED | Existing topology/config reused without edits; root bridge UP at 172.18.50.1/24 confirmed read-only; namespace reachability is separate |
| Verify detector namespace routes use dN-mgmt0 | NOT TESTED | Existing exercise checks routes; no accessible route result |
| Verify collector HTTP reachability from all three namespaces | NOT TESTED | Existing exercise probes all three; localhost tests do not establish namespace connectivity |
| Separate capture data plane and telemetry management plane | PASSED | Interface guard, incoming MAC filtering, default management URL and proxy bypass inspected; routing needs live verification |
| Avoid forwarding loops, interface reconfiguration and pipeline reloads | PASSED | Detector has no transmit path; audit made no live network changes; exercise source does not reconfigure/provision |
| Prefer standard library/existing dependencies | PASSED | Detector/collector use the standard library; no packages installed |
| Prove exact Python/P4 CRC32 bucket-hash parity | NOT TESTED | No parity implementation/corpus/live proof; bucket 59 alone is insufficient |
| Explicitly mark bucket state unavailable without parity proof | PASSED | per_bucket=null; validator rejects non-null bucket claims; global/flow/source metrics retained |
| Keep organized, serializable state for future work | PASSED | Bounded bins contain JSON-safe flow/source counters; serialization test passes; missing portable schema described below |
| Do not implement state export/import or transfer | PASSED | Source audit; no state-transfer endpoints/protocols |
| Keep telemetry suitable for a future adaptive consumer without decisions | PASSED | Versioned fields and null semantics documented; no balancing policy or automatic migration in detector/collector |
| No dashboard, ML, standalone traffic generator or unrelated rewrite | PASSED | Audit introduced none; existing inline UDP stimulus remains confined to the live test harness |
| Preserve existing detector invocation where possible | PASSED | --server-id/--interface and direct-script support retained; changed JSON logging documented |
| Provide a live harness using the existing topology | PASSED | Existing exercise inspected; it does not create a Mininet instance or reload the switch |
| Test all three detector instances live | NOT TESTED | Three local server IDs are tested; three namespace processes need live evidence |
| Verify forwarding and manual migration still work | PASSED | User-reported four-phase migration pass with same PID and restoration; not rerun by this audit |
| Do not restart BMv2 or reset switch state unnecessarily | PASSED | No live switch commands run in audit; user reports unchanged PID in recheck |
| Report blocked integration honestly and provide exact commands | PASSED | NOT TESTED rows stay unverified; manual steps below |
| Live harness cleans up all its owned processes and preserves assignments | NOT TESTED | Cleanup code inspected; no readable detector-exercise report; local cleanup tests pass |
| Document files, architecture, startup, dependencies/config and JSON contract | PASSED | Corresponding sections above |
| Document thresholds, limitations, test commands and actual results | PASSED | Historical results preserved and current audit results recorded separately |
| Document live status and Checkpoint 4 handoff without implementing it | PASSED | This audit and handoff section |
| Keep AGENTS.md accurate and preserve historical Checkpoint 2 evidence | PASSED | Concise audit update; no edits to original Checkpoint 2 document/report/harness |
| No commit or push | PASSED | Neither operation performed |

### Confirmed defect and focused fix

Before the fix, a reading timestamped 96, accepted at wall time 100/monotonic time
10, was correctly stale with age 4. After a clock rollback to wall time 97 and one
monotonic second, GET incorrectly reported age 1 and stale=false. The old formula
forgot age already present when the reading arrived. A two-case unit regression
failed before the fix (both subcases), establishing the defect independently of HTTP.

`detectors/collector.py` now retains `(monotonic_receipt, age_at_receipt)` per server
and computes age as the maximum of wall-clock age and
`age_at_receipt + monotonic_elapsed`. The corrected example returns age 5 and
stale=true. Added tests:

- `test_rollback_preserves_age_already_present_at_receipt`: already-stale and
  initially-fresh-but-aging readings across rollback.
- `test_http_stale_reading_stays_stale_after_clock_rollback`: real HTTP POST/GET
  with controlled collector clocks.

This changes only collector freshness accounting; telemetry fields, detector
statistics and switch behavior are unchanged. It does not eliminate the documented
requirement for synchronized clocks or rejection of decreasing sender timestamps.

### Tests executed in this audit

The original 24 Checkpoint 3 tests passed before the regression was added. After
the fix, the full suite returned **26 passed, 0 failed, 0 errors**. The two targeted
rollback tests also passed separately. Real HTTP tests ran with approval outside
the sandbox because socket creation is denied inside it. The existing controller
suite returned **23 passed, 0 failed, 0 errors**. The documented expanded compileall
command returned **exit 0**; `git diff --check` passed. Protected P4/controller,
forwarding config, topology, Checkpoint 2 harness, document and historical report
have no working-tree source differences from their existing index versions.

Current output: `logs/checkpoint3-audit-tests.txt` and
`logs/checkpoint3-audit-validation.json`. Earlier logs remain historical evidence.
Temporary localhost servers and the owned collector test subprocess were cleaned
up. No live harness was executed by this audit. The only sudo attempt was the
explicitly approved read-only report access, which failed for lack of a password.

### Missing state and hash limitations

There is no proof that a Python CRC32 implementation reproduces BMv2's exact field
packing/CRC variant. The P4 hash input is IPv4 src, IPv4 dst, transport src port,
transport dst port, then IP protocol; packet payloads do not contain the bucket ID.
Summing live bucket counters by assignment in the harness verifies aggregate
forwarding, not a Python bucket hash. No per-bucket statistics or detection state
are available. Do not infer a bucket from the detector's ID or its port.

State currently contains bounded per-bin flow and source counts, exact observed
global counts, lifetime totals and global alert/cooldown bookkeeping. It is volatile
and capped, not a complete migration record. Telemetry exposes active-flow count,
not individual flow counters. There is no portable full-state schema, atomic state
snapshot/export, epoch translation, import, persistence, owner synchronization or
per-bucket cooldown/state. Monotonic timestamps are process-local, and the initial
last-alert sentinel is negative infinity rather than a strict JSON value. A future
full-state serializer must address those details; it is intentionally not added
here. Bins and alert payloads themselves serialize, as tested.

### Exactly what to run manually

1. **Read existing evidence first; this does not alter the switch.** In the existing
   root Mininet CLI, print report statuses:

   ```text
   py [(str(p), __import__('json').loads(p.read_text()).get('status')) for p in __import__('pathlib').Path('/home/dynohash/dynohash/logs').glob('checkpoint3-*/report.json')]
   ```

   Send the actual report JSONs, particularly any PASSED detector exercise, for
   verification of captures, routes, alert samples, idle results and cleanup.
   The known migration report can be printed without rerunning migration:

   ```text
   py print(__import__('pathlib').Path('/home/dynohash/dynohash/logs/checkpoint3-migration-d9vsd6fs/report.json').read_text())
   ```

2. **If no existing detector/telemetry exercise report is PASSED, run the already
   supplied exercise in that same CLI.** It starts its own collector/detectors;
   first stop only duplicate Checkpoint 3 processes you previously started. Leave
   Mininet/BMv2 up and use an idle lab. The command sends the existing bounded test
   stimulus, reads counters/assignments and does not modify table entries:

   ```text
   py __import__('runpy').run_path('/home/dynohash/dynohash/tests/topology/checkpoint3_detection.py')['exercise'](net)
   ```

   If the harness collector port is already occupied, choose a free port:

   ```text
   py __import__('runpy').run_path('/home/dynohash/dynohash/tests/topology/checkpoint3_detection.py')['exercise'](net, port=8081)
   ```

   A usable pass needs `status=PASSED`, correct management routes for all three,
   fresh delivered snapshots, capture/counter agreement, no normal-traffic alerts,
   high-rate alerts on each detector, zero idle window metrics, unchanged assignments
   and PID, and no cleanup errors. This exercises the test threshold (100 pps), not
   calibration of the default 1000-pps threshold.

3. **Restart your collector normally when ready to use the freshness fix.** Tests
   used temporary collectors and did not replace any existing process. A previously
   running collector continues using its old loaded code until you restart it.
   Standalone command, after stopping only your own old collector:

   ```bash
   cd ~/dynohash
   .venv/bin/python -m detectors.collector --bind 172.18.50.1 --port 8080
   ```

No migration rerun, new topology, pipeline reload, interface changes or Checkpoint 4
work is required for the remaining Checkpoint 3 evidence. Namespace routing/HTTP is
checked by the existing exercise; the earlier startup section also gives individual
read-only route and HTTP commands for diagnosis if that check fails.
