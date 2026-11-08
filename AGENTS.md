# DynoHash conventions

- P4 v1model pipeline: `p4/dynohash.p4`; compiled JSON/P4Info beside it.
- Preserve CRC32 IPv4 five-tuple hashing, 64 buckets, Ethernet rewriting and counters.
- Config: `config/dynohash.json`; d1/d2/d3 map to ports 2/3/4 and configured MACs.
- `controller/core.py`: configuration and migration validation; `runtime.py`: live
  P4Runtime protobuf/gRPC adapter; `cli.py`: module CLI. Normal commands never reload
  the pipeline, insert entries or take over a higher/equal-election controller.
- Migration requires all 64 entries, one MODIFY, full-table readback and unchanged
  unrelated assignments. Do not report success on a write response alone.
- `tests/topology/dynohash_detectors.py`: existing Mininet topology; detectors live in
  `detectors/`. Integration procedure and limitations: `docs/checkpoint2.md`.
- Tests: `.venv/bin/python -m unittest discover -s tests/controller -v`.
- Syntax: `.venv/bin/python -m compileall -q controller tests/controller tests/topology/checkpoint2_migration.py tools/initialize_checkpoint2.py`.
- Checkpoint 2 live evidence in `logs/checkpoint2-integration.json` is PASSED:
  bucket 59 d3 -> d1 -> d3, restored, same BMv2 PID. Preserve this historical evidence.
- Checkpoint 3: `detectors/minimal_detector.py` captures only detector data interfaces;
  `statistics.py` holds bounded rolling statistics/heuristics; `telemetry.py` sends
  versioned HTTP; `collector.py` validates/stores bounded telemetry. Separate settings:
  `config/checkpoint3.json`; management endpoint: 172.18.50.1:8080.
- Per-bucket attribution is unavailable (null); Python/BMv2 hash parity is unverified.
  CPU, queue and capture-drop measurements are null, never fabricated.
- Checkpoint 3 tests: `.venv/bin/python -m unittest discover -s tests/detectors -v`.
  Audited: 26 Checkpoint 3 tests and 23 existing controller tests pass; syntax passes.
  Collector freshness now preserves age-at-receipt across wall-clock rollback.
  User confirms Checkpoint 3 PASSED live, including detector capture, statistics,
  alerts, telemetry, normal/high/idle checks and migration regression. Earlier
  local audit limitations in `docs/checkpoint3.md` are historical evidence.
- No automatic balancing/migration, dashboard or state transfer in Checkpoint 3.
  Never commit, disrupt existing topology or run cleanup without authorization.
  Explicit fresh-switch provisioning lives in `tools/initialize_checkpoint2.py`.
- Checkpoint 4: `controller/adaptive.py`, `telemetry_client.py`, `adaptive_cli.py`;
  settings `config/checkpoint4.json`. Reuses collector GET and Runtime counters;
  `BucketController.migrate` adds optional expected-assignment/pre-write guards.
  Dry-run default. Live requires BOTH `--live --acknowledge-state-loss`; no detector
  history transfer. One action budget by default, freshness/sustained/hysteresis,
  measured bucket benefit, cooldowns, settling and full-table readback required.
- User confirms Checkpoints 1/2/3 PASSED live; older Checkpoint 3 audit is historical.
  Checkpoint 4 verified: 44 adaptive + 23 controller + 26 detector tests pass (93),
  syntax/whitespace checks pass. Run `.venv/bin/python -m unittest discover -s tests/adaptive -v`.
  CLI: `.venv/bin/python -m controller.adaptive_cli --iterations 60` (dry-run).
- Checkpoint 4 LIVE NOT VERIFIED/BLOCKED here (uid 1000, no bridge/visible BMv2).
  Next: existing-Mininet `tests/topology/checkpoint4_adaptive.py` exercise(net), then
  explicit live=True/acknowledge_state_loss=True test. It owns one P4Runtime worker,
  discovers real flow buckets, and restores in finally without overwriting unrelated
  changes. See `docs/checkpoint4.md`; never provision/restart just to run the test.
