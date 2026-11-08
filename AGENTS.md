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
  User reports migration recheck PASSED (bucket 59, four ten-packet phases, restored,
  same PID). Detector/telemetry live results remain unverified: report directories
  are unreadable here. See `docs/checkpoint3.md` audit matrix and manual commands.
  Next: review existing `checkpoint3-*` reports or run the detector exercise in the
  existing VM topology; do not rerun migration just to establish telemetry behavior.
- No automatic balancing/migration, dashboard or state transfer in Checkpoint 3.
  Never commit, disrupt existing topology or run cleanup without authorization.
  Explicit fresh-switch provisioning lives in `tools/initialize_checkpoint2.py`.
