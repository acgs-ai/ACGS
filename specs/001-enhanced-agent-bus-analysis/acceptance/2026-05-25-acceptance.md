# Acceptance Evidence — Enhanced Agent Bus Analysis

**Date**: 2026-05-25
**Branch**: `feat/agent-bus-analyzer`
**Tip commit**: see `git log -1 --format=%H` at time of acceptance
**Plan**: `.omc/plans/2026-05-25-enhanced-agent-bus-analysis-execution.md`

## Local gate (T065)

`make verify` at workspace root → exit 0.

Per-stage tail captured below; full output too large to inline.

### Python — `agent-bus-analyzer`

```
============================= 365 passed in 3.24s ==============================
```

Includes:
- US1 capture/store/query/audit (test_capture, test_capture_readonly, test_bus_dispatch_capture, test_query_by_correlation, test_auth, test_auth_audits_rejections, test_backpressure_gap_marker, test_chain_integrity, test_classifier, test_cli, test_api, test_api_traces, test_config, test_hashing, test_gove_zone_audit_tail, test_schema_export, test_deploy_contract, test_evidence_signing)
- US2 wiring detection (test_handler_registry_snapshot, test_wiring_defect_detection, test_wiring_defect_dispatcher_level, test_classifier_extended, test_api_defects)
- US3 integrity (test_chain_integrity, test_fail_closed_integrity_store, test_constitutional_hash_rotation, test_verify_cli)
- Phase 6 (test_capture_latency, test_classification_accuracy, test_fault_injection_sc006, test_query_expired)

### Python — sibling packages

```
acgs_governance_eval_mvp:    127 passed
acgs-cft-governance-pack:      6 passed
```

### JS / TS surfaces

```
acgi-ai:lint:   Checked 69 files in 31ms. No fixes applied.
acgi-ai:build:console   ✓ built in 168ms (dist/assets/index-*.js 413 kB / 124 kB gzip)
acgi-ai:build:marketing ✓ built in 169ms (dist-marketing/assets/index-*.js 355 kB / 110 kB gzip)
turbo: 2 tasks successful, FULL TURBO
```

## Frontend build smoke (T068)

`pnpm -F acgi-ai build` rebuilds `/console/bus` route successfully — no orphan-route regression. Built artifact transforms 1888 modules and emits `dist/index.html` referencing the chunked console bundle.

## Constitutional-hash audit (T066)

`scripts/verify_constitutional_hashes.py` shows pre-existing drift in `packages/clinicalguard/` files. This is **not caused by this branch** — `docs/constitutional-hashes.lock` has no diff between `master` and `HEAD` for this branch:

```
$ git log --oneline master..HEAD -- docs/constitutional-hashes.lock
(empty)
```

The clinicalguard files are absent locally because the submodule is "path-filtered CI only until initialization is reliable" per `CLAUDE.md`. Initializing the submodule (with `SUBMODULE_TOKEN`) or running on CI restores the files and the verifier passes. This branch does not touch any sealed governance artifact: spec.md/data-model.md/tasks.md edits in this branch contain the literal phrase "Constitutional Hash:" in narrative text but no governance-sealed hex values.

## Quickstart correspondence (T064)

The quickstart procedure (`quickstart.md`) describes operator-facing steps. Sections 1, 2, 3, 4, 5, 6 are exercised under unit + integration tests rather than a live cluster boot; the test surface that covers each section:

| Quickstart § | Behavior | Covering tests |
|---|---|---|
| §1 bus boot | constitutional_hash anchor | `test_config.py` (env→constant resolution) |
| §2 observer attach | RO bus + RO audit + fail-closed | `test_capture_readonly.py`, `test_gove_zone_audit_tail.py`, `test_fail_closed_integrity_store.py` |
| §3 generate traffic | dev-traffic CLI + unwired-handler emit | `cli.py:_cmd_dev_traffic` + `test_handler_registry_snapshot.py`, `test_wiring_defect_dispatcher_level.py` |
| §4 console open | trace list, inspector, defect panel | `test_api_traces.py`, `test_api_defects.py` + manual smoke against `pnpm -F acgi-ai build` |
| §5 tamper edit | integrity → tampered | `test_chain_integrity.py`, `test_verify_cli.py` |
| §6 pytest suite | the suite itself | `make verify` |

Live-cluster smoke is the operator step; the test surface proves the contract on every commit.

## Success criteria

| SC | Status | Evidence |
|---|---|---|
| SC-001 (60s causal reconstruction) | covered | `test_query_by_correlation.py` orders by causal_index; FastAPI endpoint backs `/console/bus` |
| SC-002 (≥95% classifier accuracy) | harness in place | `test_classification_accuracy.py` against `fixtures/classification_corpus.jsonl` (200 events). US2 rows xfail-soft when context unavailable. |
| SC-003 (60s wiring defect surface) | covered | `wiring.compute_findings(window_seconds=60)`; `test_wiring_defect_detection.py` |
| SC-004 (no clean badge on tampered) | covered | `test_chain_integrity.py` + frontend `BusAnalysis.tsx` suppresses clean badge when integrity != intact |
| SC-005 (≤5% bus latency regression) | benchmark wired | `test_capture_latency.py` — `pytest.importorskip` skips when optional bus checkout absent |
| SC-006 (gate never fails open due to analyzer) | covered | `test_fault_injection_sc006.py` — FaultingObserver wrapper + stub gate proves non-interference |

## Outstanding items (deferred — see Notes)

- **T019, T037, T051, T063** (frontend tests): `acgi-ai` has no runtime test runner configured. The package's `test:all` script is a chain of static manifest checkers, not a test runner. Adding `vitest`/`@playwright/test` is a separate operator decision (test-runner posture change). Scaffold test files placed under `acgi-ai/tests/console/` and `acgi-ai/tests/e2e/` for activation when a runner is installed.

## Reproduction

```bash
# Python verify
cd packages/agent-bus-analyzer && make lint typecheck test

# Full workspace verify
make verify

# Frontend build smoke
pnpm -F acgi-ai build

# Hash audit
python3 scripts/verify_constitutional_hashes.py    # pre-existing clinicalguard drift; not from this branch
git log --oneline master..HEAD -- docs/constitutional-hashes.lock    # empty = lock untouched
```
