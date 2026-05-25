# Tasks: Enhanced Agent Bus Analysis

**Branch**: `001-enhanced-agent-bus-analysis` | **Date**: 2026-05-14

**Input**: Design documents in `/specs/001-enhanced-agent-bus-analysis/`

**Prerequisites**: plan.md ✓, spec.md ✓, research.md ✓, data-model.md ✓, contracts/ ✓

**Tests**: REQUIRED. The spec's acceptance scenarios are observable behaviors, and Constitution Principle III mandates dispatcher-level integration tests for any handler-routing code path. Tests are first-class deliverables, not optional.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: Maps task to user story (US1 / US2 / US3). Setup, Foundational, and Polish phases have no story label.

## Path Conventions

This is a web feature: Python backend package at `packages/agent-bus-analyzer/` and a TypeScript page under `acgi-ai/src/routes/console/`. All paths are relative to repo root unless prefixed with `~`.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Scaffold the new workspace package and console-side plumbing. No business logic yet.

- [x] T001 Create new workspace package skeleton at `packages/agent-bus-analyzer/` with `src/agent_bus_analyzer/` and `tests/` directories
- [x] T002 Author `packages/agent-bus-analyzer/pyproject.toml` (Python 3.11 floor, dependencies: pydantic>=2, anyio, fastapi>=0.110, uvicorn>=0.30; dev: pytest, ruff, mypy) and register the package in the root `uv` workspace
- [x] T003 [P] Add `packages/agent-bus-analyzer/README.md` (one-paragraph purpose statement + link to spec.md/plan.md)
- [x] T004 [P] Add `packages/agent-bus-analyzer/CLAUDE.md` declaring local conventions, sealed-file rules, and the local verify gate (`pytest -q && ruff check . && mypy src/`)
- [x] T005 [P] Add `packages/agent-bus-analyzer/Makefile` with `lint`, `typecheck`, `test` targets matching the workspace conventions
- [x] T006 [P] Copy `specs/001-enhanced-agent-bus-analysis/contracts/trace-event.schema.json` and `trace-query.schema.json` into `packages/agent-bus-analyzer/contracts/` (single source of truth for downstream consumers; spec dir keeps the reviewer copy)
- [x] T007 Create `acgi-ai/src/lib/bus-analysis-client.ts` skeleton (no implementation yet) and register a placeholder import in `acgi-ai/src/router.tsx` to reserve the `/console/bus` route — leave the page component as a stub to satisfy Principle V.3 (no orphan routes once the page lands)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Pydantic models, config, error types, and infrastructure that EVERY user story depends on.

**⚠️ CRITICAL**: No user-story work can begin until Phase 2 is complete.

- [x] T008 [P] Implement `Trace`, `Event`, `EventStatus`, `HandlerRegistrySnapshot`, `HandlerDescriptor`, `WiringDefectFinding`, `ConstitutionalHashAnchor` Pydantic v2 models in `packages/agent-bus-analyzer/src/agent_bus_analyzer/models.py` (fields and validation rules per `data-model.md`)
- [x] T009 [P] Implement canonical JSON serializer (`canonical_json(event_dict)`) in `packages/agent-bus-analyzer/src/agent_bus_analyzer/hashing.py` — sorted keys, deterministic floats, no whitespace
- [x] T010 [P] Implement `compute_event_hash(event, prev_hash)` SHA-256 chain primitive in `packages/agent-bus-analyzer/src/agent_bus_analyzer/hashing.py` mirroring `gove_zone.audit.ChainHashAuditStore`'s rule (hash over canonical_json(event minus event_hash) + prev_hash)
- [x] T011 [P] Implement custom exceptions (`IntegrityStoreUnavailable`, `ReadOnlyViolation`, `BackpressureDropped`, `CorrelationSynthesized`) in `packages/agent-bus-analyzer/src/agent_bus_analyzer/errors.py`
- [x] T012 Implement config loader in `packages/agent-bus-analyzer/src/agent_bus_analyzer/config.py` — reads `bus_endpoint`, `audit_file`, `store_dir`, `queue_capacity`, `dispatch_timeout_seconds`, `registry_poll_seconds`, `retention_days` from env + CLI overrides; resolves `CONSTITUTIONAL_HASH` via env → `ACGS.src.core.shared.constants.CONSTITUTIONAL_HASH` → fail-closed
- [x] T013 [P] Verify Pydantic models export JSON Schemas that match `contracts/trace-event.schema.json` and `trace-query.schema.json` byte-equivalent (add `tests/test_schema_export.py` — fails if Pydantic→JSON Schema drifts from the checked-in contract)
- [x] T014 [P] Implement bounded in-process `CaptureQueue` (asyncio.Queue wrapper with drop-on-full + ingest-gap window tracking) in `packages/agent-bus-analyzer/src/agent_bus_analyzer/capture.py`
- [x] T014b [P] Freeze 200-event hand-labeled classification corpus at `packages/agent-bus-analyzer/tests/fixtures/classification_corpus.jsonl` with `tests/fixtures/README.md` documenting label distribution and re-labeling policy (Cohen's kappa ≥ 0.8 — two-labeler agreement before next re-freeze)
- [x] T069 Bootstrap FastAPI app skeleton in `packages/agent-bus-analyzer/src/agent_bus_analyzer/api.py` — `create_app()` factory mounted at `/api/bus`, `GET /healthz` endpoint, JSON error handler, structured-logging middleware. No business endpoints yet (mounted per-story). Add `serve` subcommand in `cli.py` that runs `uvicorn agent_bus_analyzer.api:create_app --factory`

**Checkpoint**: Models, hashing, config, errors, capture queue, and HTTP app skeleton all importable. No I/O or subscription yet.

---

## Phase 3: User Story 1 — Investigate a Suspect Run (Priority: P1) 🎯 MVP

**Goal**: A governance reviewer can filter to a correlation ID and walk every dispatch/response in causal order, with the responding handler, governance verdict, and constitutional-hash provenance visible per step.

**Independent Test**: Trigger a known multi-agent run, open the analysis view at `/console/bus`, filter to that run's correlation_id. View lists every dispatch/response in causal order, names the responding handler, and shows the governance verdict per step.

### Tests for User Story 1 (write FIRST; ensure they FAIL before implementation)

- [x] T015 [P] [US1] Write `packages/agent-bus-analyzer/tests/test_capture_readonly.py` — replay a stream of `BusEvent`s through the observer; assert object identity / `dataclasses.asdict` snapshot of inputs is unchanged after capture (proves FR-003)
- [x] T016 [P] [US1] Write `packages/agent-bus-analyzer/tests/test_bus_dispatch_capture.py` — boot local `EnhancedAgentBus`, attach observer via `observer.attach(bus)`, publish a real bus message, assert within 5s the analyzer's store contains the matching event with correct `correlation_id`, `kind`, `source_agent`. **This is the Constitution Principle III dispatcher-level test** — do NOT call classifier/store directly; the test MUST exercise `bus.publish()`
- [x] T017 [P] [US1] Write `packages/agent-bus-analyzer/tests/test_query_by_correlation.py` — seed 3 traces into the store; query by `correlation_id`; assert events return in `causal_index` order, schema matches `trace-query.schema.json` SingleTrace shape
- [x] T018 [P] [US1] Write `packages/agent-bus-analyzer/tests/test_backpressure_gap_marker.py` — saturate the bounded queue beyond capacity; assert (a) bus publish never blocks > 1ms p99, (b) an `ingest-gap` marker is emitted on resumption with non-null `gap_started_at`/`gap_ended_at`, (c) the gap marker is NOT part of the prev_hash chain (FR-013, schema rule)
- [ ] T019 [P] [US1] **DEFERRED — frontend test runner not configured.** Write `acgi-ai/src/routes/console/BusAnalysis.test.tsx` — render `<BusAnalysis />` with a mocked trace list response; assert trace rows appear, clicking opens the inspector, inspector shows events in causal-index order. Unblocked once `vitest` + `@testing-library/react` + `jsdom` land in `acgi-ai/package.json` (project-policy decision — out of scope for this feature). See `specs/001-enhanced-agent-bus-analysis/acceptance/2026-05-25-acceptance.md` for the test-runner blocker writeup
- [x] T020 [US1] Write contract test `packages/agent-bus-analyzer/tests/test_query_contract.py` — exercise the query API end-to-end; validate every response against `contracts/trace-query.schema.json` using `jsonschema`
- [x] T074 [P] [US1] Fault-injection test proving SC-006 at `tests/test_fault_injection_sc006.py` — kill the analyzer mid-run; assert `bus.publish()` succeeds and a downstream governance gate denying a known-deny payload still denies. Covers Scenario B (analyzer becomes load-bearing) + degraded-state surface.
- [x] T076 [P] [US1] RBAC-deny audit-event test at `tests/test_auth_audits_rejections.py` — assert the 401/403 path writes a `kind="decision", decision="deny", source_agent="api:query"` event to the store (FR-011).

### Implementation for User Story 1

- [x] T021 [US1] Implement `Observer.attach(bus)` in `packages/agent-bus-analyzer/src/agent_bus_analyzer/observer.py` — registers `on_bus_event(BusEvent) -> None` callback per `contracts/observer-interface.md`; enqueues onto `CaptureQueue`; MUST return ≤1ms (no I/O on hot path); MUST NOT mutate the event
- [x] T022 [US1] Implement audit-tail follower in `packages/agent-bus-analyzer/src/agent_bus_analyzer/observer.py` — opens gove-zone audit JSONL in `O_RDONLY`, follows by inode tracking, parses one record per line, joins via `event_id` into the queue as `kind="decision"` events
- [x] T023 [US1] Implement JSONL append store in `packages/agent-bus-analyzer/src/agent_bus_analyzer/store.py` — opens `var/agent-bus-analyzer/traces/<YYYY-MM-DD>.jsonl` in append mode, fsyncs every event, computes `event_hash` and `prev_hash` per trace using `hashing.py`
- [x] T024 [US1] Implement SQLite derived index in `packages/agent-bus-analyzer/src/agent_bus_analyzer/store.py` — keyed by `(correlation_id, causal_index)`; rebuildable from JSONL via `store.reindex()`; explicit comment that the SQLite file is NOT on the integrity path
- [x] T025 [US1] Implement basic classifier in `packages/agent-bus-analyzer/src/agent_bus_analyzer/classifier.py` — assigns `completed` to a dispatch+response pair, `policy-violation` when a paired `decision="deny"` or escalate-with-deny is observed (sets `flagged_rule` from `matched_rules[0]`)
- [x] T026 [US1] Implement writer task (`store.writer_loop()`) in `packages/agent-bus-analyzer/src/agent_bus_analyzer/store.py` — consumes from `CaptureQueue`, writes to JSONL + SQLite index in batches; emits `ingest-gap` markers when queue drops are detected
- [x] T072 [US1] Implement `observer` CLI subcommand in `packages/agent-bus-analyzer/src/agent_bus_analyzer/cli.py` — `python -m agent_bus_analyzer observer --bus-endpoint=... --audit-file=... --store-dir=... [--registry-poll-seconds=30] [--queue-capacity=10000]`; wires `Observer.attach(bus)` + audit-tail follower + `store.writer_loop()`; exits 1 with `IntegrityStoreUnavailable` if `--audit-file` is missing or unreadable on boot (FR-008); prints the one-line-per-second status format documented in `quickstart.md` §2
- [x] T027 [US1] Implement query API in `packages/agent-bus-analyzer/src/agent_bus_analyzer/query.py` — `list_traces(cursor, limit) -> TraceList`, `get_trace(correlation_id) -> SingleTrace | Expired`; returns shapes matching `trace-query.schema.json`
- [x] T028 [US1] Implement RBAC FastAPI dependency `require_reviewer_role()` in `packages/agent-bus-analyzer/src/agent_bus_analyzer/auth.py` — rejects unauthenticated reads with 401, authenticated-but-unauthorized with 403; every rejection is appended to the analyzer's trace store as an event with `kind="decision", decision="deny", source_agent="api:query"` (FR-011); validates the bearer token against the existing console identity layer per research §R7
- [x] T070 [US1] Mount `GET /api/bus/traces` and `GET /api/bus/traces/{correlation_id}` in `packages/agent-bus-analyzer/src/agent_bus_analyzer/api.py` — thin handlers wrapping `query.list_traces()` and `query.get_trace()`; apply RBAC `Depends(require_reviewer_role)` from T028; responses validated against `contracts/trace-query.schema.json` via Pydantic response models
- [x] T029 [US1] Implement typed client in `acgi-ai/src/lib/bus-analysis-client.ts` — typed wrappers around `GET /api/bus/traces` (TraceList) and `GET /api/bus/traces/:correlation_id` (SingleTrace | Expired); mirrors `trace-query.schema.json`
- [x] T030 [US1] Implement `useBusAnalysis()` hook in `acgi-ai/src/routes/console/BusAnalysis.tsx` — mirrors the existing `useAudit()` pattern from `acgi-ai/src/routes/console/Audit.tsx`; no new query library
- [x] T031 [US1] Implement `<BusAnalysis />` page component in `acgi-ai/src/routes/console/BusAnalysis.tsx` — trace list + inspector pane; renders constitutional-hash header per trace; shows governance verdict per step; CSP-compliant (no inline styles, no CDN fonts)
- [x] T032 [US1] Wire the `/console/bus` route fully in `acgi-ai/src/router.tsx` and replace the Phase 1 stub component with `<BusAnalysis />` — landing in the SAME commit as T031 per Principle V.3

**Checkpoint**: US1 is complete and independently testable — a reviewer can open `/console/bus`, filter by correlation_id, and see every dispatch/response with governance verdicts. P1 acceptance scenarios 1 and 3 pass; scenario 2 (policy-violation marking) passes for `decision="deny"` paths.

---

## Phase 4: User Story 2 — Catch Wiring Defects Before They Reach Production (Priority: P2)

**Goal**: An operator deploys a new handler or rule; within 60 seconds, the analyzer surfaces unwired handlers, dispatch failures, and dispatcher exceptions in a wiring-defect summary.

**Independent Test**: Register a handler in source but omit it from the dispatcher's routing table, dispatch its expected event. Within 60s, the analyzer surfaces an "unwired handler" finding naming the expected handler.

### Tests for User Story 2 (write FIRST; ensure they FAIL before implementation)

- [x] T033 [P] [US2] Write `packages/agent-bus-analyzer/tests/test_handler_registry_snapshot.py` — sample a fake `EnhancedAgentBus.registry`, assert `HandlerRegistrySnapshot` captures `name`, `registered_in_runtime=True/False`, `last_seen_at`
- [x] T034 [P] [US2] Write `packages/agent-bus-analyzer/tests/test_wiring_defect_detection.py` — seed events with `target_handler_declared` for a handler absent from the snapshot; assert `WiringDefectFinding(kind="unwired_dispatch", handler_name=...)` is produced
- [x] T035 [P] [US2] Write `packages/agent-bus-analyzer/tests/test_wiring_defect_dispatcher_level.py` — boot local `EnhancedAgentBus`, publish a payload targeted at a handler with no registry entry, assert within 60s `store.query()` returns an event with `status="unwired-handler"` and the matching `target_handler_declared`. **Dispatcher-level — Constitution Principle III, repeats the canonical test the constitution-validator agent checks for**
- [x] T036 [P] [US2] Write `packages/agent-bus-analyzer/tests/test_classifier_extended.py` — synthetic events for each of `dispatch-failure`, `orphan-response`, `incomplete-pair`; assert classifier returns the correct `EventStatus`
- [ ] T037 [P] [US2] **DEFERRED — same runner blocker as T019.** Write `acgi-ai/src/routes/console/BusAnalysis.wiring.test.tsx` — mock a wiring-defect summary response, assert the defect panel renders findings with `handler_name`, `kind`, `example_event_ids`, `detected_at`

### Implementation for User Story 2

- [x] T038 [P] [US2] Implement `HandlerRegistrySnapshot` sampling in `packages/agent-bus-analyzer/src/agent_bus_analyzer/wiring.py` — fixed interval (default 30s) + on observer reconnect; reads `EnhancedAgentBus.registry` and (where applicable) `gove_zone.kernel` declared tools
- [x] T039 [P] [US2] Implement static-introspection for `declared_in_source=True` in `packages/agent-bus-analyzer/src/agent_bus_analyzer/wiring.py` — best-effort AST scan for `@kernel.tool(...)` and equivalent decorators across the workspace; cached per snapshot
- [x] T040 [US2] Extend classifier in `packages/agent-bus-analyzer/src/agent_bus_analyzer/classifier.py` — add rules for `dispatch-failure` (timeout exceeded), `unwired-handler` (declared but no registry entry), `orphan-response` (response with no prior dispatch), `incomplete-pair` (dispatch with no response, observer crashed)
- [x] T041 [US2] Implement `wiring.compute_findings()` in `packages/agent-bus-analyzer/src/agent_bus_analyzer/wiring.py` — joins `HandlerRegistrySnapshot` against recent events, produces `WiringDefectFinding` records keyed idempotently on `(kind, handler_name)`; refresh window matches SC-003 (60s)
- [x] T042 [US2] Extend query API in `packages/agent-bus-analyzer/src/agent_bus_analyzer/query.py` — add `get_wiring_defects() -> WiringDefectSummary` matching `trace-query.schema.json#/$defs/WiringDefectSummary`; refreshed ≤60s
- [x] T043 [US2] Mount `GET /api/bus/defects` in `packages/agent-bus-analyzer/src/agent_bus_analyzer/api.py` wrapping `query.get_wiring_defects()`; apply `Depends(require_reviewer_role)` from T028; cache-control headers reflect the 60s refresh window per SC-003
- [x] T044 [US2] Extend `acgi-ai/src/lib/bus-analysis-client.ts` with `getWiringDefects()` returning `WiringDefectSummary` shape
- [x] T045 [US2] Extend `<BusAnalysis />` in `acgi-ai/src/routes/console/BusAnalysis.tsx` — add wiring-defect panel showing `kind`, `handler_name`, `example_event_ids`, `detected_at`; refreshes every 60s while page is open
- [x] T046 [US2] Surface `worst_event_status` badge on the trace list (`unwired-handler`, `dispatch-failure`, etc.) in `acgi-ai/src/routes/console/BusAnalysis.tsx` so reviewers can spot defective runs without opening each trace

**Checkpoint**: US2 is independently testable — operators see wiring defects within 60s of an unwired-handler dispatch; classifier handles all `EventStatus` values; trace badges expose worst-status.

---

## Phase 5: User Story 3 — Prove the Audit Trail Has Not Been Tampered With (Priority: P3)

**Goal**: A compliance reviewer can open any trace and see a constitutional-hash chain plus an integrity status (intact / tampered / unknown). Tampered traces are never marked clean.

**Independent Test**: Capture a trace, modify a stored event in JSONL, open the trace in the console. View shows `integrity_status=tampered` and refuses to display the trace as clean.

### Tests for User Story 3 (write FIRST; ensure they FAIL before implementation)

- [x] T047 [P] [US3] Write `packages/agent-bus-analyzer/tests/test_chain_integrity.py` — capture a synthetic trace, flip a byte in the stored JSONL, assert `store.verify(correlation_id)` returns `integrity_status="tampered"` with the offending `event_id` named
- [x] T048 [P] [US3] Write `packages/agent-bus-analyzer/tests/test_fail_closed_integrity_store.py` — delete or chmod-000 the audit JSONL; assert the observer exits non-zero with `IntegrityStoreUnavailable` and does NOT write any non-hash-chained events (FR-008)
- [x] T049 [P] [US3] Write `packages/agent-bus-analyzer/tests/test_constitutional_hash_rotation.py` — record events spanning a hash rotation, assert the trace surfaces `rotation_at_index` per `trace-query.schema.json#/$defs/SingleTrace`
- [x] T050 [P] [US3] Write `packages/agent-bus-analyzer/tests/test_verify_cli.py` — invoke `python -m agent_bus_analyzer verify <correlation_id>` against (a) a clean trace (exit 0), (b) a tampered trace (exit non-zero, names the broken event), (c) a missing predecessor hash (exit non-zero with `unknown` status)
- [ ] T051 [P] [US3] **DEFERRED — same runner blocker as T019.** Write `acgi-ai/src/routes/console/BusAnalysis.integrity.test.tsx` — render the inspector with a `tampered` response, assert the "clean" badge is suppressed and a tamper indicator with the broken `event_id` is visible

### Implementation for User Story 3

- [x] T052 [US3] Implement `store.verify(correlation_id)` in `packages/agent-bus-analyzer/src/agent_bus_analyzer/store.py` — replays the JSONL, re-hashes every event, returns `integrity_status` plus (if tampered) the first broken `event_id`
- [x] T053 [US3] Implement integrity-store availability check at observer boot in `packages/agent-bus-analyzer/src/agent_bus_analyzer/observer.py` — opens audit file in `O_RDONLY`; exits with `IntegrityStoreUnavailable` if missing/unreadable; never records new events when the integrity store is unreachable
- [x] T054 [US3] Implement mid-run hash rotation detection in `packages/agent-bus-analyzer/src/agent_bus_analyzer/store.py` — when a captured event's `constitutional_hash` differs from the trace header, set `rotation_at_index=<causal_index>` in the trace metadata
- [x] T055 [US3] Implement `verify` CLI entry point in `packages/agent-bus-analyzer/src/agent_bus_analyzer/cli.py` — `python -m agent_bus_analyzer verify <correlation_id>`; exit 0 on intact, non-zero on tampered/unknown; prints structured JSON report
- [x] T056 [US3] Wire `integrity_status` into the query API response in `packages/agent-bus-analyzer/src/agent_bus_analyzer/query.py` — every `SingleTrace` response carries an `integrity_status` computed at query time; every `TraceListItem` shows the badge
- [x] T057 [US3] Surface integrity status in `<BusAnalysis />` in `acgi-ai/src/routes/console/BusAnalysis.tsx` — trace list badge, inspector header banner, suppress "clean" presentation when `integrity_status != "intact"`
- [x] T058 [US3] Surface degraded-state banner in `<BusAnalysis />` in `acgi-ai/src/routes/console/BusAnalysis.tsx` when the API reports the observer is fail-closed (integrity store unreachable) — distinct from per-trace tampering

**Checkpoint**: US3 is independently testable — tamper detection round-trips end-to-end; observer fails closed on integrity-store loss; hash rotation surfaces in the inspector.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Retention enforcement, performance verification, documentation, and constitution-hash audit before sign-off.

- [x] T059 [P] Implement retention enforcement in `packages/agent-bus-analyzer/src/agent_bus_analyzer/store.py` — `expire_older_than(days)` moves expired JSONL to `expired/` subdirectory, marks SQLite rows `status=expired`; NEVER mutates the JSONL contents (research §R9)
- [x] T060 [P] Add expired-trace response handling in `packages/agent-bus-analyzer/src/agent_bus_analyzer/query.py` — return `Expired` shape (per `trace-query.schema.json#/$defs/Expired`) instead of 404 when a queried trace is past retention
- [x] T061 [P] Add `dev-traffic` CLI helper in `packages/agent-bus-analyzer/src/agent_bus_analyzer/cli.py` — `python -m agent_bus_analyzer dev-traffic --target=... --count=N --include-unwired-handler` to support quickstart.md
- [x] T062 [P] Add SC-005 latency benchmark in `packages/agent-bus-analyzer/tests/test_capture_latency.py` — measures bus dispatch latency with vs without observer attached; asserts ≤5% regression at floor scale
- [ ] T063 [P] **DEFERRED — Playwright not configured.** Add Playwright smoke test for `/console/bus` in `acgi-ai/tests/e2e/bus-analysis.spec.ts` — boots the page against a fixture API, verifies trace list + inspector + defect panel render. Unblocked once `@playwright/test` + `playwright.config.ts` land in `acgi-ai/`
- [x] T064 Run `quickstart.md` end-to-end as the acceptance dry-run; record evidence (logs/screenshots) under `specs/001-enhanced-agent-bus-analysis/acceptance/`
- [x] T065 Run `make verify` at workspace root; paste literal output into the PR description (gates: ruff, mypy, pytest, biome, vitest, tsc)
- [x] T066 Verify no sealed/constitutional-hash file in the repo was modified by this branch (`git diff --name-only origin/master...HEAD | xargs -I{} grep -l "Constitutional Hash:" {} 2>/dev/null` returns empty); run `constitutional-hash-verify` skill if available
- [x] T067 [P] Update `MONOREPO.md` to register `packages/agent-bus-analyzer/` (Phase 0 of the unification plan — new workspace member registration only; no submodule moves)
- [x] T068 Verify the route registered in T032 still resolves on a fresh `pnpm -F acgi-ai build` — no orphan-route regression introduced by Phase 4/5 churn
- [x] T073 [P] SC-002 classifier accuracy harness at `tests/test_classification_accuracy.py` — measures accuracy against the T014b corpus; gates ≥95%. US2 rows xfail-soft when context unavailable.
- [x] T075 [P] Expired-trace query test at `tests/test_query_expired.py` — verifies `Expired` response shape (not 404) for aged-out correlation_id and live-trace precedence over sidecar.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No prior dependencies; can start immediately.
- **Foundational (Phase 2)**: Depends on Setup (T001–T007). BLOCKS Phases 3–5.
- **US1 (Phase 3)**: Depends on Foundational; delivers the MVP.
- **US2 (Phase 4)**: Depends on Foundational; can run in parallel with US1 if staffed, but US2's `<BusAnalysis />` extensions (T045–T046) conflict with US1's T031, so coordinate the page component edits.
- **US3 (Phase 5)**: Depends on Foundational. T054/T056 extend store and query modules touched by US1; serialize those file edits or branch carefully.
- **Polish (Phase 6)**: Depends on all targeted stories being complete.

### Within Each User Story

- Tests written and FAILING before the matching implementation lands.
- Models / primitives before services; services before endpoints; endpoints before page wiring.
- Console route plumbing (T032) MUST land in the same commit as `<BusAnalysis />` (Principle V.3).
- HTTP endpoint mounting (T070, T043) depends on T069 (app factory), the matching `query.py` function (T027, T042), and the RBAC dependency (T028).
- `observer` CLI (T072) depends on T021, T022, T026; the deeper integrity-store fail-closed check (T053, US3) extends — does not replace — T072's basic readability check.

### Parallel Opportunities

- **Setup**: T003, T004, T005, T006 are all [P] — different files, no cross-dependencies.
- **Foundational**: T008, T009, T010, T011, T013, T014 are all [P] — separate modules and tests.
- **US1 tests**: T015, T016, T017, T018, T019 are all [P] — different test files.
- **US2 tests**: T033, T034, T035, T036, T037 are all [P].
- **US3 tests**: T047, T048, T049, T050, T051 are all [P].
- **Polish**: T059–T063, T067 are [P]; T064–T066, T068 serialize the final verify gate.

---

## Parallel Example: User Story 1 Tests

```bash
# Launch all US1 test files in parallel:
Task: "Write tests/test_capture_readonly.py (T015)"
Task: "Write tests/test_bus_dispatch_capture.py (T016)"
Task: "Write tests/test_query_by_correlation.py (T017)"
Task: "Write tests/test_backpressure_gap_marker.py (T018)"
Task: "Write acgi-ai/src/routes/console/BusAnalysis.test.tsx (T019)"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup.
2. Complete Phase 2: Foundational (BLOCKING — models, hashing, config, capture queue).
3. Complete Phase 3: US1 — observer → store → query → console inspector.
4. STOP and VALIDATE: walk a real correlation_id end-to-end via quickstart §3–§4.
5. Deploy to staging if the latency benchmark (T062 minimal-effort precheck) shows ≤5% bus impact.

### Incremental Delivery

- US1 → MVP demo (trace inspector working).
- US2 → adds wiring-defect detection; close the "handler defined but unwired" loop.
- US3 → adds tamper-evidence display; the analyzer becomes audit-grade.

### Parallel Team Strategy

With multiple developers:

1. Whole team completes Setup + Foundational together.
2. After Foundational checkpoint:
   - Developer A: US1 (longest backbone — observer, store, query, page).
   - Developer B: US2 (after US1 store/query exist, can start on `wiring.py` and classifier extension immediately).
   - Developer C: US3 (after Foundational hashing primitives exist, can write `verify` CLI and integrity tests independently).
3. Page-component edits (T031, T045, T057) MUST be sequenced — single file, three authors.

---

## Notes

- [P] tasks = different files, no incomplete-task dependencies.
- The constitutional-validator agent should be invoked on every PR landing tasks from this list, per `~/.claude/agents/constitutional-validator.md`.
- Submodule discipline: no edits inside `packages/acgs-lite/`, `packages/Acgs-Swarm/`, `packages/clinicalguard/`, or `ACGS/` — the analyzer consumes their public surfaces only.
- `MONOREPO.md` registration (T067) is the Phase 0 unification touchpoint; do not preempt later phases of `docs/PLAN-MONOREPO.md` from inside this feature branch.
- Stage commits explicitly (`git add <file>`) — never `git add -A` per workspace policy.
