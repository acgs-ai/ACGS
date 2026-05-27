# DESIGN-phase2.md — Agent Bus Analyzer

**Generated from implementation**: 2026-05-17
**Package**: `packages/agent-bus-analyzer`
**Verification**: 69 tests passing, ruff clean, mypy strict clean (14 source files)

---

## Overview

Observer-only analysis layer over the Enhanced Agent Bus + gove-zone audit chain. Reads
from two upstream surfaces (the bus and the audit JSONL), persists hash-chained traces to
disk, and serves a FastAPI query API for governance reviewers.

**Constitution Principle II**: read-only on all upstream surfaces. Never on the authorization path.
**Constitution Principle III**: dispatcher-level integration tests; never call observer/store
functions directly in tests that verify bus capture.

---

## Architecture: Component Topology

```
                           ┌──────────────────────┐
                           │   EnhancedAgentBus   │
                           │ (production path)    │
                           └───────┬──────────────┘
                                   │ publish(msg)
                                   ▼
                    ┌──────────────────────────────┐
                    │        Observer              │
                    │  on_bus_event()  (hot path)  │
                    │  ≤1ms, no I/O                │
                    │  1. project_bus_event(msg)   │
                    │  2. queue.try_put(event)     │
                    │     └─ drops if full;        │
                    │        opens ingest-gap      │
                    └──────────┬───────────────────┘
                               │ CaptureQueue
                               │ (asyncio bounded)
                               ▼
                    ┌──────────────────────────────┐
                    │     writer_loop()            │
                    │  (cold path, async task)     │
                    │  1. flush gap markers first  │
                    │  2. append(event)             │
                    │     └─ fcntl.flock(LOCK_EX)  │
                    │     └─ compute_event_hash()  │
                    │     └─ write + fsync JSONL   │
                    │     └─ _upsert_index()       │
                    └──────────┬───────────────────┘
                               │
            ┌──────────────────┼──────────────────────┐
            ▼                                     ▼
  ┌────────────────┐                   ┌─────────────────┐
  │  var/traces/   │                   │  index.sqlite   │
  │  {cid}.jsonl   │                   │  rebuildable    │
  │  (integrity    │                   │  (derived)      │
  │   source of    │                   │                 │
  │   truth)       │                   │                 │
  └────────┬───────┘                   └────────┬────────┘
           │                                    │
           │  ┌─────────────────┐               │
           │  │ gove-zone audit │  (read-only)  │
           │  │ JSONL tail      │               │
           │  │ follow_audit_   │               │
           │  │ file()          │               │
           │  └────────┬────────┘               │
           │           │ project_audit_record() │
           │           ▼                        │
           │  ┌────────────────────┐            │
           │  │ kind="decision"    │────────────┘
           │  │ events             │
           │  └────────────────────┘
           │
           ▼
  ┌───────────────────────────────────────────────┐
  │           FastAPI Query API                   │
  │  GET /api/bus/healthz                         │
  │  GET /api/bus/traces          [RBAC: reviewer]│
  │  GET /api/bus/traces/{cid}    [RBAC: reviewer]│
  │  GET /api/bus/defects         [planned US2]   │
  └───────────────────────────────────────────────┘
```

### Producer-Consumer Split

The hot/cold split is enforced by contract:

| Path | What | Budget |
|------|------|--------|
| `on_bus_event()` | Dict projection + queue enqueue | ≤1ms p99 |
| `writer_loop()` | JSONL write + fsync + index upsert | no constraint |

The hot path never does I/O. The cold path fsyncs per event under `fcntl.flock(LOCK_EX)`.

---

## Data Model (Pydantic v2 — Single Source of Truth)

All models live in `src/agent_bus_analyzer/models.py`. The file mirrors
`specs/001-enhanced-agent-bus-analysis/data-model.md` and the JSON Schema contracts
in `contracts/`. The schema export test (`test_schema_export.py`) catches drift.

### Core Entities

**[Event](src/agent_bus_analyzer/models.py)** — A single captured observation
(see lines 54-74 in the current source snapshot).

| Field | Type | Constraint |
|-------|------|------------|
| `event_id` | `str` | UUIDv7 |
| `correlation_id` | `str` | FK to Trace; regex-validated for path safety |
| `causal_index` | `int` | `ge=0`; monotonic within trace |
| `recorded_at` | `datetime` | Capture clock (not bus clock — we don't trust sources) |
| `source_agent` | `str` | `<role>:<instance>` |
| `target_handler_declared` | `str \| None` | What the dispatcher tried |
| `target_handler_resolved` | `str \| None` | What actually answered |
| `payload_ref` | `str` | `sha256:<hex>` — opaque ref, never inline payload |
| `kind` | `Literal["dispatch","response","decision"]` | Three observation kinds |
| `decision` | `Literal["allow","deny","transform","escalate"] \| None` | From gove-zone |
| `flagged_rule` | `str \| None` | First matched rule on deny/escalate |
| `audit_receipt_hash` | `str \| None` | Joins to gove-zone Receipt chain |
| `constitutional_hash` | `str` | 16-char hex; per-event to detect rotation |
| `event_hash` | `str` | SHA-256 hex; computed at append time |
| `prev_hash` | `str \| None` | Links to predecessor in chain |
| `status` | `EventStatus` | Classified at observation time |
| `gap_started_at` / `gap_ended_at` | `datetime \| None` | Only for ingest-gap |

**[Trace](src/agent_bus_analyzer/models.py)** — One governance-relevant run
(see lines 77-87 in the current source snapshot).

| Field | Type |
|-------|------|
| `correlation_id` | `str` |
| `started_at` / `completed_at` | `datetime` / `datetime \| None` |
| `constitutional_hash` | `str` (16-char) |
| `event_count` | `int` (ge=0) |
| `integrity_status` | `Literal["intact","tampered","unknown"]` |
| `worst_event_status` | `EventStatus` |
| `events` | `list[Event]` |

### EventStatus Enum

```
completed         — normal dispatch → response, no violations
policy-violation  — decision=deny or escalate-with-deny; flagged_rule set
dispatch-failure  — no response within timeout (US2)
unwired-handler   — dispatch targeted handler with no registry entry (US2)
orphan-response   — response with no prior dispatch (US2)
incomplete-pair   — dispatch recorded, response never arrived (US2)
ingest-gap        — synthetic marker; out-of-chain
```

### Pydantic Strictness

The base class `_Strict` sets `model_config = ConfigDict(extra="forbid")`. Every
model inherits this — unknown fields in API responses or stored data raise validation
errors. This is how we catch contract drift between the Python models and the TypeScript
console.

### ConstitutionalHashStr and EventHashStr

Type-level validation via `Annotated`:
- `ConstitutionalHashStr`: 16-char hex (`^[a-f0-9]{16}$`)
- `EventHashStr`: 64-char SHA-256 hex (`^[a-f0-9]{64}$`)

---

## Hash-Chain Integrity

### Chain Rule

```
event_hash = sha256(canonical_json(event minus event_hash))
prev_hash  = predecessor's event_hash (None for first event)
```

The chain rule mirrors `gove_zone.audit.ChainHashAuditStore` so the two chains can
cross-validate.

### canonical_json()

Sorted keys, no whitespace, UTF-8 (`ensure_ascii=False`), compact separators.
Defined in [`hashing.py`](src/agent_bus_analyzer/hashing.py), lines 26-33 in
the current source snapshot.

### compute_event_hash()

Copies the event dict, strips `event_hash`, serializes to canonical JSON, then
SHA-256. The caller sets `prev_hash` on the dict before calling — that field is
part of the hashed input (`hashing.py:36-46`).

### Verification

`TraceStore._verify_chain()` replays every event against the stored hashes. It
verifies against **raw parsed JSON dicts**, not Pydantic-projected instances,
because Pydantic's datetime serialization differs from `canonical_json` output.

Three outcomes:
- `"intact"` — all event_hashes recompute correctly, prev_hash chain unbroken
- `"tampered"` — any hash mismatch or chain break detected
- `"unknown"` — empty trace (no events to verify)

### ingest-gap Events

Ingest-gap markers do NOT participate in the hash chain (`prev_hash=None`).
They describe gaps in capture — chaining them would mean we lied about what
we captured. The event after a gap references the last real event's hash.

---

## Storage Design: JSONL + SQLite Dual-Store

### File Layout

```
var/agent-bus-analyzer/
├── traces/
│   ├── {correlation_id}.jsonl    ← integrity source of truth
│   └── {correlation_id}.jsonl.lock ← fcntl lock file
└── index.sqlite                  ← rebuildable derived index
```

Per-correlation-id files (not date-rotated). This deviates from `plan.md`'s
date-rotation default — date rotation is deferred to a follow-up.

### SQLite Index (`index.sqlite`)

Schema (`store.py:81-93`):
```sql
CREATE TABLE IF NOT EXISTS traces (
    correlation_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    constitutional_hash TEXT NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 0,
    worst_event_status TEXT NOT NULL DEFAULT 'completed',
    integrity_status TEXT NOT NULL DEFAULT 'unknown',
    status TEXT NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS traces_started_at ON traces(started_at);
```

The SQLite file is explicitly NOT on the integrity path — it is rebuildable
from the JSONL files. The class docstring states this at line 1-17.

### Concurrency

`fcntl.flock(LOCK_EX)` serializes writes per trace file. The lock is released
after fsync. This mirrors gove-zone's ChainHashAuditStore discipline.

SQLite access is serialized via `threading.Lock` (`_db_lock`) because FastAPI
dispatches handlers across threads. `check_same_thread=False` is deliberate.

### Writer Loop

`store.writer_loop()` drains the CaptureQueue. Key behaviors:
- **Gap-first**: if a gap is open and we have a trace context, flush the marker
  BEFORE clearing counters — if the write fails before close_gap runs, counters
  are preserved and retried next iteration. This is Architect blocker #2.
- **Idle timeout**: 0.5s `wait_for` on the queue. On idle, still flushes pending
  gaps if a target trace is known.
- **drain_on_idle**: exits when queue empties (test-only; production never drains).

### Path Safety

`_safe_correlation_id()` (`store.py:52-63`) is the ONLY path-component sanitizer
in the codebase. It enforces:
- Regex: `^[A-Za-z0-9._-]{1,128}$`
- Rejects `.`, `..`, hidden-file conventions
- Raises `ReadOnlyViolation` on any violation

`_trace_path()` additionally validates that the resolved path stays under the
`traces/` root (`Path.is_relative_to()`), preventing symlink escapes.

---

## Observer: Hot Path vs Cold Path

### Projection Functions

**`project_bus_event(msg, constitutional_hash)`** — Maps AgentMessage fields
to Event shape. Key mappings:

| AgentMessage field | Event field |
|-------------------|-------------|
| `message_id` | `event_id` |
| `conversation_id` | `correlation_id` (synthesized if missing) |
| `from_agent` | `source_agent` |
| `to_agent` | `target_handler_declared` |
| payload (sha256) | `payload_ref` |
| capture clock | `recorded_at` |

`causal_index`, `event_hash`, and `prev_hash` are NOT set here — they are
filled by `TraceStore.append()`.

**`project_audit_record(record, constitutional_hash)`** — Maps gove-zone
audit Receipt lines to `kind="decision"` events. Matches `event_id` for
joining and extracts `matched_rules[0]` as `flagged_rule` when the decision
is `deny` or `escalate`.

### Observer.attach(bus)

Registers `on_bus_event()` callback via `bus.subscribe()`. The callback:
1. Projects the message dict
2. Calls `queue.try_put()` (non-blocking)

Returns in ≤1ms p99 — no I/O.

### Audit-Tail Follower

`follow_audit_file()` opens the gove-zone JSONL in `O_RDONLY`, polls file
size at 250ms intervals, and dispatches each new line via the callback.

Fail-closed: raises `IntegrityStoreUnavailable` on boot if file missing; exits
if file vanishes during operation (FR-008).

---

## CaptureQueue: Backpressure Without Bus-Blocking

The `CaptureQueue` (`capture.py`) is a bounded `asyncio.Queue` wrapper that
enforces FR-013: "handle backpressure by recording ingest-gap markers, never
by blocking the bus."

### Key Design

- **`try_put(event) -> bool`**: Non-blocking enqueue. Returns `False` on drop
  (queue full). Opens a gap window and increments the dropped counter. Caller
  MUST NOT retry.
- **`peek_gap()`**: Returns current gap state WITHOUT clearing counters. Caller
  must invoke `close_gap()` only after the gap marker durably lands on disk.
  This two-phase design prevents silent gap loss on crash.
- **`close_gap()`**: Resets counters. Returns the closed gap stats.

Default capacity: 10,000 events.

### Gap Marker Flow

1. Queue fills → `try_put()` returns `False` → gap opens
2. Writer drains queue back below capacity
3. Writer loop detects `queue.gap_open()`
4. Writer calls `queue.peek_gap()` → gets (start, end, count)
5. Writer writes `ingest-gap` marker to disk (fsync)
6. Writer calls `queue.close_gap()` → gap closed

If step 5 crashes, counters survive and retry on next iteration.

---

## Classification

`classify(event)` (`classifier.py:21-29`) assigns `EventStatus`. US1 scope:
only `completed` and `policy-violation`. Default is `completed` — per FR-006,
the default is the observed positive class, not "unknown".

**policy-violation** rules:
- `kind="decision"` AND `decision="deny"` → policy-violation
- `kind="decision"` AND `decision="escalate"` AND `flagged_rule` set → policy-violation

US2 extends with `dispatch-failure`, `unwired-handler`, `orphan-response`,
`incomplete-pair` — deferred to T040.

---

## API Surface

FastAPI app factory (`create_app(store)`) at `api.py:37-93`.
Mounted at `/api/bus` with docs at `/api/bus/_docs`.

### Endpoints

| Method | Path | RBAC | Status |
|--------|------|------|--------|
| GET | `/api/bus/healthz` | none | Implemented |
| GET | `/api/bus/traces?limit=N` | `require_reviewer_role` | Implemented (US1) |
| GET | `/api/bus/traces/{correlation_id}` | `require_reviewer_role` | Implemented (US1) |
| GET | `/api/bus/defects` | planned | Not mounted (US2) |

### Response Models

- `TraceList` for list endpoint — computed integrity_status at query time
- `SingleTrace` for detail endpoint — includes events array, rotation detection
- All validated against `contracts/trace-query.schema.json` via Pydantic

### Middleware

Structured logging middleware logs `method`, `path`, `status`, `elapsed_ms`
for every request. No middleware on the authorization path.

---

## Auth / RBAC

`require_reviewer_role()` FastAPI dependency (`auth.py:99-129`).

### Design

- Bearer token extraction from `Authorization` header
- Pluggable validator via `set_validator(fn)` — test injects fake; production
  wires to console identity layer (deferred)
- Default validator denies everything (fail-closed): if operator forgets to
  wire the real validator, the surface returns 401
- Allowed roles: `governance-reviewer`, `operator`, `compliance`

### Audit Trail (FR-011)

Every rejection (401 missing bearer, 401 invalid token, 403 insufficient role)
is appended to the TraceStore as a synthetic event:
- `kind="decision"`, `decision="deny"`
- `source_agent="api:query"`
- `correlation_id=f"rbac-{YYYYMMDD}"`
- `flagged_rule=f"rbac.{reason}"`
- `status="policy-violation"`

Rejection audit is best-effort — if the store write fails, the 401/403 still
fires. The exception is logged but never swallowed.

---

## CLI

Entry point: `python -m agent_bus_analyzer <subcommand>` (`cli.py`).

### Subcommands

| Command | Status | Description |
|---------|--------|-------------|
| `serve` | Implemented | Run FastAPI via uvicorn (port 8042) |
| `observer` | Implemented | Boot audit-tail + writer loop (US1) |
| `verify` | Stub | Hash-chain verification (US3) |
| `dev-traffic` | Stub | Canned traffic generator (Polish) |

### Observer CLI

Wires `CaptureQueue` → `TraceStore.writer_loop()` + `follow_audit_file()`.
Fail-closed: exits 1 if `--audit-file` missing/unreadable.

Status line: one-line-per-second format showing `queue=N/capacity ingest_gap=open|closed`.

Note: live bus subscription (via `Observer.attach()`) is exercised by
dispatcher-level test T016, but orchestrating an in-process LocalEventBus
from the CLI is a follow-up.

---

## Config

`AnalyzerConfig` (`config.py`) — frozen dataclass with defaults:

| Field | Default |
|-------|---------|
| `queue_capacity` | 10,000 |
| `dispatch_timeout_seconds` | 30 |
| `registry_poll_seconds` | 30 |
| `retention_days` | 90 |

**Constitutional hash resolution**: env-only (`CONSTITUTIONAL_HASH`). The plan
permits fallback to `ACGS.src.core.shared.constants` — that is deferred to US1
to keep Foundational decoupled from ACGS imports (see config.py:8-10).

Fail-closed: if env var is unset or doesn't match `^[a-f0-9]{16}$`, raises
`IntegrityStoreUnavailable`.

---

## Exception Hierarchy

All exceptions defined in [`errors.py`](src/agent_bus_analyzer/errors.py):

| Exception | Maps to | Purpose |
|-----------|---------|---------|
| `IntegrityStoreUnavailable(RuntimeError)` | FR-008 | Audit store missing/unreadable; fail-closed |
| `ReadOnlyViolation(RuntimeError)` | FR-003, FR-010 | Mutation attempt on read-only surface |
| `BackpressureDropped(RuntimeWarning)` | FR-013 | Capture queue dropped event |
| `CorrelationSynthesized(UserWarning)` | Observer contract | Missing correlation_id, synthetic assigned |

---

## Test Suite

### Coverage

69 tests across 17 test files. Organized by concern:

| Test file | Lines | What it covers |
|-----------|-------|----------------|
| `test_schema_export.py` | 162 | Pydantic → JSON Schema contract drift detection |
| `test_chain_integrity.py` | 88 | Hash-chain tamper detection: byte flip, missing prev_hash |
| `test_backpressure_gap_marker.py` | 90 | Queue saturation → gap marker emission |
| `test_bus_dispatch_capture.py` | 63 | **Constitution Principle III**: `bus.publish()` → observer capture |
| `test_capture_readonly.py` | 80 | FR-003: bus events unchanged after capture |
| `test_capture.py` | 51 | Capture queue basic behavior |
| `test_classifier.py` | 30 | US1 classification: completed, policy-violation |
| `test_cli.py` | 31 | CLI argument parsing |
| `test_config.py` | 64 | Config loading, hash validation, fail-closed |
| `test_auth.py` | 45 | RBAC dependency: bearer extraction, role enforcement |
| `test_auth_audits_rejections.py` | 58 | FR-011: rejection audit events |
| `test_query_by_correlation.py` | 69 | Trace query by correlation_id, causal ordering |
| `test_api.py` | 35 | API healthz and basic HTTP |
| `test_api_traces.py` | 104 | API trace endpoints end-to-end |
| `test_hashing.py` | 47 | canonical_json + compute_event_hash |
| `test_config.py` | 64 | Config resolution, hash format validation |

### Dispatcher-Level Tests (Constitution Principle III)

`test_bus_dispatch_capture.py` is the canonical dispatcher-level test:
- Boots a real `EnhancedAgentBus`
- Attaches observer via `observer.attach(bus)`
- Publishes via `bus.publish()`
- Asserts within 5s the store has the matching event with correct fields
- Never calls classifier/store functions directly

`test_backpressure_gap_marker.py` exercises the full capture → gap → recovery path.

---

## Implementation Status vs Plan

### Phase 1: Setup — COMPLETE

All T001–T007 Done:
- Package skeleton, pyproject.toml, README, CLAUDE.md, Makefile
- JSON Schema contracts in `contracts/`
- Console route stub `bus-analysis-client.ts` (per CLAUDE.md: US1 console work planned but not implemented)

### Phase 2: Foundational — COMPLETE

All T008–T014, T069 Done:
- Pydantic v2 models with validation
- `hashing.py`: canonical JSON + SHA-256 chain primitive
- `errors.py`: 4 exception types
- `config.py`: env-based config + constitutional-hash resolution
- `capture.py`: bounded CaptureQueue with ingest-gap tracking
- `api.py`: FastAPI app factory with structured logging middleware
- Schema export test (T013): 162 lines verifying no model/schema drift
- T069: app factory + healthz + middleware

### Phase 3: US1 — SUBSTANTIALLY COMPLETE

| Task | Status | Notes |
|------|--------|-------|
| T015 test_capture_readonly | Done | 80 lines |
| T016 test_bus_dispatch_capture | Done | 63 lines, dispatcher-level |
| T017 test_query_by_correlation | Done | 69 lines |
| T018 test_backpressure_gap_marker | Done | 90 lines |
| T021 Observer.attach(bus) | Done | observer.py |
| T022 audit-tail follower | Done | follow_audit_file() |
| T023 JSONL append store | Done | store.py (full) |
| T024 SQLite derived index | Done | store.py |
| T025 classifier | Done | US1 scope only |
| T026 writer_loop | Done | store.py |
| T027 query API | Done | query.py |
| T028 RBAC dependency | Done | auth.py (133 lines) |
| T029–T032 Console (TS) | NOT DONE | Console frontend not built |

### Not Yet Implemented

- **US2 (Phase 4)**: `wiring.py` (HandlerRegistrySnapshot, wiring defect detection), classifier extension, `GET /api/bus/defects`
- **US3 (Phase 5)**: `verify` CLI implementation, fail-closed integrity store check at observer boot (currently only: audit file existence check)
- **Polish (Phase 6)**: Retention enforcement, `dev-traffic` CLI, latency benchmarks, end-to-end dry-run
- **Console frontend**: TypeScript `BusAnalysis` page at `/console/bus`, typed client, React hook

---

## Design Deviations from plan.md

1. **Per-correlation-id files, not date-rotated.** Date rotation (`<YYYY-MM-DD>.jsonl`) is deferred. Per-correlation-id `{cid}.jsonl` keeps reads O(1) and integrity verification local. Documented in `store.py:1-17`.

2. **US1 observer CLI fires without live bus.** The `observer` subcommand wires `writer_loop` + `follow_audit_file` but does NOT orchestrate an in-process `LocalEventBus`. Live bus capture is exercised by the dispatcher-level test T016. CLI comment at `cli.py:72-74`.

3. **Constitutional hash resolution: env only.** The plan permits fallback to `ACGS.src.core.shared.constants` — deferred to keep Foundational phase decoupled from ACGS imports.

4. **Console frontend deferred.** The TypeScript page, typed client, and route wiring (T029–T032) were not built in this pass. The backend API and Python package are fully implemented and independently testable.

5. **`ingest-gap` chain rule clarified.** The data model spec says gap events carry a `recovered_at_hash` dimension. The implementation instead sets `prev_hash=None` (simpler, equally correct — the event after a gap just chains from the last real event). This matches `store.py:151-152`.

---

## Verification Gate

```bash
cd packages/agent-bus-analyzer
make verify   # = lint + typecheck + test
```

| Gate | Result |
|------|--------|
| `ruff check .` | All checks passed! |
| `mypy src/` | Success: no issues found in 14 source files |
| `pytest -q` | 69 passed in 3.63s |

---

## Subproject Boundaries (Constitution Principle II)

The analyzer consumes public surfaces from:
- `EnhancedAgentBus` (via `bus.subscribe()`)
- `gove-zone` audit JSONL (via `O_RDONLY` tail)

It never:
- Edits files inside `packages/enhanced_agent_bus/`, `packages/gove-zone/`, `packages/acgs-lite/`
- Mutates `BusEvent` objects
- Writes to the gove-zone audit JSONL (`O_RDWR`)
- Participates in allow/deny decision flows

---

## Where to Look

| What | File |
|------|------|
| Pydantic models (source of truth) | `src/agent_bus_analyzer/models.py` |
| Hash chain primitive | `src/agent_bus_analyzer/hashing.py` |
| Observer + audit tail | `src/agent_bus_analyzer/observer.py` |
| App store (JSONL + SQLite) | `src/agent_bus_analyzer/store.py` |
| Capture queue (backpressure) | `src/agent_bus_analyzer/capture.py` |
| FastAPI app + endpoints | `src/agent_bus_analyzer/api.py` |
| RBAC dependency | `src/agent_bus_analyzer/auth.py` |
| Classifier | `src/agent_bus_analyzer/classifier.py` |
| Config resolver | `src/agent_bus_analyzer/config.py` |
| CLI entry | `src/agent_bus_analyzer/cli.py` |
| Query facade | `src/agent_bus_analyzer/query.py` |
| Error types | `src/agent_bus_analyzer/errors.py` |
| JSON Schema contracts | `contracts/trace-event.schema.json`, `trace-query.schema.json` |
| Spec / plan / tasks | `../../specs/001-enhanced-agent-bus-analysis/` |
