# Phase 1 — Data Model: Enhanced Agent Bus Analysis

**Branch**: `001-enhanced-agent-bus-analysis` | **Date**: 2026-05-14

All entities are defined in `packages/agent-bus-analyzer/src/agent_bus_analyzer/models.py` as Pydantic v2 models, exported to JSON Schema for the TypeScript console.

---

## Trace

A complete record of one governance-relevant run.

| Field | Type | Notes |
|---|---|---|
| `correlation_id` | `str` | Stable per-run identifier (UUIDv7 preferred). Indexed in SQLite. |
| `started_at` | `datetime` | Earliest event's wall-clock timestamp. |
| `completed_at` | `datetime \| None` | Latest event's timestamp, or `None` if open. |
| `constitutional_hash` | `str` | Active hash at trace start. Per-event hash is recorded separately; this is the header value (see Edge Case: rotation). |
| `event_count` | `int` | Cardinality, kept for fast list rendering without scanning JSONL. |
| `integrity_status` | `Literal["intact", "tampered", "unknown"]` | Computed at query time from chain re-hash. |
| `worst_event_status` | `Literal[...]` | Aggregated badge for the trace list view. |
| `events` | `list[Event]` | Loaded lazily; not embedded in trace list responses. |

**Validation rules**:
- `correlation_id` MUST be present on every persisted event; events without it are routed to a synthetic `orphan-events` trace.
- `event_count` MUST equal `len(events)` when fully loaded; mismatch flips `integrity_status` to `tampered`.
- A Trace is never deleted; expiry moves its underlying JSONL file to `expired/` and flags `status=expired` in the SQLite row (FR-012 + R9).

**State transitions**:
```
new (no events yet)
  → open (≥1 event recorded, completed_at is None)
  → closed (a terminal event or a configured idle timeout reached)
  → expired (retention boundary passed; queries return status=expired)
```

---

## Event

A single dispatch-or-response observation on the bus, or a `Decision` receipt from the gove-zone audit tail.

| Field | Type | Notes |
|---|---|---|
| `event_id` | `str` | UUIDv7. Unique per event across all traces. |
| `correlation_id` | `str` | FK to Trace. |
| `causal_index` | `int` | Monotonic within a trace; used to order events deterministically. |
| `recorded_at` | `datetime` | Wall-clock observation time (capture-side, not bus-side, since we don't trust the source clock). |
| `source_agent` | `str` | `<role>:<instance>` (e.g., `claude:worker-03`). Parses to `role=unknown` if no colon (legacy). |
| `target_handler_declared` | `str \| None` | What the dispatcher TRIED to route to (handler-name string from the bus payload). |
| `target_handler_resolved` | `str \| None` | What actually answered. None for dispatch-failures. |
| `payload_ref` | `str` | Opaque reference (hash or storage key) — we record a reference, not the payload bytes, to keep JSONL bounded. |
| `kind` | `Literal["dispatch", "response", "decision"]` | Three observable kinds: bus dispatch, bus response, gove-zone decision receipt. |
| `decision` | `Literal["allow", "deny", "transform", "escalate"] \| None` | Populated when `kind="decision"`; mirrors `gove_zone.decision.Decision`. |
| `flagged_rule` | `str \| None` | For policy-violation classification; the rule identifier that fired. |
| `audit_receipt_hash` | `str \| None` | If a gove-zone `Receipt` exists for this event, its `audit_hash` joins the two chains. |
| `constitutional_hash` | `str` | Hash active at capture time. Repeated per-event to detect mid-run rotation. |
| `event_hash` | `str` | SHA-256(canonical_json(this event minus event_hash) + prev_hash). |
| `prev_hash` | `str \| None` | Predecessor event_hash in the same trace; None for the trace's first event. |
| `status` | `EventStatus \| None` | See enum below. None when `marker_kind` is set (markers are not classifiable bus events). |
| `marker_kind` | `Literal["ingest-gap"] \| None` | Set when the row is a synthetic capture marker rather than an observed bus event. Mutually exclusive with `status`. |
| `gap_started_at` | `datetime \| None` | Populated only when `marker_kind="ingest-gap"`. |
| `gap_ended_at` | `datetime \| None` | Populated only when `marker_kind="ingest-gap"`. |

### EventStatus

```
completed         — dispatch followed by matching response, no policy violation
policy-violation  — decision=deny (or escalate with deny outcome); flagged_rule set
dispatch-failure  — no response within timeout; exception or rejection captured
unwired-handler   — dispatch targeted a handler with no live registry entry
orphan-response   — response with no prior dispatch (correlation_id known but causal_index has no producer)
incomplete-pair   — dispatch recorded but observer crashed before response landed
```

Note: `ingest-gap` is NOT an `EventStatus`. Capture gaps are recorded via the separate `marker_kind` field so that markers are excluded from classification metrics (SC-002) and from the hash chain.

**Validation rules**:
- `causal_index` MUST be strictly monotonic per `correlation_id`; non-monotonic insert flips trace `integrity_status` to `tampered`.
- `event_hash` MUST verify against re-computed canonical JSON; any mismatch flips integrity to `tampered`.
- An event with `kind="dispatch"` and no matching response within `dispatch_timeout_seconds` (config, default 30) MUST be classified `dispatch-failure` or `unwired-handler`. The two are distinguished by whether `target_handler_declared` is present in the `HandlerRegistrySnapshot` at the time of dispatch.
- Exactly one of `status` or `marker_kind` MUST be set on every row.
- Rows with `marker_kind="ingest-gap"` MUST NOT participate in the hash chain — they describe gaps in capture, so chaining them would mean we lied about what we captured. Instead, the `prev_hash` of the event immediately after a gap references the `event_hash` of the event immediately before the gap, and the gap marker is recorded as a separate row in SQLite with a `recovered_at_hash` field pointing to the post-gap event that re-anchors the chain.
- Classification accuracy metrics (SC-002) are computed against rows where `status IS NOT NULL`; marker rows are excluded from the denominator.

---

## HandlerRegistrySnapshot

The set of handlers known to the bus runtime at a point in time. Sampled on a fixed interval (default 30s) and on every observer reconnect.

| Field | Type | Notes |
|---|---|---|
| `snapshot_id` | `str` | UUIDv7. |
| `sampled_at` | `datetime` | When the registry was read. |
| `handlers` | `dict[str, HandlerDescriptor]` | Keyed by handler name. |
| `source` | `Literal["enhanced_agent_bus", "gove_zone_kernel"]` | Which registry we read. |

### HandlerDescriptor

| Field | Type | Notes |
|---|---|---|
| `name` | `str` | The registered name. |
| `declared_in_source` | `bool` | True if a `@kernel.tool(...)` or equivalent decorator exists in the codebase (resolved via best-effort static introspection). |
| `registered_in_runtime` | `bool` | True if present in the snapshot. The combination `declared_in_source=True ∧ registered_in_runtime=False` is the canonical "unwired handler" signal. |
| `last_seen_at` | `datetime \| None` | Last snapshot in which the handler appeared registered. |

---

## WiringDefectFinding

A derived record. Not stored in the JSONL chain; recomputed on demand from `HandlerRegistrySnapshot` + the most recent N events.

| Field | Type | Notes |
|---|---|---|
| `finding_id` | `str` | UUIDv7. |
| `detected_at` | `datetime` | |
| `kind` | `Literal["unwired_dispatch", "declared_but_unrouted"]` | |
| `handler_name` | `str` | |
| `expected_role` | `str \| None` | Parsed from the related event's `source_agent` where available. |
| `example_event_ids` | `list[str]` | Up to 5 representative `event_id`s that exhibit the defect. |

**Validation rules**:
- A finding is surfaced only when it has at least one supporting event_id in the configured time window (default 60s — matches SC-003).
- Findings are idempotent on `(kind, handler_name)`; refreshing the summary updates `detected_at` and `example_event_ids` rather than creating duplicates.

---

## ConstitutionalHashAnchor

A reference, not a separate stored entity — recorded on every Event. Surfaced as its own concept in the data model because the spec explicitly tracks it (Key Entities §5).

| Field | Type | Notes |
|---|---|---|
| `hash` | `str` | The active hash (e.g., `608508a9bd224290`). |
| `source` | `Literal["env", "constant", "unset"]` | How we resolved it at capture time; helps diagnose drift between env and the constants file. |
| `recorded_at` | `datetime` | Capture-side timestamp; identical to the parent Event's `recorded_at`. |

---

## Relationships

```
Trace 1 ─────* Event
                │
                │   joins to (when kind=decision)
                ▼
              gove-zone Receipt (read-only reference via audit_receipt_hash)

Trace ───── snapshot ──── HandlerRegistrySnapshot (point-in-time)

WiringDefectFinding ──── derived from ──── HandlerRegistrySnapshot + Event*

ConstitutionalHashAnchor ─── embedded on every Event
```
