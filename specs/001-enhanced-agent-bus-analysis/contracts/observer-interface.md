# Observer Interface Contract

**Branch**: `001-enhanced-agent-bus-analysis` | **Date**: 2026-05-14

This contract defines how `agent_bus_analyzer.observer` attaches to the two upstream surfaces. **Both surfaces MUST be consumed read-only.** Mutation of bus messages, gove-zone receipts, or the existing audit JSONL is a Principle III (Fail-Closed Governance) and Principle IV (Receipt-Backed Auditability) violation — the wiring tests fail closed if attempted.

---

## Upstream Surface A — `EnhancedAgentBus`

**Module**: `ACGS/packages/enhanced_agent_bus/` (entry: `enhanced_agent_bus.bus.EnhancedAgentBus`).

**Subscription mechanism**: attach a callback via the bus's existing handler-registration API. Callback signature (this is the read-only contract — the analyzer never returns a value to the bus):

```python
async def on_bus_event(event: BusEvent) -> None:
    """Observer callback. Must return promptly (≤1 ms wall-clock budget).

    Implementation: enqueue onto an in-process bounded asyncio.Queue and
    return. Persistence happens on a separate writer task. The bus must
    never block on this callback.
    """
```

**`BusEvent` (consumed shape — opaque to us beyond these fields):**

| Field | Required | Why we read it |
|---|---|---|
| `event_id` (str) | yes | UUIDv7 used as our `event_id`. |
| `correlation_id` (str) | yes | Used as our trace key. If missing on the source, the analyzer assigns one based on (source_agent, time window) and flags the trace as `correlation_synthesized`. |
| `direction` (`"publish" \| "deliver"`) | yes | Maps to our `kind`: publish→dispatch, deliver→response. |
| `source` (str) | yes | Becomes `source_agent` (the `<role>:<instance>` convention applies). |
| `target_handler` (str \| None) | yes | Becomes `target_handler_declared`. |
| `payload_ref` (str) | yes | Stored verbatim. Bodies are never inlined. |
| `published_at` / `delivered_at` (datetime) | yes | Surface clock; we record our own `recorded_at` separately and do not trust the source clock. |

**Hard rules**:

1. The callback MUST NOT mutate `event` or any field of it.
2. The callback MUST NOT raise. If serialization or enqueue fails, the failure is logged and an `ingest-gap` marker is emitted on the next successful event — the bus is never paged for our problems.
3. The callback MUST return within 1 ms p99. Slower paths go on the writer task.
4. If the bounded queue is full, the event is dropped and the current ingest-gap window is extended. We never reach back to the bus to ask for redelivery.

---

## Upstream Surface B — gove-zone audit tail

**Module**: `packages/gove-zone/src/gove_zone/audit.py` (`ChainHashAuditStore`).

**Subscription mechanism**: tail-follow the configured audit JSONL file (e.g., `/var/log/gove-zone/audit.jsonl`). The audit writer fsyncs and then releases its `fcntl` lock; the tailer reads in append-only mode and parses one JSON record per line.

**Consumed shape (one line per record):**

| Field | Required | Why we read it |
|---|---|---|
| `event_id` (str) | yes | Becomes the matching `event_id` for the `kind="decision"` event. |
| `goal` / `tool_name` / `args` (str/dict) | yes | Joined into the event's metadata. |
| `decision` (`"allow" \| "deny" \| "transform" \| "escalate"`) | yes | Stored as `decision`. |
| `matched_rules` (list[str]) | yes | First matched rule becomes `flagged_rule` when decision is deny/escalate. |
| `actor` (str) | yes | Becomes `source_agent`. |
| `event_hash` (str) | yes | Stored as `audit_receipt_hash` to join the two chains. |
| `previous_hash` (str \| None) | yes | Validated but not stored — we maintain our own chain over a different set of fields. |

**Hard rules**:

1. The tailer MUST open the audit file in read-only mode (`O_RDONLY`). Write-mode attachment is rejected at module import.
2. If a line fails to parse, the tailer logs it, increments a parse-error counter, and continues. It does NOT seek backwards or rewrite.
3. The tailer MUST NOT delete, truncate, rotate, or compress the audit file. Log rotation is the audit writer's job; the tailer follows rotations via inode tracking only.
4. If the file is unavailable (deleted, permissions), the observer fails CLOSED — it stops emitting new analyzer events and flips the operator surface into a "degraded" state. This satisfies FR-008.

---

## Downstream surface (what the analyzer produces)

The analyzer writes JSONL files matching `contracts/trace-event.schema.json` and exposes the query API matching `contracts/trace-query.schema.json`. Both are tested by:

- `tests/test_capture_readonly.py` — replays a stream of `BusEvent`s and asserts none of them were mutated (uses `dataclasses.asdict` / object identity to detect).
- `tests/test_chain_integrity.py` — captures a synthetic trace, flips a byte in a stored JSONL event, runs `agent_bus_analyzer verify <correlation_id>`, asserts the exit code is non-zero and the report names the tampered `event_id`.
- `tests/test_bus_dispatch_capture.py` — boots `EnhancedAgentBus` (local backend), publishes a payload targeted at an unregistered handler, asserts within 60s the analyzer's store contains an event with `status="unwired-handler"` and the expected `target_handler_declared`. **This is the dispatcher-level wiring test required by Constitution Principle III** — it is the test that proves the observer is actually subscribed.

---

## Versioning

The schemas in `contracts/` are versioned by their `$id` URL. Breaking changes require:

1. A new schema URL (`v2`).
2. The analyzer ships both readers in parallel for one release.
3. The console reads via a feature flag until the new schema is the default.

The observer interface here is **not** part of the analyzer's public Python API; consumers of the package should depend only on the query API and the JSON Schemas. Internal observer details may evolve without a semver bump.
