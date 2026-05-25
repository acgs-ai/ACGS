"""Observer — subscribes to LocalEventBus + gove-zone audit JSONL.

Read-only on both upstream surfaces (FR-003 / FR-010). The callback the
bus invokes does only one thing: project the AgentMessage dict into our
internal Event shape and enqueue it onto the CaptureQueue. Persistence
happens on the writer task, never on the hot path.

US1 scope: every captured bus message is recorded as ``kind="dispatch"``.
Response-pair detection via conversation_id is a follow-up — the
classifier currently maps gove-zone ``Decision`` receipts (kind="decision")
to ``policy-violation``, which is the load-bearing class for US1
acceptance scenario 2.

Audit-tail follower: opens the gove-zone JSONL in ``O_RDONLY``, tails it,
emits one ``kind="decision"`` event per record. The tailer never writes;
if the file is unreachable on boot, the observer fails closed
(``IntegrityStoreUnavailable``) per FR-008.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent_bus_analyzer.capture import CaptureQueue
from agent_bus_analyzer.classifier import classify
from agent_bus_analyzer.errors import IntegrityStoreUnavailable

log = logging.getLogger("agent_bus_analyzer.observer")

# Structural typing — accept any object exposing the subscribe contract.
BusLike = Any


def _payload_ref(payload: dict[str, Any]) -> str:
    """Stable opaque ref. We never inline payload bytes into the trace."""
    body = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _truncate_hash16(value: str) -> str:
    """Project a constitutional-hash string to the 16-char form the schema expects."""
    v = value.strip().lower()
    return v[:16]


_TRACEPARENT_RE = re.compile(
    r"^(?P<version>[0-9a-f]{2})-"
    r"(?P<trace_id>[0-9a-f]{32})-"
    r"(?P<parent_id>[0-9a-f]{16})-"
    r"(?P<trace_flags>[0-9a-f]{2})(?:-.*)?$"
)

_TRACE_ID_KEYS = ("phoenix_trace_id", "otel_trace_id", "trace_id")
_SPAN_ID_KEYS = ("phoenix_span_id", "otel_span_id", "span_id")
_PARENT_SPAN_ID_KEYS = (
    "phoenix_parent_span_id",
    "otel_parent_span_id",
    "parent_span_id",
    "parent_id",
)
_TRACEPARENT_KEYS = ("traceparent", "Traceparent")
_NESTED_CONTEXT_KEYS = ("headers", "metadata", "trace_context", "otel", "context")


def _normalize_hex_id(value: Any, *, length: int) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    if len(candidate) != length:
        return None
    if not all(char in "0123456789abcdef" for char in candidate):
        return None
    if set(candidate) == {"0"}:
        return None
    return candidate


def _string_field(record: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _candidate_context_records(*records: Any) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        candidates.append(record)
        for nested_key in _NESTED_CONTEXT_KEYS:
            nested = record.get(nested_key)
            if isinstance(nested, dict):
                candidates.append(nested)
    return candidates


def _parse_traceparent(value: str | None) -> tuple[str, str] | None:
    if value is None:
        return None
    match = _TRACEPARENT_RE.match(value.strip().lower())
    if match is None:
        return None
    trace_id = _normalize_hex_id(match.group("trace_id"), length=32)
    parent_id = _normalize_hex_id(match.group("parent_id"), length=16)
    if trace_id is None or parent_id is None:
        return None
    return trace_id, parent_id


def _extract_phoenix_trace_context(*records: Any) -> dict[str, str]:
    """Extract OpenTelemetry/Phoenix ids from known bus/audit carrier fields.

    ``traceparent`` supplies the trace id plus upstream parent span id. Explicit
    ``span_id``/``phoenix_span_id`` fields win for the current span because the
    W3C parent-id field names the caller-side span, not a newly-created span.
    """
    phoenix_trace_id: str | None = None
    phoenix_span_id: str | None = None
    phoenix_parent_span_id: str | None = None

    for candidate in _candidate_context_records(*records):
        parsed_traceparent = _parse_traceparent(_string_field(candidate, _TRACEPARENT_KEYS))
        if parsed_traceparent is not None:
            trace_id, parent_id = parsed_traceparent
            phoenix_trace_id = phoenix_trace_id or trace_id
            phoenix_parent_span_id = phoenix_parent_span_id or parent_id

        phoenix_trace_id = phoenix_trace_id or _normalize_hex_id(
            _string_field(candidate, _TRACE_ID_KEYS),
            length=32,
        )
        phoenix_span_id = phoenix_span_id or _normalize_hex_id(
            _string_field(candidate, _SPAN_ID_KEYS),
            length=16,
        )
        phoenix_parent_span_id = phoenix_parent_span_id or _normalize_hex_id(
            _string_field(candidate, _PARENT_SPAN_ID_KEYS),
            length=16,
        )

    trace_context: dict[str, str] = {}
    if phoenix_trace_id:
        trace_context["phoenix_trace_id"] = phoenix_trace_id
    if phoenix_span_id:
        trace_context["phoenix_span_id"] = phoenix_span_id
    if phoenix_parent_span_id:
        trace_context["phoenix_parent_span_id"] = phoenix_parent_span_id
    return trace_context


def project_bus_event(msg: dict[str, Any], constitutional_hash: str) -> dict[str, Any]:
    """Project an AgentMessage dict from LocalEventBus into our Event shape.

    Field mapping (lossy — only what the trace store needs):
      - message_id        -> event_id
      - conversation_id   -> correlation_id (synthesized if missing)
      - from_agent        -> source_agent
      - to_agent          -> target_handler_declared
      - payload (sha256)  -> payload_ref
      - capture clock     -> recorded_at  (we don't trust source clocks)

    ``causal_index``, ``event_hash``, and ``prev_hash`` are filled by the
    store at append time — see TraceStore.append.
    """
    correlation_id = str(msg.get("conversation_id") or msg.get("correlation_id") or uuid.uuid4())
    source_agent = msg.get("from_agent") or msg.get("sender_id") or "unknown"
    target = msg.get("to_agent") or None
    event_id = str(msg.get("message_id") or uuid.uuid4())
    payload: dict[str, Any] = dict(msg.get("payload") or msg.get("content") or {})
    cons_hash = _truncate_hash16(str(msg.get("constitutional_hash") or constitutional_hash))
    event: dict[str, Any] = {
        "event_id": event_id,
        "correlation_id": correlation_id,
        "recorded_at": datetime.now(UTC).isoformat(),
        "source_agent": source_agent,
        "target_handler_declared": target,
        "target_handler_resolved": None,
        "payload_ref": _payload_ref(payload),
        "kind": "dispatch",
        "decision": None,
        "flagged_rule": None,
        "audit_receipt_hash": None,
        "constitutional_hash": cons_hash,
    }
    event.update(_extract_phoenix_trace_context(msg, payload))
    event["status"] = classify(event)
    return event


def project_audit_record(record: dict[str, Any], constitutional_hash: str) -> dict[str, Any]:
    """Project a gove-zone audit receipt line into our Event shape (kind=decision).

    The live ``gove-zone`` audit chain writes canonical ``DecisionRecord``
    fields (``tool``, ``argument_hash``, ``timestamp_iso``). Older fixtures used
    ``tool_name``/``args``. Accept both shapes so the analyzer can backfill or
    tail deployed audit files without asking the runtime to emit analyzer-native
    events.
    """
    correlation_id = str(record.get("conversation_id") or record.get("event_id") or uuid.uuid4())
    event_id = str(record.get("event_id") or uuid.uuid4())
    actor = record.get("actor") or "unknown"
    decision = record.get("decision")
    matched_rules = record.get("matched_rules") or []
    flagged_rule = matched_rules[0] if matched_rules and decision in ("deny", "escalate") else None
    cons_hash = _truncate_hash16(str(record.get("constitutional_hash") or constitutional_hash))
    tool_name = (
        record.get("tool_name")
        or record.get("tool")
        or record.get("target_handler_resolved")
        or record.get("target_handler_declared")
    )
    argument_hash = record.get("argument_hash")
    if isinstance(argument_hash, str) and argument_hash:
        payload_ref = (
            argument_hash if argument_hash.startswith("sha256:") else f"sha256:{argument_hash}"
        )
    else:
        payload_ref = _payload_ref(record.get("args") or record.get("tool_input") or {})
    event: dict[str, Any] = {
        "event_id": event_id,
        "correlation_id": correlation_id,
        "recorded_at": str(record.get("timestamp_iso") or datetime.now(UTC).isoformat()),
        "source_agent": str(actor),
        "target_handler_declared": tool_name,
        "target_handler_resolved": tool_name,
        "payload_ref": payload_ref,
        "kind": "decision",
        "decision": decision,
        "flagged_rule": flagged_rule,
        "audit_receipt_hash": record.get("event_hash")
        or record.get("audit_hash")
        or record.get("audit_receipt_hash"),
        "constitutional_hash": cons_hash,
    }
    event.update(_extract_phoenix_trace_context(record))
    event["status"] = classify(event)
    return event


class Observer:
    """Subscribes to a LocalEventBus and enqueues projected events."""

    def __init__(self, queue: CaptureQueue, constitutional_hash: str) -> None:
        self._queue = queue
        self._constitutional_hash = constitutional_hash

    async def on_bus_event(self, msg: dict[str, Any]) -> None:
        """The hot-path callback. Returns ≤1 ms p99 (just dict projection + enqueue)."""
        projected = project_bus_event(msg, self._constitutional_hash)
        self._queue.try_put(projected)

    async def attach(self, bus: BusLike) -> None:
        """Register the on_bus_event callback with the bus."""
        await bus.subscribe(self.on_bus_event)


# ---- audit-tail follower -------------------------------------------------


AuditCallback = Callable[[dict[str, Any]], Awaitable[None]]


async def follow_audit_file(
    path: Path,
    *,
    on_record: AuditCallback,
    poll_interval: float = 0.25,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Tail the gove-zone audit JSONL. Read-only.

    Opens ``O_RDONLY``, follows by re-checking file size each poll. New
    lines are parsed and dispatched. Parse errors are counted and skipped,
    not retried. If the file disappears the loop exits with
    ``IntegrityStoreUnavailable`` (FR-008).
    """
    if not path.exists():
        raise IntegrityStoreUnavailable(f"audit file not present: {path}")
    fd = os.open(str(path), os.O_RDONLY)
    try:
        offset = 0
        while True:
            if stop_event is not None and stop_event.is_set():
                return
            try:
                size = os.fstat(fd).st_size
            except FileNotFoundError as exc:
                raise IntegrityStoreUnavailable(f"audit file vanished: {path}") from exc
            if size > offset:
                os.lseek(fd, offset, os.SEEK_SET)
                chunk = os.read(fd, size - offset)
                offset = size
                for line in chunk.decode("utf-8", errors="replace").splitlines():
                    clean = line.strip()
                    if not clean:
                        continue
                    try:
                        record = json.loads(clean)
                    except json.JSONDecodeError:
                        log.warning("audit.parse_error line=%s", clean[:120])
                        continue
                    await on_record(record)
            await asyncio.sleep(poll_interval)
    finally:
        os.close(fd)
