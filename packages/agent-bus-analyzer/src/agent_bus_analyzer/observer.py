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
    event["status"] = classify(event)
    return event


def project_audit_record(record: dict[str, Any], constitutional_hash: str) -> dict[str, Any]:
    """Project a gove-zone audit Receipt line into our Event shape (kind=decision)."""
    correlation_id = str(record.get("conversation_id") or record.get("event_id") or uuid.uuid4())
    event_id = str(record.get("event_id") or uuid.uuid4())
    actor = record.get("actor") or "unknown"
    decision = record.get("decision")
    matched_rules = record.get("matched_rules") or []
    flagged_rule = matched_rules[0] if matched_rules and decision in ("deny", "escalate") else None
    cons_hash = _truncate_hash16(str(record.get("constitutional_hash") or constitutional_hash))
    event: dict[str, Any] = {
        "event_id": event_id,
        "correlation_id": correlation_id,
        "recorded_at": datetime.now(UTC).isoformat(),
        "source_agent": str(actor),
        "target_handler_declared": record.get("tool_name"),
        "target_handler_resolved": record.get("tool_name"),
        "payload_ref": _payload_ref(record.get("args") or {}),
        "kind": "decision",
        "decision": decision,
        "flagged_rule": flagged_rule,
        "audit_receipt_hash": record.get("event_hash"),
        "constitutional_hash": cons_hash,
    }
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
