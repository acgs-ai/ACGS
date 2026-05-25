"""Hash-chained JSONL trace store + SQLite derived index.

JSONL is the integrity source of truth; SQLite is rebuildable from JSONL.
Per-correlation-id file layout (``var/traces/{correlation_id}.jsonl``)
keeps reads O(1) and integrity verification local. This deviates from
plan.md's date-rotation default — date rotation moves to a follow-up
task if/when needed.

Chain rule: every event carries ``event_hash = sha256(canonical_json(event
minus event_hash))`` and ``prev_hash`` linking to the predecessor. The
``ingest-gap`` status is intentionally NOT part of the chain — those
events describe missing capture, not captured payload.

Writer is fsync-per-event under an ``fcntl.flock`` exclusive lock on the
chain file. Mirrors gove_zone.audit.ChainHashAuditStore's serialization
discipline so concurrent writers can never produce sibling events sharing
the same prev_hash.
"""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
import re
import sqlite3
import threading
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from agent_bus_analyzer.capture import CaptureQueue
from agent_bus_analyzer.errors import IntegrityStoreUnavailable, ReadOnlyViolation
from agent_bus_analyzer.hashing import canonical_json, compute_event_hash
from agent_bus_analyzer.models import (
    Event,
    EventStatus,
    IntegrityStatus,
    ReceiptProof,
    SingleTrace,
    TraceList,
    TraceListItem,
)
from agent_bus_analyzer.signing import sign_evidence_packet

# Strict allow-list for correlation_id. Refuses path-traversal payloads
# (../, /, NUL, whitespace) before any Path concatenation. The 1-128 range
# accommodates UUIDv7 hex forms while staying short of filesystem limits.
_CORRELATION_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _safe_correlation_id(correlation_id: str) -> str:
    """Validate or raise. The ONLY path-component sanitizer in the codebase."""
    if (
        not isinstance(correlation_id, str)
        or not _CORRELATION_ID_RE.match(correlation_id)
        or correlation_id in {".", ".."}
        or correlation_id.startswith(".")  # reject hidden-file conventions
    ):
        raise ReadOnlyViolation(f"correlation_id rejected (path-safety): {correlation_id!r}")
    return correlation_id


def _trace_path(store_dir: Path, correlation_id: str) -> Path:
    cid = _safe_correlation_id(correlation_id)
    resolved = (store_dir / "traces" / f"{cid}.jsonl").resolve()
    traces_root = (store_dir / "traces").resolve()
    if not resolved.is_relative_to(traces_root):
        raise ReadOnlyViolation(f"trace path escapes store dir: {resolved} not under {traces_root}")
    return resolved


def _index_path(store_dir: Path) -> Path:
    return store_dir / "index.sqlite"


_SCHEMA = """
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
"""

# Worst-status ordering for badge aggregation.
_STATUS_WORST_ORDER: dict[EventStatus, int] = {
    "completed": 0,
    "ingest-gap": 1,
    "incomplete-pair": 2,
    "orphan-response": 3,
    "dispatch-failure": 4,
    "unwired-handler": 5,
    "policy-violation": 6,
}


def _worst(a: EventStatus, b: EventStatus) -> EventStatus:
    return a if _STATUS_WORST_ORDER[a] >= _STATUS_WORST_ORDER[b] else b


def _receipt_matches(event: dict[str, Any], receipt_id: str) -> bool:
    return receipt_id in {
        str(event.get("event_id")),
        str(event.get("correlation_id")),
        str(event.get("audit_receipt_hash")),
        str(event.get("event_hash")),
    }


def _receipt_policy_path(events: list[Event]) -> list[str]:
    path: list[str] = []
    for event in events:
        if event.kind != "decision":
            continue
        handler = event.target_handler_resolved or event.target_handler_declared
        if handler and handler not in path:
            path.append(handler)
        if event.flagged_rule and event.flagged_rule not in path:
            path.append(event.flagged_rule)
    if path:
        return path
    for event in events:
        handler = event.target_handler_resolved or event.target_handler_declared
        if handler and handler not in path:
            path.append(handler)
    return path


def _trace_context_from_events(events: Iterable[Event]) -> dict[str, str | None]:
    context: dict[str, str | None] = {
        "phoenix_trace_id": None,
        "phoenix_span_id": None,
        "phoenix_parent_span_id": None,
    }
    for event in events:
        for field in context:
            if context[field] is None:
                context[field] = getattr(event, field)
    return context


def _non_null_trace_context(context: dict[str, str | None]) -> dict[str, str]:
    return {key: value for key, value in context.items() if value is not None}


class TraceStore:
    """Append-only chain-hashed event store with a SQLite trace index."""

    def __init__(self, store_dir: str | Path) -> None:
        self.store_dir = Path(store_dir)
        (self.store_dir / "traces").mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(
            _index_path(self.store_dir),
            isolation_level=None,
            # FastAPI dispatches handlers across threads; we serialize all
            # SQLite access via _db_lock below. flock alone is insufficient
            # because flock is per-file and the SQLite index is global.
            check_same_thread=False,
        )
        self._db_lock = threading.Lock()
        self._db.executescript(_SCHEMA)

    def close(self) -> None:
        self._db.close()

    # ---- append path ------------------------------------------------------

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        """Append *event* to its trace file. Returns the persisted dict.

        Reads the trace's last hash under an exclusive flock, fills in
        ``causal_index`` and ``prev_hash``, computes ``event_hash``, then
        writes + fsyncs + releases the lock. Concurrent appends serialize.
        """
        correlation_id = event["correlation_id"]
        path = _trace_path(self.store_dir, correlation_id)
        lock_path = path.with_suffix(path.suffix + ".lock")
        path.parent.mkdir(parents=True, exist_ok=True)

        with lock_path.open("a+") as lock_fh:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            try:
                last_hash, last_index = self._tail_state(path)
                payload = dict(event)
                payload["causal_index"] = last_index + 1
                if payload.get("status") == "ingest-gap":
                    payload["prev_hash"] = None
                else:
                    payload["prev_hash"] = last_hash
                payload.pop("event_hash", None)
                payload["event_hash"] = compute_event_hash(payload)
                line = canonical_json(payload) + "\n"
                with path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
                    fh.flush()
                    os.fsync(fh.fileno())
                self._upsert_index(payload)
                return payload
            finally:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)

    def _tail_state(self, path: Path) -> tuple[str | None, int]:
        """Return (last_chain_hash, last_causal_index_seen).

        - ``last_chain_hash`` is the event_hash of the most recent
          non-ingest-gap event (the chain successor's ``prev_hash``).
        - ``last_causal_index_seen`` is the max ``causal_index`` across
          ALL events including gap markers — so the next index is
          strictly monotonic and gap markers don't collide with the
          next real event.
        """
        if not path.exists():
            return None, -1
        last_hash: str | None = None
        last_index = -1
        for event in self._iter_file(path):
            ci = event.get("causal_index")
            if isinstance(ci, int) and ci > last_index:
                last_index = ci
            if event.get("status") != "ingest-gap":
                last_hash = event.get("event_hash")
        return last_hash, last_index

    def _upsert_index(self, event: dict[str, Any]) -> None:
        cid = event["correlation_id"]
        recorded_at = event["recorded_at"]
        constitutional_hash = event["constitutional_hash"]
        status: EventStatus = event["status"]
        with self._db_lock:
            row = self._db.execute(
                "SELECT started_at, event_count, worst_event_status "
                "FROM traces WHERE correlation_id=?",
                (cid,),
            ).fetchone()
            if row is None:
                self._db.execute(
                    "INSERT INTO traces "
                    "(correlation_id, started_at, completed_at, constitutional_hash, "
                    "event_count, worst_event_status, integrity_status, status) "
                    "VALUES (?, ?, ?, ?, 1, ?, 'unknown', 'open')",
                    (cid, recorded_at, recorded_at, constitutional_hash, status),
                )
            else:
                _started_at, count, worst = row
                self._db.execute(
                    "UPDATE traces SET completed_at=?, event_count=?, worst_event_status=? "
                    "WHERE correlation_id=?",
                    (recorded_at, count + 1, _worst(worst, status), cid),
                )

    # ---- read path --------------------------------------------------------

    def list_traces(self, limit: int = 50) -> TraceList:
        with self._db_lock:
            rows = self._db.execute(
                "SELECT correlation_id, started_at, completed_at, constitutional_hash, "
                "event_count, worst_event_status "
                "FROM traces ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        # Compute integrity_status fresh per row so the list view never
        # shows a stale "unknown" — Architect blocker #1. We hash a max of
        # N events per trace; for 10K events/day floor this stays cheap.
        items: list[TraceListItem] = []
        for cid, started_at, completed_at, cons_hash, count, worst in rows:
            path = _trace_path(self.store_dir, cid)
            raw_events = list(self._iter_file(path)) if path.exists() else []
            integrity = self._verify_chain(raw_events) if raw_events else "unknown"
            events = [Event(**event) for event in raw_events]
            trace_context = _trace_context_from_events(events)
            items.append(
                TraceListItem(
                    correlation_id=cid,
                    started_at=datetime.fromisoformat(started_at),
                    completed_at=datetime.fromisoformat(completed_at) if completed_at else None,
                    event_count=count,
                    worst_event_status=worst,
                    integrity_status=integrity,
                    constitutional_hash=cons_hash,
                    phoenix_trace_id=trace_context["phoenix_trace_id"],
                    phoenix_span_id=trace_context["phoenix_span_id"],
                    phoenix_parent_span_id=trace_context["phoenix_parent_span_id"],
                )
            )
        return TraceList(items=items, next_cursor=None)

    def get_trace(self, correlation_id: str) -> SingleTrace | None:
        path = _trace_path(self.store_dir, correlation_id)
        if not path.exists():
            return None
        raw_events = list(self._iter_file(path))
        if not raw_events:
            return None
        integrity = self._verify_chain(raw_events)
        events = [Event(**e) for e in raw_events]
        worst: EventStatus = "completed"
        for ev in events:
            worst = _worst(worst, ev.status)
        trace_context = _trace_context_from_events(events)
        item = TraceListItem(
            correlation_id=correlation_id,
            started_at=events[0].recorded_at,
            completed_at=events[-1].recorded_at,
            event_count=len(events),
            worst_event_status=worst,
            integrity_status=integrity,
            constitutional_hash=events[0].constitutional_hash,
            phoenix_trace_id=trace_context["phoenix_trace_id"],
            phoenix_span_id=trace_context["phoenix_span_id"],
            phoenix_parent_span_id=trace_context["phoenix_parent_span_id"],
        )
        # Mark a rotation if the constitutional hash changed mid-trace.
        rotation_at: int | None = None
        anchor = events[0].constitutional_hash
        for ev in events:
            if ev.constitutional_hash != anchor:
                rotation_at = ev.causal_index
                break
        return SingleTrace(
            trace=item,
            events=events,
            integrity_status=integrity,
            rotation_at_index=rotation_at,
        )

    def get_receipt_proof(self, receipt_id: str) -> ReceiptProof | None:
        """Find a receipt by id or hash and return a console-ready proof packet."""
        for path in sorted((self.store_dir / "traces").glob("*.jsonl")):
            raw_events = list(self._iter_file(path))
            if not raw_events:
                continue
            match = next(
                (event for event in raw_events if _receipt_matches(event, receipt_id)),
                None,
            )
            if match is None:
                continue
            return self._build_receipt_proof(path.stem, raw_events, match)
        return None

    def _build_receipt_proof(
        self,
        correlation_id: str,
        raw_events: list[dict[str, Any]],
        match: dict[str, Any],
    ) -> ReceiptProof:
        integrity = self._verify_chain(raw_events)
        events = [Event(**e) for e in raw_events]
        worst: EventStatus = "completed"
        for ev in events:
            worst = _worst(worst, ev.status)
        trace_context = _trace_context_from_events(events)
        trace = TraceListItem(
            correlation_id=correlation_id,
            started_at=events[0].recorded_at,
            completed_at=events[-1].recorded_at,
            event_count=len(events),
            worst_event_status=worst,
            integrity_status=integrity,
            constitutional_hash=events[0].constitutional_hash,
            phoenix_trace_id=trace_context["phoenix_trace_id"],
            phoenix_span_id=trace_context["phoenix_span_id"],
            phoenix_parent_span_id=trace_context["phoenix_parent_span_id"],
        )
        receipt_hash = str(match.get("audit_receipt_hash") or match.get("event_hash"))
        policy_path = _receipt_policy_path(events)
        flagged_rules = [event.flagged_rule for event in events if event.flagged_rule]
        decision = next((event.decision for event in reversed(events) if event.decision), None)
        packet = {
            "kind": "receipt-proof-export",
            "receipt_id": str(match.get("event_id")),
            "receipt_hash": receipt_hash,
            "correlation_id": correlation_id,
            "integrity_status": integrity,
            "hash_chain_verified": integrity == "intact",
            "policy_path": policy_path,
            "decision": decision,
            "flagged_rules": flagged_rules,
            "event_hashes": [event.event_hash for event in events],
            "source_audit_hash": receipt_hash,
            "counter_signature": f"agent-bus-analyzer:{events[-1].event_hash}",
        }
        packet.update(_non_null_trace_context(trace_context))
        signed_packet = sign_evidence_packet(packet)
        return ReceiptProof(
            receipt_id=str(match.get("event_id")),
            receipt_hash=receipt_hash,
            correlation_id=correlation_id,
            trace=trace,
            events=events,
            integrity_status=integrity,
            hash_chain_verified=integrity == "intact",
            policy_path=policy_path,
            decision=decision,
            flagged_rules=flagged_rules,
            signed_evidence_packet=canonical_json(signed_packet),
            phoenix_trace_id=trace_context["phoenix_trace_id"],
            phoenix_span_id=trace_context["phoenix_span_id"],
            phoenix_parent_span_id=trace_context["phoenix_parent_span_id"],
        )

    def _verify_chain(self, raw_events: list[dict[str, Any]]) -> IntegrityStatus:
        """Verify against the raw stored JSON dicts (same input we hashed at write time).

        Pydantic round-tripping would re-serialize fields (datetime → string)
        differently from the canonical_json we wrote — verifying must use the
        on-disk bytes' parsed form, not a Pydantic-projected one.
        """
        prev: str | None = None
        for ev in raw_events:
            if ev.get("status") == "ingest-gap":
                continue
            if ev.get("prev_hash") != prev:
                return "tampered"
            recomputed = compute_event_hash(ev)
            if recomputed != ev.get("event_hash"):
                return "tampered"
            prev = ev.get("event_hash")
        return "intact"

    def _iter_file(self, path: Path) -> Iterator[dict[str, Any]]:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                clean = line.strip()
                if clean:
                    yield json.loads(clean)

    # ---- writer loop ------------------------------------------------------

    async def writer_loop(
        self,
        queue: CaptureQueue,
        *,
        drain_on_idle: bool = False,
        last_correlation_id: str | None = None,
    ) -> None:
        """Consume from *queue* and append to disk.

        If a gap is open AND we have a trace context (either a fresh event
        or a remembered last_correlation_id), flush a gap marker BEFORE
        clearing in-memory gap counters — so a crash between flush and
        clear leaves the gap recoverable (Architect blocker #2 / Code
        reviewer HIGH #3).

        ``drain_on_idle=True`` makes the loop exit when the queue empties —
        useful for tests; production callers pass False (or omit).
        """
        recent_cid = last_correlation_id
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=0.5)
            except TimeoutError:
                # Idle path: still flush a pending gap if we have a target
                # trace. Without a target we can't pick the file — defer.
                if queue.gap_open() and recent_cid is not None:
                    self._flush_gap_marker(queue, recent_cid)
                if drain_on_idle:
                    return
                continue
            recent_cid = event["correlation_id"]
            if queue.gap_open():
                self._flush_gap_marker(queue, recent_cid)
            self.append(event)

    def _flush_gap_marker(self, queue: CaptureQueue, correlation_id: str) -> None:
        """Peek → write durably → only THEN clear in-memory gap counters.

        If the write raises before close_gap runs, the in-memory counters
        are preserved and the next loop iteration retries — no silent
        gap loss on crash between peek and fsync.
        """
        gap = queue.peek_gap()
        if gap is None:
            return
        started, ended, _count = gap
        path = _trace_path(self.store_dir, correlation_id)
        _last_hash, last_index = self._tail_state(path)
        marker: dict[str, Any] = {
            "event_id": f"gap-{started.isoformat()}",
            "correlation_id": correlation_id,
            "causal_index": last_index + 1,
            "recorded_at": ended.isoformat(),
            "source_agent": "analyzer:capture-queue",
            "target_handler_declared": None,
            "target_handler_resolved": None,
            "payload_ref": "ingest-gap",
            "kind": "dispatch",
            "decision": None,
            "flagged_rule": None,
            "audit_receipt_hash": None,
            "constitutional_hash": "0" * 16,
            "status": "ingest-gap",
            "gap_started_at": started.isoformat(),
            "gap_ended_at": ended.isoformat(),
            "prev_hash": None,
        }
        marker["event_hash"] = compute_event_hash(marker)
        self._append_raw(marker)
        queue.close_gap()

    def _append_raw(self, payload: dict[str, Any]) -> None:
        """Internal raw append (used for ingest-gap markers)."""
        path = _trace_path(self.store_dir, payload["correlation_id"])
        path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = path.with_suffix(path.suffix + ".lock")
        with lock_path.open("a+") as lock_fh:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            try:
                with path.open("a", encoding="utf-8") as fh:
                    fh.write(canonical_json(payload) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                self._upsert_index(payload)
            finally:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)


    # ---- retention (T059) ------------------------------------------------

    def expire_older_than(self, days: int) -> list[str]:
        """Move traces older than *days* into ``expired/`` (T059, FR-012).

        Returns the list of correlation_ids that were expired. The JSONL
        payload is MOVED, never rewritten — preserves chain integrity per
        research §R9. A sidecar JSON file records the RetentionPolicy so
        ``query.get_trace_or_expired`` can return an ``Expired`` shape
        instead of a generic not-found.
        """
        if days < 0:
            raise ValueError(f"days must be >= 0, got {days}")
        expired_dir = self.store_dir / "expired"
        expired_dir.mkdir(parents=True, exist_ok=True)
        purged_at = datetime.now().isoformat()
        cutoff_expr = f"datetime('now', '-{int(days)} days')"
        expired_ids: list[str] = []
        with self._db_lock:
            rows = self._db.execute(
                "SELECT correlation_id FROM traces "
                f"WHERE completed_at IS NOT NULL AND completed_at < {cutoff_expr} "
                "AND status != 'expired'"
            ).fetchall()
            for (cid,) in rows:
                src = _trace_path(self.store_dir, cid)
                if src.exists():
                    dst = expired_dir / src.name
                    src.replace(dst)
                sidecar = expired_dir / f"{cid}.json"
                sidecar.write_text(
                    canonical_json({"max_age_days": int(days), "purged_at": purged_at}),
                    encoding="utf-8",
                )
                self._db.execute(
                    "UPDATE traces SET status='expired' WHERE correlation_id=?",
                    (cid,),
                )
                expired_ids.append(cid)
        return expired_ids


def open_store(store_dir: str | Path) -> TraceStore:
    """Open or create a TraceStore. Fails closed if the dir is not writable."""
    p = Path(store_dir)
    try:
        p.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise IntegrityStoreUnavailable(f"store_dir not writable: {p}: {exc}") from exc
    return TraceStore(p)


def iter_trace_events(store_dir: str | Path, correlation_id: str) -> Iterable[dict[str, Any]]:
    """Read-only iteration over a trace's stored events (test/debug helper)."""
    path = _trace_path(Path(store_dir), correlation_id)
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            clean = line.strip()
            if clean:
                yield json.loads(clean)
