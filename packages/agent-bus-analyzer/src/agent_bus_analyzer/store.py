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
import sqlite3
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from agent_bus_analyzer.capture import CaptureQueue
from agent_bus_analyzer.errors import IntegrityStoreUnavailable
from agent_bus_analyzer.hashing import canonical_json, compute_event_hash
from agent_bus_analyzer.models import (
    Event,
    EventStatus,
    IntegrityStatus,
    SingleTrace,
    TraceList,
    TraceListItem,
)


def _trace_path(store_dir: Path, correlation_id: str) -> Path:
    return store_dir / "traces" / f"{correlation_id}.jsonl"


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


class TraceStore:
    """Append-only chain-hashed event store with a SQLite trace index."""

    def __init__(self, store_dir: str | Path) -> None:
        self.store_dir = Path(store_dir)
        (self.store_dir / "traces").mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(
            _index_path(self.store_dir),
            isolation_level=None,
            # FastAPI dispatches handlers across threads; the analyzer owns
            # a single store per process and serializes appends via fcntl
            # flock on the trace file, so this relaxation is safe.
            check_same_thread=False,
        )
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
        row = self._db.execute(
            "SELECT started_at, event_count, worst_event_status FROM traces WHERE correlation_id=?",
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
        rows = self._db.execute(
            "SELECT correlation_id, started_at, completed_at, constitutional_hash, "
            "event_count, worst_event_status, integrity_status "
            "FROM traces ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        items = [
            TraceListItem(
                correlation_id=cid,
                started_at=datetime.fromisoformat(started_at),
                completed_at=datetime.fromisoformat(completed_at) if completed_at else None,
                event_count=count,
                worst_event_status=worst,
                integrity_status=integrity,
                constitutional_hash=cons_hash,
            )
            for (cid, started_at, completed_at, cons_hash, count, worst, integrity) in rows
        ]
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
        item = TraceListItem(
            correlation_id=correlation_id,
            started_at=events[0].recorded_at,
            completed_at=events[-1].recorded_at,
            event_count=len(events),
            worst_event_status=worst,
            integrity_status=integrity,
            constitutional_hash=events[0].constitutional_hash,
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

    async def writer_loop(self, queue: CaptureQueue, *, drain_on_idle: bool = False) -> None:
        """Consume from *queue* and append to disk.

        On every successful append, if a gap was open it is closed and an
        `ingest-gap` synthetic event is emitted to the same trace (FR-013).
        ``drain_on_idle=True`` makes the loop exit when the queue empties —
        useful for tests; production callers pass False (or omit).
        """
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=0.5)
            except TimeoutError:
                if drain_on_idle:
                    return
                continue
            gap = queue.close_gap()
            if gap is not None:
                started, ended, _count = gap
                # Synthesize a gap marker that sits at the next causal index
                # for this trace. The marker is NOT in the chain (prev_hash
                # is null) but it shares a strictly-monotonic causal_index
                # with the rest of the trace so the reader can order it.
                marker_path = _trace_path(self.store_dir, event["correlation_id"])
                _last_hash, last_index = self._tail_state(marker_path)
                marker = dict(event)
                marker["status"] = "ingest-gap"
                marker["causal_index"] = last_index + 1
                marker["gap_started_at"] = started.isoformat()
                marker["gap_ended_at"] = ended.isoformat()
                marker["prev_hash"] = None
                marker.pop("event_hash", None)
                marker["event_hash"] = compute_event_hash(marker)
                self._append_raw(marker)
            self.append(event)


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
