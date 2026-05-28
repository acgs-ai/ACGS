"""T059 — retention enforcement via TraceStore.expire_older_than.

The producer side of FR-012: traces past the configured age are MOVED
into ``expired/`` with a sidecar that ``query.get_trace_or_expired``
can read. JSONL contents are never rewritten — chain integrity is
preserved.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from agent_bus_analyzer.hashing import canonical_json, compute_event_hash
from agent_bus_analyzer.query import get_trace_or_expired
from agent_bus_analyzer.store import open_store

CONS_HASH = "608508a9bd224290"


def _make_event(correlation_id: str, recorded_at: datetime) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_id": f"evt-{correlation_id}",
        "correlation_id": correlation_id,
        "recorded_at": recorded_at.isoformat(),
        "source_agent": "claude:worker-01",
        "target_handler_declared": "handler.alpha",
        "target_handler_resolved": "handler.alpha",
        "payload_ref": "ref-1",
        "kind": "dispatch",
        "decision": None,
        "flagged_rule": None,
        "audit_receipt_hash": None,
        "constitutional_hash": CONS_HASH,
        "status": "completed",
        "prev_hash": None,
    }
    payload["event_hash"] = compute_event_hash(payload)
    return payload


def test_expire_older_than_moves_old_traces(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        old = datetime.now(UTC) - timedelta(days=100)
        recent = datetime.now(UTC) - timedelta(days=1)
        store.append(_make_event("old-trace", old))
        store.append(_make_event("recent-trace", recent))

        expired = store.expire_older_than(days=90)
    finally:
        store.close()

    assert expired == ["old-trace"]
    assert (tmp_path / "expired" / "old-trace.jsonl").exists()
    assert (tmp_path / "expired" / "old-trace.json").exists()
    assert (tmp_path / "traces" / "old-trace.jsonl").exists() is False
    assert (tmp_path / "traces" / "recent-trace.jsonl").exists()

    sidecar = json.loads((tmp_path / "expired" / "old-trace.json").read_text(encoding="utf-8"))
    assert sidecar["max_age_days"] == 90
    assert "purged_at" in sidecar


def test_expire_then_query_returns_expired_shape(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        old = datetime.now(UTC) - timedelta(days=200)
        store.append(_make_event("aged", old))
        store.expire_older_than(days=90)

        result = get_trace_or_expired(store, "aged")
    finally:
        store.close()

    assert result is not None
    assert result.kind == "expired"
    assert result.correlation_id == "aged"
    assert result.retention_policy.max_age_days == 90


def test_expire_jsonl_bytes_unchanged(tmp_path: Path) -> None:
    """Chain-integrity guarantee: expiration MOVES the file, never rewrites it."""
    store = open_store(tmp_path)
    try:
        old = datetime.now(UTC) - timedelta(days=100)
        store.append(_make_event("chain-check", old))
        original = (tmp_path / "traces" / "chain-check.jsonl").read_bytes()
        store.expire_older_than(days=90)
    finally:
        store.close()

    moved = (tmp_path / "expired" / "chain-check.jsonl").read_bytes()
    assert moved == original


def test_expire_idempotent(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        old = datetime.now(UTC) - timedelta(days=100)
        store.append(_make_event("once", old))
        first = store.expire_older_than(days=90)
        second = store.expire_older_than(days=90)
    finally:
        store.close()

    assert first == ["once"]
    assert second == []


def test_expire_negative_days_raises(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        with pytest.raises(ValueError):
            store.expire_older_than(days=-1)
    finally:
        store.close()


def test_canonical_json_helper_used(tmp_path: Path) -> None:
    """Sidecar JSON is canonical (sorted keys, no whitespace) for diffability."""
    store = open_store(tmp_path)
    try:
        old = datetime.now(UTC) - timedelta(days=100)
        store.append(_make_event("canon", old))
        store.expire_older_than(days=90)
    finally:
        store.close()

    raw = (tmp_path / "expired" / "canon.json").read_text(encoding="utf-8")
    parsed = json.loads(raw)
    assert raw == canonical_json(parsed)
