"""T075 — expired-trace query returns Expired shape, not None.

Scenario: a trace file has been moved to the retention sidecar location
``{store_dir}/expired/{correlation_id}.json``.  The public
``get_trace_or_expired`` helper must return an ``Expired`` response
(kind="expired", correlation_id, retention_policy) rather than ``None``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agent_bus_analyzer.models import Expired
from agent_bus_analyzer.query import get_trace_or_expired
from agent_bus_analyzer.store import open_store


@pytest.fixture()
def tmp_store(tmp_path: Path):  # type: ignore[no-untyped-def]
    store = open_store(tmp_path / "store")
    yield store
    store.close()


def _write_expired_sidecar(store_dir: Path, correlation_id: str, *, max_age_days: int = 30) -> None:
    expired_dir = store_dir / "expired"
    expired_dir.mkdir(parents=True, exist_ok=True)
    sidecar = expired_dir / f"{correlation_id}.json"
    sidecar.write_text(
        json.dumps(
            {
                "max_age_days": max_age_days,
                "purged_at": datetime.now(UTC).isoformat(),
            }
        ),
        encoding="utf-8",
    )


def test_expired_returns_expired_shape(tmp_store) -> None:  # type: ignore[no-untyped-def]
    """A trace with a sidecar returns Expired, not None."""
    cid = "trace-expired-001"
    _write_expired_sidecar(tmp_store.store_dir, cid, max_age_days=7)

    result = get_trace_or_expired(tmp_store, cid)

    assert result is not None, "expected Expired, got None"
    assert isinstance(result, Expired), f"expected Expired, got {type(result)}"
    assert result.kind == "expired"
    assert result.correlation_id == cid
    assert result.retention_policy.max_age_days == 7


def test_live_trace_wins_over_sidecar(tmp_store) -> None:  # type: ignore[no-untyped-def]
    """When a live trace exists it takes priority over any sidecar."""
    from datetime import UTC, datetime

    from agent_bus_analyzer.models import SingleTrace

    cid = "trace-live-001"
    # Write a sidecar first
    _write_expired_sidecar(tmp_store.store_dir, cid)
    # Append a real event to create a live trace
    tmp_store.append(
        {
            "event_id": "evt-live-001",
            "correlation_id": cid,
            "recorded_at": datetime.now(UTC).isoformat(),
            "source_agent": "test-agent",
            "payload_ref": "sha256:" + "a" * 64,
            "kind": "dispatch",
            "decision": None,
            "flagged_rule": None,
            "audit_receipt_hash": None,
            "constitutional_hash": "a1b2c3d4e5f60718",
            "status": "completed",
        }
    )

    result = get_trace_or_expired(tmp_store, cid)

    assert isinstance(result, SingleTrace), f"expected SingleTrace, got {type(result)}"


def test_missing_trace_returns_none(tmp_store) -> None:  # type: ignore[no-untyped-def]
    """Trace with no sidecar and no live file returns None."""
    result = get_trace_or_expired(tmp_store, "trace-never-existed")
    assert result is None


def test_malformed_sidecar_returns_none(tmp_store) -> None:  # type: ignore[no-untyped-def]
    """A sidecar missing required fields returns None rather than crashing."""
    cid = "trace-bad-sidecar"
    expired_dir = tmp_store.store_dir / "expired"
    expired_dir.mkdir(parents=True, exist_ok=True)
    (expired_dir / f"{cid}.json").write_text('{"broken": true}', encoding="utf-8")

    result = get_trace_or_expired(tmp_store, cid)
    assert result is None
