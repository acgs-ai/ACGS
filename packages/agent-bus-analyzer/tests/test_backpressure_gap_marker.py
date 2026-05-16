"""T018 — saturate the capture queue; assert (a) try_put never blocks and
(b) an ingest-gap marker is emitted on resumption with the right window.

Note: FR-013 says backpressure surfaces as a synthetic ``ingest-gap``
marker. The marker is in the JSONL but NOT in the prev_hash chain (its
prev_hash is null and the next non-gap event's prev_hash references the
last non-gap event's hash).
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from agent_bus_analyzer.capture import CaptureQueue
from agent_bus_analyzer.store import TraceStore, iter_trace_events


def _event(suffix: str) -> dict[str, Any]:
    return {
        "event_id": f"00000000-0000-0000-0000-0000000000{suffix:>02}",
        "correlation_id": "trace-burst",
        "recorded_at": datetime.now(UTC).isoformat(),
        "source_agent": "claude:worker-03",
        "target_handler_declared": "policy.evaluate",
        "target_handler_resolved": None,
        "payload_ref": f"sha256:{suffix:0>64}",
        "kind": "dispatch",
        "decision": None,
        "flagged_rule": None,
        "audit_receipt_hash": None,
        "constitutional_hash": "608508a9bd224290",
        "status": "completed",
    }


def test_try_put_returns_quickly_under_saturation() -> None:
    q = CaptureQueue(capacity=4)
    # Fill, then sustained over-capacity try_put calls.
    for i in range(4):
        assert q.try_put(_event(str(i))) is True
    start = time.perf_counter()
    drops = 0
    for i in range(4, 100):
        if not q.try_put(_event(str(i))):
            drops += 1
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    assert drops == 96
    # 96 try_put calls under 50ms total — well under the 1ms-per-call budget.
    assert elapsed_ms < 50.0, f"saturation try_put too slow: {elapsed_ms:.2f}ms"
    assert q.gap_open() is True


@pytest.mark.asyncio
async def test_writer_emits_ingest_gap_marker_on_resumption(tmp_path: Path) -> None:
    q = CaptureQueue(capacity=2)
    store = TraceStore(tmp_path)

    # Drive the queue: 2 ok, 3 dropped (gap opens), then 1 more after gap closes.
    assert q.try_put(_event("0")) is True
    assert q.try_put(_event("1")) is True
    assert q.try_put(_event("2")) is False  # drop
    assert q.try_put(_event("3")) is False  # drop
    assert q.gap_open() is True

    # Drain the existing two events via the writer.
    writer = asyncio.create_task(store.writer_loop(q, drain_on_idle=True))
    await writer  # exits when queue empties

    # Now publish a fresh event after the gap and drain again.
    assert q.try_put(_event("9")) is True
    writer2 = asyncio.create_task(store.writer_loop(q, drain_on_idle=True))
    await writer2

    persisted = list(iter_trace_events(tmp_path, "trace-burst"))
    statuses = [e["status"] for e in persisted]
    assert "ingest-gap" in statuses, f"no gap marker in persisted events: {statuses}"
    gap = next(e for e in persisted if e["status"] == "ingest-gap")
    assert gap["gap_started_at"] <= gap["gap_ended_at"]
    assert gap["prev_hash"] is None

    # Chain still intact when verified through the public read path.
    trace = store.get_trace("trace-burst")
    assert trace is not None
    assert trace.integrity_status == "intact"
