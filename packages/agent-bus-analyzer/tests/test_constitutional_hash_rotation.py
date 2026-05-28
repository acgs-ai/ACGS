"""T049 — Constitutional hash rotation detection mid-trace.

FR-002 edge case: when constitutional_hash changes mid-run, the store must
record rotation_at_index pointing at the first event with the rotated hash.
A trace with no rotation must have rotation_at_index is None.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent_bus_analyzer.store import TraceStore

_HASH_A = "608508a9bd224290"
_HASH_B = "aaaaaaaaaaaaaaaa"


def _event(cid: str, idx: int, constitutional_hash: str = _HASH_A) -> dict[str, Any]:
    return {
        "event_id": f"00000000-0000-0000-0000-00000000{idx:0>4}",
        "correlation_id": cid,
        "recorded_at": datetime.now(UTC).isoformat(),
        "source_agent": "claude:test",
        "target_handler_declared": "policy.evaluate",
        "target_handler_resolved": None,
        "payload_ref": f"sha256:{'0' * 64}",
        "kind": "dispatch",
        "decision": None,
        "flagged_rule": None,
        "audit_receipt_hash": None,
        "constitutional_hash": constitutional_hash,
        "status": "completed",
    }


def test_no_rotation_when_hash_constant(tmp_path: Path) -> None:
    """Trace with no hash change has rotation_at_index=None."""
    store = TraceStore(tmp_path)
    for i in range(3):
        store.append(_event("trace-const", i, _HASH_A))

    result = store.get_trace("trace-const")
    assert result is not None
    assert result.rotation_at_index is None


def test_rotation_detected_at_correct_index(tmp_path: Path) -> None:
    """rotation_at_index equals causal_index of first event with rotated hash."""
    store = TraceStore(tmp_path)
    # Events 0,1,2 with HASH_A; events 3,4 with HASH_B
    for i in range(3):
        store.append(_event("trace-rot", i, _HASH_A))
    for i in range(3, 5):
        store.append(_event("trace-rot", i, _HASH_B))

    result = store.get_trace("trace-rot")
    assert result is not None
    # Event at causal_index=3 is the first with HASH_B
    assert result.rotation_at_index == 3


def test_rotation_at_first_event(tmp_path: Path) -> None:
    """If ALL events have HASH_B but anchor is HASH_A, no rotation reported.

    The anchor is the constitutional_hash of events[0], so rotation can only
    be detected when a later event diverges from that anchor.
    """
    store = TraceStore(tmp_path)
    # Single event; anchor == its own hash, no divergence possible
    store.append(_event("trace-single", 0, _HASH_B))

    result = store.get_trace("trace-single")
    assert result is not None
    assert result.rotation_at_index is None


def test_rotation_at_second_event(tmp_path: Path) -> None:
    """rotation_at_index=1 when second event has a different constitutional hash."""
    store = TraceStore(tmp_path)
    store.append(_event("trace-second", 0, _HASH_A))
    store.append(_event("trace-second", 1, _HASH_B))

    result = store.get_trace("trace-second")
    assert result is not None
    assert result.rotation_at_index == 1


def test_rotation_integrity_status_still_intact(tmp_path: Path) -> None:
    """A valid hash rotation does not corrupt the chain — chain stays intact."""
    store = TraceStore(tmp_path)
    for i in range(2):
        store.append(_event("trace-rot-intact", i, _HASH_A))
    for i in range(2, 4):
        store.append(_event("trace-rot-intact", i, _HASH_B))

    result = store.get_trace("trace-rot-intact")
    assert result is not None
    assert result.integrity_status == "intact"
    assert result.rotation_at_index == 2
