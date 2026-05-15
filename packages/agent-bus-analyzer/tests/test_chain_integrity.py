"""Tamper-detection round-trip — the load-bearing primitive must actually flip.

Code-reviewer HIGH#1: no test was exercising the `tampered` return value
of ``_verify_chain``. This test fixes that by:
  - writing 3 clean events
  - asserting integrity_status='intact'
  - mutating one byte in a non-gap line on disk
  - asserting integrity_status='tampered'
  - also asserting list view picks up the same status (Architect blocker #1)
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from agent_bus_analyzer.errors import ReadOnlyViolation
from agent_bus_analyzer.store import TraceStore, _trace_path


def _event(cid: str, idx: int) -> dict[str, Any]:
    return {
        "event_id": f"00000000-0000-0000-0000-0000000000{idx:>02}",
        "correlation_id": cid,
        "recorded_at": datetime.now(UTC).isoformat(),
        "source_agent": "claude:worker-03",
        "target_handler_declared": "policy.evaluate",
        "target_handler_resolved": None,
        "payload_ref": f"sha256:{idx:0>64}",
        "kind": "dispatch",
        "decision": None,
        "flagged_rule": None,
        "audit_receipt_hash": None,
        "constitutional_hash": "608508a9bd224290",
        "status": "completed",
    }


def test_clean_trace_is_intact(tmp_path: Path) -> None:
    store = TraceStore(tmp_path)
    for i in range(3):
        store.append(_event("trace-a", i))
    assert store.get_trace("trace-a").integrity_status == "intact"  # type: ignore[union-attr]
    assert store.list_traces().items[0].integrity_status == "intact"


def test_byte_flip_flips_integrity_to_tampered(tmp_path: Path) -> None:
    store = TraceStore(tmp_path)
    for i in range(3):
        store.append(_event("trace-a", i))

    path = _trace_path(tmp_path, "trace-a")
    data = path.read_bytes()
    # Flip a single payload character mid-file (avoid the JSON brackets).
    midpoint = len(data) // 2
    # Find a safe spot in the body (not a structural char), shift if needed.
    while data[midpoint : midpoint + 1] in (b"{", b"}", b"[", b"]", b'"', b":", b",", b"\n"):
        midpoint += 1
    new_byte = b"Z" if data[midpoint : midpoint + 1] != b"Z" else b"Y"
    path.write_bytes(data[:midpoint] + new_byte + data[midpoint + 1 :])

    trace = store.get_trace("trace-a")
    assert trace is not None
    assert trace.integrity_status == "tampered"

    # List view must also reflect tampering — was the Architect blocker.
    listed = store.list_traces().items[0]
    assert listed.integrity_status == "tampered"


def test_path_traversal_correlation_id_rejected(tmp_path: Path) -> None:
    """Security CRITICAL#1: correlation_id from user input cannot escape store_dir."""
    store = TraceStore(tmp_path)
    for bad in [
        "../../../etc/passwd",
        "..",
        "/absolute/path",
        "a/b",
        "trace\x00.jsonl",
        "trace with spaces",
        "",
        "x" * 200,
    ]:
        with pytest.raises(ReadOnlyViolation):
            store.append({**_event("placeholder", 0), "correlation_id": bad})
