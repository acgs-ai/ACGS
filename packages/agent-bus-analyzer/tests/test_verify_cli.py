"""T050 — `verify` CLI subcommand integration tests.

Covers:
  (a) clean trace → exit 0, JSON integrity_status='intact'
  (b) tampered trace → exit 1, JSON names broken_event_id, status='tampered'
  (c) missing trace → exit 1, JSON status='unknown'
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent_bus_analyzer.store import TraceStore, _trace_path

_HASH = "608508a9bd224290"


def _event(cid: str, idx: int) -> dict[str, Any]:
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
        "constitutional_hash": _HASH,
        "status": "completed",
    }


def _verify(cid: str, store_dir: Path, *, timeout: int = 10) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_bus_analyzer",
            "verify",
            cid,
            "--store-dir",
            str(store_dir),
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# Case (a): clean trace
# ---------------------------------------------------------------------------


def test_verify_clean_trace_exits_zero(tmp_path: Path) -> None:
    store = TraceStore(tmp_path)
    for i in range(3):
        store.append(_event("trace-clean", i))
    store.close()

    result = _verify("trace-clean", tmp_path)

    assert result.returncode == 0, f"Expected exit 0; stderr={result.stderr!r}"
    payload = json.loads(result.stdout)
    assert payload["integrity_status"] == "intact"
    assert payload["correlation_id"] == "trace-clean"
    assert payload["event_count"] == 3
    assert payload["broken_event_id"] is None


# ---------------------------------------------------------------------------
# Case (b): tampered trace
# ---------------------------------------------------------------------------


def test_verify_tampered_trace_exits_nonzero(tmp_path: Path) -> None:
    store = TraceStore(tmp_path)
    events_written: list[dict[str, Any]] = []
    for i in range(3):
        written = store.append(_event("trace-tampered", i))
        events_written.append(written)
    store.close()

    # Flip a byte in the JSONL to corrupt the chain
    path = _trace_path(tmp_path, "trace-tampered")
    data = path.read_bytes()
    midpoint = len(data) // 2
    while data[midpoint : midpoint + 1] in (b"{", b"}", b"[", b"]", b'"', b":", b",", b"\n"):
        midpoint += 1
    new_byte = b"Z" if data[midpoint : midpoint + 1] != b"Z" else b"Y"
    path.write_bytes(data[:midpoint] + new_byte + data[midpoint + 1 :])

    result = _verify("trace-tampered", tmp_path)

    assert result.returncode != 0, f"Expected non-zero exit; stderr={result.stderr!r}"
    payload = json.loads(result.stdout)
    assert payload["integrity_status"] == "tampered"
    assert payload["correlation_id"] == "trace-tampered"
    assert payload["broken_event_id"] is not None, "Expected broken_event_id to be set"


# ---------------------------------------------------------------------------
# Case (c): missing trace
# ---------------------------------------------------------------------------


def test_verify_missing_trace_exits_nonzero(tmp_path: Path) -> None:
    result = _verify("no-such-trace", tmp_path)

    assert result.returncode != 0, f"Expected non-zero exit; stderr={result.stderr!r}"
    payload = json.loads(result.stdout)
    assert payload["integrity_status"] == "unknown"
    assert payload["correlation_id"] == "no-such-trace"
    assert payload["event_count"] == 0
