"""T048 — Fail-closed boot: missing/unreadable audit JSONL.

FR-008: Observer MUST exit non-zero with IntegrityStoreUnavailable when the
integrity store is unavailable. No hash-less events must be written.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from agent_bus_analyzer.errors import IntegrityStoreUnavailable

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _event(cid: str, idx: int) -> dict[str, Any]:
    from datetime import UTC, datetime

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
        "constitutional_hash": "608508a9bd224290",
        "status": "completed",
    }


def _observer_argv(*, bus_endpoint: str, audit_file: Path, store_dir: Path) -> list[str]:
    return [
        sys.executable,
        "-m",
        "agent_bus_analyzer",
        "observer",
        "--bus-endpoint",
        bus_endpoint,
        "--audit-file",
        str(audit_file),
        "--store-dir",
        str(store_dir),
    ]


# ---------------------------------------------------------------------------
# Case (a): audit file does not exist
# ---------------------------------------------------------------------------


def test_fail_closed_missing_audit_file_exits_nonzero(tmp_path: Path) -> None:
    """Observer exits non-zero when audit_file does not exist (FR-008)."""
    audit_file = tmp_path / "nonexistent_audit.jsonl"
    store_dir = tmp_path / "store"

    result = subprocess.run(
        _observer_argv(
            bus_endpoint="http://localhost:9999",
            audit_file=audit_file,
            store_dir=store_dir,
        ),
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode != 0, (
        f"Expected non-zero exit for missing audit file; got {result.returncode}. "
        f"stderr={result.stderr!r}"
    )
    assert "IntegrityStoreUnavailable" in result.stderr or "fail-closed" in result.stderr.lower(), (
        f"Expected IntegrityStoreUnavailable signal in stderr. stderr={result.stderr!r}"
    )


def test_fail_closed_missing_audit_file_no_events_written(tmp_path: Path) -> None:
    """No trace files written when boot fails due to missing audit file."""
    audit_file = tmp_path / "nonexistent_audit.jsonl"
    store_dir = tmp_path / "store"

    subprocess.run(
        _observer_argv(
            bus_endpoint="http://localhost:9999",
            audit_file=audit_file,
            store_dir=store_dir,
        ),
        capture_output=True,
        timeout=10,
    )

    traces_dir = store_dir / "traces"
    if traces_dir.exists():
        jsonl_files = list(traces_dir.glob("*.jsonl"))
        assert jsonl_files == [], f"Expected no trace files, found {jsonl_files}"


def test_in_process_missing_audit_raises_integrity_unavailable(tmp_path: Path) -> None:
    """In-process: observer_main raises IntegrityStoreUnavailable for missing file.

    Tests the fail-closed contract at the Python API layer (not just CLI).
    """
    import asyncio

    from agent_bus_analyzer.cli import _observer_main

    class _Args:
        bus_endpoint = "http://localhost:9999"
        audit_file = tmp_path / "nonexistent_audit.jsonl"
        store_dir = tmp_path / "store"
        queue_capacity = 100
        registry_poll_seconds = 30

    with pytest.raises(IntegrityStoreUnavailable):
        asyncio.run(_observer_main(_Args()))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Case (b): audit file exists but is unreadable (chmod 000)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    os.getuid() == 0,  # type: ignore[attr-defined]
    reason="chmod 000 has no effect when running as root",
)
def test_fail_closed_unreadable_audit_file_exits_nonzero(tmp_path: Path) -> None:
    """Observer exits non-zero when audit_file exists but is unreadable (FR-008)."""
    audit_file = tmp_path / "audit.jsonl"
    audit_file.touch()
    audit_file.chmod(0o000)
    store_dir = tmp_path / "store"

    try:
        result = subprocess.run(
            _observer_argv(
                bus_endpoint="http://localhost:9999",
                audit_file=audit_file,
                store_dir=store_dir,
            ),
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode != 0, (
            f"Expected non-zero exit for unreadable audit file; got {result.returncode}. "
            f"stderr={result.stderr!r}"
        )
    finally:
        audit_file.chmod(0o644)


@pytest.mark.skipif(
    os.getuid() == 0,  # type: ignore[attr-defined]
    reason="chmod 000 has no effect when running as root",
)
def test_fail_closed_unreadable_audit_file_no_events_written(tmp_path: Path) -> None:
    """No trace files written when boot fails due to unreadable audit file."""
    audit_file = tmp_path / "audit.jsonl"
    audit_file.touch()
    audit_file.chmod(0o000)
    store_dir = tmp_path / "store"

    try:
        subprocess.run(
            _observer_argv(
                bus_endpoint="http://localhost:9999",
                audit_file=audit_file,
                store_dir=store_dir,
            ),
            capture_output=True,
            timeout=10,
        )

        traces_dir = store_dir / "traces"
        if traces_dir.exists():
            jsonl_files = list(traces_dir.glob("*.jsonl"))
            assert jsonl_files == [], f"Expected no trace files, found {jsonl_files}"
    finally:
        audit_file.chmod(0o644)
