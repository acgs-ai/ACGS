"""Audit-chain integrity tests.

Covers:

- Empty store reports genesis hash.
- Single append links to genesis and advances last_hash.
- N sequential appends produce a chain that ``verify_chain`` accepts.
- Tampering with ``event_hash`` is detected.
- Tampering with ``previous_hash`` is detected.
- ``query`` filters by predicate.
- N concurrent process-level writers preserve chain integrity (no two events
  share a ``previous_hash``; ``verify_chain`` accepts the result). Writers run in
  separate interpreter processes (not fork), so the test runs identically on
  Linux, macOS, and Windows, exercising each platform's real audit-lock branch.
"""

from __future__ import annotations

import builtins
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from gove_zone import (
    GENESIS_HASH,
    ChainHashAuditStore,
    Decision,
    DecisionRecord,
    sha256_json,
)


def _record(event_id: str, tool: str = "write_file") -> DecisionRecord:
    return DecisionRecord(
        decision=Decision.ALLOW,
        tool=tool,
        argument_hash=sha256_json({"id": event_id}),
        policy_version="v0",
        event_id=event_id,
    )


def test_append_fails_closed_without_lock_primitive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No POSIX ``fcntl`` and no Windows ``msvcrt`` -> append refuses rather than
    writing an unserialized event. Fail-closed, never a silent unsafe append."""
    real_import = builtins.__import__

    def _no_lock_import(name: str, *args: object, **kwargs: object) -> object:
        if name in {"fcntl", "msvcrt"}:
            raise ModuleNotFoundError(name)
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", _no_lock_import)

    audit_path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(audit_path)
    with pytest.raises(RuntimeError, match="file-lock primitive"):
        store.append(_record("e1"))

    # Fail-closed: the refused append left no event in the chain.
    assert not audit_path.exists() or audit_path.stat().st_size == 0


def test_empty_chain_has_genesis_hash(tmp_path: Path) -> None:
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    assert store.last_hash() == GENESIS_HASH


def test_single_append_links_to_genesis(tmp_path: Path) -> None:
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    payload = store.append(_record("e1"))
    assert payload["previous_hash"] == GENESIS_HASH
    assert payload["event_hash"] != GENESIS_HASH
    assert store.last_hash() == payload["event_hash"]


def test_chain_verifies_after_sequential_appends(tmp_path: Path) -> None:
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    for i in range(20):
        store.append(_record(f"e{i}"))
    result = store.verify_chain()
    assert result["valid"] is True
    assert result["checked"] == 20
    assert result["failures"] == []


def test_interleaved_store_instances_reread_tail_under_lock(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    store_a = ChainHashAuditStore(path)
    store_b = ChainHashAuditStore(path)

    first = store_a.append(_record("e1"))
    second = store_b.append(_record("e2"))
    third = store_a.append(_record("e3"))

    assert second["previous_hash"] == first["event_hash"]
    assert third["previous_hash"] == second["event_hash"]
    result = ChainHashAuditStore(path).verify_chain()
    assert result["valid"] is True
    assert result["checked"] == 3


def test_chain_detects_tampered_event_hash(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    for i in range(5):
        store.append(_record(f"e{i}"))
    lines = path.read_text().splitlines()
    event = json.loads(lines[2])
    event["event_hash"] = "0" * 64
    lines[2] = json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")

    result = ChainHashAuditStore(path).verify_chain()
    assert result["valid"] is False
    assert any(f["type"] == "event_hash_mismatch" for f in result["failures"])


def test_chain_detects_tampered_previous_hash(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    for i in range(5):
        store.append(_record(f"e{i}"))
    lines = path.read_text().splitlines()
    event = json.loads(lines[2])
    event["previous_hash"] = "0" * 64
    lines[2] = json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")

    result = ChainHashAuditStore(path).verify_chain()
    assert result["valid"] is False
    # Tampering previous_hash without re-signing event_hash trips both checks.
    assert any(f["type"] == "previous_hash_mismatch" for f in result["failures"])


def test_query_filter_predicate(tmp_path: Path) -> None:
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    for i in range(10):
        store.append(_record(f"e{i}", tool="write_file" if i % 2 == 0 else "http_post"))
    writes = store.query(where=lambda e: e["tool"] == "write_file", limit=100)
    assert len(writes) == 5
    assert all(w["tool"] == "write_file" for w in writes)


# Worker program run in a *separate* interpreter process (one per concurrent
# writer). Launching real OS processes -- rather than multiprocessing with the
# "fork" start method -- makes this test OS-agnostic: it runs identically on
# Linux, macOS, and Windows (which has no "fork"), and each worker exercises the
# platform's real audit-lock branch (POSIX ``fcntl`` or Windows ``msvcrt``).
# Using ``sys.executable`` guarantees the workers share this test run's venv, so
# ``import gove_zone`` resolves without any sys.path juggling. A subprocess also
# sidesteps the spawn/pickle constraint under pytest's ``--import-mode=importlib``
# (the test module is not re-importable by name in a fresh interpreter).
_WORKER_PROGRAM = textwrap.dedent(
    """
    import sys
    from gove_zone import ChainHashAuditStore, Decision, DecisionRecord, sha256_json

    path, count, prefix = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    store = ChainHashAuditStore(path)
    for i in range(count):
        event_id = f"{prefix}-{i}"
        store.append(
            DecisionRecord(
                decision=Decision.ALLOW,
                tool="write_file",
                argument_hash=sha256_json({"id": event_id}),
                policy_version="v0",
                event_id=event_id,
            )
        )
    """
)


def test_concurrent_appends_preserve_chain_integrity(tmp_path: Path) -> None:
    path = str(tmp_path / "audit.jsonl")
    n_workers = 4
    per_worker = 25

    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _WORKER_PROGRAM, path, str(per_worker), f"w{i}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for i in range(n_workers)
    ]
    for proc in procs:
        stdout, stderr = proc.communicate(timeout=120)
        assert proc.returncode == 0, (
            f"worker exited with {proc.returncode}\nstdout: {stdout}\nstderr: {stderr}"
        )

    result = ChainHashAuditStore(path).verify_chain()
    assert result["valid"] is True, f"chain broken: {result['failures'][:3]}"
    assert result["checked"] == n_workers * per_worker
