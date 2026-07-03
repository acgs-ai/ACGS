"""Unsafe-filesystem guard wired into the governed MCP v0 audit write path.

``_evidence_lock`` is the single chokepoint every audit append in
``governed_mcp_v0.server`` passes through. These tests prove the
filesystem-reliability probe (``governance.audit.jsonl_chain``) fires
*before* the lock is acquired or any evidence byte is written, so an
unreliable mount (NFS, CIFS, FUSE, Gluster, Ceph) fails closed with no
side effect — and that the dispatcher-level path through
``GovernedMCPServer`` surfaces the refusal too.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from governance.audit import jsonl_chain
from governance.audit.jsonl_chain import UnsafeAuditStorageError
from governed_mcp_v0._io import UnsafeAuditStorageError as ReexportedError
from governed_mcp_v0._io import _evidence_lock
from governed_mcp_v0.errors import GovernanceStorageError
from governed_mcp_v0.fixtures import create_fixture_environment
from governed_mcp_v0.server import GovernedMCPServer

_DENYLIST = ["nfs", "nfs3", "nfs4", "smb", "smb2", "smb3", "cifs", "fuse", "glusterfs", "ceph", "cephfs"]


def test_unsafe_error_is_reexported_from_io() -> None:
    # Callers of governed_mcp_v0._io must be able to catch the refusal
    # without importing governance.audit themselves.
    assert ReexportedError is UnsafeAuditStorageError


@pytest.mark.parametrize("fs_type", _DENYLIST)
def test_evidence_lock_refuses_unreliable_fs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fs_type: str) -> None:
    monkeypatch.setattr(jsonl_chain, "_detect_fs_type", lambda path: fs_type)
    audit_path = tmp_path / "evidence" / "audit.jsonl"
    with pytest.raises(UnsafeAuditStorageError) as exc_info:
        with _evidence_lock(audit_path):
            pytest.fail("lock body must never execute on an unreliable filesystem")
    assert fs_type in str(exc_info.value)
    # Fail-closed means *no* side effect: neither the audit file nor the
    # sidecar lock file may exist, and the parent dir was not created.
    assert not audit_path.exists()
    assert not audit_path.with_suffix(audit_path.suffix + ".lock").exists()
    assert not audit_path.parent.exists()


def test_evidence_lock_permissive_on_unknown_fs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(jsonl_chain, "_detect_fs_type", lambda path: None)
    audit_path = tmp_path / "evidence" / "audit.jsonl"
    with _evidence_lock(audit_path):
        pass
    assert audit_path.with_suffix(audit_path.suffix + ".lock").exists()


def test_evidence_lock_accepts_local_fs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(jsonl_chain, "_detect_fs_type", lambda path: "ext4")
    audit_path = tmp_path / "evidence" / "audit.jsonl"
    with _evidence_lock(audit_path):
        pass
    assert audit_path.with_suffix(audit_path.suffix + ".lock").exists()


@pytest.mark.parametrize("fs_type", ["nfs", "cifs", "fuse"])
def test_mcp_server_audit_write_fails_closed_on_unreliable_fs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fs_type: str
) -> None:
    # Dispatcher-level: a guarded tool call goes admit -> _record_decision
    # -> _evidence_lock; the probe must abort the whole admission with no
    # receipt, no audit line, and no filesystem effect.
    targets = create_fixture_environment(tmp_path)
    server = GovernedMCPServer(targets)
    monkeypatch.setattr(jsonl_chain, "_detect_fs_type", lambda path: fs_type)
    with pytest.raises(GovernanceStorageError) as exc_info:
        server.write_file("notes.txt", "hello")
    assert isinstance(exc_info.value.__cause__, UnsafeAuditStorageError)
    assert fs_type in str(exc_info.value)
    assert not targets.audit_path.exists()
    assert list(targets.receipts_dir.iterdir()) == []
    assert not (targets.fs_dir / "notes.txt").exists()


def test_mcp_server_audit_write_permissive_on_unknown_fs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Positive control: an undetectable filesystem stays permissive and the
    # governed write path completes with receipt + audit line.
    targets = create_fixture_environment(tmp_path)
    server = GovernedMCPServer(targets)
    monkeypatch.setattr(jsonl_chain, "_detect_fs_type", lambda path: None)
    written = server.write_file("notes.txt", "hello")
    assert written.read_text(encoding="utf-8") == "hello"
    assert targets.audit_path.exists()
    assert len(list(targets.receipts_dir.iterdir())) == 1
