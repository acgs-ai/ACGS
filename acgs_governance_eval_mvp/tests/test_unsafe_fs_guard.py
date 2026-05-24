"""Phase 2 design test #15: ChainHashAuditStore must refuse to open on
filesystems where fcntl LOCK_EX is silently advisory across hosts.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from governance.audit import ChainHashAuditStore, UnsafeAuditStorageError
from governance.audit import jsonl_chain


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


def test_local_filesystem_is_accepted(audit_path: Path) -> None:
    # tmp_path is on a local FS in CI; constructor must not raise.
    store = ChainHashAuditStore(audit_path)
    assert store.path == audit_path


def test_unknown_fs_type_is_permissive(monkeypatch: pytest.MonkeyPatch, audit_path: Path) -> None:
    monkeypatch.setattr(jsonl_chain, "_detect_fs_type", lambda path: None)
    ChainHashAuditStore(audit_path)


def test_ext4_is_accepted(monkeypatch: pytest.MonkeyPatch, audit_path: Path) -> None:
    monkeypatch.setattr(jsonl_chain, "_detect_fs_type", lambda path: "ext4")
    ChainHashAuditStore(audit_path)


@pytest.mark.parametrize(
    "fs_type",
    ["nfs", "nfs3", "nfs4", "smb", "smb2", "smb3", "cifs", "fuse", "glusterfs", "ceph", "cephfs"],
)
def test_distributed_fs_is_refused(monkeypatch: pytest.MonkeyPatch, audit_path: Path, fs_type: str) -> None:
    monkeypatch.setattr(jsonl_chain, "_detect_fs_type", lambda path: fs_type)
    with pytest.raises(UnsafeAuditStorageError) as exc_info:
        ChainHashAuditStore(audit_path)
    assert fs_type in str(exc_info.value)


def test_case_insensitive_match(monkeypatch: pytest.MonkeyPatch, audit_path: Path) -> None:
    monkeypatch.setattr(jsonl_chain, "_detect_fs_type", lambda path: "NFS4")
    with pytest.raises(UnsafeAuditStorageError):
        ChainHashAuditStore(audit_path)


def test_detect_fs_type_returns_string_or_none() -> None:
    # Smoke test: against the real /proc/self/mounts (Linux CI) the lookup
    # must return either a non-empty string or None — never raise.
    result = jsonl_chain._detect_fs_type(Path("/tmp"))
    assert result is None or (isinstance(result, str) and result)
