"""Tests for the unsafe-filesystem startup probe (FINAL-GOAL gate G1.6).

Proves that ``ChainHashAuditStore`` refuses to start when its audit path lives on
a lock-unsafe network filesystem (NFS without lockd), fails closed with no side
effects, honors the operator override, and stays permissive on safe/local mounts
and non-Linux hosts. Detection is exercised directly against injected mountinfo
text so no real NFS export is required.
"""

from __future__ import annotations

import pytest

import gove_zone.audit as audit_mod
from gove_zone._fsprobe import (
    ALLOW_UNSAFE_FS_ENV,
    filesystem_is_lock_safe,
    unsafe_fs_override_enabled,
)
from gove_zone.audit import ChainHashAuditStore
from gove_zone.errors import AuditError, UnsafeAuditFilesystemError

# A realistic /proc/self/mountinfo with root on ext4 and /mnt/nfs on nfs4.
_MOUNTINFO_NFS = (
    "22 27 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw\n"
    "36 35 98:0 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
    "41 36 0:36 / /mnt/nfs rw,relatime shared:29 - nfs4 srv:/export "
    "rw,vers=4.2,addr=10.0.0.2\n"
)

# All-local mountinfo: root ext4, /tmp tmpfs. No network filesystem.
_MOUNTINFO_LOCAL = (
    "36 35 98:0 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
    "37 36 0:22 / /tmp rw,nosuid,nodev shared:7 - tmpfs tmpfs rw\n"
)


def _reader(text: str):
    return lambda: text


# --- pure detection ---------------------------------------------------------


def test_nfs_mount_detected_as_unsafe() -> None:
    assert (
        filesystem_is_lock_safe("/mnt/nfs/audit.jsonl", mountinfo_reader=_reader(_MOUNTINFO_NFS))
        is False
    )


def test_nested_nfs_path_detected_as_unsafe() -> None:
    # A deeper path under the NFS mount must still resolve to nfs4.
    assert (
        filesystem_is_lock_safe(
            "/mnt/nfs/sub/dir/audit.jsonl", mountinfo_reader=_reader(_MOUNTINFO_NFS)
        )
        is False
    )


def test_local_ext4_path_is_safe() -> None:
    assert (
        filesystem_is_lock_safe("/var/log/audit.jsonl", mountinfo_reader=_reader(_MOUNTINFO_NFS))
        is True
    )


def test_all_local_mountinfo_is_safe() -> None:
    assert (
        filesystem_is_lock_safe("/tmp/x/audit.jsonl", mountinfo_reader=_reader(_MOUNTINFO_LOCAL))
        is True
    )


def test_missing_mountinfo_defaults_safe() -> None:
    # Unreadable/absent mountinfo (non-Linux, sandbox) -> fail-safe True.
    assert filesystem_is_lock_safe("/mnt/nfs/audit.jsonl", mountinfo_reader=lambda: None) is True


def test_empty_mountinfo_defaults_safe() -> None:
    assert filesystem_is_lock_safe("/mnt/nfs/audit.jsonl", mountinfo_reader=lambda: "") is True


def test_override_env_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ALLOW_UNSAFE_FS_ENV, raising=False)
    assert unsafe_fs_override_enabled() is False
    monkeypatch.setenv(ALLOW_UNSAFE_FS_ENV, "1")
    assert unsafe_fs_override_enabled() is True
    monkeypatch.setenv(ALLOW_UNSAFE_FS_ENV, "0")
    assert unsafe_fs_override_enabled() is False


# --- store construction wiring ---------------------------------------------


def test_store_refuses_unsafe_fs_side_effect_free(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(ALLOW_UNSAFE_FS_ENV, raising=False)
    monkeypatch.setattr(audit_mod, "filesystem_is_lock_safe", lambda path: False)
    audit_path = tmp_path / "nfs" / "audit.jsonl"
    with pytest.raises(UnsafeAuditFilesystemError):
        ChainHashAuditStore(audit_path)
    # Side-effect-free refusal: neither the audit file nor its parent dir exist.
    assert not audit_path.exists()
    assert not audit_path.parent.exists()


def test_unsafe_fs_error_is_audit_error(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    # Callers catching AuditError must treat an unsafe store as fail-closed.
    monkeypatch.delenv(ALLOW_UNSAFE_FS_ENV, raising=False)
    monkeypatch.setattr(audit_mod, "filesystem_is_lock_safe", lambda path: False)
    with pytest.raises(AuditError):
        ChainHashAuditStore(tmp_path / "audit.jsonl")


def test_escape_hatch_allows_unsafe_fs(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit_mod, "filesystem_is_lock_safe", lambda path: False)
    monkeypatch.setenv(ALLOW_UNSAFE_FS_ENV, "1")
    audit_path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(audit_path)  # must NOT raise
    assert store.path == audit_path


def test_safe_detection_constructs_normally(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ALLOW_UNSAFE_FS_ENV, raising=False)
    monkeypatch.setattr(audit_mod, "filesystem_is_lock_safe", lambda path: True)
    audit_path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(audit_path)
    assert store.path == audit_path
    assert audit_path.parent.exists()
