"""Follow-up to design test #15 (issue #107): the unreliable-filesystem
denylist must catch subtyped FUSE mounts (``fuse.<subtype>``) and the
``overlay``/``9p`` families, and must expose a public guard name shared with
the governed-MCP IO layer.

Regression: Linux reports FUSE mounts in ``/proc/self/mounts`` as
``fuse.sshfs``, ``fuse.glusterfs`` etc. The original ``fs_type.lower() in
_UNRELIABLE_FS`` exact-match check only held the bare token ``fuse``, so every
subtyped FUSE mount silently bypassed the guard and the audit store opened on a
filesystem with advisory-only ``LOCK_EX`` semantics.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from governance.audit import (
    ChainHashAuditStore,
    UnsafeAuditStorageError,
    refuse_unreliable_fs,
)
from governance.audit import jsonl_chain


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.mark.parametrize(
    "fs_type",
    [
        "fuse.sshfs",
        "fuse.glusterfs",
        "fuse.s3fs",
        "fuse.ceph",
        "FUSE.SSHFS",  # case-insensitive family match
        "overlay",
        "overlayfs",
        "9p",
    ],
)
def test_subtyped_and_new_unreliable_fs_is_refused(
    monkeypatch: pytest.MonkeyPatch, audit_path: Path, fs_type: str
) -> None:
    monkeypatch.setattr(jsonl_chain, "_detect_fs_type", lambda path: fs_type)
    with pytest.raises(UnsafeAuditStorageError) as exc_info:
        ChainHashAuditStore(audit_path)
    assert fs_type in str(exc_info.value)


@pytest.mark.parametrize(
    "fs_type",
    [
        "fuseblk",  # local FUSE block device (ntfs-3g); no dotted subtype
        "fusectl",  # FUSE control pseudo-filesystem
        "ext4",
        "xfs",
        "btrfs",
    ],
)
def test_local_fuse_and_common_fs_stay_permissive(
    monkeypatch: pytest.MonkeyPatch, audit_path: Path, fs_type: str
) -> None:
    # ``fuseblk``/``fusectl`` share the ``fuse`` prefix but are NOT the dotted
    # ``fuse.<subtype>`` convention, so they must not be over-blocked.
    monkeypatch.setattr(jsonl_chain, "_detect_fs_type", lambda path: fs_type)
    store = ChainHashAuditStore(audit_path)
    assert store.path == audit_path


def test_is_unreliable_fs_type_unit() -> None:
    assert jsonl_chain._is_unreliable_fs_type("fuse.sshfs") is True
    assert jsonl_chain._is_unreliable_fs_type("FUSE.S3FS") is True
    assert jsonl_chain._is_unreliable_fs_type("overlay") is True
    assert jsonl_chain._is_unreliable_fs_type("9p") is True
    assert jsonl_chain._is_unreliable_fs_type("nfs4") is True
    # Permissive boundary.
    assert jsonl_chain._is_unreliable_fs_type("fuseblk") is False
    assert jsonl_chain._is_unreliable_fs_type("fusectl") is False
    assert jsonl_chain._is_unreliable_fs_type("ext4") is False


def test_public_guard_is_exported_and_aliased() -> None:
    # The governed-MCP IO layer imports the public name from the package API;
    # the private alias must remain the identical object for back-compat.
    assert refuse_unreliable_fs is jsonl_chain.refuse_unreliable_fs
    assert jsonl_chain._refuse_unreliable_fs is refuse_unreliable_fs


def test_public_guard_refuses_subtyped_fuse(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(jsonl_chain, "_detect_fs_type", lambda path: "fuse.sshfs")
    with pytest.raises(UnsafeAuditStorageError):
        refuse_unreliable_fs(tmp_path)
