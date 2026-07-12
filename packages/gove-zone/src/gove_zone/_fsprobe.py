"""Unsafe-filesystem startup probe for the audit store (FINAL-GOAL G1.6).

The audit chain's append-only guarantee depends on ``fcntl.flock`` serializing
concurrent writers (see :mod:`gove_zone._locking`). On an NFS mount **without a
running lock manager (lockd/NLM)**, ``flock`` can silently succeed without
actually excluding other writers, so two processes may append sibling events
sharing a ``previous_hash`` and corrupt the chain. There is no portable runtime
API that reports "does this NFS export have lockd?", so the probe takes the
conservative, fail-closed position: if the audit path resolves to a *network*
filesystem known to make ``flock`` unreliable (``nfs``/``nfs4``), the store
refuses to start unless the operator explicitly opts in.

Design constraints:

- **Standard library only** — gove-zone declares zero runtime dependencies. The
  probe reads ``/proc/self/mountinfo`` (Linux), which needs no ``ctypes`` or
  syscall bindings and is trivial to unit-test by injecting fixture text.
- **Default-safe off the known-risk path** — on non-Linux hosts, or when the
  filesystem type cannot be determined, the probe returns *safe*. It targets the
  specific, documented NFS-without-lockd risk rather than second-guessing local
  disks (ext4/xfs/apfs/ntfs), tmpfs, or CI overlay mounts.
- **Injectable** — :func:`filesystem_is_lock_safe` is a pure function of the
  path plus (optionally) a mountinfo-text reader, so tests simulate an NFS mount
  without needing a real export.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path

# Filesystem types whose whole-file advisory locking (``fcntl.flock``) is not a
# reliable cross-process mutex without additional infrastructure (an NFS lock
# manager). Kept deliberately narrow: only network filesystems with the
# documented lockd dependency are refused by default.
_LOCK_UNSAFE_FSTYPES: frozenset[str] = frozenset({"nfs", "nfs4"})

_MOUNTINFO_PATH = "/proc/self/mountinfo"

#: Environment variable an operator sets (to ``"1"``) to bypass the refusal when
#: they know their NFS export runs lockd and locking is therefore reliable.
ALLOW_UNSAFE_FS_ENV = "GOVE_ZONE_ALLOW_UNSAFE_FS"


def _read_mountinfo() -> str | None:
    """Return the raw text of ``/proc/self/mountinfo``, or ``None`` if absent.

    Absent on non-Linux hosts (macOS/Windows) and inside minimal sandboxes; a
    ``None`` return makes the probe default to *safe*.
    """
    try:
        with open(_MOUNTINFO_PATH, encoding="utf-8") as fh:
            return fh.read()
    except (OSError, ValueError):
        return None


def _fstype_for_path(resolved: Path, mountinfo_text: str) -> str | None:
    """Resolve *resolved* to its filesystem type using mountinfo text.

    ``/proc/self/mountinfo`` lines look like::

        36 35 98:0 / /mnt/nfs rw,... - nfs4 server:/export rw,...

    The mount point is field index 4 (0-based); the filesystem type is the first
    field after the ``-`` separator. The longest mount-point prefix that
    contains *resolved* wins (nested mounts). Returns ``None`` when no mount
    matches (should not happen for a real path, but keeps the caller fail-safe).
    """
    best_type: str | None = None
    best_len = -1
    for line in mountinfo_text.splitlines():
        fields = line.split()
        if "-" not in fields:
            continue
        sep = fields.index("-")
        # Mount point is field 4; fstype is the field immediately after ``-``.
        if sep < 5 or sep + 1 >= len(fields):
            continue
        mount_point = fields[4]
        fstype = fields[sep + 1]
        try:
            mp = Path(mount_point)
        except (TypeError, ValueError):
            continue
        if _path_is_within(resolved, mp) and len(mount_point) > best_len:
            best_type = fstype
            best_len = len(mount_point)
    return best_type


def _path_is_within(candidate: Path, mount_point: Path) -> bool:
    """True when *candidate* is at or below *mount_point*."""
    try:
        candidate.relative_to(mount_point)
        return True
    except ValueError:
        return False


def filesystem_is_lock_safe(
    path: str | os.PathLike[str],
    *,
    mountinfo_reader: Callable[[], str | None] = _read_mountinfo,
) -> bool:
    """Return ``True`` if *path* lives on a filesystem safe for ``flock``-based
    cross-process serialization, ``False`` for a known lock-unsafe network mount.

    Fail-safe defaults (return ``True``): non-Linux hosts, unreadable/absent
    mountinfo, or an undeterminable filesystem type. Only a positive match
    against :data:`_LOCK_UNSAFE_FSTYPES` (``nfs``/``nfs4``) returns ``False``.

    *mountinfo_reader* is injectable so tests can simulate an NFS mount without a
    real export.
    """
    if not sys.platform.startswith("linux"):
        # macOS/Windows use different lock primitives; the NFS-without-lockd
        # risk this probe targets is Linux-specific. Default safe.
        return True

    mountinfo_text = mountinfo_reader()
    if not mountinfo_text:
        return True

    try:
        resolved = Path(path).resolve()
    except (OSError, ValueError):
        return True

    fstype = _fstype_for_path(resolved, mountinfo_text)
    if fstype is None:
        return True
    return fstype.lower() not in _LOCK_UNSAFE_FSTYPES


def unsafe_fs_override_enabled() -> bool:
    """Return ``True`` when the operator override env var is set to ``"1"``."""
    return os.environ.get(ALLOW_UNSAFE_FS_ENV, "") == "1"
