"""Shared cross-process file-lock primitive.

Extracted from :mod:`acgs_proofpack_verifier.audit` so the audit chain and the receipt
consumption ledger serialize writers through one implementation. Standard
library only (``fcntl`` on POSIX, ``msvcrt`` on Windows); importing this
module requires neither — the primitive is resolved lazily when the lock is
taken. A host exposing neither primitive fails closed at lock time rather
than proceeding without serialization.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import TextIO


@contextmanager
def _exclusive_file_lock(lock_fh: TextIO) -> Generator[None, None, None]:
    """Hold an exclusive cross-process lock on the sidecar lock file.

    POSIX hosts use ``fcntl.flock`` (advisory whole-file lock). Windows hosts
    use ``msvcrt.locking`` (a mandatory byte-range lock on the first byte).
    Both serialize concurrent appenders so two writes never produce sibling
    events sharing a ``previous_hash``. Both primitives are in the standard
    library, so this adds no runtime dependency. A host exposing neither fails
    closed with a clear error rather than appending without serialization.
    """
    try:
        import fcntl
    except ModuleNotFoundError:
        fcntl = None  # type: ignore[assignment]

    if fcntl is not None:
        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
        return

    try:
        import msvcrt
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "ChainHashAuditStore append requires a platform file-lock primitive "
            "(POSIX fcntl or Windows msvcrt); neither is available on this host, "
            "so audit append cannot be serialized safely and is refused."
        ) from exc

    # Windows: lock the first byte. ``msvcrt.locking`` locks ``nbytes`` from the
    # current position and can lock a region beyond EOF, so an empty lock file is
    # fine. NOTE a semantic divergence from POSIX: ``LK_LOCK`` retries ~10 times
    # at 1s intervals and then raises ``OSError`` — it does not block
    # indefinitely like ``fcntl.flock(LOCK_EX)``. Under sustained (>~10s)
    # contention a Windows appender therefore fails closed (raises before
    # ``yield``, so no unserialized or partial append) rather than waiting.
    lock_fh.seek(0)
    msvcrt.locking(lock_fh.fileno(), msvcrt.LK_LOCK, 1)
    try:
        yield
    finally:
        lock_fh.seek(0)
        msvcrt.locking(lock_fh.fileno(), msvcrt.LK_UNLCK, 1)
