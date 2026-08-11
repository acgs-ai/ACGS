"""Append-only authority-evidence registry (JSONL) in THIS package.

Never in the substrate. Blank lines are tolerated; a malformed non-blank line
is a fail-closed error, not a silently skipped record — a registry that cannot
be fully parsed must not be treated as if the unparseable records were absent.

The registry file is opened through a PINNED parent directory descriptor with
no-follow semantics: a registry path replaced by a symlink to a writable
external file would otherwise be read from — and appended to — by a fully
authenticated ingestion, reporting INGESTED while corrupting a file outside
the configured registry store.

For appends the parent descriptor is RETAINED through the write and the
directory entry revalidated afterwards: the no-follow open alone does not
stop a rename-and-replace after the open, which would leave the record on a
detached inode while ingestion reports INGESTED and the configured registry
gains nothing.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

REGISTRY_NAME = "authority_evidence_registry.jsonl"


class RegistryError(RuntimeError):
    """The registry contains a line that cannot be parsed, or the registry
    path cannot be securely opened (symlinked/non-regular) — fail closed."""


def _open_registry_fd(path: Path, flags: int) -> tuple[int, int] | None:
    """Open the registry's final path component relative to its parent
    directory descriptor with O_NOFOLLOW, and require a regular file.

    Returns (fd, parent_fd) — the caller owns and must close BOTH. The parent
    descriptor is handed back so append paths can revalidate the directory
    entry after writing. Returns None when neither the file (nor, for
    read-only opens, its parent) exists. A symlink at the registry path — or
    a non-regular occupant — is refused, never followed."""
    absolute = path.absolute()
    if absolute.name in ("", ".", ".."):
        raise RegistryError(f"invalid registry path: {path}")
    try:
        parent_fd = os.open(absolute.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError as exc:
        if flags & os.O_CREAT:
            raise RegistryError(
                f"registry parent directory does not exist: {absolute.parent}"
            ) from exc
        return None
    except OSError as exc:
        raise RegistryError(
            f"registry parent is not a real directory (symlinked?): {absolute.parent}: {exc}"
        ) from exc
    handed_over = False
    try:
        try:
            fd = os.open(absolute.name, flags | os.O_NOFOLLOW, 0o644, dir_fd=parent_fd)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise RegistryError(
                f"cannot securely open registry {path} (symlinked registry path?): {exc}"
            ) from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise RegistryError(f"registry is not a regular file: {path}")
        except Exception:
            os.close(fd)
            raise
        handed_over = True
        return fd, parent_fd
    finally:
        if not handed_over:
            os.close(parent_fd)


def read_registry(path: Path) -> list[dict[str, Any]]:
    opened = _open_registry_fd(path, os.O_RDONLY)
    if opened is None:
        return []
    fd, parent_fd = opened
    os.close(parent_fd)
    with os.fdopen(fd, "r", encoding="utf-8") as fh:
        text = fh.read()
    out: list[dict[str, Any]] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw)
        except ValueError as exc:
            raise RegistryError(f"{path}:{lineno}: malformed JSONL: {exc}") from exc
        if not isinstance(rec, dict):
            raise RegistryError(f"{path}:{lineno}: record is not an object")
        out.append(rec)
    return out


def append_record(path: Path, record: dict[str, Any]) -> None:
    line = json.dumps(record, sort_keys=True, ensure_ascii=False)
    opened = _open_registry_fd(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
    assert opened is not None  # O_CREAT: only a raised RegistryError returns no fd
    fd, parent_fd = opened
    try:
        data = (line + "\n").encode("utf-8")
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
        # Revalidate the directory entry through the RETAINED parent
        # descriptor: a rename-and-replace after the open would leave this
        # record on a detached inode while the configured registry contains
        # nothing new — ingestion must fail loudly, never report INGESTED
        # for a record the registry does not hold.
        pinned = os.fstat(fd)
        try:
            named = os.stat(path.absolute().name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise RegistryError(
                f"registry entry vanished during append (record on a detached "
                f"file, not in the configured registry): {path}: {exc}"
            ) from exc
        if (named.st_dev, named.st_ino) != (pinned.st_dev, pinned.st_ino):
            raise RegistryError(
                f"registry was replaced during append — the record landed on a "
                f"detached file, not in the configured registry: {path}"
            )
    finally:
        os.close(fd)
        os.close(parent_fd)
