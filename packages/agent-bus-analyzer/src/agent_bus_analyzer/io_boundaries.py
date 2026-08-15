"""Bounded input and crash-safe output primitives for CLI trust boundaries."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

DEFAULT_MAX_LINE_BYTES = 1 * 1024 * 1024
DEFAULT_MAX_RECORDS = 100_000
DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_CONFIG_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class InputLimits:
    """Explicit byte and record ceilings for untrusted line-oriented inputs."""

    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES
    max_records: int = DEFAULT_MAX_RECORDS
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES

    def __post_init__(self) -> None:
        for name, value in (
            ("max_line_bytes", self.max_line_bytes),
            ("max_records", self.max_records),
            ("max_total_bytes", self.max_total_bytes),
        ):
            if isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


def _positive_int(raw: str) -> int:
    value = int(raw)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


def add_input_limit_arguments(parser: argparse.ArgumentParser) -> None:
    """Expose consistent, operator-configurable line/record/total limits."""
    parser.add_argument(
        "--max-input-line-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_LINE_BYTES,
        help=f"Maximum bytes per input line (default: {DEFAULT_MAX_LINE_BYTES})",
    )
    parser.add_argument(
        "--max-input-records",
        type=_positive_int,
        default=DEFAULT_MAX_RECORDS,
        help=f"Maximum non-empty input records (default: {DEFAULT_MAX_RECORDS})",
    )
    parser.add_argument(
        "--max-input-total-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_TOTAL_BYTES,
        help=f"Maximum total input bytes (default: {DEFAULT_MAX_TOTAL_BYTES})",
    )


def input_limits_from_namespace(args: argparse.Namespace) -> InputLimits:
    """Build limits while remaining compatible with older programmatic namespaces."""
    return InputLimits(
        max_line_bytes=getattr(args, "max_input_line_bytes", DEFAULT_MAX_LINE_BYTES),
        max_records=getattr(args, "max_input_records", DEFAULT_MAX_RECORDS),
        max_total_bytes=getattr(args, "max_input_total_bytes", DEFAULT_MAX_TOTAL_BYTES),
    )


@contextmanager
def open_regular_binary(
    path: Path,
    *,
    purpose: str,
    owner_only: bool = False,
) -> Iterator[BinaryIO]:
    """Open a regular file without following its final path component."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{purpose} must be a readable non-symlink regular file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{purpose} must be a regular file")
        if owner_only and (
            metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ValueError(f"{purpose} must be an owner-only regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            yield handle
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _bounded_lines_from_handle(
    handle: Any,
    *,
    limits: InputLimits,
    source: str,
) -> Iterator[tuple[int, bytes]]:
    total_bytes = 0
    records = 0
    line_number = 0
    while True:
        raw = handle.readline(limits.max_line_bytes + 1)
        if raw == b"" or raw == "":
            return
        line_number += 1
        raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
        if len(raw_bytes) > limits.max_line_bytes:
            raise ValueError(
                f"input line exceeds {limits.max_line_bytes} bytes at {source}:{line_number}"
            )
        total_bytes += len(raw_bytes)
        if total_bytes > limits.max_total_bytes:
            raise ValueError(f"input exceeds {limits.max_total_bytes} total bytes: {source}")
        if raw_bytes.strip():
            records += 1
            if records > limits.max_records:
                raise ValueError(f"input exceeds {limits.max_records} records: {source}")
        yield line_number, raw_bytes


def iter_bounded_lines(
    path: str | Path,
    *,
    limits: InputLimits,
    purpose: str,
    allow_stdin: bool = False,
    owner_only: bool = False,
) -> Iterator[tuple[int, bytes]]:
    """Stream bounded lines from stdin or a no-follow regular file."""
    if str(path) == "-":
        if not allow_stdin:
            raise ValueError(f"{purpose} does not accept stdin")
        handle = getattr(sys.stdin, "buffer", sys.stdin)
        yield from _bounded_lines_from_handle(handle, limits=limits, source="stdin")
        return
    input_path = Path(path)
    with open_regular_binary(input_path, purpose=purpose, owner_only=owner_only) as handle:
        yield from _bounded_lines_from_handle(handle, limits=limits, source=str(input_path))


def iter_jsonl_objects(
    path: str | Path,
    *,
    limits: InputLimits,
    purpose: str,
    allow_stdin: bool = False,
    owner_only: bool = False,
) -> Iterator[tuple[int, dict[str, Any]]]:
    """Parse bounded JSONL while requiring object records with string keys."""
    source = "stdin" if str(path) == "-" else str(path)
    for line_number, raw_line in iter_bounded_lines(
        path,
        limits=limits,
        purpose=purpose,
        allow_stdin=allow_stdin,
        owner_only=owner_only,
    ):
        if not raw_line.strip():
            continue
        try:
            decoded = raw_line.decode("utf-8")
            value: Any = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"malformed JSONL at {source}:{line_number}: {exc}") from exc
        if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
            raise ValueError(f"JSONL record must be an object at {source}:{line_number}")
        yield line_number, value


def read_bounded_regular_bytes(
    path: Path,
    *,
    max_bytes: int,
    purpose: str,
    owner_only: bool = False,
) -> bytes:
    """Read a bounded security/configuration file through the no-follow gate."""
    if isinstance(max_bytes, bool) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    with open_regular_binary(path, purpose=purpose, owner_only=owner_only) as handle:
        payload = handle.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise ValueError(f"{purpose} exceeds {max_bytes} bytes")
    return payload


@contextmanager
def _output_directory(path: Path) -> Iterator[tuple[int, str]]:
    if path.name in {"", ".", ".."}:
        raise ValueError(f"output path must name a file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directory = os.open(path.parent, flags)
    except OSError as exc:
        raise ValueError(f"output parent must be a non-symlink directory: {path.parent}") from exc
    try:
        yield directory, path.name
    finally:
        os.close(directory)


def _target_metadata(directory: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _validate_output_metadata(
    metadata: os.stat_result | None,
    *,
    path: Path,
    overwrite: bool,
) -> None:
    if metadata is None:
        return
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"refusing symlink output: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"output must be a regular file: {path}")
    if not overwrite:
        raise ValueError(f"refusing to overwrite output without --force: {path}")


def preflight_output_path(path: Path, *, overwrite: bool) -> None:
    """Validate both current output type and overwrite intent before work begins."""
    with _output_directory(path) as (directory, name):
        _validate_output_metadata(
            _target_metadata(directory, name),
            path=path,
            overwrite=overwrite,
        )


def atomic_write_bytes(path: Path, payload: bytes, *, overwrite: bool) -> None:
    """Publish bytes atomically, no-follow, mode 0600, and fsync the directory."""
    with _output_directory(path) as (directory, name):
        _validate_output_metadata(
            _target_metadata(directory, name),
            path=path,
            overwrite=overwrite,
        )
        temporary = f".{name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
        flags = (
            os.O_CREAT
            | os.O_EXCL
            | os.O_WRONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            if overwrite:
                os.replace(
                    temporary,
                    name,
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                )
            else:
                try:
                    os.link(
                        temporary,
                        name,
                        src_dir_fd=directory,
                        dst_dir_fd=directory,
                        follow_symlinks=False,
                    )
                except FileExistsError as exc:
                    raise ValueError(
                        f"refusing to overwrite output without --force: {path}"
                    ) from exc
                os.unlink(temporary, dir_fd=directory)
            os.fsync(directory)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass


def remove_regular_output(path: Path) -> bool:
    """Remove an existing regular output/commit marker without following links."""
    with _output_directory(path) as (directory, name):
        metadata = _target_metadata(directory, name)
        if metadata is None:
            return False
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"refusing symlink output: {path}")
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"output must be a regular file: {path}")
        os.unlink(name, dir_fd=directory)
        os.fsync(directory)
        return True


def paths_refer_to_same_file(first: Path, second: Path) -> bool:
    """Detect lexical aliases and existing hard-link/symlink aliases."""
    if os.path.abspath(first) == os.path.abspath(second):
        return True
    try:
        return first.exists() and second.exists() and os.path.samefile(first, second)
    except OSError:
        return False


def raw_sha256(payload: bytes) -> str:
    """Return the digest of the exact bytes published at an artifact boundary."""
    return hashlib.sha256(payload).hexdigest()
