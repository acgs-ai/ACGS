"""Reusable sealed proof-pack encoding and filesystem integrity mechanics.

This module deliberately knows nothing about release, MCP, receipt, policy,
audit, replay, or consumption semantics.  A caller supplies one immutable
schema and performs all domain verification after the codec has established
canonical bytes, exact membership, content hashes, and stable path identity.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import hmac
import json
import os
import secrets
import stat
import sys
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

from gove_zone.decision import canonical_json
from gove_zone.path_capability import (
    AttestedDirectory,
    OwnedAttestedDirectory,
    _duplicate_owned_attested_directory,
    _mint_attested_directory,
    is_descriptor_alias_path,
    require_attested_directory,
)

_SHA256 = frozenset("0123456789abcdef")
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_WRITE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_PROC_SELF_FD = Path("/proc/self/fd")
_PROC_DIRECTORY_FLAGS = _DIRECTORY_FLAGS & ~getattr(os, "O_NOFOLLOW", 0)


class SealedPackError(RuntimeError):
    """A sealed pack failed structural, canonical, or filesystem validation."""


class SealedPackExportState:
    """Machine-readable filesystem truth attached to an export failure."""

    committed: bool
    parent_identity_preserved: bool | None
    pinned_final_entry_exists: bool | None
    lexical_final_path_exists: bool | None
    final_path_exists: bool | None
    cleanup_attempted: bool
    cleanup_succeeded: bool | None
    durability_uncertain: bool
    retry_safe: bool
    phase: str
    final_path: Path
    temp_path: Path | None
    temp_path_exists: bool | None

    def _initialize_export_state(
        self,
        *,
        committed: bool,
        parent_identity_preserved: bool | None,
        pinned_final_entry_exists: bool | None,
        lexical_final_path_exists: bool | None,
        final_path_exists: bool | None,
        cleanup_attempted: bool,
        cleanup_succeeded: bool | None,
        durability_uncertain: bool,
        retry_safe: bool,
        phase: str,
        final_path: Path,
        temp_path: Path | None,
        temp_path_exists: bool | None,
    ) -> None:
        self.committed = committed
        self.parent_identity_preserved = parent_identity_preserved
        self.pinned_final_entry_exists = pinned_final_entry_exists
        self.lexical_final_path_exists = lexical_final_path_exists
        self.final_path_exists = final_path_exists
        self.cleanup_attempted = cleanup_attempted
        self.cleanup_succeeded = cleanup_succeeded
        self.durability_uncertain = durability_uncertain
        self.retry_safe = retry_safe
        self.phase = phase
        self.final_path = final_path
        self.temp_path = temp_path
        self.temp_path_exists = temp_path_exists


class SealedPackExportError(SealedPackError, SealedPackExportState):
    """A sealed-pack export failed with explicit commit and cleanup state."""

    def __init__(
        self,
        message: str,
        *,
        committed: bool,
        parent_identity_preserved: bool | None,
        pinned_final_entry_exists: bool | None,
        lexical_final_path_exists: bool | None,
        final_path_exists: bool | None,
        cleanup_attempted: bool,
        cleanup_succeeded: bool | None,
        durability_uncertain: bool,
        retry_safe: bool,
        phase: str,
        final_path: Path,
        temp_path: Path | None,
        temp_path_exists: bool | None,
    ) -> None:
        SealedPackError.__init__(self, message)
        self._initialize_export_state(
            committed=committed,
            parent_identity_preserved=parent_identity_preserved,
            pinned_final_entry_exists=pinned_final_entry_exists,
            lexical_final_path_exists=lexical_final_path_exists,
            final_path_exists=final_path_exists,
            cleanup_attempted=cleanup_attempted,
            cleanup_succeeded=cleanup_succeeded,
            durability_uncertain=durability_uncertain,
            retry_safe=retry_safe,
            phase=phase,
            final_path=final_path,
            temp_path=temp_path,
            temp_path_exists=temp_path_exists,
        )


ErrorType = type[RuntimeError]
DirectoryIdentity = tuple[int, int]
OpenDirectory = Callable[[Path], tuple[int, DirectoryIdentity]]
AssertPathIdentity = Callable[[Path, DirectoryIdentity], None]
AssertMembership = Callable[[int, frozenset[str], str], None]
ReadFileAt = Callable[[int, str, str], bytes]
WriteNewAt = Callable[[int, str, bytes], None]
ReadExact = Callable[[int, int, str], bytes]


def _relative_parts(path: str | Path, *, error_type: ErrorType) -> tuple[str, ...]:
    relative = Path(path)
    parts = relative.parts
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in parts):
        raise error_type("pinned output paths must be normalized relative paths")
    return parts


def _open_verified_proc_descriptor(
    descriptor: int,
    expected: DirectoryIdentity,
    *,
    error_type: ErrorType,
) -> int:
    proc_path = _PROC_SELF_FD / str(descriptor)
    try:
        duplicate = os.open(proc_path, _PROC_DIRECTORY_FLAGS)
        info = os.fstat(duplicate)
        source = os.fstat(descriptor)
    except OSError as exc:
        raise error_type("compatible procfs descriptor paths are unavailable") from exc
    if (
        _identity(info) != expected
        or _identity(source) != expected
        or not stat.S_ISDIR(info.st_mode)
    ):
        os.close(duplicate)
        raise error_type("procfs descriptor path does not retain the expected directory")
    return duplicate


class PinnedOutputRoot:
    """Retain an output inode and expose only descriptor-pinned operations.

    Pathname-only local fixtures receive verified ``/proc/self/fd`` paths. No
    lexical fallback is provided when procfs is missing or incompatible.
    """

    def __init__(
        self,
        path: Path,
        parent_fd: int,
        root_fd: int,
        parent_identity: DirectoryIdentity,
        root_identity: DirectoryIdentity,
        *,
        error_type: ErrorType,
    ) -> None:
        self.path = path
        self.parent_fd = parent_fd
        self.root_fd = root_fd
        self.parent_identity = parent_identity
        self.root_identity = root_identity
        self.error_type = error_type
        self._closed = False
        self._attest_in_progress = False

    @classmethod
    def create(
        cls,
        path: str | Path,
        *,
        error_type: ErrorType = SealedPackError,
    ) -> PinnedOutputRoot:
        absolute, _parts = _absolute_parts(Path(path), error_type=error_type)
        if not _safe_basename(absolute.name):
            raise error_type("pinned output root must end in a safe basename")
        parent_fd = -1
        root_fd = -1
        created = False
        try:
            parent_fd, parent_identity = open_directory(
                absolute.parent,
                error_type=error_type,
            )
            proc_parent = _open_verified_proc_descriptor(
                parent_fd,
                parent_identity,
                error_type=error_type,
            )
            os.close(proc_parent)
            before = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            before = None
        except BaseException:
            if parent_fd >= 0:
                os.close(parent_fd)
            raise
        try:
            if before is None:
                assert_path_identity(
                    absolute.parent,
                    parent_identity,
                    open_directory=lambda value: open_directory(value, error_type=error_type),
                    error_type=error_type,
                )
                _ensure_absent_at(parent_fd, absolute.name, error_type=error_type)
                os.mkdir(absolute.name, 0o700, dir_fd=parent_fd)
                os.fsync(parent_fd)
                created = True
            elif not stat.S_ISDIR(before.st_mode):
                raise error_type("pinned output root must be a real directory")
            root_fd = os.open(absolute.name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
            root_info = os.fstat(root_fd)
            entry = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
            if _identity(root_info) != _identity(entry):
                raise error_type("pinned output root identity changed during open")
            if (
                root_info.st_uid != os.geteuid()
                or stat.S_IMODE(root_info.st_mode) != 0o700
                or root_info.st_nlink < 2
            ):
                raise error_type("pinned output root must be owned, private, and linked")
            if os.listdir(root_fd):
                raise error_type("pinned output root must be absent or empty")
            root_identity = _identity(root_info)
            proc_root = _open_verified_proc_descriptor(
                root_fd,
                root_identity,
                error_type=error_type,
            )
            os.close(proc_root)
            current_parent = os.fstat(parent_fd)
            if _identity(current_parent) != parent_identity:
                raise error_type("pinned output parent identity changed")
            return cls(
                absolute,
                parent_fd,
                root_fd,
                parent_identity,
                root_identity,
                error_type=error_type,
            )
        except BaseException:
            if root_fd >= 0:
                os.close(root_fd)
            if created:
                with suppress(OSError):
                    os.rmdir(absolute.name, dir_fd=parent_fd)
                    os.fsync(parent_fd)
            os.close(parent_fd)
            raise

    def __enter__(self) -> PinnedOutputRoot:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        os.close(self.root_fd)
        os.close(self.parent_fd)

    def _ensure_open(self) -> None:
        if self._closed:
            raise self.error_type("pinned output root is closed")

    def _proc_base(self) -> Path:
        return _PROC_SELF_FD / str(self.root_fd)

    def proc_path(self, relative: str | Path = Path()) -> Path:
        self._ensure_open()
        parts = _relative_parts(relative, error_type=self.error_type)
        duplicate = _open_verified_proc_descriptor(
            self.root_fd,
            self.root_identity,
            error_type=self.error_type,
        )
        os.close(duplicate)
        return self._proc_base().joinpath(*parts)

    def attest(self) -> AttestedDirectory:
        """Mint the sole concrete capability for this retained output inode."""

        self.checkpoint()
        if self._attest_in_progress:
            raise self.error_type("recursive attestation is not allowed")
        self._attest_in_progress = True
        try:
            return _mint_attested_directory(
                owner=self,
                parent_fd=self.parent_fd,
                root_fd=self.root_fd,
                parent_identity=self.parent_identity,
                identity=self.root_identity,
                display_path=self.path,
                proc_root=_PROC_SELF_FD,
                error_type=self.error_type,
            )
        finally:
            self._attest_in_progress = False

    def _parts_from_callback_path(self, path: Path) -> tuple[str, ...]:
        absolute, _ = _absolute_parts(path, error_type=self.error_type)
        prefix = self._proc_base().parts
        if absolute.parts[: len(prefix)] != prefix:
            raise self.error_type("path is outside the pinned output capability")
        return _relative_parts(
            Path(*absolute.parts[len(prefix) :]),
            error_type=self.error_type,
        )

    def _open_relative_directory(self, parts: tuple[str, ...]) -> tuple[int, DirectoryIdentity]:
        self._ensure_open()
        descriptor = os.dup(self.root_fd)
        try:
            for part in parts:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode):
                raise self.error_type("pinned capability target is not a directory")
            return descriptor, _identity(info)
        except BaseException as exc:
            with suppress(OSError):
                os.close(descriptor)
            if isinstance(exc, self.error_type):
                raise
            raise self.error_type("unsafe pinned output directory") from exc

    def open_directory(self, path: Path) -> tuple[int, DirectoryIdentity]:
        return self._open_relative_directory(self._parts_from_callback_path(path))

    def assert_path_identity(self, path: Path, expected: DirectoryIdentity) -> None:
        descriptor, actual = self.open_directory(path)
        try:
            if actual != expected:
                raise self.error_type("pinned directory identity changed")
        finally:
            os.close(descriptor)

    def mkdir(self, relative: str | Path) -> DirectoryIdentity:
        parts = _relative_parts(relative, error_type=self.error_type)
        if not parts:
            raise self.error_type("pinned mkdir requires a non-root relative path")
        parent, identity = self._open_relative_directory(parts[:-1])
        del identity
        try:
            _ensure_absent_at(parent, parts[-1], error_type=self.error_type)
            os.mkdir(parts[-1], 0o700, dir_fd=parent)
            os.fsync(parent)
            child = os.open(parts[-1], _DIRECTORY_FLAGS, dir_fd=parent)
            try:
                info = os.fstat(child)
                return _identity(info)
            finally:
                os.close(child)
        finally:
            os.close(parent)

    def identity(self, relative: str | Path = Path()) -> DirectoryIdentity:
        parts = _relative_parts(relative, error_type=self.error_type)
        descriptor, identity = self._open_relative_directory(parts)
        os.close(descriptor)
        return identity

    def read_bytes(self, relative: str | Path, *, label: str) -> bytes:
        parts = _relative_parts(relative, error_type=self.error_type)
        if not parts:
            raise self.error_type("pinned read requires a file path")
        parent, _identity_value = self._open_relative_directory(parts[:-1])
        try:
            return read_file_at(
                parent,
                parts[-1],
                label,
                max_file_size=2 * 1024 * 1024,
                read_exact=read_fd_exact,
                error_type=self.error_type,
            )
        finally:
            os.close(parent)

    def checkpoint(self) -> None:
        self._ensure_open()
        lexical_parent, lexical_parent_identity = open_directory(
            self.path.parent,
            error_type=self.error_type,
        )
        os.close(lexical_parent)
        if lexical_parent_identity != self.parent_identity:
            raise self.error_type("pinned output parent identity changed")
        parent = os.fstat(self.parent_fd)
        root = os.fstat(self.root_fd)
        try:
            entry = os.stat(self.path.name, dir_fd=self.parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise self.error_type("pinned output root identity changed") from exc
        if (
            _identity(parent) != self.parent_identity
            or _identity(root) != self.root_identity
            or _identity(entry) != self.root_identity
            or not stat.S_ISDIR(entry.st_mode)
            or entry.st_uid != os.geteuid()
            or stat.S_IMODE(entry.st_mode) != 0o700
        ):
            raise self.error_type("pinned output root identity changed")
        duplicate = _open_verified_proc_descriptor(
            self.root_fd,
            self.root_identity,
            error_type=self.error_type,
        )
        os.close(duplicate)

    def _remove_tree_at(self, parent_fd: int, name: str) -> None:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode):
            os.unlink(name, dir_fd=parent_fd)
            return
        child = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        try:
            for entry in os.listdir(child):
                self._remove_tree_at(child, entry)
        finally:
            os.close(child)
        os.rmdir(name, dir_fd=parent_fd)

    def cleanup(self, relative: str | Path) -> None:
        parts = _relative_parts(relative, error_type=self.error_type)
        if not parts:
            raise self.error_type("pinned cleanup cannot remove the output root")
        parent, _identity_value = self._open_relative_directory(parts[:-1])
        try:
            self._remove_tree_at(parent, parts[-1])
            os.fsync(parent)
        finally:
            os.close(parent)


def _frozen_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("sealed pack metadata keys must be strings")
            frozen[key] = _frozen_json(item)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_frozen_json(item) for item in value)
    if value is None or type(value) in {str, int, bool, float}:
        return value
    raise TypeError("sealed pack metadata must contain only JSON values")


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain_json(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class SealedPackSchema:
    """Immutable fixed-membership schema for one family of sealed packs."""

    schema: str
    digest_domain: bytes
    media_types: Mapping[str, str]
    verification: Mapping[str, Any]
    manifest_name: str = "manifest.json"
    max_file_size: int = 2 * 1024 * 1024
    max_total_size: int = 8 * 1024 * 1024
    max_jsonl_records: int = 1000
    jsonl_identity_key: str = "event_id"
    error_type: ErrorType = SealedPackError
    payload_files: tuple[str, ...] = field(init=False)
    pack_files: frozenset[str] = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.error_type, type) or not issubclass(self.error_type, RuntimeError):
            raise TypeError("error_type must be a RuntimeError subclass")
        error_type = self.error_type
        if type(self.schema) is not str or not self.schema or self.schema != self.schema.strip():
            raise error_type("sealed pack schema must be canonical nonempty text")
        if type(self.digest_domain) is not bytes or not self.digest_domain:
            raise error_type("sealed pack digest domain must be nonempty bytes")
        if type(self.manifest_name) is not str or not _safe_basename(self.manifest_name):
            raise error_type("sealed pack manifest name must be a safe basename")
        if type(self.jsonl_identity_key) is not str or not _safe_field_name(
            self.jsonl_identity_key
        ):
            raise error_type("JSONL identity key must be a safe canonical field name")
        if any(
            type(limit) is not int or limit <= 0
            for limit in (self.max_file_size, self.max_total_size, self.max_jsonl_records)
        ):
            raise error_type("sealed pack limits must be positive integers")
        if not isinstance(self.media_types, Mapping):
            raise error_type("sealed pack media types must be a mapping")
        if not isinstance(self.verification, Mapping):
            raise error_type("sealed pack verification metadata must be a mapping")

        media_types: dict[str, str] = {}
        for name, media_type in self.media_types.items():
            if type(name) is not str or not _safe_basename(name):
                raise error_type("sealed pack payload members must be safe basenames")
            if name == self.manifest_name:
                raise error_type("sealed pack manifest cannot also be a payload member")
            if type(media_type) is not str or not media_type or media_type != media_type.strip():
                raise error_type("sealed pack media types must be canonical nonempty text")
            if media_type not in {"application/json", "application/x-ndjson"}:
                raise error_type("sealed pack media type has no canonical validator")
            media_types[name] = media_type
        if not media_types:
            raise error_type("sealed pack requires at least one payload member")

        payload_files = tuple(sorted(media_types))
        object.__setattr__(self, "media_types", MappingProxyType(dict(media_types)))
        try:
            frozen_verification = _frozen_json(self.verification)
            canonical_json(_plain_json(frozen_verification))
        except (TypeError, ValueError, UnicodeError) as exc:
            raise error_type(f"sealed pack verification metadata is invalid: {exc}") from exc
        object.__setattr__(self, "verification", frozen_verification)
        object.__setattr__(self, "payload_files", payload_files)
        object.__setattr__(
            self,
            "pack_files",
            frozenset((*payload_files, self.manifest_name)),
        )


@dataclass(frozen=True, slots=True)
class SealedPackCodec:
    """Generic canonical codec and descriptor-relative sealed-pack boundary."""

    schema: SealedPackSchema
    error_type: ErrorType = SealedPackError
    export_error_type: ErrorType = SealedPackExportError

    def __post_init__(self) -> None:
        if not isinstance(self.schema, SealedPackSchema):
            raise TypeError("schema must be SealedPackSchema")
        if not isinstance(self.error_type, type) or not issubclass(self.error_type, RuntimeError):
            raise TypeError("error_type must be a RuntimeError subclass")
        if (
            not isinstance(self.export_error_type, type)
            or not issubclass(self.export_error_type, RuntimeError)
            or not issubclass(self.export_error_type, SealedPackExportState)
        ):
            raise TypeError(
                "export_error_type must be a RuntimeError and SealedPackExportState subclass"
            )

    def json_bytes(self, value: Any) -> bytes:
        return json_bytes(value)

    def jsonl_bytes(self, values: list[dict[str, Any]]) -> bytes:
        return jsonl_bytes(values)

    def strict_json(self, data: bytes, name: str) -> Any:
        return strict_json(data, name, error_type=self.error_type)

    def strict_jsonl(self, data: bytes, name: str) -> list[dict[str, Any]]:
        return strict_jsonl(
            data,
            name,
            identity_key=self.schema.jsonl_identity_key,
            max_records=self.schema.max_jsonl_records,
            error_type=self.error_type,
        )

    def manifest_entries(self, payloads: Mapping[str, bytes]) -> list[dict[str, Any]]:
        if set(payloads) != set(self.schema.payload_files):
            raise self.error_type("proof payload file set is not the fixed allowlist")
        return [
            {
                "path": name,
                "sha256": hashlib.sha256(payloads[name]).hexdigest(),
                "size": len(payloads[name]),
                "media_type": self.schema.media_types[name],
            }
            for name in self.schema.payload_files
        ]

    def manifest_payload(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "schema": self.schema.schema,
            "files": entries,
            "verification": _plain_json(self.schema.verification),
        }

    def pack_digest(self, payload: Mapping[str, Any]) -> str:
        canonical = canonical_json(dict(payload)).encode("utf-8")
        return hashlib.sha256(self.schema.digest_domain + canonical).hexdigest()

    def require_sha256(self, value: object, name: str) -> str:
        return required_sha256(value, name, error_type=self.error_type)

    def read_external_bytes(self, path: str | Path, label: str, *, size: int) -> bytes:
        raw = self.secure_read_file(Path(path), label)
        if len(raw) != size:
            raise self.error_type(f"{label} must be a {size}-byte regular file")
        return raw

    def read_exact_pack(
        self,
        root: Path,
        *,
        open_directory: OpenDirectory | None = None,
        read_file_at: ReadFileAt | None = None,
        assert_membership: AssertMembership | None = None,
        assert_path_identity: AssertPathIdentity | None = None,
    ) -> dict[str, bytes]:
        open_directory = open_directory or self.open_directory
        read_file_at = read_file_at or self.read_file_at
        assert_membership = assert_membership or self.assert_exact_membership
        assert_path_identity = assert_path_identity or self.assert_path_identity
        directory_fd, identity = open_directory(root)
        try:
            result = self._read_exact_pack_fd(
                directory_fd,
                read_file_at=read_file_at,
                assert_membership=assert_membership,
                label="proof pack",
            )
            assert_path_identity(root, identity)
            return result
        finally:
            os.close(directory_fd)

    def read_exact_pack_attested(
        self, directory: AttestedDirectory | OwnedAttestedDirectory
    ) -> dict[str, bytes]:
        """Read an exact pack from one live retained directory inode."""

        if isinstance(directory, OwnedAttestedDirectory):
            descriptor, expected_identity = _duplicate_owned_attested_directory(
                directory, error_type=self.error_type
            )
        else:
            require_attested_directory(directory, error_type=self.error_type)
            try:
                descriptor = os.dup(directory.root_fd)
                os.set_inheritable(descriptor, False)
                expected_identity = directory.identity
            except OSError as exc:
                raise self.error_type("proof pack directory capability is unavailable") from exc
        info = os.fstat(descriptor)
        try:
            if (
                (info.st_dev, info.st_ino) != expected_identity
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_nlink < 2
            ):
                raise self.error_type("proof pack directory capability identity is invalid")
            return self._read_exact_pack_fd(
                descriptor,
                read_file_at=self.read_file_at,
                assert_membership=self.assert_exact_membership,
                label="proof pack",
            )
        finally:
            os.close(descriptor)

    def export_new_pack(
        self,
        output: Path,
        payloads: Mapping[str, bytes],
        *,
        open_directory: OpenDirectory | None = None,
        read_file_at: ReadFileAt | None = None,
        write_new_at: WriteNewAt | None = None,
        assert_membership: AssertMembership | None = None,
        assert_path_identity: AssertPathIdentity | None = None,
    ) -> tuple[dict[str, Any], str]:
        """Durably commit a complete pack at a previously absent final path."""

        # No filesystem path is opened or created until every byte, size, and
        # digest constraint has passed.  Rejected input therefore cannot leave
        # even a temporary directory behind.
        prepared, manifest, pack_digest = self._preflight(payloads)
        output = Path(output)
        if not _safe_basename(output.name):
            raise self.error_type("proof output path must end in a safe basename")

        open_directory = open_directory or self.open_directory
        read_file_at = read_file_at or self.read_file_at
        write_new_at = write_new_at or self.write_new_at
        assert_membership = assert_membership or self.assert_exact_membership
        assert_path_identity = assert_path_identity or self.assert_path_identity

        parent_fd = -1
        temp_fd = -1
        parent_identity: DirectoryIdentity | None = None
        temp_identity: DirectoryIdentity | None = None
        temp_name: str | None = None
        committed = False
        parent_commit_fsynced = False
        phase = "open_parent"
        try:
            parent_fd, parent_identity = open_directory(output.parent)
            phase = "initial_parent_identity"
            assert_path_identity(output.parent, parent_identity)
            phase = "initial_final_absence"
            _ensure_absent_at(parent_fd, output.name, error_type=self.error_type)
            phase = "create_private_temp"
            temp_name, temp_fd, temp_identity = _create_private_temp_directory(
                parent_fd,
                error_type=self.error_type,
            )
            phase = "initial_temp_identity"
            _assert_directory_entry_identity(
                parent_fd,
                temp_name,
                temp_identity,
                error_type=self.error_type,
            )

            for name in self.schema.payload_files:
                phase = f"write:{name}"
                write_new_at(temp_fd, name, prepared[name])
            phase = f"write:{self.schema.manifest_name}"
            write_new_at(temp_fd, self.schema.manifest_name, prepared[self.schema.manifest_name])
            phase = "temp_membership"
            assert_membership(temp_fd, self.schema.pack_files, "proof output")
            phase = "temp_directory_fsync"
            os.fsync(temp_fd)

            phase = "precommit_verify"
            reread = self._read_exact_pack_fd(
                temp_fd,
                read_file_at=read_file_at,
                assert_membership=assert_membership,
                label="proof output",
            )
            self._assert_prepared_bytes(reread, prepared, pack_digest)
            phase = "precommit_temp_identity"
            _assert_directory_entry_identity(
                parent_fd,
                temp_name,
                temp_identity,
                error_type=self.error_type,
            )
            phase = "precommit_parent_identity"
            assert_path_identity(output.parent, parent_identity)
            phase = "precommit_final_absence"
            _ensure_absent_at(parent_fd, output.name, error_type=self.error_type)

            phase = "commit_rename"
            _rename_noreplace(
                parent_fd,
                temp_name,
                parent_fd,
                output.name,
                error_type=self.error_type,
            )
            committed = True
            phase = "postcommit_final_identity"
            _assert_directory_entry_identity(
                parent_fd,
                output.name,
                temp_identity,
                error_type=self.error_type,
            )
            phase = "postcommit_verify"
            final_reread = self._read_exact_pack_fd(
                temp_fd,
                read_file_at=read_file_at,
                assert_membership=assert_membership,
                label="proof output",
            )
            self._assert_prepared_bytes(final_reread, prepared, pack_digest)
            phase = "parent_commit_fsync"
            os.fsync(parent_fd)
            parent_commit_fsynced = True
            phase = "postcommit_parent_identity"
            assert_path_identity(output.parent, parent_identity)
            phase = "postcommit_final_identity"
            _assert_directory_entry_identity(
                parent_fd,
                output.name,
                temp_identity,
                error_type=self.error_type,
            )
        except Exception as exc:
            if temp_fd >= 0:
                with suppress(OSError):
                    os.close(temp_fd)
                temp_fd = -1

            temp_path = output.parent / temp_name if temp_name is not None else None
            temp_path_exists = (
                _entry_exists_at(parent_fd, temp_name) if temp_name is not None else False
            )
            cleanup_attempted = False
            cleanup_succeeded: bool | None = None
            cleanup_error: Exception | None = None

            # Atomic rename is the irreversible commit point.  Once it returns,
            # the final directory is never deleted automatically: a caller must
            # see that a commit occurred and must not retry an uncertain effect.
            if not committed and parent_fd >= 0 and temp_name is not None and temp_identity:
                cleanup_attempted = True
                try:
                    _cleanup_owned_directory(
                        parent_fd,
                        temp_name,
                        temp_identity,
                        error_type=self.error_type,
                    )
                except Exception as cleanup_exc:  # pragma: no branch - evidence path
                    cleanup_error = cleanup_exc
                temp_path_exists = _entry_exists_at(parent_fd, temp_name)
                if cleanup_error is None and temp_path_exists is False:
                    cleanup_succeeded = True
                elif temp_path_exists is True:
                    cleanup_succeeded = False

            parent_identity_preserved = _path_identity_preserved(
                output.parent,
                parent_identity,
                open_directory=open_directory,
            )
            pinned_final_entry_exists = _entry_exists_at(parent_fd, output.name)
            lexical_final_path_exists = _lexical_path_exists(output)
            final_path_exists = _reconciled_final_path_exists(
                parent_identity_preserved=parent_identity_preserved,
                pinned_final_entry_exists=pinned_final_entry_exists,
                lexical_final_path_exists=lexical_final_path_exists,
            )

            if committed:
                durability_uncertain = not parent_commit_fsynced
                retry_safe = False
            elif cleanup_attempted:
                durability_uncertain = cleanup_succeeded is not True
                retry_safe = (
                    cleanup_succeeded is True
                    and temp_path_exists is False
                    and final_path_exists is False
                )
            else:
                durability_uncertain = False
                retry_safe = temp_path_exists is False and final_path_exists is False

            detail = str(exc) or type(exc).__name__
            if cleanup_error is not None:
                cleanup_detail = str(cleanup_error) or type(cleanup_error).__name__
                if cleanup_error.__cause__ is not None:
                    root_detail = (
                        str(cleanup_error.__cause__) or type(cleanup_error.__cause__).__name__
                    )
                    cleanup_detail = f"{cleanup_detail}: {root_detail}"
                detail = f"{detail}; cleanup failed: {cleanup_detail}"
            export_error = self._export_error(
                detail,
                committed=committed,
                parent_identity_preserved=parent_identity_preserved,
                pinned_final_entry_exists=pinned_final_entry_exists,
                lexical_final_path_exists=lexical_final_path_exists,
                final_path_exists=final_path_exists,
                cleanup_attempted=cleanup_attempted,
                cleanup_succeeded=cleanup_succeeded,
                durability_uncertain=durability_uncertain,
                retry_safe=retry_safe,
                phase=phase,
                final_path=output,
                temp_path=temp_path,
                temp_path_exists=temp_path_exists,
            )
            if getattr(export_error, "redact_export_cause", False):
                raise export_error from None
            raise export_error from exc
        finally:
            if temp_fd >= 0:
                os.close(temp_fd)
            if parent_fd >= 0:
                os.close(parent_fd)
        return manifest, pack_digest

    def _export_error(
        self,
        detail: str,
        *,
        committed: bool,
        parent_identity_preserved: bool | None,
        pinned_final_entry_exists: bool | None,
        lexical_final_path_exists: bool | None,
        final_path_exists: bool | None,
        cleanup_attempted: bool,
        cleanup_succeeded: bool | None,
        durability_uncertain: bool,
        retry_safe: bool,
        phase: str,
        final_path: Path,
        temp_path: Path | None,
        temp_path_exists: bool | None,
    ) -> RuntimeError:
        message = (
            f"sealed pack export failed during {phase}: {detail}; "
            f"committed={committed}; parent_identity_preserved={parent_identity_preserved}; "
            f"pinned_final_entry_exists={pinned_final_entry_exists}; "
            f"lexical_final_path_exists={lexical_final_path_exists}; "
            f"final_path_exists={final_path_exists}; "
            f"cleanup_attempted={cleanup_attempted}; cleanup_succeeded={cleanup_succeeded}; "
            f"durability_uncertain={durability_uncertain}; retry_safe={retry_safe}"
        )
        constructor = cast(Callable[..., RuntimeError], self.export_error_type)
        return constructor(
            message,
            committed=committed,
            parent_identity_preserved=parent_identity_preserved,
            pinned_final_entry_exists=pinned_final_entry_exists,
            lexical_final_path_exists=lexical_final_path_exists,
            final_path_exists=final_path_exists,
            cleanup_attempted=cleanup_attempted,
            cleanup_succeeded=cleanup_succeeded,
            durability_uncertain=durability_uncertain,
            retry_safe=retry_safe,
            phase=phase,
            final_path=final_path,
            temp_path=temp_path,
            temp_path_exists=temp_path_exists,
        )

    def _preflight(
        self,
        payloads: Mapping[str, bytes],
    ) -> tuple[dict[str, bytes], dict[str, Any], str]:
        if set(payloads) != set(self.schema.payload_files):
            raise self.error_type("proof payload file set is not the fixed allowlist")
        prepared: dict[str, bytes] = {}
        total = 0
        for name in self.schema.payload_files:
            data = payloads[name]
            if type(data) is not bytes or not data or len(data) > self.schema.max_file_size:
                raise self.error_type(f"{name} violates proof file size limits")
            self._validate_payload_bytes(name, data)
            total += len(data)
            if total > self.schema.max_total_size:
                raise self.error_type("proof pack exceeds total size limit")
            prepared[name] = data

        entries = self.manifest_entries(prepared)
        manifest_payload = self.manifest_payload(entries)
        pack_digest = self.pack_digest(manifest_payload)
        manifest = {**manifest_payload, "pack_digest": pack_digest}
        manifest_bytes = self.json_bytes(manifest)
        self.strict_json(manifest_bytes, self.schema.manifest_name)
        if not manifest_bytes or len(manifest_bytes) > self.schema.max_file_size:
            raise self.error_type(f"{self.schema.manifest_name} violates proof file size limits")
        total += len(manifest_bytes)
        if total > self.schema.max_total_size:
            raise self.error_type("proof pack exceeds total size limit")
        prepared[self.schema.manifest_name] = manifest_bytes
        self._verify_raw_pack(prepared, expected_digest=pack_digest)
        return prepared, manifest, pack_digest

    def _validate_payload_bytes(self, name: str, data: bytes) -> None:
        media_type = self.schema.media_types[name]
        if media_type == "application/json":
            self.strict_json(data, name)
            return
        if media_type == "application/x-ndjson":
            self.strict_jsonl(data, name)
            return
        raise self.error_type(f"{name} has no canonical payload validator")

    def _read_exact_pack_fd(
        self,
        directory_fd: int,
        *,
        read_file_at: ReadFileAt,
        assert_membership: AssertMembership,
        label: str,
    ) -> dict[str, bytes]:
        if set(os.listdir(directory_fd)) != self.schema.pack_files:
            raise self.error_type("proof pack file set is not exact")
        result: dict[str, bytes] = {}
        total = 0
        for name in sorted(self.schema.pack_files):
            data = read_file_at(directory_fd, name, name)
            total += len(data)
            if total > self.schema.max_total_size:
                raise self.error_type("proof pack exceeds total size limit")
            result[name] = data
        assert_membership(directory_fd, self.schema.pack_files, label)
        self._verify_raw_pack(result)
        return result

    def _verify_raw_pack(
        self,
        raw: Mapping[str, bytes],
        *,
        expected_digest: str | None = None,
    ) -> str:
        if set(raw) != self.schema.pack_files:
            raise self.error_type("proof pack file set is not exact")
        total = 0
        for name in self.schema.payload_files:
            data = raw[name]
            if type(data) is not bytes or not data or len(data) > self.schema.max_file_size:
                raise self.error_type(f"{name} violates proof file size limits")
            total += len(data)
            self._validate_payload_bytes(name, data)
        manifest_bytes = raw[self.schema.manifest_name]
        if (
            type(manifest_bytes) is not bytes
            or not manifest_bytes
            or len(manifest_bytes) > self.schema.max_file_size
        ):
            raise self.error_type(f"{self.schema.manifest_name} violates proof file size limits")
        total += len(manifest_bytes)
        if total > self.schema.max_total_size:
            raise self.error_type("proof pack exceeds total size limit")

        manifest = self.strict_json(manifest_bytes, self.schema.manifest_name)
        if type(manifest) is not dict or set(manifest) != {
            "schema",
            "pack_digest",
            "files",
            "verification",
        }:
            raise self.error_type("manifest has an incompatible shape")
        if manifest["schema"] != self.schema.schema:
            raise self.error_type("manifest schema mismatch")
        entries = self.manifest_entries({name: raw[name] for name in self.schema.payload_files})
        manifest_payload = self.manifest_payload(entries)
        digest = self.pack_digest(manifest_payload)
        if (
            manifest["files"] != entries
            or manifest["verification"] != manifest_payload["verification"]
            or type(manifest["pack_digest"]) is not str
            or not hmac.compare_digest(manifest["pack_digest"], digest)
            or (expected_digest is not None and not hmac.compare_digest(digest, expected_digest))
        ):
            raise self.error_type("manifest hashes, sizes, media types, or pack digest mismatch")
        return digest

    def _assert_prepared_bytes(
        self,
        actual: Mapping[str, bytes],
        expected: Mapping[str, bytes],
        expected_digest: str,
    ) -> None:
        digest = self._verify_raw_pack(actual, expected_digest=expected_digest)
        if not hmac.compare_digest(digest, expected_digest) or any(
            not hmac.compare_digest(actual[name], expected[name]) for name in self.schema.pack_files
        ):
            raise self.error_type("proof output bytes changed before atomic commit")

    def open_directory(self, path: Path, *, create: bool = False) -> tuple[int, DirectoryIdentity]:
        return open_directory(path, create=create, error_type=self.error_type)

    def assert_path_identity(self, path: Path, expected: DirectoryIdentity) -> None:
        assert_path_identity(
            path,
            expected,
            open_directory=self.open_directory,
            error_type=self.error_type,
        )

    def open_or_create_empty_directory(self, path: Path) -> tuple[int, DirectoryIdentity]:
        return open_or_create_empty_directory(
            path,
            open_directory=self.open_directory,
            error_type=self.error_type,
        )

    def assert_exact_membership(
        self,
        parent_fd: int,
        expected: frozenset[str],
        label: str,
    ) -> None:
        assert_exact_membership(parent_fd, expected, label, error_type=self.error_type)

    def read_fd_exact(self, descriptor: int, size: int, label: str) -> bytes:
        return read_fd_exact(descriptor, size, label, error_type=self.error_type)

    def read_file_at(self, parent_fd: int, name: str, label: str) -> bytes:
        return read_file_at(
            parent_fd,
            name,
            label,
            max_file_size=self.schema.max_file_size,
            read_exact=self.read_fd_exact,
            error_type=self.error_type,
        )

    def secure_read_file(self, path: Path, label: str) -> bytes:
        return secure_read_file(
            path,
            label,
            open_directory=self.open_directory,
            read_file_at=self.read_file_at,
            assert_path_identity=self.assert_path_identity,
        )

    def secure_sha256_file(self, path: Path, label: str, *, max_size: int) -> str:
        return secure_sha256_file(
            path,
            label,
            max_size=max_size,
            open_directory=self.open_directory,
            assert_path_identity=self.assert_path_identity,
            error_type=self.error_type,
        )

    def write_new_at(self, parent_fd: int, name: str, data: bytes) -> None:
        write_new_at(
            parent_fd,
            name,
            data,
            max_file_size=self.schema.max_file_size,
            read_exact=self.read_fd_exact,
            error_type=self.error_type,
        )

    def write_new(self, path: Path, data: bytes) -> None:
        write_new(
            path,
            data,
            open_directory=self.open_directory,
            write_new_at=self.write_new_at,
            assert_path_identity=self.assert_path_identity,
        )


def _ensure_absent_at(parent_fd: int, name: str, *, error_type: ErrorType) -> None:
    if not _safe_basename(name):
        raise error_type("proof output path must end in a safe basename")
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise error_type("proof output path availability could not be confirmed") from exc
    raise error_type("proof output path must not already exist")


def _entry_exists_at(parent_fd: int, name: str) -> bool | None:
    """Return descriptor-relative entry existence, or ``None`` when unknowable."""

    if parent_fd < 0 or not _safe_basename(name):
        return None
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError:
        return None
    return True


def _lexical_path_exists(path: Path) -> bool | None:
    """Inspect the requested lexical entry without following its final symlink."""

    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return None
    return True


def _path_identity_preserved(
    path: Path,
    expected: DirectoryIdentity | None,
    *,
    open_directory: OpenDirectory,
) -> bool | None:
    """Compare the current lexical directory with the pinned original identity."""

    if expected is None:
        return None
    try:
        descriptor, actual = open_directory(path)
    except Exception as exc:
        if _exception_proves_path_loss(exc):
            return False
        return None
    try:
        return actual == expected
    finally:
        with suppress(OSError):
            os.close(descriptor)


def _exception_proves_path_loss(exc: BaseException) -> bool:
    current: BaseException | None = exc
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if isinstance(current, OSError) and current.errno in {
            errno.ENOENT,
            errno.ENOTDIR,
            errno.ELOOP,
        }:
            return True
        current = current.__cause__ or current.__context__
    return False


def _reconciled_final_path_exists(
    *,
    parent_identity_preserved: bool | None,
    pinned_final_entry_exists: bool | None,
    lexical_final_path_exists: bool | None,
) -> bool | None:
    if (
        parent_identity_preserved is True
        and pinned_final_entry_exists is not None
        and pinned_final_entry_exists is lexical_final_path_exists
    ):
        return pinned_final_entry_exists
    return None


def _create_private_temp_directory(
    parent_fd: int,
    *,
    error_type: ErrorType,
) -> tuple[str, int, DirectoryIdentity]:
    for _ in range(32):
        name = f".sealed-pack-{os.getpid()}-{secrets.token_hex(12)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        except OSError as exc:
            raise error_type("private sibling proof directory could not be created") from exc
        try:
            descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_uid != os.geteuid()
            ):
                os.close(descriptor)
                raise error_type("private sibling proof directory has unsafe ownership or mode")
            return name, descriptor, _identity(info)
        except Exception:
            with suppress(OSError):
                os.rmdir(name, dir_fd=parent_fd)
            raise
    raise error_type("could not allocate a unique private sibling proof directory")


def _assert_directory_entry_identity(
    parent_fd: int,
    name: str,
    expected: DirectoryIdentity,
    *,
    error_type: ErrorType,
) -> None:
    if not _safe_basename(name):
        raise error_type("proof directory entry name is unsafe")
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise error_type("proof directory entry identity is unavailable") from exc
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or _identity(info) != expected:
        raise error_type("proof directory entry identity changed")


def _rename_noreplace(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
    *,
    error_type: ErrorType,
) -> None:
    """Linux atomic rename with an explicit no-replace contract."""

    if not sys.platform.startswith("linux"):
        raise error_type("atomic no-replace directory commit is unsupported on this platform")
    if not _safe_basename(source_name) or not _safe_basename(destination_name):
        raise error_type("atomic directory commit names must be safe basenames")
    try:
        source = source_name.encode("utf-8", errors="strict")
        destination = destination_name.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise error_type("atomic directory commit names must be strict UTF-8") from exc

    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise error_type("atomic no-replace directory commit is unsupported by libc")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        source_parent_fd,
        ctypes.c_char_p(source),
        destination_parent_fd,
        ctypes.c_char_p(destination),
        1,  # RENAME_NOREPLACE
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise error_type("proof output path was created concurrently and was not replaced")
    if error_number in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP}:
        raise error_type("atomic no-replace directory commit is unsupported")
    raise error_type("atomic no-replace directory commit failed") from OSError(
        error_number, os.strerror(error_number)
    )


def _cleanup_owned_directory(
    parent_fd: int,
    name: str,
    expected: DirectoryIdentity,
    *,
    error_type: ErrorType,
) -> None:
    """Remove only a same-identity private directory owned by this process."""

    _assert_directory_entry_identity(parent_fd, name, expected, error_type=error_type)
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise error_type("owned proof directory could not be opened for cleanup") from exc
    try:
        info = os.fstat(descriptor)
        if _identity(info) != expected or info.st_uid != os.geteuid():
            raise error_type("owned proof directory identity changed before cleanup")
        names = os.listdir(descriptor)
        for member in names:
            if not _safe_basename(member):
                raise error_type("owned proof directory contains an unsafe cleanup member")
            member_info = os.stat(member, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(member_info.st_mode):
                raise error_type("owned proof directory contains an unexpected child directory")
        for member in names:
            os.unlink(member, dir_fd=descriptor)
        if os.listdir(descriptor):
            raise error_type("owned proof directory changed during cleanup")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _assert_directory_entry_identity(parent_fd, name, expected, error_type=error_type)
    try:
        os.rmdir(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError as exc:
        raise error_type("owned proof directory cleanup was not durable") from exc


def _safe_basename(name: str) -> bool:
    return (
        _safe_field_name(name)
        and name not in {".", ".."}
        and name == Path(name).name
        and "/" not in name
        and "\\" not in name
    )


def _safe_field_name(name: str) -> bool:
    if (
        type(name) is not str
        or not name
        or name != name.strip()
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
    ):
        return False
    try:
        encoded = name.encode("utf-8", errors="strict")
        if encoded.decode("utf-8", errors="strict") != name:
            return False
    except UnicodeError:
        return False
    return not any(ord(character) < 0x20 or ord(character) == 0x7F for character in name)


def required_sha256(value: object, name: str, *, error_type: ErrorType = SealedPackError) -> str:
    if type(value) is not str or len(value) != 64 or not set(value) <= _SHA256:
        raise error_type(f"{name} must be a lowercase SHA-256 digest")
    return value


def strict_json(data: bytes, name: str, *, error_type: ErrorType = SealedPackError) -> Any:
    try:
        text = data.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=lambda constant: _raise_json_constant(constant),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise error_type(f"{name} is not strict JSON: {exc}") from exc
    if data != json_bytes(value):
        raise error_type(f"{name} is not canonical JSON")
    return value


def strict_jsonl(
    data: bytes,
    name: str,
    *,
    identity_key: str = "event_id",
    max_records: int = 1000,
    error_type: ErrorType = SealedPackError,
) -> list[dict[str, Any]]:
    if b"\r" in data or not data.endswith(b"\n"):
        raise error_type(f"{name} must end with one canonical newline")
    lines = data[:-1].split(b"\n")
    if not lines or len(lines) > max_records or any(not line for line in lines):
        raise error_type(f"{name} has blank, missing, or excessive records")
    records: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for line in lines:
        value = strict_json(line + b"\n", name, error_type=error_type)
        if type(value) is not dict:
            raise error_type(f"{name} records must be objects")
        raw_identifier = value.get(identity_key)
        if (
            type(raw_identifier) is not str
            or not raw_identifier
            or raw_identifier != raw_identifier.strip()
        ):
            raise error_type(f"{name}.{identity_key} must be canonical nonempty text")
        if raw_identifier in identifiers:
            raise error_type(f"{name} contains duplicate event identifiers")
        identifiers.add(raw_identifier)
        records.append(value)
    return records


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _raise_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number: {value}")


def json_bytes(value: Any) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def jsonl_bytes(values: list[dict[str, Any]]) -> bytes:
    return b"".join(json_bytes(value) for value in values)


def _absolute_parts(path: Path, *, error_type: ErrorType) -> tuple[Path, tuple[str, ...]]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    parts = absolute.parts[1:]
    if not absolute.is_absolute() or any(part in {"", ".", ".."} for part in parts):
        raise error_type("path must be an absolute canonical filesystem path")
    return absolute, parts


def _identity(info: os.stat_result) -> DirectoryIdentity:
    return info.st_dev, info.st_ino


def open_directory(
    path: Path,
    *,
    create: bool = False,
    error_type: ErrorType = SealedPackError,
) -> tuple[int, DirectoryIdentity]:
    absolute, parts = _absolute_parts(path, error_type=error_type)
    if is_descriptor_alias_path(absolute):
        raise error_type("direct descriptor alias paths are not accepted")
    descriptor = os.open(absolute.anchor, _DIRECTORY_FLAGS)
    try:
        for part in parts:
            try:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=descriptor)
                os.fsync(descriptor)
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise error_type("path is not a directory")
        return descriptor, _identity(info)
    except BaseException as exc:
        with suppress(OSError):
            os.close(descriptor)
        if isinstance(exc, error_type):
            raise
        if isinstance(exc, OSError) and exc.errno in {errno.ELOOP, errno.ENOTDIR, errno.ENOENT}:
            raise error_type(f"unsafe or unavailable directory path: {path}") from exc
        raise


def assert_path_identity(
    path: Path,
    expected: DirectoryIdentity,
    *,
    open_directory: OpenDirectory,
    error_type: ErrorType = SealedPackError,
) -> None:
    descriptor, actual = open_directory(path)
    try:
        if actual != expected:
            raise error_type("directory path identity changed during proof operation")
    finally:
        os.close(descriptor)


def open_or_create_empty_directory(
    path: Path,
    *,
    open_directory: Callable[..., tuple[int, DirectoryIdentity]],
    error_type: ErrorType = SealedPackError,
) -> tuple[int, DirectoryIdentity]:
    descriptor, identity = open_directory(path, create=True)
    try:
        if os.listdir(descriptor):
            raise error_type("proof output directory must be absent or empty")
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _stable_stat(info: os.stat_result) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def assert_exact_membership(
    parent_fd: int,
    expected: frozenset[str],
    label: str,
    *,
    error_type: ErrorType = SealedPackError,
) -> None:
    if set(os.listdir(parent_fd)) != expected:
        raise error_type(f"{label} file set changed during proof operation")


def read_fd_exact(
    descriptor: int,
    size: int,
    label: str,
    *,
    error_type: ErrorType = SealedPackError,
) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(descriptor, min(remaining, 65536))
        if not chunk:
            raise error_type(f"{label} changed while it was read")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise error_type(f"{label} grew while it was read")
    return b"".join(chunks)


def read_file_at(
    parent_fd: int,
    name: str,
    label: str,
    *,
    max_file_size: int,
    read_exact: ReadExact,
    error_type: ErrorType = SealedPackError,
) -> bytes:
    if not _safe_basename(name):
        raise error_type("proof member path is not a basename")
    try:
        descriptor = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise error_type(f"{label} could not be securely opened") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise error_type(f"{label} must be a regular non-hardlinked file")
        if before.st_size <= 0 or before.st_size > max_file_size:
            raise error_type(f"{label} violates proof file size limits")
        data = read_exact(descriptor, before.st_size, label)
        after = os.fstat(descriptor)
        if _stable_stat(before) != _stable_stat(after):
            raise error_type(f"{label} changed while it was read")
    finally:
        os.close(descriptor)
    try:
        current = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise error_type(f"{label} path changed while it was read") from exc
    try:
        current_before = os.fstat(current)
        if not stat.S_ISREG(current_before.st_mode) or current_before.st_nlink != 1:
            raise error_type(f"{label} final path is not a private regular file")
        if _identity(current_before) != _identity(after):
            raise error_type(f"{label} path identity changed while it was read")
        if _stable_stat(current_before) != _stable_stat(after):
            raise error_type(f"{label} content or metadata changed before final read")
        reread = read_exact(current, current_before.st_size, label)
        current_after = os.fstat(current)
        if _stable_stat(current_before) != _stable_stat(current_after) or not hmac.compare_digest(
            reread, data
        ):
            raise error_type(f"{label} changed during final read verification")
    finally:
        os.close(current)
    return data


def secure_read_file(
    path: Path,
    label: str,
    *,
    open_directory: OpenDirectory,
    read_file_at: ReadFileAt,
    assert_path_identity: AssertPathIdentity,
) -> bytes:
    parent_fd, identity = open_directory(path.parent)
    try:
        data = read_file_at(parent_fd, path.name, label)
        assert_path_identity(path.parent, identity)
        return data
    finally:
        os.close(parent_fd)


def secure_sha256_file(
    path: Path,
    label: str,
    *,
    max_size: int,
    open_directory: OpenDirectory,
    assert_path_identity: AssertPathIdentity,
    error_type: ErrorType = SealedPackError,
) -> str:
    """Hash stable regular-file bytes twice through a pinned directory fd."""

    def digest_descriptor(descriptor: int, size: int) -> str:
        digest = hashlib.sha256()
        remaining = size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise error_type(f"{label} changed while it was hashed")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise error_type(f"{label} grew while it was hashed")
        return digest.hexdigest()

    parent_fd, parent_identity = open_directory(path.parent)
    try:
        try:
            descriptor = os.open(path.name, _READ_FLAGS, dir_fd=parent_fd)
        except OSError as exc:
            raise error_type(f"{label} could not be securely opened") from exc
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise error_type(f"{label} must be a regular non-hardlinked file")
            if before.st_size <= 0 or before.st_size > max_size:
                raise error_type(f"{label} violates artifact size limits")
            first_digest = digest_descriptor(descriptor, before.st_size)
            after = os.fstat(descriptor)
            if _stable_stat(before) != _stable_stat(after):
                raise error_type(f"{label} changed while it was hashed")
        finally:
            os.close(descriptor)

        try:
            current = os.open(path.name, _READ_FLAGS, dir_fd=parent_fd)
        except OSError as exc:
            raise error_type(f"{label} path changed while it was hashed") from exc
        try:
            current_before = os.fstat(current)
            if (
                not stat.S_ISREG(current_before.st_mode)
                or current_before.st_nlink != 1
                or _identity(current_before) != _identity(after)
                or _stable_stat(current_before) != _stable_stat(after)
            ):
                raise error_type(f"{label} identity changed before final hash")
            second_digest = digest_descriptor(current, current_before.st_size)
            current_after = os.fstat(current)
            if _stable_stat(current_before) != _stable_stat(current_after):
                raise error_type(f"{label} changed during final hash")
            if not hmac.compare_digest(first_digest, second_digest):
                raise error_type(f"{label} digest changed during final hash")
        finally:
            os.close(current)
        assert_path_identity(path.parent, parent_identity)
        return first_digest
    finally:
        os.close(parent_fd)


def write_new_at(
    parent_fd: int,
    name: str,
    data: bytes,
    *,
    max_file_size: int,
    read_exact: ReadExact,
    error_type: ErrorType = SealedPackError,
) -> None:
    if not _safe_basename(name):
        raise error_type("proof output member path is not a basename")
    if not data or len(data) > max_file_size:
        raise error_type(f"{name} violates proof file size limits")
    descriptor = os.open(name, _WRITE_FLAGS, 0o600, dir_fd=parent_fd)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise error_type(f"{name} output is not a private regular file")
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise error_type(f"{name} could not be durably written")
            view = view[written:]
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or after.st_size != len(data)
            or _identity(after) != _identity(before)
        ):
            raise error_type(f"{name} output identity changed while writing")
    finally:
        os.close(descriptor)
    current = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
    try:
        current_before = os.fstat(current)
        if not stat.S_ISREG(current_before.st_mode) or current_before.st_nlink != 1:
            raise error_type(f"{name} output final path is not a private regular file")
        if _identity(current_before) != _identity(after):
            raise error_type(f"{name} output path identity changed after writing")
        if _stable_stat(current_before) != _stable_stat(after):
            raise error_type(f"{name} output content or metadata changed after writing")
        reread = read_exact(current, current_before.st_size, name)
        current_after = os.fstat(current)
        if _stable_stat(current_before) != _stable_stat(current_after) or not hmac.compare_digest(
            reread, data
        ):
            raise error_type(f"{name} output changed during final verification")
    finally:
        os.close(current)


def write_new(
    path: Path,
    data: bytes,
    *,
    open_directory: OpenDirectory,
    write_new_at: WriteNewAt,
    assert_path_identity: AssertPathIdentity,
) -> None:
    parent_fd, identity = open_directory(path.parent)
    try:
        write_new_at(parent_fd, path.name, data)
        os.fsync(parent_fd)
        assert_path_identity(path.parent, identity)
    finally:
        os.close(parent_fd)


def read_exact_pack_by_schema(
    root: Path,
    codecs: Mapping[str, SealedPackCodec],
    *,
    open_directory: OpenDirectory | None = None,
    read_file_at: ReadFileAt | None = None,
    assert_membership: AssertMembership | None = None,
    assert_path_identity: AssertPathIdentity | None = None,
) -> tuple[SealedPackCodec, dict[str, bytes]]:
    """Select one allowlisted codec without reopening the proof directory.

    The manifest is read through the same pinned directory descriptor later
    used for exact membership and payload reads.  A caller therefore cannot
    use a schema probe to bypass the codec's no-symlink or path-identity
    protections.
    """

    if not isinstance(codecs, Mapping) or not codecs:
        raise TypeError("codecs must be a nonempty schema mapping")
    normalized: dict[str, SealedPackCodec] = {}
    for schema, codec in codecs.items():
        if type(schema) is not str or not isinstance(codec, SealedPackCodec):
            raise TypeError("codec mapping entries must be schema strings and codecs")
        if schema != codec.schema.schema or schema in normalized:
            raise ValueError("codec mapping must exactly match unique codec schemas")
        normalized[schema] = codec
    first = next(iter(normalized.values()))
    manifest_names = {codec.schema.manifest_name for codec in normalized.values()}
    if len(manifest_names) != 1:
        raise ValueError("dispatched codecs must share one manifest basename")
    manifest_name = next(iter(manifest_names))
    root = Path(root)
    open_directory = open_directory or first.open_directory
    read_file_at = read_file_at or first.read_file_at
    assert_membership = assert_membership or first.assert_exact_membership
    assert_path_identity = assert_path_identity or first.assert_path_identity
    directory_fd, identity = open_directory(root)
    try:
        manifest_raw = read_file_at(directory_fd, manifest_name, "proof pack manifest")
        manifest = strict_json(manifest_raw, manifest_name, error_type=first.error_type)
        if type(manifest) is not dict or type(manifest.get("schema")) is not str:
            raise first.error_type("proof pack manifest schema is missing or incompatible")
        selected = normalized.get(cast(str, manifest["schema"]))
        if selected is None:
            raise first.error_type("proof pack manifest schema is not allowlisted")
        result = selected._read_exact_pack_fd(
            directory_fd,
            read_file_at=read_file_at,
            assert_membership=assert_membership,
            label="proof pack",
        )
        assert_path_identity(root, identity)
        return selected, result
    finally:
        os.close(directory_fd)
