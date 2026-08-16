"""Private local-only payment fixture with a durable idempotent journal.

The journal hash chain is unkeyed and is not independently tamper-resistant against a
malicious same-UID process that can truncate, rewrite, and rechain the file.  In the
supported adapter, the anchored :class:`SQLiteSpendStore` is the authoritative durable
state.  This fixture provider must not be used standalone as an authorization or
idempotency boundary.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import time
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, cast

from gove_zone.authorization import strict_json_hash, validate_strict_json_budget
from gove_zone.path_capability import AttestedDirectory, require_attested_directory

_ZERO_HASH = "0" * 64
_SCHEMA = "acgs.spend-fixture-journal/v1"


class FixtureProviderStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class FixtureProviderResult:
    status: FixtureProviderStatus
    provider_reference: str | None
    result_digest: str | None
    uncertainty_digest: str | None
    replayed: bool


class FixtureProviderError(RuntimeError):
    """The local fixture journal cannot prove a safe provider outcome."""


class _FileLocking(Protocol):
    LOCK_EX: int
    LOCK_SH: int

    def flock(self, fd: int, operation: int, /) -> None: ...


def _load_file_locking() -> _FileLocking | None:
    try:
        import fcntl as _fcntl
    except ModuleNotFoundError:
        return None
    return cast(_FileLocking, _fcntl)


_fcntl = _load_file_locking()


def _require_fixture_locking() -> _FileLocking:
    locking = _fcntl
    if locking is None:
        raise FixtureProviderError("fixture journal locking is unavailable")
    return locking


def _lock_shared(fd: int) -> None:
    locking = _require_fixture_locking()
    locking.flock(fd, locking.LOCK_SH)


def _lock_exclusive(fd: int) -> None:
    locking = _require_fixture_locking()
    locking.flock(fd, locking.LOCK_EX)


class LocalJournalFixtureProvider:
    """A deterministic local provider that never performs an external payment.

    Its unkeyed journal only detects accidental or unprivileged corruption.  A malicious
    same-UID process can truncate and rechain it, so the provider is not a standalone
    authorization or idempotency boundary.  ``SpendGuardAdapter`` relies on the anchored
    ``SQLiteSpendStore`` as the authoritative state before this fixture is invoked.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        unknown: bool = False,
        delay_seconds: float = 0.0,
    ) -> None:
        _require_fixture_locking()
        candidate = Path(path)
        if not candidate.is_absolute() or candidate != candidate.resolve(strict=False):
            raise FixtureProviderError("fixture journal path must be absolute and normalized")
        parent = candidate.parent
        parent_stat = parent.stat(follow_symlinks=False)
        if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_IMODE(parent_stat.st_mode) != 0o700:
            raise FixtureProviderError("fixture journal directory must be private mode 0700")
        if parent_stat.st_uid != os.getuid():
            raise FixtureProviderError("fixture journal directory owner is not trusted")
        if type(unknown) is not bool:
            raise FixtureProviderError("unknown must be a bool")
        if type(delay_seconds) not in (int, float):
            raise FixtureProviderError("delay_seconds must be a nonnegative number")
        if type(delay_seconds) is float and not math.isfinite(delay_seconds):
            raise FixtureProviderError("delay_seconds must be finite")
        if delay_seconds < 0 or delay_seconds > 5:
            raise FixtureProviderError("delay_seconds is outside the local fixture bound")
        self._path = candidate
        self._unknown = unknown
        self._delay_seconds = float(delay_seconds)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(candidate, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            self._validate_fd(fd)
            os.fsync(fd)
            parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        finally:
            os.close(fd)

        self._attested_directory: AttestedDirectory | None = None
        self._attested_relative: str | None = None

    @classmethod
    def from_attested(
        cls,
        directory: AttestedDirectory,
        relative: str,
        *,
        unknown: bool = False,
        delay_seconds: float = 0.0,
    ) -> LocalJournalFixtureProvider:
        """Borrow an exact registered capability and use descriptor-relative journal I/O."""
        _require_fixture_locking()
        capability = require_attested_directory(directory, error_type=FixtureProviderError)
        capability.checkpoint()
        if type(relative) is not str or not relative or "\0" in relative:
            raise FixtureProviderError("attested fixture journal basename is invalid")
        relative_path = Path(relative)
        if (
            relative_path.is_absolute()
            or len(relative_path.parts) != 1
            or relative_path.parts[0] in {".", ".."}
        ):
            raise FixtureProviderError("attested fixture journal must be one normalized basename")
        if type(unknown) is not bool:
            raise FixtureProviderError("unknown must be a bool")
        if type(delay_seconds) not in (int, float):
            raise FixtureProviderError("delay_seconds must be a nonnegative number")
        if type(delay_seconds) is float and not math.isfinite(delay_seconds):
            raise FixtureProviderError("delay_seconds must be finite")
        if delay_seconds < 0 or delay_seconds > 5:
            raise FixtureProviderError("delay_seconds is outside the local fixture bound")
        descriptor = capability.open_file(relative, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            instance = cls.__new__(cls)
            instance._path = capability.display_path / relative
            instance._unknown = unknown
            instance._delay_seconds = float(delay_seconds)
            instance._attested_directory = capability
            instance._attested_relative = relative
            instance._validate_fd(descriptor)
            os.fsync(descriptor)
            parent, _identity = capability.open_directory(".")
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
            return instance
        finally:
            os.close(descriptor)

    @property
    def path(self) -> Path:
        return self._path

    @property
    def effect_count(self) -> int:
        _require_fixture_locking()
        fd = self._open()
        try:
            _lock_shared(fd)
            return len(self._read_verified(fd))
        finally:
            os.close(fd)

    def read_records(self) -> list[dict[str, Any]]:
        """Return a verified snapshot without reopening the display pathname."""
        _require_fixture_locking()
        fd = self._open()
        try:
            _lock_shared(fd)
            return self._read_verified(fd)
        finally:
            os.close(fd)

    def create_payment(
        self,
        envelope: Mapping[str, Any],
        *,
        idempotency_digest: str,
    ) -> FixtureProviderResult:
        _require_fixture_locking()
        validate_strict_json_budget(envelope)
        if not _is_digest(idempotency_digest):
            raise FixtureProviderError("idempotency_digest must be lowercase SHA-256")
        envelope_digest = strict_json_hash(envelope)
        if self._delay_seconds:
            time.sleep(self._delay_seconds)
        fd = self._open()
        try:
            _lock_exclusive(fd)
            records = self._read_verified(fd)
            for record in records:
                if record["idempotency_digest"] != idempotency_digest:
                    continue
                if record["envelope_digest"] != envelope_digest:
                    raise FixtureProviderError("fixture idempotency journal conflict")
                return _result_from_record(record, replayed=True)

            status = (
                FixtureProviderStatus.UNKNOWN if self._unknown else FixtureProviderStatus.SUCCEEDED
            )
            sequence = len(records) + 1
            provider_reference = (
                None if status is FixtureProviderStatus.UNKNOWN else f"fixture-{sequence:08d}"
            )
            result_digest = (
                None
                if status is FixtureProviderStatus.UNKNOWN
                else strict_json_hash(
                    {
                        "provider_reference": provider_reference,
                        "envelope_digest": envelope_digest,
                    }
                )
            )
            uncertainty_digest = (
                strict_json_hash(
                    {
                        "reason": "fixture-provider-uncertain",
                        "envelope_digest": envelope_digest,
                    }
                )
                if status is FixtureProviderStatus.UNKNOWN
                else None
            )
            body: dict[str, Any] = {
                "schema": _SCHEMA,
                "sequence": sequence,
                "idempotency_digest": idempotency_digest,
                "envelope_digest": envelope_digest,
                "status": status.value,
                "provider_reference": provider_reference,
                "result_digest": result_digest,
                "uncertainty_digest": uncertainty_digest,
                "previous_hash": records[-1]["event_hash"] if records else _ZERO_HASH,
            }
            body["event_hash"] = _event_hash(body)
            encoded = _canonical(body) + b"\n"
            os.lseek(fd, 0, os.SEEK_END)
            if os.write(fd, encoded) != len(encoded):
                raise FixtureProviderError("fixture journal write was incomplete")
            os.fsync(fd)
            return _result_from_record(body, replayed=False)
        except FixtureProviderError:
            raise
        except OSError as exc:
            raise FixtureProviderError("fixture journal operation failed") from exc
        finally:
            os.close(fd)

    def _open(self) -> int:
        try:
            if self._attested_directory is None:
                fd = os.open(self._path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
            else:
                directory = require_attested_directory(
                    self._attested_directory,
                    error_type=FixtureProviderError,
                )
                if self._attested_relative is None:
                    raise FixtureProviderError("attested fixture journal path is missing")
                directory.checkpoint()
                fd = directory.open_file(self._attested_relative, os.O_RDWR)
            self._validate_fd(fd)
            return fd
        except OSError as exc:
            raise FixtureProviderError("fixture journal is unavailable") from exc

    def _validate_fd(self, fd: int) -> None:
        value = os.fstat(fd)
        if (
            not stat.S_ISREG(value.st_mode)
            or stat.S_IMODE(value.st_mode) != 0o600
            or value.st_uid != os.getuid()
            or value.st_nlink != 1
        ):
            raise FixtureProviderError("fixture journal file is not private mode 0600")

    def _read_verified(self, fd: int) -> list[dict[str, Any]]:
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65_536)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
        if raw and not raw.endswith(b"\n"):
            raise FixtureProviderError("fixture journal has a partial record")
        records: list[dict[str, Any]] = []
        previous = _ZERO_HASH
        for sequence, line in enumerate(raw.splitlines(), start=1):
            try:
                value = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise FixtureProviderError("fixture journal JSON is invalid") from None
            if type(value) is not dict:
                raise FixtureProviderError("fixture journal record must be an object")
            record = cast(dict[str, Any], value)
            expected_keys = {
                "schema",
                "sequence",
                "idempotency_digest",
                "envelope_digest",
                "status",
                "provider_reference",
                "result_digest",
                "uncertainty_digest",
                "previous_hash",
                "event_hash",
            }
            if set(record) != expected_keys or record.get("schema") != _SCHEMA:
                raise FixtureProviderError("fixture journal record shape is invalid")
            if record.get("sequence") != sequence or record.get("previous_hash") != previous:
                raise FixtureProviderError("fixture journal order is invalid")
            if not _is_digest(record.get("idempotency_digest")) or not _is_digest(
                record.get("envelope_digest")
            ):
                raise FixtureProviderError("fixture journal digest is invalid")
            event_hash = record.get("event_hash")
            if not _is_digest(event_hash) or event_hash != _event_hash(record):
                raise FixtureProviderError("fixture journal hash chain is invalid")
            _result_from_record(record, replayed=False)
            previous = cast(str, event_hash)
            records.append(record)
        return records


def _result_from_record(record: Mapping[str, Any], *, replayed: bool) -> FixtureProviderResult:
    try:
        status = FixtureProviderStatus(record["status"])
    except (KeyError, ValueError):
        raise FixtureProviderError("fixture journal status is invalid") from None
    provider_reference = record.get("provider_reference")
    result_digest = record.get("result_digest")
    uncertainty_digest = record.get("uncertainty_digest")
    if status is FixtureProviderStatus.SUCCEEDED:
        if type(provider_reference) is not str or not _is_digest(result_digest):
            raise FixtureProviderError("fixture success record is invalid")
        if uncertainty_digest is not None:
            raise FixtureProviderError("fixture success record has uncertainty")
    else:
        if provider_reference is not None or result_digest is not None:
            raise FixtureProviderError("fixture unknown record has a success value")
        if not _is_digest(uncertainty_digest):
            raise FixtureProviderError("fixture unknown record is invalid")
    return FixtureProviderResult(
        status=status,
        provider_reference=provider_reference,
        result_digest=cast(str | None, result_digest),
        uncertainty_digest=cast(str | None, uncertainty_digest),
        replayed=replayed,
    )


def _event_hash(record: Mapping[str, Any]) -> str:
    body = {key: value for key, value in record.items() if key != "event_hash"}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _is_digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )
