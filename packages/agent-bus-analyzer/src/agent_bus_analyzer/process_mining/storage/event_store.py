"""Tenant-isolated append-only storage for normalized ProcessEvent records."""

from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from enum import StrEnum
from pathlib import Path
from typing import IO, Literal, Self

from pydantic import Field, TypeAdapter, ValidationError, model_validator

from agent_bus_analyzer.process_mining._canonical import canonical_json, sha256_canonical
from agent_bus_analyzer.process_mining.errors import (
    ConflictingDuplicateError,
    EventStoreIntegrityError,
)
from agent_bus_analyzer.process_mining.schemas.process_event import (
    ProcessEvent,
    Sha256Hex,
    TenantId,
    _StrictModel,
    validated_event_snapshot,
)

GENESIS_RECORD_HASH = "0" * 64
_TENANT_ADAPTER = TypeAdapter(TenantId)


class AppendStatus(StrEnum):
    APPENDED = "appended"
    DUPLICATE = "duplicate"


class StoredEventRecord(_StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    storage_sequence: int = Field(ge=0)
    previous_record_hash: Sha256Hex
    event: ProcessEvent
    record_hash: Sha256Hex

    @model_validator(mode="after")
    def verify_record_hash(self) -> Self:
        payload = self.model_dump(mode="python", exclude={"record_hash"})
        if self.record_hash != sha256_canonical(payload):
            raise ValueError("record_hash does not match canonical stored event envelope")
        return self

    @classmethod
    def create(
        cls,
        *,
        storage_sequence: int,
        previous_record_hash: str,
        event: ProcessEvent,
    ) -> StoredEventRecord:
        event_snapshot = validated_event_snapshot(event)
        payload: dict[str, object] = {
            "schema_version": "1.0",
            "storage_sequence": storage_sequence,
            "previous_record_hash": previous_record_hash,
            "event": event_snapshot,
        }
        return cls(
            schema_version="1.0",
            storage_sequence=storage_sequence,
            previous_record_hash=previous_record_hash,
            event=event_snapshot,
            record_hash=sha256_canonical(payload),
        )


class AppendResult(_StrictModel):
    status: AppendStatus
    record: StoredEventRecord


class ChainVerificationResult(_StrictModel):
    valid: bool
    checked: int = Field(ge=0)
    last_hash: Sha256Hex
    failure_index: int | None = Field(default=None, ge=0)
    failure: str | None = None


def _tenant_path(root: Path, tenant_id: str) -> Path:
    safe_tenant = _TENANT_ADAPTER.validate_python(tenant_id, strict=True)
    tenants_root = Path(os.path.abspath(root / "tenants"))
    path = tenants_root / safe_tenant / "events.jsonl"
    if not path.is_relative_to(tenants_root):
        raise ValueError("tenant path escapes event-store root")
    return path


def _ensure_private_directory(path: Path) -> None:
    """Create/validate one owned directory without accepting a symlink."""
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except FileNotFoundError:
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        path.mkdir(mode=0o700, exist_ok=True)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise EventStoreIntegrityError("event-store directory is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise EventStoreIntegrityError("event-store directory must be a real directory")
    try:
        os.chmod(path, 0o700, follow_symlinks=False)
    except OSError as exc:
        raise EventStoreIntegrityError("event-store directory permissions are invalid") from exc


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EventStoreIntegrityError("event-store directory cannot be synchronized") from exc
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _open_private_file(path: Path, flags: int, *, mode: int = 0o600) -> int:
    """Open a regular file relative to a no-follow directory descriptor."""
    _ensure_private_directory(path.parent)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(path.parent, directory_flags)
    try:
        descriptor = os.open(
            path.name,
            flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            mode,
            dir_fd=directory_fd,
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(descriptor)
            raise EventStoreIntegrityError("event-store path must be a regular file")
        writable = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT))
        if writable:
            os.fchmod(descriptor, 0o600)
        elif stat.S_IMODE(metadata.st_mode) != 0o600:
            os.close(descriptor)
            raise EventStoreIntegrityError("event-store file permissions must be 0600")
        if flags & os.O_CREAT:
            os.fsync(directory_fd)
        return descriptor
    except FileNotFoundError:
        raise
    except EventStoreIntegrityError:
        raise
    except OSError as exc:
        raise EventStoreIntegrityError("event-store file failed secure open") from exc
    finally:
        os.close(directory_fd)


@contextmanager
def _locked_tenant_file(path: Path, *, exclusive: bool) -> Iterator[IO[str]]:
    lock_path = path.with_suffix(".lock")
    descriptor = _open_private_file(
        lock_path,
        os.O_RDWR | os.O_APPEND | os.O_CREAT,
    )
    lock_handle = os.fdopen(descriptor, "a+", encoding="utf-8")
    try:
        fcntl.flock(
            lock_handle.fileno(),
            fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH,
        )
        yield lock_handle
    finally:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        lock_handle.close()


class EventStore:
    """One independently chained append log per tenant.

    Tenant id is always explicit.  There is intentionally no cross-tenant
    query method and no silent default tenant.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(os.path.abspath(root))
        self.root.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        _ensure_private_directory(self.root)
        _ensure_private_directory(self.root / "tenants")
        _fsync_directory(self.root)

    def _read_records_unlocked(
        self,
        tenant_id: str,
    ) -> tuple[list[StoredEventRecord], ChainVerificationResult]:
        path = _tenant_path(self.root, tenant_id)
        try:
            descriptor = _open_private_file(path, os.O_RDONLY)
        except FileNotFoundError:
            return [], ChainVerificationResult(
                valid=True,
                checked=0,
                last_hash=GENESIS_RECORD_HASH,
            )
        records: list[StoredEventRecord] = []
        previous = GENESIS_RECORD_HASH
        try:
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                for line_index, line in enumerate(handle):
                    clean = line.strip()
                    if not clean:
                        continue
                    try:
                        record = StoredEventRecord.model_validate_json(clean)
                    except (ValidationError, ValueError) as exc:
                        return records, ChainVerificationResult(
                            valid=False,
                            checked=len(records),
                            last_hash=previous,
                            failure_index=line_index,
                            failure=f"invalid stored record: {exc}",
                        )
                    if record.storage_sequence != len(records):
                        return records, ChainVerificationResult(
                            valid=False,
                            checked=len(records),
                            last_hash=previous,
                            failure_index=line_index,
                            failure="non-contiguous storage_sequence",
                        )
                    if record.previous_record_hash != previous:
                        return records, ChainVerificationResult(
                            valid=False,
                            checked=len(records),
                            last_hash=previous,
                            failure_index=line_index,
                            failure="previous_record_hash mismatch",
                        )
                    if record.event.tenant_id != tenant_id:
                        return records, ChainVerificationResult(
                            valid=False,
                            checked=len(records),
                            last_hash=previous,
                            failure_index=line_index,
                            failure="stored event crosses tenant boundary",
                        )
                    records.append(record)
                    previous = record.record_hash
        except (OSError, UnicodeError) as exc:
            return records, ChainVerificationResult(
                valid=False,
                checked=len(records),
                last_hash=previous,
                failure_index=len(records),
                failure=f"event store unreadable: {exc}",
            )
        return records, ChainVerificationResult(
            valid=True,
            checked=len(records),
            last_hash=previous,
        )

    def _read_records(
        self,
        tenant_id: str,
    ) -> tuple[list[StoredEventRecord], ChainVerificationResult]:
        path = _tenant_path(self.root, tenant_id)
        with _locked_tenant_file(path, exclusive=False):
            return self._read_records_unlocked(tenant_id)

    def _verified_records_unlocked(self, tenant_id: str) -> list[StoredEventRecord]:
        records, verification = self._read_records_unlocked(tenant_id)
        if not verification.valid:
            raise EventStoreIntegrityError(
                f"tenant event chain failed at {verification.failure_index}: {verification.failure}"
            )
        return records

    def _verified_records(self, tenant_id: str) -> list[StoredEventRecord]:
        records, verification = self._read_records(tenant_id)
        if not verification.valid:
            raise EventStoreIntegrityError(
                f"tenant event chain failed at {verification.failure_index}: {verification.failure}"
            )
        return records

    def append(self, event: ProcessEvent) -> AppendResult:
        event = validated_event_snapshot(event)
        path = _tenant_path(self.root, event.tenant_id)
        with _locked_tenant_file(path, exclusive=True):
            records = self._verified_records_unlocked(event.tenant_id)
            for existing in records:
                if existing.event.event_id != event.event_id:
                    continue
                if existing.event.normalization_hash == event.normalization_hash:
                    return AppendResult(status=AppendStatus.DUPLICATE, record=existing)
                raise ConflictingDuplicateError(
                    f"event_id {event.event_id!r} already exists with different content"
                )
            previous = records[-1].record_hash if records else GENESIS_RECORD_HASH
            record = StoredEventRecord.create(
                storage_sequence=len(records),
                previous_record_hash=previous,
                event=event,
            )
            encoded = (canonical_json(record) + "\n").encode("utf-8")
            descriptor = _open_private_file(
                path,
                os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            )
            try:
                original_size = os.lseek(descriptor, 0, os.SEEK_END)
                written = os.write(descriptor, encoded)
                if written != len(encoded):
                    os.ftruncate(descriptor, original_size)
                    os.fsync(descriptor)
                    raise EventStoreIntegrityError("event-store append was incomplete")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            _fsync_directory(path.parent)
            return AppendResult(status=AppendStatus.APPENDED, record=record)

    def verify_chain(self, tenant_id: str) -> ChainVerificationResult:
        """Re-walk one tenant chain without exposing another tenant's data."""
        _records, verification = self._read_records(tenant_id)
        return verification

    def query_by_case(self, *, tenant_id: str, case_id: str) -> tuple[ProcessEvent, ...]:
        if not case_id.strip():
            raise ValueError("case_id cannot be blank")
        return tuple(
            validated_event_snapshot(record.event)
            for record in self._verified_records(tenant_id)
            if record.event.case_id == case_id
        )

    def list_events(self, *, tenant_id: str) -> tuple[ProcessEvent, ...]:
        """Return one tenant's verified events in append order."""
        return tuple(
            validated_event_snapshot(record.event) for record in self._verified_records(tenant_id)
        )

    def query_by_process(
        self,
        *,
        tenant_id: str,
        process_id: str,
    ) -> tuple[ProcessEvent, ...]:
        if not process_id.strip():
            raise ValueError("process_id cannot be blank")
        return tuple(
            validated_event_snapshot(record.event)
            for record in self._verified_records(tenant_id)
            if record.event.process_id == process_id
        )

    def get_event(self, *, tenant_id: str, event_id: str) -> ProcessEvent | None:
        if not event_id.strip():
            raise ValueError("event_id cannot be blank")
        for record in self._verified_records(tenant_id):
            if record.event.event_id == event_id:
                return validated_event_snapshot(record.event)
        return None
