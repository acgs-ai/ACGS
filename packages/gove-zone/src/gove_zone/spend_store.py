"""Fail-closed durable local-fixture state for Spend Guard B1 and B2.

This module owns the schema-v1 integrity foundation and local reservation,
outcome, budget, and emergency-stop mutations. It deliberately has no payment
provider call, payment execution adapter, or production deployment claim.

Capability boundary: CPython's sqlite3 API opens a pathname rather than an
already validated file descriptor. Holding and revalidating directory/file FDs
closes ordinary rename and symlink races, but cannot fully exclude a malicious
same-UID process that swaps and restores the same pathname entirely inside the
sqlite3 pathname-open call. Deployments requiring that stronger property need
OS isolation from untrusted same-UID processes.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
import sys
import uuid
from _thread import RLock
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from functools import partial
from pathlib import Path
from typing import Any, Protocol, TypeVar, cast, runtime_checkable

from gove_zone.path_capability import AttestedDirectory, require_attested_directory

SPEND_APPLICATION_ID = 1_094_928_211
SPEND_SCHEMA_VERSION = 1
ZERO_HASH = "0" * 64

_ANCHOR_ENVELOPE_SCHEMA = "gove-zone.spend-state-anchor-envelope/v1"
_ANCHOR_RECORD_SCHEMA = "gove-zone.spend-state-anchor-record/v1"
_ANCHOR_MAC_SCHEMA = "gove-zone.spend-state-anchor-mac-payload/v1"
_ANCHOR_MAC_DOMAIN = b"gove-zone:spend-state-anchor:v1\x00"
_KEY_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")
_MAX_ANCHOR_BYTES = 16 * 1024
_ENVELOPE_KEYS = frozenset({"schema", "key_id", "record", "mac"})
_RECORD_KEYS = frozenset(
    {"schema", "key_id", "namespace", "store_id", "generation", "event_count", "head_hash"}
)
_MAC_KEYS = frozenset({"schema", "key_id", "record"})
_OPEN_BASE = os.O_NOFOLLOW | os.O_CLOEXEC
_SecurityHook = Callable[[str], None]
_T = TypeVar("_T")
_OPERATION_LOCKS: dict[object, RLock] = {}
_OPERATION_LOCKS_GUARD = RLock()


def _operation_lock_for(key: object) -> RLock:
    with _OPERATION_LOCKS_GUARD:
        return _OPERATION_LOCKS.setdefault(key, RLock())


def _attested_basename(value: object, label: str) -> str:
    if type(value) is not str or not value or "\0" in value:
        raise SpendPathSecurityError(f"attested {label} basename is invalid")
    path = Path(value)
    if path.is_absolute() or len(path.parts) != 1 or path.parts[0] in {".", ".."}:
        raise SpendPathSecurityError(f"attested {label} must be one normalized basename")
    return value


_RULES_SCHEMA = "gove-zone.spend-budget-rules/v1"
_SNAPSHOT_SCHEMA = "gove-zone.spend-budget-snapshot/v1"
_EVENT_PAYLOAD_SCHEMA = "gove-zone.spend-integrity-event-payload/v1"
_EVENT_HASH_DOMAIN = b"gove-zone:spend-integrity-event:v1\x00"
_MAX_TEXT_BYTES = 512
_MAX_RULE_VENDORS = 256
_MAX_WINDOW_SECONDS = 31_536_000
_MAX_SNAPSHOT_BYTES = 32 * 1024
_MAX_EVENT_PAYLOAD_BYTES = 64 * 1024
_MAX_SQLITE_INTEGER = 9_223_372_036_854_775_807

SPEND_IDEMPOTENCY_CONFLICT = "SPEND_IDEMPOTENCY_CONFLICT"
SPEND_EMERGENCY_STOP_ACTIVE = "SPEND_EMERGENCY_STOP_ACTIVE"
SPEND_STOP_GENERATION_MISMATCH = "SPEND_STOP_GENERATION_MISMATCH"
SPEND_CLOCK_ROLLBACK = "SPEND_CLOCK_ROLLBACK"
SPEND_SINGLE_LIMIT_EXCEEDED = "SPEND_SINGLE_LIMIT_EXCEEDED"
SPEND_HOURLY_LIMIT_EXCEEDED = "SPEND_HOURLY_LIMIT_EXCEEDED"
SPEND_DAILY_LIMIT_EXCEEDED = "SPEND_DAILY_LIMIT_EXCEEDED"
SPEND_MONTHLY_LIMIT_EXCEEDED = "SPEND_MONTHLY_LIMIT_EXCEEDED"
SPEND_VENDOR_BUDGET_UNCONFIGURED = "SPEND_VENDOR_BUDGET_UNCONFIGURED"
SPEND_VENDOR_MONTHLY_LIMIT_EXCEEDED = "SPEND_VENDOR_MONTHLY_LIMIT_EXCEEDED"
SPEND_RATE_LIMIT_EXCEEDED = "SPEND_RATE_LIMIT_EXCEEDED"
SPEND_LOOP_LIMIT_EXCEEDED = "SPEND_LOOP_LIMIT_EXCEEDED"
SPEND_ANOMALOUS_GROWTH = "SPEND_ANOMALOUS_GROWTH"
SPEND_OUTCOME_CONFLICT = "SPEND_OUTCOME_CONFLICT"
SPEND_CONTROL_GENERATION_CONFLICT = "SPEND_CONTROL_GENERATION_CONFLICT"


class SpendStoreError(RuntimeError):
    """Spend persistence could not be safely accessed."""


class SpendStoreUnavailable(SpendStoreError):
    """A required owned resource could not be cleanly released."""


class _FileLocking(Protocol):
    LOCK_EX: int
    LOCK_UN: int

    def flock(self, fd: int, operation: int, /) -> None: ...


def _load_file_locking() -> _FileLocking | None:
    try:
        import fcntl as _fcntl
    except ModuleNotFoundError:
        return None
    return cast(_FileLocking, _fcntl)


_fcntl = _load_file_locking()


def _require_spend_locking() -> _FileLocking:
    locking = _fcntl
    if locking is None:
        raise SpendStoreUnavailable("spend state locking is unavailable")
    return locking


def _lock_exclusive(fd: int) -> None:
    locking = _require_spend_locking()
    locking.flock(fd, locking.LOCK_EX)


def _unlock(fd: int) -> None:
    locking = _require_spend_locking()
    locking.flock(fd, locking.LOCK_UN)


class SpendSecurityError(SpendStoreError):
    """A filesystem or identity security invariant failed."""


class SpendPathSecurityError(SpendSecurityError):
    """A path, directory, or file capability was unsafe."""


class SpendIntegrityError(SpendStoreError):
    """Durable Spend state is inconsistent or tampered."""


class SpendRepairRequired(SpendIntegrityError):
    """The database is durably ahead of its trusted anchor."""


class SpendAnchorKeyMismatch(SpendIntegrityError):
    """Anchor key identity differs from the configured key identity."""


class SpendAnchorAuthenticationError(SpendIntegrityError):
    """Anchor HMAC authentication failed after key identity matched."""


class SpendOutcomeState(StrEnum):
    RESERVED = "RESERVED"
    SUCCEEDED = "SUCCEEDED"
    UNKNOWN = "UNKNOWN"


SPEND_BUDGET_SNAPSHOT_MISMATCH = "SPEND_BUDGET_SNAPSHOT_MISMATCH"


@dataclass(frozen=True, slots=True)
class SpendBudgetRules:
    currency: str
    single_limit_minor: int
    hourly_limit_minor: int
    daily_limit_minor: int
    monthly_limit_minor: int
    vendor_monthly_limits: tuple[tuple[str, int], ...]
    rate_window_seconds: int
    rate_limit_count: int
    loop_window_seconds: int
    loop_limit_count: int
    anomaly_window_seconds: int
    anomaly_growth_basis_points: int
    anomaly_floor_minor: int
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        _validate_currency(self.currency)
        for name, value in (
            ("single_limit_minor", self.single_limit_minor),
            ("hourly_limit_minor", self.hourly_limit_minor),
            ("daily_limit_minor", self.daily_limit_minor),
            ("monthly_limit_minor", self.monthly_limit_minor),
            ("anomaly_floor_minor", self.anomaly_floor_minor),
        ):
            _validate_positive_integer(value, name)
        for name, value in (
            ("rate_window_seconds", self.rate_window_seconds),
            ("loop_window_seconds", self.loop_window_seconds),
            ("anomaly_window_seconds", self.anomaly_window_seconds),
        ):
            _validate_window_seconds(value, name)
        _validate_positive_integer(self.rate_limit_count, "rate_limit_count")
        _validate_positive_integer(self.loop_limit_count, "loop_limit_count")
        _validate_positive_integer(
            self.anomaly_growth_basis_points,
            "anomaly_growth_basis_points",
        )
        if self.anomaly_growth_basis_points > 1_000_000:
            raise SpendIntegrityError("anomaly_growth_basis_points exceeds its bound")
        if type(self.vendor_monthly_limits) is not tuple:
            raise SpendIntegrityError("vendor_monthly_limits must be a canonical tuple")
        if not self.vendor_monthly_limits or len(self.vendor_monthly_limits) > _MAX_RULE_VENDORS:
            raise SpendIntegrityError("vendor_monthly_limits has an invalid size")
        prior: str | None = None
        vendor_rows: list[list[object]] = []
        for item in self.vendor_monthly_limits:
            if type(item) is not tuple or len(item) != 2:
                raise SpendIntegrityError("vendor_monthly_limits entries must be pairs")
            recipient, limit = item
            _validate_spend_text(recipient, "vendor recipient")
            _validate_positive_integer(limit, "vendor monthly limit")
            if prior is not None and recipient <= prior:
                raise SpendIntegrityError(
                    "vendor_monthly_limits must be unique and sorted by recipient"
                )
            prior = recipient
            vendor_rows.append([recipient, limit])
        document = {
            "schema": _RULES_SCHEMA,
            "currency": self.currency,
            "single_limit_minor": self.single_limit_minor,
            "hourly_limit_minor": self.hourly_limit_minor,
            "daily_limit_minor": self.daily_limit_minor,
            "monthly_limit_minor": self.monthly_limit_minor,
            "vendor_monthly_limits": vendor_rows,
            "rate_window_seconds": self.rate_window_seconds,
            "rate_limit_count": self.rate_limit_count,
            "loop_window_seconds": self.loop_window_seconds,
            "loop_limit_count": self.loop_limit_count,
            "anomaly_window_seconds": self.anomaly_window_seconds,
            "anomaly_growth_basis_points": self.anomaly_growth_basis_points,
            "anomaly_floor_minor": self.anomaly_floor_minor,
        }
        object.__setattr__(self, "digest", hashlib.sha256(_canonical_json(document)).hexdigest())


@dataclass(frozen=True, slots=True)
class SpendReservationRequest:
    tenant_id: str
    provider: str
    recipient: str
    currency: str
    amount_minor: int
    attempt_digest: str
    reference_digest: str
    argument_digest: str
    semantic_digest: str
    loop_fingerprint_digest: str
    receipt_digest: str
    policy_digest: str
    approval_digest: str | None
    idempotency_digest: str
    expected_stop_generation: int

    def __post_init__(self) -> None:
        for name, value in (
            ("tenant_id", self.tenant_id),
            ("provider", self.provider),
            ("recipient", self.recipient),
        ):
            _validate_spend_text(value, name)
        _validate_currency(self.currency)
        _validate_positive_integer(self.amount_minor, "amount_minor")
        for name, value in (
            ("attempt_digest", self.attempt_digest),
            ("reference_digest", self.reference_digest),
            ("argument_digest", self.argument_digest),
            ("semantic_digest", self.semantic_digest),
            ("loop_fingerprint_digest", self.loop_fingerprint_digest),
            ("receipt_digest", self.receipt_digest),
            ("policy_digest", self.policy_digest),
            ("idempotency_digest", self.idempotency_digest),
        ):
            _validate_digest(value, name)
        if self.approval_digest is not None:
            _validate_digest(self.approval_digest, "approval_digest")
        _validate_nonnegative_integer(self.expected_stop_generation, "expected_stop_generation")


@dataclass(frozen=True, slots=True)
class SpendBudgetSnapshot:
    observed_at_us: int
    base_generation: int
    reservation_generation: int
    stop_generation: int
    rules_digest: str
    snapshot_json: str
    snapshot_digest: str

    def __post_init__(self) -> None:
        _validate_nonnegative_integer(self.observed_at_us, "observed_at_us")
        _validate_nonnegative_integer(self.base_generation, "base_generation")
        _validate_positive_integer(self.reservation_generation, "reservation_generation")
        _validate_nonnegative_integer(self.stop_generation, "stop_generation")
        _validate_digest(self.rules_digest, "rules_digest")
        _validate_digest(self.snapshot_digest, "snapshot_digest")
        document = _decode_canonical_document(
            self.snapshot_json,
            "budget snapshot",
            _MAX_SNAPSHOT_BYTES,
        )
        expected = {
            "schema",
            "observed_at_us",
            "base_generation",
            "reservation_generation",
            "stop_generation",
            "rules_digest",
            "metrics",
        }
        if set(document) != expected or document.get("schema") != _SNAPSHOT_SCHEMA:
            raise SpendIntegrityError("budget snapshot fields are incompatible")
        if (
            document.get("observed_at_us") != self.observed_at_us
            or document.get("base_generation") != self.base_generation
            or document.get("reservation_generation") != self.reservation_generation
            or document.get("stop_generation") != self.stop_generation
            or document.get("rules_digest") != self.rules_digest
            or not isinstance(document.get("metrics"), dict)
        ):
            raise SpendIntegrityError("budget snapshot binding mismatch")
        if hashlib.sha256(self.snapshot_json.encode()).hexdigest() != self.snapshot_digest:
            raise SpendIntegrityError("budget snapshot digest mismatch")


@dataclass(frozen=True, slots=True)
class SpendBudgetProbe:
    """Read-only budget decision bound to the exact mutable store head."""

    request_digest: str
    base_generation: int
    stop_generation: int
    rules_digest: str
    budget_snapshot: SpendBudgetSnapshot
    reason_code: str | None
    snapshot_digest: str

    def __post_init__(self) -> None:
        _validate_digest(self.request_digest, "request_digest")
        _validate_nonnegative_integer(self.base_generation, "base_generation")
        _validate_nonnegative_integer(self.stop_generation, "stop_generation")
        _validate_digest(self.rules_digest, "rules_digest")
        if type(self.budget_snapshot) is not SpendBudgetSnapshot:
            raise SpendIntegrityError("budget_snapshot must be SpendBudgetSnapshot")
        if self.budget_snapshot.base_generation != self.base_generation:
            raise SpendIntegrityError("budget probe generation binding mismatch")
        if self.budget_snapshot.stop_generation != self.stop_generation:
            raise SpendIntegrityError("budget probe stop binding mismatch")
        if self.budget_snapshot.rules_digest != self.rules_digest:
            raise SpendIntegrityError("budget probe rules binding mismatch")
        if self.reason_code is not None:
            _validate_spend_text(self.reason_code, "reason_code")
        _validate_digest(self.snapshot_digest, "snapshot_digest")

    @property
    def allowed(self) -> bool:
        return self.reason_code is None


@dataclass(frozen=True, slots=True)
class SpendOutcome:
    spend_id: str
    state: SpendOutcomeState
    state_generation: int
    transitioned_at_us: int
    result_digest: str | None
    provider_reference_digest: str | None
    uncertainty_digest: str | None

    def __post_init__(self) -> None:
        _validate_uuid(self.spend_id, "spend_id")
        if type(self.state) is not SpendOutcomeState or self.state is SpendOutcomeState.RESERVED:
            raise SpendIntegrityError("outcome state must be SUCCEEDED or UNKNOWN")
        _validate_positive_integer(self.state_generation, "state_generation")
        _validate_nonnegative_integer(self.transitioned_at_us, "transitioned_at_us")
        if self.state is SpendOutcomeState.SUCCEEDED:
            if self.result_digest is None or self.provider_reference_digest is None:
                raise SpendIntegrityError("SUCCEEDED outcome requires result digests")
            _validate_digest(self.result_digest, "result_digest")
            _validate_digest(self.provider_reference_digest, "provider_reference_digest")
            if self.uncertainty_digest is not None:
                raise SpendIntegrityError("SUCCEEDED outcome cannot carry uncertainty")
        else:
            if self.uncertainty_digest is None:
                raise SpendIntegrityError("UNKNOWN outcome requires uncertainty_digest")
            _validate_digest(self.uncertainty_digest, "uncertainty_digest")
            if self.result_digest is not None or self.provider_reference_digest is not None:
                raise SpendIntegrityError("UNKNOWN outcome cannot carry success digests")


@dataclass(frozen=True, slots=True)
class SpendReservation:
    spend_id: str
    state: SpendOutcomeState
    replayed: bool
    state_generation: int
    stop_generation: int
    budget_snapshot: SpendBudgetSnapshot
    outcome: SpendOutcome | None

    def __post_init__(self) -> None:
        _validate_uuid(self.spend_id, "spend_id")
        if type(self.state) is not SpendOutcomeState or type(self.replayed) is not bool:
            raise SpendIntegrityError("reservation state is invalid")
        _validate_positive_integer(self.state_generation, "state_generation")
        _validate_nonnegative_integer(self.stop_generation, "stop_generation")
        if not isinstance(self.budget_snapshot, SpendBudgetSnapshot):
            raise SpendIntegrityError("reservation budget_snapshot is invalid")
        if (self.state is SpendOutcomeState.RESERVED) != (self.outcome is None):
            raise SpendIntegrityError("reservation outcome projection is inconsistent")
        if self.outcome is not None and (
            self.outcome.spend_id != self.spend_id or self.outcome.state is not self.state
        ):
            raise SpendIntegrityError("reservation outcome binding mismatch")


@dataclass(frozen=True, slots=True)
class SpendControlState:
    tenant_id: str
    enabled: bool
    stop_generation: int
    state_generation: int
    changed_at_us: int
    authority_digest: str | None
    reason_digest: str | None

    def __post_init__(self) -> None:
        _validate_spend_text(self.tenant_id, "tenant_id")
        if type(self.enabled) is not bool:
            raise SpendIntegrityError("enabled must be a boolean")
        _validate_nonnegative_integer(self.stop_generation, "stop_generation")
        _validate_nonnegative_integer(self.state_generation, "state_generation")
        _validate_nonnegative_integer(self.changed_at_us, "changed_at_us")
        if self.stop_generation == 0:
            if (
                self.enabled
                or self.state_generation != 0
                or self.changed_at_us != 0
                or self.authority_digest is not None
                or self.reason_digest is not None
            ):
                raise SpendIntegrityError("initial control state is invalid")
        else:
            if self.authority_digest is None or self.reason_digest is None:
                raise SpendIntegrityError("control state requires authority and reason digests")
            _validate_digest(self.authority_digest, "authority_digest")
            _validate_digest(self.reason_digest, "reason_digest")


class SpendReservationRejected(SpendStoreError):
    def __init__(
        self,
        reason_code: str,
        snapshot: SpendBudgetSnapshot | None = None,
    ) -> None:
        if type(reason_code) is not str or reason_code not in _SPEND_REJECTION_CODES:
            raise SpendIntegrityError("reservation rejection code is invalid")
        if snapshot is not None and not isinstance(snapshot, SpendBudgetSnapshot):
            raise SpendIntegrityError("reservation rejection snapshot is invalid")
        self.reason_code = reason_code
        self.snapshot = snapshot
        super().__init__(reason_code)


_SPEND_REJECTION_CODES = frozenset(
    {
        SPEND_IDEMPOTENCY_CONFLICT,
        SPEND_BUDGET_SNAPSHOT_MISMATCH,
        SPEND_EMERGENCY_STOP_ACTIVE,
        SPEND_STOP_GENERATION_MISMATCH,
        SPEND_CLOCK_ROLLBACK,
        SPEND_SINGLE_LIMIT_EXCEEDED,
        SPEND_HOURLY_LIMIT_EXCEEDED,
        SPEND_DAILY_LIMIT_EXCEEDED,
        SPEND_MONTHLY_LIMIT_EXCEEDED,
        SPEND_VENDOR_BUDGET_UNCONFIGURED,
        SPEND_VENDOR_MONTHLY_LIMIT_EXCEEDED,
        SPEND_RATE_LIMIT_EXCEEDED,
        SPEND_LOOP_LIMIT_EXCEEDED,
        SPEND_ANOMALOUS_GROWTH,
        SPEND_OUTCOME_CONFLICT,
        SPEND_CONTROL_GENERATION_CONFLICT,
    }
)


@runtime_checkable
class SpendClock(Protocol):
    def now(self) -> datetime: ...


class SystemSpendClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class SpendAnchorRecord:
    key_id: str
    namespace: str
    store_id: str
    generation: int
    event_count: int
    head_hash: str

    def __post_init__(self) -> None:
        _validate_key_id(self.key_id)
        _validate_namespace(self.namespace)
        _validate_store_id(self.store_id)
        _validate_count(self.generation, "generation")
        _validate_count(self.event_count, "event_count")
        _validate_digest(self.head_hash, "head_hash")
        if self.generation != self.event_count:
            raise SpendIntegrityError("anchor generation and event_count must match")


@runtime_checkable
class SpendStateAnchor(Protocol):
    @property
    def key_id(self) -> str: ...

    def read(self, namespace: str) -> SpendAnchorRecord | None: ...

    def compare_and_swap(
        self,
        namespace: str,
        expected: SpendAnchorRecord | None,
        replacement: SpendAnchorRecord,
    ) -> None: ...


@dataclass(slots=True)
class _SecureDirectory:
    path: Path
    fd: int
    identity: tuple[int, int]
    owner_uid: int
    capability: AttestedDirectory | None = None

    @classmethod
    def open(cls, value: str | Path) -> _SecureDirectory:
        path = _validated_absolute_path(value, "directory")
        owner_uid = os.geteuid()
        fd = _open_directory_components(path, owner_uid)
        try:
            file_stat = os.fstat(fd)
            return cls(path, fd, _identity(file_stat), owner_uid)
        except BaseException as exc:
            _cleanup_owned(
                (("directory open fd", lambda: os.close(fd)),),
                primary=exc,
                error_type=SpendPathSecurityError,
            )
            raise

    @classmethod
    def from_attested(cls, value: AttestedDirectory) -> _SecureDirectory:
        directory = require_attested_directory(value, error_type=SpendPathSecurityError)
        directory.checkpoint()
        fd = os.dup(directory.root_fd)
        try:
            info = os.fstat(fd)
            return cls(directory.display_path, fd, _identity(info), os.geteuid(), directory)
        except BaseException as exc:
            _cleanup_owned(
                (("attested directory fd", lambda: os.close(fd)),),
                primary=exc,
                error_type=SpendPathSecurityError,
            )
            raise

    def revalidate(self) -> None:
        _require_secure_directory_stat(os.fstat(self.fd), self.owner_uid)
        if self.capability is not None:
            directory = require_attested_directory(
                self.capability,
                error_type=SpendPathSecurityError,
            )
            directory.checkpoint()
            if _identity(os.fstat(directory.root_fd)) != self.identity:
                raise SpendPathSecurityError("secure directory capability identity changed")
            return
        fresh = _open_directory_components(self.path, self.owner_uid)
        try:
            if _identity(os.fstat(fresh)) != self.identity:
                raise SpendPathSecurityError("secure directory pathname was replaced")
        finally:
            _cleanup_owned(
                (("directory validation fd", lambda: os.close(fresh)),),
                primary=sys.exception(),
                error_type=SpendPathSecurityError,
            )

    def close(self) -> None:
        if self.fd >= 0:
            fd = self.fd
            self.fd = -1
            _cleanup_owned(
                (("directory fd", lambda: os.close(fd)),),
                primary=sys.exception(),
                error_type=SpendPathSecurityError,
            )


class FileSpendStateAnchor:
    """Canonical HMAC anchor serialized under a held secure directory FD."""

    def __init__(
        self,
        directory: str | Path,
        *,
        hmac_key: bytes,
        key_id: str,
        security_hook: _SecurityHook | None = None,
    ) -> None:
        _require_spend_locking()
        self._key = _validate_hmac_key(hmac_key)
        self._key_id = _validate_key_id(key_id)
        self._directory = _SecureDirectory.open(directory)
        self._hook = security_hook

    @classmethod
    def from_attested(
        cls,
        directory: AttestedDirectory,
        *,
        hmac_key: bytes,
        key_id: str,
        security_hook: _SecurityHook | None = None,
    ) -> FileSpendStateAnchor:
        """Borrow an exact registered directory capability for anchor files."""
        _require_spend_locking()
        instance = cls.__new__(cls)
        instance._key = _validate_hmac_key(hmac_key)
        instance._key_id = _validate_key_id(key_id)
        instance._directory = _SecureDirectory.from_attested(directory)
        instance._hook = security_hook
        return instance

    @property
    def key_id(self) -> str:
        return self._key_id

    def close(self) -> None:
        self._directory.close()

    def read(self, namespace: str) -> SpendAnchorRecord | None:
        namespace = _validate_namespace(namespace)
        with self._namespace_lock(namespace):
            return self._read_unlocked(namespace)

    def compare_and_swap(
        self,
        namespace: str,
        expected: SpendAnchorRecord | None,
        replacement: SpendAnchorRecord,
    ) -> None:
        namespace = _validate_namespace(namespace)
        if replacement.namespace != namespace:
            raise SpendIntegrityError("replacement anchor namespace mismatch")
        if replacement.key_id != self._key_id:
            raise SpendAnchorKeyMismatch("replacement anchor key_id mismatch")
        with self._namespace_lock(namespace):
            current = self._read_unlocked(namespace)
            if current != expected:
                raise SpendIntegrityError("anchor compare-and-swap conflict")
            if current is not None:
                if replacement.store_id != current.store_id:
                    raise SpendIntegrityError("anchor store identity cannot change")
                if replacement.generation < current.generation:
                    raise SpendIntegrityError("anchor rollback is forbidden")
                if replacement.generation == current.generation:
                    if replacement != current:
                        raise SpendIntegrityError("anchor head cannot change at one generation")
                    return
            self._write_unlocked(namespace, replacement)

    def _names(self, namespace: str) -> tuple[str, str]:
        digest = hashlib.sha256(namespace.encode()).hexdigest()
        return f"{digest}.anchor.json", f"{digest}.lock"

    @contextlib.contextmanager
    def _namespace_lock(self, namespace: str) -> Iterator[None]:
        _require_spend_locking()
        _, lock_name = self._names(namespace)
        self._directory.revalidate()
        lock_fd = _open_or_create_secure_file(self._directory, lock_name)
        try:
            lock_identity = _identity(os.fstat(lock_fd))
            _revalidate_name_to_fd(self._directory, lock_name, lock_fd)
            _call_hook(self._hook, "lock_before_flock")
            _revalidate_name_to_fd(self._directory, lock_name, lock_fd)
            _lock_exclusive(lock_fd)
            _call_hook(self._hook, "lock_after_flock")
            _revalidate_name_to_fd(self._directory, lock_name, lock_fd)
            if _identity(os.fstat(lock_fd)) != lock_identity:
                raise SpendPathSecurityError("anchor lock identity changed")
            yield
            _revalidate_name_to_fd(self._directory, lock_name, lock_fd)
            self._directory.revalidate()
        except SpendStoreError:
            raise
        except OSError as exc:
            raise SpendPathSecurityError("anchor namespace lock failed") from exc
        finally:
            _cleanup_owned(
                (
                    ("namespace lock release", lambda: _unlock(lock_fd)),
                    ("namespace lock fd", lambda: os.close(lock_fd)),
                ),
                primary=sys.exception(),
                error_type=SpendPathSecurityError,
            )

    def _read_unlocked(self, namespace: str) -> SpendAnchorRecord | None:
        anchor_name, _ = self._names(namespace)
        initial = _stat_name(self._directory, anchor_name)
        if initial is None:
            _call_hook(self._hook, "anchor_absent")
            if _stat_name(self._directory, anchor_name) is not None:
                raise SpendPathSecurityError("anchor appeared during absence check")
            return None
        fd = _open_secure_existing_file(self._directory, anchor_name)
        try:
            _call_hook(self._hook, "anchor_before_read")
            _revalidate_name_to_fd(self._directory, anchor_name, fd)
            raw = _read_bounded(fd, _MAX_ANCHOR_BYTES)
            _call_hook(self._hook, "anchor_after_read")
            _revalidate_name_to_fd(self._directory, anchor_name, fd)
            self._directory.revalidate()
        finally:
            _cleanup_owned(
                (("anchor read fd", lambda: os.close(fd)),),
                primary=sys.exception(),
                error_type=SpendPathSecurityError,
            )
        return self._decode(namespace, raw)

    def _write_unlocked(self, namespace: str, record: SpendAnchorRecord) -> None:
        anchor_name, _ = self._names(namespace)
        prior = _stat_name(self._directory, anchor_name)
        envelope = self._envelope(record)
        encoded = _canonical_json(envelope)
        if len(encoded) > _MAX_ANCHOR_BYTES:
            raise SpendIntegrityError("anchor exceeds its size limit")
        temp_name = f".{anchor_name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
        temp_fd, temp_identity = _create_secure_file(self._directory, temp_name)
        try:
            if _identity(os.fstat(temp_fd)) != temp_identity:
                raise SpendPathSecurityError("anchor temporary file identity mismatch")
            _write_all(temp_fd, encoded)
            os.fsync(temp_fd)
            _revalidate_name_to_fd(self._directory, temp_name, temp_fd)
            _call_hook(self._hook, "anchor_before_replace")
            _revalidate_optional_identity(self._directory, anchor_name, prior)
            _revalidate_name_to_fd(self._directory, temp_name, temp_fd)
            os.replace(
                temp_name,
                anchor_name,
                src_dir_fd=self._directory.fd,
                dst_dir_fd=self._directory.fd,
            )
            _call_hook(self._hook, "anchor_after_replace")
            current = _stat_name(self._directory, anchor_name)
            if current is None or _identity(current) != temp_identity:
                raise SpendPathSecurityError("anchor replacement identity mismatch")
            _require_secure_file_stat(current, self._directory.owner_uid, "anchor")
            os.fsync(self._directory.fd)
            _revalidate_name_to_fd(self._directory, anchor_name, temp_fd)
            self._directory.revalidate()
        except SpendStoreError:
            raise
        except OSError as exc:
            raise SpendPathSecurityError("anchor atomic write failed") from exc
        finally:
            _cleanup_owned(
                (
                    ("anchor temp fd", lambda: os.close(temp_fd)),
                    (
                        "anchor temp unlink",
                        lambda: _unlink_name_if_identity(self._directory, temp_name, temp_identity),
                    ),
                ),
                primary=sys.exception(),
                error_type=SpendPathSecurityError,
            )
        if self._read_unlocked(namespace) != record:
            raise SpendIntegrityError("anchor read-after-write mismatch")

    def _envelope(self, record: SpendAnchorRecord) -> dict[str, object]:
        record_value = _record_dict(record)
        mac_payload = {
            "schema": _ANCHOR_MAC_SCHEMA,
            "key_id": self._key_id,
            "record": record_value,
        }
        if set(mac_payload) != _MAC_KEYS:
            raise SpendIntegrityError("internal anchor MAC schema mismatch")
        mac = hmac.new(
            self._key,
            _ANCHOR_MAC_DOMAIN + _canonical_json(mac_payload),
            hashlib.sha256,
        ).hexdigest()
        return {
            "schema": _ANCHOR_ENVELOPE_SCHEMA,
            "key_id": self._key_id,
            "record": record_value,
            "mac": mac,
        }

    def _decode(self, namespace: str, raw: bytes) -> SpendAnchorRecord:
        if len(raw) > _MAX_ANCHOR_BYTES:
            raise SpendIntegrityError("anchor exceeds its size limit")
        try:
            decoded = json.loads(raw.decode(), object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, ValueError) as exc:
            raise SpendIntegrityError("anchor is not strict JSON") from exc
        if not isinstance(decoded, dict) or set(decoded) != _ENVELOPE_KEYS:
            raise SpendIntegrityError("anchor envelope fields are incompatible")
        if _canonical_json(decoded) != raw:
            raise SpendIntegrityError("anchor is not canonical JSON")
        if decoded.get("schema") != _ANCHOR_ENVELOPE_SCHEMA:
            raise SpendIntegrityError("anchor envelope schema is incompatible")
        envelope_key_id = _required_text(decoded.get("key_id"), "key_id")
        record_value = decoded.get("record")
        if not isinstance(record_value, dict) or set(record_value) != _RECORD_KEYS:
            raise SpendIntegrityError("anchor record fields are incompatible")
        record_key_id = _required_text(record_value.get("key_id"), "record key_id")
        if envelope_key_id != record_key_id or envelope_key_id != self._key_id:
            raise SpendAnchorKeyMismatch("anchor key_id does not match configured key_id")
        mac = _required_text(decoded.get("mac"), "mac")
        _validate_digest(mac, "mac")
        mac_payload = {
            "schema": _ANCHOR_MAC_SCHEMA,
            "key_id": envelope_key_id,
            "record": record_value,
        }
        expected = hmac.new(
            self._key,
            _ANCHOR_MAC_DOMAIN + _canonical_json(mac_payload),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(mac, expected):
            raise SpendAnchorAuthenticationError("anchor HMAC authentication failed")
        record = _record_from_dict(record_value)
        if record.namespace != namespace:
            raise SpendIntegrityError("anchor namespace does not match lookup namespace")
        return record


_TABLE_DDL = {
    "spend_store_metadata": """
        CREATE TABLE spend_store_metadata (
            singleton INTEGER PRIMARY KEY CHECK (singleton=1),
            schema_version INTEGER NOT NULL CHECK (schema_version=1),
            store_id TEXT NOT NULL UNIQUE,
            generation INTEGER NOT NULL CHECK (generation>=0),
            event_count INTEGER NOT NULL CHECK (event_count>=0),
            head_hash TEXT NOT NULL CHECK (
                length(head_hash)=64 AND head_hash NOT GLOB '*[^0-9a-f]*'
            ),
            created_at_us INTEGER NOT NULL CHECK (created_at_us>=0),
            anchor_namespace TEXT NOT NULL
        ) STRICT
    """,
    "spend_intents": """
        CREATE TABLE spend_intents (
            spend_id TEXT PRIMARY KEY,
            attempt_digest TEXT NOT NULL CHECK(
                length(attempt_digest)=64 AND attempt_digest NOT GLOB '*[^0-9a-f]*'
            ),
            tenant_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            recipient TEXT NOT NULL,
            currency TEXT NOT NULL CHECK (length(currency)=3 AND currency=upper(currency)),
            amount_minor INTEGER NOT NULL
                CHECK (amount_minor>0 AND amount_minor<=9223372036854775807),
            reference_digest TEXT NOT NULL CHECK(
                length(reference_digest)=64 AND reference_digest NOT GLOB '*[^0-9a-f]*'
            ),
            argument_digest TEXT NOT NULL CHECK(
                length(argument_digest)=64 AND argument_digest NOT GLOB '*[^0-9a-f]*'
            ),
            semantic_digest TEXT NOT NULL CHECK(
                length(semantic_digest)=64 AND semantic_digest NOT GLOB '*[^0-9a-f]*'
            ),
            loop_fingerprint_digest TEXT NOT NULL CHECK(
                length(loop_fingerprint_digest)=64
                AND loop_fingerprint_digest NOT GLOB '*[^0-9a-f]*'
            ),
            receipt_digest TEXT NOT NULL CHECK(
                length(receipt_digest)=64 AND receipt_digest NOT GLOB '*[^0-9a-f]*'
            ),
            policy_digest TEXT NOT NULL CHECK(
                length(policy_digest)=64 AND policy_digest NOT GLOB '*[^0-9a-f]*'
            ),
            approval_digest TEXT,
            budget_rules_digest TEXT NOT NULL CHECK(
                length(budget_rules_digest)=64
                AND budget_rules_digest NOT GLOB '*[^0-9a-f]*'
            ),
            budget_snapshot_digest TEXT NOT NULL CHECK(
                length(budget_snapshot_digest)=64
                AND budget_snapshot_digest NOT GLOB '*[^0-9a-f]*'
            ),
            budget_snapshot_json TEXT NOT NULL,
            idempotency_digest TEXT NOT NULL CHECK(
                length(idempotency_digest)=64 AND idempotency_digest NOT GLOB '*[^0-9a-f]*'
            ),
            state_generation INTEGER NOT NULL CHECK (state_generation>=0),
            stop_generation INTEGER NOT NULL CHECK (stop_generation>=0),
            reserved_at_us INTEGER NOT NULL CHECK (reserved_at_us>=0),
            UNIQUE (tenant_id,provider,idempotency_digest),
            CHECK (
                approval_digest IS NULL OR (
                    length(approval_digest)=64
                    AND approval_digest NOT GLOB '*[^0-9a-f]*'
                )
            )
        ) STRICT
    """,
    "spend_outcomes": """
        CREATE TABLE spend_outcomes (
            spend_id TEXT PRIMARY KEY
                REFERENCES spend_intents(spend_id) ON DELETE RESTRICT,
            state TEXT NOT NULL CHECK (state IN ('SUCCEEDED','UNKNOWN')),
            result_digest TEXT CHECK(
                result_digest IS NULL OR (
                    length(result_digest)=64 AND result_digest NOT GLOB '*[^0-9a-f]*'
                )
            ),
            provider_reference_digest TEXT CHECK(
                provider_reference_digest IS NULL OR (
                    length(provider_reference_digest)=64
                    AND provider_reference_digest NOT GLOB '*[^0-9a-f]*'
                )
            ),
            uncertainty_digest TEXT CHECK(
                uncertainty_digest IS NULL OR (
                    length(uncertainty_digest)=64
                    AND uncertainty_digest NOT GLOB '*[^0-9a-f]*'
                )
            ),
            transitioned_at_us INTEGER NOT NULL CHECK (transitioned_at_us>=0),
            CHECK (
                (state='SUCCEEDED' AND result_digest IS NOT NULL
                    AND provider_reference_digest IS NOT NULL
                    AND uncertainty_digest IS NULL)
                OR (state='UNKNOWN' AND result_digest IS NULL
                    AND provider_reference_digest IS NULL
                    AND uncertainty_digest IS NOT NULL)
            )
        ) STRICT
    """,
    "spend_control_events": """
        CREATE TABLE spend_control_events (
            tenant_id TEXT NOT NULL,
            stop_generation INTEGER NOT NULL CHECK (stop_generation>0),
            enabled INTEGER NOT NULL CHECK (enabled IN (0,1)),
            authority_digest TEXT NOT NULL CHECK(
                length(authority_digest)=64 AND authority_digest NOT GLOB '*[^0-9a-f]*'
            ),
            reason_digest TEXT NOT NULL CHECK(
                length(reason_digest)=64 AND reason_digest NOT GLOB '*[^0-9a-f]*'
            ),
            changed_at_us INTEGER NOT NULL CHECK(changed_at_us>=0),
            PRIMARY KEY(tenant_id,stop_generation)
        ) STRICT
    """,
    "spend_integrity_events": """
        CREATE TABLE spend_integrity_events (
            generation INTEGER PRIMARY KEY CHECK(generation>0),
            event_id TEXT NOT NULL UNIQUE,
            event_type TEXT NOT NULL CHECK(event_type IN ('RESERVE','OUTCOME','CONTROL')),
            entity_id TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            payload_digest TEXT NOT NULL CHECK(
                length(payload_digest)=64 AND payload_digest NOT GLOB '*[^0-9a-f]*'
            ),
            previous_hash TEXT NOT NULL CHECK(
                length(previous_hash)=64 AND previous_hash NOT GLOB '*[^0-9a-f]*'
            ),
            event_hash TEXT NOT NULL UNIQUE CHECK(
                length(event_hash)=64 AND event_hash NOT GLOB '*[^0-9a-f]*'
            ),
            occurred_at_us INTEGER NOT NULL CHECK(occurred_at_us>=0)
        ) STRICT
    """,
}

_INDEX_DDL = {
    "idx_spend_scope_time": (
        "CREATE INDEX idx_spend_scope_time "
        "ON spend_intents(tenant_id,provider,currency,reserved_at_us)"
    ),
    "idx_spend_vendor_time": (
        "CREATE INDEX idx_spend_vendor_time "
        "ON spend_intents(tenant_id,provider,recipient,currency,reserved_at_us)"
    ),
    "idx_spend_loop_time": (
        "CREATE INDEX idx_spend_loop_time ON spend_intents(tenant_id,provider,recipient,"
        "currency,loop_fingerprint_digest,reserved_at_us)"
    ),
    "idx_spend_control_latest": (
        "CREATE INDEX idx_spend_control_latest "
        "ON spend_control_events(tenant_id,stop_generation DESC)"
    ),
}


class SQLiteSpendStore:
    """Strict SQLite v1 receipt-bound Spend Guard state machine."""

    def __init__(
        self,
        path: str | Path,
        *,
        anchor: SpendStateAnchor,
        anchor_namespace: str,
        clock: SpendClock | None = None,
        security_hook: _SecurityHook | None = None,
        _create: bool | None = None,
        _attested_directory: AttestedDirectory | None = None,
        _attested_relative: str | None = None,
    ) -> None:
        _require_spend_locking()
        if _create is None:
            raise SpendStoreError("use SQLiteSpendStore.create or SQLiteSpendStore.open")
        self._attested_directory = _attested_directory
        self._attested_relative = _attested_relative
        if _attested_directory is None:
            if _attested_relative is not None:
                raise SpendPathSecurityError("attested database directory is required")
            self.path = _validated_absolute_path(path, "database")
            self._parent = _SecureDirectory.open(self.path.parent)
            operation_lock_key: object = self.path
        else:
            directory = require_attested_directory(
                _attested_directory,
                error_type=SpendPathSecurityError,
            )
            if _attested_relative is None:
                raise SpendPathSecurityError("attested database basename is required")
            directory.checkpoint()
            directory.sqlite_path(_attested_relative)
            self.path = directory.display_path / _attested_relative
            self._parent = _SecureDirectory.from_attested(directory)
            operation_lock_key = (directory.identity, _attested_relative)
        try:
            self._mutation_lock = _operation_lock_for(operation_lock_key)
            self._poisoned = False
            self._name = self.path.name
            self._anchor = anchor
            self._anchor_namespace = _validate_namespace(anchor_namespace)
            self._clock = clock or SystemSpendClock()
            self._hook = security_hook
            if not isinstance(anchor, SpendStateAnchor):
                raise SpendStoreError("anchor must implement SpendStateAnchor")
            if _create:
                self._create_store()
            else:
                self._open_store()
        except BaseException:
            self._parent.close()
            raise

    @classmethod
    def create(
        cls,
        path: str | Path,
        *,
        anchor: SpendStateAnchor,
        anchor_namespace: str,
        clock: SpendClock | None = None,
        security_hook: _SecurityHook | None = None,
    ) -> SQLiteSpendStore:
        _require_spend_locking()
        return cls(
            path,
            anchor=anchor,
            anchor_namespace=anchor_namespace,
            clock=clock,
            security_hook=security_hook,
            _create=True,
        )

    @classmethod
    def open(
        cls,
        path: str | Path,
        *,
        anchor: SpendStateAnchor,
        anchor_namespace: str,
        clock: SpendClock | None = None,
        security_hook: _SecurityHook | None = None,
    ) -> SQLiteSpendStore:
        _require_spend_locking()
        return cls(
            path,
            anchor=anchor,
            anchor_namespace=anchor_namespace,
            clock=clock,
            security_hook=security_hook,
            _create=False,
        )

    @classmethod
    def create_from_attested(
        cls,
        directory: AttestedDirectory,
        relative: str,
        *,
        anchor: SpendStateAnchor,
        anchor_namespace: str,
        clock: SpendClock | None = None,
        security_hook: _SecurityHook | None = None,
    ) -> SQLiteSpendStore:
        _require_spend_locking()
        capability = require_attested_directory(directory, error_type=SpendPathSecurityError)
        relative = _attested_basename(relative, "database")
        return cls(
            capability.display_path / relative,
            anchor=anchor,
            anchor_namespace=anchor_namespace,
            clock=clock,
            security_hook=security_hook,
            _create=True,
            _attested_directory=capability,
            _attested_relative=relative,
        )

    @classmethod
    def open_from_attested(
        cls,
        directory: AttestedDirectory,
        relative: str,
        *,
        anchor: SpendStateAnchor,
        anchor_namespace: str,
        clock: SpendClock | None = None,
        security_hook: _SecurityHook | None = None,
    ) -> SQLiteSpendStore:
        _require_spend_locking()
        capability = require_attested_directory(directory, error_type=SpendPathSecurityError)
        relative = _attested_basename(relative, "database")
        return cls(
            capability.display_path / relative,
            anchor=anchor,
            anchor_namespace=anchor_namespace,
            clock=clock,
            security_hook=security_hook,
            _create=False,
            _attested_directory=capability,
            _attested_relative=relative,
        )

    def _sqlite_connection_path(self) -> Path:
        directory = self._attested_directory
        relative = self._attested_relative
        if directory is None or relative is None:
            return self.path
        require_attested_directory(directory, error_type=SpendPathSecurityError)
        directory.checkpoint()
        return directory.sqlite_path(relative)

    def close(self) -> None:
        with self._mutation_lock:
            self._parent.close()

    def verify_integrity(self) -> SpendAnchorRecord:
        with self._mutation_lock:
            self._ensure_operable()
            with self._connect() as connection:
                self._validate_schema(connection)
                record = self._metadata_record(connection)
                _verify_exact_spend_state(connection, record)
            self._verify_anchor(record)
            self._validate_database_success()
            return record

    def preview(
        self,
        request: SpendReservationRequest,
        rules: SpendBudgetRules,
    ) -> SpendBudgetProbe:
        """Evaluate budget state transactionally without mutating durable state."""

        if type(request) is not SpendReservationRequest:
            raise SpendIntegrityError("request must be SpendReservationRequest")
        rules = _trusted_budget_rules(rules)
        if request.currency != rules.currency:
            raise SpendIntegrityError("request currency does not match budget rules")
        with self._mutation_lock:
            self._ensure_operable()
            with self._connect() as connection:
                connection.execute("BEGIN")
                try:
                    self._validate_schema(connection)
                    base = self._metadata_record(connection)
                    verified = _verify_exact_spend_state(connection, base)
                    self._verify_anchor(base)
                    now_us = _clock_us(self._clock)
                    if now_us < verified.last_occurred_at_us:
                        raise SpendReservationRejected(SPEND_CLOCK_ROLLBACK)
                    control = _current_control(connection, request.tenant_id)
                    evaluation = _budget_evaluation(
                        connection,
                        request,
                        rules,
                        base,
                        now_us,
                        control,
                    )
                    reason: str | None
                    if request.expected_stop_generation != control.stop_generation:
                        reason = SPEND_STOP_GENERATION_MISMATCH
                    elif control.enabled:
                        reason = SPEND_EMERGENCY_STOP_ACTIVE
                    else:
                        reason = _budget_rejection(request, rules, evaluation)
                    request_digest = _probe_request_digest(request)
                    return SpendBudgetProbe(
                        request_digest=request_digest,
                        base_generation=base.generation,
                        stop_generation=control.stop_generation,
                        rules_digest=rules.digest,
                        budget_snapshot=evaluation.snapshot,
                        reason_code=reason,
                        snapshot_digest=_probe_digest(
                            request_digest=request_digest,
                            rules_digest=rules.digest,
                            base_generation=base.generation,
                            stop_generation=control.stop_generation,
                        ),
                    )
                finally:
                    if connection.in_transaction:
                        connection.rollback()

    def reserve(
        self,
        request: SpendReservationRequest,
        rules: SpendBudgetRules,
        *,
        expected_snapshot_digest: str | None = None,
    ) -> SpendReservation:
        if type(request) is not SpendReservationRequest:
            raise SpendIntegrityError("request must be SpendReservationRequest")
        rules = _trusted_budget_rules(rules)
        if expected_snapshot_digest is not None:
            _validate_digest(expected_snapshot_digest, "expected_snapshot_digest")
        if request.currency != rules.currency:
            raise SpendIntegrityError("request currency does not match budget rules")

        def apply(
            connection: sqlite3.Connection,
            base: SpendAnchorRecord,
            now_us: int,
        ) -> tuple[SpendReservation, bool]:
            existing = connection.execute(
                "SELECT * FROM spend_intents "
                "WHERE tenant_id=? AND provider=? AND idempotency_digest=?",
                (request.tenant_id, request.provider, request.idempotency_digest),
            ).fetchone()
            if existing is not None:
                if not _intent_matches_request(existing, request, rules.digest):
                    raise SpendReservationRejected(SPEND_IDEMPOTENCY_CONFLICT)
                if expected_snapshot_digest is not None:
                    existing_probe = _probe_digest(
                        request_digest=_probe_request_digest(request),
                        rules_digest=rules.digest,
                        base_generation=_row_int(existing, "state_generation") - 1,
                        stop_generation=_row_int(existing, "stop_generation"),
                    )
                    if not hmac.compare_digest(expected_snapshot_digest, existing_probe):
                        raise SpendReservationRejected(SPEND_BUDGET_SNAPSHOT_MISMATCH)
                return _reservation_from_row(connection, existing, replayed=True), False
            control = _current_control(connection, request.tenant_id)
            if expected_snapshot_digest is not None:
                current_probe = _probe_digest(
                    request_digest=_probe_request_digest(request),
                    rules_digest=rules.digest,
                    base_generation=base.generation,
                    stop_generation=control.stop_generation,
                )
                if not hmac.compare_digest(expected_snapshot_digest, current_probe):
                    raise SpendReservationRejected(SPEND_BUDGET_SNAPSHOT_MISMATCH)
            if request.expected_stop_generation != control.stop_generation:
                raise SpendReservationRejected(SPEND_STOP_GENERATION_MISMATCH)
            if control.enabled:
                raise SpendReservationRejected(SPEND_EMERGENCY_STOP_ACTIVE)
            evaluation = _budget_evaluation(connection, request, rules, base, now_us, control)
            reason = _budget_rejection(request, rules, evaluation)
            if reason is not None:
                raise SpendReservationRejected(reason, evaluation.snapshot)
            spend_id = str(uuid.uuid4())
            generation = base.generation + 1
            row: dict[str, object] = {
                "spend_id": spend_id,
                "attempt_digest": request.attempt_digest,
                "tenant_id": request.tenant_id,
                "provider": request.provider,
                "recipient": request.recipient,
                "currency": request.currency,
                "amount_minor": request.amount_minor,
                "reference_digest": request.reference_digest,
                "argument_digest": request.argument_digest,
                "semantic_digest": request.semantic_digest,
                "loop_fingerprint_digest": request.loop_fingerprint_digest,
                "receipt_digest": request.receipt_digest,
                "policy_digest": request.policy_digest,
                "approval_digest": request.approval_digest,
                "budget_rules_digest": rules.digest,
                "budget_snapshot_digest": evaluation.snapshot.snapshot_digest,
                "budget_snapshot_json": evaluation.snapshot.snapshot_json,
                "idempotency_digest": request.idempotency_digest,
                "state_generation": generation,
                "stop_generation": control.stop_generation,
                "reserved_at_us": now_us,
            }
            connection.execute(
                """INSERT INTO spend_intents (
                       spend_id,attempt_digest,tenant_id,provider,recipient,currency,
                       amount_minor,reference_digest,argument_digest,semantic_digest,
                       loop_fingerprint_digest,receipt_digest,policy_digest,approval_digest,
                       budget_rules_digest,budget_snapshot_digest,budget_snapshot_json,
                       idempotency_digest,state_generation,stop_generation,reserved_at_us
                   ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                tuple(row[name] for name in _INTENT_COLUMNS),
            )
            _append_integrity_event(connection, base, "RESERVE", spend_id, row, now_us)
            return (
                SpendReservation(
                    spend_id=spend_id,
                    state=SpendOutcomeState.RESERVED,
                    replayed=False,
                    state_generation=generation,
                    stop_generation=control.stop_generation,
                    budget_snapshot=evaluation.snapshot,
                    outcome=None,
                ),
                True,
            )

        return self._run_mutation(apply)

    def record_outcome(
        self,
        spend_id: str,
        *,
        state: SpendOutcomeState,
        result_digest: str | None = None,
        provider_reference_digest: str | None = None,
        uncertainty_digest: str | None = None,
    ) -> SpendOutcome:
        spend_id = _validate_uuid(spend_id, "spend_id")
        if type(state) is not SpendOutcomeState or state is SpendOutcomeState.RESERVED:
            raise SpendReservationRejected(SPEND_OUTCOME_CONFLICT)
        if state is SpendOutcomeState.SUCCEEDED:
            if result_digest is None or provider_reference_digest is None:
                raise SpendReservationRejected(SPEND_OUTCOME_CONFLICT)
            _validate_digest(result_digest, "result_digest")
            _validate_digest(provider_reference_digest, "provider_reference_digest")
            if uncertainty_digest is not None:
                raise SpendReservationRejected(SPEND_OUTCOME_CONFLICT)
        else:
            if uncertainty_digest is None:
                raise SpendReservationRejected(SPEND_OUTCOME_CONFLICT)
            _validate_digest(uncertainty_digest, "uncertainty_digest")
            if result_digest is not None or provider_reference_digest is not None:
                raise SpendReservationRejected(SPEND_OUTCOME_CONFLICT)

        def apply(
            connection: sqlite3.Connection,
            base: SpendAnchorRecord,
            now_us: int,
        ) -> tuple[SpendOutcome, bool]:
            intent = connection.execute(
                "SELECT spend_id FROM spend_intents WHERE spend_id=?", (spend_id,)
            ).fetchone()
            if intent is None:
                raise SpendReservationRejected(SPEND_OUTCOME_CONFLICT)
            existing = connection.execute(
                "SELECT * FROM spend_outcomes WHERE spend_id=?", (spend_id,)
            ).fetchone()
            if existing is not None:
                outcome = _outcome_from_row(connection, existing)
                if (
                    outcome.state is state
                    and outcome.result_digest == result_digest
                    and outcome.provider_reference_digest == provider_reference_digest
                    and outcome.uncertainty_digest == uncertainty_digest
                ):
                    return outcome, False
                raise SpendReservationRejected(SPEND_OUTCOME_CONFLICT)
            generation = base.generation + 1
            row: dict[str, object] = {
                "spend_id": spend_id,
                "state": state.value,
                "result_digest": result_digest,
                "provider_reference_digest": provider_reference_digest,
                "uncertainty_digest": uncertainty_digest,
                "transitioned_at_us": now_us,
            }
            connection.execute(
                """INSERT INTO spend_outcomes (
                       spend_id,state,result_digest,provider_reference_digest,
                       uncertainty_digest,transitioned_at_us
                   ) VALUES (?,?,?,?,?,?)""",
                tuple(row[name] for name in _OUTCOME_COLUMNS),
            )
            _append_integrity_event(connection, base, "OUTCOME", spend_id, row, now_us)
            return (
                SpendOutcome(
                    spend_id=spend_id,
                    state=state,
                    state_generation=generation,
                    transitioned_at_us=now_us,
                    result_digest=result_digest,
                    provider_reference_digest=provider_reference_digest,
                    uncertainty_digest=uncertainty_digest,
                ),
                True,
            )

        return self._run_mutation(apply)

    def set_emergency_stop(
        self,
        tenant_id: str,
        *,
        enabled: bool,
        expected_generation: int,
        authority_digest: str,
        reason_digest: str,
    ) -> SpendControlState:
        tenant_id = _validate_spend_text(tenant_id, "tenant_id")
        if type(enabled) is not bool:
            raise SpendIntegrityError("enabled must be a boolean")
        _validate_nonnegative_integer(expected_generation, "expected_generation")
        authority_digest = _validate_digest(authority_digest, "authority_digest")
        reason_digest = _validate_digest(reason_digest, "reason_digest")

        def apply(
            connection: sqlite3.Connection,
            base: SpendAnchorRecord,
            now_us: int,
        ) -> tuple[SpendControlState, bool]:
            current = _current_control(connection, tenant_id)
            if current.stop_generation != expected_generation:
                raise SpendReservationRejected(SPEND_CONTROL_GENERATION_CONFLICT)
            stop_generation = current.stop_generation + 1
            state_generation = base.generation + 1
            row: dict[str, object] = {
                "tenant_id": tenant_id,
                "stop_generation": stop_generation,
                "enabled": int(enabled),
                "authority_digest": authority_digest,
                "reason_digest": reason_digest,
                "changed_at_us": now_us,
            }
            connection.execute(
                """INSERT INTO spend_control_events (
                       tenant_id,stop_generation,enabled,authority_digest,reason_digest,
                       changed_at_us
                   ) VALUES (?,?,?,?,?,?)""",
                tuple(row[name] for name in _CONTROL_COLUMNS),
            )
            _append_integrity_event(connection, base, "CONTROL", tenant_id, row, now_us)
            return (
                SpendControlState(
                    tenant_id=tenant_id,
                    enabled=enabled,
                    stop_generation=stop_generation,
                    state_generation=state_generation,
                    changed_at_us=now_us,
                    authority_digest=authority_digest,
                    reason_digest=reason_digest,
                ),
                True,
            )

        return self._run_mutation(apply)

    def _run_mutation(
        self,
        apply: Callable[
            [sqlite3.Connection, SpendAnchorRecord, int],
            tuple[_T, bool],
        ],
    ) -> _T:
        with self._mutation_lock:
            self._ensure_operable()
            committed = False
            anchor_completed = False
            try:
                with self._connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    try:
                        self._validate_schema(connection)
                        base = self._metadata_record(connection)
                        verified = _verify_exact_spend_state(connection, base)
                        self._verify_anchor(base)
                        now_us = _clock_us(self._clock)
                        if now_us < verified.last_occurred_at_us:
                            raise SpendReservationRejected(SPEND_CLOCK_ROLLBACK)
                        result, changed = apply(connection, base, now_us)
                        if not changed:
                            connection.rollback()
                            return result
                        replacement = self._metadata_record(connection)
                        if (
                            replacement.generation != base.generation + 1
                            or replacement.event_count != base.event_count + 1
                        ):
                            raise SpendIntegrityError(
                                "mutation did not advance exactly one generation"
                            )
                        _verify_exact_spend_state(connection, replacement)
                        _call_hook(self._hook, "spend_mutation_before_commit")
                        connection.commit()
                        committed = True
                        _call_hook(self._hook, "spend_mutation_after_commit")
                        _call_hook(self._hook, "spend_mutation_before_anchor_cas")
                        self._anchor.compare_and_swap(
                            self._anchor_namespace,
                            base,
                            replacement,
                        )
                        published = self._anchor.read(self._anchor_namespace)
                        if published != replacement:
                            raise SpendRepairRequired(
                                "trusted anchor publication did not match committed spend state"
                            )
                        anchor_completed = True
                        _call_hook(self._hook, "spend_mutation_after_anchor_cas")
                    except BaseException as exc:
                        if not committed and connection.in_transaction:
                            try:
                                connection.rollback()
                            except BaseException as rollback_failure:
                                exc.add_note(
                                    "SQLite rollback cleanup failed "
                                    f"({type(rollback_failure).__name__})"
                                )
                        raise
                return result
            except BaseException as exc:
                if committed:
                    self._poisoned = True
                    if not anchor_completed:
                        raise SpendRepairRequired(
                            "committed spend mutation is not confirmed by its trusted anchor"
                        ) from exc
                raise

    def _ensure_operable(self) -> None:
        if self._poisoned:
            raise SpendRepairRequired("live spend store is poisoned after an uncertain mutation")
        if self._parent.fd < 0:
            raise SpendStoreUnavailable("spend store is closed")

    def _create_store(self) -> None:
        if self._anchor.read(self._anchor_namespace) is not None:
            raise SpendIntegrityError("anchor namespace is already initialized")
        if _stat_name(self._parent, self._name) is not None:
            raise SpendStoreError("spend store already exists")
        database_fd, _ = _create_secure_file(self._parent, self._name)
        try:
            os.fsync(database_fd)
            os.fsync(self._parent.fd)
            with self._connect(validation_fd=database_fd) as connection:
                connection.execute("BEGIN IMMEDIATE")
                for ddl in _TABLE_DDL.values():
                    connection.execute(ddl)
                for ddl in _INDEX_DDL.values():
                    connection.execute(ddl)
                # Fixed module integer, never caller input.
                connection.execute(  # nosec B608
                    f"PRAGMA application_id = {SPEND_APPLICATION_ID}"
                )
                # Fixed schema integer, never caller input.
                connection.execute(  # nosec B608
                    f"PRAGMA user_version = {SPEND_SCHEMA_VERSION}"
                )
                record = SpendAnchorRecord(
                    key_id=self._anchor.key_id,
                    namespace=self._anchor_namespace,
                    store_id=str(uuid.uuid4()),
                    generation=0,
                    event_count=0,
                    head_hash=ZERO_HASH,
                )
                connection.execute(
                    """
                    INSERT INTO spend_store_metadata (
                        singleton,schema_version,store_id,generation,event_count,
                        head_hash,created_at_us,anchor_namespace
                    ) VALUES (1,1,?,0,0,?,?,?)
                    """,
                    (record.store_id, ZERO_HASH, _clock_us(self._clock), self._anchor_namespace),
                )
                connection.commit()
                self._validate_schema(connection)
                if self._metadata_record(connection) != record:
                    raise SpendIntegrityError("created metadata did not materialize exactly")
                os.fsync(database_fd)
                self._validate_sidecars()
                os.fsync(self._parent.fd)
            self._anchor.compare_and_swap(self._anchor_namespace, None, record)
            self.verify_integrity()
            os.fsync(self._parent.fd)
            _revalidate_name_to_fd(self._parent, self._name, database_fd)
            self._parent.revalidate()
        except SpendStoreError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise SpendStoreError("spend store initialization failed") from exc
        finally:
            _cleanup_owned(
                (("database create fd", lambda: os.close(database_fd)),),
                primary=sys.exception(),
                error_type=SpendStoreUnavailable,
            )

    def _open_store(self) -> None:
        with self._connect() as connection:
            self._validate_schema(connection)
            record = self._metadata_record(connection)
        self._verify_anchor(record)
        self.verify_integrity()

    @contextlib.contextmanager
    def _connect(self, validation_fd: int | None = None) -> Iterator[sqlite3.Connection]:
        owns_fd = validation_fd is None
        if validation_fd is None:
            validation_fd = _open_secure_existing_file(self._parent, self._name)
        connection: sqlite3.Connection | None = None
        try:
            _revalidate_name_to_fd(self._parent, self._name, validation_fd)
            _call_hook(self._hook, "database_before_connect")
            _revalidate_name_to_fd(self._parent, self._name, validation_fd)
            connection = sqlite3.connect(
                self._sqlite_connection_path(),
                timeout=5.0,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            _call_hook(self._hook, "database_after_connect")
            _revalidate_name_to_fd(self._parent, self._name, validation_fd)
            self._configure_connection(connection)
            self._validate_sidecars()
            yield connection
            _call_hook(self._hook, "database_before_success")
            _revalidate_name_to_fd(self._parent, self._name, validation_fd)
            self._validate_sidecars()
            self._parent.revalidate()
        except SpendStoreError:
            raise
        except sqlite3.Error as exc:
            raise SpendStoreError("spend store SQLite operation failed") from exc
        finally:
            cleanup_actions: list[tuple[str, Callable[[], None]]] = []
            if connection is not None:
                cleanup_actions.append(("SQLite connection", connection.close))
            if owns_fd:
                cleanup_actions.append(("SQLite validation fd", lambda: os.close(validation_fd)))
            _cleanup_owned(
                cleanup_actions,
                primary=sys.exception(),
                error_type=SpendStoreUnavailable,
            )

    def _configure_connection(self, connection: sqlite3.Connection) -> None:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA busy_timeout = 5000")
        expected = {"foreign_keys": 1, "trusted_schema": 0, "synchronous": 2, "busy_timeout": 5000}
        for name, value in expected.items():
            if (
                _single_int(
                    # Name comes only from the fixed expected-object map.
                    connection.execute(  # nosec B608
                        f"PRAGMA {name}"
                    ).fetchone(),
                    name,
                )
                != value
            ):
                raise SpendStoreError(f"SQLite {name} pragma was not enforced")
        mode = connection.execute("PRAGMA journal_mode").fetchone()
        if mode is None or str(mode[0]).lower() != "wal":
            raise SpendStoreError("SQLite WAL journal mode was not enforced")

    def _validate_sidecars(self) -> None:
        for suffix in ("-wal", "-shm"):
            name = f"{self._name}{suffix}"
            if _stat_name(self._parent, name) is None:
                continue
            fd = _open_secure_existing_file(self._parent, name)
            try:
                _revalidate_name_to_fd(self._parent, name, fd)
            finally:
                _cleanup_owned(
                    (("SQLite sidecar fd", partial(os.close, fd)),),
                    primary=sys.exception(),
                    error_type=SpendPathSecurityError,
                )

    def _validate_database_success(self) -> None:
        fd = _open_secure_existing_file(self._parent, self._name)
        try:
            _call_hook(self._hook, "database_final_validation")
            _revalidate_name_to_fd(self._parent, self._name, fd)
            self._validate_sidecars()
            self._parent.revalidate()
        finally:
            _cleanup_owned(
                (("database validation fd", lambda: os.close(fd)),),
                primary=sys.exception(),
                error_type=SpendPathSecurityError,
            )

    def _validate_schema(self, connection: sqlite3.Connection) -> None:
        application_id = _single_int(
            connection.execute("PRAGMA application_id").fetchone(), "application_id"
        )
        if application_id != SPEND_APPLICATION_ID:
            raise SpendStoreError("spend store application_id is incompatible")
        user_version = _single_int(
            connection.execute("PRAGMA user_version").fetchone(), "user_version"
        )
        if user_version != SPEND_SCHEMA_VERSION:
            raise SpendStoreError("spend store schema migration is unsupported")
        rows = connection.execute(
            "SELECT type,name,sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        ).fetchall()
        actual = {
            (_row_text(row, "type"), _row_text(row, "name")): _normalize_ddl(_row_text(row, "sql"))
            for row in rows
        }
        expected = {
            **{("table", name): _normalize_ddl(sql) for name, sql in _TABLE_DDL.items()},
            **{("index", name): _normalize_ddl(sql) for name, sql in _INDEX_DDL.items()},
        }
        if actual != expected:
            raise SpendStoreError("spend store schema objects are incompatible")
        strict = {
            _row_text(row, "name")
            for row in connection.execute("PRAGMA table_list").fetchall()
            if _row_text(row, "name") in _TABLE_DDL and int(row[5]) == 1
        }
        if strict != set(_TABLE_DDL):
            raise SpendStoreError("all spend store tables must be STRICT")

    def _metadata_record(self, connection: sqlite3.Connection) -> SpendAnchorRecord:
        rows = connection.execute(
            """SELECT singleton,schema_version,store_id,generation,event_count,
                      head_hash,created_at_us,anchor_namespace FROM spend_store_metadata"""
        ).fetchall()
        if len(rows) != 1:
            raise SpendIntegrityError("spend metadata must contain exactly one row")
        row = rows[0]
        if _row_int(row, "singleton") != 1 or _row_int(row, "schema_version") != 1:
            raise SpendIntegrityError("spend metadata identity is invalid")
        if _row_int(row, "created_at_us") < 0:
            raise SpendIntegrityError("spend metadata timestamp is invalid")
        namespace = _row_text(row, "anchor_namespace")
        if namespace != self._anchor_namespace:
            raise SpendIntegrityError("spend metadata anchor namespace mismatch")
        return SpendAnchorRecord(
            key_id=self._anchor.key_id,
            namespace=namespace,
            store_id=_row_text(row, "store_id"),
            generation=_row_int(row, "generation"),
            event_count=_row_int(row, "event_count"),
            head_hash=_row_text(row, "head_hash"),
        )

    def _verify_anchor(self, database: SpendAnchorRecord) -> None:
        anchored = self._anchor.read(self._anchor_namespace)
        if anchored is None:
            raise SpendRepairRequired("database state has no trusted anchor")
        if (
            database.generation >= anchored.generation
            and database.event_count >= anchored.event_count
            and database != anchored
            and (
                database.generation > anchored.generation
                or database.event_count > anchored.event_count
            )
        ):
            raise SpendRepairRequired("database state is ahead of its trusted anchor")
        if anchored.generation > database.generation or anchored.event_count > database.event_count:
            raise SpendIntegrityError("trusted anchor is ahead of the database")
        if anchored != database:
            raise SpendIntegrityError("trusted anchor and database head do not match")


_INTENT_COLUMNS = (
    "spend_id",
    "attempt_digest",
    "tenant_id",
    "provider",
    "recipient",
    "currency",
    "amount_minor",
    "reference_digest",
    "argument_digest",
    "semantic_digest",
    "loop_fingerprint_digest",
    "receipt_digest",
    "policy_digest",
    "approval_digest",
    "budget_rules_digest",
    "budget_snapshot_digest",
    "budget_snapshot_json",
    "idempotency_digest",
    "state_generation",
    "stop_generation",
    "reserved_at_us",
)
_OUTCOME_COLUMNS = (
    "spend_id",
    "state",
    "result_digest",
    "provider_reference_digest",
    "uncertainty_digest",
    "transitioned_at_us",
)
_CONTROL_COLUMNS = (
    "tenant_id",
    "stop_generation",
    "enabled",
    "authority_digest",
    "reason_digest",
    "changed_at_us",
)


@dataclass(frozen=True, slots=True)
class _VerifiedSpendState:
    last_occurred_at_us: int


@dataclass(frozen=True, slots=True)
class _BudgetEvaluation:
    snapshot: SpendBudgetSnapshot
    hourly_projected: int
    daily_projected: int
    monthly_projected: int
    vendor_projected: int
    vendor_limit: int | None
    rate_projected: int
    loop_projected: int
    anomaly_projected: int
    anomaly_threshold: int


def _append_integrity_event(
    connection: sqlite3.Connection,
    base: SpendAnchorRecord,
    event_type: str,
    entity_id: str,
    materialized_row: dict[str, object],
    occurred_at_us: int,
) -> SpendAnchorRecord:
    generation = base.generation + 1
    event_id = str(uuid.uuid4())
    payload_json = _canonical_json(
        {
            "schema": _EVENT_PAYLOAD_SCHEMA,
            "event_type": event_type,
            "row": materialized_row,
        }
    ).decode()
    if len(payload_json.encode()) > _MAX_EVENT_PAYLOAD_BYTES:
        raise SpendIntegrityError("spend integrity event payload exceeds its bound")
    payload_digest = hashlib.sha256(payload_json.encode()).hexdigest()
    event_hash = _spend_event_hash(
        generation=generation,
        event_id=event_id,
        event_type=event_type,
        entity_id=entity_id,
        payload_digest=payload_digest,
        previous_hash=base.head_hash,
        occurred_at_us=occurred_at_us,
    )
    connection.execute(
        """INSERT INTO spend_integrity_events (
               generation,event_id,event_type,entity_id,payload_json,payload_digest,
               previous_hash,event_hash,occurred_at_us
           ) VALUES (?,?,?,?,?,?,?,?,?)""",
        (
            generation,
            event_id,
            event_type,
            entity_id,
            payload_json,
            payload_digest,
            base.head_hash,
            event_hash,
            occurred_at_us,
        ),
    )
    cursor = connection.execute(
        """UPDATE spend_store_metadata
           SET generation=?,event_count=?,head_hash=?
           WHERE singleton=1 AND generation=? AND event_count=? AND head_hash=?""",
        (
            generation,
            base.event_count + 1,
            event_hash,
            base.generation,
            base.event_count,
            base.head_hash,
        ),
    )
    if cursor.rowcount != 1:
        raise SpendIntegrityError("spend metadata generation changed during mutation")
    return SpendAnchorRecord(
        key_id=base.key_id,
        namespace=base.namespace,
        store_id=base.store_id,
        generation=generation,
        event_count=base.event_count + 1,
        head_hash=event_hash,
    )


def _verify_exact_spend_state(
    connection: sqlite3.Connection,
    record: SpendAnchorRecord,
) -> _VerifiedSpendState:
    metadata_time = _single_int(
        connection.execute(
            "SELECT created_at_us FROM spend_store_metadata WHERE singleton=1"
        ).fetchone(),
        "created_at_us",
    )
    prior_hash = ZERO_HASH
    last_occurred = metadata_time
    expected_intents: dict[str, dict[str, object]] = {}
    expected_outcomes: dict[str, dict[str, object]] = {}
    expected_controls: list[dict[str, object]] = []
    control_generations: dict[str, int] = {}
    rows = connection.execute(
        """SELECT generation,event_id,event_type,entity_id,payload_json,payload_digest,
                  previous_hash,event_hash,occurred_at_us
           FROM spend_integrity_events ORDER BY generation"""
    ).fetchall()
    if len(rows) != record.event_count or record.generation != record.event_count:
        raise SpendIntegrityError("spend integrity event count does not match metadata")
    for expected_generation, event in enumerate(rows, start=1):
        generation = _row_int(event, "generation")
        event_id = _validate_uuid(_row_text(event, "event_id"), "event_id")
        event_type = _row_text(event, "event_type")
        entity_id = _validate_spend_text(_row_text(event, "entity_id"), "entity_id")
        payload_json = _row_text(event, "payload_json")
        payload_digest = _validate_digest(_row_text(event, "payload_digest"), "payload_digest")
        previous_hash = _validate_digest(_row_text(event, "previous_hash"), "previous_hash")
        event_hash = _validate_digest(_row_text(event, "event_hash"), "event_hash")
        occurred_at_us = _row_int(event, "occurred_at_us")
        _validate_nonnegative_integer(occurred_at_us, "occurred_at_us")
        if generation != expected_generation or previous_hash != prior_hash:
            raise SpendIntegrityError("spend integrity event order or previous hash is invalid")
        if occurred_at_us < last_occurred:
            raise SpendIntegrityError("spend integrity event clock moved backwards")
        if hashlib.sha256(payload_json.encode()).hexdigest() != payload_digest:
            raise SpendIntegrityError("spend integrity payload digest mismatch")
        if event_hash != _spend_event_hash(
            generation=generation,
            event_id=event_id,
            event_type=event_type,
            entity_id=entity_id,
            payload_digest=payload_digest,
            previous_hash=previous_hash,
            occurred_at_us=occurred_at_us,
        ):
            raise SpendIntegrityError("spend integrity event hash mismatch")
        payload = _decode_canonical_document(
            payload_json,
            "spend integrity payload",
            _MAX_EVENT_PAYLOAD_BYTES,
        )
        if set(payload) != {"schema", "event_type", "row"} or (
            payload.get("schema") != _EVENT_PAYLOAD_SCHEMA
            or payload.get("event_type") != event_type
        ):
            raise SpendIntegrityError("spend integrity payload fields are incompatible")
        if event_type == "RESERVE":
            materialized = _validated_intent_event_row(payload.get("row"))
            spend_id = str(materialized["spend_id"])
            if spend_id != entity_id or spend_id in expected_intents:
                raise SpendIntegrityError("reserve integrity event identity is invalid")
            if materialized["state_generation"] != generation:
                raise SpendIntegrityError("reserve state generation mismatch")
            tenant_id = str(materialized["tenant_id"])
            if materialized["stop_generation"] != control_generations.get(tenant_id, 0):
                raise SpendIntegrityError("reserve stop generation mismatch")
            snapshot = _snapshot_from_storage(
                str(materialized["budget_snapshot_json"]),
                str(materialized["budget_snapshot_digest"]),
            )
            if (
                snapshot.observed_at_us != occurred_at_us
                or snapshot.base_generation != generation - 1
                or snapshot.reservation_generation != generation
                or snapshot.stop_generation != materialized["stop_generation"]
                or snapshot.rules_digest != materialized["budget_rules_digest"]
            ):
                raise SpendIntegrityError("reserve budget snapshot event binding mismatch")
            if materialized["reserved_at_us"] != occurred_at_us:
                raise SpendIntegrityError("reserve event timestamp mismatch")
            expected_intents[spend_id] = materialized
        elif event_type == "OUTCOME":
            materialized = _validated_outcome_event_row(payload.get("row"))
            spend_id = str(materialized["spend_id"])
            if (
                spend_id != entity_id
                or spend_id not in expected_intents
                or spend_id in expected_outcomes
                or materialized["transitioned_at_us"] != occurred_at_us
            ):
                raise SpendIntegrityError("outcome integrity event is invalid")
            expected_outcomes[spend_id] = materialized
        elif event_type == "CONTROL":
            materialized = _validated_control_event_row(payload.get("row"))
            tenant_id = str(materialized["tenant_id"])
            expected_stop = control_generations.get(tenant_id, 0) + 1
            if (
                tenant_id != entity_id
                or materialized["stop_generation"] != expected_stop
                or materialized["changed_at_us"] != occurred_at_us
            ):
                raise SpendIntegrityError("control integrity event is invalid")
            control_generations[tenant_id] = expected_stop
            expected_controls.append(materialized)
        else:
            raise SpendIntegrityError("spend integrity event type is invalid")
        prior_hash = event_hash
        last_occurred = occurred_at_us
    if record.head_hash != prior_hash:
        raise SpendIntegrityError("spend metadata head does not match replayed events")
    actual_intents = _materialized_rows(
        connection,
        "spend_intents",
        _INTENT_COLUMNS,
        "spend_id",
    )
    actual_outcomes = _materialized_rows(
        connection,
        "spend_outcomes",
        _OUTCOME_COLUMNS,
        "spend_id",
    )
    actual_controls = _materialized_rows(
        connection,
        "spend_control_events",
        _CONTROL_COLUMNS,
        "tenant_id,stop_generation",
    )
    if actual_intents != [expected_intents[key] for key in sorted(expected_intents)]:
        raise SpendIntegrityError("spend intents do not equal integrity replay")
    if actual_outcomes != [expected_outcomes[key] for key in sorted(expected_outcomes)]:
        raise SpendIntegrityError("spend outcomes do not equal integrity replay")
    if actual_controls != sorted(
        expected_controls,
        key=lambda item: (
            _validate_spend_text(item["tenant_id"], "tenant_id"),
            _validate_nonnegative_integer(item["stop_generation"], "stop_generation"),
        ),
    ):
        raise SpendIntegrityError("spend controls do not equal integrity replay")
    return _VerifiedSpendState(last_occurred_at_us=last_occurred)


def _spend_event_hash(
    *,
    generation: int,
    event_id: str,
    event_type: str,
    entity_id: str,
    payload_digest: str,
    previous_hash: str,
    occurred_at_us: int,
) -> str:
    document = {
        "generation": generation,
        "event_id": event_id,
        "event_type": event_type,
        "entity_id": entity_id,
        "payload_digest": payload_digest,
        "previous_hash": previous_hash,
        "occurred_at_us": occurred_at_us,
    }
    return hashlib.sha256(_EVENT_HASH_DOMAIN + _canonical_json(document)).hexdigest()


def _materialized_rows(
    connection: sqlite3.Connection,
    table: str,
    columns: tuple[str, ...],
    order_by: str,
) -> list[dict[str, object]]:
    rows = connection.execute(
        f"SELECT {','.join(columns)} FROM {table} ORDER BY {order_by}"  # noqa: S608  # nosec B608
    ).fetchall()
    return [{name: _sqlite_scalar(row[name], name) for name in columns} for row in rows]


def _validated_intent_event_row(value: object) -> dict[str, object]:
    row = _event_row(value, _INTENT_COLUMNS, "intent")
    for name in ("spend_id",):
        row[name] = _validate_uuid(row[name], name)
    for name in ("tenant_id", "provider", "recipient"):
        row[name] = _validate_spend_text(row[name], name)
    row["currency"] = _validate_currency(row["currency"])
    row["amount_minor"] = _validate_positive_integer(row["amount_minor"], "amount_minor")
    for name in (
        "attempt_digest",
        "reference_digest",
        "argument_digest",
        "semantic_digest",
        "loop_fingerprint_digest",
        "receipt_digest",
        "policy_digest",
        "budget_rules_digest",
        "budget_snapshot_digest",
        "idempotency_digest",
    ):
        row[name] = _validate_digest(row[name], name)
    approval = row["approval_digest"]
    if approval is not None:
        row["approval_digest"] = _validate_digest(approval, "approval_digest")
    row["budget_snapshot_json"] = _validate_bounded_json_text(
        row["budget_snapshot_json"], "budget_snapshot_json", _MAX_SNAPSHOT_BYTES
    )
    row["state_generation"] = _validate_positive_integer(
        row["state_generation"], "state_generation"
    )
    row["stop_generation"] = _validate_nonnegative_integer(
        row["stop_generation"], "stop_generation"
    )
    row["reserved_at_us"] = _validate_nonnegative_integer(row["reserved_at_us"], "reserved_at_us")
    return row


def _validated_outcome_event_row(value: object) -> dict[str, object]:
    row = _event_row(value, _OUTCOME_COLUMNS, "outcome")
    spend_id = _validate_uuid(row["spend_id"], "spend_id")
    state_text = _validate_spend_text(row["state"], "state")
    try:
        state = SpendOutcomeState(state_text)
    except ValueError as exc:
        raise SpendIntegrityError("outcome state is invalid") from exc
    generation_placeholder = 1
    SpendOutcome(
        spend_id=spend_id,
        state=state,
        state_generation=generation_placeholder,
        transitioned_at_us=_validate_nonnegative_integer(
            row["transitioned_at_us"], "transitioned_at_us"
        ),
        result_digest=_optional_digest(row["result_digest"], "result_digest"),
        provider_reference_digest=_optional_digest(
            row["provider_reference_digest"], "provider_reference_digest"
        ),
        uncertainty_digest=_optional_digest(row["uncertainty_digest"], "uncertainty_digest"),
    )
    return row


def _validated_control_event_row(value: object) -> dict[str, object]:
    row = _event_row(value, _CONTROL_COLUMNS, "control")
    row["tenant_id"] = _validate_spend_text(row["tenant_id"], "tenant_id")
    row["stop_generation"] = _validate_positive_integer(row["stop_generation"], "stop_generation")
    enabled = row["enabled"]
    if type(enabled) is not int or enabled not in (0, 1):
        raise SpendIntegrityError("control enabled flag is invalid")
    row["authority_digest"] = _validate_digest(row["authority_digest"], "authority_digest")
    row["reason_digest"] = _validate_digest(row["reason_digest"], "reason_digest")
    row["changed_at_us"] = _validate_nonnegative_integer(row["changed_at_us"], "changed_at_us")
    return row


def _event_row(value: object, columns: tuple[str, ...], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != set(columns):
        raise SpendIntegrityError(f"spend {label} event row fields are incompatible")
    return {name: value[name] for name in columns}


def _budget_evaluation(
    connection: sqlite3.Connection,
    request: SpendReservationRequest,
    rules: SpendBudgetRules,
    base: SpendAnchorRecord,
    now_us: int,
    control: SpendControlState,
) -> _BudgetEvaluation:
    hour_start, day_start, month_start = _calendar_starts_us(now_us)
    hourly = _scope_amount(connection, request, hour_start)
    daily = _scope_amount(connection, request, day_start)
    monthly = _scope_amount(connection, request, month_start)
    vendor = _scope_amount(connection, request, month_start, recipient=request.recipient)
    vendor_limit = _vendor_limit(rules, request.recipient)
    rate_start = max(0, now_us - rules.rate_window_seconds * 1_000_000)
    loop_start = max(0, now_us - rules.loop_window_seconds * 1_000_000)
    rate_count = _scope_count(connection, request, rate_start)
    loop_count = _scope_count(
        connection,
        request,
        loop_start,
        recipient=request.recipient,
        loop_fingerprint=request.loop_fingerprint_digest,
    )
    anomaly_window_us = rules.anomaly_window_seconds * 1_000_000
    current_start = max(0, now_us - anomaly_window_us)
    previous_start = max(0, now_us - 2 * anomaly_window_us)
    current_amount = _scope_amount(connection, request, current_start)
    previous_amount = _scope_amount(
        connection,
        request,
        previous_start,
        end_exclusive=current_start,
    )
    anomaly_threshold = max(
        rules.anomaly_floor_minor,
        (previous_amount * rules.anomaly_growth_basis_points + 9_999) // 10_000,
    )
    metrics: dict[str, object] = {
        "single": {
            "projected_minor": request.amount_minor,
            "limit_minor": rules.single_limit_minor,
        },
        "hourly": {
            "used_minor": hourly,
            "projected_minor": hourly + request.amount_minor,
            "limit_minor": rules.hourly_limit_minor,
        },
        "daily": {
            "used_minor": daily,
            "projected_minor": daily + request.amount_minor,
            "limit_minor": rules.daily_limit_minor,
        },
        "monthly": {
            "used_minor": monthly,
            "projected_minor": monthly + request.amount_minor,
            "limit_minor": rules.monthly_limit_minor,
        },
        "vendor_monthly": {
            "used_minor": vendor,
            "projected_minor": vendor + request.amount_minor,
            "limit_minor": vendor_limit,
        },
        "rate": {
            "observed_count": rate_count,
            "projected_count": rate_count + 1,
            "limit_count": rules.rate_limit_count,
            "window_seconds": rules.rate_window_seconds,
        },
        "loop": {
            "observed_count": loop_count,
            "projected_count": loop_count + 1,
            "limit_count": rules.loop_limit_count,
            "window_seconds": rules.loop_window_seconds,
        },
        "anomaly": {
            "current_minor": current_amount,
            "projected_current_minor": current_amount + request.amount_minor,
            "previous_minor": previous_amount,
            "threshold_minor": anomaly_threshold,
            "window_seconds": rules.anomaly_window_seconds,
        },
    }
    document = {
        "schema": _SNAPSHOT_SCHEMA,
        "observed_at_us": now_us,
        "base_generation": base.generation,
        "reservation_generation": base.generation + 1,
        "stop_generation": control.stop_generation,
        "rules_digest": rules.digest,
        "metrics": metrics,
    }
    snapshot_json = _canonical_json(document).decode()
    snapshot = SpendBudgetSnapshot(
        observed_at_us=now_us,
        base_generation=base.generation,
        reservation_generation=base.generation + 1,
        stop_generation=control.stop_generation,
        rules_digest=rules.digest,
        snapshot_json=snapshot_json,
        snapshot_digest=hashlib.sha256(snapshot_json.encode()).hexdigest(),
    )
    return _BudgetEvaluation(
        snapshot=snapshot,
        hourly_projected=hourly + request.amount_minor,
        daily_projected=daily + request.amount_minor,
        monthly_projected=monthly + request.amount_minor,
        vendor_projected=vendor + request.amount_minor,
        vendor_limit=vendor_limit,
        rate_projected=rate_count + 1,
        loop_projected=loop_count + 1,
        anomaly_projected=current_amount + request.amount_minor,
        anomaly_threshold=anomaly_threshold,
    )


def _probe_request_digest(request: SpendReservationRequest) -> str:
    document = {
        "schema": "acgs.spend-budget-probe-request/v1",
        "tenant_id": request.tenant_id,
        "provider": request.provider,
        "recipient": request.recipient,
        "currency": request.currency,
        "amount_minor": request.amount_minor,
        "attempt_digest": request.attempt_digest,
        "reference_digest": request.reference_digest,
        "argument_digest": request.argument_digest,
        "semantic_digest": request.semantic_digest,
        "loop_fingerprint_digest": request.loop_fingerprint_digest,
        "policy_digest": request.policy_digest,
        "approval_digest": request.approval_digest,
        "idempotency_digest": request.idempotency_digest,
        "expected_stop_generation": request.expected_stop_generation,
    }
    return hashlib.sha256(_canonical_json(document)).hexdigest()


def _probe_digest(
    *,
    request_digest: str,
    rules_digest: str,
    base_generation: int,
    stop_generation: int,
) -> str:
    document = {
        "schema": "acgs.spend-budget-probe/v1",
        "request_digest": request_digest,
        "rules_digest": rules_digest,
        "base_generation": base_generation,
        "stop_generation": stop_generation,
    }
    return hashlib.sha256(_canonical_json(document)).hexdigest()


def _trusted_budget_rules(value: object) -> SpendBudgetRules:
    if type(value) is not SpendBudgetRules:
        raise SpendIntegrityError("rules must be SpendBudgetRules")
    cached_digest = value.digest
    currency = value.currency
    single_limit_minor = value.single_limit_minor
    hourly_limit_minor = value.hourly_limit_minor
    daily_limit_minor = value.daily_limit_minor
    monthly_limit_minor = value.monthly_limit_minor
    vendor_value = value.vendor_monthly_limits
    rate_window_seconds = value.rate_window_seconds
    rate_limit_count = value.rate_limit_count
    loop_window_seconds = value.loop_window_seconds
    loop_limit_count = value.loop_limit_count
    anomaly_window_seconds = value.anomaly_window_seconds
    anomaly_growth_basis_points = value.anomaly_growth_basis_points
    anomaly_floor_minor = value.anomaly_floor_minor
    if type(vendor_value) is not tuple:
        raise SpendIntegrityError("vendor_monthly_limits must be a canonical tuple")
    vendor_snapshot: list[tuple[str, int]] = []
    for item in vendor_value:
        if type(item) is not tuple or len(item) != 2:
            raise SpendIntegrityError("vendor_monthly_limits entries must be pairs")
        recipient = item[0]
        limit = item[1]
        if type(recipient) is not str or type(limit) is not int:
            raise SpendIntegrityError("vendor_monthly_limits entries use invalid primitive types")
        vendor_snapshot.append((recipient, limit))
    trusted = SpendBudgetRules(
        currency=currency,
        single_limit_minor=single_limit_minor,
        hourly_limit_minor=hourly_limit_minor,
        daily_limit_minor=daily_limit_minor,
        monthly_limit_minor=monthly_limit_minor,
        vendor_monthly_limits=tuple(vendor_snapshot),
        rate_window_seconds=rate_window_seconds,
        rate_limit_count=rate_limit_count,
        loop_window_seconds=loop_window_seconds,
        loop_limit_count=loop_limit_count,
        anomaly_window_seconds=anomaly_window_seconds,
        anomaly_growth_basis_points=anomaly_growth_basis_points,
        anomaly_floor_minor=anomaly_floor_minor,
    )
    if type(cached_digest) is not str or not hmac.compare_digest(cached_digest, trusted.digest):
        raise SpendIntegrityError("budget rules were mutated after digest computation")
    return trusted


def _budget_rejection(
    request: SpendReservationRequest,
    rules: SpendBudgetRules,
    evaluation: _BudgetEvaluation,
) -> str | None:
    if request.amount_minor > rules.single_limit_minor:
        return SPEND_SINGLE_LIMIT_EXCEEDED
    if evaluation.hourly_projected > rules.hourly_limit_minor:
        return SPEND_HOURLY_LIMIT_EXCEEDED
    if evaluation.daily_projected > rules.daily_limit_minor:
        return SPEND_DAILY_LIMIT_EXCEEDED
    if evaluation.monthly_projected > rules.monthly_limit_minor:
        return SPEND_MONTHLY_LIMIT_EXCEEDED
    if evaluation.vendor_limit is None:
        return SPEND_VENDOR_BUDGET_UNCONFIGURED
    if evaluation.vendor_projected > evaluation.vendor_limit:
        return SPEND_VENDOR_MONTHLY_LIMIT_EXCEEDED
    if evaluation.rate_projected > rules.rate_limit_count:
        return SPEND_RATE_LIMIT_EXCEEDED
    if evaluation.loop_projected > rules.loop_limit_count:
        return SPEND_LOOP_LIMIT_EXCEEDED
    if evaluation.anomaly_projected > evaluation.anomaly_threshold:
        return SPEND_ANOMALOUS_GROWTH
    return None


def _scope_amount(
    connection: sqlite3.Connection,
    request: SpendReservationRequest,
    start_us: int,
    *,
    recipient: str | None = None,
    end_exclusive: int | None = None,
) -> int:
    clauses = [
        "tenant_id=?",
        "provider=?",
        "currency=?",
        "reserved_at_us>=?",
    ]
    params: list[object] = [request.tenant_id, request.provider, request.currency, start_us]
    if recipient is not None:
        clauses.append("recipient=?")
        params.append(recipient)
    if end_exclusive is not None:
        clauses.append("reserved_at_us<?")
        params.append(end_exclusive)
    else:
        clauses.append("reserved_at_us<=?")
        params.append(_MAX_SQLITE_INTEGER)
    query = (
        "SELECT COALESCE(sum(amount_minor),0) FROM spend_intents WHERE "  # noqa: S608  # nosec B608
        + " AND ".join(clauses)
    )
    row = connection.execute(query, params).fetchone()
    return _single_nonnegative_int(row, "budget amount")


def _scope_count(
    connection: sqlite3.Connection,
    request: SpendReservationRequest,
    start_us: int,
    *,
    recipient: str | None = None,
    loop_fingerprint: str | None = None,
) -> int:
    clauses = [
        "tenant_id=?",
        "provider=?",
        "currency=?",
        "reserved_at_us>=?",
    ]
    params: list[object] = [request.tenant_id, request.provider, request.currency, start_us]
    if recipient is not None:
        clauses.append("recipient=?")
        params.append(recipient)
    if loop_fingerprint is not None:
        clauses.append("loop_fingerprint_digest=?")
        params.append(loop_fingerprint)
    query = (
        "SELECT count(*) FROM spend_intents WHERE "  # noqa: S608  # nosec B608
        + " AND ".join(clauses)
    )
    row = connection.execute(query, params).fetchone()
    return _single_nonnegative_int(row, "budget count")


def _calendar_starts_us(now_us: int) -> tuple[int, int, int]:
    current = datetime.fromtimestamp(now_us // 1_000_000, UTC).replace(
        microsecond=now_us % 1_000_000
    )
    hour = current.replace(minute=0, second=0, microsecond=0)
    day = current.replace(hour=0, minute=0, second=0, microsecond=0)
    month = day.replace(day=1)
    return (
        int(hour.timestamp()) * 1_000_000,
        int(day.timestamp()) * 1_000_000,
        int(month.timestamp()) * 1_000_000,
    )


def _vendor_limit(rules: SpendBudgetRules, recipient: str) -> int | None:
    for configured_recipient, limit in rules.vendor_monthly_limits:
        if configured_recipient == recipient:
            return limit
    return None


def _current_control(connection: sqlite3.Connection, tenant_id: str) -> SpendControlState:
    row = connection.execute(
        """SELECT tenant_id,stop_generation,enabled,authority_digest,reason_digest,changed_at_us
           FROM spend_control_events WHERE tenant_id=?
           ORDER BY stop_generation DESC LIMIT 1""",
        (tenant_id,),
    ).fetchone()
    if row is None:
        return SpendControlState(
            tenant_id=tenant_id,
            enabled=False,
            stop_generation=0,
            state_generation=0,
            changed_at_us=0,
            authority_digest=None,
            reason_digest=None,
        )
    changed_at_us = _row_int(row, "changed_at_us")
    event = connection.execute(
        """SELECT generation FROM spend_integrity_events
           WHERE event_type='CONTROL' AND entity_id=? AND occurred_at_us=?
           ORDER BY generation DESC LIMIT 1""",
        (tenant_id, changed_at_us),
    ).fetchone()
    if event is None:
        raise SpendIntegrityError("control state has no integrity event")
    enabled = _row_int(row, "enabled")
    if enabled not in (0, 1):
        raise SpendIntegrityError("control enabled flag is invalid")
    return SpendControlState(
        tenant_id=tenant_id,
        enabled=bool(enabled),
        stop_generation=_row_int(row, "stop_generation"),
        state_generation=_single_nonnegative_int(event, "control state generation"),
        changed_at_us=changed_at_us,
        authority_digest=_row_text(row, "authority_digest"),
        reason_digest=_row_text(row, "reason_digest"),
    )


def _intent_matches_request(
    row: sqlite3.Row,
    request: SpendReservationRequest,
    rules_digest: str,
) -> bool:
    return (
        _row_text(row, "attempt_digest") == request.attempt_digest
        and _row_text(row, "tenant_id") == request.tenant_id
        and _row_text(row, "provider") == request.provider
        and _row_text(row, "recipient") == request.recipient
        and _row_text(row, "currency") == request.currency
        and _row_int(row, "amount_minor") == request.amount_minor
        and _row_text(row, "reference_digest") == request.reference_digest
        and _row_text(row, "argument_digest") == request.argument_digest
        and _row_text(row, "semantic_digest") == request.semantic_digest
        and _row_text(row, "loop_fingerprint_digest") == request.loop_fingerprint_digest
        and _row_text(row, "receipt_digest") == request.receipt_digest
        and _row_text(row, "policy_digest") == request.policy_digest
        and row["approval_digest"] == request.approval_digest
        and _row_text(row, "budget_rules_digest") == rules_digest
        and _row_text(row, "idempotency_digest") == request.idempotency_digest
        and _row_int(row, "stop_generation") == request.expected_stop_generation
    )


def _reservation_from_row(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    replayed: bool,
) -> SpendReservation:
    spend_id = _row_text(row, "spend_id")
    snapshot = _snapshot_from_storage(
        _row_text(row, "budget_snapshot_json"),
        _row_text(row, "budget_snapshot_digest"),
    )
    outcome_row = connection.execute(
        "SELECT * FROM spend_outcomes WHERE spend_id=?", (spend_id,)
    ).fetchone()
    outcome = None if outcome_row is None else _outcome_from_row(connection, outcome_row)
    return SpendReservation(
        spend_id=spend_id,
        state=SpendOutcomeState.RESERVED if outcome is None else outcome.state,
        replayed=replayed,
        state_generation=_row_int(row, "state_generation")
        if outcome is None
        else outcome.state_generation,
        stop_generation=_row_int(row, "stop_generation"),
        budget_snapshot=snapshot,
        outcome=outcome,
    )


def _outcome_from_row(connection: sqlite3.Connection, row: sqlite3.Row) -> SpendOutcome:
    spend_id = _row_text(row, "spend_id")
    event = connection.execute(
        """SELECT generation FROM spend_integrity_events
           WHERE event_type='OUTCOME' AND entity_id=? ORDER BY generation DESC LIMIT 1""",
        (spend_id,),
    ).fetchone()
    if event is None:
        raise SpendIntegrityError("outcome has no integrity event")
    try:
        state = SpendOutcomeState(_row_text(row, "state"))
    except ValueError as exc:
        raise SpendIntegrityError("outcome state is invalid") from exc
    return SpendOutcome(
        spend_id=spend_id,
        state=state,
        state_generation=_single_nonnegative_int(event, "outcome state generation"),
        transitioned_at_us=_row_int(row, "transitioned_at_us"),
        result_digest=_row_optional_text(row, "result_digest"),
        provider_reference_digest=_row_optional_text(row, "provider_reference_digest"),
        uncertainty_digest=_row_optional_text(row, "uncertainty_digest"),
    )


def _snapshot_from_storage(snapshot_json: str, snapshot_digest: str) -> SpendBudgetSnapshot:
    document = _decode_canonical_document(
        snapshot_json,
        "budget snapshot",
        _MAX_SNAPSHOT_BYTES,
    )
    return SpendBudgetSnapshot(
        observed_at_us=_document_int(document, "observed_at_us"),
        base_generation=_document_int(document, "base_generation"),
        reservation_generation=_document_int(document, "reservation_generation"),
        stop_generation=_document_int(document, "stop_generation"),
        rules_digest=_document_text(document, "rules_digest"),
        snapshot_json=snapshot_json,
        snapshot_digest=snapshot_digest,
    )


def _decode_canonical_document(value: str, label: str, limit: int) -> dict[str, Any]:
    value = _validate_bounded_json_text(value, label, limit)
    try:
        document = json.loads(value, object_pairs_hook=_unique_object)
    except ValueError as exc:
        raise SpendIntegrityError(f"{label} is not strict JSON") from exc
    if not isinstance(document, dict) or _canonical_json(document).decode() != value:
        raise SpendIntegrityError(f"{label} is not canonical JSON")
    return document


def _validate_bounded_json_text(value: object, label: str, limit: int) -> str:
    if type(value) is not str:
        raise SpendIntegrityError(f"{label} must be text")
    try:
        encoded = value.encode()
    except UnicodeEncodeError as exc:
        raise SpendIntegrityError(f"{label} must be valid UTF-8") from exc
    if not encoded or len(encoded) > limit:
        raise SpendIntegrityError(f"{label} exceeds its bound")
    return value


def _validate_spend_text(value: object, name: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise SpendIntegrityError(f"{name} must be bounded non-empty text")
    try:
        encoded = value.encode()
    except UnicodeEncodeError as exc:
        raise SpendIntegrityError(f"{name} must be valid UTF-8") from exc
    if len(encoded) > _MAX_TEXT_BYTES:
        raise SpendIntegrityError(f"{name} exceeds its bound")
    return value


def _validate_currency(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 3
        or not value.isascii()
        or not value.isalpha()
        or value != value.upper()
    ):
        raise SpendIntegrityError("currency must be three uppercase ASCII letters")
    return value


def _validate_positive_integer(value: object, name: str) -> int:
    if type(value) is not int or value <= 0 or value > _MAX_SQLITE_INTEGER:
        raise SpendIntegrityError(f"{name} must be a bounded positive integer")
    return value


def _validate_nonnegative_integer(value: object, name: str) -> int:
    if type(value) is not int or value < 0 or value > _MAX_SQLITE_INTEGER:
        raise SpendIntegrityError(f"{name} must be a bounded non-negative integer")
    return value


def _validate_window_seconds(value: object, name: str) -> int:
    value = _validate_positive_integer(value, name)
    if value > _MAX_WINDOW_SECONDS:
        raise SpendIntegrityError(f"{name} exceeds its bound")
    return value


def _validate_uuid(value: object, name: str) -> str:
    if type(value) is not str:
        raise SpendIntegrityError(f"{name} must be canonical UUID text")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise SpendIntegrityError(f"{name} must be canonical UUID text") from exc
    if str(parsed) != value:
        raise SpendIntegrityError(f"{name} must be canonical UUID text")
    return value


def _optional_digest(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _validate_digest(value, name)


def _single_nonnegative_int(row: object, name: str) -> int:
    return _validate_nonnegative_integer(_single_int(row, name), name)


def _sqlite_scalar(value: object, name: str) -> object:
    if value is None or type(value) in (str, int):
        return value
    raise SpendIntegrityError(f"SQLite {name} has an unsupported value type")


def _row_optional_text(row: sqlite3.Row, name: str) -> str | None:
    value = row[name]
    if value is None:
        return None
    if type(value) is not str:
        raise SpendIntegrityError(f"SQLite {name} must be text or NULL")
    return value


def _document_int(document: dict[str, Any], name: str) -> int:
    return _validate_nonnegative_integer(document.get(name), name)


def _document_text(document: dict[str, Any], name: str) -> str:
    value = document.get(name)
    if type(value) is not str:
        raise SpendIntegrityError(f"budget snapshot {name} must be text")
    return value


def _open_directory_components(path: Path, owner_uid: int) -> int:
    root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    opened = [root]

    def close_opened(index: int) -> None:
        fd = opened[index]
        if fd < 0:
            return
        opened[index] = -1
        os.close(fd)

    try:
        parts = path.parts[1:]
        if not parts:
            raise SpendPathSecurityError("filesystem root cannot be a secure parent")
        for index, component in enumerate(parts):
            try:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=opened[-1],
                )
            except OSError as exc:
                raise SpendPathSecurityError(
                    "secure directory component could not be opened"
                ) from exc
            opened.append(next_fd)
            if index == len(parts) - 1:
                _require_secure_directory_stat(os.fstat(next_fd), owner_uid)
        final = opened[-1]
        _cleanup_owned(
            tuple(
                ("directory traversal fd", partial(close_opened, index))
                for index in range(len(opened) - 1)
            ),
            primary=None,
            error_type=SpendPathSecurityError,
        )
        return final
    except BaseException as exc:
        _cleanup_owned(
            tuple(
                ("directory traversal fd", partial(close_opened, index))
                for index in range(len(opened))
            ),
            primary=exc,
            error_type=SpendPathSecurityError,
        )
        raise


def _require_secure_directory_stat(value: os.stat_result, owner_uid: int) -> None:
    if not stat.S_ISDIR(value.st_mode):
        raise SpendPathSecurityError("secure parent must be a directory")
    if value.st_uid != owner_uid:
        raise SpendPathSecurityError("secure parent must be owned by the effective user")
    if stat.S_IMODE(value.st_mode) != 0o700:
        raise SpendPathSecurityError("secure parent permissions must be exactly 0700")


def _require_secure_file_stat(value: os.stat_result, owner_uid: int, label: str) -> None:
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
        raise SpendPathSecurityError(f"{label} must be a regular single-link file")
    if value.st_uid != owner_uid:
        raise SpendPathSecurityError(f"{label} must be owned by the effective user")
    if stat.S_IMODE(value.st_mode) != 0o600:
        raise SpendPathSecurityError(f"{label} permissions must be exactly 0600")


def _create_secure_file(directory: _SecureDirectory, name: str) -> tuple[int, tuple[int, int]]:
    directory.revalidate()
    try:
        fd = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | _OPEN_BASE,
            0o600,
            dir_fd=directory.fd,
        )
    except OSError as exc:
        raise SpendPathSecurityError(f"secure file {name!r} could not be created") from exc
    created_identity: tuple[int, int] | None = None
    try:
        created_identity = _identity(os.fstat(fd))
        os.fchmod(fd, 0o600)
        _require_secure_file_stat(os.fstat(fd), directory.owner_uid, name)
        _revalidate_name_to_fd(directory, name, fd)
        return fd, created_identity
    except BaseException as exc:
        primary: BaseException
        if isinstance(exc, OSError):
            primary = SpendPathSecurityError(f"secure file {name!r} setup failed")
        else:
            primary = exc
        cleanup_actions: list[tuple[str, Callable[[], None]]] = [
            ("secure create fd", lambda: os.close(fd))
        ]
        if created_identity is not None:
            cleanup_actions.append(
                (
                    "secure create unlink",
                    lambda: _unlink_name_if_identity(directory, name, created_identity),
                )
            )
        _cleanup_owned(
            cleanup_actions,
            primary=primary,
            error_type=SpendPathSecurityError,
        )
        if primary is exc:
            raise
        raise primary from exc


def _open_or_create_secure_file(directory: _SecureDirectory, name: str) -> int:
    if _stat_name(directory, name) is None:
        fd, _ = _create_secure_file(directory, name)
        return fd
    return _open_secure_existing_file(directory, name)


def _open_secure_existing_file(directory: _SecureDirectory, name: str) -> int:
    directory.revalidate()
    try:
        fd = os.open(name, os.O_RDWR | _OPEN_BASE, dir_fd=directory.fd)
    except OSError as exc:
        raise SpendPathSecurityError(f"secure file {name!r} could not be opened") from exc
    try:
        _require_secure_file_stat(os.fstat(fd), directory.owner_uid, name)
        _revalidate_name_to_fd(directory, name, fd)
        return fd
    except BaseException as exc:
        _cleanup_owned(
            (("secure open fd", lambda: os.close(fd)),),
            primary=exc,
            error_type=SpendPathSecurityError,
        )
        raise


def _stat_name(directory: _SecureDirectory, name: str) -> os.stat_result | None:
    directory.revalidate()
    try:
        return os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SpendPathSecurityError(f"secure file {name!r} could not be inspected") from exc


def _revalidate_name_to_fd(directory: _SecureDirectory, name: str, fd: int) -> None:
    value = os.fstat(fd)
    _require_secure_file_stat(value, directory.owner_uid, name)
    current = _stat_name(directory, name)
    if current is None or _identity(current) != _identity(value):
        raise SpendPathSecurityError(f"secure file {name!r} pathname identity changed")


def _revalidate_optional_identity(
    directory: _SecureDirectory,
    name: str,
    expected: os.stat_result | None,
) -> None:
    current = _stat_name(directory, name)
    if (current is None) != (expected is None):
        raise SpendPathSecurityError(f"secure file {name!r} existence changed")
    if current is not None and expected is not None and _identity(current) != _identity(expected):
        raise SpendPathSecurityError(f"secure file {name!r} identity changed")


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _unlink_name_if_identity(
    directory: _SecureDirectory,
    name: str,
    expected: tuple[int, int],
) -> None:
    try:
        current = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if _identity(current) != expected:
        return
    os.unlink(name, dir_fd=directory.fd)
    os.fsync(directory.fd)


def _cleanup_owned(
    actions: Iterator[tuple[str, Callable[[], None]]]
    | list[tuple[str, Callable[[], None]]]
    | tuple[tuple[str, Callable[[], None]], ...],
    *,
    primary: BaseException | None,
    error_type: type[SpendStoreError],
) -> None:
    active = primary if primary is not None else sys.exception()
    cleanup_error: SpendStoreError | None = None
    cleanup_cause: BaseException | None = None
    for label, action in actions:
        try:
            action()
        except BaseException as failure:
            note = f"{label} cleanup failed ({type(failure).__name__})"[:160]
            if active is not None:
                active.add_note(note)
                continue
            if cleanup_error is None:
                cleanup_error = error_type(f"{label} cleanup failed")
                cleanup_cause = failure
            else:
                cleanup_error.add_note(note)
    if cleanup_error is not None:
        raise cleanup_error from cleanup_cause


def _validated_absolute_path(value: str | Path, label: str) -> Path:
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise SpendPathSecurityError(f"{label} path is invalid") from exc
    if not isinstance(raw, str) or not raw or "\x00" in raw or not os.path.isabs(raw):
        raise SpendPathSecurityError(f"{label} path must be absolute")
    if os.path.normpath(raw) != raw or any(part in {".", ".."} for part in raw.split("/")):
        raise SpendPathSecurityError(
            f"{label} path must be lexically normalized without dot segments"
        )
    return Path(raw)


def _clock_us(clock: SpendClock) -> int:
    try:
        current = clock.now()
    except Exception as exc:
        raise SpendStoreError("spend clock failed") from exc
    if not isinstance(current, datetime) or current.tzinfo is None:
        raise SpendStoreError("spend clock must return an aware UTC datetime")
    if current.utcoffset() != timedelta(0):
        raise SpendStoreError("spend clock must return UTC")
    current = current.astimezone(UTC)
    if current < datetime(1970, 1, 1, tzinfo=UTC):
        raise SpendStoreError("spend clock cannot precede the Unix epoch")
    return int(current.timestamp() * 1_000_000)


def _validate_hmac_key(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) < 32:
        raise SpendIntegrityError("anchor hmac_key must contain at least 32 bytes")
    return bytes(value)


def _validate_key_id(value: str) -> str:
    if not isinstance(value, str) or _KEY_ID_RE.fullmatch(value) is None:
        raise SpendAnchorKeyMismatch("key_id is invalid")
    return value


def _validate_namespace(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or "\x00" in value:
        raise SpendIntegrityError("anchor namespace must be bounded non-empty text")
    try:
        value.encode()
    except UnicodeEncodeError as exc:
        raise SpendIntegrityError("anchor namespace must be valid UTF-8") from exc
    return value


def _validate_store_id(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError) as exc:
        raise SpendIntegrityError("store_id must be a UUID") from exc
    if str(parsed) != value:
        raise SpendIntegrityError("store_id must use canonical UUID text")
    return value


def _validate_count(value: int, name: str) -> int:
    if type(value) is not int or value < 0:
        raise SpendIntegrityError(f"{name} must be a non-negative integer")
    return value


def _validate_digest(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise SpendIntegrityError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _record_dict(record: SpendAnchorRecord) -> dict[str, object]:
    return {
        "schema": _ANCHOR_RECORD_SCHEMA,
        "key_id": record.key_id,
        "namespace": record.namespace,
        "store_id": record.store_id,
        "generation": record.generation,
        "event_count": record.event_count,
        "head_hash": record.head_hash,
    }


def _record_from_dict(value: dict[str, Any]) -> SpendAnchorRecord:
    if value.get("schema") != _ANCHOR_RECORD_SCHEMA:
        raise SpendIntegrityError("anchor record schema is incompatible")
    return SpendAnchorRecord(
        key_id=_required_text(value.get("key_id"), "record key_id"),
        namespace=_required_text(value.get("namespace"), "namespace"),
        store_id=_required_text(value.get("store_id"), "store_id"),
        generation=_required_int(value.get("generation"), "generation"),
        event_count=_required_int(value.get("event_count"), "event_count"),
        head_hash=_required_text(value.get("head_hash"), "head_hash"),
    )


def _required_text(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise SpendIntegrityError(f"anchor {name} must be text")
    return value


def _required_int(value: object, name: str) -> int:
    if type(value) is not int:
        raise SpendIntegrityError(f"anchor {name} must be an integer")
    return value


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise SpendIntegrityError("anchor canonicalization failed") from exc


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read_bounded(fd: int, limit: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    value = os.read(fd, limit + 1)
    if len(value) > limit:
        raise SpendIntegrityError("anchor exceeds its size limit")
    return value


def _write_all(fd: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        written = os.write(fd, value[offset:])
        if written <= 0:
            raise OSError("short anchor write")
        offset += written


def _call_hook(hook: _SecurityHook | None, checkpoint: str) -> None:
    if hook is not None:
        hook(checkpoint)


def _normalize_ddl(value: str) -> str:
    return " ".join(value.strip().rstrip(";").split())


def _single_int(row: object, name: str) -> int:
    try:
        value = row[0]  # type: ignore[index]
    except (IndexError, KeyError, TypeError) as exc:
        raise SpendStoreError(f"invalid SQLite {name} response") from exc
    if type(value) is not int:
        raise SpendStoreError(f"invalid SQLite {name} response")
    return value


def _row_text(row: sqlite3.Row, name: str) -> str:
    value = row[name]
    if not isinstance(value, str):
        raise SpendIntegrityError(f"SQLite {name} must be text")
    return value


def _row_int(row: sqlite3.Row, name: str) -> int:
    value = row[name]
    if type(value) is not int:
        raise SpendIntegrityError(f"SQLite {name} must be an integer")
    return value
