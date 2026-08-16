"""Durable, fail-closed single-use receipt consumption.

The store persists only receipt identifiers, caller-verified receipt, binding,
and idempotency digests, plus tenant-bound HMAC-SHA-256 nonce digests. It never
stores raw nonces, raw idempotency keys, HMAC keys, receipt bodies, arguments,
evidence, or credentials.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import math
import os
import sqlite3
import stat
from _thread import RLock
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from threading import Lock
from typing import Protocol, TypeGuard, TypeVar, runtime_checkable

from gove_zone.path_capability import (
    AttestedDirectory,
    is_proc_fd_path,
    require_attested_directory,
)

_SCHEMA_VERSION = 4
_EXPECTED_TABLES = {
    "consumption_metadata",
    "receipt_consumptions",
    "receipt_revocations",
}
_KEY_FINGERPRINT_NAME = "hmac_key_fingerprint"
_STORE_ID_NAME = "store_id"
_GENERATION_NAME = "generation"
_CHAIN_HEAD_NAME = "chain_head"
_STATE_ROOT_NAME = "state_root"
_ANCHOR_NAMESPACE_NAME = "anchor_namespace"
_EXPECTED_METADATA_KEYS = {
    _KEY_FINGERPRINT_NAME,
    _STORE_ID_NAME,
    _GENERATION_NAME,
    _CHAIN_HEAD_NAME,
    _STATE_ROOT_NAME,
    _ANCHOR_NAMESPACE_NAME,
}
_KEY_FINGERPRINT_DOMAIN = b"gove-zone:receipt-consumption:key:v1\x00"
_TENANT_KEY_DOMAIN = b"gove-zone:receipt-consumption:tenant-key:v1\x00"
_NONCE_DOMAIN = b"gove-zone:receipt-consumption:tenant-nonce:v1\x00"
_CHAIN_INITIAL_DOMAIN = b"gove-zone:receipt-consumption:chain-initial:v1\x00"
_CHAIN_NEXT_DOMAIN = b"gove-zone:receipt-consumption:chain-next:v1\x00"
_STATE_ROOT_DOMAIN = b"gove-zone:receipt-consumption:state-root:v1\x00"
_STATE_ROOT_SENTINEL = "<self-authenticated-state-root>"
_EXPECTED_AUTO_INDEXES = {
    "sqlite_autoindex_consumption_metadata_1",
    "sqlite_autoindex_receipt_consumptions_1",
    "sqlite_autoindex_receipt_consumptions_2",
    "sqlite_autoindex_receipt_consumptions_3",
    "sqlite_autoindex_receipt_revocations_1",
}
_OPERATION_LOCKS_GUARD = Lock()
_OPERATION_LOCKS: dict[object, RLock] = {}


class ConsumptionState(StrEnum):
    """Persistent consumption outcome, plus the pre-use revocation projection."""

    RESERVED = "RESERVED"
    SUCCEEDED = "SUCCEEDED"
    UNKNOWN = "UNKNOWN"
    REVOKED = "REVOKED"


@dataclass(frozen=True, slots=True)
class ConsumptionRecord:
    """Immutable view of a receipt's consumption and revocation state."""

    tenant_id: str
    receipt_id: str
    state: ConsumptionState
    nonce_hash: str | None
    receipt_hash: str | None
    binding_hash: str | None
    idempotency_digest: str | None
    attempt_id: str | None
    reserved_at: str | None
    updated_at: str
    revoked_at: str | None
    recovery_authority: str | None
    recovery_reason_code: str | None
    recovery_evidence_digest: str | None


class ReceiptConsumptionError(RuntimeError):
    """Base class for fail-closed receipt consumption failures."""


class ReceiptReplayError(ReceiptConsumptionError):
    """Raised when a receipt, nonce, or idempotency digest was reserved."""


class ReceiptRevokedError(ReceiptConsumptionError):
    """Raised when reservation is attempted for a revoked receipt."""


class ConsumptionTransitionError(ReceiptConsumptionError):
    """Raised for an illegal state transition or an attempt-owner mismatch."""


class ConsumptionStoreError(ReceiptConsumptionError):
    """Raised when durable consumption state cannot be safely accessed."""


_T = TypeVar("_T")


@dataclass(frozen=True, slots=True)
class AnchoredConsumptionState:
    """Exact externally anchored state for one stable deployment namespace."""

    store_id: str
    generation: int
    chain_head: str
    state_root: str


@runtime_checkable
class ConsumptionStateAnchor(Protocol):
    """Trusted external monotonic state used to detect database rollback.

    Implementations must durably reject rollback of their own state. SQLite and
    this external interface cannot commit atomically: a crash or anchor failure
    after the database commit deliberately leaves the store fail-stopped rather
    than pretending the mutation did not happen.
    """

    def read(self, namespace: str) -> AnchoredConsumptionState | None: ...

    def compare_and_swap(
        self,
        namespace: str,
        expected: AnchoredConsumptionState | None,
        replacement: AnchoredConsumptionState,
    ) -> bool: ...


class ReceiptConsumptionStore:
    """SQLite-backed single-use receipt, nonce, and idempotency store.

    Each operation uses its own connection and an immediate transaction.
    reserve commits its durable reservation before returning, so callers
    must not invoke a side effect until it returns successfully.

    The constructor rejects symlinks and records the database device/inode.
    Each later transaction rechecks both. These checks narrow path-replacement
    risk but cannot eliminate filesystem TOCTOU without opening SQLite through
    a caller-controlled, platform-specific file descriptor.
    """

    _CONSUMPTION_SELECT = """
        SELECT
            c.tenant_id,
            c.receipt_id,
            c.nonce_hash,
            c.receipt_hash,
            c.binding_hash,
            c.idempotency_digest,
            c.attempt_id,
            c.state,
            c.reserved_at,
            c.updated_at,
            c.recovery_authority,
            c.recovery_reason_code,
            c.recovery_evidence_digest,
            r.revoked_at
        FROM receipt_consumptions AS c
        LEFT JOIN receipt_revocations AS r
          ON r.tenant_id = c.tenant_id
         AND r.receipt_id = c.receipt_id
        WHERE c.tenant_id = ? AND c.receipt_id = ?
    """

    def __init__(
        self,
        path: str | Path,
        *,
        hmac_key: bytes,
        timeout: float = 30.0,
        timeout_seconds: float | None = None,
        state_anchor: ConsumptionStateAnchor | None = None,
        anchor_namespace: str | None = None,
        require_trusted_anchor: bool = False,
        _attested_directory: AttestedDirectory | None = None,
        _attested_relative: str | None = None,
    ) -> None:
        if require_trusted_anchor and state_anchor is None:
            raise ConsumptionStoreError("trusted state anchor is required but was not configured")
        if timeout_seconds is not None:
            if timeout != 30.0:
                raise ConsumptionStoreError("timeout and timeout_seconds cannot both be configured")
            timeout = timeout_seconds
        self.path = _absolute_path(path)
        self._attested_directory = _attested_directory
        self._attested_relative = _attested_relative
        if _attested_directory is None:
            if _is_proc_descriptor_alias(self.path):
                raise ConsumptionStoreError("direct procfs descriptor paths are not accepted")
            operation_lock_key: object = self.path
        else:
            require_attested_directory(
                _attested_directory,
                error_type=ConsumptionStoreError,
            )
            _attested_directory.checkpoint()
            if _attested_relative is None:
                raise ConsumptionStoreError("attested consumption path is required")
            _attested_directory.sqlite_path(_attested_relative)
            operation_lock_key = (_attested_directory.identity, _attested_relative)
        if state_anchor is not None and anchor_namespace is None:
            raise ConsumptionStoreError(
                "stable anchor_namespace is required with a trusted state anchor"
            )
        if anchor_namespace is None:
            path_digest = hashlib.sha256(str(self.path).encode("utf-8")).hexdigest()
            anchor_namespace = f"local:{path_digest}"
        self._anchor_namespace = _validated_text(
            anchor_namespace,
            "anchor_namespace",
        )
        self._hmac_key = _validated_hmac_key(hmac_key)
        self._key_fingerprint = hashlib.sha256(_KEY_FINGERPRINT_DOMAIN + self._hmac_key).hexdigest()
        self._timeout = _validated_timeout(timeout)
        self._state_anchor = state_anchor
        self._require_trusted_anchor = require_trusted_anchor
        self._database_identity: tuple[int, int] | None = None
        self._created_schema = False
        self._poisoned = False
        self._operation_lock = _operation_lock_for(operation_lock_key)

        self._verify_storage_path(allow_missing_database=True)
        self._run_immediate(self._initialize_schema, initialize=True)
        self._database_identity = self._read_database_identity()

    @classmethod
    def from_attested(
        cls,
        directory: AttestedDirectory,
        relative: str,
        *,
        hmac_key: bytes,
        anchor_namespace: str,
        timeout: float = 30.0,
        timeout_seconds: float | None = None,
        state_anchor: ConsumptionStateAnchor | None = None,
        require_trusted_anchor: bool = False,
    ) -> ReceiptConsumptionStore:
        """Borrow *directory* and open one capability-derived SQLite basename."""
        require_attested_directory(directory, error_type=ConsumptionStoreError)
        directory.checkpoint()
        directory.sqlite_path(relative)
        return cls(
            directory.display_path / relative,
            hmac_key=hmac_key,
            timeout=timeout,
            timeout_seconds=timeout_seconds,
            state_anchor=state_anchor,
            anchor_namespace=anchor_namespace,
            require_trusted_anchor=require_trusted_anchor,
            _attested_directory=directory,
            _attested_relative=relative,
        )

    def _sqlite_path(self) -> Path:
        directory = self._attested_directory
        relative = self._attested_relative
        if directory is None or relative is None:
            return self.path
        require_attested_directory(directory, error_type=ConsumptionStoreError)
        directory.checkpoint()
        return directory.sqlite_path(relative)

    @property
    def integrity_scope(self) -> str:
        """Describe the verified integrity boundary without overstating it."""
        if self._state_anchor is not None:
            return "trusted-anchor-rollback-resistant"
        return "local-keyed-tamper-evidence-no-snapshot-rollback-resistance"

    @property
    def trusted_anchor_required(self) -> bool:
        """Whether construction required an external monotonic state anchor."""
        return self._require_trusted_anchor

    @property
    def strict_integrity_ready(self) -> bool:
        """Return true only after current DB bytes match the external anchor.

        An unanchored store returns false. Anchor unavailability, database
        rollback, or any local/remote divergence raises instead of degrading to
        local keyed evidence, so a strict runtime can fail closed by requiring
        this property immediately before use.
        """
        if self._state_anchor is None:
            return False
        return self._run_immediate(lambda _connection: True)

    def reserve(
        self,
        tenant_id: str,
        receipt_id: str,
        nonce: str,
        receipt_hash: str,
        binding_hash: str,
        attempt_id: str,
        *,
        idempotency_digest: str,
    ) -> ConsumptionRecord:
        """Durably reserve one receipt, nonce, and idempotency binding.

        ``idempotency_digest`` must already be a verified, tenant-bound digest;
        raw idempotency keys are never accepted or stored. Duplicate receipt
        identifiers, tenant-bound nonces, and tenant-bound idempotency digests
        all fail closed. Raw nonce material is HMACed before any database
        operation.
        """
        tenant_id = _validated_text(tenant_id, "tenant_id")
        receipt_id = _validated_text(receipt_id, "receipt_id")
        receipt_hash = _validated_sha256(receipt_hash, "receipt_hash")
        binding_hash = _validated_sha256(binding_hash, "binding_hash")
        idempotency_digest = _validated_sha256(
            idempotency_digest,
            "idempotency_digest",
        )
        attempt_id = _validated_text(attempt_id, "attempt_id")
        nonce_hash = self._nonce_hash(tenant_id, nonce)
        timestamp = _utc_timestamp()

        def operation(connection: sqlite3.Connection) -> ConsumptionRecord:
            revoked = connection.execute(
                """
                SELECT revoked_at
                FROM receipt_revocations
                WHERE tenant_id = ? AND receipt_id = ?
                """,
                (tenant_id, receipt_id),
            ).fetchone()
            if revoked is not None:
                raise ReceiptRevokedError("receipt is revoked")

            try:
                connection.execute(
                    """
                    INSERT INTO receipt_consumptions (
                        tenant_id,
                        receipt_id,
                        nonce_hash,
                        receipt_hash,
                        binding_hash,
                        idempotency_digest,
                        attempt_id,
                        state,
                        reserved_at,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        tenant_id,
                        receipt_id,
                        nonce_hash,
                        receipt_hash,
                        binding_hash,
                        idempotency_digest,
                        attempt_id,
                        ConsumptionState.RESERVED.value,
                        timestamp,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                existing_receipt = connection.execute(
                    """
                    SELECT 1
                    FROM receipt_consumptions
                    WHERE tenant_id = ? AND receipt_id = ?
                    """,
                    (tenant_id, receipt_id),
                ).fetchone()
                if existing_receipt is not None:
                    raise ReceiptReplayError("receipt was already reserved") from exc

                existing_nonce = connection.execute(
                    """
                    SELECT 1
                    FROM receipt_consumptions
                    WHERE tenant_id = ? AND nonce_hash = ?
                    """,
                    (tenant_id, nonce_hash),
                ).fetchone()
                if existing_nonce is not None:
                    raise ReceiptReplayError("nonce was already reserved") from exc

                existing_idempotency = connection.execute(
                    """
                    SELECT 1
                    FROM receipt_consumptions
                    WHERE tenant_id = ? AND idempotency_digest = ?
                    """,
                    (tenant_id, idempotency_digest),
                ).fetchone()
                if existing_idempotency is not None:
                    raise ReceiptReplayError("idempotency digest was already reserved") from exc
                raise

            record = self._load_status(connection, tenant_id, receipt_id)
            if record is None:
                raise ConsumptionStoreError("reservation was not readable before commit")
            return record

        return self._run_immediate(
            operation,
            mutation=(
                "reserve",
                tenant_id,
                receipt_id,
                nonce_hash,
                receipt_hash,
                binding_hash,
                idempotency_digest,
                attempt_id,
            ),
        )

    def mark_succeeded(
        self,
        tenant_id: str,
        receipt_id: str,
        attempt_id: str,
    ) -> ConsumptionRecord:
        """Record a successful outcome for the matching reserved attempt."""
        return self._transition(
            tenant_id,
            receipt_id,
            attempt_id,
            ConsumptionState.SUCCEEDED,
        )

    def mark_unknown(
        self,
        tenant_id: str,
        receipt_id: str,
        attempt_id: str,
    ) -> ConsumptionRecord:
        """Record an indeterminate outcome for the matching reserved attempt."""
        return self._transition(
            tenant_id,
            receipt_id,
            attempt_id,
            ConsumptionState.UNKNOWN,
        )

    def recover_unknown(
        self,
        tenant_id: str,
        receipt_id: str,
        attempt_id: str,
        *,
        recovery_authority: str,
        reason_code: str,
        evidence_digest: str,
    ) -> ConsumptionRecord:
        """Resolve an abandoned matching reservation to UNKNOWN.

        The caller must externally prove that the attempt owner is dead before
        calling this method. The store deliberately provides no timeout-based
        recovery because elapsed time cannot prove that a side effect did not
        run or cannot still complete.
        """
        authority = _validated_text(recovery_authority, "recovery_authority")
        reason = _validated_text(reason_code, "reason_code")
        digest = _validated_sha256(evidence_digest, "evidence_digest")
        return self._transition(
            tenant_id,
            receipt_id,
            attempt_id,
            ConsumptionState.UNKNOWN,
            recovery=(authority, reason, digest),
        )

    def status(
        self,
        tenant_id: str,
        receipt_id: str,
    ) -> ConsumptionRecord | None:
        """Return truthful outcome state with any separate revocation timestamp."""
        return self._run_immediate(
            lambda connection: self._load_status(connection, tenant_id, receipt_id)
        )

    def revoke(self, tenant_id: str, receipt_id: str) -> ConsumptionRecord:
        """Idempotently revoke a receipt without rewriting consumption outcome.

        A pre-use revocation is returned as a REVOKED projection. If an
        attempt is already reserved or terminal, its state remains truthful and
        revoked_at carries the independently persisted revocation.
        """
        tenant_id = _validated_text(tenant_id, "tenant_id")
        receipt_id = _validated_text(receipt_id, "receipt_id")
        timestamp = _utc_timestamp()

        def operation(connection: sqlite3.Connection) -> ConsumptionRecord:
            connection.execute(
                """
                INSERT OR IGNORE INTO receipt_revocations (
                    tenant_id, receipt_id, revoked_at
                ) VALUES (?, ?, ?)
                """,
                (tenant_id, receipt_id, timestamp),
            )
            record = self._load_status(connection, tenant_id, receipt_id)
            if record is None:
                raise ConsumptionStoreError("revocation was not readable before commit")
            return record

        return self._run_immediate(
            operation,
            mutation=("revoke", tenant_id, receipt_id, timestamp),
        )

    def is_revoked(self, tenant_id: str, receipt_id: str) -> bool:
        """Return the final-gate revocation decision for a receipt."""

        def operation(connection: sqlite3.Connection) -> bool:
            row = connection.execute(
                """
                SELECT 1
                FROM receipt_revocations
                WHERE tenant_id = ? AND receipt_id = ?
                """,
                (tenant_id, receipt_id),
            ).fetchone()
            return row is not None

        return self._run_immediate(operation)

    def _transition(
        self,
        tenant_id: str,
        receipt_id: str,
        attempt_id: str,
        target: ConsumptionState,
        recovery: tuple[str, str, str] | None = None,
    ) -> ConsumptionRecord:
        tenant_id = _validated_text(tenant_id, "tenant_id")
        receipt_id = _validated_text(receipt_id, "receipt_id")
        attempt_id = _validated_text(attempt_id, "attempt_id")
        timestamp = _utc_timestamp()
        recovery_authority, recovery_reason, recovery_digest = recovery or (
            None,
            None,
            None,
        )

        def operation(connection: sqlite3.Connection) -> ConsumptionRecord:
            current = self._load_status(connection, tenant_id, receipt_id)
            if current is None or current.state is ConsumptionState.REVOKED:
                raise ConsumptionTransitionError("receipt has no reserved attempt")
            if current.attempt_id != attempt_id:
                raise ConsumptionTransitionError("attempt does not own reservation")
            if current.state is not ConsumptionState.RESERVED:
                raise ConsumptionTransitionError(
                    f"cannot transition terminal state {current.state.value}"
                )

            cursor = connection.execute(
                """
                UPDATE receipt_consumptions
                SET state = ?,
                    updated_at = ?,
                    recovery_authority = ?,
                    recovery_reason_code = ?,
                    recovery_evidence_digest = ?
                WHERE tenant_id = ?
                  AND receipt_id = ?
                  AND attempt_id = ?
                  AND state = ?
                """,
                (
                    target.value,
                    timestamp,
                    recovery_authority,
                    recovery_reason,
                    recovery_digest,
                    tenant_id,
                    receipt_id,
                    attempt_id,
                    ConsumptionState.RESERVED.value,
                ),
            )
            if cursor.rowcount != 1:
                raise ConsumptionTransitionError("reservation transition was rejected")

            updated = self._load_status(connection, tenant_id, receipt_id)
            if updated is None:
                raise ConsumptionStoreError("transition was not readable before commit")
            return updated

        mutation = (
            "transition",
            tenant_id,
            receipt_id,
            attempt_id,
            target.value,
            recovery_authority or "",
            recovery_reason or "",
            recovery_digest or "",
        )
        return self._run_immediate(operation, mutation=mutation)

    def _nonce_hash(self, tenant_id: str, nonce: str) -> str:
        tenant_id = _validated_text(tenant_id, "tenant_id")
        nonce = _validated_text(nonce, "nonce")
        try:
            tenant_bytes = tenant_id.encode("utf-8")
            nonce_bytes = nonce.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ConsumptionStoreError("tenant_id or nonce is not valid UTF-8") from exc
        tenant_message = _TENANT_KEY_DOMAIN + len(tenant_bytes).to_bytes(8, "big") + tenant_bytes
        tenant_key = hmac.new(self._hmac_key, tenant_message, hashlib.sha256).digest()
        nonce_message = _NONCE_DOMAIN + len(nonce_bytes).to_bytes(8, "big") + nonce_bytes
        return hmac.new(tenant_key, nonce_message, hashlib.sha256).hexdigest()

    def _load_status(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        receipt_id: str,
    ) -> ConsumptionRecord | None:
        row = connection.execute(
            self._CONSUMPTION_SELECT,
            (tenant_id, receipt_id),
        ).fetchone()
        if row is not None:
            try:
                state = ConsumptionState(_row_text(row, "state"))
            except ValueError as exc:
                raise ConsumptionStoreError("invalid consumption state row") from exc
            return ConsumptionRecord(
                tenant_id=_row_text(row, "tenant_id"),
                receipt_id=_row_text(row, "receipt_id"),
                state=state,
                nonce_hash=_row_text(row, "nonce_hash"),
                receipt_hash=_row_text(row, "receipt_hash"),
                binding_hash=_row_text(row, "binding_hash"),
                idempotency_digest=_row_text(row, "idempotency_digest"),
                attempt_id=_row_text(row, "attempt_id"),
                reserved_at=_row_text(row, "reserved_at"),
                updated_at=_row_text(row, "updated_at"),
                revoked_at=_row_optional_text(row, "revoked_at"),
                recovery_authority=_row_optional_text(row, "recovery_authority"),
                recovery_reason_code=_row_optional_text(row, "recovery_reason_code"),
                recovery_evidence_digest=_row_optional_text(row, "recovery_evidence_digest"),
            )

        revoked = connection.execute(
            """
            SELECT revoked_at
            FROM receipt_revocations
            WHERE tenant_id = ? AND receipt_id = ?
            """,
            (tenant_id, receipt_id),
        ).fetchone()
        if revoked is None:
            return None
        revoked_at = _row_text(revoked, "revoked_at")
        return ConsumptionRecord(
            tenant_id=tenant_id,
            receipt_id=receipt_id,
            state=ConsumptionState.REVOKED,
            nonce_hash=None,
            receipt_hash=None,
            binding_hash=None,
            idempotency_digest=None,
            attempt_id=None,
            reserved_at=None,
            updated_at=revoked_at,
            revoked_at=revoked_at,
            recovery_authority=None,
            recovery_reason_code=None,
            recovery_evidence_digest=None,
        )

    def _run_immediate(
        self,
        operation: Callable[[sqlite3.Connection], _T],
        *,
        mutation: tuple[str, ...] | None = None,
        initialize: bool = False,
    ) -> _T:
        with self._operation_lock:
            return self._run_immediate_locked(
                operation,
                mutation=mutation,
                initialize=initialize,
            )

    def _run_immediate_locked(
        self,
        operation: Callable[[sqlite3.Connection], _T],
        *,
        mutation: tuple[str, ...] | None = None,
        initialize: bool = False,
    ) -> _T:
        if self._poisoned:
            raise ConsumptionStoreError(
                "store is fail-stopped; rollback suspected after anchor publication failure"
            )
        connection: sqlite3.Connection | None = None
        anchor_update: (
            tuple[
                AnchoredConsumptionState | None,
                AnchoredConsumptionState,
            ]
            | None
        ) = None
        try:
            initializing = self._database_identity is None
            self._verify_storage_path(allow_missing_database=initializing)
            if not initializing:
                self._verify_database_identity()

            connection = sqlite3.connect(
                str(self._sqlite_path()),
                timeout=self._timeout,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row

            self._verify_storage_path(allow_missing_database=False)
            if not initializing:
                self._verify_database_identity()

            busy_timeout_ms = max(
                1,
                int(min(self._timeout, 2_147_483.647) * 1000),
            )
            connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
            busy_timeout = connection.execute("PRAGMA busy_timeout").fetchone()
            if _pragma_int(busy_timeout, "busy_timeout") <= 0:
                raise ConsumptionStoreError("SQLite busy_timeout was not applied")

            connection.execute("BEGIN IMMEDIATE")
            before: tuple[str, int, str, str, str] | None = None
            anchored_before: AnchoredConsumptionState | None = None
            if not initialize:
                self._validate_schema(connection)
                before = self._load_integrity_state(connection)
                self._verify_state_root(connection, before[3])
                anchored_before = self._verify_anchor(
                    self._anchor_state(before),
                    allow_initialize=False,
                )
            result = operation(connection)
            current = self._load_integrity_state(connection)
            if initialize:
                self._verify_state_root(connection, current[3])
                anchored_before = self._verify_anchor(
                    self._anchor_state(current),
                    allow_initialize=self._created_schema,
                )
            elif before != current:
                raise ConsumptionStoreError(
                    "integrity metadata changed outside the mutation protocol"
                )
            if mutation is not None:
                store_id, generation, chain_head, _, namespace = current
                next_generation = generation + 1
                next_head = self._next_chain_head(
                    store_id,
                    next_generation,
                    chain_head,
                    mutation,
                )
                self._write_integrity_state(connection, next_generation, next_head)
                next_root = self._compute_state_root(connection)
                self._write_state_root(connection, next_root)
                replacement = AnchoredConsumptionState(
                    store_id=store_id,
                    generation=next_generation,
                    chain_head=next_head,
                    state_root=next_root,
                )
                if namespace != self._anchor_namespace:
                    raise ConsumptionStoreError("anchor namespace changed during mutation")
                if self._state_anchor is not None:
                    anchor_update = (anchored_before, replacement)
            elif initialize and self._created_schema:
                if self._state_anchor is not None:
                    anchor_update = (anchored_before, self._anchor_state(current))
            else:
                self._verify_state_root(connection, current[3])
            connection.commit()
            connection.close()
            connection = None
            if anchor_update is not None:
                self._publish_anchor(*anchor_update)
            return result
        except ReceiptConsumptionError:
            if connection is not None:
                _rollback_quietly(connection)
            raise
        except (OSError, OverflowError, TypeError, ValueError, sqlite3.Error) as exc:
            if connection is not None:
                _rollback_quietly(connection)
            raise ConsumptionStoreError("consumption store operation failed") from exc
        finally:
            if connection is not None:
                with contextlib.suppress(sqlite3.Error):
                    connection.close()

    def _initialize_schema(self, connection: sqlite3.Connection) -> None:
        version = _user_version(connection)
        tables = _user_tables(connection)

        if version == 0:
            if tables:
                raise ConsumptionStoreError("unversioned or incompatible consumption store schema")
            self._create_schema(connection)
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            store_id = os.urandom(32).hex()
            chain_head = self._initial_chain_head(store_id)
            connection.executemany(
                """
                INSERT INTO consumption_metadata (metadata_key, metadata_value)
                VALUES (?, ?)
                """,
                (
                    (_KEY_FINGERPRINT_NAME, self._key_fingerprint),
                    (_STORE_ID_NAME, store_id),
                    (_GENERATION_NAME, "0"),
                    (_CHAIN_HEAD_NAME, chain_head),
                    (_STATE_ROOT_NAME, "0" * 64),
                    (_ANCHOR_NAMESPACE_NAME, self._anchor_namespace),
                ),
            )
            self._write_state_root(connection, self._compute_state_root(connection))
            self._created_schema = True
        elif version != _SCHEMA_VERSION:
            raise ConsumptionStoreError(f"unsupported consumption store schema version: {version}")

        self._validate_schema(connection)
        metadata = connection.execute(
            """
            SELECT metadata_key, metadata_value
            FROM consumption_metadata
            ORDER BY metadata_key
            """
        ).fetchall()
        if len(metadata) != len(_EXPECTED_METADATA_KEYS):
            raise ConsumptionStoreError("invalid consumption metadata rows")
        values = {
            _row_text(row, "metadata_key"): _row_text(row, "metadata_value") for row in metadata
        }
        if set(values) != _EXPECTED_METADATA_KEYS:
            raise ConsumptionStoreError("invalid consumption metadata keys")
        stored_fingerprint = values[_KEY_FINGERPRINT_NAME]
        if not hmac.compare_digest(stored_fingerprint, self._key_fingerprint):
            raise ConsumptionStoreError("consumption store HMAC key mismatch")
        self._validate_integrity_values(
            values[_STORE_ID_NAME],
            values[_GENERATION_NAME],
            values[_CHAIN_HEAD_NAME],
            values[_STATE_ROOT_NAME],
            values[_ANCHOR_NAMESPACE_NAME],
        )
        self._verify_state_root(connection, values[_STATE_ROOT_NAME])

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE receipt_consumptions (
                tenant_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                nonce_hash TEXT NOT NULL,
                receipt_hash TEXT NOT NULL,
                binding_hash TEXT NOT NULL,
                idempotency_digest TEXT NOT NULL,
                attempt_id TEXT NOT NULL,
                state TEXT NOT NULL
                    CHECK (state IN ('RESERVED', 'SUCCEEDED', 'UNKNOWN')),
                reserved_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                recovery_authority TEXT,
                recovery_reason_code TEXT,
                recovery_evidence_digest TEXT,
                PRIMARY KEY (tenant_id, receipt_id),
                UNIQUE (tenant_id, nonce_hash),
                UNIQUE (tenant_id, idempotency_digest)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE receipt_revocations (
                tenant_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                revoked_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, receipt_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE consumption_metadata (
                metadata_key TEXT NOT NULL PRIMARY KEY
                    CHECK (metadata_key IN (
                        'hmac_key_fingerprint', 'store_id', 'generation', 'chain_head',
                        'state_root', 'anchor_namespace'
                    )),
                metadata_value TEXT NOT NULL
            )
            """
        )

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> None:
        if _user_version(connection) != _SCHEMA_VERSION:
            raise ConsumptionStoreError("consumption schema version changed")
        if _user_tables(connection) != _EXPECTED_TABLES:
            raise ConsumptionStoreError("consumption schema table set is incompatible")

        _validate_columns(
            connection,
            "receipt_consumptions",
            (
                ("tenant_id", "TEXT", 1, 1),
                ("receipt_id", "TEXT", 1, 2),
                ("nonce_hash", "TEXT", 1, 0),
                ("receipt_hash", "TEXT", 1, 0),
                ("binding_hash", "TEXT", 1, 0),
                ("idempotency_digest", "TEXT", 1, 0),
                ("attempt_id", "TEXT", 1, 0),
                ("state", "TEXT", 1, 0),
                ("reserved_at", "TEXT", 1, 0),
                ("updated_at", "TEXT", 1, 0),
                ("recovery_authority", "TEXT", 0, 0),
                ("recovery_reason_code", "TEXT", 0, 0),
                ("recovery_evidence_digest", "TEXT", 0, 0),
            ),
        )
        _validate_columns(
            connection,
            "receipt_revocations",
            (
                ("tenant_id", "TEXT", 1, 1),
                ("receipt_id", "TEXT", 1, 2),
                ("revoked_at", "TEXT", 1, 0),
            ),
        )
        _validate_columns(
            connection,
            "consumption_metadata",
            (
                ("metadata_key", "TEXT", 1, 1),
                ("metadata_value", "TEXT", 1, 0),
            ),
        )

        indexes = connection.execute('PRAGMA index_list("receipt_consumptions")').fetchall()
        nonce_unique = False
        idempotency_unique = False
        for index in indexes:
            if _row_int(index, "unique") != 1 or _row_int(index, "partial") != 0:
                continue
            index_name = _row_text(index, "name")
            index_columns = connection.execute(
                """
                SELECT name
                FROM pragma_index_info(?)
                ORDER BY seqno
                """,
                (index_name,),
            ).fetchall()
            names = tuple(_row_text(column, "name") for column in index_columns)
            if names == ("tenant_id", "nonce_hash"):
                nonce_unique = True
            elif names == ("tenant_id", "idempotency_digest"):
                idempotency_unique = True
        if not nonce_unique:
            raise ConsumptionStoreError("tenant-bound nonce uniqueness constraint is missing")
        if not idempotency_unique:
            raise ConsumptionStoreError("tenant-bound idempotency uniqueness constraint is missing")

        _validate_schema_objects(connection)
        _validate_consumption_conflict_policies(connection)

        consumption_sql = _table_sql(connection, "receipt_consumptions")
        normalized_consumption_sql = "".join(consumption_sql.upper().split())
        if "CHECK(STATEIN('RESERVED','SUCCEEDED','UNKNOWN'))" not in normalized_consumption_sql:
            raise ConsumptionStoreError("consumption state CHECK is incompatible")

        metadata_sql = _table_sql(connection, "consumption_metadata")
        normalized_metadata_sql = "".join(metadata_sql.upper().split())
        if (
            "CHECK(METADATA_KEYIN('HMAC_KEY_FINGERPRINT','STORE_ID','GENERATION','CHAIN_HEAD','STATE_ROOT','ANCHOR_NAMESPACE'))"
            not in normalized_metadata_sql
        ):
            raise ConsumptionStoreError("consumption metadata CHECK is incompatible")

    def _load_integrity_state(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[str, int, str, str, str]:
        rows = connection.execute(
            """
            SELECT metadata_key, metadata_value
            FROM consumption_metadata
            WHERE metadata_key IN (?, ?, ?, ?, ?)
            """,
            (
                _STORE_ID_NAME,
                _GENERATION_NAME,
                _CHAIN_HEAD_NAME,
                _STATE_ROOT_NAME,
                _ANCHOR_NAMESPACE_NAME,
            ),
        ).fetchall()
        if len(rows) != 5:
            raise ConsumptionStoreError("integrity metadata is missing or duplicated")
        values = {_row_text(row, "metadata_key"): _row_text(row, "metadata_value") for row in rows}
        return self._validate_integrity_values(
            values.get(_STORE_ID_NAME),
            values.get(_GENERATION_NAME),
            values.get(_CHAIN_HEAD_NAME),
            values.get(_STATE_ROOT_NAME),
            values.get(_ANCHOR_NAMESPACE_NAME),
        )

    def _validate_integrity_values(
        self,
        store_id: str | None,
        generation_text: str | None,
        chain_head: str | None,
        state_root: str | None,
        anchor_namespace: str | None,
    ) -> tuple[str, int, str, str, str]:
        if not _is_sha256(store_id):
            raise ConsumptionStoreError("invalid integrity store identifier")
        try:
            generation = int(generation_text) if generation_text is not None else -1
        except (TypeError, ValueError) as exc:
            raise ConsumptionStoreError("invalid integrity generation") from exc
        if generation < 0 or str(generation) != generation_text:
            raise ConsumptionStoreError("invalid integrity generation")
        if not _is_sha256(chain_head):
            raise ConsumptionStoreError("invalid integrity chain head")
        if not _is_sha256(state_root):
            raise ConsumptionStoreError("invalid integrity state root")
        if anchor_namespace != self._anchor_namespace:
            raise ConsumptionStoreError("consumption anchor namespace mismatch")
        if generation == 0 and not hmac.compare_digest(
            chain_head, self._initial_chain_head(store_id)
        ):
            raise ConsumptionStoreError("invalid initial integrity chain head")
        return store_id, generation, chain_head, state_root, anchor_namespace

    def _initial_chain_head(self, store_id: str) -> str:
        return hmac.new(
            self._hmac_key,
            _CHAIN_INITIAL_DOMAIN
            + self._anchor_namespace.encode("utf-8")
            + b"\x00"
            + store_id.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def _next_chain_head(
        self,
        store_id: str,
        generation: int,
        previous_head: str,
        mutation: tuple[str, ...],
    ) -> str:
        digest = hashlib.sha256()
        for item in mutation:
            encoded = item.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        message = (
            _CHAIN_NEXT_DOMAIN
            + self._anchor_namespace.encode("utf-8")
            + b"\x00"
            + store_id.encode("ascii")
            + generation.to_bytes(16, "big")
            + bytes.fromhex(previous_head)
            + digest.digest()
        )
        return hmac.new(self._hmac_key, message, hashlib.sha256).hexdigest()

    @staticmethod
    def _write_integrity_state(
        connection: sqlite3.Connection,
        generation: int,
        chain_head: str,
    ) -> None:
        for key, value in (
            (_GENERATION_NAME, str(generation)),
            (_CHAIN_HEAD_NAME, chain_head),
        ):
            cursor = connection.execute(
                """
                UPDATE consumption_metadata
                SET metadata_value = ?
                WHERE metadata_key = ?
                """,
                (value, key),
            )
            if cursor.rowcount != 1:
                raise ConsumptionStoreError("integrity metadata update failed")

    @staticmethod
    def _write_state_root(
        connection: sqlite3.Connection,
        state_root: str,
    ) -> None:
        cursor = connection.execute(
            """
            UPDATE consumption_metadata
            SET metadata_value = ?
            WHERE metadata_key = ?
            """,
            (state_root, _STATE_ROOT_NAME),
        )
        if cursor.rowcount != 1:
            raise ConsumptionStoreError("integrity state root update failed")

    def _compute_state_root(self, connection: sqlite3.Connection) -> str:
        schema_rows = connection.execute(
            """
            SELECT type, name, tbl_name, sql
            FROM sqlite_master
            ORDER BY type, name, tbl_name
            """
        ).fetchall()
        metadata_rows = connection.execute(
            """
            SELECT metadata_key, metadata_value
            FROM consumption_metadata
            ORDER BY metadata_key
            """
        ).fetchall()
        metadata = []
        for row in metadata_rows:
            key = _row_text(row, "metadata_key")
            value = _row_text(row, "metadata_value")
            metadata.append((key, _STATE_ROOT_SENTINEL if key == _STATE_ROOT_NAME else value))
        consumption_rows = connection.execute(
            """
            SELECT tenant_id, receipt_id, nonce_hash, receipt_hash, binding_hash,
                   idempotency_digest, attempt_id, state, reserved_at, updated_at,
                   recovery_authority, recovery_reason_code, recovery_evidence_digest
            FROM receipt_consumptions
            ORDER BY tenant_id, receipt_id
            """
        ).fetchall()
        consumptions = [_canonical_sql_row(row) for row in consumption_rows]
        for row in consumptions:
            if row[7] not in {
                ConsumptionState.RESERVED.value,
                ConsumptionState.SUCCEEDED.value,
                ConsumptionState.UNKNOWN.value,
            }:
                raise ConsumptionStoreError("invalid consumption state row")
        revocation_rows = connection.execute(
            """
            SELECT tenant_id, receipt_id, revoked_at
            FROM receipt_revocations
            ORDER BY tenant_id, receipt_id
            """
        ).fetchall()
        payload = {
            "schema_version": _user_version(connection),
            "schema": [_canonical_sql_row(row) for row in schema_rows],
            "metadata": metadata,
            "consumptions": consumptions,
            "revocations": [_canonical_sql_row(row) for row in revocation_rows],
        }
        try:
            encoded = json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, UnicodeEncodeError, ValueError) as exc:
            raise ConsumptionStoreError("state root canonicalization failed") from exc
        return hmac.new(
            self._hmac_key,
            _STATE_ROOT_DOMAIN + encoded,
            hashlib.sha256,
        ).hexdigest()

    def _verify_state_root(
        self,
        connection: sqlite3.Connection,
        expected: str,
    ) -> None:
        computed = self._compute_state_root(connection)
        if not hmac.compare_digest(computed, expected):
            raise ConsumptionStoreError("keyed consumption state root mismatch")

    @staticmethod
    def _anchor_state(
        integrity: tuple[str, int, str, str, str],
    ) -> AnchoredConsumptionState:
        return AnchoredConsumptionState(
            store_id=integrity[0],
            generation=integrity[1],
            chain_head=integrity[2],
            state_root=integrity[3],
        )

    def _read_anchor(self) -> AnchoredConsumptionState | None:
        if self._state_anchor is None:
            return None
        try:
            state = self._state_anchor.read(self._anchor_namespace)
        except Exception as exc:
            raise ConsumptionStoreError("trusted state anchor is unavailable") from exc
        if state is None:
            return None
        if (
            type(state) is not AnchoredConsumptionState
            or not _is_sha256(state.store_id)
            or type(state.generation) is not int
            or state.generation < 0
            or not _is_sha256(state.chain_head)
            or not _is_sha256(state.state_root)
        ):
            raise ConsumptionStoreError("trusted state anchor returned malformed state")
        return state

    def _verify_anchor(
        self,
        current: AnchoredConsumptionState,
        *,
        allow_initialize: bool,
    ) -> AnchoredConsumptionState | None:
        if self._state_anchor is None:
            if self._require_trusted_anchor:
                raise ConsumptionStoreError("trusted state anchor is unavailable")
            return None
        anchored = self._read_anchor()
        if anchored is None and allow_initialize:
            return None
        if anchored is None:
            raise ConsumptionStoreError("trusted state anchor has no store state")
        if anchored != current:
            raise ConsumptionStoreError("trusted state anchor mismatch; rollback suspected")
        return anchored

    def _publish_anchor(
        self,
        expected: AnchoredConsumptionState | None,
        replacement: AnchoredConsumptionState,
    ) -> None:
        if self._state_anchor is None:
            return
        try:
            updated = self._state_anchor.compare_and_swap(
                self._anchor_namespace,
                expected,
                replacement,
            )
        except Exception as exc:
            self._poisoned = True
            raise ConsumptionStoreError(
                "trusted state anchor CAS outcome is unknown after database commit; "
                "store is fail-stopped"
            ) from exc
        if updated is not True:
            self._poisoned = True
            raise ConsumptionStoreError(
                "trusted state anchor CAS failed after database commit; store is fail-stopped"
            )

    def _verify_storage_path(self, *, allow_missing_database: bool) -> None:
        directory = self._attested_directory
        relative = self._attested_relative
        if directory is not None and relative is not None:
            directory.checkpoint()
            try:
                descriptor = directory.open_file(relative, os.O_RDONLY)
            except FileNotFoundError:
                if allow_missing_database:
                    return
                raise ConsumptionStoreError(
                    f"consumption database is missing: {self.path}"
                ) from None
            else:
                os.close(descriptor)
                return
        try:
            parent = self.path.parent
            parent_parts = parent.parts
            current = Path(parent_parts[0])
            parent_stat = os.lstat(current)
            if stat.S_ISLNK(parent_stat.st_mode):
                raise ConsumptionStoreError(f"symlink path component rejected: {current}")

            for part in parent_parts[1:]:
                current = current / part
                component_stat = os.lstat(current)
                if stat.S_ISLNK(component_stat.st_mode):
                    raise ConsumptionStoreError(f"symlink path component rejected: {current}")

            if not stat.S_ISDIR(os.lstat(parent).st_mode):
                raise ConsumptionStoreError(
                    f"consumption store parent is not a directory: {parent}"
                )

            try:
                database_stat = os.lstat(self.path)
            except FileNotFoundError:
                if allow_missing_database:
                    return
                raise ConsumptionStoreError(
                    f"consumption database is missing: {self.path}"
                ) from None
            if stat.S_ISLNK(database_stat.st_mode):
                raise ConsumptionStoreError(f"symlink consumption database rejected: {self.path}")
            if not stat.S_ISREG(database_stat.st_mode):
                raise ConsumptionStoreError(
                    f"consumption database is not a regular file: {self.path}"
                )
        except ConsumptionStoreError:
            raise
        except OSError as exc:
            raise ConsumptionStoreError(
                f"cannot safely inspect consumption store path: {self.path}"
            ) from exc

    def _read_database_identity(self) -> tuple[int, int]:
        directory = self._attested_directory
        relative = self._attested_relative
        if directory is not None and relative is not None:
            directory.checkpoint()
            try:
                descriptor = directory.open_file(relative, os.O_RDONLY)
                try:
                    database_stat = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
            except OSError as exc:
                raise ConsumptionStoreError(
                    f"cannot identify consumption database: {self.path}"
                ) from exc
            return (database_stat.st_dev, database_stat.st_ino)
        try:
            database_stat = os.lstat(self.path)
        except OSError as exc:
            raise ConsumptionStoreError(
                f"cannot identify consumption database: {self.path}"
            ) from exc
        if stat.S_ISLNK(database_stat.st_mode) or not stat.S_ISREG(database_stat.st_mode):
            raise ConsumptionStoreError("consumption database identity is unsafe")
        return (database_stat.st_dev, database_stat.st_ino)

    def _verify_database_identity(self) -> None:
        if self._database_identity is None:
            raise ConsumptionStoreError("consumption database identity is unavailable")
        if self._read_database_identity() != self._database_identity:
            raise ConsumptionStoreError("consumption database file was replaced")


def _absolute_path(path: str | Path) -> Path:
    try:
        expanded = Path(path).expanduser()
        return Path(os.path.abspath(os.fspath(expanded)))
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ConsumptionStoreError("invalid consumption store path") from exc


def _is_proc_descriptor_alias(path: Path) -> bool:
    if is_proc_fd_path(path):
        return True
    parts = Path(os.path.abspath(os.fspath(path))).parts
    return (
        len(parts) >= 5
        and parts[:2] == ("/", "proc")
        and (parts[2].isdecimal() or parts[2] == "thread-self")
        and parts[3] == "fd"
        and parts[4].isdecimal()
    )


def _validated_hmac_key(hmac_key: bytes) -> bytes:
    if not isinstance(hmac_key, bytes) or len(hmac_key) < 32:
        raise ConsumptionStoreError("hmac_key must contain at least 32 bytes")
    return bytes(hmac_key)


def _validated_text(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConsumptionStoreError(f"{field_name} must be a non-empty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ConsumptionStoreError(f"{field_name} must be valid UTF-8") from exc
    return value


def _is_sha256(value: object) -> TypeGuard[str]:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(character in "0123456789abcdef" for character in value)


def _validated_sha256(value: str, field_name: str) -> str:
    if not _is_sha256(value):
        raise ConsumptionStoreError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _validated_timeout(timeout: float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ConsumptionStoreError("timeout must be a finite positive number")
    value = float(timeout)
    if not math.isfinite(value) or value <= 0:
        raise ConsumptionStoreError("timeout must be a finite positive number")
    return value


def _user_version(connection: sqlite3.Connection) -> int:
    return _pragma_int(connection.execute("PRAGMA user_version").fetchone(), "user_version")


def _pragma_int(row: object, pragma_name: str) -> int:
    try:
        value = row[0]  # type: ignore[index]
    except (IndexError, KeyError, TypeError) as exc:
        raise ConsumptionStoreError(f"invalid SQLite {pragma_name} response") from exc
    if type(value) is not int:
        raise ConsumptionStoreError(f"invalid SQLite {pragma_name} response")
    return value


def _user_tables(connection: sqlite3.Connection) -> set[str]:
    rows = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = ? AND name NOT LIKE ?
        """,
        ("table", "sqlite_%"),
    ).fetchall()
    return {_row_text(row, "name") for row in rows}


def _validate_schema_objects(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        """
        SELECT type, name, tbl_name, sql
        FROM sqlite_master
        ORDER BY type, name, tbl_name
        """
    ).fetchall()
    auto_indexes: set[str] = set()
    for row in rows:
        object_type = _row_text(row, "type")
        name = _row_text(row, "name")
        table_name = _row_text(row, "tbl_name")
        sql = _row_optional_text(row, "sql")
        if object_type == "table" and name in _EXPECTED_TABLES and table_name == name:
            continue
        if (
            object_type == "index"
            and sql is None
            and name.startswith("sqlite_autoindex_")
            and table_name in _EXPECTED_TABLES
        ):
            auto_indexes.add(name)
            continue
        raise ConsumptionStoreError(f"unexpected consumption schema object: {object_type} {name}")
    if auto_indexes != _EXPECTED_AUTO_INDEXES:
        raise ConsumptionStoreError("consumption schema auto-index set is incompatible")


def _validate_consumption_conflict_policies(connection: sqlite3.Connection) -> None:
    """Prove protected constraints use SQLite's statement-rollback ABORT semantics.

    SQLite's schema pragmas expose unique index columns but not their configured
    conflict policy.  Parsing ``sqlite_master.sql`` is fragile around comments,
    quoting, whitespace, and keyword casing, so validation uses rollback-only
    semantic probes instead.  For each protected constraint, a two-row INSERT
    writes one fresh row before provoking a conflict.  ABORT rejects the
    statement and leaves neither row-level replacement nor the first row;
    IGNORE/REPLACE return successfully, FAIL retains the first row, and
    ROLLBACK ends the surrounding transaction.  Every probe is contained in a
    savepoint and cannot commit probe data.
    """
    if not connection.in_transaction:
        raise ConsumptionStoreError(
            "consumption conflict-policy validation requires an active transaction"
        )

    marker = f"gove-zone-conflict-probe-{os.urandom(16).hex()}"
    tenant_id = f"{marker}-tenant"
    baseline = _consumption_probe_row(
        marker=marker,
        tenant_id=tenant_id,
        receipt_id=f"{marker}-receipt-base",
        nonce_hash=_probe_digest(marker, "nonce-base"),
        idempotency_digest=_probe_digest(marker, "idempotency-base"),
    )
    first = _consumption_probe_row(
        marker=marker,
        tenant_id=tenant_id,
        receipt_id=f"{marker}-receipt-first",
        nonce_hash=_probe_digest(marker, "nonce-first"),
        idempotency_digest=_probe_digest(marker, "idempotency-first"),
    )
    conflicts = (
        (
            "receipt primary key",
            _consumption_probe_row(
                marker=marker,
                tenant_id=tenant_id,
                receipt_id=str(baseline[1]),
                nonce_hash=_probe_digest(marker, "nonce-pk-conflict"),
                idempotency_digest=_probe_digest(
                    marker,
                    "idempotency-pk-conflict",
                ),
            ),
        ),
        (
            "tenant-bound nonce",
            _consumption_probe_row(
                marker=marker,
                tenant_id=tenant_id,
                receipt_id=f"{marker}-receipt-nonce-conflict",
                nonce_hash=str(baseline[2]),
                idempotency_digest=_probe_digest(
                    marker,
                    "idempotency-nonce-conflict",
                ),
            ),
        ),
        (
            "tenant-bound idempotency",
            _consumption_probe_row(
                marker=marker,
                tenant_id=tenant_id,
                receipt_id=f"{marker}-receipt-idempotency-conflict",
                nonce_hash=_probe_digest(marker, "nonce-idempotency-conflict"),
                idempotency_digest=str(baseline[5]),
            ),
        ),
    )
    for constraint_name, conflict in conflicts:
        _probe_abort_conflict_policy(
            connection,
            constraint_name=constraint_name,
            baseline=baseline,
            first=first,
            conflict=conflict,
        )


def _probe_abort_conflict_policy(
    connection: sqlite3.Connection,
    *,
    constraint_name: str,
    baseline: tuple[str | None, ...],
    first: tuple[str | None, ...],
    conflict: tuple[str | None, ...],
) -> None:
    savepoint = "gove_zone_conflict_policy_probe"
    connection.execute(f"SAVEPOINT {savepoint}")
    try:
        connection.execute(
            """
            INSERT INTO receipt_consumptions (
                tenant_id, receipt_id, nonce_hash, receipt_hash, binding_hash,
                idempotency_digest, attempt_id, state, reserved_at, updated_at,
                recovery_authority, recovery_reason_code, recovery_evidence_digest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            baseline,
        )
        conflict_was_rejected = False
        try:
            connection.execute(
                """
                INSERT INTO receipt_consumptions (
                    tenant_id, receipt_id, nonce_hash, receipt_hash, binding_hash,
                    idempotency_digest, attempt_id, state, reserved_at, updated_at,
                    recovery_authority, recovery_reason_code, recovery_evidence_digest
                ) VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                first + conflict,
            )
        except sqlite3.IntegrityError:
            conflict_was_rejected = True

        if not connection.in_transaction:
            raise ConsumptionStoreError(
                f"{constraint_name} constraint must use ABORT conflict policy"
            )
        baseline_after = connection.execute(
            """
            SELECT tenant_id, receipt_id, nonce_hash, receipt_hash, binding_hash,
                   idempotency_digest, attempt_id, state, reserved_at, updated_at,
                   recovery_authority, recovery_reason_code, recovery_evidence_digest
            FROM receipt_consumptions
            WHERE tenant_id = ? AND receipt_id = ?
            """,
            (baseline[0], baseline[1]),
        ).fetchone()
        first_after = connection.execute(
            """
            SELECT 1 FROM receipt_consumptions
            WHERE tenant_id = ? AND receipt_id = ?
            """,
            (first[0], first[1]),
        ).fetchone()
        if (
            not conflict_was_rejected
            or baseline_after is None
            or tuple(baseline_after) != baseline
            or first_after is not None
        ):
            raise ConsumptionStoreError(
                f"{constraint_name} constraint must use ABORT conflict policy"
            )
    finally:
        if connection.in_transaction:
            try:
                connection.execute(f"ROLLBACK TO {savepoint}")
                connection.execute(f"RELEASE {savepoint}")
            except sqlite3.Error as exc:
                raise ConsumptionStoreError(
                    "consumption conflict-policy probe cleanup failed"
                ) from exc


def _consumption_probe_row(
    *,
    marker: str,
    tenant_id: str,
    receipt_id: str,
    nonce_hash: str,
    idempotency_digest: str,
) -> tuple[str | None, ...]:
    return (
        tenant_id,
        receipt_id,
        nonce_hash,
        _probe_digest(marker, f"receipt-hash:{receipt_id}"),
        _probe_digest(marker, f"binding-hash:{receipt_id}"),
        idempotency_digest,
        f"{marker}-attempt:{receipt_id}",
        ConsumptionState.RESERVED.value,
        f"{marker}-reserved-at",
        f"{marker}-updated-at",
        None,
        None,
        None,
    )


def _probe_digest(marker: str, label: str) -> str:
    return hashlib.sha256(f"{marker}\x00{label}".encode()).hexdigest()


def _canonical_sql_row(row: sqlite3.Row) -> tuple[str | int | None, ...]:
    canonical: list[str | int | None] = []
    for value in row:
        if value is None or type(value) in {str, int}:
            canonical.append(value)
            continue
        raise ConsumptionStoreError("unsupported SQLite value in canonical state")
    return tuple(canonical)


def _operation_lock_for(path: object) -> RLock:
    with _OPERATION_LOCKS_GUARD:
        lock = _OPERATION_LOCKS.get(path)
        if lock is None:
            lock = RLock()
            _OPERATION_LOCKS[path] = lock
        return lock


def _validate_columns(
    connection: sqlite3.Connection,
    table: str,
    expected: tuple[tuple[str, str, int, int], ...],
) -> None:
    pragma_by_table = {
        "receipt_consumptions": 'PRAGMA table_info("receipt_consumptions")',
        "receipt_revocations": 'PRAGMA table_info("receipt_revocations")',
        "consumption_metadata": 'PRAGMA table_info("consumption_metadata")',
    }
    try:
        pragma = pragma_by_table[table]
    except KeyError as exc:
        raise ConsumptionStoreError("unexpected schema table") from exc
    rows = connection.execute(pragma).fetchall()
    actual = tuple(
        (
            _row_text(row, "name"),
            _row_text(row, "type").upper(),
            _row_int(row, "notnull"),
            _row_int(row, "pk"),
        )
        for row in rows
    )
    if actual != expected:
        raise ConsumptionStoreError(f"incompatible columns for {table}")


def _table_sql(connection: sqlite3.Connection, table: str) -> str:
    row = connection.execute(
        """
        SELECT sql
        FROM sqlite_master
        WHERE type = ? AND name = ?
        """,
        ("table", table),
    ).fetchone()
    if row is None:
        raise ConsumptionStoreError(f"missing schema SQL for {table}")
    return _row_text(row, "sql")


def _row_text(row: sqlite3.Row, column: str) -> str:
    try:
        value = row[column]
    except (IndexError, KeyError, TypeError) as exc:
        raise ConsumptionStoreError(f"invalid SQLite row column: {column}") from exc
    if not isinstance(value, str):
        raise ConsumptionStoreError(f"invalid SQLite text value: {column}")
    return value


def _row_optional_text(row: sqlite3.Row, column: str) -> str | None:
    try:
        value = row[column]
    except (IndexError, KeyError, TypeError) as exc:
        raise ConsumptionStoreError(f"invalid SQLite row column: {column}") from exc
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConsumptionStoreError(f"invalid SQLite text value: {column}")
    return value


def _row_int(row: sqlite3.Row, column: str) -> int:
    try:
        value = row[column]
    except (IndexError, KeyError, TypeError) as exc:
        raise ConsumptionStoreError(f"invalid SQLite row column: {column}") from exc
    if type(value) is not int:
        raise ConsumptionStoreError(f"invalid SQLite integer value: {column}")
    return int(value)


def _utc_timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _rollback_quietly(connection: sqlite3.Connection) -> None:
    with contextlib.suppress(sqlite3.Error):
        connection.rollback()
