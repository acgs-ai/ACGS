"""Fail-closed receipt consumption persistence tests."""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier, Lock
from typing import cast

import pytest

from gove_zone.consumption import (
    AnchoredConsumptionState,
    ConsumptionRecord,
    ConsumptionState,
    ConsumptionStateAnchor,
    ConsumptionStoreError,
    ConsumptionTransitionError,
    ReceiptConsumptionStore,
    ReceiptReplayError,
    ReceiptRevokedError,
)
from gove_zone.proof_pack import PinnedOutputRoot

_HMAC_KEY = b"test-only-stable-consumption-hmac-key-32-bytes"
_OTHER_HMAC_KEY = b"different-test-only-consumption-key-32-bytes"
_RECOVERY_DIGEST = "a" * 64
_RECEIPT_HASH = "b" * 64
_BINDING_HASH = "c" * 64


def _idempotency_digest(
    tenant_id: str,
    receipt_id: str,
    nonce: str,
) -> str:
    """Stand in for the trusted authorization layer's tenant-scoped digest."""
    payload = f"{tenant_id}\x00{receipt_id}\x00{nonce}".encode()
    return hashlib.sha256(payload).hexdigest()


class InMemoryAnchor(ConsumptionStateAnchor):
    def __init__(self) -> None:
        self.states: dict[str, AnchoredConsumptionState] = {}
        self.fail_reads = False
        self.fail_writes = False
        self.reject_writes = False
        self.raise_after_write = False
        self._lock = Lock()

    def read(self, namespace: str) -> AnchoredConsumptionState | None:
        if self.fail_reads:
            raise RuntimeError("injected anchor read failure")
        with self._lock:
            return self.states.get(namespace)

    def compare_and_swap(
        self,
        namespace: str,
        expected: AnchoredConsumptionState | None,
        replacement: AnchoredConsumptionState,
    ) -> bool:
        if self.fail_writes:
            raise RuntimeError("injected anchor write failure")
        with self._lock:
            if self.reject_writes or self.states.get(namespace) != expected:
                return False
            self.states[namespace] = replacement
            if self.raise_after_write:
                raise RuntimeError("injected failure after durable CAS")
            return True


def _store(
    tmp_path: Path,
    *,
    key: bytes = _HMAC_KEY,
    timeout: float = 5.0,
    name: str = "consumption.sqlite3",
    anchor: ConsumptionStateAnchor | None = None,
    require_anchor: bool = False,
    anchor_namespace: str = "test-anchor",
) -> tuple[ReceiptConsumptionStore, Path]:
    path = tmp_path / name
    return (
        ReceiptConsumptionStore(
            path,
            hmac_key=key,
            timeout=timeout,
            state_anchor=anchor,
            anchor_namespace=anchor_namespace if anchor is not None else None,
            require_trusted_anchor=require_anchor,
        ),
        path,
    )


def _reserve(
    store: ReceiptConsumptionStore,
    *,
    tenant_id: str = "tenant-a",
    receipt_id: str = "receipt-1",
    nonce: str = "nonce-secret-1",
    attempt_id: str = "attempt-1",
    receipt_hash: str = _RECEIPT_HASH,
    binding_hash: str = _BINDING_HASH,
    idempotency_digest: str | None = None,
) -> ConsumptionRecord:
    if idempotency_digest is None:
        idempotency_digest = _idempotency_digest(tenant_id, receipt_id, nonce)
    return store.reserve(
        tenant_id,
        receipt_id,
        nonce,
        receipt_hash,
        binding_hash,
        attempt_id,
        idempotency_digest=idempotency_digest,
    )


def test_reserve_once(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)

    record = _reserve(store)

    assert record.state is ConsumptionState.RESERVED
    assert record.tenant_id == "tenant-a"
    assert record.receipt_id == "receipt-1"
    assert record.attempt_id == "attempt-1"
    assert record.nonce_hash is not None
    assert record.nonce_hash != "nonce-secret-1"
    assert record.receipt_hash == _RECEIPT_HASH
    assert record.binding_hash == _BINDING_HASH
    assert record.idempotency_digest == _idempotency_digest(
        "tenant-a",
        "receipt-1",
        "nonce-secret-1",
    )
    assert record.revoked_at is None
    assert store.status("tenant-a", "receipt-1") == record


def test_duplicate_receipt_fails_closed(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    _reserve(store)

    with pytest.raises(ReceiptReplayError):
        _reserve(store, nonce="other-nonce", attempt_id="attempt-2")


def test_duplicate_nonce_for_another_receipt_fails_closed(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    _reserve(store)

    with pytest.raises(ReceiptReplayError):
        _reserve(
            store,
            receipt_id="receipt-2",
            nonce="nonce-secret-1",
            attempt_id="attempt-2",
        )


def test_duplicate_idempotency_digest_for_another_call_fails_closed(
    tmp_path: Path,
) -> None:
    store, _ = _store(tmp_path)
    digest = "d" * 64
    _reserve(store, idempotency_digest=digest)

    with pytest.raises(ReceiptReplayError, match="idempotency"):
        _reserve(
            store,
            receipt_id="receipt-2",
            nonce="nonce-secret-2",
            attempt_id="attempt-2",
            idempotency_digest=digest,
        )

    assert store.status("tenant-a", "receipt-2") is None


@pytest.mark.parametrize(
    ("field_name", "invalid_digest"),
    [
        ("receipt_hash", ""),
        ("receipt_hash", "a" * 63),
        ("receipt_hash", "A" * 64),
        ("receipt_hash", "g" * 64),
        ("binding_hash", ""),
        ("binding_hash", "b" * 63),
        ("binding_hash", "B" * 64),
        ("binding_hash", "g" * 64),
        ("idempotency_digest", ""),
        ("idempotency_digest", "c" * 63),
        ("idempotency_digest", "C" * 64),
        ("idempotency_digest", "g" * 64),
    ],
)
def test_reserve_requires_strict_lowercase_sha256_digests(
    tmp_path: Path,
    field_name: str,
    invalid_digest: str,
) -> None:
    store, _ = _store(tmp_path)
    values = {
        "receipt_hash": _RECEIPT_HASH,
        "binding_hash": _BINDING_HASH,
        "idempotency_digest": "d" * 64,
    }
    values[field_name] = invalid_digest

    with pytest.raises(ConsumptionStoreError, match=field_name):
        store.reserve(
            "tenant-a",
            "receipt-1",
            "nonce-1",
            values["receipt_hash"],
            values["binding_hash"],
            "attempt-1",
            idempotency_digest=values["idempotency_digest"],
        )


def test_idempotency_digest_is_required_keyword_only(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)

    with pytest.raises(TypeError):
        store.reserve(
            "tenant-a",
            "receipt-1",
            "nonce-1",
            _RECEIPT_HASH,
            _BINDING_HASH,
            "attempt-1",
        )
    with pytest.raises(TypeError):
        store.reserve(
            "tenant-a",
            "receipt-1",
            "nonce-1",
            _RECEIPT_HASH,
            _BINDING_HASH,
            "attempt-1",
            "d" * 64,
        )


def test_idempotency_uniqueness_is_tenant_scoped(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    digest = "d" * 64

    first = _reserve(store, tenant_id="tenant-a", idempotency_digest=digest)
    second = _reserve(
        store,
        tenant_id="tenant-b",
        receipt_id="receipt-2",
        nonce="nonce-secret-2",
        attempt_id="attempt-2",
        idempotency_digest=digest,
    )

    assert first.idempotency_digest == second.idempotency_digest == digest


def test_same_nonce_has_different_tenant_bound_hmac(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)

    first = _reserve(store, tenant_id="tenant-a", receipt_id="receipt-a")
    second = _reserve(
        store,
        tenant_id="tenant-b",
        receipt_id="receipt-b",
        attempt_id="attempt-b",
    )

    assert first.nonce_hash is not None
    assert second.nonce_hash is not None
    assert first.nonce_hash != second.nonce_hash


def test_database_contains_no_raw_nonce_idempotency_key_or_hmac_key(
    tmp_path: Path,
) -> None:
    store, path = _store(tmp_path)
    raw_nonce = "nonce-visible-marker-7e92bdb0"
    raw_test_marker = "plain fixture marker must stay out of database"
    digest = hashlib.sha256(f"tenant-a\x00{raw_test_marker}".encode()).hexdigest()
    _reserve(store, nonce=raw_nonce, idempotency_digest=digest)

    database_bytes = path.read_bytes()

    assert raw_nonce.encode() not in database_bytes
    assert raw_test_marker.encode() not in database_bytes
    assert digest.encode() in database_bytes
    assert _HMAC_KEY not in database_bytes


def test_restart_with_same_key_preserves_state(tmp_path: Path) -> None:
    store, path = _store(tmp_path)
    reserved = _reserve(store)

    restarted = ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY, timeout=5.0)

    assert restarted.status("tenant-a", "receipt-1") == reserved


def test_restart_preserves_idempotency_replay_block(tmp_path: Path) -> None:
    store, path = _store(tmp_path)
    digest = "d" * 64
    _reserve(store, idempotency_digest=digest)

    restarted = ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY, timeout=5.0)

    with pytest.raises(ReceiptReplayError, match="idempotency"):
        _reserve(
            restarted,
            receipt_id="receipt-2",
            nonce="nonce-secret-2",
            attempt_id="attempt-2",
            idempotency_digest=digest,
        )
    assert restarted.status("tenant-a", "receipt-2") is None


@pytest.mark.parametrize("terminal_state", [ConsumptionState.SUCCEEDED, ConsumptionState.UNKNOWN])
def test_terminal_state_never_turns_idempotency_replay_into_permission(
    tmp_path: Path,
    terminal_state: ConsumptionState,
) -> None:
    store, _ = _store(tmp_path)
    digest = "d" * 64
    _reserve(store, idempotency_digest=digest)
    if terminal_state is ConsumptionState.SUCCEEDED:
        store.mark_succeeded("tenant-a", "receipt-1", "attempt-1")
    else:
        store.mark_unknown("tenant-a", "receipt-1", "attempt-1")

    with pytest.raises(ReceiptReplayError, match="idempotency"):
        _reserve(
            store,
            receipt_id="receipt-2",
            nonce="nonce-secret-2",
            attempt_id="attempt-2",
            idempotency_digest=digest,
        )
    assert store.status("tenant-a", "receipt-2") is None


def test_restart_with_wrong_key_fails_closed(tmp_path: Path) -> None:
    _, path = _store(tmp_path)

    with pytest.raises(ConsumptionStoreError, match="key mismatch"):
        ReceiptConsumptionStore(path, hmac_key=_OTHER_HMAC_KEY, timeout=5.0)


def test_concurrent_same_receipt_has_exactly_one_winner(tmp_path: Path) -> None:
    _, path = _store(tmp_path)
    stores = [ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY) for _ in range(32)]
    barrier = Barrier(len(stores))

    def attempt(index: int) -> bool:
        barrier.wait()
        try:
            _reserve(stores[index], attempt_id=f"attempt-{index}")
        except ReceiptReplayError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=32) as executor:
        results = list(executor.map(attempt, range(32)))

    assert sum(results) == 1


def test_concurrent_same_nonce_different_receipts_has_one_winner(tmp_path: Path) -> None:
    _, path = _store(tmp_path)
    stores = [ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY) for _ in range(16)]
    barrier = Barrier(len(stores))

    def attempt(index: int) -> bool:
        barrier.wait()
        try:
            _reserve(
                stores[index],
                receipt_id=f"receipt-{index}",
                attempt_id=f"attempt-{index}",
            )
        except ReceiptReplayError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=len(stores)) as executor:
        results = list(executor.map(attempt, range(len(stores))))

    assert sum(results) == 1


def test_32_stores_concurrent_same_idempotency_digest_have_one_winner(
    tmp_path: Path,
) -> None:
    _, path = _store(tmp_path)
    stores = [ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY) for _ in range(32)]
    barrier = Barrier(len(stores))
    digest = "d" * 64

    def attempt(index: int) -> bool:
        barrier.wait()
        try:
            _reserve(
                stores[index],
                receipt_id=f"receipt-{index}",
                nonce=f"nonce-{index}",
                attempt_id=f"attempt-{index}",
                idempotency_digest=digest,
            )
        except ReceiptReplayError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=32) as executor:
        results = list(executor.map(attempt, range(32)))

    assert sum(results) == 1
    records = [stores[0].status("tenant-a", f"receipt-{index}") for index in range(32)]
    assert sum(record is not None for record in records) == 1


def test_concurrent_reserve_vs_revoke_is_truthful(tmp_path: Path) -> None:
    _, path = _store(tmp_path)
    reserve_store = ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY)
    revoke_store = ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY)
    barrier = Barrier(2)

    def reserve() -> str:
        barrier.wait()
        try:
            _reserve(reserve_store)
        except ReceiptRevokedError:
            return "revoked-first"
        return "reserved-first"

    def revoke() -> ConsumptionRecord:
        barrier.wait()
        return revoke_store.revoke("tenant-a", "receipt-1")

    with ThreadPoolExecutor(max_workers=2) as executor:
        reserve_future = executor.submit(reserve)
        revoke_future = executor.submit(revoke)
        outcome = reserve_future.result()
        revoked = revoke_future.result()

    final = reserve_store.status("tenant-a", "receipt-1")
    assert final is not None
    assert final.revoked_at is not None
    assert revoked.revoked_at == final.revoked_at
    assert final.state is (
        ConsumptionState.REVOKED if outcome == "revoked-first" else ConsumptionState.RESERVED
    )


def test_revoke_before_use_blocks_reservation(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)

    revoked = store.revoke("tenant-a", "receipt-1")

    assert revoked.state is ConsumptionState.REVOKED
    assert revoked.revoked_at is not None
    assert store.is_revoked("tenant-a", "receipt-1")
    with pytest.raises(ReceiptRevokedError):
        _reserve(store)


def test_revoke_reserved_attempt_keeps_truthful_outcome(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    _reserve(store)

    revoked = store.revoke("tenant-a", "receipt-1")
    succeeded = store.mark_succeeded("tenant-a", "receipt-1", "attempt-1")

    assert revoked.state is ConsumptionState.RESERVED
    assert revoked.revoked_at is not None
    assert succeeded.state is ConsumptionState.SUCCEEDED
    assert succeeded.revoked_at == revoked.revoked_at
    assert store.is_revoked("tenant-a", "receipt-1")
    with pytest.raises(ReceiptRevokedError):
        _reserve(store, nonce="new-nonce", attempt_id="new-attempt")


def test_mark_unknown_is_terminal(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    _reserve(store)

    unknown = store.mark_unknown("tenant-a", "receipt-1", "attempt-1")

    assert unknown.state is ConsumptionState.UNKNOWN
    with pytest.raises(ConsumptionTransitionError):
        store.mark_succeeded("tenant-a", "receipt-1", "attempt-1")


def test_wrong_attempt_cannot_complete_reservation(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    _reserve(store)

    with pytest.raises(ConsumptionTransitionError, match="does not own"):
        store.mark_succeeded("tenant-a", "receipt-1", "attempt-wrong")

    current = store.status("tenant-a", "receipt-1")
    assert current is not None
    assert current.state is ConsumptionState.RESERVED


def test_succeeded_state_rejects_another_transition(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    _reserve(store)
    store.mark_succeeded("tenant-a", "receipt-1", "attempt-1")

    with pytest.raises(ConsumptionTransitionError, match="terminal"):
        store.mark_unknown("tenant-a", "receipt-1", "attempt-1")


def test_explicit_recover_unknown_requires_matching_attempt(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    _reserve(store)

    with pytest.raises(ConsumptionTransitionError):
        store.recover_unknown(
            "tenant-a",
            "receipt-1",
            "attempt-wrong",
            recovery_authority="incident-commander",
            reason_code="owner-confirmed-dead",
            evidence_digest=_RECOVERY_DIGEST,
        )

    recovered = store.recover_unknown(
        "tenant-a",
        "receipt-1",
        "attempt-1",
        recovery_authority="incident-commander",
        reason_code="owner-confirmed-dead",
        evidence_digest=_RECOVERY_DIGEST,
    )
    assert recovered.state is ConsumptionState.UNKNOWN
    assert recovered.recovery_authority == "incident-commander"
    assert recovered.recovery_reason_code == "owner-confirmed-dead"
    assert recovered.recovery_evidence_digest == _RECOVERY_DIGEST
    with pytest.raises(ReceiptReplayError):
        _reserve(store, nonce="replacement-nonce", attempt_id="replacement-attempt")


@pytest.mark.parametrize(
    ("authority", "reason", "digest"),
    [
        ("", "reason", _RECOVERY_DIGEST),
        ("authority", "", _RECOVERY_DIGEST),
        ("authority", "reason", "not-a-digest"),
    ],
)
def test_recover_unknown_requires_incident_proof(
    tmp_path: Path,
    authority: str,
    reason: str,
    digest: str,
) -> None:
    store, _ = _store(tmp_path)
    _reserve(store)

    with pytest.raises(ConsumptionStoreError):
        store.recover_unknown(
            "tenant-a",
            "receipt-1",
            "attempt-1",
            recovery_authority=authority,
            reason_code=reason,
            evidence_digest=digest,
        )


def test_missing_parent_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "missing" / "consumption.sqlite3"

    with pytest.raises(ConsumptionStoreError):
        ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY, timeout=5.0)

    assert not path.parent.exists()


def test_symlink_database_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.sqlite3"
    target.touch()
    link = tmp_path / "linked.sqlite3"
    link.symlink_to(target)

    with pytest.raises(ConsumptionStoreError, match="symlink"):
        ReceiptConsumptionStore(link, hmac_key=_HMAC_KEY, timeout=5.0)


def test_symlink_parent_is_rejected(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ConsumptionStoreError, match="symlink"):
        ReceiptConsumptionStore(
            linked_parent / "consumption.sqlite3",
            hmac_key=_HMAC_KEY,
            timeout=5.0,
        )


def test_database_inode_replacement_fails_closed(tmp_path: Path) -> None:
    store, path = _store(tmp_path)
    original_inode = os.lstat(path).st_ino
    _, replacement = _store(tmp_path, name="replacement.sqlite3")
    os.replace(replacement, path)
    assert os.lstat(path).st_ino != original_inode

    with pytest.raises(ConsumptionStoreError, match="replaced"):
        store.status("tenant-a", "receipt-1")


def test_incompatible_user_version_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "future.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version = 999")

    with pytest.raises(ConsumptionStoreError, match="schema version"):
        ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY, timeout=5.0)


def test_incompatible_schema_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "wrong-schema.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE receipt_consumptions (tenant_id TEXT NOT NULL)")
        connection.execute("PRAGMA user_version = 1")

    with pytest.raises(ConsumptionStoreError):
        ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY, timeout=5.0)


def _replace_consumption_table(
    path: Path,
    *,
    include_primary_key: bool = True,
    include_nonce_unique: bool = True,
    include_idempotency_column: bool = True,
    include_idempotency_unique: bool = True,
    include_state_check: bool = True,
    primary_key_conflict_policy: str = "",
    nonce_conflict_policy: str = "",
    idempotency_conflict_policy: str = "",
) -> None:
    primary_key = (
        f", PRIMARY KEY (tenant_id, receipt_id) {primary_key_conflict_policy}"
        if include_primary_key
        else ""
    )
    nonce_unique = (
        f", UNIQUE (tenant_id, nonce_hash) {nonce_conflict_policy}" if include_nonce_unique else ""
    )
    idempotency_column = ", idempotency_digest TEXT NOT NULL" if include_idempotency_column else ""
    idempotency_unique = (
        f", UNIQUE (tenant_id, idempotency_digest) {idempotency_conflict_policy}"
        if include_idempotency_column and include_idempotency_unique
        else ""
    )
    state_check = (
        " CHECK (state IN ('RESERVED', 'SUCCEEDED', 'UNKNOWN'))" if include_state_check else ""
    )
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE receipt_consumptions")
        connection.execute(
            f"""
            CREATE TABLE receipt_consumptions (
                tenant_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                nonce_hash TEXT NOT NULL,
                receipt_hash TEXT NOT NULL,
                binding_hash TEXT NOT NULL{idempotency_column},
                attempt_id TEXT NOT NULL,
                state TEXT NOT NULL{state_check},
                reserved_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                recovery_authority TEXT,
                recovery_reason_code TEXT,
                recovery_evidence_digest TEXT
                {primary_key}{nonce_unique}{idempotency_unique}
            )
            """
        )


def test_schema_v3_fails_closed_without_automatic_migration(tmp_path: Path) -> None:
    _, path = _store(tmp_path)
    _replace_consumption_table(path, include_idempotency_column=False)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version = 3")

    with pytest.raises(ConsumptionStoreError, match="schema version: 3"):
        ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY)

    with sqlite3.connect(path) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()
        columns = connection.execute('PRAGMA table_info("receipt_consumptions")').fetchall()
    assert version == (3,)
    assert "idempotency_digest" not in {str(column[1]) for column in columns}


def test_new_store_uses_exact_schema_v4_idempotency_contract(
    tmp_path: Path,
) -> None:
    _, path = _store(tmp_path)

    with sqlite3.connect(path) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()
        columns = connection.execute('PRAGMA table_info("receipt_consumptions")').fetchall()
        indexes = connection.execute('PRAGMA index_list("receipt_consumptions")').fetchall()
        schema_sql_row = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'table' AND name = 'receipt_consumptions'
            """
        ).fetchone()
        unique_columns = {
            tuple(
                str(column[2])
                for column in connection.execute(f'PRAGMA index_info("{index[1]}")').fetchall()
            )
            for index in indexes
            if index[2] == 1
        }

    assert version == (4,)
    assert "idempotency_digest" in {str(column[1]) for column in columns}
    assert ("tenant_id", "idempotency_digest") in unique_columns
    assert schema_sql_row is not None
    assert "ON CONFLICT" not in str(schema_sql_row[0]).upper()


@pytest.mark.parametrize(
    "constraint",
    ["primary_key", "nonce", "idempotency"],
)
@pytest.mark.parametrize(
    "conflict_policy",
    [
        "ON CONFLICT REPLACE",
        "on/**/conflict/**/ignore",
        "ON\nCONFLICT\tFAIL",
        "on -- split keywords\n conflict rollback",
    ],
)
def test_schema_non_abort_conflict_policy_fails_closed_without_replacing_rows(
    tmp_path: Path,
    constraint: str,
    conflict_policy: str,
) -> None:
    _, path = _store(tmp_path)
    _replace_consumption_table(
        path,
        primary_key_conflict_policy=(conflict_policy if constraint == "primary_key" else ""),
        nonce_conflict_policy=conflict_policy if constraint == "nonce" else "",
        idempotency_conflict_policy=(conflict_policy if constraint == "idempotency" else ""),
    )
    original = (
        "tenant-control",
        "receipt-control",
        "1" * 64,
        _RECEIPT_HASH,
        _BINDING_HASH,
        "2" * 64,
        "attempt-control",
        ConsumptionState.RESERVED.value,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00Z",
        None,
        None,
        None,
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO receipt_consumptions (
                tenant_id, receipt_id, nonce_hash, receipt_hash, binding_hash,
                idempotency_digest, attempt_id, state, reserved_at, updated_at,
                recovery_authority, recovery_reason_code, recovery_evidence_digest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            original,
        )

    with pytest.raises(ConsumptionStoreError, match="must use ABORT conflict policy"):
        ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY)

    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            """
            SELECT tenant_id, receipt_id, nonce_hash, receipt_hash, binding_hash,
                   idempotency_digest, attempt_id, state, reserved_at, updated_at,
                   recovery_authority, recovery_reason_code, recovery_evidence_digest
            FROM receipt_consumptions
            """
        ).fetchall()
    assert rows == [original]


def test_schema_explicit_abort_conflict_policies_are_accepted(tmp_path: Path) -> None:
    store, path = _store(tmp_path)
    _replace_consumption_table(
        path,
        primary_key_conflict_policy="oN/**/cOnFlIcT/**/aBoRt",
        nonce_conflict_policy="ON\nCONFLICT\tABORT",
        idempotency_conflict_policy="on -- split keywords\n conflict abort",
    )
    with sqlite3.connect(path, isolation_level=None) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        store._write_state_root(connection, store._compute_state_root(connection))
        connection.commit()

    restarted = ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY)
    original = _reserve(restarted)

    with pytest.raises(ReceiptReplayError):
        _reserve(restarted, nonce="nonce-2", attempt_id="attempt-2")
    assert restarted.status("tenant-a", "receipt-1") == original


def test_schema_missing_consumption_primary_key_fails_closed(tmp_path: Path) -> None:
    _, path = _store(tmp_path)
    _replace_consumption_table(path, include_primary_key=False)

    with pytest.raises(ConsumptionStoreError, match="columns"):
        ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY)


def test_schema_missing_tenant_nonce_unique_fails_closed(tmp_path: Path) -> None:
    _, path = _store(tmp_path)
    _replace_consumption_table(path, include_nonce_unique=False)

    with pytest.raises(ConsumptionStoreError, match="nonce uniqueness"):
        ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY)


def test_schema_missing_idempotency_column_fails_closed(tmp_path: Path) -> None:
    _, path = _store(tmp_path)
    _replace_consumption_table(path, include_idempotency_column=False)

    with pytest.raises(ConsumptionStoreError, match="columns"):
        ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY)


def test_schema_missing_tenant_idempotency_unique_fails_closed(
    tmp_path: Path,
) -> None:
    _, path = _store(tmp_path)
    _replace_consumption_table(path, include_idempotency_unique=False)

    with pytest.raises(ConsumptionStoreError, match="idempotency uniqueness"):
        ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY)


def test_schema_missing_state_check_fails_closed(tmp_path: Path) -> None:
    _, path = _store(tmp_path)
    _replace_consumption_table(path, include_state_check=False)

    with pytest.raises(ConsumptionStoreError, match="state CHECK"):
        ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY)


def test_mutated_metadata_key_fingerprint_fails_closed(tmp_path: Path) -> None:
    _, path = _store(tmp_path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            UPDATE consumption_metadata
            SET metadata_value = ?
            WHERE metadata_key = 'hmac_key_fingerprint'
            """,
            ("0" * 64,),
        )

    with pytest.raises(ConsumptionStoreError, match="key mismatch"):
        ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY)


@pytest.mark.parametrize(
    "timeout",
    [
        0.0,
        -1.0,
        float("inf"),
        float("-inf"),
        float("nan"),
        cast(float, True),
        cast(float, False),
    ],
)
def test_invalid_timeout_fails_closed(tmp_path: Path, timeout: float) -> None:
    with pytest.raises(ConsumptionStoreError, match="timeout"):
        ReceiptConsumptionStore(
            tmp_path / "invalid-timeout.sqlite3",
            hmac_key=_HMAC_KEY,
            timeout=timeout,
        )


def test_corrupt_database_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "corrupt.sqlite3"
    path.write_bytes(b"not a sqlite database\x00with junk")

    with pytest.raises(ConsumptionStoreError):
        ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY, timeout=5.0)


@pytest.mark.parametrize("key", [b"", b"short", b"x" * 31])
def test_short_hmac_key_fails_closed(tmp_path: Path, key: bytes) -> None:
    with pytest.raises(ConsumptionStoreError, match="at least 32 bytes"):
        ReceiptConsumptionStore(tmp_path / "weak.sqlite3", hmac_key=key)


def test_required_anchor_refuses_missing_configuration(tmp_path: Path) -> None:
    with pytest.raises(ConsumptionStoreError, match="required"):
        ReceiptConsumptionStore(
            tmp_path / "required.sqlite3",
            hmac_key=_HMAC_KEY,
            require_trusted_anchor=True,
        )


def test_trusted_anchor_detects_old_database_rollback(tmp_path: Path) -> None:
    anchor = InMemoryAnchor()
    store, path = _store(tmp_path, anchor=anchor, require_anchor=True)
    snapshot = tmp_path / "old.sqlite3"
    shutil.copy2(path, snapshot)
    _reserve(store)
    os.replace(snapshot, path)

    with pytest.raises(ConsumptionStoreError, match="rollback suspected"):
        ReceiptConsumptionStore(
            path,
            hmac_key=_HMAC_KEY,
            state_anchor=anchor,
            anchor_namespace="test-anchor",
            require_trusted_anchor=True,
        )


def test_trusted_anchor_read_failure_fails_closed(tmp_path: Path) -> None:
    anchor = InMemoryAnchor()
    store, _ = _store(tmp_path, anchor=anchor, require_anchor=True)
    anchor.fail_reads = True

    with pytest.raises(ConsumptionStoreError, match="unavailable"):
        store.status("tenant-a", "receipt-1")


def test_trusted_anchor_write_failure_fail_stops_store(tmp_path: Path) -> None:
    anchor = InMemoryAnchor()
    store, _ = _store(tmp_path, anchor=anchor, require_anchor=True)
    anchor.fail_writes = True

    with pytest.raises(ConsumptionStoreError, match="after database commit"):
        _reserve(store)
    anchor.fail_writes = False
    with pytest.raises(ConsumptionStoreError, match="rollback suspected"):
        store.status("tenant-a", "receipt-1")


def test_invalid_persisted_state_row_fails_closed(tmp_path: Path) -> None:
    store, path = _store(tmp_path)
    _reserve(store)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            """
            UPDATE receipt_consumptions
            SET state = ?
            WHERE tenant_id = ? AND receipt_id = ?
            """,
            ("BROKEN", "tenant-a", "receipt-1"),
        )

    with pytest.raises(ConsumptionStoreError, match="state row"):
        store.status("tenant-a", "receipt-1")


def test_trusted_anchor_requires_stable_namespace(tmp_path: Path) -> None:
    with pytest.raises(ConsumptionStoreError, match="anchor_namespace"):
        ReceiptConsumptionStore(
            tmp_path / "missing-namespace.sqlite3",
            hmac_key=_HMAC_KEY,
            state_anchor=InMemoryAnchor(),
        )


def test_anchor_initial_state_binds_full_root_and_64_hex_store_id(
    tmp_path: Path,
) -> None:
    anchor = InMemoryAnchor()
    _store(tmp_path, anchor=anchor, require_anchor=True)

    state = anchor.states["test-anchor"]
    assert len(state.store_id) == 64
    assert len(state.chain_head) == 64
    assert len(state.state_root) == 64
    assert state.generation == 0


def test_anchor_namespace_cannot_initialize_a_second_database(tmp_path: Path) -> None:
    anchor = InMemoryAnchor()
    _store(tmp_path, anchor=anchor, name="first.sqlite3")

    with pytest.raises(ConsumptionStoreError, match="rollback suspected"):
        _store(tmp_path, anchor=anchor, name="second.sqlite3")


def test_anchor_detects_database_delete_and_recreate(tmp_path: Path) -> None:
    anchor = InMemoryAnchor()
    _, path = _store(tmp_path, anchor=anchor)
    path.unlink()

    with pytest.raises(ConsumptionStoreError, match="rollback suspected"):
        ReceiptConsumptionStore(
            path,
            hmac_key=_HMAC_KEY,
            state_anchor=anchor,
            anchor_namespace="test-anchor",
        )


def test_state_root_detects_selective_consumption_row_deletion(tmp_path: Path) -> None:
    anchor = InMemoryAnchor()
    store, path = _store(tmp_path, anchor=anchor)
    _reserve(store)
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM receipt_consumptions")

    with pytest.raises(ConsumptionStoreError, match="state root"):
        ReceiptConsumptionStore(
            path,
            hmac_key=_HMAC_KEY,
            state_anchor=anchor,
            anchor_namespace="test-anchor",
        )


def test_state_root_detects_selective_consumption_row_modification(
    tmp_path: Path,
) -> None:
    store, path = _store(tmp_path)
    _reserve(store)
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE receipt_consumptions SET binding_hash = 'tampered'")

    with pytest.raises(ConsumptionStoreError, match="state root"):
        store.status("tenant-a", "receipt-1")


def test_state_root_detects_idempotency_digest_row_modification(
    tmp_path: Path,
) -> None:
    store, path = _store(tmp_path)
    _reserve(store, idempotency_digest="d" * 64)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE receipt_consumptions SET idempotency_digest = ?",
            ("e" * 64,),
        )

    with pytest.raises(ConsumptionStoreError, match="state root"):
        store.status("tenant-a", "receipt-1")


def test_state_root_detects_revocation_row_deletion(tmp_path: Path) -> None:
    store, path = _store(tmp_path)
    store.revoke("tenant-a", "receipt-1")
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM receipt_revocations")

    with pytest.raises(ConsumptionStoreError, match="state root"):
        store.is_revoked("tenant-a", "receipt-1")


def test_recovery_proof_is_authenticated_across_restart(tmp_path: Path) -> None:
    anchor = InMemoryAnchor()
    store, path = _store(tmp_path, anchor=anchor)
    _reserve(store)
    recovered = store.recover_unknown(
        "tenant-a",
        "receipt-1",
        "attempt-1",
        recovery_authority="incident-commander",
        reason_code="owner-confirmed-dead",
        evidence_digest=_RECOVERY_DIGEST,
    )
    restarted = ReceiptConsumptionStore(
        path,
        hmac_key=_HMAC_KEY,
        state_anchor=anchor,
        anchor_namespace="test-anchor",
    )

    assert restarted.status("tenant-a", "receipt-1") == recovered


def test_schema_trigger_is_rejected(tmp_path: Path) -> None:
    _, path = _store(tmp_path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TRIGGER erase_old_receipts AFTER INSERT ON receipt_consumptions
            BEGIN DELETE FROM receipt_consumptions WHERE receipt_id <> NEW.receipt_id; END
            """
        )

    with pytest.raises(ConsumptionStoreError, match="schema object"):
        ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY)


def test_schema_view_is_rejected(tmp_path: Path) -> None:
    _, path = _store(tmp_path)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE VIEW receipt_projection AS SELECT * FROM receipt_consumptions")

    with pytest.raises(ConsumptionStoreError, match="schema object"):
        ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY)


def test_schema_user_index_is_rejected(tmp_path: Path) -> None:
    _, path = _store(tmp_path)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE INDEX attacker_index ON receipt_consumptions(updated_at)")

    with pytest.raises(ConsumptionStoreError, match="schema object"):
        ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY)


def test_schema_extra_table_is_rejected(tmp_path: Path) -> None:
    _, path = _store(tmp_path)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE attacker_state (value TEXT)")

    with pytest.raises(ConsumptionStoreError, match="table set"):
        ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY)


def test_external_anchor_detects_full_database_snapshot_rollback(
    tmp_path: Path,
) -> None:
    anchor = InMemoryAnchor()
    store, path = _store(tmp_path, anchor=anchor)
    snapshot = tmp_path / "anchored-snapshot.sqlite3"
    shutil.copy2(path, snapshot)
    _reserve(store)
    os.replace(snapshot, path)

    with pytest.raises(ConsumptionStoreError, match="rollback suspected"):
        ReceiptConsumptionStore(
            path,
            hmac_key=_HMAC_KEY,
            state_anchor=anchor,
            anchor_namespace="test-anchor",
        )


def test_external_anchor_ahead_of_database_fails_closed(tmp_path: Path) -> None:
    anchor = InMemoryAnchor()
    _, path = _store(tmp_path, anchor=anchor)
    current = anchor.states["test-anchor"]
    anchor.states["test-anchor"] = replace(
        current,
        generation=current.generation + 1,
    )

    with pytest.raises(ConsumptionStoreError, match="rollback suspected"):
        ReceiptConsumptionStore(
            path,
            hmac_key=_HMAC_KEY,
            state_anchor=anchor,
            anchor_namespace="test-anchor",
        )


def test_rejected_cas_poisoned_instance_and_database_ahead_fail_closed(
    tmp_path: Path,
) -> None:
    anchor = InMemoryAnchor()
    store, path = _store(tmp_path, anchor=anchor)
    anchor.reject_writes = True

    with pytest.raises(ConsumptionStoreError, match="after database commit"):
        _reserve(store)
    with pytest.raises(ConsumptionStoreError, match="fail-stopped"):
        store.status("tenant-a", "receipt-1")
    anchor.reject_writes = False
    with pytest.raises(ConsumptionStoreError, match="rollback suspected"):
        ReceiptConsumptionStore(
            path,
            hmac_key=_HMAC_KEY,
            state_anchor=anchor,
            anchor_namespace="test-anchor",
        )


def test_cas_exception_before_update_leaves_database_ahead(tmp_path: Path) -> None:
    anchor = InMemoryAnchor()
    store, path = _store(tmp_path, anchor=anchor)
    anchor.fail_writes = True

    with pytest.raises(ConsumptionStoreError, match="outcome is unknown"):
        _reserve(store)
    anchor.fail_writes = False
    with pytest.raises(ConsumptionStoreError, match="rollback suspected"):
        ReceiptConsumptionStore(
            path,
            hmac_key=_HMAC_KEY,
            state_anchor=anchor,
            anchor_namespace="test-anchor",
        )


def test_cas_exception_after_durable_update_reopens_safely(tmp_path: Path) -> None:
    anchor = InMemoryAnchor()
    store, path = _store(tmp_path, anchor=anchor)
    anchor.raise_after_write = True

    with pytest.raises(ConsumptionStoreError, match="outcome is unknown"):
        _reserve(store)
    anchor.raise_after_write = False
    restarted = ReceiptConsumptionStore(
        path,
        hmac_key=_HMAC_KEY,
        state_anchor=anchor,
        anchor_namespace="test-anchor",
    )
    assert restarted.status("tenant-a", "receipt-1") is not None


def test_anchored_concurrent_same_receipt_has_one_winner(tmp_path: Path) -> None:
    anchor = InMemoryAnchor()
    _, path = _store(tmp_path, anchor=anchor)
    stores = [
        ReceiptConsumptionStore(
            path,
            hmac_key=_HMAC_KEY,
            state_anchor=anchor,
            anchor_namespace="test-anchor",
        )
        for _ in range(16)
    ]
    barrier = Barrier(len(stores))

    def attempt(index: int) -> bool:
        barrier.wait()
        try:
            _reserve(stores[index], attempt_id=f"anchored-{index}")
        except ReceiptReplayError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=len(stores)) as executor:
        results = list(executor.map(attempt, range(len(stores))))

    assert sum(results) == 1


def test_anchored_concurrent_distinct_receipts_serialize_cas(tmp_path: Path) -> None:
    anchor = InMemoryAnchor()
    _, path = _store(tmp_path, anchor=anchor)
    stores = [
        ReceiptConsumptionStore(
            path,
            hmac_key=_HMAC_KEY,
            state_anchor=anchor,
            anchor_namespace="test-anchor",
        )
        for _ in range(8)
    ]
    barrier = Barrier(len(stores))

    def attempt(index: int) -> ConsumptionRecord:
        barrier.wait()
        return _reserve(
            stores[index],
            receipt_id=f"anchored-receipt-{index}",
            nonce=f"anchored-nonce-{index}",
            attempt_id=f"anchored-attempt-{index}",
        )

    with ThreadPoolExecutor(max_workers=len(stores)) as executor:
        records = list(executor.map(attempt, range(len(stores))))

    assert len(records) == len(stores)
    assert anchor.states["test-anchor"].generation == len(stores)


def test_local_state_root_detects_state_root_metadata_tamper(tmp_path: Path) -> None:
    store, path = _store(tmp_path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            UPDATE consumption_metadata SET metadata_value = ?
            WHERE metadata_key = 'state_root'
            """,
            ("f" * 64,),
        )

    with pytest.raises(ConsumptionStoreError, match="state root"):
        store.status("tenant-a", "receipt-1")


def test_local_mode_truthfully_disclaims_snapshot_rollback_resistance(
    tmp_path: Path,
) -> None:
    store, path = _store(tmp_path)
    first = _reserve(store)
    snapshot = tmp_path / "local-snapshot.sqlite3"
    shutil.copy2(path, snapshot)
    _reserve(
        store,
        receipt_id="receipt-2",
        nonce="nonce-2",
        attempt_id="attempt-2",
    )
    os.replace(snapshot, path)
    restarted = ReceiptConsumptionStore(path, hmac_key=_HMAC_KEY)

    assert "no-snapshot-rollback-resistance" in restarted.integrity_scope
    assert restarted.status("tenant-a", "receipt-1") == first
    assert restarted.status("tenant-a", "receipt-2") is None


def test_recovery_proof_row_modification_is_detected(tmp_path: Path) -> None:
    store, path = _store(tmp_path)
    _reserve(store)
    store.recover_unknown(
        "tenant-a",
        "receipt-1",
        "attempt-1",
        recovery_authority="incident-commander",
        reason_code="owner-confirmed-dead",
        evidence_digest=_RECOVERY_DIGEST,
    )
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE receipt_consumptions SET recovery_authority = 'attacker'")

    with pytest.raises(ConsumptionStoreError, match="state root"):
        store.status("tenant-a", "receipt-1")


def test_direct_consumption_store_rejects_proc_descriptor_alias() -> None:
    for root in ("/proc/self/fd/0", f"/proc/{os.getpid()}/fd/0"):
        with pytest.raises(ConsumptionStoreError, match="procfs"):
            ReceiptConsumptionStore(
                f"{root}/consumption.sqlite3",
                hmac_key=_HMAC_KEY,
            )


def test_attested_consumption_store_persists_and_shares_inode_relative_lock(
    tmp_path: Path,
) -> None:
    output = tmp_path / "attested-consumption"
    with PinnedOutputRoot.create(output) as pinned:
        first_directory = pinned.attest()
        second_directory = pinned.attest()
        try:
            first = ReceiptConsumptionStore.from_attested(
                first_directory,
                "consumption.sqlite3",
                hmac_key=_HMAC_KEY,
                anchor_namespace="fixture/consumption",
            )
            reserved = _reserve(first)
            second = ReceiptConsumptionStore.from_attested(
                second_directory,
                "consumption.sqlite3",
                hmac_key=_HMAC_KEY,
                anchor_namespace="fixture/consumption",
            )

            assert second.status("tenant-a", "receipt-1") == reserved
            assert first._operation_lock is second._operation_lock
        finally:
            first_directory.close()
            second_directory.close()


def test_attested_consumption_rejects_traversal_and_closed_capability(
    tmp_path: Path,
) -> None:
    output = tmp_path / "attested-consumption-closed"
    with PinnedOutputRoot.create(output) as pinned:
        directory = pinned.attest()
        with pytest.raises(RuntimeError, match="relative"):
            ReceiptConsumptionStore.from_attested(
                directory,
                "../consumption.sqlite3",
                hmac_key=_HMAC_KEY,
                anchor_namespace="fixture/consumption",
            )
        store = ReceiptConsumptionStore.from_attested(
            directory,
            "consumption.sqlite3",
            hmac_key=_HMAC_KEY,
            anchor_namespace="fixture/consumption",
        )
        directory.close()

        with pytest.raises(RuntimeError, match="closed"):
            store.status("tenant-a", "missing")


def test_attested_consumption_rejects_fake_proxy_and_nul_before_write(
    tmp_path: Path,
) -> None:
    from gove_zone.path_capability import AttestedDirectory

    class Proxy:
        def __init__(self, target: AttestedDirectory) -> None:
            self._target = target

        def __getattr__(self, name: str) -> object:
            return getattr(self._target, name)

    output = tmp_path / "attested-consumption-boundary"
    with PinnedOutputRoot.create(output) as pinned, pinned.attest() as directory:
        fake = object.__new__(AttestedDirectory)
        for candidate in (fake, Proxy(directory)):
            with pytest.raises(ConsumptionStoreError, match="exact registered live"):
                ReceiptConsumptionStore.from_attested(  # type: ignore[arg-type]
                    candidate,
                    "consumption.sqlite3",
                    hmac_key=_HMAC_KEY,
                    anchor_namespace="fixture/consumption",
                )
        with pytest.raises(RuntimeError, match="NUL"):
            ReceiptConsumptionStore.from_attested(
                directory,
                "prefix/\0consumption.sqlite3",
                hmac_key=_HMAC_KEY,
                anchor_namespace="fixture/consumption",
            )
        assert list(output.iterdir()) == []


def test_attested_consumption_detects_directory_replacement_before_transaction(
    tmp_path: Path,
) -> None:
    output = tmp_path / "attested-consumption-replaced"
    moved = tmp_path / "attested-consumption-original"
    with PinnedOutputRoot.create(output) as pinned, pinned.attest() as directory:
        store = ReceiptConsumptionStore.from_attested(
            directory,
            "consumption.sqlite3",
            hmac_key=_HMAC_KEY,
            anchor_namespace="fixture/consumption",
        )
        output.rename(moved)
        output.mkdir(mode=0o700)

        with pytest.raises(RuntimeError, match="identity changed"):
            store.status("tenant-a", "missing")

    assert list(output.iterdir()) == []
