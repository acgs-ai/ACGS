"""Tamper-evidence tests for the consumption ledger hash chain.

``test_receipt_consumption.py`` proves the *replay-blocking* contract through
the real ESCALATE→approve→resume gate. This file proves the *tamper-evidence*
contract of the ledger file itself: each entry is hash-chained to the prior one
(mirroring :class:`~gove_zone.audit.ChainHashAuditStore`), so an interior
delete / reorder / content edit is detectable, and :meth:`verify_ledger`
reports it. It drives the ledger mechanics directly with a minimal receipt
stand-in (the heavy real-receipt path is already covered elsewhere) so the
integrity properties are exercised in isolation.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from gove_zone import (
    GENESIS_HASH,
    ConsumptionLedgerError,
    ReceiptAlreadyUsedError,
    ReceiptConsumptionLedger,
    sha256_json,
)


@dataclasses.dataclass
class _FakeReceipt:
    """Minimal stand-in exposing only what ``consume`` reads."""

    audit_event_hash: str
    request_id: str = "req-1"
    tenant_id: str = "tenant-acme"
    actor: str = "agent-x"
    proposed_action: str = "write_file"

    def compute_hash(self) -> str:
        return "receipt-hash-" + self.audit_event_hash[:8]


def _anchor(label: str) -> str:
    # A 64-hex-ish anchor; only uniqueness and str-ness matter to the ledger.
    return (label * 64)[:64]


def _recompute_entry_hash(entry: dict) -> str:
    payload = {k: v for k, v in entry.items() if k != "entry_hash"}
    return sha256_json(payload)


def _read_lines(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _write_lines(path: Path, records: list[dict]) -> None:
    path.write_text(
        "".join(
            json.dumps(r, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
            for r in records
        ),
        encoding="utf-8",
    )


# --- U1: chain on write -------------------------------------------------------


def test_first_entry_chains_from_genesis(tmp_path):
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    entry = ledger.consume(_FakeReceipt(_anchor("a")))
    assert entry["previous_hash"] == GENESIS_HASH
    assert entry["entry_hash"] == _recompute_entry_hash(entry)


def test_entries_link_sequentially(tmp_path):
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    e0 = ledger.consume(_FakeReceipt(_anchor("a")))
    e1 = ledger.consume(_FakeReceipt(_anchor("b")))
    e2 = ledger.consume(_FakeReceipt(_anchor("c")))
    assert e0["previous_hash"] == GENESIS_HASH
    assert e1["previous_hash"] == e0["entry_hash"]
    assert e2["previous_hash"] == e1["entry_hash"]
    for e in (e0, e1, e2):
        assert e["entry_hash"] == _recompute_entry_hash(e)


def test_consumed_key_is_bound_into_entry_hash(tmp_path):
    # Editing the burn anchor in a written line breaks the recomputed entry_hash:
    # the consumed_key is inside the hashed payload, so the chain binds it.
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path)
    ledger.consume(_FakeReceipt(_anchor("a")))
    [stored] = _read_lines(path)
    tampered = dict(stored, consumed_key=_anchor("z"))
    assert _recompute_entry_hash(tampered) != tampered["entry_hash"]


def test_replay_same_anchor_still_blocked_with_chaining(tmp_path):
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    ledger.consume(_FakeReceipt(_anchor("a")))
    with pytest.raises(ReceiptAlreadyUsedError):
        ledger.consume(_FakeReceipt(_anchor("a")))


def test_consume_return_contract_preserved(tmp_path):
    # Existing fields stay; chaining fields are additive.
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    entry = ledger.consume(_FakeReceipt(_anchor("a")))
    for key in (
        "consumed_key",
        "receipt_hash",
        "request_id",
        "tenant_id",
        "actor",
        "proposed_action",
        "consumed_at",
        "previous_hash",
        "entry_hash",
    ):
        assert key in entry


# --- U2: verify_ledger --------------------------------------------------------


def _seed(path: Path, n: int) -> ReceiptConsumptionLedger:
    ledger = ReceiptConsumptionLedger(path)
    for i in range(n):
        ledger.consume(_FakeReceipt(_anchor(chr(ord("a") + i))))
    return ledger


def test_verify_clean_ledger_valid(tmp_path):
    path = tmp_path / "consumed.jsonl"
    ledger = _seed(path, 3)
    report = ledger.verify_ledger()
    assert report["valid"] is True
    assert report["checked"] == 3
    assert report["failures"] == []
    assert report["unverified_legacy"] == 0
    assert report["last_hash"] == _read_lines(path)[-1]["entry_hash"]


def test_verify_interior_delete_detected(tmp_path):
    path = tmp_path / "consumed.jsonl"
    _seed(path, 3)
    records = _read_lines(path)
    _write_lines(path, [records[0], records[2]])  # drop the middle
    report = ReceiptConsumptionLedger(path).verify_ledger()
    assert report["valid"] is False
    assert any(f["type"] == "previous_hash_mismatch" for f in report["failures"])


def test_verify_reorder_detected(tmp_path):
    path = tmp_path / "consumed.jsonl"
    _seed(path, 3)
    records = _read_lines(path)
    _write_lines(path, [records[0], records[2], records[1]])
    report = ReceiptConsumptionLedger(path).verify_ledger()
    assert report["valid"] is False
    assert report["checked"] == 3
    assert sum(1 for f in report["failures"] if f["type"] == "previous_hash_mismatch") >= 1


def test_verify_legacy_after_chain_detected(tmp_path):
    # The un-burn downgrade vector: append an UNCHAINED line after chained
    # entries to make a deletion look like a benign legacy tail. It must be
    # flagged, not silently absorbed into ``unverified_legacy``.
    path = tmp_path / "consumed.jsonl"
    _seed(path, 2)
    records = _read_lines(path)
    legacy_tail = {
        "consumed_key": _anchor("z"),
        "receipt_hash": "rh-z",
        "request_id": "r",
        "tenant_id": "t",
        "actor": "a",
        "proposed_action": "write_file",
        "consumed_at": "2026-01-01T00:00:00+00:00",
    }
    _write_lines(path, [*records, legacy_tail])
    report = ReceiptConsumptionLedger(path).verify_ledger()
    assert report["valid"] is False
    assert any(f["type"] == "legacy_after_chain" for f in report["failures"])


def test_verify_full_strip_to_legacy_caught_by_high_water_mark(tmp_path):
    # Stripping every chain field off a previously-chained ledger makes it look
    # all-legacy: verify_ledger() alone reports checked==0 (it cannot tell a
    # genuine pre-chaining ledger from a maliciously stripped one). The external
    # high-water-mark — the same defense documented for tail truncation — catches
    # it, because the walked tail collapses to GENESIS.
    path = tmp_path / "consumed.jsonl"
    ledger = _seed(path, 3)
    real_last = ledger.verify_ledger()["last_hash"]
    stripped = [
        {k: v for k, v in r.items() if k not in ("previous_hash", "entry_hash")}
        for r in _read_lines(path)
    ]
    _write_lines(path, stripped)
    bare = ReceiptConsumptionLedger(path)

    assert bare.verify_ledger()["checked"] == 0  # the limitation, made explicit
    report = bare.verify_ledger(expected_last_hash=real_last)
    assert report["valid"] is False
    assert any(f["type"] == "last_hash_mismatch" for f in report["failures"])


def test_verify_content_edit_detected(tmp_path):
    path = tmp_path / "consumed.jsonl"
    _seed(path, 3)
    records = _read_lines(path)
    records[1] = dict(records[1], actor="impostor")  # edit, do NOT recompute hash
    _write_lines(path, records)
    report = ReceiptConsumptionLedger(path).verify_ledger()
    assert report["valid"] is False
    assert any(f["type"] == "entry_hash_mismatch" for f in report["failures"])


def test_verify_tail_truncation_needs_high_water_mark(tmp_path):
    path = tmp_path / "consumed.jsonl"
    _seed(path, 3)
    records = _read_lines(path)
    pre_truncation_last = records[-1]["entry_hash"]
    _write_lines(path, records[:-1])  # drop the last entry
    ledger = ReceiptConsumptionLedger(path)

    # Without an external high-water-mark, a truncated tail is a valid shorter
    # chain — honestly documents the limitation.
    assert ledger.verify_ledger()["valid"] is True
    # With the real pre-truncation hash, truncation is caught.
    report = ledger.verify_ledger(expected_last_hash=pre_truncation_last)
    assert report["valid"] is False
    assert any(f["type"] == "last_hash_mismatch" for f in report["failures"])


def test_verify_leading_legacy_entries(tmp_path):
    path = tmp_path / "consumed.jsonl"
    # Two unchained legacy lines (old format, no previous_hash/entry_hash) ...
    legacy = [
        {
            "consumed_key": _anchor("x"),
            "receipt_hash": "rh-x",
            "request_id": "r",
            "tenant_id": "t",
            "actor": "a",
            "proposed_action": "write_file",
            "consumed_at": "2026-01-01T00:00:00+00:00",
        },
        {
            "consumed_key": _anchor("y"),
            "receipt_hash": "rh-y",
            "request_id": "r",
            "tenant_id": "t",
            "actor": "a",
            "proposed_action": "write_file",
            "consumed_at": "2026-01-01T00:00:01+00:00",
        },
    ]
    _write_lines(path, legacy)
    # ... then chained burns appended onto the legacy tail.
    ledger = ReceiptConsumptionLedger(path)
    ledger.consume(_FakeReceipt(_anchor("a")))
    ledger.consume(_FakeReceipt(_anchor("b")))

    report = ledger.verify_ledger()
    assert report["unverified_legacy"] == 2
    assert report["checked"] == 2
    assert report["valid"] is True


def test_verify_corrupt_json_raises(tmp_path):
    path = tmp_path / "consumed.jsonl"
    _seed(path, 1)
    with path.open("a", encoding="utf-8") as fh:
        fh.write("this is not json\n")
    with pytest.raises(ConsumptionLedgerError):
        ReceiptConsumptionLedger(path).verify_ledger()


# --- U4: seal() migration -----------------------------------------------------


def _legacy_record(label: str) -> dict:
    return {
        "consumed_key": _anchor(label),
        "receipt_hash": "rh-" + label,
        "request_id": "r",
        "tenant_id": "t",
        "actor": "a",
        "proposed_action": "write_file",
        "consumed_at": "2026-01-01T00:00:00+00:00",
    }


def test_seal_unchained_then_valid(tmp_path):
    path = tmp_path / "consumed.jsonl"
    legacy = [_legacy_record("a"), _legacy_record("b"), _legacy_record("c")]
    _write_lines(path, legacy)
    ledger = ReceiptConsumptionLedger(path)

    ledger.seal()
    report = ledger.verify_ledger()
    assert report["valid"] is True
    assert report["unverified_legacy"] == 0
    assert report["checked"] == 3
    keys = [r["consumed_key"] for r in _read_lines(path)]
    assert keys == [_anchor("a"), _anchor("b"), _anchor("c")]


def test_seal_is_idempotent(tmp_path):
    path = tmp_path / "consumed.jsonl"
    _write_lines(path, [_legacy_record("a"), _legacy_record("b")])
    ledger = ReceiptConsumptionLedger(path)
    ledger.seal()
    first = _read_lines(path)
    ledger.seal()
    second = _read_lines(path)
    assert first == second
    assert ledger.verify_ledger()["valid"] is True


def test_seal_atomic_on_failure(tmp_path, monkeypatch):
    path = tmp_path / "consumed.jsonl"
    original = [_legacy_record("a"), _legacy_record("b")]
    _write_lines(path, original)
    before = path.read_text(encoding="utf-8")

    def _boom(*_a, **_k):
        raise OSError("simulated replace failure")

    monkeypatch.setattr("gove_zone.consumption.os.replace", _boom)
    with pytest.raises(ConsumptionLedgerError):
        ReceiptConsumptionLedger(path).seal()

    # Original file untouched; no stray temp file left behind.
    assert path.read_text(encoding="utf-8") == before
    assert list(tmp_path.glob("*.seal-tmp")) == []


def test_consume_after_seal_chains_on_tail(tmp_path):
    path = tmp_path / "consumed.jsonl"
    _write_lines(path, [_legacy_record("a"), _legacy_record("b")])
    ledger = ReceiptConsumptionLedger(path)
    ledger.seal()
    sealed_last = _read_lines(path)[-1]["entry_hash"]

    entry = ledger.consume(_FakeReceipt(_anchor("c")))
    assert entry["previous_hash"] == sealed_last
    assert ledger.verify_ledger()["valid"] is True
