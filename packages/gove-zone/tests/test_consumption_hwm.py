"""Durable high-water-mark (HWM) checkpoint for the consumption ledger.

#120 exposed ``verify_ledger(expected_last_hash=...)`` so an operator *could*
detect tail truncation / strip-to-legacy — but only by storing the last
``entry_hash`` themselves. This persists it: an opt-in ``<ledger>.hwm`` sidecar
that ``consume()`` advances under the burn lock, and that ``verify_ledger()``
auto-consults when present, so truncating the ledger tail is caught without
external bookkeeping.

Honest boundary: the sidecar shares the ledger's storage. An attacker who can
rewrite both consistently is not stopped — the value is that truncating the
ledger *alone* (or an accidental truncation) is now detected, and the sidecar
can be placed on more-protected/append-only storage to raise the bar further.
"""

from __future__ import annotations

import dataclasses

import pytest

from gove_zone import (
    GENESIS_HASH,
    ConsumptionLedgerError,
    ReceiptAlreadyUsedError,
    ReceiptConsumptionLedger,
)


@dataclasses.dataclass
class _FakeReceipt:
    audit_event_hash: str
    request_id: str = "req-1"
    tenant_id: str = "tenant-acme"
    actor: str = "agent-x"
    proposed_action: str = "write_file"

    def compute_hash(self) -> str:
        return "receipt-hash-" + self.audit_event_hash[:8]


def _anchor(label: str) -> str:
    return (label * 64)[:64]


def _read_last_entry_hash(path) -> str:
    import json

    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return json.loads(lines[-1])["entry_hash"]


# --- checkpoint maintenance ---------------------------------------------------


def test_checkpoint_written_on_consume(tmp_path):
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path, checkpoint=True)
    ledger.consume(_FakeReceipt(_anchor("a")))
    ledger.consume(_FakeReceipt(_anchor("b")))
    hwm_path = tmp_path / "consumed.jsonl.hwm"
    assert hwm_path.exists()
    assert ledger.checkpoint_hash() == _read_last_entry_hash(path)


def test_checkpoint_advances_each_burn(tmp_path):
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path, checkpoint=True)
    ledger.consume(_FakeReceipt(_anchor("a")))
    first = ledger.checkpoint_hash()
    ledger.consume(_FakeReceipt(_anchor("b")))
    second = ledger.checkpoint_hash()
    assert first != second
    assert second == _read_last_entry_hash(path)


def test_no_checkpoint_by_default(tmp_path):
    # Default (checkpoint=False) writes no sidecar and changes nothing.
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path)
    ledger.consume(_FakeReceipt(_anchor("a")))
    assert not (tmp_path / "consumed.jsonl.hwm").exists()
    assert ledger.checkpoint_hash() is None


def test_checkpoint_atomic_no_tmp_leftover(tmp_path):
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path, checkpoint=True)
    ledger.consume(_FakeReceipt(_anchor("a")))
    assert list(tmp_path.glob("*.hwm.tmp")) == []


# --- verify auto-consults the checkpoint --------------------------------------


def _seed(path, n, *, checkpoint):
    ledger = ReceiptConsumptionLedger(path, checkpoint=checkpoint)
    for i in range(n):
        ledger.consume(_FakeReceipt(_anchor(chr(ord("a") + i))))
    return ledger


def test_verify_clean_with_checkpoint_valid(tmp_path):
    path = tmp_path / "consumed.jsonl"
    ledger = _seed(path, 3, checkpoint=True)
    report = ledger.verify_ledger()
    assert report["valid"] is True
    assert report["checkpoint"] == ledger.checkpoint_hash()


def test_verify_auto_detects_tail_truncation_via_checkpoint(tmp_path):
    # The headline win: with a persisted HWM, verify_ledger() catches truncation
    # WITHOUT the caller passing expected_last_hash.
    import json

    path = tmp_path / "consumed.jsonl"
    _seed(path, 3, checkpoint=True)
    records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    path.write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in records[:-1]),  # drop tail
        encoding="utf-8",
    )
    # A fresh instance (even checkpoint=False) auto-consults the existing sidecar.
    report = ReceiptConsumptionLedger(path).verify_ledger()
    assert report["valid"] is False
    assert any(f["type"] == "last_hash_mismatch" for f in report["failures"])


def test_explicit_expected_last_hash_overrides_checkpoint(tmp_path):
    path = tmp_path / "consumed.jsonl"
    ledger = _seed(path, 2, checkpoint=True)
    real = ledger.checkpoint_hash()
    # Passing the real HWM explicitly still validates; a wrong one fails — proves
    # the explicit arg takes precedence over the stored sidecar.
    assert ledger.verify_ledger(expected_last_hash=real)["valid"] is True
    bad = ledger.verify_ledger(expected_last_hash="0" * 64)
    assert bad["valid"] is False
    assert any(f["type"] == "last_hash_mismatch" for f in bad["failures"])


def test_verify_without_checkpoint_skips_hwm_check(tmp_path):
    # No sidecar -> no auto HWM check -> truncation is NOT detected (the #120
    # baseline limitation, preserved when checkpointing is off).
    import json

    path = tmp_path / "consumed.jsonl"
    _seed(path, 3, checkpoint=False)
    records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    path.write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in records[:-1]),
        encoding="utf-8",
    )
    report = ReceiptConsumptionLedger(path).verify_ledger()
    assert report["valid"] is True  # undetected without a checkpoint
    assert report["checkpoint"] is None


# --- seal keeps the checkpoint consistent -------------------------------------


def test_seal_updates_checkpoint(tmp_path):
    import json

    path = tmp_path / "consumed.jsonl"
    # Legacy unchained entries + checkpoint enabled.
    legacy = [
        {
            "consumed_key": _anchor(c),
            "receipt_hash": "rh",
            "request_id": "r",
            "tenant_id": "t",
            "actor": "a",
            "proposed_action": "write_file",
            "consumed_at": "2026-01-01T00:00:00+00:00",
        }
        for c in ("a", "b")
    ]
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in legacy), encoding="utf-8")
    ledger = ReceiptConsumptionLedger(path, checkpoint=True)
    ledger.seal()
    assert ledger.checkpoint_hash() == _read_last_entry_hash(path)
    assert ledger.verify_ledger()["valid"] is True


def test_consume_after_seal_advances_checkpoint(tmp_path):
    path = tmp_path / "consumed.jsonl"
    ledger = _seed(path, 2, checkpoint=True)
    ledger.seal()
    sealed_hwm = ledger.checkpoint_hash()
    ledger.consume(_FakeReceipt(_anchor("z")))
    assert ledger.checkpoint_hash() != sealed_hwm
    assert ledger.checkpoint_hash() == _read_last_entry_hash(path)
    assert ledger.verify_ledger()["valid"] is True


# --- fail-closed + edge cases -------------------------------------------------


def test_checkpoint_write_failure_fails_burn_closed(tmp_path, monkeypatch):
    # The security-load-bearing path: if the sidecar write fails, consume() must
    # raise (refuse execution) — and because the entry is already durable, the
    # receipt stays burned, so there is no replay window. (Guards the subtle
    # ConsumptionLedgerError <: ReceiptValidationError routing in consume().)
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path, checkpoint=True)

    def _boom(*_a, **_k):
        raise OSError("simulated sidecar replace failure")

    monkeypatch.setattr("gove_zone.consumption.os.replace", _boom)
    with pytest.raises(ConsumptionLedgerError):
        ledger.consume(_FakeReceipt(_anchor("a")))

    # Entry already fsync'd before the checkpoint write -> receipt stays burned.
    assert path.exists()
    assert ledger.is_consumed(_anchor("a"))

    # With the failure cleared, a retry of the same receipt still refuses
    # (already burned) and never re-runs the side effect — no replay window.
    monkeypatch.undo()
    with pytest.raises(ReceiptAlreadyUsedError):
        ledger.consume(_FakeReceipt(_anchor("a")))


def test_seal_empty_ledger_with_checkpoint(tmp_path):
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path, checkpoint=True)
    ledger.seal()  # nothing to seal
    assert ledger.checkpoint_hash() == GENESIS_HASH
    assert ledger.verify_ledger()["valid"] is True
