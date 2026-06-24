"""Gate-entry reason codes — single-use replay + fail-closed ledger errors.

These reach the **consumption ledger**, not ``DecisionReceipt.verify()`` (which is stateless),
so they are driven through ``ReceiptConsumptionLedger.consume()`` — the unit
``execute_with_receipt`` invokes after a receipt verifies. Crypto-free (unsigned receipts).

Covers the two ``ReceiptValidationError`` subclasses whose ``reason_code`` defaults live in
``errors.py``: ``RECEIPT_ALREADY_USED`` and ``CONSUMPTION_LEDGER_UNPROVABLE``. The latter is the
spec's "single most important security property": if freshness cannot be *proven*, the gate must
fail closed (reject), never degrade to stateless/replayable verification.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gove_zone import (
    Decision,
    DecisionReceipt,
    DecisionRecord,
    ReceiptConsumptionLedger,
    Validator,
)
from gove_zone.decision import sha256_json
from gove_zone.errors import (
    ConsumptionLedgerError,
    ReceiptAlreadyUsedError,
    ReceiptRejectionReason,
)


def _receipt() -> DecisionReceipt:
    """A valid unsigned receipt with a non-empty audit anchor (the ledger key)."""
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool="runtime.file.write",
        argument_hash=sha256_json({"path": "safe.txt"}),
        policy_version="v1",
        event_id="ev_gate",
        actor="agent-1",
        timestamp_iso="2026-01-01T00:00:00+00:00",
    )
    return DecisionReceipt.from_record(
        record=record,
        audit_hash="audit-anchor-1",
        previous_audit_hash="prev",
        tenant_id="tenant-A",
        execution_boundary="local-sandbox",
        policy_bundle_id="policy-bundle",
        policy_hash="policy-hash",
        request_id="req-123",
        validator=Validator("constitutional-council"),
        authority="tenant-A/write-grant",
        signer=None,
    )


def test_replayed_receipt_reason_code(tmp_path: Path) -> None:
    """Second presentation of the same audit anchor is rejected as already-used."""
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    receipt = _receipt()
    ledger.consume(receipt)  # first use burns the anchor
    with pytest.raises(ReceiptAlreadyUsedError) as excinfo:
        ledger.consume(receipt)  # replay
    assert excinfo.value.reason_code == ReceiptRejectionReason.RECEIPT_ALREADY_USED


def test_unprovable_ledger_fails_closed(tmp_path: Path) -> None:
    """A corrupt ledger cannot prove freshness — the gate must REJECT, not fail open."""
    path = tmp_path / "consumed.jsonl"
    path.write_text("this is not json\n", encoding="utf-8")
    ledger = ReceiptConsumptionLedger(path)
    with pytest.raises(ConsumptionLedgerError) as excinfo:
        ledger.consume(_receipt())
    assert excinfo.value.reason_code == ReceiptRejectionReason.CONSUMPTION_LEDGER_UNPROVABLE
