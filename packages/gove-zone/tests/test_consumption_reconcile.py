"""Audit-chain reconciliation for the consumption ledger.

Hash-chaining (test_consumption_tamper.py) makes the ledger *internally*
tamper-evident, but it cannot tell whether a burned ``consumed_key`` was ever a
*real* decision. ``reconcile(audit_store)`` closes that gap: it cross-checks
every burn against the audit chain's ``event_hash`` set, detecting a **forged /
orphan burn** — a ledger entry whose ``consumed_key`` corresponds to no audit
event (e.g. a fabricated burn written to deny a legitimate receipt, or a burn
left behind after its audit event was dropped).
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from gove_zone import (
    ChainHashAuditStore,
    ConsumptionLedgerError,
    Decision,
    DecisionRecord,
    ReceiptConsumptionLedger,
    sha256_json,
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


def _audit_with_events(tmp_path, n: int) -> tuple[ChainHashAuditStore, list[str]]:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    hashes: list[str] = []
    for i in range(n):
        record = DecisionRecord(
            decision=Decision.ALLOW,
            tool="write_file",
            argument_hash=sha256_json({"i": i}),
            policy_version="v0",
            event_id=f"e{i}",
        )
        event = audit.append(record)
        hashes.append(str(event["event_hash"]))
    return audit, hashes


def test_reconcile_all_burns_match_audit(tmp_path):
    audit, hashes = _audit_with_events(tmp_path, 2)
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    for h in hashes:
        ledger.consume(_FakeReceipt(h))
    report = ledger.reconcile(audit)
    assert report["valid"] is True
    assert report["checked"] == 2
    assert report["unmatched"] == []
    assert report["audit_events"] == 2


def test_reconcile_forged_burn_detected(tmp_path):
    audit, hashes = _audit_with_events(tmp_path, 1)
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    ledger.consume(_FakeReceipt(hashes[0]))  # real audit anchor
    ledger.consume(_FakeReceipt("f" * 64))  # forged — no such audit event
    report = ledger.reconcile(audit)
    assert report["valid"] is False
    assert report["checked"] == 2
    assert len(report["unmatched"]) == 1
    assert report["unmatched"][0]["consumed_key"] == "f" * 64


def test_reconcile_empty_ledger_valid(tmp_path):
    audit, _ = _audit_with_events(tmp_path, 1)
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    report = ledger.reconcile(audit)
    assert report["valid"] is True
    assert report["checked"] == 0
    assert report["unmatched"] == []


def test_reconcile_empty_audit_flags_every_burn(tmp_path):
    empty_audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    ledger.consume(_FakeReceipt("a" * 64))
    report = ledger.reconcile(empty_audit)
    assert report["valid"] is False
    assert len(report["unmatched"]) == 1
    assert report["audit_events"] == 0


def test_reconcile_mixed_only_forged_unmatched(tmp_path):
    audit, hashes = _audit_with_events(tmp_path, 3)
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    ledger.consume(_FakeReceipt(hashes[0]))
    ledger.consume(_FakeReceipt("d" * 64))  # forged
    ledger.consume(_FakeReceipt(hashes[2]))
    report = ledger.reconcile(audit)
    assert report["valid"] is False
    assert report["checked"] == 3
    assert {u["consumed_key"] for u in report["unmatched"]} == {"d" * 64}


def test_reconcile_corrupt_ledger_raises(tmp_path):
    audit, _ = _audit_with_events(tmp_path, 1)
    path = tmp_path / "consumed.jsonl"
    path.write_text("this is not json\n", encoding="utf-8")
    with pytest.raises(ConsumptionLedgerError):
        ReceiptConsumptionLedger(path).reconcile(audit)


def test_reconcile_none_consumed_key_is_unmatched(tmp_path):
    # Defense-in-depth: consume() rejects an empty anchor, so no real record has
    # a None consumed_key — but if one ever appears, it must reconcile as
    # unmatched (None not in valid_hashes), never silently matched.
    audit, _ = _audit_with_events(tmp_path, 1)
    path = tmp_path / "consumed.jsonl"
    path.write_text(
        json.dumps({"receipt_hash": "rh", "previous_hash": "0" * 64}) + "\n",
        encoding="utf-8",
    )
    report = ReceiptConsumptionLedger(path).reconcile(audit)
    assert report["valid"] is False
    assert report["checked"] == 1
    assert report["unmatched"][0]["consumed_key"] is None


def test_reconcile_audit_event_without_event_hash_excluded(tmp_path):
    # An audit event lacking a str event_hash is excluded from valid_hashes, so
    # reconcile stays strict (fail-closed) rather than counting it as a match.
    audit, hashes = _audit_with_events(tmp_path, 1)
    with (tmp_path / "audit.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"event_id": "noev", "previous_hash": hashes[0]}) + "\n")
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    ledger.consume(_FakeReceipt(hashes[0]))  # the real burn still matches
    report = ledger.reconcile(audit)
    assert report["valid"] is True
    assert report["audit_events"] == 1  # malformed audit event not counted
