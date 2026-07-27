"""Tests for the formalized named-contract layer (gove_zone.contracts).

These prove the additive typed vocabulary behaves correctly and that
``ReceiptVerifier`` is the same fail-closed gate as ``DecisionReceipt.verify``
(no second, weaker enforcement path).
"""

from __future__ import annotations

import dataclasses

import pytest

from gove_zone import (
    AuditEvent,
    Decision,
    DecisionReceipt,
    DecisionRecord,
    ExecutionBoundary,
    GovernanceRequest,
    PolicyBundleRef,
    ProposedAction,
    ReceiptRejectionReason,
    ReceiptValidationError,
    ReceiptVerifier,
    TenantPolicyBinding,
    Validator,
)


def _allow_receipt(tenant_id: str = "tenant-A") -> DecisionReceipt:
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool="runtime.file.write",
        argument_hash="hash",
        policy_version="v1",
        event_id="ev_1",
    )
    return DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev_audit_hash",
        tenant_id=tenant_id,
        execution_boundary="local-sandbox",
        policy_bundle_id="bundle-A",
        policy_hash="policy-hash",
        request_id="req-1",
        validator=Validator("validator-1"),
        authority="tenant-A/write-grant",
    )


# --- value objects -------------------------------------------------------


def test_proposed_action_summary_is_log_safe() -> None:
    action = ProposedAction(tool="write_file", args={"path": "/tmp/x", "content": "secret"})
    # Summary names the fields, never their values.
    assert action.summary() == "write_file(content, path)"
    assert "secret" not in action.summary()


def test_execution_boundary_is_a_str_newtype() -> None:
    boundary = ExecutionBoundary("local-sandbox")
    assert boundary == "local-sandbox"


def test_governance_request_requires_tenant_and_request_id() -> None:
    action = ProposedAction(tool="t", args={})
    with pytest.raises(ValueError, match="tenant_id is required"):
        GovernanceRequest(
            tenant_id="",
            actor="a",
            request_id="r",
            proposed_action=action,
            execution_boundary="b",
        )
    with pytest.raises(ValueError, match="request_id is required"):
        GovernanceRequest(
            tenant_id="t",
            actor="a",
            request_id="",
            proposed_action=action,
            execution_boundary="b",
        )


def test_tenant_policy_binding_requires_tenant() -> None:
    ref = PolicyBundleRef(bundle_id="b", version="v1", policy_hash="h")
    binding = TenantPolicyBinding(tenant_id="tenant-A", policy_bundle=ref)
    assert binding.policy_bundle.bundle_id == "b"
    with pytest.raises(ValueError, match="tenant_id is required"):
        TenantPolicyBinding(tenant_id="", policy_bundle=ref)


# --- ReceiptVerifier: same gate as DecisionReceipt.verify ----------------


def test_verifier_accepts_valid_receipt() -> None:
    verifier = ReceiptVerifier(
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_actor="anonymous",
        require_signature=False,  # explicit dev mode (unsigned)
    )
    verifier.verify(_allow_receipt(), expected_action="runtime.file.write")
    assert verifier.is_valid(_allow_receipt(), expected_action="runtime.file.write")


def test_verifier_rejects_none_receipt() -> None:
    verifier = ReceiptVerifier(
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_actor="anonymous",
        require_signature=False,  # explicit dev mode (unsigned)
    )
    with pytest.raises(ReceiptValidationError, match="No receipt provided"):
        verifier.verify(None)
    assert verifier.is_valid(None) is False


def test_verifier_rejects_wrong_tenant() -> None:
    verifier = ReceiptVerifier(
        expected_tenant_id="tenant-B",
        expected_execution_boundary="local-sandbox",
        expected_actor="anonymous",
        require_signature=False,  # explicit dev mode (unsigned)
    )
    with pytest.raises(ReceiptValidationError, match="Tenant mismatch"):
        verifier.verify(_allow_receipt(tenant_id="tenant-A"))


def test_verifier_rejects_tampered_receipt() -> None:
    verifier = ReceiptVerifier(
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_actor="anonymous",
        require_signature=False,  # explicit dev mode (unsigned)
    )
    tampered = dataclasses.replace(_allow_receipt(), actor="mallory")
    with pytest.raises(ReceiptValidationError, match="receipt_hash mismatch"):
        verifier.verify(tampered)


# --- AuditEvent projection ----------------------------------------------


def test_audit_event_joins_receipt_and_chain_event() -> None:
    receipt = _allow_receipt()
    chain_event = {
        "event_id": receipt.receipt_id,
        "previous_hash": "0" * 64,
        "event_hash": receipt.audit_event_hash,
        "timestamp_iso": "2026-05-28T00:00:00+00:00",
        "args": {"content": "secret"},
        "payload": {"raw": "secret"},
    }
    event = AuditEvent.from_receipt_and_event(receipt, chain_event)
    assert event.event_id == receipt.receipt_id
    assert event.event_hash == receipt.audit_event_hash
    # Governance linkage comes from the receipt, not the bare chain record.
    assert event.tenant_id == "tenant-A"
    assert event.request_id == "req-1"
    assert event.receipt_id == receipt.receipt_id
    assert event.decision == "allow"
    assert event.action_summary == "runtime.file.write"
    assert set(event.to_dict()) >= {
        "event_id",
        "request_id",
        "receipt_id",
        "tenant_id",
        "actor",
        "action_summary",
        "decision",
        "policy_bundle_id",
        "timestamp",
        "previous_hash",
        "event_hash",
    }
    assert "args" not in event.to_dict()
    assert "payload" not in event.to_dict()


def test_audit_event_rejects_event_id_mismatch() -> None:
    receipt = _allow_receipt()
    chain_event = {
        "event_id": "ev_wrong",
        "previous_hash": receipt.previous_audit_hash,
        "event_hash": receipt.audit_event_hash,
        "timestamp_iso": "2026-05-28T00:00:00+00:00",
    }

    with pytest.raises(ReceiptValidationError, match="Audit event id mismatch") as exc:
        AuditEvent.from_receipt_and_event(receipt, chain_event)
    assert exc.value.reason_code is ReceiptRejectionReason.AUDIT_HASH_MISMATCH


@pytest.mark.parametrize("event_id", [None, ""])
def test_audit_event_rejects_missing_or_empty_event_id(event_id: str | None) -> None:
    receipt = _allow_receipt()
    chain_event = {
        "previous_hash": receipt.previous_audit_hash,
        "event_hash": receipt.audit_event_hash,
        "timestamp_iso": "2026-05-28T00:00:00+00:00",
    }
    if event_id is not None:
        chain_event["event_id"] = event_id

    with pytest.raises(ReceiptValidationError, match="audit event missing event_id") as exc:
        AuditEvent.from_receipt_and_event(receipt, chain_event)
    assert exc.value.reason_code is ReceiptRejectionReason.MISSING_REQUIRED_FIELD


def test_audit_event_rejects_audit_hash_mismatch() -> None:
    receipt = _allow_receipt()
    chain_event = {
        "event_id": receipt.receipt_id,
        "previous_hash": receipt.previous_audit_hash,
        "event_hash": "wrong_hash",
        "timestamp_iso": "2026-05-28T00:00:00+00:00",
    }

    with pytest.raises(ReceiptValidationError, match="Audit hash mismatch") as exc:
        AuditEvent.from_receipt_and_event(receipt, chain_event)
    assert exc.value.reason_code is ReceiptRejectionReason.AUDIT_HASH_MISMATCH


@pytest.mark.parametrize("event_hash", [None, ""])
def test_audit_event_rejects_missing_or_empty_event_hash(event_hash: str | None) -> None:
    receipt = _allow_receipt()
    chain_event = {
        "event_id": receipt.receipt_id,
        "previous_hash": receipt.previous_audit_hash,
        "timestamp_iso": "2026-05-28T00:00:00+00:00",
    }
    if event_hash is not None:
        chain_event["event_hash"] = event_hash

    with pytest.raises(ReceiptValidationError, match="audit event missing event_hash") as exc:
        AuditEvent.from_receipt_and_event(receipt, chain_event)
    assert exc.value.reason_code is ReceiptRejectionReason.MISSING_REQUIRED_FIELD
