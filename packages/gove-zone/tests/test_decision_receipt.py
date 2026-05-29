"""Tests for canonical DecisionReceipt schema, hashing, and verification."""

from __future__ import annotations

from typing import Any

import pytest

from gove_zone import Decision, DecisionReceipt, DecisionRecord, ReceiptValidationError, Validator


def make_valid_receipt(
    decision: str = "allow",
    transformations: list[dict[str, Any]] | None = None,
) -> DecisionReceipt:
    record = DecisionRecord(
        decision=Decision(decision),
        tool="runtime.file.write",
        argument_hash="abc123hash",
        policy_version="v1.0.0",
        event_id="ev_test_123",
        matched_rules=("SMOKE_SECRET_BOUNDARY:keyword:id_rsa",) if decision == "deny" else (),
        reason="Test decision",
        transformed_args={"path": "transformed_path.txt"} if decision == "transform" else None,
    )
    receipt = DecisionReceipt.from_record(
        record=record,
        audit_hash="curr_audit_hash_hex_12345",
        previous_audit_hash="prev_audit_hash_hex_67890",
        tenant_id="tenant-A",
        execution_boundary="local-sandbox",
        policy_bundle_id="policy-bundle-xyz",
        policy_hash="const-hash-val",
        request_id="req-unique-999",
        subject="test-subject",
        validator=Validator("validator-1"),
        authority="tenant-A/write-grant",
    )
    if transformations is not None:
        # Override transformations for malformed testing
        import dataclasses

        receipt = dataclasses.replace(receipt, transformations=transformations)
        h = receipt.compute_hash()
        receipt = dataclasses.replace(receipt, receipt_hash=h)
    return receipt


def test_decision_receipt_round_trip() -> None:
    receipt = make_valid_receipt()
    d = receipt.to_dict()
    assert d["signature"] == "unsigned_local"

    reconstructed = DecisionReceipt.from_dict(d)
    assert reconstructed == receipt

    json_str = receipt.to_json()
    reconstructed_json = DecisionReceipt.from_json(json_str)
    assert reconstructed_json == receipt


def test_verification_passes_on_valid_allowed_receipt() -> None:
    receipt = make_valid_receipt("allow")
    receipt.verify(
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_audit_hash="curr_audit_hash_hex_12345",
        expected_action="runtime.file.write",
    )


def test_verification_rejects_missing_fields() -> None:
    fields_to_test = [
        "receipt_id",
        "request_id",
        "tenant_id",
        "actor",
        "proposed_action",
        "execution_boundary",
        "policy_bundle_id",
        "policy_version",
        "policy_hash",
        "decision",
        "timestamp",
        "previous_audit_hash",
        "audit_event_hash",
    ]
    import dataclasses

    for field in fields_to_test:
        receipt = make_valid_receipt()
        # Force empty field
        kwargs: dict[str, Any] = {field: ""}
        receipt = dataclasses.replace(receipt, **kwargs)
        # Note: we need to recompute hash otherwise it fails on hash mismatch first
        h = receipt.compute_hash()
        receipt = dataclasses.replace(receipt, receipt_hash=h)

        with pytest.raises(ReceiptValidationError) as exc_info:
            receipt.verify()
        assert "Missing or empty required field" in str(exc_info.value)


def test_verification_rejects_altered_fields() -> None:
    import dataclasses

    receipt = make_valid_receipt()

    # Alter proposed_action but keep the original receipt_hash
    tampered = dataclasses.replace(receipt, proposed_action="runtime.delete_all")
    with pytest.raises(ReceiptValidationError) as exc_info:
        tampered.verify()
    assert "receipt_hash mismatch" in str(exc_info.value)

    # Alter tenant_id
    tampered = dataclasses.replace(receipt, tenant_id="tenant-B")
    with pytest.raises(ReceiptValidationError) as exc_info:
        tampered.verify()
    assert "receipt_hash mismatch" in str(exc_info.value)


def test_verification_rejects_unknown_decisions() -> None:
    import dataclasses

    receipt = make_valid_receipt()
    tampered = dataclasses.replace(receipt, decision="super-allow")
    h = tampered.compute_hash()
    tampered = dataclasses.replace(tampered, receipt_hash=h)

    with pytest.raises(ReceiptValidationError) as exc_info:
        tampered.verify()
    assert "Unknown decision: super-allow" in str(exc_info.value)


def test_verification_rejects_denied_and_escalated_receipts() -> None:
    # Denied
    receipt_deny = make_valid_receipt("deny")
    with pytest.raises(ReceiptValidationError) as exc_info:
        receipt_deny.verify()
    assert "Denied receipt cannot authorize execution" in str(exc_info.value)

    # Escalated
    receipt_escalate = make_valid_receipt("escalate")
    with pytest.raises(ReceiptValidationError) as exc_info:
        receipt_escalate.verify()
    assert "Escalated receipt cannot authorize execution" in str(exc_info.value)


def test_verification_rejects_tenant_mismatch() -> None:
    receipt = make_valid_receipt()
    with pytest.raises(ReceiptValidationError) as exc_info:
        receipt.verify(expected_tenant_id="tenant-B")
    assert "Tenant mismatch" in str(exc_info.value)


def test_verification_rejects_execution_boundary_mismatch() -> None:
    receipt = make_valid_receipt()
    with pytest.raises(ReceiptValidationError) as exc_info:
        receipt.verify(expected_execution_boundary="remote-prod")
    assert "Execution boundary mismatch" in str(exc_info.value)


def test_verification_rejects_audit_hash_mismatch() -> None:
    receipt = make_valid_receipt()
    with pytest.raises(ReceiptValidationError) as exc_info:
        receipt.verify(expected_audit_hash="different_hash")
    assert "Audit hash mismatch" in str(exc_info.value)


def test_verification_rejects_malformed_transforms() -> None:
    # 1. transformations not a list
    receipt = make_valid_receipt("transform", transformations="not-a-list")  # type: ignore
    with pytest.raises(ReceiptValidationError) as exc_info:
        receipt.verify()
    assert "transformations must be a list" in str(exc_info.value)

    # 2. transformation item not a dict
    receipt = make_valid_receipt("transform", transformations=["not-a-dict"])  # type: ignore
    with pytest.raises(ReceiptValidationError) as exc_info:
        receipt.verify()
    assert "each transformation must be a dictionary" in str(exc_info.value)

    # 3. transformation item missing required keys
    receipt = make_valid_receipt("transform", transformations=[{"field": "path"}])
    with pytest.raises(ReceiptValidationError) as exc_info:
        receipt.verify()
    assert "transformation dictionary must contain 'field' and 'value'" in str(exc_info.value)

    # 4. field not a string
    receipt = make_valid_receipt("transform", transformations=[{"field": 123, "value": "x"}])
    with pytest.raises(ReceiptValidationError) as exc_info:
        receipt.verify()
    assert "field' key must be a string" in str(exc_info.value)


def test_verification_rejects_transform_mismatch() -> None:
    receipt = make_valid_receipt("transform")
    # Expected transformations contains [{"field": "path", "value": "transformed_path.txt"}]

    # 1. Missing transformation key in args
    with pytest.raises(ReceiptValidationError) as exc_info:
        receipt.verify(expected_args={"content": "hello"})
    assert "missing from arguments" in str(exc_info.value)

    # 2. Mismatched value
    with pytest.raises(ReceiptValidationError) as exc_info:
        receipt.verify(expected_args={"path": "original_path.txt"})
    assert "Transform mismatch" in str(exc_info.value)

    # 3. Correct value passes
    receipt.verify(expected_args={"path": "transformed_path.txt"})
