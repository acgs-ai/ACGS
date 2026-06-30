"""Tests for tenant-bound policy isolation and safety."""

from __future__ import annotations

from pathlib import Path

import pytest

from gove_zone import (
    ChainHashAuditStore,
    Decision,
    DecisionReceipt,
    DecisionRecord,
    PolicyError,
    ReceiptValidationError,
    RuleSetPolicy,
    TenantPolicyStore,
    Validator,
    evaluate_tenant_action,
    execute_with_receipt,
    sha256_json,
)


@pytest.fixture
def policy_store(tmp_path: Path) -> TenantPolicyStore:
    return TenantPolicyStore(tmp_path / "tenant_policies")


@pytest.fixture
def audit_store(tmp_path: Path) -> ChainHashAuditStore:
    return ChainHashAuditStore(tmp_path / "audit.jsonl")


def test_tenant_a_cannot_load_tenant_b_bundle(policy_store: TenantPolicyStore) -> None:
    policy = RuleSetPolicy.from_dict(
        {
            "id": "policy-A",
            "rules": [
                {
                    "id": "RULE_1",
                    "effect": "deny",
                    "tools": ["runtime.file.write"],
                }
            ],
        }
    )
    policy_store.store_bundle("tenant-A", policy)

    # Tenant A loads tenant A bundle successfully
    loaded = policy_store.load_bundle("tenant-A", "tenant-A")
    assert isinstance(loaded, RuleSetPolicy)
    assert loaded.policy_id == "policy-A"

    # Tenant B loading Tenant A bundle raises PermissionError
    with pytest.raises(PermissionError) as exc_info:
        policy_store.load_bundle("tenant-A", "tenant-B")
    assert "Cross-tenant access blocked" in str(exc_info.value)


def test_missing_tenant_fails_closed(
    policy_store: TenantPolicyStore,
    audit_store: ChainHashAuditStore,
) -> None:
    # 1. Missing tenant on action evaluation raises PolicyError
    with pytest.raises(PolicyError) as exc_info:
        evaluate_tenant_action(
            store=policy_store,
            tenant_id="",
            requester_tenant_id="tenant-A",
            action="runtime.file.write",
            args={"path": "test.txt"},
            execution_boundary="sandbox",
            request_id="req-1",
            actor="actor-1",
            validator=Validator("validator-1"),
            authority="tenant-A/write-grant",
            audit_store=audit_store,
        )
    assert "Tenant identification missing" in str(exc_info.value)


def test_missing_bundle_fails_closed(
    policy_store: TenantPolicyStore,
    audit_store: ChainHashAuditStore,
) -> None:
    with pytest.raises(PolicyError) as exc_info:
        evaluate_tenant_action(
            store=policy_store,
            tenant_id="tenant-A",
            requester_tenant_id="tenant-A",
            action="runtime.file.write",
            args={"path": "test.txt"},
            execution_boundary="sandbox",
            request_id="req-1",
            actor="actor-1",
            validator=Validator("validator-1"),
            authority="tenant-A/write-grant",
            audit_store=audit_store,
        )
    assert "Tenant bundle missing for tenant-A" in str(exc_info.value)


def test_tenant_a_receipt_cannot_authorize_tenant_b_action() -> None:
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool="runtime.file.write",
        argument_hash=sha256_json({"path": "test.txt"}),
        policy_version="v1",
        event_id="ev_1",
    )
    receipt = DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev_audit_hash",
        tenant_id="tenant-A",
        execution_boundary="sandbox",
        policy_bundle_id="bundle-A",
        policy_hash="policy-hash-A",
        request_id="req-1",
        validator=Validator("validator-1"),
        authority="tenant-A/write-grant",
    )

    # Executing for tenant-B raises ReceiptValidationError
    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            tool_fn=lambda **kw: "ok",
            args={"path": "test.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-B",
            expected_execution_boundary="sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            require_signature=False,  # explicit dev mode (unsigned)
        )
    assert "Tenant mismatch" in str(exc_info.value)


def test_policy_hash_mismatch_fails_closed() -> None:
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool="runtime.file.write",
        argument_hash=sha256_json({"path": "test.txt"}),
        policy_version="v1",
        event_id="ev_1",
    )
    receipt = DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev_audit_hash",
        tenant_id="tenant-A",
        execution_boundary="sandbox",
        policy_bundle_id="bundle-A",
        policy_hash="policy-hash-A",
        request_id="req-1",
        validator=Validator("validator-1"),
        authority="tenant-A/write-grant",
    )

    # Executing with mismatched policy hash raises ReceiptValidationError
    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            tool_fn=lambda **kw: "ok",
            args={"path": "test.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            require_signature=False,  # explicit dev mode (unsigned)
            expected_policy_hash="policy-hash-different",
        )
    assert "Policy hash mismatch" in str(exc_info.value)
