"""MACI authority / validator-role enforcement AT THE GATE.

``authority`` and ``validator_role`` are bound into ``receipt_hash`` and checkable via
``DecisionReceipt.verify(expected_authority=..., expected_validator_role=...)`` (checks
12b/12c). Before this change no *gate* surface plumbed them, so a least-privilege
deployment that treats ``authority`` as a grant boundary could not enforce it at the
executor gate — only via a direct ``verify()`` call.

These tests prove enforcement THROUGH each real gate surface — ``execute_with_receipt``,
``GovernedExecutor``, ``ReceiptVerifier``, and ``resume_with_receipt`` — and that leaving
the pins unset preserves the prior behavior exactly (opt-in, backward-compatible).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from gove_zone import (
    ChainHashAuditStore,
    Decision,
    DecisionReceipt,
    DecisionRecord,
    GovernedExecutor,
    ReceiptValidationError,
    ReceiptVerifier,
    Validator,
    execute_with_receipt,
)
from gove_zone.decision import sha256_json
from gove_zone.escalation import PendingApproval, approve_escalation, resume_with_receipt

TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
ACTION = "runtime.file.write"
ARGS: dict[str, Any] = {"path": "safe.txt"}
GRANT = "tenant-A/write-grant"


class SideEffect:
    def __init__(self) -> None:
        self.run_count = 0

    def run(self, **kwargs: Any) -> str:
        self.run_count += 1
        return "EXECUTED"


def _issue(
    *,
    actor: str = "agent-1",
    validator_id: str = "constitutional-council",
    validator_role: str = "validator",
    authority: str = GRANT,
) -> DecisionReceipt:
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=ACTION,
        argument_hash=sha256_json(ARGS),
        policy_version="v1",
        event_id="ev_abc",
        actor=actor,
    )
    return DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev_audit_hash",
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="policy-bundle",
        policy_hash="policy-hash",
        request_id="req-123",
        validator=Validator(validator_id, role=validator_role),
        authority=authority,
    )


def _run(receipt: DecisionReceipt, se: SideEffect, **kw: Any) -> Any:
    return execute_with_receipt(
        tool_fn=se.run,
        args=ARGS,
        receipt=receipt,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action=ACTION,
        expected_actor="agent-1",
        require_signature=False,
        **kw,
    )


# --- execute_with_receipt ---------------------------------------------------


def test_execute_with_receipt_rejects_wrong_authority() -> None:
    se = SideEffect()
    receipt = _issue(authority="tenant-A/read-grant")
    with pytest.raises(ReceiptValidationError, match="[Aa]uthority"):
        _run(receipt, se, expected_authority=GRANT)
    assert se.run_count == 0


def test_execute_with_receipt_accepts_matching_authority() -> None:
    se = SideEffect()
    receipt = _issue(authority=GRANT)
    assert _run(receipt, se, expected_authority=GRANT) == "EXECUTED"
    assert se.run_count == 1


def test_execute_with_receipt_rejects_wrong_validator_role() -> None:
    se = SideEffect()
    receipt = _issue(validator_role="reviewer")
    with pytest.raises(ReceiptValidationError, match="[Vv]alidator role"):
        _run(receipt, se, expected_validator_role="admin")
    assert se.run_count == 0


def test_execute_with_receipt_accepts_matching_validator_role() -> None:
    se = SideEffect()
    receipt = _issue(validator_role="admin")
    assert _run(receipt, se, expected_validator_role="admin") == "EXECUTED"
    assert se.run_count == 1


def test_unpinned_authority_preserves_prior_behavior() -> None:
    """Opt-in: with no pin the field is not consulted — backward-compatible."""
    se = SideEffect()
    receipt = _issue(authority="tenant-A/any-old-grant")
    assert _run(receipt, se) == "EXECUTED"  # no expected_authority -> not checked
    assert se.run_count == 1


# --- GovernedExecutor -------------------------------------------------------


def test_governed_executor_constructor_authority_pin() -> None:
    ex = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor="agent-1",
        expected_authority=GRANT,
        require_signature=False,
    )
    se = SideEffect()
    ex.register(ACTION, se.run)

    assert ex.execute(ACTION, ARGS, _issue(authority=GRANT)) == "EXECUTED"
    with pytest.raises(ReceiptValidationError):
        ex.execute(ACTION, ARGS, _issue(authority="tenant-A/read-grant"))
    # A per-call None must NOT silently disable a constructor-bound pin.
    with pytest.raises(ReceiptValidationError):
        ex.execute(ACTION, ARGS, _issue(authority="tenant-A/read-grant"), expected_authority=None)
    assert se.run_count == 1


# --- ReceiptVerifier --------------------------------------------------------


def test_receipt_verifier_authority_pin() -> None:
    rv = ReceiptVerifier(
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_actor="agent-1",
        expected_authority=GRANT,
        require_signature=False,
    )
    good = _issue(authority=GRANT)
    bad = _issue(authority="tenant-A/read-grant")

    rv.verify(good, expected_action=ACTION, expected_args=ARGS)
    assert rv.is_valid(good, expected_action=ACTION, expected_args=ARGS)
    with pytest.raises(ReceiptValidationError):
        rv.verify(bad, expected_action=ACTION, expected_args=ARGS)
    assert not rv.is_valid(bad, expected_action=ACTION, expected_args=ARGS)


# --- resume_with_receipt ----------------------------------------------------


def test_resume_with_receipt_authority_pin(tmp_path: Path) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    escalated = DecisionRecord(
        decision=Decision.ESCALATE,
        tool=ACTION,
        argument_hash=sha256_json(ARGS),
        policy_version="v1",
        event_id="ev_esc",
        actor="agent-1",
    )
    pending = PendingApproval(escalated, audit_hash="anchor", args=ARGS)
    receipt = approve_escalation(
        pending,
        validator=Validator("human-approver"),
        authority=GRANT,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="policy-bundle",
        policy_hash="policy-hash",
        audit=audit,
    )
    ex = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor="agent-1",
        require_signature=False,
    )
    se = SideEffect()
    ex.register(ACTION, se.run)

    with pytest.raises(ReceiptValidationError):
        resume_with_receipt(ex, pending, receipt, expected_authority="tenant-A/ADMIN-grant")
    assert se.run_count == 0

    assert resume_with_receipt(ex, pending, receipt, expected_authority=GRANT) == "EXECUTED"
    assert se.run_count == 1
