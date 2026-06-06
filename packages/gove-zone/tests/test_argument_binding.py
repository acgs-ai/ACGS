"""Argument binding — an ALLOW receipt only authorizes the exact proposed args.

gove-zone binds ``argument_hash`` (SHA-256 of the proposed args dict) into the
receipt_hash at issuance, and verifies it at the gate for ALLOW decisions.  This
closes the substitution gap: a valid ALLOW receipt for
``write_file(path=/tmp/safe)`` cannot be reused to execute
``write_file(path=/etc/shadow)``.

The gate proof (test #1) exercises :func:`execute_with_receipt` on the negative
path — the sentinel side effect must NEVER run.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

from gove_zone import (
    ChainHashAuditStore,
    Decision,
    DecisionReceipt,
    DecisionRecord,
    ReceiptValidationError,
    RuleSetPolicy,
    TenantPolicyStore,
    Validator,
    evaluate_tenant_action,
    execute_with_receipt,
    sha256_json,
)

TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
ACTION = "runtime.file.write"
AUTHORITY = "tenant-A/write-grant"
VALIDATOR = Validator("constitutional-council")


class SideEffect:
    """Stand-in high-risk tool — records whether it actually ran."""

    def __init__(self) -> None:
        self.ran = False
        self.args: dict[str, Any] | None = None

    def run(self, **kwargs: Any) -> str:
        self.ran = True
        self.args = kwargs
        return "executed"


def _allow_policy() -> RuleSetPolicy:
    return RuleSetPolicy.from_dict(
        {"id": "policy-A", "rules": [{"id": "R1", "effect": "deny", "tools": ["shell.exec"]}]}
    )


def _issue(
    store: TenantPolicyStore,
    audit: ChainHashAuditStore,
    args: dict[str, Any],
    *,
    request_id: str = "req-1",
) -> DecisionReceipt:
    return evaluate_tenant_action(
        store=store,
        tenant_id=TENANT,
        requester_tenant_id=TENANT,
        action=ACTION,
        args=args,
        execution_boundary=BOUNDARY,
        request_id=request_id,
        actor="agent-1",
        validator=VALIDATOR,
        authority=AUTHORITY,
        audit_store=audit,
    )


# ---------------------------------------------------------------------------
# 1. GATE PROOF — arg substitution blocked through execute_with_receipt
# ---------------------------------------------------------------------------


def test_allow_receipt_rejects_substituted_args(tmp_path: Path) -> None:
    """GATE PROOF — the executor rejects args different from those the receipt
    was issued for, and the side effect NEVER runs.

    Receipt issued for A1 = {path: /tmp/safe}.
    Gate called with   A2 = {path: /etc/shadow}.
    Expected: ReceiptValidationError("argument mismatch"), sentinel never ran.
    """
    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle(TENANT, _allow_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")

    a1 = {"path": "/tmp/safe", "content": "ok"}
    receipt = _issue(store, audit, a1)
    assert receipt.decision == "allow"
    assert receipt.argument_hash == sha256_json(a1)

    a2 = {"path": "/etc/shadow", "content": "pwned"}
    side = SideEffect()
    with pytest.raises(ReceiptValidationError, match="argument mismatch"):
        execute_with_receipt(
            tool_fn=side.run,
            args=a2,
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor="agent-1",
            require_signature=False,  # explicit dev mode (unsigned)
        )
    assert not side.ran  # side effect was NEVER executed


# ---------------------------------------------------------------------------
# 2. Happy path — matching args execute successfully
# ---------------------------------------------------------------------------


def test_allow_receipt_executes_for_matching_args(tmp_path: Path) -> None:
    """An ALLOW receipt called with the exact args it was issued for executes."""
    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle(TENANT, _allow_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")

    args = {"path": "/tmp/safe", "content": "ok"}
    receipt = _issue(store, audit, args)
    assert receipt.decision == "allow"

    side = SideEffect()
    result = execute_with_receipt(
        tool_fn=side.run,
        args=args,
        receipt=receipt,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action=ACTION,
        expected_actor="agent-1",
        require_signature=False,  # explicit dev mode (unsigned)
    )
    assert result == "executed"
    assert side.ran
    assert side.args == args


# ---------------------------------------------------------------------------
# 3. argument_hash is bound into receipt_hash
# ---------------------------------------------------------------------------


def test_argument_hash_bound_into_receipt_hash(tmp_path: Path) -> None:
    """Tampering with argument_hash without recomputing receipt_hash is caught
    by the tamper check (#2), proving the arg hash is cryptographically bound.
    Recomputing the hash but submitting mismatching args is caught by #10b.
    """
    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle(TENANT, _allow_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")

    args = {"path": "/tmp/safe", "content": "ok"}
    receipt = _issue(store, audit, args)

    # --- tamper without recomputing hash: caught by check #2 ---
    tampered = dataclasses.replace(receipt, argument_hash="forged_hash")
    with pytest.raises(ReceiptValidationError, match="receipt_hash mismatch"):
        tampered.verify()

    # --- intact receipt submitted with DIFFERENT args at the gate: caught by #10b ---
    # The original receipt still binds args (argument_hash == sha256_json(args)).
    # Submitting different args at the gate triggers the argument binding check.
    other_args = {"path": "/etc/shadow", "content": "pwned"}
    side = SideEffect()
    with pytest.raises(ReceiptValidationError, match="argument mismatch"):
        execute_with_receipt(
            tool_fn=side.run,
            args=other_args,  # different from what the receipt was issued for
            receipt=receipt,  # original receipt; its argument_hash covers 'args', not 'other_args'
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor="agent-1",
            require_signature=False,  # explicit dev mode (unsigned)
        )
    assert not side.ran


# ---------------------------------------------------------------------------
# 4. TRANSFORM regression — existing transform path still works
# ---------------------------------------------------------------------------


def test_transform_receipt_still_verifies_and_executes(tmp_path: Path) -> None:
    """TRANSFORM receipts are not affected by the ALLOW arg check.

    The executed (transformed) args differ from the original proposed args that
    argument_hash covers; the transform-field check (#10) remains the binding
    for TRANSFORM execution. Confirm the transform path still works end-to-end.
    """
    from gove_zone.tenant import TransformPolicy

    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle(TENANT, TransformPolicy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")

    original_args = {"path": "original.txt"}
    receipt = _issue(store, audit, original_args, request_id="req-transform")
    assert receipt.decision == "transform"
    # argument_hash covers the ORIGINAL args (as proposed).
    assert receipt.argument_hash == sha256_json(original_args)

    # Running un-approved (original) args is refused by the transform-field check.
    side = SideEffect()
    with pytest.raises(ReceiptValidationError, match="Transform mismatch"):
        execute_with_receipt(
            tool_fn=side.run,
            args=original_args,
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor="agent-1",
            require_signature=False,  # explicit dev mode (unsigned)
        )
    assert not side.ran

    # Only the approved transformed args reach the side effect.
    approved = {"path": "transformed.txt"}
    side = SideEffect()
    result = execute_with_receipt(
        tool_fn=side.run,
        args=approved,
        receipt=receipt,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action=ACTION,
        expected_actor="agent-1",
        require_signature=False,  # explicit dev mode (unsigned)
    )
    assert result == "executed"
    assert side.ran
    assert side.args == approved


# ---------------------------------------------------------------------------
# 5–7. TRANSFORM exact-match binding (new completeness check #10c)
# ---------------------------------------------------------------------------


def test_transform_receipt_rejects_extra_executed_field(tmp_path: Path) -> None:
    """GATE PROOF — execute_with_receipt rejects TRANSFORM execution that includes
    an extra field not in the approved transformed set.

    Receipt issued via TransformPolicy: input {"path": "original.txt"} →
    approved {"path": "transformed.txt"}.
    Gate called with {"path": "transformed.txt", "content": "malicious"} — the
    extra "content" field was never approved and must be rejected.
    The sentinel side effect must NEVER run.
    """
    from gove_zone.tenant import TransformPolicy

    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle(TENANT, TransformPolicy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")

    receipt = _issue(store, audit, {"path": "original.txt"}, request_id="req-extra")
    assert receipt.decision == "transform"
    # Approved set is exactly {"path": "transformed.txt"}.
    assert receipt.transformations == [{"field": "path", "value": "transformed.txt"}]

    # Execute with the approved field PLUS an extra un-approved field.
    extra_args = {"path": "transformed.txt", "content": "malicious"}
    side = SideEffect()
    with pytest.raises(ReceiptValidationError, match="transform mismatch"):
        execute_with_receipt(
            tool_fn=side.run,
            args=extra_args,
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor="agent-1",
            require_signature=False,  # explicit dev mode (unsigned)
        )
    assert not side.ran  # side effect was NEVER executed


def test_transform_receipt_rejects_missing_field(tmp_path: Path) -> None:
    """execute_with_receipt rejects TRANSFORM execution that is missing an
    approved field from the transformed set.

    This exercises the case where approved = {field_A: v, field_B: v} but
    execution only supplies {field_A: v}.  We build a hand-crafted receipt
    with two approved fields so we can pass the per-field sub-checks while
    having a missing key.
    """
    original_args = {"path": "original.txt", "mode": "read"}
    approved_args = {"path": "transformed.txt", "mode": "write"}
    record = DecisionRecord(
        decision=Decision.TRANSFORM,
        tool=ACTION,
        argument_hash=sha256_json(original_args),
        policy_version="v1",
        event_id="ev-missing",
        transformed_args=approved_args,
    )
    receipt = DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev_hash",
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="bundle-A",
        policy_hash="policy-hash",
        request_id="req-missing",
        validator=Validator("constitutional-council"),
        authority=AUTHORITY,
    )
    assert receipt.decision == "transform"
    assert len(receipt.transformations) == 2  # both fields approved

    # Execute with ONLY ONE of the two approved fields — the "mode" field is missing.
    side = SideEffect()
    # The per-field check (#10) fires first when an approved field is absent from
    # executed args ("field 'mode' is missing from arguments").  The completeness
    # check (#10c) would independently catch this.  Either message proves the
    # un-approved execution was blocked — match the common substring.
    with pytest.raises(ReceiptValidationError, match="[Mm]ismatch|missing"):
        execute_with_receipt(
            tool_fn=side.run,
            args={"path": "transformed.txt"},  # missing "mode"
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            # Hand-built record has no actor → proposer resolves to "anonymous".
            expected_actor="anonymous",
            require_signature=False,  # explicit dev mode (unsigned)
        )
    assert not side.ran


def test_transform_exact_match_passes(tmp_path: Path) -> None:
    """Executing with EXACTLY the approved transformed set passes the gate.

    Confirms the completeness check is not over-restrictive: the existing
    happy-path (exact approved args) still works after the #10c addition.
    """
    from gove_zone.tenant import TransformPolicy

    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle(TENANT, TransformPolicy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")

    receipt = _issue(store, audit, {"path": "original.txt"}, request_id="req-exact")
    assert receipt.decision == "transform"

    approved = {"path": "transformed.txt"}
    side = SideEffect()
    result = execute_with_receipt(
        tool_fn=side.run,
        args=approved,
        receipt=receipt,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action=ACTION,
        expected_actor="agent-1",
        require_signature=False,  # explicit dev mode (unsigned)
    )
    assert result == "executed"
    assert side.ran
    assert side.args == approved
