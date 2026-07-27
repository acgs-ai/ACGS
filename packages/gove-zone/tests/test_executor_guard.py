"""Tests for the receipt-required executor guard (execute_with_receipt, GovernedExecutor)."""

from __future__ import annotations

import re
from typing import Any

import pytest

from gove_zone import (
    Decision,
    DecisionReceipt,
    DecisionRecord,
    GovernedExecutor,
    ReceiptValidationError,
    Validator,
    execute_with_receipt,
)
from gove_zone.policy import PolicyRule, RuleSetPolicy


class SideEffectTracker:
    def __init__(self) -> None:
        self.called = False
        self.called_with: dict[str, Any] | None = None

    def run_tool(self, **kwargs: Any) -> str:
        self.called = True
        self.called_with = kwargs
        return "success"


_DEFAULT_ALLOW_ARGS: dict[str, Any] = {"path": "safe.txt"}


def make_test_receipt(
    decision: str = "allow",
    transformations: list[dict[str, Any]] | None = None,
    tenant_id: str = "tenant-A",
    execution_boundary: str = "local-sandbox",
    action: str = "runtime.file.write",
    args: dict[str, Any] | None = None,
) -> DecisionReceipt:
    from gove_zone.decision import sha256_json

    effective_args = args if args is not None else _DEFAULT_ALLOW_ARGS
    record = DecisionRecord(
        decision=Decision(decision),
        tool=action,
        argument_hash=sha256_json(effective_args),
        policy_version="v1",
        event_id="ev_abc",
        transformed_args={"path": "transformed.txt"} if decision == "transform" else None,
    )
    receipt = DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev_audit_hash",
        tenant_id=tenant_id,
        execution_boundary=execution_boundary,
        policy_bundle_id="policy-bundle",
        policy_hash="policy-hash",
        request_id="req-123",
        validator=Validator("validator-1"),
        authority="tenant-A/write-grant",
    )
    if transformations is not None:
        import dataclasses

        receipt = dataclasses.replace(receipt, transformations=transformations)
        h = receipt.compute_hash()
        receipt = dataclasses.replace(receipt, receipt_hash=h)
    return receipt


def test_executor_refuses_no_receipt() -> None:
    tracker = SideEffectTracker()
    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=None,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            require_signature=False,  # explicit dev mode: this case tests non-signing behavior
        )
    assert "No receipt provided" in str(exc_info.value)
    assert not tracker.called


def test_executor_refuses_malformed_receipt() -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt()
    import dataclasses

    # Make it malformed by clearing receipt_id
    receipt = dataclasses.replace(receipt, receipt_id="")

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            require_signature=False,  # explicit dev mode: this case tests non-signing behavior
        )
    assert "Missing or empty required field" in str(exc_info.value)
    assert not tracker.called


def test_executor_refuses_tampered_receipt() -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt()
    import dataclasses

    # Tamper with tenant_id without recomputing receipt_hash
    receipt = dataclasses.replace(receipt, tenant_id="tenant-B")

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            require_signature=False,  # explicit dev mode: this case tests non-signing behavior
        )
    assert "receipt_hash mismatch" in str(exc_info.value)
    assert not tracker.called


def test_executor_refuses_denied_receipt() -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt("deny")

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            require_signature=False,  # explicit dev mode: this case tests non-signing behavior
        )
    assert "Denied receipt cannot authorize execution" in str(exc_info.value)
    assert not tracker.called


def test_executor_refuses_escalated_receipt() -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt("escalate")

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            require_signature=False,  # explicit dev mode: this case tests non-signing behavior
        )
    assert "Escalated receipt cannot authorize execution" in str(exc_info.value)
    assert not tracker.called


def test_executor_refuses_wrong_tenant() -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt(tenant_id="tenant-B")

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            require_signature=False,  # explicit dev mode: this case tests non-signing behavior
        )
    assert "Tenant mismatch" in str(exc_info.value)
    assert not tracker.called


def test_executor_refuses_transform_mismatch() -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt("transform")
    # Expected transform args has path="transformed.txt"

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            # Pass original untransformed arg
            args={"path": "original.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            require_signature=False,  # explicit dev mode: this case tests non-signing behavior
        )
    assert "Transform mismatch" in str(exc_info.value)
    assert not tracker.called


def test_executor_allows_valid_allowed_receipt() -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt("allow")

    res = execute_with_receipt(
        tool_fn=tracker.run_tool,
        args={"path": "safe.txt"},
        receipt=receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action="runtime.file.write",
        expected_actor="anonymous",
        require_signature=False,  # explicit dev mode: this case tests non-signing behavior
    )
    assert res == "success"
    assert tracker.called
    assert tracker.called_with == {"path": "safe.txt"}


def test_executor_allows_valid_transformed_receipt() -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt("transform")
    # Expected transform args must have path="transformed.txt"

    res = execute_with_receipt(
        tool_fn=tracker.run_tool,
        args={"path": "transformed.txt"},
        receipt=receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action="runtime.file.write",
        expected_actor="anonymous",
        require_signature=False,  # explicit dev mode: this case tests non-signing behavior
    )
    assert res == "success"
    assert tracker.called
    assert tracker.called_with == {"path": "transformed.txt"}


def test_governed_executor_workflow() -> None:
    tracker = SideEffectTracker()
    # Explicit dev mode: this case exercises the registry/execute plumbing with an
    # unsigned receipt, not the production-signed default.
    executor = GovernedExecutor(
        tenant_id="tenant-A",
        execution_boundary="local-sandbox",
        expected_actor="anonymous",
        require_signature=False,
    )
    executor.register("runtime.file.write", tracker.run_tool)

    receipt = make_test_receipt("allow", args={"path": "test.txt"})
    res = executor.execute("runtime.file.write", {"path": "test.txt"}, receipt)
    assert res == "success"
    assert tracker.called


def test_executor_production_default_rejects_unsigned_no_verifier() -> None:
    """DEFAULT-FLIP PROOF: with no require_signature argument, the gate runs in the
    production profile (require_signature=True). An unsigned receipt with no verifier
    configured fails closed LOUD, naming the dev opt-out, and the side effect never runs.
    """
    from gove_zone import ProductionProfileError

    tracker = SideEffectTracker()
    receipt = make_test_receipt("allow")
    with pytest.raises(ProductionProfileError) as exc_info:
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            # NOTE: no require_signature, no verifier — production profile is the default.
        )
    assert "production profile requires a signer/verifier" in str(exc_info.value)
    assert "GovernanceProfile.dev()" in str(exc_info.value)
    assert not tracker.called


class _StubPolicy:
    """Minimal Policy-shaped stub: only `.version` / `.policy_id` matter here."""

    def __init__(self, version: str) -> None:
        self._version = version

    @property
    def version(self) -> str:
        return self._version

    @property
    def policy_id(self) -> str:
        return "stub"


def _receipt_with_policy_hash(policy_hash: str, *, args: dict[str, Any]) -> DecisionReceipt:
    """Issue a valid unsigned ALLOW receipt carrying a chosen policy_hash.

    policy_hash is bound into receipt_hash by from_record, so this is the honest
    way to get a receipt the gate's check 11 can compare against a bound policy.
    """
    from gove_zone.decision import sha256_json

    record = DecisionRecord(
        decision=Decision("allow"),
        tool="runtime.file.write",
        argument_hash=sha256_json(args),
        policy_version=policy_hash,
        event_id="ev_ph",
        transformed_args=None,
    )
    return DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev_audit_hash",
        tenant_id="tenant-A",
        execution_boundary="local-sandbox",
        policy_bundle_id="policy-bundle",
        policy_hash=policy_hash,
        request_id="req-ph",
        validator=Validator("validator-1"),
        authority="tenant-A/write-grant",
    )


def test_gate_policy_binding_accepts_matching_policy() -> None:
    """A receipt minted under the gate's bound policy passes check 11 and runs."""
    tracker = SideEffectTracker()
    args = {"path": "safe.txt"}
    receipt = _receipt_with_policy_hash("ruleset/x/abc1234567890def", args=args)

    res = execute_with_receipt(
        tool_fn=tracker.run_tool,
        args=args,
        receipt=receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action="runtime.file.write",
        expected_actor="anonymous",
        policy=_StubPolicy("ruleset/x/abc1234567890def"),
        require_signature=False,
    )
    assert res == "success"
    assert tracker.called


def test_gate_policy_binding_rejects_mismatched_policy() -> None:
    """A receipt minted under a DIFFERENT policy is rejected at the live gate,
    even though receipt_hash/signature are intact — the expected hash comes from
    the policy the gate enforces, not from the receipt."""
    from gove_zone.errors import ReceiptRejectionReason

    tracker = SideEffectTracker()
    args = {"path": "safe.txt"}
    receipt = _receipt_with_policy_hash("ruleset/x/policyB000000000", args=args)

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            args=args,
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            policy=_StubPolicy("ruleset/x/policyA000000000"),
            require_signature=False,
        )
    assert exc_info.value.reason_code == ReceiptRejectionReason.POLICY_HASH_MISMATCH
    assert not tracker.called


def test_gate_policy_binding_contradiction_fails_closed() -> None:
    """If both an explicit expected_policy_hash and a bound policy are given and
    they disagree, the gate fails closed before any side effect."""
    tracker = SideEffectTracker()
    args = {"path": "safe.txt"}
    receipt = _receipt_with_policy_hash("ruleset/x/policyA000000000", args=args)

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            args=args,
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            expected_policy_hash="ruleset/x/policyA000000000",
            policy=_StubPolicy("ruleset/x/policyB000000000"),
            require_signature=False,
        )
    assert "contradictory policy contract" in str(exc_info.value)
    assert not tracker.called


def _real_policy() -> RuleSetPolicy:
    return RuleSetPolicy(
        policy_id="gate/v1",
        rules=[PolicyRule.from_dict({"id": "R1", "effect": "deny", "tools": ["fs.delete"]})],
    )


def test_gate_binds_a_real_policy_by_its_full_digest() -> None:
    """End-to-end: the gate accepts a receipt carrying the real full-digest version.

    Uses a real RuleSetPolicy rather than a stub so the 64-hex identity is the
    thing actually compared at the gate.
    """
    policy = _real_policy()
    assert re.fullmatch(r"[0-9a-f]{64}", policy.version.rsplit("/", 1)[-1])

    tracker = SideEffectTracker()
    args = {"path": "safe.txt"}
    receipt = _receipt_with_policy_hash(policy.version, args=args)

    res = execute_with_receipt(
        tool_fn=tracker.run_tool,
        args=args,
        receipt=receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action="runtime.file.write",
        expected_actor="anonymous",
        policy=policy,
        require_signature=False,
    )
    assert res == "success"
    assert tracker.called


def test_gate_refuses_a_truncated_policy_identity() -> None:
    """The pre-hardening 16-hex identity must NOT authorize under the new one.

    This is the no-dual-acceptance assertion: the truncated form is an exact
    prefix of the full digest, so a lenient comparison would accept it. The gate
    must reject it and run no side effect.
    """
    from gove_zone.errors import ReceiptRejectionReason

    policy = _real_policy()
    prefix, digest = policy.version.rsplit("/", 1)
    truncated = f"{prefix}/{digest[:16]}"
    assert policy.version.startswith(truncated)  # a lenient check would pass

    tracker = SideEffectTracker()
    args = {"path": "safe.txt"}
    receipt = _receipt_with_policy_hash(truncated, args=args)

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            args=args,
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
            policy=policy,
            require_signature=False,
        )
    assert exc_info.value.reason_code == ReceiptRejectionReason.POLICY_HASH_MISMATCH
    assert not tracker.called
    assert tracker.called_with is None


def test_unbound_executor_ignores_policy_hash_by_default() -> None:
    """Regression guard: with no bound policy and no expected_policy_hash, the
    gate does not check policy_hash (unchanged pre-hardening behavior)."""
    tracker = SideEffectTracker()
    args = {"path": "safe.txt"}
    receipt = _receipt_with_policy_hash("any/unchecked/hash", args=args)

    res = execute_with_receipt(
        tool_fn=tracker.run_tool,
        args=args,
        receipt=receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action="runtime.file.write",
        expected_actor="anonymous",
        require_signature=False,
    )
    assert res == "success"
    assert tracker.called


def test_governed_executor_policy_binding_rejects_mismatch() -> None:
    """GovernedExecutor constructed with a bound policy rejects a receipt minted
    under a different policy at execute() time."""
    from gove_zone.errors import ReceiptRejectionReason

    tracker = SideEffectTracker()
    executor = GovernedExecutor(
        tenant_id="tenant-A",
        execution_boundary="local-sandbox",
        expected_actor="anonymous",
        policy=_StubPolicy("ruleset/x/policyA000000000"),
        require_signature=False,
    )
    executor.register("runtime.file.write", tracker.run_tool)
    args = {"path": "test.txt"}
    receipt = _receipt_with_policy_hash("ruleset/x/policyB000000000", args=args)
    with pytest.raises(ReceiptValidationError) as exc_info:
        executor.execute("runtime.file.write", args, receipt)
    assert exc_info.value.reason_code == ReceiptRejectionReason.POLICY_HASH_MISMATCH
    assert not tracker.called


def test_governed_executor_production_default_rejects_unsigned() -> None:
    """DEFAULT-FLIP PROOF for GovernedExecutor: constructed with no require_signature,
    it defaults to the production profile and fails closed loud on an unsigned receipt
    with no verifier.
    """
    from gove_zone import ProductionProfileError

    tracker = SideEffectTracker()
    executor = GovernedExecutor(
        tenant_id="tenant-A",
        execution_boundary="local-sandbox",
        expected_actor="anonymous",
        # NOTE: no require_signature — production profile is the default.
    )
    executor.register("runtime.file.write", tracker.run_tool)
    receipt = make_test_receipt("allow", args={"path": "test.txt"})
    with pytest.raises(ProductionProfileError):
        executor.execute("runtime.file.write", {"path": "test.txt"}, receipt)
    assert not tracker.called
