"""MACI role separation — the proposer can never validate its own authority.

gove-zone enforces validator≠proposer at two layers:

    1. Issuance — :meth:`DecisionReceipt.from_record` (via
       :func:`evaluate_tenant_action`) refuses to MINT a receipt whose
       validator equals the proposer.
    2. Verification — :meth:`DecisionReceipt.verify` (the gate, reached through
       :func:`execute_with_receipt`) refuses to USE a receipt when the caller's
       identity (``expected_actor``) is also the validator, anchoring the check
       against an identity the receipt author cannot forge by editing fields.

The negative-path tests that exercise the GATE are:
- :func:`test_gate_refuses_forged_self_validated_receipt` (naive forge: validator_id==actor)
- :func:`test_gate_refuses_actor_rewrite_forgery` (actor-rewrite bypass: anchored by expected_actor)
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
    replay_call,
)
from gove_zone.tool import ToolCall

BOUNDARY = "local-sandbox"
TENANT = "tenant-A"
ACTION = "runtime.file.write"
AUTHORITY = "tenant-A/write-grant"


class SideEffect:
    """A stand-in high-risk tool. Records whether — and how — it actually ran."""

    def __init__(self) -> None:
        self.ran = False
        self.args: dict[str, Any] | None = None

    def run(self, **kwargs: Any) -> str:
        self.ran = True
        self.args = kwargs
        return "executed"


def _allow_policy() -> RuleSetPolicy:
    # Denies a *different* tool, so our target tool falls through to default ALLOW.
    return RuleSetPolicy.from_dict(
        {"id": "policy-A", "rules": [{"id": "R1", "effect": "deny", "tools": ["shell.exec"]}]}
    )


def _issue(
    store: TenantPolicyStore,
    audit: ChainHashAuditStore,
    *,
    actor: str,
    validator: Validator,
    args: dict[str, Any] | None = None,
    request_id: str = "req-1",
) -> DecisionReceipt:
    return evaluate_tenant_action(
        store=store,
        tenant_id=TENANT,
        requester_tenant_id=TENANT,
        action=ACTION,
        args=args or {"path": "safe.txt", "content": "hi"},
        execution_boundary=BOUNDARY,
        request_id=request_id,
        actor=actor,
        validator=validator,
        authority=AUTHORITY,
        audit_store=audit,
    )


def test_issuance_refuses_self_validation(tmp_path: Path) -> None:
    """The issuer can never MINT a receipt where the validator is the proposer."""
    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle(TENANT, _allow_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")

    with pytest.raises(ReceiptValidationError, match="self-validation forbidden"):
        evaluate_tenant_action(
            store=store,
            tenant_id=TENANT,
            requester_tenant_id=TENANT,
            action=ACTION,
            args={"path": "safe.txt", "content": "hi"},
            execution_boundary=BOUNDARY,
            request_id="req-self",
            actor="agent-1",
            validator=Validator("agent-1"),  # same identity as the proposer
            authority=AUTHORITY,
            audit_store=audit,
        )


def test_from_record_refuses_self_validation_for_anonymous() -> None:
    """A proposer-less record defaults to "anonymous"; a validator of the same
    id is still refused at mint time."""
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=ACTION,
        argument_hash="hash",
        policy_version="v1",
        event_id="ev_self",
    )
    with pytest.raises(ReceiptValidationError, match="self-validation forbidden"):
        DecisionReceipt.from_record(
            record=record,
            audit_hash="audit_hash",
            previous_audit_hash="prev_audit_hash",
            tenant_id=TENANT,
            execution_boundary=BOUNDARY,
            policy_bundle_id="bundle-A",
            policy_hash="policy-hash",
            request_id="req-1",
            validator=Validator("anonymous"),  # collides with the default proposer
            authority=AUTHORITY,
        )


def test_gate_refuses_forged_self_validated_receipt(tmp_path: Path) -> None:
    """THE WIRING PROOF — the gate (execute_with_receipt) refuses a forged
    self-validated receipt, and the side effect never runs.

    A real receipt is minted with a DISTINCT validator, then forged so that
    ``validator_id == actor`` with a freshly-recomputed CONSISTENT hash (so the
    receipt_hash check passes). Only the structural MACI check can reject it —
    proving it is independent defense-in-depth, not a side effect of tampering.
    """
    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle(TENANT, _allow_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")

    minted = _issue(store, audit, actor="agent-1", validator=Validator("constitutional-council"))
    assert minted.decision == "allow"
    assert minted.validator_id == "constitutional-council"

    # Forge: make the validator the proposer, then recompute a consistent hash.
    forged = dataclasses.replace(minted, validator_id=minted.actor)
    forged = dataclasses.replace(forged, receipt_hash=forged.compute_hash())
    assert forged.compute_hash() == forged.receipt_hash  # hash check would PASS

    side = SideEffect()
    args = {"path": "safe.txt", "content": "hi"}
    with pytest.raises(ReceiptValidationError, match="self-validation"):
        execute_with_receipt(
            tool_fn=side.run,
            args=args,
            receipt=forged,
            # Every expected_* MATCHES the minted receipt, so the ONLY possible
            # violation is validator_id == actor.
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_audit_hash=forged.audit_event_hash,
            expected_policy_hash=forged.policy_hash,
            expected_policy_bundle_id=forged.policy_bundle_id,
        )
    assert not side.ran  # the side effect was NEVER executed


def test_happy_path_distinct_validator_executes(tmp_path: Path) -> None:
    """A receipt with a distinct validator reaches execution through the gate,
    including when expected_actor is supplied from the caller's runtime context."""
    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle(TENANT, _allow_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")

    receipt = _issue(store, audit, actor="agent-1", validator=Validator("constitutional-council"))
    assert receipt.approval_chain_summary == {
        "proposer": "agent-1",
        "validator_id": "constitutional-council",
        "validator_role": "validator",
        "authority": AUTHORITY,
    }

    side = SideEffect()
    args = {"path": "safe.txt", "content": "hi"}
    result = execute_with_receipt(
        tool_fn=side.run,
        args=args,
        receipt=receipt,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action=ACTION,
        expected_actor="agent-1",  # anchor: caller supplies its own identity
    )
    assert result == "executed"
    assert side.ran
    assert side.args == args


def test_missing_validator_fields_fail_closed(tmp_path: Path) -> None:
    """A receipt with empty validator/authority fields is refused at the gate."""
    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle(TENANT, _allow_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    receipt = _issue(store, audit, actor="agent-1", validator=Validator("constitutional-council"))

    for field in ("validator_id", "validator_role", "authority"):
        stripped = dataclasses.replace(receipt, **{field: ""})
        # Recompute the hash so we test the missing-field check, not the hash check.
        stripped = dataclasses.replace(stripped, receipt_hash=stripped.compute_hash())
        side = SideEffect()
        with pytest.raises(ReceiptValidationError, match="Missing or empty required field"):
            execute_with_receipt(
                tool_fn=side.run,
                args={"path": "safe.txt", "content": "hi"},
                receipt=stripped,
                expected_tenant_id=TENANT,
                expected_execution_boundary=BOUNDARY,
                expected_action=ACTION,
            )
        assert not side.ran


def test_issued_receipt_with_validator_fields_replays(tmp_path: Path) -> None:
    """An issued receipt carrying the new MACI fields still verifies and the
    underlying decision replays against its policy."""
    policy = _allow_policy()
    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle(TENANT, policy)
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")

    args = {"path": "safe.txt", "content": "hi"}
    receipt = _issue(
        store, audit, actor="agent-1", validator=Validator("constitutional-council"), args=args
    )
    # The receipt verifies end to end with the new bound fields present.
    receipt.verify(
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action=ACTION,
    )

    # Replay the decision against the same policy and the captured args.
    replayed = replay_call(
        ToolCall(name=ACTION, args=args),
        expected_decision=Decision(receipt.decision),
        policy=policy,
        expected_policy_version=receipt.policy_version,
    )
    assert replayed.matches is True
    assert replayed.replayed_decision is Decision.ALLOW


def test_expected_validator_role_and_authority_checks(tmp_path: Path) -> None:
    """Optional expected_validator_role / expected_authority: mismatch fails,
    match passes."""
    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle(TENANT, _allow_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    receipt = _issue(store, audit, actor="agent-1", validator=Validator("constitutional-council"))

    with pytest.raises(ReceiptValidationError, match="Validator role mismatch"):
        receipt.verify(expected_validator_role="root")
    with pytest.raises(ReceiptValidationError, match="Authority mismatch"):
        receipt.verify(expected_authority="tenant-A/admin-grant")

    # Matching values pass cleanly.
    receipt.verify(
        expected_validator_role="validator",
        expected_authority=AUTHORITY,
    )


def test_gate_refuses_actor_rewrite_forgery(tmp_path: Path) -> None:
    """GATE NEGATIVE PATH — actor-rewrite bypass closed by expected_actor anchor.

    The bypass: forge a receipt where ``validator_id`` is the REAL proposer
    (e.g. "agent-1") but ``actor`` is changed to a phantom value (e.g. "phantom").
    Because ``validator_id != actor`` on the receipt, the naive 2c check passes.
    Only the caller-anchored 2b check — which compares ``validator_id`` against
    ``expected_actor`` supplied from outside the receipt — can catch this.

    This test MUST FAIL (ReceiptValidationError not raised) if expected_actor is
    removed from execute_with_receipt, proving the anchor is load-bearing.
    """
    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle(TENANT, _allow_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")

    # Mint a legitimate receipt for the real proposer "agent-1".
    minted = _issue(store, audit, actor="agent-1", validator=Validator("constitutional-council"))

    # Forge: set validator_id to the real proposer, change actor to a phantom,
    # then recompute a CONSISTENT hash so the receipt_hash check passes.
    forged = dataclasses.replace(minted, validator_id="agent-1", actor="phantom")
    forged = dataclasses.replace(forged, receipt_hash=forged.compute_hash())
    # Confirm: naive check (validator_id == actor) would NOT catch this.
    assert forged.validator_id != forged.actor  # "agent-1" != "phantom"
    # Confirm: hash is internally consistent.
    assert forged.compute_hash() == forged.receipt_hash

    side = SideEffect()
    args = {"path": "safe.txt", "content": "hi"}
    # The gate rejects via check 2b. Because actor="phantom" != expected_actor="agent-1",
    # the actor-mismatch sub-check fires first. Both sub-checks in 2b enforce the
    # invariant; the important assertion is that the gate raises and the tool never runs.
    with pytest.raises(ReceiptValidationError, match="actor mismatch|self-validation"):
        execute_with_receipt(
            tool_fn=side.run,
            args=args,
            receipt=forged,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            # The invoking principal identifies itself as "agent-1".
            # Check (i): actor mismatch (phantom != agent-1) → reject.
            # Check (ii) would fire if actor matched: validator_id==expected_actor → reject.
            expected_actor="agent-1",
        )
    assert not side.ran  # side effect was NEVER executed


def test_gate_refuses_receipt_for_wrong_caller(tmp_path: Path) -> None:
    """GATE NEGATIVE PATH — a validly-minted receipt issued for actor "agent-1"
    is refused when the invoking principal identifies itself as "agent-2".

    The gate uses expected_actor from the caller's runtime context (not from the
    receipt) to confirm the receipt was issued for this caller.
    """
    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle(TENANT, _allow_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")

    # Receipt was minted for "agent-1".
    receipt = _issue(store, audit, actor="agent-1", validator=Validator("constitutional-council"))
    assert receipt.actor == "agent-1"

    side = SideEffect()
    with pytest.raises(ReceiptValidationError, match="actor mismatch"):
        execute_with_receipt(
            tool_fn=side.run,
            args={"path": "safe.txt", "content": "hi"},
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor="agent-2",  # different principal invoking the gate
        )
    assert not side.ran


def test_approval_chain_summary_divergence_rejected(tmp_path: Path) -> None:
    """A receipt whose approval_chain_summary.validator_id disagrees with the
    top-level validator_id field is rejected at verify(), even with a fresh
    consistent receipt_hash.

    This catches hand-constructed or inconsistently-built receipts where the
    summary and the bound fields disagree — both are inside receipt_hash, so
    they must agree structurally.
    """
    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle(TENANT, _allow_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    receipt = _issue(store, audit, actor="agent-1", validator=Validator("constitutional-council"))

    # Diverge: top-level validator_id changed, summary still says "constitutional-council".
    diverged = dataclasses.replace(receipt, validator_id="some-other-validator")
    diverged = dataclasses.replace(diverged, receipt_hash=diverged.compute_hash())
    # The summary still has validator_id="constitutional-council" from issuance.
    assert diverged.approval_chain_summary.get("validator_id") == "constitutional-council"
    assert diverged.validator_id == "some-other-validator"

    with pytest.raises(
        ReceiptValidationError, match="approval_chain_summary.validator_id disagrees"
    ):
        diverged.verify()


def test_gate_refuses_validator_equals_caller(tmp_path: Path) -> None:
    """GATE NEGATIVE PATH — sub-check (ii) in isolation.

    Sub-check (i) fires when actor != expected_actor (actor-mismatch).
    Sub-check (ii) fires when validator_id == expected_actor (self-validation),
    regardless of what actor says.

    This test isolates sub-check (ii) by ensuring actor == expected_actor so
    sub-check (i) does NOT fire, then sets validator_id == actor == expected_actor
    so only sub-check (ii) can reject the forgery.

    The approval_chain_summary is forged to be internally consistent with the
    new validator_id so check 2d does not pre-empt the check under test.
    The receipt_hash is recomputed so check 2 (tamper) does not pre-empt it.
    The only remaining guard is sub-check (ii): validator_id == expected_actor.
    """
    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle(TENANT, _allow_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")

    # Mint a legitimate receipt: proposer "agent-1", distinct validator.
    minted = _issue(store, audit, actor="agent-1", validator=Validator("constitutional-council"))
    assert minted.actor == "agent-1"
    assert minted.validator_id == "constitutional-council"

    # Forge: set validator_id = "agent-1" = actor.
    # Also update approval_chain_summary so it stays internally consistent with
    # the forged validator_id — this prevents check 2d from firing first.
    forged_summary = dict(minted.approval_chain_summary)
    forged_summary["validator_id"] = "agent-1"
    forged = dataclasses.replace(
        minted,
        validator_id="agent-1",
        approval_chain_summary=forged_summary,
    )
    # Recompute a consistent hash so check 2 (tamper detection) passes.
    forged = dataclasses.replace(forged, receipt_hash=forged.compute_hash())

    # Confirm sub-check (i) would NOT fire: actor == expected_actor.
    assert forged.actor == "agent-1"  # actor matches the invoking principal
    # Confirm sub-check (ii) WILL fire: validator_id == expected_actor == "agent-1".
    assert forged.validator_id == "agent-1"
    # Confirm check 2d is satisfied: summary is consistent with top-level fields.
    assert forged.approval_chain_summary.get("validator_id") == forged.validator_id
    assert forged.approval_chain_summary.get("proposer") == forged.actor

    side = SideEffect()
    with pytest.raises(ReceiptValidationError, match="self-validation"):
        execute_with_receipt(
            tool_fn=side.run,
            args={"path": "safe.txt", "content": "hi"},
            receipt=forged,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor="agent-1",  # actor == expected_actor, so (i) does not fire
        )
    assert not side.ran  # side effect was NEVER executed
