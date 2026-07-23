"""Tests for the ESCALATE → approve → resume bridge (gove_zone.escalation).

These drive the real dispatcher path — kernel.dispatch raises EscalateError,
approve_escalation mints an ALLOW receipt with a distinct human Validator, and
resume_with_receipt executes only through the GovernedExecutor gate — rather than
unit-calling the bridge in isolation. The negative-path tests prove the
fail-closed properties hold at the gate (verify checks), not just at issuance.
"""

from __future__ import annotations

import pytest

from gove_zone import (
    ChainHashAuditStore,
    Decision,
    DecisionRecord,
    Ed25519Signer,
    EscalateError,
    GovernedExecutor,
    Kernel,
    PendingApproval,
    Policy,
    ReceiptValidationError,
    Validator,
    approve_escalation,
    new_event_id,
    resume_with_receipt,
    sha256_json,
)
from gove_zone._strict_dispatch_fixture import StrictReceiptGateFixture
from gove_zone.receipt import DecisionReceipt
from gove_zone.tool import ToolCall

TENANT = "tenant-acme"
BOUNDARY = "prod/api"
PROPOSER = "agent-x"
BUNDLE = "bundle-1"
PHASH = "policyhash-abc"


class _EscalatePolicy(Policy):
    """Test policy: escalate every call (needs a human)."""

    @property
    def version(self) -> str:
        return "test-escalate/v1"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.ESCALATE,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("ESCALATE:needs-human",),
            reason="needs human approval",
        )


def _spy() -> tuple[object, list[str]]:
    calls: list[str] = []

    def fn(path: str) -> str:
        calls.append(path)
        return f"wrote {path}"

    return fn, calls


def _escalated(
    strict: StrictReceiptGateFixture,
    *,
    actor: str = PROPOSER,
    args: dict | None = None,
) -> tuple[EscalateError, ChainHashAuditStore]:
    args = {"path": "/tmp/safe"} if args is None else args
    audit = strict.audit
    kernel = Kernel(policy=_EscalatePolicy(), audit=audit, actor=actor)
    call = ToolCall(
        name="write_file",
        args=args,
        goal="do the thing",
        actor=actor,
    )
    record, audit_hash = kernel.evaluate_and_record(call)
    pending = PendingApproval(record, audit_hash, args)
    return EscalateError(record, audit_hash, pending=pending), audit


def _approve(
    pending: PendingApproval,
    strict: StrictReceiptGateFixture,
    **over,
) -> DecisionReceipt:
    kw = dict(
        validator=Validator("human-alice", "approver"),
        authority="grant:write",
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id=BUNDLE,
        policy_hash=PHASH,
        audit=strict.audit,
        signer=strict.signer,
    )
    kw.update(over)
    return approve_escalation(pending, **kw)


def _executor(
    strict: StrictReceiptGateFixture,
    *,
    tenant: str = TENANT,
    boundary: str = BOUNDARY,
    actor: str = PROPOSER,
    verifier: object | None = None,
):
    fn, calls = _spy()
    ex = GovernedExecutor(
        tenant_id=tenant,
        execution_boundary=boundary,
        expected_actor=actor,
        consumption_store=strict.consumption_store,
        rejection_audit=strict.audit,
        verifier=verifier or strict.signer,
        lifecycle_signer=strict.lifecycle_signer,
        lifecycle_authority_id="fixture-lifecycle-validator",
    )
    ex.register("write_file", fn)
    return ex, calls


# --- wiring + back-compat ---------------------------------------------------


def test_kernel_attaches_pending_on_escalate(strict_receipt_gate: StrictReceiptGateFixture):
    err, _ = _escalated(strict_receipt_gate, args={"path": "/tmp/safe"})
    assert isinstance(err.pending, PendingApproval)
    assert err.pending.record is err.record
    assert err.pending.audit_hash == err.audit_hash
    assert dict(err.pending.args) == {"path": "/tmp/safe"}


def test_escalate_error_pending_optional():
    rec = DecisionRecord(
        decision=Decision.ESCALATE,
        tool="t",
        argument_hash="h",
        policy_version="p",
        event_id="e",
    )
    err = EscalateError(rec, "ah")
    assert err.pending is None
    assert err.record is rec


def test_non_escalate_pending_refused():
    rec = DecisionRecord(
        decision=Decision.ALLOW,
        tool="write_file",
        argument_hash=sha256_json({"path": "/tmp/safe"}),
        policy_version="x",
        event_id="e1",
        actor=PROPOSER,
    )
    with pytest.raises(ReceiptValidationError, match="requires an ESCALATE record"):
        PendingApproval(rec, "auditx", {"path": "/tmp/safe"})


# --- happy path -------------------------------------------------------------


def test_happy_path_executes_once(strict_receipt_gate: StrictReceiptGateFixture):
    err, _audit = _escalated(strict_receipt_gate)
    receipt = _approve(err.pending, strict_receipt_gate)
    assert receipt.decision == "allow"
    assert receipt.validator_id == "human-alice"
    assert receipt.actor == PROPOSER

    ex, calls = _executor(strict_receipt_gate)
    result = resume_with_receipt(ex, err.pending, receipt)
    assert result == "wrote /tmp/safe"
    assert calls == ["/tmp/safe"]


# --- fail-closed: the original escalation can never authorize execution ------


def test_escalated_receipt_cannot_execute(
    strict_receipt_gate: StrictReceiptGateFixture,
):
    err, _audit = _escalated(strict_receipt_gate)
    # Mint a receipt straight from the ESCALATE record: decision stays "escalate".
    bad = DecisionReceipt.from_record(
        err.pending.record,
        audit_hash=err.pending.audit_hash,
        previous_audit_hash="0" * 64,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id=BUNDLE,
        policy_hash=PHASH,
        request_id="r1",
        validator=Validator("human-alice", "approver"),
        authority="grant:write",
        signer=strict_receipt_gate.signer,
    )
    assert bad.decision == "escalate"
    ex, calls = _executor(strict_receipt_gate)
    with pytest.raises(ReceiptValidationError, match="cannot authorize execution"):
        resume_with_receipt(ex, err.pending, bad)
    assert calls == []


# --- fail-closed: human must differ from the agent (MACI) -------------------


def test_self_approval_forbidden(strict_receipt_gate: StrictReceiptGateFixture):
    err, audit = _escalated(strict_receipt_gate, actor=PROPOSER)
    with pytest.raises(ReceiptValidationError, match="self-validation forbidden"):
        _approve(
            err.pending,
            strict_receipt_gate,
            validator=Validator(PROPOSER, "approver"),
        )
    # The rejected self-approval must NOT have polluted the audit chain.
    decisions = [e["decision"] for e in audit.iter_events()]
    assert "allow" not in decisions


def test_wrong_invoking_principal_rejected(
    strict_receipt_gate: StrictReceiptGateFixture,
):
    err, _audit = _escalated(strict_receipt_gate, actor=PROPOSER)
    receipt = _approve(err.pending, strict_receipt_gate)
    ex, calls = _executor(strict_receipt_gate, actor="agent-y")
    with pytest.raises(ReceiptValidationError, match="actor mismatch"):
        ex.execute("write_file", dict(err.pending.args), receipt)
    assert calls == []


# --- fail-closed: exact-argument binding ------------------------------------


def test_arg_tamper_rejected(strict_receipt_gate: StrictReceiptGateFixture):
    err, _audit = _escalated(strict_receipt_gate, args={"path": "/tmp/safe"})
    receipt = _approve(err.pending, strict_receipt_gate)
    ex, calls = _executor(strict_receipt_gate)
    with pytest.raises(ReceiptValidationError, match="argument mismatch"):
        ex.execute("write_file", {"path": "/etc/shadow"}, receipt)
    assert calls == []


# --- audit integrity --------------------------------------------------------


def test_approval_is_audited_and_chain_verifies(
    strict_receipt_gate: StrictReceiptGateFixture,
):
    err, audit = _escalated(strict_receipt_gate)
    _approve(err.pending, strict_receipt_gate)
    chain = audit.verify_chain()
    assert chain["valid"] is True
    pairs = [(e["decision"], e["event_id"]) for e in audit.iter_events()]
    assert ("escalate", err.pending.record.event_id) in pairs
    assert any(d == "allow" and eid.endswith(":approved") for d, eid in pairs)


# --- fail-closed: tenant / boundary binding ---------------------------------


def test_wrong_tenant_rejected(strict_receipt_gate: StrictReceiptGateFixture):
    err, _audit = _escalated(strict_receipt_gate)
    receipt = _approve(err.pending, strict_receipt_gate, tenant_id=TENANT)
    ex, calls = _executor(strict_receipt_gate, tenant="tenant-other")
    with pytest.raises(ReceiptValidationError, match="[Tt]enant mismatch"):
        resume_with_receipt(ex, err.pending, receipt)
    assert calls == []


# --- crypto closure ---------------------------------------------------------


def test_signed_approval_roundtrips(strict_receipt_gate: StrictReceiptGateFixture):
    err, _audit = _escalated(strict_receipt_gate)
    signer = Ed25519Signer.generate(key_id="k1")
    receipt = _approve(err.pending, strict_receipt_gate, signer=signer)
    assert receipt.signature_algorithm == "ed25519"

    verifier = Ed25519Signer.from_public_bytes(signer.public_bytes(), key_id="k1")
    ex, calls = _executor(strict_receipt_gate, verifier=verifier)
    result = resume_with_receipt(ex, err.pending, receipt)
    assert result == "wrote /tmp/safe"
    assert calls == ["/tmp/safe"]


def test_unsigned_approval_rejected_when_signature_required(
    strict_receipt_gate: StrictReceiptGateFixture,
):
    # Gate configured to verify signatures (verifier present), but the approval is
    # unsigned -> verify check 2a rejects it. (A verifier is supplied so we reach
    # verify rather than the production-misconfig guard, which the next test covers.)
    err, audit = _escalated(strict_receipt_gate)
    receipt = approve_escalation(
        err.pending,
        validator=Validator("human-alice", "approver"),
        authority="grant:write",
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id=BUNDLE,
        policy_hash=PHASH,
        audit=audit,
    )
    ex, calls = _executor(strict_receipt_gate)
    with pytest.raises(ReceiptValidationError, match="signature required"):
        resume_with_receipt(ex, err.pending, receipt)
    assert calls == []


def test_production_executor_without_verifier_fails_closed(
    strict_receipt_gate: StrictReceiptGateFixture,
):
    # Production profile is the executor default (require_signature=True). Resuming
    # through it with no verifier configured fails closed LOUD (ProductionProfileError,
    # a ReceiptValidationError subclass) rather than silently downgrading — the bridge
    # inherits the secure default.
    with pytest.raises(ValueError, match="trusted verifier"):
        GovernedExecutor(
            tenant_id=TENANT,
            execution_boundary=BOUNDARY,
            expected_actor=PROPOSER,
            consumption_store=strict_receipt_gate.consumption_store,
            rejection_audit=strict_receipt_gate.audit,
        )


# --- expiry -----------------------------------------------------------------


def test_expired_approval_rejected(strict_receipt_gate: StrictReceiptGateFixture):
    err, _audit = _escalated(strict_receipt_gate)
    receipt = _approve(
        err.pending,
        strict_receipt_gate,
        expires_at="2000-01-01T00:00:00+00:00",
    )
    ex, calls = _executor(strict_receipt_gate)
    with pytest.raises(ReceiptValidationError, match="expired"):
        resume_with_receipt(ex, err.pending, receipt)
    assert calls == []


# --- the bridge's own MACI anchor, exercised THROUGH resume_with_receipt -----


def test_resume_rejects_executor_actor_pin_mismatch(
    strict_receipt_gate: StrictReceiptGateFixture,
):
    # resume_with_receipt must anchor expected_actor to pending.record.actor,
    # overriding the executor's own default. The executor here is built with a
    # DIFFERENT default actor; if the bridge's anchor regressed (e.g. to None),
    # the gate would fall back to that wrong default and reject the receipt.
    # Succeeding proves the proposer anchor is live on the resume path itself.
    err, _audit = _escalated(strict_receipt_gate, actor=PROPOSER)
    receipt = _approve(err.pending, strict_receipt_gate)
    ex, calls = _executor(
        strict_receipt_gate,
        actor="executor-default-not-the-proposer",
    )
    with pytest.raises(ReceiptValidationError, match="cannot override"):
        resume_with_receipt(ex, err.pending, receipt)
    assert calls == []


def test_resume_rejects_receipt_issued_for_different_proposer(
    strict_receipt_gate: StrictReceiptGateFixture,
):
    # Negative path THROUGH resume_with_receipt (not ex.execute): a receipt issued
    # for agent-x is resumed via a pending whose proposer is agent-y. The bridge
    # anchors expected_actor to pending.record.actor (agent-y), so verify check 2b
    # rejects the receipt naming agent-x. Guards the anchor against binding the
    # wrong identity.
    err_x, _audit = _escalated(strict_receipt_gate, actor="agent-x")
    receipt_x = _approve(err_x.pending, strict_receipt_gate)
    err_y, _ = _escalated(strict_receipt_gate, actor="agent-y")
    ex, calls = _executor(strict_receipt_gate, actor="agent-y")
    with pytest.raises(ReceiptValidationError, match="actor mismatch"):
        resume_with_receipt(ex, err_y.pending, receipt_x)
    assert calls == []


# --- replay resistance ------------------------------------------------------


def test_single_approval_second_resume_is_denied(
    strict_receipt_gate: StrictReceiptGateFixture,
):
    err, _audit = _escalated(strict_receipt_gate)
    receipt = _approve(err.pending, strict_receipt_gate)
    ex, calls = _executor(strict_receipt_gate)

    assert resume_with_receipt(ex, err.pending, receipt) == "wrote /tmp/safe"
    with pytest.raises(ReceiptValidationError, match="replay"):
        resume_with_receipt(ex, err.pending, receipt)

    assert calls == ["/tmp/safe"]
