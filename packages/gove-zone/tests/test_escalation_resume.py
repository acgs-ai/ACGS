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
    tmp_path, *, actor: str = PROPOSER, args: dict | None = None
) -> tuple[EscalateError, ChainHashAuditStore]:
    args = {"path": "/tmp/safe"} if args is None else args
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(policy=_EscalatePolicy(), audit=audit, actor=actor)

    @kernel.tool("write_file")
    def _never(**kwargs):  # pragma: no cover - must never run on ESCALATE
        raise AssertionError("kernel tool must not run on an ESCALATE dispatch")

    with pytest.raises(EscalateError) as ei:
        kernel.dispatch("write_file", args, goal="do the thing")
    return ei.value, audit


def _approve(pending: PendingApproval, audit: ChainHashAuditStore, **over) -> DecisionReceipt:
    kw = dict(
        validator=Validator("human-alice", "approver"),
        authority="grant:write",
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id=BUNDLE,
        policy_hash=PHASH,
        audit=audit,
    )
    kw.update(over)
    return approve_escalation(pending, **kw)


def _executor(
    *,
    tenant: str = TENANT,
    boundary: str = BOUNDARY,
    actor: str = PROPOSER,
    require_signature: bool = False,
):
    # Default to the explicit unsigned dev profile: these tests exercise the
    # actor/argument/tenant/decision gate logic, not signature verification.
    # The signed-path test passes require_signature=True + a verifier per-call.
    fn, calls = _spy()
    ex = GovernedExecutor(
        tenant_id=tenant,
        execution_boundary=boundary,
        expected_actor=actor,
        require_signature=require_signature,
    )
    ex.register("write_file", fn)
    return ex, calls


# --- wiring + back-compat ---------------------------------------------------


def test_kernel_attaches_pending_on_escalate(tmp_path):
    err, _ = _escalated(tmp_path, args={"path": "/tmp/safe"})
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


def test_happy_path_executes_once(tmp_path):
    err, audit = _escalated(tmp_path)
    receipt = _approve(err.pending, audit)
    assert receipt.decision == "allow"
    assert receipt.validator_id == "human-alice"
    assert receipt.actor == PROPOSER

    ex, calls = _executor()
    result = resume_with_receipt(ex, err.pending, receipt)
    assert result == "wrote /tmp/safe"
    assert calls == ["/tmp/safe"]


# --- fail-closed: the original escalation can never authorize execution ------


def test_escalated_receipt_cannot_execute(tmp_path):
    err, audit = _escalated(tmp_path)
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
    )
    assert bad.decision == "escalate"
    ex, calls = _executor()
    with pytest.raises(ReceiptValidationError, match="cannot authorize execution"):
        resume_with_receipt(ex, err.pending, bad)
    assert calls == []


# --- fail-closed: human must differ from the agent (MACI) -------------------


def test_self_approval_forbidden(tmp_path):
    err, audit = _escalated(tmp_path, actor=PROPOSER)
    with pytest.raises(ReceiptValidationError, match="self-validation forbidden"):
        _approve(err.pending, audit, validator=Validator(PROPOSER, "approver"))
    # The rejected self-approval must NOT have polluted the audit chain.
    decisions = [e["decision"] for e in audit.iter_events()]
    assert "allow" not in decisions


def test_wrong_invoking_principal_rejected(tmp_path):
    err, audit = _escalated(tmp_path, actor=PROPOSER)
    receipt = _approve(err.pending, audit)
    ex, calls = _executor(actor="agent-y")
    with pytest.raises(ReceiptValidationError, match="actor mismatch"):
        ex.execute("write_file", dict(err.pending.args), receipt, expected_actor="agent-y")
    assert calls == []


# --- fail-closed: exact-argument binding ------------------------------------


def test_arg_tamper_rejected(tmp_path):
    err, audit = _escalated(tmp_path, args={"path": "/tmp/safe"})
    receipt = _approve(err.pending, audit)
    ex, calls = _executor()
    with pytest.raises(ReceiptValidationError, match="argument mismatch"):
        ex.execute("write_file", {"path": "/etc/shadow"}, receipt, expected_actor=PROPOSER)
    assert calls == []


# --- audit integrity --------------------------------------------------------


def test_approval_is_audited_and_chain_verifies(tmp_path):
    err, audit = _escalated(tmp_path)
    _approve(err.pending, audit)
    chain = audit.verify_chain()
    assert chain["valid"] is True
    pairs = [(e["decision"], e["event_id"]) for e in audit.iter_events()]
    assert ("escalate", err.pending.record.event_id) in pairs
    assert any(d == "allow" and eid.endswith(":approved") for d, eid in pairs)


# --- fail-closed: tenant / boundary binding ---------------------------------


def test_wrong_tenant_rejected(tmp_path):
    err, audit = _escalated(tmp_path)
    receipt = _approve(err.pending, audit, tenant_id=TENANT)
    ex, calls = _executor(tenant="tenant-other")
    with pytest.raises(ReceiptValidationError, match="[Tt]enant mismatch"):
        resume_with_receipt(ex, err.pending, receipt)
    assert calls == []


# --- crypto closure ---------------------------------------------------------


def test_signed_approval_roundtrips(tmp_path):
    err, audit = _escalated(tmp_path)
    signer = Ed25519Signer.generate(key_id="k1")
    receipt = _approve(err.pending, audit, signer=signer)
    assert receipt.signature_algorithm == "ed25519"

    verifier = Ed25519Signer.from_public_bytes(signer.public_bytes(), key_id="k1")
    ex, calls = _executor()
    result = resume_with_receipt(
        ex, err.pending, receipt, verifier=verifier, require_signature=True
    )
    assert result == "wrote /tmp/safe"
    assert calls == ["/tmp/safe"]


def test_unsigned_approval_rejected_when_signature_required(tmp_path):
    # Gate configured to verify signatures (verifier present), but the approval is
    # unsigned -> verify check 2a rejects it. (A verifier is supplied so we reach
    # verify rather than the production-misconfig guard, which the next test covers.)
    err, audit = _escalated(tmp_path)
    receipt = _approve(err.pending, audit)  # unsigned
    verifier = Ed25519Signer.generate(key_id="kv")
    ex, calls = _executor()
    with pytest.raises(ReceiptValidationError, match="signature required"):
        resume_with_receipt(ex, err.pending, receipt, verifier=verifier, require_signature=True)
    assert calls == []


def test_production_executor_without_verifier_fails_closed(tmp_path):
    # Production profile is the executor default (require_signature=True). Resuming
    # through it with no verifier configured fails closed LOUD (ProductionProfileError,
    # a ReceiptValidationError subclass) rather than silently downgrading — the bridge
    # inherits the secure default.
    err, audit = _escalated(tmp_path)
    receipt = _approve(err.pending, audit)
    fn, calls = _spy()
    ex = GovernedExecutor(
        tenant_id=TENANT, execution_boundary=BOUNDARY, expected_actor=PROPOSER
    )  # production default: require_signature=True, no verifier
    ex.register("write_file", fn)
    with pytest.raises(
        ReceiptValidationError, match="production profile requires a signer/verifier"
    ):
        resume_with_receipt(ex, err.pending, receipt)
    assert calls == []


# --- expiry -----------------------------------------------------------------


def test_expired_approval_rejected(tmp_path):
    err, audit = _escalated(tmp_path)
    receipt = _approve(err.pending, audit, expires_at="2000-01-01T00:00:00+00:00")
    ex, calls = _executor()
    with pytest.raises(ReceiptValidationError, match="expired"):
        resume_with_receipt(ex, err.pending, receipt)
    assert calls == []


# --- the bridge's own MACI anchor, exercised THROUGH resume_with_receipt -----


def test_resume_anchors_expected_actor_to_proposer(tmp_path):
    # resume_with_receipt must anchor expected_actor to pending.record.actor,
    # overriding the executor's own default. The executor here is built with a
    # DIFFERENT default actor; if the bridge's anchor regressed (e.g. to None),
    # the gate would fall back to that wrong default and reject the receipt.
    # Succeeding proves the proposer anchor is live on the resume path itself.
    err, audit = _escalated(tmp_path, actor=PROPOSER)
    receipt = _approve(err.pending, audit)  # issued for PROPOSER
    fn, calls = _spy()
    ex = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor="executor-default-not-the-proposer",
        require_signature=False,
    )
    ex.register("write_file", fn)
    result = resume_with_receipt(ex, err.pending, receipt)
    assert result == "wrote /tmp/safe"
    assert calls == ["/tmp/safe"]


def test_resume_rejects_receipt_issued_for_different_proposer(tmp_path):
    # Negative path THROUGH resume_with_receipt (not ex.execute): a receipt issued
    # for agent-x is resumed via a pending whose proposer is agent-y. The bridge
    # anchors expected_actor to pending.record.actor (agent-y), so verify check 2b
    # rejects the receipt naming agent-x. Guards the anchor against binding the
    # wrong identity.
    err_x, audit = _escalated(tmp_path, actor="agent-x")
    receipt_x = _approve(err_x.pending, audit)  # actor == agent-x
    err_y, _ = _escalated(tmp_path, actor="agent-y")  # same tool+args, proposer agent-y
    fn, calls = _spy()
    ex = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor="agent-y",
        require_signature=False,
    )
    ex.register("write_file", fn)
    with pytest.raises(ReceiptValidationError, match="actor mismatch"):
        resume_with_receipt(ex, err_y.pending, receipt_x)
    assert calls == []


# --- KNOWN LIMITATION: approvals are not single-use (pinned, tracked) --------


def test_known_limitation_single_approval_is_replayable(tmp_path):
    # The stateless gate enforces no single-use, so one approval resumes N times
    # (an ordinary kernel ALLOW receipt behaves identically). This is a documented
    # limitation (see approve_escalation docstring); the test pins the current
    # behavior so adding a used-receipt ledger later is a conscious, visible change
    # rather than a silent one. "No valid receipt, no side effect" still holds:
    # every replay carries a genuinely valid ALLOW receipt.
    err, audit = _escalated(tmp_path)
    receipt = _approve(err.pending, audit)
    fn, calls = _spy()
    ex = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor=PROPOSER,
        require_signature=False,
    )
    ex.register("write_file", fn)
    for _ in range(3):
        assert resume_with_receipt(ex, err.pending, receipt) == "wrote /tmp/safe"
    assert calls == ["/tmp/safe", "/tmp/safe", "/tmp/safe"]
