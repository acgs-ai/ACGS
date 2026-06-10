"""Tests for the agent-facing structured rejection envelope (gove_zone.rejection).

These drive the **real** dispatcher path — ``kernel.dispatch`` raises the typed
error, and the envelope is read off that caught error — rather than constructing
errors by hand. Coverage spans: envelope shape on DENY and ESCALATE, the
resume affordance tracking ``pending``, the *no-side-effect-on-deny* invariant
(via a call counter), the fail-closed synthesized-DENY projection, and the
value-leak boundary (the policy-authored ``reason`` is the single by-design
value-bearing channel — nothing else echoes raw inputs).
"""

from __future__ import annotations

import json

import pytest

from gove_zone import (
    BoundaryPolicy,
    ChainHashAuditStore,
    Decision,
    DecisionRecord,
    DeniedError,
    EscalateError,
    Kernel,
    Policy,
    new_event_id,
    rejection_dict,
    sha256_json,
)
from gove_zone.rejection import _FAIL_CLOSED_REASON
from gove_zone.tool import ToolCall


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


class _RaisingPolicy(Policy):
    """Test policy that raises — exercises the kernel's fail-closed synth DENY."""

    @property
    def version(self) -> str:
        return "test-raising/v1"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        raise RuntimeError("boom")


class _EchoReasonPolicy(Policy):
    """Test policy whose DENY reason echoes a call argument value.

    Used to pin the documented boundary: ``reason`` is the ONE field that can
    carry a policy-authored value, by design — every other envelope field is a
    hash or fixed metadata. (README: "Keep policy ``reason`` strings
    non-sensitive.")
    """

    @property
    def version(self) -> str:
        return "test-echo/v1"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        secret = str(call.args.get("secret", ""))
        return DecisionRecord(
            decision=Decision.DENY,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("ECHO:deny",),
            reason=f"denied; offending value was {secret}",
        )


def _deny_kernel(tmp_path, *, rule_id: str) -> tuple[Kernel, list[str]]:
    """Denying kernel plus a list that records every actual tool execution."""
    ran: list[str] = []
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(
        policy=BoundaryPolicy(forbidden_keywords=["forbidden"], rule_id=rule_id),
        audit=audit,
        actor="agent-x",
    )

    @kernel.tool("do.thing")
    def thing(trigger: str) -> str:
        ran.append(trigger)
        return f"ran:{trigger}"

    return kernel, ran


def _kernel_with(policy: Policy, tmp_path) -> Kernel:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(policy=policy, audit=audit, actor="agent-x")

    @kernel.tool("do.thing")
    def thing(**kwargs: object) -> str:  # pragma: no cover - never runs on DENY/ESCALATE
        return "ran"

    return kernel


def test_denied_envelope_shape(tmp_path) -> None:
    """DENY → envelope off the real raise path, correct shape & resolution."""
    kernel, ran = _deny_kernel(tmp_path, rule_id="P-DENY")
    with pytest.raises(DeniedError) as ei:
        kernel.dispatch("do.thing", {"trigger": "this is forbidden"}, goal="g")
    err = ei.value
    env = err.to_rejection_dict()

    assert env["status"] == "deny"
    assert env["outcome"] == "denied"
    assert env["resumable"] is False
    assert env["resolution"] == "revise_and_retry"
    assert env["tool"] == "do.thing"
    assert env["actor"] == "agent-x"
    assert env["matched_rules"] == list(err.record.matched_rules)
    assert any("P-DENY" in r for r in env["matched_rules"])
    assert env["audit_hash"] == err.audit_hash
    # pinned to the actual bound value, not merely "truthy"
    assert env["decision_request_hash"] == err.record.decision_request_hash
    assert env["decision_request_hash"]  # bound at dispatch, non-empty
    assert "allowed_alternatives" not in env  # omitted until PR-2 computes it
    assert "approval" not in env  # deny carries no resume affordance
    assert ran == []  # DENY executed no side effect


def test_escalated_envelope_advertises_resume(tmp_path) -> None:
    """ESCALATE → envelope is resumable and points at approve_escalation (R3→R2)."""
    kernel = _kernel_with(_EscalatePolicy(), tmp_path)
    with pytest.raises(EscalateError) as ei:
        kernel.dispatch("do.thing", {"path": "/tmp/safe"}, goal="g")
    err = ei.value
    env = err.to_rejection_dict()

    assert env["status"] == "escalate"
    assert env["outcome"] == "escalated"
    assert env["resumable"] is True
    assert env["resolution"] == "human_approval"
    assert env["approval"] == {"via": "approve_escalation", "pending": True}
    # the kernel attached the PendingApproval that makes resume possible (PR-4)
    assert err.pending is not None


def test_escalate_without_pending_is_not_resumable() -> None:
    """Hand-constructed EscalateError (no pending) → resumable is honestly False.

    ``resumable`` tracks the actual affordance, not the verdict class: with no
    PendingApproval attached there is nothing to drive ``approve_escalation``, so
    ``resumable`` and ``approval.pending`` must both be False and agree.
    """
    record = DecisionRecord(
        decision=Decision.ESCALATE,
        tool="t",
        argument_hash="h",
        policy_version="v",
        event_id="e",
        matched_rules=("ESCALATE:x",),
        reason="needs human",
    )
    err = EscalateError(record, "audit-hash")  # back-compat: no pending
    env = err.to_rejection_dict()

    assert err.pending is None
    assert env["resumable"] is False
    assert env["approval"] == {"via": "approve_escalation", "pending": False}
    assert env["resumable"] is env["approval"]["pending"]  # never disagree


def test_rejection_enables_self_correction(tmp_path) -> None:
    """The envelope is actionable AND fail-closed: 0 executions on deny, 1 on the revised allow."""
    kernel, ran = _deny_kernel(tmp_path, rule_id="P-SC")

    # 1st attempt — denied; tool must not run (no side effect on deny).
    with pytest.raises(DeniedError) as ei:
        kernel.dispatch("do.thing", {"trigger": "this is forbidden"}, goal="g")
    env = ei.value.to_rejection_dict()
    assert env["status"] == "deny"
    assert any("P-SC" in r for r in env["matched_rules"])
    assert ran == []  # zero side effects on DENY (core invariant)

    # Agent revises away the offending content and retries — ALLOW executes exactly once.
    result, receipt = kernel.dispatch("do.thing", {"trigger": "this is clean"}, goal="g")
    assert result == "ran:this is clean"
    assert receipt.record.decision is Decision.ALLOW
    assert ran == ["this is clean"]  # executed exactly once, only on the allowed call


def test_fail_closed_synth_deny_projects(tmp_path) -> None:
    """The kernel-synthesized DENY (policy raised) — the most security-relevant
    DENY — projects into a well-formed envelope an integrator can surface."""
    kernel = _kernel_with(_RaisingPolicy(), tmp_path)
    with pytest.raises(DeniedError) as ei:
        kernel.dispatch("do.thing", {"x": 1}, goal="g")
    env = ei.value.to_rejection_dict()

    assert env["status"] == "deny"
    assert env["resumable"] is False
    assert env["resolution"] == "revise_and_retry"
    assert env["policy_version"] == "fail-closed/policy-raised"
    assert any("POLICY_ERROR" in r for r in env["matched_rules"])
    # reason is redacted on fail-closed records — exception text never reaches the agent
    assert env["reason"] == _FAIL_CLOSED_REASON
    assert "boom" not in env["reason"]
    # ...but the audit-retained record keeps the full exception-derived reason
    assert "boom" in ei.value.record.reason


def test_fail_closed_reason_redacts_exception_arg_leak(tmp_path) -> None:
    """A policy whose exception message embeds a raw arg value must NOT leak it.

    On the fail-closed synth-DENY path the kernel sets ``reason=f'...{exc}'``; if
    the exception echoes an argument, the verbatim ``record.reason`` carries it.
    The envelope redacts ``reason``, so the agent-facing channel is leak-safe by
    construction — the value survives only in the audit-retained ``record.reason``.
    """
    sentinel = "ARG-SENTINEL-fec1c3a9d8b04127"

    class _ArgEchoRaisingPolicy(Policy):
        @property
        def version(self) -> str:
            return "test-arg-echo-raising/v1"

        def evaluate(self, call: ToolCall) -> DecisionRecord:
            raise RuntimeError(f"schema validation failed for {call.args.get('secret')}")

    kernel = _kernel_with(_ArgEchoRaisingPolicy(), tmp_path)
    with pytest.raises(DeniedError) as ei:
        kernel.dispatch("do.thing", {"secret": sentinel}, goal="g")
    err = ei.value
    env = err.to_rejection_dict()

    assert sentinel in err.record.reason  # kernel synthesized it into the record (audit keeps it)
    assert env["reason"] == _FAIL_CLOSED_REASON  # ...but the envelope redacts it
    assert sentinel not in json.dumps(env)  # the value never reaches the agent


def test_envelope_does_not_leak_arg_values(tmp_path) -> None:
    """No raw argument/state VALUES the record carries reach the envelope."""
    kernel = _kernel_with(
        BoundaryPolicy(forbidden_keywords=["forbidden"], rule_id="P-LEAK"), tmp_path
    )
    sentinel = "SENTINEL-SECRET-d41d8cd98f00b204"
    goal_sentinel = "GOAL-SENTINEL-e99a18c428cb38d5"
    with pytest.raises(DeniedError) as ei:
        kernel.dispatch(
            "do.thing",
            {"trigger": "this is forbidden", "secret": sentinel},
            goal=goal_sentinel,
            state={"session": "STATE-SENTINEL-3c59dc048e8850243"},
        )
    err = ei.value
    env = err.to_rejection_dict()
    blob = json.dumps(env)

    # Positive absence of sensitive VALUES the record actually holds — the real leak check.
    assert sentinel not in blob  # raw arg value
    assert goal_sentinel not in blob  # raw goal (free-text, sensitive-by-nature)
    assert err.record.argument_hash and err.record.argument_hash not in blob
    if err.record.state_hash:
        assert err.record.state_hash not in blob

    # Sensitive record FIELDS are absent by name too (cheap regression guard).
    for k in ("goal", "argument_hash", "state_hash", "transformed_args", "path"):
        assert k not in env

    # Secondary guard: keys ⊆ record's public surface ∪ fixed control keys.
    record_keys = set(err.record.to_dict())
    control_keys = {
        "status",
        "outcome",
        "audit_hash",
        "resumable",
        "resolution",
        "approval",
    }
    assert set(env) <= record_keys | control_keys


def test_reason_is_the_only_value_bearing_channel(tmp_path) -> None:
    """Documented boundary: a policy-authored value surfaces ONLY through `reason`.

    If a policy echoes an arg into its reason, that value appears in
    ``env['reason']`` (by design) and in NO other field. This pins the scope of
    the README warning "keep policy ``reason`` strings non-sensitive".
    """
    kernel = _kernel_with(_EchoReasonPolicy(), tmp_path)
    secret = "ECHO-SENTINEL-2cf24dba5fb0a30e"
    with pytest.raises(DeniedError) as ei:
        kernel.dispatch("do.thing", {"secret": secret}, goal="g")
    env = ei.value.to_rejection_dict()

    assert secret in env["reason"]  # the one by-design value channel
    leaked_elsewhere = {k: v for k, v in env.items() if k != "reason" and secret in json.dumps(v)}
    assert leaked_elsewhere == {}  # nowhere else


@pytest.mark.parametrize("decision", [Decision.ALLOW, Decision.TRANSFORM])
def test_rejection_dict_rejects_non_terminal_decision(decision: Decision) -> None:
    """Fail-closed: projecting a non-DENY/ESCALATE record raises, never fabricates."""
    record = DecisionRecord(
        decision=decision,
        tool="t",
        argument_hash="h",
        policy_version="v",
        event_id="e",
    )
    with pytest.raises(ValueError, match="DENY/ESCALATE"):
        rejection_dict(record, "ah", resumable=False, resolution="revise_and_retry")
