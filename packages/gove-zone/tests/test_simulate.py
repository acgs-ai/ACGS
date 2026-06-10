"""Tests for ``Kernel.simulate`` — read-only capability discovery (audit R4).

``simulate`` predicts the decision ``dispatch`` *would* reach, via the shared
``_evaluate_only`` path, without executing the tool or touching the audit chain.
Two properties matter and are tested directly:

- **Faithfulness:** ``simulate(x)`` reaches the same verdict ``dispatch(x)`` does
  (decision + matched_rules + policy_version + decision_request_hash), across
  ALLOW / DENY / ESCALATE / TRANSFORM and the fail-closed synthesized DENY.
- **Side-effect-freedom (kernel level):** no ``tool_fn`` runs and the audit chain
  head is unchanged across a ``simulate`` call — asserted, not assumed.
"""

from __future__ import annotations

import time

import pytest

from gove_zone import (
    AllowAllPolicy,
    BoundaryPolicy,
    ChainHashAuditStore,
    Decision,
    DecisionRecord,
    DeniedError,
    EscalateError,
    Kernel,
    Policy,
    ReplaySideStore,
    UnknownToolError,
    new_event_id,
    sha256_json,
)
from gove_zone.tool import ToolCall


class _EscalatePolicy(Policy):
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


class _TransformPolicy(Policy):
    @property
    def version(self) -> str:
        return "test-transform/v1"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        transformed = dict(call.args)
        transformed["redacted"] = True
        return DecisionRecord(
            decision=Decision.TRANSFORM,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("T:redact",),
            reason="redacted before execution",
            transformed_args=transformed,
        )


class _RaisingPolicy(Policy):
    """Raises — exercises the kernel's fail-closed synth DENY in simulate too."""

    @property
    def version(self) -> str:
        return "test-raising/v1"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        raise RuntimeError("boom")


class _SlowPolicy(Policy):
    """Sleeps past the watchdog deadline — exercises the timeout synth DENY."""

    @property
    def version(self) -> str:
        return "test-slow/v1"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        time.sleep(0.5)
        return DecisionRecord(
            decision=Decision.ALLOW,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
        )


class _MalformedTransformPolicy(Policy):
    """Returns TRANSFORM with no transformed_args — the kernel must downgrade to DENY."""

    @property
    def version(self) -> str:
        return "test-malformed-transform/v1"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.TRANSFORM,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("T:bad",),
            reason="transform without args",
        )  # transformed_args defaults to None


def _side_count(path) -> int:
    return sum(1 for _ in path.open()) if path.exists() else 0


def _kernel(policy: Policy, tmp_path) -> tuple[Kernel, list[dict]]:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    ran: list[dict] = []
    kernel = Kernel(policy=policy, audit=audit, actor="agent-x")

    @kernel.tool("do.thing")
    def thing(**kwargs: object) -> str:
        ran.append(dict(kwargs))
        return "did it"

    return kernel, ran


def _dispatch_record(kernel: Kernel, tool: str, args: dict, *, goal: str = "") -> DecisionRecord:
    """The DecisionRecord dispatch reaches, however it surfaces it."""
    try:
        _, receipt = kernel.dispatch(tool, args, goal=goal)
        return receipt.record
    except (DeniedError, EscalateError) as exc:
        return exc.record


def _assert_faithful(sim: DecisionRecord, disp: DecisionRecord) -> None:
    assert sim.decision == disp.decision
    assert sim.matched_rules == disp.matched_rules
    assert sim.policy_version == disp.policy_version
    # same actor/args/goal/path/state -> identical bound context hash
    assert sim.decision_request_hash == disp.decision_request_hash


def test_simulate_predicts_allow(tmp_path) -> None:
    kernel, ran = _kernel(AllowAllPolicy(), tmp_path)
    args = {"x": 1}
    before = kernel.audit.last_hash()

    sim = kernel.simulate("do.thing", args, goal="g")
    assert sim.decision is Decision.ALLOW
    assert ran == []  # no execution
    assert kernel.audit.last_hash() == before  # no audit append

    disp = _dispatch_record(kernel, "do.thing", args, goal="g")
    _assert_faithful(sim, disp)
    assert ran == [{"x": 1}]  # dispatch DID execute exactly once


def test_simulate_predicts_deny(tmp_path) -> None:
    kernel, ran = _kernel(
        BoundaryPolicy(forbidden_keywords=["forbidden"], rule_id="P-D"), tmp_path
    )
    args = {"trigger": "this is forbidden"}
    before = kernel.audit.last_hash()

    sim = kernel.simulate("do.thing", args, goal="g")
    assert sim.decision is Decision.DENY
    assert ran == []
    assert kernel.audit.last_hash() == before

    disp = _dispatch_record(kernel, "do.thing", args, goal="g")
    _assert_faithful(sim, disp)
    assert ran == []  # deny never executes


def test_simulate_predicts_escalate(tmp_path) -> None:
    kernel, ran = _kernel(_EscalatePolicy(), tmp_path)
    args = {"x": 1}
    before = kernel.audit.last_hash()

    sim = kernel.simulate("do.thing", args, goal="g")
    assert sim.decision is Decision.ESCALATE  # returns the record, does NOT raise
    assert ran == []
    assert kernel.audit.last_hash() == before

    disp = _dispatch_record(kernel, "do.thing", args, goal="g")
    _assert_faithful(sim, disp)


def test_simulate_predicts_transform(tmp_path) -> None:
    kernel, ran = _kernel(_TransformPolicy(), tmp_path)
    args = {"x": 1}
    before = kernel.audit.last_hash()

    sim = kernel.simulate("do.thing", args, goal="g")
    assert sim.decision is Decision.TRANSFORM
    assert sim.transformed_args == {"x": 1, "redacted": True}
    assert ran == []
    assert kernel.audit.last_hash() == before

    disp = _dispatch_record(kernel, "do.thing", args, goal="g")
    _assert_faithful(sim, disp)
    assert ran == [{"x": 1, "redacted": True}]  # dispatch executed the transformed args


def test_simulate_predicts_fail_closed_synth_deny(tmp_path) -> None:
    kernel, ran = _kernel(_RaisingPolicy(), tmp_path)
    args = {"x": 1}
    before = kernel.audit.last_hash()

    sim = kernel.simulate("do.thing", args, goal="g")
    assert sim.decision is Decision.DENY
    assert sim.policy_version == "fail-closed/policy-raised"
    assert any("POLICY_ERROR" in r for r in sim.matched_rules)
    assert ran == []
    assert kernel.audit.last_hash() == before

    disp = _dispatch_record(kernel, "do.thing", args, goal="g")
    _assert_faithful(sim, disp)


def test_simulate_unknown_tool_raises(tmp_path) -> None:
    """simulate mirrors dispatch: an unregistered tool raises UnknownToolError."""
    kernel, ran = _kernel(AllowAllPolicy(), tmp_path)
    before = kernel.audit.last_hash()
    with pytest.raises(UnknownToolError):
        kernel.simulate("nope.missing", {"x": 1})
    assert ran == []
    assert kernel.audit.last_hash() == before  # raised before any evaluation/append


def test_simulate_predicts_timeout_synth_deny(tmp_path) -> None:
    """Watchdog timeout -> fail-closed/policy-timeout DENY, faithful in simulate."""
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    ran: list[dict] = []
    kernel = Kernel(policy=_SlowPolicy(), audit=audit, actor="agent-x", policy_timeout=0.05)

    @kernel.tool("do.thing")
    def thing(**kwargs: object) -> str:
        ran.append(dict(kwargs))
        return "did it"

    args = {"x": 1}
    before = kernel.audit.last_hash()
    sim = kernel.simulate("do.thing", args, goal="g")
    assert sim.decision is Decision.DENY
    assert sim.policy_version == "fail-closed/policy-timeout"
    assert any("POLICY_ERROR:TIMEOUT" in r for r in sim.matched_rules)
    assert ran == []
    assert kernel.audit.last_hash() == before

    disp = _dispatch_record(kernel, "do.thing", args, goal="g")
    _assert_faithful(sim, disp)


def test_simulate_predicts_malformed_transform_deny(tmp_path) -> None:
    """A TRANSFORM with no transformed_args is downgraded to DENY — faithful in simulate."""
    kernel, ran = _kernel(_MalformedTransformPolicy(), tmp_path)
    args = {"x": 1}
    before = kernel.audit.last_hash()

    sim = kernel.simulate("do.thing", args, goal="g")
    assert sim.decision is Decision.DENY
    assert "POLICY_ERROR:MALFORMED_TRANSFORM" in sim.matched_rules
    assert ran == []
    assert kernel.audit.last_hash() == before

    disp = _dispatch_record(kernel, "do.thing", args, goal="g")
    _assert_faithful(sim, disp)


def test_simulate_does_not_write_side_store(tmp_path) -> None:
    """simulate writes neither the audit chain nor the raw-args side store."""
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    side_path = tmp_path / "side.jsonl"
    side = ReplaySideStore(side_path)
    ran: list[dict] = []
    kernel = Kernel(policy=AllowAllPolicy(), audit=audit, actor="agent-x", side_store=side)

    @kernel.tool("do.thing")
    def thing(**kwargs: object) -> str:
        ran.append(dict(kwargs))
        return "did it"

    before = kernel.audit.last_hash()
    sim = kernel.simulate("do.thing", {"x": 1}, goal="g")
    assert sim.decision is Decision.ALLOW
    assert ran == []
    assert kernel.audit.last_hash() == before  # no audit append
    assert _side_count(side_path) == 0  # no side-store write

    # contrast: a real dispatch DOES write the side store (proves the test is non-vacuous)
    kernel.dispatch("do.thing", {"x": 1}, goal="g")
    assert _side_count(side_path) == 1


def test_simulate_threads_path_and_state(tmp_path) -> None:
    """path/state context is threaded into the predicted record exactly as dispatch does."""
    kernel, ran = _kernel(AllowAllPolicy(), tmp_path)
    args = {"x": 1}
    ctx = {"goal": "g", "path": "tenant/matter-9", "state": {"trust_tier": "analyst"}}

    sim = kernel.simulate("do.thing", args, **ctx)
    assert sim.path  # non-empty normalized path
    assert sim.state_hash is not None

    _, receipt = kernel.dispatch("do.thing", args, **ctx)
    disp = receipt.record
    assert sim.path == disp.path
    assert sim.state_hash == disp.state_hash
    _assert_faithful(sim, disp)  # decision_request_hash binds path+state, so this proves threading
