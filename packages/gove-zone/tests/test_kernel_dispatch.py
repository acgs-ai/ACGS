"""Kernel dispatch path tests.

Proves the central loop:

- ALLOW path returns ``(result, receipt)`` with an audit-chained receipt.
- DENY path raises :class:`DeniedError` carrying the record + audit hash.
- ESCALATE path raises :class:`EscalateError`.
- Unknown-tool dispatch raises :class:`UnknownToolError`.
- Every dispatch — ALLOW or non-ALLOW — appends exactly one event to the
  audit chain, anchoring the decision.

These tests hit ``kernel.dispatch`` (the dispatcher path), not the tool
function directly — that's the wiring proof per the review-handler-wiring rule.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from gove_zone import (
    AllowAllPolicy,
    BoundaryPolicy,
    ChainHashAuditStore,
    Decision,
    DeniedError,
    DenyAllPolicy,
    Kernel,
    ToolEffect,
    UnknownToolError,
)
from gove_zone.decision import DecisionRecord, sha256_json
from gove_zone.errors import AuditError
from gove_zone.kernel import GovernedTool
from gove_zone.replay import replay_call
from gove_zone.replay_store import ReplaySideStore
from gove_zone.tool import ToolCall


def _kernel(tmp_path: Path, policy_obj: Any) -> Kernel:
    return Kernel(
        policy=policy_obj,
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
    )


class _StaticDecisionPolicy:
    def __init__(self, decision: Decision) -> None:
        self.decision = decision

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        transformed_args = {"value": "approved"} if self.decision is Decision.TRANSFORM else None
        return DecisionRecord(
            decision=self.decision,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version="test/static-v1",
            event_id=f"event-{self.decision.value}",
            reason=f"static {self.decision.value}",
            transformed_args=transformed_args,
        )


class _RaisingPolicy:
    def evaluate(self, call: ToolCall) -> DecisionRecord:
        raise RuntimeError("policy unavailable")


class _ActorPolicy:
    def evaluate(self, call: ToolCall) -> DecisionRecord:
        decision = Decision.ALLOW if call.actor == "admin" else Decision.DENY
        return DecisionRecord(
            decision=decision,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version="test/actor-v1",
            event_id="event-actor",
            reason="actor check",
        )


@pytest.mark.parametrize("decision", list(Decision))
def test_evaluate_and_record_preserves_decision_without_tool_invocation(
    tmp_path: Path,
    decision: Decision,
) -> None:
    k = _kernel(tmp_path, _StaticDecisionPolicy(decision))
    executed: list[str] = []

    @k.tool("side_effect")
    def side_effect(value: str) -> None:
        executed.append(value)

    record, audit_hash = k.evaluate_and_record(
        ToolCall(
            name="side_effect",
            args={"value": "requested"},
            actor="agent-1",
        )
    )

    assert executed == []
    assert record.decision is decision
    assert record.reason == f"static {decision.value}"
    assert record.transformed_args == (
        {"value": "approved"} if decision is Decision.TRANSFORM else None
    )
    events = list(k.audit.iter_events())
    assert len(events) == 1
    assert events[0]["decision"] == decision.value
    assert events[0]["event_hash"] == audit_hash


def test_evaluate_and_record_matches_simulate_fail_closed_synthesis(tmp_path: Path) -> None:
    k = _kernel(tmp_path, _RaisingPolicy())
    executed: list[str] = []

    @k.tool("side_effect")
    def side_effect(value: str) -> None:
        executed.append(value)

    args = {"value": "requested"}
    simulated = k.simulate(
        "side_effect",
        args,
        goal="release",
    )
    recorded, _ = k.evaluate_and_record(
        ToolCall(
            name="side_effect",
            args=args,
            goal="release",
            actor=k.actor,
        )
    )

    simulated_payload = simulated.to_dict()
    recorded_payload = recorded.to_dict()
    for unstable_field in ("event_id", "timestamp_iso"):
        simulated_payload.pop(unstable_field)
        recorded_payload.pop(unstable_field)
    assert recorded_payload == simulated_payload
    assert recorded.decision is Decision.DENY
    assert recorded.policy_version == "fail-closed/policy-raised"
    assert executed == []
    assert k.audit.verify_chain()["checked"] == 1


def test_evaluate_and_record_uses_kernel_actor_not_spoofed_actor(tmp_path: Path) -> None:
    k = Kernel(
        policy=_ActorPolicy(),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
        actor="worker",
    )

    record, _ = k.evaluate_and_record(ToolCall(name="unregistered", actor="admin"))

    assert record.decision is Decision.DENY
    assert record.actor == "worker"
    events = list(k.audit.iter_events())
    assert len(events) == 1
    assert events[0]["actor"] == "worker"


def test_evaluate_and_record_rejects_caller_context_override(tmp_path: Path) -> None:
    trusted_state = {"resource": "staging", "trust_tier": "worker"}
    k = Kernel(
        policy=_StaticDecisionPolicy(Decision.ALLOW),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
        actor="kernel-worker",
        context_hydrator=lambda _name, _args: trusted_state,
    )

    record, _ = k.evaluate_and_record(
        ToolCall(
            name="unregistered",
            actor="admin",
            path=("production",),
            state={"resource": "production", "trust_tier": "admin"},
        )
    )

    assert record.decision is Decision.DENY
    assert record.policy_version == "fail-closed/context-mismatch"
    assert record.actor == "kernel-worker"
    assert record.path == ()
    assert record.state_hash == sha256_json(trusted_state)
    events = list(k.audit.iter_events())
    assert len(events) == 1
    assert events[0]["actor"] == "kernel-worker"
    assert events[0]["path"] == []
    assert events[0]["state_hash"] == sha256_json(trusted_state)


def test_evaluate_and_record_allows_unregistered_tool_without_lookup(tmp_path: Path) -> None:
    k = _kernel(tmp_path, _StaticDecisionPolicy(Decision.ALLOW))

    record, audit_hash = k.evaluate_and_record(ToolCall(name="not_registered"))

    assert record.decision is Decision.ALLOW
    assert k.audit.last_hash() == audit_hash


def test_evaluate_and_record_audit_failure_raises_without_tool_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    k = _kernel(tmp_path, AllowAllPolicy())
    executed: list[str] = []

    @k.tool("side_effect")
    def side_effect(value: str) -> None:
        executed.append(value)

    def fail_append(record: DecisionRecord) -> dict[str, Any]:
        raise OSError("audit unavailable")

    monkeypatch.setattr(k.audit, "append", fail_append)

    with pytest.raises(AuditError, match="audit append failed"):
        k.evaluate_and_record(ToolCall(name="side_effect", args={"value": "requested"}))

    assert executed == []


def test_allow_dispatch_executes_tool_and_returns_receipt(tmp_path: Path) -> None:
    k = _kernel(tmp_path, AllowAllPolicy())

    @k.tool("echo", effect=ToolEffect.PURE_READ_ONLY)
    def echo(msg: str) -> str:
        return msg.upper()

    result, receipt = k.dispatch("echo", {"msg": "hi"})

    assert result == "HI"
    assert receipt.record.decision is Decision.ALLOW
    assert receipt.audit_hash and receipt.audit_hash != "0" * 64
    assert receipt.result_hash is not None
    assert receipt.actor == "anonymous"


def test_deny_dispatch_raises_and_does_not_execute(tmp_path: Path) -> None:
    k = _kernel(tmp_path, DenyAllPolicy(reason="test deny"))
    executed: list[str] = []

    @k.tool("side_effect", effect=ToolEffect.PURE_READ_ONLY)
    def side_effect() -> None:
        executed.append("ran")

    with pytest.raises(DeniedError) as exc_info:
        k.dispatch("side_effect")

    assert executed == []  # side effect was blocked
    assert exc_info.value.record.decision is Decision.DENY
    assert exc_info.value.audit_hash != "0" * 64
    assert "test deny" in str(exc_info.value)


def test_unknown_tool_raises_before_any_audit_append(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    k = Kernel(policy=AllowAllPolicy(), audit=ChainHashAuditStore(audit_path))

    with pytest.raises(UnknownToolError):
        k.dispatch("not_registered", {})

    # No events should have been appended.
    assert not audit_path.exists() or audit_path.read_text() == ""


def test_every_dispatch_anchors_in_audit_chain(tmp_path: Path) -> None:
    k = _kernel(tmp_path, AllowAllPolicy())

    @k.tool("noop", effect=ToolEffect.PURE_READ_ONLY)
    def noop() -> int:
        return 1

    for _ in range(5):
        k.dispatch("noop")

    result = k.audit.verify_chain()
    assert result["valid"] is True
    assert result["checked"] == 5


def test_dispatch_returns_receipt_linked_to_audit_event(tmp_path: Path) -> None:
    """The receipt's audit_hash must equal the event_hash recorded in audit."""
    k = _kernel(tmp_path, AllowAllPolicy())

    @k.tool("ping", effect=ToolEffect.PURE_READ_ONLY)
    def ping() -> str:
        return "pong"

    _, receipt = k.dispatch("ping")
    events = list(k.audit.iter_events())
    assert len(events) == 1
    assert events[0]["event_hash"] == receipt.audit_hash
    assert events[0]["event_id"] == receipt.record.event_id


def test_tool_registry_rejects_duplicate_names(tmp_path: Path) -> None:
    k = _kernel(tmp_path, AllowAllPolicy())

    @k.tool("dup")
    def first() -> None:
        return None

    with pytest.raises(ValueError, match="already registered"):

        @k.tool("dup")
        def second() -> None:
            return None


def test_kernel_tool_decorator_records_default_and_explicit_effects(tmp_path: Path) -> None:
    k = _kernel(tmp_path, AllowAllPolicy())

    @k.tool("default_effect")
    def default_effect() -> None:
        return None

    @k.tool("pure_read", effect=ToolEffect.PURE_READ_ONLY)
    def pure_read() -> str:
        return "value"

    assert k.registry.effect("default_effect") is ToolEffect.SIDE_EFFECT
    assert k.registry.effect("pure_read") is ToolEffect.PURE_READ_ONLY
    registered = k.registry._get_registered("pure_read")
    assert registered.fn is pure_read
    assert registered.effect is ToolEffect.PURE_READ_ONLY
    assert k.registry.get("pure_read") is pure_read


def test_governed_tool_wrapper_forwards_effect_metadata(tmp_path: Path) -> None:
    k = _kernel(tmp_path, AllowAllPolicy())

    def lookup() -> str:
        return "value"

    wrapped = GovernedTool(k, "lookup", lookup, effect=ToolEffect.PURE_READ_ONLY)

    assert k.registry.effect("lookup") is ToolEffect.PURE_READ_ONLY
    assert wrapped() == "value"


def test_default_off_creates_no_side_store_and_behaves_identically(tmp_path: Path) -> None:
    """With no side_store, dispatch is unchanged and no side-store file appears."""
    k = _kernel(tmp_path, AllowAllPolicy())

    @k.tool("echo", effect=ToolEffect.PURE_READ_ONLY)
    def echo(msg: str) -> str:
        return msg.upper()

    result, receipt = k.dispatch("echo", {"msg": "hi"})

    assert result == "HI"
    assert receipt.record.decision is Decision.ALLOW
    assert not (tmp_path / "replay.jsonl").exists()
    assert list(tmp_path.glob("*.jsonl")) == [tmp_path / "audit.jsonl"]


def test_opt_in_allow_writes_side_record_matching_receipt(tmp_path: Path) -> None:
    side_store = ReplaySideStore(tmp_path / "replay.jsonl")
    k = Kernel(
        policy=BoundaryPolicy(forbidden_keywords=["secret"]),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
        side_store=side_store,
    )

    @k.tool("send", effect=ToolEffect.PURE_READ_ONLY)
    def send(body: str) -> None:
        return None

    _, receipt = k.dispatch("send", {"body": "hello"})

    side = side_store.get(receipt.record.event_id)
    assert side is not None
    assert side["args"] == {"body": "hello"}
    assert side["argument_hash"] == receipt.record.argument_hash
    assert side["policy_version"] == receipt.record.policy_version
    assert side["decision"] == receipt.record.decision.value


def test_opt_in_deny_still_writes_side_record(tmp_path: Path) -> None:
    side_store = ReplaySideStore(tmp_path / "replay.jsonl")
    k = Kernel(
        policy=DenyAllPolicy(reason="blocked"),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
        side_store=side_store,
    )

    @k.tool("side_effect", effect=ToolEffect.PURE_READ_ONLY)
    def side_effect() -> None:
        return None

    with pytest.raises(DeniedError) as exc_info:
        k.dispatch("side_effect", {"x": 1})

    event_id = exc_info.value.record.event_id
    side = side_store.get(event_id)
    assert side is not None
    assert side["decision"] == "deny"
    assert side["args"] == {"x": 1}


def test_side_record_matches_audit_event_fields(tmp_path: Path) -> None:
    side_store = ReplaySideStore(tmp_path / "replay.jsonl")
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    k = Kernel(
        policy=BoundaryPolicy(forbidden_keywords=["secret"]),
        audit=audit,
        side_store=side_store,
    )

    @k.tool("send", effect=ToolEffect.PURE_READ_ONLY)
    def send(body: str) -> None:
        return None

    _, receipt = k.dispatch("send", {"body": "hello"})
    events = list(audit.iter_events())
    assert len(events) == 1
    event = events[0]
    side = side_store.get(receipt.record.event_id)
    assert side is not None
    assert side["event_id"] == event["event_id"]
    assert side["argument_hash"] == event["argument_hash"]
    assert side["policy_version"] == event["policy_version"]
    assert side["decision"] == event["decision"]


def test_redacted_call_tombstones_side_store_but_not_chain(tmp_path: Path) -> None:
    side_store = ReplaySideStore(
        tmp_path / "replay.jsonl",
        redact=lambda c: "id_rsa" in str(c.args),
    )
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    k = Kernel(
        policy=AllowAllPolicy(),
        audit=audit,
        side_store=side_store,
    )

    @k.tool("write_file", effect=ToolEffect.PURE_READ_ONLY)
    def write_file(path: str) -> str:
        return path

    _, receipt = k.dispatch("write_file", {"path": "id_rsa"})

    side = side_store.get(receipt.record.event_id)
    assert side == {"event_id": receipt.record.event_id, "redacted": True}

    events = list(audit.iter_events())
    assert events[0]["argument_hash"] == receipt.record.argument_hash
    assert audit.verify_chain()["valid"] is True


def test_side_store_record_feeds_replay_call(tmp_path: Path) -> None:
    """The write path produces a record the replay re-derivation can consume."""
    policy = BoundaryPolicy(forbidden_keywords=["secret"])
    side_store = ReplaySideStore(tmp_path / "replay.jsonl")
    k = Kernel(
        policy=policy,
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
        side_store=side_store,
    )

    @k.tool("send", effect=ToolEffect.PURE_READ_ONLY)
    def send(body: str) -> None:
        return None

    _, receipt = k.dispatch("send", {"body": "hello"})
    side = side_store.get(receipt.record.event_id)
    assert side is not None

    reconstructed = ToolCall(
        name=side["tool"],
        args=dict(side["args"]),
        goal=side["goal"],
        actor=side["actor"],
        path=tuple(side["path"]),
        state=dict(side["state"]),
    )
    replayed = replay_call(
        reconstructed,
        expected_decision=receipt.record.decision,
        policy=policy,
        expected_policy_version=receipt.record.policy_version,
    )
    assert replayed.matches is True
