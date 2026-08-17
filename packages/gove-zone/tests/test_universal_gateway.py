"""Universal Agent Gateway — Policy → Receipt → Executor across every surface.

Covers the single chokepoint (invoke), the five framework surfaces (MCP,
OpenAI function calling, LangGraph is exercised via the shared invoke path,
Claude Code hooks, REST), and bypass detection (sealed tools).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from pathlib import Path
from typing import Any

import pytest

from gove_zone.consumption import ReceiptConsumptionLedger
from gove_zone.decision import Decision, DecisionRecord
from gove_zone.errors import ProductionProfileError, UnknownToolError
from gove_zone.gateway import (
    BYPASS_RULE,
    BypassAttemptError,
    UniversalGateway,
    http_json_tool,
)
from gove_zone.policy import Policy, PolicyRule, RuleSetPolicy
from gove_zone.profile import GovernanceProfile
from gove_zone.receipt import Validator
from gove_zone.tool import ToolCall


class FakeSigner:
    """Deterministic HMAC signer implementing the ReceiptSigner protocol."""

    algorithm = "test-hmac-sha256"

    def __init__(self, key: bytes = b"test-key", key_id: str = "test-key-1") -> None:
        self._key = key
        self.key_id = key_id

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


def make_policy() -> RuleSetPolicy:
    return RuleSetPolicy(
        policy_id="gateway-tests",
        rules=(
            PolicyRule(
                rule_id="deny-rm-prod",
                effect=Decision.DENY,
                tools=frozenset({"rm_prod"}),
                reason="destructive tool is always denied",
            ),
            PolicyRule(
                rule_id="escalate-deploy",
                effect=Decision.ESCALATE,
                tools=frozenset({"deploy"}),
                reason="deploy requires human approval",
            ),
            PolicyRule(
                rule_id="deny-runtime-bash",
                effect=Decision.DENY,
                tools=frozenset({"runtime.Bash"}),
                reason="runtime Bash is denied for hook tests",
            ),
        ),
    )


def make_gateway(
    tmp_path: Path,
    *,
    policy: Policy | None = None,
    profile: GovernanceProfile | None = None,
    allowed_actors: frozenset[str] | None = None,
    approver_actors: frozenset[str] | None = None,
    max_pending: int = 256,
    max_pending_per_principal: int = 64,
) -> UniversalGateway:
    signer = FakeSigner()
    return UniversalGateway(
        tenant_id="tenant-1",
        execution_boundary="boundary-1",
        policy=policy or make_policy(),
        profile=profile or GovernanceProfile.production(signer=signer, verifier=signer),
        validator=Validator(validator_id="validator-1"),
        authority="authority-1",
        audit_path=tmp_path / "audit.jsonl",
        ledger_path=tmp_path / "ledger.jsonl",
        allowed_actors=allowed_actors,
        approver_actors=approver_actors,
        max_pending=max_pending,
        max_pending_per_principal=max_pending_per_principal,
    )


def audit_events(tmp_path: Path) -> list[dict[str, Any]]:
    path = tmp_path / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# -- the chokepoint ---------------------------------------------------------- #


def test_allow_executes_with_signed_receipt(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)
    calls: list[dict[str, Any]] = []

    def echo(message: str) -> str:
        calls.append({"message": message})
        return f"echo:{message}"

    gateway.register_tool("echo", echo)
    outcome = gateway.invoke("agent-a", "echo", {"message": "hi"})

    assert outcome.executed
    assert outcome.result == "echo:hi"
    assert calls == [{"message": "hi"}]
    assert outcome.receipt is not None
    assert outcome.receipt.signature_algorithm == "test-hmac-sha256"
    anchors = outcome.receipt_anchors()
    assert anchors["receipt_hash"]
    assert anchors["audit_hash"] == outcome.audit_hash
    events = audit_events(tmp_path)
    assert len(events) == 1
    assert events[0]["decision"] == "allow"
    # single-use: the executed receipt was burned in the ledger
    assert (tmp_path / "ledger.jsonl").read_text().strip()


def test_deny_blocks_side_effect(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)
    calls: list[Any] = []
    gateway.register_tool("rm_prod", lambda **kwargs: calls.append(kwargs))

    outcome = gateway.invoke("agent-a", "rm_prod", {"target": "db"})

    assert outcome.status == "denied"
    assert calls == []
    assert outcome.envelope is not None
    assert outcome.envelope["outcome"] == "denied"
    assert outcome.envelope["resolution"] == "revise_and_retry"
    assert audit_events(tmp_path)[0]["decision"] == "deny"


def test_escalate_returns_envelope(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)
    calls: list[Any] = []
    gateway.register_tool("deploy", lambda **kwargs: calls.append(kwargs))

    outcome = gateway.invoke("agent-a", "deploy", {"env": "prod"})

    assert outcome.status == "escalated"
    assert calls == []
    assert outcome.envelope is not None
    assert outcome.envelope["outcome"] == "escalated"
    assert outcome.envelope["resolution"] == "human_approval"
    assert outcome.envelope["resumable"] is True
    assert outcome.envelope["approval"]["event_id"]


def test_unknown_tool_is_structurally_uncallable(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)
    with pytest.raises(UnknownToolError):
        gateway.invoke("agent-a", "not_registered", {})


def test_actor_allowlist_denies_and_audits(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path, allowed_actors=frozenset({"alice"}))
    calls: list[Any] = []
    gateway.register_tool("echo", lambda **kwargs: calls.append(kwargs))

    outcome = gateway.invoke("mallory", "echo", {"message": "hi"})

    assert outcome.status == "denied"
    assert calls == []
    assert outcome.envelope is not None
    assert "ACTOR_NOT_ALLOWED" in outcome.envelope["matched_rules"]
    events = audit_events(tmp_path)
    assert events[0]["matched_rules"] == ["ACTOR_NOT_ALLOWED"]

    allowed = gateway.invoke("alice", "echo", {"message": "hi"})
    assert allowed.executed


def test_production_profile_without_verifier_fails_loud(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path, profile=GovernanceProfile.production(signer=FakeSigner()))
    gateway.register_tool("echo", lambda message: message)
    with pytest.raises(ProductionProfileError):
        gateway.invoke("agent-a", "echo", {"message": "hi"})


def test_tool_exception_reports_class_only(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)

    def boom(secret: str) -> None:
        raise RuntimeError(f"leaked {secret}")

    gateway.register_tool("boom", boom)
    outcome = gateway.invoke("agent-a", "boom", {"secret": "s3cr3t"})

    assert outcome.status == "error"
    assert outcome.error_class == "RuntimeError"
    assert "s3cr3t" not in json.dumps(outcome.to_dict())


class _TransformPolicy(Policy):
    """Rewrites every call's args to a fixed transformed payload."""

    def __init__(self, transformed: dict[str, Any]) -> None:
        self._transformed = transformed

    @property
    def version(self) -> str:
        return "transform-test/v1"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.TRANSFORM,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version=self.version,
            event_id=uuid.uuid4().hex,
            matched_rules=("transform-all",),
            reason="test transform",
            transformed_args=dict(self._transformed),
            goal=call.goal,
            actor=call.actor,
            path=call.path,
            state_hash=call.state_hash(),
            decision_request_hash=call.decision_request_hash(),
        )


def test_transform_executes_transformed_args(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path, policy=_TransformPolicy({"message": "sanitized"}))
    calls: list[dict[str, Any]] = []

    def echo(message: str) -> str:
        calls.append({"message": message})
        return message

    gateway.register_tool("echo", echo)
    outcome = gateway.invoke("agent-a", "echo", {"message": "raw"})

    assert outcome.executed
    assert calls == [{"message": "sanitized"}]


# -- bypass detection --------------------------------------------------------- #


def test_direct_sealed_call_is_blocked_and_audited(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)
    calls: list[Any] = []
    sealed = gateway.register_tool("echo", lambda **kwargs: calls.append(kwargs))

    with pytest.raises(BypassAttemptError):
        sealed(message="sneaky")

    assert calls == []
    attempts = gateway.bypass_attempts()
    assert len(attempts) == 1
    assert attempts[0]["tool"] == "echo"
    events = audit_events(tmp_path)
    assert events[-1]["decision"] == "deny"
    assert events[-1]["matched_rules"] == [BYPASS_RULE]


def test_nested_sealed_call_inside_gated_tool_is_detected(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)
    side_effects: list[str] = []
    sealed_b = gateway.register_tool("tool_b", lambda **kwargs: side_effects.append("b-ran"))

    def tool_a() -> str:
        # tool A abuses its gated execution window to call another sealed
        # tool without its own decision/receipt: must be detected.
        sealed_b()
        return "a-ran"

    gateway.register_tool("tool_a", tool_a)

    with pytest.raises(BypassAttemptError):
        gateway.invoke("agent-a", "tool_a", {})

    assert side_effects == []
    assert any(entry["tool"] == "tool_b" for entry in gateway.bypass_attempts())


def test_reentrant_same_tool_call_is_detected(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)
    runs: list[str] = []
    holder: dict[str, Any] = {}

    def recurse() -> str:
        runs.append("ran")
        holder["sealed"]()  # one-shot grant already spent
        return "done"

    holder["sealed"] = gateway.register_tool("recurse", recurse)

    with pytest.raises(BypassAttemptError):
        gateway.invoke("agent-a", "recurse", {})

    assert runs == ["ran"]


# -- MCP surface --------------------------------------------------------------- #


def test_mcp_call_allow_and_deny(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)
    gateway.register_tool("echo", lambda message: f"echo:{message}")
    gateway.register_tool("rm_prod", lambda **kwargs: "never")

    allowed = gateway.handle_mcp_call(
        {"method": "tools/call", "params": {"name": "echo", "arguments": {"message": "hi"}}},
        actor="agent-a",
    )
    assert allowed["isError"] is False
    assert allowed["content"][0]["text"] == "echo:hi"
    assert allowed["_meta"]["gove_zone"]["decision"] == "allow"
    assert allowed["_meta"]["gove_zone"]["receipt_hash"]

    denied = gateway.handle_mcp_call(
        {"name": "rm_prod", "arguments": {"target": "db"}}, actor="agent-a"
    )
    assert denied["isError"] is True
    assert denied["_meta"]["gove_zone"]["decision"] == "denied"
    assert denied["_meta"]["gove_zone"]["envelope"]["outcome"] == "denied"


def test_mcp_call_malformed_and_unregistered(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)
    malformed = gateway.handle_mcp_call({"params": []}, actor="agent-a")  # type: ignore[dict-item]
    assert malformed["isError"] is True
    assert malformed["_meta"]["gove_zone"]["decision"] == "not_evaluated"

    missing = gateway.handle_mcp_call({"name": "ghost", "arguments": {}}, actor="agent-a")
    assert missing["isError"] is True
    assert "not registered" in missing["content"][0]["text"]


def test_mcp_tools_list_matches_registry(tmp_path: Path) -> None:
    from gove_zone.gateway import MCP_APPROVE_TOOL, MCP_RESUME_TOOL

    gateway = make_gateway(tmp_path)
    gateway.register_tool("b_tool", lambda: None)
    gateway.register_tool("a_tool", lambda: None)
    assert gateway.mcp_tools_list() == {
        "tools": [
            {"name": MCP_APPROVE_TOOL},
            {"name": MCP_RESUME_TOOL},
            {"name": "a_tool"},
            {"name": "b_tool"},
        ]
    }


def test_reserved_name_cannot_be_registered(tmp_path: Path) -> None:
    from gove_zone.gateway import MCP_APPROVE_TOOL

    gateway = make_gateway(tmp_path)
    with pytest.raises(ValueError, match="reserved"):
        gateway.register_tool(MCP_APPROVE_TOOL, lambda **kwargs: "nope")


def test_approver_actors_must_be_disjoint_from_allowed_actors(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="approver_actors collide"):
        make_gateway(
            tmp_path,
            allowed_actors=frozenset({"agent-a"}),
            approver_actors=frozenset({"agent-a"}),
        )


def test_mcp_human_loop_is_reachable_through_handle_mcp_call(tmp_path: Path) -> None:
    from gove_zone.gateway import MCP_APPROVE_TOOL, MCP_RESUME_TOOL

    gateway = make_gateway(tmp_path, approver_actors=frozenset({"human-approver"}))
    calls: list[dict[str, Any]] = []
    gateway.register_tool("deploy", lambda **kwargs: calls.append(dict(kwargs)) or "deployed")

    parked = gateway.handle_mcp_call(
        {"name": "deploy", "arguments": {"env": "prod"}}, actor="agent-a"
    )
    assert parked["isError"] is True
    assert parked["_meta"]["gove_zone"]["decision"] == "escalated"
    event_id = parked["_meta"]["gove_zone"]["escalation_event_id"]
    assert calls == []

    self_approve = gateway.handle_mcp_call(
        {"name": MCP_APPROVE_TOOL, "arguments": {"event_id": event_id}},
        actor="agent-a",
    )
    assert self_approve["isError"] is True
    assert calls == []

    approved = gateway.handle_mcp_call(
        {"name": MCP_APPROVE_TOOL, "arguments": {"event_id": event_id}},
        actor="human-approver",
    )
    assert approved["isError"] is False
    assert approved["_meta"]["gove_zone"]["executed"] is False
    assert calls == []

    resumed = gateway.handle_mcp_call(
        {"name": MCP_RESUME_TOOL, "arguments": {"event_id": event_id}},
        actor="agent-a",
    )
    assert resumed["isError"] is False
    assert calls == [{"env": "prod"}]

    replay = gateway.handle_mcp_call(
        {"name": MCP_RESUME_TOOL, "arguments": {"event_id": event_id}},
        actor="agent-a",
    )
    assert replay["isError"] is True
    assert calls == [{"env": "prod"}]


def test_mcp_resume_expired_approval_does_not_execute(tmp_path: Path) -> None:
    from datetime import UTC, datetime, timedelta

    from gove_zone.gateway import MCP_RESUME_TOOL

    gateway = make_gateway(tmp_path, approver_actors=frozenset({"human-approver"}))
    calls: list[Any] = []
    gateway.register_tool("deploy", lambda **kwargs: calls.append(kwargs))
    parked = gateway.invoke("agent-a", "deploy", {"env": "prod"})
    event_id = parked.envelope["approval"]["event_id"]
    expired = (datetime.now(UTC) - timedelta(seconds=5)).isoformat()
    from gove_zone.escalation import approve_escalation
    from gove_zone.receipt import Validator

    pending = gateway._pending[event_id]
    receipt = approve_escalation(
        pending,
        validator=Validator(validator_id="human-approver", role="approver"),
        authority=gateway.authority,
        tenant_id=gateway.tenant_id,
        execution_boundary=gateway.execution_boundary,
        policy_bundle_id=gateway.policy_bundle_id,
        policy_hash=gateway.policy.version,
        audit=gateway._audit,
        expires_at=expired,
        signer=gateway.profile.signer,
    )
    gateway._approvals[event_id] = (receipt, receipt.audit_event_hash)

    resumed = gateway.handle_mcp_call(
        {"name": MCP_RESUME_TOOL, "arguments": {"event_id": event_id}},
        actor="agent-a",
    )
    assert resumed["isError"] is True
    assert calls == []


def test_non_approver_cannot_approve_via_handle_mcp_call(tmp_path: Path) -> None:
    from gove_zone.gateway import MCP_APPROVE_TOOL

    gateway = make_gateway(tmp_path, approver_actors=frozenset({"human-approver"}))
    calls: list[dict[str, Any]] = []
    gateway.register_tool("deploy", lambda **kwargs: calls.append(dict(kwargs)) or "deployed")

    parked = gateway.handle_mcp_call(
        {"name": "deploy", "arguments": {"env": "prod"}}, actor="agent-a"
    )
    event_id = parked["_meta"]["gove_zone"]["escalation_event_id"]

    refused = gateway.handle_mcp_call(
        {"name": MCP_APPROVE_TOOL, "arguments": {"event_id": event_id}},
        actor="agent-b",
    )
    assert refused["isError"] is True
    assert refused["_meta"]["gove_zone"]["decision"] == "denied"
    assert calls == []
    assert event_id in gateway._pending
    assert event_id not in gateway._approvals

    later = gateway.handle_mcp_call(
        {"name": MCP_APPROVE_TOOL, "arguments": {"event_id": event_id}},
        actor="human-approver",
    )
    assert later["isError"] is False
    assert calls == []


def test_only_proposer_may_resume_via_handle_mcp_call(tmp_path: Path) -> None:
    from gove_zone.gateway import MCP_APPROVE_TOOL, MCP_RESUME_TOOL

    gateway = make_gateway(tmp_path, approver_actors=frozenset({"human-approver"}))
    calls: list[dict[str, Any]] = []
    gateway.register_tool("deploy", lambda **kwargs: calls.append(dict(kwargs)) or "deployed")

    parked = gateway.handle_mcp_call(
        {"name": "deploy", "arguments": {"env": "prod"}}, actor="agent-a"
    )
    event_id = parked["_meta"]["gove_zone"]["escalation_event_id"]
    approved = gateway.handle_mcp_call(
        {"name": MCP_APPROVE_TOOL, "arguments": {"event_id": event_id}},
        actor="human-approver",
    )
    assert approved["isError"] is False

    stranger = gateway.handle_mcp_call(
        {"name": MCP_RESUME_TOOL, "arguments": {"event_id": event_id}},
        actor="agent-b",
    )
    assert stranger["isError"] is True
    assert stranger["_meta"]["gove_zone"]["decision"] == "denied"
    assert calls == []
    assert event_id in gateway._pending

    resumed = gateway.handle_mcp_call(
        {"name": MCP_RESUME_TOOL, "arguments": {"event_id": event_id}},
        actor="agent-a",
    )
    assert resumed["isError"] is False
    assert calls == [{"env": "prod"}]


def test_human_loop_refusal_is_audited_and_chain_verifies(tmp_path: Path) -> None:
    from gove_zone.audit import ChainHashAuditStore
    from gove_zone.gateway import HUMAN_LOOP_REFUSED_RULE, MCP_APPROVE_TOOL

    gateway = make_gateway(tmp_path, approver_actors=frozenset({"human-approver"}))
    calls: list[Any] = []
    gateway.register_tool("deploy", lambda **kwargs: calls.append(kwargs))
    # The proposer is also a mapped approver, so the not_approver guard does
    # not fire and the self-approval rule is the one that must audit.
    parked = gateway.handle_mcp_call(
        {"name": "deploy", "arguments": {"env": "prod"}}, actor="human-approver"
    )
    event_id = parked["_meta"]["gove_zone"]["escalation_event_id"]

    refused = gateway.handle_mcp_call(
        {"name": MCP_APPROVE_TOOL, "arguments": {"event_id": event_id}},
        actor="human-approver",
    )
    assert refused["isError"] is True
    envelope = refused["_meta"]["gove_zone"]["envelope"]
    assert envelope["audit_hash"]
    assert envelope["matched_rules"] == [f"{HUMAN_LOOP_REFUSED_RULE}:self_approval"]
    assert calls == []
    assert event_id in gateway._pending

    report = ChainHashAuditStore(str(tmp_path / "audit.jsonl")).verify_chain()
    assert report["valid"] is True
    assert any(
        event.get("matched_rules") == [f"{HUMAN_LOOP_REFUSED_RULE}:self_approval"]
        for event in audit_events(tmp_path)
    )


def test_pending_capacity_backpressure_on_universal_gateway(tmp_path: Path) -> None:
    from gove_zone.gateway import CAPACITY_REJECTED_RULE

    gateway = make_gateway(
        tmp_path,
        approver_actors=frozenset({"human-approver"}),
        max_pending=2,
        max_pending_per_principal=2,
    )
    calls: list[Any] = []
    gateway.register_tool("deploy", lambda **kwargs: calls.append(kwargs))

    first = gateway.handle_mcp_call({"name": "deploy", "arguments": {"env": "a"}}, actor="agent-a")
    second = gateway.handle_mcp_call({"name": "deploy", "arguments": {"env": "b"}}, actor="agent-a")
    assert first["_meta"]["gove_zone"]["decision"] == "escalated"
    assert second["_meta"]["gove_zone"]["decision"] == "escalated"
    assert len(gateway._pending) == 2

    overflow = gateway.handle_mcp_call(
        {"name": "deploy", "arguments": {"env": "c"}}, actor="agent-a"
    )
    assert overflow["isError"] is True
    assert overflow["_meta"]["gove_zone"]["decision"] == "denied"
    assert overflow["_meta"]["gove_zone"]["envelope"]["matched_rules"] == [
        f"{CAPACITY_REJECTED_RULE}:pending"
    ]
    assert len(gateway._pending) == 2
    assert calls == []


def test_constructor_rejects_nonpositive_pending_caps(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="capacity caps must be positive"):
        make_gateway(tmp_path, max_pending=0)


def test_per_principal_capacity_rejects_before_global(tmp_path: Path) -> None:
    from gove_zone.gateway import CAPACITY_REJECTED_RULE

    gateway = make_gateway(
        tmp_path,
        approver_actors=frozenset({"human-approver"}),
        max_pending=10,
        max_pending_per_principal=2,
    )
    calls: list[Any] = []
    gateway.register_tool("deploy", lambda **kwargs: calls.append(kwargs))
    gateway.handle_mcp_call({"name": "deploy", "arguments": {"env": "a"}}, actor="agent-a")
    gateway.handle_mcp_call({"name": "deploy", "arguments": {"env": "b"}}, actor="agent-a")
    overflow = gateway.handle_mcp_call(
        {"name": "deploy", "arguments": {"env": "c"}}, actor="agent-a"
    )
    assert overflow["_meta"]["gove_zone"]["decision"] == "denied"
    assert overflow["_meta"]["gove_zone"]["envelope"]["matched_rules"] == [
        f"{CAPACITY_REJECTED_RULE}:principal"
    ]
    assert len(gateway._pending) == 2
    assert calls == []


def test_post_burn_tool_failure_frees_pending_slot(tmp_path: Path) -> None:
    from gove_zone.gateway import MCP_APPROVE_TOOL, MCP_RESUME_TOOL

    gateway = make_gateway(tmp_path, approver_actors=frozenset({"human-approver"}))

    def boom(**kwargs: Any) -> None:
        raise RuntimeError("downstream exploded")

    gateway.register_tool("deploy", boom)
    parked = gateway.handle_mcp_call(
        {"name": "deploy", "arguments": {"env": "prod"}}, actor="agent-a"
    )
    event_id = parked["_meta"]["gove_zone"]["escalation_event_id"]
    approved = gateway.handle_mcp_call(
        {"name": MCP_APPROVE_TOOL, "arguments": {"event_id": event_id}},
        actor="human-approver",
    )
    assert approved["isError"] is False
    failed = gateway.handle_mcp_call(
        {"name": MCP_RESUME_TOOL, "arguments": {"event_id": event_id}},
        actor="agent-a",
    )
    assert failed["isError"] is True
    assert failed["_meta"]["gove_zone"]["error_class"] == "RuntimeError"
    assert event_id not in gateway._pending
    replay = gateway.handle_mcp_call(
        {"name": MCP_RESUME_TOOL, "arguments": {"event_id": event_id}},
        actor="agent-a",
    )
    assert replay["isError"] is True
    assert event_id not in gateway._pending


def test_openai_tool_specs_from_signatures(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)

    def send_mail(to: str, retries: int = 3) -> str:
        """Send an email."""
        return to

    gateway.register_tool("send_mail", send_mail)
    (spec,) = gateway.openai_tools()
    assert spec["type"] == "function"
    function = spec["function"]
    assert function["name"] == "send_mail"
    assert function["description"] == "Send an email."
    assert function["parameters"]["properties"]["to"] == {"type": "string"}
    assert function["parameters"]["properties"]["retries"] == {"type": "integer"}
    assert function["parameters"]["required"] == ["to"]


def test_openai_tool_call_roundtrip(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)
    gateway.register_tool("echo", lambda message: f"echo:{message}")

    message = gateway.handle_openai_tool_call(
        {
            "id": "call_1",
            "type": "function",
            "function": {"name": "echo", "arguments": json.dumps({"message": "hi"})},
        },
        actor="agent-a",
    )
    assert message["role"] == "tool"
    assert message["tool_call_id"] == "call_1"
    body = json.loads(message["content"])
    assert body["status"] == "executed"
    assert body["result"] == "echo:hi"
    assert body["receipt"]["receipt_hash"]


def test_openai_malformed_arguments_fail_closed(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)
    calls: list[Any] = []
    gateway.register_tool("echo", lambda **kwargs: calls.append(kwargs))

    message = gateway.handle_openai_tool_call(
        {"id": "call_2", "function": {"name": "echo", "arguments": "{not json"}},
        actor="agent-a",
    )
    body = json.loads(message["content"])
    assert body["status"] == "error"
    assert calls == []


# -- Claude Code hook surface ------------------------------------------------------ #


def test_claude_hook_deny_and_allow(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)

    denied = gateway.handle_claude_hook(
        {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
        actor="claude-session-1",
    )
    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"

    allowed = gateway.handle_claude_hook(
        {"tool_name": "Read", "tool_input": {"file_path": "/tmp/x"}},
        actor="claude-session-1",
    )
    assert allowed["hookSpecificOutput"]["permissionDecision"] == "allow"
    (receipt_anchor,) = allowed["gove_zone"]["receipts"]
    assert receipt_anchor["receipt_hash"]
    assert receipt_anchor["signature_algorithm"] == "test-hmac-sha256"

    events = audit_events(tmp_path)
    assert [event["decision"] for event in events] == ["deny", "allow"]


def test_claude_hook_batch_deny_wins(tmp_path: Path) -> None:
    # A batch smuggling a denied action alongside an allowed one must be
    # denied as a whole — every item is evaluated and audited individually.
    gateway = make_gateway(tmp_path)
    response = gateway.handle_claude_hook(
        {
            "tool_calls": [
                {"function": {"name": "Read", "arguments": '{"file_path": "/tmp/x"}'}},
                {"function": {"name": "Bash", "arguments": '{"command": "rm -rf /"}'}},
            ]
        },
        actor="claude-session-1",
    )
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    events = audit_events(tmp_path)
    assert len(events) == 2
    assert sorted(event["decision"] for event in events) == ["allow", "deny"]


def test_claude_hook_batch_all_allowed_mints_receipt_per_call(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)
    response = gateway.handle_claude_hook(
        {
            "tool_calls": [
                {"function": {"name": "Read", "arguments": '{"file_path": "/tmp/a"}'}},
                {"function": {"name": "Glob", "arguments": '{"pattern": "*.py"}'}},
            ]
        },
        actor="claude-session-1",
    )
    assert response["hookSpecificOutput"]["permissionDecision"] == "allow"
    receipts = response["gove_zone"]["receipts"]
    assert len(receipts) == 2
    assert all(anchor["receipt_hash"] for anchor in receipts)


def test_claude_hook_actor_allowlist(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path, allowed_actors=frozenset({"alice"}))
    response = gateway.handle_claude_hook({"tool_name": "Read", "tool_input": {}}, actor="mallory")
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    # The refusal is chain-visible, exactly like the `invoke` surface: an
    # unauthorized principal probing the hook must not be invisible to chain
    # verification and incident review.
    (event,) = audit_events(tmp_path)
    assert event["decision"] == "deny"
    assert event["matched_rules"] == ["ACTOR_NOT_ALLOWED"]
    assert event["actor"] == "mallory"


def test_claude_hook_actor_allowlist_audits_every_batched_call(tmp_path: Path) -> None:
    # The docstring promise — every proposed call is evaluated and audited
    # individually — holds for the allowlist refusal too: one synthesized
    # deny per call, not one per batch.
    gateway = make_gateway(tmp_path, allowed_actors=frozenset({"alice"}))
    response = gateway.handle_claude_hook(
        {
            "tool_calls": [
                {"function": {"name": "Read", "arguments": '{"file_path": "/tmp/a"}'}},
                {"function": {"name": "Glob", "arguments": '{"pattern": "*.py"}'}},
            ]
        },
        actor="mallory",
    )
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "gove_zone" not in response
    events = audit_events(tmp_path)
    assert len(events) == 2
    assert all(event["decision"] == "deny" for event in events)
    assert all(event["matched_rules"] == ["ACTOR_NOT_ALLOWED"] for event in events)


# -- REST surface ------------------------------------------------------------------- #


def test_rest_surface_status_mapping(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)
    gateway.register_tool("echo", lambda message: f"echo:{message}")
    gateway.register_tool("rm_prod", lambda **kwargs: "never")
    gateway.register_tool("deploy", lambda **kwargs: "never")

    ok = gateway.handle_rest_call({"tool": "echo", "args": {"message": "hi"}}, actor="agent-a")
    assert ok["status"] == 200
    assert ok["body"]["result"] == "echo:hi"

    forbidden = gateway.handle_rest_call({"tool": "rm_prod", "args": {}}, actor="agent-a")
    assert forbidden["status"] == 403

    escalated = gateway.handle_rest_call({"tool": "deploy", "args": {}}, actor="agent-a")
    assert escalated["status"] == 202

    missing = gateway.handle_rest_call({"tool": "ghost", "args": {}}, actor="agent-a")
    assert missing["status"] == 404

    malformed = gateway.handle_rest_call({"args": {}}, actor="agent-a")
    assert malformed["status"] == 400

    with pytest.raises(ValueError):
        gateway.handle_rest_call({"tool": "echo", "args": {}}, actor="")


def test_rest_surface_ignores_body_supplied_actor(tmp_path: Path) -> None:
    # Identity spoofing guard: an "actor" key in the wire payload must never
    # override the authenticated principal supplied by the web layer.
    gateway = make_gateway(tmp_path, allowed_actors=frozenset({"alice"}))
    calls: list[Any] = []
    gateway.register_tool("echo", lambda **kwargs: calls.append(kwargs))

    spoofed = gateway.handle_rest_call(
        {"tool": "echo", "actor": "alice", "args": {"message": "hi"}},
        actor="mallory",
    )
    assert spoofed["status"] == 403
    assert calls == []
    assert spoofed["body"]["actor"] == "mallory"


# -- outbound REST tool factory ------------------------------------------------------- #


def test_http_json_tool_pins_url() -> None:
    tool = http_json_tool("https://api.example.com/v1/send")
    assert "api.example.com" in (tool.__name__ or "")
    with pytest.raises(ValueError):
        http_json_tool("ftp://example.com/x")
    with pytest.raises(ValueError):
        http_json_tool("/relative/path")


# -- registry discipline ---------------------------------------------------------------- #


def test_duplicate_registration_fails_loud(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)
    gateway.register_tool("echo", lambda message: message)
    with pytest.raises(ValueError, match="already registered"):
        gateway.register_tool("echo", lambda message: f"impostor:{message}")


def test_grant_is_bound_to_sealed_instance_not_name(tmp_path: Path) -> None:
    # A stale handle for the same tool name must not be able to consume a
    # grant issued for the currently registered sealed tool.
    gateway = make_gateway(tmp_path)
    ran: list[str] = []
    stale = gateway.register_tool("worker", lambda **kwargs: ran.append("real"))

    def hijack(**kwargs: Any) -> None:
        # Inside worker's gate window, the (already spent or differently
        # bound) stale handle must still be blocked.
        with pytest.raises(BypassAttemptError):
            stale(**kwargs)

    # Fresh gateway sharing nothing: simulate replacement by a second gateway
    # registering the same name — the grant check is instance-bound.
    other = make_gateway(tmp_path / "other")
    other.register_tool("worker", hijack)
    outcome = other.invoke("agent-a", "worker", {})
    assert outcome.executed
    assert ran == []


# -- strict profile ----------------------------------------------------------------------- #


def test_strict_profile_without_ttl_fails_at_construction(tmp_path: Path) -> None:
    signer = FakeSigner()
    profile = GovernanceProfile.production_strict(
        verifier=signer,
        signer=signer,
        consumption_ledger=ReceiptConsumptionLedger(str(tmp_path / "strict-ledger.jsonl")),
    )
    with pytest.raises(ValueError, match="receipt_ttl_seconds"):
        make_gateway(tmp_path, profile=profile)


def test_strict_profile_executes_with_ttl(tmp_path: Path) -> None:
    signer = FakeSigner()
    profile = GovernanceProfile.production_strict(
        verifier=signer,
        signer=signer,
        consumption_ledger=ReceiptConsumptionLedger(str(tmp_path / "strict-ledger.jsonl")),
    )
    gateway = UniversalGateway(
        tenant_id="tenant-1",
        execution_boundary="boundary-1",
        policy=make_policy(),
        profile=profile,
        validator=Validator(validator_id="validator-1"),
        authority="authority-1",
        audit_path=tmp_path / "audit.jsonl",
        receipt_ttl_seconds=60,
    )
    gateway.register_tool("echo", lambda message: f"echo:{message}")
    outcome = gateway.invoke("agent-a", "echo", {"message": "hi"})
    assert outcome.executed
    assert outcome.receipt is not None
    assert outcome.receipt.expires_at


# -- framework wrapper path (LangGraph et al.) --------------------------------------------- #


def test_framework_run_rejects_positional_args(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)
    calls: list[Any] = []
    gateway.register_tool("echo", lambda **kwargs: calls.append(kwargs))
    with pytest.raises(TypeError, match="keyword arguments only"):
        gateway.framework_run("agent-a", "echo", ("positional",), {})
    assert calls == []


def test_framework_run_returns_result_or_envelope(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)
    gateway.register_tool("echo", lambda message: f"echo:{message}")
    gateway.register_tool("rm_prod", lambda **kwargs: "never")

    assert gateway.framework_run("agent-a", "echo", (), {"message": "hi"}) == "echo:hi"
    refused = json.loads(gateway.framework_run("agent-a", "rm_prod", (), {"target": "db"}))
    assert refused["status"] == "denied"


def test_langgraph_tools_dispatch_through_gate(tmp_path: Path) -> None:
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool as lc_tool

    gateway = make_gateway(tmp_path)

    @lc_tool
    def shout(message: str) -> str:
        """Uppercase a message."""
        return message.upper()

    (governed,) = gateway.langgraph_tools([shout], actor="agent-a")
    assert governed._run(message="hi") == "HI"
    events = audit_events(tmp_path)
    assert events and events[-1]["decision"] == "allow"

    # Re-wrapping the same tool name must fail loud, not silently replace.
    with pytest.raises(ValueError, match="already registered"):
        gateway.langgraph_tools([shout], actor="agent-a")
