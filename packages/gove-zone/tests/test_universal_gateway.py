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
    gateway = make_gateway(tmp_path)
    gateway.register_tool("b_tool", lambda: None)
    gateway.register_tool("a_tool", lambda: None)
    assert gateway.mcp_tools_list() == {"tools": [{"name": "a_tool"}, {"name": "b_tool"}]}


# -- OpenAI function-calling surface --------------------------------------------- #


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
    assert allowed["gove_zone"]["receipt_hash"]
    assert allowed["gove_zone"]["signature_algorithm"] == "test-hmac-sha256"

    events = audit_events(tmp_path)
    assert [event["decision"] for event in events] == ["deny", "allow"]


def test_claude_hook_actor_allowlist(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path, allowed_actors=frozenset({"alice"}))
    response = gateway.handle_claude_hook({"tool_name": "Read", "tool_input": {}}, actor="mallory")
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"


# -- REST surface ------------------------------------------------------------------- #


def test_rest_surface_status_mapping(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path)
    gateway.register_tool("echo", lambda message: f"echo:{message}")
    gateway.register_tool("rm_prod", lambda **kwargs: "never")
    gateway.register_tool("deploy", lambda **kwargs: "never")

    ok = gateway.handle_rest_call({"tool": "echo", "actor": "agent-a", "args": {"message": "hi"}})
    assert ok["status"] == 200
    assert ok["body"]["result"] == "echo:hi"

    forbidden = gateway.handle_rest_call({"tool": "rm_prod", "actor": "agent-a", "args": {}})
    assert forbidden["status"] == 403

    escalated = gateway.handle_rest_call({"tool": "deploy", "actor": "agent-a", "args": {}})
    assert escalated["status"] == 202

    missing = gateway.handle_rest_call({"tool": "ghost", "actor": "agent-a", "args": {}})
    assert missing["status"] == 404

    malformed = gateway.handle_rest_call({"actor": "agent-a", "args": {}})
    assert malformed["status"] == 400

    no_actor = gateway.handle_rest_call({"tool": "echo", "args": {}})
    assert no_actor["status"] == 400


# -- outbound REST tool factory ------------------------------------------------------- #


def test_http_json_tool_pins_url() -> None:
    tool = http_json_tool("https://api.example.com/v1/send")
    assert "api.example.com" in (tool.__name__ or "")
    with pytest.raises(ValueError):
        http_json_tool("ftp://example.com/x")
    with pytest.raises(ValueError):
        http_json_tool("/relative/path")
