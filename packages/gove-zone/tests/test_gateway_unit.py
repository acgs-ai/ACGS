"""Direct unit tests for :mod:`gove_zone.gateway`.

Covers the module's own public units: the :class:`GatewayResult` value object,
the sealed registry (:meth:`UniversalGateway.register_tool` /
:class:`SealedTool` bypass detection), the constructor's fail-loud
misconfiguration guards, the surface projections (MCP / OpenAI / REST /
Claude hook) on their malformed-input paths, and the
:func:`http_json_tool` factory's URL pinning.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest

from gove_zone.decision import Decision
from gove_zone.errors import UnknownToolError
from gove_zone.gateway import (
    BYPASS_RULE,
    BypassAttemptError,
    GatewayResult,
    SealedTool,
    UniversalGateway,
    http_json_tool,
)
from gove_zone.policy import Policy, PolicyRule, RuleSetPolicy
from gove_zone.profile import GovernanceProfile
from gove_zone.receipt import Validator


class FakeSigner:
    """Deterministic HMAC signer implementing the ReceiptSigner protocol."""

    algorithm = "test-hmac-sha256"

    def __init__(self, key: bytes = b"gw-unit-key", key_id: str = "gw-key-1") -> None:
        self._key = key
        self.key_id = key_id

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


def _policy() -> RuleSetPolicy:
    return RuleSetPolicy(
        policy_id="gateway-unit",
        rules=(
            PolicyRule(
                rule_id="deny-wipe",
                effect=Decision.DENY,
                tools=frozenset({"wipe"}),
                reason="destructive tool is always denied",
            ),
            # The hook surface namespaces host tools as ``runtime.<name>``.
            PolicyRule(
                rule_id="deny-runtime-wipe",
                effect=Decision.DENY,
                tools=frozenset({"runtime.wipe"}),
                reason="destructive host tool is always denied",
            ),
        ),
    )


def _gateway(
    tmp_path: Path,
    *,
    policy: Policy | None = None,
    allowed_actors: frozenset[str] | None = None,
) -> UniversalGateway:
    signer = FakeSigner()
    return UniversalGateway(
        tenant_id="tenant-unit",
        execution_boundary="boundary-unit",
        policy=policy or _policy(),
        profile=GovernanceProfile.production(signer=signer, verifier=signer),
        validator=Validator("validator-unit"),
        authority="authority-unit",
        audit_path=tmp_path / "audit.jsonl",
        ledger_path=tmp_path / "ledger.jsonl",
        allowed_actors=allowed_actors,
    )


@pytest.fixture
def gateway(tmp_path: Path) -> UniversalGateway:
    return _gateway(tmp_path)


def _audit_events(tmp_path: Path) -> list[dict[str, Any]]:
    path = tmp_path / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# --- GatewayResult ------------------------------------------------------------- #


def test_gateway_result_executed_flag_tracks_status() -> None:
    assert GatewayResult(status="executed", tool="t", actor="a").executed is True
    assert GatewayResult(status="denied", tool="t", actor="a").executed is False


def test_gateway_result_receipt_anchors_are_empty_without_a_receipt() -> None:
    assert GatewayResult(status="denied", tool="t", actor="a").receipt_anchors() == {}


def test_gateway_result_to_dict_omits_result_for_non_executed_statuses() -> None:
    payload = GatewayResult(
        status="error", tool="t", actor="a", audit_hash="h", error_class="Boom"
    ).to_dict()
    assert payload == {
        "status": "error",
        "tool": "t",
        "actor": "a",
        "audit_hash": "h",
        "error_class": "Boom",
    }
    assert "result" not in payload


def test_gateway_result_to_dict_carries_the_envelope_when_present() -> None:
    envelope = {"reason": "denied by policy"}
    payload = GatewayResult(status="denied", tool="t", actor="a", envelope=envelope).to_dict()
    assert payload["envelope"] == envelope


# --- constructor guards ---------------------------------------------------------- #


def test_require_expiry_profile_without_ttl_fails_loud_at_construction(tmp_path: Path) -> None:
    signer = FakeSigner()
    profile = dataclasses.replace(
        GovernanceProfile.production(signer=signer, verifier=signer), require_expiry=True
    )
    with pytest.raises(ValueError, match="receipt_ttl_seconds"):
        UniversalGateway(
            tenant_id="tenant-unit",
            execution_boundary="boundary-unit",
            policy=_policy(),
            profile=profile,
            validator=Validator("validator-unit"),
            authority="authority-unit",
            audit_path=tmp_path / "audit.jsonl",
            ledger_path=tmp_path / "ledger.jsonl",
        )


def test_policy_bundle_id_defaults_to_the_policy_version(gateway: UniversalGateway) -> None:
    assert gateway.policy_bundle_id == gateway.policy.version


# --- sealed registry --------------------------------------------------------------- #


def test_register_tool_returns_a_sealed_handle_not_the_raw_callable(
    gateway: UniversalGateway,
) -> None:
    def echo(value: str) -> str:
        return value

    sealed = gateway.register_tool("echo", echo)
    assert isinstance(sealed, SealedTool)
    assert sealed is not echo
    assert sealed.name == "echo"


def test_register_tool_rejects_a_blank_name(gateway: UniversalGateway) -> None:
    with pytest.raises(ValueError, match="tool name is required"):
        gateway.register_tool("   ", lambda: None)


def test_register_tool_is_fail_closed_on_duplicates(gateway: UniversalGateway) -> None:
    gateway.register_tool("echo", lambda value: value)
    with pytest.raises(ValueError, match="already registered"):
        gateway.register_tool("echo", lambda value: value)


def test_tool_decorator_registers_and_names_are_sorted(gateway: UniversalGateway) -> None:
    @gateway.tool("zeta")
    def zeta() -> str:
        return "z"

    @gateway.tool("alpha")
    def alpha() -> str:
        return "a"

    assert isinstance(zeta, SealedTool)
    assert gateway.tool_names() == ("alpha", "zeta")
    assert gateway.mcp_tools_list() == {"tools": [{"name": "alpha"}, {"name": "zeta"}]}


def test_openai_tools_spec_maps_annotations_to_json_types(gateway: UniversalGateway) -> None:
    def annotated(name: str, count: int, ratio: float, flag: bool, extra=None) -> str:  # noqa: ANN001
        """Do a thing."""
        return name

    gateway.register_tool("annotated", annotated)
    spec = gateway.openai_tools()[0]["function"]

    assert spec["name"] == "annotated"
    assert spec["description"] == "Do a thing."
    properties = spec["parameters"]["properties"]
    assert properties["name"]["type"] == "string"
    assert properties["count"]["type"] == "integer"
    assert properties["ratio"]["type"] == "number"
    assert properties["flag"]["type"] == "boolean"
    # Unannotated parameters fall back to "string"; defaulted ones are optional.
    assert properties["extra"]["type"] == "string"
    assert spec["parameters"]["required"] == ["name", "count", "ratio", "flag"]


# --- bypass detection ---------------------------------------------------------------- #


def test_calling_a_sealed_tool_directly_is_blocked_and_audited(tmp_path: Path) -> None:
    gateway = _gateway(tmp_path)
    ran: list[str] = []

    sealed = gateway.register_tool("write", lambda value: ran.append(value))

    with pytest.raises(BypassAttemptError, match="bypass attempt blocked"):
        sealed(value="never")

    assert ran == []
    attempts = gateway.bypass_attempts()
    assert len(attempts) == 1
    assert attempts[0]["tool"] == "write"
    assert attempts[0]["audit_hash"]
    denies = [e for e in _audit_events(tmp_path) if BYPASS_RULE in e.get("matched_rules", [])]
    assert len(denies) == 1
    assert denies[0]["decision"] == "deny"


def test_bypass_attempts_returns_defensive_copies(tmp_path: Path) -> None:
    gateway = _gateway(tmp_path)
    sealed = gateway.register_tool("write", lambda value: value)
    with pytest.raises(BypassAttemptError):
        sealed(value="never")

    snapshot = gateway.bypass_attempts()
    snapshot[0]["tool"] = "mutated"
    assert gateway.bypass_attempts()[0]["tool"] == "write"


# --- invoke, the single chokepoint ------------------------------------------------------ #


def test_invoke_executes_an_allowed_tool_and_returns_receipt_anchors(
    gateway: UniversalGateway,
) -> None:
    gateway.register_tool("echo", lambda value: f"echo:{value}")

    outcome = gateway.invoke("agent-1", "echo", {"value": "hi"})

    assert outcome.executed
    assert outcome.result == "echo:hi"
    assert outcome.receipt is not None
    anchors = outcome.receipt_anchors()
    assert anchors["receipt_hash"] == outcome.receipt.receipt_hash
    assert anchors["audit_hash"] == outcome.audit_hash


def test_invoke_requires_a_non_blank_actor(gateway: UniversalGateway) -> None:
    gateway.register_tool("echo", lambda value: value)
    with pytest.raises(ValueError, match="actor is required"):
        gateway.invoke("   ", "echo", {"value": "hi"})


def test_invoke_raises_for_an_unregistered_tool(gateway: UniversalGateway) -> None:
    with pytest.raises(UnknownToolError):
        gateway.invoke("agent-1", "ghost", {})


def test_invoke_returns_a_denied_envelope_for_a_denied_tool(gateway: UniversalGateway) -> None:
    ran: list[str] = []
    gateway.register_tool("wipe", lambda target: ran.append(target))

    outcome = gateway.invoke("agent-1", "wipe", {"target": "prod"})

    assert outcome.status == "denied"
    assert outcome.envelope is not None
    assert ran == []


def test_invoke_denies_an_actor_outside_the_allowlist(tmp_path: Path) -> None:
    gateway = _gateway(tmp_path, allowed_actors=frozenset({"agent-1"}))
    ran: list[str] = []
    gateway.register_tool("echo", lambda value: ran.append(value))

    outcome = gateway.invoke("intruder", "echo", {"value": "hi"})

    assert outcome.status == "denied"
    assert ran == []
    denies = [
        e for e in _audit_events(tmp_path) if "ACTOR_NOT_ALLOWED" in e.get("matched_rules", [])
    ]
    assert len(denies) == 1


def test_invoke_converts_a_raising_tool_into_a_fail_closed_error(
    gateway: UniversalGateway,
) -> None:
    def boom(value: str) -> str:
        raise KeyError("secret-argument-value")

    gateway.register_tool("boom", boom)
    outcome = gateway.invoke("agent-1", "boom", {"value": "hi"})

    assert outcome.status == "error"
    # Class name only — exception text may echo raw arguments.
    assert outcome.error_class == "KeyError"
    assert "secret-argument-value" not in json.dumps(outcome.to_dict())


def test_framework_run_rejects_positional_arguments(gateway: UniversalGateway) -> None:
    gateway.register_tool("echo", lambda value: value)
    with pytest.raises(TypeError, match="keyword arguments only"):
        gateway.framework_run("agent-1", "echo", ("positional",), {})


# --- surface projections ---------------------------------------------------------------- #


def test_handle_mcp_call_rejects_an_unsupported_method(gateway: UniversalGateway) -> None:
    result = gateway.handle_mcp_call({"method": "tools/list"}, actor="agent-1")
    assert result["isError"] is True
    assert result["_meta"]["gove_zone"]["decision"] == "not_evaluated"


def test_handle_mcp_call_rejects_a_missing_tool_name(gateway: UniversalGateway) -> None:
    result = gateway.handle_mcp_call({"params": {"arguments": {}}}, actor="agent-1")
    assert result["isError"] is True
    assert "missing tool name" in result["content"][0]["text"]


def test_handle_mcp_call_reports_an_unregistered_tool(gateway: UniversalGateway) -> None:
    result = gateway.handle_mcp_call(
        {"method": "tools/call", "params": {"name": "ghost", "arguments": {}}}, actor="agent-1"
    )
    assert result["isError"] is True
    assert "tool not registered" in result["content"][0]["text"]


def test_handle_openai_tool_call_rejects_non_json_arguments(gateway: UniversalGateway) -> None:
    gateway.register_tool("echo", lambda value: value)
    message = gateway.handle_openai_tool_call(
        {"id": "call-1", "function": {"name": "echo", "arguments": "{not json"}}, actor="agent-1"
    )
    assert message["role"] == "tool"
    assert message["tool_call_id"] == "call-1"
    assert json.loads(message["content"])["error"] == "arguments is not valid JSON"


def test_handle_openai_tool_call_rejects_a_non_object_argument_payload(
    gateway: UniversalGateway,
) -> None:
    gateway.register_tool("echo", lambda value: value)
    message = gateway.handle_openai_tool_call(
        {"id": "call-2", "function": {"name": "echo", "arguments": "[1, 2]"}}, actor="agent-1"
    )
    assert json.loads(message["content"])["error"] == "arguments must be a JSON object"


def test_handle_rest_call_maps_statuses(gateway: UniversalGateway) -> None:
    gateway.register_tool("echo", lambda value: f"echo:{value}")
    gateway.register_tool("wipe", lambda target: target)

    assert (
        gateway.handle_rest_call({"tool": "echo", "args": {"value": "hi"}}, actor="a")["status"]
        == 200
    )
    assert (
        gateway.handle_rest_call({"tool": "wipe", "args": {"target": "p"}}, actor="a")["status"]
        == 403
    )
    assert gateway.handle_rest_call({"tool": "ghost"}, actor="a")["status"] == 404
    assert gateway.handle_rest_call({"args": {}}, actor="a")["status"] == 400
    assert gateway.handle_rest_call({"tool": "echo", "args": [1]}, actor="a")["status"] == 400
    assert gateway.handle_rest_call({"tool": "echo", "goal": 7}, actor="a")["status"] == 400


def test_handle_rest_call_ignores_an_actor_supplied_in_the_body(
    gateway: UniversalGateway,
) -> None:
    seen: list[str] = []
    gateway.register_tool("echo", lambda value: seen.append(value) or "ok")

    response = gateway.handle_rest_call(
        {"tool": "echo", "args": {"value": "hi"}, "actor": "spoofed"}, actor="authenticated"
    )

    assert response["body"]["actor"] == "authenticated"


def test_handle_claude_hook_requires_an_actor(gateway: UniversalGateway) -> None:
    with pytest.raises(ValueError, match="actor is required"):
        gateway.handle_claude_hook({}, actor="")


def test_handle_claude_hook_denies_a_policy_denied_host_tool(
    gateway: UniversalGateway,
) -> None:
    response = gateway.handle_claude_hook(
        {"tool_name": "wipe", "tool_input": {"target": "prod"}}, actor="agent-1"
    )
    hook = response["hookSpecificOutput"]
    assert hook["permissionDecision"] == "deny"
    assert hook["hookEventName"] == "PreToolUse"
    # Decision-only surface: no receipt is minted for a denied hook event.
    assert "gove_zone" not in response


def test_handle_claude_hook_allows_and_returns_receipt_anchors(
    gateway: UniversalGateway,
) -> None:
    response = gateway.handle_claude_hook(
        {"tool_name": "Read", "tool_input": {"path": "notes.txt"}}, actor="agent-1"
    )
    assert response["hookSpecificOutput"]["permissionDecision"] == "allow"
    anchors = response["gove_zone"]["receipts"]
    assert len(anchors) == 1
    assert anchors[0]["tool"] == "runtime.Read"
    assert anchors[0]["receipt_hash"]
    assert anchors[0]["signature_algorithm"] == FakeSigner.algorithm


def test_handle_claude_hook_honors_the_actor_allowlist(tmp_path: Path) -> None:
    gateway = _gateway(tmp_path, allowed_actors=frozenset({"agent-1"}))
    response = gateway.handle_claude_hook({"tool_name": "Read", "tool_input": {}}, actor="intruder")
    hook = response["hookSpecificOutput"]
    assert hook["permissionDecision"] == "deny"
    assert "allowlist" in hook["permissionDecisionReason"]


# --- http_json_tool ------------------------------------------------------------------------ #


def test_http_json_tool_requires_an_absolute_http_url() -> None:
    for bad in ("/relative/path", "ftp://host/x", "not a url"):
        with pytest.raises(ValueError, match="absolute http"):
            http_json_tool(bad)


def test_http_json_tool_pins_the_destination_in_its_metadata() -> None:
    tool = http_json_tool("https://api.example.com/v1/notify")
    assert tool.__name__ == "http_json_tool[api.example.com/v1/notify]"
    assert "https://api.example.com/v1/notify" in (tool.__doc__ or "")


def test_http_json_tool_is_registrable_on_the_gateway(gateway: UniversalGateway) -> None:
    sealed = gateway.register_tool("notify", http_json_tool("https://api.example.com/notify"))
    assert isinstance(sealed, SealedTool)
    assert "notify" in gateway.tool_names()
