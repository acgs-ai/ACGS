from __future__ import annotations

import pytest

from gove_zone import GovernanceRequest
from gove_zone.adapters import AdapterError, normalize_governance_request

_BASE = {
    "tenant_id": "tenant-alpha",
    "actor": {"id": "agent-1"},
    "subject": {"id": "workflow-1"},
    "declared_goal": "run governed action",
    "execution_boundary": {"environment": "local"},
    "policy_bundle_id": "bundle-alpha",
}


def _assert_request(request: GovernanceRequest, tool: str) -> None:
    assert request.tenant_id == "tenant-alpha"
    assert request.policy_bundle_id == "bundle-alpha"
    assert request.proposed_action["tool"] == tool
    assert request.declared_goal == "run governed action"


def test_normalizes_mcp_tool_call() -> None:
    request = normalize_governance_request(
        {
            "method": "tools/call",
            "params": {"name": "message.send", "arguments": {"body": "hello"}},
            **_BASE,
        }
    )

    _assert_request(request, "message.send")
    assert request.proposed_action["args"] == {"body": "hello"}


def test_normalizes_openai_responses_function_call() -> None:
    request = normalize_governance_request(
        {
            "type": "function_call",
            "call_id": "call_1",
            "name": "message.send",
            "arguments": '{"body":"hello"}',
            **_BASE,
        }
    )

    _assert_request(request, "message.send")
    assert request.request_id == "call_1"
    assert request.proposed_action["args"] == {"body": "hello"}


def test_normalizes_langchain_tool_call() -> None:
    request = normalize_governance_request(
        {
            "type": "langchain.tool_call",
            "id": "lc-1",
            "name": "message.send",
            "args": {"body": "hello"},
            **_BASE,
        }
    )

    _assert_request(request, "message.send")
    assert request.request_id == "lc-1"


def test_normalizes_generic_json_tool_call() -> None:
    request = normalize_governance_request(
        {"tool": "message.send", "args": {"body": "hello"}, **_BASE}
    )

    _assert_request(request, "message.send")


def test_normalizes_ci_cd_action() -> None:
    request = normalize_governance_request(
        {"type": "ci.exec", "job": "deploy", "args": {"ref": "main"}, **_BASE}
    )

    _assert_request(request, "ci.exec")
    assert request.proposed_action["args"] == {"job": "deploy", "ref": "main"}


def test_normalizes_workflow_step() -> None:
    request = normalize_governance_request(
        {
            "type": "workflow.step",
            "step_id": "step-1",
            "action": "message.send",
            "inputs": {"body": "hello"},
            **_BASE,
        }
    )

    _assert_request(request, "message.send")
    assert request.proposed_action["args"] == {"body": "hello", "step_id": "step-1"}


def test_unsupported_envelope_fails_closed() -> None:
    with pytest.raises(AdapterError, match="unsupported governance envelope"):
        normalize_governance_request({"name": "message.send", **_BASE})
