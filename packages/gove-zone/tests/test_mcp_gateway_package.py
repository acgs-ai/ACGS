"""Tests for the ``mcp_gateway`` package (ACGS MCP Governance Gateway).

Covers the four required scenarios — allowed tool, denied tool, modified
arguments, expired receipt — plus the two remaining bindings the gateway
advertises: tool-name binding and identity binding.
"""

from __future__ import annotations

from typing import Any

import pytest
from gove_zone.audit import ChainHashAuditStore
from gove_zone.decision import Decision
from gove_zone.errors import ReceiptValidationError, UnknownToolError
from gove_zone.kernel import Kernel
from gove_zone.policy import PolicyRule, RuleSetPolicy
from gove_zone.profile import GovernanceProfile
from gove_zone.receipt import Validator
from mcp_gateway import MCPGovernanceGateway

AGENT = "agent://research-assistant"


def _gateway(tmp_path, **overrides: Any) -> tuple[MCPGovernanceGateway, list[dict[str, Any]]]:
    """A gateway over a two-tool kernel: read_report (allowed by default),
    delete_records (denied by rule). Returns (gateway, execution_log)."""
    executed: list[dict[str, Any]] = []

    policy = RuleSetPolicy(
        policy_id="mcp-gateway-tests/v1",
        rules=[
            PolicyRule(
                rule_id="no-destructive-deletes",
                effect=Decision.DENY,
                tools=frozenset({"delete_records"}),
            )
        ],
    )
    kernel = Kernel(
        policy=policy,
        audit=ChainHashAuditStore(str(tmp_path / "audit.jsonl")),
        actor=AGENT,
    )

    @kernel.tool("read_report")
    def read_report(report_id: str) -> dict[str, Any]:
        executed.append({"tool": "read_report", "report_id": report_id})
        return {"report_id": report_id, "status": "ok"}

    @kernel.tool("delete_records")
    def delete_records(table: str) -> None:
        executed.append({"tool": "delete_records", "table": table})

    config: dict[str, Any] = dict(
        tenant_id="tenant-a",
        execution_boundary="mcp-gateway-tests",
        policy_bundle_id="bundle-tests",
        authority="policy-engine",
        validator=Validator(validator_id="acgs-validator", role="validator"),
        profile=GovernanceProfile.dev(),
    )
    config.update(overrides)
    return MCPGovernanceGateway(kernel, **config), executed


def _request(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {"method": "tools/call", "params": {"name": name, "arguments": arguments}}


def test_allowed_tool_executes_with_receipt(tmp_path) -> None:
    gateway, executed = _gateway(tmp_path)
    result = gateway.handle_tools_call(_request("read_report", {"report_id": "r-1"}), actor=AGENT)

    assert result["isError"] is False
    assert executed == [{"tool": "read_report", "report_id": "r-1"}]
    meta = result["_meta"]["gove_zone"]
    assert meta["decision"] == "allow"
    assert meta["receipt_id"]
    assert meta["receipt_hash"]
    assert meta["argument_hash"]
    assert meta["actor"] == AGENT
    assert meta["audit_event_hash"]


def test_denied_tool_never_executes(tmp_path) -> None:
    gateway, executed = _gateway(tmp_path)
    result = gateway.handle_tools_call(
        _request("delete_records", {"table": "customers"}), actor=AGENT
    )

    assert result["isError"] is True
    assert executed == []
    meta = result["_meta"]["gove_zone"]
    assert meta["decision"] == "deny"
    assert "no-destructive-deletes" in meta["matched_rules"]
    assert meta["audit_event_hash"]


def test_modified_arguments_are_refused(tmp_path) -> None:
    """A receipt minted for one argument set cannot execute another."""
    gateway, executed = _gateway(tmp_path)
    decision = gateway.authorize("read_report", {"report_id": "r-1"}, actor=AGENT)
    assert decision.allowed

    with pytest.raises(ReceiptValidationError):
        gateway.execute(decision.receipt, "read_report", {"report_id": "r-999"}, actor=AGENT)
    assert executed == []

    # The untampered arguments still execute.
    out = gateway.execute(decision.receipt, "read_report", {"report_id": "r-1"}, actor=AGENT)
    assert out == {"report_id": "r-1", "status": "ok"}
    assert executed == [{"tool": "read_report", "report_id": "r-1"}]


def test_expired_receipt_is_refused(tmp_path) -> None:
    """A receipt past its expires_at cannot authorise execution."""
    gateway, executed = _gateway(tmp_path, receipt_ttl_seconds=-1.0)
    decision = gateway.authorize("read_report", {"report_id": "r-1"}, actor=AGENT)
    assert decision.allowed
    assert decision.receipt is not None and decision.receipt.expires_at

    with pytest.raises(ReceiptValidationError):
        gateway.execute(decision.receipt, "read_report", {"report_id": "r-1"}, actor=AGENT)
    assert executed == []

    result = gateway.handle_tools_call(_request("read_report", {"report_id": "r-1"}), actor=AGENT)
    assert result["isError"] is True
    assert executed == []


def test_tool_name_binding_receipt_cannot_cross_tools(tmp_path) -> None:
    """A receipt minted for read_report cannot execute delete_records."""
    gateway, executed = _gateway(tmp_path)
    decision = gateway.authorize("read_report", {"table": "customers"}, actor=AGENT)
    assert decision.allowed

    with pytest.raises(ReceiptValidationError):
        gateway.execute(decision.receipt, "delete_records", {"table": "customers"}, actor=AGENT)
    assert executed == []


def test_identity_binding_wrong_actor_cannot_spend_receipt(tmp_path) -> None:
    gateway, executed = _gateway(tmp_path)
    decision = gateway.authorize("read_report", {"report_id": "r-1"}, actor=AGENT)
    assert decision.allowed

    with pytest.raises(ReceiptValidationError):
        gateway.execute(
            decision.receipt, "read_report", {"report_id": "r-1"}, actor="agent://impostor"
        )
    assert executed == []


def test_verify_receipt_offline_checks_all_bindings(tmp_path) -> None:
    gateway, _ = _gateway(tmp_path, receipt_ttl_seconds=3600.0)
    decision = gateway.authorize("read_report", {"report_id": "r-1"}, actor=AGENT)
    receipt = decision.receipt
    assert receipt is not None

    # Matching bindings verify cleanly.
    gateway.verify_receipt(receipt, name="read_report", arguments={"report_id": "r-1"}, actor=AGENT)

    with pytest.raises(ReceiptValidationError):
        gateway.verify_receipt(
            receipt, name="read_report", arguments={"report_id": "TAMPERED"}, actor=AGENT
        )
    with pytest.raises(ReceiptValidationError):
        gateway.verify_receipt(
            receipt, name="delete_records", arguments={"report_id": "r-1"}, actor=AGENT
        )
    with pytest.raises(ReceiptValidationError):
        gateway.verify_receipt(
            receipt, name="read_report", arguments={"report_id": "r-1"}, actor="agent://impostor"
        )
    # Expired-by-clock: verification honours now_iso beyond expires_at.
    with pytest.raises(ReceiptValidationError):
        gateway.verify_receipt(
            receipt,
            name="read_report",
            arguments={"report_id": "r-1"},
            actor=AGENT,
            now_iso="2999-01-01T00:00:00+00:00",
        )


def test_unregistered_tool_is_structurally_inadmissible(tmp_path) -> None:
    gateway, executed = _gateway(tmp_path)
    with pytest.raises(UnknownToolError):
        gateway.authorize("not_a_tool", {}, actor=AGENT)

    result = gateway.handle_tools_call(_request("not_a_tool", {}), actor=AGENT)
    assert result["isError"] is True
    assert result["_meta"]["gove_zone"]["decision"] == "not_evaluated"
    assert executed == []


def test_malformed_requests_are_error_results_not_exceptions(tmp_path) -> None:
    gateway, executed = _gateway(tmp_path)
    for bad in (
        {"method": "tools/list"},
        {"params": "nope"},
        {"params": {"name": ""}},
        {"params": {"name": "read_report", "arguments": "nope"}},
    ):
        result = gateway.handle_tools_call(bad, actor=AGENT)
        assert result["isError"] is True
        assert result["_meta"]["gove_zone"]["decision"] == "not_evaluated"
    assert executed == []
