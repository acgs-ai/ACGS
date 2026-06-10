from __future__ import annotations

import json
from typing import Any

from gove_zone import (
    Decision,
    DecisionReceipt,
    DecisionRecord,
    ReceiptValidationError,
    Validator,
    execute_with_receipt,
    sha256_json,
)
from gove_zone.integration import tool_call_from_hook_payload

TENANT = "tenant-A"
BOUNDARY = "mcp-gateway/local"
ACTOR = "mcp-agent-1"


def issue_receipt(action: str, args: dict[str, Any]) -> DecisionReceipt:
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=action,
        argument_hash=sha256_json(args),
        policy_version="mcp-example-policy/v1",
        event_id="ev_mcp_tool_gate",
        actor=ACTOR,
        reason="example MCP gateway allow",
    )
    return DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash_mcp_tool_gate",
        previous_audit_hash="0" * 64,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="mcp-example-policy",
        policy_hash="mcp-example-policy/v1",
        request_id="req-mcp-tool-gate",
        validator=Validator("gateway-validator"),
        authority="tenant-A/mcp-write-grant",
    )


class McpToolImplementation:
    def __init__(self) -> None:
        self.calls = 0

    def run(self, **kwargs: Any) -> str:
        self.calls += 1
        return f"MCP SIDE EFFECT EXECUTED for {sorted(kwargs)}"


def main() -> int:
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "file.write",
            "arguments": {"path": "evidence/report.json", "content": "proof"},
        },
        "goal": "persist governed evidence",
    }
    call = tool_call_from_hook_payload(payload, action_kind="mcp", actor=ACTOR)
    tool = McpToolImplementation()
    receipt = issue_receipt(call.name, dict(call.args))

    result = execute_with_receipt(
        require_signature=False,  # dev-mode: local unsigned demo
        tool_fn=tool.run,
        args=dict(call.args),
        receipt=receipt,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action=call.name,
        expected_actor=ACTOR,
    )

    missing_blocked = False
    try:
        execute_with_receipt(
            require_signature=False,  # dev-mode: local unsigned demo
            tool_fn=tool.run,
            args=dict(call.args),
            receipt=None,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=call.name,
            expected_actor=ACTOR,
        )
    except ReceiptValidationError:
        missing_blocked = True

    report = {
        "status": "pass" if missing_blocked and tool.calls == 1 else "fail",
        "normalized_tool": call.name,
        "valid_receipt_executed": result.startswith("MCP SIDE EFFECT EXECUTED"),
        "missing_receipt_blocked": missing_blocked,
        "side_effect_count": tool.calls,
        "invariant": "No valid Decision Receipt, no side effect.",
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
