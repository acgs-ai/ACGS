from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from gove_zone import (
    Decision,
    DecisionReceipt,
    DecisionRecord,
    ReceiptValidationError,
    Validator,
    adapter_artifact_digest,
    execute_with_receipt,
    sha256_json,
)
from gove_zone._strict_dispatch_fixture import (
    StrictReceiptGateFixture,
    build_strict_receipt_gate_fixture,
)
from gove_zone.integration import tool_call_from_hook_payload

TENANT = "tenant-A"
BOUNDARY = "mcp-gateway/local"
ACTOR = "mcp-agent-1"
LIFECYCLE_AUTHORITY_ID = "fixture-lifecycle-validator"


def issue_receipt(
    fixture: StrictReceiptGateFixture,
    action: str,
    args: dict[str, Any],
) -> DecisionReceipt:
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=action,
        argument_hash=sha256_json(args),
        policy_version="mcp-example-policy/v1",
        event_id="ev_mcp_tool_gate",
        actor=ACTOR,
        reason="example MCP gateway allow",
    )
    event = fixture.audit.append(record)
    return DecisionReceipt.from_record(
        record=record,
        audit_hash=event["event_hash"],
        previous_audit_hash=event["previous_hash"],
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="mcp-example-policy",
        policy_hash="mcp-example-policy/v1",
        request_id="req-mcp-tool-gate",
        validator=Validator("gateway-validator"),
        authority="tenant-A/mcp-write-grant",
        signer=fixture.signer,
    )


class McpToolImplementation:
    def __init__(self) -> None:
        self.calls = 0

    def run(self, **kwargs: Any) -> str:
        self.calls += 1
        return f"MCP SIDE EFFECT EXECUTED for {sorted(kwargs)}"


def _last_audit_denial(fixture: StrictReceiptGateFixture, reason_code: str) -> bool:
    events = list(fixture.audit.iter_events())
    if not events:
        return False
    last = events[-1]
    return last["decision"] == Decision.DENY.value and last["matched_rules"] == [reason_code]


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

    with TemporaryDirectory() as tmp:
        fixture = build_strict_receipt_gate_fixture(Path(tmp), name="mcp-tool-gate")
        tool = McpToolImplementation()
        receipt = issue_receipt(fixture, call.name, dict(call.args))

        result = execute_with_receipt(
            tool_fn=tool.run,
            args=dict(call.args),
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=call.name,
            expected_actor=ACTOR,
            expected_adapter_artifact_digest=adapter_artifact_digest(tool.run),
            require_signature=True,
            verifier=fixture.signer,
            consumption_store=fixture.consumption_store,
            rejection_audit=fixture.audit,
            lifecycle_signer=fixture.lifecycle_signer,
            lifecycle_authority_id=LIFECYCLE_AUTHORITY_ID,
        )

        missing_blocked = False
        try:
            execute_with_receipt(
                tool_fn=tool.run,
                args=dict(call.args),
                receipt=None,
                expected_tenant_id=TENANT,
                expected_execution_boundary=BOUNDARY,
                expected_action=call.name,
                expected_actor=ACTOR,
                expected_adapter_artifact_digest=adapter_artifact_digest(tool.run),
                require_signature=True,
                verifier=fixture.signer,
                consumption_store=fixture.consumption_store,
                rejection_audit=fixture.audit,
                lifecycle_signer=fixture.lifecycle_signer,
                lifecycle_authority_id=LIFECYCLE_AUTHORITY_ID,
            )
        except ReceiptValidationError:
            missing_blocked = True

        missing_audited = _last_audit_denial(fixture, "receipt.execution.receipt_required")

        ok = (
            result.startswith("MCP SIDE EFFECT EXECUTED")
            and missing_blocked
            and missing_audited
            and tool.calls == 1
        )
        report = {
            "status": "pass" if ok else "fail",
            "normalized_tool": call.name,
            "valid_receipt_executed": result.startswith("MCP SIDE EFFECT EXECUTED"),
            "missing_receipt_blocked": missing_blocked,
            "missing_receipt_audited": missing_audited,
            "side_effect_count": tool.calls,
            "invariant": "No valid Decision Receipt, no side effect.",
        }
        print(json.dumps(report, sort_keys=True))
        return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
