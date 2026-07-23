"""Frontend contract projection tests.

These tests prove the React console shape can be produced from real kernel
receipts and denial records, not only hand-authored fixtures.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gove_zone import (
    BoundaryPolicy,
    ChainHashAuditStore,
    Decision,
    DeniedError,
    Kernel,
    ToolEffect,
    receipt_to_governed_action,
    record_to_governed_action,
)


def test_receipt_projects_to_frontend_action_contract(tmp_path: Path) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(
        policy=BoundaryPolicy(forbidden_keywords=["secret"]),
        audit=audit,
        actor="agent-01",
    )
    args = {"body": "hello"}

    @kernel.tool("message.preview", effect=ToolEffect.PURE_READ_ONLY)
    def send(body: str) -> dict[str, str]:
        return {"sent": body}

    _, receipt = kernel.dispatch("message.preview", args, goal="Patient update channel")
    view = receipt_to_governed_action(receipt, args_before=args)

    assert view["agent"] == "agent-01"
    assert view["action"] == "message.preview"
    assert view["target"] == "Patient update channel"
    assert view["outcome"] == "allowed"
    assert view["receiptId"] == receipt.record.event_id
    assert view["receiptHash"] == receipt.audit_hash
    assert view["traceId"] == receipt.record.event_id
    assert "gove-zone replay --event" in view["replayCommand"]
    assert view["auditEventId"] == receipt.record.event_id
    assert '"tool_executed":true' in view["after"]


def test_denial_projects_clear_reason_and_no_execution(tmp_path: Path) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(
        policy=BoundaryPolicy(forbidden_keywords=["secret"], rule_id="P-1207"),
        audit=audit,
        actor="analyst-12",
    )
    args = {"body": "contains secret"}
    executed: list[str] = []

    @kernel.tool("matter.fetch", effect=ToolEffect.PURE_READ_ONLY)
    def fetch(body: str) -> None:
        executed.append(body)

    with pytest.raises(DeniedError) as exc_info:
        kernel.dispatch("matter.fetch", args, goal="Matter-9821/private-notes")

    view = record_to_governed_action(
        exc_info.value.record,
        audit_hash=exc_info.value.audit_hash,
        args_before=args,
        actor="analyst-12",
    )

    assert executed == []
    assert exc_info.value.record.decision is Decision.DENY
    assert view["outcome"] == "denied"
    assert view["agent"] == "analyst-12"
    assert view["target"] == "Matter-9821/private-notes"
    assert "matched 1 boundary rule" in view["plainReason"]
    assert view["checks"][0]["id"].startswith("P-1207")
    assert '"tool_executed":false' in view["after"]
