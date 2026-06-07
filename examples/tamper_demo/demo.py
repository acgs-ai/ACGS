from __future__ import annotations

import dataclasses
import json
import tempfile
from pathlib import Path
from typing import Any

from gove_zone import (
    ChainHashAuditStore,
    Decision,
    DecisionReceipt,
    DecisionRecord,
    ReceiptValidationError,
    Validator,
    execute_with_receipt,
    sha256_json,
)

TENANT = "tenant-A"
BOUNDARY = "tamper-demo/local"
ACTION = "runtime.file.write"
ACTOR = "agent-1"
ARGS = {"path": "safe.txt", "content": "approved"}


def issue_receipt(audit: ChainHashAuditStore, args: dict[str, Any]) -> DecisionReceipt:
    previous = audit.last_hash()
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=ACTION,
        argument_hash=sha256_json(args),
        policy_version="tamper-demo-policy/v1",
        event_id="ev_tamper_demo_allow",
        actor=ACTOR,
        reason="example allow before tamper",
    )
    event = audit.append(record)
    return DecisionReceipt.from_record(
        record=record,
        audit_hash=str(event["event_hash"]),
        previous_audit_hash=previous,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="tamper-demo-policy",
        policy_hash="tamper-demo-policy/v1",
        request_id="req-tamper-demo",
        validator=Validator("constitutional-council"),
        authority="tenant-A/write-grant",
    )


class SideEffect:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def run(self, **kwargs: Any) -> str:
        self.calls.append(dict(kwargs))
        return "SIDE EFFECT EXECUTED"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="acgs-tamper-demo-") as tmp:
        audit_path = Path(tmp) / "audit.jsonl"
        audit = ChainHashAuditStore(audit_path)
        receipt = issue_receipt(audit, ARGS)
        side = SideEffect()

        result = execute_with_receipt(
            tool_fn=side.run,
            args=ARGS,
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor=ACTOR,
            expected_audit_hash=receipt.audit_event_hash,
            expected_policy_hash="tamper-demo-policy/v1",
            expected_policy_bundle_id="tamper-demo-policy",
            require_signature=False,  # dev-mode — local unsigned demo
        )

        tampered_blocked = False
        tampered = dataclasses.replace(receipt, proposed_action="runtime.shell.run")
        try:
            execute_with_receipt(
                tool_fn=side.run,
                args=ARGS,
                receipt=tampered,
                expected_tenant_id=TENANT,
                expected_execution_boundary=BOUNDARY,
                expected_action=ACTION,
                expected_actor=ACTOR,
                require_signature=False,  # dev-mode — local unsigned demo
            )
        except ReceiptValidationError:
            tampered_blocked = True

        arg_mismatch_blocked = False
        try:
            execute_with_receipt(
                tool_fn=side.run,
                args={"path": "different.txt", "content": "approved"},
                receipt=receipt,
                expected_tenant_id=TENANT,
                expected_execution_boundary=BOUNDARY,
                expected_action=ACTION,
                expected_actor=ACTOR,
                require_signature=False,  # dev-mode — local unsigned demo
            )
        except ReceiptValidationError:
            arg_mismatch_blocked = True

        before = ChainHashAuditStore(audit_path).verify_chain()
        lines = audit_path.read_text(encoding="utf-8").splitlines()
        event = json.loads(lines[0])
        event["decision"] = "deny"
        lines[0] = json.dumps(event, sort_keys=True, separators=(",", ":"))
        audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        after = ChainHashAuditStore(audit_path).verify_chain()

    ok = (
        result == "SIDE EFFECT EXECUTED"
        and tampered_blocked
        and arg_mismatch_blocked
        and before["valid"]
        and not after["valid"]
        and len(side.calls) == 1
    )
    report = {
        "status": "pass" if ok else "fail",
        "valid_receipt_executed": result == "SIDE EFFECT EXECUTED",
        "tampered_receipt_blocked": tampered_blocked,
        "argument_mismatch_blocked": arg_mismatch_blocked,
        "audit_chain_valid_before_tamper": before["valid"],
        "audit_chain_valid_after_tamper": after["valid"],
        "side_effect_count": len(side.calls),
        "invariant": "No valid Decision Receipt, no side effect.",
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
