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

TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
ACTION = "runtime.file.write"
ACTOR = "agent-1"
ARGS = {"path": "safe.txt", "content": "approved"}


def issue_receipt(args: dict[str, Any]) -> DecisionReceipt:
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=ACTION,
        argument_hash=sha256_json(args),
        policy_version="example-policy/v1",
        event_id="ev_python_tool_gate",
        actor=ACTOR,
        reason="example allow",
    )
    return DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash_python_tool_gate",
        previous_audit_hash="0" * 64,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="example-policy",
        policy_hash="example-policy/v1",
        request_id="req-python-tool-gate",
        validator=Validator("constitutional-council"),
        authority="tenant-A/write-grant",
    )


class SideEffect:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def write_file(self, **kwargs: Any) -> str:
        self.calls.append(dict(kwargs))
        return "SIDE EFFECT EXECUTED"


def main() -> int:
    side_effect = SideEffect()
    receipt = issue_receipt(ARGS)

    result = execute_with_receipt(
        require_signature=False,  # dev-mode: local unsigned demo
        tool_fn=side_effect.write_file,
        args=ARGS,
        receipt=receipt,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action=ACTION,
        expected_actor=ACTOR,
        require_signature=False,  # dev-mode — local unsigned demo
    )

    missing_blocked = False
    try:
        execute_with_receipt(
            require_signature=False,  # dev-mode: local unsigned demo
            tool_fn=side_effect.write_file,
            args=ARGS,
            receipt=None,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor=ACTOR,
            require_signature=False,  # dev-mode — local unsigned demo
        )
    except ReceiptValidationError:
        missing_blocked = True

    ok = result == "SIDE EFFECT EXECUTED" and missing_blocked and len(side_effect.calls) == 1
    report = {
        "status": "pass" if ok else "fail",
        "valid_receipt_executed": result == "SIDE EFFECT EXECUTED",
        "missing_receipt_blocked": missing_blocked,
        "side_effect_count": len(side_effect.calls),
        "invariant": "No valid Decision Receipt, no side effect.",
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
