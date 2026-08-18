from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_EXAMPLE_DIR = Path(__file__).resolve().parent
if str(_EXAMPLE_DIR) not in sys.path:
    sys.path.insert(0, str(_EXAMPLE_DIR))

from gove_zone import (
    Decision,
    DecisionReceipt,
    DecisionRecord,
    ReceiptValidationError,
    Validator,
    execute_with_receipt,
    sha256_json,
)

from receipt_to_semantica import emit_to_semantica, receipt_to_semantica

TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
ACTION = "runtime.file.write"
ACTOR = "agent-1"
ARGS = {"path": "safe.txt", "content": "approved"}
VALIDATOR = Validator("constitutional-council")


def issue_receipt(
    *,
    decision: Decision,
    event_id: str,
    args: dict[str, Any] | None = None,
    goal: str = "",
    transformed_args: dict[str, Any] | None = None,
    reason: str = "example",
) -> DecisionReceipt:
    bound_args = args if args is not None else ARGS
    record = DecisionRecord(
        decision=decision,
        tool=ACTION,
        argument_hash=sha256_json(bound_args),
        policy_version="example-policy/v1",
        event_id=event_id,
        actor=ACTOR,
        reason=reason,
        goal=goal,
        transformed_args=transformed_args,
    )
    return DecisionReceipt.from_record(
        record=record,
        audit_hash=f"audit_hash_{event_id}",
        previous_audit_hash="0" * 64,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="example-policy",
        policy_hash="example-policy/v1",
        request_id=f"req-{event_id}",
        validator=VALIDATOR,
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
    allow = issue_receipt(
        decision=Decision.ALLOW,
        event_id="ev_semantica_allow",
        goal="write approved file",
    )
    deny = issue_receipt(
        decision=Decision.DENY,
        event_id="ev_semantica_deny",
        goal="write refused file",
        reason="policy deny",
    )
    transform = issue_receipt(
        decision=Decision.TRANSFORM,
        event_id="ev_semantica_transform",
        goal="write transformed file",
        transformed_args={"path": "safe.txt", "content": "redacted"},
    )
    escalate = issue_receipt(
        decision=Decision.ESCALATE,
        event_id="ev_semantica_escalate",
        goal="write needs review",
        reason="human review",
    )

    result = execute_with_receipt(
        require_signature=False,  # dev-mode: local unsigned demo
        tool_fn=side_effect.write_file,
        args=ARGS,
        receipt=allow,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action=ACTION,
        expected_actor=ACTOR,
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
        )
    except ReceiptValidationError:
        missing_blocked = True

    payloads = [receipt_to_semantica(item) for item in (allow, deny, transform, escalate)]
    outcomes = [payload["outcome"] for payload in payloads]
    fabricated_confidence = any("confidence" in payload for payload in payloads)
    fabricated_reasoning = any("reasoning" in payload for payload in payloads)
    emit_result = emit_to_semantica(payloads[0])

    ok = (
        result == "SIDE EFFECT EXECUTED"
        and missing_blocked
        and len(side_effect.calls) == 1
        and set(outcomes) == {"allow", "deny", "transform", "escalate"}
        and all(payload["semantica_is_not_a_gate"] is True for payload in payloads)
        and not fabricated_confidence
        and not fabricated_reasoning
        and all(payload["decision_id"] for payload in payloads)
    )
    report = {
        "status": "pass" if ok else "fail",
        "valid_receipt_executed": result == "SIDE EFFECT EXECUTED",
        "missing_receipt_blocked": missing_blocked,
        "side_effect_count": len(side_effect.calls),
        "verdicts_exported": len(outcomes),
        "outcomes": sorted(outcomes),
        "semantica_is_not_a_gate": True,
        "semantica_installed": emit_result.get("reason") != "semantica_not_installed",
        "semantica_emitted": bool(emit_result.get("emitted")),
        "fabricated_confidence": fabricated_confidence,
        "fabricated_reasoning": fabricated_reasoning,
        "invariant": "No valid Decision Receipt, no side effect.",
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
