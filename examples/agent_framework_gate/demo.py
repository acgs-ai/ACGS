from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from gove_zone import (
    Decision,
    DecisionReceipt,
    DecisionRecord,
    GovernedExecutor,
    ReceiptValidationError,
    Validator,
    sha256_json,
)

TENANT = "tenant-A"
BOUNDARY = "agent-framework/local"
ACTION = "runtime.email.send"
ACTOR = "agent-framework-runner"
ARGS = {"to": "review@example.com", "body": "Evidence bundle is ready."}


def issue_receipt(args: dict[str, Any]) -> DecisionReceipt:
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=ACTION,
        argument_hash=sha256_json(args),
        policy_version="agent-framework-policy/v1",
        event_id="ev_agent_framework_gate",
        actor=ACTOR,
        reason="example framework tool allow",
    )
    return DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash_agent_framework_gate",
        previous_audit_hash="0" * 64,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="agent-framework-policy",
        policy_hash="agent-framework-policy/v1",
        request_id="req-agent-framework-gate",
        validator=Validator("framework-policy-validator"),
        authority="tenant-A/send-email-grant",
    )


class FrameworkToolWrapper:
    def __init__(self, action: str, fn: Callable[..., Any]) -> None:
        self.executor = GovernedExecutor(
            require_signature=False,  # local unsigned dev-mode demo (explicit GovernanceProfile.dev posture)
            tenant_id=TENANT,
            execution_boundary=BOUNDARY,
            expected_actor=ACTOR,
        )
        self.executor.register(action, fn)
        self.action = action

    def call(self, args: dict[str, Any], receipt: DecisionReceipt | None) -> Any:
        return self.executor.execute(self.action, args, receipt)


class Mailer:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    def send(self, **kwargs: Any) -> str:
        self.sent.append(dict(kwargs))
        return "EMAIL SENT"


def main() -> int:
    mailer = Mailer()
    wrapper = FrameworkToolWrapper(ACTION, mailer.send)
    receipt = issue_receipt(ARGS)

    result = wrapper.call(ARGS, receipt)

    substitution_blocked = False
    try:
        wrapper.call({"to": "attacker@example.com", "body": "exfiltrate"}, receipt)
    except ReceiptValidationError:
        substitution_blocked = True

    ok = result == "EMAIL SENT" and substitution_blocked and len(mailer.sent) == 1
    report = {
        "status": "pass" if ok else "fail",
        "valid_receipt_executed": result == "EMAIL SENT",
        "argument_substitution_blocked": substitution_blocked,
        "side_effect_count": len(mailer.sent),
        "invariant": "No valid Decision Receipt, no side effect.",
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
