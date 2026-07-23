from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from gove_zone import (
    Decision,
    DecisionReceipt,
    DecisionRecord,
    GovernedExecutor,
    ReceiptValidationError,
    Validator,
    adapter_artifact_digest,
    sha256_json,
)
from gove_zone._strict_dispatch_fixture import (
    StrictReceiptGateFixture,
    build_strict_receipt_gate_fixture,
)

TENANT = "tenant-A"
BOUNDARY = "agent-framework/local"
ACTION = "runtime.email.send"
ACTOR = "agent-framework-runner"
ARGS = {"to": "review@example.com", "body": "Evidence bundle is ready."}
LIFECYCLE_AUTHORITY_ID = "fixture-lifecycle-validator"


def issue_receipt(fixture: StrictReceiptGateFixture, args: dict[str, Any]) -> DecisionReceipt:
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=ACTION,
        argument_hash=sha256_json(args),
        policy_version="agent-framework-policy/v1",
        event_id="ev_agent_framework_gate",
        actor=ACTOR,
        reason="example framework tool allow",
    )
    event = fixture.audit.append(record)
    return DecisionReceipt.from_record(
        record=record,
        audit_hash=event["event_hash"],
        previous_audit_hash=event["previous_hash"],
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="agent-framework-policy",
        policy_hash="agent-framework-policy/v1",
        request_id="req-agent-framework-gate",
        validator=Validator("framework-policy-validator"),
        authority="tenant-A/send-email-grant",
        signer=fixture.signer,
    )


class FrameworkToolWrapper:
    def __init__(
        self,
        fixture: StrictReceiptGateFixture,
        action: str,
        fn: Callable[..., Any],
    ) -> None:
        self.executor = GovernedExecutor(
            tenant_id=TENANT,
            execution_boundary=BOUNDARY,
            expected_actor=ACTOR,
            require_signature=True,
            verifier=fixture.signer,
            consumption_store=fixture.consumption_store,
            rejection_audit=fixture.audit,
            lifecycle_signer=fixture.lifecycle_signer,
            lifecycle_authority_id=LIFECYCLE_AUTHORITY_ID,
        )
        self.executor.register_tool(
            action,
            fn,
            adapter_artifact_digest=adapter_artifact_digest(fn),
        )
        self.action = action

    def call(self, args: dict[str, Any], receipt: DecisionReceipt | None) -> Any:
        return self.executor.execute(self.action, args, receipt)


class Mailer:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    def send(self, **kwargs: Any) -> str:
        self.sent.append(dict(kwargs))
        return "EMAIL SENT"


def _last_audit_denial(fixture: StrictReceiptGateFixture, reason_code: str) -> bool:
    events = list(fixture.audit.iter_events())
    if not events:
        return False
    last = events[-1]
    return last["decision"] == Decision.DENY.value and last["matched_rules"] == [reason_code]


def main() -> int:
    with TemporaryDirectory() as tmp:
        fixture = build_strict_receipt_gate_fixture(Path(tmp), name="agent-framework-gate")
        mailer = Mailer()
        wrapper = FrameworkToolWrapper(fixture, ACTION, mailer.send)
        receipt = issue_receipt(fixture, ARGS)

        result = wrapper.call(ARGS, receipt)

        substitution_blocked = False
        try:
            wrapper.call({"to": "attacker@example.com", "body": "exfiltrate"}, receipt)
        except ReceiptValidationError:
            substitution_blocked = True

        substitution_audited = _last_audit_denial(fixture, "receipt.execution.receipt_invalid")

        ok = (
            result == "EMAIL SENT"
            and substitution_blocked
            and substitution_audited
            and len(mailer.sent) == 1
        )
        report = {
            "status": "pass" if ok else "fail",
            "valid_receipt_executed": result == "EMAIL SENT",
            "argument_substitution_blocked": substitution_blocked,
            "argument_substitution_audited": substitution_audited,
            "side_effect_count": len(mailer.sent),
            "invariant": "No valid Decision Receipt, no side effect.",
        }
        print(json.dumps(report, sort_keys=True))
        return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
