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

TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
ACTION = "runtime.file.write"
ACTOR = "agent-1"
ARGS = {"path": "safe.txt", "content": "approved"}
LIFECYCLE_AUTHORITY_ID = "fixture-lifecycle-validator"


def issue_receipt(fixture: StrictReceiptGateFixture, args: dict[str, Any]) -> DecisionReceipt:
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=ACTION,
        argument_hash=sha256_json(args),
        policy_version="example-policy/v1",
        event_id="ev_python_tool_gate",
        actor=ACTOR,
        reason="example allow",
    )
    event = fixture.audit.append(record)
    return DecisionReceipt.from_record(
        record=record,
        audit_hash=event["event_hash"],
        previous_audit_hash=event["previous_hash"],
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="example-policy",
        policy_hash="example-policy/v1",
        request_id="req-python-tool-gate",
        validator=Validator("constitutional-council"),
        authority="tenant-A/write-grant",
        signer=fixture.signer,
    )


class SideEffect:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def write_file(self, **kwargs: Any) -> str:
        self.calls.append(dict(kwargs))
        return "SIDE EFFECT EXECUTED"


def _last_audit_denial(fixture: StrictReceiptGateFixture, reason_code: str) -> bool:
    events = list(fixture.audit.iter_events())
    if not events:
        return False
    last = events[-1]
    return last["decision"] == Decision.DENY.value and last["matched_rules"] == [reason_code]


def main() -> int:
    with TemporaryDirectory() as tmp:
        fixture = build_strict_receipt_gate_fixture(Path(tmp), name="python-tool-gate")
        side_effect = SideEffect()
        receipt = issue_receipt(fixture, ARGS)

        result = execute_with_receipt(
            tool_fn=side_effect.write_file,
            args=ARGS,
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor=ACTOR,
            expected_adapter_artifact_digest=adapter_artifact_digest(side_effect.write_file),
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
                tool_fn=side_effect.write_file,
                args=ARGS,
                receipt=None,
                expected_tenant_id=TENANT,
                expected_execution_boundary=BOUNDARY,
                expected_action=ACTION,
                expected_actor=ACTOR,
                expected_adapter_artifact_digest=adapter_artifact_digest(side_effect.write_file),
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
            result == "SIDE EFFECT EXECUTED"
            and missing_blocked
            and missing_audited
            and len(side_effect.calls) == 1
        )
        report = {
            "status": "pass" if ok else "fail",
            "valid_receipt_executed": result == "SIDE EFFECT EXECUTED",
            "missing_receipt_blocked": missing_blocked,
            "missing_receipt_audited": missing_audited,
            "side_effect_count": len(side_effect.calls),
            "invariant": "No valid Decision Receipt, no side effect.",
        }
        print(json.dumps(report, sort_keys=True))
        return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
