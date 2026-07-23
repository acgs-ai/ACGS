from __future__ import annotations

import dataclasses
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
BOUNDARY = "tamper-demo/local"
ACTION = "runtime.file.write"
ACTOR = "agent-1"
ARGS = {"path": "safe.txt", "content": "approved"}
LIFECYCLE_AUTHORITY_ID = "fixture-lifecycle-validator"


def issue_receipt(fixture: StrictReceiptGateFixture, args: dict[str, Any]) -> DecisionReceipt:
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=ACTION,
        argument_hash=sha256_json(args),
        policy_version="tamper-demo-policy/v1",
        event_id="ev_tamper_demo_allow",
        actor=ACTOR,
        reason="example allow before tamper",
    )
    event = fixture.audit.append(record)
    return DecisionReceipt.from_record(
        record=record,
        audit_hash=event["event_hash"],
        previous_audit_hash=event["previous_hash"],
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="tamper-demo-policy",
        policy_hash="tamper-demo-policy/v1",
        request_id="req-tamper-demo",
        validator=Validator("constitutional-council"),
        authority="tenant-A/write-grant",
        signer=fixture.signer,
    )


class SideEffect:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def run(self, **kwargs: Any) -> str:
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
        fixture = build_strict_receipt_gate_fixture(Path(tmp), name="tamper-demo")
        side = SideEffect()
        receipt = issue_receipt(fixture, ARGS)

        gate_kwargs: dict[str, Any] = {
            "expected_tenant_id": TENANT,
            "expected_execution_boundary": BOUNDARY,
            "expected_action": ACTION,
            "expected_actor": ACTOR,
            "expected_adapter_artifact_digest": adapter_artifact_digest(side.run),
            "require_signature": True,
            "verifier": fixture.signer,
            "consumption_store": fixture.consumption_store,
            "rejection_audit": fixture.audit,
            "lifecycle_signer": fixture.lifecycle_signer,
            "lifecycle_authority_id": LIFECYCLE_AUTHORITY_ID,
        }

        result = execute_with_receipt(
            tool_fn=side.run,
            args=ARGS,
            receipt=receipt,
            expected_audit_hash=receipt.audit_event_hash,
            expected_policy_hash="tamper-demo-policy/v1",
            expected_policy_bundle_id="tamper-demo-policy",
            **gate_kwargs,
        )

        tampered_blocked = False
        tampered = dataclasses.replace(receipt, proposed_action="runtime.shell.run")
        try:
            execute_with_receipt(tool_fn=side.run, args=ARGS, receipt=tampered, **gate_kwargs)
        except ReceiptValidationError:
            tampered_blocked = True
        tampered_audited = _last_audit_denial(fixture, "receipt.execution.receipt_invalid")

        arg_mismatch_blocked = False
        try:
            execute_with_receipt(
                tool_fn=side.run,
                args={"path": "different.txt", "content": "approved"},
                receipt=receipt,
                **gate_kwargs,
            )
        except ReceiptValidationError:
            arg_mismatch_blocked = True
        arg_mismatch_audited = _last_audit_denial(fixture, "receipt.execution.receipt_invalid")

        # Verify the persisted chain through the same strict audit object that wrote
        # it, so the checkpoint anchor is the one bound to these events.
        before = fixture.audit.verify_checkpointed_chain()
        audit_path = Path(fixture.audit.path)
        lines = audit_path.read_text(encoding="utf-8").splitlines()
        event = json.loads(lines[0])
        event["decision"] = "deny"
        lines[0] = json.dumps(event, sort_keys=True, separators=(",", ":"))
        audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        after = fixture.audit.verify_checkpointed_chain()

        ok = (
            result == "SIDE EFFECT EXECUTED"
            and tampered_blocked
            and tampered_audited
            and arg_mismatch_blocked
            and arg_mismatch_audited
            and bool(before["valid"])
            and not bool(after["valid"])
            and len(side.calls) == 1
        )
        report = {
            "status": "pass" if ok else "fail",
            "valid_receipt_executed": result == "SIDE EFFECT EXECUTED",
            "tampered_receipt_blocked": tampered_blocked,
            "tampered_receipt_audited": tampered_audited,
            "argument_mismatch_blocked": arg_mismatch_blocked,
            "argument_mismatch_audited": arg_mismatch_audited,
            "audit_chain_valid_before_tamper": bool(before["valid"]),
            "audit_chain_valid_after_tamper": bool(after["valid"]),
            "side_effect_count": len(side.calls),
            "invariant": "No valid Decision Receipt, no side effect.",
        }
        print(json.dumps(report, sort_keys=True))
        return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
