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
BOUNDARY = "ci/local"
ACTION = "ci.deploy"
ACTOR = "ci-runner-1"
LIFECYCLE_AUTHORITY_ID = "fixture-lifecycle-validator"
PROD_RULE = "PROD_REQUIRES_MANUAL_APPROVAL"


def issue_receipt(
    fixture: StrictReceiptGateFixture,
    decision: Decision,
    args: dict[str, Any],
    event_id: str,
    rules: tuple[str, ...] = (),
) -> DecisionReceipt:
    record = DecisionRecord(
        decision=decision,
        tool=ACTION,
        argument_hash=sha256_json(args),
        policy_version="ci-deploy-policy/v1",
        event_id=event_id,
        actor=ACTOR,
        matched_rules=rules,
        reason="example CI deploy decision",
    )
    event = fixture.audit.append(record)
    return DecisionReceipt.from_record(
        record=record,
        audit_hash=event["event_hash"],
        previous_audit_hash=event["previous_hash"],
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="ci-deploy-policy",
        policy_hash="ci-deploy-policy/v1",
        request_id=f"req-{event_id}",
        validator=Validator("release-manager"),
        authority="tenant-A/deploy-grant",
        signer=fixture.signer,
    )


class Deployer:
    def __init__(self) -> None:
        self.deploys: list[dict[str, Any]] = []

    def deploy(self, **kwargs: Any) -> str:
        self.deploys.append(dict(kwargs))
        return f"DEPLOYED {kwargs['environment']}:{kwargs['version']}"


def _last_audit_denial(fixture: StrictReceiptGateFixture, reason_code: str) -> bool:
    events = list(fixture.audit.iter_events())
    if not events:
        return False
    last = events[-1]
    return last["decision"] == Decision.DENY.value and last["matched_rules"] == [reason_code]


def _authorization_rules(fixture: StrictReceiptGateFixture, event_id: str) -> list[str]:
    for event in fixture.audit.iter_events():
        if event.get("event_id") == event_id:
            return list(event["matched_rules"])
    return []


def main() -> int:
    with TemporaryDirectory() as tmp:
        fixture = build_strict_receipt_gate_fixture(Path(tmp), name="ci-deploy-gate")
        deployer = Deployer()
        staging_args = {"environment": "staging", "version": "1.2.3"}
        prod_args = {"environment": "production", "version": "1.2.3"}

        staging_receipt = issue_receipt(
            fixture,
            Decision.ALLOW,
            staging_args,
            "ev_ci_staging",
        )
        prod_deny_receipt = issue_receipt(
            fixture,
            Decision.DENY,
            prod_args,
            "ev_ci_prod",
            (PROD_RULE,),
        )

        staging_result = execute_with_receipt(
            tool_fn=deployer.deploy,
            args=staging_args,
            receipt=staging_receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor=ACTOR,
            expected_adapter_artifact_digest=adapter_artifact_digest(deployer.deploy),
            require_signature=True,
            verifier=fixture.signer,
            consumption_store=fixture.consumption_store,
            rejection_audit=fixture.audit,
            lifecycle_signer=fixture.lifecycle_signer,
            lifecycle_authority_id=LIFECYCLE_AUTHORITY_ID,
        )

        prod_denied = False
        try:
            execute_with_receipt(
                tool_fn=deployer.deploy,
                args=prod_args,
                receipt=prod_deny_receipt,
                expected_tenant_id=TENANT,
                expected_execution_boundary=BOUNDARY,
                expected_action=ACTION,
                expected_actor=ACTOR,
                expected_adapter_artifact_digest=adapter_artifact_digest(deployer.deploy),
                require_signature=True,
                verifier=fixture.signer,
                consumption_store=fixture.consumption_store,
                rejection_audit=fixture.audit,
                lifecycle_signer=fixture.lifecycle_signer,
                lifecycle_authority_id=LIFECYCLE_AUTHORITY_ID,
            )
        except ReceiptValidationError:
            prod_denied = True

        # The executor rejects a DENY receipt at the gate; the policy cause for the
        # denial lives in the separate authorization record and is asserted apart
        # from the gate reason so the two are never conflated.
        prod_denial_audited = _last_audit_denial(fixture, "receipt.execution.receipt_invalid")
        prod_policy_rule_retained = _authorization_rules(fixture, "ev_ci_prod") == [PROD_RULE]

        ok = (
            staging_result == "DEPLOYED staging:1.2.3"
            and prod_denied
            and prod_denial_audited
            and prod_policy_rule_retained
            and len(deployer.deploys) == 1
        )
        report = {
            "status": "pass" if ok else "fail",
            "staging_deploy_executed": staging_result == "DEPLOYED staging:1.2.3",
            "prod_deploy_denied": prod_denied,
            "prod_denial_audited": prod_denial_audited,
            "prod_policy_rule_retained": prod_policy_rule_retained,
            "deploy_count": len(deployer.deploys),
            "invariant": "No valid Decision Receipt, no side effect.",
        }
        print(json.dumps(report, sort_keys=True))
        return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
