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
BOUNDARY = "ci/local"
ACTION = "ci.deploy"
ACTOR = "ci-runner-1"


def issue_receipt(
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
    return DecisionReceipt.from_record(
        record=record,
        audit_hash=f"audit_hash_{event_id}",
        previous_audit_hash="0" * 64,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="ci-deploy-policy",
        policy_hash="ci-deploy-policy/v1",
        request_id=f"req-{event_id}",
        validator=Validator("release-manager"),
        authority="tenant-A/deploy-grant",
    )


class Deployer:
    def __init__(self) -> None:
        self.deploys: list[dict[str, Any]] = []

    def deploy(self, **kwargs: Any) -> str:
        self.deploys.append(dict(kwargs))
        return f"DEPLOYED {kwargs['environment']}:{kwargs['version']}"


def main() -> int:
    deployer = Deployer()
    staging_args = {"environment": "staging", "version": "1.2.3"}
    prod_args = {"environment": "production", "version": "1.2.3"}

    staging_receipt = issue_receipt(Decision.ALLOW, staging_args, "ev_ci_staging")
    prod_deny_receipt = issue_receipt(
        Decision.DENY,
        prod_args,
        "ev_ci_prod",
        ("PROD_REQUIRES_MANUAL_APPROVAL",),
    )

    staging_result = execute_with_receipt(
        require_signature=False,  # dev-mode: local unsigned demo
        tool_fn=deployer.deploy,
        args=staging_args,
        receipt=staging_receipt,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action=ACTION,
        expected_actor=ACTOR,
        require_signature=False,  # dev-mode — local unsigned demo
    )

    prod_denied = False
    try:
        execute_with_receipt(
            require_signature=False,  # dev-mode: local unsigned demo
            tool_fn=deployer.deploy,
            args=prod_args,
            receipt=prod_deny_receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor=ACTOR,
            require_signature=False,  # dev-mode — local unsigned demo
        )
    except ReceiptValidationError:
        prod_denied = True

    ok = staging_result.startswith("DEPLOYED") and prod_denied and len(deployer.deploys) == 1
    report = {
        "status": "pass" if ok else "fail",
        "staging_deploy_executed": staging_result == "DEPLOYED staging:1.2.3",
        "prod_deploy_denied": prod_denied,
        "deploy_count": len(deployer.deploys),
        "invariant": "No valid Decision Receipt, no side effect.",
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
