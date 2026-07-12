"""Governed AML (Anti-Money-Laundering) Transaction-Screening Agent Demo.

Demonstrates how to apply gove-zone's call-time policy enforcement and
receipt-gated execution to a financial-crimes transaction-screening agent
capable of sanctions screening, SAR (Suspicious Activity Report) filing,
fund release/account freezes, and case-report export.

No valid Decision Receipt, no side effect.

Run it (from the monorepo root):
    uv run --package gove-zone python examples/governed_aml_screening/demo.py

Prints a single JSON report to stdout (``status: "pass"|"fail"``); scenario
narration goes to stderr so stdout stays machine-parseable for the CI smoke
test in tests/docs/test_docs_and_examples.py.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from gove_zone import (
    ChainHashAuditStore,
    Decision,
    DecisionReceipt,
    ReceiptValidationError,
    RuleSetPolicy,
    TenantPolicyStore,
    Validator,
    execute_with_receipt,
)
from gove_zone.kernel import Kernel
from gove_zone.tool import ToolCall, normalize_path_context

TENANT = "tenant-financial-crimes"
BOUNDARY = "aml-screening-sandbox"
VALIDATOR = Validator("constitutional-council")
AUTHORITY = "tenant-financial-crimes/aml-gate"

# Declarative policy bundle targeting the AML transaction-screening tools.
AML_POLICY = RuleSetPolicy.from_dict(
    {
        "id": "policy-aml-screening-governance",
        "rules": [
            {
                "id": "DENY_SANCTIONED_COUNTERPARTY_SCREEN",
                "effect": "deny",
                "tools": ["aml.screen_transaction"],
                "state_equals": {"sanctioned_counterparty": True},
                "reason": (
                    "A transaction tied to a sanctioned counterparty cannot "
                    "be auto-screened; it must route to manual sanctions review."
                ),
            },
            {
                "id": "ESCALATE_SAR_FILING_TO_COMPLIANCE_OFFICER",
                "effect": "escalate",
                "tools": ["aml.file_sar"],
                "allow": {"trust_tiers": ["compliance-officer"]},
                "reason": (
                    "Filing a Suspicious Activity Report is a regulatory act "
                    "that requires compliance-officer approval before submission."
                ),
            },
            {
                "id": "DENY_RELEASE_OVER_THRESHOLD",
                "effect": "deny",
                "tools": ["aml.release_funds"],
                "state_equals": {"over_threshold": True},
                "reason": (
                    "Releasing funds above the currency-transaction-report "
                    "threshold without a cleared review is prohibited."
                ),
            },
            {
                "id": "ESCALATE_FREEZE_TO_SUPERVISOR",
                "effect": "escalate",
                "tools": ["aml.freeze_account"],
                "allow": {"trust_tiers": ["supervisor", "compliance-officer"]},
                "reason": (
                    "Freezing a customer account is a high-impact action that "
                    "requires supervisor sign-off."
                ),
            },
            {
                "id": "RESTRICT_EXPORT_DIRECTORY",
                "effect": "deny",
                "tools": ["aml.export_report"],
                "path_prefix": "/mnt/regulated-exports",
                "reason": (
                    "AML case reports cannot be exported to the regulated-exports "
                    "mount without an approved export-path allowance."
                ),
            },
        ],
    }
)


class AmlMockTool:
    """Mock AML screening agent capabilities simulating active side-effects."""

    def __init__(self) -> None:
        self.ran_screen_transaction = False
        self.ran_file_sar = False
        self.ran_release_funds = False
        self.ran_freeze_account = False
        self.ran_export_report = False

    def screen_transaction(
        self, transaction_id: str, counterparty: str, amount: float
    ) -> dict[str, Any]:
        self.ran_screen_transaction = True
        print(
            f"    [REAL SCREEN] Screening txn '{transaction_id}' vs "
            f"'{counterparty}' amount={amount}",
            file=sys.stderr,
        )
        return {"status": "success", "transaction_id": transaction_id, "watchlist_hit": False}

    def file_sar(self, case_id: str, narrative: str) -> dict[str, Any]:
        self.ran_file_sar = True
        print(f"    [REAL SAR FILING] Submitting SAR for case '{case_id}'", file=sys.stderr)
        return {"status": "success", "case_id": case_id, "filed": True}

    def release_funds(self, transaction_id: str, amount: float) -> dict[str, Any]:
        self.ran_release_funds = True
        print(
            f"    [REAL RELEASE] Releasing {amount} for txn '{transaction_id}'",
            file=sys.stderr,
        )
        return {"status": "success", "transaction_id": transaction_id, "released": amount}

    def freeze_account(self, account_id: str, reason: str) -> dict[str, Any]:
        self.ran_freeze_account = True
        print(f"    [REAL FREEZE] Freezing account '{account_id}': {reason}", file=sys.stderr)
        return {"status": "success", "account_id": account_id, "frozen": True}

    def export_report(self, output_dir: str, case_id: str) -> dict[str, Any]:
        self.ran_export_report = True
        report_path = f"{output_dir}/{case_id}_aml_report.pdf"
        print(f"    [REAL FILE WRITE] Exporting case report to: {report_path}", file=sys.stderr)
        return {"status": "success", "report_path": report_path}


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def _issue_aml_receipt(
    store: TenantPolicyStore,
    audit: ChainHashAuditStore,
    tool_name: str,
    tool_args: dict[str, Any],
    actor: str,
    trust_tier: str,
    state_extra: dict[str, Any],
    path_context: str | None,
    rid: str,
) -> DecisionReceipt:
    state: dict[str, Any] = {"trust_tier": trust_tier, **state_extra}

    policy = store.load_bundle(TENANT, TENANT)
    previous_hash = audit.last_hash()

    call = ToolCall(
        name=tool_name,
        args=tool_args,
        actor=actor,
        path=normalize_path_context(path_context) if path_context else (),
        state=state,
    )

    kernel = Kernel(policy=policy, audit=audit, actor=actor)
    record, audit_hash = kernel._evaluate_and_record(call)

    policy_id = getattr(policy, "policy_id", "custom")

    return DecisionReceipt.from_record(
        record=record,
        audit_hash=audit_hash,
        previous_audit_hash=previous_hash,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id=policy_id,
        policy_hash=policy.version,
        request_id=rid,
        validator=VALIDATOR,
        authority=AUTHORITY,
    )


def run_test_scenario(
    *,
    name: str,
    store: TenantPolicyStore,
    audit: ChainHashAuditStore,
    tool_name: str,
    tool_args: dict[str, Any],
    actor: str,
    trust_tier: str,
    state_extra: dict[str, Any],
    path_context: str | None,
    request_id: str,
    expected_decision: Decision,
) -> dict[str, Any]:
    _log(f"\nScenario: {name}")
    _log(
        f"  Inputs: tool={tool_name}, args={tool_args}, actor={actor}, "
        f"tier={trust_tier}, state={state_extra}, path={path_context}"
    )

    receipt = _issue_aml_receipt(
        store=store,
        audit=audit,
        tool_name=tool_name,
        tool_args=tool_args,
        actor=actor,
        trust_tier=trust_tier,
        state_extra=state_extra,
        path_context=path_context,
        rid=request_id,
    )

    outcome: dict[str, Any] = {
        "name": name,
        "tool": tool_name,
        "expected_decision": expected_decision.value,
        "actual_decision": receipt.decision,
        "invariant_held": True,
        "detail": "",
    }

    if receipt.decision != expected_decision.value:
        outcome["invariant_held"] = False
        outcome["detail"] = (
            f"expected decision {expected_decision.value.upper()}, got "
            f"{receipt.decision.upper()} (rules: {receipt.matched_rules})"
        )
        _log(f"  INVARIANT VIOLATED: {outcome['detail']}")
        return outcome

    tool = AmlMockTool()
    tool_fns = {
        "aml.screen_transaction": tool.screen_transaction,
        "aml.file_sar": tool.file_sar,
        "aml.release_funds": tool.release_funds,
        "aml.freeze_account": tool.freeze_account,
        "aml.export_report": tool.export_report,
    }
    tool_fn = tool_fns[tool_name]

    try:
        result = execute_with_receipt(
            tool_fn=tool_fn,
            args=tool_args,
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action=tool_name,
            expected_actor=actor,
            require_signature=False,  # dev mode (unsigned)
        )

        if expected_decision != Decision.ALLOW:
            outcome["invariant_held"] = False
            outcome["detail"] = (
                f"{expected_decision.value.upper()} action executed anyway"
            )
            _log(f"  INVARIANT VIOLATED: {outcome['detail']}")
        else:
            _log(f"  OK: executed successfully. Result: {result}")

    except ReceiptValidationError as exc:
        if expected_decision == Decision.ALLOW:
            outcome["invariant_held"] = False
            outcome["detail"] = f"allowed action was incorrectly blocked: {exc}"
            _log(f"  INVARIANT VIOLATED: {outcome['detail']}")
        elif any(vars(tool).values()):
            outcome["invariant_held"] = False
            outcome["detail"] = (
                f"{expected_decision.value.upper()} action triggered mock tool "
                "side-effects"
            )
            _log(f"  INVARIANT VIOLATED: {outcome['detail']}")
        else:
            _log(f"  OK: blocked as expected by execution gate: {exc}")

    return outcome


def main() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="gove-zone-aml-screening-demo-"))
    store = TenantPolicyStore(workdir / "policies")
    store.store_bundle(TENANT, AML_POLICY)
    audit = ChainHashAuditStore(workdir / "audit.jsonl")

    allowed_export_dir = str(workdir / "case-exports")
    blocked_export_dir = "/mnt/regulated-exports/case-4471"

    _log("=======================================================")
    _log("gove-zone -- Governed AML Transaction-Screening Agent Proof")
    _log("=======================================================")

    scenarios = [
        dict(
            name="1. Screen a transaction against a non-sanctioned counterparty",
            tool_name="aml.screen_transaction",
            tool_args={
                "transaction_id": "txn-1001",
                "counterparty": "Acme Trading LLC",
                "amount": 4200.00,
            },
            actor="analyst-1",
            trust_tier="analyst",
            state_extra={"sanctioned_counterparty": False},
            path_context=None,
            request_id="req-screen-allow",
            expected_decision=Decision.ALLOW,
        ),
        dict(
            name="2. Screen a transaction tied to a sanctioned counterparty",
            tool_name="aml.screen_transaction",
            tool_args={
                "transaction_id": "txn-1002",
                "counterparty": "Sanctioned Shell Corp",
                "amount": 15000.00,
            },
            actor="analyst-1",
            trust_tier="analyst",
            state_extra={"sanctioned_counterparty": True},
            path_context=None,
            request_id="req-screen-deny",
            expected_decision=Decision.DENY,
        ),
        dict(
            name="3. Standard analyst files a SAR without compliance-officer approval",
            tool_name="aml.file_sar",
            tool_args={"case_id": "case-4471", "narrative": "Structuring pattern across 5 txns"},
            actor="analyst-1",
            trust_tier="analyst",
            state_extra={},
            path_context=None,
            request_id="req-sar-escalate",
            expected_decision=Decision.ESCALATE,
        ),
        dict(
            name="4. Compliance officer files the same SAR",
            tool_name="aml.file_sar",
            tool_args={"case_id": "case-4471", "narrative": "Structuring pattern across 5 txns"},
            actor="compliance-officer-1",
            trust_tier="compliance-officer",
            state_extra={},
            path_context=None,
            request_id="req-sar-allow",
            expected_decision=Decision.ALLOW,
        ),
        dict(
            name="5. Release funds above the CTR reporting threshold",
            tool_name="aml.release_funds",
            tool_args={"transaction_id": "txn-1003", "amount": 25000.00},
            actor="analyst-1",
            trust_tier="analyst",
            state_extra={"over_threshold": True},
            path_context=None,
            request_id="req-release-deny",
            expected_decision=Decision.DENY,
        ),
        dict(
            name="6. Release funds under the CTR reporting threshold",
            tool_name="aml.release_funds",
            tool_args={"transaction_id": "txn-1004", "amount": 900.00},
            actor="analyst-1",
            trust_tier="analyst",
            state_extra={"over_threshold": False},
            path_context=None,
            request_id="req-release-allow",
            expected_decision=Decision.ALLOW,
        ),
        dict(
            name="7. Standard analyst freezes an account without supervisor sign-off",
            tool_name="aml.freeze_account",
            tool_args={"account_id": "acct-8890", "reason": "suspected structuring"},
            actor="analyst-1",
            trust_tier="analyst",
            state_extra={},
            path_context=None,
            request_id="req-freeze-escalate",
            expected_decision=Decision.ESCALATE,
        ),
        dict(
            name="8. Supervisor freezes the account",
            tool_name="aml.freeze_account",
            tool_args={"account_id": "acct-8890", "reason": "suspected structuring"},
            actor="supervisor-1",
            trust_tier="supervisor",
            state_extra={},
            path_context=None,
            request_id="req-freeze-allow",
            expected_decision=Decision.ALLOW,
        ),
        dict(
            name="9. Export a case report to the regulated-exports mount",
            tool_name="aml.export_report",
            tool_args={"output_dir": blocked_export_dir, "case_id": "case-4471"},
            actor="analyst-1",
            trust_tier="analyst",
            state_extra={},
            path_context=blocked_export_dir,
            request_id="req-export-deny",
            expected_decision=Decision.DENY,
        ),
        dict(
            name="10. Export a case report to an approved case-exports directory",
            tool_name="aml.export_report",
            tool_args={"output_dir": allowed_export_dir, "case_id": "case-4471"},
            actor="analyst-1",
            trust_tier="analyst",
            state_extra={},
            path_context=allowed_export_dir,
            request_id="req-export-allow",
            expected_decision=Decision.ALLOW,
        ),
    ]

    results = [run_test_scenario(store=store, audit=audit, **scenario) for scenario in scenarios]

    chain_ok = True
    chain_checked = 0
    try:
        chain = audit.verify_chain()
        chain_ok = bool(chain["valid"])
        chain_checked = chain.get("checked", 0)
        if chain_ok:
            _log(f"\nAudit chain verified with {chain_checked} tamper-evident events.")
        else:
            _log(f"\nAUDIT CHAIN FAILED: {chain['failures']}")
    except Exception as exc:  # pragma: no cover - defensive
        chain_ok = False
        _log(f"\nAUDIT CHAIN VERIFICATION RAISED: {exc}")

    all_ok = chain_ok and all(r["invariant_held"] for r in results)

    report = {
        "status": "pass" if all_ok else "fail",
        "scenario_count": len(results),
        "scenarios_held": sum(1 for r in results if r["invariant_held"]),
        "audit_chain_valid": chain_ok,
        "audit_events_checked": chain_checked,
        "scenarios": results,
        "invariant": "No valid Decision Receipt, no side effect.",
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
