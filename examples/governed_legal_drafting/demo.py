"""Governed Legal Drafting & Discovery Agent Demo.

Demonstrates how to apply gove-zone's call-time policy enforcement and
receipt-gated execution to a legal drafting/discovery agent: drafting
documents, filing court submissions, accessing attorney-client privileged
material, messaging clients, and exporting discovery sets.

No valid Decision Receipt, no side effect.

Run it (from the monorepo root):
    uv run --package gove-zone python examples/governed_legal_drafting/demo.py

This example is local-only (tempdir-only, unsigned dev-mode receipts). It is
NOT a bar-approval, compliance-certification, or regulator-facing claim of
any kind — see docs/design/governance-legal-agent.md for scope and
non-claims.

Only the final JSON report is written to stdout (matching the demo/README
contract enforced by tests/docs/test_docs_and_examples.py); human-readable
scenario diagnostics are written to stderr.
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
from gove_zone.tool import ToolCall, normalize_path_context

TENANT = "tenant-legal-ops"
BOUNDARY = "legal-drafting-sandbox"
VALIDATOR = Validator("general-counsel")
AUTHORITY = "tenant-legal-ops/matter-gate"

# Declarative policy bundle targeting the legal drafting/discovery agent's tools
LEGAL_POLICY = RuleSetPolicy.from_dict(
    {
        "id": "policy-legal-drafting-governance",
        "rules": [
            {
                "id": "ESCALATE_COURT_SUBMISSION_NON_ATTORNEY",
                "effect": "escalate",
                "tools": ["legal.file_court_submission"],
                "allow": {"trust_tiers": ["supervising-attorney"]},
                "reason": (
                    "Court and regulatory filings require supervising-attorney "
                    "sign-off before submission."
                ),
            },
            {
                "id": "DENY_PRIVILEGED_ACCESS_OUTSIDE_SCOPE",
                "effect": "deny",
                "tools": ["legal.access_privileged_docs"],
                "state_equals": {"outside_matter_scope": True},
                "reason": (
                    "Attorney-client privileged material cannot be accessed "
                    "outside the matter's ethical-wall scope."
                ),
            },
            {
                "id": "DENY_UNREVIEWED_CLIENT_COMMS",
                "effect": "deny",
                "tools": ["legal.send_client_communication"],
                "state_equals": {"unreviewed": True},
                "reason": (
                    "Unreviewed draft communications cannot be sent to clients "
                    "without a QC pass."
                ),
            },
            {
                "id": "ESCALATE_CLIENT_COMMS_NON_ATTORNEY",
                "effect": "escalate",
                "tools": ["legal.send_client_communication"],
                "allow": {"trust_tiers": ["attorney", "supervising-attorney"]},
                "reason": (
                    "Reviewed client communications still require an "
                    "attorney-tier sender before sending."
                ),
            },
            {
                "id": "DENY_DISCOVERY_EXPORT_TO_PRIVILEGED_MOUNT",
                "effect": "deny",
                "tools": ["legal.export_discovery"],
                "path_prefix": "/mnt/privileged",
                "reason": (
                    "Discovery exports cannot be written to privileged/shared "
                    "mount paths, preventing leakage of privileged material to "
                    "unmanaged shares."
                ),
            },
        ],
    }
)


class LegalMockTool:
    """Mock legal drafting/discovery agent capabilities simulating side-effects."""

    def __init__(self) -> None:
        self.ran_draft_document = False
        self.ran_file_court_submission = False
        self.ran_access_privileged_docs = False
        self.ran_send_client_communication = False
        self.ran_export_discovery = False

    def draft_document(self, matter_id: str, doc_type: str) -> dict[str, Any]:
        self.ran_draft_document = True
        print(f"    [REAL DRAFT] Drafting {doc_type} for matter {matter_id}", file=sys.stderr)
        return {"status": "success", "doc_type": doc_type}

    def file_court_submission(
        self, matter_id: str, court: str, document_id: str
    ) -> dict[str, Any]:
        self.ran_file_court_submission = True
        print(
            f"    [REAL FILING] Submitting document {document_id} to {court} "
            f"for matter {matter_id}",
            file=sys.stderr,
        )
        return {"status": "success", "filed": True}

    def access_privileged_docs(self, matter_id: str, doc_id: str) -> dict[str, Any]:
        self.ran_access_privileged_docs = True
        print(
            f"    [REAL ACCESS] Opening privileged document {doc_id} for matter {matter_id}",
            file=sys.stderr,
        )
        return {"status": "success", "content": "[privileged content]"}

    def send_client_communication(
        self, matter_id: str, client_id: str, body: str
    ) -> dict[str, Any]:
        self.ran_send_client_communication = True
        print(
            f"    [REAL SEND] Sending client communication to {client_id} "
            f"for matter {matter_id}",
            file=sys.stderr,
        )
        return {"status": "success", "sent": True}

    def export_discovery(self, matter_id: str, output_dir: str) -> dict[str, Any]:
        self.ran_export_discovery = True
        report_path = f"{output_dir}/discovery_export.zip"
        print(f"    [REAL EXPORT] Writing discovery export to {report_path}", file=sys.stderr)
        return {"status": "success", "export_path": report_path}

    def any_side_effect_ran(self) -> bool:
        return (
            self.ran_draft_document
            or self.ran_file_court_submission
            or self.ran_access_privileged_docs
            or self.ran_send_client_communication
            or self.ran_export_discovery
        )


def _ok(msg: str) -> None:
    print(f"  \033[32m✓\033[0m {msg}", file=sys.stderr)


def _fail(msg: str) -> None:
    print(f"  \033[31m✗ INVARIANT VIOLATED: {msg}\033[0m", file=sys.stderr)


def _issue_legal_receipt(
    store: TenantPolicyStore,
    audit: ChainHashAuditStore,
    tool_name: str,
    tool_args: dict[str, Any],
    actor: str,
    trust_tier: str,
    outside_matter_scope: bool,
    unreviewed: bool,
    path_context: str | None,
    rid: str,
) -> DecisionReceipt:
    # State used for policy checks
    state = {
        "trust_tier": trust_tier,
        "outside_matter_scope": outside_matter_scope,
        "unreviewed": unreviewed,
    }

    policy = store.load_bundle(TENANT, TENANT)
    previous_hash = audit.last_hash()

    from gove_zone.kernel import Kernel

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
    name: str,
    store: TenantPolicyStore,
    audit: ChainHashAuditStore,
    tool_name: str,
    tool_args: dict[str, Any],
    actor: str,
    trust_tier: str,
    outside_matter_scope: bool,
    unreviewed: bool,
    path_context: str | None,
    request_id: str,
    expected_decision: Decision,
) -> bool:
    print(f"\nScenario: {name}", file=sys.stderr)
    print(
        f"  Inputs: tool={tool_name}, args={tool_args}, actor={actor}, "
        f"tier={trust_tier}, outside_scope={outside_matter_scope}, "
        f"unreviewed={unreviewed}, path={path_context}",
        file=sys.stderr,
    )

    receipt = _issue_legal_receipt(
        store=store,
        audit=audit,
        tool_name=tool_name,
        tool_args=tool_args,
        actor=actor,
        trust_tier=trust_tier,
        outside_matter_scope=outside_matter_scope,
        unreviewed=unreviewed,
        path_context=path_context,
        rid=request_id,
    )

    if receipt.decision != expected_decision.value:
        _fail(
            f"Expected decision {expected_decision.value.upper()}, got "
            f"{receipt.decision.upper()} (rules: {receipt.matched_rules})"
        )
        return False

    tool = LegalMockTool()
    tool_fns = {
        "legal.draft_document": tool.draft_document,
        "legal.file_court_submission": tool.file_court_submission,
        "legal.access_privileged_docs": tool.access_privileged_docs,
        "legal.send_client_communication": tool.send_client_communication,
        "legal.export_discovery": tool.export_discovery,
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
            _fail(f"{expected_decision.value.upper()} action executed anyway!")
            return False
        _ok(f"Executed successfully! Result: {result}")
        return True

    except ReceiptValidationError as exc:
        if expected_decision == Decision.ALLOW:
            _fail(f"Allowed action was incorrectly blocked: {exc}")
            return False
        if tool.any_side_effect_ran():
            _fail(
                f"{expected_decision.value.upper()} action triggered mock tool side-effects!"
            )
            return False
        _ok(f"Blocked as expected by execution gate ({expected_decision.value}): {exc}")
        return True


def main() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="gove-zone-legal-drafting-demo-"))
    store = TenantPolicyStore(workdir / "policies")
    store.store_bundle(TENANT, LEGAL_POLICY)
    audit = ChainHashAuditStore(workdir / "audit.jsonl")

    print("\n=======================================================", file=sys.stderr)
    print("gove-zone — Governed Legal Drafting & Discovery Agent Proof", file=sys.stderr)
    print("=======================================================", file=sys.stderr)

    scenarios: list[dict[str, Any]] = [
        dict(
            name="1. Draft a motion for an in-scope matter",
            tool_name="legal.draft_document",
            tool_args={"matter_id": "M-1001", "doc_type": "motion_to_compel"},
            actor="paralegal-1",
            trust_tier="paralegal",
            outside_matter_scope=False,
            unreviewed=False,
            path_context=None,
            request_id="req-draft-allow",
            expected_decision=Decision.ALLOW,
        ),
        dict(
            name="2. Court submission attempted by a standard paralegal",
            tool_name="legal.file_court_submission",
            tool_args={"matter_id": "M-1001", "court": "N.D. Cal.", "document_id": "doc-501"},
            actor="paralegal-1",
            trust_tier="paralegal",
            outside_matter_scope=False,
            unreviewed=False,
            path_context=None,
            request_id="req-filing-escalate",
            expected_decision=Decision.ESCALATE,
        ),
        dict(
            name="3. Court submission filed by a supervising attorney",
            tool_name="legal.file_court_submission",
            tool_args={"matter_id": "M-1001", "court": "N.D. Cal.", "document_id": "doc-501"},
            actor="attorney-jane",
            trust_tier="supervising-attorney",
            outside_matter_scope=False,
            unreviewed=False,
            path_context=None,
            request_id="req-filing-allow",
            expected_decision=Decision.ALLOW,
        ),
        dict(
            name="4. Privileged document access outside matter scope (ethical wall)",
            tool_name="legal.access_privileged_docs",
            tool_args={"matter_id": "M-2002", "doc_id": "priv-77"},
            actor="paralegal-1",
            trust_tier="paralegal",
            outside_matter_scope=True,
            unreviewed=False,
            path_context=None,
            request_id="req-priv-deny",
            expected_decision=Decision.DENY,
        ),
        dict(
            name="5. Privileged document access inside matter scope",
            tool_name="legal.access_privileged_docs",
            tool_args={"matter_id": "M-1001", "doc_id": "priv-12"},
            actor="paralegal-1",
            trust_tier="paralegal",
            outside_matter_scope=False,
            unreviewed=False,
            path_context=None,
            request_id="req-priv-allow",
            expected_decision=Decision.ALLOW,
        ),
        dict(
            name="6. Unreviewed client communication",
            tool_name="legal.send_client_communication",
            tool_args={"matter_id": "M-1001", "client_id": "client-acme", "body": "draft update"},
            actor="attorney-jane",
            trust_tier="attorney",
            outside_matter_scope=False,
            unreviewed=True,
            path_context=None,
            request_id="req-comms-deny",
            expected_decision=Decision.DENY,
        ),
        dict(
            name="7. Reviewed client communication sent by a non-attorney",
            tool_name="legal.send_client_communication",
            tool_args={
                "matter_id": "M-1001",
                "client_id": "client-acme",
                "body": "reviewed update",
            },
            actor="paralegal-1",
            trust_tier="paralegal",
            outside_matter_scope=False,
            unreviewed=False,
            path_context=None,
            request_id="req-comms-escalate",
            expected_decision=Decision.ESCALATE,
        ),
        dict(
            name="8. Reviewed client communication sent by an attorney",
            tool_name="legal.send_client_communication",
            tool_args={
                "matter_id": "M-1001",
                "client_id": "client-acme",
                "body": "reviewed update",
            },
            actor="attorney-jane",
            trust_tier="attorney",
            outside_matter_scope=False,
            unreviewed=False,
            path_context=None,
            request_id="req-comms-allow",
            expected_decision=Decision.ALLOW,
        ),
        dict(
            name="9. Discovery export written to a privileged shared mount",
            tool_name="legal.export_discovery",
            tool_args={"matter_id": "M-1001", "output_dir": "/mnt/privileged/exports"},
            actor="paralegal-1",
            trust_tier="paralegal",
            outside_matter_scope=False,
            unreviewed=False,
            path_context="/mnt/privileged/exports",
            request_id="req-export-deny",
            expected_decision=Decision.DENY,
        ),
        dict(
            name="10. Discovery export written to the matter's managed output directory",
            tool_name="legal.export_discovery",
            tool_args={"matter_id": "M-1001", "output_dir": f"{workdir}/exports"},
            actor="paralegal-1",
            trust_tier="paralegal",
            outside_matter_scope=False,
            unreviewed=False,
            path_context=f"{workdir}/exports",
            request_id="req-export-allow",
            expected_decision=Decision.ALLOW,
        ),
    ]

    results = [
        run_test_scenario(store=store, audit=audit, **scenario) for scenario in scenarios
    ]

    print("\n-------------------------------------------------------", file=sys.stderr)
    print("Verifying Audit Chain...", file=sys.stderr)
    chain = audit.verify_chain()
    chain_valid = bool(chain["valid"])
    if not chain_valid:
        _fail(f"Audit chain failed: {chain['failures']}")
    else:
        _ok(f"Audit chain successfully verified with {chain['checked']} tamper-evident events.")

    ok = all(results) and chain_valid
    report = {
        "status": "pass" if ok else "fail",
        "scenarios_run": len(results),
        "scenarios_passed": sum(1 for passed in results if passed),
        "audit_chain_valid": chain_valid,
        "audit_events_checked": chain.get("checked", 0),
        "invariant": "No valid Decision Receipt, no side effect.",
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
