"""Governed Maigret Reconnaissance Demo.

Demonstrates how to apply gove-zone's call-time policy enforcement and
receipt-gated execution to highly active OSINT reconnaissance tools (like Maigret).

No valid Decision Receipt, no side effect.

Run it (from the monorepo root):
    uv run --package gove-zone python \\
        packages/gove-zone/examples/governed_maigret_demo.py
"""

from __future__ import annotations

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

TENANT = "tenant-security-ops"
BOUNDARY = "maci-sandbox"
VALIDATOR = Validator("constitutional-council")
AUTHORITY = "tenant-security-ops/recon-gate"

# Declarative policy bundle specifically targeting the maigret.search tool
MAIGRET_POLICY = RuleSetPolicy.from_dict(
    {
        "id": "policy-recon-governance",
        "rules": [
            {
                "id": "DENY_SYSTEM_USERNAMES",
                "effect": "deny",
                "tools": ["maigret.search"],
                "state_equals": {"is_system_username": True},
                "reason": "Searching for system administration usernames is prohibited.",
            },
            {
                "id": "RESTRICT_SENSITIVE_CATEGORIES",
                "effect": "deny",
                "tools": ["maigret.search"],
                "state_equals": {"has_sensitive_tags": True},
                "allow": {"trust_tiers": ["elevated"]},
                "reason": (
                    "Standard agents are blocked from searching dating, adult, or financial sites."
                ),
            },
            {
                "id": "RESTRICT_OUTPUT_DIRECTORY",
                "effect": "deny",
                "tools": ["maigret.search"],
                "path_prefix": "/opt/secure/secrets",
                "reason": "Reports cannot be written to secure secrets directory paths.",
            },
            {
                "id": "BLOCK_RECON_AI_SUMMARY",
                "effect": "deny",
                "tools": ["maigret.search"],
                "state_equals": {"use_ai": True},
                "allow": {"actors": ["lead-investigator"]},
                "reason": "Only the lead-investigator actor may run AI-based profile summarization.",
            },
        ],
    }
)


class MaigretMockTool:
    """Mock Maigret engine simulating side-effectful network username checks and
    report files generation."""

    def __init__(self) -> None:
        self.ran = False
        self.last_username: str | None = None
        self.last_tags: list[str] | None = None
        self.last_output_dir: str | None = None
        self.last_use_ai: bool = False

    def search(
        self,
        username: str,
        tags: list[str] | None = None,
        output_dir: str = "./reports",
        use_ai: bool = False,
    ) -> dict[str, Any]:
        self.ran = True
        self.last_username = username
        self.last_tags = tags
        self.last_output_dir = output_dir
        self.last_use_ai = use_ai

        # Simulate network side effect
        tags_str = ", ".join(tags) if tags else "all categories"
        print(
            f"    [REAL SCAN] Initiated scanning for '{username}' "
            f"across sites matching tags: {tags_str}"
        )
        print(
            f"    [REAL FILE] Generating report file under: "
            f"{output_dir}/maigret_report_{username}.html"
        )
        if use_ai:
            print(
                "    [REAL LLM] Sending scraped data to external LLM API "
                "for analysis report summary"
            )

        return {
            "status": "success",
            "username": username,
            "sites_scanned": 150 if tags else 3000,
            "report_path": f"{output_dir}/maigret_report_{username}.html",
            "use_ai": use_ai,
        }


def _ok(msg: str) -> None:
    print(f"  \033[32m✓\033[0m {msg}")


def _fail(msg: str) -> None:
    print(f"  \033[31m✗ INVARIANT VIOLATED: {msg}\033[0m")
    raise SystemExit(1)


def _issue_recon_receipt(
    store: TenantPolicyStore,
    audit: ChainHashAuditStore,
    actor: str,
    username: str,
    tags: list[str] | None,
    output_dir: str,
    use_ai: bool,
    trust_tier: str,
    rid: str,
) -> DecisionReceipt:
    # Hydrate state with resolved attributes for policy rules to evaluate
    restricted_usernames = ["admin", "root", "administrator", "system", "support"]
    restricted_tags = ["dating", "adult", "finance"]

    state = {
        "is_system_username": username in restricted_usernames,
        "has_sensitive_tags": any(t in restricted_tags for t in (tags or [])),
        "trust_tier": trust_tier,
        "use_ai": use_ai,
    }

    policy = store.load_bundle(TENANT, TENANT)
    previous_hash = audit.last_hash()

    from gove_zone.kernel import Kernel

    call = ToolCall(
        name="maigret.search",
        args={
            "username": username,
            "tags": tags,
            "output_dir": output_dir,
            "use_ai": use_ai,
        },
        actor=actor,
        path=normalize_path_context(output_dir),
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
    actor: str,
    username: str,
    tags: list[str] | None,
    output_dir: str,
    use_ai: bool,
    trust_tier: str,
    request_id: str,
    expected_decision: Decision,
) -> None:
    print(f"\nScenario: {name}")
    print(
        f"  Inputs: actor={actor}, username={username}, tags={tags}, "
        f"out={output_dir}, use_ai={use_ai}, tier={trust_tier}"
    )

    receipt = _issue_recon_receipt(
        store=store,
        audit=audit,
        actor=actor,
        username=username,
        tags=tags,
        output_dir=output_dir,
        use_ai=use_ai,
        trust_tier=trust_tier,
        rid=request_id,
    )

    if receipt.decision != expected_decision.value:
        _fail(
            f"Expected decision {expected_decision.value.upper()}, "
            f"got {receipt.decision.upper()} (rules: {receipt.matched_rules})"
        )

    tool = MaigretMockTool()

    try:
        result = execute_with_receipt(
            tool_fn=tool.search,
            args={
                "username": username,
                "tags": tags,
                "output_dir": output_dir,
                "use_ai": use_ai,
            },
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action="maigret.search",
            expected_actor=actor,
            require_signature=False,  # dev mode (unsigned)
        )

        if expected_decision == Decision.DENY:
            _fail("Denied action executed anyway!")
        _ok(f"Executed successfully! Result path: {result['report_path']}")

    except ReceiptValidationError as exc:
        if expected_decision == Decision.ALLOW:
            _fail(f"Allowed action was incorrectly blocked: {exc}")
        if tool.ran:
            _fail("Denied action triggered mock tool side-effects!")
        _ok(f"Blocked as expected by execution gate: {exc}")


def main() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="gove-zone-maigret-demo-"))
    store = TenantPolicyStore(workdir / "policies")
    store.store_bundle(TENANT, MAIGRET_POLICY)
    audit = ChainHashAuditStore(workdir / "audit.jsonl")

    print("\n=======================================================")
    print("gove-zone — Governed Maigret Reconnaissance Engine Proof")
    print("=======================================================")

    # 1. ALLOW: Normal search query
    run_test_scenario(
        name="1. Normal search on coding/social sites",
        store=store,
        audit=audit,
        actor="recon-agent-1",
        username="martin_dev",
        tags=["coding", "social"],
        output_dir="/home/martin/reports",
        use_ai=False,
        trust_tier="standard",
        request_id="req-normal",
        expected_decision=Decision.ALLOW,
    )

    # 2. DENY: Target username is restricted (system username)
    run_test_scenario(
        name="2. Restricted system username query",
        store=store,
        audit=audit,
        actor="recon-agent-1",
        username="admin",
        tags=["social"],
        output_dir="/home/martin/reports",
        use_ai=False,
        trust_tier="standard",
        request_id="req-system-user",
        expected_decision=Decision.DENY,
    )

    # 3. DENY: Scanning sensitive dating/adult tags by standard agent
    run_test_scenario(
        name="3. Sensitive tags (dating) by standard agent",
        store=store,
        audit=audit,
        actor="recon-agent-1",
        username="martin_dev",
        tags=["dating", "social"],
        output_dir="/home/martin/reports",
        use_ai=False,
        trust_tier="standard",
        request_id="req-sensitive-tags-deny",
        expected_decision=Decision.DENY,
    )

    # 4. ALLOW: Scanning sensitive tags by elevated agent
    run_test_scenario(
        name="4. Sensitive tags (dating) by elevated agent",
        store=store,
        audit=audit,
        actor="recon-agent-1",
        username="martin_dev",
        tags=["dating", "social"],
        output_dir="/home/martin/reports",
        use_ai=False,
        trust_tier="elevated",
        request_id="req-sensitive-tags-allow",
        expected_decision=Decision.ALLOW,
    )

    # 5. DENY: Output directory is path-restricted
    run_test_scenario(
        name="5. Path restricted output directory",
        store=store,
        audit=audit,
        actor="recon-agent-1",
        username="martin_dev",
        tags=["coding"],
        output_dir="/opt/secure/secrets/confidential",
        use_ai=False,
        trust_tier="standard",
        request_id="req-path-deny",
        expected_decision=Decision.DENY,
    )

    # 6. DENY: Standard actor requesting AI analysis
    run_test_scenario(
        name="6. Standard actor requesting AI summary analysis",
        store=store,
        audit=audit,
        actor="recon-agent-1",
        username="martin_dev",
        tags=["coding"],
        output_dir="/home/martin/reports",
        use_ai=True,
        trust_tier="standard",
        request_id="req-ai-deny",
        expected_decision=Decision.DENY,
    )

    # 7. ALLOW: Authorized lead-investigator actor requesting AI analysis
    run_test_scenario(
        name="7. Authorized lead-investigator requesting AI summary analysis",
        store=store,
        audit=audit,
        actor="lead-investigator",
        username="martin_dev",
        tags=["coding"],
        output_dir="/home/martin/reports",
        use_ai=True,
        trust_tier="standard",
        request_id="req-ai-allow",
        expected_decision=Decision.ALLOW,
    )

    print("\n-------------------------------------------------------")
    print("Verifying Audit Chain...")
    chain = audit.verify_chain()
    if not chain["valid"]:
        _fail(f"Audit chain failed: {chain['failures']}")
    _ok(f"Audit chain successfully verified with {chain['checked']} tamper-evident events.")

    print("\nAll Maigret governance invariants held. No valid Decision Receipt, no side effect.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
