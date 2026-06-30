"""Governed VulnClaw Penetration Testing Agent Demo.

Demonstrates how to apply gove-zone's call-time policy enforcement and
receipt-gated execution to highly active and privileged pentest agents (like VulnClaw).

No valid Decision Receipt, no side effect.

Run it (from the monorepo root):
    uv run --package gove-zone python \\
        packages/gove-zone/examples/governed_vulnclaw_demo.py
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
    GovernanceRequest,
    ProposedAction,
    ReceiptValidationError,
    RuleSetPolicy,
    TenantPolicyStore,
    Validator,
    evaluate_tenant_action,
    execute_with_receipt,
)
from gove_zone.tool import ToolCall, normalize_path_context

TENANT = "tenant-security-ops"
BOUNDARY = "maci-sandbox"
VALIDATOR = Validator("constitutional-council")
AUTHORITY = "tenant-security-ops/recon-gate"

# Declarative policy bundle targeting VulnClaw pentest tools
VULNCLAW_POLICY = RuleSetPolicy.from_dict({
    "id": "policy-vulnclaw-governance",
    "rules": [
        {
            "id": "DENY_UNAUTHORIZED_TARGETS",
            "effect": "deny",
            "tools": ["vulnclaw.port_scan", "vulnclaw.exploit"],
            "state_equals": {
                "is_unauthorized_target": True
            },
            "reason": "Scanning or exploiting targets outside the authorized scoping boundary is prohibited."
        },
        {
            "id": "RESTRICT_EXPLOITATION_TO_ADMINS",
            "effect": "deny",
            "tools": ["vulnclaw.exploit"],
            "allow": {
                "actors": ["elevated-administrator", "system-operator"]
            },
            "reason": "Standard agent actors are restricted from triggering target exploitation payloads."
        },
        {
            "id": "BLOCK_LOCAL_PYTHON_EXECUTION",
            "effect": "deny",
            "tools": ["vulnclaw.python_execute"],
            "allow": {
                "trust_tiers": ["system-admin"]
            },
            "reason": "Arbitrary local Python code execution is blocked for standard and elevated security agents."
        },
        {
            "id": "RESTRICT_REPORT_DIRECTORY",
            "effect": "deny",
            "tools": ["vulnclaw.generate_report"],
            "path_prefix": "/opt/secure/secrets",
            "reason": "Pentesting reports and PoC scripts cannot be written to secure secrets directory paths."
        }
    ]
})


class VulnClawMockTool:
    """Mock VulnClaw pentest agent capabilities simulating active side-effects."""

    def __init__(self) -> None:
        self.ran_port_scan = False
        self.ran_exploit = False
        self.ran_python_execute = False
        self.ran_generate_report = False

    def port_scan(self, target: str, ports: list[int]) -> dict[str, Any]:
        self.ran_port_scan = True
        print(f"    [REAL SCAN] Scanning target '{target}' ports: {ports}")
        return {"status": "success", "open_ports": [22, 80, 443]}

    def exploit(self, target: str, cve_id: str, payload: str) -> dict[str, Any]:
        self.ran_exploit = True
        print(f"    [REAL EXPLOIT] Delivering exploit '{cve_id}' with payload '{payload}' to target '{target}'")
        return {"status": "success", "exploit_delivered": True}

    def python_execute(self, script_body: str) -> dict[str, Any]:
        self.ran_python_execute = True
        print(f"    [REAL LOCAL EXEC] Running Python script on local runner: {script_body!r}")
        return {"status": "success", "stdout": "uid=1000(martin) gid=1000(martin) groups=1000(martin)\n"}

    def generate_report(self, output_dir: str, format: str = "markdown") -> dict[str, Any]:
        self.ran_generate_report = True
        report_path = f"{output_dir}/vulnclaw_report.md"
        print(f"    [REAL FILE WRITE] Generating report files under: {report_path}")
        return {"status": "success", "report_path": report_path}


def _ok(msg: str) -> None:
    print(f"  \033[32m✓\033[0m {msg}")


def _fail(msg: str) -> None:
    print(f"  \033[31m✗ INVARIANT VIOLATED: {msg}\033[0m")
    raise SystemExit(1)


def _issue_vulnclaw_receipt(
    store: TenantPolicyStore,
    audit: ChainHashAuditStore,
    tool_name: str,
    tool_args: dict[str, Any],
    actor: str,
    trust_tier: str,
    is_unauthorized_target: bool,
    path_context: str | None,
    rid: str,
) -> DecisionReceipt:
    # State used for policy checks
    state = {
        "is_unauthorized_target": is_unauthorized_target,
        "trust_tier": trust_tier,
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
    is_unauthorized_target: bool,
    path_context: str | None,
    request_id: str,
    expected_decision: Decision,
) -> None:
    print(f"\nScenario: {name}")
    print(f"  Inputs: tool={tool_name}, args={tool_args}, actor={actor}, tier={trust_tier}, unauthorized_target={is_unauthorized_target}, path={path_context}")

    receipt = _issue_vulnclaw_receipt(
        store=store,
        audit=audit,
        tool_name=tool_name,
        tool_args=tool_args,
        actor=actor,
        trust_tier=trust_tier,
        is_unauthorized_target=is_unauthorized_target,
        path_context=path_context,
        rid=request_id,
    )

    if receipt.decision != expected_decision.value:
        _fail(f"Expected decision {expected_decision.value.upper()}, got {receipt.decision.upper()} (rules: {receipt.matched_rules})")

    tool = VulnClawMockTool()

    # Map tool name to mock function
    tool_fns = {
        "vulnclaw.port_scan": tool.port_scan,
        "vulnclaw.exploit": tool.exploit,
        "vulnclaw.python_execute": tool.python_execute,
        "vulnclaw.generate_report": tool.generate_report,
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

        if expected_decision == Decision.DENY:
            _fail("Denied action executed anyway!")
        _ok(f"Executed successfully! Result: {result}")

    except ReceiptValidationError as exc:
        if expected_decision == Decision.ALLOW:
            _fail(f"Allowed action was incorrectly blocked: {exc}")
        # Verify that mock tool did not run
        if tool.ran_port_scan or tool.ran_exploit or tool.ran_python_execute or tool.ran_generate_report:
            _fail("Denied action triggered mock tool side-effects!")
        _ok(f"Blocked as expected by execution gate: {exc}")


def main() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="gove-zone-vulnclaw-demo-"))
    store = TenantPolicyStore(workdir / "policies")
    store.store_bundle(TENANT, VULNCLAW_POLICY)
    audit = ChainHashAuditStore(workdir / "audit.jsonl")

    print("\n=======================================================")
    print("gove-zone — Governed VulnClaw Pentesting Agent Proof")
    print("=======================================================")

    # 1. ALLOW: Port scanning on authorized target
    run_test_scenario(
        name="1. Reconnaissance scan on authorized target host",
        store=store,
        audit=audit,
        tool_name="vulnclaw.port_scan",
        tool_args={"target": "192.168.1.100", "ports": [22, 80, 443]},
        actor="recon-agent-1",
        trust_tier="standard",
        is_unauthorized_target=False,
        path_context=None,
        request_id="req-recon-allow",
        expected_decision=Decision.ALLOW,
    )

    # 2. DENY: Port scanning on unauthorized target
    run_test_scenario(
        name="2. Reconnaissance scan on unauthorized target host",
        store=store,
        audit=audit,
        tool_name="vulnclaw.port_scan",
        tool_args={"target": "10.0.0.1", "ports": [22, 80, 443]},
        actor="recon-agent-1",
        trust_tier="standard",
        is_unauthorized_target=True,
        path_context=None,
        request_id="req-recon-deny",
        expected_decision=Decision.DENY,
    )

    # 3. DENY: Target exploitation by standard actor
    run_test_scenario(
        name="3. Exploitation payload delivered by standard agent",
        store=store,
        audit=audit,
        tool_name="vulnclaw.exploit",
        tool_args={"target": "192.168.1.100", "cve_id": "CVE-2024-1234", "payload": "id"},
        actor="recon-agent-1",
        trust_tier="standard",
        is_unauthorized_target=False,
        path_context=None,
        request_id="req-exploit-deny",
        expected_decision=Decision.DENY,
    )

    # 4. ALLOW: Target exploitation by admin actor
    run_test_scenario(
        name="4. Exploitation payload delivered by elevated administrator",
        store=store,
        audit=audit,
        tool_name="vulnclaw.exploit",
        tool_args={"target": "192.168.1.100", "cve_id": "CVE-2024-1234", "payload": "id"},
        actor="elevated-administrator",
        trust_tier="standard",
        is_unauthorized_target=False,
        path_context=None,
        request_id="req-exploit-allow",
        expected_decision=Decision.ALLOW,
    )

    # 5. DENY: Local Python code execution by standard/elevated agent
    run_test_scenario(
        name="5. Local Python code execution by standard/elevated agent",
        store=store,
        audit=audit,
        tool_name="vulnclaw.python_execute",
        tool_args={"script_body": "import os; os.system('id')"},
        actor="recon-agent-1",
        trust_tier="elevated",
        is_unauthorized_target=False,
        path_context=None,
        request_id="req-python-deny",
        expected_decision=Decision.DENY,
    )

    # 6. ALLOW: Local Python code execution by system-admin trust tier
    run_test_scenario(
        name="6. Local Python code execution by system-admin trust tier",
        store=store,
        audit=audit,
        tool_name="vulnclaw.python_execute",
        tool_args={"script_body": "import os; os.system('id')"},
        actor="system-operator",
        trust_tier="system-admin",
        is_unauthorized_target=False,
        path_context=None,
        request_id="req-python-allow",
        expected_decision=Decision.ALLOW,
    )

    # 7. DENY: Generate report in protected path prefix
    run_test_scenario(
        name="7. Writing reports/PoC to a path-restricted directory prefix",
        store=store,
        audit=audit,
        tool_name="vulnclaw.generate_report",
        tool_args={"output_dir": "/opt/secure/secrets/critical"},
        actor="recon-agent-1",
        trust_tier="standard",
        is_unauthorized_target=False,
        path_context="/opt/secure/secrets/critical",
        request_id="req-path-deny",
        expected_decision=Decision.DENY,
    )

    # 8. ALLOW: Generate report in normal output directory
    run_test_scenario(
        name="8. Writing reports/PoC to an allowed output directory",
        store=store,
        audit=audit,
        tool_name="vulnclaw.generate_report",
        tool_args={"output_dir": "/home/martin/reports"},
        actor="recon-agent-1",
        trust_tier="standard",
        is_unauthorized_target=False,
        path_context="/home/martin/reports",
        request_id="req-path-allow",
        expected_decision=Decision.ALLOW,
    )

    print("\n-------------------------------------------------------")
    print("Verifying Audit Chain...")
    chain = audit.verify_chain()
    if not chain["valid"]:
        _fail(f"Audit chain failed: {chain['failures']}")
    _ok(f"Audit chain successfully verified with {chain['checked']} tamper-evident events.")

    print("\nAll VulnClaw governance invariants held. No valid Decision Receipt, no side effect.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
