"""Game-day drill: persist a governed incident-evidence bundle.

This is the executable half of the G3.4 game-day / tabletop runbook
(``packages/gove-zone/docs/gameday-runbook.md``). It drives the **real** kernel,
GovernedExecutor, and hash-chained audit store through two fail-closed events --

1. a **DENY** (a pentest tool call outside the authorized scope), proving the
   DENY :class:`DecisionReceipt` *cannot* execute (``execute_with_receipt`` raises
   :class:`ReceiptValidationError` and no side effect runs), and
2. an **ESCALATE** (a call that dead-ends waiting for a human), proving the
   ESCALATE receipt cannot auto-execute, and that the only way forward is the
   governed human-approval -> resume path in :mod:`gove_zone.escalation`
   (a *distinct* human validator approves; execution routes solely through the
   :class:`GovernedExecutor` gate) --

then verifies the resulting tamper-evident chain and **persists** a durable,
sha256-manifested incident-evidence bundle to a caller-provided output directory.
The bundle members are mapped to the incident-response playbook's required
inputs / expected outputs
(``packages/ai-governance-research/solution-catalog/incident-response.md``).

The drill NEVER weakens fail-closed behavior and NEVER treats DENY/ESCALATE as
executable. Production / organic attestation stays human-gated and is out of
scope: this proves the *mechanism*, not a production incident.

Run it (from the monorepo root)::

    uv run --package gove-zone python \
        packages/gove-zone/examples/gameday_incident_evidence.py [OUTPUT_DIR]

If ``OUTPUT_DIR`` is omitted a temp directory is used. On success the script
emits a single-line JSON status summary (``"status": "pass"``) to stdout so it is
CI-friendly, and exits 0.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from gove_zone import (
    ChainHashAuditStore,
    Decision,
    DecisionReceipt,
    DecisionRecord,
    EscalateError,
    GovernedExecutor,
    Kernel,
    Policy,
    ReceiptValidationError,
    RuleSetPolicy,
    Validator,
    approve_escalation,
    execute_with_receipt,
    new_event_id,
    resume_with_receipt,
    sha256_json,
)
from gove_zone.tool import ToolCall

# --- deployment identity (shared by every governed decision in the drill) ----

TENANT = "tenant-security-ops"
BOUNDARY = "maci-sandbox"
POLICY_BUNDLE_ID = "policy-gameday-incident"
PROPOSER = "recon-agent-1"
PROPOSER_VALIDATOR = Validator("constitutional-council", "proposer")
HUMAN_APPROVER = Validator("human-on-call-approver", "approver")
AUTHORITY = "tenant-security-ops/incident-gate"

# The DENY scenario reuses the VulnClaw scope-boundary rule: a standard agent
# scanning an UNAUTHORIZED target is denied. (Same shape as governed_vulnclaw_demo.)
DENY_POLICY = RuleSetPolicy.from_dict(
    {
        "id": POLICY_BUNDLE_ID,
        "rules": [
            {
                "id": "DENY_UNAUTHORIZED_TARGETS",
                "effect": "deny",
                "tools": ["vulnclaw.port_scan", "vulnclaw.exploit"],
                "state_equals": {"is_unauthorized_target": True},
                "reason": (
                    "Scanning or exploiting targets outside the authorized "
                    "scoping boundary is prohibited."
                ),
            }
        ],
    }
)


class _EscalateEveryCallPolicy(Policy):
    """Escalate every call: the side effect needs a human decision first."""

    @property
    def version(self) -> str:
        return "gameday-escalate/v1"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.ESCALATE,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("ESCALATE:needs-human-authority",),
            reason="privileged pentest action requires named human authority",
        )


class _SideEffectSpy:
    """Records whether the guarded tool actually ran (a real side effect)."""

    def __init__(self) -> None:
        self.ran = False
        self.calls: list[dict[str, Any]] = []

    def port_scan(self, target: str, ports: list[int]) -> dict[str, Any]:
        self.ran = True
        self.calls.append({"target": target, "ports": ports})
        return {"status": "success", "open_ports": [22, 80, 443]}

    def exploit(self, target: str, cve_id: str, payload: str) -> dict[str, Any]:
        self.ran = True
        self.calls.append({"target": target, "cve_id": cve_id})
        return {"status": "success", "exploit_delivered": True}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dump_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# --- scenario drivers --------------------------------------------------------


def _run_deny_scenario(audit: ChainHashAuditStore) -> tuple[DecisionReceipt, bool]:
    """Drive a DENY through the real kernel; prove the receipt cannot execute.

    Returns the captured DENY :class:`DecisionReceipt` and a bool that is True
    iff the execution gate blocked the call AND the guarded tool never ran.
    """
    kernel = Kernel(policy=DENY_POLICY, audit=audit, actor=PROPOSER)
    call = ToolCall(
        name="vulnclaw.port_scan",
        args={"target": "10.0.0.1", "ports": [22, 80, 443]},
        actor=PROPOSER,
        state={"is_unauthorized_target": True},
    )
    previous_hash = audit.last_hash()
    record, audit_hash = kernel._evaluate_and_record(call)

    receipt = DecisionReceipt.from_record(
        record=record,
        audit_hash=audit_hash,
        previous_audit_hash=previous_hash,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id=POLICY_BUNDLE_ID,
        policy_hash=DENY_POLICY.version,
        request_id="incident-deny-001",
        validator=PROPOSER_VALIDATOR,
        authority=AUTHORITY,
    )
    if receipt.decision != Decision.DENY.value:
        raise AssertionError(f"expected DENY receipt, got {receipt.decision!r}")

    spy = _SideEffectSpy()
    blocked = False
    try:
        execute_with_receipt(
            tool_fn=spy.port_scan,
            args=dict(call.args),
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action="vulnclaw.port_scan",
            expected_actor=PROPOSER,
            require_signature=False,
        )
    except ReceiptValidationError:
        blocked = True
    # Fail-closed invariant: the gate refused AND the side effect never fired.
    deny_held = blocked and not spy.ran
    if not deny_held:
        raise AssertionError("DENY receipt was executable -- fail-closed invariant broken")
    return receipt, deny_held


def _run_escalate_scenario(
    audit: ChainHashAuditStore,
) -> tuple[DecisionReceipt, DecisionReceipt, bool, bool]:
    """Drive an ESCALATE through the real kernel + human-approval resume bridge.

    Returns ``(escalate_receipt, approval_receipt, auto_execute_blocked,
    resume_executed)``:

    * ``escalate_receipt`` -- a receipt minted straight from the ESCALATE record
      (its decision stays ``"escalate"``; it can NEVER authorize execution).
    * ``approval_receipt`` -- the ALLOW receipt a *distinct human* validator mints
      via :func:`approve_escalation`.
    * ``auto_execute_blocked`` -- True iff resuming with the ESCALATE receipt is
      refused at the gate and the tool never runs.
    * ``resume_executed`` -- True iff, only after human approval, the resume path
      executes the tool through the :class:`GovernedExecutor` gate.
    """
    kernel = Kernel(policy=_EscalateEveryCallPolicy(), audit=audit, actor=PROPOSER)
    spy = _SideEffectSpy()

    @kernel.tool("vulnclaw.exploit")
    def _guarded(**kwargs: Any) -> dict[str, Any]:  # pragma: no cover - must not run on ESCALATE
        raise AssertionError("kernel tool must not run on an ESCALATE dispatch")

    exploit_args = {"target": "192.168.1.100", "cve_id": "CVE-2024-1234", "payload": "id"}

    try:
        kernel.dispatch("vulnclaw.exploit", exploit_args, goal="deliver approved exploit")
    except EscalateError as err:
        escalate_err = err
    else:  # pragma: no cover - dispatch must dead-end on ESCALATE
        raise AssertionError("ESCALATE dispatch did not dead-end -- fail-closed invariant broken")

    pending = escalate_err.pending
    assert pending is not None

    # (a) A receipt minted from the ESCALATE record keeps decision == "escalate"
    #     and must be rejected at the gate -- capture it as evidence.
    escalate_receipt = DecisionReceipt.from_record(
        record=pending.record,
        audit_hash=pending.audit_hash,
        previous_audit_hash="0" * 64,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id=POLICY_BUNDLE_ID,
        policy_hash=pending.record.policy_version,
        request_id="incident-escalate-001",
        validator=HUMAN_APPROVER,
        authority=AUTHORITY,
    )
    if escalate_receipt.decision != Decision.ESCALATE.value:
        raise AssertionError("captured escalate receipt lost its ESCALATE decision")

    reject_executor = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor=PROPOSER,
        require_signature=False,
    )
    reject_executor.register("vulnclaw.exploit", spy.exploit)
    auto_execute_blocked = False
    try:
        resume_with_receipt(reject_executor, pending, escalate_receipt)
    except ReceiptValidationError:
        auto_execute_blocked = True
    auto_execute_blocked = auto_execute_blocked and not spy.ran
    if not auto_execute_blocked:
        msg = "ESCALATE receipt authorized execution -- fail-closed invariant broken"
        raise AssertionError(msg)

    # (b) The governed human-approval path: a DISTINCT human validator approves,
    #     appending the approval as its own audit event; resume executes ONLY
    #     through the GovernedExecutor gate.
    approval_receipt = approve_escalation(
        pending,
        validator=HUMAN_APPROVER,
        authority=AUTHORITY,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id=POLICY_BUNDLE_ID,
        policy_hash=pending.record.policy_version,
        audit=audit,
        request_id="incident-escalate-approval-001",
    )
    if approval_receipt.decision != Decision.ALLOW.value:
        raise AssertionError("human approval did not mint an ALLOW receipt")

    resume_executor = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor=PROPOSER,
        require_signature=False,
    )
    resume_executor.register("vulnclaw.exploit", spy.exploit)
    resume_with_receipt(resume_executor, pending, approval_receipt)
    resume_executed = spy.ran
    if not resume_executed:
        raise AssertionError("approved resume did not execute through the gate")
    return escalate_receipt, approval_receipt, auto_execute_blocked, resume_executed


# --- bundle assembly ---------------------------------------------------------


def _write_bundle(
    out_dir: Path,
    *,
    deny_receipt: DecisionReceipt,
    escalate_receipt: DecisionReceipt,
    approval_receipt: DecisionReceipt,
    audit: ChainHashAuditStore,
    chain: dict[str, Any],
    deny_held: bool,
    auto_execute_blocked: bool,
    resume_executed: bool,
) -> dict[str, Any]:
    """Persist the four member artifacts + a sha256 manifest binding them."""
    out_dir.mkdir(parents=True, exist_ok=True)
    generated_at = _now()

    # 1. incident-summary.json -- mapped to incident-response.md REQUIRED INPUTS
    #    and EXPECTED OUTPUTS.
    incident_summary = {
        "schema": "gove-zone/incident-evidence/incident-summary/v1",
        "generated_at": generated_at,
        "playbook": "ai-governance-research/solution-catalog/incident-response.md",
        "required_inputs": {
            "incident_description": (
                "Game-day drill: a governed pentest agent attempted (1) a scan of "
                "an out-of-scope target and (2) a privileged exploit that requires "
                "named human authority."
            ),
            "affected_people_systems_data": [
                "target host 10.0.0.1 (out-of-scope, scan DENIED before any packet)",
                "target host 192.168.1.100 (exploit ESCALATED, ran only after approval)",
            ],
            "severity_and_risk_tier": {
                "deny_event": "high -- unauthorized-scope action, contained at the gate",
                "escalate_event": "medium -- privileged action gated on human authority",
            },
            "logs_and_receipts": {
                "audit_chain_events": chain["checked"],
                "decision_receipts": ["deny", "escalate", "approval-allow"],
            },
            "current_containment_status": "contained -- no unauthorized side effect executed",
            "required_notification_owners": [
                "security-ops on-call",
                "constitutional council (policy authority)",
            ],
        },
        "expected_outputs": {
            "severity_classification": "DENY=high (contained), ESCALATE=medium (human-gated)",
            "containment_action": (
                "fail-closed execution gate refused the DENY receipt and the "
                "ESCALATE receipt; no side effect ran without a valid ALLOW receipt"
            ),
            "evidence_preservation_plan": (
                "durable sha256-manifested bundle (this directory); audit chain is "
                "tamper-evident and re-verifiable offline"
            ),
            "remediation_owner_and_timeline": (
                "security-ops on-call owns follow-up; re-scope the target list before "
                "re-enabling the agent"
            ),
            "retest_and_reactivation_criteria": (
                "re-run this drill green (chain verifies, DENY non-executable, "
                "ESCALATE resume-only) before reactivating the agent"
            ),
            "lessons_learned_record": (
                "see verification-summary.md; the gate -- not the agent -- is the control point"
            ),
        },
        "fail_closed_invariants": {
            "deny_receipt_non_executable": deny_held,
            "escalate_receipt_cannot_auto_execute": auto_execute_blocked,
            "resume_executes_only_after_human_approval": resume_executed,
        },
    }

    # 2. decision-receipts.json -- the captured receipts (hash-bound evidence).
    decision_receipts = {
        "schema": "gove-zone/incident-evidence/decision-receipts/v1",
        "generated_at": generated_at,
        "deny_receipt": deny_receipt.to_dict(),
        "escalate_receipt": escalate_receipt.to_dict(),
        "approval_receipt": approval_receipt.to_dict(),
    }

    # 3. audit-chain.json -- the full tamper-evident chain + its verification.
    audit_chain = {
        "schema": "gove-zone/incident-evidence/audit-chain/v1",
        "generated_at": generated_at,
        "events": list(audit.iter_events()),
        "verification": chain,
    }

    # 4. verification-summary.md -- human-readable auditor summary.
    verification_md = _render_summary(
        generated_at=generated_at,
        chain=chain,
        deny_receipt=deny_receipt,
        escalate_receipt=escalate_receipt,
        approval_receipt=approval_receipt,
        deny_held=deny_held,
        auto_execute_blocked=auto_execute_blocked,
        resume_executed=resume_executed,
    )

    members = {
        "incident-summary.json": incident_summary,
        "decision-receipts.json": decision_receipts,
        "audit-chain.json": audit_chain,
    }
    for name, payload in members.items():
        _dump_json(out_dir / name, payload)
    (out_dir / "verification-summary.md").write_text(verification_md, encoding="utf-8")

    member_names = [*members.keys(), "verification-summary.md"]

    # manifest.json binds every member by sha256. Like proofpack, the manifest
    # cannot carry its own digest (self-reference), so it is NOT a member of
    # itself -- an auditor recomputes each member's digest and compares.
    manifest = {
        "schema": "gove-zone/incident-evidence/manifest/v1",
        "generated_at": generated_at,
        "playbook": "ai-governance-research/solution-catalog/incident-response.md",
        "runbook": "packages/gove-zone/docs/gameday-runbook.md",
        "audit_chain_valid": bool(chain["valid"]),
        "audit_chain_events": chain["checked"],
        "members": {
            name: {
                "sha256": _sha256_file(out_dir / name),
                "bytes": (out_dir / name).stat().st_size,
            }
            for name in member_names
        },
    }
    _dump_json(out_dir / "manifest.json", manifest)
    return manifest


def _render_summary(
    *,
    generated_at: str,
    chain: dict[str, Any],
    deny_receipt: DecisionReceipt,
    escalate_receipt: DecisionReceipt,
    approval_receipt: DecisionReceipt,
    deny_held: bool,
    auto_execute_blocked: bool,
    resume_executed: bool,
) -> str:
    ok = "PASS" if (deny_held and auto_execute_blocked and resume_executed) else "FAIL"
    lines = [
        "# Game-Day Incident Evidence -- Verification Summary",
        "",
        f"- Generated: {generated_at}",
        f"- Overall: **{ok}**",
        "- Playbook: `ai-governance-research/solution-catalog/incident-response.md`",
        "- Runbook: `packages/gove-zone/docs/gameday-runbook.md`",
        "",
        "## Fail-closed outcomes (expected outputs)",
        "",
        "| Event | Decision | Fail-closed invariant | Held |",
        "|---|---|---|---|",
        f"| Out-of-scope scan | `{deny_receipt.decision}` | "
        f"DENY receipt is non-executable | {'yes' if deny_held else 'NO'} |",
        f"| Privileged exploit | `{escalate_receipt.decision}` | "
        f"ESCALATE receipt cannot auto-execute | {'yes' if auto_execute_blocked else 'NO'} |",
        f"| Exploit (after approval) | `{approval_receipt.decision}` | "
        f"resume executes ONLY via the gate after a distinct human approval | "
        f"{'yes' if resume_executed else 'NO'} |",
        "",
        "## Evidence preservation",
        "",
        f"- Tamper-evident audit chain: **{chain['checked']} events**, "
        f"valid = **{chain['valid']}**.",
        "- Every member artifact is bound by sha256 in `manifest.json`; recompute "
        "each digest to detect tampering.",
        f"- Approval receipt id: `{approval_receipt.receipt_id}` "
        f"(validator `{approval_receipt.validator_id}`, distinct from proposer "
        f"`{approval_receipt.actor}`).",
        "",
        "## Lessons learned",
        "",
        "- The **gate**, not the agent, is the control point: no valid ALLOW "
        "receipt, no side effect.",
        "- ESCALATE dead-ends until a *named human* (MACI: approver != proposer) "
        "authorizes it; the original ESCALATE decision can never authorize "
        "execution.",
        "- Re-run this drill green before reactivating any governed pentest agent.",
        "",
    ]
    return "\n".join(lines)


# --- entry point -------------------------------------------------------------


def run_drill(out_dir: Path) -> dict[str, Any]:
    """Run both scenarios, verify the chain, and persist the bundle.

    Returns the single-line status payload (also printed by :func:`main`).
    """
    workdir = Path(tempfile.mkdtemp(prefix="gove-zone-gameday-"))
    audit = ChainHashAuditStore(workdir / "audit.jsonl")

    deny_receipt, deny_held = _run_deny_scenario(audit)
    (
        escalate_receipt,
        approval_receipt,
        auto_execute_blocked,
        resume_executed,
    ) = _run_escalate_scenario(audit)

    chain = audit.verify_chain()
    if not chain["valid"]:
        raise AssertionError(f"audit chain failed to verify: {chain['failures']}")

    manifest = _write_bundle(
        out_dir,
        deny_receipt=deny_receipt,
        escalate_receipt=escalate_receipt,
        approval_receipt=approval_receipt,
        audit=audit,
        chain=chain,
        deny_held=deny_held,
        auto_execute_blocked=auto_execute_blocked,
        resume_executed=resume_executed,
    )

    manifest_sha256 = _sha256_file(out_dir / "manifest.json")
    return {
        "status": "pass",
        "bundle_dir": str(out_dir),
        "manifest_sha256": manifest_sha256,
        "members": len(manifest["members"]),
        "deny_blocked": deny_held,
        "escalate_auto_execute_blocked": auto_execute_blocked,
        "resume_executed_after_approval": resume_executed,
        "chain_valid": bool(chain["valid"]),
        "chain_events": chain["checked"],
    }


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        out_dir = Path(args[0]).expanduser().resolve()
    else:
        out_dir = Path(tempfile.mkdtemp(prefix="gove-zone-gameday-bundle-"))

    summary = run_drill(out_dir)
    # Single-line JSON status summary for CI consumption.
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
