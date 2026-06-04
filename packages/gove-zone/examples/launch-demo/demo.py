"""gove-zone launch demo — the five-beat story, proven end to end.

    No valid Decision Receipt, no side effect.

Run it (from the monorepo root):

    uv run --package gove-zone python \\
        packages/gove-zone/examples/launch-demo/demo.py

This is the launch narrative as an *executable* proof, not a slide. Five beats,
each asserted against the real policy evaluator, receipt issuer, executor gate,
audit chain, and replay engine. Any violated invariant exits non-zero.

    1. ALLOW   — a safe action runs under a valid receipt.
    2. DENY    — an unsafe action is blocked *before* the side effect fires.
    3. RECEIPT — show the real Decision Receipt that authorized beat 1.
    4. AUDIT   — every decision left a tamper-evident, hash-chained record.
    5. REPLAY  — re-run the recorded decisions against policy; they still match.

Status: foundational / Alpha (0.1.0.dev0). This proves the LOCAL invariant.
It is NOT a production, compliance, or regulator-ready certification. The demo
runs UNSIGNED by default (receipts are ``unsigned_local``); Ed25519 signing is
opt-in (see SECURITY.md). The registered "tool" is a stand-in — gove-zone decides
*whether* and *with which arguments* it runs; it does not sandbox the side effect.
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
    replay_call,
)
from gove_zone.tool import ToolCall, normalize_path_context

TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
# A distinct MACI validating principal — never the proposer ("agent-1").
VALIDATOR = Validator("constitutional-council")
# The invoking principal's AUTHENTICATED identity, supplied to the gate as
# expected_actor from runtime context — never from the request body or receipt.
CALLER_IDENTITY = "agent-1"
AUTHORITY = "tenant-A/write-grant"

# One bundle for the whole demo: writes pass (default ALLOW), shell.exec is denied.
POLICY = RuleSetPolicy.from_dict(
    {"id": "policy-A", "rules": [{"id": "R1", "effect": "deny", "tools": ["shell.exec"]}]}
)


class Tool:
    """A stand-in high-risk side effect. Records whether it actually ran."""

    def __init__(self) -> None:
        self.ran = False
        self.args: dict[str, Any] | None = None

    def run(self, **kwargs: Any) -> str:
        self.ran = True
        self.args = kwargs
        return "SIDE EFFECT EXECUTED"


def _ok(msg: str) -> None:
    print(f"  \033[32m✓\033[0m {msg}")


def _fail(msg: str) -> None:
    print(f"  \033[31m✗ INVARIANT VIOLATED: {msg}\033[0m")
    raise SystemExit(1)


def _issue(
    store: TenantPolicyStore, audit: ChainHashAuditStore, tool: str, args: dict[str, Any], rid: str
) -> DecisionReceipt:
    req = GovernanceRequest(
        tenant_id=TENANT,
        actor="agent-1",
        request_id=rid,
        proposed_action=ProposedAction(tool=tool, args=args),
        execution_boundary=BOUNDARY,
    )
    return evaluate_tenant_action(
        store=store,
        tenant_id=req.tenant_id,
        requester_tenant_id=req.tenant_id,
        action=req.proposed_action.tool,
        args=req.proposed_action.args,
        execution_boundary=req.execution_boundary,
        request_id=req.request_id,
        actor=req.actor,
        validator=VALIDATOR,
        authority=AUTHORITY,
        audit_store=audit,
    )


def main() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="gove-zone-launch-demo-"))
    store = TenantPolicyStore(workdir / "policies")
    store.store_bundle(TENANT, POLICY)
    audit = ChainHashAuditStore(workdir / "audit.jsonl")

    print("\n\033[1mgove-zone — launch demo\033[0m")
    print("Invariant: No valid Decision Receipt, no side effect.\n")

    # --- Beat 1: ALLOW — a safe action runs under a valid receipt. ----------
    print("[1] A safe action runs — under a valid receipt")
    allow_args = {"path": "report.txt", "content": "quarterly numbers"}
    allow_receipt = _issue(store, audit, "runtime.file.write", allow_args, "req-allow")
    if allow_receipt.decision != "allow":
        _fail(f"expected ALLOW, got {allow_receipt.decision}")
    tool = Tool()
    result = execute_with_receipt(
        tool_fn=tool.run,
        args=allow_args,
        receipt=allow_receipt,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action="runtime.file.write",
        expected_actor=CALLER_IDENTITY,
    )
    if not tool.ran:
        _fail("valid ALLOW receipt did not reach execution")
    _ok(f"safe write executed → {result!r}")

    # --- Beat 2: DENY — an unsafe action is blocked BEFORE the side effect. --
    print("\n[2] An unsafe action is blocked — before the side effect fires")
    deny_args = {"cmd": "rm -rf /"}
    deny_receipt = _issue(store, audit, "shell.exec", deny_args, "req-deny")
    if deny_receipt.decision != "deny":
        _fail(f"expected DENY, got {deny_receipt.decision}")
    tool = Tool()
    try:
        execute_with_receipt(
            tool_fn=tool.run,
            args=deny_args,
            receipt=deny_receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action="shell.exec",
            expected_actor=CALLER_IDENTITY,
        )
        _fail("denied action reached execution")
    except ReceiptValidationError as exc:
        if tool.ran:
            _fail("side effect ran despite DENY")
        _ok(f"shell.exec blocked, side effect never fired: {exc}")

    # --- Beat 3: RECEIPT — show the real object that authorized beat 1. ------
    print("\n[3] The Decision Receipt that authorized the safe action")
    r = allow_receipt
    print(f"    decision        : {r.decision}")
    print(f"    tenant / actor  : {TENANT} / {r.actor}")
    print(f"    validator       : {VALIDATOR.validator_id} (≠ proposer — MACI)")
    print("    action          : runtime.file.write")
    print(f"    argument_hash   : {r.argument_hash[:24]}…  (binds the exact args)")
    print(f"    receipt_hash    : {r.receipt_hash[:24]}…")
    print(f"    signature       : {r.signature} ({r.signature_algorithm})")
    _ok("a receipt authorizes a specific action with specific arguments")

    # --- Beat 4: AUDIT — tamper-evident, hash-chained record of everything. --
    print("\n[4] Every decision left tamper-evident audit evidence")
    chain = audit.verify_chain()
    if not chain["valid"]:
        _fail(f"audit chain failed verification: {chain['failures']}")
    _ok(f"audit chain verified: {chain['checked']} hash-chained events, 0 failures")

    # --- Beat 5: REPLAY — re-run recorded decisions against policy. ----------
    print("\n[5] Replay — the record matches what the policy says should have happened")
    allow_call = ToolCall(
        name="runtime.file.write",
        args=allow_args,
        actor="agent-1",
        path=normalize_path_context(allow_args.get("path", ())),
    )
    allow_replay = replay_call(allow_call, expected_decision=Decision.ALLOW, policy=POLICY)
    if not allow_replay.matches:
        _fail(f"ALLOW replay mismatch: {allow_replay.to_dict()}")
    _ok(f"ALLOW replays to ALLOW (args + policy agree): matches={allow_replay.matches}")

    deny_call = ToolCall(name="shell.exec", args=deny_args, actor="agent-1")
    deny_replay = replay_call(deny_call, expected_decision=Decision.DENY, policy=POLICY)
    if not deny_replay.matches:
        _fail(f"DENY replay mismatch: {deny_replay.to_dict()}")
    _ok(f"DENY replays to DENY: matches={deny_replay.matches}")

    print("\n\033[32mAll five beats held. No valid Decision Receipt, no side effect.\033[0m")
    print(f"(audit log: {audit.path})\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
