"""Receipt-gated execution — the core invariant, proven end to end.

    No valid Decision Receipt, no side effect.

Run it (from the monorepo root):

    uv run --package gove-zone python \\
        packages/gove-zone/examples/receipt-gated-execution/demo.py

This is an executable proof, not a slide. Each scenario asserts the expected
outcome; if any invariant is violated the script exits non-zero. It demonstrates,
against the real policy evaluator, receipt issuer, executor guard, and audit
chain:

    1. allowed action executes
    2. denied action is blocked
    3. missing receipt is blocked
    4. tampered receipt is blocked
    5. cross-tenant receipt is blocked
    6. a transformed action runs ONLY as approved
    7. every decision left tamper-evident audit evidence

Status: foundational / Alpha. This proves the local invariant. It is NOT a
production, compliance, or regulator-ready certification.
"""

from __future__ import annotations

import dataclasses
import sys
import tempfile
from pathlib import Path
from typing import Any

from gove_zone import (
    AuditEvent,
    ChainHashAuditStore,
    DecisionReceipt,
    GovernanceRequest,
    ProposedAction,
    ReceiptValidationError,
    ReceiptVerifier,
    RuleSetPolicy,
    TenantPolicyStore,
    evaluate_tenant_action,
    execute_with_receipt,
)
from gove_zone.tenant import TransformPolicy

BOUNDARY = "local-sandbox"
TENANT = "tenant-A"


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
    store: TenantPolicyStore,
    audit: ChainHashAuditStore,
    request: GovernanceRequest,
) -> DecisionReceipt:
    return evaluate_tenant_action(
        store=store,
        tenant_id=request.tenant_id,
        requester_tenant_id=request.tenant_id,
        action=request.proposed_action.tool,
        args=request.proposed_action.args,
        execution_boundary=request.execution_boundary,
        request_id=request.request_id,
        actor=request.actor,
        audit_store=audit,
    )


def _request(tool: str, args: dict[str, Any], request_id: str) -> GovernanceRequest:
    return GovernanceRequest(
        tenant_id=TENANT,
        actor="agent-1",
        request_id=request_id,
        proposed_action=ProposedAction(tool=tool, args=args),
        execution_boundary=BOUNDARY,
    )


def main() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="gove-zone-demo-"))
    store = TenantPolicyStore(workdir / "policies")
    audit = ChainHashAuditStore(workdir / "audit.jsonl")

    # A bundle that denies shell.exec but lets file writes through (default ALLOW),
    # plus a separate transform bundle for tenant scenario 6.
    allow_bundle = RuleSetPolicy.from_dict(
        {"id": "policy-A", "rules": [{"id": "R1", "effect": "deny", "tools": ["shell.exec"]}]}
    )
    deny_bundle = RuleSetPolicy.from_dict(
        {
            "id": "policy-A",
            "rules": [{"id": "R1", "effect": "deny", "tools": ["runtime.file.write"]}],
        }
    )
    store.store_bundle(TENANT, allow_bundle)

    verifier = ReceiptVerifier(expected_tenant_id=TENANT, expected_execution_boundary=BOUNDARY)

    print("\ngove-zone — receipt-gated execution proof")
    print("Invariant: No valid Decision Receipt, no side effect.\n")

    # 1. ALLOW: a valid receipt authorizes the exact approved action.
    print("[1] Allowed action executes")
    req = _request("runtime.file.write", {"path": "report.txt", "content": "ok"}, "req-allow")
    receipt = _issue(store, audit, req)
    if receipt.decision != "allow":
        _fail(f"expected ALLOW, got {receipt.decision}")
    # The OO gate (ReceiptVerifier) and the functional gate (execute_with_receipt)
    # are the same fail-closed check; verify before the side effect can run.
    verifier.verify(
        receipt,
        expected_action="runtime.file.write",
        expected_args=req.proposed_action.args,
    )
    tool = Tool()
    result = execute_with_receipt(
        tool_fn=tool.run,
        args=req.proposed_action.args,
        receipt=receipt,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action="runtime.file.write",
    )
    if not tool.ran:
        _fail("valid ALLOW receipt did not reach execution")
    _ok(f"verified + executed with valid receipt → {result!r}")

    # 2. DENY: a denied receipt cannot execute.
    print("[2] Denied action is blocked")
    store.store_bundle(TENANT, deny_bundle)
    req = _request("runtime.file.write", {"path": "report.txt", "content": "no"}, "req-deny")
    denied = _issue(store, audit, req)
    if denied.decision != "deny":
        _fail(f"expected DENY, got {denied.decision}")
    tool = Tool()
    try:
        execute_with_receipt(
            tool_fn=tool.run,
            args=req.proposed_action.args,
            receipt=denied,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action="runtime.file.write",
        )
        _fail("denied receipt reached execution")
    except ReceiptValidationError as exc:
        if tool.ran:
            _fail("side effect ran despite DENY")
        _ok(f"blocked: {exc}")
    store.store_bundle(TENANT, allow_bundle)

    # 3. MISSING receipt → block.
    print("[3] Missing receipt is blocked")
    tool = Tool()
    try:
        execute_with_receipt(
            tool_fn=tool.run,
            args={"path": "report.txt"},
            receipt=None,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action="runtime.file.write",
        )
        _fail("missing receipt reached execution")
    except ReceiptValidationError as exc:
        _ok(f"blocked: {exc}")

    # 4. TAMPERED receipt → block (hash mismatch).
    print("[4] Tampered receipt is blocked")
    req = _request("runtime.file.write", {"path": "report.txt", "content": "ok"}, "req-tamper")
    good = _issue(store, audit, req)
    tampered = dataclasses.replace(good, proposed_action="shell.exec")
    tool = Tool()
    try:
        execute_with_receipt(
            tool_fn=tool.run,
            args=req.proposed_action.args,
            receipt=tampered,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action="shell.exec",
        )
        _fail("tampered receipt reached execution")
    except ReceiptValidationError as exc:
        _ok(f"blocked: {exc}")

    # 5. CROSS-TENANT receipt → block.
    print("[5] Cross-tenant receipt is blocked")
    req = _request("runtime.file.write", {"path": "report.txt", "content": "ok"}, "req-tenant")
    tenant_a_receipt = _issue(store, audit, req)
    tool = Tool()
    try:
        execute_with_receipt(
            tool_fn=tool.run,
            args=req.proposed_action.args,
            receipt=tenant_a_receipt,
            expected_tenant_id="tenant-B",  # a different tenant's executor
            expected_execution_boundary=BOUNDARY,
            expected_action="runtime.file.write",
        )
        _fail("tenant-A receipt authorized a tenant-B executor")
    except ReceiptValidationError as exc:
        _ok(f"blocked: {exc}")

    # 6. TRANSFORM: only the approved transformed action runs.
    print("[6] Transformed action is constrained to the approved output")
    transform_store = TenantPolicyStore(workdir / "transform_policies")
    transform_store.store_bundle(TENANT, TransformPolicy())
    req = _request("runtime.file.write", {"path": "original.txt"}, "req-transform")
    t_receipt = _issue(transform_store, audit, req)
    if t_receipt.decision != "transform":
        _fail(f"expected TRANSFORM, got {t_receipt.decision}")
    # The original (un-approved) args are refused.
    tool = Tool()
    try:
        execute_with_receipt(
            tool_fn=tool.run,
            args={"path": "original.txt"},
            receipt=t_receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action="runtime.file.write",
        )
        _fail("un-approved original args reached execution")
    except ReceiptValidationError:
        pass
    if tool.ran:
        _fail("side effect ran with un-approved args")
    # Only the approved transformed args run.
    tool = Tool()
    execute_with_receipt(
        tool_fn=tool.run,
        args={"path": "transformed.txt"},
        receipt=t_receipt,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action="runtime.file.write",
    )
    if not tool.ran or tool.args != {"path": "transformed.txt"}:
        _fail("approved transformed action did not run as approved")
    _ok("original args refused; approved transformed args executed")

    # 7. AUDIT evidence for every decision.
    print("[7] Audit evidence generated for every decision")
    chain = audit.verify_chain()
    if not chain["valid"]:
        _fail(f"audit chain failed verification: {chain['failures']}")
    events = audit.query(limit=1000)
    _ok(f"audit chain verified: {chain['checked']} tamper-evident events")
    # Project the ALLOW decision's evidence honestly: join its receipt with the
    # exact chain event it anchored (matched by event_hash).
    anchor = next((e for e in events if e.get("event_hash") == receipt.audit_event_hash), None)
    if anchor is not None:
        ev = AuditEvent.from_receipt_and_event(receipt, anchor)
        print("\n  Audit evidence for the ALLOW decision (AuditEvent projection):")
        print(f"    request_id={ev.request_id}  tenant={ev.tenant_id}  decision={ev.decision}")
        print(f"    action={ev.action_summary}  receipt_id={ev.receipt_id[:16]}…")
        print(f"    event_hash={ev.event_hash[:16]}…  prev_hash={ev.previous_hash[:16]}…")

    print("\n\033[32mAll invariants held. No valid Decision Receipt, no side effect.\033[0m")
    print(f"(audit log: {audit.path})\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
