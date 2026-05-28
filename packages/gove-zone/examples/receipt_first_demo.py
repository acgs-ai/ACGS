"""Minimal receipt-first governed execution demo.

Run from the repository root:

    PYTHONPATH=packages/gove-zone/src python3 packages/gove-zone/examples/receipt_first_demo.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from gove_zone import (
    BoundaryPolicy,
    ChainHashAuditStore,
    GovernanceEngine,
    GovernanceRequest,
    GovernedExecutor,
    PolicyBundleBinding,
    ReceiptVerificationError,
    StaticPolicyBundleRegistry,
    sha256_json,
)


def request(body: str) -> GovernanceRequest:
    return GovernanceRequest(
        request_id="req-demo-001",
        tenant_id="tenant-alpha",
        actor={"id": "demo-agent", "role": "agent"},
        subject={"id": "demo-workflow", "type": "agentic_workflow"},
        proposed_action={"tool": "message.send", "args": {"body": body}},
        declared_goal="send a governed status update",
        execution_boundary={"environment": "local", "network": "disabled"},
        policy_bundle_id="bundle-alpha",
    )


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="gove-zone-receipt-demo-"))
    audit = ChainHashAuditStore(tmp / "audit.jsonl")
    policy_hash = sha256_json({"bundle": "bundle-alpha", "rule": "deny secret bodies"})
    registry = StaticPolicyBundleRegistry(
        [
            PolicyBundleBinding(
                tenant_id="tenant-alpha",
                policy_bundle_id="bundle-alpha",
                policy_version="alpha/v1",
                constitutional_hash=policy_hash,
                policy=BoundaryPolicy(forbidden_keywords=["secret"], rule_id="DEMO-BOUNDARY"),
            )
        ]
    )
    engine = GovernanceEngine(policy_registry=registry, audit=audit)
    executor = GovernedExecutor()

    @executor.tool("message.send")
    def send(body: str) -> str:
        return f"sent:{body}"

    allowed = engine.precheck(request("hello"))
    print("ALLOW")
    print("  result       =", executor.execute("message.send", {"body": "hello"}, receipt=allowed))
    print("  receipt_id   =", allowed.receipt_id)
    print("  receipt_hash =", allowed.receipt_hash[:16])

    denied = engine.precheck(request("secret token"))
    print("DENY")
    try:
        executor.execute("message.send", {"body": "secret token"}, receipt=denied)
    except ReceiptVerificationError as exc:
        print("  blocked      =", exc)
        print("  decision     =", denied.decision.name)

    print("MISSING RECEIPT")
    try:
        executor.execute("message.send", {"body": "hello"}, receipt=None)
    except ReceiptVerificationError as exc:
        print("  blocked      =", exc)

    chain = audit.verify_chain()
    print("AUDIT")
    print("  valid        =", chain["valid"])
    print("  events       =", chain["checked"])
    print("  path         =", audit.path)


if __name__ == "__main__":
    main()
