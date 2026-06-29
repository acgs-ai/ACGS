"""A2A receipt-gated delegation — agent→agent delegation, proven end to end.

    No valid Decision Receipt for THIS delegating actor, no remote side effect.

Run it (from the monorepo root; signed path needs the crypto extra):

    uv run --package gove-zone --extra crypto python \\
        packages/gove-zone/examples/a2a_governed_delegation/demo.py

This is an executable proof, not a slide. Agent A (``planner``) delegates
``contract.redline`` to a remote Agent B (``legal-svc``) across a *simulated* A2A
boundary. There is NO real ``a2a`` SDK dependency — this mirrors the A2A
delegation contract (client agent → AgentCard-identified remote agent →
delegated task) the same way the kernel demos mirror their integrations. It is a
mechanism demonstration, not a compliance or production-readiness claim.

Each scenario asserts its expected outcome; any violation exits non-zero. The
fail-closed scenarios prove the remote handler (the spy) never ran.

Trust assumption (load-bearing): ``authenticated_delegator`` MUST come from a
transport authentication mechanism (mutual TLS / signed JWT / A2A handshake).
This demo passes it as a literal to model the boundary; the adapter binds the
receipt to it but does not itself authenticate it.

Status: foundational / Alpha. Proves the local delegation invariant. NOT a
production, compliance, or regulator-ready certification.
"""

from __future__ import annotations

import dataclasses
import sys
import tempfile
from pathlib import Path
from typing import Any

from gove_zone import (
    ChainHashAuditStore,
    Ed25519Signer,
    RuleSetPolicy,
    TenantPolicyStore,
    Validator,
)
from gove_zone.a2a import (
    A2ADelegationError,
    AgentCard,
    DelegatedTask,
    GovernedA2AServer,
    mint_delegation,
)

TENANT = "tenant-legal"
BOUNDARY = "a2a-remote-sandbox"
DELEGATOR = "planner"  # Agent A — the delegating principal (receipt proposer)
VALIDATOR = Validator("legal-council")  # distinct MACI validating principal
AUTHORITY = "tenant-legal/redline-grant"
ACTION = "contract.redline"


class RemoteHandler:
    """Agent B's real side effect. Records whether it actually ran."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def redline(self, **kwargs: Any) -> str:
        self.calls.append(kwargs)
        return f"REDLINED fields={kwargs.get('fields')!r}"


def _ok(msg: str) -> None:
    print(f"  \033[32m✓\033[0m {msg}")


def _fail(msg: str) -> None:
    print(f"  \033[31m✗ INVARIANT VIOLATED: {msg}\033[0m")
    raise SystemExit(1)


def _task(fields: list[str]) -> DelegatedTask:
    return DelegatedTask(action=ACTION, args={"fields": fields}, declared_goal="redline contract")


def main() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="gove-zone-a2a-demo-"))
    store = TenantPolicyStore(workdir / "policies")
    audit = ChainHashAuditStore(workdir / "audit.jsonl")
    # A bundle that denies shell.exec but lets contract.redline through (default ALLOW).
    store.store_bundle(
        TENANT,
        RuleSetPolicy.from_dict(
            {
                "id": "policy-legal",
                "rules": [{"id": "R1", "effect": "deny", "tools": ["shell.exec"]}],
            }
        ),
    )

    card = AgentCard(agent_id="legal-svc", execution_boundary=BOUNDARY, capabilities=(ACTION,))

    print("\ngove-zone — A2A receipt-gated delegation proof")
    print("Invariant: No valid receipt for THIS delegating actor, no remote side effect.\n")

    # --- HAPPY PATH: signed receipt bound to `planner`, B runs the action. ---
    print("[1] ALLOWED: signed delegation from planner executes on the remote agent")
    signing_key = Ed25519Signer.generate()
    verify_key = Ed25519Signer.from_public_bytes(signing_key.public_bytes())
    receipt = mint_delegation(
        store=store,
        audit_store=audit,
        delegating_actor=DELEGATOR,
        task=_task(["price"]),
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        request_id="req-redline-1",
        validator=VALIDATOR,
        authority=AUTHORITY,
        signer=signing_key,
    )
    handler = RemoteHandler()
    # Signed by default (require_signature defaults to True).
    server = GovernedA2AServer(card=card, tenant_id=TENANT, verifier=verify_key)
    server.register(ACTION, handler.redline)
    result = server.accept_delegation(
        authenticated_delegator=DELEGATOR,  # from the transport handshake
        task=_task(["price"]),
        receipt=receipt,
    )
    if not handler.calls:
        _fail("valid signed delegation did not reach the remote handler")
    _ok(f"remote handler ran → {result!r}")
    print(f"      receipt: actor={receipt.actor!r} decision={receipt.decision!r} "
          f"alg={receipt.signature_algorithm!r} key={receipt.signing_key_id[:8]}…")

    # --- FAIL-CLOSED 1: no receipt. ---
    print("[2] BLOCKED: no receipt")
    handler = RemoteHandler()
    server = GovernedA2AServer(card=card, tenant_id=TENANT, require_signature=False)
    server.register(ACTION, handler.redline)
    try:
        server.accept_delegation(
            authenticated_delegator=DELEGATOR, task=_task(["price"]), receipt=None
        )
        _fail("missing receipt reached the remote handler")
    except A2ADelegationError as exc:
        if handler.calls:
            _fail("remote handler ran despite missing receipt")
        _ok(f"blocked: {exc}")

    # --- FAIL-CLOSED 2: wrong delegator (receipt for planner; transport says impostor). ---
    print("[3] BLOCKED: receipt minted for planner, transport authenticates 'impostor'")
    unsigned = mint_delegation(
        store=store, audit_store=audit, delegating_actor=DELEGATOR, task=_task(["price"]),
        tenant_id=TENANT, execution_boundary=BOUNDARY, request_id="req-redline-3",
        validator=VALIDATOR, authority=AUTHORITY,
    )
    handler = RemoteHandler()
    server = GovernedA2AServer(card=card, tenant_id=TENANT, require_signature=False)
    server.register(ACTION, handler.redline)
    try:
        server.accept_delegation(
            authenticated_delegator="impostor", task=_task(["price"]), receipt=unsigned
        )
        _fail("receipt was honored for an unauthenticated delegator")
    except A2ADelegationError as exc:
        if handler.calls:
            _fail("remote handler ran for the wrong delegator")
        _ok(f"blocked: {exc}")

    # --- FAIL-CLOSED 3: substituted args (receipt for [price]; asked to run more). ---
    print("[4] BLOCKED: receipt for {fields:[price]}, remote asked to run [price,liability]")
    handler = RemoteHandler()
    server = GovernedA2AServer(card=card, tenant_id=TENANT, require_signature=False)
    server.register(ACTION, handler.redline)
    try:
        server.accept_delegation(
            authenticated_delegator=DELEGATOR, task=_task(["price", "liability"]), receipt=unsigned
        )
        _fail("substituted args reached the remote handler")
    except A2ADelegationError as exc:
        if handler.calls:
            _fail("remote handler ran with substituted args")
        _ok(f"blocked: {exc}")

    # --- FAIL-CLOSED 4: tampered/forged signed receipt. ---
    print("[5] BLOCKED: tampered signed receipt (signature attests the original hash)")
    forged = dataclasses.replace(receipt, declared_goal="exfiltrate")
    forged = dataclasses.replace(forged, receipt_hash=forged.compute_hash())
    handler = RemoteHandler()
    server = GovernedA2AServer(card=card, tenant_id=TENANT, verifier=verify_key)
    server.register(ACTION, handler.redline)
    try:
        server.accept_delegation(
            authenticated_delegator=DELEGATOR, task=_task(["price"]), receipt=forged
        )
        _fail("forged receipt reached the remote handler")
    except A2ADelegationError as exc:
        if handler.calls:
            _fail("remote handler ran despite a forged receipt")
        _ok(f"blocked: {exc} — no private key, no valid signature")

    # --- AUDIT: every minted decision left tamper-evident evidence. ---
    print("[6] Audit chain verified for every delegation decision")
    chain = audit.verify_chain()
    if not chain["valid"]:
        _fail(f"audit chain failed verification: {chain['failures']}")
    _ok(f"audit chain verified: {chain['checked']} tamper-evident events")

    print(
        "\n\033[32mAll invariants held. "
        "No valid receipt for this delegator, no remote side effect.\033[0m"
    )
    print(f"(audit log: {audit.path})\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
