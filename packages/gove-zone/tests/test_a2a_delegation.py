"""Wave 3 (Plug) — A2A receipt-gated delegation tests.

Drives ``GovernedA2AServer.accept_delegation(...)`` (the wired handler), NOT
``execute_with_receipt`` directly (handler-wiring rule). A spy executor records
every call; each fail-closed test asserts BOTH the raise AND that the spy's call
list stayed empty — the un-run side effect is the real proof.

All tenants here are the SAME (constraint 7, same-tenant delegation only). These
tests exercise ALLOW decisions, so the argument-binding path (receipt.py ALLOW
``argument_hash`` check) is what guards arg substitution; TRANSFORM binding is
NOT exercised here and is not claimed.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

from gove_zone.a2a import (
    A2ADelegationError,
    AgentCard,
    DelegatedTask,
    GovernedA2AServer,
    mint_delegation,
)
from gove_zone.audit import ChainHashAuditStore
from gove_zone.errors import ReceiptValidationError
from gove_zone.policy import RuleSetPolicy
from gove_zone.receipt import Validator
from gove_zone.signing import Ed25519Signer
from gove_zone.tenant import TenantPolicyStore

TENANT = "tenant-legal"
BOUNDARY = "a2a-remote-sandbox"
DELEGATOR = "planner"
VALIDATOR = Validator("legal-council")
AUTHORITY = "tenant-legal/redline-grant"
ACTION = "contract.redline"


class SpyExecutor:
    """Records every invocation; an empty ``calls`` list proves no side effect."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def run(self, **kwargs: Any) -> str:
        self.calls.append(kwargs)
        return "REDLINE COMPLETE"


def _setup(tmp_path: Path) -> tuple[TenantPolicyStore, ChainHashAuditStore]:
    """A store with a same-tenant ALLOW bundle (denies only shell.exec) + audit."""
    store = TenantPolicyStore(tmp_path / "policies")
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    bundle = RuleSetPolicy.from_dict(
        {"id": "policy-legal", "rules": [{"id": "R1", "effect": "deny", "tools": ["shell.exec"]}]}
    )
    store.store_bundle(TENANT, bundle)
    return store, audit


def _card() -> AgentCard:
    return AgentCard(
        agent_id="legal-svc",
        execution_boundary=BOUNDARY,
        capabilities=(ACTION,),
    )


def _task(fields: list[str]) -> DelegatedTask:
    return DelegatedTask(action=ACTION, args={"fields": fields}, declared_goal="redline contract")


# --- The load-bearing guard: written FIRST, must be RED on the wrong wiring. ---


def test_delegation_wrong_delegator_fails_closed(tmp_path: Path) -> None:
    """Receipt minted for DELEGATOR, transport authenticates a DIFFERENT agent.

    This is the single most likely implementation bug: passing
    ``expected_actor=receipt.actor`` instead of the authenticated transport
    identity. With that wrong wiring no exception is raised and the spy runs —
    so this test must exist and go RED before the implementation is correct.
    """
    store, audit = _setup(tmp_path)
    receipt = mint_delegation(
        store=store,
        audit_store=audit,
        delegating_actor=DELEGATOR,
        task=_task(["price"]),
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        request_id="req-wrong-delegator",
        validator=VALIDATOR,
        authority=AUTHORITY,
    )

    spy = SpyExecutor()
    server = GovernedA2AServer(card=_card(), tenant_id=TENANT, require_signature=False)
    server.register(ACTION, spy.run)

    with pytest.raises(A2ADelegationError):
        server.accept_delegation(
            authenticated_delegator="impostor",
            task=_task(["price"]),
            receipt=receipt,
        )
    assert spy.calls == []


def test_delegation_allows_authenticated_delegator_and_runs(tmp_path: Path) -> None:
    store, audit = _setup(tmp_path)
    receipt = mint_delegation(
        store=store,
        audit_store=audit,
        delegating_actor=DELEGATOR,
        task=_task(["price"]),
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        request_id="req-allow",
        validator=VALIDATOR,
        authority=AUTHORITY,
    )

    spy = SpyExecutor()
    server = GovernedA2AServer(card=_card(), tenant_id=TENANT, require_signature=False)
    server.register(ACTION, spy.run)

    result = server.accept_delegation(
        authenticated_delegator=DELEGATOR,
        task=_task(["price"]),
        receipt=receipt,
    )

    assert result == "REDLINE COMPLETE"
    assert spy.calls == [{"fields": ["price"]}]
    # The minted receipt was persisted to a tamper-evident audit chain.
    chain = audit.verify_chain()
    assert chain["valid"]


def test_delegation_no_receipt_fails_closed(tmp_path: Path) -> None:
    _setup(tmp_path)
    spy = SpyExecutor()
    server = GovernedA2AServer(card=_card(), tenant_id=TENANT, require_signature=False)
    server.register(ACTION, spy.run)

    with pytest.raises(A2ADelegationError):
        server.accept_delegation(
            authenticated_delegator=DELEGATOR,
            task=_task(["price"]),
            receipt=None,
        )
    assert spy.calls == []


def test_delegation_substituted_args_fails_closed(tmp_path: Path) -> None:
    store, audit = _setup(tmp_path)
    # Receipt is minted for {fields: [price]} ...
    receipt = mint_delegation(
        store=store,
        audit_store=audit,
        delegating_actor=DELEGATOR,
        task=_task(["price"]),
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        request_id="req-subst",
        validator=VALIDATOR,
        authority=AUTHORITY,
    )

    spy = SpyExecutor()
    server = GovernedA2AServer(card=_card(), tenant_id=TENANT, require_signature=False)
    server.register(ACTION, spy.run)

    # ... but the remote is asked to run {fields: [price, liability]}.
    with pytest.raises(A2ADelegationError):
        server.accept_delegation(
            authenticated_delegator=DELEGATOR,
            task=_task(["price", "liability"]),
            receipt=receipt,
        )
    assert spy.calls == []


def test_delegation_signed_forgery_rejected(tmp_path: Path) -> None:
    store, audit = _setup(tmp_path)
    signing_key = Ed25519Signer.generate()
    verify_key = Ed25519Signer.from_public_bytes(signing_key.public_bytes())

    signed = mint_delegation(
        store=store,
        audit_store=audit,
        delegating_actor=DELEGATOR,
        task=_task(["price"]),
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        request_id="req-signed",
        validator=VALIDATOR,
        authority=AUTHORITY,
        signer=signing_key,
    )
    assert signed.signature_algorithm == "ed25519"

    # Forge: tamper a field and recompute a self-consistent receipt_hash. The
    # hash check passes, but the signature still attests the ORIGINAL hash and
    # cannot be re-produced without the private key → invalid signature.
    forged = dataclasses.replace(signed, declared_goal="tampered goal")
    forged = dataclasses.replace(forged, receipt_hash=forged.compute_hash())

    spy = SpyExecutor()
    server = GovernedA2AServer(card=_card(), tenant_id=TENANT, verifier=verify_key)
    server.register(ACTION, spy.run)

    with pytest.raises(A2ADelegationError):
        server.accept_delegation(
            authenticated_delegator=DELEGATOR,
            task=_task(["price"]),
            receipt=forged,
        )
    assert spy.calls == []


def test_delegation_signed_happy_path_runs(tmp_path: Path) -> None:
    """The signed-by-default server admits a genuinely signed receipt."""
    store, audit = _setup(tmp_path)
    signing_key = Ed25519Signer.generate()
    verify_key = Ed25519Signer.from_public_bytes(signing_key.public_bytes())

    signed = mint_delegation(
        store=store,
        audit_store=audit,
        delegating_actor=DELEGATOR,
        task=_task(["price"]),
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        request_id="req-signed-ok",
        validator=VALIDATOR,
        authority=AUTHORITY,
        signer=signing_key,
    )

    spy = SpyExecutor()
    server = GovernedA2AServer(card=_card(), tenant_id=TENANT, verifier=verify_key)
    server.register(ACTION, spy.run)

    result = server.accept_delegation(
        authenticated_delegator=DELEGATOR,
        task=_task(["price"]),
        receipt=signed,
    )
    assert result == "REDLINE COMPLETE"
    assert spy.calls == [{"fields": ["price"]}]


def test_mint_self_validation_forbidden(tmp_path: Path) -> None:
    """validator == delegating_actor is MACI self-validation; the kernel rejects it."""
    store, audit = _setup(tmp_path)
    with pytest.raises(ReceiptValidationError):
        mint_delegation(
            store=store,
            audit_store=audit,
            delegating_actor=DELEGATOR,
            task=_task(["price"]),
            tenant_id=TENANT,
            execution_boundary=BOUNDARY,
            request_id="req-self",
            validator=Validator(DELEGATOR),  # same principal as the proposer
            authority=AUTHORITY,
        )


def test_server_signed_by_default_requires_verifier() -> None:
    # Secure by default: require_signature defaults to True, so a missing verifier
    # is a fail-closed construction error.
    with pytest.raises(ValueError):
        GovernedA2AServer(card=_card(), tenant_id=TENANT)

    with pytest.raises(ValueError):
        GovernedA2AServer(card=_card(), tenant_id=TENANT, require_signature=True, verifier=None)

    # Explicit unsigned same-domain opt-in constructs without a verifier.
    server = GovernedA2AServer(card=_card(), tenant_id=TENANT, require_signature=False)
    assert server.require_signature is False
