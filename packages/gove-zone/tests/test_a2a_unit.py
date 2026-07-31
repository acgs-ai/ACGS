"""Direct unit tests for :mod:`gove_zone.a2a`.

These drive the module's own public surface — :class:`AgentCard`,
:class:`DelegatedTask`, :func:`mint_delegation` and
:class:`GovernedA2AServer` — rather than reaching it transitively. Every
fail-closed row asserts BOTH the raise AND that the registered handler never
ran: the un-run side effect is the actual property under test.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
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
from gove_zone.tenant import TenantPolicyStore

TENANT = "tenant-unit"
BOUNDARY = "a2a-unit-sandbox"
DELEGATOR = "planner-unit"
VALIDATOR = Validator("council-unit")
AUTHORITY = "tenant-unit/unit-grant"
ACTION = "doc.summarize"


class FakeSigner:
    """Deterministic HMAC signer implementing the ReceiptSigner protocol."""

    algorithm = "test-hmac-sha256"

    def __init__(self, key: bytes = b"a2a-unit-key", key_id: str = "a2a-key-1") -> None:
        self._key = key
        self.key_id = key_id

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


class Handler:
    """Records every invocation; an empty ``calls`` list proves no side effect."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def run(self, **kwargs: Any) -> str:
        self.calls.append(kwargs)
        return "SUMMARY"


@pytest.fixture
def stores(tmp_path: Path) -> tuple[TenantPolicyStore, ChainHashAuditStore]:
    """A same-tenant bundle that allows everything except ``shell.exec``."""
    store = TenantPolicyStore(tmp_path / "policies")
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    store.store_bundle(
        TENANT,
        RuleSetPolicy.from_dict(
            {
                "id": "policy-unit",
                "rules": [{"id": "R1", "effect": "deny", "tools": ["shell.exec"]}],
            }
        ),
    )
    return store, audit


@pytest.fixture
def card() -> AgentCard:
    return AgentCard(agent_id="summarizer", execution_boundary=BOUNDARY, capabilities=(ACTION,))


@pytest.fixture
def task() -> DelegatedTask:
    return DelegatedTask(action=ACTION, args={"doc": "contract-7"}, declared_goal="summarize")


def _mint(
    stores: tuple[TenantPolicyStore, ChainHashAuditStore],
    task: DelegatedTask,
    *,
    delegating_actor: str = DELEGATOR,
    validator: Validator = VALIDATOR,
    signer: Any = None,
    request_id: str = "req-unit-1",
) -> Any:
    store, audit = stores
    return mint_delegation(
        store=store,
        audit_store=audit,
        delegating_actor=delegating_actor,
        task=task,
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        request_id=request_id,
        validator=validator,
        authority=AUTHORITY,
        signer=signer,
    )


# --- value objects ---------------------------------------------------------- #


def test_agent_card_defaults_to_no_capabilities_and_is_frozen() -> None:
    bare = AgentCard(agent_id="a", execution_boundary="b")
    assert bare.capabilities == ()
    with pytest.raises(dataclasses.FrozenInstanceError):
        bare.agent_id = "other"  # type: ignore[misc]


def test_delegated_task_declared_goal_defaults_to_empty() -> None:
    bare = DelegatedTask(action="x", args={})
    assert bare.declared_goal == ""
    assert bare.args == {}


# --- mint_delegation -------------------------------------------------------- #


def test_mint_delegation_binds_receipt_to_the_delegating_actor(
    stores: tuple[TenantPolicyStore, ChainHashAuditStore], task: DelegatedTask
) -> None:
    receipt = _mint(stores, task)
    assert receipt.actor == DELEGATOR
    assert receipt.proposed_action == ACTION
    assert receipt.tenant_id == TENANT
    assert receipt.execution_boundary == BOUNDARY
    # A freshly minted receipt is internally consistent.
    receipt.verify()


def test_mint_delegation_surfaces_self_validation_raw(
    stores: tuple[TenantPolicyStore, ChainHashAuditStore], task: DelegatedTask
) -> None:
    """MACI is the kernel's; the raw ReceiptValidationError is NOT wrapped."""
    with pytest.raises(ReceiptValidationError, match="self-validation"):
        _mint(stores, task, validator=Validator(DELEGATOR))


def test_mint_delegation_with_signer_produces_a_signed_receipt(
    stores: tuple[TenantPolicyStore, ChainHashAuditStore], task: DelegatedTask
) -> None:
    signer = FakeSigner()
    receipt = _mint(stores, task, signer=signer)
    assert receipt.signature_algorithm == signer.algorithm
    assert receipt.signing_key_id == signer.key_id
    assert signer.verify(receipt.receipt_hash.encode("utf-8"), receipt.signature)


# --- GovernedA2AServer construction ----------------------------------------- #


def test_server_rejects_signature_required_without_verifier(card: AgentCard) -> None:
    with pytest.raises(ValueError, match="requires a verifier"):
        GovernedA2AServer(card=card, tenant_id=TENANT)


def test_server_unsigned_opt_in_is_explicit(card: AgentCard) -> None:
    server = GovernedA2AServer(card=card, tenant_id=TENANT, require_signature=False)
    assert server.require_signature is False
    assert server.verifier is None
    assert server.card is card


# --- accept_delegation ------------------------------------------------------ #


def test_accept_delegation_runs_the_registered_handler(
    stores: tuple[TenantPolicyStore, ChainHashAuditStore], card: AgentCard, task: DelegatedTask
) -> None:
    receipt = _mint(stores, task)
    handler = Handler()
    server = GovernedA2AServer(card=card, tenant_id=TENANT, require_signature=False)
    server.register(ACTION, handler.run)

    result = server.accept_delegation(authenticated_delegator=DELEGATOR, task=task, receipt=receipt)

    assert result == "SUMMARY"
    assert handler.calls == [{"doc": "contract-7"}]


def test_accept_delegation_without_a_handler_fails_closed(
    stores: tuple[TenantPolicyStore, ChainHashAuditStore], card: AgentCard, task: DelegatedTask
) -> None:
    receipt = _mint(stores, task)
    server = GovernedA2AServer(card=card, tenant_id=TENANT, require_signature=False)

    with pytest.raises(A2ADelegationError, match="no handler registered"):
        server.accept_delegation(authenticated_delegator=DELEGATOR, task=task, receipt=receipt)


def test_accept_delegation_without_a_receipt_fails_closed(
    card: AgentCard, task: DelegatedTask
) -> None:
    handler = Handler()
    server = GovernedA2AServer(card=card, tenant_id=TENANT, require_signature=False)
    server.register(ACTION, handler.run)

    with pytest.raises(A2ADelegationError):
        server.accept_delegation(authenticated_delegator=DELEGATOR, task=task, receipt=None)
    assert handler.calls == []


def test_accept_delegation_rejects_a_substituted_delegator(
    stores: tuple[TenantPolicyStore, ChainHashAuditStore], card: AgentCard, task: DelegatedTask
) -> None:
    """``authenticated_delegator`` is the anchor — never ``receipt.actor``."""
    receipt = _mint(stores, task)
    handler = Handler()
    server = GovernedA2AServer(card=card, tenant_id=TENANT, require_signature=False)
    server.register(ACTION, handler.run)

    with pytest.raises(A2ADelegationError):
        server.accept_delegation(authenticated_delegator="impostor", task=task, receipt=receipt)
    assert handler.calls == []


def test_accept_delegation_rejects_substituted_args(
    stores: tuple[TenantPolicyStore, ChainHashAuditStore], card: AgentCard, task: DelegatedTask
) -> None:
    receipt = _mint(stores, task)
    handler = Handler()
    server = GovernedA2AServer(card=card, tenant_id=TENANT, require_signature=False)
    server.register(ACTION, handler.run)
    swapped = DelegatedTask(action=ACTION, args={"doc": "contract-OTHER"})

    with pytest.raises(A2ADelegationError):
        server.accept_delegation(authenticated_delegator=DELEGATOR, task=swapped, receipt=receipt)
    assert handler.calls == []


def test_accept_delegation_rejects_a_foreign_execution_boundary(
    stores: tuple[TenantPolicyStore, ChainHashAuditStore], task: DelegatedTask
) -> None:
    """The server's own card boundary is the expectation, not the receipt's."""
    receipt = _mint(stores, task)
    handler = Handler()
    other_card = AgentCard(agent_id="summarizer", execution_boundary="some-other-boundary")
    server = GovernedA2AServer(card=other_card, tenant_id=TENANT, require_signature=False)
    server.register(ACTION, handler.run)

    with pytest.raises(A2ADelegationError):
        server.accept_delegation(authenticated_delegator=DELEGATOR, task=task, receipt=receipt)
    assert handler.calls == []


def test_signed_server_accepts_a_signed_delegation(
    stores: tuple[TenantPolicyStore, ChainHashAuditStore], card: AgentCard, task: DelegatedTask
) -> None:
    signer = FakeSigner()
    receipt = _mint(stores, task, signer=signer)
    handler = Handler()
    server = GovernedA2AServer(card=card, tenant_id=TENANT, verifier=signer)
    server.register(ACTION, handler.run)

    assert (
        server.accept_delegation(authenticated_delegator=DELEGATOR, task=task, receipt=receipt)
        == "SUMMARY"
    )
    assert len(handler.calls) == 1


def test_signed_server_rejects_an_unsigned_delegation(
    stores: tuple[TenantPolicyStore, ChainHashAuditStore], card: AgentCard, task: DelegatedTask
) -> None:
    receipt = _mint(stores, task)  # unsigned
    handler = Handler()
    server = GovernedA2AServer(card=card, tenant_id=TENANT, verifier=FakeSigner())
    server.register(ACTION, handler.run)

    with pytest.raises(A2ADelegationError):
        server.accept_delegation(authenticated_delegator=DELEGATOR, task=task, receipt=receipt)
    assert handler.calls == []


def test_register_replaces_the_handler_for_an_action(
    stores: tuple[TenantPolicyStore, ChainHashAuditStore], card: AgentCard, task: DelegatedTask
) -> None:
    """The registry is last-write-wins; only the live handler is reachable."""
    receipt = _mint(stores, task)
    stale, live = Handler(), Handler()
    server = GovernedA2AServer(card=card, tenant_id=TENANT, require_signature=False)
    server.register(ACTION, stale.run)
    server.register(ACTION, live.run)

    server.accept_delegation(authenticated_delegator=DELEGATOR, task=task, receipt=receipt)

    assert stale.calls == []
    assert len(live.calls) == 1
