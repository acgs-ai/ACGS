"""Scoped receipt-v2 trust enforcement on the gateway's HTTP request path.

The scoped-trust primitives (:mod:`gove_zone.trust`,
:meth:`gove_zone.receipt.DecisionReceipt.from_record_v2`, the v2 branch of
:func:`gove_zone.executor.execute_with_receipt`) were fail-closed at the
library layer but had no caller on the request path: every surface of
:class:`~gove_zone.gateway.UniversalGateway` minted receipt-v1 and passed no
``trust_registry`` to the gate.

These tests exercise the wiring through the **dispatcher** (``handle_rest_call``
/ ``handle_mcp_call`` / ``handle_claude_hook``), never by calling the executor
directly — a passing direct-executor test proves nothing about the HTTP path.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")

from gove_zone.decision import Decision  # noqa: E402
from gove_zone.gateway import UniversalGateway  # noqa: E402
from gove_zone.policy import Policy, PolicyRule, RuleSetPolicy  # noqa: E402
from gove_zone.profile import GovernanceProfile  # noqa: E402
from gove_zone.receipt import Validator  # noqa: E402
from gove_zone.signing import Ed25519Signer  # noqa: E402
from gove_zone.trust import (  # noqa: E402
    RECEIPT_V2,
    ReceiptTrustScope,
    StaticReceiptTrustRegistry,
    TrustedReceiptKey,
)

TENANT = "tenant-1"
PROJECT = "project-main"
ENV = "prod"
BOUNDARY = "boundary-1"
ACTOR = "agent-1"
FUTURE = "2099-01-01T00:00:00+00:00"


def make_policy() -> RuleSetPolicy:
    return RuleSetPolicy(
        policy_id="gateway-scoped-trust-tests",
        rules=(
            PolicyRule(
                rule_id="deny-rm-prod",
                effect=Decision.DENY,
                tools=frozenset({"rm_prod"}),
                reason="destructive tool is always denied",
            ),
        ),
    )


def public_spki_der(signer: Ed25519Signer) -> bytes:
    return Ed25519Signer.from_public_bytes(signer.public_bytes())._public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def trust_registry(
    signer: Ed25519Signer,
    *,
    project_id: str = PROJECT,
    environment_id: str = ENV,
    activated_epoch: int = 1,
    status: str = "active",
    retired_epoch: int | None = None,
    not_after: str = FUTURE,
) -> StaticReceiptTrustRegistry:
    return StaticReceiptTrustRegistry(
        [
            TrustedReceiptKey(
                scope=ReceiptTrustScope(TENANT, project_id, environment_id),
                key_id=signer.key_id,
                algorithm=signer.algorithm,
                public_key_spki_der=public_spki_der(signer),
                activated_epoch=activated_epoch,
                not_after=not_after,
                retired_epoch=retired_epoch,
                status=status,  # type: ignore[arg-type]
            )
        ]
    )


def make_gateway(
    tmp_path: Path,
    *,
    signer: Ed25519Signer | None,
    registry: StaticReceiptTrustRegistry | None,
    project_id: str = PROJECT,
    environment_id: str = ENV,
    trust_epoch: int | None = 1,
    receipt_ttl_seconds: float | None = 300.0,
    policy: Policy | None = None,
) -> UniversalGateway:
    return UniversalGateway(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy=policy or make_policy(),
        profile=GovernanceProfile.production(signer=signer),
        validator=Validator(validator_id="validator-1"),
        authority="authority-1",
        audit_path=tmp_path / "audit.jsonl",
        ledger_path=tmp_path / "ledger.jsonl",
        receipt_ttl_seconds=receipt_ttl_seconds,
        project_id=project_id,
        environment_id=environment_id,
        trust_epoch=trust_epoch,
        trust_registry=registry,
    )


def register_echo(gateway: UniversalGateway) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def echo(message: str) -> str:
        calls.append({"message": message})
        return message

    gateway.register_tool("echo", echo)
    return calls


# -- HTTP/REST surface: scoped trust is enforced ------------------------------- #


def test_rest_call_mints_v2_receipt_verified_against_trust_registry(tmp_path: Path) -> None:
    """A scoped gateway mints receipt-v2 on the HTTP path and the gate resolves
    the signing key through the trust registry before the side effect runs."""
    signer = Ed25519Signer.generate(key_id="scoped-gateway-key")
    gateway = make_gateway(tmp_path, signer=signer, registry=trust_registry(signer))
    calls = register_echo(gateway)

    response = gateway.handle_rest_call({"tool": "echo", "args": {"message": "hi"}}, actor=ACTOR)

    assert response["status"] == 200
    assert response["body"]["status"] == "executed"
    assert response["body"]["receipt"]["receipt_schema_version"] == RECEIPT_V2
    assert response["body"]["receipt"]["signature_algorithm"] == "ed25519"
    assert calls == [{"message": "hi"}]


def test_rest_call_rejects_v2_receipt_when_no_trust_root_exists(tmp_path: Path) -> None:
    """Fail-closed: an empty trust registry cannot authorize anything — the HTTP
    request is refused at the gate with zero side effect."""
    signer = Ed25519Signer.generate(key_id="unrooted-key")
    gateway = make_gateway(tmp_path, signer=signer, registry=StaticReceiptTrustRegistry([]))
    calls = register_echo(gateway)

    response = gateway.handle_rest_call({"tool": "echo", "args": {"message": "hi"}}, actor=ACTOR)

    assert response["status"] == 500
    assert response["body"]["error_class"] == "ReceiptValidationError"
    assert calls == []


def test_rest_call_rejects_v2_receipt_when_trust_root_is_out_of_scope(tmp_path: Path) -> None:
    """A trust root for another project cannot authorize this project's request."""
    signer = Ed25519Signer.generate(key_id="other-project-key")
    gateway = make_gateway(
        tmp_path, signer=signer, registry=trust_registry(signer, project_id="project-other")
    )
    calls = register_echo(gateway)

    response = gateway.handle_rest_call({"tool": "echo", "args": {"message": "hi"}}, actor=ACTOR)

    assert response["status"] == 500
    assert response["body"]["error_class"] == "ReceiptValidationError"
    assert calls == []


def test_rest_call_rejects_v2_receipt_when_trust_root_is_revoked(tmp_path: Path) -> None:
    """A revoked scoped root refuses the request even though the signature is valid."""
    signer = Ed25519Signer.generate(key_id="revoked-key")
    gateway = make_gateway(
        tmp_path, signer=signer, registry=trust_registry(signer, status="revoked")
    )
    calls = register_echo(gateway)

    response = gateway.handle_rest_call({"tool": "echo", "args": {"message": "hi"}}, actor=ACTOR)

    assert response["status"] == 500
    assert response["body"]["error_class"] == "ReceiptValidationError"
    assert calls == []


def test_rest_call_rejects_v2_receipt_minted_before_the_trust_epoch(tmp_path: Path) -> None:
    """A root activated at a later epoch cannot authorize an earlier-epoch receipt."""
    signer = Ed25519Signer.generate(key_id="future-epoch-key")
    gateway = make_gateway(
        tmp_path, signer=signer, registry=trust_registry(signer, activated_epoch=7)
    )
    calls = register_echo(gateway)

    response = gateway.handle_rest_call({"tool": "echo", "args": {"message": "hi"}}, actor=ACTOR)

    assert response["status"] == 500
    assert response["body"]["error_class"] == "ReceiptValidationError"
    assert calls == []


# -- other surfaces share the same chokepoint ---------------------------------- #


def test_scoped_gateway_refuses_to_mint_v1_approval(tmp_path: Path) -> None:
    """A scoped gateway must not approve via v1 from_record and then resume."""
    from gove_zone.gateway import MCP_APPROVE_TOOL

    signer = Ed25519Signer.generate(key_id="scoped-approve-key")
    policy = RuleSetPolicy(
        policy_id="scoped-escalate",
        rules=(
            PolicyRule(
                rule_id="escalate-deploy",
                effect=Decision.ESCALATE,
                tools=frozenset({"deploy"}),
                reason="needs human",
            ),
        ),
    )
    gateway = make_gateway(tmp_path, signer=signer, registry=trust_registry(signer), policy=policy)
    gateway.approver_actors = frozenset({"human-approver"})
    calls: list[Any] = []
    gateway.register_tool("deploy", lambda **kwargs: calls.append(dict(kwargs)))

    parked = gateway.handle_mcp_call({"name": "deploy", "arguments": {"env": "prod"}}, actor=ACTOR)
    assert parked["_meta"]["gove_zone"]["decision"] == "escalated"
    event_id = parked["_meta"]["gove_zone"]["escalation_event_id"]

    approved = gateway.handle_mcp_call(
        {"name": MCP_APPROVE_TOOL, "arguments": {"event_id": event_id}},
        actor="human-approver",
    )
    assert approved["isError"] is True
    assert approved["_meta"]["gove_zone"]["envelope"]["matched_rules"] == [
        "HUMAN_LOOP_REFUSED:scoped_v1_forbidden"
    ]
    assert calls == []
    assert event_id in gateway._pending
    assert event_id not in gateway._approvals


def test_mcp_call_under_scoped_trust_executes_and_reports_v2(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="mcp-scoped-key")
    gateway = make_gateway(tmp_path, signer=signer, registry=trust_registry(signer))
    calls = register_echo(gateway)

    result = gateway.handle_mcp_call(
        {"method": "tools/call", "params": {"name": "echo", "arguments": {"message": "hi"}}},
        actor=ACTOR,
    )

    assert result["isError"] is False
    assert result["_meta"]["gove_zone"]["receipt_schema_version"] == RECEIPT_V2
    assert calls == [{"message": "hi"}]


def test_mcp_call_under_scoped_trust_refuses_without_trust_root(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="mcp-unrooted-key")
    gateway = make_gateway(tmp_path, signer=signer, registry=StaticReceiptTrustRegistry([]))
    calls = register_echo(gateway)

    result = gateway.handle_mcp_call(
        {"method": "tools/call", "params": {"name": "echo", "arguments": {"message": "hi"}}},
        actor=ACTOR,
    )

    assert result["isError"] is True
    assert result["_meta"]["gove_zone"]["error_class"] == "ReceiptValidationError"
    assert calls == []


def test_claude_hook_mints_v2_receipts_under_scoped_trust(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="hook-scoped-key")
    gateway = make_gateway(tmp_path, signer=signer, registry=trust_registry(signer))
    register_echo(gateway)

    response = gateway.handle_claude_hook(
        {"tool_name": "echo", "tool_input": {"message": "hi"}},
        actor="claude-session-1",
    )

    assert response["hookSpecificOutput"]["permissionDecision"] == "allow"
    (anchor,) = response["gove_zone"]["receipts"]
    assert anchor["receipt_schema_version"] == RECEIPT_V2
    assert anchor["signature_algorithm"] == "ed25519"


# -- fail-closed configuration ------------------------------------------------- #


def test_scoped_trust_without_registry_fails_at_construction(tmp_path: Path) -> None:
    """No bypass: a gateway asked for a v2 scope with no trust registry must
    refuse to exist rather than silently downgrade to unscoped v1 receipts."""
    signer = Ed25519Signer.generate(key_id="no-registry-key")
    with pytest.raises(ValueError, match="trust_registry"):
        make_gateway(tmp_path, signer=signer, registry=None)


def test_scoped_trust_requires_a_signer(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="no-signer-key")
    with pytest.raises(ValueError, match="signer"):
        UniversalGateway(
            tenant_id=TENANT,
            execution_boundary=BOUNDARY,
            policy=make_policy(),
            profile=GovernanceProfile.production(),
            validator=Validator(validator_id="validator-1"),
            authority="authority-1",
            audit_path=tmp_path / "audit.jsonl",
            ledger_path=tmp_path / "ledger.jsonl",
            receipt_ttl_seconds=300.0,
            project_id=PROJECT,
            environment_id=ENV,
            trust_epoch=1,
            trust_registry=trust_registry(signer),
        )


def test_scoped_trust_requires_receipt_ttl(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="no-ttl-key")
    with pytest.raises(ValueError, match="receipt_ttl_seconds"):
        make_gateway(
            tmp_path,
            signer=signer,
            registry=trust_registry(signer),
            receipt_ttl_seconds=None,
        )


@pytest.mark.parametrize(
    ("project_id", "environment_id", "trust_epoch", "expected"),
    [
        ("", ENV, 1, "project_id"),
        (PROJECT, "", 1, "environment_id"),
        (PROJECT, ENV, 0, "trust_epoch"),
        (PROJECT, ENV, None, "trust_epoch"),
    ],
)
def test_partial_scope_fails_at_construction(
    tmp_path: Path,
    project_id: str,
    environment_id: str,
    trust_epoch: int | None,
    expected: str,
) -> None:
    signer = Ed25519Signer.generate(key_id="partial-scope-key")
    with pytest.raises(ValueError, match=expected):
        make_gateway(
            tmp_path,
            signer=signer,
            registry=trust_registry(signer),
            project_id=project_id,
            environment_id=environment_id,
            trust_epoch=trust_epoch,
        )


def test_unscoped_gateway_still_mints_v1_receipts(tmp_path: Path) -> None:
    """Backward compatibility: a gateway with no scope configured is unchanged —
    receipt-v1, no trust registry, verifier-based signature check."""
    signer = Ed25519Signer.generate(key_id="unscoped-key")
    gateway = UniversalGateway(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy=make_policy(),
        profile=GovernanceProfile.production(signer=signer, verifier=signer),
        validator=Validator(validator_id="validator-1"),
        authority="authority-1",
        audit_path=tmp_path / "audit.jsonl",
        ledger_path=tmp_path / "ledger.jsonl",
    )
    calls = register_echo(gateway)

    response = gateway.handle_rest_call({"tool": "echo", "args": {"message": "hi"}}, actor=ACTOR)

    assert response["status"] == 200
    assert response["body"]["receipt"]["receipt_schema_version"] == ""
    assert calls == [{"message": "hi"}]
