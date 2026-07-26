"""Route-level tests for canonical managed agent registration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from gove_zone.decision import sha256_json
from gove_zone.policy import RuleSetPolicy
from gove_zone.receipt import DecisionReceipt
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, ReceiptTrustScope

from acgs_control_plane.agent_registration import (
    DefaultAgentRegistrationReceiptIssuer,
    local_agent_registration_issuer,
)
from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.managed_mutations import CONTROL_PLANE_AGENT_CREATE_ACTION
from acgs_control_plane.migrations import upgrade_database
from acgs_control_plane.models import (
    AgentRecord,
    AgentRegistrationIdempotency,
    Environment,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedMutationAttempt,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    Organization,
    PolicyBundle,
    Project,
    ReceiptRow,
    new_id,
    utcnow,
)
from acgs_control_plane.tenant_bootstrap import BOOTSTRAP_IDEMPOTENCY_HEADER
from acgs_control_plane.trust import (
    ManagedTrustLifecycleService,
    public_spki_der_from_signer,
)

BOOTSTRAP_TOKEN = "test-bootstrap-token"


def test_agent_register_route_executes_through_managed_receipt_v2_spine(
    tmp_path: Path,
) -> None:
    app, client = _migrated_client(tmp_path)
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate_allow_agent_create(client, org)

    resp = client.post(
        f"/orgs/{org['org_id']}/agents",
        json={
            "name": "deploy-bot",
            "description": "caller supplied metadata is ignored",
            "trust_tier": "untrusted",
            "allowed_tools": ["deploy.production"],
        },
        headers=_agent_headers(org, "agent-register-route-0001"),
    )

    assert resp.status_code == 201, resp.text
    payload = resp.json()
    assert payload["receipt_id"]
    assert payload["name"] == "deploy-bot"
    assert payload["description"] == "caller supplied metadata is ignored"
    assert payload["trust_tier"] == "untrusted"
    assert payload["allowed_tools"] == ["deploy.production"]
    with app.state.session_factory() as session:
        agent = session.scalars(
            sa.select(AgentRecord).where(
                AgentRecord.org_id == org["org_id"],
                AgentRecord.name == "deploy-bot",
            )
        ).one()
        receipt = session.scalars(sa.select(ManagedDecisionReceipt)).one()
        consumption = session.scalars(sa.select(ManagedReceiptConsumption)).one()
        event = session.scalars(sa.select(ManagedGovernanceEvent)).one()
        outbox = session.scalars(sa.select(ManagedOutboxMessage)).one()

        assert agent.id == payload["agent_id"]
        assert agent.project_id is not None
        assert agent.environment_id is not None
        assert agent.description == "caller supplied metadata is ignored"
        assert agent.trust_tier == "untrusted"
        assert agent.allowed_tools == ["deploy.production"]
        assert receipt.receipt_id == payload["receipt_id"]
        assert receipt.proposed_action == CONTROL_PLANE_AGENT_CREATE_ACTION
        assert receipt.decision == "allow"
        assert receipt.actor == f"user:{org['admin_user_id']}"
        assert receipt.projection["assurance_class"] == "native"
        assert receipt.projection["sealed_receipt"]["schema"] == "managed-receipt-artifact-seal/v1"
        assert "deploy.production" not in str(receipt.projection)
        assert consumption.managed_receipt_id == receipt.id
        assert event.managed_receipt_id == receipt.id
        assert event.proposed_action == CONTROL_PLANE_AGENT_CREATE_ACTION
        assert outbox.managed_receipt_id == receipt.id
        # The managed spine owns the authoritative receipt, and the legacy
        # receipts table carries a mirror of it so the explorer, dashboard,
        # and compliance export still see this registration. Mirrored under
        # the pre-rename tool name, which is what those consumers query.
        assert _count_legacy_agent_receipts(session, org["org_id"]) == 1


def test_agent_register_mirror_stays_verifiable_on_the_org_audit_chain(
    tmp_path: Path,
) -> None:
    """The mirror must be real evidence, not a decorative row.

    Writing into ``receipts`` without appending to the org's audit chain, or
    advancing the anchor independently of the chain tip, would leave
    ``POST /receipts/{id}/verify`` reporting a healthy chain as broken -- or
    worse, a broken one as healthy. Verify through the API the auditor uses.
    """
    app, client = _migrated_client(tmp_path)
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate_allow_agent_create(client, org)
    headers = _admin_headers(org)

    created = client.post(
        f"/orgs/{org['org_id']}/agents",
        json={"name": "audited-bot"},
        headers=_agent_headers(org, "mirror-audited-bot"),
    )
    assert created.status_code == 201, created.text

    listed = client.get(f"/orgs/{org['org_id']}/receipts", headers=headers)
    assert listed.status_code == 200, listed.text
    mirrored = [item for item in listed.json()["items"] if item["tool"] == "agent.register"]
    assert len(mirrored) == 1, listed.text

    verified = client.post(
        f"/orgs/{org['org_id']}/receipts/{mirrored[0]['receipt_id']}/verify",
        headers=headers,
    )
    assert verified.status_code == 200, verified.text
    body = verified.json()
    assert body["receipt_in_chain"] is True, body
    assert body["chain_valid"] is True, body
    assert body["anchor_matched"] is True, body
    assert body["failures"] == [], body


def test_agent_register_route_requires_idempotency_key_before_issuance_or_persistence(
    tmp_path: Path,
) -> None:
    receipt_issuer = _IssuanceForbidden()
    app, client = _migrated_client(tmp_path, receipt_issuer=receipt_issuer)
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate_allow_agent_create(client, org)

    resp = client.post(
        f"/orgs/{org['org_id']}/agents",
        json={"name": "missing-key-bot", "trust_tier": "internal"},
        headers=_admin_headers(org),
    )

    assert resp.status_code == 400, resp.text
    assert resp.json()["code"] == "IDEMPOTENCY_KEY_REQUIRED"
    assert resp.json()["status"] == "idempotency_key_required"
    assert receipt_issuer.calls == 0
    with app.state.session_factory() as session:
        assert _count_agents(session, org["org_id"], "missing-key-bot") == 0
        assert _count(session, AgentRegistrationIdempotency) == 0
        assert _count(session, ManagedDecisionReceipt) == 0
        assert _count(session, ManagedReceiptConsumption) == 0
        assert _count(session, ManagedGovernanceEvent) == 0
        assert _count(session, ManagedOutboxMessage) == 0
        assert _count(session, ManagedMutationAttempt) == 0
        assert _count_legacy_agent_receipts(session, org["org_id"]) == 0


def test_agent_register_route_refusal_matrix_has_zero_managed_side_effects(
    tmp_path: Path,
) -> None:
    cases: list[dict[str, Any]] = [
        {"name": "missing_auth", "status": 401, "code": None, "scope": True, "policy": "allow"},
        {
            "name": "rbac_denied",
            "status": 403,
            "code": None,
            "scope": True,
            "policy": "allow",
            "role": "viewer",
        },
        {"name": "missing_scope", "status": 409, "code": "SCOPE_NOT_READY", "scope": False},
        {"name": "missing_policy", "status": 409, "code": "POLICY_NOT_READY", "scope": True},
        # A policy refusal answers in the receipted envelope, not the flat
        # {code,status,detail} one, so it carries no "code" to assert. The
        # envelope itself is asserted below, keyed off "evidence".
        {
            "name": "deny",
            "status": 403,
            "code": None,
            "scope": True,
            "policy": "deny",
            "evidence": "deny",
        },
        {
            "name": "escalate",
            "status": 202,
            "code": None,
            "scope": True,
            "policy": "escalate",
            "evidence": "escalate",
        },
        {
            "name": "malformed_receipt",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "allow",
            "receipt_mode": "malformed",
        },
        {
            "name": "invalid_signature",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "allow",
            "receipt_mode": "invalid_signature",
        },
        {
            "name": "expired_receipt",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "allow",
            "receipt_mode": "expired",
        },
        {
            "name": "untrusted_key",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "allow",
            "receipt_mode": "untrusted_key",
        },
        {
            "name": "wrong_tenant",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "allow",
            "receipt_mode": "wrong_tenant",
        },
        {
            "name": "wrong_project",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "allow",
            "receipt_mode": "wrong_project",
        },
        {
            "name": "wrong_environment",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "allow",
            "receipt_mode": "wrong_environment",
        },
        {
            "name": "wrong_action",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "allow",
            "receipt_mode": "wrong_action",
        },
        {
            "name": "wrong_actor",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "allow",
            "receipt_mode": "wrong_actor",
        },
        {
            "name": "wrong_args",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "allow",
            "receipt_mode": "wrong_args",
        },
        {
            "name": "wrong_policy_hash",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "allow",
            "receipt_mode": "wrong_policy_hash",
        },
        {
            "name": "wrong_policy_bundle",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "allow",
            "receipt_mode": "wrong_policy_bundle",
        },
        {
            "name": "wrong_validator",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "allow",
            "receipt_mode": "wrong_validator",
        },
        {
            "name": "wrong_authority",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "allow",
            "receipt_mode": "wrong_authority",
        },
        {
            "name": "wrong_audit",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "allow",
            "receipt_mode": "wrong_audit",
        },
        {
            "name": "trust_outage",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "allow",
            "trust": "missing",
        },
        {
            "name": "trust_revoked",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "allow",
            "trust": "revoked",
        },
        {
            "name": "trust_expired",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "allow",
            "trust": "expired",
        },
        {
            "name": "allow_policy_changed_before_execution",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "allow",
            "race": "deny",
        },
        {
            "name": "deny_policy_changed_before_evidence",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "deny",
            "race": "allow",
        },
        {
            "name": "escalate_policy_changed_before_evidence",
            "status": 503,
            "code": "RECEIPT_REFUSED",
            "scope": True,
            "policy": "escalate",
            "race": "allow",
        },
        {
            "name": "tx_abort_before_append",
            "status": 503,
            "code": "TX_ABORTED",
            "scope": True,
            "policy": "deny",
            "receipt_sealer": _FailingReceiptSealer(),
        },
        {
            "name": "tx_abort_after_agent_insert",
            "status": 409,
            "code": "AGENT_NAME_CONFLICT",
            "scope": True,
            "policy": "allow",
            "preexisting_agent": True,
        },
    ]
    for case in cases:
        app_holder: dict[str, Any] = {}
        org_holder: dict[str, Any] = {}
        on_issue = _race_policy_swapper(case, app_holder, org_holder)

        app, client = _migrated_client(
            tmp_path,
            label=str(case["name"]),
            receipt_mode=case.get("receipt_mode"),
            on_issue=on_issue,
            receipt_sealer=case.get("receipt_sealer"),
        )
        app_holder["app"] = app
        org = _bootstrap_org(client)
        org_holder["org"] = org
        scope_ids: tuple[str, str] | None = None
        if case.get("scope"):
            scope_ids = _seed_default_scope_and_trust(
                app,
                org["org_id"],
                bootstrap_trust=case.get("trust") != "missing",
            )
        if case.get("trust") in {"revoked", "expired"}:
            _expire_or_revoke_trust(app, org["org_id"], status=str(case["trust"]))
        if case.get("policy") is not None:
            _publish_and_activate(client, org, rules=_rules_for_policy(str(case["policy"])))
        if case.get("preexisting_agent"):
            assert scope_ids is not None
            with app.state.session_factory.begin() as session:
                session.add(
                    AgentRecord(
                        org_id=org["org_id"],
                        project_id=scope_ids[0],
                        environment_id=scope_ids[1],
                        name="blocked-bot",
                    )
                )
        headers = _agent_headers(org, f"agent-refusal-{case['name']}-0001")
        if case.get("role") == "viewer":
            headers = {
                **_create_user(client, org, role="viewer"),
                BOOTSTRAP_IDEMPOTENCY_HEADER: f"agent-refusal-{case['name']}-0001",
            }
        if case["name"] == "missing_auth":
            headers = {}

        resp = client.post(
            f"/orgs/{org['org_id']}/agents",
            json={"name": "blocked-bot", "trust_tier": "internal"},
            headers=headers,
        )

        assert resp.status_code == case["status"], (case["name"], resp.text)
        if case.get("code") is not None:
            assert resp.json()["code"] == case["code"], case["name"]
        if case.get("evidence") is not None:
            # The refusal receipt is committed, so the response must cite it.
            # Matches the envelope the route served before agent registration
            # became a managed mutation (see test_v1_api_contract.py).
            body = resp.json()
            assert set(body) == {
                "status",
                "reason",
                "receipt_id",
                "decision",
                "request_id",
            }, (case["name"], resp.text)
            assert body["receipt_id"], case["name"]
            assert body["decision"] == case["evidence"], case["name"]
        else:
            # No policy decision was reached, so there is no receipt to cite.
            assert "receipt_id" not in resp.json(), (case["name"], resp.text)
        with app.state.session_factory() as session:
            expected_agents = 1 if case.get("preexisting_agent") else 0
            assert _count_agents(session, org["org_id"], "blocked-bot") == expected_agents, case[
                "name"
            ]
            assert _count(session, ManagedReceiptConsumption) == 0, case["name"]
            assert _managed_allow_receipts(session) == 0, case["name"]
            # The legacy mirror is written inside the refusal's own
            # transaction, so a refusal that never became final -- aborted
            # revalidation, replayed receipt, refused trust -- must leave the
            # org's evidence surface untouched.
            assert _count_legacy_agent_receipts(session, org["org_id"]) == (
                1 if case.get("evidence") else 0
            ), case["name"]
            if case.get("evidence") is None:
                assert _count(session, ManagedDecisionReceipt) == 0, case["name"]
                assert _count(session, ManagedGovernanceEvent) == 0, case["name"]
                assert _count(session, ManagedOutboxMessage) == 0, case["name"]
                assert _count(session, AgentRegistrationIdempotency) == 0, case["name"]
            else:
                receipt = session.scalars(sa.select(ManagedDecisionReceipt)).one()
                assert receipt.decision == case["evidence"], case["name"]
                assert _count(session, ManagedGovernanceEvent) == 1, case["name"]
                assert _count(session, ManagedOutboxMessage) == 1, case["name"]
                assert _count(session, AgentRegistrationIdempotency) == 1, case["name"]

    _assert_replay_case(tmp_path, decision="allow")
    _assert_replay_case(tmp_path, decision="deny")
    _assert_concurrent_replay_case(tmp_path)


def test_agent_register_route_scope_and_policy_are_server_owned(
    tmp_path: Path,
) -> None:
    app, client = _migrated_client(tmp_path)
    with pytest.raises(AttributeError):
        app.state.agent_registration_service._providers = object()
    with pytest.raises(AttributeError):
        app.state.agent_registration_service._session_factory = None
    with pytest.raises(AttributeError):
        app.state.agent_registration_service.extra_provider = object()

    org = _bootstrap_org(client)
    project_id, environment_id = _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate_allow_agent_create(client, org)

    resp = client.post(
        f"/orgs/{org['org_id']}/agents",
        json={
            "name": "scoped-bot",
            "description": "scoped",
            "trust_tier": "internal",
            "allowed_tools": [],
            "project_id": "caller-controlled",
        },
        headers=_agent_headers(org, "agent-scope-invalid-0001"),
    )

    assert resp.status_code == 422, resp.text
    ok = client.post(
        f"/orgs/{org['org_id']}/agents",
        json={
            "name": "scoped-bot",
            "description": "scoped",
            "trust_tier": "internal",
            "allowed_tools": [],
        },
        headers=_agent_headers(org, "agent-scope-ok-0001"),
    )
    assert ok.status_code == 201, ok.text
    with app.state.session_factory() as session:
        agent = session.scalars(
            sa.select(AgentRecord).where(
                AgentRecord.org_id == org["org_id"],
                AgentRecord.name == "scoped-bot",
            )
        ).one()
        receipt = session.scalars(sa.select(ManagedDecisionReceipt)).one()
        assert agent.project_id == project_id
        assert agent.environment_id == environment_id
        assert receipt.project_id == project_id
        assert receipt.environment_id == environment_id
        assert receipt.policy_bundle_id is not None


@pytest.mark.parametrize(
    ("decision", "expected_status", "expected_code"),
    [
        ("deny", 403, "POLICY_DENIED"),
        ("escalate", 202, "ESCALATE_PENDING"),
    ],
)
def test_agent_register_route_duplicate_refusals_replay_original_terminal_response(
    tmp_path: Path,
    decision: str,
    expected_status: int,
    expected_code: str,
) -> None:
    app, client = _migrated_client(tmp_path, label=f"duplicate-{decision}")
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate(client, org, rules=_rules_for_policy(decision))
    headers = _agent_headers(org, f"agent-refusal-duplicate-{decision}-0001")
    body = {"name": f"duplicate-{decision}-bot", "trust_tier": "internal"}

    first = client.post(f"/orgs/{org['org_id']}/agents", json=body, headers=headers)
    second = client.post(f"/orgs/{org['org_id']}/agents", json=body, headers=headers)

    assert first.status_code == expected_status, first.text
    assert second.status_code == expected_status, second.text
    assert first.json() == second.json()
    assert second.json()["code"] == expected_code
    _assert_single_refusal_evidence(app, org["org_id"], f"duplicate-{decision}-bot", decision)


def test_agent_register_route_rejects_forged_allow_replay_payload(
    tmp_path: Path,
) -> None:
    app, client = _migrated_client(tmp_path, label="forged-allow-replay")
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate_allow_agent_create(client, org)
    headers = _agent_headers(org, "agent-forged-allow-0001")
    body = {"name": "forged-allow-bot", "trust_tier": "internal"}

    first = client.post(f"/orgs/{org['org_id']}/agents", json=body, headers=headers)
    assert first.status_code == 201, first.text
    with app.state.session_factory.begin() as session:
        row = session.scalars(sa.select(AgentRegistrationIdempotency)).one()
        row.response = {
            **row.response,
            "name": "attacker-name",
            "trust_tier": "admin",
            "allowed_tools": ["*"],
            "status": "elevated",
        }

    replay = client.post(f"/orgs/{org['org_id']}/agents", json=body, headers=headers)

    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
    with app.state.session_factory() as session:
        assert _count_agents(session, org["org_id"], "forged-allow-bot") == 1
        assert _count(session, AgentRegistrationIdempotency) == 1
        assert _count(session, ManagedDecisionReceipt) == 1
        assert _count(session, ManagedReceiptConsumption) == 1
        assert _count(session, ManagedGovernanceEvent) == 1
        assert _count(session, ManagedOutboxMessage) == 1


def test_agent_register_route_rejects_deny_payload_upgraded_to_escalate(
    tmp_path: Path,
) -> None:
    app, client = _migrated_client(tmp_path, label="forged-deny-replay")
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate(client, org, rules=_rules_for_policy("deny"))
    headers = _agent_headers(org, "agent-forged-deny-0001")
    body = {"name": "forged-deny-bot", "trust_tier": "internal"}

    first = client.post(f"/orgs/{org['org_id']}/agents", json=body, headers=headers)
    assert first.status_code == 403, first.text
    with app.state.session_factory.begin() as session:
        row = session.scalars(sa.select(AgentRegistrationIdempotency)).one()
        row.response = {
            **row.response,
            "terminal": "escalate",
            "http_status": 202,
            "code": "ESCALATE_PENDING",
            "status": "escalate_pending",
            "detail": "agent registration requires separated approval",
        }

    replay = client.post(f"/orgs/{org['org_id']}/agents", json=body, headers=headers)

    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
    _assert_single_refusal_evidence(app, org["org_id"], "forged-deny-bot", "deny")


@pytest.mark.parametrize(
    ("decision", "expected_status", "expected_code"),
    [
        ("deny", 403, "POLICY_DENIED"),
        ("escalate", 202, "ESCALATE_PENDING"),
    ],
)
def test_agent_register_route_concurrent_refusals_converge_to_one_terminal_response(
    tmp_path: Path,
    decision: str,
    expected_status: int,
    expected_code: str,
) -> None:
    app, client = _migrated_client(tmp_path, label=f"concurrent-{decision}")
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate(client, org, rules=_rules_for_policy(decision))
    headers = _agent_headers(org, f"agent-refusal-concurrent-{decision}-0001")
    body = {"name": f"concurrent-{decision}-bot", "trust_tier": "internal"}

    def register() -> tuple[int, str | None]:
        resp = client.post(f"/orgs/{org['org_id']}/agents", json=body, headers=headers)
        code = (
            resp.json().get("code")
            if resp.headers.get("content-type", "").startswith("application/json")
            else None
        )
        return resp.status_code, code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: register(), range(2)))

    assert results == [(expected_status, expected_code), (expected_status, expected_code)]
    _assert_single_refusal_evidence(app, org["org_id"], f"concurrent-{decision}-bot", decision)


class _FailingReceiptSealer:
    def seal(self, plaintext: bytes, *, associated_data: bytes) -> dict[str, Any]:
        del plaintext, associated_data
        raise ValueError("simulated receipt artifact sealer outage")


class _MutatingReceiptIssuer:
    def __init__(
        self,
        inner: DefaultAgentRegistrationReceiptIssuer,
        mode: str,
        on_issue: Any | None = None,
    ) -> None:
        self.inner = inner
        self.mode = mode
        self.on_issue = on_issue
        self.fixed_receipt: DecisionReceipt | None = None

    def issue(self, **kwargs: Any) -> DecisionReceipt | None:
        receipt = self.inner.issue(**kwargs)
        if self.on_issue is not None:
            self.on_issue(receipt)
        if self.mode == "malformed":
            return None
        if self.mode == "pass_through":
            return receipt
        if self.mode == "invalid_signature":
            return replace(receipt, signature=f"{receipt.signature[:-2]}aa")
        if self.mode == "expired":
            return _rehashed_receipt(
                receipt,
                expires_at=(datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
            )
        if self.mode == "fixed":
            if self.fixed_receipt is None:
                self.fixed_receipt = receipt
            return self.fixed_receipt
        if self.mode == "untrusted_key":
            return _rehashed_receipt(receipt, signing_key_id="missing-test-key")
        if self.mode == "wrong_tenant":
            return _rehashed_receipt(receipt, tenant_id="wrong-tenant")
        if self.mode == "wrong_project":
            return _rehashed_receipt(receipt, project_id="wrong-project")
        if self.mode == "wrong_environment":
            return _rehashed_receipt(receipt, environment_id="wrong-environment")
        if self.mode == "wrong_action":
            return _rehashed_receipt(receipt, proposed_action="control-plane.agent.delete")
        if self.mode == "wrong_actor":
            return _rehashed_receipt(receipt, actor="user:attacker")
        if self.mode == "wrong_args":
            return _rehashed_receipt(receipt, argument_hash=sha256_json({"name": "other"}))
        if self.mode == "wrong_policy_hash":
            return _rehashed_receipt(receipt, policy_hash="f" * 64)
        if self.mode == "wrong_policy_bundle":
            return _rehashed_receipt(receipt, policy_bundle_id="wrong-policy-bundle")
        if self.mode == "wrong_validator":
            return _rehashed_receipt(receipt, validator_role="wrong-validator")
        if self.mode == "wrong_authority":
            return _rehashed_receipt(receipt, authority="wrong-authority")
        if self.mode == "wrong_audit":
            return _rehashed_receipt(receipt, audit_event_hash="e" * 64)
        raise AssertionError(f"unsupported receipt mutation mode: {self.mode}")


class _IssuanceForbidden:
    def __init__(self) -> None:
        self.calls = 0

    def issue(self, **_kwargs: Any) -> DecisionReceipt:
        self.calls += 1
        raise AssertionError("receipt issuance should not run")


def _rehashed_receipt(receipt: DecisionReceipt, **changes: Any) -> DecisionReceipt:
    mutated = replace(receipt, **changes)
    return replace(mutated, receipt_hash=mutated.compute_hash())


def _race_policy_swapper(
    case: dict[str, Any],
    app_holder: dict[str, Any],
    org_holder: dict[str, Any],
) -> Any:
    def on_issue(_receipt: DecisionReceipt) -> None:
        race = case.get("race")
        if race is None:
            return
        _replace_active_policy_direct(
            app_holder["app"],
            org_holder["org"]["org_id"],
            rules=_rules_for_policy(str(race)),
        )

    return on_issue


def _migrated_client(
    tmp_path: Path,
    *,
    label: str = "control-plane",
    receipt_mode: str | None = None,
    on_issue: Any | None = None,
    receipt_sealer: Any | None = None,
    receipt_issuer: Any | None = None,
) -> tuple[Any, TestClient]:
    database_url = f"sqlite:///{tmp_path / f'{label}.sqlite3'}"
    upgrade_database(database_url)
    issuer = local_agent_registration_issuer()
    issuer_mode = receipt_mode or ("pass_through" if on_issue is not None else None)
    effective_receipt_issuer = receipt_issuer or (
        _MutatingReceiptIssuer(
            DefaultAgentRegistrationReceiptIssuer(issuer),
            issuer_mode,
            on_issue=on_issue,
        )
        if issuer_mode is not None
        else None
    )
    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=tmp_path / f"audit-{label}",
            bootstrap_token=BOOTSTRAP_TOKEN,
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        ),
        agent_registration_issuer=issuer,
        agent_registration_receipt_sealer=receipt_sealer,
        agent_registration_receipt_issuer=effective_receipt_issuer,
    )
    return app, TestClient(app, raise_server_exceptions=False)


def _bootstrap_org(client: TestClient) -> dict[str, Any]:
    resp = client.post(
        "/orgs",
        json={
            "name": f"Acme {new_id()}",
            "admin_name": "Root Admin",
            "admin_email": f"root-{new_id()}@acme.example.com",
        },
        headers={"X-Bootstrap-Token": BOOTSTRAP_TOKEN},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _admin_headers(org: dict[str, Any]) -> dict[str, str]:
    return {"X-API-Key": org["admin_api_key"]}


def _agent_headers(org: dict[str, Any], idempotency_key: str) -> dict[str, str]:
    return {
        **_admin_headers(org),
        BOOTSTRAP_IDEMPOTENCY_HEADER: idempotency_key,
    }


def _seed_default_scope_and_trust(
    app: Any, org_id: str, *, bootstrap_trust: bool = True
) -> tuple[str, str]:
    project_id = f"project-{new_id()}"
    environment_id = f"environment-{new_id()}"
    with app.state.session_factory.begin() as session:
        assert session.get(Organization, org_id) is not None
        project = Project(id=project_id, org_id=org_id, slug="default", name="Default")
        environment = Environment(
            id=environment_id,
            org_id=org_id,
            project_id=project_id,
            slug="production",
            name="Production",
        )
        session.add_all([project, environment])
        session.flush()
        if bootstrap_trust:
            scope = ReceiptTrustScope(org_id, project_id, environment_id, DECISION_RECEIPT_PURPOSE)
            signer = app.state.agent_registration_service.issuer.signer_for_scope(
                scope,
                trust_epoch=1,
            )
            ManagedTrustLifecycleService(session).bootstrap(
                scope=scope,
                key_id=signer.key_id,
                algorithm=signer.algorithm,
                public_key_spki_der=public_spki_der_from_signer(signer),
                not_after=utcnow() + timedelta(days=1),
            )
    return project_id, environment_id


def _publish_and_activate_allow_agent_create(client: TestClient, org: dict[str, Any]) -> None:
    _publish_and_activate(
        client,
        org,
        rules=_rules_for_policy("allow"),
    )


def _rules_for_policy(policy: str) -> list[dict[str, Any]]:
    if policy == "allow":
        return [
            {
                "id": "deny-unrelated",
                "effect": "deny",
                "tools": ["unrelated.tool"],
                "reason": "unrelated tools disabled",
            }
        ]
    if policy == "deny":
        return [
            {
                "id": "deny-agent-create",
                "effect": "deny",
                "tools": [CONTROL_PLANE_AGENT_CREATE_ACTION],
                "reason": "managed agent creation disabled",
            }
        ]
    if policy == "escalate":
        return [
            {
                "id": "escalate-agent-create",
                "effect": "escalate",
                "tools": [CONTROL_PLANE_AGENT_CREATE_ACTION],
                "reason": "managed agent creation needs approval",
            }
        ]
    raise AssertionError(f"unsupported policy fixture: {policy}")


def _publish_and_activate(
    client: TestClient,
    org: dict[str, Any],
    *,
    rules: list[dict[str, Any]],
) -> None:
    publish = client.post(
        f"/orgs/{org['org_id']}/policies",
        json={"policy_id": f"policy-{new_id()}", "rules": rules},
        headers=_admin_headers(org),
    )
    assert publish.status_code == 201, publish.text
    activate = client.post(
        f"/orgs/{org['org_id']}/policies/{publish.json()['bundle_id']}/activate",
        headers=_admin_headers(org),
    )
    assert activate.status_code == 200, activate.text


def _create_user(client: TestClient, org: dict[str, Any], *, role: str) -> dict[str, str]:
    resp = client.post(
        f"/orgs/{org['org_id']}/users",
        json={
            "name": f"{role} user",
            "email": f"{role}-{new_id()}@acme.example.com",
            "role": role,
        },
        headers=_admin_headers(org),
    )
    assert resp.status_code == 201, resp.text
    return {"X-API-Key": resp.json()["api_key"]}


def _replace_active_policy_direct(app: Any, org_id: str, *, rules: list[dict[str, Any]]) -> None:
    bundle = {"id": f"race-policy-{new_id()}", "rules": rules}
    parsed = RuleSetPolicy.from_dict(bundle)
    with app.state.session_factory.begin() as session:
        for row in session.scalars(
            sa.select(PolicyBundle)
            .where(PolicyBundle.org_id == org_id, PolicyBundle.status == "active")
            .with_for_update()
        ):
            row.status = "superseded"
        session.add(
            PolicyBundle(
                org_id=org_id,
                policy_id=bundle["id"],
                version=parsed.version,
                bundle=bundle,
                status="active",
                activated_at=utcnow(),
            )
        )


def _expire_or_revoke_trust(app: Any, org_id: str, *, status: str) -> None:
    from acgs_control_plane.models import ManagedTrustKey

    with app.state.session_factory.begin() as session:
        keys = list(
            session.scalars(sa.select(ManagedTrustKey).where(ManagedTrustKey.org_id == org_id))
        )
        assert len(keys) == 1
        if status == "expired":
            keys[0].not_after = utcnow() - timedelta(days=1)
        else:
            keys[0].status = status


def _count(session: Any, model: type[Any]) -> int:
    return int(session.scalar(sa.select(sa.func.count()).select_from(model)) or 0)


def _count_agents(session: Any, org_id: str, name: str) -> int:
    return int(
        session.scalar(
            sa.select(sa.func.count())
            .select_from(AgentRecord)
            .where(AgentRecord.org_id == org_id, AgentRecord.name == name)
        )
        or 0
    )


def _count_legacy_agent_receipts(session: Any, org_id: str) -> int:
    return int(
        session.scalar(
            sa.select(sa.func.count())
            .select_from(ReceiptRow)
            .where(ReceiptRow.org_id == org_id, ReceiptRow.tool == "agent.register")
        )
        or 0
    )


def _managed_allow_receipts(session: Any) -> int:
    return int(
        session.scalar(
            sa.select(sa.func.count())
            .select_from(ManagedDecisionReceipt)
            .where(ManagedDecisionReceipt.decision == "allow")
        )
        or 0
    )


def _assert_single_refusal_evidence(
    app: Any,
    org_id: str,
    name: str,
    decision: str,
) -> None:
    with app.state.session_factory() as session:
        assert _count_agents(session, org_id, name) == 0
        assert _count(session, ManagedReceiptConsumption) == 0
        assert _count(session, AgentRegistrationIdempotency) == 1
        assert _count(session, ManagedDecisionReceipt) == 1
        assert _count(session, ManagedGovernanceEvent) == 1
        assert _count(session, ManagedOutboxMessage) == 1
        receipt = session.scalars(sa.select(ManagedDecisionReceipt)).one()
        assert receipt.decision == decision


def _assert_replay_case(tmp_path: Path, *, decision: str) -> None:
    app, client = _migrated_client(
        tmp_path,
        label=f"replay-{decision}",
        receipt_mode="fixed",
    )
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate(client, org, rules=_rules_for_policy(decision))
    first = client.post(
        f"/orgs/{org['org_id']}/agents",
        json={"name": "replay-bot", "trust_tier": "internal"},
        headers=_agent_headers(org, f"agent-replay-{decision}-0001"),
    )
    expected_first = 201 if decision == "allow" else 403
    assert first.status_code == expected_first, first.text
    second = client.post(
        f"/orgs/{org['org_id']}/agents",
        json={"name": "replay-bot", "trust_tier": "internal"},
        headers=_agent_headers(org, f"agent-replay-{decision}-0002"),
    )
    assert second.status_code == 409, second.text
    assert second.json()["code"] == "RECEIPT_ALREADY_USED"
    with app.state.session_factory() as session:
        expected_agents = 1 if decision == "allow" else 0
        assert _count_agents(session, org["org_id"], "replay-bot") == expected_agents
        assert _count(session, ManagedDecisionReceipt) == 1
        assert _count(session, ManagedGovernanceEvent) == 1
        assert _count(session, ManagedOutboxMessage) == 1


def _assert_concurrent_replay_case(tmp_path: Path) -> None:
    app, client = _migrated_client(
        tmp_path,
        label="replay-concurrent-deny",
        receipt_mode="fixed",
    )
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate(client, org, rules=_rules_for_policy("deny"))
    first = client.post(
        f"/orgs/{org['org_id']}/agents",
        json={"name": "concurrent-replay-bot", "trust_tier": "internal"},
        headers=_agent_headers(org, "agent-concurrent-replay-0001"),
    )
    assert first.status_code == 403, first.text

    def replay(index: int) -> tuple[int, str | None]:
        resp = client.post(
            f"/orgs/{org['org_id']}/agents",
            json={"name": "concurrent-replay-bot", "trust_tier": "internal"},
            headers=_agent_headers(org, f"agent-concurrent-replay-000{index}"),
        )
        code = (
            resp.json().get("code")
            if resp.headers.get("content-type", "").startswith("application/json")
            else None
        )
        return resp.status_code, code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(replay, range(2, 4)))

    assert results == [(409, "RECEIPT_ALREADY_USED"), (409, "RECEIPT_ALREADY_USED")]
    with app.state.session_factory() as session:
        assert _count_agents(session, org["org_id"], "concurrent-replay-bot") == 0
        assert _count(session, ManagedDecisionReceipt) == 1
        assert _count(session, ManagedGovernanceEvent) == 1
        assert _count(session, ManagedOutboxMessage) == 1
