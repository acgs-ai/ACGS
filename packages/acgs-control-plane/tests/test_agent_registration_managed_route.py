"""Route-level tests for canonical managed agent registration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from gove_zone.decision import sha256_json
from gove_zone.policy import RuleSetPolicy
from gove_zone.receipt import DecisionReceipt, safe_result_hash
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, ReceiptTrustScope

import acgs_control_plane.approvals as approvals_module
from acgs_control_plane.agent_registration import (
    DefaultAgentRegistrationReceiptIssuer,
    _to_utc,
    local_agent_registration_issuer,
)
from acgs_control_plane.app import create_app
from acgs_control_plane.approvals import approval_payload_aad, local_approval_payload_sealer
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.managed_mutations import (
    CONTROL_PLANE_AGENT_CREATE_ACTION,
    CONTROL_PLANE_APPROVAL_VOTE_ACTION,
)
from acgs_control_plane.migrations import upgrade_database
from acgs_control_plane.models import (
    AgentRecord,
    AgentRegistrationIdempotency,
    ApprovalOutcome,
    ApprovalRequest,
    ApprovalResumeAuthorization,
    ApprovalVote,
    Environment,
    EnvironmentPolicyHead,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedGovernanceEventHead,
    ManagedMutationAttempt,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    Organization,
    PolicyVersion,
    Project,
    ReceiptRow,
    User,
    new_id,
    utcnow,
)
from acgs_control_plane.policy_registry import (
    POLICY_ENVELOPE_PURPOSE,
    _signed_envelope,
    local_policy_registry_issuer,
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
        receipt = session.scalars(_managed_agent_receipt_select()).one()
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
        headers=_agent_headers(org, "agent-audited-mirror-0001"),
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
        assert _managed_agent_receipts(session) == 0
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
                assert _managed_agent_receipts(session) == 0, case["name"]
                assert _count(session, ManagedGovernanceEvent) == 0, case["name"]
                assert _count(session, ManagedOutboxMessage) == 0, case["name"]
                assert _count(session, AgentRegistrationIdempotency) == 0, case["name"]
            else:
                receipt = session.scalars(_managed_agent_receipt_select()).one()
                assert receipt.decision == case["evidence"], case["name"]
                assert _count(session, ManagedGovernanceEvent) == 1, case["name"]
                assert _count(session, ManagedOutboxMessage) == 1, case["name"]
                assert _count(session, AgentRegistrationIdempotency) == 1, case["name"]
                if case["evidence"] == "escalate":
                    approval = session.scalars(sa.select(ApprovalRequest)).one()
                    assert resp.json()["approval_request_id"] == approval.id, case["name"]
                    assert resp.json()["approval_request_hash"] == approval.request_hash, case[
                        "name"
                    ]
                    assert approval.org_id == org["org_id"], case["name"]
                    assert approval.project_id == receipt.project_id, case["name"]
                    assert approval.environment_id == receipt.environment_id, case["name"]
                    assert approval.action == CONTROL_PLANE_AGENT_CREATE_ACTION, case["name"]
                    assert approval.escalate_receipt_id == receipt.receipt_id, case["name"]
                    assert approval.escalate_receipt_hash == receipt.receipt_hash, case["name"]
                    assert approval.escalate_audit_event_hash == receipt.audit_event_hash, case[
                        "name"
                    ]
                    assert approval.status == "pending", case["name"]
                    assert approval.quorum_threshold == 1, case["name"]
                    assert "blocked-bot" not in str(approval.sealed_arguments), case["name"]
                else:
                    assert _count(session, ApprovalRequest) == 0, case["name"]

    _assert_replay_case(tmp_path, decision="allow")
    _assert_replay_case(tmp_path, decision="deny")
    _assert_concurrent_replay_case(tmp_path)


def test_approval_vote_and_resume_route_execute_parked_agent_registration_once(
    tmp_path: Path,
) -> None:
    app, client = _migrated_client(tmp_path)
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate(client, org, rules=_rules_for_policy("escalate"))

    request_resp = client.post(
        f"/orgs/{org['org_id']}/agents",
        json={
            "name": "approved-bot",
            "description": "parked registration",
            "trust_tier": "internal",
            "allowed_tools": ["deploy.staging"],
        },
        headers=_agent_headers(org, "approval-flow-request-0001"),
    )

    assert request_resp.status_code == 202, request_resp.text
    approval_request_id = request_resp.json()["approval_request_id"]
    assert _count_agents_by_app(app, org["org_id"], "approved-bot") == 0

    self_vote = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/votes",
        json={"decision": "approve"},
        headers=_agent_headers(org, "approval-flow-self-vote-0001"),
    )
    assert self_vote.status_code == 403, self_vote.text
    assert self_vote.json()["code"] == "APPROVAL_SELF_APPROVAL_DENIED"
    assert _count_agents_by_app(app, org["org_id"], "approved-bot") == 0

    approver_headers = {
        **_create_user(client, org, role="org_admin"),
        BOOTSTRAP_IDEMPOTENCY_HEADER: "approval-flow-vote-0001",
    }
    vote = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/votes",
        json={"decision": "approve"},
        headers=approver_headers,
    )
    assert vote.status_code == 200, vote.text
    assert vote.json()["approval_request_id"] == approval_request_id
    assert vote.json()["decision"] == "approve"
    assert vote.json()["outcome"] == "approved"
    assert vote.json()["receipt_id"]

    resume_headers = {
        **{k: v for k, v in approver_headers.items() if k != BOOTSTRAP_IDEMPOTENCY_HEADER},
        BOOTSTRAP_IDEMPOTENCY_HEADER: "approval-flow-resume-0001",
    }
    resume = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers=resume_headers,
    )
    assert resume.status_code == 201, resume.text
    resumed = resume.json()
    assert resumed["name"] == "approved-bot"
    assert resumed["description"] == "parked registration"
    assert resumed["trust_tier"] == "internal"
    assert resumed["allowed_tools"] == ["deploy.staging"]
    assert resumed["receipt_id"]

    replay = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers=resume_headers,
    )
    assert replay.status_code == 201, replay.text
    assert replay.json() == resumed

    second_resume = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers={
            **{k: v for k, v in approver_headers.items() if k != BOOTSTRAP_IDEMPOTENCY_HEADER},
            BOOTSTRAP_IDEMPOTENCY_HEADER: "approval-flow-resume-0002",
        },
    )
    assert second_resume.status_code == 409, second_resume.text
    assert second_resume.json()["code"] == "APPROVAL_ALREADY_RESUMED"

    with app.state.session_factory() as session:
        assert _count_agents(session, org["org_id"], "approved-bot") == 1
        receipts = list(
            session.scalars(
                sa.select(ManagedDecisionReceipt).where(
                    ManagedDecisionReceipt.org_id == org["org_id"]
                )
            )
        )
        assert [row.decision for row in receipts].count("escalate") == 1
        assert [row.decision for row in receipts].count("allow") >= 2
        resume_receipt = session.scalars(
            sa.select(ManagedDecisionReceipt).where(
                ManagedDecisionReceipt.receipt_id == resumed["receipt_id"]
            )
        ).one()
        assert resume_receipt.proposed_action == CONTROL_PLANE_AGENT_CREATE_ACTION
        assert resume_receipt.actor == f"user:{org['admin_user_id']}"
        assert resume_receipt.projection["approval_chain_hash"] != sha256_json({})
        assert _count(session, ApprovalRequest) == 1
        assert _count(session, ApprovalVote) == 1
        assert _count(session, ApprovalOutcome) == 1
        assert _count(session, ApprovalResumeAuthorization) == 1
        assert _count(session, ManagedReceiptConsumption) == 2
        assert _count(session, AgentRecord) == 1


def test_approval_resume_idempotency_replay_survives_trust_rotation(
    tmp_path: Path,
) -> None:
    app, client = _migrated_client(tmp_path)
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate(client, org, rules=_rules_for_policy("escalate"))
    first_request_id, first_approver = _park_and_approve_existing_org_agent_registration(
        client,
        org,
        name="rotation-replay-committed",
    )
    second_request_id, second_approver = _park_and_approve_existing_org_agent_registration(
        client,
        org,
        name="rotation-replay-stale",
    )
    first_headers = {
        **first_approver,
        BOOTSTRAP_IDEMPOTENCY_HEADER: "rotation-replay-resume-0001",
    }
    first = client.post(
        f"/orgs/{org['org_id']}/approvals/{first_request_id}/resume",
        headers=first_headers,
    )
    assert first.status_code == 201, first.text
    resumed = first.json()
    _rotate_receipt_trust(app, org["org_id"])
    before_replay = _approval_counts(app, org["org_id"])

    replay = client.post(
        f"/orgs/{org['org_id']}/approvals/{first_request_id}/resume",
        headers=first_headers,
    )

    assert replay.status_code == 201, replay.text
    assert replay.json() == resumed
    after_replay = _approval_counts(app, org["org_id"])
    assert after_replay == before_replay

    fresh = client.post(
        f"/orgs/{org['org_id']}/approvals/{second_request_id}/resume",
        headers={
            **second_approver,
            BOOTSTRAP_IDEMPOTENCY_HEADER: "rotation-replay-fresh-0001",
        },
    )

    assert fresh.status_code == 409, fresh.text
    assert fresh.json()["code"] == "APPROVAL_TRUST_STALE"
    after_fresh = _approval_counts(app, org["org_id"])
    assert after_fresh == after_replay


def test_approval_resume_fails_closed_when_policy_changed_after_approval(tmp_path: Path) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    _replace_active_policy_direct(app, org["org_id"], rules=_rules_for_policy("deny"))
    before = _approval_counts(app, org["org_id"])

    resp = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers={"X-API-Key": approver_api_key, BOOTSTRAP_IDEMPOTENCY_HEADER: "stale-resume-0001"},
    )

    assert resp.status_code == 409, resp.text
    assert resp.json()["code"] == "APPROVAL_POLICY_STALE"
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]
    assert after["consumptions"] == before["consumptions"]


@pytest.mark.parametrize("mutation", ["inactive", "role_loss"])
def test_approval_resume_fails_closed_when_requester_loses_authority(
    tmp_path: Path,
    mutation: str,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    with app.state.session_factory.begin() as session:
        user = session.get(User, org["admin_user_id"])
        assert user is not None
        if mutation == "inactive":
            user.active = False
        else:
            user.role = "viewer"
    before = _approval_counts(app, org["org_id"])

    resp = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers={
            "X-API-Key": approver_api_key,
            BOOTSTRAP_IDEMPOTENCY_HEADER: f"requester-{mutation}-0001",
        },
    )

    assert resp.status_code == 409, resp.text
    assert resp.json()["code"] in {
        "APPROVAL_REQUESTER_INACTIVE",
        "APPROVAL_REQUESTER_UNAUTHORIZED",
    }
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]
    assert after["consumptions"] == before["consumptions"]


@pytest.mark.parametrize(
    ("mutation", "expected_status", "expected_code"),
    [
        ("inactive", 409, "APPROVAL_CALLER_STALE"),
        ("role_loss", 403, "APPROVAL_ROLE_DENIED"),
        ("credential_rotation", 409, "APPROVAL_CREDENTIAL_STALE"),
    ],
)
def test_approval_vote_fails_closed_when_caller_changes_after_auth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected_status: int,
    expected_code: str,
) -> None:
    app, client = _migrated_client(tmp_path)
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate(client, org, rules=_rules_for_policy("escalate"))
    request_resp = client.post(
        f"/orgs/{org['org_id']}/agents",
        json={"name": "vote-caller-stale-bot", "trust_tier": "internal"},
        headers=_agent_headers(org, "vote-caller-stale-request-0001"),
    )
    assert request_resp.status_code == 202, request_resp.text
    approval_request_id = request_resp.json()["approval_request_id"]
    approver = _create_user(client, org, role="org_admin")
    _install_after_auth_caller_mutation(monkeypatch, app, mutation=mutation)
    before = _approval_counts(app, org["org_id"])

    resp = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/votes",
        json={"decision": "approve"},
        headers={
            **approver,
            BOOTSTRAP_IDEMPOTENCY_HEADER: f"vote-caller-stale-{mutation}-0001",
        },
    )

    assert resp.status_code == expected_status, resp.text
    assert resp.json()["code"] == expected_code
    after = _approval_counts(app, org["org_id"])
    assert after == before


@pytest.mark.parametrize(
    ("mutation", "expected_status", "expected_code"),
    [
        ("inactive", 409, "APPROVAL_CALLER_STALE"),
        ("role_loss", 403, "APPROVAL_ROLE_DENIED"),
        ("credential_rotation", 409, "APPROVAL_CREDENTIAL_STALE"),
    ],
)
def test_approval_resume_fails_closed_when_caller_changes_after_auth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected_status: int,
    expected_code: str,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    _install_after_auth_caller_mutation(monkeypatch, app, mutation=mutation)
    before = _approval_counts(app, org["org_id"])

    resp = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers={
            "X-API-Key": approver_api_key,
            BOOTSTRAP_IDEMPOTENCY_HEADER: f"resume-caller-stale-{mutation}-0001",
        },
    )

    assert resp.status_code == expected_status, resp.text
    assert resp.json()["code"] == expected_code
    after = _approval_counts(app, org["org_id"])
    assert after == before


@pytest.mark.parametrize(
    ("mutation", "expected_status", "expected_code"),
    [
        ("inactive", 409, "APPROVAL_CALLER_STALE"),
        ("role_loss", 403, "APPROVAL_ROLE_DENIED"),
        ("credential_rotation", 409, "APPROVAL_CREDENTIAL_STALE"),
    ],
)
def test_approval_resume_replay_fails_closed_when_caller_changes_after_auth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected_status: int,
    expected_code: str,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    headers = {
        "X-API-Key": approver_api_key,
        BOOTSTRAP_IDEMPOTENCY_HEADER: f"resume-replay-caller-stale-{mutation}-0001",
    }
    first = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers=headers,
    )
    assert first.status_code == 201, first.text
    _install_after_auth_caller_mutation(monkeypatch, app, mutation=mutation)
    before = _approval_counts(app, org["org_id"])

    replay = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers=headers,
    )

    assert replay.status_code == expected_status, replay.text
    assert replay.json()["code"] == expected_code
    after = _approval_counts(app, org["org_id"])
    assert after == before


@pytest.mark.parametrize("mutation", ["inactive", "deleted", "role_loss"])
def test_approval_resume_fails_closed_when_vote_approver_is_stale(
    tmp_path: Path,
    mutation: str,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, _approver_api_key = _park_and_approve_agent_registration(app, client)
    resume_admin = _create_user(client, org, role="org_admin")
    with app.state.session_factory.begin() as session:
        request = session.get(ApprovalRequest, approval_request_id)
        assert request is not None
        vote = session.scalars(sa.select(ApprovalVote)).one()
        receipt = _vote_receipt_for_vote(session, request, vote)
        assert receipt.actor.startswith("user:")
        voter_user_id = receipt.actor.removeprefix("user:")
        voter = session.get(User, voter_user_id)
        assert voter is not None
        if mutation == "inactive":
            voter.active = False
        elif mutation == "role_loss":
            voter.role = "viewer"
        elif mutation != "deleted":  # pragma: no cover - parametrization guard
            raise AssertionError(f"unsupported stale approver mutation: {mutation}")
    if mutation == "deleted":
        _delete_user_direct(app, voter_user_id)
    before = _approval_counts(app, org["org_id"])

    resp = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers={
            **resume_admin,
            BOOTSTRAP_IDEMPOTENCY_HEADER: f"stale-voter-{mutation}-0001",
        },
    )

    assert resp.status_code == 409, resp.text
    assert resp.json()["code"] == "APPROVAL_APPROVER_STALE"
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]
    assert after["consumptions"] == before["consumptions"]


@pytest.mark.parametrize(
    "mutation",
    [
        "aad",
        "column",
        "ciphertext",
        "approver_role",
        "escalate_receipt_id",
        "escalate_receipt_hash",
        "created_at",
        "expires_at",
        "status",
    ],
)
def test_approval_resume_fails_closed_when_request_binding_is_tampered(
    tmp_path: Path,
    mutation: str,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    with app.state.session_factory.begin() as session:
        request = session.get(ApprovalRequest, approval_request_id)
        assert request is not None
        if mutation == "aad":
            aad = dict(request.aad)
            aad["policy_hash"] = "0" * 64
            request.aad = aad
        elif mutation == "column":
            request.policy_hash = "0" * 64
        elif mutation == "ciphertext":
            sealed = dict(request.sealed_arguments)
            sealed["ciphertext"] = sealed["ciphertext"][:-4] + "AAAA"
            request.sealed_arguments = sealed
        elif mutation == "approver_role":
            request.approver_role = "security_admin"
        elif mutation == "escalate_receipt_id":
            pass
        elif mutation == "escalate_receipt_hash":
            request.escalate_receipt_hash = "0" * 64
        elif mutation == "created_at":
            request.created_at = request.created_at + timedelta(seconds=1)
        elif mutation == "expires_at":
            request.expires_at = request.expires_at + timedelta(seconds=1)
        elif mutation == "status":
            pass
        else:  # pragma: no cover - parametrization guard
            raise AssertionError(f"unsupported binding tamper mutation: {mutation}")
    if mutation == "escalate_receipt_id":
        _corrupt_approval_request_column(
            app,
            approval_request_id,
            column="escalate_receipt_id",
            value=f"tampered-{new_id()}",
        )
    elif mutation == "status":
        _corrupt_approval_request_column(
            app,
            approval_request_id,
            column="status",
            value="approved",
        )
    before = _approval_counts(app, org["org_id"])

    resp = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers={
            "X-API-Key": approver_api_key,
            BOOTSTRAP_IDEMPOTENCY_HEADER: f"tamper-{mutation}-0001",
        },
    )

    assert resp.status_code == 503, resp.text
    assert resp.json()["code"] in {
        "APPROVAL_BINDING_INVALID",
        "APPROVAL_PAYLOAD_INVALID",
        "TX_ABORTED",
    }
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]
    assert after["consumptions"] == before["consumptions"]


def test_approval_resume_fails_closed_when_request_expiry_exceeds_source_receipt_expiry(
    tmp_path: Path,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    with app.state.session_factory.begin() as session:
        request = session.get(ApprovalRequest, approval_request_id)
        assert request is not None
        sealer = local_approval_payload_sealer()
        old_binding = dict(request.aad)
        plaintext = sealer.unseal(
            request.sealed_arguments,
            associated_data=approval_payload_aad(
                approval_request_id=request.id,
                binding=old_binding,
            ),
        )
        extended_expiry = request.expires_at + timedelta(minutes=5)
        new_binding = {
            **old_binding,
            "expires_at": _test_canonical_timestamp(extended_expiry),
        }
        request.expires_at = extended_expiry
        request.aad = new_binding
        request.request_hash = sha256_json(new_binding)
        request.sealed_arguments = dict(
            sealer.seal(
                plaintext,
                associated_data=approval_payload_aad(
                    approval_request_id=request.id,
                    binding=new_binding,
                ),
            )
        )
    before = _approval_counts(app, org["org_id"])

    resp = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers={
            "X-API-Key": approver_api_key,
            BOOTSTRAP_IDEMPOTENCY_HEADER: "expiry-source-tamper-0001",
        },
    )

    assert resp.status_code == 503, resp.text
    assert resp.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]
    assert after["consumptions"] == before["consumptions"]


@pytest.mark.parametrize("mutation", ["vote_deleted", "outcome_forged"])
def test_approval_resume_fails_closed_when_votes_deleted_or_outcome_forged(
    tmp_path: Path,
    mutation: str,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    with app.state.session_factory.begin() as session:
        if mutation == "vote_deleted":
            session.delete(session.scalars(sa.select(ApprovalVote)).one())
        else:
            outcome = session.scalars(sa.select(ApprovalOutcome)).one()
            outcome.quorum_digest = "0" * 64
            outcome.approver_set_hash = "0" * 64
    before = _approval_counts(app, org["org_id"])

    resp = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers={
            "X-API-Key": approver_api_key,
            BOOTSTRAP_IDEMPOTENCY_HEADER: f"vote-outcome-{mutation}-0001",
        },
    )

    assert resp.status_code == 503, resp.text
    assert resp.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]
    assert after["consumptions"] == before["consumptions"]


@pytest.mark.parametrize("mutation", ["missing_consumption", "missing_attempt", "failed_attempt"])
def test_approval_resume_fails_closed_when_vote_execution_evidence_is_invalid(
    tmp_path: Path,
    mutation: str,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    with app.state.session_factory.begin() as session:
        request = session.get(ApprovalRequest, approval_request_id)
        assert request is not None
        vote = session.scalars(sa.select(ApprovalVote)).one()
        receipt = _vote_receipt_for_vote(session, request, vote)
        if mutation == "missing_consumption":
            session.delete(_consumption_for_receipt(session, receipt))
        elif mutation == "missing_attempt":
            session.delete(_attempt_for_receipt(session, receipt))
        elif mutation == "failed_attempt":
            attempt = _attempt_for_receipt(session, receipt)
            attempt.status = "failed"
            attempt.failure_class_hash = sha256_json("test.failure")
            attempt.failure_digest = sha256_json("test.failure.digest")
        else:  # pragma: no cover - parametrization guard
            raise AssertionError(f"unsupported vote execution evidence mutation: {mutation}")
    before = _approval_counts(app, org["org_id"])

    resp = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers={
            "X-API-Key": approver_api_key,
            BOOTSTRAP_IDEMPOTENCY_HEADER: f"vote-execution-{mutation}-0001",
        },
    )

    assert resp.status_code == 503, resp.text
    assert resp.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]
    assert after["consumptions"] == before["consumptions"]


def test_approval_resume_fails_closed_when_source_escalate_sealed_receipt_is_tampered(
    tmp_path: Path,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    with app.state.session_factory.begin() as session:
        request = session.get(ApprovalRequest, approval_request_id)
        assert request is not None
        receipt = session.scalars(
            sa.select(ManagedDecisionReceipt).where(
                ManagedDecisionReceipt.receipt_id == request.escalate_receipt_id
            )
        ).one()
        sealed = dict(receipt.projection["sealed_receipt"])
        sealed["ciphertext"] = sealed["ciphertext"][:-4] + "AAAA"
        receipt.projection = {**receipt.projection, "sealed_receipt": sealed}
    before = _approval_counts(app, org["org_id"])

    resp = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers={
            "X-API-Key": approver_api_key,
            BOOTSTRAP_IDEMPOTENCY_HEADER: "source-sealed-tamper-0001",
        },
    )

    assert resp.status_code == 503, resp.text
    assert resp.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]
    assert after["consumptions"] == before["consumptions"]


@pytest.mark.parametrize("target", ["source", "vote"])
def test_approval_resume_fails_closed_when_evidence_event_chain_position_is_tampered(
    tmp_path: Path,
    target: str,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    with app.state.session_factory.begin() as session:
        request = session.get(ApprovalRequest, approval_request_id)
        assert request is not None
        if target == "source":
            receipt = session.scalars(
                sa.select(ManagedDecisionReceipt).where(
                    ManagedDecisionReceipt.receipt_id == request.escalate_receipt_id
                )
            ).one()
        elif target == "vote":
            vote = session.scalars(sa.select(ApprovalVote)).one()
            receipt = _vote_receipt_for_vote(session, request, vote)
        else:  # pragma: no cover - parametrization guard
            raise AssertionError(f"unsupported event-chain tamper target: {target}")
        event = _event_for_receipt(session, receipt)
        event.previous_hash = "1" * 64
        _recompute_event_and_outbox_hashes(session, event)
    before = _approval_counts(app, org["org_id"])

    resp = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers={
            "X-API-Key": approver_api_key,
            BOOTSTRAP_IDEMPOTENCY_HEADER: f"chain-{target}-tamper-0001",
        },
    )

    assert resp.status_code == 503, resp.text
    assert resp.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]
    assert after["consumptions"] == before["consumptions"]


def test_approval_resume_fails_closed_when_source_genesis_is_corrupted_and_head_recomputed(
    tmp_path: Path,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    with app.state.session_factory.begin() as session:
        request = session.get(ApprovalRequest, approval_request_id)
        assert request is not None
        source_receipt = session.scalars(
            sa.select(ManagedDecisionReceipt).where(
                ManagedDecisionReceipt.receipt_id == request.escalate_receipt_id
            )
        ).one()
        source = _event_for_receipt(session, source_receipt)
        vote = session.scalars(
            sa.select(ManagedGovernanceEvent).where(
                ManagedGovernanceEvent.org_id == source.org_id,
                ManagedGovernanceEvent.project_id == source.project_id,
                ManagedGovernanceEvent.environment_id == source.environment_id,
                ManagedGovernanceEvent.sequence == source.sequence + 1,
            )
        ).one()
        source.previous_hash = "1" * 64
        _recompute_event_and_outbox_hashes(session, source)
        vote.previous_hash = source.event_hash
        _recompute_event_and_outbox_hashes(session, vote, update_head=True)
    before = _approval_counts(app, org["org_id"])

    resp = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers={
            "X-API-Key": approver_api_key,
            BOOTSTRAP_IDEMPOTENCY_HEADER: "chain-source-genesis-recomputed-0001",
        },
    )

    assert resp.status_code == 503, resp.text
    assert resp.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]
    assert after["consumptions"] == before["consumptions"]


def test_approval_resume_fails_closed_when_unrelated_predecessor_outbox_is_corrupted(
    tmp_path: Path,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    with app.state.session_factory.begin() as session:
        request = session.get(ApprovalRequest, approval_request_id)
        assert request is not None
        vote = session.scalars(sa.select(ApprovalVote)).one()
        vote_receipt = _vote_receipt_for_vote(session, request, vote)
        vote_event = _event_for_receipt(session, vote_receipt)
        predecessor = session.scalars(
            sa.select(ManagedGovernanceEvent).where(
                ManagedGovernanceEvent.org_id == vote_event.org_id,
                ManagedGovernanceEvent.project_id == vote_event.project_id,
                ManagedGovernanceEvent.environment_id == vote_event.environment_id,
                ManagedGovernanceEvent.sequence == vote_event.sequence - 1,
            )
        ).one()
        predecessor_outbox = session.scalars(
            sa.select(ManagedOutboxMessage).where(
                ManagedOutboxMessage.managed_event_id == predecessor.id
            )
        ).one()
        predecessor_outbox.payload = {
            **predecessor_outbox.payload,
            "result_hash": "0" * 64,
        }
        predecessor_outbox.payload_digest = sha256_json(predecessor_outbox.payload)
        _recompute_event_and_outbox_hashes(session, vote_event, update_head=True)
    before = _approval_counts(app, org["org_id"])

    resp = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers={
            "X-API-Key": approver_api_key,
            BOOTSTRAP_IDEMPOTENCY_HEADER: "chain-unrelated-outbox-0001",
        },
    )

    assert resp.status_code == 503, resp.text
    assert resp.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]
    assert after["consumptions"] == before["consumptions"]


def test_approval_resume_fails_closed_when_predecessor_decision_column_is_corrupted(
    tmp_path: Path,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    with app.state.session_factory.begin() as session:
        request = session.get(ApprovalRequest, approval_request_id)
        assert request is not None
        source_receipt = session.scalars(
            sa.select(ManagedDecisionReceipt).where(
                ManagedDecisionReceipt.receipt_id == request.escalate_receipt_id
            )
        ).one()
        predecessor = _event_for_receipt(session, source_receipt)
        predecessor.decision = "allow"
    before = _approval_counts(app, org["org_id"])

    resp = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers={
            "X-API-Key": approver_api_key,
            BOOTSTRAP_IDEMPOTENCY_HEADER: "chain-predecessor-decision-0001",
        },
    )

    assert resp.status_code == 503, resp.text
    assert resp.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]
    assert after["consumptions"] == before["consumptions"]


def test_approval_resume_fails_closed_when_predecessor_payload_is_recomputed(
    tmp_path: Path,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    with app.state.session_factory.begin() as session:
        request = session.get(ApprovalRequest, approval_request_id)
        assert request is not None
        vote = session.scalars(sa.select(ApprovalVote)).one()
        vote_receipt = _vote_receipt_for_vote(session, request, vote)
        vote_event = _event_for_receipt(session, vote_receipt)
        predecessor = session.scalars(
            sa.select(ManagedGovernanceEvent).where(
                ManagedGovernanceEvent.org_id == vote_event.org_id,
                ManagedGovernanceEvent.project_id == vote_event.project_id,
                ManagedGovernanceEvent.environment_id == vote_event.environment_id,
                ManagedGovernanceEvent.sequence == vote_event.sequence - 1,
            )
        ).one()
        predecessor.payload = {**predecessor.payload, "actor_hash": "0" * 64}
        _recompute_event_and_outbox_hashes(session, predecessor)
        vote_event.previous_hash = predecessor.event_hash
        _recompute_event_and_outbox_hashes(session, vote_event, update_head=True)
    before = _approval_counts(app, org["org_id"])

    resp = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers={
            "X-API-Key": approver_api_key,
            BOOTSTRAP_IDEMPOTENCY_HEADER: "chain-predecessor-payload-0001",
        },
    )

    assert resp.status_code == 503, resp.text
    assert resp.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]
    assert after["consumptions"] == before["consumptions"]


@pytest.mark.parametrize("decision", ["deny", "escalate"])
def test_approval_vote_denial_records_non_executable_evidence_without_vote(
    tmp_path: Path,
    decision: str,
) -> None:
    app, client = _migrated_client(tmp_path)
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate(client, org, rules=_rules_for_policy("escalate"))
    request_resp = client.post(
        f"/orgs/{org['org_id']}/agents",
        json={"name": "vote-blocked-bot", "trust_tier": "internal"},
        headers=_agent_headers(org, f"vote-block-request-{decision}-0001"),
    )
    assert request_resp.status_code == 202, request_resp.text
    approval_request_id = request_resp.json()["approval_request_id"]
    _replace_active_policy_direct(
        app,
        org["org_id"],
        rules=[
            {
                "id": f"{decision}-approval-vote",
                "effect": decision,
                "tools": [CONTROL_PLANE_APPROVAL_VOTE_ACTION],
                "reason": "approval votes paused",
            }
        ],
    )
    approver = _create_user(client, org, role="org_admin")
    before = _approval_counts(app, org["org_id"])

    resp = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/votes",
        json={"decision": "approve"},
        headers={
            **approver,
            BOOTSTRAP_IDEMPOTENCY_HEADER: f"vote-block-{decision}-0001",
        },
    )

    assert resp.status_code == (202 if decision == "escalate" else 403), resp.text
    assert resp.json()["code"] == (
        "ESCALATE_PENDING" if decision == "escalate" else "POLICY_DENIED"
    )
    after = _approval_counts(app, org["org_id"])
    assert after["votes"] == before["votes"]
    assert after["agents"] == before["agents"]
    assert after["consumptions"] == before["consumptions"]
    assert after["all_receipts"] == before["all_receipts"] + 1
    with app.state.session_factory() as session:
        receipt = session.scalars(
            sa.select(ManagedDecisionReceipt)
            .where(
                ManagedDecisionReceipt.org_id == org["org_id"],
                ManagedDecisionReceipt.proposed_action == CONTROL_PLANE_APPROVAL_VOTE_ACTION,
            )
            .order_by(ManagedDecisionReceipt.created_at.desc())
        ).first()
        assert receipt is not None
        assert receipt.decision == decision
        assert _count(session, ManagedGovernanceEvent) == before["events"] + 1
        assert _count(session, ManagedOutboxMessage) == before["outbox"] + 1


@pytest.mark.parametrize("mutation", ["receipt", "consumption", "event", "outbox", "agent_scope"])
def test_approval_resume_replay_fails_closed_when_committed_projection_is_tampered(
    tmp_path: Path,
    mutation: str,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    headers = {
        "X-API-Key": approver_api_key,
        BOOTSTRAP_IDEMPOTENCY_HEADER: "replay-integrity-resume-0001",
    }
    first = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers=headers,
    )
    assert first.status_code == 201, first.text
    before = _approval_counts(app, org["org_id"])
    with app.state.session_factory.begin() as session:
        resume = session.scalars(sa.select(ApprovalResumeAuthorization)).one()
        if mutation == "receipt":
            receipt = session.scalars(
                sa.select(ManagedDecisionReceipt).where(
                    ManagedDecisionReceipt.receipt_id == resume.resume_receipt_id
                )
            ).one()
            projection = dict(receipt.projection)
            projection["approval_chain_hash"] = "0" * 64
            receipt.projection = projection
        elif mutation == "consumption":
            consumption = session.scalars(
                sa.select(ManagedReceiptConsumption).where(
                    ManagedReceiptConsumption.receipt_hash == resume.resume_receipt_hash
                )
            ).one()
            session.delete(consumption)
        elif mutation == "event":
            event = session.scalars(
                sa.select(ManagedGovernanceEvent).where(
                    ManagedGovernanceEvent.event_hash == resume.resume_audit_event_hash
                )
            ).one()
            payload = dict(event.payload)
            payload["result_hash"] = "0" * 64
            event.payload = payload
        elif mutation == "outbox":
            outbox = session.scalars(
                sa.select(ManagedOutboxMessage).where(
                    ManagedOutboxMessage.managed_event_id
                    == sa.select(ManagedGovernanceEvent.id)
                    .where(ManagedGovernanceEvent.event_hash == resume.resume_audit_event_hash)
                    .scalar_subquery()
                )
            ).one()
            payload = dict(outbox.payload)
            payload["result_hash"] = "0" * 64
            outbox.payload = payload
        else:
            pass
    if mutation == "agent_scope":
        raw_connection = app.state.engine.raw_connection()
        try:
            cursor = raw_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=OFF")
            cursor.execute(
                "UPDATE approval_resume_authorizations SET resumed_agent_id = ?",
                (new_id(),),
            )
            raw_connection.commit()
            cursor.execute("PRAGMA foreign_keys=ON")
            raw_connection.commit()
        finally:
            raw_connection.close()

    replay = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers=headers,
    )

    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]


@pytest.mark.parametrize("mutation", ["missing_attempt", "failed_attempt", "wrong_scope"])
def test_approval_resume_replay_fails_closed_when_resume_attempt_is_invalid(
    tmp_path: Path,
    mutation: str,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    headers = {
        "X-API-Key": approver_api_key,
        BOOTSTRAP_IDEMPOTENCY_HEADER: "replay-resume-attempt-0001",
    }
    first = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers=headers,
    )
    assert first.status_code == 201, first.text
    with app.state.session_factory.begin() as session:
        resume = session.scalars(sa.select(ApprovalResumeAuthorization)).one()
        receipt = session.scalars(
            sa.select(ManagedDecisionReceipt).where(
                ManagedDecisionReceipt.receipt_id == resume.resume_receipt_id
            )
        ).one()
        attempt = _attempt_for_receipt(session, receipt)
        attempt_id = attempt.id
        if mutation == "missing_attempt":
            session.delete(attempt)
        elif mutation == "failed_attempt":
            attempt.status = "failed"
            attempt.failure_class_hash = sha256_json("test.failure")
            attempt.failure_digest = sha256_json("test.failure.digest")
        elif mutation != "wrong_scope":  # pragma: no cover - parametrization guard
            raise AssertionError(f"unsupported resume attempt mutation: {mutation}")
    if mutation == "wrong_scope":
        _corrupt_attempt_project_direct(app, attempt_id, project_id=f"wrong-project-{new_id()}")
    before = _approval_counts(app, org["org_id"])

    replay = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers=headers,
    )

    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]
    assert after["consumptions"] == before["consumptions"]


@pytest.mark.parametrize(
    ("target", "recompute_digest"),
    [
        ("event", False),
        ("event", True),
        ("outbox", False),
        ("outbox", True),
    ],
)
def test_approval_resume_replay_rejects_receipt_hash_tamper_even_when_digests_recomputed(
    tmp_path: Path,
    target: str,
    recompute_digest: bool,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    headers = {
        "X-API-Key": approver_api_key,
        BOOTSTRAP_IDEMPOTENCY_HEADER: "replay-receipt-hash-tamper-0001",
    }
    first = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers=headers,
    )
    assert first.status_code == 201, first.text
    before = _approval_counts(app, org["org_id"])
    with app.state.session_factory.begin() as session:
        resume = session.scalars(sa.select(ApprovalResumeAuthorization)).one()
        event = session.scalars(
            sa.select(ManagedGovernanceEvent).where(
                ManagedGovernanceEvent.event_hash == resume.resume_audit_event_hash
            )
        ).one()
        outbox = session.scalars(
            sa.select(ManagedOutboxMessage).where(ManagedOutboxMessage.managed_event_id == event.id)
        ).one()
        if target == "event":
            payload = dict(event.payload)
            payload["receipt_hash"] = "0" * 64
            event.payload = payload
            if recompute_digest:
                event.payload_digest = sha256_json(payload)
                event.event_hash = sha256_json(
                    {
                        "schema": "managed-mutation-event-chain/v1",
                        "sequence": event.sequence,
                        "previous_hash": event.previous_hash,
                        "payload_digest": event.payload_digest,
                    }
                )
                resume.resume_audit_event_hash = event.event_hash
        else:
            payload = dict(outbox.payload)
            payload["receipt_hash"] = "0" * 64
            outbox.payload = payload
            if recompute_digest:
                outbox.payload_digest = sha256_json(payload)

    replay = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers=headers,
    )

    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]
    assert after["consumptions"] == before["consumptions"]


def test_approval_resume_replay_fails_closed_when_resume_sealed_receipt_is_tampered(
    tmp_path: Path,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    headers = {
        "X-API-Key": approver_api_key,
        BOOTSTRAP_IDEMPOTENCY_HEADER: "resume-sealed-tamper-0001",
    }
    first = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers=headers,
    )
    assert first.status_code == 201, first.text
    before = _approval_counts(app, org["org_id"])
    with app.state.session_factory.begin() as session:
        resume = session.scalars(sa.select(ApprovalResumeAuthorization)).one()
        receipt = session.scalars(
            sa.select(ManagedDecisionReceipt).where(
                ManagedDecisionReceipt.receipt_id == resume.resume_receipt_id
            )
        ).one()
        sealed = dict(receipt.projection["sealed_receipt"])
        sealed["ciphertext"] = sealed["ciphertext"][:-4] + "AAAA"
        receipt.projection = {**receipt.projection, "sealed_receipt": sealed}

    replay = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers=headers,
    )

    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]
    assert after["consumptions"] == before["consumptions"]


def test_approval_resume_replay_fails_closed_when_resume_event_chain_position_is_tampered(
    tmp_path: Path,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    headers = {
        "X-API-Key": approver_api_key,
        BOOTSTRAP_IDEMPOTENCY_HEADER: "resume-chain-tamper-0001",
    }
    first = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers=headers,
    )
    assert first.status_code == 201, first.text
    before = _approval_counts(app, org["org_id"])
    with app.state.session_factory.begin() as session:
        resume = session.scalars(sa.select(ApprovalResumeAuthorization)).one()
        event = session.scalars(
            sa.select(ManagedGovernanceEvent).where(
                ManagedGovernanceEvent.event_hash == resume.resume_audit_event_hash
            )
        ).one()
        event.previous_hash = "1" * 64
        _recompute_event_and_outbox_hashes(session, event, resume=resume)

    replay = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers=headers,
    )

    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]
    assert after["consumptions"] == before["consumptions"]


def test_approval_resume_replay_fails_closed_when_vote_predecessor_is_recomputed(
    tmp_path: Path,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    headers = {
        "X-API-Key": approver_api_key,
        BOOTSTRAP_IDEMPOTENCY_HEADER: "resume-vote-predecessor-recomputed-0001",
    }
    first = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers=headers,
    )
    assert first.status_code == 201, first.text
    before = _approval_counts(app, org["org_id"])
    with app.state.session_factory.begin() as session:
        request = session.get(ApprovalRequest, approval_request_id)
        assert request is not None
        vote_row = session.scalars(sa.select(ApprovalVote)).one()
        vote_receipt = _vote_receipt_for_vote(session, request, vote_row)
        vote_event = _event_for_receipt(session, vote_receipt)
        resume = session.scalars(sa.select(ApprovalResumeAuthorization)).one()
        resume_event = session.scalars(
            sa.select(ManagedGovernanceEvent).where(
                ManagedGovernanceEvent.event_hash == resume.resume_audit_event_hash
            )
        ).one()
        vote_event.previous_hash = "2" * 64
        _recompute_event_and_outbox_hashes(session, vote_event)
        resume_event.previous_hash = vote_event.event_hash
        _recompute_event_and_outbox_hashes(session, resume_event, resume=resume, update_head=True)

    replay = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers=headers,
    )

    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]
    assert after["consumptions"] == before["consumptions"]


def test_approval_resume_replay_fails_closed_when_predecessor_receipt_row_is_rewritten(
    tmp_path: Path,
) -> None:
    app, client = _migrated_client(tmp_path)
    org, approval_request_id, approver_api_key = _park_and_approve_agent_registration(app, client)
    headers = {
        "X-API-Key": approver_api_key,
        BOOTSTRAP_IDEMPOTENCY_HEADER: "resume-predecessor-receipt-row-0001",
    }
    first = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers=headers,
    )
    assert first.status_code == 201, first.text
    before = _approval_counts(app, org["org_id"])
    with app.state.session_factory.begin() as session:
        request = session.get(ApprovalRequest, approval_request_id)
        assert request is not None
        vote_row = session.scalars(sa.select(ApprovalVote)).one()
        vote_receipt = _vote_receipt_for_vote(session, request, vote_row)
        vote_event = _event_for_receipt(session, vote_receipt)
        resume = session.scalars(sa.select(ApprovalResumeAuthorization)).one()
        resume_event = session.scalars(
            sa.select(ManagedGovernanceEvent).where(
                ManagedGovernanceEvent.event_hash == resume.resume_audit_event_hash
            )
        ).one()
        vote_receipt.actor = "user:rewritten-attacker"
        vote_event.actor = vote_receipt.actor
        vote_event.payload = {
            **vote_event.payload,
            "actor_hash": sha256_json(vote_receipt.actor),
        }
        _recompute_event_and_outbox_hashes(session, vote_event)
        resume_event.previous_hash = vote_event.event_hash
        _recompute_event_and_outbox_hashes(session, resume_event, resume=resume, update_head=True)

    replay = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
        headers=headers,
    )

    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
    after = _approval_counts(app, org["org_id"])
    assert after["agents"] == before["agents"]
    assert after["agent_receipts"] == before["agent_receipts"]
    assert after["consumptions"] == before["consumptions"]


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
        receipt = session.scalars(_managed_agent_receipt_select()).one()
        assert agent.project_id == project_id
        assert agent.environment_id == environment_id
        assert receipt.project_id == project_id
        assert receipt.environment_id == environment_id
        assert receipt.policy_bundle_id is not None


@pytest.mark.parametrize(
    ("decision", "expected_status"),
    [
        ("deny", 403),
        ("escalate", 202),
    ],
)
def test_agent_register_route_duplicate_refusals_replay_original_terminal_response(
    tmp_path: Path,
    decision: str,
    expected_status: int,
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
    # Both answers use the receipted refusal envelope and must converge on the
    # same terminal decision, reason, and receipt. Only request_id is
    # per-request; everything else replays byte-for-byte.
    first_body = first.json()
    second_body = second.json()
    assert set(first_body) == {"status", "reason", "receipt_id", "decision", "request_id"}
    assert set(second_body) == {"status", "reason", "receipt_id", "decision", "request_id"}
    first_body.pop("request_id")
    second_body.pop("request_id")
    assert first_body == second_body
    assert second_body["decision"] == decision
    assert second_body["receipt_id"]
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
        assert _managed_agent_receipts(session) == 1
        assert _count(session, ManagedReceiptConsumption) == 1
        assert _count(session, ManagedGovernanceEvent) == 1
        assert _count(session, ManagedOutboxMessage) == 1


def test_agent_register_route_exact_allow_duplicate_replays_without_new_effects(
    tmp_path: Path,
) -> None:
    app, client = _migrated_client(tmp_path, label="exact-allow-replay")
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate_allow_agent_create(client, org)
    headers = _agent_headers(org, "agent-exact-allow-0001")
    body = {"name": "exact-allow-bot", "trust_tier": "internal"}

    first = client.post(f"/orgs/{org['org_id']}/agents", json=body, headers=headers)
    before = _managed_integrity_counts(app)
    second = client.post(f"/orgs/{org['org_id']}/agents", json=body, headers=headers)
    after = _managed_integrity_counts(app)

    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text
    assert first.json() == second.json()
    assert (
        after
        == before
        == {
            "agents": 1,
            "idempotency": 1,
            "receipts": 1,
            "consumptions": 1,
            "events": 1,
            "outbox": 1,
            "attempts": 1,
            "approval_requests": 0,
        }
    )


@pytest.mark.parametrize(
    "tamper_case",
    [
        "sealed_receipt_ciphertext",
        "missing_allow_consumption",
        "event_payload",
        "event_previous_hash",
        "missing_outbox",
        "failed_attempt",
        "coordinated_agent_response",
    ],
)
def test_agent_register_route_rejects_corrupt_replay_integrity_state_without_new_effects(
    tmp_path: Path,
    tamper_case: str,
) -> None:
    app, client = _migrated_client(tmp_path, label=f"corrupt-replay-{tamper_case}")
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate_allow_agent_create(client, org)
    headers = _agent_headers(org, f"agent-corrupt-replay-{tamper_case}-0001")
    body = {"name": f"corrupt-replay-{tamper_case}-bot", "trust_tier": "internal"}

    first = client.post(f"/orgs/{org['org_id']}/agents", json=body, headers=headers)
    assert first.status_code == 201, first.text
    with app.state.session_factory.begin() as session:
        if tamper_case == "sealed_receipt_ciphertext":
            receipt = session.scalars(_managed_agent_receipt_select()).one()
            sealed_receipt = dict(receipt.projection["sealed_receipt"])
            sealed_receipt["ciphertext"] = f"{sealed_receipt['ciphertext']}A"
            receipt.projection = {**receipt.projection, "sealed_receipt": sealed_receipt}
        elif tamper_case == "missing_allow_consumption":
            session.delete(session.scalars(sa.select(ManagedReceiptConsumption)).one())
        elif tamper_case == "event_payload":
            event = session.scalars(sa.select(ManagedGovernanceEvent)).one()
            event.payload = {**event.payload, "receipt_hash": "f" * 64}
        elif tamper_case == "event_previous_hash":
            event = session.scalars(sa.select(ManagedGovernanceEvent)).one()
            event.previous_hash = "f" * 64
        elif tamper_case == "missing_outbox":
            session.delete(session.scalars(sa.select(ManagedOutboxMessage)).one())
        elif tamper_case == "failed_attempt":
            attempt = session.scalars(sa.select(ManagedMutationAttempt)).one()
            attempt.status = "failed"
            attempt.failure_class_hash = sha256_json("test.failure")
            attempt.failure_digest = sha256_json("test.failure.digest")
        elif tamper_case == "coordinated_agent_response":
            _tamper_allow_replay_to_coordinated_agent_response(session)
        else:  # pragma: no cover - parametrization guard
            raise AssertionError(f"unsupported replay tamper case: {tamper_case}")
    before_replay = _managed_integrity_counts(app)

    replay = client.post(f"/orgs/{org['org_id']}/agents", json=body, headers=headers)
    after_replay = _managed_integrity_counts(app)

    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
    assert after_replay == before_replay
    with app.state.session_factory() as session:
        assert _count(session, AgentRecord) == 1


def _tamper_allow_replay_to_coordinated_agent_response(session: Any) -> None:
    agent = session.scalars(sa.select(AgentRecord)).one()
    row = session.scalars(sa.select(AgentRegistrationIdempotency)).one()
    event = session.scalars(sa.select(ManagedGovernanceEvent)).one()
    outbox = session.scalars(sa.select(ManagedOutboxMessage)).one()

    agent.name = "tampered-agent"
    agent.description = "tampered description"
    agent.trust_tier = "admin"
    agent.allowed_tools = ["*"]
    agent.status = "active"
    row.response = {
        **row.response,
        "name": agent.name,
        "description": agent.description,
        "trust_tier": agent.trust_tier,
        "allowed_tools": list(agent.allowed_tools),
        "status": agent.status,
    }
    tampered_result_hash = safe_result_hash(
        {
            "agent_id": agent.id,
            "org_id": agent.org_id,
            "project_id_hash": sha256_json(agent.project_id or ""),
            "environment_id_hash": sha256_json(agent.environment_id or ""),
            "name_hash": sha256_json(agent.name),
            "status": agent.status,
            "created_at": _to_utc(agent.created_at).isoformat(),
        }
    )
    event.payload = {**event.payload, "result_hash": tampered_result_hash}
    event.payload_digest = sha256_json(event.payload)
    outbox.payload = {
        **outbox.payload,
        "result_hash": tampered_result_hash,
        "payload_digest": event.payload_digest,
    }
    outbox.payload_digest = sha256_json(outbox.payload)


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
    ("decision", "expected_status"),
    [
        ("deny", 403),
        ("escalate", 202),
    ],
)
def test_agent_register_route_concurrent_refusals_converge_to_one_terminal_response(
    tmp_path: Path,
    decision: str,
    expected_status: int,
) -> None:
    app, client = _migrated_client(tmp_path, label=f"concurrent-{decision}")
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate(client, org, rules=_rules_for_policy(decision))
    headers = _agent_headers(org, f"agent-refusal-concurrent-{decision}-0001")
    body = {"name": f"concurrent-{decision}-bot", "trust_tier": "internal"}

    def register() -> tuple[int, str | None]:
        resp = client.post(f"/orgs/{org['org_id']}/agents", json=body, headers=headers)
        terminal = (
            resp.json().get("decision")
            if resp.headers.get("content-type", "").startswith("application/json")
            else None
        )
        return resp.status_code, terminal

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: register(), range(2)))

    # Both racers answer in the receipted refusal envelope with the same
    # terminal decision; the refusal evidence below proves only one of them
    # committed it.
    assert results == [(expected_status, decision), (expected_status, decision)]
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


def _test_canonical_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC).isoformat()
    return value.astimezone(UTC).isoformat()


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
        policy_scope = ReceiptTrustScope(
            org_id, project_id, environment_id, POLICY_ENVELOPE_PURPOSE
        )
        policy_issuer = local_policy_registry_issuer()
        policy_signer = policy_issuer.signer_for_scope(policy_scope, trust_epoch=1)
        ManagedTrustLifecycleService(session).bootstrap(
            scope=policy_scope,
            key_id=policy_signer.key_id,
            algorithm=policy_signer.algorithm,
            public_key_spki_der=public_spki_der_from_signer(policy_signer),
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
    org_id = org["org_id"]
    policy_id = f"policy-{new_id()}"
    parsed = RuleSetPolicy.from_dict({"id": policy_id, "rules": rules})
    document = {"id": parsed.policy_id, "version": parsed.version, "rules": list(rules)}
    app = cast(Any, client.app)
    with app.state.session_factory.begin() as session:
        environment = session.scalars(
            sa.select(Environment)
            .where(Environment.org_id == org_id)
            .order_by(Environment.created_at.desc())
        ).first()
        assert environment is not None
        envelope = _signed_envelope(
            issuer=local_policy_registry_issuer(),
            org_id=org_id,
            project_id=environment.project_id,
            environment_id=environment.id,
            policy_id=policy_id,
            document=document,
            trust_epoch=1,
        )
        version = PolicyVersion(
            id=new_id(),
            org_id=org_id,
            project_id=environment.project_id,
            environment_id=environment.id,
            policy_id=policy_id,
            version=document["version"],
            content_hash=envelope["content_hash"],
            document=document,
            rules=list(document["rules"]),
            canonical_envelope=envelope,
            purpose=envelope["purpose"],
            key_id=envelope["key_id"],
            signature_algorithm=envelope["signature_algorithm"],
            signature=envelope["signature"],
            trust_epoch=envelope["trust_epoch"],
            receipt_id=f"test-policy-receipt-{new_id()}",
        )
        session.add(version)
        session.flush()
        head_receipt_id = _seed_policy_head_receipt(
            session,
            org_id=org_id,
            project_id=environment.project_id,
            environment_id=environment.id,
            prefix="test-policy-head",
        )
        existing_head = session.scalars(
            sa.select(EnvironmentPolicyHead).where(
                EnvironmentPolicyHead.org_id == org_id,
                EnvironmentPolicyHead.project_id == environment.project_id,
                EnvironmentPolicyHead.environment_id == environment.id,
            )
        ).one_or_none()
        if existing_head is None:
            session.add(
                EnvironmentPolicyHead(
                    id=new_id(),
                    org_id=org_id,
                    project_id=environment.project_id,
                    environment_id=environment.id,
                    active_policy_version_id=version.id,
                    generation=1,
                    status="active",
                    receipt_id=head_receipt_id,
                    created_at=utcnow(),
                    updated_at=utcnow(),
                )
            )
        else:
            existing_head.active_policy_version_id = version.id
            existing_head.generation += 1
            existing_head.receipt_id = head_receipt_id
            existing_head.updated_at = utcnow()


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


def _install_after_auth_caller_mutation(
    monkeypatch: pytest.MonkeyPatch,
    app: Any,
    *,
    mutation: str,
) -> None:
    original = approvals_module._locked_current_principal

    def mutate_then_lock(
        service_session: Any,
        *,
        org_id: str,
        principal: Any,
        permission: Any,
        operation: str,
    ) -> Any:
        with app.state.session_factory.begin() as mutation_session:
            user = mutation_session.scalars(
                sa.select(User).where(User.org_id == principal.org_id, User.id == principal.user_id)
            ).one()
            if mutation == "inactive":
                user.active = False
            elif mutation == "role_loss":
                user.role = "viewer"
            elif mutation == "credential_rotation":
                user.api_key_hash = "0" * 64
            else:
                raise AssertionError(f"unsupported caller mutation: {mutation}")
        return original(
            service_session,
            org_id=org_id,
            principal=principal,
            permission=permission,
            operation=operation,
        )

    monkeypatch.setattr(approvals_module, "_locked_current_principal", mutate_then_lock)


def _park_and_approve_agent_registration(
    app: Any,
    client: TestClient,
) -> tuple[dict[str, Any], str, str]:
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate(client, org, rules=_rules_for_policy("escalate"))
    request_resp = client.post(
        f"/orgs/{org['org_id']}/agents",
        json={
            "name": f"approved-bot-{new_id()}",
            "description": "parked registration",
            "trust_tier": "internal",
            "allowed_tools": ["deploy.staging"],
        },
        headers=_agent_headers(org, f"approval-request-{new_id()}"),
    )
    assert request_resp.status_code == 202, request_resp.text
    approval_request_id = request_resp.json()["approval_request_id"]
    approver_headers = _create_user(client, org, role="org_admin")
    vote = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/votes",
        json={"decision": "approve"},
        headers={
            **approver_headers,
            BOOTSTRAP_IDEMPOTENCY_HEADER: f"approval-vote-{new_id()}",
        },
    )
    assert vote.status_code == 200, vote.text
    assert vote.json()["outcome"] == "approved"
    return org, approval_request_id, approver_headers["X-API-Key"]


def _park_and_approve_existing_org_agent_registration(
    client: TestClient,
    org: dict[str, Any],
    *,
    name: str,
) -> tuple[str, dict[str, str]]:
    request_resp = client.post(
        f"/orgs/{org['org_id']}/agents",
        json={
            "name": name,
            "description": "parked registration",
            "trust_tier": "internal",
            "allowed_tools": ["deploy.staging"],
        },
        headers=_agent_headers(org, f"approval-request-{new_id()}"),
    )
    assert request_resp.status_code == 202, request_resp.text
    approval_request_id = request_resp.json()["approval_request_id"]
    approver_headers = _create_user(client, org, role="org_admin")
    vote = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/votes",
        json={"decision": "approve"},
        headers={
            **approver_headers,
            BOOTSTRAP_IDEMPOTENCY_HEADER: f"approval-vote-{new_id()}",
        },
    )
    assert vote.status_code == 200, vote.text
    assert vote.json()["outcome"] == "approved"
    return approval_request_id, approver_headers


def _rotate_receipt_trust(app: Any, org_id: str) -> None:
    with app.state.session_factory.begin() as session:
        environment = session.scalars(
            sa.select(Environment)
            .where(Environment.org_id == org_id)
            .order_by(Environment.created_at.desc())
            .with_for_update()
        ).one()
        scope = ReceiptTrustScope(
            org_id,
            environment.project_id,
            environment.id,
            DECISION_RECEIPT_PURPOSE,
        )
        signer = app.state.agent_registration_service.issuer.signer_for_scope(
            scope,
            trust_epoch=2,
        )
        ManagedTrustLifecycleService(session).rotate(
            scope=scope,
            key_id=signer.key_id,
            algorithm=signer.algorithm,
            public_key_spki_der=public_spki_der_from_signer(signer),
            not_after=utcnow() + timedelta(days=1),
            expected_current_epoch=1,
        )


def _approval_counts(app: Any, org_id: str) -> dict[str, int]:
    with app.state.session_factory() as session:
        return {
            "agents": int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(AgentRecord)
                    .where(AgentRecord.org_id == org_id)
                )
                or 0
            ),
            "agent_receipts": int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(ManagedDecisionReceipt)
                    .where(
                        ManagedDecisionReceipt.org_id == org_id,
                        ManagedDecisionReceipt.proposed_action == CONTROL_PLANE_AGENT_CREATE_ACTION,
                    )
                )
                or 0
            ),
            "all_receipts": int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(ManagedDecisionReceipt)
                    .where(ManagedDecisionReceipt.org_id == org_id)
                )
                or 0
            ),
            "consumptions": int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(ManagedReceiptConsumption)
                    .where(ManagedReceiptConsumption.org_id == org_id)
                )
                or 0
            ),
            "events": int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(ManagedGovernanceEvent)
                    .where(ManagedGovernanceEvent.org_id == org_id)
                )
                or 0
            ),
            "outbox": int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(ManagedOutboxMessage)
                    .where(ManagedOutboxMessage.org_id == org_id)
                )
                or 0
            ),
            "votes": int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(ApprovalVote)
                    .where(ApprovalVote.org_id == org_id)
                )
                or 0
            ),
            "outcomes": int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(ApprovalOutcome)
                    .where(ApprovalOutcome.org_id == org_id)
                )
                or 0
            ),
            "resumes": int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(ApprovalResumeAuthorization)
                    .where(ApprovalResumeAuthorization.org_id == org_id)
                )
                or 0
            ),
        }


def _corrupt_approval_request_column(
    app: Any,
    approval_request_id: str,
    *,
    column: str,
    value: str,
) -> None:
    if column not in {"escalate_receipt_id", "status"}:
        raise AssertionError(f"unsupported approval request corruption column: {column}")
    raw_connection = app.state.engine.raw_connection()
    try:
        cursor = raw_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=OFF")
        cursor.execute("PRAGMA ignore_check_constraints=ON")
        cursor.execute(
            f"UPDATE approval_requests SET {column} = ? WHERE id = ?",
            (value, approval_request_id),
        )
        raw_connection.commit()
        cursor.execute("PRAGMA ignore_check_constraints=OFF")
        cursor.execute("PRAGMA foreign_keys=ON")
        raw_connection.commit()
    finally:
        raw_connection.close()


def _delete_user_direct(app: Any, user_id: str) -> None:
    raw_connection = app.state.engine.raw_connection()
    try:
        cursor = raw_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=OFF")
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        raw_connection.commit()
        cursor.execute("PRAGMA foreign_keys=ON")
        raw_connection.commit()
    finally:
        raw_connection.close()


def _corrupt_attempt_project_direct(app: Any, attempt_id: str, *, project_id: str) -> None:
    raw_connection = app.state.engine.raw_connection()
    try:
        cursor = raw_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=OFF")
        cursor.execute(
            "UPDATE managed_mutation_attempts SET project_id = ? WHERE id = ?",
            (project_id, attempt_id),
        )
        raw_connection.commit()
        cursor.execute("PRAGMA foreign_keys=ON")
        raw_connection.commit()
    finally:
        raw_connection.close()


def _vote_receipt_for_vote(
    session: Any,
    request: ApprovalRequest,
    vote: ApprovalVote,
) -> ManagedDecisionReceipt:
    return session.scalars(
        sa.select(ManagedDecisionReceipt).where(
            ManagedDecisionReceipt.org_id == request.org_id,
            ManagedDecisionReceipt.project_id == request.project_id,
            ManagedDecisionReceipt.environment_id == request.environment_id,
            ManagedDecisionReceipt.proposed_action == CONTROL_PLANE_APPROVAL_VOTE_ACTION,
            ManagedDecisionReceipt.argument_hash
            == sha256_json(
                {
                    "approval_request_id": request.id,
                    "decision": vote.decision,
                    "request_hash": request.request_hash,
                }
            ),
            ManagedDecisionReceipt.decision == "allow",
        )
    ).one()


def _event_for_receipt(
    session: Any,
    receipt: ManagedDecisionReceipt,
) -> ManagedGovernanceEvent:
    return session.scalars(
        sa.select(ManagedGovernanceEvent).where(
            ManagedGovernanceEvent.org_id == receipt.org_id,
            ManagedGovernanceEvent.project_id == receipt.project_id,
            ManagedGovernanceEvent.environment_id == receipt.environment_id,
            ManagedGovernanceEvent.managed_receipt_id == receipt.id,
        )
    ).one()


def _consumption_for_receipt(
    session: Any,
    receipt: ManagedDecisionReceipt,
) -> ManagedReceiptConsumption:
    return session.scalars(
        sa.select(ManagedReceiptConsumption).where(
            ManagedReceiptConsumption.org_id == receipt.org_id,
            ManagedReceiptConsumption.project_id == receipt.project_id,
            ManagedReceiptConsumption.environment_id == receipt.environment_id,
            ManagedReceiptConsumption.managed_receipt_id == receipt.id,
            ManagedReceiptConsumption.receipt_hash == receipt.receipt_hash,
            ManagedReceiptConsumption.audit_event_hash == receipt.audit_event_hash,
        )
    ).one()


def _attempt_for_receipt(
    session: Any,
    receipt: ManagedDecisionReceipt,
) -> ManagedMutationAttempt:
    return session.scalars(
        sa.select(ManagedMutationAttempt).where(
            ManagedMutationAttempt.org_id == receipt.org_id,
            ManagedMutationAttempt.project_id == receipt.project_id,
            ManagedMutationAttempt.environment_id == receipt.environment_id,
            ManagedMutationAttempt.receipt_hash == receipt.receipt_hash,
            ManagedMutationAttempt.audit_event_hash == receipt.audit_event_hash,
            ManagedMutationAttempt.action == receipt.proposed_action,
            ManagedMutationAttempt.actor_hash == sha256_json(receipt.actor),
            ManagedMutationAttempt.argument_hash == receipt.argument_hash,
        )
    ).one()


def _recompute_event_and_outbox_hashes(
    session: Any,
    event: ManagedGovernanceEvent,
    *,
    resume: ApprovalResumeAuthorization | None = None,
    update_head: bool = False,
) -> None:
    head = session.get(
        ManagedGovernanceEventHead,
        (event.org_id, event.project_id, event.environment_id),
    )
    assert head is not None
    event.payload_digest = sha256_json(event.payload)
    event.event_hash = sha256_json(
        {
            "schema": "managed-mutation-event-chain/v1",
            "sequence": event.sequence,
            "previous_hash": event.previous_hash,
            "payload_digest": event.payload_digest,
        }
    )
    outbox = session.scalars(
        sa.select(ManagedOutboxMessage).where(ManagedOutboxMessage.managed_event_id == event.id)
    ).one()
    outbox.payload = {
        **outbox.payload,
        "event_hash": event.event_hash,
        "payload_digest": event.payload_digest,
    }
    outbox.payload_digest = sha256_json(outbox.payload)
    outbox.delivery_key = f"managed-mutation-uow/v1:{event.event_hash}"
    if resume is not None:
        resume.resume_audit_event_hash = event.event_hash
    if update_head:
        head.last_sequence = event.sequence
        head.last_event_hash = event.event_hash


def _replace_active_policy_direct(app: Any, org_id: str, *, rules: list[dict[str, Any]]) -> None:
    policy_id = f"race-policy-{new_id()}"
    parsed = RuleSetPolicy.from_dict({"id": policy_id, "rules": rules})
    document = {"id": parsed.policy_id, "version": parsed.version, "rules": list(rules)}
    with app.state.session_factory.begin() as session:
        environment = session.scalars(
            sa.select(Environment)
            .where(Environment.org_id == org_id)
            .order_by(Environment.created_at.desc())
            .with_for_update()
        ).first()
        assert environment is not None
        envelope = _signed_envelope(
            issuer=local_policy_registry_issuer(),
            org_id=org_id,
            project_id=environment.project_id,
            environment_id=environment.id,
            policy_id=policy_id,
            document=document,
            trust_epoch=1,
        )
        version = PolicyVersion(
            id=new_id(),
            org_id=org_id,
            project_id=environment.project_id,
            environment_id=environment.id,
            policy_id=policy_id,
            version=document["version"],
            content_hash=envelope["content_hash"],
            document=document,
            rules=list(document["rules"]),
            canonical_envelope=envelope,
            purpose=envelope["purpose"],
            key_id=envelope["key_id"],
            signature_algorithm=envelope["signature_algorithm"],
            signature=envelope["signature"],
            trust_epoch=envelope["trust_epoch"],
            receipt_id=f"test-policy-race-receipt-{new_id()}",
        )
        session.add(version)
        session.flush()
        head_receipt_id = _seed_policy_head_receipt(
            session,
            org_id=org_id,
            project_id=environment.project_id,
            environment_id=environment.id,
            prefix="test-policy-race-head",
        )
        head = session.scalars(
            sa.select(EnvironmentPolicyHead)
            .where(
                EnvironmentPolicyHead.org_id == org_id,
                EnvironmentPolicyHead.project_id == environment.project_id,
                EnvironmentPolicyHead.environment_id == environment.id,
            )
            .with_for_update()
        ).one()
        head.active_policy_version_id = version.id
        head.generation += 1
        head.receipt_id = head_receipt_id
        head.updated_at = utcnow()


def _seed_policy_head_receipt(
    session: Any,
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    prefix: str,
) -> str:
    receipt_id = f"{prefix}-receipt-{new_id()}"
    receipt_hash = sha256_json({"schema": "test-policy-head-receipt/v1", "receipt_id": receipt_id})
    audit_hash = sha256_json({"schema": "test-policy-head-audit/v1", "receipt_id": receipt_id})
    now = utcnow()
    session.add(
        ManagedDecisionReceipt(
            id=f"{prefix}-{new_id()}",
            org_id=org_id,
            project_id=project_id,
            environment_id=environment_id,
            receipt_id=receipt_id,
            receipt_hash=receipt_hash,
            audit_event_hash=audit_hash,
            decision="ALLOW",
            actor="test-policy-fixture",
            proposed_action="control-plane.policy.activate",
            execution_boundary="test-policy-fixture-boundary",
            policy_bundle_id="test-policy-fixture",
            policy_version="test-policy-fixture/v1",
            policy_hash=sha256_json({"schema": "test-policy-fixture/v1"}),
            argument_hash=sha256_json({"receipt_id": receipt_id}),
            signing_key_id="test-policy-fixture-key",
            signature_algorithm="ed25519",
            receipt_schema_version="receipt/v2",
            trust_epoch=1,
            assurance_class="native",
            source_system="gove-zone",
            issued_at=now,
            expires_at=now + timedelta(minutes=10),
            projection={"schema": "test-policy-head-receipt/v1"},
            created_at=now,
        )
    )
    return receipt_id


def _expire_or_revoke_trust(app: Any, org_id: str, *, status: str) -> None:
    from acgs_control_plane.models import ManagedTrustKey

    with app.state.session_factory.begin() as session:
        keys = list(
            session.scalars(
                sa.select(ManagedTrustKey).where(
                    ManagedTrustKey.org_id == org_id,
                    ManagedTrustKey.purpose == DECISION_RECEIPT_PURPOSE,
                )
            )
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


def _managed_agent_receipt_select() -> Any:
    return sa.select(ManagedDecisionReceipt).where(
        ManagedDecisionReceipt.proposed_action == CONTROL_PLANE_AGENT_CREATE_ACTION
    )


def _managed_agent_receipts(session: Any) -> int:
    return int(
        session.scalar(
            sa.select(sa.func.count())
            .select_from(ManagedDecisionReceipt)
            .where(ManagedDecisionReceipt.proposed_action == CONTROL_PLANE_AGENT_CREATE_ACTION)
        )
        or 0
    )


def _count_agents_by_app(app: Any, org_id: str, name: str) -> int:
    with app.state.session_factory() as session:
        return _count_agents(session, org_id, name)


def _managed_integrity_counts(app: Any) -> dict[str, int]:
    with app.state.session_factory() as session:
        return {
            "agents": _count(session, AgentRecord),
            "idempotency": _count(session, AgentRegistrationIdempotency),
            "receipts": _managed_agent_receipts(session),
            "consumptions": _count(session, ManagedReceiptConsumption),
            "events": _count(session, ManagedGovernanceEvent),
            "outbox": _count(session, ManagedOutboxMessage),
            "attempts": _count(session, ManagedMutationAttempt),
            "approval_requests": _count(session, ApprovalRequest),
        }


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
        assert _managed_agent_receipts(session) == 1
        assert _count(session, ManagedGovernanceEvent) == 1
        assert _count(session, ManagedOutboxMessage) == 1
        receipt = session.scalars(_managed_agent_receipt_select()).one()
        assert receipt.decision == decision
        expected_approvals = 1 if decision == "escalate" else 0
        assert _count(session, ApprovalRequest) == expected_approvals


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
        assert _managed_agent_receipts(session) == 1
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
        assert _managed_agent_receipts(session) == 1
        assert _count(session, ManagedGovernanceEvent) == 1
        assert _count(session, ManagedOutboxMessage) == 1
