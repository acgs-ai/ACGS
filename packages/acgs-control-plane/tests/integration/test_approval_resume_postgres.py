"""Live-PostgreSQL gates for approval voting and resume wiring."""

from __future__ import annotations

import os
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, ReceiptTrustScope
from sqlalchemy.exc import IntegrityError

import acgs_control_plane.approvals as approvals_module
from acgs_control_plane.agent_registration import _to_utc, local_agent_registration_issuer
from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.managed_mutations import (
    CONTROL_PLANE_AGENT_CREATE_ACTION,
    CONTROL_PLANE_APPROVAL_VOTE_ACTION,
    CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
)
from acgs_control_plane.migrations import DatabaseSchemaState, upgrade_database
from acgs_control_plane.models import (
    AgentRecord,
    ApprovalOutcome,
    ApprovalRequest,
    ApprovalResumeAuthorization,
    ApprovalVote,
    Environment,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedMutationAttempt,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    User,
    new_id,
    utcnow,
)
from acgs_control_plane.tenant_bootstrap import BOOTSTRAP_IDEMPOTENCY_HEADER
from acgs_control_plane.trust import (
    ManagedTrustLifecycleService,
    public_spki_der_from_signer,
)
from tests.test_agent_registration_managed_route import (
    BOOTSTRAP_TOKEN,
    _admin_headers,
    _bootstrap_org,
    _create_user,
    _publish_and_activate,
    _replace_active_policy_direct,
    _rules_for_policy,
    _seed_default_scope_and_trust,
)

EXPECTED_DATABASE = "acgs_control_plane_test"


def test_pg_escalate_creates_scoped_pending_without_agent_or_consumption(tmp_path: Path) -> None:
    app, client, org, database_url = _postgres_approval_app(tmp_path)
    try:
        approval_request_id = _park_agent_registration(
            client,
            org,
            name="pg-escalate-pending-bot",
            idempotency_key="pg-approval-escalate-0001",
        )

        with app.state.session_factory() as session:
            approval = session.get(ApprovalRequest, approval_request_id)
            receipt = session.scalars(
                sa.select(ManagedDecisionReceipt).where(
                    ManagedDecisionReceipt.org_id == org["org_id"],
                    ManagedDecisionReceipt.proposed_action == CONTROL_PLANE_AGENT_CREATE_ACTION,
                    ManagedDecisionReceipt.decision == "escalate",
                )
            ).one()
            assert approval is not None
            assert approval.org_id == org["org_id"]
            assert approval.project_id == receipt.project_id
            assert approval.environment_id == receipt.environment_id
            assert approval.action == CONTROL_PLANE_AGENT_CREATE_ACTION
            assert approval.escalate_receipt_id == receipt.receipt_id
            assert approval.escalate_receipt_hash == receipt.receipt_hash
            assert approval.escalate_audit_event_hash == receipt.audit_event_hash
            assert approval.status == "pending"
            assert approval.quorum_threshold == 1
            assert "pg-escalate-pending-bot" not in str(approval.sealed_arguments)
            assert _count_named_agents(session, org["org_id"], "pg-escalate-pending-bot") == 0
            assert _count(session, ManagedReceiptConsumption) == 0
            assert _count(session, ApprovalVote) == 0
            assert _count(session, ApprovalOutcome) == 0
            assert _count(session, ApprovalResumeAuthorization) == 0
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_pg_self_and_wrong_role_approval_are_non_executable(tmp_path: Path) -> None:
    app, client, org, database_url = _postgres_approval_app(tmp_path)
    try:
        approval_request_id = _park_agent_registration(
            client,
            org,
            name="pg-rbac-denied-approval-bot",
            idempotency_key="pg-approval-rbac-request-0001",
        )
        before = _approval_counts(app, org["org_id"])

        self_vote = client.post(
            f"/orgs/{org['org_id']}/approvals/{approval_request_id}/votes",
            json={"decision": "approve"},
            headers={
                **_admin_headers(org),
                BOOTSTRAP_IDEMPOTENCY_HEADER: "pg-approval-self-vote-0001",
            },
        )
        assert self_vote.status_code == 403, self_vote.text
        assert self_vote.json()["code"] == "APPROVAL_SELF_APPROVAL_DENIED"
        assert _approval_counts(app, org["org_id"]) == before

        wrong_role_vote = client.post(
            f"/orgs/{org['org_id']}/approvals/{approval_request_id}/votes",
            json={"decision": "approve"},
            headers={
                **_create_user(client, org, role="viewer"),
                BOOTSTRAP_IDEMPOTENCY_HEADER: "pg-approval-viewer-vote-0001",
            },
        )
        assert wrong_role_vote.status_code == 403, wrong_role_vote.text
        assert _approval_counts(app, org["org_id"]) == before
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_pg_resume_before_required_vote_is_non_executable(tmp_path: Path) -> None:
    app, client, org, database_url = _postgres_approval_app(tmp_path)
    try:
        approval_request_id = _park_agent_registration(
            client,
            org,
            name="pg-no-quorum-bot",
            idempotency_key="pg-approval-no-quorum-request-0001",
        )
        approver_headers = _create_user(client, org, role="org_admin")
        before = _approval_counts(app, org["org_id"])

        response = client.post(
            f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
            headers={
                **approver_headers,
                BOOTSTRAP_IDEMPOTENCY_HEADER: "pg-approval-no-quorum-resume-0001",
            },
        )

        assert response.status_code == 409, response.text
        assert response.json()["code"] == "APPROVAL_NOT_APPROVED"
        assert _approval_counts(app, org["org_id"]) == before
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_pg_approved_resume_executes_once_and_replay_is_stable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, client, org, database_url = _postgres_approval_app(tmp_path)
    try:
        approval_request_id, approver_headers = _park_and_approve(
            client,
            org,
            name="pg-approved-resume-bot",
            request_key="pg-approval-positive-request-0001",
            vote_key="pg-approval-positive-vote-0001",
        )
        before = _approval_counts(app, org["org_id"])
        resume_headers = {
            **approver_headers,
            BOOTSTRAP_IDEMPOTENCY_HEADER: "pg-approval-positive-resume-0001",
        }

        response = client.post(
            f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
            headers=resume_headers,
        )
        assert response.status_code == 201, response.text
        payload = response.json()
        assert payload["name"] == "pg-approved-resume-bot"
        assert payload["receipt_id"]

        status_mutation = client.patch(
            f"/orgs/{org['org_id']}/agents/{payload['agent_id']}/status",
            json={"status": "suspended"},
            headers=approver_headers,
        )
        assert status_mutation.status_code == 200, status_mutation.text
        assert status_mutation.json()["status"] == "suspended"
        with app.state.session_factory() as session:
            request = session.get(ApprovalRequest, approval_request_id)
            assert request is not None
            expired_now = _to_utc(request.expires_at) + timedelta(minutes=1)
        monkeypatch.setattr(approvals_module, "utcnow", lambda: expired_now)

        replay = client.post(
            f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
            headers=resume_headers,
        )
        assert replay.status_code == 201, replay.text
        assert replay.json() == payload

        second_key = client.post(
            f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
            headers={
                **approver_headers,
                BOOTSTRAP_IDEMPOTENCY_HEADER: "pg-approval-positive-resume-0002",
            },
        )
        assert second_key.status_code == 409, second_key.text
        assert second_key.json()["code"] == "APPROVAL_ALREADY_RESUMED"

        after = _approval_counts(app, org["org_id"])
        assert after == {
            **before,
            "agents": before["agents"] + 1,
            "agent_receipts": before["agent_receipts"] + 1,
            "all_receipts": before["all_receipts"] + 1,
            "consumptions": before["consumptions"] + 1,
            "events": before["events"] + 1,
            "outbox": before["outbox"] + 1,
            "attempts": before["attempts"] + 1,
            "resumes": before["resumes"] + 1,
        }
        with app.state.session_factory() as session:
            resume = session.scalars(sa.select(ApprovalResumeAuthorization)).one()
            receipt = session.scalars(
                sa.select(ManagedDecisionReceipt).where(
                    ManagedDecisionReceipt.receipt_id == resume.resume_receipt_id
                )
            ).one()
            assert receipt.receipt_id == payload["receipt_id"]
            assert receipt.decision == "allow"
            assert receipt.actor == f"user:{org['admin_user_id']}"
            assert receipt.proposed_action == CONTROL_PLANE_AGENT_CREATE_ACTION
            assert receipt.projection["approval_chain_hash"] == resume.approval_chain_hash
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_pg_rejected_and_expired_requests_resume_zero_side_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, client, org, database_url = _postgres_approval_app(tmp_path)
    try:
        rejected_id = _park_agent_registration(
            client,
            org,
            name="pg-rejected-resume-bot",
            idempotency_key="pg-approval-rejected-request-0001",
        )
        approver_headers = {
            **_create_user(client, org, role="org_admin"),
            BOOTSTRAP_IDEMPOTENCY_HEADER: "pg-approval-reject-vote-0001",
        }
        vote = client.post(
            f"/orgs/{org['org_id']}/approvals/{rejected_id}/votes",
            json={"decision": "reject"},
            headers=approver_headers,
        )
        assert vote.status_code == 200, vote.text
        assert vote.json()["outcome"] == "rejected"
        before_rejected_resume = _approval_counts(app, org["org_id"])
        rejected_resume = client.post(
            f"/orgs/{org['org_id']}/approvals/{rejected_id}/resume",
            headers={
                **{k: v for k, v in approver_headers.items() if k != BOOTSTRAP_IDEMPOTENCY_HEADER},
                BOOTSTRAP_IDEMPOTENCY_HEADER: "pg-approval-rejected-resume-0001",
            },
        )
        assert rejected_resume.status_code in {409, 503}, rejected_resume.text
        assert rejected_resume.json()["code"] in {
            "APPROVAL_NOT_APPROVED",
            "IDEMPOTENCY_RECORD_INVALID",
        }
        assert _approval_counts(app, org["org_id"]) == before_rejected_resume

        expired_id = _park_agent_registration(
            client,
            org,
            name="pg-expired-resume-bot",
            idempotency_key="pg-approval-expired-request-0001",
        )
        with app.state.session_factory() as session:
            expired = session.get(ApprovalRequest, expired_id)
            assert expired is not None
            expired_now = _to_utc(expired.expires_at) + timedelta(minutes=1)
        monkeypatch.setattr(approvals_module, "utcnow", lambda: expired_now)
        before_expired_resume = _approval_counts(app, org["org_id"])
        expired_resume = client.post(
            f"/orgs/{org['org_id']}/approvals/{expired_id}/resume",
            headers={
                **_create_user(client, org, role="org_admin"),
                BOOTSTRAP_IDEMPOTENCY_HEADER: "pg-approval-expired-resume-0001",
            },
        )
        assert expired_resume.status_code == 409, expired_resume.text
        assert expired_resume.json()["code"] == "APPROVAL_EXPIRED"
        assert _approval_counts(app, org["org_id"]) == before_expired_resume
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


@pytest.mark.parametrize("decision", ["deny", "escalate"])
def test_pg_concurrent_vote_refusal_replay_records_one_evidence_set(
    tmp_path: Path,
    decision: str,
) -> None:
    app, client, org, database_url = _postgres_approval_app(tmp_path)
    try:
        approval_request_id = _park_agent_registration(
            client,
            org,
            name=f"pg-vote-refusal-race-{decision}-bot",
            idempotency_key=f"pg-vote-refusal-race-{decision}-request-0001",
        )
        _replace_active_policy_direct(
            app,
            org["org_id"],
            rules=[
                {
                    "id": f"pg-{decision}-approval-vote",
                    "effect": decision,
                    "tools": [CONTROL_PLANE_APPROVAL_VOTE_ACTION],
                    "reason": "approval vote refusal race",
                }
            ],
        )
        approver_headers = _create_user(client, org, role="org_admin")
        before = _approval_counts(app, org["org_id"])
        idempotency_key = f"pg-vote-refusal-race-{decision}-vote-0001"

        with ProcessPoolExecutor(max_workers=4) as pool:
            futures = [
                pool.submit(
                    _vote_worker,
                    database_url,
                    org["org_id"],
                    approval_request_id,
                    approver_headers["X-API-Key"],
                    idempotency_key,
                )
                for _ in range(4)
            ]
            results = [future.result(timeout=30) for future in as_completed(futures)]

        expected_status = 202 if decision == "escalate" else 403
        expected_code = "ESCALATE_PENDING" if decision == "escalate" else "POLICY_DENIED"
        assert all(result["status_code"] == expected_status for result in results), results
        assert all(result["code"] == expected_code for result in results), results
        after = _approval_counts(app, org["org_id"])
        assert after == {
            **before,
            "approval_vote_receipts": before["approval_vote_receipts"] + 1,
            "all_receipts": before["all_receipts"] + 1,
            "events": before["events"] + 1,
            "outbox": before["outbox"] + 1,
        }
        with app.state.session_factory() as session:
            receipt = session.scalars(
                sa.select(ManagedDecisionReceipt).where(
                    ManagedDecisionReceipt.org_id == org["org_id"],
                    ManagedDecisionReceipt.proposed_action == CONTROL_PLANE_APPROVAL_VOTE_ACTION,
                    ManagedDecisionReceipt.decision == decision,
                )
            ).one()
            assert receipt.projection["request_id_hash"]
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_pg_mixed_refusal_then_allow_same_vote_key_has_one_terminal_artifact(
    tmp_path: Path,
) -> None:
    app, client, org, database_url = _postgres_approval_app(tmp_path)
    try:
        approval_request_id = _park_agent_registration(
            client,
            org,
            name="pg-mixed-vote-refusal-allow-bot",
            idempotency_key="pg-mixed-vote-request-0001",
        )
        first_approver = _create_user(client, org, role="org_admin")
        second_approver = _create_user(client, org, role="org_admin")
        before = _approval_counts(app, org["org_id"])
        idempotency_key = "pg-mixed-vote-key-0001"

        with ProcessPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(
                    _vote_after_policy_worker,
                    database_url,
                    org["org_id"],
                    approval_request_id,
                    first_approver["X-API-Key"],
                    idempotency_key,
                    "deny",
                    0.0,
                ),
                pool.submit(
                    _vote_after_policy_worker,
                    database_url,
                    org["org_id"],
                    approval_request_id,
                    second_approver["X-API-Key"],
                    idempotency_key,
                    "allow",
                    0.25,
                ),
            ]
            results = [future.result(timeout=30) for future in as_completed(futures)]

        status_codes = {result["status_code"] for result in results}
        codes = {result["code"] for result in results}
        assert status_codes == {403, 409}, results
        assert codes == {"POLICY_DENIED", "IDEMPOTENCY_CONFLICT"}, results
        after = _approval_counts(app, org["org_id"])
        assert after == {
            **before,
            "approval_vote_receipts": before["approval_vote_receipts"] + 1,
            "policy_activate_receipts": before["policy_activate_receipts"] + 2,
            "all_receipts": before["all_receipts"] + 3,
            "events": before["events"] + 1,
            "outbox": before["outbox"] + 1,
        }
        with app.state.session_factory() as session:
            assert _count(session, ApprovalVote, org_id=org["org_id"]) == before["votes"]
            assert _count(session, ApprovalOutcome, org_id=org["org_id"]) == before["outcomes"]
            assert (
                _count(session, ManagedReceiptConsumption, org_id=org["org_id"])
                == before["consumptions"]
            )
            assert (
                _count(
                    session,
                    ManagedDecisionReceipt,
                    org_id=org["org_id"],
                    action=CONTROL_PLANE_APPROVAL_VOTE_ACTION,
                )
                == before["approval_vote_receipts"] + 1
            )
            assert (
                _count(
                    session,
                    ManagedDecisionReceipt,
                    org_id=org["org_id"],
                    action=CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
                )
                == before["policy_activate_receipts"] + 2
            )
            receipt = session.scalars(
                sa.select(ManagedDecisionReceipt).where(
                    ManagedDecisionReceipt.org_id == org["org_id"],
                    ManagedDecisionReceipt.proposed_action == CONTROL_PLANE_APPROVAL_VOTE_ACTION,
                )
            ).one()
            assert receipt.decision == "deny"
            assert (
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(ManagedDecisionReceipt)
                    .where(
                        ManagedDecisionReceipt.org_id == org["org_id"],
                        ManagedDecisionReceipt.proposed_action
                        == CONTROL_PLANE_APPROVAL_VOTE_ACTION,
                        ManagedDecisionReceipt.decision == "allow",
                    )
                )
                == 0
            )
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_pg_stale_policy_trust_and_requester_resume_zero_side_effects(tmp_path: Path) -> None:
    cases = ("policy", "trust", "requester")
    for case in cases:
        app, client, org, database_url = _postgres_approval_app(tmp_path / case)
        try:
            approval_request_id, approver_headers = _park_and_approve(
                client,
                org,
                name=f"pg-stale-{case}-bot",
                request_key=f"pg-approval-stale-{case}-request-0001",
                vote_key=f"pg-approval-stale-{case}-vote-0001",
            )
            if case == "policy":
                _replace_active_policy_direct(app, org["org_id"], rules=_rules_for_policy("deny"))
                expected_code = "APPROVAL_POLICY_STALE"
            elif case == "trust":
                _rotate_receipt_trust_epoch(app, org["org_id"])
                expected_code = "APPROVAL_TRUST_STALE"
            else:
                with app.state.session_factory.begin() as session:
                    user = session.get(User, org["admin_user_id"])
                    assert user is not None
                    user.active = False
                expected_code = "APPROVAL_REQUESTER_INACTIVE"
            before = _approval_counts(app, org["org_id"])

            response = client.post(
                f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
                headers={
                    **approver_headers,
                    BOOTSTRAP_IDEMPOTENCY_HEADER: f"pg-approval-stale-{case}-resume-0001",
                },
            )

            assert response.status_code == 409, (case, response.text)
            assert response.json()["code"] == expected_code
            assert _approval_counts(app, org["org_id"]) == before
        finally:
            app.state.engine.dispose()
            _reset_postgres_schema(database_url)


def test_pg_tampered_sealed_payload_resume_zero_side_effects(tmp_path: Path) -> None:
    app, client, org, database_url = _postgres_approval_app(tmp_path)
    try:
        approval_request_id, approver_headers = _park_and_approve(
            client,
            org,
            name="pg-tampered-payload-bot",
            request_key="pg-approval-tamper-request-0001",
            vote_key="pg-approval-tamper-vote-0001",
        )
        with app.state.session_factory.begin() as session:
            request = session.get(ApprovalRequest, approval_request_id)
            assert request is not None
            sealed = dict(request.sealed_arguments)
            sealed["ciphertext"] = sealed["ciphertext"][:-4] + "AAAA"
            request.sealed_arguments = sealed
        before = _approval_counts(app, org["org_id"])

        response = client.post(
            f"/orgs/{org['org_id']}/approvals/{approval_request_id}/resume",
            headers={
                **approver_headers,
                BOOTSTRAP_IDEMPOTENCY_HEADER: "pg-approval-tamper-resume-0001",
            },
        )

        assert response.status_code == 503, response.text
        assert response.json()["code"] in {"APPROVAL_PAYLOAD_INVALID", "TX_ABORTED"}
        assert _approval_counts(app, org["org_id"]) == before
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_pg_multiprocess_resume_race_authorizes_one_agent(tmp_path: Path) -> None:
    app, client, org, database_url = _postgres_approval_app(tmp_path)
    try:
        approval_request_id, approver_headers = _park_and_approve(
            client,
            org,
            name="pg-multiprocess-resume-bot",
            request_key="pg-approval-multiprocess-request-0001",
            vote_key="pg-approval-multiprocess-vote-0001",
        )
        before = _approval_counts(app, org["org_id"])
        api_key = approver_headers["X-API-Key"]
        worker_keys = [
            "pg-approval-multiprocess-resume-shared",
            "pg-approval-multiprocess-resume-shared",
            "pg-approval-multiprocess-resume-shared",
            "pg-approval-multiprocess-resume-shared",
            "pg-approval-multiprocess-resume-uniq-0001",
            "pg-approval-multiprocess-resume-uniq-0002",
            "pg-approval-multiprocess-resume-uniq-0003",
            "pg-approval-multiprocess-resume-uniq-0004",
        ]

        with ProcessPoolExecutor(max_workers=8) as executor:
            futures = [
                executor.submit(
                    _resume_worker,
                    database_url,
                    org["org_id"],
                    approval_request_id,
                    api_key,
                    key,
                )
                for key in worker_keys
            ]
            results = [future.result(timeout=60) for future in as_completed(futures)]

        statuses = sorted(result["status_code"] for result in results)
        assert statuses.count(201) >= 1, results
        assert set(statuses) <= {201, 409, 500, 503}, results
        if any(result["status_code"] == 503 for result in results):
            assert {result.get("code") for result in results if result["status_code"] == 503} <= {
                "TX_ABORTED"
            }
        with app.state.session_factory() as session:
            assert _count_named_agents(session, org["org_id"], "pg-multiprocess-resume-bot") == 1
            assert _count(session, ApprovalOutcome, org_id=org["org_id"]) == 1
            assert _count(session, ApprovalResumeAuthorization, org_id=org["org_id"]) == 1
            assert _count(session, ManagedReceiptConsumption) == before["consumptions"] + 1
            assert (
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(ManagedMutationAttempt)
                    .where(
                        ManagedMutationAttempt.org_id == org["org_id"],
                        ManagedMutationAttempt.status == "succeeded",
                    )
                )
                == before["attempts"] + 1
            )
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_pg_approval_composite_constraints_reject_cross_scope_rows(tmp_path: Path) -> None:
    app, client, org, database_url = _postgres_approval_app(tmp_path)
    try:
        approval_request_id = _park_agent_registration(
            client,
            org,
            name="pg-cross-scope-bot",
            idempotency_key="pg-approval-cross-scope-request-0001",
        )
        other_org = _bootstrap_org(client)
        _seed_default_scope_and_trust(app, other_org["org_id"])
        with app.state.session_factory() as session:
            request = session.get(ApprovalRequest, approval_request_id)
            other_environment = session.scalars(
                sa.select(Environment).where(Environment.org_id == other_org["org_id"])
            ).one()
            assert request is not None
            request_id = request.id
            other_project_id = other_environment.project_id
            other_environment_id = other_environment.id
        with pytest.raises(IntegrityError):
            with app.state.session_factory.begin() as session:
                session.add(
                    ApprovalVote(
                        id=new_id(),
                        org_id=other_org["org_id"],
                        project_id=other_project_id,
                        environment_id=other_environment_id,
                        approval_request_id=request_id,
                        approver_actor_hash="0" * 64,
                        approver_credential_hash="3" * 64,
                        approver_role="org_admin",
                        decision="approve",
                        idempotency_key_hash="1" * 64,
                        vote_receipt_id="cross-scope-vote-receipt",
                        vote_receipt_hash="4" * 64,
                        vote_audit_event_hash="5" * 64,
                        vote_hash="2" * 64,
                        vote_replay_seal={},
                    )
                )
                session.flush()
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def _postgres_approval_app(tmp_path: Path) -> tuple[Any, TestClient, dict[str, Any], str]:
    if (
        os.environ.get("ACP_TEST_POSTGRES_GATE_ACTIVE") != "1"
        or os.environ.get("ACP_TEST_POSTGRES_SELECTOR_MODE") != "p3-approval"
    ):
        pytest.skip("approval PostgreSQL gate requires the exact P3 approval selector")
    database_url = os.environ.get("ACP_TEST_POSTGRES_URL")
    if not database_url:
        pytest.fail("ACP_TEST_POSTGRES_URL is required by the P3 approval PostgreSQL gate")

    _reset_postgres_schema(database_url)
    result = upgrade_database(database_url, expected_database=EXPECTED_DATABASE)
    assert result.after.state is DatabaseSchemaState.VERSION_0010

    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=tmp_path / "audit",
            bootstrap_token=BOOTSTRAP_TOKEN,
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        ),
    )
    client = TestClient(app, raise_server_exceptions=False)
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate(client, org, rules=_rules_for_policy("escalate"))
    return app, client, org, database_url


def _park_agent_registration(
    client: TestClient,
    org: dict[str, Any],
    *,
    name: str,
    idempotency_key: str,
) -> str:
    response = client.post(
        f"/orgs/{org['org_id']}/agents",
        json={
            "name": name,
            "description": "parked registration",
            "trust_tier": "internal",
            "allowed_tools": ["deploy.staging"],
        },
        headers={
            **_admin_headers(org),
            BOOTSTRAP_IDEMPOTENCY_HEADER: idempotency_key,
        },
    )
    assert response.status_code == 202, response.text
    payload = response.json()
    assert payload["status"] == "escalate_pending"
    assert payload["decision"] == "escalate"
    assert payload["receipt_id"]
    return str(payload["approval_request_id"])


def _park_and_approve(
    client: TestClient,
    org: dict[str, Any],
    *,
    name: str,
    request_key: str,
    vote_key: str,
) -> tuple[str, dict[str, str]]:
    approval_request_id = _park_agent_registration(
        client,
        org,
        name=name,
        idempotency_key=request_key,
    )
    approver_headers = _create_user(client, org, role="org_admin")
    vote = client.post(
        f"/orgs/{org['org_id']}/approvals/{approval_request_id}/votes",
        json={"decision": "approve"},
        headers={
            **approver_headers,
            BOOTSTRAP_IDEMPOTENCY_HEADER: vote_key,
        },
    )
    assert vote.status_code == 200, vote.text
    assert vote.json()["outcome"] == "approved"
    return approval_request_id, approver_headers


def _resume_worker(
    database_url: str,
    org_id: str,
    approval_request_id: str,
    api_key: str,
    idempotency_key: str,
) -> dict[str, Any]:
    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=Path(tempfile.mkdtemp(prefix="acp-approval-race-audit-")),
            bootstrap_token=BOOTSTRAP_TOKEN,
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        ),
        agent_registration_issuer=local_agent_registration_issuer(),
    )
    client = TestClient(app, raise_server_exceptions=False)
    try:
        response = client.post(
            f"/orgs/{org_id}/approvals/{approval_request_id}/resume",
            headers={
                "X-API-Key": api_key,
                BOOTSTRAP_IDEMPOTENCY_HEADER: idempotency_key,
            },
        )
        payload: dict[str, Any]
        try:
            payload = response.json()
        except ValueError:
            payload = {"text": response.text}
        return {"status_code": response.status_code, **payload}
    finally:
        app.state.engine.dispose()


def _vote_worker(
    database_url: str,
    org_id: str,
    approval_request_id: str,
    api_key: str,
    idempotency_key: str,
) -> dict[str, Any]:
    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=Path(tempfile.mkdtemp(prefix="acp-approval-vote-race-audit-")),
            bootstrap_token=BOOTSTRAP_TOKEN,
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        ),
        agent_registration_issuer=local_agent_registration_issuer(),
    )
    client = TestClient(app, raise_server_exceptions=False)
    try:
        response = client.post(
            f"/orgs/{org_id}/approvals/{approval_request_id}/votes",
            json={"decision": "approve"},
            headers={
                "X-API-Key": api_key,
                BOOTSTRAP_IDEMPOTENCY_HEADER: idempotency_key,
            },
        )
        try:
            payload = response.json()
        except ValueError:
            payload = {"text": response.text}
        return {"status_code": response.status_code, **payload}
    finally:
        app.state.engine.dispose()


def _vote_after_policy_worker(
    database_url: str,
    org_id: str,
    approval_request_id: str,
    api_key: str,
    idempotency_key: str,
    policy: str,
    delay_seconds: float,
) -> dict[str, Any]:
    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=Path(tempfile.mkdtemp(prefix="acp-approval-mixed-vote-audit-")),
            bootstrap_token=BOOTSTRAP_TOKEN,
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        ),
        agent_registration_issuer=local_agent_registration_issuer(),
    )
    client = TestClient(app, raise_server_exceptions=False)
    try:
        if delay_seconds:
            time.sleep(delay_seconds)
        if policy == "allow":
            _replace_active_policy_direct(app, org_id, rules=_rules_for_policy("allow"))
        else:
            _replace_active_policy_direct(
                app,
                org_id,
                rules=[
                    {
                        "id": "pg-mixed-deny-approval-vote",
                        "effect": "deny",
                        "tools": [CONTROL_PLANE_APPROVAL_VOTE_ACTION],
                        "reason": "mixed approval vote race",
                    }
                ],
            )
        response = client.post(
            f"/orgs/{org_id}/approvals/{approval_request_id}/votes",
            json={"decision": "approve"},
            headers={
                "X-API-Key": api_key,
                BOOTSTRAP_IDEMPOTENCY_HEADER: idempotency_key,
            },
        )
        try:
            payload = response.json()
        except ValueError:
            payload = {"text": response.text}
        return {"status_code": response.status_code, **payload}
    finally:
        app.state.engine.dispose()


def _rotate_receipt_trust_epoch(app: Any, org_id: str) -> None:
    with app.state.session_factory.begin() as session:
        environment = session.scalars(
            sa.select(Environment).where(Environment.org_id == org_id)
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
            "agents": _count(session, AgentRecord, org_id=org_id),
            "agent_receipts": _count(
                session,
                ManagedDecisionReceipt,
                org_id=org_id,
                action=CONTROL_PLANE_AGENT_CREATE_ACTION,
            ),
            "approval_vote_receipts": _count(
                session,
                ManagedDecisionReceipt,
                org_id=org_id,
                action=CONTROL_PLANE_APPROVAL_VOTE_ACTION,
            ),
            "policy_activate_receipts": _count(
                session,
                ManagedDecisionReceipt,
                org_id=org_id,
                action=CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
            ),
            "all_receipts": _count(session, ManagedDecisionReceipt, org_id=org_id),
            "consumptions": _count(session, ManagedReceiptConsumption, org_id=org_id),
            "events": _count(session, ManagedGovernanceEvent, org_id=org_id),
            "outbox": _count(session, ManagedOutboxMessage, org_id=org_id),
            "attempts": _count(session, ManagedMutationAttempt, org_id=org_id),
            "requests": _count(session, ApprovalRequest, org_id=org_id),
            "votes": _count(session, ApprovalVote, org_id=org_id),
            "outcomes": _count(session, ApprovalOutcome, org_id=org_id),
            "resumes": _count(session, ApprovalResumeAuthorization, org_id=org_id),
        }


def _count(
    session: Any,
    model: type[Any],
    *,
    org_id: str | None = None,
    action: str | None = None,
) -> int:
    statement = sa.select(sa.func.count()).select_from(model)
    if org_id is not None:
        statement = statement.where(model.org_id == org_id)
    if action is not None:
        statement = statement.where(model.proposed_action == action)
    return int(session.scalar(statement) or 0)


def _count_named_agents(session: Any, org_id: str, name: str) -> int:
    return int(
        session.scalar(
            sa.select(sa.func.count())
            .select_from(AgentRecord)
            .where(AgentRecord.org_id == org_id, AgentRecord.name == name)
        )
        or 0
    )


def _reset_postgres_schema(database_url: str) -> None:
    if os.environ.get("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE") != "1":
        pytest.fail("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE=1 is required")
    url = sa.engine.make_url(database_url)
    if url.get_backend_name() != "postgresql" or url.database != EXPECTED_DATABASE:
        pytest.fail("P3 approval gate must target the exact disposable database")
    engine = sa.create_engine(
        url.update_query_dict({"options": "-csearch_path=pg_catalog,public"}),
        future=True,
    )
    try:
        with engine.begin() as connection:
            assert connection.scalar(sa.text("SELECT pg_catalog.current_database()")) == (
                EXPECTED_DATABASE
            )
            connection.execute(sa.text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(sa.text("CREATE SCHEMA public"))
    finally:
        engine.dispose()
