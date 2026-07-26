"""Durable idempotency evidence for canonical native agent creation."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any, cast

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from gove_zone.decision import sha256_json
from sqlalchemy.orm import Session

import acgs_control_plane.app as app_module
from acgs_control_plane.models import (
    AgentRecord,
    AuditProjectionOutbox,
    GovernanceEvent,
    ManagedIdempotencyResult,
    NativeDecisionReceiptRow,
    NativeReceiptConsumption,
)


def _session_factory(client: TestClient) -> Any:
    return cast(Any, client.app).state.session_factory


def _native_providers(client: TestClient) -> Any:
    return cast(Any, client.app).state.native_agent_transaction


def _counts(client: TestClient, org_id: str) -> dict[str, int]:
    with _session_factory(client)() as session:
        return {
            "agents": int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(AgentRecord)
                    .where(AgentRecord.org_id == org_id)
                )
                or 0
            ),
            "events": int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(GovernanceEvent)
                    .where(GovernanceEvent.org_id == org_id)
                )
                or 0
            ),
            "native_receipts": int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(NativeDecisionReceiptRow)
                    .where(NativeDecisionReceiptRow.org_id == org_id)
                )
                or 0
            ),
            "consumptions": int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(NativeReceiptConsumption)
                    .where(NativeReceiptConsumption.org_id == org_id)
                )
                or 0
            ),
            "idempotency": int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(ManagedIdempotencyResult)
                    .where(ManagedIdempotencyResult.org_id == org_id)
                )
                or 0
            ),
        }


def _headers(admin_headers: dict[str, str], key: str) -> dict[str, str]:
    return {**admin_headers, "Idempotency-Key": key}


def _bootstrap_org(client: TestClient, suffix: str) -> dict[str, Any]:
    response = client.post(
        "/orgs",
        json={
            "name": f"Acme {suffix}",
            "admin_name": f"Root {suffix}",
            "admin_email": f"root-{suffix}@acme.example.com",
        },
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _one_idempotency_row(client: TestClient, org_id: str) -> ManagedIdempotencyResult:
    with _session_factory(client)() as session:
        return session.scalars(
            sa.select(ManagedIdempotencyResult).where(ManagedIdempotencyResult.org_id == org_id)
        ).one()


def test_agent_create_requires_bounded_idempotency_key_and_rejects_unknown_fields(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    org_id = org["org_id"]
    before = _counts(client, org_id)

    missing = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "missing-key"},
        headers=admin_headers,
    )
    unknown = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "unknown-field", "environment_id": "attacker"},
        headers=_headers(admin_headers, "unknown-field"),
    )
    duplicate = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "duplicate-header"},
        headers=[
            ("X-API-Key", admin_headers["X-API-Key"]),
            ("Idempotency-Key", "dup-a"),
            ("Idempotency-Key", "dup-b"),
        ],
    )

    assert missing.status_code == 428
    assert missing.json()["code"] == "precondition_required"
    assert unknown.status_code == 422
    assert duplicate.status_code == 400
    assert _counts(client, org_id) == before


def test_same_key_replays_across_v1_alias_with_defaults_and_key_order_without_new_effects(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    org_id = org["org_id"]
    key = "same-key-defaults-alias"
    created = client.post(
        f"/v1/orgs/{org_id}/agents",
        json={"allowed_tools": ["ticket.create"], "name": "déployer"},
        headers=_headers(admin_headers, key),
    )
    assert created.status_code == 201, created.text
    before = _counts(client, org_id)

    replayed = client.post(
        f"/orgs/{org_id}/agents",
        json={
            "name": "déployer",
            "description": "",
            "trust_tier": "untrusted",
            "allowed_tools": ["ticket.create"],
        },
        headers=_headers(admin_headers, key),
    )

    assert replayed.status_code == 201, replayed.text
    assert replayed.json() == created.json()
    assert _counts(client, org_id) == before
    with _session_factory(client)() as session:
        row = session.scalars(
            sa.select(ManagedIdempotencyResult).where(ManagedIdempotencyResult.org_id == org_id)
        ).one()
        agent = session.get(AgentRecord, row.agent_id)
        assert row.key_digest != key
        assert key not in str(row.result_artifact)
        assert "response_body" not in row.result_artifact
        assert row.result_artifact["response_body_hash"] == row.response_body_hash
        assert row.response_body_hash == sha256_json(created.json())
        assert "déployer" not in str(row.result_artifact)
        assert "déployer" not in str(row.__dict__)
        assert agent is not None
        assert agent.name == "déployer"


def test_raw_key_and_agent_body_are_minimized_outside_authoritative_agent_row(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    org_id = org["org_id"]
    key = "raw-key-minimize-sentinel"
    sentinel = "raw-agent-body-minimize-sentinel"

    created = client.post(
        f"/orgs/{org_id}/agents",
        json={
            "name": sentinel,
            "description": sentinel,
            "allowed_tools": [sentinel],
        },
        headers=_headers(admin_headers, key),
    )

    assert created.status_code == 201, created.text
    with _session_factory(client)() as session:
        agent = session.scalars(
            sa.select(AgentRecord).where(AgentRecord.org_id == org_id, AgentRecord.name == sentinel)
        ).one()
        assert sentinel in str(
            {
                "name": agent.name,
                "description": agent.description,
                "allowed_tools": agent.allowed_tools,
            }
        )

        surfaces: dict[str, str] = {}
        row = session.scalars(
            sa.select(ManagedIdempotencyResult).where(ManagedIdempotencyResult.org_id == org_id)
        ).one()
        surfaces["idempotency_row"] = str(
            {
                column.name: getattr(row, column.name)
                for column in row.__table__.columns
                if column.name != "created_at"
            }
        )
        assert "response_body" not in row.__table__.columns
        event = session.scalars(
            sa.select(GovernanceEvent).where(GovernanceEvent.org_id == org_id)
        ).one()
        surfaces["governance_event"] = str(event.payload)
        outbox = session.scalars(
            sa.select(AuditProjectionOutbox).where(AuditProjectionOutbox.org_id == org_id)
        ).one()
        surfaces["audit_projection_outbox"] = str(outbox.payload)
        native = session.scalars(
            sa.select(NativeDecisionReceiptRow).where(NativeDecisionReceiptRow.org_id == org_id)
        ).one()
        surfaces["native_receipt"] = str(
            {
                "projection": native.projection,
                "receipt_artifact": native.receipt_artifact,
            }
        )
        consumption = session.scalars(
            sa.select(NativeReceiptConsumption).where(NativeReceiptConsumption.org_id == org_id)
        ).one()
        surfaces["native_consumption"] = str(consumption.attestation_artifact)

    for name, surface in surfaces.items():
        assert key not in surface, name
        assert sentinel not in surface, name


def test_same_key_different_body_returns_stable_conflict_without_new_effect(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    org_id = org["org_id"]
    key = "same-key-conflict"
    created = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "conflict-a"},
        headers=_headers(admin_headers, key),
    )
    assert created.status_code == 201, created.text
    before = _counts(client, org_id)

    conflict = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "conflict-b"},
        headers=_headers(admin_headers, key),
    )

    assert conflict.status_code == 409
    assert conflict.json()["code"] == "idempotency_conflict"
    assert "conflict-a" not in conflict.text
    assert "conflict-b" not in conflict.text
    assert _counts(client, org_id) == before


def test_unicode_codepoint_and_list_order_are_distinct_semantics(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    org_id = org["org_id"]
    composed = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "café"},
        headers=_headers(admin_headers, "unicode-codepoint"),
    )
    decomposed = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "cafe\u0301"},
        headers=_headers(admin_headers, "unicode-codepoint"),
    )
    ordered = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "ordered-tools", "allowed_tools": ["a", "b"]},
        headers=_headers(admin_headers, "list-order"),
    )
    reordered = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "ordered-tools-2", "allowed_tools": ["b", "a"]},
        headers=_headers(admin_headers, "list-order"),
    )

    assert composed.status_code == 201, composed.text
    assert decomposed.status_code == 409
    assert ordered.status_code == 201, ordered.text
    assert reordered.status_code == 409


def test_same_key_isolated_by_tenant_and_principal(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    make_user: Any,
) -> None:
    first_org_id = org["org_id"]
    second_org = _bootstrap_org(client, "idempotency-isolation")
    second_headers = {"X-API-Key": second_org["admin_api_key"]}
    operator_headers = make_user("agent_operator")
    key = "shared-but-scoped"

    first = client.post(
        f"/orgs/{first_org_id}/agents",
        json={"name": "first-admin"},
        headers=_headers(admin_headers, key),
    )
    same_tenant_other_principal = client.post(
        f"/orgs/{first_org_id}/agents",
        json={"name": "first-operator"},
        headers=_headers(operator_headers, key),
    )
    second_tenant = client.post(
        f"/orgs/{second_org['org_id']}/agents",
        json={"name": "first-admin"},
        headers=_headers(second_headers, key),
    )

    assert first.status_code == 201, first.text
    assert same_tenant_other_principal.status_code == 201, same_tenant_other_principal.text
    assert second_tenant.status_code == 201, second_tenant.text
    assert _counts(client, first_org_id)["idempotency"] == 2
    assert _counts(client, second_org["org_id"])["idempotency"] == 1


def test_concurrent_same_key_different_body_has_one_winner_and_one_conflict(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    org_id = org["org_id"]

    def _create(name: str) -> tuple[int, str]:
        response = client.post(
            f"/orgs/{org_id}/agents",
            json={"name": name},
            headers=_headers(admin_headers, "concurrent-different"),
        )
        return response.status_code, response.text

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_create, ["race-a", "race-b"]))

    assert sorted(status for status, _text in results) == [201, 409]
    assert _counts(client, org_id) == {
        "agents": 1,
        "events": 1,
        "native_receipts": 1,
        "consumptions": 1,
        "idempotency": 1,
    }


def test_policy_deny_replay_returns_fresh_request_id_without_new_evidence(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    publish_and_activate: Any,
) -> None:
    org_id = org["org_id"]
    publish_and_activate(
        org_id,
        admin_headers,
        rules=[
            {
                "id": "deny-idempotent-agent",
                "effect": "deny",
                "tools": ["database.agent.create"],
                "reason": "agent creation denied",
            }
        ],
    )
    key = "deny-replay"
    denied = client.post(
        f"/v1/orgs/{org_id}/agents",
        json={"name": "denied"},
        headers=_headers(admin_headers, key),
    )
    assert denied.status_code == 403, denied.text
    before = _counts(client, org_id)

    replayed = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "denied"},
        headers=_headers(admin_headers, key),
    )

    assert replayed.status_code == 403
    assert replayed.json()["receipt_id"] == denied.json()["receipt_id"]
    assert replayed.json()["request_id"] != denied.json()["request_id"]
    assert _counts(client, org_id) == before


def test_policy_rotation_does_not_change_completed_replay(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    publish_and_activate: Any,
) -> None:
    org_id = org["org_id"]
    key = "policy-rotation-replay"
    created = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "before-rotation"},
        headers=_headers(admin_headers, key),
    )
    assert created.status_code == 201, created.text
    before = _counts(client, org_id)
    publish_and_activate(
        org_id,
        admin_headers,
        rules=[
            {
                "id": "deny-after-first-result",
                "effect": "deny",
                "tools": ["database.agent.create"],
                "reason": "policy rotated",
            }
        ],
        policy_id="rotated-policy",
    )

    replayed = client.post(
        f"/v1/orgs/{org_id}/agents",
        json={"name": "before-rotation"},
        headers=_headers(admin_headers, key),
    )

    assert replayed.status_code == 201, replayed.text
    assert replayed.json() == created.json()
    assert _counts(client, org_id) == before


def test_missing_historical_trust_fails_closed_without_new_effects(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    org_id = org["org_id"]
    key = "missing-historical-trust"
    created = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "trust-replay"},
        headers=_headers(admin_headers, key),
    )
    assert created.status_code == 201, created.text
    before = _counts(client, org_id)
    _native_providers(client).consumption_trust.verifiers = {}

    replayed = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "trust-replay"},
        headers=_headers(admin_headers, key),
    )

    assert replayed.status_code == 503
    assert _counts(client, org_id) == before


@pytest.mark.parametrize(
    "tamper",
    [
        "outcome",
        "status",
        "receipt",
        "agent",
        "response_hash",
        "signature",
        "artifact_hash",
    ],
)
def test_tampered_idempotency_result_fails_closed_without_reexecution(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str], tamper: str
) -> None:
    org_id = org["org_id"]
    key = f"tamper-idempotency-{tamper}"
    created = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": f"tamper-idem-{tamper}"},
        headers=_headers(admin_headers, key),
    )
    assert created.status_code == 201, created.text
    before = _counts(client, org_id)
    with _session_factory(client)() as session:
        row = session.scalars(
            sa.select(ManagedIdempotencyResult).where(ManagedIdempotencyResult.org_id == org_id)
        ).one()
        if tamper == "outcome":
            row.terminal_decision = "deny"
        elif tamper == "status":
            row.response_status = 202
        elif tamper == "receipt":
            row.receipt_id = "forged-receipt"
        elif tamper == "agent":
            row.agent_id = None
        elif tamper == "response_hash":
            row.response_body_hash = "0" * 64
        elif tamper == "signature":
            row.result_signature = "00"
        elif tamper == "artifact_hash":
            row.result_artifact = {**row.result_artifact, "response_body_hash": "0" * 64}
        session.commit()

    replayed = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": f"tamper-idem-{tamper}"},
        headers=_headers(admin_headers, key),
    )

    assert replayed.status_code == 503
    assert _counts(client, org_id) == before


def test_commit_ack_ambiguity_replays_committed_result_without_new_effect(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = org["org_id"]
    original_commit = Session.commit
    state = {"raised": False}

    def _commit_then_raise_once(session: Session) -> None:
        original_commit(session)
        if not state["raised"]:
            state["raised"] = True
            raise RuntimeError("simulated lost commit acknowledgement")

    monkeypatch.setattr(Session, "commit", _commit_then_raise_once)
    first = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "ack-ambiguous"},
        headers=_headers(admin_headers, "commit-ack"),
    )
    assert first.status_code == 500
    before = _counts(client, org_id)
    monkeypatch.setattr(Session, "commit", original_commit)

    replayed = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "ack-ambiguous"},
        headers=_headers(admin_headers, "commit-ack"),
    )

    assert replayed.status_code == 201, replayed.text
    assert _counts(client, org_id) == before


def test_transient_failure_before_result_rolls_back_without_idempotency_row(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = org["org_id"]

    def _fail_before_result(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("simulated transient failure before idempotency result")

    monkeypatch.setattr(app_module, "sign_result_artifact", _fail_before_result)
    failed = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "rollback-before-result"},
        headers=_headers(admin_headers, "rollback-before-result"),
    )

    assert failed.status_code == 500
    assert _counts(client, org_id) == {
        "agents": 0,
        "events": 0,
        "native_receipts": 0,
        "consumptions": 0,
        "idempotency": 0,
    }


def test_concurrent_identical_replays_one_effect_same_process_sqlite(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    org_id = org["org_id"]

    def _create() -> tuple[int, str]:
        response = client.post(
            f"/orgs/{org_id}/agents",
            json={"name": "concurrent-one"},
            headers=_headers(admin_headers, "concurrent-identical"),
        )
        return response.status_code, response.json()["receipt_id"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: _create(), range(2)))

    assert results[0][0] == 201
    assert results[1][0] == 201
    assert results[0][1] == results[1][1]
    assert _counts(client, org_id) == {
        "agents": 1,
        "events": 1,
        "native_receipts": 1,
        "consumptions": 1,
        "idempotency": 1,
    }
