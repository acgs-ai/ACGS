"""Managed environment-scoped policy registry route tests."""

from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError

from acgs_control_plane.managed_mutations import (
    CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
    CONTROL_PLANE_POLICY_PUBLISH_ACTION,
)
from acgs_control_plane.models import (
    Environment,
    EnvironmentPolicyHead,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedMutationAttempt,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    PolicyRegistryIdempotency,
    PolicyVersion,
    Project,
    new_id,
)
from acgs_control_plane.policy_registry import (
    bootstrap_local_policy_registry_trust,
    local_policy_registry_issuer,
)
from acgs_control_plane.tenant_bootstrap import BOOTSTRAP_IDEMPOTENCY_HEADER


def _seed_scope(client: TestClient, org_id: str) -> tuple[str, str]:
    project_id = "project-policy"
    environment_id = "env-policy"
    with client.app.state.session_factory.begin() as session:
        session.add(Project(id=project_id, org_id=org_id, slug="policy", name="Policy"))
        session.add(
            Environment(
                id=environment_id,
                org_id=org_id,
                project_id=project_id,
                slug="production",
                name="Production",
            )
        )
        bootstrap_local_policy_registry_trust(
            session,
            org_id=org_id,
            project_id=project_id,
            environment_id=environment_id,
            issuer=local_policy_registry_issuer(),
        )
    return project_id, environment_id


def _counts(client: TestClient) -> dict[str, int]:
    tables = {
        "versions": PolicyVersion,
        "heads": EnvironmentPolicyHead,
        "receipts": ManagedDecisionReceipt,
        "consumptions": ManagedReceiptConsumption,
        "events": ManagedGovernanceEvent,
        "outbox": ManagedOutboxMessage,
        "attempts": ManagedMutationAttempt,
        "idempotency": PolicyRegistryIdempotency,
    }
    with client.app.state.session_factory() as session:
        return {
            name: int(session.scalar(sa.select(sa.func.count()).select_from(model)) or 0)
            for name, model in tables.items()
        }


def _publish(
    client: TestClient,
    org_id: str,
    project_id: str,
    environment_id: str,
    headers: dict[str, str],
    *,
    key: str = "policy-publish-0001",
    policy_id: str = "policy-one",
    rules: list[dict[str, Any]] | None = None,
) -> Any:
    return client.post(
        f"/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/policies",
        json={
            "policy_id": policy_id,
            "rules": rules
            if rules is not None
            else [{"id": "deny-prod", "effect": "deny", "tools": ["deploy.prod"]}],
        },
        headers={**headers, BOOTSTRAP_IDEMPOTENCY_HEADER: key},
    )


def _activate(
    client: TestClient,
    org_id: str,
    project_id: str,
    environment_id: str,
    bundle_id: str,
    headers: dict[str, str],
    *,
    key: str,
    expected_generation: int,
) -> Any:
    return client.post(
        f"/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/policies/{bundle_id}/activate",
        json={"expected_generation": expected_generation},
        headers={**headers, BOOTSTRAP_IDEMPOTENCY_HEADER: key},
    )


def _allowing_rules() -> list[dict[str, Any]]:
    return [{"id": "deny-unrelated", "effect": "deny", "tools": ["unrelated.tool"]}]


def test_managed_policy_publish_creates_immutable_version_without_head(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    project_id, environment_id = _seed_scope(client, org["org_id"])
    resp = _publish(client, org["org_id"], project_id, environment_id, admin_headers)

    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["project_id"] == project_id
    assert body["environment_id"] == environment_id
    assert body["status"] == "published"
    assert body["generation"] is None
    assert body["key_id"] == "local-control-plane-policy-registry"
    assert body["signature_algorithm"] == "ed25519"
    assert _counts(client) == {
        "versions": 1,
        "heads": 0,
        "receipts": 1,
        "consumptions": 1,
        "events": 1,
        "outbox": 1,
        "attempts": 1,
        "idempotency": 1,
    }
    with client.app.state.session_factory() as session:
        version = session.scalars(sa.select(PolicyVersion)).one()
        assert version.canonical_envelope["scope"] == {
            "org_id": org["org_id"],
            "project_id": project_id,
            "environment_id": environment_id,
        }
        assert version.canonical_envelope["content_hash"] == version.content_hash


def test_managed_policy_versions_are_database_immutable(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    project_id, environment_id = _seed_scope(client, org["org_id"])
    published = _publish(client, org["org_id"], project_id, environment_id, admin_headers).json()

    with client.app.state.session_factory.begin() as session:
        version = session.get(PolicyVersion, published["bundle_id"])
        assert version is not None
        version.policy_id = "mutated-policy-id"
        try:
            session.flush()
        except (DBAPIError, IntegrityError, OperationalError):
            pass
        else:  # pragma: no cover - trigger absence is the failure under test.
            raise AssertionError("policy_versions update was not blocked by the database")

    with client.app.state.session_factory() as session:
        version = session.get(PolicyVersion, published["bundle_id"])
        assert version is not None
        assert version.policy_id == published["policy_id"]

    with client.app.state.session_factory.begin() as session:
        version = session.get(PolicyVersion, published["bundle_id"])
        assert version is not None
        session.delete(version)
        try:
            session.flush()
        except (DBAPIError, IntegrityError, OperationalError):
            pass
        else:  # pragma: no cover - trigger absence is the failure under test.
            raise AssertionError("policy_versions delete was not blocked by the database")

    with client.app.state.session_factory() as session:
        version = session.get(PolicyVersion, published["bundle_id"])
        assert version is not None


def test_managed_policy_activate_advances_head_once_and_stale_is_zero_effect(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    project_id, environment_id = _seed_scope(client, org["org_id"])
    published = _publish(client, org["org_id"], project_id, environment_id, admin_headers).json()
    before_stale = _counts(client)

    active = client.post(
        f"/orgs/{org['org_id']}/projects/{project_id}/environments/{environment_id}/policies/{published['bundle_id']}/activate",
        json={"expected_generation": 0},
        headers={**admin_headers, BOOTSTRAP_IDEMPOTENCY_HEADER: "policy-activate-0001"},
    )
    assert active.status_code == 200, active.text
    assert active.json()["status"] == "active"
    assert active.json()["generation"] == 1

    after_active = _counts(client)
    assert after_active["heads"] == 1
    assert after_active["receipts"] == before_stale["receipts"] + 1
    stale = client.post(
        f"/orgs/{org['org_id']}/projects/{project_id}/environments/{environment_id}/policies/{published['bundle_id']}/activate",
        json={"expected_generation": 0},
        headers={**admin_headers, BOOTSTRAP_IDEMPOTENCY_HEADER: "policy-activate-stale-0001"},
    )
    assert stale.status_code == 409, stale.text
    assert stale.json()["code"] == "POLICY_GENERATION_STALE"
    assert _counts(client) == after_active


def test_managed_policy_head_database_blocks_rewind_and_forged_receipt(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    project_id, environment_id = _seed_scope(client, org["org_id"])
    published = _publish(client, org["org_id"], project_id, environment_id, admin_headers).json()
    active = _activate(
        client,
        org["org_id"],
        project_id,
        environment_id,
        published["bundle_id"],
        admin_headers,
        key="policy-head-guard-activate",
        expected_generation=0,
    )
    assert active.status_code == 200, active.text

    with client.app.state.session_factory.begin() as session:
        head = session.scalars(sa.select(EnvironmentPolicyHead)).one()
        head.generation = 0
        try:
            session.flush()
        except (DBAPIError, IntegrityError, OperationalError):
            pass
        else:  # pragma: no cover - trigger absence is the failure under test.
            raise AssertionError("policy head rewind was not blocked by the database")

    try:
        with client.app.state.session_factory.begin() as session:
            head = session.scalars(sa.select(EnvironmentPolicyHead)).one()
            session.execute(
                sa.update(EnvironmentPolicyHead)
                .where(EnvironmentPolicyHead.id == head.id)
                .values(generation=head.generation + 1, receipt_id="forged-receipt-id")
            )
    except (DBAPIError, IntegrityError, OperationalError):
        pass
    else:  # pragma: no cover - trigger/FK absence is the failure under test.
        raise AssertionError("policy head forged receipt update was not blocked")

    with client.app.state.session_factory() as session:
        head = session.scalars(sa.select(EnvironmentPolicyHead)).one()
        assert head.generation == 1
        assert head.receipt_id == active.json()["receipt_id"]


def test_managed_policy_idempotent_replay_and_conflict(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    project_id, environment_id = _seed_scope(client, org["org_id"])
    first = _publish(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key="policy-publish-replay",
    )
    assert first.status_code == 201, first.text
    counts_after_first = _counts(client)
    replay = _publish(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key="policy-publish-replay",
    )
    assert replay.status_code == 201, replay.text
    assert replay.json() == first.json()
    assert _counts(client) == counts_after_first

    conflict = _publish(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key="policy-publish-replay",
        policy_id="other-policy",
    )
    assert conflict.status_code == 409
    assert conflict.json()["code"] == "IDEMPOTENCY_CONFLICT"
    assert _counts(client) == counts_after_first

    with client.app.state.session_factory.begin() as session:
        session.add(
            Environment(
                id="env-policy-other",
                org_id=org["org_id"],
                project_id=project_id,
                slug="other",
                name="Other",
            )
        )
        bootstrap_local_policy_registry_trust(
            session,
            org_id=org["org_id"],
            project_id=project_id,
            environment_id="env-policy-other",
            issuer=local_policy_registry_issuer(),
        )
    scope_conflict = _publish(
        client,
        org["org_id"],
        project_id,
        "env-policy-other",
        admin_headers,
        key="policy-publish-replay",
    )
    assert scope_conflict.status_code == 409
    assert scope_conflict.json()["code"] == "IDEMPOTENCY_CONFLICT"
    assert _counts(client) == counts_after_first


def test_managed_policy_publish_denial_records_evidence_without_policy_state(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    project_id, environment_id = _seed_scope(client, org["org_id"])
    starter = _publish(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key="policy-deny-starter",
        policy_id="starter",
        rules=_allowing_rules(),
    ).json()
    assert (
        _activate(
            client,
            org["org_id"],
            project_id,
            environment_id,
            starter["bundle_id"],
            admin_headers,
            key="policy-deny-starter-activate",
            expected_generation=0,
        ).status_code
        == 200
    )
    deny_policy = _publish(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key="policy-deny-publish-policy",
        policy_id="deny-publish",
        rules=[
            {
                "id": "deny-policy-publish",
                "effect": "deny",
                "tools": [CONTROL_PLANE_POLICY_PUBLISH_ACTION],
            }
        ],
    ).json()
    assert (
        _activate(
            client,
            org["org_id"],
            project_id,
            environment_id,
            deny_policy["bundle_id"],
            admin_headers,
            key="policy-deny-publish-activate",
            expected_generation=1,
        ).status_code
        == 200
    )
    before = _counts(client)

    denied = _publish(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key="policy-denied-publish",
        policy_id="blocked-candidate",
    )

    assert denied.status_code == 403, denied.text
    assert denied.json()["code"] == "POLICY_DENIED"
    after = _counts(client)
    assert after["versions"] == before["versions"]
    assert after["heads"] == before["heads"]
    assert after["consumptions"] == before["consumptions"]
    assert after["attempts"] == before["attempts"]
    assert after["receipts"] == before["receipts"] + 1
    assert after["events"] == before["events"] + 1
    assert after["outbox"] == before["outbox"] + 1
    assert after["idempotency"] == before["idempotency"] + 1

    replay = _publish(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key="policy-denied-publish",
        policy_id="blocked-candidate",
    )
    assert replay.status_code == 403
    assert replay.json() == denied.json()
    assert _counts(client) == after


def test_managed_policy_activate_escalation_records_evidence_without_head_change(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    project_id, environment_id = _seed_scope(client, org["org_id"])
    escalate_policy = _publish(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key="policy-escalate-activate-policy",
        policy_id="escalate-activate",
        rules=[
            {
                "id": "escalate-policy-activate",
                "effect": "escalate",
                "tools": [CONTROL_PLANE_POLICY_ACTIVATE_ACTION],
            }
        ],
    ).json()
    first_active = _activate(
        client,
        org["org_id"],
        project_id,
        environment_id,
        escalate_policy["bundle_id"],
        admin_headers,
        key="policy-escalate-initial-activate",
        expected_generation=0,
    )
    assert first_active.status_code == 200, first_active.text
    candidate = _publish(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key="policy-escalate-next-candidate",
        policy_id="next-candidate",
        rules=_allowing_rules(),
    ).json()
    before = _counts(client)

    escalated = _activate(
        client,
        org["org_id"],
        project_id,
        environment_id,
        candidate["bundle_id"],
        admin_headers,
        key="policy-escalated-activate",
        expected_generation=1,
    )

    assert escalated.status_code == 202, escalated.text
    assert escalated.json()["code"] == "ESCALATE_PENDING"
    after = _counts(client)
    assert after["versions"] == before["versions"]
    assert after["heads"] == before["heads"]
    assert after["consumptions"] == before["consumptions"]
    assert after["attempts"] == before["attempts"]
    assert after["receipts"] == before["receipts"] + 1
    assert after["events"] == before["events"] + 1
    assert after["outbox"] == before["outbox"] + 1
    assert after["idempotency"] == before["idempotency"] + 1
    with client.app.state.session_factory() as session:
        head = session.scalars(sa.select(EnvironmentPolicyHead)).one()
        assert head.active_policy_version_id == escalate_policy["bundle_id"]
        assert head.generation == 1


def test_managed_policy_activate_replay_precedes_trust_and_generation_checks(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    project_id, environment_id = _seed_scope(client, org["org_id"])
    published = _publish(client, org["org_id"], project_id, environment_id, admin_headers).json()
    first = _activate(
        client,
        org["org_id"],
        project_id,
        environment_id,
        published["bundle_id"],
        admin_headers,
        key="policy-activate-replay-before-cas",
        expected_generation=0,
    )
    assert first.status_code == 200, first.text
    before_replay = _counts(client)
    with client.app.state.session_factory.begin() as session:
        version = session.get(PolicyVersion, published["bundle_id"])
        assert version is not None
        key = version.key_id
        session.execute(
            sa.text("UPDATE managed_trust_keys SET status = 'revoked' WHERE key_id = :key_id"),
            {"key_id": key},
        )

    replay = _activate(
        client,
        org["org_id"],
        project_id,
        environment_id,
        published["bundle_id"],
        admin_headers,
        key="policy-activate-replay-before-cas",
        expected_generation=0,
    )

    assert replay.status_code == 200, replay.text
    assert replay.json() == first.json()
    assert _counts(client) == before_replay


def test_managed_policy_rejects_nonfinite_json_before_persistence(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    project_id, environment_id = _seed_scope(client, org["org_id"])
    before = _counts(client)

    response = client.post(
        f"/orgs/{org['org_id']}/projects/{project_id}/environments/{environment_id}/policies",
        content=(
            '{"policy_id":"nan-policy","rules":'
            '[{"id":"nan","effect":"deny","tools":["x"],"weight":NaN}]}'
        ),
        headers={
            **admin_headers,
            BOOTSTRAP_IDEMPOTENCY_HEADER: "policy-nonfinite-json",
            "content-type": "application/json",
        },
    )

    assert response.status_code == 422, response.text
    assert response.json()["code"] == "POLICY_INVALID_JSON"
    assert _counts(client) == before


def test_managed_policy_cross_environment_envelope_transplant_fails_before_effect(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    project_id, environment_id = _seed_scope(client, org["org_id"])
    other_environment_id = "env-policy-transplant"
    with client.app.state.session_factory.begin() as session:
        session.add(
            Environment(
                id=other_environment_id,
                org_id=org["org_id"],
                project_id=project_id,
                slug="transplant",
                name="Transplant",
            )
        )
        bootstrap_local_policy_registry_trust(
            session,
            org_id=org["org_id"],
            project_id=project_id,
            environment_id=other_environment_id,
            issuer=local_policy_registry_issuer(),
        )
    published = _publish(client, org["org_id"], project_id, environment_id, admin_headers).json()
    with client.app.state.session_factory.begin() as session:
        original = session.get(PolicyVersion, published["bundle_id"])
        assert original is not None
        session.add(
            PolicyVersion(
                id=new_id(),
                org_id=org["org_id"],
                project_id=project_id,
                environment_id=other_environment_id,
                policy_id=original.policy_id,
                version=original.version,
                content_hash=original.content_hash,
                document=dict(original.document),
                rules=list(original.rules),
                canonical_envelope=dict(original.canonical_envelope),
                purpose=original.purpose,
                key_id=original.key_id,
                signature_algorithm=original.signature_algorithm,
                signature=original.signature,
                trust_epoch=original.trust_epoch,
                receipt_id=original.receipt_id,
            )
        )
    before = _counts(client)
    with client.app.state.session_factory() as session:
        transplanted = session.scalars(
            sa.select(PolicyVersion).where(PolicyVersion.environment_id == other_environment_id)
        ).one()

    response = _activate(
        client,
        org["org_id"],
        project_id,
        other_environment_id,
        transplanted.id,
        admin_headers,
        key="policy-transplant-activate",
        expected_generation=0,
    )

    assert response.status_code == 503, response.text
    assert response.json()["code"] == "POLICY_SIGNATURE_REFUSED"
    assert _counts(client) == before


def test_managed_policy_wrong_environment_fails_before_effect(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    project_id, _environment_id = _seed_scope(client, org["org_id"])
    before = _counts(client)
    resp = _publish(client, org["org_id"], project_id, "missing-env", admin_headers)
    assert resp.status_code == 404
    assert resp.json()["code"] == "SCOPE_NOT_FOUND"
    assert _counts(client) == before
