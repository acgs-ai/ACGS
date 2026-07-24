"""Route-level evidence for native transactional agent creation."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest
import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from gove_zone.decision import sha256_json
from gove_zone.policy import RuleSetPolicy
from gove_zone.signing import Ed25519Signer
from sqlalchemy.orm.attributes import flag_modified

from acgs_control_plane.app import NativeAgentTransactionProviders, create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.models import (
    AgentRecord,
    AuditProjectionOutbox,
    Environment,
    GovernanceEvent,
    GovernanceEventHead,
    NativeDecisionReceiptRow,
    NativeReceiptConsumption,
    PolicyBundle,
    Project,
    ReceiptRow,
)
from acgs_control_plane.native_receipts import (
    ManagedConsumptionAttestationTrust,
    ManagedNativeReceiptTrust,
    TenantPrivacyProvider,
    verify_native_evidence_chain,
)
from acgs_control_plane.scope_defaults import (
    legacy_default_environment_id,
    legacy_default_project_id,
)

BOOTSTRAP_TOKEN = "test-bootstrap-token"
_ISSUER_PRIVATE = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
_ATTESTOR_PRIVATE = bytes.fromhex(
    "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
)


def _providers() -> NativeAgentTransactionProviders:
    issuer = Ed25519Signer.from_private_bytes(_ISSUER_PRIVATE, key_id="native-agent-route-issuer")
    attestor = Ed25519Signer.from_private_bytes(
        _ATTESTOR_PRIVATE, key_id="native-agent-route-attestor"
    )
    return NativeAgentTransactionProviders(
        receipt_trust=ManagedNativeReceiptTrust(
            signer=issuer,
            verifiers={issuer.key_id: issuer},
        ),
        consumption_trust=ManagedConsumptionAttestationTrust(
            signer=attestor,
            verifiers={attestor.key_id: attestor},
        ),
        privacy=TenantPrivacyProvider(b"native-agent-route-privacy-key-32b"),
    )


def _providers_with_same_public_key() -> NativeAgentTransactionProviders:
    signer = Ed25519Signer.from_private_bytes(_ISSUER_PRIVATE, key_id="issuer")
    attestor = Ed25519Signer.from_private_bytes(_ISSUER_PRIVATE, key_id="attestor")
    return NativeAgentTransactionProviders(
        receipt_trust=ManagedNativeReceiptTrust(
            signer=signer,
            verifiers={signer.key_id: signer},
        ),
        consumption_trust=ManagedConsumptionAttestationTrust(
            signer=attestor,
            verifiers={attestor.key_id: attestor},
        ),
        privacy=TenantPrivacyProvider(b"native-agent-route-privacy-key-32b"),
    )


def _client(
    tmp_path: Path, *, providers: NativeAgentTransactionProviders | None = None
) -> TestClient:
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'native-agent-route.sqlite3'}",
            audit_dir=tmp_path / "audit",
            bootstrap_token=BOOTSTRAP_TOKEN,
            create_tables=True,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        ),
        native_agent_transaction=providers,
    )
    return TestClient(app, raise_server_exceptions=False)


def _app(client: TestClient) -> FastAPI:
    return cast(FastAPI, client.app)


def _bootstrap(client: TestClient, name: str = "Native Route Org") -> dict[str, Any]:
    response = client.post(
        "/orgs",
        json={
            "name": name,
            "admin_name": "Root Admin",
            "admin_email": f"{name.lower().replace(' ', '-')}@example.com",
        },
        headers={"X-Bootstrap-Token": BOOTSTRAP_TOKEN},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _insert_active_policy(
    client: TestClient,
    org_id: str,
    *,
    environment_id: str,
    policy_id: str,
    rules: list[dict[str, Any]],
) -> None:
    bundle = {"id": policy_id, "rules": rules}
    parsed = RuleSetPolicy.from_dict(bundle)
    with _app(client).state.session_factory() as session:
        environment = session.get(Environment, environment_id)
        assert environment is not None
        # The schema allows one active bundle per org, so activating here
        # retires any currently active bundle first.
        for row in session.scalars(
            sa.select(PolicyBundle).where(
                PolicyBundle.org_id == org_id, PolicyBundle.status == "active"
            )
        ):
            row.status = "retired"
        session.add(
            PolicyBundle(
                org_id=org_id,
                project_id=environment.project_id,
                environment_id=environment_id,
                policy_id=policy_id,
                version=parsed.version,
                bundle=bundle,
                status="active",
            )
        )
        session.commit()


def _counts(client: TestClient, org_id: str) -> dict[str, int]:
    with _app(client).state.session_factory() as session:
        return {
            "agents": int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(AgentRecord)
                    .where(AgentRecord.org_id == org_id)
                )
                or 0
            ),
            "legacy_receipts": int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(ReceiptRow)
                    .where(ReceiptRow.org_id == org_id)
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
            "projects": int(
                session.scalar(
                    sa.select(sa.func.count()).select_from(Project).where(Project.org_id == org_id)
                )
                or 0
            ),
            "environments": int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(Environment)
                    .where(Environment.org_id == org_id)
                )
                or 0
            ),
        }


def _assert_native_verify_ok(
    client: TestClient, org_id: str, headers: dict[str, str], receipt_id: str
) -> None:
    verified = client.post(f"/v1/orgs/{org_id}/receipts/{receipt_id}/verify", headers=headers)
    assert verified.status_code == 200, verified.text
    assert verified.json()["chain_valid"] is True
    assert verified.json()["failures"] == []


def _assert_native_verify_invalid(
    client: TestClient, org_id: str, headers: dict[str, str], receipt_id: str
) -> None:
    verified = client.post(f"/v1/orgs/{org_id}/receipts/{receipt_id}/verify", headers=headers)
    assert verified.status_code == 200, verified.text
    assert verified.json() == {
        "receipt_id": receipt_id,
        "receipt_in_chain": False,
        "chain_valid": False,
        "chain_checked": 1,
        "anchor_matched": False,
        "failures": [{"type": "native_evidence_invalid"}],
        "assurance_class": "native",
        "source_system": "gove-zone",
    }


def test_agent_create_uses_single_native_sql_transaction_and_verifies_offline(
    tmp_path: Path,
) -> None:
    providers = _providers()
    client = _client(tmp_path, providers=providers)
    try:
        org = _bootstrap(client)
        org_id = org["org_id"]

        created = client.post(
            f"/v1/orgs/{org_id}/agents",
            json={"name": "dispatcher", "allowed_tools": ["ticket.create"]},
            headers={"X-API-Key": org["admin_api_key"]},
        )

        assert created.status_code == 201, created.text
        assert created.json()["receipt_id"]
        public_receipt = client.get(
            f"/v1/orgs/{org_id}/receipts/{created.json()['receipt_id']}",
            headers={"X-API-Key": org["admin_api_key"]},
        )
        assert public_receipt.status_code == 200, public_receipt.text
        public_body = public_receipt.json()
        assert public_body["assurance_class"] == "native"
        assert public_body["source_system"] == "gove-zone"
        assert public_body["tool"] == "database.agent.create"
        assert public_body["execution_boundary"] == "control-plane/sql-transaction"
        assert public_body["payload"]["receipt_id"] == created.json()["receipt_id"]
        public_verify = client.post(
            f"/v1/orgs/{org_id}/receipts/{created.json()['receipt_id']}/verify",
            headers={"X-API-Key": org["admin_api_key"]},
        )
        assert public_verify.status_code == 200, public_verify.text
        assert public_verify.json() == {
            "receipt_id": created.json()["receipt_id"],
            "receipt_in_chain": True,
            "chain_valid": True,
            "chain_checked": 1,
            "anchor_matched": True,
            "failures": [],
            "assurance_class": "native",
            "source_system": "gove-zone",
        }
        with _app(client).state.session_factory() as session:
            agent = session.scalars(
                sa.select(AgentRecord).where(AgentRecord.org_id == org_id)
            ).one()
            event = session.scalars(
                sa.select(GovernanceEvent).where(GovernanceEvent.org_id == org_id)
            ).one()
            head = session.get(GovernanceEventHead, org_id)
            outbox = session.scalars(
                sa.select(AuditProjectionOutbox).where(AuditProjectionOutbox.org_id == org_id)
            ).one()
            native = session.scalars(
                sa.select(NativeDecisionReceiptRow).where(NativeDecisionReceiptRow.org_id == org_id)
            ).one()
            consumption = session.scalars(
                sa.select(NativeReceiptConsumption).where(NativeReceiptConsumption.org_id == org_id)
            ).one()
            legacy_tools = [
                row.tool
                for row in session.scalars(sa.select(ReceiptRow).where(ReceiptRow.org_id == org_id))
            ]
            environment = session.get(Environment, agent.environment_id)
            assert environment is not None

            assert agent.name == "dispatcher"
            assert legacy_tools == ["org.create"]
            assert event.tool == "database.agent.create"
            assert event.decision == "allow"
            assert event.payload["path"] == [org_id, environment.project_id, agent.environment_id]
            assert event.payload["argument_hash"] == sha256_json(
                {
                    "name": "dispatcher",
                    "description": "",
                    "trust_tier": "untrusted",
                    "allowed_tools": ["ticket.create"],
                }
            )
            assert head is not None
            assert (head.last_sequence, head.last_event_hash) == (1, event.event_hash)
            assert outbox.event_hash == event.event_hash
            assert native.audit_event_hash == event.event_hash
            assert native.policy_hash == sha256_json(
                {
                    "id": "acp-baseline/v1",
                    "rules": [
                        {
                            "id": "baseline-escalate-org-destructive",
                            "effect": "escalate",
                            "tools": ["org.delete", "org.purge"],
                            "reason": (
                                "destructive org operations require explicit policy + approval"
                            ),
                        }
                    ],
                }
            )
            assert native.receipt_artifact is not None
            assert consumption.attestation_artifact is not None
            assert consumption.attestation_signing_key_id != native.signing_key_id
            verified = verify_native_evidence_chain(
                session,
                org_id,
                trust=providers.receipt_trust,
                consumption_trust=providers.consumption_trust,
            )
            assert verified.receipt_count == 1
            assert verified.event_count == 1
            assert verified.last_event_hash == event.event_hash
    finally:
        _app(client).state.engine.dispose()


def test_agent_create_missing_native_providers_fails_before_mutation(tmp_path: Path) -> None:
    client = _client(tmp_path)
    try:
        org = _bootstrap(client)
        before = _counts(client, org["org_id"])

        response = client.post(
            f"/orgs/{org['org_id']}/agents",
            json={"name": "dispatcher"},
            headers={"X-API-Key": org["admin_api_key"]},
        )

        assert response.status_code == 503
        assert _counts(client, org["org_id"]) == before
    finally:
        _app(client).state.engine.dispose()


def test_agent_create_rejects_same_issuer_attestor_key_material_before_governance(
    tmp_path: Path,
) -> None:
    client = _client(tmp_path, providers=_providers_with_same_public_key())
    try:
        org = _bootstrap(client)
        before = _counts(client, org["org_id"])

        response = client.post(
            f"/orgs/{org['org_id']}/agents",
            json={"name": "dispatcher"},
            headers={"X-API-Key": org["admin_api_key"]},
        )

        assert response.status_code == 503
        assert _counts(client, org["org_id"]) == before
    finally:
        _app(client).state.engine.dispose()


def test_agent_create_policy_deny_has_no_agent_or_native_consumption(tmp_path: Path) -> None:
    providers = _providers()
    client = _client(tmp_path, providers=providers)
    try:
        org = _bootstrap(client, "Native Deny Org")
        headers = {"X-API-Key": org["admin_api_key"]}
        published = client.post(
            f"/orgs/{org['org_id']}/policies",
            json={
                "policy_id": "deny-native-agent",
                "rules": [
                    {
                        "id": "deny-native-untrusted",
                        "effect": "deny",
                        "tools": ["database.agent.create"],
                        "state_equals": {"trust_tier": "untrusted"},
                        "reason": "untrusted native agents are not allowed",
                    }
                ],
            },
            headers=headers,
        )
        assert published.status_code == 201, published.text
        activated = client.post(
            f"/orgs/{org['org_id']}/policies/{published.json()['bundle_id']}/activate",
            headers=headers,
        )
        assert activated.status_code == 200, activated.text
        before = _counts(client, org["org_id"])

        denied = client.post(
            f"/v1/orgs/{org['org_id']}/agents",
            json={"name": "blocked", "trust_tier": "untrusted"},
            headers=headers,
        )

        assert denied.status_code == 403
        receipt_id = denied.json()["receipt_id"]
        assert receipt_id
        after = _counts(client, org["org_id"])
        assert after["agents"] == before["agents"]
        assert after["legacy_receipts"] == before["legacy_receipts"]
        assert after["native_receipts"] == before["native_receipts"] + 1
        assert after["consumptions"] == before["consumptions"]
        assert after["events"] == before["events"] + 1
        assert after["projects"] == before["projects"]
        assert after["environments"] == before["environments"]
        receipt = client.get(f"/v1/orgs/{org['org_id']}/receipts/{receipt_id}", headers=headers)
        assert receipt.status_code == 200, receipt.text
        assert receipt.json()["decision"] == "deny"
        assert receipt.json()["assurance_class"] == "native"
        _assert_native_verify_ok(client, org["org_id"], headers, receipt_id)
        with _app(client).state.session_factory() as session:
            native = session.scalars(
                sa.select(NativeDecisionReceiptRow).where(
                    NativeDecisionReceiptRow.org_id == org["org_id"]
                )
            ).one()
            verified = verify_native_evidence_chain(
                session,
                org["org_id"],
                trust=providers.receipt_trust,
                consumption_trust=providers.consumption_trust,
            )
            assert verified.receipt_count == 1
            session.add(
                NativeReceiptConsumption(
                    org_id=org["org_id"],
                    native_receipt_id=native.id,
                    receipt_hash="0" * 64,
                    audit_event_hash="1" * 64,
                )
            )
            session.commit()
        _assert_native_verify_invalid(client, org["org_id"], headers, receipt_id)
    finally:
        _app(client).state.engine.dispose()


def test_agent_create_policy_escalate_has_no_agent_or_scope_creation(tmp_path: Path) -> None:
    providers = _providers()
    client = _client(tmp_path, providers=providers)
    try:
        org = _bootstrap(client, "Native Escalate Org")
        headers = {"X-API-Key": org["admin_api_key"]}
        published = client.post(
            f"/orgs/{org['org_id']}/policies",
            json={
                "policy_id": "escalate-native-agent",
                "rules": [
                    {
                        "id": "escalate-native-untrusted",
                        "effect": "escalate",
                        "tools": ["database.agent.create"],
                        "state_equals": {"trust_tier": "untrusted"},
                        "reason": "untrusted native agents need approval",
                    }
                ],
            },
            headers=headers,
        )
        assert published.status_code == 201, published.text
        activated = client.post(
            f"/orgs/{org['org_id']}/policies/{published.json()['bundle_id']}/activate",
            headers=headers,
        )
        assert activated.status_code == 200, activated.text
        before = _counts(client, org["org_id"])

        escalated = client.post(
            f"/v1/orgs/{org['org_id']}/agents",
            json={"name": "pending", "trust_tier": "untrusted"},
            headers=headers,
        )

        assert escalated.status_code == 202
        receipt_id = escalated.json()["receipt_id"]
        assert receipt_id
        after = _counts(client, org["org_id"])
        assert after["agents"] == before["agents"]
        assert after["legacy_receipts"] == before["legacy_receipts"]
        assert after["native_receipts"] == before["native_receipts"] + 1
        assert after["consumptions"] == before["consumptions"]
        assert after["events"] == before["events"] + 1
        assert after["projects"] == before["projects"]
        assert after["environments"] == before["environments"]
        receipt = client.get(f"/v1/orgs/{org['org_id']}/receipts/{receipt_id}", headers=headers)
        assert receipt.status_code == 200, receipt.text
        assert receipt.json()["decision"] == "escalate"
        assert receipt.json()["assurance_class"] == "native"
        _assert_native_verify_ok(client, org["org_id"], headers, receipt_id)
        with _app(client).state.session_factory() as session:
            verified = verify_native_evidence_chain(
                session,
                org["org_id"],
                trust=providers.receipt_trust,
                consumption_trust=providers.consumption_trust,
            )
            assert verified.receipt_count == 1
    finally:
        _app(client).state.engine.dispose()


def test_agent_create_uses_default_environment_policy_not_cross_env_allow(
    tmp_path: Path,
) -> None:
    client = _client(tmp_path, providers=_providers())
    try:
        org = _bootstrap(client, "Native Cross Env Org")
        org_id = org["org_id"]
        default_env_id = legacy_default_environment_id(org_id)
        default_project_id = legacy_default_project_id(org_id)
        sibling_project_id = "sibling-project"
        sibling_env_id = "sibling-env"
        with _app(client).state.session_factory() as session:
            session.add(
                Project(
                    id=sibling_project_id,
                    org_id=org_id,
                    slug="sibling",
                    name="Sibling project",
                )
            )
            session.add(
                Environment(
                    id=sibling_env_id,
                    org_id=org_id,
                    project_id=sibling_project_id,
                    slug="sibling",
                    name="Sibling environment",
                )
            )
            assert session.get(Environment, default_env_id) is not None
            assert session.get(Project, default_project_id) is not None
            session.commit()
        # Phase 1: the org's single active bundle is bound to the sibling
        # environment and denies native agent creation. The route must select
        # policy by the default environment, so the sibling deny cannot govern
        # this action and the transaction falls back to the baseline policy.
        _insert_active_policy(
            client,
            org_id,
            environment_id=sibling_env_id,
            policy_id="sibling-env-deny",
            rules=[
                {
                    "id": "sibling-deny-agent-create",
                    "effect": "deny",
                    "tools": ["database.agent.create"],
                    "reason": "sibling environment denies native agent creation",
                }
            ],
        )
        before = _counts(client, org_id)

        allowed = client.post(
            f"/orgs/{org_id}/agents",
            json={"name": "not-confused"},
            headers={"X-API-Key": org["admin_api_key"]},
        )

        assert allowed.status_code == 201, allowed.text
        after_allow = _counts(client, org_id)
        assert after_allow["agents"] == before["agents"] + 1
        assert after_allow["native_receipts"] == before["native_receipts"] + 1
        assert after_allow["consumptions"] == before["consumptions"] + 1
        assert after_allow["events"] == before["events"] + 1

        # Phase 2: activating a deny bundle bound to the default environment
        # (which retires the sibling bundle) must govern and block creation.
        _insert_active_policy(
            client,
            org_id,
            environment_id=default_env_id,
            policy_id="default-env-deny",
            rules=[
                {
                    "id": "deny-default-env-agent",
                    "effect": "deny",
                    "tools": ["database.agent.create"],
                    "reason": "default environment denies native agent creation",
                }
            ],
        )
        before = _counts(client, org_id)

        denied = client.post(
            f"/orgs/{org_id}/agents",
            json={"name": "confused"},
            headers={"X-API-Key": org["admin_api_key"]},
        )

        assert denied.status_code == 403
        assert "default environment denies" in denied.json()["reason"]
        after = _counts(client, org_id)
        assert after["agents"] == before["agents"]
        assert after["native_receipts"] == before["native_receipts"] + 1
        assert after["consumptions"] == before["consumptions"]
        assert after["events"] == before["events"] + 1
    finally:
        _app(client).state.engine.dispose()


@pytest.mark.parametrize(
    "tamper",
    ["receipt_artifact", "projection", "event", "consumption", "signature"],
)
def test_public_native_verify_fails_closed_on_tampered_evidence(
    tmp_path: Path, tamper: str
) -> None:
    client = _client(tmp_path, providers=_providers())
    try:
        org = _bootstrap(client, f"Native Tamper {tamper}")
        org_id = org["org_id"]
        headers = {"X-API-Key": org["admin_api_key"]}
        created = client.post(
            f"/v1/orgs/{org_id}/agents",
            json={"name": f"tamper-{tamper}"},
            headers=headers,
        )
        assert created.status_code == 201, created.text
        receipt_id = created.json()["receipt_id"]

        with _app(client).state.session_factory() as session:
            native = session.scalars(
                sa.select(NativeDecisionReceiptRow).where(NativeDecisionReceiptRow.org_id == org_id)
            ).one()
            event = session.scalars(
                sa.select(GovernanceEvent).where(GovernanceEvent.org_id == org_id)
            ).one()
            consumption = session.scalars(
                sa.select(NativeReceiptConsumption).where(NativeReceiptConsumption.org_id == org_id)
            ).one()
            if tamper == "receipt_artifact":
                artifact = dict(native.receipt_artifact or {})
                artifact["policy_hash"] = "0" * 64
                native.receipt_artifact = artifact
            elif tamper == "projection":
                projection = dict(native.projection)
                projection["argument_hash"] = "0" * 64
                native.projection = projection
            elif tamper == "event":
                payload = dict(event.payload)
                payload["actor"] = "attacker"
                event.payload = payload
                flag_modified(event, "payload")
            elif tamper == "consumption":
                artifact = dict(consumption.attestation_artifact or {})
                artifact["proposed_action"] = "database.agent.delete"
                consumption.attestation_artifact = artifact
            else:
                artifact = dict(native.receipt_artifact or {})
                artifact["signature"] = "00"
                native.receipt_artifact = artifact
            session.commit()

        _assert_native_verify_invalid(client, org_id, headers, receipt_id)
    finally:
        _app(client).state.engine.dispose()
