"""Receipt cursor pagination through the actual FastAPI router."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient
from gove_zone.decision import sha256_json
from gove_zone.policy import RuleSetPolicy
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, ReceiptTrustScope
from sqlalchemy import delete, func, select

import acgs_control_plane.pagination as pagination
from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.migrations import upgrade_database
from acgs_control_plane.models import (
    ComplianceExport,
    Environment,
    EnvironmentPolicyHead,
    ManagedDecisionReceipt,
    Organization,
    PolicyBundle,
    PolicyVersion,
    Project,
    ReceiptRow,
    new_id,
    utcnow,
)
from acgs_control_plane.pagination import (
    CursorConfigurationError,
    CursorKeyring,
    issue_receipt_cursor,
    receipt_filter_digest,
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

BOOTSTRAP_TOKEN = "cursor-bootstrap-token"
KEY_BYTES = bytes(range(32))
OTHER_KEY_BYTES = bytes(reversed(range(32)))


def _keyring(
    key: bytes = KEY_BYTES, *, ttl_seconds: int = 300, clock_skew_seconds: int = 30
) -> CursorKeyring:
    return CursorKeyring(
        active_key_id="test-key",
        active_key=key,
        ttl_seconds=ttl_seconds,
        clock_skew_seconds=clock_skew_seconds,
    )


def _settings(
    tmp_path: Path,
    audit_dir: Path,
    *,
    key: bytes = KEY_BYTES,
    clock_skew_seconds: int = 30,
    database_name: str = "acp.sqlite3",
) -> Settings:
    # Migrate rather than create_tables=True: the latter builds only the frozen
    # v0 surface, which has no projects/environments tables, so agent
    # registration cannot resolve its scope. These tests exercise the router as
    # deployed, which is always a migrated schema.
    database_url = f"sqlite:///{tmp_path / database_name}"
    upgrade_database(database_url)
    return Settings(
        database_url=database_url,
        audit_dir=audit_dir,
        bootstrap_token=BOOTSTRAP_TOKEN,
        create_tables=False,
        runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        cursor_keyring=_keyring(key, clock_skew_seconds=clock_skew_seconds),
        cursor_clock_skew_seconds=clock_skew_seconds,
    )


def _client(
    tmp_path: Path, audit_dir: Path, *, key: bytes = KEY_BYTES, clock_skew_seconds: int = 30
) -> TestClient:
    return TestClient(
        create_app(_settings(tmp_path, audit_dir, key=key, clock_skew_seconds=clock_skew_seconds)),
        raise_server_exceptions=False,
    )


def _bootstrap(client: TestClient) -> tuple[str, dict[str, str]]:
    resp = client.post(
        "/orgs",
        json={
            "name": "Cursor Org",
            "admin_name": "Root Admin",
            "admin_email": "root.cursor@example.com",
        },
        headers={"X-Bootstrap-Token": BOOTSTRAP_TOKEN},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    headers = {"X-API-Key": body["admin_api_key"]}
    _seed_agent_registration_prerequisites(client, body["org_id"], headers)
    return body["org_id"], headers


def _seed_agent_registration_prerequisites(
    client: TestClient, org_id: str, headers: dict[str, str]
) -> None:
    """Satisfy the governed preconditions for ``POST /orgs/{org}/agents``.

    Agent registration is a canonical managed mutation: it resolves the
    org's default project/environment scope, mints a receipt-v2 under a
    trusted key for that scope, and requires an active policy bundle.
    These tests use agent creation only to produce receipts to paginate,
    so they seed the scope and trust directly and publish a permissive
    bundle, mirroring test_agent_registration_managed_route.py.
    """
    app = client.app
    project_id = f"project-{new_id()}"
    environment_id = f"environment-{new_id()}"
    with app.state.session_factory.begin() as session:
        session.add_all(
            [
                Project(id=project_id, org_id=org_id, slug="default", name="Default"),
                Environment(
                    id=environment_id,
                    org_id=org_id,
                    project_id=project_id,
                    slug="production",
                    name="Production",
                ),
            ]
        )
        session.flush()
        scope = ReceiptTrustScope(org_id, project_id, environment_id, DECISION_RECEIPT_PURPOSE)
        signer = app.state.agent_registration_service.issuer.signer_for_scope(scope, trust_epoch=1)
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
        policy_signer = local_policy_registry_issuer().signer_for_scope(policy_scope, trust_epoch=1)
        ManagedTrustLifecycleService(session).bootstrap(
            scope=policy_scope,
            key_id=policy_signer.key_id,
            algorithm=policy_signer.algorithm,
            public_key_spki_der=public_spki_der_from_signer(policy_signer),
            not_after=utcnow() + timedelta(days=1),
        )
    _activate_managed_policy(client, org_id)
    publish = client.post(
        f"/orgs/{org_id}/policies",
        json={
            "policy_id": f"policy-{new_id()}",
            "rules": [
                {
                    "id": "deny-unrelated",
                    "effect": "deny",
                    "tools": ["unrelated.tool"],
                    "reason": "unrelated tools disabled",
                }
            ],
        },
        headers=headers,
    )
    assert publish.status_code == 201, publish.text
    activate = client.post(
        f"/orgs/{org_id}/policies/{publish.json()['bundle_id']}/activate",
        headers=headers,
    )
    assert activate.status_code == 200, activate.text


def _activate_managed_policy(client: TestClient, org_id: str) -> None:
    """Seed the signed environment policy head that governs agent registration.

    Agent registration fails closed without an active, signature-verifiable
    ``EnvironmentPolicyHead``. Mirrors test_agent_registration_managed_route.py:
    the version and head are seeded directly because the managed policy routes
    mint decision receipts under the policy-registry issuer, while these tests
    bootstrap the scope's decision-receipt trust with the agent-registration
    issuer key.
    """
    policy_id = f"managed-policy-{new_id()}"
    rules = [
        {
            "id": "deny-unrelated",
            "effect": "deny",
            "tools": ["unrelated.tool"],
            "reason": "unrelated tools disabled",
        }
    ]
    parsed = RuleSetPolicy.from_dict({"id": policy_id, "rules": rules})
    document = {"id": parsed.policy_id, "version": parsed.version, "rules": list(rules)}
    with client.app.state.session_factory.begin() as session:
        environment = session.scalars(
            select(Environment)
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
        )
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


def _seed_policy_head_receipt(
    session: Any,
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
) -> str:
    receipt_id = f"test-policy-head-receipt-{new_id()}"
    receipt_hash = sha256_json({"schema": "test-policy-head-receipt/v1", "receipt_id": receipt_id})
    audit_hash = sha256_json({"schema": "test-policy-head-audit/v1", "receipt_id": receipt_id})
    now = utcnow()
    session.add(
        ManagedDecisionReceipt(
            id=f"test-policy-head-{new_id()}",
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


def _seed_receipts(
    client: TestClient, org_id: str, headers: dict[str, str], count: int = 5
) -> None:
    for i in range(count):
        resp = client.post(
            f"/orgs/{org_id}/agents",
            json={"name": f"cursor-bot-{i}"},
            headers={**headers, BOOTSTRAP_IDEMPOTENCY_HEADER: f"cursor-seed-{i:04d}"},
        )
        assert resp.status_code == 201, resp.text


def _pin_receipt_order(client: TestClient, org_id: str) -> list[str]:
    with client.app.state.session_factory() as session:
        rows = list(
            session.execute(
                select(ReceiptRow).where(ReceiptRow.org_id == org_id).order_by(ReceiptRow.id.asc())
            ).scalars()
        )
        base = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
        for index, row in enumerate(rows):
            row.created_at = base + timedelta(seconds=index // 2)
        session.commit()
        ordered = list(
            session.execute(
                select(ReceiptRow)
                .where(ReceiptRow.org_id == org_id)
                .order_by(ReceiptRow.created_at.desc(), ReceiptRow.id.desc())
            ).scalars()
        )
        return [row.id for row in ordered]


def _snapshot(client: TestClient, audit_dir: Path, org_id: str) -> dict[str, Any]:
    audit_file = audit_dir / f"{org_id}.audit.jsonl"
    audit_bytes = audit_file.read_bytes() if audit_file.exists() else b""
    with client.app.state.session_factory() as session:
        org = session.get(Organization, org_id)
        assert org is not None
        return {
            "receipts": session.scalar(
                select(func.count()).select_from(ReceiptRow).where(ReceiptRow.org_id == org_id)
            ),
            "exports": session.scalar(
                select(func.count())
                .select_from(ComplianceExport)
                .where(ComplianceExport.org_id == org_id)
            ),
            "policies": session.scalar(
                select(func.count()).select_from(PolicyBundle).where(PolicyBundle.org_id == org_id)
            ),
            "anchor_count": org.audit_anchor_count,
            "anchor_hash": org.audit_anchor_hash,
            "audit_bytes": len(audit_bytes),
            "audit_sha256": hashlib.sha256(audit_bytes).hexdigest(),
        }


def test_receipt_cursor_orders_tied_timestamps_once_and_preserves_offset(
    tmp_path: Path, audit_dir: Path
) -> None:
    client = _client(tmp_path, audit_dir)
    org_id, headers = _bootstrap(client)
    _seed_receipts(client, org_id, headers, count=5)
    expected = _pin_receipt_order(client, org_id)

    legacy = client.get(
        f"/orgs/{org_id}/receipts",
        params={"limit": 2, "offset": 2},
        headers=headers,
    )
    assert legacy.status_code == 200, legacy.text
    assert legacy.json()["offset"] == 2
    assert legacy.json()["next_cursor"] is None
    assert [item["receipt_id"] for item in legacy.json()["items"]] == expected[2:4]

    first = client.get(f"/orgs/{org_id}/receipts", params={"limit": 2}, headers=headers)
    assert first.status_code == 200, first.text
    assert first.headers["cache-control"] == "private, no-store"
    body = first.json()
    assert body["offset"] == 0
    assert body["next_cursor"]
    assert [item["receipt_id"] for item in body["items"]] == expected[:2]

    seen = body["items"]
    cursor = body["next_cursor"]
    while cursor:
        page = client.get(
            f"/orgs/{org_id}/receipts",
            params={"limit": 2, "cursor": cursor},
            headers=headers,
        )
        assert page.status_code == 200, page.text
        assert page.headers["cache-control"] == "private, no-store"
        page_body = page.json()
        seen.extend(page_body["items"])
        cursor = page_body["next_cursor"]

    assert [item["receipt_id"] for item in seen] == expected
    assert len({item["receipt_id"] for item in seen}) == len(expected)


def test_receipt_cursor_is_stable_when_newer_receipt_is_inserted_between_pages(
    tmp_path: Path, audit_dir: Path
) -> None:
    client = _client(tmp_path, audit_dir)
    org_id, headers = _bootstrap(client)
    _seed_receipts(client, org_id, headers, count=4)
    expected = _pin_receipt_order(client, org_id)
    first = client.get(f"/orgs/{org_id}/receipts", params={"limit": 2}, headers=headers).json()

    create_new = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "newer-after-first-page"},
        headers={**headers, BOOTSTRAP_IDEMPOTENCY_HEADER: "cursor-newer-0001"},
    )
    assert create_new.status_code == 201, create_new.text
    with client.app.state.session_factory() as session:
        row = session.get(ReceiptRow, create_new.json()["receipt_id"])
        assert row is not None
        row.created_at = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
        session.commit()

    second = client.get(
        f"/orgs/{org_id}/receipts",
        params={"limit": 20, "cursor": first["next_cursor"]},
        headers=headers,
    )
    assert second.status_code == 200, second.text
    assert [item["receipt_id"] for item in second.json()["items"]] == expected[2:]


def test_receipt_cursor_boundary_row_can_be_deleted_without_duplication(
    tmp_path: Path, audit_dir: Path
) -> None:
    client = _client(tmp_path, audit_dir)
    org_id, headers = _bootstrap(client)
    _seed_receipts(client, org_id, headers, count=4)
    expected = _pin_receipt_order(client, org_id)
    first = client.get(f"/orgs/{org_id}/receipts", params={"limit": 2}, headers=headers).json()
    boundary_id = first["items"][-1]["receipt_id"]

    with client.app.state.session_factory() as session:
        session.execute(delete(ReceiptRow).where(ReceiptRow.id == boundary_id))
        session.commit()

    second = client.get(
        f"/orgs/{org_id}/receipts",
        params={"limit": 20, "cursor": first["next_cursor"]},
        headers=headers,
    )
    assert second.status_code == 200, second.text
    assert [item["receipt_id"] for item in second.json()["items"]] == expected[2:]


@pytest.mark.parametrize(
    "cursor_value",
    [
        "not-base64",
        base64.urlsafe_b64encode(b"too-short").decode("ascii").rstrip("="),
        "A" * 4097,
    ],
)
def test_invalid_cursor_values_are_generic_redacted_and_side_effect_free(
    tmp_path: Path, audit_dir: Path, cursor_value: str
) -> None:
    client = _client(tmp_path, audit_dir)
    org_id, headers = _bootstrap(client)
    _seed_receipts(client, org_id, headers, count=2)
    before = _snapshot(client, audit_dir, org_id)

    resp = client.get(
        f"/orgs/{org_id}/receipts",
        params={"cursor": cursor_value, "tool": "SECRET-tool-filter"},
        headers=headers,
    )
    assert resp.status_code == 400, resp.text
    assert resp.headers["cache-control"] == "private, no-store"
    body = resp.json()
    assert body["code"] == "invalid_cursor"
    assert "SECRET-tool-filter" not in resp.text
    assert cursor_value not in resp.text
    assert _snapshot(client, audit_dir, org_id) == before


def test_cursor_rejects_tampered_expired_wrong_scope_wrong_filter_and_wrong_key(
    tmp_path: Path, audit_dir: Path
) -> None:
    client = _client(tmp_path, audit_dir)
    org_id, headers = _bootstrap(client)
    _seed_receipts(client, org_id, headers, count=3)
    first = client.get(f"/orgs/{org_id}/receipts", params={"limit": 1}, headers=headers).json()
    token = first["next_cursor"]
    before = _snapshot(client, audit_dir, org_id)

    tamper_index = len(token) // 2
    tampered = (
        token[:tamper_index]
        + ("A" if token[tamper_index] != "A" else "B")
        + token[tamper_index + 1 :]
    )
    digest = receipt_filter_digest(decision=None, tool=None, actor=None, since=None, until=None)
    expired = _manual_cursor(
        client,
        org_id,
        filter_digest=digest,
        now=datetime.now(UTC) - timedelta(hours=2),
        ttl_seconds=1,
    )
    wrong_scope = _manual_cursor(client, "other-org", filter_digest=digest)
    wrong_filter = token
    wrong_key = _manual_cursor(
        client,
        org_id,
        filter_digest=digest,
        key=OTHER_KEY_BYTES,
    )

    cases = [
        (tampered, {}),
        (expired, {}),
        (wrong_scope, {}),
        (wrong_filter, {"tool": "agent.register"}),
        (wrong_key, {}),
    ]
    for candidate, extra_params in cases:
        params = {"cursor": candidate, **extra_params}
        resp = client.get(f"/orgs/{org_id}/receipts", params=params, headers=headers)
        assert resp.status_code == 400, resp.text
        assert resp.json()["code"] == "invalid_cursor"
        assert "agent.register" not in resp.text
        assert _snapshot(client, audit_dir, org_id) == before


def _manual_cursor(
    client: TestClient,
    org_id: str,
    *,
    filter_digest: str,
    key: bytes = KEY_BYTES,
    now: datetime | None = None,
    ttl_seconds: int = 300,
    clock_skew_seconds: int = 30,
) -> str:
    with client.app.state.session_factory() as session:
        row = (
            session.execute(
                select(ReceiptRow).order_by(ReceiptRow.created_at.desc(), ReceiptRow.id.desc())
            )
            .scalars()
            .first()
        )
        assert row is not None
        return issue_receipt_cursor(
            keyring=_keyring(key, ttl_seconds=ttl_seconds, clock_skew_seconds=clock_skew_seconds),
            org_id=org_id,
            filter_digest=filter_digest,
            boundary_created_at=row.created_at,
            boundary_receipt_id=row.id,
            now=now,
        )


def _row_cursor_payload(
    client: TestClient,
    org_id: str,
    *,
    filter_digest: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    with client.app.state.session_factory() as session:
        row = (
            session.execute(
                select(ReceiptRow).order_by(ReceiptRow.created_at.desc(), ReceiptRow.id.desc())
            )
            .scalars()
            .first()
        )
        assert row is not None
        return {
            "boundary_created_at_us": int(
                row.created_at.replace(tzinfo=UTC).timestamp() * 1_000_000
            ),
            "boundary_receipt_id": row.id,
            "exp_us": int((now + timedelta(seconds=300)).timestamp() * 1_000_000),
            "filter_digest": filter_digest,
            "iat_us": int(now.timestamp() * 1_000_000),
            "kid": "test-key",
            "order": pagination.CURSOR_ORDER_RECEIPTS_DESC,
            "resource": pagination.CURSOR_RESOURCE_RECEIPTS,
            "scope_org_id": org_id,
            "v": pagination.CURSOR_VERSION,
        }


def _forge_valid_aead_cursor(
    org_id: str, payload: dict[str, Any], *, key: bytes = KEY_BYTES
) -> str:
    nonce = b"\x01" * 12
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, body, pagination._aad("test-key", org_id))
    return pagination._b64url(nonce + ciphertext)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.__setitem__("v", True),
        lambda p: p.__setitem__("boundary_created_at_us", True),
        lambda p: p.__setitem__("iat_us", True),
        lambda p: p.__setitem__("exp_us", True),
        lambda p: p.__setitem__("exp_us", p["iat_us"]),
        lambda p: p.__setitem__("exp_us", p["iat_us"] - 1),
        lambda p: p.__setitem__("kid", 123),
        lambda p: p.__setitem__("resource", ["receipts"]),
        lambda p: p.__setitem__("order", {"order": "bad"}),
        lambda p: p.__setitem__("scope_org_id", False),
        lambda p: p.__setitem__("filter_digest", 0),
        lambda p: p.__setitem__("boundary_receipt_id", ""),
    ],
)
def test_forged_valid_aead_cursor_payload_types_and_interval_are_rejected(
    tmp_path: Path, audit_dir: Path, mutate: Any
) -> None:
    client = _client(tmp_path, audit_dir)
    org_id, headers = _bootstrap(client)
    _seed_receipts(client, org_id, headers, count=2)
    digest = receipt_filter_digest(decision=None, tool=None, actor=None, since=None, until=None)
    payload = _row_cursor_payload(client, org_id, filter_digest=digest)
    mutate(payload)
    token = _forge_valid_aead_cursor(org_id, payload)
    before = _snapshot(client, audit_dir, org_id)

    resp = client.get(f"/orgs/{org_id}/receipts", params={"cursor": token}, headers=headers)
    assert resp.status_code == 400, resp.text
    assert resp.json()["code"] == "invalid_cursor"
    assert token not in resp.text
    assert _snapshot(client, audit_dir, org_id) == before


def test_cursor_issue_time_accepts_bounded_skew_but_expiry_remains_strict(
    tmp_path: Path, audit_dir: Path
) -> None:
    client = _client(tmp_path, audit_dir, clock_skew_seconds=30)
    org_id, headers = _bootstrap(client)
    _seed_receipts(client, org_id, headers, count=3)
    digest = receipt_filter_digest(decision=None, tool=None, actor=None, since=None, until=None)
    now = datetime.now(UTC)
    within_skew = _manual_cursor(
        client,
        org_id,
        filter_digest=digest,
        now=now + timedelta(seconds=29),
        clock_skew_seconds=30,
    )
    outside_skew = _manual_cursor(
        client,
        org_id,
        filter_digest=digest,
        now=now + timedelta(seconds=31),
        clock_skew_seconds=30,
    )
    expired_payload = _row_cursor_payload(client, org_id, filter_digest=digest, now=now)
    expired_payload["iat_us"] = int((now - timedelta(seconds=301)).timestamp() * 1_000_000)
    expired_payload["exp_us"] = int(now.timestamp() * 1_000_000)
    expired = _forge_valid_aead_cursor(org_id, expired_payload)

    accepted = client.get(
        f"/orgs/{org_id}/receipts", params={"cursor": within_skew}, headers=headers
    )
    assert accepted.status_code == 200, accepted.text
    for rejected in (outside_skew, expired):
        before = _snapshot(client, audit_dir, org_id)
        resp = client.get(f"/orgs/{org_id}/receipts", params={"cursor": rejected}, headers=headers)
        assert resp.status_code == 400, resp.text
        assert resp.json()["code"] == "invalid_cursor"
        assert _snapshot(client, audit_dir, org_id) == before


def test_cursor_offset_conflict_duplicate_and_auth_precedence(
    tmp_path: Path, audit_dir: Path
) -> None:
    client = _client(tmp_path, audit_dir)
    org_id, headers = _bootstrap(client)
    _seed_receipts(client, org_id, headers, count=2)
    token = client.get(f"/orgs/{org_id}/receipts", params={"limit": 1}, headers=headers).json()[
        "next_cursor"
    ]
    before = _snapshot(client, audit_dir, org_id)

    offset_conflict = client.get(
        f"/orgs/{org_id}/receipts",
        params={"cursor": token, "offset": 1},
        headers=headers,
    )
    assert offset_conflict.status_code == 400, offset_conflict.text
    duplicate = client.get(
        f"/orgs/{org_id}/receipts?cursor={token}&cursor={token}",
        headers=headers,
    )
    assert duplicate.status_code == 400, duplicate.text
    unauth = client.get(f"/orgs/{org_id}/receipts", params={"cursor": "bad"})
    assert unauth.status_code == 401, unauth.text
    assert unauth.json()["code"] == "unauthorized"
    assert _snapshot(client, audit_dir, org_id) == before


def test_cursor_rejects_duplicate_bound_query_params_after_auth_without_side_effects(
    tmp_path: Path, audit_dir: Path
) -> None:
    client = _client(tmp_path, audit_dir)
    org_id, headers = _bootstrap(client)
    _seed_receipts(client, org_id, headers, count=3)
    token = client.get(f"/orgs/{org_id}/receipts", params={"limit": 1}, headers=headers).json()[
        "next_cursor"
    ]
    before = _snapshot(client, audit_dir, org_id)

    duplicate_cursor_params = (
        f"cursor={token}&decision=allow&decision=deny&tool=a&tool=b&actor=a&actor=b"
        "&since=2026-01-01T00:00:00Z&since=2026-01-02T00:00:00Z"
        "&until=2026-01-03T00:00:00Z&until=2026-01-04T00:00:00Z"
        "&limit=1&limit=2&offset=0&offset=0"
    )
    resp = client.get(f"/orgs/{org_id}/receipts?{duplicate_cursor_params}", headers=headers)
    assert resp.status_code == 400, resp.text
    assert resp.json()["code"] == "invalid_cursor"
    assert token not in resp.text
    assert _snapshot(client, audit_dir, org_id) == before

    duplicate_first_page_filter = client.get(
        f"/orgs/{org_id}/receipts?tool=a&tool=b&limit=1",
        headers=headers,
    )
    assert duplicate_first_page_filter.status_code == 400, duplicate_first_page_filter.text
    assert duplicate_first_page_filter.json()["code"] == "invalid_cursor"
    assert _snapshot(client, audit_dir, org_id) == before

    legacy_offset_duplicate_filter = client.get(
        f"/orgs/{org_id}/receipts?tool=a&tool=b&offset=1",
        headers=headers,
    )
    assert legacy_offset_duplicate_filter.status_code == 200, legacy_offset_duplicate_filter.text
    assert legacy_offset_duplicate_filter.json()["offset"] == 1
    assert legacy_offset_duplicate_filter.json()["next_cursor"] is None
    assert _snapshot(client, audit_dir, org_id) == before


@pytest.mark.parametrize(
    "query",
    [
        "offset=1&offset=0&limit=1",
        "offset=0&offset=1&limit=1",
        "offset=0&offset=0&limit=1",
        "offset=00&offset=1&limit=1",
        "offset=%2B0&offset=1&limit=1",
        "offset=-0&offset=1&limit=1",
        "offset=1&offset=2&limit=1",
    ],
)
def test_cursor_first_page_rejects_duplicate_offset_ambiguity_without_side_effects(
    tmp_path: Path, audit_dir: Path, query: str
) -> None:
    client = _client(tmp_path, audit_dir)
    org_id, headers = _bootstrap(client)
    _seed_receipts(client, org_id, headers, count=3)
    before = _snapshot(client, audit_dir, org_id)

    resp = client.get(f"/orgs/{org_id}/receipts?{query}", headers=headers)
    assert resp.status_code == 400, resp.text
    assert resp.json()["code"] == "invalid_cursor"
    assert _snapshot(client, audit_dir, org_id) == before


def test_cursor_cross_instance_requires_same_configured_key(
    tmp_path: Path, audit_dir: Path
) -> None:
    database_name = "shared.sqlite3"
    settings_one = _settings(tmp_path, audit_dir, database_name=database_name)
    client_one = TestClient(create_app(settings_one), raise_server_exceptions=False)
    org_id, headers = _bootstrap(client_one)
    _seed_receipts(client_one, org_id, headers, count=3)
    page = client_one.get(f"/orgs/{org_id}/receipts", params={"limit": 1}, headers=headers).json()

    same_key = TestClient(
        create_app(_settings(tmp_path, audit_dir, database_name=database_name)),
        raise_server_exceptions=False,
    )
    same_response = same_key.get(
        f"/orgs/{org_id}/receipts",
        params={"cursor": page["next_cursor"], "limit": 1},
        headers=headers,
    )
    assert same_response.status_code == 200, same_response.text

    different_key = TestClient(
        create_app(
            _settings(tmp_path, audit_dir, key=OTHER_KEY_BYTES, database_name=database_name)
        ),
        raise_server_exceptions=False,
    )
    different_response = different_key.get(
        f"/orgs/{org_id}/receipts",
        params={"cursor": page["next_cursor"], "limit": 1},
        headers=headers,
    )
    assert different_response.status_code == 400, different_response.text
    assert different_response.json()["code"] == "invalid_cursor"


def test_cursor_env_config_requires_paired_bounded_base64_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACP_CURSOR_KEY_ID", "kid")
    monkeypatch.delenv("ACP_CURSOR_KEY", raising=False)
    with pytest.raises(CursorConfigurationError) as missing:
        Settings.from_env()
    assert "kid" not in str(missing.value)

    monkeypatch.setenv("ACP_CURSOR_KEY", "not-base64-secret-value")
    with pytest.raises(CursorConfigurationError) as invalid:
        Settings.from_env()
    assert "not-base64-secret-value" not in str(invalid.value)

    monkeypatch.setenv("ACP_CURSOR_KEY", base64.b64encode(KEY_BYTES).decode("ascii"))
    monkeypatch.setenv("ACP_CURSOR_TTL_SECONDS", "0")
    with pytest.raises(CursorConfigurationError):
        Settings.from_env()

    monkeypatch.setenv("ACP_CURSOR_TTL_SECONDS", "300")
    settings = Settings.from_env()
    assert settings.cursor_keyring is not None
    assert settings.cursor_keyring.active_key_id == "kid"
    assert settings.cursor_keyring.ephemeral is False


def test_cursor_keyring_and_settings_repr_redact_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    encoded_key = base64.b64encode(KEY_BYTES).decode("ascii")
    monkeypatch.setenv("ACP_CURSOR_KEY_ID", "kid")
    monkeypatch.setenv("ACP_CURSOR_KEY", encoded_key)
    monkeypatch.setenv("ACP_BOOTSTRAP_TOKEN", BOOTSTRAP_TOKEN)

    settings = Settings.from_env()
    keyring = _keyring()
    settings_repr = repr(settings)
    keyring_repr = repr(keyring)

    assert encoded_key not in settings_repr
    assert repr(KEY_BYTES) not in settings_repr
    assert BOOTSTRAP_TOKEN not in settings_repr
    assert encoded_key not in keyring_repr
    assert repr(KEY_BYTES) not in keyring_repr
    assert "bootstrap_token" not in settings_repr
    assert "cursor_keyring" not in settings_repr
    assert "active_key=" not in keyring_repr
