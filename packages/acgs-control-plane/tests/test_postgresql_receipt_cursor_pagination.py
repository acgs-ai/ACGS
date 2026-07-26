"""Opt-in PostgreSQL proof for receipt cursor pagination boundaries.

``tests/test_receipt_cursor_pagination.py`` runs the same router on SQLite and
pins every receipt to a whole-second timestamp, so it cannot observe the two
places where the production engine can disagree with it:

* ``created_at`` is ``DateTime(timezone=True)``, which is ``timestamptz`` on
  PostgreSQL and text on SQLite.  The cursor carries the boundary as integer
  microseconds, so only a real ``timestamptz`` round-trip proves the boundary
  survives with microsecond fidelity.
* ``receipts.id`` is ``String(64)``.  SQLite compares text with the BINARY
  collation while PostgreSQL uses the database collation, so the keyset
  tiebreak ``id < :boundary_id`` and its ``ORDER BY id DESC`` are only proven
  consistent by executing both on PostgreSQL.

These tests therefore derive the expected order from the database itself rather
than from Python ordering: the invariant under proof is that the pages cover the
server's own ordering exactly once, not that the server matches Python's.

Like every other PostgreSQL suite here, this one requires
``ACP_TEST_POSTGRES_URL``, an explicit ``ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE=1``
acknowledgement, and the exact dedicated disposable database
``acgs_control_plane_test`` before it resets that database's ``public`` schema.
It never infers or uses an application/runtime database URL.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from gove_zone.decision import sha256_json
from gove_zone.policy import RuleSetPolicy
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, ReceiptTrustScope
from sqlalchemy import select
from sqlalchemy.engine import Connection

from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.db import make_engine
from acgs_control_plane.migrations import upgrade_database
from acgs_control_plane.models import (
    Environment,
    EnvironmentPolicyHead,
    ManagedDecisionReceipt,
    PolicyVersion,
    Project,
    ReceiptRow,
    new_id,
    utcnow,
)
from acgs_control_plane.pagination import (
    CursorKeyring,
    decode_receipt_cursor,
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

BOOTSTRAP_TOKEN = "pg-cursor-bootstrap-token"
KEY_BYTES = bytes(range(32))

_TEST_POSTGRES_URL = os.environ.get("ACP_TEST_POSTGRES_URL")
_TEST_URL = sa.engine.make_url(_TEST_POSTGRES_URL) if _TEST_POSTGRES_URL else None
_DISPOSABLE_DATABASE_NAME = "acgs_control_plane_test"


def _assert_disposable_database(connection: Connection) -> None:
    database_name = connection.scalar(sa.text("SELECT current_database()"))
    if database_name != _DISPOSABLE_DATABASE_NAME:
        raise RuntimeError(
            "Refusing to reset PostgreSQL public schema outside the exact dedicated test database."
        )


def _reset_public_schema() -> None:
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.begin() as connection:
            _assert_disposable_database(connection)
            connection.execute(sa.text("DROP SCHEMA public CASCADE"))
            connection.execute(sa.text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


@pytest.fixture(autouse=True)
def _isolated_postgresql_schema() -> Iterator[None]:
    """Reset only the explicitly named disposable database before and after a test."""
    if not _TEST_POSTGRES_URL:
        pytest.skip("set ACP_TEST_POSTGRES_URL to run disposable PostgreSQL cursor tests")
    if os.environ.get("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE") != "1":
        raise RuntimeError(
            "Set ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE=1 to acknowledge that this test "
            "will reset the exact disposable PostgreSQL public schema."
        )
    pytest.importorskip("psycopg")
    assert _TEST_URL is not None
    if _TEST_URL.get_backend_name() != "postgresql":
        raise RuntimeError("ACP_TEST_POSTGRES_URL must use a PostgreSQL URL.")
    if _TEST_URL.database != _DISPOSABLE_DATABASE_NAME:
        raise RuntimeError(
            "ACP_TEST_POSTGRES_URL must name exactly the dedicated disposable database "
            f"{_DISPOSABLE_DATABASE_NAME!r} before this test may reset its public schema."
        )
    _reset_public_schema()
    try:
        yield
    finally:
        _reset_public_schema()


def _keyring() -> CursorKeyring:
    return CursorKeyring(active_key_id="pg-test-key", active_key=KEY_BYTES)


def _client(tmp_path: Path) -> TestClient:
    """Bring the disposable database to head the way an operator would, then serve it."""
    upgrade_database(_TEST_POSTGRES_URL)
    settings = Settings(
        database_url=_TEST_POSTGRES_URL,
        audit_dir=tmp_path / "audit",
        bootstrap_token=BOOTSTRAP_TOKEN,
        create_tables=False,
        runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        cursor_keyring=_keyring(),
    )
    return TestClient(create_app(settings), raise_server_exceptions=False)


def _bootstrap(client: TestClient, *, name: str, email: str) -> tuple[str, dict[str, str]]:
    resp = client.post(
        "/orgs",
        json={"name": name, "admin_name": "Root Admin", "admin_email": email},
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

    Mirrors the SQLite twin in ``test_receipt_cursor_pagination.py``: agent
    registration is a canonical managed mutation, so it needs the org's
    default project/environment scope, a trusted key for that scope, and an
    active policy bundle. These tests use agent creation only to produce
    receipts to paginate.
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
    session: sa.orm.Session,
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


def _seed_receipts(client: TestClient, org_id: str, headers: dict[str, str], *, count: int) -> None:
    for i in range(count):
        resp = client.post(
            f"/orgs/{org_id}/agents",
            json={"name": f"pg-cursor-bot-{i}"},
            headers={**headers, BOOTSTRAP_IDEMPOTENCY_HEADER: f"pg-cursor-seed-{i:04d}"},
        )
        assert resp.status_code == 201, resp.text


def _server_order(client: TestClient, org_id: str) -> list[str]:
    """The server's own ordering, under PostgreSQL's collation -- not Python's."""
    with client.app.state.session_factory() as session:
        return [
            row.id
            for row in session.execute(
                select(ReceiptRow)
                .where(ReceiptRow.org_id == org_id)
                .order_by(ReceiptRow.created_at.desc(), ReceiptRow.id.desc())
            ).scalars()
        ]


def _tie_timestamps_with_microseconds(client: TestClient, org_id: str) -> None:
    """Force ties on ``created_at`` while keeping a non-zero microsecond component.

    Pairs of receipts share an identical ``timestamptz`` so every page boundary
    has to fall back to the ``id`` tiebreak, and the microseconds are non-zero so
    the integer-microsecond cursor cannot pass by truncating them away.
    """
    base = datetime(2026, 7, 24, 12, 0, 0, 456_789, tzinfo=UTC)
    with client.app.state.session_factory() as session:
        rows = list(
            session.execute(
                select(ReceiptRow).where(ReceiptRow.org_id == org_id).order_by(ReceiptRow.id.asc())
            ).scalars()
        )
        for index, row in enumerate(rows):
            # Integer-divide so consecutive rows share one timestamp exactly; the
            # non-zero microseconds come from ``base`` and are never perturbed
            # here, or the pairs would stop being ties.
            row.created_at = base + timedelta(seconds=index // 2)
        session.commit()


def _drain_pages(
    client: TestClient, org_id: str, headers: dict[str, str], *, limit: int
) -> list[str]:
    """Walk every cursor page, refusing to loop forever on a non-advancing cursor."""
    resp = client.get(f"/orgs/{org_id}/receipts", params={"limit": limit}, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    collected = [item["receipt_id"] for item in body["items"]]
    cursor = body["next_cursor"]
    total = body["total"]
    pages = 1
    while cursor:
        pages += 1
        assert pages <= total + 2, "cursor pagination failed to terminate"
        resp = client.get(
            f"/orgs/{org_id}/receipts",
            params={"limit": limit, "cursor": cursor},
            headers=headers,
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        collected.extend(item["receipt_id"] for item in body["items"])
        cursor = body["next_cursor"]
    return collected


def test_postgresql_cursor_pages_cover_the_server_ordering_exactly_once(tmp_path: Path) -> None:
    client = _client(tmp_path)
    org_id, headers = _bootstrap(client, name="PG Cursor Org", email="pg.cursor@example.com")
    _seed_receipts(client, org_id, headers, count=9)
    _tie_timestamps_with_microseconds(client, org_id)

    expected = _server_order(client, org_id)
    # Nine agent registrations, the receipt the org bootstrap itself emits,
    # and the publish/activate pair from seeding the required policy bundle.
    assert len(expected) == 12

    for limit in (1, 2, 4):
        collected = _drain_pages(client, org_id, headers, limit=limit)
        assert collected == expected, f"page order diverged at limit={limit}"
        assert len(collected) == len(set(collected)), f"duplicate receipt at limit={limit}"
        assert set(collected) == set(expected), f"missing receipt at limit={limit}"


def test_postgresql_cursor_boundary_survives_the_timestamptz_round_trip(tmp_path: Path) -> None:
    client = _client(tmp_path)
    org_id, headers = _bootstrap(client, name="PG Boundary Org", email="pg.boundary@example.com")
    # No timestamp pinning: keep whatever microsecond-precision values the
    # application wrote through psycopg, which is what production stores.
    _seed_receipts(client, org_id, headers, count=4)

    expected = _server_order(client, org_id)
    resp = client.get(f"/orgs/{org_id}/receipts", params={"limit": 2}, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["next_cursor"]

    with client.app.state.session_factory() as session:
        boundary_row = session.get(ReceiptRow, expected[1])
        assert boundary_row is not None
        stored_created_at = boundary_row.created_at

    decoded = decode_receipt_cursor(
        token=body["next_cursor"],
        keyring=_keyring(),
        org_id=org_id,
        filter_digest=receipt_filter_digest(
            decision=None, tool=None, actor=None, since=None, until=None
        ),
    )
    assert decoded.receipt_id == expected[1]
    # Microsecond-exact, not merely close: a truncated boundary would re-emit or
    # skip the row it points at.
    assert decoded.created_at == stored_created_at.replace(tzinfo=UTC)
    assert decoded.created_at.microsecond == stored_created_at.microsecond

    # The boundary the cursor carries must select the remaining rows exactly.
    resp = client.get(
        f"/orgs/{org_id}/receipts",
        params={"limit": 2, "cursor": body["next_cursor"]},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert [item["receipt_id"] for item in resp.json()["items"]] == expected[2:4]


def test_postgresql_cursor_from_another_org_is_refused_without_detail(tmp_path: Path) -> None:
    client = _client(tmp_path)
    org_a, headers_a = _bootstrap(client, name="PG Org A", email="pg.org.a@example.com")
    org_b, headers_b = _bootstrap(client, name="PG Org B", email="pg.org.b@example.com")
    _seed_receipts(client, org_a, headers_a, count=4)
    _seed_receipts(client, org_b, headers_b, count=4)

    resp = client.get(f"/orgs/{org_a}/receipts", params={"limit": 2}, headers=headers_a)
    assert resp.status_code == 200, resp.text
    foreign_cursor = resp.json()["next_cursor"]
    assert foreign_cursor

    # Positive control: org B's own cursor works, so the refusal below is
    # attributable to the cursor being foreign rather than to paging being
    # broken for org B generally.
    own = client.get(f"/orgs/{org_b}/receipts", params={"limit": 2}, headers=headers_b)
    assert own.status_code == 200, own.text
    own_cursor = own.json()["next_cursor"]
    assert own_cursor
    resumed = client.get(
        f"/orgs/{org_b}/receipts",
        params={"limit": 2, "cursor": own_cursor},
        headers=headers_b,
    )
    assert resumed.status_code == 200, resumed.text

    refused = client.get(
        f"/orgs/{org_b}/receipts",
        params={"limit": 2, "cursor": foreign_cursor},
        headers=headers_b,
    )
    assert refused.status_code == 400, refused.text
    body = refused.json()
    assert body["code"] == "invalid_cursor"
    assert body["status"] == "error"
    # The refusal must not disclose which check failed, nor leak the other
    # tenant's identifiers back to this caller.
    serialized = refused.text
    assert org_a not in serialized
    assert "scope" not in serialized
    assert "expired" not in serialized
    assert "decrypt" not in serialized
