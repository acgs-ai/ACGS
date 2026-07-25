from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError

from acgs_control_plane.db import make_engine
from acgs_control_plane.migrations import upgrade_database
from acgs_control_plane.models import Base, User


def _database_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'control-plane.sqlite3'}"


def test_user_org_id_id_constraint_is_in_metadata_and_create_all(tmp_path: Path) -> None:
    assert {
        constraint.name
        for constraint in User.__table__.constraints
        if isinstance(constraint, sa.UniqueConstraint)
    } >= {"uq_users_org_id_id", "uq_users_org_email"}

    engine = make_engine(_database_url(tmp_path))
    try:
        Base.metadata.create_all(engine)
        unique_constraints = {
            constraint["name"] for constraint in sa.inspect(engine).get_unique_constraints("users")
        }
        assert "uq_users_org_id_id" in unique_constraints
    finally:
        engine.dispose()


def test_sqlite_rejects_cross_scope_tenant_bootstrap_rows(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)
    upgrade_database(database_url)
    engine = make_engine(database_url)
    try:
        _seed_scope_constraint_rows(engine)

        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    sa.text(
                        """
                        INSERT INTO organization_memberships (
                            id, org_id, user_id, role, created_at
                        ) VALUES (
                            'membership-cross-org', 'org-b', 'user-a', 'owner', :now
                        )
                        """
                    ),
                    {"now": "2026-07-25T00:00:00+00:00"},
                )

        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    sa.text(
                        """
                        INSERT INTO tenant_bootstrap_idempotency (
                            id, idempotency_key, actor, request_hash,
                            org_id, project_id, environment_id, response, created_at
                        ) VALUES (
                            'idem-wrong-env', 'idem-wrong-env-key', 'actor', :hash,
                            'org-a', 'project-a', 'env-missing', '{}', :now
                        )
                        """
                    ),
                    {"hash": "a" * 64, "now": "2026-07-25T00:00:00+00:00"},
                )

        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    sa.text(
                        """
                        INSERT INTO tenant_bootstrap_policy_artifacts (
                            id, invitation_id, org_id, project_id, environment_id,
                            decision, receipt_hash, audit_event_hash,
                            sealed_receipt, event, created_at
                        ) VALUES (
                            'artifact-wrong-scope', 'invite-a', 'org-b', 'project-a', 'env-a',
                            'escalate', :receipt_hash, :audit_hash,
                            '{}', '{}', :now
                        )
                        """
                    ),
                    {
                        "receipt_hash": "b" * 64,
                        "audit_hash": "c" * 64,
                        "now": "2026-07-25T00:00:00+00:00",
                    },
                )

        for statement in (
            """
            INSERT INTO pending_approvals (
                id, org_id, project_id, environment_id, actor, action,
                invitation_id, policy_artifact_id, receipt_hash, audit_event_hash,
                lineage, status, created_at
            ) VALUES (
                'approval-wrong-scope', 'org-b', 'project-a', 'env-a', 'actor', 'tenant.bootstrap',
                'invite-a', 'artifact-a', :receipt_hash, :audit_hash,
                '{}', 'pending', :now
            )
            """,
            """
            INSERT INTO tenant_bootstrap_pending_outbox (
                id, org_id, project_id, environment_id, invitation_id, policy_artifact_id,
                delivery_key, payload_digest, payload, status, attempts,
                created_at, available_at, delivered_at
            ) VALUES (
                'outbox-wrong-scope', 'org-b', 'project-a', 'env-a', 'invite-a', 'artifact-a',
                'delivery-wrong-scope', :payload_digest, '{}', 'pending', 0,
                :now, :now, NULL
            )
            """,
        ):
            with pytest.raises(IntegrityError):
                with engine.begin() as connection:
                    connection.execute(
                        sa.text(statement),
                        {
                            "receipt_hash": "d" * 64,
                            "audit_hash": "e" * 64,
                            "payload_digest": "f" * 64,
                            "now": "2026-07-25T00:00:00+00:00",
                        },
                    )
    finally:
        engine.dispose()


def _seed_scope_constraint_rows(engine: sa.Engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            sa.text(
                """
                INSERT INTO organizations (
                    id, name, created_at, audit_anchor_count, audit_anchor_hash
                )
                VALUES
                    ('org-a', 'Org A', :now, 0, ''),
                    ('org-b', 'Org B', :now, 0, '')
                """
            ),
            {"now": "2026-07-25T00:00:00+00:00"},
        )
        connection.execute(
            sa.text(
                """
                INSERT INTO projects (id, org_id, slug, name, created_at)
                VALUES ('project-a', 'org-a', 'default', 'Default', :now)
                """
            ),
            {"now": "2026-07-25T00:00:00+00:00"},
        )
        connection.execute(
            sa.text(
                """
                INSERT INTO environments (id, org_id, project_id, slug, name, created_at)
                VALUES ('env-a', 'org-a', 'project-a', 'production', 'Production', :now)
                """
            ),
            {"now": "2026-07-25T00:00:00+00:00"},
        )
        connection.execute(
            sa.text(
                """
                INSERT INTO users (id, org_id, name, email, role, api_key_hash, active, created_at)
                VALUES (
                    'user-a', 'org-a', 'User A', 'user-a@example.com',
                    'org_admin', NULL, 1, :now
                )
                """
            ),
            {"now": "2026-07-25T00:00:00+00:00"},
        )
        connection.execute(
            sa.text(
                """
                INSERT INTO platform_bootstrap_invitations (
                    id, token_hash, invitee_actor, invitee_role,
                    prospective_org_id, prospective_project_id, prospective_environment_id,
                    prospective_membership_id, policy_outcome,
                    revoked_at, consumed_at, consumed_org_id, created_at, expires_at
                ) VALUES (
                    'invite-a', :token_hash, 'actor', 'tenant-bootstrap-invitee',
                    'org-a', 'project-a', 'env-a',
                    'membership-a', 'escalate',
                    NULL, NULL, NULL, :now, :expires
                )
                """
            ),
            {
                "token_hash": "1" * 64,
                "now": "2026-07-25T00:00:00+00:00",
                "expires": "2026-07-25T01:00:00+00:00",
            },
        )
        connection.execute(
            sa.text(
                """
                INSERT INTO tenant_bootstrap_policy_artifacts (
                    id, invitation_id, org_id, project_id, environment_id,
                    decision, receipt_hash, audit_event_hash,
                    sealed_receipt, event, created_at
                ) VALUES (
                    'artifact-a', 'invite-a', 'org-a', 'project-a', 'env-a',
                    'escalate', :receipt_hash, :audit_hash,
                    '{}', '{}', :now
                )
                """
            ),
            {
                "receipt_hash": "2" * 64,
                "audit_hash": "3" * 64,
                "now": "2026-07-25T00:00:00+00:00",
            },
        )
