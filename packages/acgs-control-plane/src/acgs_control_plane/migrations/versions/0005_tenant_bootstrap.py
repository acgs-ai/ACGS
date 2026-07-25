"""Add canonical tenant bootstrap state.

Revision ``0005`` adds the server-owned invitation, idempotency, owner
membership, and non-executable policy-artifact tables needed for the
``POST /v1/tenant-bootstrap`` vertical. It is additive and forward-only.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


_MANAGED_LEDGER_DEFERRABLE_FKS = (
    (
        "managed_decision_receipts",
        "managed_decision_receipts_org_id_fkey",
        ["org_id"],
        "organizations",
        ["id"],
    ),
    (
        "managed_decision_receipts",
        "fk_managed_receipts_scope_environment",
        ["org_id", "project_id", "environment_id"],
        "environments",
        ["org_id", "project_id", "id"],
    ),
    (
        "managed_mutation_attempts",
        "managed_mutation_attempts_org_id_fkey",
        ["org_id"],
        "organizations",
        ["id"],
    ),
    (
        "managed_mutation_attempts",
        "fk_managed_attempts_scope_environment",
        ["org_id", "project_id", "environment_id"],
        "environments",
        ["org_id", "project_id", "id"],
    ),
    (
        "managed_receipt_consumptions",
        "managed_receipt_consumptions_org_id_fkey",
        ["org_id"],
        "organizations",
        ["id"],
    ),
    (
        "managed_receipt_consumptions",
        "fk_managed_consumptions_scope_environment",
        ["org_id", "project_id", "environment_id"],
        "environments",
        ["org_id", "project_id", "id"],
    ),
    (
        "managed_receipt_consumptions",
        "fk_managed_consumptions_scope_receipt",
        ["org_id", "project_id", "environment_id", "managed_receipt_id"],
        "managed_decision_receipts",
        ["org_id", "project_id", "environment_id", "id"],
    ),
    (
        "managed_governance_event_heads",
        "managed_governance_event_heads_org_id_fkey",
        ["org_id"],
        "organizations",
        ["id"],
    ),
    (
        "managed_governance_event_heads",
        "fk_managed_event_heads_scope_environment",
        ["org_id", "project_id", "environment_id"],
        "environments",
        ["org_id", "project_id", "id"],
    ),
    (
        "managed_governance_events",
        "managed_governance_events_org_id_fkey",
        ["org_id"],
        "organizations",
        ["id"],
    ),
    (
        "managed_governance_events",
        "fk_managed_events_scope_environment",
        ["org_id", "project_id", "environment_id"],
        "environments",
        ["org_id", "project_id", "id"],
    ),
    (
        "managed_governance_events",
        "fk_managed_events_scope_receipt",
        ["org_id", "project_id", "environment_id", "managed_receipt_id"],
        "managed_decision_receipts",
        ["org_id", "project_id", "environment_id", "id"],
    ),
    (
        "managed_outbox",
        "managed_outbox_org_id_fkey",
        ["org_id"],
        "organizations",
        ["id"],
    ),
    (
        "managed_outbox",
        "fk_managed_outbox_scope_environment",
        ["org_id", "project_id", "environment_id"],
        "environments",
        ["org_id", "project_id", "id"],
    ),
    (
        "managed_outbox",
        "fk_managed_outbox_scope_receipt",
        ["org_id", "project_id", "environment_id", "managed_receipt_id"],
        "managed_decision_receipts",
        ["org_id", "project_id", "environment_id", "id"],
    ),
    (
        "managed_outbox",
        "fk_managed_outbox_scope_event",
        ["org_id", "project_id", "environment_id", "managed_event_id"],
        "managed_governance_events",
        ["org_id", "project_id", "environment_id", "id"],
    ),
)


def _unique_or_index_exists(table_name: str, name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(
        constraint.get("name") == name
        for constraint in inspector.get_unique_constraints(table_name)
    ) or any(index.get("name") == name for index in inspector.get_indexes(table_name))


def _alter_managed_ledger_constraints_deferrable() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    for (
        table,
        constraint,
        columns,
        referred_table,
        referred_columns,
    ) in _MANAGED_LEDGER_DEFERRABLE_FKS:
        quoted_columns = ", ".join(columns)
        quoted_referred_columns = ", ".join(referred_columns)
        op.execute(
            sa.text(
                f"""
                ALTER TABLE {table}
                DROP CONSTRAINT {constraint},
                ADD CONSTRAINT {constraint}
                FOREIGN KEY ({quoted_columns})
                REFERENCES {referred_table} ({quoted_referred_columns})
                DEFERRABLE INITIALLY DEFERRED
                """
            )
        )


def upgrade() -> None:
    _alter_managed_ledger_constraints_deferrable()

    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column(
            "api_key_hash",
            existing_type=sa.String(length=64),
            nullable=True,
            existing_nullable=False,
        )
        if not _unique_or_index_exists("users", "uq_users_org_id_id"):
            batch_op.create_unique_constraint("uq_users_org_id_id", ["org_id", "id"])

    op.create_table(
        "organization_memberships",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(
            ["org_id", "user_id"],
            ["users.org_id", "users.id"],
            name="fk_org_memberships_org_user",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "user_id", name="uq_org_memberships_org_user"),
        sa.CheckConstraint("role IN ('owner')", name="ck_org_memberships_role"),
    )
    op.create_index("ix_organization_memberships_org_id", "organization_memberships", ["org_id"])
    op.create_index("ix_organization_memberships_user_id", "organization_memberships", ["user_id"])

    op.create_table(
        "platform_bootstrap_invitations",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("invitee_actor", sa.String(length=200), nullable=False),
        sa.Column("invitee_role", sa.String(length=64), nullable=False),
        sa.Column("prospective_org_id", sa.String(length=64), nullable=False),
        sa.Column("prospective_project_id", sa.String(length=64), nullable=False),
        sa.Column("prospective_environment_id", sa.String(length=64), nullable=False),
        sa.Column("prospective_membership_id", sa.String(length=64), nullable=False),
        sa.Column("policy_outcome", sa.String(length=16), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_org_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash", name="uq_platform_bootstrap_invitation_token_hash"),
        sa.UniqueConstraint(
            "prospective_org_id",
            "prospective_project_id",
            "prospective_environment_id",
            name="uq_platform_bootstrap_invitation_scope",
        ),
        sa.UniqueConstraint(
            "id",
            "prospective_org_id",
            "prospective_project_id",
            "prospective_environment_id",
            name="uq_platform_bootstrap_invitation_id_scope",
        ),
        sa.CheckConstraint(
            "policy_outcome IN ('allow', 'deny', 'escalate')",
            name="ck_platform_bootstrap_invitation_policy_outcome",
        ),
    )
    op.create_index(
        "ix_platform_bootstrap_invitations_invitee_actor",
        "platform_bootstrap_invitations",
        ["invitee_actor"],
    )

    op.create_table(
        "tenant_bootstrap_idempotency",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key", sa.String(length=200), nullable=False),
        sa.Column("actor", sa.String(length=200), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column(
            "response",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_tenant_bootstrap_idempotency_environment",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key", name="uq_tenant_bootstrap_idempotency_key"),
        sa.UniqueConstraint("org_id", name="uq_tenant_bootstrap_idempotency_org"),
    )

    op.create_table(
        "tenant_bootstrap_policy_artifacts",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("invitation_id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("receipt_hash", sa.String(length=64), nullable=False),
        sa.Column("audit_event_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "sealed_receipt",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "event",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["invitation_id"], ["platform_bootstrap_invitations.id"]),
        sa.ForeignKeyConstraint(
            ["invitation_id", "org_id", "project_id", "environment_id"],
            [
                "platform_bootstrap_invitations.id",
                "platform_bootstrap_invitations.prospective_org_id",
                "platform_bootstrap_invitations.prospective_project_id",
                "platform_bootstrap_invitations.prospective_environment_id",
            ],
            name="fk_tenant_bootstrap_policy_invitation_scope",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("invitation_id", "id", name="uq_tenant_bootstrap_policy_invitation_id"),
        sa.UniqueConstraint(
            "invitation_id",
            "id",
            "org_id",
            "project_id",
            "environment_id",
            name="uq_tenant_bootstrap_policy_invitation_id_scope",
        ),
        sa.UniqueConstraint("invitation_id", name="uq_tenant_bootstrap_policy_invitation"),
        sa.UniqueConstraint("receipt_hash", name="uq_tenant_bootstrap_policy_receipt_hash"),
        sa.UniqueConstraint("audit_event_hash", name="uq_tenant_bootstrap_policy_audit_hash"),
        sa.CheckConstraint(
            "decision IN ('deny', 'escalate')",
            name="ck_tenant_bootstrap_policy_decision",
        ),
    )
    op.create_index(
        "ix_tenant_bootstrap_policy_artifacts_invitation_id",
        "tenant_bootstrap_policy_artifacts",
        ["invitation_id"],
    )

    op.create_table(
        "pending_approvals",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("actor", sa.String(length=200), nullable=False),
        sa.Column("action", sa.String(length=200), nullable=False),
        sa.Column("invitation_id", sa.String(length=64), nullable=False),
        sa.Column("policy_artifact_id", sa.String(length=64), nullable=False),
        sa.Column("receipt_hash", sa.String(length=64), nullable=False),
        sa.Column("audit_event_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "lineage",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["invitation_id"], ["platform_bootstrap_invitations.id"]),
        sa.ForeignKeyConstraint(
            ["invitation_id", "policy_artifact_id", "org_id", "project_id", "environment_id"],
            [
                "tenant_bootstrap_policy_artifacts.invitation_id",
                "tenant_bootstrap_policy_artifacts.id",
                "tenant_bootstrap_policy_artifacts.org_id",
                "tenant_bootstrap_policy_artifacts.project_id",
                "tenant_bootstrap_policy_artifacts.environment_id",
            ],
            name="fk_pending_approvals_policy_artifact_scope",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("receipt_hash", name="uq_pending_approvals_receipt_hash"),
        sa.UniqueConstraint("audit_event_hash", name="uq_pending_approvals_audit_hash"),
        sa.CheckConstraint("status IN ('pending')", name="ck_pending_approvals_status"),
    )
    op.create_index("ix_pending_approvals_org_id", "pending_approvals", ["org_id"])
    op.create_index(
        "ix_pending_approvals_invitation_id",
        "pending_approvals",
        ["invitation_id"],
    )
    op.create_index(
        "ix_pending_approvals_policy_artifact_id",
        "pending_approvals",
        ["policy_artifact_id"],
    )

    op.create_table(
        "tenant_bootstrap_pending_outbox",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("invitation_id", sa.String(length=64), nullable=False),
        sa.Column("policy_artifact_id", sa.String(length=64), nullable=False),
        sa.Column("delivery_key", sa.String(length=200), nullable=False),
        sa.Column("payload_digest", sa.String(length=64), nullable=False),
        sa.Column(
            "payload",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["invitation_id"], ["platform_bootstrap_invitations.id"]),
        sa.ForeignKeyConstraint(
            ["invitation_id", "policy_artifact_id", "org_id", "project_id", "environment_id"],
            [
                "tenant_bootstrap_policy_artifacts.invitation_id",
                "tenant_bootstrap_policy_artifacts.id",
                "tenant_bootstrap_policy_artifacts.org_id",
                "tenant_bootstrap_policy_artifacts.project_id",
                "tenant_bootstrap_policy_artifacts.environment_id",
            ],
            name="fk_tenant_bootstrap_pending_policy_artifact_scope",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "policy_artifact_id", name="uq_tenant_bootstrap_pending_policy_artifact"
        ),
        sa.UniqueConstraint("delivery_key", name="uq_tenant_bootstrap_pending_delivery_key"),
        sa.UniqueConstraint("payload_digest", name="uq_tenant_bootstrap_pending_payload_digest"),
        sa.CheckConstraint(
            "status IN ('pending', 'delivered', 'failed')",
            name="ck_tenant_bootstrap_pending_status",
        ),
    )
    op.create_index(
        "ix_tenant_bootstrap_pending_outbox_invitation_id",
        "tenant_bootstrap_pending_outbox",
        ["invitation_id"],
    )
    op.create_index(
        "ix_tenant_bootstrap_pending_outbox_policy_artifact_id",
        "tenant_bootstrap_pending_outbox",
        ["policy_artifact_id"],
    )

    op.create_table(
        "tenant_bootstrap_refusal_events",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("route", sa.String(length=64), nullable=False),
        sa.Column("method", sa.String(length=8), nullable=False),
        sa.Column("stage", sa.String(length=32), nullable=False),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=False),
        sa.Column("invitation_id", sa.String(length=64), nullable=True),
        sa.Column("invitation_digest", sa.String(length=64), nullable=True),
        sa.Column("idempotency_digest", sa.String(length=64), nullable=True),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("request_id", name="uq_tenant_bootstrap_refusal_request_id"),
        sa.CheckConstraint("route = 'POST /v1/tenant-bootstrap'", name="ck_tbr_route"),
        sa.CheckConstraint("method = 'POST'", name="ck_tbr_method"),
        sa.CheckConstraint(
            "stage IN ('transport', 'authn', 'authz', 'policy', 'issuance', 'executor', 'tx')",
            name="ck_tbr_stage",
        ),
        sa.CheckConstraint("http_status IN (400, 401, 403, 409, 413, 503)", name="ck_tbr_status"),
    )


def downgrade() -> None:
    """Fail closed instead of deleting tenant bootstrap evidence."""
    msg = (
        "The control-plane migration history is forward-only; "
        "restore a verified backup to roll back."
    )
    raise NotImplementedError(msg)
