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


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column(
            "api_key_hash",
            existing_type=sa.String(length=64),
            nullable=True,
            existing_nullable=False,
        )

    op.create_table(
        "organization_memberships",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("invitation_id", "id", name="uq_tenant_bootstrap_policy_invitation_id"),
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
            ["invitation_id", "policy_artifact_id"],
            [
                "tenant_bootstrap_policy_artifacts.invitation_id",
                "tenant_bootstrap_policy_artifacts.id",
            ],
            name="fk_pending_approvals_invitation_policy_artifact",
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
            ["invitation_id", "policy_artifact_id"],
            [
                "tenant_bootstrap_policy_artifacts.invitation_id",
                "tenant_bootstrap_policy_artifacts.id",
            ],
            name="fk_tenant_bootstrap_pending_invitation_policy_artifact",
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


def downgrade() -> None:
    """Fail closed instead of deleting tenant bootstrap evidence."""
    msg = (
        "The control-plane migration history is forward-only; "
        "restore a verified backup to roll back."
    )
    raise NotImplementedError(msg)
