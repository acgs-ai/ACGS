"""Add managed approval request substrate.

Revision ``0009`` is additive and forward-only. It stores immutable approval
requests for managed ESCALATE evidence plus append-only vote/outcome/resume
authorization rows. It does not expose a generic approval API by itself.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

JSONVariant = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "approval_requests",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=200), nullable=False),
        sa.Column("requester_actor_hash", sa.String(length=64), nullable=False),
        sa.Column("validator_role", sa.String(length=200), nullable=False),
        sa.Column("authority", sa.String(length=200), nullable=False),
        sa.Column("approver_role", sa.String(length=32), nullable=False),
        sa.Column("argument_hash", sa.String(length=128), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("policy_bundle_id", sa.String(length=200), nullable=False),
        sa.Column("policy_version", sa.String(length=200), nullable=False),
        sa.Column("policy_hash", sa.String(length=128), nullable=False),
        sa.Column("policy_head_generation", sa.Integer(), nullable=False),
        sa.Column("trust_epoch", sa.Integer(), nullable=False),
        sa.Column("execution_boundary", sa.String(length=200), nullable=False),
        sa.Column("escalate_receipt_id", sa.String(length=200), nullable=False),
        sa.Column("escalate_receipt_hash", sa.String(length=64), nullable=False),
        sa.Column("escalate_audit_event_hash", sa.String(length=64), nullable=False),
        sa.Column("quorum_threshold", sa.Integer(), nullable=False),
        sa.Column("sealed_arguments", JSONVariant, nullable=False),
        sa.Column("aad", JSONVariant, nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status = 'pending'", name="ck_approval_requests_status_pending"),
        sa.CheckConstraint("quorum_threshold > 0", name="ck_approval_requests_quorum_positive"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], deferrable=True, initially="DEFERRED"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_approval_requests_environment",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "escalate_receipt_id"],
            [
                "managed_decision_receipts.org_id",
                "managed_decision_receipts.project_id",
                "managed_decision_receipts.environment_id",
                "managed_decision_receipts.receipt_id",
            ],
            name="fk_approval_requests_escalate_receipt",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "project_id", "environment_id", "id", name="uq_ar_scope_id"),
        sa.UniqueConstraint("org_id", "request_hash", name="uq_ar_org_request_hash"),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "escalate_receipt_hash",
            name="uq_ar_scope_escalate_receipt_hash",
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "escalate_audit_event_hash",
            name="uq_ar_scope_escalate_audit_event_hash",
        ),
    )
    op.create_index("ix_approval_requests_org_id", "approval_requests", ["org_id"])

    op.create_table(
        "approval_votes",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("approval_request_id", sa.String(length=64), nullable=False),
        sa.Column("approver_actor_hash", sa.String(length=64), nullable=False),
        sa.Column("approver_role", sa.String(length=32), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(length=64), nullable=False),
        sa.Column("vote_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("decision IN ('approve', 'reject')", name="ck_approval_votes_decision"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], deferrable=True, initially="DEFERRED"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "approval_request_id"],
            [
                "approval_requests.org_id",
                "approval_requests.project_id",
                "approval_requests.environment_id",
                "approval_requests.id",
            ],
            name="fk_approval_votes_request_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "approval_request_id",
            "approver_actor_hash",
            name="uq_av_scope_request_actor",
        ),
        sa.UniqueConstraint(
            "org_id",
            "approval_request_id",
            "idempotency_key_hash",
            name="uq_av_org_request_idempotency",
        ),
    )
    op.create_index("ix_approval_votes_org_id", "approval_votes", ["org_id"])

    op.create_table(
        "approval_outcomes",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("approval_request_id", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("quorum_digest", sa.String(length=64), nullable=False),
        sa.Column("approver_set_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "outcome IN ('approved', 'rejected', 'expired', 'canceled')",
            name="ck_approval_outcomes_outcome",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], deferrable=True, initially="DEFERRED"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "approval_request_id"],
            [
                "approval_requests.org_id",
                "approval_requests.project_id",
                "approval_requests.environment_id",
                "approval_requests.id",
            ],
            name="fk_approval_outcomes_request_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "approval_request_id",
            name="uq_ao_scope_request",
        ),
    )
    op.create_index("ix_approval_outcomes_org_id", "approval_outcomes", ["org_id"])

    op.create_table(
        "approval_resume_authorizations",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("approval_request_id", sa.String(length=64), nullable=False),
        sa.Column("resumed_agent_id", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(length=64), nullable=False),
        sa.Column("resume_receipt_id", sa.String(length=200), nullable=False),
        sa.Column("resume_receipt_hash", sa.String(length=64), nullable=False),
        sa.Column("resume_audit_event_hash", sa.String(length=64), nullable=False),
        sa.Column("approval_chain_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], deferrable=True, initially="DEFERRED"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "approval_request_id"],
            [
                "approval_requests.org_id",
                "approval_requests.project_id",
                "approval_requests.environment_id",
                "approval_requests.id",
            ],
            name="fk_approval_resume_auth_request_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "resume_receipt_id"],
            [
                "managed_decision_receipts.org_id",
                "managed_decision_receipts.project_id",
                "managed_decision_receipts.environment_id",
                "managed_decision_receipts.receipt_id",
            ],
            name="fk_approval_resume_auth_receipt_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "resumed_agent_id"],
            ["agents.org_id", "agents.project_id", "agents.environment_id", "agents.id"],
            name="fk_approval_resume_auth_agent_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "approval_request_id",
            name="uq_ara_scope_request",
        ),
        sa.UniqueConstraint("org_id", "resume_receipt_hash", name="uq_ara_org_resume_receipt_hash"),
        sa.UniqueConstraint(
            "org_id", "resume_audit_event_hash", name="uq_ara_org_resume_audit_event_hash"
        ),
        sa.UniqueConstraint(
            "org_id",
            "approval_request_id",
            "idempotency_key_hash",
            name="uq_ara_org_request_idempotency",
        ),
    )
    op.create_index(
        "ix_approval_resume_authorizations_org_id",
        "approval_resume_authorizations",
        ["org_id"],
    )


def downgrade() -> None:
    """Fail closed instead of deleting approval evidence."""

    raise NotImplementedError(
        "The control-plane migration history is forward-only; "
        "restore a verified backup to roll back approval evidence."
    )
