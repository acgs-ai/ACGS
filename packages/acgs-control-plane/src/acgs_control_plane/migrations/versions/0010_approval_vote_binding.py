"""Bind approval votes to credentials and exact managed vote receipts.

Revision ``0010`` is intentionally fail-closed for databases that already
contain approval vote rows. Revision ``0009`` did not store the exact
credential or receipt linkage needed to prove those historical votes without
guessing from nearby receipts, so this migration refuses that ambiguous state
instead of fabricating provenance.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

JSONVariant = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    existing_votes = connection.scalar(sa.text("SELECT COUNT(*) FROM approval_votes"))
    existing_resumes = connection.scalar(
        sa.text("SELECT COUNT(*) FROM approval_resume_authorizations")
    )
    if existing_votes or existing_resumes:
        raise RuntimeError(
            "revision 0010 refuses to upgrade databases with historical approval_votes or "
            "approval_resume_authorizations; export and re-issue approval evidence through "
            "the 0010 approval paths"
        )

    with op.batch_alter_table("approval_votes") as batch_op:
        batch_op.add_column(
            sa.Column("approver_credential_hash", sa.String(length=64), nullable=False)
        )
        batch_op.add_column(sa.Column("vote_receipt_id", sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column("vote_receipt_hash", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("vote_audit_event_hash", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("vote_replay_seal", JSONVariant, nullable=False))
        batch_op.create_unique_constraint(
            "uq_av_scope_vote_receipt_id",
            ["org_id", "project_id", "environment_id", "vote_receipt_id"],
        )
        batch_op.create_unique_constraint(
            "uq_av_scope_vote_receipt_hash",
            ["org_id", "project_id", "environment_id", "vote_receipt_hash"],
        )
        batch_op.create_unique_constraint(
            "uq_av_scope_vote_audit_event_hash",
            ["org_id", "project_id", "environment_id", "vote_audit_event_hash"],
        )
        batch_op.create_foreign_key(
            "fk_approval_votes_receipt_scope",
            "managed_decision_receipts",
            ["org_id", "project_id", "environment_id", "vote_receipt_id"],
            ["org_id", "project_id", "environment_id", "receipt_id"],
            deferrable=True,
            initially="DEFERRED",
        )
    with op.batch_alter_table("approval_resume_authorizations") as batch_op:
        batch_op.add_column(
            sa.Column("resume_argument_hash", sa.String(length=128), nullable=False)
        )
        batch_op.add_column(sa.Column("resumer_actor_hash", sa.String(length=64), nullable=False))
        batch_op.add_column(
            sa.Column("resumer_credential_hash", sa.String(length=64), nullable=False)
        )
        batch_op.add_column(sa.Column("resumer_role", sa.String(length=32), nullable=False))
        batch_op.add_column(sa.Column("resume_result_hash", sa.String(length=128), nullable=False))
        batch_op.add_column(sa.Column("resume_result", JSONVariant, nullable=False))
        batch_op.add_column(sa.Column("resume_response_hash", sa.String(length=64), nullable=False))
        batch_op.add_column(sa.Column("resume_response", JSONVariant, nullable=False))
        batch_op.add_column(sa.Column("resume_replay_seal", JSONVariant, nullable=False))


def downgrade() -> None:
    """Fail closed instead of deleting approval-vote provenance."""

    raise NotImplementedError(
        "The control-plane migration history is forward-only; "
        "restore a verified backup to roll back approval vote bindings."
    )
