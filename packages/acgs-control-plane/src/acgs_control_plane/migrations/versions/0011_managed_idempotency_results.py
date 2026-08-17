"""Add terminal managed idempotency results.

The table stores only terminal replay evidence for managed mutations. It has
no pending row, lease, takeover, expiry, or purge path; pre-governance and
transient failures therefore leave no idempotency state behind.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    with op.batch_alter_table("agents") as batch_op:
        batch_op.create_unique_constraint("uq_agents_org_id_id", ["org_id", "id"])
    op.create_table(
        "managed_idempotency_results",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("principal_id", sa.String(length=64), nullable=False),
        sa.Column("canonical_action", sa.String(length=200), nullable=False),
        sa.Column("key_digest", sa.String(length=64), nullable=False),
        sa.Column("request_digest_version", sa.String(length=64), nullable=False),
        sa.Column("request_digest", sa.String(length=64), nullable=False),
        sa.Column("canonicalizer_version", sa.String(length=64), nullable=False),
        sa.Column("terminal_decision", sa.String(length=16), nullable=False),
        sa.Column("response_status", sa.Integer(), nullable=False),
        sa.Column("response_body_hash", sa.String(length=64), nullable=False),
        sa.Column("native_receipt_row_id", sa.String(length=64), nullable=False),
        sa.Column("receipt_id", sa.String(length=200), nullable=False),
        sa.Column("governance_event_id", sa.String(length=64), nullable=False),
        sa.Column("governance_event_hash", sa.String(length=64), nullable=False),
        sa.Column("agent_id", sa.String(length=64), nullable=True),
        sa.Column("result_artifact", _JSON, nullable=False),
        sa.Column("result_artifact_hash", sa.String(length=64), nullable=False),
        sa.Column("result_signature_algorithm", sa.String(length=32), nullable=False),
        sa.Column("result_signing_key_id", sa.String(length=200), nullable=False),
        sa.Column("result_signature", sa.String(length=256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "terminal_decision = 'allow' "
            "OR terminal_decision = 'deny' "
            "OR terminal_decision = 'escalate'",
            name="ck_idempotency_terminal_decision",
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_idempotency_results_scope_environment",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "native_receipt_row_id"],
            ["native_decision_receipts.org_id", "native_decision_receipts.id"],
            name="fk_idempotency_results_org_native_receipt",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "governance_event_id"],
            ["governance_events.org_id", "governance_events.id"],
            name="fk_idempotency_results_org_event",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "agent_id"],
            ["agents.org_id", "agents.id"],
            name="fk_idempotency_results_org_agent",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id",
            "environment_id",
            "principal_id",
            "canonical_action",
            "key_digest",
            name="uq_idempotency_scope_key",
        ),
    )
    op.create_index(
        "ix_managed_idempotency_results_org_id", "managed_idempotency_results", ["org_id"]
    )


def downgrade() -> None:
    """Fail closed instead of deleting durable idempotency replay evidence."""
    msg = (
        "The control-plane migration history is forward-only; "
        "restore a verified backup to roll back."
    )
    raise NotImplementedError(msg)
