"""Add scoped idempotency state for managed agent registration.

Revision ``0007`` records terminal ``agent.register`` responses. It is
intentionally additive: existing registration rows remain unchanged, while new
idempotency rows bind the caller-owned key digest to the
server-authenticated org/project/environment/actor request boundary.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("agents") as batch_op:
        batch_op.create_unique_constraint(
            "uq_agents_scope_id",
            ["org_id", "project_id", "environment_id", "id"],
        )
    op.create_table(
        "agent_registration_idempotency",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(length=64), nullable=False),
        sa.Column("actor_hash", sa.String(length=64), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("agent_id", sa.String(length=64), nullable=True),
        sa.Column("receipt_id", sa.String(length=200), nullable=False),
        sa.Column(
            "response",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "agent_id"],
            ["agents.org_id", "agents.project_id", "agents.environment_id", "agents.id"],
            name="fk_agent_registration_idempotency_agent_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "receipt_id"],
            [
                "managed_decision_receipts.org_id",
                "managed_decision_receipts.project_id",
                "managed_decision_receipts.environment_id",
                "managed_decision_receipts.receipt_id",
            ],
            name="fk_agent_registration_idempotency_receipt_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_agent_registration_idempotency_environment",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "idempotency_key_hash",
            name="uq_agent_registration_idempotency_key_hash",
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "agent_id",
            name="uq_agent_registration_idempotency_agent",
        ),
    )
    op.create_index(
        "ix_agent_registration_idempotency_org_id",
        "agent_registration_idempotency",
        ["org_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_agent_registration_idempotency_org_id",
        table_name="agent_registration_idempotency",
    )
    op.drop_table("agent_registration_idempotency")
    with op.batch_alter_table("agents") as batch_op:
        batch_op.drop_constraint("uq_agents_scope_id", type_="unique")
