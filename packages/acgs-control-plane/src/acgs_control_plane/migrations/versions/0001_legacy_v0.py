"""Create the frozen control-plane v0 schema.

Revision ``0001`` is a reconstruction of the additive ``create_all`` schema
that shipped before Alembic was introduced.  It intentionally contains no
project or environment columns: existing evidence remains organization-scoped
and is never relabelled by the later scope migration.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    """Create exactly the known v0 tables for a new database."""
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("audit_anchor_count", sa.Integer(), nullable=False),
        sa.Column("audit_anchor_hash", sa.String(length=128), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("api_key_hash", sa.String(length=64), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "email", name="uq_users_org_email"),
    )
    op.create_index("ix_users_org_id", "users", ["org_id"], unique=False)
    op.create_index("ix_users_api_key_hash", "users", ["api_key_hash"], unique=True)

    op.create_table(
        "agents",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("trust_tier", sa.String(length=32), nullable=False),
        sa.Column("allowed_tools", _JSON, nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "name", name="uq_agents_org_name"),
    )
    op.create_index("ix_agents_org_id", "agents", ["org_id"], unique=False)

    op.create_table(
        "policy_bundles",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("policy_id", sa.String(length=200), nullable=False),
        sa.Column("version", sa.String(length=200), nullable=False),
        sa.Column("bundle", _JSON, nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_policy_bundles_org_id", "policy_bundles", ["org_id"], unique=False)

    op.create_table(
        "receipts",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("tool", sa.String(length=200), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("actor", sa.String(length=200), nullable=False),
        sa.Column("goal", sa.Text(), nullable=False),
        sa.Column("argument_hash", sa.String(length=128), nullable=False),
        sa.Column("audit_hash", sa.String(length=128), nullable=False),
        sa.Column("policy_version", sa.String(length=200), nullable=False),
        sa.Column("result_hash", sa.String(length=128), nullable=True),
        sa.Column("error_class", sa.String(length=200), nullable=True),
        sa.Column("payload", _JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_receipts_org_id", "receipts", ["org_id"], unique=False)
    op.create_index("ix_receipts_tool", "receipts", ["tool"], unique=False)
    op.create_index("ix_receipts_decision", "receipts", ["decision"], unique=False)
    op.create_index("ix_receipts_actor", "receipts", ["actor"], unique=False)
    op.create_index("ix_receipts_created_at", "receipts", ["created_at"], unique=False)

    op.create_table(
        "compliance_exports",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("receipt_count", sa.Integer(), nullable=False),
        sa.Column("bundle_hash", sa.String(length=128), nullable=False),
        sa.Column("bundle", _JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_compliance_exports_org_id", "compliance_exports", ["org_id"], unique=False)


def downgrade() -> None:
    """Fail closed instead of dropping organization evidence automatically."""
    msg = (
        "The control-plane migration history is forward-only; "
        "restore a verified backup to roll back."
    )
    raise NotImplementedError(msg)
