"""Add database-primary governance event groundwork.

Existing control-plane routes still treat the legacy JSONL audit files as the
read authority.  These tables are a transaction-safe foundation for a later,
explicit cutover; this revision does not infer project/environment provenance
or rewrite historical evidence.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "governance_event_heads",
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("last_sequence", sa.Integer(), nullable=False),
        sa.Column("last_event_hash", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("org_id"),
    )
    op.create_table(
        "governance_events",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.String(length=200), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=False),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("tool", sa.String(length=200), nullable=False),
        sa.Column("actor", sa.String(length=200), nullable=False),
        sa.Column("policy_version", sa.String(length=200), nullable=False),
        sa.Column("payload", _JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "id", name="uq_governance_events_org_id_id"),
        sa.UniqueConstraint("org_id", "sequence", name="uq_governance_events_org_sequence"),
        sa.UniqueConstraint("org_id", "event_id", name="uq_governance_events_org_event_id"),
    )
    op.create_index("ix_governance_events_org_id", "governance_events", ["org_id"])

    op.create_table(
        "audit_projection_outbox",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("governance_event_id", sa.String(length=64), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("payload", _JSON, nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["org_id", "governance_event_id"],
            ["governance_events.org_id", "governance_events.id"],
            name="fk_audit_projection_outbox_org_event",
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "sequence", name="uq_audit_projection_outbox_org_sequence"),
    )
    op.create_index("ix_audit_projection_outbox_org_id", "audit_projection_outbox", ["org_id"])

    op.create_table(
        "governance_event_cutover",
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("legacy_audit_anchor_count", sa.Integer(), nullable=False),
        sa.Column("legacy_audit_anchor_hash", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cutover_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("org_id"),
    )


def downgrade() -> None:
    """Fail closed instead of dropping governance event evidence automatically."""
    msg = (
        "The control-plane migration history is forward-only; "
        "restore a verified backup to roll back."
    )
    raise NotImplementedError(msg)
