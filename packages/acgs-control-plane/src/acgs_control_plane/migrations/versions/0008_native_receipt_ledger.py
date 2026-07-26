"""Add minimized native Decision Receipt projections and consumption burns.

The tables are additive and not wired to legacy HTTP routes. A receipt row and
its consumption burn are intended to share the caller's SQL transaction with
the protected database effect. The migration history is forward-only.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "native_decision_receipts",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("receipt_id", sa.String(length=200), nullable=False),
        sa.Column("receipt_hash", sa.String(length=64), nullable=False),
        sa.Column("audit_event_hash", sa.String(length=64), nullable=False),
        sa.Column("assurance_class", sa.String(length=32), nullable=False),
        sa.Column("source_system", sa.String(length=64), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("actor", sa.String(length=200), nullable=False),
        sa.Column("execution_boundary", sa.String(length=200), nullable=False),
        sa.Column("proposed_action", sa.String(length=200), nullable=False),
        sa.Column("policy_bundle_id", sa.String(length=200), nullable=False),
        sa.Column("policy_version", sa.String(length=200), nullable=False),
        sa.Column("policy_hash", sa.String(length=128), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signing_key_id", sa.String(length=200), nullable=False),
        sa.Column("signature_algorithm", sa.String(length=32), nullable=False),
        sa.Column("projection", _JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("assurance_class = 'native'", name="ck_native_receipts_assurance_class"),
        sa.CheckConstraint("source_system = 'gove-zone'", name="ck_native_receipts_source_system"),
        sa.UniqueConstraint("org_id", "id", name="uq_native_receipts_org_id_id"),
        sa.UniqueConstraint("org_id", "receipt_id", name="uq_native_receipts_org_receipt_id"),
        sa.UniqueConstraint("org_id", "receipt_hash", name="uq_native_receipts_org_receipt_hash"),
        sa.UniqueConstraint(
            "org_id", "audit_event_hash", name="uq_native_receipts_org_audit_event_hash"
        ),
    )
    op.create_index("ix_native_decision_receipts_org_id", "native_decision_receipts", ["org_id"])

    op.create_table(
        "native_receipt_consumptions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("native_receipt_id", sa.String(length=64), nullable=False),
        sa.Column("receipt_hash", sa.String(length=64), nullable=False),
        sa.Column("audit_event_hash", sa.String(length=64), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(
            ["org_id", "native_receipt_id"],
            ["native_decision_receipts.org_id", "native_decision_receipts.id"],
            name="fk_native_consumptions_org_receipt",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id", "native_receipt_id", name="uq_native_consumptions_org_receipt"
        ),
        sa.UniqueConstraint(
            "org_id", "receipt_hash", name="uq_native_consumptions_org_receipt_hash"
        ),
        sa.UniqueConstraint(
            "org_id", "audit_event_hash", name="uq_native_consumptions_org_audit_event_hash"
        ),
    )
    op.create_index(
        "ix_native_receipt_consumptions_org_id", "native_receipt_consumptions", ["org_id"]
    )


def downgrade() -> None:
    """Fail closed instead of deleting receipt or consumption evidence."""
    msg = (
        "The control-plane migration history is forward-only; "
        "restore a verified backup to roll back."
    )
    raise NotImplementedError(msg)
