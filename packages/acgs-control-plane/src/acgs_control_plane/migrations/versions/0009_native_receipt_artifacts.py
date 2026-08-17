"""Add reconstructible native Decision Receipt artifacts.

The columns are additive and nullable so revision 0008 databases upgrade
without rewriting historical rows. New native evidence verification fails
closed unless a row has the managed-safe profile, canonical artifact, and
artifact hash populated.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column(
        "governance_event_cutover",
        sa.Column("native_event_count", sa.Integer(), nullable=True),
    )
    op.add_column(
        "governance_event_cutover",
        sa.Column("native_event_head_hash", sa.String(length=64), nullable=True),
    )
    op.add_column("native_decision_receipts", sa.Column("receipt_artifact", _JSON, nullable=True))
    op.add_column(
        "native_decision_receipts",
        sa.Column("receipt_artifact_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "native_decision_receipts",
        sa.Column("evidence_profile", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "native_receipt_consumptions",
        sa.Column("attestation_artifact", _JSON, nullable=True),
    )
    op.add_column(
        "native_receipt_consumptions",
        sa.Column("attestation_artifact_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "native_receipt_consumptions",
        sa.Column("attestation_signature_algorithm", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "native_receipt_consumptions",
        sa.Column("attestation_signing_key_id", sa.String(length=200), nullable=True),
    )
    op.add_column(
        "native_receipt_consumptions",
        sa.Column("attestation_signature", sa.String(length=256), nullable=True),
    )


def downgrade() -> None:
    """Fail closed instead of deleting native receipt artifacts."""
    msg = (
        "The control-plane migration history is forward-only; "
        "restore a verified backup to roll back."
    )
    raise NotImplementedError(msg)
