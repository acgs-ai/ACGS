"""Add managed receipt-v2 trust roots.

Revision ``0004`` is additive. It persists public verifier material and v2
receipt projection fields only; it does not rewrite legacy v1/unsigned receipt
bytes, expose key bootstrap routes, or store private signing material.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def _scope_fk(name: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["org_id", "project_id", "environment_id"],
        ["environments.org_id", "environments.project_id", "environments.id"],
        name=name,
    )


def upgrade() -> None:
    with op.batch_alter_table("managed_decision_receipts") as batch_op:
        batch_op.add_column(
            sa.Column("receipt_schema_version", sa.String(length=64), nullable=True)
        )
        batch_op.add_column(sa.Column("trust_epoch", sa.Integer(), nullable=True))

    op.create_table(
        "managed_trust_scopes",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("purpose", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        _scope_fk("fk_managed_trust_scopes_environment"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "purpose",
            name="uq_managed_trust_scope_full",
        ),
    )
    op.create_index("ix_managed_trust_scopes_org_id", "managed_trust_scopes", ["org_id"])

    op.create_table(
        "managed_trust_keys",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("purpose", sa.String(length=64), nullable=False),
        sa.Column("key_id", sa.String(length=200), nullable=False),
        sa.Column("algorithm", sa.String(length=32), nullable=False),
        sa.Column("public_key_spki_der", sa.LargeBinary(), nullable=False),
        sa.Column("activated_epoch", sa.Integer(), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("retired_epoch", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        _scope_fk("fk_managed_trust_keys_environment"),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "purpose"],
            [
                "managed_trust_scopes.org_id",
                "managed_trust_scopes.project_id",
                "managed_trust_scopes.environment_id",
                "managed_trust_scopes.purpose",
            ],
            name="fk_managed_trust_keys_scope",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "purpose",
            "key_id",
            "algorithm",
            "activated_epoch",
            name="uq_managed_trust_key_epoch",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'retired', 'revoked')",
            name="ck_managed_trust_key_status",
        ),
        sa.CheckConstraint("activated_epoch > 0", name="ck_managed_trust_key_epoch_positive"),
        sa.CheckConstraint(
            "(status = 'retired' AND retired_epoch IS NOT NULL "
            "AND retired_epoch > activated_epoch) OR "
            "(status IN ('active', 'revoked') AND retired_epoch IS NULL)",
            name="ck_managed_trust_key_retired_epoch",
        ),
    )
    op.create_index("ix_managed_trust_keys_org_id", "managed_trust_keys", ["org_id"])
    op.create_index(
        "uq_managed_trust_key_active_scope",
        "managed_trust_keys",
        ["org_id", "project_id", "environment_id", "purpose"],
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
        postgresql_where=sa.text("status = 'active'"),
    )


def downgrade() -> None:
    """Fail closed instead of deleting trust roots or v2 receipt projection state."""
    msg = (
        "The control-plane migration history is forward-only; "
        "restore a verified backup to roll back."
    )
    raise NotImplementedError(msg)
