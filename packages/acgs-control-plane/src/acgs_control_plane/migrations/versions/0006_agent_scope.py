"""Bind managed agents to server-owned project/environment scope.

Revision ``0006`` keeps legacy agent rows nullable and unscoped. New managed
agent registrations must write both ``project_id`` and ``environment_id`` so
the receipt projection, consumption, event, outbox, and agent row share one
database-enforced tenant/project/environment boundary.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    with op.batch_alter_table("agents") as batch_op:
        batch_op.add_column(sa.Column("project_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("environment_id", sa.String(length=64), nullable=True))
        batch_op.drop_constraint("uq_agents_org_name", type_="unique")
        batch_op.create_check_constraint(
            "ck_agents_scope_both_null_or_set",
            "(project_id IS NULL AND environment_id IS NULL) OR "
            "(project_id IS NOT NULL AND environment_id IS NOT NULL)",
        )
        batch_op.create_foreign_key(
            "fk_agents_scope_environment",
            "environments",
            ["org_id", "project_id", "environment_id"],
            ["org_id", "project_id", "id"],
        )

    op.create_index(
        "uq_agents_legacy_org_name",
        "agents",
        ["org_id", "name"],
        unique=True,
        sqlite_where=sa.text("project_id IS NULL AND environment_id IS NULL"),
        postgresql_where=sa.text("project_id IS NULL AND environment_id IS NULL"),
    )
    op.create_index(
        "uq_agents_scope_name",
        "agents",
        ["org_id", "project_id", "environment_id", "name"],
        unique=True,
        sqlite_where=sa.text("project_id IS NOT NULL AND environment_id IS NOT NULL"),
        postgresql_where=sa.text("project_id IS NOT NULL AND environment_id IS NOT NULL"),
    )
    op.create_index(
        "uq_policy_bundles_one_active_per_org",
        "policy_bundles",
        ["org_id"],
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
        postgresql_where=sa.text("status = 'active'"),
    )
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("ALTER TABLE agents VALIDATE CONSTRAINT fk_agents_scope_environment"))


def downgrade() -> None:
    op.drop_index("uq_policy_bundles_one_active_per_org", table_name="policy_bundles")
    op.drop_index("uq_agents_scope_name", table_name="agents")
    op.drop_index("uq_agents_legacy_org_name", table_name="agents")
    with op.batch_alter_table("agents") as batch_op:
        batch_op.drop_constraint("fk_agents_scope_environment", type_="foreignkey")
        batch_op.drop_constraint("ck_agents_scope_both_null_or_set", type_="check")
        batch_op.create_unique_constraint("uq_agents_org_name", ["org_id", "name"])
        batch_op.drop_column("environment_id")
        batch_op.drop_column("project_id")
