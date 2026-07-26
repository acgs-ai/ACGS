"""Attach agents to the organization's project/environment scope.

Every ``managed_*`` table introduced from revision 0003 onward is
environment-scoped; ``agents`` was the remaining organization-only exception.
This revision closes that gap.

**Why a separate table rather than columns on ``agents``.**  ``agents`` is a
frozen revision-0001 table that the ORM still creates verbatim via
``metadata.create_all``; a fresh developer database is recognized as
"current metadata-created v0 schema" and stamped at revision 0001 before being
migrated forward.  Adding columns to the model would break that adoption path.
Every post-v0 concept in this schema therefore lives in its own
Alembic-managed table, and scope attachment follows the same rule.

**Attachment is optional and exclusive.**  Revision 0002 deliberately declined
to infer project or environment provenance for existing records, and the same
reasoning applies here: an agent created before scope existed genuinely has no
environment, and guessing one would fabricate governance attribution.  So an
agent has zero or one attachment -- never a partial or ambiguous one -- and
rows in ``agents`` are not rewritten at all.

The composite foreign keys are what make cross-environment attachment a schema
error rather than a convention: the agent must belong to the attachment's
organization, and the environment must belong to the same organization and
project.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the agent scope-attachment table without touching ``agents``."""
    # First: ``agents`` gains the composite candidate key the attachment's
    # foreign key targets. This must precede the create_table -- PostgreSQL
    # rejects a foreign key with no matching unique constraint, while SQLite
    # would accept it and only diverge later.
    # Additive: no column, row, or existing constraint changes.
    with op.batch_alter_table("agents") as batch_op:
        batch_op.create_unique_constraint("uq_agents_org_id_id", ["org_id", "id"])
    op.create_table(
        "agent_environment_scope",
        sa.Column("agent_id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        # One attachment per agent: the primary key alone makes a second
        # environment for the same agent unrepresentable.
        sa.PrimaryKeyConstraint("agent_id", name="pk_agent_environment_scope"),
        # The agent must live in the organization this attachment claims.
        sa.ForeignKeyConstraint(
            ["org_id", "agent_id"],
            ["agents.org_id", "agents.id"],
            name="fk_agent_environment_scope_agent",
        ),
        # The environment must belong to that same organization and project, so
        # an attachment cannot reach across organizations or projects.
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_agent_environment_scope_environment",
        ),
        # The scoped candidate key a future managed child must target to prove
        # it references an agent in its own environment.
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "agent_id",
            name="uq_agent_environment_scope_scope_agent",
        ),
    )
    op.create_index(
        "ix_agent_environment_scope_scope",
        "agent_environment_scope",
        ["org_id", "project_id", "environment_id"],
        unique=False,
    )


def downgrade() -> None:
    """Fail closed instead of dropping scope attribution automatically."""
    msg = (
        "The control-plane migration history is forward-only; "
        "restore a verified backup to roll back."
    )
    raise NotImplementedError(msg)
