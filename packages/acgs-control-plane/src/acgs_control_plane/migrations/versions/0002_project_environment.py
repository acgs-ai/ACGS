"""Add organization-bound project and environment scope.

Existing v0 rows remain organization-scoped.  This expansion deliberately
does not infer project or environment provenance for receipts, audit anchors,
or export evidence.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from acgs_control_plane.migrations import ScopeMigrationResumeState, scope_migration_resume_state

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add scoped hierarchy tables without rewriting legacy evidence.

    A failed attempt can resume only when the already-created scope tables
    exactly match this revision and contain no data.  Any mixed or data-bearing
    partial state is rejected by ``scope_migration_resume_state``.
    """
    resume_state = scope_migration_resume_state(op.get_bind())
    if resume_state is ScopeMigrationResumeState.FRESH:
        _create_projects()
        _create_environments()
    elif resume_state is ScopeMigrationResumeState.PROJECTS_CREATED:
        _create_environments()
    elif resume_state is ScopeMigrationResumeState.SCOPE_TABLES_CREATED:
        return
    else:  # pragma: no cover - StrEnum is closed; keep a fail-closed guard.
        msg = f"unsupported scope migration resume state: {resume_state}"
        raise RuntimeError(msg)


def _create_projects() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("slug", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "slug", name="uq_projects_org_slug"),
        # The composite candidate key is intentionally redundant with the
        # primary key so environments can prove their parent has the same org.
        sa.UniqueConstraint("org_id", "id", name="uq_projects_org_id_id"),
    )


def _create_environments() -> None:
    op.create_table(
        "environments",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("slug", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id"],
            ["projects.org_id", "projects.id"],
            name="fk_environments_org_project",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id", "project_id", "slug", name="uq_environments_org_project_slug"
        ),
    )


def downgrade() -> None:
    """Fail closed instead of dropping project/environment records automatically."""
    msg = (
        "The control-plane migration history is forward-only; "
        "restore a verified backup to roll back."
    )
    raise NotImplementedError(msg)
