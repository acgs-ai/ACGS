"""Make runtime wiring challenge-consumption lineage immutable."""

from __future__ import annotations

from alembic import op

from acgs_control_plane.runtime_lineage_schema import (
    POSTGRES_RUNTIME_LINEAGE_FUNCTIONS_0013_DELTA,
    POSTGRES_RUNTIME_LINEAGE_TRIGGERS_0013_DELTA,
    SQLITE_RUNTIME_LINEAGE_OBJECTS_0013_DELTA,
)

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        for statement in POSTGRES_RUNTIME_LINEAGE_FUNCTIONS_0013_DELTA.values():
            op.execute(statement)
        for statement in POSTGRES_RUNTIME_LINEAGE_TRIGGERS_0013_DELTA.values():
            op.execute(statement)
    elif dialect == "sqlite":
        for statement in SQLITE_RUNTIME_LINEAGE_OBJECTS_0013_DELTA.values():
            op.execute(statement)


def downgrade() -> None:
    """Fail closed instead of deleting runtime challenge-consumption provenance."""

    raise NotImplementedError(
        "The control-plane migration history is forward-only; "
        "restore a verified backup to roll back runtime challenge-consumption immutability."
    )
