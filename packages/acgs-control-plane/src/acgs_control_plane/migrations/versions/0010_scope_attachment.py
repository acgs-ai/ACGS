"""Attach legacy agents and policy bundles to canonical default scope.

Revision ``0010`` extends the nullable composite scope model that revision
``0006`` introduced for ``agents`` to ``policy_bundles``, then backfills every
still-unscoped legacy row onto a deterministic per-organization default
project/environment. The scope columns stay nullable: new writes attach scope
at the application layer while pre-existing databases converge through the
seeded defaults.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from acgs_control_plane.scope_defaults import (
    LEGACY_DEFAULT_ENVIRONMENT_NAME,
    LEGACY_DEFAULT_ENVIRONMENT_SLUG,
    LEGACY_DEFAULT_PROJECT_NAME,
    LEGACY_DEFAULT_PROJECT_SLUG,
    legacy_default_environment_id,
    legacy_default_environment_values,
    legacy_default_project_id,
    legacy_default_project_values,
)

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

_BATCH_TEMP_TABLES = {
    "policy_bundles": "_alembic_tmp_policy_bundles",
}
_EXPECTED_TEMP_COLUMNS = {
    "policy_bundles": (
        "id",
        "org_id",
        "policy_id",
        "version",
        "bundle",
        "status",
        "created_at",
        "activated_at",
        "project_id",
        "environment_id",
    ),
}


def upgrade() -> None:
    connection = op.get_bind()
    _prepare_interrupted_batch_tables(connection)
    _reject_orphan_legacy_rows(connection)
    _reject_conflicting_default_scope_rows(connection)
    _seed_missing_default_scopes(connection)
    _ensure_scope_columns(connection, "policy_bundles")
    _backfill_legacy_rows(connection)
    _finalize_scope_attachment(connection, "policy_bundles")


def downgrade() -> None:
    """Fail closed instead of detaching records from their resolved scope."""
    msg = (
        "The control-plane migration history is forward-only; "
        "restore a verified backup to roll back."
    )
    raise NotImplementedError(msg)


def _prepare_interrupted_batch_tables(connection: sa.Connection) -> None:
    table_names = _table_names(connection)
    for base_table, temp_table in _BATCH_TEMP_TABLES.items():
        has_base = base_table in table_names
        has_temp = temp_table in table_names
        if not has_temp:
            continue
        _validate_batch_temp_table(connection, base_table, temp_table)
        if has_base:
            op.drop_table(temp_table)
        else:
            raise RuntimeError(
                "revision 0010 recovery refused: "
                f"{temp_table} exists but canonical table {base_table} is missing. "
                "Restore a verified backup or perform manual recovery before retrying."
            )


def _validate_batch_temp_table(connection: sa.Connection, base_table: str, temp_table: str) -> None:
    column_names = _column_layout(connection, temp_table)
    expected_column_names = _EXPECTED_TEMP_COLUMNS[base_table]
    if column_names != expected_column_names:
        raise RuntimeError(
            "revision 0010 recovery refused: "
            f"{temp_table} has malformed columns {column_names!r}; "
            f"expected {expected_column_names!r}."
        )
    if connection.scalar(sa.text(f"SELECT 1 FROM {temp_table} LIMIT 1")) is not None:
        raise RuntimeError(
            "revision 0010 recovery refused: "
            f"{temp_table} contains data and cannot be discarded automatically."
        )


def _reject_orphan_legacy_rows(connection: sa.Connection) -> None:
    checks = (
        (
            "users",
            """
            SELECT count(*) FROM users AS row
            LEFT JOIN organizations AS org ON org.id = row.org_id
            WHERE org.id IS NULL
            """,
        ),
        (
            "agents",
            """
            SELECT count(*) FROM agents AS row
            LEFT JOIN organizations AS org ON org.id = row.org_id
            WHERE org.id IS NULL
            """,
        ),
        (
            "policy_bundles",
            """
            SELECT count(*) FROM policy_bundles AS row
            LEFT JOIN organizations AS org ON org.id = row.org_id
            WHERE org.id IS NULL
            """,
        ),
        (
            "projects",
            """
            SELECT count(*) FROM projects AS row
            LEFT JOIN organizations AS org ON org.id = row.org_id
            WHERE org.id IS NULL
            """,
        ),
        (
            "environments.organization",
            """
            SELECT count(*) FROM environments AS row
            LEFT JOIN organizations AS org ON org.id = row.org_id
            WHERE org.id IS NULL
            """,
        ),
        (
            "environments.project",
            """
            SELECT count(*) FROM environments AS row
            LEFT JOIN projects AS project
              ON project.org_id = row.org_id AND project.id = row.project_id
            WHERE project.id IS NULL
            """,
        ),
    )
    for label, statement in checks:
        if _table_exists(connection, label.split(".", maxsplit=1)[0]) and connection.scalar(
            sa.text(statement)
        ):
            raise RuntimeError(
                f"revision 0010 refused orphan legacy rows before schema mutation: {label}"
            )


def _reject_conflicting_default_scope_rows(connection: sa.Connection) -> None:
    org_ids = _org_ids(connection)
    for org_id in org_ids:
        project_id = legacy_default_project_id(org_id)
        project_rows = list(
            connection.execute(
                sa.text(
                    """
                    SELECT id, org_id, slug, name
                    FROM projects
                    WHERE id = :project_id
                       OR (org_id = :org_id AND slug = :project_slug)
                    """
                ),
                {
                    "project_id": project_id,
                    "org_id": org_id,
                    "project_slug": LEGACY_DEFAULT_PROJECT_SLUG,
                },
            ).mappings()
        )
        if len(project_rows) > 1:
            raise RuntimeError(f"conflicting legacy default project rows for org {org_id}")
        if project_rows:
            project = project_rows[0]
            if (
                project["id"] != project_id
                or project["org_id"] != org_id
                or project["slug"] != LEGACY_DEFAULT_PROJECT_SLUG
                or project["name"] != LEGACY_DEFAULT_PROJECT_NAME
            ):
                raise RuntimeError(f"legacy default project slug/id/name conflict for org {org_id}")

        environment_id = legacy_default_environment_id(org_id)
        environment_rows = list(
            connection.execute(
                sa.text(
                    """
                    SELECT id, org_id, project_id, slug, name
                    FROM environments
                    WHERE id = :environment_id
                       OR (org_id = :org_id AND slug = :environment_slug)
                    """
                ),
                {
                    "environment_id": environment_id,
                    "org_id": org_id,
                    "environment_slug": LEGACY_DEFAULT_ENVIRONMENT_SLUG,
                },
            ).mappings()
        )
        if len(environment_rows) > 1:
            raise RuntimeError(f"conflicting legacy default environment rows for org {org_id}")
        if environment_rows:
            environment = environment_rows[0]
            if (
                environment["id"] != environment_id
                or environment["org_id"] != org_id
                or environment["project_id"] != project_id
                or environment["slug"] != LEGACY_DEFAULT_ENVIRONMENT_SLUG
                or environment["name"] != LEGACY_DEFAULT_ENVIRONMENT_NAME
            ):
                raise RuntimeError(
                    f"legacy default environment slug/id/name conflict for org {org_id}"
                )


def _seed_missing_default_scopes(connection: sa.Connection) -> None:
    for org_id in _org_ids(connection):
        project_id = legacy_default_project_id(org_id)
        if (
            connection.scalar(
                sa.text("SELECT 1 FROM projects WHERE id = :id"),
                {"id": project_id},
            )
            is None
        ):
            connection.execute(
                sa.text(
                    """
                    INSERT INTO projects (id, org_id, slug, name, created_at)
                    VALUES (:id, :org_id, :slug, :name, :created_at)
                    """
                ),
                legacy_default_project_values(org_id),
            )

        environment_id = legacy_default_environment_id(org_id)
        if (
            connection.scalar(
                sa.text("SELECT 1 FROM environments WHERE id = :id"),
                {"id": environment_id},
            )
            is None
        ):
            connection.execute(
                sa.text(
                    """
                    INSERT INTO environments (id, org_id, project_id, slug, name, created_at)
                    VALUES (:id, :org_id, :project_id, :slug, :name, :created_at)
                    """
                ),
                legacy_default_environment_values(org_id),
            )


def _ensure_scope_columns(connection: sa.Connection, table_name: str) -> None:
    column_names = _column_names(connection, table_name)
    if "project_id" not in column_names:
        op.add_column(table_name, sa.Column("project_id", sa.String(length=64), nullable=True))
    if "environment_id" not in column_names:
        op.add_column(table_name, sa.Column("environment_id", sa.String(length=64), nullable=True))


def _backfill_legacy_rows(connection: sa.Connection) -> None:
    for org_id in _org_ids(connection):
        parameters = {
            "org_id": org_id,
            "project_id": legacy_default_project_id(org_id),
            "environment_id": legacy_default_environment_id(org_id),
        }
        for table_name in ("agents", "policy_bundles"):
            connection.execute(
                sa.text(
                    f"""
                    UPDATE {table_name}
                    SET project_id = :project_id, environment_id = :environment_id
                    WHERE org_id = :org_id
                      AND project_id IS NULL
                      AND environment_id IS NULL
                    """
                ),
                parameters,
            )


def _finalize_scope_attachment(connection: sa.Connection, table_name: str) -> None:
    has_check = _check_constraint_exists(
        connection, table_name, f"ck_{table_name}_scope_both_null_or_set"
    )
    has_fk = _foreign_key_exists(
        connection,
        table_name,
        ("org_id", "project_id", "environment_id"),
        "environments",
        ("org_id", "project_id", "id"),
    )
    if has_check and has_fk:
        return

    with op.batch_alter_table(table_name) as batch_op:
        if not has_check:
            batch_op.create_check_constraint(
                f"ck_{table_name}_scope_both_null_or_set",
                "(project_id IS NULL AND environment_id IS NULL) OR "
                "(project_id IS NOT NULL AND environment_id IS NOT NULL)",
            )
        if not has_fk:
            batch_op.create_foreign_key(
                f"fk_{table_name}_scope_environment",
                "environments",
                ["org_id", "project_id", "environment_id"],
                ["org_id", "project_id", "id"],
            )


def _org_ids(connection: sa.Connection) -> tuple[str, ...]:
    return tuple(
        str(row[0])
        for row in connection.execute(sa.text("SELECT id FROM organizations ORDER BY id")).all()
    )


def _table_names(connection: sa.Connection) -> set[str]:
    schema = "public" if connection.dialect.name == "postgresql" else None
    return set(sa.inspect(connection).get_table_names(schema=schema))


def _table_exists(connection: sa.Connection, table_name: str) -> bool:
    return table_name in _table_names(connection)


def _column_names(connection: sa.Connection, table_name: str) -> set[str]:
    return set(_column_layout(connection, table_name))


def _column_layout(connection: sa.Connection, table_name: str) -> tuple[str, ...]:
    schema = "public" if connection.dialect.name == "postgresql" else None
    return tuple(
        str(column["name"])
        for column in sa.inspect(connection).get_columns(table_name, schema=schema)
    )


def _check_constraint_exists(
    connection: sa.Connection, table_name: str, constraint_name: str
) -> bool:
    schema = "public" if connection.dialect.name == "postgresql" else None
    for constraint in sa.inspect(connection).get_check_constraints(table_name, schema=schema):
        if constraint.get("name") == constraint_name:
            return True
    return False


def _foreign_key_exists(
    connection: sa.Connection,
    table_name: str,
    constrained_columns: tuple[str, ...],
    referred_table: str,
    referred_columns: tuple[str, ...],
) -> bool:
    schema = "public" if connection.dialect.name == "postgresql" else None
    for foreign_key in sa.inspect(connection).get_foreign_keys(table_name, schema=schema):
        if (
            tuple(foreign_key.get("constrained_columns") or ()) == constrained_columns
            and foreign_key.get("referred_table") == referred_table
            and tuple(foreign_key.get("referred_columns") or ()) == referred_columns
        ):
            return True
    return False
