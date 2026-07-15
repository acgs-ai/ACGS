"""Opt-in PostgreSQL migration tests for the controlled operator path.

These tests intentionally require ``ACP_TEST_POSTGRES_URL``, an explicit
``ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE=1`` acknowledgement, and the exact
dedicated disposable database ``acgs_control_plane_test`` before they reset its
``public`` schema.  They never infer or use an application/runtime database URL.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError

import acgs_control_plane.app as app_module
import acgs_control_plane.migrations as migration_module
from acgs_control_plane.app import create_app
from acgs_control_plane.config import ProductionPostureBlocked, RuntimePosture, Settings
from acgs_control_plane.db import Base, make_engine
from acgs_control_plane.migrations import (
    _POSTGRES_MIGRATION_LOCK_CLASS_ID,
    _POSTGRES_MIGRATION_LOCK_OBJECT_ID,
    _POSTGRES_MIGRATION_LOCK_STATEMENT,
    HEAD_REVISION,
    LEGACY_V0_REVISION,
    DatabaseSchemaState,
    MigrationLockUnavailable,
    MigrationPreflightError,
    StartupSchemaPreflightError,
    inspect_schema,
    migration_config,
    upgrade_database,
)

_TEST_POSTGRES_URL = os.environ.get("ACP_TEST_POSTGRES_URL")
if not _TEST_POSTGRES_URL:
    pytest.skip(
        "set ACP_TEST_POSTGRES_URL to run disposable PostgreSQL migration tests",
        allow_module_level=True,
    )
if os.environ.get("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE") != "1":
    raise RuntimeError(
        "Set ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE=1 to acknowledge that this test "
        "will reset the exact disposable PostgreSQL public schema."
    )

pytest.importorskip("psycopg")
_TEST_URL = sa.engine.make_url(_TEST_POSTGRES_URL)
_DISPOSABLE_DATABASE_NAME = "acgs_control_plane_test"
if _TEST_URL.get_backend_name() != "postgresql":
    raise RuntimeError("ACP_TEST_POSTGRES_URL must use a PostgreSQL URL.")
if _TEST_URL.database != _DISPOSABLE_DATABASE_NAME:
    raise RuntimeError(
        "ACP_TEST_POSTGRES_URL must name exactly the dedicated disposable database "
        f"{_DISPOSABLE_DATABASE_NAME!r} before this test may reset its public schema."
    )

_LOCK_PARAMETERS = {
    "class_id": _POSTGRES_MIGRATION_LOCK_CLASS_ID,
    "object_id": _POSTGRES_MIGRATION_LOCK_OBJECT_ID,
}


def _assert_disposable_database(connection: Connection) -> None:
    database_name = connection.scalar(sa.text("SELECT current_database()"))
    if database_name != _DISPOSABLE_DATABASE_NAME:
        raise RuntimeError(
            "Refusing to reset PostgreSQL public schema outside the exact dedicated test database."
        )


def _reset_public_schema() -> None:
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.begin() as connection:
            _assert_disposable_database(connection)
            connection.execute(sa.text("DROP SCHEMA public CASCADE"))
            connection.execute(sa.text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


@pytest.fixture(autouse=True)
def _isolated_postgresql_schema() -> Iterator[None]:
    """Reset only the explicitly named disposable database before and after a test."""
    _reset_public_schema()
    try:
        yield
    finally:
        _reset_public_schema()


def _table_names() -> set[str]:
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.connect() as connection:
            return set(sa.inspect(connection).get_table_names(schema="public"))
    finally:
        engine.dispose()


def _try_advisory_xact_lock(connection: Connection) -> bool:
    return bool(connection.scalar(_POSTGRES_MIGRATION_LOCK_STATEMENT, _LOCK_PARAMETERS))


def _catalog_and_data_snapshot() -> tuple[tuple[object, ...], ...]:
    """Capture the disposable public schema and every controlled test row."""
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.connect() as connection:
            catalog = connection.execute(
                sa.text(
                    """
                    SELECT c.relkind, c.relname, a.attnum, a.attname,
                           pg_catalog.format_type(a.atttypid, a.atttypmod),
                           a.attnotnull, pg_catalog.pg_get_expr(d.adbin, d.adrelid),
                           con.conname, pg_catalog.pg_get_constraintdef(con.oid, true),
                           idx.relname, pg_catalog.pg_get_indexdef(idx.oid)
                    FROM pg_catalog.pg_class AS c
                    JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                    LEFT JOIN pg_catalog.pg_attribute AS a
                      ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
                    LEFT JOIN pg_catalog.pg_attrdef AS d
                      ON d.adrelid = c.oid AND d.adnum = a.attnum
                    LEFT JOIN pg_catalog.pg_constraint AS con ON con.conrelid = c.oid
                    LEFT JOIN pg_catalog.pg_index AS ix ON ix.indrelid = c.oid
                    LEFT JOIN pg_catalog.pg_class AS idx ON idx.oid = ix.indexrelid
                    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm')
                    ORDER BY c.relkind, c.relname, a.attnum, con.conname, idx.relname
                    """
                )
            ).all()
            table_names = sa.inspect(connection).get_table_names(schema="public")
            data: list[tuple[object, ...]] = []
            metadata = sa.MetaData()
            for table_name in sorted(table_names):
                table = sa.Table(table_name, metadata, autoload_with=connection)
                rows = connection.execute(sa.select(table)).all()
                serialized_rows = tuple(tuple(repr(value) for value in row) for row in rows)
                data.append(("data", table_name, serialized_rows))
            return tuple(tuple(row) for row in catalog) + tuple(data)
    finally:
        engine.dispose()


def _seed_exact_legacy_v0_schema() -> None:
    """Create only the frozen legacy tables for an adoption/rollback probe."""
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()


def test_postgresql_clean_install_has_types_and_cross_org_parent_constraint() -> None:
    result = upgrade_database(_TEST_POSTGRES_URL)

    assert result.before.state is DatabaseSchemaState.EMPTY
    assert result.after.state is DatabaseSchemaState.VERSION_0002
    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.VERSION_0002

    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.connect() as connection:
            inspector = sa.inspect(connection)
            version_numbers = (
                connection.execute(sa.text("SELECT version_num FROM alembic_version"))
                .scalars()
                .all()
            )
            assert version_numbers == [HEAD_REVISION]

            receipt_columns = {
                column["name"]: column for column in inspector.get_columns("receipts")
            }
            assert isinstance(receipt_columns["payload"]["type"], postgresql.JSONB)
            assert isinstance(receipt_columns["created_at"]["type"], postgresql.TIMESTAMP)
            assert receipt_columns["created_at"]["type"].timezone is True

            project_columns = {
                column["name"]: column for column in inspector.get_columns("projects")
            }
            assert isinstance(project_columns["created_at"]["type"], postgresql.TIMESTAMP)
            assert project_columns["created_at"]["type"].timezone is True

            environment_foreign_keys = {
                (
                    tuple(foreign_key["constrained_columns"]),
                    foreign_key["referred_table"],
                    tuple(foreign_key["referred_columns"]),
                )
                for foreign_key in inspector.get_foreign_keys("environments")
            }
            assert (("org_id", "project_id"), "projects", ("org_id", "id")) in (
                environment_foreign_keys
            )

        with engine.begin() as connection:
            created_at = "2026-07-13T00:00:00+00:00"
            connection.execute(
                sa.text(
                    """
                    INSERT INTO organizations (
                        id, name, created_at, audit_anchor_count, audit_anchor_hash
                    ) VALUES
                        ('org-a', 'Organization A', :created_at, 0, ''),
                        ('org-b', 'Organization B', :created_at, 0, '')
                    """
                ),
                {"created_at": created_at},
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO projects (id, org_id, slug, name, created_at)
                    VALUES ('project-a', 'org-a', 'core', 'Core Project', :created_at)
                    """
                ),
                {"created_at": created_at},
            )

        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    sa.text(
                        """
                        INSERT INTO environments (id, org_id, project_id, slug, name, created_at)
                        VALUES (
                            'environment-cross-org', 'org-b', 'project-a', 'production',
                            'Cross-org Attempt', :created_at
                        )
                        """
                    ),
                    {"created_at": "2026-07-13T00:00:00+00:00"},
                )
    finally:
        engine.dispose()


def test_postgresql_lock_contention_rejects_before_schema_mutation_then_retries() -> None:
    holder_engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with holder_engine.connect() as holder:
            with holder.begin():
                assert _try_advisory_xact_lock(holder)
                with pytest.raises(MigrationLockUnavailable, match="migration lock is held"):
                    upgrade_database(_TEST_POSTGRES_URL)

                assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.EMPTY
                assert _table_names() == set()

        result = upgrade_database(_TEST_POSTGRES_URL)
    finally:
        holder_engine.dispose()

    assert result.after.state is DatabaseSchemaState.VERSION_0002


def test_postgresql_injected_stamp_and_upgrade_rollback_atomically_and_release_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_exact_legacy_v0_schema()
    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.LEGACY_V0

    original_upgrade = migration_module.command.upgrade

    def _run_actual_upgrade_then_fail(config: object, revision: str, **kwargs: object) -> None:
        assert isinstance(config, migration_module.Config)
        injected_connection = config.attributes["connection"]
        assert isinstance(injected_connection, Connection)
        assert injected_connection.in_transaction()
        assert (
            injected_connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
            == LEGACY_V0_REVISION
        )

        observer_engine = make_engine(_TEST_POSTGRES_URL)
        try:
            with observer_engine.connect() as observer:
                # The legacy stamp is inside the outer transaction and cannot
                # be observed/committed by another PostgreSQL session.
                with observer.begin():
                    assert (
                        observer.scalar(sa.text("SELECT to_regclass('public.alembic_version')"))
                        is None
                    )
                    assert not _try_advisory_xact_lock(observer)
        finally:
            observer_engine.dispose()

        original_upgrade(config, revision, **kwargs)
        assert (
            injected_connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
            == HEAD_REVISION
        )
        raise RuntimeError("injected failure after actual PostgreSQL Alembic upgrade")

    with monkeypatch.context() as scoped_patch:
        scoped_patch.setattr(migration_module.command, "upgrade", _run_actual_upgrade_then_fail)
        with pytest.raises(
            RuntimeError, match="injected failure after actual PostgreSQL Alembic upgrade"
        ):
            upgrade_database(_TEST_POSTGRES_URL)

    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.LEGACY_V0
    assert _table_names() == {
        "agents",
        "compliance_exports",
        "organizations",
        "policy_bundles",
        "receipts",
        "users",
    }

    lock_probe_engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with lock_probe_engine.connect() as connection:
            with connection.begin():
                assert _try_advisory_xact_lock(connection)
    finally:
        lock_probe_engine.dispose()

    result = upgrade_database(_TEST_POSTGRES_URL)
    assert result.before.state is DatabaseSchemaState.LEGACY_V0
    assert result.after.state is DatabaseSchemaState.VERSION_0002


def test_raw_postgresql_alembic_commands_reject_before_schema_or_version_mutation() -> None:
    with pytest.raises(MigrationPreflightError, match="Refusing a raw Alembic operation"):
        command.upgrade(migration_config(_TEST_POSTGRES_URL), "head")
    with pytest.raises(MigrationPreflightError, match="Refusing a raw Alembic operation"):
        command.stamp(migration_config(_TEST_POSTGRES_URL), LEGACY_V0_REVISION)

    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.EMPTY
    assert _table_names() == set()


def _seed_postgresql_startup_state(state: str) -> DatabaseSchemaState:
    if state == "empty":
        return DatabaseSchemaState.EMPTY
    if state == "unknown":
        engine = make_engine(_TEST_POSTGRES_URL)
        try:
            with engine.begin() as connection:
                connection.execute(sa.text("CREATE TABLE unexpected (id INTEGER PRIMARY KEY)"))
                connection.execute(sa.text("INSERT INTO unexpected (id) VALUES (17)"))
        finally:
            engine.dispose()
        return DatabaseSchemaState.UNKNOWN

    upgrade_database(_TEST_POSTGRES_URL)
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.begin() as connection:
            if state == "version-0001":
                connection.execute(sa.text("DROP TABLE environments"))
                connection.execute(sa.text("DROP TABLE projects"))
                connection.execute(sa.text("UPDATE alembic_version SET version_num = '0001'"))
                return DatabaseSchemaState.VERSION_0001
            if state == "partial-0001":
                connection.execute(sa.text("DROP TABLE environments"))
                connection.execute(sa.text("UPDATE alembic_version SET version_num = '0001'"))
                return DatabaseSchemaState.VERSION_0001_PARTIAL_PROJECTS
            if state == "future":
                connection.execute(sa.text("UPDATE alembic_version SET version_num = '9999'"))
                return DatabaseSchemaState.UNKNOWN
    finally:
        engine.dispose()
    raise AssertionError(f"unknown PostgreSQL startup seed state: {state}")


@pytest.mark.parametrize(
    "seed_state",
    ("empty", "version-0001", "partial-0001", "future", "unknown"),
)
def test_postgresql_schema_managed_startup_rejects_noncurrent_schema_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    seed_state: str,
) -> None:
    expected_state = _seed_postgresql_startup_state(seed_state)
    assert inspect_schema(_TEST_POSTGRES_URL).state is expected_state
    before = _catalog_and_data_snapshot()
    observed_engine = make_engine(_TEST_POSTGRES_URL)
    statements: list[str] = []

    @sa.event.listens_for(observed_engine, "before_cursor_execute")
    def _record_statement(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: object,
    ) -> None:
        statements.append(statement)

    monkeypatch.setattr(app_module, "make_engine", lambda _url: observed_engine)
    audit_dir = tmp_path / "audit"
    with pytest.raises(StartupSchemaPreflightError) as stopped:
        create_app(
            Settings(
                database_url=_TEST_POSTGRES_URL,
                audit_dir=audit_dir,
                create_tables=False,
                runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
            )
        )

    assert stopped.value.schema_state is expected_state
    assert statements
    mutation_verbs = {
        "ALTER",
        "CREATE",
        "DELETE",
        "DROP",
        "INSERT",
        "MERGE",
        "TRUNCATE",
        "UPDATE",
    }
    assert (
        not {statement.lstrip().partition(" ")[0].upper() for statement in statements}
        & mutation_verbs
    )
    assert _catalog_and_data_snapshot() == before
    assert inspect_schema(_TEST_POSTGRES_URL).state is expected_state
    assert not audit_dir.exists()


def test_postgresql_exact_head_production_is_blocked_before_persistence_and_local_is_not_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = upgrade_database(_TEST_POSTGRES_URL)
    assert result.after.state is DatabaseSchemaState.VERSION_0002
    before = _catalog_and_data_snapshot()
    audit_dir = tmp_path / "audit"
    calls = {"engine": 0}

    def forbidden_engine(_url: str) -> object:
        calls["engine"] += 1
        raise AssertionError("production posture constructed a PostgreSQL engine")

    with monkeypatch.context() as production_patch:
        production_patch.setattr(app_module, "make_engine", forbidden_engine)
        with pytest.raises(ProductionPostureBlocked) as stopped:
            create_app(
                Settings(
                    database_url=_TEST_POSTGRES_URL,
                    audit_dir=audit_dir,
                    create_tables=False,
                    runtime_posture=RuntimePosture.PRODUCTION,
                )
            )
    assert calls == {"engine": 0}
    assert (
        len(
            [
                blocker
                for blocker in stopped.value.blockers
                if blocker.code == "LEGACY_UNSIGNED_WRITE"
            ]
        )
        == 7
    )
    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.VERSION_0002
    assert not audit_dir.exists()

    app = create_app(
        Settings(
            database_url=_TEST_POSTGRES_URL,
            audit_dir=audit_dir,
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        )
    )
    try:
        response = TestClient(app).get("/readyz")
        assert response.status_code == 503
        assert response.json() == {
            "blockers": [blocker.to_dict() for blocker in app.state.readiness_blockers],
            "schema_current": True,
            "schema_state": DatabaseSchemaState.VERSION_0002.value,
            "status": "not-production-ready",
        }
        assert not audit_dir.exists()
    finally:
        app.state.engine.dispose()
    assert _catalog_and_data_snapshot() == before
