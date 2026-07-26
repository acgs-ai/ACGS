"""Opt-in PostgreSQL migration tests for the controlled operator path.

These tests intentionally require ``ACP_TEST_POSTGRES_URL``, an explicit
``ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE=1`` acknowledgement, and the exact
dedicated disposable database ``acgs_control_plane_test`` before they reset its
``public`` schema.  They never infer or use an application/runtime database URL.
"""

from __future__ import annotations

import io
import json
import os
import signal
import subprocess
import sys
import time
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from queue import Empty, Queue
from threading import Condition, Event, Thread
from typing import Literal, Protocol

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
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.db import Base, make_engine
from acgs_control_plane.governance import ProductionPostureBlocked
from acgs_control_plane.migrations import (
    _POSTGRES_MIGRATION_LOCK_CLASS_ID,
    _POSTGRES_MIGRATION_LOCK_OBJECT_ID,
    _POSTGRES_MIGRATION_LOCK_STATEMENT,
    HEAD_REVISION,
    LEGACY_V0_REVISION,
    DatabaseSchemaBindingMismatch,
    DatabaseSchemaState,
    MigrationLockUnavailable,
    MigrationPreflightError,
    StartupSchemaPreflightError,
    inspect_schema,
    migration_config,
    upgrade_database,
)

_TEST_POSTGRES_URL = os.environ.get("ACP_TEST_POSTGRES_URL")
_TEST_URL = sa.engine.make_url(_TEST_POSTGRES_URL) if _TEST_POSTGRES_URL else None
_DISPOSABLE_DATABASE_NAME = "acgs_control_plane_test"

_LOCK_PARAMETERS = {
    "class_id": _POSTGRES_MIGRATION_LOCK_CLASS_ID,
    "object_id": _POSTGRES_MIGRATION_LOCK_OBJECT_ID,
}


def _postgres_url() -> str:
    assert _TEST_POSTGRES_URL is not None
    return _TEST_POSTGRES_URL


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


@pytest.fixture
def worker_protocol_only() -> None:
    """Declare a pure worker-protocol test that must run without PostgreSQL."""


@pytest.fixture(autouse=True)
def _isolated_postgresql_schema(request: pytest.FixtureRequest) -> Iterator[None]:
    """Reset only the explicitly named disposable database before and after a test."""
    if "worker_protocol_only" in request.fixturenames:
        yield
        return
    if not _TEST_POSTGRES_URL:
        pytest.skip("set ACP_TEST_POSTGRES_URL to run disposable PostgreSQL migration tests")
    if os.environ.get("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE") != "1":
        raise RuntimeError(
            "Set ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE=1 to acknowledge that this test "
            "will reset the exact disposable PostgreSQL public schema."
        )
    pytest.importorskip("psycopg")
    assert _TEST_URL is not None
    if _TEST_URL.get_backend_name() != "postgresql":
        raise RuntimeError("ACP_TEST_POSTGRES_URL must use a PostgreSQL URL.")
    if _TEST_URL.database != _DISPOSABLE_DATABASE_NAME:
        raise RuntimeError(
            "ACP_TEST_POSTGRES_URL must name exactly the dedicated disposable database "
            f"{_DISPOSABLE_DATABASE_NAME!r} before this test may reset its public schema."
        )
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
                    WITH catalog_objects AS (
                        SELECT
                            'relation' AS object_kind,
                            c.relkind::text AS kind,
                            c.relname AS name,
                            a.attnum::text AS detail_1,
                            a.attname AS detail_2,
                            pg_catalog.format_type(a.atttypid, a.atttypmod) AS detail_3,
                            a.attnotnull::text AS detail_4,
                            pg_catalog.pg_get_expr(d.adbin, d.adrelid) AS detail_5,
                            con.conname AS detail_6,
                            pg_catalog.pg_get_constraintdef(con.oid, true) AS detail_7,
                            idx.relname AS detail_8,
                            pg_catalog.pg_get_indexdef(idx.oid) AS detail_9
                        FROM pg_catalog.pg_class AS c
                        JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                        LEFT JOIN pg_catalog.pg_attribute AS a
                          ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
                        LEFT JOIN pg_catalog.pg_attrdef AS d
                          ON d.adrelid = c.oid AND d.adnum = a.attnum
                        LEFT JOIN pg_catalog.pg_constraint AS con ON con.conrelid = c.oid
                        LEFT JOIN pg_catalog.pg_index AS ix ON ix.indrelid = c.oid
                        LEFT JOIN pg_catalog.pg_class AS idx ON idx.oid = ix.indexrelid
                        WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
                        UNION ALL
                        SELECT
                            'routine',
                            p.prokind::text,
                            p.proname,
                            pg_catalog.pg_get_function_identity_arguments(p.oid),
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL
                        FROM pg_catalog.pg_proc AS p
                        JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
                        WHERE n.nspname = 'public'
                        UNION ALL
                        SELECT
                            'type',
                            t.typtype::text,
                            t.typname,
                            c.relkind::text,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL
                        FROM pg_catalog.pg_type AS t
                        JOIN pg_catalog.pg_namespace AS n ON n.oid = t.typnamespace
                        LEFT JOIN pg_catalog.pg_class AS c ON c.oid = t.typrelid
                        WHERE n.nspname = 'public'
                        UNION ALL
                        SELECT
                            'rewrite_rule',
                            r.ev_type::text,
                            c.relname,
                            r.rulename,
                            pg_catalog.pg_get_ruledef(r.oid),
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL
                        FROM pg_catalog.pg_rewrite AS r
                        JOIN pg_catalog.pg_class AS c ON c.oid = r.ev_class
                        JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public'
                    )
                    SELECT * FROM catalog_objects
                    ORDER BY object_kind, kind, name, detail_1, detail_2, detail_6, detail_8
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


def _head_schema_with_unsupported_object_snapshot() -> tuple[tuple[object, ...], ...]:
    test_url = _postgres_url()
    result = upgrade_database(test_url)
    assert result.after.state is DatabaseSchemaState.VERSION_0008
    before = _catalog_and_data_snapshot()
    assert inspect_schema(test_url).state is DatabaseSchemaState.VERSION_0008
    return before


def _seed_unsupported_public_object(seed_sql: str) -> tuple[tuple[object, ...], ...]:
    _head_schema_with_unsupported_object_snapshot()
    engine = make_engine(_postgres_url())
    try:
        with engine.begin() as connection:
            connection.execute(sa.text(seed_sql))
    finally:
        engine.dispose()
    return _catalog_and_data_snapshot()


@pytest.mark.parametrize(
    ("seed_sql", "detail_fragment"),
    (
        (
            """
            CREATE FUNCTION public.acgs_unowned_probe()
            RETURNS integer
            LANGUAGE sql
            AS $$ SELECT 1 $$;
            """,
            "function:public.acgs_unowned_probe()",
        ),
        (
            """
            CREATE PROCEDURE public.acgs_unowned_procedure()
            LANGUAGE sql
            AS $$ SELECT 1 $$;
            """,
            "procedure:public.acgs_unowned_procedure()",
        ),
        (
            "CREATE SEQUENCE public.acgs_unowned_sequence",
            "sequence:public.acgs_unowned_sequence",
        ),
        (
            """
            CREATE SEQUENCE public.acgs_owned_late_sequence;
            ALTER SEQUENCE public.acgs_owned_late_sequence OWNED BY public.organizations.id;
            """,
            "sequence:public.acgs_owned_late_sequence",
        ),
        (
            "CREATE TYPE public.acgs_unowned_enum AS ENUM ('one', 'two')",
            "enum:public.acgs_unowned_enum",
        ),
        (
            "CREATE DOMAIN public.acgs_unowned_domain AS text CHECK (VALUE <> '')",
            "domain:public.acgs_unowned_domain",
        ),
        (
            "CREATE TYPE public.acgs_unowned_composite AS (value text)",
            "composite_type:public.acgs_unowned_composite",
        ),
        (
            """
            CREATE RULE acgs_unowned_rewrite AS
            ON UPDATE TO public.organizations
            DO ALSO NOTHING;
            """,
            "rewrite_rule:public.organizations.acgs_unowned_rewrite",
        ),
    ),
)
def test_revision_unowned_public_objects_are_unknown_without_guarded_side_effects(
    seed_sql: str,
    detail_fragment: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before_refusal = _seed_unsupported_public_object(seed_sql)
    test_url = _postgres_url()

    malformed = inspect_schema(test_url)
    assert malformed.state is DatabaseSchemaState.UNKNOWN
    assert detail_fragment in malformed.detail

    with pytest.raises(MigrationPreflightError, match="unexpected non-table schema objects"):
        upgrade_database(test_url)
    assert _catalog_and_data_snapshot() == before_refusal

    observed_engine = make_engine(test_url)
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

    def forbidden_session_factory(_engine: object) -> object:
        raise AssertionError("startup reached session-factory creation")

    monkeypatch.setattr(app_module, "make_engine", lambda _url: observed_engine)
    monkeypatch.setattr(app_module, "make_session_factory", forbidden_session_factory)
    audit_dir = tmp_path / "audit"
    with pytest.raises(StartupSchemaPreflightError) as stopped:
        create_app(
            Settings(
                database_url=test_url,
                audit_dir=audit_dir,
                create_tables=False,
                runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
            )
        )

    assert stopped.value.schema_state is DatabaseSchemaState.UNKNOWN
    assert statements
    assert _catalog_and_data_snapshot() == before_refusal
    assert not audit_dir.exists()


def test_owned_postgresql_table_sequences_are_not_part_of_current_revisions() -> None:
    test_url = _postgres_url()
    result = upgrade_database(test_url)
    assert result.after.state is DatabaseSchemaState.VERSION_0008

    engine = make_engine(test_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    """
                    CREATE TABLE public.acgs_owned_artifact_probe (
                        id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                        serial_value serial NOT NULL
                    )
                    """
                )
            )
            non_table_detail = migration_module._non_table_object_detail(connection)
            assert non_table_detail is not None
            assert "sequence:public.acgs_owned_artifact_probe_id_seq" in non_table_detail
            assert "sequence:public.acgs_owned_artifact_probe_serial_value_seq" in (
                non_table_detail
            )
    finally:
        engine.dispose()

    malformed = inspect_schema(test_url)
    assert malformed.state is DatabaseSchemaState.UNKNOWN
    assert "sequence:public.acgs_owned_artifact_probe_id_seq" in malformed.detail
    assert "sequence:public.acgs_owned_artifact_probe_serial_value_seq" in malformed.detail


def test_catalog_snapshot_captures_public_non_table_objects_for_side_effect_checks() -> None:
    before = _seed_unsupported_public_object(
        """
        CREATE FUNCTION public.acgs_snapshot_probe()
        RETURNS integer
        LANGUAGE sql
        AS $$ SELECT 1 $$;
        """
    )
    engine = make_engine(_postgres_url())
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("DROP FUNCTION public.acgs_snapshot_probe()"))
    finally:
        engine.dispose()
    assert _catalog_and_data_snapshot() != before


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
    assert result.after.state is DatabaseSchemaState.VERSION_0008
    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.VERSION_0008

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

            reflected_environment_foreign_keys = inspector.get_foreign_keys(
                "environments", schema="public"
            )
            assert all(
                foreign_key.get("referred_schema") in (None, "public")
                for foreign_key in reflected_environment_foreign_keys
            )
            environment_foreign_keys = {
                (
                    tuple(foreign_key["constrained_columns"]),
                    foreign_key["referred_table"],
                    tuple(foreign_key["referred_columns"]),
                )
                for foreign_key in reflected_environment_foreign_keys
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


@pytest.mark.parametrize(
    ("table_name", "constraint_name", "weakened_check"),
    [
        (
            "managed_decision_receipts",
            "ck_mdr_assurance_native",
            "(assurance_class='native')::boolean OR TRUE",
        ),
        (
            "managed_decision_receipts",
            "ck_mdr_source_gove_zone",
            "(source_system='gove-zone')::boolean AND FALSE",
        ),
        (
            "managed_mutation_attempts",
            "ck_mma_terminal_status",
            "(status IN ('in_progress', 'succeeded', 'failed'))::boolean OR TRUE",
        ),
    ],
)
def test_postgresql_casted_boolean_check_widening_is_unknown(
    table_name: str,
    constraint_name: str,
    weakened_check: str,
) -> None:
    result = upgrade_database(_TEST_POSTGRES_URL)
    assert result.after.state is DatabaseSchemaState.VERSION_0008

    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(f"ALTER TABLE {table_name} DROP CONSTRAINT {constraint_name}")
            )
            connection.execute(
                sa.text(
                    f"ALTER TABLE {table_name} "
                    f"ADD CONSTRAINT {constraint_name} CHECK ({weakened_check})"
                )
            )
    finally:
        engine.dispose()

    malformed = inspect_schema(_TEST_POSTGRES_URL)
    assert malformed.state is DatabaseSchemaState.UNKNOWN
    assert malformed.detail == f"{table_name} has unexpected check constraints"


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

    assert result.after.state is DatabaseSchemaState.VERSION_0008


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
    assert result.after.state is DatabaseSchemaState.VERSION_0008


def test_raw_postgresql_alembic_commands_reject_before_schema_or_version_mutation() -> None:
    with pytest.raises(MigrationPreflightError, match="Refusing a raw Alembic operation"):
        command.upgrade(migration_config(_TEST_POSTGRES_URL), "head")
    with pytest.raises(MigrationPreflightError, match="Refusing a raw Alembic operation"):
        command.stamp(migration_config(_TEST_POSTGRES_URL), LEGACY_V0_REVISION)

    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.EMPTY
    assert _table_names() == set()


def test_shadow_schema_foreign_key_is_unknown_and_cannot_stamp_migrate_or_serve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A same-named parent outside ``public`` must never satisfy the frozen contract."""
    cleanup_engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with cleanup_engine.begin() as connection:
            connection.execute(sa.text("DROP SCHEMA IF EXISTS shadow CASCADE"))
    finally:
        cleanup_engine.dispose()

    result = upgrade_database(_TEST_POSTGRES_URL)
    assert result.after.state is DatabaseSchemaState.VERSION_0008

    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("CREATE SCHEMA shadow"))
            connection.execute(
                sa.text("CREATE TABLE shadow.organizations (id VARCHAR(64) PRIMARY KEY)")
            )
            connection.execute(sa.text("ALTER TABLE users DROP CONSTRAINT users_org_id_fkey"))
            connection.execute(
                sa.text(
                    "ALTER TABLE users ADD CONSTRAINT users_org_id_fkey "
                    "FOREIGN KEY (org_id) REFERENCES shadow.organizations (id)"
                )
            )
    finally:
        engine.dispose()

    malformed = inspect_schema(_TEST_POSTGRES_URL)
    assert malformed.state is DatabaseSchemaState.UNKNOWN
    assert malformed.detail == "users has unexpected foreign keys"
    before = _catalog_and_data_snapshot()

    with pytest.raises(MigrationPreflightError, match="users has unexpected foreign keys"):
        upgrade_database(_TEST_POSTGRES_URL)
    with pytest.raises(MigrationPreflightError, match="Refusing a raw Alembic operation"):
        command.stamp(migration_config(_TEST_POSTGRES_URL), HEAD_REVISION)

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

    assert stopped.value.schema_state is DatabaseSchemaState.UNKNOWN
    assert statements
    assert _catalog_and_data_snapshot() == before
    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.UNKNOWN
    assert not audit_dir.exists()

    cleanup_engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with cleanup_engine.begin() as connection:
            connection.execute(sa.text("DROP SCHEMA shadow CASCADE"))
    finally:
        cleanup_engine.dispose()


def test_application_refuses_shadow_first_search_path_before_serving_or_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A complete same-name shadow schema must not become the runtime schema."""
    cleanup_engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with cleanup_engine.begin() as connection:
            connection.execute(sa.text("DROP SCHEMA IF EXISTS shadow CASCADE"))
    finally:
        cleanup_engine.dispose()

    result = upgrade_database(_TEST_POSTGRES_URL)
    assert result.after.state is DatabaseSchemaState.VERSION_0008
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("CREATE SCHEMA shadow"))
            table_names = sa.inspect(connection).get_table_names(schema="public")
            for table_name in table_names:
                connection.execute(
                    sa.text(
                        f'CREATE TABLE shadow."{table_name}" '
                        f'(LIKE public."{table_name}" INCLUDING ALL)'
                    )
                )
            connection.execute(
                sa.text("INSERT INTO shadow.alembic_version (version_num) VALUES (:revision)"),
                {"revision": HEAD_REVISION},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO shadow.organizations "
                    "(id, name, created_at, audit_anchor_count, audit_anchor_hash) "
                    "VALUES ('shadow-org', 'Shadow Organization', now(), 0, '')"
                )
            )
            connection.execute(sa.text("CREATE TABLE shadow.sentinel (id INTEGER PRIMARY KEY)"))
            connection.execute(sa.text("INSERT INTO shadow.sentinel (id) VALUES (11)"))
            connection.execute(
                sa.text(
                    """
                    CREATE FUNCTION shadow.current_schema()
                    RETURNS name LANGUAGE plpgsql AS $function$
                    BEGIN
                        UPDATE shadow.sentinel SET id = 12 WHERE id = 11;
                        RETURN 'shadow';
                    END
                    $function$
                    """
                )
            )
            connection.execute(
                sa.text(
                    """
                    CREATE FUNCTION shadow.current_database()
                    RETURNS name LANGUAGE plpgsql AS $function$
                    BEGIN
                        UPDATE shadow.sentinel SET id = 13 WHERE id = 11;
                        RETURN 'shadow_database';
                    END
                    $function$
                    """
                )
            )
    finally:
        engine.dispose()

    before = _catalog_and_data_snapshot()
    hostile_url = f"{_TEST_POSTGRES_URL}?options=-csearch_path%3Dshadow%2Cpg_catalog%2Cpublic"
    assert inspect_schema(hostile_url).state is DatabaseSchemaState.VERSION_0008
    session_factory_calls = {"count": 0}

    def forbidden_session_factory(_engine: object) -> object:
        session_factory_calls["count"] += 1
        raise AssertionError("shadow-first startup reached session-factory creation")

    monkeypatch.setattr(app_module, "make_session_factory", forbidden_session_factory)

    with pytest.raises(
        DatabaseSchemaBindingMismatch,
        match="canonical public schema",
    ):
        app = create_app(
            Settings(
                database_url=hostile_url,
                audit_dir=tmp_path / "audit",
                create_tables=False,
                runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
            )
        )
        app.state.engine.dispose()

    assert _catalog_and_data_snapshot() == before
    check_engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with check_engine.connect() as connection:
            assert connection.scalar(sa.text("SELECT id FROM shadow.sentinel")) == 11
            assert connection.scalar(sa.text("SELECT count(*) FROM shadow.organizations")) == 1
    finally:
        check_engine.dispose()
    assert session_factory_calls == {"count": 0}
    assert not (tmp_path / "audit").exists()

    cleanup_engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with cleanup_engine.begin() as connection:
            connection.execute(sa.text("DROP SCHEMA shadow CASCADE"))
    finally:
        cleanup_engine.dispose()


def test_application_pins_every_accepted_pool_connection_to_public(tmp_path: Path) -> None:
    result = upgrade_database(_TEST_POSTGRES_URL)
    assert result.after.state is DatabaseSchemaState.VERSION_0008
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("CREATE SCHEMA shadow"))
    finally:
        engine.dispose()

    public_first_url = f"{_TEST_POSTGRES_URL}?options=-csearch_path%3Dpublic%2Cshadow%2Cpg_catalog"
    app = create_app(
        Settings(
            database_url=public_first_url,
            audit_dir=tmp_path / "audit",
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        )
    )
    try:
        for _ in range(2):
            with app.state.engine.connect() as connection:
                assert (
                    connection.scalar(sa.text("SELECT pg_catalog.current_database()"))
                    == _DISPOSABLE_DATABASE_NAME
                )
                assert connection.scalar(sa.text("SELECT pg_catalog.current_schema()")) == "public"
                assert (
                    connection.scalar(sa.text("SELECT pg_catalog.current_setting('search_path')"))
                    == "public"
                )
            app.state.engine.dispose()
    finally:
        app.state.engine.dispose()

    cleanup_engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with cleanup_engine.begin() as connection:
            connection.execute(sa.text("DROP SCHEMA shadow CASCADE"))
    finally:
        cleanup_engine.dispose()


_WORKER_SCRIPT = Path(__file__).with_name("_postgresql_migration_worker.py")
_WORKER_EVENT_TIMEOUT_SECONDS = 15.0
_WORKER_EXIT_TIMEOUT_SECONDS = 15.0
_WORKER_TERMINATE_TIMEOUT_SECONDS = 3.0
_WORKER_THREAD_CLEANUP_GRACE_SECONDS = 1.0
_WORKER_READER_QUEUE_CAPACITY = 64
_WORKER_OUTPUT_MAX_BYTES = 256 * 1024
_WORKER_LINE_MAX_BYTES = 64 * 1024
_WORKER_READ_CHUNK_CHARS = 4096
_SENSITIVE_WORKER_VALUES = tuple(
    value
    for value in (
        _TEST_POSTGRES_URL,
        _TEST_URL.password if _TEST_URL is not None else None,
    )
    if isinstance(value, str) and value
)


@dataclass(frozen=True)
class _ReaderMessage:
    kind: Literal["line", "violation", "overflow", "error", "eof"]
    line: str = ""
    error: BaseException | None = None


class _ReadableTextStream(Protocol):
    def readline(self, size: int = -1, /) -> str: ...

    def close(self) -> None: ...


class _WorkerOutputOverflow(RuntimeError):
    """A worker stream exceeded its bounded diagnostic storage."""


class _WorkerSecretExposure(AssertionError):
    """A configured sensitive value appeared in a worker stream."""


@dataclass
class _MigrationWorker:
    process: subprocess.Popen[str]
    stdout_text: str = ""
    stderr_text: str = ""
    drained: bool = False
    events: list[dict[str, object]] = field(default_factory=list)
    stdout_messages: Queue[_ReaderMessage] = field(
        default_factory=lambda: Queue(maxsize=_WORKER_READER_QUEUE_CAPACITY)
    )
    stderr_messages: Queue[_ReaderMessage] = field(
        default_factory=lambda: Queue(maxsize=_WORKER_READER_QUEUE_CAPACITY)
    )
    stdout_reader: Thread | None = None
    stderr_reader: Thread | None = None
    stdout_collector: Thread | None = None
    stderr_collector: Thread | None = None
    stdout_stream: _ReadableTextStream | None = None
    stderr_stream: _ReadableTextStream | None = None
    stdout_condition: Condition = field(default_factory=Condition)
    stdout_pending: deque[_ReaderMessage] = field(default_factory=deque)
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    stdout_terminal: bool = False
    stderr_terminal: bool = False
    stdout_failure: BaseException | None = None
    stderr_failure: BaseException | None = None


def _assert_secret_free(value: str) -> None:
    for sensitive_value in _SENSITIVE_WORKER_VALUES:
        if sensitive_value in value:
            raise _WorkerSecretExposure(
                "worker argv or output contained a configured sensitive value"
            )


def _assert_worker_secret_safe(worker: _MigrationWorker) -> None:
    args = worker.process.args
    if isinstance(args, (str, bytes, os.PathLike)):
        argv = os.fsdecode(args)
    else:
        argv = " ".join(os.fsdecode(argument) for argument in args)
    _assert_secret_free(argv)
    _assert_secret_free(worker.stdout_text)
    _assert_secret_free(worker.stderr_text)


def _read_stream(stream: _ReadableTextStream, messages: Queue[_ReaderMessage]) -> None:
    retained_parts: list[str] = []
    retained_bytes = 0
    discarding_overlong_line = False
    overlap_limit = max((len(value) for value in _SENSITIVE_WORKER_VALUES), default=1) - 1
    scan_overlap = ""
    secret_failure_reported = False
    try:
        while True:
            chunk = stream.readline(_WORKER_READ_CHUNK_CHARS)
            if not chunk:
                if retained_parts and not discarding_overlong_line:
                    messages.put(_ReaderMessage(kind="line", line="".join(retained_parts)))
                messages.put(_ReaderMessage(kind="eof"))
                return
            scan_window = scan_overlap + chunk
            try:
                _assert_secret_free(scan_window)
            except _WorkerSecretExposure as exc:
                if not secret_failure_reported:
                    messages.put(_ReaderMessage(kind="violation", error=exc))
                    secret_failure_reported = True
            scan_overlap = scan_window[-overlap_limit:] if overlap_limit else ""

            ends_line = chunk.endswith("\n")
            if discarding_overlong_line:
                if ends_line:
                    discarding_overlong_line = False
                continue

            chunk_bytes = len(chunk.encode("utf-8"))
            if retained_bytes + chunk_bytes > _WORKER_LINE_MAX_BYTES:
                retained_parts.clear()
                retained_bytes = 0
                messages.put(
                    _ReaderMessage(
                        kind="overflow",
                        error=_WorkerOutputOverflow(
                            f"worker line exceeded {_WORKER_LINE_MAX_BYTES} byte limit"
                        ),
                    )
                )
                discarding_overlong_line = not ends_line
                continue

            retained_parts.append(chunk)
            retained_bytes += chunk_bytes
            if ends_line:
                messages.put(_ReaderMessage(kind="line", line="".join(retained_parts)))
                retained_parts.clear()
                retained_bytes = 0
    except Exception as exc:
        messages.put(_ReaderMessage(kind="error", error=exc))


def _set_stream_failure(
    worker: _MigrationWorker,
    *,
    stream_name: Literal["stdout", "stderr"],
    error: BaseException,
) -> None:
    attribute = f"{stream_name}_failure"
    current_error = getattr(worker, attribute)
    should_replace = current_error is None or (
        isinstance(current_error, _WorkerOutputOverflow)
        and isinstance(error, _WorkerSecretExposure)
    )
    if should_replace:
        setattr(worker, attribute, error)
        if stream_name == "stdout":
            with worker.stdout_condition:
                worker.stdout_condition.notify_all()


def _collect_stream(
    worker: _MigrationWorker,
    messages: Queue[_ReaderMessage],
    *,
    stream_name: Literal["stdout", "stderr"],
) -> None:
    while True:
        message = messages.get()
        if message.kind == "line":
            line = message.line
            safe_to_store = True
            try:
                _assert_secret_free(line)
            except Exception as exc:
                safe_to_store = False
                _set_stream_failure(worker, stream_name=stream_name, error=exc)

            encoded_size = len(line.encode("utf-8"))
            bytes_attribute = f"{stream_name}_bytes"
            new_size = int(getattr(worker, bytes_attribute)) + encoded_size
            setattr(worker, bytes_attribute, new_size)
            if new_size > _WORKER_OUTPUT_MAX_BYTES:
                _set_stream_failure(
                    worker,
                    stream_name=stream_name,
                    error=_WorkerOutputOverflow(
                        f"worker {stream_name} exceeded {_WORKER_OUTPUT_MAX_BYTES} byte limit"
                    ),
                )
            elif safe_to_store:
                text_attribute = f"{stream_name}_text"
                setattr(worker, text_attribute, str(getattr(worker, text_attribute)) + line)
                if stream_name == "stdout":
                    with worker.stdout_condition:
                        worker.stdout_pending.append(message)
                        worker.stdout_condition.notify_all()
            continue

        if message.kind == "overflow":
            error = message.error or _WorkerOutputOverflow("worker stream overflowed")
            _set_stream_failure(worker, stream_name=stream_name, error=error)
            continue

        if message.kind == "violation":
            error = message.error or _WorkerSecretExposure("worker stream exposed a secret")
            _set_stream_failure(worker, stream_name=stream_name, error=error)
            continue

        if message.kind == "error":
            error = message.error or RuntimeError(f"worker {stream_name} reader failed")
            _set_stream_failure(worker, stream_name=stream_name, error=error)
        setattr(worker, f"{stream_name}_terminal", True)
        if stream_name == "stdout":
            with worker.stdout_condition:
                worker.stdout_condition.notify_all()
        return


def _start_stream_reader(
    stream: _ReadableTextStream,
    messages: Queue[_ReaderMessage],
    *,
    name: str,
) -> Thread:
    reader = Thread(target=_read_stream, args=(stream, messages), name=name, daemon=True)
    reader.start()
    return reader


def _start_stream_collector(
    worker: _MigrationWorker,
    messages: Queue[_ReaderMessage],
    *,
    stream_name: Literal["stdout", "stderr"],
) -> Thread:
    collector = Thread(
        target=_collect_stream,
        args=(worker, messages),
        kwargs={"stream_name": stream_name},
        name=f"acgs-migration-{stream_name}-collector-{worker.process.pid}",
        daemon=True,
    )
    collector.start()
    return collector


def _start_worker_streams(
    worker: _MigrationWorker,
    *,
    stdout_stream: _ReadableTextStream | None = None,
    stderr_stream: _ReadableTextStream | None = None,
) -> None:
    process = worker.process
    if stdout_stream is None:
        assert process.stdout is not None
        stdout_stream = process.stdout
    if stderr_stream is None:
        assert process.stderr is not None
        stderr_stream = process.stderr
    worker.stdout_stream = stdout_stream
    worker.stderr_stream = stderr_stream
    worker.stdout_collector = _start_stream_collector(
        worker,
        worker.stdout_messages,
        stream_name="stdout",
    )
    worker.stderr_collector = _start_stream_collector(
        worker,
        worker.stderr_messages,
        stream_name="stderr",
    )
    worker.stdout_reader = _start_stream_reader(
        stdout_stream,
        worker.stdout_messages,
        name=f"acgs-migration-stdout-{process.pid}",
    )
    worker.stderr_reader = _start_stream_reader(
        stderr_stream,
        worker.stderr_messages,
        name=f"acgs-migration-stderr-{process.pid}",
    )


def _launch_migration_worker(workers: list[_MigrationWorker], mode: str) -> _MigrationWorker:
    environment = os.environ.copy()
    assert _TEST_POSTGRES_URL is not None
    environment["ACP_TEST_POSTGRES_URL"] = _TEST_POSTGRES_URL
    process = subprocess.Popen(
        [sys.executable, str(_WORKER_SCRIPT), mode],
        cwd=_WORKER_SCRIPT.parents[1],
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        bufsize=1,
        start_new_session=sys.platform != "win32",
    )
    worker = _MigrationWorker(process=process)
    _start_worker_streams(worker)
    workers.append(worker)
    _assert_worker_secret_safe(worker)
    return worker


def _read_worker_event(
    worker: _MigrationWorker, timeout: float = _WORKER_EVENT_TIMEOUT_SECONDS
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    with worker.stdout_condition:
        while (
            not worker.stdout_pending
            and not worker.stdout_terminal
            and worker.stdout_failure is None
        ):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(
                    f"worker event timed out with return code {worker.process.poll()}"
                )
            worker.stdout_condition.wait(timeout=remaining)
        if worker.stdout_failure is not None:
            error = worker.stdout_failure
            raise AssertionError(
                f"worker stdout collection failed with {type(error).__name__}"
            ) from error
        if not worker.stdout_pending:
            raise AssertionError(f"worker closed stdout with return code {worker.process.poll()}")
        line = worker.stdout_pending.popleft().line

    event = json.loads(line)
    assert isinstance(event, dict)
    worker.events.append(event)
    return event


def _join_stream_threads(
    worker: _MigrationWorker,
    *,
    stream_name: Literal["stdout", "stderr"],
    deadline: float,
) -> None:
    reader = worker.stdout_reader if stream_name == "stdout" else worker.stderr_reader
    collector = worker.stdout_collector if stream_name == "stdout" else worker.stderr_collector
    assert reader is not None
    assert collector is not None

    collector.join(timeout=max(0.0, deadline - time.monotonic()))
    stream_failure = getattr(worker, f"{stream_name}_failure")
    needs_forced_unblock = (
        collector.is_alive()
        or stream_failure is not None
        or not bool(getattr(worker, f"{stream_name}_terminal"))
    )
    if collector.is_alive():
        _set_stream_failure(
            worker,
            stream_name=stream_name,
            error=TimeoutError(f"worker {stream_name} collector did not reach EOF before deadline"),
        )
    elif not bool(getattr(worker, f"{stream_name}_terminal")):
        _set_stream_failure(
            worker,
            stream_name=stream_name,
            error=RuntimeError(f"worker {stream_name} collector exited without EOF/error"),
        )

    if needs_forced_unblock:
        stream = worker.stdout_stream if stream_name == "stdout" else worker.stderr_stream
        if stream is not None:
            try:
                stream.close()
            except Exception as exc:
                _set_stream_failure(worker, stream_name=stream_name, error=exc)
        cleanup_deadline = time.monotonic() + _WORKER_THREAD_CLEANUP_GRACE_SECONDS
    else:
        cleanup_deadline = deadline

    reader.join(timeout=max(0.0, cleanup_deadline - time.monotonic()))
    collector.join(timeout=max(0.0, cleanup_deadline - time.monotonic()))
    if reader.is_alive():
        _set_stream_failure(
            worker,
            stream_name=stream_name,
            error=TimeoutError(f"worker {stream_name} reader did not terminate before deadline"),
        )
    if collector.is_alive():
        _set_stream_failure(
            worker,
            stream_name=stream_name,
            error=TimeoutError(f"worker {stream_name} collector did not terminate after unblock"),
        )


def _raise_stream_failures(worker: _MigrationWorker) -> None:
    failures = [
        ("stdout", worker.stdout_failure),
        ("stderr", worker.stderr_failure),
    ]
    for stream_name, error in failures:
        if error is not None:
            raise AssertionError(
                f"worker {stream_name} collection failed with {type(error).__name__}"
            ) from error


def _close_owned_streams(worker: _MigrationWorker) -> None:
    for stream_name in ("stdout", "stderr"):
        stream = worker.stdout_stream if stream_name == "stdout" else worker.stderr_stream
        if stream is None:
            continue
        try:
            stream.close()
        except Exception as exc:
            if stream_name == "stdout":
                _set_stream_failure(worker, stream_name="stdout", error=exc)
            else:
                _set_stream_failure(worker, stream_name="stderr", error=exc)


def _drain_worker(worker: _MigrationWorker, *, deadline: float | None = None) -> None:
    if worker.drained:
        return
    assert worker.process.poll() is not None, "worker output may only be drained after exit"
    if deadline is None:
        deadline = time.monotonic() + _WORKER_TERMINATE_TIMEOUT_SECONDS
    _join_stream_threads(worker, stream_name="stdout", deadline=deadline)
    _join_stream_threads(worker, stream_name="stderr", deadline=deadline)
    threads = (
        worker.stdout_reader,
        worker.stderr_reader,
        worker.stdout_collector,
        worker.stderr_collector,
    )
    if (
        worker.stdout_failure is not None
        or worker.stderr_failure is not None
        or any(thread is None or thread.is_alive() for thread in threads)
    ):
        _close_owned_streams(worker)
        cleanup_deadline = time.monotonic() + _WORKER_THREAD_CLEANUP_GRACE_SECONDS
        for thread in threads:
            if thread is not None:
                thread.join(timeout=max(0.0, cleanup_deadline - time.monotonic()))
    if any(thread is None or thread.is_alive() for thread in threads):
        raise AssertionError("worker stream cleanup left a reader or collector thread alive")
    worker.drained = True
    _assert_worker_secret_safe(worker)
    _raise_stream_failures(worker)


def _stop_worker(worker: _MigrationWorker) -> None:
    process = worker.process
    deadline = time.monotonic() + _WORKER_TERMINATE_TIMEOUT_SECONDS
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=min(1.0, max(0.0, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
    stdin = process.stdin
    if stdin is not None and not stdin.closed:
        stdin.close()
    _drain_worker(worker, deadline=deadline)


def _wait_worker(worker: _MigrationWorker, timeout: float = _WORKER_EXIT_TIMEOUT_SECONDS) -> int:
    try:
        return_code = worker.process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _stop_worker(worker)
        raise AssertionError("migration worker did not exit within its bounded timeout") from None
    _drain_worker(worker)
    return return_code


def _release_worker(worker: _MigrationWorker) -> None:
    stdin = worker.process.stdin
    assert stdin is not None
    stdin.write("release\n")
    stdin.flush()


@pytest.fixture
def migration_workers() -> Iterator[list[_MigrationWorker]]:
    workers: list[_MigrationWorker] = []
    try:
        yield workers
    finally:
        for worker in workers:
            _stop_worker(worker)


def _observe_migration_lock() -> tuple[int, set[int]]:
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.connect() as connection:
            _assert_disposable_database(connection)
            observer_pid = connection.scalar(sa.text("SELECT pg_backend_pid()"))
            assert isinstance(observer_pid, int)
            lock_pids = {
                int(pid)
                for pid in connection.execute(
                    sa.text(
                        """
                        SELECT pid
                        FROM pg_catalog.pg_locks
                        WHERE locktype = 'advisory'
                          AND database = (
                              SELECT oid FROM pg_catalog.pg_database
                              WHERE datname = current_database()
                          )
                          AND classid::bigint = :class_id
                          AND objid::bigint = :object_id
                          AND objsubid = 2
                          AND granted
                        """
                    ),
                    _LOCK_PARAMETERS,
                ).scalars()
            }
            return observer_pid, lock_pids
    finally:
        engine.dispose()


def _backend_is_active(backend_pid: int) -> bool:
    engine = make_engine(_TEST_POSTGRES_URL)
    try:
        with engine.connect() as connection:
            _assert_disposable_database(connection)
            return bool(
                connection.scalar(
                    sa.text(
                        "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity "
                        "WHERE pid = :backend_pid)"
                    ),
                    {"backend_pid": backend_pid},
                )
            )
    finally:
        engine.dispose()


def _wait_for_backend_and_lock_release(backend_pid: int) -> None:
    deadline = time.monotonic() + _WORKER_EXIT_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        _, lock_pids = _observe_migration_lock()
        if backend_pid not in lock_pids and not _backend_is_active(backend_pid):
            return
        time.sleep(0.05)
    raise AssertionError("PostgreSQL backend or advisory lock outlived the bounded wait")


def _assert_ready_event(worker: _MigrationWorker, event: dict[str, object], stage: str) -> int:
    assert event["event"] == "ready"
    assert event["stage"] == stage
    assert event["os_pid"] == worker.process.pid
    backend_pid = event["backend_pid"]
    assert isinstance(backend_pid, int)
    assert backend_pid > 0
    _assert_worker_secret_safe(worker)
    return backend_pid


def _assert_success_event(worker: _MigrationWorker, event: dict[str, object]) -> int:
    assert event == {
        "event": "result",
        "status": "success",
        "mode": "ordinary",
        "os_pid": worker.process.pid,
        "backend_pid": event["backend_pid"],
        "before": DatabaseSchemaState.EMPTY.value,
        "after": DatabaseSchemaState.VERSION_0008.value,
    }
    backend_pid = event["backend_pid"]
    assert isinstance(backend_pid, int)
    return backend_pid


class _FailingStream:
    def readline(self, _limit: int = -1) -> str:
        raise OSError("synthetic reader failure")

    def close(self) -> None:
        pass


class _BlockingStream:
    def __init__(self) -> None:
        self.release = Event()
        self.closed = False

    def readline(self, _limit: int = -1) -> str:
        self.release.wait()
        return ""

    def close(self) -> None:
        self.closed = True
        self.release.set()


def _assert_forced_termination_return_code(return_code: int, *, platform: str) -> None:
    if platform == "win32":
        assert return_code != 0, "Windows forced termination must produce a nonzero exit"
        return
    assert return_code == -signal.SIGKILL, "POSIX kill() must prove actual SIGKILL delivery"


def _protocol_worker(command: str) -> _MigrationWorker:
    process = subprocess.Popen(
        [sys.executable, "-c", command],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    worker = _MigrationWorker(process=process)
    _start_worker_streams(worker)
    return worker


def _assert_worker_threads_stopped(worker: _MigrationWorker) -> None:
    threads = (
        worker.stdout_reader,
        worker.stderr_reader,
        worker.stdout_collector,
        worker.stderr_collector,
    )
    assert all(thread is not None and not thread.is_alive() for thread in threads)


def test_worker_reader_protocol_reports_line_error_eof_and_timeout_without_thread_leaks(
    worker_protocol_only: None,
) -> None:
    line_messages: Queue[_ReaderMessage] = Queue(maxsize=_WORKER_READER_QUEUE_CAPACITY)
    line_reader = _start_stream_reader(
        io.StringIO("event-line\n"),
        line_messages,
        name="acgs-reader-test-line",
    )
    assert line_messages.get(timeout=1.0) == _ReaderMessage(kind="line", line="event-line\n")
    assert line_messages.get(timeout=1.0) == _ReaderMessage(kind="eof")
    line_reader.join(timeout=1.0)
    assert not line_reader.is_alive()

    error_messages: Queue[_ReaderMessage] = Queue(maxsize=_WORKER_READER_QUEUE_CAPACITY)
    error_reader = _start_stream_reader(
        _FailingStream(),
        error_messages,
        name="acgs-reader-test-error",
    )
    error_message = error_messages.get(timeout=1.0)
    assert error_message.kind == "error"
    assert isinstance(error_message.error, OSError)
    error_reader.join(timeout=1.0)
    assert not error_reader.is_alive()

    blocking_stream = _BlockingStream()
    timeout_messages: Queue[_ReaderMessage] = Queue(maxsize=_WORKER_READER_QUEUE_CAPACITY)
    timeout_reader = _start_stream_reader(
        blocking_stream,
        timeout_messages,
        name="acgs-reader-test-timeout",
    )
    with pytest.raises(Empty):
        timeout_messages.get(timeout=0.01)
    blocking_stream.release.set()
    assert timeout_messages.get(timeout=1.0) == _ReaderMessage(kind="eof")
    timeout_reader.join(timeout=1.0)
    assert not timeout_reader.is_alive()


def test_worker_event_reader_propagates_explicit_error_and_eof_messages(
    worker_protocol_only: None,
) -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", "pass"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert process.wait(timeout=3.0) == 0
    worker = _MigrationWorker(process=process)

    reader_error = OSError("synthetic stdout reader failure")
    _set_stream_failure(worker, stream_name="stdout", error=reader_error)
    with pytest.raises(AssertionError, match="stdout collection failed with OSError") as caught:
        _read_worker_event(worker, timeout=0.01)
    assert caught.value.__cause__ is reader_error

    worker.stdout_failure = None
    worker.stdout_terminal = True
    with pytest.raises(AssertionError, match="worker closed stdout with return code 0"):
        _read_worker_event(worker, timeout=0.01)


def test_worker_collectors_drain_more_than_queue_capacity_without_deadlock(
    worker_protocol_only: None,
) -> None:
    line_count = _WORKER_READER_QUEUE_CAPACITY + 16
    worker = _protocol_worker(
        "import sys; "
        f"[(print(f'out-{{i}}', flush=True), print(f'err-{{i}}', file=sys.stderr, flush=True)) "
        f"for i in range({line_count})]"
    )
    assert _wait_worker(worker, timeout=5.0) == 0
    assert worker.stdout_text.count("\n") == line_count
    assert worker.stderr_text.count("\n") == line_count
    assert f"out-{line_count - 1}\n" in worker.stdout_text
    assert f"err-{line_count - 1}\n" in worker.stderr_text
    assert worker.drained
    _assert_worker_threads_stopped(worker)
    _drain_worker(worker)


@pytest.mark.parametrize("stream_name", ["stdout", "stderr"])
def test_worker_collectors_scan_secret_after_queue_capacity_and_leave_no_threads(
    worker_protocol_only: None,
    monkeypatch: pytest.MonkeyPatch,
    stream_name: str,
) -> None:
    secret = "secret-after-capacity"
    monkeypatch.setattr(sys.modules[__name__], "_SENSITIVE_WORKER_VALUES", (secret,))
    line_count = _WORKER_READER_QUEUE_CAPACITY + 16
    destination = "sys.stdout" if stream_name == "stdout" else "sys.stderr"
    worker = _protocol_worker(
        "import sys; "
        f"[(print((('secret-' + 'after-capacity') if i == {line_count - 1} "
        "else f'clean-{i}'), "
        f"file={destination}, flush=True)) for i in range({line_count})]"
    )
    with pytest.raises(AssertionError, match=f"worker {stream_name} collection failed") as caught:
        _wait_worker(worker, timeout=5.0)
    assert caught.value.__cause__ is not None
    assert secret not in worker.stdout_text
    assert secret not in worker.stderr_text
    assert getattr(worker, f"{stream_name}_bytes") > len(secret)
    _assert_worker_threads_stopped(worker)


def test_worker_multimegabyte_newline_free_output_is_bounded_refused_and_leak_free(
    worker_protocol_only: None,
) -> None:
    output_size = 4 * 1024 * 1024
    worker = _protocol_worker(
        f"import sys; sys.stdout.write('x' * {output_size}); sys.stdout.flush()"
    )
    with pytest.raises(AssertionError, match="stdout collection failed with _WorkerOutputOverflow"):
        _wait_worker(worker, timeout=5.0)
    assert worker.stdout_text == ""
    assert worker.stdout_failure is not None
    assert "worker line exceeded" in str(worker.stdout_failure)
    _assert_worker_threads_stopped(worker)


def _assert_secret_exposure_refused_and_drained(
    worker: _MigrationWorker,
    *,
    stream_name: str,
    secret: str,
) -> None:
    with pytest.raises(
        AssertionError,
        match=f"worker {stream_name} collection failed with _WorkerSecretExposure",
    ) as caught:
        _wait_worker(worker, timeout=5.0)
    assert isinstance(caught.value.__cause__, _WorkerSecretExposure)
    assert secret not in worker.stdout_text
    assert secret not in worker.stderr_text
    assert worker.process.poll() is not None
    _assert_worker_threads_stopped(worker)


@pytest.mark.parametrize("stream_name", ["stdout", "stderr"])
def test_worker_secret_after_line_overflow_in_multimegabyte_stream_is_detected(
    worker_protocol_only: None,
    monkeypatch: pytest.MonkeyPatch,
    stream_name: str,
) -> None:
    secret = "late-secret-after-overflow"
    monkeypatch.setattr(sys.modules[__name__], "_SENSITIVE_WORKER_VALUES", (secret,))
    prefix_size = _WORKER_LINE_MAX_BYTES + (2 * _WORKER_READ_CHUNK_CHARS)
    suffix_size = (4 * 1024 * 1024) - prefix_size - len(secret)
    destination = "sys.stdout" if stream_name == "stdout" else "sys.stderr"
    worker = _protocol_worker(
        "import sys; "
        f"stream={destination}; "
        f"stream.write(('x' * {prefix_size}) + ('late-' + 'secret-after-overflow') + "
        f"('x' * {suffix_size})); stream.flush()"
    )

    _assert_secret_exposure_refused_and_drained(
        worker,
        stream_name=stream_name,
        secret=secret,
    )


@pytest.mark.parametrize("stream_name", ["stdout", "stderr"])
def test_worker_secret_split_at_read_chunk_boundary_is_detected(
    worker_protocol_only: None,
    monkeypatch: pytest.MonkeyPatch,
    stream_name: str,
) -> None:
    secret = "split-boundary-secret"
    split_at = len("split-")
    monkeypatch.setattr(sys.modules[__name__], "_SENSITIVE_WORKER_VALUES", (secret,))
    prefix_size = _WORKER_READ_CHUNK_CHARS - split_at
    suffix_size = (4 * 1024 * 1024) - prefix_size - len(secret)
    destination = "sys.stdout" if stream_name == "stdout" else "sys.stderr"
    worker = _protocol_worker(
        "import sys; "
        f"stream={destination}; "
        f"stream.write(('x' * {prefix_size}) + ('split-' + 'boundary-secret') + "
        f"('x' * {suffix_size})); stream.flush()"
    )

    _assert_secret_exposure_refused_and_drained(
        worker,
        stream_name=stream_name,
        secret=secret,
    )


def test_worker_total_output_overflow_is_explicit_bounded_and_leak_free(
    worker_protocol_only: None,
) -> None:
    line_count = 4096
    line = "x" * 100
    expected_bytes = line_count * (len(line) + 1)
    worker = _protocol_worker(
        f"[(print('x' * {len(line)}, flush=True)) for _ in range({line_count})]"
    )
    with pytest.raises(AssertionError, match="stdout collection failed with _WorkerOutputOverflow"):
        _wait_worker(worker, timeout=5.0)
    assert worker.stdout_bytes == expected_bytes
    assert len(worker.stdout_text.encode("utf-8")) <= _WORKER_OUTPUT_MAX_BYTES
    _assert_worker_threads_stopped(worker)


def _exited_worker_with_streams(
    stdout_stream: _ReadableTextStream,
    stderr_stream: _ReadableTextStream,
) -> _MigrationWorker:
    process = subprocess.Popen(
        [sys.executable, "-c", "pass"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert process.wait(timeout=3.0) == 0
    worker = _MigrationWorker(process=process)
    _start_worker_streams(
        worker,
        stdout_stream=stdout_stream,
        stderr_stream=stderr_stream,
    )
    return worker


def test_worker_cleanup_timeout_closes_blocking_streams_and_stops_all_threads(
    worker_protocol_only: None,
) -> None:
    stdout_stream = _BlockingStream()
    stderr_stream = _BlockingStream()
    worker = _exited_worker_with_streams(stdout_stream, stderr_stream)

    with pytest.raises(
        AssertionError, match="stdout collection failed with TimeoutError"
    ) as caught:
        _drain_worker(worker, deadline=time.monotonic() + 0.01)

    assert caught.value.__cause__ is not None
    assert "collector did not reach EOF before deadline" in str(caught.value.__cause__)
    assert stdout_stream.closed
    assert stderr_stream.closed
    _assert_worker_threads_stopped(worker)


def test_worker_cleanup_error_closes_other_blocking_stream_and_stops_all_threads(
    worker_protocol_only: None,
) -> None:
    stdout_stream = _FailingStream()
    stderr_stream = _BlockingStream()
    worker = _exited_worker_with_streams(stdout_stream, stderr_stream)

    with pytest.raises(AssertionError, match="stdout collection failed with OSError"):
        _drain_worker(worker, deadline=time.monotonic() + 0.01)

    assert stderr_stream.closed
    _assert_worker_threads_stopped(worker)


def test_worker_event_timeout_is_bounded_and_cleanup_leaves_no_reader_threads(
    worker_protocol_only: None,
) -> None:
    worker = _protocol_worker("import time; time.sleep(30)")
    try:
        with pytest.raises(AssertionError, match="worker event timed out"):
            _read_worker_event(worker, timeout=0.01)
    finally:
        _stop_worker(worker)
    _assert_worker_threads_stopped(worker)


def test_forced_termination_return_codes_keep_posix_and_windows_claims_distinct(
    worker_protocol_only: None,
) -> None:
    sigkill = getattr(signal, "SIGKILL", None)
    if sigkill is not None:
        _assert_forced_termination_return_code(-sigkill, platform="linux")
        with pytest.raises(AssertionError, match="actual SIGKILL"):
            _assert_forced_termination_return_code(1, platform="linux")
    _assert_forced_termination_return_code(1, platform="win32")
    with pytest.raises(AssertionError, match="nonzero exit"):
        _assert_forced_termination_return_code(0, platform="win32")


def test_postgresql_independent_process_lock_owner_rejects_contender_then_retries(
    migration_workers: list[_MigrationWorker],
) -> None:
    owner = _launch_migration_worker(migration_workers, "pause-before-upgrade")
    owner_ready = _read_worker_event(owner)
    owner_backend_pid = _assert_ready_event(owner, owner_ready, "after-lock-before-upgrade")

    observer_pid, lock_pids = _observe_migration_lock()
    assert lock_pids == {owner_backend_pid}
    assert observer_pid != owner_backend_pid

    contender = _launch_migration_worker(migration_workers, "ordinary")
    contender_result = _read_worker_event(contender)
    assert contender_result["event"] == "result"
    assert contender_result["status"] == "error"
    assert contender_result["error_type"] == MigrationLockUnavailable.__name__
    assert contender_result["os_pid"] == contender.process.pid
    contender_backend_pid = contender_result["backend_pid"]
    assert isinstance(contender_backend_pid, int)
    assert contender.process.pid != owner.process.pid
    assert contender_backend_pid not in {owner_backend_pid, observer_pid}
    assert _wait_worker(contender) == 3

    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.EMPTY
    assert _table_names() == set()
    _, lock_pids = _observe_migration_lock()
    assert lock_pids == {owner_backend_pid}

    _release_worker(owner)
    owner_result = _read_worker_event(owner)
    assert owner_result["event"] == "result"
    assert owner_result["status"] == "released"
    assert owner_result["backend_pid"] == owner_backend_pid
    assert _wait_worker(owner) == 0
    _wait_for_backend_and_lock_release(owner_backend_pid)

    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.EMPTY
    assert _table_names() == set()

    retry = _launch_migration_worker(migration_workers, "ordinary")
    retry_result = _read_worker_event(retry)
    retry_backend_pid = _assert_success_event(retry, retry_result)
    assert retry.process.pid not in {owner.process.pid, contender.process.pid}
    assert retry_backend_pid not in {
        owner_backend_pid,
        contender_backend_pid,
        observer_pid,
    }
    assert _wait_worker(retry) == 0
    _wait_for_backend_and_lock_release(retry_backend_pid)

    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.VERSION_0008
    assert all(worker.process.poll() is not None for worker in migration_workers)
    for worker in migration_workers:
        _assert_worker_secret_safe(worker)


def _exercise_forced_termination_rollback_and_lock_release(
    migration_workers: list[_MigrationWorker],
    *,
    platform: str,
) -> None:
    owner = _launch_migration_worker(migration_workers, "pause-after-upgrade")
    owner_ready = _read_worker_event(owner)
    owner_backend_pid = _assert_ready_event(owner, owner_ready, "after-ddl-before-commit")
    assert owner_ready["transaction_state"] == DatabaseSchemaState.VERSION_0008.value

    observer_pid, lock_pids = _observe_migration_lock()
    assert lock_pids == {owner_backend_pid}
    assert observer_pid != owner_backend_pid
    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.EMPTY
    assert _table_names() == set()

    owner.process.kill()
    _assert_forced_termination_return_code(_wait_worker(owner), platform=platform)
    _wait_for_backend_and_lock_release(owner_backend_pid)

    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.EMPTY
    assert _table_names() == set()
    _, lock_pids = _observe_migration_lock()
    assert lock_pids == set()

    retry = _launch_migration_worker(migration_workers, "ordinary")
    retry_result = _read_worker_event(retry)
    retry_backend_pid = _assert_success_event(retry, retry_result)
    assert retry.process.pid != owner.process.pid
    assert retry_backend_pid not in {owner_backend_pid, observer_pid}
    assert _wait_worker(retry) == 0
    _wait_for_backend_and_lock_release(retry_backend_pid)

    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.VERSION_0008
    assert all(worker.process.poll() is not None for worker in migration_workers)
    for worker in migration_workers:
        _assert_worker_secret_safe(worker)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX SIGKILL semantics only")
def test_postgresql_sigkill_rolls_back_uncommitted_ddl_and_releases_lock(
    migration_workers: list[_MigrationWorker],
) -> None:
    _exercise_forced_termination_rollback_and_lock_release(
        migration_workers,
        platform=sys.platform,
    )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows kill() semantics only")
def test_postgresql_windows_kill_rolls_back_uncommitted_ddl_and_releases_lock(
    migration_workers: list[_MigrationWorker],
) -> None:
    _exercise_forced_termination_rollback_and_lock_release(
        migration_workers,
        platform="win32",
    )


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
                _drop_post_0001_tables(connection)
                _undo_post_0005_agent_scope(connection)
                connection.execute(sa.text("DROP TABLE environments CASCADE"))
                connection.execute(sa.text("DROP TABLE projects"))
                connection.execute(sa.text("UPDATE alembic_version SET version_num = '0001'"))
                return DatabaseSchemaState.VERSION_0001
            if state == "partial-0001":
                _drop_post_0001_tables(connection)
                _undo_post_0005_agent_scope(connection)
                connection.execute(sa.text("DROP TABLE environments CASCADE"))
                connection.execute(sa.text("UPDATE alembic_version SET version_num = '0001'"))
                return DatabaseSchemaState.VERSION_0001_PARTIAL_PROJECTS
            if state == "future":
                connection.execute(sa.text("UPDATE alembic_version SET version_num = '9999'"))
                return DatabaseSchemaState.UNKNOWN
    finally:
        engine.dispose()
    raise AssertionError(f"unknown PostgreSQL startup seed state: {state}")


_MIGRATION_0005_TENANT_BOOTSTRAP_TABLES: tuple[str, ...] = (
    "tenant_bootstrap_refusal_events",
    "tenant_bootstrap_pending_outbox",
    "pending_approvals",
    "tenant_bootstrap_policy_artifacts",
    "tenant_bootstrap_idempotency",
    "organization_memberships",
    "platform_bootstrap_invitations",
)


def _drop_post_0001_tables(connection: Connection) -> None:
    for table_name in (
        "policy_registry_idempotency",
        "environment_policy_heads",
        "policy_versions",
        *_MIGRATION_0005_TENANT_BOOTSTRAP_TABLES,
        "managed_trust_keys",
        "managed_trust_scopes",
        "managed_outbox",
        "managed_governance_events",
        "managed_governance_event_heads",
        "agent_registration_idempotency",
        "managed_receipt_consumptions",
        "managed_mutation_attempts",
        "managed_decision_receipts",
    ):
        connection.execute(sa.text(f"DROP TABLE IF EXISTS {table_name} CASCADE"))


def _undo_post_0005_agent_scope(connection: Connection) -> None:
    connection.execute(sa.text("DROP INDEX IF EXISTS uq_policy_bundles_one_active_per_org"))
    connection.execute(sa.text("DROP INDEX IF EXISTS uq_agents_scope_name"))
    connection.execute(sa.text("DROP INDEX IF EXISTS uq_agents_legacy_org_name"))
    connection.execute(
        sa.text("ALTER TABLE agents DROP CONSTRAINT IF EXISTS fk_agents_scope_environment")
    )
    connection.execute(
        sa.text("ALTER TABLE agents DROP CONSTRAINT IF EXISTS ck_agents_scope_both_null_or_set")
    )
    connection.execute(
        sa.text("ALTER TABLE agents ADD CONSTRAINT uq_agents_org_name UNIQUE (org_id, name)")
    )
    connection.execute(sa.text("ALTER TABLE agents DROP COLUMN IF EXISTS environment_id"))
    connection.execute(sa.text("ALTER TABLE agents DROP COLUMN IF EXISTS project_id"))


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
    assert result.after.state is DatabaseSchemaState.VERSION_0008
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
    legacy_routes = [
        blocker for blocker in stopped.value.blockers if blocker.code == "LEGACY_UNSIGNED_WRITE"
    ]
    assert len(legacy_routes) == 6
    assert {blocker.route for blocker in legacy_routes} == {
        "PATCH /orgs/{org_id}/agents/{agent_id}/status",
        "POST /orgs",
        "POST /orgs/{org_id}/exports",
        "POST /orgs/{org_id}/policies",
        "POST /orgs/{org_id}/policies/{bundle_id}/activate",
        "POST /orgs/{org_id}/users",
    }
    assert inspect_schema(_TEST_POSTGRES_URL).state is DatabaseSchemaState.VERSION_0008
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
            "code": ProductionPostureBlocked.code,
            "stage": ProductionPostureBlocked.stage,
            "status": "not-production-ready",
            "blockers": [blocker.to_dict() for blocker in app.state.readiness_blockers],
            "schema_current": True,
            "schema_state": DatabaseSchemaState.VERSION_0008.value,
        }
        assert not audit_dir.exists()
    finally:
        app.state.engine.dispose()
    assert _catalog_and_data_snapshot() == before
