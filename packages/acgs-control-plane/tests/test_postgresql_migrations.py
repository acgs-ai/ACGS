"""Opt-in PostgreSQL migration tests for the controlled operator path.

These tests intentionally require ``ACP_TEST_POSTGRES_URL``, an explicit
``ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE=1`` acknowledgement, and the exact
dedicated disposable database ``acgs_control_plane_test`` before they reset its
``public`` schema.  They never infer or use an application/runtime database URL.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
import sqlalchemy as sa
from alembic import command
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError

import acgs_control_plane.migrations as migration_module
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
