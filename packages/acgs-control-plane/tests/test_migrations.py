"""Alembic adoption tests for the pre-Alembic control-plane schema."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from alembic import command
from alembic import op as alembic_op
from sqlalchemy.dialects import postgresql

import acgs_control_plane.migrations as migration_module
from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.db import Base, make_engine
from acgs_control_plane.migrations import (
    HEAD_REVISION,
    LEGACY_V0_REVISION,
    DatabaseSchemaState,
    MigrationPreflightError,
    _ColumnSpec,
    _matches_type,
    inspect_schema,
    migration_config,
    upgrade_database,
)


def _database_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'control-plane.sqlite3'}"


def _seed_exact_legacy_v0_schema(database_url: str) -> None:
    """Create the actual former v0 contract without an Alembic version marker."""
    engine = make_engine(database_url)
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()


def _table_names(database_url: str) -> set[str]:
    engine = make_engine(database_url)
    try:
        return set(sa.inspect(engine).get_table_names())
    finally:
        engine.dispose()


def _version_number(database_url: str) -> str:
    engine = make_engine(database_url)
    try:
        with engine.connect() as connection:
            version = connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
    finally:
        engine.dispose()
    assert isinstance(version, str)
    return version


def _insert_legacy_receipt_evidence(database_url: str, receipt_id: str) -> None:
    """Insert one v0 evidence row without relying on post-v0 ORM models."""
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    """
                    INSERT INTO organizations (
                        id, name, created_at, audit_anchor_count, audit_anchor_hash
                    ) VALUES (
                        :id, :name, :created_at, :audit_anchor_count, :audit_anchor_hash
                    )
                    """
                ),
                {
                    "id": "org-0002-resume",
                    "name": "0002 Resume Organization",
                    "created_at": "2026-07-13T00:00:00+00:00",
                    "audit_anchor_count": 1,
                    "audit_anchor_hash": "a" * 64,
                },
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO receipts (
                        id, org_id, tool, decision, actor, goal, argument_hash, audit_hash,
                        policy_version, result_hash, error_class, payload, created_at
                    ) VALUES (
                        :id, :org_id, :tool, :decision, :actor, :goal, :argument_hash, :audit_hash,
                        :policy_version, :result_hash, :error_class, :payload, :created_at
                    )
                    """
                ),
                {
                    "id": receipt_id,
                    "org_id": "org-0002-resume",
                    "tool": "legacy.tool",
                    "decision": "allow",
                    "actor": "legacy-actor",
                    "goal": "prove 0002 interruption does not rewrite evidence",
                    "argument_hash": "b" * 64,
                    "audit_hash": "c" * 64,
                    "policy_version": "legacy-v0",
                    "result_hash": None,
                    "error_class": None,
                    "payload": json.dumps({"preserve": "0002-resume"}),
                    "created_at": "2026-07-13T00:00:00+00:00",
                },
            )
    finally:
        engine.dispose()


def _receipt_payload(database_url: str, receipt_id: str) -> tuple[str, str]:
    engine = make_engine(database_url)
    try:
        with engine.connect() as connection:
            row = connection.execute(
                sa.text("SELECT org_id, payload FROM receipts WHERE id = :id"),
                {"id": receipt_id},
            ).one()
    finally:
        engine.dispose()
    return row.org_id, row.payload


def _interrupt_0002_after_table(
    database_url: str, monkeypatch: pytest.MonkeyPatch, table_name: str
) -> None:
    """Crash revision 0002 immediately after one exact scope table exists."""
    original_create_table = alembic_op.create_table

    def _create_table_then_fail(created_table_name: str, *args: object, **kwargs: object) -> object:
        result = original_create_table(created_table_name, *args, **kwargs)
        if created_table_name == table_name:
            raise RuntimeError(f"injected interruption after {table_name} table creation")
        return result

    with monkeypatch.context() as scoped_patch:
        scoped_patch.setattr(alembic_op, "create_table", _create_table_then_fail)
        with pytest.raises(RuntimeError, match=f"injected interruption after {table_name}"):
            upgrade_database(database_url)


def _wheel_build_command(dist_dir: Path) -> list[str]:
    """Build through the prover-pinned uv when its closed runtime exports one."""
    uv_bin = os.environ.get("UV_BIN")
    if uv_bin:
        return [
            uv_bin,
            "build",
            "--no-build-isolation",
            "--python",
            sys.executable,
            "--offline",
            "--no-index",
            "--no-cache",
            "--wheel",
            "--out-dir",
            str(dist_dir),
            ".",
        ]
    return ["uv", "build", "--wheel", "--out-dir", str(dist_dir), "."]


def test_scope_table_probe_rejects_unexpected_identifier_before_execute() -> None:
    """A schema name never becomes executable SQL in the bounded resume probe."""

    class _Result:
        def first(self) -> None:
            return None

    class _RecordingConnection:
        class _Dialect:
            name = "sqlite"

        def __init__(self) -> None:
            self.statements: list[object] = []
            self.dialect = self._Dialect()

        def execute(self, statement: object) -> _Result:
            self.statements.append(statement)
            return _Result()

    malicious = _RecordingConnection()
    detail = migration_module._scope_tables_empty(  # type: ignore[arg-type]
        malicious,
        ("projects", "projects; DROP TABLE receipts; --"),
    )

    assert detail == (
        "unsupported scope table names for the bounded migration probe: "
        "['projects; DROP TABLE receipts; --']"
    )
    assert malicious.statements == []

    valid = _RecordingConnection()
    assert migration_module._scope_tables_empty(valid, ("projects",)) is None  # type: ignore[arg-type]
    assert len(valid.statements) == 1
    assert isinstance(valid.statements[0], sa.sql.Select)


def test_wheel_build_command_uses_prover_pinned_uv_without_network_or_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dist_dir = tmp_path / "dist"
    monkeypatch.setenv("UV_BIN", "/trusted/bin/uv")

    assert _wheel_build_command(dist_dir) == [
        "/trusted/bin/uv",
        "build",
        "--no-build-isolation",
        "--python",
        sys.executable,
        "--offline",
        "--no-index",
        "--no-cache",
        "--wheel",
        "--out-dir",
        str(dist_dir),
        ".",
    ]


@pytest.mark.parametrize("uv_bin", [None, ""])
def test_wheel_build_command_preserves_local_isolated_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, uv_bin: str | None
) -> None:
    dist_dir = tmp_path / "dist"
    if uv_bin is None:
        monkeypatch.delenv("UV_BIN", raising=False)
    else:
        monkeypatch.setenv("UV_BIN", uv_bin)

    assert _wheel_build_command(dist_dir) == [
        "uv",
        "build",
        "--wheel",
        "--out-dir",
        str(dist_dir),
        ".",
    ]


def test_wheel_ships_and_resolves_the_canonical_alembic_resources(tmp_path: Path) -> None:
    """Exercise the built artifact, not an editable/source-tree fallback."""
    package_root = Path(__file__).resolve().parents[1]
    dist_dir = tmp_path / "dist"
    build = subprocess.run(
        _wheel_build_command(dist_dir),
        cwd=package_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert build.returncode == 0, build.stderr

    wheels = list(dist_dir.glob("acgs_control_plane-*.whl"))
    assert len(wheels) == 1
    extracted_root = tmp_path / "wheel-extract"
    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
        assert {
            "acgs_control_plane/alembic.ini",
            "acgs_control_plane/migrations/env.py",
            "acgs_control_plane/migrations/versions/0001_legacy_v0.py",
            "acgs_control_plane/migrations/versions/0002_project_environment.py",
        } <= names
        archive.extractall(extracted_root)

    artifact_check = """
from pathlib import Path
import sys

import acgs_control_plane
import sqlalchemy as sa
from acgs_control_plane.migrations import (
    DatabaseSchemaState,
    inspect_schema,
    migration_config,
    upgrade_database,
)

artifact_root = Path(sys.argv[1]).resolve()
package_root = artifact_root / "acgs_control_plane"
assert Path(acgs_control_plane.__file__).resolve().is_relative_to(artifact_root)
database_url = f"sqlite:///{artifact_root / 'artifact-test.sqlite3'}"
config = migration_config(database_url)
assert Path(config.config_file_name).resolve() == package_root / "alembic.ini"
assert Path(config.get_main_option("script_location")).resolve() == package_root / "migrations"
result = upgrade_database(database_url)
assert result.before.state is DatabaseSchemaState.EMPTY
assert result.after.state is DatabaseSchemaState.VERSION_0002
assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0002
engine = sa.create_engine(database_url)
try:
    assert set(sa.inspect(engine).get_table_names()) == {
        "agents",
        "alembic_version",
        "compliance_exports",
        "environments",
        "organizations",
        "policy_bundles",
        "projects",
        "receipts",
        "users",
    }
finally:
    engine.dispose()
"""
    environment = os.environ.copy()
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = str(extracted_root) + (
        os.pathsep + existing_pythonpath if existing_pythonpath else ""
    )
    verification = subprocess.run(
        [sys.executable, "-c", artifact_check, str(extracted_root)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )
    assert verification.returncode == 0, verification.stderr


def test_empty_database_migrates_to_head_through_alembic(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)

    result = upgrade_database(database_url)

    assert result.before.state is DatabaseSchemaState.EMPTY
    assert result.after.state is DatabaseSchemaState.VERSION_0002
    assert _table_names(database_url) == {
        "agents",
        "alembic_version",
        "compliance_exports",
        "environments",
        "organizations",
        "policy_bundles",
        "projects",
        "receipts",
        "users",
    }

    engine = make_engine(database_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
                == HEAD_REVISION
            )
    finally:
        engine.dispose()


def test_raw_alembic_upgrade_rejects_an_empty_database_before_schema_mutation(
    tmp_path: Path,
) -> None:
    """Only the helper may make an empty database into a versioned schema."""
    database_url = _database_url(tmp_path)

    with pytest.raises(MigrationPreflightError, match="Refusing a raw Alembic operation"):
        command.upgrade(migration_config(database_url), "head")

    assert inspect_schema(database_url).state is DatabaseSchemaState.EMPTY
    assert _table_names(database_url) == set()


def test_raw_alembic_stamp_and_ensure_version_reject_an_empty_database(
    tmp_path: Path,
) -> None:
    """No raw online command may strand an empty DB with only a version table."""
    database_url = _database_url(tmp_path)

    with pytest.raises(MigrationPreflightError, match="Refusing a raw Alembic operation"):
        command.stamp(migration_config(database_url), HEAD_REVISION)
    with pytest.raises(MigrationPreflightError, match="Refusing a raw Alembic operation"):
        command.ensure_version(migration_config(database_url))
    with pytest.raises(MigrationPreflightError, match="Refusing a raw Alembic operation"):
        command.downgrade(migration_config(database_url), "base")

    assert inspect_schema(database_url).state is DatabaseSchemaState.EMPTY
    assert _table_names(database_url) == set()


def test_exact_legacy_schema_is_stamped_only_after_preflight_then_upgraded(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)
    _seed_exact_legacy_v0_schema(database_url)

    assert inspect_schema(database_url).state is DatabaseSchemaState.LEGACY_V0
    result = upgrade_database(database_url)

    assert result.before.state is DatabaseSchemaState.LEGACY_V0
    assert result.after.state is DatabaseSchemaState.VERSION_0002


def test_current_legacy_create_all_contract_is_adoptable_by_the_guard(tmp_path: Path) -> None:
    """The metadata exclusion leaves the former v0 table contract recognizable."""
    database_url = _database_url(tmp_path)
    engine = make_engine(database_url)
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()

    assert inspect_schema(database_url).state is DatabaseSchemaState.LEGACY_V0
    assert "projects" not in _table_names(database_url)
    assert "environments" not in _table_names(database_url)
    assert "alembic_version" not in _table_names(database_url)

    result = upgrade_database(database_url)

    assert result.before.state is DatabaseSchemaState.LEGACY_V0
    assert result.after.state is DatabaseSchemaState.VERSION_0002


@pytest.mark.parametrize("table_name", ["unowned_explicit_table", "organizations"])
def test_legacy_create_all_rejects_explicit_noncanonical_tables_without_ddl(
    tmp_path: Path, table_name: str
) -> None:
    """The SQLAlchemy ``tables=`` argument cannot expand or spoof legacy bootstrap DDL."""
    database_url = _database_url(tmp_path)
    external_table = sa.Table(
        table_name,
        sa.MetaData(),
        sa.Column("id", sa.String(length=64), primary_key=True),
    )
    engine = make_engine(database_url)
    try:
        with pytest.raises(RuntimeError, match="does not accept the SQLAlchemy tables="):
            Base.metadata.create_all(engine, tables=[external_table])
    finally:
        engine.dispose()

    assert inspect_schema(database_url).state is DatabaseSchemaState.EMPTY
    assert _table_names(database_url) == set()


@pytest.mark.parametrize("table_names", [("organizations",), ("organizations", "users")])
def test_legacy_create_all_rejects_canonical_table_subsets_without_ddl(
    tmp_path: Path, table_names: tuple[str, ...]
) -> None:
    """Even canonical subsets would manufacture an unversioned partial v0 schema."""
    database_url = _database_url(tmp_path)
    requested_tables = [Base.metadata.tables[table_name] for table_name in table_names]
    engine = make_engine(database_url)
    try:
        with pytest.raises(RuntimeError, match="does not accept the SQLAlchemy tables="):
            Base.metadata.create_all(engine, tables=requested_tables)
    finally:
        engine.dispose()

    assert inspect_schema(database_url).state is DatabaseSchemaState.EMPTY
    assert _table_names(database_url) == set()


def test_legacy_create_all_rejects_an_unknown_metadata_table_without_ddl(tmp_path: Path) -> None:
    """A future unmarked model cannot silently expand the transitional startup schema."""
    database_url = _database_url(tmp_path)
    unexpected_table = sa.Table(
        "unexpected_legacy_bootstrap_table",
        Base.metadata,
        sa.Column("id", sa.String(length=64), primary_key=True),
    )
    engine = make_engine(database_url)
    try:
        with pytest.raises(RuntimeError, match="metadata table set"):
            Base.metadata.create_all(engine)
    finally:
        Base.metadata.remove(unexpected_table)
        engine.dispose()

    assert inspect_schema(database_url).state is DatabaseSchemaState.EMPTY
    assert _table_names(database_url) == set()


def test_legacy_create_all_cleans_up_preflight_transaction_on_clean_connection(
    tmp_path: Path,
) -> None:
    """A clean supplied Connection remains immediately usable after bootstrap DDL."""
    database_url = _database_url(tmp_path)
    engine = make_engine(database_url)
    try:
        with engine.connect() as connection:
            assert not connection.in_transaction()
            Base.metadata.create_all(connection)
            assert not connection.in_transaction()
            with connection.begin():
                assert connection.scalar(sa.text("SELECT 1")) == 1
    finally:
        engine.dispose()

    assert inspect_schema(database_url).state is DatabaseSchemaState.LEGACY_V0


def test_legacy_create_all_rejection_cleans_up_preflight_transaction_on_clean_connection(
    tmp_path: Path,
) -> None:
    """A rejected preflight neither mutates tables nor poisons a clean Connection."""
    database_url = _database_url(tmp_path)
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("CREATE TABLE projects (id VARCHAR(64) PRIMARY KEY)"))

        with engine.connect() as connection:
            assert not connection.in_transaction()
            with pytest.raises(RuntimeError, match="Refusing legacy create_all"):
                Base.metadata.create_all(connection)
            assert not connection.in_transaction()
            with connection.begin():
                assert connection.scalar(sa.text("SELECT 1")) == 1
    finally:
        engine.dispose()

    assert _table_names(database_url) == {"projects"}


def test_legacy_create_all_preserves_a_caller_owned_connection_transaction(tmp_path: Path) -> None:
    """The preflight must not roll back a transaction that existed before the call."""
    database_url = _database_url(tmp_path)
    engine = make_engine(database_url)
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                Base.metadata.create_all(connection)
                assert connection.in_transaction()
            finally:
                transaction.rollback()
    finally:
        engine.dispose()


def test_legacy_create_all_rejection_preserves_a_caller_owned_connection_transaction(
    tmp_path: Path,
) -> None:
    """A rejected preflight likewise must leave an already-active caller transaction open."""
    database_url = _database_url(tmp_path)
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("CREATE TABLE projects (id VARCHAR(64) PRIMARY KEY)"))

        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                with pytest.raises(RuntimeError, match="Refusing legacy create_all"):
                    Base.metadata.create_all(connection)
                assert connection.in_transaction()
            finally:
                transaction.rollback()
    finally:
        engine.dispose()

    assert _table_names(database_url) == {"projects"}


def test_app_create_tables_bootstraps_only_an_empty_database_as_legacy_v0(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)

    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=tmp_path / "audit",
            create_tables=True,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        )
    )
    try:
        assert inspect_schema(database_url).state is DatabaseSchemaState.LEGACY_V0
        assert _table_names(database_url) == {
            "agents",
            "compliance_exports",
            "organizations",
            "policy_bundles",
            "receipts",
            "users",
        }
    finally:
        app.state.engine.dispose()


def test_legacy_create_tables_cannot_create_unversioned_scope_tables(tmp_path: Path) -> None:
    """The legacy app factory must not bypass the Alembic adoption guard."""
    database_url = _database_url(tmp_path)
    _seed_exact_legacy_v0_schema(database_url)

    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=tmp_path / "audit",
            create_tables=True,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        )
    )
    try:
        assert inspect_schema(database_url).state is DatabaseSchemaState.LEGACY_V0
        assert "alembic_version" not in _table_names(database_url)
        assert "projects" not in _table_names(database_url)
        assert "environments" not in _table_names(database_url)
    finally:
        app.state.engine.dispose()


def test_app_create_tables_rejects_a_projects_only_database_before_mutation(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("CREATE TABLE projects (id VARCHAR(64) PRIMARY KEY)"))
    finally:
        engine.dispose()

    with pytest.raises(RuntimeError, match="Refusing legacy create_all"):
        create_app(
            Settings(
                database_url=database_url,
                audit_dir=tmp_path / "audit",
                create_tables=True,
                runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
            )
        )

    assert inspect_schema(database_url).state is DatabaseSchemaState.UNKNOWN
    assert _table_names(database_url) == {"projects"}


def test_legacy_create_tables_does_not_mutate_an_unversioned_mixed_scope_schema(
    tmp_path: Path,
) -> None:
    """Startup fails before it can heal or extend a mixed scope state."""
    database_url = _database_url(tmp_path)
    _seed_exact_legacy_v0_schema(database_url)
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("CREATE TABLE projects (id VARCHAR(64) PRIMARY KEY)"))
    finally:
        engine.dispose()
    table_names_before = _table_names(database_url)

    with pytest.raises(RuntimeError, match="Refusing legacy create_all"):
        create_app(
            Settings(
                database_url=database_url,
                audit_dir=tmp_path / "audit",
                create_tables=True,
                runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
            )
        )

    assert inspect_schema(database_url).state is DatabaseSchemaState.UNKNOWN
    assert _table_names(database_url) == table_names_before
    assert "alembic_version" not in _table_names(database_url)
    assert "environments" not in _table_names(database_url)


def test_app_create_tables_rejects_a_versioned_schema_until_startup_migration_integration(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    upgrade_database(database_url)
    table_names_before = _table_names(database_url)

    with pytest.raises(RuntimeError, match="Refusing legacy create_all"):
        create_app(
            Settings(
                database_url=database_url,
                audit_dir=tmp_path / "audit",
                create_tables=True,
                runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
            )
        )

    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0002
    assert _table_names(database_url) == table_names_before


def test_app_create_tables_rejects_a_partial_scope_schema_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url = _database_url(tmp_path)
    _seed_exact_legacy_v0_schema(database_url)
    _interrupt_0002_after_table(database_url, monkeypatch, "projects")
    table_names_before = _table_names(database_url)

    with pytest.raises(RuntimeError, match="Refusing legacy create_all"):
        create_app(
            Settings(
                database_url=database_url,
                audit_dir=tmp_path / "audit",
                create_tables=True,
                runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
            )
        )

    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0001_PARTIAL_PROJECTS
    assert _table_names(database_url) == table_names_before


def test_raw_alembic_upgrade_rejects_exact_legacy_before_version_mutation(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)
    _seed_exact_legacy_v0_schema(database_url)
    table_names_before = _table_names(database_url)

    with pytest.raises(MigrationPreflightError, match="Refusing a raw Alembic operation"):
        command.upgrade(migration_config(database_url), "head")

    assert inspect_schema(database_url).state is DatabaseSchemaState.LEGACY_V0
    assert _table_names(database_url) == table_names_before
    assert "alembic_version" not in _table_names(database_url)


def test_raw_alembic_stamp_cannot_bypass_the_legacy_adoption_guard(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)
    _seed_exact_legacy_v0_schema(database_url)

    with pytest.raises(MigrationPreflightError, match="Refusing a raw Alembic operation"):
        command.stamp(migration_config(database_url), LEGACY_V0_REVISION)

    assert inspect_schema(database_url).state is DatabaseSchemaState.LEGACY_V0
    assert "alembic_version" not in _table_names(database_url)


def test_raw_alembic_upgrade_rejects_unknown_partial_before_version_mutation(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("CREATE TABLE organizations (id VARCHAR(64) PRIMARY KEY)"))
    finally:
        engine.dispose()

    with pytest.raises(MigrationPreflightError, match="Refusing a raw Alembic operation"):
        command.upgrade(migration_config(database_url), "head")

    assert inspect_schema(database_url).state is DatabaseSchemaState.UNKNOWN
    assert _table_names(database_url) == {"organizations"}


def test_unknown_partial_schema_is_rejected_without_creating_version_table(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("CREATE TABLE organizations (id VARCHAR(64) PRIMARY KEY)"))
    finally:
        engine.dispose()

    with pytest.raises(MigrationPreflightError, match="unexpected table set"):
        upgrade_database(database_url)

    assert _table_names(database_url) == {"organizations"}
    assert inspect_schema(database_url).state is DatabaseSchemaState.UNKNOWN


def test_partial_legacy_columns_are_rejected_without_a_stamp(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)
    _seed_exact_legacy_v0_schema(database_url)
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("ALTER TABLE receipts DROP COLUMN payload"))
    finally:
        engine.dispose()

    with pytest.raises(MigrationPreflightError, match="unexpected column layout"):
        upgrade_database(database_url)

    assert "alembic_version" not in _table_names(database_url)
    assert inspect_schema(database_url).state is DatabaseSchemaState.UNKNOWN


def test_sqlite_view_blocks_migration_before_any_version_table_is_created(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("CREATE VIEW unowned_schema_view AS SELECT 1 AS value"))
    finally:
        engine.dispose()

    table_names_before = _table_names(database_url)
    engine = make_engine(database_url)
    try:
        with pytest.raises(RuntimeError, match="Refusing legacy create_all"):
            Base.metadata.create_all(engine)
    finally:
        engine.dispose()

    preflight = inspect_schema(database_url)
    assert preflight.state is DatabaseSchemaState.UNKNOWN
    assert "view:unowned_schema_view" in preflight.detail
    with pytest.raises(MigrationPreflightError, match="unexpected non-table schema objects"):
        upgrade_database(database_url)

    assert _table_names(database_url) == table_names_before


def test_sqlite_trigger_blocks_legacy_adoption_without_a_stamp(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)
    _seed_exact_legacy_v0_schema(database_url)
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    """
                    CREATE TRIGGER receipt_noop_trigger
                    AFTER INSERT ON receipts
                    BEGIN
                        SELECT 1;
                    END
                    """
                )
            )
    finally:
        engine.dispose()

    table_names_before = _table_names(database_url)
    engine = make_engine(database_url)
    try:
        with pytest.raises(RuntimeError, match="Refusing legacy create_all"):
            Base.metadata.create_all(engine)
    finally:
        engine.dispose()

    preflight = inspect_schema(database_url)
    assert preflight.state is DatabaseSchemaState.UNKNOWN
    assert "trigger:receipt_noop_trigger" in preflight.detail
    with pytest.raises(MigrationPreflightError, match="unexpected non-table schema objects"):
        upgrade_database(database_url)

    assert "alembic_version" not in _table_names(database_url)
    assert _table_names(database_url) == table_names_before
    assert "projects" not in _table_names(database_url)
    assert "environments" not in _table_names(database_url)


def test_postgresql_non_table_objects_and_probe_failures_are_fail_closed() -> None:
    """The PostgreSQL guard covers views, triggers, RLS, and policies by catalog query.

    SQLite is the package test backend, so this exercises the PostgreSQL branch
    as a pure probe and asserts that inspection failure itself is not treated as
    a clean schema.
    """

    class _Result:
        def __init__(self, rows: list[tuple[str, str]]) -> None:
            self.rows = rows

        def all(self) -> list[tuple[str, str]]:
            return self.rows

    class _PostgreSQLProbe:
        dialect = SimpleNamespace(name="postgresql")

        def __init__(self, rows: list[tuple[str, str]]) -> None:
            self.rows = rows
            self.statement = ""

        def execute(self, statement: object) -> _Result:
            self.statement = str(statement)
            return _Result(self.rows)

    class _FailingPostgreSQLProbe:
        dialect = SimpleNamespace(name="postgresql")

        def execute(self, _statement: object) -> _Result:
            raise sa.exc.SQLAlchemyError("catalog unavailable")

    probe = _PostgreSQLProbe([("policy", "public.receipts.tenant_isolation")])
    detail = migration_module._non_table_object_detail(probe)  # type: ignore[arg-type]

    assert detail == "unexpected non-table schema objects: policy:public.receipts.tenant_isolation"
    assert "pg_catalog.pg_views" in probe.statement
    assert "pg_catalog.pg_matviews" in probe.statement
    assert "pg_catalog.pg_trigger" in probe.statement
    assert "relrowsecurity" in probe.statement
    assert "pg_catalog.pg_policies" in probe.statement
    assert (
        migration_module._non_table_object_detail(  # type: ignore[arg-type]
            _FailingPostgreSQLProbe()
        )
        == "unable to inspect non-table schema objects: SQLAlchemyError"
    )


def test_postgresql_preflight_does_not_accept_naive_timestamps_or_plain_json() -> None:
    datetime_column = _ColumnSpec("created_at", "datetime", False)
    json_column = _ColumnSpec("payload", "json", False)

    assert _matches_type(postgresql.TIMESTAMP(timezone=True), datetime_column, "postgresql")
    assert not _matches_type(postgresql.TIMESTAMP(timezone=False), datetime_column, "postgresql")
    assert _matches_type(postgresql.JSONB(), json_column, "postgresql")
    assert not _matches_type(postgresql.JSON(), json_column, "postgresql")


def test_upgrade_can_be_retried_after_a_completed_run(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)

    first = upgrade_database(database_url)
    second = upgrade_database(database_url)

    assert first.after.state is DatabaseSchemaState.VERSION_0002
    assert second.before.state is DatabaseSchemaState.VERSION_0002
    assert second.after.state is DatabaseSchemaState.VERSION_0002


def test_retry_after_failure_immediately_after_legacy_stamp_preserves_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url = _database_url(tmp_path)
    _seed_exact_legacy_v0_schema(database_url)
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    """
                    INSERT INTO organizations (
                        id, name, created_at, audit_anchor_count, audit_anchor_hash
                    ) VALUES (
                        :id, :name, :created_at, :audit_anchor_count, :audit_anchor_hash
                    )
                    """
                ),
                {
                    "id": "org-stamp-retry",
                    "name": "Stamped Retry Organization",
                    "created_at": "2026-07-13T00:00:00+00:00",
                    "audit_anchor_count": 1,
                    "audit_anchor_hash": "d" * 64,
                },
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO receipts (
                        id, org_id, tool, decision, actor, goal, argument_hash, audit_hash,
                        policy_version, result_hash, error_class, payload, created_at
                    ) VALUES (
                        :id, :org_id, :tool, :decision, :actor, :goal, :argument_hash, :audit_hash,
                        :policy_version, :result_hash, :error_class, :payload, :created_at
                    )
                    """
                ),
                {
                    "id": "receipt-stamp-retry",
                    "org_id": "org-stamp-retry",
                    "tool": "legacy.tool",
                    "decision": "allow",
                    "actor": "legacy-actor",
                    "goal": "retry without rewriting evidence",
                    "argument_hash": "e" * 64,
                    "audit_hash": "f" * 64,
                    "policy_version": "legacy-v0",
                    "result_hash": None,
                    "error_class": None,
                    "payload": json.dumps({"preserve": True}),
                    "created_at": "2026-07-13T00:00:00+00:00",
                },
            )
    finally:
        engine.dispose()

    def _fail_after_stamp(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("injected failure after the accepted legacy stamp")

    with monkeypatch.context() as scoped_patch:
        scoped_patch.setattr(migration_module.command, "upgrade", _fail_after_stamp)
        with pytest.raises(RuntimeError, match="injected failure"):
            upgrade_database(database_url)

    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0001
    engine = make_engine(database_url)
    try:
        inspector = sa.inspect(engine)
        assert "projects" not in inspector.get_table_names()
        assert "environments" not in inspector.get_table_names()
        with engine.connect() as connection:
            assert connection.execute(
                sa.text("SELECT org_id, payload FROM receipts WHERE id = :id"),
                {"id": "receipt-stamp-retry"},
            ).one() == ("org-stamp-retry", json.dumps({"preserve": True}))
    finally:
        engine.dispose()

    result = upgrade_database(database_url)
    assert result.before.state is DatabaseSchemaState.VERSION_0001
    assert result.after.state is DatabaseSchemaState.VERSION_0002


def test_0002_projects_only_interruption_retries_without_rewriting_legacy_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url = _database_url(tmp_path)
    _seed_exact_legacy_v0_schema(database_url)
    _insert_legacy_receipt_evidence(database_url, "receipt-0002-projects")

    _interrupt_0002_after_table(database_url, monkeypatch, "projects")

    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0001_PARTIAL_PROJECTS
    assert _version_number(database_url) == LEGACY_V0_REVISION
    assert "projects" in _table_names(database_url)
    assert "environments" not in _table_names(database_url)
    assert _receipt_payload(database_url, "receipt-0002-projects") == (
        "org-0002-resume",
        json.dumps({"preserve": "0002-resume"}),
    )

    result = upgrade_database(database_url)

    assert result.before.state is DatabaseSchemaState.VERSION_0001_PARTIAL_PROJECTS
    assert result.after.state is DatabaseSchemaState.VERSION_0002
    assert _receipt_payload(database_url, "receipt-0002-projects") == (
        "org-0002-resume",
        json.dumps({"preserve": "0002-resume"}),
    )


def test_0002_full_scope_interruption_retries_when_both_empty_tables_are_exact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url = _database_url(tmp_path)
    _seed_exact_legacy_v0_schema(database_url)

    _interrupt_0002_after_table(database_url, monkeypatch, "environments")

    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0001_PARTIAL_SCOPE
    assert _version_number(database_url) == LEGACY_V0_REVISION
    assert {"projects", "environments"} <= _table_names(database_url)

    result = upgrade_database(database_url)

    assert result.before.state is DatabaseSchemaState.VERSION_0001_PARTIAL_SCOPE
    assert result.after.state is DatabaseSchemaState.VERSION_0002


def test_0002_data_bearing_partial_scope_is_rejected_without_resuming(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url = _database_url(tmp_path)
    _seed_exact_legacy_v0_schema(database_url)
    _interrupt_0002_after_table(database_url, monkeypatch, "projects")

    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    """
                    INSERT INTO organizations (
                        id, name, created_at, audit_anchor_count, audit_anchor_hash
                    ) VALUES ('org-data-bearing', 'Data Bearing', :created_at, 0, '')
                    """
                ),
                {"created_at": "2026-07-13T00:00:00+00:00"},
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO projects (id, org_id, slug, name, created_at)
                    VALUES ('project-data-bearing', 'org-data-bearing', 'core', 'Core', :created_at)
                    """
                ),
                {"created_at": "2026-07-13T00:00:00+00:00"},
            )
    finally:
        engine.dispose()

    preflight = inspect_schema(database_url)
    assert preflight.state is DatabaseSchemaState.UNKNOWN
    assert "partial scope table projects contains data" in preflight.detail
    with pytest.raises(MigrationPreflightError, match="partial scope table projects contains data"):
        upgrade_database(database_url)

    assert _version_number(database_url) == LEGACY_V0_REVISION
    assert "environments" not in _table_names(database_url)


def test_0002_malformed_partial_scope_is_rejected_without_resuming(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url = _database_url(tmp_path)
    _seed_exact_legacy_v0_schema(database_url)
    _interrupt_0002_after_table(database_url, monkeypatch, "projects")

    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("CREATE INDEX ix_projects_unexpected ON projects (name)"))
    finally:
        engine.dispose()

    preflight = inspect_schema(database_url)
    assert preflight.state is DatabaseSchemaState.UNKNOWN
    assert "projects has unexpected non-unique indexes" in preflight.detail
    with pytest.raises(MigrationPreflightError, match="projects has unexpected non-unique indexes"):
        upgrade_database(database_url)

    assert _version_number(database_url) == LEGACY_V0_REVISION
    assert "environments" not in _table_names(database_url)


def test_legacy_receipt_evidence_stays_unmapped_after_scope_upgrade(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)
    _seed_exact_legacy_v0_schema(database_url)
    created_at = "2026-07-13T00:00:00+00:00"
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    """
                    INSERT INTO organizations (
                        id, name, created_at, audit_anchor_count, audit_anchor_hash
                    ) VALUES (
                        :id, :name, :created_at, :audit_anchor_count, :audit_anchor_hash
                    )
                    """
                ),
                {
                    "id": "org-legacy",
                    "name": "Legacy Organization",
                    "created_at": created_at,
                    "audit_anchor_count": 1,
                    "audit_anchor_hash": "a" * 64,
                },
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO receipts (
                        id, org_id, tool, decision, actor, goal, argument_hash, audit_hash,
                        policy_version, result_hash, error_class, payload, created_at
                    ) VALUES (
                        :id, :org_id, :tool, :decision, :actor, :goal, :argument_hash, :audit_hash,
                        :policy_version, :result_hash, :error_class, :payload, :created_at
                    )
                    """
                ),
                {
                    "id": "legacy-receipt",
                    "org_id": "org-legacy",
                    "tool": "legacy.tool",
                    "decision": "allow",
                    "actor": "legacy-actor",
                    "goal": "retain original organization-only provenance",
                    "argument_hash": "b" * 64,
                    "audit_hash": "c" * 64,
                    "policy_version": "legacy-v0",
                    "result_hash": None,
                    "error_class": None,
                    "payload": json.dumps({"legacy": True}),
                    "created_at": created_at,
                },
            )
    finally:
        engine.dispose()

    result = upgrade_database(database_url)

    assert result.before.state is DatabaseSchemaState.LEGACY_V0
    engine = make_engine(database_url)
    try:
        inspector = sa.inspect(engine)
        receipt_columns = {column["name"] for column in inspector.get_columns("receipts")}
        assert "project_id" not in receipt_columns
        assert "environment_id" not in receipt_columns
        with engine.connect() as connection:
            row = connection.execute(
                sa.text("SELECT id, org_id, payload FROM receipts WHERE id = :id"),
                {"id": "legacy-receipt"},
            ).one()
    finally:
        engine.dispose()

    assert row.id == "legacy-receipt"
    assert row.org_id == "org-legacy"
    assert json.loads(row.payload) == {"legacy": True}
