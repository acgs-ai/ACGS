"""Exact live-PostgreSQL selectors for the G005 migration evidence gate.

This module deliberately fails rather than skips when the private gate wrapper
has not provisioned every pinned prerequisite.  All destructive operations are
bound to the exact disposable database names below.
"""

from __future__ import annotations

import importlib
import os
import shutil
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from threading import Event, Thread

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from sqlalchemy.engine import Connection

import acgs_control_plane.migrations as migration_module
from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.db import make_engine
from acgs_control_plane.migration_recovery import (
    RecoveryRefused,
    _capture_database_state_url,
    create_recovery_bundle,
    restore_recovery_bundle,
    verify_recovery_bundle,
)
from acgs_control_plane.migrations import (
    HEAD_REVISION,
    LEGACY_V0_REVISION,
    DatabaseSchemaState,
    MigrationPreflightError,
    inspect_schema,
    migration_config,
    upgrade_database,
)
from acgs_control_plane.models import utcnow
from acgs_control_plane.tenant_bootstrap import (
    BOOTSTRAP_AUTHORIZATION_HEADER,
    BOOTSTRAP_IDEMPOTENCY_HEADER,
    BOOTSTRAP_INVITATION_HEADER,
    BOOTSTRAP_INVITEE_ROLE,
    create_platform_bootstrap_invitation,
)
from tests import test_postgresql_migrations as migrations_pg
from tests import test_postgresql_rolling_upgrade as rolling_pg

_MAIN_ENV = "ACP_TEST_POSTGRES_URL"
_SOURCE_ENV = "ACP_TEST_RECOVERY_SOURCE_URL"
_TARGET_ENV = "ACP_TEST_RECOVERY_TARGET_URL"
_ROLLING_ENV = "ACP_TEST_ROLLING_POSTGRES_URL"
_EXPECTED_DATABASES = {
    _MAIN_ENV: "acgs_control_plane_test",
    _SOURCE_ENV: "acgs_control_plane_recovery_source_test",
    _TARGET_ENV: "acgs_control_plane_recovery_target_test",
    _ROLLING_ENV: "acgs_control_plane_rolling_upgrade_test",
}
_LEGACY_TABLES = (
    "agents",
    "compliance_exports",
    "organizations",
    "policy_bundles",
    "receipts",
    "users",
)
_CURRENT_FORWARD_ONLY_REVISIONS = frozenset(
    {"0001", "0002", "0003", "0004", "0005", "0007", "0008", "0009", "0010", "0011"}
)
_CURRENT_REVERSIBLE_REVISIONS: frozenset[str] = frozenset({"0006"})
_LEGACY_ROW_COLUMNS = {
    "agents": (
        "id",
        "org_id",
        "name",
        "description",
        "trust_tier",
        "allowed_tools",
        "status",
        "created_at",
    ),
    # Revision 0010 attaches resolved scope (``project_id`` / ``environment_id``)
    # to pre-existing bundles, so the preservation probe compares only the frozen
    # v0 columns declared in revision 0001.
    "policy_bundles": (
        "id",
        "org_id",
        "policy_id",
        "version",
        "bundle",
        "status",
        "created_at",
        "activated_at",
    ),
}
_LARGE_TABLE_ROWS = 10_000
_MIGRATION_ELAPSED_BUDGET_SECONDS = 20.0
_MIGRATION_LOCK_WAIT_BUDGET_MS = 5_000
_APPLICATION_PROBE_LATENCY_BUDGET_SECONDS = 5.0
_PROBE_SYNC_BUDGET_SECONDS = 10.0


@dataclass(frozen=True)
class _ProbeObservation:
    phase: str
    started_at: float
    finished_at: float
    rows_seen: int
    rows_written: int

    @property
    def latency_seconds(self) -> float:
        return self.finished_at - self.started_at


def _required_url(variable: str) -> str:
    raw = os.environ.get(variable)
    expected_database = _EXPECTED_DATABASES[variable]
    if not raw:
        pytest.fail(f"{variable} is required by run_postgres_gate.sh", pytrace=False)
    try:
        url = sa.engine.make_url(raw)
    except Exception:
        pytest.fail(f"{variable} must be a valid PostgreSQL URL", pytrace=False)
    if url.get_backend_name() != "postgresql" or url.database != expected_database:
        pytest.fail(
            f"{variable} must name exactly the disposable database {expected_database!r}",
            pytrace=False,
        )
    return raw


def _admin_url(database_url: str) -> str:
    return (
        sa.engine.make_url(database_url)
        .update_query_dict({"options": "-csearch_path=pg_catalog,public"})
        .render_as_string(hide_password=False)
    )


def _reset_exact_database(database_url: str, expected_database: str) -> None:
    if os.environ.get("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE") != "1":
        pytest.fail("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE=1 is required", pytrace=False)
    engine = make_engine(_admin_url(database_url))
    try:
        with engine.begin() as connection:
            assert connection.scalar(sa.text("SELECT pg_catalog.current_database()")) == (
                expected_database
            )
            assert connection.scalar(sa.text("SHOW server_version_num")) == "170010"
            connection.execute(sa.text("DROP SCHEMA IF EXISTS shadow CASCADE"))
            connection.execute(sa.text("DROP SCHEMA public CASCADE"))
            connection.execute(sa.text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


def _assert_pinned_database(database_url: str, expected_database: str) -> None:
    engine = make_engine(_admin_url(database_url))
    try:
        with engine.connect() as connection:
            assert connection.scalar(sa.text("SELECT pg_catalog.current_database()")) == (
                expected_database
            )
            assert connection.scalar(sa.text("SHOW server_version_num")) == "170010"
    finally:
        engine.dispose()


@pytest.fixture(scope="session", autouse=True)
def _require_exact_gate_environment() -> Iterator[None]:
    if os.environ.get("ACP_TEST_POSTGRES_GATE_ACTIVE") != "1":
        pytest.skip("live PostgreSQL migration gate is inactive; use run_postgres_gate.sh")
    if os.environ.get("ACGS_TEST_SEED") != "20260710":
        pytest.fail("ACGS_TEST_SEED must equal 20260710", pytrace=False)
    if os.environ.get("PYTHONHASHSEED") != "0":
        pytest.fail("PYTHONHASHSEED must equal 0", pytrace=False)
    if os.environ.get("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE") != "1":
        pytest.fail("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE must equal 1", pytrace=False)
    if "PGOPTIONS" in os.environ:
        pytest.fail("ambient PGOPTIONS must be absent before the exact gate", pytrace=False)
    try:
        importlib.import_module("psycopg")
    except ImportError:
        pytest.fail("psycopg is required for the live PostgreSQL gate", pytrace=False)
    missing_clients = [name for name in ("psql", "pg_dump", "pg_restore") if not shutil.which(name)]
    if missing_clients:
        pytest.fail(
            "pinned PostgreSQL client wrappers are required: " + ", ".join(missing_clients),
            pytrace=False,
        )

    urls = {variable: _required_url(variable) for variable in _EXPECTED_DATABASES}
    try:
        rolling_pg._validate_old_artifact(
            os.environ.get("ACP_TEST_OLD_APP_ARTIFACT"),
            os.environ.get("ACP_TEST_OLD_APP_ARTIFACT_SHA256"),
        )
    except rolling_pg.ArtifactRefusal:
        pytest.fail("the exact pinned old-app artifact and digest are required", pytrace=False)
    for variable, expected_database in _EXPECTED_DATABASES.items():
        try:
            _assert_pinned_database(urls[variable], expected_database)
        except Exception:
            pytest.fail(
                f"{variable} did not reach the exact pinned PostgreSQL test database",
                pytrace=False,
            )
    yield


@pytest.fixture(autouse=True)
def _isolated_main_database() -> Iterator[None]:
    database_url = _required_url(_MAIN_ENV)
    expected_database = _EXPECTED_DATABASES[_MAIN_ENV]
    _reset_exact_database(database_url, expected_database)
    try:
        yield
    finally:
        _reset_exact_database(database_url, expected_database)


def _seed_exact_alpha_schema() -> None:
    migrations_pg._seed_exact_legacy_v0_schema()
    assert inspect_schema(_required_url(_MAIN_ENV)).state is DatabaseSchemaState.LEGACY_V0


def _seed_legacy_rows(database_url: str) -> None:
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    """
                    INSERT INTO organizations (
                        id, name, created_at, audit_anchor_count, audit_anchor_hash
                    ) VALUES ('org-alpha', 'Alpha Existing', now(), 0, '')
                    """
                )
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO users (
                        id, org_id, name, email, role, api_key_hash, active, created_at
                    ) VALUES (
                        'user-alpha', 'org-alpha', 'Alpha User', 'alpha@example.test',
                        'viewer', repeat('a', 64), true, now()
                    )
                    """
                )
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO agents (
                        id, org_id, name, description, trust_tier, allowed_tools,
                        status, created_at
                    ) VALUES (
                        'agent-alpha', 'org-alpha', 'Alpha Agent', 'legacy probe',
                        'standard', '[]'::jsonb, 'active', now()
                    )
                    """
                )
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO policy_bundles (
                        id, org_id, policy_id, version, bundle, status, created_at
                    ) VALUES (
                        'policy-alpha', 'org-alpha', 'alpha-policy', '1', '{}'::jsonb,
                        'draft', now()
                    )
                    """
                )
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO receipts (
                        id, org_id, tool, decision, actor, goal, argument_hash,
                        audit_hash, policy_version, payload, created_at
                    ) VALUES (
                        'receipt-alpha', 'org-alpha', 'probe.read', 'deny', 'user-alpha',
                        'legacy preservation probe', repeat('b', 64), repeat('c', 64),
                        '1', '{}'::jsonb, now()
                    )
                    """
                )
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO compliance_exports (
                        id, org_id, created_by, receipt_count, bundle_hash, bundle, created_at
                    ) VALUES (
                        'export-alpha', 'org-alpha', 'user-alpha', 1, repeat('d', 64),
                        '{}'::jsonb, now()
                    )
                    """
                )
            )
    finally:
        engine.dispose()


def _rows(database_url: str, tables: tuple[str, ...]) -> dict[str, tuple[tuple[str, ...], ...]]:
    engine = make_engine(database_url)
    try:
        with engine.connect() as connection:
            inspector = sa.inspect(connection)
            available = set(inspector.get_table_names(schema="public"))
            assert set(tables) <= available
            rows: dict[str, tuple[tuple[str, ...], ...]] = {}
            metadata = sa.MetaData()
            for table_name in tables:
                table = sa.Table(table_name, metadata, autoload_with=connection)
                legacy_column_names = _LEGACY_ROW_COLUMNS.get(table_name)
                if legacy_column_names is not None:
                    selected_columns = tuple(
                        table.c[column_name] for column_name in legacy_column_names
                    )
                else:
                    selected_columns = tuple(table.c)
                primary_key = tuple(table.primary_key.columns)
                statement = sa.select(*selected_columns)
                if primary_key:
                    statement = statement.order_by(*primary_key)
                rows[table_name] = tuple(
                    tuple(repr(value) for value in row)
                    for row in connection.execute(statement).all()
                )
            return rows
    finally:
        engine.dispose()


def _head_version(database_url: str) -> str:
    engine = make_engine(database_url)
    try:
        with engine.connect() as connection:
            version = connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
            assert isinstance(version, str)
            return version
    finally:
        engine.dispose()


def _controlled_upgrade_to_revision(database_url: str, revision: str) -> None:
    config = migration_config(database_url)
    engine = make_engine(database_url)
    try:
        with engine.connect() as connection:
            with connection.begin():
                before = inspect_schema(database_url)
                config.attributes["connection"] = connection
                migration_module._run_controlled_operation(
                    config,
                    migration_module._SCOPE_RESUME_TOKEN,
                    before.state,
                    lambda: command.upgrade(config, revision),
                )
                config.attributes.pop("connection", None)
    finally:
        config.attributes.pop("connection", None)
        engine.dispose()


def _constraint_deferrability(
    database_url: str, constraint_names: tuple[str, ...]
) -> dict[str, bool]:
    engine = make_engine(database_url)
    try:
        with engine.connect() as connection:
            rows = connection.execute(
                sa.text(
                    """
                    SELECT conname, condeferrable AND condeferred
                    FROM pg_catalog.pg_constraint
                    WHERE connamespace = 'public'::regnamespace
                      AND conname = ANY(:constraint_names)
                    """
                ),
                {"constraint_names": list(constraint_names)},
            ).all()
            return {str(name): bool(is_initially_deferred) for name, is_initially_deferred in rows}
    finally:
        engine.dispose()


def _assert_real_tenant_bootstrap(database_url: str, tmp_path: Path) -> None:
    token = "tenant_bootstrap_immutable_0004_upgrade_000000000000000000000000000"
    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=tmp_path / "audit-immutable-0004",
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        )
    )
    try:
        with app.state.session_factory() as session:
            with session.begin():
                create_platform_bootstrap_invitation(
                    session,
                    token=token,
                    actor="platform:invitee:alice",
                    expires_at=utcnow() + timedelta(hours=1),
                    policy_outcome="allow",
                    role=BOOTSTRAP_INVITEE_ROLE,
                )
        response = TestClient(app).post(
            "/v1/tenant-bootstrap",
            json={
                "display_name": "Immutable 0004 Upgrade",
                "admin_name": "Migration Admin",
                "admin_email": "migration-admin@example.com",
            },
            headers={
                BOOTSTRAP_AUTHORIZATION_HEADER: "Bearer local-platform-token-alice",
                BOOTSTRAP_INVITATION_HEADER: token,
                BOOTSTRAP_IDEMPOTENCY_HEADER: "tenant-bootstrap-key-immutable-0004-upgrade",
            },
        )
        assert response.status_code == 201, response.json()
        assert response.json()["assurance_class"] == "native"
    finally:
        app.state.engine.dispose()


def test_empty_and_existing_alpha_upgrade_head() -> None:
    database_url = _required_url(_MAIN_ENV)
    expected_database = _EXPECTED_DATABASES[_MAIN_ENV]
    empty_result = upgrade_database(database_url, expected_database=expected_database)
    assert empty_result.before.state is DatabaseSchemaState.EMPTY
    assert empty_result.after.state is DatabaseSchemaState.VERSION_0011
    assert _head_version(database_url) == HEAD_REVISION

    _reset_exact_database(database_url, expected_database)
    _seed_exact_alpha_schema()
    _seed_legacy_rows(database_url)
    legacy_rows = _rows(database_url, _LEGACY_TABLES)

    existing_result = upgrade_database(database_url, expected_database=expected_database)
    assert existing_result.before.state is DatabaseSchemaState.LEGACY_V0
    assert existing_result.after.state is DatabaseSchemaState.VERSION_0011
    assert _head_version(database_url) == HEAD_REVISION
    assert _rows(database_url, _LEGACY_TABLES) == legacy_rows


def test_immutable_0004_upgrade_defers_managed_ledger_constraints_and_bootstraps(
    tmp_path: Path,
) -> None:
    database_url = _required_url(_MAIN_ENV)
    expected_database = _EXPECTED_DATABASES[_MAIN_ENV]
    _controlled_upgrade_to_revision(database_url, "0004")
    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0004
    assert _head_version(database_url) == "0004"

    managed_constraints = (
        "fk_managed_receipts_scope_environment",
        "fk_managed_consumptions_scope_receipt",
        "fk_managed_events_scope_receipt",
        "fk_managed_outbox_scope_receipt",
        "fk_managed_outbox_scope_event",
    )
    before_deferrability = _constraint_deferrability(database_url, managed_constraints)
    assert set(before_deferrability) == set(managed_constraints)
    assert not any(before_deferrability.values())

    existing_result = upgrade_database(database_url, expected_database=expected_database)
    assert existing_result.before.state is DatabaseSchemaState.VERSION_0004
    assert existing_result.after.state is DatabaseSchemaState.VERSION_0011
    assert _head_version(database_url) == HEAD_REVISION
    assert all(_constraint_deferrability(database_url, managed_constraints).values())

    _assert_real_tenant_bootstrap(database_url, tmp_path)


def test_declared_reversible_round_trip() -> None:
    database_url = _required_url(_MAIN_ENV)
    upgrade_database(database_url, expected_database=_EXPECTED_DATABASES[_MAIN_ENV])
    _seed_legacy_rows(database_url)
    before = migrations_pg._catalog_and_data_snapshot()

    revisions = {
        revision.revision: revision
        for revision in ScriptDirectory.from_config(migration_config(database_url)).walk_revisions()
    }
    assert set(revisions) == (_CURRENT_FORWARD_ONLY_REVISIONS | _CURRENT_REVERSIBLE_REVISIONS), (
        "every packaged revision must have an explicit rollback classification"
    )
    assert _CURRENT_REVERSIBLE_REVISIONS == {"0006"}
    for revision_id in sorted(_CURRENT_REVERSIBLE_REVISIONS):
        assert callable(revisions[revision_id].module.downgrade)

    for revision_id in sorted(_CURRENT_FORWARD_ONLY_REVISIONS):
        downgrade = revisions[revision_id].module.downgrade
        assert downgrade.__doc__ is not None and "Fail closed" in downgrade.__doc__
        with pytest.raises(
            NotImplementedError,
            match="forward-only; restore a verified backup to roll back",
        ):
            downgrade()

    with pytest.raises(MigrationPreflightError, match="Refusing a raw Alembic operation"):
        command.downgrade(migration_config(database_url), "0001")
    assert migrations_pg._catalog_and_data_snapshot() == before
    assert _head_version(database_url) == HEAD_REVISION


def test_mixed_version_rolling_compatibility(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url = _required_url(_ROLLING_ENV)
    expected_database = _EXPECTED_DATABASES[_ROLLING_ENV]
    _reset_exact_database(database_url, expected_database)
    monkeypatch.setenv("ACP_TEST_POSTGRES_URL", database_url)
    engine = make_engine(database_url)
    try:
        rolling_pg.test_candidate_old_app_remains_org_scoped_across_exact_operator_upgrade(
            engine, tmp_path
        )
        assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0011
        assert _head_version(database_url) == HEAD_REVISION
    finally:
        engine.dispose()
        _reset_exact_database(database_url, expected_database)


def test_large_table_online_migration_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    database_url = _required_url(_MAIN_ENV)
    expected_database = _EXPECTED_DATABASES[_MAIN_ENV]
    _seed_exact_alpha_schema()
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    """
                    INSERT INTO organizations (
                        id, name, created_at, audit_anchor_count, audit_anchor_hash
                    )
                    SELECT
                        'org-large-' || series::text,
                        'Large Org ' || series::text,
                        now(), 0, ''
                    FROM generate_series(1, :row_count) AS series
                    """
                ),
                {"row_count": _LARGE_TABLE_ROWS},
            )
    finally:
        engine.dispose()
    legacy_rows = _rows(database_url, _LEGACY_TABLES)
    assert len(legacy_rows["organizations"]) == _LARGE_TABLE_ROWS

    with monkeypatch.context() as scoped_environment:
        scoped_environment.setenv(
            "PGOPTIONS", f"-c lock_timeout={_MIGRATION_LOCK_WAIT_BUDGET_MS}ms"
        )
        budget_engine = make_engine(database_url)
        try:
            with budget_engine.connect() as connection:
                assert connection.scalar(sa.text("SHOW lock_timeout")) == "5s"
        finally:
            budget_engine.dispose()

        probe_window_open = Event()
        probe_armed_for_upgrade = Event()
        actual_upgrade_started = Event()
        probe_observations: list[_ProbeObservation] = []
        probe_errors: list[BaseException] = []
        actual_upgrade_interval: dict[str, float] = {}

        def _run_probe(connection: Connection, phase: str) -> None:
            started_at = time.monotonic()
            rows_seen = int(
                connection.scalar(
                    sa.text("SELECT count(*) FROM organizations WHERE id LIKE 'org-large-%'")
                )
            )
            updated = connection.execute(
                sa.text("UPDATE organizations SET name = name WHERE id = 'org-large-1'")
            )
            finished_at = time.monotonic()
            probe_observations.append(
                _ProbeObservation(
                    phase=phase,
                    started_at=started_at,
                    finished_at=finished_at,
                    rows_seen=rows_seen,
                    rows_written=int(updated.rowcount or 0),
                )
            )

        def _application_probe_worker() -> None:
            probe_engine = make_engine(database_url)
            try:
                if not probe_window_open.wait(_PROBE_SYNC_BUDGET_SECONDS):
                    raise AssertionError("migration did not open the application probe window")
                for _ in range(2):
                    with probe_engine.begin() as connection:
                        _run_probe(connection, "migration-window")

                with probe_engine.begin() as connection:
                    started_at = time.monotonic()
                    rows_seen = int(
                        connection.scalar(
                            sa.text(
                                "SELECT count(*) FROM organizations WHERE id LIKE 'org-large-%'"
                            )
                        )
                    )
                    probe_armed_for_upgrade.set()
                    if not actual_upgrade_started.wait(_PROBE_SYNC_BUDGET_SECONDS):
                        raise AssertionError("actual Alembic upgrade did not start")
                    updated = connection.execute(
                        sa.text("UPDATE organizations SET name = name WHERE id = 'org-large-1'")
                    )
                    probe_observations.append(
                        _ProbeObservation(
                            phase="actual-upgrade-overlap",
                            started_at=started_at,
                            finished_at=time.monotonic(),
                            rows_seen=rows_seen,
                            rows_written=int(updated.rowcount or 0),
                        )
                    )
            except BaseException as exc:
                probe_errors.append(exc)
                probe_armed_for_upgrade.set()
            finally:
                probe_engine.dispose()

        original_upgrade = migration_module.command.upgrade

        def _coordinated_upgrade(config: object, revision: str, **kwargs: object) -> None:
            probe_window_open.set()
            if not probe_armed_for_upgrade.wait(_PROBE_SYNC_BUDGET_SECONDS):
                raise AssertionError("application probe did not arm before Alembic upgrade")
            actual_upgrade_interval["started_at"] = time.monotonic()
            actual_upgrade_started.set()
            try:
                original_upgrade(config, revision, **kwargs)
            finally:
                actual_upgrade_interval["finished_at"] = time.monotonic()

        probe_thread = Thread(
            target=_application_probe_worker,
            name="acgs-large-table-application-probe",
            daemon=False,
        )
        scoped_environment.setattr(migration_module.command, "upgrade", _coordinated_upgrade)
        probe_thread.start()
        started = time.monotonic()
        try:
            result = upgrade_database(database_url, expected_database=expected_database)
            elapsed = time.monotonic() - started
        finally:
            actual_upgrade_started.set()
            probe_window_open.set()
            probe_thread.join(timeout=_PROBE_SYNC_BUDGET_SECONDS)
        assert not probe_thread.is_alive(), "application probe thread exceeded its cleanup budget"
        assert not probe_errors
        assert len(probe_observations) == 3
        assert {observation.phase for observation in probe_observations} == {
            "migration-window",
            "actual-upgrade-overlap",
        }
        assert all(observation.rows_seen == _LARGE_TABLE_ROWS for observation in probe_observations)
        assert all(observation.rows_written == 1 for observation in probe_observations)
        assert max(observation.latency_seconds for observation in probe_observations) < (
            _APPLICATION_PROBE_LATENCY_BUDGET_SECONDS
        )
        overlapping = next(
            observation
            for observation in probe_observations
            if observation.phase == "actual-upgrade-overlap"
        )
        assert overlapping.started_at <= actual_upgrade_interval["finished_at"]
        assert overlapping.finished_at >= actual_upgrade_interval["started_at"]
    assert result.before.state is DatabaseSchemaState.LEGACY_V0
    assert result.after.state is DatabaseSchemaState.VERSION_0011
    assert elapsed < _MIGRATION_ELAPSED_BUDGET_SECONDS
    assert _rows(database_url, _LEGACY_TABLES) == legacy_rows


def _seed_recovery_source(database_url: str, expected_database: str) -> None:
    upgrade_database(database_url, expected_database=expected_database)
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    """
                    INSERT INTO organizations (
                        id, name, created_at, audit_anchor_count, audit_anchor_hash
                    ) VALUES ('org-recovery', 'Recovery Drill', now(), 0, '')
                    """
                )
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO projects (id, org_id, slug, name, created_at)
                    VALUES ('project-recovery', 'org-recovery', 'core', 'Core', now())
                    """
                )
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO environments (
                        id, org_id, project_id, slug, name, created_at
                    ) VALUES (
                        'environment-recovery', 'org-recovery', 'project-recovery',
                        'local', 'Local', now()
                    )
                    """
                )
            )
    finally:
        engine.dispose()


def _required_gate_client_path(name: str) -> Path:
    # The real subprocess runner refuses bare tool names, so the gate resolves
    # the pinned client wrappers that the session fixture already required.
    resolved = shutil.which(name)
    if resolved is None:
        pytest.fail(f"{name} must be resolvable for the live PostgreSQL gate", pytrace=False)
    selected = Path(resolved)
    if not selected.is_absolute():
        selected = Path.cwd() / selected
    return selected


def test_irreversible_restore_rehearsal(tmp_path: Path) -> None:
    source_url = _required_url(_SOURCE_ENV)
    target_url = _required_url(_TARGET_ENV)
    source_database = _EXPECTED_DATABASES[_SOURCE_ENV]
    target_database = _EXPECTED_DATABASES[_TARGET_ENV]
    pg_dump_path = _required_gate_client_path("pg_dump")
    pg_restore_path = _required_gate_client_path("pg_restore")
    _reset_exact_database(source_url, source_database)
    _reset_exact_database(target_url, target_database)
    try:
        _seed_recovery_source(source_url, source_database)
        expected_state = _capture_database_state_url(source_url)
        source_audit = tmp_path / "source-audit"
        source_audit.mkdir()
        bundle = tmp_path / "bundle"

        created = create_recovery_bundle(
            source_url_env=_SOURCE_ENV,
            audit_dir=source_audit,
            output=bundle,
            pg_dump_path=pg_dump_path,
            pg_restore_path=pg_restore_path,
        )
        verified = verify_recovery_bundle(bundle=bundle, pg_restore_path=pg_restore_path)
        assert created == verified

        source_engine = make_engine(source_url)
        try:
            with source_engine.begin() as connection:
                # CASCADE detaches the revision 0003/0004 foreign keys that now
                # reference environments; the corrupted source still
                # classifies as UNKNOWN.
                connection.execute(sa.text("DROP TABLE environments CASCADE"))
        finally:
            source_engine.dispose()
        assert inspect_schema(source_url).state is DatabaseSchemaState.UNKNOWN

        restored = restore_recovery_bundle(
            bundle=bundle,
            target_url_env=_TARGET_ENV,
            target_database_name=target_database,
            target_audit_dir=tmp_path / "target-audit",
            acknowledge_operator_controlled_bundle=True,
            pg_restore_path=pg_restore_path,
        )
        assert created == verified == restored
        assert _capture_database_state_url(target_url) == expected_state
        assert inspect_schema(target_url).state is DatabaseSchemaState.VERSION_0011

        target_before_refusal = _capture_database_state_url(target_url)
        with pytest.raises(RecoveryRefused, match="must have an exact empty"):
            restore_recovery_bundle(
                bundle=bundle,
                target_url_env=_TARGET_ENV,
                target_database_name=target_database,
                target_audit_dir=tmp_path / "blocked-target-audit",
                acknowledge_operator_controlled_bundle=True,
                pg_restore_path=pg_restore_path,
            )
        assert _capture_database_state_url(target_url) == target_before_refusal
    finally:
        _reset_exact_database(source_url, source_database)
        _reset_exact_database(target_url, target_database)


def test_failed_migration_no_later_state(monkeypatch: pytest.MonkeyPatch) -> None:
    database_url = _required_url(_MAIN_ENV)
    _seed_exact_alpha_schema()
    _seed_legacy_rows(database_url)
    before = migrations_pg._catalog_and_data_snapshot()
    legacy_rows = _rows(database_url, _LEGACY_TABLES)
    original_upgrade = migration_module.command.upgrade

    def _upgrade_then_fail(config: object, revision: str, **kwargs: object) -> None:
        assert isinstance(config, migration_module.Config)
        connection = config.attributes["connection"]
        assert isinstance(connection, Connection)
        assert connection.in_transaction()
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == (
            LEGACY_V0_REVISION
        )
        original_upgrade(config, revision, **kwargs)
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == (
            HEAD_REVISION
        )
        raise RuntimeError("injected failure after actual PostgreSQL Alembic upgrade")

    with monkeypatch.context() as scoped_patch:
        scoped_patch.setattr(migration_module.command, "upgrade", _upgrade_then_fail)
        with pytest.raises(
            RuntimeError,
            match="injected failure after actual PostgreSQL Alembic upgrade",
        ):
            upgrade_database(database_url, expected_database=_EXPECTED_DATABASES[_MAIN_ENV])

    assert inspect_schema(database_url).state is DatabaseSchemaState.LEGACY_V0
    assert migrations_pg._catalog_and_data_snapshot() == before
    assert _rows(database_url, _LEGACY_TABLES) == legacy_rows

    lock_engine = make_engine(database_url)
    try:
        with lock_engine.connect() as connection, connection.begin():
            assert migrations_pg._try_advisory_xact_lock(connection)
    finally:
        lock_engine.dispose()

    retried = upgrade_database(database_url, expected_database=_EXPECTED_DATABASES[_MAIN_ENV])
    assert retried.before.state is DatabaseSchemaState.LEGACY_V0
    assert retried.after.state is DatabaseSchemaState.VERSION_0011
    assert _head_version(database_url) == HEAD_REVISION
    assert _rows(database_url, _LEGACY_TABLES) == legacy_rows
