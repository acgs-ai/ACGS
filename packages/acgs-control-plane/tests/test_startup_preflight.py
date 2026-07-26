"""Application-factory gates for migration-managed startup."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.testclient import TestClient

import acgs_control_plane.app as app_module
from acgs_control_plane.app import create_app
from acgs_control_plane.config import (
    RuntimePosture,
    RuntimePostureConfigurationError,
    Settings,
)
from acgs_control_plane.db import Base, make_engine
from acgs_control_plane.governance import ProductionPostureBlocked
from acgs_control_plane.migrations import (
    DatabaseSchemaState,
    StartupSchemaPreflightError,
    inspect_schema,
    upgrade_database,
)


def _database_url(path: Path) -> str:
    return f"sqlite:///{path}"


def _schema_managed_local_settings(database_url: str, audit_dir: Path) -> Settings:
    return Settings(
        database_url=database_url,
        audit_dir=audit_dir,
        create_tables=False,
        runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _create_version_table(connection: sa.Connection, version: str = "0001") -> None:
    connection.execute(
        sa.text("CREATE TABLE alembic_version (version_num VARCHAR(32) PRIMARY KEY)")
    )
    connection.execute(
        sa.text("INSERT INTO alembic_version (version_num) VALUES (:version)"),
        {"version": version},
    )


def _seed_empty(database_url: str) -> None:
    engine = make_engine(database_url)
    try:
        with engine.connect():
            pass
    finally:
        engine.dispose()


def _seed_legacy_v0(database_url: str) -> None:
    engine = make_engine(database_url)
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()


def _seed_version_0001(database_url: str) -> None:
    _seed_legacy_v0(database_url)
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            _create_version_table(connection)
    finally:
        engine.dispose()


def _seed_partial_0001(database_url: str) -> None:
    _seed_version_0001(database_url)
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    """
                    CREATE TABLE projects (
                        id VARCHAR(64) NOT NULL,
                        org_id VARCHAR(64) NOT NULL,
                        slug VARCHAR(128) NOT NULL,
                        name VARCHAR(200) NOT NULL,
                        created_at DATETIME NOT NULL,
                        PRIMARY KEY (id),
                        FOREIGN KEY(org_id) REFERENCES organizations (id),
                        CONSTRAINT uq_projects_org_slug UNIQUE (org_id, slug),
                        CONSTRAINT uq_projects_org_id_id UNIQUE (org_id, id)
                    )
                    """
                )
            )
    finally:
        engine.dispose()


def _seed_future(database_url: str) -> None:
    upgrade_database(database_url)
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("UPDATE alembic_version SET version_num = '9999'"))
    finally:
        engine.dispose()


def _seed_unknown(database_url: str) -> None:
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("CREATE TABLE unexpected (id INTEGER PRIMARY KEY)"))
            connection.execute(sa.text("INSERT INTO unexpected (id) VALUES (17)"))
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    ("seed", "expected_state"),
    [
        (_seed_empty, DatabaseSchemaState.EMPTY),
        (_seed_legacy_v0, DatabaseSchemaState.LEGACY_V0),
        (_seed_version_0001, DatabaseSchemaState.VERSION_0001),
        (_seed_partial_0001, DatabaseSchemaState.VERSION_0001_PARTIAL_PROJECTS),
        (_seed_future, DatabaseSchemaState.UNKNOWN),
        (_seed_unknown, DatabaseSchemaState.UNKNOWN),
    ],
    ids=("empty", "legacy-v0", "version-0001", "partial-0001", "future", "unknown"),
)
def test_schema_managed_startup_rejects_noncurrent_schema_without_mutation_or_session_wiring(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    seed: Callable[[str], None],
    expected_state: DatabaseSchemaState,
) -> None:
    database_path = tmp_path / "control-plane.sqlite3"
    database_url = _database_url(database_path)
    audit_dir = tmp_path / "audit"
    seed(database_url)
    assert inspect_schema(database_url).state is expected_state
    before = _sha256(database_path)
    calls = {"create_all": 0, "session_factory": 0}

    def forbidden_create_all(*_args: object, **_kwargs: object) -> None:
        calls["create_all"] += 1
        raise AssertionError("production startup invoked create_all")

    def forbidden_session_factory(*_args: object, **_kwargs: object) -> object:
        calls["session_factory"] += 1
        raise AssertionError("session/worker wiring occurred before schema refusal")

    monkeypatch.setattr(app_module.Base.metadata, "create_all", forbidden_create_all)
    monkeypatch.setattr(app_module, "make_session_factory", forbidden_session_factory)

    with pytest.raises(StartupSchemaPreflightError) as stopped:
        create_app(_schema_managed_local_settings(database_url, audit_dir))

    assert stopped.value.schema_state is expected_state
    assert calls == {"create_all": 0, "session_factory": 0}
    assert _sha256(database_path) == before
    assert inspect_schema(database_url).state is expected_state
    assert not audit_dir.exists()


def test_exact_head_production_still_refuses_legacy_unsigned_routes_before_persistence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url = _database_url(tmp_path / "control-plane.sqlite3")
    upgrade_database(database_url)
    database_path = tmp_path / "control-plane.sqlite3"
    before = _sha256(database_path)
    calls = {"engine": 0, "session_factory": 0}

    def forbidden_engine(_database_url: str) -> object:
        calls["engine"] += 1
        raise AssertionError("production posture constructed persistence")

    def forbidden_session_factory(*_args: object, **_kwargs: object) -> object:
        calls["session_factory"] += 1
        raise AssertionError("production posture constructed a session factory")

    monkeypatch.setattr(app_module, "make_engine", forbidden_engine)
    monkeypatch.setattr(app_module, "make_session_factory", forbidden_session_factory)
    with pytest.raises(ProductionPostureBlocked) as stopped:
        create_app(
            Settings(
                database_url=database_url,
                audit_dir=tmp_path / "audit",
                create_tables=False,
                runtime_posture=RuntimePosture.PRODUCTION,
            )
        )

    assert calls == {"engine": 0, "session_factory": 0}
    legacy_routes = [
        blocker for blocker in stopped.value.blockers if blocker.code == "LEGACY_UNSIGNED_WRITE"
    ]
    # Master aliases every legacy write under /v1 (14 = 7 routes x 2), and this
    # branch governs agent registration with receipt v2, so that route pair is
    # no longer an unsigned legacy write: 6 remaining routes x 2 aliases.
    assert len(legacy_routes) == 12
    assert {blocker.route for blocker in legacy_routes} == {
        "PATCH /orgs/{org_id}/agents/{agent_id}/status",
        "PATCH /v1/orgs/{org_id}/agents/{agent_id}/status",
        "POST /orgs",
        "POST /v1/orgs",
        "POST /orgs/{org_id}/exports",
        "POST /v1/orgs/{org_id}/exports",
        "POST /orgs/{org_id}/policies",
        "POST /v1/orgs/{org_id}/policies",
        "POST /orgs/{org_id}/policies/{bundle_id}/activate",
        "POST /v1/orgs/{org_id}/policies/{bundle_id}/activate",
        "POST /orgs/{org_id}/users",
        "POST /v1/orgs/{org_id}/users",
    }
    assert _sha256(database_path) == before
    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0008
    assert not (tmp_path / "audit").exists()


def test_exact_head_schema_evidence_is_nonproduction_and_never_ready(tmp_path: Path) -> None:
    database_path = tmp_path / "control-plane.sqlite3"
    database_url = _database_url(database_path)
    upgrade_database(database_url)
    before = _sha256(database_path)
    app = create_app(_schema_managed_local_settings(database_url, tmp_path / "audit"))
    try:
        client = TestClient(app)
        assert client.get("/healthz").json() == {"status": "ok"}
        ready = client.get("/readyz")
        assert ready.status_code == 503
        assert ready.json() == {
            "code": ProductionPostureBlocked.code,
            "stage": ProductionPostureBlocked.stage,
            "status": "not-production-ready",
            "blockers": [blocker.to_dict() for blocker in app.state.readiness_blockers],
            "schema_current": True,
            "schema_state": DatabaseSchemaState.VERSION_0008.value,
        }
        assert app.state.schema_preflight.state is DatabaseSchemaState.VERSION_0008
        assert not (tmp_path / "audit").exists()
    finally:
        app.state.engine.dispose()
    assert _sha256(database_path) == before


def test_application_shutdown_disposes_its_database_engine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url = _database_url(tmp_path / "local.sqlite3")
    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=tmp_path / "audit",
            create_tables=True,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        )
    )
    calls = {"dispose": 0}
    real_dispose = app.state.engine.dispose

    def dispose() -> None:
        calls["dispose"] += 1
        real_dispose()

    monkeypatch.setattr(app.state.engine, "dispose", dispose)
    with TestClient(app) as client:
        assert client.get("/healthz").status_code == 200

    assert calls == {"dispose": 1}


def test_unclassified_future_write_route_keeps_production_blocked_before_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_register = app_module._register_routes
    calls = {"engine": 0}

    def register_with_future_write(app: FastAPI) -> None:
        original_register(app)

        @app.put("/future-write")
        def future_write() -> dict[str, bool]:
            return {"unexpected": True}

    def forbidden_engine(_database_url: str) -> object:
        calls["engine"] += 1
        raise AssertionError("unclassified production route reached persistence")

    monkeypatch.setattr(app_module, "_register_routes", register_with_future_write)
    monkeypatch.setattr(app_module, "make_engine", forbidden_engine)
    with pytest.raises(ProductionPostureBlocked) as stopped:
        create_app(Settings(runtime_posture=RuntimePosture.PRODUCTION))

    assert calls == {"engine": 0}
    assert any(
        blocker.code == "UNCLASSIFIED_ROUTE" and blocker.route == "PUT /future-write"
        for blocker in stopped.value.blockers
    )


def test_local_dev_bootstrap_is_explicit_and_never_reports_production_ready(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path / "local.sqlite3")
    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=tmp_path / "audit",
            create_tables=True,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        )
    )
    try:
        ready = TestClient(app).get("/readyz")
        assert ready.status_code == 503
        assert ready.json() == {
            "code": ProductionPostureBlocked.code,
            "stage": ProductionPostureBlocked.stage,
            "status": "not-production-ready",
            "blockers": [blocker.to_dict() for blocker in app.state.readiness_blockers],
            "schema_current": False,
            "schema_state": DatabaseSchemaState.LEGACY_V0.value,
        }
    finally:
        app.state.engine.dispose()


@pytest.mark.parametrize(
    ("posture", "blocker"),
    [
        (None, "RUNTIME_POSTURE_REQUIRED"),
        ("typo", "RUNTIME_POSTURE_UNKNOWN"),
    ],
)
def test_missing_or_unknown_posture_refuses_before_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    posture: RuntimePosture | str | None,
    blocker: str,
) -> None:
    calls = {"engine": 0}

    def forbidden_engine(_database_url: str) -> object:
        calls["engine"] += 1
        raise AssertionError("engine constructed before posture refusal")

    monkeypatch.setattr(app_module, "make_engine", forbidden_engine)
    settings = Settings(database_url="sqlite://", runtime_posture=None)
    object.__setattr__(settings, "runtime_posture", posture)
    with pytest.raises(ProductionPostureBlocked) as stopped:
        create_app(settings)
    assert {reason.code for reason in stopped.value.blockers} == {blocker}
    assert calls == {"engine": 0}


def test_production_cannot_enable_local_schema_bootstrap_before_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"engine": 0}

    def forbidden_engine(_database_url: str) -> object:
        calls["engine"] += 1
        raise AssertionError("engine constructed for forbidden production bootstrap")

    monkeypatch.setattr(app_module, "make_engine", forbidden_engine)
    with pytest.raises(ProductionPostureBlocked) as stopped:
        create_app(
            Settings(
                database_url="sqlite://",
                create_tables=True,
                runtime_posture=RuntimePosture.PRODUCTION,
            )
        )
    assert {reason.code for reason in stopped.value.blockers} == {
        "PRODUCTION_SCHEMA_BOOTSTRAP_FORBIDDEN"
    }
    assert calls == {"engine": 0}


def test_environment_posture_is_required_and_unknown_values_are_stable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ACP_RUNTIME_POSTURE", raising=False)
    assert Settings.from_env().runtime_posture is None

    monkeypatch.setenv("ACP_RUNTIME_POSTURE", "prod-ish")
    with pytest.raises(RuntimePostureConfigurationError) as stopped:
        Settings.from_env()
    assert "RUNTIME_POSTURE_UNKNOWN" in str(stopped.value)
    assert "prod-ish" not in str(stopped.value)
    assert stopped.value.__cause__ is None
    assert stopped.value.__context__ is None

    monkeypatch.setenv("ACP_RUNTIME_POSTURE", RuntimePosture.PRODUCTION.value)
    monkeypatch.delenv("ACP_CREATE_TABLES", raising=False)
    settings = Settings.from_env()
    assert settings.runtime_posture is RuntimePosture.PRODUCTION
    assert settings.create_tables is False
