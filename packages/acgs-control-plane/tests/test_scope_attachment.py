"""Revision 0010 default-scope attachment tests."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

import acgs_control_plane.app as app_module
from acgs_control_plane.app import NativeAgentTransactionProviders, create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.db import make_engine
from acgs_control_plane.migrations import (
    _SCOPE_RESUME_TOKEN,
    DatabaseSchemaState,
    MigrationPreflightError,
    _run_controlled_operation,
    inspect_schema,
    migration_config,
    upgrade_database,
)
from acgs_control_plane.models import Environment, Organization, Project
from acgs_control_plane.scope_defaults import (
    LEGACY_DEFAULT_ENVIRONMENT_SLUG,
    LEGACY_DEFAULT_PROJECT_NAME,
    LEGACY_DEFAULT_PROJECT_SLUG,
    LegacyDefaultScopeConflict,
    ensure_legacy_default_scope,
    legacy_default_environment_id,
    legacy_default_project_id,
)


def _database_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'control-plane.sqlite3'}"


def _upgrade_to_0009(database_url: str) -> None:
    config = migration_config(database_url)
    _run_controlled_operation(
        config,
        _SCOPE_RESUME_TOKEN,
        DatabaseSchemaState.EMPTY,
        lambda: command.upgrade(config, "0009"),
    )
    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0009


def _seed_0009_org_agent_policy(database_url: str, org_id: str, name: str) -> None:
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    """
                    INSERT INTO organizations (
                        id, name, created_at, audit_anchor_count, audit_anchor_hash
                    ) VALUES (:id, :name, :created_at, 0, '')
                    """
                ),
                {"id": org_id, "name": name, "created_at": "2026-07-24T00:00:00+00:00"},
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO agents (
                        id, org_id, name, description, trust_tier,
                        allowed_tools, status, created_at
                    ) VALUES (
                        :id, :org_id, :name, '', 'internal',
                        :allowed_tools, 'active', :created_at
                    )
                    """
                ),
                {
                    "id": f"agent-{org_id}",
                    "org_id": org_id,
                    "name": f"{name} agent",
                    "allowed_tools": json.dumps(["deploy"]),
                    "created_at": "2026-07-24T00:00:00+00:00",
                },
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO policy_bundles (
                        id, org_id, policy_id, version, bundle, status, created_at, activated_at
                    ) VALUES (
                        :id, :org_id, 'policy', :version, :bundle, 'published', :created_at, NULL
                    )
                    """
                ),
                {
                    "id": f"policy-{org_id}",
                    "org_id": org_id,
                    "version": f"version-{org_id}",
                    "bundle": json.dumps({"id": "policy", "rules": []}),
                    "created_at": "2026-07-24T00:00:00+00:00",
                },
            )
    finally:
        engine.dispose()


def _seed_0009_scoped_agent(
    database_url: str, org_id: str, project_id: str, environment_id: str
) -> None:
    """Insert an already-scoped agent so the backfill must leave it untouched."""
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    """
                    INSERT INTO projects (id, org_id, slug, name, created_at)
                    VALUES (:id, :org_id, 'default', 'Default', :created_at)
                    """
                ),
                {
                    "id": project_id,
                    "org_id": org_id,
                    "created_at": "2026-07-24T00:00:00+00:00",
                },
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO environments (id, org_id, project_id, slug, name, created_at)
                    VALUES (:id, :org_id, :project_id, 'production', 'Production', :created_at)
                    """
                ),
                {
                    "id": environment_id,
                    "org_id": org_id,
                    "project_id": project_id,
                    "created_at": "2026-07-24T00:00:00+00:00",
                },
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO agents (
                        id, org_id, project_id, environment_id, name, description,
                        trust_tier, allowed_tools, status, created_at
                    ) VALUES (
                        :id, :org_id, :project_id, :environment_id, 'scoped agent', '',
                        'internal', '[]', 'active', :created_at
                    )
                    """
                ),
                {
                    "id": f"scoped-agent-{org_id}",
                    "org_id": org_id,
                    "project_id": project_id,
                    "environment_id": environment_id,
                    "created_at": "2026-07-24T00:00:00+00:00",
                },
            )
    finally:
        engine.dispose()


def _create_empty_policy_bundles_batch_temp(connection: sa.Connection) -> None:
    connection.execute(
        sa.text(
            """
            CREATE TABLE _alembic_tmp_policy_bundles (
                id VARCHAR(64),
                org_id VARCHAR(64),
                policy_id VARCHAR(200),
                version VARCHAR(200),
                bundle JSON,
                status VARCHAR(16),
                created_at DATETIME,
                activated_at DATETIME,
                project_id VARCHAR(64),
                environment_id VARCHAR(64)
            )
            """
        )
    )


def test_revision_0010_backfills_one_default_scope_per_org_and_attaches_legacy_rows(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    _upgrade_to_0009(database_url)
    _seed_0009_org_agent_policy(database_url, "org-a", "Org A")
    _seed_0009_org_agent_policy(database_url, "org-b", "Org B")

    result = upgrade_database(database_url)

    assert result.before.state is DatabaseSchemaState.VERSION_0009
    assert result.after.state is DatabaseSchemaState.VERSION_0010
    engine = make_engine(database_url)
    try:
        with engine.connect() as connection:
            projects = connection.execute(
                sa.text("SELECT org_id, id, slug FROM projects ORDER BY org_id")
            ).all()
            environments = connection.execute(
                sa.text("SELECT org_id, id, project_id, slug FROM environments ORDER BY org_id")
            ).all()
            agents = connection.execute(
                sa.text("SELECT org_id, project_id, environment_id FROM agents ORDER BY org_id")
            ).all()
            policies = connection.execute(
                sa.text(
                    "SELECT org_id, project_id, environment_id FROM policy_bundles ORDER BY org_id"
                )
            ).all()
    finally:
        engine.dispose()

    assert projects == [
        ("org-a", legacy_default_project_id("org-a"), LEGACY_DEFAULT_PROJECT_SLUG),
        ("org-b", legacy_default_project_id("org-b"), LEGACY_DEFAULT_PROJECT_SLUG),
    ]
    assert environments == [
        (
            "org-a",
            legacy_default_environment_id("org-a"),
            legacy_default_project_id("org-a"),
            LEGACY_DEFAULT_ENVIRONMENT_SLUG,
        ),
        (
            "org-b",
            legacy_default_environment_id("org-b"),
            legacy_default_project_id("org-b"),
            LEGACY_DEFAULT_ENVIRONMENT_SLUG,
        ),
    ]
    assert agents == [
        ("org-a", legacy_default_project_id("org-a"), legacy_default_environment_id("org-a")),
        ("org-b", legacy_default_project_id("org-b"), legacy_default_environment_id("org-b")),
    ]
    assert policies == [
        ("org-a", legacy_default_project_id("org-a"), legacy_default_environment_id("org-a")),
        ("org-b", legacy_default_project_id("org-b"), legacy_default_environment_id("org-b")),
    ]


def test_revision_0010_leaves_already_scoped_agents_untouched(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)
    _upgrade_to_0009(database_url)
    _seed_0009_org_agent_policy(database_url, "org-a", "Org A")
    _seed_0009_scoped_agent(database_url, "org-a", "project-managed", "environment-managed")

    result = upgrade_database(database_url)
    assert result.after.state is DatabaseSchemaState.VERSION_0010

    engine = make_engine(database_url)
    try:
        with engine.connect() as connection:
            agents = dict(
                connection.execute(
                    sa.text("SELECT id, environment_id FROM agents ORDER BY id")
                ).all()
            )
    finally:
        engine.dispose()

    assert agents == {
        "agent-org-a": legacy_default_environment_id("org-a"),
        "scoped-agent-org-a": "environment-managed",
    }


def test_scope_attachment_constraints_reject_half_scoped_and_cross_tenant_rows(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    _upgrade_to_0009(database_url)
    _seed_0009_org_agent_policy(database_url, "org-a", "Org A")
    _seed_0009_org_agent_policy(database_url, "org-b", "Org B")
    upgrade_database(database_url)

    engine = make_engine(database_url)
    try:
        # Half-attached scope (environment without project) violates the
        # both-null-or-both-set check on each table.
        with engine.begin() as connection:
            with pytest.raises(sa.exc.IntegrityError):
                connection.execute(
                    sa.text(
                        """
                        INSERT INTO agents (
                            id, org_id, environment_id, name, description, trust_tier,
                            allowed_tools, status, created_at
                        ) VALUES (
                            'agent-half-scope', 'org-a', :environment_id, 'half scope',
                            '', 'internal', '[]', 'active', :created_at
                        )
                        """
                    ),
                    {
                        "environment_id": legacy_default_environment_id("org-a"),
                        "created_at": "2026-07-24T00:00:00+00:00",
                    },
                )
        with engine.begin() as connection:
            with pytest.raises(sa.exc.IntegrityError):
                connection.execute(
                    sa.text(
                        """
                        UPDATE policy_bundles
                        SET project_id = NULL
                        WHERE id = 'policy-org-a'
                        """
                    )
                )
        # A scope pair pointing at another tenant's environment violates the
        # composite (org_id, project_id, environment_id) foreign key.
        with engine.begin() as connection:
            with pytest.raises(sa.exc.IntegrityError):
                connection.execute(
                    sa.text(
                        """
                        INSERT INTO agents (
                            id, org_id, project_id, environment_id, name, description,
                            trust_tier, allowed_tools, status, created_at
                        ) VALUES (
                            'agent-cross-env', 'org-a', :project_id, :environment_id,
                            'cross env', '', 'internal', '[]', 'active', :created_at
                        )
                        """
                    ),
                    {
                        "project_id": legacy_default_project_id("org-b"),
                        "environment_id": legacy_default_environment_id("org-b"),
                        "created_at": "2026-07-24T00:00:00+00:00",
                    },
                )
        with engine.begin() as connection:
            with pytest.raises(sa.exc.IntegrityError):
                connection.execute(
                    sa.text(
                        """
                        UPDATE policy_bundles
                        SET project_id = :project_id, environment_id = :environment_id
                        WHERE id = 'policy-org-a'
                        """
                    ),
                    {
                        "project_id": legacy_default_project_id("org-b"),
                        "environment_id": legacy_default_environment_id("org-b"),
                    },
                )
    finally:
        engine.dispose()


def test_ensure_legacy_default_scope_rolls_back_cleanly_on_duplicate_default_slug(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    upgrade_database(database_url)

    engine = make_engine(database_url)
    try:
        with Session(engine) as session:
            session.add(Organization(id="org-conflict", name="Conflict Org"))
            session.commit()

        with pytest.raises(LegacyDefaultScopeConflict, match="legacy default project"):
            with Session(engine) as session, session.begin():
                session.add(
                    Project(
                        id="wrong-default-project",
                        org_id="org-conflict",
                        slug=LEGACY_DEFAULT_PROJECT_SLUG,
                        name="Wrong Default",
                    )
                )
                session.flush()
                ensure_legacy_default_scope(session, "org-conflict")

        with engine.connect() as connection:
            assert (
                connection.scalar(
                    sa.text("SELECT count(*) FROM projects WHERE org_id = 'org-conflict'")
                )
                == 0
            )
            assert (
                connection.scalar(
                    sa.text("SELECT count(*) FROM environments WHERE org_id = 'org-conflict'")
                )
                == 0
            )
            assert connection.scalar(sa.text("SELECT count(*) FROM agents")) == 0
            assert connection.scalar(sa.text("SELECT count(*) FROM policy_bundles")) == 0
    finally:
        engine.dispose()


def test_ensure_legacy_default_scope_rejects_wrong_canonical_display_names(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    upgrade_database(database_url)

    engine = make_engine(database_url)
    try:
        with Session(engine) as session:
            session.add(Organization(id="org-wrong-project-name", name="Wrong Project Name Org"))
            session.add(
                Project(
                    id=legacy_default_project_id("org-wrong-project-name"),
                    org_id="org-wrong-project-name",
                    slug=LEGACY_DEFAULT_PROJECT_SLUG,
                    name="Misleading default project",
                )
            )
            session.commit()

        with pytest.raises(LegacyDefaultScopeConflict, match="project slug/id/name"):
            with Session(engine) as session:
                ensure_legacy_default_scope(session, "org-wrong-project-name")

        with Session(engine) as session:
            session.add(
                Organization(id="org-wrong-environment-name", name="Wrong Environment Name Org")
            )
            session.add(
                Project(
                    id=legacy_default_project_id("org-wrong-environment-name"),
                    org_id="org-wrong-environment-name",
                    slug=LEGACY_DEFAULT_PROJECT_SLUG,
                    name=LEGACY_DEFAULT_PROJECT_NAME,
                )
            )
            session.add(
                Environment(
                    id=legacy_default_environment_id("org-wrong-environment-name"),
                    org_id="org-wrong-environment-name",
                    project_id=legacy_default_project_id("org-wrong-environment-name"),
                    slug=LEGACY_DEFAULT_ENVIRONMENT_SLUG,
                    name="Misleading default environment",
                )
            )
            session.commit()

        with pytest.raises(LegacyDefaultScopeConflict, match="environment slug/id/name"):
            with Session(engine) as session:
                ensure_legacy_default_scope(session, "org-wrong-environment-name")
    finally:
        engine.dispose()


def test_ensure_legacy_default_scope_returns_the_deterministic_scope_pair(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    upgrade_database(database_url)

    engine = make_engine(database_url)
    try:
        with Session(engine) as session, session.begin():
            session.add(Organization(id="org-pair", name="Pair Org"))
            session.flush()
            first = ensure_legacy_default_scope(session, "org-pair")
            second = ensure_legacy_default_scope(session, "org-pair")

        expected = (
            legacy_default_project_id("org-pair"),
            legacy_default_environment_id("org-pair"),
        )
        assert first == expected
        assert second == expected
    finally:
        engine.dispose()


def test_revision_0010_rejects_wrong_canonical_default_display_names(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    _upgrade_to_0009(database_url)
    _seed_0009_org_agent_policy(database_url, "org-wrong-name", "Wrong Name Org")

    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    """
                    INSERT INTO projects (id, org_id, slug, name, created_at)
                    VALUES (:id, :org_id, :slug, :name, :created_at)
                    """
                ),
                {
                    "id": legacy_default_project_id("org-wrong-name"),
                    "org_id": "org-wrong-name",
                    "slug": LEGACY_DEFAULT_PROJECT_SLUG,
                    "name": "Misleading default project",
                    "created_at": "2026-07-24T00:00:00+00:00",
                },
            )
    finally:
        engine.dispose()

    with pytest.raises(RuntimeError, match="project slug/id/name conflict"):
        upgrade_database(database_url)

    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0009


def test_revision_0010_refuses_orphan_legacy_agents_before_schema_mutation(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    _upgrade_to_0009(database_url)

    engine = make_engine(database_url)
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            connection.execute(
                sa.text(
                    """
                    INSERT INTO agents (
                        id, org_id, name, description, trust_tier,
                        allowed_tools, status, created_at
                    ) VALUES (
                        'agent-orphan', 'missing-org', 'orphan', '',
                        'internal', '[]', 'active', :created_at
                    )
                    """
                ),
                {"created_at": "2026-07-24T00:00:00+00:00"},
            )
            connection.commit()
    finally:
        engine.dispose()

    with pytest.raises(RuntimeError, match="refused orphan legacy rows"):
        upgrade_database(database_url)

    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0009
    engine = make_engine(database_url)
    try:
        with engine.connect() as connection:
            assert "project_id" not in {
                column["name"] for column in sa.inspect(connection).get_columns("policy_bundles")
            }
            assert not any(
                table_name.startswith("_alembic_tmp_")
                for table_name in sa.inspect(connection).get_table_names()
            )
    finally:
        engine.dispose()


@pytest.mark.parametrize("added_columns", [("project_id",), ("project_id", "environment_id")])
def test_revision_0010_retry_completes_after_scope_column_interruption(
    tmp_path: Path, added_columns: tuple[str, ...]
) -> None:
    database_url = _database_url(tmp_path)
    _upgrade_to_0009(database_url)
    _seed_0009_org_agent_policy(database_url, "org-a", "Org A")

    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            for column_name in added_columns:
                connection.execute(
                    sa.text(f"ALTER TABLE policy_bundles ADD COLUMN {column_name} VARCHAR(64)")
                )
        preflight = inspect_schema(database_url)
    finally:
        engine.dispose()

    assert preflight.state is DatabaseSchemaState.VERSION_0009_PARTIAL_SCOPE_ATTACHMENT
    result = upgrade_database(database_url)
    assert result.before.state is DatabaseSchemaState.VERSION_0009_PARTIAL_SCOPE_ATTACHMENT
    assert result.after.state is DatabaseSchemaState.VERSION_0010


def test_revision_0010_retry_drops_safe_leftover_batch_temp_table(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    _upgrade_to_0009(database_url)
    _seed_0009_org_agent_policy(database_url, "org-a", "Org A")

    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            _create_empty_policy_bundles_batch_temp(connection)
        assert (
            inspect_schema(database_url).state
            is DatabaseSchemaState.VERSION_0009_PARTIAL_SCOPE_ATTACHMENT
        )
    finally:
        engine.dispose()

    result = upgrade_database(database_url)
    assert result.before.state is DatabaseSchemaState.VERSION_0009_PARTIAL_SCOPE_ATTACHMENT
    assert result.after.state is DatabaseSchemaState.VERSION_0010


def test_revision_0010_refuses_malformed_batch_temp_table_before_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url = _database_url(tmp_path)
    _upgrade_to_0009(database_url)

    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("CREATE TABLE _alembic_tmp_policy_bundles (secret TEXT)"))
        assert inspect_schema(database_url).state is DatabaseSchemaState.UNKNOWN
    finally:
        engine.dispose()

    with pytest.raises(MigrationPreflightError, match="malformed columns"):
        upgrade_database(database_url)
    with pytest.raises(MigrationPreflightError, match="Refusing a raw Alembic operation"):
        command.upgrade(migration_config(database_url), "head")

    revision_path = (
        Path(__file__).parents[1]
        / "src"
        / "acgs_control_plane"
        / "migrations"
        / "versions"
        / "0010_scope_attachment.py"
    )
    spec = importlib.util.spec_from_file_location("revision_0010_scope_attachment", revision_path)
    assert spec is not None and spec.loader is not None
    revision_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(revision_module)
    engine = make_engine(database_url)
    try:
        with engine.connect() as connection:
            monkeypatch.setattr(revision_module.op, "get_bind", lambda: connection)
            with pytest.raises(RuntimeError, match="malformed columns"):
                revision_module.upgrade()
    finally:
        engine.dispose()


def test_revision_0010_refuses_data_bearing_batch_temp_table_before_retry(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    _upgrade_to_0009(database_url)

    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            _create_empty_policy_bundles_batch_temp(connection)
            connection.execute(
                sa.text(
                    """
                    INSERT INTO _alembic_tmp_policy_bundles (
                        id, org_id, policy_id, version, bundle, status,
                        created_at, activated_at, project_id, environment_id
                    ) VALUES (
                        'tmp-policy', 'org-a', 'policy', 'v1', '{}', 'published',
                        :created_at, NULL, 'tmp-project', 'tmp-env'
                    )
                    """
                ),
                {"created_at": "2026-07-24T00:00:00+00:00"},
            )
        assert inspect_schema(database_url).state is DatabaseSchemaState.UNKNOWN
    finally:
        engine.dispose()

    with pytest.raises(MigrationPreflightError, match="contains data"):
        upgrade_database(database_url)


def test_revision_0010_refuses_missing_base_table_batch_recovery(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    _upgrade_to_0009(database_url)

    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            _create_empty_policy_bundles_batch_temp(connection)
            connection.execute(sa.text("DROP TABLE policy_bundles"))
        assert (
            inspect_schema(database_url).state
            is DatabaseSchemaState.VERSION_0009_PARTIAL_SCOPE_ATTACHMENT
        )
    finally:
        engine.dispose()

    with pytest.raises(RuntimeError, match="recovery refused"):
        upgrade_database(database_url)


def test_org_bootstrap_seeds_default_scope_and_mutations_reuse_it(
    tmp_path: Path,
    native_agent_transaction_providers: NativeAgentTransactionProviders,
) -> None:
    database_url = _database_url(tmp_path)
    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=tmp_path / "audit",
            bootstrap_token="bootstrap",
            create_tables=True,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        ),
        native_agent_transaction=native_agent_transaction_providers,
    )
    try:
        client = TestClient(app, raise_server_exceptions=False)
        org_response = client.post(
            "/orgs",
            json={
                "name": "Scoped Org",
                "admin_name": "Root Admin",
                "admin_email": "root@scoped.example.com",
            },
            headers={"X-Bootstrap-Token": "bootstrap"},
        )
        assert org_response.status_code == 201, org_response.text
        org = org_response.json()
        headers = {"X-API-Key": org["admin_api_key"]}
        assert (
            client.post(
                f"/orgs/{org['org_id']}/policies",
                json={
                    "policy_id": "policy",
                    "rules": [{"id": "deny-never", "effect": "deny", "tools": ["never"]}],
                },
                headers=headers,
            ).status_code
            == 201
        )
    finally:
        app.state.engine.dispose()

    engine = make_engine(database_url)
    try:
        with engine.connect() as connection:
            org_id = org["org_id"]
            project_id = legacy_default_project_id(org_id)
            environment_id = legacy_default_environment_id(org_id)
            assert (
                connection.scalar(
                    sa.text(
                        """
                        SELECT count(*) FROM projects
                        WHERE org_id = :org_id AND id = :project_id
                        """
                    ),
                    {"org_id": org_id, "project_id": project_id},
                )
                == 1
            )
            assert (
                connection.scalar(
                    sa.text(
                        """
                        SELECT count(*) FROM environments
                        WHERE org_id = :org_id AND id = :environment_id
                        """
                    ),
                    {"org_id": org_id, "environment_id": environment_id},
                )
                == 1
            )
            assert connection.execute(
                sa.text(
                    "SELECT project_id, environment_id FROM policy_bundles WHERE org_id = :org_id"
                ),
                {"org_id": org_id},
            ).all() == [(project_id, environment_id)]
    finally:
        engine.dispose()


def test_org_bootstrap_rolls_back_if_default_scope_cannot_be_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url = _database_url(tmp_path)
    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=tmp_path / "audit",
            bootstrap_token="bootstrap",
            create_tables=True,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        )
    )

    def fail_default_scope(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("injected default scope failure")

    monkeypatch.setattr(app_module, "ensure_legacy_default_scope", fail_default_scope)
    try:
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/orgs",
            json={
                "name": "Broken Scope Org",
                "admin_name": "Root Admin",
                "admin_email": "root@broken.example.com",
            },
            headers={"X-Bootstrap-Token": "bootstrap"},
        )
        assert response.status_code == 500
    finally:
        app.state.engine.dispose()

    engine = make_engine(database_url)
    try:
        with engine.connect() as connection:
            assert connection.scalar(sa.text("SELECT count(*) FROM organizations")) == 0
            assert connection.scalar(sa.text("SELECT count(*) FROM users")) == 0
            assert connection.scalar(sa.text("SELECT count(*) FROM projects")) == 0
            assert connection.scalar(sa.text("SELECT count(*) FROM environments")) == 0
    finally:
        engine.dispose()


def test_scope_attachment_does_not_add_project_or_environment_routes(tmp_path: Path) -> None:
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
        paths = set(app.openapi()["paths"])
    finally:
        app.state.engine.dispose()

    assert not any("projects" in path or "environments" in path for path in paths)
