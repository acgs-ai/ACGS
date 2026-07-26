"""Revision 0006 attaches agents to exactly one project/environment.

The attachment lives in its own Alembic-managed table rather than as columns on
``agents``. ``agents`` is a frozen revision-0001 table that
``metadata.create_all`` still reproduces verbatim so a fresh database is
recognized as "current metadata-created v0 schema" and stamped at 0001 before
being migrated forward; adding columns to it would break that adoption path.

These tests pin both halves of that decision: the scope rules themselves, and
the v0 metadata contract they must not disturb.
"""

from __future__ import annotations

import importlib.util
from datetime import UTC, datetime
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from sqlalchemy.exc import IntegrityError

from acgs_control_plane import migrations as migration_module
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.db import make_engine
from acgs_control_plane.migrations import (
    DatabaseSchemaState,
    MigrationPreflightError,
    inspect_schema,
    migration_config,
    upgrade_database,
)

TENANT_BOOTSTRAP_REVISION = "0005"


def _url(tmp_path: Path, name: str = "control-plane") -> str:
    return f"sqlite:///{tmp_path / f'{name}.sqlite3'}"


def _stage_at_tenant_bootstrap(database_url: str) -> None:
    """Bring an empty database to revision 0005, the revision before scope.

    Raw Alembic commands are refused by the preflight guard, so this goes
    through the same controlled-operation path production uses -- it just stops
    one revision short of head.
    """
    config = migration_config(database_url)
    migration_module._run_controlled_operation(  # type: ignore[attr-defined]
        config,
        migration_module._SCOPE_RESUME_TOKEN,  # type: ignore[attr-defined]
        DatabaseSchemaState.EMPTY,
        lambda: command.upgrade(config, TENANT_BOOTSTRAP_REVISION),
    )


def _seed_org_project_environment(engine: sa.Engine, suffix: str = "") -> dict[str, str]:
    """Insert one organization, project, and environment with known ids."""
    ids = {
        "org": f"org{suffix}",
        "project": f"proj{suffix}",
        "environment": f"env{suffix}",
    }
    now = datetime.now(UTC)
    with engine.begin() as connection:
        connection.execute(
            sa.text(
                "INSERT INTO organizations (id, name, created_at, audit_anchor_count,"
                " audit_anchor_hash) VALUES (:id, :name, :now, 0, '')"
            ),
            {"id": ids["org"], "name": f"org-{suffix or '0'}", "now": now},
        )
        connection.execute(
            sa.text(
                "INSERT INTO projects (id, org_id, slug, name, created_at)"
                " VALUES (:id, :org, :slug, :name, :now)"
            ),
            {
                "id": ids["project"],
                "org": ids["org"],
                "slug": f"p{suffix or '0'}",
                "name": "project",
                "now": now,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO environments (id, org_id, project_id, slug, name, created_at)"
                " VALUES (:id, :org, :project, :slug, :name, :now)"
            ),
            {
                "id": ids["environment"],
                "org": ids["org"],
                "project": ids["project"],
                "slug": f"e{suffix or '0'}",
                "name": "environment",
                "now": now,
            },
        )
    return ids


def _insert_agent(engine: sa.Engine, agent_id: str, org_id: str) -> None:
    with engine.begin() as connection:
        connection.execute(
            sa.text(
                "INSERT INTO agents (id, org_id, name, description, trust_tier,"
                " allowed_tools, status, created_at)"
                " VALUES (:id, :org, :name, '', 'untrusted', '[]', 'active', :now)"
            ),
            {"id": agent_id, "org": org_id, "name": agent_id, "now": datetime.now(UTC)},
        )


def _attach(
    engine: sa.Engine,
    *,
    agent_id: str,
    org_id: str,
    project_id: str,
    environment_id: str,
) -> None:
    with engine.begin() as connection:
        connection.execute(
            sa.text(
                "INSERT INTO agent_environment_scope"
                " (agent_id, org_id, project_id, environment_id, created_at)"
                " VALUES (:agent, :org, :project, :environment, :now)"
            ),
            {
                "agent": agent_id,
                "org": org_id,
                "project": project_id,
                "environment": environment_id,
                "now": datetime.now(UTC),
            },
        )


def test_existing_agents_survive_the_scope_migration(tmp_path: Path) -> None:
    """An agent written before 0006 keeps every value and gains no attachment.

    This is the migration-safety claim for a populated table: revision 0006
    must not rewrite, re-key, or invent scope for rows that predate it.
    """
    url = _url(tmp_path)
    _stage_at_tenant_bootstrap(url)
    assert inspect_schema(url).state is DatabaseSchemaState.VERSION_0005

    engine = make_engine(url)
    ids = _seed_org_project_environment(engine)
    _insert_agent(engine, "legacy-agent", ids["org"])
    with engine.begin() as connection:
        before = dict(
            connection.execute(sa.text("SELECT * FROM agents WHERE id = 'legacy-agent'"))
            .mappings()
            .one()
        )

    result = upgrade_database(url)
    assert result.after.state is DatabaseSchemaState.VERSION_0006

    engine = make_engine(url)
    with engine.begin() as connection:
        after = dict(
            connection.execute(sa.text("SELECT * FROM agents WHERE id = 'legacy-agent'"))
            .mappings()
            .one()
        )
        attachments = connection.execute(
            sa.text("SELECT COUNT(*) FROM agent_environment_scope")
        ).scalar_one()

    assert after == before
    # No provenance is invented: the row is simply unattached.
    assert attachments == 0


def test_agent_belongs_to_exactly_one_environment(tmp_path: Path) -> None:
    """A second attachment for the same agent is unrepresentable."""
    url = _url(tmp_path)
    upgrade_database(url)
    engine = make_engine(url)
    ids = _seed_org_project_environment(engine)
    _insert_agent(engine, "agent-a", ids["org"])

    with engine.begin() as connection:
        connection.execute(
            sa.text(
                "INSERT INTO environments (id, org_id, project_id, slug, name, created_at)"
                " VALUES ('env-second', :org, :project, 'second', 'second', :now)"
            ),
            {"org": ids["org"], "project": ids["project"], "now": datetime.now(UTC)},
        )

    _attach(
        engine,
        agent_id="agent-a",
        org_id=ids["org"],
        project_id=ids["project"],
        environment_id=ids["environment"],
    )
    with pytest.raises(IntegrityError):
        _attach(
            engine,
            agent_id="agent-a",
            org_id=ids["org"],
            project_id=ids["project"],
            environment_id="env-second",
        )

    with engine.begin() as connection:
        assert (
            connection.execute(
                sa.text("SELECT COUNT(*) FROM agent_environment_scope WHERE agent_id='agent-a'")
            ).scalar_one()
            == 1
        )


def test_attachment_environment_must_exist(tmp_path: Path) -> None:
    """Attaching to an environment that does not exist is a database error."""
    url = _url(tmp_path)
    upgrade_database(url)
    engine = make_engine(url)
    ids = _seed_org_project_environment(engine)
    _insert_agent(engine, "agent-a", ids["org"])

    with pytest.raises(IntegrityError):
        _attach(
            engine,
            agent_id="agent-a",
            org_id=ids["org"],
            project_id=ids["project"],
            environment_id="no-such-environment",
        )


def test_attachment_cannot_cross_organizations(tmp_path: Path) -> None:
    """An agent cannot be attached to another organization's environment.

    This is the cross-scope claim: it fails at the database boundary, not in an
    API route or ORM query, so no application path can bypass it.
    """
    url = _url(tmp_path)
    upgrade_database(url)
    engine = make_engine(url)
    first = _seed_org_project_environment(engine, suffix="1")
    second = _seed_org_project_environment(engine, suffix="2")
    _insert_agent(engine, "agent-a", first["org"])

    # Claiming org 1 (so the agent FK holds) while pointing at org 2's
    # environment fails the environment FK.
    with pytest.raises(IntegrityError):
        _attach(
            engine,
            agent_id="agent-a",
            org_id=first["org"],
            project_id=second["project"],
            environment_id=second["environment"],
        )

    # Claiming org 2 to match the environment fails the agent FK instead: the
    # agent does not belong to org 2. Neither direction is representable.
    with pytest.raises(IntegrityError):
        _attach(
            engine,
            agent_id="agent-a",
            org_id=second["org"],
            project_id=second["project"],
            environment_id=second["environment"],
        )


def test_attachment_cannot_cross_projects(tmp_path: Path) -> None:
    """The environment must belong to the project the attachment names."""
    url = _url(tmp_path)
    upgrade_database(url)
    engine = make_engine(url)
    ids = _seed_org_project_environment(engine)
    _insert_agent(engine, "agent-a", ids["org"])

    with engine.begin() as connection:
        connection.execute(
            sa.text(
                "INSERT INTO projects (id, org_id, slug, name, created_at)"
                " VALUES ('proj-other', :org, 'other', 'other', :now)"
            ),
            {"org": ids["org"], "now": datetime.now(UTC)},
        )

    with pytest.raises(IntegrityError):
        _attach(
            engine,
            agent_id="agent-a",
            org_id=ids["org"],
            project_id="proj-other",
            environment_id=ids["environment"],
        )


def test_scoped_candidate_key_is_available_for_environment_bound_children(
    tmp_path: Path,
) -> None:
    """The attachment exposes a scoped candidate key for future managed children.

    A managed table that references an agent must be able to target
    ``(org_id, project_id, environment_id, agent_id)``, so that referencing an
    agent from a different environment is a foreign-key error rather than a
    convention. This pins that the key exists and is unique.
    """
    url = _url(tmp_path)
    upgrade_database(url)
    inspector = sa.inspect(make_engine(url))
    uniques = {
        constraint["name"]: tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints("agent_environment_scope")
    }
    assert uniques["uq_agent_environment_scope_scope_agent"] == (
        "org_id",
        "project_id",
        "environment_id",
        "agent_id",
    )
    # ``agents`` carries the composite key the attachment's own agent FK targets.
    agent_uniques = {
        tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints("agents")
    }
    assert ("org_id", "id") in agent_uniques


def test_downgrade_fails_closed(tmp_path: Path) -> None:
    """Rollback is not automated: scope attribution is never silently dropped.

    Two independent layers refuse it, and this pins both. The outer preflight
    guard rejects any raw Alembic command, so an operator cannot reach the
    revision at all; and the revision's own ``downgrade`` raises even when
    called directly, so a future caller that acquires a config cannot drop the
    attachment table either.
    """
    url = _url(tmp_path)
    upgrade_database(url)

    with pytest.raises(MigrationPreflightError, match="Refusing a raw Alembic operation"):
        command.downgrade(migration_config(url), TENANT_BOOTSTRAP_REVISION)

    # The revision module name begins with a digit, so it is not importable by
    # statement; load it by path from the script location Alembic itself uses.
    version_path = Path(migration_config(url).get_main_option("script_location") or "")
    module_path = version_path / "versions" / "0006_agent_environment_scope.py"
    spec = importlib.util.spec_from_file_location("revision_0006", module_path)
    assert spec is not None and spec.loader is not None
    revision_0006 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(revision_0006)

    with pytest.raises(NotImplementedError, match="forward-only"):
        revision_0006.downgrade()

    # The refusal left the schema at head with the attachment table intact.
    assert inspect_schema(url).state is DatabaseSchemaState.VERSION_0006


def test_metadata_create_all_contract_is_unchanged(tmp_path: Path) -> None:
    """The v0 adoption path still works, which is why scope is a separate table.

    A metadata-created database must still classify as the frozen v0 schema so
    it can be stamped at revision 0001 and migrated forward. If a future change
    adds columns or constraints to ``AgentRecord``, this test fails and the
    adoption path is what broke.
    """
    url = _url(tmp_path, "metadata")
    from acgs_control_plane.app import create_app

    create_app(
        Settings(
            database_url=url,
            audit_dir=tmp_path / "audit",
            create_tables=True,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
            bootstrap_token="t" * 32,
        )
    )
    preflight = inspect_schema(url)
    assert preflight.state is DatabaseSchemaState.LEGACY_V0

    inspector = sa.inspect(make_engine(url))
    # The Alembic-managed attachment table is absent from a create_all database,
    # exactly like every other post-v0 table.
    assert "agent_environment_scope" not in inspector.get_table_names()
