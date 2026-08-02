"""Alembic adoption tests for the pre-Alembic control-plane schema."""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import importlib.util
import io
import json
import os
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from alembic import command
from alembic import op as alembic_op
from sqlalchemy.dialects import postgresql, sqlite

import acgs_control_plane.migrations as migration_module
from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.db import Base, make_engine
from acgs_control_plane.migrations import (
    HEAD_REVISION,
    LEGACY_V0_REVISION,
    RUNTIME_ENROLLMENT_REVISION,
    SCOPED_REVISION,
    DatabaseSchemaState,
    MigrationPreflightError,
    StartupSchemaPreflightError,
    _check_constraint_signature,
    _ColumnSpec,
    _index_where_signature,
    _matches_type,
    assert_current_startup_schema,
    inspect_schema,
    migration_config,
    upgrade_database,
)
from acgs_control_plane.models import (
    AgentRecord,
    RuntimeReport,
    RuntimeReportHead,
    RuntimeWiringAttestation,
)


def _load_migration_revision_module(filename: str) -> object:
    path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "acgs_control_plane"
        / "migrations"
        / "versions"
        / filename
    )
    spec = importlib.util.spec_from_file_location(f"acgs_control_plane_test_{filename}", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def test_revision_0006_scopes_agents_without_fabricating_legacy_scope(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    result = upgrade_database(database_url)
    assert result.after.state is DatabaseSchemaState.VERSION_0012
    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0012

    engine = make_engine(database_url)
    try:
        inspector = sa.inspect(engine)
        agent_columns = {column["name"]: column for column in inspector.get_columns("agents")}
        assert agent_columns["project_id"]["nullable"] is True
        assert agent_columns["environment_id"]["nullable"] is True
        unique_names = {
            constraint["name"] for constraint in inspector.get_unique_constraints("agents")
        }
        assert "uq_agents_org_name" not in unique_names
        agent_fk_names = {fk["name"] for fk in inspector.get_foreign_keys("agents")}
        assert "fk_agents_scope_environment" in agent_fk_names
        index_names = {index["name"] for index in inspector.get_indexes("agents")}
        assert {"uq_agents_legacy_org_name", "uq_agents_scope_name"} <= index_names
        metadata_constraint_names = {
            constraint.name for constraint in AgentRecord.__table__.constraints
        }
        assert "uq_agents_org_name" not in metadata_constraint_names
        assert "fk_agents_scope_environment" in metadata_constraint_names
        policy_index_names = {index["name"] for index in inspector.get_indexes("policy_bundles")}
        assert "uq_policy_bundles_one_active_per_org" in policy_index_names

        now = "2026-07-25T00:00:00+00:00"
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    """
                    INSERT INTO organizations (
                        id, name, created_at, audit_anchor_count, audit_anchor_hash
                    ) VALUES ('org-0006', 'Org 0006', :now, 0, '')
                    """
                ),
                {"now": now},
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO projects (id, org_id, slug, name, created_at)
                    VALUES ('project-0006', 'org-0006', 'default', 'Default', :now)
                    """
                ),
                {"now": now},
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO environments (id, org_id, project_id, slug, name, created_at)
                    VALUES
                        (
                            'env-0006-a', 'org-0006', 'project-0006',
                            'production', 'Production', :now
                        ),
                        ('env-0006-b', 'org-0006', 'project-0006', 'staging', 'Staging', :now)
                    """
                ),
                {"now": now},
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO agents (
                        id, org_id, name, description, trust_tier, allowed_tools, status, created_at
                    ) VALUES (
                        'agent-legacy', 'org-0006', 'same-name', '',
                        'untrusted', '[]', 'active', :now
                    )
                    """
                ),
                {"now": now},
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO agents (
                        id, org_id, project_id, environment_id, name, description,
                        trust_tier, allowed_tools, status, created_at
                    ) VALUES (
                        'agent-scoped-a', 'org-0006', 'project-0006', 'env-0006-a',
                        'same-name', '', 'internal', '[]', 'active', :now
                    )
                    """
                ),
                {"now": now},
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO agents (
                        id, org_id, project_id, environment_id, name, description,
                        trust_tier, allowed_tools, status, created_at
                    ) VALUES (
                        'agent-scoped-b', 'org-0006', 'project-0006', 'env-0006-b',
                        'same-name', '', 'internal', '[]', 'active', :now
                    )
                    """
                ),
                {"now": now},
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO policy_bundles (
                        id, org_id, policy_id, version, bundle, status, created_at, activated_at
                    ) VALUES (
                        'policy-active-a', 'org-0006', 'policy-a', 'v1', '{}',
                        'active', :now, :now
                    )
                    """
                ),
                {"now": now},
            )

        with engine.connect() as connection:
            legacy_scope = connection.execute(
                sa.text(
                    """
                    SELECT project_id, environment_id
                    FROM agents
                    WHERE id = 'agent-legacy'
                    """
                )
            ).one()
            assert legacy_scope == (None, None)

        with pytest.raises(sa.exc.IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    sa.text(
                        """
                        INSERT INTO agents (
                            id, org_id, project_id, environment_id, name, description,
                            trust_tier, allowed_tools, status, created_at
                        ) VALUES (
                            'agent-scoped-dup', 'org-0006', 'project-0006', 'env-0006-a',
                            'same-name', '', 'internal', '[]', 'active', :now
                        )
                        """
                    ),
                    {"now": now},
                )
        with pytest.raises(sa.exc.IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    sa.text(
                        """
                        INSERT INTO policy_bundles (
                            id, org_id, policy_id, version, bundle, status, created_at, activated_at
                        ) VALUES (
                            'policy-active-b', 'org-0006', 'policy-b', 'v2', '{}',
                            'active', :now, :now
                        )
                        """
                    ),
                    {"now": now},
                )
    finally:
        engine.dispose()


_SQLITE_RUNTIME_LINEAGE_TRIGGER_TARGETS = {
    "runtime_reports_immutable_update": ("UPDATE", "runtime_reports"),
    "runtime_reports_immutable_delete": ("DELETE", "runtime_reports"),
    "runtime_wiring_attestations_immutable_update": (
        "UPDATE",
        "runtime_wiring_attestations",
    ),
    "runtime_wiring_attestations_immutable_delete": (
        "DELETE",
        "runtime_wiring_attestations",
    ),
    "runtime_report_heads_monotonic_update": ("UPDATE", "runtime_report_heads"),
    "runtime_report_heads_monotonic_delete": ("DELETE", "runtime_report_heads"),
}


def test_runtime_report_orm_metadata_matches_revision_0012_constraints() -> None:
    report_constraints = {item.name: item for item in RuntimeReport.__table__.constraints}
    report_org_fk = report_constraints["fk_runtime_reports_organization"]
    assert isinstance(report_org_fk, sa.ForeignKeyConstraint)
    assert report_org_fk.deferrable is True
    assert report_org_fk.initially == "DEFERRED"

    head_constraints = {item.name: item for item in RuntimeReportHead.__table__.constraints}
    head_org_fk = head_constraints["fk_runtime_report_heads_organization"]
    assert isinstance(head_org_fk, sa.ForeignKeyConstraint)
    assert head_org_fk.deferrable is True
    assert head_org_fk.initially == "DEFERRED"
    assert "ck_runtime_report_heads_history_count" in head_constraints

    attestation_constraints = {
        item.name: item for item in RuntimeWiringAttestation.__table__.constraints
    }
    assert "uq_runtime_wiring_attestations_attestation_hash" in attestation_constraints


@pytest.mark.parametrize("trigger_name", sorted(_SQLITE_RUNTIME_LINEAGE_TRIGGER_TARGETS))
@pytest.mark.parametrize("mutation", ["drop", "replace"])
def test_revision_0012_requires_exact_sqlite_runtime_lineage_trigger_definitions(
    tmp_path: Path,
    trigger_name: str,
    mutation: str,
) -> None:
    database_url = _database_url(tmp_path)
    upgrade_database(database_url)
    event, table_name = _SQLITE_RUNTIME_LINEAGE_TRIGGER_TARGETS[trigger_name]
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text(f'DROP TRIGGER "{trigger_name}"'))
            if mutation == "replace":
                connection.execute(
                    sa.text(
                        f'CREATE TRIGGER "{trigger_name}" BEFORE {event} ON "{table_name}" '
                        "BEGIN SELECT 1; END"
                    )
                )
        preflight = inspect_schema(database_url)
        assert preflight.state is DatabaseSchemaState.UNKNOWN
        assert "runtime lineage" in preflight.detail
        with engine.connect() as connection:
            with pytest.raises(StartupSchemaPreflightError):
                assert_current_startup_schema(connection)
    finally:
        engine.dispose()


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


def _upgrade_to_exact_0002(database_url: str) -> None:
    config = migration_config(database_url)
    migration_module._run_controlled_operation(  # type: ignore[attr-defined]
        config,
        migration_module._LEGACY_ADOPTION_TOKEN,  # type: ignore[attr-defined]
        DatabaseSchemaState.LEGACY_V0,
        lambda: command.stamp(config, LEGACY_V0_REVISION),
    )
    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0001
    migration_module._run_controlled_operation(  # type: ignore[attr-defined]
        config,
        migration_module._SCOPE_RESUME_TOKEN,  # type: ignore[attr-defined]
        DatabaseSchemaState.VERSION_0001,
        lambda: command.upgrade(config, SCOPED_REVISION),
    )
    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0002


def _insert_scoped_0002_rows(database_url: str) -> None:
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
                    "id": "org-prior-0002",
                    "name": "Prior 0002 Organization",
                    "created_at": "2026-07-24T00:00:00+00:00",
                    "audit_anchor_count": 0,
                    "audit_anchor_hash": "",
                },
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO projects (id, org_id, slug, name, created_at)
                    VALUES (:id, :org_id, :slug, :name, :created_at)
                    """
                ),
                {
                    "id": "project-prior-0002",
                    "org_id": "org-prior-0002",
                    "slug": "core",
                    "name": "Core",
                    "created_at": "2026-07-24T00:00:00+00:00",
                },
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO environments (
                        id, org_id, project_id, slug, name, created_at
                    ) VALUES (
                        :id, :org_id, :project_id, :slug, :name, :created_at
                    )
                    """
                ),
                {
                    "id": "environment-prior-0002",
                    "org_id": "org-prior-0002",
                    "project_id": "project-prior-0002",
                    "slug": "production",
                    "name": "Production",
                    "created_at": "2026-07-24T00:00:00+00:00",
                },
            )
    finally:
        engine.dispose()


def _scoped_0002_rows(database_url: str) -> tuple[tuple[str, str], tuple[str, str, str]]:
    engine = make_engine(database_url)
    try:
        with engine.connect() as connection:
            project = connection.execute(
                sa.text("SELECT id, org_id FROM projects WHERE id = :id"),
                {"id": "project-prior-0002"},
            ).one()
            environment = connection.execute(
                sa.text(
                    """
                    SELECT id, org_id, project_id
                    FROM environments
                    WHERE id = :id
                    """
                ),
                {"id": "environment-prior-0002"},
            ).one()
    finally:
        engine.dispose()
    return (project.id, project.org_id), (
        environment.id,
        environment.org_id,
        environment.project_id,
    )


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
            "acgs_control_plane/migrations/versions/0003_managed_mutation_uow.py",
            "acgs_control_plane/migrations/versions/0004_managed_trust_v2.py",
            "acgs_control_plane/migrations/versions/0005_tenant_bootstrap.py",
            "acgs_control_plane/migrations/versions/0006_agent_scope.py",
            "acgs_control_plane/migrations/versions/0007_agent_registration_idempotency.py",
            "acgs_control_plane/migrations/versions/0008_policy_registry.py",
            "acgs_control_plane/migrations/versions/0009_approval_substrate.py",
            "acgs_control_plane/migrations/versions/0010_approval_vote_binding.py",
            "acgs_control_plane/migrations/versions/0011_runtime_enrollment.py",
            "acgs_control_plane/migrations/versions/0012_runtime_reports.py",
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
assert result.after.state is DatabaseSchemaState.VERSION_0012
assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0012
engine = sa.create_engine(database_url)
try:
    assert set(sa.inspect(engine).get_table_names()) == {
        "agent_registration_idempotency",
        "agents",
        "alembic_version",
        "approval_outcomes",
        "approval_requests",
        "approval_resume_authorizations",
        "approval_votes",
        "compliance_exports",
        "environments",
        "environment_policy_heads",
        "managed_decision_receipts",
        "managed_governance_event_heads",
        "managed_governance_events",
        "managed_mutation_attempts",
        "managed_outbox",
        "managed_receipt_consumptions",
        "managed_trust_keys",
        "managed_trust_scopes",
        "organization_memberships",
        "organizations",
        "pending_approvals",
        "platform_bootstrap_invitations",
        "policy_bundles",
        "policy_registry_idempotency",
        "policy_versions",
        "projects",
        "receipts",
        "runtime_credential_generations",
        "runtime_enrollment_bootstraps",
        "runtime_enrollment_idempotency",
        "runtime_identities",
        "runtime_identity_gates",
        "runtime_operation_idempotency",
            "runtime_reports",
            "runtime_report_heads",
            "runtime_request_nonces",
            "runtime_wiring_attestations",
            "runtime_wiring_challenge_consumptions",
        "tenant_bootstrap_idempotency",
        "tenant_bootstrap_pending_outbox",
        "tenant_bootstrap_policy_artifacts",
        "tenant_bootstrap_refusal_events",
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
    assert result.after.state is DatabaseSchemaState.VERSION_0012
    assert _table_names(database_url) == {
        "agent_registration_idempotency",
        "agents",
        "alembic_version",
        "approval_outcomes",
        "approval_requests",
        "approval_resume_authorizations",
        "approval_votes",
        "compliance_exports",
        "environments",
        "environment_policy_heads",
        "managed_decision_receipts",
        "managed_governance_event_heads",
        "managed_governance_events",
        "managed_mutation_attempts",
        "managed_outbox",
        "managed_receipt_consumptions",
        "managed_trust_keys",
        "managed_trust_scopes",
        "organization_memberships",
        "organizations",
        "pending_approvals",
        "platform_bootstrap_invitations",
        "policy_bundles",
        "policy_registry_idempotency",
        "policy_versions",
        "projects",
        "receipts",
        "runtime_credential_generations",
        "runtime_enrollment_bootstraps",
        "runtime_enrollment_idempotency",
        "runtime_identities",
        "runtime_identity_gates",
        "runtime_operation_idempotency",
        "runtime_reports",
        "runtime_report_heads",
        "runtime_request_nonces",
        "runtime_wiring_attestations",
        "runtime_wiring_challenge_consumptions",
        "tenant_bootstrap_idempotency",
        "tenant_bootstrap_pending_outbox",
        "tenant_bootstrap_policy_artifacts",
        "tenant_bootstrap_refusal_events",
        "users",
    }

    engine = make_engine(database_url)
    try:
        inspector = sa.inspect(engine)
        resume_columns = {
            column["name"]: column
            for column in inspector.get_columns("approval_resume_authorizations")
        }
        for column_name in {
            "resumer_actor_hash",
            "resumer_credential_hash",
            "resumer_role",
            "resume_argument_hash",
            "resume_result_hash",
            "resume_result",
            "resume_response_hash",
            "resume_response",
            "resume_replay_seal",
        }:
            assert column_name in resume_columns
            assert resume_columns[column_name]["nullable"] is False
        vote_columns = {
            column["name"]: column for column in inspector.get_columns("approval_votes")
        }
        assert "vote_replay_seal" in vote_columns
        assert vote_columns["vote_replay_seal"]["nullable"] is False
        with engine.connect() as connection:
            assert (
                connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
                == HEAD_REVISION
            )
    finally:
        engine.dispose()
    revision_0010 = _load_migration_revision_module("0010_approval_vote_binding.py")
    resume_result = sa.Column("resume_result", revision_0010.JSONVariant)
    resume_response = sa.Column("resume_response", revision_0010.JSONVariant)
    resume_replay_seal = sa.Column("resume_replay_seal", revision_0010.JSONVariant)
    vote_replay_seal = sa.Column("vote_replay_seal", revision_0010.JSONVariant)
    assert resume_result.type.compile(dialect=postgresql.dialect()) == "JSONB"
    assert resume_response.type.compile(dialect=postgresql.dialect()) == "JSONB"
    assert resume_replay_seal.type.compile(dialect=postgresql.dialect()) == "JSONB"
    assert vote_replay_seal.type.compile(dialect=postgresql.dialect()) == "JSONB"
    assert resume_result.type.compile(dialect=sqlite.dialect()) == "JSON"
    assert resume_response.type.compile(dialect=sqlite.dialect()) == "JSON"
    assert resume_replay_seal.type.compile(dialect=sqlite.dialect()) == "JSON"
    assert vote_replay_seal.type.compile(dialect=sqlite.dialect()) == "JSON"


def test_stamped_0011_without_runtime_tables_is_unknown(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("CREATE TABLE alembic_version (version_num VARCHAR(32))"))
            connection.execute(
                sa.text("INSERT INTO alembic_version(version_num) VALUES (:revision)"),
                {"revision": RUNTIME_ENROLLMENT_REVISION},
            )
    finally:
        engine.dispose()

    assert inspect_schema(database_url).state is DatabaseSchemaState.UNKNOWN


def test_revision_0010_upgrades_to_0011_runtime_enrollment_tables(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)
    config = migration_config(database_url)
    migration_module._run_controlled_operation(  # type: ignore[attr-defined]
        config,
        migration_module._SCOPE_RESUME_TOKEN,  # type: ignore[attr-defined]
        DatabaseSchemaState.EMPTY,
        lambda: command.upgrade(config, "0010"),
    )
    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0010

    result = upgrade_database(database_url)

    assert result.before.state is DatabaseSchemaState.VERSION_0010
    assert result.after.state is DatabaseSchemaState.VERSION_0012
    assert {
        "runtime_credential_generations",
        "runtime_enrollment_bootstraps",
        "runtime_enrollment_idempotency",
        "runtime_identities",
        "runtime_identity_gates",
        "runtime_operation_idempotency",
        "runtime_request_nonces",
    } <= _table_names(database_url)


def test_populated_revision_0011_is_current_for_upgrade_and_preserved_by_0012(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    config = migration_config(database_url)
    migration_module._run_controlled_operation(  # type: ignore[attr-defined]
        config,
        migration_module._SCOPE_RESUME_TOKEN,  # type: ignore[attr-defined]
        DatabaseSchemaState.EMPTY,
        lambda: command.upgrade(config, RUNTIME_ENROLLMENT_REVISION),
    )
    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0011
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    "INSERT INTO organizations "
                    "(id, name, created_at, audit_anchor_count, audit_anchor_hash) "
                    "VALUES ('org-0011', 'Org 0011', :now, 0, '')"
                ),
                {"now": "2026-08-01T00:00:00+00:00"},
            )
            descriptor = json.dumps(
                {
                    "schema": "runtime-identity/v1",
                    "runtime_identity_id": "identity-0011",
                    "credential_id": "credential-0011",
                    "credential_generation": 1,
                    "binding": "preserve-exactly",
                },
                sort_keys=True,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO runtime_identities "
                    "(id, org_id, project_id, environment_id, gate_id, name, actor, "
                    "workload_key_id, public_key, public_key_thumbprint, descriptor, status, "
                    "current_generation, created_at, updated_at, revoked_at) VALUES "
                    "('identity-0011', 'org-0011', 'project-0011', 'env-0011', 'gate-0011', "
                    "'Runtime 0011', 'runtime:identity-0011', 'workload-key-0011', "
                    "'public-key-0011', :thumbprint, :descriptor, 'active', 1, :created_at, "
                    ":updated_at, NULL)"
                ),
                {
                    "thumbprint": "a" * 64,
                    "descriptor": descriptor,
                    "created_at": "2026-08-01T00:01:00+00:00",
                    "updated_at": "2026-08-01T00:02:00+00:00",
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO runtime_credential_generations "
                    "(id, org_id, project_id, environment_id, identity_id, generation, "
                    "workload_key_id, public_key_thumbprint, not_before, not_after, status, "
                    "descriptor, created_at, superseded_at, revoked_at) VALUES "
                    "('credential-0011', 'org-0011', 'project-0011', 'env-0011', "
                    "'identity-0011', 1, 'workload-key-0011', :thumbprint, :not_before, "
                    ":not_after, 'active', :descriptor, :created_at, NULL, NULL)"
                ),
                {
                    "thumbprint": "a" * 64,
                    "not_before": "2026-08-01T00:00:00+00:00",
                    "not_after": "2026-08-02T00:00:00+00:00",
                    "descriptor": descriptor,
                    "created_at": "2026-08-01T00:03:00+00:00",
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO projects (id, org_id, slug, name, created_at) "
                    "VALUES ('project-0011', 'org-0011', 'project', 'Project', :now)"
                ),
                {"now": "2026-08-01T00:00:00+00:00"},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO environments "
                    "(id, org_id, project_id, slug, name, created_at) "
                    "VALUES ('env-0011', 'org-0011', 'project-0011', 'env', 'Env', :now)"
                ),
                {"now": "2026-08-01T00:00:00+00:00"},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO runtime_identity_gates "
                    "(id, org_id, project_id, environment_id, status, created_at, updated_at) "
                    "VALUES ('gate-0011', 'org-0011', 'project-0011', 'env-0011', "
                    "'active', :now, :now)"
                ),
                {"now": "2026-08-01T00:00:00+00:00"},
            )
    finally:
        engine.dispose()

    result = upgrade_database(database_url)

    assert result.before.state is DatabaseSchemaState.VERSION_0011
    assert result.after.state is DatabaseSchemaState.VERSION_0012
    engine = make_engine(database_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.scalar(
                    sa.text("SELECT status FROM runtime_identity_gates WHERE id = 'gate-0011'")
                )
                == "active"
            )
            identity = (
                connection.execute(
                    sa.text("SELECT * FROM runtime_identities WHERE id = 'identity-0011'")
                )
                .mappings()
                .one()
            )
            credential = (
                connection.execute(
                    sa.text(
                        "SELECT * FROM runtime_credential_generations WHERE id = 'credential-0011'"
                    )
                )
                .mappings()
                .one()
            )
            assert {
                "org_id": identity["org_id"],
                "project_id": identity["project_id"],
                "environment_id": identity["environment_id"],
                "gate_id": identity["gate_id"],
                "status": identity["status"],
                "current_generation": identity["current_generation"],
                "workload_key_id": identity["workload_key_id"],
                "public_key": identity["public_key"],
                "public_key_thumbprint": identity["public_key_thumbprint"],
                "descriptor": json.loads(identity["descriptor"]),
                "created_at": identity["created_at"],
                "updated_at": identity["updated_at"],
            } == {
                "org_id": "org-0011",
                "project_id": "project-0011",
                "environment_id": "env-0011",
                "gate_id": "gate-0011",
                "status": "active",
                "current_generation": 1,
                "workload_key_id": "workload-key-0011",
                "public_key": "public-key-0011",
                "public_key_thumbprint": "a" * 64,
                "descriptor": json.loads(descriptor),
                "created_at": "2026-08-01T00:01:00+00:00",
                "updated_at": "2026-08-01T00:02:00+00:00",
            }
            assert {
                "org_id": credential["org_id"],
                "project_id": credential["project_id"],
                "environment_id": credential["environment_id"],
                "identity_id": credential["identity_id"],
                "generation": credential["generation"],
                "status": credential["status"],
                "workload_key_id": credential["workload_key_id"],
                "public_key_thumbprint": credential["public_key_thumbprint"],
                "descriptor": json.loads(credential["descriptor"]),
                "not_before": credential["not_before"],
                "not_after": credential["not_after"],
                "created_at": credential["created_at"],
            } == {
                "org_id": "org-0011",
                "project_id": "project-0011",
                "environment_id": "env-0011",
                "identity_id": "identity-0011",
                "generation": 1,
                "status": "active",
                "workload_key_id": "workload-key-0011",
                "public_key_thumbprint": "a" * 64,
                "descriptor": json.loads(descriptor),
                "not_before": "2026-08-01T00:00:00+00:00",
                "not_after": "2026-08-02T00:00:00+00:00",
                "created_at": "2026-08-01T00:03:00+00:00",
            }
    finally:
        engine.dispose()


def test_runtime_enrollment_timestamp_columns_are_not_nullable(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)
    upgrade_database(database_url)
    engine = make_engine(database_url)
    try:
        inspector = sa.inspect(engine)
        for table_name, column_name in {
            ("runtime_identity_gates", "created_at"),
            ("runtime_identity_gates", "updated_at"),
            ("runtime_identities", "created_at"),
            ("runtime_identities", "updated_at"),
            ("runtime_enrollment_bootstraps", "created_at"),
            ("runtime_credential_generations", "created_at"),
            ("runtime_enrollment_idempotency", "created_at"),
            ("runtime_operation_idempotency", "created_at"),
            ("runtime_request_nonces", "observed_at"),
        }:
            columns = {column["name"]: column for column in inspector.get_columns(table_name)}
            assert columns[column_name]["nullable"] is False
    finally:
        engine.dispose()


def test_revision_0010_refuses_historical_approval_votes_without_backfill(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    config = migration_config(database_url)
    migration_module._run_controlled_operation(  # type: ignore[attr-defined]
        config,
        migration_module._SCOPE_RESUME_TOKEN,  # type: ignore[attr-defined]
        DatabaseSchemaState.EMPTY,
        lambda: command.upgrade(config, migration_module.APPROVAL_SUBSTRATE_REVISION),
    )
    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0009
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("PRAGMA foreign_keys=OFF"))
            connection.execute(
                sa.text(
                    """
                    INSERT INTO approval_votes (
                        id, org_id, project_id, environment_id, approval_request_id,
                        approver_actor_hash, approver_role, decision, idempotency_key_hash,
                        vote_hash, created_at
                    ) VALUES (
                        :id, :org_id, :project_id, :environment_id, :approval_request_id,
                        :approver_actor_hash, :approver_role, :decision, :idempotency_key_hash,
                        :vote_hash, :created_at
                    )
                    """
                ),
                {
                    "id": "historical-vote-0009",
                    "org_id": "org-historical-vote",
                    "project_id": "project-historical-vote",
                    "environment_id": "environment-historical-vote",
                    "approval_request_id": "approval-request-historical-vote",
                    "approver_actor_hash": "a" * 64,
                    "approver_role": "org_admin",
                    "decision": "approve",
                    "idempotency_key_hash": "b" * 64,
                    "vote_hash": "c" * 64,
                    "created_at": "2026-07-27T00:00:00+00:00",
                },
            )
            connection.execute(sa.text("PRAGMA foreign_keys=ON"))
    finally:
        engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="refuses to upgrade databases with historical approval_votes",
    ):
        migration_module._run_controlled_operation(  # type: ignore[attr-defined]
            config,
            migration_module._SCOPE_RESUME_TOKEN,  # type: ignore[attr-defined]
            DatabaseSchemaState.VERSION_0009,
            lambda: command.upgrade(config, HEAD_REVISION),
        )

    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0009


def test_revision_0010_refuses_historical_approval_resumes_without_backfill(
    tmp_path: Path,
) -> None:
    database_url = _database_url(tmp_path)
    config = migration_config(database_url)
    migration_module._run_controlled_operation(  # type: ignore[attr-defined]
        config,
        migration_module._SCOPE_RESUME_TOKEN,  # type: ignore[attr-defined]
        DatabaseSchemaState.EMPTY,
        lambda: command.upgrade(config, migration_module.APPROVAL_SUBSTRATE_REVISION),
    )
    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0009
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("PRAGMA foreign_keys=OFF"))
            connection.execute(
                sa.text(
                    """
                    INSERT INTO approval_resume_authorizations (
                        id, org_id, project_id, environment_id, approval_request_id,
                        resumed_agent_id, idempotency_key_hash, resume_receipt_id,
                        resume_receipt_hash, resume_audit_event_hash, approval_chain_hash,
                        created_at
                    ) VALUES (
                        :id, :org_id, :project_id, :environment_id, :approval_request_id,
                        :resumed_agent_id, :idempotency_key_hash, :resume_receipt_id,
                        :resume_receipt_hash, :resume_audit_event_hash, :approval_chain_hash,
                        :created_at
                    )
                    """
                ),
                {
                    "id": "historical-resume-0009",
                    "org_id": "org-historical-resume",
                    "project_id": "project-historical-resume",
                    "environment_id": "environment-historical-resume",
                    "approval_request_id": "approval-request-historical-resume",
                    "resumed_agent_id": "agent-historical-resume",
                    "idempotency_key_hash": "b" * 64,
                    "resume_receipt_id": "receipt-historical-resume",
                    "resume_receipt_hash": "c" * 64,
                    "resume_audit_event_hash": "d" * 64,
                    "approval_chain_hash": "e" * 64,
                    "created_at": "2026-07-27T00:00:00+00:00",
                },
            )
            connection.execute(sa.text("PRAGMA foreign_keys=ON"))
    finally:
        engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="approval_resume_authorizations",
    ):
        migration_module._run_controlled_operation(  # type: ignore[attr-defined]
            config,
            migration_module._SCOPE_RESUME_TOKEN,  # type: ignore[attr-defined]
            DatabaseSchemaState.VERSION_0009,
            lambda: command.upgrade(config, HEAD_REVISION),
        )

    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0009


@pytest.mark.parametrize(
    ("replacement_sql", "expected_detail"),
    [
        (
            None,
            "managed_trust_keys has unexpected unique index predicates",
        ),
        (
            """
            CREATE UNIQUE INDEX uq_managed_trust_key_active_scope
            ON managed_trust_keys (org_id, project_id, environment_id, purpose)
            """,
            "managed_trust_keys has unexpected unique constraints or indexes",
        ),
        (
            """
            CREATE UNIQUE INDEX uq_managed_trust_key_active_scope
            ON managed_trust_keys (org_id, project_id, environment_id, purpose)
            WHERE status = 'revoked'
            """,
            "managed_trust_keys has unexpected unique index predicates",
        ),
    ],
)
def test_head_schema_rejects_trust_active_root_unique_predicate_drift(
    tmp_path: Path,
    replacement_sql: str | None,
    expected_detail: str,
) -> None:
    database_url = _database_url(tmp_path)
    upgrade_database(database_url)
    engine = make_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(sa.text("DROP INDEX uq_managed_trust_key_active_scope"))
            if replacement_sql is not None:
                connection.execute(sa.text(replacement_sql))
    finally:
        engine.dispose()

    preflight = inspect_schema(database_url)

    assert preflight.state is DatabaseSchemaState.UNKNOWN
    assert expected_detail in preflight.detail


@pytest.mark.parametrize(
    "replacement_options",
    (None, {}, {"deferrable": False, "initially": "IMMEDIATE"}),
)
def test_runtime_schema_rejects_missing_or_wrong_deferred_foreign_key_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement_options: dict[str, object] | None,
) -> None:
    database_url = _database_url(tmp_path)
    upgrade_database(database_url)
    original = sa.engine.reflection.Inspector.get_foreign_keys

    def drifted_foreign_keys(
        inspector: sa.engine.reflection.Inspector,
        table_name: str,
        *args: object,
        **kwargs: object,
    ) -> list[dict[str, object]]:
        rows = original(inspector, table_name, *args, **kwargs)
        if table_name == "runtime_identities":
            rows = [dict(row) for row in rows]
            if replacement_options is None:
                rows[0].pop("options", None)
            else:
                rows[0]["options"] = replacement_options
        return rows

    monkeypatch.setattr(
        sa.engine.reflection.Inspector,
        "get_foreign_keys",
        drifted_foreign_keys,
    )

    preflight = inspect_schema(database_url)

    assert preflight.state is DatabaseSchemaState.UNKNOWN
    assert (
        "runtime_identities has foreign-key options outside the frozen schema" in preflight.detail
    )


def test_frozen_pre_runtime_schema_still_allows_absent_foreign_key_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_url = _database_url(tmp_path)
    config = migration_config(database_url)
    migration_module._run_controlled_operation(  # type: ignore[attr-defined]
        config,
        migration_module._SCOPE_RESUME_TOKEN,  # type: ignore[attr-defined]
        DatabaseSchemaState.EMPTY,
        lambda: command.upgrade(config, "0010"),
    )
    original = sa.engine.reflection.Inspector.get_foreign_keys

    def optionless_foreign_keys(
        inspector: sa.engine.reflection.Inspector,
        table_name: str,
        *args: object,
        **kwargs: object,
    ) -> list[dict[str, object]]:
        rows = [dict(row) for row in original(inspector, table_name, *args, **kwargs)]
        for row in rows:
            row.pop("options", None)
        return rows

    monkeypatch.setattr(
        sa.engine.reflection.Inspector,
        "get_foreign_keys",
        optionless_foreign_keys,
    )

    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0010


def test_postgresql_trust_active_root_predicate_reflection_is_normalized() -> None:
    assert (
        _index_where_signature(
            {
                "dialect_options": {
                    "postgresql_where": "((status)::text = 'active'::text)",
                }
            },
            "postgresql",
        )
        == "status:active"
    )
    assert (
        _index_where_signature(
            {
                "dialect_options": {
                    "postgresql_where": "((status)::text = 'revoked'::text)",
                }
            },
            "postgresql",
        )
        != "status:active"
    )


def test_agent_scope_partial_unique_predicate_reflection_is_normalized() -> None:
    assert (
        _index_where_signature(
            {
                "dialect_options": {
                    "postgresql_where": "((project_id IS NULL) AND (environment_id IS NULL))",
                }
            },
            "postgresql",
        )
        == "agent-scope:legacy-unscoped"
    )
    assert (
        _index_where_signature(
            {
                "dialect_options": {
                    "sqlite_where": "project_id IS NULL AND environment_id IS NULL",
                }
            },
            "sqlite",
        )
        == "agent-scope:legacy-unscoped"
    )
    assert (
        _index_where_signature(
            {
                "dialect_options": {
                    "postgresql_where": (
                        "((project_id IS NOT NULL) AND (environment_id IS NOT NULL))"
                    ),
                }
            },
            "postgresql",
        )
        == "agent-scope:scoped"
    )


def test_agent_scope_check_constraint_reflection_is_normalized() -> None:
    assert (
        _check_constraint_signature(
            "(project_id IS NULL AND environment_id IS NULL) OR "
            "(project_id IS NOT NULL AND environment_id IS NOT NULL)"
        )
        == "agent-scope:both-null-or-set"
    )
    assert (
        _check_constraint_signature(
            "(((project_id IS NULL) AND (environment_id IS NULL)) OR "
            "((project_id IS NOT NULL) AND (environment_id IS NOT NULL)))"
        )
        == "agent-scope:both-null-or-set"
    )
    assert (
        _index_where_signature(
            {
                "dialect_options": {
                    "sqlite_where": "project_id IS NOT NULL AND environment_id IS NOT NULL",
                }
            },
            "sqlite",
        )
        == "agent-scope:scoped"
    )


def test_postgres_gate_wrapper_exports_exact_reproducibility_environment() -> None:
    script = (Path(__file__).resolve().parents[1] / "scripts" / "run_postgres_gate.sh").read_text(
        encoding="utf-8"
    )
    reset_line = "unset PYTEST_ADDOPTS PYTHONPATH PYTHONHOME PYTHONOPTIMIZE PGOPTIONS"

    assert reset_line in script
    assert "export ACGS_TEST_SEED=20260710" in script
    assert "export PYTHONHASHSEED=0" in script
    assert script.index("export ACGS_TEST_SEED=20260710") > script.index(reset_line)
    assert script.index("export PYTHONHASHSEED=0") > script.index(reset_line)


def test_postgres_gate_wrapper_locks_runtime_enrollment_selector() -> None:
    package_dir = Path(__file__).resolve().parents[1]
    script = (package_dir / "scripts" / "run_postgres_gate.sh").read_text(encoding="utf-8")
    integration_source = (
        package_dir / "tests" / "integration" / "test_runtime_enrollment_postgres.py"
    ).read_text(encoding="utf-8")
    expected_tests = [
        "test_populated_runtime_enrollment_0011_upgrades_to_0012_postgresql",
        "test_runtime_lineage_schema_objects_are_required_postgresql",
        "test_runtime_report_provider_outages_are_redacted_and_atomic_postgresql",
        "test_identical_runtime_reports_converge_on_postgresql",
        "test_identical_concurrent_wiring_reports_replay_without_debris_postgresql",
        "test_concurrent_different_runtime_report_body_conflicts_without_debris",
        "test_runtime_wiring_challenge_is_invalidated_by_intervening_report_postgresql",
        "test_runtime_report_post_persistence_failure_rolls_back_postgresql",
        "test_runtime_report_head_composite_anchor_is_enforced_postgresql",
        "test_runtime_wiring_historical_replay_and_projection_binding_postgresql",
        "test_runtime_wiring_attestations_are_immutable_postgresql",
        "test_runtime_report_bigint_schema_and_current_binding_postgresql",
        "test_100_identical_runtime_enrollments_converge_to_one_identity",
        "test_runtime_enrollment_conflict_and_cross_scope_idempotency_are_isolated",
        "test_runtime_renew_replay_revoke_and_expired_paths_are_nonduplicating",
    ]
    expected_selectors = [
        f"tests/integration/test_runtime_enrollment_postgres.py::{name}" for name in expected_tests
    ]
    actual_tests = re.findall(r"^def (test_[a-zA-Z0-9_]+)\(", integration_source, re.M)

    assert actual_tests == expected_tests
    assert "p4_runtime_enrollment_selectors=(" in script
    for selector in expected_selectors:
        assert f"  '{selector}'" in script
    assert (
        'if [[ -z "$selector_mode" && $# == "${#p4_runtime_enrollment_selectors[@]}" ]]; then'
        in script
    )
    assert "  selector_mode='p4-runtime-enrollment'" in script
    assert "  junit_expected_tests=17" in script
    assert (
        'for index in "${!p4_runtime_enrollment_selectors[@]}"; do\n'
        '    if [[ "${actual_selectors[index]}" != '
        '"${p4_runtime_enrollment_selectors[index]}" ]]; then' in script
    )
    assert (
        "the exact ordered PostgreSQL migration, P2 tenant-bootstrap, P2 register, "
        "P2 idempotency, P2 vertical-gate, P3 policy, P3 mutations, P3 approval, "
        "P4 runtime-enrollment, or immutable-0004 selector is required" in script
    )
    selector_block_index = script.index("p4_runtime_enrollment_selectors=(")
    mode_index = script.index("selector_mode='p4-runtime-enrollment'")
    export_index = script.index('export ACP_TEST_POSTGRES_SELECTOR_MODE="$selector_mode"')
    assert selector_block_index < mode_index < export_index

    approval_mode_index = script.index("selector_mode='p3-approval'")
    approval_junit_index = script.index("  junit_expected_tests=12", approval_mode_index)
    assert approval_mode_index < approval_junit_index < mode_index


def test_postgres_gate_wrapper_runs_pytest_only_inside_bwrap_sandbox() -> None:
    script = (Path(__file__).resolve().parents[1] / "scripts" / "run_postgres_gate.sh").read_text(
        encoding="utf-8"
    )

    assert (
        "required_command in bwrap cmp docker git mktemp realpath sha256sum stat tar timeout"
        in script
    )
    assert "bwrap preflight failed; refusing to run" in script
    assert 'env -i "$bwrap_bin" "${bwrap_args[@]}" --' in script
    assert (
        'write_verified_private_artifact "$state_dir/tmp" "pytest-output.bin" 0600 </dev/null'
        in script
    )
    assert '/usr/bin/python3 -I -S - "$target_dir" "$target_name" "$target_mode" 3<&0 <<' in script
    assert "payload = sys.stdin.buffer.read" not in script
    assert "chunk = os.read(3, min(65_536, remaining))" in script
    assert 'verify_private_artifact_fd "$pytest_output_file"' in script
    assert 'summarize_private_output_sink "$pytest_output_file"' in script
    assert "ulimit -f 131072" in script
    assert "--clearenv" in script
    assert "--unshare-all --unshare-user --die-with-parent --new-session --disable-userns" in script
    assert "--share-net" not in script
    assert "--ro-bind / /" not in script
    assert "--tmpfs /run" in script
    assert "--setenv ACP_TEST_POSTGRES_GATE_ACTIVE 1" in script
    assert '--setenv ACP_TEST_POSTGRES_SELECTOR_MODE "$selector_mode"' in script
    assert '--setenv PYTEST_ADDOPTS "-p no:cacheprovider"' in script
    assert '--ro-bind "$postgres_socket_bridge" /run/acgs-pg' in script
    assert '--bind "$state_dir/tmp" /run/tmp' in script
    assert '--bind "$state_dir/proof-scratch" /proof-scratch' in script
    assert "--setenv ACP_POSTGRES_CLIENT_BROKER_SOCKET /run/broker/postgresql-client.sock" in script
    assert "PostgreSQL client broker" in script
    assert '"tool": tool, "argv": sys.argv[1:], "env": env' in script
    server_launch_start = script.index('container_id="$(\n', script.index("docker_started=1\n"))
    server_launch_end = script.index('\n)"\ncreated_server_record=', server_launch_start)
    server_launch = script[server_launch_start:server_launch_end]
    assert "docker create" in server_launch
    assert "docker run -d" not in server_launch
    assert "--network none" in server_launch
    assert "--publish" not in server_launch
    assert "--user 999:999" in server_launch
    assert "--cap-drop ALL" in server_launch
    assert (
        "--tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=2g,uid=999,gid=999,mode=700"
        in server_launch
    )
    assert "--tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=2g \\" not in script
    assert "--env PGHOST=/run/acgs-pg" not in server_launch
    assert "PGSERVICE" not in server_launch
    assert "PGSERVICEFILE" not in server_launch
    assert "PGHOST" not in server_launch
    assert "--tmpfs /var/run/postgresql" not in server_launch
    assert '--ro-bind "$uv_bin"' not in script
    assert '--mount "type=bind,src=$postgres_socket_bridge,dst=/var/run/postgresql"' in (
        server_launch
    )
    assert "/run/acgs-pg-service.conf" not in script
    assert "acgs-entrypoint-pg-service.conf" not in script
    assert "verify_server_config_before_start" in script
    assert script.index("verify_server_config_before_start") < script.index(
        'docker start "$container_id"'
    )
    assert "--entrypoint /bin/sh" in server_launch
    assert 'exec /usr/local/bin/docker-entrypoint.sh "$@"' in script
    assert "ACGS_POSTGRES_SOCKET_BRIDGE_EXPECTED_IDENTITY" in server_launch
    assert "ACGS_POSTGRES_SOCKET_BRIDGE_MARKER_SHA256" in server_launch
    assert "listen_addresses=" in server_launch
    assert "unix_socket_directories=/var/run/postgresql" in server_launch

    pytest_invocation = (
        'timeout --preserve-status 900s env -i "$bwrap_bin" "${bwrap_args[@]}" -- \\\n'
        '    /bin/sh -c "$inner_uv_preflight" sh "$inner_uv_bin" "$pinned_uv_sha256" \\\n'
        '      "$package_dir/.venv/bin/pytest" -q --junitxml="$junit_report" "$@"'
    )
    obsolete_direct_pytest_invocation = (
        'timeout --preserve-status 900s env -i "$bwrap_bin" "${bwrap_args[@]}" -- \\\n'
        '    "$package_dir/.venv/bin/pytest" -q --junitxml="$junit_report" "$@"'
    )
    assert pytest_invocation in script
    assert obsolete_direct_pytest_invocation not in script
    assert ') >"/proc/$BASHPID/fd/$pytest_output_fd" 2>&1' in script
    assert (
        'env -i "$bwrap_bin" "${bwrap_args[@]}" -- \\\n'
        '  "$package_dir/.venv/bin/pytest" -q --junitxml="$junit_report" "$@"'
    ) not in script
    assert script.index(pytest_invocation) > script.index("broker_socket=")


def test_postgres_gate_binds_fresh_verified_uv_fd_to_inner_sandboxes() -> None:
    script = _postgres_gate_script_source()

    assert "inner_uv_bin='/run/acgs-uv'" in script
    assert "active_uv_fd=''" in script
    assert (
        "pinned_uv_sha256='a00d3a24514fc0403fc232c9c99bf5e542657c38f4ed941e0611731e4cff268b'"
        in script
    )
    assert "pinned_uv_version='uv 0.11.19 (x86_64-unknown-linux-gnu)'" in script
    assert "verify_trusted_uv_fd()" in script
    assert "open_active_verified_uv_fd()" in script
    assert 'exec {active_uv_fd}<"$uv_bin"' in script
    assert 'verify_trusted_uv_fd "$active_uv_fd" "$uv_bin"' in script
    assert "close_active_uv_fd()" in script
    assert 'descriptor_path = f"/proc/self/fd/{fd}"' in script
    assert "os.path.samefile(descriptor_path, expected_path)" in script
    assert "post_hash_fd_stat = os.fstat(fd)" in script
    assert "post_hash_path_stat = os.stat(expected_path, follow_symlinks=False)" in script
    assert "digest.hexdigest() != expected_sha256" in script
    assert "os.lseek(fd, 0, os.SEEK_CUR) != 0" in script
    assert "os.lseek(fd, 0, os.SEEK_SET)" in script
    assert "inner_uv_preflight='set -eu" in script
    assert 'mode=$(/usr/bin/stat -c %a -- "$uv_path")' in script
    assert 'test "$mode" = 500' in script
    assert 'digest_line=$(/usr/bin/sha256sum -- "$uv_path")' in script
    assert 'test "$digest" = "$expected_sha"' in script
    assert 'exec "$@"' in script

    assert script.count("open_active_verified_uv_fd") == 3
    assert script.count("close_active_uv_fd") == 5
    assert script.count("close_child_state_dir_fd") == 4
    assert '--perms 500 --ro-bind-data "$active_uv_fd" "$inner_uv_bin"' in script
    assert '--tmpfs /run\n  --perms 500 --ro-bind-data "$active_uv_fd" "$inner_uv_bin"' in script
    assert 'if (\n    close_child_state_dir_fd || exit 70\n    env -i "$bwrap_bin" \\' in script
    assert (
        '/bin/sh -c "$inner_uv_preflight" sh "$inner_uv_bin" "$pinned_uv_sha256" \\\n'
        '        "$inner_uv_bin" build --no-build-isolation' in script
    )
    assert "(\n  close_child_state_dir_fd || exit 70\n  ulimit -f 131072" in script
    assert (
        '/bin/sh -c "$inner_uv_preflight" sh "$inner_uv_bin" "$pinned_uv_sha256" \\\n'
        '      "$package_dir/.venv/bin/pytest" -q --junitxml="$junit_report" "$@"' in script
    )
    assert '"$inner_uv_bin" build --no-build-isolation' in script
    assert 'export UV_BIN="$inner_uv_bin"' in script
    assert '--setenv UV_BIN "$inner_uv_bin"' in script
    assert 'broker_child_path="/run/client:$package_dir/.venv/bin:/usr/bin:/bin"' in script
    assert "/run/client:$package_dir/.venv/bin:/run:/usr/bin:/bin" not in script


def _run_verify_trusted_uv_fd(
    uv_path: Path,
    expected_path: Path,
    expected_sha256: str,
    tmp_path: Path,
    *,
    consume_fd_before_verify: bool = False,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    script = _postgres_gate_script_source()
    verify_source = _extract_shell_function(
        script,
        "verify_trusted_uv_fd",
        "open_active_verified_uv_fd",
    )
    sentinel_file = tmp_path / f"verified-{time.time_ns()}"
    consume_line = 'dd bs=1 count=1 <&"$uv_fd" >/dev/null 2>&1' if consume_fd_before_verify else ":"
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"pinned_uv_sha256={shlex.quote(expected_sha256)}",
            verify_source,
            f"exec {{uv_fd}}<{shlex.quote(str(uv_path))}",
            consume_line,
            f'if verify_trusted_uv_fd "$uv_fd" {shlex.quote(str(expected_path))}; then',
            f"  printf verified >{shlex.quote(str(sentinel_file))}",
            "else",
            "  rc=$?",
            '  exit "$rc"',
            "fi",
        )
    )
    result = subprocess.run(
        ["bash", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    return result, sentinel_file


def test_postgres_gate_trusted_uv_fd_verifier_rejects_mismatches(
    tmp_path: Path,
) -> None:
    uv_source = tmp_path / "uv"
    uv_source.write_bytes(b"trusted uv bytes\n")
    uv_source.chmod(0o755)
    expected_sha = hashlib.sha256(uv_source.read_bytes()).hexdigest()
    other_uv = tmp_path / "other-uv"
    other_uv.write_bytes(uv_source.read_bytes())
    other_uv.chmod(0o755)

    ok_result, ok_sentinel = _run_verify_trusted_uv_fd(
        uv_source,
        uv_source,
        expected_sha,
        tmp_path,
    )
    assert ok_result.returncode == 0, ok_result.stderr
    assert ok_sentinel.read_text(encoding="ascii") == "verified"

    mismatch_result, mismatch_sentinel = _run_verify_trusted_uv_fd(
        uv_source,
        other_uv,
        expected_sha,
        tmp_path,
    )
    assert mismatch_result.returncode != 0
    assert not mismatch_sentinel.exists()

    wrong_digest_result, wrong_digest_sentinel = _run_verify_trusted_uv_fd(
        uv_source,
        uv_source,
        hashlib.sha256(b"mutated uv bytes\n").hexdigest(),
        tmp_path,
    )
    assert wrong_digest_result.returncode != 0
    assert not wrong_digest_sentinel.exists()

    offset_result, offset_sentinel = _run_verify_trusted_uv_fd(
        uv_source,
        uv_source,
        expected_sha,
        tmp_path,
        consume_fd_before_verify=True,
    )
    assert offset_result.returncode != 0
    assert not offset_sentinel.exists()


def test_postgres_gate_trusted_uv_fd_accepts_deleted_ro_bind_data_procfd(
    tmp_path: Path,
) -> None:
    bwrap_bin = _require_postgres_gate_bwrap()
    script = _postgres_gate_script_source()
    verify_source = _extract_shell_function(
        script,
        "verify_trusted_uv_fd",
        "open_active_verified_uv_fd",
    )
    uv_payload = b"trusted uv snapshot\n"
    expected_sha = hashlib.sha256(uv_payload).hexdigest()
    uv_source = tmp_path / "uv-source"
    uv_source.write_bytes(uv_payload)
    uv_source.chmod(0o755)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    fd = os.open(uv_source, os.O_RDONLY)
    try:
        result = subprocess.run(
            [
                bwrap_bin,
                "--unshare-all",
                "--unshare-user",
                "--die-with-parent",
                "--new-session",
                "--disable-userns",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--tmpfs",
                "/run",
                "--perms",
                "500",
                "--ro-bind-data",
                str(fd),
                "/run/acgs-uv",
                "--ro-bind",
                "/usr",
                "/usr",
                "--ro-bind",
                "/bin",
                "/bin",
                "--ro-bind-try",
                "/lib",
                "/lib",
                "--ro-bind-try",
                "/lib64",
                "/lib64",
                "--bind",
                str(out_dir),
                "/out",
                "--clearenv",
                "--setenv",
                "PATH",
                "/usr/bin:/bin",
                "--",
                "/bin/bash",
                "-s",
            ],
            input="\n".join(
                (
                    "set -euo pipefail",
                    f"pinned_uv_sha256={shlex.quote(expected_sha)}",
                    verify_source,
                    "exec {uv_fd}</run/acgs-uv",
                    'readlink "/proc/self/fd/$uv_fd" >/out/procfd-target',
                    'verify_trusted_uv_fd "$uv_fd" /run/acgs-uv',
                    "printf verified >/out/verified",
                )
            ),
            capture_output=True,
            text=True,
            pass_fds=(fd,),
            check=False,
        )
    finally:
        os.close(fd)

    assert result.returncode == 0, result.stderr
    assert (out_dir / "verified").read_text(encoding="ascii") == "verified"
    assert "(deleted)" in (out_dir / "procfd-target").read_text(encoding="ascii")


def test_postgres_gate_uv_fd_cleanup_is_first_cleanup_side_effect() -> None:
    script = _postgres_gate_script_source()

    cleanup_source = script.split("cleanup() {", 1)[1].split("\n}\ntrap cleanup EXIT", 1)[0]
    assert cleanup_source.splitlines()[1:5] == [
        "  local status=$?",
        "  close_active_uv_fd",
        "  close_broker_script_fd",
        "  close_pytest_output_fd",
    ]
    assert script.index("pytest_output_file=") < script.index(
        "open_active_verified_uv_fd || {\n  echo 'failed to open a fresh verified uv FD"
    )


def test_postgres_gate_rejects_old_inner_uv_path_bind_contract() -> None:
    script = _postgres_gate_script_source()

    forbidden_fragments = [
        '--ro-bind "$uv_bin" "$uv_bin"',
        '--ro-bind "$uv_bin" /run/acgs-uv',
        '--ro-bind "$uv_bin" "$inner_uv_bin"',
        '--ro-bind-data "$uv_bin"',
        '--ro-bind-data "$canonical_uv_bin"',
    ]
    for fragment in forbidden_fragments:
        assert fragment not in script


def _require_postgres_gate_bwrap() -> str:
    bwrap_bin = shutil.which("bwrap")
    if bwrap_bin is None:
        pytest.skip("bwrap is unavailable")
    preflight = subprocess.run(
        [
            bwrap_bin,
            "--unshare-all",
            "--unshare-user",
            "--die-with-parent",
            "--new-session",
            "--disable-userns",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/run",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/bin",
            "/bin",
            "--ro-bind-try",
            "/lib",
            "/lib",
            "--ro-bind-try",
            "/lib64",
            "/lib64",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--",
            "/bin/sh",
            "-c",
            "true",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if preflight.returncode != 0:
        pytest.skip(f"bwrap preflight unavailable: {preflight.stderr.strip()}")
    return bwrap_bin


def _run_inner_uv_snapshot_preflight(
    tmp_path: Path,
    uv_payload: bytes,
    *,
    expected_sha256: str | None = None,
    bind_mode: str = "500",
    seek_to_end_then_reset: bool = False,
) -> tuple[subprocess.CompletedProcess[str], Path, int]:
    bwrap_bin = _require_postgres_gate_bwrap()
    uv_source = tmp_path / "uv-source"
    uv_source.write_bytes(uv_payload)
    expected = expected_sha256 or hashlib.sha256(uv_payload).hexdigest()
    sentinel_dir = tmp_path / "sentinel"
    sentinel_dir.mkdir()
    sentinel_file = sentinel_dir / "executed"
    fd = os.open(uv_source, os.O_RDONLY)
    try:
        if seek_to_end_then_reset:
            os.read(fd, len(uv_payload))
            assert os.lseek(fd, 0, os.SEEK_CUR) == len(uv_payload)
            os.lseek(fd, 0, os.SEEK_SET)
        result = subprocess.run(
            [
                bwrap_bin,
                "--unshare-all",
                "--unshare-user",
                "--die-with-parent",
                "--new-session",
                "--disable-userns",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--tmpfs",
                "/run",
                "--perms",
                bind_mode,
                "--ro-bind-data",
                str(fd),
                "/run/acgs-uv",
                "--ro-bind",
                "/usr",
                "/usr",
                "--ro-bind",
                "/bin",
                "/bin",
                "--ro-bind-try",
                "/lib",
                "/lib",
                "--ro-bind-try",
                "/lib64",
                "/lib64",
                "--bind",
                str(sentinel_dir),
                "/out",
                "--clearenv",
                "--setenv",
                "PATH",
                "/usr/bin:/bin",
                "--",
                "/bin/sh",
                "-c",
                (
                    "set -eu\n"
                    "uv_path=$1\n"
                    "expected_sha=$2\n"
                    "shift 2\n"
                    'mode=$(/usr/bin/stat -c %a -- "$uv_path")\n'
                    'test "$mode" = 500\n'
                    'digest_line=$(/usr/bin/sha256sum -- "$uv_path")\n'
                    "digest=${digest_line%% *}\n"
                    'test "$digest" = "$expected_sha"\n'
                    'exec "$@"'
                ),
                "sh",
                "/run/acgs-uv",
                expected,
                "/bin/sh",
                "-c",
                "printf executed > /out/executed",
            ],
            capture_output=True,
            text=True,
            pass_fds=(fd,),
            check=False,
        )
    finally:
        os.close(fd)
    return result, sentinel_file, fd


def test_postgres_gate_inner_uv_snapshot_preflight_executes_only_matching_mode500(
    tmp_path: Path,
) -> None:
    result, sentinel_file, fd = _run_inner_uv_snapshot_preflight(
        tmp_path,
        b"trusted uv snapshot\n",
        seek_to_end_then_reset=True,
    )

    assert result.returncode == 0, result.stderr
    assert sentinel_file.read_text(encoding="utf-8") == "executed"
    assert not Path(f"/proc/self/fd/{fd}").exists()


def test_postgres_gate_inner_uv_snapshot_preflight_blocks_mutated_bytes(
    tmp_path: Path,
) -> None:
    expected = hashlib.sha256(b"trusted uv snapshot\n").hexdigest()
    result, sentinel_file, fd = _run_inner_uv_snapshot_preflight(
        tmp_path,
        b"mutated uv snapshot\n",
        expected_sha256=expected,
    )

    assert result.returncode != 0
    assert not sentinel_file.exists()
    assert not Path(f"/proc/self/fd/{fd}").exists()


def test_postgres_gate_inner_uv_snapshot_preflight_blocks_wrong_mode(
    tmp_path: Path,
) -> None:
    result, sentinel_file, fd = _run_inner_uv_snapshot_preflight(
        tmp_path,
        b"trusted uv snapshot\n",
        bind_mode="400",
    )

    assert result.returncode != 0
    assert not sentinel_file.exists()
    assert not Path(f"/proc/self/fd/{fd}").exists()


def test_postgres_gate_fake_entrypoint_uses_default_socket_after_clearing_pg_env(
    tmp_path: Path,
) -> None:
    script = _postgres_gate_script_source()
    config_source = _extract_shell_function(
        script,
        "verify_server_config_before_start",
        "verify_server_socket_bridge_marker",
    )
    marker_source = _extract_shell_function(
        script,
        "verify_server_socket_bridge_marker",
        "capture_postgres_server_diagnostics",
    )
    guard_wrapper = _postgres_gate_server_entrypoint_guard_wrapper(script)
    server_source = _postgres_gate_server_launch_and_health_source(script)
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    argv_log = tmp_path / "docker-argv.jsonl"
    started_marker = tmp_path / "started"
    secret_sentinel = "entrypoint-secret-sentinel"
    server_id = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    proof_label = "acp-postgres-gate-1000-0123456789abcdef0123456789abcdef"
    container_name = f"{proof_label}-server"
    docker_path = fake_bin / "docker"
    docker_path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "import json, os, sys",
                f"argv_log = {str(argv_log)!r}",
                f"started_marker = {str(started_marker)!r}",
                f"secret_sentinel = {secret_sentinel!r}",
                f"server_id = {server_id!r}",
                f"container_name = {container_name!r}",
                f"proof_label = {proof_label!r}",
                "def log(argv):",
                "    redacted = list(argv)",
                "    for index, value in enumerate(redacted[:-1]):",
                "        if value == '--env':",
                "            key = redacted[index + 1].split('=', 1)[0]",
                "            redacted[index + 1] = key + '=<redacted>'",
                "    with open(argv_log, 'a', encoding='utf-8') as handle:",
                "        handle.write(json.dumps(redacted) + '\\n')",
                "argv = sys.argv[1:]",
                "log(argv)",
                "if argv[:1] == ['create']:",
                "    env_pairs = [",
                "        argv[idx + 1] for idx, value in enumerate(argv[:-1]) if value == '--env'",
                "    ]",
                "    cmd = argv[argv.index('-ceu'):]",
                "    entrypoint = [argv[argv.index('--entrypoint') + 1]]",
                "    env_keys = [item.split('=', 1)[0] for item in env_pairs]",
                "    with open(argv_log + '.create.json', 'w', encoding='utf-8') as handle:",
                "        json.dump(",
                "            {'EnvKeys': env_keys, 'Entrypoint': entrypoint, 'Cmd': cmd},",
                "            handle,",
                "        )",
                "    print(server_id)",
                "    raise SystemExit(0)",
                "if argv[:2] == ['inspect', '--format']:",
                "    fmt = argv[2]",
                "    if fmt.startswith('{{printf \"[\"}}'):",
                "        print(json.dumps([",
                "            server_id,",
                "            '/' + container_name,",
                "            {'acgs.postgres.proof': proof_label, 'acgs.postgres.server': 'main'},",
                "            'created', False, False, False, False, False, 0, 'no',",
                "        ], separators=(',', ':')))",
                "        raise SystemExit(0)",
                "    if fmt.startswith('{\"State\"'):",
                "        create = json.load(open(argv_log + '.create.json', encoding='utf-8'))",
                "        if secret_sentinel in json.dumps(create):",
                "            raise SystemExit(88)",
                "        print(json.dumps({'State': {'Status': 'created'}, 'Config': create}))",
                "        raise SystemExit(0)",
                "    if fmt == '{{.State.Status}}':",
                "        print('running' if os.path.exists(started_marker) else 'created')",
                "        raise SystemExit(0)",
                "    if fmt == '{{.State.Health.Status}}':",
                "        print('healthy' if os.path.exists(started_marker) else 'starting')",
                "        raise SystemExit(0)",
                "if argv[:1] == ['start']:",
                "    open(started_marker, 'w', encoding='ascii').write('1')",
                "    print(argv[-1])",
                "    raise SystemExit(0)",
                "if argv[:1] == ['exec']:",
                "    if '/var/run/postgresql/.acgs-postgres-socket-bridge.v2' in ' '.join(argv):",
                "        raise SystemExit(0)",
                "    raise SystemExit(70)",
                "raise SystemExit(127)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    docker_path.chmod(0o755)
    socket_bridge = tmp_path / "bridge"
    socket_bridge.mkdir()
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"PATH={str(fake_bin)!r}:$PATH",
            "sleep() { :; }",
            "verify_docker_mounts() { return 0; }",
            "capture_postgres_server_diagnostics() { exit 91; }",
            f"state_dir={str(tmp_path / 'state')!r}",
            'mkdir -p "$state_dir"',
            f"container_name={container_name!r}",
            f"server_cidfile={str(tmp_path / 'server.cid')!r}",
            f"proof_label={proof_label!r}",
            "postgres_image='postgres@example'",
            "main_database='acgs'",
            "postgres_user='acgs'",
            f"postgres_password={secret_sentinel!r}",
            f"postgres_socket_bridge={str(socket_bridge)!r}",
            "postgres_socket_bridge_identity='1:2:3:1777'",
            "postgres_socket_bridge_marker_sha256='" + ("a" * 64) + "'",
            "expected_server_cid=''",
            "created_server_record=''",
            "created_server_state=''",
            "container_status=''",
            "health_status=''",
            _extract_shell_function(
                script,
                "validate_exact_recorded_container",
                "remove_exact_recorded_container",
            ),
            config_source,
            marker_source,
            f"postgres_entrypoint_guard_wrapper={shlex.quote(guard_wrapper)}",
            server_source,
            "test -f " + shlex.quote(str(started_marker)),
        )
    )
    result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert secret_sentinel not in result.stdout
    assert secret_sentinel not in result.stderr
    assert secret_sentinel not in argv_log.read_text(encoding="utf-8")
    lines = [json.loads(line) for line in argv_log.read_text(encoding="utf-8").splitlines()]
    assert [line[0] for line in lines if line] == [
        "create",
        "inspect",
        "inspect",
        "start",
        "exec",
        "inspect",
        "inspect",
        "inspect",
    ]
    create = lines[0]
    env_pairs = [create[index + 1] for index, value in enumerate(create[:-1]) if value == "--env"]
    assert "PGSERVICE=acgs-entrypoint-init" not in env_pairs
    assert not any(value.startswith("PGSERVICEFILE=") for value in env_pairs)
    assert all(not value.startswith("PGHOST=") for value in env_pairs)
    assert "--mount" in create
    assert "type=bind,src=" + str(socket_bridge) + ",dst=/var/run/postgresql" in create
    assert "/run/acgs-pg-service.conf" not in " ".join(create)
    assert create[create.index("--entrypoint") + 1] == "/bin/sh"
    cmd_start = create.index("-ceu")
    assert create[cmd_start + 2] == "acgs-postgres-entrypoint-guard"
    assert 'exec /usr/local/bin/docker-entrypoint.sh "$@"' in create[cmd_start + 1]
    assert create[-10:] == [
        "-ceu",
        create[cmd_start + 1],
        "acgs-postgres-entrypoint-guard",
        "postgres",
        "-c",
        "listen_addresses=",
        "-c",
        "unix_socket_directories=/var/run/postgresql",
        "-c",
        "unix_socket_permissions=0777",
    ]
    inspect_payload = (argv_log.with_suffix(argv_log.suffix + ".create.json")).read_text(
        encoding="utf-8"
    )
    assert secret_sentinel not in inspect_payload


def _postgres_gate_server_entrypoint_guard_wrapper(script: str) -> str:
    marker = "postgres_entrypoint_guard_wrapper='"
    start = script.index(marker) + len(marker)
    end = script.index("'\n", start)
    return script[start:end]


@pytest.mark.parametrize(
    ("case_name", "expected_rc", "entrypoint_expected"),
    [
        ("ok", 0, True),
        ("rename-substitute", 70, False),
        ("wrong-dir-mode", 70, False),
        ("marker-directory", 70, False),
        ("marker-symlink", 70, False),
        ("marker-hardlink", 70, False),
        ("marker-mode", 70, False),
        ("marker-hash", 70, False),
        ("marker-owner", 70, False),
    ],
)
def test_postgres_gate_server_entrypoint_guard_revalidates_actual_bind_mount(
    tmp_path: Path,
    case_name: str,
    expected_rc: int,
    entrypoint_expected: bool,
) -> None:
    script = _postgres_gate_script_source()
    wrapper = _postgres_gate_server_entrypoint_guard_wrapper(script)
    socket_bridge = tmp_path / "bridge"
    bridge_identity, bridge_marker_sha256, _bridge_mnt_id = _write_postgres_socket_bridge(
        socket_bridge,
        "acgs-proof-label",
        "0" * 32,
    )
    marker = socket_bridge / ".acgs-postgres-socket-bridge.v2"
    expected_uid = bridge_identity.split(":")[2]

    if case_name == "rename-substitute":
        saved_bridge = tmp_path / "bridge-original"
        socket_bridge.rename(saved_bridge)
        socket_bridge.mkdir(mode=0o700)
        socket_bridge.chmod(0o1777)
        (socket_bridge / ".acgs-postgres-socket-bridge.v2").write_text(
            "substitute\n",
            encoding="ascii",
        )
        (socket_bridge / ".acgs-postgres-socket-bridge.v2").chmod(0o444)
    elif case_name == "wrong-dir-mode":
        socket_bridge.chmod(0o700)
    elif case_name == "marker-directory":
        marker.unlink()
        marker.mkdir()
    elif case_name == "marker-symlink":
        marker.unlink()
        marker.symlink_to("/etc/passwd")
    elif case_name == "marker-hardlink":
        os.link(marker, marker.with_name(".acgs-postgres-socket-bridge.v2.link"))
    elif case_name == "marker-mode":
        marker.chmod(0o644)
    elif case_name == "marker-hash":
        marker.chmod(0o644)
        marker.write_text("tampered\n", encoding="ascii")
        marker.chmod(0o444)
    elif case_name == "marker-owner":
        wrapper = wrapper.replace(
            "${guard_expected_uid}:1:444",
            f"{int(expected_uid) + 1}:1:444",
        )

    fake_entrypoint = tmp_path / "docker-entrypoint.sh"
    sentinel = tmp_path / "official-entrypoint-called"
    fake_entrypoint.write_text(
        "\n".join(
            [
                "#!/bin/sh",
                '[ "${ACGS_POSTGRES_SOCKET_BRIDGE_EXPECTED_IDENTITY+set}" != set ] || exit 81',
                '[ "${ACGS_POSTGRES_SOCKET_BRIDGE_MARKER_SHA256+set}" != set ] || exit 82',
                f"printf '%s\\n' \"$@\" > {shlex.quote(str(sentinel))}",
            ]
        )
        + "\n",
        encoding="ascii",
    )
    fake_entrypoint.chmod(0o755)
    executable_wrapper = wrapper.replace(
        "guard_dir=/var/run/postgresql;",
        f"guard_dir={shlex.quote(str(socket_bridge))};",
    ).replace(
        "/usr/local/bin/docker-entrypoint.sh",
        shlex.quote(str(fake_entrypoint)),
    )
    secret_sentinel = "server-entrypoint-password-secret"
    env = {
        "ACGS_POSTGRES_SOCKET_BRIDGE_EXPECTED_IDENTITY": bridge_identity,
        "ACGS_POSTGRES_SOCKET_BRIDGE_MARKER_SHA256": bridge_marker_sha256,
        "POSTGRES_PASSWORD": secret_sentinel,
    }
    result = subprocess.run(
        [
            "sh",
            "-ceu",
            executable_wrapper,
            "acgs-postgres-entrypoint-guard",
            "postgres",
            "-c",
            "listen_addresses=",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == expected_rc, (case_name, result.stdout, result.stderr)
    assert secret_sentinel not in result.stdout
    assert secret_sentinel not in result.stderr
    assert sentinel.exists() is entrypoint_expected
    if entrypoint_expected:
        assert result.stdout == ""
        assert result.stderr == ""
        assert sentinel.read_text(encoding="ascii").splitlines() == [
            "postgres",
            "-c",
            "listen_addresses=",
        ]
    else:
        assert result.stdout == ""
        assert result.stderr == "PostgreSQL socket bridge guard rejected mounted source\n"


@pytest.mark.parametrize(
    ("mode", "expected_rc"),
    [
        ("ok", 0),
        ("forbidden-pghost", 70),
        ("forbidden-pgservice", 70),
        ("forbidden-pgservicefile", 70),
        ("duplicate-env-key", 70),
        ("malformed-env-key", 70),
        ("wrong-status", 70),
        ("wrong-command", 70),
        ("wrong-entrypoint", 70),
        ("wrong-wrapper", 70),
        ("wrong-args", 70),
        ("missing-guard-identity", 70),
        ("missing-guard-marker-sha", 70),
        ("missing-both-guard-keys", 70),
        ("missing-postgres-initdb-args", 70),
    ],
)
def test_postgres_gate_server_config_verifier_uses_key_only_env_inspect(
    tmp_path: Path,
    mode: str,
    expected_rc: int,
) -> None:
    script = _postgres_gate_script_source()
    verify_source = _extract_shell_function(
        script,
        "verify_server_config_before_start",
        "verify_server_socket_bridge_marker",
    )
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    argv_log = tmp_path / "docker-config-argv.jsonl"
    secret_sentinel = "postgres-password-must-not-enter-config-inspect"
    expected_wrapper = "expected-entrypoint-guard-wrapper"
    server_id = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    docker_path = fake_bin / "docker"
    docker_path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "import json, sys",
                f"argv_log = {str(argv_log)!r}",
                f"mode = {mode!r}",
                "with open(argv_log, 'a', encoding='utf-8') as handle:",
                "    handle.write(json.dumps(sys.argv[1:]) + '\\n')",
                "if sys.argv[1:3] == ['inspect', '--format']:",
                "    env_keys = [",
                "        'POSTGRES_DB',",
                "        'POSTGRES_USER',",
                "        'POSTGRES_PASSWORD',",
                "        'POSTGRES_INITDB_ARGS',",
                "        'ACGS_POSTGRES_SOCKET_BRIDGE_EXPECTED_IDENTITY',",
                "        'ACGS_POSTGRES_SOCKET_BRIDGE_MARKER_SHA256',",
                "    ]",
                "    status = 'created'",
                "    entrypoint = ['/bin/sh']",
                "    cmd = [",
                "        '-ceu',",
                "        'expected-entrypoint-guard-wrapper',",
                "        'acgs-postgres-entrypoint-guard',",
                "        'postgres', '-c', 'listen_addresses=', '-c',",
                "        'unix_socket_directories=/var/run/postgresql', '-c',",
                "        'unix_socket_permissions=0777',",
                "    ]",
                "    if mode == 'forbidden-pghost':",
                "        env_keys.append('PGHOST')",
                "    elif mode == 'forbidden-pgservice':",
                "        env_keys.append('PGSERVICE')",
                "    elif mode == 'forbidden-pgservicefile':",
                "        env_keys.append('PGSERVICEFILE')",
                "    elif mode == 'duplicate-env-key':",
                "        env_keys.append('POSTGRES_DB')",
                "    elif mode == 'malformed-env-key':",
                "        env_keys.append('BAD=KEY')",
                "    elif mode == 'wrong-status':",
                "        status = 'running'",
                "    elif mode == 'wrong-command':",
                "        cmd = ['postgres', '-c', 'unix_socket_directories=/run/acgs-pg']",
                "    elif mode == 'wrong-entrypoint':",
                "        entrypoint = ['/usr/local/bin/docker-entrypoint.sh']",
                "    elif mode == 'wrong-wrapper':",
                "        cmd[1] = 'altered-wrapper'",
                "    elif mode == 'wrong-args':",
                "        cmd[2] = 'altered-guard-argv0'",
                "    elif mode == 'missing-guard-identity':",
                "        env_keys.remove('ACGS_POSTGRES_SOCKET_BRIDGE_EXPECTED_IDENTITY')",
                "    elif mode == 'missing-guard-marker-sha':",
                "        env_keys.remove('ACGS_POSTGRES_SOCKET_BRIDGE_MARKER_SHA256')",
                "    elif mode == 'missing-both-guard-keys':",
                "        env_keys.remove('ACGS_POSTGRES_SOCKET_BRIDGE_EXPECTED_IDENTITY')",
                "        env_keys.remove('ACGS_POSTGRES_SOCKET_BRIDGE_MARKER_SHA256')",
                "    elif mode == 'missing-postgres-initdb-args':",
                "        env_keys.remove('POSTGRES_INITDB_ARGS')",
                "    snapshot = {",
                "        'State': {'Status': status},",
                "        'Config': {",
                "            'EnvKeys': env_keys,",
                "            'Entrypoint': entrypoint,",
                "            'Cmd': cmd,",
                "        },",
                "    }",
                "    print(json.dumps(snapshot))",
                "    raise SystemExit(0)",
                "raise SystemExit(127)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    docker_path.chmod(0o755)
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"PATH={str(fake_bin)!r}:$PATH",
            f"secret_sentinel={secret_sentinel!r}",
            verify_source,
            f"verify_server_config_before_start {server_id} {shlex.quote(expected_wrapper)}",
        )
    )
    result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == expected_rc, (mode, result.stdout, result.stderr)
    assert secret_sentinel not in result.stdout
    assert secret_sentinel not in result.stderr
    docker_argv = argv_log.read_text(encoding="utf-8")
    assert secret_sentinel not in docker_argv
    assert "POSTGRES_PASSWORD=" not in docker_argv


@pytest.mark.parametrize("failure_mode", ["mount", "config", "missing-guard-identity"])
def test_postgres_gate_server_pre_start_verification_failure_never_starts_container(
    tmp_path: Path,
    failure_mode: str,
) -> None:
    script = _postgres_gate_script_source()
    config_source = _extract_shell_function(
        script,
        "verify_server_config_before_start",
        "verify_server_socket_bridge_marker",
    )
    guard_wrapper = _postgres_gate_server_entrypoint_guard_wrapper(script)
    server_source = _postgres_gate_server_launch_and_health_source(script)
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    docker_log = tmp_path / "docker-prestart.jsonl"
    server_id = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    proof_label = "acp-postgres-gate-1000-0123456789abcdef0123456789abcdef"
    container_name = f"{proof_label}-server"
    docker_path = fake_bin / "docker"
    docker_path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "import json, sys",
                f"docker_log = {str(docker_log)!r}",
                f"failure_mode = {failure_mode!r}",
                f"server_id = {server_id!r}",
                f"container_name = {container_name!r}",
                f"proof_label = {proof_label!r}",
                "def redacted(argv):",
                "    result = list(argv)",
                "    for index, value in enumerate(result[:-1]):",
                "        if value == '--env':",
                "            key = result[index + 1].split('=', 1)[0]",
                "            result[index + 1] = key + '=<redacted>'",
                "    return result",
                "with open(docker_log, 'a', encoding='utf-8') as handle:",
                "    handle.write(json.dumps(redacted(sys.argv[1:])) + '\\n')",
                "argv = sys.argv[1:]",
                "if argv[:1] == ['create']:",
                "    env_pairs = [",
                "        argv[idx + 1] for idx, value in enumerate(argv[:-1]) if value == '--env'",
                "    ]",
                "    env_keys = [item.split('=', 1)[0] for item in env_pairs]",
                "    cmd = argv[argv.index('-ceu'):]",
                "    entrypoint = [argv[argv.index('--entrypoint') + 1]]",
                "    with open(docker_log + '.create.json', 'w', encoding='utf-8') as handle:",
                "        json.dump(",
                "            {'EnvKeys': env_keys, 'Entrypoint': entrypoint, 'Cmd': cmd},",
                "            handle,",
                "        )",
                "    print(server_id)",
                "    raise SystemExit(0)",
                "if argv[:2] == ['inspect', '--format']:",
                "    fmt = argv[2]",
                "    if fmt.startswith('{{printf \"[\"}}'):",
                "        print(json.dumps([",
                "            server_id,",
                "            '/' + container_name,",
                "            {'acgs.postgres.proof': proof_label, 'acgs.postgres.server': 'main'},",
                "            'created', False, False, False, False, False, 0, 'no',",
                "        ], separators=(',', ':')))",
                "        raise SystemExit(0)",
                "    create = json.load(open(docker_log + '.create.json', encoding='utf-8'))",
                "    if failure_mode == 'config':",
                "        create['EnvKeys'].append('PGSERVICE')",
                "    elif failure_mode == 'missing-guard-identity':",
                "        create['EnvKeys'].remove('ACGS_POSTGRES_SOCKET_BRIDGE_EXPECTED_IDENTITY')",
                "    snapshot = {",
                "        'State': {'Status': 'created'},",
                "        'Config': create,",
                "    }",
                "    print(json.dumps(snapshot))",
                "    raise SystemExit(0)",
                "if argv[:1] == ['start']:",
                "    raise SystemExit(99)",
                "raise SystemExit(127)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    docker_path.chmod(0o755)
    socket_bridge = tmp_path / "bridge"
    socket_bridge.mkdir()
    verify_mounts = (
        "verify_docker_mounts() { return 70; }"
        if failure_mode == "mount"
        else "verify_docker_mounts() { return 0; }"
    )
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"PATH={str(fake_bin)!r}:$PATH",
            verify_mounts,
            "capture_postgres_server_diagnostics() { exit 91; }",
            f"state_dir={str(tmp_path / 'state')!r}",
            'mkdir -p "$state_dir"',
            f"container_name={container_name!r}",
            f"server_cidfile={str(tmp_path / 'server.cid')!r}",
            f"proof_label={proof_label!r}",
            "postgres_image='postgres@example'",
            "main_database='acgs'",
            "postgres_user='acgs'",
            "postgres_password='entrypoint-secret'",
            f"postgres_socket_bridge={str(socket_bridge)!r}",
            "postgres_socket_bridge_identity='1:2:3:1777'",
            "postgres_socket_bridge_marker_sha256='" + ("a" * 64) + "'",
            "expected_server_cid=''",
            "created_server_record=''",
            "created_server_state=''",
            _extract_shell_function(
                script,
                "validate_exact_recorded_container",
                "remove_exact_recorded_container",
            ),
            config_source,
            f"postgres_entrypoint_guard_wrapper={shlex.quote(guard_wrapper)}",
            server_source,
        )
    )
    result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 70, (result.stdout, result.stderr)
    docker_calls = [
        json.loads(line) for line in docker_log.read_text(encoding="utf-8").splitlines()
    ]
    assert [call[0] for call in docker_calls] == ["create", "inspect"] + (
        ["inspect"] if failure_mode != "mount" else []
    )
    assert not any(call[:1] == ["start"] for call in docker_calls)


def _postgres_gate_python_runtime_validation_source() -> str:
    script = (Path(__file__).resolve().parents[1] / "scripts" / "run_postgres_gate.sh").read_text(
        encoding="utf-8"
    )
    start = script.index(
        'canonical_venv_python="$(realpath -e -- "$package_dir/.venv/bin/python")"\n'
    )
    end = script.index("\numask 077\n", start)
    return script[start:end]


def _write_control_plane_venv_python(package_dir: Path, target: Path) -> None:
    (package_dir / ".venv/bin").mkdir(parents=True)
    target.parent.mkdir(parents=True)
    target.write_text("#!/bin/sh\n", encoding="utf-8")
    target.chmod(0o755)
    (package_dir / ".venv/bin/python").symlink_to(target)


def _mkdir_private(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def _run_postgres_gate_python_runtime_validation(
    package_dir: Path,
    *,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    script = (
        'package_dir="$1"\n'
        f"{_postgres_gate_python_runtime_validation_source()}\n"
        'printf "%s\\n" "$python_runtime_root"\n'
    )
    validation_env = {"PATH": os.environ["PATH"]}
    for name in ("TMPDIR", "UV_PYTHON_INSTALL_DIR"):
        if name in os.environ:
            validation_env[name] = os.environ[name]
    if env:
        validation_env.update(env)
    return subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s", "--", str(package_dir)],
        input=script,
        env=validation_env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_postgres_gate_python_runtime_accepts_default_and_proof_scratch(
    tmp_path: Path,
) -> None:
    package_dir = Path(__file__).resolve().parents[1]
    default_result = _run_postgres_gate_python_runtime_validation(package_dir)
    assert default_result.returncode == 0, default_result.stderr
    if os.environ.get("UV_PYTHON_INSTALL_DIR"):
        assert default_result.stdout.strip().startswith(f"{os.environ['UV_PYTHON_INSTALL_DIR']}/")
    else:
        assert "/home/" in default_result.stdout
        assert "/.local/share/uv/python/" in default_result.stdout

    proof_root = tmp_path / "proof-root"
    runtime_tmp = proof_root / "scratch/tmp"
    install_root = proof_root / "runtime/uv-python"
    runtime_root = install_root / "cpython-3.13-linux-x86_64-gnu"
    proof_package = tmp_path / "proof-package"
    for directory in (
        proof_root,
        proof_root / "scratch",
        runtime_tmp,
        proof_root / "runtime",
        install_root,
    ):
        _mkdir_private(directory)
    _write_control_plane_venv_python(proof_package, runtime_root / "bin/python3.13")

    proof_result = _run_postgres_gate_python_runtime_validation(
        proof_package,
        env={"TMPDIR": str(runtime_tmp), "UV_PYTHON_INSTALL_DIR": str(install_root)},
    )
    assert proof_result.returncode == 0, proof_result.stderr
    assert proof_result.stdout.strip() == str(runtime_root)


@pytest.mark.parametrize(
    ("case_name", "expected_stderr"),
    (
        ("relative-install-root", "UV_PYTHON_INSTALL_DIR must be absolute"),
        ("symlink-install-root", "UV_PYTHON_INSTALL_DIR must be canonical and non-symlinked"),
        ("traversal-install-root", "UV_PYTHON_INSTALL_DIR must be canonical and non-symlinked"),
        ("untrusted-root", "UV_PYTHON_INSTALL_DIR must equal the proof runtime uv-python"),
        ("scratch-install-root", "UV_PYTHON_INSTALL_DIR must equal the proof runtime uv-python"),
        ("bad-tmp-parent", "TMPDIR must be nested under the proof scratch/tmp directory"),
        ("world-writable-proof-root", "must be owned by the current user with mode 700"),
        ("raw-target-traversal", "must resolve beneath UV_PYTHON_INSTALL_DIR"),
        ("wrong-runtime-root", "must resolve beneath UV_PYTHON_INSTALL_DIR"),
    ),
)
def test_postgres_gate_python_runtime_rejects_untrusted_proof_roots(
    tmp_path: Path,
    case_name: str,
    expected_stderr: str,
) -> None:
    proof_root = tmp_path / "proof-root"
    runtime_tmp = proof_root / "scratch/tmp"
    install_root = proof_root / "runtime/uv-python"
    runtime_root = install_root / "cpython-3.13-linux-x86_64-gnu"
    package_dir = tmp_path / "package"
    for directory in (
        proof_root,
        proof_root / "scratch",
        runtime_tmp,
        proof_root / "runtime",
        install_root,
    ):
        _mkdir_private(directory)

    env = {"TMPDIR": str(runtime_tmp), "UV_PYTHON_INSTALL_DIR": str(install_root)}
    target = runtime_root / "bin/python3.13"
    if case_name == "relative-install-root":
        env["UV_PYTHON_INSTALL_DIR"] = "relative/uv-python"
    elif case_name == "symlink-install-root":
        linked_install = tmp_path / "linked-uv-python"
        linked_install.symlink_to(install_root, target_is_directory=True)
        env["UV_PYTHON_INSTALL_DIR"] = str(linked_install)
    elif case_name == "traversal-install-root":
        env["UV_PYTHON_INSTALL_DIR"] = str(install_root / ".." / "uv-python")
    elif case_name == "untrusted-root":
        other_runtime_tmp = tmp_path / "other-proof-root/scratch/tmp"
        for directory in (
            tmp_path / "other-proof-root",
            tmp_path / "other-proof-root/scratch",
            other_runtime_tmp,
        ):
            _mkdir_private(directory)
        env["TMPDIR"] = str(other_runtime_tmp)
    elif case_name == "scratch-install-root":
        scratch_install = proof_root / "scratch/uv-python"
        _mkdir_private(scratch_install)
        env["UV_PYTHON_INSTALL_DIR"] = str(scratch_install)
    elif case_name == "bad-tmp-parent":
        bad_runtime_tmp = proof_root / "tmp"
        _mkdir_private(bad_runtime_tmp)
        env["TMPDIR"] = str(bad_runtime_tmp)
    elif case_name == "world-writable-proof-root":
        proof_root.chmod(0o777)
    elif case_name == "raw-target-traversal":
        target = install_root / "../evil/bin/python3.13"
    elif case_name == "wrong-runtime-root":
        other_install = tmp_path / "other-install"
        target = other_install / "cpython-3.13-linux-x86_64-gnu/bin/python3.13"

    _write_control_plane_venv_python(package_dir, target)
    result = _run_postgres_gate_python_runtime_validation(package_dir, env=env)
    assert result.returncode == 69
    assert expected_stderr in result.stderr


def _write_postgres_socket_bridge(
    socket_bridge: Path,
    proof_label: str,
    proof_nonce: str,
) -> tuple[str, str, str]:
    socket_bridge.mkdir(mode=0o700)
    socket_bridge.chmod(0o1777)
    bridge_stat = socket_bridge.stat(follow_symlinks=False)
    bridge_identity = f"{bridge_stat.st_dev}:{bridge_stat.st_ino}:{bridge_stat.st_uid}:1777"
    fd = os.open(socket_bridge, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        bridge_mnt_id = ""
        with open(f"/proc/self/fdinfo/{fd}", encoding="utf-8") as fdinfo:
            for line in fdinfo:
                if line.startswith("mnt_id:"):
                    bridge_mnt_id = line.split(":", 1)[1].strip()
                    break
    finally:
        os.close(fd)
    assert bridge_mnt_id.isdigit()
    marker_payload = "\n".join(
        (
            "schema=acgs-postgres-socket-bridge/v2",
            f"proof_nonce={proof_nonce}",
            f"proof_label={proof_label}",
            f"bridge_basename={socket_bridge.name}",
            f"bridge_identity={bridge_identity}",
            f"bridge_mnt_id={bridge_mnt_id}",
            "",
        )
    ).encode("ascii")
    marker = socket_bridge / ".acgs-postgres-socket-bridge.v2"
    marker.write_bytes(marker_payload)
    marker.chmod(0o444)
    return bridge_identity, hashlib.sha256(marker_payload).hexdigest(), bridge_mnt_id


def _mount_id(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        with open(f"/proc/self/fdinfo/{fd}", encoding="utf-8") as fdinfo:
            for line in fdinfo:
                if line.startswith("mnt_id:"):
                    value = line.split(":", 1)[1].strip()
                    assert value.isdigit()
                    return value
    finally:
        os.close(fd)
    raise AssertionError("mnt_id missing")


def _canonical_tmp_root() -> Path:
    tmp_root = Path("/tmp")
    assert tmp_root.exists()
    assert tmp_root.is_dir()
    assert not tmp_root.is_symlink()
    canonical_tmp = tmp_root.resolve(strict=True)
    assert canonical_tmp == tmp_root
    return canonical_tmp


def _private_canonical_tmp_dir(prefix: str, request: pytest.FixtureRequest) -> Path:
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=_canonical_tmp_root()))
    request.addfinalizer(lambda: shutil.rmtree(path, ignore_errors=True))
    path.chmod(0o700)
    path_stat = path.stat(follow_symlinks=False)
    assert path_stat.st_uid == os.getuid()
    assert stat.S_IMODE(path_stat.st_mode) == 0o700
    return path


def _directory_identity(path: Path) -> tuple[int, int, int, int]:
    path_stat = path.stat(follow_symlinks=False)
    assert stat.S_ISDIR(path_stat.st_mode)
    return (
        path_stat.st_dev,
        path_stat.st_ino,
        path_stat.st_uid,
        stat.S_IMODE(path_stat.st_mode),
    )


def _recovery_root_binding(path: Path) -> str:
    root_stat = path.stat(follow_symlinks=False)
    return (
        "acgs-postgres-recovery-root/v2\t"
        f"{root_stat.st_dev}:{root_stat.st_ino}:{root_stat.st_uid}:700\t"
        f"{_mount_id(path)}"
    )


def _run_recovery_root_binding_validation(
    recovery_root: Path,
    binding: str,
    sentinel: Path,
) -> subprocess.CompletedProcess[str]:
    script = _postgres_gate_script_source()
    validate_root_source = _extract_shell_function(
        script,
        "validate_postgres_recovery_root",
        "validate_postgres_recovery_root_binding",
    )
    validate_binding_source = _extract_shell_function_before_marker(
        script,
        "validate_postgres_recovery_root_binding",
        "\n\nmint_postgres_proof_nonce",
    )
    harness = "\n".join(
        (
            "set -u",
            f"postgres_recovery_root={str(recovery_root)!r}",
            f"postgres_recovery_root_binding={shlex.quote(binding)}",
            validate_root_source,
            validate_binding_source,
            'if ! postgres_recovery_root="$(validate_postgres_recovery_root '
            '"$postgres_recovery_root")"; then',
            '  printf "VALID_BINDING_RC=70\\n"',
            "  exit 70",
            "fi",
            'if observed_mnt_id="$(validate_postgres_recovery_root_binding '
            '"$postgres_recovery_root" "$postgres_recovery_root_binding")"; then',
            f"  touch {shlex.quote(str(sentinel))}",
            '  printf "VALID_BINDING_MNT_ID=%s\\n" "$observed_mnt_id"',
            "  exit 0",
            "else",
            '  printf "VALID_BINDING_RC=70\\n"',
            "  exit 70",
            "fi",
        )
    )
    return subprocess.run(
        ["bash", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )


def test_postgres_gate_recovery_root_binding_validation_accepts_exact_identity(
    tmp_path: Path,
) -> None:
    recovery_root = tmp_path / "recovery"
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    sentinel = tmp_path / "binding-sentinel"

    result = _run_recovery_root_binding_validation(
        recovery_root,
        _recovery_root_binding(recovery_root),
        sentinel,
    )

    assert result.returncode == 0, result.stderr
    assert f"VALID_BINDING_MNT_ID={_mount_id(recovery_root)}\n" in result.stdout
    assert sentinel.exists()


def test_postgres_gate_recovery_root_binding_validation_refuses_bad_inputs(
    request: pytest.FixtureRequest,
) -> None:
    tmp_root = _private_canonical_tmp_dir("acp-pg-binding-", request)
    recovery_root = tmp_root / "recovery"
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    exact_binding = _recovery_root_binding(recovery_root)
    exact_mnt_id = _mount_id(recovery_root)
    stat_fields = recovery_root.stat(follow_symlinks=False)
    exact_identity = f"{stat_fields.st_dev}:{stat_fields.st_ino}:{stat_fields.st_uid}:700"
    cases = {
        "missing": "",
        "malformed": "acgs-postgres-recovery-root/v2\ttoo-few-fields",
        "wrong-schema": f"wrong/v2\t{exact_identity}\t{exact_mnt_id}",
        "wrong-identity": f"acgs-postgres-recovery-root/v2\t1:2:3:700\t{exact_mnt_id}",
        "wrong-mount": f"acgs-postgres-recovery-root/v2\t{exact_identity}\t0",
        "malformed-mount": f"acgs-postgres-recovery-root/v2\t{exact_identity}\tnot-a-mount",
    }
    for name, binding in cases.items():
        sentinel = tmp_root / f"{name}-sentinel"
        result = _run_recovery_root_binding_validation(recovery_root, binding, sentinel)
        assert result.returncode == 70, (name, result.stdout, result.stderr)
        assert "VALID_BINDING_RC=70\n" in result.stdout
        assert not sentinel.exists()

    recovery_root.chmod(0o770)
    mode_sentinel = tmp_root / "wrong-mode-sentinel"
    mode_result = _run_recovery_root_binding_validation(
        recovery_root,
        exact_binding,
        mode_sentinel,
    )
    assert mode_result.returncode == 70, (mode_result.stdout, mode_result.stderr)
    assert not mode_sentinel.exists()
    recovery_root.chmod(0o700)

    symlink_root = tmp_root / "recovery-link"
    symlink_root.symlink_to(recovery_root, target_is_directory=True)
    symlink_sentinel = tmp_root / "symlink-sentinel"
    symlink_result = _run_recovery_root_binding_validation(
        symlink_root,
        exact_binding,
        symlink_sentinel,
    )
    assert symlink_result.returncode == 70, (symlink_result.stdout, symlink_result.stderr)
    assert not symlink_sentinel.exists()

    replacement_root = tmp_root / "recovery-replacement"
    replacement_root.mkdir()
    replacement_root.chmod(0o700)
    assert _directory_identity(replacement_root) != _directory_identity(recovery_root)
    shutil.rmtree(recovery_root)
    replacement_root.rename(recovery_root)
    replaced_sentinel = tmp_root / "post-mint-replaced-sentinel"
    replaced_result = _run_recovery_root_binding_validation(
        recovery_root,
        exact_binding,
        replaced_sentinel,
    )
    assert replaced_result.returncode == 70, (replaced_result.stdout, replaced_result.stderr)
    assert not replaced_sentinel.exists()

    current_binding = _recovery_root_binding(recovery_root)
    renamed_original = tmp_root / "recovery-original-renamed"
    rename_replacement = tmp_root / "recovery-rename-replacement"
    rename_replacement.mkdir()
    rename_replacement.chmod(0o700)
    assert _directory_identity(rename_replacement) != _directory_identity(recovery_root)
    recovery_root.rename(renamed_original)
    rename_replacement.rename(recovery_root)
    renamed_sentinel = tmp_root / "rename-replaced-sentinel"
    renamed_result = _run_recovery_root_binding_validation(
        recovery_root,
        current_binding,
        renamed_sentinel,
    )
    assert renamed_result.returncode == 70, (renamed_result.stdout, renamed_result.stderr)
    assert not renamed_sentinel.exists()


def _write_fake_postgres_client_docker(
    docker_path: Path,
    docker_log: Path,
    docker_state: Path,
    mounts: list[dict[str, object]],
    *,
    mode: str = "ok",
) -> None:
    docker_path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "import json, os, shlex, subprocess, sys, time",
                "from pathlib import Path",
                "args = sys.argv[1:]",
                f"log = Path({str(docker_log)!r})",
                f"state = Path({str(docker_state)!r})",
                f"mounts = json.loads({json.dumps(mounts)!r})",
                f"mode = {mode!r}",
                "cid = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'",
                "def normalized_mount_snapshot():",
                "    if state.exists():",
                "        raw_args = json.loads(state.read_text(encoding='utf-8'))['args']",
                "        bind_mounts = []",
                "        tmpfs = {}",
                "        for index, value in enumerate(raw_args):",
                "            if value == '--mount':",
                "                raw_parts = raw_args[index + 1].split(',')",
                "                parts = dict(",
                "                    part.split('=', 1) for part in raw_parts if '=' in part",
                "                )",
                "                bind_mounts.append(",
                "                    {",
                "                        'Type': parts['type'],",
                "                        'Source': parts['src'],",
                "                        'Destination': parts['dst'],",
                "                        'RW': 'readonly' not in raw_parts,",
                "                        'Mode': '',",
                "                        'Propagation': 'rprivate',",
                "                    }",
                "                )",
                "            elif value == '--tmpfs':",
                "                target, _separator, options = raw_args[index + 1].partition(':')",
                "                tmpfs[target] = options",
                "        return {'Mounts': bind_mounts, 'HostConfig': {'Tmpfs': tmpfs}}",
                "    bind_mounts = []",
                "    tmpfs = {}",
                "    for mount in mounts:",
                "        if mount.get('Type') == 'tmpfs':",
                "            destination = mount['Destination']",
                "            tmpfs[destination] = mount.get(",
                "                'Options',",
                "                'rw,noexec,nosuid,nodev,mode=1777,size=512m',",
                "            )",
                "            continue",
                "        item = dict(mount)",
                "        item.setdefault('Mode', '')",
                "        item.setdefault('Propagation', 'rprivate')",
                "        bind_mounts.append(item)",
                "    return {'Mounts': bind_mounts, 'HostConfig': {'Tmpfs': tmpfs}}",
                "def append_log(payload):",
                "    with log.open('a', encoding='utf-8') as handle:",
                "        handle.write(json.dumps(payload, separators=(',', ':')) + '\\n')",
                "def create_args_mount_source(target):",
                "    data = json.loads(state.read_text(encoding='utf-8'))",
                "    raw_args = data['args']",
                "    for index, value in enumerate(raw_args):",
                "        if value == '--mount':",
                "            parts = dict(",
                "                item.split('=', 1)",
                "                for item in raw_args[index + 1].split(',')",
                "                if '=' in item",
                "            )",
                "            if parts.get('dst') == target:",
                "                return Path(parts['src'])",
                "    raise SystemExit(70)",
                "if args[:2] == ['info', '--format']:",
                "    print('[\"name=rootless\"]')",
                "    raise SystemExit(0)",
                "if args[:2] == ['inspect', '--format'] and args[2].startswith('{\"Mounts\":'):",
                "    if mode == 'fast-inspect-fail':",
                "        raise SystemExit(1)",
                "    if mode == 'malformed-inspect':",
                "        print('{')",
                "        raise SystemExit(0)",
                "    if mode == 'oversized-inspect':",
                "        print('x' * 70000)",
                "        raise SystemExit(0)",
                "    if mode == 'duplicate-json-top':",
                '        print(\'{"Mounts":[],"Mounts":[],"HostConfig":{"Tmpfs":{}}}\')',
                "        raise SystemExit(0)",
                "    if mode == 'duplicate-json-nested':",
                '        print(\'{"Mounts":[],"HostConfig":{"Tmpfs":{},"Tmpfs":{}}}\')',
                "        raise SystemExit(0)",
                "    if mode == 'duplicate-json-bind-field':",
                "        print(",
                '            \'{"Mounts":[{"Type":"bind","Type":"bind",\'',
                '            \'"Source":"/tmp/x","Destination":"/run/acgs-pg",\'',
                '            \'"RW":false,"Mode":"ro","Propagation":"rprivate"}],\'',
                '            \'"HostConfig":{"Tmpfs":{\'',
                '            \'"/tmp":"rw,noexec,nosuid,nodev,mode=1777,size=512m"}}}\'',
                "        )",
                "        raise SystemExit(0)",
                "    if mode == 'duplicate-json-tmpfs-destination':",
                "        print(",
                '            \'{"Mounts":[],"HostConfig":{"Tmpfs":{\'',
                '            \'"/tmp":"rw,noexec,nosuid,nodev,mode=1777,size=512m",\'',
                '            \'"/tmp":"rw,noexec,nosuid,nodev,mode=1777,size=512m"}}}\'',
                "        )",
                "        raise SystemExit(0)",
                "    if mode == 'delayed-inspect':",
                "        count = Path(str(state) + '.inspect-count')",
                "        previous = (",
                "            int(count.read_text(encoding='ascii')) if count.exists() else 0",
                "        )",
                "        count.write_text(str(previous + 1), encoding='ascii')",
                "        if previous == 0:",
                "            raise SystemExit(1)",
                "    snapshot = normalized_mount_snapshot()",
                "    actual = list(snapshot['Mounts'])",
                "    tmpfs = snapshot['HostConfig']['Tmpfs']",
                "    if mode == 'extra-mount':",
                "        actual.append(",
                "            {",
                "                'Type': 'bind',",
                "                'Source': '/tmp/extra',",
                "                'Destination': '/extra',",
                "                'RW': True,",
                "                'Mode': '',",
                "                'Propagation': 'rprivate',",
                "            }",
                "        )",
                "    elif mode == 'duplicate-mount':",
                "        actual.append(actual[0])",
                "    elif mode == 'wrong-mount':",
                "        actual[0] = {**actual[0], 'Source': '/tmp/wrong'}",
                "    elif mode == 'wrong-type':",
                "        actual[0] = {**actual[0], 'Type': 'volume'}",
                "    elif mode == 'wrong-rw':",
                "        actual[0] = {**actual[0], 'RW': True, 'Mode': ''}",
                "    elif mode == 'readonly-bind-mode-ro':",
                "        actual[0] = {**actual[0], 'Mode': 'ro'}",
                "    elif mode == 'wrong-propagation':",
                "        actual[0] = {**actual[0], 'Propagation': 'rshared'}",
                "    elif mode == 'tmpfs-fabricated-in-mounts':",
                "        actual.append(",
                "            {",
                "                'Type': 'tmpfs',",
                "                'Source': '',",
                "                'Destination': '/tmp',",
                "                'RW': True,",
                "                'Mode': '',",
                "                'Propagation': '',",
                "            }",
                "        )",
                "    elif mode == 'image-volume-data-entry':",
                "        actual.append(",
                "            {",
                "                'Type': 'volume',",
                "                'Source': '/var/lib/docker/volumes/postgres-data/_data',",
                "                'Destination': '/var/lib/postgresql/data',",
                "                'RW': True,",
                "                'Mode': '',",
                "                'Propagation': '',",
                "            }",
                "        )",
                "    elif mode == 'missing-tmpfs':",
                "        tmpfs.pop('/tmp', None)",
                "    elif mode == 'missing-data-tmpfs':",
                "        tmpfs.pop('/var/lib/postgresql/data', None)",
                "    elif mode == 'extra-tmpfs':",
                "        tmpfs['/run'] = 'rw,noexec,nosuid,nodev,mode=755,size=64m'",
                "    elif mode == 'weak-data-tmpfs-option':",
                "        tmpfs['/var/lib/postgresql/data'] = (",
                "            'rw,nosuid,nodev,size=2g,uid=999,gid=999,mode=700'",
                "        )",
                "    elif mode == 'wrong-data-tmpfs-option':",
                "        tmpfs['/var/lib/postgresql/data'] = (",
                "            'rw,noexec,nosuid,nodev,size=2g,uid=999,gid=999,mode=755'",
                "        )",
                "    elif mode == 'wrong-tmpfs-option':",
                "        tmpfs['/tmp'] = 'rw,exec,nosuid,nodev,mode=1777,size=512m'",
                "    elif mode == 'duplicate-tmpfs-option':",
                "        tmpfs['/tmp'] = 'rw,rw,noexec,nosuid,nodev,mode=1777,size=512m'",
                "    elif mode == 'tmpfs-flag-assigned':",
                "        tmpfs['/tmp'] = 'rw=true,noexec,nosuid,nodev,mode=1777,size=512m'",
                "    elif mode == 'tmpfs-assignment-missing':",
                "        tmpfs['/tmp'] = 'rw,noexec,nosuid,nodev,mode,size=512m'",
                "    elif mode == 'tmpfs-assignment-empty':",
                "        tmpfs['/tmp'] = 'rw,noexec,nosuid,nodev,mode=,size=512m'",
                "    elif mode == 'tmpfs-unsupported-key':",
                "        tmpfs['/tmp'] = 'rw,noexec,nosuid,nodev,mode=1777,size=512m,foo=bar'",
                "    elif mode == 'null-hostconfig':",
                "        snapshot['HostConfig'] = None",
                "    snapshot['Mounts'] = actual",
                "    print(json.dumps(snapshot, separators=(',', ':')))",
                "    raise SystemExit(0)",
                "if args[:3] == ['inspect', '--format', '{{json .Mounts}}']:",
                "    legacy_mounts = normalized_mount_snapshot()['Mounts']",
                "    print(json.dumps(legacy_mounts, separators=(',', ':')))",
                "    raise SystemExit(0)",
                "if args[:1] == ['inspect']:",
                "    if not state.exists():",
                "        raise SystemExit(1)",
                "    if mode == 'identity-inspect-absent':",
                "        raise SystemExit(1)",
                "    if mode == 'identity-inspect-non1':",
                "        raise SystemExit(2)",
                "    if mode == 'identity-inspect-malformed':",
                "        print('malformed-inspect-record')",
                "        raise SystemExit(0)",
                "    if mode == 'identity-inspect-nonascii':",
                "        sys.stdout.buffer.write(b'\\xff\\xfe')",
                "        raise SystemExit(0)",
                "    if mode == 'identity-inspect-oversize':",
                "        sys.stdout.write('[' + (' ' * 8193) + ']')",
                "        raise SystemExit(0)",
                "    data = json.loads(state.read_text(encoding='utf-8'))",
                "    server_label = (",
                "        'main'",
                "        if mode == 'wrong-server-label'",
                "        else None",
                "    )",
                "    id_value = (",
                "        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'",
                "        if mode == 'wrong-created-id'",
                "        else data['id']",
                "    )",
                "    name_value = (",
                "        'wrong-client-name'",
                "        if mode == 'wrong-created-name'",
                "        else data['name']",
                "    )",
                "    proof_label = (",
                "        'wrong-proof-label'",
                "        if mode == 'wrong-required-proof-label'",
                "        else (",
                "            None",
                "            if mode == 'missing-required-proof-label'",
                "            else (",
                "                ''",
                "                if mode == 'empty-required-proof-label'",
                "                else data['proof']",
                "            )",
                "        )",
                "    )",
                "    if mode == 'proof-terminal-lf':",
                "        proof_label = data['proof'] + '\\n'",
                "    elif mode == 'proof-multiple-lf':",
                "        proof_label = data['proof'] + '\\nspoof'",
                "    elif mode == 'proof-terminal-space':",
                "        proof_label = data['proof'] + ' '",
                "    elif mode == 'proof-terminal-tab':",
                "        proof_label = data['proof'] + '\\t'",
                "    client_label = (",
                "        'wrong-client-label'",
                "        if mode == 'wrong-required-client-label'",
                "        else (",
                "            None",
                "            if mode == 'missing-required-client-label'",
                "            else (",
                "                ''",
                "                if mode == 'empty-required-client-label'",
                "                else 'trusted-broker'",
                "            )",
                "        )",
                "    )",
                "    if mode == 'client-terminal-lf':",
                "        client_label = 'trusted-broker\\n'",
                "    elif mode == 'client-multiple-lf':",
                "        client_label = 'trusted-broker\\nspoof'",
                "    elif mode == 'client-terminal-space':",
                "        client_label = 'trusted-broker '",
                "    elif mode == 'client-terminal-tab':",
                "        client_label = 'trusted-broker\\t'",
                "    fields = [",
                "        id_value,",
                "        f'/{name_value}',",
                "        proof_label,",
                "        server_label,",
                "        client_label,",
                "    ]",
                "    if mode == 'identity-inspect-extra-json':",
                "        fields.append('extra')",
                "    print(",
                "        json.dumps(",
                "            fields,",
                "            separators=(',', ':'),",
                "        )",
                "    )",
                "    raise SystemExit(0)",
                "if args[:2] == ['rm', '-f']:",
                "    if mode == 'rm-fail':",
                "        raise SystemExit(70)",
                "    Path(str(state) + '.removed').write_text('1\\n', encoding='ascii')",
                "    if mode != 'post-rm-nonabsence':",
                "        state.unlink(missing_ok=True)",
                "    raise SystemExit(0)",
                "if args[:1] == ['create']:",
                "    append_log(args)",
                "    if mode == 'create-fail':",
                "        print('create failed')",
                "        raise SystemExit(65)",
                "    name = args[args.index('--name') + 1]",
                "    proof = next(",
                "        args[index + 1].split('=', 1)[1]",
                "        for index, value in enumerate(args)",
                "        if value == '--label'",
                "        and args[index + 1].startswith('acgs.postgres.proof=')",
                "    )",
                "    cidfile = Path(args[args.index('--cidfile') + 1])",
                "    cidfile.write_text(cid + '\\n', encoding='ascii')",
                "    cidfile.chmod(0o600)",
                "    Path(str(state) + '.env.json').write_text(",
                "        json.dumps(",
                "            {",
                "                'pgpassword_is_request': os.environ.get('PGPASSWORD')",
                "                == 'request-secret',",
                "                'pgpassword_is_ambient': os.environ.get('PGPASSWORD')",
                "                == 'ambient-secret',",
                "            },",
                "            separators=(',', ':'),",
                "        ),",
                "        encoding='utf-8',",
                "    )",
                "    state.write_text(",
                "        json.dumps({'id': cid, 'name': name, 'proof': proof, 'args': args}),",
                "        encoding='utf-8',",
                "    )",
                "    print(cid)",
                "    raise SystemExit(0)",
                "if args[:2] == ['start', '-a']:",
                "    append_log(args)",
                "    data = json.loads(state.read_text(encoding='utf-8'))",
                "    raw_args = data['args']",
                "    if mode == 'marker-missing-on-start':",
                "        marker = (",
                "            create_args_mount_source('/run/acgs-pg')",
                "            / '.acgs-postgres-socket-bridge.v2'",
                "        )",
                "        marker.unlink(missing_ok=True)",
                "    if mode == 'marker-hardlink-on-start':",
                "        marker = (",
                "            create_args_mount_source('/run/acgs-pg')",
                "            / '.acgs-postgres-socket-bridge.v2'",
                "        )",
                "        os.link(",
                "            marker,",
                "            marker.with_name('.acgs-postgres-socket-bridge.v2.link'),",
                "        )",
                "    if mode == 'bridge-mode-on-start':",
                "        create_args_mount_source('/run/acgs-pg').chmod(0o700)",
                "    if mode in {",
                "        'marker-missing-on-start',",
                "        'marker-hardlink-on-start',",
                "        'bridge-mode-on-start',",
                "    }:",
                "        wrapper = raw_args[raw_args.index('-ec') + 1]",
                "        host_bridge = create_args_mount_source('/run/acgs-pg')",
                "        wrapper = wrapper.replace('/run/acgs-pg', shlex.quote(str(host_bridge)))",
                "        sentinel = Path(str(state) + '.tool-sentinel')",
                "        completed = subprocess.run(",
                "            [",
                "                'sh',",
                "                '-ec',",
                "                wrapper,",
                "                'wrapper',",
                "                'sh',",
                "                '-c',",
                "                'touch ' + shlex.quote(str(sentinel)),",
                "            ],",
                "            check=False,",
                "        )",
                "        raise SystemExit(completed.returncode)",
                "    if 'pg_dump' in raw_args:",
                "        file_arg = next(arg for arg in raw_args if arg.startswith('--file='))",
                "        output = Path(file_arg.split('=', 1)[1])",
                "        source = create_args_mount_source('/run/acgs-exchange/tmp')",
                "        host_output = source / output.relative_to('/run/acgs-exchange/tmp')",
                "        if host_output.parent.is_symlink() or host_output.is_symlink():",
                "            print(",
                "                'container output path resolves outside mounted roots',",
                "                file=sys.stderr,",
                "            )",
                "            raise SystemExit(65)",
                "        host_output.parent.mkdir(parents=True, exist_ok=True)",
                "        payload = (",
                "            b'not-a-custom-dump'",
                "            if mode == 'bad-dump-magic'",
                "            else b'PGDMP-test'",
                "        )",
                "        host_output.write_bytes(payload)",
                "    raise SystemExit(0)",
                "raise SystemExit(127)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    docker_path.chmod(0o755)


def _run_fake_docker_broker_request(
    tmp_path: Path,
    mode: str,
    *,
    tool: str = "pg_dump",
    argv: list[str] | None = None,
    env_overrides: dict[str, str] | None = None,
    broker_source_mutator: Callable[[str], str] | None = None,
    ambient_password: str = "secret",
    prepare_state: Callable[[Path], None] | None = None,
    before_request: Callable[[Path], None] | None = None,
) -> tuple[dict[str, object], list[object], bool, dict[str, bool] | None, bool]:
    state_dir = tmp_path / f"state-{mode}"
    broker_dir = state_dir / "broker"
    client_dir = state_dir / "client"
    allowed_tmp = state_dir / "tmp"
    proof_scratch = state_dir / "proof-scratch"
    recovery_root = state_dir / "recovery"
    fake_bin = tmp_path / f"fake-bin-{mode}"
    proof_label = f"acp-postgres-gate-{os.getuid()}-0123456789abcdef0123456789abcdef"
    socket_bridge = recovery_root / f"{proof_label}-socket-bridge"
    for directory in (
        broker_dir,
        client_dir,
        allowed_tmp,
        proof_scratch,
        recovery_root,
        fake_bin,
    ):
        directory.mkdir(parents=True)
        directory.chmod(0o700)
    if prepare_state is not None:
        prepare_state(state_dir)
    bridge_identity, bridge_marker_sha256, bridge_mnt_id = _write_postgres_socket_bridge(
        socket_bridge,
        proof_label,
        "0123456789abcdef0123456789abcdef",
    )
    root_mnt_id = _mount_id(recovery_root)
    broker_source, _client_source = _postgres_gate_client_sources()
    if broker_source_mutator is not None:
        broker_source = broker_source_mutator(broker_source)
    broker_path = broker_dir / "postgres_client_broker.py"
    broker_path.write_text(broker_source, encoding="utf-8")
    docker_log = tmp_path / f"docker-{mode}.jsonl"
    docker_state = tmp_path / f"docker-{mode}.state.json"
    docker_path = fake_bin / "docker"
    _write_fake_postgres_client_docker(
        docker_path,
        docker_log,
        docker_state,
        [
            {
                "Type": "bind",
                "Source": str(socket_bridge),
                "Destination": "/run/acgs-pg",
                "RW": False,
            },
            {"Type": "bind", "Source": str(allowed_tmp), "Destination": "/run/tmp", "RW": True},
            {
                "Type": "bind",
                "Source": str(proof_scratch),
                "Destination": "/proof-scratch",
                "RW": True,
            },
            {
                "Type": "tmpfs",
                "Source": "",
                "Destination": "/var/lib/postgresql/data",
                "RW": True,
                "Options": "rw,noexec,nosuid,nodev,size=2g,uid=999,gid=999,mode=700",
            },
            {"Type": "tmpfs", "Source": "", "Destination": "/tmp", "RW": True},
        ],
        mode=mode,
    )
    socket_path = broker_dir / "postgresql-client.sock"
    broker_env = os.environ.copy()
    broker_env["PGPASSWORD"] = ambient_password
    broker_env["PATH"] = f"{fake_bin}:{broker_env['PATH']}"
    broker_env["ACP_POSTGRES_CLIENT_BROKER_DOCKER"] = str(docker_path)
    broker_env["ACP_POSTGRES_CLIENT_PROOF_LABEL"] = proof_label
    broker_env["ACP_POSTGRES_CLIENT_PROOF_NONCE"] = "0123456789abcdef0123456789abcdef"
    broker_env["ACP_POSTGRES_SERVER_NAME"] = f"{proof_label}-server"
    broker_env["ACGS_POSTGRES_RECOVERY_ROOT"] = str(recovery_root)
    broker_env["ACP_POSTGRES_SOCKET_BRIDGE"] = str(socket_bridge)
    broker_env["ACP_POSTGRES_SOCKET_BRIDGE_IDENTITY"] = bridge_identity
    broker_env["ACP_POSTGRES_SOCKET_BRIDGE_MARKER_SHA256"] = bridge_marker_sha256
    broker_env["ACP_POSTGRES_SOCKET_BRIDGE_MNT_ID"] = bridge_mnt_id
    broker_env["ACP_POSTGRES_RECOVERY_ROOT_MNT_ID"] = root_mnt_id
    broker = subprocess.Popen(
        [sys.executable, str(broker_path), str(socket_path), str(state_dir)],
        env=broker_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        umask=0o077,
    )
    try:
        deadline = time.monotonic() + 15
        original_cwd = Path.cwd()
        broker_client: socket.socket | None = None
        try:
            os.chdir(socket_path.parent)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    pytest.fail("broker socket did not become ready")
                if broker.poll() is not None:
                    stdout, stderr = broker.communicate(timeout=1)
                    pytest.fail(f"broker exited early: stdout={stdout!r} stderr={stderr!r}")
                candidate: socket.socket | None = None
                try:
                    candidate = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    candidate.settimeout(min(1.0, remaining))
                    candidate.connect(socket_path.name)
                except (FileNotFoundError, ConnectionRefusedError, TimeoutError):
                    if candidate is not None:
                        candidate.close()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        pytest.fail("broker socket did not become ready")
                    time.sleep(min(0.05, remaining))
                    continue
                except Exception:
                    if candidate is not None:
                        candidate.close()
                    raise
                broker_client = candidate
                broker_client.settimeout(15)
                break
            if broker.poll() is not None:
                stdout, stderr = broker.communicate(timeout=1)
                pytest.fail(f"broker exited early: stdout={stdout!r} stderr={stderr!r}")
            if mode == "precreate-bridge-mode":
                socket_bridge.chmod(0o700)
            if before_request is not None:
                before_request(state_dir)
            with broker_client:
                broker_client.sendall(
                    json.dumps(
                        {
                            "tool": tool,
                            "argv": argv or ["--format=custom", "--file=/run/tmp/archive.dump"],
                            "env": {
                                "PGHOST": "/run/acgs-pg",
                                "PGPORT": "5432",
                                "PGUSER": "operator",
                                "PGPASSWORD": "request-secret",
                                "PGDATABASE": "acgs_control_plane_test",
                                **(env_overrides or {}),
                            },
                        },
                        separators=(",", ":"),
                    ).encode("utf-8")
                )
                broker_client.shutdown(socket.SHUT_WR)
                try:
                    raw_response = broker_client.recv(65536)
                except TimeoutError:
                    pytest.fail("broker request timed out")
                response = json.loads(raw_response.decode("utf-8"))
        finally:
            os.chdir(original_cwd)
    finally:
        broker.terminate()
        try:
            broker.wait(timeout=5)
        except subprocess.TimeoutExpired:
            broker.kill()
            broker.wait(timeout=5)
    log_lines = (
        [json.loads(line) for line in docker_log.read_text(encoding="utf-8").splitlines()]
        if docker_log.exists()
        else []
    )
    env_attestation_path = Path(str(docker_state) + ".env.json")
    env_attestation = (
        json.loads(env_attestation_path.read_text(encoding="utf-8"))
        if env_attestation_path.exists()
        else None
    )
    return (
        response,
        log_lines,
        (allowed_tmp / "archive.dump").exists(),
        env_attestation,
        Path(str(docker_state) + ".tool-sentinel").exists(),
    )


def test_postgres_gate_client_broker_normalizes_optional_server_label_and_removes_records(
    tmp_path: Path,
) -> None:
    mode = "ok"
    (
        response,
        _docker_lines,
        archive_exists,
        _env_attestation,
        tool_sentinel_exists,
    ) = _run_fake_docker_broker_request(tmp_path, mode)

    state_dir = tmp_path / f"state-{mode}"
    client_dir = state_dir / "client"
    docker_state = tmp_path / f"docker-{mode}.state.json"

    assert response["returncode"] == 0, response
    assert archive_exists
    assert not tool_sentinel_exists
    assert not docker_state.exists()
    assert Path(str(docker_state) + ".removed").read_text(encoding="ascii") == "1\n"
    assert not list(client_dir.glob("*.cid"))
    assert not list(client_dir.glob("*.name"))


@pytest.mark.parametrize(
    "mode",
    [
        "wrong-required-proof-label",
        "missing-required-proof-label",
        "empty-required-proof-label",
        "proof-terminal-lf",
        "proof-multiple-lf",
        "proof-terminal-space",
        "proof-terminal-tab",
        "wrong-required-client-label",
        "missing-required-client-label",
        "empty-required-client-label",
        "client-terminal-lf",
        "client-multiple-lf",
        "client-terminal-space",
        "client-terminal-tab",
        "wrong-server-label",
        "wrong-created-id",
        "wrong-created-name",
        "identity-inspect-absent",
        "identity-inspect-non1",
        "identity-inspect-malformed",
        "identity-inspect-nonascii",
        "identity-inspect-extra-json",
        "identity-inspect-oversize",
    ],
)
def test_postgres_gate_client_broker_untrusted_created_identity_is_retained_before_start(
    tmp_path: Path,
    mode: str,
) -> None:
    (
        response,
        docker_lines,
        archive_exists,
        _env_attestation,
        tool_sentinel_exists,
    ) = _run_fake_docker_broker_request(tmp_path, mode)

    state_dir = tmp_path / f"state-{mode}"
    client_dir = state_dir / "client"
    recovery_dir = state_dir / "recovery"
    docker_state = tmp_path / f"docker-{mode}.state.json"

    assert response["returncode"] == 70, response
    assert not archive_exists
    assert not [line for line in docker_lines if line[:2] == ["start", "-a"]]
    assert not tool_sentinel_exists
    assert docker_state.exists()
    assert not Path(str(docker_state) + ".removed").exists()
    assert list(client_dir.glob("*.cid"))
    assert list(client_dir.glob("*.name"))
    assert list(recovery_dir.glob("*.intent"))


@pytest.mark.parametrize("mode", ["rm-fail", "post-rm-nonabsence"])
def test_postgres_gate_client_broker_uncertain_removal_retains_records(
    tmp_path: Path,
    mode: str,
) -> None:
    (
        response,
        docker_lines,
        archive_exists,
        _env_attestation,
        tool_sentinel_exists,
    ) = _run_fake_docker_broker_request(tmp_path, mode)

    state_dir = tmp_path / f"state-{mode}"
    client_dir = state_dir / "client"
    recovery_dir = state_dir / "recovery"
    docker_state = tmp_path / f"docker-{mode}.state.json"

    assert response["returncode"] == 70, response
    assert "container cleanup is uncertain" in response["stderr"]
    starts = [line for line in docker_lines if line[:2] == ["start", "-a"]]
    assert bool(starts)
    assert not archive_exists
    assert not tool_sentinel_exists
    assert docker_state.exists()
    assert list(client_dir.glob("*.cid"))
    assert list(client_dir.glob("*.name"))
    assert list(recovery_dir.glob("*.intent"))
    assert list(recovery_dir.glob("*-exchange"))
    if mode == "rm-fail":
        assert not Path(str(docker_state) + ".removed").exists()
    else:
        assert Path(str(docker_state) + ".removed").read_text(encoding="ascii") == "1\n"


def test_postgres_gate_client_broker_uses_fixed_roots_and_rejects_endpoint_escape(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    canonical_tmp = Path(tempfile.gettempdir()).resolve(strict=True)
    long_parent = canonical_tmp / ("acp-pg-gate-" + ("x" * 80))
    long_parent.mkdir(exist_ok=True)
    state_dir = Path(tempfile.mkdtemp(prefix=("nested-" + ("y" * 40) + "-"), dir=long_parent))
    request.addfinalizer(lambda: shutil.rmtree(state_dir, ignore_errors=True))
    request.addfinalizer(lambda: shutil.rmtree(long_parent, ignore_errors=True))
    state_dir.chmod(0o700)
    state_stat = state_dir.stat()
    assert state_stat.st_uid == os.getuid()
    assert stat.S_IMODE(state_stat.st_mode) == 0o700

    broker_dir = state_dir / "broker"
    client_dir = state_dir / "client"
    home_dir = state_dir / "home"
    allowed_tmp = state_dir / "tmp"
    proof_scratch = state_dir / "proof-scratch"
    recovery_root = state_dir / "recovery"
    proof_label = f"acp-postgres-gate-{os.getuid()}-0123456789abcdef0123456789abcdef"
    socket_bridge = recovery_root / f"{proof_label}-socket-bridge"
    fake_bin = tmp_path / "fake-bin"
    outside_dir = tmp_path / "outside"

    for directory in (
        broker_dir,
        client_dir,
        home_dir,
        allowed_tmp,
        proof_scratch,
        recovery_root,
        fake_bin,
        outside_dir,
    ):
        directory.mkdir(parents=True)
        directory.chmod(0o700)
    bridge_identity, bridge_marker_sha256, bridge_mnt_id = _write_postgres_socket_bridge(
        socket_bridge,
        proof_label,
        "0123456789abcdef0123456789abcdef",
    )
    root_mnt_id = _mount_id(recovery_root)
    assert bridge_mnt_id == root_mnt_id

    broker_source, client_source = _postgres_gate_client_sources()
    broker_path = broker_dir / "postgres_client_broker.py"
    client_path = client_dir / "postgresql-client"
    broker_path.write_text(broker_source, encoding="utf-8")
    client_path.write_text(client_source, encoding="utf-8")
    client_path.chmod(0o755)
    (client_dir / "pg_dump").symlink_to("postgresql-client")

    docker_log = tmp_path / "docker-args.jsonl"
    docker_state = tmp_path / "docker-state.json"
    docker_path = fake_bin / "docker"
    fake_mounts = [
        {
            "Type": "bind",
            "Source": str(socket_bridge),
            "Destination": "/run/acgs-pg",
            "RW": False,
        },
        {"Type": "bind", "Source": str(allowed_tmp), "Destination": "/run/tmp", "RW": True},
        {
            "Type": "bind",
            "Source": str(proof_scratch),
            "Destination": "/proof-scratch",
            "RW": True,
        },
        {
            "Type": "tmpfs",
            "Source": "",
            "Destination": "/var/lib/postgresql/data",
            "RW": True,
            "Options": "rw,noexec,nosuid,nodev,size=2g,uid=999,gid=999,mode=700",
        },
        {"Type": "tmpfs", "Source": "", "Destination": "/tmp", "RW": True},
    ]
    _write_fake_postgres_client_docker(docker_path, docker_log, docker_state, fake_mounts)
    socket_path = broker_dir / "postgresql-client.sock"
    assert len(str(socket_path)) > 108
    broker_env = os.environ.copy()
    broker_env["PATH"] = f"{fake_bin}:{broker_env['PATH']}"
    broker_env["ACP_POSTGRES_CLIENT_BROKER_DOCKER"] = str(docker_path)
    broker_env["ACP_POSTGRES_CLIENT_PROOF_LABEL"] = proof_label
    broker_env["ACP_POSTGRES_CLIENT_PROOF_NONCE"] = "0123456789abcdef0123456789abcdef"
    broker_env["ACP_POSTGRES_SERVER_NAME"] = (
        f"{broker_env['ACP_POSTGRES_CLIENT_PROOF_LABEL']}-server"
    )
    broker_env["ACGS_POSTGRES_RECOVERY_ROOT"] = str(recovery_root)
    broker_env["ACP_POSTGRES_SOCKET_BRIDGE"] = str(socket_bridge)
    broker_env["ACP_POSTGRES_SOCKET_BRIDGE_IDENTITY"] = bridge_identity
    broker_env["ACP_POSTGRES_SOCKET_BRIDGE_MARKER_SHA256"] = bridge_marker_sha256
    broker_env["ACP_POSTGRES_SOCKET_BRIDGE_MNT_ID"] = bridge_mnt_id
    broker_env["ACP_POSTGRES_RECOVERY_ROOT_MNT_ID"] = root_mnt_id
    broker = subprocess.Popen(
        [sys.executable, str(broker_path), str(socket_path), str(state_dir)],
        env=broker_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5
        while not socket_path.exists() and time.monotonic() < deadline:
            if broker.poll() is not None:
                stdout, stderr = broker.communicate(timeout=1)
                pytest.fail(f"broker exited early: stdout={stdout!r} stderr={stderr!r}")
            time.sleep(0.05)
        assert socket_path.exists()

        client_env = {
            "ACP_POSTGRES_CLIENT_BROKER_SOCKET": str(socket_path),
            "PGHOST": "/run/acgs-pg",
            "PGPORT": "5432",
            "PGUSER": "operator",
            "PGPASSWORD": "secret",
            "PGDATABASE": "acgs_control_plane_test",
            "PGCONNECT_TIMEOUT": "5",
        }

        denied_archive = outside_dir / "escape.dump"
        denied = subprocess.run(
            [str(client_dir / "pg_dump"), "--format=custom", f"--file={denied_archive}"],
            env=client_env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert denied.returncode == 64
        assert "outside broker-owned roots" in denied.stderr
        assert not denied_archive.exists()
        assert not docker_log.exists()

        endpoint_escape_env = {**client_env, "PGHOST": "127.0.0.1"}
        endpoint_escape = subprocess.run(
            [str(client_dir / "pg_dump"), "--file=/run/tmp/endpoint.dump"],
            env=endpoint_escape_env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert endpoint_escape.returncode == 64
        assert "endpoint is pinned" in endpoint_escape.stderr
        assert not docker_log.exists()

        original_cwd = Path.cwd()
        raw_broker_env = {
            key: value
            for key, value in client_env.items()
            if key != "ACP_POSTGRES_CLIENT_BROKER_SOCKET"
        }
        try:
            os.chdir(socket_path.parent)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as broker_client:
                broker_client.connect(socket_path.name)
                broker_client.sendall(
                    json.dumps(
                        {
                            "tool": "pg_dump",
                            "argv": ["--file=/run/tmp/caller-user.dump"],
                            "env": {**raw_broker_env, "USER": "0:0"},
                        },
                        separators=(",", ":"),
                    ).encode("utf-8")
                )
                broker_client.shutdown(socket.SHUT_WR)
                response = json.loads(broker_client.recv(65536).decode("utf-8"))
        finally:
            os.chdir(original_cwd)
        assert response["returncode"] == 64
        assert "unsupported PostgreSQL client env: USER" in response["stderr"]
        assert not docker_log.exists()

        allowed_archive = allowed_tmp / "archive.dump"
        allowed = subprocess.run(
            [str(client_dir / "pg_dump"), "--format=custom", "--file=/run/tmp/archive.dump"],
            env=client_env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert allowed.returncode == 0, allowed.stderr
        assert allowed_archive.read_bytes() == b"PGDMP-test"
        docker_lines = docker_log.read_text(encoding="utf-8").splitlines()
        docker_invocation = json.loads(docker_lines[0])
        assert docker_invocation[0] == "create"
        assert json.loads(docker_lines[-1]) == [
            "start",
            "-a",
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        ]
        assert "--network" in docker_invocation
        assert docker_invocation[docker_invocation.index("--network") + 1] == "none"
        assert "--user" in docker_invocation
        assert docker_invocation[docker_invocation.index("--user") + 1] == (
            f"{os.getuid()}:{os.getgid()}"
        )
        assert "label=disable" in docker_invocation
        assert (
            "/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=2g,uid=999,gid=999,mode=700"
            in (docker_invocation)
        )
        assert f"type=bind,src={socket_bridge},dst=/run/acgs-pg,readonly" in docker_invocation
        assert not any(f"src={allowed_tmp}," in argument for argument in docker_invocation)
        assert not any(f"src={proof_scratch}," in argument for argument in docker_invocation)
        exchange_tmp_mount = next(
            argument for argument in docker_invocation if "dst=/run/acgs-exchange/tmp" in argument
        )
        exchange_proof_mount = next(
            argument
            for argument in docker_invocation
            if "dst=/run/acgs-exchange/proof-scratch" in argument
        )
        assert "-client-" in exchange_tmp_mount
        assert "-client-" in exchange_proof_mount
        assert "-exchange/tmp" in exchange_tmp_mount
        assert "-exchange/proof-scratch" in exchange_proof_mount
        assert "client-exchange" not in exchange_tmp_mount
        assert "client-exchange" not in exchange_proof_mount
        assert not any(f"{state_dir}:/run/acgs-pg" in argument for argument in docker_invocation)
        assert not any(str(outside_dir) in argument for argument in docker_invocation)
        assert docker_invocation[-3:] == [
            "pg_dump",
            "--format=custom",
            "--file=/run/acgs-exchange/tmp/archive.dump",
        ]

        docker_log.unlink()
        marker = socket_bridge / ".acgs-postgres-socket-bridge.v2"
        marker.chmod(0o644)
        marker.write_text(
            "tampered\n",
            encoding="ascii",
        )
        marker.chmod(0o444)
        tampered = subprocess.run(
            [str(client_dir / "pg_dump"), "--format=custom", "--file=/run/tmp/tampered.dump"],
            env=client_env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert tampered.returncode == 70
        assert "socket bridge marker digest changed" in tampered.stderr
        assert not docker_log.exists()
    finally:
        broker.terminate()
        try:
            broker.wait(timeout=5)
        except subprocess.TimeoutExpired:
            broker.kill()
            broker.wait(timeout=5)


@pytest.mark.parametrize(
    ("mode", "expected_rc", "expected_started"),
    [
        ("delayed-inspect", 0, True),
        ("fast-inspect-fail", 70, False),
        ("extra-mount", 70, False),
        ("duplicate-mount", 70, False),
        ("wrong-mount", 70, False),
        ("wrong-type", 70, False),
        ("wrong-rw", 70, False),
        ("readonly-bind-mode-ro", 70, False),
        ("wrong-propagation", 70, False),
        ("tmpfs-fabricated-in-mounts", 70, False),
        ("image-volume-data-entry", 70, False),
        ("missing-tmpfs", 70, False),
        ("missing-data-tmpfs", 70, False),
        ("extra-tmpfs", 70, False),
        ("weak-data-tmpfs-option", 70, False),
        ("wrong-data-tmpfs-option", 70, False),
        ("wrong-tmpfs-option", 70, False),
        ("duplicate-tmpfs-option", 70, False),
        ("tmpfs-flag-assigned", 70, False),
        ("tmpfs-assignment-missing", 70, False),
        ("tmpfs-assignment-empty", 70, False),
        ("tmpfs-unsupported-key", 70, False),
        ("malformed-inspect", 70, False),
        ("null-hostconfig", 70, False),
        ("oversized-inspect", 70, False),
        ("duplicate-json-top", 70, False),
        ("duplicate-json-nested", 70, False),
        ("duplicate-json-bind-field", 70, False),
        ("duplicate-json-tmpfs-destination", 70, False),
        ("marker-missing-on-start", 70, True),
        ("marker-hardlink-on-start", 70, True),
        ("bridge-mode-on-start", 70, True),
    ],
)
def test_postgres_gate_client_broker_fake_docker_mount_and_marker_refusals(
    tmp_path: Path,
    mode: str,
    expected_rc: int,
    expected_started: bool,
) -> None:
    (
        response,
        docker_lines,
        archive_exists,
        _env_attestation,
        tool_sentinel_exists,
    ) = _run_fake_docker_broker_request(
        tmp_path,
        mode,
    )

    assert response["returncode"] == expected_rc, response
    assert archive_exists is (expected_rc == 0)
    assert docker_lines[0][0] == "create"
    starts = [line for line in docker_lines if line[:2] == ["start", "-a"]]
    assert bool(starts) is expected_started
    assert not tool_sentinel_exists


@pytest.mark.parametrize(
    ("argv", "env_overrides"),
    [
        (["--file=/run/tmp/archive.dump", "--host=/run/tmp", "--port=6543"], {}),
        (["--file=/run/tmp/archive.dump", "--host", "/run/tmp"], {}),
        (["--file=/run/tmp/archive.dump", "--port", "6543"], {}),
        (["--file=/run/tmp/archive.dump", "--hos=/run/tmp"], {}),
        (["--file=/run/tmp/archive.dump", "--por=6543"], {}),
        (["--file=/run/tmp/archive.dump", "-h", "/run/tmp"], {}),
        (["--file=/run/tmp/archive.dump", "-p6543"], {}),
        (["--file=/run/tmp/archive.dump", "-vh/run/tmp"], {}),
        (["--file=/run/tmp/archive.dump", "-vp6543"], {}),
        (["--file=/run/tmp/archive.dump", "--dbn=host=/run/tmp"], {}),
        (["--file=/run/tmp/archive.dump", "--db=service=prod"], {}),
        (["--file=/run/tmp/archive.dump", "--dbn", "host=/run/tmp"], {}),
        (["--file=/run/tmp/archive.dump", "--db", "service=prod"], {}),
        (["--file=/run/tmp/archive.dump", "-vdservice=foo"], {}),
        (["--file=/run/tmp/archive.dump", "-vd", "service=foo"], {}),
        (["postgresql://operator@example.invalid:6543/db"], {}),
        (["dbname=acgs host=/run/tmp port=6543"], {}),
        (["--dbname", "host = /run/tmp port = 6543 dbname=x"], {}),
        (["--dbname=host = /run/tmp port = 6543 dbname=x"], {}),
        (["service=prod"], {}),
        (["service = prod"], {}),
        (["servicefile=/run/tmp/pg_service.conf"], {}),
        (["--file=/run/tmp/archive.dump"], {"PGHOSTADDR": "127.0.0.1"}),
        (["--file=/run/tmp/archive.dump"], {"PGSERVICE": "prod"}),
        (["--file=/run/tmp/archive.dump"], {"PGSERVICEFILE": "/run/tmp/pg_service.conf"}),
    ],
)
def test_postgres_gate_client_broker_rejects_endpoint_override_before_docker(
    tmp_path: Path,
    argv: list[str],
    env_overrides: dict[str, str],
) -> None:
    (
        response,
        docker_lines,
        archive_exists,
        env_attestation,
        tool_sentinel_exists,
    ) = _run_fake_docker_broker_request(
        tmp_path,
        "ok",
        argv=argv,
        env_overrides=env_overrides,
    )

    assert response["returncode"] == 64, response
    assert "endpoint is pinned" in response["stderr"]
    assert docker_lines == []
    assert env_attestation is None
    assert not archive_exists
    assert not tool_sentinel_exists


@pytest.mark.parametrize(
    "argv",
    [
        ["--command=\\connect attacker operator /run/tmp 6543"],
        ["--command", "\\connect attacker operator /run/tmp 6543"],
        ["--com=\\c attacker"],
        ["--com", "\\c attacker"],
        ["-c\\connect attacker operator /run/tmp 6543"],
        ["-c", "\\connect attacker operator /run/tmp 6543"],
        ["-vc\\c attacker"],
        ["--file=/run/tmp/reconnect.sql"],
        ["--file", "/run/tmp/reconnect.sql"],
        ["--fil=/run/tmp/reconnect.sql"],
        ["--fil", "/run/tmp/reconnect.sql"],
        ["-f/run/tmp/reconnect.sql"],
        ["-f", "/run/tmp/reconnect.sql"],
        ["-vf/run/tmp/reconnect.sql"],
        ["--set=evil=\\connect attacker operator /run/tmp 6543", "--command", ":evil"],
        ["--variable=evil=\\connect attacker operator /run/tmp 6543", "--command", ":evil"],
        ["--set", "evil=\\connect attacker operator /run/tmp 6543", "--command", ":evil"],
        ["--command", ":evil"],
        ["--command=SELECT 1"],
    ],
)
def test_postgres_gate_client_broker_rejects_psql_reconnect_paths_before_docker(
    tmp_path: Path,
    argv: list[str],
) -> None:
    response, docker_lines, archive_exists, env_attestation, tool_sentinel_exists = (
        _run_fake_docker_broker_request(
            tmp_path,
            "ok",
            tool="psql",
            argv=argv,
        )
    )

    assert response["returncode"] == 64, response
    assert (
        "psql reconnect paths are disabled" in response["stderr"]
        or "psql script files are disabled" in response["stderr"]
        or "psql variable interpolation is disabled" in response["stderr"]
        or "psql argv is not allowed" in response["stderr"]
    )
    assert docker_lines == []
    assert env_attestation is None
    assert not archive_exists
    assert not tool_sentinel_exists


@pytest.mark.parametrize(
    "argv",
    [
        ["--set", "ON_ERROR_STOP=1", "--command", "SELECT 1"],
        ["--set=ON_ERROR_STOP=1", "--command", "SELECT 1"],
        [
            "--set",
            "ON_ERROR_STOP=1",
            "--command",
            "CREATE DATABASE acgs_control_plane_recovery_source_test",
        ],
        [
            "--set",
            "ON_ERROR_STOP=1",
            "--command",
            "CREATE ROLE acgs_fixture_owner LOGIN PASSWORD 'secret' NOSUPERUSER",
            "--command",
            "GRANT CONNECT, TEMPORARY ON DATABASE acgs_control_plane_test TO acgs_fixture_owner",
        ],
        [
            "--set",
            "ON_ERROR_STOP=1",
            "--command",
            "COPY (SELECT 1) TO PROGRAM 'true'",
        ],
        ["--tuples-only", "--no-align", "--command", "SELECT rolname FROM pg_roles"],
        ["--version"],
    ],
)
def test_postgres_gate_client_broker_allows_gate_psql_sql_without_meta_commands(
    tmp_path: Path,
    argv: list[str],
) -> None:
    response, docker_lines, archive_exists, env_attestation, tool_sentinel_exists = (
        _run_fake_docker_broker_request(
            tmp_path,
            "ok",
            tool="psql",
            argv=argv,
        )
    )

    assert response["returncode"] == 0, response
    assert docker_lines[0][0] == "create"
    assert any(line[:2] == ["start", "-a"] for line in docker_lines)
    assert env_attestation == {
        "pgpassword_is_request": True,
        "pgpassword_is_ambient": False,
    }
    assert not archive_exists
    assert not tool_sentinel_exists


def test_postgres_gate_client_broker_uses_request_env_and_omits_create_id_stdout(
    tmp_path: Path,
) -> None:
    response, docker_lines, archive_exists, env_attestation, tool_sentinel_exists = (
        _run_fake_docker_broker_request(
            tmp_path,
            "ok",
            ambient_password="ambient-secret",
        )
    )

    assert response["returncode"] == 0, response
    assert response["stdout"] == ""
    assert "abcdef123456" not in response["stdout"]
    assert "ambient-secret" not in json.dumps(response, sort_keys=True)
    assert "ambient-secret" not in json.dumps(docker_lines, sort_keys=True)
    assert archive_exists
    assert not tool_sentinel_exists
    assert env_attestation == {
        "pgpassword_is_request": True,
        "pgpassword_is_ambient": False,
    }


def test_postgres_gate_client_broker_freezes_and_validates_final_create_argv(
    tmp_path: Path,
) -> None:
    response, docker_lines, archive_exists, env_attestation, tool_sentinel_exists = (
        _run_fake_docker_broker_request(tmp_path, "ok")
    )

    assert response["returncode"] == 0, response
    assert archive_exists
    assert env_attestation == {
        "pgpassword_is_request": True,
        "pgpassword_is_ambient": False,
    }
    assert not tool_sentinel_exists
    docker_invocation = docker_lines[0]
    image_index = docker_invocation.index(
        "postgres:17.10-bookworm@"
        "sha256:4f736ae292687621d4dbe0d499ffd024a36bd2ee7d8ca6f2ccd4c800f047b394"
    )
    create_prefix = docker_invocation[:image_index]
    assert docker_invocation[:5] == ["create", "--pull=never", "--network", "none", "--name"]
    assert "--privileged" not in create_prefix
    assert "--add-host" not in create_prefix
    assert ["--network", "host"] not in [
        docker_invocation[index : index + 2]
        for index, value in enumerate(docker_invocation)
        if value == "--network"
    ]
    assert docker_invocation.count("--mount") == 3
    mount_values = [
        docker_invocation[index + 1]
        for index, value in enumerate(docker_invocation)
        if value == "--mount"
    ]
    assert any("dst=/run/acgs-pg,readonly" in value for value in mount_values)
    assert any("dst=/run/acgs-exchange/tmp" in value for value in mount_values)
    assert any("dst=/run/acgs-exchange/proof-scratch" in value for value in mount_values)
    mount_sources = {
        part.split("=", 1)[1]
        for mount_value in mount_values
        for part in mount_value.split(",")
        if part.startswith("src=")
    }
    state_dir = tmp_path / "state-ok"
    assert str(state_dir / "tmp") not in mount_sources
    assert str(state_dir / "proof-scratch") not in mount_sources
    assert str(state_dir / "recovery") not in mount_sources


@pytest.mark.parametrize(
    "mutation",
    [
        "privileged",
        "network-host",
        "add-host",
        "recovery-root-mount",
        "quota-root-mount",
        "tail-extra-arg",
    ],
)
def test_postgres_gate_client_broker_revalidates_mutated_final_create_argv_before_docker(
    tmp_path: Path,
    mutation: str,
) -> None:
    def mutate_broker_source(source: str) -> str:
        validation_call = (
            "            validated_docker_create_args = validate_final_docker_create_argv(\n"
            "                docker_create_args, tuple(docker_args), "
            "docker_create_tail, exchange_roots\n"
            "            )"
        )
        mutations = {
            "privileged": (
                "            docker_create_args = docker_create_args[:2] + "
                "('--privileged',) + docker_create_args[2:]\n"
            ),
            "network-host": (
                "            network_index = docker_create_args.index('--network')\n"
                "            docker_create_args = docker_create_args[: network_index + 1] "
                "+ ('host',) + docker_create_args[network_index + 2 :]\n"
            ),
            "add-host": (
                "            docker_create_args = docker_create_args[:2] + "
                "('--add-host', 'host.docker.internal:host-gateway') + docker_create_args[2:]\n"
            ),
            "recovery-root-mount": (
                "            docker_create_args = docker_create_args[:2] + "
                "('--mount', f'type=bind,src={RECOVERY_ROOT},"
                "dst=/run/acgs-exchange/tmp') + docker_create_args[2:]\n"
            ),
            "quota-root-mount": (
                "            docker_create_args = docker_create_args[:2] + "
                "('--mount', f'type=bind,src={HOST_TMP},"
                "dst=/run/acgs-exchange/tmp') + docker_create_args[2:]\n"
            ),
            "tail-extra-arg": (
                "            docker_create_args = docker_create_args + ('tail-drift',)\n"
            ),
        }
        mutated = source.replace(validation_call, mutations[mutation] + validation_call, 1)
        assert mutated != source
        compile(mutated, f"mutated-broker-{mutation}.py", "exec")
        return mutated

    response, docker_lines, archive_exists, env_attestation, tool_sentinel_exists = (
        _run_fake_docker_broker_request(
            tmp_path,
            f"final-argv-{mutation}",
            broker_source_mutator=mutate_broker_source,
        )
    )

    assert response["returncode"] == 70, response
    assert (
        "Docker create argv" in str(response["stderr"])
        or "Docker network changed" in str(response["stderr"])
        or "Docker mount is forbidden" in str(response["stderr"])
        or "Docker create tail changed" in str(response["stderr"])
    )
    assert docker_lines == []
    assert not archive_exists
    assert env_attestation is None
    assert not tool_sentinel_exists


def test_postgres_gate_client_broker_create_failure_is_visible_and_redacted(
    tmp_path: Path,
) -> None:
    response, docker_lines, archive_exists, env_attestation, tool_sentinel_exists = (
        _run_fake_docker_broker_request(
            tmp_path,
            "create-fail",
        )
    )

    state_dir = tmp_path / "state-create-fail"
    client_dir = state_dir / "client"
    recovery_dir = state_dir / "recovery"
    stderr = str(response["stderr"])

    assert response["returncode"] == 70, response
    assert response["stdout"] == ""
    assert '"event":"postgres_client_docker_create_failed"' in stderr
    assert '"broker_rc":70' in stderr
    assert '"docker_rc":65' in stderr
    assert '"output_bytes":' in stderr
    assert '"output_sha256":"' in stderr
    assert '"safe_reason":"docker-create-failed"' in stderr
    assert str(state_dir) not in stderr
    assert "request-secret" not in stderr
    assert docker_lines[0][0] == "create"
    assert not [line for line in docker_lines if line[:2] == ["start", "-a"]]
    assert not archive_exists
    assert env_attestation is None
    assert not tool_sentinel_exists
    assert list(client_dir.glob("*.name"))
    assert not list(client_dir.glob("*.cid"))
    assert list(recovery_dir.glob("*.intent"))


def test_postgres_gate_client_broker_precreate_failure_cleans_exchange(
    tmp_path: Path,
) -> None:
    response, docker_lines, archive_exists, env_attestation, tool_sentinel_exists = (
        _run_fake_docker_broker_request(
            tmp_path,
            "precreate-bridge-mode",
        )
    )

    state_dir = tmp_path / "state-precreate-bridge-mode"

    assert response["returncode"] == 70, response
    assert "socket bridge mode is unsafe" in response["stderr"]
    assert docker_lines == []
    assert not archive_exists
    assert env_attestation is None
    assert not tool_sentinel_exists
    assert not list((state_dir / "recovery").glob("*-exchange"))


@pytest.mark.parametrize(
    ("case_name", "argv", "expected_stderr"),
    [
        (
            "short-file",
            ["--format=custom", "-f", "/run/tmp/archive.dump"],
            "pg_dump output must use --file=PATH",
        ),
        (
            "short-format",
            ["-F", "custom", "--file=/run/tmp/archive.dump"],
            "allows only custom-format pg_dump output",
        ),
        (
            "split-format",
            ["--format", "custom", "--file=/run/tmp/archive.dump"],
            "allows only custom-format pg_dump output",
        ),
        (
            "abbrev-file",
            ["--format=custom", "--fo=/run/tmp/archive.dump"],
            "allows only explicit pg_dump file and format options",
        ),
        (
            "abbrev-format",
            ["--for=plain", "--file=/run/tmp/archive.dump"],
            "allows only explicit pg_dump file and format options",
        ),
        (
            "plain-format",
            ["--format=plain", "--file=/run/tmp/archive.dump"],
            "allows only custom-format pg_dump output",
        ),
        (
            "duplicate-file",
            [
                "--format=custom",
                "--file=/run/tmp/archive.dump",
                "--file=/run/tmp/other.dump",
            ],
            "allows only one pg_dump output",
        ),
        (
            "duplicate-format",
            ["--format=custom", "--format=custom", "--file=/run/tmp/archive.dump"],
            "pg_dump format is duplicated",
        ),
    ],
)
def test_postgres_gate_client_broker_strictly_parses_pg_dump_output_options(
    tmp_path: Path,
    case_name: str,
    argv: list[str],
    expected_stderr: str,
) -> None:
    response, docker_lines, archive_exists, env_attestation, tool_sentinel_exists = (
        _run_fake_docker_broker_request(
            tmp_path,
            f"strict-pg-dump-{case_name}",
            argv=argv,
        )
    )

    assert response["returncode"] == 64, response
    assert expected_stderr in response["stderr"]
    assert docker_lines == []
    assert not archive_exists
    assert env_attestation is None
    assert not tool_sentinel_exists


def test_postgres_gate_client_broker_stages_pg_restore_input_from_quota(
    tmp_path: Path,
) -> None:
    def prepare_state(state_dir: Path) -> None:
        archive = state_dir / "tmp" / "archive.dump"
        archive.write_bytes(b"PGDMP-test")
        archive.chmod(0o600)

    response, docker_lines, archive_exists, env_attestation, tool_sentinel_exists = (
        _run_fake_docker_broker_request(
            tmp_path,
            "ok",
            tool="pg_restore",
            argv=["--list", "/run/tmp/archive.dump"],
            prepare_state=prepare_state,
        )
    )

    assert response["returncode"] == 0, response
    assert archive_exists
    assert not tool_sentinel_exists
    assert env_attestation == {
        "pgpassword_is_request": True,
        "pgpassword_is_ambient": False,
    }
    docker_invocation = docker_lines[0]
    assert docker_invocation[-3:] == [
        "pg_restore",
        "--list",
        "/run/acgs-exchange/tmp/archive.dump",
    ]


def test_postgres_gate_client_broker_stages_exact_input_limits_once(
    tmp_path: Path,
) -> None:
    def prepare_state(state_dir: Path) -> None:
        for index in range(32):
            archive = state_dir / "tmp" / f"archive-{index}.dump"
            archive.write_bytes(b"x" * 262_144)
            archive.chmod(0o600)

    argv = ["/run/tmp/archive-0.dump", "/run/tmp/archive-0.dump"]
    argv.extend(f"/run/tmp/archive-{index}.dump" for index in range(1, 32))
    response, docker_lines, archive_exists, env_attestation, tool_sentinel_exists = (
        _run_fake_docker_broker_request(
            tmp_path,
            "staging-exact-limit",
            tool="pg_restore",
            argv=argv,
            prepare_state=prepare_state,
        )
    )

    assert response["returncode"] == 0, response
    assert not archive_exists
    assert env_attestation == {
        "pgpassword_is_request": True,
        "pgpassword_is_ambient": False,
    }
    assert not tool_sentinel_exists
    assert [line for line in docker_lines if line[:2] == ["start", "-a"]]
    docker_invocation = docker_lines[0]
    assert docker_invocation[-33:] == [
        "/run/acgs-exchange/tmp/archive-0.dump",
        "/run/acgs-exchange/tmp/archive-0.dump",
        *(f"/run/acgs-exchange/tmp/archive-{index}.dump" for index in range(1, 32)),
    ]


def test_postgres_gate_client_broker_duplicate_read_rewrite_uses_cache_before_open() -> None:
    broker_source, _client_source = _postgres_gate_client_sources()
    cache_index = broker_source.index("if path in read_paths:")
    limit_index = broker_source.index("if len(read_paths) >= MAX_STAGED_INPUT_FILES:")
    open_index = broker_source.index("open_quota_regular_fd(", limit_index)

    assert cache_index < open_index
    assert limit_index < open_index


def test_postgres_gate_client_broker_rejects_input_count_overflow_before_docker(
    tmp_path: Path,
) -> None:
    def prepare_state(state_dir: Path) -> None:
        for index in range(32):
            archive = state_dir / "tmp" / f"archive-{index}.dump"
            archive.write_bytes(b"PGDMP-test")
            archive.chmod(0o600)

    response, docker_lines, archive_exists, env_attestation, tool_sentinel_exists = (
        _run_fake_docker_broker_request(
            tmp_path,
            "staging-count-overflow",
            tool="pg_restore",
            argv=[f"/run/tmp/archive-{index}.dump" for index in range(33)],
            prepare_state=prepare_state,
        )
    )
    state_dir = tmp_path / "state-staging-count-overflow"
    stderr = str(response["stderr"])

    assert response["returncode"] == 65, response
    assert "staging count exceeds broker limit" in stderr
    assert str(state_dir) not in stderr
    assert docker_lines == []
    assert not archive_exists
    assert env_attestation is None
    assert not tool_sentinel_exists
    assert not list((state_dir / "recovery").glob("*-exchange"))


def test_postgres_gate_client_broker_rejects_input_byte_overflow_before_docker(
    tmp_path: Path,
) -> None:
    def prepare_state(state_dir: Path) -> None:
        for index in range(8):
            archive = state_dir / "tmp" / f"archive-{index}.dump"
            archive.write_bytes(b"x" * 1_048_576)
            archive.chmod(0o600)
        archive = state_dir / "tmp" / "archive-8.dump"
        archive.write_bytes(b"y")
        archive.chmod(0o600)

    response, docker_lines, archive_exists, env_attestation, tool_sentinel_exists = (
        _run_fake_docker_broker_request(
            tmp_path,
            "staging-byte-overflow",
            tool="pg_restore",
            argv=[f"/run/tmp/archive-{index}.dump" for index in range(9)],
            prepare_state=prepare_state,
        )
    )
    state_dir = tmp_path / "state-staging-byte-overflow"
    stderr = str(response["stderr"])

    assert response["returncode"] == 65, response
    assert "staging bytes exceed broker limit" in stderr
    assert str(state_dir) not in stderr
    assert docker_lines == []
    assert not archive_exists
    assert env_attestation is None
    assert not tool_sentinel_exists
    assert not list((state_dir / "recovery").glob("*-exchange"))


def test_postgres_gate_client_broker_stages_exact_byte_limit(
    tmp_path: Path,
) -> None:
    def prepare_state(state_dir: Path) -> None:
        for index in range(8):
            archive = state_dir / "tmp" / f"archive-{index}.dump"
            archive.write_bytes(b"x" * 1_048_576)
            archive.chmod(0o600)

    response, docker_lines, archive_exists, env_attestation, tool_sentinel_exists = (
        _run_fake_docker_broker_request(
            tmp_path,
            "staging-byte-exact-limit",
            tool="pg_restore",
            argv=[f"/run/tmp/archive-{index}.dump" for index in range(8)],
            prepare_state=prepare_state,
        )
    )

    assert response["returncode"] == 0, response
    assert not archive_exists
    assert env_attestation == {
        "pgpassword_is_request": True,
        "pgpassword_is_ambient": False,
    }
    assert not tool_sentinel_exists
    assert [line for line in docker_lines if line[:2] == ["start", "-a"]]


def test_postgres_gate_client_broker_rejects_fifo_input_without_hanging(
    tmp_path: Path,
) -> None:
    def prepare_state(state_dir: Path) -> None:
        os.mkfifo(state_dir / "tmp" / "archive.dump", 0o600)

    response, docker_lines, archive_exists, env_attestation, tool_sentinel_exists = (
        _run_fake_docker_broker_request(
            tmp_path,
            "fifo-input",
            tool="pg_restore",
            argv=["--list", "/run/tmp/archive.dump"],
            prepare_state=prepare_state,
        )
    )
    state_dir = tmp_path / "state-fifo-input"
    stderr = str(response["stderr"])

    assert response["returncode"] == 64, response
    assert "path must be a regular file" in stderr
    assert str(state_dir) not in stderr
    assert docker_lines == []
    assert archive_exists
    assert env_attestation is None
    assert not tool_sentinel_exists
    assert not list((state_dir / "recovery").glob("*-exchange"))


def test_postgres_gate_client_broker_missing_input_is_redacted_and_leaves_no_exchange(
    tmp_path: Path,
) -> None:
    response, docker_lines, archive_exists, env_attestation, tool_sentinel_exists = (
        _run_fake_docker_broker_request(
            tmp_path,
            "missing-input",
            tool="pg_restore",
            argv=["--list", "/run/tmp/missing.dump"],
        )
    )
    state_dir = tmp_path / "state-missing-input"
    stderr = str(response["stderr"])

    assert response["returncode"] == 65, response
    assert "path is unavailable" in stderr
    assert str(state_dir) not in stderr
    assert "request-secret" not in stderr
    assert docker_lines == []
    assert not archive_exists
    assert env_attestation is None
    assert not tool_sentinel_exists
    assert not list((state_dir / "recovery").glob("*-exchange"))


def test_postgres_gate_client_broker_refuses_symlink_input_before_docker(
    tmp_path: Path,
) -> None:
    def prepare_state(state_dir: Path) -> None:
        outside = state_dir.parent / "outside.dump"
        outside.write_bytes(b"PGDMP-test")
        (state_dir / "tmp" / "archive.dump").symlink_to(outside)

    response, docker_lines, archive_exists, env_attestation, tool_sentinel_exists = (
        _run_fake_docker_broker_request(
            tmp_path,
            "ok",
            tool="pg_restore",
            argv=["--list", "/run/tmp/archive.dump"],
            prepare_state=prepare_state,
        )
    )

    assert response["returncode"] == 65, response
    assert "path is unavailable" in response["stderr"]
    assert docker_lines == []
    assert archive_exists
    assert env_attestation is None
    assert not tool_sentinel_exists


def test_postgres_gate_client_broker_refuses_symlink_ancestor_before_docker(
    tmp_path: Path,
) -> None:
    def prepare_state(state_dir: Path) -> None:
        outside = state_dir.parent / "outside"
        outside.mkdir()
        outside.chmod(0o700)
        (outside / "archive.dump").write_bytes(b"PGDMP-test")
        (state_dir / "tmp" / "slot").symlink_to(outside)

    response, docker_lines, archive_exists, env_attestation, tool_sentinel_exists = (
        _run_fake_docker_broker_request(
            tmp_path,
            "symlink-ancestor",
            tool="pg_restore",
            argv=["--list", "/run/tmp/slot/archive.dump"],
            prepare_state=prepare_state,
        )
    )
    state_dir = tmp_path / "state-symlink-ancestor"
    stderr = str(response["stderr"])

    assert response["returncode"] == 65, response
    assert "parent is unavailable" in stderr
    assert str(state_dir) not in stderr
    assert docker_lines == []
    assert not archive_exists
    assert env_attestation is None
    assert not tool_sentinel_exists
    assert not list((state_dir / "recovery").glob("*-exchange"))


def test_postgres_gate_client_broker_no_replace_publish_cleans_exchange_and_redacts(
    tmp_path: Path,
) -> None:
    def prepare_state(state_dir: Path) -> None:
        archive = state_dir / "tmp" / "archive.dump"
        archive.write_bytes(b"existing")
        archive.chmod(0o600)

    response, docker_lines, archive_exists, env_attestation, tool_sentinel_exists = (
        _run_fake_docker_broker_request(
            tmp_path,
            "preexisting-output",
            prepare_state=prepare_state,
        )
    )
    state_dir = tmp_path / "state-preexisting-output"
    archive = state_dir / "tmp" / "archive.dump"
    stderr = str(response["stderr"])

    assert response["returncode"] == 65, response
    assert "destination already exists" in stderr
    assert str(state_dir) not in stderr
    assert "request-secret" not in stderr
    assert docker_lines == []
    assert archive_exists
    assert archive.read_bytes() == b"existing"
    assert env_attestation is None
    assert not tool_sentinel_exists
    assert not list((state_dir / "recovery").glob("*-exchange"))


def test_postgres_gate_client_broker_rejects_non_custom_dump_magic_and_cleans_exchange(
    tmp_path: Path,
) -> None:
    response, docker_lines, archive_exists, env_attestation, tool_sentinel_exists = (
        _run_fake_docker_broker_request(
            tmp_path,
            "bad-dump-magic",
        )
    )
    state_dir = tmp_path / "state-bad-dump-magic"
    stderr = str(response["stderr"])

    assert response["returncode"] == 65, response
    assert "not a custom-format dump" in stderr
    assert str(state_dir) not in stderr
    assert "request-secret" not in stderr
    assert [line for line in docker_lines if line[:2] == ["start", "-a"]]
    assert not archive_exists
    assert env_attestation == {
        "pgpassword_is_request": True,
        "pgpassword_is_ambient": False,
    }
    assert not tool_sentinel_exists
    assert not list((state_dir / "recovery").glob("*-exchange"))


def test_postgres_gate_broker_directory_exchange_cannot_write_external_path(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    tmp_root = Path("/tmp")
    assert tmp_root.exists()
    assert tmp_root.is_dir()
    assert not tmp_root.is_symlink()
    canonical_tmp = tmp_root.resolve(strict=True)
    assert canonical_tmp == tmp_root
    state_dir = Path(tempfile.mkdtemp(prefix="acp-pg-gate-race-", dir=canonical_tmp))
    request.addfinalizer(lambda: shutil.rmtree(state_dir, ignore_errors=True))
    state_dir.chmod(0o700)
    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700
    broker_dir = state_dir / "broker"
    client_dir = state_dir / "client"
    allowed_tmp = state_dir / "tmp"
    proof_scratch = state_dir / "proof-scratch"
    recovery_root = state_dir / "recovery"
    proof_label = f"acp-postgres-gate-{os.getuid()}-0123456789abcdef0123456789abcdef"
    socket_bridge = recovery_root / f"{proof_label}-socket-bridge"
    fake_bin = tmp_path / "fake-bin"
    external_dir = tmp_path / "external"
    exchange_dir = allowed_tmp / "slot"
    for directory in (
        broker_dir,
        client_dir,
        allowed_tmp,
        proof_scratch,
        recovery_root,
        fake_bin,
        external_dir,
        exchange_dir,
    ):
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)
    bridge_identity, bridge_marker_sha256, bridge_mnt_id = _write_postgres_socket_bridge(
        socket_bridge,
        proof_label,
        "0123456789abcdef0123456789abcdef",
    )
    root_mnt_id = _mount_id(recovery_root)
    assert bridge_mnt_id == root_mnt_id

    broker_source, client_source = _postgres_gate_client_sources()
    broker_path = broker_dir / "postgres_client_broker.py"
    client_path = client_dir / "postgresql-client"
    broker_path.write_text(broker_source, encoding="utf-8")
    client_path.write_text(client_source, encoding="utf-8")
    client_path.chmod(0o755)
    (client_dir / "pg_dump").symlink_to("postgresql-client")

    docker_log = tmp_path / "docker-race-args.jsonl"
    docker_state = tmp_path / "docker-race-state.json"
    docker_path = fake_bin / "docker"
    _write_fake_postgres_client_docker(
        docker_path,
        docker_log,
        docker_state,
        [
            {
                "Type": "bind",
                "Source": str(socket_bridge),
                "Destination": "/run/acgs-pg",
                "RW": False,
            },
            {"Type": "bind", "Source": str(allowed_tmp), "Destination": "/run/tmp", "RW": True},
            {
                "Type": "bind",
                "Source": str(proof_scratch),
                "Destination": "/proof-scratch",
                "RW": True,
            },
            {
                "Type": "tmpfs",
                "Source": "",
                "Destination": "/var/lib/postgresql/data",
                "RW": True,
                "Options": "rw,noexec,nosuid,nodev,size=2g,uid=999,gid=999,mode=700",
            },
            {"Type": "tmpfs", "Source": "", "Destination": "/tmp", "RW": True},
        ],
    )

    socket_path = broker_dir / "postgresql-client.sock"
    broker_env = os.environ.copy()
    broker_env["PATH"] = f"{fake_bin}:{broker_env['PATH']}"
    broker_env["ACP_POSTGRES_CLIENT_BROKER_DOCKER"] = str(docker_path)
    broker_env["ACP_POSTGRES_CLIENT_PROOF_LABEL"] = proof_label
    broker_env["ACP_POSTGRES_CLIENT_PROOF_NONCE"] = "0123456789abcdef0123456789abcdef"
    broker_env["ACP_POSTGRES_SERVER_NAME"] = (
        f"{broker_env['ACP_POSTGRES_CLIENT_PROOF_LABEL']}-server"
    )
    broker_env["ACGS_POSTGRES_RECOVERY_ROOT"] = str(recovery_root)
    broker_env["ACP_POSTGRES_SOCKET_BRIDGE"] = str(socket_bridge)
    broker_env["ACP_POSTGRES_SOCKET_BRIDGE_IDENTITY"] = bridge_identity
    broker_env["ACP_POSTGRES_SOCKET_BRIDGE_MARKER_SHA256"] = bridge_marker_sha256
    broker_env["ACP_POSTGRES_SOCKET_BRIDGE_MNT_ID"] = bridge_mnt_id
    broker_env["ACP_POSTGRES_RECOVERY_ROOT_MNT_ID"] = root_mnt_id
    broker = subprocess.Popen(
        [sys.executable, str(broker_path), str(socket_path), str(state_dir)],
        env=broker_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5
        while not socket_path.exists() and time.monotonic() < deadline:
            if broker.poll() is not None:
                stdout, stderr = broker.communicate(timeout=1)
                pytest.fail(f"broker exited early: stdout={stdout!r} stderr={stderr!r}")
            time.sleep(0.05)
        assert socket_path.exists()

        attacker_link = allowed_tmp / "attacker-link"
        attacker_link.symlink_to(external_dir)
        original_exchange_identity = (
            exchange_dir.stat().st_dev,
            exchange_dir.stat().st_ino,
        )
        _rename_exchange(exchange_dir, attacker_link)
        assert exchange_dir.is_symlink()
        assert exchange_dir.resolve(strict=True) == external_dir.resolve(strict=True)
        assert attacker_link.is_dir()
        assert not attacker_link.is_symlink()
        assert (
            attacker_link.stat().st_dev,
            attacker_link.stat().st_ino,
        ) == original_exchange_identity

        external_archive = external_dir / "escape.dump"
        raced = subprocess.run(
            [
                str(client_dir / "pg_dump"),
                "--format=custom",
                "--file=/run/tmp/slot/escape.dump",
            ],
            env={
                "ACP_POSTGRES_CLIENT_BROKER_SOCKET": str(socket_path),
                "PGHOST": "/run/acgs-pg",
                "PGPORT": "5432",
                "PGUSER": "operator",
                "PGPASSWORD": "secret",
                "PGDATABASE": "acgs_control_plane_test",
            },
            capture_output=True,
            text=True,
            check=False,
        )
        assert raced.returncode == 65
        assert "parent is unavailable" in raced.stderr
        assert not external_archive.exists()
        assert not docker_log.exists()
    finally:
        broker.terminate()
        try:
            broker.wait(timeout=5)
        except subprocess.TimeoutExpired:
            broker.kill()
            broker.wait(timeout=5)


def test_postgres_gate_socket_sources_bind_relative_names() -> None:
    script = (Path(__file__).resolve().parents[1] / "scripts" / "run_postgres_gate.sh").read_text(
        encoding="utf-8"
    )
    broker_source, client_source = _postgres_gate_client_sources()

    assert "postgres_socket_proxy.py" not in script
    assert "--publish 127.0.0.1" not in script
    assert "listen_addresses=" in script
    assert "unix_socket_directories=/var/run/postgresql" in script
    assert "--security-opt label=disable" in script
    assert '"type=bind,src=$postgres_socket_bridge,dst=/var/run/postgresql"' in script
    assert "verify_docker_mounts" in script
    assert "verify_server_socket_bridge_marker" in script
    assert "acgs-entrypoint-pg-service.conf" not in script
    assert '"$state_dir/pg:/run/acgs-pg' not in script
    assert "forbids volume syntax drift" in broker_source
    assert "STATE_DIR = Path(sys.argv[2]).resolve(strict=True)" in broker_source
    assert "SOCKET_PATH.parent.parent" not in broker_source
    assert 'PG_SOCKET_BRIDGE = Path(os.environ["ACP_POSTGRES_SOCKET_BRIDGE"])' in broker_source
    assert 'f"type=bind,src={PG_SOCKET_BRIDGE},dst=/run/acgs-pg,readonly"' in broker_source
    assert "validate_socket_bridge()" in broker_source
    assert "inspect_exact_docker_mounts(docker_args, exchange_roots)" in broker_source
    assert "validate_final_docker_create_argv(" in broker_source
    assert "maybe_mutate_final_docker_create_argv_for_test(" not in broker_source
    assert "ACGS_TEST_POSTGRES_CLIENT_BROKER_MUTATE_FINAL_CREATE_ARGV" not in broker_source
    assert 'str(DOCKER_BIN), "create"' in broker_source
    tail_tuple_index = broker_source.index("docker_create_tail = (")
    create_tuple_index = broker_source.index("docker_create_args = (", tail_tuple_index)
    initial_mount_index = broker_source.index(
        "inspect_exact_docker_mounts(docker_args, exchange_roots)",
        create_tuple_index,
    )
    final_validation_index = broker_source.index(
        "validate_final_docker_create_argv(",
        initial_mount_index,
    )
    subprocess_create_index = broker_source.index(
        "subprocess.run(\n                validated_docker_create_args,",
        final_validation_index,
    )
    adjacency = broker_source[final_validation_index:subprocess_create_index]
    assert "docker_create_tail" in adjacency
    assert "subprocess." not in adjacency
    assert "container_might_exist = True\n            validated_docker_create_args" in broker_source
    assert tail_tuple_index < create_tuple_index < initial_mount_index
    assert initial_mount_index < final_validation_index < subprocess_create_index
    assert '"--rm"' not in broker_source
    assert "wait_for_actual_docker_mounts(created_container_ref, exchange_roots)" in broker_source
    assert 'str(DOCKER_BIN), "start", "-a", created_container_ref' in broker_source
    assert "acgs-client-marker-wrapper" in broker_source
    assert "stat -c '%d:%i:%u:%a' /run/acgs-pg" in broker_source
    assert "temp_created = False" in broker_source
    assert "os.unlink(tmp_name, dir_fd=parent_fd)" in broker_source
    assert "server.bind(str(SOCKET_PATH))" not in broker_source
    assert "client.connect(socket_path)" not in client_source
    assert "os.chdir(SOCKET_DIR)" in broker_source
    assert "server.bind(SOCKET_NAME)" in broker_source
    assert "os.chdir(socket_dir)" in client_source
    assert "import time" in client_source
    assert "def connect_broker_socket() -> socket.socket:" in client_source
    assert "deadline = time.monotonic() + 15" in client_source
    assert "except (FileNotFoundError, ConnectionRefusedError, TimeoutError):" in client_source
    assert "client.settimeout(min(1.0, remaining))" in client_source
    assert "client.settimeout(15)" in client_source
    assert "time.sleep(min(0.05, remaining))" in client_source
    assert "PostgreSQL client broker is unavailable" in client_source
    assert "raise SystemExit(70) from None" in client_source
    assert "with connect_broker_socket() as client:" in client_source
    assert "client.connect(socket_name)" in client_source
    exchange_marker_open_index = broker_source.index("def write_exchange_marker")
    exchange_marker_fchmod_index = broker_source.index(
        "os.fchmod(fd, 0o444)", exchange_marker_open_index
    )
    exchange_marker_fstat_index = broker_source.index(
        "marker_stat = os.fstat(fd)", exchange_marker_open_index
    )
    assert exchange_marker_fchmod_index < exchange_marker_fstat_index
    assert '"--memory", "512m", "--cpus", "1", "--pids-limit", "128"' in broker_source
    assert '"--ulimit", "nofile=256:256"' in broker_source
    assert (
        '"/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=2g,uid=999,gid=999,mode=700"'
        in broker_source
    )
    assert '"--ulimit", f"fsize={MAX_COMBINED_OUTPUT_BYTES}:{MAX_COMBINED_OUTPUT_BYTES}"' in (
        broker_source
    )
    assert '"nproc=128:128"' not in broker_source


def _postgres_gate_client_sources() -> tuple[str, str]:
    script = (Path(__file__).resolve().parents[1] / "scripts" / "run_postgres_gate.sh").read_text(
        encoding="utf-8"
    )
    broker_source = _extract_single_quoted_heredoc(
        script,
        'write_verified_private_artifact "$state_dir/broker" '
        "\"postgres_client_broker.py\" 0700 <<'PY'\n",
    )
    client_source = _extract_single_quoted_heredoc(
        script,
        'write_verified_private_artifact "$state_dir/client" '
        "\"$postgres_client_tool\" 0700 <<'PY'\n",
    )
    return broker_source, client_source


def _write_extracted_postgres_client(tmp_path: Path, source: str) -> Path:
    client_path = tmp_path / "pg_dump"
    client_path.write_text(source, encoding="utf-8")
    client_path.chmod(0o700)
    return client_path


def test_postgres_gate_client_wrapper_retries_until_bound_socket_listens(
    tmp_path: Path,
) -> None:
    _broker_source, client_source = _postgres_gate_client_sources()
    client_path = _write_extracted_postgres_client(tmp_path, client_source)
    received: list[dict[str, object]] = []

    with tempfile.TemporaryDirectory(prefix="acgs-pg-client-", dir="/tmp") as socket_dir_name:
        socket_dir = Path(socket_dir_name)
        socket_path = socket_dir / "delayed-listen.sock"
        assert socket_dir.parent == Path("/tmp")
        assert socket_dir.stat().st_uid == os.getuid()
        assert stat.S_IMODE(socket_dir.stat().st_mode) == 0o700
        assert str(tmp_path) not in str(socket_path)
        assert len(os.fsencode(socket_path)) < 108

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(socket_path))

        def delayed_server() -> None:
            time.sleep(0.25)
            server.listen(1)
            server.settimeout(5)
            conn, _addr = server.accept()
            with conn:
                payload = conn.recv(65536)
                received.append(json.loads(payload.decode("utf-8")))
                conn.sendall(
                    json.dumps(
                        {"stdout": "ready\n", "stderr": "", "returncode": 0},
                        separators=(",", ":"),
                    ).encode("utf-8")
                )
            server.close()

        thread = threading.Thread(target=delayed_server)
        thread.start()
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(client_path),
                    "--format=custom",
                    "--file=/run/tmp/archive.dump",
                ],
                env={
                    **os.environ,
                    "ACP_POSTGRES_CLIENT_BROKER_SOCKET": str(socket_path),
                    "PGHOST": "/run/acgs-pg",
                    "PGPORT": "5432",
                    "PGUSER": "operator",
                    "PGPASSWORD": "request-secret",
                    "PGDATABASE": "acgs_control_plane_test",
                },
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        finally:
            thread.join(timeout=5)
            server.close()

    assert result.returncode == 0, result.stderr
    assert result.stdout == "ready\n"
    assert result.stderr == ""
    assert received
    assert received[0]["tool"] == "pg_dump"
    assert received[0]["argv"] == ["--format=custom", "--file=/run/tmp/archive.dump"]


def test_postgres_gate_client_wrapper_fails_closed_when_broker_unavailable(
    tmp_path: Path,
) -> None:
    _broker_source, client_source = _postgres_gate_client_sources()
    client_source = client_source.replace("time.monotonic() + 15", "time.monotonic() + 0.2", 1)
    assert "time.monotonic() + 0.2" in client_source
    client_path = _write_extracted_postgres_client(tmp_path, client_source)
    socket_path = tmp_path / "missing-broker.sock"
    side_effect = tmp_path / "side-effect"

    result = subprocess.run(
        [sys.executable, str(client_path), "--format=custom", f"--file={side_effect}"],
        env={
            **os.environ,
            "ACP_POSTGRES_CLIENT_BROKER_SOCKET": str(socket_path),
            "PGHOST": "/run/acgs-pg",
            "PGPORT": "5432",
            "PGUSER": "operator",
            "PGPASSWORD": "request-secret",
            "PGDATABASE": "acgs_control_plane_test",
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )

    assert result.returncode == 70
    assert result.stdout == ""
    assert result.stderr.strip() == "PostgreSQL client broker is unavailable"
    assert not socket_path.exists()
    assert not side_effect.exists()


class _FakePostgresClientClock:
    def __init__(self) -> None:
        self.elapsed = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.elapsed

    def sleep(self, duration: float) -> None:
        self.sleeps.append(duration)
        self.elapsed += duration


class _FakePostgresClientSocket:
    def __init__(
        self,
        factory: _FakePostgresClientSocketFactory,
    ) -> None:
        self.factory = factory
        self.timeouts: list[float] = []
        self.closed = False
        self.connected = False

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)

    def connect(self, socket_name: str) -> None:
        self.factory.connect_names.append(socket_name)
        outcome = self.factory.next_outcome()
        if outcome == "success":
            self.connected = True
            return
        if outcome == "timeout":
            assert self.timeouts
            self.factory.clock.elapsed += self.timeouts[-1]
            raise TimeoutError("timeout-canary")
        if outcome == "not-found":
            raise FileNotFoundError("not-found-canary")
        if outcome == "refused":
            raise ConnectionRefusedError("refused-canary")
        if outcome == "fatal":
            raise OSError("fatal-canary")
        raise AssertionError(f"unknown fake socket outcome {outcome!r}")

    def close(self) -> None:
        self.closed = True


class _FakePostgresClientSocketFactory:
    AF_UNIX = socket.AF_UNIX
    SOCK_STREAM = socket.SOCK_STREAM

    def __init__(self, clock: _FakePostgresClientClock, outcomes: list[str]) -> None:
        self.clock = clock
        self.outcomes = list(outcomes)
        self.instances: list[_FakePostgresClientSocket] = []
        self.connect_names: list[str] = []

    def socket(self, family: int, kind: int) -> _FakePostgresClientSocket:
        assert family == socket.AF_UNIX
        assert kind == socket.SOCK_STREAM
        instance = _FakePostgresClientSocket(self)
        self.instances.append(instance)
        return instance

    def next_outcome(self) -> str:
        if self.outcomes:
            return self.outcomes.pop(0)
        return "timeout"


def _load_extracted_client_connect_broker_socket(
    client_source: str,
    *,
    fake_clock: _FakePostgresClientClock,
    fake_socket: _FakePostgresClientSocketFactory,
) -> Callable[[], _FakePostgresClientSocket]:
    start = client_source.index("def connect_broker_socket() -> socket.socket:")
    end = client_source.index("\n\nwith connect_broker_socket() as client:", start)
    function_source = client_source[start:end]
    namespace = {
        "os": SimpleNamespace(chdir=lambda _path: None),
        "socket": fake_socket,
        "socket_dir": Path("/fake/socket-parent"),
        "socket_name": "broker.sock",
        "sys": sys,
        "time": fake_clock,
    }
    exec(function_source, namespace)
    return namespace["connect_broker_socket"]


def test_postgres_gate_client_wrapper_bounds_attempt_timeout_by_remaining_deadline() -> None:
    _broker_source, client_source = _postgres_gate_client_sources()
    fake_clock = _FakePostgresClientClock()
    fake_socket = _FakePostgresClientSocketFactory(fake_clock, ["timeout"] * 64)
    connect_broker_socket = _load_extracted_client_connect_broker_socket(
        client_source,
        fake_clock=fake_clock,
        fake_socket=fake_socket,
    )

    stderr = io.StringIO()
    with pytest.raises(SystemExit) as exc_info, contextlib.redirect_stderr(stderr):
        connect_broker_socket()

    assert exc_info.value.code == 70
    assert stderr.getvalue().strip() == "PostgreSQL client broker is unavailable"
    assert "Traceback" not in stderr.getvalue()
    assert "timeout-canary" not in stderr.getvalue()
    assert fake_clock.elapsed <= 15.0
    assert fake_clock.elapsed == pytest.approx(15.0)
    assert fake_socket.instances
    assert all(instance.closed for instance in fake_socket.instances)
    assert all(instance.timeouts for instance in fake_socket.instances)
    assert max(instance.timeouts[-1] for instance in fake_socket.instances) <= 1.0
    assert fake_clock.sleeps
    assert max(fake_clock.sleeps) <= 0.05


@pytest.mark.parametrize(
    "outcomes",
    [
        ["not-found", "success"],
        ["refused", "success"],
        ["timeout", "success"],
    ],
)
def test_postgres_gate_client_wrapper_retries_transient_connect_errors_then_succeeds(
    outcomes: list[str],
) -> None:
    _broker_source, client_source = _postgres_gate_client_sources()
    fake_clock = _FakePostgresClientClock()
    fake_socket = _FakePostgresClientSocketFactory(fake_clock, outcomes)
    connect_broker_socket = _load_extracted_client_connect_broker_socket(
        client_source,
        fake_clock=fake_clock,
        fake_socket=fake_socket,
    )

    connected = connect_broker_socket()
    try:
        assert connected.connected
        assert not connected.closed
        assert connected.timeouts[-1] == 15
        assert len(fake_socket.instances) == 2
        assert fake_socket.instances[0].closed
        assert fake_socket.instances[1] is connected
        assert fake_socket.connect_names == ["broker.sock", "broker.sock"]
    finally:
        connected.close()


def test_postgres_gate_client_wrapper_closes_post_alloc_nontransient_connect_error() -> None:
    _broker_source, client_source = _postgres_gate_client_sources()
    fake_clock = _FakePostgresClientClock()
    fake_socket = _FakePostgresClientSocketFactory(fake_clock, ["fatal"])
    connect_broker_socket = _load_extracted_client_connect_broker_socket(
        client_source,
        fake_clock=fake_clock,
        fake_socket=fake_socket,
    )

    stderr = io.StringIO()
    with pytest.raises(SystemExit) as exc_info, contextlib.redirect_stderr(stderr):
        connect_broker_socket()

    assert exc_info.value.code == 70
    assert stderr.getvalue().strip() == "PostgreSQL client broker is unavailable"
    assert "fatal-canary" not in stderr.getvalue()
    assert fake_socket.instances
    assert all(instance.closed for instance in fake_socket.instances)


@pytest.mark.parametrize(
    ("case_name", "source_mutation", "expected_missing"),
    [
        (
            "missing-parent",
            lambda source, socket_path: source,
            "missing-parent",
        ),
        (
            "constructor-failure",
            lambda source, socket_path: source.replace(
                "client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)",
                "raise OSError('socket-canary-secret')",
                1,
            ),
            "socket-canary-secret",
        ),
    ],
)
def test_postgres_gate_client_wrapper_failures_are_generic_without_traceback_or_path(
    tmp_path: Path,
    case_name: str,
    source_mutation: Callable[[str, Path], str],
    expected_missing: str,
) -> None:
    _broker_source, client_source = _postgres_gate_client_sources()
    socket_parent = tmp_path / case_name / "parent"
    socket_path = socket_parent / "broker.sock"
    if case_name != "missing-parent":
        socket_parent.mkdir(parents=True)
    client_source = source_mutation(client_source, socket_path)
    client_path = _write_extracted_postgres_client(tmp_path, client_source)
    side_effect = tmp_path / f"{case_name}-side-effect"

    result = subprocess.run(
        [sys.executable, str(client_path), "--format=custom", f"--file={side_effect}"],
        env={
            **os.environ,
            "ACP_POSTGRES_CLIENT_BROKER_SOCKET": str(socket_path),
            "PGHOST": "/run/acgs-pg",
            "PGPORT": "5432",
            "PGUSER": "operator",
            "PGPASSWORD": "request-secret",
            "PGDATABASE": "acgs_control_plane_test",
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )

    assert result.returncode == 70
    assert result.stdout == ""
    assert result.stderr.strip() == "PostgreSQL client broker is unavailable"
    assert "Traceback" not in result.stderr
    assert str(socket_path) not in result.stderr
    assert expected_missing not in result.stderr
    assert not side_effect.exists()


def _postgres_gate_script_source() -> str:
    script_override = os.environ.get("ACGS_POSTGRES_GATE_SCRIPT_UNDER_TEST")
    script_path = (
        Path(script_override)
        if script_override
        else Path(__file__).resolve().parents[1] / "scripts" / "run_postgres_gate.sh"
    )
    return script_path.read_text(encoding="utf-8")


def _extract_shell_function(script: str, name: str, next_name: str) -> str:
    start = script.index(f"{name}() {{")
    end = script.index(f"\n{next_name}() {{", start)
    return script[start:end]


def _extract_shell_function_before_marker(script: str, name: str, marker: str) -> str:
    start = script.index(f"{name}() {{")
    end = script.index(marker, start)
    return script[start:end].rstrip()


def test_postgres_gate_child_state_dir_fd_closure_blocks_parent_escape_and_socket_reach() -> None:
    script = _postgres_gate_script_source()
    closer_source = _extract_shell_function_before_marker(
        script,
        "close_child_state_dir_fd",
        "\n\n# shellcheck disable=SC2016",
    )
    cleanup_start = script.index("cleanup() {")
    cleanup_end = script.index("\ntrap cleanup EXIT", cleanup_start)
    cleanup_source = script[cleanup_start:cleanup_end]
    assert script.count('exec {state_dir_fd}<"$state_dir"') == 1
    assert script.count("close_child_state_dir_fd") == 4
    assert "close_child_state_dir_fd" not in cleanup_source
    assert 'local retained_state_fd="${state_dir_fd:-}"' in closer_source
    assert '[[ ! "$retained_state_fd" =~ ^[0-9]+$ ]]' in closer_source
    assert "exec {state_dir_fd}<&-" in closer_source
    assert '[[ ! -e "/proc/$BASHPID/fd/$retained_state_fd" ]] || return 70' in closer_source
    assert "state_dir_fd=''" in closer_source
    assert "unset state_dir_fd" in closer_source
    assert closer_source.count("return 70") == 2
    assert closer_source.index("local retained_state_fd=") < closer_source.index(
        '[[ ! "$retained_state_fd" =~ ^[0-9]+$ ]]'
    )
    assert closer_source.index('[[ ! "$retained_state_fd" =~ ^[0-9]+$ ]]') < (
        closer_source.index("exec {state_dir_fd}<&-")
    )
    assert closer_source.index("exec {state_dir_fd}<&-") < closer_source.index(
        '[[ ! -e "/proc/$BASHPID/fd/$retained_state_fd" ]] || return 70'
    )
    assert closer_source.rindex("state_dir_fd=''") < closer_source.rindex("unset state_dir_fd")
    assert closer_source.rstrip().endswith("  state_dir_fd=''\n  unset state_dir_fd\n}")
    assert script.count("close_child_state_dir_fd || exit 70") == 3

    with tempfile.TemporaryDirectory(prefix="acgs-pg-fd-", dir="/tmp") as raw_tmp:
        temp_root = Path(raw_tmp)
        state_dir = temp_root / "state"
        state_dir.mkdir(mode=0o700)
        sibling_path = temp_root / "sibling-created"
        socket_path = temp_root / "external.sock"
        harness = temp_root / "child-fd-closure.sh"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(socket_path))
            listener.listen(1)
            harness.write_text(
                "#!/usr/bin/env bash\n"
                "set -Eeuo pipefail\n"
                f"{closer_source}\n"
                f"state_dir={shlex.quote(str(state_dir))}\n"
                f"sibling_path={shlex.quote(str(sibling_path))}\n"
                f"external_socket={shlex.quote(str(socket_path))}\n"
                'exec {state_dir_fd}<"$state_dir"\n'
                "set +e\n"
                "(\n"
                "  state_dir_fd=not-a-number\n"
                "  close_child_state_dir_fd || exit 70\n"
                "  exit 37\n"
                ")\n"
                "invalid_child_status=$?\n"
                "set -e\n"
                '[[ "$invalid_child_status" == 70 ]] || exit 80\n'
                "set +e\n"
                "(\n"
                "  close_child_state_dir_fd || exit 70\n"
                "  exit 37\n"
                ")\n"
                "propagated_child_status=$?\n"
                "set -e\n"
                '[[ "$propagated_child_status" == 37 ]] || exit 81\n'
                '[[ -e "/proc/$BASHPID/fd/$state_dir_fd" ]] || exit 82\n'
                "(\n"
                "  close_child_state_dir_fd || exit 70\n"
                '  /usr/bin/python3 -I -S - "$state_dir" "$sibling_path" '
                "\"$external_socket\" <<'PY'\n"
                "from __future__ import annotations\n"
                "import errno\n"
                "import os\n"
                "import socket\n"
                "import stat\n"
                "import sys\n"
                "state_dir, sibling_path, external_socket = sys.argv[1:4]\n"
                "state_stat = os.stat(state_dir, follow_symlinks=False)\n"
                "parent_path = os.path.dirname(state_dir)\n"
                "sibling_name = os.path.basename(sibling_path)\n"
                "socket_name = os.path.basename(external_socket)\n"
                "for fd_name in os.listdir('/proc/self/fd'):\n"
                "    if not fd_name.isdigit():\n"
                "        continue\n"
                "    fd_path = f'/proc/self/fd/{fd_name}'\n"
                "    try:\n"
                "        fd_stat = os.stat(fd_path)\n"
                "    except OSError:\n"
                "        continue\n"
                "    if stat.S_ISDIR(fd_stat.st_mode) and fd_stat.st_dev == state_stat.st_dev "
                "and fd_stat.st_ino == state_stat.st_ino:\n"
                "        raise SystemExit(71)\n"
                "    if os.path.realpath(os.path.join(fd_path, '..')) != parent_path:\n"
                "        continue\n"
                "    try:\n"
                "        escaped_fd = os.open(os.path.join(fd_path, '..', sibling_name), "
                "os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)\n"
                "    except OSError as exc:\n"
                "        if exc.errno not in {errno.ENOENT, errno.ENOTDIR, errno.EBADF}:\n"
                "            raise SystemExit(72) from exc\n"
                "    else:\n"
                "        os.close(escaped_fd)\n"
                "        raise SystemExit(73)\n"
                "    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:\n"
                "        try:\n"
                "            client.settimeout(0.1)\n"
                "            client.connect(os.path.join(fd_path, '..', socket_name))\n"
                "        except OSError:\n"
                "            pass\n"
                "        else:\n"
                "            raise SystemExit(74)\n"
                "print('CHILD_STATE_FD_CLOSED')\n"
                "PY\n"
                ")\n",
                encoding="utf-8",
            )
            harness.chmod(0o755)
            result = subprocess.run(
                [str(harness)],
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert "CHILD_STATE_FD_CLOSED" in result.stdout
        assert not sibling_path.exists()


def _postgres_gate_server_launch_and_health_source(script: str) -> str:
    start = script.index("docker_started=1\n")
    end = script.index('\nif [[ ! -S "$postgres_socket_bridge/.s.PGSQL.5432" ]]', start)
    return script[start:end]


def _postgres_gate_server_health_loop_source(script: str) -> str:
    start = script.index("for _ in {1..90}; do\n")
    end = script.index('\nif [[ ! -S "$postgres_socket_bridge/.s.PGSQL.5432" ]]', start)
    return script[start:end]


@pytest.mark.parametrize("fail_at", ["write", "fchmod", "validation"])
def test_postgres_gate_private_artifact_failure_unlinks_only_created_inode(
    tmp_path: Path,
    fail_at: str,
) -> None:
    script = _postgres_gate_script_source()
    write_source = _extract_shell_function(
        script,
        "write_verified_private_artifact",
        "verify_private_artifact_fd",
    )
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    harness = "\n".join(
        (
            "set -euo pipefail",
            "umask 077",
            f"state_dir={str(state_dir)!r}",
            f"export ACGS_TEST_WRITE_VERIFIED_PRIVATE_ARTIFACT_FAIL_AT={fail_at!r}",
            write_source,
            'if write_verified_private_artifact "$state_dir" generic-private-artifact.txt 0444 <<'
            "'EOF'",
            "artifact",
            "EOF",
            "then exit 90; fi",
            'test ! -e "$state_dir/generic-private-artifact.txt"',
        )
    )
    result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (fail_at, result.stdout, result.stderr)


@pytest.mark.parametrize(
    ("mode", "expected_state_status"),
    [
        ("ok", "ok"),
        ("state-malformed", "malformed"),
        ("state-duplicate", "malformed"),
        ("state-oversize", "oversized"),
        ("state-fail", "command_failed"),
        ("state-timeout", "command_failed"),
        ("logs-oversize", "ok"),
        ("logs-fail", "ok"),
        ("logs-binary", "ok"),
    ],
)
def test_postgres_gate_prehealth_exit_captures_hash_only_bounded_diagnostics(
    tmp_path: Path,
    mode: str,
    expected_state_status: str,
) -> None:
    script = _postgres_gate_script_source()
    diagnostic_source = _extract_shell_function(
        script,
        "capture_postgres_server_diagnostics",
        "cleanup",
    )
    health_source = _postgres_gate_server_health_loop_source(script)
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    sentinel = tmp_path / "pytest-client-or-broker-reached"
    argv_log = tmp_path / "docker-argv.log"
    docker_path = fake_bin / "docker"
    raw_sentinels = [
        "super-secret-password",
        "Bearer abc.def.ghi",
        "access_token=token-123",
        "--password p@ssw0rd",
        "postgresql://user:url-secret@example/acgs",
        "MiXeDSecret=case-value",
        "prefixsuper-secret-passwordsuffix",
    ]
    secret_blob = " ".join(raw_sentinels)
    docker_path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "import json, sys",
                f"mode = {mode!r}",
                f"argv_log = {str(argv_log)!r}",
                f"secret_blob = {secret_blob!r}",
                "with open(argv_log, 'a', encoding='utf-8') as handle:",
                "    handle.write(json.dumps(sys.argv) + '\\n')",
                "argv = sys.argv[1:]",
                "if argv[:2] == ['inspect', '--format']:",
                "    fmt = argv[2]",
                "    if fmt == '{{.State.Status}}':",
                "        print('exited')",
                "        raise SystemExit(0)",
                "    if fmt == '{{.State.Health.Status}}':",
                "        print('starting')",
                "        raise SystemExit(0)",
                "    if fmt.startswith('{\"State\"'):",
                "        if mode == 'state-fail':",
                "            print(secret_blob, file=sys.stderr)",
                "            raise SystemExit(42)",
                "        if mode == 'state-timeout':",
                "            print(secret_blob, file=sys.stderr)",
                "            raise SystemExit(124)",
                "        if mode == 'state-malformed':",
                "            print('{')",
                "            raise SystemExit(0)",
                "        if mode == 'state-duplicate':",
                '            print(\'{"State":{"Status":"exited","Status":"running"}}\')',
                "            raise SystemExit(0)",
                "        if mode == 'state-oversize':",
                "            sys.stdout.write('x' * 70000)",
                "            raise SystemExit(0)",
                "        print(secret_blob, file=sys.stderr)",
                "        print(json.dumps({",
                "            'State': {",
                "                'Status': 'exited',",
                "                'ExitCode': 2,",
                "                'Error': secret_blob,",
                "                'OOMKilled': False,",
                "                'HealthStatus': 'starting',",
                "                'FailingStreak': 1,",
                "            },",
                "        }, separators=(',', ':')))",
                "        raise SystemExit(0)",
                "if argv[:1] == ['logs']:",
                "    if mode == 'logs-fail':",
                "        print(secret_blob, file=sys.stderr)",
                "        raise SystemExit(43)",
                "    if mode == 'logs-oversize':",
                "        sys.stdout.write(secret_blob + ('x' * 17000))",
                "        raise SystemExit(0)",
                "    if mode == 'logs-binary':",
                "        sys.stdout.buffer.write(b'\\xff\\x00' + secret_blob.encode())",
                "        raise SystemExit(0)",
                "    print(secret_blob)",
                "    print(secret_blob, file=sys.stderr)",
                "    raise SystemExit(0)",
                "raise SystemExit(127)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    docker_path.chmod(0o755)
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"PATH={str(fake_bin)!r}:$PATH",
            "sleep() { :; }",
            f"state_dir={str(tmp_path / 'state')!r}",
            'mkdir -p "$state_dir/tmp"',
            "container_id='server-cid'",
            diagnostic_source,
            health_source,
            "touch " + shlex.quote(str(sentinel)),
        )
    )
    result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 70, (mode, result.stdout, result.stderr)
    assert not sentinel.exists()
    diagnostic_lines = [
        line
        for line in result.stderr.splitlines()
        if line.startswith("postgres_server_diagnostic=")
    ]
    assert len(diagnostic_lines) == 1, result.stderr
    assert len(diagnostic_lines[0].encode("utf-8")) <= 4096 + len("postgres_server_diagnostic=")
    diagnostic = json.loads(diagnostic_lines[0].split("=", 1)[1])
    assert diagnostic["schema"] == "acgs-postgres-server-prehealth-diagnostic/v1"
    assert diagnostic["state"]["capture_status"] == expected_state_status
    assert "sha256" in diagnostic["logs_stdout"]
    assert "byte_count" in diagnostic["logs_stdout"]
    assert "the disposable PostgreSQL container exited before becoming healthy" in result.stderr
    docker_argv = argv_log.read_text(encoding="utf-8")
    combined_output = result.stdout + result.stderr + docker_argv
    for sentinel_value in raw_sentinels:
        assert sentinel_value not in combined_output
    if mode == "ok":
        assert diagnostic["state"]["Status"] == "exited"
        assert diagnostic["state"]["ExitCode"] == 2
        assert diagnostic["state"]["HealthStatus"] == "starting"
        assert diagnostic["error"]["byte_count"] == len(secret_blob.encode("utf-8"))


def _run_recovery_root_validation_to_bridge(
    tmp_path: Path,
    recovery_root: Path,
) -> tuple[subprocess.CompletedProcess[str], Path, Path, Path]:
    script = _postgres_gate_script_source()
    validate_root_source = _extract_shell_function(
        script,
        "validate_postgres_recovery_root",
        "validate_postgres_recovery_root_binding",
    )
    create_bridge_source = _extract_shell_function(
        script,
        "create_postgres_socket_bridge",
        "verify_postgres_socket_bridge",
    )
    assert "\nimport time\n" in create_bridge_source
    assert "time.sleep(0.2)" in create_bridge_source
    proof_nonce = "0123456789abcdef0123456789abcdef"
    proof_label = f"acp-postgres-gate-{os.getuid()}-{proof_nonce}"
    bridge = recovery_root / f"{proof_label}-socket-bridge"
    bridge_created_sentinel = tmp_path / "bridge-created-sentinel"
    contract_trust_sentinel = tmp_path / "contract-trust-sentinel"
    outside_sentinel = tmp_path / "outside-sentinel"
    outside_sentinel.write_text("outside\n", encoding="ascii")
    env = {
        **os.environ,
        "ACGS_TEST_RECOVERY_ROOT": str(recovery_root),
        "ACGS_TEST_ROOT_BINDING": _recovery_root_binding(recovery_root),
        "ACGS_TEST_ROOT_MNT_ID": _mount_id(recovery_root),
    }
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"proof_nonce={proof_nonce!r}",
            f"proof_label={proof_label!r}",
            "postgres_recovery_root=$ACGS_TEST_RECOVERY_ROOT",
            "postgres_recovery_root_binding=$ACGS_TEST_ROOT_BINDING",
            "postgres_recovery_root_mnt_id=$ACGS_TEST_ROOT_MNT_ID",
            validate_root_source,
            create_bridge_source,
            "if postgres_recovery_root=$(validate_postgres_recovery_root "
            '"$postgres_recovery_root"); then',
            '  mapfile -t fields < <(create_postgres_socket_bridge "$proof_label-socket-bridge")',
            '  test "${#fields[@]}" = 5',
            f"  touch {shlex.quote(str(bridge_created_sentinel))}",
            f"  touch {shlex.quote(str(contract_trust_sentinel))}",
            "  rc=0",
            "else",
            "  rc=$?",
            "fi",
            'printf "VALIDATE_RC=%s\\n" "$rc"',
            'exit "$rc"',
        )
    )
    result = subprocess.run(
        ["bash", "-s"],
        input=harness,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert outside_sentinel.read_text(encoding="ascii") == "outside\n"
    return result, bridge, bridge_created_sentinel, contract_trust_sentinel


def test_postgres_gate_recovery_root_validation_allows_safe_path(tmp_path: Path) -> None:
    recovery_root = tmp_path / "safe-recovery"
    recovery_root.mkdir()
    recovery_root.chmod(0o700)

    result, bridge, bridge_created_sentinel, contract_trust_sentinel = (
        _run_recovery_root_validation_to_bridge(tmp_path, recovery_root)
    )

    assert result.returncode == 0, result.stderr
    assert "VALIDATE_RC=0\n" in result.stdout
    assert bridge.is_dir()
    assert bridge_created_sentinel.exists()
    assert contract_trust_sentinel.exists()


@pytest.mark.parametrize("control_char", ["\n", "\r", "\t", "\x7f"])
def test_postgres_gate_recovery_root_validation_rejects_supplied_control_chars(
    tmp_path: Path,
    control_char: str,
) -> None:
    recovery_root = tmp_path / f"recovery{control_char}root"
    recovery_root.mkdir()
    recovery_root.chmod(0o700)

    result, bridge, bridge_created_sentinel, contract_trust_sentinel = (
        _run_recovery_root_validation_to_bridge(tmp_path, recovery_root)
    )

    assert result.returncode == 70, (control_char, result.stdout, result.stderr)
    assert "VALIDATE_RC=70\n" in result.stdout
    assert not bridge.exists()
    assert not bridge_created_sentinel.exists()
    assert not contract_trust_sentinel.exists()


def test_postgres_gate_recovery_root_validation_rejects_control_char_canonical_path(
    tmp_path: Path,
) -> None:
    target_parent = tmp_path / "target\nparent"
    target_parent.mkdir()
    target_parent.chmod(0o700)
    target_root = target_parent / "recovery"
    target_root.mkdir()
    target_root.chmod(0o700)
    clean_link = tmp_path / "clean-link"
    clean_link.symlink_to(target_parent, target_is_directory=True)
    supplied_root = clean_link / "recovery"

    result, bridge, bridge_created_sentinel, contract_trust_sentinel = (
        _run_recovery_root_validation_to_bridge(tmp_path, supplied_root)
    )

    assert result.returncode == 70, result.stderr
    assert "VALIDATE_RC=70\n" in result.stdout
    assert not bridge.exists()
    assert not bridge_created_sentinel.exists()
    assert not contract_trust_sentinel.exists()


def test_postgres_gate_socket_bridge_create_refuses_existing_paths(tmp_path: Path) -> None:
    script = _postgres_gate_script_source()
    create_bridge_source = _extract_shell_function(
        script,
        "create_postgres_socket_bridge",
        "verify_postgres_socket_bridge",
    )
    recovery_root = tmp_path / "recovery"
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    proof_nonce = "0123456789abcdef0123456789abcdef"
    proof_label = f"acp-postgres-gate-{os.getuid()}-{proof_nonce}"
    bridge_name = f"{proof_label}-socket-bridge"
    root_binding = _recovery_root_binding(recovery_root)
    root_mnt_id = _mount_id(recovery_root)
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"postgres_recovery_root={str(recovery_root)!r}",
            f"postgres_recovery_root_binding={shlex.quote(root_binding)}",
            f"postgres_recovery_root_mnt_id={root_mnt_id!r}",
            f"proof_nonce={proof_nonce!r}",
            f"proof_label={proof_label!r}",
            create_bridge_source,
            'mapfile -t fields < <(create_postgres_socket_bridge "$proof_label-socket-bridge")',
            'test "${#fields[@]}" = 5',
            'test -d "${fields[0]}"',
            'test "$(stat -c %a "${fields[0]}")" = 1777',
            'test "$(stat -c %a "${fields[0]}/.acgs-postgres-socket-bridge.v2")" = 444',
            'if create_postgres_socket_bridge "$proof_label-socket-bridge"; then exit 90; fi',
        )
    )
    result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    shutil.rmtree(recovery_root / bridge_name)
    (recovery_root / bridge_name).symlink_to(tmp_path)
    symlink_result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input="\n".join(
            (
                "set -euo pipefail",
                f"postgres_recovery_root={str(recovery_root)!r}",
                f"postgres_recovery_root_binding={shlex.quote(root_binding)}",
                f"postgres_recovery_root_mnt_id={root_mnt_id!r}",
                f"proof_nonce={proof_nonce!r}",
                f"proof_label={proof_label!r}",
                create_bridge_source,
                'create_postgres_socket_bridge "$proof_label-socket-bridge"',
            )
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert symlink_result.returncode == 70
    assert (recovery_root / bridge_name).is_symlink()

    (recovery_root / bridge_name).unlink()
    for case_name, binding, mnt_id in (
        ("missing-binding", "", root_mnt_id),
        ("wrong-binding", "acgs-postgres-recovery-root/v2\t1:2:3:700", root_mnt_id),
        ("wrong-mnt", root_binding, "0"),
    ):
        bad_result = subprocess.run(
            ["bash", "-e", "-u", "-o", "pipefail", "-s"],
            input="\n".join(
                (
                    "set -euo pipefail",
                    f"postgres_recovery_root={str(recovery_root)!r}",
                    f"postgres_recovery_root_binding={shlex.quote(binding)}",
                    f"postgres_recovery_root_mnt_id={mnt_id!r}",
                    f"proof_nonce={proof_nonce!r}",
                    f"proof_label={proof_label!r}",
                    create_bridge_source,
                    'create_postgres_socket_bridge "$proof_label-socket-bridge"',
                )
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        assert bad_result.returncode == 70, (case_name, bad_result.stderr)
        assert not (recovery_root / bridge_name).exists()

    for fault_name in (
        "ACGS_POSTGRES_SOCKET_BRIDGE_FAULT_AFTER_MKDIR",
        "ACGS_POSTGRES_SOCKET_BRIDGE_FAULT_AFTER_MARKER_WRITE",
        "ACGS_POSTGRES_SOCKET_BRIDGE_FAULT_AFTER_BRIDGE_FSYNC",
        "ACGS_POSTGRES_SOCKET_BRIDGE_FAULT_AFTER_ROOT_FSYNC",
    ):
        shutil.rmtree(recovery_root)
        recovery_root.mkdir()
        recovery_root.chmod(0o700)
        root_binding = _recovery_root_binding(recovery_root)
        root_mnt_id = _mount_id(recovery_root)
        fault_result = subprocess.run(
            ["bash", "-e", "-u", "-o", "pipefail", "-s"],
            input="\n".join(
                (
                    "set -euo pipefail",
                    f"export {fault_name}=1",
                    f"postgres_recovery_root={str(recovery_root)!r}",
                    f"postgres_recovery_root_binding={shlex.quote(root_binding)}",
                    f"postgres_recovery_root_mnt_id={root_mnt_id!r}",
                    f"proof_nonce={proof_nonce!r}",
                    f"proof_label={proof_label!r}",
                    create_bridge_source,
                    'create_postgres_socket_bridge "$proof_label-socket-bridge"',
                )
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        assert fault_result.returncode != 0, (fault_name, fault_result.stderr)
        assert "socket_bridge_creation_uncertain=1" in fault_result.stderr
        assert (recovery_root / bridge_name).exists(), fault_name

    shutil.rmtree(recovery_root)
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    root_binding = _recovery_root_binding(recovery_root)
    root_mnt_id = _mount_id(recovery_root)
    outside_original = tmp_path / "outside-original"
    outside_result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input="\n".join(
            (
                "set -euo pipefail",
                "export ACGS_POSTGRES_SOCKET_BRIDGE_FAULT_AFTER_MKDIR=1",
                "export "
                f"ACGS_POSTGRES_SOCKET_BRIDGE_MOVE_OUTSIDE_ROOT_INSIDE_MKDIR={str(outside_original)!r}",
                f"postgres_recovery_root={str(recovery_root)!r}",
                f"postgres_recovery_root_binding={shlex.quote(root_binding)}",
                f"postgres_recovery_root_mnt_id={root_mnt_id!r}",
                f"proof_nonce={proof_nonce!r}",
                f"proof_label={proof_label!r}",
                create_bridge_source,
                'create_postgres_socket_bridge "$proof_label-socket-bridge"',
            )
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert outside_result.returncode != 0, outside_result.stderr
    assert "socket_bridge_creation_uncertain=1" in outside_result.stderr
    assert (recovery_root / bridge_name).is_dir()
    assert outside_original.is_dir()

    shutil.rmtree(recovery_root)
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    baseline_child = recovery_root / "baseline-1234abcd"
    baseline_child.mkdir()
    root_binding = _recovery_root_binding(recovery_root)
    root_mnt_id = _mount_id(recovery_root)
    under_baseline_result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input="\n".join(
            (
                "set -euo pipefail",
                "export ACGS_POSTGRES_SOCKET_BRIDGE_FAULT_AFTER_MKDIR=1",
                "export "
                "ACGS_POSTGRES_SOCKET_BRIDGE_MOVE_UNDER_BASELINE_CHILD_INSIDE_MKDIR="
                f"{baseline_child.name!r}",
                f"postgres_recovery_root={str(recovery_root)!r}",
                f"postgres_recovery_root_binding={shlex.quote(root_binding)}",
                f"postgres_recovery_root_mnt_id={root_mnt_id!r}",
                f"proof_nonce={proof_nonce!r}",
                f"proof_label={proof_label!r}",
                create_bridge_source,
                'create_postgres_socket_bridge "$proof_label-socket-bridge"',
            )
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert under_baseline_result.returncode != 0, under_baseline_result.stderr
    assert "socket_bridge_creation_uncertain=1" in under_baseline_result.stderr
    assert (recovery_root / bridge_name).is_dir()
    assert (baseline_child / bridge_name).is_dir()

    shutil.rmtree(recovery_root)
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    baseline_child = recovery_root / "baseline-5678abcd"
    baseline_child.mkdir()
    root_binding = _recovery_root_binding(recovery_root)
    root_mnt_id = _mount_id(recovery_root)
    no_fault_under_baseline_result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input="\n".join(
            (
                "set -euo pipefail",
                "export "
                "ACGS_POSTGRES_SOCKET_BRIDGE_MOVE_UNDER_BASELINE_CHILD_INSIDE_MKDIR="
                f"{baseline_child.name!r}",
                f"postgres_recovery_root={str(recovery_root)!r}",
                f"postgres_recovery_root_binding={shlex.quote(root_binding)}",
                f"postgres_recovery_root_mnt_id={root_mnt_id!r}",
                f"proof_nonce={proof_nonce!r}",
                f"proof_label={proof_label!r}",
                create_bridge_source,
                'create_postgres_socket_bridge "$proof_label-socket-bridge"',
            )
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert no_fault_under_baseline_result.returncode != 0, no_fault_under_baseline_result.stderr
    assert "socket_bridge_creation_uncertain=1" in no_fault_under_baseline_result.stderr
    assert (recovery_root / bridge_name).is_dir()
    assert (baseline_child / bridge_name).is_dir()

    shutil.rmtree(recovery_root)
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    root_binding = _recovery_root_binding(recovery_root)
    root_mnt_id = _mount_id(recovery_root)
    prepopulated_original = tmp_path / "prepopulated-original"
    prepopulated_result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input="\n".join(
            (
                "set -euo pipefail",
                "export ACGS_POSTGRES_SOCKET_BRIDGE_PREPOPULATE_SUBSTITUTE_INSIDE_MKDIR=1",
                "export "
                "ACGS_POSTGRES_SOCKET_BRIDGE_MOVE_OUTSIDE_ROOT_INSIDE_MKDIR="
                f"{str(prepopulated_original)!r}",
                f"postgres_recovery_root={str(recovery_root)!r}",
                f"postgres_recovery_root_binding={shlex.quote(root_binding)}",
                f"postgres_recovery_root_mnt_id={root_mnt_id!r}",
                f"proof_nonce={proof_nonce!r}",
                f"proof_label={proof_label!r}",
                create_bridge_source,
                'create_postgres_socket_bridge "$proof_label-socket-bridge"',
            )
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert prepopulated_result.returncode != 0, prepopulated_result.stderr
    assert "socket_bridge_creation_uncertain=1" in prepopulated_result.stderr
    assert prepopulated_original.is_dir()
    assert (recovery_root / bridge_name / "prepopulated").is_file()

    shutil.rmtree(recovery_root)
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    root_binding = _recovery_root_binding(recovery_root)
    root_mnt_id = _mount_id(recovery_root)
    inside_exchange_name = f"{bridge_name}-exchange"
    inside_exchange_result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input="\n".join(
            (
                "set -euo pipefail",
                "export ACGS_POSTGRES_SOCKET_BRIDGE_FAULT_AFTER_MKDIR=1",
                "export "
                "ACGS_POSTGRES_SOCKET_BRIDGE_EXCHANGE_INSIDE_MKDIR="
                f"{inside_exchange_name!r}",
                f"postgres_recovery_root={str(recovery_root)!r}",
                f"postgres_recovery_root_binding={shlex.quote(root_binding)}",
                f"postgres_recovery_root_mnt_id={root_mnt_id!r}",
                f"proof_nonce={proof_nonce!r}",
                f"proof_label={proof_label!r}",
                create_bridge_source,
                'create_postgres_socket_bridge "$proof_label-socket-bridge"',
            )
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert inside_exchange_result.returncode != 0, inside_exchange_result.stderr
    assert "socket_bridge_creation_uncertain=1" in inside_exchange_result.stderr
    assert (recovery_root / bridge_name).is_dir()
    assert (recovery_root / inside_exchange_name).is_dir()

    shutil.rmtree(recovery_root)
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    root_binding = _recovery_root_binding(recovery_root)
    root_mnt_id = _mount_id(recovery_root)
    exchange_name = f"{bridge_name}-exchange"
    exchange_result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input="\n".join(
            (
                "set -euo pipefail",
                "export ACGS_POSTGRES_SOCKET_BRIDGE_FAULT_AFTER_MKDIR=1",
                f"export ACGS_POSTGRES_SOCKET_BRIDGE_RENAME_EXCHANGE_AFTER_MKDIR={exchange_name!r}",
                f"postgres_recovery_root={str(recovery_root)!r}",
                f"postgres_recovery_root_binding={shlex.quote(root_binding)}",
                f"postgres_recovery_root_mnt_id={root_mnt_id!r}",
                f"proof_nonce={proof_nonce!r}",
                f"proof_label={proof_label!r}",
                create_bridge_source,
                'create_postgres_socket_bridge "$proof_label-socket-bridge"',
            )
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert exchange_result.returncode != 0, exchange_result.stderr
    assert "socket_bridge_creation_uncertain=1" in exchange_result.stderr
    assert (recovery_root / bridge_name).is_dir()
    assert (recovery_root / exchange_name).is_dir()


def test_postgres_gate_socket_bridge_creation_uncertainty_writes_contract(
    tmp_path: Path,
) -> None:
    script = _postgres_gate_script_source()
    create_bridge_source = _extract_shell_function(
        script,
        "create_postgres_socket_bridge",
        "verify_postgres_socket_bridge",
    )
    assert "\nimport time\n" in create_bridge_source
    assert "time.sleep(0.2)" in create_bridge_source
    bind_source = _extract_shell_function(
        script,
        "bind_state_dir_identity",
        "validate_postgres_proof_nonce",
    )
    write_recovery_source = _extract_shell_function(
        script,
        "write_recovery_contract",
        "verify_junit_report",
    )
    state_dir = tmp_path / "state"
    recovery_root = tmp_path / "recovery"
    state_dir.mkdir()
    state_dir.chmod(0o700)
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    proof_nonce = "0123456789abcdef0123456789abcdef"
    proof_label = f"acp-postgres-gate-{os.getuid()}-{proof_nonce}"
    bridge_name = f"{proof_label}-socket-bridge"
    root_binding = _recovery_root_binding(recovery_root)
    root_mnt_id = _mount_id(recovery_root)
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"state_dir={str(state_dir)!r}",
            f"postgres_recovery_root={str(recovery_root)!r}",
            f"postgres_recovery_root_binding={shlex.quote(root_binding)}",
            f"postgres_recovery_root_mnt_id={root_mnt_id!r}",
            f"proof_nonce={proof_nonce!r}",
            f"proof_label={proof_label!r}",
            f"container_name={proof_label + '-server'!r}",
            f"server_cidfile={str(state_dir / 'server.cid')!r}",
            f"postgres_socket_bridge_name={bridge_name!r}",
            "postgres_socket_bridge_identity=''",
            "postgres_socket_bridge_marker_sha256=''",
            "postgres_socket_bridge_mnt_id=''",
            "postgres_socket_bridge_creation_uncertain=0",
            "expected_server_cid=''",
            "recovery_contract_written=0",
            bind_source,
            'exec {state_dir_fd}<"$state_dir"',
            'mapfile -t fields < <(bind_state_dir_identity "$state_dir_fd")',
            'state_dir_parent="${fields[0]}"',
            'state_dir_name="${fields[1]}"',
            'state_dir_identity="${fields[2]}"',
            'state_dir_parent_identity="${fields[3]}"',
            'state_dir_mnt_id="${fields[4]}"',
            'state_dir_parent_mnt_id="${fields[5]}"',
            "export ACGS_POSTGRES_SOCKET_BRIDGE_FAULT_AFTER_MKDIR=1",
            create_bridge_source,
            write_recovery_source,
            'if create_postgres_socket_bridge "$postgres_socket_bridge_name"; then exit 90; fi',
            "postgres_socket_bridge_creation_uncertain=1",
            "write_recovery_contract 70",
        )
    )
    result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    contract = (state_dir / "recovery-contract.env").read_text(encoding="ascii")
    assert "socket_bridge_creation_uncertain=1\n" in contract
    assert f"socket_bridge_basename={bridge_name}\n" in contract
    assert "socket_bridge_identity=\n" in contract
    assert "socket_bridge_marker_sha256=\n" in contract
    assert "socket_bridge_mnt_id=\n" in contract
    assert f"recovery_root_mnt_id={root_mnt_id}\n" in contract
    assert (recovery_root / bridge_name).is_dir()


def _assert_postgres_socket_bridge_block_uncertainty_order(bridge_block: str) -> None:
    set_uncertain_index = bridge_block.index("postgres_socket_bridge_creation_uncertain=1\n")
    create_index = bridge_block.index(
        'postgres_socket_bridge_output="$(create_postgres_socket_bridge '
        '"$postgres_socket_bridge_name")" || {'
    )
    mapfile_index = bridge_block.index(
        'mapfile -t postgres_socket_bridge_fields <<<"$postgres_socket_bridge_output"'
    )
    parse_complete_index = bridge_block.index(
        'postgres_socket_bridge_mnt_id="${postgres_socket_bridge_fields[4]}"'
    )
    verify_index = bridge_block.index("verify_postgres_socket_bridge 1777 || {")
    clear_uncertain = "postgres_socket_bridge_creation_uncertain=0"
    assert bridge_block.count(clear_uncertain) == 1
    clear_uncertain_index = bridge_block.index(clear_uncertain)
    metadata_assignment_indexes = [
        bridge_block.index('postgres_socket_bridge="${postgres_socket_bridge_fields[0]}"'),
        bridge_block.index('postgres_socket_bridge_name="${postgres_socket_bridge_fields[1]}"'),
        bridge_block.index('postgres_socket_bridge_identity="${postgres_socket_bridge_fields[2]}"'),
        bridge_block.index(
            'postgres_socket_bridge_marker_sha256="${postgres_socket_bridge_fields[3]}"'
        ),
        parse_complete_index,
    ]
    assert (
        set_uncertain_index
        < create_index
        < mapfile_index
        < min(metadata_assignment_indexes)
        <= max(metadata_assignment_indexes)
        < verify_index
        < clear_uncertain_index
    )


def test_postgres_gate_socket_bridge_term_after_mkdir_keeps_uncertain_contract(
    tmp_path: Path,
) -> None:
    script = _postgres_gate_script_source()
    create_bridge_source = _extract_shell_function(
        script,
        "create_postgres_socket_bridge",
        "verify_postgres_socket_bridge",
    )
    bind_source = _extract_shell_function(
        script,
        "bind_state_dir_identity",
        "validate_postgres_proof_nonce",
    )
    write_recovery_source = _extract_shell_function(
        script,
        "write_recovery_contract",
        "verify_junit_report",
    )
    cleanup_start = script.index("cleanup() {")
    cleanup_end = script.index("\ntrap cleanup EXIT", cleanup_start)
    cleanup_source = script[cleanup_start:cleanup_end]
    state_dir = tmp_path / "state"
    recovery_root = tmp_path / "recovery"
    state_dir.mkdir()
    state_dir.chmod(0o700)
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    proof_nonce = "0123456789abcdef0123456789abcdef"
    proof_label = f"acp-postgres-gate-{os.getuid()}-{proof_nonce}"
    bridge_name = f"{proof_label}-socket-bridge"
    root_binding = _recovery_root_binding(recovery_root)
    root_mnt_id = _mount_id(recovery_root)
    external_sentinel = tmp_path / "external-sentinel"
    external_sentinel.write_text("outside\n", encoding="ascii")
    bridge_block_start = script.index("postgres_socket_bridge_creation_uncertain=1\n")
    bridge_block_end = script.index(
        "\nwrite_postgres_recovery_intent server-intent server",
        bridge_block_start,
    )
    bridge_block = script[bridge_block_start:bridge_block_end]
    bridge_output_line = (
        'postgres_socket_bridge_output="$(create_postgres_socket_bridge '
        '"$postgres_socket_bridge_name")" || {'
    )
    assert bridge_output_line in bridge_block
    assert "postgres_socket_bridge_create_status=$?" in bridge_block
    assert "verify_postgres_socket_bridge 1777 || {" in bridge_block
    assert bridge_block.rstrip().endswith("postgres_socket_bridge_creation_uncertain=0")
    _assert_postgres_socket_bridge_block_uncertainty_order(bridge_block)
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"state_dir={str(state_dir)!r}",
            f"postgres_recovery_root={str(recovery_root)!r}",
            f"postgres_recovery_root_binding={shlex.quote(root_binding)}",
            f"postgres_recovery_root_mnt_id={root_mnt_id!r}",
            f"proof_nonce={proof_nonce!r}",
            f"proof_label={proof_label!r}",
            f"container_name={proof_label + '-server'!r}",
            f"server_cidfile={str(state_dir / 'server.cid')!r}",
            f"postgres_socket_bridge_name={bridge_name!r}",
            "postgres_socket_bridge=''",
            "postgres_socket_bridge_identity=''",
            "postgres_socket_bridge_marker_sha256=''",
            "postgres_socket_bridge_mnt_id=''",
            "postgres_socket_bridge_creation_uncertain=0",
            "expected_server_cid=''",
            "recovery_contract_written=0",
            "active_uv_fd=''",
            "broker_script_fd=''",
            "pytest_output_fd=''",
            "broker_pid=''",
            "docker_started=0",
            "DOCKER_PS_IDS=()",
            "close_active_uv_fd() { :; }",
            "close_broker_script_fd() { :; }",
            "close_pytest_output_fd() { :; }",
            bind_source,
            'exec {state_dir_fd}<"$state_dir"',
            'mapfile -t fields < <(bind_state_dir_identity "$state_dir_fd")',
            'state_dir_parent="${fields[0]}"',
            'state_dir_name="${fields[1]}"',
            'state_dir_identity="${fields[2]}"',
            'state_dir_parent_identity="${fields[3]}"',
            'state_dir_mnt_id="${fields[4]}"',
            'state_dir_parent_mnt_id="${fields[5]}"',
            create_bridge_source,
            write_recovery_source,
            "cleanup_client_containers() { return 99; }",
            "cleanup_server_container() { return 99; }",
            "verify_stable_no_proof_labelled_containers() { return 99; }",
            "cleanup_postgres_socket_bridge() { return 99; }",
            "unlink_postgres_recovery_intents() { return 0; }",
            "finalize_state_dir_removal() { return 70; }",
            cleanup_source,
            "trap cleanup EXIT",
            "trap 'exit 143' TERM",
            bridge_block,
            "exit 90",
        )
    )
    result = subprocess.run(
        ["bash", "-s"],
        input=harness,
        env={**os.environ, "ACGS_POSTGRES_SOCKET_BRIDGE_SIGNAL_PARENT_AFTER_MKDIR": "1"},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 143, (result.stdout, result.stderr)
    assert "retained recovery state" in result.stderr
    assert external_sentinel.read_text(encoding="ascii") == "outside\n"
    assert (recovery_root / bridge_name).is_dir()
    contract = (state_dir / "recovery-contract.env").read_text(encoding="ascii")
    assert "socket_bridge_creation_uncertain=1\n" in contract
    assert f"socket_bridge_basename={bridge_name}\n" in contract
    assert "socket_bridge_identity=\n" in contract
    assert "socket_bridge_marker_sha256=\n" in contract
    assert "socket_bridge_mnt_id=\n" in contract
    assert f"recovery_root_mnt_id={root_mnt_id}\n" in contract
    assert "external_cleanup_uncertain=1\n" in contract
    assert contract != "\n".join(
        [
            "contract_version=2",
            "schema=acgs-postgres-recovery-contract/v2",
            "external_cleanup_uncertain=1",
            "cleanup_status=70",
            f"proof_nonce={proof_nonce}",
            f"proof_label={proof_label}",
            f"server_name={proof_label}-server",
            "",
        ]
    )


def _run_postgres_recovery_contract_validation(
    tmp_path: Path,
    *,
    shape: str,
    mutation: str = "none",
    authenticated_server_cid: str | None = None,
    cidfile_value: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], str, bool, bool]:
    script = _postgres_gate_script_source()
    read_private_source = _extract_shell_function(
        script,
        "read_private_container_file",
        "write_private_container_name_file",
    )
    bind_source = _extract_shell_function(
        script,
        "bind_state_dir_identity",
        "validate_postgres_proof_nonce",
    )
    write_recovery_source = _extract_shell_function(
        script,
        "write_recovery_contract",
        "verify_junit_report",
    )
    state_dir = tmp_path / f"state-{shape}-{mutation}"
    recovery_root = tmp_path / f"recovery-{shape}-{mutation}"
    state_dir.mkdir()
    state_dir.chmod(0o700)
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    proof_nonce = "0123456789abcdef0123456789abcdef"
    proof_label = f"acp-postgres-gate-{os.getuid()}-{proof_nonce}"
    server_cid = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    trusted_server_cid = authenticated_server_cid
    if trusted_server_cid is None and shape == "full":
        trusted_server_cid = server_cid
    server_cidfile = state_dir / "server.cid"
    bridge_name = ""
    bridge_identity = ""
    bridge_marker_sha256 = ""
    bridge_mnt_id = ""
    root_mnt_id = ""
    bridge_creation_uncertain = "0"
    if shape == "full":
        server_cidfile.write_text(f"{cidfile_value or server_cid}\n", encoding="ascii")
        server_cidfile.chmod(0o600)
        bridge = recovery_root / f"{proof_label}-socket-bridge"
        bridge_name = bridge.name
        bridge_identity, bridge_marker_sha256, bridge_mnt_id = _write_postgres_socket_bridge(
            bridge,
            proof_label,
            proof_nonce,
        )
        root_mnt_id = _mount_id(recovery_root)
    elif shape == "empty":
        pass
    elif shape == "partial-uncertain":
        bridge_name = f"{proof_label}-socket-bridge"
        root_mnt_id = _mount_id(recovery_root)
        bridge_creation_uncertain = "1"
    elif shape == "early-production":
        bridge_name = f"{proof_label}-socket-bridge"
        root_mnt_id = _mount_id(recovery_root)
    else:
        raise AssertionError(f"unknown recovery contract shape: {shape}")
    sentinel = tmp_path / f"validated-{shape}-{mutation}"
    external_sentinel = tmp_path / f"external-side-effect-{shape}-{mutation}"
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"state_dir={str(state_dir)!r}",
            f"proof_nonce={proof_nonce!r}",
            f"proof_label={proof_label!r}",
            f"container_name={proof_label + '-server'!r}",
            f"server_cidfile={str(server_cidfile)!r}",
            f"expected_server_cid={trusted_server_cid or ''!r}",
            "recovery_contract_written=0",
            f"postgres_socket_bridge_name={bridge_name!r}",
            f"postgres_socket_bridge_identity={bridge_identity!r}",
            f"postgres_socket_bridge_marker_sha256={bridge_marker_sha256!r}",
            f"postgres_socket_bridge_mnt_id={bridge_mnt_id!r}",
            f"postgres_recovery_root_mnt_id={root_mnt_id!r}",
            f"postgres_socket_bridge_creation_uncertain={bridge_creation_uncertain!r}",
            read_private_source,
            bind_source,
            'exec {state_dir_fd}<"$state_dir"',
            'mapfile -t fields < <(bind_state_dir_identity "$state_dir_fd")',
            'state_dir_parent="${fields[0]}"',
            'state_dir_name="${fields[1]}"',
            'state_dir_identity="${fields[2]}"',
            'state_dir_parent_identity="${fields[3]}"',
            'state_dir_mnt_id="${fields[4]}"',
            'state_dir_parent_mnt_id="${fields[5]}"',
            write_recovery_source,
            "write_recovery_contract 70",
            f"python3 - {str(state_dir / 'recovery-contract.env')!r} {mutation!r} <<'PY'",
            "from __future__ import annotations",
            "from pathlib import Path",
            "import sys",
            "path = Path(sys.argv[1])",
            "mutation = sys.argv[2]",
            "lines = path.read_text(encoding='ascii').splitlines()",
            "def replace(key: str, value: str) -> None:",
            "    for index, line in enumerate(lines):",
            "        if line.startswith(key + '='):",
            "            lines[index] = f'{key}={value}'",
            "            return",
            "    raise SystemExit(91)",
            "def remove(key: str) -> None:",
            "    original = len(lines)",
            "    lines[:] = [line for line in lines if not line.startswith(key + '=')]",
            "    if len(lines) == original:",
            "        raise SystemExit(92)",
            "if mutation == 'none':",
            "    pass",
            "elif mutation == 'server_cid':",
            "    replace(",
            "        'server_cid',",
            "        'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321',",
            "    )",
            "elif mutation == 'creation_uncertain':",
            "    replace('socket_bridge_creation_uncertain', '0')",
            "elif mutation == 'basename':",
            "    replace(",
            "        'socket_bridge_basename',",
            "        'acp-postgres-gate-999-0123456789abcdef0123456789abcdef-socket-bridge',",
            "    )",
            "elif mutation == 'identity':",
            "    replace('socket_bridge_identity', '9:8:7:1777')",
            "elif mutation == 'marker_sha256':",
            "    replace('socket_bridge_marker_sha256', 'b' * 64)",
            "elif mutation == 'bridge_mnt_id':",
            "    replace('socket_bridge_mnt_id', '43')",
            "elif mutation == 'root_mnt_id':",
            "    replace('recovery_root_mnt_id', '44')",
            "elif mutation == 'unknown':",
            "    lines.append('unexpected=1')",
            "elif mutation == 'missing':",
            "    remove('server_cid')",
            "elif mutation == 'duplicate':",
            "    lines.append(next(line for line in lines if line.startswith('server_cid=')))",
            "elif mutation == 'reordered':",
            "    server_index = next(",
            "        i for i, line in enumerate(lines) if line.startswith('server_cid=')",
            "    )",
            "    bridge_index = next(",
            "        i",
            "        for i, line in enumerate(lines)",
            "        if line.startswith('socket_bridge_basename=')",
            "    )",
            "    lines[server_index], lines[bridge_index] = (",
            "        lines[bridge_index],",
            "        lines[server_index],",
            "    )",
            "else:",
            "    raise SystemExit(93)",
            "path.write_text('\\n'.join(lines) + '\\n', encoding='ascii')",
            "PY",
            "set +e",
            "validate_recovery_contract 70",
            "validate_rc=$?",
            "set -e",
            f'if [[ "$validate_rc" == 0 ]]; then printf validated >{str(sentinel)!r}; fi',
            'printf "VALIDATE_RC=%s\\n" "$validate_rc"',
        )
    )
    result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    contract = (
        (state_dir / "recovery-contract.env").read_text(encoding="ascii")
        if (state_dir / "recovery-contract.env").exists()
        else ""
    )
    return result, contract, sentinel.exists(), external_sentinel.exists()


@pytest.mark.parametrize("shape", ["full", "empty", "partial-uncertain"])
def test_postgres_gate_recovery_contract_validates_exact_optional_shapes(
    tmp_path: Path,
    shape: str,
) -> None:
    result, contract, sentinel_exists, external_sentinel_exists = (
        _run_postgres_recovery_contract_validation(
            tmp_path,
            shape=shape,
        )
    )

    assert result.returncode == 0, (shape, result.stderr)
    assert "VALIDATE_RC=0\n" in result.stdout
    assert sentinel_exists
    assert not external_sentinel_exists
    if shape == "full":
        assert "server_cid=" in contract
        assert "socket_bridge_basename=" in contract
        assert "socket_bridge_identity=" in contract
        assert "socket_bridge_marker_sha256=" in contract
        assert "socket_bridge_mnt_id=" in contract
        assert "recovery_root_mnt_id=" in contract
    elif shape == "empty":
        assert "server_cid=" not in contract
        assert "socket_bridge_" not in contract
        assert "recovery_root_mnt_id=" not in contract
    else:
        assert "socket_bridge_creation_uncertain=1\n" in contract
        assert "socket_bridge_basename=" in contract
        assert "socket_bridge_identity=\n" in contract
        assert "socket_bridge_marker_sha256=\n" in contract
        assert "socket_bridge_mnt_id=\n" in contract


def test_postgres_gate_recovery_contract_accepts_pre_bridge_initialized_shape(
    tmp_path: Path,
) -> None:
    result, contract, sentinel_exists, external_sentinel_exists = (
        _run_postgres_recovery_contract_validation(
            tmp_path,
            shape="early-production",
        )
    )

    assert result.returncode == 0, result.stderr
    assert "VALIDATE_RC=0\n" in result.stdout
    assert sentinel_exists
    assert not external_sentinel_exists
    assert "socket_bridge_" not in contract
    assert "recovery_root_mnt_id=" not in contract
    assert "server_cid=" not in contract
    assert contract == "\n".join(
        [
            "contract_version=2",
            "schema=acgs-postgres-recovery-contract/v2",
            "external_cleanup_uncertain=1",
            "cleanup_status=70",
            "proof_nonce=0123456789abcdef0123456789abcdef",
            f"proof_label=acp-postgres-gate-{os.getuid()}-0123456789abcdef0123456789abcdef",
            f"server_name=acp-postgres-gate-{os.getuid()}-0123456789abcdef0123456789abcdef-server",
            "",
        ]
    )


def test_postgres_gate_recovery_contract_uses_validated_server_id_not_cidfile(
    tmp_path: Path,
) -> None:
    authenticated_id = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    cidfile_id = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
    result, contract, sentinel_exists, external_sentinel_exists = (
        _run_postgres_recovery_contract_validation(
            tmp_path,
            shape="full",
            authenticated_server_cid=authenticated_id,
            cidfile_value=cidfile_id,
        )
    )

    assert result.returncode == 0, result.stderr
    assert "VALIDATE_RC=0\n" in result.stdout
    assert sentinel_exists
    assert not external_sentinel_exists
    assert f"server_cid={authenticated_id}\n" in contract
    assert cidfile_id not in contract


def test_postgres_gate_recovery_contract_omits_unvalidated_tampered_cidfile(
    tmp_path: Path,
) -> None:
    cidfile_id = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
    result, contract, sentinel_exists, external_sentinel_exists = (
        _run_postgres_recovery_contract_validation(
            tmp_path,
            shape="full",
            authenticated_server_cid="",
            cidfile_value=cidfile_id,
        )
    )

    assert result.returncode == 0, result.stderr
    assert "VALIDATE_RC=0\n" in result.stdout
    assert sentinel_exists
    assert not external_sentinel_exists
    assert "server_cid=" not in contract
    assert cidfile_id not in contract


def test_postgres_gate_cleanup_refuses_preexisting_recovery_contract_shortcut(
    tmp_path: Path,
) -> None:
    script = _postgres_gate_script_source()
    bind_source = _extract_shell_function(
        script,
        "bind_state_dir_identity",
        "validate_postgres_proof_nonce",
    )
    write_recovery_source = _extract_shell_function(
        script,
        "write_recovery_contract",
        "verify_junit_report",
    )
    close_active_uv_start = script.index("close_active_uv_fd() {")
    close_active_uv_end = script.index("\n}\n\n# shellcheck disable=SC2016", close_active_uv_start)
    close_sources = script[close_active_uv_start : close_active_uv_end + 3]
    cleanup_start = script.index("cleanup() {")
    cleanup_end = script.index("\ntrap cleanup EXIT", cleanup_start)
    cleanup_source = script[cleanup_start:cleanup_end]
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_dir.chmod(0o700)
    proof_nonce = "0123456789abcdef0123456789abcdef"
    proof_label = f"acp-postgres-gate-{os.getuid()}-{proof_nonce}"
    external_sentinel = tmp_path / "external-sentinel"
    external_sentinel.write_text("external\n", encoding="ascii")
    contract = "\n".join(
        [
            "contract_version=2",
            "schema=acgs-postgres-recovery-contract/v2",
            "external_cleanup_uncertain=1",
            "cleanup_status=70",
            f"proof_nonce={proof_nonce}",
            f"proof_label={proof_label}",
            f"server_name={proof_label}-server",
            "",
        ]
    )
    contract_path = state_dir / "recovery-contract.env"
    contract_path.write_text(contract, encoding="ascii")
    contract_path.chmod(0o600)
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"state_dir={str(state_dir)!r}",
            f"proof_nonce={proof_nonce!r}",
            f"proof_label={proof_label!r}",
            f"container_name={proof_label + '-server'!r}",
            f"server_cidfile={str(state_dir / 'server.cid')!r}",
            "expected_server_cid=''",
            "recovery_contract_written=0",
            "postgres_socket_bridge_name=''",
            "postgres_socket_bridge_identity=''",
            "postgres_socket_bridge_marker_sha256=''",
            "postgres_socket_bridge_mnt_id=''",
            "postgres_recovery_root_mnt_id=''",
            "postgres_socket_bridge_creation_uncertain=0",
            "active_uv_fd=''",
            "broker_script_fd=''",
            "pytest_output_fd=''",
            "broker_pid=''",
            "docker_started=0",
            "postgres_socket_bridge=''",
            bind_source,
            write_recovery_source,
            close_sources,
            'exec {state_dir_fd}<"$state_dir"',
            'mapfile -t fields < <(bind_state_dir_identity "$state_dir_fd")',
            'state_dir_parent="${fields[0]}"',
            'state_dir_name="${fields[1]}"',
            'state_dir_identity="${fields[2]}"',
            'state_dir_parent_identity="${fields[3]}"',
            'state_dir_mnt_id="${fields[4]}"',
            'state_dir_parent_mnt_id="${fields[5]}"',
            "cleanup_client_containers() { return 99; }",
            "cleanup_server_container() { return 99; }",
            "verify_stable_no_proof_labelled_containers() { return 99; }",
            "cleanup_postgres_socket_bridge() { return 99; }",
            "unlink_postgres_recovery_intents() { return 0; }",
            "finalize_state_dir_removal() { return 0; }",
            cleanup_source,
            "cleanup",
        )
    )
    result = subprocess.run(
        ["bash", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 70, result.stderr
    assert "failed to write terminal recovery contract" in result.stderr
    assert contract_path.read_text(encoding="ascii") == contract
    assert external_sentinel.read_text(encoding="ascii") == "external\n"


def test_postgres_gate_socket_bridge_create_marks_uncertain_after_mkdir_exchange_estale(
    tmp_path: Path,
) -> None:
    script = _postgres_gate_script_source()
    create_bridge_source = _extract_shell_function(
        script,
        "create_postgres_socket_bridge",
        "verify_postgres_socket_bridge",
    )
    recovery_root = tmp_path / "recovery"
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    proof_nonce = "0123456789abcdef0123456789abcdef"
    proof_label = f"acp-postgres-gate-{os.getuid()}-{proof_nonce}"
    bridge_name = f"{proof_label}-socket-bridge"
    exchange_name = f"{bridge_name}-exchange"
    root_binding = _recovery_root_binding(recovery_root)
    root_mnt_id = _mount_id(recovery_root)
    result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input="\n".join(
            (
                "set -euo pipefail",
                "export ACGS_POSTGRES_SOCKET_BRIDGE_RENAME_EXCHANGE_ESTALE=1",
                f"export ACGS_POSTGRES_SOCKET_BRIDGE_EXCHANGE_INSIDE_MKDIR={exchange_name!r}",
                f"postgres_recovery_root={str(recovery_root)!r}",
                f"postgres_recovery_root_binding={shlex.quote(root_binding)}",
                f"postgres_recovery_root_mnt_id={root_mnt_id!r}",
                f"proof_nonce={proof_nonce!r}",
                f"proof_label={proof_label!r}",
                create_bridge_source,
                'create_postgres_socket_bridge "$proof_label-socket-bridge"',
            )
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0, result.stderr
    assert "socket_bridge_creation_uncertain=1" in result.stderr
    assert (recovery_root / bridge_name).is_dir()
    assert (recovery_root / exchange_name).is_dir()


def test_postgres_gate_socket_bridge_create_pre_mkdir_failure_has_no_completed_identity(
    tmp_path: Path,
) -> None:
    script = _postgres_gate_script_source()
    create_bridge_source = _extract_shell_function(
        script,
        "create_postgres_socket_bridge",
        "verify_postgres_socket_bridge",
    )
    recovery_root = tmp_path / "recovery"
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    proof_nonce = "0123456789abcdef0123456789abcdef"
    proof_label = f"acp-postgres-gate-{os.getuid()}-{proof_nonce}"
    bridge_name = f"{proof_label}-socket-bridge"
    (recovery_root / bridge_name).mkdir()
    root_binding = _recovery_root_binding(recovery_root)
    root_mnt_id = _mount_id(recovery_root)
    result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input="\n".join(
            (
                "set -euo pipefail",
                f"postgres_recovery_root={str(recovery_root)!r}",
                f"postgres_recovery_root_binding={shlex.quote(root_binding)}",
                f"postgres_recovery_root_mnt_id={root_mnt_id!r}",
                f"proof_nonce={proof_nonce!r}",
                f"proof_label={proof_label!r}",
                create_bridge_source,
                'create_postgres_socket_bridge "$proof_label-socket-bridge"',
            )
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 70, result.stderr
    assert "socket_bridge_creation_uncertain=1" not in result.stderr
    assert "socket_bridge_identity=" not in result.stderr
    assert (recovery_root / bridge_name).is_dir()


def test_postgres_gate_socket_bridge_cleanup_refuses_unknown_files(tmp_path: Path) -> None:
    script = _postgres_gate_script_source()
    create_bridge_source = _extract_shell_function(
        script,
        "create_postgres_socket_bridge",
        "verify_postgres_socket_bridge",
    )
    cleanup_bridge_source = _extract_shell_function(
        script,
        "cleanup_postgres_socket_bridge",
        "unlink_postgres_recovery_intents",
    )
    recovery_root = tmp_path / "recovery"
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    proof_nonce = "0123456789abcdef0123456789abcdef"
    proof_label = f"acp-postgres-gate-{os.getuid()}-{proof_nonce}"
    bridge_name = f"{proof_label}-socket-bridge"
    root_binding = _recovery_root_binding(recovery_root)
    root_mnt_id = _mount_id(recovery_root)
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"postgres_recovery_root={str(recovery_root)!r}",
            f"postgres_recovery_root_binding={shlex.quote(root_binding)}",
            f"postgres_recovery_root_mnt_id={root_mnt_id!r}",
            f"proof_nonce={proof_nonce!r}",
            f"proof_label={proof_label!r}",
            create_bridge_source,
            cleanup_bridge_source,
            'mapfile -t fields < <(create_postgres_socket_bridge "$proof_label-socket-bridge")',
            'postgres_socket_bridge="${fields[0]}"',
            'postgres_socket_bridge_name="${fields[1]}"',
            'postgres_socket_bridge_identity="${fields[2]}"',
            'postgres_socket_bridge_marker_sha256="${fields[3]}"',
            'postgres_socket_bridge_mnt_id="${fields[4]}"',
            'printf unsafe >"$postgres_socket_bridge/unexpected"',
            'if cleanup_postgres_socket_bridge "$(id -u)"; then exit 90; fi',
            'test -e "$postgres_socket_bridge/unexpected"',
            'rm "$postgres_socket_bridge/unexpected"',
            "python3 - \"$postgres_socket_bridge\" <<'PY'",
            "from pathlib import Path",
            "import os",
            "import socket",
            "import sys",
            "bridge = Path(sys.argv[1])",
            "sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)",
            "try:",
            "    os.chdir(bridge)",
            "    sock.bind('.s.PGSQL.5432')",
            "finally:",
            "    sock.close()",
            "(bridge / '.s.PGSQL.5432.lock').write_text('5432\\n', encoding='ascii')",
            "PY",
            'chmod 600 "$postgres_socket_bridge/.s.PGSQL.5432.lock"',
            'if cleanup_postgres_socket_bridge "$(id -u)"; then exit 91; fi',
            'test -S "$postgres_socket_bridge/.s.PGSQL.5432"',
            'test -f "$postgres_socket_bridge/.s.PGSQL.5432.lock"',
            'rm "$postgres_socket_bridge/.s.PGSQL.5432"',
            'rm "$postgres_socket_bridge/.s.PGSQL.5432.lock"',
            'cleanup_postgres_socket_bridge "$(id -u)"',
            f"test ! -e {str(recovery_root / bridge_name)!r}",
        )
    )
    result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("case_name", "setup_lines", "expected_exists"),
    [
        (
            "marker-symlink",
            [
                'rm "$postgres_socket_bridge/.acgs-postgres-socket-bridge.v2"',
                'ln -s /dev/null "$postgres_socket_bridge/.acgs-postgres-socket-bridge.v2"',
            ],
            ".acgs-postgres-socket-bridge.v2",
        ),
        (
            "socket-regular",
            ['printf x >"$postgres_socket_bridge/.s.PGSQL.5432"'],
            ".s.PGSQL.5432",
        ),
        (
            "lock-hardlink",
            [
                'printf 5432 >"$postgres_socket_bridge/.s.PGSQL.5432.lock"',
                (
                    'ln "$postgres_socket_bridge/.s.PGSQL.5432.lock" '
                    '"$postgres_socket_bridge/lock-copy"'
                ),
            ],
            ".s.PGSQL.5432.lock",
        ),
    ],
)
def test_postgres_gate_socket_bridge_cleanup_refuses_artifact_substitution(
    tmp_path: Path,
    case_name: str,
    setup_lines: list[str],
    expected_exists: str,
) -> None:
    script = _postgres_gate_script_source()
    create_bridge_source = _extract_shell_function(
        script,
        "create_postgres_socket_bridge",
        "verify_postgres_socket_bridge",
    )
    cleanup_bridge_source = _extract_shell_function(
        script,
        "cleanup_postgres_socket_bridge",
        "unlink_postgres_recovery_intents",
    )
    recovery_root = tmp_path / "recovery"
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    proof_nonce = "0123456789abcdef0123456789abcdef"
    proof_label = f"acp-postgres-gate-{os.getuid()}-{proof_nonce}"
    root_binding = _recovery_root_binding(recovery_root)
    root_mnt_id = _mount_id(recovery_root)
    harness = "\n".join(
        [
            "set -euo pipefail",
            f"postgres_recovery_root={str(recovery_root)!r}",
            f"postgres_recovery_root_binding={shlex.quote(root_binding)}",
            f"postgres_recovery_root_mnt_id={root_mnt_id!r}",
            f"proof_nonce={proof_nonce!r}",
            f"proof_label={proof_label!r}",
            create_bridge_source,
            cleanup_bridge_source,
            'mapfile -t fields < <(create_postgres_socket_bridge "$proof_label-socket-bridge")',
            'postgres_socket_bridge="${fields[0]}"',
            'postgres_socket_bridge_name="${fields[1]}"',
            'postgres_socket_bridge_identity="${fields[2]}"',
            'postgres_socket_bridge_marker_sha256="${fields[3]}"',
            'postgres_socket_bridge_mnt_id="${fields[4]}"',
            *setup_lines,
            'if cleanup_postgres_socket_bridge "$(id -u)"; then exit 90; fi',
            f'test -e "$postgres_socket_bridge/{expected_exists}"',
        ]
    )
    result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (case_name, result.stderr)


def _run_postgres_socket_bridge_cleanup_fault(
    tmp_path: Path,
    extra_env: dict[str, str],
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    script = _postgres_gate_script_source()
    create_bridge_source = _extract_shell_function(
        script,
        "create_postgres_socket_bridge",
        "verify_postgres_socket_bridge",
    )
    cleanup_bridge_source = _extract_shell_function(
        script,
        "cleanup_postgres_socket_bridge",
        "unlink_postgres_recovery_intents",
    )
    recovery_root = tmp_path / "recovery"
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    proof_nonce = "0123456789abcdef0123456789abcdef"
    proof_label = f"acp-postgres-gate-{os.getuid()}-{proof_nonce}"
    bridge_name = f"{proof_label}-socket-bridge"
    root_binding = _recovery_root_binding(recovery_root)
    root_mnt_id = _mount_id(recovery_root)
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"postgres_recovery_root={str(recovery_root)!r}",
            f"postgres_recovery_root_binding={shlex.quote(root_binding)}",
            f"postgres_recovery_root_mnt_id={root_mnt_id!r}",
            f"proof_nonce={proof_nonce!r}",
            f"proof_label={proof_label!r}",
            create_bridge_source,
            cleanup_bridge_source,
            'mapfile -t fields < <(create_postgres_socket_bridge "$proof_label-socket-bridge")',
            'postgres_socket_bridge="${fields[0]}"',
            'postgres_socket_bridge_name="${fields[1]}"',
            'postgres_socket_bridge_identity="${fields[2]}"',
            'postgres_socket_bridge_marker_sha256="${fields[3]}"',
            'postgres_socket_bridge_mnt_id="${fields[4]}"',
            "set +e",
            'cleanup_postgres_socket_bridge "$(id -u)"',
            "cleanup_rc=$?",
            "set -e",
            'printf "CLEANUP_RC=%s\\n" "$cleanup_rc"',
        )
    )
    result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input=harness,
        env={**os.environ, **extra_env},
        capture_output=True,
        text=True,
        check=False,
    )
    return result, recovery_root, recovery_root / bridge_name


@pytest.mark.parametrize(
    ("case_name", "extra_env", "expected_rc", "bridge_exists", "root_mode"),
    [
        (
            "post-rmdir-estale",
            {"ACGS_POSTGRES_SOCKET_BRIDGE_ESTALE_AFTER_RMDIR": "1"},
            0,
            False,
            0o700,
        ),
        (
            "pre-rmdir-estale",
            {"ACGS_POSTGRES_SOCKET_BRIDGE_ESTALE_BEFORE_RMDIR": "1"},
            1,
            True,
            0o700,
        ),
        (
            "post-rmdir-eio",
            {"ACGS_POSTGRES_SOCKET_BRIDGE_EIO_AFTER_RMDIR": "1"},
            1,
            False,
            0o700,
        ),
        (
            "post-rmdir-estale-name-reappears",
            {
                "ACGS_POSTGRES_SOCKET_BRIDGE_ESTALE_AFTER_RMDIR": "1",
                "ACGS_POSTGRES_SOCKET_BRIDGE_REAPPEAR_AFTER_RMDIR_ESTALE": "1",
            },
            70,
            True,
            0o700,
        ),
        (
            "post-rmdir-estale-parent-binding-drift",
            {
                "ACGS_POSTGRES_SOCKET_BRIDGE_ESTALE_AFTER_RMDIR": "1",
                "ACGS_POSTGRES_SOCKET_BRIDGE_CHMOD_ROOT_AFTER_RMDIR_ESTALE": "1",
            },
            70,
            False,
            0o755,
        ),
    ],
)
def test_postgres_gate_socket_bridge_cleanup_accepts_only_post_rmdir_estale(
    tmp_path: Path,
    case_name: str,
    extra_env: dict[str, str],
    expected_rc: int,
    bridge_exists: bool,
    root_mode: int,
) -> None:
    result, recovery_root, bridge = _run_postgres_socket_bridge_cleanup_fault(tmp_path, extra_env)
    assert result.returncode == 0, (case_name, result.stdout, result.stderr)
    assert f"CLEANUP_RC={expected_rc}\n" in result.stdout, (case_name, result.stdout, result.stderr)
    assert bridge.exists() is bridge_exists
    assert stat.S_IMODE(recovery_root.stat().st_mode) == root_mode
    if case_name == "pre-rmdir-estale":
        assert (bridge / ".acgs-postgres-socket-bridge.v2").is_file()


def test_postgres_gate_recovery_intent_group_deletes_server_and_clients(tmp_path: Path) -> None:
    script = _postgres_gate_script_source()
    unlink_source = _extract_shell_function(
        script,
        "unlink_postgres_recovery_intents",
        "verify_docker_mounts",
    )
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    (state_dir / "client").mkdir()
    recovery_root = tmp_path / "recovery"
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    proof_nonce = "0123456789abcdef0123456789abcdef"
    proof_label = f"acp-postgres-gate-{os.getuid()}-{proof_nonce}"
    server_name = f"{proof_label}-server"
    server_cidfile = state_dir / "server.cid"
    server_namefile = state_dir / "server.name"
    bridge_name = f"{proof_label}-socket-bridge"
    bridge_identity = "1:2:3:1777"
    bridge_sha = "a" * 64
    bridge_mnt = "42"
    server_payload = "\n".join(
        (
            "intent_version=2",
            "schema=acgs-postgres-recovery-intent/server/v2",
            "phase=server-intent",
            f"proof_nonce={proof_nonce}",
            f"proof_label={proof_label}",
            f"server_name={server_name}",
            f"record_path={server_namefile}",
            f"server_cidfile={server_cidfile}",
            f"server_namefile={server_namefile}",
            f"socket_bridge_basename={bridge_name}",
            f"socket_bridge_identity={bridge_identity}",
            f"socket_bridge_marker_sha256={bridge_sha}",
            f"socket_bridge_mnt_id={bridge_mnt}",
            "",
        )
    )
    client_name = f"{proof_label}-client-123-1"
    client_cidfile = state_dir / "client" / f"{client_name}.cid"
    client_namefile = state_dir / "client" / f"{client_name}.name"
    exchange_basename = f"{client_name}-exchange"
    exchange_identity = "4:5:6:700"
    exchange_sha = "b" * 64
    exchange_mnt = "42"
    client_payload = "\n".join(
        (
            "intent_version=2",
            "schema=acgs-postgres-recovery-intent/client/v2",
            "phase=client-intent",
            f"proof_nonce={proof_nonce}",
            f"proof_label={proof_label}",
            f"server_name={server_name}",
            f"client_name={client_name}",
            f"record_path={client_namefile}",
            f"client_cidfile={client_cidfile}",
            f"client_namefile={client_namefile}",
            f"exchange_basename={exchange_basename}",
            f"exchange_identity={exchange_identity}",
            f"exchange_marker_sha256={exchange_sha}",
            f"exchange_mnt_id={exchange_mnt}",
            "",
        )
    )
    (recovery_root / f"{proof_label}-server.intent").write_text(server_payload, encoding="ascii")
    (recovery_root / f"{client_name}.intent").write_text(client_payload, encoding="ascii")
    for path in recovery_root.iterdir():
        path.chmod(0o600)
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"postgres_recovery_root={str(recovery_root)!r}",
            f"state_dir={str(state_dir)!r}",
            f"proof_label={proof_label!r}",
            f"container_name={server_name!r}",
            f"server_cidfile={str(server_cidfile)!r}",
            f"server_namefile={str(server_namefile)!r}",
            f"postgres_socket_bridge_name={bridge_name!r}",
            f"postgres_socket_bridge_identity={bridge_identity!r}",
            f"postgres_socket_bridge_marker_sha256={bridge_sha!r}",
            f"postgres_socket_bridge_mnt_id={bridge_mnt!r}",
            unlink_source,
            "unlink_postgres_recovery_intents",
            f"test ! -e {str(recovery_root / f'{proof_label}-server.intent')!r}",
            f"test ! -e {str(recovery_root / f'{client_name}.intent')!r}",
        )
    )
    result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "case_name",
    [
        "server-extra",
        "server-missing",
        "server-duplicate",
        "server-name-derived-path",
        "client-wrong-record-path",
        "client-leftover-exchange",
    ],
)
def test_postgres_gate_recovery_intent_strict_contract_refuses_mutation(
    tmp_path: Path,
    case_name: str,
) -> None:
    script = _postgres_gate_script_source()
    unlink_source = _extract_shell_function(
        script,
        "unlink_postgres_recovery_intents",
        "verify_docker_mounts",
    )
    state_dir = tmp_path / "state"
    client_dir = state_dir / "client"
    recovery_root = tmp_path / "recovery"
    client_dir.mkdir(parents=True)
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    proof_nonce = "0123456789abcdef0123456789abcdef"
    proof_label = f"acp-postgres-gate-{os.getuid()}-{proof_nonce}"
    server_name = f"{proof_label}-server"
    server_cidfile = state_dir / "server.cid"
    server_namefile = state_dir / "server.name"
    bridge_name = f"{proof_label}-socket-bridge"
    bridge_identity = "1:2:3:1777"
    bridge_sha = "a" * 64
    bridge_mnt = "42"
    server_pairs = [
        ("intent_version", "2"),
        ("schema", "acgs-postgres-recovery-intent/server/v2"),
        ("phase", "server-intent"),
        ("proof_nonce", proof_nonce),
        ("proof_label", proof_label),
        ("server_name", server_name),
        ("record_path", str(server_namefile)),
        ("server_cidfile", str(server_cidfile)),
        ("server_namefile", str(server_namefile)),
        ("socket_bridge_basename", bridge_name),
        ("socket_bridge_identity", bridge_identity),
        ("socket_bridge_marker_sha256", bridge_sha),
        ("socket_bridge_mnt_id", bridge_mnt),
    ]
    client_name = f"{proof_label}-client-123-1"
    client_cidfile = client_dir / f"{client_name}.cid"
    client_namefile = client_dir / f"{client_name}.name"
    exchange_basename = f"{client_name}-exchange"
    client_pairs = [
        ("intent_version", "2"),
        ("schema", "acgs-postgres-recovery-intent/client/v2"),
        ("phase", "client-intent"),
        ("proof_nonce", proof_nonce),
        ("proof_label", proof_label),
        ("server_name", server_name),
        ("client_name", client_name),
        ("record_path", str(client_namefile)),
        ("client_cidfile", str(client_cidfile)),
        ("client_namefile", str(client_namefile)),
        ("exchange_basename", exchange_basename),
        ("exchange_identity", "4:5:6:700"),
        ("exchange_marker_sha256", "b" * 64),
        ("exchange_mnt_id", "42"),
    ]
    if case_name == "server-extra":
        server_pairs.append(("unexpected", "1"))
    elif case_name == "server-missing":
        server_pairs.pop(1)
    elif case_name == "server-duplicate":
        server_pairs.append(("proof_label", proof_label))
    elif case_name == "server-name-derived-path":
        server_pairs[7] = ("server_cidfile", str(state_dir / f"{server_name}.cid"))
    elif case_name == "client-wrong-record-path":
        client_pairs[7] = ("record_path", str(tmp_path / "outside.name"))
    elif case_name == "client-leftover-exchange":
        leftover_exchange = recovery_root / exchange_basename
        leftover_exchange.mkdir()
        leftover_exchange.chmod(0o700)
    server_payload = "\n".join(f"{key}={value}" for key, value in server_pairs) + "\n"
    client_payload = "\n".join(f"{key}={value}" for key, value in client_pairs) + "\n"
    server_intent = recovery_root / f"{proof_label}-server.intent"
    client_intent = recovery_root / f"{client_name}.intent"
    server_intent.write_text(server_payload, encoding="ascii")
    client_intent.write_text(client_payload, encoding="ascii")
    server_intent.chmod(0o600)
    client_intent.chmod(0o600)
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"postgres_recovery_root={str(recovery_root)!r}",
            f"state_dir={str(state_dir)!r}",
            f"proof_label={proof_label!r}",
            f"container_name={server_name!r}",
            f"server_cidfile={str(server_cidfile)!r}",
            f"server_namefile={str(server_namefile)!r}",
            f"postgres_socket_bridge_name={bridge_name!r}",
            f"postgres_socket_bridge_identity={bridge_identity!r}",
            f"postgres_socket_bridge_marker_sha256={bridge_sha!r}",
            f"postgres_socket_bridge_mnt_id={bridge_mnt!r}",
            unlink_source,
            "if unlink_postgres_recovery_intents; then exit 90; fi",
            f"test -e {str(server_intent)!r}",
            f"test -e {str(client_intent)!r}",
        )
    )
    result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (case_name, result.stderr)


@pytest.mark.parametrize(
    ("case_name", "mode", "expected_rc"),
    [
        ("exact", None, 0),
        ("reordered-tmpfs-options", "reordered-tmpfs-options", 0),
        ("tmpfs-fabricated-in-mounts", "tmpfs-fabricated-in-mounts", 70),
        ("missing-tmpfs", "missing-tmpfs", 70),
        ("extra-tmpfs", "extra-tmpfs", 70),
        ("wrong-tmpfs-option", "wrong-tmpfs-option", 70),
        ("duplicate-tmpfs-option", "duplicate-tmpfs-option", 70),
        ("tmpfs-flag-assigned", "tmpfs-flag-assigned", 70),
        ("tmpfs-assignment-missing", "tmpfs-assignment-missing", 70),
        ("tmpfs-assignment-empty", "tmpfs-assignment-empty", 70),
        ("tmpfs-unsupported-key", "tmpfs-unsupported-key", 70),
        ("wrong-bind-type", "wrong-bind-type", 70),
        ("wrong-bind-source", "wrong-bind-source", 70),
        ("wrong-bind-rw", "wrong-bind-rw", 70),
        ("wrong-bind-propagation", "wrong-bind-propagation", 70),
        ("extra-bind", "extra-bind", 70),
        ("duplicate-bind-destination", "duplicate-bind-destination", 70),
        ("malformed-inspect", "malformed-inspect", 70),
        ("null-hostconfig", "null-hostconfig", 70),
        ("oversized-inspect", "oversized-inspect", 70),
        ("duplicate-json-top", "duplicate-json-top", 70),
        ("duplicate-json-nested", "duplicate-json-nested", 70),
        ("duplicate-json-bind-field", "duplicate-json-bind-field", 70),
        ("duplicate-json-tmpfs-destination", "duplicate-json-tmpfs-destination", 70),
        ("inspect-failure", "inspect-failure", 66),
    ],
)
def test_postgres_gate_server_mount_verifier_requires_exact_type_source_rw(
    tmp_path: Path,
    case_name: str,
    mode: str | None,
    expected_rc: int,
) -> None:
    script = _postgres_gate_script_source()
    verify_source = _extract_shell_function(
        script,
        "verify_docker_mounts",
        "verify_server_socket_bridge_marker",
    )
    socket_bridge = tmp_path / "bridge"
    socket_bridge.mkdir()
    snapshot = {
        "Mounts": [
            {
                "Type": "bind",
                "Source": str(socket_bridge),
                "Destination": "/var/run/postgresql",
                "RW": True,
                "Mode": "",
                "Propagation": "rprivate",
            },
        ],
        "HostConfig": {
            "Tmpfs": {
                "/var/lib/postgresql/data": (
                    "rw,noexec,nosuid,nodev,size=2g,uid=999,gid=999,mode=700"
                ),
                "/tmp": "rw,noexec,nosuid,nodev,size=2g,mode=1777",
            },
        },
    }
    if mode == "reordered-tmpfs-options":
        snapshot["HostConfig"]["Tmpfs"]["/tmp"] = "mode=1777,size=2g,nodev,nosuid,noexec,rw"
    elif mode == "tmpfs-fabricated-in-mounts":
        snapshot["Mounts"].append(
            {
                "Type": "tmpfs",
                "Source": "",
                "Destination": "/tmp",
                "RW": True,
                "Mode": "",
                "Propagation": "",
            }
        )
    elif mode == "missing-tmpfs":
        del snapshot["HostConfig"]["Tmpfs"]["/tmp"]
    elif mode == "extra-tmpfs":
        snapshot["HostConfig"]["Tmpfs"]["/run"] = "rw,noexec,nosuid,nodev,size=64m,mode=755"
    elif mode == "wrong-tmpfs-option":
        snapshot["HostConfig"]["Tmpfs"]["/tmp"] = "rw,exec,nosuid,nodev,size=2g,mode=1777"
    elif mode == "duplicate-tmpfs-option":
        snapshot["HostConfig"]["Tmpfs"]["/tmp"] = "rw,rw,noexec,nosuid,nodev,size=2g,mode=1777"
    elif mode == "tmpfs-flag-assigned":
        snapshot["HostConfig"]["Tmpfs"]["/tmp"] = "rw=true,noexec,nosuid,nodev,size=2g,mode=1777"
    elif mode == "tmpfs-assignment-missing":
        snapshot["HostConfig"]["Tmpfs"]["/tmp"] = "rw,noexec,nosuid,nodev,size,mode=1777"
    elif mode == "tmpfs-assignment-empty":
        snapshot["HostConfig"]["Tmpfs"]["/tmp"] = "rw,noexec,nosuid,nodev,size=,mode=1777"
    elif mode == "tmpfs-unsupported-key":
        snapshot["HostConfig"]["Tmpfs"]["/tmp"] = "rw,noexec,nosuid,nodev,size=2g,mode=1777,foo=bar"
    elif mode == "wrong-bind-type":
        snapshot["Mounts"][0] = {**snapshot["Mounts"][0], "Type": "volume"}
    elif mode == "wrong-bind-source":
        snapshot["Mounts"][0] = {**snapshot["Mounts"][0], "Source": "/tmp/wrong"}
    elif mode == "wrong-bind-rw":
        snapshot["Mounts"][0] = {**snapshot["Mounts"][0], "RW": False}
    elif mode == "wrong-bind-propagation":
        snapshot["Mounts"][0] = {**snapshot["Mounts"][0], "Propagation": "rshared"}
    elif mode == "extra-bind":
        snapshot["Mounts"].append(
            {
                "Type": "bind",
                "Source": "/tmp/extra",
                "Destination": "/extra",
                "RW": True,
                "Mode": "",
                "Propagation": "rprivate",
            }
        )
    elif mode == "duplicate-bind-destination":
        snapshot["Mounts"].append(dict(snapshot["Mounts"][0]))
    elif mode == "null-hostconfig":
        snapshot["HostConfig"] = None
    expected = {
        "binds": {
            "/var/run/postgresql": {
                "source": str(socket_bridge),
                "rw": True,
                "mode": "",
                "propagation": "rprivate",
            },
        },
        "tmpfs": {
            "/var/lib/postgresql/data": ("rw,noexec,nosuid,nodev,size=2g,uid=999,gid=999,mode=700"),
            "/tmp": "rw,noexec,nosuid,nodev,size=2g,mode=1777",
        },
    }
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    docker_path = fake_bin / "docker"
    docker_path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "import json, sys",
                f"snapshot = json.loads({json.dumps(snapshot)!r})",
                f"mode = {mode!r}",
                "if sys.argv[1:3] == ['inspect', '--format']:",
                "    if mode == 'inspect-failure':",
                "        raise SystemExit(66)",
                "    if mode == 'malformed-inspect':",
                "        print('{')",
                "        raise SystemExit(0)",
                "    if mode == 'oversized-inspect':",
                "        print('x' * 70000)",
                "        raise SystemExit(0)",
                "    if mode == 'duplicate-json-top':",
                '        print(\'{"Mounts":[],"Mounts":[],"HostConfig":{"Tmpfs":{}}}\')',
                "        raise SystemExit(0)",
                "    if mode == 'duplicate-json-nested':",
                '        print(\'{"Mounts":[],"HostConfig":{"Tmpfs":{},"Tmpfs":{}}}\')',
                "        raise SystemExit(0)",
                "    if mode == 'duplicate-json-bind-field':",
                "        print(",
                '            \'{"Mounts":[{"Type":"bind","Type":"bind",\'',
                '            \'"Source":"/tmp/x","Destination":"/var/run/postgresql",\'',
                '            \'"RW":true,"Mode":"","Propagation":"rprivate"}],\'',
                '            \'"HostConfig":{"Tmpfs":{\'',
                "            '\"/var/lib/postgresql/data\":'",
                "            '\"rw,noexec,nosuid,nodev,size=2g,uid=999,gid=999,mode=700\",'",
                '            \'"/tmp":"rw,noexec,nosuid,nodev,size=2g,mode=1777"}}}\'',
                "        )",
                "        raise SystemExit(0)",
                "    if mode == 'duplicate-json-tmpfs-destination':",
                "        print(",
                '            \'{"Mounts":[],"HostConfig":{"Tmpfs":{\'',
                '            \'"/tmp":"rw,noexec,nosuid,nodev,size=2g,mode=1777",\'',
                '            \'"/tmp":"rw,noexec,nosuid,nodev,size=2g,mode=1777"}}}\'',
                "        )",
                "        raise SystemExit(0)",
                "    print(json.dumps(snapshot, separators=(',', ':')))",
                "    raise SystemExit(0)",
                "raise SystemExit(127)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    docker_path.chmod(0o755)
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"PATH={str(fake_bin)!r}:$PATH",
            verify_source,
            "verify_docker_mounts container "
            f"{shlex.quote(json.dumps(expected, separators=(',', ':')))}",
        )
    )
    result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == expected_rc, (case_name, result.stderr)


def test_postgres_gate_recovery_intent_keeps_server_and_client_v2_contracts() -> None:
    script = _postgres_gate_script_source()
    broker_source, _client_source = _postgres_gate_client_sources()

    assert "intent_version=2" in script
    assert "schema=acgs-postgres-recovery-intent/server/v2" in script
    assert "socket_bridge_basename=" in script
    assert "socket_bridge_identity=" in script
    assert "socket_bridge_marker_sha256=" in script
    assert "socket_bridge_mnt_id=" in script
    assert "schema=acgs-postgres-recovery-intent/client/v2" in broker_source
    assert "exchange_basename=" in broker_source
    assert "exchange_identity=" in broker_source
    assert "exchange_marker_sha256=" in broker_source
    assert "exchange_mnt_id=" in broker_source
    client_payload = broker_source.split("def write_client_recovery_intent", 1)[1].split(
        "\ndef execute", 1
    )[0]
    assert "socket_bridge_" not in client_payload


def test_postgres_gate_cleanup_preserves_bridge_until_docker_absence_is_stable() -> None:
    script = _postgres_gate_script_source()
    start = script.index("cleanup() {")
    end = script.index("\ntrap cleanup EXIT", start)
    cleanup_source = script[start:end]

    assert "local cleanup_safe=1" in cleanup_source
    assert 'if [[ "$docker_started" == 1 ]]; then' in cleanup_source
    assert "verify_stable_no_proof_labelled_containers" in cleanup_source
    assert "cleanup_safe=0" in cleanup_source
    assert 'if [[ "$cleanup_safe" == 1 && -n "$postgres_socket_bridge" ]]; then' in (cleanup_source)
    assert cleanup_source.index("cleanup_client_containers") < cleanup_source.index(
        "cleanup_postgres_socket_bridge"
    )
    assert cleanup_source.index("cleanup_server_container") < cleanup_source.index(
        "cleanup_postgres_socket_bridge"
    )
    assert cleanup_source.index("verify_stable_no_proof_labelled_containers") < (
        cleanup_source.index("cleanup_postgres_socket_bridge")
    )
    assert cleanup_source.index("cleanup_postgres_socket_bridge") < cleanup_source.index(
        "unlink_postgres_recovery_intents"
    )
    assert "write_recovery_contract" in cleanup_source


def test_postgres_gate_duplicate_cleanup_inspect_absence_is_quiet_and_fail_closed(
    tmp_path: Path,
) -> None:
    script = _postgres_gate_script_source()
    remove_exact_source = _extract_shell_function(
        script,
        "validate_exact_recorded_container",
        "cleanup_server_container",
    )
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    docker_path = fake_bin / "docker"
    docker_path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "import sys",
                "args = sys.argv[1:]",
                "if args[:1] == ['inspect'] and '--format' in args:",
                "    print('Error: No such object: duplicate-client', file=sys.stderr)",
                "    raise SystemExit(1)",
                "raise SystemExit(127)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    docker_path.chmod(0o755)
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"PATH={str(fake_bin)!r}:$PATH",
            "proof_label='acp-postgres-gate-1000-0123456789abcdef0123456789abcdef'",
            remove_exact_source,
            "if remove_exact_recorded_container duplicate-client "
            "acp-postgres-gate-1000-0123456789abcdef0123456789abcdef-client-1-1 "
            "trusted-broker; then",
            "  exit 90",
            "else",
            "  rc=$?",
            "fi",
            'test "$rc" -eq 1',
        )
    )
    result = subprocess.run(
        ["bash", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stderr == ""


@pytest.mark.parametrize(
    ("mode", "container_ref", "expected_role", "expected_rc", "rm_expected", "signal_expected"),
    [
        ("exact-trusted-broker", "trusted-client", "trusted-broker", 0, True, False),
        ("exact-main-running", "main-server", "main", 0, True, True),
        ("exact-main-created", "main-server", "main", 0, True, False),
        ("exact-main-exited", "main-server", "main", 0, True, False),
        ("trusted-created", "trusted-client", "trusted-broker", 0, True, False),
        ("trusted-exited", "trusted-client", "trusted-broker", 0, True, False),
        ("trusted-with-server-label", "trusted-client", "trusted-broker", 70, False, False),
        ("main-with-client-label", "main-server", "main", 70, False, False),
        ("trusted-missing-role", "trusted-client", "trusted-broker", 70, False, False),
        ("main-missing-role", "main-server", "main", 70, False, False),
        ("trusted-empty-server-label", "trusted-client", "trusted-broker", 70, False, False),
        ("main-empty-client-label", "main-server", "main", 70, False, False),
        ("proof-terminal-lf", "trusted-client", "trusted-broker", 70, False, False),
        ("proof-multiple-lf", "trusted-client", "trusted-broker", 70, False, False),
        ("proof-terminal-space", "trusted-client", "trusted-broker", 70, False, False),
        ("proof-terminal-tab", "trusted-client", "trusted-broker", 70, False, False),
        ("client-terminal-lf", "trusted-client", "trusted-broker", 70, False, False),
        ("client-multiple-lf", "trusted-client", "trusted-broker", 70, False, False),
        ("client-terminal-space", "trusted-client", "trusted-broker", 70, False, False),
        ("client-terminal-tab", "trusted-client", "trusted-broker", 70, False, False),
        ("main-client-terminal-lf", "main-server", "main", 70, False, False),
        ("main-client-multiple-lf", "main-server", "main", 70, False, False),
        ("main-client-terminal-space", "main-server", "main", 70, False, False),
        ("main-client-terminal-tab", "main-server", "main", 70, False, False),
        ("malformed-json", "trusted-client", "trusted-broker", 70, False, False),
        ("extra-json", "trusted-client", "trusted-broker", 70, False, False),
        ("oversize-json", "trusted-client", "trusted-broker", 70, False, False),
        ("wrong-name", "trusted-client", "trusted-broker", 70, False, False),
        ("restart-always", "trusted-client", "trusted-broker", 70, False, False),
        ("trusted-paused", "trusted-client", "trusted-broker", 70, False, False),
        ("trusted-restarting", "trusted-client", "trusted-broker", 70, False, False),
        ("trusted-removing", "trusted-client", "trusted-broker", 70, False, False),
        ("trusted-dead", "trusted-client", "trusted-broker", 70, False, False),
        ("main-paused", "main-server", "main", 70, False, False),
        ("main-restarting", "main-server", "main", 70, False, False),
        ("main-removing", "main-server", "main", 70, False, False),
        ("main-dead", "main-server", "main", 70, False, False),
        ("main-running-flag-false", "main-server", "main", 70, False, False),
        ("main-created-running-true", "main-server", "main", 70, False, False),
        ("main-exited-running-true", "main-server", "main", 70, False, False),
        ("main-exited-oom", "main-server", "main", 70, False, False),
        ("main-exited-nonzero", "main-server", "main", 70, False, False),
        ("signal-rc2", "main-server", "main", 2, False, True),
        ("signal-rc143", "main-server", "main", 143, False, True),
        ("post-signal-running", "main-server", "main", 70, False, True),
        ("post-signal-disappeared", "main-server", "main", 70, False, True),
        ("post-signal-restarting", "main-server", "main", 70, False, True),
        ("post-signal-identity-mismatch", "main-server", "main", 70, False, True),
        ("post-signal-restart-always", "main-server", "main", 70, False, True),
        ("post-signal-oom", "main-server", "main", 70, False, True),
        ("post-signal-nonzero-exit", "main-server", "main", 70, False, True),
        ("main-nonforce-rm-failure", "main-server", "main", 2, True, True),
        (
            "wrong-id",
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "trusted-broker",
            70,
            False,
            False,
        ),
        ("short-hex-ref", "abcdef123456", "trusted-broker", 70, False, False),
        (
            "sixty-three-hex-ref",
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789",
            "trusted-broker",
            70,
            False,
            False,
        ),
        (
            "sixty-five-hex-ref",
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678901",
            "trusted-broker",
            70,
            False,
            False,
        ),
        (
            "uppercase-id-ref",
            "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890",
            "trusted-broker",
            70,
            False,
            False,
        ),
        ("post-rm-eventual-absence", "trusted-client", "trusted-broker", 0, True, False),
        ("post-rm-nonabsence", "trusted-client", "trusted-broker", 70, True, False),
        ("post-rm-rc2", "trusted-client", "trusted-broker", 2, True, False),
        ("post-rm-timeout", "trusted-client", "trusted-broker", 124, True, False),
    ],
)
def test_postgres_gate_remove_exact_recorded_container_strict_identity_matrix(
    tmp_path: Path,
    mode: str,
    container_ref: str,
    expected_role: str,
    expected_rc: int,
    rm_expected: bool,
    signal_expected: bool,
) -> None:
    script = _postgres_gate_script_source()
    remove_exact_source = _extract_shell_function(
        script,
        "validate_exact_recorded_container",
        "cleanup_server_container",
    )
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    rm_marker = tmp_path / "rm-called"
    signal_marker = tmp_path / "signal-called"
    command_log = tmp_path / "docker-commands.log"
    post_rm_inspect_count = tmp_path / "post-rm-inspect-count"
    signal_inspect_count = tmp_path / "signal-inspect-count"
    trusted_name = "acp-postgres-gate-1000-0123456789abcdef0123456789abcdef-client-1-1"
    main_name = "acp-postgres-gate-1000-0123456789abcdef0123456789abcdef-server"
    trusted_id = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    main_id = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    docker_path = fake_bin / "docker"
    sleep_path = fake_bin / "sleep"
    docker_path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "from pathlib import Path",
                "import json",
                "import sys",
                "args = sys.argv[1:]",
                f"mode = {mode!r}",
                f"rm_marker = Path({str(rm_marker)!r})",
                f"signal_marker = Path({str(signal_marker)!r})",
                f"command_log = Path({str(command_log)!r})",
                f"post_rm_inspect_count = Path({str(post_rm_inspect_count)!r})",
                f"signal_inspect_count = Path({str(signal_inspect_count)!r})",
                f"trusted_id = {trusted_id!r}",
                f"main_id = {main_id!r}",
                f"trusted_name = {trusted_name!r}",
                f"main_name = {main_name!r}",
                "proof = 'acp-postgres-gate-1000-0123456789abcdef0123456789abcdef'",
                "if command_log.exists():",
                "    previous_log = command_log.read_text(encoding='ascii')",
                "else:",
                "    previous_log = ''",
                "command_log.write_text(previous_log + ' '.join(args) + '\\n', encoding='ascii')",
                "if args[:1] == ['inspect'] and '--format' in args:",
                "    if mode == 'malformed-json':",
                "        print('malformed-inspect-record')",
                "        raise SystemExit(0)",
                "    if mode == 'oversize-json':",
                "        sys.stdout.write('[' + (' ' * 8193) + ']')",
                "        raise SystemExit(0)",
                "    is_main = (",
                "        mode.startswith('main')",
                "        or mode.startswith('exact-main')",
                "        or mode.startswith('signal-')",
                "        or mode.startswith('post-signal')",
                "    )",
                "    if signal_marker.exists():",
                "        signal_count = 1",
                "        if signal_inspect_count.exists():",
                "            previous_count = signal_inspect_count.read_text(encoding='ascii')",
                "            signal_count = int(previous_count) + 1",
                "        signal_inspect_count.write_text(",
                "            str(signal_count) + '\\n',",
                "            encoding='ascii',",
                "        )",
                "    else:",
                "        signal_count = 0",
                "    if mode == 'post-signal-disappeared' and signal_marker.exists():",
                "        raise SystemExit(1)",
                "    container_id = main_id if is_main else trusted_id",
                "    name = (",
                "        main_name",
                "        if is_main",
                "        else trusted_name",
                "    )",
                "    if mode == 'wrong-id':",
                "        container_id = (",
                "            'fedcba0987654321fedcba0987654321'",
                "            'fedcba0987654321fedcba0987654321'",
                "        )",
                "    if mode == 'post-signal-identity-mismatch' and signal_marker.exists():",
                "        container_id = trusted_id",
                "    if mode == 'wrong-name':",
                "        name = 'unexpected-client-name'",
                "    labels = {'acgs.postgres.proof': proof}",
                "    if is_main:",
                "        labels['acgs.postgres.server'] = 'main'",
                "    else:",
                "        labels['acgs.postgres.client'] = 'trusted-broker'",
                "    if mode == 'trusted-with-server-label':",
                "        labels['acgs.postgres.server'] = 'main'",
                "    elif mode == 'main-with-client-label':",
                "        labels['acgs.postgres.client'] = 'trusted-broker'",
                "    elif mode == 'trusted-missing-role':",
                "        labels.pop('acgs.postgres.client', None)",
                "    elif mode == 'main-missing-role':",
                "        labels.pop('acgs.postgres.server', None)",
                "    elif mode == 'trusted-empty-server-label':",
                "        labels['acgs.postgres.server'] = ''",
                "    elif mode == 'main-empty-client-label':",
                "        labels['acgs.postgres.client'] = ''",
                "    elif mode.startswith('main-client-'):",
                "        labels['acgs.postgres.client'] = ''",
                "    if mode == 'proof-terminal-lf':",
                "        labels['acgs.postgres.proof'] = proof + '\\n'",
                "    elif mode == 'proof-multiple-lf':",
                "        labels['acgs.postgres.proof'] = proof + '\\nspoof'",
                "    elif mode == 'proof-terminal-space':",
                "        labels['acgs.postgres.proof'] = proof + ' '",
                "    elif mode == 'proof-terminal-tab':",
                "        labels['acgs.postgres.proof'] = proof + '\\t'",
                "    client_value = labels.get('acgs.postgres.client', '')",
                "    if mode in {'client-terminal-lf', 'main-client-terminal-lf'}:",
                "        labels['acgs.postgres.client'] = client_value + '\\n'",
                "    elif mode in {'client-multiple-lf', 'main-client-multiple-lf'}:",
                "        labels['acgs.postgres.client'] = client_value + '\\nspoof'",
                "    elif mode in {'client-terminal-space', 'main-client-terminal-space'}:",
                "        labels['acgs.postgres.client'] = client_value + ' '",
                "    elif mode in {'client-terminal-tab', 'main-client-terminal-tab'}:",
                "        labels['acgs.postgres.client'] = client_value + '\\t'",
                "    state = 'running'",
                "    if mode.endswith('-created'):",
                "        state = 'created'",
                "    elif mode.endswith('-exited'):",
                "        state = 'exited'",
                "    elif mode.endswith('-paused'):",
                "        state = 'paused'",
                "    elif mode.endswith('-restarting'):",
                "        state = 'restarting'",
                "    elif mode.endswith('-removing'):",
                "        state = 'removing'",
                "    elif mode.endswith('-dead'):",
                "        state = 'dead'",
                "    if mode == 'main-created-running-true':",
                "        state = 'created'",
                "    elif mode in {",
                "        'main-exited-running-true',",
                "        'main-exited-oom',",
                "        'main-exited-nonzero',",
                "    }:",
                "        state = 'exited'",
                "    if mode.startswith('post-signal') and not signal_marker.exists():",
                "        state = 'running'",
                "    if signal_marker.exists() and mode not in {",
                "        'post-signal-running',",
                "        'post-signal-restarting',",
                "    }:",
                "        state = 'exited'",
                "    if mode == 'post-signal-running':",
                "        state = 'running'",
                "    elif mode == 'post-signal-restarting' and signal_marker.exists():",
                "        state = 'restarting'",
                "    restart_policy = 'no'",
                "    if mode == 'restart-always' or (",
                "        mode == 'post-signal-restart-always'",
                "        and signal_marker.exists()",
                "    ):",
                "        restart_policy = 'always'",
                "    running = state == 'running'",
                "    restarting = state == 'restarting'",
                "    paused = state == 'paused'",
                "    dead = state == 'dead'",
                "    oom_killed = mode in {'main-exited-oom', 'post-signal-oom'}",
                "    exit_code = 0",
                "    if mode in {'main-exited-nonzero', 'post-signal-nonzero-exit'}:",
                "        exit_code = 1",
                "    if mode == 'main-running-flag-false':",
                "        running = False",
                "    elif mode == 'main-created-running-true':",
                "        running = True",
                "    elif mode == 'main-exited-running-true':",
                "        running = True",
                "    fields = [",
                "        container_id,",
                "        f'/{name}',",
                "        labels,",
                "        state,",
                "        running,",
                "        restarting,",
                "        paused,",
                "        dead,",
                "        oom_killed,",
                "        exit_code,",
                "        restart_policy,",
                "    ]",
                "    if mode == 'extra-json':",
                "        fields.append('extra')",
                "    print(json.dumps(fields, separators=(',', ':')))",
                "    raise SystemExit(0)",
                "if args[:1] == ['kill']:",
                "    signal_marker.write_text(' '.join(args) + '\\n', encoding='ascii')",
                "    if mode == 'signal-rc2':",
                "        raise SystemExit(2)",
                "    if mode == 'signal-rc143':",
                "        raise SystemExit(143)",
                "    raise SystemExit(0)",
                "if args[:2] == ['rm', '-f']:",
                "    rm_marker.write_text(args[-1] + '\\n', encoding='ascii')",
                "    raise SystemExit(0)",
                "if args[:1] == ['rm']:",
                "    rm_marker.write_text(' '.join(args) + '\\n', encoding='ascii')",
                "    if mode == 'main-nonforce-rm-failure':",
                "        raise SystemExit(2)",
                "    raise SystemExit(0)",
                "if args[:1] == ['inspect']:",
                "    count = 1",
                "    if post_rm_inspect_count.exists():",
                "        count = int(post_rm_inspect_count.read_text(encoding='ascii')) + 1",
                "    post_rm_inspect_count.write_text(str(count) + '\\n', encoding='ascii')",
                "    if mode == 'post-rm-eventual-absence' and count == 1:",
                "        raise SystemExit(0)",
                "    if mode == 'post-rm-nonabsence':",
                "        raise SystemExit(0)",
                "    if mode == 'post-rm-rc2':",
                "        raise SystemExit(2)",
                "    if mode == 'post-rm-timeout':",
                "        raise SystemExit(124)",
                "    raise SystemExit(1)",
                "raise SystemExit(127)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    docker_path.chmod(0o755)
    sleep_path.write_text("#!/usr/bin/env sh\nexit 0\n", encoding="utf-8")
    sleep_path.chmod(0o755)
    expected_name = main_name if expected_role == "main" else trusted_name
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"PATH={str(fake_bin)!r}:$PATH",
            "proof_label='acp-postgres-gate-1000-0123456789abcdef0123456789abcdef'",
            remove_exact_source,
            f"if remove_exact_recorded_container {shlex.quote(container_ref)} "
            f"{shlex.quote(expected_name)} {shlex.quote(expected_role)}; then",
            "  rc=0",
            "else",
            "  rc=$?",
            "fi",
            f'test "$rc" -eq {expected_rc}',
        )
    )
    result = subprocess.run(
        ["bash", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (mode, result.returncode, result.stdout, result.stderr)
    assert rm_marker.exists() is rm_expected
    assert signal_marker.exists() is signal_expected
    docker_commands = command_log.read_text(encoding="ascii").splitlines()
    if expected_role == "main" and rm_expected:
        assert any(
            command.startswith("rm ") and " -f " not in f" {command} "
            for command in docker_commands
        )
    if expected_role == "trusted-broker" and rm_expected:
        assert any(command.startswith("rm -f ") for command in docker_commands)
        assert not any(command.startswith("kill ") for command in docker_commands)
    if mode == "exact-main-running":
        assert docker_commands.index(f"kill --signal SIGINT {main_id}") < next(
            index for index, command in enumerate(docker_commands) if command == f"rm {main_id}"
        )
    if mode == "post-signal-running":
        assert int(signal_inspect_count.read_text(encoding="ascii")) == 150
    if mode == "post-rm-eventual-absence":
        assert int(post_rm_inspect_count.read_text(encoding="ascii")) > 1
    elif mode == "post-rm-nonabsence":
        assert int(post_rm_inspect_count.read_text(encoding="ascii")) == 25


@pytest.mark.parametrize(
    (
        "mode",
        "expected_rc",
        "expected_signal_count",
        "expected_inspect_count",
        "expected_rm",
        "expected_post_rm_inspects",
    ),
    [
        ("selected-created-success", 0, 0, 1, True, 1),
        ("selected-rc1", 1, 0, 1, False, 0),
        ("signal-rc143", 143, 1, 1, False, 0),
        ("post-signal-exhaustion", 70, 1, 151, False, 0),
        ("ambiguous-state", 70, 0, 1, False, 0),
    ],
)
def test_postgres_gate_cleanup_server_container_uses_one_authoritative_ref(
    tmp_path: Path,
    mode: str,
    expected_rc: int,
    expected_signal_count: int,
    expected_inspect_count: int,
    expected_rm: bool,
    expected_post_rm_inspects: int,
) -> None:
    script = _postgres_gate_script_source()
    remove_exact_source = _extract_shell_function(
        script,
        "validate_exact_recorded_container",
        "cleanup_server_container",
    )
    cleanup_server_source = _extract_shell_function(
        script,
        "cleanup_server_container",
        "verify_no_proof_labelled_containers",
    )
    fake_bin = tmp_path / "fake-bin"
    state_dir = tmp_path / "state"
    fake_bin.mkdir()
    state_dir.mkdir()
    proof_label = "acp-postgres-gate-1000-0123456789abcdef0123456789abcdef"
    server_name = f"{proof_label}-server"
    selected_id = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    cidfile_id = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    server_cidfile = state_dir / f"{proof_label}-server.cid"
    server_namefile = state_dir / f"{proof_label}-server.name"
    server_cidfile.write_text(f"{cidfile_id}\n", encoding="ascii")
    server_namefile.write_text(f"{server_name}\n", encoding="ascii")
    server_cidfile.chmod(0o600)
    server_namefile.chmod(0o600)
    inspect_refs = tmp_path / "inspect-refs.log"
    post_rm_inspect_refs = tmp_path / "post-rm-inspect-refs.log"
    signal_log = tmp_path / "signal.log"
    rm_log = tmp_path / "rm.log"
    docker_path = fake_bin / "docker"
    sleep_path = fake_bin / "sleep"
    docker_path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "from pathlib import Path",
                "import json",
                "import sys",
                "args = sys.argv[1:]",
                f"mode = {mode!r}",
                f"proof_label = {proof_label!r}",
                f"server_name = {server_name!r}",
                f"selected_id = {selected_id!r}",
                f"cidfile_id = {cidfile_id!r}",
                f"inspect_refs = Path({str(inspect_refs)!r})",
                f"post_rm_inspect_refs = Path({str(post_rm_inspect_refs)!r})",
                f"signal_log = Path({str(signal_log)!r})",
                f"rm_log = Path({str(rm_log)!r})",
                "def append(path: Path, text: str) -> None:",
                "    previous = path.read_text(encoding='ascii') if path.exists() else ''",
                "    path.write_text(previous + text + '\\n', encoding='ascii')",
                "def emit(container_id: str, name: str, state: str) -> None:",
                "    print(",
                "        json.dumps(",
                "            [",
                "                container_id,",
                "                f'/{name}',",
                "                {",
                "                    'acgs.postgres.proof': proof_label,",
                "                    'acgs.postgres.server': 'main',",
                "                },",
                "                state,",
                "                state == 'running',",
                "                state == 'restarting',",
                "                state == 'paused',",
                "                False,",
                "                False,",
                "                0,",
                "                'no',",
                "            ],",
                "            separators=(',', ':'),",
                "        )",
                "    )",
                "if args[:1] == ['inspect'] and '--format' in args:",
                "    ref = args[-1]",
                "    append(inspect_refs, ref)",
                "    if ref == selected_id:",
                "        if mode == 'selected-rc1':",
                "            raise SystemExit(1)",
                "        if mode == 'ambiguous-state':",
                "            emit(selected_id, server_name, 'paused')",
                "            raise SystemExit(0)",
                "        if mode == 'selected-created-success':",
                "            emit(selected_id, server_name, 'created')",
                "            raise SystemExit(0)",
                "        if signal_log.exists():",
                "            emit(selected_id, server_name, 'running')",
                "            raise SystemExit(0)",
                "        emit(selected_id, server_name, 'running')",
                "        raise SystemExit(0)",
                "    if ref in {cidfile_id, server_name}:",
                "        emit(cidfile_id, server_name, 'exited')",
                "        raise SystemExit(0)",
                "    raise SystemExit(1)",
                "if args[:1] == ['inspect']:",
                "    ref = args[-1]",
                "    append(post_rm_inspect_refs, ref)",
                "    if mode == 'selected-created-success' and ref == selected_id:",
                "        raise SystemExit(1)",
                "    raise SystemExit(127)",
                "if args[:1] == ['kill']:",
                "    append(signal_log, ' '.join(args))",
                "    if mode == 'signal-rc143':",
                "        raise SystemExit(143)",
                "    raise SystemExit(0)",
                "if args[:1] == ['rm']:",
                "    append(rm_log, ' '.join(args))",
                "    raise SystemExit(0)",
                "raise SystemExit(127)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    docker_path.chmod(0o755)
    sleep_path.write_text("#!/usr/bin/env sh\nexit 0\n", encoding="utf-8")
    sleep_path.chmod(0o755)
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"PATH={str(fake_bin)!r}:$PATH",
            f"state_dir={str(state_dir)!r}",
            f"proof_label={proof_label!r}",
            f"container_name={server_name!r}",
            f"container_id={selected_id!r}",
            f"server_cidfile={str(server_cidfile)!r}",
            f"server_namefile={str(server_namefile)!r}",
            remove_exact_source,
            cleanup_server_source,
            "if cleanup_server_container; then",
            "  rc=0",
            "else",
            "  rc=$?",
            "fi",
            f'test "$rc" -eq {expected_rc}',
        )
    )
    result = subprocess.run(
        ["bash", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (mode, result.returncode, result.stdout, result.stderr)
    refs = inspect_refs.read_text(encoding="ascii").splitlines()
    assert refs == [selected_id] * expected_inspect_count
    assert cidfile_id not in refs
    assert server_name not in refs
    signals = signal_log.read_text(encoding="ascii").splitlines() if signal_log.exists() else []
    assert len(signals) == expected_signal_count
    rms = rm_log.read_text(encoding="ascii").splitlines() if rm_log.exists() else []
    if expected_rm:
        assert rms == [f"rm {selected_id}"]
    else:
        assert rms == []
    assert not any(cidfile_id in rm for rm in rms)
    assert not any(server_name in rm for rm in rms)
    post_rm_refs = (
        post_rm_inspect_refs.read_text(encoding="ascii").splitlines()
        if post_rm_inspect_refs.exists()
        else []
    )
    assert post_rm_refs == [selected_id] * expected_post_rm_inspects


@pytest.mark.parametrize(
    "failure_function",
    [
        "cleanup_client_containers",
        "cleanup_client_identity_mismatch",
        "cleanup_client_post_rm_rc2",
        "cleanup_client_post_rm_timeout",
        "cleanup_client_terminal_lf",
        "cleanup_client_multiple_lf",
        "cleanup_client_terminal_space",
        "cleanup_client_terminal_tab",
        "cleanup_server_post_signal_exhaustion",
        "verify_stable_no_proof_labelled_containers",
    ],
)
def test_postgres_gate_cleanup_uncertainty_preserves_bridge_and_intents(
    tmp_path: Path,
    failure_function: str,
) -> None:
    script = _postgres_gate_script_source()
    read_private_source = _extract_shell_function(
        script,
        "read_private_container_file",
        "write_private_container_name_file",
    )
    write_recovery_source = _extract_shell_function(
        script,
        "write_recovery_contract",
        "verify_junit_report",
    )
    bind_source = _extract_shell_function(
        script,
        "bind_state_dir_identity",
        "validate_postgres_proof_nonce",
    )
    capture_source = _extract_shell_function(
        script,
        "capture_docker_ps_ids",
        "cleanup_client_containers",
    )
    cleanup_client_source = _extract_shell_function(
        script,
        "cleanup_client_containers",
        "remove_exact_recorded_container",
    )
    remove_exact_source = _extract_shell_function(
        script,
        "validate_exact_recorded_container",
        "cleanup_server_container",
    )
    cleanup_server_source = _extract_shell_function(
        script,
        "cleanup_server_container",
        "verify_no_proof_labelled_containers",
    )
    verify_no_source = _extract_shell_function(
        script,
        "verify_no_proof_labelled_containers",
        "verify_stable_no_proof_labelled_containers",
    )
    verify_stable_source = _extract_shell_function(
        script,
        "verify_stable_no_proof_labelled_containers",
        "cleanup_postgres_socket_bridge",
    )
    close_active_uv_start = script.index("close_active_uv_fd() {")
    close_active_uv_end = script.index("\n}\n\n# shellcheck disable=SC2016", close_active_uv_start)
    close_active_uv_source = script[close_active_uv_start : close_active_uv_end + 3]
    start = script.index("cleanup() {")
    end = script.index("\ntrap cleanup EXIT", start)
    cleanup_source = script[start:end]
    state_dir = tmp_path / "state"
    client_dir = state_dir / "client"
    fake_bin = tmp_path / "fake-bin"
    recovery_root = tmp_path / "recovery"
    proof_nonce = "0123456789abcdef0123456789abcdef"
    proof_label = f"acp-postgres-gate-{os.getuid()}-{proof_nonce}"
    bridge = recovery_root / f"{proof_label}-socket-bridge"
    intent = recovery_root / f"{proof_label}-client-1-1.intent"
    client_name = f"{proof_label}-client-1-1"
    client_id = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    server_name = f"{proof_label}-server"
    server_id = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    alternate_server_id = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
    state_dir.mkdir()
    state_dir.chmod(0o700)
    client_dir.mkdir()
    fake_bin.mkdir()
    recovery_root.mkdir()
    recovery_root.chmod(0o700)
    bridge_identity, bridge_marker_sha256, bridge_mnt_id = _write_postgres_socket_bridge(
        bridge,
        proof_label,
        proof_nonce,
    )
    intent.write_text("intent", encoding="ascii")
    intent.chmod(0o600)
    server_cidfile = state_dir / f"{proof_label}-server.cid"
    server_namefile = state_dir / f"{proof_label}-server.name"
    if failure_function == "cleanup_server_post_signal_exhaustion":
        server_cidfile.write_text(f"{alternate_server_id}\n", encoding="ascii")
        server_namefile.write_text(f"{server_name}\n", encoding="ascii")
        server_cidfile.chmod(0o600)
        server_namefile.chmod(0o600)
    if failure_function in {
        "cleanup_client_containers",
        "cleanup_client_identity_mismatch",
        "cleanup_client_post_rm_rc2",
        "cleanup_client_post_rm_timeout",
        "cleanup_client_terminal_lf",
        "cleanup_client_multiple_lf",
        "cleanup_client_terminal_space",
        "cleanup_client_terminal_tab",
    }:
        (client_dir / f"{client_name}.cid").write_text(f"{client_id}\n", encoding="ascii")
        (client_dir / f"{client_name}.name").write_text(f"{client_name}\n", encoding="ascii")
        (client_dir / f"{client_name}.cid").chmod(0o600)
        (client_dir / f"{client_name}.name").chmod(0o600)
    docker_path = fake_bin / "docker"
    rm_marker = tmp_path / "cleanup-rm-called"
    signal_marker = tmp_path / "cleanup-signal-called"
    inspect_log = tmp_path / "cleanup-inspects.log"
    docker_path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "from pathlib import Path",
                "import json",
                "import os, sys",
                "args = sys.argv[1:]",
                f"mode = {failure_function!r}",
                f"proof_label = {proof_label!r}",
                f"client_id = {client_id!r}",
                f"client_name = {client_name!r}",
                f"server_id = {server_id!r}",
                f"alternate_server_id = {alternate_server_id!r}",
                f"server_name = {server_name!r}",
                f"rm_marker = Path({str(rm_marker)!r})",
                f"signal_marker = Path({str(signal_marker)!r})",
                f"inspect_log = Path({str(inspect_log)!r})",
                "def append(path: Path, text: str) -> None:",
                "    previous = path.read_text(encoding='ascii') if path.exists() else ''",
                "    path.write_text(previous + text + '\\n', encoding='ascii')",
                "if args[:1] == ['inspect'] and '--format' in args:",
                "    ref = args[-1]",
                "    append(inspect_log, ref)",
                "    if mode == 'cleanup_server_post_signal_exhaustion' and ref == server_id:",
                "        print(",
                "            json.dumps(",
                "                [",
                "                    server_id,",
                "                    f'/{server_name}',",
                "                    {",
                "                        'acgs.postgres.proof': proof_label,",
                "                        'acgs.postgres.server': 'main',",
                "                    },",
                "                    'running',",
                "                    True,",
                "                    False,",
                "                    False,",
                "                    False,",
                "                    False,",
                "                    0,",
                "                    'no',",
                "                ],",
                "                separators=(',', ':'),",
                "            )",
                "        )",
                "        raise SystemExit(0)",
                "    if mode == 'cleanup_server_post_signal_exhaustion' and ref in {",
                "        alternate_server_id,",
                "        server_name,",
                "    }:",
                "        print(",
                "            json.dumps(",
                "                [",
                "                    alternate_server_id,",
                "                    f'/{server_name}',",
                "                    {",
                "                        'acgs.postgres.proof': proof_label,",
                "                        'acgs.postgres.server': 'main',",
                "                    },",
                "                    'exited',",
                "                    False,",
                "                    False,",
                "                    False,",
                "                    False,",
                "                    False,",
                "                    0,",
                "                    'no',",
                "                ],",
                "                separators=(',', ':'),",
                "            )",
                "        )",
                "        raise SystemExit(0)",
                "    if mode in {",
                "        'cleanup_client_containers',",
                "        'cleanup_client_post_rm_rc2',",
                "        'cleanup_client_post_rm_timeout',",
                "    } and ref in {client_id, client_name}:",
                "        print(",
                "            json.dumps(",
                "                [",
                "                    client_id,",
                "                    f'/{client_name}',",
                "                    {",
                "                        'acgs.postgres.proof': proof_label,",
                "                        'acgs.postgres.client': 'trusted-broker',",
                "                    },",
                "                    'running',",
                "                    True,",
                "                    False,",
                "                    False,",
                "                    False,",
                "                    False,",
                "                    0,",
                "                    'no',",
                "                ],",
                "                separators=(',', ':'),",
                "            )",
                "        )",
                "        raise SystemExit(0)",
                "    if (",
                "        mode == 'cleanup_client_identity_mismatch'",
                "        and ref in {client_id, client_name}",
                "    ):",
                "        print(",
                "            json.dumps(",
                "                [",
                "                    client_id,",
                "                    f'/{client_name}',",
                "                    {",
                "                        'acgs.postgres.proof': proof_label,",
                "                        'acgs.postgres.client': 'wrong-client-label',",
                "                    },",
                "                    'running',",
                "                    True,",
                "                    False,",
                "                    False,",
                "                    False,",
                "                    False,",
                "                    0,",
                "                    'no',",
                "                ],",
                "                separators=(',', ':'),",
                "            )",
                "        )",
                "        raise SystemExit(0)",
                "    if mode in {",
                "        'cleanup_client_terminal_lf',",
                "        'cleanup_client_multiple_lf',",
                "        'cleanup_client_terminal_space',",
                "        'cleanup_client_terminal_tab',",
                "    } and ref in {client_id, client_name}:",
                "        client_label = 'trusted-broker'",
                "        if mode == 'cleanup_client_terminal_lf':",
                "            client_label += '\\n'",
                "        elif mode == 'cleanup_client_multiple_lf':",
                "            client_label += '\\nspoof'",
                "        elif mode == 'cleanup_client_terminal_space':",
                "            client_label += ' '",
                "        elif mode == 'cleanup_client_terminal_tab':",
                "            client_label += '\\t'",
                "        print(",
                "            json.dumps(",
                "                [",
                "                    client_id,",
                "                    f'/{client_name}',",
                "                    {",
                "                        'acgs.postgres.proof': proof_label,",
                "                        'acgs.postgres.client': client_label,",
                "                    },",
                "                    'running',",
                "                    True,",
                "                    False,",
                "                    False,",
                "                    False,",
                "                    False,",
                "                    0,",
                "                    'no',",
                "                ],",
                "                separators=(',', ':'),",
                "            )",
                "        )",
                "        raise SystemExit(0)",
                "    raise SystemExit(1)",
                "if args[:1] == ['inspect']:",
                "    if mode == 'cleanup_client_post_rm_rc2':",
                "        raise SystemExit(2)",
                "    if mode == 'cleanup_client_post_rm_timeout':",
                "        raise SystemExit(124)",
                "    raise SystemExit(1)",
                "if args[:2] == ['rm', '-f']:",
                "    rm_marker.write_text(args[-1] + '\\n', encoding='ascii')",
                "    if mode == 'cleanup_client_containers':",
                "        raise SystemExit(70)",
                "    if mode == 'cleanup_client_identity_mismatch':",
                "        raise SystemExit(90)",
                "    raise SystemExit(0)",
                "if args[:1] == ['kill']:",
                "    signal_marker.write_text(' '.join(args) + '\\n', encoding='ascii')",
                "    raise SystemExit(0)",
                "if args[:2] == ['ps', '-aq']:",
                "    joined = ' '.join(args)",
                "    if mode == 'cleanup_client_containers':",
                "        print(client_id)",
                "        raise SystemExit(0)",
                "    if 'acgs.postgres.client=trusted-broker' in joined:",
                "        raise SystemExit(0)",
                "    raise SystemExit(70)",
                "raise SystemExit(127)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    docker_path.chmod(0o755)
    touched = tmp_path / "touched"
    active_uv_fd_source = tmp_path / "active-uv-fd"
    active_uv_fd_source.write_text("fd lifecycle sentinel\n", encoding="ascii")
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"PATH={str(fake_bin)!r}:$PATH",
            f"state_dir={str(state_dir)!r}",
            f"proof_nonce={proof_nonce!r}",
            f"proof_label={proof_label!r}",
            f"container_name={proof_label + '-server'!r}",
            f"container_id={server_id!r}"
            if failure_function == "cleanup_server_post_signal_exhaustion"
            else "container_id=''",
            f"server_cidfile={str(server_cidfile)!r}",
            f"server_namefile={str(server_namefile)!r}",
            f"postgres_recovery_root={str(recovery_root)!r}",
            f"postgres_socket_bridge={str(bridge)!r}",
            f"postgres_socket_bridge_name={bridge.name!r}",
            f"postgres_socket_bridge_identity={bridge_identity!r}",
            f"postgres_socket_bridge_marker_sha256={bridge_marker_sha256!r}",
            f"postgres_socket_bridge_mnt_id={bridge_mnt_id!r}",
            "postgres_socket_bridge_creation_uncertain=0",
            f"postgres_recovery_root_mnt_id={_mount_id(recovery_root)!r}",
            "expected_server_cid=''",
            "recovery_contract_written=0",
            "broker_pid=''",
            "docker_started=1",
            "DOCKER_PS_IDS=()",
            "active_uv_fd=''",
            f"active_uv_fd_source={str(active_uv_fd_source)!r}",
            read_private_source,
            bind_source,
            'exec {state_dir_fd}<"$state_dir"',
            'mapfile -t fields < <(bind_state_dir_identity "$state_dir_fd")',
            'state_dir_parent="${fields[0]}"',
            'state_dir_name="${fields[1]}"',
            'state_dir_identity="${fields[2]}"',
            'state_dir_parent_identity="${fields[3]}"',
            'state_dir_mnt_id="${fields[4]}"',
            'state_dir_parent_mnt_id="${fields[5]}"',
            write_recovery_source,
            capture_source,
            cleanup_client_source,
            remove_exact_source,
            cleanup_server_source,
            verify_no_source,
            verify_stable_source,
            close_active_uv_source,
            "cleanup_postgres_socket_bridge() {",
            f"  echo bridge >>{str(touched)!r}",
            f"  rm -rf {str(bridge)!r}",
            "}",
            "unlink_postgres_recovery_intents() {",
            f"  echo intents >>{str(touched)!r}",
            f"  rm -f {str(intent)!r}",
            "}",
            cleanup_source,
            'exec {active_uv_fd}<"$active_uv_fd_source"',
            "cleanup",
        )
    )
    result = subprocess.run(
        ["bash", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    expected_rc = {
        "cleanup_client_post_rm_rc2": 2,
        "cleanup_client_post_rm_timeout": 124,
    }.get(failure_function, 70)
    assert result.returncode == expected_rc, (failure_function, result.stderr)
    assert bridge.is_dir()
    assert (bridge / ".acgs-postgres-socket-bridge.v2").is_file()
    assert intent.read_text(encoding="ascii") == "intent"
    assert not touched.exists()
    assert (state_dir / "recovery-contract.env").exists()
    if failure_function == "cleanup_server_post_signal_exhaustion":
        refs = inspect_log.read_text(encoding="ascii").splitlines()
        assert refs == [server_id] * 151
        assert alternate_server_id not in refs
        assert server_name not in refs
        assert signal_marker.read_text(encoding="ascii") == (f"kill --signal SIGINT {server_id}\n")
    if failure_function in {
        "cleanup_client_containers",
        "cleanup_client_post_rm_rc2",
        "cleanup_client_post_rm_timeout",
    }:
        assert rm_marker.exists()
    else:
        assert not rm_marker.exists()
    if failure_function in {
        "cleanup_client_containers",
        "cleanup_client_identity_mismatch",
        "cleanup_client_post_rm_rc2",
        "cleanup_client_post_rm_timeout",
        "cleanup_client_terminal_lf",
        "cleanup_client_multiple_lf",
        "cleanup_client_terminal_space",
        "cleanup_client_terminal_tab",
    }:
        assert (client_dir / f"{client_name}.cid").read_text(encoding="ascii") == (f"{client_id}\n")
        assert (client_dir / f"{client_name}.name").read_text(encoding="ascii") == (
            f"{client_name}\n"
        )


def _postgres_gate_state_cleanup_sources() -> tuple[str, str]:
    script = _postgres_gate_script_source()
    bind_source = _extract_shell_function(
        script,
        "bind_state_dir_identity",
        "validate_postgres_proof_nonce",
    )
    cleanup_source = _extract_shell_function(script, "finalize_state_dir_removal", "cleanup")
    return bind_source, cleanup_source


def _run_postgres_gate_state_cleanup(
    state_dir: Path,
    *,
    env: dict[str, str] | None = None,
    setup: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    bind_source, cleanup_source = _postgres_gate_state_cleanup_sources()
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"state_dir={str(state_dir)!r}",
            *(setup or []),
            bind_source,
            cleanup_source,
            'exec {state_dir_fd}<"$state_dir"',
            'mapfile -t fields < <(bind_state_dir_identity "$state_dir_fd")',
            'state_dir_parent="${fields[0]}"',
            'state_dir_name="${fields[1]}"',
            'state_dir_identity="${fields[2]}"',
            'state_dir_parent_identity="${fields[3]}"',
            'state_dir_mnt_id="${fields[4]}"',
            'state_dir_parent_mnt_id="${fields[5]}"',
            "set +e",
            "finalize_state_dir_removal",
            "cleanup_rc=$?",
            "set -e",
            'printf "CLEANUP_RC=%s\\n" "$cleanup_rc"',
        )
    )
    return subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input=harness,
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        check=False,
    )


def test_postgres_gate_state_cleanup_closes_local_fds_before_deletion(tmp_path: Path) -> None:
    script = _postgres_gate_script_source()
    close_active_uv_start = script.index("close_active_uv_fd() {")
    close_active_uv_end = script.index("\n}\n\n# shellcheck disable=SC2016", close_active_uv_start)
    close_sources = script[close_active_uv_start : close_active_uv_end + 3]
    cleanup_start = script.index("cleanup() {")
    cleanup_end = script.index("\ntrap cleanup EXIT", cleanup_start)
    cleanup_source = script[cleanup_start:cleanup_end]
    marker = tmp_path / "finalizer-marker"
    broker_file = tmp_path / "broker.py"
    pytest_file = tmp_path / "pytest-output.bin"
    uv_file = tmp_path / "uv"
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    for path in (broker_file, pytest_file, uv_file):
        path.write_text("fd\n", encoding="ascii")
    harness = "\n".join(
        (
            "set -euo pipefail",
            "active_uv_fd=''",
            "broker_script_fd=''",
            "pytest_output_fd=''",
            "broker_pid=''",
            "docker_started=0",
            "postgres_socket_bridge=''",
            f"state_dir={str(state_dir)!r}",
            "cleanup_status_seen=''",
            close_sources,
            "cleanup_client_containers() { return 99; }",
            "cleanup_server_container() { return 99; }",
            "verify_stable_no_proof_labelled_containers() { return 99; }",
            "cleanup_postgres_socket_bridge() { return 99; }",
            "unlink_postgres_recovery_intents() { return 0; }",
            "write_recovery_contract() { return 0; }",
            "finalize_state_dir_removal() {",
            '  test -z "$active_uv_fd"',
            '  test -z "$broker_script_fd"',
            '  test -z "$pytest_output_fd"',
            f"  printf deleted >{str(marker)!r}",
            "}",
            cleanup_source,
            f"exec {{active_uv_fd}}<{str(uv_file)!r}",
            f"exec {{broker_script_fd}}<{str(broker_file)!r}",
            f"exec {{pytest_output_fd}}<>{str(pytest_file)!r}",
            "cleanup",
        )
    )
    result = subprocess.run(
        ["bash", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text(encoding="ascii") == "deleted"


def test_postgres_gate_state_cleanup_transient_enotempty_settles(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    sibling = tmp_path / "state-sibling"
    nested = state_dir / "nested"
    nested.mkdir(parents=True)
    sibling.mkdir()
    state_dir.chmod(0o700)
    (nested / "payload.txt").write_text("payload", encoding="ascii")
    (sibling / "must-survive").write_text("sibling", encoding="ascii")
    (state_dir / "recovery-contract.env").write_text("contract", encoding="ascii")
    result = _run_postgres_gate_state_cleanup(
        state_dir,
        env={"ACGS_POSTGRES_STATE_CLEANUP_TRANSIENT_ENOTEMPTY": "1"},
    )
    assert result.returncode == 0, result.stderr
    assert "CLEANUP_RC=0\n" in result.stdout
    assert not state_dir.exists()
    assert (sibling / "must-survive").read_text(encoding="ascii") == "sibling"


def test_postgres_gate_state_cleanup_persistent_residue_fails_and_keeps_recovery(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_dir.chmod(0o700)
    (state_dir / "payload.txt").write_text("payload", encoding="ascii")
    (state_dir / "recovery-contract.env").write_text("contract", encoding="ascii")
    result = _run_postgres_gate_state_cleanup(
        state_dir,
        env={"ACGS_POSTGRES_STATE_CLEANUP_PERSISTENT_ENOTEMPTY": "1"},
    )
    assert result.returncode == 0, result.stderr
    assert "CLEANUP_RC=70\n" in result.stdout
    assert state_dir.is_dir()
    assert (state_dir / "recovery-contract.env").read_text(encoding="ascii") == "contract"


@pytest.mark.parametrize(
    "setup",
    [
        [
            'state_dir_parent=$(dirname -- "$state_dir")',
            'rm -rf -- "$state_dir"',
            'ln -s /tmp "$state_dir"',
        ],
        ['rm -rf -- "$state_dir"', 'mkdir -- "$state_dir"'],
    ],
)
def test_postgres_gate_state_cleanup_refuses_substituted_state_dir(
    tmp_path: Path,
    setup: list[str],
) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_dir.chmod(0o700)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "must-survive").write_text("outside", encoding="ascii")
    bind_source, cleanup_source = _postgres_gate_state_cleanup_sources()
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"state_dir={str(state_dir)!r}",
            bind_source,
            cleanup_source,
            'exec {state_dir_fd}<"$state_dir"',
            'mapfile -t fields < <(bind_state_dir_identity "$state_dir_fd")',
            'state_dir_parent="${fields[0]}"',
            'state_dir_name="${fields[1]}"',
            'state_dir_identity="${fields[2]}"',
            'state_dir_parent_identity="${fields[3]}"',
            'state_dir_mnt_id="${fields[4]}"',
            'state_dir_parent_mnt_id="${fields[5]}"',
            *setup,
            "set +e",
            "finalize_state_dir_removal",
            "cleanup_rc=$?",
            "set -e",
            'printf "CLEANUP_RC=%s\\n" "$cleanup_rc"',
        )
    )
    result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "CLEANUP_RC=70\n" in result.stdout
    assert (outside / "must-survive").read_text(encoding="ascii") == "outside"


def test_postgres_gate_state_cleanup_recreation_after_absence_fails(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_dir.chmod(0o700)
    result = _run_postgres_gate_state_cleanup(
        state_dir,
        env={"ACGS_POSTGRES_STATE_CLEANUP_RECREATE_AFTER_DELETE": "1"},
    )
    assert result.returncode == 0, result.stderr
    assert "CLEANUP_RC=70\n" in result.stdout
    assert state_dir.is_dir()


@pytest.mark.parametrize(
    ("case_name", "extra_env", "expected_rc", "state_exists", "parent_mode"),
    [
        (
            "post-rmdir-estale",
            {"ACGS_POSTGRES_STATE_CLEANUP_ESTALE_AFTER_RMDIR": "1"},
            0,
            False,
            0o700,
        ),
        (
            "pre-rmdir-estale",
            {"ACGS_POSTGRES_STATE_CLEANUP_ESTALE_BEFORE_RMDIR": "1"},
            70,
            True,
            0o700,
        ),
        (
            "post-rmdir-eio",
            {"ACGS_POSTGRES_STATE_CLEANUP_EIO_AFTER_RMDIR": "1"},
            70,
            False,
            0o700,
        ),
        (
            "post-rmdir-estale-name-reappears",
            {
                "ACGS_POSTGRES_STATE_CLEANUP_ESTALE_AFTER_RMDIR": "1",
                "ACGS_POSTGRES_STATE_CLEANUP_REAPPEAR_AFTER_RMDIR_ESTALE": "1",
            },
            70,
            True,
            0o700,
        ),
        (
            "post-rmdir-estale-parent-binding-drift",
            {
                "ACGS_POSTGRES_STATE_CLEANUP_ESTALE_AFTER_RMDIR": "1",
                "ACGS_POSTGRES_STATE_CLEANUP_CHMOD_PARENT_AFTER_RMDIR_ESTALE": "1",
            },
            70,
            False,
            0o755,
        ),
    ],
)
def test_postgres_gate_state_cleanup_accepts_only_post_rmdir_estale(
    tmp_path: Path,
    case_name: str,
    extra_env: dict[str, str],
    expected_rc: int,
    state_exists: bool,
    parent_mode: int,
) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_dir.chmod(0o700)
    (state_dir / "recovery-contract.env").write_text("contract", encoding="ascii")

    result = _run_postgres_gate_state_cleanup(state_dir, env=extra_env)

    assert result.returncode == 0, (case_name, result.stdout, result.stderr)
    assert f"CLEANUP_RC={expected_rc}\n" in result.stdout, (
        case_name,
        result.stdout,
        result.stderr,
    )
    assert state_dir.exists() is state_exists
    assert stat.S_IMODE(tmp_path.stat().st_mode) == parent_mode


def test_postgres_gate_state_cleanup_refuses_mount_binding_drift(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_dir.chmod(0o700)
    bind_source, cleanup_source = _postgres_gate_state_cleanup_sources()
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"state_dir={str(state_dir)!r}",
            bind_source,
            cleanup_source,
            'exec {state_dir_fd}<"$state_dir"',
            'mapfile -t fields < <(bind_state_dir_identity "$state_dir_fd")',
            'state_dir_parent="${fields[0]}"',
            'state_dir_name="${fields[1]}"',
            'state_dir_identity="${fields[2]}"',
            'state_dir_parent_identity="${fields[3]}"',
            "state_dir_mnt_id=0",
            'state_dir_parent_mnt_id="${fields[5]}"',
            "set +e",
            "finalize_state_dir_removal",
            "cleanup_rc=$?",
            "set -e",
            'printf "CLEANUP_RC=%s\\n" "$cleanup_rc"',
        )
    )
    result = subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "CLEANUP_RC=70\n" in result.stdout
    assert state_dir.is_dir()


def _prove_rename_exchange_round_trip(
    first: Path,
    second: Path,
) -> tuple[tuple[int, int, int, int], tuple[int, int, int, int]]:
    """Prove canonical native/tmpfs RENAME_EXCHANGE support for these paths.

    Separate FUSE evidence records unsupported EINVAL behavior.
    """
    first_identity = _directory_identity(first)
    second_identity = _directory_identity(second)
    assert first_identity != second_identity

    _rename_exchange(first, second)
    assert _directory_identity(first) == second_identity
    assert _directory_identity(second) == first_identity

    _rename_exchange(first, second)
    assert _directory_identity(first) == first_identity
    assert _directory_identity(second) == second_identity
    return first_identity, second_identity


@pytest.mark.parametrize("substitute_has_payload", [True, False])
def test_postgres_gate_state_cleanup_refuses_top_level_rename_exchange(
    request: pytest.FixtureRequest,
    substitute_has_payload: bool,
) -> None:
    tmp_root = _private_canonical_tmp_dir("acp-pg-cleanup-top-exchange-", request)
    state_dir = tmp_root / "state"
    substitute = tmp_root / "substitute"
    state_dir.mkdir()
    substitute.mkdir()
    state_dir.chmod(0o700)
    substitute.chmod(0o700)
    (state_dir / "original.txt").write_text("original", encoding="ascii")
    if substitute_has_payload:
        (substitute / "must-survive.txt").write_text("substitute", encoding="ascii")
    (state_dir / "recovery-contract.env").write_text("contract", encoding="ascii")
    original_state_identity, original_substitute_identity = _prove_rename_exchange_round_trip(
        state_dir,
        substitute,
    )
    result = _run_postgres_gate_state_cleanup(
        state_dir,
        env={"ACGS_POSTGRES_STATE_CLEANUP_RENAME_EXCHANGE_TOP": substitute.name},
    )
    assert result.returncode == 0, result.stderr
    assert "CLEANUP_RC=70\n" in result.stdout
    if substitute_has_payload:
        assert (state_dir / "must-survive.txt").read_text(encoding="ascii") == "substitute"
    else:
        assert state_dir.is_dir()
        assert not (state_dir / "must-survive.txt").exists()
    assert substitute.is_dir()
    assert _directory_identity(state_dir) == original_substitute_identity
    assert _directory_identity(substitute) == original_state_identity


@pytest.mark.parametrize("substitute_has_payload", [True, False])
def test_postgres_gate_state_cleanup_refuses_nested_rename_exchange(
    request: pytest.FixtureRequest,
    substitute_has_payload: bool,
) -> None:
    tmp_root = _private_canonical_tmp_dir("acp-pg-cleanup-nested-exchange-", request)
    state_dir = tmp_root / "state"
    nested = state_dir / "nested"
    substitute = state_dir / "substitute"
    nested.mkdir(parents=True)
    substitute.mkdir()
    state_dir.chmod(0o700)
    nested.chmod(0o700)
    substitute.chmod(0o700)
    (nested / "original.txt").write_text("original", encoding="ascii")
    if substitute_has_payload:
        (substitute / "must-survive.txt").write_text("substitute", encoding="ascii")
    (state_dir / "recovery-contract.env").write_text("contract", encoding="ascii")
    original_nested_identity, original_substitute_identity = _prove_rename_exchange_round_trip(
        nested,
        substitute,
    )
    result = _run_postgres_gate_state_cleanup(
        state_dir,
        env={
            "ACGS_POSTGRES_STATE_CLEANUP_RENAME_EXCHANGE_NESTED": nested.name,
            "ACGS_POSTGRES_STATE_CLEANUP_RENAME_EXCHANGE_NESTED_WITH": substitute.name,
        },
    )
    assert result.returncode == 0, result.stderr
    assert "CLEANUP_RC=70\n" in result.stdout
    if substitute_has_payload:
        assert (nested / "must-survive.txt").read_text(encoding="ascii") == "substitute"
    else:
        assert nested.is_dir()
        assert not (nested / "must-survive.txt").exists()
    assert substitute.is_dir()
    assert (state_dir / "recovery-contract.env").read_text(encoding="ascii") == "contract"
    assert _directory_identity(nested) == original_substitute_identity
    assert _directory_identity(substitute) == original_nested_identity


def test_postgres_gate_state_cleanup_refuses_top_level_exchange_after_verify(
    request: pytest.FixtureRequest,
) -> None:
    tmp_root = _private_canonical_tmp_dir("acp-pg-cleanup-top-after-verify-", request)
    state_dir = tmp_root / "state"
    substitute = tmp_root / "substitute"
    state_dir.mkdir()
    substitute.mkdir()
    state_dir.chmod(0o700)
    substitute.chmod(0o700)
    (state_dir / "original.txt").write_text("original", encoding="ascii")
    (state_dir / "recovery-contract.env").write_text("contract", encoding="ascii")
    original_state_identity, original_substitute_identity = _prove_rename_exchange_round_trip(
        state_dir,
        substitute,
    )
    result = _run_postgres_gate_state_cleanup(
        state_dir,
        env={
            "ACGS_POSTGRES_STATE_CLEANUP_RENAME_EXCHANGE_TOP_AFTER_VERIFY": substitute.name,
        },
    )
    assert result.returncode == 0, result.stderr
    assert "CLEANUP_RC=70\n" in result.stdout
    assert state_dir.is_dir()
    assert not (state_dir / "original.txt").exists()
    assert substitute.is_dir()
    assert not (substitute / "original.txt").exists()
    assert _directory_identity(state_dir) == original_substitute_identity
    assert _directory_identity(substitute) == original_state_identity


def test_postgres_gate_state_cleanup_refuses_nested_exchange_after_verify(
    request: pytest.FixtureRequest,
) -> None:
    tmp_root = _private_canonical_tmp_dir("acp-pg-cleanup-nested-after-verify-", request)
    state_dir = tmp_root / "state"
    nested = state_dir / "nested"
    substitute = state_dir / "substitute"
    nested.mkdir(parents=True)
    substitute.mkdir()
    state_dir.chmod(0o700)
    nested.chmod(0o700)
    substitute.chmod(0o700)
    (nested / "original.txt").write_text("original", encoding="ascii")
    (state_dir / "recovery-contract.env").write_text("contract", encoding="ascii")
    original_nested_identity, original_substitute_identity = _prove_rename_exchange_round_trip(
        nested,
        substitute,
    )
    result = _run_postgres_gate_state_cleanup(
        state_dir,
        env={
            "ACGS_POSTGRES_STATE_CLEANUP_RENAME_EXCHANGE_NESTED_AFTER_VERIFY": nested.name,
            "ACGS_POSTGRES_STATE_CLEANUP_RENAME_EXCHANGE_NESTED_AFTER_VERIFY_WITH": substitute.name,
        },
    )
    assert result.returncode == 0, result.stderr
    assert "CLEANUP_RC=70\n" in result.stdout
    assert not nested.exists()
    assert substitute.is_dir()
    assert not (substitute / "original.txt").exists()
    assert (state_dir / "recovery-contract.env").read_text(encoding="ascii") == "contract"
    assert _directory_identity(substitute) == original_nested_identity
    assert original_substitute_identity != original_nested_identity


def test_postgres_gate_cleanup_preserves_original_body_status_on_cleanup_failure(
    tmp_path: Path,
) -> None:
    script = _postgres_gate_script_source()
    close_active_uv_start = script.index("close_active_uv_fd() {")
    close_active_uv_end = script.index("\n}\n\n# shellcheck disable=SC2016", close_active_uv_start)
    close_sources = script[close_active_uv_start : close_active_uv_end + 3]
    cleanup_start = script.index("cleanup() {")
    cleanup_end = script.index("\ntrap cleanup EXIT", cleanup_start)
    cleanup_source = script[cleanup_start:cleanup_end]
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_dir.chmod(0o700)
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"state_dir={str(state_dir)!r}",
            "active_uv_fd=''",
            "broker_script_fd=''",
            "pytest_output_fd=''",
            "broker_pid=''",
            "docker_started=0",
            "postgres_socket_bridge=''",
            close_sources,
            "cleanup_client_containers() { return 99; }",
            "cleanup_server_container() { return 99; }",
            "verify_stable_no_proof_labelled_containers() { return 99; }",
            "cleanup_postgres_socket_bridge() { return 99; }",
            "unlink_postgres_recovery_intents() { return 0; }",
            "write_recovery_contract() {",
            '  if [[ -e "$state_dir/recovery-contract.env" ]]; then return 99; fi',
            '  printf \'cleanup_status=%s\\n\' "$1" >"$state_dir/recovery-contract.env"',
            "}",
            "validate_recovery_contract() {",
            "  grep -qx 'cleanup_status=70' \"$state_dir/recovery-contract.env\"",
            "}",
            "finalize_state_dir_removal() { return 70; }",
            cleanup_source,
            "set +e",
            "false",
            "cleanup",
        )
    )
    result = subprocess.run(
        ["bash", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1, result.stderr
    assert (state_dir / "recovery-contract.env").read_text(encoding="ascii") == (
        "cleanup_status=70\n"
    )


def test_postgres_gate_cleanup_refuses_recovery_write_after_state_recreation(
    tmp_path: Path,
) -> None:
    script = _postgres_gate_script_source()
    read_private_source = _extract_shell_function(
        script,
        "read_private_container_file",
        "write_private_container_name_file",
    )
    bind_source = _extract_shell_function(
        script,
        "bind_state_dir_identity",
        "validate_postgres_proof_nonce",
    )
    write_recovery_source = _extract_shell_function(
        script,
        "write_recovery_contract",
        "verify_junit_report",
    )
    close_active_uv_start = script.index("close_active_uv_fd() {")
    close_active_uv_end = script.index("\n}\n\n# shellcheck disable=SC2016", close_active_uv_start)
    close_sources = script[close_active_uv_start : close_active_uv_end + 3]
    cleanup_start = script.index("cleanup() {")
    cleanup_end = script.index("\ntrap cleanup EXIT", cleanup_start)
    cleanup_source = script[cleanup_start:cleanup_end]
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_dir.chmod(0o700)
    proof_nonce = "0123456789abcdef0123456789abcdef"
    proof_label = f"acp-postgres-gate-{os.getuid()}-{proof_nonce}"
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"state_dir={str(state_dir)!r}",
            f"proof_nonce={proof_nonce!r}",
            f"proof_label={proof_label!r}",
            f"container_name={proof_label + '-server'!r}",
            f"server_cidfile={str(state_dir / 'server.cid')!r}",
            "postgres_socket_bridge_name=''",
            "postgres_socket_bridge_identity=''",
            "postgres_socket_bridge_marker_sha256=''",
            "postgres_socket_bridge_mnt_id=''",
            "postgres_recovery_root_mnt_id=''",
            "postgres_socket_bridge_creation_uncertain=0",
            "expected_server_cid=''",
            "recovery_contract_written=0",
            "active_uv_fd=''",
            "broker_script_fd=''",
            "pytest_output_fd=''",
            "broker_pid=''",
            "docker_started=0",
            "postgres_socket_bridge=''",
            read_private_source,
            bind_source,
            write_recovery_source,
            close_sources,
            'exec {state_dir_fd}<"$state_dir"',
            'mapfile -t fields < <(bind_state_dir_identity "$state_dir_fd")',
            'state_dir_parent="${fields[0]}"',
            'state_dir_name="${fields[1]}"',
            'state_dir_identity="${fields[2]}"',
            'state_dir_parent_identity="${fields[3]}"',
            'state_dir_mnt_id="${fields[4]}"',
            'state_dir_parent_mnt_id="${fields[5]}"',
            "cleanup_client_containers() { return 99; }",
            "cleanup_server_container() { return 99; }",
            "verify_stable_no_proof_labelled_containers() { return 99; }",
            "cleanup_postgres_socket_bridge() { return 99; }",
            "unlink_postgres_recovery_intents() { return 0; }",
            "finalize_state_dir_removal() {",
            '  rm -rf -- "$state_dir"',
            '  mkdir -- "$state_dir"',
            '  chmod 700 "$state_dir"',
            '  printf replacement >"$state_dir/replacement.txt"',
            "  return 70",
            "}",
            cleanup_source,
            "cleanup",
        )
    )
    result = subprocess.run(
        ["bash", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 70, result.stderr
    assert "lost original state directory identity" in result.stderr
    assert not (state_dir / "recovery-contract.env").exists()
    assert (state_dir / "replacement.txt").read_text(encoding="ascii") == "replacement"


def test_postgres_gate_cleanup_refuses_recovery_write_after_spoofed_state_reuse(
    tmp_path: Path,
) -> None:
    script = _postgres_gate_script_source()
    read_private_source = _extract_shell_function(
        script,
        "read_private_container_file",
        "write_private_container_name_file",
    )
    bind_source = _extract_shell_function(
        script,
        "bind_state_dir_identity",
        "validate_postgres_proof_nonce",
    )
    write_recovery_source = _extract_shell_function(
        script,
        "write_recovery_contract",
        "verify_junit_report",
    )
    validate_recovery_source = _extract_shell_function(
        script,
        "validate_recovery_contract",
        "validate_current_state_dir_identity",
    )
    validate_state_source = _extract_shell_function(
        script,
        "validate_current_state_dir_identity",
        "verify_junit_report",
    )
    close_active_uv_start = script.index("close_active_uv_fd() {")
    close_active_uv_end = script.index("\n}\n\n# shellcheck disable=SC2016", close_active_uv_start)
    close_sources = script[close_active_uv_start : close_active_uv_end + 3]
    cleanup_start = script.index("cleanup() {")
    cleanup_end = script.index("\ntrap cleanup EXIT", cleanup_start)
    cleanup_source = script[cleanup_start:cleanup_end]
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_dir.chmod(0o700)
    proof_nonce = "0123456789abcdef0123456789abcdef"
    proof_label = f"acp-postgres-gate-{os.getuid()}-{proof_nonce}"
    harness = "\n".join(
        (
            "set -euo pipefail",
            f"state_dir={str(state_dir)!r}",
            f"proof_nonce={proof_nonce!r}",
            f"proof_label={proof_label!r}",
            f"container_name={proof_label + '-server'!r}",
            f"server_cidfile={str(state_dir / 'server.cid')!r}",
            "postgres_socket_bridge_name=''",
            "postgres_socket_bridge_identity=''",
            "postgres_socket_bridge_marker_sha256=''",
            "postgres_socket_bridge_mnt_id=''",
            "postgres_recovery_root_mnt_id=''",
            "postgres_socket_bridge_creation_uncertain=0",
            "expected_server_cid=''",
            "recovery_contract_written=0",
            "active_uv_fd=''",
            "broker_script_fd=''",
            "pytest_output_fd=''",
            "broker_pid=''",
            "docker_started=0",
            "postgres_socket_bridge=''",
            read_private_source,
            bind_source,
            write_recovery_source,
            validate_recovery_source,
            validate_state_source,
            close_sources,
            'exec {state_dir_fd}<"$state_dir"',
            'mapfile -t fields < <(bind_state_dir_identity "$state_dir_fd")',
            'state_dir_parent="${fields[0]}"',
            'state_dir_name="${fields[1]}"',
            'state_dir_identity="${fields[2]}"',
            'state_dir_parent_identity="${fields[3]}"',
            'state_dir_mnt_id="${fields[4]}"',
            'state_dir_parent_mnt_id="${fields[5]}"',
            "cleanup_client_containers() { return 99; }",
            "cleanup_server_container() { return 99; }",
            "verify_stable_no_proof_labelled_containers() { return 99; }",
            "cleanup_postgres_socket_bridge() { return 99; }",
            "unlink_postgres_recovery_intents() { return 0; }",
            "finalize_state_dir_removal() {",
            '  rm -rf -- "$state_dir"',
            '  mkdir -- "$state_dir"',
            '  chmod 700 "$state_dir"',
            '  printf replacement >"$state_dir/replacement.txt"',
            '  state_dir_identity="$(stat -Lc "%d:%i:%u:%a" -- "$state_dir")"',
            "  state_dir_mnt_id=$(python3 - \"$state_dir\" <<'PY'",
            "from __future__ import annotations",
            "import os",
            "import sys",
            "fd = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)",
            "try:",
            "    with open(f'/proc/self/fdinfo/{fd}', encoding='utf-8') as fdinfo:",
            "        for line in fdinfo:",
            "            if line.startswith('mnt_id:'):",
            "                print(line.split(':', 1)[1].strip())",
            "                break",
            "finally:",
            "    os.close(fd)",
            "PY",
            "  )",
            "  return 70",
            "}",
            cleanup_source,
            "cleanup",
        )
    )
    result = subprocess.run(
        ["bash", "-s"],
        input=harness,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 70, result.stderr
    assert "lost original state directory identity" in result.stderr
    assert not (state_dir / "recovery-contract.env").exists()
    assert (state_dir / "replacement.txt").read_text(encoding="ascii") == "replacement"


def _rename_exchange(first: Path, second: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    syscall = libc.syscall
    syscall.argtypes = (
        ctypes.c_long,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    syscall.restype = ctypes.c_long
    renameat2_syscall = 316
    at_fdcwd = -100
    rename_exchange = 2
    rc = syscall(
        renameat2_syscall,
        at_fdcwd,
        os.fsencode(first),
        at_fdcwd,
        os.fsencode(second),
        rename_exchange,
    )
    if rc != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno), f"{first} <-> {second}")


def _extract_single_quoted_heredoc(script: str, marker: str) -> str:
    start = script.index(marker) + len(marker)
    end = script.index("\nPY\n", start)
    return script[start:end] + "\n"


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
    assert result.after.state is DatabaseSchemaState.VERSION_0012


def test_prior_0002_schema_upgrade_to_0003_preserves_scoped_rows(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)
    _seed_exact_legacy_v0_schema(database_url)
    _upgrade_to_exact_0002(database_url)
    _insert_scoped_0002_rows(database_url)

    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0002
    assert _scoped_0002_rows(database_url) == (
        ("project-prior-0002", "org-prior-0002"),
        ("environment-prior-0002", "org-prior-0002", "project-prior-0002"),
    )

    result = upgrade_database(database_url)

    assert result.before.state is DatabaseSchemaState.VERSION_0002
    assert result.after.state is DatabaseSchemaState.VERSION_0012
    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0012
    assert _version_number(database_url) == HEAD_REVISION
    assert _scoped_0002_rows(database_url) == (
        ("project-prior-0002", "org-prior-0002"),
        ("environment-prior-0002", "org-prior-0002", "project-prior-0002"),
    )


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
    engine = make_engine(database_url)
    try:
        legacy_unique_names = {
            constraint["name"] for constraint in sa.inspect(engine).get_unique_constraints("agents")
        }
    finally:
        engine.dispose()
    assert "uq_agents_org_name" in legacy_unique_names

    result = upgrade_database(database_url)

    assert result.before.state is DatabaseSchemaState.LEGACY_V0
    assert result.after.state is DatabaseSchemaState.VERSION_0012


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

    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0012
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


def test_check_constraint_signature_matches_postgresql_native_reflection_without_widening() -> None:
    expected = _check_constraint_signature("assurance_class='native'")
    status_expected = _check_constraint_signature(
        "status IN ('in_progress', 'succeeded', 'failed')"
    )
    pending_status_expected = _check_constraint_signature("status IN ('pending')")
    active_revoked_status_expected = _check_constraint_signature("status IN ('active', 'revoked')")
    active_revoked_retired_status_expected = _check_constraint_signature(
        "status IN ('active', 'retired', 'revoked')"
    )
    four_value_status_expected = _check_constraint_signature(
        "status IN ('active', 'consumed', 'revoked', 'expired')"
    )
    trust_retired_epoch_expected = _check_constraint_signature(
        "(status = 'retired' AND retired_epoch IS NOT NULL "
        "AND retired_epoch > activated_epoch) OR "
        "(status IN ('active', 'revoked') AND retired_epoch IS NULL)"
    )

    assert _check_constraint_signature("((assurance_class)::text = 'native'::text)") == expected
    assert _check_constraint_signature(
        "kind::text = ANY (ARRAY['status'::character varying, 'wiring'::character varying]::text[])"
    ) == _check_constraint_signature("kind IN ('status', 'wiring')")
    assert _check_constraint_signature("source_system='gove-zone'") == _check_constraint_signature(
        "(source_system)::text = 'gove-zone'::text"
    )
    assert pending_status_expected == 'status:["pending"]'
    for reflected_pending_sql in (
        "status = 'pending'",
        "(status)::text = 'pending'::text",
        "((status)::text = 'pending'::text)",
        "(\"status\")::text = ('pending'::character varying)",
    ):
        assert _check_constraint_signature(reflected_pending_sql) == pending_status_expected
    assert (
        _check_constraint_signature(
            "(status)::text = ANY "
            "(ARRAY[('in_progress'::character varying)::text, "
            "('succeeded'::character varying)::text, "
            "('failed'::character varying)::text])"
        )
        == status_expected
    )
    assert (
        _check_constraint_signature(
            "(status)::text = ANY "
            "((ARRAY['active'::character varying, "
            "'revoked'::character varying])::text[])"
        )
        == active_revoked_status_expected
    )
    assert (
        _check_constraint_signature(
            "((status)::text = ANY "
            "(ARRAY[('active'::character varying)::text, "
            "('revoked'::character varying)::text]))"
        )
        == active_revoked_status_expected
    )
    assert (
        _check_constraint_signature("((\"status\")::text = ANY (ARRAY['active', 'revoked']))")
        == active_revoked_status_expected
    )
    assert (
        _check_constraint_signature(
            "status::text = 'retired'::text "
            "AND retired_epoch IS NOT NULL "
            "AND retired_epoch > activated_epoch "
            "OR (status::text = ANY "
            "(ARRAY['active'::character varying, 'revoked'::character varying]::text[])) "
            "AND retired_epoch IS NULL"
        )
        == trust_retired_epoch_expected
    )
    assert (
        _check_constraint_signature(
            "status::text = 'retired'::text "
            "AND retired_epoch IS NOT NULL "
            "AND retired_epoch >= activated_epoch "
            "OR (status::text = ANY "
            "(ARRAY['active'::character varying, 'revoked'::character varying]::text[])) "
            "AND retired_epoch IS NULL"
        )
        != trust_retired_epoch_expected
    )
    assert (
        _check_constraint_signature(
            "status::text = 'retired'::text "
            "AND retired_epoch IS NOT NULL "
            "OR (status::text = ANY "
            "(ARRAY['active'::character varying, 'revoked'::character varying]::text[])) "
            "AND retired_epoch IS NULL"
        )
        != trust_retired_epoch_expected
    )
    assert (
        _check_constraint_signature("assurance_class IN ('native', 'development-unsigned')")
        != expected
    )
    assert (
        _check_constraint_signature("status IN ('in_progress', 'succeeded', 'failed', 'retrying')")
        != status_expected
    )
    assert (
        _check_constraint_signature("status IN ('failed', 'in_progress', 'succeeded')")
        != status_expected
    )
    assert (
        _check_constraint_signature("status IN ('active', 'retired', 'revoked')")
        != active_revoked_status_expected
    )
    assert (
        _check_constraint_signature("status IN ('revoked', 'active')")
        != active_revoked_status_expected
    )
    for mutated_literal in (
        "status IN ('ACTIVE', 'revoked')",
        "status IN ('act ive', 'revoked')",
        "status IN ('active::text', 'revoked')",
        "status IN ('act\"ive', 'revoked')",
    ):
        assert _check_constraint_signature(mutated_literal) != active_revoked_status_expected
    assert (
        _check_constraint_signature("status IN ('active,revoked')")
        != active_revoked_status_expected
    )
    assert (
        _check_constraint_signature("status IN ('active,retired', 'revoked')")
        != active_revoked_retired_status_expected
    )
    assert (
        _check_constraint_signature("status IN ('active', 'retired,revoked')")
        != active_revoked_retired_status_expected
    )
    assert (
        _check_constraint_signature("status IN ('active,consumed', 'revoked', 'expired')")
        != four_value_status_expected
    )
    assert (
        _check_constraint_signature("status IN ('active', 'consumed,revoked', 'expired')")
        != four_value_status_expected
    )
    assert (
        _check_constraint_signature("status IN ('active', 'consumed', 'revoked,expired')")
        != four_value_status_expected
    )
    assert _check_constraint_signature("other_status IN ('active', 'revoked')") != (
        active_revoked_status_expected
    )
    assert (
        _check_constraint_signature("status IN ('active', 'active')")
        != active_revoked_status_expected
    )
    assert _check_constraint_signature("status IN ('', 'revoked')") != (
        active_revoked_status_expected
    )
    assert (
        _check_constraint_signature("status IN ('active'::text, 'revoked'::text) OR TRUE")
        != active_revoked_status_expected
    )
    for invalid_cast_sql in (
        "status::text[] IN ('active', 'revoked')",
        "status IN ('active'::text[], 'revoked')",
        "status = ANY (ARRAY['active', 'revoked']::text)",
        "status::text[ IN ('active', 'revoked')",
        "status IN ('active'::text[, 'revoked')",
        "status = ANY (ARRAY['active', 'revoked']::text[)",
    ):
        assert _check_constraint_signature(invalid_cast_sql) != active_revoked_status_expected
    assert (
        _check_constraint_signature("status IN ('active::text', 'revoked')")
        != active_revoked_status_expected
    )
    assert (
        _check_constraint_signature(
            "(status IN ('in_progress', 'succeeded', 'failed'))::boolean OR TRUE"
        )
        != status_expected
    )
    assert (
        _check_constraint_signature(
            "(status IN ('in_progress', 'succeeded', 'failed'))::boolean AND FALSE"
        )
        != status_expected
    )
    assert _check_constraint_signature("status='succeeded' OR TRUE") != status_expected
    assert _check_constraint_signature("assurance_class='native' OR TRUE") != expected
    assert _check_constraint_signature("(assurance_class='native')::boolean OR TRUE") != expected
    assert _check_constraint_signature("(assurance_class='native')::boolean AND FALSE") != expected
    assert _check_constraint_signature(
        "(source_system='gove-zone')::boolean OR TRUE"
    ) != _check_constraint_signature("source_system='gove-zone'")
    assert _check_constraint_signature(
        "(source_system='gove-zone')::boolean AND FALSE"
    ) != _check_constraint_signature("source_system='gove-zone'")
    assert (
        _check_constraint_signature("assurance_class='native' AND source_system='gove-zone'")
        != expected
    )
    assert _check_constraint_signature("other_column='native'") != expected
    for rejected_pending_sql in (
        "other_status = 'pending'",
        "status = 'PENDING'",
        "status = 'pen ding'",
        "status = 'pend,ing'",
        "status = 'pend\"ing'",
        "status = 'pending::text'",
        "status::text[] = 'pending'",
        "status = 'pending'::text[]",
        "status = 'pending'::text::text",
        "(status::text)::text = 'pending'",
        "status = ('pending'::character varying)::text",
        "status = ARRAY['pending']",
        "status = 'pending' OR TRUE",
        "(status = 'pending')::boolean OR TRUE",
        "status = 'pending' AND FALSE",
        "'pending' = status",
        "status = current_setting('acgs.status')",
        "status = ('pending')::text::text",
        "status::text[ = 'pending'",
        "status = 'pending'::text[",
    ):
        assert _check_constraint_signature(rejected_pending_sql) != pending_status_expected


def test_schema_detail_accepts_postgresql_reflected_runtime_gate_status_check() -> None:
    class RuntimeGateStatusInspector:
        bind = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

        def __init__(self, sqltext: str) -> None:
            self.sqltext = sqltext

        def get_columns(
            self, table_name: str, *, schema: str | None = None
        ) -> list[dict[str, object]]:
            assert table_name == "runtime_identity_gates"
            assert schema == "public"
            return [
                {"name": "id", "nullable": False, "default": None, "type": postgresql.VARCHAR(64)},
                {
                    "name": "status",
                    "nullable": False,
                    "default": None,
                    "type": postgresql.VARCHAR(16),
                },
            ]

        def get_pk_constraint(
            self, table_name: str, *, schema: str | None = None
        ) -> dict[str, object]:
            assert table_name == "runtime_identity_gates"
            assert schema == "public"
            return {"constrained_columns": ["id"]}

        def get_foreign_keys(
            self, table_name: str, *, schema: str | None = None
        ) -> list[dict[str, object]]:
            assert table_name == "runtime_identity_gates"
            assert schema == "public"
            return []

        def get_unique_constraints(
            self, table_name: str, *, schema: str | None = None
        ) -> list[dict[str, object]]:
            assert table_name == "runtime_identity_gates"
            assert schema == "public"
            return []

        def get_indexes(
            self, table_name: str, *, schema: str | None = None
        ) -> list[dict[str, object]]:
            assert table_name == "runtime_identity_gates"
            assert schema == "public"
            return []

        def get_check_constraints(
            self, table_name: str, *, schema: str | None = None
        ) -> list[dict[str, object]]:
            assert table_name == "runtime_identity_gates"
            assert schema == "public"
            return [{"name": "ck_runtime_identity_gate_status", "sqltext": self.sqltext}]

    expected_columns = {
        "runtime_identity_gates": (
            _ColumnSpec("id", "string", False, 64),
            _ColumnSpec("status", "string", False, 16),
        )
    }
    expected_checks = {
        "runtime_identity_gates": frozenset(
            {("ck_runtime_identity_gate_status", "status IN ('active', 'revoked')")}
        )
    }
    shared_kwargs = {
        "actual_tables": {"runtime_identity_gates"},
        "expected_columns": expected_columns,
        "expected_primary_keys": {"runtime_identity_gates": ("id",)},
        "expected_foreign_keys": {"runtime_identity_gates": frozenset()},
        "expected_uniques": {"runtime_identity_gates": frozenset()},
        "expected_non_unique_indexes": {"runtime_identity_gates": frozenset()},
        "expected_checks": expected_checks,
    }

    assert (
        migration_module._schema_detail(
            RuntimeGateStatusInspector("status IN ('active', 'revoked')"),
            **shared_kwargs,
        )
        is None
    )
    assert (
        migration_module._schema_detail(
            RuntimeGateStatusInspector(
                "(status)::text = ANY "
                "((ARRAY['active'::character varying, "
                "'revoked'::character varying])::text[])"
            ),
            **shared_kwargs,
        )
        is None
    )
    assert (
        migration_module._schema_detail(
            RuntimeGateStatusInspector("status IN ('active', 'retired', 'revoked')"),
            **shared_kwargs,
        )
        == "runtime_identity_gates has unexpected check constraints"
    )
    for rejected_sqltext in (
        "status IN ('ACTIVE', 'revoked')",
        "status IN ('act ive', 'revoked')",
        "status IN ('active::text', 'revoked')",
        "status IN ('act\"ive', 'revoked')",
        "status IN ('active,revoked')",
        "status IN ('active,retired', 'revoked')",
        "status IN ('revoked', 'active')",
        "status IN ('active', 'retired', 'revoked')",
        "(status IN ('active', 'revoked'))::boolean OR TRUE",
        "other_status IN ('active', 'revoked')",
        "status IN ('active', 'active')",
        "status IN ('', 'revoked')",
        "status IN ('active::text', 'revoked')",
        "status::text[] IN ('active', 'revoked')",
        "status IN ('active'::text[], 'revoked')",
        "status = ANY (ARRAY['active', 'revoked']::text)",
        "status::text[ IN ('active', 'revoked')",
        "status IN ('active'::text[, 'revoked')",
        "status = ANY (ARRAY['active', 'revoked']::text[)",
    ):
        assert (
            migration_module._schema_detail(
                RuntimeGateStatusInspector(rejected_sqltext),
                **shared_kwargs,
            )
            == "runtime_identity_gates has unexpected check constraints"
        )


def test_schema_detail_accepts_postgresql_reflected_pending_approval_status_check() -> None:
    class PendingApprovalsStatusInspector:
        bind = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

        def __init__(self, sqltext: str) -> None:
            self.sqltext = sqltext

        def get_columns(
            self, table_name: str, *, schema: str | None = None
        ) -> list[dict[str, object]]:
            assert table_name == "pending_approvals"
            assert schema == "public"
            return [
                {"name": "id", "nullable": False, "default": None, "type": postgresql.VARCHAR(64)},
                {
                    "name": "status",
                    "nullable": False,
                    "default": None,
                    "type": postgresql.VARCHAR(16),
                },
            ]

        def get_pk_constraint(
            self, table_name: str, *, schema: str | None = None
        ) -> dict[str, object]:
            assert table_name == "pending_approvals"
            assert schema == "public"
            return {"constrained_columns": ["id"]}

        def get_foreign_keys(
            self, table_name: str, *, schema: str | None = None
        ) -> list[dict[str, object]]:
            assert table_name == "pending_approvals"
            assert schema == "public"
            return []

        def get_unique_constraints(
            self, table_name: str, *, schema: str | None = None
        ) -> list[dict[str, object]]:
            assert table_name == "pending_approvals"
            assert schema == "public"
            return []

        def get_indexes(
            self, table_name: str, *, schema: str | None = None
        ) -> list[dict[str, object]]:
            assert table_name == "pending_approvals"
            assert schema == "public"
            return []

        def get_check_constraints(
            self, table_name: str, *, schema: str | None = None
        ) -> list[dict[str, object]]:
            assert table_name == "pending_approvals"
            assert schema == "public"
            return [{"name": "ck_pending_approvals_status", "sqltext": self.sqltext}]

    expected_columns = {
        "pending_approvals": (
            _ColumnSpec("id", "string", False, 64),
            _ColumnSpec("status", "string", False, 16),
        )
    }
    expected_checks = {
        "pending_approvals": frozenset({("ck_pending_approvals_status", "status IN ('pending')")})
    }
    shared_kwargs = {
        "actual_tables": {"pending_approvals"},
        "expected_columns": expected_columns,
        "expected_primary_keys": {"pending_approvals": ("id",)},
        "expected_foreign_keys": {"pending_approvals": frozenset()},
        "expected_uniques": {"pending_approvals": frozenset()},
        "expected_non_unique_indexes": {"pending_approvals": frozenset()},
        "expected_checks": expected_checks,
    }

    assert (
        migration_module._schema_detail(
            PendingApprovalsStatusInspector("(status)::text = 'pending'::text"),
            **shared_kwargs,
        )
        is None
    )
    assert (
        migration_module._schema_detail(
            PendingApprovalsStatusInspector("status = 'pending'::text::text"),
            **shared_kwargs,
        )
        == "pending_approvals has unexpected check constraints"
    )


def test_upgrade_can_be_retried_after_a_completed_run(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path)

    first = upgrade_database(database_url)
    second = upgrade_database(database_url)

    assert first.after.state is DatabaseSchemaState.VERSION_0012
    assert second.before.state is DatabaseSchemaState.VERSION_0012
    assert second.after.state is DatabaseSchemaState.VERSION_0012


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
    assert result.after.state is DatabaseSchemaState.VERSION_0012


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
    assert result.after.state is DatabaseSchemaState.VERSION_0012
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
    assert result.after.state is DatabaseSchemaState.VERSION_0012


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
