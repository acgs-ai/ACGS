"""Fail-closed helpers for adopting the pre-Alembic control-plane schema.

The original v0 control plane used ``Base.metadata.create_all`` and therefore
has no migration version table.  This module recognizes only the frozen v0
schema reconstructed in revision ``0001``.  It refuses partial, unknown, or
mixed schemas *before* it creates an Alembic version table or runs a revision.

The mutation helpers are deliberate operator actions.  Schema-managed startup
reuses only the read-only classifier and never invokes Alembic or advances a
revision. No claim is made about backups, restore drills, or rollback safety.
PostgreSQL uses one caller-owned transaction and a nonblocking transaction-level
advisory lock for the controlled migration operation; that is not a replacement
for deployment orchestration or recovery procedures.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Connection, make_url
from sqlalchemy.engine.reflection import Inspector
from sqlalchemy.exc import SQLAlchemyError

from acgs_control_plane import models as _models  # noqa: F401  # load Base metadata
from acgs_control_plane.db import make_engine

LEGACY_V0_REVISION: Final = "0001"
SCOPED_REVISION: Final = "0002"
HEAD_REVISION: Final = "0003"
_VERSION_TABLE = "alembic_version"
_ALEMBIC_VERSION_TABLE: Final = sa.table(_VERSION_TABLE, sa.column("version_num"))
_SCOPE_TABLES: Final = MappingProxyType(
    {
        "projects": sa.table("projects"),
        "environments": sa.table("environments"),
    }
)
_SQLITE_INTERNAL_TABLES: Final = frozenset({"sqlite_sequence"})
_LEGACY_ADOPTION_TOKEN: Final = object()
_SCOPE_RESUME_TOKEN: Final = object()
# Fixed PostgreSQL two-int advisory-lock identifiers for the entire
# control-plane migration history.  They are deliberately not derived from a
# tenant, URL, schema, or caller-provided value: every operator of one target
# database must contend on the same migration lock.
_POSTGRES_MIGRATION_LOCK_CLASS_ID: Final = 1_010_100_101
_POSTGRES_MIGRATION_LOCK_OBJECT_ID: Final = 1_010_100_102
_POSTGRES_MIGRATION_LOCK_STATEMENT: Final = sa.select(
    sa.func.pg_catalog.pg_try_advisory_xact_lock(
        sa.bindparam("class_id", type_=sa.Integer()),
        sa.bindparam("object_id", type_=sa.Integer()),
    )
)
_POSTGRES_INITIAL_SCHEMA_INFO_KEY: Final = "acgs_control_plane_initial_schema"


class DatabaseSchemaState(StrEnum):
    """Database states recognized by the migration adoption guard."""

    EMPTY = "empty"
    LEGACY_V0 = "exact_legacy_v0"
    VERSION_0001 = "version_0001"
    VERSION_0001_PARTIAL_PROJECTS = "version_0001_partial_projects"
    VERSION_0001_PARTIAL_SCOPE = "version_0001_partial_scope"
    VERSION_0002 = "version_0002"
    VERSION_0003 = "version_0003"
    UNKNOWN = "unknown"


class ScopeMigrationResumeState(StrEnum):
    """Exact, empty states from which revision 0002 may resume."""

    FRESH = "fresh"
    PROJECTS_CREATED = "projects_created"
    SCOPE_TABLES_CREATED = "scope_tables_created"


class MigrationPreflightError(RuntimeError):
    """Raised before mutation when a database is not a known schema state."""


class StartupSchemaPreflightError(RuntimeError):
    """The application database is not the exact packaged schema revision."""

    code = "STARTUP_SCHEMA_NOT_CURRENT"
    stage = "pre-serving"

    def __init__(self, preflight: SchemaPreflight) -> None:
        self.schema_state = preflight.state
        super().__init__(
            f"{self.code}: expected {DatabaseSchemaState.VERSION_0003.value}; "
            f"found {preflight.state.value}. Run the acgs-control-plane migration CLI."
        )


class MigrationLockUnavailable(MigrationPreflightError):
    """The official PostgreSQL migration lock is held by another operator."""


class DatabaseIdentityMismatch(MigrationPreflightError):
    """The connected PostgreSQL database does not match the operator expectation."""


class DatabaseSchemaBindingMismatch(MigrationPreflightError):
    """The PostgreSQL connection is not bound to the canonical public schema."""


class UnsupportedMigrationDialect(MigrationPreflightError):
    """An identity-bound operator action targeted a non-PostgreSQL database."""


@dataclass(frozen=True)
class SchemaPreflight:
    """A narrow report suitable for operator logs without leaking row data."""

    state: DatabaseSchemaState
    detail: str


@dataclass(frozen=True)
class MigrationResult:
    """The pre- and post-migration schema states for one deliberate run."""

    before: SchemaPreflight
    after: SchemaPreflight


@dataclass(frozen=True)
class _ColumnSpec:
    name: str
    type_name: str
    nullable: bool
    length: int | None = None


_LEGACY_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = {
    "organizations": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("name", "string", False, 200),
        _ColumnSpec("created_at", "datetime", False),
        _ColumnSpec("audit_anchor_count", "integer", False),
        _ColumnSpec("audit_anchor_hash", "string", False, 128),
    ),
    "users": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("name", "string", False, 200),
        _ColumnSpec("email", "string", False, 320),
        _ColumnSpec("role", "string", False, 32),
        _ColumnSpec("api_key_hash", "string", False, 64),
        _ColumnSpec("active", "boolean", False),
        _ColumnSpec("created_at", "datetime", False),
    ),
    "agents": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("name", "string", False, 200),
        _ColumnSpec("description", "text", False),
        _ColumnSpec("trust_tier", "string", False, 32),
        _ColumnSpec("allowed_tools", "json", False),
        _ColumnSpec("status", "string", False, 16),
        _ColumnSpec("created_at", "datetime", False),
    ),
    "policy_bundles": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("policy_id", "string", False, 200),
        _ColumnSpec("version", "string", False, 200),
        _ColumnSpec("bundle", "json", False),
        _ColumnSpec("status", "string", False, 16),
        _ColumnSpec("created_at", "datetime", False),
        _ColumnSpec("activated_at", "datetime", True),
    ),
    "receipts": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("tool", "string", False, 200),
        _ColumnSpec("decision", "string", False, 16),
        _ColumnSpec("actor", "string", False, 200),
        _ColumnSpec("goal", "text", False),
        _ColumnSpec("argument_hash", "string", False, 128),
        _ColumnSpec("audit_hash", "string", False, 128),
        _ColumnSpec("policy_version", "string", False, 200),
        _ColumnSpec("result_hash", "string", True, 128),
        _ColumnSpec("error_class", "string", True, 200),
        _ColumnSpec("payload", "json", False),
        _ColumnSpec("created_at", "datetime", False),
    ),
    "compliance_exports": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("created_by", "string", False, 200),
        _ColumnSpec("receipt_count", "integer", False),
        _ColumnSpec("bundle_hash", "string", False, 128),
        _ColumnSpec("bundle", "json", False),
        _ColumnSpec("created_at", "datetime", False),
    ),
}

_SCOPED_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = {
    **_LEGACY_COLUMNS,
    "projects": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("slug", "string", False, 128),
        _ColumnSpec("name", "string", False, 200),
        _ColumnSpec("created_at", "datetime", False),
    ),
    "environments": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("slug", "string", False, 128),
        _ColumnSpec("name", "string", False, 200),
        _ColumnSpec("created_at", "datetime", False),
    ),
}
_MANAGED_MUTATION_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = {
    **_SCOPED_COLUMNS,
    "managed_decision_receipts": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("receipt_id", "string", False, 200),
        _ColumnSpec("receipt_hash", "string", False, 64),
        _ColumnSpec("audit_event_hash", "string", False, 64),
        _ColumnSpec("decision", "string", False, 16),
        _ColumnSpec("actor", "string", False, 200),
        _ColumnSpec("proposed_action", "string", False, 200),
        _ColumnSpec("execution_boundary", "string", False, 200),
        _ColumnSpec("policy_bundle_id", "string", False, 200),
        _ColumnSpec("policy_version", "string", False, 200),
        _ColumnSpec("policy_hash", "string", False, 128),
        _ColumnSpec("argument_hash", "string", False, 128),
        _ColumnSpec("signing_key_id", "string", False, 200),
        _ColumnSpec("signature_algorithm", "string", False, 32),
        _ColumnSpec("assurance_class", "string", False, 32),
        _ColumnSpec("source_system", "string", False, 64),
        _ColumnSpec("issued_at", "datetime", False),
        _ColumnSpec("expires_at", "datetime", False),
        _ColumnSpec("projection", "json", False),
        _ColumnSpec("created_at", "datetime", False),
    ),
    "managed_mutation_attempts": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("receipt_hash", "string", False, 64),
        _ColumnSpec("audit_event_hash", "string", False, 64),
        _ColumnSpec("action", "string", False, 200),
        _ColumnSpec("actor_hash", "string", False, 64),
        _ColumnSpec("argument_hash", "string", False, 128),
        _ColumnSpec("status", "string", False, 32),
        _ColumnSpec("failure_class_hash", "string", True, 64),
        _ColumnSpec("failure_digest", "string", True, 64),
        _ColumnSpec("created_at", "datetime", False),
        _ColumnSpec("updated_at", "datetime", False),
    ),
    "managed_receipt_consumptions": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("managed_receipt_id", "string", False, 64),
        _ColumnSpec("receipt_hash", "string", False, 64),
        _ColumnSpec("audit_event_hash", "string", False, 64),
        _ColumnSpec("consumed_at", "datetime", False),
    ),
    "managed_governance_event_heads": (
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("last_sequence", "integer", False),
        _ColumnSpec("last_event_hash", "string", False, 64),
        _ColumnSpec("updated_at", "datetime", False),
    ),
    "managed_governance_events": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("managed_receipt_id", "string", False, 64),
        _ColumnSpec("sequence", "integer", False),
        _ColumnSpec("previous_hash", "string", False, 64),
        _ColumnSpec("event_hash", "string", False, 64),
        _ColumnSpec("decision", "string", False, 16),
        _ColumnSpec("actor", "string", False, 200),
        _ColumnSpec("proposed_action", "string", False, 200),
        _ColumnSpec("policy_version", "string", False, 200),
        _ColumnSpec("payload_digest", "string", False, 64),
        _ColumnSpec("payload", "json", False),
        _ColumnSpec("created_at", "datetime", False),
    ),
    "managed_outbox": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("managed_receipt_id", "string", False, 64),
        _ColumnSpec("managed_event_id", "string", False, 64),
        _ColumnSpec("delivery_key", "string", False, 200),
        _ColumnSpec("payload_digest", "string", False, 64),
        _ColumnSpec("payload", "json", False),
        _ColumnSpec("status", "string", False, 32),
        _ColumnSpec("attempts", "integer", False),
        _ColumnSpec("created_at", "datetime", False),
        _ColumnSpec("available_at", "datetime", False),
        _ColumnSpec("delivered_at", "datetime", True),
    ),
}
_PROJECTS_ONLY_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = {
    **_LEGACY_COLUMNS,
    "projects": _SCOPED_COLUMNS["projects"],
}

_LEGACY_PRIMARY_KEYS: Final[dict[str, tuple[str, ...]]] = {
    table_name: ("id",) for table_name in _LEGACY_COLUMNS
}
_SCOPED_PRIMARY_KEYS: Final[dict[str, tuple[str, ...]]] = {
    table_name: ("id",) for table_name in _SCOPED_COLUMNS
}
_MANAGED_MUTATION_PRIMARY_KEYS: Final[dict[str, tuple[str, ...]]] = {
    **_SCOPED_PRIMARY_KEYS,
    "managed_decision_receipts": ("id",),
    "managed_mutation_attempts": ("id",),
    "managed_receipt_consumptions": ("id",),
    "managed_governance_event_heads": ("org_id", "project_id", "environment_id"),
    "managed_governance_events": ("id",),
    "managed_outbox": ("id",),
}
_PROJECTS_ONLY_PRIMARY_KEYS: Final[dict[str, tuple[str, ...]]] = {
    table_name: ("id",) for table_name in _PROJECTS_ONLY_COLUMNS
}

_ForeignKeySpec = tuple[tuple[str, ...], str | None, str, tuple[str, ...]]


_LEGACY_FOREIGN_KEYS: Final[dict[str, frozenset[_ForeignKeySpec]]] = {
    "organizations": frozenset(),
    "users": frozenset({(("org_id",), None, "organizations", ("id",))}),
    "agents": frozenset({(("org_id",), None, "organizations", ("id",))}),
    "policy_bundles": frozenset({(("org_id",), None, "organizations", ("id",))}),
    "receipts": frozenset({(("org_id",), None, "organizations", ("id",))}),
    "compliance_exports": frozenset({(("org_id",), None, "organizations", ("id",))}),
}
_SCOPED_FOREIGN_KEYS: Final[dict[str, frozenset[_ForeignKeySpec]]] = {
    **_LEGACY_FOREIGN_KEYS,
    "projects": frozenset({(("org_id",), None, "organizations", ("id",))}),
    "environments": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            (("org_id", "project_id"), None, "projects", ("org_id", "id")),
        }
    ),
}
_SCOPE_ENVIRONMENT_FK: Final[_ForeignKeySpec] = (
    ("org_id", "project_id", "environment_id"),
    None,
    "environments",
    ("org_id", "project_id", "id"),
)
_SCOPE_RECEIPT_FK: Final[_ForeignKeySpec] = (
    ("org_id", "project_id", "environment_id", "managed_receipt_id"),
    None,
    "managed_decision_receipts",
    ("org_id", "project_id", "environment_id", "id"),
)
_MANAGED_MUTATION_FOREIGN_KEYS: Final[dict[str, frozenset[_ForeignKeySpec]]] = {
    **_SCOPED_FOREIGN_KEYS,
    "managed_decision_receipts": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            _SCOPE_ENVIRONMENT_FK,
        }
    ),
    "managed_receipt_consumptions": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            _SCOPE_ENVIRONMENT_FK,
            _SCOPE_RECEIPT_FK,
        }
    ),
    "managed_mutation_attempts": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            _SCOPE_ENVIRONMENT_FK,
        }
    ),
    "managed_governance_event_heads": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            _SCOPE_ENVIRONMENT_FK,
        }
    ),
    "managed_governance_events": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            _SCOPE_ENVIRONMENT_FK,
            _SCOPE_RECEIPT_FK,
        }
    ),
    "managed_outbox": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            _SCOPE_ENVIRONMENT_FK,
            _SCOPE_RECEIPT_FK,
            (
                ("org_id", "project_id", "environment_id", "managed_event_id"),
                None,
                "managed_governance_events",
                ("org_id", "project_id", "environment_id", "id"),
            ),
        }
    ),
}
_PROJECTS_ONLY_FOREIGN_KEYS: Final[dict[str, frozenset[_ForeignKeySpec]]] = {
    **_LEGACY_FOREIGN_KEYS,
    "projects": _SCOPED_FOREIGN_KEYS["projects"],
}

_LEGACY_UNIQUES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    "organizations": frozenset({("name",)}),
    "users": frozenset({("org_id", "email"), ("api_key_hash",)}),
    "agents": frozenset({("org_id", "name")}),
    "policy_bundles": frozenset(),
    "receipts": frozenset(),
    "compliance_exports": frozenset(),
}
_SCOPED_UNIQUES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_LEGACY_UNIQUES,
    "projects": frozenset({("org_id", "slug"), ("org_id", "id")}),
    "environments": frozenset({("org_id", "project_id", "slug")}),
}
_MANAGED_MUTATION_UNIQUES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_SCOPED_UNIQUES,
    "environments": frozenset(
        {
            ("org_id", "project_id", "slug"),
            ("org_id", "project_id", "id"),
        }
    ),
    "managed_decision_receipts": frozenset(
        {
            ("org_id", "project_id", "environment_id", "id"),
            ("org_id", "project_id", "environment_id", "receipt_id"),
            ("org_id", "project_id", "environment_id", "receipt_hash"),
            ("org_id", "project_id", "environment_id", "audit_event_hash"),
            ("org_id", "receipt_hash"),
            ("org_id", "audit_event_hash"),
        }
    ),
    "managed_receipt_consumptions": frozenset(
        {
            ("org_id", "project_id", "environment_id", "managed_receipt_id"),
            ("org_id", "project_id", "environment_id", "receipt_hash"),
            ("org_id", "project_id", "environment_id", "audit_event_hash"),
            ("org_id", "receipt_hash"),
            ("org_id", "audit_event_hash"),
        }
    ),
    "managed_mutation_attempts": frozenset(
        {
            ("org_id", "receipt_hash"),
            ("org_id", "audit_event_hash"),
        }
    ),
    "managed_governance_event_heads": frozenset(),
    "managed_governance_events": frozenset(
        {
            ("org_id", "project_id", "environment_id", "id"),
            ("org_id", "project_id", "environment_id", "sequence"),
            ("org_id", "project_id", "environment_id", "event_hash"),
            ("org_id", "project_id", "environment_id", "managed_receipt_id"),
        }
    ),
    "managed_outbox": frozenset(
        {
            ("org_id", "project_id", "environment_id", "delivery_key"),
            ("org_id", "project_id", "environment_id", "payload_digest"),
        }
    ),
}
_PROJECTS_ONLY_UNIQUES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_LEGACY_UNIQUES,
    "projects": _SCOPED_UNIQUES["projects"],
}

_LEGACY_NON_UNIQUE_INDEXES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    "organizations": frozenset(),
    "users": frozenset({("org_id",)}),
    "agents": frozenset({("org_id",)}),
    "policy_bundles": frozenset({("org_id",)}),
    "receipts": frozenset({("org_id",), ("tool",), ("decision",), ("actor",), ("created_at",)}),
    "compliance_exports": frozenset({("org_id",)}),
}
_SCOPED_NON_UNIQUE_INDEXES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_LEGACY_NON_UNIQUE_INDEXES,
    # The unique scope keys have the same left prefixes, so standalone scope
    # indexes would be redundant and would create extra non-transactional DDL
    # interruption boundaries on SQLite.
    "projects": frozenset(),
    "environments": frozenset(),
}
_MANAGED_MUTATION_NON_UNIQUE_INDEXES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_SCOPED_NON_UNIQUE_INDEXES,
    "managed_decision_receipts": frozenset({("org_id",)}),
    "managed_mutation_attempts": frozenset({("org_id",)}),
    "managed_receipt_consumptions": frozenset({("org_id",)}),
    "managed_governance_event_heads": frozenset(),
    "managed_governance_events": frozenset({("org_id",)}),
    "managed_outbox": frozenset({("org_id",)}),
}
_MANAGED_MUTATION_CHECKS: Final[dict[str, frozenset[tuple[str, str]]]] = {
    **{table_name: frozenset() for table_name in _SCOPED_COLUMNS},
    "managed_decision_receipts": frozenset(
        {
            ("ck_mdr_assurance_native", "assurance_class='native'"),
            ("ck_mdr_source_gove_zone", "source_system='gove-zone'"),
        }
    ),
    "managed_mutation_attempts": frozenset(
        {
            (
                "ck_mma_terminal_status",
                "status IN ('in_progress', 'succeeded', 'failed')",
            ),
        }
    ),
    "managed_receipt_consumptions": frozenset(),
    "managed_governance_event_heads": frozenset(),
    "managed_governance_events": frozenset(),
    "managed_outbox": frozenset(),
}
_PROJECTS_ONLY_NON_UNIQUE_INDEXES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_LEGACY_NON_UNIQUE_INDEXES,
    "projects": _SCOPED_NON_UNIQUE_INDEXES["projects"],
}


def migration_config(database_url: str) -> Config:
    """Return the wheel-shipped Alembic configuration for one explicit URL."""
    package_root = Path(__file__).resolve().parent
    config_path = package_root / "alembic.ini"
    script_path = package_root / "migrations"
    if not config_path.is_file() or not script_path.is_dir():
        msg = (
            "The installed acgs-control-plane package is missing its Alembic resources. "
            "Reinstall a complete wheel; do not fall back to an unrelated source checkout."
        )
        raise RuntimeError(msg)

    config = Config(str(config_path))
    # Set absolute paths from the imported package, not the process CWD.  This
    # keeps source, editable, and installed-wheel execution on one canonical
    # migration history without a source-tree fallback.
    config.set_main_option("script_location", str(script_path))
    config.set_main_option("prepend_sys_path", str(package_root.parent))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def inspect_schema(database_url: str, *, expected_database: str | None = None) -> SchemaPreflight:
    """Classify a database without mutation, optionally binding PostgreSQL identity.

    Existing callers may omit ``expected_database`` and retain the original
    dialect-neutral inspection behavior. Operator-facing callers provide it so
    PostgreSQL verifies ``current_database()`` on the same live connection and
    transaction used for schema inspection.
    """
    if expected_database is not None:
        _assert_expected_postgresql_url(database_url, expected_database)
    engine = make_engine(database_url)
    if engine.dialect.name == "postgresql":
        _install_postgresql_operator_connection_guard(engine)
    try:
        with engine.connect() as connection:
            if expected_database is None:
                return inspect_connection(connection)
            with connection.begin():
                _bind_postgresql_operator_target(connection, expected_database)
                return inspect_connection(connection)
    finally:
        engine.dispose()


def inspect_connection(connection: Connection) -> SchemaPreflight:
    """Classify a live connection before an Alembic operation mutates it."""
    non_table_detail = _non_table_object_detail(connection)
    if non_table_detail is not None:
        return SchemaPreflight(DatabaseSchemaState.UNKNOWN, non_table_detail)

    inspector = sa.inspect(connection)
    inspection_schema = "public" if connection.dialect.name == "postgresql" else None
    table_names = set(inspector.get_table_names(schema=inspection_schema)) - _SQLITE_INTERNAL_TABLES
    if not table_names:
        return SchemaPreflight(DatabaseSchemaState.EMPTY, "database has no user tables")

    if _VERSION_TABLE not in table_names:
        legacy_detail = _schema_detail(
            inspector,
            table_names,
            _LEGACY_COLUMNS,
            _LEGACY_PRIMARY_KEYS,
            _LEGACY_FOREIGN_KEYS,
            _LEGACY_UNIQUES,
            _LEGACY_NON_UNIQUE_INDEXES,
        )
        if legacy_detail is None:
            return SchemaPreflight(
                DatabaseSchemaState.LEGACY_V0,
                "exact pre-Alembic v0 schema; safe to stamp revision 0001",
            )
        return SchemaPreflight(DatabaseSchemaState.UNKNOWN, legacy_detail)

    versions = _migration_versions(connection)
    user_tables = table_names - {_VERSION_TABLE}
    if versions == [LEGACY_V0_REVISION]:
        return _classify_revision_0001(connection, inspector, user_tables)
    if versions == [SCOPED_REVISION]:
        detail = _schema_detail(
            inspector,
            user_tables,
            _SCOPED_COLUMNS,
            _SCOPED_PRIMARY_KEYS,
            _SCOPED_FOREIGN_KEYS,
            _SCOPED_UNIQUES,
            _SCOPED_NON_UNIQUE_INDEXES,
        )
        if detail is None:
            return SchemaPreflight(DatabaseSchemaState.VERSION_0002, "known Alembic revision 0002")
        return SchemaPreflight(DatabaseSchemaState.UNKNOWN, detail)
    if versions == [HEAD_REVISION]:
        detail = _schema_detail(
            inspector,
            user_tables,
            _MANAGED_MUTATION_COLUMNS,
            _MANAGED_MUTATION_PRIMARY_KEYS,
            _MANAGED_MUTATION_FOREIGN_KEYS,
            _MANAGED_MUTATION_UNIQUES,
            _MANAGED_MUTATION_NON_UNIQUE_INDEXES,
            _MANAGED_MUTATION_CHECKS,
        )
        if detail is None:
            return SchemaPreflight(DatabaseSchemaState.VERSION_0003, "known Alembic revision 0003")
        return SchemaPreflight(DatabaseSchemaState.UNKNOWN, detail)

    return SchemaPreflight(
        DatabaseSchemaState.UNKNOWN,
        f"unrecognized Alembic version state: {versions!r}",
    )


def assert_current_startup_schema(connection: Connection) -> SchemaPreflight:
    """Require the exact packaged head using inspection only.

    The caller owns connection and transaction cleanup.  This function never
    stamps, upgrades, creates, repairs, or otherwise mutates schema or data.
    """
    preflight = inspect_connection(connection)
    if preflight.state is not DatabaseSchemaState.VERSION_0003:
        raise StartupSchemaPreflightError(preflight)
    return preflight


def assert_online_migration_operation(connection: Connection, config: Config) -> SchemaPreflight:
    """Reject raw online Alembic operations; permit only a helper-bound path.

    The internal helper records the exact preflight state in ``Config``
    attributes.  This is process-local and cannot be supplied through Alembic
    ``-x`` arguments, so an operator cannot bypass the live schema check from
    the CLI.  Rejecting raw operations even on an empty database prevents
    ``stamp`` or ``ensure_version`` from creating a bare version table with no
    schema.  Any state change between helper preflight and the live migration
    connection is rejected.
    """
    preflight = inspect_connection(connection)
    operation = config.attributes.get("acgs_control_plane_internal_operation")
    if operation == (_SCOPE_RESUME_TOKEN, preflight.state) or operation == (
        _LEGACY_ADOPTION_TOKEN,
        preflight.state,
    ):
        return preflight

    msg = (
        "Refusing a raw Alembic operation on a control-plane database "
        f"in state {preflight.state}: {preflight.detail}. Use upgrade_database(), "
        "which rechecks and records a controlled operation state."
    )
    raise MigrationPreflightError(msg)


def scope_migration_resume_state(connection: Connection) -> ScopeMigrationResumeState:
    """Return the only exact states in which revision 0002 may continue."""
    preflight = inspect_connection(connection)
    if preflight.state is DatabaseSchemaState.VERSION_0001:
        return ScopeMigrationResumeState.FRESH
    if preflight.state is DatabaseSchemaState.VERSION_0001_PARTIAL_PROJECTS:
        return ScopeMigrationResumeState.PROJECTS_CREATED
    if preflight.state is DatabaseSchemaState.VERSION_0001_PARTIAL_SCOPE:
        return ScopeMigrationResumeState.SCOPE_TABLES_CREATED
    msg = f"Revision 0002 cannot resume from {preflight.state}: {preflight.detail}"
    raise MigrationPreflightError(msg)


def upgrade_database(database_url: str, *, expected_database: str | None = None) -> MigrationResult:
    """Run the official Alembic path only after a fail-closed schema check.

    Exact legacy-v0 databases are stamped at revision ``0001`` *only after*
    their tables, columns, constraints, and indexes match the frozen schema.
    A partial or unknown database raises before Alembic can create its version
    table. Existing receipt/export rows are not read, rewritten, or scoped.

    Existing callers may omit ``expected_database``. Operator-facing callers
    provide it to bind PostgreSQL ``current_database()`` inside the same
    transaction that owns the advisory lock, preflight, and migration.
    """
    if expected_database is not None:
        _assert_expected_postgresql_url(database_url, expected_database)
    backend_name = make_url(database_url).get_backend_name()
    if backend_name == "postgresql":
        return _upgrade_postgresql_database(database_url, expected_database=expected_database)
    if expected_database is not None:
        raise UnsupportedMigrationDialect("Identity-bound migration operations require PostgreSQL.")

    # Keep the independently tested SQLite path intact.  SQLite's DDL
    # interruption/resume contract is intentionally different from the
    # transactional PostgreSQL operation below.
    return _upgrade_database_with_independent_connections(database_url)


def _upgrade_database_with_independent_connections(database_url: str) -> MigrationResult:
    """Run the existing non-PostgreSQL controlled migration path unchanged."""
    before = inspect_schema(database_url)
    if before.state is DatabaseSchemaState.UNKNOWN:
        raise MigrationPreflightError(before.detail)

    config = migration_config(database_url)
    if before.state is DatabaseSchemaState.LEGACY_V0:
        _run_controlled_operation(
            config,
            _LEGACY_ADOPTION_TOKEN,
            DatabaseSchemaState.LEGACY_V0,
            lambda: command.stamp(config, LEGACY_V0_REVISION),
        )
        stamped = inspect_schema(database_url)
        if stamped.state is not DatabaseSchemaState.VERSION_0001:
            msg = f"Legacy adoption stamp did not produce revision 0001: {stamped.detail}"
            raise MigrationPreflightError(msg)
        _run_controlled_operation(
            config,
            _SCOPE_RESUME_TOKEN,
            DatabaseSchemaState.VERSION_0001,
            lambda: command.upgrade(config, "head"),
        )
    else:
        _run_controlled_operation(
            config,
            _SCOPE_RESUME_TOKEN,
            before.state,
            lambda: command.upgrade(config, "head"),
        )
    after = inspect_schema(database_url)
    if after.state is not DatabaseSchemaState.VERSION_0003:
        msg = f"Migration ended in unexpected schema state: {after.state} ({after.detail})"
        raise MigrationPreflightError(msg)
    return MigrationResult(before=before, after=after)


def _upgrade_postgresql_database(
    database_url: str, *, expected_database: str | None = None
) -> MigrationResult:
    """Migrate PostgreSQL under one shared, caller-owned transaction.

    The transaction-level advisory lock is taken before the authoritative
    preflight.  The preflight, any legacy stamp, revision upgrade, and
    postflight therefore see one locked, atomic migration attempt.  Alembic is
    given this exact connection through ``Config.attributes`` so it must not
    create or commit a separate connection/transaction.
    """
    engine = make_engine(database_url)
    if expected_database is not None:
        _install_postgresql_operator_connection_guard(engine)
    try:
        with engine.connect() as connection:
            with connection.begin():
                if expected_database is not None:
                    _bind_postgresql_operator_target(connection, expected_database)
                _acquire_postgresql_migration_lock(connection)
                before = inspect_connection(connection)
                if before.state is DatabaseSchemaState.UNKNOWN:
                    raise MigrationPreflightError(before.detail)

                config = migration_config(database_url)
                config.attributes["connection"] = connection
                try:
                    if before.state is DatabaseSchemaState.LEGACY_V0:
                        _run_controlled_operation(
                            config,
                            _LEGACY_ADOPTION_TOKEN,
                            DatabaseSchemaState.LEGACY_V0,
                            lambda: command.stamp(config, LEGACY_V0_REVISION),
                        )
                        stamped = inspect_connection(connection)
                        if stamped.state is not DatabaseSchemaState.VERSION_0001:
                            msg = (
                                "Legacy adoption stamp did not produce revision 0001: "
                                f"{stamped.detail}"
                            )
                            raise MigrationPreflightError(msg)
                        _run_controlled_operation(
                            config,
                            _SCOPE_RESUME_TOKEN,
                            DatabaseSchemaState.VERSION_0001,
                            lambda: command.upgrade(config, "head"),
                        )
                    else:
                        _run_controlled_operation(
                            config,
                            _SCOPE_RESUME_TOKEN,
                            before.state,
                            lambda: command.upgrade(config, "head"),
                        )

                    after = inspect_connection(connection)
                    if after.state is not DatabaseSchemaState.VERSION_0003:
                        msg = (
                            "Migration ended in unexpected schema state: "
                            f"{after.state} ({after.detail})"
                        )
                        raise MigrationPreflightError(msg)
                    result = MigrationResult(before=before, after=after)
                finally:
                    config.attributes.pop("connection", None)

        return result
    finally:
        engine.dispose()


def _require_postgresql_dialect(connection: Connection) -> None:
    if connection.dialect.name != "postgresql":
        raise UnsupportedMigrationDialect("Identity-bound migration operations require PostgreSQL.")


def _assert_expected_postgresql_url(database_url: str, expected_database: str) -> None:
    """Reject a mismatched URL target before an engine or connection exists."""
    parsed_url = make_url(database_url)
    if parsed_url.get_backend_name() != "postgresql":
        raise UnsupportedMigrationDialect("Identity-bound migration operations require PostgreSQL.")
    if parsed_url.database != expected_database:
        raise DatabaseIdentityMismatch(
            "PostgreSQL URL database does not match the operator expectation."
        )


def _install_postgresql_operator_connection_guard(engine: sa.Engine) -> None:
    """Sanitize search-path resolution before SQLAlchemy initializes a connection.

    PostgreSQL's SQLAlchemy dialect discovers its default schema during the
    pool ``connect`` event with an unqualified function call. This guard is
    inserted ahead of dialect initialization, records the original schema with
    a schema-qualified probe, then pins the short-lived engine session to
    ``public``. Bound operations additionally use ``SET LOCAL`` below.
    """
    sa.event.listen(
        engine.pool,
        "connect",
        _guard_postgresql_dbapi_connection,
        insert=True,
    )


def install_postgresql_application_connection_guard(engine: sa.Engine) -> None:
    """Reject shadow-first PostgreSQL sessions and pin every accepted pool connection."""
    if engine.dialect.name != "postgresql":
        return
    expected_database = engine.url.database
    if not expected_database:
        raise DatabaseIdentityMismatch("PostgreSQL application URL must name its database.")

    def guard(dbapi_connection: Any, connection_record: Any) -> None:
        _guard_postgresql_application_connection(
            dbapi_connection,
            connection_record,
            expected_database,
        )

    sa.event.listen(
        engine.pool,
        "connect",
        guard,
        insert=True,
    )


def _guard_postgresql_application_connection(
    dbapi_connection: Any,
    _connection_record: Any,
    expected_database: str,
) -> None:
    previous_autocommit = dbapi_connection.autocommit
    dbapi_connection.autocommit = True
    try:
        with dbapi_connection.cursor() as cursor:
            cursor.execute("SELECT pg_catalog.current_database()")
            database_row = cursor.fetchone()
            if not database_row or database_row[0] != expected_database:
                raise DatabaseIdentityMismatch(
                    "PostgreSQL application database does not match its URL target."
                )
            cursor.execute("SELECT pg_catalog.current_schema()")
            row = cursor.fetchone()
            if not row or row[0] != "public":
                raise DatabaseSchemaBindingMismatch(
                    "PostgreSQL application target is not bound to the canonical public schema."
                )
            cursor.execute("SET SESSION search_path TO public")
    finally:
        dbapi_connection.autocommit = previous_autocommit


def _guard_postgresql_dbapi_connection(dbapi_connection: Any, connection_record: Any) -> None:
    previous_autocommit = dbapi_connection.autocommit
    dbapi_connection.autocommit = True
    try:
        with dbapi_connection.cursor() as cursor:
            cursor.execute("SELECT pg_catalog.current_schema()")
            row = cursor.fetchone()
            connection_record.info[_POSTGRES_INITIAL_SCHEMA_INFO_KEY] = row[0] if row else None
            cursor.execute("SET SESSION search_path TO public")
    finally:
        dbapi_connection.autocommit = previous_autocommit


def _bind_postgresql_operator_target(connection: Connection, expected_database: str) -> None:
    """Bind database and canonical schema inside the operator transaction.

    SQLAlchemy determines ``default_schema_name`` when the DBAPI connection is
    initialized. The connection guard records the original schema before that
    initialization and pins the engine session without invoking a shadowable
    function. A connection that began in a non-public schema is rejected even
    after ``SET LOCAL`` so cached dialect state cannot redirect reflection or
    Alembic. Leaving ``pg_catalog`` implicit makes PostgreSQL resolve it before
    ``public``; every explicit identity probe remains schema-qualified.
    """
    _require_postgresql_dialect(connection)
    current_database = connection.scalar(sa.text("SELECT pg_catalog.current_database()"))
    if current_database != expected_database:
        raise DatabaseIdentityMismatch(
            "Connected PostgreSQL database does not match the operator expectation."
        )

    original_schema = connection.info.get(_POSTGRES_INITIAL_SCHEMA_INFO_KEY)
    transaction_schema = connection.scalar(sa.text("SELECT pg_catalog.current_schema()"))
    connection.exec_driver_sql("SET LOCAL search_path TO public")
    pinned_schema = connection.scalar(sa.text("SELECT pg_catalog.current_schema()"))
    pinned_search_path = connection.scalar(
        sa.text("SELECT pg_catalog.current_setting('search_path')")
    )
    if (
        original_schema != "public"
        or transaction_schema != "public"
        or connection.dialect.default_schema_name != "public"
        or pinned_schema != "public"
        or pinned_search_path != "public"
    ):
        raise DatabaseSchemaBindingMismatch(
            "PostgreSQL operator target is not bound to the canonical public schema."
        )


def _acquire_postgresql_migration_lock(connection: Connection) -> None:
    """Take the fixed nonblocking xact lock or refuse before schema mutation."""
    acquired = connection.scalar(
        _POSTGRES_MIGRATION_LOCK_STATEMENT,
        {
            "class_id": _POSTGRES_MIGRATION_LOCK_CLASS_ID,
            "object_id": _POSTGRES_MIGRATION_LOCK_OBJECT_ID,
        },
    )
    if acquired:
        return
    msg = (
        "PostgreSQL control-plane migration lock is held by another operator; "
        "no schema or version mutation was attempted. Retry after that migration finishes."
    )
    raise MigrationLockUnavailable(msg)


def _run_controlled_operation(
    config: Config,
    token: object,
    expected_state: DatabaseSchemaState,
    operation: Callable[[], None],
) -> None:
    config.attributes["acgs_control_plane_internal_operation"] = (token, expected_state)
    try:
        operation()
    finally:
        config.attributes.pop("acgs_control_plane_internal_operation", None)


def _classify_revision_0001(
    connection: Connection, inspector: Inspector, user_tables: set[str]
) -> SchemaPreflight:
    legacy_detail = _schema_detail(
        inspector,
        user_tables,
        _LEGACY_COLUMNS,
        _LEGACY_PRIMARY_KEYS,
        _LEGACY_FOREIGN_KEYS,
        _LEGACY_UNIQUES,
        _LEGACY_NON_UNIQUE_INDEXES,
    )
    if legacy_detail is None:
        return SchemaPreflight(DatabaseSchemaState.VERSION_0001, "known Alembic revision 0001")

    projects_detail = _schema_detail(
        inspector,
        user_tables,
        _PROJECTS_ONLY_COLUMNS,
        _PROJECTS_ONLY_PRIMARY_KEYS,
        _PROJECTS_ONLY_FOREIGN_KEYS,
        _PROJECTS_ONLY_UNIQUES,
        _PROJECTS_ONLY_NON_UNIQUE_INDEXES,
    )
    if projects_detail is None:
        empty_detail = _scope_tables_empty(connection, ("projects",))
        if empty_detail is None:
            return SchemaPreflight(
                DatabaseSchemaState.VERSION_0001_PARTIAL_PROJECTS,
                "exact, empty projects table exists before revision 0002 was recorded",
            )
        return SchemaPreflight(DatabaseSchemaState.UNKNOWN, empty_detail)

    scoped_detail = _schema_detail(
        inspector,
        user_tables,
        _SCOPED_COLUMNS,
        _SCOPED_PRIMARY_KEYS,
        _SCOPED_FOREIGN_KEYS,
        _SCOPED_UNIQUES,
        _SCOPED_NON_UNIQUE_INDEXES,
    )
    if scoped_detail is None:
        empty_detail = _scope_tables_empty(connection, ("projects", "environments"))
        if empty_detail is None:
            return SchemaPreflight(
                DatabaseSchemaState.VERSION_0001_PARTIAL_SCOPE,
                "exact, empty scope tables exist before revision 0002 was recorded",
            )
        return SchemaPreflight(DatabaseSchemaState.UNKNOWN, empty_detail)

    if user_tables == set(_PROJECTS_ONLY_COLUMNS):
        return SchemaPreflight(DatabaseSchemaState.UNKNOWN, projects_detail)
    if user_tables == set(_SCOPED_COLUMNS):
        return SchemaPreflight(DatabaseSchemaState.UNKNOWN, scoped_detail)
    return SchemaPreflight(DatabaseSchemaState.UNKNOWN, legacy_detail)


def _migration_versions(connection: Connection) -> list[str]:
    version_table = _ALEMBIC_VERSION_TABLE
    if connection.dialect.name == "postgresql":
        version_table = sa.table(
            _VERSION_TABLE,
            sa.column("version_num"),
            schema="public",
        )
    rows = connection.execute(sa.select(version_table.c.version_num))
    return list(rows.scalars())


def _scope_tables_empty(connection: Connection, table_names: Sequence[str]) -> str | None:
    unexpected_table_names = sorted(set(table_names) - set(_SCOPE_TABLES))
    if unexpected_table_names:
        return (
            "unsupported scope table names for the bounded migration probe: "
            f"{unexpected_table_names!r}"
        )

    try:
        for table_name in table_names:
            table = _SCOPE_TABLES[table_name]
            if connection.dialect.name == "postgresql":
                table = sa.table(table_name, schema="public")
            statement = sa.select(sa.literal(1)).select_from(table).limit(1)
            row = connection.execute(statement).first()
            if row is not None:
                return f"partial scope table {table_name} contains data and cannot be resumed"
    except SQLAlchemyError as exc:
        return f"unable to inspect partial scope tables: {type(exc).__name__}"
    return None


def _non_table_object_detail(connection: Connection) -> str | None:
    """Reject schema objects that migration revisions do not own or model."""
    try:
        dialect_name = connection.dialect.name
        if dialect_name == "sqlite":
            rows = connection.execute(
                sa.text(
                    """
                    SELECT type, name FROM sqlite_master
                    WHERE type IN ('view', 'trigger') AND name NOT LIKE 'sqlite_%'
                    UNION ALL
                    SELECT type, name FROM sqlite_temp_master
                    WHERE type IN ('view', 'trigger') AND name NOT LIKE 'sqlite_%'
                    ORDER BY type, name
                    """
                )
            ).all()
        elif dialect_name == "postgresql":
            rows = connection.execute(
                sa.text(
                    """
                    WITH non_table_objects AS (
                        SELECT 'view' AS kind, schemaname || '.' || viewname AS object_name
                        FROM pg_catalog.pg_views
                        WHERE schemaname = 'public'
                        UNION ALL
                        SELECT 'materialized_view', schemaname || '.' || matviewname
                        FROM pg_catalog.pg_matviews
                        WHERE schemaname = 'public'
                        UNION ALL
                        SELECT 'trigger', n.nspname || '.' || c.relname || '.' || t.tgname
                        FROM pg_catalog.pg_trigger AS t
                        JOIN pg_catalog.pg_class AS c ON c.oid = t.tgrelid
                        JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                        WHERE NOT t.tgisinternal
                          AND n.nspname = 'public'
                        UNION ALL
                        SELECT 'row_level_security', n.nspname || '.' || c.relname
                        FROM pg_catalog.pg_class AS c
                        JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                        WHERE (c.relrowsecurity OR c.relforcerowsecurity)
                          AND n.nspname = 'public'
                        UNION ALL
                        SELECT 'policy', schemaname || '.' || tablename || '.' || policyname
                        FROM pg_catalog.pg_policies
                        WHERE schemaname = 'public'
                        UNION ALL
                        SELECT
                            CASE p.prokind
                                WHEN 'p' THEN 'procedure'
                                WHEN 'a' THEN 'aggregate'
                                WHEN 'w' THEN 'window_function'
                                ELSE 'function'
                            END,
                            n.nspname || '.' || p.proname || '('
                            || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')'
                        FROM pg_catalog.pg_proc AS p
                        JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
                        WHERE n.nspname = 'public'
                        UNION ALL
                        SELECT 'sequence', n.nspname || '.' || c.relname
                        FROM pg_catalog.pg_class AS c
                        JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public'
                          AND c.relkind = 'S'
                        UNION ALL
                        SELECT
                            CASE t.typtype
                                WHEN 'd' THEN 'domain'
                                WHEN 'e' THEN 'enum'
                                WHEN 'c' THEN 'composite_type'
                                WHEN 'r' THEN 'range_type'
                                WHEN 'm' THEN 'multirange_type'
                                ELSE 'base_type'
                            END,
                            n.nspname || '.' || t.typname
                        FROM pg_catalog.pg_type AS t
                        JOIN pg_catalog.pg_namespace AS n ON n.oid = t.typnamespace
                        LEFT JOIN pg_catalog.pg_class AS c ON c.oid = t.typrelid
                        WHERE n.nspname = 'public'
                          AND t.typtype IN ('b', 'c', 'd', 'e', 'r', 'm')
                          AND NOT (t.typtype = 'b' AND t.typelem <> 0)
                          AND NOT (
                              t.typtype = 'c'
                              AND c.reltype = t.oid
                              AND c.relkind IN ('r', 'p')
                          )
                        UNION ALL
                        SELECT 'rewrite_rule', n.nspname || '.' || c.relname || '.' || r.rulename
                        FROM pg_catalog.pg_rewrite AS r
                        JOIN pg_catalog.pg_class AS c ON c.oid = r.ev_class
                        JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public'
                          AND r.rulename <> '_RETURN'
                    )
                    SELECT kind, object_name FROM non_table_objects ORDER BY kind, object_name
                    """
                )
            ).all()
        else:
            return f"unsupported migration schema-inspection dialect: {dialect_name}"
    except SQLAlchemyError as exc:
        return f"unable to inspect non-table schema objects: {type(exc).__name__}"

    if rows:
        objects = ", ".join(f"{row[0]}:{row[1]}" for row in rows)
        return f"unexpected non-table schema objects: {objects}"
    return None


def _canonical_referred_schema(value: object, dialect_name: str) -> str | None:
    """Map the dialect's canonical local schema to the frozen ``None`` sentinel."""
    canonical = {"postgresql": "public", "sqlite": "main"}.get(dialect_name)
    if value is None or (canonical is not None and value == canonical):
        return None
    return str(value)


def _schema_detail(
    inspector: Inspector,
    actual_tables: set[str],
    expected_columns: dict[str, tuple[_ColumnSpec, ...]],
    expected_primary_keys: dict[str, tuple[str, ...]],
    expected_foreign_keys: dict[str, frozenset[_ForeignKeySpec]],
    expected_uniques: dict[str, frozenset[tuple[str, ...]]],
    expected_non_unique_indexes: dict[str, frozenset[tuple[str, ...]]],
    expected_checks: dict[str, frozenset[tuple[str, str]]] | None = None,
) -> str | None:
    expected_tables = set(expected_columns)
    if actual_tables != expected_tables:
        return (
            f"unexpected table set: expected {sorted(expected_tables)}, got {sorted(actual_tables)}"
        )

    dialect_name = inspector.bind.dialect.name
    inspection_schema = "public" if dialect_name == "postgresql" else None
    expected_checks_by_table = expected_checks or {
        table_name: frozenset() for table_name in expected_columns
    }

    for table_name, columns in expected_columns.items():
        actual_columns = inspector.get_columns(table_name, schema=inspection_schema)
        if [column["name"] for column in actual_columns] != [column.name for column in columns]:
            return f"{table_name} has an unexpected column layout"
        for actual, expected in zip(actual_columns, columns, strict=True):
            if actual["nullable"] is not expected.nullable:
                return f"{table_name}.{expected.name} has an unexpected nullability"
            if actual.get("default") is not None:
                return f"{table_name}.{expected.name} has an unexpected server default"
            if not _matches_type(actual["type"], expected, dialect_name):
                return f"{table_name}.{expected.name} has an unexpected type"

        actual_primary_key = tuple(
            inspector.get_pk_constraint(table_name, schema=inspection_schema)["constrained_columns"]
            or ()
        )
        if actual_primary_key != expected_primary_keys[table_name]:
            return f"{table_name} has an unexpected primary key"

        foreign_keys = inspector.get_foreign_keys(table_name, schema=inspection_schema)
        if any(foreign_key.get("options") for foreign_key in foreign_keys):
            return f"{table_name} has foreign-key options outside the frozen schema"
        actual_foreign_keys = frozenset(
            (
                tuple(foreign_key["constrained_columns"]),
                _canonical_referred_schema(foreign_key.get("referred_schema"), dialect_name),
                foreign_key["referred_table"],
                tuple(foreign_key["referred_columns"]),
            )
            for foreign_key in foreign_keys
        )
        if actual_foreign_keys != expected_foreign_keys[table_name]:
            return f"{table_name} has unexpected foreign keys"

        actual_uniques: set[tuple[str, ...]] = set()
        for constraint in inspector.get_unique_constraints(table_name, schema=inspection_schema):
            column_names = _reflected_column_tuple(constraint["column_names"])
            if column_names is None:
                return f"{table_name} has an unnamed unique constraint"
            actual_uniques.add(column_names)
        actual_indexes: set[tuple[str, ...]] = set()
        for index in inspector.get_indexes(table_name, schema=inspection_schema):
            column_names = _reflected_column_tuple(index["column_names"])
            if column_names is None:
                return f"{table_name} has an unnamed index"
            if index.get("unique"):
                actual_uniques.add(column_names)
            else:
                actual_indexes.add(column_names)
        if frozenset(actual_uniques) != expected_uniques[table_name]:
            return f"{table_name} has unexpected unique constraints or indexes"

        if frozenset(actual_indexes) != expected_non_unique_indexes[table_name]:
            return f"{table_name} has unexpected non-unique indexes"

        actual_checks = frozenset(
            (
                str(constraint.get("name") or ""),
                _check_constraint_signature(constraint.get("sqltext")),
            )
            for constraint in inspector.get_check_constraints(table_name, schema=inspection_schema)
        )
        expected_check_signatures = frozenset(
            (name, _check_constraint_signature(sqltext))
            for name, sqltext in expected_checks_by_table[table_name]
        )
        if actual_checks != expected_check_signatures:
            return f"{table_name} has unexpected check constraints"

    return None


def _normalized_constraint_sql(value: object) -> str:
    return "".join(str(value or "").replace('"', "").split())


def _check_constraint_signature(value: object) -> str:
    raw = str(value or "").lower()
    compact = _normalized_constraint_sql(
        re.sub(
            r"::(?:text|character\s+varying)(?:\[\])?",
            "",
            raw,
            flags=re.IGNORECASE,
        )
    ).lower()
    compact = compact.replace("(assurance_class)", "assurance_class")
    compact = compact.replace("(source_system)", "source_system")
    compact = compact.replace("(status)", "status")
    compact = re.sub(r"\('([^']+)'\)", r"'\1'", compact)
    compact = _strip_outer_parentheses(compact)

    if compact == "assurance_class='native'":
        return "assurance_class:native"
    if compact == "source_system='gove-zone'":
        return "source_system:gove-zone"
    if compact in {
        "statusin('in_progress','succeeded','failed')",
        "status=any(array['in_progress','succeeded','failed'])",
    }:
        return "status:in_progress,succeeded,failed"
    return compact


def _strip_outer_parentheses(value: str) -> str:
    result = value
    while result.startswith("(") and result.endswith(")"):
        depth = 0
        encloses_entire_expression = True
        for index, character in enumerate(result):
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0 and index != len(result) - 1:
                    encloses_entire_expression = False
                    break
        if not encloses_entire_expression:
            break
        result = result[1:-1]
    return result


def _reflected_column_tuple(column_names: Sequence[str | None] | None) -> tuple[str, ...] | None:
    if not column_names or any(column is None for column in column_names):
        return None
    return tuple(column for column in column_names if column is not None)


def _matches_type(
    actual_type: sa.types.TypeEngine[object], expected: _ColumnSpec, dialect_name: str
) -> bool:
    if expected.type_name == "string":
        return (
            isinstance(actual_type, sa.String)
            and not isinstance(actual_type, sa.Text)
            and actual_type.length == expected.length
        )
    if expected.type_name == "text":
        return isinstance(actual_type, sa.Text)
    if expected.type_name == "datetime":
        if not isinstance(actual_type, sa.DateTime):
            return False
        # SQLite reflection does not preserve ``timezone=True``.  PostgreSQL,
        # the supported production dialect, must preserve it so a naive
        # timestamp schema is never stamped as the known v0 contract.
        return dialect_name == "sqlite" or (
            dialect_name == "postgresql" and actual_type.timezone is True
        )
    if expected.type_name == "integer":
        return isinstance(actual_type, sa.Integer) and not isinstance(actual_type, sa.Boolean)
    if expected.type_name == "boolean":
        return isinstance(actual_type, sa.Boolean)
    if expected.type_name == "json":
        if dialect_name == "postgresql":
            return isinstance(actual_type, postgresql.JSONB)
        return dialect_name == "sqlite" and isinstance(actual_type, sa.JSON)
    msg = f"unknown frozen schema type {expected.type_name!r}"
    raise AssertionError(msg)
