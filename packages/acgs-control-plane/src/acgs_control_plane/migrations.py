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

import json
import re
from collections.abc import Callable, Mapping, Sequence
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
from acgs_control_plane.runtime_lineage_schema import (
    POSTGRES_RUNTIME_LINEAGE_FUNCTIONS,
    POSTGRES_RUNTIME_LINEAGE_FUNCTIONS_0012,
    POSTGRES_RUNTIME_LINEAGE_TRIGGER_ENABLED_STATES,
    POSTGRES_RUNTIME_LINEAGE_TRIGGER_ENABLED_STATES_0012,
    POSTGRES_RUNTIME_LINEAGE_TRIGGERS,
    POSTGRES_RUNTIME_LINEAGE_TRIGGERS_0012,
    SQLITE_RUNTIME_LINEAGE_OBJECTS,
    SQLITE_RUNTIME_LINEAGE_OBJECTS_0012,
)

LEGACY_V0_REVISION: Final = "0001"
SCOPED_REVISION: Final = "0002"
MANAGED_MUTATION_REVISION: Final = "0003"
TRUST_V2_REVISION: Final = "0004"
TENANT_BOOTSTRAP_REVISION: Final = "0005"
AGENT_SCOPE_REVISION: Final = "0006"
AGENT_REGISTRATION_IDEMPOTENCY_REVISION: Final = "0007"
POLICY_REGISTRY_REVISION: Final = "0008"
APPROVAL_SUBSTRATE_REVISION: Final = "0009"
APPROVAL_VOTE_BINDING_REVISION: Final = "0010"
RUNTIME_ENROLLMENT_REVISION: Final = "0011"
RUNTIME_REPORTS_REVISION: Final = "0012"
RUNTIME_CHALLENGE_CONSUMPTION_IMMUTABILITY_REVISION: Final = "0013"
HEAD_REVISION: Final = RUNTIME_CHALLENGE_CONSUMPTION_IMMUTABILITY_REVISION
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
    VERSION_0004 = "version_0004"
    VERSION_0005 = "version_0005"
    VERSION_0006 = "version_0006"
    VERSION_0007 = "version_0007"
    VERSION_0008 = "version_0008"
    VERSION_0009 = "version_0009"
    VERSION_0010 = "version_0010"
    VERSION_0011 = "version_0011"
    VERSION_0012 = "version_0012"
    VERSION_0013 = "version_0013"
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
            f"{self.code}: expected {DatabaseSchemaState.VERSION_0013.value}; "
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


def _with_nullable_user_api_key_hash(
    columns_by_table: dict[str, tuple[_ColumnSpec, ...]],
) -> dict[str, tuple[_ColumnSpec, ...]]:
    return {
        **columns_by_table,
        "users": tuple(
            _ColumnSpec("api_key_hash", "string", True, 64)
            if column.name == "api_key_hash"
            else column
            for column in columns_by_table["users"]
        ),
    }


def _detail_after_nullable_user_fallback(primary_detail: str, fallback_detail: str) -> str:
    if primary_detail == "users.api_key_hash has an unexpected nullability":
        return fallback_detail
    return primary_detail


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
_LEGACY_CREATE_ALL_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = (
    _with_nullable_user_api_key_hash(_LEGACY_COLUMNS)
)

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
_SCOPED_CREATE_ALL_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = (
    _with_nullable_user_api_key_hash(_SCOPED_COLUMNS)
)
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
_MANAGED_MUTATION_CREATE_ALL_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = (
    _with_nullable_user_api_key_hash(_MANAGED_MUTATION_COLUMNS)
)
_TRUST_V2_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = {
    **{
        table_name: columns
        for table_name, columns in _MANAGED_MUTATION_COLUMNS.items()
        if table_name != "managed_decision_receipts"
    },
    "managed_decision_receipts": (
        *_MANAGED_MUTATION_COLUMNS["managed_decision_receipts"],
        _ColumnSpec("receipt_schema_version", "string", True, 64),
        _ColumnSpec("trust_epoch", "integer", True),
    ),
    "managed_trust_scopes": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("purpose", "string", False, 64),
        _ColumnSpec("created_at", "datetime", False),
        _ColumnSpec("updated_at", "datetime", False),
    ),
    "managed_trust_keys": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("purpose", "string", False, 64),
        _ColumnSpec("key_id", "string", False, 200),
        _ColumnSpec("algorithm", "string", False, 32),
        _ColumnSpec("public_key_spki_der", "binary", False),
        _ColumnSpec("activated_epoch", "integer", False),
        _ColumnSpec("not_after", "datetime", False),
        _ColumnSpec("status", "string", False, 16),
        _ColumnSpec("retired_epoch", "integer", True),
        _ColumnSpec("created_at", "datetime", False),
        _ColumnSpec("updated_at", "datetime", False),
    ),
}
_TRUST_V2_CREATE_ALL_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = (
    _with_nullable_user_api_key_hash(_TRUST_V2_COLUMNS)
)
_TENANT_BOOTSTRAP_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = {
    **_TRUST_V2_CREATE_ALL_COLUMNS,
    "organization_memberships": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("user_id", "string", False, 64),
        _ColumnSpec("role", "string", False, 32),
        _ColumnSpec("created_at", "datetime", False),
    ),
    "platform_bootstrap_invitations": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("token_hash", "string", False, 64),
        _ColumnSpec("invitee_actor", "string", False, 200),
        _ColumnSpec("invitee_role", "string", False, 64),
        _ColumnSpec("prospective_org_id", "string", False, 64),
        _ColumnSpec("prospective_project_id", "string", False, 64),
        _ColumnSpec("prospective_environment_id", "string", False, 64),
        _ColumnSpec("prospective_membership_id", "string", False, 64),
        _ColumnSpec("policy_outcome", "string", False, 16),
        _ColumnSpec("revoked_at", "datetime", True),
        _ColumnSpec("consumed_at", "datetime", True),
        _ColumnSpec("consumed_org_id", "string", True, 64),
        _ColumnSpec("created_at", "datetime", False),
        _ColumnSpec("expires_at", "datetime", False),
    ),
    "tenant_bootstrap_idempotency": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("idempotency_key", "string", False, 200),
        _ColumnSpec("actor", "string", False, 200),
        _ColumnSpec("request_hash", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("response", "json", False),
        _ColumnSpec("created_at", "datetime", False),
    ),
    "tenant_bootstrap_policy_artifacts": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("invitation_id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("decision", "string", False, 16),
        _ColumnSpec("receipt_hash", "string", False, 64),
        _ColumnSpec("audit_event_hash", "string", False, 64),
        _ColumnSpec("sealed_receipt", "json", False),
        _ColumnSpec("event", "json", False),
        _ColumnSpec("created_at", "datetime", False),
    ),
    "pending_approvals": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("actor", "string", False, 200),
        _ColumnSpec("action", "string", False, 200),
        _ColumnSpec("invitation_id", "string", False, 64),
        _ColumnSpec("policy_artifact_id", "string", False, 64),
        _ColumnSpec("receipt_hash", "string", False, 64),
        _ColumnSpec("audit_event_hash", "string", False, 64),
        _ColumnSpec("lineage", "json", False),
        _ColumnSpec("status", "string", False, 32),
        _ColumnSpec("created_at", "datetime", False),
    ),
    "tenant_bootstrap_pending_outbox": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("invitation_id", "string", False, 64),
        _ColumnSpec("policy_artifact_id", "string", False, 64),
        _ColumnSpec("delivery_key", "string", False, 200),
        _ColumnSpec("payload_digest", "string", False, 64),
        _ColumnSpec("payload", "json", False),
        _ColumnSpec("status", "string", False, 32),
        _ColumnSpec("attempts", "integer", False),
        _ColumnSpec("created_at", "datetime", False),
        _ColumnSpec("available_at", "datetime", False),
        _ColumnSpec("delivered_at", "datetime", True),
    ),
    "tenant_bootstrap_refusal_events": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("request_id", "string", False, 64),
        _ColumnSpec("route", "string", False, 64),
        _ColumnSpec("method", "string", False, 8),
        _ColumnSpec("stage", "string", False, 32),
        _ColumnSpec("code", "string", False, 64),
        _ColumnSpec("http_status", "integer", False),
        _ColumnSpec("invitation_id", "string", True, 64),
        _ColumnSpec("invitation_digest", "string", True, 64),
        _ColumnSpec("idempotency_digest", "string", True, 64),
        _ColumnSpec("event_hash", "string", False, 64),
        _ColumnSpec("created_at", "datetime", False),
    ),
}
_AGENT_SCOPE_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = {
    **_TENANT_BOOTSTRAP_COLUMNS,
    "agents": (
        *_TENANT_BOOTSTRAP_COLUMNS["agents"],
        _ColumnSpec("project_id", "string", True, 64),
        _ColumnSpec("environment_id", "string", True, 64),
    ),
}
_AGENT_REGISTRATION_IDEMPOTENCY_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = {
    **_AGENT_SCOPE_COLUMNS,
    "agent_registration_idempotency": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("idempotency_key_hash", "string", False, 64),
        _ColumnSpec("actor_hash", "string", False, 64),
        _ColumnSpec("request_hash", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("agent_id", "string", True, 64),
        _ColumnSpec("receipt_id", "string", False, 200),
        _ColumnSpec("response", "json", False),
        _ColumnSpec("created_at", "datetime", False),
    ),
}
_POLICY_REGISTRY_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = {
    **_AGENT_REGISTRATION_IDEMPOTENCY_COLUMNS,
    "policy_versions": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("policy_id", "string", False, 200),
        _ColumnSpec("version", "string", False, 200),
        _ColumnSpec("content_hash", "string", False, 64),
        _ColumnSpec("document", "json", False),
        _ColumnSpec("rules", "json", False),
        _ColumnSpec("canonical_envelope", "json", False),
        _ColumnSpec("purpose", "string", False, 64),
        _ColumnSpec("key_id", "string", False, 200),
        _ColumnSpec("signature_algorithm", "string", False, 32),
        _ColumnSpec("signature", "text", False),
        _ColumnSpec("trust_epoch", "integer", False),
        _ColumnSpec("receipt_id", "string", False, 200),
        _ColumnSpec("created_at", "datetime", False),
    ),
    "environment_policy_heads": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("active_policy_version_id", "string", False, 64),
        _ColumnSpec("generation", "integer", False),
        _ColumnSpec("status", "string", False, 16),
        _ColumnSpec("receipt_id", "string", False, 200),
        _ColumnSpec("created_at", "datetime", False),
        _ColumnSpec("updated_at", "datetime", False),
    ),
    "policy_registry_idempotency": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("idempotency_key_hash", "string", False, 64),
        _ColumnSpec("actor_hash", "string", False, 64),
        _ColumnSpec("request_hash", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("action", "string", False, 200),
        _ColumnSpec("receipt_id", "string", False, 200),
        _ColumnSpec("response", "json", False),
        _ColumnSpec("created_at", "datetime", False),
    ),
}
_APPROVAL_SUBSTRATE_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = {
    **_POLICY_REGISTRY_COLUMNS,
    "approval_requests": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("action", "string", False, 200),
        _ColumnSpec("requester_actor_hash", "string", False, 64),
        _ColumnSpec("validator_role", "string", False, 200),
        _ColumnSpec("authority", "string", False, 200),
        _ColumnSpec("approver_role", "string", False, 32),
        _ColumnSpec("argument_hash", "string", False, 128),
        _ColumnSpec("request_hash", "string", False, 64),
        _ColumnSpec("policy_bundle_id", "string", False, 200),
        _ColumnSpec("policy_version", "string", False, 200),
        _ColumnSpec("policy_hash", "string", False, 128),
        _ColumnSpec("policy_head_generation", "integer", False),
        _ColumnSpec("trust_epoch", "integer", False),
        _ColumnSpec("execution_boundary", "string", False, 200),
        _ColumnSpec("escalate_receipt_id", "string", False, 200),
        _ColumnSpec("escalate_receipt_hash", "string", False, 64),
        _ColumnSpec("escalate_audit_event_hash", "string", False, 64),
        _ColumnSpec("quorum_threshold", "integer", False),
        _ColumnSpec("sealed_arguments", "json", False),
        _ColumnSpec("aad", "json", False),
        _ColumnSpec("status", "string", False, 32),
        _ColumnSpec("created_at", "datetime", False),
        _ColumnSpec("expires_at", "datetime", False),
    ),
    "approval_votes": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("approval_request_id", "string", False, 64),
        _ColumnSpec("approver_actor_hash", "string", False, 64),
        _ColumnSpec("approver_role", "string", False, 32),
        _ColumnSpec("decision", "string", False, 16),
        _ColumnSpec("idempotency_key_hash", "string", False, 64),
        _ColumnSpec("vote_hash", "string", False, 64),
        _ColumnSpec("created_at", "datetime", False),
        _ColumnSpec("approver_credential_hash", "string", False, 64),
        _ColumnSpec("vote_receipt_id", "string", True, 200),
        _ColumnSpec("vote_receipt_hash", "string", True, 64),
        _ColumnSpec("vote_audit_event_hash", "string", True, 64),
        _ColumnSpec("vote_replay_seal", "json", False),
    ),
    "approval_outcomes": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("approval_request_id", "string", False, 64),
        _ColumnSpec("outcome", "string", False, 16),
        _ColumnSpec("quorum_digest", "string", False, 64),
        _ColumnSpec("approver_set_hash", "string", False, 64),
        _ColumnSpec("created_at", "datetime", False),
    ),
    "approval_resume_authorizations": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("approval_request_id", "string", False, 64),
        _ColumnSpec("resumed_agent_id", "string", False, 64),
        _ColumnSpec("idempotency_key_hash", "string", False, 64),
        _ColumnSpec("resume_receipt_id", "string", False, 200),
        _ColumnSpec("resume_receipt_hash", "string", False, 64),
        _ColumnSpec("resume_audit_event_hash", "string", False, 64),
        _ColumnSpec("approval_chain_hash", "string", False, 64),
        _ColumnSpec("created_at", "datetime", False),
        _ColumnSpec("resume_argument_hash", "string", False, 128),
        _ColumnSpec("resumer_actor_hash", "string", False, 64),
        _ColumnSpec("resumer_credential_hash", "string", False, 64),
        _ColumnSpec("resumer_role", "string", False, 32),
        _ColumnSpec("resume_result_hash", "string", False, 128),
        _ColumnSpec("resume_result", "json", False),
        _ColumnSpec("resume_response_hash", "string", False, 64),
        _ColumnSpec("resume_response", "json", False),
        _ColumnSpec("resume_replay_seal", "json", False),
    ),
}
_APPROVAL_SUBSTRATE_0009_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = {
    **_APPROVAL_SUBSTRATE_COLUMNS,
    "approval_votes": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("approval_request_id", "string", False, 64),
        _ColumnSpec("approver_actor_hash", "string", False, 64),
        _ColumnSpec("approver_role", "string", False, 32),
        _ColumnSpec("decision", "string", False, 16),
        _ColumnSpec("idempotency_key_hash", "string", False, 64),
        _ColumnSpec("vote_hash", "string", False, 64),
        _ColumnSpec("created_at", "datetime", False),
    ),
    "approval_resume_authorizations": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("approval_request_id", "string", False, 64),
        _ColumnSpec("resumed_agent_id", "string", False, 64),
        _ColumnSpec("idempotency_key_hash", "string", False, 64),
        _ColumnSpec("resume_receipt_id", "string", False, 200),
        _ColumnSpec("resume_receipt_hash", "string", False, 64),
        _ColumnSpec("resume_audit_event_hash", "string", False, 64),
        _ColumnSpec("approval_chain_hash", "string", False, 64),
        _ColumnSpec("created_at", "datetime", False),
    ),
}
_APPROVAL_VOTE_BINDING_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = {
    **_APPROVAL_SUBSTRATE_COLUMNS,
    "approval_votes": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("approval_request_id", "string", False, 64),
        _ColumnSpec("approver_actor_hash", "string", False, 64),
        _ColumnSpec("approver_role", "string", False, 32),
        _ColumnSpec("decision", "string", False, 16),
        _ColumnSpec("idempotency_key_hash", "string", False, 64),
        _ColumnSpec("vote_hash", "string", False, 64),
        _ColumnSpec("created_at", "datetime", False),
        _ColumnSpec("approver_credential_hash", "string", False, 64),
        _ColumnSpec("vote_receipt_id", "string", True, 200),
        _ColumnSpec("vote_receipt_hash", "string", True, 64),
        _ColumnSpec("vote_audit_event_hash", "string", True, 64),
        _ColumnSpec("vote_replay_seal", "json", False),
    ),
}
_RUNTIME_ENROLLMENT_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = {
    **_APPROVAL_VOTE_BINDING_COLUMNS,
    "runtime_identity_gates": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("status", "string", False, 16),
        _ColumnSpec("created_at", "datetime", False),
        _ColumnSpec("updated_at", "datetime", False),
    ),
    "runtime_identities": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("gate_id", "string", False, 64),
        _ColumnSpec("name", "string", False, 200),
        _ColumnSpec("actor", "string", False, 240),
        _ColumnSpec("workload_key_id", "string", False, 128),
        _ColumnSpec("public_key", "text", False),
        _ColumnSpec("public_key_thumbprint", "string", False, 64),
        _ColumnSpec("descriptor", "json", False),
        _ColumnSpec("status", "string", False, 16),
        _ColumnSpec("current_generation", "integer", False),
        _ColumnSpec("created_at", "datetime", False),
        _ColumnSpec("updated_at", "datetime", False),
        _ColumnSpec("revoked_at", "datetime", True),
    ),
    "runtime_enrollment_bootstraps": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("gate_id", "string", False, 64),
        _ColumnSpec("bootstrap_digest", "string", False, 64),
        _ColumnSpec("bootstrap_locator", "string", False, 64),
        _ColumnSpec("pepper_key_id", "string", False, 128),
        _ColumnSpec("server_challenge", "string", False, 256),
        _ColumnSpec("runtime_identity_id", "string", False, 64),
        _ColumnSpec("audience", "string", False, 128),
        _ColumnSpec("workload_key_id", "string", False, 128),
        _ColumnSpec("public_key_thumbprint", "string", False, 64),
        _ColumnSpec("status", "string", False, 16),
        _ColumnSpec("created_by_actor", "string", False, 200),
        _ColumnSpec("consumed_by_identity_id", "string", True, 64),
        _ColumnSpec("policy_head_generation", "integer", False),
        _ColumnSpec("created_at", "datetime", False),
        _ColumnSpec("expires_at", "datetime", False),
        _ColumnSpec("consumed_at", "datetime", True),
        _ColumnSpec("revoked_at", "datetime", True),
    ),
    "runtime_credential_generations": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("identity_id", "string", False, 64),
        _ColumnSpec("generation", "integer", False),
        _ColumnSpec("workload_key_id", "string", False, 128),
        _ColumnSpec("public_key_thumbprint", "string", False, 64),
        _ColumnSpec("not_before", "datetime", False),
        _ColumnSpec("not_after", "datetime", False),
        _ColumnSpec("status", "string", False, 16),
        _ColumnSpec("descriptor", "json", False),
        _ColumnSpec("created_at", "datetime", False),
        _ColumnSpec("superseded_at", "datetime", True),
        _ColumnSpec("revoked_at", "datetime", True),
    ),
    "runtime_enrollment_idempotency": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("idempotency_key_hash", "string", False, 64),
        _ColumnSpec("request_hash", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("identity_id", "string", False, 64),
        _ColumnSpec("receipt_id", "string", False, 200),
        _ColumnSpec("response", "json", False),
        _ColumnSpec("created_at", "datetime", False),
    ),
    "runtime_request_nonces": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("identity_id", "string", False, 64),
        _ColumnSpec("nonce", "string", False, 128),
        _ColumnSpec("idempotency_key_hash", "string", False, 64),
        _ColumnSpec("request_hash", "string", False, 64),
        _ColumnSpec("purpose", "string", False, 64),
        _ColumnSpec("receipt_id", "string", True, 200),
        _ColumnSpec("response", "json", True),
        _ColumnSpec("observed_at", "datetime", False),
    ),
    "runtime_operation_idempotency": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("idempotency_key_hash", "string", False, 64),
        _ColumnSpec("request_hash", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("identity_id", "string", False, 64),
        _ColumnSpec("operation", "string", False, 64),
        _ColumnSpec("receipt_id", "string", False, 200),
        _ColumnSpec("response", "json", False),
        _ColumnSpec("created_at", "datetime", False),
    ),
}
_RUNTIME_REPORTS_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = {
    **_RUNTIME_ENROLLMENT_COLUMNS,
    "runtime_reports": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("gate_id", "string", False, 64),
        _ColumnSpec("actor", "string", False, 240),
        _ColumnSpec("identity_id", "string", False, 64),
        _ColumnSpec("credential_id", "string", False, 64),
        _ColumnSpec("credential_generation", "integer", False),
        _ColumnSpec("workload_key_id", "string", False, 128),
        _ColumnSpec("public_key_thumbprint", "string", False, 64),
        _ColumnSpec("policy_version_id", "string", False, 64),
        _ColumnSpec("policy_head_generation", "integer", False),
        _ColumnSpec("policy_content_hash", "string", False, 64),
        _ColumnSpec("runtime_build_digest", "string", False, 64),
        _ColumnSpec("configuration_digest", "string", False, 64),
        _ColumnSpec("policy_snapshot_hash", "string", False, 64),
        _ColumnSpec("policy_provenance_hash", "string", False, 64),
        _ColumnSpec("policy_issued_at", "datetime", False),
        _ColumnSpec("policy_revocation_checked_at", "datetime", False),
        _ColumnSpec("policy_fresh_until", "datetime", False),
        _ColumnSpec("policy_expires_at", "datetime", False),
        _ColumnSpec("kind", "string", False, 16),
        _ColumnSpec("sequence", "big_integer", False),
        _ColumnSpec("nonce", "string", False, 128),
        _ColumnSpec("report_hash", "string", False, 64),
        _ColumnSpec("projection_commitment", "string", False, 64),
        _ColumnSpec("request_projection", "json", False),
        _ColumnSpec("request_signature", "text", False),
        _ColumnSpec("receipt_id", "string", False, 200),
        _ColumnSpec("observed_at", "datetime", False),
        _ColumnSpec("expires_at", "datetime", False),
        _ColumnSpec("created_at", "datetime", False),
    ),
    "runtime_report_heads": (
        _ColumnSpec("identity_id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("last_sequence", "big_integer", False),
        _ColumnSpec("latest_report_id", "string", False, 64),
        _ColumnSpec("latest_report_hash", "string", False, 64),
        _ColumnSpec("latest_projection_commitment", "string", False, 64),
        _ColumnSpec("history_count", "big_integer", False),
        _ColumnSpec("history_accumulator", "string", False, 64),
        _ColumnSpec("latest_wiring_kind", "string", True, 16),
        _ColumnSpec("latest_wiring_sequence", "big_integer", True),
        _ColumnSpec("latest_wiring_report_id", "string", True, 64),
        _ColumnSpec("latest_wiring_report_hash", "string", True, 64),
        _ColumnSpec("latest_wiring_projection_commitment", "string", True, 64),
        _ColumnSpec("updated_at", "datetime", False),
    ),
    "runtime_wiring_challenge_consumptions": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("identity_id", "string", False, 64),
        _ColumnSpec("credential_id", "string", False, 64),
        _ColumnSpec("credential_generation", "integer", False),
        _ColumnSpec("sequence", "big_integer", False),
        _ColumnSpec("expected_sequence", "big_integer", False),
        _ColumnSpec("report_kind", "string", False, 16),
        _ColumnSpec("report_id", "string", False, 64),
        _ColumnSpec("receipt_id", "string", False, 200),
        _ColumnSpec("challenge_nonce", "string", False, 128),
        _ColumnSpec("namespace_digest", "string", False, 64),
        _ColumnSpec("request_hash", "string", False, 64),
        _ColumnSpec("idempotency_key_hash", "string", False, 64),
        _ColumnSpec("projection_commitment", "string", False, 64),
        _ColumnSpec("consumed_at", "datetime", False),
    ),
    "runtime_wiring_attestations": (
        _ColumnSpec("id", "string", False, 64),
        _ColumnSpec("org_id", "string", False, 64),
        _ColumnSpec("project_id", "string", False, 64),
        _ColumnSpec("environment_id", "string", False, 64),
        _ColumnSpec("gate_id", "string", False, 64),
        _ColumnSpec("identity_id", "string", False, 64),
        _ColumnSpec("report_kind", "string", False, 16),
        _ColumnSpec("report_id", "string", False, 64),
        _ColumnSpec("attestation_hash", "string", False, 64),
        _ColumnSpec("assurance_class", "string", False, 64),
        _ColumnSpec("evidence_kind", "string", False, 64),
        _ColumnSpec("suite_id", "string", False, 128),
        _ColumnSpec("suite_hash", "string", False, 64),
        _ColumnSpec("artifact", "json", False),
        _ColumnSpec("created_at", "datetime", False),
    ),
}
_PROJECTS_ONLY_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = {
    **_LEGACY_COLUMNS,
    "projects": _SCOPED_COLUMNS["projects"],
}
_PROJECTS_ONLY_CREATE_ALL_COLUMNS: Final[dict[str, tuple[_ColumnSpec, ...]]] = (
    _with_nullable_user_api_key_hash(_PROJECTS_ONLY_COLUMNS)
)

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
_TRUST_V2_PRIMARY_KEYS: Final[dict[str, tuple[str, ...]]] = {
    **_MANAGED_MUTATION_PRIMARY_KEYS,
    "managed_trust_scopes": ("id",),
    "managed_trust_keys": ("id",),
}
_TENANT_BOOTSTRAP_PRIMARY_KEYS: Final[dict[str, tuple[str, ...]]] = {
    **_TRUST_V2_PRIMARY_KEYS,
    "organization_memberships": ("id",),
    "platform_bootstrap_invitations": ("id",),
    "tenant_bootstrap_idempotency": ("id",),
    "tenant_bootstrap_policy_artifacts": ("id",),
    "pending_approvals": ("id",),
    "tenant_bootstrap_pending_outbox": ("id",),
    "tenant_bootstrap_refusal_events": ("id",),
}
_AGENT_REGISTRATION_IDEMPOTENCY_PRIMARY_KEYS: Final[dict[str, tuple[str, ...]]] = {
    **_TENANT_BOOTSTRAP_PRIMARY_KEYS,
    "agent_registration_idempotency": ("id",),
}
_POLICY_REGISTRY_PRIMARY_KEYS: Final[dict[str, tuple[str, ...]]] = {
    **_AGENT_REGISTRATION_IDEMPOTENCY_PRIMARY_KEYS,
    "policy_versions": ("id",),
    "environment_policy_heads": ("id",),
    "policy_registry_idempotency": ("id",),
}
_APPROVAL_SUBSTRATE_PRIMARY_KEYS: Final[dict[str, tuple[str, ...]]] = {
    **_POLICY_REGISTRY_PRIMARY_KEYS,
    "approval_requests": ("id",),
    "approval_votes": ("id",),
    "approval_outcomes": ("id",),
    "approval_resume_authorizations": ("id",),
}
_RUNTIME_ENROLLMENT_PRIMARY_KEYS: Final[dict[str, tuple[str, ...]]] = {
    **_APPROVAL_SUBSTRATE_PRIMARY_KEYS,
    "runtime_identity_gates": ("id",),
    "runtime_identities": ("id",),
    "runtime_enrollment_bootstraps": ("id",),
    "runtime_credential_generations": ("id",),
    "runtime_enrollment_idempotency": ("id",),
    "runtime_request_nonces": ("id",),
    "runtime_operation_idempotency": ("id",),
}
_RUNTIME_REPORTS_PRIMARY_KEYS: Final[dict[str, tuple[str, ...]]] = {
    **_RUNTIME_ENROLLMENT_PRIMARY_KEYS,
    "runtime_reports": ("id",),
    "runtime_wiring_attestations": ("id",),
    "runtime_report_heads": ("identity_id",),
    "runtime_wiring_challenge_consumptions": ("id",),
}
_PROJECTS_ONLY_PRIMARY_KEYS: Final[dict[str, tuple[str, ...]]] = {
    table_name: ("id",) for table_name in _PROJECTS_ONLY_COLUMNS
}

_ForeignKeySpec = tuple[tuple[str, ...], str | None, str, tuple[str, ...]]
_UniqueIndexSpec = tuple[tuple[str, ...], str]


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
_DEFERRABLE_MANAGED_MUTATION_FK_TABLES: Final = frozenset(
    (_MANAGED_MUTATION_FOREIGN_KEYS.keys() - _SCOPED_FOREIGN_KEYS.keys())
    | {
        "agent_registration_idempotency",
        "approval_outcomes",
        "approval_requests",
        "approval_resume_authorizations",
        "approval_votes",
        "policy_versions",
        "environment_policy_heads",
        "policy_registry_idempotency",
        "runtime_identity_gates",
        "runtime_identities",
        "runtime_enrollment_bootstraps",
        "runtime_credential_generations",
        "runtime_enrollment_idempotency",
        "runtime_request_nonces",
        "runtime_operation_idempotency",
        "runtime_reports",
        "runtime_report_heads",
        "runtime_wiring_challenge_consumptions",
        "runtime_wiring_attestations",
    }
)
_TRUST_SCOPE_FK: Final[_ForeignKeySpec] = (
    ("org_id", "project_id", "environment_id", "purpose"),
    None,
    "managed_trust_scopes",
    ("org_id", "project_id", "environment_id", "purpose"),
)
_TRUST_V2_FOREIGN_KEYS: Final[dict[str, frozenset[_ForeignKeySpec]]] = {
    **_MANAGED_MUTATION_FOREIGN_KEYS,
    "managed_trust_scopes": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            _SCOPE_ENVIRONMENT_FK,
        }
    ),
    "managed_trust_keys": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            _SCOPE_ENVIRONMENT_FK,
            _TRUST_SCOPE_FK,
        }
    ),
}
_TENANT_BOOTSTRAP_FOREIGN_KEYS: Final[dict[str, frozenset[_ForeignKeySpec]]] = {
    **_TRUST_V2_FOREIGN_KEYS,
    "organization_memberships": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            (("user_id",), None, "users", ("id",)),
            (("org_id", "user_id"), None, "users", ("org_id", "id")),
        }
    ),
    "platform_bootstrap_invitations": frozenset(),
    "tenant_bootstrap_idempotency": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            (
                ("org_id", "project_id", "environment_id"),
                None,
                "environments",
                ("org_id", "project_id", "id"),
            ),
        }
    ),
    "tenant_bootstrap_policy_artifacts": frozenset(
        {
            (("invitation_id",), None, "platform_bootstrap_invitations", ("id",)),
            (
                ("invitation_id", "org_id", "project_id", "environment_id"),
                None,
                "platform_bootstrap_invitations",
                (
                    "id",
                    "prospective_org_id",
                    "prospective_project_id",
                    "prospective_environment_id",
                ),
            ),
        }
    ),
    "pending_approvals": frozenset(
        {
            (("invitation_id",), None, "platform_bootstrap_invitations", ("id",)),
            (
                ("invitation_id", "policy_artifact_id", "org_id", "project_id", "environment_id"),
                None,
                "tenant_bootstrap_policy_artifacts",
                ("invitation_id", "id", "org_id", "project_id", "environment_id"),
            ),
        }
    ),
    "tenant_bootstrap_pending_outbox": frozenset(
        {
            (("invitation_id",), None, "platform_bootstrap_invitations", ("id",)),
            (
                ("invitation_id", "policy_artifact_id", "org_id", "project_id", "environment_id"),
                None,
                "tenant_bootstrap_policy_artifacts",
                ("invitation_id", "id", "org_id", "project_id", "environment_id"),
            ),
        }
    ),
    "tenant_bootstrap_refusal_events": frozenset(),
}
_AGENT_SCOPE_FOREIGN_KEYS: Final[dict[str, frozenset[_ForeignKeySpec]]] = {
    **_TENANT_BOOTSTRAP_FOREIGN_KEYS,
    "agents": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            (
                ("org_id", "project_id", "environment_id"),
                None,
                "environments",
                ("org_id", "project_id", "id"),
            ),
        }
    ),
}
_AGENT_REGISTRATION_IDEMPOTENCY_FOREIGN_KEYS: Final[dict[str, frozenset[_ForeignKeySpec]]] = {
    **_AGENT_SCOPE_FOREIGN_KEYS,
    "agent_registration_idempotency": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            (
                ("org_id", "project_id", "environment_id"),
                None,
                "environments",
                ("org_id", "project_id", "id"),
            ),
            (
                ("org_id", "project_id", "environment_id", "agent_id"),
                None,
                "agents",
                ("org_id", "project_id", "environment_id", "id"),
            ),
            (
                ("org_id", "project_id", "environment_id", "receipt_id"),
                None,
                "managed_decision_receipts",
                ("org_id", "project_id", "environment_id", "receipt_id"),
            ),
        }
    ),
}
_POLICY_VERSION_SCOPE_ID_FK: Final[_ForeignKeySpec] = (
    ("org_id", "project_id", "environment_id", "active_policy_version_id"),
    None,
    "policy_versions",
    ("org_id", "project_id", "environment_id", "id"),
)
_ENVIRONMENT_POLICY_HEAD_RECEIPT_FK: Final[_ForeignKeySpec] = (
    ("org_id", "project_id", "environment_id", "receipt_id"),
    None,
    "managed_decision_receipts",
    ("org_id", "project_id", "environment_id", "receipt_id"),
)
_POLICY_REGISTRY_FOREIGN_KEYS: Final[dict[str, frozenset[_ForeignKeySpec]]] = {
    **_AGENT_REGISTRATION_IDEMPOTENCY_FOREIGN_KEYS,
    "policy_versions": frozenset(
        {(("org_id",), None, "organizations", ("id",)), _SCOPE_ENVIRONMENT_FK}
    ),
    "environment_policy_heads": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            _SCOPE_ENVIRONMENT_FK,
            _POLICY_VERSION_SCOPE_ID_FK,
            _ENVIRONMENT_POLICY_HEAD_RECEIPT_FK,
        }
    ),
    "policy_registry_idempotency": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            _SCOPE_ENVIRONMENT_FK,
            (
                ("org_id", "project_id", "environment_id", "receipt_id"),
                None,
                "managed_decision_receipts",
                ("org_id", "project_id", "environment_id", "receipt_id"),
            ),
        }
    ),
}
_APPROVAL_REQUEST_SCOPE_FK: Final[_ForeignKeySpec] = (
    ("org_id", "project_id", "environment_id", "approval_request_id"),
    None,
    "approval_requests",
    ("org_id", "project_id", "environment_id", "id"),
)
_APPROVAL_SUBSTRATE_FOREIGN_KEYS: Final[dict[str, frozenset[_ForeignKeySpec]]] = {
    **_POLICY_REGISTRY_FOREIGN_KEYS,
    "approval_requests": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            _SCOPE_ENVIRONMENT_FK,
            (
                ("org_id", "project_id", "environment_id", "escalate_receipt_id"),
                None,
                "managed_decision_receipts",
                ("org_id", "project_id", "environment_id", "receipt_id"),
            ),
        }
    ),
    "approval_votes": frozenset(
        {(("org_id",), None, "organizations", ("id",)), _APPROVAL_REQUEST_SCOPE_FK}
    ),
    "approval_outcomes": frozenset(
        {(("org_id",), None, "organizations", ("id",)), _APPROVAL_REQUEST_SCOPE_FK}
    ),
    "approval_resume_authorizations": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            _APPROVAL_REQUEST_SCOPE_FK,
            (
                ("org_id", "project_id", "environment_id", "resumed_agent_id"),
                None,
                "agents",
                ("org_id", "project_id", "environment_id", "id"),
            ),
            (
                ("org_id", "project_id", "environment_id", "resume_receipt_id"),
                None,
                "managed_decision_receipts",
                ("org_id", "project_id", "environment_id", "receipt_id"),
            ),
        }
    ),
}
_APPROVAL_SUBSTRATE_0009_FOREIGN_KEYS: Final = _APPROVAL_SUBSTRATE_FOREIGN_KEYS
_APPROVAL_VOTE_RECEIPT_FK: Final[_ForeignKeySpec] = (
    ("org_id", "project_id", "environment_id", "vote_receipt_id"),
    None,
    "managed_decision_receipts",
    ("org_id", "project_id", "environment_id", "receipt_id"),
)
_APPROVAL_VOTE_BINDING_FOREIGN_KEYS: Final[dict[str, frozenset[_ForeignKeySpec]]] = {
    **_APPROVAL_SUBSTRATE_FOREIGN_KEYS,
    "approval_votes": _APPROVAL_SUBSTRATE_FOREIGN_KEYS["approval_votes"]
    | frozenset({_APPROVAL_VOTE_RECEIPT_FK}),
}
_RUNTIME_GATE_SCOPE_FK: Final[_ForeignKeySpec] = (
    ("org_id", "project_id", "environment_id", "gate_id"),
    None,
    "runtime_identity_gates",
    ("org_id", "project_id", "environment_id", "id"),
)
_RUNTIME_IDENTITY_SCOPE_FK: Final[_ForeignKeySpec] = (
    ("org_id", "project_id", "environment_id", "identity_id"),
    None,
    "runtime_identities",
    ("org_id", "project_id", "environment_id", "id"),
)
_RUNTIME_RECEIPT_SCOPE_FK: Final[_ForeignKeySpec] = (
    ("org_id", "project_id", "environment_id", "receipt_id"),
    None,
    "managed_decision_receipts",
    ("org_id", "project_id", "environment_id", "receipt_id"),
)
_RUNTIME_ENROLLMENT_FOREIGN_KEYS: Final[dict[str, frozenset[_ForeignKeySpec]]] = {
    **_APPROVAL_VOTE_BINDING_FOREIGN_KEYS,
    "runtime_identity_gates": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            _SCOPE_ENVIRONMENT_FK,
        }
    ),
    "runtime_identities": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            _SCOPE_ENVIRONMENT_FK,
            _RUNTIME_GATE_SCOPE_FK,
        }
    ),
    "runtime_enrollment_bootstraps": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            _SCOPE_ENVIRONMENT_FK,
            _RUNTIME_GATE_SCOPE_FK,
            (
                ("org_id", "project_id", "environment_id", "consumed_by_identity_id"),
                None,
                "runtime_identities",
                ("org_id", "project_id", "environment_id", "id"),
            ),
        }
    ),
    "runtime_credential_generations": frozenset(
        {(("org_id",), None, "organizations", ("id",)), _RUNTIME_IDENTITY_SCOPE_FK}
    ),
    "runtime_enrollment_idempotency": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            _RUNTIME_IDENTITY_SCOPE_FK,
            _RUNTIME_RECEIPT_SCOPE_FK,
        }
    ),
    "runtime_request_nonces": frozenset(
        {(("org_id",), None, "organizations", ("id",)), _RUNTIME_IDENTITY_SCOPE_FK}
    ),
    "runtime_operation_idempotency": frozenset(
        {(("org_id",), None, "organizations", ("id",)), _RUNTIME_RECEIPT_SCOPE_FK}
    ),
}
_RUNTIME_REPORTS_FOREIGN_KEYS: Final[dict[str, frozenset[_ForeignKeySpec]]] = {
    **_RUNTIME_ENROLLMENT_FOREIGN_KEYS,
    "runtime_reports": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            _RUNTIME_GATE_SCOPE_FK,
            (
                ("org_id", "project_id", "environment_id", "gate_id", "identity_id"),
                None,
                "runtime_identities",
                ("org_id", "project_id", "environment_id", "gate_id", "id"),
            ),
            (
                (
                    "org_id",
                    "project_id",
                    "environment_id",
                    "identity_id",
                    "credential_generation",
                    "credential_id",
                ),
                None,
                "runtime_credential_generations",
                (
                    "org_id",
                    "project_id",
                    "environment_id",
                    "identity_id",
                    "generation",
                    "id",
                ),
            ),
            (
                ("org_id", "project_id", "environment_id", "policy_version_id"),
                None,
                "policy_versions",
                ("org_id", "project_id", "environment_id", "id"),
            ),
            _RUNTIME_RECEIPT_SCOPE_FK,
        }
    ),
    "runtime_wiring_attestations": frozenset(
        {
            (
                (
                    "org_id",
                    "project_id",
                    "environment_id",
                    "gate_id",
                    "identity_id",
                    "report_kind",
                    "report_id",
                ),
                None,
                "runtime_reports",
                (
                    "org_id",
                    "project_id",
                    "environment_id",
                    "gate_id",
                    "identity_id",
                    "kind",
                    "id",
                ),
            )
        }
    ),
    "runtime_report_heads": frozenset(
        {
            (("org_id",), None, "organizations", ("id",)),
            (
                ("org_id", "project_id", "environment_id", "identity_id"),
                None,
                "runtime_identities",
                ("org_id", "project_id", "environment_id", "id"),
            ),
            (
                (
                    "org_id",
                    "project_id",
                    "environment_id",
                    "identity_id",
                    "last_sequence",
                    "latest_report_id",
                ),
                None,
                "runtime_reports",
                (
                    "org_id",
                    "project_id",
                    "environment_id",
                    "identity_id",
                    "sequence",
                    "id",
                ),
            ),
            (
                (
                    "org_id",
                    "project_id",
                    "environment_id",
                    "identity_id",
                    "latest_wiring_kind",
                    "latest_wiring_sequence",
                    "latest_wiring_report_id",
                ),
                None,
                "runtime_reports",
                (
                    "org_id",
                    "project_id",
                    "environment_id",
                    "identity_id",
                    "kind",
                    "sequence",
                    "id",
                ),
            ),
        }
    ),
    "runtime_wiring_challenge_consumptions": frozenset(
        {
            (
                (
                    "org_id",
                    "project_id",
                    "environment_id",
                    "identity_id",
                    "report_kind",
                    "sequence",
                    "report_id",
                ),
                None,
                "runtime_reports",
                (
                    "org_id",
                    "project_id",
                    "environment_id",
                    "identity_id",
                    "kind",
                    "sequence",
                    "id",
                ),
            ),
            _RUNTIME_RECEIPT_SCOPE_FK,
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
_LEGACY_CREATE_ALL_UNIQUES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_LEGACY_UNIQUES,
    "users": _LEGACY_UNIQUES["users"] | frozenset({("org_id", "id")}),
}
_SCOPED_CREATE_ALL_UNIQUES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_SCOPED_UNIQUES,
    "users": _LEGACY_CREATE_ALL_UNIQUES["users"],
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
_MANAGED_MUTATION_CREATE_ALL_UNIQUES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_MANAGED_MUTATION_UNIQUES,
    "users": _LEGACY_CREATE_ALL_UNIQUES["users"],
}
_TRUST_V2_UNIQUES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_MANAGED_MUTATION_UNIQUES,
    "managed_trust_scopes": frozenset({("org_id", "project_id", "environment_id", "purpose")}),
    "managed_trust_keys": frozenset(
        {
            (
                "org_id",
                "project_id",
                "environment_id",
                "purpose",
                "key_id",
                "algorithm",
                "activated_epoch",
            ),
        }
    ),
}
_TRUST_V2_CREATE_ALL_UNIQUES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_TRUST_V2_UNIQUES,
    "users": _LEGACY_CREATE_ALL_UNIQUES["users"],
}
_TENANT_BOOTSTRAP_UNIQUES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_TRUST_V2_UNIQUES,
    "users": frozenset({("org_id", "email"), ("api_key_hash",), ("org_id", "id")}),
    "organization_memberships": frozenset({("org_id", "user_id")}),
    "platform_bootstrap_invitations": frozenset(
        {
            ("token_hash",),
            ("prospective_org_id", "prospective_project_id", "prospective_environment_id"),
            (
                "id",
                "prospective_org_id",
                "prospective_project_id",
                "prospective_environment_id",
            ),
        }
    ),
    "tenant_bootstrap_idempotency": frozenset({("idempotency_key",), ("org_id",)}),
    "tenant_bootstrap_policy_artifacts": frozenset(
        {
            ("invitation_id", "id"),
            ("invitation_id", "id", "org_id", "project_id", "environment_id"),
            ("invitation_id",),
            ("receipt_hash",),
            ("audit_event_hash",),
        }
    ),
    "pending_approvals": frozenset({("receipt_hash",), ("audit_event_hash",)}),
    "tenant_bootstrap_pending_outbox": frozenset(
        {("policy_artifact_id",), ("delivery_key",), ("payload_digest",)}
    ),
    "tenant_bootstrap_refusal_events": frozenset({("request_id",)}),
}
_AGENT_SCOPE_UNIQUES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_TENANT_BOOTSTRAP_UNIQUES,
    "agents": frozenset(),
}
_AGENT_REGISTRATION_IDEMPOTENCY_UNIQUES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_AGENT_SCOPE_UNIQUES,
    "agents": frozenset({("org_id", "project_id", "environment_id", "id")}),
    "agent_registration_idempotency": frozenset(
        {
            ("idempotency_key_hash",),
            ("org_id", "project_id", "environment_id", "agent_id"),
        }
    ),
}
_POLICY_REGISTRY_UNIQUES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_AGENT_REGISTRATION_IDEMPOTENCY_UNIQUES,
    "policy_versions": frozenset(
        {
            ("org_id", "project_id", "environment_id", "id"),
            ("org_id", "project_id", "environment_id", "policy_id", "version"),
            ("org_id", "project_id", "environment_id", "content_hash"),
        }
    ),
    "environment_policy_heads": frozenset(
        {
            ("org_id", "project_id", "environment_id"),
            ("org_id", "project_id", "environment_id", "generation"),
        }
    ),
    "policy_registry_idempotency": frozenset({("idempotency_key_hash",)}),
}
_APPROVAL_SUBSTRATE_UNIQUES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_POLICY_REGISTRY_UNIQUES,
    "approval_requests": frozenset(
        {
            ("org_id", "project_id", "environment_id", "id"),
            ("org_id", "request_hash"),
            ("org_id", "project_id", "environment_id", "escalate_receipt_hash"),
            ("org_id", "project_id", "environment_id", "escalate_audit_event_hash"),
        }
    ),
    "approval_votes": frozenset(
        {
            (
                "org_id",
                "project_id",
                "environment_id",
                "approval_request_id",
                "approver_actor_hash",
            ),
            ("org_id", "approval_request_id", "idempotency_key_hash"),
        }
    ),
    "approval_outcomes": frozenset(
        {("org_id", "project_id", "environment_id", "approval_request_id")}
    ),
    "approval_resume_authorizations": frozenset(
        {
            ("org_id", "project_id", "environment_id", "approval_request_id"),
            ("org_id", "resume_receipt_hash"),
            ("org_id", "resume_audit_event_hash"),
            ("org_id", "approval_request_id", "idempotency_key_hash"),
        }
    ),
}
_APPROVAL_SUBSTRATE_0009_UNIQUES: Final = _APPROVAL_SUBSTRATE_UNIQUES
_APPROVAL_VOTE_BINDING_UNIQUES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_APPROVAL_SUBSTRATE_UNIQUES,
    "approval_votes": frozenset(
        {
            (
                "org_id",
                "project_id",
                "environment_id",
                "approval_request_id",
                "approver_actor_hash",
            ),
            ("org_id", "approval_request_id", "idempotency_key_hash"),
            ("org_id", "project_id", "environment_id", "vote_receipt_id"),
            ("org_id", "project_id", "environment_id", "vote_receipt_hash"),
            ("org_id", "project_id", "environment_id", "vote_audit_event_hash"),
        }
    ),
}
_RUNTIME_ENROLLMENT_UNIQUES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_APPROVAL_VOTE_BINDING_UNIQUES,
    "runtime_identity_gates": frozenset(
        {
            ("org_id", "project_id", "environment_id"),
            ("org_id", "project_id", "environment_id", "id"),
        }
    ),
    "runtime_identities": frozenset(
        {
            ("org_id", "project_id", "environment_id", "id"),
            ("org_id", "project_id", "environment_id", "name"),
            ("org_id", "project_id", "environment_id", "public_key_thumbprint"),
        }
    ),
    "runtime_enrollment_bootstraps": frozenset({("bootstrap_digest",), ("bootstrap_locator",)}),
    "runtime_credential_generations": frozenset(
        {("org_id", "project_id", "environment_id", "identity_id", "generation")}
    ),
    "runtime_enrollment_idempotency": frozenset(
        {
            (
                "org_id",
                "project_id",
                "environment_id",
                "identity_id",
                "idempotency_key_hash",
            ),
            ("org_id", "project_id", "environment_id", "identity_id"),
        }
    ),
    "runtime_request_nonces": frozenset(
        {("org_id", "project_id", "environment_id", "identity_id", "nonce")}
    ),
    "runtime_operation_idempotency": frozenset(
        {
            (
                "org_id",
                "project_id",
                "environment_id",
                "identity_id",
                "operation",
                "idempotency_key_hash",
            )
        }
    ),
}
_RUNTIME_REPORTS_UNIQUES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_RUNTIME_ENROLLMENT_UNIQUES,
    "runtime_identities": _RUNTIME_ENROLLMENT_UNIQUES["runtime_identities"]
    | frozenset({("org_id", "project_id", "environment_id", "gate_id", "id")}),
    "runtime_credential_generations": _RUNTIME_ENROLLMENT_UNIQUES["runtime_credential_generations"]
    | frozenset({("org_id", "project_id", "environment_id", "identity_id", "generation", "id")}),
    "runtime_reports": frozenset(
        {
            (
                "org_id",
                "project_id",
                "environment_id",
                "gate_id",
                "identity_id",
                "kind",
                "id",
            ),
            ("org_id", "project_id", "environment_id", "receipt_id"),
            ("org_id", "project_id", "environment_id", "identity_id", "sequence"),
            (
                "org_id",
                "project_id",
                "environment_id",
                "identity_id",
                "sequence",
                "id",
            ),
            (
                "org_id",
                "project_id",
                "environment_id",
                "identity_id",
                "kind",
                "sequence",
                "id",
            ),
            (
                "org_id",
                "project_id",
                "environment_id",
                "identity_id",
                "kind",
                "id",
            ),
            ("org_id", "project_id", "environment_id", "identity_id", "nonce"),
        }
    ),
    "runtime_wiring_attestations": frozenset({("report_id",), ("attestation_hash",)}),
    "runtime_report_heads": frozenset(),
    "runtime_wiring_challenge_consumptions": frozenset(
        {
            ("report_id",),
            (
                "org_id",
                "project_id",
                "environment_id",
                "identity_id",
                "challenge_nonce",
            ),
        }
    ),
}
_TRUST_V2_UNIQUE_INDEXES: Final[dict[str, frozenset[_UniqueIndexSpec]]] = {
    **{table_name: frozenset() for table_name in _TRUST_V2_COLUMNS},
    "managed_trust_keys": frozenset(
        {
            (
                ("org_id", "project_id", "environment_id", "purpose"),
                "status:active",
            ),
        }
    ),
}
_TENANT_BOOTSTRAP_UNIQUE_INDEXES: Final[dict[str, frozenset[_UniqueIndexSpec]]] = {
    **_TRUST_V2_UNIQUE_INDEXES,
    **{
        table_name: frozenset()
        for table_name in (
            "organization_memberships",
            "platform_bootstrap_invitations",
            "tenant_bootstrap_idempotency",
            "tenant_bootstrap_policy_artifacts",
            "pending_approvals",
            "tenant_bootstrap_pending_outbox",
            "tenant_bootstrap_refusal_events",
        )
    },
}
_AGENT_SCOPE_UNIQUE_INDEXES: Final[dict[str, frozenset[_UniqueIndexSpec]]] = {
    **_TENANT_BOOTSTRAP_UNIQUE_INDEXES,
    "agents": frozenset(
        {
            (
                ("org_id", "name"),
                "agent-scope:legacy-unscoped",
            ),
            (
                ("org_id", "project_id", "environment_id", "name"),
                "agent-scope:scoped",
            ),
        }
    ),
    "policy_bundles": frozenset({(("org_id",), "status:active")}),
}
_AGENT_REGISTRATION_IDEMPOTENCY_UNIQUE_INDEXES: Final[dict[str, frozenset[_UniqueIndexSpec]]] = {
    **_AGENT_SCOPE_UNIQUE_INDEXES,
    "agent_registration_idempotency": frozenset(),
}
_POLICY_REGISTRY_UNIQUE_INDEXES: Final[dict[str, frozenset[_UniqueIndexSpec]]] = {
    **_AGENT_REGISTRATION_IDEMPOTENCY_UNIQUE_INDEXES,
    "policy_versions": frozenset(),
    "environment_policy_heads": frozenset(),
    "policy_registry_idempotency": frozenset(),
}
_APPROVAL_SUBSTRATE_UNIQUE_INDEXES: Final[dict[str, frozenset[_UniqueIndexSpec]]] = {
    **_POLICY_REGISTRY_UNIQUE_INDEXES,
    "approval_requests": frozenset(),
    "approval_votes": frozenset(),
    "approval_outcomes": frozenset(),
    "approval_resume_authorizations": frozenset(),
}
_RUNTIME_ENROLLMENT_UNIQUE_INDEXES: Final[dict[str, frozenset[_UniqueIndexSpec]]] = {
    **_APPROVAL_SUBSTRATE_UNIQUE_INDEXES,
    "runtime_identity_gates": frozenset(),
    "runtime_identities": frozenset(),
    "runtime_enrollment_bootstraps": frozenset(
        {
            (
                ("org_id", "project_id", "environment_id", "gate_id"),
                "status:active",
            )
        }
    ),
    "runtime_credential_generations": frozenset(
        {
            (
                ("org_id", "project_id", "environment_id", "identity_id"),
                "status:active",
            )
        }
    ),
    "runtime_enrollment_idempotency": frozenset(),
    "runtime_request_nonces": frozenset(),
    "runtime_operation_idempotency": frozenset(),
}
_RUNTIME_REPORTS_UNIQUE_INDEXES: Final[dict[str, frozenset[_UniqueIndexSpec]]] = {
    **_RUNTIME_ENROLLMENT_UNIQUE_INDEXES,
    "runtime_reports": frozenset(),
    "runtime_wiring_attestations": frozenset(),
    "runtime_report_heads": frozenset(),
    "runtime_wiring_challenge_consumptions": frozenset(),
}
_PROJECTS_ONLY_UNIQUES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_LEGACY_UNIQUES,
    "projects": _SCOPED_UNIQUES["projects"],
}
_PROJECTS_ONLY_CREATE_ALL_UNIQUES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_LEGACY_CREATE_ALL_UNIQUES,
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
_TRUST_V2_NON_UNIQUE_INDEXES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_MANAGED_MUTATION_NON_UNIQUE_INDEXES,
    "managed_trust_scopes": frozenset({("org_id",)}),
    "managed_trust_keys": frozenset({("org_id",)}),
}
_TENANT_BOOTSTRAP_NON_UNIQUE_INDEXES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_TRUST_V2_NON_UNIQUE_INDEXES,
    "organization_memberships": frozenset({("org_id",), ("user_id",)}),
    "platform_bootstrap_invitations": frozenset({("invitee_actor",)}),
    "tenant_bootstrap_idempotency": frozenset(),
    "tenant_bootstrap_policy_artifacts": frozenset({("invitation_id",)}),
    "pending_approvals": frozenset({("org_id",), ("invitation_id",), ("policy_artifact_id",)}),
    "tenant_bootstrap_pending_outbox": frozenset({("invitation_id",), ("policy_artifact_id",)}),
    "tenant_bootstrap_refusal_events": frozenset(),
}
_AGENT_REGISTRATION_IDEMPOTENCY_NON_UNIQUE_INDEXES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_TENANT_BOOTSTRAP_NON_UNIQUE_INDEXES,
    "agent_registration_idempotency": frozenset({("org_id",)}),
}
_POLICY_REGISTRY_NON_UNIQUE_INDEXES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_AGENT_REGISTRATION_IDEMPOTENCY_NON_UNIQUE_INDEXES,
    "policy_versions": frozenset({("org_id",)}),
    "environment_policy_heads": frozenset({("org_id",)}),
    "policy_registry_idempotency": frozenset({("org_id",)}),
}
_APPROVAL_SUBSTRATE_NON_UNIQUE_INDEXES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_POLICY_REGISTRY_NON_UNIQUE_INDEXES,
    "approval_requests": frozenset({("org_id",)}),
    "approval_votes": frozenset({("org_id",)}),
    "approval_outcomes": frozenset({("org_id",)}),
    "approval_resume_authorizations": frozenset({("org_id",)}),
}
_RUNTIME_ENROLLMENT_NON_UNIQUE_INDEXES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_APPROVAL_SUBSTRATE_NON_UNIQUE_INDEXES,
    "runtime_identity_gates": frozenset({("org_id",)}),
    "runtime_identities": frozenset({("org_id",)}),
    "runtime_enrollment_bootstraps": frozenset({("org_id",)}),
    "runtime_credential_generations": frozenset({("org_id",)}),
    "runtime_enrollment_idempotency": frozenset({("org_id",)}),
    "runtime_request_nonces": frozenset({("org_id",)}),
    "runtime_operation_idempotency": frozenset({("org_id",)}),
}
_RUNTIME_REPORTS_NON_UNIQUE_INDEXES: Final[dict[str, frozenset[tuple[str, ...]]]] = {
    **_RUNTIME_ENROLLMENT_NON_UNIQUE_INDEXES,
    "runtime_reports": frozenset({("org_id",)}),
    "runtime_wiring_attestations": frozenset(
        {("org_id", "project_id", "environment_id", "identity_id")}
    ),
    "runtime_report_heads": frozenset({("org_id",)}),
    "runtime_wiring_challenge_consumptions": frozenset({("org_id",)}),
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
_TRUST_V2_CHECKS: Final[dict[str, frozenset[tuple[str, str]]]] = {
    **_MANAGED_MUTATION_CHECKS,
    "managed_trust_scopes": frozenset(),
    "managed_trust_keys": frozenset(
        {
            (
                "ck_managed_trust_key_status",
                "status IN ('active', 'retired', 'revoked')",
            ),
            ("ck_managed_trust_key_epoch_positive", "activated_epoch > 0"),
            (
                "ck_managed_trust_key_retired_epoch",
                "(status = 'retired' AND retired_epoch IS NOT NULL "
                "AND retired_epoch > activated_epoch) OR "
                "(status IN ('active', 'revoked') AND retired_epoch IS NULL)",
            ),
        }
    ),
}
_TENANT_BOOTSTRAP_CHECKS: Final[dict[str, frozenset[tuple[str, str]]]] = {
    **_TRUST_V2_CHECKS,
    "organization_memberships": frozenset({("ck_org_memberships_role", "role IN ('owner')")}),
    "platform_bootstrap_invitations": frozenset(
        {
            (
                "ck_platform_bootstrap_invitation_policy_outcome",
                "policy_outcome IN ('allow', 'deny', 'escalate')",
            ),
        }
    ),
    "tenant_bootstrap_idempotency": frozenset(),
    "tenant_bootstrap_policy_artifacts": frozenset(
        {
            (
                "ck_tenant_bootstrap_policy_decision",
                "decision IN ('deny', 'escalate')",
            ),
        }
    ),
    "pending_approvals": frozenset({("ck_pending_approvals_status", "status IN ('pending')")}),
    "tenant_bootstrap_pending_outbox": frozenset(
        {
            (
                "ck_tenant_bootstrap_pending_status",
                "status IN ('pending', 'delivered', 'failed')",
            ),
        }
    ),
    "tenant_bootstrap_refusal_events": frozenset(
        {
            ("ck_tbr_route", "route = 'POST /v1/tenant-bootstrap'"),
            ("ck_tbr_method", "method = 'POST'"),
            (
                "ck_tbr_stage",
                "stage IN ('transport', 'authn', 'authz', 'policy', 'issuance', 'executor', 'tx')",
            ),
            ("ck_tbr_status", "http_status IN (400, 401, 403, 409, 413, 503)"),
        }
    ),
}
_AGENT_SCOPE_CHECKS: Final[dict[str, frozenset[tuple[str, str]]]] = {
    **_TENANT_BOOTSTRAP_CHECKS,
    "agents": frozenset(
        {
            (
                "ck_agents_scope_both_null_or_set",
                "(project_id IS NULL AND environment_id IS NULL) OR "
                "(project_id IS NOT NULL AND environment_id IS NOT NULL)",
            ),
        }
    ),
}
_AGENT_REGISTRATION_IDEMPOTENCY_CHECKS: Final[dict[str, frozenset[tuple[str, str]]]] = {
    **_AGENT_SCOPE_CHECKS,
    "agent_registration_idempotency": frozenset(),
}
_POLICY_REGISTRY_CHECKS: Final[dict[str, frozenset[tuple[str, str]]]] = {
    **_AGENT_REGISTRATION_IDEMPOTENCY_CHECKS,
    "policy_versions": frozenset(
        {
            ("ck_pv_trust_epoch_positive", "trust_epoch > 0"),
            ("ck_pv_signature_algorithm", "signature_algorithm = 'ed25519'"),
            ("ck_pv_purpose", "purpose = 'acgs.policy-envelope/v1'"),
        }
    ),
    "environment_policy_heads": frozenset(
        {
            ("ck_eph_generation_nonnegative", "generation >= 0"),
            ("ck_eph_status", "status IN ('active')"),
        }
    ),
    "policy_registry_idempotency": frozenset(),
}
_APPROVAL_SUBSTRATE_CHECKS: Final[dict[str, frozenset[tuple[str, str]]]] = {
    **_POLICY_REGISTRY_CHECKS,
    "approval_requests": frozenset(
        {
            ("ck_approval_requests_status_pending", "status = 'pending'"),
            ("ck_approval_requests_quorum_positive", "quorum_threshold > 0"),
        }
    ),
    "approval_votes": frozenset(
        {("ck_approval_votes_decision", "decision IN ('approve', 'reject')")}
    ),
    "approval_outcomes": frozenset(
        {
            (
                "ck_approval_outcomes_outcome",
                "outcome IN ('approved', 'rejected', 'expired', 'canceled')",
            )
        }
    ),
    "approval_resume_authorizations": frozenset(),
}
_RUNTIME_ENROLLMENT_CHECKS: Final[dict[str, frozenset[tuple[str, str]]]] = {
    **_APPROVAL_SUBSTRATE_CHECKS,
    "runtime_identity_gates": frozenset(
        {("ck_runtime_identity_gate_status", "status IN ('active', 'revoked')")}
    ),
    "runtime_identities": frozenset(
        {("ck_runtime_identities_status", "status IN ('active', 'revoked')")}
    ),
    "runtime_enrollment_bootstraps": frozenset(
        {
            (
                "ck_runtime_enrollment_bootstrap_status",
                "status IN ('active', 'consumed', 'revoked', 'expired')",
            )
        }
    ),
    "runtime_credential_generations": frozenset(
        {
            (
                "ck_runtime_credential_generation_status",
                "status IN ('active', 'superseded', 'revoked', 'expired')",
            )
        }
    ),
    "runtime_enrollment_idempotency": frozenset(),
    "runtime_request_nonces": frozenset(),
    "runtime_operation_idempotency": frozenset(),
}
_RUNTIME_REPORTS_CHECKS: Final[dict[str, frozenset[tuple[str, str]]]] = {
    **_RUNTIME_ENROLLMENT_CHECKS,
    "runtime_reports": frozenset(
        {
            ("ck_runtime_reports_kind", "kind IN ('status', 'wiring')"),
            (
                "ck_runtime_reports_sequence_positive",
                "sequence >= 1 AND sequence <= 9007199254740991",
            ),
            ("ck_runtime_reports_expiry_order", "expires_at > observed_at"),
            (
                "ck_runtime_reports_policy_time_order",
                "policy_issued_at <= policy_revocation_checked_at AND "
                "policy_revocation_checked_at <= policy_fresh_until AND "
                "policy_fresh_until <= policy_expires_at",
            ),
        }
    ),
    "runtime_wiring_attestations": frozenset(
        {
            ("ck_runtime_wiring_attestations_assurance", "assurance_class = 'observed'"),
            (
                "ck_runtime_wiring_attestations_evidence_kind",
                "evidence_kind = 'in_process_public_surface_conformance'",
            ),
            ("ck_runtime_wiring_attestations_report_kind", "report_kind = 'wiring'"),
        }
    ),
    "runtime_report_heads": frozenset(
        {
            (
                "ck_runtime_report_heads_sequence_positive",
                "last_sequence >= 1 AND last_sequence <= 9007199254740991",
            ),
            (
                "ck_runtime_report_heads_history_count",
                "history_count = last_sequence",
            ),
            (
                "ck_runtime_report_heads_wiring_sequence_bounds",
                "latest_wiring_sequence IS NULL OR "
                "(latest_wiring_sequence >= 1 AND "
                "latest_wiring_sequence <= 9007199254740991)",
            ),
            (
                "ck_runtime_report_heads_wiring_sequence_order",
                "latest_wiring_sequence IS NULL OR latest_wiring_sequence <= last_sequence",
            ),
            (
                "ck_runtime_report_heads_wiring_tuple",
                "(latest_wiring_report_id IS NULL AND latest_wiring_kind IS NULL "
                "AND latest_wiring_sequence IS NULL AND latest_wiring_report_hash IS NULL "
                "AND latest_wiring_projection_commitment IS NULL) OR "
                "(latest_wiring_report_id IS NOT NULL AND latest_wiring_kind = 'wiring' "
                "AND latest_wiring_sequence IS NOT NULL AND latest_wiring_report_hash IS NOT NULL "
                "AND latest_wiring_projection_commitment IS NOT NULL)",
            ),
        }
    ),
    "runtime_wiring_challenge_consumptions": frozenset(
        {
            ("ck_runtime_wiring_challenge_kind", "report_kind = 'wiring'"),
            (
                "ck_runtime_wiring_challenge_sequence_bounds",
                "sequence >= 1 AND sequence <= 9007199254740991",
            ),
            (
                "ck_runtime_wiring_challenge_expected_sequence_bounds",
                "expected_sequence >= 1 AND expected_sequence <= 9007199254740991",
            ),
            (
                "ck_runtime_wiring_challenge_expected_sequence_binding",
                "expected_sequence = sequence",
            ),
        }
    ),
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
        legacy_create_all_detail = _schema_detail(
            inspector,
            table_names,
            _LEGACY_CREATE_ALL_COLUMNS,
            _LEGACY_PRIMARY_KEYS,
            _LEGACY_FOREIGN_KEYS,
            _LEGACY_CREATE_ALL_UNIQUES,
            _LEGACY_NON_UNIQUE_INDEXES,
        )
        if legacy_create_all_detail is None:
            return SchemaPreflight(
                DatabaseSchemaState.LEGACY_V0,
                "current metadata-created v0 schema; safe to stamp revision 0001",
            )
        return SchemaPreflight(
            DatabaseSchemaState.UNKNOWN,
            _detail_after_nullable_user_fallback(legacy_detail, legacy_create_all_detail),
        )

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
        create_all_detail = _schema_detail(
            inspector,
            user_tables,
            _SCOPED_CREATE_ALL_COLUMNS,
            _SCOPED_PRIMARY_KEYS,
            _SCOPED_FOREIGN_KEYS,
            _SCOPED_CREATE_ALL_UNIQUES,
            _SCOPED_NON_UNIQUE_INDEXES,
        )
        if create_all_detail is None:
            return SchemaPreflight(
                DatabaseSchemaState.VERSION_0002,
                "known Alembic revision 0002 with metadata-created nullable user key",
            )
        return SchemaPreflight(
            DatabaseSchemaState.UNKNOWN,
            _detail_after_nullable_user_fallback(detail, create_all_detail),
        )
    if versions == [MANAGED_MUTATION_REVISION]:
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
        create_all_detail = _schema_detail(
            inspector,
            user_tables,
            _MANAGED_MUTATION_CREATE_ALL_COLUMNS,
            _MANAGED_MUTATION_PRIMARY_KEYS,
            _MANAGED_MUTATION_FOREIGN_KEYS,
            _MANAGED_MUTATION_CREATE_ALL_UNIQUES,
            _MANAGED_MUTATION_NON_UNIQUE_INDEXES,
            _MANAGED_MUTATION_CHECKS,
        )
        if create_all_detail is None:
            return SchemaPreflight(
                DatabaseSchemaState.VERSION_0003,
                "known Alembic revision 0003 with metadata-created nullable user key",
            )
        return SchemaPreflight(
            DatabaseSchemaState.UNKNOWN,
            _detail_after_nullable_user_fallback(detail, create_all_detail),
        )
    if versions == [TRUST_V2_REVISION]:
        detail = _schema_detail(
            inspector,
            user_tables,
            _TRUST_V2_COLUMNS,
            _TRUST_V2_PRIMARY_KEYS,
            _TRUST_V2_FOREIGN_KEYS,
            _TRUST_V2_UNIQUES,
            _TRUST_V2_NON_UNIQUE_INDEXES,
            _TRUST_V2_CHECKS,
            _TRUST_V2_UNIQUE_INDEXES,
        )
        if detail is None:
            return SchemaPreflight(DatabaseSchemaState.VERSION_0004, "known Alembic revision 0004")
        create_all_detail = _schema_detail(
            inspector,
            user_tables,
            _TRUST_V2_CREATE_ALL_COLUMNS,
            _TRUST_V2_PRIMARY_KEYS,
            _TRUST_V2_FOREIGN_KEYS,
            _TRUST_V2_CREATE_ALL_UNIQUES,
            _TRUST_V2_NON_UNIQUE_INDEXES,
            _TRUST_V2_CHECKS,
            _TRUST_V2_UNIQUE_INDEXES,
        )
        if create_all_detail is None:
            return SchemaPreflight(
                DatabaseSchemaState.VERSION_0004,
                "known Alembic revision 0004 with metadata-created nullable user key",
            )
        return SchemaPreflight(
            DatabaseSchemaState.UNKNOWN,
            _detail_after_nullable_user_fallback(detail, create_all_detail),
        )
    if versions == [TENANT_BOOTSTRAP_REVISION]:
        detail = _schema_detail(
            inspector,
            user_tables,
            _TENANT_BOOTSTRAP_COLUMNS,
            _TENANT_BOOTSTRAP_PRIMARY_KEYS,
            _TENANT_BOOTSTRAP_FOREIGN_KEYS,
            _TENANT_BOOTSTRAP_UNIQUES,
            _TENANT_BOOTSTRAP_NON_UNIQUE_INDEXES,
            _TENANT_BOOTSTRAP_CHECKS,
            _TENANT_BOOTSTRAP_UNIQUE_INDEXES,
        )
        if detail is None:
            return SchemaPreflight(DatabaseSchemaState.VERSION_0005, "known Alembic revision 0005")
        return SchemaPreflight(DatabaseSchemaState.UNKNOWN, detail)
    if versions == [AGENT_SCOPE_REVISION]:
        detail = _schema_detail(
            inspector,
            user_tables,
            _AGENT_SCOPE_COLUMNS,
            _TENANT_BOOTSTRAP_PRIMARY_KEYS,
            _AGENT_SCOPE_FOREIGN_KEYS,
            _AGENT_SCOPE_UNIQUES,
            _TENANT_BOOTSTRAP_NON_UNIQUE_INDEXES,
            _AGENT_SCOPE_CHECKS,
            _AGENT_SCOPE_UNIQUE_INDEXES,
        )
        if detail is None:
            return SchemaPreflight(DatabaseSchemaState.VERSION_0006, "known Alembic revision 0006")
        return SchemaPreflight(DatabaseSchemaState.UNKNOWN, detail)
    if versions == [AGENT_REGISTRATION_IDEMPOTENCY_REVISION]:
        detail = _schema_detail(
            inspector,
            user_tables,
            _AGENT_REGISTRATION_IDEMPOTENCY_COLUMNS,
            _AGENT_REGISTRATION_IDEMPOTENCY_PRIMARY_KEYS,
            _AGENT_REGISTRATION_IDEMPOTENCY_FOREIGN_KEYS,
            _AGENT_REGISTRATION_IDEMPOTENCY_UNIQUES,
            _AGENT_REGISTRATION_IDEMPOTENCY_NON_UNIQUE_INDEXES,
            _AGENT_REGISTRATION_IDEMPOTENCY_CHECKS,
            _AGENT_REGISTRATION_IDEMPOTENCY_UNIQUE_INDEXES,
        )
        if detail is None:
            return SchemaPreflight(DatabaseSchemaState.VERSION_0007, "known Alembic revision 0007")
        return SchemaPreflight(DatabaseSchemaState.UNKNOWN, detail)
    if versions == [POLICY_REGISTRY_REVISION]:
        detail = _schema_detail(
            inspector,
            user_tables,
            _POLICY_REGISTRY_COLUMNS,
            _POLICY_REGISTRY_PRIMARY_KEYS,
            _POLICY_REGISTRY_FOREIGN_KEYS,
            _POLICY_REGISTRY_UNIQUES,
            _POLICY_REGISTRY_NON_UNIQUE_INDEXES,
            _POLICY_REGISTRY_CHECKS,
            _POLICY_REGISTRY_UNIQUE_INDEXES,
        )
        if detail is None:
            return SchemaPreflight(DatabaseSchemaState.VERSION_0008, "known Alembic revision 0008")
        return SchemaPreflight(DatabaseSchemaState.UNKNOWN, detail)
    if versions == [APPROVAL_SUBSTRATE_REVISION]:
        detail = _schema_detail(
            inspector,
            user_tables,
            _APPROVAL_SUBSTRATE_0009_COLUMNS,
            _APPROVAL_SUBSTRATE_PRIMARY_KEYS,
            _APPROVAL_SUBSTRATE_0009_FOREIGN_KEYS,
            _APPROVAL_SUBSTRATE_0009_UNIQUES,
            _APPROVAL_SUBSTRATE_NON_UNIQUE_INDEXES,
            _APPROVAL_SUBSTRATE_CHECKS,
            _APPROVAL_SUBSTRATE_UNIQUE_INDEXES,
        )
        if detail is None:
            return SchemaPreflight(DatabaseSchemaState.VERSION_0009, "known Alembic revision 0009")
        return SchemaPreflight(DatabaseSchemaState.UNKNOWN, detail)
    if versions == [APPROVAL_VOTE_BINDING_REVISION]:
        detail = _schema_detail(
            inspector,
            user_tables,
            _APPROVAL_VOTE_BINDING_COLUMNS,
            _APPROVAL_SUBSTRATE_PRIMARY_KEYS,
            _APPROVAL_VOTE_BINDING_FOREIGN_KEYS,
            _APPROVAL_VOTE_BINDING_UNIQUES,
            _APPROVAL_SUBSTRATE_NON_UNIQUE_INDEXES,
            _APPROVAL_SUBSTRATE_CHECKS,
            _APPROVAL_SUBSTRATE_UNIQUE_INDEXES,
        )
        if detail is None:
            return SchemaPreflight(DatabaseSchemaState.VERSION_0010, "known Alembic revision 0010")
        return SchemaPreflight(DatabaseSchemaState.UNKNOWN, detail)
    if versions == [RUNTIME_ENROLLMENT_REVISION]:
        detail = _schema_detail(
            inspector,
            user_tables,
            _RUNTIME_ENROLLMENT_COLUMNS,
            _RUNTIME_ENROLLMENT_PRIMARY_KEYS,
            _RUNTIME_ENROLLMENT_FOREIGN_KEYS,
            _RUNTIME_ENROLLMENT_UNIQUES,
            _RUNTIME_ENROLLMENT_NON_UNIQUE_INDEXES,
            _RUNTIME_ENROLLMENT_CHECKS,
            _RUNTIME_ENROLLMENT_UNIQUE_INDEXES,
        )
        if detail is None:
            return SchemaPreflight(DatabaseSchemaState.VERSION_0011, "known Alembic revision 0011")
        return SchemaPreflight(DatabaseSchemaState.UNKNOWN, detail)
    if versions in ([RUNTIME_REPORTS_REVISION], [HEAD_REVISION]):
        detail = _schema_detail(
            inspector,
            user_tables,
            _RUNTIME_REPORTS_COLUMNS,
            _RUNTIME_REPORTS_PRIMARY_KEYS,
            _RUNTIME_REPORTS_FOREIGN_KEYS,
            _RUNTIME_REPORTS_UNIQUES,
            _RUNTIME_REPORTS_NON_UNIQUE_INDEXES,
            _RUNTIME_REPORTS_CHECKS,
            _RUNTIME_REPORTS_UNIQUE_INDEXES,
        )
        if detail is None:
            if versions == [RUNTIME_REPORTS_REVISION]:
                detail = _runtime_lineage_object_detail(
                    connection,
                    expected_sqlite_objects=SQLITE_RUNTIME_LINEAGE_OBJECTS_0012,
                    expected_postgres_functions=POSTGRES_RUNTIME_LINEAGE_FUNCTIONS_0012,
                    expected_postgres_triggers=POSTGRES_RUNTIME_LINEAGE_TRIGGERS_0012,
                    expected_postgres_enabled_states=(
                        POSTGRES_RUNTIME_LINEAGE_TRIGGER_ENABLED_STATES_0012
                    ),
                )
            else:
                detail = _runtime_lineage_object_detail(
                    connection,
                    expected_sqlite_objects=SQLITE_RUNTIME_LINEAGE_OBJECTS,
                    expected_postgres_functions=POSTGRES_RUNTIME_LINEAGE_FUNCTIONS,
                    expected_postgres_triggers=POSTGRES_RUNTIME_LINEAGE_TRIGGERS,
                    expected_postgres_enabled_states=(
                        POSTGRES_RUNTIME_LINEAGE_TRIGGER_ENABLED_STATES
                    ),
                )
        if detail is None:
            if versions == [RUNTIME_REPORTS_REVISION]:
                return SchemaPreflight(
                    DatabaseSchemaState.VERSION_0012, "known Alembic revision 0012"
                )
            return SchemaPreflight(DatabaseSchemaState.VERSION_0013, "known Alembic revision 0013")
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
    if preflight.state is not DatabaseSchemaState.VERSION_0013:
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
    if after.state is not DatabaseSchemaState.VERSION_0013:
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
                    if after.state is not DatabaseSchemaState.VERSION_0013:
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
    legacy_create_all_detail = _schema_detail(
        inspector,
        user_tables,
        _LEGACY_CREATE_ALL_COLUMNS,
        _LEGACY_PRIMARY_KEYS,
        _LEGACY_FOREIGN_KEYS,
        _LEGACY_CREATE_ALL_UNIQUES,
        _LEGACY_NON_UNIQUE_INDEXES,
    )
    if legacy_create_all_detail is None:
        return SchemaPreflight(
            DatabaseSchemaState.VERSION_0001,
            "known Alembic revision 0001 with metadata-created nullable user key",
        )

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
    projects_create_all_detail = _schema_detail(
        inspector,
        user_tables,
        _PROJECTS_ONLY_CREATE_ALL_COLUMNS,
        _PROJECTS_ONLY_PRIMARY_KEYS,
        _PROJECTS_ONLY_FOREIGN_KEYS,
        _PROJECTS_ONLY_CREATE_ALL_UNIQUES,
        _PROJECTS_ONLY_NON_UNIQUE_INDEXES,
    )
    if projects_create_all_detail is None:
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
    scoped_create_all_detail = _schema_detail(
        inspector,
        user_tables,
        _SCOPED_CREATE_ALL_COLUMNS,
        _SCOPED_PRIMARY_KEYS,
        _SCOPED_FOREIGN_KEYS,
        _SCOPED_CREATE_ALL_UNIQUES,
        _SCOPED_NON_UNIQUE_INDEXES,
    )
    if scoped_create_all_detail is None:
        empty_detail = _scope_tables_empty(connection, ("projects", "environments"))
        if empty_detail is None:
            return SchemaPreflight(
                DatabaseSchemaState.VERSION_0001_PARTIAL_SCOPE,
                "exact, empty scope tables exist before revision 0002 was recorded",
            )
        return SchemaPreflight(DatabaseSchemaState.UNKNOWN, empty_detail)

    if user_tables == set(_PROJECTS_ONLY_COLUMNS):
        return SchemaPreflight(
            DatabaseSchemaState.UNKNOWN,
            _detail_after_nullable_user_fallback(projects_detail, projects_create_all_detail),
        )
    if user_tables == set(_SCOPED_COLUMNS):
        return SchemaPreflight(
            DatabaseSchemaState.UNKNOWN,
            _detail_after_nullable_user_fallback(scoped_detail, scoped_create_all_detail),
        )
    return SchemaPreflight(
        DatabaseSchemaState.UNKNOWN,
        _detail_after_nullable_user_fallback(legacy_detail, legacy_create_all_detail),
    )


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

    owned_objects = {
        ("trigger", "environment_policy_heads_monotonic_update"),
        ("trigger", "policy_versions_immutable_delete"),
        ("trigger", "policy_versions_immutable_update"),
        ("trigger", "runtime_report_heads_monotonic_delete"),
        ("trigger", "runtime_report_heads_monotonic_update"),
        ("trigger", "runtime_reports_immutable_delete"),
        ("trigger", "runtime_reports_immutable_update"),
        ("trigger", "runtime_wiring_attestations_immutable_delete"),
        ("trigger", "runtime_wiring_attestations_immutable_update"),
        ("trigger", "runtime_wiring_challenge_consumptions_immutable_delete"),
        ("trigger", "runtime_wiring_challenge_consumptions_immutable_update"),
        ("trigger", "public.environment_policy_heads.environment_policy_heads_monotonic_update"),
        ("trigger", "public.policy_versions.policy_versions_immutable_delete"),
        ("trigger", "public.policy_versions.policy_versions_immutable_update"),
        (
            "trigger",
            "public.runtime_report_heads.runtime_report_heads_monotonic_delete",
        ),
        (
            "trigger",
            "public.runtime_report_heads.runtime_report_heads_monotonic_update",
        ),
        ("trigger", "public.runtime_reports.runtime_reports_immutable_delete"),
        ("trigger", "public.runtime_reports.runtime_reports_immutable_update"),
        (
            "trigger",
            "public.runtime_wiring_attestations.runtime_wiring_attestations_immutable_delete",
        ),
        (
            "trigger",
            "public.runtime_wiring_attestations.runtime_wiring_attestations_immutable_update",
        ),
        (
            "trigger",
            "public.runtime_wiring_challenge_consumptions."
            "runtime_wiring_challenge_consumptions_immutable_delete",
        ),
        (
            "trigger",
            "public.runtime_wiring_challenge_consumptions."
            "runtime_wiring_challenge_consumptions_immutable_update",
        ),
        (
            "trigger",
            "public.runtime_wiring_challenge_consumptions."
            "runtime_wiring_challenge_consumptions_immutable_truncate",
        ),
        ("function", "public.acgs_environment_policy_heads_monotonic()"),
        ("function", "public.acgs_policy_versions_immutable()"),
        ("function", "public.acgs_runtime_report_heads_monotonic()"),
        ("function", "public.acgs_runtime_reports_immutable()"),
        ("function", "public.acgs_runtime_wiring_attestations_immutable()"),
        ("function", "public.acgs_runtime_wiring_challenge_consumptions_immutable()"),
    }
    rows = [row for row in rows if (str(row[0]), str(row[1])) not in owned_objects]
    if rows:
        objects = ", ".join(f"{row[0]}:{row[1]}" for row in rows)
        return f"unexpected non-table schema objects: {objects}"
    return None


def _normalized_runtime_lineage_definition(value: object) -> str:
    definition = str(value or "").lower().replace('"', "")
    definition = definition.replace("public.", "")
    definition = re.sub(r"\$[a-z_][a-z0-9_]*\$", "$$", definition)
    return "".join(definition.split()).rstrip(";")


def _runtime_lineage_object_detail(
    connection: Connection,
    *,
    expected_sqlite_objects: Mapping[str, str],
    expected_postgres_functions: Mapping[str, str],
    expected_postgres_triggers: Mapping[str, str],
    expected_postgres_enabled_states: Mapping[str, str],
) -> str | None:
    """Require exact version-owned lineage objects while querying the known union."""

    dialect_name = connection.dialect.name
    actual: dict[str, str | tuple[str, str]]
    expected: dict[str, str | tuple[str, str]]
    try:
        if dialect_name == "sqlite":
            rows = connection.execute(
                sa.text(
                    "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND name IN :names"
                ).bindparams(
                    sa.bindparam(
                        "names",
                        expanding=True,
                        value=tuple(SQLITE_RUNTIME_LINEAGE_OBJECTS),
                    )
                )
            ).all()
            actual = {str(name): _normalized_runtime_lineage_definition(sql) for name, sql in rows}
            expected = {
                name: _normalized_runtime_lineage_definition(definition)
                for name, definition in expected_sqlite_objects.items()
            }
        elif dialect_name == "postgresql":
            trigger_rows = connection.execute(
                sa.text(
                    """
                    SELECT t.tgname, pg_catalog.pg_get_triggerdef(t.oid, false), t.tgenabled
                    FROM pg_catalog.pg_trigger AS t
                    JOIN pg_catalog.pg_class AS c ON c.oid = t.tgrelid
                    JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                    WHERE NOT t.tgisinternal AND n.nspname = 'public'
                      AND t.tgname IN :names
                    """
                ).bindparams(
                    sa.bindparam(
                        "names",
                        expanding=True,
                        value=tuple(POSTGRES_RUNTIME_LINEAGE_TRIGGERS),
                    )
                )
            ).all()
            function_rows = connection.execute(
                sa.text(
                    """
                    SELECT p.proname, pg_catalog.pg_get_functiondef(p.oid)
                    FROM pg_catalog.pg_proc AS p
                    JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
                    WHERE n.nspname = 'public' AND p.pronargs = 0
                      AND p.proname IN :names
                    """
                ).bindparams(
                    sa.bindparam(
                        "names",
                        expanding=True,
                        value=tuple(POSTGRES_RUNTIME_LINEAGE_FUNCTIONS),
                    )
                )
            ).all()
            actual = {
                f"trigger:{name}": (
                    _normalized_runtime_lineage_definition(definition),
                    str(enabled_state),
                )
                for name, definition, enabled_state in trigger_rows
            }
            actual.update(
                {
                    f"function:{name}": _normalized_runtime_lineage_definition(definition)
                    for name, definition in function_rows
                }
            )
            expected = {
                f"trigger:{name}": (
                    _normalized_runtime_lineage_definition(definition),
                    expected_postgres_enabled_states[name],
                )
                for name, definition in expected_postgres_triggers.items()
            }
            expected.update(
                {
                    f"function:{name}": _normalized_runtime_lineage_definition(definition)
                    for name, definition in expected_postgres_functions.items()
                }
            )
        else:
            return f"unsupported runtime lineage inspection dialect: {dialect_name}"
    except SQLAlchemyError as exc:
        return f"unable to inspect runtime lineage objects: {type(exc).__name__}"

    if actual.keys() != expected.keys():
        missing = sorted(expected.keys() - actual.keys())
        unexpected = sorted(actual.keys() - expected.keys())
        return f"runtime lineage objects missing={missing!r} unexpected={unexpected!r}"
    drifted = sorted(name for name in expected if actual[name] != expected[name])
    if drifted:
        return f"runtime lineage object definitions drifted: {drifted!r}"
    return None


def _canonical_referred_schema(value: object, dialect_name: str) -> str | None:
    """Map the dialect's canonical local schema to the frozen ``None`` sentinel."""
    canonical = {"postgresql": "public", "sqlite": "main"}.get(dialect_name)
    if value is None or (canonical is not None and value == canonical):
        return None
    return str(value)


def _has_only_expected_foreign_key_options(
    table_name: str,
    foreign_key: Mapping[str, Any],
    dialect_name: str,
    *,
    require_deferred: bool,
) -> bool:
    options = foreign_key.get("options") or {}
    if not options:
        return not require_deferred
    if dialect_name not in {"postgresql", "sqlite"}:
        return False
    if table_name not in _DEFERRABLE_MANAGED_MUTATION_FK_TABLES:
        return False

    normalized = {str(key).lower(): value for key, value in options.items()}
    return (
        normalized.get("deferrable") is True
        and str(normalized.get("initially", "")).upper() == "DEFERRED"
        and set(normalized) <= {"deferrable", "initially"}
    )


def _schema_detail(
    inspector: Inspector,
    actual_tables: set[str],
    expected_columns: dict[str, tuple[_ColumnSpec, ...]],
    expected_primary_keys: dict[str, tuple[str, ...]],
    expected_foreign_keys: dict[str, frozenset[_ForeignKeySpec]],
    expected_uniques: dict[str, frozenset[tuple[str, ...]]],
    expected_non_unique_indexes: dict[str, frozenset[tuple[str, ...]]],
    expected_checks: dict[str, frozenset[tuple[str, str]]] | None = None,
    expected_unique_indexes: dict[str, frozenset[_UniqueIndexSpec]] | None = None,
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
    expected_unique_indexes_by_table = expected_unique_indexes or {
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
        if any(
            not _has_only_expected_foreign_key_options(
                table_name,
                foreign_key,
                dialect_name,
                require_deferred=(
                    table_name.startswith("runtime_")
                    and (
                        expected_foreign_keys is _RUNTIME_ENROLLMENT_FOREIGN_KEYS
                        or expected_foreign_keys is _RUNTIME_REPORTS_FOREIGN_KEYS
                    )
                ),
            )
            for foreign_key in foreign_keys
        ):
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
        actual_unique_indexes: set[_UniqueIndexSpec] = set()
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
                predicate = _index_where_signature(index, dialect_name)
                if predicate is None:
                    actual_uniques.add(column_names)
                else:
                    actual_unique_indexes.add((column_names, predicate))
            else:
                actual_indexes.add(column_names)
        if frozenset(actual_uniques) != expected_uniques[table_name]:
            return f"{table_name} has unexpected unique constraints or indexes"

        if frozenset(actual_unique_indexes) != expected_unique_indexes_by_table[table_name]:
            return f"{table_name} has unexpected unique index predicates"

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
    singleton_status_signature = _singleton_status_signature_from_sql(value)
    if singleton_status_signature is not None:
        return singleton_status_signature

    status_set_signature = _status_set_signature_from_sql(value)
    if status_set_signature is not None:
        return status_set_signature

    raw = str(value or "").lower()
    compact = _normalized_constraint_sql(
        re.sub(
            r"::(?:text|character\s+varying|bigint|integer|numeric)(?:\[\])?",
            "",
            raw,
            flags=re.IGNORECASE,
        )
    ).lower()
    compact = compact.replace("(assurance_class)", "assurance_class")
    compact = compact.replace("(source_system)", "source_system")
    compact = compact.replace("(status)", "status")
    compact = re.sub(r"'([0-9]+)'", r"\1", compact)
    compact = re.sub(r"\('([^']+)'\)", r"'\1'", compact)
    compact = _strip_outer_parentheses(compact)

    head_wiring_compact = compact.replace("(", "").replace(")", "")
    if head_wiring_compact == "sequence>=1andsequence<=9007199254740991":
        return "sequence:ijson_bounds"
    if head_wiring_compact == "last_sequence>=1andlast_sequence<=9007199254740991":
        return "last_sequence:ijson_bounds"
    if head_wiring_compact == (
        "latest_wiring_sequenceisnullorlatest_wiring_sequence>=1and"
        "latest_wiring_sequence<=9007199254740991"
    ):
        return "latest_wiring_sequence:null_or_ijson_bounds"
    if head_wiring_compact == (
        "latest_wiring_sequenceisnullorlatest_wiring_sequence<=last_sequence"
    ):
        return "latest_wiring_sequence:null_or_not_after_last"
    if head_wiring_compact == (
        "latest_wiring_report_idisnullandlatest_wiring_kindisnulland"
        "latest_wiring_sequenceisnullandlatest_wiring_report_hashisnulland"
        "latest_wiring_projection_commitmentisnullorlatest_wiring_report_idisnotnulland"
        "latest_wiring_kind='wiring'andlatest_wiring_sequenceisnotnulland"
        "latest_wiring_report_hashisnotnullandlatest_wiring_projection_commitmentisnotnull"
    ):
        return "runtime_report_head:wiring_tuple"

    if compact == "assurance_class='native'":
        return "assurance_class:native"
    if compact == "source_system='gove-zone'":
        return "source_system:gove-zone"
    if compact in {
        "statusin('in_progress','succeeded','failed')",
        "status=any(array['in_progress','succeeded','failed'])",
    }:
        return "status:in_progress,succeeded,failed"
    if compact in {
        "statusin('active','retired','revoked')",
        "status=any(array['active','retired','revoked'])",
    }:
        return "status:active,retired,revoked"
    if compact in {
        "statusin('active')",
        "statusin'active'",
        "status=any(array['active'])",
        "status=any((array['active']))",
    }:
        return "status:active"
    if compact in {
        "statusin('pending')",
        "statusin'pending'",
        "status=any(array['pending'])",
    }:
        return "status:pending"
    if compact in {
        "statusin('pending','delivered','failed')",
        "status=any(array['pending','delivered','failed'])",
        "status=any((array['pending','delivered','failed']))",
    }:
        return "status:pending,delivered,failed"
    if compact in {
        "activated_epoch>0",
    }:
        return "activated_epoch:positive"
    if compact in {
        "trust_epoch>0",
    }:
        return "trust_epoch:positive"
    if compact in {
        "generation>=0",
    }:
        return "generation:nonnegative"
    if compact in {
        "signature_algorithm='ed25519'",
    }:
        return "signature_algorithm:ed25519"
    if compact in {
        "purpose='acgs.policy-envelope/v1'",
    }:
        return "purpose:policy-envelope-v1"
    if compact in {
        "role='owner'",
        "rolein('owner')",
        "rolein'owner'",
        "role=any(array['owner'])",
    }:
        return "role:owner"
    if compact in {
        "policy_outcomein('allow','deny','escalate')",
        "policy_outcome=any(array['allow','deny','escalate'])",
    }:
        return "policy_outcome:allow,deny,escalate"
    if compact in {
        "kindin('status','wiring')",
        "kind=any(array['status','wiring'])",
    }:
        return "kind:status,wiring"
    if compact in {
        "decisionin('deny','escalate')",
        "decision=any(array['deny','escalate'])",
    }:
        return "decision:deny,escalate"
    if compact in {
        "decisionin('approve','reject')",
        "decision=any(array['approve','reject'])",
        "decision=any((array['approve','reject']))",
    }:
        return "decision:approve,reject"
    if compact in {
        "outcomein('approved','rejected','expired','canceled')",
        "outcome=any(array['approved','rejected','expired','canceled'])",
        "outcome=any((array['approved','rejected','expired','canceled']))",
    }:
        return "outcome:approved,rejected,expired,canceled"
    if compact in {
        "quorum_threshold>0",
    }:
        return "quorum_threshold:positive"
    if compact in {
        "route='post/v1/tenant-bootstrap'",
    }:
        return "route:tenant-bootstrap"
    if compact in {
        "method='post'",
    }:
        return "method:post"
    if compact in {
        ("stagein('transport','authn','authz','policy','issuance','executor','tx')"),
        ("stage=any(array['transport','authn','authz','policy','issuance','executor','tx'])"),
    }:
        return "stage:transport,authn,authz,policy,issuance,executor,tx"
    if compact in {
        "http_statusin(400,401,403,409,413,503)",
        "http_status=any(array[400,401,403,409,413,503])",
    }:
        return "http_status:400,401,403,409,413,503"
    if compact in {
        ("project_idisnullandenvironment_idisnullorproject_idisnotnullandenvironment_idisnotnull"),
        (
            "(project_idisnullandenvironment_idisnull)or"
            "(project_idisnotnullandenvironment_idisnotnull)"
        ),
        (
            "((project_idisnull)and(environment_idisnull))or"
            "((project_idisnotnull)and(environment_idisnotnull))"
        ),
    }:
        return "agent-scope:both-null-or-set"
    if compact in {
        (
            "status='retired'andretired_epochisnotnull"
            "andretired_epoch>activated_epochor"
            "statusin('active','revoked')andretired_epochisnull"
        ),
        (
            "(status='retired'andretired_epochisnotnull"
            "andretired_epoch>activated_epoch)or"
            "(statusin('active','revoked')andretired_epochisnull)"
        ),
        (
            "status='retired'andretired_epochisnotnull"
            "andretired_epoch>activated_epochor"
            "(status=any(array['active','revoked']))andretired_epochisnull"
        ),
    }:
        return "retired_epoch:retired-only-and-terminal-null"
    return compact


_SqlToken = tuple[str, str]


def _singleton_status_signature_from_sql(value: object) -> str | None:
    tokens = _tokenize_constraint_sql(str(value or ""))
    if not tokens:
        return None
    tokens = _strip_outer_token_parentheses(tokens)
    singleton = _SingletonStatusParser(tokens).parse()
    if singleton is None:
        return None
    return "status:" + json.dumps((singleton,), ensure_ascii=True, separators=(",", ":"))


def _status_set_signature_from_sql(value: object) -> str | None:
    tokens = _tokenize_constraint_sql(str(value or ""))
    if not tokens:
        return None
    tokens = _strip_outer_token_parentheses(tokens)
    values = _StatusSetParser(tokens).parse()
    if values is None or len(values) != len(set(values)) or any(not item for item in values):
        return None
    return "status:" + json.dumps(values, ensure_ascii=True, separators=(",", ":"))


def _tokenize_constraint_sql(value: str) -> list[_SqlToken] | None:
    tokens: list[_SqlToken] = []
    index = 0
    while index < len(value):
        character = value[index]
        if character.isspace():
            index += 1
            continue
        if character == "'":
            index += 1
            literal: list[str] = []
            while index < len(value):
                if value[index] == "'":
                    if index + 1 < len(value) and value[index + 1] == "'":
                        literal.append("'")
                        index += 2
                        continue
                    index += 1
                    break
                literal.append(value[index])
                index += 1
            else:
                return None
            tokens.append(("string", "".join(literal)))
            continue
        if character == '"':
            index += 1
            identifier: list[str] = []
            while index < len(value):
                if value[index] == '"':
                    if index + 1 < len(value) and value[index + 1] == '"':
                        identifier.append('"')
                        index += 2
                        continue
                    index += 1
                    break
                identifier.append(value[index])
                index += 1
            else:
                return None
            tokens.append(("identifier", "".join(identifier)))
            continue
        if value.startswith("::", index):
            tokens.append(("symbol", "::"))
            index += 2
            continue
        if character in "(),=[]":
            tokens.append(("symbol", character))
            index += 1
            continue
        if character.isalpha() or character == "_":
            start = index
            index += 1
            while index < len(value) and (value[index].isalnum() or value[index] == "_"):
                index += 1
            tokens.append(("word", value[start:index]))
            continue
        return None
    return tokens


def _strip_outer_token_parentheses(tokens: list[_SqlToken]) -> list[_SqlToken]:
    result = tokens
    while (
        len(result) >= 2
        and result[0] == ("symbol", "(")
        and result[-1] == ("symbol", ")")
        and _outer_tokens_enclose_expression(result)
    ):
        result = result[1:-1]
    return result


def _outer_tokens_enclose_expression(tokens: list[_SqlToken]) -> bool:
    depth = 0
    for index, token in enumerate(tokens):
        if token == ("symbol", "("):
            depth += 1
        elif token == ("symbol", ")"):
            depth -= 1
            if depth == 0 and index != len(tokens) - 1:
                return False
        if depth < 0:
            return False
    return depth == 0


class _StatusSetParser:
    def __init__(self, tokens: list[_SqlToken]) -> None:
        self._tokens = tokens
        self._pos = 0

    def parse(self) -> tuple[str, ...] | None:
        values = self._parse_expression()
        if values is None or self._pos != len(self._tokens):
            return None
        return tuple(values)

    def _parse_expression(self) -> list[str] | None:
        if not self._parse_status_expression():
            return None
        if self._consume_word("in"):
            if not self._consume_symbol("("):
                return None
            values = self._parse_literal_list(end_symbol=")")
            if values is None or not self._consume_symbol(")"):
                return None
            return values
        if not self._consume_symbol("=") or not self._consume_word("any"):
            return None
        return self._parse_any_array()

    def _parse_status_expression(self) -> bool:
        if self._consume_symbol("("):
            if not self._parse_status_expression() or not self._consume_symbol(")"):
                return False
        elif not self._consume_status_identifier():
            return False
        return self._consume_scalar_casts()

    def _consume_status_identifier(self) -> bool:
        token = self._peek()
        if token is None:
            return False
        kind, text = token
        if kind == "word" and text.lower() == "status":
            self._pos += 1
            return True
        if kind == "identifier" and text == "status":
            self._pos += 1
            return True
        return False

    def _parse_any_array(self) -> list[str] | None:
        wrappers = 0
        while self._consume_symbol("("):
            wrappers += 1
        if not self._consume_word("array") or not self._consume_symbol("["):
            return None
        values = self._parse_literal_list(end_symbol="]")
        if values is None or not self._consume_symbol("]"):
            return None
        if not self._consume_any_rhs_casts():
            return None
        while wrappers:
            if not self._consume_symbol(")"):
                return None
            if not self._consume_any_rhs_casts():
                return None
            wrappers -= 1
        return values

    def _parse_literal_list(self, *, end_symbol: str) -> list[str] | None:
        values: list[str] = []
        while True:
            value = self._parse_literal_expression()
            if value is None:
                return None
            values.append(value)
            if self._peek_is_symbol(end_symbol):
                return values
            if not self._consume_symbol(","):
                return None

    def _parse_literal_expression(self) -> str | None:
        if self._consume_symbol("("):
            value = self._parse_literal_expression()
            if value is None or not self._consume_symbol(")"):
                return None
            if not self._consume_scalar_casts():
                return None
            return value
        token = self._peek()
        if token is None or token[0] != "string":
            return None
        self._pos += 1
        if not self._consume_scalar_casts():
            return None
        return token[1]

    def _consume_scalar_casts(self) -> bool:
        while self._consume_symbol("::"):
            if not self._consume_type_name(allow_array=False):
                return False
        return True

    def _consume_any_rhs_casts(self) -> bool:
        if not self._consume_symbol("::"):
            return True
        if not self._consume_array_type_name():
            return False
        return not self._peek_is_symbol("::")

    def _consume_type_name(self, *, allow_array: bool) -> bool:
        if self._consume_word("text") or self._consume_word("varchar"):
            return self._consume_optional_array_suffix(allow_array=allow_array)
        if self._consume_word("character") and self._consume_word("varying"):
            return self._consume_optional_array_suffix(allow_array=allow_array)
        return False

    def _consume_optional_array_suffix(self, *, allow_array: bool) -> bool:
        if not self._consume_symbol("["):
            return True
        if not allow_array or not self._consume_symbol("]"):
            return False
        return True

    def _consume_array_type_name(self) -> bool:
        if self._consume_word("text") or self._consume_word("varchar"):
            return self._consume_required_array_suffix()
        if self._consume_word("character") and self._consume_word("varying"):
            return self._consume_required_array_suffix()
        return False

    def _consume_required_array_suffix(self) -> bool:
        return self._consume_symbol("[") and self._consume_symbol("]")

    def _consume_word(self, value: str) -> bool:
        token = self._peek()
        if token is not None and token[0] == "word" and token[1].lower() == value:
            self._pos += 1
            return True
        return False

    def _consume_symbol(self, value: str) -> bool:
        if self._peek_is_symbol(value):
            self._pos += 1
            return True
        return False

    def _peek_is_symbol(self, value: str) -> bool:
        token = self._peek()
        return token is not None and token == ("symbol", value)

    def _peek(self) -> _SqlToken | None:
        if self._pos >= len(self._tokens):
            return None
        return self._tokens[self._pos]


class _SingletonStatusParser:
    def __init__(self, tokens: list[_SqlToken]) -> None:
        self._tokens = tokens
        self._pos = 0

    def parse(self) -> str | None:
        if self._parse_status_expression() is None:
            return None
        if not self._consume_symbol("="):
            return None
        value = self._parse_literal_expression()
        if value is None or self._pos != len(self._tokens):
            return None
        return value[0]

    def _parse_status_expression(self) -> int | None:
        cast_count = 0
        if self._consume_symbol("("):
            nested_cast_count = self._parse_status_expression()
            if nested_cast_count is None or not self._consume_symbol(")"):
                return None
            cast_count += nested_cast_count
        elif not self._consume_status_identifier():
            return None
        optional_cast_count = self._consume_optional_scalar_cast()
        if optional_cast_count is None:
            return None
        cast_count += optional_cast_count
        if cast_count > 1:
            return None
        return cast_count

    def _parse_literal_expression(self) -> tuple[str, int] | None:
        cast_count = 0
        if self._consume_symbol("("):
            nested = self._parse_literal_expression()
            if nested is None or not self._consume_symbol(")"):
                return None
            value, nested_cast_count = nested
            cast_count += nested_cast_count
        else:
            token = self._peek()
            if token is None or token[0] != "string":
                return None
            value = token[1]
            self._pos += 1
        optional_cast_count = self._consume_optional_scalar_cast()
        if optional_cast_count is None:
            return None
        cast_count += optional_cast_count
        if cast_count > 1:
            return None
        return value, cast_count

    def _consume_status_identifier(self) -> bool:
        token = self._peek()
        if token is None:
            return False
        kind, text = token
        if kind == "word" and text.lower() == "status":
            self._pos += 1
            return True
        if kind == "identifier" and text == "status":
            self._pos += 1
            return True
        return False

    def _consume_optional_scalar_cast(self) -> int | None:
        if not self._consume_symbol("::"):
            return 0
        if not self._consume_type_name():
            return None
        if self._peek_is_symbol("::"):
            return None
        return 1

    def _consume_type_name(self) -> bool:
        if self._consume_word("text") or self._consume_word("varchar"):
            return not self._consume_symbol("[")
        if self._consume_word("character") and self._consume_word("varying"):
            return not self._consume_symbol("[")
        return False

    def _consume_word(self, value: str) -> bool:
        token = self._peek()
        if token is not None and token[0] == "word" and token[1].lower() == value:
            self._pos += 1
            return True
        return False

    def _consume_symbol(self, value: str) -> bool:
        if self._peek_is_symbol(value):
            self._pos += 1
            return True
        return False

    def _peek_is_symbol(self, value: str) -> bool:
        token = self._peek()
        return token is not None and token == ("symbol", value)

    def _peek(self) -> _SqlToken | None:
        if self._pos >= len(self._tokens):
            return None
        return self._tokens[self._pos]


def _index_where_signature(index: Mapping[str, object], dialect_name: str) -> str | None:
    dialect_options = index.get("dialect_options") or {}
    if not isinstance(dialect_options, Mapping):
        return None
    for key in (f"{dialect_name}_where", "postgresql_where", "sqlite_where"):
        predicate = dialect_options.get(key)
        if predicate is not None:
            return _where_predicate_signature(predicate)
    return None


def _where_predicate_signature(value: object) -> str:
    raw = str(value if value is not None else "").lower()
    compact = _normalized_constraint_sql(
        re.sub(
            r"::(?:text|character\s+varying)(?:\[\])?",
            "",
            raw,
            flags=re.IGNORECASE,
        )
    ).lower()
    compact = compact.replace("(status)", "status")
    compact = _strip_outer_parentheses(compact)
    if compact == "status='active'":
        return "status:active"
    if compact in {
        "project_idisnullandenvironment_idisnull",
        "(project_idisnull)and(environment_idisnull)",
    }:
        return "agent-scope:legacy-unscoped"
    if compact in {
        "project_idisnotnullandenvironment_idisnotnull",
        "(project_idisnotnull)and(environment_idisnotnull)",
    }:
        return "agent-scope:scoped"
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
    if expected.type_name == "big_integer":
        return (
            dialect_name == "sqlite"
            and isinstance(actual_type, sa.Integer)
            and not isinstance(actual_type, sa.Boolean)
        ) or (dialect_name == "postgresql" and isinstance(actual_type, sa.BigInteger))
    if expected.type_name == "binary":
        return isinstance(actual_type, sa.LargeBinary)
    if expected.type_name == "boolean":
        return isinstance(actual_type, sa.Boolean)
    if expected.type_name == "json":
        if dialect_name == "postgresql":
            return isinstance(actual_type, postgresql.JSONB)
        return dialect_name == "sqlite" and isinstance(actual_type, sa.JSON)
    msg = f"unknown frozen schema type {expected.type_name!r}"
    raise AssertionError(msg)
