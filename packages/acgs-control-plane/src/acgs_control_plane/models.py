"""ORM models for the control plane.

Every tenant-scoped table carries ``org_id``; all queries filter by the
authenticated principal's organization. The ``Organization`` row also stores
the org's audit-chain anchor (event count + last event hash) so chain
truncation/rollback in the file-backed audit store is detectable from the
database — the two stores cross-check each other.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    and_,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, foreign, mapped_column, relationship

from acgs_control_plane.db import ALEMBIC_MANAGED_TABLE_INFO_KEY, Base

JSONVariant = JSON().with_variant(JSONB(), "postgresql")


def new_id() -> str:
    return uuid.uuid4().hex


def utcnow() -> datetime:
    return datetime.now(UTC)


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Audit-chain anchor: updated inside the same transaction as each
    # persisted receipt. verify_chain(expected_count=, expected_last_hash=)
    # uses these to detect file-store truncation.
    audit_anchor_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    audit_anchor_hash: Mapped[str] = mapped_column(String(128), default="", nullable=False)

    projects: Mapped[list[Project]] = relationship(back_populates="organization")


class Project(Base):
    """A named scope beneath an organization.

    The composite ``(org_id, id)`` key exists so an environment can enforce
    its parent project's organization at the database boundary, not merely in
    an API route or ORM query.
    """

    __tablename__ = "projects"
    __table_args__ = (
        UniqueConstraint("org_id", "slug", name="uq_projects_org_slug"),
        UniqueConstraint("org_id", "id", name="uq_projects_org_id_id"),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"))
    slug: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    organization: Mapped[Organization] = relationship(back_populates="projects")
    environments: Mapped[list[Environment]] = relationship(
        back_populates="project",
        primaryjoin=lambda: and_(
            Project.org_id == foreign(Environment.org_id),
            Project.id == foreign(Environment.project_id),
        ),
        foreign_keys=lambda: [Environment.org_id, Environment.project_id],
    )


class Environment(Base):
    """A deployable scope whose project must belong to the same organization."""

    __tablename__ = "environments"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "project_id"],
            ["projects.org_id", "projects.id"],
            name="fk_environments_org_project",
        ),
        UniqueConstraint("org_id", "project_id", "slug", name="uq_environments_org_project_slug"),
        UniqueConstraint("org_id", "project_id", "id", name="uq_environments_org_project_id"),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"))
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    slug: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    project: Mapped[Project] = relationship(
        back_populates="environments",
        primaryjoin=lambda: and_(
            foreign(Environment.org_id) == Project.org_id,
            foreign(Environment.project_id) == Project.id,
        ),
        foreign_keys=lambda: [Environment.org_id, Environment.project_id],
    )


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_users_org_id_id"),
        UniqueConstraint("org_id", "email", name="uq_users_org_email"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    api_key_hash: Mapped[str | None] = mapped_column(String(64), unique=True, index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OrganizationMembership(Base):
    """Human membership created by the canonical tenant bootstrap path."""

    __tablename__ = "organization_memberships"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "user_id"],
            ["users.org_id", "users.id"],
            name="fk_org_memberships_org_user",
        ),
        UniqueConstraint("org_id", "user_id", name="uq_org_memberships_org_user"),
        CheckConstraint("role IN ('owner')", name="ck_org_memberships_role"),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PlatformBootstrapInvitation(Base):
    """One-use platform invitation for pre-tenant bootstrap.

    Stores only a token hash and server-owned prospective scope ids. The raw
    invite secret is never persisted.
    """

    __tablename__ = "platform_bootstrap_invitations"
    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_platform_bootstrap_invitation_token_hash"),
        UniqueConstraint(
            "prospective_org_id",
            "prospective_project_id",
            "prospective_environment_id",
            name="uq_platform_bootstrap_invitation_scope",
        ),
        UniqueConstraint(
            "id",
            "prospective_org_id",
            "prospective_project_id",
            "prospective_environment_id",
            name="uq_platform_bootstrap_invitation_id_scope",
        ),
        CheckConstraint(
            "policy_outcome IN ('allow', 'deny', 'escalate')",
            name="ck_platform_bootstrap_invitation_policy_outcome",
        ),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    invitee_actor: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    invitee_role: Mapped[str] = mapped_column(String(64), nullable=False)
    prospective_org_id: Mapped[str] = mapped_column(String(64), nullable=False)
    prospective_project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    prospective_environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    prospective_membership_id: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="allow")
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_org_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class TenantBootstrapIdempotency(Base):
    """Stable successful response for one tenant.bootstrap idempotency key."""

    __tablename__ = "tenant_bootstrap_idempotency"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_tenant_bootstrap_idempotency_environment",
        ),
        UniqueConstraint("idempotency_key", name="uq_tenant_bootstrap_idempotency_key"),
        UniqueConstraint("org_id", name="uq_tenant_bootstrap_idempotency_org"),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    response: Mapped[dict[str, Any]] = mapped_column(JSONVariant, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TenantBootstrapPolicyArtifact(Base):
    """Signed non-executable DENY/ESCALATE outcome for tenant.bootstrap."""

    __tablename__ = "tenant_bootstrap_policy_artifacts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["invitation_id", "org_id", "project_id", "environment_id"],
            [
                "platform_bootstrap_invitations.id",
                "platform_bootstrap_invitations.prospective_org_id",
                "platform_bootstrap_invitations.prospective_project_id",
                "platform_bootstrap_invitations.prospective_environment_id",
            ],
            name="fk_tenant_bootstrap_policy_invitation_scope",
        ),
        UniqueConstraint("invitation_id", "id", name="uq_tenant_bootstrap_policy_invitation_id"),
        UniqueConstraint(
            "invitation_id",
            "id",
            "org_id",
            "project_id",
            "environment_id",
            name="uq_tenant_bootstrap_policy_invitation_id_scope",
        ),
        UniqueConstraint("invitation_id", name="uq_tenant_bootstrap_policy_invitation"),
        UniqueConstraint("receipt_hash", name="uq_tenant_bootstrap_policy_receipt_hash"),
        UniqueConstraint("audit_event_hash", name="uq_tenant_bootstrap_policy_audit_hash"),
        CheckConstraint(
            "decision IN ('deny', 'escalate')",
            name="ck_tenant_bootstrap_policy_decision",
        ),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    invitation_id: Mapped[str] = mapped_column(
        ForeignKey("platform_bootstrap_invitations.id"), nullable=False, index=True
    )
    org_id: Mapped[str] = mapped_column(String(64), nullable=False)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    receipt_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    audit_event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    sealed_receipt: Mapped[dict[str, Any]] = mapped_column(JSONVariant, nullable=False)
    event: Mapped[dict[str, Any]] = mapped_column(JSONVariant, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PendingApproval(Base):
    """Durable separated-approval request for non-executable ESCALATE decisions."""

    __tablename__ = "pending_approvals"
    __table_args__ = (
        ForeignKeyConstraint(
            ["invitation_id", "policy_artifact_id", "org_id", "project_id", "environment_id"],
            [
                "tenant_bootstrap_policy_artifacts.invitation_id",
                "tenant_bootstrap_policy_artifacts.id",
                "tenant_bootstrap_policy_artifacts.org_id",
                "tenant_bootstrap_policy_artifacts.project_id",
                "tenant_bootstrap_policy_artifacts.environment_id",
            ],
            name="fk_pending_approvals_policy_artifact_scope",
        ),
        UniqueConstraint("receipt_hash", name="uq_pending_approvals_receipt_hash"),
        UniqueConstraint("audit_event_hash", name="uq_pending_approvals_audit_hash"),
        CheckConstraint("status IN ('pending')", name="ck_pending_approvals_status"),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    action: Mapped[str] = mapped_column(String(200), nullable=False)
    invitation_id: Mapped[str] = mapped_column(
        ForeignKey("platform_bootstrap_invitations.id"), nullable=False, index=True
    )
    policy_artifact_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    receipt_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    audit_event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    lineage: Mapped[dict[str, Any]] = mapped_column(JSONVariant, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TenantBootstrapPendingOutbox(Base):
    """Pre-tenant pending notification for non-executable tenant.bootstrap outcomes."""

    __tablename__ = "tenant_bootstrap_pending_outbox"
    __table_args__ = (
        ForeignKeyConstraint(
            ["invitation_id", "policy_artifact_id", "org_id", "project_id", "environment_id"],
            [
                "tenant_bootstrap_policy_artifacts.invitation_id",
                "tenant_bootstrap_policy_artifacts.id",
                "tenant_bootstrap_policy_artifacts.org_id",
                "tenant_bootstrap_policy_artifacts.project_id",
                "tenant_bootstrap_policy_artifacts.environment_id",
            ],
            name="fk_tenant_bootstrap_pending_policy_artifact_scope",
        ),
        UniqueConstraint("policy_artifact_id", name="uq_tenant_bootstrap_pending_policy_artifact"),
        UniqueConstraint("delivery_key", name="uq_tenant_bootstrap_pending_delivery_key"),
        UniqueConstraint("payload_digest", name="uq_tenant_bootstrap_pending_payload_digest"),
        CheckConstraint(
            "status IN ('pending', 'delivered', 'failed')",
            name="ck_tenant_bootstrap_pending_status",
        ),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    invitation_id: Mapped[str] = mapped_column(
        ForeignKey("platform_bootstrap_invitations.id"), nullable=False, index=True
    )
    policy_artifact_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    delivery_key: Mapped[str] = mapped_column(String(200), nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONVariant, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class TenantBootstrapRefusalEvent(Base):
    """Redacted primary refusal audit for tenant-bootstrap transport/control failures."""

    __tablename__ = "tenant_bootstrap_refusal_events"
    __table_args__ = (
        UniqueConstraint("request_id", name="uq_tenant_bootstrap_refusal_request_id"),
        CheckConstraint("route = 'POST /v1/tenant-bootstrap'", name="ck_tbr_route"),
        CheckConstraint("method = 'POST'", name="ck_tbr_method"),
        CheckConstraint(
            "stage IN ('transport', 'authn', 'authz', 'policy', 'issuance', 'executor', 'tx')",
            name="ck_tbr_stage",
        ),
        CheckConstraint("http_status IN (400, 401, 403, 409, 413, 503)", name="ck_tbr_status"),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    route: Mapped[str] = mapped_column(
        String(64), nullable=False, default="POST /v1/tenant-bootstrap"
    )
    method: Mapped[str] = mapped_column(String(8), nullable=False, default="POST")
    stage: Mapped[str] = mapped_column(String(32), nullable=False)
    code: Mapped[str] = mapped_column(String(64), nullable=False)
    http_status: Mapped[int] = mapped_column(Integer, nullable=False)
    invitation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    invitation_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    idempotency_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AgentRecord(Base):
    __tablename__ = "agents"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_agents_scope_environment",
            info={ALEMBIC_MANAGED_TABLE_INFO_KEY: True},
        ),
        UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "id",
            name="uq_agents_scope_id",
            info={ALEMBIC_MANAGED_TABLE_INFO_KEY: True},
        ),
        CheckConstraint(
            "(project_id IS NULL AND environment_id IS NULL) OR "
            "(project_id IS NOT NULL AND environment_id IS NOT NULL)",
            name="ck_agents_scope_both_null_or_set",
            info={ALEMBIC_MANAGED_TABLE_INFO_KEY: True},
        ),
        Index(
            "uq_agents_legacy_org_name",
            "org_id",
            "name",
            unique=True,
            sqlite_where=sa.text("project_id IS NULL AND environment_id IS NULL"),
            postgresql_where=sa.text("project_id IS NULL AND environment_id IS NULL"),
            info={ALEMBIC_MANAGED_TABLE_INFO_KEY: True},
        ),
        Index(
            "uq_agents_scope_name",
            "org_id",
            "project_id",
            "environment_id",
            "name",
            unique=True,
            sqlite_where=sa.text("project_id IS NOT NULL AND environment_id IS NOT NULL"),
            postgresql_where=sa.text("project_id IS NOT NULL AND environment_id IS NOT NULL"),
            info={ALEMBIC_MANAGED_TABLE_INFO_KEY: True},
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    project_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True, info={ALEMBIC_MANAGED_TABLE_INFO_KEY: True}
    )
    environment_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True, info={ALEMBIC_MANAGED_TABLE_INFO_KEY: True}
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    trust_tier: Mapped[str] = mapped_column(String(32), default="untrusted", nullable=False)
    allowed_tools: Mapped[list[str]] = mapped_column(JSONVariant, default=list)
    status: Mapped[str] = mapped_column(String(16), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AgentRegistrationIdempotency(Base):
    """Terminal response for one scoped agent-registration idempotency key."""

    __tablename__ = "agent_registration_idempotency"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_agent_registration_idempotency_environment",
            deferrable=True,
            initially="DEFERRED",
            info={ALEMBIC_MANAGED_TABLE_INFO_KEY: True},
        ),
        ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "agent_id"],
            ["agents.org_id", "agents.project_id", "agents.environment_id", "agents.id"],
            name="fk_agent_registration_idempotency_agent_scope",
            deferrable=True,
            initially="DEFERRED",
            info={ALEMBIC_MANAGED_TABLE_INFO_KEY: True},
        ),
        ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "receipt_id"],
            [
                "managed_decision_receipts.org_id",
                "managed_decision_receipts.project_id",
                "managed_decision_receipts.environment_id",
                "managed_decision_receipts.receipt_id",
            ],
            name="fk_agent_registration_idempotency_receipt_scope",
            deferrable=True,
            initially="DEFERRED",
            info={ALEMBIC_MANAGED_TABLE_INFO_KEY: True},
        ),
        UniqueConstraint(
            "idempotency_key_hash",
            name="uq_agent_registration_idempotency_key_hash",
            info={ALEMBIC_MANAGED_TABLE_INFO_KEY: True},
        ),
        UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "agent_id",
            name="uq_agent_registration_idempotency_agent",
            info={ALEMBIC_MANAGED_TABLE_INFO_KEY: True},
        ),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    idempotency_key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", deferrable=True, initially="DEFERRED"),
        index=True,
    )
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    receipt_id: Mapped[str] = mapped_column(String(200), nullable=False)
    response: Mapped[dict[str, Any]] = mapped_column(JSONVariant, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PolicyBundle(Base):
    __tablename__ = "policy_bundles"
    __table_args__ = (
        Index(
            "uq_policy_bundles_one_active_per_org",
            "org_id",
            unique=True,
            sqlite_where=sa.text("status = 'active'"),
            postgresql_where=sa.text("status = 'active'"),
            info={ALEMBIC_MANAGED_TABLE_INFO_KEY: True},
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    policy_id: Mapped[str] = mapped_column(String(200), nullable=False)
    # Content-addressed version computed by gove_zone.RuleSetPolicy — never
    # hand-assigned, so two bundles with the same rules share a version.
    version: Mapped[str] = mapped_column(String(200), nullable=False)
    bundle: Mapped[dict[str, Any]] = mapped_column(JSONVariant, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="published", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ReceiptRow(Base):
    __tablename__ = "receipts"

    # receipt_id == the kernel DecisionRecord.event_id.
    # Legacy evidence intentionally remains organization-scoped.  Adding
    # project/environment provenance requires a separately authenticated
    # evidence path; this migration never guesses or backfills it.
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    tool: Mapped[str] = mapped_column(String(200), index=True, nullable=False)
    decision: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    actor: Mapped[str] = mapped_column(String(200), index=True, nullable=False)
    goal: Mapped[str] = mapped_column(Text, default="", nullable=False)
    argument_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    audit_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(200), nullable=False)
    result_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    error_class: Mapped[str | None] = mapped_column(String(200), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONVariant, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class ComplianceExport(Base):
    __tablename__ = "compliance_exports"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    receipt_count: Mapped[int] = mapped_column(Integer, nullable=False)
    bundle_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    bundle: Mapped[dict[str, Any]] = mapped_column(JSONVariant, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ManagedDecisionReceipt(Base):
    """Safe indexed and sealed DecisionReceipt projection for managed SQL mutations."""

    __tablename__ = "managed_decision_receipts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_managed_receipts_scope_environment",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint("org_id", "project_id", "environment_id", "id", name="uq_mdr_scope_id"),
        UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "receipt_id",
            name="uq_mdr_scope_receipt_id",
        ),
        UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "receipt_hash",
            name="uq_mdr_scope_receipt_hash",
        ),
        UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "audit_event_hash",
            name="uq_mdr_scope_audit_event_hash",
        ),
        UniqueConstraint("org_id", "receipt_hash", name="uq_mdr_org_receipt_hash"),
        UniqueConstraint("org_id", "audit_event_hash", name="uq_mdr_org_audit_event_hash"),
        CheckConstraint("assurance_class = 'native'", name="ck_mdr_assurance_native"),
        CheckConstraint("source_system = 'gove-zone'", name="ck_mdr_source_gove_zone"),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", deferrable=True, initially="DEFERRED"),
        index=True,
    )
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    receipt_id: Mapped[str] = mapped_column(String(200), nullable=False)
    receipt_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    audit_event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    proposed_action: Mapped[str] = mapped_column(String(200), nullable=False)
    execution_boundary: Mapped[str] = mapped_column(String(200), nullable=False)
    policy_bundle_id: Mapped[str] = mapped_column(String(200), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(200), nullable=False)
    policy_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    argument_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(200), nullable=False)
    signature_algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    receipt_schema_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    trust_epoch: Mapped[int | None] = mapped_column(Integer, nullable=True)
    assurance_class: Mapped[str] = mapped_column(String(32), nullable=False)
    source_system: Mapped[str] = mapped_column(String(64), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    projection: Mapped[dict[str, Any]] = mapped_column(JSONVariant, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ManagedTrustScope(Base):
    """Tenant/project/environment trust namespace for one verifier purpose."""

    __tablename__ = "managed_trust_scopes"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_managed_trust_scopes_environment",
        ),
        UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "purpose",
            name="uq_managed_trust_scope_full",
        ),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    purpose: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ManagedTrustKey(Base):
    """Public-only receipt verifier material for one scoped trust epoch."""

    __tablename__ = "managed_trust_keys"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_managed_trust_keys_environment",
        ),
        ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "purpose"],
            [
                "managed_trust_scopes.org_id",
                "managed_trust_scopes.project_id",
                "managed_trust_scopes.environment_id",
                "managed_trust_scopes.purpose",
            ],
            name="fk_managed_trust_keys_scope",
        ),
        UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "purpose",
            "key_id",
            "algorithm",
            "activated_epoch",
            name="uq_managed_trust_key_epoch",
        ),
        CheckConstraint(
            "status IN ('active', 'retired', 'revoked')",
            name="ck_managed_trust_key_status",
        ),
        CheckConstraint("activated_epoch > 0", name="ck_managed_trust_key_epoch_positive"),
        CheckConstraint(
            "(status = 'retired' AND retired_epoch IS NOT NULL "
            "AND retired_epoch > activated_epoch) OR "
            "(status IN ('active', 'revoked') AND retired_epoch IS NULL)",
            name="ck_managed_trust_key_retired_epoch",
        ),
        Index(
            "uq_managed_trust_key_active_scope",
            "org_id",
            "project_id",
            "environment_id",
            "purpose",
            unique=True,
            postgresql_where=sa.text("status = 'active'"),
            sqlite_where=sa.text("status = 'active'"),
        ),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    purpose: Mapped[str] = mapped_column(String(64), nullable=False)
    key_id: Mapped[str] = mapped_column(String(200), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    public_key_spki_der: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    activated_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    retired_epoch: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ManagedMutationAttempt(Base):
    """Terminal reservation for one managed mutation receipt attempt."""

    __tablename__ = "managed_mutation_attempts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_managed_attempts_scope_environment",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint("org_id", "receipt_hash", name="uq_mma_org_receipt_hash"),
        UniqueConstraint("org_id", "audit_event_hash", name="uq_mma_org_audit_event_hash"),
        CheckConstraint(
            "status IN ('in_progress', 'succeeded', 'failed')",
            name="ck_mma_terminal_status",
        ),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", deferrable=True, initially="DEFERRED"),
        index=True,
    )
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    receipt_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    audit_event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(200), nullable=False)
    actor_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    argument_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    failure_class_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    failure_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ManagedReceiptConsumption(Base):
    """SQL transaction-bound single-use burn for a managed DecisionReceipt."""

    __tablename__ = "managed_receipt_consumptions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_managed_consumptions_scope_environment",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "managed_receipt_id"],
            [
                "managed_decision_receipts.org_id",
                "managed_decision_receipts.project_id",
                "managed_decision_receipts.environment_id",
                "managed_decision_receipts.id",
            ],
            name="fk_managed_consumptions_scope_receipt",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "managed_receipt_id",
            name="uq_mrc_scope_receipt",
        ),
        UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "receipt_hash",
            name="uq_mrc_scope_receipt_hash",
        ),
        UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "audit_event_hash",
            name="uq_mrc_scope_audit_event_hash",
        ),
        UniqueConstraint("org_id", "receipt_hash", name="uq_mrc_org_receipt_hash"),
        UniqueConstraint("org_id", "audit_event_hash", name="uq_mrc_org_audit_event_hash"),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", deferrable=True, initially="DEFERRED"),
        index=True,
    )
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    managed_receipt_id: Mapped[str] = mapped_column(String(64), nullable=False)
    receipt_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    audit_event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    consumed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ManagedGovernanceEventHead(Base):
    """Per-environment SQL event-chain head for managed mutations."""

    __tablename__ = "managed_governance_event_heads"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_managed_event_heads_scope_environment",
            deferrable=True,
            initially="DEFERRED",
        ),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", deferrable=True, initially="DEFERRED"),
        primary_key=True,
    )
    project_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    environment_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_event_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="0" * 64)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ManagedGovernanceEvent(Base):
    """SQL-only governance event linked to the consumed receipt."""

    __tablename__ = "managed_governance_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_managed_events_scope_environment",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "managed_receipt_id"],
            [
                "managed_decision_receipts.org_id",
                "managed_decision_receipts.project_id",
                "managed_decision_receipts.environment_id",
                "managed_decision_receipts.id",
            ],
            name="fk_managed_events_scope_receipt",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint("org_id", "project_id", "environment_id", "id", name="uq_mge_scope_id"),
        UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "sequence",
            name="uq_mge_scope_sequence",
        ),
        UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "event_hash",
            name="uq_mge_scope_event_hash",
        ),
        UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "managed_receipt_id",
            name="uq_mge_scope_receipt",
        ),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", deferrable=True, initially="DEFERRED"),
        index=True,
    )
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    managed_receipt_id: Mapped[str] = mapped_column(String(64), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    proposed_action: Mapped[str] = mapped_column(String(200), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(200), nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONVariant, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ManagedOutboxMessage(Base):
    """Durable SQL-only work item; delivery is intentionally out of scope."""

    __tablename__ = "managed_outbox"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_managed_outbox_scope_environment",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "managed_receipt_id"],
            [
                "managed_decision_receipts.org_id",
                "managed_decision_receipts.project_id",
                "managed_decision_receipts.environment_id",
                "managed_decision_receipts.id",
            ],
            name="fk_managed_outbox_scope_receipt",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "managed_event_id"],
            [
                "managed_governance_events.org_id",
                "managed_governance_events.project_id",
                "managed_governance_events.environment_id",
                "managed_governance_events.id",
            ],
            name="fk_managed_outbox_scope_event",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "delivery_key",
            name="uq_managed_outbox_scope_delivery_key",
        ),
        UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "payload_digest",
            name="uq_managed_outbox_scope_payload_digest",
        ),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", deferrable=True, initially="DEFERRED"),
        index=True,
    )
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    managed_receipt_id: Mapped[str] = mapped_column(String(64), nullable=False)
    managed_event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    delivery_key: Mapped[str] = mapped_column(String(200), nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONVariant, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class GovernanceEventHead(Base):
    """Per-tenant database-primary audit chain head.

    This is migration groundwork only. Existing route reads still use the
    legacy JSONL-backed audit path until a later cutover explicitly switches
    authority.
    """

    __tablename__ = "governance_event_heads"
    __table_args__ = ({"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},)

    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), primary_key=True)
    last_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_event_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="0" * 64)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GovernanceEvent(Base):
    """Database-primary governance event plus complete append payload."""

    __tablename__ = "governance_events"
    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_governance_events_org_id_id"),
        UniqueConstraint("org_id", "sequence", name="uq_governance_events_org_sequence"),
        UniqueConstraint("org_id", "event_id", name="uq_governance_events_org_event_id"),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_id: Mapped[str] = mapped_column(String(200), nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    tool: Mapped[str] = mapped_column(String(200), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(200), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONVariant, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditProjectionOutbox(Base):
    """Derived JSONL projection work item for one database governance event."""

    __tablename__ = "audit_projection_outbox"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "governance_event_id"],
            ["governance_events.org_id", "governance_events.id"],
            name="fk_audit_projection_outbox_org_event",
        ),
        UniqueConstraint("org_id", "sequence", name="uq_audit_projection_outbox_org_sequence"),
        {"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    governance_event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONVariant, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class GovernanceEventCutover(Base):
    """Tenant cutover marker; not consulted by current route/read paths yet."""

    __tablename__ = "governance_event_cutover"
    __table_args__ = ({"info": {ALEMBIC_MANAGED_TABLE_INFO_KEY: True}},)

    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), primary_key=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="legacy_jsonl")
    legacy_audit_anchor_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    legacy_audit_anchor_hash: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    cutover_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
