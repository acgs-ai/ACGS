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

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
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
    __table_args__ = (UniqueConstraint("org_id", "email", name="uq_users_org_email"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AgentRecord(Base):
    __tablename__ = "agents"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_agents_org_name"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    trust_tier: Mapped[str] = mapped_column(String(32), default="untrusted", nullable=False)
    allowed_tools: Mapped[list[str]] = mapped_column(JSONVariant, default=list)
    status: Mapped[str] = mapped_column(String(16), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PolicyBundle(Base):
    __tablename__ = "policy_bundles"

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
