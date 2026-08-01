"""Pydantic request/response schemas for the REST API."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from acgs_control_plane.rbac import Role

# ---------------------------------------------------------------------------
# Organizations / users
# ---------------------------------------------------------------------------


class OrgCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    admin_name: str = Field(min_length=1, max_length=200)
    admin_email: EmailStr


class OrgCreateResponse(BaseModel):
    org_id: str
    name: str
    admin_user_id: str
    # Shown exactly once; only its hash is stored.
    admin_api_key: str


class TenantBootstrapRequest(BaseModel):
    """Normalized display metadata accepted by the tenant bootstrap API."""

    model_config = ConfigDict(extra="forbid")

    display_name: str = Field(min_length=1, max_length=200)
    admin_name: str = Field(min_length=1, max_length=200)
    admin_email: EmailStr


class TenantBootstrapResponse(BaseModel):
    org_id: str
    project_id: str
    environment_id: str
    owner_user_id: str
    owner_membership_id: str
    receipt_id: str
    receipt_hash: str
    event_hash: str
    idempotency_key: str
    assurance_class: str


class OrgResponse(BaseModel):
    org_id: str
    name: str
    created_at: datetime
    audit_anchor_count: int
    audit_anchor_hash: str


class UserCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    email: EmailStr
    role: Role


class UserCreateResponse(BaseModel):
    user_id: str
    org_id: str
    name: str
    email: str
    role: Role
    api_key: str
    receipt_id: str


class UserResponse(BaseModel):
    user_id: str
    name: str
    email: str
    role: Role
    active: bool
    created_at: datetime


class V1UserListResponse(BaseModel):
    items: list[UserResponse]
    limit: int
    next_cursor: str | None


# ---------------------------------------------------------------------------
# Agent registry
# ---------------------------------------------------------------------------


AgentToolName = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9._:/-]+$"),
]


class AgentRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    trust_tier: str = Field(
        default="untrusted",
        min_length=1,
        max_length=32,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )
    allowed_tools: list[AgentToolName] = Field(default_factory=list, max_length=64)


class AgentResponse(BaseModel):
    agent_id: str
    org_id: str
    name: str
    description: str
    trust_tier: str
    allowed_tools: list[str]
    status: str
    created_at: datetime
    receipt_id: str | None = None


class V1AgentListResponse(BaseModel):
    items: list[AgentResponse]
    limit: int
    next_cursor: str | None


class AgentStatusRequest(BaseModel):
    status: str = Field(pattern="^(active|suspended)$")


# ---------------------------------------------------------------------------
# Policy registry
# ---------------------------------------------------------------------------


class PolicyPublishRequest(BaseModel):
    policy_id: str = Field(min_length=1, max_length=200)
    rules: list[dict[str, Any]] = Field(min_length=1)


class PolicyResponse(BaseModel):
    bundle_id: str
    org_id: str
    policy_id: str
    version: str
    status: str
    rules: list[dict[str, Any]]
    created_at: datetime
    activated_at: datetime | None
    receipt_id: str | None = None


class V1PolicyListResponse(BaseModel):
    items: list[PolicyResponse]
    limit: int
    next_cursor: str | None


class SimulateRequest(BaseModel):
    tool: str = Field(min_length=1)
    args: dict[str, Any] = Field(default_factory=dict)
    actor: str = "simulation"
    goal: str = ""
    path: list[str] = Field(default_factory=list)
    state: dict[str, Any] = Field(default_factory=dict)


class SimulateResponse(BaseModel):
    decision: str
    reason: str
    matched_rules: list[str]
    policy_version: str


# ---------------------------------------------------------------------------
# Receipts / dashboard / export
# ---------------------------------------------------------------------------


class ReceiptSummary(BaseModel):
    receipt_id: str
    tool: str
    decision: str
    actor: str
    goal: str
    policy_version: str
    audit_hash: str
    created_at: datetime
    assurance_class: str | None = None
    source_system: str | None = None


class ReceiptDetail(ReceiptSummary):
    argument_hash: str
    result_hash: str | None
    error_class: str | None
    payload: dict[str, Any]
    execution_boundary: str | None = None
    policy_hash: str | None = None
    receipt_hash: str | None = None
    evidence_profile: str | None = None


class ReceiptListResponse(BaseModel):
    items: list[ReceiptSummary]
    total: int
    limit: int
    offset: int
    next_cursor: str | None = None


class ReceiptVerifyResponse(BaseModel):
    receipt_id: str
    receipt_in_chain: bool
    chain_valid: bool
    chain_checked: int
    anchor_matched: bool
    failures: list[dict[str, Any]]
    assurance_class: str | None = None
    source_system: str | None = None


class DashboardResponse(BaseModel):
    org_id: str
    total_receipts: int
    decisions: dict[str, int]
    top_tools: list[dict[str, Any]]
    top_actors: list[dict[str, Any]]
    active_policy_version: str | None
    agents_total: int
    agents_suspended: int
    chain_valid: bool
    chain_checked: int


class ExportCreateRequest(BaseModel):
    note: str = ""


class ExportSummary(BaseModel):
    export_id: str
    created_by: str
    receipt_count: int
    bundle_hash: str
    created_at: datetime
    receipt_id: str | None = None


class V1ExportListResponse(BaseModel):
    items: list[ExportSummary]
    limit: int
    next_cursor: str | None


class ExportDetail(ExportSummary):
    bundle: dict[str, Any]


class BlockedResponse(BaseModel):
    """Body returned on policy DENY (403) and ESCALATE (202)."""

    status: str
    reason: str
    receipt_id: str
    decision: str


class V1MetadataResponse(BaseModel):
    """Minimal version metadata for the additive v1 alias surface."""

    api_version: str
    status: str
    aliased_from: str
