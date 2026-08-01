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
    # Returned exactly once on the initial successful bootstrap response. It is
    # omitted on idempotent replay so the raw secret is not persisted.
    owner_api_key: str | None = None
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


class AgentStatusRequest(BaseModel):
    status: str = Field(pattern="^(active|suspended)$")


class ApprovalVoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: str = Field(pattern="^(approve|reject)$")


class ApprovalVoteResponse(BaseModel):
    approval_request_id: str
    decision: str
    outcome: str | None
    vote_hash: str
    receipt_id: str


class RuntimeEnrollmentBootstrapCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ttl_seconds: int = Field(default=600, ge=1, le=900)
    workload_key_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    public_key_thumbprint: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]+$")


class RuntimeEnrollmentBootstrapCreateResponse(BaseModel):
    bootstrap_id: str
    org_id: str
    project_id: str
    environment_id: str
    gate_id: str
    runtime_identity_id: str
    audience: str
    workload_key_id: str
    public_key_thumbprint: str
    bootstrap_token: str = Field(repr=False)
    server_challenge: str = Field(repr=False)
    expires_at: datetime
    receipt_id: str


class RuntimeEnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    audience: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    bootstrap_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    gate_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    idempotency_key_digest: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]+$")
    org_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    project_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    environment: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    runtime_identity_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    public_key: str = Field(min_length=32, max_length=512)
    public_key_thumbprint: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]+$")
    client_nonce: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    timestamp: str = Field(min_length=20, max_length=40)
    server_challenge: str = Field(min_length=16, max_length=256)


class RuntimeIdentityDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    scope: dict[str, str]
    runtime_identity_id: str
    credential_id: str
    credential_generation: int
    public_key: str
    public_key_thumbprint: str
    issuer: str
    audience: str
    issued_at: datetime
    expires_at: datetime
    signature_algorithm: str
    signing_key_id: str
    signature: str


class RuntimeEnrollmentResponse(BaseModel):
    identity_id: str
    org_id: str
    project_id: str
    environment_id: str
    generation: int
    descriptor: RuntimeIdentityDescriptor
    receipt_id: str


class PolicySyncScope(BaseModel):
    """Exact environment and gate scope bound into a policy snapshot."""

    model_config = ConfigDict(extra="forbid")

    org_id: str
    project_id: str
    environment_id: str
    gate_id: str


class PolicySyncSnapshot(BaseModel):
    """Short-lived, signed projection of one active environment policy head."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_: str = Field(alias="schema", serialization_alias="schema")
    purpose: str
    scope: PolicySyncScope
    runtime_identity_id: str
    credential_id: str
    credential_generation: int
    cursor: str
    head_generation: int
    head_updated_at: str
    policy_version_id: str
    policy_id: str
    version: str
    content_hash: str
    policy_envelope: dict[str, Any]
    activation_receipt_id: str
    activation_receipt_hash: str
    activation_event_hash: str
    attestation_purpose: str
    attestation_trust_epoch: int
    attestation_key_id: str
    attestation_signature_algorithm: str
    issued_at: str
    revocation_checked_at: str
    fresh_until: str
    expires_at: str
    attestation_signature: str


class RuntimeSignedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    credential_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    credential_generation: int = Field(ge=1)
    audience: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    timestamp: str = Field(min_length=20, max_length=40)
    nonce: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._:/-]+$")
    idempotency_key_digest: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]+$")
    signature: str = Field(min_length=86, max_length=88)


class RuntimeIdentityRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_credential_generation: int = Field(ge=1)


# ---------------------------------------------------------------------------
# Policy registry
# ---------------------------------------------------------------------------


class PolicyPublishRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=1, max_length=200)
    rules: list[dict[str, Any]] = Field(min_length=1)


class PolicyActivateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_generation: int = Field(ge=0)


class PolicyResponse(BaseModel):
    bundle_id: str
    org_id: str
    project_id: str | None = None
    environment_id: str | None = None
    policy_id: str
    version: str
    status: str
    rules: list[dict[str, Any]]
    created_at: datetime
    activated_at: datetime | None
    receipt_id: str | None = None
    generation: int | None = None
    content_hash: str | None = None
    key_id: str | None = None
    signature_algorithm: str | None = None
    trust_epoch: int | None = None


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


class ReceiptDetail(ReceiptSummary):
    argument_hash: str
    result_hash: str | None
    error_class: str | None
    payload: dict[str, Any]


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
