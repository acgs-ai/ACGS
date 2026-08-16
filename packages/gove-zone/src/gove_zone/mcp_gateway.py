"""Protocol-agnostic MCP action gateway built on the shared side-effect kernel.

This module deliberately contains no HTTP, stdio, or MCP SDK integration.  It
defines the last in-process enforcement boundary that a transport adapter must
call.  High-risk ``tools/call`` requests are authorized and then executed by
the existing receipt-gated kernel; no raw downstream client is exposed.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import RLock
from types import MappingProxyType
from typing import Any, Protocol, cast, runtime_checkable

from gove_zone.authorization import (
    AuthorizationError,
    AuthorizationReasonCode,
    EvidenceRef,
    ExecutionRefusalEvidence,
    RefusalEvidence,
    ResolvedPolicyRef,
    SideEffectAuthorization,
    SideEffectExecutionContext,
    SideEffectExecutionError,
    SideEffectRequest,
    StrictJSONBudgetError,
    deep_freeze_json,
    deep_thaw_json,
    strict_json_hash,
    validate_strict_json_budget,
)
from gove_zone.consumption import (
    ReceiptConsumptionError,
    ReceiptConsumptionStore,
    ReceiptReplayError,
    ReceiptRevokedError,
)
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import ReceiptValidationError
from gove_zone.escalation import PendingApproval, approve_escalation
from gove_zone.mcp_identity import (
    MCPIdentityError,
    MCPIdentityReasonCode,
    MCPIdentityVerifier,
    MCPPrincipalContext,
    VerifiedMCPIdentity,
)
from gove_zone.mcp_security import (
    MCPOriginError,
    MCPOriginValidator,
    MCPStdioError,
    MCPStdioTargetValidator,
    ValidatedMCPOrigin,
    ValidatedMCPStdioTarget,
)
from gove_zone.policy import new_event_id
from gove_zone.receipt import DecisionReceipt, Validator
from gove_zone.side_effect_kernel import (
    AdapterOutcome,
    AdapterOutcomeStatus,
    ReceiptGatedSideEffectExecutor,
    SideEffectAuthorizationKernel,
)

MCP_TOOLS_CALL_OPERATION = "tools/call"
MCP_TOOLS_LIST_OPERATION = "tools/list"
MCP_TOOLS_APPROVE_OPERATION = "tools/approve"
MCP_TOOLS_RESUME_OPERATION = "tools/resume"
MCP_APPROVE_TOOL = "gove.approve"
MCP_RESUME_TOOL = "gove.resume"
MCP_GATEWAY_EXECUTION_BOUNDARY = "acgs-mcp-action-gateway"
MCP_HUMAN_LOOP_METHODS = frozenset(
    {MCP_TOOLS_APPROVE_OPERATION, MCP_TOOLS_RESUME_OPERATION}
)
MCP_HUMAN_LOOP_TOOLS = frozenset({MCP_APPROVE_TOOL, MCP_RESUME_TOOL})

# Authority is the operation the issuing identity authority signed for, and it is
# the only thing that separates a catalog reader from a caller.  A token minted
# for tools/list can never satisfy tools/call, no matter what scopes, tenant,
# role, or policy metadata it also carries.
MCP_TOOLS_LIST_AUTHORITY = "mcp.tools.list"
MCP_TOOLS_CALL_AUTHORITY = "mcp.tools.call"
MCP_TOOLS_APPROVE_AUTHORITY = "mcp.tools.approve"
MCP_APPROVAL_ROLES = frozenset({"approver"})
# tools/list is a strict capability subset of tools/call, so a caller may read the
# catalog it is allowed to act on.  Frozen: a holder must not widen this at runtime.
MCP_LIST_ALLOWED_AUTHORITIES = frozenset({MCP_TOOLS_LIST_AUTHORITY, MCP_TOOLS_CALL_AUTHORITY})
_TOOL_NAME_RE = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _require_text(value: object, name: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{name} must be valid UTF-8") from None
    return value


def _require_digest(value: object, name: str) -> str:
    text = _require_text(value, name)
    if _SHA256_RE.fullmatch(text) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return text


def _timestamp(value: object, name: str) -> str:
    text = _require_text(value, name)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"{name} must be an ISO-8601 timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{name} must be a UTC timestamp")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _as_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _plain_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    validate_strict_json_budget(value)
    plain = deep_thaw_json(value)
    if type(plain) is not dict:
        raise TypeError("expected a strict JSON object")
    return cast(dict[str, Any], plain)


def _freeze_mapping(value: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    validate_strict_json_budget(value)
    if type(value) is dict:
        plain: Any = value
    elif isinstance(value, Mapping):
        plain = deep_thaw_json(value)
    else:
        raise TypeError(f"{name} must be a dictionary")
    frozen = deep_freeze_json(plain)
    if not isinstance(frozen, Mapping):
        raise TypeError(f"{name} must be a dictionary")
    return cast(Mapping[str, Any], frozen)


def _unique_text_tuple(value: object, name: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if type(value) not in (tuple, list):
        raise TypeError(f"{name} must be a list or tuple")
    items = tuple(
        _require_text(item, f"{name} item") for item in cast(list[Any] | tuple[Any, ...], value)
    )
    if not allow_empty and not items:
        raise ValueError(f"{name} must not be empty")
    if len(items) != len(set(items)):
        raise ValueError(f"{name} must not contain duplicates")
    return items


class MCPGatewayReasonCode(StrEnum):
    """Gateway-local reasons not already represented by shared kernel codes."""

    METHOD_DENIED = "mcp.gateway.method_denied"
    OPERATION_AUTHORITY_DENIED = "mcp.gateway.operation_authority_denied"
    INVALID_REQUEST = "mcp.gateway.invalid_request"
    TOOL_UNKNOWN = "mcp.gateway.tool_unknown"
    TOOL_SCOPE_DENIED = "mcp.gateway.tool_scope_denied"
    CATALOG_UNAVAILABLE = "mcp.gateway.catalog_unavailable"
    CATALOG_COLLISION = "mcp.gateway.catalog_collision"
    CATALOG_MISMATCH = "mcp.gateway.catalog_mismatch"
    DOWNSTREAM_CREDENTIAL_FAILED = "mcp.gateway.downstream_credential_failed"
    DOWNSTREAM_CREDENTIAL_MISMATCH = "mcp.gateway.downstream_credential_mismatch"
    DOWNSTREAM_OUTCOME_UNKNOWN = "mcp.gateway.downstream_outcome_unknown"
    HUMAN_APPROVAL_REQUIRED = "mcp.gateway.human_approval_required"
    HUMAN_APPROVAL_UNKNOWN = "mcp.gateway.human_approval_unknown"
    HUMAN_APPROVAL_REPLAY = "mcp.gateway.human_approval_replay"
    HUMAN_SELF_APPROVAL = "mcp.gateway.human_self_approval"
    HUMAN_APPROVAL_MISSING = "mcp.gateway.human_approval_missing"
    HUMAN_APPROVAL_CONSUMPTION_UNAVAILABLE = (
        "mcp.gateway.human_approval_consumption_unavailable"
    )
    HUMAN_TENANT_MISMATCH = "mcp.gateway.human_tenant_mismatch"
    HUMAN_APPROVAL_INVALID = "mcp.gateway.human_approval_invalid"
    RESERVED_TOOL_NAME = "mcp.gateway.reserved_tool_name"
    SCHEMA_INVALID = "mcp.gateway.schema_invalid"
    SCHEMA_UNSUPPORTED = "mcp.gateway.schema_unsupported"


class MCPRiskClass(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MCPEscalationPolicy(StrEnum):
    NONE = "none"
    POLICY = "policy"
    HUMAN_REQUIRED = "human-required"


class MCPGatewayStatus(StrEnum):
    SUCCEEDED = "succeeded"
    LISTED = "listed"
    DENIED = "denied"
    ESCALATED = "escalated"
    FAILED_CLOSED = "failed_closed"


class MCPCatalogError(RuntimeError):
    non_retryable = True

    def __init__(self, reason_code: MCPGatewayReasonCode) -> None:
        if reason_code not in {
            MCPGatewayReasonCode.CATALOG_UNAVAILABLE,
            MCPGatewayReasonCode.CATALOG_COLLISION,
            MCPGatewayReasonCode.CATALOG_MISMATCH,
            MCPGatewayReasonCode.DOWNSTREAM_CREDENTIAL_FAILED,
            MCPGatewayReasonCode.DOWNSTREAM_CREDENTIAL_MISMATCH,
        }:
            raise ValueError("reason_code is not a catalog failure")
        self.reason_code = reason_code
        super().__init__(reason_code.value)


class MCPSchemaError(RuntimeError):
    """A bounded-schema contract or instance was rejected fail closed."""

    non_retryable = True

    def __init__(self, reason_code: MCPGatewayReasonCode) -> None:
        if reason_code not in {
            MCPGatewayReasonCode.SCHEMA_INVALID,
            MCPGatewayReasonCode.SCHEMA_UNSUPPORTED,
        }:
            raise ValueError("reason_code is not a schema failure")
        self.reason_code = reason_code
        super().__init__(reason_code.value)


_SCHEMA_TYPES = frozenset({"object", "array", "string", "integer", "number", "boolean", "null"})
_COMMON_SCHEMA_KEYS = frozenset({"type", "enum", "const"})
_TYPE_SCHEMA_KEYS = {
    "object": frozenset({"properties", "required", "additionalProperties"}),
    "array": frozenset({"items", "minItems", "maxItems"}),
    "string": frozenset({"minLength", "maxLength"}),
    "integer": frozenset({"minimum", "maximum"}),
    "number": frozenset({"minimum", "maximum"}),
    "boolean": frozenset(),
    "null": frozenset(),
}
_MAX_SCHEMA_DEPTH = 8
_MAX_SCHEMA_NODES = 256
_MAX_CONTAINER_ITEMS = 1024
_MAX_STRING_LENGTH = 65_536


def _schema_type_matches(value: Any, schema_type: str) -> bool:
    if schema_type == "object":
        return type(value) is dict
    if schema_type == "array":
        return type(value) is list
    if schema_type == "string":
        return type(value) is str
    if schema_type == "integer":
        return type(value) is int
    if schema_type == "number":
        return type(value) in (int, float) and math.isfinite(float(value))
    if schema_type == "boolean":
        return type(value) is bool
    return value is None


def _validated_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    try:
        plain = _plain_mapping(schema)
    except (StrictJSONBudgetError, TypeError, ValueError, RecursionError):
        raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_UNSUPPORTED) from None
    counter = [0]

    def validate_node(node: Any, depth: int) -> None:
        if type(node) is not dict:
            raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_UNSUPPORTED)
        counter[0] += 1
        if depth > _MAX_SCHEMA_DEPTH or counter[0] > _MAX_SCHEMA_NODES:
            raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_UNSUPPORTED)
        schema_type = node.get("type")
        if type(schema_type) is not str or schema_type not in _SCHEMA_TYPES:
            raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_UNSUPPORTED)
        if not set(node).issubset(_COMMON_SCHEMA_KEYS | _TYPE_SCHEMA_KEYS[schema_type]):
            raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_UNSUPPORTED)
        if "enum" in node:
            enum = node["enum"]
            if type(enum) is not list or not enum or len(enum) > _MAX_CONTAINER_ITEMS:
                raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_UNSUPPORTED)
            if any(not _schema_type_matches(item, schema_type) for item in enum):
                raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_UNSUPPORTED)
        if "const" in node and not _schema_type_matches(node["const"], schema_type):
            raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_UNSUPPORTED)
        if schema_type == "object":
            properties = node.get("properties", {})
            if type(properties) is not dict or len(properties) > _MAX_SCHEMA_NODES:
                raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_UNSUPPORTED)
            for name, child in properties.items():
                if type(name) is not str or not name:
                    raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_UNSUPPORTED)
                validate_node(child, depth + 1)
            required = node.get("required", [])
            if type(required) is not list or any(type(name) is not str for name in required):
                raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_UNSUPPORTED)
            if len(required) != len(set(required)) or not set(required).issubset(properties):
                raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_UNSUPPORTED)
            additional = node.get("additionalProperties", True)
            if type(additional) is not bool:
                raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_UNSUPPORTED)
        elif schema_type == "array":
            if "items" not in node:
                raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_UNSUPPORTED)
            validate_node(node["items"], depth + 1)
            _validate_nonnegative_bounds(node, "minItems", "maxItems", _MAX_CONTAINER_ITEMS)
        elif schema_type == "string":
            _validate_nonnegative_bounds(node, "minLength", "maxLength", _MAX_STRING_LENGTH)
        elif schema_type in {"integer", "number"}:
            for name in ("minimum", "maximum"):
                if name in node and not _schema_type_matches(node[name], "number"):
                    raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_UNSUPPORTED)
            if "minimum" in node and "maximum" in node and node["minimum"] > node["maximum"]:
                raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_UNSUPPORTED)

    validate_node(plain, 0)
    if plain.get("type") != "object":
        raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_UNSUPPORTED)
    return plain


def _validate_nonnegative_bounds(
    node: dict[str, Any],
    minimum_name: str,
    maximum_name: str,
    hard_maximum: int,
) -> None:
    minimum = node.get(minimum_name, 0)
    maximum = node.get(maximum_name, hard_maximum)
    if (
        type(minimum) is not int
        or type(maximum) is not int
        or minimum < 0
        or maximum < minimum
        or maximum > hard_maximum
    ):
        raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_UNSUPPORTED)


def _validate_arguments(schema: Mapping[str, Any], arguments: Mapping[str, Any]) -> None:
    trusted_schema = _validated_schema(schema)
    try:
        validate_strict_json_budget(arguments)
        value = _plain_mapping(arguments)
    except (StrictJSONBudgetError, TypeError, ValueError, RecursionError):
        raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_INVALID) from None

    def validate_value(node: dict[str, Any], current: Any, depth: int) -> None:
        if depth > _MAX_SCHEMA_DEPTH:
            raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_INVALID)
        schema_type = cast(str, node["type"])
        if not _schema_type_matches(current, schema_type):
            raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_INVALID)
        if "enum" in node and current not in node["enum"]:
            raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_INVALID)
        if "const" in node and current != node["const"]:
            raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_INVALID)
        if schema_type == "object":
            properties = cast(dict[str, Any], node.get("properties", {}))
            required = cast(list[str], node.get("required", []))
            if not set(required).issubset(current):
                raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_INVALID)
            extra = set(current) - set(properties)
            if extra and node.get("additionalProperties", True) is False:
                raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_INVALID)
            if len(current) > _MAX_CONTAINER_ITEMS:
                raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_INVALID)
            for name in set(current) & set(properties):
                validate_value(properties[name], current[name], depth + 1)
        elif schema_type == "array":
            if (
                not node.get("minItems", 0)
                <= len(current)
                <= node.get("maxItems", _MAX_CONTAINER_ITEMS)
            ):
                raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_INVALID)
            for item in current:
                validate_value(cast(dict[str, Any], node["items"]), item, depth + 1)
        elif schema_type == "string":
            if len(current) > _MAX_STRING_LENGTH or not node.get("minLength", 0) <= len(
                current
            ) <= node.get("maxLength", _MAX_STRING_LENGTH):
                raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_INVALID)
        elif schema_type in {"integer", "number"}:
            if "minimum" in node and current < node["minimum"]:
                raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_INVALID)
            if "maximum" in node and current > node["maximum"]:
                raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_INVALID)

    validate_value(trusted_schema, value, 0)


@dataclass(frozen=True, slots=True)
class MCPToolDefinition:
    """One exact name/schema/description catalog identity."""

    name: str
    description: str
    input_schema: Mapping[str, Any] = field(repr=False)

    def __post_init__(self) -> None:
        name = _require_text(self.name, "name")
        if _TOOL_NAME_RE.fullmatch(name) is None:
            raise ValueError("tool name contains unsupported characters")
        object.__setattr__(self, "name", name)
        if type(self.description) is not str:
            raise TypeError("description must be a string")
        try:
            self.description.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("description must be valid UTF-8") from None
        try:
            schema = _validated_schema(self.input_schema)
        except MCPSchemaError:
            raise
        except (TypeError, ValueError, RecursionError):
            raise MCPSchemaError(MCPGatewayReasonCode.SCHEMA_UNSUPPORTED) from None
        object.__setattr__(self, "input_schema", _freeze_mapping(schema, "input_schema"))

    @property
    def digest(self) -> str:
        return strict_json_hash(
            {
                "name": self.name,
                "description": self.description,
                "input_schema": _plain_mapping(self.input_schema),
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": _plain_mapping(self.input_schema),
            "catalog_digest": self.digest,
        }


@dataclass(frozen=True, slots=True)
class MCPToolPolicy:
    """Immutable administrative policy metadata for one downstream tool."""

    definition: MCPToolDefinition
    required_scopes: tuple[str, ...]
    downstream_scopes: tuple[str, ...]
    risk_class: MCPRiskClass
    escalation_policy: MCPEscalationPolicy
    authority: str
    resource: str
    environment: str
    side_effect_class: str
    policy_bundle_id: str
    policy_version: str
    policy_digest: str
    catalog_scopes: tuple[str, ...] = ()
    """Scopes that let an identity *see* this tool in tools/list.

    Listing is metadata disclosure, not a capability: these scopes are checked
    only by :meth:`MCPActionGateway.list_tools` and are never sufficient to call.
    A call additionally requires ``mcp.tools.call`` authority plus
    ``required_scopes``.  Defaults to ``required_scopes`` so an existing
    deployment keeps its current, narrower visibility until it opts in.
    """

    def __post_init__(self) -> None:
        if not isinstance(self.definition, MCPToolDefinition):
            raise TypeError("definition must be an MCPToolDefinition")
        object.__setattr__(
            self,
            "required_scopes",
            _unique_text_tuple(self.required_scopes, "required_scopes"),
        )
        object.__setattr__(
            self,
            "catalog_scopes",
            _unique_text_tuple(self.catalog_scopes or self.required_scopes, "catalog_scopes"),
        )
        object.__setattr__(
            self,
            "downstream_scopes",
            _unique_text_tuple(self.downstream_scopes, "downstream_scopes"),
        )
        try:
            risk_class = MCPRiskClass(self.risk_class)
            escalation_policy = MCPEscalationPolicy(self.escalation_policy)
        except ValueError:
            raise ValueError("risk_class or escalation_policy is unsupported") from None
        if risk_class in {MCPRiskClass.HIGH, MCPRiskClass.CRITICAL} and (
            escalation_policy is MCPEscalationPolicy.NONE
        ):
            raise ValueError("high and critical risk tools require escalation policy enforcement")
        object.__setattr__(self, "risk_class", risk_class)
        object.__setattr__(self, "escalation_policy", escalation_policy)
        for name in (
            "authority",
            "resource",
            "environment",
            "side_effect_class",
            "policy_bundle_id",
            "policy_version",
        ):
            object.__setattr__(self, name, _require_text(getattr(self, name), name))
        # A tool policy authorizes tools/call and nothing else, so it can only be
        # written against the call authority.  Any other value would be a policy
        # that silently never matches, or a gate widened by configuration.
        if self.authority != MCP_TOOLS_CALL_AUTHORITY:
            raise ValueError(f"tool policy authority must be {MCP_TOOLS_CALL_AUTHORITY!r}")
        object.__setattr__(
            self,
            "policy_digest",
            _require_digest(self.policy_digest, "policy_digest"),
        )

    @property
    def authorization_side_effect_class(self) -> str:
        """Content-address all trusted MCP policy metadata in the receipt binding."""

        digest = strict_json_hash(
            {
                "schema": "gove-zone.mcp-tool-policy-binding.v1",
                "catalog_digest": self.definition.digest,
                "required_scopes": list(self.required_scopes),
                "downstream_scopes": list(self.downstream_scopes),
                "risk_class": self.risk_class.value,
                "escalation_policy": self.escalation_policy.value,
                "side_effect_class": self.side_effect_class,
            }
        )
        return f"mcp-policy:{digest}"


@dataclass(frozen=True, slots=True)
class MCPGatewayConfig:
    """Single-downstream immutable gateway configuration."""

    origin: ValidatedMCPOrigin | ValidatedMCPStdioTarget
    tools: tuple[MCPToolPolicy, ...]
    execution_boundary: str = MCP_GATEWAY_EXECUTION_BOUNDARY
    list_scope: str = "tools:list"
    credential_audience: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.origin, ValidatedMCPOrigin | ValidatedMCPStdioTarget):
            raise TypeError("origin must be a validated network or stdio target")
        if type(self.tools) not in (tuple, list):
            raise TypeError("tools must be a list or tuple")
        tools = tuple(self.tools)
        if not tools or any(not isinstance(item, MCPToolPolicy) for item in tools):
            raise ValueError("tools must contain MCPToolPolicy values")
        names = tuple(item.definition.name for item in tools)
        if len(names) != len(set(names)):
            raise ValueError("configured tool names must be unique")
        if any(name in MCP_HUMAN_LOOP_TOOLS for name in names):
            raise ValueError("configured tool names must not use reserved human-loop names")
        if len({item.definition.digest for item in tools}) != len(tools):
            raise ValueError("configured catalog identities must be unique")
        if len({item.authority for item in tools}) != 1:
            raise ValueError("one gateway must use one token authority")
        object.__setattr__(self, "tools", tools)
        object.__setattr__(
            self,
            "execution_boundary",
            _require_text(self.execution_boundary, "execution_boundary"),
        )
        object.__setattr__(self, "list_scope", _require_text(self.list_scope, "list_scope"))
        audience = self.credential_audience or f"mcp://{self.origin.server_id}"
        object.__setattr__(
            self,
            "credential_audience",
            _require_text(audience, "credential_audience"),
        )

    @property
    def authority(self) -> str:
        return self.tools[0].authority


@dataclass(frozen=True, slots=True)
class MCPDownstreamCredential:
    """Opaque server-side credential; inbound bearer tokens never instantiate this."""

    credential_type: str
    credential_id: str
    tenant_id: str
    server_id: str
    audience: str
    scopes: tuple[str, ...]
    issued_at: str
    expires_at: str
    secret: str = field(repr=False)

    def __post_init__(self) -> None:
        for name in ("credential_type", "credential_id", "tenant_id", "server_id", "audience"):
            object.__setattr__(self, name, _require_text(getattr(self, name), name))
        object.__setattr__(self, "scopes", _unique_text_tuple(self.scopes, "scopes"))
        issued_at = _timestamp(self.issued_at, "issued_at")
        expires_at = _timestamp(self.expires_at, "expires_at")
        if _as_datetime(expires_at) <= _as_datetime(issued_at):
            raise ValueError("credential expiry must be after issuance")
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "secret", _require_text(self.secret, "secret"))

    @property
    def binding_hash(self) -> str:
        return strict_json_hash(self.to_safe_dict())

    def to_safe_dict(self) -> dict[str, Any]:
        """Serialize only verifiable identity metadata, never credential material."""

        return {
            "credential_type": self.credential_type,
            "credential_id": self.credential_id,
            "tenant_id": self.tenant_id,
            "server_id": self.server_id,
            "audience": self.audience,
            "scopes": list(self.scopes),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    def validate_for(
        self,
        *,
        tenant_id: str,
        server_id: str,
        audience: str,
        required_scopes: frozenset[str],
        now: datetime,
    ) -> None:
        if type(required_scopes) is not frozenset:
            raise TypeError("required_scopes must be a frozenset")
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise ValueError("credential validation clock must be UTC")
        if (
            self.tenant_id != tenant_id
            or self.server_id != server_id
            or self.audience != audience
            or not required_scopes.issubset(self.scopes)
            or not (_as_datetime(self.issued_at) <= now < _as_datetime(self.expires_at))
        ):
            raise MCPCatalogError(MCPGatewayReasonCode.DOWNSTREAM_CREDENTIAL_MISMATCH)


@runtime_checkable
class MCPDownstreamCredentialProvider(Protocol):
    def get_credential(self, server_id: str, tenant_id: str) -> MCPDownstreamCredential: ...


@dataclass(frozen=True, slots=True)
class MCPDownstreamToolList:
    tools: tuple[MCPToolDefinition, ...]
    response_origin: str = ""
    peer_address: str = ""
    redirect_url: str | None = None
    transport_binding: str = ""

    def __post_init__(self) -> None:
        if type(self.tools) not in (tuple, list):
            raise TypeError("tools must be a list or tuple")
        tools = tuple(self.tools)
        if any(not isinstance(item, MCPToolDefinition) for item in tools):
            raise TypeError("tools must contain MCPToolDefinition values")
        object.__setattr__(self, "tools", tools)
        if self.transport_binding:
            object.__setattr__(
                self,
                "transport_binding",
                _require_digest(self.transport_binding, "transport_binding"),
            )
            if self.response_origin or self.peer_address or self.redirect_url is not None:
                raise ValueError("stdio results must not claim network transport metadata")
        else:
            object.__setattr__(
                self,
                "response_origin",
                _require_text(self.response_origin, "response_origin"),
            )
            object.__setattr__(
                self,
                "peer_address",
                _require_text(self.peer_address, "peer_address"),
            )
        if self.redirect_url is not None:
            object.__setattr__(
                self,
                "redirect_url",
                _require_text(self.redirect_url, "redirect_url"),
            )


@dataclass(frozen=True, slots=True)
class MCPDownstreamToolResult:
    status: AdapterOutcomeStatus
    payload: Any
    response_origin: str = ""
    peer_address: str = ""
    redirect_url: str | None = None
    transport_binding: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.status, AdapterOutcomeStatus):
            raise TypeError("status must be an AdapterOutcomeStatus")
        if self.transport_binding:
            object.__setattr__(
                self,
                "transport_binding",
                _require_digest(self.transport_binding, "transport_binding"),
            )
            if self.response_origin or self.peer_address or self.redirect_url is not None:
                raise ValueError("stdio results must not claim network transport metadata")
        else:
            object.__setattr__(
                self,
                "response_origin",
                _require_text(self.response_origin, "response_origin"),
            )
            object.__setattr__(
                self,
                "peer_address",
                _require_text(self.peer_address, "peer_address"),
            )
        if self.redirect_url is not None:
            object.__setattr__(
                self,
                "redirect_url",
                _require_text(self.redirect_url, "redirect_url"),
            )


@runtime_checkable
class MCPDownstreamTransport(Protocol):
    """A no-redirect transport owned by the gateway deployment."""

    def list_tools(
        self,
        origin: ValidatedMCPOrigin | ValidatedMCPStdioTarget,
        credential: MCPDownstreamCredential,
    ) -> MCPDownstreamToolList: ...

    def call_tool(
        self,
        origin: ValidatedMCPOrigin | ValidatedMCPStdioTarget,
        credential: MCPDownstreamCredential,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> MCPDownstreamToolResult: ...


@dataclass(frozen=True, slots=True)
class MCPToolListResponse:
    request_id: str
    decision: Decision
    status: MCPGatewayStatus
    reason_codes: tuple[str, ...]
    tools: tuple[MCPToolDefinition, ...] = ()
    retryable: bool = False
    audit_event_id: str = ""
    refusal_evidence: RefusalEvidence | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", _require_text(self.request_id, "request_id"))
        if not isinstance(self.decision, Decision):
            raise TypeError("decision must be a Decision")
        if not isinstance(self.status, MCPGatewayStatus):
            raise TypeError("status must be an MCPGatewayStatus")
        object.__setattr__(
            self,
            "reason_codes",
            _unique_text_tuple(self.reason_codes, "reason_codes"),
        )
        if type(self.tools) not in (tuple, list):
            raise TypeError("tools must be a list or tuple")
        tools = tuple(self.tools)
        if any(not isinstance(item, MCPToolDefinition) for item in tools):
            raise TypeError("tools must contain MCPToolDefinition values")
        object.__setattr__(self, "tools", tools)
        if type(self.retryable) is not bool:
            raise TypeError("retryable must be a boolean")
        if self.audit_event_id:
            object.__setattr__(
                self,
                "audit_event_id",
                _require_text(self.audit_event_id, "audit_event_id"),
            )
        if self.refusal_evidence is not None:
            if not isinstance(self.refusal_evidence, RefusalEvidence):
                raise TypeError("refusal_evidence must be RefusalEvidence")
            if (
                self.refusal_evidence.audit_event_id != self.audit_event_id
                or self.refusal_evidence.decision is not self.decision
                or self.refusal_evidence.reason_codes != self.reason_codes
            ):
                raise ValueError("refusal evidence and tool-list response are inconsistent")


@dataclass(frozen=True, slots=True)
class MCPPendingApproval:
    """Stable, non-executable handle for a HUMAN_REQUIRED tools/call.

    This is not a Decision Receipt and cannot authorize a side effect. Resume
    requires a distinct human approval receipt that is then consumed once.
    """

    pending_id: str
    request_id: str
    tool: str
    actor_id: str
    tenant_id: str
    audit_hash: str
    decision_request_hash: str


@dataclass
class _StoredHumanApproval:
    handle: MCPPendingApproval
    pending: PendingApproval
    tool_name: str
    arguments: dict[str, Any]
    nonce: str
    idempotency_key: str
    requested_at: str
    observed_at: str
    evidence: tuple[EvidenceRef, ...]
    goal: str
    session_id: str
    actor_id: str
    tenant_id: str
    approval_receipt: DecisionReceipt | None = None


@dataclass(frozen=True, slots=True)
class MCPGatewayResponse:
    request_id: str
    decision: Decision
    status: MCPGatewayStatus
    reason_codes: tuple[str, ...]
    retryable: bool
    executed: bool
    outcome_unknown: bool = False
    payload: Any = None
    receipt: DecisionReceipt | None = field(default=None, repr=False)
    audit_event_id: str = ""
    approved_arguments: Mapping[str, Any] = field(default_factory=dict, repr=False)
    refusal_evidence: RefusalEvidence | None = field(default=None, repr=False)
    # The final execution gate's own proof, kept verbatim and deliberately
    # separate from ``refusal_evidence``: that field answers "was this request
    # authorized?" and is bound to ``audit_event_id``, while this one answers
    # "did this receipted attempt run?" and is bound to its own refusal audit
    # event. Collapsing them would destroy the only evidence a consumer can
    # verify against the exact attempt.
    execution_refusal_evidence: ExecutionRefusalEvidence | None = field(
        default=None,
        repr=False,
    )
    pending_approval: MCPPendingApproval | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", _require_text(self.request_id, "request_id"))
        if not isinstance(self.decision, Decision):
            raise TypeError("decision must be a Decision")
        if not isinstance(self.status, MCPGatewayStatus):
            raise TypeError("status must be an MCPGatewayStatus")
        object.__setattr__(
            self,
            "reason_codes",
            _unique_text_tuple(self.reason_codes, "reason_codes"),
        )
        for name in ("retryable", "executed", "outcome_unknown"):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be a boolean")
        if self.executed and self.status is not MCPGatewayStatus.SUCCEEDED:
            raise ValueError("executed responses must be successful")
        if self.outcome_unknown and self.status is not MCPGatewayStatus.FAILED_CLOSED:
            raise ValueError("unknown outcomes must be failed closed")
        if self.receipt is not None and not isinstance(self.receipt, DecisionReceipt):
            raise TypeError("receipt must be a DecisionReceipt")
        if self.audit_event_id:
            object.__setattr__(
                self,
                "audit_event_id",
                _require_text(self.audit_event_id, "audit_event_id"),
            )
        object.__setattr__(
            self,
            "approved_arguments",
            _freeze_mapping(self.approved_arguments, "approved_arguments"),
        )
        if self.refusal_evidence is not None and not isinstance(
            self.refusal_evidence, RefusalEvidence
        ):
            raise TypeError("refusal_evidence must be RefusalEvidence")
        if self.refusal_evidence is not None and (
            self.refusal_evidence.audit_event_id != self.audit_event_id
            or self.refusal_evidence.decision is not self.decision
            or self.refusal_evidence.reason_codes != self.reason_codes
        ):
            raise ValueError("refusal evidence and gateway response are inconsistent")
        if self.execution_refusal_evidence is not None:
            if not isinstance(self.execution_refusal_evidence, ExecutionRefusalEvidence):
                raise TypeError("execution_refusal_evidence must be ExecutionRefusalEvidence")
            if self.executed or self.status is not MCPGatewayStatus.FAILED_CLOSED:
                raise ValueError("only a failed-closed response can carry execution refusal proof")
            if self.execution_refusal_evidence.reason_code.value not in self.reason_codes:
                raise ValueError("execution refusal evidence and gateway response are inconsistent")
        if self.pending_approval is not None:
            if not isinstance(self.pending_approval, MCPPendingApproval):
                raise TypeError("pending_approval must be an MCPPendingApproval")
            if self.executed or self.receipt is not None:
                raise ValueError("a pending approval cannot carry an executable receipt")
            if self.status is not MCPGatewayStatus.ESCALATED:
                raise ValueError("only an escalated response can carry a pending approval")

    @property
    def execution_refusal_audit_event_id(self) -> str:
        """The refusal record's own audit event id, distinct from the authorization's."""

        evidence = self.execution_refusal_evidence
        return "" if evidence is None else evidence.audit_event_id

    @property
    def execution_refusal_audited(self) -> bool:
        """Whether the execution refusal is committed to the strict audit chain."""

        evidence = self.execution_refusal_evidence
        return False if evidence is None else evidence.audited

    @property
    def execution_refusal_signed(self) -> bool:
        """Whether the execution refusal carries an independent signature."""

        evidence = self.execution_refusal_evidence
        return False if evidence is None else evidence.signed


class MCPActionGateway:
    """One fixed-origin MCP server protected by the shared authorization kernel."""

    def __init__(
        self,
        *,
        config: MCPGatewayConfig,
        identity_verifier: MCPIdentityVerifier,
        principal_context: MCPPrincipalContext,
        origin_validator: MCPOriginValidator | MCPStdioTargetValidator,
        credential_provider: MCPDownstreamCredentialProvider,
        transport: MCPDownstreamTransport,
        authorizer: SideEffectAuthorizationKernel,
        executor: ReceiptGatedSideEffectExecutor,
        clock: Callable[[], datetime] | None = None,
        consumption_store: ReceiptConsumptionStore | None = None,
    ) -> None:
        if not isinstance(config, MCPGatewayConfig):
            raise TypeError("config must be an MCPGatewayConfig")
        if not isinstance(identity_verifier, MCPIdentityVerifier):
            raise TypeError("identity_verifier must be an MCPIdentityVerifier")
        if not isinstance(principal_context, MCPPrincipalContext):
            raise TypeError("principal_context must be an MCPPrincipalContext")
        if not isinstance(origin_validator, MCPOriginValidator | MCPStdioTargetValidator):
            raise TypeError("origin_validator must validate the configured transport")
        if isinstance(config.origin, ValidatedMCPOrigin) != isinstance(
            origin_validator, MCPOriginValidator
        ):
            raise TypeError("origin and validator transport kinds must match")
        if not isinstance(credential_provider, MCPDownstreamCredentialProvider):
            raise TypeError("credential_provider must implement MCPDownstreamCredentialProvider")
        if not isinstance(transport, MCPDownstreamTransport):
            raise TypeError("transport must implement MCPDownstreamTransport")
        if not isinstance(authorizer, SideEffectAuthorizationKernel):
            raise TypeError("authorizer must be a SideEffectAuthorizationKernel")
        if not isinstance(executor, ReceiptGatedSideEffectExecutor):
            raise TypeError("executor must be a ReceiptGatedSideEffectExecutor")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        if consumption_store is not None and not isinstance(
            consumption_store, ReceiptConsumptionStore
        ):
            raise TypeError("consumption_store must be a ReceiptConsumptionStore")

        self._config = config
        self._identity_verifier = identity_verifier
        self._principal_context = principal_context
        self._origin_validator = origin_validator
        self._credential_provider = credential_provider
        self._transport = transport
        self._authorizer = authorizer
        self._executor = executor
        self._clock = clock or (lambda: datetime.now(UTC))
        self._consumption_store = consumption_store
        self._human_approvals: dict[str, _StoredHumanApproval] = {}
        self._origin = self._reconcile_target(config.origin)
        self._expected_credential_binding: ContextVar[str | None] = ContextVar(
            "gove_zone_mcp_expected_downstream_credential",
            default=None,
        )
        self._expected_transport_binding: ContextVar[str | None] = ContextVar(
            "gove_zone_mcp_expected_transport_binding",
            default=None,
        )
        # The shared audit checkpoint is intentionally linear.  Serialize the
        # authorize-to-execute critical section so a later authorization cannot
        # advance the checkpoint before an earlier receipt reaches its adapter.
        self._call_lock = RLock()
        self._policies = MappingProxyType(
            {item.definition.name: item for item in self._config.tools}
        )
        self._all_downstream_scopes = frozenset(
            scope for item in self._config.tools for scope in item.downstream_scopes
        )
        self._gateway_refusal_digest = strict_json_hash(
            {
                "schema": "gove-zone.mcp-gateway-refusal-policy.v1",
                "server_id": self._origin.server_id,
                "transport_binding": self._target_binding(self._origin),
                "execution_boundary": self._config.execution_boundary,
                "credential_audience": self._config.credential_audience,
                "tools": [
                    {
                        "name": item.definition.name,
                        "policy_digest": item.policy_digest,
                        "authorization_side_effect_class": (item.authorization_side_effect_class),
                    }
                    for item in self._config.tools
                ],
            }
        )

        for policy in self._config.tools:
            self._executor.register_adapter(
                self._origin.server_id,
                policy.definition.name,
                MCP_TOOLS_CALL_OPERATION,
                self._adapter_for(policy),
            )

    def list_tools(
        self,
        *,
        inbound_token: str,
        session_id: str,
        request_id: str | None = None,
    ) -> MCPToolListResponse:
        safe_request_id = self._safe_request_id(request_id, "tools/list")
        identity: VerifiedMCPIdentity | None = None
        if request_id is not None:
            try:
                _require_text(request_id, "request_id")
            except (TypeError, ValueError, RecursionError):
                return self._denied_list(
                    safe_request_id,
                    MCPGatewayReasonCode.INVALID_REQUEST.value,
                    identity=None,
                )
        try:
            identity = self._identity_verifier.verify(
                inbound_token,
                session_id=session_id,
                required_authority=MCP_LIST_ALLOWED_AUTHORITIES,
                required_scopes=frozenset({self._config.list_scope}),
            )
            catalog, _credential = self._load_exact_catalog(
                identity,
                required_scopes=self._all_downstream_scopes,
            )
        except (
            MCPIdentityError,
            MCPOriginError,
            MCPStdioError,
            MCPCatalogError,
            MCPSchemaError,
        ) as exc:
            return self._denied_list(
                safe_request_id,
                exc.reason_code.value,
                identity=identity,
            )
        except (TypeError, ValueError, RecursionError):
            return self._denied_list(
                safe_request_id,
                MCPGatewayReasonCode.INVALID_REQUEST.value,
                identity=identity,
            )
        allowed = tuple(
            item
            for item in catalog
            if frozenset(self._policies[item.name].catalog_scopes).issubset(identity.scopes)
        )
        return MCPToolListResponse(
            request_id=safe_request_id,
            decision=Decision.ALLOW,
            status=MCPGatewayStatus.LISTED,
            reason_codes=("mcp.gateway.catalog_allowed",),
            tools=allowed,
        )

    def call_tool(
        self,
        *,
        inbound_token: str,
        session_id: str,
        request_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        nonce: str,
        idempotency_key: str,
        requested_at: str,
        observed_at: str,
        evidence: tuple[EvidenceRef, ...] = (),
        goal: str = "",
    ) -> MCPGatewayResponse:
        with self._call_lock:
            return self._call_tool_locked(
                inbound_token=inbound_token,
                session_id=session_id,
                request_id=request_id,
                tool_name=tool_name,
                arguments=arguments,
                nonce=nonce,
                idempotency_key=idempotency_key,
                requested_at=requested_at,
                observed_at=observed_at,
                evidence=evidence,
                goal=goal,
            )

    def _call_tool_locked(
        self,
        *,
        inbound_token: str,
        session_id: str,
        request_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        nonce: str,
        idempotency_key: str,
        requested_at: str,
        observed_at: str,
        evidence: tuple[EvidenceRef, ...],
        goal: str,
    ) -> MCPGatewayResponse:
        safe_request_id = self._safe_request_id(request_id, MCP_TOOLS_CALL_OPERATION)
        identity: VerifiedMCPIdentity | None = None
        policy: MCPToolPolicy | None = None
        try:
            _require_text(request_id, "request_id")
        except (TypeError, ValueError, RecursionError):
            return self._denied(
                safe_request_id,
                MCPGatewayReasonCode.INVALID_REQUEST.value,
                arguments=arguments,
            )
        if type(tool_name) is str and tool_name in MCP_HUMAN_LOOP_TOOLS:
            return self._denied(
                safe_request_id,
                MCPGatewayReasonCode.RESERVED_TOOL_NAME.value,
                arguments=arguments,
            )
        try:
            # Operation gate, ahead of policy, kernel and adapter.  A token the
            # authority signed for tools/list is not a caller here, whatever its
            # tenant, scopes, role, tool risk class or policy metadata say.  This
            # can only ever deny: the scope-bearing verify below still decides.
            self._identity_verifier.verify(
                inbound_token,
                session_id=session_id,
                required_authority=MCP_TOOLS_CALL_AUTHORITY,
            )
        except MCPIdentityError as exc:
            reason = (
                MCPGatewayReasonCode.OPERATION_AUTHORITY_DENIED.value
                if exc.reason_code is MCPIdentityReasonCode.AUTHORITY_MISMATCH
                else exc.reason_code.value
            )
            return self._denied(safe_request_id, reason, arguments=arguments)
        except (TypeError, ValueError, RecursionError):
            return self._denied(
                safe_request_id,
                MCPGatewayReasonCode.INVALID_REQUEST.value,
                arguments=arguments,
            )
        try:
            policy = self._policies.get(_require_text(tool_name, "tool_name"))
            if policy is None:
                return self._denied(
                    safe_request_id,
                    MCPGatewayReasonCode.TOOL_UNKNOWN.value,
                    arguments=arguments,
                )
            identity = self._identity_verifier.verify(
                inbound_token,
                session_id=session_id,
                required_authority=MCP_TOOLS_CALL_AUTHORITY,
                required_scopes=frozenset(policy.required_scopes),
            )
            _validate_arguments(policy.definition.input_schema, arguments)
            _catalog, credential = self._load_exact_catalog(
                identity,
                required_scopes=frozenset(policy.downstream_scopes),
            )
            request, context = self._build_call(
                identity,
                policy,
                credential_binding=credential.binding_hash,
                transport_binding=self._target_binding(self._origin),
                request_id=safe_request_id,
                arguments=arguments,
                nonce=nonce,
                idempotency_key=idempotency_key,
                requested_at=requested_at,
                observed_at=observed_at,
                evidence=evidence,
                goal=goal,
            )
        except (
            MCPIdentityError,
            MCPOriginError,
            MCPStdioError,
            MCPCatalogError,
            MCPSchemaError,
        ) as exc:
            return self._denied(
                safe_request_id,
                exc.reason_code.value,
                policy=policy,
                identity=identity,
                arguments=arguments,
            )
        except (TypeError, ValueError, RecursionError):
            return self._denied(
                safe_request_id,
                MCPGatewayReasonCode.INVALID_REQUEST.value,
                policy=policy,
                identity=identity,
                arguments=arguments,
            )

        if policy.escalation_policy is MCPEscalationPolicy.HUMAN_REQUIRED:
            return self._open_human_approval(
                safe_request_id,
                policy=policy,
                identity=identity,
                arguments=arguments,
                nonce=nonce,
                idempotency_key=idempotency_key,
                requested_at=requested_at,
                observed_at=observed_at,
                evidence=evidence,
                goal=goal,
                session_id=session_id,
            )

        return self._authorize_and_execute(
            request_id=safe_request_id,
            identity=identity,
            policy=policy,
            request=request,
            context=context,
            arguments=arguments,
            credential_binding=credential.binding_hash,
        )

    def approve_pending(
        self,
        *,
        pending_id: str,
        inbound_token: str,
        session_id: str,
    ) -> MCPGatewayResponse:
        """Mint a fresh ALLOW receipt for a HUMAN_REQUIRED pending. Does not execute."""

        with self._call_lock:
            return self._approve_pending_locked(
                pending_id=pending_id,
                inbound_token=inbound_token,
                session_id=session_id,
            )

    def resume_pending(
        self,
        *,
        pending_id: str,
        inbound_token: str,
        session_id: str,
    ) -> MCPGatewayResponse:
        """Resume an approved pending through the existing authorize+execute gate."""

        with self._call_lock:
            return self._resume_pending_locked(
                pending_id=pending_id,
                inbound_token=inbound_token,
                session_id=session_id,
            )

    def _open_human_approval(
        self,
        request_id: str,
        *,
        policy: MCPToolPolicy,
        identity: VerifiedMCPIdentity,
        arguments: Mapping[str, Any],
        nonce: str,
        idempotency_key: str,
        requested_at: str,
        observed_at: str,
        evidence: tuple[EvidenceRef, ...],
        goal: str,
        session_id: str,
    ) -> MCPGatewayResponse:
        existing = self._human_approvals.get(request_id)
        if existing is not None:
            return self._denied(
                request_id,
                MCPGatewayReasonCode.HUMAN_APPROVAL_REQUIRED.value,
                policy=policy,
                identity=identity,
                arguments=arguments,
                decision=Decision.ESCALATE,
                pending_approval=existing.handle,
            )
        approved_args = _plain_mapping(arguments)
        argument_hash = sha256_json(approved_args)
        decision_request_hash = sha256_json(
            {
                "schema": "gove-zone.mcp-human-required.v1",
                "request_id": request_id,
                "tool": policy.definition.name,
                "actor_id": identity.principal.actor_id,
                "argument_hash": argument_hash,
            }
        )
        record = DecisionRecord(
            decision=Decision.ESCALATE,
            tool=policy.definition.name,
            argument_hash=argument_hash,
            policy_version=policy.policy_version,
            event_id=new_event_id(),
            matched_rules=("MCP_HUMAN_REQUIRED",),
            reason="human approval required before authorization",
            actor=identity.principal.actor_id,
            goal=goal,
            decision_request_hash=decision_request_hash,
        )
        evidence_record = self._record_early_refusal(
            request_id=request_id,
            reason_code=MCPGatewayReasonCode.HUMAN_APPROVAL_REQUIRED.value,
            policy=policy,
            identity=identity,
            arguments=arguments,
            operation=MCP_TOOLS_CALL_OPERATION,
            decision=Decision.ESCALATE,
        )
        pending = PendingApproval(record, evidence_record.audit_event_id, approved_args)
        handle = MCPPendingApproval(
            pending_id=request_id,
            request_id=request_id,
            tool=policy.definition.name,
            actor_id=identity.principal.actor_id,
            tenant_id=identity.principal.tenant_id,
            audit_hash=evidence_record.audit_event_id,
            decision_request_hash=decision_request_hash,
        )
        self._human_approvals[request_id] = _StoredHumanApproval(
            handle=handle,
            pending=pending,
            tool_name=policy.definition.name,
            arguments=approved_args,
            nonce=nonce,
            idempotency_key=idempotency_key,
            requested_at=requested_at,
            observed_at=observed_at,
            evidence=evidence,
            goal=goal,
            session_id=session_id,
            actor_id=identity.principal.actor_id,
            tenant_id=identity.principal.tenant_id,
        )
        return MCPGatewayResponse(
            request_id=request_id,
            decision=Decision.ESCALATE,
            status=MCPGatewayStatus.ESCALATED,
            reason_codes=(MCPGatewayReasonCode.HUMAN_APPROVAL_REQUIRED.value,),
            retryable=False,
            executed=False,
            audit_event_id=evidence_record.audit_event_id,
            refusal_evidence=evidence_record,
            pending_approval=handle,
        )

    def _approve_pending_locked(
        self,
        *,
        pending_id: str,
        inbound_token: str,
        session_id: str,
    ) -> MCPGatewayResponse:
        stored = self._human_approvals.get(pending_id)
        if stored is None:
            return self._denied(
                pending_id,
                MCPGatewayReasonCode.HUMAN_APPROVAL_UNKNOWN.value,
                arguments=None,
            )
        try:
            identity = self._identity_verifier.verify(
                inbound_token,
                session_id=session_id,
                required_authority=MCP_TOOLS_APPROVE_AUTHORITY,
                required_scopes=frozenset(),
            )
        except MCPIdentityError as exc:
            reason = (
                MCPGatewayReasonCode.OPERATION_AUTHORITY_DENIED.value
                if exc.reason_code is MCPIdentityReasonCode.AUTHORITY_MISMATCH
                else exc.reason_code.value
            )
            return self._denied(stored.handle.request_id, reason, arguments=stored.arguments)
        except (TypeError, ValueError, RecursionError):
            return self._denied(
                stored.handle.request_id,
                MCPGatewayReasonCode.INVALID_REQUEST.value,
                arguments=stored.arguments,
            )
        if identity.principal.tenant_id != stored.tenant_id:
            return self._denied(
                stored.handle.request_id,
                MCPGatewayReasonCode.HUMAN_TENANT_MISMATCH.value,
                identity=identity,
                arguments=stored.arguments,
            )
        if identity.principal.actor_id == stored.actor_id:
            return self._denied(
                stored.handle.request_id,
                MCPGatewayReasonCode.HUMAN_SELF_APPROVAL.value,
                identity=identity,
                arguments=stored.arguments,
            )
        if identity.principal.role not in MCP_APPROVAL_ROLES:
            return self._denied(
                stored.handle.request_id,
                MCPIdentityReasonCode.ROLE_NOT_ALLOWED.value,
                identity=identity,
                arguments=stored.arguments,
            )
        if stored.approval_receipt is not None:
            return MCPGatewayResponse(
                request_id=stored.handle.request_id,
                decision=Decision.ALLOW,
                status=MCPGatewayStatus.DENIED,
                reason_codes=("mcp.gateway.human_approval_already_issued",),
                retryable=False,
                executed=False,
                receipt=stored.approval_receipt,
                audit_event_id=stored.handle.audit_hash,
            )
        policy = self._policies.get(stored.tool_name)
        if policy is None:
            return self._denied(
                stored.handle.request_id,
                MCPGatewayReasonCode.TOOL_UNKNOWN.value,
                identity=identity,
                arguments=stored.arguments,
            )
        expires_at = (self._clock() + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        receipt = approve_escalation(
            stored.pending,
            validator=Validator(identity.principal.actor_id, identity.principal.role),
            authority=MCP_TOOLS_APPROVE_AUTHORITY,
            tenant_id=stored.tenant_id,
            execution_boundary=self._config.execution_boundary,
            policy_bundle_id=policy.policy_bundle_id,
            policy_hash=policy.policy_digest,
            audit=self._authorizer._audit,
            request_id=stored.handle.request_id,
            subject=stored.tool_name,
            expires_at=expires_at,
            signer=self._authorizer._signer,
        )
        stored.approval_receipt = receipt
        return MCPGatewayResponse(
            request_id=stored.handle.request_id,
            decision=Decision.ALLOW,
            status=MCPGatewayStatus.DENIED,
            reason_codes=("mcp.gateway.human_approval_issued",),
            retryable=False,
            executed=False,
            receipt=receipt,
            audit_event_id=receipt.audit_event_hash,
        )

    def _resume_pending_locked(
        self,
        *,
        pending_id: str,
        inbound_token: str,
        session_id: str,
    ) -> MCPGatewayResponse:
        stored = self._human_approvals.get(pending_id)
        if stored is None:
            return self._denied(
                pending_id,
                MCPGatewayReasonCode.HUMAN_APPROVAL_UNKNOWN.value,
                arguments=None,
            )
        if stored.approval_receipt is None:
            return self._denied(
                stored.handle.request_id,
                MCPGatewayReasonCode.HUMAN_APPROVAL_MISSING.value,
                arguments=stored.arguments,
            )
        policy = self._policies.get(stored.tool_name)
        if policy is None:
            return self._denied(
                stored.handle.request_id,
                MCPGatewayReasonCode.TOOL_UNKNOWN.value,
                arguments=stored.arguments,
            )
        try:
            identity = self._identity_verifier.verify(
                inbound_token,
                session_id=session_id,
                required_authority=MCP_TOOLS_CALL_AUTHORITY,
                required_scopes=frozenset(policy.required_scopes),
            )
        except MCPIdentityError as exc:
            reason = (
                MCPGatewayReasonCode.OPERATION_AUTHORITY_DENIED.value
                if exc.reason_code is MCPIdentityReasonCode.AUTHORITY_MISMATCH
                else exc.reason_code.value
            )
            return self._denied(stored.handle.request_id, reason, arguments=stored.arguments)
        except (TypeError, ValueError, RecursionError):
            return self._denied(
                stored.handle.request_id,
                MCPGatewayReasonCode.INVALID_REQUEST.value,
                arguments=stored.arguments,
            )
        if identity.principal.tenant_id != stored.tenant_id:
            return self._denied(
                stored.handle.request_id,
                MCPGatewayReasonCode.HUMAN_TENANT_MISMATCH.value,
                identity=identity,
                arguments=stored.arguments,
            )
        if identity.principal.actor_id != stored.actor_id:
            return self._denied(
                stored.handle.request_id,
                MCPGatewayReasonCode.OPERATION_AUTHORITY_DENIED.value,
                identity=identity,
                arguments=stored.arguments,
            )
        if self._consumption_store is None:
            return self._denied(
                stored.handle.request_id,
                MCPGatewayReasonCode.HUMAN_APPROVAL_CONSUMPTION_UNAVAILABLE.value,
                policy=policy,
                identity=identity,
                arguments=stored.arguments,
            )
        approval = stored.approval_receipt
        now_iso = self._clock().astimezone(UTC).isoformat().replace("+00:00", "Z")
        try:
            approval.verify(
                expected_tenant_id=stored.tenant_id,
                expected_execution_boundary=self._config.execution_boundary,
                expected_args=dict(stored.arguments),
                expected_action=stored.tool_name,
                expected_policy_hash=policy.policy_digest,
                expected_policy_bundle_id=policy.policy_bundle_id,
                expected_policy_version=policy.policy_version,
                expected_request_id=stored.handle.request_id,
                expected_actor=stored.actor_id,
                expected_authority=MCP_TOOLS_APPROVE_AUTHORITY,
                expected_validator_role="approver",
                expected_audit_hash=approval.audit_event_hash,
                verifier=self._authorizer._signer,
                require_signature=True,
                now_iso=now_iso,
            )
        except ReceiptValidationError:
            return self._denied(
                stored.handle.request_id,
                MCPGatewayReasonCode.HUMAN_APPROVAL_INVALID.value,
                policy=policy,
                identity=identity,
                arguments=stored.arguments,
            )
        binding_hash = strict_json_hash(
            {
                "schema": "gove-zone.mcp-approval-binding.v1",
                "pending_id": stored.handle.pending_id,
                "decision_request_hash": stored.handle.decision_request_hash,
            }
        )
        idempotency_digest = strict_json_hash(
            {
                "schema": "gove-zone.mcp-approval-idempotency.v1",
                "pending_id": stored.handle.pending_id,
            }
        )
        try:
            self._consumption_store.reserve(
                stored.tenant_id,
                approval.receipt_id,
                f"mcp-approval-resume:{stored.handle.pending_id}",
                approval.receipt_hash,
                binding_hash,
                f"approval-{stored.handle.pending_id}",
                idempotency_digest=idempotency_digest,
            )
        except ReceiptReplayError:
            return self._denied(
                stored.handle.request_id,
                MCPGatewayReasonCode.HUMAN_APPROVAL_REPLAY.value,
                policy=policy,
                identity=identity,
                arguments=stored.arguments,
            )
        except ReceiptRevokedError:
            return self._denied(
                stored.handle.request_id,
                MCPGatewayReasonCode.HUMAN_APPROVAL_REPLAY.value,
                policy=policy,
                identity=identity,
                arguments=stored.arguments,
            )
        except ReceiptConsumptionError:
            return self._denied(
                stored.handle.request_id,
                MCPGatewayReasonCode.HUMAN_APPROVAL_CONSUMPTION_UNAVAILABLE.value,
                policy=policy,
                identity=identity,
                arguments=stored.arguments,
            )
        try:
            _catalog, credential = self._load_exact_catalog(
                identity,
                required_scopes=frozenset(policy.downstream_scopes),
            )
            request, context = self._build_call(
                identity,
                policy,
                credential_binding=credential.binding_hash,
                transport_binding=self._target_binding(self._origin),
                request_id=stored.handle.request_id,
                arguments=stored.arguments,
                nonce=stored.nonce,
                idempotency_key=stored.idempotency_key,
                requested_at=stored.requested_at,
                observed_at=stored.observed_at,
                evidence=stored.evidence,
                goal=stored.goal,
            )
        except (
            MCPIdentityError,
            MCPOriginError,
            MCPStdioError,
            MCPCatalogError,
            MCPSchemaError,
        ) as exc:
            return self._denied(
                stored.handle.request_id,
                exc.reason_code.value,
                policy=policy,
                identity=identity,
                arguments=stored.arguments,
            )
        except (TypeError, ValueError, RecursionError):
            return self._denied(
                stored.handle.request_id,
                MCPGatewayReasonCode.INVALID_REQUEST.value,
                policy=policy,
                identity=identity,
                arguments=stored.arguments,
            )
        return self._authorize_and_execute(
            request_id=stored.handle.request_id,
            identity=identity,
            policy=policy,
            request=request,
            context=context,
            arguments=stored.arguments,
            credential_binding=credential.binding_hash,
        )

    def _authorize_and_execute(
        self,
        *,
        request_id: str,
        identity: VerifiedMCPIdentity,
        policy: MCPToolPolicy,
        request: SideEffectRequest,
        context: SideEffectExecutionContext,
        arguments: Mapping[str, Any],
        credential_binding: str,
    ) -> MCPGatewayResponse:
        credential_token = self._expected_credential_binding.set(credential_binding)
        transport_token = self._expected_transport_binding.set(self._target_binding(self._origin))
        try:
            with self._principal_context.bind(identity.principal):
                try:
                    authorization = self._authorizer.authorize(request)
                except AuthorizationError as exc:
                    refusal = exc.evidence or self._record_early_refusal(
                        request_id=request_id,
                        reason_code=exc.reason_code.value,
                        policy=policy,
                        identity=identity,
                        arguments=arguments,
                        operation=MCP_TOOLS_CALL_OPERATION,
                        decision=Decision.DENY,
                    )
                    return MCPGatewayResponse(
                        request_id=request_id,
                        decision=Decision.DENY,
                        status=MCPGatewayStatus.DENIED,
                        reason_codes=(exc.reason_code.value,),
                        retryable=False,
                        executed=False,
                        audit_event_id=refusal.audit_event_id,
                        refusal_evidence=refusal,
                    )
                if not authorization.executable:
                    return self._authorization_response(authorization, executed=False)
                try:
                    payload = self._executor.execute(
                        authorization,
                        context,
                        nonce=request.nonce,
                        idempotency_key=request.idempotency_key,
                    )
                except SideEffectExecutionError as exc:
                    return MCPGatewayResponse(
                        request_id=request_id,
                        decision=authorization.decision,
                        status=MCPGatewayStatus.FAILED_CLOSED,
                        reason_codes=(exc.reason_code.value,),
                        retryable=False,
                        executed=False,
                        outcome_unknown=exc.reason_code.value
                        in {
                            "execution.outcome_unknown",
                            "execution.timeout",
                        },
                        receipt=authorization.receipt,
                        audit_event_id=authorization.audit_event_id,
                        approved_arguments=authorization.approved_arguments,
                        execution_refusal_evidence=exc.evidence,
                    )
        finally:
            self._expected_transport_binding.reset(transport_token)
            self._expected_credential_binding.reset(credential_token)
        return MCPGatewayResponse(
            request_id=request_id,
            decision=authorization.decision,
            status=MCPGatewayStatus.SUCCEEDED,
            reason_codes=("execution.succeeded",),
            retryable=False,
            executed=True,
            payload=payload,
            receipt=authorization.receipt,
            audit_event_id=authorization.audit_event_id,
            approved_arguments=authorization.approved_arguments,
        )

    def dispatch(
        self,
        method: str,
        *,
        inbound_token: str,
        session_id: str,
        request_id: str,
        params: Mapping[str, Any],
    ) -> MCPToolListResponse | MCPGatewayResponse:
        """Small transport-neutral dispatcher; every unknown method is denied."""

        safe_request_id = self._safe_request_id(
            request_id,
            method if type(method) is str else "mcp",
        )
        try:
            _require_text(request_id, "request_id")
        except (TypeError, ValueError, RecursionError):
            return self._denied(
                safe_request_id,
                MCPGatewayReasonCode.INVALID_REQUEST.value,
                arguments=params if type(params) is dict else None,
                operation=method if type(method) is str and method else "mcp.method",
            )
        if method == "tools/list":
            if type(params) is not dict or params:
                return self._denied(
                    safe_request_id,
                    MCPGatewayReasonCode.INVALID_REQUEST.value,
                    arguments=params if type(params) is dict else None,
                    operation="tools/list",
                )
            return self.list_tools(
                inbound_token=inbound_token,
                session_id=session_id,
                request_id=safe_request_id,
            )
        if method in MCP_HUMAN_LOOP_METHODS:
            return self._dispatch_human_loop(
                method,
                inbound_token=inbound_token,
                session_id=session_id,
                request_id=safe_request_id,
                params=params,
            )
        if method != MCP_TOOLS_CALL_OPERATION:
            return self._denied(
                safe_request_id,
                MCPGatewayReasonCode.METHOD_DENIED.value,
                arguments=params if type(params) is dict else None,
                operation=method if type(method) is str and method else "mcp.method",
            )
        if type(params) is not dict:
            return self._denied(safe_request_id, MCPGatewayReasonCode.INVALID_REQUEST.value)
        required = {
            "name",
            "arguments",
            "nonce",
            "idempotency_key",
            "requested_at",
            "observed_at",
        }
        optional = {"evidence", "goal"}
        if not required.issubset(params) or not set(params).issubset(required | optional):
            return self._denied(
                safe_request_id,
                MCPGatewayReasonCode.INVALID_REQUEST.value,
                arguments=params,
            )
        raw_evidence = params.get("evidence", ())
        if type(raw_evidence) not in (tuple, list):
            return self._denied(
                safe_request_id,
                MCPGatewayReasonCode.INVALID_REQUEST.value,
                arguments=params,
            )
        evidence = tuple(raw_evidence)
        if any(not isinstance(item, EvidenceRef) for item in evidence):
            return self._denied(
                safe_request_id,
                MCPGatewayReasonCode.INVALID_REQUEST.value,
                arguments=params,
            )
        arguments = params["arguments"]
        if type(arguments) is not dict:
            return self._denied(
                safe_request_id,
                MCPGatewayReasonCode.INVALID_REQUEST.value,
                arguments=params,
            )
        tool_name = params["name"]
        if type(tool_name) is str and tool_name in MCP_HUMAN_LOOP_TOOLS:
            return self._dispatch_human_loop(
                (
                    MCP_TOOLS_APPROVE_OPERATION
                    if tool_name == MCP_APPROVE_TOOL
                    else MCP_TOOLS_RESUME_OPERATION
                ),
                inbound_token=inbound_token,
                session_id=session_id,
                request_id=safe_request_id,
                params=arguments,
            )
        try:
            return self.call_tool(
                inbound_token=inbound_token,
                session_id=session_id,
                request_id=safe_request_id,
                tool_name=cast(str, tool_name),
                arguments=cast(dict[str, Any], arguments),
                nonce=cast(str, params["nonce"]),
                idempotency_key=cast(str, params["idempotency_key"]),
                requested_at=cast(str, params["requested_at"]),
                observed_at=cast(str, params["observed_at"]),
                evidence=cast(tuple[EvidenceRef, ...], evidence),
                goal=cast(str, params.get("goal", "")),
            )
        except (TypeError, ValueError, RecursionError):
            return self._denied(
                safe_request_id,
                MCPGatewayReasonCode.INVALID_REQUEST.value,
                arguments=params,
            )

    def _dispatch_human_loop(
        self,
        method: str,
        *,
        inbound_token: str,
        session_id: str,
        request_id: str,
        params: object,
    ) -> MCPGatewayResponse:
        if type(params) is not dict:
            return self._denied(
                request_id,
                MCPGatewayReasonCode.INVALID_REQUEST.value,
                arguments=None,
                operation=method,
            )
        if set(params) != {"pending_id"}:
            return self._denied(
                request_id,
                MCPGatewayReasonCode.INVALID_REQUEST.value,
                arguments=params,
                operation=method,
            )
        pending_id = params["pending_id"]
        if type(pending_id) is not str or not pending_id.strip():
            return self._denied(
                request_id,
                MCPGatewayReasonCode.INVALID_REQUEST.value,
                arguments=params,
                operation=method,
            )
        if method == MCP_TOOLS_APPROVE_OPERATION:
            return self.approve_pending(
                pending_id=pending_id,
                inbound_token=inbound_token,
                session_id=session_id,
            )
        return self.resume_pending(
            pending_id=pending_id,
            inbound_token=inbound_token,
            session_id=session_id,
        )

    def _load_exact_catalog(
        self,
        identity: VerifiedMCPIdentity,
        *,
        required_scopes: frozenset[str],
    ) -> tuple[tuple[MCPToolDefinition, ...], MCPDownstreamCredential]:
        return self._load_exact_catalog_for_tenant(
            identity.principal.tenant_id,
            required_scopes=required_scopes,
        )

    def _load_exact_catalog_for_tenant(
        self,
        tenant_id: str,
        *,
        required_scopes: frozenset[str],
    ) -> tuple[tuple[MCPToolDefinition, ...], MCPDownstreamCredential]:
        try:
            origin = self._reconcile_target(self._origin)
            credential = self._credential_provider.get_credential(
                origin.server_id,
                tenant_id,
            )
        except (MCPOriginError, MCPStdioError):
            raise
        except Exception:
            raise MCPCatalogError(MCPGatewayReasonCode.DOWNSTREAM_CREDENTIAL_FAILED) from None
        if not isinstance(credential, MCPDownstreamCredential):
            raise MCPCatalogError(MCPGatewayReasonCode.DOWNSTREAM_CREDENTIAL_FAILED)
        credential.validate_for(
            tenant_id=tenant_id,
            server_id=origin.server_id,
            audience=self._config.credential_audience,
            required_scopes=required_scopes,
            now=self._clock(),
        )
        try:
            result = self._transport.list_tools(origin, credential)
        except Exception:
            raise MCPCatalogError(MCPGatewayReasonCode.CATALOG_UNAVAILABLE) from None
        if not isinstance(result, MCPDownstreamToolList):
            raise MCPCatalogError(MCPGatewayReasonCode.CATALOG_UNAVAILABLE)
        self._validate_transport_response(origin, result)
        names = tuple(item.name for item in result.tools)
        if len(names) != len(set(names)):
            raise MCPCatalogError(MCPGatewayReasonCode.CATALOG_COLLISION)
        actual = {item.name: item.digest for item in result.tools}
        expected = {item.definition.name: item.definition.digest for item in self._config.tools}
        if actual != expected:
            raise MCPCatalogError(MCPGatewayReasonCode.CATALOG_MISMATCH)
        return tuple(self._policies[name].definition for name in names), credential

    def _build_call(
        self,
        identity: VerifiedMCPIdentity,
        policy: MCPToolPolicy,
        *,
        credential_binding: str,
        transport_binding: str,
        request_id: str,
        arguments: Mapping[str, Any],
        nonce: str,
        idempotency_key: str,
        requested_at: str,
        observed_at: str,
        evidence: tuple[EvidenceRef, ...],
        goal: str,
    ) -> tuple[SideEffectRequest, SideEffectExecutionContext]:
        policy_ref = ResolvedPolicyRef(
            tenant_id=identity.principal.tenant_id,
            bundle_id=policy.policy_bundle_id,
            version=policy.policy_version,
            digest=policy.policy_digest,
        )
        side_effect_binding = strict_json_hash(
            {
                "schema": "gove-zone.mcp-call-binding.v1",
                "tool_policy": policy.authorization_side_effect_class,
                "credential_binding": _require_digest(
                    credential_binding,
                    "credential_binding",
                ),
                "transport_binding": _require_digest(
                    transport_binding,
                    "transport_binding",
                ),
            }
        )
        request = SideEffectRequest(
            request_id=request_id,
            tenant_id=identity.principal.tenant_id,
            actor_id=identity.principal.actor_id,
            actor_role=identity.principal.role,
            authority=identity.principal.authority,
            server_id=self._origin.server_id,
            tool=policy.definition.name,
            operation=MCP_TOOLS_CALL_OPERATION,
            resource=policy.resource,
            environment=policy.environment,
            execution_boundary=self._config.execution_boundary,
            policy_ref=policy_ref,
            requested_at=requested_at,
            nonce=nonce,
            idempotency_key=idempotency_key,
            args=arguments,
            evidence=evidence,
            side_effect_class=f"mcp-call:{side_effect_binding}",
            goal=goal,
        )
        context = SideEffectExecutionContext(
            request_id=request.request_id,
            tenant_id=request.tenant_id,
            actor_id=request.actor_id,
            actor_role=request.actor_role,
            authority=request.authority,
            server_id=request.server_id,
            tool=request.tool,
            operation=request.operation,
            resource=request.resource,
            environment=request.environment,
            execution_boundary=request.execution_boundary,
            policy_ref=policy_ref,
            observed_at=observed_at,
            authentication_context=identity.principal.authentication_context,
        )
        return request, context

    def _adapter_for(self, policy: MCPToolPolicy) -> Callable[..., AdapterOutcome]:
        def adapter(**arguments: Any) -> AdapterOutcome:
            principal = self._principal_context.resolve()
            expected_credential_binding = self._expected_credential_binding.get()
            expected_transport_binding = self._expected_transport_binding.get()
            if expected_credential_binding is None or expected_transport_binding is None:
                raise RuntimeError(MCPGatewayReasonCode.DOWNSTREAM_CREDENTIAL_MISMATCH.value)
            _validate_arguments(policy.definition.input_schema, arguments)
            # Re-read and pin the exact catalog at the final controllable
            # boundary so schema/description drift after authorization cannot
            # turn the approved name into a different downstream capability.
            _catalog, credential = self._load_exact_catalog_for_tenant(
                principal.tenant_id,
                required_scopes=frozenset(policy.downstream_scopes),
            )
            origin = self._reconcile_target(self._origin)
            if credential.binding_hash != expected_credential_binding:
                raise RuntimeError(MCPGatewayReasonCode.DOWNSTREAM_CREDENTIAL_MISMATCH.value)
            if self._target_binding(origin) != expected_transport_binding:
                raise RuntimeError(MCPGatewayReasonCode.DOWNSTREAM_OUTCOME_UNKNOWN.value)
            result = self._transport.call_tool(
                origin,
                credential,
                policy.definition.name,
                arguments,
            )
            if not isinstance(result, MCPDownstreamToolResult):
                raise RuntimeError(MCPGatewayReasonCode.DOWNSTREAM_OUTCOME_UNKNOWN.value)
            self._validate_transport_response(origin, result)
            if result.status is not AdapterOutcomeStatus.CONFIRMED_SUCCEEDED:
                return AdapterOutcome(AdapterOutcomeStatus.UNKNOWN)
            return AdapterOutcome(AdapterOutcomeStatus.CONFIRMED_SUCCEEDED, result.payload)

        return adapter

    def _reconcile_target(
        self,
        target: ValidatedMCPOrigin | ValidatedMCPStdioTarget,
    ) -> ValidatedMCPOrigin | ValidatedMCPStdioTarget:
        if isinstance(target, ValidatedMCPOrigin):
            if not isinstance(self._origin_validator, MCPOriginValidator):
                raise TypeError("network target requires MCPOriginValidator")
            return self._origin_validator.reconcile(target)
        if not isinstance(self._origin_validator, MCPStdioTargetValidator):
            raise TypeError("stdio target requires MCPStdioTargetValidator")
        return self._origin_validator.revalidate(target)

    @staticmethod
    def _target_binding(
        target: ValidatedMCPOrigin | ValidatedMCPStdioTarget,
    ) -> str:
        if isinstance(target, ValidatedMCPStdioTarget):
            return target.transport_binding
        return strict_json_hash(
            {
                "schema": "gove-zone.mcp-network-target.v1",
                "server_id": target.server_id,
                "url": target.url,
                "hostname": target.hostname,
                "port": target.port,
                "pinned_addresses": list(target.pinned_addresses),
            }
        )

    def _validate_transport_response(
        self,
        target: ValidatedMCPOrigin | ValidatedMCPStdioTarget,
        result: MCPDownstreamToolList | MCPDownstreamToolResult,
    ) -> None:
        if isinstance(target, ValidatedMCPOrigin):
            if not isinstance(self._origin_validator, MCPOriginValidator):
                raise TypeError("network target requires MCPOriginValidator")
            self._origin_validator.validate_response(
                target,
                response_origin=result.response_origin,
                redirect_url=result.redirect_url,
                peer_address=result.peer_address,
            )
            return
        if not isinstance(self._origin_validator, MCPStdioTargetValidator):
            raise TypeError("stdio target requires MCPStdioTargetValidator")
        self._origin_validator.validate_response(
            target,
            transport_binding=result.transport_binding,
        )

    @staticmethod
    def _authorization_response(
        authorization: SideEffectAuthorization,
        *,
        executed: bool,
    ) -> MCPGatewayResponse:
        status = (
            MCPGatewayStatus.ESCALATED
            if authorization.decision is Decision.ESCALATE
            else MCPGatewayStatus.DENIED
        )
        return MCPGatewayResponse(
            request_id=authorization.request_id,
            decision=authorization.decision,
            status=status,
            reason_codes=tuple(code.value for code in authorization.reason_codes),
            retryable=False,
            executed=executed,
            receipt=authorization.receipt,
            audit_event_id=authorization.audit_event_id,
            approved_arguments=authorization.approved_arguments,
        )

    def _denied(
        self,
        request_id: str,
        reason_code: str,
        *,
        policy: MCPToolPolicy | None = None,
        identity: VerifiedMCPIdentity | None = None,
        arguments: Mapping[str, Any] | None = None,
        operation: str = MCP_TOOLS_CALL_OPERATION,
        decision: Decision = Decision.DENY,
        pending_approval: MCPPendingApproval | None = None,
    ) -> MCPGatewayResponse:
        evidence = self._record_early_refusal(
            request_id=request_id,
            reason_code=reason_code,
            policy=policy,
            identity=identity,
            arguments=arguments,
            operation=operation,
            decision=decision,
        )
        return MCPGatewayResponse(
            request_id=request_id,
            decision=decision,
            status=(
                MCPGatewayStatus.ESCALATED
                if decision is Decision.ESCALATE
                else MCPGatewayStatus.DENIED
            ),
            reason_codes=(reason_code,),
            retryable=False,
            executed=False,
            audit_event_id=evidence.audit_event_id,
            refusal_evidence=evidence,
            pending_approval=pending_approval,
        )

    def _denied_list(
        self,
        request_id: str,
        reason_code: str,
        *,
        identity: VerifiedMCPIdentity | None = None,
    ) -> MCPToolListResponse:
        evidence = self._record_early_refusal(
            request_id=request_id,
            reason_code=reason_code,
            policy=None,
            identity=identity,
            arguments=None,
            operation="tools/list",
            decision=Decision.DENY,
        )
        return MCPToolListResponse(
            request_id=request_id,
            decision=Decision.DENY,
            status=MCPGatewayStatus.DENIED,
            reason_codes=(reason_code,),
            audit_event_id=evidence.audit_event_id,
            refusal_evidence=evidence,
        )

    def _record_early_refusal(
        self,
        *,
        request_id: str,
        reason_code: str,
        policy: MCPToolPolicy | None,
        identity: VerifiedMCPIdentity | None,
        arguments: Mapping[str, Any] | None,
        operation: str,
        decision: Decision,
    ) -> RefusalEvidence:
        fingerprint = strict_json_hash(
            {
                "schema": "gove-zone.mcp-early-refusal.v1",
                "request_id": request_id,
                "reason_code": reason_code,
                "operation": operation,
            }
        )
        tenant_id = (
            identity.principal.tenant_id
            if identity is not None
            else f"unverified-tenant-{fingerprint[:16]}"
        )
        actor_id = (
            identity.principal.actor_id
            if identity is not None
            else f"unverified-actor-{fingerprint[:16]}"
        )
        try:
            argument_hash = strict_json_hash(
                _plain_mapping(arguments) if arguments is not None else {}
            )
        except (TypeError, ValueError, RecursionError):
            argument_hash = strict_json_hash({"malformed_mcp_arguments": True})
        if decision is Decision.ESCALATE:
            authorization_reason = AuthorizationReasonCode.ESCALATED
        elif reason_code.startswith("mcp.identity."):
            authorization_reason = AuthorizationReasonCode.PRINCIPAL_RESOLUTION_FAILED
        elif reason_code.startswith(
            ("mcp.origin.", "mcp.stdio.", "mcp.gateway.catalog", "mcp.gateway.downstream")
        ):
            authorization_reason = AuthorizationReasonCode.INTERNAL_FAILURE
        else:
            authorization_reason = AuthorizationReasonCode.INVALID_REQUEST
        return self._authorizer.record_refusal(
            request_id=request_id,
            reason_code=authorization_reason,
            decision=decision,
            exact_reason_codes=(reason_code,),
            claimed_tenant_id=tenant_id,
            claimed_actor_id=actor_id,
            operation=operation,
            argument_hash=argument_hash,
            policy_digest=(
                policy.policy_digest if policy is not None else self._gateway_refusal_digest
            ),
            policy_version=policy.policy_version if policy is not None else "mcp-gateway/v1",
            principal_verified=identity is not None,
            goal_claim=f"sha256:{fingerprint}",
        )

    @staticmethod
    def _safe_request_id(value: object, operation: str) -> str:
        try:
            return _require_text(value, "request_id")
        except (TypeError, ValueError, RecursionError):
            fingerprint = strict_json_hash(
                {
                    "schema": "gove-zone.mcp-malformed-request-id.v1",
                    "operation": operation if type(operation) is str and operation else "mcp",
                    "input_type": type(value).__name__,
                }
            )
            return f"mcp-invalid-request-{fingerprint[:20]}"


__all__ = [
    "MCPCatalogError",
    "MCPActionGateway",
    "MCPPendingApproval",
    "MCPDownstreamCredential",
    "MCPDownstreamCredentialProvider",
    "MCPDownstreamToolList",
    "MCPDownstreamToolResult",
    "MCPDownstreamTransport",
    "MCPEscalationPolicy",
    "MCPGatewayConfig",
    "MCPGatewayReasonCode",
    "MCPGatewayResponse",
    "MCPGatewayStatus",
    "MCPRiskClass",
    "MCPSchemaError",
    "MCPToolDefinition",
    "MCPToolListResponse",
    "MCPToolPolicy",
    "MCP_APPROVE_TOOL",
    "MCP_GATEWAY_EXECUTION_BOUNDARY",
    "MCP_RESUME_TOOL",
    "MCP_TOOLS_APPROVE_AUTHORITY",
    "MCP_TOOLS_APPROVE_OPERATION",
    "MCP_TOOLS_CALL_OPERATION",
    "MCP_TOOLS_RESUME_OPERATION",
]
