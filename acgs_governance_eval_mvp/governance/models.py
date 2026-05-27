from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

# 5-state decision domain. Today only "allow" and "deny" are produced by the
# runtime; "require_human", "rewrite", and "redact" are reserved for
# follow-up gates that need a richer return shape than a single bool.
# DecisionRecord.decision_state holds this; DecisionRecord.allow stays as a
# back-compat boolean = (decision_state == "allow").
DecisionState = Literal["allow", "deny", "require_human", "rewrite", "redact"]
EvaluationPolicy = Literal["initiation-time", "access-time", "completion-time"]

DECISION_SCHEMA_VERSION = "v1"
AUTHORIZATION_TRACE_SCHEMA_VERSION = "v1"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Principal:
    id: str
    role: str
    tenant: str = "default"
    scopes: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Principal:
        return cls(
            id=str(data["id"]),
            role=str(data["role"]),
            tenant=str(data.get("tenant", "default")),
            scopes=list(data.get("scopes", [])),
            attributes=dict(data.get("attributes", {})),
        )


@dataclass(frozen=True)
class ActionRequest:
    action_type: str
    resource: str
    actor: Principal
    intent: str
    inputs_hash: str
    tenant: str = "default"
    event_id: str = field(default_factory=lambda: str(uuid4()))
    amount_cents: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    # Raw tool input for the action being validated. Required by guard() so
    # execution can be bound to the validated input (TOCTOU defense). When
    # provided without an explicit inputs_hash, from_dict() derives the hash.
    tool_input: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ActionRequest:
        actor = data.get("actor")
        if isinstance(actor, Principal):
            principal = actor
        elif isinstance(actor, dict):
            principal = Principal.from_dict(actor)
        else:
            raise ValueError("ActionRequest.actor must be a Principal or dict")

        tool_input = data.get("tool_input")
        if isinstance(tool_input, dict):
            tool_input = dict(tool_input)
        elif tool_input is None:
            pass
        else:
            raise ValueError("ActionRequest.tool_input must be a dict or None")

        inputs_hash = str(data.get("inputs_hash", ""))
        if not inputs_hash and tool_input is not None:
            inputs_hash = sha256_json(tool_input)

        return cls(
            event_id=str(data.get("event_id") or uuid4()),
            tenant=str(data.get("tenant", principal.tenant)),
            intent=str(data.get("intent", "")),
            action_type=str(data["action_type"]),
            resource=str(data["resource"]),
            inputs_hash=inputs_hash,
            actor=principal,
            amount_cents=data.get("amount_cents"),
            metadata=dict(data.get("metadata", {})),
            tool_input=tool_input,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class GateResult:
    gate: str
    allowed: bool
    reason_codes: list[str]
    reasons: list[str]
    rule_ids: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    latency_ms: float | None = None
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DecisionRecord:
    event_id: str
    tenant: str
    allow: bool
    reasons: list[str]
    reason_codes: list[str]
    rule_ids: list[str]
    checks: list[GateResult]
    request: ActionRequest
    policy_version: str
    role_version: str
    timestamp: str = field(default_factory=utc_now_iso)
    previous_hash: str | None = None
    event_hash: str | None = None
    # 5-state decision: "allow" | "deny" | "require_human" | "rewrite" | "redact".
    # Today validate() only emits "allow"/"deny"; the others are reserved for
    # follow-up gates and are accepted by the schema so events written by
    # future versions remain replay-compatible with this version.
    decision_state: DecisionState = "deny"
    # Validated input bound to the decision. For "allow", equals
    # request.tool_input. For "rewrite", is the rewriter's output. guard()
    # invokes the executor with this value, NOT with arbitrary caller args.
    effective_tool_input: dict[str, Any] | None = None
    # Hash of the policy/role bundles used to make this decision. replay
    # compares against the bundle the caller supplies; mismatch → policy drift.
    policy_bundle_hash: str = ""
    role_bundle_hash: str = ""
    decision_schema_version: str = DECISION_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["checks"] = [check.to_dict() if isinstance(check, GateResult) else check for check in self.checks]
        data["request"] = self.request.to_dict() if isinstance(self.request, ActionRequest) else self.request
        return data

    def canonical_payload_for_hash(self) -> dict[str, Any]:
        payload = self.to_dict()
        payload.pop("event_hash", None)
        return payload


class GovernanceDeniedError(PermissionError):
    """Raised by GovernedToolAdapter.guard() when a decision denies. Carries the full DecisionRecord."""

    def __init__(self, decision: DecisionRecord):
        super().__init__("; ".join(decision.reasons))
        self.decision = decision


class AuthorizationTraceIntegrityError(ValueError):
    """Raised when an authorization trace fails receipt or hash validation."""


@dataclass(frozen=True)
class AuthorizationTrace:
    trace_id: str
    workflow_id: str
    parent_workflow_id: str | None
    principal_chain: tuple[dict[str, str], ...]
    evaluation_policy: EvaluationPolicy
    schema_version: str = AUTHORIZATION_TRACE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != AUTHORIZATION_TRACE_SCHEMA_VERSION:
            raise ValueError("AuthorizationTrace.schema_version must be v1")
        if self.evaluation_policy not in ("initiation-time", "access-time", "completion-time"):
            raise ValueError("AuthorizationTrace.evaluation_policy is not supported")
        if not self.trace_id:
            raise ValueError("AuthorizationTrace.trace_id is required")
        if not self.workflow_id:
            raise ValueError("AuthorizationTrace.workflow_id is required")
        if self.parent_workflow_id is not None and not self.parent_workflow_id:
            raise ValueError("AuthorizationTrace.parent_workflow_id must be non-empty or None")
        if not self.principal_chain:
            raise ValueError("AuthorizationTrace.principal_chain must not be empty")

        normalized: list[dict[str, str]] = []
        required = ("principal_id", "role", "tenant", "delegated_at", "delegation_evidence_hash")
        for entry in self.principal_chain:
            item = {key: str(entry[key]) for key in required}
            if any(not item[key] for key in required):
                raise ValueError("AuthorizationTrace.principal_chain entries must be non-empty")
            normalized.append(item)
        object.__setattr__(self, "principal_chain", tuple(normalized))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthorizationTrace:
        workflow_scope = data.get("workflow_scope")
        receipt = data.get("receipt")
        if not isinstance(workflow_scope, dict) or not isinstance(receipt, dict):
            raise ValueError("AuthorizationTrace wire format requires workflow_scope and receipt objects")

        workflow_id = workflow_scope.get("workflow_id")
        parent_workflow_id = workflow_scope.get("parent_workflow_id")
        principal_chain = workflow_scope.get("principal_chain")
        trace_id = receipt.get("trace_id")
        schema_version = receipt.get("schema_version", AUTHORIZATION_TRACE_SCHEMA_VERSION)
        persisted_trace_hash = receipt.get("trace_hash")
        if persisted_trace_hash is None:
            raise AuthorizationTraceIntegrityError("AuthorizationTrace.receipt.trace_hash is required")

        if not isinstance(principal_chain, list | tuple):
            raise ValueError("AuthorizationTrace.principal_chain must be a list")

        trace = cls(
            trace_id=str(trace_id),
            workflow_id=str(workflow_id),
            parent_workflow_id=None if parent_workflow_id is None else str(parent_workflow_id),
            principal_chain=tuple(dict(item) for item in principal_chain),
            evaluation_policy=data["evaluation_policy"],
            schema_version=str(schema_version),
        )
        if str(persisted_trace_hash) != trace.trace_hash():
            raise AuthorizationTraceIntegrityError("AuthorizationTrace.receipt.trace_hash does not match trace payload")
        return trace

    @property
    def trace_hash_value(self) -> str:
        return self.trace_hash()

    def payload_for_hash(self) -> dict[str, Any]:
        return {
            "workflow_scope": {
                "workflow_id": self.workflow_id,
                "parent_workflow_id": self.parent_workflow_id,
                "principal_chain": [dict(entry) for entry in self.principal_chain],
            },
            "evaluation_policy": self.evaluation_policy,
            "receipt": {
                "trace_id": self.trace_id,
                "schema_version": self.schema_version,
            },
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self.payload_for_hash()
        payload["receipt"] = {
            "trace_hash": self.trace_hash(),
            "audit_event_hash": "0" * 64,
            "trace_id": self.trace_id,
            "schema_version": self.schema_version,
        }
        return payload

    def canonical_json(self) -> str:
        return stable_json(self.payload_for_hash())

    def trace_hash(self) -> str:
        return sha256_json(self.payload_for_hash())


@dataclass(frozen=True)
class DecisionReceiptRef:
    receipt_hash: str
    audit_event_hash: str
    trace_id: str
    schema_version: str = AUTHORIZATION_TRACE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != AUTHORIZATION_TRACE_SCHEMA_VERSION:
            raise ValueError("DecisionReceiptRef.schema_version must be v1")
        for field_name in ("receipt_hash", "audit_event_hash", "trace_id"):
            if not getattr(self, field_name):
                raise ValueError(f"DecisionReceiptRef.{field_name} is required")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DecisionReceiptRef:
        return cls(
            receipt_hash=str(data["receipt_hash"]),
            audit_event_hash=str(data["audit_event_hash"]),
            trace_id=str(data["trace_id"]),
            schema_version=str(data.get("schema_version", AUTHORIZATION_TRACE_SCHEMA_VERSION)),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
