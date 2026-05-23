from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal
from uuid import uuid4

if TYPE_CHECKING:
    from governance.crypto.principal_keys import PrincipalKeyStore

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
    return datetime.now(UTC).isoformat()


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


class LegacyUnsignedTraceError(AuthorizationTraceIntegrityError):
    """Raised by from_dict when the wire payload is Phase-1-shaped.

    Phase 2 requires per-hop delegation signatures + action_binding +
    hop_signatures_version. A payload that lacks them entirely is a
    legacy unsigned trace; we reject it explicitly so callers can
    discriminate "untrusted wire" from "Phase 2 with a forged sig".
    """


# Phase 2 hop signed-payload schema version. Tracks the
# DOMAIN_TAG_HOP byte tag in governance.crypto.hop_signature.
HOP_SIGNATURES_VERSION = "phase2-hop-v2"

# Required Phase 2 fields on every principal_chain wire entry.
_PHASE2_HOP_REQUIRED = (
    "principal_id",
    "role",
    "tenant",
    "delegated_at",
    "delegation_evidence_hash",
    "delegator_id",
    "signing_key_id",
    "signature",
    "not_after",
)

# action_binding required keys, see docs/design/phase2-trace-crypto.md
# §action binding v2.
_ACTION_BINDING_REQUIRED = (
    "action_type",
    "tenant",
    "actor_id",
    "resource",
    "inputs_hash",
    "workflow_id",
    "policy_version",
    "role_version",
    "session_nonce",
)

_ORCHESTRATOR_ROOT_PRINCIPAL = "orchestrator-root"


@dataclass(frozen=True)
class AuthorizationTrace:
    trace_id: str
    workflow_id: str
    parent_workflow_id: str | None
    principal_chain: tuple[dict[str, str], ...]
    evaluation_policy: EvaluationPolicy
    action_binding: dict[str, str]
    hop_signatures_version: str = HOP_SIGNATURES_VERSION
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
        if self.hop_signatures_version != HOP_SIGNATURES_VERSION:
            raise ValueError(f"AuthorizationTrace.hop_signatures_version must be {HOP_SIGNATURES_VERSION!r}")

        if not isinstance(self.action_binding, dict):
            raise ValueError("AuthorizationTrace.action_binding must be a dict")
        missing_ab = [k for k in _ACTION_BINDING_REQUIRED if k not in self.action_binding]
        if missing_ab:
            raise ValueError(f"AuthorizationTrace.action_binding missing required fields: {missing_ab}")
        normalized_ab: dict[str, str] = {}
        for key in _ACTION_BINDING_REQUIRED:
            value = self.action_binding[key]
            if not isinstance(value, str) or not value:
                raise ValueError(f"AuthorizationTrace.action_binding[{key!r}] must be a non-empty string")
            normalized_ab[key] = value
        object.__setattr__(self, "action_binding", normalized_ab)

        normalized: list[dict[str, str]] = []
        for entry in self.principal_chain:
            item = {key: str(entry[key]) for key in _PHASE2_HOP_REQUIRED}
            if any(not item[key] for key in _PHASE2_HOP_REQUIRED):
                raise ValueError("AuthorizationTrace.principal_chain entries must be non-empty")
            normalized.append(item)
        object.__setattr__(self, "principal_chain", tuple(normalized))

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        *,
        key_store: PrincipalKeyStore | None = None,
        now: datetime | None = None,
    ) -> AuthorizationTrace:
        """Parse + validate a wire-format authorization trace.

        When ``key_store`` is provided, every hop is verified against its
        resolved :class:`KeyEntry` (Ed25519 signature, identity binding,
        tenant binding, purpose, validity window, revocation, expiry,
        TTL bound — see ``governance.crypto.hop_verify``).

        When ``key_store`` is ``None``, signature bytes are not verified
        against any key, but the wire payload MUST still carry the
        Phase 2 fields (per-hop signature/signing_key_id/delegator_id/
        not_after, action_binding, hop_signatures_version). A Phase 1
        unsigned payload raises :class:`LegacyUnsignedTraceError`.
        Because ``receipt.trace_hash`` covers the signature bytes,
        tamper detection still survives the no-key-store call path —
        this is the contract the chain-replay (``ChainHashAuditStore``)
        relies on.
        """
        workflow_scope = data.get("workflow_scope")
        receipt = data.get("receipt")
        if not isinstance(workflow_scope, dict) or not isinstance(receipt, dict):
            raise ValueError("AuthorizationTrace wire format requires workflow_scope and receipt objects")

        workflow_id = workflow_scope.get("workflow_id")
        parent_workflow_id = workflow_scope.get("parent_workflow_id")
        principal_chain = workflow_scope.get("principal_chain")
        action_binding = workflow_scope.get("action_binding")
        hop_signatures_version = workflow_scope.get("hop_signatures_version")
        trace_id = receipt.get("trace_id")
        schema_version = receipt.get("schema_version", AUTHORIZATION_TRACE_SCHEMA_VERSION)
        persisted_trace_hash = receipt.get("trace_hash")
        if persisted_trace_hash is None:
            raise AuthorizationTraceIntegrityError("AuthorizationTrace.receipt.trace_hash is required")

        if not isinstance(principal_chain, list | tuple):
            raise ValueError("AuthorizationTrace.principal_chain must be a list")

        # Phase 2 field presence check — distinguishes legacy unsigned
        # traces (Phase 1 shape) from Phase 2 wire payloads. We treat
        # the absence of action_binding + per-hop signature as the
        # canonical legacy signal.
        if action_binding is None and hop_signatures_version is None:
            chain_lacks_sigs = all(isinstance(entry, dict) and "signature" not in entry for entry in principal_chain)
            if chain_lacks_sigs:
                raise LegacyUnsignedTraceError(
                    "AuthorizationTrace wire payload is Phase 1 unsigned shape; "
                    "Phase 2 requires per-hop signatures, action_binding, and "
                    "hop_signatures_version"
                )

        if action_binding is None:
            raise AuthorizationTraceIntegrityError("AuthorizationTrace.workflow_scope.action_binding is required")
        if hop_signatures_version is None:
            raise AuthorizationTraceIntegrityError(
                "AuthorizationTrace.workflow_scope.hop_signatures_version is required"
            )

        trace = cls(
            trace_id=str(trace_id),
            workflow_id=str(workflow_id),
            parent_workflow_id=None if parent_workflow_id is None else str(parent_workflow_id),
            principal_chain=tuple(dict(item) for item in principal_chain),
            evaluation_policy=data["evaluation_policy"],
            action_binding=dict(action_binding),
            hop_signatures_version=str(hop_signatures_version),
            schema_version=str(schema_version),
        )
        if str(persisted_trace_hash) != trace.trace_hash():
            raise AuthorizationTraceIntegrityError("AuthorizationTrace.receipt.trace_hash does not match trace payload")

        # Chain continuity invariants (apply regardless of key_store).
        seen_principals: set[str] = set()
        seen_hop_indices: set[int] = set()
        for index, entry in enumerate(trace.principal_chain):
            delegator_id = entry["delegator_id"]
            if index == 0:
                if delegator_id != _ORCHESTRATOR_ROOT_PRINCIPAL:
                    raise AuthorizationTraceIntegrityError(
                        f"AuthorizationTrace.principal_chain[0].delegator_id must be "
                        f"{_ORCHESTRATOR_ROOT_PRINCIPAL!r}, got {delegator_id!r}"
                    )
            else:
                prev_principal = trace.principal_chain[index - 1]["principal_id"]
                if delegator_id != prev_principal:
                    raise AuthorizationTraceIntegrityError(
                        f"AuthorizationTrace.principal_chain[{index}].delegator_id "
                        f"{delegator_id!r} does not match prior hop's principal_id "
                        f"{prev_principal!r}"
                    )
            if entry["principal_id"] in seen_principals:
                raise AuthorizationTraceIntegrityError(
                    f"AuthorizationTrace.principal_chain contains duplicate principal_id {entry['principal_id']!r}"
                )
            seen_principals.add(entry["principal_id"])
            if index in seen_hop_indices:
                raise AuthorizationTraceIntegrityError(
                    f"AuthorizationTrace.principal_chain has duplicate hop_index {index}"
                )
            seen_hop_indices.add(index)

        if key_store is not None:
            trace._verify_signatures(key_store=key_store, now=now)

        return trace

    def _verify_signatures(
        self,
        *,
        key_store: PrincipalKeyStore,
        now: datetime | None = None,
    ) -> None:
        """Verify every hop's Ed25519 signature against its KeyEntry.

        Wraps the lower-level :mod:`governance.crypto.hop_verify` errors
        into :class:`AuthorizationTraceIntegrityError` so callers have a
        single exception type to catch.
        """
        # Local imports keep the crypto deps optional at import time —
        # only loaded when a key_store is provided.
        from governance.crypto.canonical import CanonicalizationError
        from governance.crypto.hop_verify import (
            HopVerificationError,
            verify_hop_against_entry,
        )
        from governance.crypto.principal_keys import UnknownSigningKeyError

        for index, entry in enumerate(self.principal_chain):
            hop_payload = self._hop_signed_payload(index, entry)
            try:
                signature = base64.urlsafe_b64decode(_pad_b64(entry["signature"]))
            except (ValueError, base64.binascii.Error) as exc:
                raise AuthorizationTraceIntegrityError(f"hop {index} signature is not valid base64url") from exc
            try:
                key_entry = key_store.get(entry["signing_key_id"])
            except UnknownSigningKeyError as exc:
                raise AuthorizationTraceIntegrityError(
                    f"hop {index} references unknown signing_key_id {entry['signing_key_id']!r}"
                ) from exc
            try:
                verify_hop_against_entry(hop_payload, signature, key_entry, now=now)
            except CanonicalizationError as exc:
                raise AuthorizationTraceIntegrityError(f"hop {index} contains non-canonicalizable payload") from exc
            except HopVerificationError as exc:
                raise AuthorizationTraceIntegrityError(f"hop {index} signature verification failed: {exc}") from exc

    def _hop_signed_payload(self, index: int, entry: dict[str, str]) -> dict[str, Any]:
        """Reconstruct the canonical hop_payload that was signed.

        See docs/design/phase2-trace-crypto.md §per-hop signed payload (v2).
        """
        return {
            "alg": "Ed25519",
            "key_version": 1,
            "schema_version": HOP_SIGNATURES_VERSION,
            "trace_id": self.trace_id,
            "parent_workflow_id": self.parent_workflow_id,
            "workflow_id": self.workflow_id,
            "evaluation_policy": self.evaluation_policy,
            "hop_index": index,
            "delegator_id": entry["delegator_id"],
            "delegatee_id": entry["principal_id"],
            "role": entry["role"],
            "tenant": entry["tenant"],
            "delegated_at": entry["delegated_at"],
            "not_after": entry["not_after"],
            "delegation_evidence_hash": entry["delegation_evidence_hash"],
            "action_binding": dict(self.action_binding),
        }

    @property
    def trace_hash_value(self) -> str:
        return self.trace_hash()

    def payload_for_hash(self) -> dict[str, Any]:
        return {
            "workflow_scope": {
                "workflow_id": self.workflow_id,
                "parent_workflow_id": self.parent_workflow_id,
                "principal_chain": [dict(entry) for entry in self.principal_chain],
                "action_binding": dict(self.action_binding),
                "hop_signatures_version": self.hop_signatures_version,
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


def _pad_b64(value: str) -> str:
    """Restore base64url padding (urlsafe_b64decode requires it)."""
    padding = (-len(value)) % 4
    return value + ("=" * padding)


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
