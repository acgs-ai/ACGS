"""Immutable contracts for unified side-effect authorization.

The contracts reuse the repository's existing DecisionReceipt and argument
hash. They intentionally accept a strict, cross-language-safe subset of JSON
rather than introducing a second canonical argument representation.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol, TypeAlias, cast, runtime_checkable

from gove_zone.decision import Decision, canonical_json, sha256_json
from gove_zone.policy import Policy
from gove_zone.receipt import DecisionReceipt, Validator

SIDE_EFFECT_BINDING_KEY = "_acgs_side_effect_v2"
RESERVED_SIDE_EFFECT_KEY = SIDE_EFFECT_BINDING_KEY
ARGUMENT_CANONICALIZATION_PROFILE = "gove-zone.sha256-json.finite-number-v1"
ARGUMENT_CANONICALIZATION_IS_RFC8785 = False
ARGUMENT_CANONICALIZATION_LIMITATIONS = (
    "Repository canonical_json encoding, UTF-8, sorted object keys, no Unicode "
    "normalization, arbitrary Python integers, and Python JSON finite-float "
    "rendering. Integrations must reproduce this encoder; this is not RFC 8785."
)
SECRET_DIGEST_PROFILE = "tenant-domain-hmac-sha256-v1"  # noqa: S105 - profile identifier
# v2 is intentionally incompatible with v1: v1 signed only a coarse generic
# authorization category and implicitly treated every audit event as DENY.
# v2 additionally commits the actual non-executable decision and exact
# protocol reasons.  There is no v1 deserializer in this package, so accepting
# a v1 payload as v2 would be a silent security downgrade.
REFUSAL_EVIDENCE_SCHEMA = "gove-zone.side-effect-refusal.v2"
# Deliberately a distinct schema from REFUSAL_EVIDENCE_SCHEMA. Authorization
# refusal and execution refusal answer different questions ("may this be
# authorized?" vs "did this bound attempt reach an adapter?") and bind different
# material, so they must never be interchangeable on the wire or in an audit.
EXECUTION_REFUSAL_EVIDENCE_SCHEMA = "gove-zone.side-effect-execution-refusal.v1"
MINIMUM_HMAC_KEY_BYTES = 32

# Iterative pre-canonicalization budget used by untrusted protocol adapters.
# These conservative limits are deliberately separate from the repository's
# historical canonical JSON profile: callers opt in before any recursive copy,
# freeze, thaw, schema walk, or hash operation.
STRICT_JSON_MAX_DEPTH = 16
STRICT_JSON_MAX_NODES = 4_096
STRICT_JSON_MAX_CONTAINER_ITEMS = 4_096
STRICT_JSON_MAX_CONTAINER_LENGTH = 1_024
STRICT_JSON_MAX_TOTAL_UTF8_BYTES = 65_536
STRICT_JSON_MAX_STRING_UTF8_BYTES = 65_536
STRICT_JSON_MAX_KEY_UTF8_BYTES = 1_024

_NONCE_HMAC_DOMAIN = b"gove-zone:side-effect:nonce-hmac:v1\x00"
_IDEMPOTENCY_HMAC_DOMAIN = b"gove-zone:side-effect:idempotency-hmac:v1\x00"
_GOAL_HASH_DOMAIN = b"gove-zone:side-effect:goal:v1\x00"
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_REFUSAL_REASON_RE = re.compile(r"[a-z][a-z0-9_.:-]{0,255}\Z")

RESERVED_BINDING_REQUIRED_KEYS = frozenset(
    {
        "schema",
        "argument_canonicalization_profile",
        "secret_digest_profile",
        "request_id",
        "tenant_id",
        "actor_id",
        "actor_role",
        "authority",
        "server_id",
        "tool",
        "operation",
        "resource",
        "environment",
        "execution_boundary",
        "side_effect_class",
        "goal_hash",
        "authorized_at",
        "policy",
        "policy_attestation",
        "audit_checkpoint",
        "requested_at",
        "expires_at",
        "principal_verified_at",
        "principal_expires_at",
        "nonce_digest",
        "idempotency_digest",
        "evidence_identifiers",
        "evidence_digest",
        "original_arguments_hash",
        "approved_arguments_hash",
        "validator_id",
        "validator_role",
        "authentication_context_hash",
        "decision",
    }
)
RESERVED_POLICY_REQUIRED_KEYS = frozenset({"tenant_id", "bundle_id", "version", "digest"})
RESERVED_POLICY_ATTESTATION_REQUIRED_KEYS = frozenset(
    {"tenant_id", "artifact_id", "policy_version", "digest", "resolver_id"}
)
RESERVED_AUDIT_CHECKPOINT_REQUIRED_KEYS = frozenset(
    {
        "namespace",
        "generation",
        "head_hash",
        "previous_checkpoint_hash",
        "checkpoint_hash",
        "key_id",
        "algorithm",
        "signature",
    }
)
EVIDENCE_IDENTIFIER_REQUIRED_KEYS = frozenset({"evidence_id", "evidence_type", "issuer"})

JSONScalar: TypeAlias = None | bool | int | float | str
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]
FrozenJSONValue: TypeAlias = (
    JSONScalar | tuple["FrozenJSONValue", ...] | Mapping[str, "FrozenJSONValue"]
)


class StrictJSONBudgetError(ValueError):
    """An untrusted JSON value exceeded the iterative safety profile."""


def validate_strict_json_budget(value: Any) -> None:
    """Validate strict JSON iteratively before recursive canonicalization.

    Both mutable JSON containers and the package's frozen ``tuple`` /
    ``MappingProxyType`` representation are accepted. Cyclic or aliased
    containers are rejected conservatively because JSON has tree semantics.
    """

    stack: list[tuple[Any, int]] = [(value, 0)]
    seen_containers: set[int] = set()
    total_nodes = 0
    total_container_items = 0
    total_utf8_bytes = 0

    while stack:
        current, depth = stack.pop()
        total_nodes += 1
        if total_nodes > STRICT_JSON_MAX_NODES:
            raise StrictJSONBudgetError("strict JSON node budget exceeded")
        if depth > STRICT_JSON_MAX_DEPTH:
            raise StrictJSONBudgetError("strict JSON depth budget exceeded")

        current_type = type(current)
        if current is None or current_type in (bool, int):
            continue
        if current_type is float:
            if not math.isfinite(cast(float, current)):
                raise StrictJSONBudgetError("strict JSON requires finite numbers")
            continue
        if current_type is str:
            try:
                length = len(cast(str, current).encode("utf-8"))
            except UnicodeEncodeError:
                raise StrictJSONBudgetError("strict JSON string is not valid UTF-8") from None
            if length > STRICT_JSON_MAX_STRING_UTF8_BYTES:
                raise StrictJSONBudgetError("strict JSON string budget exceeded")
            total_utf8_bytes += length
            if total_utf8_bytes > STRICT_JSON_MAX_TOTAL_UTF8_BYTES:
                raise StrictJSONBudgetError("strict JSON UTF-8 budget exceeded")
            continue

        is_object = current_type is dict or isinstance(current, MappingProxyType)
        is_array = current_type in (list, tuple)
        if not is_object and not is_array:
            raise StrictJSONBudgetError("value is outside the strict JSON profile")

        identity = id(current)
        if identity in seen_containers:
            raise StrictJSONBudgetError("cyclic or aliased JSON containers are forbidden")
        seen_containers.add(identity)
        length = len(current)
        if length > STRICT_JSON_MAX_CONTAINER_LENGTH:
            raise StrictJSONBudgetError("strict JSON container length exceeded")
        total_container_items += length
        if total_container_items > STRICT_JSON_MAX_CONTAINER_ITEMS:
            raise StrictJSONBudgetError("strict JSON container item budget exceeded")

        if is_object:
            try:
                items = tuple(cast(Mapping[Any, Any], current).items())
            except RuntimeError:
                raise StrictJSONBudgetError(
                    "strict JSON object mutated during validation"
                ) from None
            for key, item in items:
                if type(key) is not str:
                    raise StrictJSONBudgetError("strict JSON object keys must be strings")
                try:
                    key_length = len(key.encode("utf-8"))
                except UnicodeEncodeError:
                    raise StrictJSONBudgetError(
                        "strict JSON object key is not valid UTF-8"
                    ) from None
                if key_length > STRICT_JSON_MAX_KEY_UTF8_BYTES:
                    raise StrictJSONBudgetError("strict JSON key budget exceeded")
                total_utf8_bytes += key_length
                if total_utf8_bytes > STRICT_JSON_MAX_TOTAL_UTF8_BYTES:
                    raise StrictJSONBudgetError("strict JSON UTF-8 budget exceeded")
                stack.append((item, depth + 1))
        else:
            stack.extend((item, depth + 1) for item in cast(Sequence[Any], current))


def _require_text(value: Any, field_name: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str:
        raise TypeError(f"{field_name} must be a string")
    if not allow_empty and not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{field_name} must be valid UTF-8") from None
    return value


def _require_sha256(value: Any, field_name: str) -> str:
    text = _require_text(value, field_name)
    if _SHA256_RE.fullmatch(text) is None:
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return text


def _copy_strict_json(value: Any) -> JSONValue:
    value_type = type(value)
    if value is None:
        return None
    if value_type is bool:
        return cast(bool, value)
    if value_type is int:
        return cast(int, value)
    if value_type is float:
        number = cast(float, value)
        if not math.isfinite(number):
            raise ValueError("strict JSON does not permit non-finite numbers")
        return number
    if value_type is str:
        return _require_text(value, "strict JSON string", allow_empty=True)
    if value_type is list:
        return [_copy_strict_json(item) for item in cast(list[Any], value)]
    if value_type is dict:
        copied: dict[str, JSONValue] = {}
        for key, item in cast(dict[Any, Any], value).items():
            if type(key) is not str:
                raise TypeError("strict JSON object keys must be strings")
            safe_key = _require_text(key, "strict JSON object key", allow_empty=True)
            copied[safe_key] = _copy_strict_json(item)
        return copied
    raise TypeError("value is outside the strict JSON canonicalization profile")


def strict_canonical_json(value: Any) -> str:
    """Canonicalize the accepted subset through the existing repo function."""

    return canonical_json(_copy_strict_json(value))


def strict_json_hash(value: Any) -> str:
    """Hash the accepted subset through the existing argument-hash function."""

    return sha256_json(_copy_strict_json(value))


canonicalize_strict_json = strict_canonical_json
hash_strict_json = strict_json_hash


def _freeze_validated(value: JSONValue) -> FrozenJSONValue:
    if type(value) is dict:
        mapping = value
        return MappingProxyType({key: _freeze_validated(item) for key, item in mapping.items()})
    if type(value) is list:
        return tuple(_freeze_validated(item) for item in value)
    return cast(JSONScalar, value)


def deep_copy_json(value: Any) -> JSONValue:
    return _copy_strict_json(value)


def deep_freeze_json(value: Any) -> FrozenJSONValue:
    return _freeze_validated(_copy_strict_json(value))


def deep_thaw_json(value: Any) -> JSONValue:
    if isinstance(value, MappingProxyType):
        return {
            _require_text(key, "strict JSON object key", allow_empty=True): deep_thaw_json(item)
            for key, item in value.items()
        }
    if type(value) is tuple:
        return [deep_thaw_json(item) for item in value]
    return _copy_strict_json(value)


def _freeze_mapping(value: Mapping[str, Any], *, field_name: str) -> Mapping[str, Any]:
    if type(value) is dict:
        plain = _copy_strict_json(value)
    elif isinstance(value, MappingProxyType):
        plain = deep_thaw_json(value)
    else:
        raise TypeError(f"{field_name} must be a dictionary")
    if type(plain) is not dict:
        raise TypeError(f"{field_name} must be a dictionary")
    frozen = _freeze_validated(plain)
    if not isinstance(frozen, Mapping):
        raise TypeError(f"{field_name} must be a dictionary")
    return frozen


def _plain_mapping(value: Mapping[str, Any]) -> dict[str, JSONValue]:
    thawed = deep_thaw_json(value)
    if type(thawed) is not dict:
        raise TypeError("expected an immutable JSON object")
    return thawed


def _normalize_utc_timestamp(
    value: Any,
    field_name: str,
    *,
    required: bool = True,
) -> str:
    if value == "" and not required:
        return ""
    text = _require_text(value, field_name)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"{field_name} must be an ISO-8601 timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must be a UTC timestamp")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _as_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    evidence_id: str
    evidence_type: str
    digest: str
    issuer: str
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        for name in ("evidence_id", "evidence_type", "issuer"):
            object.__setattr__(self, name, _require_text(getattr(self, name), name))
        object.__setattr__(self, "digest", _require_sha256(self.digest, "digest"))
        issued = _normalize_utc_timestamp(self.issued_at, "issued_at")
        expires = _normalize_utc_timestamp(self.expires_at, "expires_at")
        if _as_datetime(expires) <= _as_datetime(issued):
            raise ValueError("evidence expiry must be after issuance")
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)

    def identifier_dict(self) -> dict[str, JSONValue]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "issuer": self.issuer,
        }

    def digest_dict(self) -> dict[str, JSONValue]:
        return {
            **self.identifier_dict(),
            "digest": self.digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, JSONValue]:
        return self.digest_dict()


@dataclass(frozen=True, slots=True)
class VerifiedPrincipal:
    tenant_id: str
    actor_id: str
    role: str
    authority: str
    authentication_context: Mapping[str, Any] = field(default_factory=dict, repr=False)
    verified_at: str = ""
    expires_at: str = ""

    def __post_init__(self) -> None:
        for name in ("tenant_id", "actor_id", "role", "authority"):
            object.__setattr__(self, name, _require_text(getattr(self, name), name))
        verified = _normalize_utc_timestamp(self.verified_at, "verified_at")
        expires = _normalize_utc_timestamp(self.expires_at, "expires_at")
        if _as_datetime(expires) <= _as_datetime(verified):
            raise ValueError("principal expiry must be after verification")
        object.__setattr__(self, "verified_at", verified)
        object.__setattr__(self, "expires_at", expires)
        object.__setattr__(
            self,
            "authentication_context",
            _freeze_mapping(
                self.authentication_context,
                field_name="authentication_context",
            ),
        )


@dataclass(frozen=True, slots=True)
class ResolvedPolicyRef:
    tenant_id: str
    bundle_id: str
    version: str
    digest: str

    def __post_init__(self) -> None:
        for name in ("tenant_id", "bundle_id", "version"):
            object.__setattr__(self, name, _require_text(getattr(self, name), name))
        object.__setattr__(self, "digest", _require_sha256(self.digest, "digest"))

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "tenant_id": self.tenant_id,
            "bundle_id": self.bundle_id,
            "version": self.version,
            "digest": self.digest,
        }


@dataclass(frozen=True, slots=True)
class PolicyArtifactAttestation:
    """Trusted resolver attestation for the exact evaluated policy artifact.

    ``artifact_id`` is the resolver's identifier for the policy bundle and is
    required to equal :attr:`ResolvedPolicyRef.bundle_id`.  The attestation is
    deliberately separate from ``Policy.version``: the existing version is a
    compatibility identifier, while ``digest`` binds the complete artifact
    selected by the trusted resolver.
    """

    tenant_id: str
    artifact_id: str
    policy_version: str
    digest: str
    resolver_id: str

    def __post_init__(self) -> None:
        for name in ("tenant_id", "artifact_id", "policy_version", "resolver_id"):
            object.__setattr__(self, name, _require_text(getattr(self, name), name))
        object.__setattr__(self, "digest", _require_sha256(self.digest, "digest"))

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "tenant_id": self.tenant_id,
            "artifact_id": self.artifact_id,
            "policy_version": self.policy_version,
            "digest": self.digest,
            "resolver_id": self.resolver_id,
        }


@dataclass(frozen=True, slots=True)
class ResolvedPolicy:
    ref: ResolvedPolicyRef
    policy: Policy
    attestation: PolicyArtifactAttestation
    validator: Validator
    authority: str

    def __post_init__(self) -> None:
        if not isinstance(self.ref, ResolvedPolicyRef):
            raise TypeError("ref must be a ResolvedPolicyRef")
        if not isinstance(self.policy, Policy):
            raise TypeError("policy must implement the existing Policy type")
        if not isinstance(self.attestation, PolicyArtifactAttestation):
            raise TypeError("attestation must be a PolicyArtifactAttestation")
        attested_reference = (
            self.attestation.tenant_id,
            self.attestation.artifact_id,
            self.attestation.policy_version,
            self.attestation.digest,
        )
        expected_reference = (
            self.ref.tenant_id,
            self.ref.bundle_id,
            self.ref.version,
            self.ref.digest,
        )
        if attested_reference != expected_reference:
            raise ValueError("policy artifact attestation does not match its reference")
        if self.policy.version != self.ref.version:
            raise ValueError("resolved policy version does not match its reference")
        if not isinstance(self.validator, Validator):
            raise TypeError("validator must use the existing Validator type")
        object.__setattr__(self, "authority", _require_text(self.authority, "authority"))


@dataclass(frozen=True, slots=True)
class SideEffectRequest:
    request_id: str
    tenant_id: str
    actor_id: str
    actor_role: str
    authority: str
    server_id: str
    tool: str
    operation: str
    resource: str
    environment: str
    execution_boundary: str
    policy_ref: ResolvedPolicyRef
    requested_at: str
    nonce: str = field(repr=False)
    idempotency_key: str = field(repr=False)
    args: Mapping[str, Any] = field(default_factory=dict, repr=False)
    evidence: tuple[EvidenceRef, ...] = ()
    side_effect_class: str = "high-risk"
    goal: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        for name in (
            "request_id",
            "tenant_id",
            "actor_id",
            "actor_role",
            "authority",
            "server_id",
            "tool",
            "operation",
            "resource",
            "environment",
            "execution_boundary",
            "nonce",
            "idempotency_key",
            "side_effect_class",
        ):
            object.__setattr__(self, name, _require_text(getattr(self, name), name))
        object.__setattr__(
            self,
            "goal",
            _require_text(self.goal, "goal", allow_empty=True),
        )
        if not isinstance(self.policy_ref, ResolvedPolicyRef):
            raise TypeError("policy_ref must be a ResolvedPolicyRef")
        if self.policy_ref.tenant_id != self.tenant_id:
            raise ValueError("request and policy tenants must match")
        requested = _normalize_utc_timestamp(self.requested_at, "requested_at")
        object.__setattr__(self, "requested_at", requested)
        object.__setattr__(self, "args", _freeze_mapping(self.args, field_name="args"))
        if type(self.evidence) not in (tuple, list):
            raise TypeError("evidence must be a list or tuple of EvidenceRef")
        evidence = tuple(self.evidence)
        if any(not isinstance(item, EvidenceRef) for item in evidence):
            raise TypeError("evidence must contain only EvidenceRef values")
        if len({item.evidence_id for item in evidence}) != len(evidence):
            raise ValueError("evidence identifiers must be unique")
        requested_dt = _as_datetime(requested)
        for item in evidence:
            if not (_as_datetime(item.issued_at) <= requested_dt < _as_datetime(item.expires_at)):
                raise ValueError("evidence is not valid at request time")
        object.__setattr__(self, "evidence", evidence)

    @property
    def arguments(self) -> Mapping[str, Any]:
        return self.args


def _goal_hash(goal: str) -> str:
    safe_goal = _require_text(goal, "goal", allow_empty=True)
    payload = _GOAL_HASH_DOMAIN + strict_canonical_json(safe_goal).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def goal_receipt_claim(goal: str) -> str:
    """Return the non-secret goal claim stored in a DecisionReceipt."""

    return f"sha256:{_goal_hash(goal)}"


def _require_normalized_timestamp(value: JSONValue, field_name: str) -> datetime:
    normalized = _normalize_utc_timestamp(value, field_name)
    if normalized != value:
        raise ValueError(f"{field_name} must use normalized UTC form")
    return _as_datetime(normalized)


def _validate_reserved_binding_shape(binding: dict[str, JSONValue]) -> None:
    if set(binding) != RESERVED_BINDING_REQUIRED_KEYS:
        raise ValueError("reserved binding keys are incompatible")
    if binding["schema"] != SIDE_EFFECT_BINDING_KEY:
        raise ValueError("reserved binding schema is incompatible")
    if binding["argument_canonicalization_profile"] != ARGUMENT_CANONICALIZATION_PROFILE:
        raise ValueError("argument canonicalization profile is incompatible")
    if binding["secret_digest_profile"] != SECRET_DIGEST_PROFILE:
        raise ValueError("secret digest profile is incompatible")

    for name in (
        "request_id",
        "tenant_id",
        "actor_id",
        "actor_role",
        "authority",
        "server_id",
        "tool",
        "operation",
        "resource",
        "environment",
        "execution_boundary",
        "side_effect_class",
        "validator_id",
        "validator_role",
    ):
        _require_text(binding[name], name)
    for name in (
        "goal_hash",
        "nonce_digest",
        "idempotency_digest",
        "evidence_digest",
        "original_arguments_hash",
        "approved_arguments_hash",
        "authentication_context_hash",
    ):
        _require_sha256(binding[name], name)

    policy_value = binding["policy"]
    if type(policy_value) is not dict:
        raise TypeError("reserved policy binding must be an object")
    policy = policy_value
    if set(policy) != RESERVED_POLICY_REQUIRED_KEYS:
        raise ValueError("reserved policy binding keys are incompatible")
    for name in ("tenant_id", "bundle_id", "version"):
        _require_text(policy[name], f"policy.{name}")
    _require_sha256(policy["digest"], "policy.digest")
    if policy["tenant_id"] != binding["tenant_id"]:
        raise ValueError("reserved policy tenant is inconsistent")

    attestation_value = binding["policy_attestation"]
    if type(attestation_value) is not dict:
        raise TypeError("reserved policy attestation must be an object")
    attestation = attestation_value
    if set(attestation) != RESERVED_POLICY_ATTESTATION_REQUIRED_KEYS:
        raise ValueError("reserved policy attestation keys are incompatible")
    for name in ("tenant_id", "artifact_id", "policy_version", "resolver_id"):
        _require_text(attestation[name], f"policy_attestation.{name}")
    _require_sha256(attestation["digest"], "policy_attestation.digest")
    if (
        attestation["tenant_id"],
        attestation["artifact_id"],
        attestation["policy_version"],
        attestation["digest"],
    ) != (
        policy["tenant_id"],
        policy["bundle_id"],
        policy["version"],
        policy["digest"],
    ):
        raise ValueError("reserved policy attestation is inconsistent")

    checkpoint_value = binding["audit_checkpoint"]
    if type(checkpoint_value) is not dict:
        raise TypeError("reserved audit checkpoint must be an object")
    checkpoint = checkpoint_value
    if set(checkpoint) != RESERVED_AUDIT_CHECKPOINT_REQUIRED_KEYS:
        raise ValueError("reserved audit checkpoint keys are incompatible")
    for name in ("namespace", "key_id", "algorithm", "signature"):
        _require_text(checkpoint[name], f"audit_checkpoint.{name}")
    if checkpoint["algorithm"] == "none":
        raise ValueError("reserved audit checkpoint must be signed")
    generation = checkpoint["generation"]
    if type(generation) is not int or generation <= 0:
        raise ValueError("reserved audit checkpoint generation is invalid")
    for name in (
        "head_hash",
        "previous_checkpoint_hash",
        "checkpoint_hash",
    ):
        _require_sha256(checkpoint[name], f"audit_checkpoint.{name}")
    checkpoint_payload = {
        name: value for name, value in checkpoint.items() if name != "checkpoint_hash"
    }
    if strict_json_hash(checkpoint_payload) != checkpoint["checkpoint_hash"]:
        raise ValueError("reserved audit checkpoint hash is inconsistent")

    evidence_value = binding["evidence_identifiers"]
    if type(evidence_value) is not list:
        raise TypeError("evidence identifiers must be a list")
    evidence_ids: set[str] = set()
    for value in evidence_value:
        if type(value) is not dict:
            raise TypeError("evidence identifier must be an object")
        identifier = value
        if set(identifier) != EVIDENCE_IDENTIFIER_REQUIRED_KEYS:
            raise ValueError("evidence identifier keys are incompatible")
        for name in EVIDENCE_IDENTIFIER_REQUIRED_KEYS:
            _require_text(identifier[name], f"evidence.{name}")
        evidence_id = cast(str, identifier["evidence_id"])
        if evidence_id in evidence_ids:
            raise ValueError("evidence identifiers must be unique")
        evidence_ids.add(evidence_id)

    try:
        bound_decision = Decision(_require_text(binding["decision"], "decision"))
    except ValueError:
        raise ValueError("reserved decision is invalid") from None
    if bound_decision.value != binding["decision"]:
        raise ValueError("reserved decision is invalid")

    verified_at = _require_normalized_timestamp(
        binding["principal_verified_at"], "principal_verified_at"
    )
    requested_at = _require_normalized_timestamp(binding["requested_at"], "requested_at")
    authorized_at = _require_normalized_timestamp(binding["authorized_at"], "authorized_at")
    expires_at = _require_normalized_timestamp(binding["expires_at"], "expires_at")
    principal_expires_at = _require_normalized_timestamp(
        binding["principal_expires_at"], "principal_expires_at"
    )
    if not (verified_at <= requested_at <= authorized_at < expires_at <= principal_expires_at):
        raise ValueError("reserved authorization time ordering is invalid")


@dataclass(frozen=True, slots=True)
class SideEffectAuthorization:
    request_id: str
    decision: Decision
    reason_codes: tuple[AuthorizationReasonCode, ...]
    original_arguments_hash: str
    approved_arguments_hash: str
    binding_hash: str
    audit_event_id: str
    audit_event_hash: str
    previous_audit_hash: str
    approved_arguments: Mapping[str, Any] = field(default_factory=dict, repr=False)
    reserved_binding: Mapping[str, Any] = field(default_factory=dict, repr=False)
    receipt: DecisionReceipt | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", _require_text(self.request_id, "request_id"))
        if not isinstance(self.decision, Decision):
            raise TypeError("decision must use the existing Decision enum")
        if type(self.reason_codes) is not tuple or not self.reason_codes:
            raise TypeError("reason_codes must be a non-empty tuple")
        if any(not isinstance(code, AuthorizationReasonCode) for code in self.reason_codes):
            raise TypeError("reason_codes must contain AuthorizationReasonCode values")
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("reason_codes must be unique")
        expected_primary = {
            Decision.ALLOW: AuthorizationReasonCode.ALLOWED,
            Decision.TRANSFORM: AuthorizationReasonCode.TRANSFORMED,
            Decision.DENY: AuthorizationReasonCode.DENIED,
            Decision.ESCALATE: AuthorizationReasonCode.ESCALATED,
        }[self.decision]
        if self.reason_codes[0] is not expected_primary:
            raise ValueError("decision and primary reason code are inconsistent")
        terminal_codes = {
            AuthorizationReasonCode.ALLOWED,
            AuthorizationReasonCode.TRANSFORMED,
            AuthorizationReasonCode.DENIED,
            AuthorizationReasonCode.ESCALATED,
        }
        if any(code in terminal_codes for code in self.reason_codes[1:]):
            raise ValueError("reason_codes contain contradictory terminal outcomes")
        if self.decision is not Decision.DENY and len(self.reason_codes) != 1:
            raise ValueError("executable or escalated decisions cannot carry failure reasons")
        for name in (
            "original_arguments_hash",
            "approved_arguments_hash",
            "binding_hash",
            "audit_event_hash",
            "previous_audit_hash",
        ):
            object.__setattr__(self, name, _require_sha256(getattr(self, name), name))
        object.__setattr__(
            self,
            "audit_event_id",
            _require_text(self.audit_event_id, "audit_event_id"),
        )
        approved = _freeze_mapping(
            self.approved_arguments,
            field_name="approved_arguments",
        )
        binding = _freeze_mapping(self.reserved_binding, field_name="reserved_binding")
        object.__setattr__(self, "approved_arguments", approved)
        object.__setattr__(self, "reserved_binding", binding)
        if strict_json_hash(_plain_mapping(approved)) != self.approved_arguments_hash:
            raise ValueError("approved arguments hash is inconsistent")
        if self.decision is Decision.ALLOW:
            if self.approved_arguments_hash != self.original_arguments_hash:
                raise ValueError("ALLOW must approve the original arguments exactly")
        elif self.decision in (Decision.DENY, Decision.ESCALATE) and _plain_mapping(approved):
            raise ValueError("non-executable decisions cannot approve arguments")
        if reserved_binding_hash(binding) != self.binding_hash:
            raise ValueError("reserved binding hash is inconsistent")
        plain_binding = _plain_mapping(binding)
        _validate_reserved_binding_shape(plain_binding)
        if plain_binding.get("request_id") != self.request_id:
            raise ValueError("authorization request binding is inconsistent")
        if plain_binding.get("decision") != self.decision.value:
            raise ValueError("authorization decision binding is inconsistent")
        if plain_binding.get("original_arguments_hash") != self.original_arguments_hash:
            raise ValueError("authorization original argument binding is inconsistent")
        if plain_binding.get("approved_arguments_hash") != self.approved_arguments_hash:
            raise ValueError("authorization approved argument binding is inconsistent")
        checkpoint = plain_binding.get("audit_checkpoint")
        if type(checkpoint) is not dict or checkpoint.get("head_hash") != self.audit_event_hash:
            raise ValueError("authorization audit checkpoint binding is inconsistent")
        if self.executable and self.receipt is None:
            raise ValueError("executable authorization requires a receipt")
        if self.receipt is not None:
            self._validate_receipt(plain_binding)

    @property
    def executable(self) -> bool:
        return self.decision in (Decision.ALLOW, Decision.TRANSFORM)

    @property
    def reason_code(self) -> AuthorizationReasonCode:
        return self.reason_codes[0]

    def _validate_receipt(self, binding: dict[str, JSONValue]) -> None:
        receipt = self.receipt
        if receipt is None:
            raise ValueError("receipt validation requires a receipt")
        for value, name in (
            (receipt.receipt_hash, "receipt_hash"),
            (receipt.argument_hash, "receipt.argument_hash"),
            (receipt.policy_hash, "receipt.policy_hash"),
            (receipt.audit_event_hash, "receipt.audit_event_hash"),
            (receipt.previous_audit_hash, "receipt.previous_audit_hash"),
        ):
            _require_sha256(value, name)
        if receipt.compute_hash() != receipt.receipt_hash:
            raise ValueError("receipt hash is inconsistent")
        expected_pairs = (
            (receipt.request_id, self.request_id),
            (receipt.receipt_id, self.audit_event_id),
            (receipt.decision, self.decision.value),
            (receipt.argument_hash, self.original_arguments_hash),
            (receipt.audit_event_hash, self.audit_event_hash),
            (receipt.previous_audit_hash, self.previous_audit_hash),
            (receipt.tenant_id, binding.get("tenant_id")),
            (receipt.actor, binding.get("actor_id")),
            (receipt.proposed_action, binding.get("operation")),
            (receipt.execution_boundary, binding.get("execution_boundary")),
            (receipt.policy_bundle_id, _nested_policy_value(binding, "bundle_id")),
            (receipt.policy_version, _nested_policy_value(binding, "version")),
            (receipt.policy_hash, _nested_policy_value(binding, "digest")),
            (receipt.validator_id, binding.get("validator_id")),
            (receipt.validator_role, binding.get("validator_role")),
            (receipt.authority, binding.get("authority")),
            (receipt.expires_at, binding.get("expires_at")),
        )
        if any(actual != expected for actual, expected in expected_pairs):
            raise ValueError("receipt and authorization binding are inconsistent")
        receipt_timestamp = _normalize_utc_timestamp(receipt.timestamp, "receipt.timestamp")
        if receipt_timestamp != binding.get("authorized_at"):
            raise ValueError("receipt timestamp binding is inconsistent")
        expected_goal_claim = f"sha256:{binding.get('goal_hash')}"
        if receipt.declared_goal != expected_goal_claim:
            raise ValueError("receipt goal binding is inconsistent")
        if receipt.constraints != reserved_constraints(self.reserved_binding):
            raise ValueError("receipt constraints are inconsistent")
        approved = _plain_mapping(self.approved_arguments)
        if self.decision is Decision.TRANSFORM:
            transformed: dict[str, Any] = {}
            for item in receipt.transformations:
                if not isinstance(item, dict) or set(item) != {"field", "value"}:
                    raise ValueError("receipt transformations are malformed")
                field_name = item.get("field")
                if type(field_name) is not str or field_name in transformed:
                    raise ValueError("receipt transformations are malformed")
                transformed[field_name] = item.get("value")
            if deep_copy_json(transformed) != approved:
                raise ValueError("receipt transformations are inconsistent")
        elif receipt.transformations:
            raise ValueError("non-transform receipt contains transformations")


def _nested_policy_value(binding: dict[str, JSONValue], name: str) -> JSONValue:
    policy = binding.get("policy")
    if type(policy) is not dict:
        return None
    return policy.get(name)


@dataclass(frozen=True, slots=True)
class SideEffectExecutionContext:
    request_id: str
    tenant_id: str
    actor_id: str
    actor_role: str
    authority: str
    server_id: str
    tool: str
    operation: str
    resource: str
    environment: str
    execution_boundary: str
    policy_ref: ResolvedPolicyRef
    observed_at: str
    authentication_context: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        for name in (
            "request_id",
            "tenant_id",
            "actor_id",
            "actor_role",
            "authority",
            "server_id",
            "tool",
            "operation",
            "resource",
            "environment",
            "execution_boundary",
        ):
            object.__setattr__(self, name, _require_text(getattr(self, name), name))
        if not isinstance(self.policy_ref, ResolvedPolicyRef):
            raise TypeError("policy_ref must be a ResolvedPolicyRef")
        if self.policy_ref.tenant_id != self.tenant_id:
            raise ValueError("execution context and policy tenants must match")
        object.__setattr__(
            self,
            "observed_at",
            _normalize_utc_timestamp(self.observed_at, "observed_at"),
        )
        object.__setattr__(
            self,
            "authentication_context",
            _freeze_mapping(
                self.authentication_context,
                field_name="authentication_context",
            ),
        )


@runtime_checkable
class PrincipalResolver(Protocol):
    def resolve(self) -> VerifiedPrincipal: ...


@runtime_checkable
class PolicyResolver(Protocol):
    def resolve(self, principal: VerifiedPrincipal) -> ResolvedPolicy: ...


class AuthorizationReasonCode(StrEnum):
    ALLOWED = "authorization.allowed"
    TRANSFORMED = "authorization.transformed"
    DENIED = "authorization.denied"
    ESCALATED = "authorization.escalated"
    INVALID_REQUEST = "authorization.invalid_request"
    INVALID_TIME = "authorization.invalid_time"
    INVALID_EVIDENCE = "authorization.invalid_evidence"
    PRINCIPAL_RESOLUTION_FAILED = "authorization.principal_resolution_failed"
    PRINCIPAL_MISMATCH = "authorization.principal_mismatch"
    POLICY_RESOLUTION_FAILED = "authorization.policy_resolution_failed"
    POLICY_MISMATCH = "authorization.policy_mismatch"
    SELF_VALIDATION = "authorization.self_validation"
    VALIDATOR_NOT_ALLOWED = "authorization.validator_not_allowed"
    MALFORMED_TRANSFORM = "authorization.malformed_transform"
    AUDIT_FAILED = "authorization.audit_failed"
    RECEIPT_FAILED = "authorization.receipt_failed"
    INTERNAL_FAILURE = "authorization.internal_failure"


class ExecutionReasonCode(StrEnum):
    SUCCEEDED = "execution.succeeded"
    INVALID_CONTEXT = "execution.invalid_context"
    MISSING_AUTHORIZATION = "execution.missing_authorization"
    NOT_EXECUTABLE = "execution.not_executable"
    BINDING_MISMATCH = "execution.binding_mismatch"
    RECEIPT_INVALID = "execution.receipt_invalid"
    AUDIT_EVENT_MISSING = "execution.audit_event_missing"
    AUDIT_HASH_MISMATCH = "execution.audit_hash_mismatch"
    EXPIRED = "execution.expired"
    REVOKED = "execution.revoked"
    REPLAY = "execution.replay"
    RESERVATION_FAILED = "execution.reservation_failed"
    REVOKED_AFTER_RESERVATION = "execution.revoked_after_reservation"
    ADAPTER_FAILED = "execution.adapter_failed"
    TIMEOUT = "execution.timeout"
    OUTCOME_UNKNOWN = "execution.outcome_unknown"
    CONSUMPTION_STATE_FAILED = "execution.consumption_state_failed"
    INTERNAL_FAILURE = "execution.internal_failure"


@dataclass(frozen=True, slots=True)
class RefusalEvidence:
    """Minimal integrity evidence for a pre-policy authorization refusal.

    This is intentionally not a ``DecisionReceipt``: identity or policy
    resolution may have failed, so no verified principal or validator is
    invented.  Only identifiers and hashes are retained; raw goals, arguments,
    nonce material, idempotency keys, and signing secrets are never present.
    Signature and strict-audit proofs are independent so one dependency can
    still provide verifiable refusal evidence when the other is unavailable.
    """

    request_id: str
    reason_code: AuthorizationReasonCode
    decision: Decision
    reason_codes: tuple[str, ...]
    claimed_tenant_id: str
    claimed_actor_id: str
    operation: str
    argument_hash: str
    policy_digest: str
    principal_verified: bool
    audited: bool
    audit_event_id: str = ""
    audit_event_hash: str = ""
    audit_checkpoint_hash: str = ""
    signed: bool = False
    signing_key_id: str = ""
    signature_algorithm: str = ""
    signature: str = field(default="", repr=False)
    payload_hash: str = ""
    schema: str = REFUSAL_EVIDENCE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != REFUSAL_EVIDENCE_SCHEMA:
            raise ValueError("refusal evidence schema is incompatible")
        for name in (
            "request_id",
            "claimed_tenant_id",
            "claimed_actor_id",
            "operation",
        ):
            object.__setattr__(self, name, _require_text(getattr(self, name), name))
        if not isinstance(self.reason_code, AuthorizationReasonCode):
            raise TypeError("reason_code must be an AuthorizationReasonCode")
        if self.decision not in {Decision.DENY, Decision.ESCALATE}:
            raise ValueError("refusal evidence decision must be non-executable")
        if type(self.reason_codes) is not tuple or not self.reason_codes:
            raise TypeError("reason_codes must be a non-empty tuple")
        normalized_reasons = tuple(
            _require_text(item, "reason_codes item") for item in self.reason_codes
        )
        if any(_REFUSAL_REASON_RE.fullmatch(item) is None for item in normalized_reasons):
            raise ValueError("reason_codes must contain structured protocol codes")
        if len(set(normalized_reasons)) != len(normalized_reasons):
            raise ValueError("reason_codes must be unique")
        object.__setattr__(self, "reason_codes", normalized_reasons)
        if self.decision is Decision.ESCALATE:
            if self.reason_code is not AuthorizationReasonCode.ESCALATED:
                raise ValueError("ESCALATE evidence requires the escalated category")
        elif self.reason_code is AuthorizationReasonCode.ESCALATED:
            raise ValueError("DENY evidence cannot use the escalated category")
        object.__setattr__(
            self,
            "argument_hash",
            _require_sha256(self.argument_hash, "argument_hash"),
        )
        object.__setattr__(
            self,
            "policy_digest",
            _require_sha256(self.policy_digest, "policy_digest"),
        )
        for name in ("principal_verified", "audited", "signed"):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be a boolean")
        if self.audited:
            object.__setattr__(
                self,
                "audit_event_id",
                _require_text(self.audit_event_id, "audit_event_id"),
            )
            for name in ("audit_event_hash", "audit_checkpoint_hash"):
                object.__setattr__(
                    self,
                    name,
                    _require_sha256(getattr(self, name), name),
                )
        elif any((self.audit_event_id, self.audit_event_hash, self.audit_checkpoint_hash)):
            raise ValueError("unaudited refusal evidence cannot claim audit identifiers")
        if self.signed:
            object.__setattr__(
                self,
                "signing_key_id",
                _require_text(self.signing_key_id, "signing_key_id"),
            )
            object.__setattr__(
                self,
                "signature_algorithm",
                _require_text(self.signature_algorithm, "signature_algorithm"),
            )
            if self.signature_algorithm == "none":
                raise ValueError("signed refusal evidence requires a real algorithm")
            object.__setattr__(self, "signature", _require_text(self.signature, "signature"))
        elif self.signature:
            raise ValueError("unsigned refusal evidence cannot contain a signature")
        expected_payload_hash = strict_json_hash(self._payload_dict())
        if self.payload_hash:
            if _require_sha256(self.payload_hash, "payload_hash") != expected_payload_hash:
                raise ValueError("refusal evidence payload hash is inconsistent")
        else:
            object.__setattr__(self, "payload_hash", expected_payload_hash)

    def _payload_dict(self) -> dict[str, JSONValue]:
        return {
            "schema": self.schema,
            "request_id": self.request_id,
            "reason_code": self.reason_code.value,
            "decision": self.decision.value,
            "reason_codes": list(self.reason_codes),
            "claimed_tenant_id": self.claimed_tenant_id,
            "claimed_actor_id": self.claimed_actor_id,
            "operation": self.operation,
            "argument_hash": self.argument_hash,
            "policy_digest": self.policy_digest,
            "principal_verified": self.principal_verified,
            "audited": self.audited,
            "audit_event_id": self.audit_event_id,
            "audit_event_hash": self.audit_event_hash,
            "audit_checkpoint_hash": self.audit_checkpoint_hash,
            "signing_key_id": self.signing_key_id,
            "signature_algorithm": self.signature_algorithm,
        }

    def _audit_state_dict(self) -> dict[str, JSONValue]:
        """Return every refusal claim committed by the strict audit event."""

        return {
            "schema": self.schema,
            "request_id": self.request_id,
            "reason_code": self.reason_code.value,
            "decision": self.decision.value,
            "reason_codes": list(self.reason_codes),
            "claimed_tenant_id": self.claimed_tenant_id,
            "claimed_actor_id": self.claimed_actor_id,
            "operation": self.operation,
            "argument_hash": self.argument_hash,
            "policy_digest": self.policy_digest,
            "principal_verified": self.principal_verified,
        }

    def _payload_hash_matches(self) -> bool:
        try:
            expected = strict_json_hash(self._payload_dict())
            return type(self.payload_hash) is str and hmac.compare_digest(
                expected,
                self.payload_hash,
            )
        except Exception:
            return False

    def verify_signature(self, verifier: Any) -> bool:
        if not self.signed or not self._payload_hash_matches():
            return False
        try:
            return bool(
                verifier.key_id == self.signing_key_id
                and verifier.algorithm == self.signature_algorithm
                and verifier.verify(self.payload_hash.encode("utf-8"), self.signature)
            )
        except Exception:
            return False

    def verify_integrity(
        self,
        *,
        verifier: Any | None = None,
        audit: Any | None = None,
    ) -> bool:
        """Verify either independent proof without inventing missing trust.

        A valid receipt-signing proof is sufficient.  Otherwise an audited
        refusal is accepted only when its exact event is the current head of a
        valid strict externally checkpointed chain and the checkpoint, reason,
        operation, decision, and canonical argument hash all match this object.
        Local-only chains and stale or mismatched checkpoints never qualify.
        """

        if not self._payload_hash_matches():
            return False
        if verifier is not None and self.verify_signature(verifier):
            return True
        if not self.audited or audit is None:
            return False
        try:
            from gove_zone.audit import (
                AuditCheckpoint,
                AuditCommit,
                ChainHashAuditStore,
            )

            if not isinstance(audit, ChainHashAuditStore):
                return False
            verification = audit.verify_checkpointed_chain()
            if not verification.get("valid") or not verification.get("strict"):
                return False
            checkpoint = verification.get("checkpoint")
            if type(checkpoint) is not dict:
                return False
            rebuilt_checkpoint = AuditCheckpoint(
                namespace=checkpoint["namespace"],
                generation=checkpoint["generation"],
                head_hash=checkpoint["head_hash"],
                previous_checkpoint_hash=checkpoint["previous_checkpoint_hash"],
                key_id=checkpoint["key_id"],
                algorithm=checkpoint["algorithm"],
                signature=checkpoint["signature"],
            )
            if rebuilt_checkpoint.checkpoint_hash != self.audit_checkpoint_hash:
                return False
            if rebuilt_checkpoint.head_hash != self.audit_event_hash:
                return False
            events = audit.query(
                where=lambda event: event.get("event_id") == self.audit_event_id,
                limit=2,
            )
            if len(events) != 1:
                return False
            event = events[0]
            if not (
                event.get("event_id") == self.audit_event_id
                and event.get("event_hash") == self.audit_event_hash
                and event.get("decision") == self.decision.value
                and event.get("tool") == self.operation
                and event.get("actor") == self.claimed_actor_id
                and event.get("argument_hash") == self.argument_hash
                and event.get("matched_rules") == list(self.reason_codes)
                and event.get("state_hash") == strict_json_hash(self._audit_state_dict())
            ):
                return False
            commit = AuditCommit(
                event_id=self.audit_event_id,
                event_hash=self.audit_event_hash,
                event=dict(event),
                checkpoint=rebuilt_checkpoint,
            )
            return bool(audit.run_if_committed(commit, lambda: True))
        except Exception:
            return False

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            **self._payload_dict(),
            "signed": self.signed,
            "signature": self.signature,
            "payload_hash": self.payload_hash,
        }


class ExecutionRefusalPhase(StrEnum):
    """Where in the final execution gate an attempt was provably refused."""

    AUTHORIZATION_GATE = "authorization_gate"
    RESERVATION = "reservation"
    POST_RESERVATION = "post_reservation"


# Only codes that prove the adapter was never entered may be carried by an
# execution refusal. TIMEOUT, OUTCOME_UNKNOWN, ADAPTER_FAILED and SUCCEEDED are
# deliberately absent: those outcomes are ambiguous or executed, and belong to
# the UNKNOWN/terminal execution lifecycle instead. MISSING_AUTHORIZATION is
# absent because no receipt exists to bind evidence to.
EXECUTION_REFUSAL_REASON_CODES = frozenset(
    {
        ExecutionReasonCode.NOT_EXECUTABLE,
        ExecutionReasonCode.INVALID_CONTEXT,
        ExecutionReasonCode.BINDING_MISMATCH,
        ExecutionReasonCode.RECEIPT_INVALID,
        ExecutionReasonCode.AUDIT_EVENT_MISSING,
        ExecutionReasonCode.AUDIT_HASH_MISMATCH,
        ExecutionReasonCode.EXPIRED,
        ExecutionReasonCode.REVOKED,
        ExecutionReasonCode.REPLAY,
        ExecutionReasonCode.RESERVATION_FAILED,
        ExecutionReasonCode.REVOKED_AFTER_RESERVATION,
        ExecutionReasonCode.CONSUMPTION_STATE_FAILED,
    }
)


@dataclass(frozen=True, slots=True)
class ExecutionRefusalEvidence:
    """Integrity evidence that one bound attempt never reached an adapter.

    This is not a :class:`RefusalEvidence`: that type answers "may this request
    be authorized?" before a receipt exists. This type answers "did this exact
    receipted attempt run?" and always answers *no*, binding the receipt,
    authorization audit event, reserved binding, and adapter route it refused.

    Signature and strict-audit proofs are independent so one dependency can
    still provide verifiable refusal evidence when the other is unavailable.
    Neither is fabricated: ``signed`` and ``audited`` state exactly which
    proof paths exist, and both may be false.
    """

    request_id_digest: str
    receipt_id_digest: str
    receipt_hash: str
    tenant_digest: str
    execution_boundary_digest: str
    adapter_id_digest: str
    authorization_audit_digest: str
    binding_hash: str
    argument_hash: str
    reason_code: ExecutionReasonCode
    phase: ExecutionRefusalPhase
    audited: bool
    adapter_invoked: bool = False
    attempt_id_digest: str = ""
    audit_event_id: str = ""
    audit_event_hash: str = ""
    audit_checkpoint_hash: str = ""
    audit_checkpoint_parent_hash: str = ""
    signed: bool = False
    signing_key_id: str = ""
    signature_algorithm: str = ""
    signature: str = field(default="", repr=False)
    payload_hash: str = ""
    schema: str = EXECUTION_REFUSAL_EVIDENCE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != EXECUTION_REFUSAL_EVIDENCE_SCHEMA:
            raise ValueError("execution refusal evidence schema is incompatible")
        if not isinstance(self.reason_code, ExecutionReasonCode):
            raise TypeError("reason_code must be an ExecutionReasonCode")
        if self.reason_code not in EXECUTION_REFUSAL_REASON_CODES:
            raise ValueError("reason_code does not prove the adapter was never entered")
        if not isinstance(self.phase, ExecutionRefusalPhase):
            raise TypeError("phase must be an ExecutionRefusalPhase")
        for name in ("audited", "signed", "adapter_invoked"):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be a boolean")
        if self.adapter_invoked:
            raise ValueError("execution refusal evidence cannot claim adapter invocation")
        for name in (
            "request_id_digest",
            "receipt_id_digest",
            "receipt_hash",
            "tenant_digest",
            "execution_boundary_digest",
            "adapter_id_digest",
            "authorization_audit_digest",
            "binding_hash",
            "argument_hash",
        ):
            object.__setattr__(self, name, _require_sha256(getattr(self, name), name))
        if self.phase is ExecutionRefusalPhase.POST_RESERVATION:
            object.__setattr__(
                self,
                "attempt_id_digest",
                _require_sha256(self.attempt_id_digest, "attempt_id_digest"),
            )
        elif self.attempt_id_digest:
            raise ValueError("only a post-reservation refusal can bind an attempt")
        if self.audited:
            object.__setattr__(
                self,
                "audit_event_id",
                _require_text(self.audit_event_id, "audit_event_id"),
            )
            for name in (
                "audit_event_hash",
                "audit_checkpoint_hash",
                "audit_checkpoint_parent_hash",
            ):
                object.__setattr__(self, name, _require_sha256(getattr(self, name), name))
        elif any(
            (
                self.audit_event_id,
                self.audit_event_hash,
                self.audit_checkpoint_hash,
                self.audit_checkpoint_parent_hash,
            )
        ):
            raise ValueError("unaudited execution refusal cannot claim audit identifiers")
        if self.signed:
            object.__setattr__(
                self,
                "signing_key_id",
                _require_text(self.signing_key_id, "signing_key_id"),
            )
            object.__setattr__(
                self,
                "signature_algorithm",
                _require_text(self.signature_algorithm, "signature_algorithm"),
            )
            if self.signature_algorithm == "none":
                raise ValueError("signed execution refusal requires a real algorithm")
            object.__setattr__(self, "signature", _require_text(self.signature, "signature"))
        elif self.signature:
            raise ValueError("unsigned execution refusal cannot contain a signature")
        expected_payload_hash = strict_json_hash(self._payload_dict())
        if self.payload_hash:
            if _require_sha256(self.payload_hash, "payload_hash") != expected_payload_hash:
                raise ValueError("execution refusal payload hash is inconsistent")
        else:
            object.__setattr__(self, "payload_hash", expected_payload_hash)

    def _audit_state_dict(self) -> dict[str, JSONValue]:
        """Return every refusal claim committed by the strict audit event."""

        return {
            "schema": self.schema,
            "request_id_digest": self.request_id_digest,
            "receipt_id_digest": self.receipt_id_digest,
            "receipt_hash": self.receipt_hash,
            "tenant_digest": self.tenant_digest,
            "execution_boundary_digest": self.execution_boundary_digest,
            "adapter_id_digest": self.adapter_id_digest,
            "authorization_audit_digest": self.authorization_audit_digest,
            "binding_hash": self.binding_hash,
            "argument_hash": self.argument_hash,
            "attempt_id_digest": self.attempt_id_digest,
            "reason_code": self.reason_code.value,
            "phase": self.phase.value,
            "adapter_invoked": self.adapter_invoked,
        }

    def audit_evidence(self) -> dict[str, str]:
        """Return the ``execution_evidence`` payload of the refusal record.

        Values are strings so the record shares the audit layer's existing
        ``dict[str, str]`` evidence contract; ``adapter_invoked`` is rendered
        as the exact literal ``"false"`` and is never omitted.
        """

        return {
            "schema": self.schema,
            "request_id_digest": self.request_id_digest,
            "receipt_id_digest": self.receipt_id_digest,
            "receipt_hash": self.receipt_hash,
            "tenant_digest": self.tenant_digest,
            "execution_boundary_digest": self.execution_boundary_digest,
            "adapter_id_digest": self.adapter_id_digest,
            "authorization_audit_digest": self.authorization_audit_digest,
            "binding_hash": self.binding_hash,
            "argument_hash": self.argument_hash,
            "attempt_id_digest": self.attempt_id_digest,
            "reason_code": self.reason_code.value,
            "phase": self.phase.value,
            "adapter_invoked": "false",
        }

    @classmethod
    def from_audit_evidence(cls, evidence: Mapping[str, Any]) -> ExecutionRefusalEvidence:
        """Rebuild the unproven evidence claims carried by a refusal record.

        Only the claims the audit record itself commits are restored; ``audited``
        and ``signed`` stay false because a record cannot attest its own
        proofs. Round-tripping :meth:`audit_evidence` against the result is the
        canonical way to validate a refusal record's schema and values.
        """

        if not isinstance(evidence, Mapping):
            raise TypeError("refusal audit evidence must be a mapping")
        adapter_invoked = evidence.get("adapter_invoked")
        if type(adapter_invoked) is not str:
            raise TypeError("adapter_invoked must be a string")
        # ``reason_code`` and ``phase`` name the enum members the record commits.
        # Require the exact string type before enum construction so missing or
        # non-string evidence fails closed with a clear error rather than being
        # coerced through the enum constructor with a weakened type.
        reason_code = evidence.get("reason_code")
        if type(reason_code) is not str:
            raise TypeError("reason_code must be a string")
        phase = evidence.get("phase")
        if type(phase) is not str:
            raise TypeError("phase must be a string")
        return cls(
            request_id_digest=cast(str, evidence.get("request_id_digest")),
            receipt_id_digest=cast(str, evidence.get("receipt_id_digest")),
            receipt_hash=cast(str, evidence.get("receipt_hash")),
            tenant_digest=cast(str, evidence.get("tenant_digest")),
            execution_boundary_digest=cast(str, evidence.get("execution_boundary_digest")),
            adapter_id_digest=cast(str, evidence.get("adapter_id_digest")),
            authorization_audit_digest=cast(str, evidence.get("authorization_audit_digest")),
            binding_hash=cast(str, evidence.get("binding_hash")),
            argument_hash=cast(str, evidence.get("argument_hash")),
            reason_code=ExecutionReasonCode(reason_code),
            phase=ExecutionRefusalPhase(phase),
            # Anything other than the exact literal "false" is treated as a
            # claim that the adapter ran, which this type refuses to represent.
            adapter_invoked=adapter_invoked != "false",
            attempt_id_digest=cast(str, evidence.get("attempt_id_digest", "")),
            audited=False,
        )

    def _payload_dict(self) -> dict[str, JSONValue]:
        return {
            **self._audit_state_dict(),
            "audited": self.audited,
            "audit_event_id": self.audit_event_id,
            "audit_event_hash": self.audit_event_hash,
            "audit_checkpoint_hash": self.audit_checkpoint_hash,
            "audit_checkpoint_parent_hash": self.audit_checkpoint_parent_hash,
            "signing_key_id": self.signing_key_id,
            "signature_algorithm": self.signature_algorithm,
        }

    def _payload_hash_matches(self) -> bool:
        try:
            expected = strict_json_hash(self._payload_dict())
            return type(self.payload_hash) is str and hmac.compare_digest(
                expected,
                self.payload_hash,
            )
        except Exception:
            return False

    def verify_signature(self, verifier: Any) -> bool:
        if not self.signed or not self._payload_hash_matches():
            return False
        try:
            return bool(
                verifier.key_id == self.signing_key_id
                and verifier.algorithm == self.signature_algorithm
                and verifier.verify(self.payload_hash.encode("utf-8"), self.signature)
            )
        except Exception:
            return False

    def verify_integrity(
        self,
        *,
        verifier: Any | None = None,
        audit: Any | None = None,
    ) -> bool:
        """Verify either independent proof without inventing missing trust.

        A valid signing proof is sufficient. Otherwise an audited refusal is
        accepted only when its exact ``EXECUTION_REFUSAL`` record is committed
        in a valid strict externally checkpointed chain and every bound claim
        matches this object.

        Unlike an authorization refusal, the record must *not* be required to
        be the chain head: concurrent attempts legitimately append after it.
        Inclusion is instead proved the way the audit layer proves a
        non-head commit — the record's own checkpoint is linked either by
        being the current signed anchor, or by being the checkpoint parent
        embedded in the immediately following committed event.
        """

        if not self._payload_hash_matches():
            return False
        if verifier is not None and self.verify_signature(verifier):
            return True
        if not self.audited or audit is None:
            return False
        try:
            from gove_zone.audit import AuditCheckpoint, ChainHashAuditStore

            if not isinstance(audit, ChainHashAuditStore):
                return False
            verification = audit.verify_checkpointed_chain()
            if not verification.get("valid") or not verification.get("strict"):
                return False
            checkpoint_wire = verification.get("checkpoint")
            if type(checkpoint_wire) is not dict:
                return False
            checkpoint = AuditCheckpoint(
                namespace=checkpoint_wire["namespace"],
                generation=checkpoint_wire["generation"],
                head_hash=checkpoint_wire["head_hash"],
                previous_checkpoint_hash=checkpoint_wire["previous_checkpoint_hash"],
                key_id=checkpoint_wire["key_id"],
                algorithm=checkpoint_wire["algorithm"],
                signature=checkpoint_wire["signature"],
            )
            events = list(audit.iter_events())
            matches = [
                index
                for index, event in enumerate(events)
                if event.get("event_id") == self.audit_event_id
            ]
            if len(matches) != 1:
                return False
            index = matches[0]
            event = events[index]
            if index + 1 < len(events):
                # A later event exists: its embedded checkpoint parent is the
                # checkpoint that committed this refusal.
                linked = events[index + 1].get("_audit_checkpoint_parent_hash")
            else:
                # Still the head: the current signed anchor is this refusal's
                # own committing checkpoint.
                linked = checkpoint.checkpoint_hash
                if checkpoint.head_hash != self.audit_event_hash:
                    return False
            if type(linked) is not str or not hmac.compare_digest(
                linked,
                self.audit_checkpoint_hash,
            ):
                return False
            return bool(
                event.get("event_hash") == self.audit_event_hash
                and event.get("_audit_checkpoint_parent_hash") == self.audit_checkpoint_parent_hash
                and event.get("record_kind") == "execution_refusal"
                and event.get("decision") == Decision.DENY.value
                and event.get("argument_hash") == self.argument_hash
                and event.get("matched_rules") == [self.reason_code.value]
                and event.get("reason") == self.reason_code.value
                and event.get("execution_evidence") == self.audit_evidence()
                and event.get("state_hash") == strict_json_hash(self._audit_state_dict())
            )
        except Exception:
            return False

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            **self._payload_dict(),
            "signed": self.signed,
            "signature": self.signature,
            "payload_hash": self.payload_hash,
        }


class AuthorizationError(RuntimeError):
    def __init__(
        self,
        reason_code: AuthorizationReasonCode,
        *,
        evidence: RefusalEvidence | None = None,
    ) -> None:
        if not isinstance(reason_code, AuthorizationReasonCode):
            raise TypeError("reason_code must be an AuthorizationReasonCode")
        if evidence is not None and not isinstance(evidence, RefusalEvidence):
            raise TypeError("evidence must be RefusalEvidence")
        self.reason_code = reason_code
        self.evidence = evidence
        super().__init__(reason_code.value)

    def to_dict(self) -> dict[str, str]:
        return {"status": "error", "reason_code": self.reason_code.value}


class SideEffectExecutionError(RuntimeError):
    non_retryable = True

    def __init__(
        self,
        reason_code: ExecutionReasonCode,
        *,
        evidence: ExecutionRefusalEvidence | None = None,
    ) -> None:
        if not isinstance(reason_code, ExecutionReasonCode):
            raise TypeError("reason_code must be an ExecutionReasonCode")
        if evidence is not None:
            if not isinstance(evidence, ExecutionRefusalEvidence):
                raise TypeError("evidence must be ExecutionRefusalEvidence")
            if evidence.reason_code is not reason_code:
                raise ValueError("refusal evidence must carry the original reason code")
        self.reason_code = reason_code
        self.evidence = evidence
        super().__init__(reason_code.value)

    def to_dict(self) -> dict[str, JSONValue]:
        # The original ExecutionReasonCode stays primary and unchanged: evidence
        # is additive proof, never a reclassification of the refusal.
        payload: dict[str, JSONValue] = {
            "status": "error",
            "reason_code": self.reason_code.value,
            "retryable": False,
        }
        if self.evidence is None:
            return payload
        # Exact evidence, not a summary: a consumer must be able to rebuild the
        # object and independently verify it. ``audited``/``signed`` state which
        # proof paths exist and may both be false; absent proofs are never faked.
        payload["execution_refusal_evidence"] = self.evidence.to_dict()
        payload["execution_refusal_audited"] = self.evidence.audited
        payload["execution_refusal_signed"] = self.evidence.signed
        payload["execution_refusal_audit_event_id"] = self.evidence.audit_event_id
        return payload


def _validated_hmac_key(key: Any) -> bytes:
    if type(key) is not bytes or len(key) < MINIMUM_HMAC_KEY_BYTES:
        raise ValueError("binding_hmac_key must contain at least 32 bytes")
    return key


def _validated_allowed_validator_roles(roles: Collection[str]) -> frozenset[str]:
    if isinstance(roles, (str, bytes)) or not roles:
        raise ValueError("allowed_validator_roles must be a non-empty collection")
    return frozenset(_require_text(role, "allowed validator role") for role in roles)


def _digest_secret(value: str, tenant_id: str, *, domain: bytes, key: bytes) -> str:
    safe_value = _require_text(value, "secret-derived binding value")
    tenant = _require_text(tenant_id, "tenant_id")
    key = _validated_hmac_key(key)
    tenant_bytes = tenant.encode("utf-8")
    value_bytes = safe_value.encode("utf-8")
    payload = (
        domain
        + len(tenant_bytes).to_bytes(8, "big")
        + tenant_bytes
        + len(value_bytes).to_bytes(8, "big")
        + value_bytes
    )
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def nonce_binding_digest(
    nonce: str,
    tenant_id: str,
    *,
    binding_hmac_key: bytes,
) -> str:
    """Return the tenant/domain-bound digest persisted in a receipt binding.

    The raw nonce remains caller-held and is required again at the final
    execution gate.  Exposing the exact existing derivation prevents adapters
    from inventing a second canonicalization or secret-binding scheme.
    """

    return _digest_secret(
        nonce,
        tenant_id,
        domain=_NONCE_HMAC_DOMAIN,
        key=binding_hmac_key,
    )


def idempotency_binding_digest(
    idempotency_key: str,
    tenant_id: str,
    *,
    binding_hmac_key: bytes,
) -> str:
    """Return the tenant/domain-bound idempotency digest for final gating."""

    return _digest_secret(
        idempotency_key,
        tenant_id,
        domain=_IDEMPOTENCY_HMAC_DOMAIN,
        key=binding_hmac_key,
    )


def compute_evidence_digest(evidence: Sequence[EvidenceRef]) -> str:
    if type(evidence) not in (list, tuple):
        raise TypeError("evidence must be a list or tuple")
    if any(not isinstance(item, EvidenceRef) for item in evidence):
        raise TypeError("evidence must contain only EvidenceRef values")
    return strict_json_hash([item.digest_dict() for item in evidence])


def build_reserved_binding(
    request: SideEffectRequest,
    principal: VerifiedPrincipal,
    resolved_policy: ResolvedPolicy,
    approved_arguments: Mapping[str, Any],
    *,
    audit_checkpoint: Mapping[str, Any],
    decision: Decision,
    authorized_at: str,
    expires_at: str,
    binding_hmac_key: bytes,
    allowed_validator_roles: Collection[str],
) -> Mapping[str, Any]:
    """Build the complete immutable receipt constraint binding."""

    if not isinstance(request, SideEffectRequest):
        raise TypeError("request must be a SideEffectRequest")
    if not isinstance(principal, VerifiedPrincipal):
        raise TypeError("principal must be a VerifiedPrincipal")
    if not isinstance(resolved_policy, ResolvedPolicy):
        raise TypeError("resolved_policy must be a ResolvedPolicy")
    if not isinstance(decision, Decision):
        raise TypeError("decision must use the existing Decision enum")
    checkpoint = _plain_mapping(_freeze_mapping(audit_checkpoint, field_name="audit_checkpoint"))
    key = _validated_hmac_key(binding_hmac_key)
    expected_identity = (
        request.tenant_id,
        request.actor_id,
        request.actor_role,
        request.authority,
    )
    resolved_identity = (
        principal.tenant_id,
        principal.actor_id,
        principal.role,
        principal.authority,
    )
    if expected_identity != resolved_identity:
        raise ValueError("request and verified principal are inconsistent")
    if request.policy_ref != resolved_policy.ref:
        raise ValueError("request and resolved policy are inconsistent")
    if resolved_policy.ref.tenant_id != principal.tenant_id:
        raise ValueError("principal and policy tenants are inconsistent")
    if resolved_policy.authority != request.authority:
        raise ValueError("request and policy authority are inconsistent")
    if resolved_policy.validator.validator_id == principal.actor_id:
        raise ValueError("self-validation is forbidden")
    allowed_roles = _validated_allowed_validator_roles(allowed_validator_roles)
    if resolved_policy.validator.role not in allowed_roles:
        raise ValueError("validator role is not allowed")
    authorized = _normalize_utc_timestamp(authorized_at, "authorized_at")
    expires = _normalize_utc_timestamp(expires_at, "expires_at")
    requested_dt = _as_datetime(request.requested_at)
    authorized_dt = _as_datetime(authorized)
    expires_dt = _as_datetime(expires)
    if not (
        _as_datetime(principal.verified_at)
        <= requested_dt
        <= authorized_dt
        < expires_dt
        <= _as_datetime(principal.expires_at)
    ):
        raise ValueError("principal or authorization is not valid for the request window")
    for evidence in request.evidence:
        if not (
            _as_datetime(evidence.issued_at)
            <= requested_dt
            <= authorized_dt
            < expires_dt
            <= _as_datetime(evidence.expires_at)
        ):
            raise ValueError("evidence is not valid for the authorization window")
    approved = _freeze_mapping(approved_arguments, field_name="approved_arguments")
    original_hash = strict_json_hash(_plain_mapping(request.args))
    approved_hash = strict_json_hash(_plain_mapping(approved))
    if decision is Decision.ALLOW and approved_hash != original_hash:
        raise ValueError("ALLOW must approve the original arguments exactly")
    if decision in (Decision.DENY, Decision.ESCALATE) and _plain_mapping(approved):
        raise ValueError("non-executable decisions cannot approve arguments")
    binding: dict[str, JSONValue] = {
        "schema": SIDE_EFFECT_BINDING_KEY,
        "argument_canonicalization_profile": ARGUMENT_CANONICALIZATION_PROFILE,
        "secret_digest_profile": SECRET_DIGEST_PROFILE,
        "request_id": request.request_id,
        "tenant_id": principal.tenant_id,
        "actor_id": principal.actor_id,
        "actor_role": principal.role,
        "authority": principal.authority,
        "server_id": request.server_id,
        "tool": request.tool,
        "operation": request.operation,
        "resource": request.resource,
        "environment": request.environment,
        "execution_boundary": request.execution_boundary,
        "side_effect_class": request.side_effect_class,
        "goal_hash": _goal_hash(request.goal),
        "authorized_at": authorized,
        "policy": resolved_policy.ref.to_dict(),
        "policy_attestation": resolved_policy.attestation.to_dict(),
        "audit_checkpoint": checkpoint,
        "requested_at": request.requested_at,
        "expires_at": expires,
        "principal_verified_at": principal.verified_at,
        "principal_expires_at": principal.expires_at,
        "nonce_digest": nonce_binding_digest(
            request.nonce,
            principal.tenant_id,
            binding_hmac_key=key,
        ),
        "idempotency_digest": idempotency_binding_digest(
            request.idempotency_key,
            principal.tenant_id,
            binding_hmac_key=key,
        ),
        "evidence_identifiers": [item.identifier_dict() for item in request.evidence],
        "evidence_digest": compute_evidence_digest(request.evidence),
        "original_arguments_hash": original_hash,
        "approved_arguments_hash": approved_hash,
        "validator_id": resolved_policy.validator.validator_id,
        "validator_role": resolved_policy.validator.role,
        "authentication_context_hash": strict_json_hash(
            _plain_mapping(principal.authentication_context)
        ),
        "decision": decision.value,
    }
    _validate_reserved_binding_shape(binding)
    frozen = deep_freeze_json(binding)
    if not isinstance(frozen, Mapping):
        raise TypeError("reserved binding must be an object")
    return frozen


def reserved_binding_hash(binding: Mapping[str, Any]) -> str:
    if not isinstance(binding, MappingProxyType):
        raise TypeError("binding must be an immutable reserved binding")
    return strict_json_hash(_plain_mapping(binding))


def reserved_constraints(binding: Mapping[str, Any]) -> dict[str, JSONValue]:
    if not isinstance(binding, MappingProxyType):
        raise TypeError("binding must be an immutable reserved binding")
    return {SIDE_EFFECT_BINDING_KEY: _plain_mapping(binding)}
