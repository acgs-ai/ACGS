"""Deterministic single-payment policy primitives for the P2 Spend Guard.

This module is deliberately policy-only.  It normalizes a proposed payment,
evaluates static single-payment constraints, and verifies an optional signed
approval.  It does not reserve aggregate budget or call a payment provider.
"""

from __future__ import annotations

import hashlib
import math
import re
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import MappingProxyType
from typing import Any, cast

from gove_zone.authorization import EvidenceRef
from gove_zone.decision import Decision, DecisionRecord, canonical_json, sha256_json
from gove_zone.errors import SigningError
from gove_zone.policy import Policy, PolicyArtifactSnapshot, new_event_id
from gove_zone.signing import Ed25519Signer, ReceiptSigner
from gove_zone.tool import ToolCall

SPEND_OPERATION = "spend.payment.create"
SPEND_POLICY_SCHEMA = "acgs.spend-policy/v1"
SPEND_APPROVAL_SCHEMA = "acgs.spend-approval/v1"
SPEND_APPROVAL_EVIDENCE_TYPE = "acgs.spend-approval"

_ARGUMENT_KEYS = {"provider", "recipient", "amount", "currency", "reference"}
_CONTEXT_KEYS = {
    "tenant_id",
    "authority",
    "resource",
    "environment",
    "request_id",
    "requested_at",
}
_POLICY_KEYS = {
    "kind",
    "policy_id",
    "version",
    "operation",
    "currency_exponent_version",
    "currency_exponents",
    "single_payment_limit_minor",
    "allowed_providers",
    "allowed_recipients",
    "allowed_approver_roles",
    "approval_public_keys",
    "approval_ttl_seconds",
}
_PAYLOAD_KEYS = {
    "tenant_id",
    "actor_id",
    "authority",
    "provider",
    "recipient",
    "amount",
    "currency",
    "reference",
    "resource",
    "environment",
    "request_id",
    "policy_id",
    "policy_version",
    "policy_digest",
    "issued_at",
    "expires_at",
    "approver_id",
    "approver_role",
}
_CLAIM_KEYS = {"schema", "payload", "evidence", "algorithm", "key_id", "signature"}
_EVIDENCE_KEYS = {
    "evidence_id",
    "evidence_type",
    "digest",
    "issuer",
    "issued_at",
    "expires_at",
}
_AMOUNT_RE = re.compile(r"[0-9]+(?:\.[0-9]+)?", re.ASCII)
_IDENTITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}", re.ASCII)
_REFERENCE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", re.ASCII)
_CURRENCY_RE = re.compile(r"[A-Za-z]{3}", re.ASCII)
_SHA256_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
_SIGNATURE_RE = re.compile(r"[0-9a-f]{128}", re.ASCII)
_MAX_MINOR_UNITS = (1 << 63) - 1
_MAX_AMOUNT_CHARACTERS = 128
_MAX_SNAPSHOT_DEPTH = 16
_MAX_SNAPSHOT_ITEMS = 512
_MAX_SNAPSHOT_SCALAR_BYTES = 8192
_MAX_SNAPSHOT_TOTAL_BYTES = 65536
_FINGERPRINT_PREFIX_BYTES = 256
_MAX_FINGERPRINT_COLLECTION_ITEMS = 64
_MAX_FINGERPRINT_CHILD_NODES = 32


class SpendValidationError(ValueError):
    """A stable fail-closed normalization failure."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def _ascii_identity(value: Any, field_name: str) -> str:
    if type(value) is not str or _IDENTITY_RE.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a canonical ASCII identity")
    return value


def _ascii_reference(value: Any) -> str:
    if type(value) is not str or _REFERENCE_RE.fullmatch(value) is None:
        raise ValueError("reference must be a canonical ASCII reference")
    return value


def _normalized_timestamp(value: Any, field_name: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{field_name} must be a non-empty timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"{field_name} must be an ISO-8601 timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must be a UTC timestamp")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _as_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _exact_dict(value: Any, keys: set[str], field_name: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise TypeError(f"{field_name} must be a dictionary")
    if set(value) != keys:
        raise ValueError(f"{field_name} has an incompatible shape")
    return cast(dict[str, Any], value)


def _strict_sequence(value: Any, field_name: str, *, allow_empty: bool) -> tuple[str, ...]:
    if type(value) is not list or (not allow_empty and not value):
        raise TypeError(f"{field_name} must be a {'non-empty ' if not allow_empty else ''}list")
    items = tuple(_ascii_identity(item, field_name) for item in value)
    if len(set(items)) != len(items):
        raise ValueError(f"{field_name} must not contain duplicates")
    return tuple(sorted(items))


def _canonical_amount(amount: Any, exponent: int) -> tuple[str, int]:
    if type(amount) is not str:
        raise SpendValidationError("SPEND_AMOUNT_TYPE", "amount must be a string")
    if len(amount) > _MAX_AMOUNT_CHARACTERS:
        raise SpendValidationError("SPEND_AMOUNT_RANGE", "amount exceeds its character limit")
    if _AMOUNT_RE.fullmatch(amount) is None or not amount.isascii():
        raise SpendValidationError(
            "SPEND_AMOUNT_FORMAT",
            "amount must contain only ASCII decimal digits and an optional decimal point",
        )
    whole, separator, fraction = amount.partition(".")
    if separator and len(fraction) > exponent:
        raise SpendValidationError(
            "SPEND_AMOUNT_PRECISION",
            "amount has more fractional digits than the currency exponent",
        )
    if exponent == 0 and separator:
        raise SpendValidationError(
            "SPEND_AMOUNT_PRECISION",
            "currency does not permit fractional digits",
        )
    minor_text = (whole + fraction.ljust(exponent, "0")).lstrip("0") or "0"
    maximum_text = str(_MAX_MINOR_UNITS)
    if (
        minor_text == "0"
        or len(minor_text) > len(maximum_text)
        or (len(minor_text) == len(maximum_text) and minor_text > maximum_text)
    ):
        raise SpendValidationError(
            "SPEND_AMOUNT_RANGE",
            "amount minor units must be between 1 and 2^63-1",
        )
    minor_units = int(minor_text)
    scale = 10**exponent
    canonical_whole, canonical_fraction = divmod(minor_units, scale)
    canonical = str(canonical_whole)
    if exponent:
        canonical = f"{canonical}.{canonical_fraction:0{exponent}d}"
    return canonical, minor_units


@dataclass(frozen=True, slots=True)
class NormalizedSpendArguments:
    provider: str
    recipient: str
    amount: str
    currency: str
    reference: str
    amount_minor: int

    def to_arguments(self) -> dict[str, str]:
        return {
            "provider": self.provider,
            "recipient": self.recipient,
            "amount": self.amount,
            "currency": self.currency,
            "reference": self.reference,
        }


def normalize_spend_arguments(
    arguments: Mapping[str, Any],
    currency_exponents: Mapping[str, int],
) -> NormalizedSpendArguments:
    """Return a deterministic, complete payment argument map without rounding."""
    if type(arguments) is not dict or set(arguments) != _ARGUMENT_KEYS:
        raise SpendValidationError(
            "SPEND_ARGUMENT_SHAPE",
            "payment arguments must contain exactly provider, recipient, amount, "
            "currency, reference",
        )
    try:
        provider = _ascii_identity(arguments["provider"], "provider")
        recipient = _ascii_identity(arguments["recipient"], "recipient")
        reference = _ascii_reference(arguments["reference"])
    except (TypeError, ValueError) as exc:
        raise SpendValidationError("SPEND_IDENTITY_FORMAT", str(exc)) from None
    raw_currency = arguments["currency"]
    if type(raw_currency) is not str or _CURRENCY_RE.fullmatch(raw_currency) is None:
        raise SpendValidationError(
            "SPEND_CURRENCY_FORMAT",
            "currency must be a three-letter ASCII code",
        )
    currency = raw_currency.upper()
    exponent = currency_exponents.get(currency)
    if type(exponent) is not int or isinstance(exponent, bool):
        raise SpendValidationError(
            "SPEND_CURRENCY_UNSUPPORTED",
            "currency is not supported by the pinned exponent table",
        )
    canonical_amount, minor_units = _canonical_amount(arguments["amount"], exponent)
    return NormalizedSpendArguments(
        provider=provider,
        recipient=recipient,
        amount=canonical_amount,
        currency=currency,
        reference=reference,
        amount_minor=minor_units,
    )


@dataclass(frozen=True, slots=True)
class SpendApprovalPayload:
    tenant_id: str
    actor_id: str
    authority: str
    provider: str
    recipient: str
    amount: str
    currency: str
    reference: str
    resource: str
    environment: str
    request_id: str
    policy_id: str
    policy_version: str
    policy_digest: str
    issued_at: str
    expires_at: str
    approver_id: str
    approver_role: str

    def __post_init__(self) -> None:
        for field_name in (
            "tenant_id",
            "actor_id",
            "authority",
            "provider",
            "recipient",
            "resource",
            "environment",
            "request_id",
            "policy_id",
            "policy_version",
            "approver_id",
            "approver_role",
        ):
            object.__setattr__(
                self,
                field_name,
                _ascii_identity(getattr(self, field_name), field_name),
            )
        object.__setattr__(self, "reference", _ascii_reference(self.reference))
        if type(self.amount) is not str or _AMOUNT_RE.fullmatch(self.amount) is None:
            raise ValueError("approval amount must be an ASCII decimal string")
        if type(self.currency) is not str or not re.fullmatch(r"[A-Z]{3}", self.currency):
            raise ValueError("approval currency must be an uppercase ASCII code")
        if type(self.policy_digest) is not str or _SHA256_RE.fullmatch(self.policy_digest) is None:
            raise ValueError("policy_digest must be 64 lowercase SHA-256 hex characters")
        issued_at = _normalized_timestamp(self.issued_at, "issued_at")
        expires_at = _normalized_timestamp(self.expires_at, "expires_at")
        if _as_datetime(expires_at) <= _as_datetime(issued_at):
            raise ValueError("approval expiry must be after issuance")
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)

    def to_dict(self) -> dict[str, str]:
        return {field_name: cast(str, getattr(self, field_name)) for field_name in _PAYLOAD_KEYS}

    @classmethod
    def from_dict(cls, value: Any) -> SpendApprovalPayload:
        raw = _exact_dict(value, _PAYLOAD_KEYS, "approval payload")
        if any(type(item) is not str for item in raw.values()):
            raise TypeError("approval payload fields must be strings")
        return cls(**cast(dict[str, str], raw))


def _claim_unsigned_dict(
    payload: SpendApprovalPayload,
    evidence: EvidenceRef,
    algorithm: str,
    key_id: str,
) -> dict[str, Any]:
    return {
        "schema": SPEND_APPROVAL_SCHEMA,
        "payload": payload.to_dict(),
        "evidence": evidence.to_dict(),
        "algorithm": algorithm,
        "key_id": key_id,
    }


@dataclass(frozen=True, slots=True)
class SpendApprovalClaim:
    payload: SpendApprovalPayload
    evidence: EvidenceRef
    algorithm: str
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        if not isinstance(self.payload, SpendApprovalPayload):
            raise TypeError("payload must be SpendApprovalPayload")
        if not isinstance(self.evidence, EvidenceRef):
            raise TypeError("evidence must be EvidenceRef")
        if self.algorithm != "ed25519":
            raise ValueError("approval algorithm must be ed25519")
        _ascii_identity(self.key_id, "key_id")
        if type(self.signature) is not str or _SIGNATURE_RE.fullmatch(self.signature) is None:
            raise ValueError("approval signature must be 128 lowercase hex characters")

    @classmethod
    def issue(
        cls,
        payload: SpendApprovalPayload,
        signer: ReceiptSigner,
    ) -> SpendApprovalClaim:
        if signer.algorithm != "ed25519":
            raise SigningError("spend approvals require an Ed25519 signer")
        key_id = _ascii_identity(signer.key_id, "key_id")
        evidence = EvidenceRef(
            evidence_id=payload.request_id,
            evidence_type=SPEND_APPROVAL_EVIDENCE_TYPE,
            digest=sha256_json(payload.to_dict()),
            issuer=payload.approver_id,
            issued_at=payload.issued_at,
            expires_at=payload.expires_at,
        )
        unsigned = _claim_unsigned_dict(payload, evidence, signer.algorithm, key_id)
        signature = signer.sign(canonical_json(unsigned).encode("utf-8"))
        return cls(payload, evidence, signer.algorithm, key_id, signature)

    def to_dict(self) -> dict[str, Any]:
        return {
            **_claim_unsigned_dict(self.payload, self.evidence, self.algorithm, self.key_id),
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, value: Any) -> SpendApprovalClaim:
        raw = _exact_dict(value, _CLAIM_KEYS, "approval claim")
        if raw["schema"] != SPEND_APPROVAL_SCHEMA:
            raise ValueError("approval claim schema is unsupported")
        evidence_raw = _exact_dict(raw["evidence"], _EVIDENCE_KEYS, "approval evidence")
        if any(type(item) is not str for item in evidence_raw.values()):
            raise TypeError("approval evidence fields must be strings")
        evidence = EvidenceRef(**cast(dict[str, str], evidence_raw))
        return cls(
            payload=SpendApprovalPayload.from_dict(raw["payload"]),
            evidence=evidence,
            algorithm=cast(str, raw["algorithm"]),
            key_id=cast(str, raw["key_id"]),
            signature=cast(str, raw["signature"]),
        )

    def signing_bytes(self) -> bytes:
        return canonical_json(
            _claim_unsigned_dict(self.payload, self.evidence, self.algorithm, self.key_id)
        ).encode("utf-8")


class _SnapshotBudgetExceeded(ValueError):
    pass


@dataclass(slots=True)
class _SnapshotBudget:
    items: int = 0
    total_bytes: int = 0

    def consume(self, byte_count: int) -> None:
        self.items += 1
        self.total_bytes += byte_count
        if self.items > _MAX_SNAPSHOT_ITEMS:
            raise _SnapshotBudgetExceeded("request exceeds its item budget")
        if self.total_bytes > _MAX_SNAPSHOT_TOTAL_BYTES:
            raise _SnapshotBudgetExceeded("request exceeds its byte budget")


def _freeze_exact_json(value: Any, budget: _SnapshotBudget, depth: int = 0) -> Any:
    if depth > _MAX_SNAPSHOT_DEPTH:
        raise _SnapshotBudgetExceeded("request exceeds its depth budget")
    if value is None or type(value) is bool:
        budget.consume(1)
        return value
    if type(value) is int:
        byte_count = max(1, (abs(value).bit_length() + 7) // 8)
        if byte_count > _MAX_SNAPSHOT_SCALAR_BYTES:
            raise _SnapshotBudgetExceeded("integer exceeds its scalar budget")
        budget.consume(byte_count)
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("request floats must be finite")
        budget.consume(8)
        return value
    if type(value) is str:
        if len(value) > _MAX_SNAPSHOT_SCALAR_BYTES:
            raise _SnapshotBudgetExceeded("string exceeds its scalar budget")
        encoded = value.encode("utf-8")
        if len(encoded) > _MAX_SNAPSHOT_SCALAR_BYTES:
            raise _SnapshotBudgetExceeded("string exceeds its scalar budget")
        budget.consume(len(encoded))
        return value
    if type(value) is list:
        budget.consume(1)
        return tuple(_freeze_exact_json(item, budget, depth + 1) for item in value)
    if type(value) is dict:
        budget.consume(1)
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("request dictionary keys must be strings")
            _freeze_exact_json(key, budget, depth + 1)
            frozen[key] = _freeze_exact_json(item, budget, depth + 1)
        return MappingProxyType(frozen)
    raise TypeError("request contains a non-exact JSON value")


def _thaw_exact_json(value: Any) -> Any:
    if type(value) is MappingProxyType:
        return {key: _thaw_exact_json(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_thaw_exact_json(item) for item in value]
    return value


@dataclass(slots=True)
class _FingerprintBudget:
    nodes: int = 0
    limit: int = _MAX_SNAPSHOT_ITEMS

    def available(self, depth: int) -> bool:
        if depth > _MAX_SNAPSHOT_DEPTH or self.nodes >= self.limit:
            return False
        self.nodes += 1
        return True


def _bounded_bytes_node(tag: str, data: bytes) -> dict[str, Any]:
    prefix = data[:_FINGERPRINT_PREFIX_BYTES]
    return {
        "type": tag,
        "length": len(data),
        "prefix_digest": hashlib.sha256(prefix).hexdigest(),
        "truncated": len(data) > len(prefix),
    }


def _fingerprint_node(value: Any, budget: _FingerprintBudget, depth: int = 0) -> Any:
    if not budget.available(depth):
        return {"type": "truncated", "reason": "structural-budget"}
    if value is None:
        return {"type": "none"}
    if type(value) is bool:
        return {"type": "bool", "value": value}
    if type(value) is int:
        magnitude = abs(value)
        prefix = (magnitude & ((1 << 2048) - 1)).to_bytes(256, "big")
        return {
            "type": "int",
            "negative": value < 0,
            "bits": magnitude.bit_length(),
            "low_digest": hashlib.sha256(prefix).hexdigest(),
            "truncated": magnitude.bit_length() > 2048,
        }
    if type(value) is float:
        return _bounded_bytes_node("float", struct.pack("!d", value))
    if type(value) is str:
        prefix = value[:_FINGERPRINT_PREFIX_BYTES].encode("utf-8")
        return {
            "type": "str",
            "character_length": len(value),
            "prefix_digest": hashlib.sha256(prefix).hexdigest(),
            "truncated": len(value) > _FINGERPRINT_PREFIX_BYTES,
        }
    if type(value) is bytes:
        return _bounded_bytes_node("bytes", value)
    if type(value) is Decimal:
        decimal_tuple = value.as_tuple()
        digits = bytes(decimal_tuple.digits[:_FINGERPRINT_PREFIX_BYTES])
        exponent = decimal_tuple.exponent
        exponent_node = (
            {"kind": "int", "value": exponent} if type(exponent) is int else {"kind": "special"}
        )
        return {
            "type": "decimal",
            "sign": decimal_tuple.sign,
            "digits": _bounded_bytes_node("decimal-digits", digits),
            "digit_count": len(decimal_tuple.digits),
            "exponent": exponent_node,
            "truncated": len(decimal_tuple.digits) > len(digits),
        }
    if type(value) in (list, tuple):
        tag = "list" if type(value) is list else "tuple"
        items: list[Any] = []
        for item in value:
            if budget.nodes >= _MAX_SNAPSHOT_ITEMS:
                items.append({"type": "truncated", "reason": "item-budget"})
                break
            items.append(_fingerprint_node(item, budget, depth + 1))
        return {"type": tag, "length": len(value), "items": items}
    if type(value) in (set, frozenset):
        tag = "set" if type(value) is set else "frozenset"
        if len(value) > _MAX_FINGERPRINT_COLLECTION_ITEMS:
            return {"type": tag, "length": len(value), "truncated": True}
        item_digests: list[str] = []
        for item in value:
            child = _fingerprint_node(
                item,
                _FingerprintBudget(limit=_MAX_FINGERPRINT_CHILD_NODES),
                depth + 1,
            )
            item_digests.append(sha256_json(child))
        item_digests.sort()
        return {
            "type": tag,
            "length": len(value),
            "item_digests": item_digests,
            "truncated": False,
        }
    if type(value) is dict:
        if len(value) > _MAX_FINGERPRINT_COLLECTION_ITEMS:
            return {"type": "dict", "length": len(value), "truncated": True}
        pair_digests: list[str] = []
        for key, item in value.items():
            child_budget = _FingerprintBudget(limit=_MAX_FINGERPRINT_CHILD_NODES)
            pair = {
                "key": _fingerprint_node(key, child_budget, depth + 1),
                "value": _fingerprint_node(item, child_budget, depth + 1),
            }
            if _fingerprint_is_truncated(pair):
                return {"type": "dict", "length": len(value), "truncated": True}
            pair_digests.append(sha256_json(pair))
        pair_digests.sort()
        return {
            "type": "dict",
            "length": len(value),
            "pair_digests": pair_digests,
            "truncated": False,
        }
    # Unknown objects are one conservative refusal category. Never perform ABC
    # classification, inspect class metadata, or invoke object callbacks while
    # producing denial evidence.
    return {
        "type": "opaque-invalid",
        "equivalence": "all-nonexact-objects",
    }


def _fingerprint_is_truncated(value: Any) -> bool:
    if type(value) is dict:
        if value.get("truncated") is True or value.get("type") == "truncated":
            return True
        return any(_fingerprint_is_truncated(item) for item in value.values())
    if type(value) is list:
        return any(_fingerprint_is_truncated(item) for item in value)
    return False


def _invalid_structural_fingerprint(value: Any, component: str) -> str:
    node = _fingerprint_node(value, _FingerprintBudget())
    return sha256_json(
        {
            "domain": "acgs.spend.invalid-structure/v1",
            "component": component,
            "node": node,
        }
    )


_INVALID_CALL_SNAPSHOT_HASH = sha256_json(
    {
        "domain": "acgs.spend.invalid-call-snapshot/v1",
        "category": "nonexact-tool-call",
    }
)
_INVALID_CALL_REQUEST_HASH = sha256_json(
    {
        "domain": "acgs.spend.invalid-call-request/v1",
        "category": "nonexact-tool-call",
    }
)


@dataclass(frozen=True, slots=True)
class _IngressSnapshot:
    tool: str
    goal: str
    actor: str
    path: tuple[str, ...]
    args: Mapping[str, Any] | None
    state: Mapping[str, Any] | None
    argument_hash: str
    state_hash: str | None
    decision_request_hash: str
    valid: bool

    def arguments_dict(self) -> dict[str, Any]:
        assert self.args is not None
        return cast(dict[str, Any], _thaw_exact_json(self.args))

    def state_dict(self) -> dict[str, Any]:
        assert self.state is not None
        return cast(dict[str, Any], _thaw_exact_json(self.state))


def _snapshot_call(call: ToolCall) -> _IngressSnapshot:
    if type(call) is not ToolCall:
        return _IngressSnapshot(
            tool="invalid-tool",
            goal="",
            actor="",
            path=(),
            args=None,
            state=None,
            argument_hash=_INVALID_CALL_SNAPSHOT_HASH,
            state_hash=None,
            decision_request_hash=_INVALID_CALL_REQUEST_HASH,
            valid=False,
        )
    raw_tool = call.name
    raw_args = call.args
    raw_goal = call.goal
    raw_actor = call.actor
    raw_path = call.path
    raw_state = call.state
    valid_scalars = all(type(item) is str for item in (raw_tool, raw_goal, raw_actor))
    valid_path = type(raw_path) is tuple and all(type(item) is str for item in raw_path)
    args_frozen: Mapping[str, Any] | None = None
    state_frozen: Mapping[str, Any] | None = None
    try:
        if type(raw_args) is not dict:
            raise TypeError("arguments must be an exact dictionary")
        frozen_args = _freeze_exact_json(raw_args, _SnapshotBudget())
        assert type(frozen_args) is MappingProxyType
        args_frozen = frozen_args
        argument_hash = sha256_json(_thaw_exact_json(frozen_args))
    except (OverflowError, TypeError, ValueError):
        argument_hash = _invalid_structural_fingerprint(raw_args, "arguments")
    try:
        if type(raw_state) is not dict:
            raise TypeError("state must be an exact dictionary")
        frozen_state = _freeze_exact_json(raw_state, _SnapshotBudget())
        assert type(frozen_state) is MappingProxyType
        state_frozen = frozen_state
        state_plain = _thaw_exact_json(frozen_state)
        state_hash = sha256_json(state_plain) if state_plain else None
    except (OverflowError, TypeError, ValueError):
        state_hash = _invalid_structural_fingerprint(raw_state, "state")
    valid = valid_scalars and valid_path and args_frozen is not None and state_frozen is not None
    tool = raw_tool if type(raw_tool) is str else "invalid-tool"
    goal = raw_goal if type(raw_goal) is str else ""
    actor = raw_actor if type(raw_actor) is str else ""
    path = raw_path if valid_path else ()
    if valid:
        decision_request_hash = sha256_json(
            {
                "actor": actor,
                "path": list(path),
                "goal": goal,
                "tool": tool,
                "argument_hash": argument_hash,
                "state_hash": state_hash,
            }
        )
    else:
        decision_request_hash = sha256_json(
            {
                "domain": "acgs.spend.invalid-request/v1",
                "tool_category": ("exact-string" if type(raw_tool) is str else "invalid-scalar"),
                "argument_fingerprint": argument_hash,
                "state_fingerprint": state_hash,
                "valid_scalars": valid_scalars,
                "valid_path": valid_path,
            }
        )
    return _IngressSnapshot(
        tool=tool,
        goal=goal,
        actor=actor,
        path=path,
        args=args_frozen,
        state=state_frozen,
        argument_hash=argument_hash,
        state_hash=state_hash,
        decision_request_hash=decision_request_hash,
        valid=valid,
    )


@dataclass(frozen=True, slots=True)
class SpendPolicy(Policy):
    """Immutable static single-payment policy for the shared authorization kernel."""

    policy_id: str
    policy_version: str
    currency_exponent_version: str
    currency_exponents: tuple[tuple[str, int], ...]
    single_payment_limit_minor: int
    allowed_providers: tuple[str, ...]
    allowed_recipients: tuple[str, ...]
    allowed_approver_roles: tuple[str, ...]
    approval_public_keys: tuple[tuple[str, str], ...]
    approval_ttl_seconds: int = 300

    def __post_init__(self) -> None:
        for field_name in ("policy_id", "policy_version", "currency_exponent_version"):
            object.__setattr__(
                self,
                field_name,
                _ascii_identity(getattr(self, field_name), field_name),
            )
        if type(self.single_payment_limit_minor) is not int or isinstance(
            self.single_payment_limit_minor, bool
        ):
            raise TypeError("single_payment_limit_minor must be an integer")
        if not 1 <= self.single_payment_limit_minor <= _MAX_MINOR_UNITS:
            raise ValueError("single_payment_limit_minor is outside the supported range")
        if type(self.approval_ttl_seconds) is not int or isinstance(
            self.approval_ttl_seconds, bool
        ):
            raise TypeError("approval_ttl_seconds must be an integer")
        if not 1 <= self.approval_ttl_seconds <= 86400:
            raise ValueError("approval_ttl_seconds must be between 1 and 86400")
        object.__setattr__(
            self,
            "allowed_providers",
            self._validated_id_tuple(
                self.allowed_providers, "allowed_providers", allow_empty=False
            ),
        )
        object.__setattr__(
            self,
            "allowed_recipients",
            self._validated_id_tuple(
                self.allowed_recipients, "allowed_recipients", allow_empty=True
            ),
        )
        object.__setattr__(
            self,
            "allowed_approver_roles",
            self._validated_id_tuple(
                self.allowed_approver_roles,
                "allowed_approver_roles",
                allow_empty=False,
            ),
        )
        exponents: list[tuple[str, int]] = []
        if type(self.currency_exponents) is not tuple or not self.currency_exponents:
            raise TypeError("currency_exponents must be a non-empty tuple")
        for entry in self.currency_exponents:
            if type(entry) is not tuple or len(entry) != 2:
                raise TypeError("currency exponent entries must be pairs")
            currency, exponent = entry
            if type(currency) is not str or re.fullmatch(r"[A-Z]{3}", currency) is None:
                raise ValueError("currency exponent keys must be uppercase ASCII codes")
            if type(exponent) is not int or isinstance(exponent, bool) or not 0 <= exponent <= 9:
                raise ValueError("currency exponents must be integers between 0 and 9")
            exponents.append((currency, exponent))
        if len({key for key, _ in exponents}) != len(exponents):
            raise ValueError("currency_exponents must not contain duplicates")
        object.__setattr__(self, "currency_exponents", tuple(sorted(exponents)))
        public_keys: list[tuple[str, str]] = []
        if type(self.approval_public_keys) is not tuple:
            raise TypeError("approval_public_keys must be a tuple")
        for key_entry in self.approval_public_keys:
            if type(key_entry) is not tuple or len(key_entry) != 2:
                raise TypeError("approval public-key entries must be pairs")
            key_id, public_hex = key_entry
            _ascii_identity(key_id, "key_id")
            if type(public_hex) is not str or re.fullmatch(r"[0-9a-f]{64}", public_hex) is None:
                raise ValueError("approval public keys must be 32-byte lowercase hex")
            public_keys.append((key_id, public_hex))
        if len({key for key, _ in public_keys}) != len(public_keys):
            raise ValueError("approval_public_keys must not contain duplicates")
        object.__setattr__(self, "approval_public_keys", tuple(sorted(public_keys)))

    @staticmethod
    def _validated_id_tuple(
        value: tuple[str, ...],
        field_name: str,
        *,
        allow_empty: bool,
    ) -> tuple[str, ...]:
        if type(value) is not tuple or (not allow_empty and not value):
            raise TypeError(
                f"{field_name} must be a {'non-empty ' if not allow_empty else ''}tuple"
            )
        items = tuple(_ascii_identity(item, field_name) for item in value)
        if len(set(items)) != len(items):
            raise ValueError(f"{field_name} must not contain duplicates")
        return tuple(sorted(items))

    @property
    def version(self) -> str:
        return self.policy_version

    def _artifact(self) -> dict[str, Any]:
        return {
            "kind": SPEND_POLICY_SCHEMA,
            "policy_id": self.policy_id,
            "version": self.version,
            "operation": SPEND_OPERATION,
            "currency_exponent_version": self.currency_exponent_version,
            "currency_exponents": dict(self.currency_exponents),
            "single_payment_limit_minor": self.single_payment_limit_minor,
            "allowed_providers": list(self.allowed_providers),
            "allowed_recipients": list(self.allowed_recipients),
            "allowed_approver_roles": list(self.allowed_approver_roles),
            "approval_public_keys": dict(self.approval_public_keys),
            "approval_ttl_seconds": self.approval_ttl_seconds,
        }

    @property
    def artifact_digest(self) -> str:
        return hashlib.sha256(canonical_json(self._artifact()).encode("utf-8")).hexdigest()

    def authorization_snapshot(self) -> PolicyArtifactSnapshot:
        artifact = self._artifact()
        evaluator = SpendPolicy.from_authorization_snapshot(artifact)
        return PolicyArtifactSnapshot.from_artifact(artifact, evaluator=evaluator)

    @classmethod
    def from_authorization_snapshot(cls, value: Any) -> SpendPolicy:
        raw = _exact_dict(value, _POLICY_KEYS, "spend policy artifact")
        if raw["kind"] != SPEND_POLICY_SCHEMA or raw["operation"] != SPEND_OPERATION:
            raise ValueError("spend policy artifact kind or operation is unsupported")
        exponents_raw = raw["currency_exponents"]
        if type(exponents_raw) is not dict or not exponents_raw:
            raise TypeError("currency_exponents must be a non-empty dictionary")
        exponents: list[tuple[str, int]] = []
        for currency, exponent in exponents_raw.items():
            if type(currency) is not str:
                raise TypeError("currency exponent keys must be strings")
            exponents.append((currency, exponent))
        keys_raw = raw["approval_public_keys"]
        if type(keys_raw) is not dict:
            raise TypeError("approval_public_keys must be a dictionary")
        public_keys: list[tuple[str, str]] = []
        for key_id, public_hex in keys_raw.items():
            if type(key_id) is not str or type(public_hex) is not str:
                raise TypeError("approval public-key entries must be strings")
            public_keys.append((key_id, public_hex))
        return cls(
            policy_id=_ascii_identity(raw["policy_id"], "policy_id"),
            policy_version=_ascii_identity(raw["version"], "version"),
            currency_exponent_version=_ascii_identity(
                raw["currency_exponent_version"],
                "currency_exponent_version",
            ),
            currency_exponents=tuple(exponents),
            single_payment_limit_minor=raw["single_payment_limit_minor"],
            allowed_providers=_strict_sequence(
                raw["allowed_providers"],
                "allowed_providers",
                allow_empty=False,
            ),
            allowed_recipients=_strict_sequence(
                raw["allowed_recipients"],
                "allowed_recipients",
                allow_empty=True,
            ),
            allowed_approver_roles=_strict_sequence(
                raw["allowed_approver_roles"],
                "allowed_approver_roles",
                allow_empty=False,
            ),
            approval_public_keys=tuple(public_keys),
            approval_ttl_seconds=raw["approval_ttl_seconds"],
        )

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        snapshot = _snapshot_call(call)
        if not snapshot.valid:
            return self._record(snapshot, Decision.DENY, "SPEND_REQUEST_SNAPSHOT_INVALID")
        if snapshot.tool != SPEND_OPERATION:
            return self._record(snapshot, Decision.DENY, "SPEND_WRONG_OPERATION")
        arguments = snapshot.arguments_dict()
        try:
            normalized = normalize_spend_arguments(arguments, dict(self.currency_exponents))
        except SpendValidationError as exc:
            return self._record(snapshot, Decision.DENY, exc.reason_code)
        try:
            context, approval_raw = self._context(snapshot)
        except (TypeError, ValueError):
            return self._record(snapshot, Decision.DENY, "SPEND_CONTEXT_INVALID")
        if normalized.provider not in self.allowed_providers:
            return self._record(snapshot, Decision.DENY, "SPEND_PROVIDER_DENIED")
        if normalized.amount_minor > self.single_payment_limit_minor:
            return self._record(snapshot, Decision.DENY, "SPEND_SINGLE_LIMIT_EXCEEDED")
        if approval_raw is not None:
            approval_result = self._verify_approval(
                snapshot,
                normalized,
                context,
                approval_raw,
            )
            if approval_result is not None:
                return approval_result
        elif normalized.recipient not in self.allowed_recipients:
            return self._record(
                snapshot,
                Decision.ESCALATE,
                "SPEND_NEW_RECIPIENT_APPROVAL_REQUIRED",
            )
        transformed = normalized.to_arguments()
        if transformed != arguments:
            return self._record(
                snapshot,
                Decision.TRANSFORM,
                "SPEND_ARGUMENTS_NORMALIZED",
                transformed_args=transformed,
            )
        return self._record(snapshot, Decision.ALLOW, "SPEND_ALLOWED")

    def _context(self, snapshot: _IngressSnapshot) -> tuple[dict[str, str], Any | None]:
        state = snapshot.state_dict()
        keys = set(state)
        if keys not in (_CONTEXT_KEYS, _CONTEXT_KEYS | {"approval"}):
            raise ValueError("spend context has an incompatible shape")
        context = {
            field_name: _ascii_identity(state[field_name], field_name)
            for field_name in _CONTEXT_KEYS - {"requested_at"}
        }
        context["requested_at"] = _normalized_timestamp(
            state["requested_at"],
            "requested_at",
        )
        _ascii_identity(snapshot.actor, "actor_id")
        return context, state.get("approval")

    def _verify_approval(
        self,
        snapshot: _IngressSnapshot,
        normalized: NormalizedSpendArguments,
        context: Mapping[str, str],
        approval_raw: Any,
    ) -> DecisionRecord | None:
        try:
            claim = SpendApprovalClaim.from_dict(approval_raw)
        except (TypeError, ValueError):
            return self._record(snapshot, Decision.DENY, "SPEND_APPROVAL_INVALID")
        expected = {
            "tenant_id": context["tenant_id"],
            "actor_id": snapshot.actor,
            "authority": context["authority"],
            **normalized.to_arguments(),
            "resource": context["resource"],
            "environment": context["environment"],
            "request_id": context["request_id"],
            "policy_id": self.policy_id,
            "policy_version": self.version,
            "policy_digest": self.artifact_digest,
        }
        payload = claim.payload
        if any(getattr(payload, key) != value for key, value in expected.items()):
            return self._record(
                snapshot,
                Decision.DENY,
                "SPEND_APPROVAL_BINDING_MISMATCH",
            )
        if payload.approver_id == snapshot.actor:
            return self._record(snapshot, Decision.DENY, "SPEND_SELF_APPROVAL_DENIED")
        if payload.approver_role not in self.allowed_approver_roles:
            return self._record(snapshot, Decision.DENY, "SPEND_APPROVER_ROLE_DENIED")
        issued = _as_datetime(payload.issued_at)
        expires = _as_datetime(payload.expires_at)
        requested = _as_datetime(context["requested_at"])
        if issued > requested or requested >= expires:
            return self._record(snapshot, Decision.DENY, "SPEND_APPROVAL_TIME_INVALID")
        if expires - issued > timedelta(seconds=self.approval_ttl_seconds):
            return self._record(snapshot, Decision.DENY, "SPEND_APPROVAL_TTL_EXCEEDED")
        if (
            claim.evidence.evidence_id != payload.request_id
            or claim.evidence.evidence_type != SPEND_APPROVAL_EVIDENCE_TYPE
            or claim.evidence.digest != sha256_json(payload.to_dict())
            or claim.evidence.issuer != payload.approver_id
            or claim.evidence.issued_at != payload.issued_at
            or claim.evidence.expires_at != payload.expires_at
        ):
            return self._record(snapshot, Decision.DENY, "SPEND_APPROVAL_EVIDENCE_INVALID")
        public_hex = dict(self.approval_public_keys).get(claim.key_id)
        if public_hex is None:
            return self._record(snapshot, Decision.DENY, "SPEND_APPROVAL_KEY_UNKNOWN")
        try:
            verifier = Ed25519Signer.from_public_bytes(bytes.fromhex(public_hex), claim.key_id)
            verified = verifier.verify(claim.signing_bytes(), claim.signature)
        except (ImportError, SigningError, RuntimeError, ValueError):
            return self._record(
                snapshot,
                Decision.DENY,
                "SPEND_APPROVAL_DEPENDENCY_UNAVAILABLE",
            )
        if not verified:
            return self._record(snapshot, Decision.DENY, "SPEND_APPROVAL_SIGNATURE_INVALID")
        return None

    def _record(
        self,
        snapshot: _IngressSnapshot,
        decision: Decision,
        reason_code: str,
        *,
        transformed_args: dict[str, str] | None = None,
    ) -> DecisionRecord:
        if decision is not Decision.TRANSFORM:
            transformed_args = None
        return DecisionRecord(
            decision=decision,
            tool=snapshot.tool,
            argument_hash=snapshot.argument_hash,
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=(reason_code,),
            reason=reason_code,
            transformed_args=transformed_args,
            actor=snapshot.actor,
            path=snapshot.path,
            state_hash=snapshot.state_hash,
            decision_request_hash=snapshot.decision_request_hash,
        )
