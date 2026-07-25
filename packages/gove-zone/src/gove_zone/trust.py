"""Scoped public-key trust registry for receipt-v2 verification.

This module is intentionally pure Python and runtime-local: no SQL, network,
KMS, private-key persistence, or mutable runtime roots. It names the trust
contract the executor can verify offline while managed distribution is added
above it.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Literal, Protocol, TypeAlias

from gove_zone.errors import SigningError
from gove_zone.signing import Ed25519Signer, ReceiptSigner

RECEIPT_V1 = "gove-zone/decision-receipt/v1"
RECEIPT_V2 = "gove-zone/decision-receipt/v2"
DECISION_RECEIPT_PURPOSE = "decision-receipt"

TrustKeyStatus: TypeAlias = Literal["active", "retired", "revoked"]
TrustResolutionMode: TypeAlias = Literal["execution", "historical"]
TrustReadinessCode: TypeAlias = Literal[
    "ready",
    "missing-root",
    "no-active-root",
    "expired-root",
    "malformed-root",
]


class TrustConfigurationError(ValueError):
    """Raised when scoped trust material is malformed or missing."""


@dataclass(frozen=True, slots=True)
class ReceiptTrustScope:
    """Full tenant/project/environment scope for receipt authorization roots."""

    tenant_id: str
    project_id: str
    environment_id: str
    purpose: str = DECISION_RECEIPT_PURPOSE

    def __post_init__(self) -> None:
        for field_name in ("tenant_id", "project_id", "environment_id", "purpose"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise TrustConfigurationError(f"{field_name} is required for scoped trust")


@dataclass(frozen=True, slots=True)
class TrustedReceiptKey:
    """Public verifier material for one scoped receipt-signing key."""

    scope: ReceiptTrustScope
    key_id: str
    algorithm: str
    public_key_spki_der: bytes
    activated_epoch: int
    not_after: str
    status: TrustKeyStatus = "active"
    retired_epoch: int | None = None
    public_key_fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        self._validate_primitives(check_fingerprint=False)
        object.__setattr__(
            self,
            "public_key_fingerprint",
            self._computed_public_key_fingerprint(),
        )
        self.validate()

    def validate(self) -> None:
        """Validate every trust-root invariant, including forged descriptors."""

        self._validate_primitives(check_fingerprint=True)

    def _validate_primitives(self, *, check_fingerprint: bool) -> None:
        if not isinstance(self.scope, ReceiptTrustScope):
            raise TrustConfigurationError("scope must be a ReceiptTrustScope")
        self.scope.__post_init__()
        if not isinstance(self.key_id, str) or not self.key_id.strip():
            raise TrustConfigurationError("key_id is required for scoped trust")
        if self.algorithm != "ed25519":
            raise TrustConfigurationError("receipt-v2 trust currently supports only ed25519")
        _ed25519_raw_public_from_spki_der(self.public_key_spki_der)
        if type(self.activated_epoch) is not int or self.activated_epoch <= 0:
            raise TrustConfigurationError("activated_epoch must be a positive integer")
        if self.status not in ("active", "retired", "revoked"):
            raise TrustConfigurationError(f"unknown trust key status: {self.status!r}")
        if self.retired_epoch is not None and (
            type(self.retired_epoch) is not int or self.retired_epoch <= self.activated_epoch
        ):
            raise TrustConfigurationError("retired_epoch must be greater than activated_epoch")
        if self.status == "retired" and self.retired_epoch is None:
            raise TrustConfigurationError("retired keys require retired_epoch")
        if self.status != "retired" and self.retired_epoch is not None:
            raise TrustConfigurationError("retired_epoch is only valid for retired keys")
        _parse_aware_iso(self.not_after, field_name="not_after")
        if check_fingerprint:
            stored = getattr(self, "public_key_fingerprint", None)
            if not isinstance(stored, str) or not hmac.compare_digest(
                stored, self._computed_public_key_fingerprint()
            ):
                raise TrustConfigurationError("public_key_fingerprint mismatch")

    def _computed_public_key_fingerprint(self) -> str:
        if type(self.public_key_spki_der) is not bytes:
            raise TrustConfigurationError("ed25519 public_key_spki_der must be bytes")
        return hashlib.sha256(self.public_key_spki_der).hexdigest()

    @property
    def verifier(self) -> ReceiptSigner:
        """Construct a verify-only signer from canonical public DER at use time."""

        return Ed25519Signer.from_public_bytes(
            _ed25519_raw_public_from_spki_der(self.public_key_spki_der),
            key_id=self.key_id,
        )

    def verifies_epoch(self, trust_epoch: int, *, mode: TrustResolutionMode) -> bool:
        if type(trust_epoch) is not int or trust_epoch <= 0:
            return False
        if self.status == "revoked":
            return False
        if trust_epoch < self.activated_epoch:
            return False
        if mode == "execution":
            return self.status == "active"
        if mode != "historical":
            return False
        if self.status == "active":
            return True
        return self.retired_epoch is not None and trust_epoch < self.retired_epoch

    def is_live_at(self, now_iso: str) -> bool:
        """Return whether this root is still valid at a live execution clock."""

        return _parse_aware_iso(now_iso, field_name="now_iso") <= _parse_aware_iso(
            self.not_after, field_name="not_after"
        )


@dataclass(frozen=True, slots=True)
class TrustReadinessIssue:
    code: TrustReadinessCode
    scope: ReceiptTrustScope | None = None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class TrustReadinessReport:
    ready: bool
    issues: tuple[TrustReadinessIssue, ...] = ()


class ReceiptTrustRegistry(Protocol):
    """Resolve public verifier material by full scope, purpose, epoch, alg, key."""

    def resolve(
        self,
        *,
        scope: ReceiptTrustScope,
        trust_epoch: int,
        algorithm: str,
        key_id: str,
        now_iso: str,
        mode: TrustResolutionMode = "execution",
    ) -> TrustedReceiptKey: ...

    def readiness(
        self, scopes: Iterable[ReceiptTrustScope] = (), *, now_iso: str
    ) -> TrustReadinessReport: ...


class StaticReceiptTrustRegistry:
    """Immutable in-memory scoped trust registry for local/runtime tests."""

    def __init__(self, keys: Iterable[TrustedReceiptKey] = ()) -> None:
        buckets: dict[tuple[ReceiptTrustScope, str, str], list[TrustedReceiptKey]] = {}
        scopes: set[ReceiptTrustScope] = set()
        malformed: list[TrustReadinessIssue] = []
        for key in tuple(keys):
            try:
                key.validate()
            except TrustConfigurationError as exc:
                scope = key.scope if isinstance(key.scope, ReceiptTrustScope) else None
                if scope is not None:
                    scopes.add(scope)
                malformed.append(TrustReadinessIssue("malformed-root", scope, str(exc)))
                continue
            scopes.add(key.scope)
            map_key = (key.scope, key.algorithm, key.key_id)
            bucket = buckets.setdefault(map_key, [])
            if any(existing == key for existing in bucket):
                malformed.append(
                    TrustReadinessIssue("malformed-root", key.scope, "duplicate trust root")
                )
            bucket.append(key)
        frozen_buckets: dict[tuple[ReceiptTrustScope, str, str], tuple[TrustedReceiptKey, ...]] = {}
        for map_key, bucket in buckets.items():
            frozen_buckets[map_key] = tuple(sorted(bucket, key=lambda item: item.activated_epoch))
        self._keys = MappingProxyType(frozen_buckets)
        self._scopes = frozenset(scopes)
        self._malformed = tuple(malformed)

    def resolve(
        self,
        *,
        scope: ReceiptTrustScope,
        trust_epoch: int,
        algorithm: str,
        key_id: str,
        now_iso: str,
        mode: TrustResolutionMode = "execution",
    ) -> TrustedReceiptKey:
        if mode not in ("execution", "historical"):
            raise TrustConfigurationError("unknown trust resolution mode")
        if type(trust_epoch) is not int or trust_epoch <= 0:
            raise TrustConfigurationError("trust_epoch must be a positive integer")
        _parse_aware_iso(now_iso, field_name="now_iso")
        if _scope_has_multiple_active(self._keys, scope):
            raise TrustConfigurationError("multiple active trust roots for scope")
        candidates = self._keys.get((scope, algorithm, key_id), ())
        for key in reversed(candidates):
            key.validate()
            if key.verifies_epoch(trust_epoch, mode=mode):
                if mode == "execution" and not key.is_live_at(now_iso):
                    raise TrustConfigurationError("active trust root expired")
                return key
        raise TrustConfigurationError(
            "no trusted receipt key for scope/purpose/epoch/algorithm/key"
        )

    def readiness(
        self, scopes: Iterable[ReceiptTrustScope] = (), *, now_iso: str
    ) -> TrustReadinessReport:
        wanted = tuple(scopes) if scopes else tuple(sorted(self._scopes, key=repr))
        issues: list[TrustReadinessIssue] = list(self._malformed)
        _parse_aware_iso(now_iso, field_name="now_iso")
        if not wanted:
            issues.append(TrustReadinessIssue("missing-root", None, "no trust scopes configured"))
        for scope in wanted:
            scope_keys = [
                key for bucket in self._keys.values() for key in bucket if key.scope == scope
            ]
            if not scope_keys:
                issues.append(TrustReadinessIssue("missing-root", scope, "no keys for scope"))
                continue
            active_keys = [key for key in scope_keys if key.status == "active"]
            if not active_keys:
                issues.append(TrustReadinessIssue("no-active-root", scope, "no active key"))
            elif len(active_keys) > 1:
                issues.append(TrustReadinessIssue("malformed-root", scope, "multiple active roots"))
            elif not active_keys[0].is_live_at(now_iso):
                issues.append(TrustReadinessIssue("expired-root", scope, "active root expired"))
        return TrustReadinessReport(ready=not issues, issues=tuple(issues))


def _scope_has_multiple_active(
    keys: MappingProxyType[tuple[ReceiptTrustScope, str, str], tuple[TrustedReceiptKey, ...]],
    scope: ReceiptTrustScope,
) -> bool:
    active = 0
    for bucket in keys.values():
        for key in bucket:
            if key.scope == scope and key.status == "active":
                active += 1
    return active > 1


def _parse_aware_iso(value: str, *, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise TrustConfigurationError(f"{field_name} is required")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise TrustConfigurationError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise TrustConfigurationError(f"{field_name} must be timezone-aware")
    return parsed


def _ed25519_raw_public_from_spki_der(public_key_spki_der: bytes) -> bytes:
    if type(public_key_spki_der) is not bytes:
        raise TrustConfigurationError("ed25519 public_key_spki_der must be bytes")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - exercised only without crypto extra
        raise TrustConfigurationError("Ed25519 trust roots require the 'crypto' extra") from exc
    try:
        public_key = serialization.load_der_public_key(public_key_spki_der)
    except (TypeError, ValueError) as exc:
        raise TrustConfigurationError("malformed Ed25519 SubjectPublicKeyInfo DER") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise TrustConfigurationError("trust root must be an Ed25519 public key")
    try:
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    except (TypeError, ValueError, SigningError) as exc:
        raise TrustConfigurationError("malformed Ed25519 public key") from exc
