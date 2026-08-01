"""Signed policy synchronization and local last-known-good enforcement.

This module is intentionally transport-agnostic.  Synchronization is an
authenticated management-plane operation; policy evaluation remains entirely
local and never performs a network call.
"""

from __future__ import annotations

import base64
import contextlib
import contextvars
import dataclasses
import hashlib
import json
import math
import os
import re
import stat
import time
from collections.abc import Callable, Generator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Self, TextIO, cast

from gove_zone._fsprobe import filesystem_is_lock_safe
from gove_zone.decision import Decision, DecisionRecord, canonical_json, sha256_json
from gove_zone.policy import Policy, RuleSetPolicy, new_event_id
from gove_zone.runtime_identity import (
    RuntimeHttpResponse,
    RuntimeIdentityDescriptor,
    SignedRequestClient,
)
from gove_zone.tool import ToolCall
from gove_zone.trust import (
    ReceiptTrustRegistry,
    ReceiptTrustScope,
    TrustConfigurationError,
    TrustedReceiptKey,
)

POLICY_SYNC_SCHEMA = "acgs.policy-sync.snapshot/v2"
POLICY_SYNC_PURPOSE = "acgs.policy-sync/v2"
POLICY_SYNC_ATTESTATION_PURPOSE = "acgs.policy-sync-attestation/v1"
POLICY_ENVELOPE_SCHEMA = "acgs.policy-registry.envelope/v1"
POLICY_ENVELOPE_PURPOSE = "acgs.policy-envelope/v1"
DEFAULT_MAX_POLICY_LIFETIME_SECONDS = 300
DEFAULT_MAX_DEGRADED_WINDOW_SECONDS = 240
DEFAULT_MAX_REVOCATION_CHECK_AGE_SECONDS = 60
DEFAULT_MAX_POLICY_SYNC_RESPONSE_BYTES = 1_048_576
DEFAULT_POLICY_CACHE_LOCK_TIMEOUT_SECONDS = 5.0

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_CURSOR_RE = re.compile(r"^psync_[A-Za-z0-9_-]{43}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_OUTER_FIELDS = {
    "schema",
    "purpose",
    "scope",
    "runtime_identity_id",
    "credential_id",
    "credential_generation",
    "cursor",
    "head_generation",
    "head_updated_at",
    "policy_version_id",
    "policy_id",
    "version",
    "content_hash",
    "activation_receipt_id",
    "activation_receipt_hash",
    "activation_event_hash",
    "policy_envelope",
    "attestation_purpose",
    "attestation_trust_epoch",
    "attestation_key_id",
    "attestation_signature_algorithm",
    "issued_at",
    "revocation_checked_at",
    "fresh_until",
    "expires_at",
    "attestation_signature",
}
_OUTER_SCOPE_FIELDS = {"org_id", "project_id", "environment_id", "gate_id"}
_ENVELOPE_FIELDS = {
    "schema",
    "scope",
    "policy_id",
    "version",
    "content_hash",
    "document",
    "rules",
    "key_id",
    "signature_algorithm",
    "trust_epoch",
    "purpose",
    "signature",
}
_ENVELOPE_SCOPE_FIELDS = {"org_id", "project_id", "environment_id"}
POLICY_HIGH_WATER_SCHEMA = "acgs.policy-sync.high-water/v1"
_HIGH_WATER_FIELDS = {
    "schema",
    "scope",
    "runtime_identity_id",
    "max_head_generation",
    "immutable_head_binding_hash",
    "max_credential_generation",
    "max_attestation_trust_epoch",
    "last_cursor",
    "last_snapshot_hash",
    "max_issued_at",
    "max_revocation_checked_at",
    "max_fresh_until",
    "max_expires_at",
    "state_hash",
}


class PolicySyncError(ValueError):
    """A fail-closed policy-sync validation, cache, or transport error."""


class _PolicyCacheBehindHighWaterError(PolicySyncError):
    """Verified cache is older than its durable anti-rollback floor."""


@dataclass(frozen=True, slots=True)
class _ActivePolicyBinding:
    cache_id: int
    provenance: ManagedPolicyProvenance


_ACTIVE_POLICY_BINDINGS: contextvars.ContextVar[dict[str, _ActivePolicyBinding] | None] = (
    contextvars.ContextVar("gove_zone_active_policy_bindings", default=None)
)


@dataclass(frozen=True, slots=True)
class PolicySyncScope:
    org_id: str
    project_id: str
    environment_id: str
    gate_id: str

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        _require_exact_dict(payload, "scope", _OUTER_SCOPE_FIELDS)
        return cls(
            org_id=_require_string(payload.get("org_id"), "scope.org_id"),
            project_id=_require_string(payload.get("project_id"), "scope.project_id"),
            environment_id=_require_string(payload.get("environment_id"), "scope.environment_id"),
            gate_id=_require_string(payload.get("gate_id"), "scope.gate_id"),
        )

    def to_dict(self) -> dict[str, str]:
        return dataclasses.asdict(self)


@dataclass(frozen=True, slots=True)
class PolicySyncSnapshot:
    """Strict, signed distribution snapshot for one enrolled runtime gate."""

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
    activation_receipt_id: str
    activation_receipt_hash: str
    activation_event_hash: str
    policy_envelope: Mapping[str, Any]
    attestation_purpose: str
    attestation_trust_epoch: int
    attestation_key_id: str
    attestation_signature_algorithm: str
    issued_at: str
    revocation_checked_at: str
    fresh_until: str
    expires_at: str
    attestation_signature: str
    schema: str = POLICY_SYNC_SCHEMA
    purpose: str = POLICY_SYNC_PURPOSE

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        _require_exact_dict(payload, "policy sync snapshot", _OUTER_FIELDS)
        if payload.get("schema") != POLICY_SYNC_SCHEMA:
            raise PolicySyncError("unsupported policy sync snapshot schema")
        if payload.get("purpose") != POLICY_SYNC_PURPOSE:
            raise PolicySyncError("invalid policy sync snapshot purpose")
        scope = _require_mapping(payload.get("scope"), "scope")
        envelope = _require_mapping(payload.get("policy_envelope"), "policy_envelope")
        snapshot = cls(
            schema=POLICY_SYNC_SCHEMA,
            purpose=POLICY_SYNC_PURPOSE,
            scope=PolicySyncScope.from_dict(scope),
            runtime_identity_id=_require_string(
                payload.get("runtime_identity_id"), "runtime_identity_id"
            ),
            credential_id=_require_string(payload.get("credential_id"), "credential_id"),
            credential_generation=_require_positive_int(
                payload.get("credential_generation"), "credential_generation"
            ),
            cursor=_require_cursor(payload.get("cursor")),
            head_generation=_require_positive_int(
                payload.get("head_generation"), "head_generation"
            ),
            head_updated_at=_require_timestamp(payload.get("head_updated_at"), "head_updated_at"),
            policy_version_id=_require_string(
                payload.get("policy_version_id"), "policy_version_id"
            ),
            policy_id=_require_string(payload.get("policy_id"), "policy_id"),
            version=_require_string(payload.get("version"), "version"),
            content_hash=_require_sha256(payload.get("content_hash"), "content_hash"),
            activation_receipt_id=_require_identifier(
                payload.get("activation_receipt_id"), "activation_receipt_id"
            ),
            activation_receipt_hash=_require_sha256(
                payload.get("activation_receipt_hash"), "activation_receipt_hash"
            ),
            activation_event_hash=_require_sha256(
                payload.get("activation_event_hash"), "activation_event_hash"
            ),
            policy_envelope=_copy_json_object(envelope, "policy_envelope"),
            attestation_purpose=_require_string(
                payload.get("attestation_purpose"), "attestation_purpose"
            ),
            attestation_trust_epoch=_require_positive_int(
                payload.get("attestation_trust_epoch"), "attestation_trust_epoch"
            ),
            attestation_key_id=_require_string(
                payload.get("attestation_key_id"), "attestation_key_id"
            ),
            attestation_signature_algorithm=_require_string(
                payload.get("attestation_signature_algorithm"),
                "attestation_signature_algorithm",
            ),
            issued_at=_require_timestamp(payload.get("issued_at"), "issued_at"),
            revocation_checked_at=_require_timestamp(
                payload.get("revocation_checked_at"), "revocation_checked_at"
            ),
            fresh_until=_require_timestamp(payload.get("fresh_until"), "fresh_until"),
            expires_at=_require_timestamp(payload.get("expires_at"), "expires_at"),
            attestation_signature=_require_string(
                payload.get("attestation_signature"), "attestation_signature"
            ),
        )
        if snapshot.attestation_purpose != POLICY_SYNC_ATTESTATION_PURPOSE:
            raise PolicySyncError("invalid policy sync attestation purpose")
        snapshot._validate_time_order()
        if not _constant_time_equal(snapshot.cursor, _compute_policy_sync_cursor(snapshot)):
            raise PolicySyncError("policy sync cursor binding mismatch")
        return snapshot

    @classmethod
    def from_json(cls, raw: str | bytes) -> Self:
        return cls.from_dict(_loads_json_object_no_duplicates(raw))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "purpose": self.purpose,
            "scope": self.scope.to_dict(),
            "runtime_identity_id": self.runtime_identity_id,
            "credential_id": self.credential_id,
            "credential_generation": self.credential_generation,
            "cursor": self.cursor,
            "head_generation": self.head_generation,
            "head_updated_at": self.head_updated_at,
            "policy_version_id": self.policy_version_id,
            "policy_id": self.policy_id,
            "version": self.version,
            "content_hash": self.content_hash,
            "activation_receipt_id": self.activation_receipt_id,
            "activation_receipt_hash": self.activation_receipt_hash,
            "activation_event_hash": self.activation_event_hash,
            "policy_envelope": _copy_json_object(self.policy_envelope, "policy_envelope"),
            "attestation_purpose": self.attestation_purpose,
            "attestation_trust_epoch": self.attestation_trust_epoch,
            "attestation_key_id": self.attestation_key_id,
            "attestation_signature_algorithm": self.attestation_signature_algorithm,
            "issued_at": self.issued_at,
            "revocation_checked_at": self.revocation_checked_at,
            "fresh_until": self.fresh_until,
            "expires_at": self.expires_at,
            "attestation_signature": self.attestation_signature,
        }

    def canonical_bytes(self) -> bytes:
        payload = self.to_dict()
        payload.pop("attestation_signature")
        return canonical_json(payload).encode("utf-8")

    def canonical_json_bytes(self) -> bytes:
        return canonical_json(self.to_dict()).encode("utf-8") + b"\n"

    def _validate_time_order(self) -> None:
        head_updated = _parse_timestamp(self.head_updated_at, "head_updated_at")
        issued = _parse_timestamp(self.issued_at, "issued_at")
        revocation_checked = _parse_timestamp(self.revocation_checked_at, "revocation_checked_at")
        fresh = _parse_timestamp(self.fresh_until, "fresh_until")
        expires = _parse_timestamp(self.expires_at, "expires_at")
        if head_updated > issued:
            raise PolicySyncError("head_updated_at must not be after issued_at")
        if revocation_checked > issued:
            raise PolicySyncError("revocation_checked_at must not be after issued_at")
        if not issued < fresh < expires:
            raise PolicySyncError("policy sync freshness and expiry order is invalid")


@dataclass(frozen=True, slots=True)
class ManagedPolicyProvenance:
    """Immutable executor-facing provenance for one verified managed lease."""

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
    activation_receipt_id: str
    activation_receipt_hash: str
    activation_event_hash: str
    policy_sync_schema: str
    policy_sync_purpose: str
    policy_trust_purpose: str
    policy_trust_epoch: int
    policy_key_id: str
    policy_signature_algorithm: str
    policy_key_fingerprint: str
    attestation_purpose: str
    attestation_trust_epoch: int
    attestation_key_id: str
    attestation_signature_algorithm: str
    attestation_key_fingerprint: str
    signed_snapshot_hash: str

    @classmethod
    def from_snapshot(
        cls,
        snapshot: PolicySyncSnapshot,
        *,
        policy_key_fingerprint: str,
        attestation_key_fingerprint: str,
    ) -> Self:
        snapshot = PolicySyncSnapshot.from_dict(snapshot.to_dict())
        return cls(
            scope=snapshot.scope,
            runtime_identity_id=snapshot.runtime_identity_id,
            credential_id=snapshot.credential_id,
            credential_generation=snapshot.credential_generation,
            cursor=snapshot.cursor,
            head_generation=snapshot.head_generation,
            head_updated_at=snapshot.head_updated_at,
            policy_version_id=snapshot.policy_version_id,
            policy_id=snapshot.policy_id,
            version=snapshot.version,
            content_hash=snapshot.content_hash,
            activation_receipt_id=snapshot.activation_receipt_id,
            activation_receipt_hash=snapshot.activation_receipt_hash,
            activation_event_hash=snapshot.activation_event_hash,
            policy_sync_schema=snapshot.schema,
            policy_sync_purpose=snapshot.purpose,
            policy_trust_purpose=POLICY_ENVELOPE_PURPOSE,
            policy_trust_epoch=cast(int, snapshot.policy_envelope["trust_epoch"]),
            policy_key_id=cast(str, snapshot.policy_envelope["key_id"]),
            policy_signature_algorithm=cast(str, snapshot.policy_envelope["signature_algorithm"]),
            policy_key_fingerprint=_require_sha256(
                policy_key_fingerprint, "policy_key_fingerprint"
            ),
            attestation_purpose=snapshot.attestation_purpose,
            attestation_trust_epoch=snapshot.attestation_trust_epoch,
            attestation_key_id=snapshot.attestation_key_id,
            attestation_signature_algorithm=snapshot.attestation_signature_algorithm,
            attestation_key_fingerprint=_require_sha256(
                attestation_key_fingerprint, "attestation_key_fingerprint"
            ),
            signed_snapshot_hash=hashlib.sha256(
                canonical_json(snapshot.to_dict()).encode("utf-8")
            ).hexdigest(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope.to_dict(),
            "runtime_identity_id": self.runtime_identity_id,
            "credential_id": self.credential_id,
            "credential_generation": self.credential_generation,
            "cursor": self.cursor,
            "head_generation": self.head_generation,
            "head_updated_at": self.head_updated_at,
            "policy_version_id": self.policy_version_id,
            "policy_id": self.policy_id,
            "version": self.version,
            "content_hash": self.content_hash,
            "activation_receipt_id": self.activation_receipt_id,
            "activation_receipt_hash": self.activation_receipt_hash,
            "activation_event_hash": self.activation_event_hash,
            "policy_sync_schema": self.policy_sync_schema,
            "policy_sync_purpose": self.policy_sync_purpose,
            "policy_trust_purpose": self.policy_trust_purpose,
            "policy_trust_epoch": self.policy_trust_epoch,
            "policy_key_id": self.policy_key_id,
            "policy_signature_algorithm": self.policy_signature_algorithm,
            "policy_key_fingerprint": self.policy_key_fingerprint,
            "attestation_purpose": self.attestation_purpose,
            "attestation_trust_epoch": self.attestation_trust_epoch,
            "attestation_key_id": self.attestation_key_id,
            "attestation_signature_algorithm": self.attestation_signature_algorithm,
            "attestation_key_fingerprint": self.attestation_key_fingerprint,
            "signed_snapshot_hash": self.signed_snapshot_hash,
        }

    def compute_hash(self) -> str:
        return sha256_json(self.to_dict())


@dataclass(frozen=True, slots=True)
class _PolicyHighWater:
    scope: PolicySyncScope
    runtime_identity_id: str
    max_head_generation: int
    immutable_head_binding_hash: str
    max_credential_generation: int
    max_attestation_trust_epoch: int
    last_cursor: str
    last_snapshot_hash: str
    max_issued_at: str
    max_revocation_checked_at: str
    max_fresh_until: str
    max_expires_at: str
    state_hash: str
    schema: str = POLICY_HIGH_WATER_SCHEMA

    @classmethod
    def from_snapshot(cls, snapshot: PolicySyncSnapshot) -> Self:
        unsigned = {
            "schema": POLICY_HIGH_WATER_SCHEMA,
            "scope": snapshot.scope.to_dict(),
            "runtime_identity_id": snapshot.runtime_identity_id,
            "max_head_generation": snapshot.head_generation,
            "immutable_head_binding_hash": _immutable_head_binding_hash(snapshot),
            "max_credential_generation": snapshot.credential_generation,
            "max_attestation_trust_epoch": snapshot.attestation_trust_epoch,
            "last_cursor": snapshot.cursor,
            "last_snapshot_hash": hashlib.sha256(snapshot.canonical_json_bytes()).hexdigest(),
            "max_issued_at": snapshot.issued_at,
            "max_revocation_checked_at": snapshot.revocation_checked_at,
            "max_fresh_until": snapshot.fresh_until,
            "max_expires_at": snapshot.expires_at,
        }
        return cls(
            scope=snapshot.scope,
            runtime_identity_id=snapshot.runtime_identity_id,
            max_head_generation=snapshot.head_generation,
            immutable_head_binding_hash=cast(str, unsigned["immutable_head_binding_hash"]),
            max_credential_generation=snapshot.credential_generation,
            max_attestation_trust_epoch=snapshot.attestation_trust_epoch,
            last_cursor=snapshot.cursor,
            last_snapshot_hash=cast(str, unsigned["last_snapshot_hash"]),
            max_issued_at=snapshot.issued_at,
            max_revocation_checked_at=snapshot.revocation_checked_at,
            max_fresh_until=snapshot.fresh_until,
            max_expires_at=snapshot.expires_at,
            state_hash=sha256_json(unsigned),
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        _require_exact_dict(payload, "policy high-water", _HIGH_WATER_FIELDS)
        if payload.get("schema") != POLICY_HIGH_WATER_SCHEMA:
            raise PolicySyncError("unsupported policy high-water schema")
        unsigned = dict(payload)
        state_hash = _require_sha256(unsigned.pop("state_hash"), "state_hash")
        if not _constant_time_equal(state_hash, sha256_json(unsigned)):
            raise PolicySyncError("policy high-water state hash mismatch")
        return cls(
            scope=PolicySyncScope.from_dict(
                _require_mapping(payload.get("scope"), "policy high-water scope")
            ),
            runtime_identity_id=_require_string(
                payload.get("runtime_identity_id"), "runtime_identity_id"
            ),
            max_head_generation=_require_positive_int(
                payload.get("max_head_generation"), "max_head_generation"
            ),
            immutable_head_binding_hash=_require_sha256(
                payload.get("immutable_head_binding_hash"), "immutable_head_binding_hash"
            ),
            max_credential_generation=_require_positive_int(
                payload.get("max_credential_generation"), "max_credential_generation"
            ),
            max_attestation_trust_epoch=_require_positive_int(
                payload.get("max_attestation_trust_epoch"), "max_attestation_trust_epoch"
            ),
            last_cursor=_require_cursor(payload.get("last_cursor")),
            last_snapshot_hash=_require_sha256(
                payload.get("last_snapshot_hash"), "last_snapshot_hash"
            ),
            max_issued_at=_require_timestamp(payload.get("max_issued_at"), "max_issued_at"),
            max_revocation_checked_at=_require_timestamp(
                payload.get("max_revocation_checked_at"), "max_revocation_checked_at"
            ),
            max_fresh_until=_require_timestamp(payload.get("max_fresh_until"), "max_fresh_until"),
            max_expires_at=_require_timestamp(payload.get("max_expires_at"), "max_expires_at"),
            state_hash=state_hash,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "scope": self.scope.to_dict(),
            "runtime_identity_id": self.runtime_identity_id,
            "max_head_generation": self.max_head_generation,
            "immutable_head_binding_hash": self.immutable_head_binding_hash,
            "max_credential_generation": self.max_credential_generation,
            "max_attestation_trust_epoch": self.max_attestation_trust_epoch,
            "last_cursor": self.last_cursor,
            "last_snapshot_hash": self.last_snapshot_hash,
            "max_issued_at": self.max_issued_at,
            "max_revocation_checked_at": self.max_revocation_checked_at,
            "max_fresh_until": self.max_fresh_until,
            "max_expires_at": self.max_expires_at,
            "state_hash": self.state_hash,
        }


class _PolicyHighWaterStore:
    """Internal owner-only rollback state beside a policy cache.

    This detects cache-only rollback and interrupted two-file updates. It is
    not a hardware monotonic counter: an attacker able to rewrite both files
    remains outside this local filesystem trust boundary.
    """

    def __init__(self, cache_path: Path) -> None:
        self._path = cache_path.with_name(cache_path.name + ".high-water.json")

    def _load(self) -> _PolicyHighWater:
        return _PolicyHighWater.from_dict(_loads_json_object_no_duplicates(self._read_bytes()))

    def _persist(self, mark: _PolicyHighWater) -> None:
        _atomic_owner_only_replace(self._path, canonical_json(mark.to_dict()).encode() + b"\n")

    def _read_bytes(self) -> bytes:
        return _read_owner_only_regular_file(self._path, label="policy high-water")


@dataclass(frozen=True, slots=True)
class _VerifiedPolicySnapshot:
    policy: RuleSetPolicy
    policy_key_fingerprint: str
    attestation_key_fingerprint: str

    def provenance(self, snapshot: PolicySyncSnapshot) -> ManagedPolicyProvenance:
        return ManagedPolicyProvenance.from_snapshot(
            snapshot,
            policy_key_fingerprint=self.policy_key_fingerprint,
            attestation_key_fingerprint=self.attestation_key_fingerprint,
        )


def verify_policy_sync_snapshot(
    snapshot: PolicySyncSnapshot,
    *,
    descriptor: RuntimeIdentityDescriptor,
    trust_registry: ReceiptTrustRegistry,
    now: datetime | None = None,
    max_future_skew_seconds: int = 300,
    max_total_lifetime_seconds: int = DEFAULT_MAX_POLICY_LIFETIME_SECONDS,
    max_degraded_window_seconds: int = DEFAULT_MAX_DEGRADED_WINDOW_SECONDS,
    max_revocation_check_age_seconds: int = DEFAULT_MAX_REVOCATION_CHECK_AGE_SECONDS,
    allow_expired: bool = False,
    allow_historical_credential: bool = False,
    historical_trust_verification: bool = False,
) -> RuleSetPolicy:
    """Verify both signed layers and return a fully built local policy."""

    return _verify_policy_sync_snapshot(
        snapshot,
        descriptor=descriptor,
        trust_registry=trust_registry,
        now=now,
        max_future_skew_seconds=max_future_skew_seconds,
        max_total_lifetime_seconds=max_total_lifetime_seconds,
        max_degraded_window_seconds=max_degraded_window_seconds,
        max_revocation_check_age_seconds=max_revocation_check_age_seconds,
        allow_expired=allow_expired,
        allow_historical_credential=allow_historical_credential,
        historical_trust_verification=historical_trust_verification,
    ).policy


def _verify_policy_sync_snapshot(
    snapshot: PolicySyncSnapshot,
    *,
    descriptor: RuntimeIdentityDescriptor,
    trust_registry: ReceiptTrustRegistry,
    now: datetime | None = None,
    max_future_skew_seconds: int = 300,
    max_total_lifetime_seconds: int = DEFAULT_MAX_POLICY_LIFETIME_SECONDS,
    max_degraded_window_seconds: int = DEFAULT_MAX_DEGRADED_WINDOW_SECONDS,
    max_revocation_check_age_seconds: int = DEFAULT_MAX_REVOCATION_CHECK_AGE_SECONDS,
    allow_expired: bool = False,
    allow_historical_credential: bool = False,
    historical_trust_verification: bool = False,
) -> _VerifiedPolicySnapshot:
    """Verify both signed layers and retain their physical trust identities."""

    if type(snapshot) is not PolicySyncSnapshot:
        raise PolicySyncError("snapshot must be a PolicySyncSnapshot")
    snapshot = PolicySyncSnapshot.from_dict(snapshot.to_dict())
    effective_now = _effective_now(now)
    expected_scope = PolicySyncScope(
        org_id=descriptor.scope.org_id,
        project_id=descriptor.scope.project_id,
        environment_id=descriptor.scope.environment,
        gate_id=descriptor.scope.gate_id,
    )
    if snapshot.scope != expected_scope:
        raise PolicySyncError("policy sync snapshot scope mismatch")
    if snapshot.runtime_identity_id != descriptor.runtime_identity_id:
        raise PolicySyncError("policy sync runtime identity mismatch")
    historical_generation = (
        allow_historical_credential
        and snapshot.credential_generation < descriptor.credential_generation
    )
    if allow_historical_credential:
        if snapshot.credential_generation > descriptor.credential_generation:
            raise PolicySyncError("policy sync credential generation is from the future")
        if (
            snapshot.credential_generation == descriptor.credential_generation
            and snapshot.credential_id != descriptor.credential_id
        ):
            raise PolicySyncError("policy sync credential mismatch")
    elif snapshot.credential_id != descriptor.credential_id:
        raise PolicySyncError("policy sync credential mismatch")
    elif snapshot.credential_generation != descriptor.credential_generation:
        raise PolicySyncError("policy sync credential generation mismatch")
    descriptor_issued = _parse_timestamp(descriptor.issued_at, "descriptor.issued_at")
    descriptor_expires = _parse_timestamp(descriptor.expires_at, "descriptor.expires_at")
    if descriptor_issued > effective_now + timedelta(seconds=max_future_skew_seconds):
        raise PolicySyncError("runtime identity descriptor issued_at is too far in the future")
    if effective_now >= descriptor_expires:
        raise PolicySyncError("runtime identity descriptor expired")
    issued = _parse_timestamp(snapshot.issued_at, "issued_at")
    revocation_checked = _parse_timestamp(snapshot.revocation_checked_at, "revocation_checked_at")
    fresh = _parse_timestamp(snapshot.fresh_until, "fresh_until")
    expires = _parse_timestamp(snapshot.expires_at, "expires_at")
    if issued > effective_now + timedelta(seconds=max_future_skew_seconds):
        raise PolicySyncError("policy sync snapshot issued_at is too far in the future")
    if (not historical_generation and issued < descriptor_issued) or expires > descriptor_expires:
        raise PolicySyncError("policy sync snapshot is outside descriptor validity")
    if not historical_generation and revocation_checked < descriptor_issued:
        raise PolicySyncError("policy sync revocation check predates descriptor validity")
    if (expires - issued).total_seconds() > max_total_lifetime_seconds:
        raise PolicySyncError("policy sync snapshot lifetime exceeds local limit")
    if (expires - fresh).total_seconds() > max_degraded_window_seconds:
        raise PolicySyncError("policy sync degraded window exceeds local limit")
    if (issued - revocation_checked).total_seconds() > max_revocation_check_age_seconds:
        raise PolicySyncError("policy sync revocation check is too old")
    if not allow_expired and effective_now >= expires:
        raise PolicySyncError("policy sync snapshot expired")
    attestation_key = _verify_signed_mapping(
        snapshot.to_dict(),
        scope=ReceiptTrustScope(
            snapshot.scope.org_id,
            snapshot.scope.project_id,
            snapshot.scope.environment_id,
            POLICY_SYNC_ATTESTATION_PURPOSE,
        ),
        trust_epoch=snapshot.attestation_trust_epoch,
        key_id=snapshot.attestation_key_id,
        algorithm=snapshot.attestation_signature_algorithm,
        signature=snapshot.attestation_signature,
        signature_field="attestation_signature",
        trust_registry=trust_registry,
        now=effective_now,
        historical=historical_trust_verification,
    )
    policy, policy_key = _verify_policy_envelope(
        snapshot,
        trust_registry=trust_registry,
        now=effective_now,
        historical=historical_trust_verification,
    )
    if (
        attestation_key.public_key_spki_der == policy_key.public_key_spki_der
        or _constant_time_equal(
            attestation_key.public_key_fingerprint, policy_key.public_key_fingerprint
        )
    ):
        raise PolicySyncError(
            "policy sync attestation and policy envelope require distinct physical keys"
        )
    return _VerifiedPolicySnapshot(
        policy=policy,
        policy_key_fingerprint=policy_key.public_key_fingerprint,
        attestation_key_fingerprint=attestation_key.public_key_fingerprint,
    )


class AtomicJsonPolicyCache:
    """Atomic, owner-only policy snapshot cache with anti-rollback semantics."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        descriptor: RuntimeIdentityDescriptor,
        trust_registry: ReceiptTrustRegistry,
        max_total_lifetime_seconds: int = DEFAULT_MAX_POLICY_LIFETIME_SECONDS,
        max_degraded_window_seconds: int = DEFAULT_MAX_DEGRADED_WINDOW_SECONDS,
        max_revocation_check_age_seconds: int = DEFAULT_MAX_REVOCATION_CHECK_AGE_SECONDS,
        lock_timeout_seconds: float = DEFAULT_POLICY_CACHE_LOCK_TIMEOUT_SECONDS,
    ) -> None:
        self.path = Path(path)
        self.descriptor = descriptor
        self.trust_registry = trust_registry
        self.max_total_lifetime_seconds = _require_limit(
            max_total_lifetime_seconds, "max_total_lifetime_seconds"
        )
        self.max_degraded_window_seconds = _require_limit(
            max_degraded_window_seconds, "max_degraded_window_seconds"
        )
        self.max_revocation_check_age_seconds = _require_limit(
            max_revocation_check_age_seconds, "max_revocation_check_age_seconds"
        )
        if (
            isinstance(lock_timeout_seconds, bool)
            or not isinstance(lock_timeout_seconds, (int, float))
            or not math.isfinite(lock_timeout_seconds)
            or lock_timeout_seconds <= 0
            or lock_timeout_seconds > 30
        ):
            raise PolicySyncError("lock_timeout_seconds must be finite and in (0, 30]")
        self.lock_timeout_seconds = float(lock_timeout_seconds)
        self._high_water_store = _PolicyHighWaterStore(self.path)
        self._snapshot: PolicySyncSnapshot | None = None
        self._policy: RuleSetPolicy | None = None
        self._bytes_digest: str | None = None

    @property
    def snapshot(self) -> PolicySyncSnapshot | None:
        return self._snapshot

    @property
    def policy(self) -> RuleSetPolicy | None:
        return self._policy

    def load(self, *, now: datetime | None = None) -> PolicySyncSnapshot:
        with self._locked():
            loaded = self._load_current_under_lock(now=now)
            if loaded is None:
                raise PolicySyncError("policy cache is missing")
            snapshot, policy, digest = loaded
            mark = self._load_required_high_water()
            _validate_high_water_covers_snapshot(mark, snapshot)
            if not _constant_time_equal(mark.last_snapshot_hash, digest):
                raise _PolicyCacheBehindHighWaterError(
                    "policy cache is behind its high-water state"
                )
            self._snapshot = snapshot
            self._policy = policy
            self._bytes_digest = digest
            return snapshot

    def install(self, snapshot: PolicySyncSnapshot, *, now: datetime | None = None) -> bool:
        if type(snapshot) is not PolicySyncSnapshot:
            raise PolicySyncError("snapshot must be a PolicySyncSnapshot")
        snapshot = PolicySyncSnapshot.from_dict(snapshot.to_dict())
        verified = self._verify(snapshot, now=now)
        data = snapshot.canonical_json_bytes()
        with self._locked():
            loaded = self._load_current_under_lock(now=now)
            current = loaded[0] if loaded is not None else None
            high_water_exists = self._high_water_store._path.exists()
            if current is not None and not high_water_exists:
                raise PolicySyncError(
                    "existing policy cache has no high-water; discard and re-enroll"
                )
            mark = self._high_water_store._load() if high_water_exists else None
            if mark is not None:
                if current is not None:
                    try:
                        _validate_high_water_covers_snapshot(mark, current)
                    except _PolicyCacheBehindHighWaterError:
                        current = None
                _validate_snapshot_against_high_water(snapshot, mark)
            if current is not None:
                transition = _validate_snapshot_transition(current, snapshot, data)
                if transition == "identical":
                    assert mark is not None
                    if not _constant_time_equal(
                        mark.last_snapshot_hash, hashlib.sha256(data).hexdigest()
                    ):
                        raise _PolicyCacheBehindHighWaterError(
                            "policy cache is behind its high-water state"
                        )
                    if self._snapshot is None and loaded is not None:
                        self._snapshot, self._policy, self._bytes_digest = loaded
                    return False
            candidate_mark = _PolicyHighWater.from_snapshot(snapshot)
            self._high_water_store._persist(candidate_mark)
            self._atomic_replace(data)
            self._snapshot = snapshot
            self._policy = verified.policy
            self._bytes_digest = hashlib.sha256(data).hexdigest()
            return True

    def update_descriptor(self, descriptor: RuntimeIdentityDescriptor) -> None:
        """Adopt a strictly newer credential for the same enrolled runtime."""

        if descriptor.scope != self.descriptor.scope:
            raise PolicySyncError("runtime identity descriptor scope change rejected")
        if descriptor.runtime_identity_id != self.descriptor.runtime_identity_id:
            raise PolicySyncError("runtime identity descriptor identity change rejected")
        floor = self.descriptor.credential_generation
        if self._snapshot is not None:
            floor = max(floor, self._snapshot.credential_generation)
        if descriptor.credential_generation <= floor:
            raise PolicySyncError("runtime identity credential generation rollback rejected")
        self.descriptor = descriptor

    def assert_intact(self) -> None:
        if self._snapshot is None or self._policy is None or self._bytes_digest is None:
            raise PolicySyncError("policy cache is not loaded")
        data = self._read_bytes()
        if not _constant_time_equal(hashlib.sha256(data).hexdigest(), self._bytes_digest):
            raise PolicySyncError("policy cache changed after verification")

    def active_receipt_provenance(self) -> ManagedPolicyProvenance | None:
        resource = str(self.path.resolve(strict=False))
        active = (_ACTIVE_POLICY_BINDINGS.get() or {}).get(resource)
        if active is None or active.cache_id != id(self):
            return None
        return active.provenance

    @contextlib.contextmanager
    def receipt_binding_scope(
        self, *, now: datetime | None = None
    ) -> Generator[ManagedPolicyProvenance, None, None]:
        """Hold the durable cache lease while binding and executing a receipt."""

        effective_now = _effective_now(now)
        resource = str(self.path.resolve(strict=False))
        active = _ACTIVE_POLICY_BINDINGS.get() or {}
        existing = active.get(resource)
        if existing is not None:
            if existing.cache_id != id(self):
                raise PolicySyncError(
                    "policy cache resource is already bound by a different cache object"
                )
            yield existing.provenance
            return
        with self._locked():
            loaded = self._load_current_under_lock(now=effective_now)
            if loaded is None:
                raise PolicySyncError("policy cache is unavailable")
            snapshot, _, digest = loaded
            mark = self._load_required_high_water()
            _validate_high_water_covers_snapshot(mark, snapshot)
            if not _constant_time_equal(mark.last_snapshot_hash, digest):
                raise _PolicyCacheBehindHighWaterError(
                    "policy cache is behind its high-water state"
                )
            verified = self._verify(snapshot, now=effective_now)
            self._snapshot = snapshot
            self._policy = verified.policy
            self._bytes_digest = digest
            provenance = verified.provenance(snapshot)
            token = _ACTIVE_POLICY_BINDINGS.set(
                {**active, resource: _ActivePolicyBinding(id(self), provenance)}
            )
            try:
                yield provenance
            finally:
                _ACTIVE_POLICY_BINDINGS.reset(token)

    def _verify(
        self,
        snapshot: PolicySyncSnapshot,
        *,
        now: datetime | None,
        allow_expired: bool = False,
        historical: bool = False,
    ) -> _VerifiedPolicySnapshot:
        return _verify_policy_sync_snapshot(
            snapshot,
            descriptor=self.descriptor,
            trust_registry=self.trust_registry,
            now=now,
            max_total_lifetime_seconds=self.max_total_lifetime_seconds,
            max_degraded_window_seconds=self.max_degraded_window_seconds,
            max_revocation_check_age_seconds=self.max_revocation_check_age_seconds,
            allow_expired=allow_expired,
            allow_historical_credential=historical,
            historical_trust_verification=historical,
        )

    def _load_current_under_lock(
        self, *, now: datetime | None
    ) -> tuple[PolicySyncSnapshot, RuleSetPolicy, str] | None:
        if not self.path.exists():
            return None
        data = self._read_bytes()
        snapshot = PolicySyncSnapshot.from_json(data)
        verified = self._verify(snapshot, now=now, allow_expired=True, historical=True)
        return snapshot, verified.policy, hashlib.sha256(data).hexdigest()

    def _load_required_high_water(self) -> _PolicyHighWater:
        if not self._high_water_store._path.exists():
            raise PolicySyncError("policy high-water is missing")
        return self._high_water_store._load()

    @contextlib.contextmanager
    def _locked(self) -> Generator[None, None, None]:
        if not filesystem_is_lock_safe(self.path):
            raise PolicySyncError(
                "policy cache requires a filesystem with reliable cross-process locking"
            )
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _validate_cache_directory(self.path.parent)
        lock_path = self.path.with_name(f".{self.path.name}.lock")
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(lock_path, flags, 0o600)
        with os.fdopen(fd, "r+", encoding="utf-8") as lock_fh:
            info = os.fstat(lock_fh.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o777 != 0o600:
                raise PolicySyncError("policy cache lock must be a mode 0600 regular file")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise PolicySyncError("policy cache lock must be owned by current user")
            with _bounded_exclusive_file_lock(lock_fh, timeout_seconds=self.lock_timeout_seconds):
                yield

    def _read_bytes(self) -> bytes:
        _validate_cache_directory(self.path.parent)
        try:
            first = os.lstat(self.path)
        except FileNotFoundError as exc:
            raise PolicySyncError("policy cache is missing") from exc
        if stat.S_ISLNK(first.st_mode) or not stat.S_ISREG(first.st_mode):
            raise PolicySyncError("policy cache must be a regular file")
        if first.st_mode & 0o777 != 0o600:
            raise PolicySyncError("policy cache must be mode 0600")
        if hasattr(os, "getuid") and first.st_uid != os.getuid():
            raise PolicySyncError("policy cache must be owned by current user")
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.path, flags)
        except OSError as exc:
            raise PolicySyncError("policy cache is not readable") from exc
        try:
            current = os.fstat(fd)
            if (first.st_dev, first.st_ino) != (current.st_dev, current.st_ino):
                raise PolicySyncError("policy cache changed during open")
            if current.st_size <= 0 or current.st_size > 1_048_576:
                raise PolicySyncError("policy cache size is invalid")
            data = os.read(fd, current.st_size + 1)
            if len(data) != current.st_size:
                raise PolicySyncError("policy cache changed during read")
            return data
        finally:
            os.close(fd)

    def _atomic_replace(self, data: bytes) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _validate_cache_directory(self.path.parent)
        nonce = os.urandom(8).hex()
        tmp_path = self.path.with_name(f".{self.path.name}.{os.getpid()}.{nonce}.tmp")
        backup_path = self.path.with_name(f".{self.path.name}.{os.getpid()}.{nonce}.bak")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(tmp_path, flags, 0o600)
        backup_created = False
        replaced = False
        try:
            with os.fdopen(fd, "wb") as fh:
                fd = -1
                if os.fstat(fh.fileno()).st_mode & 0o777 != 0o600:
                    raise PolicySyncError("policy cache temp file must be mode 0600")
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            if self.path.exists():
                os.link(self.path, backup_path, follow_symlinks=False)
                backup_created = True
            os.replace(tmp_path, self.path)
            replaced = True
            _fsync_directory(self.path.parent)
        except Exception as exc:
            if fd >= 0:
                os.close(fd)
            with contextlib.suppress(FileNotFoundError):
                tmp_path.unlink()
            if replaced:
                try:
                    if backup_created:
                        os.replace(backup_path, self.path)
                    else:
                        self.path.unlink()
                    _fsync_directory(self.path.parent)
                except Exception as rollback_exc:
                    raise PolicySyncError(
                        "policy cache persistence failed and rollback could not be verified"
                    ) from rollback_exc
            with contextlib.suppress(FileNotFoundError):
                backup_path.unlink()
            raise exc
        with contextlib.suppress(FileNotFoundError):
            backup_path.unlink()


class SyncedRuleSetPolicy(Policy):
    """Kernel-compatible policy using only a verified local cache."""

    def __init__(
        self,
        cache: AtomicJsonPolicyCache,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._cache = cache
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def version(self) -> str:
        policy = self._cache.policy
        return policy.version if policy is not None else "policy-sync/unavailable"

    @property
    def mode(self) -> str:
        snapshot = self._cache.snapshot
        if snapshot is None:
            return "unavailable"
        now = _effective_now(self._clock())
        if now < _parse_timestamp(snapshot.fresh_until, "fresh_until"):
            return "fresh"
        if now < _parse_timestamp(snapshot.expires_at, "expires_at"):
            return "degraded_lkg"
        return "expired"

    @contextlib.contextmanager
    def receipt_binding_scope(self) -> Generator[ManagedPolicyProvenance, None, None]:
        with self._cache.receipt_binding_scope(now=self._clock()) as provenance:
            yield provenance

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        """Public policy evaluation always denies; managed authority is gateway-internal."""

        return self._fail_closed(call)

    def _evaluate_managed(
        self, call: ToolCall, provenance: ManagedPolicyProvenance
    ) -> DecisionRecord:
        """Evaluate only for UniversalGateway under its verified binding lease."""

        try:
            active_provenance = self._cache.active_receipt_provenance()
            if active_provenance is None or active_provenance != provenance:
                raise PolicySyncError(
                    "managed policy evaluation requires the gateway's active verified binding"
                )
            self._cache.assert_intact()
            snapshot = self._cache.snapshot
            if snapshot is None or self._cache.policy is None:
                raise PolicySyncError("policy cache is unavailable")
            now = _effective_now(self._clock())
            if now >= _parse_timestamp(snapshot.expires_at, "expires_at"):
                raise PolicySyncError("policy cache expired")
            # Re-resolve local trust on every evaluation so a locally installed
            # revocation takes effect immediately without any network call.
            verified = self._cache._verify(
                snapshot,
                now=now,
            )
            verified_provenance = verified.provenance(snapshot)
            if verified_provenance != provenance:
                raise PolicySyncError("managed policy provenance changed within binding scope")
            record = verified.policy.evaluate(call)
            return dataclasses.replace(
                record,
                policy_provenance_hash=provenance.compute_hash(),
            )
        except (PolicySyncError, TrustConfigurationError, OSError, ValueError, TypeError):
            return self._fail_closed(call)

    def _fail_closed(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.DENY,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("POLICY_SYNC_FAIL_CLOSED",),
            reason="local signed policy is unavailable or invalid",
        )


class PolicySyncClient:
    """Explicit sync client over an injected signed-request transport."""

    def __init__(
        self,
        *,
        signed_client: SignedRequestClient,
        cache: AtomicJsonPolicyCache,
        max_response_bytes: int = DEFAULT_MAX_POLICY_SYNC_RESPONSE_BYTES,
    ) -> None:
        self._signed_client = signed_client
        self._cache = cache
        self._max_response_bytes = _require_limit(max_response_bytes, "max_response_bytes")

    def sync(self, *, now: datetime | None = None) -> bool:
        effective_now = _effective_now(now)
        identity_id = self._cache.descriptor.runtime_identity_id
        force_full_sync = False
        if self._cache.snapshot is None and self._cache.path.exists():
            try:
                self._cache.load(now=effective_now)
            except _PolicyCacheBehindHighWaterError:
                # A high-water-first crash may leave a verified old cache behind
                # its preserved floor. Only this exact state forces an
                # authenticated unconditional fetch; corruption and missing
                # high-water failures continue to propagate fail closed.
                force_full_sync = True
        current = self._cache.snapshot
        use_validator = (
            not force_full_sync
            and current is not None
            and effective_now < _parse_timestamp(current.fresh_until, "fresh_until")
        )
        query = f"cursor={current.cursor}" if use_validator and current is not None else ""
        response = self._signed_client.request(
            method="GET",
            path=f"/v1/runtime-identities/{identity_id}/policy-bundle",
            query=query,
        )
        return self.apply_response(response, now=effective_now, allow_not_modified=use_validator)

    def apply_response(
        self,
        response: RuntimeHttpResponse,
        *,
        now: datetime | None = None,
        allow_not_modified: bool | None = None,
    ) -> bool:
        if len(response.body) > self._max_response_bytes:
            raise PolicySyncError("policy sync response exceeds local size limit")
        if response.status_code == 304:
            if response.body:
                raise PolicySyncError("policy sync 304 response must have an empty body")
            if allow_not_modified is None:
                current = self._cache.snapshot
                allow_not_modified = current is not None and _effective_now(now) < _parse_timestamp(
                    current.fresh_until, "fresh_until"
                )
            if not allow_not_modified:
                raise PolicySyncError("policy sync 304 response refused during forced renewal")
            if self._cache.snapshot is None:
                raise PolicySyncError("policy sync 304 response requires an existing cache")
            self._cache.assert_intact()
            return False
        if response.status_code != 200:
            raise PolicySyncError(f"policy sync refused with status {response.status_code}")
        snapshot = PolicySyncSnapshot.from_json(response.body)
        return self._cache.install(snapshot, now=now)


def _verify_policy_envelope(
    snapshot: PolicySyncSnapshot,
    *,
    trust_registry: ReceiptTrustRegistry,
    now: datetime,
    historical: bool = False,
) -> tuple[RuleSetPolicy, TrustedReceiptKey]:
    envelope = snapshot.policy_envelope
    _require_exact_dict(envelope, "policy_envelope", _ENVELOPE_FIELDS)
    if envelope.get("schema") != POLICY_ENVELOPE_SCHEMA:
        raise PolicySyncError("unsupported policy envelope schema")
    if envelope.get("purpose") != POLICY_ENVELOPE_PURPOSE:
        raise PolicySyncError("invalid policy envelope purpose")
    scope = _require_mapping(envelope.get("scope"), "policy_envelope.scope")
    _require_exact_dict(scope, "policy_envelope.scope", _ENVELOPE_SCOPE_FIELDS)
    expected_inner_scope = {
        "org_id": snapshot.scope.org_id,
        "project_id": snapshot.scope.project_id,
        "environment_id": snapshot.scope.environment_id,
    }
    if dict(scope) != expected_inner_scope:
        raise PolicySyncError("policy envelope scope mismatch")
    document = _require_mapping(envelope.get("document"), "policy_envelope.document")
    _require_exact_dict(document, "policy_envelope.document", {"id", "version", "rules"})
    rules = envelope.get("rules")
    if type(rules) is not list:
        raise PolicySyncError("policy_envelope.rules must be an array")
    if document.get("rules") != rules:
        raise PolicySyncError("policy envelope rules mismatch")
    content_hash = _require_sha256(envelope.get("content_hash"), "policy_envelope.content_hash")
    if not _constant_time_equal(sha256_json(document), content_hash):
        raise PolicySyncError("policy envelope content hash mismatch")
    if not _constant_time_equal(content_hash, snapshot.content_hash):
        raise PolicySyncError("policy sync content hash mismatch")
    policy = RuleSetPolicy.from_dict(document)
    inner_policy_id = _require_string(envelope.get("policy_id"), "policy_envelope.policy_id")
    inner_version = _require_string(envelope.get("version"), "policy_envelope.version")
    if (
        inner_policy_id != snapshot.policy_id
        or document.get("id") != snapshot.policy_id
        or policy.policy_id != snapshot.policy_id
    ):
        raise PolicySyncError("policy sync policy id mismatch")
    if (
        inner_version != snapshot.version
        or document.get("version") != snapshot.version
        or policy.version != snapshot.version
    ):
        raise PolicySyncError("policy sync policy version mismatch")
    inner_epoch = _require_positive_int(envelope.get("trust_epoch"), "policy_envelope.trust_epoch")
    inner_key_id = _require_string(envelope.get("key_id"), "policy_envelope.key_id")
    inner_algorithm = _require_string(
        envelope.get("signature_algorithm"), "policy_envelope.signature_algorithm"
    )
    inner_signature = _require_string(envelope.get("signature"), "policy_envelope.signature")
    policy_key = _verify_signed_mapping(
        envelope,
        scope=ReceiptTrustScope(
            snapshot.scope.org_id,
            snapshot.scope.project_id,
            snapshot.scope.environment_id,
            POLICY_ENVELOPE_PURPOSE,
        ),
        trust_epoch=inner_epoch,
        key_id=inner_key_id,
        algorithm=inner_algorithm,
        signature=inner_signature,
        signature_field="signature",
        trust_registry=trust_registry,
        now=now,
        historical=historical,
    )
    return policy, policy_key


def _validate_snapshot_transition(
    current: PolicySyncSnapshot,
    candidate: PolicySyncSnapshot,
    candidate_bytes: bytes,
) -> str:
    if candidate.credential_generation < current.credential_generation:
        raise PolicySyncError("policy sync credential generation rollback rejected")
    if candidate.head_generation < current.head_generation:
        raise PolicySyncError("policy sync rollback rejected")
    if candidate.head_generation > current.head_generation:
        return "advanced"
    if candidate_bytes == current.canonical_json_bytes():
        return "identical"
    if _lease_immutable_fields(candidate) != _lease_immutable_fields(current):
        raise PolicySyncError("same-generation policy sync equivocation rejected")
    if candidate.credential_generation == current.credential_generation:
        if candidate.credential_id != current.credential_id:
            raise PolicySyncError("same-generation credential equivocation rejected")
    elif candidate.credential_generation <= current.credential_generation:
        raise PolicySyncError("policy sync credential generation rollback rejected")
    if candidate.attestation_trust_epoch < current.attestation_trust_epoch:
        raise PolicySyncError("policy sync attestation trust epoch rollback rejected")
    if candidate.attestation_trust_epoch == current.attestation_trust_epoch and (
        candidate.attestation_key_id != current.attestation_key_id
        or candidate.attestation_signature_algorithm != current.attestation_signature_algorithm
    ):
        raise PolicySyncError("same-epoch policy sync attestation equivocation rejected")
    current_issued = _parse_timestamp(current.issued_at, "issued_at")
    candidate_issued = _parse_timestamp(candidate.issued_at, "issued_at")
    current_checked = _parse_timestamp(current.revocation_checked_at, "revocation_checked_at")
    candidate_checked = _parse_timestamp(candidate.revocation_checked_at, "revocation_checked_at")
    current_fresh = _parse_timestamp(current.fresh_until, "fresh_until")
    candidate_fresh = _parse_timestamp(candidate.fresh_until, "fresh_until")
    current_expires = _parse_timestamp(current.expires_at, "expires_at")
    candidate_expires = _parse_timestamp(candidate.expires_at, "expires_at")
    if (
        candidate_issued < current_issued
        or candidate_checked < current_checked
        or candidate_fresh < current_fresh
        or candidate_expires <= current_expires
    ):
        raise PolicySyncError("same-generation policy sync lease did not advance monotonically")
    return "renewed"


def _lease_immutable_fields(snapshot: PolicySyncSnapshot) -> dict[str, Any]:
    payload = snapshot.to_dict()
    for field in {
        "credential_id",
        "credential_generation",
        "issued_at",
        "revocation_checked_at",
        "fresh_until",
        "expires_at",
        "cursor",
        "attestation_purpose",
        "attestation_trust_epoch",
        "attestation_key_id",
        "attestation_signature_algorithm",
        "attestation_signature",
    }:
        payload.pop(field)
    return payload


def _immutable_head_binding_hash(snapshot: PolicySyncSnapshot) -> str:
    return sha256_json(
        {
            "scope": snapshot.scope.to_dict(),
            "runtime_identity_id": snapshot.runtime_identity_id,
            "head_generation": snapshot.head_generation,
            "head_updated_at": snapshot.head_updated_at,
            "policy_version_id": snapshot.policy_version_id,
            "policy_id": snapshot.policy_id,
            "version": snapshot.version,
            "content_hash": snapshot.content_hash,
            "policy_envelope": _copy_json_object(snapshot.policy_envelope, "policy_envelope"),
            "activation_receipt_id": snapshot.activation_receipt_id,
            "activation_receipt_hash": snapshot.activation_receipt_hash,
            "activation_event_hash": snapshot.activation_event_hash,
        }
    )


def _validate_high_water_covers_snapshot(
    mark: _PolicyHighWater, snapshot: PolicySyncSnapshot
) -> None:
    if mark.scope != snapshot.scope or mark.runtime_identity_id != snapshot.runtime_identity_id:
        raise PolicySyncError("policy high-water scope or runtime identity mismatch")
    if mark.max_head_generation < snapshot.head_generation:
        raise PolicySyncError("policy high-water head is lower than the cache")
    if (
        mark.max_head_generation == snapshot.head_generation
        and mark.immutable_head_binding_hash != _immutable_head_binding_hash(snapshot)
    ):
        raise PolicySyncError("policy high-water immutable head binding mismatch")
    if mark.max_credential_generation < snapshot.credential_generation:
        raise PolicySyncError("policy high-water credential generation is lower than the cache")
    if mark.max_attestation_trust_epoch < snapshot.attestation_trust_epoch:
        raise PolicySyncError("policy high-water trust epoch is lower than the cache")
    for mark_value, snapshot_value, field_name in (
        (mark.max_issued_at, snapshot.issued_at, "issued_at"),
        (mark.max_revocation_checked_at, snapshot.revocation_checked_at, "revocation_checked_at"),
        (mark.max_fresh_until, snapshot.fresh_until, "fresh_until"),
        (mark.max_expires_at, snapshot.expires_at, "expires_at"),
    ):
        if _parse_timestamp(mark_value, field_name) < _parse_timestamp(snapshot_value, field_name):
            raise PolicySyncError(f"policy high-water {field_name} is lower than the cache")


def _validate_snapshot_against_high_water(
    snapshot: PolicySyncSnapshot, mark: _PolicyHighWater
) -> None:
    if mark.scope != snapshot.scope or mark.runtime_identity_id != snapshot.runtime_identity_id:
        raise PolicySyncError("policy snapshot does not match its high-water scope")
    if snapshot.head_generation < mark.max_head_generation:
        raise PolicySyncError("policy snapshot rollback is below the durable high-water head")
    if (
        snapshot.head_generation == mark.max_head_generation
        and _immutable_head_binding_hash(snapshot) != mark.immutable_head_binding_hash
    ):
        raise PolicySyncError(
            "same-generation policy sync equivocation conflicts with durable high-water"
        )
    if snapshot.credential_generation < mark.max_credential_generation:
        raise PolicySyncError("policy snapshot credential is below durable high-water")
    if snapshot.attestation_trust_epoch < mark.max_attestation_trust_epoch:
        raise PolicySyncError("policy snapshot trust epoch is below durable high-water")
    for snapshot_value, mark_value, field_name in (
        (snapshot.issued_at, mark.max_issued_at, "issued_at"),
        (snapshot.revocation_checked_at, mark.max_revocation_checked_at, "revocation_checked_at"),
        (snapshot.fresh_until, mark.max_fresh_until, "fresh_until"),
        (snapshot.expires_at, mark.max_expires_at, "expires_at"),
    ):
        if _parse_timestamp(snapshot_value, field_name) < _parse_timestamp(mark_value, field_name):
            raise PolicySyncError(
                f"policy snapshot {field_name} did not advance monotonically above high-water"
            )


def _verify_signed_mapping(
    payload: Mapping[str, Any],
    *,
    scope: ReceiptTrustScope,
    trust_epoch: int,
    key_id: str,
    algorithm: str,
    signature: str,
    signature_field: str,
    trust_registry: ReceiptTrustRegistry,
    now: datetime,
    historical: bool = False,
) -> TrustedReceiptKey:
    try:
        key = trust_registry.resolve(
            scope=scope,
            trust_epoch=trust_epoch,
            algorithm=algorithm,
            key_id=key_id,
            now_iso=now.isoformat(),
            mode="historical" if historical else "execution",
        )
    except (TrustConfigurationError, ValueError, TypeError) as exc:
        raise PolicySyncError("policy sync trust could not be resolved") from exc
    unsigned = dict(payload)
    unsigned.pop(signature_field, None)
    if not key.verifier.verify(canonical_json(unsigned).encode("utf-8"), signature):
        raise PolicySyncError("policy sync signature is invalid")
    return key


def _require_exact_dict(payload: Mapping[str, Any], field: str, expected: set[str]) -> None:
    if type(payload) is not dict:
        raise PolicySyncError(f"{field} must be an exact JSON object")
    if any(type(key) is not str for key in payload):
        raise PolicySyncError(f"{field} keys must be strings")
    observed = set(payload)
    if observed != expected:
        raise PolicySyncError(f"{field} keys mismatch")


def _require_mapping(value: object, field: str) -> Mapping[str, Any]:
    if type(value) is not dict:
        raise PolicySyncError(f"{field} must be an exact JSON object")
    return value


def _require_string(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise PolicySyncError(f"{field} must be a non-empty string")
    return value


def _require_identifier(value: object, field: str) -> str:
    text = _require_string(value, field)
    if not _IDENTIFIER_RE.fullmatch(text):
        raise PolicySyncError(f"{field} is not a canonical identifier")
    return text


def _require_positive_int(value: object, field: str) -> int:
    if type(value) is not int or value < 1:
        raise PolicySyncError(f"{field} must be a positive integer")
    return value


def _require_limit(value: object, field: str) -> int:
    if type(value) is not int or value < 1:
        raise PolicySyncError(f"{field} must be a positive integer")
    return value


def _require_sha256(value: object, field: str) -> str:
    text = _require_string(value, field)
    if not _HEX64_RE.fullmatch(text):
        raise PolicySyncError(f"{field} must be lowercase SHA-256 hex")
    return text


def _require_cursor(value: object) -> str:
    text = _require_string(value, "cursor")
    if not _CURSOR_RE.fullmatch(text):
        raise PolicySyncError("cursor is malformed")
    return text


def _compute_policy_sync_cursor(snapshot: PolicySyncSnapshot) -> str:
    envelope = snapshot.policy_envelope
    binding = {
        "schema": "acgs.policy-sync.binding/v2",
        "scope": snapshot.scope.to_dict(),
        "runtime_identity_id": snapshot.runtime_identity_id,
        "credential_id": snapshot.credential_id,
        "credential_generation": snapshot.credential_generation,
        "head_generation": snapshot.head_generation,
        "head_updated_at": snapshot.head_updated_at,
        "policy_version_id": snapshot.policy_version_id,
        "policy_id": snapshot.policy_id,
        "version": snapshot.version,
        "content_hash": snapshot.content_hash,
        "policy_envelope_trust_epoch": envelope.get("trust_epoch"),
        "policy_envelope_key_id": envelope.get("key_id"),
        "policy_envelope_signature_algorithm": envelope.get("signature_algorithm"),
        "policy_envelope_signature": envelope.get("signature"),
        "activation_receipt_id": snapshot.activation_receipt_id,
        "activation_receipt_hash": snapshot.activation_receipt_hash,
        "activation_event_hash": snapshot.activation_event_hash,
        "attestation_purpose": snapshot.attestation_purpose,
        "attestation_trust_epoch": snapshot.attestation_trust_epoch,
        "attestation_key_id": snapshot.attestation_key_id,
        "attestation_signature_algorithm": snapshot.attestation_signature_algorithm,
    }
    digest = hashlib.sha256(canonical_json(binding).encode("utf-8")).digest()
    return "psync_" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@contextlib.contextmanager
def _bounded_exclusive_file_lock(
    lock_fh: TextIO, *, timeout_seconds: float
) -> Generator[None, None, None]:
    """Acquire the cache lock within a bounded interval or fail closed."""

    deadline = time.monotonic() + timeout_seconds
    try:
        import fcntl
    except ModuleNotFoundError:
        fcntl = None  # type: ignore[assignment]
    if fcntl is not None:
        while True:
            try:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise PolicySyncError("policy cache lock acquisition timed out") from exc
                time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
        try:
            yield
        finally:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
        return

    try:
        import msvcrt
    except ModuleNotFoundError as exc:
        raise PolicySyncError("policy cache requires a platform file-lock primitive") from exc
    while True:
        try:
            lock_fh.seek(0)
            msvcrt.locking(lock_fh.fileno(), msvcrt.LK_NBLCK, 1)
            break
        except OSError as exc:
            if time.monotonic() >= deadline:
                raise PolicySyncError("policy cache lock acquisition timed out") from exc
            time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
    try:
        yield
    finally:
        lock_fh.seek(0)
        msvcrt.locking(lock_fh.fileno(), msvcrt.LK_UNLCK, 1)


def _read_owner_only_regular_file(path: Path, *, label: str) -> bytes:
    _validate_cache_directory(path.parent)
    try:
        first = os.lstat(path)
    except FileNotFoundError as exc:
        raise PolicySyncError(f"{label} is missing") from exc
    if stat.S_ISLNK(first.st_mode) or not stat.S_ISREG(first.st_mode):
        raise PolicySyncError(f"{label} must be a regular file")
    if first.st_mode & 0o777 != 0o600:
        raise PolicySyncError(f"{label} must be mode 0600")
    if hasattr(os, "getuid") and first.st_uid != os.getuid():
        raise PolicySyncError(f"{label} must be owned by current user")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        current = os.fstat(fd)
        if (first.st_dev, first.st_ino) != (current.st_dev, current.st_ino):
            raise PolicySyncError(f"{label} changed during open")
        if current.st_size <= 0 or current.st_size > 1_048_576:
            raise PolicySyncError(f"{label} size is invalid")
        data = os.read(fd, current.st_size + 1)
        if len(data) != current.st_size:
            raise PolicySyncError(f"{label} changed during read")
        return data
    finally:
        os.close(fd)


def _atomic_owner_only_replace(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _validate_cache_directory(path.parent)
    nonce = os.urandom(8).hex()
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.{nonce}.tmp")
    backup_path = path.with_name(f".{path.name}.{os.getpid()}.{nonce}.bak")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(tmp_path, flags, 0o600)
    backup_created = False
    replaced = False
    try:
        with os.fdopen(fd, "wb") as fh:
            fd = -1
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if path.exists():
            os.link(path, backup_path, follow_symlinks=False)
            backup_created = True
        os.replace(tmp_path, path)
        replaced = True
        _fsync_directory(path.parent)
    except Exception:
        if fd >= 0:
            os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            tmp_path.unlink()
        if replaced:
            try:
                if backup_created:
                    os.replace(backup_path, path)
                else:
                    path.unlink()
                _fsync_directory(path.parent)
            except Exception as rollback_exc:
                raise PolicySyncError(
                    f"atomic persistence for {path.name} failed and rollback was unverified"
                ) from rollback_exc
        with contextlib.suppress(FileNotFoundError):
            backup_path.unlink()
        raise
    with contextlib.suppress(FileNotFoundError):
        backup_path.unlink()


def _require_timestamp(value: object, field: str) -> str:
    text = _require_string(value, field)
    _parse_timestamp(text, field)
    return text


def _parse_timestamp(value: str, field: str) -> datetime:
    if not value.endswith("Z"):
        raise PolicySyncError(f"{field} must use canonical UTC Z form")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PolicySyncError(f"{field} must be an ISO-8601 UTC timestamp") from exc
    return parsed.astimezone(UTC)


def _effective_now(now: datetime | None) -> datetime:
    current = datetime.now(UTC) if now is None else now
    if current.tzinfo is None:
        raise PolicySyncError("now must be timezone-aware")
    return current.astimezone(UTC)


def _loads_json_object_no_duplicates(raw: str | bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PolicySyncError("duplicate JSON key rejected")
            result[key] = value
        return result

    try:
        parsed = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError, PolicySyncError) as exc:
        raise PolicySyncError("policy sync snapshot JSON is malformed") from exc
    if type(parsed) is not dict:
        raise PolicySyncError("policy sync snapshot JSON must be an object")
    return parsed


def _copy_json_object(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    _validate_json_value(value, field)
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        copied = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise PolicySyncError(f"{field} must contain finite JSON values") from exc
    if type(copied) is not dict:
        raise PolicySyncError(f"{field} must be an object")
    return copied


def _validate_json_value(value: object, field: str) -> None:
    value_type = type(value)
    if value is None or value_type in (str, int, bool):
        return
    if value_type is float:
        import math

        if not math.isfinite(cast(float, value)):
            raise PolicySyncError(f"{field} must contain finite JSON values")
        return
    if value_type is list:
        for index, item in enumerate(cast(list[object], value)):
            _validate_json_value(item, f"{field}[{index}]")
        return
    if value_type is dict:
        for key, item in cast(dict[object, object], value).items():
            if type(key) is not str:
                raise PolicySyncError(f"{field} keys must be strings")
            _validate_json_value(item, f"{field}.{key}")
        return
    raise PolicySyncError(f"{field} must contain exact JSON values")


def _constant_time_equal(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _validate_cache_directory(path: Path) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError as exc:
        raise PolicySyncError("policy cache directory is missing") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise PolicySyncError("policy cache directory must be a directory")
    if info.st_mode & 0o077:
        raise PolicySyncError("policy cache directory must not grant group or other access")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise PolicySyncError("policy cache directory must be owned by current user")
