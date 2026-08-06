"""Authenticated, read-only distribution of signed active policy snapshots."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import sqlalchemy as sa
from gove_zone.receipt import safe_result_hash
from gove_zone.runtime_identity import (
    RuntimeIdentityError,
    sha256_bytes,
    verify_signed_runtime_request,
)
from gove_zone.signing import Ed25519Signer
from gove_zone.trust import ReceiptTrustScope, TrustConfigurationError
from sqlalchemy.orm import Session, sessionmaker

from acgs_control_plane.managed_mutations import (
    ManagedReplayArtifactValidationError,
    ReceiptArtifactSealer,
    validate_managed_replay_artifacts,
)
from acgs_control_plane.models import (
    EnvironmentPolicyHead,
    ManagedDecisionReceipt,
    ManagedTrustKey,
    PolicyVersion,
    RuntimeCredentialGeneration,
    RuntimeIdentity,
    RuntimeIdentityGate,
    utcnow,
)
from acgs_control_plane.policy_registry import (
    CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
    POLICY_ENVELOPE_PURPOSE,
    _verify_envelope,
)
from acgs_control_plane.runtime_enrollment import (
    RUNTIME_ENROLLMENT_AUTHORITY,
    RUNTIME_SIGNED_REQUEST_SKEW_SECONDS,
    RuntimeEnrollmentHttpError,
    _parse_runtime_timestamp,
    _runtime_public_key_bytes,
    _runtime_timestamp,
    _to_utc,
    validate_current_runtime_identity_binding,
)
from acgs_control_plane.schemas import PolicySyncSnapshot
from acgs_control_plane.trust import (
    InProcessPlatformIssuer,
    ManagedPlatformIssuer,
    ManagedTrustError,
    SqlReceiptTrustRegistry,
)

POLICY_SYNC_ATTESTATION_PURPOSE = "acgs.policy-sync-attestation/v1"
POLICY_SYNC_SCHEMA = "acgs.policy-sync.snapshot/v2"
POLICY_SYNC_PURPOSE = "acgs.policy-sync/v2"
POLICY_SYNC_PATH_TEMPLATE = "/v1/runtime-identities/{identity_id}/policy-bundle"
POLICY_SYNC_FRESH_SECONDS = 60
POLICY_SYNC_EXPIRY_SECONDS = 300
_CURSOR_RE = re.compile(r"psync_[A-Za-z0-9_-]{43}")
_LOCAL_POLICY_SYNC_ATTESTATION_SEED = hashlib.sha256(
    b"acgs-local-policy-sync-attestation-issuer/v1"
).digest()


def local_policy_sync_attestation_issuer() -> InProcessPlatformIssuer:
    """Deterministic local-only issuer isolated from policy publication trust."""

    return InProcessPlatformIssuer(
        Ed25519Signer.from_private_bytes(
            _LOCAL_POLICY_SYNC_ATTESTATION_SEED,
            key_id="local-control-plane-policy-sync-attestation",
        ),
        allowed_purposes=frozenset({POLICY_SYNC_ATTESTATION_PURPOSE}),
    )


@dataclass(frozen=True)
class PolicySyncAuth:
    key_id: str
    credential_id: str
    credential_generation: int
    audience: str
    timestamp: str
    nonce: str
    body_sha256: str
    signature: str


@dataclass(frozen=True)
class PolicySyncResult:
    snapshot: PolicySyncSnapshot
    etag: str
    not_modified: bool


class PolicySyncService:
    """Build a signed snapshot from one locked, revalidated database view."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        attestation_issuer: ManagedPlatformIssuer,
        policy_registry_issuer: ManagedPlatformIssuer,
        receipt_sealer: ReceiptArtifactSealer,
        descriptor_signer: Any,
    ) -> None:
        self._session_factory = session_factory
        self._attestation_issuer = attestation_issuer
        self._policy_registry_issuer = policy_registry_issuer
        self._receipt_sealer = receipt_sealer
        self._descriptor_signer = descriptor_signer

    def fetch(
        self,
        *,
        identity_id: str,
        auth: PolicySyncAuth,
        raw_query: str,
        raw_path: bytes,
        body: bytes,
        cursor: str | None,
    ) -> PolicySyncResult:
        _validate_query(raw_query=raw_query, cursor=cursor)
        now = utcnow()
        path = POLICY_SYNC_PATH_TEMPLATE.format(identity_id=identity_id)
        try:
            expected_raw_path = path.encode("ascii")
        except UnicodeEncodeError as exc:
            raise _authentication_refused() from exc
        if raw_path != expected_raw_path or body != b"":
            raise _authentication_refused()
        with self._session_factory() as session, session.begin():
            identity, credential = _authenticate_runtime_read(
                session,
                descriptor_signer=self._descriptor_signer,
                identity_id=identity_id,
                auth=auth,
                path=path,
                query=raw_query,
                body=body,
                now=now,
            )
            gate = _active_gate(session, identity=identity)
            head, version = _active_policy_snapshot(session, identity=identity)
            envelope = dict(version.canonical_envelope)
            _verify_envelope(
                session,
                envelope,
                expected_org_id=identity.org_id,
                expected_project_id=identity.project_id,
                expected_environment_id=identity.environment_id,
                expected_policy_id=version.policy_id,
                expected_version=version.version,
                expected_document=version.document,
            )
            _require_version_matches_envelope(version=version, envelope=envelope)
            activation_receipt, activation_event_hash = _validated_activation_evidence(
                session,
                head=head,
                version=version,
                receipt_sealer=self._receipt_sealer,
            )
            publisher_scope = ReceiptTrustScope(
                identity.org_id,
                identity.project_id,
                identity.environment_id,
                POLICY_ENVELOPE_PURPOSE,
            )
            attestation_scope = ReceiptTrustScope(
                identity.org_id,
                identity.project_id,
                identity.environment_id,
                POLICY_SYNC_ATTESTATION_PURPOSE,
            )
            try:
                trust_registry = SqlReceiptTrustRegistry(session, lock_rows=True)
                publisher_key = trust_registry.resolve(
                    scope=publisher_scope,
                    trust_epoch=version.trust_epoch,
                    algorithm=version.signature_algorithm,
                    key_id=version.key_id,
                    now_iso=_runtime_timestamp(_to_utc(now)),
                )
                attestation_row = _active_attestation_trust_row(
                    session,
                    org_id=identity.org_id,
                    project_id=identity.project_id,
                    environment_id=identity.environment_id,
                )
                attestation_key = trust_registry.resolve(
                    scope=attestation_scope,
                    trust_epoch=attestation_row.activated_epoch,
                    algorithm=attestation_row.algorithm,
                    key_id=attestation_row.key_id,
                    now_iso=_runtime_timestamp(_to_utc(now)),
                )
                attestation_signer = self._attestation_issuer.signer_for_scope(
                    attestation_scope,
                    trust_epoch=attestation_key.activated_epoch,
                )
            except (TrustConfigurationError, ManagedTrustError) as exc:
                raise _attestation_refused() from exc
            if self._attestation_issuer is self._policy_registry_issuer:
                raise _attestation_refused()
            if (
                attestation_signer.key_id != attestation_key.key_id
                or attestation_signer.algorithm != attestation_key.algorithm
                or attestation_key.key_id == publisher_key.key_id
                or attestation_key.public_key_fingerprint == publisher_key.public_key_fingerprint
                or attestation_key.public_key_spki_der == publisher_key.public_key_spki_der
            ):
                raise _attestation_refused()

            immutable = _immutable_binding(
                identity=identity,
                credential=credential,
                gate=gate,
                head=head,
                version=version,
                envelope=envelope,
                attestation_purpose=POLICY_SYNC_ATTESTATION_PURPOSE,
                attestation_trust_epoch=attestation_key.activated_epoch,
                attestation_key_id=attestation_signer.key_id,
                attestation_algorithm=attestation_signer.algorithm,
                activation_receipt_id=activation_receipt.receipt_id,
                activation_receipt_hash=activation_receipt.receipt_hash,
                activation_event_hash=activation_event_hash,
            )
            binding_bytes = _canonical_bytes(immutable)
            cursor_value = "psync_" + _b64url(hashlib.sha256(binding_bytes).digest())
            etag_digest = hashlib.sha256(
                b"acgs-policy-sync-etag/v2\x00" + binding_bytes
            ).hexdigest()
            etag = f'"{etag_digest}"'

            issued_at = _to_utc(now)
            validity_cap = min(
                _to_utc(credential.not_after),
                _to_utc(datetime.fromisoformat(publisher_key.not_after.replace("Z", "+00:00"))),
                _to_utc(datetime.fromisoformat(attestation_key.not_after.replace("Z", "+00:00"))),
            )
            fresh_until = min(
                issued_at + timedelta(seconds=POLICY_SYNC_FRESH_SECONDS), validity_cap
            )
            expires_at = min(
                issued_at + timedelta(seconds=POLICY_SYNC_EXPIRY_SECONDS), validity_cap
            )
            if not issued_at < fresh_until < expires_at:
                raise RuntimeEnrollmentHttpError(
                    503,
                    "POLICY_SNAPSHOT_STALE",
                    "unavailable",
                    "active policy snapshot cannot be issued within the required validity window",
                )
            unsigned: dict[str, Any] = {
                "schema": POLICY_SYNC_SCHEMA,
                "purpose": POLICY_SYNC_PURPOSE,
                "scope": {
                    "org_id": identity.org_id,
                    "project_id": identity.project_id,
                    "environment_id": identity.environment_id,
                    "gate_id": gate.id,
                },
                "runtime_identity_id": identity.id,
                "credential_id": credential.id,
                "credential_generation": credential.generation,
                "cursor": cursor_value,
                "head_generation": head.generation,
                "head_updated_at": _runtime_timestamp(_to_utc(head.updated_at)),
                "policy_version_id": version.id,
                "policy_id": version.policy_id,
                "version": version.version,
                "content_hash": version.content_hash,
                "policy_envelope": envelope,
                "activation_receipt_id": activation_receipt.receipt_id,
                "activation_receipt_hash": activation_receipt.receipt_hash,
                "activation_event_hash": activation_event_hash,
                "attestation_purpose": POLICY_SYNC_ATTESTATION_PURPOSE,
                "attestation_trust_epoch": attestation_key.activated_epoch,
                "attestation_key_id": attestation_signer.key_id,
                "attestation_signature_algorithm": attestation_signer.algorithm,
                "issued_at": _runtime_timestamp(issued_at),
                "revocation_checked_at": _runtime_timestamp(issued_at),
                "fresh_until": _runtime_timestamp(fresh_until),
                "expires_at": _runtime_timestamp(expires_at),
            }
            unsigned_bytes = _canonical_bytes(unsigned)
            try:
                signature = attestation_signer.sign(unsigned_bytes)
                signature_valid = attestation_key.verifier.verify(unsigned_bytes, signature)
            except (TrustConfigurationError, ManagedTrustError, RuntimeError, ValueError) as exc:
                raise _attestation_refused() from exc
            if not signature_valid:
                raise _attestation_refused()
            snapshot = PolicySyncSnapshot(**unsigned, attestation_signature=signature)
            return PolicySyncResult(
                snapshot=snapshot,
                etag=etag,
                not_modified=cursor is not None and cursor == cursor_value,
            )


def _authenticate_runtime_read(
    session: Session,
    *,
    descriptor_signer: Any,
    identity_id: str,
    auth: PolicySyncAuth,
    path: str,
    query: str,
    body: bytes,
    now: Any,
) -> tuple[RuntimeIdentity, RuntimeCredentialGeneration]:
    if body != b"" or auth.body_sha256 != sha256_bytes(body):
        raise _authentication_refused()
    identity = session.scalars(
        sa.select(RuntimeIdentity)
        .where(RuntimeIdentity.id == identity_id)
        .with_for_update(read=True)
    ).one_or_none()
    if identity is None or identity.status != "active":
        raise _authentication_refused()
    if auth.key_id != identity.workload_key_id:
        raise _authentication_refused()
    if auth.audience != RUNTIME_ENROLLMENT_AUTHORITY:
        raise _authentication_refused()
    credential = _active_credential(session, identity=identity, auth=auth, now=now)
    try:
        validate_current_runtime_identity_binding(
            identity,
            credential,
            descriptor_signer=descriptor_signer,
            now=_to_utc(now),
        )
    except RuntimeIdentityError as exc:
        raise _authentication_refused() from exc
    try:
        verify_signed_runtime_request(
            public_key=_runtime_public_key_bytes(identity.public_key),
            signature=auth.signature,
            method="GET",
            path=path,
            query=query,
            body=body,
            timestamp=auth.timestamp,
            nonce=auth.nonce,
            key_id=auth.key_id,
            identity_id=identity.id,
            credential_id=auth.credential_id,
            credential_generation=auth.credential_generation,
            idempotency_key=None,
            audience=auth.audience,
        )
    except RuntimeIdentityError as exc:
        raise _authentication_refused() from exc
    try:
        timestamp_skew = abs(
            (_parse_runtime_timestamp(auth.timestamp) - _to_utc(now)).total_seconds()
        )
    except RuntimeEnrollmentHttpError as exc:
        raise _authentication_refused() from exc
    if timestamp_skew > RUNTIME_SIGNED_REQUEST_SKEW_SECONDS:
        raise _authentication_refused()
    return identity, credential


def _active_credential(
    session: Session,
    *,
    identity: RuntimeIdentity,
    auth: PolicySyncAuth,
    now: Any,
) -> RuntimeCredentialGeneration:
    credential = session.scalars(
        sa.select(RuntimeCredentialGeneration)
        .where(
            RuntimeCredentialGeneration.org_id == identity.org_id,
            RuntimeCredentialGeneration.project_id == identity.project_id,
            RuntimeCredentialGeneration.environment_id == identity.environment_id,
            RuntimeCredentialGeneration.identity_id == identity.id,
            RuntimeCredentialGeneration.id == auth.credential_id,
            RuntimeCredentialGeneration.generation == auth.credential_generation,
        )
        .with_for_update(read=True)
    ).one_or_none()
    if (
        credential is None
        or credential.status != "active"
        or identity.current_generation != auth.credential_generation
        or _to_utc(now) < _to_utc(credential.not_before)
        or _to_utc(now) >= _to_utc(credential.not_after)
    ):
        raise _authentication_refused()
    if credential.workload_key_id != auth.key_id:
        raise _authentication_refused()
    if credential.public_key_thumbprint != identity.public_key_thumbprint:
        raise _authentication_refused()
    return credential


def _active_gate(session: Session, *, identity: RuntimeIdentity) -> RuntimeIdentityGate:
    gate = session.scalars(
        sa.select(RuntimeIdentityGate)
        .where(
            RuntimeIdentityGate.org_id == identity.org_id,
            RuntimeIdentityGate.project_id == identity.project_id,
            RuntimeIdentityGate.environment_id == identity.environment_id,
            RuntimeIdentityGate.id == identity.gate_id,
            RuntimeIdentityGate.status == "active",
        )
        .with_for_update(read=True)
    ).one_or_none()
    if gate is None:
        raise _authentication_refused()
    return gate


def _active_policy_snapshot(
    session: Session,
    *,
    identity: RuntimeIdentity,
) -> tuple[EnvironmentPolicyHead, PolicyVersion]:
    row = session.execute(
        sa.select(EnvironmentPolicyHead, PolicyVersion)
        .join(
            PolicyVersion,
            sa.and_(
                PolicyVersion.org_id == EnvironmentPolicyHead.org_id,
                PolicyVersion.project_id == EnvironmentPolicyHead.project_id,
                PolicyVersion.environment_id == EnvironmentPolicyHead.environment_id,
                PolicyVersion.id == EnvironmentPolicyHead.active_policy_version_id,
            ),
        )
        .where(
            EnvironmentPolicyHead.org_id == identity.org_id,
            EnvironmentPolicyHead.project_id == identity.project_id,
            EnvironmentPolicyHead.environment_id == identity.environment_id,
            EnvironmentPolicyHead.status == "active",
        )
        .with_for_update(read=True)
    ).one_or_none()
    if row is None:
        raise RuntimeEnrollmentHttpError(
            503,
            "POLICY_HEAD_UNAVAILABLE",
            "unavailable",
            "active policy head is unavailable",
        )
    return row._tuple()


def _require_version_matches_envelope(*, version: PolicyVersion, envelope: dict[str, Any]) -> None:
    if (
        version.purpose != POLICY_ENVELOPE_PURPOSE
        or version.content_hash != envelope.get("content_hash")
        or version.key_id != envelope.get("key_id")
        or version.signature_algorithm != envelope.get("signature_algorithm")
        or version.signature != envelope.get("signature")
        or version.trust_epoch != envelope.get("trust_epoch")
        or list(version.rules) != list(envelope.get("rules", []))
    ):
        raise RuntimeEnrollmentHttpError(
            503,
            "POLICY_SIGNATURE_REFUSED",
            "signature_refused",
            "active policy version does not match its signed envelope",
        )


def _validated_activation_evidence(
    session: Session,
    *,
    head: EnvironmentPolicyHead,
    version: PolicyVersion,
    receipt_sealer: ReceiptArtifactSealer,
) -> tuple[ManagedDecisionReceipt, str]:
    if head.generation < 1:
        raise _activation_evidence_refused()
    receipt = session.scalars(
        sa.select(ManagedDecisionReceipt)
        .where(
            ManagedDecisionReceipt.org_id == head.org_id,
            ManagedDecisionReceipt.project_id == head.project_id,
            ManagedDecisionReceipt.environment_id == head.environment_id,
            ManagedDecisionReceipt.receipt_id == head.receipt_id,
        )
        .with_for_update(read=True)
    ).one_or_none()
    if receipt is None:
        raise _activation_evidence_refused()
    try:
        artifacts = validate_managed_replay_artifacts(
            session,
            receipt,
            expected_action=CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
            expected_actor=receipt.actor,
            expected_decision="allow",
            expected_args={
                "policy_version_id": version.id,
                "expected_generation": head.generation - 1,
            },
            expected_result_hash=safe_result_hash(
                {"policy_version_id": version.id, "generation": head.generation}
            ),
            receipt_sealer=receipt_sealer,
        )
    except ManagedReplayArtifactValidationError as exc:
        raise _activation_evidence_refused() from exc
    return receipt, artifacts.event.event_hash


def _active_attestation_trust_row(
    session: Session,
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
) -> ManagedTrustKey:
    rows = list(
        session.scalars(
            sa.select(ManagedTrustKey)
            .where(
                ManagedTrustKey.org_id == org_id,
                ManagedTrustKey.project_id == project_id,
                ManagedTrustKey.environment_id == environment_id,
                ManagedTrustKey.purpose == POLICY_SYNC_ATTESTATION_PURPOSE,
                ManagedTrustKey.status == "active",
            )
            .with_for_update(read=True)
        )
    )
    if len(rows) != 1:
        raise _attestation_refused()
    return rows[0]


def _immutable_binding(
    *,
    identity: RuntimeIdentity,
    credential: RuntimeCredentialGeneration,
    gate: RuntimeIdentityGate,
    head: EnvironmentPolicyHead,
    version: PolicyVersion,
    envelope: dict[str, Any],
    attestation_purpose: str,
    attestation_trust_epoch: int,
    attestation_key_id: str,
    attestation_algorithm: str,
    activation_receipt_id: str,
    activation_receipt_hash: str,
    activation_event_hash: str,
) -> dict[str, Any]:
    return {
        "schema": "acgs.policy-sync.binding/v2",
        "scope": {
            "org_id": identity.org_id,
            "project_id": identity.project_id,
            "environment_id": identity.environment_id,
            "gate_id": gate.id,
        },
        "runtime_identity_id": identity.id,
        "credential_id": credential.id,
        "credential_generation": credential.generation,
        "head_generation": head.generation,
        "head_updated_at": _runtime_timestamp(_to_utc(head.updated_at)),
        "policy_version_id": version.id,
        "policy_id": version.policy_id,
        "version": version.version,
        "content_hash": version.content_hash,
        "policy_envelope_trust_epoch": envelope["trust_epoch"],
        "policy_envelope_key_id": envelope["key_id"],
        "policy_envelope_signature_algorithm": envelope["signature_algorithm"],
        "policy_envelope_signature": envelope["signature"],
        "activation_receipt_id": activation_receipt_id,
        "activation_receipt_hash": activation_receipt_hash,
        "activation_event_hash": activation_event_hash,
        "attestation_purpose": attestation_purpose,
        "attestation_trust_epoch": attestation_trust_epoch,
        "attestation_key_id": attestation_key_id,
        "attestation_signature_algorithm": attestation_algorithm,
    }


def _validate_query(*, raw_query: str, cursor: str | None) -> None:
    if cursor is None:
        expected = ""
    elif _CURSOR_RE.fullmatch(cursor) is None:
        raise RuntimeEnrollmentHttpError(
            400,
            "POLICY_CURSOR_INVALID",
            "bad_request",
            "policy synchronization cursor is invalid",
        )
    else:
        expected = f"cursor={cursor}"
    if raw_query != expected:
        raise RuntimeEnrollmentHttpError(
            400,
            "POLICY_CURSOR_INVALID",
            "bad_request",
            "policy synchronization query is not canonical",
        )


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _authentication_refused() -> RuntimeEnrollmentHttpError:
    return RuntimeEnrollmentHttpError(
        401,
        "RUNTIME_AUTHENTICATION_FAILED",
        "unauthorized",
        "runtime request authentication failed",
    )


def _attestation_refused() -> RuntimeEnrollmentHttpError:
    return RuntimeEnrollmentHttpError(
        503,
        "POLICY_SYNC_ATTESTATION_REFUSED",
        "attestation_refused",
        "policy synchronization attestation was refused",
    )


def _activation_evidence_refused() -> RuntimeEnrollmentHttpError:
    return RuntimeEnrollmentHttpError(
        503,
        "POLICY_ACTIVATION_EVIDENCE_REFUSED",
        "evidence_refused",
        "active policy activation evidence was refused",
    )


__all__ = [
    "POLICY_SYNC_ATTESTATION_PURPOSE",
    "POLICY_SYNC_PATH_TEMPLATE",
    "POLICY_SYNC_PURPOSE",
    "POLICY_SYNC_SCHEMA",
    "PolicySyncAuth",
    "PolicySyncResult",
    "PolicySyncService",
    "local_policy_sync_attestation_issuer",
]
