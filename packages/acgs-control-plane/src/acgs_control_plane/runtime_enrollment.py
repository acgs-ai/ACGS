"""Runtime identity enrollment for hosted signed runtime operations."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

import sqlalchemy as sa
from gove_zone.decision import Decision, DecisionRecord, canonical_json, sha256_json
from gove_zone.errors import ReceiptAlreadyUsedError, ReceiptValidationError
from gove_zone.receipt import DecisionReceipt, safe_result_hash
from gove_zone.runtime_identity import (
    GateScope,
    InMemoryEd25519WorkloadKeyProvider,
    RuntimeIdentityError,
    b64url_decode,
    sha256_bytes,
    sha256_text,
    verify_enrollment_pop,
    verify_signed_runtime_request,
)
from gove_zone.runtime_identity import (
    RuntimeIdentityDescriptor as GoveRuntimeIdentityDescriptor,
)
from gove_zone.runtime_identity import (
    public_key_thumbprint as gove_public_key_thumbprint,
)
from gove_zone.signing import Ed25519Signer
from gove_zone.tool import ToolCall, normalize_path_context
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, ReceiptTrustScope, TrustConfigurationError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from acgs_control_plane.agent_registration import _active_policy_context
from acgs_control_plane.auth import Principal
from acgs_control_plane.managed_mutations import (
    CONTROL_PLANE_RUNTIME_BOOTSTRAP_ISSUE_ACTION,
    CONTROL_PLANE_RUNTIME_IDENTITY_ENROLL_ACTION,
    CONTROL_PLANE_RUNTIME_IDENTITY_RENEW_ACTION,
    CONTROL_PLANE_RUNTIME_IDENTITY_REVOKE_ACTION,
    AesGcmReceiptArtifactSealer,
    ManagedMutationContext,
    ManagedMutationReplayResult,
    ManagedMutationResult,
    ManagedMutationUnitOfWork,
    ManagedNonExecutableEvidenceResult,
    ManagedReplayArtifacts,
    ManagedReplayArtifactValidationError,
    managed_mutation_execution_boundary,
    validate_managed_replay_artifacts,
)
from acgs_control_plane.models import (
    Environment,
    EnvironmentPolicyHead,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedOutboxMessage,
    Organization,
    PolicyVersion,
    Project,
    RuntimeCredentialGeneration,
    RuntimeEnrollmentBootstrap,
    RuntimeEnrollmentIdempotency,
    RuntimeIdentity,
    RuntimeIdentityGate,
    RuntimeOperationIdempotency,
    RuntimeRequestNonce,
    new_id,
    utcnow,
)
from acgs_control_plane.schemas import (
    RuntimeEnrollmentBootstrapCreateRequest,
    RuntimeEnrollmentBootstrapCreateResponse,
    RuntimeEnrollmentRequest,
    RuntimeEnrollmentResponse,
    RuntimeIdentityDescriptor,
    RuntimeIdentityRevokeRequest,
    RuntimeSignedRequest,
)
from acgs_control_plane.trust import (
    InProcessPlatformIssuer,
    ManagedPlatformIssuer,
    ManagedReceiptContext,
    ManagedTrustError,
    active_trust_epoch_for_scope,
    mint_managed_decision_receipt_v2,
)

RUNTIME_BOOTSTRAP_TTL_SECONDS = 600
RUNTIME_BOOTSTRAP_MAX_TTL_SECONDS = 900
RUNTIME_CREDENTIAL_TTL_SECONDS = 24 * 60 * 60
RUNTIME_SIGNED_REQUEST_SKEW_SECONDS = 30
RUNTIME_ENROLLMENT_AUTHORITY = "control-plane.runtime-enrollment:v1"
RUNTIME_ENROLLMENT_VALIDATOR_ROLE = "control-plane.runtime-policy/v1"
RUNTIME_BOOTSTRAP_PEPPER_KEY_ID = "local-runtime-bootstrap-pepper"
RUNTIME_RECEIPT_KEY_ID = "local-control-plane-runtime-enrollment"
_TERMINAL_RESPONSE_SEAL_KEY = "_terminal_response_seal"
_TERMINAL_RESPONSE_SEAL_SCHEMA = "runtime-terminal-response-seal/v1"
_GENESIS_AUDIT_HASH = "0" * 64
_LOCAL_RUNTIME_SIGNER_SEED = bytes.fromhex(
    "7ddc4e2c193798075cf583755b3c8718456644759192550927cc2c8fc7067960"
)
_LOCAL_RUNTIME_BOOTSTRAP_PEPPER = hashlib.sha256(
    b"acgs-control-plane-local-runtime-bootstrap-pepper"
).digest()
_TX_ABORT_EXCEPTIONS = (
    SQLAlchemyError,
    ReceiptValidationError,
    TrustConfigurationError,
    ManagedTrustError,
)


@dataclass
class RuntimeEnrollmentHttpError(RuntimeError):
    status_code: int
    code: str
    status: str
    detail: str
    receipt_id: str | None = None
    decision: str | None = None


class RuntimeBootstrapPepper(Protocol):
    key_id: str

    def digest(self, token: str) -> str: ...


@dataclass(frozen=True)
class HmacRuntimeBootstrapPepper:
    key_id: str
    key: bytes

    def __post_init__(self) -> None:
        if len(self.key) < 32:
            raise ValueError("runtime bootstrap pepper must be at least 256 bits")
        if not self.key_id:
            raise ValueError("runtime bootstrap pepper key id is required")

    def digest(self, token: str) -> str:
        return hmac.new(
            self.key,
            token.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()


def local_runtime_enrollment_issuer() -> InProcessPlatformIssuer:
    """Explicit local/test issuer; production must inject custody."""

    return InProcessPlatformIssuer(
        Ed25519Signer.from_private_bytes(_LOCAL_RUNTIME_SIGNER_SEED, key_id=RUNTIME_RECEIPT_KEY_ID),
        allowed_purposes=frozenset({DECISION_RECEIPT_PURPOSE}),
    )


def local_runtime_enrollment_receipt_sealer() -> AesGcmReceiptArtifactSealer:
    """Explicit local/test sealer; production must inject KMS-backed custody."""

    return AesGcmReceiptArtifactSealer(
        key_id="local-control-plane-runtime-enrollment-sealer",
        key=hashlib.sha256(b"acgs-control-plane-local-runtime-enrollment-sealer").digest(),
    )


def local_runtime_bootstrap_pepper() -> HmacRuntimeBootstrapPepper:
    """Explicit local/test bootstrap token pepper."""

    return HmacRuntimeBootstrapPepper(
        key_id=RUNTIME_BOOTSTRAP_PEPPER_KEY_ID,
        key=_LOCAL_RUNTIME_BOOTSTRAP_PEPPER,
    )


def local_runtime_descriptor_signer() -> InMemoryEd25519WorkloadKeyProvider:
    """Explicit local/test runtime descriptor signer."""

    return InMemoryEd25519WorkloadKeyProvider(key_id="local-runtime-descriptor")


@dataclass(frozen=True)
class RuntimeEnrollmentProviders:
    issuer: ManagedPlatformIssuer
    receipt_sealer: AesGcmReceiptArtifactSealer
    bootstrap_pepper: RuntimeBootstrapPepper
    descriptor_signer: InMemoryEd25519WorkloadKeyProvider


class RuntimeEnrollmentService:
    __slots__ = ("_providers", "_session_factory")

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        issuer: ManagedPlatformIssuer,
        receipt_sealer: AesGcmReceiptArtifactSealer,
        bootstrap_pepper: RuntimeBootstrapPepper,
        descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
    ) -> None:
        self._session_factory = session_factory
        self._providers = RuntimeEnrollmentProviders(
            issuer=issuer,
            receipt_sealer=receipt_sealer,
            bootstrap_pepper=bootstrap_pepper,
            descriptor_signer=descriptor_signer,
        )

    @property
    def issuer(self) -> ManagedPlatformIssuer:
        return self._providers.issuer

    def issue_bootstrap(
        self,
        *,
        org_id: str,
        project_id: str,
        environment_id: str,
        principal: Principal,
        body: RuntimeEnrollmentBootstrapCreateRequest,
    ) -> RuntimeEnrollmentBootstrapCreateResponse:
        ttl_seconds = min(body.ttl_seconds, RUNTIME_BOOTSTRAP_MAX_TTL_SECONDS)
        token_locator = secrets.token_urlsafe(16)
        token_secret = secrets.token_urlsafe(43)
        token = f"acgs_gbt_{token_locator}.{token_secret}"
        server_challenge = f"challenge-{new_id()}-{secrets.token_hex(24)}"
        runtime_identity_id = f"runtime-{new_id()}"
        with self._session_factory() as session:
            project, environment = _resolve_scope(
                session,
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
            )
            policy, policy_bundle_id, policy_hash, _policy_version, policy_generation = (
                _active_policy_context(
                    session,
                    org_id=org_id,
                    project_id=project.id,
                    environment_id=environment.id,
                )
            )
            args = {
                "ttl_seconds": ttl_seconds,
                "runtime_identity_id": runtime_identity_id,
                "audience": RUNTIME_ENROLLMENT_AUTHORITY,
                "workload_key_id": body.workload_key_id,
                "public_key_thumbprint": body.public_key_thumbprint,
            }
            context = _context(
                org_id=org_id,
                project_id=project.id,
                environment_id=environment.id,
                actor=principal.actor_id,
                action=CONTROL_PLANE_RUNTIME_BOOTSTRAP_ISSUE_ACTION,
                policy_bundle_id=policy_bundle_id,
                policy_hash=policy_hash,
                policy_head_generation=policy_generation,
            )
            record = _decision_record(
                policy=policy,
                context=context,
                args=args,
                goal="issue runtime enrollment bootstrap",
            )
            audit_hash = _decision_audit_hash(record)
            context = replace(context, expected_audit_hash=audit_hash)
            receipt = self._issue_receipt(
                session=session,
                context=context,
                record=record,
                audit_hash=audit_hash,
                request_id=new_id(),
            )

        if record.decision is not Decision.ALLOW:
            raise self._record_non_executable(context=context, receipt=receipt, args=args)

        holder: dict[str, RuntimeEnrollmentBootstrapCreateResponse] = {}

        def before_execute(tx_session: Session) -> None:
            tx_session.get(Organization, org_id, with_for_update=True)
            _resolve_scope(
                tx_session,
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                lock=True,
            )
            _lock_policy_head(tx_session, context=context)

        def operation_effect(session: Session, _args: dict[str, Any]) -> dict[str, Any]:
            issued_at = utcnow()
            expires_at = issued_at + timedelta(seconds=ttl_seconds)
            if expires_at <= issued_at:
                raise ReceiptValidationError("runtime enrollment bootstrap expiry is not fresh")
            expired_bootstraps = session.scalars(
                sa.select(RuntimeEnrollmentBootstrap)
                .where(
                    RuntimeEnrollmentBootstrap.org_id == org_id,
                    RuntimeEnrollmentBootstrap.project_id == project_id,
                    RuntimeEnrollmentBootstrap.environment_id == environment_id,
                    RuntimeEnrollmentBootstrap.status == "active",
                    RuntimeEnrollmentBootstrap.expires_at <= issued_at,
                )
                .with_for_update()
            )
            for expired in expired_bootstraps:
                expired.status = "expired"
            gate = _ensure_gate(
                session,
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
            )
            bootstrap = RuntimeEnrollmentBootstrap(
                id=new_id(),
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                gate_id=gate.id,
                bootstrap_digest=self._providers.bootstrap_pepper.digest(token),
                bootstrap_locator=token_locator,
                pepper_key_id=self._providers.bootstrap_pepper.key_id,
                server_challenge=server_challenge,
                runtime_identity_id=runtime_identity_id,
                audience=RUNTIME_ENROLLMENT_AUTHORITY,
                workload_key_id=body.workload_key_id,
                public_key_thumbprint=body.public_key_thumbprint,
                status="active",
                created_by_actor=principal.actor_id,
                policy_head_generation=policy_generation,
                created_at=issued_at,
                expires_at=expires_at,
            )
            session.add(bootstrap)
            session.flush()
            return {
                "bootstrap_id": bootstrap.id,
                "gate_id": bootstrap.gate_id,
                "expires_at": _runtime_timestamp(expires_at),
            }

        def after_success(
            _session: Session,
            receipt_row: ManagedDecisionReceipt,
            _event: ManagedGovernanceEvent,
            _outbox: ManagedOutboxMessage,
            result: ManagedMutationResult,
        ) -> None:
            holder["response"] = RuntimeEnrollmentBootstrapCreateResponse(
                bootstrap_id=str(result.result["bootstrap_id"]),
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                gate_id=str(result.result["gate_id"]),
                runtime_identity_id=runtime_identity_id,
                audience=RUNTIME_ENROLLMENT_AUTHORITY,
                workload_key_id=body.workload_key_id,
                public_key_thumbprint=body.public_key_thumbprint,
                bootstrap_token=token,
                server_challenge=server_challenge,
                expires_at=_parse_runtime_timestamp(str(result.result["expires_at"])),
                receipt_id=receipt_row.receipt_id,
            )

        try:
            ManagedMutationUnitOfWork(
                self._session_factory,
                receipt_sealer=self._providers.receipt_sealer,
            ).execute(
                context=context,
                receipt=receipt,
                args=args,
                before_execute=before_execute,
                operation_effect=operation_effect,
                after_success=after_success,
            )
        except IntegrityError as exc:
            raise RuntimeEnrollmentHttpError(
                409,
                "BOOTSTRAP_TOKEN_NOT_REPLAYABLE",
                "conflict",
                "an active runtime enrollment bootstrap already exists for this environment; "
                "bootstrap tokens are not replayable",
            ) from exc
        except _TX_ABORT_EXCEPTIONS as exc:
            raise RuntimeEnrollmentHttpError(
                503,
                "TX_ABORTED",
                "tx_aborted",
                "runtime enrollment bootstrap transaction aborted",
            ) from exc
        return holder["response"]

    def enroll(
        self,
        *,
        body: RuntimeEnrollmentRequest,
        authorization: str | None,
        idempotency_key: str | None,
        pop_signature: str | None,
        pop_key_id: str | None,
        raw_body: bytes,
        bootstrap_id_header: str | None = None,
    ) -> RuntimeEnrollmentResponse:
        bootstrap_token = _bootstrap_token_from_authorization(authorization)
        if idempotency_key is None:
            raise RuntimeEnrollmentHttpError(
                400,
                "IDEMPOTENCY_KEY_REQUIRED",
                "bad_request",
                "runtime enrollment requires an Idempotency-Key header",
            )
        if pop_signature is None:
            raise RuntimeEnrollmentHttpError(
                401,
                "POP_SIGNATURE_REQUIRED",
                "unauthorized",
                "runtime enrollment proof-of-possession signature is required",
            )
        if pop_key_id is None:
            raise RuntimeEnrollmentHttpError(
                401,
                "POP_KEY_ID_REQUIRED",
                "unauthorized",
                "runtime enrollment proof-of-possession key id is required",
            )
        if bootstrap_id_header is not None and bootstrap_id_header != body.bootstrap_id:
            raise RuntimeEnrollmentHttpError(
                400,
                "BOOTSTRAP_ID_MISMATCH",
                "bad_request",
                "runtime enrollment bootstrap header does not match request body",
            )
        expected_idempotency_digest = sha256_text(idempotency_key)
        if body.idempotency_key_digest != expected_idempotency_digest:
            raise RuntimeEnrollmentHttpError(
                400,
                "IDEMPOTENCY_DIGEST_MISMATCH",
                "bad_request",
                "runtime enrollment idempotency digest does not match header",
            )
        if body.audience != RUNTIME_ENROLLMENT_AUTHORITY:
            raise RuntimeEnrollmentHttpError(
                401,
                "AUDIENCE_MISMATCH",
                "unauthorized",
                "runtime enrollment audience is not accepted by this server",
            )
        body_bytes = raw_body
        request_hash = sha256_json(
            {
                "schema": "runtime-enrollment-request/v1",
                "bootstrap_token_digest": self._providers.bootstrap_pepper.digest(bootstrap_token),
                "body_digest": hashlib.sha256(body_bytes).hexdigest(),
                "pop_key_id": pop_key_id,
                "pop_signature": pop_signature,
            }
        )
        with self._session_factory() as session:
            bootstrap = _lookup_bootstrap_by_digest(
                session,
                digest=self._providers.bootstrap_pepper.digest(bootstrap_token),
                lock=False,
            )
            if bootstrap is None:
                raise RuntimeEnrollmentHttpError(
                    401,
                    "BOOTSTRAP_NOT_AUTHORIZED",
                    "unauthorized",
                    "runtime enrollment bootstrap is not valid",
                )
            if bootstrap.server_challenge != body.server_challenge:
                raise RuntimeEnrollmentHttpError(
                    401,
                    "BOOTSTRAP_CHALLENGE_MISMATCH",
                    "unauthorized",
                    "runtime enrollment challenge does not match bootstrap",
                )
            if (
                bootstrap.runtime_identity_id != body.runtime_identity_id
                or bootstrap.audience != RUNTIME_ENROLLMENT_AUTHORITY
                or bootstrap.audience != body.audience
                or bootstrap.workload_key_id != pop_key_id
                or bootstrap.public_key_thumbprint != body.public_key_thumbprint
            ):
                raise RuntimeEnrollmentHttpError(
                    401,
                    "BOOTSTRAP_BINDING_MISMATCH",
                    "unauthorized",
                    "runtime enrollment request does not match bootstrap binding",
                )
            if (
                bootstrap.id != body.bootstrap_id
                or bootstrap.org_id != body.org_id
                or bootstrap.project_id != body.project_id
                or bootstrap.environment_id != body.environment
            ):
                raise RuntimeEnrollmentHttpError(
                    401,
                    "BOOTSTRAP_SCOPE_MISMATCH",
                    "unauthorized",
                    "runtime enrollment bootstrap does not match request scope",
                )
            public_key = _runtime_public_key_bytes(body.public_key)
            thumbprint = gove_public_key_thumbprint(public_key)
            if thumbprint != body.public_key_thumbprint:
                raise RuntimeEnrollmentHttpError(
                    400,
                    "PUBLIC_KEY_THUMBPRINT_MISMATCH",
                    "bad_request",
                    "runtime public key thumbprint does not match request public key",
                )
            enroll_args = {
                "bootstrap_id": bootstrap.id,
                "runtime_identity_id": body.runtime_identity_id,
                "public_key_thumbprint": thumbprint,
                "workload_key_id": pop_key_id,
            }
            try:
                verify_enrollment_pop(
                    public_key=public_key,
                    signature=pop_signature,
                    method="POST",
                    path="/v1/runtime-enrollments",
                    audience=body.audience,
                    bootstrap_id=body.bootstrap_id,
                    runtime_identity_id=body.runtime_identity_id,
                    gate_id=body.gate_id,
                    org_id=body.org_id,
                    project_id=body.project_id,
                    environment=body.environment,
                    public_key_thumbprint=body.public_key_thumbprint,
                    idempotency_key=idempotency_key,
                    body=body_bytes,
                    server_challenge=body.server_challenge,
                    client_nonce=body.client_nonce,
                    timestamp=body.timestamp,
                )
            except RuntimeIdentityError as exc:
                raise RuntimeEnrollmentHttpError(
                    401,
                    "POP_SIGNATURE_INVALID",
                    "unauthorized",
                    "runtime enrollment proof-of-possession failed",
                ) from exc
            existing = _lookup_enrollment_idempotency(
                session,
                key_hash=_idempotency_key_hash(idempotency_key),
                org_id=bootstrap.org_id,
                project_id=bootstrap.project_id,
                environment_id=bootstrap.environment_id,
                identity_id=bootstrap.runtime_identity_id,
                lock=False,
            )
            if existing is not None:
                if existing.request_hash != request_hash:
                    raise RuntimeEnrollmentHttpError(
                        409,
                        "IDEMPOTENCY_CONFLICT",
                        "conflict",
                        "idempotency key was already used for a different enrollment",
                    )
                return _response_from_payload_verified(
                    session,
                    existing.response,
                    org_id=existing.org_id,
                    project_id=existing.project_id,
                    environment_id=existing.environment_id,
                    identity_id=existing.identity_id,
                    receipt_id=existing.receipt_id,
                    expected_action=CONTROL_PLANE_RUNTIME_IDENTITY_ENROLL_ACTION,
                    operation="enroll",
                    expected_actor=f"runtime:{existing.identity_id}",
                    expected_args=enroll_args,
                    request_hash=existing.request_hash,
                    idempotency_key_hash=existing.idempotency_key_hash,
                    receipt_sealer=self._providers.receipt_sealer,
                    descriptor_signer=self._providers.descriptor_signer,
                )
            refusal = _lookup_runtime_operation_idempotency(
                session,
                org_id=bootstrap.org_id,
                project_id=bootstrap.project_id,
                environment_id=bootstrap.environment_id,
                identity_id=bootstrap.runtime_identity_id,
                operation="enroll",
                idempotency_key_hash=_idempotency_key_hash(idempotency_key),
                lock=False,
            )
            if refusal is not None:
                if refusal.request_hash != request_hash:
                    raise RuntimeEnrollmentHttpError(
                        409,
                        "IDEMPOTENCY_CONFLICT",
                        "conflict",
                        "idempotency key was already used for a different runtime operation",
                    )
                return _replay_runtime_operation(
                    refusal,
                    session=session,
                    expected_action=CONTROL_PLANE_RUNTIME_IDENTITY_ENROLL_ACTION,
                    expected_actor=f"runtime:{refusal.identity_id}",
                    expected_args=enroll_args,
                    receipt_sealer=self._providers.receipt_sealer,
                    descriptor_signer=self._providers.descriptor_signer,
                )
            now = utcnow()
            if now >= _to_utc(bootstrap.expires_at):
                raise RuntimeEnrollmentHttpError(
                    401,
                    "BOOTSTRAP_EXPIRED",
                    "unauthorized",
                    "runtime enrollment bootstrap expired",
                )
            timestamp_skew = abs((_parse_runtime_timestamp(body.timestamp) - now).total_seconds())
            if timestamp_skew > RUNTIME_SIGNED_REQUEST_SKEW_SECONDS:
                raise RuntimeEnrollmentHttpError(
                    401,
                    "STALE_TIMESTAMP",
                    "unauthorized",
                    "runtime enrollment timestamp is outside the allowed skew",
                )
            gate = session.get(RuntimeIdentityGate, bootstrap.gate_id)
            if gate is None or gate.status != "active" or gate.id != body.gate_id:
                raise RuntimeEnrollmentHttpError(
                    401,
                    "GATE_NOT_ACTIVE",
                    "unauthorized",
                    "runtime enrollment gate is not active",
                )
            policy, policy_bundle_id, policy_hash, _policy_version, _policy_generation = (
                _active_policy_context(
                    session,
                    org_id=bootstrap.org_id,
                    project_id=bootstrap.project_id,
                    environment_id=bootstrap.environment_id,
                )
            )
            args = enroll_args
            context = _context(
                org_id=bootstrap.org_id,
                project_id=bootstrap.project_id,
                environment_id=bootstrap.environment_id,
                actor=f"runtime:{body.runtime_identity_id}",
                action=CONTROL_PLANE_RUNTIME_IDENTITY_ENROLL_ACTION,
                policy_bundle_id=policy_bundle_id,
                policy_hash=policy_hash,
                policy_head_generation=_policy_generation,
            )
            record = _decision_record(
                policy=policy,
                context=context,
                args=args,
                goal="enroll hosted runtime identity",
            )
            audit_hash = _decision_audit_hash(record)
            context = replace(context, expected_audit_hash=audit_hash)
            receipt = self._issue_receipt(
                session=session,
                context=context,
                record=record,
                audit_hash=audit_hash,
                request_id=f"runtime-enroll:{_idempotency_key_hash(idempotency_key)}",
            )

        if record.decision is not Decision.ALLOW:
            raise self._record_non_executable(
                context=context,
                receipt=receipt,
                args=args,
                operation_name="enroll",
                idempotency_key_hash=_idempotency_key_hash(idempotency_key),
                request_hash=request_hash,
                identity_id=body.runtime_identity_id,
            )

        holder: dict[str, RuntimeEnrollmentResponse] = {}

        def before_attempt_reservation(tx_session: Session) -> ManagedMutationReplayResult | None:
            tx_session.get(Organization, context.org_id, with_for_update=True)
            locked = _lookup_bootstrap_by_digest(
                tx_session,
                digest=self._providers.bootstrap_pepper.digest(bootstrap_token),
                lock=True,
            )
            if locked is None or locked.id != bootstrap.id:
                raise ReceiptValidationError("runtime enrollment bootstrap changed")
            if locked.server_challenge != body.server_challenge:
                raise ReceiptValidationError("runtime enrollment bootstrap challenge changed")
            if (
                locked.org_id != body.org_id
                or locked.project_id != body.project_id
                or locked.environment_id != body.environment
                or locked.gate_id != body.gate_id
                or locked.runtime_identity_id != body.runtime_identity_id
                or locked.audience != body.audience
                or locked.workload_key_id != pop_key_id
                or locked.public_key_thumbprint != body.public_key_thumbprint
            ):
                raise ReceiptValidationError("runtime enrollment bootstrap binding changed")
            _lock_policy_head(tx_session, context=context)
            existing = _lookup_enrollment_idempotency(
                tx_session,
                key_hash=_idempotency_key_hash(idempotency_key),
                org_id=context.org_id,
                project_id=context.project_id,
                environment_id=context.environment_id,
                identity_id=body.runtime_identity_id,
                lock=True,
            )
            if existing is not None:
                if existing.request_hash != request_hash:
                    raise RuntimeEnrollmentHttpError(
                        409,
                        "IDEMPOTENCY_CONFLICT",
                        "conflict",
                        "idempotency key was already used for a different enrollment",
                    )
                return ManagedMutationReplayResult(
                    _response_from_payload_verified(
                        tx_session,
                        existing.response,
                        org_id=existing.org_id,
                        project_id=existing.project_id,
                        environment_id=existing.environment_id,
                        identity_id=existing.identity_id,
                        receipt_id=existing.receipt_id,
                        expected_action=CONTROL_PLANE_RUNTIME_IDENTITY_ENROLL_ACTION,
                        operation="enroll",
                        expected_actor=f"runtime:{existing.identity_id}",
                        expected_args=args,
                        request_hash=existing.request_hash,
                        idempotency_key_hash=existing.idempotency_key_hash,
                        receipt_sealer=self._providers.receipt_sealer,
                        descriptor_signer=self._providers.descriptor_signer,
                    )
                )
            if locked.status != "active":
                raise RuntimeEnrollmentHttpError(
                    401,
                    "BOOTSTRAP_NOT_AUTHORIZED",
                    "unauthorized",
                    "runtime enrollment bootstrap is not valid",
                )
            if utcnow() >= _to_utc(locked.expires_at):
                raise RuntimeEnrollmentHttpError(
                    401,
                    "BOOTSTRAP_EXPIRED",
                    "unauthorized",
                    "runtime enrollment bootstrap expired",
                )
            if tx_session.get(RuntimeIdentity, body.runtime_identity_id) is not None:
                raise RuntimeEnrollmentHttpError(
                    409,
                    "IDENTITY_CONFLICT",
                    "conflict",
                    "runtime identity already exists",
                )
            if (
                tx_session.scalars(
                    sa.select(RuntimeIdentity)
                    .where(
                        RuntimeIdentity.org_id == context.org_id,
                        RuntimeIdentity.project_id == context.project_id,
                        RuntimeIdentity.environment_id == context.environment_id,
                        RuntimeIdentity.public_key_thumbprint == thumbprint,
                    )
                    .with_for_update()
                ).one_or_none()
                is not None
            ):
                raise RuntimeEnrollmentHttpError(
                    409,
                    "PUBLIC_KEY_CONFLICT",
                    "conflict",
                    "runtime public key is already enrolled in this scope",
                )
            return None

        def before_execute(_tx_session: Session) -> None:
            return None

        def operation_effect(session: Session, _args: dict[str, Any]) -> dict[str, Any]:
            gate = session.get(RuntimeIdentityGate, bootstrap.gate_id, with_for_update=True)
            if gate is None or gate.status != "active":
                raise ReceiptValidationError("runtime identity gate is not active")
            identity = RuntimeIdentity(
                id=body.runtime_identity_id,
                org_id=context.org_id,
                project_id=context.project_id,
                environment_id=context.environment_id,
                gate_id=gate.id,
                name=body.runtime_identity_id,
                actor=context.actor,
                workload_key_id=pop_key_id,
                public_key=body.public_key,
                public_key_thumbprint=thumbprint,
                descriptor={},
                status="active",
                current_generation=1,
            )
            now = utcnow()
            expires_at = now + timedelta(seconds=RUNTIME_CREDENTIAL_TTL_SECONDS)
            credential = RuntimeCredentialGeneration(
                id=new_id(),
                org_id=context.org_id,
                project_id=context.project_id,
                environment_id=context.environment_id,
                identity_id=identity.id,
                generation=1,
                workload_key_id=pop_key_id,
                public_key_thumbprint=thumbprint,
                not_before=now,
                not_after=expires_at,
                status="active",
                descriptor={},
            )
            descriptor = _descriptor(
                identity=identity,
                credential=credential,
                public_key=public_key,
                gate_id=gate.id,
                audience=body.audience,
                issued_at=now,
                expires_at=expires_at,
                signer=self._providers.descriptor_signer,
            )
            identity.descriptor = descriptor
            credential.descriptor = descriptor
            boot = session.get(RuntimeEnrollmentBootstrap, bootstrap.id, with_for_update=True)
            if boot is None or boot.status != "active":
                raise ReceiptValidationError("runtime enrollment bootstrap already consumed")
            boot.status = "consumed"
            boot.consumed_at = now
            boot.consumed_by_identity_id = identity.id
            session.add(identity)
            session.add(credential)
            session.flush()
            return {"identity_id": identity.id, "generation": 1}

        def after_success(
            session: Session,
            receipt_row: ManagedDecisionReceipt,
            _event: ManagedGovernanceEvent,
            _outbox: ManagedOutboxMessage,
            result: ManagedMutationResult,
        ) -> None:
            identity = session.get(RuntimeIdentity, str(result.result["identity_id"]))
            if identity is None:
                raise RuntimeError("runtime enrollment committed without identity")
            payload = _response_payload(identity=identity, receipt_id=receipt_row.receipt_id)
            sealed_payload = _sealed_terminal_response_payload(
                payload,
                receipt_sealer=self._providers.receipt_sealer,
                org_id=identity.org_id,
                project_id=identity.project_id,
                environment_id=identity.environment_id,
                identity_id=identity.id,
                action=CONTROL_PLANE_RUNTIME_IDENTITY_ENROLL_ACTION,
                operation="enroll",
                request_hash=request_hash,
                idempotency_key_hash=_idempotency_key_hash(idempotency_key),
                receipt_id=receipt_row.receipt_id,
                receipt_hash=receipt_row.receipt_hash,
            )
            session.add(
                RuntimeEnrollmentIdempotency(
                    id=new_id(),
                    idempotency_key_hash=_idempotency_key_hash(idempotency_key),
                    request_hash=request_hash,
                    org_id=identity.org_id,
                    project_id=identity.project_id,
                    environment_id=identity.environment_id,
                    identity_id=identity.id,
                    receipt_id=receipt_row.receipt_id,
                    response=sealed_payload,
                )
            )
            holder["response"] = _response_from_payload(payload)

        try:
            mutation_outcome = ManagedMutationUnitOfWork(
                self._session_factory,
                receipt_sealer=self._providers.receipt_sealer,
            ).execute(
                context=context,
                receipt=receipt,
                args=args,
                before_attempt_reservation=before_attempt_reservation,
                before_execute=before_execute,
                operation_effect=operation_effect,
                after_success=after_success,
            )
            if isinstance(mutation_outcome, ManagedMutationReplayResult):
                return cast(RuntimeEnrollmentResponse, mutation_outcome.result)
        except IntegrityError as exc:
            existing = _lookup_enrollment_idempotency_new_session(
                self._session_factory,
                key_hash=_idempotency_key_hash(idempotency_key),
                org_id=context.org_id,
                project_id=context.project_id,
                environment_id=context.environment_id,
                identity_id=body.runtime_identity_id,
            )
            if existing is not None and existing.request_hash == request_hash:
                with self._session_factory() as replay_session:
                    return _response_from_payload_verified(
                        replay_session,
                        existing.response,
                        org_id=existing.org_id,
                        project_id=existing.project_id,
                        environment_id=existing.environment_id,
                        identity_id=existing.identity_id,
                        receipt_id=existing.receipt_id,
                        expected_action=CONTROL_PLANE_RUNTIME_IDENTITY_ENROLL_ACTION,
                        operation="enroll",
                        expected_actor=f"runtime:{existing.identity_id}",
                        expected_args=args,
                        request_hash=existing.request_hash,
                        idempotency_key_hash=existing.idempotency_key_hash,
                        receipt_sealer=self._providers.receipt_sealer,
                        descriptor_signer=self._providers.descriptor_signer,
                    )
            raise RuntimeEnrollmentHttpError(
                409,
                "ENROLLMENT_CONFLICT",
                "conflict",
                "runtime enrollment request conflicts with existing state",
            ) from exc
        except _TX_ABORT_EXCEPTIONS as exc:
            existing = _lookup_enrollment_idempotency_new_session(
                self._session_factory,
                key_hash=_idempotency_key_hash(idempotency_key),
                org_id=context.org_id,
                project_id=context.project_id,
                environment_id=context.environment_id,
                identity_id=body.runtime_identity_id,
            )
            if existing is not None and existing.request_hash == request_hash:
                with self._session_factory() as replay_session:
                    return _response_from_payload_verified(
                        replay_session,
                        existing.response,
                        org_id=existing.org_id,
                        project_id=existing.project_id,
                        environment_id=existing.environment_id,
                        identity_id=existing.identity_id,
                        receipt_id=existing.receipt_id,
                        expected_action=CONTROL_PLANE_RUNTIME_IDENTITY_ENROLL_ACTION,
                        operation="enroll",
                        expected_actor=f"runtime:{existing.identity_id}",
                        expected_args=args,
                        request_hash=existing.request_hash,
                        idempotency_key_hash=existing.idempotency_key_hash,
                        receipt_sealer=self._providers.receipt_sealer,
                        descriptor_signer=self._providers.descriptor_signer,
                    )
            raise RuntimeEnrollmentHttpError(
                503,
                "TX_ABORTED",
                "tx_aborted",
                "runtime enrollment transaction aborted",
            ) from exc
        return holder["response"]

    def renew(
        self,
        *,
        identity_id: str,
        body: RuntimeSignedRequest,
        raw_body: bytes,
        query: str,
        body_sha256: str | None,
        idempotency_key: str,
    ) -> RuntimeEnrollmentResponse:
        if body.idempotency_key_digest != sha256_text(idempotency_key):
            raise RuntimeEnrollmentHttpError(
                400,
                "IDEMPOTENCY_DIGEST_MISMATCH",
                "bad_request",
                "runtime signed request idempotency digest does not match header",
            )
        if query or raw_body != b"{}":
            raise RuntimeEnrollmentHttpError(
                400,
                "RUNTIME_RENEWAL_PAYLOAD_NOT_CANONICAL",
                "bad_request",
                "runtime renewal requires an empty query and canonical empty JSON body",
            )
        replay_hash = _runtime_request_replay_hash(
            identity_id=identity_id,
            body=body,
            raw_body=raw_body,
            query=query,
            idempotency_key=idempotency_key,
        )
        authenticated = self._authenticate_signed_runtime_request(
            identity_id=identity_id,
            body=body,
            raw_body=raw_body,
            query=query,
            body_sha256=body_sha256,
            idempotency_key=idempotency_key,
            replay_hash=replay_hash,
            purpose="renew",
        )
        if isinstance(authenticated, RuntimeEnrollmentResponse):
            return authenticated
        identity, credential = authenticated
        args = {
            "identity_id": identity.id,
            "nonce": body.nonce,
            "credential_id": credential.id,
            "credential_generation": credential.generation,
            "generation": credential.generation + 1,
        }
        idempotency_key_hash = _idempotency_key_hash(idempotency_key)
        return self._governed_identity_update(
            identity=identity,
            action=CONTROL_PLANE_RUNTIME_IDENTITY_RENEW_ACTION,
            args=args,
            goal="renew hosted runtime credential",
            operation_name="renew",
            idempotency_key_hash=idempotency_key_hash,
            request_hash=replay_hash,
            operation=lambda session: _burn_nonce_then_renew(
                session,
                identity=identity,
                body=body,
                expected_credential=credential,
                idempotency_key_hash=idempotency_key_hash,
                request_hash=replay_hash,
                descriptor_signer=self._providers.descriptor_signer,
            ),
        )

    def revoke(
        self,
        *,
        org_id: str,
        project_id: str,
        environment_id: str,
        identity_id: str,
        principal: Principal,
        body: RuntimeIdentityRevokeRequest,
        idempotency_key: str,
    ) -> RuntimeEnrollmentResponse:
        idempotency_key_hash = _idempotency_key_hash(idempotency_key)
        with self._session_factory() as session:
            identity = _scoped_identity(
                session,
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                identity_id=identity_id,
            )
            if identity is None:
                raise RuntimeEnrollmentHttpError(
                    404,
                    "IDENTITY_NOT_FOUND",
                    "not_found",
                    "runtime identity was not found",
                )
            request_hash = _runtime_operation_request_hash(
                operation="revoke",
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                identity_id=identity_id,
                actor=principal.actor_id,
                expected_credential_generation=body.expected_credential_generation,
            )
            args = {
                "identity_id": identity_id,
                "expected_credential_generation": body.expected_credential_generation,
            }
            existing = _lookup_runtime_operation_idempotency(
                session,
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                identity_id=identity_id,
                operation="revoke",
                idempotency_key_hash=idempotency_key_hash,
                lock=False,
            )
            if existing is not None:
                if existing.request_hash != request_hash:
                    raise RuntimeEnrollmentHttpError(
                        409,
                        "IDEMPOTENCY_CONFLICT",
                        "conflict",
                        "idempotency key was already used for a different runtime operation",
                    )
                return _replay_runtime_operation(
                    existing,
                    session=session,
                    expected_action=CONTROL_PLANE_RUNTIME_IDENTITY_REVOKE_ACTION,
                    expected_actor=principal.actor_id,
                    expected_args=args,
                    receipt_sealer=self._providers.receipt_sealer,
                    descriptor_signer=self._providers.descriptor_signer,
                )
            detached = _detach_identity(identity)
        return self._governed_identity_update(
            identity=detached,
            action=CONTROL_PLANE_RUNTIME_IDENTITY_REVOKE_ACTION,
            args=args,
            goal="revoke hosted runtime identity",
            actor=principal.actor_id,
            operation_name="revoke",
            idempotency_key_hash=idempotency_key_hash,
            request_hash=request_hash,
            operation=lambda session: _revoke_identity(
                session,
                org_id=detached.org_id,
                project_id=detached.project_id,
                environment_id=detached.environment_id,
                identity_id=identity_id,
                expected_credential_generation=body.expected_credential_generation,
            ),
        )

    def _authenticate_signed_runtime_request(
        self,
        *,
        identity_id: str,
        body: RuntimeSignedRequest,
        raw_body: bytes,
        query: str,
        body_sha256: str | None,
        idempotency_key: str,
        replay_hash: str,
        purpose: str,
    ) -> tuple[RuntimeIdentity, RuntimeCredentialGeneration] | RuntimeEnrollmentResponse:
        now = utcnow()
        if body_sha256 is None or body_sha256 != sha256_bytes(raw_body):
            raise RuntimeEnrollmentHttpError(
                401,
                "BODY_DIGEST_MISMATCH",
                "unauthorized",
                "runtime signed request body digest is invalid",
            )
        with self._session_factory() as session:
            identity = session.get(RuntimeIdentity, identity_id)
            if identity is None:
                raise RuntimeEnrollmentHttpError(
                    401,
                    "IDENTITY_NOT_ACTIVE",
                    "unauthorized",
                    "runtime identity is not active",
                )
            if body.key_id != identity.workload_key_id:
                raise RuntimeEnrollmentHttpError(
                    401,
                    "RUNTIME_KEY_ID_MISMATCH",
                    "unauthorized",
                    "runtime key id does not match active identity",
                )
            if body.audience != RUNTIME_ENROLLMENT_AUTHORITY:
                raise RuntimeEnrollmentHttpError(
                    401,
                    "AUDIENCE_MISMATCH",
                    "unauthorized",
                    "runtime signed request audience is not accepted by this server",
                )
            path = f"/v1/runtime-identities/{identity.id}/renew"
            try:
                verify_signed_runtime_request(
                    public_key=_runtime_public_key_bytes(identity.public_key),
                    signature=body.signature,
                    method="POST",
                    path=path,
                    query=query,
                    body=raw_body,
                    timestamp=body.timestamp,
                    nonce=body.nonce,
                    key_id=body.key_id,
                    identity_id=identity.id,
                    credential_id=body.credential_id,
                    credential_generation=body.credential_generation,
                    idempotency_key=idempotency_key,
                    audience=body.audience,
                )
            except RuntimeIdentityError as exc:
                raise RuntimeEnrollmentHttpError(
                    401,
                    "RUNTIME_SIGNATURE_INVALID",
                    "unauthorized",
                    "runtime request signature is invalid",
                ) from exc
            existing_nonce = session.scalars(
                sa.select(RuntimeRequestNonce).where(
                    RuntimeRequestNonce.org_id == identity.org_id,
                    RuntimeRequestNonce.project_id == identity.project_id,
                    RuntimeRequestNonce.environment_id == identity.environment_id,
                    RuntimeRequestNonce.identity_id == identity.id,
                    RuntimeRequestNonce.nonce == body.nonce,
                )
            ).one_or_none()
            if existing_nonce is not None:
                if (
                    existing_nonce.idempotency_key_hash == _idempotency_key_hash(idempotency_key)
                    and existing_nonce.request_hash == replay_hash
                    and existing_nonce.purpose == purpose
                    and existing_nonce.response is not None
                ):
                    return _response_from_payload_verified(
                        session,
                        existing_nonce.response,
                        org_id=identity.org_id,
                        project_id=identity.project_id,
                        environment_id=identity.environment_id,
                        identity_id=identity.id,
                        receipt_id=existing_nonce.receipt_id,
                        expected_action=CONTROL_PLANE_RUNTIME_IDENTITY_RENEW_ACTION,
                        operation="renew",
                        expected_actor=identity.actor,
                        expected_args={
                            "identity_id": identity.id,
                            "nonce": body.nonce,
                            "credential_id": body.credential_id,
                            "credential_generation": body.credential_generation,
                            "generation": body.credential_generation + 1,
                        },
                        request_hash=existing_nonce.request_hash,
                        idempotency_key_hash=existing_nonce.idempotency_key_hash,
                        receipt_sealer=self._providers.receipt_sealer,
                        descriptor_signer=self._providers.descriptor_signer,
                    )
                raise RuntimeEnrollmentHttpError(
                    409,
                    "NONCE_REPLAYED",
                    "conflict",
                    "runtime signed request nonce was already used",
                )
            timestamp_skew = abs((_parse_runtime_timestamp(body.timestamp) - now).total_seconds())
            if timestamp_skew > RUNTIME_SIGNED_REQUEST_SKEW_SECONDS:
                raise RuntimeEnrollmentHttpError(
                    401,
                    "STALE_TIMESTAMP",
                    "unauthorized",
                    "runtime signed request timestamp is outside the allowed skew",
                )
            if identity.status != "active":
                raise RuntimeEnrollmentHttpError(
                    401,
                    "IDENTITY_NOT_ACTIVE",
                    "unauthorized",
                    "runtime identity is not active",
                )
            credential = session.scalars(
                sa.select(RuntimeCredentialGeneration).where(
                    RuntimeCredentialGeneration.org_id == identity.org_id,
                    RuntimeCredentialGeneration.project_id == identity.project_id,
                    RuntimeCredentialGeneration.environment_id == identity.environment_id,
                    RuntimeCredentialGeneration.identity_id == identity.id,
                    RuntimeCredentialGeneration.status == "active",
                )
            ).one_or_none()
            if credential is None or now >= _to_utc(credential.not_after):
                raise RuntimeEnrollmentHttpError(
                    401,
                    "CREDENTIAL_NOT_ACTIVE",
                    "unauthorized",
                    "runtime credential is not active",
                )
            if now < _to_utc(credential.not_before):
                raise RuntimeEnrollmentHttpError(
                    401,
                    "CREDENTIAL_NOT_ACTIVE",
                    "unauthorized",
                    "runtime credential is not active yet",
                )
            if body.key_id != credential.workload_key_id:
                raise RuntimeEnrollmentHttpError(
                    401,
                    "RUNTIME_KEY_ID_MISMATCH",
                    "unauthorized",
                    "runtime key id does not match active credential",
                )
            if (
                body.credential_id != credential.id
                or body.credential_generation != credential.generation
            ):
                raise RuntimeEnrollmentHttpError(
                    401,
                    "CREDENTIAL_BINDING_MISMATCH",
                    "unauthorized",
                    "runtime signed request does not match active credential",
                )
            gate = session.scalars(
                sa.select(RuntimeIdentityGate).where(
                    RuntimeIdentityGate.org_id == identity.org_id,
                    RuntimeIdentityGate.project_id == identity.project_id,
                    RuntimeIdentityGate.environment_id == identity.environment_id,
                    RuntimeIdentityGate.id == identity.gate_id,
                    RuntimeIdentityGate.status == "active",
                )
            ).one_or_none()
            if gate is None:
                raise RuntimeEnrollmentHttpError(
                    401,
                    "GATE_NOT_ACTIVE",
                    "unauthorized",
                    "runtime identity gate is not active",
                )
            return _detach_identity(identity), _detach_credential(credential)

    def _governed_identity_update(
        self,
        *,
        identity: RuntimeIdentity,
        action: str,
        args: dict[str, Any],
        goal: str,
        operation: Any,
        operation_name: str,
        idempotency_key_hash: str,
        request_hash: str,
        actor: str | None = None,
    ) -> RuntimeEnrollmentResponse:
        with self._session_factory() as session:
            existing = _lookup_runtime_operation_idempotency(
                session,
                org_id=identity.org_id,
                project_id=identity.project_id,
                environment_id=identity.environment_id,
                identity_id=identity.id,
                operation=operation_name,
                idempotency_key_hash=idempotency_key_hash,
                lock=False,
            )
            if existing is not None:
                if existing.request_hash != request_hash:
                    raise RuntimeEnrollmentHttpError(
                        409,
                        "IDEMPOTENCY_CONFLICT",
                        "conflict",
                        "idempotency key was already used for a different runtime operation",
                    )
                return _replay_runtime_operation(
                    existing,
                    session=session,
                    expected_action=action,
                    expected_actor=actor or identity.actor,
                    expected_args=args,
                    receipt_sealer=self._providers.receipt_sealer,
                    descriptor_signer=self._providers.descriptor_signer,
                )
            policy, policy_bundle_id, policy_hash, _policy_version, policy_generation = (
                _active_policy_context(
                    session,
                    org_id=identity.org_id,
                    project_id=identity.project_id,
                    environment_id=identity.environment_id,
                )
            )
            context = _context(
                org_id=identity.org_id,
                project_id=identity.project_id,
                environment_id=identity.environment_id,
                actor=actor or identity.actor,
                action=action,
                policy_bundle_id=policy_bundle_id,
                policy_hash=policy_hash,
                policy_head_generation=policy_generation,
            )
            record = _decision_record(policy=policy, context=context, args=args, goal=goal)
            audit_hash = _decision_audit_hash(record)
            context = replace(context, expected_audit_hash=audit_hash)
            receipt = self._issue_receipt(
                session=session,
                context=context,
                record=record,
                audit_hash=audit_hash,
                request_id=f"runtime-operation:{operation_name}:{idempotency_key_hash}",
            )
        if record.decision is not Decision.ALLOW:
            raise self._record_non_executable(
                context=context,
                receipt=receipt,
                args=args,
                operation_name=operation_name,
                idempotency_key_hash=idempotency_key_hash,
                request_hash=request_hash,
                identity_id=identity.id,
            )

        holder: dict[str, RuntimeEnrollmentResponse] = {}

        def before_attempt_reservation(tx_session: Session) -> ManagedMutationReplayResult | None:
            tx_session.get(Organization, context.org_id, with_for_update=True)
            locked_identity = tx_session.scalars(
                sa.select(RuntimeIdentity)
                .where(
                    RuntimeIdentity.org_id == identity.org_id,
                    RuntimeIdentity.project_id == identity.project_id,
                    RuntimeIdentity.environment_id == identity.environment_id,
                    RuntimeIdentity.id == identity.id,
                )
                .with_for_update()
            ).one_or_none()
            if locked_identity is None:
                raise ReceiptValidationError("runtime identity changed before update")
            _lock_policy_head(tx_session, context=context)
            existing = _lookup_runtime_operation_idempotency(
                tx_session,
                org_id=identity.org_id,
                project_id=identity.project_id,
                environment_id=identity.environment_id,
                identity_id=identity.id,
                operation=operation_name,
                idempotency_key_hash=idempotency_key_hash,
                lock=True,
            )
            if existing is not None:
                if existing.request_hash != request_hash:
                    raise RuntimeEnrollmentHttpError(
                        409,
                        "IDEMPOTENCY_CONFLICT",
                        "conflict",
                        "idempotency key was already used for a different runtime operation",
                    )
                return ManagedMutationReplayResult(
                    _replay_runtime_operation(
                        existing,
                        session=tx_session,
                        expected_action=action,
                        expected_actor=actor or identity.actor,
                        expected_args=args,
                        receipt_sealer=self._providers.receipt_sealer,
                        descriptor_signer=self._providers.descriptor_signer,
                    )
                )
            if operation_name == "revoke":
                if locked_identity.status != "active":
                    raise RuntimeEnrollmentHttpError(
                        409,
                        "IDENTITY_NOT_ACTIVE",
                        "conflict",
                        "runtime identity is not active",
                    )
                credential = _active_credential(
                    tx_session,
                    org_id=identity.org_id,
                    project_id=identity.project_id,
                    environment_id=identity.environment_id,
                    identity_id=identity.id,
                    lock=True,
                )
                if credential is None or credential.generation != args.get(
                    "expected_credential_generation"
                ):
                    raise RuntimeEnrollmentHttpError(
                        409,
                        "CREDENTIAL_GENERATION_MISMATCH",
                        "conflict",
                        "runtime identity active credential generation does not match "
                        "expected generation",
                    )
            return None

        def after_success(
            session: Session,
            receipt_row: ManagedDecisionReceipt,
            _event: ManagedGovernanceEvent,
            _outbox: ManagedOutboxMessage,
            result: ManagedMutationResult,
        ) -> None:
            updated = session.get(RuntimeIdentity, str(result.result["identity_id"]))
            if updated is None:
                raise RuntimeError("runtime identity update committed without identity")
            payload = _response_payload(identity=updated, receipt_id=receipt_row.receipt_id)
            sealed_payload = _sealed_terminal_response_payload(
                payload,
                receipt_sealer=self._providers.receipt_sealer,
                org_id=updated.org_id,
                project_id=updated.project_id,
                environment_id=updated.environment_id,
                identity_id=updated.id,
                action=context.action,
                operation=operation_name,
                request_hash=request_hash,
                idempotency_key_hash=idempotency_key_hash,
                receipt_id=receipt_row.receipt_id,
                receipt_hash=receipt_row.receipt_hash,
            )
            if context.action == CONTROL_PLANE_RUNTIME_IDENTITY_RENEW_ACTION:
                nonce_row = session.scalars(
                    sa.select(RuntimeRequestNonce).where(
                        RuntimeRequestNonce.org_id == updated.org_id,
                        RuntimeRequestNonce.project_id == updated.project_id,
                        RuntimeRequestNonce.environment_id == updated.environment_id,
                        RuntimeRequestNonce.identity_id == updated.id,
                        RuntimeRequestNonce.nonce == str(args["nonce"]),
                    )
                ).one_or_none()
                if nonce_row is None:
                    raise RuntimeError("runtime renewal committed without nonce")
                nonce_row.receipt_id = receipt_row.receipt_id
                nonce_row.response = sealed_payload
            session.add(
                RuntimeOperationIdempotency(
                    id=new_id(),
                    idempotency_key_hash=idempotency_key_hash,
                    request_hash=request_hash,
                    org_id=updated.org_id,
                    project_id=updated.project_id,
                    environment_id=updated.environment_id,
                    identity_id=updated.id,
                    operation=operation_name,
                    receipt_id=receipt_row.receipt_id,
                    response=sealed_payload,
                )
            )
            holder["response"] = _response_from_payload(payload)

        try:
            mutation_outcome = ManagedMutationUnitOfWork(
                self._session_factory,
                receipt_sealer=self._providers.receipt_sealer,
            ).execute(
                context=context,
                receipt=receipt,
                args=args,
                before_attempt_reservation=before_attempt_reservation,
                operation_effect=lambda session, _args: operation(session),
                after_success=after_success,
            )
            if isinstance(mutation_outcome, ManagedMutationReplayResult):
                return cast(RuntimeEnrollmentResponse, mutation_outcome.result)
        except IntegrityError as exc:
            existing = _lookup_runtime_operation_idempotency_new_session(
                self._session_factory,
                org_id=identity.org_id,
                project_id=identity.project_id,
                environment_id=identity.environment_id,
                identity_id=identity.id,
                operation=operation_name,
                idempotency_key_hash=idempotency_key_hash,
            )
            if existing is not None and existing.request_hash == request_hash:
                with self._session_factory() as replay_session:
                    return _replay_runtime_operation(
                        existing,
                        session=replay_session,
                        expected_action=action,
                        expected_actor=actor or identity.actor,
                        expected_args=args,
                        receipt_sealer=self._providers.receipt_sealer,
                        descriptor_signer=self._providers.descriptor_signer,
                    )
            raise RuntimeEnrollmentHttpError(
                409,
                "NONCE_REPLAYED",
                "conflict",
                "runtime signed request nonce was already used",
            ) from exc
        except _TX_ABORT_EXCEPTIONS as exc:
            existing = _lookup_runtime_operation_idempotency_new_session(
                self._session_factory,
                org_id=identity.org_id,
                project_id=identity.project_id,
                environment_id=identity.environment_id,
                identity_id=identity.id,
                operation=operation_name,
                idempotency_key_hash=idempotency_key_hash,
            )
            if existing is not None and existing.request_hash == request_hash:
                with self._session_factory() as replay_session:
                    return _replay_runtime_operation(
                        existing,
                        session=replay_session,
                        expected_action=action,
                        expected_actor=actor or identity.actor,
                        expected_args=args,
                        receipt_sealer=self._providers.receipt_sealer,
                        descriptor_signer=self._providers.descriptor_signer,
                    )
            raise RuntimeEnrollmentHttpError(
                503,
                "TX_ABORTED",
                "tx_aborted",
                "runtime identity governed update aborted",
            ) from exc
        return holder["response"]

    def _issue_receipt(
        self,
        *,
        session: Session,
        context: ManagedMutationContext,
        record: DecisionRecord,
        audit_hash: str,
        request_id: str,
    ) -> DecisionReceipt:
        try:
            trust_epoch = active_trust_epoch_for_scope(
                session,
                ReceiptTrustScope(
                    context.org_id,
                    context.project_id,
                    context.environment_id,
                    DECISION_RECEIPT_PURPOSE,
                ),
            )
            return mint_managed_decision_receipt_v2(
                issuer=self._providers.issuer,
                context=cast(ManagedReceiptContext, context),
                record=record,
                audit_hash=audit_hash,
                previous_audit_hash=_GENESIS_AUDIT_HASH,
                trust_epoch=trust_epoch,
                request_id=request_id,
                expires_at=(utcnow() + timedelta(minutes=10)).isoformat(),
                purpose=DECISION_RECEIPT_PURPOSE,
                constraints={"schema": "runtime-enrollment-constraints/v1"},
                approval_chain_summary={},
            )
        except (TrustConfigurationError, ManagedTrustError, ReceiptValidationError) as exc:
            raise RuntimeEnrollmentHttpError(
                503,
                "SIGNER_UNAVAILABLE",
                "signer_unavailable",
                "runtime enrollment signer or trust root unavailable",
            ) from exc

    def _record_non_executable(
        self,
        *,
        context: ManagedMutationContext,
        receipt: DecisionReceipt,
        args: dict[str, Any],
        operation_name: str | None = None,
        idempotency_key_hash: str | None = None,
        request_hash: str | None = None,
        identity_id: str | None = None,
    ) -> RuntimeEnrollmentHttpError:
        refusal = _non_executable_error_for_receipt(receipt)
        response_payload = _refusal_payload(refusal)

        def before_record(tx_session: Session) -> None:
            tx_session.get(Organization, context.org_id, with_for_update=True)
            _lock_policy_head(tx_session, context=context)

        def after_record(
            session: Session,
            receipt_row: ManagedDecisionReceipt,
            _event: ManagedGovernanceEvent,
            _outbox: ManagedOutboxMessage,
            _result: ManagedNonExecutableEvidenceResult,
        ) -> None:
            if operation_name is not None:
                if idempotency_key_hash is None or request_hash is None or identity_id is None:
                    raise RuntimeError("runtime refusal idempotency metadata is incomplete")
                response_payload["receipt_id"] = receipt_row.receipt_id
                sealed_payload = _sealed_terminal_response_payload(
                    response_payload,
                    receipt_sealer=self._providers.receipt_sealer,
                    org_id=context.org_id,
                    project_id=context.project_id,
                    environment_id=context.environment_id,
                    identity_id=identity_id,
                    action=context.action,
                    operation=operation_name,
                    request_hash=request_hash,
                    idempotency_key_hash=idempotency_key_hash,
                    receipt_id=receipt_row.receipt_id,
                    receipt_hash=receipt_row.receipt_hash,
                )
                session.add(
                    RuntimeOperationIdempotency(
                        id=new_id(),
                        idempotency_key_hash=idempotency_key_hash,
                        request_hash=request_hash,
                        org_id=context.org_id,
                        project_id=context.project_id,
                        environment_id=context.environment_id,
                        identity_id=identity_id,
                        operation=operation_name,
                        receipt_id=receipt_row.receipt_id,
                        response=sealed_payload,
                    )
                )
            return None

        try:
            ManagedMutationUnitOfWork(
                self._session_factory,
                receipt_sealer=self._providers.receipt_sealer,
            ).record_non_executable_evidence(
                context=context,
                receipt=receipt,
                args=args,
                before_record=before_record,
                after_record=after_record,
            )
        except (ReceiptAlreadyUsedError, SQLAlchemyError, ReceiptValidationError) as exc:
            raise RuntimeEnrollmentHttpError(
                503,
                "TX_ABORTED",
                "tx_aborted",
                "runtime enrollment refusal evidence transaction aborted",
            ) from exc
        return refusal


def runtime_public_key_thumbprint(public_key: str) -> str:
    return gove_public_key_thumbprint(_runtime_public_key_bytes(public_key))


def _runtime_public_key_bytes(public_key: str) -> bytes:
    try:
        return b64url_decode(public_key, expected_len=32)
    except RuntimeIdentityError as exc:
        raise RuntimeEnrollmentHttpError(
            400,
            "PUBLIC_KEY_MALFORMED",
            "bad_request",
            "runtime public key is malformed",
        ) from exc


def _bootstrap_token_from_authorization(authorization: str | None) -> str:
    if authorization is None:
        raise RuntimeEnrollmentHttpError(
            401,
            "BOOTSTRAP_AUTH_REQUIRED",
            "unauthorized",
            "runtime enrollment requires an Authorization bootstrap token",
        )
    prefix = "ACGS-Gate-Bootstrap "
    if not authorization.startswith(prefix):
        raise RuntimeEnrollmentHttpError(
            401,
            "BOOTSTRAP_AUTH_SCHEME_INVALID",
            "unauthorized",
            "runtime enrollment bootstrap authorization scheme is invalid",
        )
    token = authorization.removeprefix(prefix).strip()
    if not token.startswith("acgs_gbt_") or "." not in token:
        raise RuntimeEnrollmentHttpError(
            401,
            "BOOTSTRAP_TOKEN_MALFORMED",
            "unauthorized",
            "runtime enrollment bootstrap token is malformed",
        )
    return token


def _enrollment_request_body_bytes(body: RuntimeEnrollmentRequest) -> bytes:
    timestamp = body.timestamp
    return canonical_json(
        {
            "audience": body.audience,
            "bootstrap_id": body.bootstrap_id,
            "client_nonce": body.client_nonce,
            "gate_id": body.gate_id,
            "idempotency_key_digest": body.idempotency_key_digest,
            "org_id": body.org_id,
            "project_id": body.project_id,
            "environment": body.environment,
            "public_key": body.public_key,
            "public_key_thumbprint": body.public_key_thumbprint,
            "runtime_identity_id": body.runtime_identity_id,
            "server_challenge": body.server_challenge,
            "timestamp": timestamp,
        }
    ).encode("utf-8")


def _signed_request_hash(
    *,
    identity_id: str,
    credential_id: str,
    credential_generation: int,
    key_id: str,
    audience: str,
    timestamp: datetime,
    nonce: str,
    idempotency_key_hash: str,
    body_digest: str,
    query_digest: str,
) -> dict[str, Any]:
    return {
        "schema": "runtime-identity-signed-request/v1",
        "identity_id": identity_id,
        "credential_id": credential_id,
        "credential_generation": credential_generation,
        "key_id": key_id,
        "audience": audience,
        "nonce": nonce,
        "timestamp": _to_utc(timestamp).isoformat(),
        "idempotency_key_hash": idempotency_key_hash,
        "body_digest": body_digest,
        "query_digest": query_digest,
    }


def _runtime_request_replay_hash(
    *,
    identity_id: str,
    body: RuntimeSignedRequest,
    raw_body: bytes,
    query: str,
    idempotency_key: str,
) -> str:
    return sha256_json(
        _signed_request_hash(
            identity_id=identity_id,
            credential_id=body.credential_id,
            credential_generation=body.credential_generation,
            key_id=body.key_id,
            audience=body.audience,
            timestamp=_parse_runtime_timestamp(body.timestamp),
            nonce=body.nonce,
            idempotency_key_hash=_idempotency_key_hash(idempotency_key),
            body_digest=sha256_bytes(raw_body),
            query_digest=sha256_text(query),
        )
    )


def _context(
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    actor: str,
    action: str,
    policy_bundle_id: str,
    policy_hash: str,
    policy_head_generation: int | None = None,
) -> ManagedMutationContext:
    return ManagedMutationContext(
        org_id=org_id,
        project_id=project_id,
        environment_id=environment_id,
        actor=actor,
        action=action,
        execution_boundary=managed_mutation_execution_boundary(
            org_id=org_id,
            project_id=project_id,
            environment_id=environment_id,
            action=action,
        ),
        policy_bundle_id=policy_bundle_id,
        policy_hash=policy_hash,
        validator_role=RUNTIME_ENROLLMENT_VALIDATOR_ROLE,
        authority=RUNTIME_ENROLLMENT_AUTHORITY,
        expected_policy_head_generation=policy_head_generation,
    )


def _decision_record(
    *,
    policy: Any,
    context: ManagedMutationContext,
    args: dict[str, Any],
    goal: str,
) -> DecisionRecord:
    record = policy.evaluate(
        ToolCall(
            name=context.action,
            args=dict(args),
            actor=context.actor,
            goal=goal,
            path=normalize_path_context(["control-plane", "runtime-identities"]),
            state={"environment_id_hash": sha256_json(context.environment_id)},
        )
    )
    return DecisionRecord(
        decision=record.decision,
        tool=context.action,
        argument_hash=sha256_json(args),
        policy_version=record.policy_version,
        event_id=record.event_id,
        matched_rules=tuple(record.matched_rules),
        reason=record.reason,
        timestamp_iso=record.timestamp_iso,
        transformed_args=None,
        goal=goal,
        actor=context.actor,
        path=normalize_path_context(["control-plane", "runtime-identities"]),
        state_hash=sha256_json({"environment_id": context.environment_id}),
        decision_request_hash=sha256_json(
            {
                "schema": "runtime-enrollment-decision-request/v1",
                "action": context.action,
                "args": args,
                "actor": context.actor,
            }
        ),
    )


def _decision_audit_hash(record: DecisionRecord) -> str:
    return sha256_json(
        {
            "schema": "runtime-enrollment-decision-audit/v1",
            "previous_hash": _GENESIS_AUDIT_HASH,
            "record": record.to_dict(),
        }
    )


def _resolve_scope(
    session: Session,
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    lock: bool = False,
) -> tuple[Project, Environment]:
    project_stmt = sa.select(Project).where(Project.org_id == org_id, Project.id == project_id)
    env_stmt = sa.select(Environment).where(
        Environment.org_id == org_id,
        Environment.project_id == project_id,
        Environment.id == environment_id,
    )
    if lock:
        project_stmt = project_stmt.with_for_update()
        env_stmt = env_stmt.with_for_update()
    project = session.scalars(project_stmt).one_or_none()
    environment = session.scalars(env_stmt).one_or_none()
    if project is None or environment is None:
        raise RuntimeEnrollmentHttpError(
            404,
            "SCOPE_NOT_FOUND",
            "not_found",
            "runtime enrollment scope was not found",
        )
    return project, environment


def _lock_policy_head(session: Session, *, context: ManagedMutationContext) -> None:
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
            EnvironmentPolicyHead.org_id == context.org_id,
            EnvironmentPolicyHead.project_id == context.project_id,
            EnvironmentPolicyHead.environment_id == context.environment_id,
        )
        .with_for_update()
    ).one_or_none()
    if row is None:
        raise ReceiptValidationError("runtime enrollment policy head changed")
    head, version = row
    if (
        head.active_policy_version_id != context.policy_bundle_id
        or version.content_hash != context.policy_hash
        or (
            context.expected_policy_head_generation is not None
            and head.generation != context.expected_policy_head_generation
        )
    ):
        raise ReceiptValidationError("runtime enrollment policy head changed")


def _ensure_gate(
    session: Session, *, org_id: str, project_id: str, environment_id: str
) -> RuntimeIdentityGate:
    gate = session.scalars(
        sa.select(RuntimeIdentityGate)
        .where(
            RuntimeIdentityGate.org_id == org_id,
            RuntimeIdentityGate.project_id == project_id,
            RuntimeIdentityGate.environment_id == environment_id,
        )
        .with_for_update()
    ).one_or_none()
    if gate is not None:
        if gate.status != "active":
            raise ReceiptValidationError("runtime identity gate is revoked")
        return gate
    gate = RuntimeIdentityGate(
        id=new_id(),
        org_id=org_id,
        project_id=project_id,
        environment_id=environment_id,
        status="active",
    )
    session.add(gate)
    session.flush()
    return gate


def _lookup_active_bootstrap(
    session: Session, *, digest: str, lock: bool
) -> RuntimeEnrollmentBootstrap | None:
    stmt = sa.select(RuntimeEnrollmentBootstrap).where(
        RuntimeEnrollmentBootstrap.bootstrap_digest == digest,
        RuntimeEnrollmentBootstrap.status == "active",
    )
    if lock:
        stmt = stmt.with_for_update()
    return session.scalars(stmt).one_or_none()


def _lookup_bootstrap_by_digest(
    session: Session, *, digest: str, lock: bool
) -> RuntimeEnrollmentBootstrap | None:
    stmt = sa.select(RuntimeEnrollmentBootstrap).where(
        RuntimeEnrollmentBootstrap.bootstrap_digest == digest
    )
    if lock:
        stmt = stmt.with_for_update()
    return session.scalars(stmt).one_or_none()


def _lookup_enrollment_idempotency(
    session: Session,
    *,
    key_hash: str,
    org_id: str,
    project_id: str,
    environment_id: str,
    identity_id: str,
    lock: bool,
) -> RuntimeEnrollmentIdempotency | None:
    stmt = sa.select(RuntimeEnrollmentIdempotency).where(
        RuntimeEnrollmentIdempotency.idempotency_key_hash == key_hash,
        RuntimeEnrollmentIdempotency.org_id == org_id,
        RuntimeEnrollmentIdempotency.project_id == project_id,
        RuntimeEnrollmentIdempotency.environment_id == environment_id,
        RuntimeEnrollmentIdempotency.identity_id == identity_id,
    )
    if lock:
        stmt = stmt.with_for_update()
    return session.scalars(stmt).one_or_none()


def _lookup_enrollment_idempotency_new_session(
    session_factory: sessionmaker[Session],
    *,
    key_hash: str,
    org_id: str,
    project_id: str,
    environment_id: str,
    identity_id: str,
) -> RuntimeEnrollmentIdempotency | None:
    if not key_hash:
        return None
    with session_factory() as session:
        return _lookup_enrollment_idempotency(
            session,
            key_hash=key_hash,
            org_id=org_id,
            project_id=project_id,
            environment_id=environment_id,
            identity_id=identity_id,
            lock=False,
        )


def _lookup_runtime_operation_idempotency(
    session: Session,
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    identity_id: str,
    operation: str,
    idempotency_key_hash: str,
    lock: bool,
) -> RuntimeOperationIdempotency | None:
    stmt = sa.select(RuntimeOperationIdempotency).where(
        RuntimeOperationIdempotency.org_id == org_id,
        RuntimeOperationIdempotency.project_id == project_id,
        RuntimeOperationIdempotency.environment_id == environment_id,
        RuntimeOperationIdempotency.identity_id == identity_id,
        RuntimeOperationIdempotency.operation == operation,
        RuntimeOperationIdempotency.idempotency_key_hash == idempotency_key_hash,
    )
    if lock:
        stmt = stmt.with_for_update()
    return session.scalars(stmt).one_or_none()


def _lookup_runtime_operation_idempotency_new_session(
    session_factory: sessionmaker[Session],
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    identity_id: str,
    operation: str,
    idempotency_key_hash: str,
) -> RuntimeOperationIdempotency | None:
    with session_factory() as session:
        return _lookup_runtime_operation_idempotency(
            session,
            org_id=org_id,
            project_id=project_id,
            environment_id=environment_id,
            identity_id=identity_id,
            operation=operation,
            idempotency_key_hash=idempotency_key_hash,
            lock=False,
        )


def _idempotency_key_hash(key: str) -> str:
    return sha256_json({"schema": "runtime-enrollment-idempotency-key/v1", "key": key})


def _runtime_operation_request_hash(
    *,
    operation: str,
    org_id: str,
    project_id: str,
    environment_id: str,
    identity_id: str,
    actor: str,
    expected_credential_generation: int | None = None,
) -> str:
    return sha256_json(
        {
            "schema": "runtime-operation-request/v1",
            "operation": operation,
            "org_id": org_id,
            "project_id": project_id,
            "environment_id": environment_id,
            "identity_id": identity_id,
            "actor": actor,
            "expected_credential_generation": expected_credential_generation,
        }
    )


def _descriptor(
    *,
    identity: RuntimeIdentity,
    credential: RuntimeCredentialGeneration,
    public_key: bytes,
    gate_id: str,
    audience: str,
    issued_at: datetime,
    expires_at: datetime,
    signer: InMemoryEd25519WorkloadKeyProvider,
) -> dict[str, Any]:
    return GoveRuntimeIdentityDescriptor.issue(
        scope=GateScope(
            org_id=identity.org_id,
            project_id=identity.project_id,
            environment=identity.environment_id,
            gate_id=gate_id,
        ),
        runtime_identity_id=identity.id,
        credential_id=credential.id,
        credential_generation=credential.generation,
        workload_public_key=public_key,
        issuer="acgs-control-plane",
        audience=audience,
        issued_at=_runtime_timestamp(_to_utc(issued_at)),
        expires_at=_runtime_timestamp(_to_utc(expires_at)),
        signer=signer,
    ).to_dict()


def _response_payload(*, identity: RuntimeIdentity, receipt_id: str) -> dict[str, Any]:
    return {
        "identity_id": identity.id,
        "org_id": identity.org_id,
        "project_id": identity.project_id,
        "environment_id": identity.environment_id,
        "generation": identity.current_generation,
        "descriptor": dict(identity.descriptor),
        "receipt_id": receipt_id,
    }


def _sealed_terminal_response_payload(
    payload: Mapping[str, Any],
    *,
    receipt_sealer: AesGcmReceiptArtifactSealer,
    org_id: str,
    project_id: str,
    environment_id: str,
    identity_id: str,
    action: str,
    operation: str,
    request_hash: str,
    idempotency_key_hash: str,
    receipt_id: str,
    receipt_hash: str,
) -> dict[str, Any]:
    terminal_payload = dict(payload)
    terminal_payload.pop(_TERMINAL_RESPONSE_SEAL_KEY, None)
    envelope = receipt_sealer.seal(
        canonical_json(terminal_payload).encode("utf-8"),
        associated_data=_terminal_response_aad(
            org_id=org_id,
            project_id=project_id,
            environment_id=environment_id,
            identity_id=identity_id,
            action=action,
            operation=operation,
            request_hash=request_hash,
            idempotency_key_hash=idempotency_key_hash,
            receipt_id=receipt_id,
            receipt_hash=receipt_hash,
        ),
    )
    return {**terminal_payload, _TERMINAL_RESPONSE_SEAL_KEY: dict(envelope)}


def _verified_stored_terminal_payload(
    payload: Mapping[str, Any],
    *,
    receipt_sealer: AesGcmReceiptArtifactSealer,
    org_id: str,
    project_id: str,
    environment_id: str,
    identity_id: str,
    action: str,
    operation: str,
    request_hash: str,
    idempotency_key_hash: str,
    receipt_id: str,
    receipt_hash: str,
) -> dict[str, Any]:
    seal = payload.get(_TERMINAL_RESPONSE_SEAL_KEY)
    if not isinstance(seal, Mapping):
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime terminal response seal is missing",
        )
    terminal_payload = dict(payload)
    terminal_payload.pop(_TERMINAL_RESPONSE_SEAL_KEY, None)
    try:
        plaintext = receipt_sealer.unseal(
            seal,
            associated_data=_terminal_response_aad(
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                identity_id=identity_id,
                action=action,
                operation=operation,
                request_hash=request_hash,
                idempotency_key_hash=idempotency_key_hash,
                receipt_id=receipt_id,
                receipt_hash=receipt_hash,
            ),
        )
        sealed_payload = json.loads(plaintext.decode("utf-8"))
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime terminal response seal is invalid",
        ) from exc
    if sealed_payload != terminal_payload:
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime terminal response seal does not match stored payload",
        )
    return terminal_payload


def _terminal_response_aad(
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    identity_id: str,
    action: str,
    operation: str,
    request_hash: str,
    idempotency_key_hash: str,
    receipt_id: str,
    receipt_hash: str,
) -> bytes:
    return canonical_json(
        {
            "schema": _TERMINAL_RESPONSE_SEAL_SCHEMA,
            "org_id": org_id,
            "project_id": project_id,
            "environment_id": environment_id,
            "identity_id": identity_id,
            "action": action,
            "operation": operation,
            "request_hash": request_hash,
            "idempotency_key_hash": idempotency_key_hash,
            "receipt_id": receipt_id,
            "receipt_hash": receipt_hash,
            "response_schema": "runtime-terminal-response/v1",
        }
    ).encode("utf-8")


def _response_from_payload(payload: dict[str, Any]) -> RuntimeEnrollmentResponse:
    descriptor = dict(payload["descriptor"])
    return RuntimeEnrollmentResponse(
        identity_id=str(payload["identity_id"]),
        org_id=str(payload["org_id"]),
        project_id=str(payload["project_id"]),
        environment_id=str(payload["environment_id"]),
        generation=int(payload["generation"]),
        descriptor=RuntimeIdentityDescriptor(**descriptor),
        receipt_id=str(payload["receipt_id"]),
    )


def _response_from_payload_verified(
    session: Session,
    payload: dict[str, Any],
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    identity_id: str,
    receipt_id: str | None,
    expected_action: str,
    operation: str,
    expected_actor: str,
    expected_args: Mapping[str, Any],
    request_hash: str,
    idempotency_key_hash: str,
    receipt_sealer: AesGcmReceiptArtifactSealer,
    descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> RuntimeEnrollmentResponse:
    if receipt_id is None:
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime enrollment terminal response receipt does not match its ledger",
        )
    receipt = session.scalars(
        sa.select(ManagedDecisionReceipt).where(
            ManagedDecisionReceipt.org_id == org_id,
            ManagedDecisionReceipt.project_id == project_id,
            ManagedDecisionReceipt.environment_id == environment_id,
            ManagedDecisionReceipt.receipt_id == receipt_id,
        )
    ).one_or_none()
    if receipt is None:
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime terminal response receipt is missing",
        )
    terminal_payload = _verified_stored_terminal_payload(
        payload,
        receipt_sealer=receipt_sealer,
        org_id=org_id,
        project_id=project_id,
        environment_id=environment_id,
        identity_id=identity_id,
        action=expected_action,
        operation=operation,
        request_hash=request_hash,
        idempotency_key_hash=idempotency_key_hash,
        receipt_id=receipt_id,
        receipt_hash=receipt.receipt_hash,
    )
    if terminal_payload.get("receipt_id") != receipt_id:
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime enrollment terminal response receipt does not match its ledger",
        )
    if (
        terminal_payload.get("org_id") != org_id
        or terminal_payload.get("project_id") != project_id
        or terminal_payload.get("environment_id") != environment_id
        or terminal_payload.get("identity_id") != identity_id
    ):
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime enrollment terminal response does not match its scope",
        )
    try:
        expected_generation = int(terminal_payload["generation"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime enrollment terminal response generation is invalid",
        ) from exc
    identity = _scoped_identity(
        session,
        org_id=org_id,
        project_id=project_id,
        environment_id=environment_id,
        identity_id=identity_id,
    )
    if identity is None:
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime enrollment terminal response identity is missing",
        )
    return _response_from_identity_verified(
        session,
        identity,
        receipt=receipt,
        receipt_id=receipt_id,
        expected_generation=expected_generation,
        expected_action=expected_action,
        expected_actor=expected_actor,
        expected_args=expected_args,
        receipt_sealer=receipt_sealer,
        descriptor_signer=descriptor_signer,
    )


def _response_from_identity_verified(
    session: Session,
    identity: RuntimeIdentity,
    *,
    receipt: ManagedDecisionReceipt,
    receipt_id: str,
    expected_generation: int,
    expected_action: str,
    expected_actor: str,
    expected_args: Mapping[str, Any],
    receipt_sealer: AesGcmReceiptArtifactSealer,
    descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> RuntimeEnrollmentResponse:
    credential = session.scalars(
        sa.select(RuntimeCredentialGeneration).where(
            RuntimeCredentialGeneration.org_id == identity.org_id,
            RuntimeCredentialGeneration.project_id == identity.project_id,
            RuntimeCredentialGeneration.environment_id == identity.environment_id,
            RuntimeCredentialGeneration.identity_id == identity.id,
            RuntimeCredentialGeneration.generation == expected_generation,
        )
    ).one_or_none()
    if credential is None:
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime enrollment terminal response credential is invalid",
        )
    descriptor_payload = dict(credential.descriptor)
    try:
        descriptor = GoveRuntimeIdentityDescriptor.from_dict(descriptor_payload)
    except RuntimeIdentityError as exc:
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime enrollment terminal response descriptor is malformed",
        ) from exc
    expected_scope = GateScope(
        org_id=identity.org_id,
        project_id=identity.project_id,
        environment=identity.environment_id,
        gate_id=identity.gate_id,
    )
    try:
        descriptor.verify(
            descriptor_signer.public_key_bytes(),
            expected_scope=expected_scope,
            expected_audience=RUNTIME_ENROLLMENT_AUTHORITY,
            now=_descriptor_issued_at(descriptor),
        )
    except RuntimeIdentityError as exc:
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime enrollment terminal response descriptor is invalid",
        ) from exc
    if (
        descriptor.runtime_identity_id != identity.id
        or descriptor.credential_generation != expected_generation
        or descriptor.public_key_thumbprint != credential.public_key_thumbprint
    ):
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime enrollment terminal response descriptor does not match identity",
        )
    if (
        credential.id != descriptor.credential_id
        or dict(credential.descriptor) != descriptor_payload
    ):
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime enrollment terminal response credential is invalid",
        )
    descriptor_issued_at = _descriptor_issued_at(descriptor)
    descriptor_expires_at = _descriptor_expires_at(descriptor)
    if (
        _to_utc(credential.not_before) != descriptor_issued_at
        or _to_utc(credential.not_after) != descriptor_expires_at
    ):
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime enrollment terminal response credential validity is invalid",
        )
    _verify_replay_receipt(
        session,
        receipt,
        expected_action=expected_action,
        expected_actor=expected_actor,
        expected_decision="allow",
        expected_args=expected_args,
        expected_result={"identity_id": identity.id, "generation": expected_generation},
        receipt_sealer=receipt_sealer,
    )
    payload = {
        "identity_id": identity.id,
        "org_id": identity.org_id,
        "project_id": identity.project_id,
        "environment_id": identity.environment_id,
        "generation": expected_generation,
        "descriptor": descriptor_payload,
        "receipt_id": receipt_id,
    }
    return _response_from_payload(payload)


def _descriptor_issued_at(descriptor: GoveRuntimeIdentityDescriptor) -> datetime:
    return _parse_terminal_descriptor_timestamp(descriptor.issued_at, field_name="issued_at")


def _descriptor_expires_at(descriptor: GoveRuntimeIdentityDescriptor) -> datetime:
    return _parse_terminal_descriptor_timestamp(descriptor.expires_at, field_name="expires_at")


def _parse_terminal_descriptor_timestamp(value: str, *, field_name: str) -> datetime:
    try:
        if value.endswith("Z"):
            parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
        else:
            parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            f"runtime enrollment terminal response descriptor {field_name} is malformed",
        ) from exc
    return _to_utc(parsed)


def _replay_runtime_operation(
    existing: RuntimeOperationIdempotency,
    *,
    session: Session | None = None,
    expected_action: str,
    expected_actor: str,
    expected_args: Mapping[str, Any],
    receipt_sealer: AesGcmReceiptArtifactSealer,
    descriptor_signer: InMemoryEd25519WorkloadKeyProvider | None = None,
) -> RuntimeEnrollmentResponse:
    if session is None:
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime operation terminal response cannot be verified",
        )
    receipt = session.scalars(
        sa.select(ManagedDecisionReceipt).where(
            ManagedDecisionReceipt.org_id == existing.org_id,
            ManagedDecisionReceipt.project_id == existing.project_id,
            ManagedDecisionReceipt.environment_id == existing.environment_id,
            ManagedDecisionReceipt.receipt_id == existing.receipt_id,
        )
    ).one_or_none()
    if receipt is None:
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime operation terminal response receipt is missing",
        )
    decision = receipt.decision.upper()
    if decision in {"DENY", "ESCALATE"}:
        artifacts = _verify_replay_receipt(
            session,
            receipt,
            expected_action=expected_action,
            expected_actor=expected_actor,
            expected_decision=decision.lower(),
            expected_args=expected_args,
            expected_result={"status": "non_executable", "decision": receipt.decision},
            receipt_sealer=receipt_sealer,
        )
        canonical_error = _non_executable_error_for_receipt(artifacts.sealed_receipt)
        canonical_payload = _refusal_payload(canonical_error)
        terminal_payload = _verified_stored_terminal_payload(
            existing.response,
            receipt_sealer=receipt_sealer,
            org_id=existing.org_id,
            project_id=existing.project_id,
            environment_id=existing.environment_id,
            identity_id=existing.identity_id,
            action=expected_action,
            operation=existing.operation,
            request_hash=existing.request_hash,
            idempotency_key_hash=existing.idempotency_key_hash,
            receipt_id=existing.receipt_id,
            receipt_hash=receipt.receipt_hash,
        )
        if terminal_payload != canonical_payload:
            raise RuntimeEnrollmentHttpError(
                503,
                "TERMINAL_RESPONSE_TAMPERED",
                "terminal_response_tampered",
                "runtime operation terminal refusal does not match its receipt",
            )
        raise canonical_error
    if descriptor_signer is None:
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime operation terminal response cannot be verified",
        )
    return _response_from_payload_verified(
        session,
        existing.response,
        org_id=existing.org_id,
        project_id=existing.project_id,
        environment_id=existing.environment_id,
        identity_id=existing.identity_id,
        receipt_id=existing.receipt_id,
        expected_action=expected_action,
        operation=existing.operation,
        expected_actor=expected_actor,
        expected_args=expected_args,
        request_hash=existing.request_hash,
        idempotency_key_hash=existing.idempotency_key_hash,
        receipt_sealer=receipt_sealer,
        descriptor_signer=descriptor_signer,
    )


def _verify_replay_receipt(
    session: Session,
    receipt: ManagedDecisionReceipt | None,
    *,
    expected_action: str,
    expected_actor: str,
    expected_decision: str,
    expected_args: Mapping[str, Any],
    expected_result: Mapping[str, Any],
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> ManagedReplayArtifacts:
    if receipt is None:
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime terminal response receipt is missing",
        )
    result_for_hash = (
        {"status": "non_executable", "decision": receipt.decision}
        if expected_decision.lower() != "allow"
        else dict(expected_result)
    )
    try:
        return validate_managed_replay_artifacts(
            session,
            receipt,
            expected_action=expected_action,
            expected_actor=expected_actor,
            expected_decision=expected_decision,
            expected_args=expected_args,
            expected_result_hash=safe_result_hash(result_for_hash),
            receipt_sealer=receipt_sealer,
        )
    except ManagedReplayArtifactValidationError as exc:
        raise RuntimeEnrollmentHttpError(
            503,
            "TERMINAL_RESPONSE_TAMPERED",
            "terminal_response_tampered",
            "runtime terminal response managed replay artifacts are invalid",
        ) from exc


def _non_executable_error_for_receipt(
    receipt: DecisionReceipt | ManagedDecisionReceipt,
) -> RuntimeEnrollmentHttpError:
    decision = receipt.decision.upper()
    if decision == "DENY":
        return RuntimeEnrollmentHttpError(
            403,
            "POLICY_DENIED",
            "denied",
            "runtime operation was denied by policy",
            receipt_id=receipt.receipt_id,
            decision="DENY",
        )
    if decision == "ESCALATE":
        return RuntimeEnrollmentHttpError(
            202,
            "POLICY_ESCALATED",
            "pending_approval",
            "runtime operation requires approval",
            receipt_id=receipt.receipt_id,
            decision="ESCALATE",
        )
    raise RuntimeEnrollmentHttpError(
        503,
        "POLICY_NOT_EXECUTABLE",
        "not_executable",
        "runtime operation produced a non-executable decision",
        receipt_id=receipt.receipt_id,
        decision=decision,
    )


def _refusal_payload(error: RuntimeEnrollmentHttpError) -> dict[str, Any]:
    return {
        "status": error.status,
        "reason": error.detail,
        "receipt_id": error.receipt_id,
        "decision": error.decision,
    }


def _scoped_identity(
    session: Session,
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    identity_id: str,
) -> RuntimeIdentity | None:
    return session.scalars(
        sa.select(RuntimeIdentity).where(
            RuntimeIdentity.org_id == org_id,
            RuntimeIdentity.project_id == project_id,
            RuntimeIdentity.environment_id == environment_id,
            RuntimeIdentity.id == identity_id,
        )
    ).one_or_none()


def _active_credential(
    session: Session,
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    identity_id: str,
    lock: bool,
) -> RuntimeCredentialGeneration | None:
    stmt = sa.select(RuntimeCredentialGeneration).where(
        RuntimeCredentialGeneration.org_id == org_id,
        RuntimeCredentialGeneration.project_id == project_id,
        RuntimeCredentialGeneration.environment_id == environment_id,
        RuntimeCredentialGeneration.identity_id == identity_id,
        RuntimeCredentialGeneration.status == "active",
    )
    if lock:
        stmt = stmt.with_for_update()
    return session.scalars(stmt).one_or_none()


def _burn_nonce_then_renew(
    session: Session,
    *,
    identity: RuntimeIdentity,
    body: RuntimeSignedRequest,
    expected_credential: RuntimeCredentialGeneration,
    idempotency_key_hash: str,
    request_hash: str,
    descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> dict[str, Any]:
    current = session.scalars(
        sa.select(RuntimeCredentialGeneration)
        .where(
            RuntimeCredentialGeneration.org_id == identity.org_id,
            RuntimeCredentialGeneration.project_id == identity.project_id,
            RuntimeCredentialGeneration.environment_id == identity.environment_id,
            RuntimeCredentialGeneration.identity_id == identity.id,
            RuntimeCredentialGeneration.status == "active",
        )
        .with_for_update()
    ).one_or_none()
    if (
        current is None
        or current.id != expected_credential.id
        or current.generation != expected_credential.generation
    ):
        raise ReceiptValidationError("runtime credential generation changed")
    now = utcnow()
    if not (_to_utc(current.not_before) <= now < _to_utc(current.not_after)):
        raise ReceiptValidationError("runtime credential generation expired")
    gate = session.scalars(
        sa.select(RuntimeIdentityGate)
        .where(
            RuntimeIdentityGate.org_id == identity.org_id,
            RuntimeIdentityGate.project_id == identity.project_id,
            RuntimeIdentityGate.environment_id == identity.environment_id,
            RuntimeIdentityGate.id == identity.gate_id,
        )
        .with_for_update()
    ).one_or_none()
    if gate is None or gate.status != "active":
        raise ReceiptValidationError("runtime identity gate is not active")
    session.add(
        RuntimeRequestNonce(
            id=new_id(),
            org_id=identity.org_id,
            project_id=identity.project_id,
            environment_id=identity.environment_id,
            identity_id=identity.id,
            nonce=body.nonce,
            idempotency_key_hash=idempotency_key_hash,
            request_hash=request_hash,
            purpose="renew",
        )
    )
    return _renew_identity(session, identity.id, descriptor_signer=descriptor_signer)


def _renew_identity(
    session: Session,
    identity_id: str,
    *,
    descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> dict[str, Any]:
    identity = session.get(RuntimeIdentity, identity_id, with_for_update=True)
    if identity is None or identity.status != "active":
        raise ReceiptValidationError("runtime identity is not active")
    current = session.scalars(
        sa.select(RuntimeCredentialGeneration)
        .where(
            RuntimeCredentialGeneration.org_id == identity.org_id,
            RuntimeCredentialGeneration.project_id == identity.project_id,
            RuntimeCredentialGeneration.environment_id == identity.environment_id,
            RuntimeCredentialGeneration.identity_id == identity.id,
            RuntimeCredentialGeneration.status == "active",
        )
        .with_for_update()
    ).one_or_none()
    if current is None:
        raise ReceiptValidationError("runtime identity active credential is missing")
    now = utcnow()
    current.status = "superseded"
    current.superseded_at = now
    generation = current.generation + 1
    expires_at = now + timedelta(seconds=RUNTIME_CREDENTIAL_TTL_SECONDS)
    next_credential = RuntimeCredentialGeneration(
        id=new_id(),
        org_id=identity.org_id,
        project_id=identity.project_id,
        environment_id=identity.environment_id,
        identity_id=identity.id,
        generation=generation,
        workload_key_id=identity.workload_key_id,
        public_key_thumbprint=identity.public_key_thumbprint,
        not_before=now,
        not_after=expires_at,
        status="active",
        descriptor={},
    )
    descriptor = _descriptor(
        identity=identity,
        credential=next_credential,
        public_key=_runtime_public_key_bytes(identity.public_key),
        gate_id=identity.gate_id,
        audience=RUNTIME_ENROLLMENT_AUTHORITY,
        issued_at=now,
        expires_at=expires_at,
        signer=descriptor_signer,
    )
    identity.current_generation = generation
    identity.descriptor = descriptor
    identity.updated_at = now
    next_credential.descriptor = descriptor
    session.add(next_credential)
    session.flush()
    return {"identity_id": identity.id, "generation": generation}


def _revoke_identity(
    session: Session,
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    identity_id: str,
    expected_credential_generation: int,
) -> dict[str, Any]:
    identity = session.scalars(
        sa.select(RuntimeIdentity)
        .where(
            RuntimeIdentity.org_id == org_id,
            RuntimeIdentity.project_id == project_id,
            RuntimeIdentity.environment_id == environment_id,
            RuntimeIdentity.id == identity_id,
        )
        .with_for_update()
    ).one_or_none()
    if identity is None or identity.status != "active":
        raise ReceiptValidationError("runtime identity is not active")
    active = _active_credential(
        session,
        org_id=org_id,
        project_id=project_id,
        environment_id=environment_id,
        identity_id=identity_id,
        lock=True,
    )
    if active is None or active.generation != expected_credential_generation:
        raise ReceiptValidationError("runtime credential generation changed")
    now = utcnow()
    identity.status = "revoked"
    identity.revoked_at = now
    identity.updated_at = now
    credentials = session.scalars(
        sa.select(RuntimeCredentialGeneration)
        .where(
            RuntimeCredentialGeneration.org_id == identity.org_id,
            RuntimeCredentialGeneration.project_id == identity.project_id,
            RuntimeCredentialGeneration.environment_id == identity.environment_id,
            RuntimeCredentialGeneration.identity_id == identity.id,
            RuntimeCredentialGeneration.status == "active",
        )
        .with_for_update()
    )
    for credential in credentials:
        credential.status = "revoked"
        credential.revoked_at = now
    session.flush()
    return {"identity_id": identity.id, "generation": identity.current_generation}


def _detach_identity(identity: RuntimeIdentity) -> RuntimeIdentity:
    return RuntimeIdentity(
        id=identity.id,
        org_id=identity.org_id,
        project_id=identity.project_id,
        environment_id=identity.environment_id,
        gate_id=identity.gate_id,
        name=identity.name,
        actor=identity.actor,
        workload_key_id=identity.workload_key_id,
        public_key=identity.public_key,
        public_key_thumbprint=identity.public_key_thumbprint,
        descriptor=dict(identity.descriptor),
        status=identity.status,
        current_generation=identity.current_generation,
    )


def _detach_credential(credential: RuntimeCredentialGeneration) -> RuntimeCredentialGeneration:
    return RuntimeCredentialGeneration(
        id=credential.id,
        org_id=credential.org_id,
        project_id=credential.project_id,
        environment_id=credential.environment_id,
        identity_id=credential.identity_id,
        generation=credential.generation,
        workload_key_id=credential.workload_key_id,
        public_key_thumbprint=credential.public_key_thumbprint,
        not_before=credential.not_before,
        not_after=credential.not_after,
        status=credential.status,
        descriptor=dict(credential.descriptor),
    )


def _to_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _parse_runtime_timestamp(value: str) -> datetime:
    if not value.endswith("Z"):
        raise RuntimeEnrollmentHttpError(
            400,
            "TIMESTAMP_MALFORMED",
            "bad_request",
            "runtime timestamp must use canonical UTC Z form",
        )
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise RuntimeEnrollmentHttpError(
            400,
            "TIMESTAMP_MALFORMED",
            "bad_request",
            "runtime timestamp is malformed",
        ) from exc
    return _to_utc(parsed)


def _runtime_timestamp(value: datetime) -> str:
    return _to_utc(value).isoformat().replace("+00:00", "Z")


__all__ = [
    "RUNTIME_BOOTSTRAP_PEPPER_KEY_ID",
    "RUNTIME_RECEIPT_KEY_ID",
    "RuntimeEnrollmentHttpError",
    "RuntimeEnrollmentService",
    "local_runtime_bootstrap_pepper",
    "local_runtime_descriptor_signer",
    "local_runtime_enrollment_issuer",
    "local_runtime_enrollment_receipt_sealer",
    "runtime_public_key_thumbprint",
]
