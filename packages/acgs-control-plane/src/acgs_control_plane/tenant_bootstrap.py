"""Canonical tenant bootstrap service for the managed control plane."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

import sqlalchemy as sa
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import ReceiptAlreadyUsedError, ReceiptRejectionReason, ReceiptValidationError
from gove_zone.receipt import DecisionReceipt
from gove_zone.signing import Ed25519Signer
from gove_zone.trust import (
    ReceiptTrustRegistry,
    ReceiptTrustScope,
    StaticReceiptTrustRegistry,
    TrustConfigurationError,
    TrustedReceiptKey,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from acgs_control_plane.auth import generate_api_key
from acgs_control_plane.managed_mutations import (
    ASSURANCE_CLASS_NATIVE,
    TENANT_BOOTSTRAP_ACTION,
    TENANT_BOOTSTRAP_EXECUTION_BOUNDARY,
    AesGcmReceiptArtifactSealer,
    ManagedMutationContext,
    ManagedMutationResult,
    ManagedMutationUnitOfWork,
)
from acgs_control_plane.models import (
    Environment,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    Organization,
    OrganizationMembership,
    PendingApproval,
    PlatformBootstrapInvitation,
    Project,
    TenantBootstrapIdempotency,
    TenantBootstrapPendingOutbox,
    TenantBootstrapPolicyArtifact,
    TenantBootstrapRefusalEvent,
    User,
    new_id,
    utcnow,
)
from acgs_control_plane.schemas import TenantBootstrapRequest, TenantBootstrapResponse
from acgs_control_plane.trust import (
    InProcessPlatformIssuer,
    ManagedPlatformIssuer,
    ManagedReceiptContext,
    mint_managed_decision_receipt_v2,
    public_spki_der_from_signer,
)

BOOTSTRAP_AUTHORIZATION_HEADER = "Authorization"
BOOTSTRAP_INVITATION_HEADER = "X-Bootstrap-Invitation"
BOOTSTRAP_IDEMPOTENCY_HEADER = "Idempotency-Key"
BOOTSTRAP_INVITEE_ROLE = "tenant-bootstrap-invitee"

TENANT_BOOTSTRAP_POLICY_BUNDLE_ID = "platform-tenant-bootstrap"
TENANT_BOOTSTRAP_POLICY_VERSION = "platform-tenant-bootstrap/v1"
TENANT_BOOTSTRAP_POLICY_HASH = sha256_json(
    {
        "schema": "platform-tenant-bootstrap-policy/v1",
        "policy_id": TENANT_BOOTSTRAP_POLICY_BUNDLE_ID,
        "version": TENANT_BOOTSTRAP_POLICY_VERSION,
        "rules": ("valid-one-use-platform-invitation",),
    }
)
PLATFORM_BOOTSTRAP_RECEIPT_PURPOSE = "acgs.platform-bootstrap.receipt.v1"
TENANT_BOOTSTRAP_AUTHORITY = "platform.provisioner/v1"
TENANT_BOOTSTRAP_VALIDATOR_ROLE = "platform.bootstrap-policy/v1"
_GENESIS_AUDIT_HASH = "0" * 64
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,199}$")
_BOOTSTRAP_TOKEN_MIN_BYTES = 32
_LOCAL_TEST_SIGNER_SEED = bytes.fromhex(
    "4f8f3f9d5f8d181f0d4ed3704f0b8e5a06152f4b45bdc6db0f5482d2d7b61db1"
)
_LOCAL_TEST_HMAC_KEY = hashlib.sha256(b"acgs-control-plane-local-bootstrap-hmac").digest()


@dataclass(frozen=True)
class TenantBootstrapHttpError(RuntimeError):
    status_code: int
    code: str
    status: str
    detail: str
    stage: str = "policy"
    invitation_id: str | None = None
    invitation_digest: str | None = None
    idempotency_digest: str | None = None


@dataclass(frozen=True)
class BootstrapRefusalError(RuntimeError):
    code: str
    reason: str

    def __str__(self) -> str:
        return self.reason


class BootstrapTrustUnavailable(TrustConfigurationError):
    """Typed bootstrap provider outage; message text is not a routing contract."""


class BootstrapKeyUntrusted(TrustConfigurationError):
    """Typed bootstrap key refusal; message text is not a routing contract."""


class BootstrapKeyRevoked(TrustConfigurationError):
    """Typed bootstrap key revocation; message text is not a routing contract."""


_REFUSAL_EVENT_CODES = frozenset(
    {
        "REQUEST_TOO_LARGE",
        "REQUEST_MALFORMED",
        "AUTHENTICATION_REQUIRED",
        "AUTHORIZATION_DENIED",
        "BOOTSTRAP_NOT_AUTHORIZED",
        "IDEMPOTENCY_KEY_INVALID",
        "IDEMPOTENCY_CONFLICT",
        "SIGNER_UNAVAILABLE",
        "RECEIPT_MISSING",
        "RECEIPT_MALFORMED",
        "RECEIPT_VERSION_UNSUPPORTED",
        "RECEIPT_FIELD_MISSING",
        "SIGNATURE_INVALID",
        "KEY_UNTRUSTED",
        "KEY_REVOKED",
        "TRUST_PROVIDER_UNAVAILABLE",
        "EXPIRED",
        "REPLAYED",
        "CONSUMED",
        "DECISION_NOT_ALLOW",
        "ORG_MISMATCH",
        "PROJECT_MISMATCH",
        "ENV_MISMATCH",
        "EXECUTION_BOUNDARY_MISMATCH",
        "ACTOR_MISMATCH",
        "AUTHORITY_MISMATCH",
        "VALIDATOR_MISMATCH",
        "ACTION_MISMATCH",
        "ARGUMENTS_MISMATCH",
        "POLICY_MISMATCH",
        "AUDIT_ANCHOR_MISMATCH",
        "TX_ABORTED",
    }
)
_NON_REFUSAL_OUTCOMES = frozenset({"POLICY_DENIED", "ESCALATE_PENDING"})


@dataclass(frozen=True)
class PlatformBootstrapPrincipal:
    actor: str
    permissions: frozenset[str]


class PlatformBootstrapAuthenticator(Protocol):
    def authenticate_bearer(self, bearer_token: str) -> PlatformBootstrapPrincipal | None: ...


class TenantBootstrapReceiptIssuer(Protocol):
    def issue(
        self,
        *,
        context: ManagedMutationContext,
        args: dict[str, str],
        decision: Decision,
        reason: str,
        request_id: str,
    ) -> tuple[DecisionReceipt | None, str]: ...


@dataclass(frozen=True, slots=True)
class TenantBootstrapProviders:
    issuer: ManagedPlatformIssuer
    authenticator: PlatformBootstrapAuthenticator
    secret_hasher: TenantBootstrapSecretHasher
    trust_registry: ReceiptTrustRegistry
    receipt_sealer: AesGcmReceiptArtifactSealer
    receipt_issuer: TenantBootstrapReceiptIssuer


@dataclass(frozen=True)
class StaticPlatformBootstrapAuthenticator:
    """Test/local authenticator; production must inject an IdP-backed provider."""

    token_to_principal: dict[str, PlatformBootstrapPrincipal]

    def authenticate_bearer(self, bearer_token: str) -> PlatformBootstrapPrincipal | None:
        return self.token_to_principal.get(bearer_token)


@dataclass(frozen=True)
class DefaultTenantBootstrapReceiptIssuer:
    issuer: ManagedPlatformIssuer

    def issue(
        self,
        *,
        context: ManagedMutationContext,
        args: dict[str, str],
        decision: Decision,
        reason: str,
        request_id: str,
    ) -> tuple[DecisionReceipt, str]:
        return _mint_receipt(
            issuer=self.issuer,
            context=context,
            args=args,
            decision=decision,
            reason=reason,
            request_id=request_id,
        )


@dataclass(frozen=True)
class TenantBootstrapSecretHasher:
    """Keyed hashing boundary for pre-tenant secrets and idempotency digests."""

    key: bytes

    def __post_init__(self) -> None:
        if len(self.key) < _BOOTSTRAP_TOKEN_MIN_BYTES:
            raise ValueError("tenant bootstrap HMAC key must be at least 256 bits")

    def digest(self, payload: dict[str, Any]) -> str:
        return hmac.new(
            self.key,
            _canonical_json_bytes(payload),
            hashlib.sha256,
        ).hexdigest()


def local_bootstrap_issuer() -> InProcessPlatformIssuer:
    """Deterministic local/test issuer; production must inject real custody."""

    return InProcessPlatformIssuer(
        Ed25519Signer.from_private_bytes(
            _LOCAL_TEST_SIGNER_SEED,
            key_id="local-platform-tenant-bootstrap",
        ),
        allowed_purposes=frozenset({PLATFORM_BOOTSTRAP_RECEIPT_PURPOSE}),
    )


def local_platform_bootstrap_authenticator() -> StaticPlatformBootstrapAuthenticator:
    """Deterministic local/test authenticator; production must inject real auth."""

    return StaticPlatformBootstrapAuthenticator(
        {
            "local-platform-token-alice": PlatformBootstrapPrincipal(
                actor="platform:invitee:alice",
                permissions=frozenset({"tenant:bootstrap"}),
            ),
            "local-platform-token-eve": PlatformBootstrapPrincipal(
                actor="platform:invitee:eve",
                permissions=frozenset({"tenant:bootstrap"}),
            ),
            "local-platform-token-viewer": PlatformBootstrapPrincipal(
                actor="platform:invitee:viewer",
                permissions=frozenset(),
            ),
        }
    )


def local_bootstrap_secret_hasher() -> TenantBootstrapSecretHasher:
    """Deterministic local/test HMAC key; production must inject secret storage."""

    return TenantBootstrapSecretHasher(_LOCAL_TEST_HMAC_KEY)


def local_receipt_sealer() -> AesGcmReceiptArtifactSealer:
    """Deterministic local/test envelope key; production must inject KMS storage."""

    return AesGcmReceiptArtifactSealer(
        key_id="local-platform-bootstrap-sealer",
        key=hashlib.sha256(b"acgs-control-plane-local-bootstrap-sealer").digest(),
    )


def local_platform_trust_registry() -> StaticReceiptTrustRegistry:
    """Local/test verifier registry built from public material only."""

    issuer = local_bootstrap_issuer()
    signer = issuer.signer_for_scope(
        ReceiptTrustScope(
            tenant_id="local-bootstrap-placeholder",
            project_id="local-bootstrap-placeholder",
            environment_id="local-bootstrap-placeholder",
            purpose=PLATFORM_BOOTSTRAP_RECEIPT_PURPOSE,
        ),
        trust_epoch=1,
    )
    # The public key is scoped dynamically by TenantBootstrapScopeTrustRegistry;
    # this helper returns a descriptor template without exposing private custody.
    return _TenantBootstrapScopeTrustRegistry(
        key_id=issuer.key_id,
        algorithm=issuer.algorithm,
        public_key_spki_der=public_spki_der_from_signer(signer),
        not_after=utcnow() + timedelta(days=1),
    )


class _TenantBootstrapScopeTrustRegistry:
    def __init__(
        self,
        *,
        key_id: str,
        algorithm: str,
        public_key_spki_der: bytes,
        not_after: datetime,
        status: str = "active",
        unavailable: bool = False,
    ) -> None:
        self.key_id = key_id
        self.algorithm = algorithm
        self.public_key_spki_der = public_key_spki_der
        self.not_after = not_after
        self.status = status
        self.unavailable = unavailable

    def resolve(
        self,
        *,
        scope: ReceiptTrustScope,
        trust_epoch: int,
        algorithm: str,
        key_id: str,
        now_iso: str,
        mode: str = "execution",
    ) -> TrustedReceiptKey:
        if self.unavailable:
            raise BootstrapTrustUnavailable("tenant bootstrap trust provider unavailable")
        if scope.purpose != PLATFORM_BOOTSTRAP_RECEIPT_PURPOSE:
            raise BootstrapKeyUntrusted("tenant bootstrap platform key is purpose-bound")
        if key_id != self.key_id or algorithm != self.algorithm:
            raise BootstrapKeyUntrusted("tenant bootstrap platform key is not trusted")
        return TrustedReceiptKey(
            scope=scope,
            key_id=self.key_id,
            algorithm=self.algorithm,
            public_key_spki_der=self.public_key_spki_der,
            activated_epoch=1,
            not_after=self.not_after.isoformat(),
            status=self.status,
        )


def generate_bootstrap_invitation_token() -> str:
    return secrets.token_urlsafe(_BOOTSTRAP_TOKEN_MIN_BYTES)


def hash_invitation_token(token: str, hasher: TenantBootstrapSecretHasher | None = None) -> str:
    _require_strong_secret(token, code="BOOTSTRAP_NOT_AUTHORIZED")
    return (hasher or local_bootstrap_secret_hasher()).digest(
        {
            "schema": "tenant-bootstrap-invitation-token/v1",
            "token": token,
        }
    )


def create_platform_bootstrap_invitation(
    session: Session,
    *,
    token: str,
    actor: str,
    expires_at: datetime,
    policy_outcome: str = "allow",
    role: str = BOOTSTRAP_INVITEE_ROLE,
    hasher: TenantBootstrapSecretHasher | None = None,
) -> PlatformBootstrapInvitation:
    invitation = PlatformBootstrapInvitation(
        id=new_id(),
        token_hash=hash_invitation_token(token, hasher),
        invitee_actor=actor,
        invitee_role=role,
        prospective_org_id=new_id(),
        prospective_project_id=new_id(),
        prospective_environment_id=new_id(),
        prospective_membership_id=new_id(),
        policy_outcome=policy_outcome,
        expires_at=expires_at,
    )
    session.add(invitation)
    session.flush()
    return invitation


class TenantBootstrapService:
    _providers: TenantBootstrapProviders
    _session_factory: sessionmaker[Session]

    __slots__ = ("_providers", "_session_factory")

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        issuer: ManagedPlatformIssuer,
        receipt_sealer: AesGcmReceiptArtifactSealer,
        authenticator: PlatformBootstrapAuthenticator,
        secret_hasher: TenantBootstrapSecretHasher,
        trust_registry: ReceiptTrustRegistry,
        receipt_issuer: TenantBootstrapReceiptIssuer | None = None,
    ) -> None:
        object.__setattr__(self, "_session_factory", session_factory)
        object.__setattr__(
            self,
            "_providers",
            TenantBootstrapProviders(
                issuer=issuer,
                authenticator=authenticator,
                secret_hasher=secret_hasher,
                trust_registry=trust_registry,
                receipt_sealer=receipt_sealer,
                receipt_issuer=receipt_issuer or DefaultTenantBootstrapReceiptIssuer(issuer),
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("tenant bootstrap service is frozen after initialization")

    def bootstrap(
        self,
        *,
        body: TenantBootstrapRequest,
        authorization: str | None,
        invitation_secret: str | None,
        idempotency_key: str | None,
    ) -> TenantBootstrapResponse:
        providers = self._providers
        principal = _require_authenticated_principal(authorization, providers.authenticator)
        _require_platform_permission(principal)
        actor = principal.actor
        idempotency_key = _require_idempotency_key(idempotency_key)
        invitation_token = _require_invitation_secret(invitation_secret)

        with self._session_factory() as session:
            invitation = _locked_invitation(
                session,
                token=invitation_token,
                hasher=providers.secret_hasher,
            )
            if invitation is None:
                raise TenantBootstrapHttpError(
                    403,
                    "BOOTSTRAP_NOT_AUTHORIZED",
                    "bootstrap_not_authorized",
                    "platform bootstrap invitation is not valid",
                    stage="policy",
                )
            if invitation.invitee_actor != actor:
                raise TenantBootstrapHttpError(
                    403,
                    "BOOTSTRAP_NOT_AUTHORIZED",
                    "bootstrap_not_authorized",
                    "platform bootstrap invitation is not valid",
                    stage="policy",
                    invitation_id=invitation.id,
                )
            _require_invitation_role(invitation.invitee_role)
            stored_idempotency_key = _idempotency_storage_key(
                actor=actor,
                invitation_id=invitation.id,
                key=idempotency_key,
                hasher=providers.secret_hasher,
            )
            request_projection = _request_projection(body, actor=actor)
            existing = _lookup_idempotency(session, idempotency_key=stored_idempotency_key)
            if existing is not None:
                _assert_same_request(existing, request_projection)
                return TenantBootstrapResponse.model_validate(existing.response)
            if invitation.consumed_at is not None or invitation.revoked_at is not None:
                raise TenantBootstrapHttpError(
                    403,
                    "BOOTSTRAP_NOT_AUTHORIZED",
                    "bootstrap_not_authorized",
                    "platform bootstrap invitation is no longer executable",
                    stage="policy",
                    invitation_id=invitation.id,
                )
            if _to_utc(invitation.expires_at) <= utcnow():
                raise TenantBootstrapHttpError(
                    403,
                    "BOOTSTRAP_NOT_AUTHORIZED",
                    "bootstrap_not_authorized",
                    "platform bootstrap invitation is expired",
                    stage="policy",
                    invitation_id=invitation.id,
                )
            if invitation.policy_outcome == Decision.DENY.value:
                return self._record_non_executable(
                    session,
                    invitation=invitation,
                    body=body,
                    actor=actor,
                    idempotency_key=idempotency_key,
                    decision=Decision.DENY,
                )
            if invitation.policy_outcome == Decision.ESCALATE.value:
                return self._record_non_executable(
                    session,
                    invitation=invitation,
                    body=body,
                    actor=actor,
                    idempotency_key=idempotency_key,
                    decision=Decision.ESCALATE,
                )

        return self._execute_allow(
            body=body,
            actor=actor,
            invitation_token=invitation_token,
            idempotency_key=idempotency_key,
            stored_idempotency_key=stored_idempotency_key,
            request_projection=request_projection,
        )

    def _record_non_executable(
        self,
        session: Session,
        *,
        invitation: PlatformBootstrapInvitation,
        body: TenantBootstrapRequest,
        actor: str,
        idempotency_key: str,
        decision: Decision,
    ) -> TenantBootstrapResponse:
        providers = self._providers
        existing_artifact = session.scalars(
            sa.select(TenantBootstrapPolicyArtifact)
            .where(TenantBootstrapPolicyArtifact.invitation_id == invitation.id)
            .with_for_update()
        ).first()
        if existing_artifact is not None:
            if existing_artifact.decision == Decision.ESCALATE.value:
                raise TenantBootstrapHttpError(
                    202,
                    "ESCALATE_PENDING",
                    "escalate_pending",
                    "tenant bootstrap requires separated approval",
                )
            raise TenantBootstrapHttpError(
                403,
                "POLICY_DENIED",
                "policy_denied",
                "tenant bootstrap policy denied the invitation",
            )
        context, args = _context_and_args(invitation, body, actor, idempotency_key)
        receipt, audit_event_hash = providers.receipt_issuer.issue(
            context=context,
            args=args,
            decision=decision,
            reason=f"platform tenant bootstrap policy returned {decision.value}",
            request_id=idempotency_key,
        )
        if receipt is None:
            raise _executor_refusal("RECEIPT_MISSING", ValueError("policy outcome receipt missing"))
        context = replace(context, expected_audit_hash=audit_event_hash)
        _verify_signed_policy_outcome(
            receipt=receipt,
            context=context,
            args=args,
            trust_registry=providers.trust_registry,
        )
        artifact = TenantBootstrapPolicyArtifact(
            id=new_id(),
            invitation_id=invitation.id,
            org_id=context.org_id,
            project_id=context.project_id,
            environment_id=context.environment_id,
            decision=decision.value,
            receipt_hash=receipt.receipt_hash,
            audit_event_hash=audit_event_hash,
            sealed_receipt=dict(
                providers.receipt_sealer.seal(
                    _canonical_json_bytes(receipt.to_dict()),
                    associated_data=_canonical_json_bytes(
                        {
                            "schema": "tenant-bootstrap-policy-artifact/v1",
                            "receipt_hash": receipt.receipt_hash,
                        }
                    ),
                )
            ),
            event={
                "schema": "tenant-bootstrap-policy-artifact-event/v1",
                "decision": decision.value,
                "audit_event_hash": audit_event_hash,
                "actor_hash": sha256_json(actor),
                "argument_hash": receipt.argument_hash,
                "receipt_hash": receipt.receipt_hash,
                "policy_bundle_id": context.policy_bundle_id,
                "policy_version": TENANT_BOOTSTRAP_POLICY_VERSION,
                "policy_hash": context.policy_hash,
                "org_id": context.org_id,
                "project_id": context.project_id,
                "environment_id": context.environment_id,
                "assurance_class": ASSURANCE_CLASS_NATIVE,
                "source_system": "gove-zone",
            },
        )
        session.add(artifact)
        if decision is Decision.ESCALATE:
            session.flush()
            pending_payload = {
                "schema": "tenant-bootstrap-pending-outbox/v1",
                "policy_artifact_id": artifact.id,
                "receipt_hash": receipt.receipt_hash,
                "audit_event_hash": audit_event_hash,
                "argument_hash": receipt.argument_hash,
                "assurance_class": ASSURANCE_CLASS_NATIVE,
                "source_system": "gove-zone",
            }
            pending_delivery_key = f"tenant-bootstrap/escalate:{receipt.receipt_hash}"
            pending_payload_digest = sha256_json(pending_payload)
            session.add(
                TenantBootstrapPendingOutbox(
                    id=new_id(),
                    invitation_id=invitation.id,
                    policy_artifact_id=artifact.id,
                    delivery_key=pending_delivery_key,
                    payload_digest=pending_payload_digest,
                    payload=pending_payload,
                    status="pending",
                    attempts=0,
                    created_at=utcnow(),
                    available_at=utcnow(),
                    delivered_at=None,
                    org_id=context.org_id,
                    project_id=context.project_id,
                    environment_id=context.environment_id,
                )
            )
            session.add(
                PendingApproval(
                    id=new_id(),
                    org_id=context.org_id,
                    project_id=context.project_id,
                    environment_id=context.environment_id,
                    actor=actor,
                    action=context.action,
                    invitation_id=invitation.id,
                    policy_artifact_id=artifact.id,
                    receipt_hash=receipt.receipt_hash,
                    audit_event_hash=audit_event_hash,
                    lineage={
                        "schema": "tenant-bootstrap-pending-approval-lineage/v1",
                        "policy_artifact_id": artifact.id,
                        "receipt_hash": receipt.receipt_hash,
                        "audit_event_hash": audit_event_hash,
                        "assurance_class": ASSURANCE_CLASS_NATIVE,
                        "source_system": "gove-zone",
                        "pending_outbox": {
                            "schema": pending_payload["schema"],
                            "delivery_key": pending_delivery_key,
                            "payload_digest": pending_payload_digest,
                        },
                    },
                    status="pending",
                )
            )
        session.commit()
        if decision is Decision.ESCALATE:
            raise TenantBootstrapHttpError(
                202,
                "ESCALATE_PENDING",
                "escalate_pending",
                "tenant bootstrap requires separated approval",
            )
        raise TenantBootstrapHttpError(
            403,
            "POLICY_DENIED",
            "policy_denied",
            "tenant bootstrap policy denied the invitation",
            stage="policy",
            invitation_id=invitation.id,
        )

    def _execute_allow(
        self,
        *,
        body: TenantBootstrapRequest,
        actor: str,
        invitation_token: str,
        idempotency_key: str,
        stored_idempotency_key: str,
        request_projection: dict[str, Any],
    ) -> TenantBootstrapResponse:
        providers = self._providers
        with self._session_factory() as session:
            invitation = _locked_invitation(
                session,
                token=invitation_token,
                hasher=providers.secret_hasher,
            )
            if invitation is None:
                existing = _lookup_idempotency(session, idempotency_key=stored_idempotency_key)
                if existing is not None:
                    _assert_same_request(existing, request_projection)
                    return TenantBootstrapResponse.model_validate(existing.response)
                raise TenantBootstrapHttpError(
                    403,
                    "BOOTSTRAP_NOT_AUTHORIZED",
                    "bootstrap_not_authorized",
                    "platform bootstrap invitation is not valid for this actor",
                    stage="policy",
                )
            context, args = _context_and_args(invitation, body, actor, idempotency_key)
        receipt, audit_event_hash = providers.receipt_issuer.issue(
            context=context,
            args=args,
            decision=Decision.ALLOW,
            reason="platform invitation authorizes tenant bootstrap",
            request_id=idempotency_key,
        )
        context = replace(context, expected_audit_hash=audit_event_hash)
        if receipt is None:
            raise _executor_refusal(
                "RECEIPT_MISSING",
                ValueError("tenant bootstrap receipt missing"),
            )
        try:
            _verify_bootstrap_receipt(
                receipt=receipt,
                context=context,
                args=args,
                trust_registry=providers.trust_registry,
                allow_policy_outcome_refusal=False,
            )
            _reject_replayed_bootstrap_receipt(
                self._session_factory,
                receipt=receipt,
                context=context,
            )
        except ReceiptAlreadyUsedError as exc:
            raise _executor_refusal(_receipt_already_used_code(exc), exc) from exc
        except BootstrapRefusalError as exc:
            raise _map_executor_refusal(exc) from exc
        holder: dict[str, TenantBootstrapResponse] = {}
        one_time_secrets: dict[str, str] = {}
        uow = ManagedMutationUnitOfWork(
            self._session_factory,
            receipt_sealer=providers.receipt_sealer,
        )

        def before_execute(session: Session) -> None:
            invitation = _locked_invitation(
                session,
                token=invitation_token,
                hasher=providers.secret_hasher,
            )
            if invitation is None or invitation.policy_outcome != Decision.ALLOW.value:
                raise TenantBootstrapHttpError(
                    403,
                    "BOOTSTRAP_NOT_AUTHORIZED",
                    "bootstrap_not_authorized",
                    "platform bootstrap invitation is not executable",
                    stage="policy",
                )
            if invitation.invitee_actor != actor:
                raise TenantBootstrapHttpError(
                    403,
                    "BOOTSTRAP_NOT_AUTHORIZED",
                    "bootstrap_not_authorized",
                    "platform bootstrap invitation identity changed",
                    stage="policy",
                    invitation_id=invitation.id,
                )
            _require_invitation_role(invitation.invitee_role)
            existing = _lookup_idempotency(session, idempotency_key=stored_idempotency_key)
            if existing is not None:
                raise _CommittedIdempotencyRace()
            if invitation.consumed_at is not None or invitation.revoked_at is not None:
                raise TenantBootstrapHttpError(
                    403,
                    "BOOTSTRAP_NOT_AUTHORIZED",
                    "bootstrap_not_authorized",
                    "platform bootstrap invitation is no longer executable",
                    stage="policy",
                    invitation_id=invitation.id,
                )
            if _to_utc(invitation.expires_at) <= utcnow():
                raise TenantBootstrapHttpError(
                    403,
                    "BOOTSTRAP_NOT_AUTHORIZED",
                    "bootstrap_not_authorized",
                    "platform bootstrap invitation is expired",
                    stage="policy",
                    invitation_id=invitation.id,
                )

        def after_success(
            session: Session,
            receipt_row: ManagedDecisionReceipt,
            event: ManagedGovernanceEvent,
            _outbox: ManagedOutboxMessage,
            _result: ManagedMutationResult,
        ) -> None:
            response = TenantBootstrapResponse(
                org_id=context.org_id,
                project_id=context.project_id,
                environment_id=context.environment_id,
                owner_user_id=args["owner_user_id"],
                owner_membership_id=args["owner_membership_id"],
                owner_api_key=one_time_secrets["owner_api_key"],
                receipt_id=receipt_row.receipt_id,
                receipt_hash=receipt_row.receipt_hash,
                event_hash=event.event_hash,
                idempotency_key=idempotency_key,
                assurance_class=ASSURANCE_CLASS_NATIVE,
            )
            replay_response = response.model_copy(update={"owner_api_key": None})
            session.add(
                TenantBootstrapIdempotency(
                    id=new_id(),
                    idempotency_key=stored_idempotency_key,
                    actor=actor,
                    request_hash=sha256_json(request_projection),
                    org_id=context.org_id,
                    project_id=context.project_id,
                    environment_id=context.environment_id,
                    response=replay_response.model_dump(),
                )
            )
            holder["response"] = response

        try:
            uow.execute(
                context=context,
                receipt=receipt,
                args=args,
                before_execute=before_execute,
                after_success=after_success,
                operation_effect=lambda session, verified_args: _execute_bootstrap_effect(
                    session,
                    invitation_token=invitation_token,
                    secret_hasher=providers.secret_hasher,
                    body=body,
                    args=cast(dict[str, str], verified_args),
                    actor=actor,
                    context=context,
                    one_time_secrets=one_time_secrets,
                ),
                trust_registry=providers.trust_registry,
                trust_purpose=PLATFORM_BOOTSTRAP_RECEIPT_PURPOSE,
            )
        except _CommittedIdempotencyRace:
            existing = _lookup_idempotency_new_session(
                self._session_factory,
                idempotency_key=stored_idempotency_key,
            )
            if existing is not None:
                _assert_same_request(existing, request_projection)
                return TenantBootstrapResponse.model_validate(existing.response)
            raise TenantBootstrapHttpError(503, "TX_ABORTED", "tx_aborted", "commit lost") from None
        except SQLAlchemyError as exc:
            existing = _lookup_idempotency_new_session(
                self._session_factory,
                idempotency_key=stored_idempotency_key,
            )
            if existing is not None:
                _assert_same_request(existing, request_projection)
                return TenantBootstrapResponse.model_validate(existing.response)
            raise TenantBootstrapHttpError(
                503,
                "TX_ABORTED",
                "tx_aborted",
                "tenant bootstrap transaction aborted",
                stage="tx",
            ) from exc
        except ReceiptAlreadyUsedError as exc:
            existing = _lookup_idempotency_new_session(
                self._session_factory,
                idempotency_key=stored_idempotency_key,
            )
            if existing is not None:
                _assert_same_request(existing, request_projection)
                return TenantBootstrapResponse.model_validate(existing.response)
            raise _executor_refusal(_receipt_already_used_code(exc), exc) from exc
        except (
            BootstrapRefusalError,
            ReceiptValidationError,
            TrustConfigurationError,
        ) as exc:
            raise _map_executor_refusal(exc) from exc
        except TenantBootstrapHttpError:
            raise
        except Exception as exc:
            existing = _lookup_idempotency_new_session(
                self._session_factory,
                idempotency_key=stored_idempotency_key,
            )
            if existing is not None:
                _assert_same_request(existing, request_projection)
                return TenantBootstrapResponse.model_validate(existing.response)
            raise TenantBootstrapHttpError(
                503,
                "TX_ABORTED",
                "tx_aborted",
                "tenant bootstrap transaction aborted",
                stage="tx",
            ) from exc
        if "response" not in holder:
            existing = _lookup_idempotency_new_session(
                self._session_factory,
                idempotency_key=stored_idempotency_key,
            )
            if existing is not None:
                _assert_same_request(existing, request_projection)
                return TenantBootstrapResponse.model_validate(existing.response)
            raise TenantBootstrapHttpError(503, "TX_ABORTED", "tx_aborted", "commit lost")
        return holder["response"]

    def record_refusal(
        self,
        *,
        request_id: str,
        error: TenantBootstrapHttpError,
        invitation_secret: str | None = None,
        idempotency_key: str | None = None,
    ) -> None:
        if error.code in _NON_REFUSAL_OUTCOMES:
            return
        code = error.code if error.code in _REFUSAL_EVENT_CODES else "TX_ABORTED"
        stage = error.stage
        if stage not in {
            "transport",
            "authn",
            "authz",
            "policy",
            "issuance",
            "executor",
            "tx",
        }:
            stage = "tx"
        payload = {
            "schema": "tenant-bootstrap-refusal-event/v1",
            "request_id": request_id,
            "route": "POST /v1/tenant-bootstrap",
            "method": "POST",
            "stage": stage,
            "code": code,
            "http_status": error.status_code,
            "invitation_id": error.invitation_id,
            "invitation_digest": error.invitation_digest
            or _optional_secret_digest(
                self._providers.secret_hasher, "invitation", invitation_secret
            ),
            "idempotency_digest": error.idempotency_digest
            or _optional_secret_digest(
                self._providers.secret_hasher, "idempotency", idempotency_key
            ),
        }
        event_hash = sha256_json(payload)
        with self._session_factory() as session:
            existing = session.scalars(
                sa.select(TenantBootstrapRefusalEvent).where(
                    TenantBootstrapRefusalEvent.request_id == request_id
                )
            ).first()
            if existing is not None:
                return
            session.add(
                TenantBootstrapRefusalEvent(
                    id=new_id(),
                    request_id=request_id,
                    route="POST /v1/tenant-bootstrap",
                    method="POST",
                    stage=stage,
                    code=code,
                    http_status=error.status_code,
                    invitation_id=error.invitation_id,
                    invitation_digest=payload["invitation_digest"],
                    idempotency_digest=payload["idempotency_digest"],
                    event_hash=event_hash,
                    created_at=utcnow(),
                )
            )
            session.commit()


class _CommittedIdempotencyRace(RuntimeError):
    """Internal signal that a concurrent winner committed the stable result."""


def _require_authenticated_principal(
    authorization: str | None,
    authenticator: PlatformBootstrapAuthenticator,
) -> PlatformBootstrapPrincipal:
    if not authorization:
        raise TenantBootstrapHttpError(
            401,
            "AUTHENTICATION_REQUIRED",
            "authentication_required",
            "platform bearer credential is required",
            stage="authn",
        )
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip() or " " in token.strip():
        raise TenantBootstrapHttpError(
            401,
            "AUTHENTICATION_REQUIRED",
            "authentication_required",
            "platform bearer credential is malformed",
            stage="authn",
        )
    principal = authenticator.authenticate_bearer(token.strip())
    if principal is None or not principal.actor:
        raise TenantBootstrapHttpError(
            401,
            "AUTHENTICATION_REQUIRED",
            "authentication_required",
            "platform bearer credential is not recognized",
            stage="authn",
        )
    return principal


def _require_invitation_secret(invitation_secret: str | None) -> str:
    if not invitation_secret or not invitation_secret.strip() or " " in invitation_secret.strip():
        raise TenantBootstrapHttpError(
            403,
            "BOOTSTRAP_NOT_AUTHORIZED",
            "bootstrap_not_authorized",
            "platform bootstrap invitation is not valid",
            stage="policy",
        )
    token = invitation_secret.strip()
    _require_strong_secret(token, code="BOOTSTRAP_NOT_AUTHORIZED")
    return token


def _idempotency_storage_key(
    *,
    actor: str,
    invitation_id: str,
    key: str,
    hasher: TenantBootstrapSecretHasher,
) -> str:
    return hasher.digest(
        {
            "schema": "tenant-bootstrap-idempotency-storage-key/v1",
            "route": "POST /v1/tenant-bootstrap",
            "actor": actor,
            "invitation_id": invitation_id,
            "key": key,
        }
    )


def _require_strong_secret(token: str, *, code: str) -> None:
    status = (
        "bootstrap_not_authorized" if code == "BOOTSTRAP_NOT_AUTHORIZED" else "request_malformed"
    )
    try:
        raw = token.encode("ascii")
    except UnicodeEncodeError as exc:
        raise TenantBootstrapHttpError(
            403 if code == "BOOTSTRAP_NOT_AUTHORIZED" else 400,
            code,
            status,
            "platform bootstrap secret is not valid",
        ) from exc
    if len(raw) < 43:
        raise TenantBootstrapHttpError(
            403 if code == "BOOTSTRAP_NOT_AUTHORIZED" else 400,
            code,
            status,
            "platform bootstrap secret is not valid",
        )


def _require_platform_permission(principal: PlatformBootstrapPrincipal) -> None:
    if "tenant:bootstrap" not in principal.permissions:
        raise TenantBootstrapHttpError(
            403,
            "AUTHORIZATION_DENIED",
            "authorization_denied",
            "platform actor is not authorized for tenant bootstrap",
            stage="authz",
        )


def _require_invitation_role(platform_role: str | None) -> None:
    if platform_role != BOOTSTRAP_INVITEE_ROLE:
        raise TenantBootstrapHttpError(
            403,
            "BOOTSTRAP_NOT_AUTHORIZED",
            "bootstrap_not_authorized",
            "platform bootstrap invitation is not valid",
            stage="policy",
        )


def _require_idempotency_key(idempotency_key: str | None) -> str:
    if not idempotency_key or not _IDEMPOTENCY_RE.fullmatch(idempotency_key):
        raise TenantBootstrapHttpError(
            400,
            "IDEMPOTENCY_KEY_INVALID",
            "idempotency_key_invalid",
            "idempotency key must be 8-200 safe characters",
            stage="policy",
        )
    return idempotency_key


def _lookup_idempotency(
    session: Session, *, idempotency_key: str
) -> TenantBootstrapIdempotency | None:
    return session.scalars(
        sa.select(TenantBootstrapIdempotency)
        .where(TenantBootstrapIdempotency.idempotency_key == idempotency_key)
        .with_for_update()
    ).first()


def _lookup_idempotency_new_session(
    session_factory: sessionmaker[Session], *, idempotency_key: str
) -> TenantBootstrapIdempotency | None:
    with session_factory() as session:
        return _lookup_idempotency(session, idempotency_key=idempotency_key)


def _assert_same_request(
    row: TenantBootstrapIdempotency, request_projection: dict[str, Any]
) -> None:
    if row.request_hash != sha256_json(request_projection):
        raise TenantBootstrapHttpError(
            409,
            "IDEMPOTENCY_CONFLICT",
            "idempotency_conflict",
            "idempotency key was already used for a different tenant bootstrap request",
            stage="policy",
        )


def _locked_invitation(
    session: Session,
    *,
    token: str,
    hasher: TenantBootstrapSecretHasher,
) -> PlatformBootstrapInvitation | None:
    return session.scalars(
        sa.select(PlatformBootstrapInvitation)
        .where(PlatformBootstrapInvitation.token_hash == hash_invitation_token(token, hasher))
        .with_for_update()
    ).first()


def _context_and_args(
    invitation: PlatformBootstrapInvitation,
    body: TenantBootstrapRequest,
    actor: str,
    idempotency_key: str,
) -> tuple[ManagedMutationContext, dict[str, str]]:
    owner_user_id = sha256_json(
        {
            "schema": "tenant-bootstrap-owner-user-id/v1",
            "invitation_id": invitation.id,
            "idempotency_key": idempotency_key,
        }
    )[:32]
    args = {
        "display_name": body.display_name.strip(),
        "admin_name": body.admin_name.strip(),
        "admin_email_hash": sha256_json(str(body.admin_email).lower()),
        "org_id": invitation.prospective_org_id,
        "project_id": invitation.prospective_project_id,
        "environment_id": invitation.prospective_environment_id,
        "owner_user_id": owner_user_id,
        "owner_membership_id": invitation.prospective_membership_id,
        "idempotency_key_hash": sha256_json(idempotency_key),
        "invitation_id_hash": sha256_json(invitation.id),
    }
    context = ManagedMutationContext(
        org_id=invitation.prospective_org_id,
        project_id=invitation.prospective_project_id,
        environment_id=invitation.prospective_environment_id,
        actor=actor,
        action=TENANT_BOOTSTRAP_ACTION,
        execution_boundary=TENANT_BOOTSTRAP_EXECUTION_BOUNDARY,
        policy_bundle_id=TENANT_BOOTSTRAP_POLICY_BUNDLE_ID,
        policy_hash=TENANT_BOOTSTRAP_POLICY_HASH,
        validator_role=TENANT_BOOTSTRAP_VALIDATOR_ROLE,
        authority=TENANT_BOOTSTRAP_AUTHORITY,
    )
    return context, args


def _mint_receipt(
    *,
    issuer: ManagedPlatformIssuer,
    context: ManagedMutationContext,
    args: dict[str, str],
    decision: Decision,
    reason: str,
    request_id: str,
) -> tuple[DecisionReceipt, str]:
    record = DecisionRecord(
        decision=decision,
        tool=context.action,
        argument_hash=sha256_json(args),
        policy_version=TENANT_BOOTSTRAP_POLICY_VERSION,
        event_id=new_id(),
        matched_rules=("tenant-bootstrap-platform-invitation",),
        reason=reason,
        goal="tenant bootstrap",
        actor=context.actor,
        path=("control-plane", "tenant-bootstrap"),
        decision_request_hash=sha256_json(
            {
                "schema": "tenant-bootstrap-decision-request/v1",
                "actor": context.actor,
                "args": args,
            }
        ),
    )
    audit_event_hash = sha256_json(
        {
            "schema": "tenant-bootstrap-audit-event/v1",
            "previous_hash": _GENESIS_AUDIT_HASH,
            "record": record.to_dict(),
        }
    )
    try:
        receipt = mint_managed_decision_receipt_v2(
            issuer=issuer,
            context=cast(ManagedReceiptContext, context),
            record=record,
            audit_hash=audit_event_hash,
            previous_audit_hash=_GENESIS_AUDIT_HASH,
            trust_epoch=1,
            request_id=request_id,
            expires_at=(utcnow() + timedelta(minutes=10)).isoformat(),
            purpose=PLATFORM_BOOTSTRAP_RECEIPT_PURPOSE,
            constraints={"schema": "tenant-bootstrap-constraints/v1"},
            approval_chain_summary={},
        )
    except Exception as exc:
        raise TenantBootstrapHttpError(
            503,
            "SIGNER_UNAVAILABLE",
            "signer_unavailable",
            "tenant bootstrap signer unavailable",
            stage="issuance",
        ) from exc
    return receipt, audit_event_hash


def _insert_domain_rows(
    session: Session,
    *,
    invitation: PlatformBootstrapInvitation,
    body: TenantBootstrapRequest,
    args: dict[str, str],
    actor: str,
    owner_api_key_hash: str,
) -> None:
    org = Organization(id=invitation.prospective_org_id, name=body.display_name.strip())
    project = Project(
        id=invitation.prospective_project_id,
        org_id=org.id,
        slug="default",
        name="Default",
    )
    environment = Environment(
        id=invitation.prospective_environment_id,
        org_id=org.id,
        project_id=project.id,
        slug="production",
        name="Production",
    )
    user = User(
        id=args["owner_user_id"],
        org_id=org.id,
        name=body.admin_name.strip(),
        email=str(body.admin_email).lower(),
        role="org_admin",
        api_key_hash=owner_api_key_hash,
    )
    membership = OrganizationMembership(
        id=invitation.prospective_membership_id,
        org_id=org.id,
        user_id=user.id,
        role="owner",
    )
    session.add_all([org, project, environment, user])
    session.flush()
    session.add(membership)
    session.flush()


def _execute_bootstrap_effect(
    session: Session,
    *,
    invitation_token: str,
    secret_hasher: TenantBootstrapSecretHasher,
    body: TenantBootstrapRequest,
    args: dict[str, str],
    actor: str,
    context: ManagedMutationContext,
    one_time_secrets: dict[str, str],
) -> dict[str, str]:
    invitation = _locked_invitation(
        session,
        token=invitation_token,
        hasher=secret_hasher,
    )
    if invitation is None:
        raise TenantBootstrapHttpError(
            403,
            "BOOTSTRAP_NOT_AUTHORIZED",
            "bootstrap_not_authorized",
            "platform bootstrap invitation is not executable",
        )
    if invitation.invitee_actor != actor or invitation.policy_outcome != Decision.ALLOW.value:
        raise TenantBootstrapHttpError(
            403,
            "BOOTSTRAP_NOT_AUTHORIZED",
            "bootstrap_not_authorized",
            "platform bootstrap invitation changed before execution",
            invitation_id=invitation.id,
        )
    if (
        invitation.prospective_org_id != context.org_id
        or invitation.prospective_project_id != context.project_id
        or invitation.prospective_environment_id != context.environment_id
    ):
        raise BootstrapRefusalError(
            "ORG_MISMATCH",
            "platform bootstrap invitation scope changed before execution",
        )
    owner_api_key, owner_api_key_hash = generate_api_key()
    one_time_secrets["owner_api_key"] = owner_api_key
    _insert_domain_rows(
        session,
        invitation=invitation,
        body=body,
        args=args,
        actor=actor,
        owner_api_key_hash=owner_api_key_hash,
    )
    invitation.consumed_at = utcnow()
    invitation.consumed_org_id = context.org_id
    session.flush()
    return {
        "org_id": context.org_id,
        "project_id": context.project_id,
        "environment_id": context.environment_id,
        "owner_user_id": args["owner_user_id"],
        "owner_membership_id": args["owner_membership_id"],
    }


def _request_projection(body: TenantBootstrapRequest, *, actor: str) -> dict[str, Any]:
    return {
        "schema": "tenant-bootstrap-request/v1",
        "actor": actor,
        "display_name": body.display_name.strip(),
        "admin_name": body.admin_name.strip(),
        "admin_email_hash": sha256_json(str(body.admin_email).lower()),
    }


def _canonical_json_bytes(payload: Any) -> bytes:
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _optional_secret_digest(
    hasher: TenantBootstrapSecretHasher,
    label: str,
    value: str | None,
) -> str | None:
    if not value or " " in value:
        return None
    try:
        return hasher.digest(
            {
                "schema": f"tenant-bootstrap-{label}-refusal-digest/v1",
                "value": value,
            }
        )
    except Exception:
        return None


def _to_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _verify_bootstrap_receipt(
    *,
    receipt: object,
    context: ManagedMutationContext,
    args: dict[str, str],
    trust_registry: ReceiptTrustRegistry,
    allow_policy_outcome_refusal: bool,
) -> None:
    if not isinstance(receipt, DecisionReceipt):
        raise BootstrapRefusalError("RECEIPT_MALFORMED", "receipt is not a DecisionReceipt")
    try:
        receipt.verify(
            expected_tenant_id=context.org_id,
            expected_execution_boundary=context.execution_boundary,
            expected_action=context.action,
            expected_actor=context.actor,
            expected_audit_hash=context.expected_audit_hash,
            expected_args=args,
            expected_policy_hash=context.policy_hash,
            expected_policy_bundle_id=context.policy_bundle_id,
            expected_project_id=context.project_id,
            expected_environment_id=context.environment_id,
            expected_validator_role=context.validator_role,
            expected_authority=context.authority,
            verifier=None,
            require_signature=True,
            require_expiry=True,
            trust_registry=trust_registry,
            trust_purpose=PLATFORM_BOOTSTRAP_RECEIPT_PURPOSE,
        )
    except ReceiptValidationError as exc:
        if exc.reason_code == ReceiptRejectionReason.SCOPED_TRUST_MISMATCH:
            if receipt.tenant_id != context.org_id:
                raise _executor_refusal("ORG_MISMATCH", exc) from exc
            if receipt.project_id != context.project_id:
                raise _executor_refusal("PROJECT_MISMATCH", exc) from exc
            if receipt.environment_id != context.environment_id:
                raise _executor_refusal("ENV_MISMATCH", exc) from exc
            _precheck_bootstrap_trust(
                receipt=receipt,
                context=context,
                trust_registry=trust_registry,
            )
        if allow_policy_outcome_refusal and exc.reason_code in (
            ReceiptRejectionReason.DENIED_RECEIPT,
            ReceiptRejectionReason.ESCALATED_RECEIPT,
        ):
            return
        raise _map_executor_refusal(exc) from exc
    except TrustConfigurationError as exc:
        raise _map_executor_refusal(exc) from exc


def _precheck_bootstrap_trust(
    *,
    receipt: DecisionReceipt,
    context: ManagedMutationContext,
    trust_registry: ReceiptTrustRegistry,
) -> None:
    try:
        trusted_key = trust_registry.resolve(
            scope=ReceiptTrustScope(
                tenant_id=context.org_id,
                project_id=context.project_id,
                environment_id=context.environment_id,
                purpose=PLATFORM_BOOTSTRAP_RECEIPT_PURPOSE,
            ),
            trust_epoch=receipt.trust_epoch,
            algorithm=receipt.signature_algorithm,
            key_id=receipt.signing_key_id,
            now_iso=utcnow().isoformat(),
            mode="execution",
        )
        trusted_key.validate()
        if trusted_key.status == "revoked":
            raise BootstrapKeyRevoked("tenant bootstrap platform key revoked")
        if trusted_key.status != "active":
            raise BootstrapKeyUntrusted("tenant bootstrap platform key is not trusted")
        if not trusted_key.is_live_at(utcnow().isoformat()):
            raise BootstrapKeyUntrusted("tenant bootstrap platform key is not trusted")
    except TrustConfigurationError as exc:
        raise _map_executor_refusal(exc) from exc


def _verify_signed_policy_outcome(
    *,
    receipt: DecisionReceipt,
    context: ManagedMutationContext,
    args: dict[str, str],
    trust_registry: ReceiptTrustRegistry,
) -> None:
    _verify_bootstrap_receipt(
        receipt=receipt,
        context=context,
        args=args,
        trust_registry=trust_registry,
        allow_policy_outcome_refusal=True,
    )


def _reject_replayed_bootstrap_receipt(
    session_factory: sessionmaker[Session],
    *,
    receipt: DecisionReceipt,
    context: ManagedMutationContext,
) -> None:
    with session_factory() as session:
        existing = session.scalars(
            sa.select(ManagedDecisionReceipt)
            .where(
                ManagedDecisionReceipt.org_id == context.org_id,
                ManagedDecisionReceipt.project_id == context.project_id,
                ManagedDecisionReceipt.environment_id == context.environment_id,
                sa.or_(
                    ManagedDecisionReceipt.receipt_hash == receipt.receipt_hash,
                    ManagedDecisionReceipt.audit_event_hash == receipt.audit_event_hash,
                ),
            )
            .with_for_update()
        ).first()
        if existing is not None:
            consumption = session.scalars(
                sa.select(ManagedReceiptConsumption)
                .where(
                    ManagedReceiptConsumption.org_id == context.org_id,
                    ManagedReceiptConsumption.project_id == context.project_id,
                    ManagedReceiptConsumption.environment_id == context.environment_id,
                    ManagedReceiptConsumption.audit_event_hash == receipt.audit_event_hash,
                )
                .with_for_update()
            ).first()
            if consumption is not None:
                raise ReceiptAlreadyUsedError(receipt.audit_event_hash, "managed-sql-ledger")
            raise ReceiptAlreadyUsedError(receipt.audit_event_hash, "managed-receipt-projection")


def _executor_refusal(code: str, exc: BaseException) -> TenantBootstrapHttpError:
    if code == "TX_ABORTED" or code == "TRUST_PROVIDER_UNAVAILABLE":
        status_code = 503
        status = "tx_aborted" if code == "TX_ABORTED" else "receipt_refused"
    elif code in ("IDEMPOTENCY_CONFLICT", "REPLAYED", "CONSUMED"):
        status_code = 409
        status = "idempotency_conflict" if code == "IDEMPOTENCY_CONFLICT" else "receipt_refused"
    elif code in (
        "RECEIPT_MISSING",
        "RECEIPT_MALFORMED",
        "RECEIPT_VERSION_UNSUPPORTED",
        "RECEIPT_FIELD_MISSING",
    ):
        status_code = 400
        status = "receipt_refused"
    else:
        status_code = 403
        status = "receipt_refused"
    stage = "tx" if code == "TX_ABORTED" else "executor"
    return TenantBootstrapHttpError(status_code, code, status, str(exc) or code, stage=stage)


_REJECTION_REASON_TO_CODE = {
    ReceiptRejectionReason.MISSING_REQUIRED_FIELD: "RECEIPT_FIELD_MISSING",
    ReceiptRejectionReason.RECEIPT_HASH_MISSING: "RECEIPT_FIELD_MISSING",
    ReceiptRejectionReason.RECEIPT_HASH_MISMATCH: "SIGNATURE_INVALID",
    ReceiptRejectionReason.RECEIPT_SCHEMA_MISMATCH: "RECEIPT_VERSION_UNSUPPORTED",
    ReceiptRejectionReason.SCOPED_TRUST_REQUIRED: "KEY_UNTRUSTED",
    ReceiptRejectionReason.SCOPED_TRUST_MISMATCH: "KEY_UNTRUSTED",
    ReceiptRejectionReason.UNSIGNED_REJECTED: "SIGNATURE_INVALID",
    ReceiptRejectionReason.SIGNING_KEY_UNKNOWN: "KEY_UNTRUSTED",
    ReceiptRejectionReason.SIGNING_KEY_REVOKED: "KEY_REVOKED",
    ReceiptRejectionReason.SIGNED_RECEIPT_NO_VERIFIER: "KEY_UNTRUSTED",
    ReceiptRejectionReason.SIGNATURE_ALG_MISMATCH: "SIGNATURE_INVALID",
    ReceiptRejectionReason.SIGNATURE_INVALID: "SIGNATURE_INVALID",
    ReceiptRejectionReason.ACTOR_MISMATCH: "ACTOR_MISMATCH",
    ReceiptRejectionReason.SELF_VALIDATION: "VALIDATOR_MISMATCH",
    ReceiptRejectionReason.APPROVAL_CHAIN_DIVERGENCE: "VALIDATOR_MISMATCH",
    ReceiptRejectionReason.UNKNOWN_DECISION: "DECISION_NOT_ALLOW",
    ReceiptRejectionReason.DENIED_RECEIPT: "DECISION_NOT_ALLOW",
    ReceiptRejectionReason.ESCALATED_RECEIPT: "DECISION_NOT_ALLOW",
    ReceiptRejectionReason.TENANT_MISMATCH: "ORG_MISMATCH",
    ReceiptRejectionReason.EXECUTION_BOUNDARY_MISMATCH: "EXECUTION_BOUNDARY_MISMATCH",
    ReceiptRejectionReason.ACTION_MISMATCH: "ACTION_MISMATCH",
    ReceiptRejectionReason.AUDIT_HASH_MISMATCH: "AUDIT_ANCHOR_MISMATCH",
    ReceiptRejectionReason.TRANSFORMATIONS_MALFORMED: "RECEIPT_MALFORMED",
    ReceiptRejectionReason.TRANSFORM_MISMATCH: "ARGUMENTS_MISMATCH",
    ReceiptRejectionReason.ARGUMENT_MISMATCH: "ARGUMENTS_MISMATCH",
    ReceiptRejectionReason.POLICY_HASH_MISMATCH: "POLICY_MISMATCH",
    ReceiptRejectionReason.POLICY_BUNDLE_MISMATCH: "POLICY_MISMATCH",
    ReceiptRejectionReason.VALIDATOR_ROLE_MISMATCH: "VALIDATOR_MISMATCH",
    ReceiptRejectionReason.AUTHORITY_MISMATCH: "AUTHORITY_MISMATCH",
    ReceiptRejectionReason.EXPIRY_UNPARSEABLE: "RECEIPT_MALFORMED",
    ReceiptRejectionReason.RECEIPT_EXPIRED: "EXPIRED",
    ReceiptRejectionReason.EXPIRY_REQUIRED: "RECEIPT_FIELD_MISSING",
    ReceiptRejectionReason.PRODUCTION_PROFILE_NO_VERIFIER: "KEY_UNTRUSTED",
    ReceiptRejectionReason.RECEIPT_ALREADY_USED: "CONSUMED",
    ReceiptRejectionReason.CONSUMPTION_LEDGER_UNPROVABLE: "CONSUMED",
    ReceiptRejectionReason.AUTHORITY_VIOLATION: "AUTHORITY_MISMATCH",
}


def _map_executor_refusal(exc: BaseException) -> TenantBootstrapHttpError:
    if isinstance(exc, BootstrapRefusalError):
        return _executor_refusal(exc.code, exc)
    if isinstance(exc, BootstrapTrustUnavailable):
        return _executor_refusal("TRUST_PROVIDER_UNAVAILABLE", exc)
    if isinstance(exc, BootstrapKeyRevoked):
        return _executor_refusal("KEY_REVOKED", exc)
    if isinstance(exc, (BootstrapKeyUntrusted, TrustConfigurationError)):
        return _executor_refusal("KEY_UNTRUSTED", exc)
    if isinstance(exc, ReceiptValidationError):
        mapped = _REJECTION_REASON_TO_CODE.get(exc.reason_code)
        if mapped is not None:
            return _executor_refusal(mapped, exc)
    return _executor_refusal("RECEIPT_MALFORMED", exc)


def _receipt_already_used_code(exc: ReceiptAlreadyUsedError) -> str:
    ledger_path = str(getattr(exc, "ledger_path", "") or "")
    if ledger_path == "managed-sql-ledger":
        return "CONSUMED"
    return "REPLAYED"
