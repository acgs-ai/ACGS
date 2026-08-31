"""Environment-scoped managed policy registry service."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any, Protocol, cast

import sqlalchemy as sa
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import ReceiptAlreadyUsedError, ReceiptValidationError
from gove_zone.policy import RuleSetPolicy
from gove_zone.receipt import DecisionReceipt
from gove_zone.signing import Ed25519Signer
from gove_zone.tool import ToolCall
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, ReceiptTrustScope, TrustConfigurationError
from sqlalchemy.exc import IntegrityError, MultipleResultsFound, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from acgs_control_plane.auth import Principal
from acgs_control_plane.managed_mutations import (
    CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
    CONTROL_PLANE_POLICY_PUBLISH_ACTION,
    AesGcmReceiptArtifactSealer,
    ManagedMutationContext,
    ManagedMutationResult,
    ManagedMutationUnitOfWork,
    ManagedNonExecutableEvidenceResult,
    managed_mutation_execution_boundary,
)
from acgs_control_plane.models import (
    Environment,
    EnvironmentPolicyHead,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedOutboxMessage,
    PolicyBundle,
    PolicyRegistryIdempotency,
    PolicyVersion,
    Project,
    new_id,
    utcnow,
)
from acgs_control_plane.schemas import PolicyActivateRequest, PolicyPublishRequest
from acgs_control_plane.trust import (
    InProcessPlatformIssuer,
    ManagedPlatformIssuer,
    ManagedReceiptContext,
    ManagedTrustError,
    SqlReceiptTrustRegistry,
    active_trust_epoch_for_scope,
    mint_managed_decision_receipt_v2,
    public_spki_der_from_signer,
)

POLICY_ENVELOPE_PURPOSE = "acgs.policy-envelope/v1"
POLICY_REGISTRY_AUTHORITY = "control-plane.policy-registry/v1"
POLICY_REGISTRY_VALIDATOR_ROLE = "control-plane.policy-policy/v1"
LEGACY_POLICY_PUBLISH_ACTION = "policy.publish"
LEGACY_POLICY_ACTIVATE_ACTION = "policy.activate"
_GENESIS_AUDIT_HASH = "0" * 64
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9._:/-]{8,200}$")
_LOCAL_POLICY_SIGNER_SEED = bytes.fromhex(
    "3fd0c33d26a22c4db9b3dbe27e4a556909769a0e0fef4e9e84543e25af7c51f8"
)
_LOCAL_POLICY_SEALER_SEED = b"acgs-control-plane-local-policy-registry-sealer"


@dataclass
class PolicyRegistryHttpError(RuntimeError):
    status_code: int
    code: str
    status: str
    detail: str
    stage: str = "policy"


@dataclass(frozen=True)
class PolicyRegistryResult:
    bundle_id: str
    org_id: str
    project_id: str
    environment_id: str
    policy_id: str
    version: str
    status: str
    rules: list[dict[str, Any]]
    created_at: Any
    activated_at: Any | None
    receipt_id: str
    generation: int | None
    content_hash: str
    key_id: str
    signature_algorithm: str
    trust_epoch: int


class PolicyRegistryReceiptIssuer(Protocol):
    def issue(
        self,
        *,
        context: ManagedMutationContext,
        args: dict[str, Any],
        decision_record: DecisionRecord,
        audit_hash: str,
        request_id: str,
        trust_epoch: int,
    ) -> DecisionReceipt: ...


@dataclass(frozen=True)
class DefaultPolicyRegistryReceiptIssuer:
    issuer: ManagedPlatformIssuer

    def issue(
        self,
        *,
        context: ManagedMutationContext,
        args: dict[str, Any],
        decision_record: DecisionRecord,
        audit_hash: str,
        request_id: str,
        trust_epoch: int,
    ) -> DecisionReceipt:
        del args
        return mint_managed_decision_receipt_v2(
            issuer=self.issuer,
            context=cast(ManagedReceiptContext, context),
            record=decision_record,
            audit_hash=audit_hash,
            previous_audit_hash=_GENESIS_AUDIT_HASH,
            trust_epoch=trust_epoch,
            request_id=request_id,
            expires_at=(utcnow() + timedelta(minutes=10)).isoformat(),
            purpose=DECISION_RECEIPT_PURPOSE,
            constraints={"schema": "policy-registry-constraints/v1"},
            approval_chain_summary={},
        )


@dataclass(frozen=True)
class PolicyRegistryProviders:
    issuer: ManagedPlatformIssuer
    receipt_sealer: AesGcmReceiptArtifactSealer
    receipt_issuer: PolicyRegistryReceiptIssuer


def local_policy_registry_issuer() -> InProcessPlatformIssuer:
    """Deterministic local/test issuer; production must inject real custody."""

    return InProcessPlatformIssuer(
        Ed25519Signer.from_private_bytes(
            _LOCAL_POLICY_SIGNER_SEED,
            key_id="local-control-plane-policy-registry",
        ),
        allowed_purposes=frozenset({DECISION_RECEIPT_PURPOSE, POLICY_ENVELOPE_PURPOSE}),
    )


def local_policy_registry_receipt_sealer() -> AesGcmReceiptArtifactSealer:
    """Deterministic local/test receipt sealer; production must inject KMS storage."""

    return AesGcmReceiptArtifactSealer(
        key_id="local-control-plane-policy-registry-sealer",
        key=hashlib.sha256(_LOCAL_POLICY_SEALER_SEED).digest(),
    )


class PolicyRegistryService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        issuer: ManagedPlatformIssuer,
        receipt_sealer: AesGcmReceiptArtifactSealer,
        receipt_issuer: PolicyRegistryReceiptIssuer | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._providers = PolicyRegistryProviders(
            issuer=issuer,
            receipt_sealer=receipt_sealer,
            receipt_issuer=receipt_issuer or DefaultPolicyRegistryReceiptIssuer(issuer),
        )

    @property
    def issuer(self) -> ManagedPlatformIssuer:
        return self._providers.issuer

    def publish(
        self,
        *,
        org_id: str,
        project_id: str,
        environment_id: str,
        principal: Principal,
        body: PolicyPublishRequest,
        idempotency_key: str | None,
    ) -> PolicyRegistryResult:
        idempotency_key = _normalize_idempotency_key(idempotency_key)
        parsed = _parse_policy(body)
        request_args: dict[str, Any] = {"policy_id": body.policy_id, "rules": parsed["rules"]}
        idem = _idempotency_context(
            org_id=org_id,
            project_id=project_id,
            environment_id=environment_id,
            actor=principal.actor_id,
            action=CONTROL_PLANE_POLICY_PUBLISH_ACTION,
            key=idempotency_key,
            args=request_args,
        )
        with self._session_factory() as session:
            existing = _lookup_idempotency(session, idem.storage_key)
            if existing is not None:
                return _replay_result(existing, idem)
            _resolve_scope(
                session, org_id=org_id, project_id=project_id, environment_id=environment_id
            )
            receipt_epoch = active_trust_epoch_for_scope(
                session,
                ReceiptTrustScope(org_id, project_id, environment_id, DECISION_RECEIPT_PURPOSE),
            )
            envelope_epoch = active_trust_epoch_for_scope(
                session,
                ReceiptTrustScope(org_id, project_id, environment_id, POLICY_ENVELOPE_PURPOSE),
            )
            envelope = _signed_envelope(
                issuer=self._providers.issuer,
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                policy_id=body.policy_id,
                document=parsed,
                trust_epoch=envelope_epoch,
            )
            _verify_envelope(
                session,
                envelope,
                expected_org_id=org_id,
                expected_project_id=project_id,
                expected_environment_id=environment_id,
                expected_policy_id=body.policy_id,
                expected_version=parsed["version"],
                expected_document=parsed,
            )
            operation_args = {
                "policy_id": body.policy_id,
                "version": parsed["version"],
                "content_hash": envelope["content_hash"],
                "canonical_envelope": envelope,
            }
            authz = _authorizing_policy_context(
                session,
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                actor=principal.actor_id,
                action=CONTROL_PLANE_POLICY_PUBLISH_ACTION,
                args=operation_args,
            )
            context, args = _context_and_args(
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                actor=principal.actor_id,
                action=CONTROL_PLANE_POLICY_PUBLISH_ACTION,
                policy_bundle_id=authz.policy_bundle_id,
                policy_hash=authz.policy_hash,
                args=operation_args,
            )
            decision_record = authz.decision_record
            audit_hash = sha256_json(decision_record.to_dict())
            context = replace(context, expected_audit_hash=audit_hash)
            receipt = self._issue_receipt(
                context, args, decision_record, audit_hash, idempotency_key, receipt_epoch
            )

        holder: dict[str, PolicyRegistryResult] = {}
        uow = ManagedMutationUnitOfWork(
            self._session_factory,
            receipt_sealer=self._providers.receipt_sealer,
        )

        def before_execute(tx_session: Session) -> None:
            _resolve_scope(
                tx_session,
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                lock=True,
            )
            _verify_envelope(
                tx_session,
                envelope,
                expected_org_id=org_id,
                expected_project_id=project_id,
                expected_environment_id=environment_id,
                expected_policy_id=body.policy_id,
                expected_version=parsed["version"],
                expected_document=parsed,
            )
            locked_authz = _authorizing_policy_context(
                tx_session,
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                actor=principal.actor_id,
                action=CONTROL_PLANE_POLICY_PUBLISH_ACTION,
                args=args,
                lock=True,
            )
            if (
                locked_authz.policy_bundle_id != context.policy_bundle_id
                or locked_authz.policy_hash != context.policy_hash
                or locked_authz.decision_record.decision is not decision_record.decision
            ):
                raise ReceiptValidationError("policy publish authorizing policy changed")
            existing = _lookup_idempotency(tx_session, idem.storage_key)
            if existing is not None:
                _assert_same_request(existing, idem)
                raise _CommittedPolicyIdempotencyRace()

        def operation_effect(session: Session, verified_args: dict[str, Any]) -> dict[str, Any]:
            del verified_args
            version = PolicyVersion(
                id=new_id(),
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                policy_id=body.policy_id,
                version=parsed["version"],
                content_hash=envelope["content_hash"],
                document=parsed,
                rules=list(parsed["rules"]),
                canonical_envelope=envelope,
                purpose=POLICY_ENVELOPE_PURPOSE,
                key_id=str(envelope["key_id"]),
                signature_algorithm=str(envelope["signature_algorithm"]),
                signature=str(envelope["signature"]),
                trust_epoch=int(envelope["trust_epoch"]),
                receipt_id=receipt.receipt_id,
            )
            session.add(version)
            session.flush()
            return {"policy_version_id": version.id, "content_hash": version.content_hash}

        def after_success(
            session: Session,
            receipt_row: ManagedDecisionReceipt,
            _event: ManagedGovernanceEvent,
            _outbox: ManagedOutboxMessage,
            result: ManagedMutationResult,
        ) -> None:
            version = session.get(PolicyVersion, result.result["policy_version_id"])
            if version is None:
                raise RuntimeError("policy version was not committed")
            response = _result_from_version(version, receipt_id=receipt_row.receipt_id)
            session.add(
                _idempotency_row(
                    idem, context=context, receipt_id=receipt_row.receipt_id, response=response
                )
            )
            holder["response"] = response

        try:
            if decision_record.decision is Decision.ALLOW:
                uow.execute(
                    context=context,
                    receipt=receipt,
                    args=args,
                    before_execute=before_execute,
                    operation_effect=operation_effect,
                    after_success=after_success,
                )
            else:
                self._record_non_executable(
                    uow=uow,
                    context=context,
                    receipt=receipt,
                    args=args,
                    idem=idem,
                    decision_record=decision_record,
                    before_record=before_execute,
                )
        except _CommittedPolicyIdempotencyRace:
            existing = _lookup_idempotency_new_session(self._session_factory, idem)
            if existing is not None:
                return _replay_result(existing, idem)
            raise _tx_aborted("policy publish idempotency commit was not observable") from None
        except IntegrityError as exc:
            existing = _lookup_idempotency_new_session(self._session_factory, idem)
            if existing is not None:
                return _replay_result(existing, idem)
            raise _tx_aborted("policy publish transaction aborted") from exc
        except (
            ReceiptAlreadyUsedError,
            ReceiptValidationError,
            TrustConfigurationError,
            ManagedTrustError,
        ) as exc:
            raise PolicyRegistryHttpError(
                503,
                "RECEIPT_REFUSED",
                "receipt_refused",
                "policy publish receipt was refused",
                stage="executor",
            ) from exc
        except (SQLAlchemyError, ValueError, RuntimeError) as exc:
            existing = _lookup_idempotency_new_session(self._session_factory, idem)
            if existing is not None:
                return _replay_result(existing, idem)
            raise _tx_aborted("policy publish transaction aborted") from exc
        if "response" not in holder:
            raise _tx_aborted("policy publish did not return a response")
        return holder["response"]

    def activate(
        self,
        *,
        org_id: str,
        project_id: str,
        environment_id: str,
        policy_version_id: str,
        principal: Principal,
        body: PolicyActivateRequest,
        idempotency_key: str | None,
    ) -> PolicyRegistryResult:
        idempotency_key = _normalize_idempotency_key(idempotency_key)
        request_args = {
            "policy_version_id": policy_version_id,
            "expected_generation": body.expected_generation,
        }
        idem = _idempotency_context(
            org_id=org_id,
            project_id=project_id,
            environment_id=environment_id,
            actor=principal.actor_id,
            action=CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
            key=idempotency_key,
            args=request_args,
        )
        with self._session_factory() as session:
            existing = _lookup_idempotency(session, idem.storage_key)
            if existing is not None:
                return _replay_result(existing, idem)
            _resolve_scope(
                session, org_id=org_id, project_id=project_id, environment_id=environment_id
            )
            version = _get_version(session, org_id, project_id, environment_id, policy_version_id)
            _verify_envelope(
                session,
                version.canonical_envelope,
                expected_org_id=org_id,
                expected_project_id=project_id,
                expected_environment_id=environment_id,
                expected_policy_id=version.policy_id,
                expected_version=version.version,
                expected_document=version.document,
            )
            current_head = _head(session, org_id, project_id, environment_id, lock=False)
            current_generation = current_head.generation if current_head is not None else 0
            if current_generation != body.expected_generation:
                raise _stale_generation()
            receipt_epoch = active_trust_epoch_for_scope(
                session,
                ReceiptTrustScope(org_id, project_id, environment_id, DECISION_RECEIPT_PURPOSE),
            )
            authz = _authorizing_policy_context(
                session,
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                actor=principal.actor_id,
                action=CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
                args=request_args,
            )
            context, args = _context_and_args(
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                actor=principal.actor_id,
                action=CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
                policy_bundle_id=authz.policy_bundle_id,
                policy_hash=authz.policy_hash,
                args=request_args,
            )
            decision_record = authz.decision_record
            audit_hash = sha256_json(decision_record.to_dict())
            context = replace(context, expected_audit_hash=audit_hash)
            receipt = self._issue_receipt(
                context, args, decision_record, audit_hash, idempotency_key, receipt_epoch
            )

        holder: dict[str, PolicyRegistryResult] = {}
        uow = ManagedMutationUnitOfWork(
            self._session_factory,
            receipt_sealer=self._providers.receipt_sealer,
        )

        def before_execute(tx_session: Session) -> None:
            _resolve_scope(
                tx_session,
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                lock=True,
            )
            locked_version = _get_version(
                tx_session, org_id, project_id, environment_id, policy_version_id, lock=True
            )
            _verify_envelope(
                tx_session,
                locked_version.canonical_envelope,
                expected_org_id=org_id,
                expected_project_id=project_id,
                expected_environment_id=environment_id,
                expected_policy_id=locked_version.policy_id,
                expected_version=locked_version.version,
                expected_document=locked_version.document,
            )
            locked_head = _head(tx_session, org_id, project_id, environment_id, lock=True)
            locked_generation = locked_head.generation if locked_head is not None else 0
            if locked_generation != body.expected_generation:
                raise _StalePolicyGeneration()
            locked_authz = _authorizing_policy_context(
                tx_session,
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                actor=principal.actor_id,
                action=CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
                args=args,
                lock=True,
            )
            if (
                locked_authz.policy_bundle_id != context.policy_bundle_id
                or locked_authz.policy_hash != context.policy_hash
                or locked_authz.decision_record.decision is not decision_record.decision
            ):
                raise ReceiptValidationError("policy activate authorizing policy changed")
            existing = _lookup_idempotency(tx_session, idem.storage_key)
            if existing is not None:
                _assert_same_request(existing, idem)
                raise _CommittedPolicyIdempotencyRace()

        def operation_effect(session: Session, verified_args: dict[str, Any]) -> dict[str, Any]:
            del verified_args
            version = _get_version(session, org_id, project_id, environment_id, policy_version_id)
            head = _head(session, org_id, project_id, environment_id, lock=True)
            now = utcnow()
            if head is None:
                head = EnvironmentPolicyHead(
                    id=new_id(),
                    org_id=org_id,
                    project_id=project_id,
                    environment_id=environment_id,
                    active_policy_version_id=version.id,
                    generation=1,
                    status="active",
                    receipt_id=receipt.receipt_id,
                    created_at=now,
                    updated_at=now,
                )
                session.add(head)
            else:
                head.active_policy_version_id = version.id
                head.generation += 1
                head.receipt_id = receipt.receipt_id
                head.updated_at = now
            session.flush()
            return {"policy_version_id": version.id, "generation": head.generation}

        def after_success(
            session: Session,
            receipt_row: ManagedDecisionReceipt,
            _event: ManagedGovernanceEvent,
            _outbox: ManagedOutboxMessage,
            result: ManagedMutationResult,
        ) -> None:
            version = _get_version(
                session, org_id, project_id, environment_id, result.result["policy_version_id"]
            )
            response = _result_from_version(
                version,
                receipt_id=receipt_row.receipt_id,
                generation=int(result.result["generation"]),
                activated_at=utcnow(),
            )
            session.add(
                _idempotency_row(
                    idem, context=context, receipt_id=receipt_row.receipt_id, response=response
                )
            )
            holder["response"] = response

        try:
            if decision_record.decision is Decision.ALLOW:
                uow.execute(
                    context=context,
                    receipt=receipt,
                    args=args,
                    before_execute=before_execute,
                    operation_effect=operation_effect,
                    after_success=after_success,
                )
            else:
                self._record_non_executable(
                    uow=uow,
                    context=context,
                    receipt=receipt,
                    args=args,
                    idem=idem,
                    decision_record=decision_record,
                    before_record=before_execute,
                )
        except _StalePolicyGeneration as exc:
            raise _stale_generation() from exc
        except _CommittedPolicyIdempotencyRace:
            existing = _lookup_idempotency_new_session(self._session_factory, idem)
            if existing is not None:
                return _replay_result(existing, idem)
            raise _tx_aborted("policy activate idempotency commit was not observable") from None
        except (
            ReceiptAlreadyUsedError,
            ReceiptValidationError,
            TrustConfigurationError,
            ManagedTrustError,
        ) as exc:
            raise PolicyRegistryHttpError(
                503,
                "RECEIPT_REFUSED",
                "receipt_refused",
                "policy activate receipt was refused",
                stage="executor",
            ) from exc
        except (SQLAlchemyError, ValueError, RuntimeError) as exc:
            existing = _lookup_idempotency_new_session(self._session_factory, idem)
            if existing is not None:
                return _replay_result(existing, idem)
            raise _tx_aborted("policy activate transaction aborted") from exc
        if "response" not in holder:
            raise _tx_aborted("policy activate did not return a response")
        return holder["response"]

    def _record_non_executable(
        self,
        *,
        uow: ManagedMutationUnitOfWork,
        context: ManagedMutationContext,
        receipt: DecisionReceipt,
        args: Mapping[str, Any],
        idem: _PolicyIdempotencyContext,
        decision_record: DecisionRecord,
        before_record: Callable[[Session], None],
    ) -> None:
        error = _terminal_policy_error(decision_record.decision)

        def after_record(
            session: Session,
            receipt_row: ManagedDecisionReceipt,
            _event: ManagedGovernanceEvent,
            _outbox: ManagedOutboxMessage,
            _result: ManagedNonExecutableEvidenceResult,
        ) -> None:
            session.add(
                _idempotency_row(
                    idem,
                    context=context,
                    receipt_id=receipt_row.receipt_id,
                    response=_error_payload(error),
                )
            )

        uow.record_non_executable_evidence(
            context=context,
            receipt=receipt,
            args=args,
            before_record=before_record,
            after_record=after_record,
        )
        raise error

    def _issue_receipt(
        self,
        context: ManagedMutationContext,
        args: dict[str, Any],
        decision_record: DecisionRecord,
        audit_hash: str,
        request_id: str,
        trust_epoch: int,
    ) -> DecisionReceipt:
        try:
            receipt = self._providers.receipt_issuer.issue(
                context=context,
                args=args,
                decision_record=decision_record,
                audit_hash=audit_hash,
                request_id=request_id,
                trust_epoch=trust_epoch,
            )
        except (TrustConfigurationError, ManagedTrustError) as exc:
            raise PolicyRegistryHttpError(
                503,
                "RECEIPT_REFUSED",
                "receipt_refused",
                "policy registry receipt was refused",
                stage="issuance",
            ) from exc
        if not isinstance(receipt, DecisionReceipt):
            raise PolicyRegistryHttpError(
                503,
                "RECEIPT_REFUSED",
                "receipt_refused",
                "policy registry receipt was malformed",
                stage="issuance",
            )
        return receipt


@dataclass(frozen=True)
class _PolicyIdempotencyContext:
    raw_key: str
    storage_key: str
    request_projection: dict[str, Any]
    request_hash: str


@dataclass(frozen=True)
class _AuthorizingPolicyContext:
    policy: RuleSetPolicy | None
    policy_bundle_id: str
    policy_hash: str
    decision_record: DecisionRecord


class _CommittedPolicyIdempotencyRace(RuntimeError):
    pass


class _StalePolicyGeneration(RuntimeError):
    pass


def _normalize_idempotency_key(key: str | None) -> str:
    if key is None:
        raise PolicyRegistryHttpError(
            400,
            "IDEMPOTENCY_KEY_REQUIRED",
            "idempotency_key_required",
            "idempotency key is required for managed policy registry",
            stage="policy",
        )
    if not _IDEMPOTENCY_RE.fullmatch(key):
        raise PolicyRegistryHttpError(
            400,
            "IDEMPOTENCY_KEY_INVALID",
            "idempotency_key_invalid",
            "idempotency key must be 8-200 safe characters",
            stage="policy",
        )
    return key


def _parse_policy(body: PolicyPublishRequest) -> dict[str, Any]:
    document = {"id": body.policy_id, "rules": _strict_json_round_trip(body.rules)}
    try:
        parsed = RuleSetPolicy.from_dict(document)
    except (ValueError, TypeError) as exc:
        raise PolicyRegistryHttpError(
            422,
            "POLICY_INVALID",
            "policy_invalid",
            "policy bundle is invalid",
        ) from exc
    return {"id": parsed.policy_id, "version": parsed.version, "rules": list(document["rules"])}


def _strict_json_round_trip(value: Any) -> Any:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise PolicyRegistryHttpError(
            422,
            "POLICY_INVALID_JSON",
            "policy_invalid_json",
            "policy JSON must be finite and canonical JSON encodable",
        ) from exc


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _signed_envelope(
    *,
    issuer: ManagedPlatformIssuer,
    org_id: str,
    project_id: str,
    environment_id: str,
    policy_id: str,
    document: dict[str, Any],
    trust_epoch: int,
) -> dict[str, Any]:
    scope = ReceiptTrustScope(org_id, project_id, environment_id, POLICY_ENVELOPE_PURPOSE)
    signer = issuer.signer_for_scope(scope, trust_epoch=trust_epoch)
    body = {
        "schema": "acgs.policy-registry.envelope/v1",
        "scope": {"org_id": org_id, "project_id": project_id, "environment_id": environment_id},
        "policy_id": policy_id,
        "version": document["version"],
        "content_hash": sha256_json(document),
        "document": document,
        "rules": list(document["rules"]),
        "key_id": signer.key_id,
        "signature_algorithm": signer.algorithm,
        "trust_epoch": trust_epoch,
        "purpose": POLICY_ENVELOPE_PURPOSE,
    }
    return {**body, "signature": signer.sign(_canonical_bytes(body))}


def _verify_envelope(
    session: Session,
    envelope: Mapping[str, Any],
    *,
    expected_org_id: str | None = None,
    expected_project_id: str | None = None,
    expected_environment_id: str | None = None,
    expected_policy_id: str | None = None,
    expected_version: str | None = None,
    expected_document: Mapping[str, Any] | None = None,
) -> None:
    required = {
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
    if set(envelope) != required:
        raise PolicyRegistryHttpError(
            503,
            "POLICY_SIGNATURE_REFUSED",
            "signature_refused",
            "policy envelope has unexpected fields",
        )
    if (
        envelope["schema"] != "acgs.policy-registry.envelope/v1"
        or envelope["purpose"] != POLICY_ENVELOPE_PURPOSE
    ):
        raise PolicyRegistryHttpError(
            503,
            "POLICY_SIGNATURE_REFUSED",
            "signature_refused",
            "policy envelope purpose is invalid",
        )
    scope_value = envelope["scope"]
    if not isinstance(scope_value, Mapping):
        raise PolicyRegistryHttpError(
            503, "POLICY_SIGNATURE_REFUSED", "signature_refused", "policy envelope scope is invalid"
        )
    if (
        (expected_org_id is not None and scope_value.get("org_id") != expected_org_id)
        or (
            expected_project_id is not None and scope_value.get("project_id") != expected_project_id
        )
        or (
            expected_environment_id is not None
            and scope_value.get("environment_id") != expected_environment_id
        )
    ):
        raise PolicyRegistryHttpError(
            503,
            "POLICY_SIGNATURE_REFUSED",
            "signature_refused",
            "policy envelope scope does not match request",
        )
    scope = ReceiptTrustScope(
        str(scope_value.get("org_id")),
        str(scope_value.get("project_id")),
        str(scope_value.get("environment_id")),
        POLICY_ENVELOPE_PURPOSE,
    )
    document = envelope["document"]
    if not isinstance(document, Mapping) or sha256_json(document) != envelope["content_hash"]:
        raise PolicyRegistryHttpError(
            503,
            "POLICY_SIGNATURE_REFUSED",
            "signature_refused",
            "policy envelope content hash mismatch",
        )
    if expected_policy_id is not None and envelope["policy_id"] != expected_policy_id:
        raise PolicyRegistryHttpError(
            503,
            "POLICY_SIGNATURE_REFUSED",
            "signature_refused",
            "policy envelope policy id does not match request",
        )
    if expected_version is not None and envelope["version"] != expected_version:
        raise PolicyRegistryHttpError(
            503,
            "POLICY_SIGNATURE_REFUSED",
            "signature_refused",
            "policy envelope version does not match document",
        )
    if expected_document is not None and document != expected_document:
        raise PolicyRegistryHttpError(
            503,
            "POLICY_SIGNATURE_REFUSED",
            "signature_refused",
            "policy envelope document does not match request",
        )
    if (
        document.get("id") != envelope["policy_id"]
        or document.get("version") != envelope["version"]
    ):
        raise PolicyRegistryHttpError(
            503,
            "POLICY_SIGNATURE_REFUSED",
            "signature_refused",
            "policy envelope metadata does not match document",
        )
    if list(document.get("rules", [])) != list(envelope["rules"]):
        raise PolicyRegistryHttpError(
            503,
            "POLICY_SIGNATURE_REFUSED",
            "signature_refused",
            "policy envelope rules do not match document",
        )
    registry = SqlReceiptTrustRegistry(session, lock_rows=True)
    try:
        key = registry.resolve(
            scope=scope,
            trust_epoch=int(envelope["trust_epoch"]),
            algorithm=str(envelope["signature_algorithm"]),
            key_id=str(envelope["key_id"]),
            now_iso=utcnow().isoformat(),
            mode="execution",
        )
    except (TrustConfigurationError, ManagedTrustError, TypeError, ValueError) as exc:
        raise PolicyRegistryHttpError(
            503,
            "POLICY_SIGNATURE_REFUSED",
            "signature_refused",
            "policy envelope trust could not be resolved",
        ) from exc
    unsigned = dict(envelope)
    signature = str(unsigned.pop("signature"))
    if not key.verifier.verify(_canonical_bytes(unsigned), signature):
        raise PolicyRegistryHttpError(
            503,
            "POLICY_SIGNATURE_REFUSED",
            "signature_refused",
            "policy envelope signature is invalid",
        )


def _resolve_scope(
    session: Session,
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    lock: bool = False,
) -> tuple[Project, Environment]:
    statement = (
        sa.select(Project, Environment)
        .join(
            Environment,
            sa.and_(
                Environment.org_id == Project.org_id,
                Environment.project_id == Project.id,
            ),
        )
        .where(
            Project.org_id == org_id,
            Project.id == project_id,
            Environment.id == environment_id,
        )
    )
    if lock:
        statement = statement.with_for_update()
    row = session.execute(statement).first()
    if row is None:
        raise PolicyRegistryHttpError(
            404, "SCOPE_NOT_FOUND", "scope_not_found", "policy environment scope was not found"
        )
    return row[0], row[1]


def _get_version(
    session: Session,
    org_id: str,
    project_id: str,
    environment_id: str,
    version_id: str,
    *,
    lock: bool = False,
) -> PolicyVersion:
    statement = sa.select(PolicyVersion).where(
        PolicyVersion.org_id == org_id,
        PolicyVersion.project_id == project_id,
        PolicyVersion.environment_id == environment_id,
        PolicyVersion.id == version_id,
    )
    if lock:
        statement = statement.with_for_update()
    row = session.scalars(statement).one_or_none()
    if row is None:
        raise PolicyRegistryHttpError(
            404, "POLICY_VERSION_NOT_FOUND", "not_found", "policy version was not found"
        )
    return row


def _head(
    session: Session, org_id: str, project_id: str, environment_id: str, *, lock: bool
) -> EnvironmentPolicyHead | None:
    statement = sa.select(EnvironmentPolicyHead).where(
        EnvironmentPolicyHead.org_id == org_id,
        EnvironmentPolicyHead.project_id == project_id,
        EnvironmentPolicyHead.environment_id == environment_id,
    )
    if lock:
        statement = statement.with_for_update()
    return session.scalars(statement).one_or_none()


def _context_and_args(
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    actor: str,
    action: str,
    policy_bundle_id: str,
    policy_hash: str,
    args: dict[str, Any],
) -> tuple[ManagedMutationContext, dict[str, Any]]:
    return (
        ManagedMutationContext(
            org_id=org_id,
            project_id=project_id,
            environment_id=environment_id,
            actor=actor,
            action=action,
            execution_boundary=managed_mutation_execution_boundary(
                org_id=org_id, project_id=project_id, environment_id=environment_id, action=action
            ),
            policy_bundle_id=policy_bundle_id,
            policy_hash=policy_hash,
            validator_role=POLICY_REGISTRY_VALIDATOR_ROLE,
            authority=POLICY_REGISTRY_AUTHORITY,
        ),
        args,
    )


def _allow_record(*, context: ManagedMutationContext, args: Mapping[str, Any]) -> DecisionRecord:
    call = ToolCall(
        name=context.action,
        args=dict(args),
        actor=context.actor,
        goal="managed policy registry",
        path=("control-plane", "policy-registry"),
    )
    return DecisionRecord(
        decision=Decision.ALLOW,
        tool=call.name,
        actor=call.actor,
        goal=call.goal,
        reason="managed policy registry server-owned allow",
        matched_rules=("policy-registry-managed-write",),
        policy_version="policy-registry-managed/v1",
        event_id=new_id(),
        argument_hash=sha256_json(dict(args)),
        path=call.path,
        transformed_args=dict(args),
        state_hash=sha256_json({}),
    )


def _authorizing_policy_context(
    session: Session,
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    actor: str,
    action: str,
    args: Mapping[str, Any],
    lock: bool = False,
) -> _AuthorizingPolicyContext:
    head = _head(session, org_id, project_id, environment_id, lock=lock)
    if head is None:
        if not _is_initial_bootstrap_action(action=action, args=args):
            raise PolicyRegistryHttpError(
                409,
                "POLICY_NOT_READY",
                "policy_not_ready",
                "active environment policy head is not configured",
            )
        org_policy = _active_org_policy_context(session, org_id=org_id, lock=lock)
        if org_policy is not None:
            policy, bundle_id, policy_hash = org_policy
            return _AuthorizingPolicyContext(
                policy,
                bundle_id,
                policy_hash,
                _canonicalize_registry_decision(
                    _evaluate_registry_policy(policy, action=action, args=args, actor=actor),
                    action=action,
                    args=args,
                    actor=actor,
                ),
            )
        baseline_hash = sha256_json(
            {
                "schema": "policy-registry-bootstrap-baseline/v1",
                "allowed_actions": [
                    CONTROL_PLANE_POLICY_PUBLISH_ACTION,
                    CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
                ],
            }
        )
        context = ManagedMutationContext(
            org_id=org_id,
            project_id=project_id,
            environment_id=environment_id,
            actor=actor,
            action=action,
            execution_boundary=managed_mutation_execution_boundary(
                org_id=org_id, project_id=project_id, environment_id=environment_id, action=action
            ),
            policy_bundle_id="policy-registry/bootstrap",
            policy_hash=baseline_hash,
            validator_role=POLICY_REGISTRY_VALIDATOR_ROLE,
            authority=POLICY_REGISTRY_AUTHORITY,
        )
        decision = _allow_record(context=context, args=args)
        return _AuthorizingPolicyContext(None, context.policy_bundle_id, baseline_hash, decision)

    version = _get_version(
        session,
        org_id,
        project_id,
        environment_id,
        head.active_policy_version_id,
        lock=lock,
    )
    _verify_envelope(
        session,
        version.canonical_envelope,
        expected_org_id=org_id,
        expected_project_id=project_id,
        expected_environment_id=environment_id,
        expected_policy_id=version.policy_id,
        expected_version=version.version,
        expected_document=version.document,
    )
    try:
        policy = RuleSetPolicy.from_dict(version.document)
    except (TypeError, ValueError) as exc:
        raise PolicyRegistryHttpError(
            409,
            "POLICY_NOT_READY",
            "policy_not_ready",
            "active environment policy document is invalid",
        ) from exc
    return _AuthorizingPolicyContext(
        policy,
        version.id,
        version.content_hash,
        _canonicalize_registry_decision(
            _evaluate_registry_policy(policy, action=action, args=args, actor=actor),
            action=action,
            args=args,
            actor=actor,
        ),
    )


def _active_org_policy_context(
    session: Session, *, org_id: str, lock: bool
) -> tuple[RuleSetPolicy, str, str] | None:
    try:
        statement = sa.select(PolicyBundle).where(
            PolicyBundle.org_id == org_id,
            PolicyBundle.status == "active",
        )
        if lock:
            statement = statement.with_for_update()
        row = session.execute(statement).scalar_one_or_none()
    except MultipleResultsFound as exc:
        raise PolicyRegistryHttpError(
            409,
            "POLICY_NOT_READY",
            "policy_not_ready",
            "active organization policy bundle is not uniquely configured",
        ) from exc
    if row is None:
        return None
    try:
        policy = RuleSetPolicy.from_dict(row.bundle)
    except (TypeError, ValueError) as exc:
        raise PolicyRegistryHttpError(
            409,
            "POLICY_NOT_READY",
            "policy_not_ready",
            "active organization policy document is invalid",
        ) from exc
    return policy, row.id, sha256_json(row.bundle)


def _evaluate_registry_policy(
    policy: RuleSetPolicy, *, action: str, args: Mapping[str, Any], actor: str
) -> DecisionRecord:
    """Decide under both the managed and the legacy action name.

    Governing this route renamed ``policy.publish`` / ``policy.activate`` to
    ``control-plane.policy.publish`` / ``control-plane.policy.activate``. Org
    PolicyBundle rules already name the old actions, so evaluating only the new
    name would skip them and leak a bootstrap ALLOW. Both names are evaluated
    and the restrictive outcome wins, matching agent-create.
    """
    managed = policy.evaluate(_registry_policy_tool_call(action, args=args, actor=actor))
    if managed.decision is not Decision.ALLOW:
        return managed
    legacy = policy.evaluate(
        _registry_policy_tool_call(_legacy_registry_action(action), args=args, actor=actor)
    )
    if legacy.decision is not Decision.ALLOW:
        return legacy
    return managed


def _legacy_registry_action(action: str) -> str:
    if action == CONTROL_PLANE_POLICY_PUBLISH_ACTION:
        return LEGACY_POLICY_PUBLISH_ACTION
    if action == CONTROL_PLANE_POLICY_ACTIVATE_ACTION:
        return LEGACY_POLICY_ACTIVATE_ACTION
    return action


def _registry_policy_tool_call(name: str, *, args: Mapping[str, Any], actor: str) -> ToolCall:
    return ToolCall(
        name=name,
        args=dict(args),
        actor=actor,
        goal="managed policy registry",
        path=("control-plane", "policy-registry"),
    )


def _canonicalize_registry_decision(
    record: DecisionRecord, *, action: str, args: Mapping[str, Any], actor: str
) -> DecisionRecord:
    return replace(
        record,
        tool=action,
        actor=actor,
        goal="managed policy registry",
        argument_hash=sha256_json(dict(args)),
        event_id=record.event_id or new_id(),
        path=("control-plane", "policy-registry"),
        transformed_args=dict(args),
    )


def _is_initial_bootstrap_action(*, action: str, args: Mapping[str, Any]) -> bool:
    if action == CONTROL_PLANE_POLICY_PUBLISH_ACTION:
        return set(args) == {"policy_id", "version", "content_hash", "canonical_envelope"}
    if action == CONTROL_PLANE_POLICY_ACTIVATE_ACTION:
        return (
            set(args) == {"policy_version_id", "expected_generation"}
            and args.get("expected_generation") == 0
        )
    return False


def _idempotency_context(
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    actor: str,
    action: str,
    key: str,
    args: Mapping[str, Any],
) -> _PolicyIdempotencyContext:
    projection = {
        "schema": "policy-registry-idempotency-request/v1",
        "org_id": org_id,
        "project_id": project_id,
        "environment_id": environment_id,
        "actor": actor,
        "action": action,
        "args": dict(args),
    }
    storage_key = sha256_json(
        {
            "schema": "policy-registry-idempotency-storage-key/v1",
            "org_id": org_id,
            "actor": actor,
            "action": action,
            "key": key,
        }
    )
    return _PolicyIdempotencyContext(key, storage_key, projection, sha256_json(projection))


def _lookup_idempotency(session: Session, storage_key: str) -> PolicyRegistryIdempotency | None:
    return session.scalars(
        sa.select(PolicyRegistryIdempotency)
        .where(PolicyRegistryIdempotency.idempotency_key_hash == storage_key)
        .with_for_update()
    ).first()


def _lookup_idempotency_new_session(
    session_factory: sessionmaker[Session], idem: _PolicyIdempotencyContext
) -> PolicyRegistryIdempotency | None:
    with session_factory() as session:
        row = _lookup_idempotency(session, idem.storage_key)
        if row is not None:
            _assert_same_request(row, idem)
        return row


def _assert_same_request(row: PolicyRegistryIdempotency, idem: _PolicyIdempotencyContext) -> None:
    if row.request_hash != idem.request_hash:
        raise PolicyRegistryHttpError(
            409,
            "IDEMPOTENCY_CONFLICT",
            "idempotency_conflict",
            "idempotency key was already used for a different policy registry request",
        )


def _idempotency_row(
    idem: _PolicyIdempotencyContext,
    *,
    context: ManagedMutationContext,
    receipt_id: str,
    response: PolicyRegistryResult | Mapping[str, Any],
) -> PolicyRegistryIdempotency:
    return PolicyRegistryIdempotency(
        id=new_id(),
        idempotency_key_hash=idem.storage_key,
        actor_hash=sha256_json(context.actor),
        request_hash=idem.request_hash,
        org_id=context.org_id,
        project_id=context.project_id,
        environment_id=context.environment_id,
        action=context.action,
        receipt_id=receipt_id,
        response=(
            _result_payload(response)
            if isinstance(response, PolicyRegistryResult)
            else dict(response)
        ),
    )


def _replay_result(
    row: PolicyRegistryIdempotency, idem: _PolicyIdempotencyContext
) -> PolicyRegistryResult:
    _assert_same_request(row, idem)
    if row.actor_hash != sha256_json(idem.request_projection["actor"]):
        raise _invalid_idempotency_record()
    if row.response.get("kind") == "error":
        raise _error_from_payload(row.response)
    return PolicyRegistryResult(**row.response)


def _result_from_version(
    version: PolicyVersion,
    *,
    receipt_id: str,
    generation: int | None = None,
    activated_at: Any | None = None,
) -> PolicyRegistryResult:
    return PolicyRegistryResult(
        bundle_id=version.id,
        org_id=version.org_id,
        project_id=version.project_id,
        environment_id=version.environment_id,
        policy_id=version.policy_id,
        version=version.version,
        status="active" if generation is not None else "published",
        rules=list(version.rules),
        created_at=version.created_at,
        activated_at=activated_at,
        receipt_id=receipt_id,
        generation=generation,
        content_hash=version.content_hash,
        key_id=version.key_id,
        signature_algorithm=version.signature_algorithm,
        trust_epoch=version.trust_epoch,
    )


def _stale_generation() -> PolicyRegistryHttpError:
    return PolicyRegistryHttpError(
        409,
        "POLICY_GENERATION_STALE",
        "generation_stale",
        "policy head generation precondition failed",
    )


def _tx_aborted(detail: str) -> PolicyRegistryHttpError:
    return PolicyRegistryHttpError(503, "TX_ABORTED", "tx_aborted", detail, stage="tx")


def _terminal_policy_error(decision: Decision) -> PolicyRegistryHttpError:
    if decision is Decision.DENY:
        return PolicyRegistryHttpError(
            403,
            "POLICY_DENIED",
            "denied",
            "policy registry refused by policy",
        )
    if decision is Decision.ESCALATE:
        return PolicyRegistryHttpError(
            202,
            "ESCALATE_PENDING",
            "escalate_pending",
            "policy registry requires separated approval",
        )
    raise PolicyRegistryHttpError(
        503,
        "RECEIPT_REFUSED",
        "receipt_refused",
        "policy registry receipt was refused",
        stage="executor",
    )


def _error_payload(error: PolicyRegistryHttpError) -> dict[str, Any]:
    return {
        "kind": "error",
        "status_code": error.status_code,
        "code": error.code,
        "status": error.status,
        "detail": error.detail,
        "stage": error.stage,
    }


def _error_from_payload(payload: Mapping[str, Any]) -> PolicyRegistryHttpError:
    try:
        return PolicyRegistryHttpError(
            int(payload["status_code"]),
            str(payload["code"]),
            str(payload["status"]),
            str(payload["detail"]),
            stage=str(payload.get("stage", "policy")),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise _invalid_idempotency_record() from exc


def _invalid_idempotency_record() -> PolicyRegistryHttpError:
    return PolicyRegistryHttpError(
        503,
        "IDEMPOTENCY_RECORD_CORRUPT",
        "idempotency_corrupt",
        "policy idempotency record is corrupt",
        stage="tx",
    )


def _result_payload(result: PolicyRegistryResult) -> dict[str, Any]:
    payload = dict(result.__dict__)
    for field_name in ("created_at", "activated_at"):
        value = payload.get(field_name)
        if isinstance(value, datetime):
            payload[field_name] = value.isoformat()
    return payload


def bootstrap_local_policy_registry_trust(
    session: Session,
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    issuer: InProcessPlatformIssuer | None = None,
) -> None:
    """Test/local helper that makes the fixture purpose explicit."""

    from acgs_control_plane.trust import ManagedTrustLifecycleService

    issuer = issuer or local_policy_registry_issuer()
    not_after = utcnow() + timedelta(days=7)
    for purpose in (DECISION_RECEIPT_PURPOSE, POLICY_ENVELOPE_PURPOSE):
        scope = ReceiptTrustScope(org_id, project_id, environment_id, purpose)
        ManagedTrustLifecycleService(session).bootstrap(
            scope=scope,
            key_id=issuer.key_id,
            algorithm=issuer.algorithm,
            public_key_spki_der=public_spki_der_from_signer(
                issuer.signer_for_scope(scope, trust_epoch=1)
            ),
            not_after=not_after,
        )
