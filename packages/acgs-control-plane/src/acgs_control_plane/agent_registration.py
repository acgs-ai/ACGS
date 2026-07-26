"""Canonical managed agent-registration service."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

import sqlalchemy as sa
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import ReceiptAlreadyUsedError, ReceiptRejectionReason, ReceiptValidationError
from gove_zone.receipt import DecisionReceipt, safe_result_hash
from gove_zone.signing import Ed25519Signer
from gove_zone.tool import ToolCall, normalize_path_context
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, ReceiptTrustScope, TrustConfigurationError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from acgs_control_plane.auth import Principal
from acgs_control_plane.managed_mutations import (
    CONTROL_PLANE_AGENT_CREATE_ACTION,
    AesGcmReceiptArtifactSealer,
    ManagedMutationContext,
    ManagedMutationResult,
    ManagedMutationUnitOfWork,
    ManagedNonExecutableEvidenceResult,
    _validated_operation_args,
    managed_mutation_execution_boundary,
    managed_receipt_artifact_aad,
)
from acgs_control_plane.models import (
    AgentRecord,
    AgentRegistrationIdempotency,
    Environment,
    EnvironmentPolicyHead,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedGovernanceEventHead,
    ManagedMutationAttempt,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    PolicyVersion,
    Project,
    new_id,
    utcnow,
)
from acgs_control_plane.policy_registry import PolicyRegistryHttpError, _verify_envelope
from acgs_control_plane.schemas import AgentRegisterRequest
from acgs_control_plane.trust import (
    InProcessPlatformIssuer,
    ManagedPlatformIssuer,
    ManagedReceiptContext,
    ManagedTrustError,
    SqlReceiptTrustRegistry,
    active_trust_epoch_for_scope,
    mint_managed_decision_receipt_v2,
)

AGENT_REGISTRATION_AUTHORITY = "control-plane.agent-registration/v1"
AGENT_REGISTRATION_VALIDATOR_ROLE = "control-plane.agent-policy/v1"
AGENT_REGISTRATION_GOAL = "register managed agent in org registry"
_GENESIS_AUDIT_HASH = "0" * 64
_LOCAL_AGENT_SIGNER_SEED = bytes.fromhex(
    "55df9db52ff7b9635dd2bbf66fbcb3fb3f70d6071359449f0d9f8ad1a3e8a9c4"
)
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9._:/-]{8,200}$")


@dataclass
class AgentRegistrationHttpError(RuntimeError):
    status_code: int
    code: str
    status: str
    detail: str
    stage: str = "policy"


@dataclass(frozen=True)
class AgentRegistrationResult:
    agent_id: str
    org_id: str
    name: str
    description: str
    trust_tier: str
    allowed_tools: list[str]
    status: str
    created_at: Any
    receipt_id: str


class AgentRegistrationReceiptIssuer(Protocol):
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
class DefaultAgentRegistrationReceiptIssuer:
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
            constraints={"schema": "agent-registration-constraints/v1"},
            approval_chain_summary={},
        )


@dataclass(frozen=True)
class AgentRegistrationProviders:
    issuer: ManagedPlatformIssuer
    receipt_sealer: AesGcmReceiptArtifactSealer
    receipt_issuer: AgentRegistrationReceiptIssuer


def local_agent_registration_issuer() -> InProcessPlatformIssuer:
    """Deterministic local/test issuer; production must inject real custody."""

    return InProcessPlatformIssuer(
        Ed25519Signer.from_private_bytes(
            _LOCAL_AGENT_SIGNER_SEED,
            key_id="local-control-plane-agent-registration",
        ),
        allowed_purposes=frozenset({DECISION_RECEIPT_PURPOSE}),
    )


def local_agent_registration_receipt_sealer() -> AesGcmReceiptArtifactSealer:
    """Deterministic local/test receipt sealer; production must inject KMS storage."""

    return AesGcmReceiptArtifactSealer(
        key_id="local-control-plane-agent-registration-sealer",
        key=hashlib.sha256(b"acgs-control-plane-local-agent-registration-sealer").digest(),
    )


class AgentRegistrationService:
    __slots__ = ("_providers", "_session_factory")
    _providers: AgentRegistrationProviders
    _session_factory: sessionmaker[Session]

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        issuer: ManagedPlatformIssuer,
        receipt_sealer: AesGcmReceiptArtifactSealer,
        receipt_issuer: AgentRegistrationReceiptIssuer | None = None,
    ) -> None:
        object.__setattr__(self, "_session_factory", session_factory)
        object.__setattr__(
            self,
            "_providers",
            AgentRegistrationProviders(
                issuer=issuer,
                receipt_sealer=receipt_sealer,
                receipt_issuer=receipt_issuer or DefaultAgentRegistrationReceiptIssuer(issuer),
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("agent registration service is frozen after initialization")

    @property
    def issuer(self) -> ManagedPlatformIssuer:
        return self._providers.issuer

    def register(
        self,
        *,
        org_id: str,
        principal: Principal,
        body: AgentRegisterRequest,
        idempotency_key: str | None = None,
    ) -> AgentRegistrationResult:
        idempotency_key = _normalize_idempotency_key(idempotency_key)
        args = _normalized_agent_args(body)
        with self._session_factory() as session:
            project, environment = _resolve_default_scope(session, org_id=org_id)
            policy, policy_bundle_id, policy_hash = _active_policy_context(
                session,
                org_id=org_id,
                project_id=project.id,
                environment_id=environment.id,
            )
            context = ManagedMutationContext(
                org_id=org_id,
                project_id=project.id,
                environment_id=environment.id,
                actor=principal.actor_id,
                action=CONTROL_PLANE_AGENT_CREATE_ACTION,
                execution_boundary=managed_mutation_execution_boundary(
                    org_id=org_id,
                    project_id=project.id,
                    environment_id=environment.id,
                    action=CONTROL_PLANE_AGENT_CREATE_ACTION,
                ),
                policy_bundle_id=policy_bundle_id,
                policy_hash=policy_hash,
                validator_role=AGENT_REGISTRATION_VALIDATOR_ROLE,
                authority=AGENT_REGISTRATION_AUTHORITY,
            )
            decision_record = _evaluate_agent_policy(
                policy,
                args=args,
                actor=principal.actor_id,
            )
            decision_record = _server_owned_decision_record(
                decision_record,
                args=args,
                actor=principal.actor_id,
            )
            audit_hash = _decision_audit_hash(decision_record)
            context = replace(context, expected_audit_hash=audit_hash)
            request_projection = _idempotency_request_projection(
                context=context,
                args=args,
            )
            idempotency_record = _AgentRegistrationIdempotencyContext(
                raw_key=idempotency_key,
                storage_key=_idempotency_storage_key(
                    context=context,
                    key=idempotency_key,
                ),
                request_projection=request_projection,
                request_hash=sha256_json(request_projection),
            )
            existing = _lookup_idempotency(
                session,
                idempotency_key_hash=idempotency_record.storage_key,
            )
            if existing is not None:
                return _replay_idempotency_response(
                    session,
                    existing,
                    idempotency_record,
                    self._providers.receipt_sealer,
                )
            try:
                trust_epoch = active_trust_epoch_for_scope(
                    session,
                    ReceiptTrustScope(
                        org_id,
                        project.id,
                        environment.id,
                        DECISION_RECEIPT_PURPOSE,
                    ),
                )
                receipt = self._providers.receipt_issuer.issue(
                    context=context,
                    args=args,
                    decision_record=decision_record,
                    audit_hash=audit_hash,
                    request_id=idempotency_key or new_id(),
                    trust_epoch=trust_epoch,
                )
            except (TrustConfigurationError, ManagedTrustError) as exc:
                raise AgentRegistrationHttpError(
                    503,
                    "RECEIPT_REFUSED",
                    "receipt_refused",
                    "agent registration receipt was refused",
                    stage="issuance",
                ) from exc
            if not isinstance(receipt, DecisionReceipt):
                raise AgentRegistrationHttpError(
                    503,
                    "RECEIPT_REFUSED",
                    "receipt_refused",
                    "agent registration receipt was malformed",
                    stage="issuance",
                )

        holder: dict[str, AgentRegistrationResult] = {}
        uow = ManagedMutationUnitOfWork(
            self._session_factory,
            receipt_sealer=self._providers.receipt_sealer,
        )

        if decision_record.decision in {Decision.DENY, Decision.ESCALATE}:

            def before_record(tx_session: Session) -> None:
                _revalidate_active_policy_under_lock(
                    tx_session,
                    context=context,
                    args=args,
                    actor=principal.actor_id,
                    expected_decision=decision_record.decision,
                )
                existing = _lookup_idempotency(
                    tx_session,
                    idempotency_key_hash=idempotency_record.storage_key,
                )
                if existing is not None:
                    _assert_same_idempotency_request(existing, idempotency_record)
                    raise _CommittedAgentRegistrationIdempotencyRace()

            def after_record(
                session: Session,
                receipt_row: ManagedDecisionReceipt,
                _event: ManagedGovernanceEvent,
                _outbox: ManagedOutboxMessage,
                _result: ManagedNonExecutableEvidenceResult,
            ) -> None:
                terminal = _terminal_http_error_for_decision(decision_record)
                session.add(
                    AgentRegistrationIdempotency(
                        id=new_id(),
                        idempotency_key_hash=idempotency_record.storage_key,
                        actor_hash=sha256_json(context.actor),
                        request_hash=idempotency_record.request_hash,
                        org_id=context.org_id,
                        project_id=context.project_id,
                        environment_id=context.environment_id,
                        agent_id=None,
                        receipt_id=receipt_row.receipt_id,
                        response=_idempotency_error_payload(
                            terminal,
                            context=context,
                            receipt_id=receipt_row.receipt_id,
                        ),
                    )
                )

            try:
                uow.record_non_executable_evidence(
                    context=context,
                    receipt=receipt,
                    args=args,
                    before_record=before_record,
                    after_record=after_record,
                )
            except _CommittedAgentRegistrationIdempotencyRace:
                existing = _lookup_idempotency_new_session(
                    self._session_factory,
                    idempotency=idempotency_record,
                )
                if existing is not None:
                    raise _replay_idempotency_response_new_session_error(
                        self._session_factory,
                        existing,
                        idempotency_record,
                        self._providers.receipt_sealer,
                    ) from None
                raise AgentRegistrationHttpError(
                    503,
                    "TX_ABORTED",
                    "tx_aborted",
                    "agent registration idempotency commit was not observable",
                    stage="tx",
                ) from None
            except ReceiptAlreadyUsedError as exc:
                existing = _lookup_idempotency_new_session(
                    self._session_factory,
                    idempotency=idempotency_record,
                )
                if existing is not None:
                    raise _replay_idempotency_response_new_session_error(
                        self._session_factory,
                        existing,
                        idempotency_record,
                        self._providers.receipt_sealer,
                    ) from exc
                raise AgentRegistrationHttpError(
                    409,
                    "RECEIPT_ALREADY_USED",
                    "receipt_replayed",
                    "agent registration refusal receipt was already recorded",
                    stage="executor",
                ) from exc
            except (ReceiptValidationError, TrustConfigurationError, ManagedTrustError) as exc:
                raise AgentRegistrationHttpError(
                    503,
                    "RECEIPT_REFUSED",
                    "receipt_refused",
                    "agent registration receipt was refused",
                    stage="executor",
                ) from exc
            except (SQLAlchemyError, ValueError, RuntimeError) as exc:
                existing = _lookup_idempotency_new_session(
                    self._session_factory,
                    idempotency=idempotency_record,
                )
                if existing is not None:
                    raise _replay_idempotency_response_new_session_error(
                        self._session_factory,
                        existing,
                        idempotency_record,
                        self._providers.receipt_sealer,
                    ) from exc
                raise AgentRegistrationHttpError(
                    503,
                    "TX_ABORTED",
                    "tx_aborted",
                    "agent registration refusal evidence transaction aborted",
                    stage="tx",
                ) from exc
            raise _terminal_http_error_for_decision(decision_record)

        if decision_record.decision is not Decision.ALLOW:
            raise AgentRegistrationHttpError(
                403,
                "POLICY_DENIED",
                "denied",
                "agent registration refused by policy",
            )

        def before_execute(tx_session: Session) -> None:
            _revalidate_active_policy_under_lock(
                tx_session,
                context=context,
                args=args,
                actor=principal.actor_id,
            )
            existing = _lookup_idempotency(
                tx_session,
                idempotency_key_hash=idempotency_record.storage_key,
            )
            if existing is not None:
                _assert_same_idempotency_request(existing, idempotency_record)
                raise _CommittedAgentRegistrationIdempotencyRace()

        def operation_effect(session: Session, verified_args: dict[str, Any]) -> dict[str, Any]:
            name = str(verified_args["name"])
            agent = AgentRecord(
                id=new_id(),
                org_id=org_id,
                project_id=context.project_id,
                environment_id=context.environment_id,
                name=name,
                description=str(verified_args["description"]),
                trust_tier=str(verified_args["trust_tier"]),
                allowed_tools=list(verified_args["allowed_tools"]),
                status="active",
            )
            session.add(agent)
            session.flush()
            return {
                "agent_id": agent.id,
                "org_id": agent.org_id,
                "project_id_hash": sha256_json(agent.project_id or ""),
                "environment_id_hash": sha256_json(agent.environment_id or ""),
                "name_hash": sha256_json(agent.name),
                "status": agent.status,
                "created_at": agent.created_at.isoformat(),
            }

        def after_success(
            session: Session,
            receipt_row: ManagedDecisionReceipt,
            _event: ManagedGovernanceEvent,
            _outbox: ManagedOutboxMessage,
            result: ManagedMutationResult,
        ) -> None:
            agent = session.get(AgentRecord, result.result["agent_id"])
            if agent is None:
                raise RuntimeError("managed agent registration committed without agent row")
            response = AgentRegistrationResult(
                agent_id=agent.id,
                org_id=agent.org_id,
                name=agent.name,
                description=agent.description,
                trust_tier=agent.trust_tier,
                allowed_tools=list(agent.allowed_tools or []),
                status=agent.status,
                created_at=agent.created_at,
                receipt_id=receipt_row.receipt_id,
            )
            session.add(
                AgentRegistrationIdempotency(
                    id=new_id(),
                    idempotency_key_hash=idempotency_record.storage_key,
                    actor_hash=sha256_json(context.actor),
                    request_hash=idempotency_record.request_hash,
                    org_id=context.org_id,
                    project_id=context.project_id,
                    environment_id=context.environment_id,
                    agent_id=agent.id,
                    receipt_id=receipt_row.receipt_id,
                    response=_idempotency_response_payload(response, context=context),
                )
            )
            holder["response"] = response

        try:
            uow.execute(
                context=context,
                receipt=receipt,
                args=args,
                before_execute=before_execute,
                operation_effect=operation_effect,
                after_success=after_success,
            )
        except _CommittedAgentRegistrationIdempotencyRace:
            existing = _lookup_idempotency_new_session(
                self._session_factory,
                idempotency=idempotency_record,
            )
            if existing is not None:
                return _replay_idempotency_response_new_session_result(
                    self._session_factory,
                    existing,
                    idempotency_record,
                    self._providers.receipt_sealer,
                )
            raise AgentRegistrationHttpError(
                503,
                "TX_ABORTED",
                "tx_aborted",
                "agent registration idempotency commit was not observable",
                stage="tx",
            ) from None
        except IntegrityError as exc:
            existing = _lookup_idempotency_new_session(
                self._session_factory,
                idempotency=idempotency_record,
            )
            if existing is not None:
                return _replay_idempotency_response_new_session_result(
                    self._session_factory,
                    existing,
                    idempotency_record,
                    self._providers.receipt_sealer,
                )
            if _is_agent_name_conflict(exc):
                raise AgentRegistrationHttpError(
                    409,
                    "AGENT_NAME_CONFLICT",
                    "conflict",
                    "agent name already exists in environment",
                    stage="tx",
                ) from exc
            raise AgentRegistrationHttpError(
                503,
                "TX_ABORTED",
                "tx_aborted",
                "agent registration transaction aborted",
                stage="tx",
            ) from exc
        except ReceiptAlreadyUsedError as exc:
            existing = _lookup_idempotency_new_session(
                self._session_factory,
                idempotency=idempotency_record,
            )
            if existing is not None:
                return _replay_idempotency_response_new_session_result(
                    self._session_factory,
                    existing,
                    idempotency_record,
                    self._providers.receipt_sealer,
                )
            raise AgentRegistrationHttpError(
                409,
                "RECEIPT_ALREADY_USED",
                "receipt_replayed",
                "agent registration receipt was already used",
                stage="executor",
            ) from exc
        except (ReceiptValidationError, TrustConfigurationError, ManagedTrustError) as exc:
            raise AgentRegistrationHttpError(
                503,
                "RECEIPT_REFUSED",
                "receipt_refused",
                "agent registration receipt was refused",
                stage="executor",
            ) from exc
        except (SQLAlchemyError, ValueError, RuntimeError) as exc:
            existing = _lookup_idempotency_new_session(
                self._session_factory,
                idempotency=idempotency_record,
            )
            if existing is not None:
                return _replay_idempotency_response_new_session_result(
                    self._session_factory,
                    existing,
                    idempotency_record,
                    self._providers.receipt_sealer,
                )
            raise AgentRegistrationHttpError(
                503,
                "TX_ABORTED",
                "tx_aborted",
                "agent registration transaction aborted",
                stage="tx",
            ) from exc
        if "response" not in holder:
            raise AgentRegistrationHttpError(
                503,
                "TX_ABORTED",
                "tx_aborted",
                "agent registration transaction did not return a response",
                stage="tx",
            )
        return holder["response"]


@dataclass(frozen=True)
class _AgentRegistrationIdempotencyContext:
    raw_key: str
    storage_key: str
    request_projection: dict[str, Any]
    request_hash: str


def _resolve_default_scope(
    session: Session, *, org_id: str, lock: bool = False
) -> tuple[Project, Environment]:
    try:
        project_statement = (
            sa.select(Project).where(Project.org_id == org_id, Project.slug == "default").limit(2)
        )
        if lock:
            project_statement = project_statement.with_for_update()
        projects = list(session.scalars(project_statement))
    except SQLAlchemyError as exc:
        raise AgentRegistrationHttpError(
            409,
            "SCOPE_NOT_READY",
            "scope_not_ready",
            "default project scope is not configured",
        ) from exc
    if len(projects) != 1:
        raise AgentRegistrationHttpError(
            409,
            "SCOPE_NOT_READY",
            "scope_not_ready",
            "default project scope is not uniquely configured",
        )
    try:
        environment_statement = (
            sa.select(Environment)
            .where(
                Environment.org_id == org_id,
                Environment.project_id == projects[0].id,
                Environment.slug == "production",
            )
            .limit(2)
        )
        if lock:
            environment_statement = environment_statement.with_for_update()
        environments = list(session.scalars(environment_statement))
    except SQLAlchemyError as exc:
        raise AgentRegistrationHttpError(
            409,
            "SCOPE_NOT_READY",
            "scope_not_ready",
            "production environment scope is not configured",
        ) from exc
    if len(environments) != 1:
        raise AgentRegistrationHttpError(
            409,
            "SCOPE_NOT_READY",
            "scope_not_ready",
            "production environment scope is not uniquely configured",
        )
    return projects[0], environments[0]


def _is_agent_name_conflict(exc: IntegrityError) -> bool:
    text = str(getattr(exc, "orig", exc)).lower()
    if any(
        marker in text
        for marker in (
            "uq_agents_scope_name",
            "uq_agents_legacy_org_name",
            "uq_agents_org_name",
        )
    ):
        return True
    return "agents.org_id" in text and "agents.name" in text


def _normalize_idempotency_key(idempotency_key: str | None) -> str:
    if idempotency_key is None:
        raise AgentRegistrationHttpError(
            400,
            "IDEMPOTENCY_KEY_REQUIRED",
            "idempotency_key_required",
            "idempotency key is required for agent registration",
            stage="policy",
        )
    if not _IDEMPOTENCY_RE.fullmatch(idempotency_key):
        raise AgentRegistrationHttpError(
            400,
            "IDEMPOTENCY_KEY_INVALID",
            "idempotency_key_invalid",
            "idempotency key must be 8-200 safe characters",
            stage="policy",
        )
    return idempotency_key


def _idempotency_storage_key(*, context: ManagedMutationContext, key: str) -> str:
    return sha256_json(
        {
            "schema": "agent-registration-idempotency-storage-key/v1",
            "org_id": context.org_id,
            "project_id": context.project_id,
            "environment_id": context.environment_id,
            "actor": context.actor,
            "key": key,
        }
    )


def _idempotency_request_projection(
    *,
    context: ManagedMutationContext,
    args: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema": "agent-registration-idempotency-request/v1",
        "org_id": context.org_id,
        "project_id": context.project_id,
        "environment_id": context.environment_id,
        "actor": context.actor,
        "action": context.action,
        "args": dict(args),
    }


def _lookup_idempotency(
    session: Session,
    *,
    idempotency_key_hash: str,
) -> AgentRegistrationIdempotency | None:
    return session.scalars(
        sa.select(AgentRegistrationIdempotency)
        .where(AgentRegistrationIdempotency.idempotency_key_hash == idempotency_key_hash)
        .with_for_update()
    ).first()


def _lookup_idempotency_new_session(
    session_factory: sessionmaker[Session],
    *,
    idempotency: _AgentRegistrationIdempotencyContext | None,
) -> AgentRegistrationIdempotency | None:
    if idempotency is None:
        return None
    with session_factory() as session:
        existing = _lookup_idempotency(
            session,
            idempotency_key_hash=idempotency.storage_key,
        )
        if existing is not None:
            _assert_same_idempotency_request(existing, idempotency)
        return existing


def _assert_same_idempotency_request(
    row: AgentRegistrationIdempotency,
    idempotency: _AgentRegistrationIdempotencyContext,
) -> None:
    if row.request_hash != idempotency.request_hash:
        raise AgentRegistrationHttpError(
            409,
            "IDEMPOTENCY_CONFLICT",
            "idempotency_conflict",
            "idempotency key was already used for a different agent registration request",
            stage="policy",
        )


def _replay_idempotency_response(
    session: Session,
    row: AgentRegistrationIdempotency,
    idempotency: _AgentRegistrationIdempotencyContext,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> AgentRegistrationResult:
    replay = _validated_idempotency_replay(session, row, idempotency, receipt_sealer)
    if isinstance(replay, AgentRegistrationResult):
        return replay
    raise replay


def _replay_idempotency_response_new_session_result(
    session_factory: sessionmaker[Session],
    row: AgentRegistrationIdempotency,
    idempotency: _AgentRegistrationIdempotencyContext,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> AgentRegistrationResult:
    with session_factory() as session:
        fresh = session.get(AgentRegistrationIdempotency, row.id)
        if fresh is None:
            raise _invalid_idempotency_record()
        return _replay_idempotency_response(session, fresh, idempotency, receipt_sealer)


def _replay_idempotency_response_new_session_error(
    session_factory: sessionmaker[Session],
    row: AgentRegistrationIdempotency,
    idempotency: _AgentRegistrationIdempotencyContext,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> AgentRegistrationHttpError:
    with session_factory() as session:
        fresh = session.get(AgentRegistrationIdempotency, row.id)
        if fresh is None:
            return _invalid_idempotency_record()
        replay = _validated_idempotency_replay(session, fresh, idempotency, receipt_sealer)
        if isinstance(replay, AgentRegistrationHttpError):
            return replay
        return _invalid_idempotency_record()


def _validated_idempotency_replay(
    session: Session,
    row: AgentRegistrationIdempotency,
    idempotency: _AgentRegistrationIdempotencyContext,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> AgentRegistrationResult | AgentRegistrationHttpError:
    _assert_same_idempotency_request(row, idempotency)
    projection = idempotency.request_projection
    if (
        row.actor_hash != sha256_json(projection["actor"])
        or row.org_id != projection["org_id"]
        or row.project_id != projection["project_id"]
        or row.environment_id != projection["environment_id"]
    ):
        raise _invalid_idempotency_record()

    receipt = session.scalars(
        sa.select(ManagedDecisionReceipt)
        .where(
            ManagedDecisionReceipt.org_id == row.org_id,
            ManagedDecisionReceipt.project_id == row.project_id,
            ManagedDecisionReceipt.environment_id == row.environment_id,
            ManagedDecisionReceipt.receipt_id == row.receipt_id,
        )
        .with_for_update()
    ).one_or_none()
    if receipt is None:
        raise _invalid_idempotency_record()
    if (
        receipt.actor != projection["actor"]
        or receipt.proposed_action != projection["action"]
        or receipt.argument_hash != sha256_json(projection["args"])
    ):
        raise _invalid_idempotency_record()
    _validate_replay_receipt_artifact(
        session,
        receipt,
        projection=projection,
        receipt_sealer=receipt_sealer,
    )
    event = _validated_replay_event(session, receipt, projection=projection)
    outbox = _validated_replay_outbox(session, receipt, event)

    if receipt.decision == "allow":
        _validated_replay_allow_consumption(session, receipt)
        _validated_replay_allow_attempt(session, receipt, projection=projection)
        if not isinstance(row.agent_id, str):
            raise _invalid_idempotency_record()
        agent = session.scalars(
            sa.select(AgentRecord)
            .where(
                AgentRecord.org_id == row.org_id,
                AgentRecord.project_id == row.project_id,
                AgentRecord.environment_id == row.environment_id,
                AgentRecord.id == row.agent_id,
            )
            .with_for_update()
        ).one_or_none()
        if agent is None:
            raise _invalid_idempotency_record()
        _validate_replay_allow_agent_result(
            agent,
            projection=projection,
            event=event,
            outbox=outbox,
        )
        result = AgentRegistrationResult(
            agent_id=agent.id,
            org_id=agent.org_id,
            name=agent.name,
            description=agent.description,
            trust_tier=agent.trust_tier,
            allowed_tools=list(agent.allowed_tools or []),
            status=agent.status,
            created_at=agent.created_at,
            receipt_id=receipt.receipt_id,
        )
        expected_response = _idempotency_response_payload_for_scope(
            result,
            project_id=row.project_id,
            environment_id=row.environment_id,
        )
        if row.response != expected_response:
            raise _invalid_idempotency_record()
        return result

    if receipt.decision in {"deny", "escalate"}:
        _validate_no_allow_consumption(session, receipt)
        _validate_no_mutation_attempt(session, receipt)
        if row.agent_id is not None:
            raise _invalid_idempotency_record()
        terminal = _terminal_http_error_for_decision_value(Decision(receipt.decision))
        expected_response = _idempotency_error_payload_for_scope(
            terminal,
            org_id=row.org_id,
            project_id=row.project_id,
            environment_id=row.environment_id,
            receipt_id=receipt.receipt_id,
        )
        if row.response != expected_response:
            raise _invalid_idempotency_record()
        return terminal

    raise _invalid_idempotency_record()


def _validate_replay_receipt_artifact(
    session: Session,
    receipt_row: ManagedDecisionReceipt,
    *,
    projection: Mapping[str, Any],
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    try:
        sealed_receipt = receipt_row.projection["sealed_receipt"]
        if not isinstance(sealed_receipt, Mapping):
            raise ValueError("sealed receipt is not an object")
        plaintext = receipt_sealer.unseal(
            sealed_receipt,
            associated_data=managed_receipt_artifact_aad(
                org_id=receipt_row.org_id,
                project_id=receipt_row.project_id,
                environment_id=receipt_row.environment_id,
                receipt_hash=receipt_row.receipt_hash,
            ),
        )
        sealed = DecisionReceipt.from_dict(json.loads(plaintext.decode("utf-8")))
        if (
            sealed.receipt_id != receipt_row.receipt_id
            or sealed.receipt_hash != receipt_row.receipt_hash
            or sealed.audit_event_hash != receipt_row.audit_event_hash
            or sealed.decision != receipt_row.decision
            or sealed.actor != receipt_row.actor
            or sealed.proposed_action != receipt_row.proposed_action
            or sealed.execution_boundary != receipt_row.execution_boundary
            or sealed.policy_bundle_id != receipt_row.policy_bundle_id
            or sealed.policy_version != receipt_row.policy_version
            or sealed.policy_hash != receipt_row.policy_hash
            or sealed.argument_hash != receipt_row.argument_hash
            or sealed.signing_key_id != receipt_row.signing_key_id
            or sealed.signature_algorithm != receipt_row.signature_algorithm
            or sealed.receipt_schema_version != receipt_row.receipt_schema_version
            or sealed.project_id != receipt_row.project_id
            or sealed.environment_id != receipt_row.environment_id
            or sealed.trust_epoch != receipt_row.trust_epoch
        ):
            raise ValueError("sealed receipt does not match indexed projection")
        if sealed.receipt_hash != sealed.compute_hash():
            raise ValueError("sealed receipt hash mismatch")
        try:
            sealed.verify(
                expected_tenant_id=receipt_row.org_id,
                expected_execution_boundary=receipt_row.execution_boundary,
                expected_action=receipt_row.proposed_action,
                expected_actor=str(projection["actor"]),
                expected_audit_hash=receipt_row.audit_event_hash,
                expected_args=_validated_operation_args(
                    str(projection["action"]),
                    cast(Mapping[str, Any], projection["args"]),
                ),
                expected_policy_hash=receipt_row.policy_hash,
                expected_policy_bundle_id=receipt_row.policy_bundle_id,
                expected_project_id=receipt_row.project_id,
                expected_environment_id=receipt_row.environment_id,
                expected_validator_role=receipt_row.projection.get("validator_role"),
                expected_authority=receipt_row.projection.get("authority"),
                verifier=None,
                require_signature=True,
                require_expiry=False,
                trust_registry=SqlReceiptTrustRegistry(session),
                historical_trust_verification=True,
                trust_purpose=DECISION_RECEIPT_PURPOSE,
                now_iso=sealed.timestamp,
            )
        except ReceiptValidationError as exc:
            terminal_reasons = {
                "deny": ReceiptRejectionReason.DENIED_RECEIPT,
                "escalate": ReceiptRejectionReason.ESCALATED_RECEIPT,
            }
            if exc.reason_code != terminal_reasons.get(sealed.decision):
                raise
    except Exception as exc:
        raise _invalid_idempotency_record() from exc


def _validated_replay_event(
    session: Session,
    receipt: ManagedDecisionReceipt,
    *,
    projection: Mapping[str, Any],
) -> ManagedGovernanceEvent:
    events = list(
        session.scalars(
            sa.select(ManagedGovernanceEvent)
            .where(
                ManagedGovernanceEvent.org_id == receipt.org_id,
                ManagedGovernanceEvent.project_id == receipt.project_id,
                ManagedGovernanceEvent.environment_id == receipt.environment_id,
                ManagedGovernanceEvent.managed_receipt_id == receipt.id,
            )
            .with_for_update()
        )
    )
    if len(events) != 1:
        raise _invalid_idempotency_record()
    event = events[0]
    event_payload = event.payload if isinstance(event.payload, Mapping) else {}
    if (
        event.decision != receipt.decision
        or event.actor != receipt.actor
        or event.proposed_action != receipt.proposed_action
        or event.policy_version != receipt.policy_version
        or event_payload.get("receipt_hash") != receipt.receipt_hash
        or event_payload.get("audit_event_hash") != receipt.audit_event_hash
        or event_payload.get("argument_hash") != sha256_json(projection["args"])
        or event_payload.get("decision") != receipt.decision
        or event_payload.get("actor_hash") != sha256_json(projection["actor"])
        or event_payload.get("action") != projection["action"]
        or event_payload.get("policy_bundle_id") != receipt.policy_bundle_id
        or event_payload.get("policy_hash") != receipt.policy_hash
    ):
        raise _invalid_idempotency_record()
    if event.payload_digest != sha256_json(event.payload):
        raise _invalid_idempotency_record()
    _validate_replay_event_chain(session, event)
    return event


def _validate_replay_event_chain(session: Session, event: ManagedGovernanceEvent) -> None:
    expected_event_hash = sha256_json(
        {
            "schema": "managed-mutation-event-chain/v1",
            "sequence": event.sequence,
            "previous_hash": event.previous_hash,
            "payload_digest": event.payload_digest,
        }
    )
    if event.event_hash != expected_event_hash:
        raise _invalid_idempotency_record()
    head = session.get(
        ManagedGovernanceEventHead,
        (event.org_id, event.project_id, event.environment_id),
        with_for_update=True,
    )
    if head is None or event.sequence < 1 or event.sequence > head.last_sequence:
        raise _invalid_idempotency_record()
    if event.sequence == 1:
        if event.previous_hash != _GENESIS_AUDIT_HASH:
            raise _invalid_idempotency_record()
    else:
        previous_event = _event_at_sequence(session, event, sequence=event.sequence - 1)
        if previous_event is None or previous_event.event_hash != event.previous_hash:
            raise _invalid_idempotency_record()
    if event.sequence == head.last_sequence:
        if head.last_event_hash != event.event_hash:
            raise _invalid_idempotency_record()
    else:
        next_event = _event_at_sequence(session, event, sequence=event.sequence + 1)
        if next_event is None or next_event.previous_hash != event.event_hash:
            raise _invalid_idempotency_record()


def _event_at_sequence(
    session: Session,
    event: ManagedGovernanceEvent,
    *,
    sequence: int,
) -> ManagedGovernanceEvent | None:
    return session.scalars(
        sa.select(ManagedGovernanceEvent)
        .where(
            ManagedGovernanceEvent.org_id == event.org_id,
            ManagedGovernanceEvent.project_id == event.project_id,
            ManagedGovernanceEvent.environment_id == event.environment_id,
            ManagedGovernanceEvent.sequence == sequence,
        )
        .with_for_update()
    ).one_or_none()


def _validated_replay_outbox(
    session: Session,
    receipt: ManagedDecisionReceipt,
    event: ManagedGovernanceEvent,
) -> ManagedOutboxMessage:
    outbox_rows = list(
        session.scalars(
            sa.select(ManagedOutboxMessage)
            .where(
                ManagedOutboxMessage.org_id == receipt.org_id,
                ManagedOutboxMessage.project_id == receipt.project_id,
                ManagedOutboxMessage.environment_id == receipt.environment_id,
                ManagedOutboxMessage.managed_receipt_id == receipt.id,
                ManagedOutboxMessage.managed_event_id == event.id,
            )
            .with_for_update()
        )
    )
    if len(outbox_rows) != 1:
        raise _invalid_idempotency_record()
    outbox = outbox_rows[0]
    outbox_payload = outbox.payload if isinstance(outbox.payload, Mapping) else {}
    if (
        outbox_payload.get("event_hash") != event.event_hash
        or outbox_payload.get("payload_digest") != event.payload_digest
        or outbox_payload.get("receipt_hash") != receipt.receipt_hash
        or outbox_payload.get("audit_event_hash") != receipt.audit_event_hash
        or outbox_payload.get("result_hash") != event.payload.get("result_hash")
        or outbox_payload.get("assurance_class") != receipt.assurance_class
        or outbox.delivery_key != f"managed-mutation-uow/v1:{event.event_hash}"
        or outbox.payload_digest != sha256_json(outbox.payload)
    ):
        raise _invalid_idempotency_record()
    return outbox


def _validate_replay_allow_agent_result(
    agent: AgentRecord,
    *,
    projection: Mapping[str, Any],
    event: ManagedGovernanceEvent,
    outbox: ManagedOutboxMessage,
) -> None:
    expected_args = _validated_operation_args(
        str(projection["action"]),
        cast(Mapping[str, Any], projection["args"]),
    )
    if (
        agent.name != expected_args["name"]
        or agent.description != expected_args["description"]
        or agent.trust_tier != expected_args["trust_tier"]
        or list(agent.allowed_tools or []) != expected_args["allowed_tools"]
        or agent.status != "active"
    ):
        raise _invalid_idempotency_record()
    expected_result_hash = safe_result_hash(
        {
            "agent_id": agent.id,
            "org_id": agent.org_id,
            "project_id_hash": sha256_json(agent.project_id or ""),
            "environment_id_hash": sha256_json(agent.environment_id or ""),
            "name_hash": sha256_json(expected_args["name"]),
            "status": "active",
            "created_at": _to_utc(agent.created_at).isoformat(),
        }
    )
    event_payload = event.payload if isinstance(event.payload, Mapping) else {}
    outbox_payload = outbox.payload if isinstance(outbox.payload, Mapping) else {}
    if (
        event_payload.get("result_hash") != expected_result_hash
        or outbox_payload.get("result_hash") != expected_result_hash
    ):
        raise _invalid_idempotency_record()


def _validated_replay_allow_consumption(
    session: Session,
    receipt: ManagedDecisionReceipt,
) -> None:
    consumptions = list(
        session.scalars(
            sa.select(ManagedReceiptConsumption)
            .where(
                ManagedReceiptConsumption.org_id == receipt.org_id,
                ManagedReceiptConsumption.project_id == receipt.project_id,
                ManagedReceiptConsumption.environment_id == receipt.environment_id,
                ManagedReceiptConsumption.managed_receipt_id == receipt.id,
            )
            .with_for_update()
        )
    )
    if len(consumptions) != 1:
        raise _invalid_idempotency_record()
    consumption = consumptions[0]
    if (
        consumption.receipt_hash != receipt.receipt_hash
        or consumption.audit_event_hash != receipt.audit_event_hash
    ):
        raise _invalid_idempotency_record()


def _validated_replay_allow_attempt(
    session: Session,
    receipt: ManagedDecisionReceipt,
    *,
    projection: Mapping[str, Any],
) -> None:
    attempts = list(
        session.scalars(
            sa.select(ManagedMutationAttempt)
            .where(
                ManagedMutationAttempt.org_id == receipt.org_id,
                ManagedMutationAttempt.receipt_hash == receipt.receipt_hash,
            )
            .with_for_update()
        )
    )
    if len(attempts) != 1:
        raise _invalid_idempotency_record()
    attempt = attempts[0]
    if (
        attempt.project_id != receipt.project_id
        or attempt.environment_id != receipt.environment_id
        or attempt.audit_event_hash != receipt.audit_event_hash
        or attempt.action != receipt.proposed_action
        or attempt.actor_hash != sha256_json(projection["actor"])
        or attempt.argument_hash != sha256_json(projection["args"])
        or attempt.status != "succeeded"
    ):
        raise _invalid_idempotency_record()


def _validate_no_allow_consumption(
    session: Session,
    receipt: ManagedDecisionReceipt,
) -> None:
    if (
        session.scalars(
            sa.select(ManagedReceiptConsumption)
            .where(
                ManagedReceiptConsumption.org_id == receipt.org_id,
                ManagedReceiptConsumption.project_id == receipt.project_id,
                ManagedReceiptConsumption.environment_id == receipt.environment_id,
                ManagedReceiptConsumption.managed_receipt_id == receipt.id,
            )
            .with_for_update()
        ).first()
        is not None
    ):
        raise _invalid_idempotency_record()


def _validate_no_mutation_attempt(
    session: Session,
    receipt: ManagedDecisionReceipt,
) -> None:
    if (
        session.scalars(
            sa.select(ManagedMutationAttempt)
            .where(
                ManagedMutationAttempt.org_id == receipt.org_id,
                ManagedMutationAttempt.receipt_hash == receipt.receipt_hash,
            )
            .with_for_update()
        ).first()
        is not None
    ):
        raise _invalid_idempotency_record()


def _invalid_idempotency_record() -> AgentRegistrationHttpError:
    return AgentRegistrationHttpError(
        503,
        "IDEMPOTENCY_RECORD_INVALID",
        "idempotency_record_invalid",
        "agent registration idempotency record failed integrity validation",
        stage="tx",
    )


def _idempotency_response_payload(
    result: AgentRegistrationResult,
    *,
    context: ManagedMutationContext,
) -> dict[str, Any]:
    return _idempotency_response_payload_for_scope(
        result,
        project_id=context.project_id,
        environment_id=context.environment_id,
    )


def _idempotency_response_payload_for_scope(
    result: AgentRegistrationResult,
    *,
    project_id: str,
    environment_id: str,
) -> dict[str, Any]:
    return {
        "schema": "agent-registration-idempotency-response/v1",
        "terminal": "allow",
        "http_status": 201,
        "agent_id": result.agent_id,
        "org_id": result.org_id,
        "project_id": project_id,
        "environment_id": environment_id,
        "name": result.name,
        "description": result.description,
        "trust_tier": result.trust_tier,
        "allowed_tools": list(result.allowed_tools),
        "status": result.status,
        "created_at": _to_utc(result.created_at).isoformat(),
        "receipt_id": result.receipt_id,
    }


def _idempotency_error_payload(
    terminal: AgentRegistrationHttpError,
    *,
    context: ManagedMutationContext,
    receipt_id: str,
) -> dict[str, Any]:
    return _idempotency_error_payload_for_scope(
        terminal,
        org_id=context.org_id,
        project_id=context.project_id,
        environment_id=context.environment_id,
        receipt_id=receipt_id,
    )


def _idempotency_error_payload_for_scope(
    terminal: AgentRegistrationHttpError,
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    receipt_id: str,
) -> dict[str, Any]:
    decision = "escalate" if terminal.code == "ESCALATE_PENDING" else "deny"
    return {
        "schema": "agent-registration-idempotency-response/v1",
        "terminal": decision,
        "http_status": terminal.status_code,
        "code": terminal.code,
        "status": terminal.status,
        "detail": terminal.detail,
        "agent_id": None,
        "org_id": org_id,
        "project_id": project_id,
        "environment_id": environment_id,
        "receipt_id": receipt_id,
    }


def _terminal_http_error_for_decision(record: DecisionRecord) -> AgentRegistrationHttpError:
    return _terminal_http_error_for_decision_value(record.decision)


def _terminal_http_error_for_decision_value(decision: Decision) -> AgentRegistrationHttpError:
    if decision is Decision.ESCALATE:
        return AgentRegistrationHttpError(
            202,
            "ESCALATE_PENDING",
            "escalate_pending",
            "agent registration requires separated approval",
            stage="policy",
        )
    if decision is Decision.DENY:
        return AgentRegistrationHttpError(
            403,
            "POLICY_DENIED",
            "denied",
            "agent registration refused by policy",
            stage="policy",
        )
    raise AgentRegistrationHttpError(
        503,
        "RECEIPT_REFUSED",
        "receipt_refused",
        "agent registration receipt was refused",
        stage="policy",
    )


def _to_utc(value: Any) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError("agent registration idempotency response timestamp must be a datetime")
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class _CommittedAgentRegistrationIdempotencyRace(RuntimeError):
    """Raised inside the SQL UoW after another request commits this key."""


def _active_policy_context(
    session: Session,
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    lock: bool = False,
) -> tuple[Any, str, str]:
    head_statement = sa.select(EnvironmentPolicyHead).where(
        EnvironmentPolicyHead.org_id == org_id,
        EnvironmentPolicyHead.project_id == project_id,
        EnvironmentPolicyHead.environment_id == environment_id,
    )
    if lock:
        head_statement = head_statement.with_for_update()
    head = session.scalars(head_statement).one_or_none()
    if head is None or not head.active_policy_version_id:
        raise AgentRegistrationHttpError(
            409,
            "POLICY_NOT_READY",
            "policy_not_ready",
            "active environment policy head is not configured",
        )
    version_statement = sa.select(PolicyVersion).where(
        PolicyVersion.org_id == org_id,
        PolicyVersion.project_id == project_id,
        PolicyVersion.environment_id == environment_id,
        PolicyVersion.id == head.active_policy_version_id,
    )
    if lock:
        version_statement = version_statement.with_for_update()
    version = session.scalars(version_statement).one_or_none()
    if version is None:
        raise AgentRegistrationHttpError(
            409,
            "POLICY_NOT_READY",
            "policy_not_ready",
            "active environment policy version is missing",
        )
    try:
        _verify_envelope(session, version.canonical_envelope)
    except (PolicyRegistryHttpError, TypeError, ValueError) as exc:
        raise AgentRegistrationHttpError(
            409,
            "POLICY_NOT_READY",
            "policy_not_ready",
            "active environment policy envelope is invalid",
        ) from exc
    from gove_zone.policy import RuleSetPolicy

    try:
        policy = RuleSetPolicy.from_dict(version.document)
    except (TypeError, ValueError) as exc:
        raise AgentRegistrationHttpError(
            409,
            "POLICY_NOT_READY",
            "policy_not_ready",
            "active environment policy document is invalid",
        ) from exc
    return policy, version.id, version.content_hash


def _normalized_agent_args(body: AgentRegisterRequest) -> dict[str, Any]:
    return {
        "name": body.name,
        "description": body.description,
        "trust_tier": body.trust_tier,
        "allowed_tools": list(body.allowed_tools),
    }


def _evaluate_agent_policy(policy: Any, *, args: Mapping[str, Any], actor: str) -> DecisionRecord:
    return policy.evaluate(
        ToolCall(
            name=CONTROL_PLANE_AGENT_CREATE_ACTION,
            args=dict(args),
            actor=actor,
            goal=AGENT_REGISTRATION_GOAL,
            path=normalize_path_context(["control-plane", "agents"]),
            state={"trust_tier": args.get("trust_tier", "")},
        )
    )


def _revalidate_active_policy_under_lock(
    session: Session,
    *,
    context: ManagedMutationContext,
    args: Mapping[str, Any],
    actor: str,
    expected_decision: Decision = Decision.ALLOW,
) -> None:
    project, environment = _resolve_default_scope(session, org_id=context.org_id, lock=True)
    if project.id != context.project_id or environment.id != context.environment_id:
        raise ReceiptValidationError("agent registration scope changed before execution")
    policy, bundle_id, policy_hash = _active_policy_context(
        session,
        org_id=context.org_id,
        project_id=context.project_id,
        environment_id=context.environment_id,
        lock=True,
    )
    if bundle_id != context.policy_bundle_id or policy_hash != context.policy_hash:
        raise ReceiptValidationError("agent registration policy changed before execution")
    decision_record = _server_owned_decision_record(
        _evaluate_agent_policy(policy, args=args, actor=actor),
        args=args,
        actor=actor,
    )
    if decision_record.decision is not expected_decision:
        raise ReceiptValidationError("agent registration policy changed before receipt recording")


def _decision_audit_hash(record: DecisionRecord) -> str:
    return sha256_json(
        {
            "schema": "agent-registration-decision-audit/v1",
            "previous_hash": _GENESIS_AUDIT_HASH,
            "record": record.to_dict(),
        }
    )


def _server_owned_decision_record(
    record: DecisionRecord,
    *,
    args: Mapping[str, Any],
    actor: str,
) -> DecisionRecord:
    event_id = record.event_id or new_id()
    return replace(
        record,
        tool=CONTROL_PLANE_AGENT_CREATE_ACTION,
        argument_hash=sha256_json(dict(args)),
        event_id=event_id,
        goal=AGENT_REGISTRATION_GOAL,
        actor=actor,
        path=("control-plane", "agents"),
        decision_request_hash=sha256_json(
            {
                "schema": "agent-registration-decision-request/v1",
                "actor": actor,
                "args": dict(args),
            }
        ),
    )
