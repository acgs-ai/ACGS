"""Canonical managed agent-registration service."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, cast

import sqlalchemy as sa
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import ReceiptAlreadyUsedError, ReceiptValidationError
from gove_zone.receipt import DecisionReceipt
from gove_zone.signing import Ed25519Signer
from gove_zone.tool import ToolCall, normalize_path_context
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, ReceiptTrustScope, TrustConfigurationError
from sqlalchemy.exc import IntegrityError, MultipleResultsFound, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from acgs_control_plane.auth import Principal
from acgs_control_plane.governance import mirror_managed_decision
from acgs_control_plane.managed_mutations import (
    CONTROL_PLANE_AGENT_CREATE_ACTION,
    AesGcmReceiptArtifactSealer,
    ManagedMutationContext,
    ManagedMutationResult,
    ManagedMutationUnitOfWork,
    ManagedNonExecutableEvidenceResult,
    managed_mutation_execution_boundary,
)
from acgs_control_plane.models import (
    AgentRecord,
    AgentRegistrationIdempotency,
    Environment,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedOutboxMessage,
    PolicyBundle,
    Project,
    new_id,
    utcnow,
)
from acgs_control_plane.schemas import AgentRegisterRequest
from acgs_control_plane.trust import (
    InProcessPlatformIssuer,
    ManagedPlatformIssuer,
    ManagedReceiptContext,
    ManagedTrustError,
    active_trust_epoch_for_scope,
    mint_managed_decision_receipt_v2,
)

AGENT_REGISTRATION_AUTHORITY = "control-plane.agent-registration/v1"
AGENT_REGISTRATION_VALIDATOR_ROLE = "control-plane.agent-policy/v1"
AGENT_REGISTRATION_GOAL = "register managed agent in org registry"
# The action name this route used before it became a managed mutation. Policy
# bundles published against it must keep denying; see _evaluate_agent_policy.
LEGACY_AGENT_REGISTER_ACTION = "agent.register"
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
    # Set only when the refusal is a policy decision about an authenticated
    # principal and its refusal receipt is already committed. Admission,
    # scope, trust, and transaction errors leave these None: they cite no
    # receipt, and several are deliberately redacted. The response handler
    # keys the envelope off these, not off the status code.
    receipt_id: str | None = None
    decision: str | None = None


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
        audit_dir: Path,
        body: AgentRegisterRequest,
        idempotency_key: str | None = None,
    ) -> AgentRegistrationResult:
        idempotency_key = _normalize_idempotency_key(idempotency_key)
        args = _normalized_agent_args(body)
        with self._session_factory() as session:
            project, environment = _resolve_default_scope(session, org_id=org_id)
            policy, policy_bundle_id, policy_hash = _active_policy_context(session, org_id=org_id)
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
                # The refusal is final past this point, so mirror it onto the
                # org evidence surface inside the same transaction. The mirror
                # runs after the idempotency race check because it appends to
                # the file-backed audit chain, which does not roll back with
                # the database transaction: a replayed key must never append a
                # second refusal event.
                mirror_managed_decision(
                    tx_session,
                    org_id=context.org_id,
                    audit_dir=audit_dir,
                    record=decision_record,
                    tool=LEGACY_AGENT_REGISTER_ACTION,
                )

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
                    ) from exc
                raise AgentRegistrationHttpError(
                    503,
                    "TX_ABORTED",
                    "tx_aborted",
                    "agent registration refusal evidence transaction aborted",
                    stage="tx",
                ) from exc
            # The refusal receipt is committed above, so cite it. Dropping it
            # here would make the refusal path the one place this API produces
            # no citable evidence, which is backwards for a receipt-gated
            # control plane. Envelope matches the pre-managed v0 contract. The
            # detail stays the deterministic terminal one so an idempotent
            # replay can rebuild the identical terminal from the stored row.
            terminal = _terminal_http_error_for_decision(decision_record)
            raise AgentRegistrationHttpError(
                terminal.status_code,
                terminal.code,
                terminal.status,
                terminal.detail,
                stage=terminal.stage,
                receipt_id=receipt.receipt_id,
                decision=receipt.decision,
            )

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
            mirror_managed_decision(
                session,
                org_id=org_id,
                audit_dir=audit_dir,
                record=decision_record,
                result_hash=result.result_hash,
                tool=LEGACY_AGENT_REGISTER_ACTION,
            )
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
) -> AgentRegistrationResult:
    _assert_idempotency_row_integrity(session, row, idempotency)
    terminal = str(row.response.get("terminal"))
    if terminal in {"deny", "escalate"}:
        raise _replay_idempotency_response_error(row, idempotency)
    if terminal != "allow":
        raise _invalid_idempotency_record()
    return _result_from_idempotency_response(row.response)


def _replay_idempotency_response_new_session_result(
    session_factory: sessionmaker[Session],
    row: AgentRegistrationIdempotency,
    idempotency: _AgentRegistrationIdempotencyContext,
) -> AgentRegistrationResult:
    with session_factory() as session:
        fresh = session.get(AgentRegistrationIdempotency, row.id)
        if fresh is None:
            raise _invalid_idempotency_record()
        return _replay_idempotency_response(session, fresh, idempotency)


def _replay_idempotency_response_new_session_error(
    session_factory: sessionmaker[Session],
    row: AgentRegistrationIdempotency,
    idempotency: _AgentRegistrationIdempotencyContext,
) -> AgentRegistrationHttpError:
    with session_factory() as session:
        fresh = session.get(AgentRegistrationIdempotency, row.id)
        if fresh is None:
            return _invalid_idempotency_record()
        _assert_idempotency_row_integrity(session, fresh, idempotency)
        return _replay_idempotency_response_error(fresh, idempotency)


def _replay_idempotency_response_error(
    row: AgentRegistrationIdempotency,
    idempotency: _AgentRegistrationIdempotencyContext,
) -> AgentRegistrationHttpError:
    terminal = str(row.response.get("terminal"))
    if terminal not in {"deny", "escalate"}:
        return _invalid_idempotency_record()
    status_code = row.response.get("http_status")
    code = row.response.get("code")
    status = row.response.get("status")
    detail = row.response.get("detail")
    if (
        not isinstance(status_code, int)
        or not isinstance(code, str)
        or not isinstance(status, str)
        or not isinstance(detail, str)
    ):
        return _invalid_idempotency_record()
    _assert_same_idempotency_request(row, idempotency)
    return AgentRegistrationHttpError(
        status_code,
        code,
        status,
        detail,
        stage="policy",
    )


def _assert_idempotency_row_integrity(
    session: Session,
    row: AgentRegistrationIdempotency,
    idempotency: _AgentRegistrationIdempotencyContext,
) -> None:
    _assert_same_idempotency_request(row, idempotency)
    projection = idempotency.request_projection
    if (
        row.actor_hash != sha256_json(projection["actor"])
        or row.org_id != projection["org_id"]
        or row.project_id != projection["project_id"]
        or row.environment_id != projection["environment_id"]
    ):
        raise _invalid_idempotency_record()

    response = row.response
    terminal = str(response.get("terminal"))
    if response.get("org_id") != row.org_id or response.get("receipt_id") != row.receipt_id:
        raise _invalid_idempotency_record()
    if response.get("project_id") != row.project_id:
        raise _invalid_idempotency_record()
    if response.get("environment_id") != row.environment_id:
        raise _invalid_idempotency_record()

    receipt = session.scalars(
        sa.select(ManagedDecisionReceipt).where(
            ManagedDecisionReceipt.org_id == row.org_id,
            ManagedDecisionReceipt.project_id == row.project_id,
            ManagedDecisionReceipt.environment_id == row.environment_id,
            ManagedDecisionReceipt.receipt_id == row.receipt_id,
        )
    ).one_or_none()
    if receipt is None:
        raise _invalid_idempotency_record()
    if (
        receipt.actor != projection["actor"]
        or receipt.proposed_action != projection["action"]
        or receipt.argument_hash != sha256_json(projection["args"])
        or receipt.decision != terminal
    ):
        raise _invalid_idempotency_record()

    if terminal == "allow":
        if not isinstance(row.agent_id, str) or response.get("agent_id") != row.agent_id:
            raise _invalid_idempotency_record()
        agent = session.scalars(
            sa.select(AgentRecord).where(
                AgentRecord.org_id == row.org_id,
                AgentRecord.project_id == row.project_id,
                AgentRecord.environment_id == row.environment_id,
                AgentRecord.id == row.agent_id,
            )
        ).one_or_none()
        if agent is None:
            raise _invalid_idempotency_record()
    elif terminal in {"deny", "escalate"}:
        if row.agent_id is not None or response.get("agent_id") is not None:
            raise _invalid_idempotency_record()
    else:
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
    return {
        "schema": "agent-registration-idempotency-response/v1",
        "terminal": "allow",
        "http_status": 201,
        "agent_id": result.agent_id,
        "org_id": result.org_id,
        "project_id": context.project_id,
        "environment_id": context.environment_id,
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
    decision = "escalate" if terminal.code == "ESCALATE_PENDING" else "deny"
    return {
        "schema": "agent-registration-idempotency-response/v1",
        "terminal": decision,
        "http_status": terminal.status_code,
        "code": terminal.code,
        "status": terminal.status,
        "detail": terminal.detail,
        "agent_id": None,
        "org_id": context.org_id,
        "project_id": context.project_id,
        "environment_id": context.environment_id,
        "receipt_id": receipt_id,
    }


def _terminal_http_error_for_decision(record: DecisionRecord) -> AgentRegistrationHttpError:
    if record.decision is Decision.ESCALATE:
        return AgentRegistrationHttpError(
            202,
            "ESCALATE_PENDING",
            "escalate_pending",
            "agent registration requires separated approval",
            stage="policy",
        )
    if record.decision is Decision.DENY:
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


def _result_from_idempotency_response(response: Mapping[str, Any]) -> AgentRegistrationResult:
    return AgentRegistrationResult(
        agent_id=str(response["agent_id"]),
        org_id=str(response["org_id"]),
        name=str(response["name"]),
        description=str(response["description"]),
        trust_tier=str(response["trust_tier"]),
        allowed_tools=[str(tool) for tool in response["allowed_tools"]],
        status=str(response["status"]),
        created_at=_parse_response_datetime(str(response["created_at"])),
        receipt_id=str(response["receipt_id"]),
    )


def _parse_response_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return _to_utc(parsed)


def _to_utc(value: Any) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError("agent registration idempotency response timestamp must be a datetime")
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class _CommittedAgentRegistrationIdempotencyRace(RuntimeError):
    """Raised inside the SQL UoW after another request commits this key."""


def _active_policy_context(
    session: Session, *, org_id: str, lock: bool = False
) -> tuple[Any, str, str]:
    try:
        statement = sa.select(PolicyBundle).where(
            PolicyBundle.org_id == org_id,
            PolicyBundle.status == "active",
        )
        if lock:
            statement = statement.with_for_update()
        row = session.execute(statement).scalar_one_or_none()
    except MultipleResultsFound as exc:
        raise AgentRegistrationHttpError(
            409,
            "POLICY_NOT_READY",
            "policy_not_ready",
            "active policy bundle is not uniquely configured",
        ) from exc
    if row is None:
        raise AgentRegistrationHttpError(
            409,
            "POLICY_NOT_READY",
            "policy_not_ready",
            "active policy bundle is not configured",
        )
    from gove_zone.policy import RuleSetPolicy

    policy = RuleSetPolicy.from_dict(row.bundle)
    return policy, row.id, sha256_json(row.bundle)


def _normalized_agent_args(body: AgentRegisterRequest) -> dict[str, Any]:
    return {
        "name": body.name,
        "description": body.description,
        "trust_tier": body.trust_tier,
        "allowed_tools": list(body.allowed_tools),
    }


def _agent_policy_tool_call(name: str, *, args: Mapping[str, Any], actor: str) -> ToolCall:
    return ToolCall(
        name=name,
        args=dict(args),
        actor=actor,
        goal=AGENT_REGISTRATION_GOAL,
        path=normalize_path_context(["control-plane", "agents"]),
        state={"trust_tier": args.get("trust_tier", "")},
    )


def _record_refusal_evidence(
    session: Session,
    *,
    context: ManagedMutationContext,
    args: Mapping[str, Any],
    actor: str,
    decision_record: DecisionRecord,
    audit_dir: Path,
) -> None:
    """Re-check the policy under lock, then mirror the refusal for auditors.

    Order matters: revalidation may still abort the whole transaction, and a
    refusal that never became final must leave no trace on the org's evidence
    surface.
    """
    _revalidate_active_policy_under_lock(
        session,
        context=context,
        args=args,
        actor=actor,
        expected_decision=decision_record.decision,
    )
    mirror_managed_decision(
        session,
        org_id=context.org_id,
        audit_dir=audit_dir,
        record=decision_record,
        tool=LEGACY_AGENT_REGISTER_ACTION,
    )


def _evaluate_agent_policy(policy: Any, *, args: Mapping[str, Any], actor: str) -> DecisionRecord:
    """Decide agent creation under both the managed and the legacy action name.

    Governing this route renamed the action from ``agent.register`` to
    ``control-plane.agent.create``. Policy bundles an org already published name
    the old action, so evaluating only the new name would silently stop
    enforcing them -- an existing DENY would start returning 201. Both names are
    evaluated and the restrictive outcome wins, so the rename can only ever
    keep a refusal, never manufacture an approval.
    """
    managed = policy.evaluate(
        _agent_policy_tool_call(CONTROL_PLANE_AGENT_CREATE_ACTION, args=args, actor=actor)
    )
    if managed.decision is not Decision.ALLOW:
        return managed
    legacy = policy.evaluate(
        _agent_policy_tool_call(LEGACY_AGENT_REGISTER_ACTION, args=args, actor=actor)
    )
    if legacy.decision is not Decision.ALLOW:
        return legacy
    return managed


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
        session, org_id=context.org_id, lock=True
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
