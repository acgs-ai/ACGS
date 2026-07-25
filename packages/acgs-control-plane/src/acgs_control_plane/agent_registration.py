"""Canonical managed agent-registration service."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import timedelta
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
from acgs_control_plane.managed_mutations import (
    CONTROL_PLANE_AGENT_CREATE_ACTION,
    AesGcmReceiptArtifactSealer,
    ManagedMutationContext,
    ManagedMutationResult,
    ManagedMutationUnitOfWork,
    managed_mutation_execution_boundary,
)
from acgs_control_plane.models import (
    AgentRecord,
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
_GENESIS_AUDIT_HASH = "0" * 64
_LOCAL_AGENT_SIGNER_SEED = bytes.fromhex(
    "55df9db52ff7b9635dd2bbf66fbcb3fb3f70d6071359449f0d9f8ad1a3e8a9c4"
)


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
    ) -> AgentRegistrationResult:
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
                    request_id=new_id(),
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
            try:
                uow.record_non_executable_evidence(
                    context=context,
                    receipt=receipt,
                    args=args,
                    before_record=lambda tx_session: _revalidate_active_policy_under_lock(
                        tx_session,
                        context=context,
                        args=args,
                        actor=principal.actor_id,
                        expected_decision=decision_record.decision,
                    ),
                )
            except ReceiptAlreadyUsedError as exc:
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
                raise AgentRegistrationHttpError(
                    503,
                    "TX_ABORTED",
                    "tx_aborted",
                    "agent registration refusal evidence transaction aborted",
                    stage="tx",
                ) from exc
            if decision_record.decision is Decision.DENY:
                raise AgentRegistrationHttpError(
                    403,
                    "POLICY_DENIED",
                    "denied",
                    decision_record.reason or "agent registration denied by policy",
                )
            raise AgentRegistrationHttpError(
                202,
                "ESCALATE_PENDING",
                "pending_approval",
                decision_record.reason or "agent registration requires approval",
            )

        if decision_record.decision is not Decision.ALLOW:
            raise AgentRegistrationHttpError(
                403,
                "POLICY_DENIED",
                "denied",
                "agent registration refused by policy",
            )

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
            holder["response"] = AgentRegistrationResult(
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

        try:
            uow.execute(
                context=context,
                receipt=receipt,
                args=args,
                before_execute=lambda tx_session: _revalidate_active_policy_under_lock(
                    tx_session,
                    context=context,
                    args=args,
                    actor=principal.actor_id,
                ),
                operation_effect=operation_effect,
                after_success=after_success,
            )
        except IntegrityError as exc:
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
