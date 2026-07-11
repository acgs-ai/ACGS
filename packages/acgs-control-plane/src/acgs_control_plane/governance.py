"""The governance membrane: control-plane mutations dispatch through gove-zone.

Core invariant, made literal for the platform itself:

    **No valid Decision Receipt, no side effect.**

Every mutating control-plane operation (register agent, publish policy,
activate policy, create user, generate export, ...) is registered as a kernel
tool and executed via :meth:`gove_zone.Kernel.dispatch` under the
organization's *active* policy bundle. The receipt — ALLOW, DENY, or
ESCALATE — is persisted in the same transaction as the side effect. A DENY
or ESCALATE rolls the transaction back, persists only the receipt, and maps
to HTTP 403 / 202.

The org's audit chain is a per-org ``ChainHashAuditStore`` file; its tip
(count + last hash) is anchored in the ``organizations`` row on every
dispatch so file-level truncation is detectable from the database.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol

from gove_zone import (
    ChainHashAuditStore,
    DeniedError,
    EscalateError,
    Kernel,
    Receipt,
)
from gove_zone.decision import Decision, DecisionRecord
from gove_zone.policy import Policy, PolicyRule, RuleSetPolicy
from gove_zone.tool import ToolCall, normalize_path_context
from sqlalchemy import select
from sqlalchemy.orm import Session

from acgs_control_plane.auth import Principal
from acgs_control_plane.models import Organization, PolicyBundle, ReceiptRow

BASELINE_POLICY_ID = "acp-baseline/v1"


class ExecutionClass(StrEnum):
    LEGACY_UNSIGNED_WRITE = "legacy_unsigned_write"
    READ_ONLY_OPERATION = "read_only_operation"
    PROTOCOL_OPERATION = "protocol_operation"
    CANONICAL_MANAGED_WRITE = "canonical_managed_write"


@dataclass(frozen=True)
class RouteContract:
    method: str
    path: str
    execution_class: ExecutionClass
    action: str | None = None
    permits_persistent_effect: bool = False
    permits_filesystem_effect: bool = False
    permits_external_effect: bool = False


_READ_PATHS = (
    ("GET", "/orgs/{org_id}"),
    ("GET", "/orgs/{org_id}/users"),
    ("GET", "/orgs/{org_id}/agents"),
    ("GET", "/orgs/{org_id}/agents/{agent_id}"),
    ("GET", "/orgs/{org_id}/policies"),
    ("POST", "/orgs/{org_id}/policies/simulate"),
    ("GET", "/orgs/{org_id}/receipts"),
    ("GET", "/orgs/{org_id}/receipts/{receipt_id}"),
    ("POST", "/orgs/{org_id}/receipts/{receipt_id}/verify"),
    ("GET", "/orgs/{org_id}/dashboard"),
    ("GET", "/orgs/{org_id}/exports"),
    ("GET", "/orgs/{org_id}/exports/{export_id}"),
)
_LEGACY_WRITES = (
    ("POST", "/orgs", "org.create"),
    ("POST", "/orgs/{org_id}/users", "user.create"),
    ("POST", "/orgs/{org_id}/agents", "agent.register"),
    ("PATCH", "/orgs/{org_id}/agents/{agent_id}/status", "agent.set_status"),
    ("POST", "/orgs/{org_id}/policies", "policy.publish"),
    ("POST", "/orgs/{org_id}/policies/{bundle_id}/activate", "policy.activate"),
    ("POST", "/orgs/{org_id}/exports", "export.generate"),
)
ROUTE_CONTRACTS: tuple[RouteContract, ...] = (
    RouteContract("GET", "/healthz", ExecutionClass.PROTOCOL_OPERATION),
    RouteContract("GET", "/readyz", ExecutionClass.PROTOCOL_OPERATION),
    *(RouteContract(m, p, ExecutionClass.READ_ONLY_OPERATION) for m, p in _READ_PATHS),
    *(
        RouteContract(m, p, ExecutionClass.LEGACY_UNSIGNED_WRITE, a, True, True)
        for m, p, a in _LEGACY_WRITES
    ),
)


@dataclass(frozen=True, order=True)
class PostureBlocker:
    code: str
    component: str
    route: str | None = None
    execution_class: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "code": self.code,
            "component": self.component,
            "route": self.route,
            "execution_class": self.execution_class,
        }


class ProductionPostureBlocked(RuntimeError):
    code = "PRODUCTION_POSTURE_BLOCKED"
    stage = "pre-persistence"

    def __init__(self, blockers: Sequence[PostureBlocker]) -> None:
        self.blockers = tuple(sorted(blockers))
        self.contract: Any | None = None
        super().__init__(
            json.dumps(
                {
                    "code": self.code,
                    "stage": self.stage,
                    "blockers": [b.to_dict() for b in self.blockers],
                },
                sort_keys=True,
            )
        )


def reconcile_route_contracts(actual: Sequence[tuple[str, str]]) -> tuple[PostureBlocker, ...]:
    expected = [(r.method, r.path) for r in ROUTE_CONTRACTS]
    blockers: list[PostureBlocker] = []
    for key in sorted(set(actual) | set(expected)):
        if expected.count(key) != 1 or actual.count(key) != 1:
            blockers.append(
                PostureBlocker("ROUTE_CONTRACT_DRIFT", "route-registry", f"{key[0]} {key[1]}")
            )
    for key in sorted(set(actual) - set(expected)):
        blockers.append(
            PostureBlocker("UNCLASSIFIED_ROUTE", "route-registry", f"{key[0]} {key[1]}")
        )
    return tuple(blockers)


class ProviderPreflight(Protocol):
    def preflight(self) -> SealedProviderStatus: ...


_PROVIDER_SEAL = object()


@dataclass(frozen=True)
class SealedProviderStatus:
    component: str
    ready: bool
    _seal: object

    @classmethod
    def from_provider(cls, component: str, ready: bool) -> SealedProviderStatus:
        return cls(component, ready, _PROVIDER_SEAL)

    def __post_init__(self) -> None:
        if self._seal is not _PROVIDER_SEAL:
            raise ValueError("provider status must be issued by the server provider boundary")


def production_blockers(
    route_drift: Sequence[PostureBlocker], providers: Sequence[ProviderPreflight] = ()
) -> tuple[PostureBlocker, ...]:
    blockers = list(route_drift)
    legacy = [
        PostureBlocker(
            "LEGACY_UNSIGNED_WRITE",
            "governance-membrane",
            f"{r.method} {r.path}",
            r.execution_class.value,
        )
        for r in ROUTE_CONTRACTS
        if r.execution_class is ExecutionClass.LEGACY_UNSIGNED_WRITE
    ]
    blockers.extend(legacy)
    required = {"signer-issuer", "trust-verifier", "durable-consumption-uow", "migration-head"}
    if legacy:
        # Do not cross provider boundaries while a local invariant already
        # proves production impossible. This is a pre-persistence short circuit.
        blockers.extend(PostureBlocker("PROVIDER_PREFLIGHT_SKIPPED", c) for c in sorted(required))
        return tuple(sorted(blockers))
    statuses = [p.preflight() for p in providers]
    ready = {s.component for s in statuses if s.ready and s._seal is _PROVIDER_SEAL}
    blockers.extend(PostureBlocker("PROVIDER_NOT_READY", c) for c in sorted(required - ready))
    return tuple(sorted(blockers))


_CONTEXT_SEAL = object()


@dataclass(frozen=True)
class AuthenticatedRuntimeContext:
    actor: str
    tenant: str
    project: str
    environment: str
    authentication_method: str
    authority_domain: str
    validated_at: str
    _seal: object

    @classmethod
    def from_server_provider(cls, **bindings: str) -> AuthenticatedRuntimeContext:
        return cls(**bindings, _seal=_CONTEXT_SEAL)

    def __post_init__(self) -> None:
        if self._seal is not _CONTEXT_SEAL:
            raise ValueError("runtime context must be issued by server authentication")


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(k): _freeze(v) for k, v in sorted(value.items())})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    return value


@dataclass(frozen=True)
class ManagedMutationContract:
    contract: str
    action: str
    execution_boundary: str
    context: AuthenticatedRuntimeContext
    canonical_arguments: Mapping[str, Any]
    argument_hash: str
    authority: str
    validator: str
    policy_id: str
    policy_version: str
    policy_hash: str
    issued_at: str
    expires_at: str
    key_id: str
    audit_anchor: str
    idempotency_key: str
    canonical_path_enabled: bool = False


_FORBIDDEN_BODY_BINDINGS = frozenset(
    {
        "actor",
        "tenant",
        "org_id",
        "project",
        "environment",
        "authority",
        "validator",
        "policy_id",
        "policy_version",
        "policy_hash",
        "execution_boundary",
        "idempotency_key",
    }
)


def managed_contract_stub(
    contract: str,
    body: Mapping[str, Any],
    context: AuthenticatedRuntimeContext,
    *,
    providers: Sequence[ProviderPreflight],
    bindings: Mapping[str, str],
    decision: str,
    mutation: Callable[[], Any] | None = None,
) -> ManagedMutationContract:
    if not isinstance(context, AuthenticatedRuntimeContext) or context._seal is not _CONTEXT_SEAL:
        raise TypeError("typed authenticated runtime context required")
    forbidden = sorted(_FORBIDDEN_BODY_BINDINGS & body.keys())
    if forbidden:
        raise ValueError(f"caller-controlled server bindings: {','.join(forbidden)}")
    statuses = [p.preflight() for p in providers]
    if not statuses or any(not s.ready or s._seal is not _PROVIDER_SEAL for s in statuses):
        raise RuntimeError("trusted providers not ready")
    frozen = _freeze(body)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    actions = {
        "tenant.bootstrap/v1": ("tenant.bootstrap", "control-plane:tenant.bootstrap/v1"),
        "agent.register/v1": ("agent.register", "control-plane:agent.register/v1"),
    }
    if contract not in actions:
        raise ValueError("unknown managed contract")
    action, boundary = actions[contract]
    required_bindings = {
        "authority",
        "validator",
        "policy_id",
        "policy_version",
        "policy_hash",
        "issued_at",
        "expires_at",
        "key_id",
        "audit_anchor",
        "idempotency_key",
    }
    missing = sorted(required_bindings - bindings.keys())
    if missing:
        raise ValueError(f"missing server bindings: {','.join(missing)}")
    shape = ManagedMutationContract(
        contract=contract,
        action=action,
        execution_boundary=boundary,
        context=context,
        canonical_arguments=frozen,
        argument_hash=hashlib.sha256(canonical.encode()).hexdigest(),
        authority=bindings["authority"],
        validator=bindings["validator"],
        policy_id=bindings["policy_id"],
        policy_version=bindings["policy_version"],
        policy_hash=bindings["policy_hash"],
        issued_at=bindings["issued_at"],
        expires_at=bindings["expires_at"],
        key_id=bindings["key_id"],
        audit_anchor=bindings["audit_anchor"],
        idempotency_key=bindings["idempotency_key"],
    )
    del decision, mutation
    # DENY, ESCALATE, and even apparently valid ALLOW stop here. P1/P2 own execution.
    error = ProductionPostureBlocked(
        (
            PostureBlocker(
                "CANONICAL_PATH_NOT_ENABLED",
                contract,
                execution_class=ExecutionClass.CANONICAL_MANAGED_WRITE.value,
            ),
        )
    )
    error.contract = shape
    raise error


def baseline_policy() -> RuleSetPolicy:
    """Default governance when an org has no active bundle yet.

    ``RuleSetPolicy`` is allow-by-default (rules can only deny/escalate), so
    the baseline ships one protective rule instead of a no-op: destructive
    org-level operations escalate until an explicit policy says otherwise.
    """
    return RuleSetPolicy(
        policy_id=BASELINE_POLICY_ID,
        rules=(
            PolicyRule(
                rule_id="baseline-escalate-org-destructive",
                effect=Decision.ESCALATE,
                tools=frozenset({"org.delete", "org.purge"}),
                reason="destructive org operations require explicit policy + approval",
            ),
        ),
    )


def load_active_policy(session: Session, org_id: str) -> Policy:
    row = session.execute(
        select(PolicyBundle).where(PolicyBundle.org_id == org_id, PolicyBundle.status == "active")
    ).scalar_one_or_none()
    if row is None:
        return baseline_policy()
    return RuleSetPolicy.from_dict(row.bundle)


def org_audit_store(audit_dir: Path, org_id: str) -> ChainHashAuditStore:
    audit_dir.mkdir(parents=True, exist_ok=True)
    return ChainHashAuditStore(audit_dir / f"{org_id}.audit.jsonl")


def existing_org_audit_store(audit_dir: Path, org_id: str) -> ChainHashAuditStore | None:
    """Open an existing chain for reads without creating directories or files."""
    path = audit_dir / f"{org_id}.audit.jsonl"
    if not path.is_file():
        return None
    return ChainHashAuditStore(path)


def chain_tip(store: ChainHashAuditStore) -> tuple[int, str]:
    """Single pass over the chain file: (event_count, last_event_hash)."""
    count = 0
    last = ""
    for event in store.iter_events():
        count += 1
        last = str(event.get("event_hash", ""))
    return count, last


@dataclass(frozen=True)
class GovernedOutcome:
    """What a governed mutation produced: a result (ALLOW only) + receipt row."""

    result: Any
    receipt: ReceiptRow
    decision: str


class PolicyDeniedError(Exception):
    """Mutation denied by the org's policy bundle. Receipt row is committed."""

    def __init__(self, receipt: ReceiptRow, reason: str) -> None:
        self.receipt = receipt
        self.reason = reason
        super().__init__(reason)


class PolicyEscalatedError(Exception):
    """Mutation requires approval. Receipt row is committed; nothing executed."""

    def __init__(self, receipt: ReceiptRow, reason: str) -> None:
        self.receipt = receipt
        self.reason = reason
        super().__init__(reason)


def _receipt_row_from_payload(org_id: str, payload: dict[str, Any]) -> ReceiptRow:
    return ReceiptRow(
        id=str(payload["event_id"]),
        org_id=org_id,
        tool=str(payload["tool"]),
        decision=str(payload["decision"]),
        actor=str(payload.get("actor", "")),
        goal=str(payload.get("goal", "")),
        argument_hash=str(payload.get("argument_hash", "")),
        audit_hash=str(payload.get("audit_hash", "")),
        policy_version=str(payload.get("policy_version", "")),
        result_hash=payload.get("result_hash"),
        error_class=payload.get("error_class"),
        payload=payload,
    )


def _blocked_payload(record: DecisionRecord, audit_hash: str) -> dict[str, Any]:
    return {
        **record.to_dict(),
        "audit_hash": audit_hash,
        "actor": record.actor,
        "result_hash": None,
        "error_class": None,
    }


def _anchor(session: Session, org_id: str, store: ChainHashAuditStore) -> None:
    """Advance the org's chain-tip anchor — never regress it.

    The file append is serialized by the audit store's flock, but two
    concurrent requests can commit their DB anchors out of order. The row
    lock (``with_for_update``; no-op on SQLite, row-level on PostgreSQL)
    serializes writers, and the monotonic guard makes a stale reader skip
    rather than regress the anchor below the true chain length — a regressed
    anchor would make ``verify_chain`` falsely report a healthy chain as
    truncated.
    """
    count, last = chain_tip(store)
    org = session.get(Organization, org_id, with_for_update=True)
    if org is not None and count >= org.audit_anchor_count:
        org.audit_anchor_count = count
        org.audit_anchor_hash = last


class GovernanceMembrane:
    """Per-request bridge between one org's HTTP mutations and its kernel."""

    def __init__(
        self,
        session: Session,
        audit_dir: Path,
        org_id: str,
        principal: Principal,
    ) -> None:
        self.session = session
        self.org_id = org_id
        self.principal = principal
        self.store = org_audit_store(audit_dir, org_id)
        self.kernel = Kernel(
            policy=load_active_policy(session, org_id),
            audit=self.store,
            actor=principal.actor_id,
        )

    def run(
        self,
        tool_name: str,
        args: Mapping[str, Any],
        fn: Callable[..., Any],
        *,
        goal: str = "",
        path: Sequence[str] = (),
        state: Mapping[str, Any] | None = None,
        persist_blocked_row: bool = True,
    ) -> GovernedOutcome:
        """Dispatch ``fn`` as governed tool ``tool_name``; commit receipt + effect atomically.

        On ALLOW: side effect + receipt row + audit anchor commit together.
        On DENY/ESCALATE: session is rolled back first, then ONLY the receipt
        row + anchor are committed, and a typed error is raised for the HTTP
        layer to map (403 / 202).

        ``persist_blocked_row=False`` is for the genesis dispatch only: when
        the governed mutation *creates the org itself*, a rolled-back DENY /
        ESCALATE leaves no ``organizations`` row for the receipt to reference,
        so persisting one would dangle its foreign key (an IntegrityError on
        PostgreSQL). The decision is still on the org's audit chain file; only
        the queryable DB row is skipped.
        """
        self.kernel.registry.register(tool_name, fn)
        call_state = {"principal_role": self.principal.role.value, **dict(state or {})}
        try:
            result, receipt = self.kernel.dispatch(
                tool_name,
                dict(args),
                goal=goal,
                path=list(path),
                state=call_state,
            )
        except DeniedError as exc:
            row = self._commit_blocked(
                _blocked_payload(exc.record, exc.audit_hash), persist_blocked_row
            )
            raise PolicyDeniedError(row, exc.record.reason) from exc
        except EscalateError as exc:
            row = self._commit_blocked(
                _blocked_payload(exc.record, exc.audit_hash), persist_blocked_row
            )
            raise PolicyEscalatedError(row, exc.record.reason) from exc
        except Exception as exc:
            # Tool execution failed after ALLOW: the kernel appended a
            # synthesized ":failure" DENY event to the audit chain
            # (best-effort). No partial side effect may survive, and the
            # failure must stay visible in the queryable receipts store —
            # these are exactly the receipts a compliance review needs.
            self.session.rollback()
            self._persist_failure_row(tool_name, exc)
            _anchor(self.session, self.org_id, self.store)
            self.session.commit()
            raise

        row = self._persist_allowed(receipt)
        return GovernedOutcome(result=result, receipt=row, decision=row.decision)

    def _commit_blocked(self, payload: dict[str, Any], persist_row: bool) -> ReceiptRow:
        """Rollback the blocked mutation, commit only the receipt + anchor."""
        self.session.rollback()
        row = _receipt_row_from_payload(self.org_id, payload)
        if persist_row:
            self.session.add(row)
            _anchor(self.session, self.org_id, self.store)
            self.session.commit()
        return row

    def _persist_failure_row(self, tool_name: str, exc: Exception) -> None:
        """Mirror the kernel's synthesized execution-failure event into the DB.

        The kernel's append is best-effort (suppressed on error), so only
        persist a row when the failure event actually reached the chain.
        """
        last_event: dict[str, Any] | None = None
        for event in self.store.iter_events():
            last_event = event
        if (
            last_event is None
            or last_event.get("tool") != tool_name
            or not str(last_event.get("event_id", "")).endswith(":failure")
        ):
            return
        payload = {
            **last_event,
            "audit_hash": str(last_event.get("event_hash", "")),
            "result_hash": None,
            "error_class": type(exc).__name__,
        }
        self.session.add(_receipt_row_from_payload(self.org_id, payload))

    def _persist_allowed(self, receipt: Receipt) -> ReceiptRow:
        row = _receipt_row_from_payload(self.org_id, receipt.to_dict())
        self.session.add(row)
        _anchor(self.session, self.org_id, self.store)
        self.session.commit()
        return row

    def simulate_decision(
        self,
        tool_name: str,
        args: Mapping[str, Any],
        *,
        actor: str,
        goal: str = "",
        path: Sequence[str] = (),
        state: Mapping[str, Any] | None = None,
    ) -> DecisionRecord:
        """Pure policy preview: evaluate without executing or auditing."""
        call = ToolCall(
            name=tool_name,
            args=dict(args),
            goal=goal,
            actor=actor,
            path=normalize_path_context(list(path)),
            state=dict(state or {}),
        )
        return self.kernel.policy.evaluate(call)
