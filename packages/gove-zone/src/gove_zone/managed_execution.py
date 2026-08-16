"""Receipt-gated execution routing for :class:`ManagedAgent` side effects.

This module only composes the existing strict authorization kernel and final
receipt-gated executor. It does not define another policy, receipt, audit, or
consumption system.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from threading import RLock
from typing import Any, NoReturn, Protocol, cast, runtime_checkable

from gove_zone.authorization import (
    AuthorizationError,
    AuthorizationReasonCode,
    ExecutionRefusalEvidence,
    RefusalEvidence,
    SideEffectExecutionContext,
    SideEffectExecutionError,
    SideEffectRequest,
    deep_freeze_json,
    deep_thaw_json,
    goal_receipt_claim,
    strict_json_hash,
    validate_strict_json_budget,
)
from gove_zone.decision import Decision
from gove_zone.receipt import DecisionReceipt
from gove_zone.side_effect_kernel import (
    AdapterOutcome,
    AdapterOutcomeStatus,
    ReceiptGatedSideEffectExecutor,
    SideEffectAuthorizationKernel,
)
from gove_zone.tool import normalize_path_context


def _text(value: object, field_name: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _frozen_object(value: Mapping[str, Any], field_name: str) -> Mapping[str, Any]:
    validate_strict_json_budget(value)
    frozen = deep_freeze_json(dict(value))
    if not isinstance(frozen, Mapping):
        raise TypeError(f"{field_name} must be a strict JSON object")
    return cast(Mapping[str, Any], frozen)


@dataclass(frozen=True, slots=True)
class ManagedExecutionRoute:
    """Trusted, fixed adapter route for one managed tool name."""

    name: str
    server_id: str
    tool: str
    operation: str
    resource: str
    environment: str
    execution_boundary: str
    side_effect_class: str = "high-risk"

    def __post_init__(self) -> None:
        for field_name in (
            "name",
            "server_id",
            "tool",
            "operation",
            "resource",
            "environment",
            "execution_boundary",
            "side_effect_class",
        ):
            object.__setattr__(self, field_name, _text(getattr(self, field_name), field_name))


@dataclass(frozen=True, slots=True)
class ManagedExecutionProposal:
    """Untrusted call proposal passed to a trusted input provider."""

    name: str
    args: Mapping[str, Any] = field(default_factory=dict, repr=False)
    goal: str = field(default="", repr=False)
    path: tuple[str, ...] = ()
    state: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _text(self.name, "name"))
        if type(self.goal) is not str:
            raise TypeError("goal must be a string")
        object.__setattr__(self, "args", _frozen_object(self.args, "args"))
        object.__setattr__(self, "path", normalize_path_context(self.path))
        object.__setattr__(self, "state", _frozen_object(self.state, "state"))


@dataclass(frozen=True, slots=True)
class ManagedExecutionInputs:
    """Trusted request and execution context built for one proposal."""

    request: SideEffectRequest
    context: SideEffectExecutionContext

    def __post_init__(self) -> None:
        if not isinstance(self.request, SideEffectRequest):
            raise TypeError("request must be a SideEffectRequest")
        if not isinstance(self.context, SideEffectExecutionContext):
            raise TypeError("context must be a SideEffectExecutionContext")


@runtime_checkable
class ManagedExecutionProvider(Protocol):
    """Trusted identity, policy-reference, and evidence input provider."""

    def prepare(
        self,
        proposal: ManagedExecutionProposal,
        route: ManagedExecutionRoute,
    ) -> ManagedExecutionInputs: ...


@dataclass(frozen=True, slots=True)
class ManagedExecutionResult:
    """Successful payload plus the exact authorizing receipt and audit event."""

    payload: Any
    receipt: DecisionReceipt
    audit_event_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, DecisionReceipt):
            raise TypeError("receipt must be a DecisionReceipt")
        object.__setattr__(self, "audit_event_id", _text(self.audit_event_id, "audit_event_id"))
        if self.receipt.receipt_id != self.audit_event_id:
            raise ValueError("receipt and audit event identifiers must match")

    def __iter__(self) -> Iterator[Any]:
        """Preserve the SDK's historical ``result, receipt`` unpacking shape."""
        yield self.payload
        yield self.receipt


class ManagedExecutionRefusal(RuntimeError):
    """Fail-closed managed execution result retaining available refusal proof.

    ``evidence`` keeps its existing meaning: authorization-level
    :class:`RefusalEvidence`. When the refusal came from the final execution
    gate, the executor's own :class:`ExecutionRefusalEvidence` is additionally
    carried verbatim on ``execution_refusal_evidence`` — it is the only proof
    bound to the exact receipted attempt, and it is exposed rather than replaced
    so a consumer can verify it independently.
    """

    def __init__(
        self,
        *,
        decision: Decision,
        reason_codes: Sequence[str],
        evidence: RefusalEvidence | None = None,
        execution_refusal_evidence: ExecutionRefusalEvidence | None = None,
        receipt: DecisionReceipt | None = None,
        audit_event_id: str = "",
    ) -> None:
        if decision not in {Decision.DENY, Decision.ESCALATE}:
            raise ValueError("managed refusal must be DENY or ESCALATE")
        reasons = tuple(_text(item, "reason code") for item in reason_codes)
        if not reasons:
            raise ValueError("managed refusal requires at least one reason code")
        if evidence is not None and not isinstance(evidence, RefusalEvidence):
            raise TypeError("evidence must be RefusalEvidence")
        if execution_refusal_evidence is not None and not isinstance(
            execution_refusal_evidence,
            ExecutionRefusalEvidence,
        ):
            raise TypeError("execution_refusal_evidence must be ExecutionRefusalEvidence")
        if receipt is not None and not isinstance(receipt, DecisionReceipt):
            raise TypeError("receipt must be DecisionReceipt")
        self.decision = decision
        self.reason_codes = reasons
        self.evidence = evidence
        self.execution_refusal_evidence = execution_refusal_evidence
        self.receipt = receipt
        self.audit_event_id = audit_event_id
        # Status is reported from the evidence itself, never asserted: an
        # unaudited or unsigned refusal must stay visibly unproven.
        self.execution_audit_event_id = (
            "" if execution_refusal_evidence is None else execution_refusal_evidence.audit_event_id
        )
        self.execution_evidence_audited = (
            False if execution_refusal_evidence is None else execution_refusal_evidence.audited
        )
        self.execution_evidence_signed = (
            False if execution_refusal_evidence is None else execution_refusal_evidence.signed
        )
        super().__init__(reasons[0])

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-safe refusal with both proofs kept separate and exact.

        The two proofs answer different questions and are never merged: the
        authorization refusal on ``evidence``/``audit_event_id`` answers "was
        this request allowed?", while the execution refusal keeps its own audit
        identity and answers "did this receipted attempt run?". Each is emitted
        verbatim so a consumer can verify either on its own, and the status
        fields report only what the evidence actually carries — a refusal that
        could not be proved stays visibly unproven here.
        """

        execution = self.execution_refusal_evidence
        return {
            "decision": self.decision.value,
            "reason_codes": list(self.reason_codes),
            "audit_event_id": self.audit_event_id or None,
            "evidence": None if self.evidence is None else self.evidence.to_dict(),
            "receipt": None if self.receipt is None else self.receipt.to_dict(),
            "execution_refusal_evidence": None if execution is None else execution.to_dict(),
            "execution_refusal_audit_event_id": self.execution_audit_event_id or None,
            "execution_refusal_audited": self.execution_evidence_audited,
            "execution_refusal_signed": self.execution_evidence_signed,
        }


class ManagedExecutionDispatcher:
    """Fixed-route bridge from managed tools to the shared receipt membrane."""

    def __init__(
        self,
        *,
        routes: Sequence[ManagedExecutionRoute],
        provider: ManagedExecutionProvider,
        authorizer: SideEffectAuthorizationKernel,
        executor: ReceiptGatedSideEffectExecutor,
    ) -> None:
        if isinstance(routes, (str, bytes)) or not routes:
            raise ValueError("routes must be a non-empty sequence")
        route_map: dict[str, ManagedExecutionRoute] = {}
        execution_routes: set[tuple[str, str, str]] = set()
        for route in routes:
            if not isinstance(route, ManagedExecutionRoute):
                raise TypeError("routes must contain ManagedExecutionRoute values")
            execution_route = (route.server_id, route.tool, route.operation)
            if route.name in route_map or execution_route in execution_routes:
                raise ValueError("managed execution routes must be unique")
            route_map[route.name] = route
            execution_routes.add(execution_route)
        if not isinstance(provider, ManagedExecutionProvider):
            raise TypeError("provider must implement ManagedExecutionProvider")
        if not isinstance(authorizer, SideEffectAuthorizationKernel):
            raise TypeError("authorizer must be SideEffectAuthorizationKernel")
        if not isinstance(executor, ReceiptGatedSideEffectExecutor):
            raise TypeError("executor must be ReceiptGatedSideEffectExecutor")
        self._routes = route_map
        self._provider = provider
        self._authorizer = authorizer
        self._executor = executor
        self._registered: set[str] = set()
        self._frozen = False
        self._lock = RLock()

    def register_adapter(self, name: str, adapter: Callable[..., Any]) -> None:
        """Register one real adapter before the first dispatch attempt."""
        name = _text(name, "name")
        if not callable(adapter):
            raise TypeError("adapter must be callable")
        with self._lock:
            if self._frozen:
                raise RuntimeError(
                    "managed adapter registry is frozen after first dispatch attempt"
                )
            route = self._routes.get(name)
            if route is None:
                raise KeyError(f"no fixed managed route for tool: {name!r}")
            if name in self._registered:
                raise ValueError(f"managed adapter is already registered: {name!r}")

            def confirmed_adapter(**kwargs: Any) -> AdapterOutcome:
                outcome = adapter(**kwargs)
                if isinstance(outcome, AdapterOutcome):
                    return outcome
                return AdapterOutcome(AdapterOutcomeStatus.CONFIRMED_SUCCEEDED, outcome)

            self._executor.register_adapter(
                route.server_id,
                route.tool,
                route.operation,
                confirmed_adapter,
            )
            self._registered.add(name)

    def dispatch(self, proposal: ManagedExecutionProposal) -> ManagedExecutionResult:
        """Authorize and immediately execute one fixed-route proposal."""
        if not isinstance(proposal, ManagedExecutionProposal):
            raise TypeError("proposal must be ManagedExecutionProposal")
        with self._lock:
            self._frozen = True
            route = self._routes.get(proposal.name)
            registered = proposal.name in self._registered
        if route is None or not registered:
            self._raise_invalid_refusal(proposal, "managed.route_unavailable")

        try:
            inputs = self._provider.prepare(proposal, route)
            self._validate_inputs(proposal, route, inputs)
        except ManagedExecutionRefusal:
            raise
        except Exception:
            self._raise_invalid_refusal(proposal, "managed.provider_failed")

        try:
            authorization = self._authorizer.authorize(inputs.request)
        except AuthorizationError as exc:
            raise ManagedExecutionRefusal(
                decision=Decision.DENY,
                reason_codes=(exc.reason_code.value,),
                evidence=exc.evidence,
                audit_event_id=exc.evidence.audit_event_id if exc.evidence is not None else "",
            ) from None
        except Exception:
            self._raise_invalid_refusal(proposal, "managed.authorization_failed")

        if not authorization.executable or authorization.receipt is None:
            raise ManagedExecutionRefusal(
                decision=authorization.decision,
                reason_codes=tuple(code.value for code in authorization.reason_codes),
                receipt=authorization.receipt,
                audit_event_id=authorization.audit_event_id,
            )

        try:
            payload = self._executor.execute(
                authorization,
                inputs.context,
                nonce=inputs.request.nonce,
                idempotency_key=inputs.request.idempotency_key,
            )
        except SideEffectExecutionError as exc:
            evidence = self._execution_refusal_evidence(inputs.request, exc)
            raise ManagedExecutionRefusal(
                decision=Decision.DENY,
                reason_codes=(exc.reason_code.value,),
                evidence=evidence,
                # The executor's own proof is the only one bound to this exact
                # receipted attempt; it is preserved, not replaced.
                execution_refusal_evidence=exc.evidence,
                audit_event_id=evidence.audit_event_id if evidence is not None else "",
            ) from None
        except Exception:
            evidence = self._execution_refusal_evidence(inputs.request, None)
            raise ManagedExecutionRefusal(
                decision=Decision.DENY,
                reason_codes=("managed.execution_failed",),
                evidence=evidence,
                audit_event_id=evidence.audit_event_id if evidence is not None else "",
            ) from None

        return ManagedExecutionResult(
            payload=payload,
            receipt=authorization.receipt,
            audit_event_id=authorization.audit_event_id,
        )

    def _validate_inputs(
        self,
        proposal: ManagedExecutionProposal,
        route: ManagedExecutionRoute,
        inputs: ManagedExecutionInputs,
    ) -> None:
        if not isinstance(inputs, ManagedExecutionInputs):
            raise TypeError("provider returned invalid managed execution inputs")
        request = inputs.request
        context = inputs.context
        if (
            request.server_id,
            request.tool,
            request.operation,
            request.resource,
            request.environment,
            request.execution_boundary,
            request.side_effect_class,
        ) != (
            route.server_id,
            route.tool,
            route.operation,
            route.resource,
            route.environment,
            route.execution_boundary,
            route.side_effect_class,
        ):
            raise ValueError("trusted request does not match the fixed managed route")
        if strict_json_hash(deep_thaw_json(request.args)) != strict_json_hash(
            deep_thaw_json(proposal.args)
        ):
            raise ValueError("trusted request arguments do not match the proposal")
        if request.goal != proposal.goal:
            raise ValueError("trusted request goal does not match the proposal")
        if (
            context.request_id,
            context.tenant_id,
            context.actor_id,
            context.actor_role,
            context.authority,
            context.server_id,
            context.tool,
            context.operation,
            context.resource,
            context.environment,
            context.execution_boundary,
            context.policy_ref,
        ) != (
            request.request_id,
            request.tenant_id,
            request.actor_id,
            request.actor_role,
            request.authority,
            request.server_id,
            request.tool,
            request.operation,
            request.resource,
            request.environment,
            request.execution_boundary,
            request.policy_ref,
        ):
            raise ValueError("trusted execution context does not match the request")

    def _raise_invalid_refusal(
        self,
        proposal: ManagedExecutionProposal,
        reason_code: str,
    ) -> NoReturn:
        evidence: RefusalEvidence | None = None
        try:
            self._authorizer.authorize(cast(SideEffectRequest, proposal))
        except AuthorizationError as exc:
            evidence = exc.evidence
        except Exception:
            pass
        raise ManagedExecutionRefusal(
            decision=Decision.DENY,
            reason_codes=(reason_code,),
            evidence=evidence,
            audit_event_id=evidence.audit_event_id if evidence is not None else "",
        )

    def _execution_refusal_evidence(
        self,
        request: SideEffectRequest,
        error: SideEffectExecutionError | None,
    ) -> RefusalEvidence | None:
        exact_reason = (
            error.reason_code.value if error is not None else "execution.internal_failure"
        )
        try:
            return self._authorizer.record_refusal(
                request_id=request.request_id,
                reason_code=AuthorizationReasonCode.INTERNAL_FAILURE,
                decision=Decision.DENY,
                exact_reason_codes=(exact_reason,),
                claimed_tenant_id=request.tenant_id,
                claimed_actor_id=request.actor_id,
                operation=request.operation,
                # ``request.args`` is deep-frozen; the strict canonicalizer only
                # accepts plain JSON, so hashing it directly always raised and
                # silently discarded the refusal evidence for every execution
                # refusal. Thaw first, exactly as _validate_inputs does.
                argument_hash=strict_json_hash(deep_thaw_json(request.args)),
                policy_digest=request.policy_ref.digest,
                policy_version=request.policy_ref.version,
                principal_verified=True,
                goal_claim=goal_receipt_claim(request.goal),
            )
        except Exception:
            return None
