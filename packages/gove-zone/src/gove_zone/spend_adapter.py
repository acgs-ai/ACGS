"""Strict local-fixture Spend Guard route composed from existing ACGS primitives."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Mapping
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, cast

from gove_zone._spend_fixture_provider import (
    FixtureProviderStatus,
    LocalJournalFixtureProvider,
)
from gove_zone.authorization import (
    SideEffectAuthorization,
    SideEffectExecutionContext,
    SideEffectRequest,
    deep_thaw_json,
    idempotency_binding_digest,
    strict_json_hash,
    validate_strict_json_budget,
)
from gove_zone.decision import Decision, DecisionRecord
from gove_zone.policy import Policy, PolicyArtifactSnapshot, new_event_id
from gove_zone.side_effect_kernel import (
    AdapterOutcome,
    AdapterOutcomeStatus,
    ReceiptGatedSideEffectExecutor,
    SideEffectAuthorizationKernel,
)
from gove_zone.spend_guard import (
    SPEND_OPERATION,
    SpendApprovalClaim,
    SpendPolicy,
    normalize_spend_arguments,
)
from gove_zone.spend_store import (
    SpendBudgetProbe,
    SpendBudgetRules,
    SpendOutcomeState,
    SpendReservationRequest,
    SQLiteSpendStore,
)
from gove_zone.tool import ToolCall

SPEND_SERVER_ID = "acgs-local-spend-fixture"
SPEND_TOOL_ID = "spend-guard"
SPEND_EXECUTION_BOUNDARY = "acgs-spend-guard"
SPEND_SIDE_EFFECT_CLASS = "payment"
_ENVELOPE_SCHEMA = "acgs.spend-guard-envelope/v1"
_POLICY_SCHEMA = "acgs.spend-kernel-policy/v1"
_PLACEHOLDER_RECEIPT_DIGEST = "0" * 64


class SpendGuardError(RuntimeError):
    """The strict Spend Guard route failed closed."""


@dataclass(frozen=True, slots=True)
class SpendGuardResult:
    spend_id: str
    state: SpendOutcomeState
    provider_reference: str | None
    replayed: bool
    authorization: SideEffectAuthorization


@dataclass(frozen=True, slots=True)
class SpendKernelPolicy(Policy):
    """Attestable policy artifact combining payment and aggregate-budget rules."""

    spend_policy: SpendPolicy
    budget_rules: SpendBudgetRules

    def __post_init__(self) -> None:
        if type(self.spend_policy) is not SpendPolicy:
            raise TypeError("spend_policy must be SpendPolicy")
        if type(self.budget_rules) is not SpendBudgetRules:
            raise TypeError("budget_rules must be SpendBudgetRules")
        object.__setattr__(self, "budget_rules", _copy_rules(self.budget_rules))
        snapshot = self.spend_policy.authorization_snapshot()
        object.__setattr__(
            self,
            "spend_policy",
            SpendPolicy.from_authorization_snapshot(json.loads(snapshot.canonical_artifact)),
        )

    @property
    def version(self) -> str:
        return "acgs-spend-guard/v1"

    @property
    def artifact_digest(self) -> str:
        return self.authorization_snapshot().digest

    def authorization_snapshot(self) -> PolicyArtifactSnapshot:
        artifact = self._artifact()
        evaluator = SpendKernelPolicy.from_authorization_snapshot(artifact)
        return PolicyArtifactSnapshot.from_artifact(artifact, evaluator=evaluator)

    @classmethod
    def from_authorization_snapshot(cls, value: Any) -> SpendKernelPolicy:
        if type(value) is not dict or set(value) != {
            "kind",
            "version",
            "spend_policy",
            "budget_rules",
        }:
            raise ValueError("spend kernel policy artifact shape is invalid")
        raw = cast(dict[str, Any], value)
        if raw["kind"] != _POLICY_SCHEMA or raw["version"] != "acgs-spend-guard/v1":
            raise ValueError("spend kernel policy artifact version is invalid")
        return cls(
            spend_policy=SpendPolicy.from_authorization_snapshot(raw["spend_policy"]),
            budget_rules=_rules_from_document(raw["budget_rules"]),
        )

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        try:
            envelope = _exact_envelope(call.args)
            identity = cast(dict[str, Any], envelope["identity"])
            payment = cast(dict[str, Any], envelope["payment"])
            probe = cast(dict[str, Any], envelope["budget_probe"])
            policy = cast(dict[str, Any], envelope["policy"])
            if call.name != SPEND_OPERATION:
                return self._record(call, Decision.DENY, "SPEND_WRONG_OPERATION")
            trusted_identity = _identity_from_policy_state(call)
            if any(identity.get(key) != value for key, value in trusted_identity.items()):
                return self._record(call, Decision.DENY, "SPEND_IDENTITY_BINDING_MISMATCH")
            if envelope["rules"] != _rules_document(self.budget_rules):
                return self._record(call, Decision.DENY, "SPEND_RULES_BINDING_MISMATCH")
            if (
                probe.get("rules_digest") != self.budget_rules.digest
                or probe.get("stop_generation") != envelope["expected_stop_generation"]
                or not _is_digest(probe.get("request_digest"))
                or not _is_digest(probe.get("budget_snapshot_digest"))
                or not _is_digest(probe.get("snapshot_digest"))
            ):
                return self._record(call, Decision.DENY, "SPEND_PROBE_BINDING_MISMATCH")
            if (
                policy.get("version") != self.version
                or policy.get("digest") != self.artifact_digest
            ):
                return self._record(call, Decision.DENY, "SPEND_POLICY_BINDING_MISMATCH")
            if set(payment) != {
                "provider",
                "recipient",
                "amount",
                "currency",
                "reference",
                "amount_minor",
            }:
                return self._record(call, Decision.DENY, "SPEND_ARGUMENT_SHAPE")
            normalized = normalize_spend_arguments(
                {key: value for key, value in payment.items() if key != "amount_minor"},
                dict(self.spend_policy.currency_exponents),
            )
            if payment != {**normalized.to_arguments(), "amount_minor": normalized.amount_minor}:
                return self._record(call, Decision.DENY, "SPEND_NORMALIZATION_MISMATCH")
            reason = probe.get("reason_code")
            if reason is not None:
                if type(reason) is not str:
                    return self._record(call, Decision.DENY, "SPEND_PROBE_BINDING_MISMATCH")
                return self._record(call, Decision.DENY, reason)
            approval = envelope["approval"]
            approval_digest = envelope["approval_digest"]
            if approval is None:
                if approval_digest is not None:
                    return self._record(call, Decision.DENY, "SPEND_APPROVAL_BINDING_MISMATCH")
            elif not _is_digest(approval_digest) or strict_json_hash(approval) != approval_digest:
                return self._record(call, Decision.DENY, "SPEND_APPROVAL_BINDING_MISMATCH")
            state = {
                "tenant_id": identity["tenant_id"],
                "authority": identity["authority"],
                "resource": identity["resource"],
                "environment": identity["environment"],
                "request_id": identity["request_id"],
                "requested_at": identity["requested_at"],
            }
            if approval is not None:
                state["approval"] = approval
            base = self.spend_policy.evaluate(
                ToolCall(
                    SPEND_OPERATION,
                    normalized.to_arguments(),
                    actor=call.actor,
                    state=state,
                )
            )
            if base.decision is Decision.TRANSFORM:
                return self._record(call, Decision.DENY, "SPEND_TRANSFORM_NOT_EXECUTABLE")
            return self._record(
                call,
                base.decision,
                base.reason or "SPEND_POLICY_DECISION",
                matched_rules=base.matched_rules,
            )
        except Exception:
            return self._record(call, Decision.DENY, "SPEND_ENVELOPE_INVALID")

    def _artifact(self) -> dict[str, Any]:
        spend_snapshot = self.spend_policy.authorization_snapshot()
        return {
            "kind": _POLICY_SCHEMA,
            "version": self.version,
            "spend_policy": json.loads(spend_snapshot.canonical_artifact),
            "budget_rules": _rules_document(self.budget_rules),
        }

    def _record(
        self,
        call: ToolCall,
        decision: Decision,
        reason: str,
        *,
        matched_rules: tuple[str, ...] = (),
    ) -> DecisionRecord:
        return DecisionRecord(
            decision=decision,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("SPEND_GUARD", *matched_rules),
            reason=reason,
        )


@dataclass(frozen=True, slots=True)
class _ExecutionState:
    request: SideEffectRequest
    rules: SpendBudgetRules
    probe: SpendBudgetProbe
    envelope: dict[str, Any]
    authorization: SideEffectAuthorization
    approval_digest: str | None
    expected_stop_generation: int


_ACTIVE_EXECUTION: ContextVar[_ExecutionState | None] = ContextVar(
    "acgs_spend_active_execution",
    default=None,
)


class SpendGuardAdapter:
    """The only supported P2-C route from authorization to the local provider."""

    def __init__(
        self,
        *,
        authorizer: SideEffectAuthorizationKernel,
        executor: ReceiptGatedSideEffectExecutor,
        store: SQLiteSpendStore,
        provider: LocalJournalFixtureProvider,
        policy: SpendKernelPolicy,
        binding_hmac_key: bytes,
    ) -> None:
        if type(authorizer) is not SideEffectAuthorizationKernel:
            raise TypeError("authorizer must be SideEffectAuthorizationKernel")
        if type(executor) is not ReceiptGatedSideEffectExecutor:
            raise TypeError("executor must be ReceiptGatedSideEffectExecutor")
        if type(store) is not SQLiteSpendStore:
            raise TypeError("store must be SQLiteSpendStore")
        if type(provider) is not LocalJournalFixtureProvider:
            raise TypeError("provider must be LocalJournalFixtureProvider")
        if type(policy) is not SpendKernelPolicy:
            raise TypeError("policy must be SpendKernelPolicy")
        if type(binding_hmac_key) is not bytes or len(binding_hmac_key) < 32:
            raise ValueError("binding_hmac_key must contain at least 32 bytes")
        self._authorizer = authorizer
        self._executor = executor
        self._store = store
        self._provider = provider
        self._policy = policy
        self._binding_hmac_key = binding_hmac_key
        executor.register_adapter(
            SPEND_SERVER_ID,
            SPEND_TOOL_ID,
            SPEND_OPERATION,
            self._execute_registered,
        )

    def execute(
        self,
        request: SideEffectRequest,
        rules: SpendBudgetRules,
        *,
        approval: SpendApprovalClaim | None = None,
        authentication_context: Mapping[str, Any],
        expected_stop_generation: int = 0,
    ) -> SpendGuardResult:
        request = dataclasses.replace(request, policy_ref=dataclasses.replace(request.policy_ref))
        self._validate_route(request)
        trusted_rules = _copy_rules(rules)
        if trusted_rules.digest != self._policy.budget_rules.digest:
            raise SpendGuardError("budget rules do not match the attested policy artifact")
        normalized = normalize_spend_arguments(
            cast(Mapping[str, Any], deep_thaw_json(request.args)),
            dict(self._policy.spend_policy.currency_exponents),
        )
        payment = {**normalized.to_arguments(), "amount_minor": normalized.amount_minor}
        approval_document = approval.to_dict() if approval is not None else None
        approval_digest = (
            strict_json_hash(approval_document) if approval_document is not None else None
        )
        idempotency_digest = idempotency_binding_digest(
            request.idempotency_key,
            request.tenant_id,
            binding_hmac_key=self._binding_hmac_key,
        )
        reservation_request = self._reservation_request(
            request,
            payment,
            trusted_rules,
            approval_digest=approval_digest,
            idempotency_digest=idempotency_digest,
            receipt_digest=_PLACEHOLDER_RECEIPT_DIGEST,
            expected_stop_generation=expected_stop_generation,
        )
        probe = self._store.preview(reservation_request, trusted_rules)
        envelope = self._envelope(
            request,
            payment,
            trusted_rules,
            probe,
            approval_document,
            approval_digest,
            expected_stop_generation,
        )
        evidence = request.evidence
        if approval is not None:
            evidence = (*evidence, approval.evidence)
        governed_request = dataclasses.replace(
            request,
            args=envelope,
            evidence=evidence,
            side_effect_class=SPEND_SIDE_EFFECT_CLASS,
        )
        authorization = self._authorizer.authorize(governed_request)
        if not authorization.executable or authorization.receipt is None:
            raise SpendGuardError(
                f"spend authorization is not executable: {authorization.reason_code}"
            )
        context = SideEffectExecutionContext(
            request_id=governed_request.request_id,
            tenant_id=governed_request.tenant_id,
            actor_id=governed_request.actor_id,
            actor_role=governed_request.actor_role,
            authority=governed_request.authority,
            server_id=governed_request.server_id,
            tool=governed_request.tool,
            operation=governed_request.operation,
            resource=governed_request.resource,
            environment=governed_request.environment,
            execution_boundary=governed_request.execution_boundary,
            policy_ref=governed_request.policy_ref,
            observed_at=governed_request.requested_at,
            authentication_context=authentication_context,
        )
        state = _ExecutionState(
            request=governed_request,
            rules=trusted_rules,
            probe=probe,
            envelope=envelope,
            authorization=authorization,
            approval_digest=approval_digest,
            expected_stop_generation=expected_stop_generation,
        )
        token = _ACTIVE_EXECUTION.set(state)
        try:
            result = self._executor.execute(
                authorization,
                context,
                nonce=governed_request.nonce,
                idempotency_key=governed_request.idempotency_key,
            )
        finally:
            _ACTIVE_EXECUTION.reset(token)
        if type(result) is not SpendGuardResult:
            raise SpendGuardError("registered spend route returned an invalid result")
        return result

    def _execute_registered(self, **approved: Any) -> AdapterOutcome:
        state = _ACTIVE_EXECUTION.get()
        if state is None:
            raise SpendGuardError("direct invocation of the registered route is forbidden")
        validate_strict_json_budget(approved)
        if approved != state.envelope or strict_json_hash(approved) != strict_json_hash(
            state.envelope
        ):
            raise SpendGuardError("approved spend envelope changed before execution")
        if state.authorization.decision is not Decision.ALLOW:
            raise SpendGuardError("transformed spend authorization is not executable")
        receipt = state.authorization.receipt
        if receipt is None:
            raise SpendGuardError("receipt disappeared before spend reservation")
        binding = cast(dict[str, Any], deep_thaw_json(state.authorization.reserved_binding))
        reservation_request = self._reservation_request(
            state.request,
            cast(dict[str, Any], approved["payment"]),
            state.rules,
            approval_digest=state.approval_digest,
            idempotency_digest=cast(str, binding["idempotency_digest"]),
            receipt_digest=receipt.receipt_hash,
            expected_stop_generation=state.expected_stop_generation,
        )
        reservation = self._store.reserve(
            reservation_request,
            state.rules,
            expected_snapshot_digest=state.probe.snapshot_digest,
        )
        if reservation.replayed:
            if (
                reservation.outcome is None
                or reservation.outcome.state is SpendOutcomeState.UNKNOWN
            ):
                return AdapterOutcome(AdapterOutcomeStatus.UNKNOWN)
            return AdapterOutcome(
                AdapterOutcomeStatus.CONFIRMED_SUCCEEDED,
                SpendGuardResult(
                    spend_id=reservation.spend_id,
                    state=reservation.outcome.state,
                    provider_reference=None,
                    replayed=True,
                    authorization=state.authorization,
                ),
            )
        try:
            provider_result = self._provider.create_payment(
                approved,
                idempotency_digest=cast(str, binding["idempotency_digest"]),
            )
        except Exception as exc:
            self._store.record_outcome(
                reservation.spend_id,
                state=SpendOutcomeState.UNKNOWN,
                uncertainty_digest=strict_json_hash(
                    {"reason": "provider-exception", "exception": type(exc).__name__}
                ),
            )
            raise
        if provider_result.status is FixtureProviderStatus.UNKNOWN:
            self._store.record_outcome(
                reservation.spend_id,
                state=SpendOutcomeState.UNKNOWN,
                uncertainty_digest=cast(str, provider_result.uncertainty_digest),
            )
            return AdapterOutcome(AdapterOutcomeStatus.UNKNOWN)
        self._store.record_outcome(
            reservation.spend_id,
            state=SpendOutcomeState.SUCCEEDED,
            result_digest=cast(str, provider_result.result_digest),
            provider_reference_digest=strict_json_hash(
                {"provider_reference": provider_result.provider_reference}
            ),
        )
        return AdapterOutcome(
            AdapterOutcomeStatus.CONFIRMED_SUCCEEDED,
            SpendGuardResult(
                spend_id=reservation.spend_id,
                state=SpendOutcomeState.SUCCEEDED,
                provider_reference=provider_result.provider_reference,
                replayed=False,
                authorization=state.authorization,
            ),
        )

    def _validate_route(self, request: SideEffectRequest) -> None:
        if (
            request.server_id,
            request.tool,
            request.operation,
            request.execution_boundary,
            request.side_effect_class,
        ) != (
            SPEND_SERVER_ID,
            SPEND_TOOL_ID,
            SPEND_OPERATION,
            SPEND_EXECUTION_BOUNDARY,
            SPEND_SIDE_EFFECT_CLASS,
        ):
            raise SpendGuardError("request does not target the strict local Spend Guard route")
        snapshot = self._policy.authorization_snapshot()
        if (
            request.policy_ref.version != snapshot.policy_version
            or request.policy_ref.digest != snapshot.digest
        ):
            raise SpendGuardError("request policy reference does not match SpendKernelPolicy")

    def _reservation_request(
        self,
        request: SideEffectRequest,
        payment: Mapping[str, Any],
        rules: SpendBudgetRules,
        *,
        approval_digest: str | None,
        idempotency_digest: str,
        receipt_digest: str,
        expected_stop_generation: int,
    ) -> SpendReservationRequest:
        argument_digest = strict_json_hash(payment)
        semantic_digest = strict_json_hash(
            {
                "provider": payment["provider"],
                "recipient": payment["recipient"],
                "amount_minor": payment["amount_minor"],
                "currency": payment["currency"],
            }
        )
        return SpendReservationRequest(
            tenant_id=request.tenant_id,
            provider=cast(str, payment["provider"]),
            recipient=cast(str, payment["recipient"]),
            currency=cast(str, payment["currency"]),
            amount_minor=cast(int, payment["amount_minor"]),
            attempt_digest=strict_json_hash(
                {"request_id": request.request_id, "argument_digest": argument_digest}
            ),
            reference_digest=strict_json_hash({"reference": payment["reference"]}),
            argument_digest=argument_digest,
            semantic_digest=semantic_digest,
            loop_fingerprint_digest=strict_json_hash(
                {"semantic_digest": semantic_digest, "reference": payment["reference"]}
            ),
            receipt_digest=receipt_digest,
            policy_digest=request.policy_ref.digest,
            approval_digest=approval_digest,
            idempotency_digest=idempotency_digest,
            expected_stop_generation=expected_stop_generation,
        )

    def _envelope(
        self,
        request: SideEffectRequest,
        payment: dict[str, Any],
        rules: SpendBudgetRules,
        probe: SpendBudgetProbe,
        approval: dict[str, Any] | None,
        approval_digest: str | None,
        expected_stop_generation: int,
    ) -> dict[str, Any]:
        return {
            "schema": _ENVELOPE_SCHEMA,
            "identity": {
                "tenant_id": request.tenant_id,
                "actor_id": request.actor_id,
                "actor_role": request.actor_role,
                "authority": request.authority,
                "resource": request.resource,
                "environment": request.environment,
                "request_id": request.request_id,
                "requested_at": request.requested_at,
            },
            "payment": payment,
            "approval": approval,
            "approval_digest": approval_digest,
            "rules": _rules_document(rules),
            "budget_probe": {
                "request_digest": probe.request_digest,
                "base_generation": probe.base_generation,
                "stop_generation": probe.stop_generation,
                "rules_digest": probe.rules_digest,
                "budget_snapshot_digest": probe.budget_snapshot.snapshot_digest,
                "snapshot_digest": probe.snapshot_digest,
                "reason_code": probe.reason_code,
            },
            "policy": {
                "bundle_id": request.policy_ref.bundle_id,
                "version": request.policy_ref.version,
                "digest": request.policy_ref.digest,
            },
            "expected_stop_generation": expected_stop_generation,
        }


def _exact_envelope(value: Mapping[str, Any]) -> dict[str, Any]:
    validate_strict_json_budget(value)
    thawed = deep_thaw_json(value)
    if type(thawed) is not dict or set(thawed) != {
        "schema",
        "identity",
        "payment",
        "approval",
        "approval_digest",
        "rules",
        "budget_probe",
        "policy",
        "expected_stop_generation",
    }:
        raise ValueError("spend envelope shape is invalid")
    result = cast(dict[str, Any], thawed)
    if result["schema"] != _ENVELOPE_SCHEMA:
        raise ValueError("spend envelope schema is invalid")
    for key in ("identity", "payment", "rules", "budget_probe", "policy"):
        if type(result[key]) is not dict:
            raise TypeError(f"spend envelope {key} must be an object")
    return result


def _identity_from_policy_state(call: ToolCall) -> dict[str, Any]:
    state = cast(dict[str, Any], deep_thaw_json(call.state))
    return {
        "tenant_id": state.get("tenant_id"),
        "actor_id": call.actor,
        "actor_role": state.get("actor_role"),
        "authority": state.get("authority"),
        "resource": state.get("resource"),
        "environment": state.get("environment"),
        "request_id": state.get("request_id"),
    }


def _copy_rules(value: SpendBudgetRules) -> SpendBudgetRules:
    if type(value) is not SpendBudgetRules:
        raise TypeError("rules must be SpendBudgetRules")
    return SpendBudgetRules(
        currency=value.currency,
        single_limit_minor=value.single_limit_minor,
        hourly_limit_minor=value.hourly_limit_minor,
        daily_limit_minor=value.daily_limit_minor,
        monthly_limit_minor=value.monthly_limit_minor,
        vendor_monthly_limits=tuple(value.vendor_monthly_limits),
        rate_window_seconds=value.rate_window_seconds,
        rate_limit_count=value.rate_limit_count,
        loop_window_seconds=value.loop_window_seconds,
        loop_limit_count=value.loop_limit_count,
        anomaly_window_seconds=value.anomaly_window_seconds,
        anomaly_growth_basis_points=value.anomaly_growth_basis_points,
        anomaly_floor_minor=value.anomaly_floor_minor,
    )


def _rules_document(value: SpendBudgetRules) -> dict[str, Any]:
    return {
        "currency": value.currency,
        "single_limit_minor": value.single_limit_minor,
        "hourly_limit_minor": value.hourly_limit_minor,
        "daily_limit_minor": value.daily_limit_minor,
        "monthly_limit_minor": value.monthly_limit_minor,
        "vendor_monthly_limits": [list(item) for item in value.vendor_monthly_limits],
        "rate_window_seconds": value.rate_window_seconds,
        "rate_limit_count": value.rate_limit_count,
        "loop_window_seconds": value.loop_window_seconds,
        "loop_limit_count": value.loop_limit_count,
        "anomaly_window_seconds": value.anomaly_window_seconds,
        "anomaly_growth_basis_points": value.anomaly_growth_basis_points,
        "anomaly_floor_minor": value.anomaly_floor_minor,
        "digest": value.digest,
    }


def _rules_from_document(value: Any) -> SpendBudgetRules:
    if type(value) is not dict:
        raise TypeError("budget rules artifact must be an object")
    raw = cast(dict[str, Any], value)
    expected = set(_rules_document(_fixture_shape_rules()))
    if set(raw) != expected:
        raise ValueError("budget rules artifact shape is invalid")
    vendor_rows = raw["vendor_monthly_limits"]
    if type(vendor_rows) is not list:
        raise TypeError("vendor_monthly_limits must be a list")
    rules = SpendBudgetRules(
        currency=raw["currency"],
        single_limit_minor=raw["single_limit_minor"],
        hourly_limit_minor=raw["hourly_limit_minor"],
        daily_limit_minor=raw["daily_limit_minor"],
        monthly_limit_minor=raw["monthly_limit_minor"],
        vendor_monthly_limits=tuple((item[0], item[1]) for item in vendor_rows),
        rate_window_seconds=raw["rate_window_seconds"],
        rate_limit_count=raw["rate_limit_count"],
        loop_window_seconds=raw["loop_window_seconds"],
        loop_limit_count=raw["loop_limit_count"],
        anomaly_window_seconds=raw["anomaly_window_seconds"],
        anomaly_growth_basis_points=raw["anomaly_growth_basis_points"],
        anomaly_floor_minor=raw["anomaly_floor_minor"],
    )
    if raw["digest"] != rules.digest:
        raise ValueError("budget rules artifact digest is invalid")
    return rules


def _fixture_shape_rules() -> SpendBudgetRules:
    return SpendBudgetRules(
        currency="USD",
        single_limit_minor=1,
        hourly_limit_minor=1,
        daily_limit_minor=1,
        monthly_limit_minor=1,
        vendor_monthly_limits=(("fixture", 1),),
        rate_window_seconds=1,
        rate_limit_count=1,
        loop_window_seconds=1,
        loop_limit_count=1,
        anomaly_window_seconds=1,
        anomaly_growth_basis_points=1,
        anomaly_floor_minor=1,
    )


def _is_digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
