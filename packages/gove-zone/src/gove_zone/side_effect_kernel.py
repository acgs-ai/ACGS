"""Strict shared authorization and final-execution membrane for side effects.

This module composes the repository's existing policy ``Kernel``, public
``DecisionReceipt``, audit chain, signer, receipt gate, and durable consumption
store.  It deliberately does not introduce an alternative policy evaluator,
receipt schema, audit log, or replay ledger.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hmac
import math
import os
import secrets
from collections.abc import Callable, Collection, Mapping
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from contextvars import copy_context
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import Lock, RLock
from typing import Any, NoReturn, TypeVar, cast

from gove_zone.audit import AuditCheckpoint, AuditCommit, ChainHashAuditStore
from gove_zone.authorization import (
    EXECUTION_REFUSAL_REASON_CODES,
    AuthorizationError,
    AuthorizationReasonCode,
    ExecutionReasonCode,
    ExecutionRefusalEvidence,
    ExecutionRefusalPhase,
    PolicyResolver,
    PrincipalResolver,
    RefusalEvidence,
    ResolvedPolicy,
    ResolvedPolicyRef,
    SideEffectAuthorization,
    SideEffectExecutionContext,
    SideEffectExecutionError,
    SideEffectRequest,
    VerifiedPrincipal,
    build_reserved_binding,
    compute_evidence_digest,
    deep_freeze_json,
    deep_thaw_json,
    goal_receipt_claim,
    idempotency_binding_digest,
    nonce_binding_digest,
    reserved_binding_hash,
    reserved_constraints,
    strict_json_hash,
    validate_strict_json_budget,
)
from gove_zone.consumption import (
    ConsumptionState,
    ConsumptionStoreError,
    ConsumptionTransitionError,
    ReceiptConsumptionError,
    ReceiptConsumptionStore,
    ReceiptReplayError,
    ReceiptRevokedError,
)
from gove_zone.decision import ActionTier, Decision, DecisionRecord, RecordKind, sha256_json
from gove_zone.executor import (
    _REASON_OUTCOME_UNKNOWN,
    _REASON_RESERVED,
    _REASON_SUCCEEDED,
    _evidence_digest,
    _execution_evidence,
)
from gove_zone.kernel import Kernel
from gove_zone.path_capability import (
    DEFAULT_MAX_ARTIFACT_BYTES,
    ImmutableArtifactSnapshot,
    PathCapabilityError,
    artifact_snapshot_lease,
    capture_immutable_artifact,
    require_immutable_artifact_snapshot,
)
from gove_zone.policy import Policy, new_event_id
from gove_zone.receipt import DecisionReceipt, Validator
from gove_zone.replay_store import ReplaySideStore
from gove_zone.signing import ReceiptSigner
from gove_zone.tier import ToolTierRegistry
from gove_zone.tool import ToolCall

_T = TypeVar("_T")
_Route = tuple[str, str, str]
_Clock = Callable[[], datetime]

# Conservative aggregate ceiling on artifact-capture bytes held in flight across
# all concurrent executes. Each artifact capture reserves its worst-case route
# bound (or, for a pre-minted snapshot, its exact size) before the bytes are
# materialized, so four worst-case captures may coexist by default. Callers that
# need more concurrency raise it explicitly; the per-capture bound in
# ``capture_immutable_artifact`` is unchanged and independent of this.
DEFAULT_AGGREGATE_CAPTURE_BUDGET_BYTES = 4 * DEFAULT_MAX_ARTIFACT_BYTES


class _AggregateCaptureBudget:
    """Executor-owned bound on artifact-capture bytes held concurrently in flight.

    A reservation is taken *before* the kernel-owned source capture (worst-case
    route bound) or before a pre-minted snapshot is consumed (its exact size), and
    released deterministically in a ``finally`` once the adapter — and any refusal
    or ambiguous outcome — has finished with the bytes. Acquisition is nonblocking
    and fails closed: a request that would push the aggregate over capacity is
    refused *before* the adapter with verifiable evidence, so concurrent captures
    can neither amplify memory nor duplicate bytes beyond this ceiling, and a
    high-risk request never waits unbounded for capacity to free up.
    """

    __slots__ = ("_capacity", "_lock", "_reserved")

    def __init__(self, capacity: int) -> None:
        if type(capacity) is not int or isinstance(capacity, bool) or capacity <= 0:
            raise ValueError("aggregate_capture_budget_bytes must be a positive integer")
        self._capacity = capacity
        self._reserved = 0
        self._lock = Lock()

    @property
    def capacity(self) -> int:
        return self._capacity

    def reserved_bytes(self) -> int:
        with self._lock:
            return self._reserved

    def acquire(self, amount: int) -> None:
        """Reserve ``amount`` bytes or fail closed; never block on capacity."""

        if type(amount) is not int or isinstance(amount, bool) or amount <= 0:
            raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT)
        with self._lock:
            # A single reservation larger than the whole budget, or one that would
            # exceed the remaining capacity, is refused immediately rather than
            # waited on: the boundary is fail-closed and nonblocking.
            if amount > self._capacity or amount > self._capacity - self._reserved:
                raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT)
            self._reserved += amount

    def release(self, amount: int) -> None:
        """Return ``amount`` reserved bytes; an underflow is an invariant error.

        A release that exceeds the currently reserved total, or a negative
        amount, is a lifetime-accounting invariant violation (a double release
        or a mismatched acquire/release pair) and is raised rather than clamped
        with ``max(0, ...)``, which would silently hide a leaked or duplicated
        reservation. A zero amount (an unleased or zero-byte capture) is a no-op.
        """

        if type(amount) is not int or isinstance(amount, bool):
            raise RuntimeError("aggregate capture budget release amount must be an integer")
        if amount == 0:
            return
        if amount < 0:
            raise RuntimeError("aggregate capture budget release amount is negative")
        with self._lock:
            if amount > self._reserved:
                raise RuntimeError("aggregate capture budget release underflow")
            self._reserved -= amount


class AdapterOutcomeStatus(StrEnum):
    """Explicit downstream certainty returned by a side-effect adapter."""

    CONFIRMED_SUCCEEDED = "confirmed_succeeded"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class AdapterOutcome:
    """Adapter result envelope; bare return values never prove success."""

    status: AdapterOutcomeStatus
    payload: Any = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, AdapterOutcomeStatus):
            raise TypeError("status must be an AdapterOutcomeStatus")


@dataclass(frozen=True, slots=True)
class ImmutableArtifactRequirement:
    """Data-only route rule: one approved argument must be proven by a snapshot.

    ``argument_name`` names the receipted digest argument the snapshot must
    reproduce. ``snapshot_parameter`` names the keyword the kernel passes the
    proven snapshot to the adapter under; it is never part of the canonical,
    receipted arguments, so binding a snapshot changes no receipt or
    consumption schema.
    """

    argument_name: str
    snapshot_parameter: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "argument_name",
            _require_text(self.argument_name, "argument_name"),
        )
        object.__setattr__(
            self,
            "snapshot_parameter",
            _require_text(self.snapshot_parameter, "snapshot_parameter"),
        )
        if self.argument_name == self.snapshot_parameter:
            raise ValueError("snapshot_parameter must not shadow argument_name")


@dataclass(frozen=True, slots=True)
class PreAdapterDigestBinding:
    """Data-only binding of one exact immutable snapshot to one approved argument.

    This carries no callable and no path. The kernel verifies it at the last
    controllable boundary; it is never itself trusted as proof.
    """

    argument_name: str
    snapshot: ImmutableArtifactSnapshot

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "argument_name",
            _require_text(self.argument_name, "argument_name"),
        )
        # Exact type, checked before any attribute is read: a subclass, a proxy,
        # or a structurally similar attestation must not substitute here.
        if type(self.snapshot) is not ImmutableArtifactSnapshot:
            raise TypeError("snapshot must be an exact ImmutableArtifactSnapshot")


def _require_text(value: object, field_name: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{field_name} must be valid UTF-8") from None
    return value


def _utc_iso(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("trusted clock must return a timezone-aware datetime")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise ValueError("timestamp must be normalized UTC ISO-8601") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be normalized UTC ISO-8601")
    return parsed.astimezone(UTC)


def _plain_object(value: Mapping[str, Any]) -> dict[str, Any]:
    validate_strict_json_budget(value)
    thawed = deep_thaw_json(value)
    if type(thawed) is not dict:
        raise TypeError("expected a strict JSON object")
    return cast(dict[str, Any], thawed)


def _validated_request(request: SideEffectRequest) -> SideEffectRequest:
    if not isinstance(request, SideEffectRequest):
        raise TypeError("request must be a SideEffectRequest")
    policy_ref = dataclasses.replace(request.policy_ref)
    evidence = tuple(dataclasses.replace(item) for item in request.evidence)
    return dataclasses.replace(request, policy_ref=policy_ref, evidence=evidence)


def _validated_principal(principal: VerifiedPrincipal) -> VerifiedPrincipal:
    if not isinstance(principal, VerifiedPrincipal):
        raise TypeError("principal resolver returned an invalid principal")
    return dataclasses.replace(principal)


def _validated_resolved_policy(resolved: ResolvedPolicy) -> ResolvedPolicy:
    if not isinstance(resolved, ResolvedPolicy):
        raise TypeError("policy resolver returned an invalid policy")
    ref = dataclasses.replace(resolved.ref)
    attestation = dataclasses.replace(resolved.attestation)
    validator = Validator(resolved.validator.validator_id, resolved.validator.role)
    return ResolvedPolicy(
        ref=ref,
        policy=resolved.policy,
        attestation=attestation,
        validator=validator,
        authority=resolved.authority,
    )


def _snapshot_evaluator(resolved: ResolvedPolicy) -> Policy:
    """Return the fresh evaluator bound to the resolver's full attestation."""

    snapshot = resolved.policy.authorization_snapshot()
    if snapshot.evaluator is resolved.policy:
        raise ValueError("policy authorization snapshot must rebuild a fresh evaluator")
    if (
        snapshot.digest,
        snapshot.policy_version,
        resolved.attestation.tenant_id,
        resolved.attestation.artifact_id,
        resolved.attestation.policy_version,
        resolved.attestation.digest,
    ) != (
        resolved.ref.digest,
        resolved.ref.version,
        resolved.ref.tenant_id,
        resolved.ref.bundle_id,
        resolved.ref.version,
        resolved.ref.digest,
    ):
        raise ValueError("policy snapshot does not match the attested reference")
    return snapshot.evaluator


def _checkpoint_binding(commit: AuditCommit) -> dict[str, Any]:
    checkpoint = commit.checkpoint
    return {
        **checkpoint.to_dict(),
        "checkpoint_hash": checkpoint.checkpoint_hash,
    }


def _checkpoint_from_binding(binding: Mapping[str, Any]) -> AuditCheckpoint:
    checkpoint = binding.get("audit_checkpoint")
    if type(checkpoint) is not dict:
        raise ValueError("audit checkpoint binding is missing")
    values = cast(dict[str, Any], checkpoint)
    rebuilt = AuditCheckpoint(
        namespace=cast(str, values["namespace"]),
        generation=cast(int, values["generation"]),
        head_hash=cast(str, values["head_hash"]),
        previous_checkpoint_hash=cast(str, values["previous_checkpoint_hash"]),
        key_id=cast(str, values["key_id"]),
        algorithm=cast(str, values["algorithm"]),
        signature=cast(str, values["signature"]),
    )
    if rebuilt.checkpoint_hash != values.get("checkpoint_hash"):
        raise ValueError("audit checkpoint hash is inconsistent")
    return rebuilt


def _policy_state(
    *,
    request_id: str,
    tenant_id: str,
    actor_role: str,
    authority: str,
    server_id: str,
    tool: str,
    operation: str,
    resource: str,
    environment: str,
    execution_boundary: str,
    side_effect_class: str,
    policy_bundle_id: str,
    policy_version: str,
    policy_digest: str,
    policy_attestation_tenant_id: str,
    policy_attestation_artifact_id: str,
    policy_attestation_version: str,
    policy_attestation_digest: str,
    policy_attestation_resolver_id: str,
    evidence_digest: str,
    authentication_context_hash: str,
) -> dict[str, str]:
    """Build policy-visible trusted context entirely from bound values."""

    return {
        "request_id": request_id,
        "tenant_id": tenant_id,
        "actor_role": actor_role,
        "authority": authority,
        "server_id": server_id,
        "tool": tool,
        "operation": operation,
        "resource": resource,
        "environment": environment,
        "execution_boundary": execution_boundary,
        "side_effect_class": side_effect_class,
        "policy_bundle_id": policy_bundle_id,
        "policy_version": policy_version,
        "policy_digest": policy_digest,
        "policy_attestation_tenant_id": policy_attestation_tenant_id,
        "policy_attestation_artifact_id": policy_attestation_artifact_id,
        "policy_attestation_version": policy_attestation_version,
        "policy_attestation_digest": policy_attestation_digest,
        "policy_attestation_resolver_id": policy_attestation_resolver_id,
        "evidence_digest": evidence_digest,
        "authentication_context_hash": authentication_context_hash,
    }


class _StrictResolvedPolicy(Policy):
    """Validate one attested policy result without evaluating a second policy."""

    def __init__(
        self,
        policy: Policy,
        *,
        expected_tool: str,
        expected_argument_hash: str,
        expected_version: str,
    ) -> None:
        self._policy = policy
        self._expected_tool = expected_tool
        self._expected_argument_hash = expected_argument_hash
        self._expected_version = expected_version

    @property
    def version(self) -> str:
        return self._expected_version

    def _deny(self, rule: str, reason: str) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.DENY,
            tool=self._expected_tool,
            argument_hash=self._expected_argument_hash,
            policy_version=self._expected_version,
            event_id=new_event_id(),
            matched_rules=(rule,),
            reason=reason,
        )

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        try:
            record = self._policy.evaluate(call)
        except Exception as exc:
            return self._deny(
                f"SIDE_EFFECT_POLICY_ERROR:{type(exc).__name__}",
                "attested policy evaluation failed closed",
            )
        if not isinstance(record, DecisionRecord):
            return self._deny(
                "SIDE_EFFECT_POLICY_ERROR:INVALID_RECORD",
                "attested policy returned an invalid decision record",
            )
        if (
            not isinstance(record.decision, Decision)
            or record.tool != self._expected_tool
            or record.argument_hash != self._expected_argument_hash
            or record.policy_version != self._expected_version
            or type(record.event_id) is not str
            or not record.event_id.strip()
            or type(record.matched_rules) is not tuple
            or type(record.reason) is not str
        ):
            return self._deny(
                "SIDE_EFFECT_POLICY_ERROR:BINDING_MISMATCH",
                "attested policy returned an unbound decision record",
            )
        if record.action_tier is not None and record.action_tier not in {
            ActionTier.EXPLORE.value,
            ActionTier.COMMIT.value,
        }:
            return self._deny(
                "SIDE_EFFECT_POLICY_ERROR:INVALID_ACTION_TIER",
                "attested policy returned an invalid action tier",
            )
        if record.decision is Decision.TRANSFORM:
            if type(record.transformed_args) is not dict:
                return self._deny(
                    "SIDE_EFFECT_POLICY_ERROR:MALFORMED_TRANSFORM",
                    "transform decision did not approve a complete argument object",
                )
            try:
                validate_strict_json_budget(record.transformed_args)
                frozen = deep_freeze_json(record.transformed_args)
                if not isinstance(frozen, Mapping):
                    raise TypeError("transformed arguments are not an object")
                transformed = _plain_object(frozen)
            except (TypeError, ValueError):
                return self._deny(
                    "SIDE_EFFECT_POLICY_ERROR:MALFORMED_TRANSFORM",
                    "transform decision approved invalid arguments",
                )
            return dataclasses.replace(record, transformed_args=transformed)
        if record.transformed_args is not None:
            return self._deny(
                "SIDE_EFFECT_POLICY_ERROR:UNEXPECTED_TRANSFORM",
                "non-transform decision carried transformed arguments",
            )
        return record


class SideEffectAuthorizationKernel:
    """Issue existing signed DecisionReceipts for one fully bound request.

    Trusted identity and policy resolvers are called for every authorization.
    The resolved policy is evaluated exactly once through
    :meth:`Kernel.evaluate_and_record_event`; this class never owns a parallel
    policy evaluator or audit format.
    """

    def __init__(
        self,
        *,
        principal_resolver: PrincipalResolver,
        policy_resolver: PolicyResolver,
        audit: ChainHashAuditStore,
        signer: ReceiptSigner,
        binding_hmac_key: bytes,
        allowed_validator_roles: Collection[str],
        authorization_ttl: timedelta = timedelta(minutes=5),
        policy_timeout: float | None = None,
        side_store: ReplaySideStore | None = None,
        clock: _Clock | None = None,
    ) -> None:
        if not isinstance(principal_resolver, PrincipalResolver):
            raise TypeError("principal_resolver must implement PrincipalResolver")
        if not isinstance(policy_resolver, PolicyResolver):
            raise TypeError("policy_resolver must implement PolicyResolver")
        if not isinstance(audit, ChainHashAuditStore):
            raise TypeError("audit must be a ChainHashAuditStore")
        try:
            audit_ready = audit.strict_integrity_ready
        except Exception:
            raise ValueError("strict side-effect authorization audit is unavailable") from None
        if not audit_ready:
            raise ValueError("strict side-effect authorization requires a trusted audit checkpoint")
        if not isinstance(signer, ReceiptSigner) or signer.algorithm == "none":
            raise ValueError("strict side-effect authorization requires a signer")
        if type(binding_hmac_key) is not bytes or len(binding_hmac_key) < 32:
            raise ValueError("binding_hmac_key must contain at least 32 bytes")
        if isinstance(allowed_validator_roles, (str, bytes)):
            raise ValueError("allowed_validator_roles must be a non-empty collection")
        roles = frozenset(
            _require_text(role, "allowed validator role") for role in allowed_validator_roles
        )
        if not roles:
            raise ValueError("allowed_validator_roles must be a non-empty collection")
        if not isinstance(authorization_ttl, timedelta) or authorization_ttl <= timedelta(0):
            raise ValueError("authorization_ttl must be positive")
        if policy_timeout is not None and (
            isinstance(policy_timeout, bool)
            or not isinstance(policy_timeout, (int, float))
            or not math.isfinite(float(policy_timeout))
            or policy_timeout <= 0
        ):
            raise ValueError("policy_timeout must be a finite positive number")
        if side_store is not None and not isinstance(side_store, ReplaySideStore):
            raise TypeError("side_store must be a ReplaySideStore")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")

        self._principal_resolver = principal_resolver
        self._policy_resolver = policy_resolver
        self._audit = audit
        self._signer = signer
        self._binding_hmac_key = binding_hmac_key
        self._allowed_validator_roles = roles
        self._authorization_ttl = authorization_ttl
        self._policy_timeout = float(policy_timeout) if policy_timeout is not None else None
        self._side_store = side_store
        self._clock = clock or (lambda: datetime.now(UTC))

    def authorize(self, request: SideEffectRequest) -> SideEffectAuthorization:
        try:
            validated_request = _validated_request(request)
        except Exception:
            evidence = self._emit_invalid_request_evidence(request)
            raise AuthorizationError(
                AuthorizationReasonCode.INVALID_REQUEST,
                evidence=evidence,
            ) from None

        try:
            principal = _validated_principal(self._principal_resolver.resolve())
        except Exception:
            self._raise_refusal(
                AuthorizationReasonCode.PRINCIPAL_RESOLUTION_FAILED,
                validated_request,
                principal_verified=False,
            )
        if (
            principal.tenant_id,
            principal.actor_id,
            principal.role,
            principal.authority,
        ) != (
            validated_request.tenant_id,
            validated_request.actor_id,
            validated_request.actor_role,
            validated_request.authority,
        ):
            self._raise_refusal(
                AuthorizationReasonCode.PRINCIPAL_MISMATCH,
                validated_request,
                principal_verified=True,
            )

        try:
            authorized_at = _utc_iso(self._clock())
            requested_dt = _parse_utc(validated_request.requested_at)
            authorized_dt = _parse_utc(authorized_at)
            if not (
                _parse_utc(principal.verified_at)
                <= requested_dt
                <= authorized_dt
                < _parse_utc(principal.expires_at)
            ):
                raise ValueError("principal request window is invalid")
        except (TypeError, ValueError):
            self._raise_refusal(
                AuthorizationReasonCode.INVALID_TIME,
                validated_request,
                principal_verified=True,
            )

        try:
            resolved = _validated_resolved_policy(self._policy_resolver.resolve(principal))
        except Exception:
            self._raise_refusal(
                AuthorizationReasonCode.POLICY_RESOLUTION_FAILED,
                validated_request,
                principal_verified=True,
            )
        if (
            resolved.ref != validated_request.policy_ref
            or resolved.ref.tenant_id != principal.tenant_id
            or resolved.authority != principal.authority
        ):
            self._raise_refusal(
                AuthorizationReasonCode.POLICY_MISMATCH,
                validated_request,
                principal_verified=True,
            )
        if resolved.validator.validator_id == principal.actor_id:
            self._raise_refusal(
                AuthorizationReasonCode.SELF_VALIDATION,
                validated_request,
                principal_verified=True,
            )
        if resolved.validator.role not in self._allowed_validator_roles:
            self._raise_refusal(
                AuthorizationReasonCode.VALIDATOR_NOT_ALLOWED,
                validated_request,
                principal_verified=True,
            )
        try:
            snapshot_evaluator = _snapshot_evaluator(resolved)
        except Exception:
            self._raise_refusal(
                AuthorizationReasonCode.POLICY_MISMATCH,
                validated_request,
                principal_verified=True,
            )

        try:
            if not self._audit.strict_integrity_ready:
                raise RuntimeError("trusted audit checkpoint is unavailable")
        except Exception:
            self._raise_refusal(
                AuthorizationReasonCode.AUDIT_FAILED,
                validated_request,
                principal_verified=True,
            )

        try:
            expiry_candidates = [
                authorized_dt + self._authorization_ttl,
                _parse_utc(principal.expires_at),
                *(_parse_utc(item.expires_at) for item in validated_request.evidence),
            ]
            expires_dt = min(expiry_candidates)
            if expires_dt <= authorized_dt:
                raise ValueError("authorization has no positive validity window")
            expires_at = _utc_iso(expires_dt)
            auth_context_hash = strict_json_hash(_plain_object(principal.authentication_context))
            evidence_digest = compute_evidence_digest(validated_request.evidence)
            original_arguments = _plain_object(validated_request.args)
            original_hash = strict_json_hash(original_arguments)
        except (TypeError, ValueError):
            self._raise_refusal(
                AuthorizationReasonCode.INVALID_EVIDENCE,
                validated_request,
                principal_verified=True,
            )

        trusted_state = _policy_state(
            request_id=validated_request.request_id,
            tenant_id=validated_request.tenant_id,
            actor_role=validated_request.actor_role,
            authority=validated_request.authority,
            server_id=validated_request.server_id,
            tool=validated_request.tool,
            operation=validated_request.operation,
            resource=validated_request.resource,
            environment=validated_request.environment,
            execution_boundary=validated_request.execution_boundary,
            side_effect_class=validated_request.side_effect_class,
            policy_bundle_id=resolved.ref.bundle_id,
            policy_version=resolved.ref.version,
            policy_digest=resolved.ref.digest,
            policy_attestation_tenant_id=resolved.attestation.tenant_id,
            policy_attestation_artifact_id=resolved.attestation.artifact_id,
            policy_attestation_version=resolved.attestation.policy_version,
            policy_attestation_digest=resolved.attestation.digest,
            policy_attestation_resolver_id=resolved.attestation.resolver_id,
            evidence_digest=evidence_digest,
            authentication_context_hash=auth_context_hash,
        )
        policy = _StrictResolvedPolicy(
            snapshot_evaluator,
            expected_tool=validated_request.operation,
            expected_argument_hash=original_hash,
            expected_version=resolved.ref.version,
        )
        kernel = Kernel(
            policy=policy,
            audit=self._audit,
            actor=principal.actor_id,
            policy_timeout=self._policy_timeout,
            side_store=self._side_store,
            context_hydrator=lambda _name, _args: dict(trusted_state),
        )
        call = ToolCall(
            name=validated_request.operation,
            args=original_arguments,
            goal=goal_receipt_claim(validated_request.goal),
            actor=principal.actor_id,
            state=trusted_state,
        )
        try:
            record, audit_commit = kernel.evaluate_and_record_commit(
                call,
                trusted_timestamp_iso=authorized_at,
                trusted_fail_closed_policy_version=resolved.ref.version,
            )
        except Exception:
            self._raise_refusal(
                AuthorizationReasonCode.AUDIT_FAILED,
                validated_request,
                principal_verified=True,
            )

        if record.decision is Decision.TRANSFORM:
            if type(record.transformed_args) is not dict:
                self._raise_refusal(
                    AuthorizationReasonCode.MALFORMED_TRANSFORM,
                    validated_request,
                    principal_verified=True,
                )
            approved_arguments: Mapping[str, Any] = record.transformed_args
        elif record.decision is Decision.ALLOW:
            approved_arguments = original_arguments
        else:
            approved_arguments = {}

        try:
            binding = build_reserved_binding(
                validated_request,
                principal,
                resolved,
                approved_arguments,
                audit_checkpoint=_checkpoint_binding(audit_commit),
                decision=record.decision,
                authorized_at=authorized_at,
                expires_at=expires_at,
                binding_hmac_key=self._binding_hmac_key,
                allowed_validator_roles=self._allowed_validator_roles,
            )
            audit_hash = audit_commit.event_hash
            previous_hash = cast(str, audit_commit.event["previous_hash"])
            receipt = DecisionReceipt.from_record(
                record=record,
                audit_hash=audit_hash,
                previous_audit_hash=previous_hash,
                tenant_id=validated_request.tenant_id,
                execution_boundary=validated_request.execution_boundary,
                policy_bundle_id=resolved.ref.bundle_id,
                policy_hash=resolved.ref.digest,
                request_id=validated_request.request_id,
                validator=resolved.validator,
                authority=resolved.authority,
                constraints=reserved_constraints(binding),
                expires_at=expires_at,
                signer=self._signer,
            )
            primary = {
                Decision.ALLOW: AuthorizationReasonCode.ALLOWED,
                Decision.TRANSFORM: AuthorizationReasonCode.TRANSFORMED,
                Decision.DENY: AuthorizationReasonCode.DENIED,
                Decision.ESCALATE: AuthorizationReasonCode.ESCALATED,
            }[record.decision]
            reasons: tuple[AuthorizationReasonCode, ...] = (primary,)
            if record.decision is Decision.DENY:
                if any("MALFORMED_TRANSFORM" in rule for rule in record.matched_rules):
                    reasons = (primary, AuthorizationReasonCode.MALFORMED_TRANSFORM)
                elif any(
                    "POLICY_ERROR" in rule or rule.startswith("KERNEL_ERROR")
                    for rule in record.matched_rules
                ):
                    reasons = (primary, AuthorizationReasonCode.INTERNAL_FAILURE)
            return SideEffectAuthorization(
                request_id=validated_request.request_id,
                decision=record.decision,
                reason_codes=reasons,
                original_arguments_hash=original_hash,
                approved_arguments_hash=strict_json_hash(approved_arguments),
                binding_hash=reserved_binding_hash(binding),
                audit_event_id=record.event_id,
                audit_event_hash=audit_hash,
                previous_audit_hash=previous_hash,
                approved_arguments=approved_arguments,
                reserved_binding=binding,
                receipt=receipt,
            )
        except AuthorizationError:
            raise
        except Exception:
            self._raise_refusal(
                AuthorizationReasonCode.RECEIPT_FAILED,
                validated_request,
                principal_verified=True,
            )

    def _raise_refusal(
        self,
        reason_code: AuthorizationReasonCode,
        request: SideEffectRequest,
        *,
        principal_verified: bool,
    ) -> NoReturn:
        evidence = self._emit_refusal_evidence(
            reason_code,
            request,
            principal_verified=principal_verified,
        )
        raise AuthorizationError(reason_code, evidence=evidence)

    def record_refusal(
        self,
        *,
        request_id: str,
        reason_code: AuthorizationReasonCode,
        decision: Decision,
        exact_reason_codes: tuple[str, ...],
        claimed_tenant_id: str,
        claimed_actor_id: str,
        operation: str,
        argument_hash: str,
        policy_digest: str,
        policy_version: str,
        principal_verified: bool,
        goal_claim: str,
    ) -> RefusalEvidence:
        """Commit and sign non-executable refusal evidence for an outer gate.

        Protocol adapters sometimes must reject before a complete
        :class:`SideEffectRequest` can be constructed (for example, invalid
        authentication, malformed protocol input, or an unsafe network
        origin).  This method deliberately reuses the kernel's existing
        refusal signer and strict audit chain; it cannot issue an executable
        receipt or call an adapter.
        """

        if not isinstance(reason_code, AuthorizationReasonCode):
            raise TypeError("reason_code must be an AuthorizationReasonCode")
        if decision not in {Decision.DENY, Decision.ESCALATE}:
            raise ValueError("refusal decision must be DENY or ESCALATE")
        if type(exact_reason_codes) is not tuple or not exact_reason_codes:
            raise TypeError("exact_reason_codes must be a non-empty tuple")
        if type(principal_verified) is not bool:
            raise TypeError("principal_verified must be a boolean")
        return self._emit_refusal_evidence_fields(
            request_id=request_id,
            reason_code=reason_code,
            decision=decision,
            exact_reason_codes=exact_reason_codes,
            claimed_tenant_id=claimed_tenant_id,
            claimed_actor_id=claimed_actor_id,
            operation=operation,
            argument_hash=argument_hash,
            policy_digest=policy_digest,
            policy_version=policy_version,
            principal_verified=principal_verified,
            goal_claim=goal_claim,
        )

    def _emit_refusal_evidence(
        self,
        reason_code: AuthorizationReasonCode,
        request: SideEffectRequest,
        *,
        principal_verified: bool,
    ) -> RefusalEvidence:
        argument_hash = strict_json_hash(_plain_object(request.args))
        return self._emit_refusal_evidence_fields(
            request_id=request.request_id,
            reason_code=reason_code,
            decision=Decision.DENY,
            exact_reason_codes=(reason_code.value,),
            claimed_tenant_id=request.tenant_id,
            claimed_actor_id=request.actor_id,
            operation=request.operation,
            argument_hash=argument_hash,
            policy_digest=request.policy_ref.digest,
            policy_version=request.policy_ref.version,
            principal_verified=principal_verified,
            goal_claim=goal_receipt_claim(request.goal),
        )

    def _emit_invalid_request_evidence(self, request: object) -> RefusalEvidence:
        fingerprint_payload: dict[str, Any] = {
            "schema": "gove-zone.invalid-side-effect-request-fingerprint.v1",
            "contract_type": (
                "SideEffectRequest" if isinstance(request, SideEffectRequest) else "other"
            ),
        }
        argument_hash = strict_json_hash({"invalid_side_effect_request": True})
        policy_digest = strict_json_hash({"unverified_policy_reference": True})
        if isinstance(request, SideEffectRequest):
            for name in (
                "request_id",
                "tenant_id",
                "actor_id",
                "operation",
                "requested_at",
            ):
                try:
                    value = object.__getattribute__(request, name)
                except Exception:
                    fingerprint_payload[name] = "unavailable"
                else:
                    try:
                        fingerprint_payload[name] = (
                            strict_json_hash(value) if type(value) is str else "invalid-type"
                        )
                    except Exception:
                        fingerprint_payload[name] = "invalid-text"
            try:
                arguments = _plain_object(object.__getattribute__(request, "args"))
                argument_hash = strict_json_hash(arguments)
                fingerprint_payload["argument_hash"] = argument_hash
            except Exception:
                fingerprint_payload["argument_hash"] = argument_hash
            try:
                policy_ref = object.__getattribute__(request, "policy_ref")
                if isinstance(policy_ref, ResolvedPolicyRef):
                    policy_digest = strict_json_hash(policy_ref.to_dict())
            except Exception:
                fingerprint_payload["policy_reference_error"] = True
            fingerprint_payload["policy_reference_hash"] = policy_digest

        fingerprint = strict_json_hash(fingerprint_payload)
        suffix = fingerprint[:16]
        request_id = f"invalid-request-{suffix}"
        tenant_id = f"unverified-tenant-{suffix}"
        actor_id = f"unverified-actor-{suffix}"
        operation = f"invalid-operation-{suffix}"
        return self._emit_refusal_evidence_fields(
            request_id=request_id,
            reason_code=AuthorizationReasonCode.INVALID_REQUEST,
            decision=Decision.DENY,
            exact_reason_codes=(AuthorizationReasonCode.INVALID_REQUEST.value,),
            claimed_tenant_id=tenant_id,
            claimed_actor_id=actor_id,
            operation=operation,
            argument_hash=argument_hash,
            policy_digest=policy_digest,
            policy_version="invalid-request/v1",
            principal_verified=False,
            goal_claim=f"sha256:{fingerprint}",
        )

    def _emit_refusal_evidence_fields(
        self,
        *,
        request_id: str,
        reason_code: AuthorizationReasonCode,
        decision: Decision,
        exact_reason_codes: tuple[str, ...],
        claimed_tenant_id: str,
        claimed_actor_id: str,
        operation: str,
        argument_hash: str,
        policy_digest: str,
        policy_version: str,
        principal_verified: bool,
        goal_claim: str,
    ) -> RefusalEvidence:
        evidence = RefusalEvidence(
            request_id=request_id,
            reason_code=reason_code,
            decision=decision,
            reason_codes=exact_reason_codes,
            claimed_tenant_id=claimed_tenant_id,
            claimed_actor_id=claimed_actor_id,
            operation=operation,
            argument_hash=argument_hash,
            policy_digest=policy_digest,
            principal_verified=principal_verified,
            audited=False,
            signed=False,
            signing_key_id=self._signer.key_id,
            signature_algorithm=self._signer.algorithm,
        )
        state_hash = strict_json_hash(evidence._audit_state_dict())
        request_hash = sha256_json(
            {
                "actor": claimed_actor_id,
                "path": [],
                "goal": goal_claim,
                "tool": operation,
                "argument_hash": argument_hash,
                "state_hash": state_hash,
            }
        )
        record = DecisionRecord(
            decision=decision,
            tool=operation,
            argument_hash=argument_hash,
            policy_version=policy_version,
            event_id=new_event_id(),
            matched_rules=exact_reason_codes,
            reason=(
                "side-effect authorization refused before executable issuance: "
                + ",".join(exact_reason_codes)
            ),
            actor=claimed_actor_id,
            goal=goal_claim,
            state_hash=state_hash,
            decision_request_hash=request_hash,
            timestamp_iso=_utc_iso(datetime.now(UTC)),
        )
        try:
            commit = self._audit.append_committed(record)
        except Exception:
            commit = None
        if commit is not None:
            evidence = dataclasses.replace(
                evidence,
                audited=True,
                audit_event_id=commit.event_id,
                audit_event_hash=commit.event_hash,
                audit_checkpoint_hash=commit.checkpoint.checkpoint_hash,
                payload_hash="",
            )
        try:
            signature = self._signer.sign(evidence.payload_hash.encode("utf-8"))
        except Exception:
            return evidence
        return dataclasses.replace(evidence, signed=True, signature=signature)


class ReceiptGatedSideEffectExecutor:
    """Final receipt gate with anchored integrity and explicit outcome certainty."""

    def __init__(
        self,
        *,
        principal_resolver: PrincipalResolver,
        policy_resolver: PolicyResolver,
        audit: ChainHashAuditStore,
        consumption_store: ReceiptConsumptionStore,
        verifier: ReceiptSigner | Mapping[str, ReceiptSigner],
        lifecycle_signer: ReceiptSigner | None = None,
        lifecycle_authority_id: str = "lifecycle-validator",
        binding_hmac_key: bytes,
        allowed_validator_roles: Collection[str],
        require_signature: bool = True,
        tool_tier_registry: ToolTierRegistry | None = None,
        adapter_timeout: float | None = None,
        aggregate_capture_budget_bytes: int = DEFAULT_AGGREGATE_CAPTURE_BUDGET_BYTES,
        clock: _Clock | None = None,
    ) -> None:
        if not isinstance(principal_resolver, PrincipalResolver):
            raise TypeError("principal_resolver must implement PrincipalResolver")
        if not isinstance(policy_resolver, PolicyResolver):
            raise TypeError("policy_resolver must implement PolicyResolver")
        if not isinstance(audit, ChainHashAuditStore):
            raise TypeError("audit must be a ChainHashAuditStore")
        if not isinstance(consumption_store, ReceiptConsumptionStore):
            raise TypeError("consumption_store must be a ReceiptConsumptionStore")
        try:
            audit_ready = audit.strict_integrity_ready
        except Exception:
            raise ValueError("strict side-effect execution audit is unavailable") from None
        if not audit_ready:
            raise ValueError("strict side-effect execution requires a trusted audit checkpoint")
        try:
            consumption_ready = consumption_store.strict_integrity_ready
        except Exception:
            raise ValueError("strict side-effect consumption state is unavailable") from None
        if not consumption_ready:
            raise ValueError("strict side-effect execution requires a trusted consumption anchor")
        if verifier is None:
            raise ValueError("strict side-effect execution requires a verifier")
        if type(binding_hmac_key) is not bytes or len(binding_hmac_key) < 32:
            raise ValueError("binding_hmac_key must contain at least 32 bytes")
        if require_signature is not True:
            raise ValueError("strict side-effect execution requires signatures")
        if isinstance(allowed_validator_roles, (str, bytes)):
            raise ValueError("allowed_validator_roles must be a non-empty collection")
        roles = frozenset(
            _require_text(role, "allowed validator role") for role in allowed_validator_roles
        )
        if not roles:
            raise ValueError("allowed_validator_roles must be a non-empty collection")
        if adapter_timeout is not None and (
            isinstance(adapter_timeout, bool)
            or not isinstance(adapter_timeout, (int, float))
            or not math.isfinite(float(adapter_timeout))
            or adapter_timeout <= 0
        ):
            raise ValueError("adapter_timeout must be a finite positive number")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")

        self._principal_resolver = principal_resolver
        self._policy_resolver = policy_resolver
        self._audit = audit
        self._consumption_store = consumption_store
        self._verifier = verifier
        self._lifecycle_signer = lifecycle_signer
        self._lifecycle_authority_id = _require_text(
            lifecycle_authority_id,
            "lifecycle_authority_id",
        )
        self._binding_hmac_key = binding_hmac_key
        self._allowed_validator_roles = roles
        self._tool_tier_registry = tool_tier_registry
        self._adapter_timeout = float(adapter_timeout) if adapter_timeout is not None else None
        self._clock = clock or (lambda: datetime.now(UTC))
        self._registry: dict[_Route, Callable[..., Any]] = {}
        self._artifact_requirements: dict[_Route, ImmutableArtifactRequirement] = {}
        self._registry_lock = RLock()
        self._registry_frozen = False
        # Executor-wide, fail-closed ceiling on concurrently-held artifact-capture
        # bytes. Constructed once so the bound is shared across every execute; a
        # route with no artifact requirement never touches it (P1/P2 unaffected).
        self._capture_budget = _AggregateCaptureBudget(aggregate_capture_budget_bytes)
        # Non-forgeable per-executor identity stamped onto every snapshot this
        # executor captures. A pre-minted snapshot is accepted for execution only
        # when its capture lease names THIS token as owner, so a module-level or
        # foreign-executor snapshot (whose lease is absent or names another owner)
        # is refused pre-adapter with verifiable evidence.
        self._capture_owner = object()

    def capture_artifact_snapshot(
        self,
        source: str | Any,
        *,
        max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> ImmutableArtifactSnapshot:
        """Capture an immutable artifact snapshot through the kernel-owned factory.

        Callers never mint snapshots themselves. Capture is deliberately a
        kernel entry point so that what a gate later compares and what an
        adapter later consumes are the same bytes, taken once, here.

        The capture is leased to this executor: the artifact's exact size is
        charged to the executor's aggregate capture budget BEFORE the bytes are
        read (an over-budget capture is refused with no allocation), and the
        returned snapshot carries a non-forgeable lease naming this executor as
        owner. The reservation is held for the snapshot's lifetime and released
        exactly once when the snapshot is closed, so a caller that retains many
        snapshots cannot exceed the aggregate ceiling and a snapshot passed back
        for pre-minted execution is provably this executor's own.
        """

        return capture_immutable_artifact(
            source,
            max_bytes=max_bytes,
            owner=self._capture_owner,
            acquire=self._capture_budget.acquire,
            release=self._capture_budget.release,
        )

    def _require_owned_snapshot(self, snapshot: object) -> ImmutableArtifactSnapshot:
        """Return a live snapshot leased to THIS executor, or refuse pre-adapter.

        A module-level (unleased) snapshot or one leased to a different executor
        is refused with an execution reason code, so a pre-minted binding can
        only carry a snapshot this executor captured and whose retained bytes it
        already charged to its own aggregate budget.
        """

        try:
            proven = require_immutable_artifact_snapshot(snapshot)
            lease = artifact_snapshot_lease(proven)
        except PathCapabilityError:
            raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT) from None
        if lease is None or lease.owner is not self._capture_owner:
            raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT)
        return proven

    def register_artifact_requirement(
        self,
        server_id: str,
        tool: str,
        operation: str,
        requirement: ImmutableArtifactRequirement,
    ) -> None:
        """Require an immutable snapshot proof for one route's digest argument.

        A requirement may only be registered *before* the route's adapter is
        published. Publishing an adapter first and adding the requirement second
        is the exact interposition gap that let a concurrent :meth:`execute`
        freeze the registry with an adapter but no requirement — an
        artifact-proof bypass. That ordering is now refused; publish an
        artifact-gated route atomically with :meth:`register_route`.
        """

        route = (
            _require_text(server_id, "server_id"),
            _require_text(tool, "tool"),
            _require_text(operation, "operation"),
        )
        if type(requirement) is not ImmutableArtifactRequirement:
            raise TypeError("requirement must be an exact ImmutableArtifactRequirement")
        with self._registry_lock:
            if self._registry_frozen:
                raise RuntimeError("adapter registry is frozen after first execute")
            if route in self._registry:
                raise RuntimeError(
                    "adapter is already published for this route; register the artifact "
                    "requirement atomically with the adapter via register_route"
                )
            if route in self._artifact_requirements:
                raise ValueError(f"artifact requirement is already registered: {route!r}")
            self._artifact_requirements[route] = requirement

    def register_route(
        self,
        server_id: str,
        tool: str,
        operation: str,
        adapter: Callable[..., Any],
        *,
        artifact_requirement: ImmutableArtifactRequirement | None = None,
    ) -> None:
        """Atomically publish one adapter and its optional artifact requirement.

        Both registrations commit under a single hold of the registry lock, so a
        concurrent :meth:`execute` — which freezes the registry under the same
        lock — can never observe a route that has an adapter but is missing its
        intended immutable-artifact requirement. This is the only safe way to
        publish an artifact-gated route; the separate :meth:`register_adapter` /
        :meth:`register_artifact_requirement` calls cannot express the two
        registrations as one atomic, fail-closed step. Freeze semantics remain
        fail closed: once frozen, this refuses.
        """

        route = (
            _require_text(server_id, "server_id"),
            _require_text(tool, "tool"),
            _require_text(operation, "operation"),
        )
        if not callable(adapter):
            raise TypeError("adapter must be callable")
        if artifact_requirement is not None and (
            type(artifact_requirement) is not ImmutableArtifactRequirement
        ):
            raise TypeError("artifact_requirement must be an exact ImmutableArtifactRequirement")
        with self._registry_lock:
            if self._registry_frozen:
                raise RuntimeError("adapter registry is frozen after first execute")
            if route in self._registry:
                raise ValueError(f"adapter route is already registered: {route!r}")
            if route in self._artifact_requirements:
                raise ValueError(f"artifact requirement is already registered: {route!r}")
            self._registry[route] = adapter
            if artifact_requirement is not None:
                self._artifact_requirements[route] = artifact_requirement

    def _precheck_artifact_binding(
        self,
        requirement: ImmutableArtifactRequirement | None,
        binding: PreAdapterDigestBinding | None,
        source: Any,
        approved_arguments: Mapping[str, Any],
    ) -> None:
        """Refuse a missing, forged, closed, or wrong-route artifact input by shape.

        This runs at the authorization gate, before any state is reserved, so an
        obviously malformed binding — or the legacy "no snapshot and no source"
        call — is refused without burning a reservation, and with verifiable
        refusal evidence rather than a pre-execute ValueError. It deliberately
        does NOT open the source or compare the digest: the fixed kernel-owned
        secure capture and the authoritative content comparison both belong at
        the last controllable boundary, after the receipt has been re-verified
        against the approved arguments.
        """

        if requirement is None:
            if binding is not None or source is not None:
                raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT)
            return
        # Requirement present: exactly one of a caller pre-minted binding or a
        # data-only source path must be supplied. Neither (or both) fails closed
        # here — before any reservation — so an omitted artifact input fails
        # closed with evidence instead of raising a pre-execute ValueError.
        if (binding is None) == (source is None):
            raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT)
        if requirement.snapshot_parameter in approved_arguments:
            raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT)
        if requirement.argument_name not in approved_arguments:
            raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT)
        if binding is not None:
            if type(binding) is not PreAdapterDigestBinding:
                raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT)
            if binding.argument_name != requirement.argument_name:
                raise SideEffectExecutionError(ExecutionReasonCode.BINDING_MISMATCH)
            # A pre-minted snapshot must be one THIS executor captured (its bytes
            # were charged to this executor's aggregate budget at capture time).
            # A module-level or foreign-executor snapshot is refused here, before
            # any reservation, with verifiable AUTHORIZATION_GATE refusal evidence.
            self._require_owned_snapshot(binding.snapshot)
            return
        # Data-only source: a Path/str the kernel captures itself at the last
        # controllable boundary. Never a callable — capture is a fixed
        # kernel-owned secure read, never deferred to caller code.
        if callable(source) or not isinstance(source, (str, os.PathLike)):
            raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT)

    def _verified_artifact_kwargs(
        self,
        requirement: ImmutableArtifactRequirement | None,
        binding: PreAdapterDigestBinding | None,
        approved_arguments: Mapping[str, Any],
    ) -> dict[str, ImmutableArtifactSnapshot]:
        """Prove the bound snapshot reproduces the receipted digest, or refuse.

        This is the last controllable boundary. It runs after the receipt has
        been re-verified against the approved arguments and immediately before
        the adapter latch, so every failure here is refused while
        ``adapter_entered`` is still false and is therefore provably
        adapter-free. The digest is recomputed from the captured bytes rather
        than read off the snapshot, so the value compared is the value the
        adapter will consume.
        """

        if requirement is None:
            if binding is not None:
                raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT)
            return {}
        if type(binding) is not PreAdapterDigestBinding:
            raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT)
        if binding.argument_name != requirement.argument_name:
            raise SideEffectExecutionError(ExecutionReasonCode.BINDING_MISMATCH)
        if requirement.snapshot_parameter in approved_arguments:
            raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT)
        try:
            snapshot = require_immutable_artifact_snapshot(binding.snapshot)
            observed = snapshot.content_digest()
        except PathCapabilityError:
            raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT) from None
        approved = approved_arguments.get(requirement.argument_name)
        if type(approved) is not str or not hmac.compare_digest(observed, approved):
            raise SideEffectExecutionError(ExecutionReasonCode.BINDING_MISMATCH)
        return {requirement.snapshot_parameter: snapshot}

    def _capture_source_binding(
        self,
        requirement: ImmutableArtifactRequirement,
        source: Any,
    ) -> PreAdapterDigestBinding:
        """Capture the artifact source under kernel control at the last boundary.

        This is a fixed kernel-owned secure read (``capture_immutable_artifact``:
        every path component ``O_NOFOLLOW``, the file
        ``O_RDONLY|O_CLOEXEC|O_NOFOLLOW``, regular and non-hardlinked,
        size-bounded, identical ``fstat`` before and after, digest recomputed
        from the captured bytes) — never a caller callback. It runs
        post-reservation and immediately before ``adapter_entered`` is set, so a
        missing / open / fstat / read / oversize / changed source raises here
        while the adapter is provably not entered and is refused with evidence.
        Every ``PathCapabilityError`` and raw ``OSError`` is wrapped into a
        closed execution reason so no raw OS error escapes the structured
        boundary; the recomputed-digest comparison against the receipted
        argument still happens in :meth:`_verified_artifact_kwargs`.
        """

        try:
            snapshot = self.capture_artifact_snapshot(source)
        except (PathCapabilityError, OSError):
            raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT) from None
        return PreAdapterDigestBinding(
            argument_name=requirement.argument_name,
            snapshot=snapshot,
        )

    def register_adapter(
        self,
        server_id: str,
        tool: str,
        operation: str,
        adapter: Callable[..., Any],
    ) -> None:
        route = (
            _require_text(server_id, "server_id"),
            _require_text(tool, "tool"),
            _require_text(operation, "operation"),
        )
        if not callable(adapter):
            raise TypeError("adapter must be callable")
        with self._registry_lock:
            if self._registry_frozen:
                raise RuntimeError("adapter registry is frozen after first execute")
            if route in self._registry:
                raise ValueError(f"adapter route is already registered: {route!r}")
            self._registry[route] = adapter

    def execute(
        self,
        authorization: SideEffectAuthorization | None,
        context: SideEffectExecutionContext,
        *,
        nonce: str,
        idempotency_key: str,
        artifact_binding: PreAdapterDigestBinding | None = None,
        artifact_source: Any = None,
    ) -> Any:
        with self._registry_lock:
            self._registry_frozen = True

        if authorization is None:
            raise SideEffectExecutionError(ExecutionReasonCode.MISSING_AUTHORIZATION)
        try:
            authorization = dataclasses.replace(authorization)
        except Exception:
            raise SideEffectExecutionError(ExecutionReasonCode.RECEIPT_INVALID) from None
        if not authorization.executable or authorization.receipt is None:
            self._refuse(
                ExecutionReasonCode.NOT_EXECUTABLE,
                authorization=authorization,
                phase=ExecutionRefusalPhase.AUTHORIZATION_GATE,
            )
        try:
            context = dataclasses.replace(
                context,
                policy_ref=dataclasses.replace(context.policy_ref),
            )
            trusted_now = _utc_iso(self._clock())
        except Exception:
            self._refuse(
                ExecutionReasonCode.INVALID_CONTEXT,
                authorization=authorization,
                phase=ExecutionRefusalPhase.AUTHORIZATION_GATE,
            )

        receipt = authorization.receipt
        # Every gate below refuses before any adapter is selected or entered, so
        # a refusal here is provably adapter-free. Evidence is emitted once, at
        # the single exit, rather than duplicated at each raise site.
        try:
            self._require_integrity_ready()
            binding = _plain_object(authorization.reserved_binding)
            try:
                principal = _validated_principal(self._principal_resolver.resolve())
            except Exception:
                raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT) from None
            self._validate_context(context, principal, binding, trusted_now=trusted_now)
            resolved = self._resolve_current_policy(principal)
            self._validate_current_policy(resolved, binding, actor_id=principal.actor_id)
            self._validate_secret_bindings(
                binding,
                tenant_id=context.tenant_id,
                nonce=nonce,
                idempotency_key=idempotency_key,
            )
            self._verify_receipt(
                receipt,
                authorization,
                context,
                binding,
                trusted_now=trusted_now,
            )
            try:
                existing_consumption = self._consumption_store.status(
                    context.tenant_id,
                    receipt.receipt_id,
                )
            except ReceiptConsumptionError:
                raise SideEffectExecutionError(
                    ExecutionReasonCode.CONSUMPTION_STATE_FAILED
                ) from None
            if existing_consumption is not None:
                if existing_consumption.state is ConsumptionState.REVOKED:
                    raise SideEffectExecutionError(ExecutionReasonCode.REVOKED)
                raise SideEffectExecutionError(ExecutionReasonCode.REPLAY)
            authorization_commit = self._verify_audit_event(authorization, binding)
            # Bind once: the gate below and the attestation issued later must be
            # decided by the same signer value, not by a re-read of the attribute.
            lifecycle_signer = self._lifecycle_signer
            if lifecycle_signer is None:
                raise SideEffectExecutionError(ExecutionReasonCode.AUDIT_HASH_MISMATCH)
            if lifecycle_signer.key_id == authorization_commit.checkpoint.key_id:
                raise SideEffectExecutionError(ExecutionReasonCode.AUDIT_HASH_MISMATCH)
            if self._lifecycle_authority_id in {
                "audit-checkpoint",
                f"audit-checkpoint:{authorization_commit.checkpoint.namespace}",
            }:
                raise SideEffectExecutionError(ExecutionReasonCode.AUDIT_HASH_MISMATCH)

            route = (context.server_id, context.tool, context.operation)
            with self._registry_lock:
                adapter = self._registry.get(route)
                requirement = self._artifact_requirements.get(route)
            if adapter is None:
                raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT)
            # Shape-only pre-check so a missing, forged, closed, or wrong-route
            # binding is refused at the authorization gate, before any state is
            # reserved. The authoritative digest comparison still happens at the
            # last controllable boundary below; this never substitutes for it.
            self._precheck_artifact_binding(
                requirement,
                artifact_binding,
                artifact_source,
                _plain_object(authorization.approved_arguments),
            )

            try:
                if self._consumption_store.is_revoked(context.tenant_id, receipt.receipt_id):
                    raise SideEffectExecutionError(ExecutionReasonCode.REVOKED)
            except SideEffectExecutionError:
                raise
            except ReceiptConsumptionError:
                raise SideEffectExecutionError(
                    ExecutionReasonCode.CONSUMPTION_STATE_FAILED
                ) from None
        except SideEffectExecutionError as gate_refusal:
            self._refuse(
                gate_refusal.reason_code,
                authorization=authorization,
                phase=ExecutionRefusalPhase.AUTHORIZATION_GATE,
            )

        attempt_id = f"attempt_{secrets.token_hex(16)}"
        try:
            self._consumption_store.reserve(
                context.tenant_id,
                receipt.receipt_id,
                nonce,
                receipt.receipt_hash,
                authorization.binding_hash,
                attempt_id,
                idempotency_digest=cast(str, binding["idempotency_digest"]),
            )
        except ReceiptReplayError:
            self._refuse(
                ExecutionReasonCode.REPLAY,
                authorization=authorization,
                phase=ExecutionRefusalPhase.RESERVATION,
            )
        except ReceiptRevokedError:
            self._refuse(
                ExecutionReasonCode.REVOKED,
                authorization=authorization,
                phase=ExecutionRefusalPhase.RESERVATION,
            )
        except (ConsumptionStoreError, ConsumptionTransitionError, ReceiptConsumptionError):
            self._refuse(
                ExecutionReasonCode.RESERVATION_FAILED,
                authorization=authorization,
                phase=ExecutionRefusalPhase.RESERVATION,
            )

        adapter_id = f"{context.server_id}:{context.tool}:{context.operation}"
        idempotency_digest = cast(str, binding["idempotency_digest"])
        # Latched immediately before control passes to adapter code. A refusal
        # may only be claimed while this is false; otherwise a hostile adapter
        # could raise SideEffectExecutionError and forge "the adapter never ran".
        adapter_entered = False

        def append_execution_event(
            *,
            reason_code: str,
            state: ConsumptionState,
            phase: str,
        ) -> AuditCommit:
            evidence = _execution_evidence(
                tenant_id=context.tenant_id,
                execution_boundary=context.execution_boundary,
                adapter_id=adapter_id,
                receipt=receipt,
                authorization_audit_hash=authorization_commit.event_hash,
                nonce_material=nonce,
                idempotency_digest=idempotency_digest,
                attempt_id=attempt_id,
                binding_hash=authorization.binding_hash,
                argument_hash=receipt.argument_hash,
                phase=phase,
                reason_code=reason_code,
                state=state,
            )
            return self._audit.append_committed(
                DecisionRecord.lifecycle(
                    decision=(
                        Decision.ALLOW if state is not ConsumptionState.UNKNOWN else Decision.DENY
                    ),
                    tool=context.operation,
                    argument_hash=receipt.argument_hash,
                    policy_version=context.policy_ref.version,
                    event_id=new_event_id(),
                    matched_rules=(reason_code,),
                    reason=reason_code,
                    actor=context.actor_id,
                    timestamp_iso=_utc_iso(self._clock()),
                    execution_evidence=evidence,
                    signer=lifecycle_signer,
                    authority_id=self._lifecycle_authority_id,
                )
            )

        def confirm_unknown() -> None:
            try:
                self._require_consumption_ready()
                current = self._consumption_store.status(
                    context.tenant_id,
                    receipt.receipt_id,
                )
                if current is not None and current.state is ConsumptionState.RESERVED:
                    self._consumption_store.mark_unknown(
                        context.tenant_id,
                        receipt.receipt_id,
                        attempt_id,
                    )
                confirmed = self._consumption_store.status(
                    context.tenant_id,
                    receipt.receipt_id,
                )
            except ReceiptConsumptionError:
                raise SideEffectExecutionError(
                    ExecutionReasonCode.CONSUMPTION_STATE_FAILED
                ) from None
            if confirmed is None or confirmed.state is not ConsumptionState.UNKNOWN:
                raise SideEffectExecutionError(ExecutionReasonCode.CONSUMPTION_STATE_FAILED)

        def commit_unknown_outcome() -> None:
            confirm_unknown()
            try:
                append_execution_event(
                    reason_code=_REASON_OUTCOME_UNKNOWN,
                    state=ConsumptionState.UNKNOWN,
                    phase="terminal",
                )
            except Exception:
                raise SideEffectExecutionError(ExecutionReasonCode.AUDIT_HASH_MISMATCH) from None

        def commit_unknown_outcome_or_refuse() -> None:
            """Commit the UNKNOWN outcome; refuse if that provably pre-adapter fails.

            Committing the conservative UNKNOWN state and proving the refusal are
            independent obligations. A failure to record the terminal UNKNOWN
            lifecycle event is itself a provably pre-adapter failure whenever the
            adapter was never entered, so it must not swallow the refusal proof the
            way a bare raise from ``commit_unknown_outcome`` would: the caller would
            see the reason code with no evidence at all.

            The failure's own reason code stays primary — a terminal append failure
            reports AUDIT_HASH_MISMATCH, a state-confirmation failure reports
            CONSUMPTION_STATE_FAILED — and is additively evidenced. Once the adapter
            has been entered nothing is provable, so the original raise stands.

            Only callers whose ``adapter_entered`` read is ordered after the adapter
            thread may use this. The timeout path may not: its worker may still be
            mid-flight, so ``adapter_entered`` is racy there and False does not prove
            the adapter was skipped.
            """

            try:
                commit_unknown_outcome()
            except SideEffectExecutionError as terminal_failure:
                if adapter_entered:
                    raise
                self._refuse(
                    terminal_failure.reason_code,
                    authorization=authorization,
                    phase=ExecutionRefusalPhase.POST_RESERVATION,
                    attempt_id=attempt_id,
                )

        try:
            execution_claim = append_execution_event(
                reason_code=_REASON_RESERVED,
                state=ConsumptionState.RESERVED,
                phase="claim_committed",
            )
        except Exception:
            # Provably pre-adapter: this attempt is reserved but no adapter has
            # been selected or entered, so the refusal is evidenceable. State is
            # handled conservatively first, but a failure to confirm UNKNOWN must
            # not suppress the refusal proof: the two are independent, and the
            # primary AUDIT_HASH_MISMATCH stays the reported reason either way.
            with contextlib.suppress(Exception):
                confirm_unknown()
            self._refuse(
                ExecutionReasonCode.AUDIT_HASH_MISMATCH,
                authorization=authorization,
                phase=ExecutionRefusalPhase.POST_RESERVATION,
                attempt_id=attempt_id,
            )

        def reserved_committed_adapter_call() -> Any:
            # This closure exists only after this exact attempt was durably
            # reserved and is invoked only by ``run_if_committed`` below.
            self._require_consumption_ready()
            if self._consumption_store.is_revoked(context.tenant_id, receipt.receipt_id):
                raise SideEffectExecutionError(ExecutionReasonCode.REVOKED_AFTER_RESERVATION)
            reserved = self._consumption_store.status(context.tenant_id, receipt.receipt_id)
            if (
                reserved is None
                or reserved.state is not ConsumptionState.RESERVED
                or reserved.attempt_id != attempt_id
                or reserved.binding_hash != authorization.binding_hash
                or reserved.idempotency_digest != idempotency_digest
            ):
                raise SideEffectExecutionError(ExecutionReasonCode.CONSUMPTION_STATE_FAILED)
            current_principal = _validated_principal(self._principal_resolver.resolve())
            if current_principal != principal:
                raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT)
            current_policy = self._resolve_current_policy(current_principal)
            self._validate_current_policy(
                current_policy,
                binding,
                actor_id=current_principal.actor_id,
            )
            final_now = _utc_iso(self._clock())
            self._validate_context(
                context,
                current_principal,
                binding,
                trusted_now=final_now,
            )
            self._verify_receipt(
                receipt,
                authorization,
                context,
                binding,
                trusted_now=final_now,
            )
            approved_arguments = _plain_object(authorization.approved_arguments)

            def invoke_bound_adapter() -> Any:
                nonlocal adapter_entered
                validate_strict_json_budget(approved_arguments)
                receipt.verify(
                    expected_tenant_id=context.tenant_id,
                    expected_execution_boundary=context.execution_boundary,
                    expected_audit_hash=authorization.audit_event_hash,
                    expected_args=approved_arguments,
                    expected_action=context.operation,
                    expected_actor=context.actor_id,
                    expected_policy_hash=context.policy_ref.digest,
                    expected_policy_bundle_id=context.policy_ref.bundle_id,
                    expected_policy_version=context.policy_ref.version,
                    expected_validator_id=cast(str, binding["validator_id"]),
                    expected_validator_role=cast(str, binding["validator_role"]),
                    expected_authority=context.authority,
                    expected_constraints=reserved_constraints(authorization.reserved_binding),
                    expected_request_id=context.request_id,
                    verifier=self._verifier,
                    require_signature=True,
                    now_iso=final_now,
                    tool_tier_registry=self._tool_tier_registry,
                )
                # Last controllable boundary: the receipt has just been
                # re-verified against these exact approved arguments. When the
                # caller passed a data-only source path rather than a pre-minted
                # snapshot, the kernel captures it here — after reservation and
                # receipt re-verification, before the adapter latch — so a
                # missing/unsafe/oversize/changed source is refused with provable
                # evidence while ``adapter_entered`` is still false. The digest
                # recomputed below is then compared to an authenticated value, so
                # a content mismatch is likewise refused pre-adapter rather than
                # sanitized to an ambiguous outcome.
                # Aggregate capture budget & snapshot lifetime. The reservation is
                # tied to the ACGS-owned snapshot's lifetime, not to this adapter
                # window. A source snapshot is captured here — its EXACT size charged
                # to the executor budget BEFORE any bytes are read (an over-budget
                # capture is refused pre-adapter with zero side effect), then bound
                # to an executor-owned lease — and is closed deterministically in the
                # finally below, after the adapter, a refusal, or an UNKNOWN outcome,
                # releasing its lease exactly once. A caller's pre-minted snapshot
                # already holds its own lease (charged when the caller captured it
                # through this executor), so execution neither re-charges nor
                # releases it: the caller keeps the lease until it closes the
                # snapshot itself, and execution must not release it prematurely.
                # This bounds ACGS-owned allocation and lifetime only; a copy a
                # hostile adapter makes of the bytes is outside this boundary.
                effective_binding = artifact_binding
                source_snapshot: ImmutableArtifactSnapshot | None = None
                if requirement is not None and artifact_source is not None:
                    effective_binding = self._capture_source_binding(
                        requirement,
                        artifact_source,
                    )
                    source_snapshot = effective_binding.snapshot
                try:
                    adapter_kwargs = self._verified_artifact_kwargs(
                        requirement,
                        effective_binding,
                        approved_arguments,
                    )
                    adapter_entered = True
                    return adapter(**approved_arguments, **adapter_kwargs)
                finally:
                    if source_snapshot is not None:
                        source_snapshot.close()

            if self._adapter_timeout is None:
                return invoke_bound_adapter()
            pool = ThreadPoolExecutor(max_workers=1)
            try:
                adapter_context = copy_context()
                future = pool.submit(adapter_context.run, invoke_bound_adapter)
                return future.result(timeout=self._adapter_timeout)
            finally:
                pool.shutdown(wait=False, cancel_futures=True)

        try:
            self._require_integrity_ready()
            if self._consumption_store.is_revoked(context.tenant_id, receipt.receipt_id):
                raise SideEffectExecutionError(ExecutionReasonCode.REVOKED_AFTER_RESERVATION)
            outcome = self._audit.run_if_committed(
                execution_claim,
                reserved_committed_adapter_call,
            )
        except FuturesTimeoutError:
            # Ambiguous: the adapter may be mid-flight, so ``adapter_entered`` is
            # racy here and False would not prove the adapter was skipped. This
            # path must never claim a refusal: UNKNOWN, even if the terminal
            # append fails and reports AUDIT_HASH_MISMATCH unevidenced.
            commit_unknown_outcome()
            raise SideEffectExecutionError(ExecutionReasonCode.TIMEOUT) from None
        except SideEffectExecutionError as post_reservation_refusal:
            commit_unknown_outcome_or_refuse()
            if adapter_entered:
                # Control already passed to adapter code, so this exception is
                # not trustworthy: a hostile adapter can raise any reason code
                # carrying any evidence, including a valid refusal transplanted
                # from an unrelated attempt. Once the adapter has been entered
                # the outcome is ambiguous by definition, so the raise is
                # sanitized to the same UNKNOWN outcome any other adapter
                # exception produces. The UNKNOWN consumption state and
                # lifecycle event were already committed above; no refusal
                # evidence is emitted, because none can be proved.
                raise SideEffectExecutionError(ExecutionReasonCode.OUTCOME_UNKNOWN) from None
            self._refuse(
                post_reservation_refusal.reason_code,
                authorization=authorization,
                phase=ExecutionRefusalPhase.POST_RESERVATION,
                attempt_id=attempt_id,
            )
        except Exception:
            # Adapter raised, or a pre-adapter dependency failed ambiguously.
            # Neither proves the adapter was skipped: UNKNOWN, never refusal.
            commit_unknown_outcome_or_refuse()
            raise SideEffectExecutionError(ExecutionReasonCode.OUTCOME_UNKNOWN) from None

        if (
            type(outcome) is not AdapterOutcome
            or outcome.status is not AdapterOutcomeStatus.CONFIRMED_SUCCEEDED
        ):
            commit_unknown_outcome()
            raise SideEffectExecutionError(ExecutionReasonCode.OUTCOME_UNKNOWN)

        try:
            completed = self._consumption_store.mark_succeeded(
                context.tenant_id,
                receipt.receipt_id,
                attempt_id,
            )
        except ReceiptConsumptionError:
            try:
                observed = self._consumption_store.status(
                    context.tenant_id,
                    receipt.receipt_id,
                )
            except ReceiptConsumptionError:
                raise SideEffectExecutionError(
                    ExecutionReasonCode.CONSUMPTION_STATE_FAILED
                ) from None
            if observed is not None and observed.state is ConsumptionState.SUCCEEDED:
                try:
                    append_execution_event(
                        reason_code=_REASON_SUCCEEDED,
                        state=ConsumptionState.SUCCEEDED,
                        phase="terminal",
                    )
                except Exception:
                    raise SideEffectExecutionError(
                        ExecutionReasonCode.AUDIT_HASH_MISMATCH
                    ) from None
                return outcome.payload
            if observed is not None and observed.state is ConsumptionState.RESERVED:
                commit_unknown_outcome()
            raise SideEffectExecutionError(ExecutionReasonCode.OUTCOME_UNKNOWN) from None
        if completed.state is not ConsumptionState.SUCCEEDED:
            commit_unknown_outcome()
            raise SideEffectExecutionError(ExecutionReasonCode.OUTCOME_UNKNOWN)
        try:
            append_execution_event(
                reason_code=_REASON_SUCCEEDED,
                state=ConsumptionState.SUCCEEDED,
                phase="terminal",
            )
        except Exception:
            raise SideEffectExecutionError(ExecutionReasonCode.AUDIT_HASH_MISMATCH) from None
        return outcome.payload

    def _build_refusal_evidence(
        self,
        reason_code: ExecutionReasonCode,
        *,
        authorization: SideEffectAuthorization,
        phase: ExecutionRefusalPhase,
        attempt_id: str,
    ) -> ExecutionRefusalEvidence:
        """Build refusal evidence bound to the receipt and its reserved route.

        Every digest is taken from the receipt and the authenticated reserved
        binding, never from the caller-supplied execution context: a refusal
        attests the route the receipt authorized, not the one a caller claimed.
        """

        receipt = authorization.receipt
        if receipt is None:
            raise ValueError("execution refusal evidence requires a receipt")
        signer = self._lifecycle_signer
        binding = _plain_object(authorization.reserved_binding)
        adapter_id = ":".join(
            (
                _require_text(binding["server_id"], "server_id"),
                _require_text(binding["tool"], "tool"),
                _require_text(binding["operation"], "operation"),
            )
        )
        return ExecutionRefusalEvidence(
            request_id_digest=_evidence_digest("request_id", receipt.request_id),
            receipt_id_digest=_evidence_digest("receipt_id", receipt.receipt_id),
            receipt_hash=receipt.receipt_hash,
            tenant_digest=_evidence_digest("tenant", cast(str, binding["tenant_id"])),
            execution_boundary_digest=_evidence_digest(
                "execution_boundary",
                cast(str, binding["execution_boundary"]),
            ),
            adapter_id_digest=_evidence_digest("adapter_id", adapter_id),
            authorization_audit_digest=_evidence_digest(
                "authorization_audit",
                authorization.audit_event_hash,
            ),
            binding_hash=authorization.binding_hash,
            argument_hash=receipt.argument_hash,
            reason_code=reason_code,
            phase=phase,
            audited=False,
            attempt_id_digest=(
                _evidence_digest("attempt_id", attempt_id)
                if phase is ExecutionRefusalPhase.POST_RESERVATION
                else ""
            ),
            # Named before signing so the signature covers the key identity it
            # was produced with; ``signed`` itself is deliberately outside the
            # payload so flipping it cannot invalidate the hash.
            signing_key_id="" if signer is None else signer.key_id,
            signature_algorithm="" if signer is None else signer.algorithm,
        )

    def _emit_refusal_evidence(
        self,
        reason_code: ExecutionReasonCode,
        *,
        authorization: SideEffectAuthorization,
        phase: ExecutionRefusalPhase,
        attempt_id: str = "",
    ) -> ExecutionRefusalEvidence | None:
        """Commit and sign refusal evidence, never fabricating absent proofs.

        The audit append and the signature are independent: either may fail and
        the surviving proof is still returned. When both fail the evidence is
        returned with ``audited`` and ``signed`` both false — explicitly
        unverifiable rather than silently trusted.

        This must never be called while the audit sidecar lock is held: the
        append below takes the same exclusive lock and would self-deadlock.
        """

        try:
            evidence = self._build_refusal_evidence(
                reason_code,
                authorization=authorization,
                phase=phase,
                attempt_id=attempt_id,
            )
        except Exception:
            return None
        receipt = authorization.receipt
        if receipt is None:
            return None
        binding = _plain_object(authorization.reserved_binding)
        policy = cast(dict[str, Any], binding["policy"])
        state_hash = strict_json_hash(evidence._audit_state_dict())
        try:
            record = DecisionRecord(
                decision=Decision.DENY,
                tool=cast(str, binding["operation"]),
                argument_hash=receipt.argument_hash,
                policy_version=cast(str, policy["version"]),
                event_id=new_event_id(),
                matched_rules=(reason_code.value,),
                reason=reason_code.value,
                actor=cast(str, binding["actor_id"]),
                goal=receipt.declared_goal,
                state_hash=state_hash,
                decision_request_hash=sha256_json(
                    {
                        "actor": binding["actor_id"],
                        "path": [],
                        "goal": receipt.declared_goal,
                        "tool": binding["operation"],
                        "argument_hash": receipt.argument_hash,
                        "state_hash": state_hash,
                    }
                ),
                timestamp_iso=_utc_iso(self._clock()),
                record_kind=RecordKind.EXECUTION_REFUSAL,
                execution_evidence=evidence.audit_evidence(),
            )
            commit = self._audit.append_committed(record)
        except Exception:
            commit = None
        if commit is not None:
            evidence = dataclasses.replace(
                evidence,
                audited=True,
                audit_event_id=commit.event_id,
                audit_event_hash=commit.event_hash,
                audit_checkpoint_hash=commit.checkpoint.checkpoint_hash,
                audit_checkpoint_parent_hash=cast(
                    str,
                    commit.event["_audit_checkpoint_parent_hash"],
                ),
                payload_hash="",
            )
        signer = self._lifecycle_signer
        if signer is None:
            return evidence
        try:
            signature = signer.sign(evidence.payload_hash.encode("utf-8"))
        except Exception:
            return evidence
        try:
            return dataclasses.replace(evidence, signed=True, signature=signature)
        except Exception:
            return evidence

    def _refuse(
        self,
        reason_code: ExecutionReasonCode,
        *,
        authorization: SideEffectAuthorization,
        phase: ExecutionRefusalPhase,
        attempt_id: str = "",
    ) -> NoReturn:
        """Raise the original refusal, additively evidenced where provable."""

        evidence = None
        if reason_code in EXECUTION_REFUSAL_REASON_CODES:
            evidence = self._emit_refusal_evidence(
                reason_code,
                authorization=authorization,
                phase=phase,
                attempt_id=attempt_id,
            )
        raise SideEffectExecutionError(reason_code, evidence=evidence)

    def _require_integrity_ready(self) -> None:
        try:
            if not self._audit.strict_integrity_ready:
                raise SideEffectExecutionError(ExecutionReasonCode.AUDIT_HASH_MISMATCH)
        except SideEffectExecutionError:
            raise
        except Exception:
            raise SideEffectExecutionError(ExecutionReasonCode.AUDIT_HASH_MISMATCH) from None
        self._require_consumption_ready()

    def _require_consumption_ready(self) -> None:
        try:
            if not self._consumption_store.strict_integrity_ready:
                raise SideEffectExecutionError(ExecutionReasonCode.CONSUMPTION_STATE_FAILED)
        except SideEffectExecutionError:
            raise
        except Exception:
            raise SideEffectExecutionError(ExecutionReasonCode.CONSUMPTION_STATE_FAILED) from None

    def _resolve_current_policy(self, principal: VerifiedPrincipal) -> ResolvedPolicy:
        try:
            return _validated_resolved_policy(self._policy_resolver.resolve(principal))
        except Exception:
            raise SideEffectExecutionError(ExecutionReasonCode.BINDING_MISMATCH) from None

    def _validate_context(
        self,
        context: SideEffectExecutionContext,
        principal: VerifiedPrincipal,
        binding: dict[str, Any],
        *,
        trusted_now: str,
    ) -> None:
        expected = {
            "request_id": context.request_id,
            "tenant_id": context.tenant_id,
            "actor_id": context.actor_id,
            "actor_role": context.actor_role,
            "authority": context.authority,
            "server_id": context.server_id,
            "tool": context.tool,
            "operation": context.operation,
            "resource": context.resource,
            "environment": context.environment,
            "execution_boundary": context.execution_boundary,
        }
        if any(binding.get(name) != value for name, value in expected.items()):
            raise SideEffectExecutionError(ExecutionReasonCode.BINDING_MISMATCH)
        policy = binding.get("policy")
        if type(policy) is not dict or policy != context.policy_ref.to_dict():
            raise SideEffectExecutionError(ExecutionReasonCode.BINDING_MISMATCH)
        if (
            principal.tenant_id,
            principal.actor_id,
            principal.role,
            principal.authority,
        ) != (
            context.tenant_id,
            context.actor_id,
            context.actor_role,
            context.authority,
        ):
            raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT)
        auth_context_hash = strict_json_hash(_plain_object(principal.authentication_context))
        context_auth_hash = strict_json_hash(_plain_object(context.authentication_context))
        if (
            auth_context_hash != context_auth_hash
            or binding.get("authentication_context_hash") != auth_context_hash
        ):
            raise SideEffectExecutionError(ExecutionReasonCode.BINDING_MISMATCH)
        try:
            observed = _parse_utc(trusted_now)
            if not (
                _parse_utc(principal.verified_at) <= observed < _parse_utc(principal.expires_at)
            ):
                raise ValueError("principal is not current")
            if observed < _parse_utc(cast(str, binding["authorized_at"])):
                raise ValueError("execution predates authorization")
            if observed >= _parse_utc(cast(str, binding["expires_at"])):
                raise SideEffectExecutionError(ExecutionReasonCode.EXPIRED)
        except SideEffectExecutionError:
            raise
        except (KeyError, TypeError, ValueError):
            raise SideEffectExecutionError(ExecutionReasonCode.INVALID_CONTEXT) from None

    def _validate_current_policy(
        self,
        resolved: ResolvedPolicy,
        binding: dict[str, Any],
        *,
        actor_id: str,
    ) -> None:
        try:
            _snapshot_evaluator(resolved)
        except Exception:
            raise SideEffectExecutionError(ExecutionReasonCode.BINDING_MISMATCH) from None
        if binding.get("policy") != resolved.ref.to_dict():
            raise SideEffectExecutionError(ExecutionReasonCode.BINDING_MISMATCH)
        if binding.get("policy_attestation") != resolved.attestation.to_dict():
            raise SideEffectExecutionError(ExecutionReasonCode.BINDING_MISMATCH)
        if binding.get("authority") != resolved.authority:
            raise SideEffectExecutionError(ExecutionReasonCode.BINDING_MISMATCH)
        if (
            binding.get("validator_id") != resolved.validator.validator_id
            or binding.get("validator_role") != resolved.validator.role
            or resolved.validator.role not in self._allowed_validator_roles
            or resolved.validator.validator_id == actor_id
        ):
            raise SideEffectExecutionError(ExecutionReasonCode.BINDING_MISMATCH)

    def _validate_secret_bindings(
        self,
        binding: dict[str, Any],
        *,
        tenant_id: str,
        nonce: str,
        idempotency_key: str,
    ) -> None:
        try:
            nonce_digest = nonce_binding_digest(
                nonce,
                tenant_id,
                binding_hmac_key=self._binding_hmac_key,
            )
            idempotency_digest = idempotency_binding_digest(
                idempotency_key,
                tenant_id,
                binding_hmac_key=self._binding_hmac_key,
            )
            bound_nonce = cast(str, binding["nonce_digest"])
            bound_idempotency = cast(str, binding["idempotency_digest"])
        except Exception:
            raise SideEffectExecutionError(ExecutionReasonCode.BINDING_MISMATCH) from None
        if not (
            hmac.compare_digest(nonce_digest, bound_nonce)
            and hmac.compare_digest(idempotency_digest, bound_idempotency)
        ):
            raise SideEffectExecutionError(ExecutionReasonCode.BINDING_MISMATCH)

    def _verify_receipt(
        self,
        receipt: DecisionReceipt,
        authorization: SideEffectAuthorization,
        context: SideEffectExecutionContext,
        binding: dict[str, Any],
        *,
        trusted_now: str,
    ) -> None:
        try:
            receipt.verify(
                expected_tenant_id=context.tenant_id,
                expected_execution_boundary=context.execution_boundary,
                expected_audit_hash=authorization.audit_event_hash,
                expected_args=_plain_object(authorization.approved_arguments),
                expected_action=context.operation,
                expected_policy_hash=context.policy_ref.digest,
                expected_policy_bundle_id=context.policy_ref.bundle_id,
                expected_policy_version=context.policy_ref.version,
                expected_validator_id=cast(str, binding["validator_id"]),
                expected_validator_role=cast(str, binding["validator_role"]),
                expected_authority=context.authority,
                expected_constraints=reserved_constraints(authorization.reserved_binding),
                expected_request_id=context.request_id,
                expected_actor=context.actor_id,
                verifier=self._verifier,
                require_signature=True,
                now_iso=trusted_now,
                tool_tier_registry=self._tool_tier_registry,
            )
        except Exception:
            raise SideEffectExecutionError(ExecutionReasonCode.RECEIPT_INVALID) from None

    def _verify_audit_event(
        self,
        authorization: SideEffectAuthorization,
        binding: dict[str, Any],
    ) -> AuditCommit:
        try:
            verification = self._audit.verify_checkpointed_chain()
            if not verification.get("valid") or not verification.get("strict"):
                raise ValueError("checkpointed audit chain is invalid")
            checkpoint = _checkpoint_from_binding(binding)
            checked = verification.get("checked")
            if type(checked) is not int or checkpoint.generation > checked:
                raise ValueError("authorization checkpoint is outside the trusted chain")
            events = self._audit.query(
                where=lambda event: event.get("event_id") == authorization.audit_event_id,
                limit=2,
            )
            if len(events) != 1:
                raise ValueError("audit event is missing or duplicated")
            event = events[0]
            receipt = authorization.receipt
            if receipt is None:
                raise ValueError("receipt is missing")
            policy = cast(dict[str, Any], binding["policy"])
            attestation = cast(dict[str, Any], binding["policy_attestation"])
            trusted_state = _policy_state(
                request_id=cast(str, binding["request_id"]),
                tenant_id=cast(str, binding["tenant_id"]),
                actor_role=cast(str, binding["actor_role"]),
                authority=cast(str, binding["authority"]),
                server_id=cast(str, binding["server_id"]),
                tool=cast(str, binding["tool"]),
                operation=cast(str, binding["operation"]),
                resource=cast(str, binding["resource"]),
                environment=cast(str, binding["environment"]),
                execution_boundary=cast(str, binding["execution_boundary"]),
                side_effect_class=cast(str, binding["side_effect_class"]),
                policy_bundle_id=cast(str, policy["bundle_id"]),
                policy_version=cast(str, policy["version"]),
                policy_digest=cast(str, policy["digest"]),
                policy_attestation_tenant_id=cast(str, attestation["tenant_id"]),
                policy_attestation_artifact_id=cast(str, attestation["artifact_id"]),
                policy_attestation_version=cast(str, attestation["policy_version"]),
                policy_attestation_digest=cast(str, attestation["digest"]),
                policy_attestation_resolver_id=cast(str, attestation["resolver_id"]),
                evidence_digest=cast(str, binding["evidence_digest"]),
                authentication_context_hash=cast(str, binding["authentication_context_hash"]),
            )
            state_hash = strict_json_hash(trusted_state)
            expected_request_hash = sha256_json(
                {
                    "actor": binding["actor_id"],
                    "path": [],
                    "goal": f"sha256:{binding['goal_hash']}",
                    "tool": binding["operation"],
                    "argument_hash": binding["original_arguments_hash"],
                    "state_hash": state_hash,
                }
            )
            expected = {
                "event_id": authorization.audit_event_id,
                "event_hash": authorization.audit_event_hash,
                "previous_hash": authorization.previous_audit_hash,
                "decision": authorization.decision.value,
                "tool": binding["operation"],
                "argument_hash": authorization.original_arguments_hash,
                "policy_version": policy["version"],
                "actor": binding["actor_id"],
                "goal": f"sha256:{binding['goal_hash']}",
                "path": [],
                "state_hash": state_hash,
                "decision_request_hash": expected_request_hash,
                "timestamp_iso": binding["authorized_at"],
                "matched_rules": receipt.matched_rules,
            }
            if any(event.get(name) != value for name, value in expected.items()):
                raise ValueError("audit event does not match authorization")
            if checkpoint.head_hash != authorization.audit_event_hash:
                raise ValueError("checkpoint does not bind the authorization event")
            event_tier = ActionTier.coerce(event.get("action_tier")).value
            if event_tier != receipt.action_tier:
                raise ValueError("audit action tier does not match receipt")
            if authorization.decision is Decision.TRANSFORM:
                if event.get("transformed_args") != _plain_object(authorization.approved_arguments):
                    raise ValueError("audit transform does not match authorization")
            elif event.get("transformed_args") is not None:
                raise ValueError("non-transform audit event has transformed arguments")
            return AuditCommit(
                event_id=authorization.audit_event_id,
                event_hash=authorization.audit_event_hash,
                event=dict(event),
                checkpoint=checkpoint,
            )
        except SideEffectExecutionError:
            raise
        except Exception:
            raise SideEffectExecutionError(ExecutionReasonCode.AUDIT_HASH_MISMATCH) from None
