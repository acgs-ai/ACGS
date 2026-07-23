"""Governed executor and receipt-gate runner.

Guarantees that high-risk tool execution fail-closes before any side effects
can be run.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import secrets
import types
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from threading import RLock
from types import MappingProxyType
from typing import Any, cast

from gove_zone.audit import AuditCommit, ChainHashAuditStore
from gove_zone.consumption import (
    ConsumptionState,
    ConsumptionStoreError,
    ConsumptionTransitionError,
    ReceiptConsumptionError,
    ReceiptConsumptionStore,
    ReceiptReplayError,
    ReceiptRevokedError,
)
from gove_zone.decision import Decision, DecisionRecord, RecordKind, canonical_json, sha256_json
from gove_zone.errors import (
    PRODUCTION_NO_VERIFIER_MSG,
    DeniedError,
    GoveZoneError,
    ProductionProfileError,
    ReceiptValidationError,
)
from gove_zone.receipt import DecisionReceipt
from gove_zone.sandbox import _code_identity_bytes
from gove_zone.signing import ReceiptSigner
from gove_zone.tier import ToolTierRegistry

_EXECUTION_AUDIT_VERSION = "standalone-receipt-execution/v1"
_BINDING_DOMAIN = "gove-zone:standalone-receipt-binding:v1"
_IDEMPOTENCY_DOMAIN = "gove-zone:standalone-request-idempotency:v1"
_REASON_AUDIT_REQUIRED = "receipt.execution.audit_required"
_REASON_AUDIT_FAILED = "receipt.execution.audit_failed"
_REASON_STORE_REQUIRED = "receipt.execution.consumption_store_required"
_REASON_STORE_FAILED = "receipt.execution.consumption_store_failed"
_REASON_ACTOR_REQUIRED = "receipt.execution.actor_required"
_REASON_VERIFIER_REQUIRED = "receipt.execution.verifier_required"
_REASON_RECEIPT_REQUIRED = "receipt.execution.receipt_required"
_REASON_RECEIPT_INVALID = "receipt.execution.receipt_invalid"
_REASON_REPLAY = "receipt.execution.replay"
_REASON_REVOKED = "receipt.execution.revoked"
_REASON_RESERVED = "receipt.execution.reserved"
_REASON_SUCCEEDED = "receipt.execution.succeeded"
_REASON_OUTCOME_UNKNOWN = "receipt.execution.outcome_unknown"
_REASON_ARGUMENT_SNAPSHOT_INVALID = "receipt.execution.argument_snapshot_invalid"
_REASON_ADAPTER_ARTIFACT_REQUIRED = "receipt.execution.adapter_artifact_required"
_REASON_ADAPTER_ARTIFACT_MISMATCH = "receipt.execution.adapter_artifact_mismatch"
_EVIDENCE_DOMAIN = "gove-zone:standalone-execution-evidence:v1"


def _argument_hash(args: dict[str, Any]) -> str:
    try:
        return sha256_json(args)
    except Exception:
        return ""


def _canonical_object_snapshot(value: object, field_name: str) -> tuple[str, dict[str, Any]]:
    """Return an independent canonical-JSON object snapshot or fail closed."""

    try:
        serialized = canonical_json(value)
        snapshot = json.loads(serialized)
    except Exception:
        raise ReceiptValidationError(
            f"{_REASON_ARGUMENT_SNAPSHOT_INVALID}: {field_name} is not canonical JSON"
        ) from None
    if type(snapshot) is not dict or canonical_json(snapshot) != serialized:
        raise ReceiptValidationError(
            f"{_REASON_ARGUMENT_SNAPSHOT_INVALID}: {field_name} must be a JSON object"
        )
    return serialized, snapshot


def _validated_sha256(value: str, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field_name} must be 64 lowercase SHA-256 hex characters")
    return value


def _callable_code_digest(adapter: Callable[..., Any]) -> str:
    kind: str
    function: types.FunctionType
    if type(adapter) is types.FunctionType:
        kind = "function"
        function = adapter
    elif type(adapter) is types.MethodType:
        kind = "bound_method"
        function = cast(types.FunctionType, adapter.__func__)
    else:
        raise TypeError("unsupported callable identity; register an exact function or method")
    code = getattr(function, "__code__", None)
    if type(code) is not types.CodeType:
        raise TypeError("callable has no deterministic Python code identity")
    code_digest = hashlib.sha256(_code_identity_bytes(code)).hexdigest()
    return sha256_json(
        {
            "domain": "gove-zone:adapter-callable:v1",
            "kind": kind,
            "code_digest": code_digest,
        }
    )


def _adapter_artifact_identity(
    adapter: Callable[..., Any],
    declared_artifact_digest: str | None,
) -> tuple[str, str]:
    if type(adapter) is partial:
        base_digest = _callable_code_digest(adapter.func)
        keyword_names = sorted((adapter.keywords or {}).keys())
        callable_digest = sha256_json(
            {
                "domain": "gove-zone:adapter-callable:v1",
                "kind": "partial",
                "base_callable_digest": base_digest,
                "positional_binding_count": len(adapter.args),
                "keyword_binding_names": keyword_names,
            }
        )
        if (adapter.args or adapter.keywords) and declared_artifact_digest is None:
            raise ValueError("partial adapters with bound values require adapter_artifact_digest")
        artifact_digest = declared_artifact_digest or callable_digest
    else:
        callable_digest = _callable_code_digest(adapter)
        artifact_digest = declared_artifact_digest or callable_digest
    return (
        _validated_sha256(artifact_digest, "adapter_artifact_digest"),
        callable_digest,
    )


def adapter_artifact_digest(adapter: Callable[..., Any]) -> str:
    """Return the deterministic code identity required at a direct adapter gate."""

    artifact_digest, callable_digest = _adapter_artifact_identity(adapter, None)
    if not hmac.compare_digest(artifact_digest, callable_digest):
        raise ValueError("adapter artifact digest must match callable code identity")
    return callable_digest


def _require_audit_ready(audit: ChainHashAuditStore) -> None:
    try:
        if not audit.strict_integrity_ready:
            raise ValueError("strict integrity is unavailable")
        verification = audit.verify_checkpointed_chain()
    except Exception:
        raise ReceiptValidationError(f"{_REASON_AUDIT_FAILED}: audit is unavailable") from None
    if verification.get("valid") is not True or verification.get("strict") is not True:
        raise ReceiptValidationError(f"{_REASON_AUDIT_FAILED}: strict audit chain is invalid")


def _require_consumption_ready(store: ReceiptConsumptionStore) -> None:
    try:
        if not store.strict_integrity_ready:
            raise ValueError("strict integrity is unavailable")
    except Exception:
        raise ReceiptValidationError(
            f"{_REASON_STORE_FAILED}: consumption state is unavailable"
        ) from None


def _evidence_digest(label: str, value: str) -> str:
    return sha256_json({"domain": _EVIDENCE_DOMAIN, "field": label, "value": value})


def _execution_evidence(
    *,
    tenant_id: str,
    execution_boundary: str,
    adapter_id: str,
    receipt: DecisionReceipt,
    authorization_audit_hash: str,
    nonce_material: str,
    idempotency_digest: str,
    attempt_id: str,
    binding_hash: str,
    argument_hash: str,
    phase: str,
    reason_code: str,
    state: ConsumptionState,
    adapter_artifact_digest: str | None = None,
) -> dict[str, str]:
    return {
        "tenant_digest": _evidence_digest("tenant", tenant_id),
        "execution_boundary_digest": _evidence_digest("execution_boundary", execution_boundary),
        "adapter_id_digest": _evidence_digest("adapter_id", adapter_id),
        "adapter_artifact_digest": adapter_artifact_digest
        or _evidence_digest("adapter_artifact", adapter_id),
        "receipt_id_digest": _evidence_digest("receipt_id", receipt.receipt_id),
        "receipt_hash": receipt.receipt_hash,
        "request_id_digest": _evidence_digest("request_id", receipt.request_id),
        "authorization_audit_digest": _evidence_digest(
            "authorization_audit", authorization_audit_hash
        ),
        "nonce_digest": _evidence_digest("nonce", nonce_material),
        "idempotency_digest": idempotency_digest,
        "attempt_id_digest": _evidence_digest("attempt_id", attempt_id),
        "binding_hash": binding_hash,
        "argument_hash": argument_hash,
        "phase": phase,
        "reason_code": reason_code,
        "consumption_state": state.value,
    }


def _dependency_failure_evidence(
    *,
    tenant_id: str,
    execution_boundary: str,
    adapter_id: str,
    argument_hash: str,
    reason_code: str,
) -> dict[str, str]:
    return {
        "tenant_digest": _evidence_digest("tenant", tenant_id),
        "execution_boundary_digest": _evidence_digest("execution_boundary", execution_boundary),
        "adapter_id_digest": _evidence_digest("adapter_id", adapter_id),
        "argument_hash": argument_hash,
        "phase": "dependency_validation",
        "reason_code": reason_code,
        "consumption_state": "UNAVAILABLE",
    }


def _append_execution_audit(
    audit: ChainHashAuditStore,
    *,
    decision: Decision,
    reason_code: str,
    action: str,
    actor: str,
    argument_hash: str,
    policy_version: str,
    execution_evidence: dict[str, str] | None = None,
    record_kind: RecordKind = RecordKind.POLICY_DECISION,
    lifecycle_signer: ReceiptSigner | None = None,
    lifecycle_authority_id: str = "lifecycle-validator",
) -> AuditCommit:
    _require_audit_ready(audit)
    common: dict[str, Any] = {
        "decision": decision,
        "tool": action,
        "argument_hash": argument_hash,
        "policy_version": policy_version or _EXECUTION_AUDIT_VERSION,
        "event_id": f"ev_{secrets.token_hex(16)}",
        "matched_rules": (reason_code,),
        "reason": reason_code,
        "actor": actor,
        "timestamp_iso": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    if record_kind is RecordKind.EXECUTION_LIFECYCLE:
        if lifecycle_signer is None or execution_evidence is None:
            raise ReceiptValidationError(
                f"{_REASON_AUDIT_FAILED}: lifecycle signing authority is unavailable"
            )
        checkpoint = audit.verify_checkpointed_chain().get("checkpoint")
        if type(checkpoint) is not dict:
            raise ReceiptValidationError(f"{_REASON_AUDIT_FAILED}: checkpoint unavailable")
        checkpoint_namespace = checkpoint.get("namespace")
        if lifecycle_signer.key_id == checkpoint.get("key_id") or lifecycle_authority_id in {
            "audit-checkpoint",
            f"audit-checkpoint:{checkpoint_namespace}",
        }:
            raise ReceiptValidationError(
                f"{_REASON_AUDIT_FAILED}: lifecycle authority is not code-separated"
            )
        record = DecisionRecord.lifecycle(
            **common,
            execution_evidence=execution_evidence,
            signer=lifecycle_signer,
            authority_id=lifecycle_authority_id,
        )
    else:
        record = DecisionRecord(**common)
    try:
        return audit.append_committed(record)
    except Exception:
        raise ReceiptValidationError(f"{_REASON_AUDIT_FAILED}: audit append failed") from None


def _verified_consumption_bindings(
    receipt: DecisionReceipt,
    *,
    expected_tenant_id: str,
    expected_execution_boundary: str,
    expected_action: str,
    expected_actor: str,
    actual_argument_hash: str,
    adapter_id: str,
    adapter_artifact_digest: str,
) -> tuple[str, str, str]:
    common = {
        "tenant_id": expected_tenant_id,
        "execution_boundary": expected_execution_boundary,
        "action": expected_action,
        "actor": expected_actor,
        "argument_hash": actual_argument_hash,
        "adapter_id": adapter_id,
    }
    binding_hash = sha256_json(
        {
            "domain": _BINDING_DOMAIN,
            "receipt_id": receipt.receipt_id,
            "receipt_hash": receipt.receipt_hash,
            "request_id": receipt.request_id,
            "adapter_artifact_digest": adapter_artifact_digest,
            **common,
        }
    )
    idempotency_digest = sha256_json(
        {
            "domain": _IDEMPOTENCY_DOMAIN,
            "request_id": receipt.request_id,
            **common,
        }
    )
    reserved = receipt.constraints.get("_acgs_side_effect_v2")
    nonce_material = reserved.get("nonce_digest") if type(reserved) is dict else None
    if type(nonce_material) is not str or not nonce_material:
        nonce_material = f"request-id:{receipt.request_id}"
    return binding_hash, idempotency_digest, nonce_material


def execute_with_receipt(
    tool_fn: Callable[..., Any],
    args: dict[str, Any],
    receipt: DecisionReceipt | None,
    *,
    expected_tenant_id: str,
    expected_execution_boundary: str,
    expected_action: str,
    expected_actor: str,
    expected_audit_hash: str | None = None,
    expected_policy_hash: str | None = None,
    expected_policy_bundle_id: str | None = None,
    expected_policy_version: str | None = None,
    expected_validator_id: str | None = None,
    expected_validator_role: str | None = None,
    expected_authority: str | None = None,
    expected_constraints: Mapping[str, Any] | None = None,
    expected_request_id: str | None = None,
    verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
    require_signature: bool = True,
    now_iso: str | None = None,
    tool_tier_registry: ToolTierRegistry | None = None,
    expected_adapter_artifact_digest: str | None = None,
    consumption_store: ReceiptConsumptionStore | None = None,
    rejection_audit: ChainHashAuditStore | None = None,
    lifecycle_signer: ReceiptSigner | None = None,
    lifecycle_authority_id: str = "lifecycle-validator",
) -> Any:
    """Execute *tool_fn* with *args* iff *receipt* is valid and matches constraints.

    Refuses execution with ReceiptValidationError if:
    - No receipt is provided
    - Receipt verification fails (altered, tampered, invalid hashes, wrong tenant/boundary)
    - Receipt is denied or escalated
    - Transformations in a TRANSFORM receipt do not match execution arguments

    ``expected_actor`` (the invoking principal's identity, from the caller's
    runtime context — NOT read from the receipt) is **required**. It anchors the
    MACI self-validation/proposer-binding check against an identity the receipt
    author cannot forge by editing receipt fields, so the strong check is the
    default at the gate rather than an opt-in. Omitting it is a ``TypeError``
    (it has no default); passing an empty string fails closed with
    ``ReceiptValidationError``. The relocated trust lives with the integrator:
    this does not manufacture an authenticated identity the architecture lacks —
    signed issuance (``require_signature=True`` + a trusted verifier) is the
    cryptographic closure.
    """
    try:
        arguments_json, verification_args = _canonical_object_snapshot(args, "args")
        if expected_constraints is None:
            verification_constraints = None
        else:
            _, verification_constraints = _canonical_object_snapshot(
                dict(expected_constraints),
                "expected_constraints",
            )
    except ReceiptValidationError:
        if isinstance(rejection_audit, ChainHashAuditStore):
            try:
                _require_audit_ready(rejection_audit)
                _append_execution_audit(
                    rejection_audit,
                    decision=Decision.DENY,
                    reason_code=_REASON_ARGUMENT_SNAPSHOT_INVALID,
                    action=expected_action,
                    actor=expected_actor or "<missing-actor>",
                    argument_hash="",
                    policy_version=_EXECUTION_AUDIT_VERSION,
                )
            except Exception:
                pass
        raise
    argument_hash = _argument_hash(verification_args)
    if rejection_audit is None:
        raise ReceiptValidationError(f"{_REASON_AUDIT_REQUIRED}: rejection audit is required")
    if not isinstance(rejection_audit, ChainHashAuditStore):
        raise ReceiptValidationError(f"{_REASON_AUDIT_FAILED}: invalid rejection audit")
    _require_audit_ready(rejection_audit)
    if consumption_store is None:
        _append_execution_audit(
            rejection_audit,
            decision=Decision.DENY,
            reason_code=_REASON_STORE_REQUIRED,
            action=expected_action,
            actor=expected_actor,
            argument_hash=argument_hash,
            policy_version=_EXECUTION_AUDIT_VERSION,
        )
        raise ReceiptValidationError(
            f"{_REASON_STORE_REQUIRED}: receipt consumption store is required"
        )
    if not isinstance(consumption_store, ReceiptConsumptionStore):
        _append_execution_audit(
            rejection_audit,
            decision=Decision.DENY,
            reason_code=_REASON_STORE_FAILED,
            action=expected_action,
            actor=expected_actor,
            argument_hash=argument_hash,
            policy_version=_EXECUTION_AUDIT_VERSION,
        )
        raise ReceiptValidationError(f"{_REASON_STORE_FAILED}: invalid consumption store")
    try:
        _require_consumption_ready(consumption_store)
    except ReceiptValidationError:
        _append_execution_audit(
            rejection_audit,
            decision=Decision.DENY,
            reason_code=_REASON_STORE_FAILED,
            action=expected_action,
            actor=expected_actor or "<missing-actor>",
            argument_hash=argument_hash,
            policy_version=_EXECUTION_AUDIT_VERSION,
            execution_evidence=_dependency_failure_evidence(
                tenant_id=expected_tenant_id,
                execution_boundary=expected_execution_boundary,
                adapter_id=f"{expected_execution_boundary}:{expected_action}",
                argument_hash=argument_hash,
                reason_code=_REASON_STORE_FAILED,
            ),
            record_kind=RecordKind.EXECUTION_LIFECYCLE,
            lifecycle_signer=lifecycle_signer,
            lifecycle_authority_id=lifecycle_authority_id,
        )
        raise
    if not expected_actor or not expected_actor.strip():
        _append_execution_audit(
            rejection_audit,
            decision=Decision.DENY,
            reason_code=_REASON_ACTOR_REQUIRED,
            action=expected_action,
            actor="<missing-actor>",
            argument_hash=argument_hash,
            policy_version=_EXECUTION_AUDIT_VERSION,
        )
        raise ReceiptValidationError(
            f"{_REASON_ACTOR_REQUIRED}: expected_actor is required for governed execution"
        )
    if require_signature is not True:
        _append_execution_audit(
            rejection_audit,
            decision=Decision.DENY,
            reason_code=_REASON_VERIFIER_REQUIRED,
            action=expected_action,
            actor=expected_actor,
            argument_hash=argument_hash,
            policy_version=_EXECUTION_AUDIT_VERSION,
        )
        raise ProductionProfileError(
            f"{_REASON_VERIFIER_REQUIRED}: standalone execution requires signatures"
        )
    if verifier is None:
        _append_execution_audit(
            rejection_audit,
            decision=Decision.DENY,
            reason_code=_REASON_VERIFIER_REQUIRED,
            action=expected_action,
            actor=expected_actor,
            argument_hash=argument_hash,
            policy_version=_EXECUTION_AUDIT_VERSION,
        )
        raise ProductionProfileError(f"{_REASON_VERIFIER_REQUIRED}: {PRODUCTION_NO_VERIFIER_MSG}")
    if receipt is None:
        _append_execution_audit(
            rejection_audit,
            decision=Decision.DENY,
            reason_code=_REASON_RECEIPT_REQUIRED,
            action=expected_action,
            actor=expected_actor,
            argument_hash=argument_hash,
            policy_version=_EXECUTION_AUDIT_VERSION,
        )
        raise ReceiptValidationError(
            f"{_REASON_RECEIPT_REQUIRED}: No receipt provided for governed execution"
        )

    # verify will check missing fields, signature, hashes, decision type,
    # tenant, boundary, action, audit hash, transform mismatches, and — when
    # expected_actor is supplied — that the receipt was issued for this caller
    # and that the caller is not also the validator.
    try:
        receipt.verify(
            expected_tenant_id=expected_tenant_id,
            expected_execution_boundary=expected_execution_boundary,
            expected_audit_hash=expected_audit_hash,
            expected_args=verification_args,
            expected_action=expected_action,
            expected_policy_hash=expected_policy_hash,
            expected_policy_bundle_id=expected_policy_bundle_id,
            expected_policy_version=expected_policy_version,
            expected_validator_id=expected_validator_id,
            expected_validator_role=expected_validator_role,
            expected_authority=expected_authority,
            expected_constraints=verification_constraints,
            expected_request_id=expected_request_id,
            expected_actor=expected_actor,
            verifier=verifier,
            require_signature=require_signature,
            now_iso=now_iso,
            tool_tier_registry=tool_tier_registry,
        )
    except Exception:
        _append_execution_audit(
            rejection_audit,
            decision=Decision.DENY,
            reason_code=_REASON_RECEIPT_INVALID,
            action=expected_action,
            actor=expected_actor,
            argument_hash=argument_hash,
            policy_version=receipt.policy_version,
        )
        raise

    adapter_id = f"{expected_execution_boundary}:{expected_action}"
    try:
        if expected_adapter_artifact_digest is None:
            raise ValueError("expected_adapter_artifact_digest is required")
        expected_artifact_digest = _validated_sha256(
            expected_adapter_artifact_digest,
            "expected_adapter_artifact_digest",
        )
        actual_artifact_digest = adapter_artifact_digest(tool_fn)
    except Exception:
        _append_execution_audit(
            rejection_audit,
            decision=Decision.DENY,
            reason_code=_REASON_ADAPTER_ARTIFACT_REQUIRED,
            action=expected_action,
            actor=expected_actor,
            argument_hash=argument_hash,
            policy_version=receipt.policy_version,
        )
        raise ReceiptValidationError(
            f"{_REASON_ADAPTER_ARTIFACT_REQUIRED}: deterministic adapter identity is required"
        ) from None
    if not hmac.compare_digest(expected_artifact_digest, actual_artifact_digest):
        _append_execution_audit(
            rejection_audit,
            decision=Decision.DENY,
            reason_code=_REASON_ADAPTER_ARTIFACT_MISMATCH,
            action=expected_action,
            actor=expected_actor,
            argument_hash=argument_hash,
            policy_version=receipt.policy_version,
        )
        raise ReceiptValidationError(
            f"{_REASON_ADAPTER_ARTIFACT_MISMATCH}: registered adapter changed"
        )
    pinned_adapter_artifact_digest = actual_artifact_digest
    binding_hash, idempotency_digest, nonce_material = _verified_consumption_bindings(
        receipt,
        expected_tenant_id=expected_tenant_id,
        expected_execution_boundary=expected_execution_boundary,
        expected_action=expected_action,
        expected_actor=expected_actor,
        actual_argument_hash=argument_hash,
        adapter_id=adapter_id,
        adapter_artifact_digest=pinned_adapter_artifact_digest,
    )
    attempt_id = f"attempt_{secrets.token_hex(16)}"
    try:
        consumption_store.reserve(
            expected_tenant_id,
            receipt.receipt_id,
            nonce_material,
            receipt.receipt_hash,
            binding_hash,
            attempt_id,
            idempotency_digest=idempotency_digest,
        )
    except ReceiptReplayError:
        reason = _REASON_REPLAY
    except ReceiptRevokedError:
        reason = _REASON_REVOKED
    except (ConsumptionStoreError, ConsumptionTransitionError, ReceiptConsumptionError):
        reason = _REASON_STORE_FAILED
    else:
        reason = ""
    if reason:
        _append_execution_audit(
            rejection_audit,
            decision=Decision.DENY,
            reason_code=reason,
            action=expected_action,
            actor=expected_actor,
            argument_hash=argument_hash,
            policy_version=receipt.policy_version,
        )
        raise ReceiptValidationError(f"{reason}: receipt execution refused")

    claim_evidence = _execution_evidence(
        tenant_id=expected_tenant_id,
        execution_boundary=expected_execution_boundary,
        adapter_id=adapter_id,
        receipt=receipt,
        authorization_audit_hash=expected_audit_hash or receipt.audit_event_hash,
        nonce_material=nonce_material,
        idempotency_digest=idempotency_digest,
        attempt_id=attempt_id,
        binding_hash=binding_hash,
        argument_hash=argument_hash,
        phase="claim_committed",
        reason_code=_REASON_RESERVED,
        state=ConsumptionState.RESERVED,
        adapter_artifact_digest=pinned_adapter_artifact_digest,
    )
    try:
        claim_commit = _append_execution_audit(
            rejection_audit,
            decision=Decision.ALLOW,
            reason_code=_REASON_RESERVED,
            action=expected_action,
            actor=expected_actor,
            argument_hash=argument_hash,
            policy_version=receipt.policy_version,
            execution_evidence=claim_evidence,
            record_kind=RecordKind.EXECUTION_LIFECYCLE,
            lifecycle_signer=lifecycle_signer,
            lifecycle_authority_id=lifecycle_authority_id,
        )
    except Exception:
        try:
            current = consumption_store.status(expected_tenant_id, receipt.receipt_id)
            if current is not None and current.state is ConsumptionState.RESERVED:
                consumption_store.mark_unknown(expected_tenant_id, receipt.receipt_id, attempt_id)
        except ReceiptConsumptionError:
            pass
        raise

    def committed_adapter_call() -> Any:
        _require_consumption_ready(consumption_store)
        current = consumption_store.status(expected_tenant_id, receipt.receipt_id)
        if (
            current is None
            or current.state is not ConsumptionState.RESERVED
            or current.attempt_id != attempt_id
            or current.binding_hash != binding_hash
            or current.idempotency_digest != idempotency_digest
        ):
            raise ReceiptValidationError(f"{_REASON_STORE_FAILED}: reservation changed")
        if consumption_store.is_revoked(expected_tenant_id, receipt.receipt_id):
            raise ReceiptValidationError(f"{_REASON_REVOKED}: receipt is revoked")
        receipt.verify(
            expected_tenant_id=expected_tenant_id,
            expected_execution_boundary=expected_execution_boundary,
            expected_audit_hash=expected_audit_hash,
            expected_args=json.loads(arguments_json),
            expected_action=expected_action,
            expected_policy_hash=expected_policy_hash,
            expected_policy_bundle_id=expected_policy_bundle_id,
            expected_policy_version=expected_policy_version,
            expected_validator_id=expected_validator_id,
            expected_validator_role=expected_validator_role,
            expected_authority=expected_authority,
            expected_constraints=verification_constraints,
            expected_request_id=expected_request_id,
            expected_actor=expected_actor,
            verifier=verifier,
            require_signature=True,
            now_iso=now_iso,
            tool_tier_registry=tool_tier_registry,
        )
        return tool_fn(**json.loads(arguments_json))

    def record_outcome(reason_code: str, state: ConsumptionState) -> None:
        evidence = _execution_evidence(
            tenant_id=expected_tenant_id,
            execution_boundary=expected_execution_boundary,
            adapter_id=adapter_id,
            receipt=receipt,
            authorization_audit_hash=expected_audit_hash or receipt.audit_event_hash,
            nonce_material=nonce_material,
            idempotency_digest=idempotency_digest,
            attempt_id=attempt_id,
            binding_hash=binding_hash,
            argument_hash=argument_hash,
            phase="terminal",
            reason_code=reason_code,
            state=state,
            adapter_artifact_digest=pinned_adapter_artifact_digest,
        )
        _append_execution_audit(
            rejection_audit,
            decision=Decision.ALLOW if state is ConsumptionState.SUCCEEDED else Decision.DENY,
            reason_code=reason_code,
            action=expected_action,
            actor=expected_actor,
            argument_hash=argument_hash,
            policy_version=receipt.policy_version,
            execution_evidence=evidence,
            record_kind=RecordKind.EXECUTION_LIFECYCLE,
            lifecycle_signer=lifecycle_signer,
            lifecycle_authority_id=lifecycle_authority_id,
        )

    def persist_unknown() -> None:
        try:
            current = consumption_store.status(expected_tenant_id, receipt.receipt_id)
            if current is not None and current.state is ConsumptionState.RESERVED:
                consumption_store.mark_unknown(expected_tenant_id, receipt.receipt_id, attempt_id)
            confirmed = consumption_store.status(expected_tenant_id, receipt.receipt_id)
        except ReceiptConsumptionError:
            raise ReceiptValidationError(
                f"{_REASON_OUTCOME_UNKNOWN}: consumption state is fail-stopped"
            ) from None
        if confirmed is None or confirmed.state is not ConsumptionState.UNKNOWN:
            raise ReceiptValidationError(
                f"{_REASON_OUTCOME_UNKNOWN}: UNKNOWN state could not be confirmed"
            )
        record_outcome(_REASON_OUTCOME_UNKNOWN, ConsumptionState.UNKNOWN)

    try:
        result = rejection_audit.run_if_committed(claim_commit, committed_adapter_call)
    except Exception:
        persist_unknown()
        raise ReceiptValidationError(
            f"{_REASON_OUTCOME_UNKNOWN}: adapter completion is not confirmed"
        ) from None

    try:
        completed = consumption_store.mark_succeeded(
            expected_tenant_id,
            receipt.receipt_id,
            attempt_id,
        )
    except ReceiptConsumptionError:
        try:
            observed = consumption_store.status(expected_tenant_id, receipt.receipt_id)
        except ReceiptConsumptionError:
            raise ReceiptValidationError(
                f"{_REASON_OUTCOME_UNKNOWN}: terminal state is fail-stopped"
            ) from None
        if observed is not None and observed.state is ConsumptionState.SUCCEEDED:
            record_outcome(_REASON_SUCCEEDED, ConsumptionState.SUCCEEDED)
            return result
        if observed is not None and observed.state is ConsumptionState.RESERVED:
            persist_unknown()
        raise ReceiptValidationError(
            f"{_REASON_OUTCOME_UNKNOWN}: success could not be persisted"
        ) from None
    if completed.state is not ConsumptionState.SUCCEEDED:
        persist_unknown()
        raise ReceiptValidationError(f"{_REASON_OUTCOME_UNKNOWN}: invalid terminal state")
    record_outcome(_REASON_SUCCEEDED, ConsumptionState.SUCCEEDED)
    return result


@dataclass(frozen=True, slots=True)
class _FrozenAdapterBinding:
    action: str
    adapter_id: str
    adapter_artifact_digest: str
    callable_digest: str
    adapter: Callable[..., Any] = field(repr=False, compare=False)


class GovernedExecutor:
    """A wrapper for a tool registry that enforces receipt-gated execution.

    ``expected_actor`` (the proposing principal's identity) is supplied at
    construction time as the immutable contract for all calls made through this
    executor. Per-call values may only repeat that pinned identity. It is **required**:
    construction with no ``expected_actor`` is a ``TypeError`` and an empty
    string fails closed with ``ReceiptValidationError``. Supplying it activates
    the strong caller-anchored proposer-binding check in
    :meth:`DecisionReceipt.verify` (check 2b) by default, anchoring the MACI
    self-validation guard against an identity the receipt author cannot forge by
    editing receipt fields. There is no silent downgrade to the weak
    ``validator_id == actor`` heuristic (check 2c) through this gate; 2c remains
    only as residual defense for direct :meth:`DecisionReceipt.verify` calls.
    """

    __slots__ = (
        "_tenant_id",
        "_execution_boundary",
        "_expected_actor",
        "_consumption_store",
        "_rejection_audit",
        "_verifier",
        "_lifecycle_signer",
        "_lifecycle_authority_id",
        "_tool_tier_registry",
        "_expected_policy_version",
        "_expected_validator_id",
        "_expected_validator_role",
        "_expected_authority",
        "_expected_constraints_json",
        "__registry",
        "__registry_lock",
        "__registry_frozen",
        "_sealed",
    )

    _tenant_id: str
    _execution_boundary: str
    _expected_actor: str
    _consumption_store: ReceiptConsumptionStore
    _rejection_audit: ChainHashAuditStore
    _verifier: ReceiptSigner | Mapping[str, ReceiptSigner]
    _lifecycle_signer: ReceiptSigner | None
    _lifecycle_authority_id: str
    _tool_tier_registry: ToolTierRegistry | None
    _expected_policy_version: str | None
    _expected_validator_id: str | None
    _expected_validator_role: str | None
    _expected_authority: str | None
    _expected_constraints_json: str | None
    __registry: Mapping[str, _FrozenAdapterBinding]
    __registry_lock: RLock
    __registry_frozen: bool
    _sealed: bool

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f"{name} is immutable on a sealed GovernedExecutor")

    def __init__(
        self,
        *,
        tenant_id: str,
        execution_boundary: str,
        expected_actor: str,
        consumption_store: ReceiptConsumptionStore,
        rejection_audit: ChainHashAuditStore,
        verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
        lifecycle_signer: ReceiptSigner | None = None,
        lifecycle_authority_id: str = "lifecycle-validator",
        require_signature: bool = True,
        tool_tier_registry: ToolTierRegistry | None = None,
        expected_policy_version: str | None = None,
        expected_validator_id: str | None = None,
        expected_validator_role: str | None = None,
        expected_authority: str | None = None,
        expected_constraints: Mapping[str, Any] | None = None,
    ) -> None:
        if not expected_actor or not expected_actor.strip():
            raise ReceiptValidationError(
                "expected_actor is required for GovernedExecutor (fail-closed)"
            )
        if require_signature is not True:
            raise ValueError("GovernedExecutor requires signed receipts")
        if not isinstance(consumption_store, ReceiptConsumptionStore):
            raise TypeError("consumption_store must be a ReceiptConsumptionStore")
        if not isinstance(rejection_audit, ChainHashAuditStore):
            raise TypeError("rejection_audit must be a ChainHashAuditStore")
        _require_consumption_ready(consumption_store)
        _require_audit_ready(rejection_audit)
        if verifier is None:
            raise ValueError("GovernedExecutor requires a trusted verifier")
        object.__setattr__(self, "_sealed", False)
        object.__setattr__(self, "_tenant_id", tenant_id)
        object.__setattr__(self, "_execution_boundary", execution_boundary)
        object.__setattr__(self, "_expected_actor", expected_actor)
        object.__setattr__(self, "_consumption_store", consumption_store)
        object.__setattr__(self, "_rejection_audit", rejection_audit)
        object.__setattr__(
            self,
            "_verifier",
            MappingProxyType(dict(verifier)) if isinstance(verifier, Mapping) else verifier,
        )
        object.__setattr__(self, "_lifecycle_signer", lifecycle_signer)
        object.__setattr__(self, "_lifecycle_authority_id", lifecycle_authority_id)
        object.__setattr__(self, "_tool_tier_registry", tool_tier_registry)
        object.__setattr__(self, "_expected_policy_version", expected_policy_version)
        object.__setattr__(self, "_expected_validator_id", expected_validator_id)
        object.__setattr__(self, "_expected_validator_role", expected_validator_role)
        object.__setattr__(self, "_expected_authority", expected_authority)
        constraints_json = None
        if expected_constraints is not None:
            constraints_json, _ = _canonical_object_snapshot(
                dict(expected_constraints),
                "expected_constraints",
            )
        object.__setattr__(self, "_expected_constraints_json", constraints_json)
        object.__setattr__(self, "_GovernedExecutor__registry", MappingProxyType({}))
        object.__setattr__(self, "_GovernedExecutor__registry_lock", RLock())
        object.__setattr__(self, "_GovernedExecutor__registry_frozen", False)
        object.__setattr__(self, "_sealed", True)

    @property
    def expected_actor(self) -> str:
        """Return the immutable caller identity pinned at construction."""
        return self._expected_actor

    @property
    def tenant_id(self) -> str:
        """Return the immutable tenant identity pinned at construction."""
        return self._tenant_id

    @property
    def execution_boundary(self) -> str:
        """Return the immutable execution boundary pinned at construction."""
        return self._execution_boundary

    def register_tool(
        self,
        name: str,
        fn: Callable[..., Any],
        *,
        adapter_artifact_digest: str | None = None,
    ) -> None:
        if not name or not name.strip():
            raise ValueError("registered action must be non-empty")
        if not callable(fn):
            raise TypeError("registered adapter must be callable")
        artifact_digest, callable_digest = _adapter_artifact_identity(
            fn,
            adapter_artifact_digest,
        )
        if not hmac.compare_digest(artifact_digest, callable_digest):
            raise ValueError("adapter_artifact_digest must match the callable code identity")
        with self.__registry_lock:
            if self.__registry_frozen:
                raise RuntimeError("registry is frozen after first execution attempt")
            if name in self.__registry:
                raise ValueError(f"action is already registered: {name!r}")
            adapter_id = f"{self._execution_boundary}:{name}"
            snapshot = dict(self.__registry)
            snapshot[name] = _FrozenAdapterBinding(
                action=name,
                adapter_id=adapter_id,
                adapter_artifact_digest=artifact_digest,
                callable_digest=callable_digest,
                adapter=fn,
            )
            object.__setattr__(
                self,
                "_GovernedExecutor__registry",
                MappingProxyType(snapshot),
            )

    def register(self, name: str, fn: Callable[..., Any]) -> None:
        self.register_tool(name, fn)

    def execute(
        self,
        action: str,
        args: dict[str, Any],
        receipt: DecisionReceipt | None,
        *,
        expected_audit_hash: str | None = None,
        expected_policy_hash: str | None = None,
        expected_policy_bundle_id: str | None = None,
        expected_policy_version: str | None = None,
        expected_validator_id: str | None = None,
        expected_validator_role: str | None = None,
        expected_authority: str | None = None,
        expected_constraints: Mapping[str, Any] | None = None,
        expected_request_id: str | None = None,
        expected_actor: str | None = None,
        verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
        require_signature: bool | None = None,
        now_iso: str | None = None,
        tool_tier_registry: ToolTierRegistry | None = None,
    ) -> Any:
        with self.__registry_lock:
            object.__setattr__(self, "_GovernedExecutor__registry_frozen", True)
            registered = self.__registry.get(action)
        if registered is None:
            raise KeyError(f"Tool {action!r} not registered with executor")
        tool_fn = registered.adapter

        def require_pin(name: str, override: object, pinned: object) -> object:
            if override is not None and override != pinned:
                raise ReceiptValidationError(f"{name} cannot override constructor trust root")
            return pinned

        effective_actor = require_pin("expected_actor", expected_actor, self._expected_actor)
        effective_verifier = require_pin("verifier", verifier, self._verifier)
        require_pin("require_signature", require_signature, True)
        effective_tier_registry = require_pin(
            "tool_tier_registry", tool_tier_registry, self._tool_tier_registry
        )
        effective_policy_version = require_pin(
            "expected_policy_version", expected_policy_version, self._expected_policy_version
        )
        effective_validator_id = require_pin(
            "expected_validator_id", expected_validator_id, self._expected_validator_id
        )
        effective_validator_role = require_pin(
            "expected_validator_role", expected_validator_role, self._expected_validator_role
        )
        effective_authority = require_pin(
            "expected_authority", expected_authority, self._expected_authority
        )
        if expected_constraints is not None:
            override_constraints_json, _ = _canonical_object_snapshot(
                dict(expected_constraints),
                "expected_constraints",
            )
            if override_constraints_json != self._expected_constraints_json:
                raise ReceiptValidationError(
                    "expected_constraints cannot override constructor trust root"
                )
        effective_constraints = (
            None
            if self._expected_constraints_json is None
            else json.loads(self._expected_constraints_json)
        )
        return execute_with_receipt(
            tool_fn=tool_fn,
            args=args,
            receipt=receipt,
            expected_tenant_id=self._tenant_id,
            expected_execution_boundary=self._execution_boundary,
            expected_action=action,
            expected_audit_hash=expected_audit_hash,
            expected_policy_hash=expected_policy_hash,
            expected_policy_bundle_id=expected_policy_bundle_id,
            expected_policy_version=cast(str | None, effective_policy_version),
            expected_validator_id=cast(str | None, effective_validator_id),
            expected_validator_role=cast(str | None, effective_validator_role),
            expected_authority=cast(str | None, effective_authority),
            expected_constraints=cast(Mapping[str, Any] | None, effective_constraints),
            expected_request_id=expected_request_id,
            expected_actor=str(effective_actor),
            verifier=cast(ReceiptSigner | Mapping[str, ReceiptSigner], effective_verifier),
            require_signature=True,
            now_iso=now_iso,
            tool_tier_registry=cast(ToolTierRegistry | None, effective_tier_registry),
            expected_adapter_artifact_digest=registered.adapter_artifact_digest,
            consumption_store=self._consumption_store,
            rejection_audit=self._rejection_audit,
            lifecycle_signer=self._lifecycle_signer,
            lifecycle_authority_id=self._lifecycle_authority_id,
        )


class StateRollbackHandler:
    """Fail-safe context manager that tracks transaction state and rolls back on failure."""

    def __init__(self, rollback_fn: Callable[[], None] | None = None) -> None:
        self.rollback_fn = rollback_fn

    def __enter__(self) -> StateRollbackHandler:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        if exc_type is not None:
            if self.rollback_fn is not None:
                with contextlib.suppress(Exception):
                    self.rollback_fn()
            # Wrap standard/assertion errors into DeniedError standard security error format
            if not isinstance(exc_val, GoveZoneError):
                raise DeniedError(
                    DecisionRecord(
                        decision=Decision.DENY,
                        tool="unknown",
                        argument_hash="",
                        policy_version="rollback/v0",
                        event_id="ev_rollback",
                        reason=f"Execution aborted and rolled back due to: {exc_val}",
                    ),
                    audit_hash="",
                ) from exc_val
