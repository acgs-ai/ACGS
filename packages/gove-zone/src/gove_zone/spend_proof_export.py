"""Genuine local Spend Guard capture and sealed proof export."""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import os
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from gove_zone import proof_pack as sealed_pack
from gove_zone._spend_fixture_provider import LocalJournalFixtureProvider
from gove_zone.audit import AuditCheckpoint, AuditCheckpointAnchor, ChainHashAuditStore
from gove_zone.authorization import (
    ExecutionReasonCode,
    ExecutionRefusalEvidence,
    PolicyArtifactAttestation,
    ResolvedPolicy,
    ResolvedPolicyRef,
    SideEffectAuthorization,
    SideEffectExecutionContext,
    SideEffectExecutionError,
    SideEffectRequest,
    VerifiedPrincipal,
    deep_thaw_json,
    idempotency_binding_digest,
    strict_json_hash,
)
from gove_zone.consumption import (
    AnchoredConsumptionState,
    ConsumptionRecord,
    ConsumptionStateAnchor,
    ReceiptConsumptionStore,
)
from gove_zone.decision import Decision, RecordKind
from gove_zone.path_capability import AttestedDirectory, require_attested_directory
from gove_zone.proof_pack import DirectoryIdentity, OpenDirectory, SealedPackCodec, SealedPackSchema
from gove_zone.receipt import Validator
from gove_zone.replay import execution_refusal_error
from gove_zone.replay_store import ReplaySideStore
from gove_zone.side_effect_kernel import (
    ReceiptGatedSideEffectExecutor,
    SideEffectAuthorizationKernel,
)
from gove_zone.signing import Ed25519Signer
from gove_zone.spend_adapter import (
    SPEND_EXECUTION_BOUNDARY,
    SPEND_SERVER_ID,
    SPEND_SIDE_EFFECT_CLASS,
    SPEND_TOOL_ID,
    SpendGuardAdapter,
    SpendGuardError,
    SpendGuardResult,
    SpendKernelPolicy,
)
from gove_zone.spend_guard import SPEND_OPERATION, SpendPolicy, normalize_spend_arguments
from gove_zone.spend_proof import (
    SPEND_CHECKPOINT_SCHEMA,
    SPEND_CONSUMPTION_SUMMARY_SCHEMA,
    SPEND_LOOP_CHECKPOINT_SCHEMA,
    SPEND_LOOP_CONSUMPTION_SUMMARY_SCHEMA,
    SPEND_LOOP_POLICY_EVIDENCE_SCHEMA,
    SPEND_LOOP_RUNTIME_SCHEMA,
    SPEND_LOOP_SCENARIO_SCHEMA,
    SPEND_LOOP_STORE_SUMMARY_SCHEMA,
    SPEND_LOOP_TRUST_SCHEMA,
    SPEND_POLICY_EVIDENCE_SCHEMA,
    SPEND_PROOF_CODEC,
    SPEND_PROOF_LANES,
    SPEND_RUNTIME_SCHEMA,
    SPEND_SCENARIO_SCHEMA,
    SPEND_STORE_SUMMARY_SCHEMA,
    SPEND_TRUST_SCHEMA,
    SpendProofError,
    SpendProofPack,
    SpendProofPayloads,
    _verify_with_trust_bytes,
    signed_summary,
)
from gove_zone.spend_store import FileSpendStateAnchor, SpendBudgetRules, SQLiteSpendStore

SPEND_PROOF_ENVELOPE_SCHEMA = "gove-zone.spend-proof-envelope/v1"
SPEND_EXPECTED_DIGEST_SCHEMA = "gove-zone.spend-expected-pack-digest/v1"
_NOW = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)
_AUTH_CONTEXT = {"method": "workload-identity", "audience": "spend-guard"}
_BINDING_KEY = hashlib.sha256(b"gove-zone-spend-proof-binding-v1").digest()
_CONSUMPTION_KEY = hashlib.sha256(b"gove-zone-spend-proof-consumption-v1").digest()
_SPEND_KEY = hashlib.sha256(b"gove-zone-spend-proof-store-v1").digest()

SPEND_PROOF_ENVELOPE_CODEC = SealedPackCodec(
    SealedPackSchema(
        schema=SPEND_PROOF_ENVELOPE_SCHEMA,
        digest_domain=b"gove-zone:spend-proof-envelope:v1\0",
        media_types={
            "expected-pack-digest.json": "application/json",
            "trust-bundle.json": "application/json",
        },
        verification={"mode": "external-envelope-digest"},
        jsonl_identity_key="record_id",
        error_type=SpendProofError,
    ),
    error_type=SpendProofError,
)


@dataclass(frozen=True, slots=True)
class SpendGenuineProofExport:
    pack_directory: Path
    pack_digest: str
    envelope_directory: Path
    envelope_digest: str


class _PrincipalResolver:
    def __init__(self, principal: VerifiedPrincipal) -> None:
        self.principal = principal

    def resolve(self) -> VerifiedPrincipal:
        return self.principal


class _PolicyResolver:
    def __init__(self, resolved: ResolvedPolicy) -> None:
        self.resolved = resolved

    def resolve(self, principal: VerifiedPrincipal) -> ResolvedPolicy:
        if principal.tenant_id != self.resolved.ref.tenant_id:
            raise RuntimeError("fixture policy tenant mismatch")
        return self.resolved


class _AuditAnchor(AuditCheckpointAnchor):
    def __init__(self) -> None:
        self.states: dict[str, AuditCheckpoint] = {}
        self.lock = threading.Lock()

    def read(self, namespace: str) -> AuditCheckpoint | None:
        with self.lock:
            return self.states.get(namespace)

    def compare_and_swap(
        self,
        namespace: str,
        expected: AuditCheckpoint | None,
        replacement: AuditCheckpoint,
    ) -> bool:
        with self.lock:
            if self.states.get(namespace) != expected:
                return False
            self.states[namespace] = replacement
            return True


class _ConsumptionAnchor(ConsumptionStateAnchor):
    def __init__(self) -> None:
        self.states: dict[str, AnchoredConsumptionState] = {}
        self.lock = threading.Lock()

    def read(self, namespace: str) -> AnchoredConsumptionState | None:
        with self.lock:
            return self.states.get(namespace)

    def compare_and_swap(
        self,
        namespace: str,
        expected: AnchoredConsumptionState | None,
        replacement: AnchoredConsumptionState,
    ) -> bool:
        with self.lock:
            if self.states.get(namespace) != expected:
                return False
            self.states[namespace] = replacement
            return True


class _Clock:
    def now(self) -> datetime:
        return _NOW


@dataclass(slots=True)
class _Runtime:
    lane: str
    root: Path
    request: SideEffectRequest
    rules: SpendBudgetRules
    policy: SpendKernelPolicy
    attestation: PolicyArtifactAttestation
    authorizer: SideEffectAuthorizationKernel
    executor: ReceiptGatedSideEffectExecutor
    adapter: SpendGuardAdapter
    audit: ChainHashAuditStore
    audit_anchor: _AuditAnchor
    audit_namespace: str
    side_store: ReplaySideStore
    consumption: ReceiptConsumptionStore
    spend_store: SQLiteSpendStore
    spend_anchor: FileSpendStateAnchor
    provider: LocalJournalFixtureProvider
    decision_signer: Ed25519Signer
    checkpoint_signer: Ed25519Signer
    consumption_signer: Ed25519Signer
    spend_signer: Ed25519Signer
    lifecycle_signer: Ed25519Signer
    owned_capabilities: tuple[AttestedDirectory, ...]


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _rules() -> SpendBudgetRules:
    return SpendBudgetRules(
        currency="USD",
        single_limit_minor=10_000,
        hourly_limit_minor=100_000,
        daily_limit_minor=200_000,
        monthly_limit_minor=1_000_000,
        vendor_monthly_limits=(("vendor-known", 500_000),),
        rate_window_seconds=3600,
        rate_limit_count=100,
        loop_window_seconds=3600,
        loop_limit_count=100,
        anomaly_window_seconds=3600,
        anomaly_growth_basis_points=100_000,
        anomaly_floor_minor=500_000,
    )


def _policy(rules: SpendBudgetRules) -> SpendKernelPolicy:
    return SpendKernelPolicy(
        SpendPolicy(
            policy_id="fixture-spend-proof",
            policy_version="acgs-spend/v1",
            currency_exponent_version="fixture-iso4217/v1",
            currency_exponents=(("USD", 2),),
            single_payment_limit_minor=10_000,
            allowed_providers=("stripe-test",),
            allowed_recipients=("vendor-known",),
            allowed_approver_roles=("finance-approver",),
            approval_public_keys=(),
        ),
        rules,
    )


def _request(policy: SpendKernelPolicy, lane: str) -> SideEffectRequest:
    snapshot = policy.authorization_snapshot()
    amount = "200.00" if lane == "deny" else "10.00"
    return SideEffectRequest(
        request_id=f"spend-proof-{lane}-request",
        tenant_id="tenant-fixture",
        actor_id="agent-fixture",
        actor_role="purchasing-agent",
        authority="spend.pay",
        server_id=SPEND_SERVER_ID,
        tool=SPEND_TOOL_ID,
        operation=SPEND_OPERATION,
        resource="fixture-budget",
        environment="test",
        execution_boundary=SPEND_EXECUTION_BOUNDARY,
        policy_ref=ResolvedPolicyRef(
            tenant_id="tenant-fixture",
            bundle_id="fixture-spend-kernel",
            version=snapshot.policy_version,
            digest=snapshot.digest,
        ),
        requested_at=_iso(_NOW - timedelta(seconds=1)),
        nonce=f"fixture-nonce-{lane}",
        idempotency_key=f"fixture-idempotency-{lane}",
        args={
            "provider": "stripe-test",
            "recipient": "vendor-known",
            "amount": amount,
            "currency": "USD",
            "reference": f"fixture-order-{lane}",
        },
        side_effect_class=SPEND_SIDE_EFFECT_CLASS,
        goal=f"local fixture {lane} spend proof",
    )


def _runtime(
    root: Path,
    lane: str,
    *,
    rules: SpendBudgetRules | None = None,
    directory: AttestedDirectory | None = None,
    commit_guard: Callable[[str], None] | None = None,
) -> _Runtime:
    if directory is None:
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        os.chmod(root, 0o700)
    else:
        capability = require_attested_directory(directory, error_type=SpendProofError)
        capability.checkpoint()
        if Path(os.path.abspath(root)) != capability.display_path:
            raise SpendProofError("runtime capability does not bind the requested root")
    rules = rules or _rules()
    policy = _policy(rules)
    request = _request(policy, lane)
    decision_signer = Ed25519Signer.generate(f"spend-{lane}-decision")
    checkpoint_signer = Ed25519Signer.generate(f"spend-{lane}-checkpoint")
    consumption_signer = Ed25519Signer.generate(f"spend-{lane}-consumption")
    spend_signer = Ed25519Signer.generate(f"spend-{lane}-summary")
    lifecycle_signer = Ed25519Signer.generate(f"spend-{lane}-lifecycle")
    principal = VerifiedPrincipal(
        tenant_id=request.tenant_id,
        actor_id=request.actor_id,
        role=request.actor_role,
        authority=request.authority,
        authentication_context=_AUTH_CONTEXT,
        verified_at=_iso(_NOW - timedelta(hours=1)),
        expires_at=_iso(_NOW + timedelta(hours=1)),
    )
    attestation = PolicyArtifactAttestation(
        tenant_id=request.tenant_id,
        artifact_id=request.policy_ref.bundle_id,
        policy_version=request.policy_ref.version,
        digest=request.policy_ref.digest,
        resolver_id="fixture-spend-proof-resolver",
    )
    resolved = ResolvedPolicy(
        ref=request.policy_ref,
        policy=policy,
        attestation=attestation,
        validator=Validator("finance-validator", "approver"),
        authority=request.authority,
    )
    principal_resolver = _PrincipalResolver(principal)
    policy_resolver = _PolicyResolver(resolved)
    audit_anchor = _AuditAnchor()
    audit_namespace = f"spend-proof:{lane}"
    if directory is None:
        audit = ChainHashAuditStore(
            root / "audit.jsonl",
            checkpoint_anchor=audit_anchor,
            checkpoint_namespace=audit_namespace,
            checkpoint_signer=checkpoint_signer,
            checkpoint_verifier={checkpoint_signer.key_id: checkpoint_signer},
            require_trusted_checkpoint=True,
        )
    else:
        audit = ChainHashAuditStore.from_attested(
            directory,
            "audit.jsonl",
            checkpoint_anchor=audit_anchor,
            checkpoint_namespace=audit_namespace,
            checkpoint_signer=checkpoint_signer,
            checkpoint_verifier={checkpoint_signer.key_id: checkpoint_signer},
            require_trusted_checkpoint=True,
        )
    side_store = (
        ReplaySideStore(root / "replay.jsonl")
        if directory is None
        else ReplaySideStore.from_attested(directory, "replay.jsonl")
    )
    authorizer = SideEffectAuthorizationKernel(
        principal_resolver=principal_resolver,
        policy_resolver=policy_resolver,
        audit=audit,
        signer=decision_signer,
        binding_hmac_key=_BINDING_KEY,
        allowed_validator_roles=("approver",),
        side_store=side_store,
        clock=lambda: _NOW,
    )
    consumption_anchor = _ConsumptionAnchor()
    if directory is None:
        consumption = ReceiptConsumptionStore(
            root / "consumption.sqlite3",
            hmac_key=_CONSUMPTION_KEY,
            state_anchor=consumption_anchor,
            anchor_namespace=f"spend-proof-consumption:{lane}",
            require_trusted_anchor=True,
        )
    else:
        consumption = ReceiptConsumptionStore.from_attested(
            directory,
            "consumption.sqlite3",
            hmac_key=_CONSUMPTION_KEY,
            state_anchor=consumption_anchor,
            anchor_namespace=f"spend-proof-consumption:{lane}",
            require_trusted_anchor=True,
        )
    executor = ReceiptGatedSideEffectExecutor(
        principal_resolver=principal_resolver,
        policy_resolver=policy_resolver,
        audit=audit,
        consumption_store=consumption,
        verifier=decision_signer,
        binding_hmac_key=_BINDING_KEY,
        allowed_validator_roles=("approver",),
        clock=lambda: _NOW + timedelta(seconds=1),
        lifecycle_signer=lifecycle_signer,
        lifecycle_authority_id=f"spend-execution-validator:{lane}",
    )
    owned_capabilities: list[AttestedDirectory] = []
    if commit_guard is not None:
        commit_guard("before-anchor")
    if directory is None:
        anchor_dir = root / "spend-anchor"
        anchor_dir.mkdir(mode=0o700)
        os.chmod(anchor_dir, 0o700)
        spend_anchor = FileSpendStateAnchor(
            anchor_dir,
            hmac_key=_SPEND_KEY,
            key_id="spend-proof-key",
        )
    else:
        anchor_capability = directory.subdirectory("spend-anchor", create=True)
        owned_capabilities.append(anchor_capability)
        spend_anchor = FileSpendStateAnchor.from_attested(
            anchor_capability,
            hmac_key=_SPEND_KEY,
            key_id="spend-proof-key",
        )
    if commit_guard is not None:
        commit_guard("before-store")
    spend_store = (
        SQLiteSpendStore.create(
            root / "spend.sqlite3",
            anchor=spend_anchor,
            anchor_namespace=f"spend-proof-store:{lane}",
            clock=_Clock(),
        )
        if directory is None
        else SQLiteSpendStore.create_from_attested(
            directory,
            "spend.sqlite3",
            anchor=spend_anchor,
            anchor_namespace=f"spend-proof-store:{lane}",
            clock=_Clock(),
        )
    )
    if commit_guard is not None:
        commit_guard("before-journal")
    if directory is None:
        provider_dir = root / "provider"
        provider_dir.mkdir(mode=0o700)
        os.chmod(provider_dir, 0o700)
        provider = LocalJournalFixtureProvider(provider_dir / "journal.jsonl")
    else:
        provider_capability = directory.subdirectory("provider", create=True)
        owned_capabilities.append(provider_capability)
        provider = LocalJournalFixtureProvider.from_attested(
            provider_capability,
            "journal.jsonl",
        )
    adapter = SpendGuardAdapter(
        authorizer=authorizer,
        executor=executor,
        store=spend_store,
        provider=provider,
        policy=policy,
        binding_hmac_key=_BINDING_KEY,
    )
    return _Runtime(
        lane,
        root,
        request,
        rules,
        policy,
        attestation,
        authorizer,
        executor,
        adapter,
        audit,
        audit_anchor,
        audit_namespace,
        side_store,
        consumption,
        spend_store,
        spend_anchor,
        provider,
        decision_signer,
        checkpoint_signer,
        consumption_signer,
        spend_signer,
        lifecycle_signer,
        tuple(owned_capabilities),
    )


def _prepare(runtime: _Runtime) -> SideEffectRequest:
    request = runtime.request
    normalized = normalize_spend_arguments(
        cast(dict[str, Any], deep_thaw_json(request.args)),
        dict(runtime.policy.spend_policy.currency_exponents),
    )
    payment = {**normalized.to_arguments(), "amount_minor": normalized.amount_minor}
    idempotency_digest = idempotency_binding_digest(
        request.idempotency_key,
        request.tenant_id,
        binding_hmac_key=_BINDING_KEY,
    )
    reservation = runtime.adapter._reservation_request(  # noqa: SLF001
        request,
        payment,
        runtime.rules,
        approval_digest=None,
        idempotency_digest=idempotency_digest,
        receipt_digest="0" * 64,
        expected_stop_generation=0,
    )
    probe = runtime.spend_store.preview(reservation, runtime.rules)
    envelope = runtime.adapter._envelope(  # noqa: SLF001
        request,
        payment,
        runtime.rules,
        probe,
        None,
        None,
        0,
    )
    return dataclasses.replace(request, args=envelope, side_effect_class=SPEND_SIDE_EFFECT_CLASS)


def _context(request: SideEffectRequest, *, tampered: bool = False) -> SideEffectExecutionContext:
    return SideEffectExecutionContext(
        request_id=request.request_id,
        tenant_id=request.tenant_id,
        actor_id="tampered-agent" if tampered else request.actor_id,
        actor_role=request.actor_role,
        authority=request.authority,
        server_id=request.server_id,
        tool=request.tool,
        operation=request.operation,
        resource=request.resource,
        environment=request.environment,
        execution_boundary=request.execution_boundary,
        policy_ref=request.policy_ref,
        observed_at=_iso(_NOW + timedelta(seconds=1)),
        authentication_context=_AUTH_CONTEXT,
    )


def _sqlite_rows(path: Path, query: str) -> list[dict[str, Any]]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in connection.execute(query)]
    finally:
        connection.close()


def _spend_summary(runtime: _Runtime) -> dict[str, Any]:
    anchor = runtime.spend_store.verify_integrity()
    return {
        "schema": SPEND_STORE_SUMMARY_SCHEMA,
        "lane": runtime.lane,
        "anchor": dataclasses.asdict(anchor),
        "events": _sqlite_rows(
            runtime.spend_store._sqlite_connection_path(),  # noqa: SLF001
            "SELECT generation,event_id,event_type,entity_id,payload_json,payload_digest,"
            "previous_hash,event_hash,occurred_at_us "
            "FROM spend_integrity_events ORDER BY generation",
        ),
        "intents": _sqlite_rows(
            runtime.spend_store._sqlite_connection_path(),  # noqa: SLF001
            "SELECT * FROM spend_intents ORDER BY spend_id",
        ),
        "outcomes": _sqlite_rows(
            runtime.spend_store._sqlite_connection_path(),  # noqa: SLF001
            "SELECT * FROM spend_outcomes ORDER BY spend_id",
        ),
        "controls": _sqlite_rows(
            runtime.spend_store._sqlite_connection_path(),  # noqa: SLF001
            "SELECT * FROM spend_control_events ORDER BY tenant_id,stop_generation",
        ),
    }


def _consumption_record(value: ConsumptionRecord | None) -> dict[str, Any] | None:
    if value is None:
        return None
    result = dataclasses.asdict(value)
    result["state"] = value.state.value
    return result


def _key(signer: Ed25519Signer, purpose: str) -> dict[str, str]:
    return {
        "purpose": purpose,
        "key_id": signer.key_id,
        "algorithm": signer.algorithm,
        "public_bytes_hex": signer.public_bytes().hex(),
    }


def _pin(runtime: _Runtime) -> dict[str, Any]:
    return {
        "tenant_id": runtime.request.tenant_id,
        "policy_version": runtime.request.policy_ref.version,
        "policy_digest": runtime.request.policy_ref.digest,
        "policy_attestation": runtime.attestation.to_dict(),
        "target": {
            "server_id": SPEND_SERVER_ID,
            "tool": SPEND_TOOL_ID,
            "operation": SPEND_OPERATION,
            "execution_boundary": SPEND_EXECUTION_BOUNDARY,
            "provider": "stripe-test",
            "rules_digest": runtime.rules.digest,
        },
    }


def _trust(runtime: _Runtime) -> dict[str, Any]:
    return {
        **_pin(runtime),
        "checkpoint_authority_id": f"audit-checkpoint:{runtime.audit_namespace}",
        "lifecycle_authority_id": f"spend-execution-validator:{runtime.lane}",
        "keys": {
            "receipt": _key(runtime.decision_signer, "receipt"),
            "refusal": _key(runtime.decision_signer, "refusal"),
            "audit-checkpoint": _key(runtime.checkpoint_signer, "audit-checkpoint"),
            "consumption-summary": _key(runtime.consumption_signer, "consumption-summary"),
            "spend-summary": _key(runtime.spend_signer, "spend-summary"),
            "lifecycle-attestation": _key(runtime.lifecycle_signer, "lifecycle-attestation"),
        },
    }


def _capture_lane(
    root: Path,
    lane: str,
    *,
    directory: AttestedDirectory | None = None,
    commit_guard: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    runtime = _runtime(root, lane, directory=directory, commit_guard=commit_guard)
    before = runtime.provider.effect_count
    governed: SideEffectRequest
    authorization: SideEffectAuthorization
    status: str
    executed = False
    reason_code: str
    refusal_evidence: ExecutionRefusalEvidence | None = None
    if lane == "allow":
        result = runtime.adapter.execute(
            runtime.request,
            runtime.rules,
            authentication_context=_AUTH_CONTEXT,
        )
        if type(result) is not SpendGuardResult:
            raise SpendProofError("allow lane returned an invalid result")
        authorization = result.authorization
        governed = dataclasses.replace(runtime.request, args=authorization.approved_arguments)
        status = "SUCCEEDED"
        executed = True
        reason_code = ExecutionReasonCode.SUCCEEDED.value
    else:
        governed = _prepare(runtime)
        authorization = runtime.authorizer.authorize(governed)
        if lane == "deny":
            if authorization.decision is not Decision.DENY:
                raise SpendProofError("deny lane did not produce a policy denial")
            status = "DENIED"
            reason_code = authorization.reason_code.value
        else:
            if authorization.decision is not Decision.ALLOW:
                raise SpendProofError("tamper lane did not obtain the original allow receipt")
            try:
                runtime.executor.execute(
                    authorization,
                    _context(governed, tampered=True),
                    nonce=runtime.request.nonce,
                    idempotency_key=runtime.request.idempotency_key,
                )
            except SideEffectExecutionError as exc:
                reason_code = exc.reason_code.value
                # The executor's own proof is kept exactly as raised. It is the
                # only evidence bound to this exact refused attempt, so the pack
                # is built around it rather than around the reason code alone.
                refusal_evidence = exc.evidence
            else:
                raise SpendProofError("tampered execution unexpectedly succeeded")
            if refusal_evidence is None:
                raise SpendProofError("tamper lane produced no execution refusal evidence")
            status = "TAMPER_BLOCKED"
    receipt = authorization.receipt
    if receipt is None:
        raise SpendProofError(f"{lane} lane has no signed decision receipt")
    events = list(runtime.audit.iter_events())
    side_records = list(runtime.side_store.iter_records())
    checkpoint = runtime.audit_anchor.read(runtime.audit_namespace)
    # A refused lane commits the authorization decision *and* the executor's
    # EXECUTION_REFUSAL record; only an allow lane adds the reserved/succeeded
    # lifecycle pair. Hardcoding one non-allow event would have silently dropped
    # the refusal proof from the pack.
    expected_event_count = {"allow": 3, "tamper": 2}.get(lane, 1)
    if len(events) != expected_event_count or len(side_records) != 1 or checkpoint is None:
        raise SpendProofError(f"{lane} lane evidence coverage is incomplete")
    if refusal_evidence is not None:
        refusal_event = events[1]
        # The exported record must be the exact one the executor proved, byte for
        # byte, and must satisfy the single shared refusal contract. Anything else
        # would ship a pack whose refusal cannot be verified against the attempt.
        if (
            refusal_event.get("record_kind") != RecordKind.EXECUTION_REFUSAL.value
            or refusal_event.get("event_id") != refusal_evidence.audit_event_id
            or refusal_event.get("event_hash") != refusal_evidence.audit_event_hash
            or refusal_event.get("execution_evidence") != refusal_evidence.audit_evidence()
            or execution_refusal_error(refusal_event) is not None
        ):
            raise SpendProofError(f"{lane} lane execution refusal evidence is incomplete")
    event = next(
        (
            candidate
            for candidate in events
            if candidate["event_id"] == authorization.audit_event_id
        ),
        None,
    )
    if event is None or side_records[0]["event_id"] != authorization.audit_event_id:
        raise SpendProofError(f"{lane} lane authorization audit/replay evidence is incomplete")
    after = runtime.provider.effect_count
    spend = _spend_summary(runtime)
    outcomes = cast(list[dict[str, Any]], spend["outcomes"])
    result_digest = outcomes[0]["result_digest"] if outcomes else None
    consumption = runtime.consumption.status(runtime.request.tenant_id, receipt.receipt_id)
    approved = cast(dict[str, Any], deep_thaw_json(authorization.approved_arguments))
    binding = cast(dict[str, Any], deep_thaw_json(authorization.reserved_binding))
    payment = cast(dict[str, Any], approved.get("payment", {}))
    request_row = {
        "record_id": f"request-{lane}",
        "lane": lane,
        "request_id": governed.request_id,
        "tenant_id": governed.tenant_id,
        "actor_id": governed.actor_id,
        "actor_role": governed.actor_role,
        "authority": governed.authority,
        "server_id": governed.server_id,
        "tool": governed.tool,
        "operation": governed.operation,
        "resource": governed.resource,
        "environment": governed.environment,
        "execution_boundary": governed.execution_boundary,
        "side_effect_class": governed.side_effect_class,
        "requested_at": governed.requested_at,
        "policy": {"version": governed.policy_ref.version, "digest": governed.policy_ref.digest},
        "arguments": approved
        if authorization.executable
        else cast(dict[str, Any], deep_thaw_json(governed.args)),
        "argument_hash": authorization.original_arguments_hash,
        "payment_hash": strict_json_hash(payment),
        "idempotency_digest": binding["idempotency_digest"],
        "approval_digest": approved.get("approval_digest"),
        "expected_stop_generation": approved.get("expected_stop_generation", 0),
    }
    authorization_row = {
        "record_id": f"authorization-{lane}",
        "lane": lane,
        "request_id": authorization.request_id,
        "decision": authorization.decision.value,
        "reason_codes": [code.value for code in authorization.reason_codes],
        "original_arguments_hash": authorization.original_arguments_hash,
        "approved_arguments_hash": authorization.approved_arguments_hash,
        "binding_hash": authorization.binding_hash,
        "audit_event_id": authorization.audit_event_id,
        "audit_event_hash": authorization.audit_event_hash,
        "previous_audit_hash": authorization.previous_audit_hash,
        "receipt_id": receipt.receipt_id,
        "receipt_hash": receipt.receipt_hash,
        "reserved_binding": binding,
    }
    protocol = {
        "record_id": f"protocol-{lane}",
        "lane": lane,
        "request_id": governed.request_id,
        "decision": authorization.decision.value,
        "status": status,
        "executed": executed,
        "reason_code": reason_code,
        "provider_delta": after - before,
        "receipt_id": receipt.receipt_id,
        "receipt_hash": receipt.receipt_hash,
        "audit_event_id": authorization.audit_event_id,
        "audit_event_hash": authorization.audit_event_hash,
        "argument_hash": authorization.original_arguments_hash,
        "result_digest": result_digest,
    }
    consumption_payload = {
        "schema": SPEND_CONSUMPTION_SUMMARY_SCHEMA,
        "lane": lane,
        "receipt_id": receipt.receipt_id,
        "receipt_hash": receipt.receipt_hash,
        "audit_event_id": authorization.audit_event_id,
        "audit_event_hash": authorization.audit_event_hash,
        "result_digest": result_digest,
        "record": _consumption_record(consumption),
    }
    journal = runtime.provider.read_records()
    capture_result = {
        "pin": _pin(runtime),
        "trust": _trust(runtime),
        "artifact": json.loads(runtime.policy.authorization_snapshot().canonical_artifact),
        "request": request_row,
        "authorization": authorization_row,
        "receipt": {"record_id": f"receipt-{lane}", "lane": lane, "receipt": receipt.to_dict()},
        "refusal": None
        if lane != "deny"
        else {
            "record_id": "refusal-deny",
            "lane": lane,
            "receipt": receipt.to_dict(),
            "reason_codes": [code.value for code in authorization.reason_codes],
        },
        "audit": {
            "record_id": f"audit-{lane}",
            "lane": lane,
            "event_id": authorization.audit_event_id,
            "event": event,
            "lifecycle_events": events,
        },
        "replay": {
            "record_id": f"replay-{lane}",
            "lane": lane,
            "event_id": authorization.audit_event_id,
            "side_record": side_records[0],
        },
        "checkpoint": {
            "event_id": authorization.audit_event_id,
            "event_ids": [candidate["event_id"] for candidate in events],
            "checkpoint": checkpoint.to_dict(),
        },
        "consumption": signed_summary(
            consumption_payload, runtime.consumption_signer, "consumption-summary"
        ),
        "spend": signed_summary(spend, runtime.spend_signer, "spend-summary"),
        "journal": journal,
        "protocol": protocol,
    }
    runtime.spend_store.close()
    runtime.spend_anchor.close()
    for capability in reversed(runtime.owned_capabilities):
        capability.close()
    return capture_result


def _spend_output_capabilities(
    *,
    output_capability: AttestedDirectory | None,
    open_directory: OpenDirectory | None,
    expected_output_parent: str | Path | None,
    expected_parent_identity: DirectoryIdentity | None,
) -> tuple[OpenDirectory, Callable[[Path, DirectoryIdentity], None]]:
    if output_capability is not None:
        if any(
            value is not None
            for value in (open_directory, expected_output_parent, expected_parent_identity)
        ):
            raise SpendProofError(
                "output capability cannot be mixed with legacy path identity hooks"
            )
        capability = require_attested_directory(
            output_capability,
            error_type=SpendProofError,
        )
        capability.checkpoint()
        return capability.open_directory_path, capability.assert_path_identity
    opener = open_directory or (
        lambda path: sealed_pack.open_directory(path, error_type=SpendProofError)
    )
    if (expected_output_parent is None) != (expected_parent_identity is None):
        raise SpendProofError("expected output parent and identity must be supplied together")
    if expected_output_parent is not None and expected_parent_identity is not None:
        descriptor, actual = opener(Path(expected_output_parent))
        try:
            if actual != expected_parent_identity:
                raise SpendProofError("expected output parent identity changed")
        finally:
            os.close(descriptor)

    def assert_identity(path: Path, expected: DirectoryIdentity) -> None:
        sealed_pack.assert_path_identity(
            path,
            expected,
            open_directory=opener,
            error_type=SpendProofError,
        )

    return opener, assert_identity


def _export_spend_pack_with_capabilities(
    output: str | Path,
    payloads: SpendProofPayloads,
    *,
    open_directory: OpenDirectory,
    assert_path_identity: Callable[[Path, DirectoryIdentity], None],
) -> SpendProofPack:
    _manifest, digest = SPEND_PROOF_CODEC.export_new_pack(
        Path(output),
        payloads.files,
        open_directory=open_directory,
        assert_path_identity=assert_path_identity,
    )
    return SpendProofPack(Path(output), digest)


def export_genuine_spend_proof(
    pack_output: str | Path,
    envelope_output: str | Path,
    *,
    runtime_root: str | Path,
    commit_guard: Callable[[str], None] | None = None,
    open_directory: OpenDirectory | None = None,
    expected_output_parent: str | Path | None = None,
    expected_parent_identity: DirectoryIdentity | None = None,
    output_capability: AttestedDirectory | None = None,
    runtime_capability: AttestedDirectory | None = None,
) -> SpendGenuineProofExport:
    """Capture allow/deny/tamper locally, then export and independently verify."""

    opener, assert_identity = _spend_output_capabilities(
        output_capability=output_capability,
        open_directory=open_directory,
        expected_output_parent=expected_output_parent,
        expected_parent_identity=expected_parent_identity,
    )
    if commit_guard is not None:
        commit_guard("before-runtime")
    root = Path(runtime_root)
    if runtime_capability is None:
        root.mkdir(mode=0o700, parents=False, exist_ok=False)
        captures = {lane: _capture_lane(root / lane, lane) for lane in SPEND_PROOF_LANES}
    else:
        runtime_directory = require_attested_directory(
            runtime_capability,
            error_type=SpendProofError,
        )
        runtime_directory.checkpoint()
        if Path(os.path.abspath(root)) != runtime_directory.display_path:
            raise SpendProofError("runtime capability does not bind runtime_root")
        captures = {}
        for lane in SPEND_PROOF_LANES:
            lane_directory = runtime_directory.subdirectory(lane, create=True)
            try:
                captures[lane] = _capture_lane(
                    lane_directory.display_path,
                    lane,
                    directory=lane_directory,
                    commit_guard=commit_guard,
                )
            finally:
                lane_directory.close()
    if output_capability is not None:
        output_capability.relative_from_display(pack_output)
        output_capability.relative_from_display(envelope_output)
    values: dict[str, Any] = {
        "scenario.json": {
            "schema": SPEND_SCENARIO_SCHEMA,
            "lanes": {lane: captures[lane]["pin"] for lane in SPEND_PROOF_LANES},
        },
        "runtime-bindings.json": {
            "schema": SPEND_RUNTIME_SCHEMA,
            "lanes": {lane: captures[lane]["pin"] for lane in SPEND_PROOF_LANES},
        },
        "policy.json": {
            "schema": SPEND_POLICY_EVIDENCE_SCHEMA,
            "lanes": {
                lane: {**captures[lane]["pin"], "artifact": captures[lane]["artifact"]}
                for lane in SPEND_PROOF_LANES
            },
        },
        "requests.jsonl": [captures[lane]["request"] for lane in SPEND_PROOF_LANES],
        "authorizations.jsonl": [captures[lane]["authorization"] for lane in SPEND_PROOF_LANES],
        "receipts.jsonl": [captures[lane]["receipt"] for lane in SPEND_PROOF_LANES],
        "refusals.jsonl": [captures["deny"]["refusal"]],
        "audit-checkpoint.json": {
            "schema": SPEND_CHECKPOINT_SCHEMA,
            "lanes": {lane: captures[lane]["checkpoint"] for lane in SPEND_PROOF_LANES},
        },
        "audit.jsonl": [captures[lane]["audit"] for lane in SPEND_PROOF_LANES],
        "replay.jsonl": [captures[lane]["replay"] for lane in SPEND_PROOF_LANES],
        "consumption-summary.json": {
            "schema": SPEND_CONSUMPTION_SUMMARY_SCHEMA,
            "lanes": {lane: captures[lane]["consumption"] for lane in SPEND_PROOF_LANES},
        },
        "spend-store-summary.json": {
            "schema": SPEND_STORE_SUMMARY_SCHEMA,
            "lanes": {lane: captures[lane]["spend"] for lane in SPEND_PROOF_LANES},
        },
        "fixture-journal.jsonl": [
            {
                "record_id": "journal-allow-1",
                "lane": "allow",
                "event": captures["allow"]["journal"][0],
            }
        ],
        "protocol-results.jsonl": [captures[lane]["protocol"] for lane in SPEND_PROOF_LANES],
    }
    payloads = SpendProofPayloads.from_values(values)
    trust = {
        "schema": SPEND_TRUST_SCHEMA,
        "lanes": {lane: captures[lane]["trust"] for lane in SPEND_PROOF_LANES},
    }
    entries = SPEND_PROOF_CODEC.manifest_entries(payloads.files)
    predicted = SPEND_PROOF_CODEC.pack_digest(SPEND_PROOF_CODEC.manifest_payload(entries))
    envelope_payloads = {
        "trust-bundle.json": SPEND_PROOF_ENVELOPE_CODEC.json_bytes(trust),
        "expected-pack-digest.json": SPEND_PROOF_ENVELOPE_CODEC.json_bytes(
            {"schema": SPEND_EXPECTED_DIGEST_SCHEMA, "pack_digest": predicted}
        ),
    }
    if commit_guard is not None:
        commit_guard("before-pack-commit")
    pack = _export_spend_pack_with_capabilities(
        pack_output,
        payloads,
        open_directory=opener,
        assert_path_identity=assert_identity,
    )
    if commit_guard is not None:
        commit_guard("pack-committed")
    if pack.pack_digest != predicted:
        raise SpendProofError("committed spend pack digest differs from preflight")
    _manifest, envelope_digest = SPEND_PROOF_ENVELOPE_CODEC.export_new_pack(
        Path(envelope_output),
        envelope_payloads,
        open_directory=opener,
        assert_path_identity=assert_identity,
    )
    if commit_guard is not None:
        commit_guard("envelope-committed")
    verified = verify_exported_spend_proof(
        pack.directory,
        envelope_output,
        expected_envelope_digest=envelope_digest,
        output_capability=output_capability,
    )
    if not hmac.compare_digest(verified, pack.pack_digest):
        raise SpendProofError("offline verified digest differs from committed spend pack")
    if commit_guard is not None:
        commit_guard("verified")
    if output_capability is not None:
        output_directory = require_attested_directory(
            output_capability,
            error_type=SpendProofError,
        )
        output_directory.checkpoint()
        output_directory.assert_path_identity(
            output_directory.display_path,
            output_directory.identity,
        )
    if runtime_capability is not None:
        runtime_directory = require_attested_directory(
            runtime_capability,
            error_type=SpendProofError,
        )
        runtime_directory.checkpoint()
        runtime_directory.assert_path_identity(
            runtime_directory.display_path,
            runtime_directory.identity,
        )
    return SpendGenuineProofExport(
        pack.directory, pack.pack_digest, Path(envelope_output), envelope_digest
    )


def _loop_rules() -> SpendBudgetRules:
    return dataclasses.replace(
        _rules(),
        hourly_limit_minor=5_000,
        daily_limit_minor=5_000,
        monthly_limit_minor=5_000,
        vendor_monthly_limits=(("vendor-known", 5_000),),
    )


def _private_unsafe_baseline(
    root: Path,
    *,
    directory: AttestedDirectory | None = None,
    commit_guard: Callable[[str], None] | None = None,
) -> tuple[int, int]:
    if commit_guard is not None:
        commit_guard("before-journal")
    if directory is None:
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        os.chmod(root, 0o700)
        provider = LocalJournalFixtureProvider(root / "journal.jsonl")
    else:
        provider = LocalJournalFixtureProvider.from_attested(directory, "journal.jsonl")
    for index in range(1, 13):
        provider.create_payment(
            {
                "provider": "stripe-test",
                "recipient": "vendor-known",
                "amount": "10.00",
                "amount_minor": 1000,
                "currency": "USD",
                "reference": f"unsafe-loop-order-{index:02d}",
            },
            idempotency_digest=hashlib.sha256(
                f"private-unsafe-loop-{index:02d}".encode()
            ).hexdigest(),
        )
    return provider.effect_count, provider.effect_count * 1000


def _capture_loop(
    root: Path,
    *,
    directory: AttestedDirectory | None = None,
    commit_guard: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    runtime = _runtime(
        root,
        "loop",
        rules=_loop_rules(),
        directory=directory,
        commit_guard=commit_guard,
    )
    captures: list[dict[str, Any]] = []
    for index in range(1, 13):
        lane = f"loop-{index:02d}"
        runtime.request = dataclasses.replace(
            runtime.request,
            request_id=f"spend-proof-{lane}-request",
            nonce=f"fixture-nonce-{lane}",
            idempotency_key=f"fixture-idempotency-{lane}",
            args={
                "provider": "stripe-test",
                "recipient": "vendor-known",
                "amount": "10.00",
                "currency": "USD",
                "reference": f"fixture-loop-order-{index:02d}",
            },
            goal=f"local fixture spend-loop attempt {index:02d}",
        )
        governed = _prepare(runtime)
        before = runtime.provider.effect_count
        events_before = len(list(runtime.audit.iter_events()))
        side_records_before = len(list(runtime.side_store.iter_records()))
        result: SpendGuardResult | None = None
        try:
            result = runtime.adapter.execute(
                runtime.request,
                runtime.rules,
                authentication_context=_AUTH_CONTEXT,
            )
        except SpendGuardError:
            status = "DENIED"
            executed = False
            reason_code = "authorization.denied"
        else:
            status = "SUCCEEDED"
            executed = True
            reason_code = ExecutionReasonCode.SUCCEEDED.value
        if (index <= 5) != (result is not None):
            raise SpendProofError(f"{lane} did not enforce the exact cumulative budget bound")
        after = runtime.provider.effect_count
        spend = _spend_summary(runtime)
        result_digest: str | None = None
        if result is not None:
            outcomes = cast(list[dict[str, Any]], spend["outcomes"])
            outcome = next(row for row in outcomes if row["spend_id"] == result.spend_id)
            result_digest = cast(str, outcome["result_digest"])
        events = list(runtime.audit.iter_events())
        side_records = list(runtime.side_store.iter_records())
        lifecycle_events = events[events_before:]
        new_side_records = side_records[side_records_before:]
        expected_event_count = 3 if result is not None else 1
        if len(lifecycle_events) != expected_event_count or len(new_side_records) != 1:
            raise SpendProofError(f"{lane} audit/replay capture is incomplete")
        side = new_side_records[0]
        event = next(
            (
                candidate
                for candidate in lifecycle_events
                if candidate["event_id"] == side["event_id"]
            ),
            None,
        )
        if event is None:
            raise SpendProofError(f"{lane} audit/replay event mismatch")
        arguments = cast(dict[str, Any], deep_thaw_json(governed.args))
        payment = cast(dict[str, Any], arguments["payment"])
        authorization = result.authorization if result is not None else None
        receipt = authorization.receipt if authorization is not None else None
        if result is not None and receipt is None:
            raise SpendProofError(f"{lane} successful adapter result has no receipt")
        request_row = {
            "record_id": f"request-{lane}",
            "lane": lane,
            "request_id": governed.request_id,
            "tenant_id": governed.tenant_id,
            "actor_id": governed.actor_id,
            "actor_role": governed.actor_role,
            "authority": governed.authority,
            "server_id": governed.server_id,
            "tool": governed.tool,
            "operation": governed.operation,
            "resource": governed.resource,
            "environment": governed.environment,
            "execution_boundary": governed.execution_boundary,
            "side_effect_class": governed.side_effect_class,
            "requested_at": governed.requested_at,
            "policy": {
                "version": governed.policy_ref.version,
                "digest": governed.policy_ref.digest,
            },
            "arguments": arguments,
            "argument_hash": event["argument_hash"],
            "payment_hash": strict_json_hash(payment),
            "idempotency_digest": idempotency_binding_digest(
                runtime.request.idempotency_key,
                runtime.request.tenant_id,
                binding_hmac_key=_BINDING_KEY,
            ),
            "approval_digest": arguments.get("approval_digest"),
            "expected_stop_generation": arguments.get("expected_stop_generation", 0),
        }
        authorization_row = (
            None
            if authorization is None or receipt is None
            else {
                "record_id": f"authorization-{lane}",
                "lane": lane,
                "request_id": authorization.request_id,
                "decision": authorization.decision.value,
                "reason_codes": [code.value for code in authorization.reason_codes],
                "original_arguments_hash": authorization.original_arguments_hash,
                "approved_arguments_hash": authorization.approved_arguments_hash,
                "binding_hash": authorization.binding_hash,
                "audit_event_id": authorization.audit_event_id,
                "audit_event_hash": authorization.audit_event_hash,
                "previous_audit_hash": authorization.previous_audit_hash,
                "receipt_id": receipt.receipt_id,
                "receipt_hash": receipt.receipt_hash,
                "reserved_binding": cast(
                    dict[str, Any], deep_thaw_json(authorization.reserved_binding)
                ),
            }
        )
        protocol = {
            "record_id": f"protocol-{lane}",
            "lane": lane,
            "request_id": governed.request_id,
            "decision": event["decision"],
            "status": status,
            "executed": executed,
            "reason_code": reason_code,
            "provider_delta": after - before,
            "receipt_id": receipt.receipt_id if receipt is not None else None,
            "receipt_hash": receipt.receipt_hash if receipt is not None else None,
            "audit_event_id": event["event_id"],
            "audit_event_hash": event["event_hash"],
            "argument_hash": event["argument_hash"],
            "result_digest": result_digest,
        }
        captures.append(
            {
                "request": request_row,
                "authorization": authorization_row,
                "receipt": {
                    "record_id": f"receipt-{lane}",
                    "lane": lane,
                    "receipt": receipt.to_dict() if receipt is not None else None,
                },
                "refusal": {
                    "record_id": f"refusal-{lane}",
                    "lane": lane,
                    "request_id": governed.request_id,
                    "argument_hash": event["argument_hash"],
                    "audit_event_id": event["event_id"],
                    "audit_event_hash": event["event_hash"],
                    "reason_codes": ["authorization.denied"],
                },
                "audit": {
                    "record_id": f"audit-{lane}",
                    "lane": lane,
                    "event_id": event["event_id"],
                    "event": event,
                    "lifecycle_events": lifecycle_events,
                },
                "replay": {
                    "record_id": f"replay-{lane}",
                    "lane": lane,
                    "event_id": event["event_id"],
                    "side_record": side,
                },
                "protocol": protocol,
                "consumption": {
                    "lane": lane,
                    "receipt_id": receipt.receipt_id if receipt is not None else None,
                    "receipt_hash": receipt.receipt_hash if receipt is not None else None,
                    "audit_event_id": event["event_id"],
                    "audit_event_hash": event["event_hash"],
                    "result_digest": result_digest,
                    "record": _consumption_record(
                        runtime.consumption.status(runtime.request.tenant_id, receipt.receipt_id)
                        if receipt is not None
                        else None
                    ),
                },
            }
        )
    checkpoint = runtime.audit_anchor.read(runtime.audit_namespace)
    if checkpoint is None or len(list(runtime.audit.iter_events())) != 22:
        raise SpendProofError("loop audit checkpoint coverage is incomplete")
    spend = _spend_summary(runtime)
    provider_effect_count = runtime.provider.effect_count
    journal = runtime.provider.read_records()
    capture_result = {
        "runtime": runtime,
        "captures": captures,
        "checkpoint": checkpoint,
        "spend": spend,
        "journal": journal,
        "provider_effect_count": provider_effect_count,
    }
    runtime.spend_store.close()
    runtime.spend_anchor.close()
    for capability in reversed(runtime.owned_capabilities):
        capability.close()
    return capture_result


def export_spend_loop_disaster_proof(
    pack_output: str | Path,
    envelope_output: str | Path,
    *,
    runtime_root: str | Path,
    commit_guard: Callable[[str], None] | None = None,
    open_directory: OpenDirectory | None = None,
    expected_output_parent: str | Path | None = None,
    expected_parent_identity: DirectoryIdentity | None = None,
    output_capability: AttestedDirectory | None = None,
    runtime_capability: AttestedDirectory | None = None,
) -> SpendGenuineProofExport:
    """Capture the deterministic 12-call loop and its cumulative-budget refusal."""

    opener, assert_identity = _spend_output_capabilities(
        output_capability=output_capability,
        open_directory=open_directory,
        expected_output_parent=expected_output_parent,
        expected_parent_identity=expected_parent_identity,
    )
    if commit_guard is not None:
        commit_guard("before-runtime")
    root = Path(runtime_root)
    if runtime_capability is None:
        root.mkdir(mode=0o700, parents=False, exist_ok=False)
        baseline_count, baseline_total = _private_unsafe_baseline(root / "unsafe-baseline")
        captured = _capture_loop(root / "governed")
    else:
        runtime_directory = require_attested_directory(
            runtime_capability,
            error_type=SpendProofError,
        )
        runtime_directory.checkpoint()
        if Path(os.path.abspath(root)) != runtime_directory.display_path:
            raise SpendProofError("runtime capability does not bind runtime_root")
        baseline_directory = runtime_directory.subdirectory("unsafe-baseline", create=True)
        try:
            baseline_count, baseline_total = _private_unsafe_baseline(
                baseline_directory.display_path,
                directory=baseline_directory,
                commit_guard=commit_guard,
            )
        finally:
            baseline_directory.close()
        governed_directory = runtime_directory.subdirectory("governed", create=True)
        try:
            captured = _capture_loop(
                governed_directory.display_path,
                directory=governed_directory,
                commit_guard=commit_guard,
            )
        finally:
            governed_directory.close()
    if output_capability is not None:
        output_capability.relative_from_display(pack_output)
        output_capability.relative_from_display(envelope_output)
    runtime = cast(_Runtime, captured["runtime"])
    attempts = cast(list[dict[str, Any]], captured["captures"])
    pin = _pin(runtime)
    trust_lane = _trust(runtime)
    artifact = json.loads(runtime.policy.authorization_snapshot().canonical_artifact)
    consumption_payload = {
        "schema": SPEND_LOOP_CONSUMPTION_SUMMARY_SCHEMA,
        "lane": "loop",
        "records": [attempt["consumption"] for attempt in attempts],
        "succeeded_count": 5,
        "denied_count": 7,
    }
    values: dict[str, Any] = {
        "scenario.json": {
            "schema": SPEND_LOOP_SCENARIO_SCHEMA,
            "lanes": {"loop": pin},
            "loop": {
                "request_count": 12,
                "amount_minor": 1000,
                "currency": "USD",
                "budget_limit_minor": 5000,
                "baseline_effect_count": baseline_count,
                "baseline_total_minor": baseline_total,
                "governed_succeeded_count": 5,
                "governed_denied_count": 7,
                "governed_effect_count": captured["provider_effect_count"],
                "governed_total_minor": cast(int, captured["provider_effect_count"]) * 1000,
                "unsafe_baseline_mode": "private-local-fixture-no-fallback",
            },
        },
        "runtime-bindings.json": {"schema": SPEND_LOOP_RUNTIME_SCHEMA, "lanes": {"loop": pin}},
        "policy.json": {
            "schema": SPEND_LOOP_POLICY_EVIDENCE_SCHEMA,
            "lanes": {"loop": {**pin, "artifact": artifact}},
        },
        "requests.jsonl": [attempt["request"] for attempt in attempts],
        "authorizations.jsonl": [attempt["authorization"] for attempt in attempts[:5]],
        "receipts.jsonl": [attempt["receipt"] for attempt in attempts[:5]],
        "refusals.jsonl": [attempt["refusal"] for attempt in attempts[5:]],
        "audit-checkpoint.json": {
            "schema": SPEND_LOOP_CHECKPOINT_SCHEMA,
            "lane": "loop",
            "event_ids": [
                event["event_id"]
                for attempt in attempts
                for event in attempt["audit"]["lifecycle_events"]
            ],
            "checkpoint": captured["checkpoint"].to_dict(),
        },
        "audit.jsonl": [attempt["audit"] for attempt in attempts],
        "replay.jsonl": [attempt["replay"] for attempt in attempts],
        "consumption-summary.json": {
            "schema": SPEND_LOOP_CONSUMPTION_SUMMARY_SCHEMA,
            "lane": "loop",
            "summary": signed_summary(
                consumption_payload, runtime.consumption_signer, "consumption-summary"
            ),
        },
        "spend-store-summary.json": {
            "schema": SPEND_LOOP_STORE_SUMMARY_SCHEMA,
            "lane": "loop",
            "summary": signed_summary(
                cast(dict[str, Any], captured["spend"]), runtime.spend_signer, "spend-summary"
            ),
        },
        "fixture-journal.jsonl": [
            {
                "record_id": f"journal-loop-{index:02d}",
                "lane": f"loop-{index:02d}",
                "event": event,
            }
            for index, event in enumerate(cast(list[dict[str, Any]], captured["journal"]), start=1)
        ],
        "protocol-results.jsonl": [attempt["protocol"] for attempt in attempts],
    }
    payloads = SpendProofPayloads.from_values(values)
    trust = {"schema": SPEND_LOOP_TRUST_SCHEMA, "lanes": {"loop": trust_lane}}
    entries = SPEND_PROOF_CODEC.manifest_entries(payloads.files)
    predicted = SPEND_PROOF_CODEC.pack_digest(SPEND_PROOF_CODEC.manifest_payload(entries))
    envelope_payloads = {
        "trust-bundle.json": SPEND_PROOF_ENVELOPE_CODEC.json_bytes(trust),
        "expected-pack-digest.json": SPEND_PROOF_ENVELOPE_CODEC.json_bytes(
            {"schema": SPEND_EXPECTED_DIGEST_SCHEMA, "pack_digest": predicted}
        ),
    }
    if commit_guard is not None:
        commit_guard("before-pack-commit")
    pack = _export_spend_pack_with_capabilities(
        pack_output,
        payloads,
        open_directory=opener,
        assert_path_identity=assert_identity,
    )
    if commit_guard is not None:
        commit_guard("pack-committed")
    if pack.pack_digest != predicted:
        raise SpendProofError("committed spend loop pack digest differs from preflight")
    _manifest, envelope_digest = SPEND_PROOF_ENVELOPE_CODEC.export_new_pack(
        Path(envelope_output),
        envelope_payloads,
        open_directory=opener,
        assert_path_identity=assert_identity,
    )
    if commit_guard is not None:
        commit_guard("envelope-committed")
    verified = verify_exported_spend_proof(
        pack.directory,
        envelope_output,
        expected_envelope_digest=envelope_digest,
        output_capability=output_capability,
    )
    if not hmac.compare_digest(verified, pack.pack_digest):
        raise SpendProofError("offline verified digest differs from committed spend loop pack")
    if commit_guard is not None:
        commit_guard("verified")
    if output_capability is not None:
        output_directory = require_attested_directory(
            output_capability,
            error_type=SpendProofError,
        )
        output_directory.checkpoint()
        output_directory.assert_path_identity(
            output_directory.display_path,
            output_directory.identity,
        )
    if runtime_capability is not None:
        runtime_directory = require_attested_directory(
            runtime_capability,
            error_type=SpendProofError,
        )
        runtime_directory.checkpoint()
        runtime_directory.assert_path_identity(
            runtime_directory.display_path,
            runtime_directory.identity,
        )
    return SpendGenuineProofExport(
        pack.directory, pack.pack_digest, Path(envelope_output), envelope_digest
    )


def verify_exported_spend_proof(
    pack: str | Path,
    envelope: str | Path,
    *,
    expected_envelope_digest: str,
    output_capability: AttestedDirectory | None = None,
) -> str:
    if type(expected_envelope_digest) is not str or len(expected_envelope_digest) != 64:
        raise SpendProofError("expected envelope digest must be lowercase SHA-256")
    opener: OpenDirectory | None = None
    assert_identity: Callable[[Path, DirectoryIdentity], None] | None = None
    if output_capability is not None:
        capability = require_attested_directory(output_capability, error_type=SpendProofError)
        capability.checkpoint()
        capability.relative_from_display(pack)
        capability.relative_from_display(envelope)
        opener = capability.open_directory_path
        assert_identity = capability.assert_path_identity
    raw = SPEND_PROOF_ENVELOPE_CODEC.read_exact_pack(
        Path(envelope),
        open_directory=opener,
        assert_path_identity=assert_identity,
    )
    manifest = SPEND_PROOF_ENVELOPE_CODEC.strict_json(raw["manifest.json"], "manifest.json")
    if type(manifest) is not dict or type(manifest.get("pack_digest")) is not str:
        raise SpendProofError("verification envelope manifest is incompatible")
    if not hmac.compare_digest(cast(str, manifest["pack_digest"]), expected_envelope_digest):
        raise SpendProofError("external expected envelope digest mismatch")
    expected = SPEND_PROOF_ENVELOPE_CODEC.strict_json(
        raw["expected-pack-digest.json"], "expected-pack-digest.json"
    )
    if (
        type(expected) is not dict
        or set(expected) != {"schema", "pack_digest"}
        or expected["schema"] != SPEND_EXPECTED_DIGEST_SCHEMA
    ):
        raise SpendProofError("expected pack digest envelope member is incompatible")
    return _verify_with_trust_bytes(
        pack,
        trust_bundle_bytes=raw["trust-bundle.json"],
        expected_pack_digest=cast(str, expected["pack_digest"]),
        open_directory=opener,
        assert_path_identity=assert_identity,
    )


def replay_exported_spend_proof(
    pack: str | Path,
    envelope: str | Path,
    *,
    expected_envelope_digest: str,
    output_capability: AttestedDirectory | None = None,
) -> str:
    return verify_exported_spend_proof(
        pack,
        envelope,
        expected_envelope_digest=expected_envelope_digest,
        output_capability=output_capability,
    )


__all__ = [
    "SPEND_EXPECTED_DIGEST_SCHEMA",
    "SPEND_PROOF_ENVELOPE_CODEC",
    "SPEND_PROOF_ENVELOPE_SCHEMA",
    "SpendGenuineProofExport",
    "export_genuine_spend_proof",
    "export_spend_loop_disaster_proof",
    "replay_exported_spend_proof",
    "verify_exported_spend_proof",
]
