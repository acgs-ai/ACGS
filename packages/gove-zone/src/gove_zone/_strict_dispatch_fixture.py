"""Local-only strict dispatcher wiring for deterministic tests and demos."""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from gove_zone.audit import AuditCheckpoint, AuditCheckpointAnchor, ChainHashAuditStore
from gove_zone.authorization import (
    EvidenceRef,
    PolicyArtifactAttestation,
    ResolvedPolicy,
    ResolvedPolicyRef,
    SideEffectExecutionContext,
    SideEffectRequest,
    VerifiedPrincipal,
)
from gove_zone.consumption import (
    AnchoredConsumptionState,
    ConsumptionStateAnchor,
    ReceiptConsumptionStore,
)
from gove_zone.decision import Decision, DecisionRecord
from gove_zone.managed_execution import (
    ManagedExecutionDispatcher,
    ManagedExecutionInputs,
    ManagedExecutionProposal,
    ManagedExecutionRoute,
)
from gove_zone.policy import Policy, PolicyArtifactSnapshot, new_event_id
from gove_zone.receipt import Validator
from gove_zone.side_effect_kernel import (
    ReceiptGatedSideEffectExecutor,
    SideEffectAuthorizationKernel,
)
from gove_zone.signing import Ed25519Signer
from gove_zone.tool import ToolCall

_BINDING_KEY = b"strict-fixture-binding-key-32bytes!!"
_CONSUMPTION_KEY = b"strict-fixture-consumption-key-32b"


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class _FixturePolicy(Policy):
    def __init__(self, decision: Decision) -> None:
        self.decision = decision

    @property
    def version(self) -> str:
        return "strict-fixture-policy/v1"

    def authorization_snapshot(self) -> PolicyArtifactSnapshot:
        return PolicyArtifactSnapshot.from_artifact(
            {"decision": self.decision.value, "version": self.version},
            evaluator=_FixturePolicy(self.decision),
        )

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=self.decision,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("STRICT_FIXTURE_POLICY",),
            reason="strict fixture decision",
        )


class _SnapshotPolicy(Policy):
    def __init__(self, policy: Policy, artifact: Mapping[str, Any]) -> None:
        self.policy = policy
        self.artifact = dict(artifact)

    @property
    def version(self) -> str:
        return self.policy.version

    def authorization_snapshot(self) -> PolicyArtifactSnapshot:
        return PolicyArtifactSnapshot.from_artifact(
            self.artifact,
            evaluator=_SnapshotPolicy(self.policy, self.artifact),
        )

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return self.policy.evaluate(call)


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
            raise ValueError("fixture principal tenant does not match policy")
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


class _Provider:
    def __init__(
        self,
        *,
        now: datetime,
        principal: VerifiedPrincipal,
        policy_ref: ResolvedPolicyRef,
    ) -> None:
        self.now = now
        self.principal = principal
        self.policy_ref = policy_ref
        self.counter = 0

    def prepare(
        self,
        proposal: ManagedExecutionProposal,
        route: ManagedExecutionRoute,
    ) -> ManagedExecutionInputs:
        self.counter += 1
        request_id = f"strict-fixture-request-{self.counter}"
        request = SideEffectRequest(
            request_id=request_id,
            tenant_id=self.principal.tenant_id,
            actor_id=self.principal.actor_id,
            actor_role=self.principal.role,
            authority=self.principal.authority,
            server_id=route.server_id,
            tool=route.tool,
            operation=route.operation,
            resource=route.resource,
            environment=route.environment,
            execution_boundary=route.execution_boundary,
            policy_ref=self.policy_ref,
            requested_at=_iso(self.now - timedelta(seconds=1)),
            nonce=f"strict-fixture-nonce-{self.counter}",
            idempotency_key=f"strict-fixture-idempotency-{self.counter}",
            args=proposal.args,
            evidence=(
                EvidenceRef(
                    evidence_id=f"strict-fixture-evidence-{self.counter}",
                    evidence_type="local-fixture",
                    digest="b" * 64,
                    issuer="strict-fixture-provider",
                    issued_at=_iso(self.now - timedelta(hours=1)),
                    expires_at=_iso(self.now + timedelta(hours=1)),
                ),
            ),
            side_effect_class=route.side_effect_class,
            goal=proposal.goal,
        )
        context = SideEffectExecutionContext(
            request_id=request_id,
            tenant_id=request.tenant_id,
            actor_id=request.actor_id,
            actor_role=request.actor_role,
            authority=request.authority,
            server_id=route.server_id,
            tool=route.tool,
            operation=route.operation,
            resource=route.resource,
            environment=route.environment,
            execution_boundary=route.execution_boundary,
            policy_ref=self.policy_ref,
            observed_at=_iso(self.now + timedelta(seconds=1)),
            authentication_context=self.principal.authentication_context,
        )
        return ManagedExecutionInputs(request=request, context=context)


@dataclass(frozen=True, slots=True)
class StrictDispatchFixture:
    route: ManagedExecutionRoute
    provider: _Provider
    audit: ChainHashAuditStore
    dispatcher: ManagedExecutionDispatcher
    signer: Ed25519Signer


@dataclass(frozen=True, slots=True)
class StrictReceiptGateFixture:
    """Explicit local-only persistent state for standalone receipt-gate callers."""

    root: Path
    audit: ChainHashAuditStore
    consumption_store: ReceiptConsumptionStore
    signer: Ed25519Signer
    lifecycle_signer: Ed25519Signer

    def executor_kwargs(self) -> dict[str, Any]:
        return {
            "consumption_store": self.consumption_store,
            "rejection_audit": self.audit,
            "verifier": self.signer,
            "lifecycle_signer": self.lifecycle_signer,
            "lifecycle_authority_id": "fixture-lifecycle-validator",
        }


def build_strict_receipt_gate_fixture(
    root: str | Path,
    *,
    name: str = "standalone-receipt-gate",
    signer: Ed25519Signer | None = None,
) -> StrictReceiptGateFixture:
    """Build explicit fixture-only schema-v4 consumption and checkpoint state."""

    fixture_root = Path(root)
    fixture_root.mkdir(parents=True, exist_ok=True)
    resolved_signer = signer or Ed25519Signer.generate(f"{name}-key")
    lifecycle_signer = Ed25519Signer.generate(f"{name}-lifecycle-key")
    audit_path = fixture_root / "audit.jsonl"
    consumption_path = fixture_root / "consumption.sqlite3"
    audit = ChainHashAuditStore(
        audit_path,
        checkpoint_anchor=_AuditAnchor(),
        checkpoint_namespace=f"{name}:audit:{audit_path.resolve()}",
        checkpoint_signer=resolved_signer,
        checkpoint_verifier={resolved_signer.key_id: resolved_signer},
        require_trusted_checkpoint=True,
    )
    consumption_store = ReceiptConsumptionStore(
        consumption_path,
        hmac_key=_CONSUMPTION_KEY,
        state_anchor=_ConsumptionAnchor(),
        anchor_namespace=f"{name}:consumption:{consumption_path.resolve()}",
        require_trusted_anchor=True,
    )
    return StrictReceiptGateFixture(
        root=fixture_root,
        audit=audit,
        consumption_store=consumption_store,
        signer=resolved_signer,
        lifecycle_signer=lifecycle_signer,
    )


def build_strict_dispatch_fixture(
    root: str | Path,
    *,
    audit_path: str | Path | None = None,
    name: str = "write",
    actor: str = "fixture-agent",
    policy: Policy | None = None,
    policy_artifact: Mapping[str, Any] | None = None,
    decision: Decision = Decision.ALLOW,
    server_id: str = "fixture-server",
    tool: str = "fixture-adapter",
    operation: str = "fixture.write",
    resource: str = "fixture/resource",
    environment: str = "test",
    execution_boundary: str = "fixture-gate",
    side_effect_class: str = "fixture-write",
) -> StrictDispatchFixture:
    """Wire existing strict primitives for local deterministic execution only."""
    fixture_root = Path(root)
    fixture_root.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC).replace(microsecond=0)
    signer = Ed25519Signer.generate("strict-fixture-key")
    lifecycle_signer = Ed25519Signer.generate("strict-fixture-lifecycle-key")
    if policy is not None and policy_artifact is None:
        raise ValueError("custom fixture policy requires an explicit policy_artifact")
    resolved_policy = (
        _SnapshotPolicy(policy, policy_artifact)
        if policy is not None and policy_artifact is not None
        else _FixturePolicy(decision)
    )
    snapshot = resolved_policy.authorization_snapshot()
    policy_ref = ResolvedPolicyRef(
        tenant_id="fixture-tenant",
        bundle_id="strict-fixture-policy",
        version=snapshot.policy_version,
        digest=snapshot.digest,
    )
    principal = VerifiedPrincipal(
        tenant_id=policy_ref.tenant_id,
        actor_id=actor,
        role="agent",
        authority="fixture.execute",
        authentication_context={"method": "fixture", "audience": "strict-fixture"},
        verified_at=_iso(now - timedelta(hours=1)),
        expires_at=_iso(now + timedelta(hours=1)),
    )
    principal_resolver = _PrincipalResolver(principal)
    policy_resolver = _PolicyResolver(
        ResolvedPolicy(
            ref=policy_ref,
            policy=resolved_policy,
            attestation=PolicyArtifactAttestation(
                tenant_id=policy_ref.tenant_id,
                artifact_id=policy_ref.bundle_id,
                policy_version=policy_ref.version,
                digest=policy_ref.digest,
                resolver_id="strict-fixture-resolver",
            ),
            validator=Validator("strict-fixture-validator", "approver"),
            authority=principal.authority,
        )
    )
    resolved_audit_path = (
        Path(audit_path) if audit_path is not None else fixture_root / "audit.jsonl"
    )
    audit = ChainHashAuditStore(
        resolved_audit_path,
        checkpoint_anchor=_AuditAnchor(),
        checkpoint_namespace=f"strict-fixture-audit:{resolved_audit_path.resolve()}",
        checkpoint_signer=signer,
        checkpoint_verifier={signer.key_id: signer},
        require_trusted_checkpoint=True,
    )
    authorizer = SideEffectAuthorizationKernel(
        principal_resolver=principal_resolver,
        policy_resolver=policy_resolver,
        audit=audit,
        signer=signer,
        binding_hmac_key=_BINDING_KEY,
        allowed_validator_roles=("approver",),
        clock=lambda: now,
    )
    consumption_path = fixture_root / "consumption.sqlite3"
    executor = ReceiptGatedSideEffectExecutor(
        principal_resolver=principal_resolver,
        policy_resolver=policy_resolver,
        audit=audit,
        consumption_store=ReceiptConsumptionStore(
            consumption_path,
            hmac_key=_CONSUMPTION_KEY,
            state_anchor=_ConsumptionAnchor(),
            anchor_namespace=f"strict-fixture-consumption:{consumption_path.resolve()}",
            require_trusted_anchor=True,
        ),
        verifier=signer,
        lifecycle_signer=lifecycle_signer,
        lifecycle_authority_id="fixture-lifecycle-validator",
        binding_hmac_key=_BINDING_KEY,
        allowed_validator_roles=("approver",),
        clock=lambda: now + timedelta(seconds=1),
    )
    route = ManagedExecutionRoute(
        name=name,
        server_id=server_id,
        tool=tool,
        operation=operation,
        resource=resource,
        environment=environment,
        execution_boundary=execution_boundary,
        side_effect_class=side_effect_class,
    )
    provider = _Provider(now=now, principal=principal, policy_ref=policy_ref)
    dispatcher = ManagedExecutionDispatcher(
        routes=(route,),
        provider=provider,
        authorizer=authorizer,
        executor=executor,
    )
    return StrictDispatchFixture(
        route=route,
        provider=provider,
        audit=audit,
        dispatcher=dispatcher,
        signer=signer,
    )
