"""Cross-plane proof for managed policy sync and native local execution."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from typing import Any, cast

import pytest
import sqlalchemy as sa
from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.migrations import upgrade_database
from acgs_control_plane.models import (
    Environment,
    ManagedDecisionReceipt,
    Project,
    RuntimeCredentialGeneration,
    RuntimeIdentity,
    RuntimeIdentityGate,
    new_id,
    utcnow,
)
from acgs_control_plane.policy_registry import (
    POLICY_ENVELOPE_PURPOSE,
    bootstrap_local_policy_registry_trust,
    local_policy_registry_issuer,
)
from acgs_control_plane.policy_sync import (
    POLICY_SYNC_ATTESTATION_PURPOSE,
    local_policy_sync_attestation_issuer,
)
from acgs_control_plane.runtime_enrollment import RUNTIME_ENROLLMENT_AUTHORITY
from acgs_control_plane.tenant_bootstrap import BOOTSTRAP_IDEMPOTENCY_HEADER
from acgs_control_plane.trust import ManagedTrustLifecycleService, public_spki_der_from_signer
from fastapi.testclient import TestClient
from gove_zone import ChainHashAuditStore, Kernel
from gove_zone.errors import (
    DeniedError,
    ProductionProfileError,
    ReceiptAlreadyUsedError,
    ReceiptValidationError,
)
from gove_zone.executor import execute_with_receipt
from gove_zone.gateway import ScopedDecisionReceiptConfig, UniversalGateway
from gove_zone.policy_sync import (
    AtomicJsonPolicyCache,
    ManagedPolicyProvenance,
    PolicySyncClient,
    PolicySyncError,
    PolicySyncSnapshot,
    SyncedRuleSetPolicy,
)
from gove_zone.profile import GovernanceProfile
from gove_zone.receipt import Validator
from gove_zone.runtime_identity import (
    GateScope,
    InMemoryEd25519WorkloadKeyProvider,
    RuntimeHttpRequest,
    RuntimeHttpResponse,
    RuntimeIdentityDescriptor,
    SignedRequestClient,
    public_key_thumbprint,
)
from gove_zone.signing import Ed25519Signer
from gove_zone.trust import (
    DECISION_RECEIPT_PURPOSE,
    RECEIPT_V2,
    ReceiptTrustScope,
    StaticReceiptTrustRegistry,
    TrustConfigurationError,
    TrustedReceiptKey,
)

BOOTSTRAP_TOKEN = "policy-sync-integration-bootstrap"


def test_authenticated_sync_executes_native_allow_once_and_denies_locally(
    tmp_path: Path,
) -> None:
    integrated = _integrated_runtime(tmp_path)
    cache, sync_client, transport_calls, transport_responses = _sync_runtime(
        integrated, tmp_path / "runtime-cache" / "policy.json"
    )
    snapshot = cast(PolicySyncSnapshot, cache.snapshot)
    first_bytes = cache.path.read_bytes()

    assert len(transport_calls) == 1
    assert transport_calls[0].method == "GET"
    assert transport_calls[0].path.endswith("/policy-bundle")
    assert transport_calls[0].query == ""
    assert transport_responses[0].status_code == 200
    assert snapshot.policy_version_id == integrated["policy_version_id"]
    assert snapshot.activation_receipt_id == integrated["activation_receipt_id"]

    # Exact authenticated cursor replay is a 304 and cannot refresh the LKG.
    assert not sync_client.sync(now=utcnow())
    assert transport_calls[-1].query == f"cursor={snapshot.cursor}"
    assert transport_responses[-1].status_code == 304
    assert transport_responses[-1].body == b""
    assert cache.path.read_bytes() == first_bytes
    assert cache.snapshot is snapshot

    effects: list[str] = []
    gateway = _gateway(integrated, cache, tmp_path / "native", effects)
    local_transport_count = len(transport_calls)

    allowed = gateway.invoke(integrated["identity_id"], "safe.read", {})
    assert allowed.status == "executed"
    assert allowed.result == "ok"
    assert allowed.assurance_class == "native"
    assert effects == ["safe.read"]
    assert allowed.receipt is not None
    receipt = allowed.receipt
    with cache.receipt_binding_scope(now=utcnow()) as provenance:
        assert isinstance(provenance, ManagedPolicyProvenance)
    expected_constraints = {
        "schema": "acgs.managed-policy-execution/v1",
        "policy_provenance": provenance.to_dict(),
        "policy_provenance_hash": provenance.compute_hash(),
    }
    assert receipt.receipt_schema_version == RECEIPT_V2
    assert receipt.tenant_id == integrated["org_id"]
    assert receipt.project_id == integrated["project_id"]
    assert receipt.environment_id == integrated["environment_id"]
    assert receipt.execution_boundary == integrated["gate_id"]
    assert receipt.policy_bundle_id == snapshot.policy_version_id
    assert receipt.policy_hash == snapshot.content_hash
    assert receipt.constraints == expected_constraints
    assert receipt.constraints["policy_provenance"] == {
        "scope": snapshot.scope.to_dict(),
        "runtime_identity_id": snapshot.runtime_identity_id,
        "credential_id": snapshot.credential_id,
        "credential_generation": snapshot.credential_generation,
        "cursor": snapshot.cursor,
        "head_generation": snapshot.head_generation,
        "head_updated_at": snapshot.head_updated_at,
        "policy_version_id": snapshot.policy_version_id,
        "policy_id": snapshot.policy_id,
        "version": snapshot.version,
        "content_hash": snapshot.content_hash,
        "activation_receipt_id": snapshot.activation_receipt_id,
        "activation_receipt_hash": snapshot.activation_receipt_hash,
        "activation_event_hash": snapshot.activation_event_hash,
        "policy_sync_schema": snapshot.schema,
        "policy_sync_purpose": snapshot.purpose,
        "policy_trust_purpose": POLICY_ENVELOPE_PURPOSE,
        "policy_trust_epoch": snapshot.policy_envelope["trust_epoch"],
        "policy_key_id": snapshot.policy_envelope["key_id"],
        "policy_signature_algorithm": snapshot.policy_envelope["signature_algorithm"],
        "policy_key_fingerprint": provenance.policy_key_fingerprint,
        "attestation_purpose": snapshot.attestation_purpose,
        "attestation_trust_epoch": snapshot.attestation_trust_epoch,
        "attestation_key_id": snapshot.attestation_key_id,
        "attestation_signature_algorithm": snapshot.attestation_signature_algorithm,
        "attestation_key_fingerprint": provenance.attestation_key_fingerprint,
        "signed_snapshot_hash": provenance.signed_snapshot_hash,
    }

    denied = gateway.invoke(integrated["identity_id"], "dangerous.delete", {})
    assert denied.status == "denied"
    assert denied.receipt is None
    assert effects == ["safe.read"]
    assert len(transport_calls) == local_transport_count

    with pytest.raises(ReceiptAlreadyUsedError):
        execute_with_receipt(
            tool_fn=lambda: pytest.fail("replayed managed receipt executed"),
            args={},
            receipt=receipt,
            expected_tenant_id=integrated["org_id"],
            expected_execution_boundary=integrated["gate_id"],
            expected_action="safe.read",
            expected_actor=integrated["identity_id"],
            expected_audit_hash=allowed.audit_hash,
            expected_policy_hash=snapshot.content_hash,
            expected_policy_bundle_id=snapshot.policy_version_id,
            expected_constraints=expected_constraints,
            expected_project_id=integrated["project_id"],
            expected_environment_id=integrated["environment_id"],
            trust_registry=integrated["trust_registry"],
            consumption_ledger=gateway._ledger,
        )
    assert effects == ["safe.read"]

    with pytest.raises(ReceiptValidationError):
        execute_with_receipt(
            tool_fn=lambda: pytest.fail("constraint-mismatched receipt executed"),
            args={},
            receipt=receipt,
            expected_tenant_id=integrated["org_id"],
            expected_execution_boundary=integrated["gate_id"],
            expected_action="safe.read",
            expected_actor=integrated["identity_id"],
            expected_audit_hash=allowed.audit_hash,
            expected_policy_hash=snapshot.content_hash,
            expected_policy_bundle_id=snapshot.policy_version_id,
            expected_constraints={**expected_constraints, "schema": "wrong"},
            expected_project_id=integrated["project_id"],
            expected_environment_id=integrated["environment_id"],
            trust_registry=integrated["trust_registry"],
            consumption_ledger=gateway._ledger,
        )
    assert effects == ["safe.read"]
    assert len(transport_calls) == local_transport_count


def test_invalid_cache_scope_trust_generation_cursor_and_expiry_execute_zero(
    tmp_path: Path,
) -> None:
    integrated = _integrated_runtime(tmp_path)
    cache, _, transport_calls, _ = _sync_runtime(
        integrated, tmp_path / "valid-cache" / "policy.json"
    )
    snapshot = cast(PolicySyncSnapshot, cache.snapshot)
    effects: list[str] = []
    local_transport_count = len(transport_calls)

    expired_gateway = _gateway(
        integrated,
        cache,
        tmp_path / "expired",
        effects,
        clock=lambda: _parse_timestamp(snapshot.expires_at),
    )
    assert expired_gateway.invoke(integrated["identity_id"], "safe.read", {}).status == "denied"
    assert effects == []

    cache.path.write_text("{}\n", encoding="utf-8")
    tampered_gateway = _gateway(integrated, cache, tmp_path / "tampered", effects)
    assert tampered_gateway.invoke(integrated["identity_id"], "safe.read", {}).status == "denied"
    assert effects == []

    invalid_cases = {
        "wrong-scope": replace(
            snapshot,
            scope=replace(snapshot.scope, gate_id=f"wrong-{integrated['gate_id']}"),
        ),
        "wrong-credential-generation": replace(
            snapshot, credential_generation=snapshot.credential_generation + 1
        ),
        "wrong-cursor": replace(snapshot, cursor="not-a-policy-sync-cursor"),
    }
    for name, invalid_snapshot in invalid_cases.items():
        _assert_uninstallable_snapshot_executes_zero(
            integrated,
            invalid_snapshot,
            integrated["trust_registry"],
            tmp_path / name,
            effects,
        )

    wrong_trust = StaticReceiptTrustRegistry(
        [
            _trusted_key(
                integrated,
                integrated["receipt_signer"],
                DECISION_RECEIPT_PURPOSE,
            )
        ]
    )
    _assert_uninstallable_snapshot_executes_zero(
        integrated,
        snapshot,
        wrong_trust,
        tmp_path / "wrong-trust",
        effects,
    )
    assert effects == []
    assert len(transport_calls) == local_transport_count


def test_cache_replacement_waits_for_native_execution_and_rollback_executes_zero(
    tmp_path: Path,
) -> None:
    integrated = _integrated_runtime(tmp_path)
    cache, _, transport_calls, _ = _sync_runtime(
        integrated, tmp_path / "runtime-cache" / "policy.json"
    )
    first_snapshot = cast(PolicySyncSnapshot, cache.snapshot)
    _publish_and_activate(
        integrated,
        rules=[{"id": "deny-other-v2", "effect": "deny", "tools": ["other.tool"]}],
        expected_generation=1,
        suffix="v2",
    )
    next_cache, _, _, _ = _sync_runtime(integrated, tmp_path / "next-cache" / "policy.json")
    next_snapshot = cast(PolicySyncSnapshot, next_cache.snapshot)
    assert next_snapshot.head_generation == first_snapshot.head_generation + 1

    effects: list[str] = []
    entered = Event()
    release = Event()
    gateway = _gateway(
        integrated,
        cache,
        tmp_path / "leased",
        effects,
        entered=entered,
        release=release,
    )
    competing = AtomicJsonPolicyCache(
        cache.path,
        descriptor=integrated["descriptor"],
        trust_registry=integrated["trust_registry"],
    )
    local_transport_count = len(transport_calls)

    with ThreadPoolExecutor(max_workers=2) as executor:
        invocation = executor.submit(gateway.invoke, integrated["identity_id"], "safe.read", {})
        assert entered.wait(timeout=2)
        replacement = executor.submit(competing.install, next_snapshot, now=utcnow())
        assert not replacement.done()
        assert effects == ["safe.read"]
        release.set()
        result = invocation.result(timeout=3)
        assert result.status == "executed"
        assert result.assurance_class == "native"
        assert replacement.result(timeout=3)

    assert effects == ["safe.read"]
    assert len(transport_calls) == local_transport_count
    with pytest.raises(PolicySyncError):
        competing.install(first_snapshot, now=utcnow())
    assert effects == ["safe.read"]


def test_managed_gateway_rejects_decision_key_spki_aliases_before_effect(
    tmp_path: Path,
) -> None:
    integrated = _integrated_runtime(tmp_path)
    cache, _, transport_calls, _ = _sync_runtime(
        integrated, tmp_path / "alias-cache" / "policy.json"
    )
    effects: list[str] = []
    local_transport_count = len(transport_calls)

    for name, aliased_signer in (
        ("publisher-alias", integrated["policy_signer"]),
        ("attestation-alias", integrated["attestation_signer"]),
    ):
        alias_registry = StaticReceiptTrustRegistry(
            [
                _trusted_key(
                    integrated,
                    integrated["policy_signer"],
                    POLICY_ENVELOPE_PURPOSE,
                ),
                _trusted_key(
                    integrated,
                    integrated["attestation_signer"],
                    POLICY_SYNC_ATTESTATION_PURPOSE,
                ),
                _trusted_key(integrated, aliased_signer, DECISION_RECEIPT_PURPOSE),
            ]
        )
        gateway = _gateway(
            integrated,
            cache,
            tmp_path / name,
            effects,
            receipt_signer=aliased_signer,
            trust_registry=alias_registry,
        )
        with pytest.raises(
            ProductionProfileError,
            match="managed execution requires three distinct physical trust keys",
        ):
            gateway.invoke(integrated["identity_id"], "safe.read", {})
        assert effects == []
        assert len(transport_calls) == local_transport_count


def test_kernel_dispatch_denies_even_inside_public_cache_binding(tmp_path: Path) -> None:
    integrated = _integrated_runtime(tmp_path)
    cache, _, transport_calls, _ = _sync_runtime(
        integrated, tmp_path / "legacy-cache" / "policy.json"
    )
    effects: list[str] = []
    kernel = Kernel(
        policy=SyncedRuleSetPolicy(cache, clock=utcnow),
        audit=ChainHashAuditStore(tmp_path / "legacy-audit.jsonl"),
        actor=integrated["identity_id"],
    )

    @kernel.tool("safe.read")
    def safe_read() -> str:
        effects.append("safe.read")
        return "ok"

    local_transport_count = len(transport_calls)
    with pytest.raises(DeniedError, match="local signed policy is unavailable or invalid"):
        kernel.dispatch("safe.read")
    assert effects == []

    with cache.receipt_binding_scope(now=utcnow()):
        with pytest.raises(DeniedError, match="local signed policy is unavailable or invalid"):
            kernel.dispatch("safe.read")
    assert effects == []
    assert len(transport_calls) == local_transport_count


def _integrated_runtime(tmp_path: Path) -> dict[str, Any]:
    database_url = f"sqlite:///{tmp_path / 'control-plane.sqlite3'}"
    upgrade_database(database_url)
    descriptor_signer = InMemoryEd25519WorkloadKeyProvider(key_id="descriptor-key")
    policy_registry_issuer = local_policy_registry_issuer()
    attestation_issuer = local_policy_sync_attestation_issuer()
    assert policy_registry_issuer is not attestation_issuer
    assert policy_registry_issuer.key_id != attestation_issuer.key_id
    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=tmp_path / "control-plane-audit",
            bootstrap_token=BOOTSTRAP_TOKEN,
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        ),
        policy_registry_issuer=policy_registry_issuer,
        policy_sync_attestation_issuer=attestation_issuer,
        runtime_descriptor_signer=descriptor_signer,
    )
    client = TestClient(app, raise_server_exceptions=False)
    org_response = client.post(
        "/orgs",
        json={
            "name": "Policy Sync Integration",
            "admin_name": "Integration Admin",
            "admin_email": "integration@example.com",
        },
        headers={"X-Bootstrap-Token": BOOTSTRAP_TOKEN},
    )
    assert org_response.status_code == 201, org_response.text
    org_payload = org_response.json()
    org_id = str(org_payload["org_id"])
    admin_api_key = str(org_payload["admin_api_key"])
    now = utcnow()
    project_id = f"project-{new_id()}"
    environment_id = f"environment-{new_id()}"
    gate_id = f"gate-{new_id()}"
    identity_id = f"runtime-{new_id()}"
    credential_id = f"credential-{new_id()}"
    workload_key = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-workload-key")
    descriptor = RuntimeIdentityDescriptor.issue(
        scope=GateScope(org_id, project_id, environment_id, gate_id),
        runtime_identity_id=identity_id,
        credential_id=credential_id,
        credential_generation=1,
        workload_public_key=workload_key.public_key_bytes(),
        issuer="acgs-control-plane",
        audience=RUNTIME_ENROLLMENT_AUTHORITY,
        issued_at=_timestamp(now),
        expires_at=_timestamp(now + timedelta(hours=1)),
        signer=descriptor_signer,
    )
    with app.state.session_factory.begin() as session:
        session.add_all(
            [
                Project(id=project_id, org_id=org_id, slug="policy-sync", name="Policy Sync"),
                Environment(
                    id=environment_id,
                    org_id=org_id,
                    project_id=project_id,
                    slug="production",
                    name="Production",
                ),
            ]
        )
        session.flush()
        bootstrap_local_policy_registry_trust(
            session,
            org_id=org_id,
            project_id=project_id,
            environment_id=environment_id,
            issuer=policy_registry_issuer,
        )
        attestation_scope = ReceiptTrustScope(
            org_id,
            project_id,
            environment_id,
            POLICY_SYNC_ATTESTATION_PURPOSE,
        )
        attestation_signer = attestation_issuer.signer_for_scope(attestation_scope, trust_epoch=1)
        ManagedTrustLifecycleService(session).bootstrap(
            scope=attestation_scope,
            key_id=attestation_signer.key_id,
            algorithm=attestation_signer.algorithm,
            public_key_spki_der=public_spki_der_from_signer(attestation_signer),
            not_after=now + timedelta(days=7),
        )
        session.add_all(
            [
                RuntimeIdentityGate(
                    id=gate_id,
                    org_id=org_id,
                    project_id=project_id,
                    environment_id=environment_id,
                    status="active",
                ),
                RuntimeIdentity(
                    id=identity_id,
                    org_id=org_id,
                    project_id=project_id,
                    environment_id=environment_id,
                    gate_id=gate_id,
                    name="Integrated Runtime",
                    actor=f"runtime:{identity_id}",
                    workload_key_id=workload_key.key_id,
                    public_key=descriptor.public_key,
                    public_key_thumbprint=public_key_thumbprint(workload_key.public_key_bytes()),
                    descriptor=descriptor.to_dict(),
                    status="active",
                    current_generation=1,
                ),
                RuntimeCredentialGeneration(
                    id=credential_id,
                    org_id=org_id,
                    project_id=project_id,
                    environment_id=environment_id,
                    identity_id=identity_id,
                    generation=1,
                    workload_key_id=workload_key.key_id,
                    public_key_thumbprint=public_key_thumbprint(workload_key.public_key_bytes()),
                    not_before=now - timedelta(minutes=1),
                    not_after=now + timedelta(hours=1),
                    status="active",
                    descriptor=descriptor.to_dict(),
                ),
            ]
        )

    integrated: dict[str, Any] = {
        "app": app,
        "client": client,
        "org_id": org_id,
        "admin_api_key": admin_api_key,
        "project_id": project_id,
        "environment_id": environment_id,
        "gate_id": gate_id,
        "identity_id": identity_id,
        "credential_id": credential_id,
        "descriptor": descriptor,
        "workload_key": workload_key,
    }
    activated = _publish_and_activate(
        integrated,
        rules=[{"id": "deny-dangerous-delete", "effect": "deny", "tools": ["dangerous.delete"]}],
        expected_generation=0,
        suffix="v1",
    )
    policy_scope = ReceiptTrustScope(org_id, project_id, environment_id, POLICY_ENVELOPE_PURPOSE)
    policy_signer = policy_registry_issuer.signer_for_scope(policy_scope, trust_epoch=1)
    receipt_signer = Ed25519Signer.generate(key_id="decision-receipt-key")
    trust_signers = (policy_signer, attestation_signer, receipt_signer)
    assert len({signer.key_id for signer in trust_signers}) == len(trust_signers)
    assert len({public_spki_der_from_signer(signer) for signer in trust_signers}) == len(
        trust_signers
    )
    integrated.update(
        {
            **activated,
            "policy_signer": policy_signer,
            "attestation_signer": attestation_signer,
            "receipt_signer": receipt_signer,
        }
    )
    integrated["trust_registry"] = StaticReceiptTrustRegistry(
        [
            _trusted_key(integrated, policy_signer, POLICY_ENVELOPE_PURPOSE),
            _trusted_key(
                integrated,
                attestation_signer,
                POLICY_SYNC_ATTESTATION_PURPOSE,
            ),
            _trusted_key(integrated, receipt_signer, DECISION_RECEIPT_PURPOSE),
        ]
    )
    with app.state.session_factory() as session:
        receipt = session.scalars(
            sa.select(ManagedDecisionReceipt).where(
                ManagedDecisionReceipt.receipt_id == integrated["activation_receipt_id"]
            )
        ).one()
        assert receipt.proposed_action == "control-plane.policy.activate"
    return integrated


def _publish_and_activate(
    integrated: dict[str, Any],
    *,
    rules: list[dict[str, Any]],
    expected_generation: int,
    suffix: str,
) -> dict[str, str]:
    client = cast(TestClient, integrated["client"])
    org_id = integrated["org_id"]
    project_id = integrated["project_id"]
    environment_id = integrated["environment_id"]
    policy_id = f"runtime-policy-{suffix}-{new_id()}"
    published = client.post(
        f"/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/policies",
        json={"policy_id": policy_id, "rules": rules},
        headers={
            "X-API-Key": integrated["admin_api_key"],
            BOOTSTRAP_IDEMPOTENCY_HEADER: f"policy-sync-publish-{suffix}-{new_id()}",
        },
    )
    assert published.status_code == 201, published.text
    policy_version_id = str(published.json()["bundle_id"])
    activated = client.post(
        f"/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/policies/"
        f"{policy_version_id}/activate",
        json={"expected_generation": expected_generation},
        headers={
            "X-API-Key": integrated["admin_api_key"],
            BOOTSTRAP_IDEMPOTENCY_HEADER: f"policy-sync-activate-{suffix}-{new_id()}",
        },
    )
    assert activated.status_code == 200, activated.text
    return {
        "policy_version_id": policy_version_id,
        "activation_receipt_id": str(activated.json()["receipt_id"]),
    }


def _sync_runtime(
    integrated: dict[str, Any], cache_path: Path
) -> tuple[
    AtomicJsonPolicyCache,
    PolicySyncClient,
    list[RuntimeHttpRequest],
    list[RuntimeHttpResponse],
]:
    cache = AtomicJsonPolicyCache(
        cache_path,
        descriptor=integrated["descriptor"],
        trust_registry=integrated["trust_registry"],
    )
    calls: list[RuntimeHttpRequest] = []
    responses: list[RuntimeHttpResponse] = []
    signed_client = SignedRequestClient(
        descriptor=integrated["descriptor"],
        key_provider=integrated["workload_key"],
        transport=_test_client_transport(integrated["client"], calls, responses),
        audience=RUNTIME_ENROLLMENT_AUTHORITY,
    )
    sync_client = PolicySyncClient(signed_client=signed_client, cache=cache)
    assert sync_client.sync(now=utcnow())
    return cache, sync_client, calls, responses


def _gateway(
    integrated: dict[str, Any],
    cache: AtomicJsonPolicyCache,
    state_root: Path,
    effects: list[str],
    *,
    clock: Any = utcnow,
    entered: Event | None = None,
    release: Event | None = None,
    receipt_signer: Ed25519Signer | None = None,
    trust_registry: StaticReceiptTrustRegistry | None = None,
) -> UniversalGateway:
    effective_receipt_signer = receipt_signer or integrated["receipt_signer"]
    effective_trust_registry = trust_registry or integrated["trust_registry"]
    gateway = UniversalGateway(
        tenant_id=integrated["org_id"],
        execution_boundary=integrated["gate_id"],
        policy=SyncedRuleSetPolicy(cache, clock=clock),
        profile=GovernanceProfile.production(signer=effective_receipt_signer),
        validator=Validator("policy-sync-validator"),
        authority="policy-sync-integration",
        receipt_ttl_seconds=60,
        scoped_receipt_config=ScopedDecisionReceiptConfig(
            project_id=integrated["project_id"],
            environment_id=integrated["environment_id"],
            gate_id=integrated["gate_id"],
            trust_epoch=1,
            trust_registry=effective_trust_registry,
        ),
        audit_path=state_root / "audit.jsonl",
        ledger_path=state_root / "ledger.jsonl",
    )

    def safe_read() -> str:
        effects.append("safe.read")
        if entered is not None:
            entered.set()
        if release is not None:
            assert release.wait(timeout=3)
        return "ok"

    gateway.register_tool("safe.read", safe_read)
    gateway.register_tool(
        "dangerous.delete", lambda: effects.append("dangerous.delete") or "deleted"
    )
    return gateway


def _assert_uninstallable_snapshot_executes_zero(
    integrated: dict[str, Any],
    snapshot: PolicySyncSnapshot,
    trust_registry: StaticReceiptTrustRegistry,
    state_root: Path,
    effects: list[str],
) -> None:
    cache = AtomicJsonPolicyCache(
        state_root / "policy.json",
        descriptor=integrated["descriptor"],
        trust_registry=trust_registry,
    )
    with pytest.raises((PolicySyncError, TrustConfigurationError)):
        cache.install(snapshot, now=utcnow())
    gateway = _gateway(integrated, cache, state_root / "gateway", effects)
    assert gateway.invoke(integrated["identity_id"], "safe.read", {}).status == "denied"
    assert effects == []


def _trusted_key(
    integrated: dict[str, Any], signer: Ed25519Signer, purpose: str
) -> TrustedReceiptKey:
    return TrustedReceiptKey(
        scope=ReceiptTrustScope(
            integrated["org_id"],
            integrated["project_id"],
            integrated["environment_id"],
            purpose,
        ),
        key_id=signer.key_id,
        algorithm=signer.algorithm,
        public_key_spki_der=public_spki_der_from_signer(signer),
        activated_epoch=1,
        not_after=_timestamp(utcnow() + timedelta(hours=1)),
    )


def _test_client_transport(
    client: TestClient,
    calls: list[RuntimeHttpRequest],
    responses: list[RuntimeHttpResponse],
) -> Any:
    def transport(request: RuntimeHttpRequest) -> RuntimeHttpResponse:
        calls.append(request)
        response = client.request(
            request.method,
            request.path + (f"?{request.query}" if request.query else ""),
            content=request.body,
            headers=dict(request.headers),
        )
        runtime_response = RuntimeHttpResponse(
            status_code=response.status_code,
            body=response.content,
            headers=dict(response.headers),
        )
        responses.append(runtime_response)
        return runtime_response

    return transport


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
