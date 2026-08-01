from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import gove_zone
import gove_zone.policy_sync as policy_sync_module

cryptography = pytest.importorskip("cryptography")
del cryptography

from cryptography.hazmat.primitives import serialization  # noqa: E402

from gove_zone.decision import Decision, canonical_json, sha256_json  # noqa: E402
from gove_zone.errors import ProductionProfileError, ReceiptAlreadyUsedError  # noqa: E402
from gove_zone.executor import execute_with_receipt  # noqa: E402
from gove_zone.gateway import ScopedDecisionReceiptConfig, UniversalGateway  # noqa: E402
from gove_zone.policy import RuleSetPolicy  # noqa: E402
from gove_zone.policy_sync import (  # noqa: E402
    POLICY_ENVELOPE_PURPOSE,
    POLICY_SYNC_ATTESTATION_PURPOSE,
    AtomicJsonPolicyCache,
    PolicySyncClient,
    PolicySyncError,
    PolicySyncSnapshot,
    SyncedRuleSetPolicy,
    verify_policy_sync_snapshot,
)
from gove_zone.profile import GovernanceProfile  # noqa: E402
from gove_zone.receipt import Validator  # noqa: E402
from gove_zone.runtime_identity import (  # noqa: E402
    GateScope,
    InMemoryEd25519WorkloadKeyProvider,
    RuntimeHttpResponse,
    RuntimeIdentityDescriptor,
)
from gove_zone.signing import Ed25519Signer  # noqa: E402
from gove_zone.tool import ToolCall  # noqa: E402
from gove_zone.trust import (  # noqa: E402
    DECISION_RECEIPT_PURPOSE,
    ReceiptTrustScope,
    StaticReceiptTrustRegistry,
    TrustConfigurationError,
    TrustedReceiptKey,
)

NOW = datetime(2026, 1, 1, 0, 5, tzinfo=UTC)
SCOPE = GateScope("org-1", "project-1", "production", "gate-1")
ATTESTATION_SIGNER = Ed25519Signer.generate(key_id="attestation-key")


def _descriptor(
    *,
    credential_id: str = "credential-1",
    credential_generation: int = 3,
    issued_at: str = "2025-12-31T00:00:00Z",
    expires_at: str = "2026-02-01T00:00:00Z",
) -> RuntimeIdentityDescriptor:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    issuer = InMemoryEd25519WorkloadKeyProvider(key_id="identity-issuer")
    return RuntimeIdentityDescriptor.issue(
        scope=SCOPE,
        runtime_identity_id="runtime-1",
        credential_id=credential_id,
        credential_generation=credential_generation,
        workload_public_key=workload.public_key_bytes(),
        issuer="control-plane",
        audience="control-plane",
        issued_at=issued_at,
        expires_at=expires_at,
        signer=issuer,
    )


def _trusted_key(
    signer: Ed25519Signer,
    purpose: str,
    *,
    status: str = "active",
    activated_epoch: int = 1,
) -> TrustedReceiptKey:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    public = Ed25519PublicKey.from_public_bytes(signer.public_bytes())
    return TrustedReceiptKey(
        scope=ReceiptTrustScope("org-1", "project-1", "production", purpose),
        key_id=signer.key_id,
        algorithm=signer.algorithm,
        public_key_spki_der=public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        activated_epoch=activated_epoch,
        not_after="2027-01-01T00:00:00+00:00",
        status=status,  # type: ignore[arg-type]
        retired_epoch=activated_epoch + 1 if status == "retired" else None,
    )


def _registry(
    signer: Ed25519Signer,
    *,
    revoked: bool = False,
    attestation_signer: Ed25519Signer = ATTESTATION_SIGNER,
) -> StaticReceiptTrustRegistry:
    status = "revoked" if revoked else "active"
    return StaticReceiptTrustRegistry(
        [
            _trusted_key(signer, POLICY_ENVELOPE_PURPOSE, status=status),
            _trusted_key(attestation_signer, POLICY_SYNC_ATTESTATION_PURPOSE, status=status),
        ]
    )


def _managed_registry(
    policy_signer: Ed25519Signer, receipt_signer: Ed25519Signer
) -> StaticReceiptTrustRegistry:
    return StaticReceiptTrustRegistry(
        [
            _trusted_key(policy_signer, POLICY_ENVELOPE_PURPOSE),
            _trusted_key(ATTESTATION_SIGNER, POLICY_SYNC_ATTESTATION_PURPOSE),
            _trusted_key(receipt_signer, DECISION_RECEIPT_PURPOSE),
        ]
    )


def _snapshot_payload(
    signer: Ed25519Signer,
    *,
    attestation_signer: Ed25519Signer = ATTESTATION_SIGNER,
    policy_trust_epoch: int = 1,
    attestation_trust_epoch: int = 1,
    generation: int = 1,
    rules: list[dict[str, Any]] | None = None,
    credential_id: str = "credential-1",
    credential_generation: int = 3,
    issued_at: str = "2026-01-01T00:01:00Z",
    revocation_checked_at: str = "2026-01-01T00:01:00Z",
    fresh_until: str = "2026-01-01T00:02:00Z",
    expires_at: str = "2026-01-01T00:06:00Z",
) -> dict[str, Any]:
    policy_rules = rules or [{"id": "deny-delete", "effect": "deny", "tools": ["file.delete"]}]
    policy = RuleSetPolicy.from_dict({"id": "policy-1", "rules": policy_rules})
    document = {"id": policy.policy_id, "version": policy.version, "rules": policy_rules}
    content_hash = sha256_json(document)
    envelope_body = {
        "schema": "acgs.policy-registry.envelope/v1",
        "scope": {
            "org_id": "org-1",
            "project_id": "project-1",
            "environment_id": "production",
        },
        "policy_id": policy.policy_id,
        "version": policy.version,
        "content_hash": content_hash,
        "document": document,
        "rules": policy_rules,
        "key_id": signer.key_id,
        "signature_algorithm": signer.algorithm,
        "trust_epoch": policy_trust_epoch,
        "purpose": POLICY_ENVELOPE_PURPOSE,
    }
    envelope = {
        **envelope_body,
        "signature": signer.sign(canonical_json(envelope_body).encode("utf-8")),
    }
    body = {
        "schema": "acgs.policy-sync.snapshot/v2",
        "purpose": "acgs.policy-sync/v2",
        "scope": {
            "org_id": "org-1",
            "project_id": "project-1",
            "environment_id": "production",
            "gate_id": "gate-1",
        },
        "runtime_identity_id": "runtime-1",
        "credential_id": credential_id,
        "credential_generation": credential_generation,
        "cursor": "psync_" + ("A" * 43),
        "head_generation": generation,
        "head_updated_at": "2026-01-01T00:00:00Z",
        "policy_version_id": f"policy-version-{generation}",
        "policy_id": policy.policy_id,
        "version": policy.version,
        "content_hash": content_hash,
        "activation_receipt_id": "receipt-activation-1",
        "activation_receipt_hash": "a" * 64,
        "activation_event_hash": "b" * 64,
        "policy_envelope": envelope,
        "attestation_purpose": POLICY_SYNC_ATTESTATION_PURPOSE,
        "attestation_trust_epoch": attestation_trust_epoch,
        "attestation_key_id": attestation_signer.key_id,
        "attestation_signature_algorithm": attestation_signer.algorithm,
        "issued_at": issued_at,
        "revocation_checked_at": revocation_checked_at,
        "fresh_until": fresh_until,
        "expires_at": expires_at,
    }
    cursor_binding = {
        "schema": "acgs.policy-sync.binding/v2",
        "scope": body["scope"],
        "runtime_identity_id": body["runtime_identity_id"],
        "credential_id": body["credential_id"],
        "credential_generation": body["credential_generation"],
        "head_generation": body["head_generation"],
        "head_updated_at": body["head_updated_at"],
        "policy_version_id": body["policy_version_id"],
        "policy_id": body["policy_id"],
        "version": body["version"],
        "content_hash": body["content_hash"],
        "policy_envelope_trust_epoch": envelope["trust_epoch"],
        "policy_envelope_key_id": envelope["key_id"],
        "policy_envelope_signature_algorithm": envelope["signature_algorithm"],
        "policy_envelope_signature": envelope["signature"],
        "activation_receipt_id": body["activation_receipt_id"],
        "activation_receipt_hash": body["activation_receipt_hash"],
        "activation_event_hash": body["activation_event_hash"],
        "attestation_purpose": body["attestation_purpose"],
        "attestation_trust_epoch": body["attestation_trust_epoch"],
        "attestation_key_id": body["attestation_key_id"],
        "attestation_signature_algorithm": body["attestation_signature_algorithm"],
    }
    digest = __import__("hashlib").sha256(canonical_json(cursor_binding).encode("utf-8")).digest()
    body["cursor"] = "psync_" + __import__("base64").urlsafe_b64encode(digest).rstrip(b"=").decode(
        "ascii"
    )
    return {
        **body,
        "attestation_signature": attestation_signer.sign(canonical_json(body).encode("utf-8")),
    }


def _snapshot(signer: Ed25519Signer, **kwargs: Any) -> PolicySyncSnapshot:
    return PolicySyncSnapshot.from_dict(_snapshot_payload(signer, **kwargs))


def _resign_outer(payload: dict[str, Any]) -> PolicySyncSnapshot:
    unsigned = dict(payload)
    unsigned.pop("attestation_signature")
    payload["attestation_signature"] = ATTESTATION_SIGNER.sign(
        canonical_json(unsigned).encode("utf-8")
    )
    return PolicySyncSnapshot.from_dict(payload)


def test_strict_snapshot_verifies_both_layers_and_builds_ruleset() -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    snapshot = _snapshot(signer)

    policy = verify_policy_sync_snapshot(
        snapshot,
        descriptor=_descriptor(),
        trust_registry=_registry(signer),
        now=NOW,
    )

    assert policy.version == snapshot.version
    assert policy.evaluate(ToolCall("safe.read", {})).decision is Decision.ALLOW
    assert policy.evaluate(ToolCall("file.delete", {})).decision is Decision.DENY


@pytest.mark.parametrize(
    ("path", "value", "match"),
    [
        (("scope", "org_id"), "org-2", "cursor binding mismatch"),
        (("runtime_identity_id",), "runtime-2", "cursor binding mismatch"),
        (("credential_generation",), 2, "cursor binding mismatch"),
        (("policy_envelope", "document", "rules"), [], "signature is invalid"),
        (("content_hash",), "0" * 64, "cursor binding mismatch"),
        (("attestation_signature",), "00", "signature is invalid"),
    ],
)
def test_tampering_fails_closed(path: tuple[str, ...], value: Any, match: str) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    payload = _snapshot_payload(signer)
    target: Any = payload
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(PolicySyncError, match=match):
        snapshot = PolicySyncSnapshot.from_dict(payload)
        verify_policy_sync_snapshot(
            snapshot,
            descriptor=_descriptor(),
            trust_registry=_registry(signer),
            now=NOW,
        )


def test_parser_rejects_unknown_duplicate_and_hostile_types() -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    payload = _snapshot_payload(signer)
    payload["unexpected"] = True
    with pytest.raises(PolicySyncError, match="keys mismatch"):
        PolicySyncSnapshot.from_dict(payload)


def test_nested_envelope_tamper_is_rejected_after_valid_outer_signature() -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    payload = _snapshot_payload(signer)
    payload["policy_envelope"]["document"]["rules"] = []
    snapshot = _resign_outer(payload)

    with pytest.raises(PolicySyncError, match="rules mismatch"):
        verify_policy_sync_snapshot(
            snapshot,
            descriptor=_descriptor(),
            trust_registry=_registry(signer),
            now=NOW,
        )
    with pytest.raises(PolicySyncError, match="malformed"):
        PolicySyncSnapshot.from_json('{"schema":"x","schema":"y"}')
    payload = _snapshot_payload(signer)
    payload["credential_generation"] = True
    with pytest.raises(PolicySyncError, match="positive integer"):
        PolicySyncSnapshot.from_dict(payload)
    payload = _snapshot_payload(signer)
    payload["activation_receipt_id"] = "not canonical"
    with pytest.raises(PolicySyncError, match="canonical identifier"):
        PolicySyncSnapshot.from_dict(payload)


def test_atomic_cache_anti_rollback_equivocation_and_failure_preserve_lkg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    cache = AtomicJsonPolicyCache(
        tmp_path / "policy.json",
        descriptor=_descriptor(),
        trust_registry=_registry(signer),
    )
    first = _snapshot(signer, generation=2)
    assert cache.install(first, now=NOW)
    original_bytes = cache.path.read_bytes()
    original_policy = cache.policy
    assert cache.path.stat().st_mode & 0o777 == 0o600
    assert not cache.install(first, now=NOW)

    with pytest.raises(PolicySyncError, match="equivocation"):
        cache.install(
            _snapshot(
                signer,
                generation=2,
                rules=[{"id": "deny-all", "effect": "deny"}],
            ),
            now=NOW,
        )
    with pytest.raises(PolicySyncError, match="rollback"):
        cache.install(_snapshot(signer, generation=1), now=NOW)
    assert cache.install(_snapshot(signer, generation=4), now=NOW)
    original_bytes = cache.path.read_bytes()
    original_policy = cache.policy

    second = _snapshot(signer, generation=5)
    monkeypatch.setattr(os, "replace", lambda *_args: (_ for _ in ()).throw(OSError("boom")))
    with pytest.raises(OSError, match="boom"):
        cache.install(second, now=NOW)
    assert cache.path.read_bytes() == original_bytes
    assert cache.policy is original_policy


def test_atomic_cache_directory_sync_failure_rolls_back_lkg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    cache = AtomicJsonPolicyCache(
        tmp_path / "policy.json",
        descriptor=_descriptor(),
        trust_registry=_registry(signer),
    )
    cache.install(_snapshot(signer, generation=1), now=NOW)
    original_bytes = cache.path.read_bytes()
    original_policy = cache.policy
    real_fsync_directory = __import__(
        "gove_zone.policy_sync", fromlist=["_fsync_directory"]
    )._fsync_directory
    calls = 0

    def fail_once(path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("directory fsync failed")
        real_fsync_directory(path)

    monkeypatch.setattr("gove_zone.policy_sync._fsync_directory", fail_once)

    with pytest.raises(OSError, match="directory fsync failed"):
        cache.install(_snapshot(signer, generation=2), now=NOW)
    assert calls == 2
    assert cache.path.read_bytes() == original_bytes
    assert cache.policy is original_policy


def test_synced_policy_fresh_degraded_and_expired_are_local_and_fail_closed(
    tmp_path: Path,
) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    cache = AtomicJsonPolicyCache(
        tmp_path / "policy.json",
        descriptor=_descriptor(),
        trust_registry=_registry(signer),
    )
    cache.install(_snapshot(signer), now=NOW)
    calls = 0

    def clock() -> datetime:
        nonlocal calls
        calls += 1
        return datetime(2026, 1, 1, 0, 5, tzinfo=UTC)

    synced = SyncedRuleSetPolicy(cache, clock=clock)
    assert synced.mode == "degraded_lkg"
    assert synced.evaluate(ToolCall("safe.read", {})).decision is Decision.DENY
    with synced.receipt_binding_scope():
        assert synced.evaluate(ToolCall("safe.read", {})).decision is Decision.DENY
    assert calls == 2

    expired = SyncedRuleSetPolicy(cache, clock=lambda: datetime(2026, 1, 1, 0, 6, tzinfo=UTC))
    assert expired.evaluate(ToolCall("safe.read", {})).decision is Decision.DENY

    cache.path.write_text("{}", encoding="utf-8")
    assert synced.evaluate(ToolCall("safe.read", {})).decision is Decision.DENY


def test_locally_revoked_trust_denies_without_network(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    cache = AtomicJsonPolicyCache(
        tmp_path / "policy.json",
        descriptor=_descriptor(),
        trust_registry=_registry(signer),
    )
    cache.install(_snapshot(signer), now=NOW)
    cache.trust_registry = _registry(signer, revoked=True)
    synced = SyncedRuleSetPolicy(cache, clock=lambda: NOW)

    assert synced.evaluate(ToolCall("safe.read", {})).decision is Decision.DENY


def test_mutated_in_memory_policy_cannot_bypass_verified_gateway_policy(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    receipt_signer = Ed25519Signer.generate(key_id="receipt-key")
    registry = _managed_registry(signer, receipt_signer)
    cache = AtomicJsonPolicyCache(
        tmp_path / "policy.json",
        descriptor=_descriptor(),
        trust_registry=registry,
    )
    cache.install(
        _snapshot(
            signer,
            rules=[{"id": "deny-read", "effect": "deny", "tools": ["safe.read"]}],
        ),
        now=NOW,
    )
    assert cache.policy is not None
    cache.policy._rules = ()  # type: ignore[attr-defined]
    gateway = UniversalGateway(
        tenant_id="org-1",
        execution_boundary="gate-1",
        policy=SyncedRuleSetPolicy(cache, clock=lambda: NOW),
        profile=GovernanceProfile.production(signer=receipt_signer, verifier=receipt_signer),
        validator=Validator("validator-1"),
        authority="policy-sync-test",
        receipt_ttl_seconds=60,
        scoped_receipt_config=ScopedDecisionReceiptConfig(
            "project-1", "production", "gate-1", 1, registry
        ),
        audit_path=tmp_path / "audit.jsonl",
        ledger_path=tmp_path / "ledger.jsonl",
    )
    effects: list[str] = []
    gateway.register_tool("safe.read", lambda: effects.append("ran") or "ok")

    result = gateway.invoke("runtime-1", "safe.read", {})

    assert result.status == "denied"
    assert effects == []


def test_descriptor_and_local_lease_limits_fail_closed() -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    registry = _registry(signer)
    snapshot = _snapshot(signer)

    with pytest.raises(PolicySyncError, match="descriptor expired"):
        verify_policy_sync_snapshot(
            snapshot,
            descriptor=_descriptor(expires_at="2026-01-01T00:04:00Z"),
            trust_registry=registry,
            now=NOW,
        )
    with pytest.raises(PolicySyncError, match="outside descriptor validity"):
        verify_policy_sync_snapshot(
            snapshot,
            descriptor=_descriptor(expires_at="2026-01-01T00:05:30Z"),
            trust_registry=registry,
            now=datetime(2026, 1, 1, 0, 5, 0, tzinfo=UTC),
        )
    with pytest.raises(PolicySyncError, match="lifetime exceeds"):
        verify_policy_sync_snapshot(
            _snapshot(
                signer,
                fresh_until="2026-01-01T00:02:01Z",
                expires_at="2026-01-01T00:06:01Z",
            ),
            descriptor=_descriptor(),
            trust_registry=registry,
            now=NOW,
        )
    with pytest.raises(PolicySyncError, match="revocation check is too old"):
        verify_policy_sync_snapshot(
            _snapshot(
                signer,
                issued_at="2026-01-01T00:02:01Z",
                revocation_checked_at="2026-01-01T00:01:00Z",
                fresh_until="2026-01-01T00:03:01Z",
                expires_at="2026-01-01T00:07:01Z",
            ),
            descriptor=_descriptor(),
            trust_registry=registry,
            now=NOW,
        )


class _FakeSignedClient:
    def __init__(self, response: RuntimeHttpResponse) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def request(self, **kwargs: Any) -> RuntimeHttpResponse:
        self.calls.append(kwargs)
        return self.response


def test_client_applies_200_and_304_never_extends_freshness(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    snapshot = _snapshot(signer)
    cache = AtomicJsonPolicyCache(
        tmp_path / "policy.json",
        descriptor=_descriptor(),
        trust_registry=_registry(signer),
    )
    signed = _FakeSignedClient(RuntimeHttpResponse(200, snapshot.canonical_json_bytes()))
    client = PolicySyncClient(signed_client=signed, cache=cache)  # type: ignore[arg-type]

    fresh_now = datetime(2026, 1, 1, 0, 1, 30, tzinfo=UTC)
    assert client.sync(now=fresh_now)
    before = cache.path.read_bytes()
    signed.response = RuntimeHttpResponse(304, b"")
    assert not client.sync(now=fresh_now)
    assert cache.path.read_bytes() == before
    assert signed.calls[-1]["query"] == f"cursor={snapshot.cursor}"


def test_client_rejects_body_on_304_and_missing_cache(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    cache = AtomicJsonPolicyCache(
        tmp_path / "policy.json",
        descriptor=_descriptor(),
        trust_registry=_registry(signer),
    )
    signed = _FakeSignedClient(RuntimeHttpResponse(304, b"{}"))
    client = PolicySyncClient(signed_client=signed, cache=cache)  # type: ignore[arg-type]
    with pytest.raises(PolicySyncError, match="empty body"):
        client.sync(now=NOW)


def test_forced_same_head_renewal_recovers_expired_cache_after_restart(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    path = tmp_path / "policy.json"
    initial = _snapshot(signer)
    first_cache = AtomicJsonPolicyCache(
        path,
        descriptor=_descriptor(),
        trust_registry=_registry(signer),
    )
    first_cache.install(initial, now=NOW)
    renewal = _snapshot(
        signer,
        issued_at="2026-01-01T00:02:00Z",
        revocation_checked_at="2026-01-01T00:02:00Z",
        fresh_until="2026-01-01T00:03:00Z",
        expires_at="2026-01-01T00:07:00Z",
    )
    restarted = AtomicJsonPolicyCache(
        path,
        descriptor=_descriptor(),
        trust_registry=_registry(signer),
    )
    stale_304 = PolicySyncClient(
        signed_client=_FakeSignedClient(RuntimeHttpResponse(304, b"")),  # type: ignore[arg-type]
        cache=restarted,
    )
    with pytest.raises(PolicySyncError, match="forced renewal"):
        stale_304.sync(now=datetime(2026, 1, 1, 0, 2, tzinfo=UTC))
    signed = _FakeSignedClient(RuntimeHttpResponse(200, renewal.canonical_json_bytes()))
    client = PolicySyncClient(signed_client=signed, cache=restarted)  # type: ignore[arg-type]

    assert client.sync(now=datetime(2026, 1, 1, 0, 6, 30, tzinfo=UTC))
    assert signed.calls[-1]["query"] == ""
    assert restarted.snapshot == renewal

    older = _snapshot(
        signer,
        issued_at="2026-01-01T00:01:30Z",
        revocation_checked_at="2026-01-01T00:01:30Z",
        fresh_until="2026-01-01T00:02:30Z",
        expires_at="2026-01-01T00:06:30Z",
    )
    with pytest.raises(PolicySyncError, match="monotonically"):
        restarted.install(older, now=datetime(2026, 1, 1, 0, 6, 0, tzinfo=UTC))


def test_credential_rotation_is_strictly_increasing_and_preserves_head(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    cache = AtomicJsonPolicyCache(
        tmp_path / "policy.json",
        descriptor=_descriptor(),
        trust_registry=_registry(signer),
    )
    cache.install(_snapshot(signer), now=NOW)
    rotated_descriptor = _descriptor(
        credential_id="credential-2",
        credential_generation=4,
        issued_at="2026-01-01T00:02:00Z",
    )
    cache.update_descriptor(rotated_descriptor)
    rotated = _snapshot(
        signer,
        credential_id="credential-2",
        credential_generation=4,
        issued_at="2026-01-01T00:02:00Z",
        revocation_checked_at="2026-01-01T00:02:00Z",
        fresh_until="2026-01-01T00:03:00Z",
        expires_at="2026-01-01T00:07:00Z",
    )

    assert cache.install(rotated, now=datetime(2026, 1, 1, 0, 2, tzinfo=UTC))
    with pytest.raises(PolicySyncError, match="generation rollback"):
        cache.update_descriptor(_descriptor())
    with pytest.raises(PolicySyncError, match="credential"):
        cache.install(_snapshot(signer), now=NOW)


def test_concurrent_same_generation_conflict_allows_exactly_one_writer(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    path = tmp_path / "policy.json"
    caches = [
        AtomicJsonPolicyCache(path, descriptor=_descriptor(), trust_registry=_registry(signer))
        for _ in range(2)
    ]
    snapshots = [
        _snapshot(signer, rules=[{"id": f"deny-{index}", "effect": "deny"}]) for index in range(2)
    ]

    def install(index: int) -> str:
        try:
            return "installed" if caches[index].install(snapshots[index], now=NOW) else "same"
        except PolicySyncError as exc:
            assert "equivocation" in str(exc)
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(install, range(2)))

    assert sorted(results) == ["installed", "rejected"]


def test_response_size_limit_rejects_limit_plus_one(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    cache = AtomicJsonPolicyCache(
        tmp_path / "policy.json",
        descriptor=_descriptor(),
        trust_registry=_registry(signer),
    )
    client = PolicySyncClient(
        signed_client=_FakeSignedClient(RuntimeHttpResponse(200, b"x" * 11)),  # type: ignore[arg-type]
        cache=cache,
        max_response_bytes=10,
    )

    with pytest.raises(PolicySyncError, match="size limit"):
        client.sync(now=NOW)


def test_cache_rejects_insecure_directory_and_missing_cache_denies(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    insecure = tmp_path / "shared"
    insecure.mkdir(mode=0o777)
    insecure.chmod(0o777)
    cache = AtomicJsonPolicyCache(
        insecure / "policy.json",
        descriptor=_descriptor(),
        trust_registry=_registry(signer),
    )
    with pytest.raises(PolicySyncError, match="group or other access"):
        cache.install(_snapshot(signer), now=NOW)

    missing = AtomicJsonPolicyCache(
        tmp_path / "missing" / "policy.json",
        descriptor=_descriptor(),
        trust_registry=_registry(signer),
    )
    assert (
        SyncedRuleSetPolicy(missing, clock=lambda: NOW).evaluate(ToolCall("safe.read", {})).decision
        is Decision.DENY
    )


def test_snapshot_json_round_trip_is_canonical() -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    snapshot = _snapshot(signer)
    assert json.loads(snapshot.canonical_json_bytes()) == snapshot.to_dict()


def test_managed_policy_provenance_is_immutable_and_canonical() -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    snapshot = _snapshot(signer)
    provenance_type = policy_sync_module.ManagedPolicyProvenance

    provenance = provenance_type.from_snapshot(
        snapshot,
        policy_key_fingerprint=_trusted_key(signer, POLICY_ENVELOPE_PURPOSE).public_key_fingerprint,
        attestation_key_fingerprint=_trusted_key(
            ATTESTATION_SIGNER, POLICY_SYNC_ATTESTATION_PURPOSE
        ).public_key_fingerprint,
    )
    payload = provenance.to_dict()

    assert list(payload) == [
        "scope",
        "runtime_identity_id",
        "credential_id",
        "credential_generation",
        "cursor",
        "head_generation",
        "head_updated_at",
        "policy_version_id",
        "policy_id",
        "version",
        "content_hash",
        "activation_receipt_id",
        "activation_receipt_hash",
        "activation_event_hash",
        "policy_sync_schema",
        "policy_sync_purpose",
        "policy_trust_purpose",
        "policy_trust_epoch",
        "policy_key_id",
        "policy_signature_algorithm",
        "policy_key_fingerprint",
        "attestation_purpose",
        "attestation_trust_epoch",
        "attestation_key_id",
        "attestation_signature_algorithm",
        "attestation_key_fingerprint",
        "signed_snapshot_hash",
    ]
    assert (
        payload["signed_snapshot_hash"]
        == __import__("hashlib").sha256(snapshot.canonical_json_bytes().rstrip(b"\n")).hexdigest()
    )
    assert provenance.compute_hash() == sha256_json(payload)
    payload["scope"]["org_id"] = "mutated"
    assert provenance.to_dict()["scope"]["org_id"] == "org-1"
    with pytest.raises(FrozenInstanceError):
        provenance.content_hash = "0" * 64


def test_decision_record_serializes_policy_provenance_only_when_present() -> None:
    common = {
        "decision": Decision.ALLOW,
        "tool": "safe.read",
        "argument_hash": "a" * 64,
        "policy_version": "policy/v1",
        "event_id": "event-1",
    }
    legacy = __import__("gove_zone.decision", fromlist=["DecisionRecord"]).DecisionRecord(**common)
    managed = __import__("gove_zone.decision", fromlist=["DecisionRecord"]).DecisionRecord(
        **common, policy_provenance_hash="b" * 64
    )

    assert "policy_provenance_hash" not in legacy.to_dict()
    assert managed.to_dict()["policy_provenance_hash"] == "b" * 64


def test_synced_policy_exposes_read_only_signed_snapshot_currentness(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    cache = AtomicJsonPolicyCache(
        tmp_path / "policy.json", descriptor=_descriptor(), trust_registry=_registry(signer)
    )
    snapshot = _snapshot(signer)
    cache.install(snapshot, now=NOW)
    policy = SyncedRuleSetPolicy(cache, clock=lambda: NOW)

    currentness = policy.current_snapshot_currentness()

    assert currentness == {
        "issued_at": snapshot.issued_at,
        "fresh_until": snapshot.fresh_until,
        "expires_at": snapshot.expires_at,
        "mode": "degraded_lkg",
    }
    with pytest.raises(TypeError):
        currentness["mode"] = "expired"  # type: ignore[index]


def test_receipt_binding_scope_holds_verified_lease_against_replacement(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    path = tmp_path / "policy.json"
    cache = AtomicJsonPolicyCache(path, descriptor=_descriptor(), trust_registry=_registry(signer))
    cache.install(_snapshot(signer), now=NOW)
    policy = SyncedRuleSetPolicy(cache, clock=lambda: NOW)
    competing = AtomicJsonPolicyCache(
        path, descriptor=_descriptor(), trust_registry=_registry(signer)
    )
    started = __import__("threading").Event()

    def replace_cache() -> bool:
        started.set()
        return competing.install(_snapshot(signer, generation=2), now=NOW)

    with ThreadPoolExecutor(max_workers=1) as executor:
        with policy.receipt_binding_scope() as provenance:
            future = executor.submit(replace_cache)
            assert started.wait(timeout=1)
            assert not future.done()
            assert policy.evaluate(ToolCall("safe.read", {})).decision is Decision.DENY
            assert provenance.compute_hash()
        assert future.result(timeout=2)


def test_universal_gateway_executes_allow_once_then_corrupt_cache_executes_zero(
    tmp_path: Path,
) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    receipt_signer = Ed25519Signer.generate(key_id="receipt-key")
    registry = _managed_registry(signer, receipt_signer)
    cache = AtomicJsonPolicyCache(
        tmp_path / "policy.json",
        descriptor=_descriptor(),
        trust_registry=registry,
    )
    cache.install(
        _snapshot(
            signer,
            rules=[{"id": "deny-other", "effect": "deny", "tools": ["other.tool"]}],
        ),
        now=NOW,
    )
    synced = SyncedRuleSetPolicy(cache, clock=lambda: NOW)
    gateway = UniversalGateway(
        tenant_id="org-1",
        execution_boundary="gate-1",
        policy=synced,
        profile=GovernanceProfile.production(signer=receipt_signer, verifier=receipt_signer),
        validator=Validator("validator-1"),
        authority="policy-sync-test",
        receipt_ttl_seconds=60,
        scoped_receipt_config=ScopedDecisionReceiptConfig(
            "project-1", "production", "gate-1", 1, registry
        ),
        audit_path=tmp_path / "audit.jsonl",
        ledger_path=tmp_path / "ledger.jsonl",
    )
    effects: list[str] = []
    gateway.register_tool("safe.read", lambda: effects.append("ran") or "ok")

    allowed = gateway.invoke("runtime-1", "safe.read", {})
    assert allowed.executed
    assert effects == ["ran"]

    cache.path.write_bytes(b"{}\n")
    denied = gateway.invoke("runtime-1", "safe.read", {})
    assert denied.status == "denied"
    assert effects == ["ran"]


def test_managed_gateway_mints_exact_scoped_native_receipt(tmp_path: Path) -> None:
    policy_signer = Ed25519Signer.generate(key_id="policy-key")
    receipt_signer = Ed25519Signer.generate(key_id="receipt-key")
    registry = _managed_registry(policy_signer, receipt_signer)
    snapshot = _snapshot(
        policy_signer,
        rules=[{"id": "deny-other", "effect": "deny", "tools": ["other.tool"]}],
    )
    cache = AtomicJsonPolicyCache(
        tmp_path / "policy.json",
        descriptor=_descriptor(),
        trust_registry=registry,
    )
    cache.install(snapshot, now=NOW)
    gateway = UniversalGateway(
        tenant_id="org-1",
        execution_boundary="gate-1",
        policy=SyncedRuleSetPolicy(cache, clock=lambda: NOW),
        profile=GovernanceProfile.production(signer=receipt_signer),
        validator=Validator("validator-1"),
        authority="policy-sync-test",
        receipt_ttl_seconds=60,
        scoped_receipt_config=ScopedDecisionReceiptConfig(
            project_id="project-1",
            environment_id="production",
            gate_id="gate-1",
            trust_epoch=1,
            trust_registry=registry,
        ),
        audit_path=tmp_path / "audit.jsonl",
        ledger_path=tmp_path / "ledger.jsonl",
    )
    gateway.register_tool("safe.read", lambda: "ok")

    result = gateway.invoke("runtime-1", "safe.read", {})

    assert result.status == "executed"
    assert result.assurance_class == "native"
    assert result.receipt is not None
    provenance = policy_sync_module.ManagedPolicyProvenance.from_snapshot(
        snapshot,
        policy_key_fingerprint=_trusted_key(
            policy_signer, POLICY_ENVELOPE_PURPOSE
        ).public_key_fingerprint,
        attestation_key_fingerprint=_trusted_key(
            ATTESTATION_SIGNER, POLICY_SYNC_ATTESTATION_PURPOSE
        ).public_key_fingerprint,
    )
    constraints = {
        "schema": "acgs.managed-policy-execution/v1",
        "policy_provenance": provenance.to_dict(),
        "policy_provenance_hash": provenance.compute_hash(),
    }
    assert result.receipt.policy_bundle_id == snapshot.policy_version_id
    assert result.receipt.policy_hash == snapshot.content_hash
    assert result.receipt.constraints == constraints
    assert result.to_dict()["assurance_class"] == "native"

    with pytest.raises(ReceiptAlreadyUsedError):
        execute_with_receipt(
            tool_fn=lambda: pytest.fail("replayed managed receipt executed"),
            args={},
            receipt=result.receipt,
            expected_tenant_id="org-1",
            expected_execution_boundary="gate-1",
            expected_action="safe.read",
            expected_actor="runtime-1",
            expected_audit_hash=result.audit_hash,
            expected_policy_hash=snapshot.content_hash,
            expected_policy_bundle_id=snapshot.policy_version_id,
            expected_constraints=constraints,
            expected_project_id="project-1",
            expected_environment_id="production",
            trust_registry=registry,
            consumption_ledger=gateway._ledger,
        )


def test_managed_gateway_fails_loud_without_receipt_configuration(tmp_path: Path) -> None:
    policy_signer = Ed25519Signer.generate(key_id="policy-key")
    receipt_signer = Ed25519Signer.generate(key_id="receipt-key")
    registry = _managed_registry(policy_signer, receipt_signer)
    cache = AtomicJsonPolicyCache(
        tmp_path / "policy.json", descriptor=_descriptor(), trust_registry=registry
    )
    cache.install(_snapshot(policy_signer), now=NOW)
    policy = SyncedRuleSetPolicy(cache, clock=lambda: NOW)

    with pytest.raises(ProductionProfileError, match="scoped decision-receipt"):
        UniversalGateway(
            tenant_id="org-1",
            execution_boundary="gate-1",
            policy=policy,
            profile=GovernanceProfile.production(signer=receipt_signer),
            validator=Validator("validator-1"),
            authority="policy-sync-test",
            receipt_ttl_seconds=60,
            audit_path=tmp_path / "audit.jsonl",
            ledger_path=tmp_path / "ledger.jsonl",
        )


def test_managed_gateway_fails_loud_without_signer_or_receipt_trust(tmp_path: Path) -> None:
    policy_signer = Ed25519Signer.generate(key_id="policy-key")
    receipt_signer = Ed25519Signer.generate(key_id="receipt-key")
    registry = _managed_registry(policy_signer, receipt_signer)
    cache = AtomicJsonPolicyCache(
        tmp_path / "policy.json", descriptor=_descriptor(), trust_registry=registry
    )
    cache.install(_snapshot(policy_signer), now=NOW)
    policy = SyncedRuleSetPolicy(cache, clock=lambda: NOW)
    config = ScopedDecisionReceiptConfig("project-1", "production", "gate-1", 1, registry)

    with pytest.raises(ProductionProfileError, match="signer"):
        UniversalGateway(
            tenant_id="org-1",
            execution_boundary="gate-1",
            policy=policy,
            profile=GovernanceProfile.production(),
            validator=Validator("validator-1"),
            authority="policy-sync-test",
            receipt_ttl_seconds=60,
            scoped_receipt_config=config,
            audit_path=tmp_path / "missing-signer-audit.jsonl",
            ledger_path=tmp_path / "missing-signer-ledger.jsonl",
        )

    with pytest.raises(ProductionProfileError, match="trusted decision-receipt verifier"):
        UniversalGateway(
            tenant_id="org-1",
            execution_boundary="gate-1",
            policy=policy,
            profile=GovernanceProfile.production(signer=receipt_signer),
            validator=Validator("validator-1"),
            authority="policy-sync-test",
            receipt_ttl_seconds=60,
            scoped_receipt_config=ScopedDecisionReceiptConfig(
                "project-1", "production", "gate-1", 1, _registry(policy_signer)
            ),
            audit_path=tmp_path / "missing-trust-audit.jsonl",
            ledger_path=tmp_path / "missing-trust-ledger.jsonl",
        )


def test_managed_gateway_scope_mismatch_executes_zero(tmp_path: Path) -> None:
    policy_signer = Ed25519Signer.generate(key_id="policy-key")
    receipt_signer = Ed25519Signer.generate(key_id="receipt-key")
    registry = _managed_registry(policy_signer, receipt_signer)
    cache = AtomicJsonPolicyCache(
        tmp_path / "policy.json", descriptor=_descriptor(), trust_registry=registry
    )
    cache.install(_snapshot(policy_signer), now=NOW)
    gateway = UniversalGateway(
        tenant_id="org-1",
        execution_boundary="gate-2",
        policy=SyncedRuleSetPolicy(cache, clock=lambda: NOW),
        profile=GovernanceProfile.production(signer=receipt_signer),
        validator=Validator("validator-1"),
        authority="policy-sync-test",
        receipt_ttl_seconds=60,
        scoped_receipt_config=ScopedDecisionReceiptConfig(
            "project-1", "production", "gate-2", 1, registry
        ),
        audit_path=tmp_path / "audit.jsonl",
        ledger_path=tmp_path / "ledger.jsonl",
    )
    effects: list[str] = []
    gateway.register_tool("safe.read", lambda: effects.append("ran"))

    with pytest.raises(ProductionProfileError, match="provenance scope"):
        gateway.invoke("runtime-1", "safe.read", {})
    assert effects == []


def test_managed_gateway_holds_policy_lease_through_execution(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="managed-key")
    receipt_signer = Ed25519Signer.generate(key_id="receipt-key")
    registry = _managed_registry(signer, receipt_signer)
    path = tmp_path / "policy.json"
    cache = AtomicJsonPolicyCache(path, descriptor=_descriptor(), trust_registry=registry)
    cache.install(
        _snapshot(
            signer,
            rules=[{"id": "deny-other", "effect": "deny", "tools": ["other.tool"]}],
        ),
        now=NOW,
    )
    competing = AtomicJsonPolicyCache(path, descriptor=_descriptor(), trust_registry=registry)
    gateway = UniversalGateway(
        tenant_id="org-1",
        execution_boundary="gate-1",
        policy=SyncedRuleSetPolicy(cache, clock=lambda: NOW),
        profile=GovernanceProfile.production(signer=receipt_signer),
        validator=Validator("validator-1"),
        authority="policy-sync-test",
        receipt_ttl_seconds=60,
        scoped_receipt_config=ScopedDecisionReceiptConfig(
            "project-1", "production", "gate-1", 1, registry
        ),
        audit_path=tmp_path / "audit.jsonl",
        ledger_path=tmp_path / "ledger.jsonl",
    )
    entered = __import__("threading").Event()
    release = __import__("threading").Event()

    def governed_tool() -> str:
        entered.set()
        assert release.wait(timeout=2)
        return "ok"

    gateway.register_tool("safe.read", governed_tool)
    with ThreadPoolExecutor(max_workers=2) as executor:
        invocation = executor.submit(gateway.invoke, "runtime-1", "safe.read", {})
        assert entered.wait(timeout=1)
        replacement = executor.submit(competing.install, _snapshot(signer, generation=2), now=NOW)
        assert not replacement.done()
        release.set()
        assert invocation.result(timeout=2).assurance_class == "native"
        assert replacement.result(timeout=2)


def test_v2_rejects_v1_generic_outer_trust_fields() -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    payload = _snapshot_payload(signer)
    payload["schema"] = "acgs.policy-sync.snapshot/v1"
    payload["purpose"] = "acgs.policy-sync/v1"
    payload["trust_epoch"] = payload.pop("attestation_trust_epoch")
    payload["key_id"] = payload.pop("attestation_key_id")
    payload["signature_algorithm"] = payload.pop("attestation_signature_algorithm")
    payload["signature"] = payload.pop("attestation_signature")
    payload.pop("attestation_purpose")

    with pytest.raises(PolicySyncError, match="keys mismatch|unsupported"):
        PolicySyncSnapshot.from_dict(payload)


def test_attestation_and_policy_envelope_require_distinct_physical_keys() -> None:
    seed = b"p" * 32
    signer = Ed25519Signer.from_private_bytes(seed, key_id="policy-alias")
    attestation_signer = Ed25519Signer.from_private_bytes(seed, key_id="attestation-alias")
    snapshot = _snapshot(signer, attestation_signer=attestation_signer)

    with pytest.raises(PolicySyncError, match="distinct physical keys"):
        verify_policy_sync_snapshot(
            snapshot,
            descriptor=_descriptor(),
            trust_registry=_registry(signer, attestation_signer=attestation_signer),
            now=NOW,
        )


@pytest.mark.parametrize("decision_aliases", ["policy", "attestation"])
def test_managed_gateway_rejects_decision_key_physical_alias_before_burn(
    tmp_path: Path, decision_aliases: str
) -> None:
    shared_seed = b"d" * 32
    policy_signer = (
        Ed25519Signer.from_private_bytes(shared_seed, key_id="policy-alias")
        if decision_aliases == "policy"
        else Ed25519Signer.generate(key_id="policy-key")
    )
    attestation_signer = (
        Ed25519Signer.from_private_bytes(shared_seed, key_id="attestation-alias")
        if decision_aliases == "attestation"
        else Ed25519Signer.generate(key_id="attestation-key")
    )
    receipt_signer = Ed25519Signer.from_private_bytes(shared_seed, key_id="receipt-alias")
    registry = StaticReceiptTrustRegistry(
        [
            _trusted_key(policy_signer, POLICY_ENVELOPE_PURPOSE),
            _trusted_key(attestation_signer, POLICY_SYNC_ATTESTATION_PURPOSE),
            _trusted_key(receipt_signer, DECISION_RECEIPT_PURPOSE),
        ]
    )
    cache = AtomicJsonPolicyCache(
        tmp_path / "policy.json", descriptor=_descriptor(), trust_registry=registry
    )
    cache.install(_snapshot(policy_signer, attestation_signer=attestation_signer), now=NOW)
    ledger_path = tmp_path / "ledger.jsonl"
    gateway = UniversalGateway(
        tenant_id="org-1",
        execution_boundary="gate-1",
        policy=SyncedRuleSetPolicy(cache, clock=lambda: NOW),
        profile=GovernanceProfile.production(signer=receipt_signer),
        validator=Validator("validator-1"),
        authority="policy-sync-test",
        receipt_ttl_seconds=60,
        scoped_receipt_config=ScopedDecisionReceiptConfig(
            "project-1", "production", "gate-1", 1, registry
        ),
        audit_path=tmp_path / "audit.jsonl",
        ledger_path=ledger_path,
    )
    effects: list[str] = []
    gateway.register_tool("safe.read", lambda: effects.append("ran") or "ok")

    with pytest.raises(ProductionProfileError, match="three distinct physical trust keys"):
        gateway.invoke("runtime-1", "safe.read", {})
    assert effects == []
    assert not ledger_path.exists()


def test_scoped_receipt_config_rejects_non_decision_purpose() -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    with pytest.raises(TrustConfigurationError, match="exactly the decision-receipt"):
        ScopedDecisionReceiptConfig(
            "project-1",
            "production",
            "gate-1",
            1,
            _registry(signer),
            trust_purpose=POLICY_ENVELOPE_PURPOSE,
        )


def test_high_water_detects_cache_rollback_and_missing_floor_cannot_be_rebuilt(
    tmp_path: Path,
) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    path = tmp_path / "policy.json"
    cache = AtomicJsonPolicyCache(path, descriptor=_descriptor(), trust_registry=_registry(signer))
    first = _snapshot(signer, generation=1)
    second = _snapshot(signer, generation=2)
    cache.install(first, now=NOW)
    first_bytes = path.read_bytes()
    cache.install(second, now=NOW)
    path.write_bytes(first_bytes)
    restarted = AtomicJsonPolicyCache(
        path, descriptor=_descriptor(), trust_registry=_registry(signer)
    )
    with pytest.raises(PolicySyncError, match="behind its high-water"):
        restarted.load(now=NOW)

    path.write_bytes(second.canonical_json_bytes())
    path.with_name(path.name + ".high-water.json").unlink()
    with pytest.raises(PolicySyncError, match="high-water is missing"):
        restarted.load(now=NOW)
    with pytest.raises(PolicySyncError, match="discard and re-enroll"):
        restarted.install(_snapshot(signer, generation=3), now=NOW)
    assert not hasattr(restarted, "bootstrap_high_water_from_verified_cache")


def test_high_water_corruption_remains_fail_closed(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    cache = AtomicJsonPolicyCache(
        tmp_path / "policy.json", descriptor=_descriptor(), trust_registry=_registry(signer)
    )
    cache.install(_snapshot(signer), now=NOW)
    cache.path.with_name(cache.path.name + ".high-water.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(PolicySyncError, match="keys mismatch"):
        cache.load(now=NOW)
    assert not hasattr(cache, "bootstrap_high_water_from_verified_cache")


def test_high_water_floor_has_no_supported_public_mutation_api(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    cache = AtomicJsonPolicyCache(
        tmp_path / "policy.json", descriptor=_descriptor(), trust_registry=_registry(signer)
    )
    snapshot = _snapshot(signer)
    assert cache.install(snapshot, now=NOW)

    assert not hasattr(gove_zone, "PolicyHighWaterStore")
    assert not hasattr(policy_sync_module, "PolicyHighWaterStore")
    assert not hasattr(cache, "high_water_store")
    assert not hasattr(cache, "persist_high_water")
    restarted = AtomicJsonPolicyCache(
        cache.path, descriptor=_descriptor(), trust_registry=_registry(signer)
    )
    assert restarted.load(now=NOW) == snapshot


def test_restarted_client_forces_full_sync_after_high_water_first_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    path = tmp_path / "policy.json"
    cache = AtomicJsonPolicyCache(path, descriptor=_descriptor(), trust_registry=_registry(signer))
    cache.install(_snapshot(signer, generation=1), now=NOW)
    second = _snapshot(signer, generation=2)
    monkeypatch.setattr(
        cache,
        "_atomic_replace",
        lambda _data: (_ for _ in ()).throw(OSError("cache write failed")),
    )
    with pytest.raises(OSError, match="cache write failed"):
        cache.install(second, now=NOW)

    recovering = AtomicJsonPolicyCache(
        path, descriptor=_descriptor(), trust_registry=_registry(signer)
    )
    signed = _FakeSignedClient(RuntimeHttpResponse(200, second.canonical_json_bytes()))
    client = PolicySyncClient(signed_client=signed, cache=recovering)  # type: ignore[arg-type]
    assert client.sync(now=NOW)
    assert signed.calls == [
        {
            "method": "GET",
            "path": "/v1/runtime-identities/runtime-1/policy-bundle",
            "query": "",
        }
    ]
    assert recovering.load(now=NOW) == second


def test_restarted_client_rejects_lower_snapshot_after_high_water_first_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    path = tmp_path / "policy.json"
    cache = AtomicJsonPolicyCache(path, descriptor=_descriptor(), trust_registry=_registry(signer))
    first = _snapshot(signer, generation=1)
    second = _snapshot(signer, generation=2)
    cache.install(first, now=NOW)
    monkeypatch.setattr(
        cache,
        "_atomic_replace",
        lambda _data: (_ for _ in ()).throw(OSError("cache write failed")),
    )
    with pytest.raises(OSError, match="cache write failed"):
        cache.install(second, now=NOW)

    recovering = AtomicJsonPolicyCache(
        path, descriptor=_descriptor(), trust_registry=_registry(signer)
    )
    client = PolicySyncClient(
        signed_client=_FakeSignedClient(RuntimeHttpResponse(200, first.canonical_json_bytes())),  # type: ignore[arg-type]
        cache=recovering,
    )
    with pytest.raises(PolicySyncError, match="below the durable high-water head"):
        client.sync(now=NOW)
    assert (
        SyncedRuleSetPolicy(recovering, clock=lambda: NOW)
        .evaluate(ToolCall("safe.read", {}))
        .decision
        is Decision.DENY
    )


def test_binding_reentry_is_resource_scoped_and_unwinds_on_exception(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    path = tmp_path / "policy.json"
    cache = AtomicJsonPolicyCache(path, descriptor=_descriptor(), trust_registry=_registry(signer))
    cache.install(_snapshot(signer), now=NOW)
    policy = SyncedRuleSetPolicy(cache, clock=lambda: NOW)
    competing = AtomicJsonPolicyCache(
        path, descriptor=_descriptor(), trust_registry=_registry(signer)
    )

    with policy.receipt_binding_scope() as first:
        with policy.receipt_binding_scope() as second:
            assert first == second
        with (
            pytest.raises(PolicySyncError, match="different cache object"),
            competing.receipt_binding_scope(now=NOW),
        ):
            pytest.fail("different cache object reentered the bound resource")
    with pytest.raises(RuntimeError, match="unwind"), policy.receipt_binding_scope():
        raise RuntimeError("unwind")
    with policy.receipt_binding_scope():
        assert policy.evaluate(ToolCall("safe.read", {})).decision is Decision.DENY


def test_policy_cache_lock_timeout_fails_closed(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate(key_id="policy-key")
    path = tmp_path / "policy.json"
    cache = AtomicJsonPolicyCache(path, descriptor=_descriptor(), trust_registry=_registry(signer))
    cache.install(_snapshot(signer), now=NOW)
    competing = AtomicJsonPolicyCache(
        path,
        descriptor=_descriptor(),
        trust_registry=_registry(signer),
        lock_timeout_seconds=0.05,
    )

    def contend() -> str:
        with (
            pytest.raises(PolicySyncError, match="timed out"),
            competing.receipt_binding_scope(now=NOW),
        ):
            pytest.fail("contended cache lock was acquired")
        return "refused"

    with cache.receipt_binding_scope(now=NOW), ThreadPoolExecutor(max_workers=1) as executor:
        assert executor.submit(contend).result(timeout=1) == "refused"


def test_previous_cache_accepts_retired_keys_but_never_revoked(tmp_path: Path) -> None:
    old_policy = Ed25519Signer.generate(key_id="old-policy")
    old_attestation = Ed25519Signer.generate(key_id="old-attestation")
    new_policy = Ed25519Signer.generate(key_id="new-policy")
    new_attestation = Ed25519Signer.generate(key_id="new-attestation")
    path = tmp_path / "policy.json"
    initial_registry = _registry(old_policy, attestation_signer=old_attestation)
    cache = AtomicJsonPolicyCache(path, descriptor=_descriptor(), trust_registry=initial_registry)
    cache.install(
        _snapshot(old_policy, attestation_signer=old_attestation),
        now=NOW,
    )
    cache.update_descriptor(
        _descriptor(
            credential_id="credential-2",
            credential_generation=4,
            issued_at="2026-01-01T00:02:00Z",
        )
    )
    rotated_registry = StaticReceiptTrustRegistry(
        [
            _trusted_key(old_policy, POLICY_ENVELOPE_PURPOSE, status="retired"),
            _trusted_key(old_attestation, POLICY_SYNC_ATTESTATION_PURPOSE, status="retired"),
            _trusted_key(new_policy, POLICY_ENVELOPE_PURPOSE, activated_epoch=2),
            _trusted_key(new_attestation, POLICY_SYNC_ATTESTATION_PURPOSE, activated_epoch=2),
        ]
    )
    cache.trust_registry = rotated_registry
    candidate = _snapshot(
        new_policy,
        generation=2,
        attestation_signer=new_attestation,
        policy_trust_epoch=2,
        attestation_trust_epoch=2,
        credential_id="credential-2",
        credential_generation=4,
        issued_at="2026-01-01T00:02:00Z",
        revocation_checked_at="2026-01-01T00:02:00Z",
        fresh_until="2026-01-01T00:03:00Z",
        expires_at="2026-01-01T00:07:00Z",
    )
    assert cache.install(candidate, now=datetime(2026, 1, 1, 0, 2, tzinfo=UTC))

    revoked_cache = AtomicJsonPolicyCache(
        tmp_path / "revoked.json",
        descriptor=_descriptor(),
        trust_registry=initial_registry,
    )
    revoked_cache.install(_snapshot(old_policy, attestation_signer=old_attestation), now=NOW)
    revoked_cache.update_descriptor(cache.descriptor)
    revoked_cache.trust_registry = StaticReceiptTrustRegistry(
        [
            _trusted_key(old_policy, POLICY_ENVELOPE_PURPOSE, status="revoked"),
            _trusted_key(old_attestation, POLICY_SYNC_ATTESTATION_PURPOSE, status="revoked"),
            _trusted_key(new_policy, POLICY_ENVELOPE_PURPOSE, activated_epoch=2),
            _trusted_key(new_attestation, POLICY_SYNC_ATTESTATION_PURPOSE, activated_epoch=2),
        ]
    )
    with pytest.raises(PolicySyncError, match="trust could not be resolved"):
        revoked_cache.install(candidate, now=datetime(2026, 1, 1, 0, 2, tzinfo=UTC))
