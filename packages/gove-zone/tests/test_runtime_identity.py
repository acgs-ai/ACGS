from __future__ import annotations

import dataclasses
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

cryptography = pytest.importorskip("cryptography")
del cryptography

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

from gove_zone import runtime_identity as runtime_identity_module  # noqa: E402
from gove_zone.runtime_identity import (  # noqa: E402
    AtomicJsonRuntimeIdentityStore,
    GateScope,
    InMemoryEd25519WorkloadKeyProvider,
    LocalDevelopmentFileWorkloadKeyProvider,
    RuntimeEnrollmentClient,
    RuntimeHttpRequest,
    RuntimeHttpResponse,
    RuntimeIdentityDescriptor,
    RuntimeIdentityError,
    SignedRequestClient,
    b64url_decode,
    b64url_encode,
    canonical_enrollment_request_bytes,
    canonical_signed_runtime_request_bytes,
    public_key_thumbprint,
    sha256_bytes,
    sha256_text,
    verify_enrollment_pop,
    verify_signed_runtime_request,
)

SCOPE = GateScope(
    org_id="org-1",
    project_id="project-1",
    environment="dev",
    gate_id="gate-1",
)
AUDIENCE = "control-plane"
ISSUED_AT = "2026-01-01T00:00:00Z"
EXPIRES_AT = "2026-01-02T00:00:00Z"
NOW = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)


def _descriptor(
    *,
    workload: InMemoryEd25519WorkloadKeyProvider | None = None,
    issuer: InMemoryEd25519WorkloadKeyProvider | None = None,
) -> tuple[
    RuntimeIdentityDescriptor,
    InMemoryEd25519WorkloadKeyProvider,
    InMemoryEd25519WorkloadKeyProvider,
]:
    workload_key = workload or InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    issuer_key = issuer or InMemoryEd25519WorkloadKeyProvider(key_id="issuer-key")
    descriptor = RuntimeIdentityDescriptor.issue(
        scope=SCOPE,
        runtime_identity_id="runtime-1",
        credential_id="cred-1",
        credential_generation=1,
        workload_public_key=workload_key.public_key_bytes(),
        issuer="issuer-1",
        audience=AUDIENCE,
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        signer=issuer_key,
    )
    return descriptor, workload_key, issuer_key


def _enrollment_envelope(
    descriptor: RuntimeIdentityDescriptor,
    *,
    receipt_id: str = "receipt-1",
) -> dict[str, object]:
    return {
        "identity_id": descriptor.runtime_identity_id,
        "org_id": descriptor.scope.org_id,
        "project_id": descriptor.scope.project_id,
        "environment_id": descriptor.scope.environment,
        "generation": descriptor.credential_generation,
        "descriptor": descriptor.to_dict(),
        "receipt_id": receipt_id,
    }


def test_canonical_enrollment_request_bytes_are_deterministic_and_complete() -> None:
    body = b'{"runtime_identity_id":"runtime-1"}'
    key = InMemoryEd25519WorkloadKeyProvider()
    thumbprint = public_key_thumbprint(key.public_key_bytes())

    first = canonical_enrollment_request_bytes(
        method="POST",
        path="/v1/runtime-enrollments",
        audience=AUDIENCE,
        bootstrap_id="bootstrap-1",
        runtime_identity_id="runtime-1",
        gate_id=SCOPE.gate_id,
        org_id=SCOPE.org_id,
        project_id=SCOPE.project_id,
        environment=SCOPE.environment,
        public_key_thumbprint=thumbprint,
        idempotency_key="idem-1",
        body=body,
        server_challenge="challenge-1",
        client_nonce="nonce-1",
        timestamp=ISSUED_AT,
    )
    second = canonical_enrollment_request_bytes(
        method="POST",
        path="/v1/runtime-enrollments",
        audience=AUDIENCE,
        bootstrap_id="bootstrap-1",
        runtime_identity_id="runtime-1",
        gate_id=SCOPE.gate_id,
        org_id=SCOPE.org_id,
        project_id=SCOPE.project_id,
        environment=SCOPE.environment,
        public_key_thumbprint=thumbprint,
        idempotency_key="idem-1",
        body=body,
        server_challenge="challenge-1",
        client_nonce="nonce-1",
        timestamp=ISSUED_AT,
    )

    assert first == second
    assert json.loads(first) == {
        "audience": AUDIENCE,
        "body_digest": sha256_bytes(body),
        "bootstrap_id": "bootstrap-1",
        "client_nonce": "nonce-1",
        "environment": "dev",
        "gate_id": "gate-1",
        "idempotency_key_digest": sha256_text("idem-1"),
        "method": "POST",
        "org_id": "org-1",
        "path": "/v1/runtime-enrollments",
        "project_id": "project-1",
        "public_key_thumbprint": thumbprint,
        "runtime_identity_id": "runtime-1",
        "server_challenge": "challenge-1",
        "timestamp": ISSUED_AT,
    }

    with pytest.raises(RuntimeIdentityError, match="method must already be uppercase"):
        canonical_enrollment_request_bytes(
            method="post",
            path="/v1/runtime-enrollments",
            audience=AUDIENCE,
            bootstrap_id="bootstrap-1",
            runtime_identity_id="runtime-1",
            gate_id=SCOPE.gate_id,
            org_id=SCOPE.org_id,
            project_id=SCOPE.project_id,
            environment=SCOPE.environment,
            public_key_thumbprint=thumbprint,
            idempotency_key="idem-1",
            body=body,
            server_challenge="challenge-1",
            client_nonce="nonce-1",
            timestamp=ISSUED_AT,
        )


def test_enrollment_pop_verifies_and_tamper_fails_closed() -> None:
    key = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    body = b'{"public_key_thumbprint":"bound"}'
    thumbprint = public_key_thumbprint(key.public_key_bytes())
    payload = canonical_enrollment_request_bytes(
        method="POST",
        path="/v1/runtime-enrollments",
        audience=AUDIENCE,
        bootstrap_id="bootstrap-1",
        runtime_identity_id="runtime-1",
        gate_id=SCOPE.gate_id,
        org_id=SCOPE.org_id,
        project_id=SCOPE.project_id,
        environment=SCOPE.environment,
        public_key_thumbprint=thumbprint,
        idempotency_key="idem-1",
        body=body,
        server_challenge="challenge-1",
        client_nonce="nonce-1",
        timestamp=ISSUED_AT,
    )
    signature = key.sign(payload)

    verify_enrollment_pop(
        public_key=key.public_key_bytes(),
        signature=signature,
        method="POST",
        path="/v1/runtime-enrollments",
        audience=AUDIENCE,
        bootstrap_id="bootstrap-1",
        runtime_identity_id="runtime-1",
        gate_id=SCOPE.gate_id,
        org_id=SCOPE.org_id,
        project_id=SCOPE.project_id,
        environment=SCOPE.environment,
        public_key_thumbprint=thumbprint,
        idempotency_key="idem-1",
        body=body,
        server_challenge="challenge-1",
        client_nonce="nonce-1",
        timestamp=ISSUED_AT,
    )
    with pytest.raises(RuntimeIdentityError, match="invalid enrollment"):
        verify_enrollment_pop(
            public_key=key.public_key_bytes(),
            signature=signature,
            method="POST",
            path="/v1/runtime-enrollments",
            audience=AUDIENCE,
            bootstrap_id="bootstrap-1",
            runtime_identity_id="runtime-1",
            gate_id=SCOPE.gate_id,
            org_id=SCOPE.org_id,
            project_id=SCOPE.project_id,
            environment=SCOPE.environment,
            public_key_thumbprint=thumbprint,
            idempotency_key="idem-2",
            body=body,
            server_challenge="challenge-1",
            client_nonce="nonce-1",
            timestamp=ISSUED_AT,
        )


def test_descriptor_verification_tamper_wrong_key_wrong_scope_and_expiry() -> None:
    descriptor, _, issuer = _descriptor()
    descriptor.verify(
        issuer.public_key_bytes(),
        expected_scope=SCOPE,
        expected_audience=AUDIENCE,
        now=NOW,
    )

    tampered = dataclasses.replace(descriptor, audience="other-audience")
    with pytest.raises(RuntimeIdentityError, match="audience mismatch"):
        tampered.verify(issuer.public_key_bytes(), expected_audience=AUDIENCE, now=NOW)

    wrong = InMemoryEd25519WorkloadKeyProvider()
    with pytest.raises(RuntimeIdentityError, match="invalid runtime identity descriptor signature"):
        descriptor.verify(wrong.public_key_bytes(), expected_scope=SCOPE, now=NOW)

    wrong_scope = dataclasses.replace(SCOPE, project_id="project-2")
    with pytest.raises(RuntimeIdentityError, match="scope mismatch"):
        descriptor.verify(issuer.public_key_bytes(), expected_scope=wrong_scope, now=NOW)

    with pytest.raises(RuntimeIdentityError, match="expired"):
        descriptor.verify(
            issuer.public_key_bytes(),
            expected_scope=SCOPE,
            expected_audience=AUDIENCE,
            now=datetime(2026, 1, 3, tzinfo=UTC),
        )

    future_descriptor = RuntimeIdentityDescriptor.issue(
        scope=SCOPE,
        runtime_identity_id="runtime-1",
        credential_id="cred-2",
        credential_generation=2,
        workload_public_key=descriptor.public_key_bytes,
        issuer="issuer-1",
        audience=AUDIENCE,
        issued_at="2026-01-01T00:06:00Z",
        expires_at=EXPIRES_AT,
        signer=issuer,
    )
    with pytest.raises(RuntimeIdentityError, match="issued_at too far in future"):
        future_descriptor.verify(
            issuer.public_key_bytes(),
            expected_scope=SCOPE,
            expected_audience=AUDIENCE,
            now=NOW,
        )
    future_descriptor.verify(
        issuer.public_key_bytes(),
        expected_scope=SCOPE,
        expected_audience=AUDIENCE,
        now=NOW,
        max_issued_at_future_skew_seconds=360,
    )


def test_descriptor_rejects_malformed_base64_and_thumbprint_mismatch() -> None:
    descriptor, _, _ = _descriptor()
    payload = descriptor.to_dict()
    payload["public_key"] = "not=canonical"
    with pytest.raises(RuntimeIdentityError, match="malformed base64url"):
        RuntimeIdentityDescriptor.from_dict(payload)

    payload = descriptor.to_dict()
    payload["public_key_thumbprint"] = "0" * 64
    with pytest.raises(RuntimeIdentityError, match="thumbprint mismatch"):
        RuntimeIdentityDescriptor.from_dict(payload)


def test_exact_keys_and_base64url_canonical_roundtrip() -> None:
    descriptor, _, _ = _descriptor()
    payload = descriptor.to_dict()
    payload["unexpected"] = "value"
    with pytest.raises(RuntimeIdentityError, match="keys mismatch"):
        RuntimeIdentityDescriptor.from_dict(payload)

    scope_payload = SCOPE.to_dict()
    scope_payload.pop("gate_id")
    with pytest.raises(RuntimeIdentityError, match="keys mismatch"):
        GateScope.from_dict(scope_payload)

    raw = b"\x00\x01runtime-key"
    encoded = b64url_encode(raw)
    assert b64url_decode(encoded) == raw
    with pytest.raises(RuntimeIdentityError, match="malformed base64url"):
        b64url_decode(encoded + "=")
    with pytest.raises(RuntimeIdentityError, match="noncanonical base64url"):
        b64url_decode("AB")


def test_public_store_is_atomic_public_only_and_ignores_stray_tmp(tmp_path: Path) -> None:
    descriptor, _, issuer = _descriptor()
    store = AtomicJsonRuntimeIdentityStore(tmp_path / "identity.json")
    store.save(descriptor)
    (tmp_path / ".identity.json.tmp").write_text("{not-json", encoding="utf-8")

    loaded = store.load()
    loaded.verify(
        issuer.public_key_bytes(),
        expected_scope=SCOPE,
        expected_audience=AUDIENCE,
        now=NOW,
    )
    assert (tmp_path / "identity.json").stat().st_mode & 0o777 == 0o600
    stored_text = (tmp_path / "identity.json").read_text(encoding="utf-8")
    assert "private_key" not in stored_text
    assert "bootstrap" not in stored_text

    poisoned = descriptor.to_dict()
    poisoned["bootstrap_token"] = "secret"
    (tmp_path / "identity.json").write_text(json.dumps(poisoned), encoding="utf-8")
    with pytest.raises(RuntimeIdentityError, match="cannot persist bootstrap_token"):
        store.load()

    (tmp_path / "identity.json").write_text(
        '{"schema_version":"one","schema_version":"two"}',
        encoding="utf-8",
    )
    with pytest.raises(RuntimeIdentityError, match="store is malformed"):
        store.load()


def test_signed_runtime_request_verifies_and_body_tamper_fails() -> None:
    descriptor, workload, _ = _descriptor()
    body = b'{"renew":true}'
    payload = canonical_signed_runtime_request_bytes(
        method="POST",
        path="/v1/runtime-identities/runtime-1/renew",
        query="",
        body=body,
        timestamp=ISSUED_AT,
        nonce="nonce-1",
        key_id=workload.key_id,
        identity_id=descriptor.runtime_identity_id,
        credential_id=descriptor.credential_id,
        credential_generation=descriptor.credential_generation,
        idempotency_key="idem-renew-1",
        audience=AUDIENCE,
    )
    signature = workload.sign(payload)

    verify_signed_runtime_request(
        public_key=descriptor.public_key_bytes,
        signature=signature,
        method="POST",
        path="/v1/runtime-identities/runtime-1/renew",
        query="",
        body=body,
        timestamp=ISSUED_AT,
        nonce="nonce-1",
        key_id=workload.key_id,
        identity_id=descriptor.runtime_identity_id,
        credential_id=descriptor.credential_id,
        credential_generation=descriptor.credential_generation,
        idempotency_key="idem-renew-1",
        audience=AUDIENCE,
    )
    with pytest.raises(RuntimeIdentityError, match="invalid signed runtime request"):
        verify_signed_runtime_request(
            public_key=descriptor.public_key_bytes,
            signature=signature,
            method="POST",
            path="/v1/runtime-identities/runtime-1/renew",
            query="",
            body=b'{"renew":false}',
            timestamp=ISSUED_AT,
            nonce="nonce-1",
            key_id=workload.key_id,
            identity_id=descriptor.runtime_identity_id,
            credential_id=descriptor.credential_id,
            credential_generation=descriptor.credential_generation,
            idempotency_key="idem-renew-1",
            audience=AUDIENCE,
        )
    with pytest.raises(RuntimeIdentityError, match="invalid signed runtime request"):
        verify_signed_runtime_request(
            public_key=descriptor.public_key_bytes,
            signature=signature,
            method="POST",
            path="/v1/runtime-identities/runtime-1/renew",
            query="",
            body=body,
            timestamp=ISSUED_AT,
            nonce="nonce-1",
            key_id=workload.key_id,
            identity_id=descriptor.runtime_identity_id,
            credential_id=descriptor.credential_id,
            credential_generation=descriptor.credential_generation,
            idempotency_key="idem-renew-2",
            audience=AUDIENCE,
        )


def test_signed_runtime_canonical_bytes_bind_credential_generation_and_idempotency() -> None:
    descriptor, workload, _ = _descriptor()

    def canonical(
        *,
        credential_id: str = descriptor.credential_id,
        credential_generation: int = descriptor.credential_generation,
        idempotency_key: str | None = "idem-renew-1",
    ) -> bytes:
        return canonical_signed_runtime_request_bytes(
            method="POST",
            path="/v1/runtime-identities/runtime-1/renew",
            query="",
            body=b"{}",
            timestamp=ISSUED_AT,
            nonce="nonce-1",
            key_id=workload.key_id,
            identity_id=descriptor.runtime_identity_id,
            credential_id=credential_id,
            credential_generation=credential_generation,
            idempotency_key=idempotency_key,
            audience=AUDIENCE,
        )

    baseline = canonical()
    assert canonical(credential_id="cred-2") != baseline
    assert canonical(credential_generation=2) != baseline
    assert canonical(idempotency_key="idem-renew-2") != baseline

    decoded = json.loads(baseline)
    assert decoded["credential_id"] == descriptor.credential_id
    assert decoded["credential_generation"] == descriptor.credential_generation
    assert decoded["idempotency_key_digest"] == sha256_text("idem-renew-1")

    with pytest.raises(RuntimeIdentityError, match="requires idempotency_key"):
        canonical(idempotency_key=None)
    with pytest.raises(RuntimeIdentityError, match="credential_generation must be >= 1"):
        canonical(credential_generation=0)
    with pytest.raises(RuntimeIdentityError, match="credential_generation must be an integer"):
        bool_generation = cast(Any, True)
        canonical_signed_runtime_request_bytes(
            method="POST",
            path="/v1/runtime-identities/runtime-1/renew",
            query="",
            body=b"{}",
            timestamp=ISSUED_AT,
            nonce="nonce-1",
            key_id=workload.key_id,
            identity_id=descriptor.runtime_identity_id,
            credential_id=descriptor.credential_id,
            credential_generation=bool_generation,
            idempotency_key="idem-renew-1",
            audience=AUDIENCE,
        )
    with pytest.raises(RuntimeIdentityError, match="credential_generation must be an integer"):
        text_generation = cast(Any, "2")
        canonical_signed_runtime_request_bytes(
            method="POST",
            path="/v1/runtime-identities/runtime-1/renew",
            query="",
            body=b"{}",
            timestamp=ISSUED_AT,
            nonce="nonce-1",
            key_id=workload.key_id,
            identity_id=descriptor.runtime_identity_id,
            credential_id=descriptor.credential_id,
            credential_generation=text_generation,
            idempotency_key="idem-renew-1",
            audience=AUDIENCE,
        )


def test_signed_request_requires_idempotency_for_mutations_before_transport() -> None:
    descriptor, workload, _ = _descriptor()
    captured: list[RuntimeHttpRequest] = []

    def transport(request: RuntimeHttpRequest) -> RuntimeHttpResponse:
        captured.append(request)
        return RuntimeHttpResponse(status_code=200, body=b"{}")

    client = SignedRequestClient(
        descriptor=descriptor,
        key_provider=workload,
        transport=transport,
        audience=AUDIENCE,
    )

    with pytest.raises(RuntimeIdentityError, match="requires idempotency_key"):
        client.request(
            method="POST",
            path="/v1/runtime-identities/runtime-1/renew",
            body=b"{}",
            timestamp=ISSUED_AT,
            nonce="nonce-1",
        )
    with pytest.raises(RuntimeIdentityError, match="invalid header characters"):
        client.request(
            method="POST",
            path="/v1/runtime-identities/runtime-1/renew",
            body=b"{}",
            idempotency_key="idem-1\r\nx-injected: yes",
            timestamp=ISSUED_AT,
            nonce="nonce-1",
        )
    assert captured == []

    client.request(
        method="GET",
        path="/v1/runtime-identities/runtime-1",
        body=b"",
        timestamp=ISSUED_AT,
        nonce="nonce-1",
    )
    safe_request = captured.pop()
    assert "Idempotency-Key" not in safe_request.headers


@pytest.mark.parametrize("raw_nonce", [b"\xf8" + b"\x00" * 17, b"\xfc" + b"\x00" * 17])
def test_generated_signed_request_nonce_prefix_is_always_canonical(
    monkeypatch: pytest.MonkeyPatch,
    raw_nonce: bytes,
) -> None:
    descriptor, workload, _ = _descriptor()
    captured: list[RuntimeHttpRequest] = []

    def deterministic_urandom(length: int) -> bytes:
        assert length == 18
        return raw_nonce

    monkeypatch.setattr(runtime_identity_module.os, "urandom", deterministic_urandom)
    client = SignedRequestClient(
        descriptor=descriptor,
        key_provider=workload,
        transport=lambda request: (
            captured.append(request) or RuntimeHttpResponse(status_code=200, body=b"{}")
        ),
        audience=AUDIENCE,
    )

    client.request(
        method="GET",
        path="/v1/runtime-identities/runtime-1",
        timestamp=ISSUED_AT,
    )

    generated = captured[0].headers["x-acgs-runtime-nonce"]
    assert generated == "n-" + b64url_encode(raw_nonce)
    assert generated[0].isalnum()
    assert b64url_decode(generated.removeprefix("n-")) == raw_nonce


def test_runtime_enrollment_renew_requires_and_emits_idempotency_key() -> None:
    descriptor, workload, _ = _descriptor()
    captured: list[RuntimeHttpRequest] = []

    def transport(request: RuntimeHttpRequest) -> RuntimeHttpResponse:
        captured.append(request)
        return RuntimeHttpResponse(status_code=200, body=b"{}")

    enrollment = RuntimeEnrollmentClient(
        key_provider=workload,
        transport=transport,
        audience=AUDIENCE,
    )

    enrollment.renew(
        descriptor=descriptor,
        idempotency_key="idem-renew-1",
        body=b"{}",
        timestamp=ISSUED_AT,
        nonce="nonce-1",
    )
    request = captured.pop()
    assert request.headers["Idempotency-Key"] == "idem-renew-1"
    assert request.headers["X-ACGS-Runtime-Credential-ID"] == descriptor.credential_id
    assert request.headers["X-ACGS-Runtime-Credential-Generation"] == str(
        descriptor.credential_generation
    )


@pytest.mark.parametrize(
    ("path", "query"),
    (
        ("/renew\r\nX-Injected: yes", ""),
        ("/v1/runtime-identities/runtime-1/renew", "ok=1\r\nX-Injected=yes"),
        ("/a/../renew", ""),
        ("/a\\renew", ""),
        ("/a%2Frenew", ""),
        ("/a%2E%2E/renew", ""),
        ("/a%252Frenew", ""),
        ("/v1/runtime-identities/runtime-1/renew#fragment", ""),
        ("/v1/runtime-identities/runtime-1/renew", "ok=1#fragment"),
    ),
)
def test_signed_runtime_request_rejects_ambiguous_request_targets(path: str, query: str) -> None:
    descriptor, workload, _ = _descriptor()
    with pytest.raises(RuntimeIdentityError):
        canonical_signed_runtime_request_bytes(
            method="POST",
            path=path,
            query=query,
            body=b"{}",
            timestamp=ISSUED_AT,
            nonce="nonce-1",
            key_id=workload.key_id,
            identity_id=descriptor.runtime_identity_id,
            credential_id=descriptor.credential_id,
            credential_generation=descriptor.credential_generation,
            idempotency_key="idem-renew-1",
            audience=AUDIENCE,
        )


def test_signed_request_client_rejects_ambiguous_target_before_transport() -> None:
    descriptor, workload, _ = _descriptor()
    captured: list[RuntimeHttpRequest] = []

    def transport(request: RuntimeHttpRequest) -> RuntimeHttpResponse:
        captured.append(request)
        return RuntimeHttpResponse(status_code=200, body=b"{}")

    client = SignedRequestClient(
        descriptor=descriptor,
        key_provider=workload,
        transport=transport,
        audience=AUDIENCE,
    )

    with pytest.raises(RuntimeIdentityError, match="path contains control characters"):
        client.request(
            method="POST",
            path="/renew\r\nX-Injected: yes",
            body=b"{}",
            idempotency_key="idem-renew-1",
            timestamp=ISSUED_AT,
            nonce="nonce-1",
        )
    with pytest.raises(RuntimeIdentityError, match="query contains control characters"):
        client.request(
            method="POST",
            path="/v1/runtime-identities/runtime-1/renew",
            query="ok=1\r\nX-Injected=yes",
            body=b"{}",
            idempotency_key="idem-renew-1",
            timestamp=ISSUED_AT,
            nonce="nonce-1",
        )
    assert captured == []


def test_local_development_file_provider_requires_opt_in_mode_and_nonproduction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    raw_private = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "dev.key"
    key_path.write_text(b64url_encode(raw_private), encoding="utf-8")
    os.chmod(key_path, 0o600)

    with pytest.raises(RuntimeIdentityError, match="explicit opt-in"):
        LocalDevelopmentFileWorkloadKeyProvider(key_path, allow_development_key=False)

    monkeypatch.setenv("GOVE_ZONE_PROFILE", "dev")
    provider = LocalDevelopmentFileWorkloadKeyProvider(key_path, allow_development_key=True)
    assert provider.public_key_bytes() == private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    os.chmod(key_path, 0o644)
    with pytest.raises(RuntimeIdentityError, match="mode 0600"):
        LocalDevelopmentFileWorkloadKeyProvider(key_path, allow_development_key=True)

    os.chmod(key_path, 0o600)
    monkeypatch.setenv("GOVE_ZONE_PROFILE", "production")
    with pytest.raises(RuntimeIdentityError, match="requires explicit dev profile"):
        LocalDevelopmentFileWorkloadKeyProvider(key_path, allow_development_key=True)

    if hasattr(os, "symlink"):
        monkeypatch.setenv("GOVE_ZONE_PROFILE", "dev")
        link_path = tmp_path / "dev-link.key"
        os.symlink(key_path, link_path)
        with pytest.raises(RuntimeIdentityError, match="must not be a symlink|not readable"):
            LocalDevelopmentFileWorkloadKeyProvider(link_path, allow_development_key=True)

    big_path = tmp_path / "big.key"
    big_path.write_text("A" * 4097, encoding="utf-8")
    os.chmod(big_path, 0o600)
    with pytest.raises(RuntimeIdentityError, match="size is invalid|too large"):
        LocalDevelopmentFileWorkloadKeyProvider(big_path, allow_development_key=True)


@pytest.mark.parametrize(
    "profile",
    (
        None,
        "",
        "banana",
        "production",
        "PRODUCTION",
        " production ",
        " Production ",
        "production-strict",
    ),
)
def test_local_development_file_provider_requires_explicit_dev_profile_before_file_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str | None
) -> None:
    missing_path = tmp_path / "missing-dev.key"
    if profile is None:
        monkeypatch.delenv("GOVE_ZONE_PROFILE", raising=False)
    else:
        monkeypatch.setenv("GOVE_ZONE_PROFILE", profile)

    with pytest.raises(RuntimeIdentityError, match="requires explicit dev profile"):
        LocalDevelopmentFileWorkloadKeyProvider(missing_path, allow_development_key=True)
    assert not missing_path.exists()


def test_clients_emit_exact_headers_body_and_do_not_leak_bootstrap_secret() -> None:
    descriptor, workload, _ = _descriptor()
    captured: list[RuntimeHttpRequest] = []

    def transport(request: RuntimeHttpRequest) -> RuntimeHttpResponse:
        captured.append(request)
        return RuntimeHttpResponse(status_code=200, body=b"{}")

    enrollment = RuntimeEnrollmentClient(
        key_provider=workload,
        transport=transport,
        audience=AUDIENCE,
    )
    enrollment.exchange_bootstrap(
        scope=SCOPE,
        bootstrap_id="bootstrap-1",
        bootstrap_token="bootstrap-secret-token",
        runtime_identity_id=descriptor.runtime_identity_id,
        idempotency_key="idem-1",
        server_challenge="challenge-1",
        client_nonce="nonce-1",
        timestamp=ISSUED_AT,
    )
    request = captured.pop()
    assert request.method == "POST"
    assert request.path == "/v1/runtime-enrollments"
    assert set(request.headers) == {
        "content-type",
        "authorization",
        "idempotency-key",
        "x-acgs-bootstrap-id",
        "x-acgs-runtime-pop-key-id",
        "x-acgs-runtime-pop-signature",
    }
    assert request.headers["authorization"] == "ACGS-Gate-Bootstrap bootstrap-secret-token"
    assert b"bootstrap_token" not in request.body
    assert b"bootstrap-secret-token" not in request.body
    assert "bootstrap-secret-token" not in repr(request)
    assert request.body.decode("utf-8") not in repr(request)
    assert request.headers["x-acgs-runtime-pop-signature"] not in repr(request)
    assert request.redacted_headers()["authorization"] == "[REDACTED]"
    assert request.redacted_headers()["x-acgs-runtime-pop-signature"] == "[REDACTED]"
    assert json.loads(request.body)["idempotency_key_digest"] == sha256_text("idem-1")

    signed = SignedRequestClient(
        descriptor=descriptor,
        key_provider=workload,
        transport=transport,
        audience=AUDIENCE,
    )
    signed.request(
        method="POST",
        path="/v1/runtime-identities/runtime-1/renew",
        query="access_token=query-secret&ok=1",
        body=b'{"renew":true}',
        idempotency_key="idem-renew-secret",
        timestamp=ISSUED_AT,
        nonce="nonce-1",
    )
    signed_request = captured.pop()
    assert signed_request.query == "access_token=query-secret&ok=1"
    assert signed_request.body.decode("utf-8") not in repr(signed_request)
    assert signed_request.query not in repr(signed_request)
    assert "query-secret" not in repr(signed_request)
    assert "idem-renew-secret" not in repr(signed_request)
    assert f"query_sha256={sha256_text(signed_request.query)!r}" in repr(signed_request)
    assert signed_request.headers["x-acgs-runtime-signature"] not in repr(signed_request)
    assert signed_request.redacted_headers()["x-acgs-runtime-signature"] == "[REDACTED]"
    assert signed_request.redacted_headers()["Idempotency-Key"] == "[REDACTED]"
    assert signed_request.headers == {
        "content-type": "application/json",
        "x-acgs-runtime-identity-id": "runtime-1",
        "x-acgs-runtime-key-id": workload.key_id,
        "X-ACGS-Runtime-Credential-ID": descriptor.credential_id,
        "X-ACGS-Runtime-Credential-Generation": str(descriptor.credential_generation),
        "Idempotency-Key": "idem-renew-secret",
        "x-acgs-runtime-audience": AUDIENCE,
        "x-acgs-runtime-timestamp": ISSUED_AT,
        "x-acgs-runtime-nonce": "nonce-1",
        "x-acgs-runtime-body-sha256": sha256_bytes(b'{"renew":true}'),
        "x-acgs-runtime-signature": signed_request.headers["x-acgs-runtime-signature"],
    }
    verify_signed_runtime_request(
        public_key=descriptor.public_key_bytes,
        signature=signed_request.headers["x-acgs-runtime-signature"],
        method=signed_request.method,
        path=signed_request.path,
        query=signed_request.query,
        body=signed_request.body,
        timestamp=signed_request.headers["x-acgs-runtime-timestamp"],
        nonce=signed_request.headers["x-acgs-runtime-nonce"],
        key_id=signed_request.headers["x-acgs-runtime-key-id"],
        identity_id=signed_request.headers["x-acgs-runtime-identity-id"],
        credential_id=signed_request.headers["X-ACGS-Runtime-Credential-ID"],
        credential_generation=int(signed_request.headers["X-ACGS-Runtime-Credential-Generation"]),
        idempotency_key=signed_request.headers["Idempotency-Key"],
        audience=signed_request.headers["x-acgs-runtime-audience"],
    )


def test_header_injection_rejected_before_transport() -> None:
    descriptor, workload, _ = _descriptor()
    captured: list[RuntimeHttpRequest] = []

    def transport(request: RuntimeHttpRequest) -> RuntimeHttpResponse:
        captured.append(request)
        return RuntimeHttpResponse(status_code=200, body=b"{}")

    enrollment = RuntimeEnrollmentClient(
        key_provider=workload,
        transport=transport,
        audience=AUDIENCE,
    )
    with pytest.raises(RuntimeIdentityError, match="single header token"):
        enrollment.exchange_bootstrap(
            scope=SCOPE,
            bootstrap_id="bootstrap-1",
            bootstrap_token="bootstrap-secret-token injected",
            runtime_identity_id=descriptor.runtime_identity_id,
            idempotency_key="idem-1",
            server_challenge="challenge-1",
            client_nonce="nonce-1",
            timestamp=ISSUED_AT,
        )
    with pytest.raises(RuntimeIdentityError, match="invalid header characters"):
        enrollment.exchange_bootstrap(
            scope=SCOPE,
            bootstrap_id="bootstrap-1",
            bootstrap_token="bootstrap-secret-token",
            runtime_identity_id=descriptor.runtime_identity_id,
            idempotency_key="idem-1\r\nx-injected: yes",
            server_challenge="challenge-1",
            client_nonce="nonce-1",
            timestamp=ISSUED_AT,
        )
    assert captured == []


def test_signed_request_rejects_header_injection_from_provider_key_id() -> None:
    descriptor, workload, _ = _descriptor()

    class BadKeyProvider:
        @property
        def key_id(self) -> str:
            return "workload-key\r\nx-injected: yes"

        def public_key_bytes(self) -> bytes:
            return workload.public_key_bytes()

        def sign(self, payload: bytes) -> str:
            return workload.sign(payload)

    client = SignedRequestClient(
        descriptor=descriptor,
        key_provider=BadKeyProvider(),
        transport=lambda _request: RuntimeHttpResponse(status_code=200, body=b"{}"),
        audience=AUDIENCE,
    )
    with pytest.raises(RuntimeIdentityError, match="invalid header characters"):
        client.request(
            method="POST",
            path="/v1/runtime-identities/runtime-1/renew",
            body=b"{}",
            idempotency_key="idem-renew-1",
            timestamp=ISSUED_AT,
            nonce="nonce-1",
        )


def test_exchange_and_store_accepts_only_verified_descriptor(tmp_path: Path) -> None:
    descriptor, workload, issuer = _descriptor()
    store = AtomicJsonRuntimeIdentityStore(tmp_path / "identity.json")
    captured: list[RuntimeHttpRequest] = []

    def transport(request: RuntimeHttpRequest) -> RuntimeHttpResponse:
        captured.append(request)
        return RuntimeHttpResponse(
            status_code=201,
            body=json.dumps(_enrollment_envelope(descriptor)).encode(),
        )

    enrollment = RuntimeEnrollmentClient(
        key_provider=workload,
        transport=transport,
        audience=AUDIENCE,
    )
    accepted = enrollment.exchange_and_store(
        store=store,
        issuer_public_key=issuer.public_key_bytes(),
        scope=SCOPE,
        bootstrap_id="bootstrap-1",
        bootstrap_token="bootstrap-secret-token",
        runtime_identity_id=descriptor.runtime_identity_id,
        idempotency_key="idem-1",
        server_challenge="challenge-1",
        client_nonce="nonce-1",
        timestamp=ISSUED_AT,
        now=NOW,
    )
    assert accepted == descriptor
    assert store.load() == descriptor
    assert "bootstrap-secret-token" not in (tmp_path / "identity.json").read_text(encoding="utf-8")
    assert captured[0].headers["authorization"] == "ACGS-Gate-Bootstrap bootstrap-secret-token"


@pytest.mark.parametrize(
    "response",
    (
        RuntimeHttpResponse(status_code=403, body=b"{}"),
        RuntimeHttpResponse(status_code=200, body=b'{"schema_version":"a","schema_version":"b"}'),
        RuntimeHttpResponse(status_code=200, body=b"{not-json"),
        RuntimeHttpResponse(status_code=200, body=b"\xff"),
    ),
)
def test_accept_enrollment_response_rejects_without_store_write(
    tmp_path: Path, response: RuntimeHttpResponse
) -> None:
    descriptor, workload, issuer = _descriptor()
    store = AtomicJsonRuntimeIdentityStore(tmp_path / "identity.json")
    enrollment = RuntimeEnrollmentClient(
        key_provider=workload,
        transport=lambda _request: response,
        audience=AUDIENCE,
    )

    with pytest.raises(RuntimeIdentityError):
        enrollment.exchange_and_store(
            store=store,
            issuer_public_key=issuer.public_key_bytes(),
            scope=SCOPE,
            bootstrap_id="bootstrap-1",
            bootstrap_token="bootstrap-secret-token",
            runtime_identity_id=descriptor.runtime_identity_id,
            idempotency_key="idem-1",
            server_challenge="challenge-1",
            client_nonce="nonce-1",
            timestamp=ISSUED_AT,
            now=NOW,
        )
    assert not (tmp_path / "identity.json").exists()


@pytest.mark.parametrize(
    ("payload", "match"),
    (
        pytest.param("raw-descriptor", "runtime enrollment response keys mismatch", id="raw"),
        pytest.param(
            "unknown-top-level",
            "runtime enrollment response keys mismatch",
            id="unknown",
        ),
        pytest.param(
            "duplicate-top-level",
            "runtime enrollment response is malformed",
            id="duplicate",
        ),
        pytest.param("identity-mismatch", "identity does not match descriptor", id="identity"),
        pytest.param("org-mismatch", "scope does not match descriptor", id="org"),
        pytest.param("project-mismatch", "scope does not match descriptor", id="project"),
        pytest.param("environment-mismatch", "scope does not match descriptor", id="environment"),
        pytest.param(
            "generation-mismatch",
            "generation does not match descriptor",
            id="generation",
        ),
        pytest.param(
            "malformed-receipt-id",
            "receipt_id must be a canonical identifier",
            id="receipt",
        ),
    ),
)
def test_accept_enrollment_response_requires_strict_cp_envelope(
    tmp_path: Path, payload: str, match: str
) -> None:
    descriptor, workload, issuer = _descriptor()
    envelope = _enrollment_envelope(descriptor)
    if payload == "raw-descriptor":
        body = json.dumps(descriptor.to_dict()).encode()
    elif payload == "unknown-top-level":
        body = json.dumps({**envelope, "unexpected": "value"}).encode()
    elif payload == "duplicate-top-level":
        body = (
            b'{"identity_id":"runtime-1","identity_id":"runtime-2",'
            b'"org_id":"org-1","project_id":"project-1","environment_id":"dev",'
            b'"generation":1,"descriptor":{},"receipt_id":"receipt-1"}'
        )
    else:
        if payload == "identity-mismatch":
            envelope["identity_id"] = "runtime-2"
        elif payload == "org-mismatch":
            envelope["org_id"] = "org-2"
        elif payload == "project-mismatch":
            envelope["project_id"] = "project-2"
        elif payload == "environment-mismatch":
            envelope["environment_id"] = "prod"
        elif payload == "generation-mismatch":
            envelope["generation"] = 2
        elif payload == "malformed-receipt-id":
            envelope["receipt_id"] = "receipt id"
        body = json.dumps(envelope).encode()

    store = AtomicJsonRuntimeIdentityStore(tmp_path / "identity.json")
    enrollment = RuntimeEnrollmentClient(
        key_provider=workload,
        transport=lambda _request: RuntimeHttpResponse(status_code=200, body=body),
        audience=AUDIENCE,
    )

    with pytest.raises(RuntimeIdentityError, match=match):
        enrollment.exchange_and_store(
            store=store,
            issuer_public_key=issuer.public_key_bytes(),
            scope=SCOPE,
            bootstrap_id="bootstrap-1",
            bootstrap_token="bootstrap-secret-token",
            runtime_identity_id=descriptor.runtime_identity_id,
            idempotency_key="idem-1",
            server_challenge="challenge-1",
            client_nonce="nonce-1",
            timestamp=ISSUED_AT,
            now=NOW,
        )
    assert not (tmp_path / "identity.json").exists()


def test_accept_enrollment_response_rejects_substitution_and_future_issue_time(
    tmp_path: Path,
) -> None:
    descriptor, workload, issuer = _descriptor()
    store = AtomicJsonRuntimeIdentityStore(tmp_path / "identity.json")
    enrollment = RuntimeEnrollmentClient(
        key_provider=workload,
        transport=lambda _request: RuntimeHttpResponse(
            status_code=200,
            body=json.dumps(
                _enrollment_envelope(
                    dataclasses.replace(descriptor, runtime_identity_id="runtime-2")
                )
            ).encode(),
        ),
        audience=AUDIENCE,
    )
    with pytest.raises(RuntimeIdentityError, match="identity mismatch|invalid runtime identity"):
        enrollment.exchange_and_store(
            store=store,
            issuer_public_key=issuer.public_key_bytes(),
            scope=SCOPE,
            bootstrap_id="bootstrap-1",
            bootstrap_token="bootstrap-secret-token",
            runtime_identity_id=descriptor.runtime_identity_id,
            idempotency_key="idem-1",
            server_challenge="challenge-1",
            client_nonce="nonce-1",
            timestamp=ISSUED_AT,
            now=NOW,
        )
    assert not (tmp_path / "identity.json").exists()

    future_descriptor = RuntimeIdentityDescriptor.issue(
        scope=SCOPE,
        runtime_identity_id="runtime-1",
        credential_id="cred-2",
        credential_generation=2,
        workload_public_key=workload.public_key_bytes(),
        issuer="issuer-1",
        audience=AUDIENCE,
        issued_at="2026-01-01T01:00:00Z",
        expires_at="2026-01-02T00:00:00Z",
        signer=issuer,
    )
    future_enrollment = RuntimeEnrollmentClient(
        key_provider=workload,
        transport=lambda _request: RuntimeHttpResponse(
            status_code=200,
            body=json.dumps(_enrollment_envelope(future_descriptor)).encode(),
        ),
        audience=AUDIENCE,
    )
    with pytest.raises(RuntimeIdentityError, match="issued_at too far in future"):
        future_enrollment.exchange_and_store(
            store=store,
            issuer_public_key=issuer.public_key_bytes(),
            scope=SCOPE,
            bootstrap_id="bootstrap-1",
            bootstrap_token="bootstrap-secret-token",
            runtime_identity_id=descriptor.runtime_identity_id,
            idempotency_key="idem-1",
            server_challenge="challenge-1",
            client_nonce="nonce-1",
            timestamp=ISSUED_AT,
            now=NOW,
        )
    assert not (tmp_path / "identity.json").exists()
