"""Runtime identity enrollment and signed-request helpers.

This module owns the gove-zone side of runtime identity. It is intentionally
dependency-light: importing it does not import ``cryptography``. Ed25519
operations are lazy and private-key custody is delegated to a
``WorkloadKeyProvider`` implementation.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import dataclasses
import hashlib
import json
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, Self

from gove_zone.decision import canonical_json

_IDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CTL_RE = re.compile(r"[\x00-\x1f\x7f]")
_PERCENT_ESCAPE_RE = re.compile(r"%([0-9A-Fa-f]{2})")
_MISSING_DEP_MSG = "runtime Ed25519 identity requires the 'crypto' extra"
_DESCRIPTOR_SCHEMA = "gove-zone.runtime-identity.v1"
_ENROLLMENT_PATH = "/v1/runtime-enrollments"
_RENEWAL_PATH_TEMPLATE = "/v1/runtime-identities/{identity_id}/renew"
_ENROLLMENT_RESPONSE_KEYS = {
    "identity_id",
    "org_id",
    "project_id",
    "environment_id",
    "generation",
    "descriptor",
    "receipt_id",
}
_MAX_DEV_KEY_FILE_BYTES = 4096
_MUTATION_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_REDACTED_HEADERS = frozenset(
    {
        "authorization",
        "idempotency-key",
        "x-acgs-runtime-pop-signature",
        "x-acgs-runtime-signature",
    }
)


class RuntimeIdentityError(ValueError):
    """Fail-closed runtime identity validation error."""


class WorkloadKeyProvider(Protocol):
    """Private-key custody boundary for runtime workload identity.

    Production integrations should implement this protocol using their own key
    custody system. The protocol never exposes private key material.
    """

    @property
    def key_id(self) -> str: ...

    def public_key_bytes(self) -> bytes: ...

    def sign(self, payload: bytes) -> str: ...


@dataclass(frozen=True, slots=True)
class GateScope:
    """Org/project/environment/gate binding for a runtime identity."""

    org_id: str
    project_id: str
    environment: str
    gate_id: str

    def __post_init__(self) -> None:
        for field in dataclasses.fields(self):
            _require_identifier(getattr(self, field.name), field.name)

    def to_dict(self) -> dict[str, str]:
        return {
            "org_id": self.org_id,
            "project_id": self.project_id,
            "environment": self.environment,
            "gate_id": self.gate_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        _require_exact_keys(
            payload,
            "scope",
            {"org_id", "project_id", "environment", "gate_id"},
        )
        return cls(
            org_id=_require_str(payload.get("org_id"), "scope.org_id"),
            project_id=_require_str(payload.get("project_id"), "scope.project_id"),
            environment=_require_str(payload.get("environment"), "scope.environment"),
            gate_id=_require_str(payload.get("gate_id"), "scope.gate_id"),
        )


@dataclass(frozen=True, slots=True)
class RuntimeIdentityDescriptor:
    """Public-only signed metadata for a runtime workload identity."""

    scope: GateScope
    runtime_identity_id: str
    credential_id: str
    credential_generation: int
    public_key: str
    public_key_thumbprint: str
    issuer: str
    audience: str
    issued_at: str
    expires_at: str
    signing_key_id: str
    signature: str
    schema_version: str = _DESCRIPTOR_SCHEMA
    signature_algorithm: str = "ed25519"

    def __post_init__(self) -> None:
        _require_identifier(self.runtime_identity_id, "runtime_identity_id")
        _require_identifier(self.credential_id, "credential_id")
        if self.credential_generation < 1:
            raise RuntimeIdentityError("credential_generation must be >= 1")
        _require_identifier(self.issuer, "issuer")
        _require_identifier(self.audience, "audience")
        _require_identifier(self.signing_key_id, "signing_key_id")
        if self.schema_version != _DESCRIPTOR_SCHEMA:
            raise RuntimeIdentityError("unsupported runtime identity descriptor schema")
        if self.signature_algorithm != "ed25519":
            raise RuntimeIdentityError(
                "unsupported runtime identity descriptor signature algorithm"
            )
        public_key_bytes = b64url_decode(self.public_key, expected_len=32)
        expected_thumbprint = public_key_thumbprint(public_key_bytes)
        if self.public_key_thumbprint != expected_thumbprint:
            raise RuntimeIdentityError("public key thumbprint mismatch")
        _parse_timestamp(self.issued_at, "issued_at")
        _parse_timestamp(self.expires_at, "expires_at")
        if _parse_timestamp(self.expires_at, "expires_at") <= _parse_timestamp(
            self.issued_at, "issued_at"
        ):
            raise RuntimeIdentityError("descriptor expiry must be after issuance")
        b64url_decode(self.signature, expected_len=64)

    @classmethod
    def issue(
        cls,
        *,
        scope: GateScope,
        runtime_identity_id: str,
        credential_id: str,
        credential_generation: int,
        workload_public_key: bytes,
        issuer: str,
        audience: str,
        issued_at: str,
        expires_at: str,
        signer: WorkloadKeyProvider,
    ) -> Self:
        unsigned = {
            "schema_version": _DESCRIPTOR_SCHEMA,
            "scope": scope.to_dict(),
            "runtime_identity_id": runtime_identity_id,
            "credential_id": credential_id,
            "credential_generation": credential_generation,
            "public_key": b64url_encode(workload_public_key),
            "public_key_thumbprint": public_key_thumbprint(workload_public_key),
            "issuer": issuer,
            "audience": audience,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "signature_algorithm": "ed25519",
            "signing_key_id": signer.key_id,
        }
        signature = signer.sign(_canonical_bytes(unsigned))
        return cls.from_dict({**unsigned, "signature": signature})

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        _require_exact_keys(
            payload,
            "runtime identity descriptor",
            {
                "schema_version",
                "scope",
                "runtime_identity_id",
                "credential_id",
                "credential_generation",
                "public_key",
                "public_key_thumbprint",
                "issuer",
                "audience",
                "issued_at",
                "expires_at",
                "signature_algorithm",
                "signing_key_id",
                "signature",
            },
        )
        return cls(
            schema_version=_require_str(payload.get("schema_version"), "schema_version"),
            scope=GateScope.from_dict(_require_mapping(payload.get("scope"), "scope")),
            runtime_identity_id=_require_str(
                payload.get("runtime_identity_id"), "runtime_identity_id"
            ),
            credential_id=_require_str(payload.get("credential_id"), "credential_id"),
            credential_generation=_require_int(
                payload.get("credential_generation"), "credential_generation"
            ),
            public_key=_require_str(payload.get("public_key"), "public_key"),
            public_key_thumbprint=_require_str(
                payload.get("public_key_thumbprint"), "public_key_thumbprint"
            ),
            issuer=_require_str(payload.get("issuer"), "issuer"),
            audience=_require_str(payload.get("audience"), "audience"),
            issued_at=_require_str(payload.get("issued_at"), "issued_at"),
            expires_at=_require_str(payload.get("expires_at"), "expires_at"),
            signature_algorithm=_require_str(
                payload.get("signature_algorithm"), "signature_algorithm"
            ),
            signing_key_id=_require_str(payload.get("signing_key_id"), "signing_key_id"),
            signature=_require_str(payload.get("signature"), "signature"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scope": self.scope.to_dict(),
            "runtime_identity_id": self.runtime_identity_id,
            "credential_id": self.credential_id,
            "credential_generation": self.credential_generation,
            "public_key": self.public_key,
            "public_key_thumbprint": self.public_key_thumbprint,
            "issuer": self.issuer,
            "audience": self.audience,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "signature_algorithm": self.signature_algorithm,
            "signing_key_id": self.signing_key_id,
            "signature": self.signature,
        }

    def signing_bytes(self) -> bytes:
        payload = self.to_dict()
        payload.pop("signature")
        return _canonical_bytes(payload)

    def verify(
        self,
        issuer_public_key: bytes,
        *,
        expected_scope: GateScope | None = None,
        expected_audience: str | None = None,
        now: datetime | None = None,
        max_issued_at_future_skew_seconds: int = 300,
    ) -> None:
        if expected_scope is not None and self.scope != expected_scope:
            raise RuntimeIdentityError("runtime identity descriptor scope mismatch")
        if expected_audience is not None and self.audience != expected_audience:
            raise RuntimeIdentityError("runtime identity descriptor audience mismatch")
        effective_now = _effective_now(now)
        issued_at = _parse_timestamp(self.issued_at, "issued_at")
        latest_allowed = effective_now + timedelta(seconds=max_issued_at_future_skew_seconds)
        if issued_at > latest_allowed:
            raise RuntimeIdentityError("runtime identity descriptor issued_at too far in future")
        if effective_now >= _parse_timestamp(self.expires_at, "expires_at"):
            raise RuntimeIdentityError("runtime identity descriptor expired")
        if not verify_ed25519(issuer_public_key, self.signing_bytes(), self.signature):
            raise RuntimeIdentityError("invalid runtime identity descriptor signature")

    @property
    def public_key_bytes(self) -> bytes:
        return b64url_decode(self.public_key, expected_len=32)


class InMemoryEd25519WorkloadKeyProvider:
    """Test/dev in-memory Ed25519 workload key provider."""

    algorithm = "ed25519"

    def __init__(self, *, key_id: str | None = None, private_key: Any | None = None) -> None:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519
        except ImportError as exc:  # pragma: no cover - exercised only without extra
            raise RuntimeIdentityError(_MISSING_DEP_MSG) from exc

        self._private_key = private_key or ed25519.Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        raw_public = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._key_id = key_id or hashlib.sha256(raw_public).hexdigest()[:16]

    @property
    def key_id(self) -> str:
        return self._key_id

    def public_key_bytes(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, payload: bytes) -> str:
        return b64url_encode(self._private_key.sign(payload))


class LocalDevelopmentFileWorkloadKeyProvider:
    """Explicit opt-in local development private-key provider.

    The file must already exist, be mode ``0600``, and contain either a raw
    32-byte Ed25519 private key encoded as base64url or a JSON object with
    ``{"private_key": "...", "key_id": "..."}``. This provider is never a
    production default and never exposes private-key bytes.
    """

    algorithm = "ed25519"

    def __init__(self, path: str | os.PathLike[str], *, allow_development_key: bool) -> None:
        if not allow_development_key:
            raise RuntimeIdentityError(
                "local development file key provider requires explicit opt-in"
            )
        from gove_zone.profile import GovernanceProfile

        if GovernanceProfile.from_env().is_production:
            raise RuntimeIdentityError(
                "local development file key provider requires explicit dev profile"
            )
        raw_text = _read_development_key_file(path)
        key_id: str | None = None
        if raw_text.startswith("{"):
            payload = _loads_json_object_no_duplicates(
                raw_text,
                malformed_message="local development private key file is malformed",
            )
            raw_private = b64url_decode(_require_str(payload.get("private_key"), "private_key"))
            maybe_key_id = payload.get("key_id")
            key_id = _require_str(maybe_key_id, "key_id") if maybe_key_id is not None else None
        else:
            raw_private = b64url_decode(raw_text)
        if len(raw_private) != 32:
            raise RuntimeIdentityError("local development private key must be 32 raw bytes")
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
        except ImportError as exc:  # pragma: no cover - exercised only without extra
            raise RuntimeIdentityError(_MISSING_DEP_MSG) from exc
        self._delegate = InMemoryEd25519WorkloadKeyProvider(
            key_id=key_id,
            private_key=ed25519.Ed25519PrivateKey.from_private_bytes(raw_private),
        )

    @property
    def key_id(self) -> str:
        return self._delegate.key_id

    def public_key_bytes(self) -> bytes:
        return self._delegate.public_key_bytes()

    def sign(self, payload: bytes) -> str:
        return self._delegate.sign(payload)


class AtomicJsonRuntimeIdentityStore:
    """Public-only descriptor store using atomic JSON replacement."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    def save(self, descriptor: RuntimeIdentityDescriptor) -> None:
        payload = descriptor.to_dict()
        _reject_secret_fields(payload)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.path.with_name(f".{self.path.name}.{os.getpid()}.{_nonce()}.tmp")
        data = canonical_json(payload).encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(tmp_path, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fd = -1
                mode = os.fstat(fh.fileno()).st_mode & 0o777
                if mode != 0o600:
                    raise RuntimeIdentityError("runtime identity temp file must be mode 0600")
                fh.write(data)
                fh.write(b"\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, self.path)
            _fsync_directory(self.path.parent)
        except Exception:
            if fd >= 0:
                os.close(fd)
            with contextlib.suppress(FileNotFoundError):
                tmp_path.unlink()
            raise

    def load(self) -> RuntimeIdentityDescriptor:
        try:
            payload = _loads_json_object_no_duplicates(
                self.path.read_text(encoding="utf-8"),
                malformed_message="runtime identity descriptor store is malformed",
            )
        except FileNotFoundError as exc:
            raise RuntimeIdentityError("runtime identity descriptor store is missing") from exc
        except UnicodeDecodeError as exc:
            raise RuntimeIdentityError("runtime identity descriptor store is malformed") from exc
        if not isinstance(payload, dict):
            raise RuntimeIdentityError("runtime identity descriptor store must contain an object")
        _reject_secret_fields(payload)
        return RuntimeIdentityDescriptor.from_dict(payload)


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeHttpRequest:
    method: str
    path: str
    headers: Mapping[str, str]
    body: bytes
    query: str = ""

    def redacted_headers(self) -> dict[str, str]:
        return {
            key: "[REDACTED]" if key.lower() in _REDACTED_HEADERS else value
            for key, value in self.headers.items()
        }

    def __repr__(self) -> str:
        return (
            "RuntimeHttpRequest("
            f"method={self.method!r}, "
            f"path={self.path!r}, "
            f"headers={self.redacted_headers()!r}, "
            f"body_len={len(self.body)!r}, "
            f"body_sha256={sha256_bytes(self.body)!r}, "
            f"query_len={len(self.query)!r}, "
            f"query_sha256={sha256_text(self.query)!r})"
        )


@dataclass(frozen=True, slots=True)
class RuntimeHttpResponse:
    status_code: int
    body: bytes
    headers: Mapping[str, str] = dataclasses.field(default_factory=dict)


RuntimeTransport = Callable[[RuntimeHttpRequest], RuntimeHttpResponse]


class SignedRequestClient:
    """Signs runtime requests with an injected transport."""

    def __init__(
        self,
        *,
        descriptor: RuntimeIdentityDescriptor,
        key_provider: WorkloadKeyProvider,
        transport: RuntimeTransport,
        audience: str,
    ) -> None:
        if descriptor.audience != audience:
            raise RuntimeIdentityError("signed request client audience mismatch")
        if descriptor.public_key_thumbprint != public_key_thumbprint(
            key_provider.public_key_bytes()
        ):
            raise RuntimeIdentityError("signed request key does not match descriptor")
        self._descriptor = descriptor
        self._key_provider = key_provider
        self._transport = transport
        self._audience = audience

    def request(
        self,
        *,
        method: str,
        path: str,
        body: bytes = b"",
        query: str = "",
        idempotency_key: str | None = None,
        timestamp: str | None = None,
        nonce: str | None = None,
    ) -> RuntimeHttpResponse:
        canonical_method = _canonical_method(method)
        canonical_idempotency_key = _canonical_idempotency_key(canonical_method, idempotency_key)
        ts = timestamp or _now_timestamp()
        request_nonce = nonce or _nonce()
        key_id = _require_header_value(self._key_provider.key_id, "key_id")
        signing_bytes = canonical_signed_runtime_request_bytes(
            method=canonical_method,
            path=path,
            query=query,
            body=body,
            timestamp=ts,
            nonce=request_nonce,
            key_id=key_id,
            identity_id=self._descriptor.runtime_identity_id,
            credential_id=self._descriptor.credential_id,
            credential_generation=self._descriptor.credential_generation,
            idempotency_key=canonical_idempotency_key,
            audience=self._audience,
        )
        signature = self._key_provider.sign(signing_bytes)
        headers = {
            "content-type": "application/json",
            "x-acgs-runtime-identity-id": _require_header_value(
                self._descriptor.runtime_identity_id, "runtime_identity_id"
            ),
            "x-acgs-runtime-key-id": key_id,
            "X-ACGS-Runtime-Credential-ID": _require_header_value(
                self._descriptor.credential_id, "credential_id"
            ),
            "X-ACGS-Runtime-Credential-Generation": _require_header_value(
                str(_require_credential_generation(self._descriptor.credential_generation)),
                "credential_generation",
            ),
            "x-acgs-runtime-audience": _require_header_value(self._audience, "audience"),
            "x-acgs-runtime-timestamp": _require_header_value(ts, "timestamp"),
            "x-acgs-runtime-nonce": _require_header_value(request_nonce, "nonce"),
            "x-acgs-runtime-body-sha256": sha256_bytes(body),
            "x-acgs-runtime-signature": _require_header_value(signature, "signature"),
        }
        if canonical_idempotency_key is not None:
            headers["Idempotency-Key"] = _require_header_value(
                canonical_idempotency_key, "idempotency_key"
            )
        return self._transport(
            RuntimeHttpRequest(
                method=canonical_method,
                path=_canonical_path(path),
                query=query,
                headers=headers,
                body=body,
            )
        )


class RuntimeEnrollmentClient:
    """Enrollment and renewal client with no implicit network calls."""

    def __init__(
        self,
        *,
        key_provider: WorkloadKeyProvider,
        transport: RuntimeTransport,
        audience: str,
    ) -> None:
        self._key_provider = key_provider
        self._transport = transport
        self._audience = audience

    def exchange_bootstrap(
        self,
        *,
        scope: GateScope,
        bootstrap_id: str,
        bootstrap_token: str,
        runtime_identity_id: str,
        idempotency_key: str,
        server_challenge: str,
        client_nonce: str,
        timestamp: str,
    ) -> RuntimeHttpResponse:
        _require_identifier(bootstrap_id, "bootstrap_id")
        _require_str(bootstrap_token, "bootstrap_token")
        public_key = self._key_provider.public_key_bytes()
        thumbprint = public_key_thumbprint(public_key)
        body = _canonical_bytes(
            {
                "audience": self._audience,
                "bootstrap_id": bootstrap_id,
                "client_nonce": client_nonce,
                "gate_id": scope.gate_id,
                "idempotency_key_digest": sha256_text(idempotency_key),
                "org_id": scope.org_id,
                "project_id": scope.project_id,
                "environment": scope.environment,
                "public_key": b64url_encode(public_key),
                "public_key_thumbprint": thumbprint,
                "runtime_identity_id": runtime_identity_id,
                "server_challenge": server_challenge,
                "timestamp": timestamp,
            }
        )
        pop_bytes = canonical_enrollment_request_bytes(
            method="POST",
            path=_ENROLLMENT_PATH,
            audience=self._audience,
            bootstrap_id=bootstrap_id,
            runtime_identity_id=runtime_identity_id,
            gate_id=scope.gate_id,
            org_id=scope.org_id,
            project_id=scope.project_id,
            environment=scope.environment,
            public_key_thumbprint=thumbprint,
            idempotency_key=idempotency_key,
            body=body,
            server_challenge=server_challenge,
            client_nonce=client_nonce,
            timestamp=timestamp,
        )
        headers = {
            "authorization": (
                f"ACGS-Gate-Bootstrap {_require_header_token(bootstrap_token, 'bootstrap_token')}"
            ),
            "content-type": "application/json",
            "idempotency-key": _require_header_value(idempotency_key, "idempotency_key"),
            "x-acgs-bootstrap-id": _require_header_value(bootstrap_id, "bootstrap_id"),
            "x-acgs-runtime-pop-key-id": _require_header_value(self._key_provider.key_id, "key_id"),
            "x-acgs-runtime-pop-signature": _require_header_value(
                self._key_provider.sign(pop_bytes), "signature"
            ),
        }
        return self._transport(
            RuntimeHttpRequest(method="POST", path=_ENROLLMENT_PATH, headers=headers, body=body)
        )

    def accept_enrollment_response(
        self,
        response: RuntimeHttpResponse,
        *,
        issuer_public_key: bytes,
        expected_scope: GateScope,
        expected_runtime_identity_id: str,
        now: datetime | None = None,
        max_issued_at_future_skew_seconds: int = 300,
    ) -> RuntimeIdentityDescriptor:
        if response.status_code < 200 or response.status_code >= 300:
            raise RuntimeIdentityError("runtime enrollment exchange was not accepted")
        try:
            raw_body = response.body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeIdentityError("runtime enrollment response is malformed") from exc
        payload = _loads_json_object_no_duplicates(
            raw_body,
            malformed_message="runtime enrollment response is malformed",
        )
        _require_exact_keys(
            payload,
            "runtime enrollment response",
            _ENROLLMENT_RESPONSE_KEYS,
        )
        identity_id = _require_identifier(
            _require_str(payload.get("identity_id"), "identity_id"), "identity_id"
        )
        org_id = _require_identifier(_require_str(payload.get("org_id"), "org_id"), "org_id")
        project_id = _require_identifier(
            _require_str(payload.get("project_id"), "project_id"), "project_id"
        )
        environment_id = _require_identifier(
            _require_str(payload.get("environment_id"), "environment_id"),
            "environment_id",
        )
        generation = _require_int(payload.get("generation"), "generation")
        _require_identifier(_require_str(payload.get("receipt_id"), "receipt_id"), "receipt_id")
        descriptor = RuntimeIdentityDescriptor.from_dict(
            _require_mapping(payload.get("descriptor"), "descriptor")
        )
        descriptor.verify(
            issuer_public_key,
            expected_scope=expected_scope,
            expected_audience=self._audience,
            now=now,
            max_issued_at_future_skew_seconds=max_issued_at_future_skew_seconds,
        )
        if identity_id != descriptor.runtime_identity_id:
            raise RuntimeIdentityError(
                "runtime enrollment response identity does not match descriptor"
            )
        if descriptor.runtime_identity_id != expected_runtime_identity_id:
            raise RuntimeIdentityError("runtime enrollment descriptor identity mismatch")
        if (
            org_id != descriptor.scope.org_id
            or project_id != descriptor.scope.project_id
            or environment_id != descriptor.scope.environment
        ):
            raise RuntimeIdentityError(
                "runtime enrollment response scope does not match descriptor"
            )
        if generation != descriptor.credential_generation:
            raise RuntimeIdentityError(
                "runtime enrollment response generation does not match descriptor"
            )
        if descriptor.public_key_thumbprint != public_key_thumbprint(
            self._key_provider.public_key_bytes()
        ):
            raise RuntimeIdentityError("runtime enrollment descriptor key mismatch")
        return descriptor

    def exchange_and_store(
        self,
        *,
        store: AtomicJsonRuntimeIdentityStore,
        issuer_public_key: bytes,
        scope: GateScope,
        bootstrap_id: str,
        bootstrap_token: str,
        runtime_identity_id: str,
        idempotency_key: str,
        server_challenge: str,
        client_nonce: str,
        timestamp: str,
        now: datetime | None = None,
    ) -> RuntimeIdentityDescriptor:
        response = self.exchange_bootstrap(
            scope=scope,
            bootstrap_id=bootstrap_id,
            bootstrap_token=bootstrap_token,
            runtime_identity_id=runtime_identity_id,
            idempotency_key=idempotency_key,
            server_challenge=server_challenge,
            client_nonce=client_nonce,
            timestamp=timestamp,
        )
        descriptor = self.accept_enrollment_response(
            response,
            issuer_public_key=issuer_public_key,
            expected_scope=scope,
            expected_runtime_identity_id=runtime_identity_id,
            now=now,
        )
        store.save(descriptor)
        return descriptor

    def renew(
        self,
        *,
        descriptor: RuntimeIdentityDescriptor,
        idempotency_key: str,
        body: bytes = b"{}",
        timestamp: str | None = None,
        nonce: str | None = None,
    ) -> RuntimeHttpResponse:
        path = _RENEWAL_PATH_TEMPLATE.format(identity_id=descriptor.runtime_identity_id)
        return SignedRequestClient(
            descriptor=descriptor,
            key_provider=self._key_provider,
            transport=self._transport,
            audience=self._audience,
        ).request(
            method="POST",
            path=path,
            body=body,
            idempotency_key=idempotency_key,
            timestamp=timestamp,
            nonce=nonce,
        )


def canonical_enrollment_request_bytes(
    *,
    method: str,
    path: str,
    audience: str,
    bootstrap_id: str,
    runtime_identity_id: str,
    gate_id: str,
    org_id: str,
    project_id: str,
    environment: str,
    public_key_thumbprint: str,
    idempotency_key: str,
    body: bytes,
    server_challenge: str,
    client_nonce: str,
    timestamp: str,
) -> bytes:
    payload = {
        "method": _canonical_method(method),
        "path": _canonical_path(path),
        "audience": _require_identifier(audience, "audience"),
        "bootstrap_id": _require_identifier(bootstrap_id, "bootstrap_id"),
        "runtime_identity_id": _require_identifier(runtime_identity_id, "runtime_identity_id"),
        "gate_id": _require_identifier(gate_id, "gate_id"),
        "org_id": _require_identifier(org_id, "org_id"),
        "project_id": _require_identifier(project_id, "project_id"),
        "environment": _require_identifier(environment, "environment"),
        "public_key_thumbprint": _require_hex_digest(
            public_key_thumbprint, "public_key_thumbprint"
        ),
        "idempotency_key_digest": sha256_text(idempotency_key),
        "body_digest": sha256_bytes(body),
        "server_challenge": _require_identifier(server_challenge, "server_challenge"),
        "client_nonce": _require_identifier(client_nonce, "client_nonce"),
        "timestamp": _canonical_timestamp(timestamp),
    }
    return _canonical_bytes(payload)


def canonical_signed_runtime_request_bytes(
    *,
    method: str,
    path: str,
    query: str,
    body: bytes,
    timestamp: str,
    nonce: str,
    key_id: str,
    identity_id: str,
    credential_id: str,
    credential_generation: int,
    idempotency_key: str | None,
    audience: str,
) -> bytes:
    canonical_method = _canonical_method(method)
    canonical_idempotency_key = _canonical_idempotency_key(canonical_method, idempotency_key)
    payload = {
        "method": canonical_method,
        "path": _canonical_path(path),
        "query": _canonical_query(query),
        "body_digest": sha256_bytes(body),
        "timestamp": _canonical_timestamp(timestamp),
        "nonce": _require_identifier(nonce, "nonce"),
        "key_id": _require_identifier(key_id, "key_id"),
        "identity_id": _require_identifier(identity_id, "identity_id"),
        "credential_id": _require_identifier(credential_id, "credential_id"),
        "credential_generation": _require_credential_generation(credential_generation),
        "idempotency_key_digest": (
            sha256_text(canonical_idempotency_key)
            if canonical_idempotency_key is not None
            else None
        ),
        "audience": _require_identifier(audience, "audience"),
    }
    return _canonical_bytes(payload)


def verify_enrollment_pop(
    *,
    public_key: bytes,
    signature: str,
    method: str,
    path: str,
    audience: str,
    bootstrap_id: str,
    runtime_identity_id: str,
    gate_id: str,
    org_id: str,
    project_id: str,
    environment: str,
    public_key_thumbprint: str,
    idempotency_key: str,
    body: bytes,
    server_challenge: str,
    client_nonce: str,
    timestamp: str,
) -> None:
    if public_key_thumbprint != public_key_thumbprint_fn(public_key):
        raise RuntimeIdentityError("enrollment PoP public key thumbprint mismatch")
    payload = canonical_enrollment_request_bytes(
        method=method,
        path=path,
        audience=audience,
        bootstrap_id=bootstrap_id,
        runtime_identity_id=runtime_identity_id,
        gate_id=gate_id,
        org_id=org_id,
        project_id=project_id,
        environment=environment,
        public_key_thumbprint=public_key_thumbprint,
        idempotency_key=idempotency_key,
        body=body,
        server_challenge=server_challenge,
        client_nonce=client_nonce,
        timestamp=timestamp,
    )
    if not verify_ed25519(public_key, payload, signature):
        raise RuntimeIdentityError("invalid enrollment proof-of-possession signature")


def verify_signed_runtime_request(
    *,
    public_key: bytes,
    signature: str,
    method: str,
    path: str,
    query: str,
    body: bytes,
    timestamp: str,
    nonce: str,
    key_id: str,
    identity_id: str,
    credential_id: str,
    credential_generation: int,
    idempotency_key: str | None,
    audience: str,
) -> None:
    payload = canonical_signed_runtime_request_bytes(
        method=method,
        path=path,
        query=query,
        body=body,
        timestamp=timestamp,
        nonce=nonce,
        key_id=key_id,
        identity_id=identity_id,
        credential_id=credential_id,
        credential_generation=credential_generation,
        idempotency_key=idempotency_key,
        audience=audience,
    )
    if not verify_ed25519(public_key, payload, signature):
        raise RuntimeIdentityError("invalid signed runtime request signature")


def public_key_thumbprint(public_key: bytes) -> str:
    if len(public_key) != 32:
        raise RuntimeIdentityError("Ed25519 public key must be 32 raw bytes")
    return hashlib.sha256(public_key).hexdigest()


public_key_thumbprint_fn = public_key_thumbprint


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_text(payload: str) -> str:
    return sha256_bytes(payload.encode("utf-8"))


def b64url_encode(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def b64url_decode(payload: str, *, expected_len: int | None = None) -> bytes:
    if not isinstance(payload, str) or not payload:
        raise RuntimeIdentityError("base64url value must be a non-empty string")
    if "=" in payload or not re.fullmatch(r"[A-Za-z0-9_-]+", payload):
        raise RuntimeIdentityError("malformed base64url value")
    padded = payload + ("=" * ((4 - len(payload) % 4) % 4))
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise RuntimeIdentityError("malformed base64url value") from exc
    if b64url_encode(decoded) != payload:
        raise RuntimeIdentityError("noncanonical base64url value")
    if expected_len is not None and len(decoded) != expected_len:
        raise RuntimeIdentityError(f"base64url value must decode to {expected_len} bytes")
    return decoded


def verify_ed25519(public_key: bytes, payload: bytes, signature: str) -> bool:
    signature_bytes = b64url_decode(signature, expected_len=64)
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - exercised only without extra
        raise RuntimeIdentityError(_MISSING_DEP_MSG) from exc
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature_bytes, payload)
        return True
    except InvalidSignature:
        return False
    except ValueError as exc:
        raise RuntimeIdentityError("invalid Ed25519 public key") from exc


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    return canonical_json(payload).encode("utf-8")


def _canonical_method(method: str) -> str:
    candidate = _require_str(method, "method").upper()
    if candidate != method:
        raise RuntimeIdentityError("method must already be uppercase canonical form")
    if candidate not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise RuntimeIdentityError("unsupported HTTP method")
    return candidate


def _canonical_path(path: str) -> str:
    value = _require_str(path, "path")
    if _CTL_RE.search(value):
        raise RuntimeIdentityError("path contains control characters")
    if any(ord(char) < 33 or ord(char) > 126 for char in value):
        raise RuntimeIdentityError("path contains noncanonical request-target characters")
    if (
        not value.startswith("/")
        or value.startswith("//")
        or "?" in value
        or "#" in value
        or "//" in value
    ):
        raise RuntimeIdentityError("path must be canonical absolute path without query or fragment")
    if "\\" in value:
        raise RuntimeIdentityError("path must not contain backslash")
    segments = value.split("/")
    if any(segment in {".", ".."} for segment in segments):
        raise RuntimeIdentityError("path must not contain dot segments")
    _validate_percent_encoding(value, "path")
    for byte in _percent_encoded_bytes(value):
        if byte in {ord("/"), ord("\\"), ord("."), ord("?"), ord("#"), ord("%")}:
            raise RuntimeIdentityError("path contains percent-encoded normalization ambiguity")
        if byte <= 32 or byte == 127:
            raise RuntimeIdentityError("path contains percent-encoded control character")
    return value


def _canonical_query(query: str) -> str:
    if not isinstance(query, str):
        raise RuntimeIdentityError("query must be a string")
    value = query
    if _CTL_RE.search(value):
        raise RuntimeIdentityError("query contains control characters")
    if any(ord(char) < 33 or ord(char) > 126 for char in value):
        raise RuntimeIdentityError("query contains noncanonical request-target characters")
    if value.startswith("?") or "#" in value:
        raise RuntimeIdentityError("query must be canonical query without fragment marker")
    _validate_percent_encoding(value, "query")
    for byte in _percent_encoded_bytes(value):
        if byte in {ord("#")}:
            raise RuntimeIdentityError("query contains percent-encoded normalization ambiguity")
        if byte <= 32 or byte == 127:
            raise RuntimeIdentityError("query contains percent-encoded control character")
    return value


def _validate_percent_encoding(value: str, field: str) -> None:
    index = 0
    while True:
        percent = value.find("%", index)
        if percent == -1:
            return
        if percent + 2 >= len(value) or not re.fullmatch(
            r"[0-9A-Fa-f]{2}", value[percent + 1 : percent + 3]
        ):
            raise RuntimeIdentityError(f"{field} contains malformed percent encoding")
        if value[percent + 1 : percent + 3] != value[percent + 1 : percent + 3].upper():
            raise RuntimeIdentityError(f"{field} percent encoding must use uppercase hex")
        index = percent + 3


def _percent_encoded_bytes(value: str) -> list[int]:
    return [int(match.group(1), 16) for match in _PERCENT_ESCAPE_RE.finditer(value)]


def _canonical_timestamp(timestamp: str) -> str:
    _parse_timestamp(timestamp, "timestamp")
    if not timestamp.endswith("Z"):
        raise RuntimeIdentityError("timestamp must use canonical UTC Z form")
    return timestamp


def _parse_timestamp(value: str, field: str) -> datetime:
    text = _require_str(value, field)
    if not text.endswith("Z"):
        raise RuntimeIdentityError(f"{field} must use canonical UTC Z form")
    try:
        parsed = datetime.fromisoformat(text.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise RuntimeIdentityError(f"{field} must be an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None:
        raise RuntimeIdentityError(f"{field} must be timezone-aware")
    return parsed.astimezone(UTC)


def _now_timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _effective_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(UTC)
    if now.tzinfo is None:
        raise RuntimeIdentityError("now must be timezone-aware")
    return now.astimezone(UTC)


def _nonce() -> str:
    return b64url_encode(os.urandom(18))


def _require_str(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeIdentityError(f"{field} must be a non-empty string")
    return value


def _require_mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeIdentityError(f"{field} must be an object")
    return value


def _require_exact_keys(payload: Mapping[str, Any], field: str, expected: set[str]) -> None:
    observed = set(payload)
    if observed != expected:
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing={missing}")
        if extra:
            details.append(f"extra={extra}")
        raise RuntimeIdentityError(f"{field} keys mismatch: {', '.join(details)}")


def _require_int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise RuntimeIdentityError(f"{field} must be an integer")
    return value


def _require_credential_generation(value: object) -> int:
    generation = _require_int(value, "credential_generation")
    if generation < 1:
        raise RuntimeIdentityError("credential_generation must be >= 1")
    return generation


def _require_identifier(value: str, field: str) -> str:
    text = _require_str(value, field)
    if not _IDENT_RE.fullmatch(text):
        raise RuntimeIdentityError(f"{field} must be a canonical identifier")
    return text


def _canonical_idempotency_key(method: str, idempotency_key: str | None) -> str | None:
    if idempotency_key is None:
        if method in _MUTATION_METHODS:
            raise RuntimeIdentityError("mutating runtime request requires idempotency_key")
        return None
    return _require_header_value(idempotency_key, "idempotency_key")


def _require_hex_digest(value: str, field: str) -> str:
    text = _require_str(value, field)
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise RuntimeIdentityError(f"{field} must be a lowercase SHA-256 hex digest")
    return text


def _require_header_value(value: str, field: str) -> str:
    text = _require_str(value, field)
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise RuntimeIdentityError(f"{field} contains invalid header characters")
    return text


def _require_header_token(value: str, field: str) -> str:
    text = _require_header_value(value, field)
    if any(char.isspace() for char in text):
        raise RuntimeIdentityError(f"{field} must be a single header token")
    return text


def _reject_secret_fields(payload: object, *, path: str = "") -> None:
    secret_names = {"bootstrap_token", "refresh_token", "private_key", "secret", "bearer_token"}
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            key_text = str(key)
            if key_text in secret_names:
                raise RuntimeIdentityError(
                    f"public runtime identity store cannot persist {key_text}"
                )
            _reject_secret_fields(value, path=f"{path}.{key_text}" if path else key_text)
    elif isinstance(payload, list):
        for index, value in enumerate(payload):
            _reject_secret_fields(value, path=f"{path}[{index}]")


def _loads_json_object_no_duplicates(raw: str, *, malformed_message: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RuntimeIdentityError(f"duplicate JSON key rejected: {key}")
            result[key] = value
        return result

    try:
        parsed = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, RuntimeIdentityError) as exc:
        raise RuntimeIdentityError(malformed_message) from exc
    if not isinstance(parsed, dict):
        raise RuntimeIdentityError(malformed_message)
    return parsed


def _read_development_key_file(path: str | os.PathLike[str]) -> str:
    path_text = os.fspath(path)
    try:
        first_stat = os.lstat(path_text)
    except OSError as exc:
        raise RuntimeIdentityError("local development private key file is not readable") from exc
    if stat.S_ISLNK(first_stat.st_mode):
        raise RuntimeIdentityError("local development private key file must not be a symlink")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path_text, flags)
    except OSError as exc:
        raise RuntimeIdentityError("local development private key file is not readable") from exc
    try:
        current_stat = os.fstat(fd)
        if not stat.S_ISREG(current_stat.st_mode):
            raise RuntimeIdentityError("local development private key file must be a regular file")
        if current_stat.st_ino != first_stat.st_ino or current_stat.st_dev != first_stat.st_dev:
            raise RuntimeIdentityError("local development private key file changed during open")
        if current_stat.st_mode & 0o777 != 0o600:
            raise RuntimeIdentityError("local development private key file must be mode 0600")
        if hasattr(os, "getuid") and current_stat.st_uid != os.getuid():
            raise RuntimeIdentityError(
                "local development private key file must be owned by current user"
            )
        if current_stat.st_size <= 0 or current_stat.st_size > _MAX_DEV_KEY_FILE_BYTES:
            raise RuntimeIdentityError("local development private key file size is invalid")
        raw = os.read(fd, _MAX_DEV_KEY_FILE_BYTES + 1)
        if len(raw) > _MAX_DEV_KEY_FILE_BYTES:
            raise RuntimeIdentityError("local development private key file is too large")
    finally:
        os.close(fd)
    try:
        return raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise RuntimeIdentityError("local development private key file must be UTF-8") from exc


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except OSError:
        return
    try:
        try:
            os.fsync(fd)
        except OSError:
            return
    finally:
        os.close(fd)
