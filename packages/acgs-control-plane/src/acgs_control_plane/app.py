"""FastAPI application factory and REST API.

Layering per request:

1. **Authentication** — ``X-API-Key`` → :class:`Principal` (tenant-scoped).
2. **Tenant guard** — the ``org_id`` path segment must be the principal's
   org; anything else is 404 (no cross-tenant existence oracle).
3. **RBAC** — role → permission table; 403 on miss (no side effect, no
   receipt: nothing was governed because nothing was attempted).
4. **Governance membrane** — every mutation dispatches through the org's
   gove-zone kernel; the Decision Receipt commits atomically with the side
   effect. Policy DENY → 403 + receipt; ESCALATE → 202 + receipt.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Iterator
from datetime import datetime
from typing import Annotated, Any, cast

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from gove_zone.policy import RuleSetPolicy
from gove_zone.tool import ToolCall, normalize_path_context
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from acgs_control_plane.agent_registration import (
    AgentRegistrationHttpError,
    AgentRegistrationService,
    local_agent_registration_issuer,
    local_agent_registration_receipt_sealer,
)
from acgs_control_plane.api_contract import (
    RequestAdmissionMiddleware,
    has_json_decode_error,
    redacted_error,
    request_id_from_scope,
)
from acgs_control_plane.approvals import (
    ApprovalHttpError,
    ApprovalService,
    local_approval_payload_sealer,
)
from acgs_control_plane.auth import (
    API_KEY_HEADER,
    BOOTSTRAP_HEADER,
    Principal,
    generate_api_key,
    resolve_principal,
)
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.db import Base, make_engine, make_session_factory
from acgs_control_plane.exports import build_export_bundle
from acgs_control_plane.governance import (
    AuditReadError,
    GovernanceMembrane,
    PolicyDeniedError,
    PolicyEscalatedError,
    PostureBlocker,
    ProductionPostureBlocked,
    existing_org_audit_store,
    load_active_policy,
    production_blockers,
    reconcile_http_routes,
)
from acgs_control_plane.managed_mutations import ManagedReplayArtifactValidationError
from acgs_control_plane.migrations import (
    DatabaseSchemaState,
    SchemaPreflight,
    assert_current_startup_schema,
    inspect_connection,
    install_postgresql_application_connection_guard,
)
from acgs_control_plane.models import (
    AgentRecord,
    ComplianceExport,
    Environment,
    EnvironmentPolicyHead,
    Organization,
    PolicyBundle,
    PolicyVersion,
    ReceiptRow,
    RuntimeCredentialGeneration,
    RuntimeIdentity,
    RuntimeIdentityGate,
    RuntimeReport,
    RuntimeReportHead,
    RuntimeWiringAttestation,
    User,
    new_id,
    utcnow,
)
from acgs_control_plane.mutation_inventory import (
    MutationGuardedFastAPI,
    MutationInventoryDriftError,
    build_mutation_inventory_seal,
    mutation_inventory_drift_response,
)
from acgs_control_plane.pagination import (
    CURSOR_TOKEN_MAX_LENGTH,
    InvalidCursorError,
    decode_receipt_cursor,
    issue_receipt_cursor,
    receipt_filter_digest,
)
from acgs_control_plane.policy_registry import (
    PolicyRegistryHttpError,
    PolicyRegistryResult,
    PolicyRegistryService,
    local_policy_registry_issuer,
    local_policy_registry_receipt_sealer,
)
from acgs_control_plane.policy_sync import (
    PolicySyncAuth,
    PolicySyncService,
    local_policy_sync_attestation_issuer,
)
from acgs_control_plane.rbac import Permission, Role, role_allows
from acgs_control_plane.runtime_enrollment import (
    RuntimeBootstrapPepper,
    RuntimeEnrollmentHttpError,
    RuntimeEnrollmentService,
    _to_utc,
    local_runtime_bootstrap_pepper,
    local_runtime_descriptor_signer,
    local_runtime_enrollment_issuer,
    local_runtime_enrollment_receipt_sealer,
)
from acgs_control_plane.runtime_reports import (
    RuntimeReportAuth,
    RuntimeReportProviderUnavailable,
    RuntimeReportService,
)
from acgs_control_plane.schemas import (
    AgentRegisterRequest,
    AgentResponse,
    AgentStatusRequest,
    ApprovalVoteRequest,
    ApprovalVoteResponse,
    DashboardResponse,
    ExportCreateRequest,
    ExportDetail,
    ExportSummary,
    FleetResponse,
    FleetRuntime,
    FleetState,
    OrgCreateRequest,
    OrgCreateResponse,
    OrgResponse,
    PolicyActivateRequest,
    PolicyPublishRequest,
    PolicyResponse,
    PolicySyncSnapshot,
    ReceiptDetail,
    ReceiptListResponse,
    ReceiptSummary,
    ReceiptVerifyResponse,
    RuntimeAttestationChallengeResponse,
    RuntimeEnrollmentBootstrapCreateRequest,
    RuntimeEnrollmentBootstrapCreateResponse,
    RuntimeEnrollmentRequest,
    RuntimeEnrollmentResponse,
    RuntimeIdentityRevokeRequest,
    RuntimeReportRequest,
    RuntimeReportResponse,
    RuntimeSignedRequest,
    SimulateRequest,
    SimulateResponse,
    TenantBootstrapRequest,
    TenantBootstrapResponse,
    UserCreateRequest,
    UserCreateResponse,
    UserResponse,
    V1MetadataResponse,
)
from acgs_control_plane.tenant_bootstrap import (
    BOOTSTRAP_AUTHORIZATION_HEADER,
    BOOTSTRAP_IDEMPOTENCY_HEADER,
    BOOTSTRAP_INVITATION_HEADER,
    TenantBootstrapHttpError,
    TenantBootstrapService,
    local_bootstrap_issuer,
    local_bootstrap_secret_hasher,
    local_platform_bootstrap_authenticator,
    local_platform_trust_registry,
    local_receipt_sealer,
)

_TENANT_BOOTSTRAP_MAX_BODY_BYTES = 16 * 1024
_TENANT_BOOTSTRAP_PUBLIC_DETAILS = {
    "REQUEST_TOO_LARGE": "tenant bootstrap request body exceeds the allowed size",
    "REQUEST_MALFORMED": "tenant bootstrap request body is malformed",
    "AUTHENTICATION_REQUIRED": "platform bearer credential is required",
    "AUTHORIZATION_DENIED": "platform actor is not authorized for tenant bootstrap",
    "BOOTSTRAP_NOT_AUTHORIZED": "platform bootstrap invitation is not valid",
    "IDEMPOTENCY_KEY_INVALID": "idempotency key is invalid",
    "IDEMPOTENCY_CONFLICT": "idempotency key was already used for a different request",
    "SIGNER_UNAVAILABLE": "tenant bootstrap signer unavailable",
    "POLICY_DENIED": "tenant bootstrap policy denied the invitation",
    "ESCALATE_PENDING": "tenant bootstrap requires separated approval",
    "TX_ABORTED": "tenant bootstrap transaction aborted",
}
_TENANT_BOOTSTRAP_NO_STORE_HEADERS = {"Cache-Control": "no-store"}
_RUNTIME_ENROLLMENT_NO_STORE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}
_RUNTIME_ENROLLMENT_NO_STORE_PATH_PREFIXES = (
    "/v1/runtime-enrollments",
    "/v1/runtime-identities/",
)
_RUNTIME_ENROLLMENT_NO_STORE_PATH_SUFFIXES = (
    "/runtime-enrollment-bootstraps",
    "/revoke",
)

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


def _session_dep(request: Request) -> Iterator[Session]:
    session: Session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()


SessionDep = Annotated[Session, Depends(_session_dep)]


def _principal_dep(
    session: SessionDep,
    api_key: Annotated[str | None, Header(alias=API_KEY_HEADER)] = None,
) -> Principal:
    if not api_key:
        raise HTTPException(status_code=401, detail="missing API key")
    principal = resolve_principal(session, api_key)
    if principal is None:
        raise HTTPException(status_code=401, detail="invalid API key")
    return principal


PrincipalDep = Annotated[Principal, Depends(_principal_dep)]


async def _parse_tenant_bootstrap_body(request: Request) -> TenantBootstrapRequest:
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > _TENANT_BOOTSTRAP_MAX_BODY_BYTES:
            raise TenantBootstrapHttpError(
                413,
                "REQUEST_TOO_LARGE",
                "request_too_large",
                "tenant bootstrap request body exceeds the allowed size",
                stage="transport",
            )
        chunks.append(chunk)
    body = b"".join(chunks)
    try:
        payload = json.loads(body, object_pairs_hook=_reject_duplicate_json_keys)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise TenantBootstrapHttpError(
            400,
            "REQUEST_MALFORMED",
            "request_malformed",
            "tenant bootstrap request body is malformed",
            stage="transport",
        ) from exc
    try:
        return TenantBootstrapRequest.model_validate(payload)
    except ValidationError as exc:
        raise TenantBootstrapHttpError(
            400,
            "REQUEST_MALFORMED",
            "request_malformed",
            "tenant bootstrap request body is malformed",
            stage="transport",
        ) from exc


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError(f"duplicate JSON key: {key}")
        payload[key] = value
    return payload


class _TenantBootstrapRequestIdMiddleware:
    """Seed the tenant-bootstrap request id as pure ASGI middleware.

    ``@app.middleware("http")`` wraps the whole app in Starlette's
    ``BaseHTTPMiddleware``, which proxies receive/send through an anyio stream
    and mishandles a client disconnect mid-request. The bounded-admission tests
    assert real disconnect semantics, so that wrapper cannot stay on the stack.
    Pure ASGI middleware seeds the same ``request.state`` value -- ``Request.state``
    is backed by ``scope["state"]`` -- while leaving the channels untouched.

    It also stamps ``Cache-Control: no-store`` on every tenant-bootstrap
    response at ``http.response.start``, so success bodies carrying bootstrap
    receipts are never cached, matching the refusal handlers.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope.get("path") != "/v1/tenant-bootstrap":
            await self.app(scope, receive, send)
            return
        scope.setdefault("state", {})["tenant_bootstrap_request_id"] = secrets.token_hex(16)

        async def send_no_store(message: Any) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower() != b"cache-control"
                ]
                headers.append((b"cache-control", b"no-store"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_no_store)


class _RuntimeEnrollmentNoStoreMiddleware:
    """Stamp no-store headers on runtime enrollment and credential responses."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or not _is_runtime_enrollment_no_store_path(
            str(scope.get("path", ""))
        ):
            await self.app(scope, receive, send)
            return

        async def send_no_store(message: Any) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower() not in {b"cache-control", b"pragma"}
                ]
                headers.extend(
                    (name.lower().encode("ascii"), value.encode("ascii"))
                    for name, value in _RUNTIME_ENROLLMENT_NO_STORE_HEADERS.items()
                )
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_no_store)


def _is_runtime_enrollment_no_store_path(path: str) -> bool:
    return path.startswith(_RUNTIME_ENROLLMENT_NO_STORE_PATH_PREFIXES) or path.endswith(
        _RUNTIME_ENROLLMENT_NO_STORE_PATH_SUFFIXES
    )


def _record_tenant_bootstrap_refusal(request: Request, exc: TenantBootstrapHttpError) -> None:
    if request.url.path != "/v1/tenant-bootstrap":
        return
    if getattr(request.state, "tenant_bootstrap_refusal_recorded", False):
        return
    service = getattr(request.app.state, "tenant_bootstrap_service", None)
    request_id = getattr(request.state, "tenant_bootstrap_request_id", None)
    if service is None or not request_id:
        return
    request.state.tenant_bootstrap_refusal_recorded = True
    service.record_refusal(
        request_id=request_id,
        error=exc,
        invitation_secret=request.headers.get(BOOTSTRAP_INVITATION_HEADER),
        idempotency_key=request.headers.get(BOOTSTRAP_IDEMPOTENCY_HEADER),
    )


def _org_guard(org_id: str, principal: PrincipalDep, session: SessionDep) -> Organization:
    if org_id != principal.org_id:
        # 404, not 403: cross-tenant probing must not confirm existence.
        raise HTTPException(status_code=404, detail="organization not found")
    org = session.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="organization not found")
    return org


OrgDep = Annotated[Organization, Depends(_org_guard)]


def require(permission: Permission):
    def checker(principal: PrincipalDep) -> Principal:
        if not role_allows(principal.role, permission):
            raise HTTPException(
                status_code=403,
                detail=f"role {principal.role.value!r} lacks permission {permission.value!r}",
            )
        return principal

    return Depends(checker)


def _runtime_report_provider_unavailable() -> RuntimeEnrollmentHttpError:
    return RuntimeEnrollmentHttpError(
        503,
        "RUNTIME_REPORT_PROVIDER_UNAVAILABLE",
        "service_unavailable",
        "runtime report cryptographic provider is unavailable",
    )


def _runtime_report_auth(
    *,
    identity_id: str,
    runtime_identity_id: str | None,
    key_id: str | None,
    audience: str | None,
    credential_id: str | None,
    credential_generation: str | None,
    timestamp: str | None,
    nonce: str | None,
    body_sha256: str | None,
    signature: str | None,
) -> RuntimeReportAuth:
    values = {
        "runtime_identity_id": runtime_identity_id,
        "key_id": key_id,
        "audience": audience,
        "credential_id": credential_id,
        "credential_generation": credential_generation,
        "timestamp": timestamp,
        "nonce": nonce,
        "body_sha256": body_sha256,
        "signature": signature,
    }
    if any(value is None for value in values.values()) or runtime_identity_id != identity_id:
        raise RuntimeEnrollmentHttpError(
            401,
            "RUNTIME_AUTHENTICATION_FAILED",
            "unauthorized",
            "runtime authentication failed",
        )
    try:
        generation = int(cast(str, credential_generation))
    except ValueError as exc:
        raise RuntimeEnrollmentHttpError(
            401,
            "RUNTIME_AUTHENTICATION_FAILED",
            "unauthorized",
            "runtime authentication failed",
        ) from exc
    return RuntimeReportAuth(
        key_id=cast(str, key_id),
        credential_id=cast(str, credential_id),
        credential_generation=generation,
        audience=cast(str, audience),
        timestamp=cast(str, timestamp),
        nonce=cast(str, nonce),
        body_sha256=cast(str, body_sha256),
        signature=cast(str, signature),
    )


def _membrane(request: Request, session: Session, org: Organization, principal: Principal):
    settings: Settings = request.app.state.settings
    return GovernanceMembrane(session, settings.audit_dir, org.id, principal)


def _blocked_json(status_code: int, status: str, exc: Exception) -> JSONResponse:
    receipt = exc.receipt  # type: ignore[attr-defined]
    reason = exc.reason  # type: ignore[attr-defined]
    request = exc.__dict__.get("request")
    return JSONResponse(
        status_code=status_code,
        content={
            "status": status,
            "reason": reason,
            "receipt_id": receipt.id,
            "decision": receipt.decision,
            **(
                {"request_id": request_id_from_scope(request.scope)}
                if isinstance(request, Request)
                else {}
            ),
        },
    )


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app(
    settings: Settings | None = None,
    *,
    production_providers: tuple[Any, ...] = (),
    platform_bootstrap_issuer: Any | None = None,
    platform_bootstrap_authenticator: Any | None = None,
    platform_bootstrap_secret_hasher: Any | None = None,
    platform_bootstrap_trust_registry: Any | None = None,
    platform_receipt_sealer: Any | None = None,
    platform_bootstrap_receipt_issuer: Any | None = None,
    agent_registration_issuer: Any | None = None,
    agent_registration_receipt_sealer: Any | None = None,
    agent_registration_receipt_issuer: Any | None = None,
    policy_registry_issuer: Any | None = None,
    policy_registry_receipt_sealer: Any | None = None,
    policy_registry_receipt_issuer: Any | None = None,
    policy_sync_attestation_issuer: Any | None = None,
    approval_payload_sealer: Any | None = None,
    runtime_enrollment_issuer: Any | None = None,
    runtime_enrollment_receipt_sealer: Any | None = None,
    runtime_bootstrap_pepper: Any | None = None,
    runtime_descriptor_signer: Any | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    app = MutationGuardedFastAPI(
        title="ACGS Enterprise Governance Control Plane",
        version="0.1.0",
        description="Multi-tenant, receipt-gated governance management API. "
        "No valid Decision Receipt, no side effect.",
    )
    app.state.settings = settings
    app.add_middleware(
        RequestAdmissionMiddleware,
        max_request_body_bytes=settings.max_request_body_bytes,
    )

    @app.exception_handler(PolicyDeniedError)
    def _denied(request: Request, exc: PolicyDeniedError) -> JSONResponse:
        exc.__dict__["request"] = request
        return _blocked_json(403, "denied", exc)

    @app.exception_handler(PolicyEscalatedError)
    def _escalated(request: Request, exc: PolicyEscalatedError) -> JSONResponse:
        exc.__dict__["request"] = request
        return _blocked_json(202, "pending_approval", exc)

    @app.exception_handler(AuditReadError)
    def _audit_read_refused(request: Request, exc: AuditReadError) -> JSONResponse:
        request_id_from_scope(request.scope)
        return JSONResponse(
            status_code=503,
            content={"code": exc.code, "status": "audit-read-refused", "reason": exc.reason},
        )

    @app.exception_handler(HTTPException)
    def _http_error(request: Request, exc: HTTPException) -> JSONResponse:
        status_code = int(exc.status_code)
        code = "http_error"
        if status_code == 401:
            code = "unauthorized"
        elif status_code == 403:
            code = "forbidden"
        elif status_code == 404:
            code = "not_found"
        elif status_code == 409:
            code = "conflict"
        elif status_code == 422:
            code = "validation_error"
        elif status_code >= 500:
            code = "service_unavailable"
        return JSONResponse(
            status_code=status_code,
            content=redacted_error(code, request_id_from_scope(request.scope)),
            headers=dict(exc.headers or {}),
        )

    @app.exception_handler(InvalidCursorError)
    def _invalid_cursor(request: Request, exc: InvalidCursorError) -> JSONResponse:
        del exc
        return JSONResponse(
            status_code=400,
            content=redacted_error("invalid_cursor", request_id_from_scope(request.scope)),
            headers={"Cache-Control": "private, no-store"},
        )

    @app.exception_handler(MutationInventoryDriftError)
    def _mutation_inventory_drift(
        _request: Request, exc: MutationInventoryDriftError
    ) -> JSONResponse:
        return mutation_inventory_drift_response(exc)

    @app.exception_handler(TenantBootstrapHttpError)
    def _tenant_bootstrap_error(request: Request, exc: TenantBootstrapHttpError) -> JSONResponse:
        _record_tenant_bootstrap_refusal(request, exc)
        return JSONResponse(
            status_code=exc.status_code,
            headers=_TENANT_BOOTSTRAP_NO_STORE_HEADERS,
            content={
                "code": exc.code,
                "status": exc.status,
                "detail": _TENANT_BOOTSTRAP_PUBLIC_DETAILS.get(
                    exc.code, "tenant bootstrap request was refused"
                ),
            },
        )

    @app.exception_handler(AgentRegistrationHttpError)
    def _agent_registration_error(
        request: Request, exc: AgentRegistrationHttpError
    ) -> JSONResponse:
        # A policy DENY/ESCALATE carries its committed refusal receipt, so it
        # answers in the same receipted envelope the route used before agent
        # registration became a managed mutation. Every other refusal (bad
        # scope, untrusted key, aborted transaction, cross-tenant admission)
        # has no receipt to cite and stays redacted and flat.
        if exc.receipt_id is not None and exc.decision is not None:
            receipt_content: dict[str, Any] = {
                "status": exc.status,
                "reason": exc.detail,
                "receipt_id": exc.receipt_id,
                "decision": exc.decision,
                "request_id": request_id_from_scope(request.scope),
            }
            if exc.extra:
                receipt_content.update(exc.extra)
            return JSONResponse(
                status_code=exc.status_code,
                content=receipt_content,
            )
        error_content: dict[str, Any] = {
            "code": exc.code,
            "status": exc.status,
            "detail": exc.detail,
        }
        if exc.extra:
            error_content.update(exc.extra)
        return JSONResponse(
            status_code=exc.status_code,
            content=error_content,
        )

    @app.exception_handler(ApprovalHttpError)
    def _approval_error(_request: Request, exc: ApprovalHttpError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "code": exc.code,
                "status": exc.status,
                "detail": exc.detail,
            },
        )

    @app.exception_handler(PolicyRegistryHttpError)
    def _policy_registry_error(_request: Request, exc: PolicyRegistryHttpError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "code": exc.code,
                "status": exc.status,
                "detail": exc.detail,
            },
        )

    @app.exception_handler(RuntimeEnrollmentHttpError)
    def _runtime_enrollment_error(
        request: Request, exc: RuntimeEnrollmentHttpError
    ) -> JSONResponse:
        if exc.receipt_id is not None and exc.decision is not None:
            return JSONResponse(
                status_code=exc.status_code,
                content={
                    "status": exc.status,
                    "reason": exc.detail,
                    "receipt_id": exc.receipt_id,
                    "decision": exc.decision,
                    "request_id": request_id_from_scope(request.scope),
                },
            )
        return JSONResponse(
            status_code=exc.status_code,
            content={"code": exc.code, "status": exc.status, "detail": exc.detail},
        )

    # One handler per exception type wins in FastAPI, so the tenant-bootstrap
    # refusal recording (master) and the redacted admission errors (this branch)
    # have to live in the same function rather than one replacing the other.
    @app.exception_handler(RequestValidationError)
    def _request_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        if request.url.path == "/v1/tenant-bootstrap":
            _record_tenant_bootstrap_refusal(
                request,
                TenantBootstrapHttpError(
                    400,
                    "REQUEST_MALFORMED",
                    "request_malformed",
                    "tenant bootstrap request body is malformed",
                    stage="transport",
                ),
            )
            return JSONResponse(
                status_code=400,
                headers=_TENANT_BOOTSTRAP_NO_STORE_HEADERS,
                content={
                    "code": "REQUEST_MALFORMED",
                    "status": "request_malformed",
                    "detail": "tenant bootstrap request body is malformed",
                },
            )
        errors = exc.errors()
        code = "malformed_json" if has_json_decode_error(errors) else "validation_error"
        status_code = 400 if code == "malformed_json" else 422
        return JSONResponse(
            status_code=status_code,
            content=redacted_error(code, request_id_from_scope(request.scope)),
        )

    app.add_middleware(_RuntimeEnrollmentNoStoreMiddleware)
    app.add_middleware(_TenantBootstrapRequestIdMiddleware)

    @app.exception_handler(Exception)
    def _tenant_bootstrap_fail_closed_error(request: Request, _exc: Exception) -> JSONResponse:
        if request.url.path == "/v1/tenant-bootstrap":
            error = TenantBootstrapHttpError(
                503,
                "TX_ABORTED",
                "tx_aborted",
                "tenant bootstrap transaction aborted",
                stage="tx",
            )
            _record_tenant_bootstrap_refusal(request, error)
            return JSONResponse(
                status_code=503,
                headers=_TENANT_BOOTSTRAP_NO_STORE_HEADERS,
                content={
                    "code": "TX_ABORTED",
                    "status": "tx_aborted",
                    "detail": _TENANT_BOOTSTRAP_PUBLIC_DETAILS["TX_ABORTED"],
                },
            )
        raise _exc

    _register_routes(app)
    _install_v1_aliases(app)
    # Reconcile the concrete Starlette APIRoute surface. WebSockets and other
    # protocol Route types are intentionally outside this HTTP contract.
    from starlette.routing import Route

    actual = tuple(
        (method, route.path)
        for route in app.routes
        if isinstance(route, APIRoute)
        for method in sorted(route.methods or ())
    )
    protocol = tuple(
        (method, route.path)
        for route in app.routes
        if isinstance(route, Route) and not isinstance(route, APIRoute)
        for method in sorted(route.methods or ())
    )
    drift = reconcile_http_routes(actual, protocol)
    unsupported = tuple(
        sorted(
            f"{type(route).__name__} {getattr(route, 'path', getattr(route, 'host', '<unknown>'))}"
            for route in app.routes
            if not isinstance(route, Route)
        )
    )
    if unsupported:
        drift = (
            *drift,
            *(
                PostureBlocker("UNCLASSIFIED_ACTIVE_SURFACE", "route-registry", surface)
                for surface in unsupported
            ),
        )
    if drift:
        raise ProductionPostureBlocked(drift)
    if settings.runtime_posture is None:
        raise ProductionPostureBlocked(
            (
                # Missing posture is refused before engine/provider construction.
                PostureBlocker("RUNTIME_POSTURE_REQUIRED", "runtime-posture"),
            )
        )
    if not isinstance(settings.runtime_posture, RuntimePosture):
        raise ProductionPostureBlocked(
            (PostureBlocker("RUNTIME_POSTURE_UNKNOWN", "runtime-posture"),)
        )
    if settings.runtime_posture is RuntimePosture.PRODUCTION and settings.create_tables:
        raise ProductionPostureBlocked(
            (
                PostureBlocker(
                    "PRODUCTION_SCHEMA_BOOTSTRAP_FORBIDDEN",
                    "schema-bootstrap",
                ),
            )
        )
    blockers = production_blockers(drift, production_providers)
    if (
        settings.runtime_posture is RuntimePosture.PRODUCTION
        and policy_sync_attestation_issuer is None
    ):
        blockers = tuple(
            sorted(
                (
                    *blockers,
                    PostureBlocker(
                        "POLICY_SYNC_ATTESTATION_PROVIDER_REQUIRED",
                        "policy-sync-attestation-provider",
                    ),
                )
            )
        )
    app.state.readiness_blockers = blockers
    if settings.runtime_posture is RuntimePosture.PRODUCTION:
        raise ProductionPostureBlocked(blockers)
    engine = make_engine(settings.database_url)
    install_postgresql_application_connection_guard(engine)
    try:
        if settings.create_tables:
            # Deliberately retained only for disposable legacy development
            # fixtures. Production is rejected above before engine creation.
            Base.metadata.create_all(engine)
        with engine.connect() as connection:
            if settings.create_tables:
                schema_preflight = inspect_connection(connection)
            else:
                schema_preflight = assert_current_startup_schema(connection)
    except BaseException:
        engine.dispose()
        raise
    app.state.engine = engine
    app.state.schema_preflight = schema_preflight
    app.state.session_factory = make_session_factory(engine)
    bootstrap_issuer = platform_bootstrap_issuer or local_bootstrap_issuer()
    bootstrap_authenticator = (
        platform_bootstrap_authenticator or local_platform_bootstrap_authenticator()
    )
    bootstrap_secret_hasher = platform_bootstrap_secret_hasher or local_bootstrap_secret_hasher()
    bootstrap_trust_registry = platform_bootstrap_trust_registry or local_platform_trust_registry()
    bootstrap_receipt_sealer = platform_receipt_sealer or local_receipt_sealer()
    app.state.tenant_bootstrap_service = TenantBootstrapService(
        app.state.session_factory,
        issuer=bootstrap_issuer,
        receipt_sealer=bootstrap_receipt_sealer,
        authenticator=bootstrap_authenticator,
        secret_hasher=bootstrap_secret_hasher,
        trust_registry=bootstrap_trust_registry,
        receipt_issuer=platform_bootstrap_receipt_issuer,
    )
    if settings.runtime_posture is RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED:
        effective_agent_registration_issuer = (
            agent_registration_issuer or local_agent_registration_issuer()
        )
        effective_agent_registration_receipt_sealer = (
            agent_registration_receipt_sealer or local_agent_registration_receipt_sealer()
        )
        effective_approval_payload_sealer = (
            approval_payload_sealer or local_approval_payload_sealer()
        )
    else:
        if (
            agent_registration_issuer is None
            or agent_registration_receipt_sealer is None
            or approval_payload_sealer is None
        ):
            raise ProductionPostureBlocked(
                (
                    PostureBlocker(
                        "AGENT_REGISTRATION_PROVIDER_REQUIRED",
                        "agent-registration-provider",
                    ),
                )
            )
        effective_agent_registration_issuer = agent_registration_issuer
        effective_agent_registration_receipt_sealer = agent_registration_receipt_sealer
        effective_approval_payload_sealer = approval_payload_sealer
    app.state.agent_registration_service = AgentRegistrationService(
        app.state.session_factory,
        issuer=effective_agent_registration_issuer,
        receipt_sealer=effective_agent_registration_receipt_sealer,
        approval_payload_sealer=effective_approval_payload_sealer,
        receipt_issuer=agent_registration_receipt_issuer,
    )
    app.state.approval_service = ApprovalService(
        app.state.session_factory,
        issuer=effective_agent_registration_issuer,
        receipt_sealer=effective_agent_registration_receipt_sealer,
        payload_sealer=effective_approval_payload_sealer,
    )
    if settings.runtime_posture is RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED:
        effective_policy_registry_issuer = policy_registry_issuer or local_policy_registry_issuer()
        effective_policy_registry_receipt_sealer = (
            policy_registry_receipt_sealer or local_policy_registry_receipt_sealer()
        )
    else:
        if policy_registry_issuer is None or policy_registry_receipt_sealer is None:
            raise ProductionPostureBlocked(
                (
                    PostureBlocker(
                        "POLICY_REGISTRY_PROVIDER_REQUIRED",
                        "policy-registry-provider",
                    ),
                )
            )
        effective_policy_registry_issuer = policy_registry_issuer
        effective_policy_registry_receipt_sealer = policy_registry_receipt_sealer
    if settings.runtime_posture is RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED:
        effective_policy_sync_attestation_issuer = (
            policy_sync_attestation_issuer or local_policy_sync_attestation_issuer()
        )
    else:
        if policy_sync_attestation_issuer is None:
            raise ProductionPostureBlocked(
                (
                    PostureBlocker(
                        "POLICY_SYNC_ATTESTATION_PROVIDER_REQUIRED",
                        "policy-sync-attestation-provider",
                    ),
                )
            )
        effective_policy_sync_attestation_issuer = policy_sync_attestation_issuer
    if (
        effective_policy_sync_attestation_issuer is effective_policy_registry_issuer
        or effective_policy_sync_attestation_issuer.key_id
        == effective_policy_registry_issuer.key_id
    ):
        engine.dispose()
        raise ProductionPostureBlocked(
            (
                PostureBlocker(
                    "POLICY_SYNC_ATTESTATION_PROVIDER_REUSED",
                    "policy-sync-attestation-provider",
                ),
            )
        )
    app.state.policy_registry_service = PolicyRegistryService(
        app.state.session_factory,
        issuer=effective_policy_registry_issuer,
        receipt_sealer=effective_policy_registry_receipt_sealer,
        receipt_issuer=policy_registry_receipt_issuer,
    )
    if settings.runtime_posture is RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED:
        effective_runtime_issuer = runtime_enrollment_issuer or local_runtime_enrollment_issuer()
        effective_runtime_receipt_sealer = (
            runtime_enrollment_receipt_sealer or local_runtime_enrollment_receipt_sealer()
        )
        effective_runtime_bootstrap_pepper = (
            runtime_bootstrap_pepper or local_runtime_bootstrap_pepper()
        )
        effective_runtime_descriptor_signer = (
            runtime_descriptor_signer or local_runtime_descriptor_signer()
        )
    else:
        if (
            runtime_enrollment_issuer is None
            or runtime_enrollment_receipt_sealer is None
            or runtime_bootstrap_pepper is None
            or runtime_descriptor_signer is None
        ):
            raise ProductionPostureBlocked(
                (
                    PostureBlocker(
                        "RUNTIME_ENROLLMENT_PROVIDER_REQUIRED",
                        "runtime-enrollment-provider",
                    ),
                )
            )
        effective_runtime_issuer = runtime_enrollment_issuer
        effective_runtime_receipt_sealer = runtime_enrollment_receipt_sealer
        effective_runtime_bootstrap_pepper = runtime_bootstrap_pepper
        effective_runtime_descriptor_signer = runtime_descriptor_signer
    app.state.runtime_enrollment_service = RuntimeEnrollmentService(
        app.state.session_factory,
        issuer=effective_runtime_issuer,
        receipt_sealer=effective_runtime_receipt_sealer,
        bootstrap_pepper=cast(RuntimeBootstrapPepper, effective_runtime_bootstrap_pepper),
        descriptor_signer=effective_runtime_descriptor_signer,
    )
    app.state.runtime_report_service = RuntimeReportService(
        app.state.session_factory,
        runtime_enrollment_service=app.state.runtime_enrollment_service,
        descriptor_signer=effective_runtime_descriptor_signer,
    )
    app.state.policy_sync_service = PolicySyncService(
        app.state.session_factory,
        attestation_issuer=effective_policy_sync_attestation_issuer,
        policy_registry_issuer=effective_policy_registry_issuer,
        receipt_sealer=effective_policy_registry_receipt_sealer,
        descriptor_signer=effective_runtime_descriptor_signer,
    )
    try:
        app.state.mutation_inventory_seal = build_mutation_inventory_seal(app)
    except BaseException:
        engine.dispose()
        raise

    async def _dispose_engine() -> None:
        app.state.engine.dispose()

    app.router.add_event_handler("shutdown", _dispose_engine)
    return app


def _register_routes(app: FastAPI) -> None:
    # -- health ------------------------------------------------------------

    @app.get("/healthz", tags=["meta"])
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", tags=["meta"])
    def readyz(request: Request) -> JSONResponse:
        preflight: SchemaPreflight = request.app.state.schema_preflight
        schema_current = preflight.state is DatabaseSchemaState.VERSION_0012
        blockers: tuple[PostureBlocker, ...] = request.app.state.readiness_blockers
        return JSONResponse(
            status_code=503,
            content={
                "code": ProductionPostureBlocked.code,
                "stage": ProductionPostureBlocked.stage,
                "status": "not-production-ready",
                "blockers": [b.to_dict() for b in blockers],
                "schema_current": schema_current,
                "schema_state": preflight.state.value,
            },
        )

    @app.get(
        "/v1",
        response_model=V1MetadataResponse,
        tags=["meta"],
        operation_id="get_v1_metadata",
    )
    def v1_metadata() -> V1MetadataResponse:
        return V1MetadataResponse(
            api_version="v1",
            status="local-dev-legacy-alias",
            aliased_from="/orgs",
        )

    # -- organizations (bootstrap) ------------------------------------------

    @app.post(
        "/v1/tenant-bootstrap",
        response_model=TenantBootstrapResponse,
        status_code=201,
        tags=["tenant-bootstrap"],
    )
    async def tenant_bootstrap(
        request: Request,
        authorization: Annotated[str | None, Header(alias=BOOTSTRAP_AUTHORIZATION_HEADER)] = None,
        invitation_secret: Annotated[str | None, Header(alias=BOOTSTRAP_INVITATION_HEADER)] = None,
        idempotency_key: Annotated[str | None, Header(alias=BOOTSTRAP_IDEMPOTENCY_HEADER)] = None,
    ) -> TenantBootstrapResponse:
        body = await _parse_tenant_bootstrap_body(request)
        service: TenantBootstrapService = request.app.state.tenant_bootstrap_service
        return service.bootstrap(
            body=body,
            authorization=authorization,
            invitation_secret=invitation_secret,
            idempotency_key=idempotency_key,
        )

    @app.post("/orgs", response_model=OrgCreateResponse, status_code=201, tags=["orgs"])
    def create_org(
        body: OrgCreateRequest,
        request: Request,
        session: SessionDep,
        bootstrap_token: Annotated[str | None, Header(alias=BOOTSTRAP_HEADER)] = None,
    ) -> OrgCreateResponse:
        settings: Settings = request.app.state.settings
        if settings.bootstrap_token is None:
            raise HTTPException(status_code=503, detail="organization creation is disabled")
        if not bootstrap_token or not secrets.compare_digest(
            bootstrap_token, settings.bootstrap_token
        ):
            raise HTTPException(status_code=401, detail="invalid bootstrap token")
        exists = session.execute(
            select(Organization).where(Organization.name == body.name)
        ).scalar_one_or_none()
        if exists is not None:
            raise HTTPException(status_code=409, detail="organization name already exists")

        # Genesis dispatch: the org/admin rows are created INSIDE the governed
        # callback (like every other mutation), so a non-ALLOW decision rolls
        # back cleanly — no org, no admin, no dangling receipt FK. IDs are
        # pre-generated because the membrane (audit chain file, actor id)
        # needs them before the rows exist.
        org_id = new_id()
        admin_id = new_id()
        raw_key, key_hash = generate_api_key()

        def _do(name: str, admin_email: str) -> dict[str, str]:
            session.add(Organization(id=org_id, name=name))
            session.flush()
            session.add(
                User(
                    id=admin_id,
                    org_id=org_id,
                    name=body.admin_name,
                    email=admin_email,
                    role=Role.ORG_ADMIN.value,
                    api_key_hash=key_hash,
                )
            )
            session.flush()
            return {"org_id": org_id, "admin_user_id": admin_id}

        principal = Principal(
            user_id=admin_id, org_id=org_id, name=body.admin_name, role=Role.ORG_ADMIN
        )
        membrane = GovernanceMembrane(session, settings.audit_dir, org_id, principal)
        # persist_blocked_row=False: on DENY/ESCALATE the org itself is rolled
        # back, so a DB receipt row would dangle; the decision stays on the
        # org's audit chain file.
        membrane.run(
            "org.create",
            {"name": body.name, "admin_email": str(body.admin_email)},
            _do,
            goal="bootstrap organization",
            path=["control-plane", "orgs"],
            persist_blocked_row=False,
        )
        return OrgCreateResponse(
            org_id=org_id, name=body.name, admin_user_id=admin_id, admin_api_key=raw_key
        )

    @app.get("/orgs/{org_id}", response_model=OrgResponse, tags=["orgs"])
    def get_org(org: OrgDep, _p: Annotated[Principal, require(Permission.ORG_READ)]) -> OrgResponse:
        return OrgResponse(
            org_id=org.id,
            name=org.name,
            created_at=org.created_at,
            audit_anchor_count=org.audit_anchor_count,
            audit_anchor_hash=org.audit_anchor_hash,
        )

    # -- users ---------------------------------------------------------------

    @app.post(
        "/orgs/{org_id}/users",
        response_model=UserCreateResponse,
        status_code=201,
        tags=["users"],
    )
    def create_user(
        body: UserCreateRequest,
        org: OrgDep,
        request: Request,
        session: SessionDep,
        principal: Annotated[Principal, require(Permission.USER_MANAGE)],
    ) -> UserCreateResponse:
        dup = session.execute(
            select(User).where(User.org_id == org.id, User.email == str(body.email))
        ).scalar_one_or_none()
        if dup is not None:
            raise HTTPException(status_code=409, detail="email already exists in org")

        created: dict[str, str] = {}

        def _do(name: str, email: str, role: str) -> dict[str, str]:
            raw_key, key_hash = generate_api_key()
            user = User(org_id=org.id, name=name, email=email, role=role, api_key_hash=key_hash)
            session.add(user)
            session.flush()
            created["user_id"] = user.id
            created["api_key"] = raw_key
            return {"user_id": user.id}

        membrane = _membrane(request, session, org, principal)
        outcome = membrane.run(
            "user.create",
            {"name": body.name, "email": str(body.email), "role": body.role.value},
            _do,
            goal="provision control-plane user",
            path=["control-plane", "users"],
        )
        return UserCreateResponse(
            user_id=created["user_id"],
            org_id=org.id,
            name=body.name,
            email=str(body.email),
            role=body.role,
            api_key=created["api_key"],
            receipt_id=outcome.receipt.id,
        )

    @app.get("/orgs/{org_id}/users", response_model=list[UserResponse], tags=["users"])
    def list_users(
        org: OrgDep,
        session: SessionDep,
        _p: Annotated[Principal, require(Permission.USER_READ)],
    ) -> list[UserResponse]:
        users = session.execute(
            select(User).where(User.org_id == org.id).order_by(User.created_at.asc())
        ).scalars()
        return [
            UserResponse(
                user_id=u.id,
                name=u.name,
                email=u.email,
                role=Role(u.role),
                active=u.active,
                created_at=u.created_at,
            )
            for u in users
        ]

    # -- agent registry -------------------------------------------------------

    @app.post(
        "/orgs/{org_id}/agents",
        response_model=AgentResponse,
        status_code=201,
        tags=["agents"],
    )
    def register_agent(
        body: AgentRegisterRequest,
        org: OrgDep,
        request: Request,
        _session: SessionDep,
        principal: Annotated[Principal, require(Permission.AGENT_REGISTER)],
        idempotency_key: Annotated[str | None, Header(alias=BOOTSTRAP_IDEMPOTENCY_HEADER)] = None,
    ) -> AgentResponse:
        service: AgentRegistrationService = request.app.state.agent_registration_service
        result = service.register(
            org_id=org.id,
            principal=principal,
            audit_dir=request.app.state.settings.audit_dir,
            body=body,
            idempotency_key=idempotency_key,
        )
        return AgentResponse(
            agent_id=result.agent_id,
            org_id=result.org_id,
            name=result.name,
            description=result.description,
            trust_tier=result.trust_tier,
            allowed_tools=result.allowed_tools,
            status=result.status,
            created_at=result.created_at,
            receipt_id=result.receipt_id,
        )

    @app.get("/orgs/{org_id}/agents", response_model=list[AgentResponse], tags=["agents"])
    def list_agents(
        org: OrgDep,
        session: SessionDep,
        _p: Annotated[Principal, require(Permission.AGENT_READ)],
    ) -> list[AgentResponse]:
        agents = session.execute(
            select(AgentRecord)
            .where(AgentRecord.org_id == org.id)
            .order_by(AgentRecord.created_at.asc())
        ).scalars()
        return [_agent_response(a) for a in agents]

    @app.get("/orgs/{org_id}/agents/{agent_id}", response_model=AgentResponse, tags=["agents"])
    def get_agent(
        agent_id: str,
        org: OrgDep,
        session: SessionDep,
        _p: Annotated[Principal, require(Permission.AGENT_READ)],
    ) -> AgentResponse:
        rec = _get_agent_or_404(session, org.id, agent_id)
        return _agent_response(rec)

    @app.patch(
        "/orgs/{org_id}/agents/{agent_id}/status",
        response_model=AgentResponse,
        tags=["agents"],
    )
    def set_agent_status(
        agent_id: str,
        body: AgentStatusRequest,
        org: OrgDep,
        request: Request,
        session: SessionDep,
        principal: Annotated[Principal, require(Permission.AGENT_MANAGE)],
    ) -> AgentResponse:
        rec = _get_agent_or_404(session, org.id, agent_id)

        def _do(agent_id: str, status: str) -> dict[str, str]:
            rec.status = status
            session.flush()
            return {"agent_id": agent_id, "status": status}

        membrane = _membrane(request, session, org, principal)
        outcome = membrane.run(
            "agent.set_status",
            {"agent_id": agent_id, "status": body.status},
            _do,
            goal="change agent lifecycle status",
            path=["control-plane", "agents"],
            state={"trust_tier": rec.trust_tier},
        )
        return _agent_response(rec, receipt_id=outcome.receipt.id)

    # -- runtime identity enrollment ----------------------------------------

    @app.get(
        "/v1/runtime-identities/{identity_id}/attestation-challenges",
        response_model=RuntimeAttestationChallengeResponse,
        tags=["runtime-identities"],
        operation_id="runtime-attestation-challenge.issue",
    )
    def issue_runtime_attestation_challenge(
        identity_id: str,
        request: Request,
        runtime_build_digest: Annotated[str, Query(pattern=r"^[0-9a-f]{64}$")],
        configuration_digest: Annotated[str, Query(pattern=r"^[0-9a-f]{64}$")],
        policy_snapshot_hash: Annotated[str, Query(pattern=r"^[0-9a-f]{64}$")],
        runtime_identity_id: Annotated[
            str | None, Header(alias="X-ACGS-Runtime-Identity-ID")
        ] = None,
        key_id: Annotated[str | None, Header(alias="X-ACGS-Runtime-Key-ID")] = None,
        audience: Annotated[str | None, Header(alias="X-ACGS-Runtime-Audience")] = None,
        credential_id: Annotated[str | None, Header(alias="X-ACGS-Runtime-Credential-ID")] = None,
        credential_generation: Annotated[
            str | None, Header(alias="X-ACGS-Runtime-Credential-Generation")
        ] = None,
        timestamp: Annotated[str | None, Header(alias="X-ACGS-Runtime-Timestamp")] = None,
        nonce: Annotated[str | None, Header(alias="X-ACGS-Runtime-Nonce")] = None,
        body_sha256: Annotated[str | None, Header(alias="X-ACGS-Runtime-Body-Sha256")] = None,
        signature: Annotated[str | None, Header(alias="X-ACGS-Runtime-Signature")] = None,
    ) -> RuntimeAttestationChallengeResponse:
        auth = _runtime_report_auth(
            identity_id=identity_id,
            runtime_identity_id=runtime_identity_id,
            key_id=key_id,
            audience=audience,
            credential_id=credential_id,
            credential_generation=credential_generation,
            timestamp=timestamp,
            nonce=nonce,
            body_sha256=body_sha256,
            signature=signature,
        )
        service: RuntimeReportService = request.app.state.runtime_report_service
        try:
            return service.issue_challenge(
                identity_id=identity_id,
                auth=auth,
                raw_path=request.scope.get("raw_path", b""),
                raw_query=request.url.query,
                runtime_build_digest=runtime_build_digest,
                configuration_digest=configuration_digest,
                policy_snapshot_hash=policy_snapshot_hash,
            )
        except RuntimeReportProviderUnavailable as exc:
            raise _runtime_report_provider_unavailable() from exc

    @app.post(
        "/v1/runtime-identities/{identity_id}/reports",
        response_model=RuntimeReportResponse,
        status_code=201,
        tags=["runtime-identities"],
        operation_id="runtime-report.accept",
    )
    async def accept_runtime_report(
        identity_id: str,
        body: RuntimeReportRequest,
        request: Request,
        runtime_identity_id: Annotated[
            str | None, Header(alias="X-ACGS-Runtime-Identity-ID")
        ] = None,
        key_id: Annotated[str | None, Header(alias="X-ACGS-Runtime-Key-ID")] = None,
        audience: Annotated[str | None, Header(alias="X-ACGS-Runtime-Audience")] = None,
        credential_id: Annotated[str | None, Header(alias="X-ACGS-Runtime-Credential-ID")] = None,
        credential_generation: Annotated[
            str | None, Header(alias="X-ACGS-Runtime-Credential-Generation")
        ] = None,
        timestamp: Annotated[str | None, Header(alias="X-ACGS-Runtime-Timestamp")] = None,
        nonce: Annotated[str | None, Header(alias="X-ACGS-Runtime-Nonce")] = None,
        body_sha256: Annotated[str | None, Header(alias="X-ACGS-Runtime-Body-Sha256")] = None,
        signature: Annotated[str | None, Header(alias="X-ACGS-Runtime-Signature")] = None,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> RuntimeReportResponse:
        auth = _runtime_report_auth(
            identity_id=identity_id,
            runtime_identity_id=runtime_identity_id,
            key_id=key_id,
            audience=audience,
            credential_id=credential_id,
            credential_generation=credential_generation,
            timestamp=timestamp,
            nonce=nonce,
            body_sha256=body_sha256,
            signature=signature,
        )
        service: RuntimeReportService = request.app.state.runtime_report_service
        try:
            return service.accept(
                identity_id=identity_id,
                auth=auth,
                body=body,
                raw_body=await request.body(),
                raw_path=request.scope.get("raw_path", b""),
                idempotency_key=idempotency_key,
            )
        except RuntimeReportProviderUnavailable as exc:
            raise _runtime_report_provider_unavailable() from exc

    @app.get(
        "/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/fleet",
        response_model=FleetResponse,
        tags=["runtime-identities"],
        operation_id="runtime-fleet.read",
    )
    def get_runtime_fleet(
        project_id: str,
        environment_id: str,
        org: OrgDep,
        response: Response,
        session: SessionDep,
        _principal: Annotated[Principal, require(Permission.RUNTIME_FLEET_READ)],
        cursor: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> FleetResponse:
        environment = session.scalars(
            select(Environment).where(
                Environment.org_id == org.id,
                Environment.project_id == project_id,
                Environment.id == environment_id,
            )
        ).one_or_none()
        if environment is None:
            raise HTTPException(status_code=404, detail="environment not found")
        response.headers["Cache-Control"] = "private, no-store"
        now = utcnow()
        identity_stmt = select(RuntimeIdentity).where(
            RuntimeIdentity.org_id == org.id,
            RuntimeIdentity.project_id == project_id,
            RuntimeIdentity.environment_id == environment_id,
        )
        if cursor is not None:
            identity_stmt = identity_stmt.where(RuntimeIdentity.id > cursor)
        identity_page = list(
            session.scalars(identity_stmt.order_by(RuntimeIdentity.id).limit(limit + 1))
        )
        next_cursor = identity_page[limit - 1].id if len(identity_page) > limit else None
        identities = identity_page[:limit]
        identity_ids = [identity.id for identity in identities]
        gate_ids = [identity.gate_id for identity in identities]
        gates = {
            gate.id: gate
            for gate in session.scalars(
                select(RuntimeIdentityGate).where(RuntimeIdentityGate.id.in_(gate_ids))
            )
        }
        credentials = {
            credential.identity_id: credential
            for credential in session.scalars(
                select(RuntimeCredentialGeneration).where(
                    RuntimeCredentialGeneration.org_id == org.id,
                    RuntimeCredentialGeneration.project_id == project_id,
                    RuntimeCredentialGeneration.environment_id == environment_id,
                    RuntimeCredentialGeneration.identity_id.in_(identity_ids),
                    RuntimeCredentialGeneration.status == "active",
                )
            )
        }
        head = session.scalars(
            select(EnvironmentPolicyHead).where(
                EnvironmentPolicyHead.org_id == org.id,
                EnvironmentPolicyHead.project_id == project_id,
                EnvironmentPolicyHead.environment_id == environment_id,
            )
        ).one_or_none()
        active_policy = (
            session.get(PolicyVersion, head.active_policy_version_id) if head is not None else None
        )
        report_heads = {
            head.identity_id: head
            for head in session.scalars(
                select(RuntimeReportHead).where(
                    RuntimeReportHead.org_id == org.id,
                    RuntimeReportHead.project_id == project_id,
                    RuntimeReportHead.environment_id == environment_id,
                    RuntimeReportHead.identity_id.in_(identity_ids),
                )
            )
        }
        latest_report_ids = [head.latest_report_id for head in report_heads.values()]
        latest_reports = {
            report.identity_id: report
            for report in session.scalars(
                select(RuntimeReport).where(
                    RuntimeReport.org_id == org.id,
                    RuntimeReport.project_id == project_id,
                    RuntimeReport.environment_id == environment_id,
                    RuntimeReport.id.in_(latest_report_ids),
                )
            )
        }
        latest_wiring_ids = [
            head.latest_wiring_report_id
            for head in report_heads.values()
            if head.latest_wiring_report_id is not None
        ]
        wiring_reports = {
            report.identity_id: report
            for report in session.scalars(
                select(RuntimeReport).where(
                    RuntimeReport.org_id == org.id,
                    RuntimeReport.project_id == project_id,
                    RuntimeReport.environment_id == environment_id,
                    RuntimeReport.kind == "wiring",
                    RuntimeReport.id.in_(latest_wiring_ids),
                )
            )
        }
        wiring_report_ids = [report.id for report in wiring_reports.values()]
        wiring_evidence_by_report = {
            evidence.report_id: evidence
            for evidence in session.scalars(
                select(RuntimeWiringAttestation).where(
                    RuntimeWiringAttestation.report_id.in_(wiring_report_ids)
                )
            )
        }
        identity_by_id = {identity.id: identity for identity in identities}
        lineage_pairs = [
            (report, identity_by_id[report.identity_id])
            for report in {
                report.id: report for report in (*latest_reports.values(), *wiring_reports.values())
            }.values()
            if report.identity_id in identity_by_id
        ]
        try:
            lineage_valid_by_report_id = (
                app.state.runtime_report_service.validate_stored_report_lineages(
                    session, reports=lineage_pairs, now=now
                )
                if lineage_pairs
                else {}
            )
        except RuntimeReportProviderUnavailable as exc:
            raise _runtime_report_provider_unavailable() from exc
        runtimes: list[FleetRuntime] = []
        report_service: RuntimeReportService = app.state.runtime_report_service
        for identity in identities:
            gate = gates.get(identity.gate_id)
            credential = credentials.get(identity.id)
            report_head = report_heads.get(identity.id)
            latest_report = latest_reports.get(identity.id)
            wiring_report = wiring_reports.get(identity.id)
            registered = True
            identity_active = identity.status == "active"
            current_identity_binding_valid = False
            if identity_active and credential is not None:
                try:
                    report_service.validate_current_identity_binding(
                        identity=identity,
                        credential=credential,
                        now=now,
                    )
                except RuntimeReportProviderUnavailable as exc:
                    raise _runtime_report_provider_unavailable() from exc
                except ManagedReplayArtifactValidationError:
                    pass
                else:
                    current_identity_binding_valid = True
            latest_lineage_valid = False
            wiring_lineage_valid = False
            if report_head is not None and latest_report is not None:
                latest_lineage_valid = (
                    report_head.last_sequence == latest_report.sequence
                    and report_head.latest_report_id == latest_report.id
                    and report_head.latest_report_hash == latest_report.report_hash
                    and report_head.latest_projection_commitment
                    == latest_report.projection_commitment
                )
                latest_lineage_valid = latest_lineage_valid and lineage_valid_by_report_id.get(
                    latest_report.id, False
                )
            if report_head is not None and wiring_report is not None:
                wiring_lineage_valid = (
                    report_head.latest_wiring_kind == "wiring"
                    and report_head.latest_wiring_sequence == wiring_report.sequence
                    and report_head.latest_wiring_report_id == wiring_report.id
                    and report_head.latest_wiring_report_hash == wiring_report.report_hash
                    and report_head.latest_wiring_projection_commitment
                    == wiring_report.projection_commitment
                )
                wiring_lineage_valid = wiring_lineage_valid and lineage_valid_by_report_id.get(
                    wiring_report.id, False
                )
            runtime_binding_current = (
                current_identity_binding_valid
                and gate is not None
                and gate.status == "active"
                and credential is not None
                and credential.status == "active"
                and credential.generation == identity.current_generation
                and _to_utc(credential.not_before) <= now < _to_utc(credential.not_after)
            )
            report_current = (
                runtime_binding_current
                and latest_lineage_valid
                and latest_report is not None
                and now < _to_utc(latest_report.expires_at)
            )
            report_policy_current = False
            if (
                runtime_binding_current
                and report_current
                and latest_report is not None
                and head is not None
                and active_policy is not None
                and credential is not None
            ):
                report_policy_current = (
                    latest_report.policy_version_id == head.active_policy_version_id
                    and latest_report.policy_head_generation == head.generation
                    and latest_report.policy_content_hash == active_policy.content_hash
                    and now < _to_utc(latest_report.policy_fresh_until)
                    and now < _to_utc(latest_report.policy_expires_at)
                    and latest_report.credential_id == credential.id
                    and latest_report.credential_generation == credential.generation
                )
            wiring_evidence = (
                wiring_evidence_by_report.get(wiring_report.id)
                if wiring_report is not None
                else None
            )
            wiring_current = False
            if (
                runtime_binding_current
                and report_policy_current
                and wiring_lineage_valid
                and wiring_report is not None
                and wiring_evidence is not None
                and latest_report is not None
                and head is not None
                and credential is not None
            ):
                wiring_current = (
                    now < _to_utc(wiring_report.expires_at)
                    and wiring_report.policy_version_id == head.active_policy_version_id
                    and wiring_report.policy_head_generation == head.generation
                    and wiring_report.credential_id == credential.id
                    and wiring_report.credential_generation == credential.generation
                    and wiring_report.runtime_build_digest == latest_report.runtime_build_digest
                    and wiring_report.configuration_digest == latest_report.configuration_digest
                    and wiring_report.policy_version_id == latest_report.policy_version_id
                    and wiring_report.policy_head_generation == latest_report.policy_head_generation
                    and wiring_report.policy_content_hash == latest_report.policy_content_hash
                    and wiring_report.credential_id == latest_report.credential_id
                    and wiring_report.credential_generation == latest_report.credential_generation
                )
            runtimes.append(
                FleetRuntime(
                    identity_id=identity.id,
                    gate_id=identity.gate_id,
                    registered=FleetState(
                        available=registered,
                        reason=(
                            "active_registration"
                            if identity_active
                            else "durable_registration_revoked"
                        ),
                        observed_at=identity.created_at,
                    ),
                    online=FleetState(
                        available=report_current,
                        reason=(
                            "latest_accepted_runtime_report_current"
                            if report_current
                            else (
                                "registration_revoked"
                                if not identity_active
                                else (
                                    "runtime_report_lineage_invalid"
                                    if report_head is not None
                                    else "no_current_accepted_runtime_report"
                                )
                            )
                        ),
                        observed_at=(
                            latest_report.observed_at
                            if report_current and latest_report is not None
                            else None
                        ),
                    ),
                    policy_current=FleetState(
                        available=report_policy_current,
                        reason=(
                            "latest_accepted_report_policy_current"
                            if report_policy_current
                            else (
                                "registration_revoked"
                                if not identity_active
                                else "no_current_accepted_report_policy_binding"
                            )
                        ),
                        observed_at=(
                            latest_report.observed_at
                            if report_policy_current and latest_report is not None
                            else None
                        ),
                    ),
                    proven_wired=FleetState(
                        available=wiring_current,
                        reason=(
                            "current_observed_in_process_public_surface_conformance"
                            if wiring_current
                            else (
                                "wiring_attestation_not_current"
                                if wiring_report is not None
                                and wiring_evidence is not None
                                and wiring_lineage_valid
                                else (
                                    "wiring_attestation_lineage_invalid"
                                    if report_head is not None
                                    and report_head.latest_wiring_report_id is not None
                                    else "no_current_observed_wiring_attestation"
                                )
                            )
                        ),
                        observed_at=(
                            wiring_report.observed_at
                            if wiring_current and wiring_report is not None
                            else None
                        ),
                    ),
                    evidence_current=FleetState(
                        available=False,
                        reason="accepted_evidence_ingestion_not_implemented",
                        observed_at=None,
                    ),
                )
            )
        return FleetResponse(
            org_id=org.id,
            project_id=project_id,
            environment_id=environment_id,
            runtimes=runtimes,
            next_cursor=next_cursor,
        )

    @app.post(
        "/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/runtime-enrollment-bootstraps",
        response_model=RuntimeEnrollmentBootstrapCreateResponse,
        status_code=201,
        tags=["runtime-identities"],
        operation_id="runtime-enrollment-bootstrap.issue",
    )
    def issue_runtime_enrollment_bootstrap(
        project_id: str,
        environment_id: str,
        body: RuntimeEnrollmentBootstrapCreateRequest,
        org: OrgDep,
        request: Request,
        _session: SessionDep,
        principal: Annotated[Principal, require(Permission.RUNTIME_ENROLLMENT_MANAGE)],
    ) -> RuntimeEnrollmentBootstrapCreateResponse:
        service: RuntimeEnrollmentService = request.app.state.runtime_enrollment_service
        return service.issue_bootstrap(
            org_id=org.id,
            project_id=project_id,
            environment_id=environment_id,
            principal=principal,
            body=body,
        )

    @app.post(
        "/v1/runtime-enrollments",
        response_model=RuntimeEnrollmentResponse,
        status_code=201,
        tags=["runtime-identities"],
        operation_id="runtime-identity.enroll",
    )
    async def enroll_runtime_identity(
        body: RuntimeEnrollmentRequest,
        request: Request,
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
        bootstrap_id: Annotated[str | None, Header(alias="X-ACGS-Bootstrap-ID")] = None,
        pop_signature: Annotated[str | None, Header(alias="X-ACGS-Runtime-PoP-Signature")] = None,
        pop_key_id: Annotated[str | None, Header(alias="X-ACGS-Runtime-PoP-Key-ID")] = None,
    ) -> RuntimeEnrollmentResponse:
        service: RuntimeEnrollmentService = request.app.state.runtime_enrollment_service
        return service.enroll(
            body=body,
            authorization=authorization,
            idempotency_key=idempotency_key,
            pop_signature=pop_signature,
            pop_key_id=pop_key_id,
            raw_body=await request.body(),
            bootstrap_id_header=bootstrap_id,
        )

    @app.post(
        "/v1/runtime-identities/{identity_id}/renew",
        response_model=RuntimeEnrollmentResponse,
        tags=["runtime-identities"],
        operation_id="runtime-identity.renew",
    )
    async def renew_runtime_identity(
        identity_id: str,
        request: Request,
        runtime_identity_id: Annotated[
            str | None, Header(alias="X-ACGS-Runtime-Identity-ID")
        ] = None,
        key_id: Annotated[str | None, Header(alias="X-ACGS-Runtime-Key-ID")] = None,
        audience: Annotated[str | None, Header(alias="X-ACGS-Runtime-Audience")] = None,
        credential_id: Annotated[str | None, Header(alias="X-ACGS-Runtime-Credential-ID")] = None,
        credential_generation: Annotated[
            str | None, Header(alias="X-ACGS-Runtime-Credential-Generation")
        ] = None,
        timestamp: Annotated[str | None, Header(alias="X-ACGS-Runtime-Timestamp")] = None,
        nonce: Annotated[str | None, Header(alias="X-ACGS-Runtime-Nonce")] = None,
        body_sha256: Annotated[str | None, Header(alias="X-ACGS-Runtime-Body-Sha256")] = None,
        signature: Annotated[str | None, Header(alias="X-ACGS-Runtime-Signature")] = None,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> RuntimeEnrollmentResponse:
        service: RuntimeEnrollmentService = request.app.state.runtime_enrollment_service
        if runtime_identity_id is not None and runtime_identity_id != identity_id:
            raise RuntimeEnrollmentHttpError(
                400,
                "IDENTITY_ID_MISMATCH",
                "bad_request",
                "runtime identity header does not match route identity",
            )
        missing = [
            name
            for name, value in {
                "X-ACGS-Runtime-Key-ID": key_id,
                "X-ACGS-Runtime-Audience": audience,
                "X-ACGS-Runtime-Credential-ID": credential_id,
                "X-ACGS-Runtime-Credential-Generation": credential_generation,
                "X-ACGS-Runtime-Timestamp": timestamp,
                "X-ACGS-Runtime-Nonce": nonce,
                "X-ACGS-Runtime-Body-Sha256": body_sha256,
                "X-ACGS-Runtime-Signature": signature,
                "Idempotency-Key": idempotency_key,
            }.items()
            if value is None
        ]
        if missing:
            raise RuntimeEnrollmentHttpError(
                400,
                "RUNTIME_SIGNATURE_HEADERS_REQUIRED",
                "bad_request",
                f"runtime signed request headers are missing: {', '.join(missing)}",
            )
        try:
            parsed_generation = int(cast(str, credential_generation))
        except ValueError as exc:
            raise RuntimeEnrollmentHttpError(
                400,
                "CREDENTIAL_GENERATION_MALFORMED",
                "bad_request",
                "runtime credential generation header must be an integer",
            ) from exc
        body = RuntimeSignedRequest(
            key_id=cast(str, key_id),
            credential_id=cast(str, credential_id),
            credential_generation=parsed_generation,
            audience=cast(str, audience),
            timestamp=cast(str, timestamp),
            nonce=cast(str, nonce),
            idempotency_key_digest=hashlib.sha256(
                cast(str, idempotency_key).encode("utf-8")
            ).hexdigest(),
            signature=cast(str, signature),
        )
        return service.renew(
            identity_id=identity_id,
            body=body,
            raw_body=await request.body(),
            query=request.url.query,
            body_sha256=body_sha256,
            idempotency_key=cast(str, idempotency_key),
        )

    @app.get(
        "/v1/runtime-identities/{identity_id}/policy-bundle",
        response_model=PolicySyncSnapshot,
        responses={304: {"description": "The signed policy cursor is current."}},
        tags=["runtime-identities"],
        operation_id="runtime-identity.policy-sync",
    )
    async def sync_runtime_policy(
        identity_id: str,
        request: Request,
        runtime_identity_id: Annotated[
            str | None, Header(alias="X-ACGS-Runtime-Identity-ID")
        ] = None,
        key_id: Annotated[str | None, Header(alias="X-ACGS-Runtime-Key-ID")] = None,
        audience: Annotated[str | None, Header(alias="X-ACGS-Runtime-Audience")] = None,
        credential_id: Annotated[str | None, Header(alias="X-ACGS-Runtime-Credential-ID")] = None,
        credential_generation: Annotated[
            str | None, Header(alias="X-ACGS-Runtime-Credential-Generation")
        ] = None,
        timestamp: Annotated[str | None, Header(alias="X-ACGS-Runtime-Timestamp")] = None,
        nonce: Annotated[str | None, Header(alias="X-ACGS-Runtime-Nonce")] = None,
        body_sha256: Annotated[str | None, Header(alias="X-ACGS-Runtime-Body-Sha256")] = None,
        signature: Annotated[str | None, Header(alias="X-ACGS-Runtime-Signature")] = None,
        cursor: Annotated[str | None, Query(max_length=49)] = None,
    ) -> Response | PolicySyncSnapshot:
        if runtime_identity_id is not None and runtime_identity_id != identity_id:
            raise RuntimeEnrollmentHttpError(
                401,
                "RUNTIME_AUTHENTICATION_FAILED",
                "unauthorized",
                "runtime request authentication failed",
            )
        missing = [
            name
            for name, value in {
                "X-ACGS-Runtime-Identity-ID": runtime_identity_id,
                "X-ACGS-Runtime-Key-ID": key_id,
                "X-ACGS-Runtime-Audience": audience,
                "X-ACGS-Runtime-Credential-ID": credential_id,
                "X-ACGS-Runtime-Credential-Generation": credential_generation,
                "X-ACGS-Runtime-Timestamp": timestamp,
                "X-ACGS-Runtime-Nonce": nonce,
                "X-ACGS-Runtime-Body-Sha256": body_sha256,
                "X-ACGS-Runtime-Signature": signature,
            }.items()
            if value is None
        ]
        if missing:
            raise RuntimeEnrollmentHttpError(
                400,
                "RUNTIME_SIGNATURE_HEADERS_REQUIRED",
                "bad_request",
                f"runtime signed request headers are missing: {', '.join(missing)}",
            )
        try:
            parsed_generation = int(cast(str, credential_generation))
        except ValueError as exc:
            raise RuntimeEnrollmentHttpError(
                400,
                "CREDENTIAL_GENERATION_MALFORMED",
                "bad_request",
                "runtime credential generation header must be an integer",
            ) from exc
        service: PolicySyncService = request.app.state.policy_sync_service
        raw_path = request.scope.get("raw_path")
        result = service.fetch(
            identity_id=identity_id,
            auth=PolicySyncAuth(
                key_id=cast(str, key_id),
                credential_id=cast(str, credential_id),
                credential_generation=parsed_generation,
                audience=cast(str, audience),
                timestamp=cast(str, timestamp),
                nonce=cast(str, nonce),
                body_sha256=cast(str, body_sha256),
                signature=cast(str, signature),
            ),
            raw_query=request.url.query,
            raw_path=raw_path if isinstance(raw_path, bytes) else b"",
            body=await request.body(),
            cursor=cursor,
        )
        headers = {
            "ETag": result.etag,
            "Cache-Control": "private, no-store",
            "Pragma": "no-cache",
        }
        if result.not_modified:
            return Response(status_code=304, headers=headers)
        response = JSONResponse(
            status_code=200,
            content=result.snapshot.model_dump(mode="json", by_alias=True),
            headers=headers,
        )
        return response

    @app.post(
        "/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/runtime-identities/{identity_id}/revoke",
        response_model=RuntimeEnrollmentResponse,
        tags=["runtime-identities"],
        operation_id="runtime-identity.revoke",
    )
    def revoke_runtime_identity(
        project_id: str,
        environment_id: str,
        identity_id: str,
        body: RuntimeIdentityRevokeRequest,
        org: OrgDep,
        request: Request,
        _session: SessionDep,
        principal: Annotated[Principal, require(Permission.RUNTIME_IDENTITY_REVOKE)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> RuntimeEnrollmentResponse:
        if not idempotency_key:
            raise RuntimeEnrollmentHttpError(
                400,
                "IDEMPOTENCY_KEY_REQUIRED",
                "bad_request",
                "runtime identity revocation requires Idempotency-Key",
            )
        service: RuntimeEnrollmentService = request.app.state.runtime_enrollment_service
        return service.revoke(
            org_id=org.id,
            project_id=project_id,
            environment_id=environment_id,
            identity_id=identity_id,
            principal=principal,
            body=body,
            idempotency_key=idempotency_key,
        )

    # -- approvals -----------------------------------------------------------

    @app.post(
        "/orgs/{org_id}/approvals/{approval_request_id}/votes",
        response_model=ApprovalVoteResponse,
        tags=["approvals"],
        operation_id="approval.vote",
    )
    def vote_approval(
        approval_request_id: str,
        body: ApprovalVoteRequest,
        org: OrgDep,
        request: Request,
        _session: SessionDep,
        principal: Annotated[Principal, require(Permission.APPROVAL_VOTE)],
        idempotency_key: Annotated[str | None, Header(alias=BOOTSTRAP_IDEMPOTENCY_HEADER)] = None,
    ) -> ApprovalVoteResponse:
        service: ApprovalService = request.app.state.approval_service
        result = service.vote(
            org_id=org.id,
            approval_request_id=approval_request_id,
            principal=principal,
            decision=body.decision,
            idempotency_key=idempotency_key,
        )
        return ApprovalVoteResponse(
            approval_request_id=result.approval_request_id,
            decision=result.decision,
            outcome=result.outcome,
            vote_hash=result.vote_hash,
            receipt_id=result.receipt_id,
        )

    @app.post(
        "/orgs/{org_id}/approvals/{approval_request_id}/resume",
        response_model=AgentResponse,
        status_code=201,
        tags=["approvals"],
        operation_id="approval.resume",
    )
    def resume_approval(
        approval_request_id: str,
        org: OrgDep,
        request: Request,
        _session: SessionDep,
        principal: Annotated[Principal, require(Permission.APPROVAL_RESUME)],
        idempotency_key: Annotated[str | None, Header(alias=BOOTSTRAP_IDEMPOTENCY_HEADER)] = None,
    ) -> AgentResponse:
        service: ApprovalService = request.app.state.approval_service
        result = service.resume(
            org_id=org.id,
            approval_request_id=approval_request_id,
            principal=principal,
            idempotency_key=idempotency_key,
        )
        return AgentResponse(
            agent_id=result.agent_id,
            org_id=result.org_id,
            name=result.name,
            description=result.description,
            trust_tier=result.trust_tier,
            allowed_tools=result.allowed_tools,
            status=result.status,
            created_at=result.created_at,
            receipt_id=result.receipt_id,
        )

    # -- policy registry ------------------------------------------------------

    @app.post(
        "/orgs/{org_id}/policies",
        response_model=PolicyResponse,
        status_code=201,
        tags=["policies"],
    )
    def publish_policy(
        body: PolicyPublishRequest,
        org: OrgDep,
        request: Request,
        session: SessionDep,
        principal: Annotated[Principal, require(Permission.POLICY_PUBLISH)],
    ) -> PolicyResponse:
        bundle_dict: dict[str, Any] = {"id": body.policy_id, "rules": body.rules}
        try:
            parsed = RuleSetPolicy.from_dict(bundle_dict)
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=422, detail=f"invalid policy bundle: {exc}") from exc

        holder: dict[str, PolicyBundle] = {}

        def _do(policy_id: str, version: str) -> dict[str, str]:
            row = PolicyBundle(
                org_id=org.id,
                policy_id=policy_id,
                version=version,
                bundle=bundle_dict,
                status="published",
            )
            session.add(row)
            session.flush()
            holder["bundle"] = row
            return {"bundle_id": row.id, "version": version}

        membrane = _membrane(request, session, org, principal)
        outcome = membrane.run(
            "policy.publish",
            {"policy_id": body.policy_id, "version": parsed.version},
            _do,
            goal="publish policy bundle to registry",
            path=["control-plane", "policies"],
        )
        return _policy_response(holder["bundle"], receipt_id=outcome.receipt.id)

    @app.get("/orgs/{org_id}/policies", response_model=list[PolicyResponse], tags=["policies"])
    def list_policies(
        org: OrgDep,
        session: SessionDep,
        _p: Annotated[Principal, require(Permission.POLICY_READ)],
    ) -> list[PolicyResponse]:
        rows = session.execute(
            select(PolicyBundle)
            .where(PolicyBundle.org_id == org.id)
            .order_by(PolicyBundle.created_at.asc())
        ).scalars()
        return [_policy_response(r) for r in rows]

    @app.post(
        "/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/policies",
        response_model=PolicyResponse,
        status_code=201,
        tags=["policies"],
    )
    def publish_environment_policy(
        project_id: str,
        environment_id: str,
        body: PolicyPublishRequest,
        org: OrgDep,
        request: Request,
        _session: SessionDep,
        principal: Annotated[Principal, require(Permission.POLICY_PUBLISH)],
        idempotency_key: Annotated[str | None, Header(alias=BOOTSTRAP_IDEMPOTENCY_HEADER)] = None,
    ) -> PolicyResponse:
        service: PolicyRegistryService = request.app.state.policy_registry_service
        result = service.publish(
            org_id=org.id,
            project_id=project_id,
            environment_id=environment_id,
            principal=principal,
            body=body,
            idempotency_key=idempotency_key,
        )
        return _managed_policy_response(result)

    @app.get(
        "/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/policies",
        response_model=list[PolicyResponse],
        tags=["policies"],
    )
    def list_environment_policies(
        project_id: str,
        environment_id: str,
        org: OrgDep,
        session: SessionDep,
        _p: Annotated[Principal, require(Permission.POLICY_READ)],
    ) -> list[PolicyResponse]:
        head = session.scalars(
            select(EnvironmentPolicyHead).where(
                EnvironmentPolicyHead.org_id == org.id,
                EnvironmentPolicyHead.project_id == project_id,
                EnvironmentPolicyHead.environment_id == environment_id,
            )
        ).one_or_none()
        rows = session.execute(
            select(PolicyVersion)
            .where(
                PolicyVersion.org_id == org.id,
                PolicyVersion.project_id == project_id,
                PolicyVersion.environment_id == environment_id,
            )
            .order_by(PolicyVersion.created_at.asc())
        ).scalars()
        return [
            _policy_version_response(
                row,
                generation=head.generation
                if head is not None and head.active_policy_version_id == row.id
                else None,
                receipt_id=None,
            )
            for row in rows
        ]

    @app.post(
        "/orgs/{org_id}/policies/{bundle_id}/activate",
        response_model=PolicyResponse,
        tags=["policies"],
    )
    def activate_policy(
        bundle_id: str,
        org: OrgDep,
        request: Request,
        session: SessionDep,
        principal: Annotated[Principal, require(Permission.POLICY_ACTIVATE)],
    ) -> PolicyResponse:
        target = session.execute(
            select(PolicyBundle)
            .where(PolicyBundle.org_id == org.id, PolicyBundle.id == bundle_id)
            .with_for_update()
        ).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="policy bundle not found")
        if target.status == "active":
            return _policy_response(target)

        def _do(bundle_id: str, version: str) -> dict[str, str]:
            current = session.execute(
                select(PolicyBundle)
                .where(PolicyBundle.org_id == org.id, PolicyBundle.status == "active")
                .with_for_update()
            ).scalar_one_or_none()
            if current is not None:
                current.status = "retired"
                session.flush()
            target.status = "active"
            target.activated_at = _now()
            session.flush()
            return {"bundle_id": bundle_id, "version": version}

        # NOTE: activation is evaluated under the *currently* active policy —
        # the policy change itself is a governed action, so an org can write a
        # rule that escalates or denies policy.activate (change control).
        membrane = _membrane(request, session, org, principal)
        outcome = membrane.run(
            "policy.activate",
            {"bundle_id": bundle_id, "version": target.version},
            _do,
            goal="activate policy bundle for org",
            path=["control-plane", "policies"],
        )
        return _policy_response(target, receipt_id=outcome.receipt.id)

    @app.post(
        "/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/policies/{policy_version_id}/activate",
        response_model=PolicyResponse,
        tags=["policies"],
    )
    def activate_environment_policy(
        project_id: str,
        environment_id: str,
        policy_version_id: str,
        body: PolicyActivateRequest,
        org: OrgDep,
        request: Request,
        _session: SessionDep,
        principal: Annotated[Principal, require(Permission.POLICY_ACTIVATE)],
        idempotency_key: Annotated[str | None, Header(alias=BOOTSTRAP_IDEMPOTENCY_HEADER)] = None,
    ) -> PolicyResponse:
        service: PolicyRegistryService = request.app.state.policy_registry_service
        result = service.activate(
            org_id=org.id,
            project_id=project_id,
            environment_id=environment_id,
            policy_version_id=policy_version_id,
            principal=principal,
            body=body,
            idempotency_key=idempotency_key,
        )
        return _managed_policy_response(result)

    @app.post(
        "/orgs/{org_id}/policies/simulate",
        response_model=SimulateResponse,
        tags=["policies"],
    )
    def simulate(
        body: SimulateRequest,
        org: OrgDep,
        session: SessionDep,
        _principal: Annotated[Principal, require(Permission.POLICY_SIMULATE)],
    ) -> SimulateResponse:
        call = ToolCall(
            name=body.tool,
            args=dict(body.args),
            actor=body.actor,
            goal=body.goal,
            path=normalize_path_context(list(body.path)),
            state=dict(body.state),
        )
        record = load_active_policy(session, org.id).evaluate(call)
        return SimulateResponse(
            decision=record.decision.value,
            reason=record.reason,
            matched_rules=list(record.matched_rules),
            policy_version=record.policy_version,
        )

    # -- receipt explorer -----------------------------------------------------

    @app.get("/orgs/{org_id}/receipts", response_model=ReceiptListResponse, tags=["receipts"])
    def list_receipts(
        org: OrgDep,
        request: Request,
        response: Response,
        session: SessionDep,
        _p: Annotated[Principal, require(Permission.RECEIPT_READ)],
        decision: str | None = None,
        tool: str | None = None,
        actor: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
        cursor: str | None = None,
    ) -> ReceiptListResponse:
        response.headers["Cache-Control"] = "private, no-store"
        cursor_values = request.query_params.getlist("cursor")
        if len(cursor_values) > 1:
            raise InvalidCursorError("invalid cursor")
        if cursor is not None and len(cursor) > CURSOR_TOKEN_MAX_LENGTH:
            raise InvalidCursorError("invalid cursor")
        if cursor is not None and offset != 0:
            raise InvalidCursorError("invalid cursor")
        cursor_bound_names = _duplicate_query_params(request, _RECEIPT_CURSOR_QUERY_PARAMS)
        if "offset" in cursor_bound_names:
            raise InvalidCursorError("invalid cursor")
        if cursor is not None and cursor_bound_names:
            raise InvalidCursorError("invalid cursor")
        if (
            cursor is None
            and offset == 0
            and any(
                name in cursor_bound_names
                for name in ("decision", "tool", "actor", "since", "until", "limit", "offset")
            )
        ):
            raise InvalidCursorError("invalid cursor")
        filter_digest = receipt_filter_digest(
            decision=decision, tool=tool, actor=actor, since=since, until=until
        )
        query = select(ReceiptRow).where(ReceiptRow.org_id == org.id)
        if decision:
            query = query.where(ReceiptRow.decision == decision)
        if tool:
            query = query.where(ReceiptRow.tool == tool)
        if actor:
            query = query.where(ReceiptRow.actor == actor)
        if since:
            query = query.where(ReceiptRow.created_at >= since)
        if until:
            query = query.where(ReceiptRow.created_at <= until)
        total = session.execute(select(func.count()).select_from(query.subquery())).scalar_one()
        if cursor is not None:
            settings: Settings = request.app.state.settings
            keyring = settings.cursor_keyring
            assert keyring is not None
            boundary = decode_receipt_cursor(
                token=cursor,
                keyring=keyring,
                org_id=org.id,
                filter_digest=filter_digest,
            )
            query = query.where(
                (ReceiptRow.created_at < boundary.created_at)
                | (
                    (ReceiptRow.created_at == boundary.created_at)
                    & (ReceiptRow.id < boundary.receipt_id)
                )
            )
            rows = list(
                session.execute(
                    query.order_by(ReceiptRow.created_at.desc(), ReceiptRow.id.desc()).limit(
                        limit + 1
                    )
                ).scalars()
            )
            page_rows = rows[:limit]
            next_cursor = None
            if len(rows) > limit and page_rows:
                last = page_rows[-1]
                next_cursor = issue_receipt_cursor(
                    keyring=keyring,
                    org_id=org.id,
                    filter_digest=filter_digest,
                    boundary_created_at=last.created_at,
                    boundary_receipt_id=last.id,
                )
            return ReceiptListResponse(
                items=[_receipt_summary(r) for r in page_rows],
                total=total,
                limit=limit,
                offset=offset,
                next_cursor=next_cursor,
            )
        legacy_rows = session.execute(
            query.order_by(ReceiptRow.created_at.desc(), ReceiptRow.id.desc())
            .limit(limit)
            .offset(offset)
        ).scalars()
        page_rows = list(legacy_rows)
        next_cursor = None
        if offset == 0 and page_rows and len(page_rows) == limit and total > limit:
            settings = request.app.state.settings
            keyring = settings.cursor_keyring
            assert keyring is not None
            last = page_rows[-1]
            next_cursor = issue_receipt_cursor(
                keyring=keyring,
                org_id=org.id,
                filter_digest=filter_digest,
                boundary_created_at=last.created_at,
                boundary_receipt_id=last.id,
            )
        return ReceiptListResponse(
            items=[_receipt_summary(r) for r in page_rows],
            total=total,
            limit=limit,
            offset=offset,
            next_cursor=next_cursor,
        )

    @app.get(
        "/orgs/{org_id}/receipts/{receipt_id}", response_model=ReceiptDetail, tags=["receipts"]
    )
    def get_receipt(
        receipt_id: str,
        org: OrgDep,
        session: SessionDep,
        _p: Annotated[Principal, require(Permission.RECEIPT_READ)],
    ) -> ReceiptDetail:
        row = _get_receipt_or_404(session, org.id, receipt_id)
        return ReceiptDetail(
            **_receipt_summary(row).model_dump(),
            argument_hash=row.argument_hash,
            result_hash=row.result_hash,
            error_class=row.error_class,
            payload=row.payload,
        )

    @app.post(
        "/orgs/{org_id}/receipts/{receipt_id}/verify",
        response_model=ReceiptVerifyResponse,
        tags=["receipts"],
    )
    def verify_receipt(
        receipt_id: str,
        org: OrgDep,
        request: Request,
        session: SessionDep,
        _p: Annotated[Principal, require(Permission.RECEIPT_READ)],
    ) -> ReceiptVerifyResponse:
        row = _get_receipt_or_404(session, org.id, receipt_id)
        settings: Settings = request.app.state.settings
        store = existing_org_audit_store(settings.audit_dir, org.id)
        result: dict[str, Any]
        if store is None:
            in_chain = False
            failures = [] if org.audit_anchor_count == 0 else [{"type": "length_mismatch"}]
            result = {"valid": not failures, "checked": 0, "failures": failures}
        else:
            in_chain = any(
                event.get("event_hash") == row.audit_hash for event in store.iter_events()
            )
            result = store.verify_chain(
                # 0 is a legitimate anchor (org exists, chain empty) — always
                # pass the count so truncation-to-empty is still detected.
                expected_count=org.audit_anchor_count,
                expected_last_hash=org.audit_anchor_hash or None,
            )
        # verify_chain reports anchor mismatches as failures; split them out
        # so callers can distinguish "file corrupted" from "file truncated".
        anchor_failures = [
            f
            for f in result["failures"]
            if f.get("type") in {"length_mismatch", "last_hash_mismatch"}
        ]
        return ReceiptVerifyResponse(
            receipt_id=receipt_id,
            receipt_in_chain=in_chain,
            chain_valid=bool(result["valid"]),
            chain_checked=int(result["checked"]),
            anchor_matched=not anchor_failures,
            failures=list(result["failures"]),
        )

    # -- audit dashboard --------------------------------------------------------

    @app.get("/orgs/{org_id}/dashboard", response_model=DashboardResponse, tags=["dashboard"])
    def dashboard(
        org: OrgDep,
        request: Request,
        session: SessionDep,
        _p: Annotated[Principal, require(Permission.DASHBOARD_READ)],
    ) -> DashboardResponse:
        settings: Settings = request.app.state.settings

        def _grouped(column: Any, top: int | None = None) -> list[tuple[str, int]]:
            q = (
                select(column, func.count())
                .where(ReceiptRow.org_id == org.id)
                .group_by(column)
                .order_by(func.count().desc())
            )
            if top:
                q = q.limit(top)
            return [(str(k), int(v)) for k, v in session.execute(q)]

        decisions = dict(_grouped(ReceiptRow.decision))
        top_tools = [{"tool": k, "count": v} for k, v in _grouped(ReceiptRow.tool, top=10)]
        top_actors = [{"actor": k, "count": v} for k, v in _grouped(ReceiptRow.actor, top=10)]
        total = session.execute(
            select(func.count()).select_from(ReceiptRow).where(ReceiptRow.org_id == org.id)
        ).scalar_one()
        active = session.execute(
            select(PolicyBundle.version).where(
                PolicyBundle.org_id == org.id, PolicyBundle.status == "active"
            )
        ).scalar_one_or_none()
        agents_total = session.execute(
            select(func.count()).select_from(AgentRecord).where(AgentRecord.org_id == org.id)
        ).scalar_one()
        agents_suspended = session.execute(
            select(func.count())
            .select_from(AgentRecord)
            .where(AgentRecord.org_id == org.id, AgentRecord.status == "suspended")
        ).scalar_one()
        store = existing_org_audit_store(settings.audit_dir, org.id)
        chain: dict[str, Any]
        if store is None:
            failures = [] if org.audit_anchor_count == 0 else [{"type": "length_mismatch"}]
            chain = {"valid": not failures, "checked": 0, "failures": failures}
        else:
            chain = store.verify_chain(
                # 0 is a legitimate anchor (org exists, chain empty) — always
                # pass the count so truncation-to-empty is still detected.
                expected_count=org.audit_anchor_count,
                expected_last_hash=org.audit_anchor_hash or None,
            )
        return DashboardResponse(
            org_id=org.id,
            total_receipts=int(total),
            decisions=decisions,
            top_tools=top_tools,
            top_actors=top_actors,
            active_policy_version=active,
            agents_total=int(agents_total),
            agents_suspended=int(agents_suspended),
            chain_valid=bool(chain["valid"]),
            chain_checked=int(chain["checked"]),
        )

    # -- compliance export --------------------------------------------------------

    @app.post(
        "/orgs/{org_id}/exports",
        response_model=ExportSummary,
        status_code=201,
        tags=["exports"],
    )
    def create_export(
        body: ExportCreateRequest,
        org: OrgDep,
        request: Request,
        session: SessionDep,
        principal: Annotated[Principal, require(Permission.EXPORT_CREATE)],
    ) -> ExportSummary:
        membrane = _membrane(request, session, org, principal)
        holder: dict[str, ComplianceExport] = {}

        def _do(note: str) -> dict[str, str]:
            bundle = build_export_bundle(session, membrane, org, note=note)
            row = ComplianceExport(
                org_id=org.id,
                created_by=principal.actor_id,
                receipt_count=len(bundle["sections"]["receipts"]),
                bundle_hash=bundle["bundle_hash"],
                bundle=bundle,
            )
            session.add(row)
            session.flush()
            holder["export"] = row
            return {"export_id": row.id, "bundle_hash": row.bundle_hash}

        outcome = membrane.run(
            "export.generate",
            {"note": body.note},
            _do,
            goal="generate compliance evidence export",
            path=["control-plane", "exports"],
        )
        row = holder["export"]
        return _export_summary(row, receipt_id=outcome.receipt.id)

    @app.get("/orgs/{org_id}/exports", response_model=list[ExportSummary], tags=["exports"])
    def list_exports(
        org: OrgDep,
        session: SessionDep,
        _p: Annotated[Principal, require(Permission.EXPORT_READ)],
    ) -> list[ExportSummary]:
        rows = session.execute(
            select(ComplianceExport)
            .where(ComplianceExport.org_id == org.id)
            .order_by(ComplianceExport.created_at.asc())
        ).scalars()
        return [_export_summary(r) for r in rows]

    @app.get("/orgs/{org_id}/exports/{export_id}", response_model=ExportDetail, tags=["exports"])
    def get_export(
        export_id: str,
        org: OrgDep,
        session: SessionDep,
        _p: Annotated[Principal, require(Permission.EXPORT_READ)],
    ) -> ExportDetail:
        row = session.execute(
            select(ComplianceExport).where(
                ComplianceExport.org_id == org.id, ComplianceExport.id == export_id
            )
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="export not found")
        return ExportDetail(**_export_summary(row).model_dump(), bundle=row.bundle)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    from acgs_control_plane.models import utcnow

    return utcnow()


def _get_agent_or_404(session: Session, org_id: str, agent_id: str) -> AgentRecord:
    rec = session.execute(
        select(AgentRecord).where(AgentRecord.org_id == org_id, AgentRecord.id == agent_id)
    ).scalar_one_or_none()
    if rec is None:
        raise HTTPException(status_code=404, detail="agent not found")
    return rec


def _get_receipt_or_404(session: Session, org_id: str, receipt_id: str) -> ReceiptRow:
    row = session.execute(
        select(ReceiptRow).where(ReceiptRow.org_id == org_id, ReceiptRow.id == receipt_id)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="receipt not found")
    return row


def _agent_response(rec: AgentRecord, receipt_id: str | None = None) -> AgentResponse:
    return AgentResponse(
        agent_id=rec.id,
        org_id=rec.org_id,
        name=rec.name,
        description=rec.description,
        trust_tier=rec.trust_tier,
        allowed_tools=list(rec.allowed_tools),
        status=rec.status,
        created_at=rec.created_at,
        receipt_id=receipt_id,
    )


def _policy_response(row: PolicyBundle, receipt_id: str | None = None) -> PolicyResponse:
    return PolicyResponse(
        bundle_id=row.id,
        org_id=row.org_id,
        policy_id=row.policy_id,
        version=row.version,
        status=row.status,
        rules=list(row.bundle.get("rules", [])),
        created_at=row.created_at,
        activated_at=row.activated_at,
        receipt_id=receipt_id,
    )


def _managed_policy_response(row: PolicyRegistryResult) -> PolicyResponse:
    return PolicyResponse(**row.__dict__)


def _policy_version_response(
    row: PolicyVersion, *, generation: int | None, receipt_id: str | None
) -> PolicyResponse:
    return PolicyResponse(
        bundle_id=row.id,
        org_id=row.org_id,
        project_id=row.project_id,
        environment_id=row.environment_id,
        policy_id=row.policy_id,
        version=row.version,
        status="active" if generation is not None else "published",
        rules=list(row.rules),
        created_at=row.created_at,
        activated_at=None,
        receipt_id=receipt_id,
        generation=generation,
        content_hash=row.content_hash,
        key_id=row.key_id,
        signature_algorithm=row.signature_algorithm,
        trust_epoch=row.trust_epoch,
    )


def _receipt_summary(row: ReceiptRow) -> ReceiptSummary:
    return ReceiptSummary(
        receipt_id=row.id,
        tool=row.tool,
        decision=row.decision,
        actor=row.actor,
        goal=row.goal,
        policy_version=row.policy_version,
        audit_hash=row.audit_hash,
        created_at=row.created_at,
    )


def _duplicate_query_params(request: Request, names: frozenset[str]) -> frozenset[str]:
    return frozenset(name for name in names if len(request.query_params.getlist(name)) > 1)


def _export_summary(row: ComplianceExport, receipt_id: str | None = None) -> ExportSummary:
    return ExportSummary(
        export_id=row.id,
        created_by=row.created_by,
        receipt_count=row.receipt_count,
        bundle_hash=row.bundle_hash,
        created_at=row.created_at,
        receipt_id=receipt_id,
    )


_RECEIPT_CURSOR_QUERY_PARAMS = frozenset(
    {"decision", "tool", "actor", "since", "until", "limit", "offset", "cursor"}
)


def _install_v1_aliases(app: FastAPI) -> None:
    source_routes = [
        route
        for route in app.routes
        if isinstance(route, APIRoute)
        and (route.path == "/orgs" or route.path.startswith("/orgs/"))
    ]
    for route in source_routes:
        alias = APIRoute(
            path=f"/v1{route.path}",
            endpoint=route.endpoint,
            response_model=route.response_model,
            status_code=route.status_code,
            tags=list(route.tags),
            dependencies=list(route.dependencies),
            summary=route.summary,
            description=route.description,
            response_description=route.response_description,
            responses=route.responses,
            deprecated=route.deprecated,
            name=f"v1_{route.name}",
            methods=route.methods,
            operation_id=f"v1_{route.unique_id}",
            response_model_include=route.response_model_include,
            response_model_exclude=route.response_model_exclude,
            response_model_by_alias=route.response_model_by_alias,
            response_model_exclude_unset=route.response_model_exclude_unset,
            response_model_exclude_defaults=route.response_model_exclude_defaults,
            response_model_exclude_none=route.response_model_exclude_none,
            include_in_schema=route.include_in_schema,
            response_class=route.response_class,
            dependency_overrides_provider=app,
            callbacks=route.callbacks,
            openapi_extra=route.openapi_extra,
        )
        app.router.routes.append(alias)
