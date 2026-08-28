import hashlib
import hmac
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from second_brain.answering import RetrievalConfig, answer_question
from second_brain.auth import (
    SESSION_COOKIE_NAME,
    TrustedAssertion,
    deny,
    exchange_assertion,
)
from second_brain.config import Settings, get_answer_provider_settings, get_settings
from second_brain.db import (
    attest_runtime_role,
    create_database_engine,
    create_session_factory,
    scoped_session,
)
from second_brain.ingestion import CaptureResult, IdempotencyConflict, capture_source
from second_brain.memory import (
    MemoryEvidenceUnavailable,
    MemoryNotFound,
    MemoryStateConflict,
    approve_memory,
    archive_memory,
    edit_and_approve_memory,
    propose_memory,
    reject_memory_proposal,
    revise_memory,
    supersede_memory,
)
from second_brain.organization import (
    OrganizationNotFound,
    create_project,
    create_tag,
    delete_project,
    delete_tag,
    list_projects,
    list_tags,
    organize_source,
    update_project,
    update_tag,
)
from second_brain.policy import (
    PolicyContext,
    PolicyDecisionPort,
    PolicyDenied,
    PolicyUnavailable,
    evaluate_policy,
    record_policy_decision,
)
from second_brain.principal import Principal, get_principal
from second_brain.providers import (
    EmbeddingProvider,
    FakeEmbeddingProvider,
    FakeGenerationProvider,
    GenerationProvider,
    OpenAICompatibleEmbeddingProvider,
    OpenAICompatibleGenerationProvider,
    UnavailableEmbeddingProvider,
    UnavailableGenerationProvider,
)
from second_brain.purge import PurgeNotFound, request_memory_purge, request_source_purge
from second_brain.request_limits import RequestBodyLimitMiddleware
from second_brain.retrieval import SearchFilters, hybrid_search
from second_brain.safe_logging import safe_log
from second_brain.source_context import citation_context, source_detail
from second_brain.storage import FilesystemStorage
from second_brain.today import today_view
from second_brain.upload_validation import UploadRejected, validate_upload
from second_brain.url_ingest import SafeUrlError, validate_url_syntax

LOGGER = logging.getLogger("second_brain.api")
PrincipalDependency = Annotated[Principal, Depends(get_principal)]


class HealthResponse(BaseModel):
    service: str
    status: str


class StatusResponse(BaseModel):
    service: str
    status: str
    database: str
    storage: str
    model_provider: str
    embedding_provider_status: Literal["available", "unavailable"]
    generation_provider_status: Literal["available", "unavailable"]
    provider_status_scope: Literal["local_adapter_state_not_remote_health"]
    max_upload_bytes: int
    max_extracted_chars: int
    max_chunks: int
    max_processing_seconds: int


class SourceMetadata(BaseModel):
    source_id: UUID
    display_title: str
    source_type: str
    processing_state: str


class SessionResponse(BaseModel):
    status: str
    csrf_token: str
    absolute_expires_at: str
    idle_expires_at: str


class TextCaptureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=300)
    content: str = Field(min_length=1)
    source_type: Literal["note", "markdown"] = "note"
    project_id: UUID | None = None
    tag_ids: list[UUID] = Field(default_factory=list, max_length=100)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)


class UrlCaptureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=300)
    url: str = Field(min_length=1, max_length=2048)
    project_id: UUID | None = None
    tag_ids: list[UUID] = Field(default_factory=list, max_length=100)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)


class CaptureResponse(BaseModel):
    source_id: UUID
    source_version_id: UUID | None
    job_id: UUID
    state: str
    duplicate: bool


class SearchTagResponse(BaseModel):
    tag_id: UUID
    name: str


class SearchResultResponse(BaseModel):
    chunk_id: UUID
    source_id: UUID
    source_version_id: UUID
    display_title: str
    source_type: Literal["note", "markdown", "txt", "pdf", "docx", "url"]
    project_id: UUID | None
    ingested_at: datetime
    semantic_state: str
    mime_type: str
    source_metadata: dict[str, Any]
    parser_name: str
    parser_version: str
    chunker_version: str
    char_start: int
    char_end: int
    page_number: int | None
    section: str | None
    paragraph_number: int | None
    location: dict[str, Any] | None
    tags: list[SearchTagResponse]
    excerpt: str
    lexical_rank: int | None
    lexical_score: float | None
    semantic_rank: int | None
    semantic_score: float | None
    fused_rank: int
    fused_score: float


class SearchResponse(BaseModel):
    results: list[SearchResultResponse]
    semantic_status: Literal["available", "unavailable"]


class SearchFiltersRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: UUID | None = None
    tag_id: UUID | None = None
    source_type: Literal["note", "markdown", "txt", "pdf", "docx", "url"] | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None

    def domain(self) -> SearchFilters:
        return SearchFilters(**self.model_dump())


class RetrievalConfigRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lexical_k: Literal[50] = 50
    semantic_k: Literal[50] = 50
    rrf_k: Literal[60] = 60
    evidence_chunk_limit: int = Field(default=8, ge=1, le=8)
    evidence_char_limit: int = Field(default=12_000, ge=1, le=12_000)

    def domain(self) -> RetrievalConfig:
        return RetrievalConfig(**self.model_dump())


class AnswerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=2000)
    conversation_id: UUID | None = None
    filters: SearchFiltersRequest = Field(default_factory=SearchFiltersRequest)
    retrieval_config: RetrievalConfigRequest = Field(default_factory=RetrievalConfigRequest)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)


class ProjectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)


class ProjectUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=200)
    is_active: bool | None = None


class TagRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)


class SourceOrganizationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: UUID | None = None
    tag_ids: list[UUID] = Field(default_factory=list, max_length=100)


class MemoryDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)


class MemoryEditRequest(MemoryDecisionRequest):
    statement: str = Field(min_length=1, max_length=4000)
    category: Literal[
        "preference", "commitment", "project_fact", "person_fact", "reference", "other"
    ]
    confidence: float = Field(ge=0, le=1)
    evidence_quality: Literal["low", "medium", "high"]


class MemoryRevisionRequest(MemoryEditRequest):
    source_chunk_ids: list[UUID] = Field(min_length=1, max_length=100)


class MemorySupersedeRequest(MemoryDecisionRequest):
    superseding_memory_id: UUID


class PurgeRequest(MemoryDecisionRequest):
    reason_code: Literal["user_requested", "privacy_request", "retention_expired"] = (
        "user_requested"
    )


def normalize_request_id(value: str | None) -> str:
    if value is not None:
        try:
            return str(UUID(value))
        except ValueError:
            pass
    return str(uuid4())


def _trace_id(request: Request) -> str:
    return str(getattr(request.state, "trace_id", uuid4()))


def _error(
    request: Request,
    *,
    status_code: int,
    code: str,
    title: str,
    detail: str,
    retryable: bool = False,
) -> JSONResponse:
    request.state.denial_code = code
    return JSONResponse(
        status_code=status_code,
        content={
            "code": code,
            "title": title,
            "detail": detail,
            "retryable": retryable,
            "trace_id": _trace_id(request),
        },
    )


def create_app(
    settings: Settings | None = None,
    *,
    embedding_provider: EmbeddingProvider | None = None,
    generation_provider: GenerationProvider | None = None,
    policy_port: PolicyDecisionPort | None = None,
) -> FastAPI:
    resolved = settings or get_settings()
    if resolved.app_env == "production" and resolved.auth_mode == "development_headers":
        raise ValueError("development_headers auth_mode is forbidden in production")
    engine = create_database_engine(resolved)
    session_factory = create_session_factory(engine)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        attest_runtime_role(engine)
        yield
        engine.dispose()

    app = FastAPI(title="Second Brain API", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        RequestBodyLimitMiddleware,
        max_bytes=resolved.max_request_envelope_bytes,
        timeout_seconds=resolved.request_body_timeout_seconds,
    )
    app.state.settings = resolved
    app.state.engine = engine
    app.state.storage = FilesystemStorage(resolved.storage_root, resolved.max_upload_bytes)
    app.state.policy_port = policy_port
    if embedding_provider is None or generation_provider is None:
        if resolved.model_provider == "fake":
            default_embedding: EmbeddingProvider = FakeEmbeddingProvider(
                resolved.embedding_dimensions,
                profile_version=resolved.embedding_profile_version,
            )
            default_generation: GenerationProvider = FakeGenerationProvider()
        else:
            provider_settings = get_answer_provider_settings()
            if provider_settings.api_key is None:
                default_embedding = UnavailableEmbeddingProvider(
                    dimensions=resolved.embedding_dimensions,
                    profile_version=resolved.embedding_profile_version,
                )
                default_generation = UnavailableGenerationProvider()
            else:
                api_key = provider_settings.api_key.get_secret_value()
                default_embedding = OpenAICompatibleEmbeddingProvider(
                    resolved.model_base_url,
                    api_key,
                    resolved.embedding_model,
                    resolved.embedding_dimensions,
                    profile_version=resolved.embedding_profile_version,
                )
                default_generation = OpenAICompatibleGenerationProvider(
                    resolved.model_base_url,
                    api_key,
                    provider_settings.generation_model,
                )
        embedding_provider = embedding_provider or default_embedding
        generation_provider = generation_provider or default_generation
    app.state.embedding_provider = embedding_provider
    app.state.generation_provider = generation_provider

    def _adapter_status(provider: object) -> Literal["available", "unavailable"]:
        return "available" if getattr(provider, "status", None) == "available" else "unavailable"

    @app.middleware("http")
    async def safe_access_log(request: Request, call_next: Any) -> Any:
        request.state.trace_id = normalize_request_id(request.headers.get("x-request-id"))

        def finalize(response: Response, route_template: str) -> Response:
            response.headers["x-request-id"] = request.state.trace_id
            denial_code = str(getattr(request.state, "denial_code", "none"))
            LOGGER.info(
                "request_complete method=%s route=%s status=%s denial_code=%s trace_id=%s",
                request.method,
                route_template,
                response.status_code,
                denial_code,
                request.state.trace_id,
            )
            return response

        if (
            resolved.auth_mode == "trusted_proxy"
            and request.method in {"POST", "PUT", "PATCH", "DELETE"}
            and request.url.path != "/api/v1/auth/exchange"
        ):
            origin = request.headers.get("origin")
            expected_origin = resolved.public_origin
            expected_host = expected_origin.split("//", 1)[1] if expected_origin else ""
            if origin != expected_origin or request.headers.get("host") != expected_host:
                return finalize(
                    _error(
                        request,
                        status_code=403,
                        code="origin_forbidden",
                        title="Origin forbidden",
                        detail="The request origin is not allowed.",
                    ),
                    "<security-middleware>",
                )
            try:
                principal = get_principal(request)
            except HTTPException as exc:
                detail: dict[str, Any] = exc.detail if isinstance(exc.detail, dict) else {}
                return finalize(
                    _error(
                        request,
                        status_code=exc.status_code,
                        code=str(detail.get("code", "authentication_failed")),
                        title=str(detail.get("title", "Authentication failed")),
                        detail=str(detail.get("detail", "Authentication failed.")),
                    ),
                    "<security-middleware>",
                )
            csrf_token = request.headers.get("x-csrf-token", "")
            csrf_hash = hashlib.sha256(csrf_token.encode()).hexdigest()
            if principal.csrf_token_hash is None or not hmac.compare_digest(
                csrf_hash, principal.csrf_token_hash
            ):
                return finalize(
                    _error(
                        request,
                        status_code=403,
                        code="csrf_invalid",
                        title="CSRF validation failed",
                        detail="The CSRF token is invalid.",
                    ),
                    "<security-middleware>",
                )
        response = await call_next(request)
        matched_route = request.scope.get("route")
        route_template = getattr(matched_route, "path", "<unmatched>")
        return finalize(response, route_template)

    @app.exception_handler(404)
    async def not_found(request: Request, _: Exception) -> JSONResponse:
        return _error(
            request,
            status_code=404,
            code="not_found",
            title="Not found",
            detail="The requested resource is unavailable.",
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, _: RequestValidationError) -> JSONResponse:
        return _error(
            request,
            status_code=422,
            code="validation_error",
            title="Validation failed",
            detail="The request did not match the API contract.",
        )

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
        if isinstance(exc.detail, dict):
            return _error(
                request,
                status_code=exc.status_code,
                code=str(exc.detail.get("code", "request_failed")),
                title=str(exc.detail.get("title", "Request failed")),
                detail=str(exc.detail.get("detail", "The request could not be completed.")),
                retryable=bool(exc.detail.get("retryable", False)),
            )
        return _error(
            request,
            status_code=exc.status_code,
            code="request_failed",
            title="Request failed",
            detail="The request could not be completed.",
        )

    @app.exception_handler(IdempotencyConflict)
    async def idempotency_conflict(request: Request, _: IdempotencyConflict) -> JSONResponse:
        return _error(
            request,
            status_code=409,
            code="idempotency_conflict",
            title="Idempotency conflict",
            detail="The idempotency key was already used for a different request.",
        )

    @app.exception_handler(UploadRejected)
    async def upload_rejected(request: Request, _: UploadRejected) -> JSONResponse:
        return _error(
            request,
            status_code=415,
            code="upload_rejected",
            title="Upload rejected",
            detail="The uploaded file failed validation.",
        )

    @app.exception_handler(MemoryNotFound)
    @app.exception_handler(PurgeNotFound)
    @app.exception_handler(OrganizationNotFound)
    async def scoped_resource_missing(request: Request, _: Exception) -> JSONResponse:
        return _error(
            request,
            status_code=404,
            code="resource_unavailable",
            title="Resource unavailable",
            detail="The requested resource is unavailable in the active workspace.",
        )

    @app.exception_handler(MemoryEvidenceUnavailable)
    @app.exception_handler(MemoryStateConflict)
    async def memory_conflict(request: Request, _: Exception) -> JSONResponse:
        return _error(
            request,
            status_code=409,
            code="memory_conflict",
            title="Memory action unavailable",
            detail="The memory action cannot be completed from its current state.",
        )

    @app.exception_handler(PolicyDenied)
    async def policy_denied(request: Request, _: PolicyDenied) -> JSONResponse:
        return _error(
            request,
            status_code=403,
            code="policy_veto",
            title="Operation denied",
            detail="The operation was denied by the configured policy.",
        )

    @app.exception_handler(PolicyUnavailable)
    async def policy_unavailable(request: Request, _: PolicyUnavailable) -> JSONResponse:
        return _error(
            request,
            status_code=503,
            code="policy_unavailable",
            title="Policy unavailable",
            detail="The policy decision is temporarily unavailable.",
            retryable=True,
        )

    @app.exception_handler(Exception)
    async def internal_error(request: Request, exc: Exception) -> JSONResponse:
        LOGGER.error(
            "request_failed error_class=%s trace_id=%s",
            type(exc).__name__,
            _trace_id(request),
        )
        return _error(
            request,
            status_code=500,
            code="internal_error",
            title="Internal error",
            detail="The request could not be completed.",
            retryable=True,
        )

    def _membership_exists(session: Session, principal: Principal) -> bool:
        return bool(
            session.scalar(
                text(
                    "SELECT EXISTS (SELECT 1 FROM workspace_memberships "
                    "WHERE workspace_id=:workspace AND user_id=:owner)"
                ),
                {"workspace": principal.workspace_id, "owner": principal.owner_id},
            )
        )

    def _require_membership(session: Session, principal: Principal) -> None:
        if not _membership_exists(session, principal):
            raise deny(
                403,
                "workspace_forbidden",
                "Workspace forbidden",
                "The active workspace is unavailable.",
            )

    def _policy_gate(
        request: Request,
        principal: Principal,
        *,
        action: Literal[
            "capture_source",
            "generate_answer",
            "approve_memory",
            "purge_source",
            "purge_memory",
        ],
        resource_type: Literal["source", "answer", "memory", "workspace"],
        resource_id: UUID | None = None,
        source_type: str | None = None,
        mime_type: str | None = None,
        byte_count: int | None = None,
        memory_category: str | None = None,
        resource_query: str | None = None,
        resource_parameters: dict[str, Any] | None = None,
        resource_lock_target: Literal["memory"] | None = None,
    ) -> dict[str, Any] | None:
        parameters = resource_parameters or {}
        resolved_memory_category = memory_category
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            _require_membership(session, principal)
            initial = None
            if resource_query is not None:
                initial = session.execute(text(resource_query), parameters).mappings().one_or_none()
                if initial is None:
                    raise OrganizationNotFound("resource unavailable")
                if resolved_memory_category is None and "category" in initial:
                    resolved_memory_category = str(initial["category"])
        context = PolicyContext(
            request_id=UUID(_trace_id(request)),
            action=action,
            actor_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            resource_type=resource_type,
            resource_id=resource_id,
            source_type=source_type,
            mime_type=mime_type,
            byte_count=byte_count,
            memory_category=resolved_memory_category,
            native_checks="pass",
            occurred_at=datetime.now(UTC),
        )
        decision = evaluate_policy(
            app.state.policy_port,
            context,
            enabled=resolved.policy_enabled,
        )
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            _require_membership(session, principal)
            locked = None
            if resource_query is not None:
                lock_clause = (
                    " FOR UPDATE" if resource_lock_target is None else " FOR UPDATE OF memory"
                )
                locked = (
                    session.execute(text(f"{resource_query}{lock_clause}"), parameters)
                    .mappings()
                    .one_or_none()
                )
                if locked is None:
                    raise OrganizationNotFound("resource unavailable")
            if resolved.policy_enabled:
                record_policy_decision(session, context, decision)
        safe_log(
            LOGGER,
            logging.INFO,
            "policy_checked",
            action=action,
            decision=decision.decision,
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            request_id=context.request_id,
            reason_code=decision.reason_code,
        )
        if decision.decision == "veto":
            raise PolicyDenied(decision.reason_code)
        if decision.decision == "unavailable":
            raise PolicyUnavailable("policy adapter unavailable")
        selected = locked if locked is not None else initial
        return dict(selected) if selected is not None else None

    def _validate_organization(
        principal: Principal,
        project_id: UUID | None,
        tag_ids: list[UUID],
        *,
        lock: bool,
    ) -> None:
        unique_tags = sorted(set(tag_ids), key=str)
        suffix = " FOR KEY SHARE" if lock else ""
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            _require_membership(session, principal)
            if project_id is not None:
                project = session.scalar(
                    text(f"SELECT id FROM projects WHERE id=:id{suffix}"),
                    {"id": project_id},
                )
                if project is None:
                    raise OrganizationNotFound("project unavailable")
            if unique_tags:
                visible = set(
                    session.scalars(
                        text(f"SELECT id FROM tags WHERE id=ANY(:ids){suffix}"),
                        {"ids": unique_tags},
                    )
                )
                if visible != set(unique_tags):
                    raise OrganizationNotFound("tag unavailable")

    def _capture_policy(
        request: Request,
        principal: Principal,
        *,
        source_type: str,
        mime_type: str,
        byte_count: int,
        project_id: UUID | None,
        tag_ids: list[UUID],
    ) -> None:
        _validate_organization(principal, project_id, tag_ids, lock=False)
        _policy_gate(
            request,
            principal,
            action="capture_source",
            resource_type="workspace",
            resource_id=principal.workspace_id,
            source_type=source_type,
            mime_type=mime_type,
            byte_count=byte_count,
        )
        _validate_organization(principal, project_id, tag_ids, lock=True)

    def _organize_capture(
        principal: Principal,
        result: CaptureResult,
        project_id: UUID | None,
        tag_ids: list[UUID],
    ) -> None:
        if project_id is None and not tag_ids:
            return
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            organize_source(
                session,
                result.source_id,
                project_id=project_id,
                tag_ids=tag_ids,
            )

    @app.get("/api/v1/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(service="second-brain", status="ok")

    @app.get("/api/v1/status", response_model=StatusResponse)
    def status(request: Request) -> StatusResponse | JSONResponse:
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except SQLAlchemyError:
            return _error(
                request,
                status_code=503,
                code="database_unavailable",
                title="Database unavailable",
                detail="Persistence is temporarily unavailable.",
                retryable=True,
            )
        return StatusResponse(
            service="second-brain",
            status="ready",
            database="available",
            storage=resolved.storage_backend,
            model_provider=resolved.model_provider,
            embedding_provider_status=_adapter_status(app.state.embedding_provider),
            generation_provider_status=_adapter_status(app.state.generation_provider),
            provider_status_scope="local_adapter_state_not_remote_health",
            max_upload_bytes=resolved.max_upload_bytes,
            max_extracted_chars=resolved.max_extracted_chars,
            max_chunks=resolved.max_chunks,
            max_processing_seconds=resolved.max_processing_seconds,
        )

    @app.post("/api/v1/auth/exchange", response_model=SessionResponse)
    def auth_exchange(
        assertion: TrustedAssertion, request: Request, response: Response
    ) -> SessionResponse:
        if resolved.auth_mode != "trusted_proxy":
            raise deny(
                404,
                "exchange_unavailable",
                "Not found",
                "The trusted assertion exchange is unavailable.",
            )
        issued = exchange_assertion(request, assertion, resolved, session_factory)
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=issued.token,
            max_age=resolved.session_absolute_seconds,
            expires=issued.absolute_expires_at,
            path="/",
            secure=True,
            httponly=True,
            samesite="lax",
        )
        return SessionResponse(
            status="authenticated",
            csrf_token=issued.csrf_token,
            absolute_expires_at=issued.absolute_expires_at.isoformat(),
            idle_expires_at=issued.idle_expires_at.isoformat(),
        )

    @app.get("/api/v1/session/check")
    @app.post("/api/v1/session/check")
    def session_check(principal: PrincipalDependency) -> dict[str, str]:
        return {"status": "authenticated", "owner_id": str(principal.owner_id)}

    @app.get("/api/v1/sources")
    def list_sources(
        principal: PrincipalDependency,
        processing_state: Literal["queued", "processing", "ready", "failed", "purge_pending"]
        | None = None,
        project_id: UUID | None = None,
        tag_id: UUID | None = None,
        source_type: Literal["note", "markdown", "txt", "pdf", "docx", "url"] | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        query: Annotated[str | None, Query(max_length=2000)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> list[dict[str, Any]]:
        normalized_query = query.strip() if query is not None else None
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            _require_membership(session, principal)
            rows = session.execute(
                text(
                    "SELECT source.id AS source_id,source.display_title,source.source_type,"
                    "source.processing_state,source.project_id,source.ingested_at,"
                    "project.name AS project_name,COALESCE((SELECT array_agg(link.tag_id "
                    "ORDER BY link.tag_id) FROM source_tags AS link "
                    "WHERE link.source_id=source.id),'{}'::uuid[]) AS tag_ids "
                    "FROM sources AS source LEFT JOIN projects AS project "
                    "ON project.id=source.project_id WHERE source.deleted_at IS NULL "
                    "AND source.processing_state<>'purged' "
                    "AND (CAST(:state AS text) IS NULL OR source.processing_state=:state) "
                    "AND (CAST(:project AS uuid) IS NULL OR source.project_id=:project) "
                    "AND (CAST(:tag AS uuid) IS NULL OR EXISTS "
                    "(SELECT 1 FROM source_tags AS filter_tag "
                    "WHERE filter_tag.source_id=source.id AND filter_tag.tag_id=:tag)) "
                    "AND (CAST(:source_type AS text) IS NULL OR source.source_type=:source_type) "
                    "AND (CAST(:date_from AS timestamptz) IS NULL "
                    "OR source.ingested_at>=:date_from) "
                    "AND (CAST(:date_to AS timestamptz) IS NULL OR source.ingested_at<=:date_to) "
                    "AND (CAST(:query AS text) IS NULL "
                    "OR source.display_title ILIKE '%'||:query||'%' "
                    "OR EXISTS (SELECT 1 FROM source_versions AS version "
                    "JOIN chunks AS chunk ON chunk.source_version_id=version.id "
                    "WHERE version.source_id=source.id AND chunk.search_vector "
                    "@@ websearch_to_tsquery('simple',:query))) "
                    "ORDER BY source.ingested_at DESC,source.id ASC LIMIT :limit"
                ),
                {
                    "state": processing_state,
                    "project": project_id,
                    "tag": tag_id,
                    "source_type": source_type,
                    "date_from": date_from,
                    "date_to": date_to,
                    "query": normalized_query or None,
                    "limit": limit,
                },
            ).mappings()
            return [dict(row) for row in rows]

    @app.post("/api/v1/projects", status_code=201)
    def create_project_route(
        payload: ProjectRequest, principal: PrincipalDependency
    ) -> dict[str, Any]:
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            _require_membership(session, principal)
            return create_project(session, payload.name)

    @app.get("/api/v1/projects")
    def list_projects_route(
        principal: PrincipalDependency, active_only: bool = False
    ) -> list[dict[str, Any]]:
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            _require_membership(session, principal)
            return list_projects(session, active_only=active_only)

    @app.patch("/api/v1/projects/{project_id}")
    def update_project_route(
        project_id: UUID, payload: ProjectUpdateRequest, principal: PrincipalDependency
    ) -> dict[str, Any]:
        if payload.name is None and payload.is_active is None:
            raise deny(
                422,
                "validation_error",
                "Validation failed",
                "At least one project field is required.",
            )
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            _require_membership(session, principal)
            return update_project(
                session,
                project_id,
                name=payload.name,
                is_active=payload.is_active,
            )

    @app.delete("/api/v1/projects/{project_id}", status_code=204)
    def delete_project_route(project_id: UUID, principal: PrincipalDependency) -> Response:
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            _require_membership(session, principal)
            if not delete_project(session, project_id):
                raise OrganizationNotFound("project unavailable")
        return Response(status_code=204)

    @app.post("/api/v1/tags", status_code=201)
    def create_tag_route(payload: TagRequest, principal: PrincipalDependency) -> dict[str, Any]:
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            _require_membership(session, principal)
            return create_tag(session, payload.name)

    @app.get("/api/v1/tags")
    def list_tags_route(principal: PrincipalDependency) -> list[dict[str, Any]]:
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            _require_membership(session, principal)
            return list_tags(session)

    @app.patch("/api/v1/tags/{tag_id}")
    def update_tag_route(
        tag_id: UUID, payload: TagRequest, principal: PrincipalDependency
    ) -> dict[str, Any]:
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            _require_membership(session, principal)
            return update_tag(session, tag_id, name=payload.name)

    @app.delete("/api/v1/tags/{tag_id}", status_code=204)
    def delete_tag_route(tag_id: UUID, principal: PrincipalDependency) -> Response:
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            _require_membership(session, principal)
            if not delete_tag(session, tag_id):
                raise OrganizationNotFound("tag unavailable")
        return Response(status_code=204)

    @app.put("/api/v1/sources/{source_id}/organization")
    def organize_source_route(
        source_id: UUID,
        payload: SourceOrganizationRequest,
        principal: PrincipalDependency,
    ) -> dict[str, Any]:
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            _require_membership(session, principal)
            return organize_source(
                session,
                source_id,
                project_id=payload.project_id,
                tag_ids=payload.tag_ids,
            )

    @app.get("/api/v1/today")
    def today_route(
        principal: PrincipalDependency, as_of: datetime | None = None
    ) -> dict[str, Any]:
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            _require_membership(session, principal)
            return today_view(session, as_of=as_of or datetime.now(UTC))

    @app.post("/api/v1/memories/{memory_id}/resurface", status_code=202)
    def mark_memory_resurfaced(memory_id: UUID, principal: PrincipalDependency) -> dict[str, Any]:
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            _require_membership(session, principal)
            visible = session.scalar(
                text(
                    "SELECT id FROM approved_memories "
                    "WHERE id=:memory AND status='active' FOR UPDATE"
                ),
                {"memory": memory_id},
            )
            if visible is None:
                raise MemoryNotFound("memory unavailable")
            event_id = session.scalar(
                text(
                    "INSERT INTO memory_resurfacing_events "
                    "(owner_id,workspace_id,memory_id) VALUES "
                    "(:owner,:workspace,:memory) "
                    "ON CONFLICT (memory_id,((resurfaced_at AT TIME ZONE 'UTC')::date)) "
                    "DO NOTHING RETURNING id"
                ),
                {
                    "owner": principal.owner_id,
                    "workspace": principal.workspace_id,
                    "memory": memory_id,
                },
            )
        safe_log(
            LOGGER,
            logging.INFO,
            "memory_resurfaced",
            memory_id=memory_id,
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            state="active",
        )
        return {"memory_id": memory_id, "recorded": event_id is not None}

    @app.get("/api/v1/memory-proposals")
    def list_memory_proposals(
        principal: PrincipalDependency,
        status: Literal["proposed", "approved", "rejected"] = "proposed",
    ) -> list[dict[str, Any]]:
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            _require_membership(session, principal)
            rows = session.execute(
                text(
                    "SELECT proposal.id AS proposal_id,proposal.normalized_statement AS statement,"
                    "proposal.category,proposal.confidence,"
                    "proposal.evidence_quality_label AS evidence_quality,proposal.status,"
                    "proposal.proposed_at,proposal.decided_at,"
                    "coalesce(array_agg(evidence.chunk_id ORDER BY "
                    "evidence.created_at,evidence.id) FILTER (WHERE evidence.chunk_id IS NOT NULL),"
                    "'{}'::uuid[]) AS source_chunk_ids "
                    "FROM memory_proposals AS proposal "
                    "LEFT JOIN memory_proposal_evidence AS evidence "
                    "ON evidence.proposal_id=proposal.id WHERE proposal.status=:status "
                    "GROUP BY proposal.id ORDER BY proposal.proposed_at DESC,proposal.id"
                ),
                {"status": status},
            ).mappings()
            return [dict(row) for row in rows]

    def _proposal_for_policy(
        request: Request, principal: Principal, proposal_id: UUID, category: str | None = None
    ) -> dict[str, Any]:
        if category is None:
            with scoped_session(
                session_factory, principal.owner_id, principal.workspace_id
            ) as session:
                _require_membership(session, principal)
                category = session.scalar(
                    text(
                        "SELECT category FROM memory_proposals "
                        "WHERE id=:proposal AND status='proposed'"
                    ),
                    {"proposal": proposal_id},
                )
                if category is None:
                    raise MemoryNotFound("memory proposal unavailable")
        initial = _policy_gate(
            request,
            principal,
            action="approve_memory",
            resource_type="memory",
            resource_id=proposal_id,
            memory_category=category,
            resource_query=(
                "SELECT id,category FROM memory_proposals WHERE id=:proposal AND status='proposed'"
            ),
            resource_parameters={"proposal": proposal_id},
        )
        assert initial is not None
        return initial

    @app.post("/api/v1/memory-proposals/{proposal_id}/approve")
    def approve_memory_route(
        proposal_id: UUID,
        payload: MemoryDecisionRequest,
        request: Request,
        principal: PrincipalDependency,
        idempotency_header: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> dict[str, Any]:
        _proposal_for_policy(request, principal, proposal_id)
        result = approve_memory(
            session_factory,
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            proposal_id=proposal_id,
            idempotency_key=required_idempotency_key(idempotency_header, payload.idempotency_key),
        )
        safe_log(
            LOGGER,
            logging.INFO,
            "memory_approved",
            memory_id=result["memory_id"],
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            state="active",
        )
        return result

    @app.post("/api/v1/memory-proposals/{proposal_id}/edit-and-approve")
    def edit_and_approve_memory_route(
        proposal_id: UUID,
        payload: MemoryEditRequest,
        request: Request,
        principal: PrincipalDependency,
        idempotency_header: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> dict[str, Any]:
        _proposal_for_policy(request, principal, proposal_id, payload.category)
        result = edit_and_approve_memory(
            session_factory,
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            proposal_id=proposal_id,
            statement=payload.statement,
            category=payload.category,
            confidence=payload.confidence,
            evidence_quality=payload.evidence_quality,
            idempotency_key=required_idempotency_key(idempotency_header, payload.idempotency_key),
        )
        safe_log(
            LOGGER,
            logging.INFO,
            "memory_approved",
            memory_id=result["memory_id"],
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            state="active",
        )
        return result

    @app.post("/api/v1/memory-proposals/{proposal_id}/reject")
    def reject_memory_route(
        proposal_id: UUID,
        payload: MemoryDecisionRequest,
        principal: PrincipalDependency,
        idempotency_header: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> dict[str, Any]:
        result = reject_memory_proposal(
            session_factory,
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            proposal_id=proposal_id,
            idempotency_key=required_idempotency_key(idempotency_header, payload.idempotency_key),
        )
        safe_log(
            LOGGER,
            logging.INFO,
            "memory_rejected",
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            state="rejected",
        )
        return result

    @app.get("/api/v1/memories")
    def list_memories(
        principal: PrincipalDependency,
        status: Literal["active", "superseded", "archived", "purge_pending"] | None = None,
    ) -> list[dict[str, Any]]:
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            _require_membership(session, principal)
            rows = session.execute(
                text(
                    "SELECT memory.id AS memory_id,memory.status,memory.approved_at,"
                    "memory.supersedes_memory_id,memory.superseded_by_id,"
                    "revision.id AS revision_id,revision.revision_number,"
                    "revision.normalized_statement AS statement,revision.category,"
                    "revision.confidence,revision.evidence_quality_label AS evidence_quality "
                    "FROM approved_memories AS memory JOIN memory_revisions AS revision "
                    "ON revision.id=memory.current_revision_id "
                    "WHERE (CAST(:status AS text) IS NULL OR memory.status=:status) "
                    "AND memory.status <> 'purged' "
                    "ORDER BY memory.approved_at DESC,memory.id"
                ),
                {"status": status},
            ).mappings()
            return [dict(row) for row in rows]

    @app.get("/api/v1/memories/{memory_id}")
    def memory_detail_route(memory_id: UUID, principal: PrincipalDependency) -> dict[str, Any]:
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            _require_membership(session, principal)
            memory = (
                session.execute(
                    text(
                        "SELECT id AS memory_id,proposal_id,status,approved_at,"
                        "supersedes_memory_id,superseded_by_id FROM approved_memories "
                        "WHERE id=:memory AND status <> 'purged'"
                    ),
                    {"memory": memory_id},
                )
                .mappings()
                .one_or_none()
            )
            if memory is None:
                raise MemoryNotFound("memory unavailable")
            revisions = session.execute(
                text(
                    "SELECT revision.id AS revision_id,revision.revision_number,"
                    "revision.normalized_statement AS statement,revision.category,"
                    "revision.confidence,revision.evidence_quality_label AS evidence_quality,"
                    "revision.created_at,"
                    "coalesce(array_agg(evidence.chunk_id ORDER BY "
                    "evidence.created_at,evidence.id) FILTER (WHERE evidence.chunk_id IS NOT NULL),"
                    "'{}'::uuid[]) AS source_chunk_ids "
                    "FROM memory_revisions AS revision "
                    "LEFT JOIN memory_revision_evidence AS evidence "
                    "ON evidence.revision_id=revision.id WHERE revision.memory_id=:memory "
                    "GROUP BY revision.id ORDER BY revision.revision_number"
                ),
                {"memory": memory_id},
            ).mappings()
            return {**dict(memory), "revisions": [dict(row) for row in revisions]}

    @app.post("/api/v1/memories/{memory_id}/revise")
    def revise_memory_route(
        memory_id: UUID,
        payload: MemoryRevisionRequest,
        principal: PrincipalDependency,
        idempotency_header: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> dict[str, Any]:
        return revise_memory(
            session_factory,
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            memory_id=memory_id,
            statement=payload.statement,
            category=payload.category,
            evidence_chunk_ids=payload.source_chunk_ids,
            confidence=payload.confidence,
            evidence_quality=payload.evidence_quality,
            idempotency_key=required_idempotency_key(idempotency_header, payload.idempotency_key),
        )

    @app.post("/api/v1/memories/{memory_id}/supersede")
    def supersede_memory_route(
        memory_id: UUID,
        payload: MemorySupersedeRequest,
        principal: PrincipalDependency,
        idempotency_header: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> dict[str, Any]:
        return supersede_memory(
            session_factory,
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            memory_id=memory_id,
            superseding_memory_id=payload.superseding_memory_id,
            idempotency_key=required_idempotency_key(idempotency_header, payload.idempotency_key),
        )

    @app.post("/api/v1/memories/{memory_id}/archive")
    def archive_memory_route(
        memory_id: UUID,
        payload: MemoryDecisionRequest,
        principal: PrincipalDependency,
        idempotency_header: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> dict[str, Any]:
        return archive_memory(
            session_factory,
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            memory_id=memory_id,
            idempotency_key=required_idempotency_key(idempotency_header, payload.idempotency_key),
        )

    @app.post("/api/v1/sources/{source_id}/purge", status_code=202)
    def purge_source_route(
        source_id: UUID,
        payload: PurgeRequest,
        request: Request,
        principal: PrincipalDependency,
        idempotency_header: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> dict[str, Any]:
        _policy_gate(
            request,
            principal,
            action="purge_source",
            resource_type="source",
            resource_id=source_id,
            resource_query=(
                "SELECT id FROM sources WHERE id=:source AND deleted_at IS NULL "
                "AND processing_state NOT IN ('purge_pending','purged')"
            ),
            resource_parameters={"source": source_id},
        )
        result = request_source_purge(
            session_factory,
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            source_id=source_id,
            reason_code=payload.reason_code,
            idempotency_key=required_idempotency_key(idempotency_header, payload.idempotency_key),
        )
        safe_log(
            LOGGER,
            logging.INFO,
            "source_purge_requested",
            source_id=source_id,
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            state="queued",
        )
        return result

    @app.post("/api/v1/memories/{memory_id}/purge", status_code=202)
    def purge_memory_route(
        memory_id: UUID,
        payload: PurgeRequest,
        request: Request,
        principal: PrincipalDependency,
        idempotency_header: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> dict[str, Any]:
        row = _policy_gate(
            request,
            principal,
            action="purge_memory",
            resource_type="memory",
            resource_id=memory_id,
            resource_query=(
                "SELECT memory.id,revision.category FROM approved_memories AS memory "
                "JOIN memory_revisions AS revision ON revision.id=memory.current_revision_id "
                "WHERE memory.id=:memory AND memory.status IN ('active','superseded','archived')"
            ),
            resource_parameters={"memory": memory_id},
            resource_lock_target="memory",
        )
        assert row is not None
        result = request_memory_purge(
            session_factory,
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            memory_id=memory_id,
            reason_code=payload.reason_code,
            idempotency_key=required_idempotency_key(idempotency_header, payload.idempotency_key),
        )
        safe_log(
            LOGGER,
            logging.INFO,
            "memory_purge_requested",
            memory_id=memory_id,
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            state="queued",
        )
        return result

    @app.get("/api/v1/purges/{operation_id}")
    def purge_status_route(operation_id: UUID, principal: PrincipalDependency) -> dict[str, Any]:
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            _require_membership(session, principal)
            operation = (
                session.execute(
                    text(
                        "SELECT id AS operation_id,resource_type,resource_id,state,attempts,"
                        "error_class,created_at,finished_at FROM purge_operations "
                        "WHERE id=:operation"
                    ),
                    {"operation": operation_id},
                )
                .mappings()
                .one_or_none()
            )
            if operation is None:
                raise PurgeNotFound("purge unavailable")
            events = session.execute(
                text(
                    "SELECT attempt,from_state,to_state,reason_class,occurred_at "
                    "FROM purge_operation_events WHERE operation_id=:operation "
                    "ORDER BY occurred_at,id"
                ),
                {"operation": operation_id},
            ).mappings()
            return {**dict(operation), "events": [dict(row) for row in events]}

    @app.get("/api/v1/sources/{source_id}")
    def source_metadata(source_id: UUID, principal: PrincipalDependency) -> dict[str, Any]:
        try:
            with scoped_session(
                session_factory, principal.owner_id, principal.workspace_id
            ) as session:
                row = source_detail(session, source_id)
        except SQLAlchemyError as exc:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "database_unavailable",
                    "title": "Database unavailable",
                    "detail": "Persistence is temporarily unavailable.",
                    "retryable": True,
                },
            ) from exc
        if row is None:
            raise HTTPException(
                status_code=404,
                detail={
                    "code": "source_not_found",
                    "title": "Source unavailable",
                    "detail": "The source is unavailable in the active workspace.",
                    "retryable": False,
                },
            )
        return row

    def capture_response(result: CaptureResult) -> CaptureResponse:
        return CaptureResponse(**result.__dict__)

    def capture_idempotency_key(header: str | None, body: str | None) -> str | None:
        if header is not None and body is not None and header != body:
            raise IdempotencyConflict("header and body idempotency keys disagree")
        return header or body

    def required_idempotency_key(header: str | None, body: str | None) -> str:
        key = capture_idempotency_key(header, body)
        if key is None:
            raise deny(
                422,
                "idempotency_required",
                "Idempotency key required",
                "This mutation requires an idempotency key.",
            )
        return key

    @app.post("/api/v1/captures/text", response_model=CaptureResponse, status_code=202)
    def capture_text(
        payload: TextCaptureRequest,
        request: Request,
        principal: PrincipalDependency,
        idempotency_header: Annotated[
            str | None, Header(alias="Idempotency-Key", min_length=1, max_length=200)
        ] = None,
    ) -> CaptureResponse:
        data = payload.content.encode()
        if not data or len(data) > resolved.max_upload_bytes:
            raise deny(413, "capture_too_large", "Capture rejected", "Capture size is invalid.")
        mime_type = "text/markdown" if payload.source_type == "markdown" else "text/plain"
        _capture_policy(
            request,
            principal,
            source_type=payload.source_type,
            mime_type=mime_type,
            byte_count=len(data),
            project_id=payload.project_id,
            tag_ids=payload.tag_ids,
        )
        result = capture_source(
            session_factory,
            app.state.storage,
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            source_type=payload.source_type,
            title=payload.title,
            mime_type=mime_type,
            data=data,
            idempotency_key=capture_idempotency_key(idempotency_header, payload.idempotency_key),
        )
        _organize_capture(principal, result, payload.project_id, payload.tag_ids)
        safe_log(
            LOGGER,
            logging.INFO,
            "source_captured",
            source_id=result.source_id,
            job_id=result.job_id,
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            state=result.state,
            byte_count=len(data),
        )
        return capture_response(result)

    @app.post("/api/v1/captures/upload", response_model=CaptureResponse, status_code=202)
    async def capture_upload(
        request: Request,
        principal: PrincipalDependency,
        file: Annotated[UploadFile, File()],
        title: Annotated[str, Form()],
        project_id: Annotated[UUID | None, Form()] = None,
        tag_ids: Annotated[list[UUID] | None, Form()] = None,
        idempotency_key: Annotated[str | None, Form()] = None,
        idempotency_header: Annotated[
            str | None, Header(alias="Idempotency-Key", min_length=1, max_length=200)
        ] = None,
    ) -> CaptureResponse:
        resolved_tag_ids = tag_ids or []
        if (
            not title.strip()
            or len(title) > 300
            or (idempotency_key is not None and not 1 <= len(idempotency_key) <= 200)
        ):
            raise deny(
                422,
                "validation_error",
                "Validation failed",
                "The request did not match the API contract.",
            )
        data = await file.read(resolved.max_upload_bytes + 1)
        if len(data) > resolved.max_upload_bytes:
            raise deny(
                413,
                "capture_too_large",
                "Upload rejected",
                "File exceeds the configured size limit.",
            )
        validated = validate_upload(
            file.filename,
            file.content_type or "",
            data,
            resolved.max_upload_bytes,
            resolved.max_extracted_chars,
        )
        _capture_policy(
            request,
            principal,
            source_type=validated.source_type,
            mime_type=validated.mime_type,
            byte_count=len(validated.data),
            project_id=project_id,
            tag_ids=resolved_tag_ids,
        )
        result = capture_source(
            session_factory,
            app.state.storage,
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            source_type=validated.source_type,
            title=title,
            mime_type=validated.mime_type,
            data=validated.data,
            filename=validated.filename,
            idempotency_key=capture_idempotency_key(idempotency_header, idempotency_key),
        )
        _organize_capture(principal, result, project_id, resolved_tag_ids)
        safe_log(
            LOGGER,
            logging.INFO,
            "source_captured",
            source_id=result.source_id,
            job_id=result.job_id,
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            state=result.state,
            byte_count=len(validated.data),
        )
        return capture_response(result)

    @app.post("/api/v1/captures/url", response_model=CaptureResponse, status_code=202)
    def capture_url(
        payload: UrlCaptureRequest,
        request: Request,
        principal: PrincipalDependency,
        idempotency_header: Annotated[
            str | None, Header(alias="Idempotency-Key", min_length=1, max_length=200)
        ] = None,
    ) -> CaptureResponse:
        try:
            normalized, _, _ = validate_url_syntax(payload.url)
        except SafeUrlError as exc:
            raise deny(400, "url_rejected", "URL rejected", str(exc)) from exc
        data = normalized.encode()
        _capture_policy(
            request,
            principal,
            source_type="url",
            mime_type="text/uri-list",
            byte_count=len(data),
            project_id=payload.project_id,
            tag_ids=payload.tag_ids,
        )
        result = capture_source(
            session_factory,
            app.state.storage,
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            source_type="url",
            title=payload.title,
            mime_type="text/uri-list",
            data=data,
            original_uri=normalized,
            idempotency_key=capture_idempotency_key(idempotency_header, payload.idempotency_key),
        )
        _organize_capture(principal, result, payload.project_id, payload.tag_ids)
        safe_log(
            LOGGER,
            logging.INFO,
            "source_captured",
            source_id=result.source_id,
            job_id=result.job_id,
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            state=result.state,
            byte_count=len(data),
        )
        return capture_response(result)

    @app.get("/api/v1/jobs/{job_id}")
    def ingestion_job(job_id: UUID, principal: PrincipalDependency) -> dict[str, Any]:
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            row = (
                session.execute(
                    text(
                        "SELECT id,source_id,state,attempts,error_code,error_message "
                        "FROM ingestion_jobs WHERE id=:id"
                    ),
                    {"id": job_id},
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            raise deny(404, "job_not_found", "Job unavailable", "The ingestion job is unavailable.")
        return dict(row)

    @app.get("/api/v1/sources/{source_id}/content")
    def source_content(source_id: UUID, principal: PrincipalDependency) -> dict[str, Any]:
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            row = (
                session.execute(
                    text(
                        "SELECT source.id,document.extracted_text FROM sources AS source "
                        "JOIN source_versions AS version ON version.source_id=source.id "
                        "JOIN documents AS document ON document.source_version_id=version.id "
                        "WHERE source.id=:id AND source.processing_state='ready' "
                        "AND source.deleted_at IS NULL "
                        "ORDER BY version.version_number DESC LIMIT 1"
                    ),
                    {"id": source_id},
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            raise deny(
                404,
                "source_content_unavailable",
                "Source unavailable",
                "Extracted content is unavailable.",
            )
        return dict(row)

    @app.get("/api/v1/sources/{source_id}/context/{chunk_id}")
    def source_citation_context(
        source_id: UUID, chunk_id: UUID, principal: PrincipalDependency
    ) -> dict[str, Any]:
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            row = citation_context(session, source_id, chunk_id)
        if row is None:
            raise deny(
                404,
                "citation_unavailable",
                "Citation unavailable",
                "The supporting passage is unavailable.",
            )
        return row

    @app.get("/api/v1/search", response_model=SearchResponse)
    def search(
        principal: PrincipalDependency,
        q: Annotated[str, Query(min_length=1, max_length=2000)],
        project_id: UUID | None = None,
        tag_id: UUID | None = None,
        source_type: Literal["note", "markdown", "txt", "pdf", "docx", "url"] | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        limit: Annotated[int, Query(ge=1, le=50)] = 20,
    ) -> SearchResponse:
        resolved_query = q.strip()
        if not resolved_query:
            raise deny(
                422,
                "validation_error",
                "Validation failed",
                "The request did not match the API contract.",
            )
        filters = SearchFilters(project_id, tag_id, source_type, date_from, date_to)
        with scoped_session(session_factory, principal.owner_id, principal.workspace_id) as session:
            results, semantic_status = hybrid_search(
                session,
                resolved_query,
                app.state.embedding_provider,
                filters=filters,
                limit=limit,
            )
        public_results = [
            SearchResultResponse.model_validate(
                {
                    key: value
                    for key, value in result.items()
                    if key not in {"chunk_text", "semantic_status"}
                }
            )
            for result in results
        ]
        return SearchResponse.model_validate(
            {"results": public_results, "semantic_status": semantic_status}
        )

    @app.post("/api/v1/answers")
    def create_answer(
        payload: AnswerRequest,
        request: Request,
        principal: PrincipalDependency,
        idempotency_header: Annotated[
            str | None, Header(alias="Idempotency-Key", min_length=1, max_length=200)
        ] = None,
    ) -> dict[str, Any]:
        _policy_gate(
            request,
            principal,
            action="generate_answer",
            resource_type="workspace",
            resource_id=principal.workspace_id,
        )
        answer = answer_question(
            session_factory,
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            query=payload.query,
            conversation_id=payload.conversation_id,
            filters=payload.filters.domain(),
            config=payload.retrieval_config.domain(),
            embedding_provider=app.state.embedding_provider,
            generation_provider=app.state.generation_provider,
            configured_answer_min_similarity=resolved.answer_min_similarity,
            configured_embedding_profile_version=resolved.embedding_profile_version,
            configured_embedding_dimensions=resolved.embedding_dimensions,
            idempotency_key=capture_idempotency_key(idempotency_header, payload.idempotency_key),
        )
        proposal = None
        statements = answer["evidence_supported_statements"]
        if answer["status"] == "grounded" and statements:
            chunk_ids = list(
                dict.fromkeys(
                    citation["chunk_id"]
                    for statement in statements
                    for citation in statement["citations"]
                )
            )
            try:
                proposal = propose_memory(
                    session_factory,
                    owner_id=principal.owner_id,
                    workspace_id=principal.workspace_id,
                    statement=" ".join(statement["text"] for statement in statements),
                    category="reference",
                    evidence_chunk_ids=chunk_ids,
                    confidence=1.0,
                    evidence_quality="high",
                    idempotency_key=f"answer:{answer['answer_id']}:proposal",
                )
            except (MemoryEvidenceUnavailable, ValueError):
                proposal = None
        safe_log(
            LOGGER,
            logging.INFO,
            "answer_created",
            answer_id=answer["answer_id"],
            owner_id=principal.owner_id,
            workspace_id=principal.workspace_id,
            status=answer["status"],
            citation_count=sum(len(statement["citations"]) for statement in statements),
        )
        return {**answer, "proposed_memory": proposal}

    return app


app = create_app()
