import hashlib
from ipaddress import ip_address
from uuid import UUID

from fastapi import HTTPException, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import text

from second_brain.auth import PRINCIPAL_HEADER_NAMES, SESSION_COOKIE_NAME
from second_brain.config import Settings


class Principal(BaseModel):
    model_config = ConfigDict(frozen=True)

    owner_id: UUID
    workspace_id: UUID
    session_id: UUID | None = None
    csrf_token_hash: str | None = None


def _deny(status_code: int, code: str, title: str, detail: str) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "title": title, "detail": detail, "retryable": False},
    )


def _ids(request: Request) -> tuple[UUID, UUID]:
    try:
        owner_id = UUID(request.headers["x-second-brain-owner-id"])
        workspace_id = UUID(request.headers["x-second-brain-workspace-id"])
    except (KeyError, ValueError) as exc:
        raise _deny(
            401,
            "principal_required",
            "Authentication required",
            "A verified owner and workspace principal is required.",
        ) from exc
    return owner_id, workspace_id


def get_principal(request: Request) -> Principal:
    settings: Settings = request.app.state.settings

    if settings.auth_mode == "development_headers":
        owner_id, workspace_id = _ids(request)
        client_host = request.client.host if request.client else ""
        try:
            is_loopback = ip_address(client_host).is_loopback
        except ValueError:
            is_loopback = False
        if not is_loopback or "x-forwarded-for" in request.headers:
            raise _deny(
                403,
                "development_principal_forbidden",
                "Development principal forbidden",
                "Development identity is accepted only over a direct loopback connection.",
            )
        return Principal(owner_id=owner_id, workspace_id=workspace_id)

    if any(header in request.headers for header in PRINCIPAL_HEADER_NAMES):
        raise _deny(
            400,
            "browser_principal_headers_forbidden",
            "Principal headers forbidden",
            "Browser-supplied principal headers are not accepted.",
        )
    cached = getattr(request.state, "principal", None)
    if isinstance(cached, Principal):
        return cached
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        raise _deny(
            401, "session_required", "Authentication required", "A valid session is required."
        )
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    engine = request.app.state.engine
    with engine.begin() as connection:
        row = (
            connection.execute(
                text("SELECT * FROM resolve_second_brain_session(:token_hash)"),
                {"token_hash": token_hash},
            )
            .mappings()
            .one_or_none()
        )
    if row is None:
        raise _deny(
            401, "session_invalid", "Authentication required", "The session is invalid or expired."
        )
    principal = Principal(
        owner_id=row["owner_id"],
        workspace_id=row["workspace_id"],
        session_id=row["session_id"],
        csrf_token_hash=str(row["csrf_token_hash"]),
    )
    request.state.principal = principal
    return principal
