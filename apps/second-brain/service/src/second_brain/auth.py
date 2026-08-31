import hashlib
import hmac
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network
from typing import Any
from uuid import UUID

from fastapi import HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from second_brain.config import Settings
from second_brain.db import scoped_session

SESSION_COOKIE_NAME = "second_brain_session"
PRINCIPAL_HEADER_NAMES = frozenset(
    {
        "x-second-brain-owner-id",
        "x-second-brain-workspace-id",
        "x-second-brain-principal-signature",
    }
)


class TrustedAssertion(BaseModel):
    issuer: str = Field(min_length=1, max_length=200)
    audience: str = Field(min_length=1, max_length=200)
    issued_at: int
    expires_at: int
    nonce: UUID
    owner_id: UUID
    workspace_id: UUID
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class IssuedSession:
    token: str
    csrf_token: str
    absolute_expires_at: datetime
    idle_expires_at: datetime


def deny(status: int, code: str, title: str, detail: str) -> HTTPException:
    return HTTPException(
        status_code=status,
        detail={"code": code, "title": title, "detail": detail, "retryable": False},
    )


def assertion_signing_payload(assertion: Mapping[str, Any]) -> bytes:
    fields = (
        "issuer",
        "audience",
        "issued_at",
        "expires_at",
        "nonce",
        "owner_id",
        "workspace_id",
    )
    return "\n".join(str(assertion[field]) for field in fields).encode()


def new_opaque_secret() -> str:
    return secrets.token_urlsafe(32)


def _validate_assertion(request: Request, assertion: TrustedAssertion, settings: Settings) -> None:
    client_host = request.client.host if request.client else ""
    assert settings.trusted_proxy_network is not None
    try:
        trusted = ip_address(client_host) in ip_network(
            settings.trusted_proxy_network, strict=False
        )
    except ValueError:
        trusted = False
    if not trusted:
        raise deny(
            403, "trusted_proxy_required", "Trusted proxy required", "The exchange is unavailable."
        )
    if assertion.issuer != settings.trusted_assertion_issuer:
        raise deny(
            401, "assertion_invalid", "Authentication failed", "The assertion issuer is invalid."
        )
    if assertion.audience != settings.trusted_assertion_audience:
        raise deny(
            401, "assertion_invalid", "Authentication failed", "The assertion audience is invalid."
        )
    now = int(time.time())
    if assertion.issued_at > now + 30 or now - assertion.issued_at > 120:
        raise deny(
            401,
            "assertion_expired",
            "Authentication failed",
            "The assertion time window is invalid.",
        )
    if (
        assertion.expires_at <= now
        or assertion.expires_at <= assertion.issued_at
        or assertion.expires_at - assertion.issued_at > 120
    ):
        raise deny(401, "assertion_expired", "Authentication failed", "The assertion has expired.")
    secret = settings.trusted_proxy_secret
    assert secret is not None
    expected = hmac.new(
        secret.get_secret_value().encode(),
        assertion_signing_payload(assertion.model_dump()),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(assertion.signature, expected):
        raise deny(
            401, "assertion_invalid", "Authentication failed", "The assertion signature is invalid."
        )


def exchange_assertion(
    request: Request,
    assertion: TrustedAssertion,
    settings: Settings,
    session_factory: sessionmaker[Session],
) -> IssuedSession:
    _validate_assertion(request, assertion, settings)
    client_host = request.client.host if request.client else ""
    with session_factory.begin() as rate_session:
        allowed = rate_session.scalar(
            text(
                "SELECT consume_trusted_exchange_attempt("
                "CAST(:peer AS inet), :issuer, CAST(:owner AS uuid), "
                "CAST(:workspace AS uuid), :attempt_limit, :window_seconds)"
            ),
            {
                "peer": client_host,
                "issuer": assertion.issuer,
                "owner": assertion.owner_id,
                "workspace": assertion.workspace_id,
                "attempt_limit": settings.exchange_rate_limit,
                "window_seconds": settings.exchange_rate_window_seconds,
            },
        )
    if not allowed:
        raise deny(
            429,
            "exchange_rate_limited",
            "Too many authentication attempts",
            "The trusted assertion exchange rate limit was exceeded.",
        )
    now = datetime.now(UTC)
    absolute_expires_at = now + timedelta(seconds=settings.session_absolute_seconds)
    idle_expires_at = now + timedelta(seconds=settings.session_idle_seconds)
    session_token = new_opaque_secret()
    csrf_token = new_opaque_secret()
    token_hash = hashlib.sha256(session_token.encode()).hexdigest()
    csrf_hash = hashlib.sha256(csrf_token.encode()).hexdigest()
    with scoped_session(session_factory, assertion.owner_id, assertion.workspace_id) as session:
        member = session.scalar(
            text(
                "SELECT EXISTS (SELECT 1 FROM workspace_memberships "
                "WHERE workspace_id=:workspace AND user_id=:owner)"
            ),
            {"workspace": assertion.workspace_id, "owner": assertion.owner_id},
        )
        if not member:
            raise deny(
                403,
                "workspace_membership_required",
                "Workspace unavailable",
                "The asserted workspace membership is unavailable.",
            )
        nonce_id = session.scalar(
            text(
                "INSERT INTO used_assertion_nonces "
                "(owner_id,workspace_id,issuer,nonce,assertion_expires_at) "
                "VALUES (:owner,:workspace,:issuer,:nonce,:expires) "
                "ON CONFLICT (issuer,nonce) DO NOTHING RETURNING id"
            ),
            {
                "owner": assertion.owner_id,
                "workspace": assertion.workspace_id,
                "issuer": assertion.issuer,
                "nonce": assertion.nonce,
                "expires": datetime.fromtimestamp(assertion.expires_at, UTC),
            },
        )
        if nonce_id is None:
            raise deny(
                409,
                "assertion_replayed",
                "Authentication failed",
                "The assertion was already used.",
            )
        session.execute(
            text(
                "UPDATE sessions SET revoked_at=:now "
                "WHERE revoked_at IS NULL AND owner_id=:owner AND workspace_id=:workspace"
            ),
            {"now": now, "owner": assertion.owner_id, "workspace": assertion.workspace_id},
        )
        session.execute(
            text(
                "INSERT INTO sessions "
                "(owner_id,workspace_id,token_hash,csrf_token_hash,issued_at,"
                "absolute_expires_at,idle_expires_at,idle_timeout_seconds,last_seen_at) "
                "VALUES (:owner,:workspace,:token_hash,:csrf_hash,:now,:absolute,:idle,"
                ":idle_seconds,:now)"
            ),
            {
                "owner": assertion.owner_id,
                "workspace": assertion.workspace_id,
                "token_hash": token_hash,
                "csrf_hash": csrf_hash,
                "now": now,
                "absolute": absolute_expires_at,
                "idle": idle_expires_at,
                "idle_seconds": settings.session_idle_seconds,
            },
        )
    return IssuedSession(session_token, csrf_token, absolute_expires_at, idle_expires_at)
