"""RBAC FastAPI dependency for the query API (T028).

The analyzer does not own an identity system — per plan.md / research §R7
it reads bearer tokens validated by the existing console identity layer.
For now the validator is pluggable: tests inject a fake validator; the
production wiring (deferred to staging) sets the env-driven default.

Every rejection is appended to a side-chain in the TraceStore as a
synthetic ``kind="decision", decision="deny", source_agent="api:query"``
event — satisfies FR-011 ("Unauthorized reads MUST themselves be recorded
as audit events"). If no TraceStore is installed (test contexts), the
rejection still emits via the structured logger.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, NoReturn

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator

if TYPE_CHECKING:
    from agent_bus_analyzer.store import TraceStore

log = logging.getLogger("agent_bus_analyzer.auth")

REVIEWER_ROLES = frozenset({"governance-reviewer", "operator", "compliance"})


class AuthenticatedPrincipal(BaseModel):
    """Identity-layer result used by tenant-scoped process intelligence.

    The caller cannot supply this model through an HTTP header or query
    parameter.  It is returned only by the configured bearer-token validator.
    Existing role-only validators remain valid for the legacy bus endpoints,
    but cannot access tenant-scoped process routes.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    subject: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$",
    )
    roles: frozenset[str]

    @field_validator("roles")
    @classmethod
    def require_roles(cls, value: frozenset[str]) -> frozenset[str]:
        if not value or any(not role.strip() for role in value):
            raise ValueError("principal roles must contain non-blank values")
        return value


ValidationResult = AuthenticatedPrincipal | frozenset[str] | None
ValidatorFn = Callable[[str], ValidationResult]
_bearer_scheme = HTTPBearer(auto_error=False)


def _default_validator(_token: str) -> frozenset[str] | None:
    """Default validator — denies everything until wired to the console layer.

    Returning ``None`` triggers a 401. The intent: production deployment
    sets a real validator via ``set_validator`` at app startup; if the
    operator forgets, the surface fails closed.
    """
    return None


_validator: ValidatorFn = _default_validator
_validator_lock = threading.Lock()


def set_validator(fn: ValidatorFn) -> None:
    """Install the bearer-token validator. Used by app startup + tests."""
    global _validator
    with _validator_lock:
        _validator = fn


def get_validator() -> ValidatorFn:
    with _validator_lock:
        return _validator


def _request_validator(request: Request) -> ValidatorFn:
    """Prefer an app-scoped trusted validator while preserving legacy wiring."""
    configured = getattr(request.app.state, "principal_validator", None)
    return configured if callable(configured) else get_validator()


def _record_rejection(
    request: Request,
    reason: str,
    *,
    constitutional_hash: str = "0" * 16,
) -> None:
    """Append a synthetic deny-decision event to the trace store (FR-011).

    No-op if the app has no TraceStore on its state — keeps tests hermetic
    while production runs always have a store.
    """
    store: TraceStore | None = getattr(request.app.state, "store", None)
    if store is None:
        return
    try:
        cid = f"rbac-{datetime.now(UTC).strftime('%Y%m%d')}"
        event = {
            "event_id": str(uuid.uuid4()),
            "correlation_id": cid,
            "recorded_at": datetime.now(UTC).isoformat(),
            "source_agent": "api:query",
            "target_handler_declared": None,
            "target_handler_resolved": None,
            "payload_ref": f"rbac-reject:{reason}",
            "kind": "decision",
            "decision": "deny",
            "flagged_rule": f"rbac.{reason}",
            "audit_receipt_hash": None,
            "constitutional_hash": constitutional_hash,
            "status": "policy-violation",
        }
        store.append(event)
    except Exception:
        # Best-effort: a failure here MUST NOT swallow the underlying 401/403.
        log.exception("rbac.rejection_audit_failed reason=%s", reason)


def _deny(
    request: Request,
    reason: str,
    *,
    status_code: int,
    detail: str,
    authenticate: bool = False,
) -> NoReturn:
    log.warning("rbac.deny reason=%s", reason)
    _record_rejection(request, reason)
    headers = {"WWW-Authenticate": "Bearer"} if authenticate else None
    raise HTTPException(status_code=status_code, detail=detail, headers=headers)


def _authenticate(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None,
) -> AuthenticatedPrincipal | frozenset[str]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        _deny(
            request,
            "missing_bearer",
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            authenticate=True,
        )
    token = credentials.credentials.strip()
    if not token:
        _deny(
            request,
            "invalid_token",
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token",
            authenticate=True,
        )
    result = _request_validator(request)(token)
    if result is None:
        _deny(
            request,
            "invalid_token",
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token",
            authenticate=True,
        )
    return result


def _require_reviewer_roles(
    request: Request,
    result: AuthenticatedPrincipal | frozenset[str],
) -> frozenset[str]:
    roles = result.roles if isinstance(result, AuthenticatedPrincipal) else result
    if not REVIEWER_ROLES.intersection(roles):
        log.warning("rbac.deny reason=insufficient_role roles=%s", sorted(roles))
        _record_rejection(request, "insufficient_role")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Caller lacks reviewer role",
        )
    return roles


async def require_reviewer_role(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(_bearer_scheme),
    ] = None,
) -> frozenset[str]:
    """FastAPI dependency: extract bearer token, validate, enforce roles."""
    return _require_reviewer_roles(request, _authenticate(request, credentials))


async def require_process_principal(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(_bearer_scheme),
    ] = None,
) -> AuthenticatedPrincipal:
    """Require a reviewer identity with trusted tenant scope.

    Role-only validators are intentionally insufficient here.  This prevents
    a caller-controlled header, query, body, or path value from becoming the
    tenant authority for Process Intelligence.
    """
    result = _authenticate(request, credentials)
    _require_reviewer_roles(request, result)
    if not isinstance(result, AuthenticatedPrincipal):
        _deny(
            request,
            "missing_tenant_scope",
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated principal lacks tenant scope",
        )
    return result


# Re-export the dependency in a name that reads cleanly at the route site.
ReviewerRole = Annotated[frozenset[str], Depends(require_reviewer_role)]
ProcessPrincipal = Annotated[AuthenticatedPrincipal, Depends(require_process_principal)]
