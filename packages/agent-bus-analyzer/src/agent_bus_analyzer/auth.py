"""RBAC FastAPI dependency for the query API (T028).

The analyzer does not own an identity system — per plan.md / research §R7
it reads bearer tokens validated by the existing console identity layer.
For now the validator is pluggable: tests inject a fake validator; the
production wiring (deferred to staging) sets the env-driven default.

Rejections (401 / 403) are logged via the structured logger; the audit
sink for rejection-as-event records is a US1 follow-up (see U1/G2 in the
analyze report — wired here but the actual append-to-store happens at
the call site once a TraceStore handle is plumbed through).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status

log = logging.getLogger("agent_bus_analyzer.auth")

REVIEWER_ROLES = frozenset({"governance-reviewer", "operator", "compliance"})

ValidatorFn = Callable[[str], frozenset[str] | None]


def _default_validator(_token: str) -> frozenset[str] | None:
    """Default validator — denies everything until wired to the console layer.

    Returning ``None`` triggers a 401. The intent: production deployment
    sets a real validator via ``set_validator`` at app startup; if the
    operator forgets, the surface fails closed.
    """
    return None


_validator: ValidatorFn = _default_validator


def set_validator(fn: ValidatorFn) -> None:
    """Install the bearer-token validator. Used by app startup + tests."""
    global _validator
    _validator = fn


def get_validator() -> ValidatorFn:
    return _validator


async def require_reviewer_role(
    authorization: Annotated[str | None, Header()] = None,
) -> frozenset[str]:
    """FastAPI dependency: extract bearer token, validate, enforce roles."""
    if authorization is None or not authorization.lower().startswith("bearer "):
        log.warning("rbac.deny reason=missing_bearer")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.split(" ", 1)[1].strip()
    roles = get_validator()(token)
    if roles is None:
        log.warning("rbac.deny reason=invalid_token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not REVIEWER_ROLES.intersection(roles):
        log.warning("rbac.deny reason=insufficient_role roles=%s", sorted(roles))
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Caller lacks reviewer role",
        )
    return roles


# Re-export the dependency in a name that reads cleanly at the route site.
ReviewerRole = Annotated[frozenset[str], Depends(require_reviewer_role)]
