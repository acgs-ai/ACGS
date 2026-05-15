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
from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, Header, HTTPException, Request, status

if TYPE_CHECKING:
    from agent_bus_analyzer.store import TraceStore

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
_validator_lock = threading.Lock()


def set_validator(fn: ValidatorFn) -> None:
    """Install the bearer-token validator. Used by app startup + tests."""
    global _validator
    with _validator_lock:
        _validator = fn


def get_validator() -> ValidatorFn:
    with _validator_lock:
        return _validator


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


async def require_reviewer_role(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> frozenset[str]:
    """FastAPI dependency: extract bearer token, validate, enforce roles."""
    if authorization is None or not authorization.lower().startswith("bearer "):
        log.warning("rbac.deny reason=missing_bearer")
        _record_rejection(request, "missing_bearer")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.split(" ", 1)[1].strip()
    roles = get_validator()(token)
    if roles is None:
        log.warning("rbac.deny reason=invalid_token")
        _record_rejection(request, "invalid_token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not REVIEWER_ROLES.intersection(roles):
        log.warning("rbac.deny reason=insufficient_role roles=%s", sorted(roles))
        _record_rejection(request, "insufficient_role")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Caller lacks reviewer role",
        )
    return roles


# Re-export the dependency in a name that reads cleanly at the route site.
ReviewerRole = Annotated[frozenset[str], Depends(require_reviewer_role)]
