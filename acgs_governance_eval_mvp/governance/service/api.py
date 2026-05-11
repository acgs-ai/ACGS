from __future__ import annotations

import hmac
import os

from governance.adapters.tools import GovernedToolAdapter
from governance.audit.jsonl_chain import ChainHashAuditStore
from governance.policy_loader import load_policy_bundle, load_roles

try:
    from fastapi import Depends, FastAPI, HTTPException, Query
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
except Exception as exc:  # pragma: no cover
    raise RuntimeError("Install the api extra: pip install -e '.[api]'") from exc


def _load_token_registry() -> dict[str, bytes]:
    """Map tenant -> bytes(secret) parsed from env.

    ACGS_API_TOKENS=tenant1:secret1,tenant2:secret2,...   (preferred)
    ACGS_API_TOKEN=tenant:secret                          (legacy single-tenant)
    """
    registry: dict[str, bytes] = {}
    multi = os.environ.get("ACGS_API_TOKENS", "")
    for entry in (e.strip() for e in multi.split(",") if e.strip()):
        tenant, sep, secret = entry.partition(":")
        if sep and tenant and secret:
            registry[tenant] = secret.encode("utf-8")
    legacy = os.environ.get("ACGS_API_TOKEN")
    if legacy:
        tenant, sep, secret = legacy.partition(":")
        if sep and tenant and secret and tenant not in registry:
            registry[tenant] = secret.encode("utf-8")
    return registry


def _admin_tenants() -> set[str]:
    raw = os.environ.get("ACGS_ADMIN_TENANTS", "")
    return {t.strip() for t in raw.split(",") if t.strip()}


def build_adapter() -> GovernedToolAdapter:
    roles_path = os.environ.get("ACGS_ROLES_PATH", "governance/roles.json")
    policy_dir = os.environ.get("ACGS_POLICY_DIR", "governance/policies/2026-05")
    audit_path = os.environ.get("ACGS_AUDIT_PATH", ".acgs/audit.jsonl")
    return GovernedToolAdapter(
        roles_bundle=load_roles(roles_path),
        policy_bundle=load_policy_bundle(policy_dir),
        audit_store=ChainHashAuditStore(audit_path),
    )


app = FastAPI(title="ACGS Governance Evaluation MVP", version="0.1.0")
_adapter = build_adapter()

_http_bearer = HTTPBearer(auto_error=False)


async def verify_caller(
    credentials: HTTPAuthorizationCredentials | None = Depends(_http_bearer),
) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="invalid or missing auth token")
    p_tenant, p_sep, p_secret = (credentials.credentials or "").partition(":")
    registry = _load_token_registry()
    if not registry or not p_sep or not p_tenant:
        # Constant-time miss to avoid distinguishing "no registry" from "wrong token"
        hmac.compare_digest(b"x" * 32, b"y" * 32)
        raise HTTPException(status_code=401, detail="invalid or missing auth token")
    candidate = registry.get(p_tenant)
    if candidate is None:
        hmac.compare_digest(b"x" * 32, b"y" * 32)
        raise HTTPException(status_code=401, detail="invalid or missing auth token")
    if not hmac.compare_digest(p_secret.encode("utf-8"), candidate):
        raise HTTPException(status_code=401, detail="invalid or missing auth token")
    return p_tenant


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/govern/validate")
async def validate(payload: dict, caller_tenant: str = Depends(verify_caller)):
    actor = payload.get("actor") or {}
    actor_tenant = actor.get("tenant", "default") if isinstance(actor, dict) else "default"
    metadata = payload.get("metadata") or {}
    cross_tenant = bool(metadata.get("cross_tenant_delegation")) if isinstance(metadata, dict) else False
    if not cross_tenant and actor_tenant != caller_tenant:
        raise HTTPException(status_code=403, detail="actor tenant does not match caller tenant")
    decision = _adapter.validate(payload)
    return decision.to_dict()


@app.get("/govern/explain/{event_id}")
async def explain(event_id: str, caller_tenant: str = Depends(verify_caller)):
    if _adapter.audit_store is None:
        raise HTTPException(status_code=500, detail="audit store is disabled")
    events = _adapter.audit_store.query(event_id=event_id, tenant=caller_tenant, limit=1)
    if not events:
        raise HTTPException(status_code=404, detail="event not found")
    event = events[0]
    governance_checks = [check for check in event.get("checks", []) if check.get("gate") == "governance_recall"]
    return {
        "event_id": event_id,
        "allow": event.get("allow"),
        "explain": governance_checks[0].get("evidence") if governance_checks else event,
    }


@app.get("/audit/query")
async def audit_query(
    rule_id: str | None = None,
    gate: str | None = None,
    allow: bool | None = None,
    risk_tag: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    caller_tenant: str = Depends(verify_caller),
):
    if _adapter.audit_store is None:
        raise HTTPException(status_code=500, detail="audit store is disabled")
    return _adapter.audit_store.query(
        rule_id=rule_id, gate=gate, allow=allow, risk_tag=risk_tag, tenant=caller_tenant, limit=limit
    )


@app.get("/audit/verify-chain")
async def verify_chain(caller_tenant: str = Depends(verify_caller)):
    if _adapter.audit_store is None:
        raise HTTPException(status_code=500, detail="audit store is disabled")
    if caller_tenant not in _admin_tenants():
        raise HTTPException(status_code=403, detail="chain verification requires admin tenant")
    return _adapter.audit_store.verify_chain()
