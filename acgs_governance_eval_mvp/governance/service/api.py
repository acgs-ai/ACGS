from __future__ import annotations

import os

from governance.adapters.tools import GovernedToolAdapter
from governance.audit.jsonl_chain import ChainHashAuditStore
from governance.policy_loader import load_policy_bundle, load_roles


try:
    from fastapi import Depends, FastAPI, HTTPException, Query
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
except Exception as exc:  # pragma: no cover
    raise RuntimeError("Install the api extra: pip install -e '.[api]'") from exc


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
    expected = os.environ.get("ACGS_API_TOKEN")
    if not expected or credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="invalid or missing auth token")
    if credentials.credentials != expected:
        raise HTTPException(status_code=401, detail="invalid or missing auth token")
    tenant, sep, _secret = expected.partition(":")
    if not sep or not tenant:
        raise HTTPException(status_code=401, detail="invalid or missing auth token")
    return tenant


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
    events = _adapter.audit_store.query(event_id=event_id, limit=1)
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
    return _adapter.audit_store.query(rule_id=rule_id, gate=gate, allow=allow, risk_tag=risk_tag, limit=limit)


@app.get("/audit/verify-chain")
async def verify_chain(caller_tenant: str = Depends(verify_caller)):
    if _adapter.audit_store is None:
        raise HTTPException(status_code=500, detail="audit store is disabled")
    return _adapter.audit_store.verify_chain()
