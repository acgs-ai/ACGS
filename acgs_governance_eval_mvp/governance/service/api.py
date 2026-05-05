from __future__ import annotations

import os

from governance.adapters.tools import GovernedToolAdapter
from governance.audit.jsonl_chain import ChainHashAuditStore
from governance.policy_loader import load_policy_bundle, load_roles


try:
    from fastapi import FastAPI, HTTPException, Query
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


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/govern/validate")
def validate(payload: dict):
    decision = _adapter.validate(payload)
    return decision.to_dict()


@app.get("/govern/explain/{event_id}")
def explain(event_id: str):
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
def audit_query(
    rule_id: str | None = None,
    gate: str | None = None,
    allow: bool | None = None,
    risk_tag: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    if _adapter.audit_store is None:
        raise HTTPException(status_code=500, detail="audit store is disabled")
    return _adapter.audit_store.query(rule_id=rule_id, gate=gate, allow=allow, risk_tag=risk_tag, limit=limit)


@app.get("/audit/verify-chain")
def verify_chain():
    if _adapter.audit_store is None:
        raise HTTPException(status_code=500, detail="audit store is disabled")
    return _adapter.audit_store.verify_chain()
