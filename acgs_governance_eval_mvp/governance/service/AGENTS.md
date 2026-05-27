# AGENTS.md - acgs_governance_eval_mvp/governance/service

## Purpose

Public HTTP surface for the governance pipeline. The FastAPI app composes the
`GovernedToolAdapter` (which itself composes adapters, gates, hooks, audit,
metrics) and exposes a small REST contract. Downstream callers SHOULD reach
the pipeline only through this module or through `governance.adapters.tools`.

## Modules

- `api.py` - module attribute `app = FastAPI(...)`. Public routes:
  - `POST /govern/validate` - validate an `ActionRequest` payload and return a `DecisionRecord`.
  - `GET  /govern/explain/{event_id}` - replay the governance-recall explanation for a stored decision.
  - `GET  /audit/query` - filter audit events by `rule_id`, `gate`, `allow`, `risk_tag` (capped at `limit<=1000`).
  - `GET  /audit/verify-chain` - verify the JSONL audit chain hash invariant end-to-end.
  - `GET  /health` - liveness probe.

## Auth & Configuration

- Auth: HTTP Bearer; `ACGS_API_TOKEN` env var carries `tenant:secret`. The token's `tenant` prefix is enforced against `actor.tenant` (cross-tenant calls require `metadata.cross_tenant_delegation`).
- Config env vars: `ACGS_ROLES_PATH` (default `governance/roles.json`), `ACGS_POLICY_DIR` (default `governance/policies/2026-05`), `ACGS_AUDIT_PATH` (default `.acgs/audit.jsonl`).

## Stability

This is the only stable import surface for downstream code. Pipeline
internals (gates, hooks, adapters) may shift between minor versions; this
HTTP contract and its response shape are treated as semver-bounded. Run
with `uvicorn governance.service.api:app --reload --port 8080` after
`pip install -e '.[api]'`.
