# acgs-control-plane

**ACGS control-plane alpha** — a local multi-tenant management API over the
[gove-zone](../gove-zone/) governed runtime.

> **No valid Decision Receipt, no side effect.**

The current development path dispatches mutations through the organization's
legacy gove-zone `Kernel` under its **active policy bundle**. It stores legacy,
unsigned `Receipt` records, not signed canonical `DecisionReceipt` artifacts
verified through `execute_with_receipt`. Production posture refuses these legacy
mutation routes rather than representing them as a production governance
membrane. In the local development profile:

- **ALLOW** → database side effect + receipt row commit together; the file-backed
  audit append is outside the SQL transaction and is not atomic with it.
- **DENY** → transaction rolled back; only the deny receipt commits; HTTP 403.
- **ESCALATE** → transaction rolled back; only the escalate receipt commits; HTTP 202.

## Feature map

| Requirement | Where |
|---|---|
| Multi-tenant organization model | `models.Organization`, tenant guard in `app.py` (cross-tenant probes → 404) |
| Agent registry | `POST/GET /orgs/{org}/agents`, lifecycle status changes governed |
| Policy registry | `POST /orgs/{org}/policies` (content-addressed versions via `RuleSetPolicy`), governed activation, dry-run `POST .../policies/simulate` |
| Receipt explorer | `GET /orgs/{org}/receipts` (filter: decision/tool/actor/time, paginated), `GET .../receipts/{id}`, `POST .../receipts/{id}/verify` |
| Audit dashboard | `GET /orgs/{org}/dashboard` — decision mix, top tools/actors, agent gauges, live chain verification |
| Compliance export | `POST /orgs/{org}/exports` — hash-manifested evidence bundle (org, policies, agents, receipts, raw audit chain), externally recomputable via `exports.verify_export_bundle` |
| REST API | FastAPI app factory `create_app(Settings)` |
| PostgreSQL backend | SQLAlchemy 2.0, JSONB on PostgreSQL (`ACP_DATABASE_URL`); tests run the identical ORM on SQLite |
| RBAC | 5 roles (`org_admin`, `policy_author`, `agent_operator`, `auditor`, `viewer`) × permission table in `rbac.py` |

## Two enforcement layers, deliberately distinct

1. **RBAC** answers *"may this principal call this endpoint at all?"* An RBAC denial
   produces no side effect and **no receipt** — nothing governed was attempted.
2. **The governance membrane** answers *"does the org's active policy permit this
   specific action?"* Policy denials are governed decisions and are **always receipted**.

## Tamper evidence

Each org has a local file-backed `ChainHashAuditStore` chain; its tip (event count + last
hash) is anchored in the `organizations` row inside the same transaction as every
receipt. `POST .../receipts/{id}/verify` re-walks the chain **and** cross-checks the
database anchor, so both in-place edits (hash mismatch) and truncation/rollback
(anchor mismatch) are detected in the tested local threat model. The same
service controls both stores, so this is not independent witnessing.
Anchor writes take a row-level lock (PostgreSQL) and are monotonic — a stale
concurrent writer skips rather than regressing the anchor, so ordinary
concurrent traffic cannot produce false tamper reports.

Post-ALLOW execution failures (the tool ran and raised) are mirrored from the
kernel's synthesized `:failure` chain event into the receipts table, so the
explorer, dashboard, and exports stay consistent with the chain.

## Run (explicit local-development posture)

> **INSECURE LOCAL DEVELOPMENT ONLY.** The current mutation API uses legacy,
> unsigned receipts. It must be started only with the explicit local-development
> posture below. Production posture refuses these routes; do not use this profile
> for staging, production, or consequential side effects.

```bash
export ACP_RUNTIME_POSTURE="local-dev-legacy-unsigned"
export ACP_DATABASE_URL="postgresql+psycopg://acgs:acgs@localhost:5432/acgs_control_plane"
export ACP_AUDIT_DIR="/var/lib/acgs/audit"
export ACP_BOOTSTRAP_TOKEN="<one-time provisioning secret>"   # unset ⇒ org creation disabled (fail closed)
export ACP_CREATE_TABLES=1
uv run --package acgs-control-plane uvicorn --factory acgs_control_plane.app:create_app
```

This posture is deliberately non-production: its legacy bootstrap may create only the frozen
pre-Alembic v0 tables, and `/readyz` always returns 503. For a migration-managed database, run the
secret-safe operator CLI to revision `0002`, then set `ACP_CREATE_TABLES=0`. Schema currency is
reported separately from production readiness. `ACP_RUNTIME_POSTURE=production` currently refuses
before constructing a database engine because the existing mutation routes still use the legacy
unsigned membrane; an exact `0002` schema does not weaken that blocker.

Bootstrap the first org (returns the org-admin API key exactly once):

```bash
curl -s -X POST localhost:8000/orgs \
  -H "X-Bootstrap-Token: $ACP_BOOTSTRAP_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "Acme AI", "admin_name": "Root", "admin_email": "root@acme.example"}'
```

All other endpoints authenticate with `X-API-Key` (SHA-256 stored, never the raw key).

## Verify

```bash
uv run --package acgs-control-plane python -m pytest packages/acgs-control-plane/tests --import-mode=importlib -q
```

## Honest limitations (v0.1)

- **Escalation is record-only**: ESCALATE persists a receipt and returns 202; there is
  no approve/resume endpoint yet (gove-zone's `escalation.PendingApproval` is the
  intended substrate).
- **Receipts are legacy and unsigned.** This differs from gove-zone's secure
  `require_signature=True` profile, which fails loudly without configured trust
  material; production posture refuses the legacy mutation routes.
- **Schema mutation is operator-only**: Alembic revisions `0001` and `0002` are advanced through
  `python -m acgs_control_plane.migration_cli`; schema-managed startup performs an exact, read-only
  revision preflight and never migrates. The legacy `create_all` bootstrap remains available only
  under the explicit local-development posture above.
- **Production posture remains blocked** while mutation routes use the legacy unsigned governance
  membrane. A current database schema is necessary startup evidence, not production readiness.
- The chain-tip anchor is written by the same service that writes the chain — it
  detects accidents and file-level tampering, not a fully compromised service.
- **A blocked bootstrap leaves no DB receipt**: if a policy ever denies/escalates
  `org.create`, the org rolls back entirely, so the decision exists only on that
  org-id's audit chain file (a DB row would dangle its foreign key).
- **An export never references its own receipt**: the `export.generate` receipt is
  minted after the bundle is sealed, so it appears in the *next* export — evidence
  chains forward.
- There is no authenticated customer-runtime evidence-ingestion API, signed
  policy-sync API, or approve/resume API. Horizontal operation is constrained by
  per-org local JSONL files, and verification scans the chain.
