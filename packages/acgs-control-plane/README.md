# acgs-control-plane

**ACGS Enterprise Governance Control Plane** — a multi-tenant management API over the
[gove-zone](../gove-zone/) governed runtime.

> **No valid Decision Receipt, no side effect.**

The control plane applies gove-zone's core invariant to *itself*: every mutating
operation (register an agent, publish a policy, activate a policy, provision a user,
generate a compliance export) is dispatched through the organization's gove-zone
`Kernel` under the organization's **active policy bundle**. The Decision Receipt —
ALLOW, DENY, or ESCALATE — commits atomically with the side effect:

- **ALLOW** → side effect + receipt row + audit-chain anchor commit in one transaction.
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

Each org has a file-backed `ChainHashAuditStore` chain; its tip (event count + last
hash) is anchored in the `organizations` row inside the same transaction as every
receipt. `POST .../receipts/{id}/verify` re-walks the chain **and** cross-checks the
database anchor, so both in-place edits (hash mismatch) and truncation/rollback
(anchor mismatch) are detected — neither store can silently rewrite the other.

## Run

```bash
export ACP_DATABASE_URL="postgresql+psycopg://acgs:acgs@localhost:5432/acgs_control_plane"
export ACP_AUDIT_DIR="/var/lib/acgs/audit"
export ACP_BOOTSTRAP_TOKEN="<one-time provisioning secret>"   # unset ⇒ org creation disabled (fail closed)
uv run --package acgs-control-plane uvicorn --factory acgs_control_plane.app:create_app
```

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
- **Receipts are unsigned** by default, matching gove-zone's default posture; wiring a
  `ReceiptSigner`/verifier pair per org is future work.
- **Schema migrations** are `create_all` (idempotent, additive-only); Alembic arrives
  when the schema stabilises.
- The chain-tip anchor is written by the same service that writes the chain — it
  detects accidents and file-level tampering, not a fully compromised service.
