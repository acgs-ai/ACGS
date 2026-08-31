# acgs-control-plane

**ACGS control-plane alpha** — a local multi-tenant management API over the
[gove-zone](../gove-zone/) governed runtime.

> **No valid Decision Receipt, no side effect.**

Most current development routes still dispatch mutations through the
organization's legacy gove-zone `Kernel` under its **active policy bundle**.
Those routes store legacy, unsigned `Receipt` records, not signed canonical
`DecisionReceipt` artifacts verified through `execute_with_receipt`. Production
posture refuses legacy mutation routes rather than representing them as a
production governance membrane. In the local development profile:

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

`POST /orgs/{org}/agents` is the first native receipt-governed mutation path. It
uses the server-owned default project/environment scope from Alembic revision
`0010`, issues a signed native `DecisionReceipt` (action `database.agent.create`,
boundary `control-plane/sql-transaction`) inside the same SQL transaction as the
agent row, verifies it strictly before the protected insert, burns ALLOW receipts
once in the single-use consumption ledger, records DENY/ESCALATE as signed
non-executable evidence, and fails closed on stale policy, trust, binding
mismatch, and replay cases before the forbidden agent row can be inserted.

Native agent decisions are not mirrored onto the legacy `receipts` table.
Instead, the receipt list/detail/verify endpoints, the dashboard, and the export
bundle read the native ledger alongside legacy rows and keep the two lineages
distinct: native entries carry `assurance_class: native` and
`source_system: gove-zone`, and verifying a native receipt runs the full
cryptographic evidence-chain verifier (artifact, projection, governance event,
consumption attestation, signatures) rather than the legacy chain walk.

Other managed mutations — `tenant.bootstrap` — still write
`ManagedDecisionReceipt` with no legacy projection and remain invisible to the
explorer and export bundle.

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
export ACP_MAX_REQUEST_BODY_BYTES=1048576                     # optional; default 1 MiB, max 16 MiB
uv run --package acgs-control-plane uvicorn --factory acgs_control_plane.app:create_app
```

This posture is deliberately non-production: its explicit local bootstrap runs the packaged
operator migration path on an empty database only, and `/readyz` always returns 503. For a
migration-managed database, run the
secret-safe operator CLI to the current head (`0012` at this writing), then set
`ACP_CREATE_TABLES=0`. Schema currency is reported separately from production readiness.
`ACP_RUNTIME_POSTURE=production` currently refuses before constructing a database engine because
legacy mutation routes still exist; an exact current schema does not weaken that blocker.

Bootstrap the first org (returns the org-admin API key exactly once):

```bash
curl -s -X POST localhost:8000/orgs \
  -H "X-Bootstrap-Token: $ACP_BOOTSTRAP_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "Acme AI", "admin_name": "Root", "admin_email": "root@acme.example"}'
```

All other endpoints authenticate with `X-API-Key` (SHA-256 stored, never the raw key).

## Request admission and error contract

G102 request admission covers the existing v0 route set plus additive `/v1` aliases. Canonical
native agent creation requires a single `Idempotency-Key` header on both
`POST /orgs/{org_id}/agents` and `POST /v1/orgs/{org_id}/agents`; the control plane stores only
bounded replay evidence for terminal outcomes. Async jobs and `/v1/idempotency/schema` are not
implemented.

- The server ignores inbound `X-Request-ID`, generates a bounded `req_<32 lowercase hex>` request
  ID for every HTTP request, and returns it in the `X-Request-ID` response header. Redacted error
  envelopes include the same `request_id`.
- `ACP_MAX_REQUEST_BODY_BYTES` caps request bodies before FastAPI body parsing or route invocation.
  The default is `1048576` bytes. Valid values are decimal integers from `1` through `16777216`;
  invalid environment values fail loudly with a stable configuration error that does not echo the
  raw environment value.
- Declared `Content-Length` values above the configured limit are rejected without reading the body.
  Missing `Content-Length` is handled by bounded pre-read of the incoming stream: the middleware
  buffers only up to the configured limit, rejects overflow before route execution, then replays the
  admitted request downstream. Malformed or multiple `Content-Length` headers are rejected without
  echoing the header value.
- Request admission failures return stable JSON such as
  `{"code":"request_body_too_large","status":"error","request_id":"req_..."}` with HTTP 413.
  Malformed JSON returns a redacted 400 envelope. Validation and ordinary HTTP exceptions use
  stable redacted 4xx/5xx envelopes; rejected input, exception strings, credentials, and policy
  bundle contents are not echoed by those handlers.
- Missing `Idempotency-Key` on canonical native agent creation returns a redacted HTTP 428
  `precondition_required` envelope. Malformed or duplicate idempotency headers return redacted
  HTTP 400. Same key with different canonical request semantics returns redacted HTTP 409.
- Governance DENY and ESCALATE responses preserve their existing receipt fields and add the
  server-generated `request_id`. `AuditReadError` preserves its existing body shape; the response
  header still carries the server-generated request ID.

### Receipt cursor pagination

`GET /orgs/{org_id}/receipts` preserves the legacy `limit`/`offset` response fields and offset
pagination behavior. It also returns an additive `next_cursor` for the first page when more
receipt rows are available. Passing `cursor=<next_cursor>` switches that request to receipt-only
keyset pagination ordered by `created_at DESC, id DESC`; `cursor` cannot be combined with a
non-zero `offset`.

Cursors are opaque AES-256-GCM tokens scoped to the organization, receipt resource, fixed sort
order, normalized filter digest, boundary timestamp/id, key id, issue time, and expiry. Cursor
errors return a generic redacted `invalid_cursor` envelope with `Cache-Control: private, no-store`;
the token and filters are never echoed. Local development without `ACP_CURSOR_KEY_ID` and
`ACP_CURSOR_KEY` uses a per-app ephemeral key, so cursors are not portable across process restarts.
Configured deployments must set both variables, where `ACP_CURSOR_KEY` is a base64-encoded 32-byte
key. Production posture still refuses startup before persistence because the provider preflight
contains a `cursor-aead-keyring` blocker alongside the existing legacy governance blockers.

### Dedicated `/v1` collection cursor pagination

Four authenticated collection reads have dedicated `/v1` contracts:

- `GET /v1/orgs/{org_id}/users`
- `GET /v1/orgs/{org_id}/agents`
- `GET /v1/orgs/{org_id}/policies`
- `GET /v1/orgs/{org_id}/exports`

Each returns `{"items":[...],"limit":50,"next_cursor":null}` (with the requested admitted
limit) and orders rows by `created_at DESC, id DESC`. The query language accepts only one optional
decimal `limit` from 1 through 500 and one optional opaque `cursor`. Its raw aggregate byte bound
and strict syntax checks run only after authentication, tenant lookup, and endpoint RBAC, so a
malformed query cannot override an earlier 401, 404, or 403 refusal.

Collection cursors use a protocol separate from receipt cursors. AES-256-GCM authentication binds
the token to its organization, collection resource, fixed order and filter digest, key id, issue
and expiry times, and exact `(created_at, id)` boundary. Receipt and collection cursors reject each
other. Cursor and query refusals use the same generic redacted `invalid_cursor` envelope and
`Cache-Control: private, no-store`; they do not echo a token or failure detail. Trailing slashes on
these four reads are canonicalized inside the application without an external redirect, so the
query string is not reflected through a `Location` header.

The unversioned collection routes keep their existing array responses and behavior. The
unversioned receipt explorer also keeps its existing offset fields and separate receipt-cursor
protocol. This functional local slice does not add migration-managed composite
`(org_id, created_at, id)` indexes, and it provides no staging, production, capacity, or latency
claim. Those indexes and PostgreSQL query-plan evidence are a separate required follow-up;
production startup continues to refuse its existing blockers.

## Verify

```bash
uv run --package acgs-control-plane python -m pytest packages/acgs-control-plane/tests --import-mode=importlib -q
```

## Honest limitations (v0.1)

- **Escalation is record-only**: ESCALATE persists a receipt and returns 202; there is
  no approve/resume endpoint yet (gove-zone's `escalation.PendingApproval` is the
  intended substrate).
- **Most route receipts are legacy and unsigned.** `POST /orgs/{org}/agents` now uses signed
  native receipt evidence and the SQL single-use consumption ledger, but the remaining legacy
  routes still differ from gove-zone's secure `require_signature=True` profile. Production posture
  refuses while those legacy mutation routes remain.
- **Schema mutation is operator-only**: Alembic revisions `0001` through `0012` are advanced
  through `python -m acgs_control_plane.migration_cli`; schema-managed startup performs an exact,
  read-only revision preflight and never migrates. The frozen legacy `create_all` contract remains
  available only for migration-adoption tests; the app's explicit local-development bootstrap runs
  the packaged migration path on an empty database only.
- **Database governance-event tables are groundwork only**: revision `0007` adds DB-primary event,
  head, outbox, and cutover tables plus a caller-owned-session appender, but current routes and read
  paths still use the legacy JSONL authority until a later explicit cutover.
- **Native receipt persistence is a transaction provider with one route cutover**: revision `0008`
  adds tenant-bound verified, minimized signed-receipt projections and single-use consumption
  burns. It rejects TRANSFORM and freeform subject, goal, constraint, transformation, or extra
  approval metadata; request IDs and matched-rule identifiers are stored only as hashes. Providers
  flush but never commit or roll back; callers must keep receipt, burn, and protected SQL effect in
  one transaction. A rollback removes all three. The database fixes `assurance_class` to `native`
  and `source_system` to `gove-zone`; federated and observed evidence require distinct provenance.
  Only `POST /orgs/{org}/agents` has cut over to this path; other mutation routes have not.
  Non-transactional external effects still require a separate durable execution protocol.
- **Verifiable native receipt artifacts back one route**: revision `0009` adds nullable
  artifact columns and a verifier that reconstructs the signed `DecisionReceipt`, checks
  trusted key status, compares the minimized projection and scalar bindings, walks the full
  tenant governance-event chain, and refuses native cutover readiness if the marker is missing,
  legacy writes remain active, or legacy receipt rows exist beyond the cutover boundary. The
  agent-create route and native receipt verify endpoint use this verifier; the legacy JSONL
  authority is unchanged for all other routes.
- **Default scope attachment is additive compatibility groundwork**: revision `0010` creates or
  reuses one canonical legacy default project/environment per organization, backfills still-unscoped
  legacy agents and policy bundles onto it, and extends the nullable composite
  project/environment scope model from `agents` to `policy_bundles` with the same
  both-null-or-both-set check and composite environment foreign key. Scope columns stay nullable at
  the schema level; legacy write routes attach the default scope at write time. Legacy receipts and
  native receipt provenance are not backfilled or reclassified.
- **Durable idempotency is terminal-only managed replay evidence**: revision `0011` adds bounded
  result rows for canonical native agent creation. The table stores request/key digests, terminal
  semantic response hashes in signed replay artifacts, native receipt bindings, and
  governance-event bindings. Replay reconstructs the response from authoritative agent, native
  receipt, and governance-event rows before comparing it with the stored hash; it deliberately has
  no pending/lease/takeover protocol, async job surface, expiry, purge path, or raw response body
  storage.
- **Environment-scoped signed policy registry is a distinct active pointer**: revision `0012`
  adds immutable `policy_versions` plus one `environment_policy_heads` row per environment.
  An org-level `PolicyBundle` (`status=active`) and an environment `EnvironmentPolicyHead` are
  not the same object: org rules still govern legacy `/orgs/{org_id}/policies` writes and must
  also authorize the first env-scoped publish/activate; the env head is the signed pointer used
  after that environment has been bootstrapped.
- **Production posture remains blocked** while any mutation route uses the legacy unsigned
  governance membrane. A current database schema is necessary startup evidence, not production
  readiness.
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
