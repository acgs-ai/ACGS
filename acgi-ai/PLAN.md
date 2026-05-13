# acgi-ai Console Realization Spec

## 0. Product Goal

`acgi-ai` should become the **real operator console for ACGS runtime governance**, backed by the ACGS monorepo services instead of static fixtures.

The console should let an authenticated operator inspect and act on:

```text
constitution posture
→ MACI lane activity
→ deliberation matters
→ agent runtime status
→ policy compile drafts
→ audit chain events
→ operator settings
```

The current frontend already has the right skeleton. The next job is to replace mock state with authoritative backend state, while preserving the existing UI/page structure.

---

# 1. Definition of "Real"

A page is **real** only when all of the following are true:

| Layer                 | Requirement                                                                            |
| --------------------- | -------------------------------------------------------------------------------------- |
| **Auth**              | Page access is governed by real identity/session state, not local-only fake SSO.       |
| **API**               | Data comes from upstream FastAPI or governance bus APIs, not MSW-only fixtures.        |
| **Persistence**       | User-visible state survives refresh and process restart where persistence is expected. |
| **Authorization**     | Tenant/operator permissions are enforced server-side.                                  |
| **Auditability**      | Mutating actions append audit events with hash-linked evidence.                        |
| **Failure semantics** | Backend failures, partial data, and blocked posture are represented explicitly.        |
| **Type contract**     | Frontend types are generated or validated against OpenAPI/Pydantic models.             |
| **Observability**     | API calls and workflow failures are visible through logs/traces/metrics.               |

MSW should remain only for local demo/development, not the source of truth.

---

# 2. Top-Level Goals

## Goal 1 — Replace Fixture-Only State with Live Governance State

Current:

```text
React pages → TanStack Query hooks → MSW /api/* handlers → fixture data
```

Target:

```text
React pages
→ typed API client
→ authenticated FastAPI gateway
→ governance bus / policy service / audit chain / observability data
```

Acceptance:

* All existing hooks can run in either `mock` or `live` mode.
* Live mode is the default in deployed console.
* Mock mode is visibly labeled and cannot be confused with production state.

---

## Goal 2 — Make Constitution State Authoritative

The console should show the active constitution hash, draft hash, compile status, and promotion status from backend-controlled state.

Acceptance:

* `currentHash` is read from active backend constitution metadata.
* `proposedHash` is produced by a real compile/draft API.
* Promote action is server-authorized and audit-logged.
* Promotion cannot happen if replay, validation, or approval gates fail.

---

## Goal 3 — Make MACI Workflow Operational

The console should evolve from static cards into an actual governance workflow across lanes:

```text
Proposer → Validator → Executor → Custodian
```

Acceptance:

* Cards are created by real governance events or API calls.
* Card posture changes are persisted.
* Lane transitions are server-validated.
* Every transition appends an audit event.

---

## Goal 4 — Make Deliberations Stateful

Deliberations should become real governance matters with lifecycle, due dates, citations, and posture.

Acceptance:

* Matters can be opened, updated, resolved, blocked, or escalated.
* Due dates and posture are persisted.
* Citations are stored as structured references.
* Lifecycle changes are audit-logged.

---

## Goal 5 — Make Audit Append-Only and Verifiable

Audit page must stop being a static event list and become a live read model over the ACGS audit chain.

Acceptance:

* Audit events are append-only.
* Events include hash linkage.
* Filters query backend data.
* Tampering, broken chains, or missing hashes are visible.
* Raw event details are inspectable.

---

## Goal 6 — Make Auth and Tenant Boundaries Real

The console cannot rely on localStorage-only session state.

Acceptance:

* Magic-link or SSO flow is wired to a real identity provider.
* Session is issued and validated server-side.
* Console routes are protected.
* Tenant context is explicit.
* Backend enforces tenant scoping.

---

# 3. Roadmap

## Phase 0 — Contract Freeze and Integration Boundary

### Objective

Stabilize the frontend/backend boundary before replacing mocks.

### Work

* Define canonical OpenAPI schema from FastAPI Pydantic models.
* Generate TypeScript types from OpenAPI.
* Compare generated types against current hand-written types.
* Add API environment modes:

```text
mock
staging
production
```

* Keep MSW, but make it a dev-only adapter.
* Add a visible environment indicator in the console.
* Define tenant, operator, and role claims expected by the frontend.

### Exit Criteria

| ID     | Acceptance Criteria                                                                 |
| ------ | ----------------------------------------------------------------------------------- |
| P0-001 | OpenAPI schema is exported from upstream FastAPI.                                   |
| P0-002 | Frontend TypeScript API types are generated or schema-validated.                    |
| P0-003 | Existing hand-written types are either replaced or checked against generated types. |
| P0-004 | API client supports mock/staging/production base URLs.                              |
| P0-005 | Deployed console cannot silently fall back to MSW.                                  |
| P0-006 | Console displays current environment and backend health.                            |
| P0-007 | Tenant/operator identity shape is defined.                                          |

---

## Phase 1 — Read-Only Live Console

### Objective

Replace static fixtures with live backend reads, without adding dangerous mutations yet.

### Pages Made Real

* Overview
* MACI
* Agents
* Deliberations
* Audit
* Settings read view
* Constitution/Compile read state

### Work

* Connect TanStack Query hooks to real FastAPI endpoints.
* Add loading, empty, error, stale, and partial states.
* Add backend health checks.
* Add query invalidation strategy.
* Preserve MSW fixtures for local demo only.

### Exit Criteria

| ID     | Acceptance Criteria                                                          |
| ------ | ---------------------------------------------------------------------------- |
| P1-001 | Each page fetches data from live FastAPI in live mode.                       |
| P1-002 | No page depends on hardcoded fixture state in live mode.                     |
| P1-003 | API failure shows explicit degraded/partial/blocked posture.                 |
| P1-004 | Refreshing the browser preserves live state.                                 |
| P1-005 | Backend unavailable state is visible and non-misleading.                     |
| P1-006 | Console build passes without MSW enabled in production.                      |

---

## Phase 2 — Real Auth and Tenant Guarding

### Objective

Replace fake/local auth with real identity and server-side authorization.

### Work

* Wire magic-link SSO or OAuth/OIDC provider.
* Replace localStorage-only session trust with server-issued session or token.
* Add `/me` or `/session` endpoint.
* Add tenant-scoped API queries.
* Add route guards based on real auth state.
* Add logout/session expiry handling.
* Add role/lane authorization.

### Exit Criteria

| ID     | Acceptance Criteria                                                           |
| ------ | ----------------------------------------------------------------------------- |
| P2-001 | Unauthenticated users cannot access console routes.                           |
| P2-002 | Session validity is checked against backend state.                            |
| P2-003 | LocalStorage cannot grant console access by itself.                           |
| P2-004 | Tenant context is returned by authenticated session endpoint.                 |
| P2-005 | Backend rejects cross-tenant data access.                                     |
| P2-006 | Expired sessions force re-authentication.                                     |
| P2-007 | Unauthorized mutation attempts are denied and audit-logged where appropriate. |

---

## Phase 3 — Operational MACI and Deliberation Workflows

### Objective

Make governance workflow state transition in the backend.

### Work

* Add real card transition APIs.
* Add deliberation lifecycle APIs.
* Add optimistic UI only where safe.
* Add server validation for lane transitions.
* Emit audit events on every workflow transition.
* Connect Phoenix observability for workflow traces.

### Exit Criteria

| ID     | Acceptance Criteria                                                |
| ------ | ------------------------------------------------------------------ |
| P3-001 | MACI card state transitions persist server-side.                   |
| P3-002 | Invalid lane transitions are rejected server-side.                 |
| P3-003 | Deliberation lifecycle changes persist server-side.                |
| P3-004 | Every transition creates an audit event.                           |
| P3-005 | UI reconciles optimistic updates with authoritative backend state. |
| P3-006 | Failed transitions show reason and do not corrupt local state.     |

---

## Phase 4 — Real Constitution Compile, Replay, and Promote

### Objective

Turn the Compile page into a real policy-governance workflow.

### Work

* Add compile draft API.
* Add policy diff API.
* Add compile validation.
* Add replay endpoint for proposed policy changes.
* Add promote endpoint gated by validation, replay, authorization, and audit requirements.
* Add rollback metadata, but not necessarily rollback action in v0.1.

### Exit Criteria

| ID     | Acceptance Criteria                                                               |
| ------ | --------------------------------------------------------------------------------- |
| P4-001 | `currentHash` comes from active backend constitution metadata.                    |
| P4-002 | `proposedHash` is generated by backend compile process.                           |
| P4-003 | Policy changes are classified as added/amended/removed by backend diff logic.     |
| P4-004 | Replay action invokes a real backend replay/validation endpoint.                  |
| P4-005 | Promote action invokes a real backend promotion endpoint.                         |
| P4-006 | Promote is blocked if replay fails.                                               |
| P4-007 | Promote is blocked if operator lacks authorization.                               |
| P4-008 | Promote appends an audit event with current/proposed hash linkage.                |
| P4-009 | UI shows promotion result, failure reason, and resulting active hash.             |

---

## Phase 5 — Audit Chain Verification and Evidence Hardening

### Objective

Make audit evidence verifiable rather than just displayed.

### Work

* Connect audit page to JSONL audit chains or audit service.
* Add event detail drawer.
* Add chain verification status.
* Add hash continuity checks.
* Show broken-chain or missing-event warnings.
* Add replay/evidence bundle links where available.

### Exit Criteria

| ID     | Acceptance Criteria                                               |
| ------ | ----------------------------------------------------------------- |
| P5-001 | Audit events are read from append-only backend source.            |
| P5-002 | Events include hash fields generated by backend.                  |
| P5-003 | Audit filter queries backend, not just client-side fixture state. |
| P5-004 | Chain verification status is visible.                             |
| P5-005 | Broken hash linkage is surfaced as blocked/failed posture.        |
| P5-006 | Raw event payload is inspectable.                                 |
| P5-007 | Audit export is available or explicitly deferred.                 |

---

## Phase 6 — Production Deployment and Operations

### Objective

Make Cloud Run console deployment credible.

### Work

* Configure Workload Identity Federation.
* Finalize Cloud Run deployment pipeline.
* Configure Caddy routing for `console.acgs.ai`.
* Finalize Vercel marketing deployment for `acgs.ai`.
* Wire DNS.
* Add environment-specific secrets.
* Add smoke tests after deploy.
* Add uptime/health checks.

### Exit Criteria

| ID     | Acceptance Criteria                                                                     |
| ------ | --------------------------------------------------------------------------------------- |
| P6-001 | GitHub Actions can deploy console to Cloud Run without long-lived service-account keys. |
| P6-002 | `console.acgs.ai` routes to Cloud Run + Caddy.                                          |
| P6-003 | `acgs.ai` routes to marketing deployment.                                               |
| P6-004 | Console production build disables MSW.                                                  |
| P6-005 | Deployment includes health-check smoke test.                                            |
| P6-006 | Failed deploy does not overwrite last known good revision.                              |
| P6-007 | Secrets are not exposed in frontend bundle or logs.                                     |

---

# 4. Page-by-Page Realization Spec

## 4.1 Overview Page

### Current State

Likely reads overview metrics from MSW fixture via `useOverview`.

### Goal

Make Overview the live operational summary of ACGS runtime posture.

### Real Data Sources

| Data                      | Source                                    |
| ------------------------- | ----------------------------------------- |
| Current constitution hash | Constitution service / governance config  |
| Agent health              | Agent registry / runtime heartbeat        |
| MACI card counts          | Governance workflow service               |
| Deliberation counts       | Deliberation/matter service               |
| Audit event counts        | Audit service / JSONL audit index         |
| Blocked/partial posture   | Aggregated backend health/status endpoint |

### Required API

```http
GET /api/overview
GET /api/health
GET /api/constitution/active
```

### Acceptance Criteria

| ID     | Acceptance Criteria                                                                          |
| ------ | -------------------------------------------------------------------------------------------- |
| OV-001 | Overview metrics are loaded from live backend in live mode.                                  |
| OV-002 | Counts are not duplicated hardcoded constants.                                               |
| OV-003 | Overview displays active constitution hash.                                                  |
| OV-004 | Overview displays aggregate posture: confirmed, partial, blocked, or privileged.             |
| OV-005 | Overview displays backend health and last refresh timestamp.                                 |
| OV-006 | If one subsystem is unavailable, the page shows partial posture instead of failing entirely. |
| OV-007 | Clicking summary cards navigates to the relevant page with filter context where applicable.  |
| OV-008 | Overview explicitly labels mock mode when using MSW.                                         |
| OV-009 | Overview data is tenant-scoped.                                                              |
| OV-010 | Overview never claims live governance if backend is disconnected.                            |

---

## 4.2 MACI Page

### Current State

Static `MaciCard[]` fixture.

```ts
type MaciLane = "Proposer" | "Validator" | "Executor" | "Custodian";
```

### Goal

Make MACI a real lane-based governance workflow view.

### Real Data Sources

| Data          | Source                            |
| ------------- | --------------------------------- |
| Cards         | Governance bus / workflow service |
| Lane          | MACI assignment logic             |
| Agent         | Agent registry                    |
| Posture       | Policy/governance state           |
| Event history | Audit service                     |

### Required API

```http
GET  /api/maci/cards
GET  /api/maci/cards/:id
POST /api/maci/cards/:id/transition
POST /api/maci/cards/:id/comment
```

### Required Backend Semantics

Lane transitions should be server-controlled.

Example:

```text
Proposer-created
→ Validator-reviewed
→ Executor-approved-or-blocked
→ Custodian-audited
```

The frontend should not decide whether a transition is valid.

### Acceptance Criteria

| ID     | Acceptance Criteria                                                                  |
| ------ | ------------------------------------------------------------------------------------ |
| MC-001 | MACI cards are fetched from backend in live mode.                                    |
| MC-002 | Cards are grouped by backend-provided `lane`.                                        |
| MC-003 | Card posture is backend-provided, not inferred solely by UI.                         |
| MC-004 | Card detail opens with full backend state.                                           |
| MC-005 | Lane transition actions call backend mutation endpoints.                             |
| MC-006 | Backend rejects invalid transitions.                                                 |
| MC-007 | Failed transitions show a specific failure reason.                                   |
| MC-008 | Successful transitions append audit events.                                          |
| MC-009 | Cards refresh after transition.                                                      |
| MC-010 | Users only see actions they are authorized to perform.                               |
| MC-011 | Privileged posture is visually distinct from confirmed/partial/blocked.              |
| MC-012 | Static cards are unavailable in production live mode unless explicitly in demo mode. |

---

## 4.3 Deliberations Page

### Current State

Static `Deliberation[]` fixture.

```ts
type Deliberation = {
  id: string;
  matter: string;
  title: string;
  citation: string;
  opened: string;
  due: string;
  posture: Posture;
};
```

### Goal

Make deliberations into real governance matters with lifecycle.

### Recommended Lifecycle

```text
open
→ under_review
→ accepted
→ rejected
→ blocked
→ superseded
→ closed
```

You can map lifecycle to `posture`, but do not replace lifecycle with posture. They answer different questions:

| Field      | Meaning                             |
| ---------- | ----------------------------------- |
| `status`   | Where the matter is in the workflow |
| `posture`  | Trust/confidence/governance state   |
| `due`      | Time obligation                     |
| `citation` | Supporting reference                |

### Required API

```http
GET  /api/deliberations
GET  /api/deliberations/:id
POST /api/deliberations
PATCH /api/deliberations/:id
POST /api/deliberations/:id/resolve
POST /api/deliberations/:id/escalate
POST /api/deliberations/:id/comment
```

### Acceptance Criteria

| ID     | Acceptance Criteria                                                              |
| ------ | -------------------------------------------------------------------------------- |
| DL-001 | Deliberations are loaded from backend.                                           |
| DL-002 | Deliberation detail page or drawer shows full matter metadata.                   |
| DL-003 | Matter lifecycle status is persisted server-side.                                |
| DL-004 | Due-date changes persist server-side.                                            |
| DL-005 | Citation/reference fields are structured and inspectable.                        |
| DL-006 | Resolve/escalate actions call backend endpoints.                                 |
| DL-007 | Invalid lifecycle transitions are rejected server-side.                          |
| DL-008 | All lifecycle mutations append audit events.                                     |
| DL-009 | Overdue matters are clearly marked.                                              |
| DL-010 | Filter by posture and status works against backend data or hydrated query state. |
| DL-011 | Tenant scoping prevents viewing another tenant's matters.                        |

---

## 4.4 Agents Page

### Current State

Static `Agent[]` fixture.

```ts
type Agent = {
  id: string;
  name: string;
  role: string;
  lane: MaciLane;
  model: string;
  refusals24h: number;
  health: string;
  lastSeen: string;
};
```

### Goal

Make Agents a live runtime registry for governed AI actors.

### Real Data Sources

| Data           | Source                           |
| -------------- | -------------------------------- |
| Agent identity | Agent registry                   |
| Lane           | Governance/MACI assignment       |
| Model          | Runtime config / heartbeat       |
| Refusals       | Audit or policy decision metrics |
| Health         | Heartbeat / observability        |
| Last seen      | Runtime heartbeat                |

### Required API

```http
GET /api/agents
GET /api/agents/:id
GET /api/agents/:id/activity
GET /api/agents/:id/refusals
```

Optional later:

```http
PATCH /api/agents/:id
POST  /api/agents/:id/suspend
POST  /api/agents/:id/rotate-credentials
```

### Acceptance Criteria

| ID     | Acceptance Criteria                                                          |
| ------ | ---------------------------------------------------------------------------- |
| AG-001 | Agent list is loaded from backend registry or runtime heartbeat source.      |
| AG-002 | `lastSeen` reflects real heartbeat or observed event timestamp.              |
| AG-003 | Agent health is derived from backend health state.                           |
| AG-004 | `refusals24h` is computed from audit/policy events, not fixture count.       |
| AG-005 | Agent lane is backend-provided.                                              |
| AG-006 | Agent detail shows recent governed actions or audit events.                  |
| AG-007 | Stale/offline agents are visually distinct.                                  |
| AG-008 | Unknown model or missing heartbeat is shown as partial/unknown, not healthy. |
| AG-009 | Agent data is tenant-scoped.                                                 |
| AG-010 | Any mutating agent controls are hidden until backend authorization exists.   |

---

## 4.5 Compile Page

### Current State

Draft constitution view with:

```ts
type CompileDraft = {
  currentHash: string;
  proposedHash: string;
  changes: PolicyChange[];
};
```

Mock actions:

```text
replay
promote
```

### Goal

Make Compile the real constitution draft, validation, replay, and promotion workflow.

### Required Backend Concepts

| Concept             | Meaning                                                      |
| ------------------- | ------------------------------------------------------------ |
| Active constitution | Currently enforced policy/constitution                       |
| Draft constitution  | Proposed policy/constitution                                 |
| Compile result      | Backend-produced normalized/validated policy artifact        |
| Diff                | Added/amended/removed policy changes                         |
| Replay result       | Impact/safety verification against test events or proof pack |
| Promotion           | Server-side activation of proposed constitution              |

### Required API

```http
GET  /api/constitution/active
GET  /api/constitution/drafts
GET  /api/constitution/drafts/:id
POST /api/constitution/drafts
POST /api/constitution/drafts/:id/compile
POST /api/constitution/drafts/:id/replay
POST /api/constitution/drafts/:id/promote
```

### Promotion Gates

Promotion must require:

```text
valid compile
+ authorized operator
+ successful replay or explicit privileged override
+ audit append
+ resulting active hash confirmation
```

### Acceptance Criteria

| ID     | Acceptance Criteria                                                               |
| ------ | --------------------------------------------------------------------------------- |
| CP-001 | `currentHash` is loaded from backend active constitution state.                   |
| CP-002 | `proposedHash` is generated by backend compile process.                           |
| CP-003 | Policy changes are returned by backend diff logic.                                |
| CP-004 | Change types include added, amended, and removed.                                 |
| CP-005 | Compile errors are displayed with rule/path context.                              |
| CP-006 | Replay invokes a real backend endpoint.                                           |
| CP-007 | Replay result includes pass/fail status and reason.                               |
| CP-008 | Promote invokes a real backend endpoint.                                          |
| CP-009 | Promote is disabled until compile succeeds.                                       |
| CP-010 | Promote is blocked if replay fails, unless a privileged override flow exists.     |
| CP-011 | Promote is blocked for unauthorized users.                                        |
| CP-012 | Successful promotion updates active hash.                                         |
| CP-013 | Successful promotion appends audit event containing currentHash and proposedHash. |
| CP-014 | Failed promotion leaves active constitution unchanged.                            |
| CP-015 | The UI shows whether a draft is stale relative to current active hash.            |

---

## 4.6 Audit Page

### Current State

Static append-only-looking event log:

```ts
type AuditEvent = {
  ts: string;
  posture: Posture;
  ev: string;
  src: string;
  hash: string;
  matter?: string;
};
```

Text filter exists.

### Goal

Make Audit a live append-only audit chain explorer.

### Required API

```http
GET /api/audit/events
GET /api/audit/events/:hash
GET /api/audit/verify
GET /api/audit/export
```

Recommended query parameters:

```http
GET /api/audit/events?q=&posture=&src=&matter=&from=&to=&cursor=
```

### Required Fields

The frontend should prepare for richer audit records:

```ts
type AuditEvent = {
  ts: string;
  posture: Posture;
  ev: string;
  src: string;
  hash: string;
  previousHash?: string;
  matter?: string;
  actor?: string;
  tenantId?: string;
  receiptId?: string;
  bundleId?: string;
  payloadDigest?: string;
};
```

### Acceptance Criteria

| ID     | Acceptance Criteria                                                                        |
| ------ | ------------------------------------------------------------------------------------------ |
| AU-001 | Audit events are fetched from backend append-only source.                                  |
| AU-002 | Text filter queries backend or applies to a backend-hydrated result set with clear limits. |
| AU-003 | Event list supports pagination or cursor loading.                                          |
| AU-004 | Each event shows timestamp, event type, source, posture, and hash.                         |
| AU-005 | Event detail shows raw structured event payload.                                           |
| AU-006 | Hash continuity is visible when `previousHash` exists.                                     |
| AU-007 | Broken hash chain is marked as blocked/failed.                                             |
| AU-008 | Audit events are immutable from the console.                                               |
| AU-009 | New workflow mutations appear in audit after refresh or subscription update.               |
| AU-010 | Audit export is available or explicitly disabled with reason.                              |
| AU-011 | Audit events are tenant-scoped.                                                            |
| AU-012 | Sensitive payload fields are redacted in UI where required.                                |

---

## 4.7 Settings Page

### Current State

Grouped key-value settings with source:

```text
constitution / operator / default
```

### Goal

Make Settings a real read/write configuration surface with source precedence.

### Required Model

Settings should separate:

| Layer          | Meaning                  |
| -------------- | ------------------------ |
| `default`      | System fallback          |
| `constitution` | Policy-defined setting   |
| `operator`     | Tenant/operator override |
| `runtime`      | Active resolved value    |

Do not let the UI imply that all settings are editable.

### Required API

```http
GET   /api/settings
GET   /api/settings/effective
PATCH /api/settings/operator
POST  /api/settings/validate
```

### Acceptance Criteria

| ID     | Acceptance Criteria                                                                    |
| ------ | -------------------------------------------------------------------------------------- |
| ST-001 | Settings are loaded from backend.                                                      |
| ST-002 | Each setting shows key, value, source, and effective value.                            |
| ST-003 | Source precedence is visible.                                                          |
| ST-004 | Constitution-owned settings are read-only unless edited through constitution workflow. |
| ST-005 | Operator-editable settings are explicitly marked.                                      |
| ST-006 | Setting updates are validated server-side.                                             |
| ST-007 | Setting updates persist after refresh.                                                 |
| ST-008 | Setting updates append audit events.                                                   |
| ST-009 | Invalid settings are rejected with field-level error.                                  |
| ST-010 | Sensitive settings are masked or redacted.                                             |
| ST-011 | Tenant-specific settings cannot leak across tenants.                                   |

---

## 4.8 Auth / Console Shell

### Current State

* Magic-link UI exists.
* No real backend identity provider.
* Fake SSO was blocked.
* Session stored in localStorage with expiry.
* Console guards unauthenticated access client-side.

### Goal

Make authentication and authorization real.

### Required API

```http
POST /api/auth/magic-link/request
POST /api/auth/magic-link/verify
POST /api/auth/logout
GET  /api/session
```

Or OIDC equivalent.

### Acceptance Criteria

| ID      | Acceptance Criteria                                                                        |
| ------- | ------------------------------------------------------------------------------------------ |
| AUH-001 | Fake SSO cannot be enabled in production.                                                  |
| AUH-002 | LocalStorage expiry alone is not trusted as authentication.                                |
| AUH-003 | Backend validates every authenticated API request.                                         |
| AUH-004 | Console route guard depends on real session endpoint.                                      |
| AUH-005 | Session expiry triggers logout or re-authentication.                                       |
| AUH-006 | Authenticated session includes operator ID, tenant ID, roles, and permitted lanes/actions. |
| AUH-007 | Unauthorized users receive clear blocked posture.                                          |
| AUH-008 | Auth failures do not reveal tenant data.                                                   |
| AUH-009 | Login/logout events are audit-logged where appropriate.                                    |

---

# 5. Cross-Cutting Acceptance Criteria

## 5.1 API and Type Contract

| ID      | Acceptance Criteria                                                           |
| ------- | ----------------------------------------------------------------------------- |
| API-001 | Frontend types are generated from OpenAPI or checked against Pydantic schema. |
| API-002 | API client has typed success and error responses.                             |
| API-003 | All hooks expose loading, error, stale, and refetch states.                   |
| API-004 | MSW handlers match the same OpenAPI contract as live backend.                 |
| API-005 | Production build fails if configured to use MSW as authoritative backend.     |
| API-006 | Backend errors preserve machine-readable error codes.                         |
| API-007 | Frontend does not infer security-sensitive state that backend should decide.  |

---

## 5.2 Posture Semantics

Current:

```ts
type Posture = "confirmed" | "partial" | "blocked" | "privileged";
```

Acceptance:

| ID     | Acceptance Criteria                                                                           |
| ------ | --------------------------------------------------------------------------------------------- |
| PS-001 | `confirmed` means backend has authoritative successful state.                                 |
| PS-002 | `partial` means data is incomplete, stale, degraded, or subsystem-limited.                    |
| PS-003 | `blocked` means governance, auth, validation, replay, or policy gate denied the state/action. |
| PS-004 | `privileged` means elevated permission or override path was used.                             |
| PS-005 | Privileged posture always links to operator identity and audit event.                         |
| PS-006 | UI copy does not treat partial as success.                                                    |

---

## 5.3 Auditability for Mutations

Every mutating action must produce audit evidence.

Mutation examples:

* MACI transition
* deliberation resolve/escalate
* compile draft creation
* replay invocation
* promote constitution
* settings update
* auth/admin-sensitive action

Acceptance:

| ID      | Acceptance Criteria                                                        |
| ------- | -------------------------------------------------------------------------- |
| MUT-001 | Every mutation returns a mutation ID or audit event hash.                  |
| MUT-002 | UI displays mutation result and audit linkage.                             |
| MUT-003 | Failed mutations return reason and do not create misleading success state. |
| MUT-004 | Privileged mutations require explicit server-side authorization.           |
| MUT-005 | Privileged mutations are visibly marked in audit.                          |

---

## 5.4 Observability

Given upstream Phoenix integration, the console should surface operational observability where relevant.

Acceptance:

| ID      | Acceptance Criteria                                                     |
| ------- | ----------------------------------------------------------------------- |
| OBS-001 | Backend request failures include trace/request IDs where possible.      |
| OBS-002 | Workflow mutations expose trace IDs or audit hashes.                    |
| OBS-003 | Console shows backend health/degraded status.                           |
| OBS-004 | Errors are actionable, not generic "Something went wrong."              |
| OBS-005 | Production logs do not leak secrets, tokens, or raw sensitive payloads. |

---

# 6. Recommended API Hook Mapping

Keep the existing hook structure, but make each hook mode-aware.

| Hook               | Mock Source Today | Live Target                        |
| ------------------ | ----------------- | ---------------------------------- |
| `useOverview`      | MSW fixture       | `GET /api/overview`                |
| `useMaci`          | MSW fixture       | `GET /api/maci/cards`              |
| `useAudit`         | MSW fixture       | `GET /api/audit/events`            |
| `useCompileDraft`  | MSW fixture       | `GET /api/constitution/drafts/:id` |
| `useDeliberations` | MSW fixture       | `GET /api/deliberations`           |
| `useAgents`        | MSW fixture       | `GET /api/agents`                  |
| `useSettings`      | MSW fixture       | `GET /api/settings/effective`      |
| `useSession`       | localStorage      | `GET /api/session`                 |

Mutation hooks to add:

```ts
useMaciTransition()
useCreateDeliberation()
useResolveDeliberation()
useCompileConstitutionDraft()
useReplayConstitutionDraft()
usePromoteConstitutionDraft()
useUpdateOperatorSettings()
useLogout()
```

---

# 7. Release Gates

## v0.1-live Readiness

A build can be called `v0.1-live` when:

| ID     | Gate                                                                                                |
| ------ | --------------------------------------------------------------------------------------------------- |
| RG-001 | Auth is real enough that localStorage alone cannot grant access.                                    |
| RG-002 | Overview, MACI, Agents, Deliberations, Audit, Compile, and Settings read from backend in live mode. |
| RG-003 | MSW is disabled in production.                                                                      |
| RG-004 | Tenant context is visible and enforced server-side.                                                 |
| RG-005 | Audit page reads from real append-only source.                                                      |
| RG-006 | Compile page reads active constitution hash from backend.                                           |
| RG-007 | No mutating button performs fake success.                                                           |
| RG-008 | All unsupported actions are disabled or labeled as mock/dev-only.                                   |

---

## v0.2-operational Readiness

A build can be called `v0.2-operational` when:

| ID      | Gate                                                                   |
| ------- | ---------------------------------------------------------------------- |
| RG2-001 | MACI transitions are real and audit-logged.                            |
| RG2-002 | Deliberation lifecycle is real and audit-logged.                       |
| RG2-003 | Settings updates are real and audit-logged.                            |
| RG2-004 | Compile/replay/promote workflow is real.                               |
| RG2-005 | Failed replay blocks promotion.                                        |
| RG2-006 | Privileged override path, if present, is authorized and audit-visible. |
| RG2-007 | UI supports refresh/reconciliation after mutations.                    |

---

## v0.3-production Readiness

A build can be called `v0.3-production` when:

| ID      | Gate                                                            |
| ------- | --------------------------------------------------------------- |
| RG3-001 | Cloud Run + Caddy deployment is automated.                      |
| RG3-002 | Workload Identity Federation is configured.                     |
| RG3-003 | DNS is live for `console.acgs.ai`.                              |
| RG3-004 | Console has production health checks.                           |
| RG3-005 | Auth provider is production-ready.                              |
| RG3-006 | Tenant isolation tests pass.                                    |
| RG3-007 | Audit chain verification failures are visible.                  |
| RG3-008 | Security/copy guardrails prevent unsupported compliance claims. |

---

# 8. Immediate Implementation Order

## Step 1 — Contract and Runtime Mode

Do this first.

```text
OpenAPI export
→ generated TS client/types
→ API mode config
→ production MSW disable gate
→ /api/session shape
```

Reason: without contract discipline, every page will become a one-off integration.

---

## Step 2 — Live Read-Only Pages

Connect pages in this order:

```text
Auth/session
→ Overview
→ Agents
→ Audit
→ MACI
→ Deliberations
→ Compile
→ Settings
```

Reason: Overview and Agents validate connectivity; Audit validates proof posture; Compile/Settings carry higher trust risk.

---

## Step 3 — Mutations Only After Audit Is Real

Do not enable real mutation buttons until audit append is working.

Order:

```text
Audit append
→ MACI transition
→ Deliberation lifecycle
→ Settings update
→ Compile replay
→ Promote
```

Reason: in ACGS, a mutation without audit evidence weakens the product thesis.

---

# 9. Non-Negotiable Guardrails

## Do Not Ship as Real If

* MSW is the source of truth in production.
* Fake SSO can grant access.
* Promote button returns mock success.
* Audit page is static fixture data.
* Tenant context is absent.
* Backend does not enforce authorization.
* Privileged actions are not audit-visible.
* Compile/replay/promote actions do not preserve hashes.
* UI claims "verified," "compliant," or "production-ready" without backend evidence.

---

# 10. Final Direction

The console should mature in this sequence:

```text
Mock governance console
→ live read-only governance console
→ authenticated tenant-scoped governance console
→ operational MACI/deliberation console
→ real constitution compile/replay/promote console
→ verifiable audit-chain control plane
```

The most important product rule:

> **No console action should look real unless the backend, authorization, persistence, and audit trail are real.**

That keeps `acgi-ai` aligned with ACGS's core claim: runtime governance is only credible when the decision trail can be inspected, replayed, and challenged.
