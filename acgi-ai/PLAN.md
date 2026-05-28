# Complete Platform Frontend — `acgi-ai`

> **Scope guard:** this plan covers `acgi-ai/` only — the frontend. It is
> **not** the monorepo unification plan. For workspace topology, submodule
> registration, path-filtered CI, and constitutional-hash gating across all
> packages, see `docs/PLAN-MONOREPO.md` and the registry at `MONOREPO.md`.

> Scope: take the ACGS GovernZone frontend (`acgi-ai/`) from "fixture-backed
> demo with live API fallback" to "production-ready public + privileged
> surface" without breaking the privilege boundary that the design and
> deployment contracts already commit to.

Plan owner: TBD · Target branch: this one (`plan/complete-platform-frontend`) · Reviewer: `/autoplan`

---

## §1 Premises (challenge these first)

This plan stands or falls on these. If any are wrong, the plan is wrong.

1. **The product is the front-door of a regulated-AI governance platform.**
   The frontend is buyer-visible artifact, not a tool surface. Polish, copy,
   privilege framing, and the visible network topology *are* product.
2. **The design contract is settled.** `acgi-ai/DESIGN.md` is the canonical
   visual + UX language for every surface — marketing, console, product
   atlas, privileged workflows. We are not redesigning. We are completing.
3. **The deployment contract is settled.** `acgi-ai/DEPLOY.md` defines the
   two-origin topology (marketing on edge CDN, console on operator
   container) and the strict-CSP / no-third-party-on-console rules. We
   are not relitigating those decisions.
4. **There is no backend yet at the gateway boundary.** Every list, table,
   and queue currently renders fixture data. The hooks layer fetches
   `/api/v1/*` and falls back to fixtures. The plan must keep this dual-mode
   behavior until the bus client lands (`DESIGN.md §7.5`).
5. **"Complete" means buyer-demoable, audit-defensible, and operationally
   safe** — *not* "every feature shipped." The product surface area is
   already large; the gap is finish quality, not new pages.
6. **Single-region, single-tenant-class is acceptable for now.** Multi-region
   failover, real SSO, and i18n are explicit non-goals (see §3).

If a reviewer disputes any premise, halt. Do not proceed.

---

## §2 What "complete" means — definition of done

A surface is complete when **all** of the following hold:

| Dimension | Bar |
|---|---|
| **Routing** | Hits the correct surface; deep links work; back/forward work; `?next=` is honored across login round-trips; 404 falls through to `NotFound`. |
| **Data** | All 11 interaction states are explicit and tested: loading (structural — table chrome + skeleton rows preserved, CLS = 0 first poll), empty (with `emptyMeans` taxonomy: fresh-tenant / awaiting-bus / audit-drift), error (typed via `AppError`), partial-bus (per-card staleness footer), stale-while-revalidating, retry-in-flight, conflicted-mutation, permission-denied, rate-limited, optimistic-pending, expired-session. No "blank page while loading" anywhere; no silent fallback. |
| **Bus honesty** | Production builds tree-shake `withFixtureFallback`; `BUS_UPSTREAM` unset = fail-closed, NOT fixture render. Non-prod builds show a global, non-dismissable `Live / Stubbed / Fixture / Offline` indicator with timestamp + affected modules. |
| **CSP** | Bundle builds and the privileged origin loads with **strict CSP enforced** (no `'unsafe-inline'`, no third-party origins). Marketing serves report-only CSP with allowlist; cuts over to enforced within 30 days. CSP-violation events captured in Playwright; build fails if any console route fires one. |
| **Privilege** | The parchment banner is structural (`DESIGN.md §4.3`); no animation, no `aria-hidden`, no flag-gate. Survives a `view-source` audit. **No `position: fixed` or `position: sticky` element renders above the banner z-index. No toasts, modals, or FABs occlude it on `/console/*` — receipts render in the right rail or inline only.** Playwright asserts banner bounding box is never intersected by another fixed element after a synthetic mutation. |
| **Auth** | OIDC (or server-issued HttpOnly `SameSite=Strict` console session cookie) is required at the console origin in production. sessionStorage/no-OIDC is a non-production-only path, marked as such in the env indicator. Direct deep links are blocked unauthenticated. Cross-tab sign-out is honored via `localStorage` + `storage` event. |
| **A11y** | **WCAG 2.2 AA conformant** per axe-core + manual NVDA + VoiceOver pass on `/console`, `/console/agents`, `/login`. Lighthouse a11y ≥ 95 is necessary, not sufficient. Touch targets ≥ 24px (default) / 44px (primary actions). Visible focus on every interactive. Route-level keyboard maps documented. Skip links + ARIA landmarks + table semantics + modal focus-traps + live-region behavior + error-association all specified. `prefers-reduced-motion` regression-tested. |
| **Responsive** | Marketing: works down to 360px. Console: ≥ 1024px is full operator mode; **768-1023px is a deliberate read-only evidence-review mode** (collapsible sidebar, single-column content, right-rail drawer, no dense mutation workflows) — buyer/auditor/counsel iPad-portrait friendly. < 768px shows the explicit "open on a desktop" notice (not broken layout). |
| **TTHW** | `pnpm hello` from a clean checkout (Node 24 + pnpm 9) renders `/` AND `/console` with synthetic session in **< 5 minutes total** including install. Measured by a CI job on a fresh runner. |
| **Errors** | Every UI error path resolves through `src/lib/errors.ts` `AppError` (Auth / Network / Parse / RetryExhausted / CSP / Permission / RateLimit). Each renders **problem + cause + fix + trace-id**. Snapshot test enforces taxonomy completeness; build fails on any `throw new Error(string)` in `src/routes/**`. |
| **Lint + build** | `pnpm lint && pnpm build` clean; bundle scan asserts no inline styles, no `<style>` tags, no third-party URLs in console build artifacts. |
| **Test gate** | `pnpm test:all` (unit + integration + e2e + a11y + visual + CSP harness) green in CI. Required scenario tests, not coverage-percentage targets (see §6). |
| **Deploy gate** | Both `marketing.yml` and `console.yml` workflows green. Production preview URL serves correct headers per Caddyfile §5 + vercel.json. Marketing artifact verified to NOT contain console code (bundle split or symbol-absence assertion). `/healthz` returns matching `served_hash` for the deployed bundle. |
| **Compliance honesty** | Every public compliance/security claim ties to a live or explicitly stubbed evidence object (source event, decision, hash, actor, timestamp). Engineering authors a claim matrix; legal reviews before deploy. No unsupported claims in UI copy. |

A surface that fails any row is not done. There is no "ship and follow up."

---

## §3 In scope / Not in scope

### ICP (named per /autoplan UC4)

Reference buyer for this plan: **regulated-AI procurement officer at an enterprise that already uses an LLM-touching system and needs defensible governance evidence.** Proof journey: *buyer verifies one policy enforcement decision end-to-end, exports a signed receipt, and shares it with auditor.* Console surfaces and product slugs are ranked against this journey:

- **Must-demo (in scope, full polish):** `/`, `/products` (single combined page or 2 hero slugs only), `/login`, `/console`, `/console/agents`, `/console/policies`, `/console/audit`, `/console/compile`, `/healthz`, `/subprocessors`, `/trust`, `/security`, `/privacy`.
- **Support-demo (in scope, structural only — DOD applies but lighter UI investment):** `/console/maci`, `/console/deliberations`, `/console/incidents`, `/console/account`.
- **Defer (out of scope this plan, write to TODOS.md):** `/console/settings`, `/console/tenants`, the 4-6 product slugs that aren't core to the proof journey. Re-prioritize in a follow-up plan after the first pilot lands.

### In scope (this plan completes these)

- **Marketing** at `/`, `/products`, the 2 hero product slugs aligned to ICP, `/privacy`, `/subprocessors`, `/trust`, `/security`.
- **Console** must-demo + support-demo surfaces above.
- **Auth boundary: real OIDC** (or server-issued HttpOnly `SameSite=Strict` cookie) at the console origin (per UC2). Auth0 / WorkOS dev-tier integration sufficient. sessionStorage path remains for non-production demo tenants only, watermarked.
- **Bundle topology: marketing and console build separately** (per UC1) — `vite build` × 2 entry points OR a build-time assertion that the marketing artifact cannot import/render `Console`.
- **API contract**: hooks layer + types + MSW handlers; `withFixtureFallback` is tree-shaken from production (per A1).
- **Bus contract: types generated from upstream OpenAPI/protobuf schema** (per UC7) committed under `acgi-ai/contracts/`; CI generates `src/api/types.ts` + contract tests including unknown/missing-field, version-skew, and error-envelope cases.
- **Test infrastructure**: vitest + @testing-library + Playwright smoke + axe-core a11y + CSP harness + visual regression at 360 / 768 / 834 / 1024 / 1440.
- **CI/CD**: the two-workflow split in `.github/workflows/`; pinned action versions, pinned Docker images, pinned vercel CLI, font hash manifest verified at build.
- **CSP enforcement** on the console origin; **CSP report-only on marketing** with 30-day cutover to enforced.
- **Tailwind v4 + strict-CSP coexistence guard** (per UC3, elevated to Phase 0): either remove `@tailwindcss/vite` if utilities are truly banned per CLAUDE.md, or enforce a CI grep + CSP harness gate. NOT a "verify the story" risk-register entry.
- **Self-hosted WOFF2** verification end-to-end with hash manifest.
- **Full state coverage** for every in-scope console surface (11 states per §2 DOD).
- **WCAG 2.2 AA accessibility** (per UC5) — keyboard, target sizes, focus restoration, manual NVDA/VoiceOver, reduced-motion regression.
- **Tablet reviewer mode** at 768-1023px (per UC6) — read-only evidence review.
- **Production deploy** of both surfaces (Vercel marketing, Cloud Run/Fly console) — but only **after** bus-readiness + OIDC complete (per §12 phase reorder).
- **DX scaffolding** (Phase 0): `pnpm hello`, standardized scripts (`dev:mock`, `dev:live`, `test:all`, etc.), `VITE_EVAL_MODE` for deterministic audit runs, `ARCHITECTURE.md` + `INTEGRATING.md` skeletons.
- **Compliance claim matrix** (per A21) reviewed by legal before public deploy.
- **Storybook** (per T4 / Open Q4) — published to `storybook.acgs.ai` as buyer-evidence artifact (~½ day on top of Phase 2).

### Not in scope (explicitly deferred — write to TODOS.md, do not expand)

- Multi-region failover. Single region until SLO > 99.9%, **measured** via `/healthz` synthetic probe (not assumed).
- Internationalization. English only. No `i18next`, no locale switcher, no RTL. **However, all user-visible strings are wrapped in a no-op `t()` from day one** (CEO Claude F3.3) so the eventual locale switcher does not require a copy refactor — extraction pipeline only.
- Mobile-first console layout. Operator workflows desktop-only at ≥ 1024px; reviewer mode at 768-1023px (per UC6); below 768px the explicit "open on a desktop" notice stands.
- Dark mode. Banned for the privileged console (`DESIGN.md` Don'ts).
- Server-side rendering. Bundle is fully static; auth tokens come from runtime, never the build (`DEPLOY.md §6`).
- The 4-6 console pages and 4-6 product slugs *not* in the must-demo / support-demo lists above.

### Considered + rejected (do not re-raise)

- *Replacing the entire frontend with a CI-gate / Slack-bot distribution* (CEO Codex distribution-alternatives finding). Considered; the buyer-front-door framing (premise 1) stands per user judgment at the premise gate. Rejected: out of scope for this plan, but logged as an alternative product line for a future quarter.
- *TanStack Router deferral.* Original plan deferred. Per UC2 / A2 / A17, **TanStack Router migration moves into Phase 0** because the custom 14-line router already breaks `?next=` query-string handling and `/products/<slug>` routing.
- *sessionStorage as the production auth path.* Original plan kept sessionStorage to defer OIDC. Per UC2, real OIDC is now in scope — sessionStorage stays for non-production demo only.
- *Lighthouse 95 as the a11y bar.* Per UC5, replaced with WCAG 2.2 AA conformance evidenced by axe + manual SR pass.
- *Hard 1024px console cliff.* Per UC6, replaced with tablet reviewer mode at 768-1023px.

### What already exists (do not rebuild)

| Asset | Location | State |
|---|---|---|
| Visual design system | `acgi-ai/DESIGN.md` (8.9K) | Settled. Tokens declared in `src/index.css`. |
| Deployment contract | `acgi-ai/DEPLOY.md` (20.9K) | Settled. Caddyfile + vercel.json + workflows drafted. |
| Marketing surface | `src/routes/Marketing.tsx` (15.5K) | Lands cleanly on `/`. |
| Console shell | `src/routes/Console.tsx` (14.9K) | 3-column grid, sidebar, banner, topbar, right rail. |
| 9 console pages | `src/routes/console/*.tsx` | Render fixture data; need state coverage. |
| Login + Privacy + 404 | `src/routes/{Login,Privacy,NotFound}.tsx` | On master. |
| Custom router | `src/lib/navigate.ts` (7 lines) + `App.tsx` (24 lines) | Functional. |
| Self-host WOFF2 | `public/static/fonts/` + `src/fonts.css` | Claimed in DEPLOY.md §6; verify live. |
| CSP-safe utilities | `src/csp-utilities.css` | Drop-in for inline-style replacements. |
| Strict TS config | `tsconfig*.json` | `strict`, `noUnusedLocals`, `verbatimModuleSyntax`, `erasableSyntaxOnly` all on. |
| API contract layer | `src/api/{client,hooks,types}.ts` (~13K total) | On master. Single fetch wrapper + react-query hooks + hand-written FastAPI types. `withFixtureFallback` dual-mode (live API → fixture) in place. |
| MSW handlers + fixtures | `src/mocks/{handlers.ts,data/}` | On master. 12 endpoints covered with module-level fixture data. |
| Infra primitives | `acgi-ai/infra/{Caddyfile,Dockerfile.console}` + `acgi-ai/.github/workflows/{console,marketing}.yml` + `acgi-ai/vercel.json` | On master. Two-origin deploy story is wired; Phase 5 verifies it live. |

---

## §4 Inherited work — Phase 0 (must land before Phase 1 starts)

The dirty worktree at `chore/eval-regression-coverage-seed-harness` carries
in-flight frontend deltas that are *out of place on that branch* (which is
about eval-regression coverage, not the frontend) but should land before
the rest of this plan starts. The bulk of the frontend architecture
(api layer, MSW, console pages, infra) **already landed on master** in
recent commits (`c611924`, `899b666`); only polish + a small set of
net-new utility files remain.

### Phase 0a — Net-new files (currently untracked on WIP)

| File | Purpose |
|---|---|
| `acgi-ai/src/lib/session.ts` | sessionStorage-backed session gate + `SESSION_CHANGE_EVENT` (non-production path only — production uses OIDC per Phase 5). Cross-tab sync via `localStorage` + `storage` event listener (per A18). |
| `acgi-ai/src/lib/errors.ts` | `AppError` taxonomy (Auth / Network / Parse / RetryExhausted / CSP / Permission / RateLimit) with `{title, cause, fix, traceId}` per case. Per A13 / DX UC. |
| `acgi-ai/src/lib/flags.ts` | Typed runtime flags from `VITE_*` env: `VITE_USE_MOCKS`, `VITE_API_PROXY_TARGET`, `VITE_EVAL_MODE`, `VITE_LOG_LEVEL`, `VITE_DISABLE_REFRESH_INTERVAL`, `VITE_FIXTURE_FALLBACK_VISIBLE`, `VITE_PRIVILEGE_BANNER_AUDIT`. Per A5 / DX UC. |
| `acgi-ai/src/routes/ProductSurfaces.tsx` | `/products` index + the 2 hero slugs aligned to ICP (per UC4). The other 4 slugs are deferred. |
| `acgi-ai/src/routes/console/shared.tsx` | State-coverage primitives — adds `Stale`, `RetryInFlight`, `PermissionDenied`, `RateLimited`, `Conflict`, `OptimisticPending`, `EnvIndicator` to the original `Receipt`/`EmptyState`/`ConsoleLoading`/`ConsoleError` set (per A3). `EmptyState` accepts an `emptyMeans` discriminator (`fresh-tenant` / `awaiting-bus` / `audit-drift`). |
| `acgi-ai/src/contracts/` | New directory: bus OpenAPI/protobuf schema vendored from upstream (per UC7). `types.ts` is generated from this — no longer hand-written. |
| `acgi-ai/src/mocks/data/console-summary.ts` | Console summary fixture used by `useConsoleSummary`. |
| `acgi-ai/src/vite-env.d.ts` | Vite env-var type declarations covering all of `flags.ts`. |
| `acgi-ai/ARCHITECTURE.md` | One-page summary of routing, data flow, privilege boundary, build, deploy. Skeleton lands in Phase 0 (per A16); fleshed out across phases. |
| `acgi-ai/INTEGRATING.md` | Bus-client integration contract: endpoint table, auth assumptions, error envelope, retry policy, fixture contract, "known unstable" fields, schema-version handshake (per A16 / DX UC). Skeleton lands in Phase 0 — bus author can start in parallel. |
| `acgi-ai/GETTING_STARTED.md` | 5-line quickstart + first-PR ladder (CEO/DX combined). Cross-linked from CLAUDE.md and ARCHITECTURE.md. |
| `acgi-ai/tailwind.theme.json` + `acgi-ai/tokens.json` | Design token exports (Tailwind + DTCG). |
| `acgi-ai/fonts.sha256` | Manifest of WOFF2 hashes verified at `pnpm build` (per A12). |
| `acgi-ai/.node-version` | Pin Node 24. |
| `acgi-ai/scripts/hello-world.sh` | `pnpm install --frozen-lockfile && pnpm dev` with wallclock budget gate; CI runs nightly on a fresh runner (per A4). Fail if total > 5 minutes. |
| `acgi-ai/scripts/agents-drift.sh` | Validate every `AGENTS.md` matches canonical guide pointers (per T3). |
| `acgi-ai/scripts/csp-harness/*` | Production-build CSP test harness — Caddy container + Playwright assertions for `securitypolicyviolation` events (per A19 / UC3). |
| `acgi-ai/scripts/postdeploy-verify.sh` | Header verification + `/healthz` `served_hash` match + bundle scan for inline styles / third-party URLs (per A19). |
| `acgi-ai/scripts/*` | Token check + smoke scripts (`check-design-tokens.py`, `smoke-internal-doc-deny.sh`, etc.). |
| **Canonical** `acgi-ai/CLAUDE.md` + thin `AGENTS.md` stubs per directory | T3: one canonical contributor guide; per-directory AGENTS.md stubs are generated and validated by `scripts/agents-drift.sh`. Drift = CI fail. |

### Phase 0b — Modifications to existing master files (~30 M files, expanded per /autoplan)

| Cluster | Files | Nature |
|---|---|---|
| **Router migration (UC2/A2)** | `src/App.tsx`, `src/main.tsx`, `package.json` | **Migrate from custom 14-line router to TanStack Router** (already in deps). Implement `?next=` query-string handling and `/products/<slug>` routing — both required by Phase 1 + Phase 5 and currently broken. Define objective router-trigger criteria in §3 (per A17): route params beyond product slug, route-level auth guards, loader/error boundaries per route, nested layouts, search-param state. |
| **Bundle split (UC1)** | `src/main.tsx` (split into `marketing.entry.tsx` + `console.entry.tsx`), `vite.config.ts` (multi-entry `rollupOptions.input`), `Dockerfile.console`, `vercel.json`, `infra/Caddyfile` | Split marketing and console builds into separate entrypoints + bundles. Marketing CTAs use hard absolute navigation to `console.acgs.ai`. CI assertion: marketing artifact has zero references to `Console`/`console/*` page bodies (symbol-absence test). |
| **Production fixture treeshaking (A1/T1)** | `src/api/client.ts`, `src/api/hooks.ts` | Narrow `withFixtureFallback`'s catch to network-only (`error.code === 'ECONNREFUSED'` / `NetworkError`) — propagate 4xx/5xx with body to the error boundary. In production builds (`import.meta.env.PROD`), refuse to fall back at all; render `ConsoleError` instead. CI assertion: production bundle does not contain fixture data symbols. |
| **Polling hygiene (A10)** | `src/api/hooks.ts`, `src/main.tsx` (QueryClient defaults) | Jittered intervals (LIVE: 5-10s ± 30%, SLOW: 30-60s ± 30%); `refetchIntervalInBackground: false`; visibility-API gate; bus-health adaptive backoff via a single `useBusHealth()` hook that drives all consumers. |
| **Surface polish** | `src/routes/{Console,Marketing,Login}.tsx`, all in-scope `src/routes/console/*.tsx` | Adopt expanded `shared.tsx` primitives (11 states), `Receipt` policy (right rail / inline only — no toasts, modals, or FABs above privilege banner z-index). `Login.tsx` adds the parchment interstitial naming operator + matter + constitutional hash `608508a9bd224290` (per A6). All UI errors flow through `lib/errors.ts` `AppError`. |
| **State copy + emptyMeans wiring** | All in-scope `src/routes/console/*.tsx` | Each page declares `emptyMeans` (`fresh-tenant` / `awaiting-bus` / `audit-drift`); audit-drift empty pages on-call per `DEPLOY.md §10`. |
| **API layer + bus contract reversal (UC7)** | `src/api/contracts/`, `src/api/types.ts`, `src/mocks/handlers.ts` | Bus team publishes OpenAPI/protobuf schema upstream → vendored to `src/api/contracts/` → `types.ts` generated by codegen. Contract tests against recorded responses including unknown-fields, missing-fields, version-skew, error envelopes. Schema-version handshake header `X-ACGS-Schema-Version`. CI fails if fixtures and `types.ts` diverge. |
| **Eval mode (A5)** | `src/main.tsx`, `src/api/client.ts`, `src/api/hooks.ts`, `src/lib/flags.ts` | When `VITE_EVAL_MODE=true`: pin `Date.now()`, fixed fixture seed, `onUnhandledRequest: 'error'` for MSW, `refetchInterval` disabled, animations off, deterministic IDs, visible "eval mode" indicator. |
| **Styling** | `src/App.css`, `src/index.css`, `src/csp-utilities.css` | Token additions for tablet-reviewer-mode (768-1023px breakpoint per UC6); CSP-safe class additions; automated contrast check on every token vs paper backgrounds (per A20). |
| **Config + scripts (A12, A15)** | `acgi-ai/package.json`, `acgi-ai/vite.config.ts`, `acgi-ai/biome.json`, `acgi-ai/.gitignore` | Standardized scripts: `dev`, `dev:mock`, `dev:live`, `hello`, `test`, `test:e2e`, `test:a11y`, `test:csp`, `test:contract`, `test:all`, `design:export`, `audit:eval`. Biome rule forbidding `style={{}}` JSX attribute and arbitrary-value Tailwind classes (`class(Name)?=".*[a-z]+-\["`). If `@tailwindcss/vite` is kept, add CSP harness gate; otherwise remove it (per UC3). |
| **Infra (A12, A14, UC1)** | `acgi-ai/infra/{Caddyfile,Dockerfile.console,cloudrun/service.yaml}`, `.github/workflows/{console,marketing}.yml`, `vercel.json` | Pin `node:24-alpine` (was 20), pin `caddy:2.X.Y`-alpine (was floating), pin all GH actions and `vercel@X.Y.Z` (was `@latest`). Marketing CSP `Content-Security-Policy-Report-Only` header (was missing) with allowlist + report-uri. Service.yaml templated per env (preview/staging/prod) with explicit minScale + concurrency + memory + cost estimate. Console CSP harness wired into `console.yml`. |
| **Contracts** | `acgi-ai/DESIGN.md`, `acgi-ai/DEPLOY.md` | DESIGN.md amendments: privilege banner z-index protection (per A8), tablet reviewer mode (per UC6), per-route wire decisions (per A7). DEPLOY.md amendments: bundle split topology (per UC1), marketing CSP cutover plan (per A11), font hash provenance (per A12), `/trust` + `/security` + DPA + SOC2 roadmap pages (per A22). |

### Phase 0 deliverable (expanded per /autoplan, ~2 weeks not 1)

Phase 0 now carries the load-bearing risk-mitigation work the original plan
deferred to Phases 3 and 6 — Tailwind+CSP coexistence, router migration, bus
contract scaffolding, error taxonomy. Estimate is **2 weeks**, not 1, and is
acknowledged as a scope expansion.

These changes split into **6-7 narrow PRs** from `chore/eval-regression-coverage-seed-harness`
(or a new feature branch carved from it) into master, then
`plan/complete-platform-frontend` rebased on top. Suggested PR boundaries:

1. **Router migration + state utilities** — TanStack Router replacement + `lib/session.ts` (with cross-tab sync) + `lib/errors.ts` `AppError` taxonomy + `lib/flags.ts`. **Highest risk PR — land first, gate downstream.**
2. **Bundle split** — `marketing.entry.tsx` + `console.entry.tsx`, multi-entry `vite.config.ts`, marketing CSP report-only header in `vercel.json`. Includes the symbol-absence assertion.
3. **State primitives + product surfaces** — expanded `console/shared.tsx` (11 states), `ProductSurfaces.tsx` cut to ICP-aligned slugs only, `Login.tsx` parchment interstitial.
4. **Bus contract scaffolding** — `src/api/contracts/` directory, types codegen pipeline, contract tests, schema-version handshake. **Bus team coordination required — land this when bus team has a draft schema.**
5. **CSP harness + Tailwind+CSP gate** — `scripts/csp-harness/*`, Biome rule, CI grep gate, decision on `@tailwindcss/vite` keep-or-remove (per UC3).
6. **Infra polish** — Caddyfile / Dockerfile (Node 24, pinned Caddy) / workflows (pinned actions, pinned vercel CLI) / cloudrun service.yaml templating / font hash manifest.
7. **DX scaffolding + docs** — `pnpm hello` script, standardized scripts, `ARCHITECTURE.md` skeleton, `INTEGRATING.md` skeleton, `GETTING_STARTED.md`, canonical `CLAUDE.md` + thin AGENTS.md stubs + drift check.

**Risk if skipped:** Phase 1 depends on the expanded `shared.tsx` and the new
router. Phase 3 depends on the Phase 0 CSP harness. Phase 5 (bus-readiness)
depends on the contract scaffolding. Phase 6 (production deploy) depends on
the infra polish + bundle split. Without Phase 0 landed in full, every later
phase references files that exist only on a stale unrelated branch — and
production fails closed (correctly, per A1).

**Phase 0 hard-kill gate (per CEO Codex MEDIUM finding):** No Phase 1 begins
until all 7 inheritance PRs are merged, both CI workflows are green on a
non-production preview, and the plan is re-estimated against actual diff
state. This is a stop, not a "best effort".

---

## §5 Implementation phases

Phases are sequential because each builds on the prior phase's gates.
**Original budget: ~6 weeks. Post-/autoplan honest estimate: ~12 weeks for
one engineer (or ~9 weeks if Phase 0's 6-7 PRs can parallelize across two
engineers).** Per-phase estimates are documented in each phase header below
and summarized in §12.

### Phase 1 — State coverage + privilege protection on every console surface (1.5w)

**Goal:** every in-scope console page renders all 11 interaction states real
(per §2 DOD), routes errors through `AppError`, protects the privilege banner
structurally, and Logins through a parchment interstitial. Estimate raised
from 1w to 1.5w to reflect expanded scope.

**Tasks:**
1. Audit all in-scope console pages (must-demo + support-demo per §3 ICP) against the expanded `shared.tsx`. Each must use `ConsoleLoading` (structural — preserves table/toolbar chrome with skeleton rows so CLS = 0 first poll), `ConsoleError`, `EmptyState` (with `emptyMeans` taxonomy), `Stale`, `RetryInFlight`, `PermissionDenied`, `RateLimited`, `Conflict`, `OptimisticPending`. Bare conditionals and `null` returns are banned.
2. Add explicit "no data yet" copy that names the bus and the matter — never "loading…" alone. Each page's empty state declares `emptyMeans` (`fresh-tenant` / `awaiting-bus` / `audit-drift`); audit-drift pages on-call per `DEPLOY.md §10`.
3. Wire `react-error-boundary` at the console shell level so a thrown error inside any page body falls through to a console-styled boundary, not the React red screen. The boundary surfaces an `AppError` (per `lib/errors.ts`) with `problem + cause + fix + trace-id`.
4. Add `aria-live="polite"` regions to the right-rail; verify across pages. Integrate `EnvIndicator` (`Live` / `Stubbed` / `Fixture` / `Offline` + timestamp + affected modules) — global, non-dismissable in non-production builds; **absent in production builds where fail-closed renders `ConsoleError` instead** (per A1).
5. **Polling hygiene (A10):** every `useQuery` invocation uses jittered intervals (LIVE: 5-10s ± 30%, SLOW: 30-60s ± 30%); `refetchIntervalInBackground: false`; visibility-API gate at the shell level; bus-health adaptive backoff via a single `useBusHealth()` hook all consumers depend on.
6. **AppError integration (A13):** every `throw` in `src/routes/**` resolves through `AppError`; CI fails on any `throw new Error(string)` in routes. Snapshot test enforces taxonomy completeness (every `AppError` case has non-empty `{title, cause, fix}`).
7. **Login interstitial (A6):** `/login → /console?next=…` handoff renders a parchment moment (≥ 800ms, dismissible via Enter) naming the operator, the matter being entered, and the constitutional hash `608508a9bd224290`. This is the privilege bar's first impression; without it the banner is just chrome.
8. **Banner z-index protection (A8):** no `position: fixed` or `position: sticky` element renders above the privilege banner. No toasts, modals, or FABs occlude it on `/console/*`. Receipts render in the right rail or inline only. Local static foundation: `pnpm run test:privilege-banner`; full visual QA still adds a Playwright assertion that the banner's bounding box is never intersected by another fixed element after a synthetic mutation.
9. **Per-route wire-level UI decisions (A7):** for each in-scope console route, document and implement: header anatomy, primary/secondary actions, table/card density rules, filter placement, pagination/virtualization, right-rail purpose, receipt lifetime, destructive-action confirmation pattern. Write decisions into `DESIGN.md` route-by-route appendix. Local static foundation: `pnpm run test:wire-decisions`; full browser/layout validation remains a Phase 2/visual QA gate.
10. **Cross-tab session sync (A18):** session changes broadcast via `localStorage` + `storage` event listener. Sign-out in tab A propagates to tab B within one event loop. `hasSession()` re-checks on every `useQuery` retry.

**Gate:** manual smoke through every in-scope console page with the API
offline (in non-prod) and with the API returning 401/403/429/5xx (state
matrix coverage). No blank screens. No "undefined" rendered. Every action
button shows the appropriate state during a mutation. Banner survives a
toast/modal-overlay attack-test in Playwright.

### Phase 2 — Test infrastructure (1.5w)

**Goal:** a real test gate exists, runs in CI, and blocks merge on red.
**Coverage percentage is replaced by required scenario tests (per A9).**
Estimate raised from 1w to 1.5w to reflect scenario + visual + Storybook scope.

**Tasks:**
1. Add **Vitest + @testing-library/react** to devDeps. Replace 80%-coverage targets with **required scenario tests** that map 1:1 to failure modes (per A9):
   - Direct `acgs.ai/console` redirects to `console.acgs.ai/console` (308) — not rendered from marketing bundle
   - Marketing JS cannot render console (symbol-absence assertion on built marketing artifact)
   - Unauthenticated console deep link blocks (no session = redirect, with `?next=` honored across login round-trip)
   - Production build with `VITE_USE_MOCKS=false` does NOT include `withFixtureFallback` symbols
   - `/api/*` proxy fail-closed when `BUS_UPSTREAM` unset (no fixture render in PROD)
   - Partial endpoint failure renders per-card staleness footer, not a uniform fixture wall
   - Caddyfile + vercel.json header values match `DEPLOY.md §5` table (golden file test)
   - Privilege banner invariants: `aria-hidden="false"`, no animation classes, computed `display: block`, no occluding fixed element after mutation
   - `AppError` taxonomy: every case renders non-empty `{title, cause, fix}`; `throw new Error(string)` in `src/routes/**` fails build
   - Cross-tab session sync via `storage` event
2. Add **MSW node-mode** test setup so hook tests exercise the same handlers as the dev server. In test/eval mode, MSW uses `onUnhandledRequest: 'error'` (not `bypass`) so silent fall-through is impossible. Local static foundation: `pnpm run test:msw-node`; actual hook tests remain Phase 2 work until the test runner lands.
3. Add **Playwright** smoke pack: marketing landing loads at 360/768/834/1024/1440; `/products/<slug>` resolves for the 2 ICP-aligned hero slugs; `/console` redirects to `/login` without session; `/console` loads with synthetic session in dev (`VITE_BYPASS_SESSION=true`) and with real OIDC token in staging; every in-scope sidebar link navigates without throwing. Local HTTP shell smoke: `pnpm run test:e2e-http`; browser Playwright execution remains Phase 2 work.
4. **CSP harness (A19):** Playwright captures `securitypolicyviolation` events on `document` for every `/console/*` route load + every mutation. Build fails on any event. Includes Tailwind v4 `<style>`-injection regression test.
5. **Contract tests (UC7):** record real (or stubbed) bus responses; assert `types.ts` codegen matches schema; assert unknown-fields, missing-fields, version-skew, and error envelope cases all parse cleanly.
6. Add **axe-core** via `@axe-core/playwright` on every smoke route. Fail on any serious or critical violation; fail also on touch-target-size violations (24/44px per UC5).
7. Add standardized scripts (per A15): `pnpm test`, `pnpm test:e2e`, `pnpm test:a11y`, `pnpm test:csp`, `pnpm test:contract`, `pnpm test:visual`, `pnpm test:all`. Wire into both workflows. Local static foundation: `pnpm run test:test-surface`; it verifies package, docs, and manifest wiring for `pnpm run test:e2e` and `pnpm run test:visual`, while browser Playwright and visual-diff execution remains Phase 2 work.
8. Add a **visual-diff** baseline pass — Playwright screenshots at all 5 viewports (360, 768, 834, 1024, 1440) for: marketing hero, marketing 2 hero slugs, login, login interstitial, console overview, console agents (filled + empty + error + stale + permission-denied + long-content), compile receipt (success + failure). Diff threshold 0.1% per existing precision norms.
9. **Storybook publish (T4 / Open Q4):** `pnpm storybook:build` + GitHub Pages or `storybook.acgs.ai` deploy in CI. Components from `console/shared.tsx` + key console pages published as buyer-evidence artifact. Includes axe + visual-diff at component level. Estimate: ½ day.
10. **TTHW measurement gate (A4):** `scripts/hello-world.sh` clean install + mock dev-server HTTP shell wallclock budget; CI runs the clean-runner scheduled TTHW on a fresh runner; fail if total > 5 minutes. Local static foundation: `pnpm run test:tthw`; headless first-render proof remains Phase 2 Playwright work.

**Gate:** CI runs lint, build, unit+integration, e2e+a11y, CSP harness,
contract tests, visual-regression, hello-world TTHW — all green required.
Local: `pnpm test:all` runs in < 90s on a clean machine. Storybook build
publishes successfully.

### Phase 3 — CSP enforcement + privilege audit + claim matrix (2-3w, NOT 1w)

**Goal:** the console serves with **strict CSP** in production. Verifiable by
curl + browser devtools. Privilege boundary survives a third-party pentest.
Every public compliance/security claim ties to a verifiable evidence object.
**Estimate raised to 2-3w (Open Q1 answered) — Tailwind+CSP coexistence is the
unknown that drives the variance.**

**Tasks:**
1. **Tailwind+CSP decision (UC3, blocked on Phase 0 outcome):** the Phase 0 CSP harness should already have surfaced whether `@tailwindcss/vite` is staying or going. If staying: full audit of all utility classes in `src/**/*.tsx` for arbitrary values (`class(Name)?=".*[a-z]+-\["`); zero accidents tolerated; Biome lint enforces. If going: confirm removal didn't regress styling, and migrate any utility classes to component-scoped classes or `u-*` utilities.
2. Audit `src/**/*.tsx` for any `style={{}}` JSX attribute. Replace each with a `u-*` utility (`csp-utilities.css`) or a component-scoped class. `pnpm lint` passes on biome's CSP-style rule (Phase 0 added it).
3. Verify the bundle has zero `<style>` tags injected at runtime — production-build CSP harness from Phase 0 asserts this on every `/console/*` route.
4. Stand up the Caddy container locally (the pinned `infra/Dockerfile.console`). Confirm the response headers from §5 of `DEPLOY.md` are all present. Run a third-party CSP analyzer (e.g., csp-evaluator.withgoogle.com) against the production-build preview.
5. Playwright assertions (extending Phase 2 CSP harness):
   - `Content-Security-Policy` header enforced (not report-only) on every `/console/*` response
   - `X-Frame-Options: DENY` present on console; permissive on marketing
   - Zero `securitypolicyviolation` events fired on any console route or mutation
   - Marketing serves `Content-Security-Policy-Report-Only` with allowlist + report-uri
6. **Privilege audit checklist** (executed by hand, recorded in `audit/privilege-audit-<date>.md`):
   - View-source on `/console`: zero third-party origins in `<link>`, `<script>`, `<img>`, `<iframe>`, `<font>`.
   - Network panel on a fresh `/console` load: every request hits `console.acgs.ai` (or `localhost` in dev).
   - Right-click → inspect on the privilege banner: `aria-hidden` is `false`, parent has no `display: none`, no animation classes, computed `display: block`, no occluding fixed element.
   - Banner z-index protection (per A8) survives a synthetic mutation that triggers a receipt — receipt renders in right rail, not as a toast.
   - DevTools Lighthouse "Best Practices" score = 100.
7. **Third-party penetration test (Open Q3 answered: yes, required for the brand).** Engage a regulated-AI-aware firm (e.g., Trail of Bits, NCC Group) for a focused 1-week pentest of the privilege boundary, OIDC integration, and console subdomain. Findings tracked in `audit/pentest-<date>-<vendor>.md`. Critical findings block Phase 6 production deploy.
8. **Compliance claim matrix (A21, Open Q5 answered):** engineering authors a matrix mapping every public compliance/security claim (subprocessors, "no third party touches console", privilege boundary, encryption-at-rest, audit retention, EU AI Act positioning, WCAG conformance) to (a) the live or explicitly stubbed evidence object, (b) the owner, (c) the reviewer, (d) the allowed wording, (e) the next review date. Legal reviews + signs off the matrix BEFORE any public deploy.

**Gate:** privilege audit passes. CSP header present, enforced, strict. Zero
`securitypolicyviolation` events on console routes. Third-party pentest report
filed; critical findings closed. Claim matrix signed off by legal. Marketing
CSP report-only delivers usable telemetry to the report-uri.

### Phase 4 — WCAG 2.2 AA conformance (1.5w, was 1w)

**Goal:** **WCAG 2.2 AA conformant** evidenced by axe + manual NVDA/VoiceOver
pass (per UC5). Lighthouse a11y ≥ 95 is necessary, not sufficient. Keyboard
works end-to-end. Procurement-defensible answer to "WCAG conformance level?".

**Tasks:**
1. Run axe-core (Phase 2 setup) against every in-scope route. Fix all serious + critical findings. Add **touch-target-size** rule (24px default, 44px primary actions, per WCAG 2.2 SC 2.5.8).
2. **Route-level keyboard maps (UC5):** document the expected `Tab` order for the 3-column console shell on every in-scope route. Manual keyboard pass: `Tab` reaches every interactive in documented order; `Shift+Tab` reverses; `Enter` and `Space` activate buttons; `Esc` closes any modal/menu; focus is always visible (`--focus-ring` tokens applied); focus restoration after modal close + after route change. **Skip links** present at every route entry.
3. **Manual screen-reader pass scripts (UC5):** write reproducible NVDA + VoiceOver test scripts for at minimum `/login`, `/console`, `/console/agents`, `/console/audit`, login interstitial, mutation receipt success, mutation receipt failure. Each script names: setup state, action sequence, expected announcement, observed announcement, pass/fail. Stored in `audit/sr-pass-<date>.md`.
4. **Form labels + error association:** `Login.tsx`, console search inputs (`SearchToolbar`), Compile replay/promote forms, Account session-controls — every input has a programmatic label, not just a placeholder. Error messages are `aria-describedby`-associated to inputs. (Settings/Tenants forms are deferred per §3 ICP cut.)
5. **ARIA landmark audit on the `Console` shell:** sidebar `<nav aria-label="…">`, right-rail `<aside aria-label="…">`, page main `<main>` exactly once per route. Modal focus traps with `aria-modal="true"` + return-focus-on-close.
6. **Live-region behavior:** `aria-live` regions in the right-rail receipt area; tested for politeness/assertiveness across the state matrix (success / failure / retry-in-flight / conflict).
7. **Color contrast:** automated check on every token in `src/index.css` against every paper background. Body text ≥ 4.5:1; large text ≥ 3:1; UI components ≥ 3:1. Anything below the bar gets a token revision (escalate to design owner).
8. **`prefers-reduced-motion` regression test (UC5):** reset confirmed; Playwright runs each smoke route with the media query forced and asserts no motion above the reset threshold.
9. **Tablet reviewer mode a11y (UC6):** axe + manual SR pass at 768-1023px viewport. Read-only evidence views must remain WCAG 2.2 AA conformant; mutation workflows are correctly hidden/disabled below 1024px.
10. Replace the §2 a11y row Lighthouse-only language with WCAG 2.2 AA conformance; add an `A11Y.md` capturing the bar, the audit method, the SR scripts, and the conformance statement (procurement-grade).

**Gate:** WCAG 2.2 AA conformance evidenced by passing axe-core run + signed
NVDA + VoiceOver scripts on the named routes. Lighthouse a11y ≥ 95 on `/`,
`/products`, the 2 hero slugs, `/login`, `/privacy`, `/console`,
`/console/agents`, `/console/audit`. Manual keyboard pass clean. Tablet
reviewer mode passes axe at 768-1023px. `A11Y.md` published.

### Phase 5 — Bus-readiness + real auth + bundle split (was Phase 6, 2w)

**Goal:** before any production deploy, the console origin has a real auth
boundary, the production bundle cannot render fixture data, marketing and
console are build-separated, and `/api/*` proxies to a real or stubbed bus.
This phase carries the load that the original plan's "ship Phase 5 first,
fix in Phase 6" sequencing would have shipped to a buyer. Estimate: **2w**
(was 1w).

**Tasks:**
1. **Real OIDC integration (UC2).** Stand up Auth0 (or WorkOS) dev-tier; implement OIDC code flow at the console origin; tokens land in HttpOnly `SameSite=Strict` Secure cookies (NOT sessionStorage). Direct deep-link unauthenticated access blocked at the Caddy layer (signed-cookie verify before reverse-proxy). sessionStorage path remains as a non-production demo-tenant escape hatch, watermarked via `EnvIndicator`.
2. **Tree-shake `withFixtureFallback` from production builds (A1, T1).** `import.meta.env.PROD` gates the import; production bundle has zero references to fixture data. CI assertion runs on the built artifact. When `BUS_UPSTREAM` is unset, production fails closed and renders `ConsoleError` with a "service unavailable" `AppError`.
3. **Bundle split (UC1).** `vite build` × 2 entry points (`marketing.entry.tsx` + `console.entry.tsx`). Marketing CTAs use hard absolute navigation to `console.acgs.ai`. CI symbol-absence assertion: marketing artifact has zero references to `Console` / `console/*` page bodies. Update `vercel.json` to ship only the marketing entry; update `Dockerfile.console` to ship only the console entry.
4. **`/api/*` reverse-proxy + bus contract (UC7).** Activate the `/api/*` stanza in the Caddyfile (currently 503-stubs every call); wire to `BUS_UPSTREAM` env; verify with a stub upstream returning the schema-conformant 200 + JSON. Schema-version handshake header `X-ACGS-Schema-Version` honored. Run the contract tests (Phase 2) against the stub.
5. **Cloud Run service templating (A14).** Commit per-environment `service.yaml` templates: preview (minScale=0, concurrency=80, 256Mi), staging (minScale=1, concurrency=80, 512Mi), production (minScale=2, concurrency=60, 1Gi). Cost estimate: ~$15-25/mo per always-on instance. Cold-start SLO test: synthetic external pinger every 30s + Playwright assertion that p99 first-request latency under cold-start scenario is < 800ms.
6. **Performance pass.** Lighthouse Performance ≥ 90 on marketing, ≥ 85 on console. Bundle size budget: marketing ≤ 200KB gzipped, console ≤ 350KB gzipped. Wire `vite-bundle-visualizer` to the build for ongoing visibility. Performance budget enforced in CI.
7. **Honesty indicator (A1 + DX).** `EnvIndicator` component lands in topbar (non-prod only): `Live` / `Stubbed` / `Fixture` / `Offline` + timestamp + affected modules. Per-card staleness footer reads `query.fetchStatus` + `query.errorUpdatedAt` and renders "fixture (bus offline 14s ago)" when applicable. In prod, the indicator is absent because fixture rendering is impossible (per task 2).
8. **`ARCHITECTURE.md` fleshed out (A16).** Skeleton from Phase 0 grows to a one-page summary of routing (TanStack Router), data flow (`hooks.ts` + `useBusHealth()`), privilege boundary (banner + z-index protection), build (split), deploy (two-origin), error taxonomy. Cross-linked from `GETTING_STARTED.md`. Includes the synthetic-session DEV path documented inline (per DX F1.2).
9. **`INTEGRATING.md` fleshed out.** Skeleton from Phase 0 grows to the full bus-client contract: endpoint table, auth assumptions, error envelope shape, retry semantics, fixture contract, "known unstable" fields, schema-version handshake. Source of truth: `src/api/contracts/`.
10. **Onboarding eval (DX F5.1).** Recorded fresh-clone test: a developer with Node 24 + pnpm 9 only, runs `pnpm hello`, then a scripted task ("change marketing hero copy to FOO, ship a PR"). Wallclock-budgeted in CI. If > 30 min, `ARCHITECTURE.md` is incomplete.

**Gate:** OIDC works end-to-end on staging (login, deep-link redirect, sign-out
across tabs). Production bundle is verified to NOT contain fixture symbols.
Marketing artifact is verified to NOT contain console symbols. `/api/*` proxies
to the stub. Cold-start p99 < 800ms. `pnpm hello` < 5 min on a fresh runner.
Onboarding eval < 30 min.

### Phase 6 — Production deploy + post-deploy verification + trust pages (was Phase 5, 1.5w)

**Goal:** both surfaces deployed to production. Headers verified live.
Procurement-grade trust + subprocessor + DPA + SOC2-roadmap pages live.
Marketing CSP report-only delivers telemetry; 30-day cutover to enforced.
Claim matrix signed off by legal. Estimate: **1.5w** (was 1w).

**Tasks:**
1. Provision `acgs.ai` and `console.acgs.ai` per `DEPLOY.md §9`. DNS, ACME certs, CAA records, DMARC `p=reject`.
2. Deploy marketing to Vercel via `marketing.yml`. Verify production headers match `vercel.json`. CSP `Content-Security-Policy-Report-Only` active with allowlist + report-uri. Report-uri receives + processes events.
3. Deploy console to Cloud Run via `console.yml` against the Caddy container (with the bus-readiness Phase 5 wiring). Verify production headers match the Caddyfile §5 table from `DEPLOY.md`.
4. Verify the marketing → console hand-off: clicking "Open the console" on `acgs.ai` lands on `console.acgs.ai/console` via 308 redirect, not via a marketing-side `/console` rendering. Bundle-split assertion holds.
5. Wire `/healthz` on the console origin returning `{ ok, served_hash, build_id }` per `DEPLOY.md §10`. Synthetic external pinger asserts `served_hash` matches the deployed bundle. Mismatch pages on-call.
6. Configure alerting per `DEPLOY.md §10`: 5xx > 1% / 5min on console pages on-call. Cert expiry < 14d pages on-call. CSP-violation report rate threshold pages on-call (regression detector).
7. Submit `acgs.ai` to the HSTS preload list per `DEPLOY.md §9`.
8. **Trust + compliance pages (A22).** `/subprocessors` lists Vercel (marketing only), Cloud Run/Fly (console), Auth0/WorkOS (auth), Let's Encrypt (certs), the font self-hosting story, and explicitly states no third party touches `/console/*`. `/trust` links to subprocessors, DPA template, SOC 2 Type II roadmap, data-residency statement, deletion SLA, model-card disclosures, security.txt. `/security` carries the bug-bounty + responsible-disclosure policy. Sub-processor change RSS feed published. Claim matrix (per Phase 3 task 8) reviewed + signed off by legal BEFORE this deploy.
9. **Marketing CSP cutover (A11).** Within 30 days of production deploy, marketing moves from `Content-Security-Policy-Report-Only` to enforced `Content-Security-Policy`. Rollback plan documented.
10. **SLO instrumentation (CEO Codex MEDIUM finding F2.3).** `/healthz` synthetic from 3 probes; 30-day rolling availability tracked; error budget defined; multi-region eligibility re-evaluated when SLO > 99.9% sustained for 90 days. Without this, "single-region acceptable" is permanent (premise 6 hardened).
11. **Post-deploy verification script (`scripts/postdeploy-verify.sh`).** Header verification + `/healthz` `served_hash` match + bundle scan for inline styles / third-party URLs + WCAG 2.2 AA quick-check via axe-cli + CSP-violation rate baseline.

**Gate:** production verified via `scripts/postdeploy-verify.sh`. All DOD rows
from §2 pass on every in-scope surface. Trust + subprocessor + DPA pages live
+ legally-reviewed. CSP cutover plan with calendar dates filed. SLO probes
running. The next contributor (or future Claude) can run `pnpm hello` and
ship a feature without reading the whole tree.

---

## §6 Test plan (the registry)

| Surface | Unit | Integration | E2E | A11y | Visual |
|---|---|---|---|---|---|
| `Marketing.tsx` | n/a (pure render) | n/a | smoke: loads at `/` | axe @ `/` | hero baseline |
| `ProductIndex / ProductSurface` | route slug resolution | n/a | smoke: 2 hero slugs resolve (other 4 deferred per §3 ICP cut) | axe @ each | one slug baseline |
| `Login.tsx` | session create flow | session storage round-trip | smoke: invalid → error, valid → redirect to `?next=` | axe @ `/login` | login baseline |
| `Privacy.tsx` | n/a | n/a | smoke: loads at `/privacy` | axe @ `/privacy` | n/a |
| `Console.tsx` (shell) | route → page dispatch | session-required redirect | smoke: every sidebar link navigates | axe @ shell | overview baseline |
| `console/Overview` | hooks render shapes | useOverview MSW round-trip | smoke: stats render | axe | yes |
| `console/Agents` | filter logic | useAgents MSW round-trip | smoke: search filters | axe | n/a |
| `console/Maci` | lane render | useMaci MSW round-trip | n/a | axe | n/a |
| `console/Deliberations` | filter logic | useDeliberations MSW | n/a | axe | n/a |
| `console/Incidents` | filter logic | useIncidents MSW | n/a | axe | n/a |
| `console/Policies` | filter logic | usePolicies MSW | n/a | axe | n/a |
| `console/Compile` | replay + promote mutations | useReplayCompile + usePromoteCompile MSW | smoke: replay button → receipt | axe | receipt baseline |
| `console/Audit` | filter logic | useAudit MSW | n/a | axe | n/a |
| ~~`console/Settings`~~ | deferred per §3 ICP cut | — | — | — | — |
| ~~`console/Tenants`~~ | deferred per §3 ICP cut | — | — | — | — |
| `console/Account` (support) | identity + sessions render | useAccount MSW | smoke: signed-in fields visible | axe | n/a |
| `lib/session.ts` | create / clear / has + cross-tab `storage` event sync | event dispatch + multi-tab race | n/a | n/a | n/a |
| `lib/errors.ts` | `AppError` taxonomy completeness | every case has non-empty `{title, cause, fix}` | n/a | n/a | n/a |
| `api/hooks.ts` | LIVE vs SLOW intervals (jittered ± 30%) + visibility gate | **network-error fall back only** (4xx/5xx propagate to `AppError`); production fail-closed when `BUS_UPSTREAM` unset (per A1) | n/a | n/a | n/a |
| `api/contracts/` | schema → types codegen | contract tests against recorded responses (unknown-fields, missing-fields, version-skew, error-envelope) per UC7 | n/a | n/a | n/a |
| `routes/console/shared.tsx` | useTextFilter, EnvIndicator, all 11 state primitives | n/a | n/a | axe per consumer | per state |

**The registry above is the floor, not the ceiling.** Eng review should treat
a populated cell as "this dimension is acknowledged" rather than "this
dimension is covered." The failure-modes section below is the gate: every
failure mode must be catchable by at least one cell in the table, *and*
reviewers must surface failure modes the table doesn't yet cover.

**Failure modes that the test plan must catch (expanded per /autoplan):**
- A console page returns `null` while loading → blank screen — must catch with smoke + visual.
- A mutation fails silently → catch with integration test asserting `Receipt` renders the error.
- The privilege banner gets `aria-hidden="true"` from a copy-paste — catch with axe + Playwright assertion on `aria-hidden`, computed `display`, no `display: none` ancestor, no `visibility: hidden`, no `opacity: 0`, no `clip-path: inset(100%)` (per Eng T4).
- A `style={{}}` slips into the tree — catch with Biome lint rule + production-build CSP harness asserting zero `securitypolicyviolation` events.
- A third-party origin gets pulled in by a transitive dep — catch with Playwright network-log assertion on `/console` load + bundle scan for third-party URLs.
- **`withFixtureFallback` masks a 401 in production** (Eng A1+T2) — assert that a stale-session 401 fails closed in PROD, not silently renders fixture data.
- **Cross-tab session desync** (Eng A4) — sign-out in tab A propagates to tab B via `storage` event within one event loop.
- **`served_hash` mismatch** between deployed bundle and `/healthz` response — synthetic pinger pages on-call.
- **Vercel rewrite to `console.acgs.ai` not happening in PR previews** — operator clicks "Open the console" and lands on marketing-side `/console` rendering. Catch with Playwright on every preview build.
- **CSP-injected style fallback masks a real regression** — visual diff at 0.1% may pass when both baseline and current render under enforced CSP without the rule. Capture `securitypolicyviolation` events as an additional gate (per Eng T3).
- **Toast / modal / FAB occludes the privilege banner** — Playwright synthetic-mutation test asserts banner bounding box never intersects another fixed element.
- **Marketing artifact contains console symbols** — symbol-absence assertion on built marketing artifact (per UC1).
- **Production bundle contains fixture data symbols** — symbol-absence assertion on built console artifact when `import.meta.env.PROD && !VITE_USE_MOCKS` (per A1).
- **Bus contract drift: types.ts and fixtures disagree** — contract test fails CI (per UC7).
- **Tailwind v4 emits a runtime `<style>` tag** — production-build CSP harness fails on emission (per UC3).

### State matrix (page × state, per A3)

Each in-scope console page declares which of the 11 states it implements
(P = primary, ✓ = supported, — = not applicable). Phase 1 gate fails if any
P or ✓ cell is unimplemented; reviewers must surface state gaps the table
doesn't yet cover.

| Page | Loading | Empty | Error | Partial | Stale | RetryInFlight | Conflict | PermDenied | RateLimited | Optimistic | ExpiredSession |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Overview | P | P (`fresh-tenant`) | P | ✓ | ✓ | — | — | ✓ | ✓ | — | P |
| Agents | P | P (`awaiting-bus`) | P | ✓ | P | ✓ | ✓ | ✓ | ✓ | — | P |
| Policies | P | P (`fresh-tenant`) | P | ✓ | ✓ | ✓ | P | ✓ | ✓ | P | P |
| Audit | P | P (`audit-drift` — pages on-call) | P | ✓ | P | — | — | ✓ | ✓ | — | P |
| Compile | P | P (`fresh-tenant`) | P | ✓ | ✓ | P | ✓ | ✓ | ✓ | P | P |
| Maci (support) | ✓ | ✓ (`awaiting-bus`) | ✓ | ✓ | ✓ | — | — | ✓ | ✓ | — | ✓ |
| Deliberations (support) | ✓ | ✓ (`awaiting-bus`) | ✓ | ✓ | ✓ | ✓ | P | ✓ | ✓ | P | ✓ |
| Incidents (support) | ✓ | ✓ (`fresh-tenant`) | ✓ | ✓ | P | — | — | ✓ | ✓ | — | ✓ |
| Account (support) | ✓ | — | ✓ | — | — | ✓ | — | — | ✓ | — | P |

---

## §7 DX considerations

The frontend has multiple consumers: human contributors, future Claudes, and
the eventual bus client author. The plan must serve all three.

| Consumer | What they need | Where it lives |
|---|---|---|
| New human contributor | "How do I run this and ship a change?" | `acgi-ai/CLAUDE.md` (already strong) + a new `ARCHITECTURE.md` (Phase 6). |
| Future Claude | Per-directory `AGENTS.md` files | Already present per dirty branch — verify they survive Phase 0 PRs. |
| Bus client author | Type contract + request/response shape + error envelope | `src/api/types.ts` + new `INTEGRATING.md` (Phase 6). |
| Designer iterating tokens | Token export pipeline | `pnpm design:export` already wired. Verify it stays clean across phases. |
| QA / external auditor | Privilege audit reproducible | New `audit/privilege-audit-<date>.md` (Phase 3). |

**TTHW (time to hello world) target:** a new contributor with Node 24 +
pnpm 9 installed runs `pnpm hello` (Phase 0 deliverable, per A4) and sees
both `/` and `/console` (with synthetic session via `VITE_BYPASS_SESSION=true`)
in **< 5 minutes total** including install. Measured by `scripts/hello-world.sh`
in CI on a fresh runner. Synthetic-session escape hatch documented in
`GETTING_STARTED.md` and `ARCHITECTURE.md`.

**Error message bar:** every UI error path resolves through `src/lib/errors.ts`
`AppError` (Auth / Network / Parse / RetryExhausted / CSP / Permission /
RateLimit). Each renders **problem + cause + fix + trace-id**. Snapshot test
enforces taxonomy completeness; `throw new Error(string)` in `src/routes/**`
fails build (per A13).

**Multi-consumer phase gates (per DX F2.1):** every named consumer in the table
above must be exercised by at least one phase gate. Without these, "DX is
considered" is documentation only.

| Consumer | Phase gate | Verification |
|---|---|---|
| New human contributor | Phase 5 onboarding eval | Fresh-clone scripted task ("change marketing hero copy + ship a PR") completes in < 30 min; CI runs nightly |
| Future Claude (AI agent) | Phase 0 + Phase 6 | `scripts/agents-drift.sh` validates canonical guide pointers; AGENTS.md drift = CI fail. Smoke: a fresh Claude reads `CLAUDE.md` + `ARCHITECTURE.md` + one stub and produces a one-line summary in < 60s of token time |
| Bus client author | Phase 0 (skeletons) + Phase 5 (full contract) | `INTEGRATING.md` skeleton lands at Phase 0 start so bus author can read in week 1; full contract + schema codegen + contract tests by Phase 5 |
| Designer iterating tokens | All phases | `pnpm design:export` clean across phases; design-token contrast check in Phase 4 |
| QA / external auditor | Phase 3 + Phase 6 | `audit/privilege-audit-<date>.md` reproducible; `audit/sr-pass-<date>.md` reproducible; `audit/pentest-<date>-<vendor>.md` filed; `VITE_EVAL_MODE=true` (per A5) makes any audit run deterministic |

---

## §8 Risk register (severities updated per /autoplan)

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| **Tailwind v4 + strict-CSP coexistence breaks PROD bundle** (was Medium) | **HIGH** | **CRITICAL — Phase 0 hard-gate** | Phase 0 CSP harness + Biome lint forbidding `style={{}}` and arbitrary-value classes (`class(Name)?=".*[a-z]+-\["`). Decision in Phase 0: keep `@tailwindcss/vite` with full guard, or remove it. NO "verify the story" — actual build artifact tested under enforced CSP. (UC3) |
| **Bundle topology: marketing artifact contains console code** (new) | High (current state per Eng Codex) | CRITICAL — defeats two-origin claim | Phase 0 bundle split + symbol-absence assertion in CI. (UC1) |
| **Bus client API shape disagrees with types.ts** (was Low) | **HIGH** | Forces type rewrites + sprint stop | Bus team publishes OpenAPI/protobuf schema in `acgi-ai/contracts/`; CI generates `types.ts`; contract tests gate every change. Frontend cannot be unilateral source of truth. If schema is unavailable, Phase 0 PR #4 (bus contract scaffolding) blocks until bus team has a draft. (UC7) |
| **OIDC integration delays Phase 5** (new) | Medium | 1-2 weeks slip | Auth0/WorkOS dev-tier targeted; fall back to a server-issued HttpOnly SameSite=Strict cookie via Caddy if integration stalls. Stand up signed-cookie verification at the Caddy layer in parallel as low-risk hedge. (UC2) |
| **sessionStorage auth ships to production accidentally** (new) | Low (with Phase 5 gate) | CRITICAL — procurement death | Tree-shake sessionStorage path from production build (parallel to A1); CI assertion. (UC2) |
| **Phase 0 scope grew to 6-7 PRs (was 3-4)** (severity raised) | High | Phase 0 estimate slips from 1w to 2w | 6-7 narrow PRs documented in §4 deliverable; Phase 0 hard-kill gate (CEO Codex MEDIUM): no Phase 1 until all merged + CI green. |
| **Custom router already breaks `?next=` and `/products/<slug>`** (was Low/already-shipped) | **CRITICAL — current code state** | Plan can't ship Phase 1 without it | TanStack Router migration moves to Phase 0 (per UC2/A2) — the deferral was already wrong. |
| **WCAG 2.2 AA can't be reached due to design tokens** (was "Lighthouse 95") | Medium | Phase 4 stalls | Automated contrast check on every token in Phase 0; escalate failing dimensions to design owner. NVDA/VoiceOver scripts in Phase 4 reproducible. (UC5) |
| **Cloud Run cold-start exceeds 800ms p99** (was Medium) | Medium | Production gate scrutiny | Per-env `service.yaml` template (preview minScale=0; staging minScale=1; prod minScale=2 + concurrency=60) + synthetic external pinger every 30s + Playwright cold-start SLO test. (A14) |
| **CI workflows have undiagnosed bugs** | Medium | Phase 5/6 deploy fails | Verify both workflows succeed on a non-production preview during Phase 0 (not Phase 6). Action and image versions pinned (per A12). |
| **Bundle ships with `withFixtureFallback` in production** (new — addresses A1 cross-voice CRITICAL) | Low (with Phase 5 gate) | CRITICAL — compliance theater | Tree-shake under `import.meta.env.PROD` + CI symbol-absence assertion + production fail-closed when `BUS_UPSTREAM` unset (ConsoleError, NOT fixture render). (A1) |
| **Pentest finds critical privilege-boundary issue** (new) | Medium | Phase 6 deploy delayed 2-4w | Engage pentest vendor in Phase 3 (not Phase 6); critical findings close before Phase 6 production deploy. (Open Q3 answered) |
| **Legal review of claim matrix delays Phase 6** (new) | Medium | Phase 6 deploy delayed 1-2w | Engineering authors claim matrix in Phase 3; legal reviews in parallel; sign-off required before Phase 6 starts. (A21, Open Q5 answered) |
| **Marketing CSP report-only delivers no telemetry** (new) | Low | Marketing CSP cutover blocked | Verify report-uri receives + processes events during the 30-day window; abort cutover if data missing. (A11) |
| **AGENTS.md drift across directories** (was implied risk) | Medium | Future Claudes thrash | Canonical `CLAUDE.md` + thin AGENTS.md stubs + `scripts/agents-drift.sh` validation. CI fail on drift. (T3) |
| **Fixture data drifts from real bus responses once bus lands** | High (later) | Out of plan scope | `INTEGRATING.md` documents the contract (Phase 0 skeleton, Phase 5 full); contract tests run from Phase 0 onward; bus author verifies against schema-generated types. |

---

## §9 Cross-references

- `acgi-ai/DESIGN.md` — visual + UX contract (8.9K, settled)
- `acgi-ai/DEPLOY.md` — deployment + CSP + headers (20.9K, settled)
- `acgi-ai/CLAUDE.md` — agent contract / project guide
- `acgi-ai/src/api/types.ts` — API contract source of truth (on WIP branch)
- `/home/martin/Downloads/govern-zone/ACGS/DESIGN.md` — canonical design source
- Constitutional hash (brand furniture): `608508a9bd224290`

---

## §10 Decisions log

| Date | Decision | Rationale |
|---|---|---|
| 2026-05-05 | Plan written off `master`, not `chore/eval-regression-coverage-seed-harness` | The dirty branch is unrelated work (eval coverage). Plan + frontend WIP get reviewed independently. |
| 2026-05-05 | ~~WIP frontend deltas split into 3-4 narrow PRs~~ | **Superseded by /autoplan 2026-05-05 — Phase 0 scope grew to 6-7 narrow PRs (router migration + bundle split + bus contract scaffolding + CSP harness + DX scaffolding added). See §4 Phase 0 deliverable.** |
| 2026-05-05 | i18n explicitly out of scope | Adding it correctly is a separate plan; doing it wrong now blocks every later piece of copy. **(Refined by /autoplan: all user-visible strings are wrapped in a no-op `t()` from day one — extraction pipeline only, no locale switcher.)** |
| 2026-05-05 | ~~Real OIDC out of scope~~ | **Superseded by /autoplan 2026-05-05 (UC2): real OIDC moved into the new Phase 5 as a hard gate. sessionStorage path remains for non-production demo only. See §3 in-scope, §5.5 Phase 5.** |
| 2026-05-05 | ~~TanStack Router migration deferred~~ | **Superseded by /autoplan 2026-05-05 (A2/UC2): migration moved into Phase 0. The custom router already breaks `?next=` query handling and `/products/<slug>` per file:line evidence. See §4 Phase 0b.** |
| 2026-05-05 | ~~Mobile-first console out of scope; hard 1024px cliff~~ | **Refined by /autoplan 2026-05-05 (UC6): mobile-first still out of scope, but the 1024px hard cliff is replaced with a 768-1023px read-only tablet reviewer mode (iPad portrait = 834px). Below 768px the "open on a desktop" notice stands. See §3 ICP, §2 DOD, §5.4.** |
| 2026-05-05 | Strict CSP enforced on console; permissive on marketing | Per DEPLOY.md §5. Cost of console CSP miss is privilege leak; cost of marketing miss is broken analytics. |
| 2026-05-05 | Vitest + Playwright + axe-core, not Jest / Cypress | Vitest matches Vite. Playwright handles e2e + a11y in one binary. Axe-core is the axe-core. |
| 2026-05-05 | Visual diff threshold 0.1% per existing codebase precision norm | Sub-pixel font rendering varies; 0% is unachievable. 0.1% catches real regressions. |
| 2026-05-05 | ~~Each phase = one engineer-week~~ | **Superseded by /autoplan 2026-05-05 — phases now estimated per actual scope (see §12 table). Original "1w forcing function" was a budget claim, not honest estimation; weave-in of 22 auto-decisions + 7 user challenges raised honest total to ~12 weeks for one engineer.** |
| 2026-05-05 (/autoplan) | Phase 5 ↔ Phase 6 swap: bus-readiness + auth ship before production deploy | 8-way cross-voice consensus that production-with-silent-fixture-fallback is compliance theater; user confirmed at premise gate |
| 2026-05-05 (/autoplan) | OIDC moved into scope (was deferred) | UC2 — sessionStorage auth on production console fails procurement on first questionnaire; Auth0/WorkOS dev-tier is 1-2 days |
| 2026-05-05 (/autoplan) | Marketing/console bundle split required | UC1 — Eng Codex + Eng Claude both produced file:line evidence that current bundle defeats the two-origin claim |
| 2026-05-05 (/autoplan) | Tailwind v4 + strict-CSP elevated from MEDIUM Phase 3 risk to CRITICAL Phase 0 mitigation | UC3 — single utility-class accident breaks PROD bundle; "verify the story" is not a mitigation |
| 2026-05-05 (/autoplan) | ICP named: regulated-AI procurement officer at LLM-using enterprise | UC4 — 4-way cross-voice that horizontal sprawl across 11+6 surfaces guaranteed shallow polish; 4-6 console pages + 4 product slugs deferred |
| 2026-05-05 (/autoplan) | Lighthouse 95 replaced by WCAG 2.2 AA conformance evidenced by axe + manual NVDA/VoiceOver | UC5 — Lighthouse covers ~30% of WCAG SC; not a procurement-defensible answer |
| 2026-05-05 (/autoplan) | 1024px hard cliff replaced by 768-1023px tablet reviewer mode + 1024+ operator mode | UC6 — iPad portrait (834px) is the realistic auditor/reviewer device |
| 2026-05-05 (/autoplan) | Bus contract reverses ownership: types.ts ⇐ generated from upstream OpenAPI/protobuf | UC7 — frontend cannot be unilateral source of truth; bus team owns schema, frontend consumes |
| 2026-05-05 (/autoplan) | TanStack Router migration moved into Phase 0 (was deferred) | A2/UC2 — current router already breaks `?next=` and `/products/<slug>` per file:line evidence; deferral was already wrong |
| 2026-05-05 (/autoplan) | `withFixtureFallback` tree-shaken from production; production fail-closed when bus unset | A1/T1 — 8-way cross-voice CRITICAL; chose tree-shake (Claude) over deploy-block (Codex) per P3+P5 |
| 2026-05-05 (/autoplan) | Storybook published to `storybook.acgs.ai` as buyer-evidence artifact | T4 / Open Q4 answered: half-day investment with procurement-grade externality |
| 2026-05-05 (/autoplan) | 3rd-party pentest engaged in Phase 3 | Open Q3 answered: regulated-AI brand demands it; critical findings block Phase 6 |
| 2026-05-05 (/autoplan) | Compliance claim matrix authored by eng + signed by legal before Phase 6 | A21 / Open Q5 answered: subprocessor disclosure is a legal claim, not engineering copy |
| 2026-05-05 (/autoplan) | Premises 1/2/3/5 stand as-written despite cross-voice critique | User-judgment at premise gate: address strongest critiques via phase reorder + scope changes, not premise rewrite. Critiques logged as advisory in §13. |

---

## §11 Open questions for `/autoplan`

These are deliberately left for the dual-voice review to surface, not for
the plan author to pre-answer:

1. Is one engineer-week per phase realistic, or is Phase 3 (CSP) actually two weeks?
2. Should Phase 6's bus-readiness work happen *before* Phase 5's production deploy, so production never serves the silent-fixture-fallback warning to a real buyer?
3. Is a manual privilege audit (Phase 3 task 5) sufficient, or does the regulated-AI brand require a third-party penetration test before Phase 5?
4. Does the test infrastructure (Phase 2) need component-level Storybook, or is integration coverage on `shared.tsx` enough?
5. Should the subprocessor disclosure page (Phase 5) be drafted by legal review before deployment, or can engineering ship a draft and legal iterate?
6. Is the Lighthouse a11y bar of 95 the right number, or should regulated-AI insist on 100?

**Open question answers (from /autoplan, see §13):** Q1: Phase 3 is 2-3w not 1w
(UC3 elevation). Q2: yes — phase reorder accepted, see §12. Q3: regulated brand
needs 3rd-party pentest before public deploy (advisory). Q4: Storybook should
publish as a buyer-evidence artifact (taste decision T4 — recommended).
Q5: legal review before deploy; engineering drafts a claim matrix per A21.
Q6: WCAG 2.2 AA conformance, not Lighthouse 95 (UC5).

---

## §12 — Phase reorder + scope expansion (per /autoplan, 2026-05-05)

Per dual-voice review (Codex + Claude subagents across CEO/Design/Eng/DX),
the six-phase order is updated **and the phase bodies in §5.1-§5.6 have been
rewritten** to absorb 22 auto-decisions + 7 user challenges + 4 taste
recommendations approved at the final gate.

**OLD:** 0 → 1 → 2 → 3 → 4 → 5 (production deploy) → 6 (bus-readiness), 6w total
**NEW:** 0 → 1 → 2 → 3 → 4 → 5 (bus-readiness + real auth) → 6 (production deploy), **~12 weeks total**

| Phase | Goal | Estimate (was → now) |
|---|---|---|
| 0 | Inheritance + router migration + bundle split + bus contract + DX scaffolding + CSP harness | 1w → **2w** |
| 1 | Full state coverage + privilege banner z-index protection + Login interstitial + AppError | 1w → **1.5w** |
| 2 | Test infra (scenario tests, not coverage %) + 5 viewports + Storybook publish | 1w → **1.5w** |
| 3 | CSP enforcement + privilege audit + 3rd-party pentest + claim matrix | 1w → **2-3w** (Open Q1) |
| 4 | WCAG 2.2 AA + NVDA/VoiceOver SR scripts + tablet reviewer mode a11y | 1w → **1.5w** |
| 5 (was 6) | Bus-readiness + OIDC + bundle split verification + tree-shake fallback + Cloud Run templating | 1w → **2w** |
| 6 (was 5) | Production deploy + marketing CSP report-only + trust/security/DPA/SOC2 pages + SLO probes | 1w → **1.5w** |

**Why the swap:** 8-way cross-voice consensus that `withFixtureFallback`
shipping to production is compliance theater. 6-way consensus that
sessionStorage auth on `console.acgs.ai` fails procurement. The new Phase 5
must complete real OIDC (or a server-issued HttpOnly SameSite=Strict cookie),
tree-shake `withFixtureFallback` from production builds, split the marketing
and console bundles, and verify `/api/v1/*` proxies to a real or stubbed bus
before any traffic reaches `console.acgs.ai`.

**Why the scope expansion:** original "each phase = one engineer-week"
forcing function (per §10 decision log) was a budget claim, not an estimate.
The dual-voice review found 22 mechanical changes + 7 structural changes
that the original plan deferred or omitted. The user accepted all of them at
the final gate. Honest re-estimation: ~12 weeks for one engineer. If two
engineers can parallelize Phase 0's 6-7 PRs, real wall-clock is closer to 9
weeks.

**What this means for §10 (Decisions log):** the "each phase = one
engineer-week" decision is superseded — see §10 update below.

---

## §13 — /autoplan review report (2026-05-05)

Codex CLI 0.128.0. 4 phases × 2 voices = 8 independent reviews, all exit 0.
Premise gate: user accepted phase reorder; premises 1/2/3/5 critiques surface
as advisory (UC4 / advisory line in §11 answers above).

### Cross-phase themes (multi-voice consensus, top 12)

| # | Theme | Voices | Severity | Resolution |
|---|---|---|---|---|
| 1 | `withFixtureFallback` in production = trust failure | 8 | CRITICAL | §12 reorder + A1 |
| 2 | OIDC must precede production deploy | 6 | CRITICAL | §12 + UC2 |
| 3 | Marketing bundle contains console code (two-origin claim broken) | 2 (Eng) | CRITICAL | UC1 |
| 4 | Tailwind v4 + strict CSP coexistence is high-risk | 2 (Eng) | CRITICAL | UC3 |
| 5 | ICP unnamed; horizontal scope sprawl | 4 (CEO+Design) | HIGH | UC4 |
| 6 | Custom router already broken (`?next=`, `/products/*`) | 3 | HIGH | A2 |
| 7 | State coverage incomplete (stale/conflict/permission/rate-limit absent) | 3 | HIGH | A3 |
| 8 | WCAG 2.2 AA, not Lighthouse 95 | 2 (Design) | HIGH | UC5 |
| 9 | 1024px cliff strands iPad reviewers (834px) | 2 (Design) | HIGH | UC6 |
| 10 | `types.ts` can't be unilateral bus contract source | 3 | HIGH | UC7 |
| 11 | TTHW unmeasured; no `pnpm hello` | 2 (DX) | HIGH | A4 |
| 12 | No deterministic VITE_EVAL_MODE | 2 (DX) | HIGH | A5 |

### Per-phase consensus (DISAGREE = not confirmed; both voices flagged)

```
CEO (6 dimensions): 0/6 confirmed — premises (DISAGREE→user kept), problem (NO→UC4),
                    scope (NO→UC4), alternatives (NO→A2/UC2), competitive (advisory),
                    6-month traj (NO→reorder+UC1+UC4)

Design (6 dimensions): 0/6 confirmed — hierarchy (NO→UC4), states (NO→A3),
                       journey (NO→A6), specificity (NO→A7), privilege (PARTIAL→A8),
                       a11y bar (NO→UC5)

Eng (6 dimensions): 0/6 confirmed — architecture (NO→UC1+A2), tests (NO→A9),
                    perf (NO→A10), security (NO→UC2+A11+A12), errors (NO→A1+A13),
                    deploy (NO→A14)

DX (6 dimensions): 0/6 confirmed — TTHW (NO→A4), naming (NO→A15), errors (NO→A13),
                   docs (NO→A16), upgrade (NO→A17+UC7), eval-mode (NO→A5)
```

### Auto-decided changes (A1-A22) — applied on approval, audit trail in §14

| # | Change | Phase | Principle |
|---|---|---|---|
| A1 | Tree-shake `withFixtureFallback` from PROD; narrow catch to network errors only; fail-closed when `BUS_UPSTREAM` unset | new Ph 5 | P1, P5 |
| A2 | Migrate to TanStack Router in Phase 0 (already in deps; current router fails `?next=` and `/products/*` per file:line evidence) | Phase 0 | P5, P3 |
| A3 | Expand `console/shared.tsx` with Stale, RetryInFlight, PermissionDenied, RateLimited, Conflict, OptimisticPending; state matrix per page in §6 | Phase 1 | P1 |
| A4 | Add `pnpm hello` / `hello:world` script + CI gate (clean install + first render < 5 min); Local static foundation: `pnpm run test:tthw`; clean-runner scheduled TTHW measures the HTTP shell budget while browser first-render proof remains Phase 2 | Phase 0 | P1 |
| A5 | Add `VITE_EVAL_MODE` (fixed clock, fixed seed, fail-on-MSW-miss, animations off) | Phase 0/1 | P1 |
| A6 | Login interstitial (parchment moment naming operator + matter + constitutional hash `608508a9bd224290`) | Phase 1 | P5 |
| A7 | Per-route wire-level UI decisions (header anatomy, action grouping, table/filter behavior, destructive-action pattern); local static gate `pnpm run test:wire-decisions` | Phase 1 | P5 |
| A8 | Ban toasts/modals/FABs floating above privilege banner z-index; receipts render in right rail or inline only | Phase 1/3 | P5 |
| A9 | Replace 80%-coverage target with required scenario tests (origin split, auth enforcement, prod no-mocks, CSP, partial bus, headers) | Phase 2 | P1 |
| A10 | Jittered polling intervals + visibility-aware refetch + bus-health adaptive backoff | Phase 1 | P1 |
| A11 | Marketing CSP `Content-Security-Policy-Report-Only` with 30-day cutover to enforced; report-uri allowlist | new Ph 6 | P1 |
| A12 | Pin Docker images, GH actions, vercel CLI version; align Node 24; commit font hash manifest checked at build | Phase 0 | P3, P5 |
| A13 | `src/lib/errors.ts` `AppError` taxonomy (Auth/Network/Parse/RetryExhausted/CSP/Permission/RateLimit) | Phase 1 | P1, P5 |
| A14 | Cloud Run `service.yaml` templated per env; cost estimate + p99 cold-start SLO test | new Ph 5 | P1 |
| A15 | Standardize pnpm scripts: `dev`, `dev:mock`, `dev:live`, `hello`, `test`, `test:e2e`, `test:visual`, `test:a11y`, `test:all`, `design:export`, `audit:eval`; local static foundation: `pnpm run test:test-surface` | Phase 0 | P5 |
| A16 | Move ARCHITECTURE.md + INTEGRATING.md skeletons from Phase 6 to Phase 0 | Phase 0 | P5 |
| A17 | Objective TanStack Router triggers (route params, route-level guards, loaders, nested layouts, search-param state) | §3 | P5 |
| A18 | Cross-tab session sync via `localStorage` + `storage` event listener | Phase 1 | P1 |
| A19 | CSP harness in CI: production-build container, fail on console-route CSP violation, scan HTML/assets for inline styles/third-party | Phase 3 | P1 |
| A20 | Visual regression baselines: 360, 768, 834, 1024, 1440 + empty/error/stale/permission-denied/long-content states | Phase 2 | P1 |
| A21 | Compliance-claim matrix: every public claim ties to live or explicitly stubbed evidence (source event, decision, hash, actor, timestamp) | all phases | P5 |
| A22 | DPA + SOC2 roadmap + security.txt + sub-processor change RSS published on `/trust` and `/security` | new Ph 6 | P1 |

### User challenges (UC1-UC7) — gate decisions

These change the user's stated direction beyond auto-decisions; both models flagged each independently.

- **UC1: Marketing/console bundle split.** Eng codex (CRIT) + Eng claude (A2) cited file:line evidence: `App.tsx:3-7` static-imports console routes; `Marketing.tsx:127+` intercepts /console clicks via `navigate()` instead of letting `vercel.json` 308 redirect. Fix: split builds (`vite build` × 2 entry points) + assert marketing artifact cannot import console. Estimate: 1-2 days.
- **UC2: OIDC as new Phase 5 hard gate.** §3 + §10 originally deferred OIDC; both Eng + both CEO + both Design voices flagged sessionStorage auth as procurement-blocking + XSS-vulnerable. Auth0/WorkOS dev tier: 1-2 days. **Resolved: §3 in-scope updated, §10 row struck through, Phase 5 (§5.5) carries OIDC integration as task 1.**
- **UC3: Tailwind v4 + CSP elevated to Phase 0 (was MEDIUM, now CRITICAL).** Eng codex shows `@tailwindcss/vite` runtime emits `<style>` tags blocked by `style-src 'self'`. Single utility-class accident breaks PROD bundle. Either remove `@tailwindcss/vite` if utilities truly banned per CLAUDE.md, or add CSP harness + Biome-lint gate in Phase 0.
- **UC4: ICP cut.** 4-way cross-voice. 11 console pages + 6 product slugs without ICP "guarantees shallow polish." Pick 1-2 reference buyers + one proof journey ("buyer verifies policy enforcement evidence end-to-end"); freeze/defer the rest.
- **UC5: WCAG 2.2 AA replaces Lighthouse 95.** Lighthouse ≈ 30% of WCAG SC. Procurement asks "WCAG conformance level?" — Lighthouse score is not an answer. Adds: route-level keyboard maps, target sizes (24/44px), focus restoration, manual NVDA/VoiceOver pass.
- **UC6: Tablet reviewer mode (768-1023px).** iPad portrait is 834px, the realistic auditor device. Add read-only evidence-review mode in this range; hard-block only high-risk operator actions.
- **UC7: Bus contract reverses ownership.** §8 + §6 originally said "bus client adapts to types.ts." Frontend cannot be unilateral source. Fix: bus team publishes OpenAPI/protobuf schema in `acgi-ai/contracts/`; CI generates `types.ts` and contract-tests against recorded responses (incl. unknown/missing fields, version skew, error envelopes). **Resolved: §3 in-scope updated, §4 Phase 0a adds `acgi-ai/src/contracts/` directory + codegen pipeline, §6 test registry adds `api/contracts/` row, §8 risk row updated.**

### Taste decisions (T1-T4) — recommendations applied; user can override

- **T1: Production-fixture fix.** Tree-shake (Claude) vs deploy-block (Codex). *Recommended:* tree-shake (P5 + P3 — Vite supports `import.meta.env.PROD`).
- **T2: Tablet handling.** Raise cliff to 1100px (Claude) vs 768-1023 reviewer mode (Codex). *Recommended:* 768-1023 reviewer mode (P1 — covers a real device class).
- **T3: AGENTS.md drift control.** CI fails on missing AGENTS.md per dir (Claude) vs canonical guide + drift check (Codex). *Recommended:* canonical + stubs + drift check (P4 DRY).
- **T4: Storybook (open Q4).** CEO Claude proposes publishing Storybook to `storybook.acgs.ai` as a buyer-evidence artifact. *Recommended:* yes, ½ day on top of Phase 2 (P1 completeness — buyer evidence > internal-coverage framing).

---

## §14 — Decision audit trail

| # | Phase | Decision | Class | Principle | Rationale |
|---|---|---|---|---|---|
| 1 | CEO/all | Phase 5↔6 reorder | Mechanical | P1, P2 | 8-way cross-voice; user confirmed at premise gate |
| 2 | CEO | Premises 1/2/3/5 stand; concerns advisory | User-judgment | n/a | User chose option A at premise gate |
| 3 | CEO | UC4 ICP cut surfaced at final gate | User Challenge | n/a | 4-way consensus, structural change |
| 4 | Design | A3 state primitive expansion | Mechanical | P1 | 3-way consensus on incomplete states |
| 5 | Design | A6 Login interstitial | Mechanical | P5 | Both Design voices flagged journey gap |
| 6 | Design | A7 wire-level UI decisions | Mechanical | P5 | Codex MEDIUM + Claude F4 |
| 7 | Design | A8 ban toasts/modals/FABs over banner | Mechanical | P5 | Claude F1 CRITICAL with concrete attack |
| 8 | Design | UC5 WCAG 2.2 AA bar | User Challenge | n/a | 2-way HIGH; replaces user's Lighthouse 95 bar |
| 9 | Design | UC6 tablet reviewer mode | User Challenge | n/a | 2-way HIGH; reverses user's 1024px cliff |
| 10 | Eng | A1 tree-shake fixture fallback | Mechanical | P1, P5 | 8-way (cross-phase) — strongest signal |
| 11 | Eng | A2 TanStack Router migration | Mechanical | P5, P3 | 3-way + file:line evidence |
| 12 | Eng | A9 scenario tests replace coverage % | Mechanical | P1 | Both Eng voices flagged wrong surface |
| 13 | Eng | A10 jittered polling | Mechanical | P1 | Both Eng voices flagged thundering herd |
| 14 | Eng | A11 marketing CSP report-only→enforced | Mechanical | P1 | Both Eng voices on supply chain |
| 15 | Eng | A12 image/action/CLI pinning | Mechanical | P3, P5 | Codex MEDIUM + Claude S4 |
| 16 | Eng | A13 AppError taxonomy | Mechanical | P1, P5 | Cross-phase Eng+DX |
| 17 | Eng | A14 Cloud Run service templating | Mechanical | P1 | Codex MEDIUM with file refs |
| 18 | Eng | A18 cross-tab session sync | Mechanical | P1 | Claude A4 race condition |
| 19 | Eng | A19 CSP harness in CI | Mechanical | P1 | Both Eng voices on CSP enforcement |
| 20 | Eng | UC1 bundle split | User Challenge | n/a | 2-way CRITICAL with file:line refs |
| 21 | Eng | UC2 OIDC into new Phase 5 | User Challenge | n/a | 6-way; reverses §3 deferral |
| 22 | Eng | UC3 Tailwind+CSP to Phase 0 | User Challenge | n/a | 2-way; reverses §8 risk register |
| 23 | Eng | UC7 bus contract reverses | User Challenge | n/a | 3-way; reverses §8 + §6 ownership |
| 24 | DX | A4 pnpm hello + CI gate | Mechanical | P1 | Both DX voices flagged TTHW unmeasured |
| 25 | DX | A5 VITE_EVAL_MODE | Mechanical | P1 | Both DX voices on regulated-AI determinism |
| 26 | DX | A15 pnpm script standardization | Mechanical | P5 | Both DX voices on naming gaps |
| 27 | DX | A16 docs to Phase 0 | Mechanical | P5 | Both DX voices on parallel-work blocker |
| 28 | DX | A17 router triggers | Mechanical | P5 | Codex MEDIUM on subjective trigger |
| 29 | DX | A20 visual baseline expansion | Mechanical | P1 | Design Codex LOW + DX Codex |
| 30 | DX | A21 compliance claim matrix | Mechanical | P5 | CEO Codex HIGH + Design Codex MEDIUM |
| 31 | DX | A22 trust/security pages | Mechanical | P1 | CEO Claude F5.2 + CEO Codex |
| 32 | All | T1 tree-shake over deploy-block | Taste | P5, P3 | Both achieve goal; Claude approach simpler |
| 33 | All | T2 768-1023 reviewer mode | Taste | P1 | Codex approach covers real device class |
| 34 | All | T3 canonical + stubs + drift check | Taste | P4 | Codex approach lower maintenance |
| 35 | All | T4 publish Storybook (yes) | Taste | P1 | Open Q4 answered: buyer evidence value |
