# Complete Platform Frontend — `acgi-ai`

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
| **Routing** | Hits the correct surface; deep links work; back/forward work; 404 falls through to `NotFound`. |
| **Data** | Loading, error, empty, and partial states are explicit. No "blank page while loading" anywhere. |
| **CSP** | Bundle builds and the privileged origin loads with **strict CSP enforced** (no `'unsafe-inline'`, no third-party origins). |
| **Privilege** | The parchment banner is structural (`DESIGN.md §4.3`); no animation, no `aria-hidden`, no flag-gate. Survives a `view-source` audit. |
| **A11y** | Keyboard-navigable end-to-end. Visible focus on every interactive. Lighthouse a11y ≥ 95 on every surface. |
| **Responsive** | Console: ≥ 1024px supported; below that, a deliberate "open on a desktop" notice (not a broken layout). Marketing: works down to 360px. |
| **Lint + build** | `pnpm lint && pnpm build` clean. |
| **Test gate** | Smoke + a11y + visual checks pass in CI (test infra is part of this plan, see §6). |
| **Deploy gate** | Both `marketing.yml` and `console.yml` workflows green; production preview URL serves correct headers. |

A surface that fails any row is not done. There is no "ship and follow up."

---

## §3 In scope / Not in scope

### In scope (this plan completes these)

- **Marketing** at `/`, `/products`, `/products/<slug>`, `/privacy`
- **Console** at `/console`, `/console/{agents, maci, deliberations, incidents, policies, compile, audit, settings, tenants, account}`
- **Auth** boundary: session-storage gating today; OIDC-shaped API contract for tomorrow (no real IdP integration in this plan)
- **API contract**: hooks layer + types + MSW handlers + fixture fallback already shipped on the WIP branch; this plan formalizes and extends them
- **Test infrastructure**: vitest + @testing-library + playwright smoke + axe-core a11y
- **CI/CD**: the two-workflow split in `.github/workflows/` (already drafted on WIP branch); this plan green-lights it
- **CSP enforcement** on the console origin
- **Self-hosted WOFF2** verification end-to-end
- **Loading / empty / error / partial states** for every console surface
- **Keyboard accessibility** + visible focus + Lighthouse a11y ≥ 95
- **Production deploy** of both surfaces (Vercel marketing, Cloud Run/Fly console)

### Not in scope (explicitly deferred — write to TODOS.md, do not expand)

- Real IdP / OIDC integration. The session API stays sessionStorage-shaped; SSO terminates at the console origin per `DEPLOY.md §11`.
- Bus client and `/api/v1/*` server. The hooks layer continues to fall back to fixtures. When `src/core/shared/` lands in the ACGS monorepo, a separate plan picks up integration.
- Multi-region failover. Single region until SLO > 99.9%.
- Internationalization. English only. No `i18next`, no locale switcher, no RTL. (Adding i18n correctly is a separate plan; doing it wrong now blocks every later piece of copy.)
- Mobile-first console layout. Console is operator surface; explicit "open on a desktop" message below 1024px is acceptable.
- TanStack Router migration. Custom 14-line `App.tsx` router stays until data loaders or nested layouts force the change (`DESIGN.md §7.3`).
- Dark mode. Banned for the privileged console (`DESIGN.md` Don'ts).
- Server-side rendering. Bundle is fully static; auth tokens come from runtime, never the build (`DEPLOY.md §6`).

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

---

## §4 Inherited work — Phase 0 (must land before Phase 1 starts)

The WIP branch `chore/eval-regression-coverage-seed-harness` carries
substantial completion work that is *out of place on that branch* but is a
prerequisite for the rest of this plan. It must land first via its own PR(s),
not as part of this plan.

| File | Purpose | Action |
|---|---|---|
| `src/api/{client,hooks,types}.ts` | Single fetch wrapper, react-query hooks, hand-written FastAPI types | Promote to a feature branch, PR, land on master. |
| `src/lib/session.ts` | sessionStorage-backed session gate + `SESSION_CHANGE_EVENT` | Same. |
| `src/mocks/handlers.ts` + `src/mocks/data/*` | MSW handlers + 12 fixture modules | Same. |
| `src/routes/ProductSurfaces.tsx` | `/products` index + `/products/<slug>` for the 6 product references | Same. |
| `src/routes/console/shared.tsx` | `useTextFilter`, `SearchToolbar`, `Receipt`, `EmptyState`, `ConsoleLoading`, `ConsoleError` | Same. |
| `src/routes/console/{Account,Tenants,Maci,Overview,Compile,Deliberations}.tsx` (new or grown) | Page bodies | Same. |
| `infra/Caddyfile`, `infra/Dockerfile.console` | Container config for the console origin | Same. |
| `.github/workflows/{console,marketing}.yml` | Split deploy workflows | Same. |
| `vercel.json` | Marketing routing + headers | Same. |
| `tailwind.theme.json`, `tokens.json`, `scripts/check-design-tokens.py` | Design token export + lint | Same. |
| Updated `DESIGN.md`, `DEPLOY.md`, `package.json`, `vite.config.ts` | Contract + config | Same. |

**Phase 0 deliverable:** the WIP changes split into reviewable PRs, landed on master, and the `plan/complete-platform-frontend` branch rebased on top. Until that happens, the rest of this plan cannot start without depending on a branch it should not depend on.

**Risk if skipped:** the rest of the plan is built on phantom code — reviewers reading from master will not see what the plan references.

---

## §5 Implementation phases

Each phase is a **week** of focused work for one engineer. Total: ~6 weeks.
Phases are sequential because each builds on the prior phase's gates.

### Phase 1 — State coverage on every console surface (1w)

**Goal:** every console page renders a real loading state, a real empty
state, and a real error state — using `console/shared.tsx` primitives.

**Tasks:**
1. Audit all 11 console pages against `shared.tsx`. Each must use `ConsoleLoading`, `ConsoleError`, and `EmptyState` instead of bare conditionals or null returns.
2. Add explicit "no data yet" copy that names the bus and the matter — never "loading…" alone.
3. Wire `react-error-boundary` (already in deps) at the console shell level so a thrown error inside any page body falls through to a console-styled boundary, not the React red screen.
4. Add `aria-live="polite"` regions to the right-rail (already partially done in `shared.tsx`'s `Receipt`); verify across pages.
5. Verify every `useQuery` invocation has a `refetchInterval` consistent with `LIVE` (5s/10s) or `SLOW` (30s/60s) per `hooks.ts` convention.

**Gate:** manual smoke through every console page with the API offline. No blank screens. No "undefined" rendered. Every action button shows a loading state when its mutation is in flight.

### Phase 2 — Test infrastructure (1w)

**Goal:** a real test gate exists, runs in CI, and blocks merge on red.

**Tasks:**
1. Add **Vitest + @testing-library/react** to devDeps. Target: 80% coverage on `src/api/hooks.ts`, `src/lib/session.ts`, and `src/routes/console/shared.tsx`. These are the load-bearing utilities.
2. Add **MSW node-mode** test setup so hook tests exercise the same handlers as the dev server.
3. Add **Playwright** smoke pack: marketing landing loads, `/products/<slug>` resolves for all 6 slugs, `/console` redirects to `/login` without session, `/console` loads with synthetic session, every sidebar link navigates without throwing.
4. Add **axe-core** via `@axe-core/playwright` on every smoke route. Fail on any serious or critical violation.
5. Add `pnpm test`, `pnpm test:e2e`, `pnpm test:a11y` scripts. Wire into both workflows.
6. Add a **visual-diff** baseline pass — Playwright screenshots of marketing hero, console overview, login, and one product page. Diff threshold 0.1% per the existing precision norms in this codebase.

**Gate:** CI runs all four (lint, build, unit+integration, e2e+a11y) on PR. All four green required. Local: `pnpm test && pnpm test:e2e && pnpm test:a11y` runs in < 60s on a clean machine.

### Phase 3 — CSP enforcement + privilege audit (1w)

**Goal:** the console serves with **strict CSP** in production. Verifiable by curl + browser devtools.

**Tasks:**
1. Audit `src/**/*.tsx` for any `style={{}}` JSX attribute. Replace each with a `u-*` utility (`csp-utilities.css`) or a component-scoped class. `pnpm lint` passes on biome's CSP-style rule (add custom lint or grep guard if biome lacks it).
2. Verify the bundle has zero `<style>` tags injected at runtime — Vite + Tailwind v4 may emit them; if so, configure Vite to extract.
3. Stand up the Caddy container locally (the `infra/Dockerfile.console`). Confirm the response headers from §5 of `DEPLOY.md` are all present. Run a third-party CSP analyzer against a local `https://localhost.console.acgs.ai`.
4. Write a Playwright test that asserts: `Content-Security-Policy` header is enforced (not report-only) on every `/console/*` response, and `X-Frame-Options: DENY` is present.
5. Privilege audit checklist (executed by hand, recorded in `audit/privilege-audit-<date>.md`):
   - View-source on `/console`: zero third-party origins in `<link>`, `<script>`, `<img>`, `<iframe>`, `<font>`.
   - Network panel on a fresh `/console` load: every request hits `console.acgs.ai` (or `localhost` in dev).
   - Right-click → inspect on the privilege banner: `aria-hidden` is `false`, parent has no `display: none`, no animation classes.
   - DevTools Lighthouse "Best Practices" score = 100.

**Gate:** privilege audit passes. CSP header present, enforced, and strict. Zero third-party network requests on console origin in production-bundle preview.

### Phase 4 — Accessibility pass (1w)

**Goal:** Lighthouse a11y ≥ 95 on every public route. Keyboard works end-to-end.

**Tasks:**
1. Run axe-core (Phase 2 setup) against every smoke route. Fix all serious + critical findings.
2. Manual keyboard pass: `Tab` reaches every interactive in DOM order; `Shift+Tab` reverses; `Enter` and `Space` activate buttons; `Esc` closes any modal/menu; focus is always visible (the design system already has `--focus-ring` tokens — verify they are applied).
3. Form labels: `Login.tsx`, console search inputs (`SearchToolbar`), settings forms — every input has a programmatic label, not just a placeholder.
4. ARIA audit on the `Console` shell: sidebar uses `<nav aria-label="…">`, right-rail uses `<aside aria-label="…">`, page main uses `<main>` exactly once per route.
5. Color contrast: run an automated contrast check on every token in `src/index.css` against `--paper`, `--paper-alt`, `--paper-deep`, `--card`. Anything below 4.5:1 on body text or 3:1 on large text gets a token revision (escalate to design owner).
6. `prefers-reduced-motion` respect: confirm the existing reset in `src/index.css` covers any new motion added in Phase 1.
7. Add an a11y section to `DESIGN.md` (or a new `A11Y.md`) recording the bar and the audit method.

**Gate:** Lighthouse a11y ≥ 95 on `/`, `/products`, `/products/legalguard`, `/login`, `/privacy`, `/console`, `/console/agents`. Manual keyboard pass clean.

### Phase 5 — Production deploy + post-deploy verification (1w)

**Goal:** both surfaces deployed to production. Headers verified live. Subprocessor story documented.

**Tasks:**
1. Provision `acgs.ai` and `console.acgs.ai` per `DEPLOY.md §9`. DNS, ACME certs, CAA records, DMARC `p=reject`.
2. Deploy marketing to Vercel via `marketing.yml`. Verify production headers match `vercel.json`.
3. Deploy console to Cloud Run (or Fly.io) via `console.yml` against the Caddy container. Verify production headers match the Caddyfile §5 table from `DEPLOY.md`.
4. Verify the marketing → console hand-off: clicking "Open the console" on `acgs.ai` lands on `console.acgs.ai/console`, not on a marketing-side `/console` rendering.
5. Wire `/healthz` on the console origin returning `{ ok, served_hash, build_id }` per `DEPLOY.md §10`.
6. Configure alerting per `DEPLOY.md §10`: 5xx > 1% / 5min on console pages on-call. Cert expiry < 14d pages on-call.
7. Submit `acgs.ai` to the HSTS preload list per `DEPLOY.md §9`.
8. Write the **subprocessor disclosure page** (`/subprocessors` on marketing) per `DEPLOY.md §11`. List Vercel (marketing only), Cloud Run / Fly (console), Let's Encrypt (certs), font foundries — and explicitly state no third party touches `/console/*`.

**Gate:** production verified via the post-deploy checklist (`scripts/postdeploy-verify.sh` — to be written). Buyer-grade subprocessor page lives.

### Phase 6 — Hardening + bus-readiness (1w)

**Goal:** the frontend is ready for the bus client to land without a second migration.

**Tasks:**
1. Add the `/api/*` reverse-proxy stanza to the Caddyfile (commented out today). Wire it to a configurable upstream (`BUS_UPSTREAM` env). Verify with a stub upstream that returns 200 + JSON.
2. Document the bus-client landing in `INTEGRATING.md` at the repo root (next to the existing one): exact request/response contracts, header expectations, error envelope shape, retry semantics. Use `src/api/types.ts` as the source of truth for shape.
3. Add a `vite-env.d.ts` declaration for `VITE_USE_MOCKS` and `VITE_API_PROXY_TARGET` (already used in `client.ts` comments) so the env-var contract is typed.
4. Replace `withFixtureFallback`'s silent `console.warn` with a dev-only banner in the topbar: `⁂ Bus offline — rendering fixture data` so demos never silently mislead.
5. Performance pass: Lighthouse Performance ≥ 90 on marketing, ≥ 85 on console. Bundle size budget: marketing ≤ 200KB gzipped, console ≤ 350KB gzipped. Wire `vite-bundle-visualizer` to the build for ongoing visibility.
6. Add an `ARCHITECTURE.md` at `acgi-ai/` root summarizing routing, data flow, privilege boundary, build, and deploy in a single page so a new contributor can be productive in 30 minutes (DX target).

**Gate:** all DOD rows from §2 pass on every surface. The next contributor (or future Claude) can run `pnpm dev` and ship a feature without reading the whole tree.

---

## §6 Test plan (the registry)

| Surface | Unit | Integration | E2E | A11y | Visual |
|---|---|---|---|---|---|
| `Marketing.tsx` | n/a (pure render) | n/a | smoke: loads at `/` | axe @ `/` | hero baseline |
| `ProductIndex / ProductSurface` | route slug resolution | n/a | smoke: 6 slugs resolve | axe @ each | one slug baseline |
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
| `console/Settings` | section render | useSettings MSW | n/a | axe | n/a |
| `console/Tenants` | filter logic | useTenants MSW | n/a | axe | n/a |
| `console/Account` | identity + sessions render | useAccount MSW | smoke: signed-in fields visible | axe | n/a |
| `lib/session.ts` | create / clear / has | event dispatch | n/a | n/a | n/a |
| `api/hooks.ts` | LIVE vs SLOW intervals | fixture fallback on 500 | n/a | n/a | n/a |
| `routes/console/shared.tsx` | useTextFilter | n/a | n/a | axe per consumer | n/a |

**Failure modes that the test plan must catch:**
- A console page returns `null` while loading → blank screen — must catch with smoke + visual.
- A mutation fails silently → catch with integration test asserting `Receipt` renders the error.
- The privilege banner gets `aria-hidden="true"` from a copy-paste — catch with axe + a Playwright assertion against the banner's accessible name.
- A `style={{}}` slips into the tree — catch with a Biome lint rule + a build-time CSP smoke that loads the bundle in a strict-CSP iframe.
- A third-party origin gets pulled in by a transitive dep — catch with a Playwright network-log assertion on `/console` load.

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
pnpm 9 installed runs `pnpm install && pnpm dev` and sees the marketing
page in under 60 seconds. Console surface visible (with synthetic session)
in under 90 seconds.

**Error message bar:** every error message in the UI must answer
*problem + cause + fix*. "Could not reach the bus. [Retry]" already does
this — extend the same pattern to every error path added in Phases 1-6.

---

## §8 Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Phase 0 inheritance PR(s) get scope-creeped | High | Blocks every later phase | Split inheritance into 4-6 narrow PRs (api layer, products, session, mocks, infra, workflows) — not one mega-PR. |
| Strict CSP breaks Tailwind v4 runtime style injection | Medium | Phase 3 stalls | Verify Tailwind v4's CSP story before Phase 3; have a fallback to extract-only mode. |
| Custom router can't express deep links into product slugs cleanly | Low | Already shipped on WIP branch | If broken, escalate to TanStack Router migration as out-of-scope follow-up. |
| Lighthouse a11y can't reach 95 due to design choices | Medium | Phase 4 stalls | Escalate any failing dimension to design owner before changing tokens. Don't silently relax DOD. |
| Bus client lands mid-plan and changes API shape | Low | Forces type rewrites | `src/api/types.ts` is the contract. Bus client adapts to it, not vice versa. If bus disagrees, halt and re-spec. |
| Cloud Run / Fly cold-start adds latency to console | Medium | Production gate scrutiny | Pre-warm via min-instances=1 in production deploy config. |
| The dirty branch's CI workflows have undiagnosed bugs | Medium | Phase 5 deploy fails | Verify both workflows succeed on a non-production preview during Phase 0, not Phase 5. |
| Fixture data drifts from real bus responses once bus lands | High (later) | Out of plan scope | Phase 6's `INTEGRATING.md` documents the contract; future bus author verifies against types. |

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
| 2026-05-05 | WIP frontend code is Phase 0 (split-PR inheritance), not part of the plan's own commits | Keeps reviewable diffs small; lets autoplan review the plan, not the WIP. |
| 2026-05-05 | i18n explicitly out of scope | Adding it correctly is a separate plan; doing it wrong now blocks every later piece of copy. |
| 2026-05-05 | Real OIDC out of scope | sessionStorage gate is enough until SSO product line lands; auth terminates at the console origin per DEPLOY.md §11. |
| 2026-05-05 | TanStack Router migration deferred | Custom 14-line router still serves. Migrate when data loaders or nested layouts force it. |
| 2026-05-05 | Mobile-first console out of scope | Console is operator surface; explicit "open on a desktop" notice below 1024px is acceptable. Marketing must work to 360px. |
| 2026-05-05 | Strict CSP enforced on console; permissive on marketing | Per DEPLOY.md §5. Cost of console CSP miss is privilege leak; cost of marketing miss is broken analytics. |
| 2026-05-05 | Vitest + Playwright + axe-core, not Jest / Cypress | Vitest matches Vite. Playwright handles e2e + a11y in one binary. Axe-core is the axe-core. |
| 2026-05-05 | Visual diff threshold 0.1% per existing codebase precision norm | Sub-pixel font rendering varies; 0% is unachievable. 0.1% catches real regressions. |
| 2026-05-05 | Each phase = one engineer-week | Forcing function on phase scope. If a phase grows past one week, it's two phases. |

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
