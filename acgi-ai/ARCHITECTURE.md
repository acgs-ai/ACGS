# acgi-ai architecture

This is the current local architecture for the ACGS public marketing surface and privileged governance console. It is a deployment-readiness contract, not proof that the production domains are live.

## Surfaces and build

`src/main.tsx` imports `@surface/App`. Vite aliases that module at build time:

- marketing mode -> `src/surfaces/marketing/App.tsx`
- console mode -> `src/surfaces/console/App.tsx`

The package builds two artifacts from the same source tree:

- `pnpm build:console` writes the privileged console artifact to `dist/`
- `pnpm build:marketing` writes the public marketing artifact to `dist-marketing/`
- `pnpm test:surfaces` builds both and verifies that the marketing artifact excludes console-only sentinels

## Routing

Both surfaces now use TanStack Router route trees behind the `@surface/App` alias. Marketing and console still build as separate Vite artifacts, but route matching, product slugs, login search params, and console auth guards are expressed as route objects. The current route split is:

- marketing: `/`, `/privacy`, `/trust`, `/security`, `/products`, `/products/<slug>`
- marketing privileged redirect: `/login`, `/console`, `/console/*` redirect to the `console.acgs.ai` origin
- console: `/login`, `/console`, `/console/*`

`src/lib/navigate.ts` remains a small same-surface bridge for existing button handlers: it calls `history.pushState()` and dispatches `popstate`, which TanStack Router observes. The console route tree guards `/console` and `/console/$section`, validates `/login?next=`, canonicalizes `/console/overview` to `/console`, and keeps route-level loaders/error boundaries available for later phases.

## Data flow

`src/api/client.ts` is the browser API boundary. It uses same-origin relative paths and `credentials: same-origin` so the browser does not learn a third-party API origin.

- Console domain -> Caddy `/api/v1/*` and `/api/bus/*`
- Caddy -> `BUS_UPSTREAM` with `X-ACGS-Schema-Version`
- React hooks -> `src/api/hooks.ts`
- Bus schema source of truth -> `contracts/bus.openapi.json`, mirrored at `src/api/openapi.json` for local API docs
- Contract types -> `src/api/types.ts` plus generated bus types in `src/api/bus.generated.ts`

Non-production fixture fallback is gated by `VITE_USE_MOCKS=true`. Production code must fail closed when the API or bus is unavailable.

## Privilege boundary

The console is the privileged surface. Public marketing must not embed the console route tree or console fixture data. The boundary is enforced by:

- mode-specific `@surface/App` aliases
- marketing/console bundle checks
- Vercel edge route checks that deny internal docs first, redirect `/console` paths to `https://console.acgs.ai/console`, and keep the marketing SPA fallback last
- Caddy console headers and CSP
- same-origin `/api/*` proxying through `BUS_UPSTREAM`
- post-deploy asset scans for live console JS

OIDC or server-cookie auth remains a production gate. `src/lib/session.ts` is only a non-production demo-session path and intentionally returns no production session.

## Trust and claim boundary

Public trust/security language is evidence-bound:

- `claim-matrix.json` is the engineering-draft claim map
- `/trust` and `/security` are conservative publication scaffolds
- `/.well-known/security.txt` publishes contact metadata
- `/subprocessors.xml` publishes the engineering-draft subprocessor change feed

Trust/security pages are engineering-draft publication scaffolding. They do not replace legal review, live deployment evidence, third-party pentest results, OIDC setup, CSP telemetry, or manual WCAG review.

## Accessibility foundation

The local static accessibility foundation is guarded by `pnpm test:a11y`. It verifies skip links, stable main-content targets, visible focus styles, reduced-motion handling, and bounded A11Y.md wording. This is a structural readiness gate only: manual WCAG evidence remains external and still requires axe/browser scans, NVDA, VoiceOver, touch-target review, and visual baselines before public conformance wording changes.

## Console state coverage

`pnpm test:state-coverage` guards the Phase 1 console state foundation from `PLAN.md`: loading, empty, error, partial-bus, stale-while-revalidating, retry-in-flight, conflicted-mutation, permission-denied, rate-limited, optimistic-pending, and expired-session. The gate verifies reusable state primitives in `src/routes/console/shared.tsx`, the `emptyMeans` taxonomy, non-production environment indicators, and package/docs wiring. This is a local static gate; full scenario/browser coverage still requires API-state fixtures and Playwright/manual runs.


## Polling hygiene

`pnpm test:polling-hygiene` guards the Phase 1 polling foundation from `PLAN.md`: live queries use a jittered 5-10s window, slower governance settings use a jittered 30-60s window, background interval refetching is disabled, and the shared `useBusHealth()` hook gates polling on document visibility with adaptive backoff after bus fetch failures. This is a local static gate; live request-volume, tab-throttling, and backend load behavior still need deployed-browser and API telemetry evidence.

## Session sync

`pnpm test:session-sync` guards the Phase 1 cross-tab demo-session foundation from `PLAN.md`: non-production sign-in/sign-out changes are broadcast through a gated `localStorage` storage-event channel, console routes subscribe through `subscribeToSessionSync()`, TanStack Router invalidates after session changes, and QueryClient retry logic re-checks `hasSession()` before retrying. This is not production auth; OIDC or server-cookie auth at the console origin remains the production gate.


## AppError boundary

`pnpm test:app-errors` guards the Phase 1 AppError boundary foundation from `PLAN.md`: console page bodies are wrapped in a path-resetting `react-error-boundary`, thrown page faults normalize through `toAppError()`, `ConsoleError` renders problem, cause, fix, and trace ID, and route files are scanned for bare `throw new Error(...)` or string throws. This is a local rendering-fault containment gate; it does not replace API scenario tests or browser error-boundary smoke coverage.



## Login interstitial

`pnpm test:login-interstitial` guards the Phase 1 login parchment handoff from `PLAN.md`: SSO provider selection renders a visible `Login interstitial` for at least 800ms, labels the operator, entered matter, and constitutional hash, and accepts Enter as a dismissal request without fake-granting console access. This is a local privilege-boundary affordance only; production admission still requires OIDC or a server-issued console session.

## Privilege banner contract

`pnpm test:privilege-banner` guards the Phase 1 privilege banner and right-rail foundation from `PLAN.md`: the console shell renders the parchment privilege boundary as a semantic region, keeps mobile drawer/backdrop z-index layers below it, exposes the right rail as a polite live receipt/status region, and rejects route-local toasts, modals, FABs, or fixed/sticky receipt overlays. This is a local static gate; Playwright intersection checks and manual responsive/browser evidence remain external.

## Wire decisions

`pnpm test:wire-decisions` guards the Phase 1 A7 route-level wire contract from `PLAN.md`: every in-scope console route has a typed entry in `src/routes/console/wire-decisions.ts`, the shell consumes that registry for crumbs/titles and a right-rail `Route contract` evidence card, and `DESIGN.md` carries the matching route-by-route appendix for header anatomy, actions, density, filters, pagination, right-rail purpose, receipt lifetime, and destructive confirmation. This is a local static gate; browser layout review and production cursor-scale behavior remain external.


## Test surface foundation

`pnpm test:test-surface` guards the Phase 2/A15 test script foundation from `PLAN.md`. It verifies that `pnpm test:e2e`, `pnpm test:e2e-http`, and `pnpm test:visual` exist as bounded local gates, that the E2E manifest names the marketing, product, login, console redirect, synthetic-session, and 13 sidebar-route smoke scope, and that the visual manifest names the five viewport baseline matrix plus the required console state/receipt targets. This is still not full browser proof: Playwright, axe, screenshot capture, and visual-diff artifacts actually run later in Phase 2.

## Buyer evidence gallery foundation

`pnpm evidence:build` writes a dependency-free local buyer-evidence gallery to
`dist-buyer-evidence/`; `pnpm test:buyer-evidence` rebuilds it in a scratch
directory and verifies the receipt proof journey, bus-owned proof source,
claim-safe trust surface, deploy-readiness boundary, package scripts, docs, and
conservative claim language. The console workflow uploads the generated gallery
as the `buyer-evidence-gallery` artifact before credentialed deploy steps so PR
reviewers can inspect the proof bundle without live domains. `pnpm
storybook:build` is currently a compatibility alias to the local gallery
builder, not an official hosted Storybook runtime. `pnpm
test:storybook-publication` verifies the gated `.github/workflows/storybook.yml`
publication scaffold for `storybook.acgs.ai`, including CNAME output and Pages
artifact/deploy wiring guarded by `STORYBOOK_PAGES_ENABLED`. The generated
artifact also carries `.nojekyll` and manifest-level `hostedProofRequirements`
so GitHub Pages publication shape is reviewable before live DNS exists.
Official Storybook runtime, live DNS/Pages proof, browser screenshots, and
axe/visual-diff evidence remain external work before stronger buyer-evidence
claims.

## E2E HTTP shell smoke

`pnpm test:e2e-http` runs `scripts/smoke-e2e-http-shells.mjs`, starts the mock Vite dev server with `VITE_USE_MOCKS=true` and `VITE_BYPASS_SESSION=true`, and fetches the marketing landing, product slugs, login handoff URL, and every in-scope console sidebar route to confirm each path returns the Vite root shell instead of an HTTP/server-error shell. This is local runtime evidence for route availability only; browser Playwright execution remains Phase 2 work before any navigation, rendering, accessibility, or screenshot claims are upgraded.

## MSW node-mode foundation

`pnpm test:msw-node` guards the MSW node-mode foundation from `PLAN.md` Phase 2. Browser mocks and future hook tests now share the same `handlers` list, `src/mocks/server.ts` exposes `setupServer(...handlers)` with `onUnhandledRequest: 'error'`, and `src/mocks/policy.ts` makes the browser worker use strict unhandled-request behavior when `VITE_EVAL_MODE=true`. This is a setup/readiness gate only: hook tests remain Phase 2 work and still need a test runner before the coverage claims can be upgraded.

## TTHW foundation

`pnpm test:tthw` guards the TTHW foundation from `PLAN.md` A4. It verifies the `hello:world` clean-runner command, the bounded `hello:world:local` HTTP shell smoke, the scheduled `.github/workflows/tthw.yml` clean-runner workflow, and the docs/security/CI references that keep the gate visible. The local command proves only that `/` and `/console` return the Vite shell under the mock dev server; headless browser proof remains external until Phase 2 Playwright first-render coverage lands.

## Performance budget

`pnpm test:performance` builds both surfaces into a temporary `.performance-check/` directory and enforces the Phase 5 gzipped JS+CSS budgets from `PLAN.md`: marketing <= 200 KB and console <= 350 KB. This is a local bundle-budget gate only; Lighthouse scores and real-user latency still require deployed-browser evidence.

## Verification surfaces

High-signal local gates:

- `pnpm test:all` for frontend lint/build/static contracts
- `pnpm build` for both artifacts plus font provenance
- `pnpm test:security` for hardening invariants
- `pnpm test:bus-schema` for bus schema ownership, generated-type drift, strict fixture, version-skew, and error-envelope checks
- `pnpm test:performance` for marketing <= 200 KB and console <= 350 KB gzipped JS+CSS budgets
- `pnpm test:state-coverage` for the console 11-state primitive and empty-state taxonomy contract
- `pnpm test:polling-hygiene` for jittered intervals, visibility-aware polling, background interval suppression, and bus-health backoff
- `pnpm test:session-sync` for cross-tab demo-session broadcast/listener wiring and retry-time `hasSession()` re-checks
- `pnpm test:app-errors` for console AppError boundary wiring and route throw hygiene
- `pnpm test:login-interstitial` for the login parchment handoff and no fake client-side console grant
- `pnpm test:privilege-banner` for privilege banner z-index protection and right-rail live-region wiring
- `pnpm test:wire-decisions` for the typed per-route console wire contract and DESIGN appendix
- `pnpm test:test-surface` for bounded `test:e2e`/`test:visual` manifest wiring before real browser proof exists
- `pnpm test:e2e-http` for local mock-dev route shell responses across marketing, product, login, and console routes
- `pnpm test:tthw` for `hello:world` / `hello:world:local` static wiring and the scheduled clean-runner TTHW workflow
- `pnpm test:msw-node` for MSW node-mode setup and eval-mode unhandled-request strictness
- `pnpm test:e2e` for the local E2E smoke manifest gate
- `pnpm test:visual` for the local visual baseline manifest gate
- `pnpm test:contract` for bus schema/proxy, Cloud Run, and auth-boundary contracts
- `pnpm audit:eval` for claim-matrix and trust-surface checks
- root `make verify` for the monorepo fan-out

Local verification does not prove live production deployment. Live proof must come from deployed domains, headers, health checks, and post-deploy scripts.
