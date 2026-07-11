<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-07-11 -->

# acgi-ai

## Purpose
This package is the single React + Vite frontend for ACGS. It builds a public marketing surface and a separately deployed privileged governance console from one source tree. The committed marketing delivery contract uses Cloudflare Workers Static Assets; the console deployment contract uses a Caddy container on Cloud Run with fail-closed server-side authorization and same-origin API proxying. It also builds a dependency-free buyer-evidence gallery for a Storybook-named GitHub Pages handoff; that gallery is not proof that the official Storybook runtime or any production origin is deployed.

## Key Files
| File | Description |
|------|-------------|
| `CLAUDE.md` | Package-local agent contract, architecture summary, commands, and design constraints. |
| `DESIGN.md` | Authoritative package-local visual system, layout, motion, and privilege-surface rules. |
| `ARCHITECTURE.md` | Current surface, route, data-flow, trust-boundary, and claim-boundary map. |
| `DEPLOY.md` | Deployment topology, supply-chain, CSP, auth, and configured-versus-deployed contract. |
| `INTEGRATING.md` | Same-origin management API and governed bus integration contract. |
| `GETTING_STARTED.md` | Exact Node/pnpm setup, local development, and verification guide. |
| `PRODUCTION-LAUNCH.md` | Conservative production evidence checklist and external-authority blockers. |
| `A11Y.md` | Accessibility requirements and current evidence boundaries. |
| `CLAIM_VALIDATION.md` | Rules for mapping product claims to implementation and test evidence. |
| `PLAN.md` | Package delivery plan; use the root roadmap for cross-project status. |
| `package.json` | Integrity-qualified pnpm selector, Node engine, scripts, and dependencies. |
| `.node-version` | Exact Node 24.18.0 toolchain version used by the frontend gates. |
| `pnpm-lock.yaml` | Locked frontend dependency graph; install with the frozen-lockfile contract. |
| `vite.config.ts` | Mode-specific marketing/console aliases, output selection, and local API proxy. |
| `vitest.config.ts` | Unit/component test configuration. |
| `playwright.config.ts` | Browser end-to-end and accessibility test configuration. |
| `claim-matrix.json` | Machine-checked public claim inventory. |
| `fonts.sha256` | Integrity manifest for self-hosted WOFF2 assets. |
| `production-authority.example.json` | Non-live template for human-owned production authority evidence. |
| `production-evidence.example.json` | Non-live template for production verification evidence. |
| `hosted-storybook-proof.example.json` | Non-live template for hosted buyer-evidence proof. |
| `storybook-runtime.plan.json` | Pending dependency-owner plan; not official Storybook runtime proof. |
| `wrangler.toml` | Older Cloudflare Pages project configuration; the configured apex workflow uses `infra/cloudflare/workers/wrangler.toml`. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `contracts/` | Versioned OpenAPI contract and fixtures for the governed bus boundary. |
| `infra/` | Cloudflare Workers Static Assets, Caddy, Docker, and Cloud Run deployment contracts (see `infra/AGENTS.md`). |
| `public/` | Static discovery files, icons, mock worker, and same-origin font assets (see `public/AGENTS.md`). |
| `scripts/` | Builds, static contract gates, renderers, smoke tests, and evidence helpers (see `scripts/AGENTS.md`). |
| `src/` | React surfaces, routes, API hooks, mocks, tokens, and styles (see `src/AGENTS.md`). |
| `tests/` | Vitest setup plus Playwright console, governance, copilot, and end-to-end suites. |

## For AI Agents

### Working In This Directory
- Read `DESIGN.md` before UI changes and read `ARCHITECTURE.md`, `INTEGRATING.md`, and `DEPLOY.md` before changing routing, API, authentication, CSP, or deployment behavior.
- Use Node 24.18.0 and the exact integrity-qualified pnpm selector in `package.json`; do not replace the Corepack proof with an unqualified package-manager install.
- Keep marketing and console as distinct Vite build surfaces. Never allow marketing assets, fixture fallbacks, analytics, or browser-held service credentials to cross into the production console trust boundary.
- Production console access must stay server-authorized and fail closed. `AUTH_UPSTREAM`, `BUS_UPSTREAM`, and authenticated runtime identity are deployment inputs, not agent- or browser-controlled defaults.
- Treat `dist/`, `dist-marketing/`, `dist-buyer-evidence/`, `node_modules/`, coverage, and Playwright reports as generated output. Change their source or generator instead.
- Regenerate `src/api/bus.generated.ts` from `contracts/bus.openapi.json` with `pnpm gen:api`; do not hand-edit the generated client.
- Root workflows are deliberately split: `console.yml`, `marketing.yml`, and `storybook.yml` are pull-request verification only; `console-deploy.yml`, `marketing-cloudflare.yml`, and `storybook-deploy.yml` are push-only deployment workflows. Do not recombine verification and production authority.
- The production deploy workflows require exact-commit environment authorization before credentialed jobs. Committed workflow/configuration state is not evidence of DNS, credentials, a successful deploy, or a live production control.
- Do not create AGENTS.md files in generated or tool-state directories unless explicitly requested.

### Testing Requirements
- Run package commands under Node 24.18.0. From the repository root, `make verify-js-node24` is the authoritative exact-Node frontend gate.
- Run `pnpm lint`, `pnpm build`, `pnpm test:all`, and `pnpm test:unit` for package-wide changes.
- Run `pnpm test:playwright` for user journeys, routing, session, accessibility, or browser-state changes.
- Run `pnpm test:surfaces` after changes to the marketing/console split and `pnpm test:auth-boundary` after changes to login, session, Caddy auth, or production gating.
- Run `pnpm test:bus-schema`, `pnpm test:bus-proxy`, `pnpm test:cloudrun-templates`, and `pnpm test:cloudrun-renderer` after API, proxy, renderer, Cloud Run, or console workflow changes.
- Run `pnpm test:marketing-csp` and `pnpm test:marketing-routes` after Cloudflare header, redirect, Worker, route, or marketing-origin changes.
- Run `pnpm test:production-deploy-contract`, `pnpm test:production-launch-handoff`, `pnpm test:storybook-publication`, and `pnpm test:ci-gates` after root workflow or production-handoff changes.
- Run `pnpm test:font-manifest`, `pnpm test:claim-matrix`, `pnpm test:trust-surface`, or `pnpm test:docs-scaffold` when their named assets, claims, trust pages, or package guides change.
- When Docker is available, run `pnpm build:console && pnpm smoke:bus-proxy` after changing Caddy, container, auth, or bus-proxy behavior.

### Common Patterns
- `src/main.tsx` imports `@surface/App`; `vite.config.ts` resolves that alias to the marketing or console application for the active mode.
- `pnpm build` leaves the console artifact in `dist/` and the marketing artifact in `dist-marketing/`; deployment workflows rebuild the one artifact they publish.
- TanStack Router owns each surface route tree. React Query hooks use the same-origin API client, and fixture fallback is opt-in for non-production development only.
- Console routes and `/auth/status` pass through Caddy `forward_auth`; `/api/*` passes through the fail-closed governed bus proxy before any SPA fallback.
- Marketing deep links are explicit Workers Static Assets rewrites. Unknown paths remain real 404s, while `/console` routes redirect to the privileged origin.
- Design tokens live in `src/index.css`; component layout lives in `src/App.css`; CSP-safe utility classes live in `src/csp-utilities.css`. Inline styles and hardcoded hex values outside `src/index.css` are forbidden.

## Dependencies

### Internal
- The repository-root `.github/workflows/{console,marketing,storybook}.yml` files verify pull requests without production authority.
- The repository-root `.github/workflows/console-deploy.yml`, `marketing-cloudflare.yml`, and `storybook-deploy.yml` independently verify pushed commits before authorized publication.
- `contracts/` supplies generated API types consumed by `src/api/`; `public/` supplies same-origin assets; `infra/` serves and deploys the build artifacts.
- The root gove-zone/control-plane services own governed runtime behavior; this package consumes their versioned same-origin contracts rather than implementing a second authorization path.

### External
- React 19, React DOM, TanStack Router, and React Query for the application runtime.
- Vite 8 and TypeScript 6 for strict, mode-specific builds.
- Vitest, Testing Library, Playwright, axe, and MSW for unit, browser, accessibility, and non-production fixture testing.
- Biome for the package lint/format gate.
- Caddy, Docker, Google Cloud Run, Cloudflare Workers Static Assets, GitHub Pages, and GitHub Actions for the configured delivery paths.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
