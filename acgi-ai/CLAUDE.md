# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# acgi-ai

React + Vite app that ships the ACGS marketing landing and governance console
as two Vite build surfaces. Public marketing and privileged console share one
design system, same-origin API client contracts, non-production fixture fallback,
and a fail-closed Caddy `/api/*` bus proxy for deployment readiness.

## Design System

**Always read `DESIGN.md` before making any visual or UI decision.** It is the
single source for fonts, colours, spacing, layout, motion, components, and
surface mappings. Do not deviate without explicit user approval.

For architecture, bus integration, deployment, hosting topology, headers/CSP,
and the network-layer expression of the privilege boundary, read
`ARCHITECTURE.md`, `INTEGRATING.md`, and `DEPLOY.md`. `DESIGN.md` is the visual
contract above the wire; `DEPLOY.md` is the deployment contract below it.

`DESIGN.md` is downstream of the canonical
`/home/martin/Downloads/govern-zone/ACGS/DESIGN.md`. When the two disagree,
the canonical wins for tokens; this file wins for project-local React surface
mappings (routing, build, file layout). Runtime references like
"DESIGN.md §X.Y" mean the project-local file.

In QA mode, flag any code that doesn't match `DESIGN.md`.

## Stack

- Vite 8, React 19.2, TypeScript 6 (strict; `noUnusedLocals`, `noUnusedParameters`,
  `verbatimModuleSyntax`, `erasableSyntaxOnly` all on)
- Pure CSS with custom properties (no Tailwind utility classes in JSX, even
  though `@tailwindcss/vite` is wired and `tailwind-merge`/`clsx` exist via
  `src/lib/utils.ts`)
- Biome for lint + format (primary). ESLint config exists for
  `react-refresh/only-export-components` but is **not wired to an npm script**;
  CI/dev gates run through `pnpm lint`
- TanStack Router + React Query are wired for route matching and API cache boundaries
- Path alias: `@/*` → `src/*` (set in both `tsconfig` and `vite.config.ts`)

## Commands

```bash
pnpm dev            # vite — http://localhost:5173 (or 5174 if 5173 taken)
pnpm dev:mock       # vite with VITE_USE_MOCKS=true
pnpm dev:live       # vite with VITE_USE_MOCKS=false
pnpm hello          # fast DX scaffold smoke
pnpm build          # build console dist/ plus marketing dist-marketing/
pnpm build:console  # tsc -b && vite build --mode console
pnpm build:marketing # tsc -b && vite build --mode marketing
pnpm lint           # biome check (explicit file list — see package.json)
pnpm test:security  # static hardening invariant checks
pnpm test:surfaces  # builds both surfaces and verifies bundle split
pnpm test:bus-proxy # static /api proxy + Cloud Run + workflow contract check
pnpm test:cloudrun-templates # preview/staging/production service template contract
pnpm test:auth-boundary # production bundle excludes demo sessionStorage auth
pnpm test:font-manifest # verifies self-hosted WOFF2 hashes and css refs
pnpm test:postdeploy-live-assets # synthetic live-asset scan for postdeploy auth sentinels
pnpm test:claim-matrix # verifies public claim matrix and overclaim guard
pnpm test:trust-surface # verifies /trust, /security, security.txt, and subprocessor RSS
pnpm test:docs-scaffold # verifies ARCHITECTURE/INTEGRATING/GETTING_STARTED and script wiring
pnpm test:contract # bus proxy + Cloud Run template + auth-boundary contracts
pnpm audit:eval    # claim matrix + trust surface checks
pnpm test:marketing-csp # verifies Cloudflare report-only marketing CSP
pnpm smoke:bus-proxy # Docker-backed Caddy smoke against a local stub bus
pnpm test:all       # lint + console build + security/MVP/font/surface/bus/deploy/auth/live-asset/claim/trust/docs/CSP gates
pnpm format         # biome format --write
pnpm preview        # serve dist/ locally
```

There is no full test runner configured. `lint`, `test:security`, `test:all`,
`build`, and a manual browser pass must be clean before declaring UI work
complete.

## Architecture

**Two build surfaces, TanStack Router.** `src/main.tsx` imports `@surface/App`;
`vite.config.ts` aliases that module to the marketing or console surface for
the active mode. Each surface defines a TanStack Router route tree and delegates to
route components:

- `src/surfaces/marketing/App.tsx` — `/`, `/privacy`, `/trust`, `/security`,
  `/products`, and `/products/<slug>`, with privileged paths redirecting to the
  console origin.
- `src/surfaces/console/App.tsx` — `/login`, `/console`, and `/console/*`.
- `src/routes/Marketing.tsx` — `/` editorial landing. All copy lives in
  module-level `capabilities`, `coverage`, `tiers` arrays where possible.
- `src/routes/Console.tsx` — `/console/*` shell. Owns the 3-column grid,
  sidebar, **structural** privilege banner, topbar, right rail. Dispatches to
  one of nine page bodies in `src/routes/console/` based on `path` prop:
  `Overview`, `Agents`, `Maci`, `Deliberations`, `Incidents` (Operate);
  `Policies`, `Compile`, `Audit`, `Settings` (Govern). Each page title
  carries exactly one italic-rust word (DESIGN.md §2.2). The topbar
  "Compile constitution" button navigates to `/console/compile`.

**Routing.** The active surface app owns a TanStack Router route tree.
`navigate(to)` remains the same-surface bridge for existing buttons: it does
`pushState` + dispatches a synthetic `popstate`, which the router observes.
Console routes validate `/login?next=`, guard `/console/*`, and keep route objects
ready for loaders, nested layouts, and route-level error boundaries (DESIGN.md §7.3).

**Styling.** Pure CSS with custom properties. Tokens declared once in
`src/index.css`; component CSS lives in `src/App.css`; CSP-safe utilities and
component-scoped one-offs in `src/csp-utilities.css`. Hardcoded hex outside
`src/index.css` is banned. **Inline `style={{}}` is forbidden** — strict CSP
on the console (`style-src 'self'`, no `'unsafe-inline'`) blocks both `<style>`
tags and `style="..."` attributes (DEPLOY.md §5). Use an existing utility
(`u-*`) or add a component-scoped class.

**Data.** `src/api/client.ts` is the same-origin API client; `src/api/hooks.ts`
uses React Query and dynamic fixture fallback only when `VITE_USE_MOCKS=true`
outside production. Contract types live in `src/api/types.ts`; bus analyzer
types come from `src/api/bus.generated.ts`. Production must fail closed without
the governed bus and real auth.

## Privilege boundary

The parchment banner across the top of every console page is **structural**
(DESIGN.md §4.3). Never animate it, hide it with `aria-hidden`, gate it on a
feature flag, or move it below the fold. The wording is fixed copy modulo
legal review.

## Fonts

Self-hosted WOFF2 subsets (latin + latin-ext) under `public/static/fonts/`,
declared in `src/fonts.css`, served at `/static/fonts/*.woff2` by the Caddy
`@fonts` matcher in `infra/Caddyfile`. Both surfaces use the same self-hosted font set so
the privilege story is uniform — the console origin must never fetch fonts
from a third-party CDN, since matter/session IDs in `/console/*` URLs would
leak via `Referer` (DESIGN.md §7.1, DEPLOY.md §3 / §6).

Latin loads first; latin-ext is deferred via `unicode-range` and only
fetched when extended-Latin glyphs are present.

The fallback stack falls through to named families (`Helvetica Neue`, `Arial`,
`Georgia`), never `system-ui` — that would silently swap brand voice per OS.

## What not to add

- Purple / violet / indigo gradients
- Centred hero compositions (except the `/ask` surface — see DESIGN.md "Ask surface carve-out")
- 3-column icon-in-circle feature grids
- Generic SaaS stock photography
- Tailwind utility classes in JSX (the build accepts them; the design
  contract refuses them)
- Hardcoded hex literals outside `src/index.css`
- `system-ui` as a typography fallback
- Animations or `aria-hidden` on the privilege banner

The two `!important` declarations in the `prefers-reduced-motion` reset in
`src/index.css` carry `biome-ignore` comments — they are spec-mandated
(DESIGN.md §2.5) and must remain.

## Deploy configuration

The deployment contract is defined by `DEPLOY.md` and six workflows under the
repository-root `.github/workflows/` directory. GitHub Actions does not discover
workflows under `acgi-ai/.github/`. The package remains a two-surface web app;
marketing and the privileged console have different origins and deployment
authority.

### Verification and deployment are physically separated

Pull requests run only the read-only verification workflows:

- `.github/workflows/marketing.yml`
- `.github/workflows/console.yml`
- `.github/workflows/storybook.yml`

Those workflows may build and upload review artifacts, but they must not read
deployment secrets, request OIDC/Pages write authority, or perform a deploy.
Production mutations exist only in the push-to-`master` workflows:

- `.github/workflows/marketing-cloudflare.yml`
- `.github/workflows/console-deploy.yml`
- `.github/workflows/storybook-deploy.yml`

Each push workflow reverifies the pushed commit before authorization. Its
credentialed job remains unreachable unless the target environment contains an
exact 40-lowercase-hex match for that commit:

- `MARKETING_PRODUCTION_APPROVED_SHA` on the `production` environment;
- `CONSOLE_PRODUCTION_APPROVED_SHA` on the `production` environment;
- `STORYBOOK_PRODUCTION_APPROVED_SHA` on the `github-pages` environment.

Missing, malformed, stale, or different values skip the side-effectful job;
they are not a bypass. All `uses:` references remain immutable 40-hex commit
SHA pins. CI uses exact Node 24.18.0 and the integrity-qualified pnpm 9.15.4
selector through an isolated Corepack activation.

### Marketing surface (Cloudflare Workers Static Assets)

- **Committed target:** Cloudflare Worker `acgs-governance-proxy` with Workers
  Static Assets, configured by `infra/cloudflare/workers/wrangler.toml`.
- **Routes:** the config owns exactly `acgs.ai/*`, `www.acgs.ai/*`,
  `console.acgs.ai/*`, and `api.acgs.ai/telegram/*`; removing the routes block
  can detach the live zone routes.
- **Verification:** `.github/workflows/marketing.yml` is pull-request only.
- **Deployment:** `.github/workflows/marketing-cloudflare.yml` is push only,
  requires exact-commit authorization, and uses the locked Wrangler CLI.
- **External blockers:** the protected `production` environment, required
  reviewers, `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, DNS, and a live
  post-deploy verification artifact are owner-controlled and not proved by the
  repository.

The older Cloudflare Pages project/configuration is a shadow compatibility
surface, not the committed marketing deployment target. GitHub Pages is used
only for the separately privileged buyer-evidence publication below.

### Console surface (Cloud Run + Caddy)

- **Committed target:** Google Cloud Run with `infra/Dockerfile.console`,
  `infra/Caddyfile`, and per-environment templates under `infra/cloudrun/`.
- **Verification:** `.github/workflows/console.yml` is pull-request only.
- **Deployment:** `.github/workflows/console-deploy.yml` is push only and owns
  image publication plus the rendered Cloud Run deployment.
- **Identity:** Google Workload Identity Federation; do not add a long-lived
  service-account JSON key.
- **External blockers:** the protected `production` environment, required
  reviewers, `GCP_PROJECT_ID`, `GCP_REGION`,
  `GCP_WORKLOAD_IDENTITY_PROVIDER`, `GCP_SERVICE_ACCOUNT`,
  `GCP_ARTIFACT_REGISTRY`, `CONSOLE_AUTH_UPSTREAM`, `CONSOLE_BUS_UPSTREAM`,
  DNS, and live `/healthz` evidence remain owner-controlled.
- **Fail-closed boundary:** the renderer requires both authenticated upstreams;
  Caddy must not serve privileged console routes or `/api/*` through fixture or
  demo fallbacks in production.

### Buyer-evidence publication (GitHub Pages)

- `.github/workflows/storybook.yml` verifies the claim-safe gallery on pull
  requests without Pages/OIDC authority.
- `.github/workflows/storybook-deploy.yml` is the only Pages publication path;
  its deploy job is gated by exact-commit authorization and the protected
  `github-pages` environment.
- The gallery is not proof that the official Storybook runtime is installed,
  hosted, or reviewed in a live browser.

### Evidence boundary and operator checks

Configured workflow and infrastructure files are not live deployment evidence.
Do not claim a production deploy from repository state, a green local gate, DNS
history, or the presence of environment-variable names. External environment protection
and owner-controlled credentials remain blockers; domains and runtime health
must be verified by an authorized operator and captured in the production
evidence manifest.

Before handoff, run:

```bash
pnpm lint
pnpm build
pnpm test:all
pnpm test:production-deploy-contract
pnpm test:ci-gates
```

For Caddy, Cloud Run, or proxy changes, also run
`pnpm build:console && pnpm smoke:bus-proxy` when Docker is available. Only
after an authorized deploy may an operator use `gh run list`, Cloudflare/gcloud
status commands, and `scripts/postdeploy-verify.sh` as live evidence.

Container/toolchain pinning is enforced by `pnpm test:container-pins`:
`.node-version` is exact Node 24.18.0, `packageManager` integrity-pins pnpm
9.15.4, the console build uses `node:24-alpine`, and the runtime uses
`caddy:2.10.2-alpine`.
