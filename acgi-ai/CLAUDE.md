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
pnpm test:marketing-csp # verifies Vercel report-only marketing CSP
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
- Centred hero compositions
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

## Deploy Configuration (configured by /setup-deploy 2026-05-06)

Two-origin topology per `DEPLOY.md`. Workflows live at **repo-root**
`.github/workflows/{console,marketing}.yml` (NOT under `acgi-ai/.github/`).
GitHub Actions only discovers workflows from the repo root; the workflows
were originally placed under `acgi-ai/.github/workflows/` and silently never
ran (verified by `gh run list` showing zero runs). They were moved to the
root in this PR. The acgi-ai app is in a subdirectory, so each workflow
sets `defaults.run.working-directory: acgi-ai` and prefixes path filters
(e.g. `acgi-ai/src/**`) so commands run in the subdirectory while GitHub's
file-change detection works at repo-root scope.

Production domains are pending DNS/ACME provisioning per `PLAN.md §5.6`
(formerly Phase 5, now Phase 6 after the /autoplan reorder).

### Marketing surface (Vercel)

- **Platform:** Vercel
- **Production URL:** `https://acgs.ai` (pending DNS — staging URL is the Vercel preview from `vercel ls --prod`)
- **Deploy workflow:** repo-root `.github/workflows/marketing.yml`
- **Deploy trigger:** auto on push to `master`; preview on PR
- **Required secrets:** `VERCEL_TOKEN`, `VERCEL_ORG_ID`, `VERCEL_PROJECT_ID`
- **Deploy status command:** `vercel ls --prod | head -3` (run from `acgi-ai/`)
- **Health check URL:** the production URL (200 OK on `/`)

### Console surface (Cloud Run + Caddy)

- **Platform:** Google Cloud Run (Caddy container per `infra/Dockerfile.console` + `infra/cloudrun/service.yaml`, both under `acgi-ai/`)
- **Production URL:** `https://console.acgs.ai` (pending DNS — staging URL is the auto-generated `*.run.app`)
- **Deploy workflow:** repo-root `.github/workflows/console.yml` (docker build context: `acgi-ai/`, file: `acgi-ai/infra/Dockerfile.console`)
- **Deploy trigger:** image build on PR; deploy on push to `master`
- **Auth:** Workload Identity Federation (no service-account JSON in secrets)
- **Required secrets:** `GCP_PROJECT_ID`, `GCP_REGION`, `GCP_WORKLOAD_IDENTITY_PROVIDER`, `GCP_SERVICE_ACCOUNT`, `GCP_ARTIFACT_REGISTRY`, `CONSOLE_BUS_UPSTREAM`
- **Deploy status command:** `gcloud run services describe acgi-console --region=$GCP_REGION --project=$GCP_PROJECT_ID --format='value(status.url,status.latestReadyRevisionName)'`
- **Health check URL:** `${PRODUCTION_URL}/healthz` returning `{ ok, served_hash, build_id }` per `DEPLOY.md §10`
- **Bus proxy contract:** Cloud Run renders `BUS_UPSTREAM` from `CONSOLE_BUS_UPSTREAM`; Caddy proxies `/api/*` to it and forwards/echoes `X-ACGS-Schema-Version`.

### Project type

Web app (two surfaces). Not a CLI / library. Merge method: **squash** (matches the recent PR history pattern).

### Custom deploy hooks

- **Pre-merge:** `pnpm lint && pnpm build:console && pnpm build:marketing && pnpm test:all`
- **Infra smoke:** `pnpm build:console && pnpm smoke:bus-proxy` after Caddy, Cloud Run, or bus proxy changes when Docker is available
- **Deploy trigger:** automatic on push to `master`
- **Deploy status:** the platform CLI commands above; or `gh run list -w marketing -L 1` / `gh run list -w console -L 1`
- **Health check:** Curl `${PRODUCTION_URL}/healthz` for console (returns 200 + JSON), curl `${PRODUCTION_URL}` for marketing (returns 200)

### Known gaps (per `PLAN.md §13` /autoplan review)

These are not blockers for `/land-and-deploy` once URLs land, but they're CI/CD hygiene the Phase 0 PR series will address:

- Action versions are unpinned (`@vN` not `@vN.M.P`) — see plan A12
- Vercel CLI is `vercel@latest` — see plan A12
- Container image/toolchain pinning is now enforced by `pnpm test:container-pins`: `.node-version`, Node `>=24 <25`, `pnpm@9.15.4`, `node:24-alpine`, `caddy:2.10.2-alpine`, and Docker smoke image parity stay aligned.
- Cloud Run `service.yaml` has `minScale: "0"` for all envs (production should be 1+ per plan A14)

`/land-and-deploy` works without these fixes; they improve safety, not correctness.
