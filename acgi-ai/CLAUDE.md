# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# acgi-ai

React + Vite app that ships the ACGS marketing landing and governance console
as a single bundle. Two surfaces (`/` marketing, `/console/*` runtime), one
design system, no backend wiring yet.

## Design System

**Always read `DESIGN.md` before making any visual or UI decision.** It is the
single source for fonts, colours, spacing, layout, motion, components, and
surface mappings. Do not deviate without explicit user approval.

For deployment, hosting topology, headers/CSP, and the network-layer
expression of the privilege boundary, read `DEPLOY.md`. It pairs with
`DESIGN.md` — visual contract above the wire, deployment contract below it.

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
- TanStack Router + React Query are in deps but **not yet wired** — see
  DESIGN.md §7.3
- Path alias: `@/*` → `src/*` (set in both `tsconfig` and `vite.config.ts`)

## Commands

```bash
pnpm dev            # vite — http://localhost:5173 (or 5174 if 5173 taken)
pnpm build          # tsc -b && vite build
pnpm lint           # biome check (explicit file list — see package.json)
pnpm test:security  # static hardening invariant checks
pnpm test:all       # lint + build + security invariants
pnpm format         # biome format --write
pnpm preview        # serve dist/ locally
```

There is no full test runner configured. `lint`, `test:security`, `build`, and
a manual browser pass must be clean before declaring UI work complete.

## Architecture

**Single bundle, two surfaces, custom router.** `src/main.tsx` boots `<App />`,
which reads `window.location.pathname` and delegates to one of two top-level
components:

- `src/routes/Marketing.tsx` — `/` editorial landing. All copy lives in
  module-level `capabilities`, `coverage`, `tiers` arrays. Edit those, not the
  JSX.
- `src/routes/Console.tsx` — `/console/*` shell. Owns the 3-column grid,
  sidebar, **structural** privilege banner, topbar, right rail. Dispatches to
  one of nine page bodies in `src/routes/console/` based on `path` prop:
  `Overview`, `Agents`, `Maci`, `Deliberations`, `Incidents` (Operate);
  `Policies`, `Compile`, `Audit`, `Settings` (Govern). Each page title
  carries exactly one italic-rust word (DESIGN.md §2.2). The topbar
  "Compile constitution" button navigates to `/console/compile`.

**Routing.** `src/App.tsx` (24 lines) + `src/lib/navigate.ts` (7 lines).
`navigate(to)` does `pushState` + dispatches a synthetic `popstate` so the
`useState`/`popstate` listener in `App.tsx` rerenders. Migrate to TanStack
Router when data loaders or nested layouts are needed (DESIGN.md §7.3).

**Styling.** Pure CSS with custom properties. Tokens declared once in
`src/index.css`; component CSS lives in `src/App.css`; CSP-safe utilities and
component-scoped one-offs in `src/csp-utilities.css`. Hardcoded hex outside
`src/index.css` is banned. **Inline `style={{}}` is forbidden** — strict CSP
on the console (`style-src 'self'`, no `'unsafe-inline'`) blocks both `<style>`
tags and `style="..."` attributes (DEPLOY.md §5). Use an existing utility
(`u-*`) or add a component-scoped class.

**Data.** Every list, table, and queue renders module-level fixture data.
There is no API client, no auth, no persistence. When real data lands it must
reuse `src/core/shared/` from the ACGS monorepo (DESIGN.md §7.5).

## Privilege boundary

The parchment banner across the top of every console page is **structural**
(DESIGN.md §4.3). Never animate it, hide it with `aria-hidden`, gate it on a
feature flag, or move it below the fold. The wording is fixed copy modulo
legal review.

## Fonts

Self-hosted WOFF2 subsets (latin + latin-ext) under `public/static/fonts/`,
declared in `src/fonts.css`, served at `/static/fonts/*.woff2` by the Caddy
`@fonts` matcher in `infra/Caddyfile`. Both surfaces use the same bundle so
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
- **Required secrets:** `GCP_PROJECT_ID`, `GCP_REGION`, `GCP_WORKLOAD_IDENTITY_PROVIDER`, `GCP_SERVICE_ACCOUNT`, `GCP_ARTIFACT_REGISTRY`
- **Deploy status command:** `gcloud run services describe acgi-console --region=$GCP_REGION --project=$GCP_PROJECT_ID --format='value(status.url,status.latestReadyRevisionName)'`
- **Health check URL:** `${PRODUCTION_URL}/healthz` returning `{ ok, served_hash, build_id }` per `DEPLOY.md §10`

### Project type

Web app (two surfaces). Not a CLI / library. Merge method: **squash** (matches the recent PR history pattern).

### Custom deploy hooks

- **Pre-merge:** `pnpm lint && pnpm build && pnpm test:all`
- **Deploy trigger:** automatic on push to `master`
- **Deploy status:** the platform CLI commands above; or `gh run list -w marketing -L 1` / `gh run list -w console -L 1`
- **Health check:** Curl `${PRODUCTION_URL}/healthz` for console (returns 200 + JSON), curl `${PRODUCTION_URL}` for marketing (returns 200)

### Known gaps (per `PLAN.md §13` /autoplan review)

These are not blockers for `/land-and-deploy` once URLs land, but they're CI/CD hygiene the Phase 0 PR series will address:

- Action versions are unpinned (`@vN` not `@vN.M.P`) — see plan A12
- Vercel CLI is `vercel@latest` — see plan A12
- Docker base images are `node:20-alpine` (should be 24) and `caddy:2-alpine` (floating) — see plan A12
- Marketing CSP `Content-Security-Policy-Report-Only` header is missing from `vercel.json` — see plan A11
- Cloud Run `service.yaml` has `minScale: "0"` for all envs (production should be 1+ per plan A14)
- Font hash manifest (`fonts.sha256`) not yet committed — see plan A12

`/land-and-deploy` works without these fixes; they improve safety, not correctness.
