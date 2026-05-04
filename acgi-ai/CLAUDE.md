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
pnpm format         # biome format --write
pnpm preview        # serve dist/ locally
```

There is no test runner configured. All three of `lint`, `build`, and a manual
browser pass must be clean before declaring work complete.

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
`src/index.css`; component CSS lives in `src/App.css`. Hardcoded hex outside
`src/index.css` is banned. Inline `style={{}}` is allowed only for one-off
flexbox alignments and must reference `var(--*)` for any colour or font.

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
