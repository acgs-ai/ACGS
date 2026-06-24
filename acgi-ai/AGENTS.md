<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-05-04 -->

# acgi-ai

## Purpose
This repository is a React + Vite application that ships the ACGS marketing landing page and the governance console from one bundle. The public marketing surface lives at `/`; the privileged console lives under `/console/*` and is designed around a structural privilege boundary, same-origin fonts, fixture-backed console data until the API client lands, a same-origin fail-closed `/api/*` bus proxy, and deployment separation between the marketing and console origins.

## Key Files
| File | Description |
|------|-------------|
| `CLAUDE.md` | Project-specific agent contract, architecture notes, commands, and design constraints. |
| `DESIGN.md` | Project-local design system for typography, tokens, layout, motion, and surface behavior. |
| `DEPLOY.md` | Deployment topology and security-header contract for marketing and console origins. |
| `ARCHITECTURE.md` | Current routing, build-surface, data-flow, privilege-boundary, and claim-boundary map. |
| `INTEGRATING.md` | Same-origin API and governed bus integration contract for console authors. |
| `GETTING_STARTED.md` | Fresh-checkout onboarding and verification guide. |
| `README.md` | Default Vite README; not the authoritative project guide. Prefer `CLAUDE.md`, `DESIGN.md`, and `DEPLOY.md`. |
| `package.json` | pnpm scripts, pinned package manager, dependencies, and dev dependencies. |
| `pnpm-lock.yaml` | Locked pnpm dependency graph. |
| `index.html` | Vite HTML entry document with the root mount node and app title. |
| `vite.config.ts` | Vite config for React, Tailwind plugin availability, `@/*` alias, and `/api` dev proxy. |
| `tsconfig.json` | Root TypeScript project references and `@/*` alias. |
| `tsconfig.app.json` | Strict browser app TypeScript settings and `src` include. |
| `tsconfig.node.json` | TypeScript settings for Node-side config files. |
| `biome.json` | Primary formatting and lint configuration used by `pnpm lint` and `pnpm format`. |
| `eslint.config.js` | Secondary ESLint config for React refresh rules; not wired to an npm script. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `.github/` | GitHub Actions workflows for marketing and console deployment (see `.github/AGENTS.md`). |
| `infra/` | Console-origin container, Caddy, and Cloud Run configuration (see `infra/AGENTS.md`). |
| `public/` | Public static assets, MSW worker, icons, and self-hosted fonts (see `public/AGENTS.md`). |
| `src/` | React application source, styling, API hooks, mocks, and routes (see `src/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- Read `DESIGN.md` before any visual or UI change and `DEPLOY.md` before deployment, CSP, font, or hosting changes.
- Keep the app as two Vite build surfaces from one source tree unless a task explicitly changes that architecture.
- Do not add Tailwind utility classes in JSX; use project CSS classes and custom properties.
- Do not add inline `style={{}}`; the console CSP forbids inline styles.
- Keep hardcoded hex literals confined to `src/index.css`.
- Do not create AGENTS.md files for generated or tool-state directories such as `node_modules/`, `dist/`, `.omc/`, `.omx/`, `.remember/`, or `.gstack/` unless explicitly requested.

### Testing Requirements
- Run `pnpm lint` for source, config, and workflow-adjacent changes covered by Biome.
- Run `pnpm build` after source, dependency, TypeScript, Vite, or surface-routing changes; it leaves console in `dist/` and marketing in `dist-marketing/`.
- Run `pnpm test:surfaces` when changing the marketing/console bundle split.
- Run `pnpm test:bus-proxy` after Caddy, Cloud Run, or console workflow bus proxy changes.
- Run `pnpm test:auth-boundary` after changing `src/lib/session.ts`, login/session behavior, or production auth gating.
- Run `pnpm test:font-manifest` after adding, deleting, renaming, or replacing files under `public/static/fonts/` or editing `src/fonts.css`.
- Run `pnpm test:postdeploy-live-assets` after changing `scripts/postdeploy-verify.sh`, console production asset loading, or demo-auth sentinel checks.
- Run `pnpm test:claim-matrix` after changing public compliance/security copy, `claim-matrix.json`, or claim-review wording.
- Run `pnpm test:trust-surface` after changing `/trust`, `/security`, `security.txt`, subprocessor RSS, DPA/SOC2 roadmap wording, or trust/security publication links.
- Run `pnpm test:docs-scaffold` after changing `ARCHITECTURE.md`, `INTEGRATING.md`, `GETTING_STARTED.md`, `CLAUDE.md`, `AGENTS.md`, or DX script aliases.
- Run `pnpm test:marketing-csp` after changing `infra/cloudflare/_headers`, marketing-origin headers, or CSP report-only policy.
- Run `pnpm build:console && pnpm smoke:bus-proxy` when Docker is available and `/api/*` runtime proxy behavior changes.
- There is no configured test runner; use existing scripts only.

### Common Patterns
- `src/main.tsx` imports `@surface/App`; `vite.config.ts` aliases that module to `src/surfaces/marketing/App.tsx` or `src/surfaces/console/App.tsx`.
- `src/lib/navigate.ts` pushes history and dispatches `popstate` inside the active surface.
- Console data flows through `src/api/hooks.ts` and `src/api/client.ts`; MSW fixtures mirror those contracts.
- Console `/api/*` requests terminate at Caddy and reverse-proxy to `BUS_UPSTREAM` with `X-ACGS-Schema-Version`.
- `src/lib/session.ts` is a non-production demo escape hatch only; production auth must be OIDC/server-cookie backed and `hasSession()` must remain fail-closed until that layer exists.
- Design tokens live in `src/index.css`; component layout lives in `src/App.css`; CSP-safe utilities live in `src/csp-utilities.css`.

## Dependencies

### Internal
- `src/` implements both runtime surfaces and consumes `public/static/fonts/`.
- `infra/` serves the built `dist/` output and enforces console-origin CSP and headers.
- `.github/workflows/` runs lint, build, image, and deploy automation.

### External
- React 19 and React DOM for UI rendering.
- Vite 8 and TypeScript 6 for bundling and strict type checking.
- TanStack React Router for surface route trees and React Query for API hook caching.
- MSW for optional local API mocks.
- Biome for linting and formatting.
- Caddy, Docker, Cloud Run, Cloudflare Pages, and GitHub Actions for deployment.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
