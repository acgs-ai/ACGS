# Getting started with acgi-ai

This guide is for a fresh local checkout of the frontend package inside the govern-zone monorepo.

## Prerequisites

- Node >=24 <25 for CI/deploy parity
- pnpm 9.15.4 from `packageManager`
- Python and uv only when running the root monorepo gates
- Docker only when running the optional Caddy bus-proxy smoke

For local deploy-readiness parity from the monorepo root, run
`make verify-js-node24`. It uses the existing `fnm` installation plus
`acgi-ai/.node-version`, verifies Node 24 and pnpm 9.15.4, then runs
`pnpm -F acgi-ai run test:all`. This is the preferred local gate when the
shell-default `node` is older and would otherwise emit engine warnings.

## First commands

```bash
pnpm install
pnpm -F acgi-ai run hello
make verify-js-node24  # from repo root, exact Node 24 frontend gate
pnpm -F acgi-ai run test:all
pnpm -F acgi-ai build
make verify
```

`pnpm -F acgi-ai run hello` checks that the local DX documents and high-signal scripts are present. `make verify-js-node24` runs the frontend lint/build/static contract gate under Node 24. `pnpm -F acgi-ai run test:all` is the direct package command if your shell is already on Node 24. `make verify` runs the root monorepo verification fan-out.

## TTHW foundation

```bash
pnpm -F acgi-ai run test:tthw
pnpm -F acgi-ai run hello:world:local
```

`test:tthw` is the static contract for the time-to-hello-world foundation. `hello:world:local` skips install, allows local Node drift, starts the mock dev server, and proves only the `/` and `/console` HTTP shells return the Vite root. The clean-runner measurement is `.github/workflows/tthw.yml` running `acgi-ai/scripts/hello-world.sh` on Node 24 with a 300-second budget. This is not production deployment evidence, and headless browser proof remains external until the Phase 2 Playwright gate runs.

## Local route smoke

```bash
pnpm -F acgi-ai run test:e2e-http
```

`test:e2e-http` starts the mock Vite dev server and fetches the marketing landing, product slugs including `/products/gove-zone`, login handoff URL, and every in-scope console sidebar path. It proves those paths return the Vite root shell locally; it does not replace Playwright navigation, axe, screenshot, or deployed-browser evidence.

## Local browser workbench evidence

```bash
pnpm -F acgi-ai run test:browser-evidence
pnpm -F acgi-ai run evidence:browser-workbench
```

`test:browser-evidence` verifies the browser-evidence command and a dry-run
manifest. `evidence:browser-workbench` starts the mock Vite server and uses a
local Chrome/Chromium binary to capture screenshots for the marketing
workbench, `/console/workbench`, and `/console/workbench#launch-proof-ladder`
at the five visual baseline viewports. It writes local browser evidence under
`acgi-ai/dist-browser-evidence/`; this is not production deployment proof, not
hosted Storybook proof, not WCAG conformance proof, and not legal/security
assurance.

## Buyer evidence gallery

```bash
pnpm -F acgi-ai run evidence:build
pnpm -F acgi-ai run test:buyer-evidence
pnpm -F acgi-ai run test:storybook-publication
```

`evidence:build` creates a dependency-free local buyer-evidence gallery at
`acgi-ai/dist-buyer-evidence/`. `test:buyer-evidence` verifies that the
artifact covers the receipt proof journey, bus-owned proof source, claim-safe
trust surface, visual governance workbench, and deploy-readiness boundary
without unsupported production claims. Console CI uploads the same gallery as the `buyer-evidence-gallery`
artifact before credentialed deploy steps. `storybook:build` is a local
compatibility alias for this gallery. `test:storybook-publication` verifies the
gated Pages scaffold that can publish the claim-safe artifact to
`storybook.acgs.ai` when `STORYBOOK_PAGES_ENABLED` is set. The artifact includes
Pages publication files (`CNAME` when a custom domain is supplied and
`.nojekyll`) plus manifest-level `hostedProofRequirements`, but official
Storybook runtime and live browser/axe/visual proof remain external.

## Local development modes

```bash
pnpm -F acgi-ai run dev:mock
pnpm -F acgi-ai run dev:live
```

`dev:mock` enables `VITE_USE_MOCKS=true` for fixture-backed local UI development. `dev:live` disables fixture fallback and expects the same-origin API path to be reachable through the configured dev proxy or deployed console origin.

## Read before editing

- `DESIGN.md` for visual and interaction decisions
- `DEPLOY.md` for hosting, headers, CSP, fonts, and surface boundaries
- `ARCHITECTURE.md` for route/build/data/claim boundaries
- `INTEGRATING.md` for API and bus integration contracts
- `claim-matrix.json` before public compliance, security, trust, SOC 2, DPA, subprocessor, or accessibility wording changes

## Verification expectations

Use the narrow gate first, then the broader gate:

- route/build changes: `pnpm -F acgi-ai run test:all && pnpm -F acgi-ai build`
- bus/auth/deploy boundary changes: `pnpm -F acgi-ai run test:contract`
- public claim or trust-center copy: `pnpm -F acgi-ai run audit:eval`
- route shell smoke changes: `pnpm -F acgi-ai run test:e2e-http`
- MSW handler/test setup changes: `pnpm -F acgi-ai run test:msw-node`
- docs scaffold changes: `pnpm -F acgi-ai run test:docs-scaffold`
- monorepo-wide confidence: `make verify`

local verification does not equal production deployment. Production evidence requires live Vercel and Cloud Run domains, real headers, `/healthz` served-hash/build-id proof, OIDC or server-cookie auth, legal review, pentest evidence, CSP report processing, and manual WCAG review.
