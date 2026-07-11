# AGENTS.md — acgi-ai/scripts

## Purpose

Out-of-band smoke checks and static contract checks for deployed-or-deployable
behavior that unit tests cannot reach. Marketing deploys through Cloudflare
Workers Static Assets; the Workers-compatible redirects, route ownership, and
the console's Caddy boundary provide defense in depth.

## Key Files

- `smoke-internal-doc-deny.sh` — bash smoke test. Takes a target host as its
  single positional argument. Exits non-zero on any unexpected status code.
  Run only against an authorized Worker preview or deployed origin after a
  `infra/cloudflare/workers/_redirects` change, with `SPA_SMOKE_PATH` set to an
  explicit marketing route because unknown Worker paths intentionally return
  404.
- `test_vercel_internal_doc_denial.py` — obsolete Vercel-only check that still
  parses `vercel.json`; it is retained for history and is not Workers evidence.
  The current static contracts are `check-marketing-routes.mjs` and
  `check-marketing-csp.mjs`.

## How to Run

```bash
# from acgi-ai/
pnpm test:marketing-routes
pnpm test:marketing-csp
SPA_SMOKE_PATH=/trust bash scripts/smoke-internal-doc-deny.sh \
  https://authorized-worker-preview.example
```

## Gotchas

- These scripts live OUTSIDE the Biome/ESLint `lint` script (which only
  covers `src/` and a handful of root configs). Lint failures here will
  surface only via the repo-level Python / shell hygiene benches.
- The shell script uses `set -euo pipefail`; do not edit it in a way that
  breaks strict-mode error propagation, or CI silently passes on broken
  smoke runs.
- Do not run the Vercel-only Python check as Cloudflare evidence and do not use
  an arbitrary unknown path for the Worker SPA smoke; both encode superseded
  routing assumptions.
- Root workflows are physically split: `console.yml`, `marketing.yml`, and
  `storybook.yml` verify pull requests; `console-deploy.yml`,
  `marketing-cloudflare.yml`, and `storybook-deploy.yml` are push-only.
- A local or static smoke pass is configured-state evidence, not proof of a
  live deployment.
