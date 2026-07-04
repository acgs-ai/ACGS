# AGENTS.md — acgi-ai/scripts

## Purpose

Out-of-band smoke checks that exercise deployed-or-deployable behavior the
unit tests cannot reach — specifically, that the marketing edge layer correctly
denies access to internal documentation paths and falls back to the SPA shell
for unknown routes. Marketing now deploys via Cloudflare Pages; the
`_redirects` 404 rule and Caddy provide the defense-in-depth layer.

## Key Files

- `smoke-internal-doc-deny.sh` — bash smoke test. Takes a target host as its
  single positional argument. Exits non-zero on any unexpected status
  code. Run against preview deployments after a `infra/cloudflare/_redirects`
  change.
- `test_vercel_internal_doc_denial.py` — Legacy Python check (originally
  parsed `vercel.json`). Vercel removed; routing rules are now in
  `infra/cloudflare/_redirects` and asserted by `check-marketing-routes.mjs`.

## How to Run

```bash
# from acgi-ai/
bash scripts/smoke-internal-doc-deny.sh https://preview-xxx.pages.dev
python3 scripts/test_vercel_internal_doc_denial.py
```

## Gotchas

- These scripts live OUTSIDE the Biome/ESLint `lint` script (which only
  covers `src/` and a handful of root configs). Lint failures here will
  surface only via the repo-level Python / shell hygiene benches.
- The shell script uses `set -euo pipefail`; do not edit it in a way that
  breaks strict-mode error propagation, or CI silently passes on broken
  smoke runs.
