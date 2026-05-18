# AGENTS.md — acgi-ai/scripts

## Purpose

Out-of-band smoke checks that exercise deployed-or-deployable behavior the
unit tests cannot reach — specifically, that Vercel correctly denies access
to internal documentation paths and falls back to the SPA shell for
unknown routes.

## Key Files

- `smoke-internal-doc-deny.sh` — bash smoke test. Takes a target host as its
  single positional argument; accepts an optional `--vercel-curl` flag to
  switch the underlying client. Exits non-zero on any unexpected status
  code. Run against preview deployments after a `vercel.json` change.
- `test_vercel_internal_doc_denial.py` — Python sibling check that
  parses `../vercel.json` and asserts the routing rules match the
  contract documented in `../DEPLOY.md`. Pure file-IO + regex; no
  network calls.

## How to Run

```bash
# from acgi-ai/
bash scripts/smoke-internal-doc-deny.sh https://preview-xxx.vercel.app
bash scripts/smoke-internal-doc-deny.sh --vercel-curl https://console.acgs.ai
python3 scripts/test_vercel_internal_doc_denial.py
```

## Gotchas

- These scripts live OUTSIDE the Biome/ESLint `lint` script (which only
  covers `src/` and a handful of root configs). Lint failures here will
  surface only via the repo-level Python / shell hygiene benches.
- The shell script uses `set -euo pipefail`; do not edit it in a way that
  breaks strict-mode error propagation, or CI silently passes on broken
  smoke runs.
