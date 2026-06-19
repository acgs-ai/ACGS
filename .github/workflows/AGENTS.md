<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-05-04 -->

# workflows

## Purpose
This directory defines CI/CD workflows for the two-origin deployment model: a marketing surface deployed through Cloudflare Pages and a privileged console surface deployed as a Cloud Run container. It can also contain path-filtered static validation workflows for experiments that must not deploy.

## Key Files
| File | Description |
|------|-------------|
| `console.yml` | Builds, lints, containerizes, pushes, deploys, and smoke-tests the console origin using GCP Workload Identity Federation. |
| `marketing-cloudflare.yml` | Builds and deploys the marketing origin to Cloudflare Pages (gated production deploy on push to `master`). |
| `marketing.yml` | Runs lint, build, and readiness checks for the marketing origin (verify-only, no deploy). |
| `iii-governance-lab-static.yml` | Runs static-only contract checks for `experiments/iii-governance-lab/`; it must not start a live iii engine or deploy. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|

## For AI Agents

### Working In This Directory
- Keep `console.yml` and `marketing.yml` split; this separation is part of the deployment privilege boundary.
- Never replace Workload Identity Federation with long-lived GCP keys.
- Keep preview comments and production deploy conditions scoped to the correct event type.
- Keep path filters in sync with files that can affect each surface.
- Keep experiment workflows path-filtered to their experiment, read-only, and free of secrets or deployment steps.

### Testing Requirements
- Confirm edited workflow commands exist in `package.json`.
- For console workflow changes, confirm referenced infra files still exist.
- For marketing workflow changes, confirm Cloudflare config files still align with `infra/cloudflare/_redirects`, `infra/cloudflare/_headers`, and `wrangler.toml`.

### Common Patterns
- Both workflows use pnpm 9, Node 24, `pnpm install --frozen-lockfile`, `pnpm lint`, and `pnpm build`.
- Console deploys only on push to `main`; PRs build and push an image but do not replace the Cloud Run service.
- Marketing PRs run verify-only checks (lint + build + `test:all`); Cloudflare Pages preview deployments are gated on `master` push.

## Dependencies

### Internal
- `package.json`, `pnpm-lock.yaml`, `vite.config.ts`, `tsconfig*.json`, `src/`, and `public/`.
- `infra/Dockerfile.console` and `infra/cloudrun/service.yaml` for console.
- `infra/cloudflare/_redirects` and `infra/cloudflare/_headers` for marketing.

### External
- `actions/checkout`, `pnpm/action-setup`, `actions/setup-node`, `google-github-actions/auth`, `google-github-actions/setup-gcloud`, `docker/build-push-action`, `docker/setup-buildx-action`, `actions/github-script`, and `cloudflare/wrangler-action`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
