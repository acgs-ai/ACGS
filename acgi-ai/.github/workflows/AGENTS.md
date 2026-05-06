<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-05-04 -->

# workflows

## Purpose
This directory defines CI/CD workflows for the two-origin deployment model: a marketing surface deployed through Vercel and a privileged console surface deployed as a Cloud Run container.

## Key Files
| File | Description |
|------|-------------|
| `console.yml` | Builds, lints, containerizes, pushes, deploys, and smoke-tests the console origin using GCP Workload Identity Federation. |
| `marketing.yml` | Builds, lints, previews, and deploys the marketing origin using Vercel. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|

## For AI Agents

### Working In This Directory
- Keep `console.yml` and `marketing.yml` split; this separation is part of the deployment privilege boundary.
- Never replace Workload Identity Federation with long-lived GCP keys.
- Keep preview comments and production deploy conditions scoped to the correct event type.
- Keep path filters in sync with files that can affect each surface.

### Testing Requirements
- Confirm edited workflow commands exist in `package.json`.
- For console workflow changes, confirm referenced infra files still exist.
- For marketing workflow changes, confirm Vercel config names still align with `vercel.json`.

### Common Patterns
- Both workflows use pnpm 9, Node 24, `pnpm install --frozen-lockfile`, `pnpm lint`, and `pnpm build`.
- Console deploys only on push to `main`; PRs build and push an image but do not replace the Cloud Run service.
- Marketing PRs create preview deployments and comment the preview URL.

## Dependencies

### Internal
- `package.json`, `pnpm-lock.yaml`, `vite.config.ts`, `tsconfig*.json`, `src/`, and `public/`.
- `infra/Dockerfile.console` and `infra/cloudrun/service.yaml` for console.
- `vercel.json` for marketing.

### External
- `actions/checkout`, `pnpm/action-setup`, `actions/setup-node`, `google-github-actions/auth`, `google-github-actions/setup-gcloud`, `docker/build-push-action`, `docker/setup-buildx-action`, and `actions/github-script`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
