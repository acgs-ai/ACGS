<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-07-11 -->

# cloudrun

## Purpose
This directory contains reviewed Cloud Run service templates for the privileged console origin. Preview, staging, and production encode different capacity envelopes but share the same fail-closed auth, governed API, probe, resource, and traffic contract. `scripts/render-cloudrun-service.mjs` materializes the selected template for the push-only `.github/workflows/console-deploy.yml` workflow; committed manifests are configuration, not evidence of a deployed or reachable console.

## Key Files
| File | Description |
|------|-------------|
| `service.preview.yaml` | Preview source template: minimum scale 0, concurrency 80, and 256Mi memory. |
| `service.staging.yaml` | Staging source template: minimum scale 1, concurrency 80, and 512Mi memory. |
| `service.production.yaml` | Production source template: minimum scale 2, concurrency 60, and 1Gi memory. |
| `service.yaml` | Renderer output target, currently carrying the reviewed preview-default placeholders until the deploy workflow renders an authorized environment. |

## Subdirectories
This directory has no subdirectories.

## For AI Agents

### Working In This Directory
- Read `../../DEPLOY.md` and `../AGENTS.md` before changing a service template or its deployment contract.
- Edit the environment source templates and `../../scripts/render-cloudrun-service.mjs`; regenerate `service.yaml` through the renderer instead of hand-editing rendered output.
- Preserve `REPLACE_AT_DEPLOY_TIME`, `REPLACE_BUILD_ID_AT_DEPLOY_TIME`, `REPLACE_AUTH_UPSTREAM_AT_DEPLOY_TIME`, and `REPLACE_BUS_UPSTREAM_AT_DEPLOY_TIME` in source templates. The renderer must reject unresolved or empty production inputs.
- Keep `AUTH_UPSTREAM` and `BUS_UPSTREAM` separate and environment-bound. Neither may be supplied by a browser or agent request body.
- Keep startup and liveness probes on `/healthz`, `PORT=8080`, `ACGS_SCHEMA_VERSION=v1`, and 100 percent traffic to the latest rendered revision unless an explicitly reviewed migration changes the contract.
- Do not reduce the production baseline of minimum scale 2, concurrency 60, or 1Gi memory without updating `DEPLOY.md`, capacity assumptions, rollback guidance, and contract tests.
- Root `.github/workflows/console.yml` verifies pull requests and has no deploy authority. Only root `.github/workflows/console-deploy.yml` renders, publishes, and replaces the Cloud Run service after exact-commit authorization.
- Keep Google authentication on short-lived Workload Identity Federation. Do not introduce service-account JSON or other long-lived cloud credentials.
- Never describe a rendered manifest, successful local test, or committed workflow as a live Cloud Run deployment.

### Testing Requirements
- Run `pnpm test:cloudrun-templates` after changing any template or its invariant.
- Run `pnpm test:cloudrun-renderer` after changing templates, renderer inputs, placeholder handling, or `console-deploy.yml` rendering.
- Run `pnpm test:bus-proxy` and `pnpm test:auth-boundary` after changing `BUS_UPSTREAM`, `AUTH_UPSTREAM`, schema, Caddy, or console deployment wiring.
- Run `pnpm test:production-deploy-contract` and `pnpm test:ci-gates` after changing the root console workflows or deployment authority contract.
- Validate rendered YAML through the existing renderer/checker path; do not substitute ad hoc `cp`/`sed` mutation for the shared renderer.
- When Docker is available and the serving contract changes, run `pnpm build:console && pnpm smoke:bus-proxy` from `acgi-ai/`.

### Common Patterns
- Each source manifest is a Knative `serving.knative.dev/v1` `Service` named `acgi-console` using the gen2 execution environment.
- Preview scales to zero; staging keeps one warm instance; production keeps two. All environments cap scale at 10.
- The container listens on named port `http1` at 8080, uses one CPU, and receives build, auth, bus, and schema values as environment variables.
- Startup probes are intentionally fast and bounded; liveness probes run every 30 seconds. Both call Caddy's static `/healthz` endpoint.
- `.github/workflows/console-deploy.yml` publishes an immutable commit-tagged image, invokes the shared renderer with production inputs, then uses `gcloud run services replace` and post-deploy verification.

## Dependencies

### Internal
- `../Caddyfile` implements `/healthz`, server authorization, the governed `/api/*` proxy, strict console headers, and SPA serving.
- `../Dockerfile.console` defines the immutable image consumed by the rendered manifest.
- `../../scripts/render-cloudrun-service.mjs` is the only supported template-to-`service.yaml` render path.
- Repository-root `.github/workflows/console-deploy.yml` supplies immutable image/build identifiers and protected auth/bus upstream values, then deploys the rendered manifest.
- Repository-root `.github/workflows/console.yml` exercises the pull-request verification path only.

### External
- Google Cloud Run and the Knative Serving API for service execution.
- Artifact Registry for the commit-tagged console image.
- gcloud and Google Workload Identity Federation for short-lived deployment identity.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
