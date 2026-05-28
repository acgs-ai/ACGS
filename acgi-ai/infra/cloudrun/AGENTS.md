<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-05-04 -->

# cloudrun

## Purpose
This directory contains the Cloud Run service templates for the privileged console origin. They describe container settings, probes, scaling policy, resources, and traffic routing for the image produced by the console workflow.

## Key Files
| File | Description |
|------|-------------|
| `service.preview.yaml` | Preview template: minScale 0, concurrency 80, memory 256Mi. |
| `service.staging.yaml` | Staging template: minScale 1, concurrency 80, memory 512Mi. |
| `service.production.yaml` | Production template: minScale 2, concurrency 60, memory 1Gi. |
| `service.yaml` | Render target copied from `service.${DEPLOY_ENV}.yaml` by `.github/workflows/console.yml`, then populated with image/build/bus placeholders. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|

## For AI Agents

### Working In This Directory
- Keep `REPLACE_AT_DEPLOY_TIME`, `REPLACE_BUILD_ID_AT_DEPLOY_TIME`, and `REPLACE_BUS_UPSTREAM_AT_DEPLOY_TIME` unless the deployment workflow is changed at the same time.
- Do not lower production readiness around the privilege banner; production must stay at minScale `2`, concurrency `60`, memory `1Gi` unless `DEPLOY.md` and `test:cloudrun-templates` are updated with a reviewed replacement.
- Keep probes pointed at `/healthz`, which is served by `infra/Caddyfile`.

### Testing Requirements
- Validate YAML syntax with existing tooling if available.
- Run `pnpm test:cloudrun-templates` after editing any service template or the workflow render path.
- For deploy behavior changes, ensure `.github/workflows/console.yml` still renders and applies this manifest correctly.

### Common Patterns
- Preview uses `autoscaling.knative.dev/minScale: "0"`; staging uses `"1"`; production uses `"2"`.
- The container listens on `PORT=8080` and exposes an `http1` port.
- Traffic routes 100 percent to the latest revision.

## Dependencies

### Internal
- `infra/Caddyfile` for `/healthz` and serving behavior.
- `infra/Dockerfile.console` for the image contract.
- `.github/workflows/console.yml` for render and deploy commands.

### External
- Google Cloud Run, Knative Serving API, Artifact Registry, and gcloud.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
