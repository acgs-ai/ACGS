<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-05-04 -->

# cloudrun

## Purpose
This directory contains the Cloud Run service manifest for the privileged console origin. It describes container settings, probes, scaling hints, and traffic routing for the image produced by the console workflow.

## Key Files
| File | Description |
|------|-------------|
| `service.yaml` | Knative Service manifest for `acgi-console`, with `REPLACE_AT_DEPLOY_TIME` image placeholder, health probes, resources, and autoscaling annotations. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|

## For AI Agents

### Working In This Directory
- Keep `REPLACE_AT_DEPLOY_TIME` unless the deployment workflow is changed at the same time.
- Do not lower production readiness around the privilege banner; the workflow raises `minScale` to `1` for production.
- Keep probes pointed at `/healthz`, which is served by `infra/Caddyfile`.

### Testing Requirements
- Validate YAML syntax with existing tooling if available.
- For deploy behavior changes, ensure `.github/workflows/console.yml` still renders and applies this manifest correctly.

### Common Patterns
- Staging can use `autoscaling.knative.dev/minScale: "0"`; production overrides it to `"1"`.
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
