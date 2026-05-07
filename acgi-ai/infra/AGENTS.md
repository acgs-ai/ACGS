<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-05-04 -->

# infra

## Purpose
This directory contains the console-origin infrastructure contract: Caddy serves the Vite bundle with strict headers, Docker builds the runtime image, and Cloud Run hosts the privileged console surface.

## Key Files
| File | Description |
|------|-------------|
| `Caddyfile` | Console-origin server config with SPA fallback, health check, strict CSP, no-referrer policy, cache rules, and placeholder `/api/*` behavior. |
| `Dockerfile.console` | Multi-stage build that compiles the Vite app with pnpm and serves `dist/` from the Caddy runtime image. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `cloudrun/` | Knative Cloud Run service manifest for the console container (see `cloudrun/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- Read `DEPLOY.md` before modifying Caddy, Docker, Cloud Run, headers, CSP, or health behavior.
- Preserve strict console CSP; do not add `'unsafe-inline'`.
- Keep `/static/fonts/*.woff2` same-origin and long-cacheable.
- Keep `/api/*` loud-failing until the bus/API gateway is intentionally wired.

### Testing Requirements
- Run `pnpm build` after Docker build-input changes.
- If Docker is available and infra changed, build the console image path used by `.github/workflows/console.yml`.
- Caddy syntax is validated in the Dockerfile with `caddy validate`.

### Common Patterns
- `try_files {path} /index.html` supports deep links for the custom router.
- `/healthz` reports static bundle health and a served constitution hash.
- HTML is no-store; hashed assets and fonts are immutable.

## Dependencies

### Internal
- Root Vite app files copied by `Dockerfile.console`.
- `public/static/fonts/` served through the Caddy font matcher.
- `.github/workflows/console.yml` builds and deploys this directory.

### External
- Docker, Node 24 Alpine, pnpm through Corepack, Caddy 2 Alpine, and Cloud Run.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
