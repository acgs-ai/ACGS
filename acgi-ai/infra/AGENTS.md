<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-07-11 -->

# infra

## Purpose
This directory defines both frontend hosting boundaries. The public marketing origin is packaged for the configured `acgs-governance-proxy` Cloudflare Workers Static Assets deployment. The privileged console is built into a pinned Caddy container and rendered into environment-specific Cloud Run configuration with fail-closed authorization and same-origin API proxying. These files describe configured delivery contracts; they are not proof that a production environment, credential, DNS route, or protected upstream is live.

## Key Files
| File | Description |
|------|-------------|
| `Caddyfile` | Console server contract: strict headers/CSP, internal-document denial, health response, fail-closed `forward_auth`, governed `/api/*` proxy, and SPA routing. |
| `Dockerfile.console` | Multi-stage console image build with reviewed Node/pnpm and Caddy bases plus Caddy configuration validation. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `cloudflare/` | Shared marketing headers, legacy Pages routing parity, and the live Workers Static Assets script, redirects, routes, and Wrangler configuration. |
| `cloudrun/` | Preview, staging, production, and rendered Cloud Run service manifests (see `cloudrun/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- Read `../DEPLOY.md` before changing Caddy, Docker, Cloudflare, Cloud Run, CSP, authentication, proxying, routing, or deployment behavior.
- Preserve the console privilege boundary: no third-party browser scripts, no inline-style CSP exceptions, no secret redisplay, and no SPA response before the server-side auth gate accepts `/console/*`.
- Keep `AUTH_UPSTREAM` and `BUS_UPSTREAM` fail closed when absent. Do not replace their closed-port fallbacks or deploy-time non-empty checks with fixture data or allow-by-default behavior.
- Keep `/api/*` ahead of the SPA fallback and preserve the `X-ACGS-Schema-Version` request/response handshake.
- The committed marketing payload uses `cloudflare/workers/wrangler.toml`, `cloudflare/workers/worker.js`, `cloudflare/workers/_redirects`, and `cloudflare/_headers`. Do not stage the Pages `_redirects` file into the Workers Static Assets artifact.
- Preserve all four reviewed route patterns in the Workers Wrangler configuration: `acgs.ai/*`, `www.acgs.ai/*`, `console.acgs.ai/*`, and `api.acgs.ai/telegram/*`. The committed route block is a correctness contract, not proof of a deployed or healthy origin.
- Keep the Worker script limited to protocol/host canonicalization and asset dispatch unless a reviewed architecture change says otherwise. Unknown marketing paths must remain true 404s.
- Root `.github/workflows/console.yml` is pull-request verification only. Root `.github/workflows/console-deploy.yml` is the push-only Cloud Run build/render/deploy path; it must retain exact-commit authorization and scoped Google Workload Identity Federation authority.
- Root `.github/workflows/marketing.yml` is pull-request verification only. Root `.github/workflows/marketing-cloudflare.yml` is the push-only Cloudflare Workers Static Assets deployment path; never expose its credentials to pull-request jobs.
- Do not claim the console, auth upstream, bus upstream, Cloudflare routes, or production evidence are deployed based only on these committed files.

### Testing Requirements
- Run `pnpm test:bus-proxy` and `pnpm test:auth-boundary` after Caddy, Cloud Run, console workflow, auth, or governed API proxy changes.
- Run `pnpm test:cloudrun-templates` and `pnpm test:cloudrun-renderer` after service-template, renderer, or `console-deploy.yml` changes.
- Run `pnpm test:marketing-csp` and `pnpm test:marketing-routes` after Cloudflare header, redirect, Worker, or route changes.
- Run `pnpm test:production-deploy-contract` and `pnpm test:ci-gates` after either verification/deployment workflow contract changes.
- Run `pnpm test:container-pins` after Docker base, Node, pnpm, Caddy, or Wrangler toolchain changes.
- Run `pnpm build` after build-input changes. When Docker is available, run `pnpm build:console && pnpm smoke:bus-proxy` after container, Caddy, auth, or proxy changes.
- Caddy syntax is validated during the image build; retain that validation when changing the Dockerfile.

### Common Patterns
- Caddy `route`/`handle` ordering keeps health, auth status, API proxying, internal-document denial, and protected console routes ahead of the generic SPA fallback.
- `/healthz` reports the served constitution hash, build ID, and console surface; HTML is no-store while hashed assets and WOFF2 fonts are immutable.
- Production console templates receive immutable image/build identifiers plus explicit auth and bus upstreams through `scripts/render-cloudrun-service.mjs`.
- The Cloudflare Worker performs HTTP-to-HTTPS and `www`-to-apex canonicalization, then delegates to the Workers Static Assets binding.
- The Workers redirect file enumerates supported marketing deep links and the `/console` cross-origin redirects; it intentionally has no catch-all rewrite.

## Dependencies

### Internal
- `../src/` and `../public/` produce the two frontend surfaces and same-origin font assets consumed by these hosting configurations.
- `../scripts/render-cloudrun-service.mjs` renders a reviewed environment template for `.github/workflows/console-deploy.yml`.
- Repository-root `.github/workflows/console.yml` and `marketing.yml` verify pull requests without deployment authority.
- Repository-root `.github/workflows/console-deploy.yml` and `marketing-cloudflare.yml` independently reverify and deploy authorized pushed commits.

### External
- Docker and Caddy for the privileged console image and HTTP policy.
- Google Cloud Run, Artifact Registry, gcloud, and Workload Identity Federation for the configured console delivery path.
- Cloudflare Workers Static Assets and Wrangler 4.110.0 for the configured marketing delivery contract.
- GitHub Actions environments, exact-commit variables, OIDC, and repository secrets for human-authorized production jobs.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
