<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-05-04 -->

# .github

## Purpose
This directory contains GitHub platform configuration for the repository. Its durable content is the workflow set that builds, validates, previews, and deploys the two ACGS web surfaces.

## Key Files
| File | Description |
|------|-------------|
| `AGENTS.md` | AI-readable documentation for GitHub configuration. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `workflows/` | GitHub Actions workflow definitions for marketing and console deployments (see `workflows/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- Keep workflow changes aligned with `DEPLOY.md`; marketing and console have intentionally different providers and threat models.
- Do not add secrets or service-account JSON. The console workflow uses Workload Identity Federation.
- Preserve path filters so unrelated deploys are not triggered unnecessarily.

### Testing Requirements
- There is no workflow linter configured in this repository.
- For workflow edits that affect app build inputs, ensure the relevant script names still match `package.json`.

### Common Patterns
- Workflows install pnpm, set up Node 24, install with `--frozen-lockfile`, run lint, and build before deployment.
- Console deployment is Cloud Run-oriented; marketing deployment is Vercel-oriented.

## Dependencies

### Internal
- Root `package.json` scripts and lockfile.
- `infra/` for console image and Cloud Run service definitions.
- `vercel.json` for marketing-origin routing and headers.

### External
- GitHub Actions hosted runners.
- pnpm, Node, Docker Buildx, Google GitHub Actions, gcloud, and Vercel CLI.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
