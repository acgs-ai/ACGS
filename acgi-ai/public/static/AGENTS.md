<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-05-04 -->

# static

## Purpose
This directory is a stable URL namespace for public static assets that should not be imported through Vite modules. It currently exists to host same-origin fonts under `/static/fonts/`.

## Key Files
| File | Description |
|------|-------------|

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `fonts/` | Self-hosted WOFF2 font subsets and font license text (see `fonts/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- Keep URL paths stable; `src/fonts.css` refers to `/static/fonts/*.woff2`.
- Prefer adding durable asset families as subdirectories rather than mixing unrelated files at this level.

### Testing Requirements
- Run `pnpm build` after changing paths referenced by CSS or HTML.

### Common Patterns
- Assets here are served as public files and not bundled imports.
- Caddy applies long cache headers to `/static/fonts/*.woff2`.

## Dependencies

### Internal
- `public/static/fonts/`.
- `src/fonts.css` and `infra/Caddyfile`.

### External
- Browser static asset loading.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
