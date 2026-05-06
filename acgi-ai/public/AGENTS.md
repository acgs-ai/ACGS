<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-05-04 -->

# public

## Purpose
This directory contains static assets copied directly into the Vite build output. It includes icons, the MSW worker script, and self-hosted font assets required by the console privilege boundary.

## Key Files
| File | Description |
|------|-------------|
| `favicon.svg` | Browser favicon referenced by `index.html`. |
| `icons.svg` | Shared SVG symbol/icon asset served from the public root. |
| `mockServiceWorker.js` | Generated MSW service worker used when local mocks are enabled. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `static/` | Static assets under stable URL paths, currently font files (see `static/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- Do not hand-edit `mockServiceWorker.js`; regenerate it through MSW tooling if the worker must change.
- Keep font assets same-origin for console; do not replace them with CDN references.
- Public files are served at root-relative URLs, so path changes can break CSS or HTML references.
- Keep operational docs out of runtime assets. The build strips `AGENTS.md`, `CLAUDE.md`, `DESIGN.md`, and `DEPLOY.md` from `dist/` as a safety net, but this directory should contain only files meant to be served.

### Testing Requirements
- Run `pnpm build` after adding, removing, or renaming public assets referenced by source files.
- Check references in `src/fonts.css`, `index.html`, and relevant components when moving assets.

### Common Patterns
- Vite copies this directory to `dist/` without fingerprinting file names.
- Long-lived cache behavior for fonts is controlled by `infra/Caddyfile`.

## Dependencies

### Internal
- `src/fonts.css` consumes files under `public/static/fonts/`.
- `index.html` references `/favicon.svg`.
- `src/mocks/browser.ts` starts the MSW worker when `VITE_USE_MOCKS=true`.

### External
- MSW browser worker format.
- Browser support for SVG icons and WOFF2 fonts.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
