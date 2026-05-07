<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-05-04 -->

# assets

## Purpose
This directory contains source-imported static assets that Vite can fingerprint and bundle. It currently includes template SVGs and the marketing hero image asset.

## Key Files
| File | Description |
|------|-------------|
| `hero.png` | Marketing hero image asset available for source imports. |
| `react.svg` | Vite template React logo asset; verify usage before retaining or deleting. |
| `vite.svg` | Vite template logo asset; verify usage before retaining or deleting. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|

## For AI Agents

### Working In This Directory
- Prefer `public/` for assets that need stable root-relative URLs; use this directory for imported, fingerprinted assets.
- Before deleting template assets, search for references in `src/`.
- Avoid adding generic SaaS stock imagery; visual choices must match `DESIGN.md`.

### Testing Requirements
- Run `pnpm build` after adding, renaming, or deleting imported assets.

### Common Patterns
- Vite rewrites imported asset URLs into hashed build assets.
- Current core UI mostly uses CSS and text rather than image-heavy compositions.

## Dependencies

### Internal
- Route components may import assets from this directory.
- Vite handles bundling and emitted asset paths.

### External
- Browser image and SVG support.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
