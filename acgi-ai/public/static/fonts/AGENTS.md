<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-05-04 -->

# fonts

## Purpose
This directory stores self-hosted WOFF2 font subsets for both the marketing and console surfaces. Serving these fonts from the console origin prevents third-party font CDN referrer leakage from privileged `/console/*` URLs.

## Key Files
| File | Description |
|------|-------------|
| `OFL.txt` | Open Font License text for the bundled font assets. |
| `ibm-plex-serif-*.woff2` | IBM Plex Serif latin and latin-ext subsets for editorial body and console prose. |
| `instrument-sans-*.woff2` | Instrument Sans latin and latin-ext subsets for marketing UI, nav, CTAs, and buttons. |
| `instrument-serif-*.woff2` | Instrument Serif normal and italic latin/latin-ext subsets for display headings and rust emphasis. |
| `inter-tight-*.woff2` | Inter Tight latin and latin-ext subsets for console runtime chrome and tables. |
| `jetbrains-mono-*.woff2` | JetBrains Mono latin and latin-ext subsets for hashes, code, citations, and metadata. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|

## For AI Agents

### Working In This Directory
- Do not delete a subset without also updating `src/fonts.css`.
- Keep latin and latin-ext split so extended glyphs load only when needed.
- Do not add remote font imports; the console origin must remain same-origin for fonts.
- Preserve license coverage when adding or replacing font families.

### Testing Requirements
- Run `pnpm test:font-manifest` after changing font file names, paths, bytes, or `src/fonts.css` references.
- Run `pnpm build` after font changes; build verifies `fonts.sha256` before emitting artifacts.

### Common Patterns
- File names encode family, weight, style, and subset.
- `font-display: swap` and `unicode-range` live in `src/fonts.css`, not in this directory.

## Dependencies

### Internal
- `src/fonts.css` declares all `@font-face` rules.
- `src/index.css` assigns font-family tokens.
- `infra/Caddyfile` caches `/static/fonts/*.woff2`.

### External
- WOFF2-capable browsers and font licenses represented by `OFL.txt`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
