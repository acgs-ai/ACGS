<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-05-04 -->

# mocks

## Purpose
This directory provides optional MSW-backed API responses for local development. When `VITE_USE_MOCKS=true`, the app starts a browser worker before mounting React and intercepts `/api/v1/*` requests.

## Key Files
| File | Description |
|------|-------------|
| `browser.ts` | Creates the MSW browser worker from the handler list. |
| `handlers.ts` | Maps `/api/v1/*` GET routes to JSON fixtures from `data/`. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `data/` | Typed fixture payloads for every API resource (see `data/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- Keep handler paths synchronized with `src/api/client.ts`.
- Keep fixture payloads synchronized with `src/api/types.ts`.
- Do not make mocks hide errors that production would surface; missing endpoints should fail unless intentionally handled.

### Testing Requirements
- Run `pnpm lint` and `pnpm build` after mock changes.
- For a new endpoint, add both a handler and fixture data before using it from a route.

### Common Patterns
- Handlers return `HttpResponse.json(CONSTANT)` from module-level fixture constants.
- The worker starts with `onUnhandledRequest: 'bypass'` in `src/main.tsx`.

## Dependencies

### Internal
- `src/api/client.ts` endpoint paths.
- `src/api/types.ts` response shapes.
- `public/mockServiceWorker.js` generated MSW worker file.

### External
- MSW browser and core HTTP APIs.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
