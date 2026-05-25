<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-05-04 -->

# api

## Purpose
This directory defines the browser-side API boundary for the console. It keeps fetch paths relative to `/api/v1`, models response shapes, and exposes TanStack Query hooks for route components.

## Key Files
| File | Description |
|------|-------------|
| `client.ts` | Same-origin fetch wrapper, `ApiError`, and resource methods for agents, overview, MACI, deliberations, incidents, policies, compile, audit, settings, tenants, and account. |
| `hooks.ts` | React Query hooks with live or slower polling intervals for each API resource. |
| `types.ts` | Hand-written console `/api/v1` types plus aliases over generated bus schema components. |
| `bus.generated.ts` | Generated bus analyzer types from `contracts/bus.openapi.json`; do not edit by hand. |
| `openapi.json` | Compatibility mirror of `contracts/bus.openapi.json` for local API docs. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|

## For AI Agents

### Working In This Directory
- Keep API URLs relative; do not introduce absolute browser-visible API origins.
- Update `types.ts`, `client.ts`, `hooks.ts`, MSW handlers, and fixture data together when adding `/api/v1` endpoint shapes.
- For `/api/bus/*`, update `contracts/bus.openapi.json`, run `pnpm run gen:api`, keep `src/api/openapi.json` mirrored, and run `pnpm run test:bus-schema`.
- Do not swallow failed responses; `client.ts` should throw `ApiError` with status, URL, and body/status text.
- Preserve same-origin credentials behavior.

### Testing Requirements
- Run `pnpm lint` and `pnpm build` after API changes.
- If adding endpoint shapes, verify the corresponding mock handler returns data matching `types.ts`.
- If changing bus analyzer shapes, run `pnpm run test:bus-schema` and keep contract fixtures aligned.

### Common Patterns
- `LIVE` queries poll every 10 seconds with a 5 second stale time.
- `SLOW` queries poll every 60 seconds with a 30 second stale time.
- Types are explicit aliases rather than inferred fixture shapes.

## Dependencies

### Internal
- `src/mocks/handlers.ts` and `src/mocks/data/*` mirror this contract.
- `contracts/bus.openapi.json` is the `/api/bus/*` schema source of truth.
- `src/routes/console/*` consumes hooks from this directory.
- `vite.config.ts` proxies `/api` in development when MSW is not intercepting.

### External
- Browser Fetch API and TanStack React Query.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
