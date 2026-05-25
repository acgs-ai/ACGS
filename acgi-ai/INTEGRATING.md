# acgi-ai integration contract

This file is the bus-client handoff for the current console. It describes the browser contract expected by `src/api/client.ts`, `src/api/hooks.ts`, `src/api/types.ts`, and the generated bus types in `src/api/bus.generated.ts`.

## Network boundary

All browser API calls are same-origin relative requests with `credentials: same-origin`.

- typed API prefix: `/api/v1`
- bus analyzer prefix: `/api/bus`
- console Caddy proxy: forwards to `BUS_UPSTREAM`
- schema handshake header: `X-ACGS-Schema-Version`

The browser must not call an absolute bus or gateway origin. Caddy owns the upstream boundary so console cookies, matter IDs, and route context stay inside the console origin.

## Bus schema source of truth

The bus schema source of truth is `contracts/bus.openapi.json`. `src/api/openapi.json` is kept as a normalized compatibility mirror for local API docs, while `pnpm run gen:api` regenerates `src/api/bus.generated.ts` from the contract. `pnpm run test:bus-schema` verifies schema ownership, generated-type drift, positive fixtures, unknown-field and missing-required negative fixtures, schema-version skew, and the machine-readable error envelope.

Recorded or stubbed bus responses must match the vendored schema before UI fixture updates are accepted. The frontend should not invent bus fields that are absent from `contracts/bus.openapi.json`.

## Endpoint table

| Browser endpoint | Method | Hook/client surface | Response contract |
|---|---:|---|---|
| `/api/v1/console-summary` | GET | `api.consoleSummary.get`, `useConsoleSummary` | `ConsoleSummary` |
| `/api/v1/agents` | GET | `api.agents.list`, `useAgents` | `Agent[]` |
| `/api/v1/actions` | GET | `api.actions.list`, `useGovernedActions` | `GovernedAction[]` |
| `/api/v1/actions/test` | POST | `api.actions.test`, `useTestAction` | `ActionTestReceipt` |
| `/api/v1/overview` | GET | `api.overview.get`, `useOverview` | `OverviewSummary` |
| `/api/v1/maci` | GET | `api.maci.get`, `useMaci` | `MaciLanes` |
| `/api/v1/deliberations` | GET | `api.deliberations.list`, `useDeliberations` | `Deliberation[]` |
| `/api/v1/incidents` | GET | `api.incidents.list`, `useIncidents` | `Incident[]` |
| `/api/v1/policies` | GET | `api.policies.list`, `usePolicies` | `PolicyRule[]` |
| `/api/v1/compile/draft` | GET | `api.compile.draft`, `useCompileDraft` | `CompileDraft` |
| `/api/v1/compile/replay` | POST | `api.compile.replay`, `useReplayCompile` | `ActionReceipt` |
| `/api/v1/compile/promote` | POST | `api.compile.promote`, `usePromoteCompile` | `ActionReceipt` |
| `/api/v1/audit` | GET | `api.audit.list`, `useAudit` | `AuditEvent[]` |
| `/api/v1/settings` | GET | `api.settings.get`, `useSettings` | `SettingSection[]` |
| `/api/v1/tenants` | GET | `api.tenants.list`, `useTenants` | `Tenant[]` |
| `/api/v1/account` | GET | `api.account.get`, `useAccount` | `AccountView` |
| `/api/bus/traces` | GET | `api.bus.listTraces`, `useBusTraces` | `BusTraceList` |
| `/api/bus/traces/{correlation_id}` | GET | `api.bus.getTrace`, `useBusTrace` | `BusSingleTrace | BusExpired` |

## Error envelope

`makeHttp()` throws `ApiError` when `res.ok` is false. The error carries:

- `status`
- `url`
- response body text, falling back to `statusText`

Future FastAPI envelopes should keep a machine-readable problem shape, but the browser already preserves raw response text for operator debugging.

## Fixture and auth assumptions

`VITE_USE_MOCKS=true` enables non-production fixture fallback through dynamic imports in `src/api/hooks.ts`. The fallback is blocked in production by `import.meta.env.PROD`.

Production auth is not complete. OIDC or server-cookie auth remains a production gate; the current demo session code is deliberately non-production-only.

## Known unstable fields

These fields are treated as integration-sensitive until the governed bus is live:

- `constitutionHash` and `served_hash` must match the deployed bundle and policy baseline
- `traceId`, `auditEventId`, and bus `correlation_id` must remain stable and URL-safe
- `X-ACGS-Schema-Version` must be echoed by the proxy/upstream boundary
- latency, retry, refusal, and human-review counts may change source once live telemetry replaces fixtures
- bus trace expiry can return `BusExpired` instead of `BusSingleTrace`

## Contract checks

Run these after changing the bus boundary, endpoint shapes, auth/session assumptions, or fixture fallback:

```bash
pnpm -F acgi-ai run test:bus-schema
pnpm -F acgi-ai run test:contract
pnpm -F acgi-ai run test:security
pnpm -F acgi-ai run test:all
```

For Docker-backed proxy verification, run:

```bash
pnpm -F acgi-ai run smoke:bus-proxy
```
