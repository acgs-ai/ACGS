<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-05-04 -->

# data

## Purpose
This directory contains module-level fixture payloads for the console. These payloads drive MSW responses and should mirror `src/api/types.ts` until the real backend is wired.

## Key Files
| File | Description |
|------|-------------|
| `account.ts` | `ACCOUNT_VIEW` fixture for identity fields, sessions, and recent account actions. |
| `agents.ts` | `AGENTS` fixture for console agent registry rows and health states. |
| `audit.ts` | `AUDIT_EVENTS` fixture for the audit timeline. |
| `compile.ts` | `COMPILE_DRAFT` fixture for proposed constitution hash and policy changes. |
| `deliberations.ts` | `DELIBERATIONS` fixture for open governance deliberation cards. |
| `incidents.ts` | `INCIDENTS` fixture for escalation and incident rows. |
| `maci.ts` | `MACI_LANES` fixture for proposer, validator, and executor lane cards. |
| `overview.ts` | `OVERVIEW_SUMMARY` fixture for stats, active cases, queues, and refusal metrics. |
| `policies.ts` | `POLICIES` fixture for policy register rules and prose. |
| `settings.ts` | `SETTING_SECTIONS` fixture for runtime and constitution-controlled settings. |
| `tenants.ts` | `TENANTS` fixture for tenant registry rows and state details. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|

## For AI Agents

### Working In This Directory
- Use exported constants with explicit type annotations from `src/api/types.ts`.
- Keep posture values inside the `Posture` union: `confirmed`, `partial`, `blocked`, or `privileged`.
- For titles with italic-rust emphasis, keep the `emphasis` string present in the rendered `title`.
- Keep fixture data plausible for the regulated-AI governance domain; avoid generic SaaS filler.

### Testing Requirements
- Run `pnpm lint` and `pnpm build` after fixture changes.
- If changing a fixture shape, update `src/api/types.ts`, page rendering, and MSW handlers together.

### Common Patterns
- Constants are upper snake case and imported directly by `src/mocks/handlers.ts`.
- Fixture IDs use readable prefixes such as `AG-`, `INC-`, `POL-`, or tenant IDs.

## Dependencies

### Internal
- `src/api/types.ts` for compile-time contracts.
- `src/mocks/handlers.ts` for HTTP exposure.
- `src/routes/console/*` for display assumptions.

### External
- TypeScript type checking only; no runtime fixture library.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
