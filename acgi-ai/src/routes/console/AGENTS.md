<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-05-04 -->

# console

## Purpose
This directory contains the individual governance console page bodies rendered inside `src/routes/Console.tsx`. Each page consumes API hooks, renders fixture-backed operational data, and shares console styling from `src/App.css`.

## Key Files
| File | Description |
|------|-------------|
| `Overview.tsx` | Dashboard page for summary stats, active cases, queue pressure, and refusals by article. |
| `Workbench.tsx` | Visualized governed-work operator path: work queue, trace graph, evaluation panel, release gate, and evidence room blueprint. |
| `Agents.tsx` | Agent registry table with lane, model, refusals, health, and refresh metadata. |
| `Maci.tsx` | MACI lane board with proposer, validator, and executor cards. |
| `Deliberations.tsx` | Deliberation cards with emphasized title words, citations, due dates, and actions. |
| `Incidents.tsx` | Incident and escalation list with emphasized title words, source, hash, and posture. |
| `Policies.tsx` | Policy register with selectable policy list, detail pane, and diff-style example. |
| `Compile.tsx` | Constitution compile draft view with hash comparison, change counts, and change table. |
| `Audit.tsx` | Audit timeline page with events, source, posture, hashes, and matter links. |
| `Settings.tsx` | Settings table grouped by source labels from constitution, operator, or defaults. |
| `Tenants.tsx` | Tenant registry with selected tenant summary and tenant table. |
| `Account.tsx` | Account identity, session, and recent action view. |
| `wire-decisions.ts` | Route contract registry consumed by the console shell and guarded by `test:wire-decisions`. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|

## For AI Agents

### Working In This Directory
- Fetch data through `src/api/hooks.ts`; do not import `src/mocks/data/*` directly into page components.
- Preserve loading and error states when changing data rendering.
- Keep status labels and pill classes aligned with the `Posture` union.
- For `Deliberations.tsx` and `Incidents.tsx`, the `emphasis` field must match a word in the title so italic-rust rendering works.
- Keep page-specific classes CSP-safe; add CSS to `src/App.css` or `src/csp-utilities.css`, not inline styles.

### Testing Requirements
- Run `pnpm lint` and `pnpm build` after page changes.
- When changing table columns or fixture fields, update `src/api/types.ts`, mock data, and handlers as needed.

### Common Patterns
- Pages use `data ?? []` or fallback objects while React Query loads.
- Error states show retry buttons wired to `refetch`.
- Shared table, pill, toolbar, and prose classes come from `src/App.css`.

## Dependencies

### Internal
- `src/api/hooks.ts` and `src/api/types.ts`.
- `src/routes/Console.tsx` for layout, navigation, and page title metadata.
- `src/App.css` and `src/csp-utilities.css` for styling.

### External
- React and TanStack React Query through local hooks.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
