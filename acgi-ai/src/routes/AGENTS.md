<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-05-04 -->

# routes

## Purpose
This directory contains top-level route components consumed by the TanStack Router surface apps: marketing, console shell, login, privacy, trust/security disclosures, and not-found screens. Console page bodies live in the nested `console/` directory.

## Key Files
| File | Description |
|------|-------------|
| `Marketing.tsx` | Editorial marketing landing page with module-level capability, coverage, and pricing tier arrays. |
| `Console.tsx` | Governance console shell with sidebar, structural privilege banner, topbar, heartbeat, right rail, and page dispatch. |
| `Login.tsx` | Login surface with provider choices and delayed navigation into the console. |
| `Privacy.tsx` | Privacy and subprocessor page with local subprocessor data and disclosure links. |
| `Trust.tsx` | Engineering-draft trust center for DPA draft, SOC 2 roadmap, subprocessor feed, and security metadata links. |
| `Security.tsx` | Engineering-draft security posture page that keeps OIDC, live deploy proof, pentest, and WCAG evidence as explicit gates. |
| `NotFound.tsx` | Not-found UI for marketing or console contexts. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `console/` | Individual console page bodies for overview, agents, MACI, deliberations, incidents, policies, compile, audit, settings, tenants, and account (see `console/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- Keep route behavior aligned with the TanStack Router trees in `src/surfaces/*/App.tsx`.
- Preserve the console privilege banner in `Console.tsx`; do not animate, hide, gate, or move it below the top edge.
- Marketing copy belongs in the module-level arrays in `Marketing.tsx` where possible.
- Console page titles in `Console.tsx` must keep exactly one italic-rust word.
- Use `navigate()` for internal route changes that should update the active TanStack Router history.

### Testing Requirements
- Run `pnpm lint` and `pnpm build` after route changes.
- Run `pnpm test:trust-surface` after changing trust/security disclosure routes or links.
- For visual route changes, check against `DESIGN.md` constraints.

### Common Patterns
- Top-level route files export React components by name.
- `Console.tsx` owns navigation metadata and dispatches to page components by path.
- Marketing responsive nav state is local to `Marketing.tsx`.

## Dependencies

### Internal
- `src/lib/navigate.ts` for internal navigation.
- `src/routes/console/*` page bodies.
- `src/App.css` and `src/csp-utilities.css` for route styling.
- `src/api/hooks.ts` indirectly through console pages.

### External
- React hooks and JSX runtime.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
