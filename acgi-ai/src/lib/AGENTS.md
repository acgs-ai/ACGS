<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-05-04 -->

# lib

## Purpose
This directory contains small shared utilities used across the app. The current utilities support TanStack Router navigation bridging, runtime flags, AppError taxonomy, session state, and class-name composition.

## Key Files
| File | Description |
|------|-------------|
| `navigate.ts` | Internal navigation helper that calls `history.pushState` and dispatches a synthetic `popstate`. |
| `utils.ts` | `cn()` helper combining `clsx` and `tailwind-merge` for conditional class composition. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|

## For AI Agents

### Working In This Directory
- Keep `navigate()` aligned with `src/App.tsx`; route state depends on the synthetic `popstate`.
- Do not use `cn()` as permission to add Tailwind utility classes in JSX. The design contract still requires project CSS classes.
- Keep utilities small and shared; feature-specific logic belongs near the consuming route or page.

### Testing Requirements
- Run `pnpm lint` and `pnpm build` after utility changes.
- Run `pnpm -F acgi-ai run test:router` if `navigate.ts` or a surface route tree changes.

### Common Patterns
- Utilities are named exports.
- Browser-only helpers guard against server-like contexts with `typeof window`.

## Dependencies

### Internal
- `src/App.tsx` listens for navigation changes.
- Route components use `navigate()` for in-app route changes.

### External
- Browser History API.
- `clsx` and `tailwind-merge`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
