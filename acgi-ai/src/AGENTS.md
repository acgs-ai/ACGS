<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-04 | Updated: 2026-05-04 -->

# src

## Purpose
This directory contains the full React application source for the ACGS marketing landing page and governance console. It owns bootstrapping, routing, styling, API access, MSW mocks, static imports, and route components.

## Key Files
| File | Description |
|------|-------------|
| `main.tsx` | React entrypoint; creates the React Query client, optionally starts MSW, and renders `<App />`. |
| `App.tsx` | Thin re-export of the active `@surface/App` route tree selected by Vite mode. |
| `App.css` | Main component stylesheet for marketing, console, responsive behavior, and page-specific layouts. |
| `index.css` | Design tokens, global reset, font imports, focus ring, and reduced-motion reset. |
| `fonts.css` | Self-hosted `@font-face` declarations for all runtime font families and subsets. |
| `csp-utilities.css` | CSP-safe utility and component-scoped classes used instead of inline styles. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `api/` | Fetch wrapper, API contract types, and TanStack Query hooks (see `api/AGENTS.md`). |
| `assets/` | Source-imported image and SVG assets (see `assets/AGENTS.md`). |
| `lib/` | Shared helpers such as navigation and class composition (see `lib/AGENTS.md`). |
| `mocks/` | MSW browser setup, handlers, and fixture data (see `mocks/AGENTS.md`). |
| `routes/` | Marketing, console shell, auth/privacy, not-found, and console page components (see `routes/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- Read `DESIGN.md` before visual changes.
- Preserve strict TypeScript settings; avoid unnecessary casts and keep imports type-only when required.
- Do not use inline styles or Tailwind utility class names in JSX.
- Use CSS custom properties from `index.css`; add new tokenized CSS instead of one-off hex values.
- Keep the console privilege banner visible and structural in `routes/Console.tsx`.

### Testing Requirements
- Run `pnpm lint` and `pnpm build` after source changes.
- For mock/API changes, ensure `src/api/types.ts`, `src/mocks/handlers.ts`, and `src/mocks/data/*` stay aligned.

### Common Patterns
- `App.tsx` derives route state from `window.location.pathname` and listens to `popstate`.
- `navigate(to)` is the app-level navigation primitive for internal route changes.
- Console pages consume data through `src/api/hooks.ts` rather than importing fixture data directly.
- Styling is plain CSS with project classes, not CSS modules and not Tailwind utilities.

## Dependencies

### Internal
- `public/static/fonts/` for self-hosted font files.
- `infra/Caddyfile` and `vercel.json` depend on route and asset path behavior.
- Root TypeScript, Vite, and Biome configuration.

### External
- React, React DOM, TanStack React Query, MSW, Vite, TypeScript, clsx, and tailwind-merge.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
