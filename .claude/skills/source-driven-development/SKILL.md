---
name: source-driven-development
description: Make ACGS framework decisions from exact local versions plus feature-specific official docs before implementation.
---

# source-driven-development

Use for framework or tool changes under `ACGS/govern-zone`.

Process:
1. Load the nearest `AGENTS.md` / `CLAUDE.md` before touching package files.
2. Detect exact versions from the owning manifest before making framework decisions:
   - `acgi-ai/package.json` for React, Vite, TanStack, MSW, TypeScript, Tailwind.
   - workspace `pyproject.toml` and package-local `pyproject.toml` for Python and FastAPI-related work.
   - `.github/workflows/*.yml` plus referenced actions for CI syntax or runtime changes.
3. Start from official docs, then fetch the feature-specific page that matches the exact API you are changing. Do not stop at landing pages when the change depends on a specific hook, router API, dependency pattern, response model, config flag, or workflow key.
4. Cite full official URLs in the final handoff. Add code comments only when the citation materially helps a future maintainer.
5. Surface conflicts explicitly when official guidance and current project conventions diverge; do not silently pick one.
6. Prefer project conventions only after confirming they are still compatible with the exact installed version.

Starting points only — drill down to feature-specific pages before implementation decisions:
- React: https://react.dev/reference/react
- Vite: https://vite.dev/guide/
- FastAPI: https://fastapi.tiangolo.com/tutorial/
- TanStack Query: https://tanstack.com/query/latest/docs/framework/react/overview
- MSW: https://mswjs.io/docs/
- GitHub Actions: https://docs.github.com/actions
