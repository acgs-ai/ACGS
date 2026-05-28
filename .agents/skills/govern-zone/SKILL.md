```markdown
# govern-zone Development Patterns

> Auto-generated skill from repository analysis

## Overview

This skill covers the core development patterns, coding conventions, and operational workflows for the `govern-zone` repository. The codebase is primarily Python (with some frontend JavaScript/TypeScript), organized as a monorepo with multiple Python packages and a frontend app. It emphasizes strong workspace hygiene, contract-driven development, and robust CI/CD practices. This guide will help you contribute new features, maintain packages, manage readiness evidence, and keep the repository clean and production-ready.

## Coding Conventions

### File Naming

- **Python packages:** Use `camelCase` for filenames.
  - Example: `myFeatureModule.py`
- **Frontend (JS/TS):** Also uses `camelCase` for files and components.
  - Example: `UserDashboard.tsx`

### Imports

- **Python:** Use relative imports within packages.
  ```python
  from .utils import fetch_data
  ```
- **Frontend:** Standard ES module imports, often relative.
  ```javascript
  import { fetchUser } from './api/client'
  ```

### Exports

- **Python:** Named exports via explicit imports in `__init__.py`.
  ```python
  # __init__.py
  from .myFeatureModule import MyFeatureClass
  ```
- **Frontend:** Named exports.
  ```javascript
  export function useUserData() { ... }
  ```

### Commit Patterns

- Prefixes: `chore`, `fix`, `impl` (but freeform allowed)
- Example: `fix: correct package registration in pyproject.toml`

---

## Workflows

### Add New Workspace Python Package

**Trigger:** When introducing a new governed agent runtime or analyzer package.  
**Command:** `/new-python-package`

1. Create a new directory under `packages/{package}/`.
2. Add `pyproject.toml`, `README.md`, `.gitignore`, and `Makefile`.
3. Implement source files in `src/{package}/`.
4. Add tests in `tests/`.
5. Register the package in the root `pyproject.toml` under `[tool.uv.workspace].members`.
6. Update `tests/test_monorepo_invariants.py` to include the new member.
7. Add or update `.github/workflows/python-{package}.yml` for CI.

**Example:**
```bash
mkdir packages/myNewAgent
touch packages/myNewAgent/pyproject.toml
echo "# My New Agent" > packages/myNewAgent/README.md
# ...etc
```

---

### Add New Frontend Console Surface

**Trigger:** When adding a new operator-facing page or feature to the `acgi-ai` console.  
**Command:** `/new-console-page`

1. Create a new route file in `acgi-ai/src/routes/console/{Feature}.tsx`.
2. Register the route in `acgi-ai/src/routes/Console.tsx` (and sometimes `App.tsx`).
3. Update or add API client in `src/api/client.ts` and types in `src/api/types.ts`.
4. Add React Query hooks in `src/api/hooks.ts`.
5. Add or update MSW mock data and handlers in `src/mocks/data/` and `src/mocks/handlers.ts`.
6. Add or update CSS in `src/App.css`.
7. Add/extend invariant or smoke scripts in `scripts/`.
8. Update `package.json` test scripts if needed.

**Example:**
```tsx
// acgi-ai/src/routes/console/MyFeature.tsx
export function MyFeaturePage() {
  // ...
}
```

---

### Spec, Plan, and Implement Feature with Contracts and Tests

**Trigger:** When delivering a new major feature with traceable requirements and acceptance.  
**Command:** `/new-feature-spec-plan`

1. Draft feature spec and requirements in `specs/{feature}/`.
2. Write implementation plan, data model, and contracts (JSON Schema, OpenAPI).
3. Add `tasks.md` with granular task breakdown.
4. Implement backend package (see "Add New Workspace Python Package").
5. Implement frontend surface (see "Add New Frontend Console Surface").
6. Add/extend tests for backend and frontend.
7. Add/extend acceptance/README.md documenting evidence and acceptance.
8. Update readiness docs and evidence packet.

**Example:**
```markdown
# specs/agent-bus-analysis/spec.md
## Overview
...
```

---

### CI Gate Tighten or Fix

**Trigger:** When fixing failing CI, aligning root/package gates, or updating verification scope.  
**Command:** `/ci-align`

1. Update `Makefile` to include/exclude packages in lint/test/typecheck fan-out.
2. Update root `pyproject.toml` workspace.members.
3. Update or add `.github/workflows/*.yml` for affected packages.
4. Update `tests/test_monorepo_invariants.py` to match current package inventory.
5. Fix or update package-level test/lint/typecheck scripts as needed.

---

### Add or Update Readiness Evidence and Boundaries

**Trigger:** When updating readiness docs, adding evidence, or changing preflight/launch gating.  
**Command:** `/refresh-readiness-evidence`

1. Update `docs/readiness-evidence-matrix-*.md` and `docs/readiness-evidence-packet-*.md`.
2. Update scripts like `scripts/build_release_evidence.py` and `scripts/platform_readiness_report.py`.
3. Update or add tests for readiness evidence and preflight in `tests/`.
4. Update `acgi-ai/DEPLOY.md`, `PRODUCTION-LAUNCH.md`, and related docs.
5. Add or update Makefile targets for evidence/report generation.

---

### Update or Add .gitignore for Tool or Build Artifacts

**Trigger:** When preventing accidental commit of tool outputs, caches, or local artifacts.  
**Command:** `/update-gitignore`

1. Edit `.gitignore` or `packages/{package}/.gitignore` to add new patterns.
2. Document rationale in commit message.
3. Review with `git status` or similar.

**Example:**
```
# .gitignore
__pycache__/
*.pyc
dist/
```

---

### Remove or Extract Inactive or Experimental Package

**Trigger:** When cleaning up the workspace by removing unmaintained or experimental packages.  
**Command:** `/remove-package`

1. Delete the package directory and all files under it.
2. Remove the package from root `pyproject.toml` workspace.members if present.
3. Update docs or manifests referencing the package.
4. Archive externally if needed.

---

## Testing Patterns

- **Framework:** [vitest](https://vitest.dev/) (for frontend JS/TS)
- **Pattern:** Test files are named `*.test.js`
- **Python:** Tests are placed in `tests/` directories within each package and at the repo root for monorepo invariants.
- **Example (JS/TS):**
  ```javascript
  // myFeature.test.js
  import { myFeature } from './myFeature'
  test('should work', () => {
    expect(myFeature()).toBe(true)
  })
  ```
- **Example (Python):**
  ```python
  # tests/test_my_feature.py
  from myFeatureModule import my_feature

  def test_my_feature():
      assert my_feature() is True
  ```

---

## Commands

| Command                 | Purpose                                                         |
|-------------------------|-----------------------------------------------------------------|
| /new-python-package     | Scaffold and register a new Python package in the workspace     |
| /new-console-page       | Add a new operator-facing console page or feature               |
| /new-feature-spec-plan  | Deliver a new feature from spec to acceptance                   |
| /ci-align               | Align or fix CI gates, Makefile, and invariants                 |
| /refresh-readiness-evidence | Update readiness docs, evidence, and preflight scripts      |
| /update-gitignore       | Add or update .gitignore for tool/build artifacts               |
| /remove-package         | Remove or extract an inactive or experimental package           |
```
