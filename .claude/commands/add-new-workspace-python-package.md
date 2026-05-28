---
name: add-new-workspace-python-package
description: Workflow command scaffold for add-new-workspace-python-package in govern-zone.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /add-new-workspace-python-package

Use this workflow when working on **add-new-workspace-python-package** in `govern-zone`.

## Goal

Adds a new Python package to the monorepo workspace, including registration, pyproject, source, tests, and CI workflow.

## Common Files

- `packages/{package}/pyproject.toml`
- `packages/{package}/README.md`
- `packages/{package}/src/{package}/__init__.py`
- `packages/{package}/tests/`
- `pyproject.toml`
- `tests/test_monorepo_invariants.py`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Create new package directory under packages/
- Add pyproject.toml, README.md, .gitignore, and Makefile
- Implement source files in src/{package_name}/
- Add tests in tests/
- Register package in root pyproject.toml [tool.uv.workspace].members

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.