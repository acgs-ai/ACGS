---
title: Documentation contributing guide
description: Local documentation verification commands and fallback behavior for missing tools.
---

# Documentation contributing guide

This repository currently has no checked-in MkDocs, markdownlint, Vale, or
codespell configuration. Use `docs/STYLEGUIDE.md` for style and run the tools
below when they are available locally.

## How to run locally

```bash
markdownlint "**/*.md"
vale docs/
codespell -q 3 .
mkdocs build --strict
```

If a tool is missing, do not mark that check complete. Record the command and
exit output in the PR notes, then install the tool using the repository's future
documented dependency path. Until a project config is added, recommended local
install options are:

- `npm install --global markdownlint-cli` for Markdown linting.
- `pipx install codespell` for spelling checks.
- `pipx install mkdocs` only after an MkDocs config is added.
- Follow the Vale installation guide for the host platform before running
  `vale docs/`.

## Link checks

Internal links and anchors are blocking. External links should be checked with a
five-second timeout and treated as warnings unless more than five fail or the
same failures persist after a retry.

## Pull request checklist

- [ ] Markdown style reviewed against `docs/STYLEGUIDE.md`.
- [ ] Internal links and anchors verified.
- [ ] External link warnings recorded.
- [ ] Changelog entry added under `docs/CHANGELOG.md` Unreleased.
- [ ] Docs build run, or skipped because no docs site config exists.
