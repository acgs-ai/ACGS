---
name: docs-hdn
description: "Use when creating or updating codebase documentation, README changes, docs-only PRs, or pre-merge docs verification."
---

## docs-hdn

Purpose
- Provide a concise, repeatable workflow to create, format, and verify documentation in the codebase, including build and lint edge cases.

When to run
- New or updated documentation, README changes, docs-only PRs, or pre-merge verification.

Inputs
- Markdown files or drafts in a feature/docs/* or user branch (any branch other than main).
- Optional input: docs config file at docs/mkdocs.yml or docs/_bookdown.yml. If present, use that config for build/link checks; if absent, skip generator-specific build steps and only run generic link/lint checks.

Outputs
- Linted and link-checked markdown files ready for a PR.

Steps
1. Create or update markdown under the appropriate docs/ or module folder.
2. Follow the repository style defined in docs/STYLEGUIDE.md. If docs/STYLEGUIDE.md is absent, apply: 1) top-level headings use sentence case; 2) include YAML frontmatter with title and description; 3) fenced code blocks specify language. Keep content focused and minimal.
3. Run markdown linters and spellcheckers in ordered checks:
	- Detect the repository-configured markdown linter by checking for config files such as `.markdownlintrc`, `.markdownlint.json`, `.vale.ini`, or `docs/.vale.ini`, or by looking for docs lint scripts in `package.json`. If found, run it and record the tool name.
	- If no configured markdown linter is detected, run `markdownlint "**/*.md"`.
	- Check `vale --version`; if it succeeds, run `vale` as an additional style check. If not installed and Vale is documented in `docs/requirements.txt` or `package.json`, install it before running.
	- Run `codespell -q 3 -w .` only when the repository has no preferred spellchecker. If `codespell` is not installed, note this in the PR but do not fail the lint step.
	- Define required tools as the repository-configured markdown linter and the repository's documented build tool. If any required tool is missing or misconfigured, attach the failing command, stdout/stderr, and full exit output to the PR; mark lint incomplete; and add install instructions to docs/CONTRIBUTING.md. Treat non-zero exit codes as lint failures unless the tool documents otherwise.
4. Verify links, anchors, and asset references with explicit retry policy:
	- First check all internal links, anchors, and relative image/asset links inside the repo. Any broken internal link or asset fails and blocks merge.
	- Then check external links and external asset URLs using a chosen linkchecker (for example `linkchecker` or the mkdocs linkcheck plugin) with a per-request timeout of 5s.
	- Retry each external link once after a 10s delay. Treat a link as persistent only if it fails both attempts.
	- Record persistent external failures as warnings in the PR. If more than 5 external links fail after retry, mark the issue as blocking.
5. Run docs build when the repo uses a static site generator:
	- Detect a static site generator by checking for known config files: `mkdocs.yml`, `docs/mkdocs.yml`, `bookdown/_bookdown.yml`, or `mkdocs-config.yml`.
	- If none are found, skip the build step.
	- If multiple configs are found, prefer the one referenced in docs/README or a specified repo variable `DOCS_BUILD_CMD`.
	- If the repository specifies a different build command, run that command instead of `mkdocs build --strict`.
	- Only attempt `mkdocs build --strict` when a mkdocs config file is detected.
	- If any build command fails, attach the full logs to the PR, do not check the Build box, and request follow-up from the docs maintainer.
6. Add a short changelog entry to docs/CHANGELOG.md under an Unreleased heading using the format: YYYY-MM-DD — <short summary> (author). If docs/CHANGELOG.md does not exist, create it with an Unreleased heading and the changelog entry. If the repository uses a different changelog location, add the entry there and note the location in the PR.

Commands (examples)
- markdownlint "**/*.md"
- vale docs/
- codespell -q 3 -w .
- mkdocs build --strict

Verification checklist (to include in PR template)
- [ ] Linted: zero errors from the repository's configured markdown linter. If the repo uses markdownlint or vale, ensure zero errors from those tools; if the repo uses a different linter, ensure zero errors from that tool and name it in the PR checklist.
- [ ] Links: no broken internal links, anchors, or repo-relative asset links
- [ ] Spelling: no obvious typos
- [ ] Build: docs site builds without errors
- [ ] Changelog: short entry added to docs/CHANGELOG.md under Unreleased or equivalent repo changelog location
- [ ] Clear description and context in PR

Notes
- Limit documentation changes to 1000 words per file (count words in rendered markdown excluding YAML frontmatter and fenced code blocks) and no more than 5 files per PR. If exceeded, split into multiple PRs and reference them in a parent tracking issue. Include runnable examples and a short "How to run locally" section.

$CURSOR$
