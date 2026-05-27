---
title: Documentation style guide
description: Repository rules for Markdown structure, headings, examples, and verification.
---

# Documentation style guide

Use this guide for new or materially updated Markdown in the govern-zone
workspace. Older planning and handoff files may predate this guide; avoid large
retrospective rewrites unless the owning package asks for them.

## Required structure

- Start docs with YAML frontmatter containing `title` and `description`.
- Use one `#` heading that matches the document purpose.
- Use sentence-case headings: capitalize the first word and proper nouns only.
- Keep each documentation change focused on one feature, package, or runbook.
- Prefer relative links for repository files.

## Code blocks and commands

- Add a language to every fenced code block, such as `bash`, `python`, `json`,
  `yaml`, or `text`.
- Mark terminal output as `text` when it is not meant to be copied.
- Include a short "How to run locally" section when a doc introduces a command,
  generated artifact, or verification workflow.

## Governance copy

- Separate local readiness evidence from live production proof.
- Do not claim production deployment, certification, legal approval, or hosted
  availability unless the referenced live evidence exists.
- Link policy, evidence, and package ownership through
  `docs/governance-stack-index.md` when a feature crosses package boundaries.
