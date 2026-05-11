# Dual-Port Legal AI — Dependency Impact Note

Status: supporting note for the stakeholder PRD package
Scope: Ontario and Federal Canadian legal AI workflow requirements
Date: 2026-05-11

## Decision

The PRD package does **not** require any new runtime, build, model-provider, browser, or package-manager dependency. The first build phase should be treated as a documentation, workflow, policy, and configuration exercise until product leadership explicitly approves a technical implementation plan.

## Why this matters

For a legal workflow that handles confidential client information, adding dependencies too early increases review burden and can create unapproved paths for data retention, telemetry, prompt routing, or authority-source lookup. The initial PRD should therefore describe roles, output boundaries, source expectations, escalation rules, and launch gates without implying that any new third-party service, SDK, model gateway, or package must be adopted.

## PRD constraint to carry forward

Any future implementation ticket that proposes a new dependency must include:

1. **Purpose** — what legal-workflow problem the dependency solves.
2. **Data handling** — whether confidential, personal, privileged, or court-facing material leaves the controlled environment.
3. **Source and authority impact** — whether the dependency changes how official court websites, CanLII, Ontario e-Laws, or other approved legal sources are retrieved or presented.
4. **Human-review impact** — whether it changes lawyer verification, client-facing boundaries, or escalation thresholds.
5. **Security and privacy review** — approval for retention, logging, telemetry, access controls, and vendor/model use before launch.
6. **Rollback plan** — how the workflow returns to the prior dependency set if the dependency is rejected or fails review.

## Non-goals

- This note does not approve any vendor, legal-content database, AI model, SDK, browser automation package, or storage service.
- This note does not claim compliance certification or authorize autonomous legal advice.
- This note does not replace lawyer review, confidentiality analysis, or final disclaimer approval.

## Verification performed

The workspace dependency manifests were enumerated without editing them. The PRD package work in this lane changed only this Markdown note and did not modify `package.json`, lockfiles, `requirements*.txt`, `pyproject.toml`, or `uv.lock` files.
