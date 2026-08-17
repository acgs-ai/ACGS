---
name: permission-posture-research
description: Evidence and vendor-documentation research behind the govern-zone permission posture — why hooks and deny rules are not boundaries, where the real enforcement layer lives, and the current state of GitHub server-side controls on acgs-ai/ACGS. Invoke when auditing or changing permission rules, hooks, sandbox settings, or branch protection, or when someone claims a config layer is a security boundary.
---

# Permission Posture — Research & Evidence (govern-zone)

The operating directives live in `.claude/rules/permission-posture.md` (always loaded).
This file carries the evidence behind them. It is reference material, not a checklist —
read it when you need to justify, audit, or change one of those directives.

Researched 2026-07 through 2026-08-04.

## Why hooks are not the enforcement of record

Hooks run in the execution path on every matched call, which is why they beat a config
pattern at inspecting *intent*. They are **not** a hard boundary, and Anthropic says so:
the hooks documentation instructs you to "use the permission system rather than a hook to
enforce a hard allow or deny," and it specifies no general precedence order between hooks
and `permissions`. That relationship has regressed repeatedly in shipped releases — in
v2.1.84 a `PreToolUse` hook returning `permissionDecision: "ask"` defeated a matching
`permissions.deny` rule (anthropics/claude-code#39344, fixed v2.1.101, with four linked
sibling defects covering both directions). Treat the hook layer as intent inspection plus
audit signal, and do not describe it as the enforcement of record.

## Where the actual boundary lives

Per every major vendor's own documentation as of 2026-07, real enforcement is at the OS and
network layers, not in command-string matching: Claude Code's sandbox gives "OS-level
enforcement" that "holds regardless of what the model chose to run and even if an allowed
command does more than its name suggests," while permission rules only "block Claude from
even attempting" the access.

`sandbox` is configured in user settings at **stage 1 (observe)**: enabled, with `denyRead`
on `.env`, `~/.ssh`, `~/.aws`, and the `gh`/Claude credential files, and an allow-list of
build-registry domains — but `allowUnsandboxedCommands: true` and `failIfUnavailable: false`,
so it degrades rather than blocks.

**Stage 1 is not yet a boundary.** Both prerequisites that were outstanding are now met —
`socat` (needed by the Linux egress proxy) and `bwrap` are both installed at `/usr/bin`,
verified 2026-08-04. What remains before stage 1 becomes a boundary: confirm `make verify`
is green under the sandbox, then flip `allowUnsandboxedCommands` to `false` and
`failIfUnavailable` to `true`. Until both flags flip, keep treating `.claude/**` as
accident-prevention plus audit trail.

Observed behavior under the current config (2026-08-04): `/` and `/home` mount `ro`, with
read-write bind mounts punched through only for the allow-list (the project directory,
`~/.npm/_logs`, `~/.claude/debug`), and `denyRead` paths bind-mounted from `/dev/null`. So
the filesystem policy *is* being enforced today even in observe mode — a session cannot
write `~/.claude/settings.json` or `~/.claude.json` from inside the sandbox.

Even the OS layer is partial by vendor admission: the sandbox "reduces risk but is not a
complete isolation boundary," its proxy "does not terminate or inspect TLS" (domain fronting
stays open), `allowUnsandboxedCommands` defaults **true**, and `sandbox.failIfUnavailable`
defaults **false**, so a host without `bwrap` silently degrades to unsandboxed.

## The three deny-rule failure classes (each has a live instance in this repo)

Anthropic documents these; this repo's allow-list contains an instance of each. Do not claim
the deny list closes them.

- **`Read`/`Edit` deny rules do not cover subprocesses.** Verbatim from the permissions docs:
  they "apply to Claude's built-in file tools and to file commands Claude Code recognizes in
  Bash, such as `cat`, `head`, `tail`, and `sed`. They don't apply to arbitrary subprocesses
  that read or write files indirectly, like a Python or Node script that opens files itself."
  **Concrete gap here:** the `.env` `Read`/`Edit`/`Write` denies in `.claude/settings.json`
  are reachable through the `Bash(python3:*)`, `Bash(python:*)`, and `Bash(node:*)` allow
  rules in `.claude/settings.local.json` — allowed, so not even prompted. Anthropic's stated
  remedy is the sandbox.
- **Environment-runner wildcards match whatever follows.** The built-in wrapper-strip list
  (`timeout`, `time`, `nice`, `nohup`, `stdbuf`, `command`, `builtin`, `noglob`, bare `xargs`)
  is not configurable and excludes `direnv exec`, `devbox run`, `mise exec`, `npx`, and
  `docker exec`, so `Bash(devbox run *)` also matches `devbox run rm -rf .`. **Same shape
  here:** `Bash(make:*)`, `Bash(pnpm:*)`, and `Bash(uv:*)` each execute arbitrary inner
  commands (`pnpm exec`, `pnpm dlx`, `uv run python -c …`, any Makefile recipe). They are
  kept deliberately for velocity; the vendor's mitigation is one rule per inner command.
- **Argument-level patterns are fragile.** A rule shaped like `Bash(curl http://github.com/ *)`
  is defeated by flag reordering, protocol swap, HTTP redirects, `URL=… && curl $URL`, and
  extra whitespace. Prefer denying the binary and using `WebFetch(domain:…)`.

## Server-side controls: strongest available, still not a boundary against an admin

Researched against GitHub's own documentation 2026-07-30. A control binds an actor only when
it is held by a *different* principal — so for a repo where the same human holds admin, these
are accident-preventers plus an audit-log trail. State them precisely, never as absolutes.

`master` as of 2026-07-30: four required status checks with `strict: true` ("SaaS beta required
gate", "GitGuardian secret scan", "Socket supply-chain scan", "codex-review"), force-pushes and
deletions blocked, **`enforce_admins: true`** (enabled 2026-07-30 — the checks now bind the
repo owner's ordinary push path too), `required_approving_review_count: 0`.

- **Bypass is a design feature, not an oversight.** GitHub: "By default, the restrictions of a
  branch protection rule don't apply to people with admin permissions to the repository."
  Rulesets carry an explicit bypass-actor allowlist covering every rule in the set; where bypass
  is narrowed to "For pull requests only," GitHub frames the value as auditability, then adds
  that the actor "can then choose to bypass any branch protections and merge that pull request."
- **`enforce_admins` is removable by the permission that sets it.** Adding *and* removing admin
  enforcement both "require admin or owner permissions"; the same permission can `DELETE
  /branches/{branch}/protection` outright. Turning it on is a real constraint on the ordinary
  push path while enabled — and an audit entry when disabled — not an unbypassable boundary.
  The one config that might genuinely bind is an **org- or enterprise-level ruleset that does
  not list the repo admin as a bypass actor**. ACGS is org-owned (`acgs-ai`), so org rulesets
  and user/app/team push restrictions are available here; they are unavailable on personal repos.
- **A required check is satisfied by a name match, not by proof a gate ran.** `success`,
  `skipped`, **and** `neutral` all satisfy it. A job skipped by an `if:` conditional "reports
  'Success'. It will not prevent a pull request from merging, even if it is a required check,"
  and a job skipped because a `needs:` dependency failed "may not block merging" unless it uses
  `always()`. Never treat a green required context as evidence the gate executed — read the run.
  The counter-case bounds this: if the whole *workflow* is skipped by path/branch filtering the
  context stays Pending and blocks. So audit for required **jobs** that can skip inside a
  workflow that did trigger, not for skippable workflows. Compare
  `tests-docs-path-filtered-can-merge-red`.
- **One thing configured correctly here:** all four contexts are pinned to `app_id: 15368`.
  Unpinned (`app_id: -1`, or omitted) would mean "any app may set the status," and "any person
  or integration with write permissions to a repository can set the state of any status check."
  **Do not remove that pinning.**
- **Public repo + self-hosted runner is the live exposure.** `acgs-ai/ACGS` is **public**, and
  13 workflows use `runs-on: [self-hosted, …]` — including `python-gove-zone.yml`,
  `python-acgs-lite.yml`, `constitutional-hash.yml`, and `eval.yml` on the `pull_request`
  trigger. GitHub: self-hosted runners "do not have guarantees around running in ephemeral
  clean virtual machines, and can be persistently compromised by untrusted code in a workflow"
  and "should almost never be used for public repositories." The fork-PR approval policy was
  `first_time_contributors` (GitHub's default), which let a *returning* contributor's fork PR
  execute on this machine unapproved; it was set to **`all_external_contributors`** on
  2026-07-30, so every external run now needs explicit approval. That reduces the exposure but
  does not remove it — approving a fork PR still runs its code here, on a non-ephemeral runner.
  The durable fix is moving `pull_request`-triggered jobs off self-hosted. Mitigating:
  `default_workflow_permissions: read` and `can_approve_pull_request_reviews: false`.
  Non-ephemeral is the default, not a law — JIT runners "perform at most one job before being
  automatically removed."
