# Permission Posture (govern-zone)

> Always-On: How Claude Code permission modes are set in this repo and why.
> Evidence, vendor citations, and the GitHub server-side-control audit live in the
> `permission-posture-research` skill — invoke it before auditing or changing permission
> rules, hooks, sandbox settings, or branch protection.

## Default: `acceptEdits`, not `bypassPermissions`

The recommended posture is `"defaultMode": "acceptEdits"`, set machine-locally in
`.claude/settings.local.json`. That file is personal and gitignored — a fresh clone does
NOT have it, so never assume this mode is active: check whether the file exists (and what
it sets) on the machine you are on, and create it if you want this posture. When set, file
edits proceed without a prompt (fast local iteration), but Bash and other side-effectful
tools still pass through the permission layer and the deny list. `bypassPermissions`
disables that layer wholesale — inappropriate as a standing default for a receipt-gated
governance repo where claim-safety and fail-closed behavior are the product.

**Never set `bypassPermissions` as the persisted `defaultMode`.** Enable it only for a
single session, on the command line, with a stated reason:

```bash
claude --permission-mode bypassPermissions   # reason: <e.g. bulk mechanical refactor, no side effects>
```

`skipDangerousModePermissionPrompt` is left as-is; it governs the interactive prompt, not
the standing mode.

## What actually enforces safety (the fail-closed layer)

Permission modes are convenience, not the security boundary. The enforcing layers are:

1. **PreToolUse receipt hook** — `.claude/hooks/acgs-emit-receipt.py` runs on `Edit|Write|MultiEdit`
   and `Bash` (see `.claude/settings.json`). It is the ACGS membrane applied to the agent's own
   side effects, and it fires regardless of permission mode.

   **Limitation — it is only fail-closed under `GOVE_ZONE_GATE_MODE=enforce`.** The hook's
   `_gate_enforce()` reads that env var; with anything else (including unset, the default) an
   import or emission failure exits 0 and the side effect proceeds. "No valid Decision Receipt,
   no side effect" therefore describes enforce mode only — in observe mode the hook is an audit
   emitter, not a gate. The var comes from the shell that launched `claude`, **not** from any
   settings file, so a session cannot tell from `.claude/**` alone which mode is live; check it
   the way the gate does (`GOVE_ZONE_GATE_MODE`) before claiming fail-closed behavior. Under
   enforce + `profile=production` with no configured signer, every in-repo `Edit`/`Write` fails
   closed — relaunch with `GOVE_ZONE_PROFILE=dev`, `GOVE_ZONE_GATE_MODE=observe`, or a real
   signer. **Do not route around a fail-closed refusal by writing files through `Bash`**; that
   lands the edit off the governed path and creates an audit-scope gap.
2. **The deny list** in `.claude/settings.json` — blocks `git push --force`, `git add -A`,
   `git reset --hard`, `git clean -f`, `git checkout master|main`, `gh release`, `gh secret`,
   `gcloud`, `vercel`, and all `.env` reads/writes.
3. **Seal / submodule PreToolUse hooks** — `seal-block.sh`, `submodule-warn.sh`.
4. **Global blocked-op / merge-with-verify guard** — `~/.claude/hooks/blocked-op-escalation-guard.mjs`,
   wired as a `PreToolUse` hook on matcher `Bash`. The hook self-filters by command; it must NOT be
   given a pseudo-expression matcher like `tool == "Bash" && ...`, which the matcher engine treats as
   a regex against the tool *name* and therefore never matches — the hook then silently never runs.
   In this repo every op on its `HUMAN_GATES` list is already hard-denied above, and a hard deny
   short-circuits the permission layer before any `PreToolUse` hook, so the guard's only live function
   here is the `gh pr merge` verify gate: allowed iff a fresh verify-pass marker exists for the current
   branch **and** is bound to the current HEAD SHA, else denied. That gate only works because
   `gh pr merge` is deliberately in `permissions.allow` rather than `deny`. It is an accident-preventer
   and audit trail, not an adversary-proof control — CI branch protection is the enforcement of record.

**Hooks are not a hard boundary.** Anthropic's own docs say to use the permission system, not a
hook, to enforce a hard allow or deny, and specify no precedence order between the two. Treat the
hook layer as intent inspection plus audit signal; do not describe it as the enforcement of record.

**The real boundary is the OS/network sandbox, and it is not fully armed here.** `sandbox` is at
stage 1 (observe): enabled, but `allowUnsandboxedCommands: true` and `failIfUnavailable: false`,
so it degrades rather than blocks. Until both flags flip, keep treating `.claude/**` as
accident-prevention plus audit trail. Details and current status: `permission-posture-research`.

## Deny rules are NOT a boundary against command chaining

A deny rule matches the literal command string. It does **not** stop a chained or obfuscated
invocation (e.g. `bash -c '...'`, `sh -c`, piping a script to an interpreter, env-var
indirection). **Treat the deny list as an accident-preventer and audit signal, not an
adversary-proof control.**

Three documented failure classes each have a live instance in this repo's allow-list —
subprocess reads bypassing `Read`/`Edit` denies, environment-runner wildcards
(`Bash(make:*)`, `Bash(pnpm:*)`, `Bash(uv:*)`) executing arbitrary inner commands, and fragile
argument-level patterns. **Do not claim the deny list closes them.** Specifics:
`permission-posture-research`.

## Server-side controls

Branch protection on `master` is the strongest layer available, and still not a boundary
against an admin — bypass is a documented design feature and `enforce_admins` is removable by
the same permission that sets it. Two rules that matter operationally:

- **A required check is satisfied by a name match, not by proof a gate ran.** `success`,
  `skipped`, and `neutral` all satisfy it. Never treat a green required context as evidence the
  gate executed — read the run.
- **All four required contexts are pinned to `app_id: 15368`. Do not remove that pinning.**
  Unpinned means any integration with write access can set the status.

Full audit (bypass mechanics, the public-repo + self-hosted-runner exposure, fork-PR approval
policy): `permission-posture-research`.
