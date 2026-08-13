# Headless Delegation Contract (Claude lane)

> Moved to the `headless-delegation` skill (`.claude/skills/headless-delegation/SKILL.md`) —
> invoke it before any `claude -p` delegation. Non-negotiables that stay resident:
> always set `--max-turns` and an explicit `--allowedTools` allowlist; a headless run's
> pass claim is never auto-accepted — the parent re-runs the exact gate on the files on
> disk; `git push` / `gh pr merge` stay human-gated.
