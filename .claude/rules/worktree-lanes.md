# Parallel Worktree Lanes (govern-zone)

> Moved to the `worktree-lanes` skill (`.claude/skills/worktree-lanes/SKILL.md`) —
> invoke it when opening or cleaning up `claude -w` lanes. Non-negotiables that stay
> resident: one lane == one branch == one package (never two lanes editing the same
> package); nested repos (`acgs-lite`, `Acgs-Swarm`, `clinicalguard`) are NEVER
> worktree'd from the parent; never force-remove a lane with uncommitted work you
> did not create.
