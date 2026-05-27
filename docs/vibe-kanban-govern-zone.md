# Vibe Kanban for govern-zone

This is the project-specific Vibe Kanban runbook for `/home/martin/finished work/govern-zone`.

Vibe Kanban is useful here as a local kanban UI for dispatching Claude Code and Codex attempts into isolated worktrees. Treat it as an orchestration surface, not as the governance boundary: the repository rules in `AGENTS.md`, `CLAUDE.md`, `MONOREPO.md`, package-local agent guides, and local verification gates remain authoritative.

## Launch

```bash
cd "/home/martin/finished work/govern-zone"
npx vibe-kanban
```

MCP server mode for task management from another MCP client:

```bash
npx vibe-kanban --mcp
```

Vibe stores local state under `~/.local/share/vibe-kanban/` on this Linux host. Do not commit that directory or copy secrets from it into the repo.

## Repository settings

Use Vibe Settings -> Projects & Repositories and configure the govern-zone repository with these values.

| Field | Value |
|---|---|
| Repository path | `/home/martin/finished work/govern-zone` |
| Branch prefix | `vk/` |
| Default working directory | repository root |
| Setup script | `bash scripts/vibe-kanban-setup.sh` |
| Cleanup script | `bash scripts/vibe-kanban-cleanup.sh` |
| Dev server script | `bash scripts/vibe-kanban-dev-server.sh` |
| Parallel setup script | off by default for this monorepo |

The setup script is preflight-only by default. If a fresh Vibe worktree needs dependencies installed, set this environment variable for that workspace before running setup:

```bash
VK_GOVERN_ZONE_INSTALL=1 bash scripts/vibe-kanban-setup.sh
```

That mode runs only frozen installs:

```bash
pnpm install --frozen-lockfile
uv sync --all-extras --frozen
```

## Agent profiles

Do not use Vibe's built-in `DEFAULT` Claude Code or Codex profiles for governed work in this repo. Vibe's source currently ships unsafe defaults for maximum autonomy: Claude Code default enables `dangerously_skip_permissions`, and Codex default uses `danger-full-access` sandboxing.

Use the safe example variants in `docs/vibe-kanban-profiles.example.json` as a copy/paste seed for `~/.local/share/vibe-kanban/profiles.json`, then select these variants in Vibe tasks:

| Variant | Use for | Notes |
|---|---|---|
| `CLAUDE_CODE:ACGS_PLAN` | architecture/read-only planning | plan mode, approvals enabled, no dangerous permission bypass |
| `CLAUDE_CODE:ACGS_SUPERVISED` | supervised edits/reviews | approval prompts enabled, no dangerous permission bypass |
| `CODEX:ACGS_READONLY` | inspection and scoped review | read-only sandbox with on-request approvals |
| `CODEX:ACGS_WORKSPACE_WRITE` | bounded implementation attempts | workspace-write sandbox with unless-trusted approvals |

Recommended loop:

1. Create a Vibe task with a narrow objective and explicit paths.
2. Assign `CLAUDE_CODE:ACGS_PLAN` if the task is ambiguous or architectural.
3. Assign `CODEX:ACGS_WORKSPACE_WRITE` for bounded implementation after the plan is clear.
4. Run `bash scripts/vibe-kanban-verify.sh` before merging/reconciling changes.
5. For multi-package changes, run `make verify` or `VK_GOVERN_ZONE_VERIFY_SCOPE=full bash scripts/vibe-kanban-verify.sh`.

## MCP client snippet

For Claude Code or another MCP-capable client, use a local stdio server. Example JSON:

```json
{
  "mcpServers": {
    "vibe-kanban": {
      "command": "npx",
      "args": ["-y", "vibe-kanban@latest", "--mcp"]
    }
  }
}
```

Keep this as local/user config unless the team intentionally standardizes on Vibe MCP. Do not commit user auth state or Vibe local data.

## Verification scopes

`bash scripts/vibe-kanban-verify.sh` defaults to `quick`:

| Scope | Command | What it does |
|---|---|---|
| quick | `bash scripts/vibe-kanban-verify.sh` | constitutional hash drift (with the repo's known unavailable `packages/clinicalguard/` prefix ignored), shell syntax, profile JSON parse |
| conductor | `VK_GOVERN_ZONE_VERIFY_SCOPE=conductor bash scripts/vibe-kanban-verify.sh` | runs starter-kit tests if `acgs_conductor_integration_starter/` exists |
| frontend | `VK_GOVERN_ZONE_VERIFY_SCOPE=frontend bash scripts/vibe-kanban-verify.sh` | `pnpm -F acgi-ai lint` and build, requires Node 24 |
| full | `VK_GOVERN_ZONE_VERIFY_SCOPE=full bash scripts/vibe-kanban-verify.sh` | `make verify` |
| all | `VK_GOVERN_ZONE_VERIFY_SCOPE=all bash scripts/vibe-kanban-verify.sh` | quick, conductor, frontend, full |

Current caveat: `acgi-ai/package.json` requires Node `>=24 <25`. On hosts with Node 22, the dev-server and frontend verification scripts fail fast with a clear Node version error instead of producing misleading Vite failures.

## Cleanup

Vibe cleanup should be safe to run repeatedly:

```bash
bash scripts/vibe-kanban-cleanup.sh
```

It removes transient caches (`__pycache__`, `.pytest_cache`, `.ruff_cache`, `.mypy_cache`, `.turbo`, coverage outputs) and preserves source, `.venv`, `node_modules`, and nested repos. To remove known non-source build outputs as well:

```bash
VK_GOVERN_ZONE_AGGRESSIVE_CLEAN=1 bash scripts/vibe-kanban-cleanup.sh
```

## Governance notes

- Treat `packages/acgs-lite` and `packages/Acgs-Swarm` as nested git repositories. Stage or commit from inside those repos only when explicitly requested.
- Never use `git add -A` or `git add .` in this workspace.
- Do not alter files containing `# Constitutional Hash:` markers without a deliberate hash update workflow.
- Console-origin code under `acgi-ai/src/routes/console/**` remains privileged; avoid public-only CDN/script patterns.
- Vibe task prompts should include the verification scope and path boundary up front.
