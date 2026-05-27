# OpenSwarm vs `govern-zone/` Stack — Comparison

> Read-only study of [VRSEN/OpenSwarm](https://github.com/VRSEN/OpenSwarm) (v0.1.27, MIT, ~2k★, last release 2026-04-22) cloned at `external/openswarm/`. Goal: map its multi-agent model against what's already in this workspace, identify what's worth borrowing, what's redundant, and what would be needed to govern it under the AUTHZ + MACI roadmaps.

## What OpenSwarm actually is (verified from clone, not README)

- **Language**: Python (the npm package wraps a Python core via `python swarm.py`)
- **Architecture**: 1 orchestrator (`orchestrator/`) + 7 specialist agents as sibling Python packages (`data_analyst_agent/`, `deep_research/`, `docs_agent/`, `image_generation_agent/`, `slides_agent/`, `video_generation_agent/`, `virtual_assistant/`)
- **Framework dependency**: `@vrsen/agentswarm` (Agency Swarm); Playwright; Composio (when keyed)
- **Entry points**: `swarm.py` (CLI), `server.py` (HTTP on :8080), `bin/openswarm` (npm-installed CLI wrapper)
- **Each agent owns its own `tools/` dir**; `shared_tools/` for cross-agent
- **Marketed as fork-and-prompt**: "Tell Claude Code 'turn this into an SEO swarm' — they'll automatically customize all agents"
- **Notable**: ships with `.claude/`, `.omc/`, `.remember/` dirs out of the box — VRSEN develops it on the same OMC + claude-mem harness this workspace uses

## OpenSwarm vs the existing `govern-zone/` stack

| Capability | OpenSwarm | `govern-zone/` equivalent | Verdict |
|---|---|---|---|
| Multi-agent orchestration | Hierarchical: 1 orchestrator → 7 specialists | OMC: `team`, `autopilot`, `ralph`, `ultrawork`, parallel agent dispatch | **Govern-zone is more general.** OpenSwarm's hierarchy is hardcoded to content-creation specialists. |
| Specialist scope | Content (slides, video, image, docs, research, data analysis) | Code/infra (constitutional-validator, submodule-coordinator, code-reviewer, design-shotgun, etc.) | **Different domain, no overlap.** |
| Tool integrations | Composio (10K+) when keyed; Playwright; pptxgenjs | Cloudflare suite (15 MCP), gitnexus, gbrain, exa, tavily, sequential-thinking, claude-in-chrome | **Govern-zone has deeper code/infra MCPs; OpenSwarm has Composio breadth for end-user-app integrations.** |
| Browser/QA | Playwright direct | gstack `/browse`, `/qa`, `/canary`, claude-in-chrome MCP | **Govern-zone exceeds.** |
| Persistent memory | None observable in core | claude-mem + gbrain + `.remember/` + auto-memory | **Govern-zone exceeds.** |
| Process discipline | None | superpowers (TDD, brainstorming, executing-plans, verification, code-review) | **Govern-zone exceeds.** |
| Capability tokens / authz / audit | **None** | None today; AUTHZ + MACI roadmaps targeting this gap | **Both lack it. OpenSwarm makes it worse by design (fork-and-prompt agent creation).** |
| Atomic-agents context providers | None — Agency Swarm uses different abstractions | `atomic-agents-playground/` scaffold | **Different framework choice.** |

## What's worth borrowing from OpenSwarm

1. **Specialist-per-package layout.** Each agent is a self-contained Python package with its own `tools/`. Cleaner than the current `govern-zone/.claude/agents/*.md` flat layout once subagents grow tools beyond Bash/Read/Grep. Worth lifting if/when a constitutional-validator or submodule-coordinator agent needs custom tooling.
2. **Single HTTP entry point** (`server.py` on :8080) for "agent system as a service". If the eventual ACGS frontend at `acgi-ai/` needs a programmable backend for governance workflows, this shape is a reference.
3. **Graceful degradation on missing keys** (their README explicitly: "Tools gracefully degrade when keys are missing"). The atomic-agents playground does this for OpenAI; worth generalizing the pattern when Cloudflare/GCP/etc. credentials may be absent.
4. **Composio as a single MCP-ish bridge** to 10K integrations. Worth evaluating as an alternative to wiring per-service MCPs (Slack, Gmail, GitHub) one at a time. Caveat: Composio is itself a third-party authz boundary — adopting it means trusting Composio with delegated credentials, which conflicts with both AUTHZ R3 and MACI Phase 2.

## What's redundant

1. **Orchestrator pattern** — OMC's `team`/`autopilot`/`ralph` already do this with more flexibility.
2. **Per-agent specialist set** — the 7 specialists are content-creation roles; `govern-zone` is a code/infra workspace where these don't apply.
3. **Browser tooling** — gstack + claude-in-chrome already exceed Playwright-direct.

## What governing OpenSwarm would require (the AUTHZ/MACI lens)

If OpenSwarm were imported as a target system to govern (the rejected option from the choice menu), here's the gap from its current state to MACI Phase 2 compliance:

| MACI requirement | Gap in OpenSwarm |
|---|---|
| C1 (IVL + MinimalCapSet) | Agents have unscoped tool access; no per-call capability check. Need to wrap every agent's `tools/` registry with a token gate. |
| C2 (ILT + lineage) | Orchestrator routes by free-text prompt with no NLR anchor. Need to hash original user request and propagate through delegations. |
| C3 (Goal Drift) | "Fork and prompt to repurpose" pattern is *deliberately* drift-permissive. Goal drift detection would need to be opt-in per-deployment, not enforced at framework level. |
| Layer separation (Policy / Authz / Execution) | All three are conflated in each agent's `run()` method. Refactor would touch every agent file. |
| Capability tokens (HMAC-SHA256, TTL, single-use) | Zero token concept exists. Net-new substrate. |

**Conclusion on governability**: OpenSwarm is structurally hostile to the AUTHZ/MACI model — its core value proposition (rapid agent customization by free-text prompt) directly conflicts with R2 (bounded delegation) and C3 (goal drift detection). Governing it would require either a fork that fundamentally changes its UX, or a wrapping pattern that intercepts all tool calls at the Composio/Playwright boundary. Both are non-trivial.

## Cross-references

- `AUTHZ-ROADMAP.md` — the requirements OpenSwarm fails today
- `MACI-ROADMAP.md` — the architecture an OpenSwarm-style system would need to adopt
- `atomic-agents-playground/` — the alternative scaffold this workspace settled on (different multi-agent framework)
- `external/openswarm/` — the cloned source (read-only; do not modify)

## What to do about the clone

Three reasonable options:

1. **Keep as study material** at `external/openswarm/`. Untracked under govern-zone's git; will be picked up by `submodule-audit` as an independent repo. No further action.
2. **Add to `.gitignore`** so it doesn't pollute `git status` if you want a clean dirty-files baseline.
3. **Delete after this comparison is read** — it's a shallow clone, easy to recreate.

Recommended: option 2 (gitignore the path), keep the clone for occasional reference without it polluting the workspace audit.
