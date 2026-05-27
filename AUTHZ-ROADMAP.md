# Authorization-Propagation Roadmap

> Phased plan to close the gap between `govern-zone/`'s current governance
> infrastructure and the seven structural requirements derived from
> Tallam, *Authorization Propagation in Multi-Agent AI Systems: Identity
> Governance as Infrastructure* (arXiv:2605.05440, 6 May 2026).

## Provenance and caveats

- **Source**: Single-author preprint. Verified directly against the arXiv
  abstract + HTML on 2026-05-10. Title, author, date, abstract, and the seven
  R1–R7 requirements are confirmed verbatim.
- **What is NOT verified**: the author's affiliation, the paper's "120×
  better than TTL" empirical claim, and the production-evidence platform
  (Section 9.6 of the paper says only "a production enterprise AI platform"
  with no name).
- **Status**: Treat the seven requirements as a design checklist worth
  building against. Treat the empirical claims as untested. Do not promote
  any of this to constitutional doctrine without independent replication.
- **Scope**: This roadmap covers `govern-zone/` as a multi-harness AI
  workspace. The frontend completion plan in `PLAN.md` is a different scope.

## Current state — what's already wired

| Component | Path | Relevance |
|---|---|---|
| Workspace audit | `.claude/skills/submodule-audit/` | Surfaces dirty state per repo |
| Hash integrity | `.claude/skills/constitutional-hash-verify/` | R6 candidate (currently initiation-time only) |
| Multi-harness coord | `.claude/skills/agent-coordination/` | Pre-R5 trace input |
| Diff-aware evals | `.claude/skills/braintrust-eval/` | Out of authz scope |
| Worker drift | `.claude/skills/governance-proxy-ops/` | Out of authz scope |
| Diff review | `.claude/agents/constitutional-validator.md` | Pre-R3 review, not enforcement |
| Cross-repo plan | `.claude/agents/submodule-coordinator.md` | Pre-R2 delegation log only |
| Submodule guard | `.claude/scripts/block-submodule-pointer.sh` | Single-purpose R3 instance |
| Lint on edit | `.claude/scripts/ruff-mypy-on-edit.sh` | Out of authz scope |
| Session handoff | `.claude/scripts/session-end-handoff.sh` | R5 substrate (no authz field yet) |

## Phasing principle

Order by dependency, then by cost. Two cheap wins land first to give a
substrate the rest can build on; identity comes before enforcement; recovery
and aggregation are last because they have the largest blast radius.

| Phase | Reqs | Effort | Blocked by |
|---|---|---|---|
| 1 — Foundation traces | R5 + R6 | 1–2 days | nothing |
| 2 — Identity model | R1 + R2 | 3–5 days | Phase 1 |
| 3 — Boundary enforcement | R3 | 1–2 weeks | Phase 2 |
| 4 — Recovery + aggregation | R7 + R4 | 1–2 weeks | Phase 3 |

---

## Phase 1 — Foundation traces (R5 + R6)

**R5 verbatim**: "Authorization traces must be workflow-scoped and
self-contained. The complete authorization history of a workflow must be
capturable as a single, inspectable artifact."

**R6 verbatim**: "Temporal validity must be a policy decision, not an
implementation default. The system must support configurable authorization
evaluation policies (initiation-time, access-time, completion-time)."

### Deliverables

1. **Extend `session-end-handoff.sh`** to emit an `authorization` block in
   `.omc/state/handoff-${session_id}.json`. Schema:
   ```json
   "authorization": {
     "principal": "claude-code:opus-4-7",
     "session_id": "...",
     "tool_calls": [
       {"tool": "Bash", "target": "git status", "evaluated_at": "access-time", "outcome": "allow"},
       {"tool": "Edit", "target": "ACGS/src/foo.py", "evaluated_at": "access-time", "outcome": "allow"}
     ],
     "delegations": [],
     "evaluation_policy": "access-time"
   }
   ```
2. **Annotate every existing check** with its evaluation-time policy:
   - `block-submodule-pointer.sh` → `access-time`
   - `constitutional-hash-verify.sh` → `initiation-time` (today; later: also `completion-time`)
   - Document the choice in each script's header comment.

### Exit criteria

- Every Claude Code session ends with a handoff JSON that contains a non-empty
  `authorization.tool_calls` array
- `grep -l "evaluated_at:" .claude/scripts/*.sh` returns every guard script
- A new script `.claude/skills/authz-trace-inspector/` reads any handoff JSON
  and prints a workflow-scoped audit log

### Builds on

`.claude/scripts/session-end-handoff.sh` (already captures repo state and
recent files; needs the `authorization` block grafted on)

---

## Phase 2 — Identity model (R1 + R2)

**R1 verbatim**: "Agent principals must be first-class authorization
subjects. Agents must have scoped identities with explicit, bounded
permissions."

**R2 verbatim**: "Delegation must be explicit, bounded, and auditable. When
an agent delegates to another agent, the authority transfer must be
recorded, scoped to the workflow, and subject to policy constraints."

### Deliverables

1. **Agent registry** at `.omc/state/agents.json`:
   ```json
   {
     "claude-code:opus-4-7":      {"capabilities": ["read", "edit", "bash:safe", "git:read"]},
     "claude-code:subagent:reviewer": {"capabilities": ["read", "git:read"], "delegated_from": "claude-code:opus-4-7"},
     "codex:gpt-5":               {"capabilities": ["read", "edit", "bash:safe"]},
     "hermes":                    {"capabilities": ["read"]},
     "omx":                       {"capabilities": ["read"]},
     "gemini":                    {"capabilities": ["read"]}
   }
   ```
   Capability strings are namespaced: `read`, `edit`, `bash:<class>`,
   `git:<verb>`, `mcp:<server>:<tool>`.
2. **Delegation log** in each handoff: when one agent invokes another (e.g.
   Claude spawns the constitutional-validator subagent), the call is
   captured with `(delegator, delegatee, capability_subset, workflow_id)`.
   Capability subset must be a subset of the delegator's set — enforced
   programmatically.
3. **`agent-identity` skill** to query "who am I, what can I do" and
   "what was delegated to whom this session".

### Exit criteria

- `cat .omc/state/agents.json | jq` returns every harness as a principal
- Any subagent invocation in a session log can be traced to its delegator
  and the capability subset granted
- Attempting to delegate a capability the parent does not hold fails loud

### Builds on

Phase 1's authz block (delegations live there); existing `.omc/state/`
directory; existing OMC subagent dispatch model

---

## Phase 3 — Boundary enforcement (R3)

**R3 verbatim**: "Authorization must be evaluated at every data retrieval
boundary. Not once at workflow initiation, but at every point where an
agent accesses a data resource."

### Deliverables

1. **Generic PreToolUse hook** at `.claude/scripts/authz-check.sh` that:
   - Reads the calling agent identity from environment / state
   - Looks up its capability set in `.omc/state/agents.json`
   - Maps the tool call (Bash command, Edit path, MCP tool) to a required
     capability
   - Allows or blocks (exit 2 with stderr message) per match
2. **Capability map** at `.claude/policies/capabilities.toml`:
   ```toml
   [Bash]
   pattern = "^git (status|log|diff|show|rev-parse)" → required = "git:read"
   pattern = "^git (add|commit|push|merge|reset)"   → required = "git:write"
   pattern = "^rm -rf"                              → required = "bash:destructive"

   [Edit]
   path_glob = "ACGS/core/**" → required = "edit:governance"
   path_glob = "**/*"          → required = "edit"
   ```
3. **Replace** `block-submodule-pointer.sh` with a capability-policy entry —
   the bespoke guard becomes data, not code.

### Exit criteria

- Every Bash, Edit, Write, MultiEdit, and MCP tool call passes through the
  capability check
- A capability-deficient agent (e.g. a read-only Hermes call attempting an
  Edit) is blocked with a clear stderr message naming the missing capability
- The bespoke `block-submodule-pointer.sh` is gone, its rule lives in
  `capabilities.toml`

### Builds on

Phase 2's identity registry; existing `settings.json` PreToolUse hook
plumbing

### Risk

Highest-blast-radius phase. A bug in the capability matcher blocks all tool
calls. Land behind an env-var kill switch (`AUTHZ_ENFORCE=0` bypasses)
during the first week.

---

## Phase 4 — Recovery + aggregation (R7 + R4)

**R7 verbatim**: "Recovery must be traceable through the synthesis graph.
When an authorization violation is discovered, the system must be able to
identify all results derived from the violated access."

**R4 verbatim**: "Aggregation policies must be expressible and enforceable.
The system must be able to define constraints on which resource
combinations are permitted for a given principal."

### R7 deliverables

1. **Synthesis graph builder** that walks `.omc/wiki/session-log-*.md`,
   claude-mem entries, and `.omc/state/handoff-*.json` to produce a DAG:
   nodes = (file, version, agent, session); edges = "agent A read file X
   then wrote file Y in session S".
2. **`authz-backtrace` skill**: given a file path + version, returns every
   downstream artifact derived from it. Pairs with R5's audit log to answer
   "which outputs are tainted by this revoked access?".

### R4 deliverables

1. **Aggregation policy DSL** at `.claude/policies/aggregation.toml`:
   ```toml
   [[forbid]]
   name = "constitution-and-secrets"
   description = "No single agent may read both the constitution config and any .env in one workflow."
   read_set = ["ACGS/.mcp.json", "ACGS/workers/governance-proxy/wrangler.toml"]
   plus_any = [".env*", "**/credentials.json"]
   ```
2. **Aggregation enforcer** runs at SessionEnd, reads the workflow's
   read-set from the handoff JSON, and flags violations in the audit log.

### Exit criteria

- `bash .claude/skills/authz-backtrace/run.sh ACGS/src/core/foo.py@HEAD~3`
  returns the full downstream artifact list
- An aggregation-policy violation produces a non-zero exit and a clear log
  entry pointing at the offending workflow
- At least one realistic forbidden-combination policy is checked into
  `aggregation.toml`

### Builds on

All of phases 1–3; gitnexus and claude-mem as the synthesis-graph data
sources

---

## Open questions

1. **Where does the authoritative agent identity come from at runtime?**
   Claude Code surfaces `session_id`. Codex, Hermes, OMX, Gemini each have
   their own session conventions. Phase 2 will need a uniform "current agent"
   resolution rule per harness.
2. **How are subagent capabilities scoped?** Phase 2 assumes capability
   subset must be ≤ parent. The paper's R2 says "subject to policy
   constraints". Could be policy lookup, could be intersection with parent.
   Pick one before Phase 2 deliverables.
3. **What's the kill-switch model for Phase 3?** A single `AUTHZ_ENFORCE`
   env var risks being left at `0` forever. Suggest pairing with a daily
   audit that fails CI if enforcement was disabled.
4. **What does aggregation actually need to forbid in ACGS specifically?**
   Phase 4's example is hypothetical. Need real "these two together are
   bad" cases to write meaningful policies. Worth a separate discovery pass
   before building the enforcer.

## Composition with existing infrastructure

Each phase explicitly extends what's already built — this is not a
rewrite. The five existing skills + two agents + three hook scripts
become the substrate. The new pieces are: handoff schema extension
(phase 1), agent registry + delegation log (phase 2), generic
capability-check hook + policy file (phase 3), synthesis-graph
backtrace + aggregation enforcer (phase 4).

## What this roadmap does NOT cover

The Tallam paper focuses narrowly on authorization propagation. The full
ACGS governance stack also requires:

- Constitutional interpretation and policy conflict resolution
- Legal compliance mapping (EU AI Act, sectoral regimes)
- Model risk assessment (separate from authz)
- Human appeal processes
- Full MACI separation-of-powers (Tallam's R1–R7 are necessary, not
  sufficient — see arXiv:2604.23646 for the structural separation paper
  the literature search summary mentioned as a complementary read)

These belong in separate roadmap files. Don't conflate.
