> **Internal engineering document.** Not part of the public release artifact.

# Agent Stack Governance Map — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a claim-safe map that positions ACGS as the receipt-gated governance membrane below the agent-builder stack (MCP/LangGraph/A2A), plus a 3-tier "governance posture" contrast in the comparison doc.

**Architecture:** Two documentation edits, no code. One new file (`docs/AGENT_STACK_GOVERNANCE.md`) carries the diagram, narrative, and a maturity-flagged insertion-point table whose every `exists` row is backed by a real file path. One edit extends `docs/COMPARISON.md` with a 3-tier posture block that cross-links the existing Microsoft-AGT section rather than duplicating it. Each task ends green on the repo's own docs gates.

**Tech Stack:** Markdown; Python doc gates (`make lint-docs` → `scripts/check_governance_stack_index.py`; `tests/docs/` via pytest).

## Global Constraints

Every task's requirements implicitly include all of these (verbatim from the spec):

- **Zero overclaim:** every cell flagged `exists` is backed by a real file path verified by reading it this session. `partial`/`thin` are labeled as such, never dressed up.
- **Forbidden claims** (per `AGENTS.md`): do NOT describe ACGS as compliance-certified, regulator-approved, or production-ready. The map describes mechanism, not accreditation. Include the explicit "technical membrane, not a compliance certification" caveat.
- **No new code**, **no marketing-page edit** (200 KiB perf budget → separate task), no SVG/diagram tooling (ASCII diagram only).
- **Work location:** isolated worktree `/home/martin/Documents/ACGS-wt/stackmap-spec`, branch `agent/stackmap-spec`, which is 1 commit ahead of `origin/master`, 0 behind. Use ordinary `git add <explicit path>` + `git commit` (hooks run). Never `git add -A`.
- **Gate-clean:** `make lint-docs` and `python -m pytest tests/docs -q` must pass before the final commit.
- **Verified maturity grid (do not re-derive — use these exact paths/flags):**
  - MCP → `exists` → `acgs_governance_eval_mvp/governed_mcp_v0/mcp_server.py` (+ `server.py`, `policy.py`, `verify.py`) and `packages/acgs-lite/src/acgs_lite/integrations/mcp_server.py`
  - Generic runtime hooks (Claude Code PreToolUse, Codex apply_patch) → `exists` → `packages/gove-zone/src/gove_zone/integration.py`
  - Tau-bench-style eval → `exists (adjacent)` → `acgs_governance_eval_mvp/governance/benchmarks/{agentdojo,injecagent,toolemu}_adapter.py`
  - LangGraph → `partial` → `acgs_governance_eval_mvp/governance/adapters/langgraph.py` (58-LoC reference sketch, "no real langgraph dependency required")
  - A2A → `thin` → only a docstring mention in `packages/gove-zone/src/gove_zone/integration.py`; no A2A adapter/AgentCard/discovery

---

### Task 1: Create `docs/AGENT_STACK_GOVERNANCE.md`

**Files:**
- Create: `docs/AGENT_STACK_GOVERNANCE.md`
- Create (verification helper, temporary): `/home/martin/.claude/jobs/123eb425/tmp/check_stackmap.py`

**Interfaces:**
- Consumes: the verified maturity grid in Global Constraints (exact paths/flags).
- Produces: a published map file other tasks/waves reference; the `partial`/`thin` rows that Wave 2/3 target.

- [ ] **Step 1: Write the failing verification check**

Create `/home/martin/.claude/jobs/123eb425/tmp/check_stackmap.py`:

```python
import re, sys, pathlib
ROOT = pathlib.Path("/home/martin/Documents/ACGS-wt/stackmap-spec")
doc = ROOT / "docs/AGENT_STACK_GOVERNANCE.md"
if not doc.exists():
    print("FAIL: doc missing"); sys.exit(1)
text = doc.read_text(encoding="utf-8")
# 1. every "exists"-flagged path must resolve
exist_paths = [
    "acgs_governance_eval_mvp/governed_mcp_v0/mcp_server.py",
    "packages/acgs-lite/src/acgs_lite/integrations/mcp_server.py",
    "packages/gove-zone/src/gove_zone/integration.py",
    "acgs_governance_eval_mvp/governance/benchmarks/agentdojo_adapter.py",
    "acgs_governance_eval_mvp/governance/adapters/langgraph.py",
]
missing = [p for p in exist_paths if not (ROOT / p).exists()]
if missing:
    print("FAIL: cited paths do not resolve:", missing); sys.exit(1)
# 2. each cited path must actually appear in the doc
absent = [p for p in exist_paths if p not in text]
if absent:
    print("FAIL: paths not cited in doc:", absent); sys.exit(1)
# 3. forbidden overclaims must be absent
forbidden = ["compliance-certified", "regulator-approved", "production-ready", "production ready"]
hits = [w for w in forbidden if re.search(re.escape(w), text, re.I)]
if hits:
    print("FAIL: forbidden claim phrases present:", hits); sys.exit(1)
# 4. the required honest caveat must be present
if "not a compliance certification" not in text:
    print("FAIL: missing technical-membrane caveat"); sys.exit(1)
# 5. all three maturity flags present
for flag in ("exists", "partial", "thin"):
    if flag not in text:
        print(f"FAIL: maturity flag '{flag}' missing"); sys.exit(1)
print("PASS"); sys.exit(0)
```

- [ ] **Step 2: Run the check to verify it fails**

Run: `python3 /home/martin/.claude/jobs/123eb425/tmp/check_stackmap.py`
Expected: `FAIL: doc missing` (exit 1)

- [ ] **Step 3: Write the document**

Create `docs/AGENT_STACK_GOVERNANCE.md` with exactly this content:

````markdown
# The Agent Stack Governance Map

Where ACGS / gove-zone sits in the modern agent-builder stack, and how it
differs from the alternatives. Companion to [COMPARISON.md](COMPARISON.md).

## The stack, and the line everyone skips

The agent ecosystem races to give agents more agency — protocol-level
delegation (A2A), tool access (MCP), autonomous planners (Deep Agents), and
voice agents that take real actions for real customers. "The best agents are
simple" — but simple agents still fire irreversible side effects.

All that energy sits *above* the action line. The line itself — *should this
action actually execute?* — is mostly ungoverned, or governed only by
after-the-fact logging.

ACGS owns the line. It is the execution membrane below agent reasoning and
above side-effectful tools, where **no valid Decision Receipt → no side
effect**.

```
  AGENT REASONING / ORCHESTRATION              models: Claude · GPT · Gemini
  Sierra · LangGraph · Deep Agents · planners      (decide WHAT to do)
                     │ proposes action
                     ▼
   ╔══════════════════════════════════════════════════════════════╗
   ║  ACGS GOVERNANCE MEMBRANE   "no valid receipt → no effect"    ║
   ║  policy gate → Decision Receipt → fail-closed executor        ║
   ║  audit chain · single-use receipts · replay / proof-pack      ║
   ╚══════════════════════════════════════════════════════════════╝
      ▲ MCP                  ▲ LangGraph              ▲ A2A / agent-bus
   governed_mcp_v0 +      adapters/langgraph.py    integration.py
   acgs-lite MCP          (reference sketch)       (docstring only)
   [exists]              [partial]                [thin]
                     │ permitted action only
                     ▼
  SIDE-EFFECTFUL TOOLS / WORLD
  refunds · bookings · DB writes · sends · code edits
```

The ecosystem adds agency *above* the line; ACGS owns the line; and it already
reaches into the stack at three honest maturity levels.

## Insertion points (verified maturity)

Each maturity flag was verified by reading the file. Nothing is flagged
`exists` without a runnable, tested implementation.

| Stack entry | ACGS insertion point | File(s) | Maturity |
|---|---|---|---|
| MCP tool calls | Governed MCP server (gate before tool admission) | `acgs_governance_eval_mvp/governed_mcp_v0/mcp_server.py`; `packages/acgs-lite/src/acgs_lite/integrations/mcp_server.py` | **exists** |
| Generic runtime hooks (Claude Code `PreToolUse`, Codex `apply_patch`) | Canonical hook → ToolCall → Receipt adapter | `packages/gove-zone/src/gove_zone/integration.py` | **exists** |
| Agent-eval (Tau-bench style) | Security/governance benchmark adapters | `acgs_governance_eval_mvp/governance/benchmarks/agentdojo_adapter.py` (+ injecagent, toolemu) | **exists (adjacent)** |
| LangGraph tool nodes | `before_tool_node` governance pre-check | `acgs_governance_eval_mvp/governance/adapters/langgraph.py` | **partial** (reference sketch, no real `langgraph` dep) |
| A2A agent↔agent | Receipt-gated delegation at the boundary | `packages/gove-zone/src/gove_zone/integration.py` (docstring only) | **thin** (no adapter/AgentCard/discovery yet) |

The **partial** and **thin** rows are the roadmap: a LangGraph demo that fails
closed without a receipt (next), then A2A-native receipts (after).

## How this differs

See [COMPARISON.md](COMPARISON.md#governance-posture-none-vs-audit-centric-vs-receipt-centric)
for the three-tier posture contrast (ungoverned vs audit-centric vs
receipt-centric).

> **Honest scope.** ACGS is a technical governance membrane — a mechanism for
> gating actions and emitting verifiable receipts. It is **not a compliance
> certification**, regulator approval, or a production-readiness guarantee.
> This map describes mechanism, not accreditation.
````

- [ ] **Step 4: Run the check to verify it passes**

Run: `python3 /home/martin/.claude/jobs/123eb425/tmp/check_stackmap.py`
Expected: `PASS` (exit 0)

- [ ] **Step 5: Commit**

```bash
cd /home/martin/Documents/ACGS-wt/stackmap-spec
git add docs/AGENT_STACK_GOVERNANCE.md
git commit -m "docs(stack-map): add Agent Stack Governance Map (Wave 1)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Add the 3-tier posture block to `docs/COMPARISON.md`

**Files:**
- Modify: `docs/COMPARISON.md` (insert a new `##` section immediately after the `## Core distinction` section, before `## What to combine`)

**Interfaces:**
- Consumes: the existing `## Microsoft agent governance` section (cross-linked as the audit-centric example, not duplicated).
- Produces: the anchor `#governance-posture-none-vs-audit-centric-vs-receipt-centric` that `AGENT_STACK_GOVERNANCE.md` links to.

- [ ] **Step 1: Write the failing check**

Run: `grep -c "Governance posture: none vs audit-centric vs receipt-centric" /home/martin/Documents/ACGS-wt/stackmap-spec/docs/COMPARISON.md`
Expected: `0` (section absent)

- [ ] **Step 2: Insert the section**

In `docs/COMPARISON.md`, immediately after the `## Core distinction` block and before `## What to combine`, insert:

```markdown
## Governance posture: none vs audit-centric vs receipt-centric

Three postures a system can take at the agent action boundary:

| Posture | Acts… | You get | Example |
|---|---|---|---|
| **Ungoverned** (most of the stack today) | agent → tool directly | speed, zero accountability | raw MCP server, vanilla LangGraph |
| **Audit-centric** | logs *after* the action | a trail you read after harm | Microsoft Agent Governance Toolkit ([detail below](#microsoft-agent-governance)) |
| **Receipt-centric (ACGS)** | gates *before* the action | every action carries a verifiable, single-use Decision Receipt; fail-closed | gove-zone |

ACGS's distinctive choice is **receipt-centric**: the gate runs before the
side effect, and the receipt is the artifact that proves it. This is a
technical membrane, not a compliance certification. See
[AGENT_STACK_GOVERNANCE.md](AGENT_STACK_GOVERNANCE.md) for where each adapter
plugs into the agent stack.
```

- [ ] **Step 3: Run the check to verify it passes**

Run: `grep -c "Governance posture: none vs audit-centric vs receipt-centric" /home/martin/Documents/ACGS-wt/stackmap-spec/docs/COMPARISON.md`
Expected: `1`

- [ ] **Step 4: Verify the cross-link anchor resolves**

Run: `grep -n "^## Microsoft agent governance" /home/martin/Documents/ACGS-wt/stackmap-spec/docs/COMPARISON.md`
Expected: one match (confirms the `#microsoft-agent-governance` anchor the new block links to exists).

- [ ] **Step 5: Commit**

```bash
cd /home/martin/Documents/ACGS-wt/stackmap-spec
git add docs/COMPARISON.md
git commit -m "docs(comparison): add 3-tier governance-posture contrast

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Run the docs gates green and finalize

**Files:**
- (No edits unless a gate fails; if `check_governance_stack_index.py` requires the new doc to be listed, modify `docs/governance-stack-index.md`.)

**Interfaces:**
- Consumes: the two committed docs from Tasks 1–2.
- Produces: a green `lint-docs` + `tests/docs` run proving the wave landed gate-clean.

- [ ] **Step 1: Run the governance-stack-index gate**

Run: `cd /home/martin/Documents/ACGS-wt/stackmap-spec && python3 scripts/check_governance_stack_index.py`
Expected: exit 0. If it fails demanding the new doc be indexed, add a one-line entry for `docs/AGENT_STACK_GOVERNANCE.md` to `docs/governance-stack-index.md` under the most relevant existing heading, then re-run until exit 0.

- [ ] **Step 2: Run the docs test suite**

Run: `cd /home/martin/Documents/ACGS-wt/stackmap-spec && python3 -m pytest tests/docs -q`
Expected: all pass (the new doc is additive and not in `REQUIRED_DOCS`; this confirms it introduced no claim-safety regression).

- [ ] **Step 3: Re-run the Task 1 claim-safety check as a final guard**

Run: `python3 /home/martin/.claude/jobs/123eb425/tmp/check_stackmap.py`
Expected: `PASS`

- [ ] **Step 4: Commit any index change (only if Step 1 required one)**

```bash
cd /home/martin/Documents/ACGS-wt/stackmap-spec
git add docs/governance-stack-index.md
git commit -m "docs(index): register Agent Stack Governance Map

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

If Step 1 needed no change, skip this commit.

- [ ] **Step 5: Confirm branch is clean and ahead-by-N of master**

Run: `cd /home/martin/Documents/ACGS-wt/stackmap-spec && git status --short && git rev-list --count origin/master..HEAD`
Expected: empty working tree; count = 3 or 4 (spec + map + comparison [+ index]).

---

## Self-review notes

- **Spec coverage:** map doc (Task 1) ✓; COMPARISON contrast (Task 2) ✓; verified maturity grid baked into Global Constraints + Task 1 ✓; gate-clean (Task 3) ✓; zero-overclaim enforced by the Task 1 check ✓; no-code / no-marketing honored (no such tasks) ✓.
- **Hand-off:** the `partial` (LangGraph) and `thin` (A2A) rows are named in the doc as the Wave 2/3 targets.
- **Placeholders:** none — full doc content and exact commands inlined.
