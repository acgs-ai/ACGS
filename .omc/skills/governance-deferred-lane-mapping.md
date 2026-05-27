---
name: governance-deferred-lane-mapping
description: File-ownership map for parallelizing /autoplan-deferred lanes in acgs_governance_eval_mvp without merge conflicts; lists which files each lane class touches and the safe merge order.
triggers:
  - /autoplan deferred lanes
  - parallel lanes governance
  - acgs_governance_eval_mvp /team
  - merge order PRs governance
  - governance lane scope
---

# Govern-zone Deferred-Lane File Ownership Map

## The Insight

After /autoplan emits a deferred-lane backlog for `acgs_governance_eval_mvp/`, you can parallelize lanes safely **only if each lane edits a disjoint set of files**. The repo's natural seams produce a stable file-ownership map: 5 broad lane classes that don't overlap if scoped properly.

Lane scopes that look adjacent often share `models.py`, `tools.py`, or `__init__.py`. Edits to those files are the recurring conflict source. Defining "owner = exactly one lane" up front is what makes parallel execution merge-clean.

## Why This Matters

The previous /autoplan run on this repo identified 5 deferred workstreams. Spawning them naively as parallel /team workers produces conflicts on `governance/audit/__init__.py`, `governance/models.py`, and `governance/adapters/tools.py` because at least 3 lanes have "natural-seeming" edits to each. Resolving those conflicts mid-run wastes the parallelism.

Symptom signatures: PR-2's diff includes lines that PR-1 already added; rebase says "both modified" on files neither lane is "supposed to touch"; a worker reports "tests pass" but the merged result fails because its baseline drifted.

## Recognition Pattern

You are about to /team-spawn workers for govern-zone deferred work. Before drafting prompts, ask: "is the file-ownership map I'm assigning conflict-free?" If you can't list `<file> → <single owner>` for every file each worker will write, stop and re-scope.

## The Approach (Lane File-Ownership Map)

**Lane T (Test infrastructure)** — `InMemoryAuditStore`, `governance.testing` helpers
- Owns: `governance/audit/in_memory.py` (new), `governance/testing.py` (new), `governance/audit/__init__.py` (export only), `tests/test_in_memory_audit.py` (new)
- Forbidden: `tools.py`, `models.py`, any `governance/adapters/*.py`, existing tests

**Lane E (Error UX + integrator docs)** — `GovernanceDeniedError`, remediation hints, INTEGRATING/METADATA
- Owns: `governance/models.py` (add field + exception class), `governance/adapters/tools.py` (one edit in `guard()`), `governance/gates/authority_gate.py`, `governance/gates/policy_recall_gate.py`, `INTEGRATING.md` (new), `METADATA.md` (new), `tests/test_error_ux.py` (new)
- Forbidden: `audit/*`, `replay.py`, `governance/utils.py`, `governance/adapters/*.py` other than `tools.py`

**Lane A (Framework adapters + canonical hash)** — OpenAI Agents / LangGraph / Anthropic Claude reference adapters
- Owns: `governance/utils.py` (new — `canonical_input_hash`), `governance/adapters/openai_agents.py` (new), `governance/adapters/langgraph.py` (new), `governance/adapters/anthropic_claude.py` (new), `tests/test_canonical_hash.py` (new), `tests/test_reference_adapters.py` (new)
- Forbidden: `tools.py`, `models.py`, `audit/*`, `replay.py`

**Lane R (REQUIRE_HUMAN runtime)** — gate that returns the third decision state
- Owns: a new `governance/gates/human_review_gate.py`, edits to `governance/adapters/tools.py:validate` to fan out to it, edits to `governance/models.py:DecisionState` propagation
- **Conflicts with Lane E** on `tools.py` and `models.py`. Run R after E lands.

**Lane W (REWRITE / REDACT)** — post-execution rewriter primitive + observer
- Owns: `governance/observers/post_exec.py` (new), `governance/rewriters/redact.py` (new), edits to `tools.py:validate` for the post-exec hook
- **Conflicts with Lane R and Lane E** on `tools.py`. Run W after R lands.

## Safe Merge Order

For the parallel-friendly lanes (T, E, A) in any one /autoplan cycle:

1. **T** first — adds new files only, no edits to shared files except a 1-line export in `audit/__init__.py`. No downstream blocking.
2. **E** before **A** if E's INTEGRATING.md cross-references the test harness from T. Otherwise either order works.
3. **A** can land independently of E because A doesn't touch `tools.py` or `models.py`.

Sequential lanes (R, W) follow after E lands on master, in order R → W.

## Example

This session ran T → then [E ‖ A] in parallel. PR landing order:
1. PR #5 (Lane T) merged first.
2. PR #7 (Lane E) merged second — INTEGRATING.md cross-reference to test harness still valid.
3. PR #6 (Lane A) merged third.

Final test count: 37 → 54 (+17 across 3 lanes). Zero merge conflicts because no two lanes wrote to the same file.

## Common Mistakes

- **Letting Lane E and Lane A both edit `governance/adapters/tools.py`.** A's reference adapters call `adapter.guard()` — they don't need to edit `tools.py`. If a worker thinks they need to, the scope is wrong.
- **Letting Lane T touch `models.py`.** T's helpers should construct `ActionRequest` dicts, not change the dataclass. If T wants a new field, escalate to E.
- **Trying to parallelize R and E.** Both edit `tools.py:validate`. Land E first.
