# Codex `/goal` contract — Phase 1 Week 2 paper-validation gate

> Designed for Codex's `/goal` durable-objective mode (`features.goals = true`).
> Per `ROADMAP.md` Phase 1 Week 2. Paste the **Goal text** block into a Codex
> session, or run via `codex exec` with the same body.

## Working directory

```
/home/martin/Downloads/govern-zone/ACGS/govern-zone
```

## Branch

`phase-1-kernel-hardening` (already exists, 3 commits ahead of master)

## Goal text (paste this)

```text
/goal Land the Phase 1 Week 2 paper-validation benchmark gate for arXiv 2605.05440
propagation overhead against a token-based baseline in packages/gove-zone, producing
a verdict ADR and a committed benchmark artifact, without changing the kernel public
API or any sealed/generated file.

READ FIRST (in order):
- ROADMAP.md (root) — Phase 1 Week 2 section + "Receipt-chain integrity caveat"
- AUTHZ-ROADMAP.md — R1-R7 verbatim text and the 120x-better-than-TTL claim being tested
- CLAUDE.md, AGENTS.md — hard constraints, scope rules
- packages/gove-zone/src/gove_zone/kernel.py — current Kernel + policy_timeout watchdog
- packages/gove-zone/src/gove_zone/policy.py, decision.py, audit.py — existing surfaces
- packages/gove-zone/tests/test_fail_closed.py + test_fail_closed_gaps.py — test idiom

CHECKPOINTS (work in this order, commit at each):

1. Scaffold a benchmarks/ directory at packages/gove-zone/benchmarks/ with an
   __init__.py and a conftest.py. Update packages/gove-zone/pyproject.toml
   pytest config if needed so `python -m pytest benchmarks/` collects.

2. Implement a mock 3-agent delegation chain (Orchestrator -> Planner -> Executor)
   in benchmarks/agent_chain.py. Use only in-process Python (no real network),
   50KB structured payloads, configurable concurrency. Each agent must invoke
   Kernel.dispatch on a registered tool.

3. Implement TWO authorization adapters:
   a) benchmarks/authz_propagation.py — minimal model of the arXiv 2605.05440
      propagation graph (delegation chain with cryptographic verification of
      principal/tenant/role across hops).
   b) benchmarks/authz_token_baseline.py — JWT-style capability tokens signed
      by the Orchestrator with localized path + capability caveats.

4. Write benchmarks/test_propagation_overhead.py asserting all four thresholds
   from ROADMAP.md Phase 1 Week 2:
     - mean latency overhead <= 15%
     - p95 latency overhead <= 25%
     - token-consumption overhead <= 10%
     - heap growth <= 5MB
     - under 500ms simulated network timeout, lookup aborts + fails closed
       within 500ms (no hang)
   Concurrency: 10 parallel chains, simultaneous.

5. Run the benchmark and write the verdict artifact to
   .benchmarks/propagation-gate-week2.json with this exact shape:
     {
       "gate": "propagation-overhead-week2",
       "verdict": "PASS" | "FAIL",
       "thresholds": {...},
       "measured": {...},
       "ran_at": "<ISO-8601 UTC>",
       "kernel_sha": "<git rev-parse HEAD>"
     }

6. Write the ADR:
     - On PASS: docs/adr/0001-authz-propagation-accepted.md
     - On FAIL: docs/adr/0001-authz-propagation-rejected.md
   ADR must cite the artifact path + measured numbers + the agy critique
   summary from .omc/artifacts/ask/agy-critique.md. If FAIL, the ADR must
   sketch the 3-week token-based Phase 2 alternative.

7. Wire benchmarks into `make verify`: add `packages/gove-zone/benchmarks` to
   the ruff/format lists in Makefile lint-py.

STOP CONDITION (all must hold; show evidence):
  - cd packages/gove-zone && uv run --package gove-zone python -m pytest benchmarks/ -q
    exits 0
  - test -f .benchmarks/propagation-gate-week2.json
  - test -f docs/adr/0001-authz-propagation-{accepted,rejected}.md (exactly one)
  - make verify exits 0
  - git diff --stat shows ONLY changes inside packages/gove-zone/, .benchmarks/,
    docs/adr/, and Makefile; no submodule pointer drift; no sealed-file edits;
    no edits to packages/Acgs-Swarm (still expected dirty/untracked)

HARD CONSTRAINTS (do not violate; if you must, stop and ask):
  - Do not change Kernel public API (already-released signatures of dispatch,
    Kernel.__init__, decorators). Watchdog is additive — keep it that way.
  - Constitutional hashes are sealed: never edit a file with `# Constitutional Hash:`
    marker without recomputing the hash.
  - `acgs-lite` published API floor is py3.10 — do not import it in benchmarks
    in a way that breaks 3.10 compatibility.
  - Never `git add -A` or `git add .`. Stage explicitly.
  - Never edit `packages/Acgs-Swarm` or stage its pointer.
  - Console origin / CSP: no edits to `acgi-ai/src/routes/console/**`.
  - If audit.append is touched, the new code MUST be fail-closed: any exception
    blocks tool execution BEFORE any side effect (per agy critique predicting
    the Codex "fail open on lock/disk errors" failure mode).

PROGRESS LOG: append a one-line update to .omc/state/phase1-week2-goal-progress.log
after each checkpoint completes. Format:
  "<ISO-8601 UTC> CHECKPOINT <n> done: <short summary> | sha=<git short sha>"

COMMITS: one focused commit per checkpoint, conventional-commit style:
  - feat(gove-zone): scaffold benchmarks/
  - feat(gove-zone): mock 3-agent delegation chain
  - feat(gove-zone): propagation authz adapter
  - feat(gove-zone): token-baseline authz adapter
  - test(gove-zone): propagation overhead benchmark
  - chore(gove-zone): write week-2 gate verdict + ADR
  - build(gove-zone): wire benchmarks into make verify

DO NOT MERGE the phase-1-kernel-hardening branch. Stop after the last commit
and emit a short summary with the verdict, artifact path, ADR path, and the
delta between thresholds and measured values.
```

## Optional: run non-interactively

```bash
cd /home/martin/Downloads/govern-zone/ACGS/govern-zone
codex exec --dangerously-bypass-approvals-and-sandbox "$(cat .omc/plans/codex-goal-phase1-week2-paper-gate.md | awk '/^## Goal text/{p=1;next} /^```text/{q=1;next} /^```$/{q=0} q&&p')"
```

(`exec` won't honor `/goal` semantics — the `/goal` machinery is interactive-session only.
For true durable behavior, paste the goal text into an interactive Codex session.)

## Status hooks

While the goal runs, check status from any shell:

```bash
tail -f .omc/state/phase1-week2-goal-progress.log
```
