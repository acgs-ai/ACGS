# Phase 2 Entry Gate — Hardening Follow-ups

- **Phase 1.1 status:** ✅ **ACCEPTED** (Evidence Freeze = PASS).
- **Freeze boundary (immutable):** baseline `9131478`, evidence `24f8acf`, tags
  `phase-1-baseline`, `phase-1.1-freeze`. The frozen evidence under `docs/evidence/`
  is not amended retroactively — hardening lands as new Phase 2 work.
- **Do not start Phase 2** (evaluator/scoring/labels/annotation/tiering/packaging) until these
  four items are addressed and this gate is re-checked.

## Entry-gate checklist

```
PHASE_1_1_STATUS = ACCEPTED
  ✓ reproducible evidence freeze
  ✓ deterministic replay
  ✓ scoped repository state
  ✓ manifest integrity
  ✓ schema validation

Hardening (implemented — see below):
  ✓ H1  git diff / status / ls-files transition capture   -> acgs_trajectory/git_evidence.py
  ✓ H2  adversarial fixture matrix + cycle/ordering detection
  ✓ H3  version-drift matrix + non-string version guard
  ✓ H4  secret-scanner policy tiers (fail-closed, no content-controlled downgrade)
  ✓ H4  preserve frozen commit tags (phase-1-baseline, phase-1.1-freeze)
  ✓ worktree isolation recorded as the multi-agent process requirement
```

**Implementation note (security).** The H4 tier system was reviewed by independent
security + code-review passes, which found (and I fixed + execution-verified) three
content-controlled fail-OPEN bypasses in the first draft: a `pragma` in untrusted
transcript content downgrading a real secret, a provider-id prefix silently swallowing
a wrapped secret, and a blanket 40/64-hex whitelist. The shipped classifier honors NO
content-controlled downgrade at the ingestion edge; `example_placeholder` is an exact
allowlist of published example credentials only; structural-id whitelisting is bounded
and re-checks the token body for embedded named credentials. Cycle detection is O(V).

## H1 — Git diff / transition-path capture (risk R4)

The current freeze proves *state*, not the *transition*. Add to the evidence generator:

```
git diff <parent_commit>..<freeze_commit>   # exactly what changed
git status --porcelain=v1                    # working-tree cleanliness
git ls-files -s                              # tracked inventory + blob ids
```

Purpose: prove precisely what changed, ease external audit, close the
"freeze artifact exists but mutation path unknown" gap. Emit as a `transition`
block in `phase1_evidence_manifest.json` (a *new* Phase 2 manifest revision, not
an edit to the frozen one).

## H2 — Adversarial fixture matrix (risk R9)

Current corpus is intentionally minimal. Add adversarial fixtures before broader claims:

- malformed trajectories (truncated JSON, mixed sessionIds, cyclic parentUuid)
- partial / interleaved tool calls (tool_use with no result; out-of-order result-before-use)
- missing provenance (no sessionId; no version; no git join)
- replay divergence (a fixture engineered to expose non-determinism if it regresses)
- schema-evolution cases (unknown block types, added top-level keys, v2→future migration)

## H3 — Version-drift containment matrix (risk R1)

Extend the version boundary from a single supported version to a tested matrix:

- known supported versions (per-version golden fixture)
- unknown versions → quarantine + adapter review (already enforced)
- malformed version metadata (absent / non-string / empty)
- downgrade / upgrade paths across the 2.x line

## H4 — Secret-scanner policy tiers (risk R2)

Replace the flat "any high-entropy string = secret" behavior with graded classes so
fail-closed stays safe without over-quarantining every token:

| Class | Meaning | Handling |
|---|---|---|
| `confirmed_secret` | named high-precision pattern (AWS/GitHub/PEM/JWT) | quarantine + incident |
| `secret_pattern_match` | shape match, unverified | quarantine (review) |
| `example_placeholder` | documented example (e.g. `AKIA…EXAMPLE`) | allow + note |
| `test_fixture_exception` | inline `pragma: allowlist secret` in a fixture | allow + note |

Direction stays fail-closed; the tiers only refine *which* action, and are surfaced in the
finding reason so audits can distinguish real leaks from placeholders.

## Operational — worktree isolation (H3 process item)

The only process issue observed in Phase 1.1 was a **shared `.git/index` collision** with a
concurrent session (its evidence staged into the same index). A scoped commit avoided absorbing
foreign work, but the failure mode is subtle: a clean commit can still accidentally absorb another
agent's staged state. Required going forward:

```
agent-A → worktree-A   (branch agent/A)
agent-B → worktree-B   (branch agent/B)
agent-C → worktree-C   (branch agent/C)
```

Never let multiple agents mutate the same index. Use per-agent worktrees + branches.
