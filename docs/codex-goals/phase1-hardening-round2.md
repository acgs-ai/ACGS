# Codex `/goal` contract — Phase 1 hardening round 2

> Final pre-PR pass on `phase-1-kernel-hardening`. The 2026-05-22 CCA
> round-2 review found three issues the first hardening missed. Fix
> them, then we open the PR.

## Working directory

```
/home/martin/Downloads/govern-zone/ACGS/govern-zone
```

## Goal text (paste this)

```text
/goal Close the three CCA round-2 blockers on the phase-1-kernel-hardening
branch with three focused commits. No new features. Stop on the stop
condition.

READ FIRST:
- acgs_governance_eval_mvp/.omc/artifacts/ask/agy-adversarial-re-review-you-critiqued-phase-1-kernel-hardening-2026-05-23T00-34-02-197Z.md
- acgs_governance_eval_mvp/.omc/artifacts/ask/codex-adversarial-re-review-the-branch-phase-1-kernel-hardening-was-2026-05-23T00-32-25-*.md (round-2 codex review)
- acgs_governance_eval_mvp/governance/models.py (AuthorizationTrace
  from_dict + __post_init__ — see issue 1)
- acgs_governance_eval_mvp/governance/audit/jsonl_chain.py (extract_trace
  strict parameter — see issue 2)
- docs/adr/ (ADR numbering — see issue 3)

ISSUE 1 (CRITICAL — integrity bypass)
   File: acgs_governance_eval_mvp/governance/models.py
   Problem: AuthorizationTrace.from_dict sets trace_hash_value=None
   for the nested path. __post_init__ at the trace_hash_value check
   only fires when the field is non-None. An attacker can omit
   trace_hash entirely and bypass integrity verification — the
   invariant is opt-in to the attacker's cooperation.
   Fix prescription:
     - Remove trace_hash_value as an externally-supplied field.
       Expose it as a read-only computed property:
         @property
         def trace_hash_value(self) -> str:
             return self.trace_hash()
     - If callers need to PERSIST the hash alongside the trace
       (e.g. in audit JSON), they call trace.trace_hash() at write
       time. The wire format MUST include trace_hash so that on read
       the consumer can recompute and compare.
     - In from_dict: read the persisted trace_hash from the wire data
       (either nested receipt.trace_hash OR a top-level trace_hash
       field — be explicit which is canonical). Construct the trace.
       Then ASSERT that the recomputed trace_hash() matches the wire
       trace_hash; raise AuthorizationTraceIntegrityError otherwise.
     - Drop the legacy flat-shape parsing path entirely. Nested
       workflow_scope + receipt is the only valid wire format. If
       the data lacks these, raise ValueError. The schema is the
       contract.
     - Update the schema if needed so trace_hash is REQUIRED in the
       receipt block. Update the fixture accordingly.
     - Add tests:
         a) trace constructed from a valid nested wire payload — pass
         b) wire payload missing trace_hash — raises
         c) wire payload with WRONG trace_hash — raises
         d) wire payload in legacy flat shape — raises ValueError
            (the legacy shape is gone)

ISSUE 2 (HIGH — fail-open path)
   File: acgs_governance_eval_mvp/governance/audit/jsonl_chain.py
   Problem: extract_trace(strict=False) silently catches
   AuthorizationTraceIntegrityError and returns None. Any caller
   using this parameter — even by mistake — will treat tampered
   audit events as if they had no trace, and depending on policy
   may fail open.
   Fix prescription:
     - Remove the strict parameter from extract_trace entirely.
       extract_trace ALWAYS raises on integrity failure. Single
       behavior.
     - Update the class docstring to reflect single behavior.
     - The test that previously exercised strict=False
       (test_authorization_trace_receipts.py:154-167) is replaced
       by a test that demonstrates the caller pattern: try /
       except AuthorizationTraceIntegrityError at the call site.
     - The behavior-fork docstring (raise vs return) is now obsolete;
       prune it to describe the unified contract.

ISSUE 3 (MEDIUM — ADR collision)
   Files:
     docs/adr/0001-authz-propagation-accepted.md → rename to 0005-…
     docs/adr/0002-week2-benchmark-methodology-correction.md → rename to 0006-…
   Problem: ADR numbers 0001 and 0002 are already taken by pre-existing
   docs/adr/0001-in-context-procedure-execution-external-runtime-governance.md
   and 0002-maci-four-role-architecture.md. The new ADRs conflict.
   Fix prescription:
     - Use `git mv` to rename:
         git mv docs/adr/0001-authz-propagation-accepted.md \\
                docs/adr/0005-authz-propagation-accepted.md
         git mv docs/adr/0002-week2-benchmark-methodology-correction.md \\
                docs/adr/0006-week2-benchmark-methodology-correction.md
     - Update internal titles ('# ADR 0001:' → '# ADR 0005:', etc.)
     - Update cross-references inside the two files (each cites the other).
     - Update ROADMAP.md if it references the old paths.
     - Update .benchmarks/propagation-gate-week2.json if it cites an ADR.

STOP CONDITION (all must hold; literal evidence):
  - cd acgs_governance_eval_mvp && uv run --package acgs_governance_eval_mvp \\
      python -m pytest tests/ -q
    exits 0
  - cd packages/gove-zone && uv run --package gove-zone python -m pytest \\
      tests/ benchmarks/ -q
    exits 0
  - make lint-py exits 0
  - ls docs/adr/ shows no duplicate prefix (no two files starting with
    the same NNNN-)
  - git grep -E 'extract_trace.*strict' returns no hits in src or tests
    (the parameter is gone)
  - git grep 'trace_hash_value' shows trace_hash_value is now a
    @property (not a field), or returns no hits if removed entirely

HARD CONSTRAINTS:
  - Three commits, one per issue. Conventional commits:
      fix(eval-mvp): require AuthorizationTrace integrity on construction
      refactor(eval-mvp): drop strict=False from extract_trace
      docs(adr): renumber Phase-1 ADRs to 0005, 0006
  - Do not touch packages/Acgs-Swarm.
  - Do not edit AGENTS.md or sealed pyproject.toml.
  - Do not introduce new public API surface beyond fixing these issues.
  - The schema can change (we own it; it landed in this branch).
  - Test removals are OK IF justified by the spec change. State which
    tests were removed and why in the final summary.

PROGRESS LOG: append to .omc/state/phase1-hardening-round2-progress.log
with the format:
  '<ISO-8601 UTC> ISSUE <n> done: <summary> | sha=<short sha>'

DO NOT MERGE. After the third commit, emit a summary with:
  - confirmed-closed list
  - any test removed/replaced and the new test that took its place
  - the trace_hash wire-format decision you made (top-level or nested)
  - whether you found any additional issue while fixing these (if so,
    surface but don't fix in this pass — log for follow-up)
```

## Launch

```bash
cd /home/martin/Downloads/govern-zone/ACGS/govern-zone
codex exec --dangerously-bypass-approvals-and-sandbox \
  "$(awk '/^## Goal text/{p=1;next} p && /^```text$/{q=1;next} q && /^```$/{exit} q' docs/codex-goals/phase1-hardening-round2.md)"
```
