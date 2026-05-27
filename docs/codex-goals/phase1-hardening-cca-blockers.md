# Codex `/goal` contract — Phase 1 hardening pass (CCA blockers)

> Pre-PR hardening on `phase-1-kernel-hardening` driven by the 2026-05-22
> adversarial /cca pass. Both reviewers issued REQUEST CHANGES / HARDEN-
> THEN-SHIP. Fix the six bounded blockers below before PR. No new features.

## Working directory

```
/home/martin/Downloads/govern-zone/ACGS/govern-zone
```

## Branch

`phase-1-kernel-hardening` (extend; do not branch from)

## Goal text (paste this)

```text
/goal Harden the phase-1-kernel-hardening branch against the six CCA
adversarial blockers below. NO new features. Each fix is a focused commit.
Stop on the stop condition.

READ FIRST:
- acgs_governance_eval_mvp/.omc/artifacts/ask/codex-adversarial-review-before-opening-a-pr-branch-phase-1-kernel-2026-05-23T00-13-55-546Z.md
- acgs_governance_eval_mvp/.omc/artifacts/ask/agy-critique.md
- acgs_governance_eval_mvp/AGENTS.md (line 33 in particular — SEALED list)
- docs/adr/0001-authz-propagation-accepted.md
- packages/gove-zone/benchmarks/test_propagation_overhead.py (the p95 caveat)

BLOCKERS (fix in this order, one commit each):

1. SCHEMA / MODEL alignment.
   File: acgs_governance_eval_mvp/governance/schema/authorization_trace.schema.json
   File: acgs_governance_eval_mvp/governance/models.py
   File: acgs_governance_eval_mvp/tests/fixtures/authorization_trace_minimal.json
   Problem: schema requires top-level `workflow_scope` + `receipt` containers
   and forbids extras; AuthorizationTrace.to_dict() emits FLAT fields
   (`trace_id`, `workflow_id`, `principal_chain`, `evaluation_policy`,
   `trace_hash`, etc.); from_dict() therefore fails on the schema-valid
   fixture.
   Fix path: change to_dict() / from_dict() to emit and consume the NESTED
   shape (workflow_scope: { workflow_id, parent_workflow_id, principal_chain };
   receipt: { receipt_hash, audit_event_hash, trace_id, schema_version };
   evaluation_policy at top level). This preserves the R5 / R6 semantic
   intent in the schema names. Update the fixture if necessary to use the
   same nested shape. Add a test asserting AuthorizationTrace.to_dict()
   validates against the schema with jsonschema. Add a round-trip test:
   from_dict(to_dict(trace)) == trace.

2. ChainHashAuditStore._last_hash CACHE removal.
   File: acgs_governance_eval_mvp/governance/audit/jsonl_chain.py
   Problem: `self._last_hash` is per-instance; fcntl.flock only serializes
   inside the same process. Two processes pointing at the same audit file
   each cache stale parent hashes and write sibling records — chain breaks
   under multi-process concurrency even though the lock is correct.
   Fix path: drop the in-memory cache. Always call _read_last_hash_from_disk()
   INSIDE the held lock on every append. Keep the tail-read O(1). Update
   last_hash() to always read from disk. Add a test:
   `test_multiprocess_concurrent_appends_preserve_chain` that uses
   multiprocessing.Process (NOT threading) to issue N=4 concurrent appends
   on the same path; verify_chain() must return valid AND no two events
   may share the same previous_hash. Mark the test xfail/skip if the
   verify_chain semantics still need a separate fix; if so, raise that
   as a separate issue in the final summary.

3. SEALED pyproject.toml dependency.
   File: acgs_governance_eval_mvp/pyproject.toml
   File: acgs_governance_eval_mvp/AGENTS.md (READ ONLY)
   Problem: AGENTS.md:33 declares pyproject.toml SEALED; the Week 3 work
   added `jsonschema` to dev extras at lines 26-28. This is a real scope
   violation surfaced by the Codex review.
   Fix path: revert the pyproject.toml edit (drop the jsonschema dev dep).
   Make the schema-validation test load jsonschema with `pytest.importorskip`
   so it skips cleanly when the optional dep is absent. Document the new
   skip in the test's docstring. Do NOT modify AGENTS.md or change its
   sealed declaration without a separate governance commit.

4. THEATRE TEST replacement.
   File: acgs_governance_eval_mvp/tests/test_authorization_trace_receipts.py
   Problem: `test_trace_is_anchored_in_chain` mutates an in-memory copy
   and asserts hash WOULD differ — never tampers the file. No real
   tamper-write detection.
   Fix path: rewrite the test as `test_trace_tamper_detected_on_disk`.
   Pseudocode:
     - append a DecisionRecord + AuthorizationTrace
     - read the JSONL line back, mutate one principal_id, write line back
     - call extract_trace() on the mutated event dict → assert raises
       AuthorizationTraceIntegrityError
     - OR call verify_chain() → assert valid is False AND chain identifies
       the tampered event index
   Keep at least one positive test that an untampered trace round-trips.

5. RAISE-VS-RETURN behavior contract.
   File: acgs_governance_eval_mvp/governance/audit/jsonl_chain.py
   Problem: pre-existing verify_chain() returns `valid: False` on tamper;
   the new trace-bearing path raises AuthorizationTraceIntegrityError.
   That's a behavior fork that callers will trip on.
   Fix path: document the fork in the ChainHashAuditStore class docstring
   AND in extract_trace() docstring with an explicit table of which
   verification paths raise vs return. If feasible without a public API
   break, add a `strict: bool = True` parameter to extract_trace() so
   callers can opt into the legacy `return None on integrity failure`
   behavior; default stays strict / raises. Add a test exercising both
   paths.

6. ADR-0002 split.
   File: docs/adr/0001-authz-propagation-accepted.md (revise)
   File: docs/adr/0002-week2-benchmark-methodology-correction.md (NEW)
   Problem: ADR-0001 was edited post-acceptance to bury the methodology
   bug (mean==p95 by construction); buries a quality-gate failure inside
   the acceptance record.
   Fix path: restore ADR-0001 to its original numbers (the FIRST run with
   the degenerate p95) and add at the bottom a single line:
     "Status: methodology correction recorded in ADR-0002."
   Create ADR-0002 with:
     - Status: Accepted (supersedes ADR-0001 measurement methodology)
     - Context: explain the per-chain-duplication bug
     - Decision: per-chain timing via ThreadPoolExecutor.map of
       _timed_run_one is the canonical method
     - Consequences: ADR-0001 stays as historical record; future
       benchmark gates must reference ADR-0002 method
     - Measured values from the corrected run
   The Week-2 verdict is still PASS under either methodology; emphasize.

STOP CONDITION (all must hold; show literal evidence):
  - cd acgs_governance_eval_mvp && uv run --package acgs_governance_eval_mvp \\
      python -m pytest tests/ -q
    exits 0 (no existing test regressed)
  - cd packages/gove-zone && uv run --package gove-zone python -m pytest tests/ benchmarks/ -q
    exits 0
  - make lint-py exits 0
  - The 6 fixes are 6 separate commits with conventional-commit messages
  - git diff --stat shows only changes inside the named files (no scope drift)
  - No new SEALED-list violations; AGENTS.md unchanged
  - The new round-trip + tamper + multiprocess tests all pass

HARD CONSTRAINTS:
  - Do not introduce new public API surface. Only fix bugs.
  - Do not bump DECISION_SCHEMA_VERSION.
  - Do not edit AGENTS.md or change SEALED declarations.
  - Do not git add -A. Stage explicitly per file.
  - Do not touch packages/Acgs-Swarm.
  - Each commit must contain ONLY the files for that specific blocker
    (with the exception of the schema/model commit which legitimately
    spans 3 files).
  - For multiprocess test: if the test reveals a deeper bug than the
    cache fix solves, leave it skipped with a TODO and surface in the
    final summary — DO NOT silently weaken the assertion.
  - Conservatism: even after the hardening, do NOT promote the arXiv
    preprint's empirical claims into doc comments.

PROGRESS LOG: append per-blocker lines to
.omc/state/phase1-hardening-progress.log:
  "<ISO-8601 UTC> BLOCKER <n> done: <summary> | sha=<short sha>"

COMMITS (conventional commit):
  - fix(eval-mvp): align AuthorizationTrace shape with JSON schema
  - fix(eval-mvp): drop in-memory _last_hash cache for multi-process safety
  - revert(eval-mvp): drop jsonschema dep from sealed pyproject.toml
  - test(eval-mvp): replace anchor theatre with real disk-tamper detection
  - docs(eval-mvp): document trace verify raise-vs-return behavior fork
  - docs(adr): split ADR-0002 methodology correction from ADR-0001

DO NOT MERGE. Emit final summary with: blockers closed, blockers remaining,
new tests added, and any constraint you came close to violating.
```

## Launch (background)

```bash
cd /home/martin/Downloads/govern-zone/ACGS/govern-zone
codex exec --dangerously-bypass-approvals-and-sandbox \
  "$(awk '/^## Goal text/{p=1;next} p && /^```text$/{q=1;next} q && /^```$/{exit} q' docs/codex-goals/phase1-hardening-cca-blockers.md)"
```
