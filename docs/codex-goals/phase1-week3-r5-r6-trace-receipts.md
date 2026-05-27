# Codex `/goal` contract — Phase 1 Week 3 R5/R6 trace receipts

> Phase 1 Week 3 from `ROADMAP.md`. Predicate: the Week-2 paper-validation
> gate **PASSED** (see `.benchmarks/propagation-gate-week2.json` and
> `docs/adr/0001-authz-propagation-accepted.md`), so the propagation-backed
> R5/R6 path is unlocked. This goal lands the schema, model types, audit
> payload extension, fail-closed verification tests, and CI wiring.

## Working directory

```
/home/martin/Downloads/govern-zone/ACGS/govern-zone
```

## Branch

`phase-1-kernel-hardening` (already 14 commits ahead of master, will extend)

## Goal text (paste this)

```text
/goal Land Phase 1 Week 3 R5/R6 authorization-trace receipts as additive,
non-breaking extensions to acgs_governance_eval_mvp: receipt + chain-verify
fail-closed tests, JSON schema, additive model types, audit payload carry,
and CI wiring. Do not change DECISION_SCHEMA_VERSION (v1) or break any
existing test. Stop on the stop condition below.

READ FIRST (in this order, skim — do not re-derive what's already there):
- ROADMAP.md — Phase 1 Week 3 deliverables list and the Receipt-chain
  integrity caveat (fcntl.flock NFS hazard)
- docs/adr/0001-authz-propagation-accepted.md — Week 2 verdict + methodology
- AUTHZ-ROADMAP.md — R5 (workflow-scoped, self-contained traces) and
  R6 (configurable evaluation policy: initiation-time / access-time /
  completion-time)
- acgs_governance_eval_mvp/governance/models.py — existing Principal,
  ActionRequest, DecisionRecord, DECISION_SCHEMA_VERSION, sha256_json,
  stable_json. New types must NOT alter the dataclass shape of these.
- acgs_governance_eval_mvp/governance/audit/jsonl_chain.py — existing
  ChainHashAuditStore with fcntl.flock serialization and chain-hash
  canonicalization. Any new payload field must round-trip through
  payload[\"event_hash\"] = sha256_json(payload).
- acgs_governance_eval_mvp/tests/test_audit_chain.py — current chain
  invariants the new tests must NOT regress.
- packages/gove-zone/benchmarks/authz_propagation.py — already implements
  the propagation chain; if reusable types or helpers exist there,
  reuse them rather than reinvent.
- .github/workflows/python-eval-mvp.yml — current CI gate for this package.

CHECKPOINTS (one focused commit per checkpoint):

1. Author the JSON schema at
   acgs_governance_eval_mvp/governance/schema/authorization_trace.schema.json
   covering:
     - workflow_scope (R5): workflow_id, parent_workflow_id (nullable),
       principal_chain (ordered list of {principal_id, role, tenant,
       delegated_at, delegation_evidence_hash})
     - evaluation_policy (R6): one of
       'initiation-time' | 'access-time' | 'completion-time'
     - receipt: { receipt_hash, audit_event_hash, trace_id, schema_version }
   Use draft-07. Include a tests/fixtures/authorization_trace_minimal.json
   that validates against the schema.

2. Add additive types to
   acgs_governance_eval_mvp/governance/models.py:
     - AuthorizationTrace (frozen dataclass) with the R5 fields above plus
       canonical_json() and trace_hash() helpers reusing stable_json/
       sha256_json. Schema constant AUTHORIZATION_TRACE_SCHEMA_VERSION='v1'.
     - DecisionReceiptRef (frozen dataclass) with receipt_hash,
       audit_event_hash, trace_id, schema_version.
     - from_dict/to_dict round-trip helpers.
   Do NOT alter Principal, ActionRequest, DecisionRecord, or change
   DECISION_SCHEMA_VERSION. Existing tests must still pass.

3. Extend acgs_governance_eval_mvp/governance/audit/jsonl_chain.py:
     - ChainHashAuditStore.append() optionally accepts an
       authorization_trace argument (default None). When provided, the
       payload picks up authorization_trace = trace.to_dict() before
       event_hash computation, so the trace is anchored in the chain.
     - last_hash() and verify_chain() unchanged in signature.
     - Add a small public helper extract_trace(event_dict) returning
       AuthorizationTrace | None.
   Backwards compatible: callers passing no trace see byte-identical
   behavior with the existing on-disk events.

4. Write acgs_governance_eval_mvp/tests/test_authorization_trace_receipts.py:
     - test_trace_is_anchored_in_chain: append a DecisionRecord with a
       fully populated AuthorizationTrace; verify event_hash covers the
       trace payload (mutating the trace AFTER the fact and recomputing
       must yield a different hash); verify_chain() returns valid.
     - test_missing_trace_hash_fails_closed: corrupt trace_hash in a
       stored event; replay/verify path raises and does NOT silently
       accept the event.
     - test_mismatched_trace_principal_chain_fails_closed: principal
       chain on disk diverges from the receipt's referenced principals;
       must fail closed.
     - test_receipt_round_trip: AuthorizationTrace → audit append →
       on-disk JSON → from_dict → equal to the original.
     - test_evaluation_policy_round_trip: each of the three R6 values
       round-trips and ends up in the audit payload literally.
     - test_schema_fixture_validates: load the minimal fixture, validate
       against the JSON schema using jsonschema (add to dev extras if not
       present).
   No new optional deps in core; jsonschema goes in
   acgs_governance_eval_mvp/pyproject.toml [project.optional-dependencies].dev.

5. Update CI: .github/workflows/python-eval-mvp.yml runs the new test
   module. If the workflow already runs `pytest acgs_governance_eval_mvp/`
   verify the new file is collected; otherwise add an explicit step.
   Do not weaken existing matrix coverage.

6. Optional: regenerate the Week-2 gate artifact under the new audit
   payload to confirm propagation still passes. If the artifact path is
   touched, update its ran_at + kernel_sha. Skip this checkpoint if the
   audit payload change is fully behind a None-default.

STOP CONDITION (all must hold; show literal evidence in the final summary):
  - cd acgs_governance_eval_mvp && uv run --package acgs_governance_eval_mvp \\
      python -m pytest tests/test_authorization_trace_receipts.py -q
    exits 0
  - cd acgs_governance_eval_mvp && uv run --package acgs_governance_eval_mvp \\
      python -m pytest tests/ -q
    exits 0 (no existing test regressed)
  - test -f acgs_governance_eval_mvp/governance/schema/authorization_trace.schema.json
  - test -f acgs_governance_eval_mvp/tests/fixtures/authorization_trace_minimal.json
  - test -f acgs_governance_eval_mvp/tests/test_authorization_trace_receipts.py
  - make lint-py exits 0
  - git diff --stat shows ONLY changes inside
      acgs_governance_eval_mvp/, .github/workflows/python-eval-mvp.yml
    and (optional, only if checkpoint 6 ran) .benchmarks/. No edits to
    packages/Acgs-Swarm. No sealed-file hits.

HARD CONSTRAINTS (stop and ask if violation is unavoidable):
  - DO NOT change DECISION_SCHEMA_VERSION. Bumping it is a semver hazard
    for downstream consumers.
  - DO NOT change the shape or field order of Principal, ActionRequest,
    DecisionRecord. New types are additive only.
  - DO NOT modify acgs_governance_eval_mvp/tests/test_audit_chain.py;
    its assertions are the existing chain contract. If a new field breaks
    one of its assertions, that's the new code's bug, not the test's.
  - Constitutional hashes sealed: never edit a file with `# Constitutional Hash:`
    marker without recomputing.
  - acgs-lite py3.10 floor: don't add an import chain that breaks 3.10.
    (acgs_governance_eval_mvp itself does not have that floor, but be
    mindful if importing from packages/acgs-lite.)
  - Never `git add -A`. Stage explicitly.
  - Never touch packages/Acgs-Swarm.
  - Fail-closed semantics are mandatory in the new code paths: any
    exception during trace serialization, schema validation, audit
    append, or hash recomputation must block the surrounding operation
    BEFORE any external side effect. Audit hash mismatches must surface
    as a typed exception, not a silent fallback.
  - Conservatism on the arXiv preprint: even though the Week-2 gate
    passed, do NOT promote any of the preprint's empirical claims (e.g.
    '120x better than TTL') into doc strings or assertions as if proven.
    The benchmark proved overhead is acceptable, nothing else.

PROGRESS LOG: append one line per checkpoint to
.omc/state/phase1-week3-goal-progress.log with the format
'<ISO-8601 UTC> CHECKPOINT <n> done: <summary> | sha=<short sha>'.

COMMITS: conventional-commit, one per checkpoint:
  - feat(eval-mvp): add R5/R6 authorization trace JSON schema
  - feat(eval-mvp): add AuthorizationTrace + DecisionReceiptRef types
  - feat(eval-mvp): anchor authorization trace in audit chain payload
  - test(eval-mvp): fail-closed receipts + chain verification
  - ci(eval-mvp): run authorization trace receipt tests
  - (optional) chore(gove-zone): refresh week-2 gate artifact under R5/R6

DO NOT MERGE. Stop after the final commit and emit a short summary with:
  - new files
  - extended files (per file: function/class added)
  - test counts (before / after)
  - any constraint that came close to being violated and how you steered
```

## Launch (background)

```bash
cd /home/martin/Downloads/govern-zone/ACGS/govern-zone
codex exec --dangerously-bypass-approvals-and-sandbox \
  "$(awk '/^## Goal text/{p=1;next} p && /^```text$/{q=1;next} q && /^```$/{exit} q' docs/codex-goals/phase1-week3-r5-r6-trace-receipts.md)"
```

## Status hooks

```bash
tail -f .omc/state/phase1-week3-goal-progress.log
tail -f .omc/state/phase1-week3-codex-exec.log
```
