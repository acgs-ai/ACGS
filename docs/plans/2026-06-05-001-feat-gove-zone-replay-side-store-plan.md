---
title: "feat: gove-zone replay side-store — true decision re-derivation"
status: active
date: 2026-06-05
type: feat
depth: standard
plan_id: 2026-06-05-001
target_package: packages/gove-zone
---

# feat: gove-zone replay side-store — true decision re-derivation

## Summary

Add an opt-in raw-arguments side-store so `gove-zone replay` can re-execute the
original policy against the original `ToolCall` and confirm the recorded verdict
still holds — turning today's chain-integrity + policy-version check into genuine
decision re-derivation. The tamper-evident audit chain stays **hash-only and
unchanged**; the side-store is a separate, off-by-default file.

---

## Problem Frame

`gove-zone replay` (see `packages/gove-zone/src/gove_zone/cli.py` `_replay`)
currently verifies three things against an audit JSONL chain: the hash chain is
intact, the `event_id` exists, and the recorded `audit_hash` matches. It does
**not** re-run the policy, because the audit chain deliberately stores only
`argument_hash` — never raw arguments (`decision.py` `DecisionRecord.to_dict`,
`integration.py` `_summarize_tool_input`). That hash-only property is a privacy
and chain-size guarantee we must preserve.

The kernel already ships the strong-form primitive `replay_call`
(`replay.py`) — it reconstructs the decision from a real `ToolCall` + `Policy` —
but nothing persists the raw `ToolCall`, so the CLI can only reach the weak
`replay_event` path (`reason="policy-version-only replay; raw args not in audit
event"`). The README now documents this gap honestly (PR #78). This plan closes
it: an opt-in side-store that retains the raw call so `replay_call` can be wired
into the CLI.

---

## Requirements

- R1. An opt-in, off-by-default store persists the raw `ToolCall` (args, state,
  path, actor, goal, tool) keyed by `event_id`, alongside the recorded
  `argument_hash`, `policy_version`, and `decision`.
- R2. The audit chain format and its hash-only privacy property are unchanged.
- R3. `gove-zone replay`, given the side-store and the original policy bundle,
  re-executes the policy and reports whether the re-derived decision matches the
  recorded decision (true re-derivation), in addition to today's chain checks.
- R4. Replay cross-checks the side-store record against the chain: the stored raw
  args must hash to the audit event's recorded `argument_hash`; a mismatch is a
  tamper signal and fails the replay.
- R5. Re-derivation requires the supplied policy's `version` to match the
  recorded `policy_version`; a version mismatch is reported, not silently passed.
- R6. A redaction predicate can exclude sensitive calls/fields from raw
  persistence. Redacted events are flagged non-replayable and replay falls back
  to event-only verification for them — honestly, never claiming re-derivation.
- R7. Enabling the side-store is a single, agent-followable surface mirroring the
  existing gate-mode pattern (env var + opt-in constructor wiring).

---

## Key Technical Decisions

- **KTD1 — Separate side-store file, never the chain (R2).** A new
  `ChainHashAuditStore`-adjacent `ReplaySideStore` writes its own JSONL keyed by
  `event_id`. The audit chain stays byte-for-byte as today. This keeps the
  hash-only chain guarantee intact and makes the side-store independently
  deletable/prunable for retention.
- **KTD2 — Off by default, opt-in (R1, R7).** The `Kernel` takes an optional
  `side_store: ReplaySideStore | None = None`. When `None` (default), behavior is
  identical to today — zero new I/O, no raw args anywhere. Resolution mirrors
  `integration.current_gate_mode`: explicit constructor wins; an env var
  (`GOVE_ZONE_REPLAY_STORE`) and `.gove-zone/replay.jsonl` default path provide
  the agent-followable surface for the CLI/hook side later.
- **KTD3 — Policy supplied at replay time; version cross-checked, not snapshotted
  (R3, R5).** Replay loads the policy via `--policy-bundle` (same pattern as
  `gove-zone gate`). The side-store records `policy_version` so replay refuses to
  claim re-derivation when the supplied policy's version differs. Rationale:
  persisting a full policy snapshot per event duplicates policy lifecycle into the
  store and bloats it; `RuleSetPolicy` versions are already content-addressed, so
  a version match is a strong equivalence signal. (Alternative — persist a policy
  snapshot — deferred; see Scope Boundaries.)
- **KTD4 — Redaction is fail-safe and honest (R6).** Redaction is in genuine
  tension with replay fidelity: a redacted field cannot reproduce the recorded
  `argument_hash`, so a "redact-but-still-replay" mode would be a lie. Instead, a
  redaction predicate marks matching events as **not persisted raw** — the
  side-store writes a tombstone (`event_id`, `redacted: true`, no raw args). Replay
  of a tombstoned event reports `replayed: false, reason: redacted` and falls back
  to event-only verification. Default predicate persists everything (empty
  denylist); operators opt into redaction.
- **KTD5 — Reuse `replay_call`, don't reinvent (R3, R4).** The re-derivation core
  is the existing `replay_call(ToolCall, expected_decision, policy,
  expected_policy_version)`. The new code reconstructs the `ToolCall` from the
  side-store record and the `expected_decision` from the audit event, then
  delegates. Cross-check (R4) compares `ToolCall.argument_hash()` of the
  reconstructed call to the audit event's `argument_hash` before trusting it.

---

## High-Level Technical Design

Write path (opt-in) and replay path:

```text
WRITE (Kernel.dispatch, only when side_store is set)
  ToolCall ──▶ policy.evaluate ──▶ DecisionRecord ──▶ audit.append (hash-only, unchanged)
                                          │
                                          └─▶ side_store.append(call, record)
                                                 ├─ redaction predicate matches? ──▶ tombstone {event_id, redacted:true}
                                                 └─ else ──▶ {event_id, tool, actor, goal, path,
                                                              args(raw), state(raw), argument_hash,
                                                              policy_version, decision}

REPLAY (gove-zone replay --audit CHAIN --side-store STORE --policy-bundle P --event E)
  1. chain = audit.verify_chain()            # existing
  2. event = find E in chain                 # existing
  3. side = side_store.get(E)
       ├─ none/tombstone ──▶ event-only result (verified=chain∧found; rederived=false; reason)
       └─ present:
            a. reconstruct ToolCall(args,state,path,actor,goal,tool)
            b. cross-check ToolCall.argument_hash() == event.argument_hash   # R4 tamper gate
            c. replay_call(call, expected=event.decision, policy, expected_version=event.policy_version)
            d. rederived = chain.valid ∧ found ∧ arghash_match ∧ replay.matches
```

---

## Implementation Units

### U1. ReplaySideStore module

- **Goal:** New persistence primitive that stores/loads raw `ToolCall` data keyed
  by `event_id`, with a redaction predicate and tamper cross-check helper.
- **Requirements:** R1, R4, R6.
- **Dependencies:** none.
- **Files:**
  - `packages/gove-zone/src/gove_zone/replay_store.py` (new)
  - `packages/gove-zone/tests/test_replay_store.py` (new)
- **Approach:** `ReplaySideStore(path, *, redact=None)`. `append(call: ToolCall,
  record: DecisionRecord) -> dict` writes one JSONL line: either a full record
  (`event_id`, `tool`, `actor`, `goal`, `path` list, `args` raw, `state` raw,
  `argument_hash`, `policy_version`, `decision`) or, when `redact(call)` is truthy,
  a tombstone (`event_id`, `redacted: true`). `get(event_id) -> dict | None` reads
  back the last record for an id. `redact` is `Callable[[ToolCall], bool]`;
  default `None` ⇒ persist everything. Reuse `decision.sha256_json` /
  `canonical_json`; mirror `ChainHashAuditStore` file-handling (parent mkdir,
  utf-8, append). No hash chaining — this store is a lookup table, not a chain;
  integrity comes from cross-checking against the chain at replay (R4).
- **Patterns to follow:** `audit.py` `ChainHashAuditStore` (file I/O, `iter`/`get`
  shape); `tool.py` `ToolCall.argument_hash`.
- **Test scenarios** (`tests/test_replay_store.py`):
  - Happy: `append` a full call then `get(event_id)` returns raw args/state/path
    and the recorded `argument_hash` equals `ToolCall.argument_hash()`.
  - Round-trip fidelity: a `ToolCall` reconstructed from `get()` produces the same
    `argument_hash()` as the original.
  - Redaction: with `redact=lambda c: "id_rsa" in canonical_json(dict(c.args))`,
    `append` writes a tombstone; `get()` returns `{redacted: true}` and no raw args.
  - Missing id: `get("ev_absent")` returns `None`.
  - Multiple events: appending N calls and getting each returns the right record.
  - Empty/no-state call: a call with empty `state`/`path` round-trips (state stored
    as `{}`/omitted consistently; `argument_hash` still matches).

### U2. Wire optional side-store into the Kernel

- **Goal:** `Kernel` optionally writes to a `ReplaySideStore` on every dispatch,
  off by default, without altering the audit-chain path or any existing behavior.
- **Requirements:** R1, R2, R7.
- **Dependencies:** U1.
- **Files:**
  - `packages/gove-zone/src/gove_zone/kernel.py` (modify)
  - `packages/gove-zone/tests/test_kernel_dispatch.py` (modify)
- **Approach:** Add `side_store: ReplaySideStore | None = None` to `Kernel.__init__`.
  In `_evaluate_and_record`, after `self.audit.append(record)` succeeds, if
  `self.side_store is not None`, call `self.side_store.append(call, record)` inside
  a `contextlib.suppress`-free but **fail-closed-consistent** guard: a side-store
  write failure must NOT silently allow — but it also must not corrupt the audit
  contract. Decision: a side-store failure raises `AuditError`-adjacent only when
  the kernel is in an enforce posture; default raises nothing and the dispatch
  proceeds (the chain — the source of truth — already recorded). Keep the
  side-store strictly additive: it never changes the returned `(record, audit_hash)`
  nor the decision. Confirm the write happens for ALLOW, DENY, TRANSFORM, and the
  fail-closed synthesized-DENY branches (the raw call is the same object).
- **Patterns to follow:** existing `_evaluate_and_record` audit-append guard in
  `kernel.py`; `Kernel.__init__` keyword-only args.
- **Execution note:** Add a failing test first asserting that with `side_store=None`
  the dispatch path is byte-for-byte unchanged (no file created), then add the
  opt-in write.
- **Test scenarios** (`tests/test_kernel_dispatch.py`):
  - Default off: `Kernel(...)` with no `side_store` creates no side-store file and
    behaves identically (existing assertions still pass).
  - Opt-in ALLOW: with a `side_store`, an allowed dispatch writes a side record
    whose `argument_hash` matches the receipt's, keyed by the receipt `event_id`.
  - Opt-in DENY: a denied dispatch (raises `DeniedError`) still wrote a side record
    for the denied `event_id` (re-derivation must work for denies too).
  - Side record matches audit: the side record's `event_id`, `argument_hash`,
    `policy_version`, `decision` equal the corresponding audit event fields.
  - Redacted call: with a `redact` predicate matching the call, the side-store has
    a tombstone but the audit chain entry is normal (chain unaffected by redaction).
  - Integration: creating a kernel with a side-store, dispatching, then reading the
    side-store back yields a record that `replay_call` (U3) can consume — proves the
    write path feeds the read path, not just a unit in isolation.

### U3. Side-store-backed re-derivation in replay.py

- **Goal:** A function that, given an audit event, its side-store record, and a
  policy, reconstructs the `ToolCall`, runs the tamper cross-check, and delegates
  to `replay_call` to re-derive the decision.
- **Requirements:** R3, R4, R5.
- **Dependencies:** U1.
- **Files:**
  - `packages/gove-zone/src/gove_zone/replay.py` (modify)
  - `packages/gove-zone/tests/test_replay.py` (modify)
- **Approach:** Add `replay_from_side_store(event: dict, side_record: dict, policy:
  Policy) -> ReplayResult`. Reconstruct `ToolCall(name=event["tool"],
  args=side_record["args"], goal=..., actor=..., path=tuple(...),
  state=side_record.get("state", {}))`. First cross-check
  `call.argument_hash() == event["argument_hash"]`; on mismatch return a
  `ReplayResult(matches=False, ..., reason="side-store argument_hash does not match
  audit chain")` (R4). Otherwise call `replay_call(call,
  expected_decision=Decision(event["decision"]), policy=policy,
  expected_policy_version=event["policy_version"])` and return its result (R3, R5).
  Extend `ReplayResult` only if a tamper-distinct reason needs a field; prefer
  reusing existing fields with a clear `reason`.
- **Patterns to follow:** existing `replay_call` / `replay_event` in `replay.py`;
  `ReplayResult.to_dict`.
- **Test scenarios** (`tests/test_replay.py`):
  - Happy re-derivation: dispatch through a kernel with a side-store, then
    `replay_from_side_store(event, side_record, policy)` returns `matches=True`,
    `replayed_decision == recorded`.
  - Deny re-derivation: a denied call re-derives to `DENY` and matches.
  - Tamper cross-check: corrupt the side record's `args`, replay returns
    `matches=False` with the argument_hash-mismatch reason (R4).
  - Policy version mismatch: replay with a different-version policy reports
    `policy_version_match=False` and `matches=False` (R5).
  - Args-now-trip-policy: side args that a *changed* policy would now DENY surface
    `matches=False`, `replayed_decision=DENY` (re-derivation actually re-runs).
  - Covers AE: the recorded ALLOW for safe args re-derives to ALLOW under the
    original policy.

### U4. CLI: wire true re-derivation into `gove-zone replay`

- **Goal:** `gove-zone replay` accepts `--side-store` and `--policy-bundle`; when
  both are present and the event has a non-redacted side record, it reports true
  re-derivation; otherwise it cleanly falls back to today's event-only result.
- **Requirements:** R3, R5, R6.
- **Dependencies:** U1, U3.
- **Files:**
  - `packages/gove-zone/src/gove_zone/cli.py` (modify `_replay`, `build_parser`)
  - `packages/gove-zone/tests/test_cli.py` (modify)
- **Approach:** Add `--side-store PATH` and `--policy-bundle PATH` to the `replay`
  subparser. In `_replay`: keep all existing chain checks. When `--side-store` and
  `--policy-bundle` are given, load the policy via `RuleSetPolicy.load` (same
  error-to-exit-2 handling as `_gate`), `ReplaySideStore(path).get(event_id)`, and
  if a non-tombstone record exists call `replay_from_side_store`. Emit the existing
  JSON plus `rederived: bool`, `replayed_decision`, `policy_version_match`, and a
  `rederivation_status` of `verified` | `redacted` | `no-side-record` |
  `policy-version-mismatch` | `argument-hash-mismatch`. Exit non-zero when the
  caller asked for re-derivation (both flags present, record exists,
  non-redacted) and it failed; preserve current exit semantics otherwise.
- **Patterns to follow:** `_gate` policy-bundle load + exit-2 on bad bundle;
  existing `_replay` JSON-emit + exit code shape.
- **Test scenarios** (`tests/test_cli.py`):
  - Re-derivation success: seed a chain + side-store via a kernel, run `_replay`
    with both flags → JSON `rederived: true`, `rederivation_status: "verified"`,
    exit 0.
  - No side record: event exists but absent from side-store → `rederivation_status:
    "no-side-record"`, chain still reported, exit code per existing rules.
  - Redacted event: tombstoned event → `rederivation_status: "redacted"`,
    `rederived: false`, no crash.
  - Bad policy bundle: `--policy-bundle` points at invalid JSON → stderr + exit 2
    (mirror `_gate`).
  - Backward compatible: `replay --audit CHAIN --event E` with NO new flags emits
    exactly today's keys plus nothing that breaks existing consumers, exit
    unchanged.
  - Tamper: side record args mutated → `rederivation_status:
    "argument-hash-mismatch"`, exit non-zero.

### U5. Docs + setup surface

- **Goal:** Document the side-store and the now-real re-derivation; expose the
  opt-in surface in `gove-zone setup`/`enable` guidance; update the README replay
  section that PR #78 made honest.
- **Requirements:** R6, R7.
- **Dependencies:** U1–U4.
- **Files:**
  - `packages/gove-zone/README.md` (modify the "Replay (what it actually
    verifies)" section)
  - `packages/gove-zone/src/gove_zone/setup.py` (modify — mention
    `GOVE_ZONE_REPLAY_STORE` opt-in in generated instructions, if setup emits
    audit/gate config today)
  - `packages/gove-zone/tests/test_setup.py` (modify, only if setup output changes)
- **Approach:** README: add a short subsection showing `gove-zone replay --audit
  ... --side-store ... --policy-bundle ...` and that re-derivation requires the
  opt-in store + original policy; keep the honest fallback note for the no-store /
  redacted cases. Setup: if `setup.py` already emits gate/audit env guidance, add
  one line for `GOVE_ZONE_REPLAY_STORE` as opt-in; otherwise skip the setup file
  and keep docs to the README.
- **Patterns to follow:** existing README replay section (PR #78); `setup.py`
  instruction generation.
- **Test scenarios:** `Test expectation: none -- docs-only`, except: if
  `setup.py` output changes, add one assertion in `test_setup.py` that the opt-in
  line is present in the generated instructions.

---

## Scope Boundaries

In scope: `packages/gove-zone` only — the side-store module, kernel opt-in wiring,
replay re-derivation, CLI flags, and docs.

### Deferred to Follow-Up Work

- **Hook-adapter side-store wiring.** `integration.emit_receipts_for_hook` could
  also write the side-store for runtime-hook traffic. Deferred: the kernel path is
  the coherent first slice and is fully testable via smoke/kernel; the adapter is
  observe-by-default and a larger surface.
- **Policy snapshot persistence** (KTD3 alternative). Persisting the full policy
  bundle per event for fully self-contained replay. Deferred in favor of
  version cross-check + supply-at-replay.
- **Side-store retention/pruning policy** (TTL, max-size). The store is a plain
  JSONL lookup; retention can be added once real usage informs limits.
- **Encryption at rest** for the raw-args side-store. Redaction (KTD4) is the
  shipped privacy control; encryption is a future hardening.

### Out of scope

- Any change to the audit chain format or its hash-only property (R2 forbids it).
- Frontend / `acgi-ai`, other packages.

---

## Risks & Dependencies

- **R-risk1 — Privacy regression if side-store is enabled carelessly.** Mitigation:
  off by default (KTD2), redaction predicate (KTD4), separate deletable file, and
  docs that frame raw-args persistence as an explicit opt-in cost.
- **R-risk2 — Side-store drift from chain.** A side record could be edited
  independently of the chain. Mitigation: replay's argument_hash cross-check (R4)
  treats any divergence as a failed re-derivation, not a silent pass.
- **R-risk3 — False confidence from version-only equivalence.** Two policies with
  the same `version` are assumed equivalent (the `Policy` ABC contract). This is
  the existing replay assumption; documented, not newly introduced.
- **Dependency:** no new third-party dependencies; reuses stdlib + existing
  `decision`/`tool`/`policy`/`replay` modules.

---

## Verification

- `uv run --package gove-zone python -m pytest packages/gove-zone/tests
  --import-mode=importlib -q` is green, including the new `test_replay_store.py`
  and the extended kernel/replay/cli tests.
- `uv run --package gove-zone gove-zone smoke` still exits 0 (chain path unchanged).
- A manual end-to-end: kernel with side-store → dispatch allow+deny → `gove-zone
  replay --side-store ... --policy-bundle ... --event <deny-id>` reports
  `rederived: true`, `replayed_decision: deny`.
- `ruff` / `mypy` clean per the package's own gates.
