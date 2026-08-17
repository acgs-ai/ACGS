# EXTERNAL_SUBSTRATE_IDENTITY_AND_AUTHORITY_INGESTION_V1 — Report

## Primary verdict

**`AUTHORITY_LAYER_READY`.**

The authority layer is built, verified, and fail-closed. The external substrate
is cryptographically bound (`IDENTITY_CONFIRMED`). No real external authority
evidence exists, so every request correctly remains `ROUTING_REQUIRED` — 306
counsel + 34 controller — and 0 are `READY_TO_SEND`. Per Sections 24/26 that is
the correct successful state: the mechanism refuses to manufacture readiness.

## Evidence classes (Section: evidence requirements)

- **repository fact** — grep/file state.
- **cryptographically bound fact** — sha256 / HMAC recomputed here.
- **runtime-tested behavior** — a command run this session with output below.
- **historical statement** — a prior-run number, re-confirmed live.
- **assumption / unresolved external fact** — marked as such.

Tests prove **implementation behavior only**. They prove no legal right,
real-world identity, appointment, engagement, recipient ownership, or external
authority.

## Literal verification (runtime-tested behavior)

```
verify_substrate_identity.py            -> IDENTITY_CONFIRMED (exit 0)   [same path AND relocated symlink]
verify_authority_state.py (empty reg)   -> VERDICT: AUTHORITY_LAYER_READY
                                           340 routing_required (306/34), 0 ready_to_send,
                                           0 rights_assertions, 0 recipients_invented,
                                           0 receipts, all invariants PASS
pytest attack_suite/test_attacks.py     -> 41 passed
ruff check <package>                    -> All checks passed!
verify_mutation_governance.py           -> ALL CHECKS PASSED (kernel, unchanged)
verify_mutation_integration.py          -> ALL CHECKS PASSED (integration, unchanged)
```

Isolated end-to-end demonstration on the **real** substrate (a synthetic
controller appointment ingested into a **temporary** registry — the real
package registry stayed 0 bytes):

```
ingest AE-DEMO-CONTROLLER               -> INGESTED (+ receipt); re-ingest -> IDEMPOTENT
compute_state(real substrate, tmp reg)  -> VERDICT: AUTHORITY_PARTIALLY_ACTIVATED
                                           ready_to_send 34, routing_required 306,
                                           controller remaining 0, counsel remaining 306,
                                           authority_receipts 68, receipt_failures 0,
                                           rights_assertions 0, recipients_invented 0, invariants all pass
real authority_evidence_registry.jsonl  -> 0 bytes (nothing fabricated persisted)
```

This proves the transition path works **and** is scoped: a real controller
appointment resolves exactly the 34 `NO_APPOINTED_CONTROLLER` requests and
leaves all 306 counsel requests fail-closed.

## Substrate identity

- **substrate_id:** `4bf789b9fc7b82a9`
- **critical_set_digest:** `4bf789b9fc7b82a9285fba2f07f4dc65a363b86718bfefd7102e4ac4a9553e14`
- **15 critical objects** bound (registry `aade071e…`, coverage `590fac64…`,
  ontology `e0e082d2…`, request schema `f6b2bbd2…`, `CRE_INDEX`, request verifier,
  request-exec `sha256sums.txt`; requirements catalog, `RIGHTS_REQUEST_MAPPING`,
  requirement schema, `CR_INDEX`, requirement verifier, requirement-model
  `sha256sums.txt`; top `verify_readiness.py`; `README.md`).
- **identity_class:** `EXACT_PRIOR_SUBSTRATE` — path binding **strong**,
  structural fingerprint **exact**, cryptographic binding **critical_objects**,
  **vcs_lineage unavailable**. No commit ancestry is claimed.

## The 20 required answers (Section 27)

1. **What external substrate was bound?**
   `~/Downloads/traj_procurement_guideline_20260609 (2)/governance_trajectories/COMMERCIAL_BUYER_READINESS_V1`
   (a downloaded, non-git, read-only trajectory bundle).
2. **What cryptographic objects establish its identity?** sha256 of a fixed
   15-object critical set, combined into `critical_set_digest`, plus the
   structural counts re-derived from the live registries. (cryptographically
   bound fact.)
3. **Strongest justified identity level?** `EXACT_PRIOR_SUBSTRATE` on three legs:
   authorship path binding (`verify_readiness.py` hardcodes ROOT here), exact
   critical-object hashes, exact count fingerprint.
4. **What identity claim cannot be made?** VCS/commit lineage or repository
   ancestry — the bundle has no git history. Identity proves "same artifact,"
   not "descended from a specific prior commit."
5. **Any corpus byte copied or modified?** No. Zero substrate bytes copied,
   zero written. Identity confirmed unchanged after every run (**I13**). The
   committed manifest redacts operator home paths (`~/Downloads/…`) and stores a
   hash of the full path instead, so no `/home/<user>/` string enters a tracked
   artifact.
6. **Any real authority identities available?** No — the registry is empty; the
   substrate's upstream `data_controller` is `UNASSIGNED` and no counsel is on
   file. (repository fact.)
7. **Requests blocked by controller absence?** **34** (`NO_APPOINTED_CONTROLLER`).
8. **Requests blocked by counsel absence?** **306** (`NO_EVIDENCED_COUNSEL_IDENTITY`).
9. **Did any request become `READY_TO_SEND`?** No — **0**, in the production
   (empty-registry) state.
10. **Exact evidence for each transition?** None in production (0 transitions).
    In the isolated demo, each of the 34 transitions was caused by
    `AE-DEMO-CONTROLLER` (a synthetic `DATA_CONTROLLER` record hashing a real
    demo document), scope `ALL/ALL`, and is bound by two receipts each.
11. **Any commercial rights asserted?** No — **0**. `rights_assertion` stays
    `null` on all 340 requests (**I6/I7**, gate-checked).
12. **Any recipients invented?** No — **0** (**I10**). A recipient is only ever
    the evidenced `subject_identity` of a real record.
13. **Does relocation preserve identity?** Yes — verified: a relocated symlink
    and a full copytree both return `IDENTITY_CONFIRMED` (identity matches by
    bytes, not path — Section 6).
14. **What happens when substrate bytes drift?** Fail closed on both the verdict
    **and the transition** (**I9**): identity resolves to `IDENTITY_MISMATCH`
    (changed object), `IDENTITY_UNVERIFIABLE` (missing object), or
    `SUBSTRATE_DRIFT` (counts diverge), and `compute_state` **never enters
    `route()`** when identity is not confirmed — zero transitions, zero receipts,
    even when verified evidence that would otherwise resolve requests is present.
    Verification never regenerates the manifest (attacks 01–08 + the ordering
    test `test_ordering_no_transition_on_drift`, Section 16).
15. **What happens when authority expires or is revoked?** Fail closed —
    `in_effect` returns False for an expired `effective_until`, any `revoked_at`,
    or a non-`Z`-UTC instant, so the request is not resolvable (**I12**, attacks
    16/17). A record named in another's `supersedes` is also deactivated and does
    not route (Section 15, `test_supersession_deactivates_old_record`).
16. **Are aggregate counts derived from request records?** Yes — `derived_counts`
    is a pure function of the records overlaid with receipted transitions; an
    injected aggregate is ignored (**I8**, attack 24).
17. **Did every governed transition have a valid receipt?** Yes —
    `receipt_verification_failures == 0`; the layer mints exactly two receipts
    per resolved request; replay and cross-request reuse are rejected (**I11**,
    attacks 19/20/32).
18. **Did the adversarial suite pass?** Yes — **41 passed** (32 attacks +
    invariants + 2 positive controls + the ordering-gate, confirmed-empty,
    supersession, and ingest-conflict `compute_state` tests).
19. **Did the external read-only substrate remain untouched?** Yes — no writes;
    identity re-confirmed after the full run; the layer does its own read-only
    verification and never depends on the legacy verifier's write path
    (Section 17).
20. **Exact final verdict?** `AUTHORITY_LAYER_READY`.

## Section 19 — Q19 / Case-M handling

The substrate's own request-execution `CRE_INDEX.json` records `mode: "full"`
with `Q19 (a rebuild reproduces the shipped artifacts) pass: true` and layer
tree `72129b81f50917e9…`. This layer binds that exact registry/coverage/ontology
by sha256 (critical objects), so any post-hoc change to the artifacts Q19 covers
would flip identity to `IDENTITY_MISMATCH`. This is **cryptographic binding of
the Q19-covered artifacts**, not an independent re-execution of the legacy Q19
gate — that gate couples validation with a write and cannot run against the
read-only mount. Stated as bound-fact, not as directly re-executed.

## Mutation-authority integration

**No repository mutation was performed**, so the Intent → Decision → receipt →
effect → evidence path was not exercised and no mutation receipt was required.
The authority-transition receipts here are a distinct, purpose-built lifecycle
that mirrors the kernel's crypto discipline without weakening it. Kernel and
integration baselines remain green (above); `_canonical.py` is vendored
byte-for-byte from the kernel.

## Smallest concrete fact that would change the numbers

A real appointment recorded in the substrate's
`ACGS_DATA_ASSET_REGISTRY/PRIVACY_OWNERSHIP.json` `data_controller` field
(currently `"UNASSIGNED"`), ingested as a `DATA_CONTROLLER` evidence record,
would move the **34** `NO_APPOINTED_CONTROLLER` requests toward `READY_TO_SEND`
(demonstrated in isolation above). The 306 counsel requests need an evidenced
counsel identity, scope-aware. Both must be recorded from real authority
evidence — the layer cannot and will not manufacture them.

## Scope & honesty

All files under
`packages/mutation-authority/EXTERNAL_SUBSTRATE_IDENTITY_AND_AUTHORITY_INGESTION_V1/`
(this session's clean scope). Substrate read-only and untouched. Real evidence
registry empty (0 bytes) by design. No controller, counsel, entity, recipient,
appointment, engagement, right, or clearance was invented.
