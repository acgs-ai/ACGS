# Deviation report — 2026-07-28

| | |
|---|---|
| **Spec** | ACGS Hardening Spec — Enforcement Boundary & Reference Enforcement Topology |
| **Trigger** | Spec §0.3 — "Phase 0 refutes an assumption marked **LOAD-BEARING**" |
| **Surveyed ref** | `origin/master` @ `4459d849` |
| **Status** | **HALTED — awaiting review.** Deviations below are *proposed*, not executed. |
| **Evidence** | [phase0-baseline.md](./phase0-baseline.md) |

Three LOAD-BEARING assumptions are refuted: **A2**, **A3**, **A5**. One further
refutation (**A9**) has a pre-authorised remedy and does not itself halt work.

The common shape: **the repository is stronger than the spec assumes.** Every
refutation narrows scope rather than widening it. No refutation weakens a
guarantee, and no proposal below reduces fail-closed behaviour.

---

## D-1 — A2 REFUTED: signing is already default-on

**Assumed:** Ed25519 signing is opt-in.

**Found:** `require_signature: bool = True` at `executor.py:50`, `executor.py:291`,
and `contracts.py:272` — all three public gate surfaces. Signing is the default
posture, and the historical inconsistency between `execute_with_receipt` and
`ReceiptVerifier` has been closed.

Clause (b) of A2 survives in part: there is **no `signature_mode` field and no
startup warning**. An unsigned marker does exist on the data
(`signature="unsigned_local"`, `plan.py:74`, `workflow.py:158`;
`signature_algorithm="none"`, `workflow.py:197`) and a rejection code exists
(`errors.py:49 UNSIGNED_REJECTED`).

**Impact on WS-B2.** The clause "Whatever mechanism the repo uses for a production
profile defaults `require_signature=true`" is **already satisfied** — no code
change required, and attempting one risks a no-op diff or an accidental
regression.

**Proposed scope adjustment.** Reduce WS-B2 to the two genuinely missing pieces:
1. Add `signature_mode: UNSIGNED_DEV` to receipts and audit records when
   verification is disabled.
2. Emit a startup warning on that path.

Drop the default-flip. Note this also removes the WS-B "breaking change" concern
for signing: there is no default to flip, so no migration note is owed for it.

---

## D-2 — A3 REFUTED (partially): the anchor *verifier* exists; the *sink* does not

**Assumed:** no external anchoring mechanism exists.

**Found:** the verification half is shipped.
`audit.py:308-341` — `verify_chain(*, expected_count=None, expected_last_hash=None)`,
enforced at `:375` and `:385`. The docstring already states the honest property
the spec asks for: the chain "alone therefore cannot detect rollback" (`:329`),
and the operator must "Persist whichever anchor you can … in a store the audit
writer cannot rewrite" (`:339`). Detection is proven by
`test_audit_chain_corruption.py:155::test_verify_chain_detects_whole_event_truncation`,
which asserts both directions — keyless verify returns `valid=True` on a
truncated prefix; anchored verify returns `length_mismatch` + `last_hash_mismatch`.

What is genuinely absent is the *anchoring* half: no `AnchorSink`, no sink
implementations, no checkpoint emission, and **no shipped `src/` caller passes
either anchor argument** across seven call sites (`audit.py:72`, `cli.py:117`,
`cli.py:710`, `proofpack.py:296`, `replay.py:272`, `smoke.py:87`,
`verifier.py:410`).

**Characterise this precisely.** It is *keyless by design with the anchor as a
documented operator duty* — **not** an accidental wiring omission. The
distinction matters for the claims map: the control's strength is bounded by
operator discipline the repo does not implement, which is a different statement
from "the feature is unwired."

**Impact on WS-B4.** The "verification helper" deliverable is **already
satisfied** by `verify_chain`. Building a second one would duplicate a tested
control.

**Proposed scope adjustment.** Narrow WS-B4 to:
1. The `AnchorSink` interface and the two sinks (alternate-path file, HTTP webhook).
2. Periodic checkpoint emission.
3. Wiring at least one shipped path to *supply* the anchor to `verify_chain`.

Reuse `verify_chain` as the verifier rather than adding one. Also note
`max_clock_skew_seconds` already exists (`executor.py:55`, validated `:156`), so
WS-B3's "add a configurable max clock-skew tolerance" is likewise already done —
only the documentation clause of B3 remains.

---

## D-3 — A5 REFUTED: the README one-liner differs, and is already scoped

**Assumed wording:** "gove-zone is an alpha runtime governance plane for
receipt-gated agent execution — no valid Decision Receipt, no side effect."

**Found**, `README.md:32`:

> `For every execution path wired through ACGS: **No valid Decision Receipt, no side effect.**`

The assumed sentence does not appear. The shipped line **already carries a scope
qualifier** — "For every execution path wired through ACGS" — which performs
substantially the same function as the qualifier WS-A2 mandates.

**Impact on WS-A2.** The claims-surgery target does not exist as described. The
prescribed replacement text is written against a sentence that is not in the
repository.

**Proposed scope adjustment.** Two options for review; I recommend (a).

- **(a) Strengthen the existing line in place.** Keep its structure and add the
  deployment-mode pointer, e.g. *"For every execution path wired through ACGS:
  **No valid Decision Receipt, no side effect.** Wiring is the integrator's
  responsibility; adversarial deployments require the reference enforcement
  topology (`docs/ENFORCEMENT-BOUNDARY.md`)."* This honours guardrail §10.2
  (existing limitation acknowledgments are relocated or elevated, never deleted)
  and guardrail §10.6 (minimal diffs).
- **(b) Replace with the spec's sentence plus qualifier.** Rejected as the
  default: it discards a scope qualifier the project already shipped and
  substitutes a marketing-shaped sentence for a precise one.

Either way the mandatory-qualifier rule of §9/UC-A is satisfied. This is a
wording decision with claims consequences, so it is escalated rather than chosen.

---

## D-4 — A9 REFUTED: no claims map (pre-authorised remedy, not a halt)

No `docs/claims-map.md`; no `DO-NOT-SAY` / `SAY-WITH-CAVEAT` axes anywhere in
`docs/`. `docs/CLAIMS.md` and `docs/CLAIM_AUDIT.md` exist and are the natural
predecessors to fold in. Spec §3/A9 pre-authorises creating
`docs/claims-map.md` in WS-A; recorded here for completeness only.

---

## D-5 — A4 REFUTED: no `ADV-n` scheme; extend the manifest instead

No `ADV-n` identifiers exist. Adversaries are eight named classes in
`packages/gove-zone/tests/adversary/test_coverage_manifest.py`. Per §3/A4,
WS-A4's three new adversaries should extend that taxonomy rather than introduce
a parallel ID scheme — which also makes them machine-checked rather than prose.

---

## D-6 — New finding: the adversary manifest cannot record a gap

Not an assumption in §3, surfaced by the survey, and it bears directly on the
spec's claim-discipline objective.

`test_coverage_manifest.py:104`:

```python
_VALID_STATIC = frozenset({"DEFENDED"})
_VALID_ADAPTIVE = frozenset({"STABLE", "BYPASSABLE", "UNTESTED"})
```

Line 127 asserts every class's `status` ∈ `_VALID_STATIC`. All eight classes
therefore read `"status": "DEFENDED"` **by construction** — the schema admits no
other value. The only field that can express failure is `adaptive`, which reads
**5 BYPASSABLE to 3 STABLE**: `forged-authorization`, `replayed-authorization`,
`ledger-tampering`, `policy-downgrade`, and `validator-bypass` are BYPASSABLE.

The artifact that certifies adversarial coverage is structurally incapable of
reporting its absence, and the field a reader would naturally consult
(`status`) is the one that cannot be false.

**Proposed addition to WS-A** (small, additive, test-only, touches no
security-sensitive source file):
1. Widen `_VALID_STATIC` to admit at least `GAP` / `PARTIAL`.
2. Reclassify the five BYPASSABLE classes honestly against that vocabulary.
3. Require every non-`DEFENDED` class to carry a reproducing-test pointer, so a
   gap cannot be recorded without evidence.

Rationale for putting it in WS-A rather than a later PR: it is a **claims**
defect, not a controls defect, and WS-A is where claim discipline is established.
Leaving it until WS-C means the claims map would be built on a source that
cannot contradict it.

---

## Requested decisions

| # | Decision | Recommendation |
|---|---|---|
| 1 | Accept the D-1/D-2 scope reductions (drop already-satisfied deliverables)? | Accept — building them duplicates tested controls. |
| 2 | D-3: strengthen the existing README line, or replace it? | Strengthen in place (option a). |
| 3 | D-6: pull the manifest-schema fix into WS-A? | Yes — it is a claims defect and gates the claims map's credibility. |
| 4 | Confirm the target ref/branch for PR-1 onward. | This survey and branch `docs/phase0-baseline` are cut from `origin/master` @ `4459d849`. |

## Note on the target repository

The spec names `github.com/dislovelhl/ACGS`. Master's HEAD is a merge from
`acgs-ai/ACGS` (`4459d849`), consistent with a prior org transfer; the old path
still resolves by redirect. Flagged for confirmation, not treated as blocking.

## What was not done

WS-A, WS-B, WS-C, and WS-D are **not begun**, per spec §0.3 and §4. No source
file was modified. No claim was added, changed, or retired, so this PR carries an
empty Claims Delta.
