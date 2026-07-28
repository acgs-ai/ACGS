# WS-A handoff — enforcement boundary & claims surgery

| | |
|---|---|
| **Spec** | ACGS Hardening Spec — Enforcement Boundary & Reference Enforcement Topology |
| **Workstream** | A (PR-2), plus D-6 pulled in by approval |
| **Base** | `origin/master` @ `4459d849`, branch `docs/phase0-baseline` |
| **Date** | 2026-07-28 |
| **Gate for** | WS-B / WS-C / WS-D |

## 1. What shipped

| Commit | Change |
|---|---|
| `deea29b3` | Phase 0 baseline survey + deviation report (PR-1) |
| `fc6b39c1` | D-6: coverage manifest can express a gap; three new adversaries |
| `d5b9a1ad` | `docs/claims-map.md` (A9 remedy) |
| `34831dd7` | `docs/ENFORCEMENT-BOUNDARY.md` + README scoping (A1, A2) |
| `4280df4f` | Record the failed adversarial verification; mark the docs provisional |
| `91c7cb0e` | Hash-coverage drift guards; posture↔evidence consistency in the manifest |

> **Corrected after adversarial verification.** An earlier revision of this
> handoff asserted that no audit-anchor sink exists and that no static
> gate-wiring check exists. **Both were false.** See
> [ws-a-verification-findings.md](./ws-a-verification-findings.md) F-2 and F-3;
> §3 and §5 below are the corrected versions. Downstream workstreams scope off
> these tables, so they were fixed before the prose.

### A1 — enforcement boundary document
`docs/ENFORCEMENT-BOUNDARY.md`, five sections as specified: what the kernel enforces (with the
two opt-in controls called out as not-default), what an in-process library cannot enforce, four
trust preconditions each with its degradation mode, two deployment modes, and a per-adversary
coverage matrix keyed to the machine-checked manifest.

### A2 — README
Canonical statement kept **byte-for-byte** — it is the literal asserted by
`tests/docs/test_docs_and_examples.py:66-71`. Added an "Enforcement boundary" section inside the
first screenful defining "wired through ACGS", assigning wiring responsibility to the integrator,
and stating the fail-closed expectation for registered paths. Strengthened in place per the
approved decision; no broader absolute claim introduced.

### A3 — claims map
`docs/claims-map.md`: SAY / SAY-WITH-CAVEAT / DO-NOT-SAY axes, each caveated row carrying an
evidence pointer and unlock condition. Created as a **new** file rather than an edit to
`CLAIMS.md`, which is a live tripwire (three tests; ≥6-cell rows; literal `not claimed` /
`roadmap` spellings; backticked citations resolved on disk; editing row L19 reds the build).
Those constraints are now documented so the next editor does not find them by breaking CI.

### A4 — adversary expansion
The three spec adversaries were added to the **existing** eight-class manifest rather than a
parallel `ADV-n` scheme, per the approved remedy. They are machine-checked, not prose:

| Class | status | Why |
|---|---|---|
| `negligent-integrator` | PARTIAL | Wiring proven for shipped examples only; nothing detects a newly added ungoverned path |
| `compromised-host` | BYPASSABLE | Cites the `xfail` residual documenting that keyless `verify_chain()` accepts a self-consistent full rewrite, alongside the test asserting the anchored boundary. *(Corrected in `91c7cb0e`: the originally cited test asserts both halves, so the entry's comment was half wrong — F-6.)* |
| `exec-capable-agent` | UNKNOWN | No test models it in either direction |

### D-6 — the manifest can now express a gap
`status` was `Literal["DEFENDED"]`, asserted on every entry, so every class read DEFENDED by
construction — and a class with no coverage could not be added at all. Widened to
DEFENDED / PARTIAL / BYPASSABLE / UNKNOWN in both the TypedDict and the validator, with two
invariants: an evidence-bearing posture must cite a real test, and UNKNOWN must cite none.
`BASELINE_CLASSES` replaces the hard-coded eight-way equality — the taxonomy may grow, not shrink.

**Extended in `91c7cb0e` after verification showed the above was not enough.** Those invariants
proved a posture was *representable*, not that it matched its evidence: flipping
`compromised-host` from BYPASSABLE to DEFENDED with an unchanged `covering` list passed every
check. The manifest now separates claim (`status`), evidence (`covering`, plus a GAP/BOUNDARY
kind derived from the cited test's own `xfail` marker or `_KNOWN_GAP` suffix), and verifier, and
checks the first against the second — DEFENDED may not cite a gap-documenting test, BYPASSABLE
must. Deriving the kind from the test source rather than a label beside the claim is the point:
a maintainer cannot inflate a posture without changing evidence. The docstring now states that
this establishes consistency, **not** truth.

`test_adaptive_stability.py` asserted `VARIANT_GENERATORS == MANIFEST`, a strict 1:1 lock. That
set is now `MODELLED` (`adaptive != UNTESTED`), pinned in both directions, which gives `UNTESTED`
a meaning — it was previously pinned to zero and therefore a dead enum value.

## 2. Evidence artifacts

```
gove-zone suite   1191 passed, 0 failed, 5 skipped   (baseline 1189; +2 from split invariants)
tests/docs        84 passed, exit 0
make lint-docs    exit 0
ruff check        All checks passed
ruff format       2 files already formatted
```

Counts are from JUnit XML, not stdout. Earlier in this program a `| tail` pipe masked a non-zero
pytest exit; the discipline is now to redirect and read the XML.

**Guards proven to fire, not merely to pass.** Each new manifest invariant was exercised against
a synthetic violation — posture-without-evidence, UNKNOWN-with-evidence, bad vocabulary, dropped
baseline class, nonexistent covering node — and all five raised.

**Known-failing, pre-existing, unrelated:** `scripts/verify_constitutional_hashes.py` reports
drift in this worktree. The report is REMOVED-only (no CHANGED section) across
`packages/acgs-lite/**` and `packages/clinicalguard/**`, both uninitialized submodules here
(`git submodule status` shows a leading `-`). No file touched by WS-A appears in it. Initialize
the submodules before treating this as a regression.

## 3. Assumptions — refuted

| ID | Verdict | Consequence |
|----|---------|-------------|
| A2 | **REFUTED** | `require_signature` already defaults `True` at all three gate surfaces. The WS-B2 default-flip is already satisfied; only `signature_mode` marking and a startup warning remain. No migration note owed for signing. |
| A3 | **REFUTED — more strongly than first recorded** | The anchor verifier ships and is tested, **and so does a persisted sink.** `Organization.audit_anchor_count` / `audit_anchor_hash` (`models.py:57-58`) are written inside the same transaction as each persisted receipt (`governance.py:756-758`, `SELECT … FOR UPDATE`), read back at `app.py:1731` and `:1792`, migration-managed since `0001_legacy_v0.py:31`, and re-checked by `migration_recovery.py:738`, `:989`, `:1131`. **The WS-B4 "build the sink" scope is void, and the earlier "reduced scope — reuse `verify_chain`" recommendation is withdrawn**: the remaining question is whether gove-zone should ship an anchor interface of its own, given a consumer already implements one. |
| A5 | **REFUTED** | README already carried a scope qualifier. Strengthened in place. |
| A4 | REFUTED | No `ADV-n` scheme; extended the manifest instead. **Done in this PR.** |
| A8 | REFUTED | `_locking.py` is already cross-platform. Guardrail §10.7 needs no action. |
| A9 | REFUTED | No claims map existed. **Created in this PR.** |

## 4. Assumptions — still active

| ID | Status | Why it still matters |
|----|--------|----------------------|
| A1 | **CONFIRMED at the gate default, but narrower than first recorded** | Single-use is opt-in *at the gate* (`consumption_ledger=None` at `executor.py:56`, `:297`, `:354`). It is **mandatory under an existing profile**: `GovernanceProfile.production_strict` takes `consumption_ledger` as a required keyword and raises `ProductionProfileError` when it is `None`, and sets `require_expiry=True` (`profile.py:134-141`). So the hardened posture WS-B1 was scoped to create partly exists. Caveat from its own docstring: anti-replay and TTL are active on selection at the gate, but the policy watchdog is a separate wiring seam the caller must connect at kernel construction. WS-B1 should be re-scoped to "make `production_strict` reachable/default and close the watchdog seam", not "build single-use enforcement". |
| A6 | **CONFIRMED — still true** | No `deploy/` directory. WS-C is greenfield. |
| A7 | **CONFIRMED — still true** | MACI roles remain string-identified with no per-role key. WS-C4 / WS-D unaffected. |

New assumptions WS-A introduces, which later workstreams inherit:

- The `adaptive` field, not `status`, is the honest signal for adversary posture. Any future
  reporting that cites `status` alone is uninformative for classes recorded before 2026-07-28.
- `docs/claims-map.md` is the single source of speech permission. `CLAIM_AUDIT.md` verdicts are
  dated and must be re-verified, not copied forward.

## 5. Remaining security gaps

Unchanged by WS-A — this workstream documented them, it did not close any of them.

| Gap | Status | Owner |
|---|---|---|
| Complete mediation in-process | OPEN by placement | WS-C |
| Gate-wiring scan covers only claimed shipped examples, and asserts `imported & called` rather than mediation | OPEN — **narrower than first recorded** | unassigned — see below |
| Single-use receipts opt-in **at the gate default** (mandatory under `production_strict`) | OPEN, re-scoped | WS-B1 |
| No `signature_mode` field, no unsigned startup warning | OPEN | WS-B2 (reduced scope) |
| ~~No anchor sink; no shipped caller supplies an anchor~~ | **CLOSED — the premise was false.** A transactional sink and five shipped call sites exist in `acgs-control-plane` (§3, A3). What remains is scoped: no call site *inside `packages/gove-zone/src/`* supplies an anchor, so the library's own default posture is keyless | WS-B4 — re-scope before starting |
| No validator↔key binding; role separation is a string compare | OPEN | WS-C4 / WS-D |
| Sandbox degrades to unrestricted subprocess when bwrap absent and `require_bwrap` unset; that path is untested | OPEN | WS-C |
| No capability object; database and cloud effect channels wholly unmediated | OPEN | beyond current spec |
| Executor-compromise adversary has no test | OPEN | beyond current spec |
| ISO 27001 absent from the control mapping (ISO 42001 is present) | OPEN | beyond current spec |

**Not covered by any workstream:** widening the gate-wiring scan. A static AST check does
exist and is CI-enforced — `packages/gove-zone/tests/test_gate_wiring_matrix.py`, run by
`saas-beta-required.yml:202` — and an earlier revision of this handoff wrongly said it did
not. Its limits are the real gap: it asserts that a gate entrypoint is *imported and called*
somewhere in the module (`:170-173`), which is weaker than proving the side effect is
mediated, and it runs only over the examples `docs/INTEGRATION_MATRIX.md` claims as shipped.
The spec's §1 premise is that integration bypass is the core risk, yet nothing in WS-A–WS-D
extends that check to cover a newly added effect path. Recommend extending it, scoped by the
capability model it would need to check against.

## 6. WS-A work not done

- **The A3 text remediation.** 15 forbidden or unscoped occurrences were found and are recorded
  in the claims map's remediation ledger, but **none was corrected.** Deliberate: the fixes span
  a Chinese-language strategy document, an archive file, a shipped example README, and a source
  docstring, and several need judgment rather than substitution. This belongs in its own
  reviewable diff. The claims map is honest about the gap rather than implying a clean sweep.
- **Per-adversary claims tables in the threat model.** The coverage matrix in
  `ENFORCEMENT-BOUNDARY.md` §5 covers the per-mode axis; per-adversary what-holds/what-degrades
  tables inside `docs/security/threat-model-v2.md` were not added.

## 7. Readiness

**WS-B must be re-scoped before it starts.** Two of its four items rested on premises this
handoff previously stated wrongly: WS-B4's sink does not need building (§3, A3), and WS-B1's
hardened posture partly exists as `GovernanceProfile.production_strict` (§4, A1). Starting
WS-B against the original scope would build something twice. WS-D is unaffected. WS-C depends
on PR-2 and PR-3 per the spec's sequencing.

**UC-A: NOT satisfied.** The documentation artifacts exist and their known-false statements
are now corrected, but three things remain open:

1. **A3 text remediation** — 15 forbidden or unscoped occurrences recorded in the claims map's
   remediation ledger; correction is in progress in this PR series, not complete.
2. **Per-adversary claims tables** in `docs/security/threat-model-v2.md` — not written.
3. **Independent re-verification** — the corrections in this pass were made by the same author
   whose claims failed verification. They have not themselves been adversarially re-checked.

Declaring UC-A met is the reviewer's call on the merged PR. This document does not claim it.

**All commits are local.** Pushing is human-gated; PR-2 has not been opened.
