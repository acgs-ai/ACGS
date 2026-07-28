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
| `compromised-host` | BYPASSABLE | Covering test documents the keyless bypass rather than asserting a boundary |
| `exec-capable-agent` | UNKNOWN | No test models it in either direction |

### D-6 — the manifest can now express a gap
`status` was `Literal["DEFENDED"]`, asserted on every entry, so every class read DEFENDED by
construction — and a class with no coverage could not be added at all. Widened to
DEFENDED / PARTIAL / BYPASSABLE / UNKNOWN in both the TypedDict and the validator, with two
invariants: an evidence-bearing posture must cite a real test, and UNKNOWN must cite none.
`BASELINE_CLASSES` replaces the hard-coded eight-way equality — the taxonomy may grow, not shrink.

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
| A3 | **REFUTED in part** | The anchor *verifier* ships and is tested; the *sink* does not exist and no shipped caller supplies an anchor. WS-B4 should reuse `verify_chain`, not build a second verifier. |
| A5 | **REFUTED** | README already carried a scope qualifier. Strengthened in place. |
| A4 | REFUTED | No `ADV-n` scheme; extended the manifest instead. **Done in this PR.** |
| A8 | REFUTED | `_locking.py` is already cross-platform. Guardrail §10.7 needs no action. |
| A9 | REFUTED | No claims map existed. **Created in this PR.** |

## 4. Assumptions — still active

| ID | Status | Why it still matters |
|----|--------|----------------------|
| A1 | **CONFIRMED — still true** | Single-use remains opt-in (`consumption_ledger=None`). WS-B1 is unaffected by any WS-A change and is still needed in full. |
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
| No static scan / CI gate for a newly added ungoverned effect path | OPEN | unassigned — see below |
| Single-use receipts opt-in | OPEN | WS-B1 |
| No `signature_mode` field, no unsigned startup warning | OPEN | WS-B2 (reduced scope) |
| No anchor sink; no shipped caller supplies an anchor | OPEN | WS-B4 (reduced scope) |
| No validator↔key binding; role separation is a string compare | OPEN | WS-C4 / WS-D |
| Sandbox degrades to unrestricted subprocess when bwrap absent and `require_bwrap` unset; that path is untested | OPEN | WS-C |
| No capability object; database and cloud effect channels wholly unmediated | OPEN | beyond current spec |
| Executor-compromise adversary has no test | OPEN | beyond current spec |
| ISO 27001 absent from the control mapping (ISO 42001 is present) | OPEN | beyond current spec |

**Not covered by any workstream:** the static-scan / CI gate. The spec's §1 premise is that
integration bypass is the core risk, yet nothing in WS-A–WS-D adds a check that fails when a
developer introduces an ungoverned effect path. Recommend adding it, scoped by the capability
model it would need to check against.

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

WS-B and WS-D may proceed; neither depends on the unfinished WS-A items. WS-C depends on
PR-2 and PR-3 per the spec's sequencing.

**Unlock conditions:** none met. UC-A's documentation half is satisfied by `34831dd7`, but
declaring UC-A met is the reviewer's call on the merged PR, not this document's.

**All commits are local.** Pushing is human-gated; PR-2 has not been opened.
