# Adaptive-Evaluation of the gove-zone Adversary Suite — Analysis (Cycle 7, Stage 1)

> **Provenance.** Authored by the parent (Hermes) under the parent-fallback protocol
> (`.claude/rules/headless-delegation.md` §Streaming-abort) after the headless analysis lane
> aborted pre-work twice (0 writes each, transcript-confirmed). Builder ≠ analyst separation
> holds: the stage-2 build stays delegated. Grounded in the real suite, not the paper alone.
>
> **Source paper.** arXiv:2606.26479v1, "Adaptive Evaluation of Out-of-Band Defenses Against
> Prompt Injection in LLM Agents" (Narisetty, Kore, Kattamanchi, Kumarapu; 25 Jun 2026).
> Abstract + metadata fetched to /tmp/adaptive.html. This analysis uses the abstract's claims
> only; the empirical section (AgentDojo / Qwen2.5-7B / Progent) is context, not portable code.

## 0. Claim-safety posture

This is a **local proof-pack analysis**. Nothing here claims gove-zone is "adaptively robust",
"certified", or benchmarked on AgentDojo. The paper's own headline result is explicitly *one
small-scale, weak-model, single-black-box-template data point* that is "consistent with, but does
not establish" OOB robustness. Our port is strictly narrower still: a **deterministic-gate
config/input-space variant search** with no model in the loop, no GCG, no LLM attacker.

## 1. What the paper gives us

1. **Taxonomy.** OOB defenses (CaMeL, FIDES, Progent, RTBAS, FORGE) are instances of **Biba
   integrity protection**, **reference monitoring**, and **least privilege**. gove-zone's
   receipt-gated executor (`execute_with_receipt`) is squarely this class: a deterministic
   reference monitor that mediates every side effect against a policy + receipt.
2. **The warning (the part we act on).** Every listed OOB defense is validated only on **static
   benchmarks** — a fixed set of injection attempts. That same methodology made *in-band*
   defenses look strong until **adaptive, defense-aware attacks broke 12 of them at >90%
   success**. The paper specifies the threat model + protocol an adaptive evaluation requires.
3. **Empirical (context only).** Independent repro of Progent's adaptive analysis: attack success
   cut ~6× (25.8%→4.2%), hand-crafted adaptive attack did not raise it (2.6%). One data point.

## 2. The gove-zone exposure this maps onto

The adversary suite (`packages/gove-zone/tests/adversary/`) pins a **static** posture via
`test_coverage_manifest.py`: **3 DEFENDED / 5 PARTIAL / 2 NOT_DEFENDED** across 10 classes, and
`test_taxonomy_posture_is_pinned()` freezes the exact sets. Each "DEFENDED" rests on **one**
hand-written exploit that fails against the gate (e.g. `signature-stripping` →
`test_receipt_signing.py::test_unsigned_rejected_when_required`). That is exactly the
static-benchmark shape the paper flags: **a class is called DEFENDED because one template fails,
not because a defense-aware attacker could not find a passing variant.**

The honest question this cycle answers: **which DEFENDED classes are defended by a deterministic
invariant (adaptively stable — no variant can pass), and which are merely defended against the one
template we happened to write (adaptively unproven → candidate downgrade)?**

## 3. Porting the adaptive threat model to a *deterministic* gate

The paper's attacker perturbs a model to raise its attack-success probability. gove-zone has **no
probabilistic refusal** — the gate is a total function of (receipt, args, actor, tenant, policy,
signature). So "adaptive attack" must be redefined, precisely:

- **Attacker knowledge:** full white-box — the gate source, the policy, the receipt schema, and
  the exact DEFENDED template are known (defense-aware, per the paper's threat model).
- **Attack action:** search a **bounded variant space** around a known template for an input/config
  that the gate lets through. Variant axes (deterministic, no model): argument mutation, actor/
  tenant substitution, signature presence/algorithm, policy-bundle id/version, receipt field
  perturbation, encoding/normalization (path/unicode/whitespace), ordering/timing, and
  boundary/degenerate values (empty policy, empty args, duplicate event_id).
- **Success metric:** the analogue of "attack success rate" is **∃ a variant in budget N that the
  gate admits when it should deny** (side effect runs / receipt accepted). For a deterministic
  gate this is binary per class: **adaptively-stable** (all N variants denied) or **bypassable**
  (first admitted variant is a concrete exploit).
- **Budget:** N defense-aware variants per class (build stage picks N, e.g. 24), enumerated
  deterministically — no randomness, so the result is reproducible and CI-checkable.

**Key insight:** for a deterministic reference monitor, an adaptive attack that finds a bypass is
*equivalent to discovering a NOT-DEFENDED path adjacent to a DEFENDED one*. Adaptive evaluation
here is therefore **variant-space coverage of the gate's decision boundary**, not stochastic
perturbation. This is a genuinely stronger honest claim than the current single-template pin, and
it is decidable.

## 4. Per-class static→adaptive assessment

For each manifest class: current template, the adaptive variant family, and the predicted verdict.
Predictions are hypotheses the build must *prove* (code wins); "stable by construction" means a
deterministic invariant makes every variant fail, which is a stronger result than an invented
attack.

| Class | Current status | Adaptive variant family | Predicted adaptive verdict |
|---|---|---|---|
| signature-stripping | DEFENDED | strip sig / downgrade alg / null sig / empty-bytes sig / detached sig under `require_signature=True` | **stable by construction** — `require_signature` is a total check; expect all variants denied |
| tenant-crossover | DEFENDED | tenant-A receipt vs tenant-B action across arg/boundary/actor perturbations | **stable by construction** — expected_tenant is bound + checked; expect all denied |
| evidence-omission | DEFENDED | dispatch with no receipt / stripped audit / reordered anchor | **stable by construction** — anchor-before-execute invariant; expect all denied |
| forged-authorization | PARTIAL | recompute forgery across signed/unsigned + field perturbations | signed stable; **unsigned recompute admits** (known residual) → variant search should surface the *smallest* passing forgery |
| replayed-authorization | PARTIAL | standalone receipt reuse × N distinct actions/boundaries | **bypassable** — stateless gate; every replay variant admits (no consumption ledger) |
| ledger-tampering | PARTIAL | self-consistent full-chain rewrite × truncation/re-order variants | **bypassable** — no external head anchor; keyless variants pass `verify_chain()` |
| policy-downgrade | PARTIAL | unpinned hash + swapped bundle-id + version rollback combos | **bypassable on unpinned path** — variant search should show pinning is the only stable config |
| validator-bypass | PARTIAL | authority-scope / validator-role variants at the gate | **bypassable** — `expected_authority`/`expected_validator_role` not plumbed to any gate surface |
| policy-default-allow | NOT_DEFENDED | unmatched-action fallthrough + empty/malformed PQL feed variants | **bypassable** — allow-by-default; every unmatched variant admits |
| adapter-bypass | NOT_DEFENDED | autogen/langgraph tool routes × AllowAllPolicy default | **bypassable** — default "governed" agent runs every tool |

**Predicted headline:** the 3 DEFENDED classes are **adaptively stable by construction** (they rest
on total, bound-and-checked invariants — signature-required, tenant-bound, anchor-before-execute),
and the 7 PARTIAL/NOT_DEFENDED classes are **adaptively bypassable**, with the variant search
recovering the *minimal* bypass for each. If any DEFENDED class turns out bypassable under a
variant, that is a **posture downgrade** and a high-value finding. If all three hold, we have
earned the right to add an "adaptively-stable" annotation — the honest upgrade the paper motivates.

## 5. Protocol primitive to build (the Build spec)

Add a small, deterministic **adaptive-attack harness** to the adversary suite that upgrades the
manifest from a static status to a **(static status, adaptive-stability)** pair, machine-checked.

### 5.1 Primitive
`tests/adversary/adaptive.py`:
- `AdaptiveResult(class_name, variants_tried, first_bypass | None, stable: bool)`.
- `adaptive_attack(class_name, *, budget=DEFAULT_N) -> AdaptiveResult`: deterministically
  enumerate ≤ budget defense-aware variants of the class's canonical attack (variant axes from §3),
  run each against the **real** gate/surface (`execute_with_receipt` / `Kernel.dispatch` /
  `verify_chain` / policy compile — never a mock), and return the first admitted variant (bypass)
  or `stable=True` if all are denied. Pure function of (class, budget); no randomness.
- A per-class `VARIANT_GENERATORS` registry keyed by the 10 manifest class names, each yielding
  that class's variant family. Generators reuse existing gap-test fixtures/exploits as seeds so we
  do not re-implement attacks — the adaptive layer *perturbs* the existing template.

### 5.2 Manifest extension
- Extend `MANIFEST` entries with `"adaptive": "STABLE" | "BYPASSABLE" | "UNTESTED"`.
- New test `test_adaptive_stability_matches_manifest()`: for each class, run `adaptive_attack`
  and assert the observed stability equals the pinned `adaptive` value — so an accidental
  regression (a DEFENDED class that becomes bypassable, or a fix that closes a gap) flips the test,
  exactly like the existing "defense arrived" tripwire.
- New pin `test_adaptive_posture_is_pinned()`: freeze the count (predicted 3 STABLE / 7
  BYPASSABLE) so a posture change is a deliberate edit, mirroring `test_taxonomy_posture_is_pinned`.
- Keep it consistent with the paper's framing: annotate each STABLE class with which classical
  property earns it (Biba integrity / reference-monitor totality / least-privilege binding).

### 5.3 Constraints (build stage)
- Real surfaces only; no mocked gates. Deterministic enumeration; reproducible in CI.
- Bounded budget (≤ ~24 variants/class) to keep the suite fast (< a few seconds).
- Additive: do NOT weaken or delete existing static tests or the existing posture pin. The
  adaptive layer sits *alongside* the static manifest.
- Forbidden: editing `src/gove_zone/**` (this is a test-suite extension, not a defense change),
  `docs/CLAIMS.md`, `docs/ROADMAP.md`.
- Scope fence: `tests/adversary/adaptive.py` (new), `tests/adversary/test_adaptive_stability.py`
  (new), `tests/adversary/test_coverage_manifest.py` (extend MANIFEST + 2 new pins),
  `tests/adversary/README.md` (document the adaptive dimension).

## 6. Honest-scope limitations (state verbatim in the build + any doc)

- **No model, no AgentDojo, no GCG.** This is a deterministic config/input-space variant search
  over gove-zone's own gate — NOT the paper's model-in-the-loop adaptive evaluation. It cannot and
  does not claim robustness against an optimizing LLM attacker.
- **"Adaptively stable" ≠ "secure".** It means "no variant in a bounded, hand-enumerated family
  bypassed the gate," which is a stronger statement than single-template but far weaker than a
  proof. Wording must stay at "no bounded variant in family F bypassed surface S."
- **Bypassable classes are already known gaps.** The adaptive layer does not discover new
  vulnerabilities so much as *quantify the decision boundary* of known ones (minimal bypass) and
  *pin* the stability of the defended ones. That framing must not be inflated into new CVEs.
- The paper's empirical result is one weak-model data point; we cite it as motivation for the
  methodology, never as evidence about gove-zone.

## 7. Proposed CLAIMS.md / threat-model-v2 delta (propose only; do NOT apply this cycle)

- `docs/security/threat-model-v2.md` §10: add an **"Adaptive stability"** column to the
  invariant→test matrix (STABLE/BYPASSABLE/UNTESTED per class), and a short §12 describing the
  adaptive harness, its threat model (§3 here), and its explicit scope limits (§6 here).
- `docs/CLAIMS.md`: if and only if the build lands green, add one row — "adversary suite carries a
  bounded deterministic adaptive-variant layer (N variants/class) over the real gate; 3 classes
  stable-by-construction, 7 bypassable-as-documented" — with the §6 limitations verbatim in the
  limitations column. No claim of AgentDojo/model robustness.

## 8. Verdict for the build stage

Proceed to stage 2 (build) with §5 as the spec. Predicted deliverable: 2 new files + a manifest
extension + README update; ~20–26 turns. The single most valuable outcome is a **machine-checked
adaptive-stability pin** that makes "DEFENDED" mean "stable under a defense-aware variant family,"
not "survives one template" — the precise honesty upgrade arXiv:2606.26479 argues the whole OOB
field still owes.
