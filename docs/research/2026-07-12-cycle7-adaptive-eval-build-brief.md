# Cycle 7 / Stage 2 — Build Brief: Adaptive-Stability Layer for the Adversary Suite

Task class: Scoped edit (test-suite extension). Loop stage: BUILD. Spec source:
`docs/research/adaptive-eval-adversary-analysis.md` §5 (Build spec) — that doc is authoritative;
code wins over it and deviations are reported. Begin editing immediately; do not stop after reading.

## What you are building

A deterministic **adaptive-attack layer** over the EXISTING gove-zone adversary suite that
upgrades the manifest from a single static status to a `(static status, adaptive-stability)` pair,
machine-checked. This is a TEST-SUITE extension — NOT a defense change. You do not touch
`src/gove_zone/**`.

## Ground truth — read first (in this order)

1. `docs/research/adaptive-eval-adversary-analysis.md` (the spec; §3 threat model, §4 per-class
   predictions, §5 build spec, §6 honest-scope limits).
2. `packages/gove-zone/tests/adversary/test_coverage_manifest.py` (the MANIFEST dict + the 3
   posture pins + `_node_exists`).
3. `packages/gove-zone/tests/adversary/README.md`, `conftest.py`, `test_fixtures_baseline.py`.
4. Every existing gap/exploit test you will reuse as a variant SEED:
   `test_unsigned_forgery.py`, `test_standalone_receipt_replay.py`, `test_audit_full_chain_rewrite.py`,
   `test_policy_version_downgrade.py`, `test_policy_bundle_id_downgrade.py`,
   `test_authority_scope_unenforced.py`, `test_ruleset_default_allow.py`,
   `test_pql_silent_fail_open.py`, `test_adapter_bypass.py`, `test_tenant_boundary_isolation.py`.
5. The real surfaces the variants hit: `src/gove_zone/{executor.py,receipt.py,kernel.py,policy.py,
   audit.py}` — READ ONLY, to call the real gate, never mock it.

## Build (exact deliverables)

### D1 — `packages/gove-zone/tests/adversary/adaptive.py` (new)
- `@dataclass(frozen=True) AdaptiveResult`: `class_name: str`, `variants_tried: int`,
  `first_bypass: str | None` (a human-readable variant id, or None), `stable: bool`
  (`stable == (first_bypass is None)`).
- `DEFAULT_BUDGET = 24` (or a documented smaller N if a class's family is smaller; keep the whole
  suite < a few seconds).
- `VARIANT_GENERATORS: dict[str, Callable[..., Iterable[Variant]]]` keyed by ALL 10 manifest class
  names. Each generator DETERMINISTICALLY yields that class's defense-aware variant family, seeded
  from the existing exploit for that class (reuse fixtures; do not re-implement attacks). Variant
  axes per analysis §3: argument mutation, actor/tenant substitution, signature presence/algorithm,
  policy bundle-id/version, receipt-field perturbation, encoding/normalization, degenerate/boundary
  values. No randomness — a fixed enumeration so results are reproducible.
- `adaptive_attack(class_name: str, *, budget: int = DEFAULT_BUDGET) -> AdaptiveResult`: run each
  variant against the REAL surface (`execute_with_receipt` / `Kernel.dispatch` / `verify_chain` /
  policy compile as appropriate for the class), stop at the first variant the surface wrongly
  ADMITS (that is the bypass), else `stable=True`. A "bypass" means the side effect ran / the
  receipt was accepted / `verify_chain()` returned valid when it should not. Pure function of
  (class_name, budget).

### D2 — extend `test_coverage_manifest.py`
- Add `"adaptive": "STABLE" | "BYPASSABLE" | "UNTESTED"` to each of the 10 MANIFEST entries.
  Set values from the analysis §4 PREDICTIONS, but they MUST match what the harness actually
  observes (D3 enforces this — if a prediction is wrong, CHANGE THE MANIFEST to observed reality
  and note the deviation, never fudge the harness).
- `test_all_adversary_classes_are_enumerated` already asserts `len==10` and valid statuses —
  extend it to assert every entry has a valid `adaptive` value in `{STABLE,BYPASSABLE,UNTESTED}`.

### D3 — `packages/gove-zone/tests/adversary/test_adaptive_stability.py` (new)
- `test_adaptive_stability_matches_manifest()`: for each class, run `adaptive_attack` and assert
  observed stability == the pinned `adaptive` value (STABLE ⇔ `result.stable`). This is the
  "defense arrived / regressed" tripwire in the adaptive dimension.
- `test_adaptive_posture_is_pinned()`: freeze the counts (per analysis prediction: 3 STABLE /
  7 BYPASSABLE / 0 UNTESTED) so a posture change is a deliberate edit, mirroring
  `test_taxonomy_posture_is_pinned`. If observed reality differs, pin OBSERVED reality and report
  the deviation loudly in your final JSON.
- For each STABLE class, assert `first_bypass is None` AND annotate (comment or assert message)
  which classical property earns it (Biba integrity / reference-monitor totality / least-privilege
  binding), per analysis §4/§5.2.

### D4 — extend `tests/adversary/README.md`
- Document the adaptive dimension: what `adaptive_attack` does, the variant axes, the honest-scope
  limits from analysis §6 VERBATIM (no model / no AgentDojo / no GCG; "adaptively stable" ≠
  "secure"; wording capped at "no bounded variant in family F bypassed surface S").

## Scope fence (touch EXACTLY these; everything else forbidden)
- CREATE: `packages/gove-zone/tests/adversary/adaptive.py`,
  `packages/gove-zone/tests/adversary/test_adaptive_stability.py`
- EDIT: `packages/gove-zone/tests/adversary/test_coverage_manifest.py`,
  `packages/gove-zone/tests/adversary/README.md`
- FORBIDDEN: `src/gove_zone/**`, `docs/CLAIMS.md`, `docs/ROADMAP.md`, any other test file
  (reuse them as read-only seeds, do not edit them), nested repos, commits, network.

## Honest-result protocol (mandatory)
- Real surfaces only; NEVER mock the gate. If a predicted-STABLE class turns out bypassable (or
  vice-versa), that is the RESULT — pin observed reality and report it; do not bend the harness to
  hit the prediction. A wrong analysis prediction is a finding, not a failure to hide.
- If a class genuinely cannot be adaptively tested yet (no reachable surface), mark it `UNTESTED`
  with a one-line reason, do not fake a STABLE/BYPASSABLE verdict.

## Mandatory verification (run, show literal output, in order)
1. `uv run --package gove-zone --extra crypto --extra dev python -m pytest packages/gove-zone/tests/adversary --import-mode=importlib -q` — all pass, incl. the 2 new tests + extended manifest.
2. `uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q` — no regressions.
3. `bash scripts/claim_verify_headless.sh` → `all_passed: true`.
4. `git status --short packages/gove-zone/ docs/` — only the 4 in-scope files (2 new, 2 edited);
   literal output.

## Output contract (final message = JSON only)
{"files_created": [..], "files_edited": [..],
 "adaptive_posture": {"STABLE": <n>, "BYPASSABLE": <n>, "UNTESTED": <n>},
 "per_class": {"<class>": "STABLE|BYPASSABLE|UNTESTED", ...},
 "prediction_deviations": [{"class": "..", "predicted": "..", "observed": ".."}],
 "adversary_suite": "N passed", "full_package": "N passed",
 "claim_verify_all_passed": bool, "scope_clean": bool, "budget_used": <N>}
