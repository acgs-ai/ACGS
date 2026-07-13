# Cycle 7 / Stage 3 — Adversarial Review Brief: Adaptive-Stability Harness

Task class: Adversarial review (read-only + probe Bash). Loop stage: ADVERSARIAL (edge-high
gate). FRESH SESSION — do not assume familiarity with how this was built. Your job is to
BREAK it, not summarize it. A PASS verdict with no attempted attacks is itself a failed review.

## Ground truth — read first

1. `packages/gove-zone/tests/adversary/adaptive.py` (the harness: `AdaptiveResult`,
   `VARIANT_GENERATORS`, `adaptive_attack`).
2. `packages/gove-zone/tests/adversary/test_adaptive_stability.py` (the 4 pinning tests, the
   `_load()` dynamic-import shim, `_STABLE_PROPERTY`).
3. `packages/gove-zone/tests/adversary/test_coverage_manifest.py` (MANIFEST, the `adaptive`
   field per class).
4. `docs/research/adaptive-eval-adversary-analysis.md` (the spec/predictions this was built
   from) and `docs/research/2026-07-12-cycle7-adaptive-eval-build-brief.md` (the build brief).
5. Context: this build was done by Codex CLI, then the parent found and fixed TWO bugs before
   this review: (a) `_load()` never registered the loaded module in `sys.modules`, crashing
   `@dataclass` field-type resolution — fixed by adding `sys.modules[spec.name] = module`
   before `exec_module`; (b) the manifest pinned `evidence-omission: BYPASSABLE` but the
   harness observes `STABLE` — corrected the manifest to `STABLE`. Both fixes are already
   applied and verified (32 passed, 1 xfailed in the adversary suite). Do NOT assume the
   build is otherwise trustworthy just because these two are fixed — re-verify everything.

## Mandatory attack vectors

1. **Mutation analysis (mandatory).** For each of the 3 STABLE classes
   (signature-stripping, tenant-crossover, evidence-omission), find the ONE line in the real
   gate (`execute_with_receipt` in `src/gove_zone/executor.py`, or the relevant check) that
   enforces the invariant, comment it out / neuter it on a throwaway copy, and confirm
   `adaptive_attack(class)` flips to `stable=False` with a real `first_bypass`. If a STABLE
   verdict survives the neutered gate, the harness isn't actually testing the real invariant —
   FAIL finding. Restore the file after.
2. **Determinism probe.** Run `adaptive_attack` for every one of the 10 classes 5 times each
   (bare Python loop, not pytest) and confirm identical `(stable, first_bypass, variants_tried)`
   tuples every time — the brief requires "no randomness." Any nondeterminism is a finding.
3. **Budget/coverage probe.** For each BYPASSABLE class, check whether the reported
   `first_bypass` is genuinely the FIRST admitted variant in generator order (i.e. earlier
   variants in the same generator really return `False`/deny) — a harness that returns a
   bypass without actually trying earlier "should-be-denied" variants first is not doing real
   variant-space search, it's just running one known-bad case and calling it done. Spot-check
   at least 3 of the 7 BYPASSABLE classes' generators directly.
4. **STABLE-class honesty probe.** For the 3 STABLE classes, verify the variant family in
   `VARIANT_GENERATORS` is actually a *family* (≥2 meaningfully distinct variants per the
   analysis's variant axes — actor/tenant/args/encoding/etc.), not a single trivial repeat
   dressed up as N variants. A STABLE verdict over a degenerate 1-variant or duplicate-variant
   family is a weaker claim than the manifest implies — finding if so.
5. **Manifest/reality drift re-check.** Re-run `test_adaptive_stability_matches_manifest` and
   `test_adaptive_posture_is_pinned` fresh (clear `__pycache__` under
   `packages/gove-zone/tests/adversary/` first) and confirm both pass with the CURRENT files —
   given the self-report/artifact-divergence bug already found once in this build, treat any
   other agent-claimed pass as unverified until you've run it yourself.
6. **Scope-fence probe.** Confirm no other test file, README elsewhere, or `src/gove_zone/**`
   file was touched by this build. `git diff --stat -- packages/gove-zone/tests/adversary/
   docs/` should show exactly `adaptive.py` (new), `test_adaptive_stability.py` (new),
   `test_coverage_manifest.py` (modified), `README.md` (modified) plus the parent's two
   fix-diffs already inside those same files — nothing else.
7. **Honest-scope-limits wording probe.** Confirm `README.md`'s adaptive section states, close
   to verbatim, the limits from analysis §6 (no model/AgentDojo/GCG; "adaptively stable" ≠
   "secure"; wording capped at "no bounded variant in family F bypassed surface S"). Flag any
   overclaiming language.

## Verdict contract (final message = JSON only)

```
{"verdict": "PASS" | "PASS_WITH_FINDINGS" | "FAIL",
 "mutation_analysis": {"<class>": {"neutered_stable": bool, "bypass_found": str|null}},
 "determinism_check": {"all_deterministic": bool, "nondeterministic_classes": [...]},
 "coverage_probe": {"<class>": "genuine_first_bypass" | "single_case_masquerade"},
 "stable_family_probe": {"<class>": "genuine_family" | "degenerate"},
 "manifest_reality_recheck": {"passed": bool, "output": "..."},
 "scope_fence_clean": bool,
 "honest_wording_ok": bool,
 "findings": [{"severity": "LOW|MED|HIGH|CRITICAL", "location": "file:line",
   "description": "...", "proof": "...", "minimal_fix": "..."}]}
```

A PASS requires you to have actually run the mutation analysis and determinism probe with
literal command output shown in your working (not just in the JSON) — an unsupported PASS is
itself a FAIL of this review.

## Constraints

- Read-only on `src/gove_zone/**` except transient throwaway copies for mutation testing
  (mutate a temp copy, never the real file in the repo; if you must patch in-place, restore it
  before finishing — confirm with `git diff --stat -- src/` shows nothing at the end).
- No edits to `packages/gove-zone/tests/adversary/**` — findings only, no fixes (that's stage
  4 if this reports findings).
- No commits, no `git add`, no push.
