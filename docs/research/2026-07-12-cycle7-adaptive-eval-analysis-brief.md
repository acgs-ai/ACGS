# Cycle 7 / Stage 1 — Analysis Brief: Adaptive-Evaluation Protocol → Pack II Adversary Suite

Task class: Research/strategy analysis (read-only). Loop stage: ANALYSIS (stage 1 of the
build cycle). Output = an authoritative analysis doc the stage-2 build brief will be spec'd
from. NO code changes this stage.

## Source paper

arXiv:2606.26479v1 — "Adaptive Evaluation of Out-of-Band Defenses Against Prompt Injection in
LLM Agents" (Narisetty, Kore, Kattamanchi, Kumarapu; 25 Jun 2026). Local copy of abstract +
metadata: fetched to /tmp/adaptive.html. PDF: https://arxiv.org/pdf/2606.26479 (executor may
re-fetch to /tmp ONLY if network allowed; otherwise work from the abstract + this brief).

### What the paper actually says (grounded, do not overclaim beyond this)

1. Organizes out-of-band (OOB) defenses — CaMeL, FIDES, Progent, RTBAS, FORGE — as instances
   of **Biba integrity protection, reference monitoring, and least privilege**. gove-zone's
   receipt-gated executor is exactly this class: a deterministic OOB reference monitor.
2. Central warning: every one of these is validated **only on static benchmarks** (a fixed set
   of injection attempts) — the same methodology that made in-band defenses look strong until
   **adaptive, defense-aware attacks broke 12 of them at >90% success**. The paper specifies the
   **threat model + protocol** an adaptive evaluation requires.
3. Empirical: independent reproduction/extension of Progent's adaptive-attack analysis on
   AgentDojo with an open-weight agent (Qwen2.5-7B, single H200). Progent cut mean attack
   success ~6× (25.8%→4.2%); a hand-crafted adaptive attack did NOT raise it (2.6%). Explicitly
   framed as ONE small-scale, weak-model, single black-box-template data point; white-box GCG
   remains open. "Consistent with, but does not establish" the hypothesis that deterministic OOB
   enforcement is a harder adaptive target than in-band detection.

## Why this maps onto ACGS (the thesis to test in analysis)

gove-zone's adversary suite (`packages/gove-zone/tests/adversary/`) today pins a **static**
posture via `test_coverage_manifest.py`: 3 DEFENDED / 5 PARTIAL / 2 NOT_DEFENDED, each class
backed by a **fixed** exploit or gap test. That is precisely the static-benchmark methodology
the paper warns is insufficient: a class is "DEFENDED" because ONE hand-written exploit fails
against it — not because a defense-aware adaptive attacker could not find a variant that
succeeds. The paper gives us the discipline to make that distinction machine-checked.

## Ground truth the analysis MUST read before writing

- `packages/gove-zone/tests/adversary/README.md` + `test_coverage_manifest.py` (the MANIFEST
  dict, the 3 posture-pinning tests, `_node_exists`).
- `docs/security/threat-model-v2.md` (the prose taxonomy; §10/§11 posture + remediation order).
- The real gate + surfaces the manifest points at: `src/gove_zone/{executor.py,receipt.py,
  kernel.py,policy.py,audit.py}` — enough to state which classes even HAVE an adaptive attack
  surface (deterministic gates may be adaptively-stable by construction; that is a finding).
- Existing gap tests (`test_unsigned_forgery.py`, `test_audit_full_chain_rewrite.py`,
  `test_adapter_bypass.py`, etc.) to see the current single-template attack shape.
- The F1–F4 harness just landed (`examples/f1f4-divergence/`) — its `check()` biconditional is a
  candidate *adaptive-attack oracle* (does a mutated attack still get flagged?).

## Questions the analysis doc MUST answer

1. **Threat-model port.** Restate the paper's adaptive-evaluation threat model (defense-aware
   attacker, attack budget, success metric) in gove-zone terms. What is the analogue of
   "attack success" for a *deterministic* reference monitor (which has no probabilistic refuse)?
   Hypothesis to state precisely: for a deterministic gate, adaptive attack = **searching the
   input/config space for a variant that the gate lets through**, i.e. finding a NOT-DEFENDED
   path adjacent to a DEFENDED one — not perturbing a model's refusal probability.
2. **Static→adaptive upgrade per class.** For each of the 10 manifest classes, specify what an
   *adaptive* (defense-aware, multi-variant) attack would look like vs the current single
   template, and whether the class's DEFENDED/PARTIAL claim survives it. Concretely: which
   DEFENDED classes are DEFENDED only against the one template (candidate downgrade), and which
   are adaptively-stable by construction (deterministic invariant, no perturbation helps)?
3. **Protocol primitive to build.** Define the smallest reusable primitive that upgrades the
   suite from static to adaptive: e.g. an `adaptive_attack(class, budget)` harness that
   generates N defense-aware variants of a class's attack and asserts the gate holds on ALL of
   them (DEFENDED) or records the first bypass (PARTIAL/NOT_DEFENDED). Map it onto Biba /
   reference-monitor / least-privilege framing so the manifest gains an **adaptive-stability**
   dimension alongside static status.
4. **Honest-scope limits.** State plainly what this does NOT do: no model-in-the-loop, no
   AgentDojo, no GCG/white-box optimization, no LLM attacker — this is a *deterministic-gate*
   adaptive-variant search (config/input space), which is a strictly narrower and honest claim.
   The paper's own result is one weak-model data point; our port must not imply more.
5. **CLAIMS.md / threat-model-v2 delta (proposed, not applied).** Exactly which wording in
   docs/CLAIMS.md and threat-model-v2.md would need to change IF the build lands — e.g. adding an
   "adaptive-stability" column to the posture pin. Propose; do not edit this stage.

## Deviations protocol
Code wins over the paper and over this brief; report every deviation. If a class turns out to be
adaptively-stable by construction (no variant can bypass a deterministic invariant), say so — that
is a *stronger* honest result than inventing an adaptive attack that doesn't exist.

## Deliverable
Write `docs/research/adaptive-eval-adversary-analysis.md` (authoritative; a §"Build spec" section
the stage-2 brief will lift). Then run `bash scripts/claim_verify_headless.sh` (must stay
all_passed=true — analysis is read-only) and `git status --short` (only the new doc + this brief).

No code edits. No commits. No network beyond the optional /tmp PDF fetch.
