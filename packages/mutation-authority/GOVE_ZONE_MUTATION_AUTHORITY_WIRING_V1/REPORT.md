# GOVE_ZONE_MUTATION_AUTHORITY_WIRING_V1 — Final Report

## Verdict

**INTEGRATION INCOMPLETE.**

Universal mediation of gove-zone mutation by `MutationGateway` cannot be
proven, and was not attempted, for two independent reasons:

1. **Collision.** The choke-point surface that would carry the enforcement —
   and the classifier that supplies per-mutation `(resource, hashX→hashY)`
   binding — is foreign, uncommitted, and mid-flight (another session's
   ADR-0010/P11 execution-governance layer, with P12 boundary work still
   untracked). Per the task's Collision rule, it is not overwritten, merged, or
   built upon.
2. **Structural residual (the foreign layer's own admission).** No single choke
   point dominates all repository mutation even on a stable baseline —
   shell-operator effects are `decidable=False`, and the sandbox subprocess
   executors, lifecycle scripts, and interactive-terminal invocation (ADV9) are
   separate/undecidable carriers.

Reporting `INTEGRATION INCOMPLETE` is the required outcome here, not a
shortfall in the work.

## Collision evidence (recorded, not modified)

| File | sha256 (first 16) | git state |
|---|---|---|
| `packages/gove-zone/src/gove_zone/gateway.py` | `e5663ff555516eb3` | modified (+14, `call_factory` seam) |
| `packages/gove-zone/src/gove_zone/integration.py` | `04c10592a80d7c4e` | modified (+26, classifier helpers) |
| `packages/gove-zone/src/gove_zone/__init__.py` | `414fea99153e6147` | modified (+20, execution exports) |
| `packages/gove-zone/src/gove_zone/execution.py` | `8686ca854488089c` | untracked (ADR-0010/P11 layer) |

Also untracked: `tests/test_execution_bypass_adversarial.py`,
`tests/test_execution_governance.py`, `tests/test_p12_boundary_validation.py`,
`docs/adr/0010-execution-governance-layer.md`,
`0011-p12-execution-trust-boundary.md`. Last-write mtimes Aug 9 13:2x–13:48
(not being written this instant, but uncommitted foreign work).

## Chosen choke point (for the eventual wiring)

`execute_with_receipt` (`executor.py:236`, effect = `tool_fn(**args)`) — the
single performing boundary dominating in-process governed mutation. Wiring
would compose the mutation authorization with the gove-zone `DecisionReceipt`
there (see ARCHITECTURE.md), not replace it.

## What WAS delivered (non-colliding, in my own package scope)

All under `packages/mutation-authority/` — zero new files inside
`packages/gove-zone/`, no foreign file modified:

- `GOVE_ZONE_MUTATION_AUTHORITY_WIRING_V1/MUTATION_SURFACE_MAP.md` — full
  read-only mutation-surface inventory with file:line, the dominating choke
  point, the non-dominated carriers, and the unenforceable-by-design residuals.
- `GOVE_ZONE_MUTATION_AUTHORITY_WIRING_V1/ARCHITECTURE.md` — the two-receipt
  composition design (§3), fail-closed model (§4), evidence integration (§7),
  and the gove-zone-side schema-change finding.
- `mutation_authority/composition.py` — the composition binding, implemented
  against a gove-zone `DecisionReceipt` double (`GovernedActionClaim`).
  **Design-proof, not enforcement.**
- `GOVE_ZONE_MUTATION_AUTHORITY_WIRING_V1/composition_proof.py` — adversarial
  proof of the binding; every case asserts repository state before/after.
- `verify_gove_zone_mutation_authority.py` — deterministic verdict command that
  **cannot return 0 while unwired**; runs the baselines + composition proof +
  the structural coverage gate, then emits `INTEGRATION INCOMPLETE` (exit 2).

## Attacks executed (composition binding, on the double)

`python3 GOVE_ZONE_MUTATION_AUTHORITY_WIRING_V1/composition_proof.py` (literal):

```
[PASS] happy path: both legs authorize                          both legs authorize ⇒ APPLIED; evidence carries effect_id + receipt id
[PASS] gove-zone DENY cannot launder a mutation                 gove-zone DENY ⇒ REFUSED before gateway; zero state change, zero evidence
[PASS] gove-zone ASK cannot launder a mutation                  gove-zone ASK (non-ALLOW) ⇒ REFUSED; zero state change
[PASS] mutation receipt cannot cross-bind to another action     mutation receipt for effect A cannot satisfy action B ⇒ REFUSED
[PASS] action cannot authorize a substituted target             ALLOW for path A cannot authorize writing path B ⇒ REFUSED
[PASS] action cannot be carried by a substituted actor          action authorized for alpha cannot be carried by beta ⇒ REFUSED
[PASS] effect cannot precede the gove-zone decision (ordering)  ordering is structural: ALLOW check precedes the only effect call
```

State-before/after: each case reads the target file bytes before and asserts
they are unchanged after a REFUSED outcome (DENY/ASK/cross-bind/target/actor),
and that DENY emits zero evidence and appends no DECISION/COMMIT to the ledger.

**These prove the binding LOGIC on a double — not that gove-zone invokes it.**
The task's attacks A–L (direct executor bypass, retry, exception, symlink/alias,
concurrency, indirect shell) are attacks against the *wired executor*; they
cannot be run without editing the foreign boundary and are therefore **not
claimed**.

## Structural coverage result

`verify_gove_zone_mutation_authority.py` (literal tail):

```
[GAP] gateway dominance: 0 gove-zone source file(s) reference MutationGateway — NOT mediated (no wiring present)
INTEGRATION INCOMPLETE: gateway dominance unverifiable (collision + no wiring)  (exit 2)
```

The coverage gate greps gove-zone source for any `mutation_authority` /
`MutationGateway` reference; zero hits proves no wiring exists. When wiring
lands, this gate flips to the dominance check (every mutation executor routed
through the gateway) and would detect a newly added bypass executor.

## Regression results

- mutation-authority kernel baseline — `verify_mutation_governance.py` →
  `ALL CHECKS PASSED` (unchanged).
- mutation-authority integration baseline — `verify_mutation_integration.py` →
  `ALL CHECKS PASSED` (unchanged).
- Existing gove-zone governance tests — **not run**: running them would mean
  running the foreign package's suite against an unstable, partly-untracked
  baseline mixing multiple sessions' work. Deferred to the owning session; no
  gove-zone code was touched, so no gove-zone regression was introduced.

## Exact security claim now justified

- The two-receipt composition binding is sound: on the modeled boundary, a
  gove-zone DENY/ASK cannot launder a repository mutation, a mutation receipt is
  bound to one gove-zone effect and cannot cross-bind, and neither target nor
  actor can be substituted — **proven on a gove-zone double.**
- The mutation-authority kernel + integration guarantees are unchanged and
  green.

## Exact claims NOT justified

- **No claim that gove-zone mutation is mediated by MutationGateway.** Zero
  wiring exists; dominance is unproven.
- **No repository-wide prevention claim.** Even fully wired, enforcement would
  cover only classified, hook-observed, in-process mutation — not sandbox
  subprocess executors, shell-operator effects (`decidable=False`), lifecycle
  scripts, or interactive-terminal invocation (ADV9).
- **No claim that attacks A–L pass against a real gove-zone executor.** They
  were not run; the wired executor does not exist.
- **No compliance / production-ready / formally-verified claim.**

## Exact enforcement boundary (as it would stand once wired)

`execute_with_receipt` (`executor.py:236`), for calls the `execution.py`
classifier marks `decidable=True` and routes to the execution surface. Outside
that boundary: sandbox subprocess executors, undecidable shell effects,
lifecycle scripts, interactive-terminal invocation. State this boundary
explicitly in any downstream claim; do not generalize to "all repository
mutation".

## Remaining unenforced mutation surfaces

- `sandbox.py:235` `LocalProcessSandbox.run_tool` (bwrap best-effort) and
  `sandbox.py:284` `E2BSandbox` — separate effect carriers.
- Shell-operator effects (`>`,`|`,`cp`,`mv`,`$(...)`) — `decidable=False`.
- Package-manager lifecycle scripts; managers run from an interactive terminal
  (ADV9).
- Everything outside the gove-zone process (the stated trust boundary).

## Handoff to the owning session

When the ADR-0010/P11/P12 execution-governance work commits and its baseline
stabilizes, the wiring is: at `execute_with_receipt`, for a classified
governed mutation, call `compose_mutation(DecisionReceipt-derived claim,
MutationGateway, context-with-task_reference=effect_id, resource, operation,
content)` before `tool_fn`, and add `mutation_receipt_id` to the gove-zone
`DecisionReceipt`/evidence (the one additive schema change). The composition
logic and its adversarial proof are ready and green in this package.
