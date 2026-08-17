# GOVE_ZONE_EFFECT_AUTHORITY_CLOSURE_V1 — Final Report

## Verdict

**BLOCKED.**

Two independent prerequisites are unmet, in order of importance:

1. **Architectural (primary).** The execution model provides no privilege
   boundary. 8 of 11 governed mutation carriers require OS-layer enforcement
   (`minimal_dominating_layer() == 'os'`); no application-level wiring can make
   "no valid authorization → no governed repository state change" true across
   them. This holds **even with zero collision and a fully committed baseline**
   — it is a property of the carrier set, not of ownership. Proven empirically
   with real processes (`ceiling_demonstration.py`).
2. **Collision (secondary).** The gove-zone composition surface is foreign and
   uncommitted, byte-identical to the V1 record (`gateway.py e5663ff555516eb3`,
   `integration.py 04c10592a80d7c4e`, `__init__.py 414fea99153e6147`,
   `execution.py 8686ca854488089c`). Not overwritten, not merged, not built on.

`PARTIAL_MUTATION_AUTHORITY_ENFORCEMENT` would overclaim: the mediated subset of
the **real** repository is empty (no gove-zone source routes through the
boundary; V1 coverage gate = 0 references). BLOCKED is the accurate verdict.

## Step 0 — collision & baseline (recorded, not modified)

Live hashes identical to V1; files still `M`/`??` uncommitted; last write Aug 9
13:2x (22h stale, not actively written, but never committed — foreign). ADRs
0010/0011 and the P12 test suites remain untracked. Baseline captured; no
gove-zone file touched this round.

## Step 1 — mutation carrier registry

Machine-checkable in `mutation_authority/effect_authority.py`; human view in
`MUTATION_CARRIER_REGISTRY.md`. 11 carriers; 3 sanctioned (the in-process
receipt-gated path, one choke point), 8 residual (subprocess/remote/external/raw
in-process). `validate_registry()` → clean.

## Step 2 — architectural analysis

- **A. Single application choke point — rejected** (carrier set, not collision).
- **B. Capability from a receipt — rejected** under same-UID (a token the parent
  can forge / any child can read; needs C to be real).
- **C. Filesystem/workspace enforcement — the only dominating class.** Minimal
  primitive: write-denial to canonical governed paths for every non-broker
  principal + a broker that grants scoped write only against a valid mutation
  authorization. Three concrete forms: separate UID, immutable/`chattr` bit, or
  disposable-workspace-plus-authorized-promote.
- **D. Ceiling — proven.** Same-UID in-process and permission-bit enforcement do
  not dominate. See below.

## Ceiling proof (real processes, `ceiling_demonstration.py`)

```
[BYPASSED] in-process choke point                             raw write ignores the gate object entirely
[BYPASSED] same-UID chmod 0444 boundary                       owner subprocess chmod u+w then wrote
[BYPASSED] shell operator redirect (decidable=False carrier)  `echo > file` mutated governed state
[BYPASSED] subprocess direct filesystem write                 a child process the gate never sees mutated the file
CEILING CONFIRMED: OS-level privilege separation is required; it is absent here. (exit 0)
```

Each case asserts the governed byte actually changed — the bypass **succeeds**.
This is a self-refutation of same-UID enforcement, deliberately included so no
`chmod`/in-process mechanism is mistaken for a prevention guarantee.

## Steps 3–5 — design for the enabled model (not built)

ARCHITECTURE.md specifies the Effect Authority Boundary (pre-effect enforcement,
ordering invariant), the two-receipt composition binding fields, the additive
`mutation_receipt_id`-on-`DecisionReceipt` schema change, and the
disposable-workspace-plus-promote model that closes `decidable=False` shell
mutation structurally (gate on the promote, not on the command). None is wired —
each requires the OS boundary that does not exist and/or edits to the foreign
surface.

## Step 6 — attacks

Attacks A–J (composition binding: DENY/ASK launder, cross-receipt, actor/target
substitution, ordering) are proven on the gove-zone double in V1
(`composition_proof.py`, 7/7, state-asserted). Attacks K–Q (subprocess, shell,
sandbox/E2B, lifecycle, ADV9, direct-write, newly-added-executor **bypass**) are
demonstrated as **successful bypasses** by `ceiling_demonstration.py` +
`dominance_gate.py` — i.e. the enforcement they attack does not exist, so they
are reported as residual carriers, not as defended. Running them against *real
enforcement* is impossible until the OS boundary and the wiring exist. No attack
against a real gove-zone executor is claimed as defended.

## Step 7 — dominance / bypass-regression gate

`dominance_gate.py` — registry-driven, not a symbol grep. Reports
`dominance holds: False` with the 8 residual carriers enumerated, and includes a
**negative self-test** that injects a synthetic bypass executor and asserts the
gate flags it and breaks dominance (and does not false-positive a sanctioned
carrier). Exit 2 = dominance does not hold (the honest current state). When an
OS boundary lands and carriers are sanctioned, the same gate flips to enforce
dominance and will fail on any newly introduced unmediated carrier.

## Step 8 — regression (literal)

```
verify_mutation_governance.py     → ALL CHECKS PASSED            (kernel, unchanged)
verify_mutation_integration.py    → ALL CHECKS PASSED  (28 tests, unchanged)
ceiling_demonstration.py          → CEILING CONFIRMED            (exit 0)
dominance_gate.py                 → DOMINANCE DOES NOT HOLD      (exit 2, self-test OK)
verify_effect_authority_closure.py→ VERDICT: BLOCKED             (exit 2)
```

gove-zone execution/governance tests: **not run** — running the foreign
package's suite against an unstable, partly-untracked multi-session baseline is
exactly the "build upon uncommitted foreign work" the collision rule forbids. No
gove-zone code touched ⇒ no gove-zone regression introduced.

## Claim justified vs not justified

**Justified:** the minimal dominating primitive is OS-layer write-denial (proven
via registry + real-process ceiling demo); the two-receipt binding is sound (V1,
on a double); mutation-authority baselines unchanged/green; a registry-driven
regression gate detects newly introduced bypass carriers.

**NOT justified:** any repository-wide prevention claim; any claim that gove-zone
mutation is mediated; that attacks K–Q are *defended* (they are shown
*undefended*); compliance/production/formally-verified.

## What would unblock `REPOSITORY_MUTATION_AUTHORITY_ENFORCED`

Exactly one OS boundary — (a) agents under a distinct UID from the broker; (b)
canonical paths behind an immutable/`chattr +a` boundary; or (c)
disposable-workspace-plus-authorized-promote where agents never touch canonical
state — **plus** the foreign execution-governance surface committing and
stabilizing so the composition can be wired. Until both, the enforceable
invariant is the in-process-carrier subset only, and the verdict is BLOCKED.

## Files added (all under `packages/mutation-authority/`; zero in `packages/gove-zone/`)

```
mutation_authority/effect_authority.py                              (machine-checkable registry)
GOVE_ZONE_EFFECT_AUTHORITY_CLOSURE_V1/MUTATION_CARRIER_REGISTRY.md
GOVE_ZONE_EFFECT_AUTHORITY_CLOSURE_V1/ARCHITECTURE.md
GOVE_ZONE_EFFECT_AUTHORITY_CLOSURE_V1/REPORT.md
GOVE_ZONE_EFFECT_AUTHORITY_CLOSURE_V1/ceiling_demonstration.py       (real-process ceiling proof)
GOVE_ZONE_EFFECT_AUTHORITY_CLOSURE_V1/dominance_gate.py              (registry gate + negative self-test)
verify_effect_authority_closure.py                                  (deterministic BLOCKED verdict)
```
