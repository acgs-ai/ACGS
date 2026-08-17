# GOVE_ZONE_EFFECT_AUTHORITY_CLOSURE_V1 — Architecture & Ceiling Proof

Status: **analysis + ceiling proof; no enforcement wired.** Verdict `BLOCKED`
(REPORT.md). This document answers the task's central architectural question —
can all governed mutation carriers be reduced to one pre-effect authorization
boundary? — and specifies the boundary that *would* work, so a future round with
the required execution-model change can build it.

## The central question (Step 2)

> Can all governed mutation carriers be reduced to one pre-effect authorization
> boundary, and what is the minimal primitive that dominates every carrier?

Answer from the registry (`MUTATION_CARRIER_REGISTRY`): **not at the application
layer.** `minimal_dominating_layer() == 'os'`. 8 of 11 carriers cross a process
boundary or are raw in-process writes that never reach the gate; once a child
process, shell, or arbitrary in-process code holds the governed path, only an
OS-level boundary can deny the write.

### A. Single application choke point — REJECTED

Wiring everything through one application-level effect executor
(`execute_with_receipt`) cannot dominate: `bash -c 'echo x > f'`, a Python
subprocess, an interactive terminal, E2B, or a raw `Path.write_text` all mutate
governed state without passing through it. **Disproven by the carrier set, not
by the collision** — it fails even with a fully committed baseline.
`ceiling_demonstration.py` shows the in-process-choke and same-UID-permission
bypasses succeeding with real processes.

### B. Capability derived from a receipt — REJECTED under same-UID

A scoped mutation capability is only as strong as its unforgeability across the
process boundary. Under one UID, a "capability" is a token the parent can
fabricate and any child can read; the OS draws no line between the broker and
the mutator. A capability model becomes real **only** on top of a privilege
boundary (C) — at which point the boundary, not the token, is doing the work.

### C. Filesystem / workspace enforcement boundary — the only dominating class

Canonical governed paths are made physically unwritable by ordinary principals;
a privileged broker holding mutation authority is the sole writer. Concretely,
one of:

1. **Separate UID** — agents run as UID_agent; canonical paths owned by
   UID_broker, mode `0755`/`0644` (agents read, cannot write). The broker
   validates a `MutationDecisionReceipt` and performs the write.
2. **Immutable/append-only bit** — `chattr +i` / `+a` on canonical paths; only a
   privileged process clears it transactionally under a valid receipt.
3. **Disposable workspace + authorized promote** — agents mutate a throwaway
   copy freely; canonical state changes only via a broker `promote`/`commit`
   operation gated on a receipt binding the workspace diff to `(resource,
   hashX→hashY)`. This closes even `decidable=False` shell effects, because the
   shell runs in the disposable copy and cannot reach canonical state.

The minimal primitive is therefore **write-denial to canonical governed paths
for every non-broker principal**, plus a broker that grants scoped write only
against a valid mutation authorization. It is not selected for being "stronger";
it is the *weakest* primitive that dominates all 11 carriers (registry:
`required_enforcement_layer == 'os'` for the residual set).

### D. Ceiling (what is NOT achievable in the current model)

The current execution model runs agents and the would-be broker as the **same
UID** with no immutable boundary. In that model, repository-wide prevention is
**impossible**: whatever seals a file (an in-process gate, a `chmod`) is
reversible by the same-UID mutator. Proven empirically —
`ceiling_demonstration.py`, all four real-process bypasses succeed:

```
[BYPASSED] in-process choke point
[BYPASSED] same-UID chmod 0444 boundary        (owner subprocess chmod u+w, then wrote)
[BYPASSED] shell operator redirect             (echo > file)
[BYPASSED] subprocess direct filesystem write
```

The strongest invariant actually enforceable in this model is therefore NOT
repository-wide. It is:

> No governed mutation **through an authorized in-process execution carrier**
> (the `execute_with_receipt` path) without a valid, bound authorization.

Observational hooks, post-hoc detection, the `execution.py` classifier, and
audit logging are **detection**, not prevention, and are not promoted here into
a prevention guarantee.

## The Effect Authority Boundary (Step 3, design for the enabled model)

Once a privilege boundary exists (C), the boundary semantics are:

```
Intent → execution-governance decision (gove-zone DecisionReceipt)
       → mutation authorization (MutationDecisionReceipt)
       → bound authorization evidence
       → PRE-EFFECT ENFORCEMENT (broker grants scoped write only now)
       → effect (in the sole writable window)
       → post-state verification (after_hash == authorized commitment)
       → evidence
```

Ordering invariant: authorization completes before the first state-changing
instruction. In model C.3 this is structural — the agent literally cannot write
canonical state; the only path is the broker's post-authorization `promote`.

## Composition binding (Step 4)

The two-receipt binding from V1 (`mutation_authority/composition.py`, proven on
a double) is the composition; the enabled-model version binds, at minimum:

- gove-zone execution `DecisionReceipt` id
- `MutationDecisionReceipt` id
- actor · tool/executor identity · operation · resource
- canonical argument hash
- expected pre-state hash · authorized post-state commitment (`after_hash`)
- task/session authority · nonce/replay identity

Bidirectional verifiability requires the one additive gove-zone schema change
(finding carried from V1): `mutation_receipt_id` on `DecisionReceipt`, so a
receipt from one layer cannot be reused with a different decision in the other.

## Closing undecidable shell mutation (Step 5)

Do **not** try to perfectly classify arbitrary shell. Adopt model **C.3**:
shell/subprocess/lifecycle/interactive carriers all run against a disposable
workspace and cannot reach canonical state; the only canonicalizing operation is
the broker `promote`, gated on a receipt binding the produced diff to
`(resource, hashX→hashY)`. This makes mutation **structurally impossible**
rather than predicted — the `decidable=False` problem disappears because the
gate is on the promote, not on the command.

## What must change for `REPOSITORY_MUTATION_AUTHORITY_ENFORCED`

Exactly one of: (a) agents run under a distinct UID from the broker; (b)
canonical governed paths sit behind an immutable / `chattr +a` boundary; or (c)
the disposable-workspace-plus-authorized-promote model where agents never touch
canonical state. Any of these supplies the OS-layer boundary the registry shows
is required; none exists today.
