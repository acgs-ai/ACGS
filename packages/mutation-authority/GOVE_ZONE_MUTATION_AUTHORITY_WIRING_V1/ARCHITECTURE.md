# GOVE_ZONE_MUTATION_AUTHORITY_WIRING_V1 — Architecture

Status: **design only; not wired** (collision — see REPORT.md). This document
specifies the composition the wiring must follow so the other session (or a
later merged session) can execute it against a stable baseline. The binding
logic is implemented and adversarially proven on a gove-zone double in
`mutation_authority/composition.py` + `composition_proof.py`.

## Objective

Move enforcement from voluntary adapter adoption to the gove-zone effect
boundary, so: **no valid Mutation Authority Decision Receipt → no governed
repository state change.** Required order:

```
Actor → MutationIntent → MutationGateway.request_mutation → valid decision + receipt
      → governed executor effect → evidence
```

## Chosen choke point

`execute_with_receipt` (`executor.py:236`, effect = `tool_fn(**args)`) — the
single performing boundary that dominates in-process governed mutation
(reused by `GovernedExecutor.execute` and `UniversalGateway.invoke`). The
authorization must occur immediately before line 236, and DENY must return
before `tool_fn` is called.

**Caveat that forces composition, not replacement:** `execute_with_receipt`
sees an opaque host `tool_fn(**args)`. It does not know the mutation's
`(resource, pre_hash, post_hash)`. Those come from the classifier in the
in-flight `execution.py`. So the wiring is not "call MutationGateway at
line 236" in isolation — it is a composition of two authorizations.

## Two-receipt composition (deliverable §3)

Two authorizations, neither subsuming the other:

| Layer | Authorizes | Artifact |
|---|---|---|
| gove-zone | **the action** — may this actor run this classified command | `DecisionReceipt` (existing) |
| mutation-authority | **the state transition** — may this exact path go hash X → hash Y | `MutationDecisionReceipt` (existing) |

### Binding rule (anti-laundering)

Implemented in `mutation_authority.composition.compose_mutation`:

1. **Ordering is fixed and structural:** classify → gove-zone action decision →
   Mutation Intent → mutation decision → effect. The gove-zone action claim is
   a required precondition argument; the only effect call (the gateway) is
   reached after every binding check. A reversed order is impossible in the API.
2. **Non-ALLOW ⇒ zero mutation.** A gove-zone `deny`/`ask` refuses before the
   mutation gateway is reached — the DENY cannot be laundered through the
   mutation layer (success criterion #4).
3. **Identity binding.** The action's `actor` must equal the mutation
   `AuthorityContext.actor_id`.
4. **Target binding.** The action's declared `target_resource` must equal the
   mutation `resource` — an ALLOW to run a command cannot authorize an
   unrelated path.
5. **Receipt binding.** The Mutation Intent's `task_reference` MUST equal the
   gove-zone `effect_id`. A mutation receipt minted for effect A therefore
   cannot satisfy action B, and vice versa.

### Schema-change findings (what each side needs)

- **mutation-authority side: no schema change.** `task_reference` is already a
  free field on `MutationIntent`; pinning it to the gove-zone `effect_id`
  reuses existing machinery (the gateway's task-authority check already
  validates `task_reference` against policy, so `effect_id` values must match a
  policy-authorized task pattern).
- **gove-zone side: one additive change (finding for the other session).** To
  close the loop bidirectionally — so a `DecisionReceipt` cannot be presented
  as authorizing a mutation it never referenced — the gove-zone
  `DecisionReceipt` (or its evidence record) should carry the
  `mutation_receipt_id`. Without it, the binding holds in the
  action→mutation direction (enforced here) but the mutation→action direction
  relies on the composition layer being the sole caller. That is acceptable
  only once `execute_with_receipt` is the enforced single caller — i.e. once
  wiring lands.

## Fail-closed behavior (deliverable §4)

Preserved from the mutation-authority kernel and extended by the composition:

- inability to classify the mutation safely ⇒ deny (no `(resource, hash)` ⇒ no
  intent ⇒ no effect);
- inability to construct intent ⇒ deny;
- mutation-authority unavailable / verification exception ⇒ deny (kernel and
  `ci_gate` already catch-all to fail closed);
- gove-zone non-ALLOW ⇒ refuse before effect;
- no bypass, no compatibility fallback, no audit-only mode, no env-var disable.

Non-mutating operations are unaffected: the composition only intercepts calls
the classifier marks as governed mutations; everything else follows the
existing gove-zone path.

## Evidence integration (deliverable §7)

`composition.composed_evidence_fields` defines the single record binding the
final effect to: actor, action_kind, gove-zone `effect_id`, classified command,
resource, `mutation_receipt_id`, `mutation_evidence_id`, status. The
mutation-authority evidence graph already verifies its fields against
ledger-derived ground truth (round-2 hardening: root-key signature + full field
cross-check); the wired integration would additionally assert the gove-zone
`effect_id` against the authoritative gove-zone receipt/ledger, not trust the
emitter.

## What this architecture does NOT establish

- It does not make MutationGateway dominate all gove-zone mutation. The sandbox
  subprocess executors, shell-operator effects (`decidable=False`), lifecycle
  scripts, and interactive-terminal invocation (ADV9) are separate/undecidable
  carriers (MUTATION_SURFACE_MAP.md). The achievable ceiling is
  classified, hook-observed, in-process mutation.
- It does not prove gove-zone calls the composition. That requires editing the
  foreign in-flight boundary and is blocked. See REPORT.md.
