# Plan-Level Governance — design

> Status: **implemented on `master`** — `src/gove_zone/plan.py`
> (`WorkflowAuthorization`, `from_plan`, `compute_authorization_hash`) plus the
> A–E checks in `WorkflowExecutor._verify_authorization`
> (`src/gove_zone/workflow.py`); tests in `tests/test_plan_level_governance.py`.
> This file is retained as the design rationale, so its build-sequencing and
> "new files" sections describe work already landed. **The code is
> authoritative where the two differ.**
> Makes the workflow **plan** a governed object. The invariant grows from
> *"no valid step receipt … no side effect for that step"* to add:
> **"no authorized plan, no workflow step executes."**

## The gap this closes

In the workflow-receipt-chain layer the `WorkflowDAG` is bound into every step
envelope via `dag_hash`, but the DAG is *unauthenticated structure*: any
integrator can declare a plan and mint step receipts for it. There is no
proposer≠validator authority decision over the **plan itself**. This increment
adds it: a **plan proposer** proposes the DAG, a **distinct plan validator**
authorizes it (a `WorkflowAuthorization`), and steps execute only under that
authorization.

## Two MACI levels + the cross-level rule

- **Plan level:** `plan_proposer` proposes the DAG; `plan_validator_id`
  (≠ proposer) authorizes it → `WorkflowAuthorization`.
- **Step level (existing):** the step proposer (inner `actor`) proposes the
  action; the step validator (inner `validator_id`, ≠ actor) authorizes it →
  inner `DecisionReceipt`.
- **Cross-level separation (decision (b) — locked).** Two clean per-level checks
  still leak under composition: one principal could validate the plan *and*
  propose a step, thereby authorizing the plan that grants its own step's
  authority to execute. The project invariant is literally "an agent can never
  validate its own authority to execute," and the plan authority grant **is**
  part of that authority. So the executor enforces:

  > **No principal is both a proposer and a validator anywhere in the workflow.**
  > `proposers = {plan_proposer, runner} ∪ {each step actor}`;
  > `validators = {plan_validator_id} ∪ {each step validator_id}`;
  > require `proposers ∩ validators = ∅`.

  This is enforced incrementally (the executor sees the authorization at
  construction and each step receipt as it arrives). It catches the collusion
  even on hash-bound fields: passing it requires genuinely distinct identities,
  which is the point.

## The runner anchor (forgery-resistant)

The **runner** — the principal operating the `WorkflowExecutor` — is a distinct
execution principal, identified by the existing `expected_actor` carried on the
`GovernedExecutor` (the runner is the step proposer, consistent with the
single-action gate where `expected_actor == receipt.actor`). The plan-level
anchor mirrors `ae46c9d`'s required `expected_actor`:

> `plan_validator_id != runner` — the runner cannot be the authority that
> authorized the plan it runs. `runner` comes from runtime context, never from
> the authorization, so a plan author cannot satisfy it by editing fields.

The runner is folded into the cross-level set as a proposer, so it also cannot
be any step validator. `plan_proposer` MAY equal the runner (proposing your own
plan is fine) as long as a *distinct* validator authorized it and the runner
validates nothing.

## Schema — `WorkflowAuthorization` (plan receipt, new `plan.py`)

```
WorkflowAuthorization:
    workflow_id: str            # the plan-run instance this authorizes (a nonce)
    dag_hash: str               # the exact plan authorized (== WorkflowDAG.dag_hash())
    plan_proposer: str          # who proposed the plan
    plan_validator_id: str      # distinct authorizing principal
    plan_validator_role: str
    authority: str              # the grant under which the plan may run
    tenant_id: str
    execution_boundary: str
    declared_goal: str
    policy_hash: str = ""
    constraints: dict = {}
    issued_at: str = ""
    expires_at: str = ""
    authorization_hash: str = ""          # self-hash; binds all of the above
    signature_algorithm: str = "none"     # bound into authorization_hash
    signing_key_id: str = ""              # bound into authorization_hash
    signature: str = "unsigned_local"     # signs the hash; OUT of the hash
```

- `compute_authorization_hash()` excludes `authorization_hash` + `signature`;
  includes `dag_hash`, `plan_proposer`, `plan_validator_id`, alg/key_id, etc.
- `from_plan(dag, *, plan_proposer, plan_validator, authority, …, signer=None)`
  — fail-closed: refuses `plan_validator.validator_id == plan_proposer` (plan
  MACI). Computes the hash, then optionally signs it. Mirrors
  `DecisionReceipt.from_record` / `WorkflowStepReceipt.from_inner` exactly.

## Binding steps to the authorization

`WorkflowStepReceipt` gains one field: `authorization_hash` (the plan
authorization it executes under), bound into `compute_step_hash()`. A step
receipt is now tied to a *specific* authorized plan. This is what stops
**cross-plan step lifting** — a step receipt minted under authorization A cannot
be replayed under authorization B (different `authorization_hash` → step hash
mismatch or executor authorization mismatch). Default `""` keeps it
self-consistent; the executor requires it to match.

## The gate — `WorkflowExecutor`

**Breaking change (0.1.0a1, mirrors `ae46c9d`):** `WorkflowExecutor` now
**requires** a `WorkflowAuthorization`. There is no silent-ungoverned path — a
missing authorization is a fail-closed error, not a downgrade. Existing workflow
tests/demo gain an authorization fixture.

The authorization is verified on **every** `execute_step` call (not only at
construction — `execute_step` is independently callable; never run a step against
an unverified or mutated authorization). Verification, all **before** the atomic
inner gate+execute:

A. **Authorization integrity.** `authorization is None` → reject.
   `compute_authorization_hash() != authorization_hash` → reject. Signature
   (when `signature_algorithm != "none"` or `require_signature`) verified with
   the configured verifier; signed-but-no-verifier → reject.
B. **Plan binding.** `authorization.workflow_id != self.workflow_id` → reject
   (cross-plan). `authorization.dag_hash != self.dag.dag_hash()` → reject.
   `authorization.expires_at` past → reject. tenant/boundary mismatch → reject.
C. **Plan MACI + runner anchor.** `plan_validator_id == plan_proposer` → reject.
   `plan_validator_id == runner` → reject (runner self-authorization).
D. **Step→authorization binding.**
   `step_receipt.authorization_hash != authorization.authorization_hash`
   → reject.
E. **Cross-level separation.** Update `proposers`/`validators` with this step's
   `actor`/`validator_id`; if `proposers ∩ validators ≠ ∅` → reject.
F. Then the existing envelope checks (1–7) and the atomic inner gate+execute (8).

## Rejection matrix additions (each row a test through the real executor)

| Attack | Rejected by |
|---|---|
| Missing authorization | A |
| Tampered authorization (hash) | A |
| Forged/recomputed authorization, no key (when signed) | A (signature) |
| Cross-plan authorization (workflow_id / dag_hash ≠ run) | B |
| Expired authorization | B |
| Self-validated plan (plan_validator == plan_proposer) | from_plan + C |
| Runner is the plan validator | C |
| Step lifted to a different plan (authorization_hash ≠) | D |
| Cross-level collusion (one principal proposer here, validator there) | E |

Every negative-path test asserts the tool spy was **NOT called**, not merely
that it raised.

## Replay

`verify_workflow_replay` gains the authorization: it re-checks authorization
integrity + plan MACI + that every step's `authorization_hash` matches the
authorization, alongside the existing topological + inner-receipt checks. Offline
replay also re-runs the cross-level separation check over the recorded set.

## Honesty (scope of the guarantee)

- This is **plan-level role separation enforced by the verifier** (integrator-
  trusted; signing-closed). It adds proposer≠validator over the *plan* and binds
  steps to an authorized plan. It adds **no** cryptographic guarantee beyond the
  authorization receipt and its signature.
- **Not multi-agent governance.** No mutual authentication between agents, no
  delegation chains, no distinct cryptographic agent identities. Principals are
  opaque strings; the cross-level check proves *distinctness of strings*, not
  *authenticated identity*. Multi-agent governance is a separate future
  increment.
- **`workflow_id` is a nonce.** The authorization binds it; the integrator MUST
  NOT reuse a `workflow_id` across runs, or an old authorization (and its step
  receipts) could replay. The executor enforces single-execution within a run
  via the ledger, but cannot detect reuse across separate executor instances.
- Unsigned authorizations are tamper-evident (hash) but forgeable by a party who
  can recompute the hash; envelope/authorization **signing** is the closure.
  Under host compromise the same residuals as the single-action gate apply.

## Build sequencing (invariant first)

1. `WorkflowAuthorization` + `from_plan` + `compute_authorization_hash` (+ optional signing).
2. `WorkflowStepReceipt.authorization_hash` field bound into `compute_step_hash`.
3. `WorkflowExecutor` requires authorization; checks A–E before step 8. **All
   negative paths green, each asserting tool-not-called.** Update existing
   workflow tests/demo with an authorization fixture.
4. `verify_workflow_replay` authorization + cross-level checks.
5. Demo: plan proposer → plan validator authorizes → DAG → step receipts bound
   to the authorization → gated execution; negative scenarios (missing/wrong/
   self-validated authorization, cross-level collusion) all blocked; replay.
6. Docs: this file + ARCHITECTURE.md + SECURITY.md.

## New / changed files

- `src/gove_zone/plan.py` (new)
- `src/gove_zone/workflow.py` (modify: step field + executor authorization gate)
- `tests/test_plan_level_governance.py` (new)
- `examples/plan-level-governance/demo.py` (new)
- existing `tests/test_workflow_receipt_chain.py` + `examples/workflow-receipt-chain/demo.py` (authorization fixture)
