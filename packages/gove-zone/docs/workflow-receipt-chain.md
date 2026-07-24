# Workflow Receipt Chain — design

> Status: **implemented on `master`** — `src/gove_zone/workflow.py`
> (`WorkflowDAG`, `WorkflowStepReceipt`, `WorkflowExecutor.execute_step`,
> `verify_workflow_replay`); tests in `tests/test_workflow_receipt_chain.py`.
> This file is retained as the design rationale. **The code is authoritative
> where the two differ** — the executor carries at least one check this document
> predates (4b, positional binding: an envelope may only drive the DAG position
> its `step_id` names).
> Extends the single-action receipt gate to a multi-step workflow (a DAG of
> steps). The invariant grows from *"no valid Decision Receipt, no side effect"*
> to *"no valid step receipt — bound to this workflow, this step, and its
> satisfied predecessors — no side effect for that step."*

## Scope (what this increment is, and is NOT)

**Is:** per-step governance + ledger-enforced ordering over a declared DAG.
Each step's execution is gated by a `WorkflowStepReceipt` that wraps a fully
valid inner `DecisionReceipt` (verified by the existing, unchanged single-action
gate) and binds it to a workflow position. A runtime ledger enforces predecessor
satisfaction (ordering) and single-execution (no replay). The DAG structure is
bound into every envelope via `dag_hash`, so step injection or plan alteration
is detected.

**Is NOT (explicit future scope):**
- **Plan-level governance.** The DAG itself is *not* a separately
  proposer≠validator-authorized object in this increment. `dag_hash` is a
  consistency binding, not an authority decision over the plan. A future
  increment may add a `WorkflowAuthorization` receipt that governs the DAG with
  its own MACI separation.
- **Full multi-agent / swarm governance.** Out of scope per the directive.

## Why composition, not a core-schema change

The audited `DecisionReceipt` stays untouched and core `dependencies = []`
remains. The workflow layer is *additive*: it composes an inner
`DecisionReceipt` with a workflow envelope. The inner receipt is verified by the
proven gate (`execute_with_receipt` / `DecisionReceipt.verify`); the envelope
adds workflow-only checks on top. Framework-neutral, thin, deterministic.

## Schema — `WorkflowStepReceipt` (envelope)

```
WorkflowStepReceipt:
    inner: DecisionReceipt          # the single-action receipt for this step
    workflow_id: str                # the DAG-run instance id
    step_id: str                    # this step's node id in the DAG
    predecessor_step_ids: list[str] # DAG dependencies (sorted, canonical)
    predecessor_receipt_hashes: dict[str, str]
                                    # {predecessor step_id: its step_receipt_hash}
    dag_hash: str                   # sha256_json of the canonical DAG structure
    step_receipt_hash: str          # binds ALL of the above + inner.receipt_hash
    signature_algorithm: str = "none"
    signing_key_id: str = ""
    signature: str = "unsigned_local"
```

`compute_step_hash()` = `sha256_json` of every field **except**
`step_receipt_hash` and `signature` — and it **includes `inner.receipt_hash`**,
so the envelope is cryptographically bound to the exact inner receipt it wraps
(a different inner receipt → different `step_receipt_hash`). `signature_algorithm`
and `signing_key_id` are inside the hash (anti-downgrade); `signature` signs the
hash and stays out of it — identical discipline to the inner receipt.

## DAG model — `WorkflowDAG`

```
WorkflowStep:  step_id: str, action: str, predecessor_step_ids: list[str]
WorkflowDAG:   steps: dict[str, WorkflowStep]
    .dag_hash() -> sha256_json of {step_id: {action, sorted(predecessors)}}
    .validate() -> fail-closed: every predecessor must exist; no cycles
                   (topological sort must succeed); no duplicate step_ids
```

`dag_hash` is computed once from the declared plan and bound into every step
envelope. All steps in one run must carry the *same* `dag_hash`.

## The gate — `WorkflowExecutor.execute_step(...)`

Per-run state: `ledger: dict[str, str]` = `{step_id: step_receipt_hash}` of
steps already executed **in this run**. The executor is constructed with the
`workflow_id`, the `WorkflowDAG`, and a `GovernedExecutor` (carrying tenant,
boundary, expected_actor, optional verifier/require_signature).

**Order of checks is load-bearing (see BLOCKER below): ALL verification completes
before ANY side effect.**

For `execute_step(step_id, args, step_receipt, *, expected_args=...)`:

1. **Envelope present.** `step_receipt is None` → reject. (No receipt, no side
   effect.)
2. **Envelope hash.** `step_receipt.compute_step_hash() != step_receipt_hash`
   → reject (tampered envelope).
3. **Envelope signature** (if `signature_algorithm != "none"`, or
   `require_signature`): verify with the configured verifier exactly as the
   inner gate does. A signed envelope with no verifier → reject.
4. **Workflow binding.** `step_receipt.workflow_id != self.workflow_id`
   → reject (**cross-workflow**: a step receipt from another run/plan cannot
   execute here).
5. **DAG binding.** `step_receipt.dag_hash != self.dag.dag_hash()` → reject
   (plan altered / step from a different plan). `step_id not in self.dag.steps`
   → reject. `step_receipt.predecessor_step_ids != sorted(dag step predecessors)`
   → reject (declared dependencies don't match the approved DAG).
6. **No replay.** `step_id in self.ledger` → reject (step already executed).
7. **Predecessor satisfaction (ordering).** For each `p in dag predecessors`:
   `p in self.ledger` (else **reorder**: predecessor hasn't run) AND
   `step_receipt.predecessor_receipt_hashes[p] == self.ledger[p]` (else
   **predecessor substitution**: a different predecessor receipt than the one
   that actually ran).
8. **Inner gate + execute (atomic, LAST).** Call
   `self.governed.execute(action, args, step_receipt.inner, expected_actor=...)`
   — this runs the full single-action gate (actor anchor, args binding, policy,
   boundary, signature, self-validation) and only then `tool_fn(**args)`.
9. On success, record `self.ledger[step_id] = step_receipt.step_receipt_hash`
   and return the result.

### BLOCKER this design closes
`execute_with_receipt` verifies **and executes in one call**. If the inner gate
ran *before* the envelope checks, a reordered/cross-workflow step's side effect
would fire and a naive test asserting "it raised" would pass while the tool had
already run. Therefore every envelope check (steps 1–7) runs **before** step 8.
**Every negative-path test asserts the tool spy was NOT called** — not merely
that `ReceiptValidationError` was raised.

## Replay — `verify_workflow_replay(dag, step_receipts, *, verifier=None)`

Offline re-verification of a recorded run (no ledger):
- All envelopes share one `dag_hash` == `dag.dag_hash()`; all share one
  `workflow_id`.
- Each envelope's `compute_step_hash()` matches its `step_receipt_hash`; if
  `verifier` given / signed, signature verifies.
- Topological consistency: order the step receipts so every step's predecessors
  appear before it; each `predecessor_receipt_hashes[p]` equals predecessor `p`'s
  actual `step_receipt_hash`.
- Each inner `DecisionReceipt` is independently valid (`verify(...)`).
- Coverage is reported honestly: replay proves the recorded chain is internally
  consistent and topologically faithful to the approved DAG.

## Rejection matrix (every row is a test through the real executor)

| Attack | Rejected by |
|---|---|
| Missing step receipt | step 1 |
| Tampered envelope field | step 2 (hash) |
| Forged/recomputed envelope, no key | step 3 (signature) when engaged |
| Cross-workflow receipt (workflow_id ≠ run) | step 4 |
| DAG altered / step not in plan | step 5 (dag_hash / membership) |
| Replayed step (run twice) | step 6 |
| Reordered (predecessor not yet run) | step 7 (ledger miss) |
| Predecessor substitution | step 7 (hash mismatch) |
| Tampered inner receipt / wrong policy / expired | step 8 (existing gate) |
| Substituted execution args | step 8 (existing argument_hash binding) |
| Self-validated step (inner validator == actor) | step 8 (existing MACI 2b) |

## Honesty (scope of the guarantee)

- Workflow chaining proves a step ran **in the approved order with approved args
  under a valid per-step receipt**. It adds **no** cryptographic guarantee beyond
  the per-step receipts and their envelopes.
- **Unsigned** `verify_workflow_replay()` proves *internal chain consistency and
  topological faithfulness*, **not unforgeability**: an attacker who can recompute
  envelope hashes (and re-sign, if they hold the key) can produce a consistent
  chain. Envelope signing (`ReceiptSigner`) is the closure for cross-workflow and
  ordering integrity, exactly as Ed25519 closes the inner recomputed-receipt
  residual — and only when engaged.
- The ledger detects predecessor-substitution and reordering because it is
  **trusted runtime state**. Offline replay has no ledger; its
  substitution-detection rests on envelope integrity (hashes, and signatures when
  engaged).
- Under host compromise the same residuals as the single-action gate apply.

## Build sequencing (invariant first)

1. `WorkflowDAG` + `WorkflowStep` (+ `validate`, `dag_hash`).
2. `WorkflowStepReceipt` (+ `compute_step_hash`, optional signing, `from_inner`).
3. `WorkflowExecutor.execute_step` — the gate. **All negative paths green,
   each asserting tool-not-called.** This is the load-bearing invariant.
4. `verify_workflow_replay`.
5. Demo: goal → DAG → step receipts → gated execution (in order) → negative
   scenarios (reorder, cross-workflow, DAG-tamper) → replay (pass; tamper → fail).
6. Docs: this file + ARCHITECTURE.md + SECURITY.md.

## New files (additive; core untouched)

- `src/gove_zone/workflow.py`
- `tests/test_workflow_receipt_chain.py`
- `examples/workflow-receipt-chain/demo.py`
