# gove-zone — Architecture

> Status: foundational / Alpha (`0.1.0.dev0`). This describes the implemented
> design. gove-zone is **not** production-, compliance-, or regulator-certified.

## What it is

gove-zone is a **governance plane**, not an agent framework. It is the
enforcement layer immediately before a high-risk side effect. The one invariant
it exists to prove:

> **No valid Decision Receipt, no side effect.**

A caller (agent, MCP tool, workflow engine, CI runner, custom executor) proposes
an action; gove-zone decides, issues a verifiable receipt, and the executor runs
the action only if the receipt verifies.

## Components

| Module | Responsibility |
|---|---|
| `decision.py` | `Decision` enum (`ALLOW/DENY/TRANSFORM/ESCALATE`), `DecisionRecord`, canonical-JSON + SHA-256 helpers. |
| `policy.py` | `Policy` ABC + concrete policies (`RuleSetPolicy`, `BoundaryPolicy`, `CompositePolicy`, …). |
| `kernel.py` | The dispatch loop: evaluate → record → execute/deny. Fail-closed on policy error, timeout, and audit failure. |
| `audit.py` | `ChainHashAuditStore` — append-only, hash-chained, `fcntl`-locked JSONL audit log. |
| `receipt.py` | `DecisionReceipt` (public schema + `verify()`), `Receipt` (kernel proof-of-decision), and `Validator` (the MACI validating principal, distinct from the proposing `actor`). |
| `executor.py` | `execute_with_receipt` / `GovernedExecutor` — the receipt-gated runner. |
| `plan.py` | `WorkflowAuthorization` — the plan layer: a distinct plan validator's MACI authorization of a `WorkflowDAG` (`from_plan` fail-closes on plan self-validation; `compute_authorization_hash` binds `dag_hash`/proposer/validator/alg/key_id; optional Ed25519 signing). |
| `workflow.py` | `WorkflowDAG` / `WorkflowStep` / `WorkflowStepReceipt` / `WorkflowExecutor` / `verify_workflow_replay` — the workflow layer: per-step governance + ledger-enforced ordering over a declared DAG, executed only under a required `WorkflowAuthorization`, composed on top of the single-action gate (core untouched). |
| `tenant.py` | `TenantPolicyStore` + `evaluate_tenant_action` — tenant-isolated issuance. |
| `contracts.py` | Typed named-contract vocabulary (additive): `GovernanceRequest`, `ProposedAction`, `ExecutionBoundary`, `PolicyBundleRef`, `TenantPolicyBinding`, `ReceiptVerifier`, `AuditEvent`. |
| `replay.py` | Reconstruct + re-check decisions from the audit log. |
| `integration.py` | Runtime-hook adapters (Claude Code / MCP / OpenAI / LangChain payload shapes). |
| `cli.py` / `api.py` | CLI (`replay/setup/doctor/gate/enable/policy/eval/smoke/proofpack`, `--version`) and HTTP surface. |
| `errors.py` | Typed errors (`DeniedError`, `EscalateError`, `PolicyError`, `AuditError`, `ReceiptValidationError`). |

## Data flow

```
caller ── GovernanceRequest ──▶ evaluate_tenant_action ──▶ Kernel
                                      │                       │ policy.evaluate
                                      │                       ▼
                                      │                  DecisionRecord
                                      │                       │ audit.append (BEFORE execution)
                                      │                       ▼
                                      └────────────▶  DecisionReceipt  ◀── anchored to audit event
                                                            │
caller ── execute_with_receipt / ReceiptVerifier ──────────┘
                                      │ verify() — fail-closed
                                      ▼
                          side effect runs ONLY on valid ALLOW / approved TRANSFORM
```

The audit append happens **before** any side effect, so every decision —
including refusals — leaves evidence.

## Workflow layer (additive)

`workflow.py` extends the single-action invariant to a multi-step DAG without
changing the audited core. A `WorkflowStepReceipt` envelope wraps a fully valid
inner `DecisionReceipt` and binds it to a workflow position (`workflow_id`,
`step_id`, `dag_hash`, predecessor hashes). `WorkflowExecutor.execute_step` runs
**all** envelope checks (present, hash, signature, workflow binding, DAG binding,
no-replay, predecessor satisfaction) **before** delegating the atomic
gate-and-execute to `GovernedExecutor.execute` — so a reordered or cross-workflow
step's side effect can never fire ahead of the rejection. A per-run `ledger`
(trusted runtime state) enforces ordering and single-execution.
`verify_workflow_replay` re-checks a recorded run offline (no ledger): envelope
integrity, one shared `dag_hash`/`workflow_id`, topological consistency, and each
inner receipt's independent validity. See `docs/workflow-receipt-chain.md` and
the "Workflow receipt chaining" section of `SECURITY.md` for the honest scope.

## Plan layer (additive)

`plan.py` makes the workflow **plan** a governed object, growing the invariant to
add *"no authorized plan, no workflow step executes."* A **plan proposer**
proposes the DAG; a **distinct plan validator** authorizes it (`from_plan`,
fail-closed on plan self-validation), producing a `WorkflowAuthorization` whose
`authorization_hash` binds `dag_hash` + proposer + validator + signing
alg/key_id. `WorkflowStepReceipt` gains an `authorization_hash` (bound into
`compute_step_hash`) tying each step to a *specific* authorized plan — this stops
cross-plan step lifting. `WorkflowExecutor` now **requires** the authorization
(breaking change, no silent-ungoverned path) and verifies it on **every**
`execute_step` (checks A–E: authorization integrity, plan binding, plan MACI +
runner anchor, step→authorization binding, cross-level separation) before the
existing envelope checks and the atomic inner gate. The cross-level rule is
**strict separation (b)**: no principal is both a proposer (plan or any step) and
a validator (plan or any step); the runner (`governed.expected_actor`) is seeded
as a proposer and so can never be any validator. `verify_workflow_replay` takes
the authorization and re-checks its integrity + plan MACI + every step's
`authorization_hash` + cross-level separation over the recorded set (no runner
offline). See `docs/plan-level-governance.md` and the "Plan-level governance"
section of `SECURITY.md` for the honest scope.

## Design boundaries

**In the kernel:** tool-call interception, the four-verdict decision model,
fail-closed execution, hash-chained audit, replayable receipts, tenant
isolation, MACI role separation (validator ≠ proposer, enforced at issuance and
at the gate — see `SECURITY.md`), a typed contract surface.

**Explicitly out (roadmap or separate packages):** YAML constitution loading,
LangGraph/Phoenix/CrewAI integrations, circuit breakers, compliance frameworks,
swarm/debate coordination, signed/authenticated receipts (today role separation
is enforced-by-verifier and audited, not cryptographically unforgeable), bundle
lifecycle state. See `docs/PLAN-GOVE-ZONE-KERNEL.md` in the monorepo for roadmap
context.

## Verification

```bash
cd packages/gove-zone
uv run ruff check src/ tests/
uv run mypy
uv run --package gove-zone pytest -q
uv run --package gove-zone python examples/receipt-gated-execution/demo.py
```

## See also

- `docs/decision-receipts.md`, `docs/governed-execution.md`,
  `docs/audit-evidence.md`, `docs/policy-bundles.md`
- `SECURITY.md` — threat model and the security boundary.
