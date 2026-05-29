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
