# Claim ledger

Purpose: prevent marketing drift. Every public claim should be traceable to code, tests, demos, receipt evidence, replay verification, or roadmap.

| Claim | Status | Evidence source | Test or demo | Limitation | Safe public wording |
|---|---|---|---|---|---|
| ACGS / gove-zone is receipt-gated governance for AI-agent side effects. | implemented | `packages/gove-zone/src/gove_zone/*` | `gove-zone smoke`, receipt-gated demo | Local kernel, not a managed production service. | "Local receipt-gated governance layer for AI-agent side effects." |
| No valid Decision Receipt, no side effect. | tested | `executor.py`, `receipt.py` | `test_executor_guard.py`, `examples/tamper_demo`, `proofpack` | Only true for paths wired through the governed executor. | "The governed executor fails closed without a valid receipt." |
| Policy is evaluated before execution. | tested | `kernel.py` | `test_fail_closed.py`, smoke demo | Direct raw-tool calls can bypass if integrator exposes them. | "Kernel dispatch evaluates policy before the registered tool runs." |
| Denied action leaves evidence and does not run. | tested | `kernel.py`, `audit.py` | smoke demo, `test_fail_closed.py` | Local JSONL only. | "Denied local actions are audited and blocked before side effects." |
| Missing receipt is blocked. | tested | `executor.py` | `test_executor_refuses_no_receipt`, `proofpack` | Requires executor gate integration. | "Gated execution rejects missing receipts." |
| Tampered receipt is blocked. | tested | `receipt.py` | `test_decision_receipt.py`, `examples/tamper_demo` | Unsigned hashes are recomputable under host compromise. | "Receipt field tampering is hash-detected; signed mode closes recomputed-forgery when engaged." |
| Actor/action/argument binding exists. | tested | `receipt.py`, `executor.py` | `test_argument_binding.py`, `test_executor_guard.py` | Actor identity comes from integrator runtime context. | "Receipts bind the actor, action, and exact arguments checked by the executor." |
| Tenant and policy binding exist. | tested | `tenant.py`, `policy.py`, `receipt.py` | `test_tenant_safety.py`, `test_policy_bundle_io.py` | No policy lifecycle/revocation registry yet. | "Receipts can be checked against expected tenant and policy bundle/hash." |
| Expiry is supported. | tested | `receipt.py` | `test_receipt_expiry.py` | Expiry is optional; no revocation list. | "Receipts may carry hash-bound expiries that fail closed when expired." |
| Audit evidence is tamper-evident. | tested | `audit.py` | `test_audit_chain.py`, `test_audit_chain_corruption.py`, tamper demo | Local JSONL is not WORM storage. | "Local audit events are hash-chained and tamper-evident." |
| Replay verification exists. | partial/tested | `replay.py`, `replay_store.py` | `test_replay.py` | Audit-only replay is policy-version-only without raw args; strong replay needs side-store. | "Replay helpers can re-derive decisions when raw call context is retained." |
| Ed25519 signing mode exists. | tested | `signing.py`, `receipt.py` | `test_receipt_signing.py`, package demo | Opt-in; no PKI, key custody, or revocation. | "Opt-in Ed25519 receipt signing is implemented for local trusted-key verification." |
| MCP/function-call adapter shapes exist. | tested | `integration.py` | `test_integration_hook.py`, `test_integration_gaps.py`, `examples/mcp_tool_gate` | Shape parsing is not the same as a certified production adapter. | "The adapter normalizes common hook, MCP, and function-call payload shapes." |
| Proof pack generation exists. | tested | `cli.py` | `test_cli.py`, `gove-zone proofpack` | Local conformance evidence only. | "The CLI can generate a local proof pack with receipts, audit, verification, and limitations." |
| ACGS is production-certified. | not claimed | none | none | No certification evidence. | "Not production-certified." |
| ACGS is compliance-certified. | not claimed | none | none | No compliance audit/certificate. | "Not compliance-certified." |
| ACGS is regulator-approved. | not claimed | none | none | No regulator approval. | "Not regulator-approved." |
| ACGS replaces content moderation. | not claimed | none | none | It governs side effects, not all content harms. | "Complements content moderation; does not replace it." |
| ACGS replaces sandboxing. | not claimed | none | none | It authorizes execution; sandboxing contains execution. | "Complements sandboxing; does not replace it." |
| ACGS is complete IAM/RBAC/PKI. | not claimed | none | none | Identity/key lifecycle is integrator/operator-owned. | "Requires external identity and key-management systems for production." |
| ACGS is full formal verification. | not claimed | none | none | Tests and deterministic checks exist; no formal proof suite. | "Tested local invariant evidence, not full formal verification." |

## Public wording rule

If a claim is not in this table, add it here before using it in public docs. If evidence is partial, use partial wording. If evidence is roadmap-only, say planned.
