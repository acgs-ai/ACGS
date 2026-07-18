# Roadmap

> **Roadmap of record.** This is the single maintained roadmap for the
> repository. Superseded roadmaps and plans are frozen in
> [`docs/archive/`](archive/README.md); do not plan new work from them.

This roadmap is claim-safe: planned work is not described as implemented.

Status legend: **✅ SHIPPED** — every acceptance sub-clause has a source file *and* a cited test; **🟡 PARTIAL** — some sub-clauses met (the missing one is named in Status evidence below); **⬜ PLANNED** — forward-looking, not implemented yet. Marks verified against `master` @ `941e398cb266b29b88325a58605a16008d2af63c` (see Status evidence).

| Stage | Status | Why it matters | Acceptance test | User impact | Risk if skipped |
|---|---|---|---|---|---|
| Local receipt-gated kernel | ✅ SHIPPED [1] | Establish the invariant locally. | Smoke proof, receipt-gated demo, executor/audit/receipt tests pass. | Evaluators can prove `No valid Decision Receipt, no side effect` on a laptop. | Project sounds like governance theory without runnable proof. |
| Secure profile: signature-required gate by default | ✅ SHIPPED [2] | Close recomputed-hash residual for production-adjacent pilots. | Default gate rejects unsigned receipts; explicitly configured signed issuance and trusted-verifier tests pass. | Operators get a fail-closed secure gate default without implied automatic key setup. | Unsigned dev mode may be misused as production assurance. |
| Replay evidence: audit verification plus conditional re-derivation | ✅ SHIPPED [3] | Prove longer workflows/evidence bundles without overstating retained data. | Audit-only replay verifies chain/event integrity and policy-version consistency; separate side-store tests re-derive only with retained raw calls and the matching original policy. | Reviewers can distinguish evidence integrity from reproduced policy decisions. | Missing/redacted side records or policy bundles limit review to audit-only verification. |
| Integration: MCP and agent-framework adapters | ✅ SHIPPED [4] | Put the gate where teams already run agents. | Conformance tests for MCP gateway, OpenAI-style tool wrapper, LangGraph node/tool wrapper. | Faster adoption without replacing existing agent stacks. | Integrators may wire the gate incorrectly or bypass it. |
| Reference integration: real agent platform (e.g. Mattermost Agents MCP; **candidate:** flue `outboundByHost` egress callback) | ⬜ PLANNED | Prove the MCP gateway against a widely-deployed agent surface, not just local examples. | A real platform's agent tool-calls (`create_post`, `create_channel`, file ops) route through the gate; fail-closed when no receipt; `expected_actor` bound to the platform's authenticated user; bypass-path documented. The same fail-closed / `expected_actor` acceptance applies to a flue `outboundByHost` integration (call kernel → forward on `ALLOW` with the signed receipt → fail closed on `DENY`). | Operators see the gate working on a production agent stack they recognise. | MCP-adapter conformance stays illustrative; adopters can't see a concrete end-to-end wiring. |
| Policy: signed bundles and versioned policy registry | 🟡 PARTIAL [6] | Stop policy-bundle substitution and stale policy confusion. | Bundle signatures, active/stale/revoked states, tenant binding tests. | Clear operational policy lifecycle. | Receipts may bind hashes but operators lack lifecycle controls. |
| Evidence: exportable proof packs | ✅ SHIPPED [5] | Make review, buyer diligence, and incident response concrete. | CLI exports receipts, audit chain, replay verdicts, limitations, and manifest; tamper tests fail. | Reviewers can inspect artifacts without trusting prose. | Claims remain hard to verify externally. |
| Operations: production deployment profile | ⬜ PLANNED | Move from local proof to production-adjacent operation. | Deployment guide, health checks, audit sink, key management, fail-closed config, rollback drills. | Teams can run pilots with known responsibilities. | Local demo may be mistaken for production readiness. |
| Review: external security review | ⬜ PLANNED | Independent challenge of threat model and implementation. | Published review scope, findings, remediations, residual risks. | Higher buyer/security confidence. | Internal tests may miss design or threat-model gaps. |
| Ecosystem: standard receipt schema for agent runtimes | ⬜ PLANNED | Make receipts portable across frameworks. | Versioned schema, compatibility tests, reference validators in multiple hosts. | Agent runtimes can share governance evidence. | Fragmented receipts make integration harder. |

## Status evidence

Verified against `master` @ `941e398cb266b29b88325a58605a16008d2af63c`
(2026-07-17). Every `SHIPPED` /
`PARTIAL` row cites a source file and a test; each `PARTIAL` also names the
unmet sub-clause.

1. **Local kernel** — `kernel.py`, `executor.py`, `receipt.py`, `audit.py`; `gove-zone smoke`, `examples/receipt-gated-execution/demo.py`, and `test_kernel_dispatch.py` / `test_executor_guard.py` / `test_decision_receipt.py` / `test_audit_chain.py` / `test_end_to_end.py` / `test_fail_closed.py`.
2. **Secure profile (signature-required gate default)** — `profile.py` `production()` → `require_signature=True`; issuance still requires an explicit signer and the gate requires a matching trusted verifier. `test_profile.py::test_production_constructor_requires_signature` pins the unset-env → production default flip (#138); `test_receipt_signing.py` covers configured signing and verification.
3. **Replay evidence (two levels)** — audit-only `replay.py` verifies chain/event integrity and policy-version consistency; it cannot reproduce the original decision because audit records omit raw arguments. Decision re-derivation is a separate `replay_store.py` path and requires an opt-in `ReplaySideStore` plus the matching original policy bundle; `test_replay.py` and `test_replay_bundle_equivalence.py` cover those boundaries. The `consumption.py` ledger is anti-replay enforcement, not decision replay: its high-water-mark check catches wholesale + tail-below-HWM deletion, **not** interior burned-entry deletion (only the out-of-band `verify_ledger` chain check does), and the default `checkpoint=False` means no HWM at all. Workflow replay coverage is in `test_workflow_receipt_chain.py`; consumption integrity is covered by `test_consumption_{tamper,reconcile,hwm}.py`.
4. **Integration.** MCP/A2A + OpenAI-Chat/Responses + LangChain-style payload parsing ships in `integration.py`, with conformance cases in `test_adapter_conformance.py` and `test_mcp_binding.py`. The dependency-free `make_langgraph_tool_node` wrapper is exported from the same module; `test_langgraph_node.py` proves allow execution plus fail-closed deny and malformed-call behavior, and `examples/agent-framework-wrapper/demo.py` demonstrates the contract-level pattern. This does not claim conformance against an installed `langgraph` dependency.
5. **Evidence (exportable proof packs)** — `verifier.py::verify_proof_pack`; CLI `verify-proofpack`; `docs/PROOF_PATH.md`; conformance corpus `test_proofpack_corpus.py` (#144).
6. **Policy (PARTIAL).** *Shipped:* content-addressed policy **versioning** (`policy.py` `_compute_version` / `RuleSetPolicy`; CLI `policy inspect` / `policy export`; `test_policy_bundle_io.py`) and **tenant binding** (`tenant.py` active-bundle-by-tenant lookup; `test_tenant_safety.py`). *Missing:* policy-**bundle signatures** (no bundle signing exists) and the **active/stale/revoked lifecycle states** — the latter is explicitly *not modeled* (`contracts.py`: "(stale / revoked) is intentionally not modeled here").

## Roadmap wording rule

Use "planned", "roadmap", or "not implemented yet" unless a source file, test, demo output, and claim-ledger entry prove the feature exists.
