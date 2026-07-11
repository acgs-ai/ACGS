# Roadmap

> **Roadmap of record.** This is the single maintained roadmap for the
> repository. Superseded roadmaps and plans are frozen in
> [`docs/archive/`](archive/README.md); do not plan new work from them.

This roadmap is claim-safe: planned work is not described as implemented.

Status legend: **✅ SHIPPED** — every acceptance sub-clause has a source file *and* a cited test; **🟡 PARTIAL** — some sub-clauses met (the missing one is named in Status evidence below); **⬜ PLANNED** — forward-looking, not implemented yet. Marks verified against `origin/master` @ `9dd118c` (see Status evidence).

| Stage | Status | Why it matters | Acceptance test | User impact | Risk if skipped |
|---|---|---|---|---|---|
| Alpha: local receipt-gated kernel | ✅ SHIPPED <sup>[1]</sup> | Establish the invariant locally. | Smoke proof, receipt-gated demo, executor/audit/receipt tests pass. | Evaluators can prove `No valid Decision Receipt, no side effect` on a laptop. | Project sounds like governance theory without runnable proof. |
| Secure profile: signed receipts on by default | ✅ SHIPPED <sup>[2]</sup> | Close recomputed-hash residual for production-adjacent pilots. | Default secure profile rejects unsigned receipts; signed key registry tests pass. | Operators get safer defaults. | Unsigned dev mode may be misused as production assurance. |
| Replay hardening: multi-event chain verification | ✅ SHIPPED <sup>[3]</sup> | Prove longer workflows/evidence bundles, not isolated events only. | Replay verifies multi-event chain plus side-store/raw-arg consistency and fails on tamper/reorder. | Reviewers can audit realistic runs. | Proof path remains too small for serious pilots. |
| Integration: MCP and agent-framework adapters | 🟡 PARTIAL <sup>[4]</sup> | Put the gate where teams already run agents. | Conformance tests for MCP gateway, OpenAI-style tool wrapper, LangGraph node/tool wrapper. | Faster adoption without replacing existing agent stacks. | Integrators may wire the gate incorrectly or bypass it. |
| Reference integration: real agent platform (e.g. Mattermost Agents MCP; **candidate:** flue `outboundByHost` egress callback) | ⬜ PLANNED | Prove the MCP gateway against a widely-deployed agent surface, not just local examples. | A real platform's agent tool-calls (`create_post`, `create_channel`, file ops) route through the gate; fail-closed when no receipt; `expected_actor` bound to the platform's authenticated user; bypass-path documented. The same fail-closed / `expected_actor` acceptance applies to a flue `outboundByHost` integration (call kernel → forward on `ALLOW` with the signed receipt → fail closed on `DENY`). | Operators see the gate working on a production agent stack they recognise. | MCP-adapter conformance stays illustrative; adopters can't see a concrete end-to-end wiring. |
| Policy: signed bundles and versioned policy registry | 🟡 PARTIAL <sup>[6]</sup> | Stop policy-bundle substitution and stale policy confusion. | Bundle signatures, active/stale/revoked states, tenant binding tests. | Clear operational policy lifecycle. | Receipts may bind hashes but operators lack lifecycle controls. |
| Evidence: exportable proof packs | ✅ SHIPPED <sup>[5]</sup> | Make review, buyer diligence, and incident response concrete. | CLI exports receipts, audit chain, replay verdicts, limitations, and manifest; tamper tests fail. | Reviewers can inspect artifacts without trusting prose. | Claims remain hard to verify externally. |
| Operations: production deployment profile | ⬜ PLANNED | Move from local proof to production-adjacent operation. | Deployment guide, health checks, audit sink, key management, fail-closed config, rollback drills. | Teams can run pilots with known responsibilities. | Local demo may be mistaken for production readiness. |
| Review: external security review | ⬜ PLANNED | Independent challenge of threat model and implementation. | Published review scope, findings, remediations, residual risks. | Higher buyer/security confidence. | Internal tests may miss design or threat-model gaps. |
| Ecosystem: standard receipt schema for agent runtimes | ⬜ PLANNED | Make receipts portable across frameworks. | Versioned schema, compatibility tests, reference validators in multiple hosts. | Agent runtimes can share governance evidence. | Fragmented receipts make integration harder. |

## Status evidence

Verified against `origin/master` @ `9dd118c` (2026-06-18). Every `SHIPPED` /
`PARTIAL` row cites a source file and a test; each `PARTIAL` also names the
unmet sub-clause.

1. **Alpha kernel** — `kernel.py`, `executor.py`, `receipt.py`, `audit.py`; `gove-zone smoke`, `examples/receipt-gated-execution/demo.py`, and `test_kernel_dispatch.py` / `test_executor_guard.py` / `test_decision_receipt.py` / `test_audit_chain.py` / `test_end_to_end.py` / `test_fail_closed.py`.
2. **Secure profile (signed receipts default)** — `profile.py` `production()` → `require_signature=True`; `test_profile.py::test_production_constructor_requires_signature` pins the unset-env → production default flip (#138); `test_receipt_signing.py`.
3. **Replay hardening (multi-event chain)** — `replay.py` + `consumption.py` hash-chain keyed on `receipt.audit_event_hash`; `test_replay.py`, `test_replay_bundle_equivalence.py`, `test_workflow_receipt_chain.py`, `test_consumption_{tamper,reconcile,hwm}.py`. *Caveat:* the consumption ledger's high-water-mark check catches wholesale + tail-below-HWM deletion, **not** interior burned-entry deletion (only the out-of-band `verify_ledger` chain check does); the default `checkpoint=False` ⇒ no HWM at all.
4. **Integration (PARTIAL).** *Shipped:* MCP/A2A + OpenAI-Chat/Responses + LangChain-style payload parsing in `integration.py`, with conformance cases in `test_adapter_conformance.py` (`mcp-tools-call`, `openai-chat-tool-calls`, `openai-responses-*`, `langchain-tool-call`) and `test_mcp_binding.py`. *Missing:* no **LangGraph node/tool wrapper** and no LangGraph conformance case in `gove_zone.integration` — the acceptance row's LangGraph clause is unmet. (The repo's only `langgraph.py` is `acgs_governance_eval_mvp/governance/adapters/langgraph.py`, a different package; it does not satisfy this DoD.)
5. **Evidence (exportable proof packs)** — `verifier.py::verify_proof_pack`; CLI `verify-proofpack`; `docs/PROOF_PATH.md`; conformance corpus `test_proofpack_corpus.py` (#144).
6. **Policy (PARTIAL).** *Shipped:* content-addressed policy **versioning** (`policy.py` `_compute_version` / `RuleSetPolicy`; CLI `policy inspect` / `policy export`; `test_policy_bundle_io.py`) and **tenant binding** (`tenant.py` active-bundle-by-tenant lookup; `test_tenant_safety.py`). *Missing:* policy-**bundle signatures** (no bundle signing exists) and the **active/stale/revoked lifecycle states** — the latter is explicitly *not modeled* (`contracts.py`: "(stale / revoked) is intentionally not modeled here").

## Roadmap wording rule

Use "planned", "roadmap", or "not implemented yet" unless a source file, test, demo output, and claim-ledger entry prove the feature exists.
