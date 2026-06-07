# Roadmap

This roadmap is claim-safe: planned work is not described as implemented.

| Stage | Why it matters | Acceptance test | User impact | Risk if skipped |
|---|---|---|---|---|
| Alpha: local receipt-gated kernel | Establish the invariant locally. | Smoke proof, receipt-gated demo, executor/audit/receipt tests pass. | Evaluators can prove `No valid Decision Receipt, no side effect` on a laptop. | Project sounds like governance theory without runnable proof. |
| Secure profile: signed-key registry & rotation | The default gate already rejects unsigned receipts (`require_signature=True`); a managed signed-key registry, rotation, and revocation remain. | Key registry with active/stale/revoked states and rotation tests pass. | Operators get managed key lifecycle, not just default-required signing. | Key management stays ad-hoc; rotation/revocation are manual. |
| Replay hardening: multi-event chain verification | Prove longer workflows/evidence bundles, not isolated events only. | Replay verifies multi-event chain plus side-store/raw-arg consistency and fails on tamper/reorder. | Reviewers can audit realistic runs. | Proof path remains too small for serious pilots. |
| Integration: MCP and agent-framework adapters | Put the gate where teams already run agents. | Conformance tests for MCP gateway, OpenAI-style tool wrapper, LangGraph node/tool wrapper. | Faster adoption without replacing existing agent stacks. | Integrators may wire the gate incorrectly or bypass it. |
| Policy: signed bundles and versioned policy registry | Stop policy-bundle substitution and stale policy confusion. | Bundle signatures, active/stale/revoked states, tenant binding tests. | Clear operational policy lifecycle. | Receipts may bind hashes but operators lack lifecycle controls. |
| Evidence: exportable proof packs | Make review, buyer diligence, and incident response concrete. | CLI exports receipts, audit chain, replay verdicts, limitations, and manifest; tamper tests fail. | Reviewers can inspect artifacts without trusting prose. | Claims remain hard to verify externally. |
| Operations: production deployment profile | Move from local proof to production-adjacent operation. | Deployment guide, health checks, audit sink, key management, fail-closed config, rollback drills. | Teams can run pilots with known responsibilities. | Local demo may be mistaken for production readiness. |
| Review: external security review | Independent challenge of threat model and implementation. | Published review scope, findings, remediations, residual risks. | Higher buyer/security confidence. | Internal tests may miss design or threat-model gaps. |
| Ecosystem: standard receipt schema for agent runtimes | Make receipts portable across frameworks. | Versioned schema, compatibility tests, reference validators in multiple hosts. | Agent runtimes can share governance evidence. | Fragmented receipts make integration harder. |

## Roadmap wording rule

Use "planned", "roadmap", or "not implemented yet" unless a source file, test, demo output, and claim-ledger entry prove the feature exists.
