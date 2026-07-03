# Thread: Guardrails vs Receipts (Telegram campaign draft)

Source: docs/blog/2026-06-receipts-vs-guardrails-positioning.md
Every claim verified via the gove-zone proof path (smoke + receipt-gated demo + tamper demo), 2026-06-07.

---

1/ AI-agent "governance" got crowded fast. Some tools govern the *perimeter* (prompts, outputs); the strong ones already enforce at the execution boundary — Microsoft's open-source Agent Governance Toolkit does fail-closed, pre/post tool-call policy with a Merkle-chained audit. The harder question isn't the layer, it's the artifact: when the action runs, do you get a portable Decision Receipt you can verify on its own, or an audit trail reconstructed afterward? 🧵

2/ Distinction 1 — Guardrails moderate what an agent *says*. Receipts gate what it *does*. A guardrail filters text and the tool *request*. But by the time a tools/call leaves the model, the question is: may THIS actor run THIS action with THESE args under THIS policy?

3/ Worked example: a receipt issued for {"path":"/tmp/safe.txt"} will NOT authorize {"path":"/etc/shadow","content":"pwned"}. Same action name, different arguments → blocked as an argument mismatch BEFORE any side effect. A text guardrail has no equivalent move.

4/ Distinction 2 — An audit log is a narrative; a Decision Receipt is a gate. A log is a story told after the fact — it can't stop anything, and if it's mutable it can't even prove what happened. The receipt IS the gate: the same object both enforces and audits.

5/ Tamper-evidence, proven locally: corrupt one audit entry and verification flips valid→invalid. Cross-tenant receipts are rejected. Opt-in Ed25519 signing — signed verifies, forged/recomputed rejected. No valid Decision Receipt, no side effect.

6/ Where it sits: combine, don't replace. IAM authenticates, sandboxes contain, guardrails moderate text. gove-zone is the execution-legitimacy layer underneath — it binds actor + action + args + policy + validator + authority + receipt + audit into ONE decision, and fails closed.

7/ Honest boundary: gove-zone is alpha (0.1.0.dev0). Real, locally reproducible evidence — NOT production/compliance/regulator certification. The Aug 2 EU AI Act deadline is a reason to build the proof layer now, not a certificate. Repo + 1-minute proof path: github.com/dislovelhl/ACGS
