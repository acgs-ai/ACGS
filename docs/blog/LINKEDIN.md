# LinkedIn launch post — DRAFT (unpublished)

> **Status: DRAFT / unpublished.** Do not post until a human reviews against
> [`../CLAIMS.md`](../CLAIMS.md) and [`../COMPARISON.md`](../COMPARISON.md). Every
> claim below traces to those files. Project status: alpha (`gove-zone` reports
> `0.1.0.dev0`).

---

**An agent that can *decide* to call a tool can, today, *call* it.**

In most stacks, the gap between "the model chose to write this file / hit this
endpoint / move this money" and the side effect actually firing is unguarded. You
either trust the model or you turn it off.

We've been building a third option: **gove-zone**, a receipt-gated governance layer
for AI-agent side effects.

The core invariant is one sentence: **No valid Decision Receipt, no side effect.**

A Decision Receipt is a pre-execution, self-contained, vendor-neutral artifact. It
binds the actor, the action, the exact arguments, the tenant, and the policy bundle
the executor checks — *before* anything runs. It's hash-bound and can be Ed25519-
signed, so a relying party can verify it independently. Denied, missing, or
tampered receipts fail closed.

Here's the honest framing:

→ gove-zone is the **execution-legitimacy** layer, not the whole safety stack. It
**complements** — it does not replace — your agent framework, MCP, content
guardrails, sandboxing, and IAM. IAM authenticates the caller; gove-zone authorizes
the exact side effect; a sandbox contains it; guardrails moderate content.

→ The nearest comparison is Microsoft's Agent Governance Toolkit (AGT) — genuinely
strong engineering: open-source, fail-closed, framework-agnostic across 15+
runtimes, with a Merkle-chained audit log and external inclusion proofs, and
broader framework coverage than this alpha project today. The difference is
**receipt-centric vs audit-centric**: per AGT's own docs, its chain is built for
after-the-fact forensics, with no first-class decision receipt. gove-zone's narrower
bet is exactly that artifact — a receipt issued *before* execution. Contrast by
evidence, not a knock; the two could even compose.

→ And the part most launch posts skip: gove-zone is **alpha** (`0.1.0.dev0`). It is
**not** production-certified, **not** compliance-certified, and **not**
regulator-approved. The proofs are real engineering evidence — not production
deployment proof.

The whole pitch is that you don't have to take the headline on trust. There's a
proof pack you can run in one command (`status: pass` on six conformance checks),
and a tamper demo where you edit a receipt and watch it fail closed.

Read the claim ledger, the comparison, and the FAQ — and tell us where the framing
is wrong.

#AIagents #AIgovernance #AgentSafety #opensource
