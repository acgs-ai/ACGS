# Reddit launch post — DRAFT (unpublished)

> **Status: DRAFT / unpublished.** Do not post until a human reviews against
> [`../CLAIMS.md`](../CLAIMS.md) and [`../COMPARISON.md`](../COMPARISON.md).
> Suggested subreddits: r/LocalLLaMA, r/LLMDevs, r/AI_Agents (read each rules page
> first). Every claim below traces to those files. Project status: alpha
> (`gove-zone` reports `0.1.0.dev0`).

---

**Title:** gove-zone: a receipt-gated governance layer for AI-agent side effects
(alpha, open-source) — looking for holes in the framing

**Body:**

An agent that can *decide* to call a tool can, in most stacks, just *call* it.
Between "the model chose to write this file / hit this endpoint / move this money"
and the side effect firing, there's usually nothing. You trust the model or you
turn it off.

I've been building a third option and want this community to poke at it.

**gove-zone** enforces one invariant: **no valid Decision Receipt, no side effect.**

A Decision Receipt is a pre-execution, self-contained, vendor-neutral artifact that
binds the actor, action, exact arguments, tenant, and policy bundle the executor
checks before anything runs. It's hash-bound, optionally Ed25519-signed, and
verifiable by a relying party on its own. Missing / denied / tampered receipts fail
closed (and denials are still audited on a tamper-evident hash chain).

**What it is NOT** (this is the part I want to be honest about up front):

- It is the *execution-legitimacy* layer, not the whole safety stack. It
  **complements** — does not replace — agent frameworks, MCP, content guardrails,
  sandboxing, and IAM. gove-zone authorizes the exact side effect; a sandbox still
  contains it; IAM still authenticates the caller.
- It is **alpha** (`0.1.0.dev0`). **Not** production-certified, **not**
  compliance-certified, **not** regulator-approved. The local proofs are real
  engineering evidence, not production deployment proof.
- Signing is **opt-in**; verification is unsigned by default (local SHA-256 hash,
  recomputable under host compromise). No PKI/key custody/revocation.

**On the obvious comparison (Microsoft AGT):** AGT is the structurally nearest
thing and it's good — open-source, fail-closed, framework-agnostic across 15+
runtimes, Merkle-chained audit with external inclusion proofs, broader framework
coverage than this project today. The difference is *receipt-centric vs
audit-centric*: per AGT's own docs, its chain is built for after-the-fact forensics
and it has no first-class decision receipt issued before execution. gove-zone's
narrower bet is exactly that artifact. It's a contrast by evidence, not a knock —
they could even compose. (More in the comparison doc.)

**The point is you don't take the headline on trust.** There's a proof pack you run
in one command (six conformance checks → `status: pass`) and a tamper demo where
you edit a receipt and watch it fail closed.

```bash
uv run --extra crypto --package gove-zone gove-zone proofpack    # → {"status":"pass", ...}
uv run --package gove-zone python examples/tamper_demo/demo.py
```

I'd genuinely like to know where this framing is wrong — especially from people
running agents against real infrastructure. Claim ledger, comparison, and FAQ are
all in the repo.
