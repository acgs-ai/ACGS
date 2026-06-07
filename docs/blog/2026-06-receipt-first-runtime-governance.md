# Receipt-first runtime governance: why fail-closed belongs *below* the agent

> **DRAFT — not yet published.** Claim-safety review required before posting to
> Dev.to / Medium / 知乎. Every capability statement here is bound to the
> "What is implemented now" table in the repo [`README.md`](../../README.md).
> A 中文版 translation is tracked as a good-first-issue in
> [`CONTRIBUTING.md`](../../CONTRIBUTING.md).

---

Most "AI agent safety" stories are about the model: better prompts, better
refusals, better classifiers. Those matter. But they all live *above* the line
where something actually happens — the moment an agent stops talking and a tool
writes a file, posts to an API, runs SQL, sends money, or deploys.

That moment is where `gove-zone` operates. It is not another agent framework.
It is the enforcement membrane an agent, MCP tool, workflow engine, or CI runner
calls **before** it acts.

The whole design collapses to one invariant:

> **No valid Decision Receipt, no side effect.**

This post argues *why* that shape — receipt-first, fail-closed — is the right
one for high-risk agent actions, and is honest about what the current alpha does
and does not prove.

## The problem: agents request power faster than teams can prove authority

A modern agent can decide to call `write_file`, `http_post`, `db_exec`, or a
deploy tool in a single reasoning step. The natural-language layer is fluent and
fast. The "is this allowed?" layer — authority, policy, auditability, replay —
is slow, human, and usually bolted on *after* an incident.

The common failure isn't "the model said something bad." It's "the model
*requested an action*, and nothing between the request and the side effect had
the authority — or the evidence — to stop it."

Prompt-level guardrails can't close this, because they sit on the wrong side of
the line. By the time a tool call leaves the model, the interesting question is
no longer "what did the model intend?" but **"is this exact actor allowed to run
this exact action with these exact arguments under this exact policy
evidence?"**

## The shape: decide, bind, prove — then maybe execute

`gove-zone` answers that question with three moves, in order.

**1. Policy before execution.** The kernel dispatches the requested action
through policy *first*. The decision is one of allow / deny / escalate, and
`DENY`/`ESCALATE` are never executable. (`kernel.py`; `test_fail_closed.py`.)

**2. A Decision Receipt as the unit of authority.** An allowed action produces a
verifiable Decision Receipt that binds the actor, the action, the arguments, and
the policy evidence together. The receipt — not the model's confidence — is what
the executor checks. (`receipt.py`; the receipt-gated executor in `executor.py`,
`test_executor_guard.py`; binding tests `test_argument_binding.py`,
`test_tenant_safety.py`, `test_receipt_expiry.py`.)

**3. Fail closed by default.** A missing, denied, tampered, or mismatched
receipt does not "warn and continue." It blocks the side effect. The default
posture is refusal; execution is the exception that requires proof.

This is the inversion that matters. Most systems are open by default and add
denials. A governance membrane has to be **closed by default and add
permissions** — each permission carried by a receipt that can be checked,
expired, and replayed.

## Why "receipt-first" beats "log-after"

Logging is the usual answer to agent accountability: let the action happen, write
an audit line, reconstruct later. The problem is that the log is a *narrative*,
not a *gate*. It can't stop anything, and if it's mutable it can't even prove
what happened.

Receipt-first flips both:

- The receipt is the **gate**, evaluated before the side effect — so the audit
  artifact and the enforcement decision are the *same object*, not two systems
  that can drift.
- The audit chain is **tamper-evident**: decisions are hash-linked, and
  corrupting an entry breaks verification. (`audit.py`; `test_audit_chain.py`,
  `test_audit_chain_corruption.py`.)
- Decisions are **replayable** where the raw call context is retained, so "what
  was allowed, and on what evidence?" is verifiable.
  (`replay.py`; `test_replay.py`.)

For higher-assurance contexts, receipts can be **signed** with opt-in Ed25519,
so authority is cryptographically attributable rather than merely recorded.
(`signing.py`; `test_receipt_signing.py`.)

## Where it sits in a real stack

`gove-zone` is deliberately small and below the orchestration layer. It exposes
adapter *shapes* for runtime hooks, MCP `tools/call`, and function-call-style
payloads, so the governance gate can be inserted without rewriting the agent.
(`integration.py`; `test_integration_hook.py`, `test_integration_gaps.py`.)
You keep your agent framework. ACGS just answers the narrower enforcement
question underneath it.

You can watch the whole thing work locally in about a minute:

```bash
tmp=$(mktemp -d) && uv run --package gove-zone gove-zone smoke --audit "$tmp/audit.jsonl"
uv run --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py
uv run --package gove-zone python examples/tamper_demo/demo.py
```

A safe `write_file` is allowed; an `id_rsa` write is denied *before any side
effect*; both decisions verify as a hash-linked chain — and tampering with the
evidence makes verification fail.

## What this is — and isn't

Honesty is part of the design, so the limitations are not a footnote.

`gove-zone` is **alpha** (`0.1.0.dev0`). The proofs above are real engineering
evidence run locally; they are **not** production deployment proof. Per the
repository's own claims boundary, this project is **not**:

- production-certified;
- compliance-certified;
- regulator-approved;
- a replacement for sandboxing;
- a replacement for content moderation;
- a complete IAM/PKI system;
- a full formal-verification system.

What it *is*: a small, fail-closed, receipt-first enforcement core with a
local, reproducible proof path — a foundation you can inspect and break yourself,
not a maturity claim you have to take on trust.

## The takeaway

If you only govern the model, you're governing intent. The side effect is where
risk becomes real, and that's the layer that should be **closed by default and
opened only by a receipt you can verify**. That's the bet `gove-zone` makes — and
the proof path is right there to falsify it.

---

*Want to try breaking it? Clone the repo, run the proof path, then tamper with a
receipt or an audit entry and watch it fail closed. Docs:
<https://acgs.ai/docs>. Contributions — especially new framework adapters and
policy examples — are in [`CONTRIBUTING.md`](../../CONTRIBUTING.md).*
