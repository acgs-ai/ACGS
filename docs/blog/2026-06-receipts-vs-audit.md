# Audit tells you what happened. A receipt decides what's allowed — and proves it.

> **DRAFT — not yet published.** Claim-safety review required before posting to
> Dev.to / Medium / 知乎 / HN. Every capability statement here is bound to the
> [`docs/CLAIMS.md`](../CLAIMS.md) ledger, the
> [`docs/COMPARISON.md`](../COMPARISON.md) table, and the "What is implemented
> now" section of the repo [`README.md`](../../README.md). Reconcile signing /
> verifier / ledger wording against CLAIMS.md before publishing — do **not**
> claim certified, regulator-approved, or production-ready. Market-context
> claims (EU AI Act, competitor posture) are external, dated snapshots.
> A 中文版 translation is tracked as a good-first-issue in
> [`CONTRIBUTING.md`](../../CONTRIBUTING.md).

---

## The line we just crossed

For two years, "AI safety" mostly meant governing **words**. Did the model say
something toxic, leak a secret, hallucinate a citation? Guardrails filtered text.
Logs recorded prompts. Dashboards turned red. (That perimeter story is its own
post — see [Guardrails decide what an agent *says*. Receipts decide what it
*did*.](./2026-06-receipts-vs-guardrails-positioning.md).)

This post is about a different default: **the log**.

Agents don't just talk now — they **act**. They call tools, hit APIs, move money,
modify records, provision infrastructure, send the email. The unit of risk is no
longer a sentence. It's a **side effect**. And the moment an agent can *do*
things, the governing question changes from *"what did it say?"* to a much harder
one:

> **Was this action allowed — by whom, under what policy — and can you prove it
> to someone who doesn't trust you?**

Most governance tooling cannot answer that. Not because it's badly built, but
because it was designed for the wrong posture.

## The default posture: audit-centric

Walk into almost any "AI governance" tool today and you'll find the same shape:
the action happens, and the system **records** it. A log line. An audit trail. A
dashboard. Maybe an alert.

Call this **audit-centric** governance. It has three structural properties, and
all three are problems:

**1. It acts after the fact.** By the time the audit log is written, the money
has moved. Observation is not control. A camera in a bank vault doesn't stop a
robbery; it describes one.

**2. It fails open.** If the logging path hiccups, the action *still runs* — you
just don't have a record of it. The safe-by-default behavior of an audit system
is to let things through. That is exactly backwards for high-consequence actions.

**3. It's evidence you produce about yourself.** An audit log is trustworthy only
to the degree you trust the system that wrote it. It can be edited, replayed,
dropped, or quietly never written. When a regulator, an insurer, or an incident
reviewer asks "prove this action was authorized," *"here's a log from the system
that took the action"* is a weak answer. You're asking them to take your word
for it.

Audit-centric governance answers **"what happened?"** It cannot answer **"was
this allowed, and can you prove it independently?"** For an autonomous agent
touching real systems, the second question is the only one that matters.

## The reframe: control vs. observation

There are really two postures, and the industry has conflated them:

| | **Observation** (audit-centric) | **Control** (receipt-centric) |
|---|---|---|
| Acts | *After* the action | *Before* the action |
| On failure | Fails **open** — action runs | Fails **closed** — action blocked |
| Produces | A log you must be trusted for | A **receipt anyone can verify** |
| Answers | "What happened?" | "Was this allowed, by whom, under what policy — provably?" |

The shift from the left column to the right is the same one the security industry
made decades ago: from *log the login* to *check the credential before granting
access*. We don't audit our way to authentication. We **gate** it. Autonomous
agents need the same move for their actions.

## What a Decision Receipt is

A **Decision Receipt** is a verifiable artifact, produced *before* a side effect
runs, that binds together:

- **The actor** — which agent/identity requested the action
- **The action** — what it's trying to do, with its exact serialized arguments
- **The policy** — the rule that allowed (or denied) it
- **The decision** — allow / deny / escalate
- **A signature** — so the receipt is tamper-evident

And the enforcing invariant is brutally simple:

> **No valid Decision Receipt, no side effect.**

The executor — the thing that actually does the work — refuses to run without a
valid receipt matching those exact parameters. Not "logs a warning." Refuses.
That's what *fail-closed* means in practice: the governance layer is in the
execution path, not beside it.

This inverts every property of the audit posture. It acts *before*, it fails
*closed*, and — critically — it produces evidence that **doesn't require trusting
the issuer**.

## The part that matters most: don't trust, verify

Here's the property that turns a receipt from "a nicer log" into a category
shift.

A Decision Receipt can be **verified independently and offline** — without
running, or trusting, the system that issued it. Hand the receipt to a third
party with a verifier and a public key, and they can confirm: this action, by
this actor, under this policy, was decided this way, and the receipt hasn't been
altered or replayed. (Audit events are additionally hash-chained, so editing one
past entry breaks chain verification; single-use enforcement rejects a replayed
receipt.)

That's the difference between *"trust our audit log"* and *"check the math
yourself."* It's the difference between a screenshot and a cryptographic proof.
For anyone whose job is to hold an AI system accountable — risk, compliance,
audit, insurance, the regulator — that distinction is everything.

Audit logs are evidence you produce about yourself.
**A Decision Receipt is evidence anyone can check.**

## "But we already have logging." "But our cloud has guardrails."

Two reasonable objections. Both miss the posture.

**"We log everything."** Logging is observation. It happens after the action and
it fails open. The question isn't whether you have records — it's whether
anything *stops* an unauthorized action, and whether your record survives someone
editing it. A log does neither.

**"Our cloud platform ships guardrails."** Those are mostly content filters —
excellent at stopping the model from *saying* something, not designed to emit a
portable, independently verifiable receipt for what the agent *does* across your
whole stack. Use them. Then put a receipt layer under your side effects. They're
complementary: guardrails govern the words, receipts govern the actions — and the
receipt is portable across clouds and frameworks, owned by you, not by any one
platform.

## What this means for the category

The regulatory wind is blowing the same direction. Emerging high-risk AI rules
are converging on *traceability* and *record-keeping* obligations — and a
tamper-evident, independently verifiable decision record is a far stronger answer
to those duties than a self-attested log. (The EU AI Act's logging provisions are
a reason to build this layer now — not a certificate anyone ships.) The market
hasn't named this yet, so it defaults to the weaker word it already knows:
*audit*.

That's the mistake. **Audit is the floor, not the goal.** The goal is *control
with proof.* As agents take on more consequential actions, "we recorded it" will
sound exactly as inadequate as "we logged the failed login but let them in
anyway."

The teams who get this early will stop asking *"how do we audit our agents?"* and
start asking *"how do we make sure no action runs without a receipt — and that
the receipt holds up when someone who doesn't trust us checks it?"*

That's not a feature request. It's a different posture. We call it
**receipt-centric governance**, and we think it's where this whole category is
going.

---

## Try it in about a minute

```bash
tmp=$(mktemp -d) && uv run --package gove-zone gove-zone smoke --audit "$tmp/audit.jsonl"
uv run --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py
uv run --package gove-zone python examples/tamper_demo/demo.py
```

A safe write is allowed; a sensitive write is denied *before* any side effect;
both decisions verify as a hash-linked chain; tampering with the evidence makes
verification fail.

*gove-zone is a receipt-gated, fail-closed governance layer for AI-agent side
effects: it enforces policy before execution, emits a verifiable Decision
Receipt, and refuses to act without one. The open library `acgs-lite` is on
PyPI. It is alpha and self-hosted — not a managed service, and not
compliance-certified.*
