<!--
  PUBLISH-READY EXTERNAL VERSION (Dev.to / Medium / 知乎).
  Reviewer note (does NOT render on Dev.to — HTML comment):
    - Human claim-safety sign-off REQUIRED before flipping `published: true`.
    - All capability lines are bound to docs/CLAIMS.md safe wording.
    - For Medium: delete the front-matter block, paste body, set canonical link
      to https://acgs.ai/docs in Story settings.
    - For 知乎: delete front matter, translate to 中文, keep the "alpha / not
      certified" paragraph intact.
-->
---
title: "Guardrails decide what an AI agent says. Receipts decide what it did."
published: false
description: "AI-agent governance is now a crowded word. Two distinctions — receipts vs guardrails, and receipts vs audit logs — separate perimeter policy from verifiable execution legitimacy."
tags: ai, security, opensource, llm
canonical_url: https://acgs.ai/docs
---

In the last few months the AI-agent safety conversation moved. It used to be
about the model — prompts, refusals, classifiers. Now the industry is naming a
different layer out loud. The Cloud Security Alliance is writing about going
"from guardrails to governance" and the need for a *control layer*. Microsoft
shipped an open-source Agent Governance Toolkit for runtime policy enforcement.
Galileo announced an open-source "control plane for AI agents." Gartner is
warning that ~40% of enterprises will pull autonomous agents back, and Deloitte
puts mature agentic governance at ~21% of organizations. And there is a clock on
it: the EU AI Act's high-risk obligations apply from **August 2, 2026**, with
Article 12 requiring automatic event logging over a system's lifetime.

That is the market [`gove-zone`](https://github.com/dislovelhl/ACGS) was built
for. But "governance" is now a crowded word, and most of the new entrants govern
the *perimeter* — what an agent is allowed to attempt. `gove-zone` governs
something narrower and harder: **whether a specific side effect was legitimate,
with evidence you can verify afterward.**

Two distinctions make the difference concrete.

## Distinction 1 — Guardrails moderate the message. Receipts gate the action.

A guardrail sits on the model's output. It shapes, filters, or blocks *text*:
the prompt, the structured response, the tool *request*. That is genuinely
useful, and it is the right tool for "don't say that." But it lives on the wrong
side of the line for "don't *do* that." By the time a `tools/call` leaves the
model, the interesting question is no longer what the model intended — it is
whether *this exact actor* may run *this exact action* with *these exact
arguments* under *this exact policy evidence*.

`gove-zone` answers that question at the executor boundary, not the prompt.
In its own framing: **guardrails moderate content; ACGS enforces execution
legitimacy.** The governed executor fails closed without a valid receipt, and a
receipt binds the actor, the action, and the exact arguments the executor checks.

A worked example from the
[Decision Receipt spec](https://github.com/dislovelhl/ACGS/blob/master/docs/DECISION_RECEIPT_SPEC.md):
a receipt issued for `{"path":"/tmp/safe.txt","content":"ok"}` will not
authorize `{"path":"/etc/shadow","content":"pwned"}`. Same action name,
different arguments — the gate catches it as an argument mismatch *before* any
side effect. A guardrail watching the model's text has no equivalent move,
because the substitution can happen anywhere between the request and the syscall.

The two are complementary, not rivals. A real stack runs both: guardrails for
what the agent says, receipts for what it is permitted to do.

## Distinction 2 — An audit log is a narrative. A Decision Receipt is a gate.

The usual answer to agent accountability is logging: let the action run, write
a line, reconstruct later. The EU AI Act's Article 12 even mandates it. But a
log is a *story told after the fact*. It cannot stop anything, and if it is
mutable it cannot even prove what happened. The recurring industry phrase right
now — "you need an audit trail before August 2, and the part most teams haven't
built is the *verifiable* part" — is pointing at exactly this gap.

A Decision Receipt closes it by collapsing two systems into one object:

- **The receipt is the gate**, evaluated *before* the side effect — so the audit
  artifact and the enforcement decision are the same thing, not two systems that
  drift apart.
- **The audit chain is tamper-evident**: local audit events are hash-chained,
  and corrupting an entry breaks verification.
- **Decisions are replayable** when raw call context is retained: replay
  helpers can re-derive the decision, while the audit chain alone proves
  tamper evidence and policy-version continuity.
- For higher-assurance contexts, **opt-in Ed25519 signing** makes authority
  cryptographically attributable rather than merely recorded.

The slogan version: logs observe; receipts gate and audit. You do not get to ask
a log to refuse an action. You can ask a receipt.

## Where this sits next to the new "governance" tools

The honest framing is *combine, don't replace*. Perimeter policy engines,
MCP-transport wrappers, IAM, sandboxing, content guardrails, and SIEM/WORM
retention each own a real job. `gove-zone` is the **execution-legitimacy layer**
underneath them: it binds the actor, action, arguments, policy, validator,
authority, receipt, and audit evidence to one decision, and it fails closed. It
does not authenticate principals (that is IAM), it does not contain execution
(that is sandboxing), and it does not moderate model text (that is guardrails).
It proves a specific side-effect decision.

So when a team adopts Microsoft's toolkit or a control-plane product for
perimeter policy, the open question that remains is: *when the action actually
runs, is there a verifiable receipt binding it to the authority that allowed
it?* That is the slot `gove-zone` fills.

## The honest boundary

Honesty is part of the design, so this is not a footnote. `gove-zone` is
**alpha** (`0.1.0.dev0`). Everything above is real, locally reproducible
engineering evidence — not a maturity claim. Per the repository's own
[claim ledger](https://github.com/dislovelhl/ACGS/blob/master/docs/CLAIMS.md),
this project is **not** production-certified, **not** compliance-certified, and
**not** regulator-approved. It is a local kernel, not a managed production
service. Signing mode is opt-in and assumes integrator-owned identity and key
management. The Aug 2 deadline is a reason to *build the proof layer now*; it is
not a certificate `gove-zone` can issue.

## See it gate something

```bash
tmp=$(mktemp -d) && uv run --package gove-zone gove-zone smoke --audit "$tmp/audit.jsonl"
uv run --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py
uv run --package gove-zone python examples/tamper_demo/demo.py
```

A safe `write_file` is allowed; an `id_rsa` write is denied *before any side
effect*; both decisions verify as a hash-linked chain — and tampering with the
evidence makes verification fail.

---

*The category is forming around "control layer" and "verifiable audit trail."
`gove-zone`'s bet is that the unit of control should be a receipt you can check,
expire, sign, and replay — not a policy you hope held and a log you hope is
true. Clone it, run the proof path, and try to make it fail open:
[github.com/dislovelhl/ACGS](https://github.com/dislovelhl/ACGS).*
