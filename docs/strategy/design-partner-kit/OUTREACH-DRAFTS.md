# Outreach drafts — design partners (n=3) + external auditor (n=1)

**Status:** drafts for human review and send. Nothing here has been sent.
Sending is a human action; these exist so the send takes minutes, not hours.
Every technical claim below is already substantiated in the kit
([`ONE-PAGER.md`](ONE-PAGER.md), [`DEMO-RUNBOOK.md`](DEMO-RUNBOOK.md),
[`ONBOARDING.md`](ONBOARDING.md), [`PILOT-OFFER.md`](PILOT-OFFER.md)) or the
auditor packet ([`../auditor-validation/BRIEF.md`](../auditor-validation/BRIEF.md))
— do not add claims while personalizing.

Replace `[NAME]`, `[COMPANY]`, `[SPECIFIC]` before sending. One email per
segment, matched to the three audiences the one-pager targets. Keep subject
lines under ~60 chars. No attachment on first touch — link or paste-on-reply.
Every draft carries the alpha / not-certified boundary; do not delete it to
make the pitch cleaner — that boundary is why the technical audience trusts
the rest.

---

## Partner draft 1 — offensive-security tooling team

**Subject:** provable scope limits for autonomous pentest agents

Hi [NAME],

Short version: we built an execution gate that makes an autonomous pentest
agent *provably unable* to act out of scope — and we're looking for one
security-agent team to run it fail-closed in a real pipeline as a design
partner.

The mechanism: before any side-effectful tool call (scan, exploit, execute)
runs, policy is evaluated and the decision is bound into a hash-chained,
optionally Ed25519-signed Decision Receipt. No valid receipt, no side effect —
and DENY/ESCALATE receipts are non-executable. When your risk function asks
"prove this agent could not have hit an out-of-scope host," you hand them a
verifiable receipt chain instead of a log grep.

It sits below any framework at the tool-dispatch boundary, has zero runtime
dependencies, and runs in your own process — no data leaves your boundary for
the decision. Apache-2.0 kernel; you keep everything.

Honest boundary: this is alpha, not compliance-certified, and our shipped
demo governs a *mock* pentest tool (it proves the gate's allow/deny/receipt/
tamper behavior against the real API, it doesn't attack live hosts). I'd rather
you know that before the call than after.

If it's useful: a 30-min call, I run the demo live, and if the invariant lands
we scope one of your pipelines (target: first governed call under an hour).
Worth 30 minutes?

[NAME]

---

## Partner draft 2 — infra / platform automation team

**Subject:** a receipt your auditor accepts instead of a log grep

Hi [NAME],

Your automation agents can already call `write_file`, `http_post`, `db_exec`,
`python_execute`. The gap most teams have: those side effects are *audited
after they run*. A log records what happened; it does not prove what was
authorized, and it can be edited.

We built a governance kernel that flips the order — policy is evaluated and a
Decision Receipt is issued **before** the executor runs the side effect, and
the executor fails closed without a valid one. Every decision (including
denials) lands in a tamper-evident hash chain that a third party can verify
offline. Zero runtime deps, Apache-2.0, runs in-process.

We're taking on a small number (n=3) of design partners: one real pipeline of
yours wired through the gate, running fail-closed, with policy bundles authored
for your tool surface and an auditor-ready proof pack of your first receipts.
Short bounded engagement, you keep the kernel + receipts + audit chain.

Boundary up front: alpha, not production/compliance-certified — an
evidence-generation mechanism you'd be piloting, not a certified control.

30-min call to run the demo and see if the invariant fits your stack?

[NAME]

---

## Partner draft 3 — fintech / health ops team (high-blast-radius)

**Subject:** pre-execution authorization evidence for agent actions

Hi [NAME],

In a regulated ops environment, an agent that takes an irreversible action
(moves money, touches a record) without provable authorization is an incident,
not a bug. Most agent stacks can only tell you what happened after the fact.

gove-zone is an execution membrane below your agent framework: policy
evaluated before the side effect, decision bound into a hash-chained
(optionally signed) Decision Receipt, executor fails closed without one. The
decision is free and open-source (Apache-2.0, zero deps, in-process — no data
egress); what we'd help with in a pilot is turning those receipts into
auditor-grade evidence your compliance function will actually accept.

Explicit boundary: alpha, not compliance-certified, not regulator-approved.
We produce evidence mechanisms, not certifications — worth stating plainly
because your world takes that distinction seriously.

If provable-before-execution authorization is a problem you have, 30 minutes
and a live demo will tell us both whether it fits. Open to it?

[NAME]

---

## Auditor draft — external GRC / audit reviewer

**Subject:** requesting an assessment: are pre-execution decision receipts control evidence?

Hi [NAME],

I'm looking for a professional GRC/audit reviewer to answer one question from
artifacts — not to endorse a product:

> Is a pre-execution Decision Receipt — a hash-bound, optionally Ed25519-signed
> record that a specific agent action was evaluated against a specific policy
> *before* it executed, verifiable offline by a third party — acceptable
> control evidence where a post-hoc application log would not be?

We've assembled a proof pack (receipts + hash-chained audit log + a standalone
offline verifier) and a step-by-step verification walkthrough so you can reach
your own verdict from the artifacts, without running or trusting our runtime.
The brief maps every claim to code and to the exact command that demonstrates
it.

This is a request for assessment, not a sale. Negative findings are as
valuable to us as positive ones, and we intend to publish your assessment
claim-safely — attributed or anonymized, your choice. Status is stated up
front throughout: alpha, not production/compliance-certified.

Would you be willing to review the packet? I can send the brief
(`BRIEF.md` + `REVIEW-CHECKLIST.md`) and we can scope the time from there.

[NAME]

---

## Send tracking (fill on send)

| Segment | Target | Sent (date) | Replied | Ran demo / packet | Scorecard ≥3 | Next |
|---|---|---|---|---|---|---|
| Offensive-security | `[COMPANY]` | | | | | |
| Infra/platform | `[COMPANY]` | | | | | |
| Fintech/health ops | `[COMPANY]` | | | | | |
| External auditor | `[NAME]` | | | | | |

Log demo-call outcomes against the conversion-intent scorecard in
[`PILOT-OFFER.md`](PILOT-OFFER.md); the aggregate is the startup-canvas
experiment result (validation, not vanity metrics).
