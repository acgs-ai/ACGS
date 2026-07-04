# gove-zone — Paid Pilot Offer (managed evidence)

**For:** the same audience as [`ONE-PAGER.md`](ONE-PAGER.md) — teams that ran the demo, saw the invariant hold, and now ask *"what does working with you cost?"*

**Status: Alpha (`0.1.0a1`). NOT production-certified, NOT compliance-certified.**
This document defines the **commercial shape** of a pilot. It is an offer
structure, not a rate card: every `[PRICE — founder decision]` marker below is
deliberately unset until the first three scoping conversations calibrate them.
Startup-canvas experiment #4 is the point of this doc: *offer a paid pilot of
managed evidence to OSS users and measure conversion intent.*

---

## Monetization principle (invariant for every tier)

> **The decision is free; durable, managed, auditor-grade evidence is paid.**

Fail-closed enforcement is never paywalled. The Apache-2.0 kernel — policy
gate, receipts, local audit chain, offline verifier, adapters — stays free
forever. What is paid is the work and infrastructure that turns receipts into
**evidence someone else will accept**: retention, packaging, integration, and
auditor-facing proof.

## What exists today vs. what is offered early

| | Exists today (verifiable in repo) | Offered in pilot |
|---|---|---|
| Enforcement kernel | ✅ Apache-2.0, zero runtime deps | free, forever |
| Signed receipts + hash chain + offline verifier | ✅ (`crypto` extra) | free, forever |
| Proof-pack packaging | ✅ CLI, verified fixtures | **Services** (we package + walk your auditor through it) |
| Policy bundles for your tools | authoring format ✅ | **Services** (we author for your pipeline) |
| Hosted console / managed ledger / managed signing keys | ❌ not built | **early-access design input only** — pilot captures intent, does not sell vaporware |

Anything in the right column marked "not built" is **never** invoiced as if it
ships. Pilots are honest about this or they poison the claim discipline.

## The offer: one pilot, two components

### 1. Integration engagement (fixed-fee, bounded)

The Services tier from the startup canvas, made concrete:

- **Scope:** one real external pipeline (security agent, MCP tool server, CI job) wired through the gove-zone gate, running fail-closed. Same scope boundary as the one-pager.
- **Deliverables:**
  1. Working governed dispatch in your pipeline (target: first governed call < 1 hour, per `ONBOARDING.md`).
  2. Policy bundle authored for your tool surface (allow/deny/escalate rules you review line-by-line).
  3. **Auditor-ready proof pack** of your first N days of receipts — packaged, offline-verifiable, with a walkthrough for your risk function.
  4. Written integration report (what is governed, what is not, residual gaps — claim-safe).
- **Duration:** 2–4 weeks calendar, bounded effort.
- **Price:** `[PRICE — founder decision: fixed fee; calibrate against first 3 scoping calls]`
- **Exit:** you keep everything — kernel, receipts, audit chain, policy bundles, proof pack. No lock-in artifact anywhere in the engagement.

### 2. Managed-evidence early access (intent capture, not invoice)

The Team-tier hypothesis (hosted receipt ledger with retention, managed
signing keys, console) is **not built**. The pilot prices the *commitment*,
not the product:

- Pilot partners get: design-input seat on ledger/console/spec surface, first-in-line onboarding when the managed tier exists, locked early-adopter terms.
- We measure (this IS canvas experiment #4): would you pay for managed retention rather than self-hosting JSONL? At what receipt volume? What retention window does your risk function require?
- **Pricing shape to validate** (from the canvas, per-month): platform fee + usage on receipts/month. `[PRICE — founder decision: publish indicative bands only after ≥3 intent data points]`

## Qualification (who we say no to)

- No real pipeline with side-effectful tools → not yet; run the OSS demo instead.
- Wants a compliance certificate → no. We produce evidence mechanisms, not certifications (see honest-disclosure in the one-pager).
- Wants us to orchestrate their agents → no. Neutrality is the position; gove-zone never orchestrates.

## Conversion-intent scorecard (fill per prospect)

| Signal | Value |
|---|---|
| Ran `gove-zone smoke` themselves before the call | yes / no |
| Named a concrete pipeline + tool list | yes / no |
| Risk/compliance function exists and asked for proof | yes / no |
| Reacted to fixed-fee number with scoping questions (vs. silence) | yes / no |
| Stated a receipt volume + retention need unprompted | yes / no |

≥3 yes → schedule scoping. Log every scorecard (dated) next to this file; the
aggregate is the experiment result the canvas asks for.

## Next step

Same as the one-pager: 30-minute call → live demo → scope one pipeline. This
doc enters the conversation only **after** the invariant lands technically.
