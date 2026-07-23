> **Internal engineering document.** Not part of the public release artifact.

# Investor Technical Brief — ACGS / gove-zone

> **Core invariant: No valid Decision Receipt, no side effect.**

Status: **investor-facing synthesis, not an offering.** This document consolidates
the technical and product material already in this repository into a narrative for
technical diligence. It raises no new claims: every technical assertion inherits
the discipline of [`docs/CLAIMS.md`](../CLAIMS.md), and anything beyond current
code and tests is labeled *proposed* or *roadmap*. ACGS is early-stage
(`gove-zone` reports `0.1.0.dev0`, badge: alpha). It is **not** production-certified,
compliance-certified, or regulator-approved. Financial figures are proposed
design-partner anchors from [`06-pricing-model.md`](06-pricing-model.md), not
bookings, revenue, or commitments.

This brief summarizes; the source-of-truth documents govern. Read them for detail:
[`docs/ARCHITECTURE.md`](../ARCHITECTURE.md),
[`docs/SECURITY_MODEL.md`](../SECURITY_MODEL.md),
[`docs/COMPARISON.md`](../COMPARISON.md),
[`docs/PRODUCT_STRATEGY.md`](../PRODUCT_STRATEGY.md),
[`docs/ROADMAP.md`](../ROADMAP.md).

---

## 1. The problem

Enterprise software is moving from *human → software* to *human → AI agent → tools
→ real-world side effect*. Agents now write files, call APIs, move money, change
infrastructure, file documents, and trigger deployments. The load-bearing question
shifts from "can the model produce a good answer?" to a narrower, auditable one:

> **Was this exact actor authorized to run this exact action, with these exact
> arguments, under this exact policy — and can we prove it later?**

Most of the agent stack today cannot answer that. It answers *"can the action
happen?"* (orchestration) or *"what happened?"* (after-the-fact logs). Neither
proves the action was legitimate before it ran.

## 2. What ACGS is

ACGS / gove-zone is a **vendor-neutral, receipt-gated execution membrane** that
sits below any agent framework and above side-effectful tools. Before an executor
runs a tool call, policy is evaluated and a **Decision Receipt** is minted — a
verifiable artifact binding actor, action, exact arguments, tenant, execution
boundary, policy bundle and hash, validator, authority, expiry, and an audit
anchor. The governed executor **fails closed** without a valid receipt. Evidence
lands in a hash-chained, tamper-evident audit log that supports replay
verification and offline proof packs.

It is deliberately *not* an agent framework and not owned by one. Frameworks sit
above it; tools sit below it. See [`01-enterprise-architecture.md`](01-enterprise-architecture.md).

## 3. Why this is defensible — receipt-centric vs audit-centric

The distinctive technical choice (from [`docs/COMPARISON.md`](../COMPARISON.md)) is
*where the gate runs relative to the side effect*:

| Posture | Acts… | You get | Example |
|---|---|---|---|
| Ungoverned | agent → tool directly | speed, zero accountability | raw MCP, vanilla LangGraph |
| Audit-centric | logs *after* the action | a trail you read after harm | Microsoft Agent Governance Toolkit |
| **Receipt-centric (ACGS)** | gates *before* the action | every action carries a verifiable, single-use receipt; fail-closed | gove-zone |

The nearest well-resourced competitor, Microsoft's Agent Governance Toolkit, is
audit-centric — it records after the fact. ACGS's wager is that regulated and
high-risk teams need the *before* gate, and that a vendor-neutral receipt format
that describes a governed action regardless of which framework issued it is more
durable than any single framework's built-in checks. The moat today is
**architectural correctness plus early trust**, not brand or distribution (see §7).

## 4. Market — defined by problem, not demographic

From [`docs/PRODUCT_STRATEGY.md`](../PRODUCT_STRATEGY.md) §2:

- **S1 (beachhead): regulated / high-risk teams building agentic products** —
  finance, healthcare, legal tooling. They have real pain (consequential
  execution + audit pressure), budget, and the highest tolerance for the
  "inconvenience" of fail-closed — which is exactly where ACGS is strongest and
  audit-centric incumbents are weakest.
- **S2: platform / infrastructure teams** — one standardized side-effect gate
  instead of every agent team writing its own checks.
- **S3: compliance / governance owners** (buyer, not user) — need to *prove* to a
  regulator or customer that agent actions were controlled.

## 5. Business model — open-core, priced on governed surface

From [`06-pricing-model.md`](06-pricing-model.md). The enforcement core stays
Apache-2.0 and free forever (paywalling the fail-closed invariant would corrupt
the trust story and block security-sensitive adoption). Revenue comes from
operational leverage and evidence operations:

| Tier | Proposed anchor | Sells |
|---|---|---|
| Starter | $0 (open source) | the full kernel, receipts, signing, audit, replay, proof packs |
| Enterprise | $30k–$80k/yr *(proposed)* | multi-tenant policy admin, wiring-test templates, SIEM, named-runtime support |
| Regulated Industry | $100k–$250k/yr *(proposed)* | auditor-facing evidence program, hardened deployment, crosswalk workshops (self-assessment, **not** certification) |

The value metric is the **governed surface** (wired gates / governed side-effect
paths), tracking the North Star — *governed side-effecting operations per week* —
rather than taxing adoption via seats or tokens.

## 6. Traction and evidence (what is actually built)

ACGS is alpha, but the core membrane is implemented and test-backed, not
vaporware. Concrete, inspectable evidence in this repo:

- **Working kernel** — policy evaluation, receipt minting, fail-closed executor,
  hash-chained audit, replay, single-use consumption ledger, offline proof packs
  and verifier, and a CLI. Zero runtime dependencies (stdlib + optional crypto
  extra).
- **A governed-agent case study that runs** — the VulnClaw pentest-agent demo
  (`packages/gove-zone/examples/governed_vulnclaw_demo.py`,
  [`docs/design/governance-vulnclaw-pentest.md`](../design/governance-vulnclaw-pentest.md))
  governs a highly privileged agent's scan/exploit/exec/report actions through
  the membrane. Regulated-industry demos (AML screening, legal drafting/discovery)
  extend this pattern — *in progress*.
- **A governance capability benchmark** — `acgs_benchmark` (100 scenarios, 6
  categories, 0–100 Governance Score) that discriminates a governed reference from
  ungoverned baselines.
- **Self-assessment crosswalk** — [`docs/COMPLIANCE_CROSSWALK.md`](../COMPLIANCE_CROSSWALK.md)
  maps controls to NIST AI RMF / CSF 2.0 / MITRE ATLAS / OWASP (explicitly
  self-assessment, not certification).
- **Documented threat model** — [`docs/SECURITY_MODEL.md`](../SECURITY_MODEL.md)
  enumerates adversary cases ADV1–ADV14 with the corresponding defenses.

## 7. Risks (stated plainly)

The strategy canvas names these as the assumptions that must hold, and the honest
weaknesses:

- **Distribution is the weak axis.** Brand and reach are far below Microsoft's.
  §7 (growth) depends on distribution while §9 admits it is a weakness — the
  first-stage hedge is undeniable S1 integration evidence, not marketing.
- **Thin domain landing evidence.** The regulated-industry proof needs real design
  partners, not just demos.
- **No external certification yet.** The compliance story is self-assessment;
  audit/certification is a program to run, not a claim to make.
- **Category timing.** "Agent accountability" as a purchased layer is an emerging,
  not established, budget line.

## 8. The thesis

Three waves: (1) LLM adoption, (2) agent deployment, (3) **agent accountability**.
Waves 1 and 2 are underway. ACGS targets wave 3: as agents take consequential
actions, the enterprise question becomes provable authorization, and a
vendor-neutral, receipt-centric membrane is positioned to be for AI-agent side
effects what IAM became for human/service access — an infrastructure layer, not a
feature. The bet is early: the moat is correctness and trust now, converted into
defensibility through real regulated-industry integration evidence.

---

*For the underlying product and technical documents, start at
[`README.md`](README.md) in this directory.*
