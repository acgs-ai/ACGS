> **Internal engineering document.** Not part of the public release artifact.

# ACGS Productization Pack

> **Core invariant: No valid Decision Receipt, no side effect.**

This directory is the enterprise productization view of ACGS / gove-zone: how the
receipt-gated governance layer is packaged, deployed, sold, and onboarded.

**Status: internal product draft.** Nothing here is a certification, a shipped
managed service, or a public price list. Every technical claim inherits the
claim discipline of [`docs/CLAIMS.md`](../../CLAIMS.md); anything beyond current
code and tests is explicitly labeled *proposed* or *roadmap*. ACGS is not
production-certified, compliance-certified, or regulator-approved.

## Contents

| Doc | Deliverable |
|---|---|
| [01-enterprise-architecture.md](01-enterprise-architecture.md) | Enterprise architecture diagram and component responsibilities |
| [02-deployment-options.md](02-deployment-options.md) | Deployment options: SaaS, private cloud, on-premise, regulated environment |
| [03-customer-onboarding.md](03-customer-onboarding.md) | Customer onboarding flow, from install to auditor-ready proof pack |
| [04-api-documentation.md](04-api-documentation.md) | API documentation: Python API, CLI, receipt schema, MCP gateway |
| [05-security-whitepaper-outline.md](05-security-whitepaper-outline.md) | Security whitepaper outline |

Pricing and investor material are **not kept in this repository**. This repository
is public, so a directory name cannot make a document private. Those docs live in
the maintainers' private store.

## What ACGS is (one paragraph)

ACGS / gove-zone is the execution membrane between AI-agent reasoning and
real-world side effects. Before an executor runs a tool call, policy is
evaluated and a **Decision Receipt** is minted — a verifiable artifact binding
actor, action, exact arguments, tenant, execution boundary, policy bundle/hash,
validator, authority, expiry, and audit anchor. The governed executor fails
closed without a valid receipt. Evidence lands in a hash-chained, tamper-evident
audit log that supports replay verification and offline proof packs. It is not
an agent framework; agent frameworks sit above it, side-effectful tools sit
below it.

## Source-of-truth documents

Product docs here summarize; these govern:

- [`docs/ARCHITECTURE.md`](../../ARCHITECTURE.md) — runtime architecture
- [`docs/DECISION_RECEIPT_SPEC.md`](../../DECISION_RECEIPT_SPEC.md) — receipt format
- [`docs/SECURITY_MODEL.md`](../../SECURITY_MODEL.md) — threat table + adversary model (ADV1–ADV14)
- [`docs/CLAIMS.md`](../../CLAIMS.md) — the claim ledger (public wording rule)
- [`docs/INTEGRATION_MATRIX.md`](../../INTEGRATION_MATRIX.md) — per-runtime support tiers
- [`docs/COMPLIANCE_CROSSWALK.md`](../../COMPLIANCE_CROSSWALK.md) — NIST AI RMF / CSF 2.0 / ATLAS / OWASP mapping (self-assessment)
- [`docs/PRODUCT_STRATEGY.md`](../../PRODUCT_STRATEGY.md) — strategy canvas
