> **Internal engineering document.** Not part of the public release artifact.

# Pricing Model — ACGS / gove-zone

Status: **internal pricing draft — no public price list exists and nothing is
currently sold.** Numbers below are proposed anchors for design-partner
conversations, not commitments. The open-source core stays open; monetization
follows the open-core path in [`docs/PRODUCT_STRATEGY.md`](../PRODUCT_STRATEGY.md)
§7: developers adopt free, platform teams standardize, compliance buyers pay
for evidence operations, multi-tenancy, and audit-facing support.

## Value metric

Price on the **governed surface**, not on model tokens or seats: the number of
governed side-effect paths (wired gates) and the evidence-retention/ops burden.
This tracks the product's North Star (governed side-effecting operations per
week) and avoids taxing adoption of the free kernel.

## Tier summary

| | **Starter** | **Enterprise** | **Regulated Industry** |
|---|---|---|---|
| Price anchor (proposed) | **$0** (Apache-2.0 open source) | **$30k–$80k/yr** platform license + support | **$100k–$250k/yr** program (license + compliance evidence services) |
| Who | Individual teams, self-hosters, pilots | Platform/infra teams standardizing the gate across many agent teams | Finance / health / legal teams whose agents act under audit and regulator pressure |
| Kernel & receipts | Full — the invariant is never paywalled | Full | Full |
| Deployment | Self-hosted (on-prem / private cloud) | Self-hosted; managed evidence store option when it ships (roadmap) | On-prem / air-gapped; hardened profile deployment |
| Signing & anti-replay | Included (bring your own keys) | Included + key-custody runbook assistance | Included + custody/rotation procedure review |
| Tenancy | Single team | Multi-tenant policy administration (`TenantPolicyStore`) at scale | Multi-tenant + per-tenant evidence segregation |
| Evidence ops | Local proof packs, community docs | Proof-pack workflow integration, SIEM/alerting wiring support | Auditor-facing package: proof-pack handoff runbooks, offline-verifier training for the customer's auditors, compliance-crosswalk workshops |
| Integration support | Community | Named-runtime adapter support per the integration matrix; dispatcher-level wiring-test templates | Everything in Enterprise + one governed pilot path built jointly (design-partner motion) |
| Support / SLA | None (GitHub issues) | Business-hours support, upgrade guidance | Priority support; security-advisory notification; incident-evidence assistance |
| Compliance artifacts | Public docs | `COMPLIANCE_CROSSWALK.md` walkthrough | Framework-specific crosswalk workshops (NIST AI RMF / CSF 2.0 / ATLAS / OWASP), audit-season assistance — **explicitly self-assessment support, not certification** |

## Tier rationale

### Starter — $0, deliberately

The kernel is the moat's distribution engine, not the revenue line. Zero runtime
dependencies + self-hosting means the security-sensitive buyer can adopt without
procurement, which is exactly how S1 evaluation starts. Paywalling enforcement
would also corrupt the trust story: the fail-closed invariant must be
inspectable by everyone who relies on it.

**Includes everything enforcement-related, forever:** receipt gate, signing,
consumption ledger, audit chain, replay, proof packs, CLI, MCP gateway (alpha).

### Enterprise — sell standardization, not features

The buyer is the platform team (S2) tired of every agent team writing its own
checks. What they pay for is *operational leverage*: multi-tenant policy
administration, wiring-test templates that close the "installed but not wired"
gap, SIEM integration, named-runtime support, and someone to call. License
scales with governed paths / tenant count, not seats.

### Regulated Industry — sell evidence operations

The buyer is a compliance owner (S3) who must show a regulator or customer that
agent actions were authorized. What they pay for is the *audit-facing program*
around the artifacts: proof-pack handoff procedures, training the customer's
auditors on offline verification (`gove-zone verify-proofpack` — the auditor
needs no trust in the operator), crosswalk workshops mapping controls to their
framework of record, hardened-profile deployment review, and audit-season
support. `clinicalguard` is the clinical-domain proof point for this motion.

**Red line for this tier's marketing:** we sell evidence and mappings, never
"compliance." ACGS is not certified, not regulator-approved, and adopting it
does not make a customer compliant (`docs/CLAIMS.md` rows 28–30;
`COMPLIANCE_CROSSWALK.md` disclaimer). Any rep or doc that blurs this is a P0
claim-discipline violation.

## Future revenue lines (roadmap-dependent, not priced)

- **Managed evidence store** (SaaS tier prerequisite): WORM-backed hosted audit
  retention with SLAs — the natural per-GB/per-retention-year metered line.
- **Signed policy-bundle registry** with lifecycle management.
- **Attestation/transparency add-ons** once ADV3/ADV7 roadmap items ship.

## Open questions before any public price

1. Design-partner validation of the anchors (H5 experiment in
   `PRODUCT_STRATEGY.md`: measure paid-intent among self-hosting users).
2. License scaling unit: governed paths vs tenants vs both — needs 3–5 real
   deployments to calibrate.
3. Whether Regulated Industry is a tier or a services attach on Enterprise —
   depends on how repeatable the audit-facing program proves to be.
