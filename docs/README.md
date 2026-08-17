# ACGS documentation index

ACGS is a governed agent infrastructure project. Its core enforcement kernel is `gove-zone` (`packages/gove-zone`): a vendor-neutral, receipt-gated governance layer for AI-agent side effects. The kernel sits at the executor boundary below any agent framework, enforces policy before execution, emits a verifiable Decision Receipt, and makes executors fail closed without a valid receipt.

Other packages in this repository — the control plane, adapters, evaluation and policy tooling — are separate components with their own maturity levels. They are not part of the enforcement boundary and do not inherit the kernel's guarantees.

Core invariant: **No valid Decision Receipt, no side effect.**

This file is the canonical documentation index. There is deliberately no separate `docs/INDEX.md` — a second index would drift against this one.

## Best entry points

- [START_HERE](START_HERE.md) — 10-minute path.
- [PROOF_PATH](PROOF_PATH.md) — canonical proof narrative.
- [HUMAN_GUIDE](HUMAN_GUIDE.md) — evaluator/buyer/developer guide.
- [QUICKSTART](QUICKSTART.md) — copy-paste commands.
- [DEMO_SCRIPT](DEMO_SCRIPT.md) — five-minute demo.

## Technical contract

- [ARCHITECTURE](ARCHITECTURE.md)
- [DECISION_RECEIPT_SPEC](DECISION_RECEIPT_SPEC.md)
- [SECURITY_MODEL](SECURITY_MODEL.md)
- [INTEGRATION_GUIDE](INTEGRATION_GUIDE.md)
- [INTEGRATION_MATRIX](INTEGRATION_MATRIX.md) — supported runtimes by proof tier
- [COMPARISON](COMPARISON.md)

## Claim discipline and adoption

- [CLAIMS](CLAIMS.md)
- [POSITIONING](POSITIONING.md) — why a neutral governance layer is a category, not a feature
- [ROADMAP](ROADMAP.md) — the roadmap of record; superseded roadmaps/plans are frozen in [archive/](archive/README.md)
- [SaaS beta product requirements](saas/PRODUCT_REQUIREMENTS.md) — target contract, not an implementation claim
- [Assurance classes and provenance](saas/ASSURANCE_CLASSES.md) — native, federated, and observed evidence remain distinct
- [Open-core and local-safety boundary](saas/OPEN_CORE_BOUNDARY.md) — target entitlement boundary; not a license change
- [Proposed entitlement and metering matrix](saas/ENTITLEMENT_AND_METERING_MATRIX.md) — future contract; no current pricing or billing claim
- [SaaS beta target architecture](saas/ARCHITECTURE.md) — future three-plane and trust-boundary contract; not managed-service evidence
- [SaaS beta threat model](saas/THREAT_MODEL.md) — target STRIDE and agent-specific adversarial test contract
- [SaaS beta API and data contract](saas/API_AND_DATA_CONTRACT.md) — future /v1, BFF, scope, and provenance contract
- [SaaS beta migration and compatibility policy](saas/MIGRATION_VERSIONING_COMPATIBILITY_POLICY.md) — future Alembic, recovery, and artifact-compatibility requirements
- [Proposed SaaS build-vs-buy ADR packet](adr/saas-identity-oidc-saml-scim-build-vs-buy.md) — owner/counsel-gated identity, key, retention, witness, billing, and licensing decisions
- [VERSIONING](VERSIONING.md) — per-package version sources of truth; the `gove-zone` kernel line (`1.0.0rc1`/Beta) and the ACGS artifact line (`0.1.0`/alpha) are intentionally different levels
- [DOC_REFERENCE_POLICY](DOC_REFERENCE_POLICY.md) — how one document may cite another; cite by stable anchor, never by line number
- [GLOSSARY](GLOSSARY.md)
- [REVIEW_CHECKLIST](REVIEW_CHECKLIST.md)
- [ADOPTION_GUIDE](ADOPTION_GUIDE.md)

## Release and packaging

- [gove-zone release readiness](gove-zone-pypi-readiness.md) — current
  evidence, blockers, and external checks for the Python distribution.
- [gove-zone release runbook](../packages/gove-zone/docs/RELEASING.md) —
  human-gated preparation, tagging, publication, verification, and recovery.
- [gove-zone changelog](../packages/gove-zone/CHANGELOG.md) — notable package
  changes by version.
- [gove-zone API stability](../packages/gove-zone/docs/API_STABILITY.md) —
  SemVer surface and compatibility contract.

The checked-in source version, a GitHub Release, a PyPI publication, and
production deployment evidence are separate states. Verify each independently.

## Existing reference areas

- `concepts/` — authority, decision receipts, evidence bundles, fail-closed enforcement, audit replay, tool boundaries.
- `reference/` — API, CLI, policy schema, receipt schema.
- `hooks-or-runtime/` — runtime hook configuration and reference.
- `mcp/` — MCP overview, quickstart, examples.
- `adr/` — architecture decisions.
- `troubleshooting/` — common issues and security/privacy notes.

## Claim boundary

Local receipts, smoke tests, and lint output are readiness evidence. They are not production deployment proof or compliance certification unless matching live/external evidence is present.
