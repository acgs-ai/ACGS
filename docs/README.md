# ACGS documentation index

ACGS / gove-zone is a vendor-neutral, receipt-gated governance layer for AI-agent side effects. It sits at the executor boundary below any agent framework, enforces policy before execution, emits a verifiable Decision Receipt, and makes executors fail closed without a valid receipt.

Core invariant: **No valid Decision Receipt, no side effect.**

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
- [ROADMAP](ROADMAP.md)
- [GLOSSARY](GLOSSARY.md)
- [REVIEW_CHECKLIST](REVIEW_CHECKLIST.md)
- [ADOPTION_GUIDE](ADOPTION_GUIDE.md)

## Existing reference areas

- `concepts/` — authority, decision receipts, evidence bundles, fail-closed enforcement, audit replay, tool boundaries.
- `reference/` — API, CLI, policy schema, receipt schema.
- `hooks-or-runtime/` — runtime hook configuration and reference.
- `mcp/` — MCP overview, quickstart, examples.
- `adr/` — architecture decisions.
- `troubleshooting/` — common issues and security/privacy notes.

## Claim boundary

Local receipts, smoke tests, and lint output are readiness evidence. They are not production deployment proof or compliance certification unless matching live/external evidence is present.
