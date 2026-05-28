---
title: Security boundary
description: Security model, fail-closed behavior, license boundary, and known limitations.
---

# Security boundary

`govern-zone` is designed to fail closed for governed execution. Missing policy,
missing tenant, missing receipt, malformed receipt, invalid receipt hash, unknown
decision, denied decision, tenant policy mismatch, and audit write failure must
block execution.

## Current controls

- Decision Receipts are canonical JSON hashes over tenant, actor, subject,
  proposed action, goal, execution boundary, policy bundle, policy hash,
  decision, matched rules, transformations, approval summary, timestamp, and
  audit chain pointer.
- `GovernedExecutor` verifies the receipt before invoking a tool.
- `TRANSFORM` receipts authorize only the transformed action.
- Audit events are hash chained and can be replay-verified for tampering or
  reordering.
- Tenant policy bundles are looked up by `(tenant_id, policy_bundle_id)`, so one
  tenant cannot accidentally use another tenant's active bundle.

## Current limitations

- The receipt signature is a verification placeholder, not a cryptographic
  deployment signature.
- The default policy registry is in-memory and static for local deterministic
  tests and examples.
- Audit storage is local JSONL with Unix `fcntl` locking.
- This repository does not claim production readiness, compliance approval, or
  regulatory certification.

## License and templates

Root and `packages/gove-zone` package metadata declare Apache-2.0, and the root
`LICENSE` file makes that boundary visible for downstream review. Industry or
jurisdiction-specific templates must stay optional and outside the default core
unless their license terms are compatible with the repository boundary. Do not
mix AGPL-style template logic into the core unless the repository license
changes explicitly.
