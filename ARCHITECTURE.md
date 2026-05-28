---
title: govern-zone architecture
description: Receipt-first governance plane architecture and current implementation boundary.
---

# govern-zone architecture

`govern-zone` is a governance plane, not an agent framework. Agent frameworks
produce goals, plans, and proposed side effects. `govern-zone` sits before those
side effects and returns one deterministic decision with evidence.

## Canonical flow

```text
GovernanceRequest
-> tenant policy bundle lookup
-> local policy evaluation
-> DecisionReceipt
-> audit append
-> receipt-gated executor
```

The executor is a separate guard. It refuses to call a registered tool unless
the caller supplies a valid Decision Receipt whose decision authorizes exactly
the action being executed. `DENY` and `ESCALATE` receipts are not executable.
`TRANSFORM` receipts authorize only the transformed action.

## Implemented now

- `packages/gove-zone/src/gove_zone/foundation.py` defines the production-shaped
  request, tenant policy binding, Decision Receipt, verifier, governance engine,
  executor guard, and internal metrics sink.
- `ChainHashAuditStore` persists append-only JSONL events and verifies
  `previous_hash` / `event_hash` linkage.
- `Policy` is a stdlib interface; the hot path uses local deterministic checks.
- `gove_zone.adapters.normalize_governance_request` maps supported framework
  envelopes to one internal request shape and fails closed for unsupported
  envelopes.
- `gove-zone doctor`, `smoke`, `gate`, `proofpack`, and `replay` are the tested
  local CLI surfaces.
- Receipts include a `signature` placeholder of `unsigned-local-dev` until a
  deployment-managed signer is wired.

## Not implemented yet

- Managed signing keys, key rotation, and verifier trust roots.
- Remote policy engines such as OPA/Rego in the hot path.
- Production OpenTelemetry export from `gove-zone` itself.
- Distributed audit storage, external timestamping, or legal/compliance
  certification.

## Package boundaries

`packages/gove-zone` is the core governed execution package.
`acgs_governance_eval_mvp` contains evaluation, admission-gate prototypes,
MCP experiments, and optional OTel hooks. `packages/agent-bus-analyzer` observes
and analyzes evidence. Domain packages may consume `gove-zone`; they are not
part of the core hot path.
