# AGENTS.md - acgs_governance_eval_mvp/governance/gates

## Purpose

Admission-control gates evaluated before any governed action proceeds. Each
gate is deterministic and fail-closed: missing role, missing scope, malformed
config, unreachable recall backend, or exceeded limits all DENY and emit an
audit event. Gates never short-circuit silently — every call produces a
`GateResult` with a `reason_codes` list.

## Gates

- `authority_gate.py` - `AuthorityGate`; checks `request.tenant == actor.tenant` (unless `metadata.cross_tenant_delegation` is set), validates the resource is not path-traversal/absolute, enforces role + action + scope + per-tenant limits against the roles bundle. Reason codes: `AUTH_TENANT_MISMATCH`, `AUTH_RESOURCE_INVALID`, `AUTH_ROLE_MISSING`, etc.
- `policy_recall_gate.py` - `PolicyRecallGate`; for critical actions (`contract.approve`, `contract.redline`, `email.send`, `marketing.publish`, `payment.send`, `tool.external_api.call`), requires policy/obligation ids in `request.metadata.policy_citations` and applies deny policies whose `conditions` match. Reason codes include `POLICY_CITATION_MISSING`.
- `governance_recall_gate.py` - `GovernanceRecallGate`; produces a verifiable explanation by aggregating prior `GateResult`s. Requires both `authority` and `policy_recall` to have run (`mandatory_gates`); missing prior results yield `GOVERNANCE_RECALL_INCOMPLETE`.

## Evaluation Order

`AuthorityGate` -> `PolicyRecallGate` -> `GovernanceRecallGate`.
The first deny short-circuits the allow decision but
`GovernanceRecallGate` is always run to produce the final explanation
record carried in the audit event.

## Failure Modes

- Gates MUST fail closed. Any unhandled exception inside a gate is treated as deny.
- `GovernanceRecallGate` enforces a structural invariant: if `authority` or `policy_recall` did not produce a `GateResult`, recall returns `GOVERNANCE_RECALL_INCOMPLETE` instead of allowing.
- Reason codes are the contract — new gates MUST register new codes in `INTEGRATING.md` (`§3 Reason code reference`).
