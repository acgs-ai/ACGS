# ACGS Governance Evaluation MVP

## Objective

Build an evaluation layer that is usable by legal, compliance, engineering, and regulator-facing reviewers. The layer validates AI agent actions before execution, records a replayable governance trail during execution, and supports sampling, replay, and explanation after execution.

## Design principle

Treat evaluation as a product surface, not a logging sidecar.

The system must answer:

1. **Who acted?**
2. **What did the agent intend to do?**
3. **Was the actor authorized?**
4. **Which policy was recalled and cited?**
5. **Why was the action allowed or denied?**
6. **Can the decision be replayed under the same rule versions?**
7. **Can an auditor sample and verify the event without engineering assistance?**

## MVP gates

| Gate | Purpose | Fail-closed trigger |
|---|---|---|
| AuthorityGate | Role, action, scope, MACI role, amount limit | Unknown role, unauthorized action, missing scope, limit exceeded |
| PolicyRecallGate | Requires applicable policy citation before sensitive action | No policy for critical action, missing citation, deny policy match |
| GovernanceRecallGate | Produces explainable final governance path | Missing mandatory gate, any prior deny |

## API surface

### POST `/govern/validate`

Input: `ActionRequest`.

Output: `DecisionRecord`.

Required behavior:

- Return `allow=false` when any gate denies.
- Include `checks[]`, `reason_codes[]`, `rule_ids[]`, `policy_version`, `role_version`.
- Append JSONL audit event if audit store is enabled.

### GET `/govern/explain/{event_id}`

Returns the governance recall evidence for an audit event.

### GET `/audit/query`

Supports sampling by:

- `rule_id`
- `gate`
- `allow`
- `risk_tag`
- `limit`

### GET `/audit/verify-chain`

Recomputes chain hashes and reports tampering or broken links.

## Audit event minimum fields

```json
{
  "event_id": "uuid",
  "tenant": "default",
  "allow": true,
  "request": {
    "actor": {"id": "agent-legal-1", "role": "LegalOps"},
    "intent": "Redline supplier contract",
    "action_type": "contract.redline",
    "resource": "contracts/supplier-123",
    "inputs_hash": "sha256:..."
  },
  "checks": [],
  "rule_ids": [],
  "policy_version": "2026-05-contracting+2026-05-marketing",
  "role_version": "2026-05-04",
  "previous_hash": "0000...",
  "event_hash": "sha256..."
}
```

## Metrics

Minimum metric set:

| Metric | Type | Labels |
|---|---|---|
| `acgs_governance_gate_decisions_total` | counter | `gate`, `allow`, `reason_code` |
| `acgs_governance_decisions_total` | counter | `tenant`, `allow` |
| `acgs_governance_replay_consistency_ratio` | gauge/job output | `tenant`, `policy_version`, `role_version` |
| `acgs_governance_policy_citation_missing_total` | derived counter | `policy_id`, `action_type` |

## Replay acceptance criteria

A sampled event passes replay when:

1. Same input request.
2. Same roles version.
3. Same policy bundle version.
4. Same allow/deny result.
5. Same ordered reason codes.

Target: weekly 1% sample, `>=99.5%` replay consistency.

## PR implementation order

1. Add models and schema.
2. Add role/policy loader.
3. Add AuthorityGate.
4. Add PolicyRecallGate.
5. Add GovernanceRecallGate.
6. Add chain-hash JSONL audit store.
7. Add governed tool adapter.
8. Add tests for allow, deny, hash-chain verification, and replay.
9. Add FastAPI surface.
10. Add OTel counters.

## Non-negotiable invariants

- External side effects must be behind `GovernedToolAdapter.validate()`.
- Missing policy for critical action denies.
- Missing citation for applicable policy denies.
- Deny policy overrides allow policy.
- Audit append happens before tool execution when the action is allowed.
- Denied actions are also audited.
- Chain hash must verify across every JSONL line.
- Replay must not append new audit events.
