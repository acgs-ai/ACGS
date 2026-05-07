# Governance Failure Modes Taxonomy

A reference for engineers building on or modifying the ACGS governance library. Each failure
mode is a named reason code, a decision state, or an integration mistake that causes governance
to deny, produce incorrect decisions, or break replay integrity.

See [INTEGRATING.md](../INTEGRATING.md) for the full lifecycle and quick-start, and
[METADATA.md](../METADATA.md) for the complete `request.metadata` key reference.

---

## 1. AuthorityGate Failures

The `AuthorityGate` runs first on every request. All seven deny codes are `fail-closed`:
the request is rejected and no further gates run.

| Code | Trigger | Fix |
|---|---|---|
| `AUTH_TENANT_MISMATCH` | `request.tenant` ≠ `actor.tenant` with no cross-tenant delegation | Set `request.tenant = actor.tenant` or add `metadata.cross_tenant_delegation` |
| `AUTH_RESOURCE_INVALID` | Resource is empty, starts with `/`, or contains `..` | Use relative paths without `..` segments |
| `AUTH_ROLE_UNKNOWN` | `actor.role` not present in loaded roles bundle | Add role to `governance/roles.json` or correct `actor.role` |
| `AUTH_ACTION_DENIED` | Role has no entry for `action_type` and no `*` wildcard | Use a role that lists the action, or add the action to the role |
| `AUTH_SCOPE_DENIED` | Resource matches no scope on the role or actor | Add a matching scope to the role definition or `actor.scopes` |
| `AUTH_MACI_ROLE_DENIED` | `metadata.maci_required_role` not in the role's `maci_roles` | Grant the required MACI role in `roles.json` |
| `AUTH_LIMIT_EXCEEDED` | `request.amount_cents` > role's `single_amount_cents` | Reduce the amount or use a role with a higher limit |

---

## 2. PolicyRecallGate Failures

Runs after `AuthorityGate`. Denies when the caller cannot demonstrate policy awareness for
sensitive or critical actions.

| Code | Trigger | Fix |
|---|---|---|
| `POLICY_NOT_FOUND` | Action is in `critical_actions` (or `metadata.requires_policy = True`) but no policy covers it | Add a matching policy to `governance/policies/` or remove the action from `critical_actions` |
| `POLICY_DENY_MATCH` | An applicable policy has `effect: deny` and its conditions matched | Change the action, scope, or inputs so they no longer match the deny policy's `applies_when`/`conditions` |
| `POLICY_CITATION_MISSING` | Applicable policy requires a citation, but `metadata.policy_citations` is absent or doesn't include the policy id (or its obligation ids) | Populate `metadata.policy_citations` with the required policy id(s) |

---

## 3. GovernanceRecallGate Failures

Final gate — synthesises evidence from all prior gates and produces the audit explanation.

| Code | Trigger | Fix |
|---|---|---|
| `GOVERNANCE_RECALL_INCOMPLETE` | A mandatory upstream gate (`authority` or `policy_recall`) was skipped | Adapter authoring bug: the recall gate must always run after both mandatory gates. Use the bundled `GovernedToolAdapter` rather than building a custom gate chain |
| `GOVERNANCE_RECALL_DENY` | Recall produced an explanation for an upstream deny | Resolve the upstream gate's deny per its own remediation table above |

---

## 4. Decision State Failures

`DecisionRecord.decision_state` has five values. Today the runtime only emits `allow` and
`deny`. The other three are reserved for future gates but must be handled defensively:

| State | Meaning | Required caller behaviour |
|---|---|---|
| `allow` | All gates passed | Invoke executor with `decision.effective_tool_input` only |
| `deny` | At least one gate denied | Raise / propagate `GovernanceDeniedError`; do not call executor |
| `require_human` | *(reserved)* Human review required | Treat as deny until the gate that sets it is implemented |
| `rewrite` | *(reserved)* Adapter rewrote the tool input | Use `decision.effective_tool_input`; discard original caller args |
| `redact` | *(reserved)* Output must be redacted | Post-process executor output before returning to caller |

---

## 5. Integration Failure Modes

These are code-level mistakes that cause governance to be bypassed or broken even when the
reason codes show `allow`.

### 5.1 TOCTOU bypass — using raw caller args after `validate()`

**Wrong:**
```python
decision = adapter.validate(request)
if decision.allow:
    do_the_thing(**request.tool_input)   # BAD: caller can modify tool_input after validate
```

**Right:**
```python
decision = adapter.validate(request)
if decision.allow:
    do_the_thing(**decision.effective_tool_input)  # locked at validation time
```

Use `guard(request, fn)` instead — it binds execution to `effective_tool_input` automatically.

### 5.2 Calling `guard()` without an audit store

`guard()` requires `audit_store` to be set. Side effects must be persisted before they run.
Constructing `GovernedToolAdapter` without `audit_store` and then calling `guard()` raises
`ValueError` at call time — configure the store at adapter construction, not later.

### 5.3 Catching `PermissionError` instead of `GovernanceDeniedError`

```python
# Loses the DecisionRecord and remediation hints:
except PermissionError as exc: ...

# Correct — inspect decision.checks for per-gate remediation:
from governance.models import GovernanceDeniedError
except GovernanceDeniedError as exc:
    for check in exc.decision.checks:
        if not check.allowed and check.remediation:
            log(check.remediation)
```

`GovernanceDeniedError` is a subclass of `PermissionError`, so existing broad catches still
work, but new code should catch the narrower type to access remediation hints.

### 5.4 Appending audit events before constructing the decision record

The `ChainHashAuditStore.append()` call returns `(previous_hash, event_hash)`. The decision
record must be reconstructed with those values so callers see correct chain pointers. If you
build a custom adapter, follow the pattern in `governance/adapters/tools.py`.

---

## 6. Replay Failures

`replay.replay_event()` re-runs `validate()` over a stored event. It fails when:

| Symptom | Cause | Fix |
|---|---|---|
| `allow`/`deny` flip | Policy or role bundle changed since the event was recorded | Pass the same `policy_bundle` and `roles_bundle` versions as the original event (`DecisionRecord.policy_version` / `role_version`) |
| Reason code order differs | Evaluation order changed in gate code | Pin gate code version when running compliance replay |
| Hash mismatch on `verify_chain()` | JSONL file was modified after write | Treat as tampering; do not use the record for compliance evidence |

Target: ≥ 99.5% replay consistency on a weekly 1 % sample (see `docs/acgs-governance-eval-mvp.md`).

---

## 7. Non-Negotiable Invariants

These invariants are enforced by the runtime. Violating them during integration testing means
your adapter is wrong, not the governance library:

- External side effects must be behind `GovernedToolAdapter.guard()` — never call a tool with
  raw user args that haven't passed through `validate()`.
- A missing policy for a critical action always denies (`POLICY_NOT_FOUND`).
- A missing citation for an applicable policy always denies (`POLICY_CITATION_MISSING`).
- A deny policy always overrides an allow policy (`POLICY_DENY_MATCH`).
- Audit append happens **before** tool execution when the action is allowed.
- Denied actions are also audited (the `DecisionRecord` is always persisted).
- Chain hash must verify across every JSONL line — `ChainHashAuditStore.verify_chain()` must
  return `True` for any event file used as compliance evidence.
- Replay must not append new audit events.
