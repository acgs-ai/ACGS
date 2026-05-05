# Integrating the ACGS Governance Library

This guide is for engineers adding ACGS governance to their own agent or
service. It covers the five-minute quickstart, the `validate` / `guard`
lifecycle, the full reason-code catalog, and how to author new tool adapters.

For the full metadata reference (every key the gates read off
`request.metadata`) see [METADATA.md](METADATA.md).

If you want to test without writing roles or policies to disk, the in-memory
test harness lands in PR #5 (`feat/governance-test-infra` branch) — see
`governance.testing.governance_test_harness`. Until that lands, use the
on-disk quickstart below.

---

## 1. Five-minute quickstart (Python, no FastAPI)

Install (in-tree, editable):

```bash
pip install -e acgs_governance_eval_mvp
```

The library only needs the standard library plus `PyYAML` for `.yaml`
policy bundles. No web framework is required.

Load the bundled roles + policy fixtures, validate one allow and one deny,
then verify the audit chain end-to-end:

```python
from pathlib import Path

from governance.adapters.tools import GovernedToolAdapter
from governance.audit import ChainHashAuditStore
from governance.policy_loader import load_policy_bundle, load_roles

roles = load_roles("governance/roles.json")
policy = load_policy_bundle("governance/policies/2026-05")

audit = ChainHashAuditStore(Path("audit.jsonl"))
adapter = GovernedToolAdapter(
    roles_bundle=roles,
    policy_bundle=policy,
    audit_store=audit,
)

# Allow: LegalOps redlining a contract with a valid citation.
allow_decision = adapter.validate({
    "actor": {"id": "agent-legal-1", "role": "LegalOps"},
    "intent": "Redline supplier agreement",
    "action_type": "contract.redline",
    "resource": "contracts/supplier-123",
    "tool_input": {"contract_id": "supplier-123"},
    "metadata": {"policy_citations": ["CONTRACT-AUTHORITY-001"]},
})
assert allow_decision.allow is True

# Deny: MarketingOps cannot approve contracts.
deny_decision = adapter.validate({
    "actor": {"id": "agent-mkt-1", "role": "MarketingOps"},
    "intent": "Approve supplier agreement",
    "action_type": "contract.approve",
    "resource": "contracts/supplier-123",
    "tool_input": {"contract_id": "supplier-123"},
})
assert deny_decision.allow is False
assert "AUTH_ACTION_DENIED" in deny_decision.reason_codes

# Verify the on-disk audit chain.
assert audit.verify_chain() is True
```

Two `audit.jsonl` events are written; each event includes
`previous_hash` / `event_hash`, the bundle hashes, and the full
`DecisionRecord`. `verify_chain()` walks the file and recomputes every
hash — any tampering fails the check.

---

## 2. `validate` vs `guard`

There are two entry points on `GovernedToolAdapter`. Pick by whether you
already own the side-effect call site.

### `validate(request) -> DecisionRecord`

Pure decision: gates are evaluated, the decision is appended to the audit
store (if one is configured), and the record is returned. Use this when
you want to inspect the decision before deciding what to do, or when
there is no executor (e.g. replay or batch evaluation paths).

```python
decision = adapter.validate(request)
if decision.allow:
    do_the_thing(decision.effective_tool_input)  # validated input
else:
    log_denial(decision.reason_codes, decision.checks)
```

### `guard(request, fn)` — recommended for tool adapters

Validates and, on allow, calls `fn(decision.effective_tool_input)`. The
executor is bound to the validated input — arbitrary caller arguments
cannot bypass the gate. This is the TOCTOU-safe path.

`guard()` requires `audit_store` (allowed side effects must be persisted
before they run) and `request.tool_input` (so the executor can be bound to
the validated input).

```python
from governance.models import GovernanceDeniedError

def call_tool(effective_input: dict) -> str:
    return external_api.call(**effective_input)

try:
    result = adapter.guard(request, call_tool)
except GovernanceDeniedError as exc:
    # The DecisionRecord rides on the exception.
    print("denied:", exc.decision.reason_codes)
    for check in exc.decision.checks:
        if not check.allowed and check.remediation:
            print(f"  fix: {check.remediation}")
```

`GovernanceDeniedError` subclasses `PermissionError`, so existing
`except PermissionError:` catches keep working — but new code should
catch `GovernanceDeniedError` and inspect `.decision`.

---

## 3. Reason code reference

Every deny carries a `reason_code` string and (where applicable) a
one-line `remediation` hint on the corresponding `GateResult`.

### `AuthorityGate`

| Code | Meaning | Remediation |
|---|---|---|
| `AUTH_TENANT_MISMATCH` | `request.tenant` differs from `actor.tenant` and no cross-tenant delegation flag is set. | Set `request.tenant = actor.tenant` or include `metadata.cross_tenant_delegation` |
| `AUTH_RESOURCE_INVALID` | Resource is empty, absolute (`/...`), or contains a `..` segment. | Resource must not contain `..` or start with `/` |
| `AUTH_ROLE_UNKNOWN` | `actor.role` is not in the loaded roles bundle. | Add the role to `roles.json` or correct `actor.role` |
| `AUTH_ACTION_DENIED` | Role has no entry for `action_type` (and no `*` wildcard). | Use a role that lists this `action_type`, or add it to the role's `actions` |
| `AUTH_SCOPE_DENIED` | Resource doesn't match any scope on the role or actor. | Add a matching scope to the role or `actor.scopes` |
| `AUTH_MACI_ROLE_DENIED` | `metadata.maci_required_role` is not in the role's `maci_roles`. | Grant the required `maci_role` to this role in `roles.json`, or use a role that already has it |
| `AUTH_LIMIT_EXCEEDED` | `request.amount_cents` is greater than the role's `single_amount_cents`. | Reduce `amount_cents` or use a role with a higher `single_amount_cents` limit |
| `AUTH_ALLOWED` | Allow result. | — |

### `PolicyRecallGate`

| Code | Meaning | Remediation |
|---|---|---|
| `POLICY_NOT_FOUND` | No policy applies, but the action is in `critical_actions` (or `metadata.requires_policy = True`). | Add a policy whose `applies_when` matches this `action_type`/`resource`, or remove the action from `critical_actions` if it should be unregulated |
| `POLICY_DENY_MATCH` | An applicable policy has `effect: deny` and its conditions matched. | The action is forbidden by an active deny policy; change the action, scope, or content to no longer match the policy's `applies_when` / `conditions` |
| `POLICY_CITATION_MISSING` | Applicable policy required a citation, but `metadata.policy_citations` doesn't include the policy id (or one of its obligation ids). | Add the missing policy id(s) (or matching obligation ids) to `metadata.policy_citations` |
| `POLICY_RECALL_OK` | Allow — every required citation matched. | — |
| `POLICY_NOT_REQUIRED` | Allow — no policy applied and the action is not critical. | — |

### `GovernanceRecallGate`

| Code | Meaning | Remediation |
|---|---|---|
| `GOVERNANCE_RECALL_INCOMPLETE` | Some mandatory upstream gate (`authority`, `policy_recall`) was skipped. | Adapter authoring bug — the recall gate must run after the mandatory gates (the bundled `GovernedToolAdapter` already does this) |
| `GOVERNANCE_RECALL_DENY` | Recall produced an explanation for an upstream denial. | Resolve the upstream gate's deny per its own remediation |
| `GOVERNANCE_RECALL_OK` | Allow — full recall payload produced. | — |

The full evidence payload (actor, action, versions, ordered checks) is
attached to `GateResult.evidence` for both `_DENY` and `_OK` outcomes,
which is what `replay.replay_event` consumes.

---

## 4. Authoring a new tool adapter

`GovernedToolAdapter.guard()` is the canonical surface for tool calls,
but if you need a custom adapter (a different sequencing, an extra gate,
a different executor binding), follow this lifecycle.

### `ActionRequest` schema

`ActionRequest.from_dict()` accepts:

```jsonc
{
  "actor": {
    "id": "agent-legal-1",
    "role": "LegalOps",
    "tenant": "acme",         // optional, default "default"
    "scopes": ["..."],         // optional per-actor scope grants
    "attributes": {}            // free-form, surfaced in audit only
  },
  "intent": "Redline supplier agreement",
  "action_type": "contract.redline",
  "resource": "contracts/supplier-123",
  "tenant": "acme",            // optional, defaults to actor.tenant
  "amount_cents": 12000,        // optional, monetary actions only
  "tool_input": { "...": "..." },   // required if you call guard()
  "inputs_hash": "sha256:...",       // derived from tool_input if omitted
  "event_id": "uuid-...",            // generated if omitted
  "metadata": { "...": "..." }       // see METADATA.md for the full key list
}
```

### Lifecycle

1. **Build the request** from your callsite. If you have the raw tool
   args, pass them as `tool_input` — `from_dict()` will derive
   `inputs_hash` for you.
2. **Call `validate()`** to run every gate in order. Each `GateResult`
   carries `allowed`, `reason_codes`, `evidence`, and (on deny)
   `remediation`. The combined `DecisionRecord` carries the
   `decision_state`, `effective_tool_input` (set on allow), bundle
   hashes, and the chain pointers from the audit store.
3. **Append to audit** — the bundled adapter does this automatically when
   `audit_store` is set. If you build a custom adapter, call
   `audit_store.append(decision)` and re-construct the record with the
   returned `previous_hash` / `event_hash` so callers see the persisted
   chain pointers.
4. **Bind execution** — only call your tool with
   `decision.effective_tool_input`. Never with the raw user-supplied
   args (that's the TOCTOU defense). `guard()` does this for you.
5. **Wire post-execution and final-summary hooks** — these aren't part of
   pre-execution validation and are intentionally outside this adapter.
   Today the only hook lives in `governance.metrics` (gate latency and
   allow/deny counts via `GovernanceMetrics`); pass an instance into the
   adapter constructor to enable it. Wire downstream observers
   (e.g. an executor-completion event, a final-summary recall pass) on
   top of the returned `DecisionRecord` — for example, after `guard()`
   returns, log `decision.event_id` against the executor outcome, or
   submit `decision.to_dict()` to a downstream conformance check.

### Where the bundled adapter lives

- `governance/adapters/tools.py` — `GovernedToolAdapter`. Reads as a
  reference implementation: gate ordering, audit binding, and the
  TOCTOU-safe `guard()` executor binding all live here.
- `governance/gates/` — the three gates `validate()` runs through.
- `governance/audit/jsonl_chain.py` — `ChainHashAuditStore` (the only
  audit store today).
- `governance/replay.py` — re-runs `validate()` over a stored event with
  a fresh bundle and reports drift.
