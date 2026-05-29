# Policy Bundles

> Status: foundational / Alpha. gove-zone is **not** production-, compliance-,
> or regulator-certified.

A **policy** turns a proposed action into a deterministic decision. A **policy
bundle** is a serializable, content-addressed policy bound to a tenant.

## The Policy contract

`gove_zone.policy.Policy` is the ABC. `evaluate(call: ToolCall) -> DecisionRecord`
must be deterministic and must not raise on policy-internal errors (the kernel's
fail-closed wrapper converts any leak into a `DENY`).

Concrete policies shipped today:

| Policy | Behavior |
|---|---|
| `RuleSetPolicy` | Declarative bundle of rules; rules may `deny` or `escalate`; unmatched calls default to `ALLOW`. Version is a content hash. |
| `BoundaryPolicy` / `PathBoundaryPolicy` | Deny on forbidden keywords / path patterns. |
| `AllowAllPolicy` / `DenyAllPolicy` | Test and kill-switch policies. |
| `CompositePolicy` | Runs N policies in order; first non-`ALLOW` wins. |
| `TransformPolicy` | Example policy that rewrites arguments (`TRANSFORM`). |

### RuleSetPolicy bundle format

```json
{
  "id": "policy-A",
  "rules": [
    {"id": "RULE_1", "effect": "deny", "tools": ["runtime.file.write"]}
  ]
}
```

`effect` is `deny` or `escalate`. Positive authorization is the default for
unmatched calls (and via explicit exemptions) so a broad allow rule cannot mask
a later denial. The version is `ruleset/{id}/{sha256[:16]}` — changing any rule
changes the version, which the receipt records as `policy_version` + `policy_hash`.

## Tenant binding & isolation

`gove_zone.tenant.TenantPolicyStore` stores one active bundle per tenant and
enforces isolation:

- A tenant can only load **its own** bundle; a cross-tenant load raises
  `PermissionError` (`test_tenant_a_cannot_load_tenant_b_bundle`).
- Missing tenant id fails closed (`test_missing_tenant_fails_closed`).
- Missing bundle fails closed (`test_missing_bundle_fails_closed`).
- A receipt issued for tenant A cannot authorize a tenant-B executor
  (`test_tenant_a_receipt_cannot_authorize_tenant_b_action`).
- A policy-hash mismatch fails closed (`test_policy_hash_mismatch_fails_closed`).

The typed `PolicyBundleRef` (`bundle_id` + `version` + `policy_hash`) and
`TenantPolicyBinding` (`tenant_id` ↔ `PolicyBundleRef`) name this pairing in
code. They are additive value objects; storage and lookup remain in
`TenantPolicyStore`.

## Bundle lifecycle (roadmap)

The kernel does **not** model bundle lifecycle state today. There is no
`active` / `stale` / `revoked` flag and no bundle expiry. `TenantPolicyStore`
holds a single current bundle per tenant. Lifecycle state, bundle versioning
history, signed bundles, and stale-bundle rejection are roadmap. Until then,
"the active bundle" means "the bundle currently stored for the tenant."

## See also

- `decision-receipts.md` — `policy_bundle_id` / `policy_version` / `policy_hash`
  on the receipt.
- `governed-execution.md` — how a bundle's decision becomes an enforced receipt.
