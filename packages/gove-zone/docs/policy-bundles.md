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
a later denial. The version is `ruleset/{id}/{sha256}` — the **full** lowercase
64-hex digest — and changing any rule changes the version, which the receipt
records as `policy_version` + `policy_hash`.

### Policy identity and immutability

Two invariants hold for the built-in policies:

1. **Full-digest identity.** Every content-addressed version carries the complete
   64-hex SHA-256: `boundary/{sha256}`, `path-boundary/{sha256}`,
   `ruleset/{id}/{sha256}`, `risk-tier/{id}/{sha256}`, and
   `composite/{sha256}`. Short identifiers may be derived for display, but they
   are never authorization-bound: `DecisionReceipt.policy_hash` and the
   `expected_policy_hash` a policy-bound `GovernedExecutor` derives pin the full
   value only. A truncated digest is rejected at construction, and no
   dual-acceptance fallback exists.
2. **Behaviour cannot drift under a stable version.** Constructor data is copied,
   nested mappings/sequences are frozen (`MappingProxyType` / `tuple`), and
   unsupported non-JSON or mutable values (`set`, arbitrary objects, non-string
   keys, non-finite floats) are rejected. Built-in policies are sealed after
   construction, so no attribute can be rebound. `to_dict()` / `version_payload()`
   return detached mutable copies; mutating them cannot reach live state.

`CompositePolicy` caches its version but evaluates each member **live**, so every
member must be a sealed built-in whose attributes are frozen at construction.
Anything else is refused with `PolicyCompositionError`. To compose custom logic,
express it as a `RuleSetPolicy` bundle.

Member **order is part of the identity**: `CompositePolicy` is a first-non-`ALLOW`-
wins pipeline, so `Composite([A, B])` and `Composite([B, A])` are different
policies and hash differently. That is intended, not incidental — do not treat
composition as an order-free `AND`.

### Trust boundary

These guarantees are **mutation-resistance, not tamper-resistance**. They stop
accidents — a retained constructor dict, a shared list, a stale alias, a
half-immutable custom policy — and they hold against every supported API. They do
not defend against hostile code in the same process, which can reach
`object.__setattr__`, rebind a class attribute, or monkey-patch a method. That is
the same boundary the repo draws for permission deny-rules: an accident-preventer
and audit signal, with CI and the receipt/executor gates as the enforcement of
record. Treat sealing as "cannot drift," not "cannot be subverted."

Sealing freezes *instance attributes*; it is not a final behavioral boundary. A
`_SealedPolicy` subclass that seals correctly but whose `evaluate` reads
module-global or external state can still change decisions under a stable
version. Composition admits subclasses because writing one means writing code
inside the trust domain. Policy identity commits to behavior for policies built
from the shipped constructors, not for arbitrary subclasses.

The identity root is `canonical_json` (`sort_keys=True`, `separators=(",",":")`,
`ensure_ascii=False`, UTF-8): dict-order independent and stable across machines.
It applies no Unicode normalization, so NFC and NFD spellings of the same text
are distinct identities — deterministic, but worth knowing when policy ids or
rule ids come from external input.

### Migration

Policy versions computed before this change used a 16-hex truncation. A bundle
whose rules are unchanged now has a *different* version string, so its old and
new identities are distinct and are **not** interchangeable: persisted receipts,
pins, and fixtures carrying a truncated `policy_version` / `policy_hash` no longer
match a freshly constructed policy and must be reissued against the full-digest
identity. Nothing accepts both forms. `CompositePolicy` changed shape too —
`composite[a+b]` became `composite/{sha256}` — so composite identities are
likewise not comparable across the boundary. `to_dict()` / `to_json()` bundle
documents are unaffected: the version is not part of the serialized bundle.

**Composition is now restricted.** `CompositePolicy` accepts only sealed
built-ins, so policies that are plain `Policy` subclasses can no longer be
composed — including three shipped ones: `TransformPolicy`
(`api.py`, `tenant.py`), `EscalatePolicy` (`api.py`), and the internal
`_ObserverPolicy` (`integration.py`). Nothing in the tree composes them today,
and the failure is fail-closed (`PolicyCompositionError` at construction, never a
silent downgrade), but any downstream code that composed a custom policy will
raise. Express that logic as a `RuleSetPolicy` bundle.

The committed proof-pack fixture corpus was regenerated and re-signed against the
new identity (`tests/fixtures/_generate_proofpacks.py`, then
`tests/fixtures/_generate_acgs_proofpack.py` — in that order, since the ACGS
golden is built from `proofpacks/valid-replay`).

Roll out in this order, since a mixed fleet fails closed (denies) rather than
open: (1) deploy verifiers/executors pinned to the new identity, (2) deploy
issuers producing it, (3) rotate stored pins and reissue receipts.

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
