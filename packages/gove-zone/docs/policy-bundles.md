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
| `SyncedRuleSetPolicy` | Local/test wrapper over a verified managed snapshot. Public evaluation always returns `DENY`; only `UniversalGateway` may evaluate it while holding the verified cache lease. |
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

## Managed signed synchronization (local/test)

`gove_zone.policy_sync` implements the runtime side of the strict
`acgs.policy-sync.snapshot/v2` contract. `PolicySyncClient` uses the enrolled
runtime's signed-request transport to fetch
`GET /v1/runtime-identities/{identity_id}/policy-bundle`; local policy
evaluation never makes a network call. A fresh cached cursor is sent as the
exact signed query `cursor=<cursor>`. An authenticated `304` has an empty body
and does not extend the cached snapshot's freshness or expiry. Stale or expired
state forces an unconditional authenticated renewal and requires a newly signed
`200` snapshot.

The runtime verifies two independent signed layers against separate trust
purposes:

1. The inner `acgs.policy-envelope/v1` binds the org/project/environment,
   policy id/version, canonical rules, and content hash to the policy publisher.
2. The outer `acgs.policy-sync-attestation/v1` binds that envelope to the gate,
   runtime identity and credential generation, policy-head generation, lease
   times, and activation receipt id/hash and governance event hash.

Publisher and sync-attestation keys must be physically distinct, not merely
given different key ids. The activation hashes are authenticated commitments in
the snapshot; the local runtime does not receive or independently replay the
control-plane activation receipt and event artifacts in this flow.

### Durable last-known-good behavior

`AtomicJsonPolicyCache` replaces the verified snapshot and its sibling
`acgs.policy-sync.high-water/v1` record separately, with owner-only permissions,
per-file atomic replacement, directory synchronization, and a bounded
cross-process lock. The two replacements are not a pairwise transaction. The
high-water record is advanced first and rejects policy-head, credential,
attestation-epoch, lease, and same-generation equivocation rollback. Missing or
corrupt high-water state fails closed and cannot be reconstructed from the
cache. If a crash advances the high-water record before replacing the cache,
the restarted client performs an unconditional authenticated full fetch; a
response below the preserved floor is still rejected.

The last-known-good policy is usable without the control plane only through its
configured degraded window and signed expiry. Expiry, stale revocation evidence,
local trust revocation, cache tampering, lock failure, or an unsafe filesystem
returns `DENY`; none becomes an offline allow. The cache directory must be owned
by the current user, inaccessible to group/other users, and hosted on a
filesystem with reliable cross-process locking.

This high-water record is local anti-rollback state, not an independent witness,
hardware counter, or object-retention system. An attacker able to rewrite both
the cache and high-water files is outside this local-filesystem trust boundary.

### Native managed execution

`SyncedRuleSetPolicy.evaluate()` always returns `DENY`, including inside a
caller-opened cache binding. The private managed evaluator is reachable only
through `UniversalGateway` while it holds the verified cache lease. A legacy
`Kernel` therefore cannot turn a synchronized policy into executable authority.

For an allowed managed call, `UniversalGateway` requires three distinct physical
key domains: policy-envelope publisher, policy-sync attestation, and
decision-receipt signer. It then mints a signed, expiring Decision Receipt v2
that binds the full managed policy provenance, verifies the exact scope/action/
actor/arguments/policy/constraints through `execute_with_receipt`, and consumes
the receipt in the single-use ledger before the tool runs. Physical-key aliasing
is rejected before receipt consumption or the tool callback.

Only a successfully executed managed call receives `assurance_class="native"`.
Here, native means that the local `UniversalGateway` directly verified and
consumed the signed receipt before the side effect; it does not mean deployed,
production-certified, independently audited, or customer-proven. These paths
are implemented and tested locally only.

## Standalone bundle lifecycle (roadmap)

The standalone `TenantPolicyStore` still does **not** model bundle lifecycle
state. It holds one current bundle per tenant without an `active` / `stale` /
`revoked` state machine or bundle history. The managed synchronization contract
above adds signed, bounded runtime snapshots and local expiry/rollback checks;
it does not add a general lifecycle registry to the kernel store. Until then,
"the active bundle" in standalone APIs means "the bundle currently stored for
the tenant."

## See also

- `decision-receipts.md` — `policy_bundle_id` / `policy_version` / `policy_hash`
  on the receipt.
- `governed-execution.md` — how a bundle's decision becomes an enforced receipt.
