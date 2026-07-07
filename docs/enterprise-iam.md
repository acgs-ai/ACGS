# Enterprise Identity Integration Architecture

How enterprise identity — OAuth identity, SSO, service accounts, workload
identity, and RBAC mapping — feeds the governed kernel. Implemented in
`packages/gove-zone/src/gove_zone/identity.py`; proven by
`packages/gove-zone/tests/test_identity.py`.

## The enforcement chain

```text
Identity     who is calling
  |          IdentityProviderAdapter.resolve(Credential) -> Principal
  v
Authority    what they are granted
  |          RBACMapper: IdP groups -> roles -> authority grant
  |          (+ optional PrincipalEntry for the authz allowlist seam)
  v
Policy       whether this action is allowed
  |          evaluate_tenant_action -> RuleSetPolicy / bundle per tenant
  v
Receipt      the verifiable decision
  |          DecisionReceipt: actor + authority + validator bound into
  |          receipt_hash, anchored in the audit chain
  v
Execution    the gated side effect
             execute_with_receipt(expected_actor=principal.actor_id())
```

Each layer only *feeds* the next; none bypasses it. The single fail-closed
gate remains `DecisionReceipt.verify` (surfaced through
`execute_with_receipt`). The identity module is purely additive — like
`gove_zone.contracts`, it adds vocabulary and inputs, not a second
enforcement path.

## Layer 1 — Identity

### The adapter contract

Every identity-provider integration implements `IdentityProviderAdapter`:

| Member | Meaning |
|---|---|
| `provider_id` | Stable string namespacing this provider's principals |
| `supported_credential_types` | Which `CredentialType`s it can resolve |
| `resolve(credential, *, now_iso=None)` | `Credential` → verified `Principal`, or raise `IdentityError` |

Resolution is fail-closed: unknown token, revoked token, credential-type
mismatch, workload audience mismatch, and expiry are all refusals
(`IdentityError`), never warnings or partial principals. `now_iso` injects
the clock for expiry checks, mirroring `DecisionReceipt.verify(now_iso=...)`.

### Supported credential kinds

| `CredentialType` | Enterprise flow it models | Principal kind |
|---|---|---|
| `OAUTH_ACCESS_TOKEN` | OAuth 2.0 bearer token (interactive grant or client credentials) | user, service account |
| `SSO_ASSERTION` | SSO session assertion (SAML assertion / OIDC id-token analogue) | user |
| `SERVICE_ACCOUNT_KEY` | Long-lived service-account credential | service account |
| `WORKLOAD_IDENTITY_TOKEN` | Audience-bound federated token (SPIFFE / GCP WIF / Azure federated credential style) | workload |

The principal-kind ↔ credential-kind table is enforced at issuance *and*
resolution: a workload can hold only audience-bound workload tokens; a user
can never present one. A `WORKLOAD_IDENTITY_TOKEN` credential without an
audience is rejected at construction, and a token presented for a different
audience than it was issued for is refused — this is what makes workload
identity secret-less but not bearer-promiscuous.

### The resolved principal

`Principal` carries `subject`, `tenant_id`, `provider_id`, `principal_type`,
`groups`, and provider-dialect `claims`. Its canonical actor string,

```text
actor_id() = "<provider_id>:<tenant_id>:<subject>"    # e.g. mock-azure-ad:tenant-A:alice
```

is what the kernel binds into receipts (`DecisionReceipt.actor`) and what the
executor gate anchors on (`expected_actor`). The encoding is injective:
`provider_id` and `tenant_id` may not contain `:` (rejected at construction),
while subjects may (SPIFFE-style ids) — so two distinct principals can never
encode to the same actor string. Cross-principal receipt replay is then
refused at the gate *on paths where the integrator binds `expected_actor`*
(all gate surfaces require it; direct `DecisionReceipt.verify()` callers that
omit it fall back to weaker checks — see `docs/CLAIMS.md`).

### Mock providers

Three bundled adapters emulate the observable contract (issuance-bound token
type, audience binding, expiry, revocation) and claim dialect of the major
enterprise IdPs, over an in-memory directory:

| Adapter | `provider_id` | `tenant_id` plays | Dialect claims |
|---|---|---|---|
| `MockAzureADAdapter` | `mock-azure-ad` | directory / `tid` | `tid`, `oid`, `upn` |
| `MockOktaAdapter` | `mock-okta` | Okta org | `sub`, `iss`, `preferred_username` |
| `MockGoogleWorkspaceAdapter` | `mock-google-workspace` | hosted domain / `hd` | `sub`, `email`, `hd` |

The `mock-` prefix is deliberate provenance: a mock-resolved principal never
mints the same actor namespace — and thus the same receipts or authz registry
entries — as a real production adapter for that provider would.

All three subclass `MockIdentityProvider`, which is itself usable directly
for provider-agnostic tests (including restricted
`supported_credential_types`, e.g. an SSO-only provider).

**These are mocks.** They perform no real OAuth/OIDC/SAML exchange and no
cryptographic token validation; tokens are opaque handles into an in-memory
table. A production adapter implements the same `IdentityProviderAdapter`
contract against the real IdP (real JWT signature + `iss`/`aud`/`exp`
validation, JWKS rotation, directory lookups). Nothing downstream of
`resolve()` changes when a real adapter is substituted — that is the point of
the interface.

## Layer 2 — Authority (RBAC mapping)

`RBACMapper` turns IdP-asserted group membership into governance authority:

```python
rbac = RBACMapper(
    roles=[
        RoleDefinition(
            role="writer",
            authority="tenant-A/write-grant",
            allowed_tools=frozenset({"runtime.file.write"}),
        ),
        RoleDefinition(role="admin", authority="tenant-A/admin-grant", allowed_tools=None),
    ],
    group_to_role={"eng": "writer", "platform-admins": "admin"},
)
```

- **Fail-closed:** a principal whose groups match no mapping has no role —
  `roles_for` / `authority_for` raise `IdentityError` rather than defaulting
  to a permissive role. A `group_to_role` entry naming an unknown role is a
  construction-time `ValueError`.
- **Deterministic and unambiguous:** multiple roles combine as sorted,
  `+`-joined authorities, so the same principal always mints the same
  `DecisionReceipt.authority` regardless of group enumeration order. A role
  authority may not itself contain `+` (rejected at construction), so a
  single role can never mint an authority string identical to a multi-role
  grant set — `receipt.verify(expected_authority=...)` exact-matching stays
  meaningful.
- **Enforced by the bundled chain:** `govern_identity_action` refuses (before
  any policy evaluation) an action outside the principal's role-granted tool
  union, so the fail-closed `allowed_tools` default is not merely advisory.
- **Bridges to the existing authz seam:** `principal_entry(principal)`
  derives a `gove_zone.authz.PrincipalEntry` (tools = union across roles;
  any all-tools role → all tools; default = *no* tools). Feed these into a
  `PrincipalRegistry` and the existing kernel/executor `authz_enforce` seam
  enforces RBAC — this module changes nothing about that seam.

## Layers 3–5 — Policy, Receipt, Execution (existing kernel)

`govern_identity_action(adapter, credential, ...)` runs the chain for one
proposed action:

1. **Identity** — `adapter.resolve(credential)` → `Principal`.
2. **Authority** — `rbac.authority_for(principal)` → authority grant, and the
   proposed action must be inside the principal's role-granted tool union
   (`IdentityError` with `TOOL_NOT_PERMITTED_BY_ROLE` otherwise).
3. **Policy → Receipt** — delegates to `evaluate_tenant_action` with the
   principal's home tenant as both target and requester (an IdP-resolved
   principal cannot request cross-tenant), `actor=principal.actor_id()`, and
   the distinct MACI `validator` — self-validation stays structurally
   impossible.
4. **Execution** — unchanged: pass the returned receipt to
   `execute_with_receipt(..., expected_actor=principal.actor_id())`. No valid
   receipt, no side effect.

```python
from gove_zone import (
    ChainHashAuditStore, CredentialType, MockAzureADAdapter, RBACMapper,
    RoleDefinition, RuleSetPolicy, TenantPolicyStore, Validator,
    execute_with_receipt, govern_identity_action,
)

idp = MockAzureADAdapter(tenant_id="tenant-A")
idp.register_user("alice", groups=["eng"])
credential = idp.issue_credential("alice", CredentialType.OAUTH_ACCESS_TOKEN)

rbac = RBACMapper(
    roles=[RoleDefinition(role="writer", authority="tenant-A/write-grant",
                          allowed_tools=frozenset({"runtime.file.write"}))],
    group_to_role={"eng": "writer"},
)
store = TenantPolicyStore("policies")
store.store_bundle("tenant-A", RuleSetPolicy.from_dict(
    {"id": "policy-A", "rules": [{"id": "R1", "effect": "deny", "tools": ["shell.exec"]}]}
))
audit = ChainHashAuditStore("audit.jsonl")

def write_file(**kwargs):  # the governed side effect
    ...

receipt = govern_identity_action(
    idp, credential,
    policy_store=store, action="runtime.file.write",
    args={"path": "safe.txt", "content": "hi"},
    execution_boundary="local-sandbox", request_id="req-1",
    rbac=rbac, validator=Validator("constitutional-council"),
    audit_store=audit,
)

execute_with_receipt(
    write_file, {"path": "safe.txt", "content": "hi"}, receipt,
    expected_tenant_id="tenant-A",
    expected_execution_boundary="local-sandbox",
    expected_action="runtime.file.write",
    expected_actor=idp.resolve(credential).actor_id(),
    require_signature=False,  # dev profile; production keeps the signed default
)
```

## Failure taxonomy

| Error | Layer | Meaning |
|---|---|---|
| `IdentityError` (carries `IdentityRejectionReason` in `reason_code`) | Identity / Authority | No principal was established, or the action is outside the principal's role tool-grant. No governance request is ever made. |
| `AuthzDeniedError` | Execution gate (authz seam) | A resolved principal is not on the integrator allowlist for this tool. |
| `ReceiptValidationError` | Receipt / Execution gate | The receipt fails verification (tamper, wrong actor/tenant/boundary, expiry, replay) — including receipts whose `decision` is `deny`/`escalate`. |

Note: on this chain a policy DENY/ESCALATE does **not** raise
`DeniedError`/`EscalateError` — `govern_identity_action` returns a receipt
carrying that decision, and the executor gate refuses it with
`ReceiptValidationError`. Those exceptions belong to the `Kernel.dispatch`
path, which this chain does not use.

Every layer refuses independently; a defect earlier in the chain means later
layers never run.

## Limitations (claim-safe)

- The bundled providers are **in-memory mocks** for tests, demos, and
  integration development — no network protocol, no real token cryptography.
- No OIDC discovery, JWKS handling, token refresh, or SCIM directory sync is
  implemented anywhere in this module.
- `RBACMapper` is exact-match on group strings; nested/dynamic groups are the
  IdP's concern and must be flattened into the asserted `groups`.
- The principal-kind ↔ credential-kind table is static and mock-scoped: flows
  where a workload exchanges its federated token for an OAuth access token
  (GCP WIF token exchange) are not modeled by the mocks; a production adapter
  models its provider's real issuance rules.
- Offset-naive timestamps are rejected everywhere (`expires_at`, `now_iso`),
  mirroring the receipt gate — supply explicit UTC offsets.
- Cross-tenant delegation is intentionally not expressible through
  `govern_identity_action`; it pins requester = principal's home tenant.
- The kernel-side authorization seam this maps onto is the B13 first slice
  (flat principal → allowed-tools registry, `AUTHZ_ENFORCE` off by default);
  see `gove_zone/authz.py` and `AUTHZ-ROADMAP.md` for what is and is not
  enforced there today.
