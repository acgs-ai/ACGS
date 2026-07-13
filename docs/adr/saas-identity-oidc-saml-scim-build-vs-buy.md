# ADR: SaaS identity, OIDC, SAML, and SCIM build-vs-buy boundary

## Status

**Proposed — decision required.** This ADR is a Phase-0 target contract. It
does not claim an OIDC, SAML, SCIM, BFF, federation, MFA, domain-verification,
or deprovisioning implementation is shipped or configured.

## Date

2026-07-13

## Context

The [G006 survey](../saas/CURRENT_STATE_SURVEY.md) records a browser/session
contract mismatch and no accepted managed identity boundary. The target product
requires distinct human, service-account, and environment-bound gate identities;
browser sessions must not expose upstream service keys. The architecture and
threat model require a BFF and tenant-scoped authorization, but do not select an
identity vendor.

## Proposed direction pending ratification

Use standards-based OIDC as the first federation protocol to evaluate for the
target managed plane. Keep a provider interface so authentication, directory,
MFA/posture, and enterprise federation capabilities are not hard-coded. Defer
SAML and SCIM implementation decisions until a target customer lifecycle,
deprovisioning, role-mapping, support, and procurement requirement is
evidenced.

The target BFF owns browser-session validation and server-side calls to the
management API. Service/workload and gate credentials remain separate from
human identity, use narrow environment-bound scopes, and support rotation,
expiry, revocation, and last-used evidence. This proposed direction is not a
provider choice or a live federation commitment.

## Decision required

**Accountable owners:** security owner and product owner; procurement and
privacy/legal owners participate where a provider or customer data-processing
term is proposed.

Before selecting or enabling a provider, the owners must decide and record:

1. identity-provider selection or a documented no-provider/private deployment
   path;
2. OIDC issuer/claim validation, MFA/session, domain-verification, invitation,
   access-review, and break-glass requirements;
3. whether/when SAML and SCIM are justified, including deprovisioning,
   directory-source authority, role mapping, and failure behavior;
4. data residency, retention, support-access, and contractual terms;
5. customer-admin/workload/gate identity boundaries and safe migration plan.

## Safe fallback

Until ratified and implemented, the managed service must not claim federation.
Local gate safety remains independent of hosted login. No browser client may
receive a management service credential as a workaround.

## Alternatives considered

- Build a proprietary identity stack: rejected as a default because it expands
  credential, session, MFA, lifecycle, and recovery security scope.
- Enable SAML/SCIM before a lifecycle requirement: deferred; protocol support
  without tested provisioning/deprovisioning can create a false enterprise
  assurance claim.
- Put a reusable service API key in the browser: rejected; it violates the BFF
  and least-privilege boundary.

## Consequences and non-goals

This ADR does not promise MFA certification, SSO availability, SCIM support,
or customer identity-provider compatibility. It neither selects a vendor nor
creates a contract. It requires BFF/session and identity-provider failures to
fail before any governed mutation and never to weaken the open local gate.

## Evidence required after approval

- BFF, session, CSRF, CORS, expired-session, invitation, role-mapping,
  deprovisioning, rotation/revocation, and cross-tenant browser/API tests;
- provider-interface conformance and outage/failure-mode tests;
- support/access-review and privacy review evidence appropriate to the approved
  deployment model;
- updated target/runbook documentation that identifies the selected path and
  limitations.

## Downstream nodes and validation after unblock

Blocked/affected nodes: G103, G401, G501, G606.

After an approved path exists, run the affected package/browser integration
suite, cross-tenant/session negative tests, and the G103/G401/G501 validation
commands in [DELIVERY_DAG.yaml](../saas/DELIVERY_DAG.yaml).
