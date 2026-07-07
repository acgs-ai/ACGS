"""Enterprise identity integration — the Identity layer above the governed kernel.

The enforcement chain this module feeds (see ``docs/enterprise-iam.md``):

    Identity   — who is calling (this module: IdP adapters → Principal)
    Authority  — what they are granted (this module: RBACMapper → authority string
                 + optional :class:`~gove_zone.authz.PrincipalEntry` derivation)
    Policy     — whether this action is allowed (existing: RuleSetPolicy et al.)
    Receipt    — the verifiable decision (existing: DecisionReceipt)
    Execution  — the gated side effect (existing: execute_with_receipt)

Like :mod:`gove_zone.contracts`, this module is **purely additive**: it adds no
second enforcement path. The single fail-closed gate remains
:meth:`gove_zone.receipt.DecisionReceipt.verify` (surfaced through
:func:`gove_zone.executor.execute_with_receipt`). Identity resolution here
produces the *actor* and *authority* inputs that the existing kernel primitives
already bind into receipts; it never bypasses or weakens them.

Relationship to :mod:`gove_zone.authz` (B13 first slice): ``authz`` enforces a
flat principal → allowed-tools registry at the kernel/executor gate.
:class:`RBACMapper.principal_entry` derives those registry entries from
IdP-asserted group membership, so enterprise directory groups become the
source of truth for the existing enforcement seam — the seam itself is unchanged.

The three bundled providers (:class:`MockAzureADAdapter`, :class:`MockOktaAdapter`,
:class:`MockGoogleWorkspaceAdapter`) are **mocks**: in-memory token registries
that emulate each provider's claim dialect for integration tests and demos.
They perform no real OAuth/OIDC/SAML protocol exchange and no cryptographic
token validation. A production adapter implements the same
:class:`IdentityProviderAdapter` contract against the real IdP.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from gove_zone.audit import ChainHashAuditStore
from gove_zone.authz import PrincipalEntry
from gove_zone.errors import IdentityError, IdentityRejectionReason
from gove_zone.receipt import DecisionReceipt, Validator
from gove_zone.signing import ReceiptSigner
from gove_zone.tenant import TenantPolicyStore, evaluate_tenant_action


class CredentialType(StrEnum):
    """How a caller proves its identity to an identity provider.

    Values equal member names (StrEnum) so they serialise as plain strings,
    mirroring :class:`gove_zone.errors.ReceiptRejectionReason`.
    """

    # OAuth 2.0 bearer access token — interactive user grant or a
    # client-credentials grant for a service account.
    OAUTH_ACCESS_TOKEN = "OAUTH_ACCESS_TOKEN"
    # SSO session assertion — the SAML-assertion / OIDC-id-token analogue an
    # enterprise SSO flow hands to a relying party.
    SSO_ASSERTION = "SSO_ASSERTION"
    # Long-lived service-account credential (key file / client secret).
    SERVICE_ACCOUNT_KEY = "SERVICE_ACCOUNT_KEY"
    # Audience-bound federated token for workload identity (SPIFFE / GCP WIF /
    # Azure federated credentials style): no stored secret, must match audience.
    WORKLOAD_IDENTITY_TOKEN = "WORKLOAD_IDENTITY_TOKEN"


class PrincipalType(StrEnum):
    """What kind of principal a credential resolves to."""

    USER = "USER"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    WORKLOAD = "WORKLOAD"


# Which credential types may authenticate which kind of principal. Fail-closed:
# a combination outside this table is refused at issuance and at resolution.
_ALLOWED_CREDENTIALS: dict[PrincipalType, frozenset[CredentialType]] = {
    PrincipalType.USER: frozenset(
        {CredentialType.OAUTH_ACCESS_TOKEN, CredentialType.SSO_ASSERTION}
    ),
    PrincipalType.SERVICE_ACCOUNT: frozenset(
        {CredentialType.SERVICE_ACCOUNT_KEY, CredentialType.OAUTH_ACCESS_TOKEN}
    ),
    PrincipalType.WORKLOAD: frozenset({CredentialType.WORKLOAD_IDENTITY_TOKEN}),
}


def _parse_iso(value: str, *, field_name: str) -> datetime:
    """Parse an ISO-8601 timestamp, failing closed with :class:`IdentityError`.

    Offset-naive timestamps are rejected, mirroring the expiry check in
    :meth:`gove_zone.receipt.DecisionReceipt.verify`: silently assuming a zone
    for a naive timestamp can extend a credential's life (fail-open), so the
    ambiguity is refused instead.
    """
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise IdentityError(
            f"unparseable {field_name}: {value!r} (fail-closed)",
            reason_code=IdentityRejectionReason.TIMESTAMP_UNPARSEABLE,
        ) from exc
    if parsed.tzinfo is None:
        raise IdentityError(
            f"offset-naive {field_name}: {value!r} — naive timestamps are ambiguous "
            "and can fail open; supply an explicit UTC offset (fail-closed)",
            reason_code=IdentityRejectionReason.TIMESTAMP_NAIVE,
        )
    return parsed


@dataclass(frozen=True)
class Credential:
    """An opaque proof of identity presented to an adapter for resolution.

    ``audience`` is required for :attr:`CredentialType.WORKLOAD_IDENTITY_TOKEN`
    — an audience-unbound workload token is rejected at construction rather
    than resolving to a principal it was never issued for.
    """

    credential_type: CredentialType
    token: str
    audience: str = ""

    def __post_init__(self) -> None:
        # Coerce so a plain-string credential_type (== the enum but not `is` it)
        # cannot slip past identity checks; an unknown value raises ValueError.
        object.__setattr__(self, "credential_type", CredentialType(self.credential_type))
        if not self.token:
            raise ValueError("Credential.token is required (fail-closed)")
        if self.credential_type is CredentialType.WORKLOAD_IDENTITY_TOKEN and not self.audience:
            raise ValueError(
                "Credential.audience is required for WORKLOAD_IDENTITY_TOKEN (fail-closed)"
            )


@dataclass(frozen=True)
class Principal:
    """A resolved enterprise identity — the *who* behind a governance request.

    ``actor_id()`` is the canonical proposer string the kernel binds into
    receipts (``ToolCall.actor`` / ``DecisionReceipt.actor``). It is namespaced
    by provider and tenant, and the encoding is injective: ``provider_id`` and
    ``tenant_id`` may not contain the ``:`` separator (rejected at
    construction), so ``prov:tenant:subject`` parses unambiguously left-to-right
    and distinct principals can never encode to the same actor string —
    subjects themselves may contain ``:`` (e.g. SPIFFE ids).

    ``claims`` is snapshotted into a read-only mapping at construction, so a
    resolved principal cannot be mutated through an aliased dict, and the
    frozen dataclass stays hashable.
    """

    subject: str
    tenant_id: str
    provider_id: str
    principal_type: PrincipalType
    groups: frozenset[str] = frozenset()
    display_name: str = ""
    claims: Mapping[str, Any] = field(default_factory=dict, hash=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "principal_type", PrincipalType(self.principal_type))
        object.__setattr__(self, "claims", MappingProxyType(dict(self.claims)))
        if not self.subject:
            raise ValueError("Principal.subject is required (fail-closed)")
        if not self.tenant_id:
            raise ValueError("Principal.tenant_id is required (fail-closed)")
        if not self.provider_id:
            raise ValueError("Principal.provider_id is required (fail-closed)")
        if ":" in self.provider_id or ":" in self.tenant_id:
            raise ValueError(
                "Principal.provider_id and tenant_id may not contain ':' — it is the "
                "actor_id separator and would make actor encoding ambiguous (fail-closed)"
            )

    def actor_id(self) -> str:
        """Canonical, provider-namespaced actor string for receipts and authz."""
        return f"{self.provider_id}:{self.tenant_id}:{self.subject}"


class IdentityProviderAdapter(ABC):
    """Contract every identity-provider integration implements.

    An adapter turns an opaque :class:`Credential` into a verified
    :class:`Principal`, or raises :class:`~gove_zone.errors.IdentityError` —
    never a partially-populated principal. Resolution must be fail-closed:
    unknown token, revoked token, wrong credential type, audience mismatch,
    and expiry are all refusals, not warnings.
    """

    @property
    @abstractmethod
    def provider_id(self) -> str:
        """Stable identifier namespacing this provider's principals."""

    @property
    @abstractmethod
    def supported_credential_types(self) -> frozenset[CredentialType]:
        """Credential types this provider can resolve."""

    @abstractmethod
    def resolve(self, credential: Credential, *, now_iso: str | None = None) -> Principal:
        """Resolve *credential* to a :class:`Principal` or raise ``IdentityError``.

        ``now_iso`` injects the clock for expiry checks (mirrors
        ``DecisionReceipt.verify(now_iso=...)``); ``None`` means wall-clock UTC.
        """


@dataclass(frozen=True)
class _Registration:
    """A directory entry inside a mock provider."""

    subject: str
    principal_type: PrincipalType
    groups: frozenset[str]
    display_name: str
    audience: str
    claims: Mapping[str, Any]


@dataclass(frozen=True)
class _IssuedCredential:
    """One outstanding mock token and the constraints bound at issuance."""

    subject: str
    credential_type: CredentialType
    audience: str
    expires_at: str


class MockIdentityProvider(IdentityProviderAdapter):
    """In-memory mock IdP: register principals, issue opaque tokens, resolve them.

    Emulates the *observable contract* of an enterprise IdP — issuance-bound
    token type, audience binding, expiry, revocation — without any real
    protocol exchange. Tokens are opaque handles into an in-memory table, so a
    token that was never issued (or was revoked) can never resolve.
    """

    def __init__(
        self,
        *,
        provider_id: str,
        tenant_id: str,
        supported: frozenset[CredentialType] | None = None,
    ) -> None:
        if not provider_id:
            raise ValueError("provider_id is required (fail-closed)")
        if not tenant_id:
            raise ValueError("tenant_id is required (fail-closed)")
        self._provider_id = provider_id
        self._tenant_id = tenant_id
        self._supported = frozenset(CredentialType) if supported is None else supported
        self._registrations: dict[str, _Registration] = {}
        self._issued: dict[str, _IssuedCredential] = {}

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    @property
    def supported_credential_types(self) -> frozenset[CredentialType]:
        return self._supported

    # -- directory management -------------------------------------------------

    def _register(
        self,
        subject: str,
        principal_type: PrincipalType,
        *,
        groups: Iterable[str] = (),
        display_name: str = "",
        audience: str = "",
        claims: Mapping[str, Any] | None = None,
    ) -> None:
        if not subject:
            raise ValueError("subject is required (fail-closed)")
        if subject in self._registrations:
            raise ValueError(f"subject already registered: {subject!r}")
        self._registrations[subject] = _Registration(
            subject=subject,
            principal_type=principal_type,
            groups=frozenset(groups),
            display_name=display_name,
            audience=audience,
            claims=dict(claims or {}),
        )

    def register_user(
        self,
        subject: str,
        *,
        groups: Iterable[str] = (),
        display_name: str = "",
        claims: Mapping[str, Any] | None = None,
    ) -> None:
        """Register a human user (OAuth / SSO credentials)."""
        self._register(
            subject,
            PrincipalType.USER,
            groups=groups,
            display_name=display_name,
            claims=claims,
        )

    def register_service_account(
        self,
        subject: str,
        *,
        groups: Iterable[str] = (),
        display_name: str = "",
        claims: Mapping[str, Any] | None = None,
    ) -> None:
        """Register a service account (key / client-credentials OAuth)."""
        self._register(
            subject,
            PrincipalType.SERVICE_ACCOUNT,
            groups=groups,
            display_name=display_name,
            claims=claims,
        )

    def register_workload(
        self,
        subject: str,
        *,
        audience: str,
        groups: Iterable[str] = (),
        claims: Mapping[str, Any] | None = None,
    ) -> None:
        """Register a federated workload; its tokens are bound to *audience*."""
        if not audience:
            raise ValueError("workload registration requires an audience (fail-closed)")
        self._register(
            subject,
            PrincipalType.WORKLOAD,
            groups=groups,
            audience=audience,
            claims=claims,
        )

    # -- issuance / revocation ------------------------------------------------

    def issue_credential(
        self,
        subject: str,
        credential_type: CredentialType,
        *,
        expires_at: str = "",
    ) -> Credential:
        """Issue an opaque mock credential for a registered *subject*.

        Fail-closed on unknown subject, a credential type this provider does
        not support, or a type the subject's principal kind may not use
        (e.g. a workload can only hold audience-bound workload tokens).
        ``expires_at`` (ISO-8601) is optional; empty means non-expiring.
        """
        registration = self._registrations.get(subject)
        if registration is None:
            raise IdentityError(
                f"unknown subject: {subject!r} (fail-closed)",
                reason_code=IdentityRejectionReason.UNKNOWN_SUBJECT,
            )
        if credential_type not in self._supported:
            raise IdentityError(
                f"provider {self._provider_id!r} does not support {credential_type} (fail-closed)",
                reason_code=IdentityRejectionReason.UNSUPPORTED_CREDENTIAL_TYPE,
            )
        if credential_type not in _ALLOWED_CREDENTIALS[registration.principal_type]:
            raise IdentityError(
                f"{registration.principal_type} principal {subject!r} cannot hold a "
                f"{credential_type} credential (fail-closed)",
                reason_code=IdentityRejectionReason.CREDENTIAL_KIND_NOT_ALLOWED,
            )
        token = uuid.uuid4().hex
        while token in self._issued:  # never silently rebind a live token
            token = uuid.uuid4().hex
        self._issued[token] = _IssuedCredential(
            subject=subject,
            credential_type=credential_type,
            audience=registration.audience,
            expires_at=expires_at,
        )
        return Credential(
            credential_type=credential_type,
            token=token,
            audience=registration.audience,
        )

    def revoke_credentials(self, subject: str) -> int:
        """Revoke every outstanding credential for *subject*; returns the count."""
        revoked = [token for token, iss in self._issued.items() if iss.subject == subject]
        for token in revoked:
            del self._issued[token]
        return len(revoked)

    # -- resolution -------------------------------------------------------------

    def resolve(self, credential: Credential, *, now_iso: str | None = None) -> Principal:
        if credential.credential_type not in self._supported:
            raise IdentityError(
                f"provider {self._provider_id!r} does not support "
                f"{credential.credential_type} (fail-closed)",
                reason_code=IdentityRejectionReason.UNSUPPORTED_CREDENTIAL_TYPE,
            )
        issued = self._issued.get(credential.token)
        if issued is None:
            raise IdentityError(
                "unknown or revoked credential (fail-closed)",
                reason_code=IdentityRejectionReason.UNKNOWN_OR_REVOKED_CREDENTIAL,
            )
        if issued.credential_type is not credential.credential_type:
            raise IdentityError(
                f"credential type mismatch: presented as {credential.credential_type}, "
                f"issued as {issued.credential_type} (fail-closed)",
                reason_code=IdentityRejectionReason.CREDENTIAL_TYPE_MISMATCH,
            )
        if issued.audience and credential.audience != issued.audience:
            raise IdentityError(
                f"audience mismatch: token bound to {issued.audience!r}, "
                f"presented for {credential.audience!r} (fail-closed)",
                reason_code=IdentityRejectionReason.AUDIENCE_MISMATCH,
            )
        if issued.expires_at:
            expires = _parse_iso(issued.expires_at, field_name="expires_at")
            now = _parse_iso(now_iso, field_name="now_iso") if now_iso else datetime.now(UTC)
            # `>=` is deliberately one tick stricter than the receipt gate's `>`:
            # at the exact boundary the identity layer refuses (fail-closed).
            if now >= expires:
                raise IdentityError(
                    f"credential expired at {issued.expires_at} (fail-closed)",
                    reason_code=IdentityRejectionReason.CREDENTIAL_EXPIRED,
                )
        registration = self._registrations[issued.subject]
        claims = dict(registration.claims)
        claims.update(self._provider_claims(registration))
        return Principal(
            subject=registration.subject,
            tenant_id=self._tenant_id,
            provider_id=self._provider_id,
            principal_type=registration.principal_type,
            groups=registration.groups,
            display_name=registration.display_name,
            claims=claims,
        )

    def _provider_claims(self, registration: _Registration) -> dict[str, Any]:
        """Provider-dialect claims merged into the resolved principal. Hook."""
        return {}


class MockAzureADAdapter(MockIdentityProvider):
    """Mock Azure AD / Microsoft Entra ID. ``tenant_id`` plays the directory ``tid``.

    ``provider_id`` is deliberately ``mock-azure-ad`` (not ``azure-ad``): a
    mock-resolved principal must never mint the same actor namespace — and thus
    the same receipts and authz registry entries — as a real production
    adapter. Provenance is visible in every actor string.
    """

    def __init__(self, *, tenant_id: str) -> None:
        super().__init__(provider_id="mock-azure-ad", tenant_id=tenant_id)

    def _provider_claims(self, registration: _Registration) -> dict[str, Any]:
        return {
            "tid": self.tenant_id,
            "oid": registration.subject,
            "upn": registration.display_name or registration.subject,
        }


class MockOktaAdapter(MockIdentityProvider):
    """Mock Okta org. ``tenant_id`` plays the Okta org name.

    ``provider_id`` is ``mock-okta`` — see :class:`MockAzureADAdapter` on why
    mocks never share a real adapter's actor namespace.
    """

    def __init__(self, *, tenant_id: str) -> None:
        super().__init__(provider_id="mock-okta", tenant_id=tenant_id)

    def _provider_claims(self, registration: _Registration) -> dict[str, Any]:
        return {
            "sub": registration.subject,
            "iss": f"https://{self.tenant_id}.okta.example/oauth2/default",
            "preferred_username": registration.display_name or registration.subject,
        }


class MockGoogleWorkspaceAdapter(MockIdentityProvider):
    """Mock Google Workspace. ``tenant_id`` plays the hosted domain (``hd``).

    ``provider_id`` is ``mock-google-workspace`` — see
    :class:`MockAzureADAdapter` on why mocks never share a real adapter's
    actor namespace.
    """

    def __init__(self, *, tenant_id: str) -> None:
        super().__init__(provider_id="mock-google-workspace", tenant_id=tenant_id)

    def _provider_claims(self, registration: _Registration) -> dict[str, Any]:
        subject = registration.subject
        email = subject if "@" in subject else f"{subject}@{self.tenant_id}"
        return {"sub": subject, "email": email, "hd": self.tenant_id}


@dataclass(frozen=True)
class RoleDefinition:
    """One governance role: the authority grant it confers and the tools it opens.

    ``allowed_tools`` follows :class:`~gove_zone.authz.PrincipalEntry` semantics
    — ``None`` authorizes every tool, an empty frozenset authorizes none. The
    default is the empty frozenset (fail-closed): a role grants no executor
    tools unless the integrator says which.
    """

    role: str
    authority: str
    allowed_tools: frozenset[str] | None = frozenset()

    def __post_init__(self) -> None:
        if not self.role:
            raise ValueError("RoleDefinition.role is required (fail-closed)")
        if not self.authority:
            raise ValueError("RoleDefinition.authority is required (fail-closed)")
        if "+" in self.authority:
            raise ValueError(
                "RoleDefinition.authority may not contain '+' — it is the grant-set "
                "join separator, and an authority containing it would be ambiguous "
                "with a multi-role grant (fail-closed)"
            )


class RBACMapper:
    """Maps IdP-asserted group membership to governance roles — the Authority layer.

    The mapping is declarative and fail-closed: a principal whose groups match
    no mapping has **no** role, and every lookup on it raises
    :class:`~gove_zone.errors.IdentityError` rather than defaulting to a
    permissive role. Group and role names are exact-match strings.
    """

    def __init__(
        self,
        *,
        roles: Iterable[RoleDefinition],
        group_to_role: Mapping[str, str],
    ) -> None:
        self._roles: dict[str, RoleDefinition] = {}
        for definition in roles:
            if definition.role in self._roles:
                raise ValueError(f"duplicate role definition: {definition.role!r}")
            self._roles[definition.role] = definition
        for group, role in group_to_role.items():
            if role not in self._roles:
                raise ValueError(f"group {group!r} maps to unknown role {role!r}")
        self._group_to_role = dict(group_to_role)

    def roles_for(self, principal: Principal) -> tuple[RoleDefinition, ...]:
        """The principal's roles, sorted by role name. Empty → ``IdentityError``."""
        matched = sorted(
            {self._group_to_role[g] for g in principal.groups if g in self._group_to_role}
        )
        if not matched:
            raise IdentityError(
                f"no role mapped for principal {principal.actor_id()!r} (fail-closed)",
                reason_code=IdentityRejectionReason.NO_ROLE_MAPPED,
            )
        return tuple(self._roles[name] for name in matched)

    def authority_for(self, principal: Principal) -> str:
        """Deterministic authority grant string minted into the receipt.

        Multiple roles combine as their sorted, ``+``-joined authorities, so the
        same principal always yields the same authority regardless of group order.
        Distinct roles sharing an identical authority string collapse to one copy
        (intentional: the grant set is a set, never a multiset).
        """
        return "+".join(sorted({r.authority for r in self.roles_for(principal)}))

    def principal_entry(self, principal: Principal) -> PrincipalEntry:
        """Derive the :mod:`gove_zone.authz` registry entry for this principal.

        Tools are the union across roles; any role with ``allowed_tools=None``
        (all tools) makes the union ``None``. Feed the result into a
        :class:`~gove_zone.authz.PrincipalRegistry` to enforce RBAC at the
        existing executor/kernel authz seam.
        """
        roles = self.roles_for(principal)
        allowed: frozenset[str] | None
        if any(r.allowed_tools is None for r in roles):
            allowed = None
        else:
            allowed = frozenset().union(
                *(r.allowed_tools for r in roles if r.allowed_tools is not None)
            )
        return PrincipalEntry(principal_id=principal.actor_id(), allowed_tools=allowed)


def govern_identity_action(
    adapter: IdentityProviderAdapter,
    credential: Credential,
    *,
    policy_store: TenantPolicyStore,
    action: str,
    args: dict[str, Any],
    execution_boundary: str,
    request_id: str,
    rbac: RBACMapper,
    validator: Validator,
    audit_store: ChainHashAuditStore,
    goal: str = "",
    expires_at: str = "",
    signer: ReceiptSigner | None = None,
    now_iso: str | None = None,
) -> DecisionReceipt:
    """Run the full Identity → Authority → Policy → Receipt chain for one action.

    1. **Identity** — *adapter* resolves *credential* to a :class:`Principal`
       (raises :class:`~gove_zone.errors.IdentityError` on any defect).
    2. **Authority** — *rbac* maps the principal's groups to a deterministic
       authority grant (raises ``IdentityError`` if no role is mapped), and the
       proposed *action* must be within the principal's role-granted tool set
       (union of ``RoleDefinition.allowed_tools``; any all-tools role opens
       all). A role set that does not grant *action* refuses here, before any
       policy evaluation — the fail-closed ``allowed_tools`` default is
       enforced by this chain, not just by an optional executor registry.
    3. **Policy → Receipt** — delegates to
       :func:`gove_zone.tenant.evaluate_tenant_action` with the principal's own
       tenant as both target and requester (an IdP-resolved principal can only
       request within its home tenant), the namespaced ``actor_id()`` as
       proposer, and the distinct MACI *validator*.

    **Execution** stays where it always was: pass the returned receipt to
    :func:`gove_zone.executor.execute_with_receipt` with
    ``expected_actor=principal.actor_id()``. This function performs no side
    effect and adds no second enforcement path.
    """
    principal = adapter.resolve(credential, now_iso=now_iso)
    authority = rbac.authority_for(principal)
    entry = rbac.principal_entry(principal)
    if entry.allowed_tools is not None and action not in entry.allowed_tools:
        raise IdentityError(
            f"action {action!r} is not granted by any role of principal "
            f"{principal.actor_id()!r} (fail-closed)",
            reason_code=IdentityRejectionReason.TOOL_NOT_PERMITTED_BY_ROLE,
        )
    return evaluate_tenant_action(
        policy_store,
        principal.tenant_id,
        principal.tenant_id,
        action,
        args,
        goal=goal,
        execution_boundary=execution_boundary,
        request_id=request_id,
        actor=principal.actor_id(),
        validator=validator,
        authority=authority,
        audit_store=audit_store,
        expires_at=expires_at,
        signer=signer,
    )
