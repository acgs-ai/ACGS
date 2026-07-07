"""Enterprise identity integration — the Identity/Authority layers above the kernel.

Proves, per provider (Azure AD / Okta / Google Workspace mocks):

- every credential type resolves to a correct, provider-namespaced Principal
  (OAuth, SSO, service-account key, audience-bound workload token);
- resolution is fail-closed: unknown/revoked token, type mismatch, audience
  mismatch, expiry, unsupported type all raise IdentityError;
- RBAC mapping is fail-closed and deterministic (groups → roles → authority,
  and derivation of the gove_zone.authz PrincipalEntry);
- the full chain Identity → Authority → Policy → Receipt → Execution holds:
  an IdP-resolved principal's receipt passes the executor gate bound to
  ``expected_actor=principal.actor_id()``, and a foreign actor cannot use it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from gove_zone import (
    ChainHashAuditStore,
    Credential,
    CredentialType,
    IdentityError,
    MockAzureADAdapter,
    MockGoogleWorkspaceAdapter,
    MockIdentityProvider,
    MockOktaAdapter,
    Principal,
    PrincipalType,
    RBACMapper,
    ReceiptValidationError,
    RoleDefinition,
    RuleSetPolicy,
    TenantPolicyStore,
    Validator,
    execute_with_receipt,
    govern_identity_action,
)

TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
VALIDATOR = Validator("constitutional-council")

ALL_ADAPTERS = [MockAzureADAdapter, MockOktaAdapter, MockGoogleWorkspaceAdapter]


def _adapter(cls: type[MockIdentityProvider]) -> MockIdentityProvider:
    return cls(tenant_id=TENANT)


def _rbac(**overrides: Any) -> RBACMapper:
    kwargs: dict[str, Any] = {
        "roles": [
            RoleDefinition(
                role="writer",
                authority="tenant-A/write-grant",
                allowed_tools=frozenset({"runtime.file.write"}),
            ),
            RoleDefinition(role="admin", authority="tenant-A/admin-grant", allowed_tools=None),
        ],
        "group_to_role": {"eng": "writer", "platform-admins": "admin"},
    }
    kwargs.update(overrides)
    return RBACMapper(**kwargs)


def _allow_policy() -> RuleSetPolicy:
    # Denies a different tool so the governed action falls through to default ALLOW.
    return RuleSetPolicy.from_dict(
        {"id": "policy-A", "rules": [{"id": "R1", "effect": "deny", "tools": ["shell.exec"]}]}
    )


# ---------------------------------------------------------------- resolution


@pytest.mark.parametrize("adapter_cls", ALL_ADAPTERS)
def test_oauth_user_resolves_to_namespaced_principal(
    adapter_cls: type[MockIdentityProvider],
) -> None:
    idp = _adapter(adapter_cls)
    idp.register_user("alice", groups=["eng"], display_name="Alice")
    credential = idp.issue_credential("alice", CredentialType.OAUTH_ACCESS_TOKEN)

    principal = idp.resolve(credential)

    assert principal.subject == "alice"
    assert principal.tenant_id == TENANT
    assert principal.provider_id == idp.provider_id
    assert principal.principal_type is PrincipalType.USER
    assert principal.groups == frozenset({"eng"})
    assert principal.actor_id() == f"{idp.provider_id}:{TENANT}:alice"


@pytest.mark.parametrize("adapter_cls", ALL_ADAPTERS)
def test_sso_assertion_resolves_user(adapter_cls: type[MockIdentityProvider]) -> None:
    idp = _adapter(adapter_cls)
    idp.register_user("alice")
    credential = idp.issue_credential("alice", CredentialType.SSO_ASSERTION)
    assert idp.resolve(credential).principal_type is PrincipalType.USER


@pytest.mark.parametrize("adapter_cls", ALL_ADAPTERS)
def test_service_account_key_resolves(adapter_cls: type[MockIdentityProvider]) -> None:
    idp = _adapter(adapter_cls)
    idp.register_service_account("ci-deployer", groups=["eng"])
    credential = idp.issue_credential("ci-deployer", CredentialType.SERVICE_ACCOUNT_KEY)
    principal = idp.resolve(credential)
    assert principal.principal_type is PrincipalType.SERVICE_ACCOUNT


@pytest.mark.parametrize("adapter_cls", ALL_ADAPTERS)
def test_workload_identity_is_audience_bound(adapter_cls: type[MockIdentityProvider]) -> None:
    idp = _adapter(adapter_cls)
    idp.register_workload("payments-svc", audience="https://gove-zone.example/gate")
    credential = idp.issue_credential("payments-svc", CredentialType.WORKLOAD_IDENTITY_TOKEN)
    assert credential.audience == "https://gove-zone.example/gate"

    principal = idp.resolve(credential)
    assert principal.principal_type is PrincipalType.WORKLOAD

    # Same token replayed for a different audience is refused.
    forged = Credential(
        credential_type=CredentialType.WORKLOAD_IDENTITY_TOKEN,
        token=credential.token,
        audience="https://attacker.example",
    )
    with pytest.raises(IdentityError, match="audience mismatch"):
        idp.resolve(forged)


def test_provider_claim_dialects() -> None:
    azure = MockAzureADAdapter(tenant_id=TENANT)
    okta = MockOktaAdapter(tenant_id="acme")
    google = MockGoogleWorkspaceAdapter(tenant_id="acme.example")
    for idp in (azure, okta, google):
        idp.register_user("alice")

    azure_claims = azure.resolve(
        azure.issue_credential("alice", CredentialType.OAUTH_ACCESS_TOKEN)
    ).claims
    assert azure_claims["tid"] == TENANT
    assert azure_claims["oid"] == "alice"

    okta_claims = okta.resolve(
        okta.issue_credential("alice", CredentialType.OAUTH_ACCESS_TOKEN)
    ).claims
    assert okta_claims["sub"] == "alice"
    assert "okta.example" in okta_claims["iss"]

    google_claims = google.resolve(
        google.issue_credential("alice", CredentialType.OAUTH_ACCESS_TOKEN)
    ).claims
    assert google_claims["hd"] == "acme.example"
    assert google_claims["email"] == "alice@acme.example"


def test_actor_ids_never_collide_across_providers() -> None:
    principals = []
    for cls in ALL_ADAPTERS:
        idp = _adapter(cls)
        idp.register_user("alice")
        credential = idp.issue_credential("alice", CredentialType.OAUTH_ACCESS_TOKEN)
        principals.append(idp.resolve(credential))
    actor_ids = {p.actor_id() for p in principals}
    assert len(actor_ids) == len(ALL_ADAPTERS)


# ---------------------------------------------------------------- fail-closed


def test_unknown_token_fails_closed() -> None:
    idp = MockAzureADAdapter(tenant_id=TENANT)
    with pytest.raises(IdentityError, match="unknown or revoked"):
        idp.resolve(Credential(credential_type=CredentialType.OAUTH_ACCESS_TOKEN, token="bogus"))


def test_revoked_token_fails_closed() -> None:
    idp = MockOktaAdapter(tenant_id=TENANT)
    idp.register_user("alice")
    credential = idp.issue_credential("alice", CredentialType.OAUTH_ACCESS_TOKEN)
    assert idp.revoke_credentials("alice") == 1
    with pytest.raises(IdentityError, match="unknown or revoked"):
        idp.resolve(credential)


def test_credential_type_mismatch_fails_closed() -> None:
    idp = MockAzureADAdapter(tenant_id=TENANT)
    idp.register_user("alice")
    sso = idp.issue_credential("alice", CredentialType.SSO_ASSERTION)
    relabeled = Credential(credential_type=CredentialType.OAUTH_ACCESS_TOKEN, token=sso.token)
    with pytest.raises(IdentityError, match="credential type mismatch"):
        idp.resolve(relabeled)


def test_expired_token_fails_closed_and_live_token_passes() -> None:
    idp = MockGoogleWorkspaceAdapter(tenant_id="acme.example")
    idp.register_user("alice")
    credential = idp.issue_credential(
        "alice", CredentialType.OAUTH_ACCESS_TOKEN, expires_at="2026-01-01T00:00:00+00:00"
    )
    assert idp.resolve(credential, now_iso="2025-12-31T23:59:59+00:00").subject == "alice"
    with pytest.raises(IdentityError, match="expired"):
        idp.resolve(credential, now_iso="2026-01-01T00:00:00+00:00")


def test_workload_cannot_hold_non_workload_credentials_and_vice_versa() -> None:
    idp = MockAzureADAdapter(tenant_id=TENANT)
    idp.register_workload("payments-svc", audience="aud-1")
    idp.register_user("alice")
    with pytest.raises(IdentityError, match="cannot hold"):
        idp.issue_credential("payments-svc", CredentialType.OAUTH_ACCESS_TOKEN)
    with pytest.raises(IdentityError, match="cannot hold"):
        idp.issue_credential("alice", CredentialType.WORKLOAD_IDENTITY_TOKEN)


def test_unsupported_credential_type_fails_closed_at_both_ends() -> None:
    idp = MockAzureADAdapter(tenant_id=TENANT)
    sso_only = MockIdentityProvider(
        provider_id="sso-only",
        tenant_id=TENANT,
        supported=frozenset({CredentialType.SSO_ASSERTION}),
    )
    sso_only.register_user("alice")
    with pytest.raises(IdentityError, match="does not support"):
        sso_only.issue_credential("alice", CredentialType.OAUTH_ACCESS_TOKEN)
    idp.register_user("alice")
    oauth = idp.issue_credential("alice", CredentialType.OAUTH_ACCESS_TOKEN)
    with pytest.raises(IdentityError, match="does not support"):
        sso_only.resolve(oauth)


def test_constructors_fail_closed() -> None:
    with pytest.raises(ValueError, match="token is required"):
        Credential(credential_type=CredentialType.OAUTH_ACCESS_TOKEN, token="")
    with pytest.raises(ValueError, match="audience is required"):
        Credential(credential_type=CredentialType.WORKLOAD_IDENTITY_TOKEN, token="t")
    with pytest.raises(ValueError, match="subject is required"):
        Principal(subject="", tenant_id=TENANT, provider_id="x", principal_type=PrincipalType.USER)
    with pytest.raises(ValueError, match="tenant_id is required"):
        Principal(subject="a", tenant_id="", provider_id="x", principal_type=PrincipalType.USER)
    with pytest.raises(ValueError, match="audience"):
        MockAzureADAdapter(tenant_id=TENANT).register_workload("w", audience="")
    with pytest.raises(ValueError, match="already registered"):
        idp = MockAzureADAdapter(tenant_id=TENANT)
        idp.register_user("alice")
        idp.register_user("alice")


# ---------------------------------------------------------------- RBAC mapping


def _principal(groups: frozenset[str]) -> Principal:
    return Principal(
        subject="alice",
        tenant_id=TENANT,
        provider_id="azure-ad",
        principal_type=PrincipalType.USER,
        groups=groups,
    )


def test_rbac_maps_groups_to_roles_and_authority() -> None:
    rbac = _rbac()
    principal = _principal(frozenset({"eng"}))
    roles = rbac.roles_for(principal)
    assert [r.role for r in roles] == ["writer"]
    assert rbac.authority_for(principal) == "tenant-A/write-grant"


def test_rbac_multi_role_authority_is_deterministic() -> None:
    rbac = _rbac()
    principal = _principal(frozenset({"platform-admins", "eng"}))
    assert rbac.authority_for(principal) == "tenant-A/admin-grant+tenant-A/write-grant"


def test_rbac_no_mapped_role_fails_closed() -> None:
    rbac = _rbac()
    with pytest.raises(IdentityError, match="no role mapped"):
        rbac.roles_for(_principal(frozenset({"marketing"})))
    with pytest.raises(IdentityError, match="no role mapped"):
        rbac.roles_for(_principal(frozenset()))


def test_rbac_unknown_role_target_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="unknown role"):
        _rbac(group_to_role={"eng": "nonexistent"})


def test_rbac_duplicate_role_definition_rejected() -> None:
    duplicate = [
        RoleDefinition(role="writer", authority="a"),
        RoleDefinition(role="writer", authority="b"),
    ]
    with pytest.raises(ValueError, match="duplicate role"):
        RBACMapper(roles=duplicate, group_to_role={})


def test_rbac_principal_entry_union_and_all_tools() -> None:
    rbac = _rbac()
    writer_entry = rbac.principal_entry(_principal(frozenset({"eng"})))
    assert writer_entry.principal_id == "azure-ad:tenant-A:alice"
    assert writer_entry.allowed_tools == frozenset({"runtime.file.write"})
    # An all-tools role (allowed_tools=None) dominates the union.
    admin_entry = rbac.principal_entry(_principal(frozenset({"eng", "platform-admins"})))
    assert admin_entry.allowed_tools is None


def test_role_definition_defaults_to_no_tools() -> None:
    role = RoleDefinition(role="auditor", authority="tenant-A/read-grant")
    rbac = RBACMapper(roles=[role], group_to_role={"auditors": "auditor"})
    entry = rbac.principal_entry(_principal(frozenset({"auditors"})))
    assert entry.allowed_tools == frozenset()


# ------------------------------------------- full chain: Identity → Execution


class SideEffect:
    def __init__(self) -> None:
        self.ran = False

    def run(self, **kwargs: Any) -> str:
        self.ran = True
        return "executed"


@pytest.mark.parametrize("adapter_cls", ALL_ADAPTERS)
def test_identity_to_execution_chain(
    adapter_cls: type[MockIdentityProvider], tmp_path: Path
) -> None:
    idp = _adapter(adapter_cls)
    idp.register_user("alice", groups=["eng"])
    credential = idp.issue_credential("alice", CredentialType.OAUTH_ACCESS_TOKEN)
    principal = idp.resolve(credential)

    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle(TENANT, _allow_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    rbac = _rbac()

    receipt = govern_identity_action(
        idp,
        credential,
        policy_store=store,
        action="runtime.file.write",
        args={"path": "safe.txt", "content": "hi"},
        execution_boundary=BOUNDARY,
        request_id="req-1",
        rbac=rbac,
        validator=VALIDATOR,
        audit_store=audit,
    )
    assert receipt.decision == "allow"
    assert receipt.actor == principal.actor_id()
    assert receipt.authority == "tenant-A/write-grant"
    assert receipt.tenant_id == TENANT

    effect = SideEffect()
    result = execute_with_receipt(
        effect.run,
        {"path": "safe.txt", "content": "hi"},
        receipt,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action="runtime.file.write",
        expected_actor=principal.actor_id(),
        require_signature=False,
    )
    assert result == "executed"
    assert effect.ran


def test_foreign_actor_cannot_use_identity_receipt(tmp_path: Path) -> None:
    idp = MockAzureADAdapter(tenant_id=TENANT)
    idp.register_user("alice", groups=["eng"])
    credential = idp.issue_credential("alice", CredentialType.OAUTH_ACCESS_TOKEN)

    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle(TENANT, _allow_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")

    receipt = govern_identity_action(
        idp,
        credential,
        policy_store=store,
        action="runtime.file.write",
        args={"path": "safe.txt"},
        execution_boundary=BOUNDARY,
        request_id="req-1",
        rbac=_rbac(),
        validator=VALIDATOR,
        audit_store=audit,
    )

    effect = SideEffect()
    with pytest.raises(ReceiptValidationError):
        execute_with_receipt(
            effect.run,
            {"path": "safe.txt"},
            receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action="runtime.file.write",
            expected_actor="okta:tenant-A:mallory",
            require_signature=False,
        )
    assert not effect.ran


def test_chain_refuses_before_policy_on_identity_defect(tmp_path: Path) -> None:
    idp = MockAzureADAdapter(tenant_id=TENANT)
    idp.register_user("alice", groups=["marketing"])  # no mapped role
    credential = idp.issue_credential("alice", CredentialType.OAUTH_ACCESS_TOKEN)

    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle(TENANT, _allow_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")

    with pytest.raises(IdentityError, match="no role mapped"):
        govern_identity_action(
            idp,
            credential,
            policy_store=store,
            action="runtime.file.write",
            args={"path": "safe.txt"},
            execution_boundary=BOUNDARY,
            request_id="req-1",
            rbac=_rbac(),
            validator=VALIDATOR,
            audit_store=audit,
        )
