"""Role-based access control.

RBAC is the *authorization* layer (may this principal call this endpoint at
all); the governance membrane is the *policy* layer (does the organization's
active policy bundle permit this specific action). An RBAC denial produces no
side effect and therefore needs no receipt; a policy denial is a governed
decision and is receipted.
"""

from __future__ import annotations

import enum


class Role(enum.StrEnum):
    ORG_ADMIN = "org_admin"
    POLICY_AUTHOR = "policy_author"
    AGENT_OPERATOR = "agent_operator"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class Permission(enum.StrEnum):
    ORG_READ = "org.read"
    USER_MANAGE = "user.manage"
    USER_READ = "user.read"
    AGENT_REGISTER = "agent.register"
    AGENT_MANAGE = "agent.manage"
    AGENT_READ = "agent.read"
    APPROVAL_VOTE = "approval.vote"
    APPROVAL_RESUME = "approval.resume"
    RUNTIME_ENROLLMENT_MANAGE = "runtime-enrollment.manage"
    RUNTIME_IDENTITY_REVOKE = "runtime-identity.revoke"
    RUNTIME_FLEET_READ = "runtime-fleet.read"
    POLICY_PUBLISH = "policy.publish"
    POLICY_ACTIVATE = "policy.activate"
    POLICY_READ = "policy.read"
    POLICY_SIMULATE = "policy.simulate"
    RECEIPT_READ = "receipt.read"
    DASHBOARD_READ = "dashboard.read"
    EXPORT_CREATE = "export.create"
    EXPORT_READ = "export.read"


_ALL: frozenset[Role] = frozenset(Role)

PERMISSIONS: dict[Permission, frozenset[Role]] = {
    Permission.ORG_READ: _ALL,
    Permission.USER_MANAGE: frozenset({Role.ORG_ADMIN}),
    Permission.USER_READ: frozenset({Role.ORG_ADMIN, Role.AUDITOR}),
    Permission.AGENT_REGISTER: frozenset({Role.ORG_ADMIN, Role.AGENT_OPERATOR}),
    Permission.AGENT_MANAGE: frozenset({Role.ORG_ADMIN, Role.AGENT_OPERATOR}),
    Permission.AGENT_READ: _ALL,
    Permission.APPROVAL_VOTE: frozenset({Role.ORG_ADMIN}),
    Permission.APPROVAL_RESUME: frozenset({Role.ORG_ADMIN}),
    Permission.RUNTIME_ENROLLMENT_MANAGE: frozenset({Role.ORG_ADMIN, Role.AGENT_OPERATOR}),
    Permission.RUNTIME_IDENTITY_REVOKE: frozenset({Role.ORG_ADMIN}),
    Permission.RUNTIME_FLEET_READ: frozenset({Role.ORG_ADMIN, Role.AGENT_OPERATOR, Role.AUDITOR}),
    Permission.POLICY_PUBLISH: frozenset({Role.ORG_ADMIN, Role.POLICY_AUTHOR}),
    Permission.POLICY_ACTIVATE: frozenset({Role.ORG_ADMIN}),
    Permission.POLICY_READ: _ALL,
    Permission.POLICY_SIMULATE: frozenset({Role.ORG_ADMIN, Role.POLICY_AUTHOR}),
    Permission.RECEIPT_READ: _ALL,
    Permission.DASHBOARD_READ: _ALL,
    Permission.EXPORT_CREATE: frozenset({Role.ORG_ADMIN, Role.AUDITOR}),
    Permission.EXPORT_READ: frozenset({Role.ORG_ADMIN, Role.AUDITOR}),
}


def role_allows(role: Role, permission: Permission) -> bool:
    """Fail closed: an unknown permission grants nothing."""
    return role in PERMISSIONS.get(permission, frozenset())
