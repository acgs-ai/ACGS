from __future__ import annotations

from fnmatch import fnmatchcase
from time import perf_counter
from typing import Any

from governance.models import ActionRequest, GateResult


class AuthorityGate:
    """Role/action/scope/limit gate.

    The gate is deterministic and fail-closed:
    missing role, missing action, missing scope, malformed config, or exceeded limits all deny.
    """

    name = "authority"

    def __init__(self, roles_bundle: dict[str, Any]):
        self.roles_bundle = roles_bundle
        self.roles = roles_bundle.get("roles", {})
        self.version = str(roles_bundle.get("version", "unknown"))

    def validate(self, request: ActionRequest) -> GateResult:
        started = perf_counter()

        if request.tenant != request.actor.tenant and not request.metadata.get("cross_tenant_delegation"):
            return self._deny(
                started,
                "AUTH_TENANT_MISMATCH",
                f"Actor tenant '{request.actor.tenant}' does not match request tenant '{request.tenant}'.",
                {"actor_tenant": request.actor.tenant, "request_tenant": request.tenant},
                remediation="Set request.tenant = actor.tenant or include metadata.cross_tenant_delegation",
            )

        if self._normalize_resource(request.resource) is None:
            return self._deny(
                started,
                "AUTH_RESOURCE_INVALID",
                f"Resource '{request.resource}' contains path-traversal segments or is absolute.",
                {"resource": request.resource},
                remediation="Resource must not contain '..' or start with '/'",
            )

        role_name = request.actor.role
        role_def = self.roles.get(role_name)

        if not isinstance(role_def, dict):
            return self._deny(
                started,
                "AUTH_ROLE_UNKNOWN",
                f"Unknown role '{role_name}'.",
                {"actor_id": request.actor.id, "role": role_name},
                remediation="Add the role to roles.json or correct actor.role",
            )

        allowed_actions = list(role_def.get("actions", []))
        if "*" not in allowed_actions and request.action_type not in allowed_actions:
            return self._deny(
                started,
                "AUTH_ACTION_DENIED",
                f"Role '{role_name}' cannot execute action '{request.action_type}'.",
                {"allowed_actions": allowed_actions},
                remediation="Use a role that lists this action_type, or add it to the role's actions",
            )

        allowed_scopes = list(role_def.get("scopes", [])) + list(request.actor.scopes)
        if not self._scope_allowed(request.resource, allowed_scopes):
            return self._deny(
                started,
                "AUTH_SCOPE_DENIED",
                f"Role '{role_name}' has no scope for resource '{request.resource}'.",
                {"allowed_scopes": allowed_scopes, "resource": request.resource},
                remediation="Add a matching scope to the role or actor.scopes",
            )

        required_maci_role = request.metadata.get("maci_required_role")
        if required_maci_role:
            maci_roles = set(role_def.get("maci_roles", []))
            if required_maci_role not in maci_roles:
                return self._deny(
                    started,
                    "AUTH_MACI_ROLE_DENIED",
                    f"Role '{role_name}' lacks MACI role '{required_maci_role}'.",
                    {"required_maci_role": required_maci_role, "maci_roles": sorted(maci_roles)},
                    remediation="Grant the required maci_role to this role in roles.json, or use a role that already has it",
                )

        if request.amount_cents is not None:
            limits = role_def.get("limits", {})
            single_limit = limits.get("single_amount_cents")
            if single_limit is not None and request.amount_cents > int(single_limit):
                return self._deny(
                    started,
                    "AUTH_LIMIT_EXCEEDED",
                    f"Amount {request.amount_cents} exceeds single-action limit {single_limit}.",
                    {"amount_cents": request.amount_cents, "single_amount_cents": single_limit},
                    remediation="Reduce amount_cents or use a role with a higher single_amount_cents limit",
                )

        return GateResult(
            gate=self.name,
            allowed=True,
            reason_codes=["AUTH_ALLOWED"],
            reasons=[f"Role '{role_name}' is authorized for action/resource."],
            rule_ids=[f"ROLE::{role_name}"],
            evidence={
                "role_version": self.version,
                "actor_id": request.actor.id,
                "role": role_name,
                "matched_scope": self._matched_scope(request.resource, allowed_scopes),
            },
            latency_ms=self._elapsed_ms(started),
        )

    @staticmethod
    def _normalize_resource(resource: str) -> str | None:
        if not isinstance(resource, str) or not resource:
            return None
        if resource != resource.strip():
            return None
        if resource.startswith("/"):
            return None
        segments = resource.split("/")
        if any(segment == ".." for segment in segments):
            return None
        return resource

    @staticmethod
    def _scope_allowed(resource: str, scopes: list[str]) -> bool:
        return any(scope == "*" or fnmatchcase(resource, scope) for scope in scopes)

    @staticmethod
    def _matched_scope(resource: str, scopes: list[str]) -> str | None:
        for scope in scopes:
            if scope == "*" or fnmatchcase(resource, scope):
                return scope
        return None

    def _deny(
        self,
        started: float,
        code: str,
        reason: str,
        evidence: dict[str, Any],
        *,
        remediation: str | None = None,
    ) -> GateResult:
        return GateResult(
            gate=self.name,
            allowed=False,
            reason_codes=[code],
            reasons=[reason],
            rule_ids=[],
            evidence={"role_version": self.version, **evidence},
            latency_ms=self._elapsed_ms(started),
            remediation=remediation,
        )

    @staticmethod
    def _elapsed_ms(started: float) -> float:
        return round((perf_counter() - started) * 1000, 3)
