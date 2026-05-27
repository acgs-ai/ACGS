from __future__ import annotations

import re
from typing import Any

from acgs_cft_governance_pack.terraform_plan import (
    PUBLIC_RANGES,
    active_changes,
    change_after,
    firewall_ports,
    violation,
)

JsonDict = dict[str, Any]

_REPO_OWNER_EQUALITY = re.compile(r"""assertion\.repository_owner\s*==\s*['"]([^'"]+)['"]""")
_REPOSITORY_EQUALITY = re.compile(r"""assertion\.repository\s*==\s*['"]([^'"]+)['"]""")


def evaluate_control(plan: JsonDict, policy_id: str, control: JsonDict) -> JsonDict:
    control_id = _required_string(control, "id")
    rule = control.get("rule") or {}
    kind = _required_string(rule, "kind")
    resource_types = control.get("resource_types") or rule.get("resource_types") or []
    changes = active_changes(plan, resource_types)

    checker = {
        "forbidden_apis": _check_forbidden_apis,
        "require_project_labels": _check_require_project_labels,
        "restrict_project_folder": _check_restrict_project_folder,
        "restrict_billing_account": _check_restrict_billing_account,
        "deny_service_account_keys": _check_deny_service_account_keys,
        "deny_iam_roles": _check_deny_iam_roles,
        "deny_public_ingress": _check_deny_public_ingress,
        "require_firewall_log_config": _check_require_firewall_log_config,
        "require_subnet_flow_logs": _check_require_subnet_flow_logs,
        "require_gke_private_nodes": _check_require_gke_private_nodes,
        "require_gke_workload_identity": _check_require_gke_workload_identity,
        "require_gke_shielded_nodes": _check_require_gke_shielded_nodes,
        "require_gke_release_channel": _check_require_gke_release_channel,
        "require_github_oidc_provider": _check_require_github_oidc_provider,
    }.get(kind)
    if checker is None:
        raise ValueError(f"Unknown rule kind: {kind}")

    violations = checker(changes, rule)
    if not changes and not violations:
        status = "not_applicable"
    else:
        status = "fail" if violations else "pass"

    return {
        "policy_id": policy_id,
        "control_id": control_id,
        "description": control.get("description", ""),
        "severity": str(control.get("severity", "medium")).lower(),
        "rule_kind": kind,
        "status": status,
        "violations": violations,
    }


def _check_forbidden_apis(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    forbidden = set(rule.get("services", []))
    violations = []
    for change in changes:
        service = change_after(change).get("service")
        if service in forbidden:
            violations.append(violation(change, f"Forbidden API enabled: {service}"))
    return violations


def _check_require_project_labels(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    required = set(rule.get("labels", []))
    violations = []
    for change in changes:
        labels = change_after(change).get("labels") or {}
        missing = sorted(required.difference(labels.keys()))
        if missing:
            violations.append(violation(change, f"Missing required project labels: {', '.join(missing)}"))
    return violations


def _check_restrict_project_folder(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    allowed = set(rule.get("allowed_folders", []))
    return _violations_when_value_not_allowed(changes, "folder_id", allowed, "Unapproved folder")


def _check_restrict_billing_account(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    allowed = set(rule.get("allowed_billing_accounts", []))
    return _violations_when_value_not_allowed(changes, "billing_account", allowed, "Unapproved billing account")


def _check_deny_service_account_keys(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    return [violation(change, "Long-lived service account key creation is denied") for change in changes]


def _check_deny_iam_roles(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    denied_roles = set(rule.get("roles", []))
    violations = []
    for change in changes:
        after = change_after(change)
        role = after.get("role")
        if role in denied_roles:
            violations.append(violation(change, f"Denied IAM role assigned: {role}"))
    return violations


def _check_deny_public_ingress(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    denied_ports = {str(port) for port in rule.get("ports", [])}
    violations = []
    for change in changes:
        after = change_after(change)
        if str(after.get("direction", "INGRESS")).upper() != "INGRESS":
            continue
        source_ranges = set(after.get("source_ranges") or [])
        if not source_ranges.intersection(PUBLIC_RANGES):
            continue
        exposed_ports = firewall_ports(after)
        if "*" in denied_ports or denied_ports.intersection(exposed_ports) or "all" in exposed_ports:
            violations.append(
                violation(change, f"Public ingress exposes sensitive ports: {', '.join(sorted(exposed_ports))}")
            )
    return violations


def _check_require_firewall_log_config(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    violations = []
    for change in changes:
        log_config = change_after(change).get("log_config")
        if not isinstance(log_config, list) or not log_config or not log_config[0].get("metadata"):
            violations.append(violation(change, "Firewall rule must enable log_config.metadata"))
    return violations


def _check_require_subnet_flow_logs(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    violations = []
    for change in changes:
        log_config = change_after(change).get("log_config")
        enabled = isinstance(log_config, list) and bool(log_config) and log_config[0].get("enable") is True
        if not enabled:
            violations.append(violation(change, "Subnet must enable flow logs"))
    return violations


def _check_require_gke_private_nodes(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    violations = []
    for change in changes:
        private_config = change_after(change).get("private_cluster_config")
        enabled = (
            isinstance(private_config, list)
            and bool(private_config)
            and private_config[0].get("enable_private_nodes") is True
        )
        if not enabled:
            violations.append(violation(change, "GKE cluster must enable private nodes"))
    return violations


def _check_require_gke_workload_identity(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    violations = []
    for change in changes:
        workload_identity = change_after(change).get("workload_identity_config")
        enabled = (
            isinstance(workload_identity, list)
            and bool(workload_identity)
            and bool(workload_identity[0].get("workload_pool"))
        )
        if not enabled:
            violations.append(violation(change, "GKE cluster must enable Workload Identity"))
    return violations


def _check_require_gke_shielded_nodes(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    violations = []
    for change in changes:
        if change_after(change).get("enable_shielded_nodes") is not True:
            violations.append(violation(change, "GKE cluster must enable Shielded Nodes"))
    return violations


def _check_require_gke_release_channel(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    allowed = set(rule.get("allowed_channels", []))
    violations = []
    for change in changes:
        channel_config = change_after(change).get("release_channel")
        channel = None
        if isinstance(channel_config, list) and channel_config:
            channel = channel_config[0].get("channel")
        if channel not in allowed:
            violations.append(violation(change, f"GKE release channel must be one of: {', '.join(sorted(allowed))}"))
    return violations


def _check_require_github_oidc_provider(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    expected_issuer = rule.get("issuer_uri", "https://token.actions.githubusercontent.com")
    required_condition_terms = rule.get("required_condition_terms", [])
    allowed_owners = set(rule.get("allowed_repository_owners", []))
    allowed_repositories = set(rule.get("allowed_repositories", []))
    violations = []
    for change in changes:
        after = change_after(change)
        oidc = after.get("oidc")
        issuer = None
        if isinstance(oidc, list) and oidc:
            issuer = oidc[0].get("issuer_uri")
        condition = str(after.get("attribute_condition") or "")
        details = []
        if issuer != expected_issuer:
            details.append("issuer must be GitHub Actions OIDC")
        missing_terms = [term for term in required_condition_terms if term not in condition]
        if missing_terms:
            details.append(f"condition missing: {', '.join(missing_terms)}")
        # Equality binding: substring presence is not enough. Require the
        # condition to constrain assertion.repository_owner and
        # assertion.repository to literal values via ==. If allowlists are
        # configured, the bound values must be subsets.
        if "assertion.repository_owner" in required_condition_terms or allowed_owners:
            bound_owners = set(_REPO_OWNER_EQUALITY.findall(condition))
            if not bound_owners:
                details.append("condition must bind assertion.repository_owner with == to a literal value")
            elif allowed_owners:
                disallowed = bound_owners - allowed_owners
                if disallowed:
                    details.append(f"repository_owner not in allowlist: {sorted(disallowed)}")
        if "assertion.repository" in required_condition_terms or allowed_repositories:
            bound_repositories = set(_REPOSITORY_EQUALITY.findall(condition))
            if not bound_repositories:
                details.append("condition must bind assertion.repository with == to a literal value")
            elif allowed_repositories:
                disallowed = bound_repositories - allowed_repositories
                if disallowed:
                    details.append(f"repository not in allowlist: {sorted(disallowed)}")
        if details:
            violations.append(violation(change, "; ".join(details)))
    return violations


def _violations_when_value_not_allowed(
    changes: list[JsonDict],
    field: str,
    allowed: set[str],
    message: str,
) -> list[JsonDict]:
    # Fail closed: a restrictive allowlist with no entries is misconfiguration,
    # not a license to allow every value. Emit a violation per change so the
    # gate refuses the plan rather than rubber-stamping it.
    if not allowed:
        return [violation(change, f"{message}: allowlist not configured (refusing to evaluate)") for change in changes]
    violations = []
    for change in changes:
        value = change_after(change).get(field)
        if value not in allowed:
            violations.append(violation(change, f"{message}: {value}"))
    return violations


def _required_string(mapping: JsonDict, key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Expected non-empty string field: {key}")
    return value
