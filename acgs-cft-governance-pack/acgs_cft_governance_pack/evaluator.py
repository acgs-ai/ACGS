from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

_REPO_OWNER_EQUALITY = re.compile(r"""assertion\.repository_owner\s*==\s*['"]([^'"]+)['"]""")
_REPOSITORY_EQUALITY = re.compile(r"""assertion\.repository\s*==\s*['"]([^'"]+)['"]""")

JsonDict = dict[str, Any]

ACTIVE_ACTIONS = {"create", "update", "delete", "replace"}
PUBLIC_RANGES = {"0.0.0.0/0", "::/0"}


def load_policies(policy_dir: Path | str | None = None, policy_files: list[Path] | None = None) -> list[JsonDict]:
    paths: list[Path] = []
    if policy_dir:
        root = Path(policy_dir)
        if root.exists():
            paths.extend(sorted(root.glob("*.yaml")))
            paths.extend(sorted(root.glob("*.yml")))
    paths.extend(policy_files or [])

    policies: list[JsonDict] = []
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"Policy file {path} must contain a mapping.")
        loaded.setdefault("source", str(path))
        policies.append(loaded)
    if not policies:
        raise ValueError("No policy files found.")
    return policies


def evaluate_plan(
    plan: JsonDict,
    policies: list[JsonDict],
    *,
    actor_id: str,
    actor_role: str,
    tenant: str = "default",
) -> JsonDict:
    plan_hash = f"sha256:{_hash_json(plan)}"
    control_results: list[JsonDict] = []

    for policy in policies:
        policy_id = _required_string(policy, "id")
        for control in policy.get("controls", []):
            control_results.append(_evaluate_control(plan, policy_id, control))

    failures = [result for result in control_results if result["status"] == "fail"]
    decision = "deny" if failures else "allow"
    reason = (
        f"Denied by {len(failures)} governance controls"
        if failures
        else "All applicable governance controls passed"
    )
    event = {
        "schema": "acgs.cft.evidence.v1",
        "event_type": "terraform_plan_evaluation",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tenant": tenant,
        "actor": {"id": actor_id, "role": actor_role},
        "decision": decision,
        "reason": reason,
        "plan_hash": plan_hash,
        "policies": [_required_string(policy, "id") for policy in policies],
        "control_results": control_results,
    }
    event["merkle_root"] = f"sha256:{_merkle_root([plan_hash, event['actor'], control_results, decision])}"
    return event


def write_evidence_jsonl(path: Path, event: JsonDict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")))
        handle.write("\n")


def _evaluate_control(plan: JsonDict, policy_id: str, control: JsonDict) -> JsonDict:
    control_id = _required_string(control, "id")
    rule = control.get("rule") or {}
    kind = _required_string(rule, "kind")
    resource_types = control.get("resource_types") or rule.get("resource_types") or []
    changes = _active_changes(plan, resource_types)

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


def _active_changes(plan: JsonDict, resource_types: list[str]) -> list[JsonDict]:
    selected: list[JsonDict] = []
    allowed_types = set(resource_types)
    for change in plan.get("resource_changes", []):
        actions = set(change.get("change", {}).get("actions", []))
        if not actions.intersection(ACTIVE_ACTIONS):
            continue
        if allowed_types and change.get("type") not in allowed_types:
            continue
        selected.append(change)
    return selected


def _after(change: JsonDict) -> JsonDict:
    after = change.get("change", {}).get("after") or {}
    return after if isinstance(after, dict) else {}


def _address(change: JsonDict) -> str:
    return str(change.get("address") or change.get("name") or "<unknown>")


def _check_forbidden_apis(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    forbidden = set(rule.get("services", []))
    violations = []
    for change in changes:
        service = _after(change).get("service")
        if service in forbidden:
            violations.append(_violation(change, f"Forbidden API enabled: {service}"))
    return violations


def _check_require_project_labels(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    required = set(rule.get("labels", []))
    violations = []
    for change in changes:
        labels = _after(change).get("labels") or {}
        missing = sorted(required.difference(labels.keys()))
        if missing:
            violations.append(_violation(change, f"Missing required project labels: {', '.join(missing)}"))
    return violations


def _check_restrict_project_folder(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    allowed = set(rule.get("allowed_folders", []))
    return _violations_when_value_not_allowed(changes, "folder_id", allowed, "Unapproved folder")


def _check_restrict_billing_account(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    allowed = set(rule.get("allowed_billing_accounts", []))
    return _violations_when_value_not_allowed(changes, "billing_account", allowed, "Unapproved billing account")


def _check_deny_service_account_keys(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    return [_violation(change, "Long-lived service account key creation is denied") for change in changes]


def _check_deny_iam_roles(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    denied_roles = set(rule.get("roles", []))
    violations = []
    for change in changes:
        after = _after(change)
        role = after.get("role")
        if role in denied_roles:
            violations.append(_violation(change, f"Denied IAM role assigned: {role}"))
    return violations


def _check_deny_public_ingress(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    denied_ports = {str(port) for port in rule.get("ports", [])}
    violations = []
    for change in changes:
        after = _after(change)
        if str(after.get("direction", "INGRESS")).upper() != "INGRESS":
            continue
        source_ranges = set(after.get("source_ranges") or [])
        if not source_ranges.intersection(PUBLIC_RANGES):
            continue
        exposed_ports = _firewall_ports(after)
        if "*" in denied_ports or denied_ports.intersection(exposed_ports) or "all" in exposed_ports:
            violations.append(_violation(change, f"Public ingress exposes sensitive ports: {', '.join(sorted(exposed_ports))}"))
    return violations


def _check_require_firewall_log_config(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    violations = []
    for change in changes:
        log_config = _after(change).get("log_config")
        if not isinstance(log_config, list) or not log_config or not log_config[0].get("metadata"):
            violations.append(_violation(change, "Firewall rule must enable log_config.metadata"))
    return violations


def _check_require_subnet_flow_logs(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    violations = []
    for change in changes:
        log_config = _after(change).get("log_config")
        enabled = isinstance(log_config, list) and bool(log_config) and log_config[0].get("enable") is True
        if not enabled:
            violations.append(_violation(change, "Subnet must enable flow logs"))
    return violations


def _check_require_gke_private_nodes(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    violations = []
    for change in changes:
        private_config = _after(change).get("private_cluster_config")
        enabled = isinstance(private_config, list) and bool(private_config) and private_config[0].get("enable_private_nodes") is True
        if not enabled:
            violations.append(_violation(change, "GKE cluster must enable private nodes"))
    return violations


def _check_require_gke_workload_identity(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    violations = []
    for change in changes:
        workload_identity = _after(change).get("workload_identity_config")
        enabled = isinstance(workload_identity, list) and bool(workload_identity) and bool(workload_identity[0].get("workload_pool"))
        if not enabled:
            violations.append(_violation(change, "GKE cluster must enable Workload Identity"))
    return violations


def _check_require_gke_shielded_nodes(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    violations = []
    for change in changes:
        if _after(change).get("enable_shielded_nodes") is not True:
            violations.append(_violation(change, "GKE cluster must enable Shielded Nodes"))
    return violations


def _check_require_gke_release_channel(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    allowed = set(rule.get("allowed_channels", []))
    violations = []
    for change in changes:
        channel_config = _after(change).get("release_channel")
        channel = None
        if isinstance(channel_config, list) and channel_config:
            channel = channel_config[0].get("channel")
        if channel not in allowed:
            violations.append(_violation(change, f"GKE release channel must be one of: {', '.join(sorted(allowed))}"))
    return violations


def _check_require_github_oidc_provider(changes: list[JsonDict], rule: JsonDict) -> list[JsonDict]:
    expected_issuer = rule.get("issuer_uri", "https://token.actions.githubusercontent.com")
    required_condition_terms = rule.get("required_condition_terms", [])
    allowed_owners = set(rule.get("allowed_repository_owners", []))
    allowed_repositories = set(rule.get("allowed_repositories", []))
    violations = []
    for change in changes:
        after = _after(change)
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
            violations.append(_violation(change, "; ".join(details)))
    return violations


def _violations_when_value_not_allowed(
    changes: list[JsonDict],
    field: str,
    allowed: set[str],
    message: str,
) -> list[JsonDict]:
    if not allowed:
        return []
    violations = []
    for change in changes:
        value = _after(change).get(field)
        if value not in allowed:
            violations.append(_violation(change, f"{message}: {value}"))
    return violations


def _firewall_ports(after: JsonDict) -> set[str]:
    ports: set[str] = set()
    for allow in after.get("allow") or []:
        protocol = str(allow.get("protocol", "")).lower()
        rule_ports = allow.get("ports")
        if protocol == "all" or rule_ports is None:
            ports.add("all")
            continue
        ports.update(str(port) for port in rule_ports)
    return ports


def _violation(change: JsonDict, message: str) -> JsonDict:
    return {
        "address": _address(change),
        "type": change.get("type"),
        "message": message,
    }


def _required_string(mapping: JsonDict, key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Expected non-empty string field: {key}")
    return value


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _merkle_root(values: list[Any]) -> str:
    leaves = [_hash_json(value) for value in values]
    if not leaves:
        return _hash_json("")
    while len(leaves) > 1:
        if len(leaves) % 2 == 1:
            leaves.append(leaves[-1])
        leaves = [
            hashlib.sha256((leaves[index] + leaves[index + 1]).encode("utf-8")).hexdigest()
            for index in range(0, len(leaves), 2)
        ]
    return leaves[0]
