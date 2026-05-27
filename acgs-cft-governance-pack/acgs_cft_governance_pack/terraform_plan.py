from __future__ import annotations

from typing import Any

JsonDict = dict[str, Any]

ACTIVE_ACTIONS = {"create", "update", "delete", "replace"}
PUBLIC_RANGES = {"0.0.0.0/0", "::/0"}


def active_changes(plan: JsonDict, resource_types: list[str]) -> list[JsonDict]:
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


def change_after(change: JsonDict) -> JsonDict:
    after = change.get("change", {}).get("after") or {}
    return after if isinstance(after, dict) else {}


def change_address(change: JsonDict) -> str:
    return str(change.get("address") or change.get("name") or "<unknown>")


def firewall_ports(after: JsonDict) -> set[str]:
    ports: set[str] = set()
    for allow in after.get("allow") or []:
        protocol = str(allow.get("protocol", "")).lower()
        rule_ports = allow.get("ports")
        if protocol == "all" or rule_ports is None:
            ports.add("all")
            continue
        ports.update(str(port) for port in rule_ports)
    return ports


def violation(change: JsonDict, message: str) -> JsonDict:
    return {
        "address": change_address(change),
        "type": change.get("type"),
        "message": message,
    }
