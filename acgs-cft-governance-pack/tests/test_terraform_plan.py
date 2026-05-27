from __future__ import annotations

from acgs_cft_governance_pack.terraform_plan import (
    active_changes,
    change_address,
    change_after,
    firewall_ports,
    violation,
)


def test_active_changes_filters_noops_and_resource_types() -> None:
    plan = {
        "resource_changes": [
            {"type": "google_project", "change": {"actions": ["no-op"]}},
            {"type": "google_project", "change": {"actions": ["update"]}},
            {"type": "google_compute_firewall", "change": {"actions": ["create"]}},
        ],
    }

    assert active_changes(plan, ["google_project"]) == [
        {"type": "google_project", "change": {"actions": ["update"]}},
    ]


def test_change_helpers_normalize_after_addresses_ports_and_violations() -> None:
    change = {
        "name": "allow-admin",
        "type": "google_compute_firewall",
        "change": {
            "after": {
                "allow": [
                    {"protocol": "tcp", "ports": ["22", "3389"]},
                    {"protocol": "all"},
                ],
            },
        },
    }

    after = change_after(change)

    assert change_address(change) == "allow-admin"
    assert firewall_ports(after) == {"22", "3389", "all"}
    assert violation(change, "public admin ingress") == {
        "address": "allow-admin",
        "type": "google_compute_firewall",
        "message": "public admin ingress",
    }
