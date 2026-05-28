"""Policy bundle import/export contract tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gove_zone import RuleSetPolicy
from gove_zone.cli import main

BUNDLE = {
    "id": "legal-privilege/v1",
    "rules": [
        {
            "id": "PRIVILEGED_NOTES_REVIEW",
            "effect": "deny",
            "tools": ["matter.fetch"],
            "path_prefix": "tenant-7/matter-9821/private-notes",
            "state_equals": {"matter_status": "privileged"},
            "state_contains": {"org_controls": "human_review_required_for_privileged_notes"},
            "allow": {
                "actors": ["review-lead"],
                "trust_tiers": ["reviewer", "admin"],
            },
            "reason": "privileged matter notes require reviewer trust",
        }
    ],
}


def test_rule_set_policy_round_trips_canonical_bundle_file(tmp_path: Path) -> None:
    policy = RuleSetPolicy.from_dict(BUNDLE)
    bundle_path = tmp_path / "policy.bundle.json"

    policy.dump(bundle_path)
    loaded = RuleSetPolicy.load(bundle_path)

    assert loaded.version == policy.version
    exported = json.loads(bundle_path.read_text(encoding="utf-8"))
    assert exported == loaded.to_dict()
    assert exported["id"] == "legal-privilege/v1"
    assert exported["rules"][0]["path_prefix"] == [
        "tenant-7",
        "matter-9821",
        "private-notes",
    ]
    assert exported["rules"][0]["allow"] == {
        "actors": ["review-lead"],
        "trust_tiers": ["admin", "reviewer"],
    }


def test_cli_policy_inspect_reports_version_and_rule_summary(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle_path = tmp_path / "policy.bundle.json"
    bundle_path.write_text(json.dumps(BUNDLE), encoding="utf-8")

    exit_code = main(["policy", "inspect", "--bundle", str(bundle_path)])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["policy_id"] == "legal-privilege/v1"
    assert payload["version"].startswith("ruleset/legal-privilege/v1/")
    assert payload["rule_count"] == 1
    assert payload["rules"] == [
        {
            "id": "PRIVILEGED_NOTES_REVIEW",
            "effect": "deny",
            "tools": ["matter.fetch"],
            "path_prefix": ["tenant-7", "matter-9821", "private-notes"],
        }
    ]


def test_cli_policy_export_writes_canonical_bundle(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "canonical.json"
    input_path.write_text(json.dumps(BUNDLE), encoding="utf-8")

    exit_code = main(
        [
            "policy",
            "export",
            "--bundle",
            str(input_path),
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["output"] == str(output_path)
    assert payload["version"].startswith("ruleset/legal-privilege/v1/")
    assert json.loads(output_path.read_text(encoding="utf-8"))["rules"][0]["path_prefix"] == [
        "tenant-7",
        "matter-9821",
        "private-notes",
    ]
