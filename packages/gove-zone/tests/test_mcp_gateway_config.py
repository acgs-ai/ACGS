"""Dependency-free config-load tests for the governed-MCP gateway.

These exercise :func:`gove_zone.adapters.mcp_gateway.load_gateway_config` and the
:class:`GatewayConfig` fail-closed guards WITHOUT the ``mcp`` SDK (config loading
is pure JSON), so they run in the zero-dep suite and guard the two config-load
refusals the design mandates: transform-policy bundles (§3.2) and a validator
that clashes with a mapped principal (self-validation, §3.4).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gove_zone.adapters.mcp_gateway import (
    GatewayConfig,
    _load_policy_bundle,
    load_gateway_config,
)
from gove_zone.policy import RuleSetPolicy
from gove_zone.profile import GovernanceProfile
from gove_zone.receipt import Validator

_RULESET_BUNDLE = {
    "id": "tenant-A",
    "rules": [{"id": "deny-secret", "effect": "deny", "path_prefix": ["secret"]}],
}


def _write_config(tmp: Path, *, bundle: dict, validator_id: str = "constitutional-council") -> Path:
    (tmp / "policy.json").write_text(json.dumps(bundle), encoding="utf-8")
    cfg = {
        "downstream": {"transport": "stdio", "command": ["python", "-m", "srv"]},
        "governance": {
            "tenant_id": "tenant-A",
            "execution_boundary": "mcp-partner-sandbox",
            "profile": "dev",
            "policy_bundle": "policy.json",
        },
        "identity": {
            "validator_id": validator_id,
            "validator_role": "council",
            "principals": {"claude-code": "agent:claude-code@tenant-A"},
        },
        "audit": {"sink": "evidence/audit.jsonl"},
    }
    path = tmp / "gateway.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return path


def test_load_valid_ruleset_config(tmp_path: Path) -> None:
    config = load_gateway_config(_write_config(tmp_path, bundle=_RULESET_BUNDLE))
    assert config.tenant_id == "tenant-A"
    assert isinstance(config.policy, RuleSetPolicy)
    assert config.principals == {"claude-code": "agent:claude-code@tenant-A"}
    assert config.profile.name == "dev"


def test_transform_bundle_rejected_at_load(tmp_path: Path) -> None:
    transform_bundle = {"id": "transform-policy", "version": "transform-policy/v1"}
    with pytest.raises(ValueError, match="transform-policy bundles are not supported"):
        load_gateway_config(_write_config(tmp_path, bundle=transform_bundle))


def test_transform_bundle_rejected_by_loader_directly(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="transform-policy"):
        _load_policy_bundle({"id": "transform-policy", "version": "v1"}, source="unit")


def test_unknown_bundle_format_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsupported policy bundle"):
        _load_policy_bundle({"id": "mystery"}, source="unit")


def test_validator_equal_to_principal_rejected_at_load(tmp_path: Path) -> None:
    # validator_id collides with the mapped principal -> self-validation.
    path = _write_config(
        tmp_path, bundle=_RULESET_BUNDLE, validator_id="agent:claude-code@tenant-A"
    )
    with pytest.raises(ValueError, match="self-validation forbidden at config load"):
        load_gateway_config(path)


def test_config_post_init_rejects_approver_principal_name_clash(tmp_path: Path) -> None:
    policy = RuleSetPolicy.from_dict(_RULESET_BUNDLE)
    with pytest.raises(ValueError, match="approver_principals clientInfo names collide"):
        GatewayConfig(
            tenant_id="t",
            execution_boundary="b",
            policy=policy,
            policy_bundle_id="p",
            profile=GovernanceProfile.dev(),
            validator=Validator(validator_id="council", role="council"),
            principals={"host": "agent:x"},
            approver_principals={"host": "human:y"},
            audit_path=tmp_path / "a.jsonl",
            ledger_path=tmp_path / "c.jsonl",
        )


def test_config_post_init_rejects_approver_principal_id_clash(tmp_path: Path) -> None:
    policy = RuleSetPolicy.from_dict(_RULESET_BUNDLE)
    with pytest.raises(ValueError, match="approver_principals ids collide"):
        GatewayConfig(
            tenant_id="t",
            execution_boundary="b",
            policy=policy,
            policy_bundle_id="p",
            profile=GovernanceProfile.dev(),
            validator=Validator(validator_id="council", role="council"),
            principals={"agent": "same-id"},
            approver_principals={"human": "same-id"},
            audit_path=tmp_path / "a.jsonl",
            ledger_path=tmp_path / "c.jsonl",
        )


def test_load_config_reads_approver_principals(tmp_path: Path) -> None:
    path = _write_config(tmp_path, bundle=_RULESET_BUNDLE)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["identity"]["approver_principals"] = {"human-approver": "constitutional-council"}
    path.write_text(json.dumps(raw), encoding="utf-8")
    config = load_gateway_config(path)
    assert config.approver_principals == {"human-approver": "constitutional-council"}


def test_config_post_init_rejects_validator_principal_clash(tmp_path: Path) -> None:
    policy = RuleSetPolicy.from_dict(_RULESET_BUNDLE)
    with pytest.raises(ValueError, match="self-validation forbidden"):
        GatewayConfig(
            tenant_id="t",
            execution_boundary="b",
            policy=policy,
            policy_bundle_id="p",
            profile=GovernanceProfile.dev(),
            validator=Validator(validator_id="agent:x", role="council"),
            principals={"host": "agent:x"},
            audit_path=tmp_path / "a.jsonl",
            ledger_path=tmp_path / "c.jsonl",
        )


def test_load_config_reads_escalation_caps_and_ttl(tmp_path: Path) -> None:
    path = _write_config(tmp_path, bundle=_RULESET_BUNDLE)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["escalation"] = {"max_pending": 3, "max_pending_per_principal": 2}
    raw["governance"]["receipt_ttl_seconds"] = 30
    path.write_text(json.dumps(raw), encoding="utf-8")
    config = load_gateway_config(path)
    assert config.max_pending == 3
    assert config.max_pending_per_principal == 2
    assert config.receipt_ttl_seconds == 30.0


def test_load_config_rejects_zero_escalation_cap(tmp_path: Path) -> None:
    path = _write_config(tmp_path, bundle=_RULESET_BUNDLE)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["escalation"] = {"max_pending": 0, "max_pending_per_principal": 2}
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="capacity caps must be positive"):
        load_gateway_config(path)


def test_cli_approve_escalation_mints_receipt(tmp_path: Path, capsys) -> None:
    """The ``gove-zone approve-escalation`` verb wraps approve_escalation and
    prints a receipt + the approval-hash pin. Dep-free (dev/unsigned profile)."""
    from gove_zone import cli
    from gove_zone.adapters.mcp_gateway import pending_to_dict
    from gove_zone.decision import Decision, DecisionRecord
    from gove_zone.escalation import PendingApproval
    from gove_zone.policy import new_event_id

    config_path = _write_config(tmp_path, bundle=_RULESET_BUNDLE)

    record = DecisionRecord(
        decision=Decision.ESCALATE,
        tool="write_file",
        argument_hash="deadbeef",
        policy_version="ruleset/tenant-A/x",
        event_id=new_event_id(),
        matched_rules=("ESCALATE",),
        reason="needs approval",
        actor="agent:claude-code@tenant-A",
        decision_request_hash="reqhash",
    )
    pending = PendingApproval(record, "audithash", {"path": "e.txt", "content": "x"})
    descriptor_path = tmp_path / "pending.json"
    descriptor_path.write_text(json.dumps(pending_to_dict(pending)), encoding="utf-8")

    rc = cli.main(
        ["approve-escalation", "--config", str(config_path), "--pending", str(descriptor_path)]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["pending_event_id"] == record.event_id
    assert out["approval_audit_hash"]
    assert out["receipt"]["decision"] == "allow"
    # A validator that clashed with the proposer would exit 2; here it differs.
    assert out["receipt"]["validator_id"] == "constitutional-council"
