"""Risk-tiered enforcement policy surface (`docs/reconstruction/04-platform-blueprint.md` §2f).

Proves:

- Enforcement depth scales per tier: low -> ALLOW (receipt-logged like every
  governed call), high -> ESCALATE, critical -> DENY.
- Fail-closed default is preserved: a tool without a tier assignment falls
  into the most restrictive tier defined (unless an explicit ``default_tier``
  is configured), never a silent allow.
- Tiers are policy metadata, not new enforcement code paths: DENY/ESCALATE
  records stay non-executable through the ONE kernel gate (dispatcher-level
  tests, per the handler-wiring rule).
- Bundles are declarative and content-addressed (dict/JSON/YAML round-trips,
  stable versions).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gove_zone import (
    ChainHashAuditStore,
    CompositePolicy,
    Decision,
    DeniedError,
    EscalateError,
    Kernel,
    RiskTier,
    RiskTierPolicy,
)
from gove_zone.tool import ToolCall
from gove_zone.yaml_policy import YAMLRiskTierPolicy

TIERS = (
    RiskTier(name="low", enforcement=Decision.ALLOW, description="read-only"),
    RiskTier(
        name="high",
        enforcement=Decision.ESCALATE,
        requirements=("signed", "single-use", "human-approval"),
    ),
    RiskTier(name="critical", enforcement=Decision.DENY),
)

TOOL_TIERS = {
    "read_file": "low",
    "deploy_service": "high",
    "drop_database": "critical",
}


def _policy(**overrides: object) -> RiskTierPolicy:
    kwargs: dict = {
        "policy_id": "test-tiers",
        "tiers": TIERS,
        "tool_tiers": TOOL_TIERS,
    }
    kwargs.update(overrides)
    return RiskTierPolicy(**kwargs)


# --- tiered enforcement -----------------------------------------------------


def test_enforcement_scales_by_tier() -> None:
    policy = _policy()

    low = policy.evaluate(ToolCall(name="read_file", args={"path": "/tmp/x"}))
    assert low.decision is Decision.ALLOW
    assert "RISK_TIER:low" in low.matched_rules

    high = policy.evaluate(ToolCall(name="deploy_service", args={"env": "prod"}))
    assert high.decision is Decision.ESCALATE
    assert "RISK_TIER:high" in high.matched_rules

    critical = policy.evaluate(ToolCall(name="drop_database", args={}))
    assert critical.decision is Decision.DENY
    assert "RISK_TIER:critical" in critical.matched_rules


def test_unassigned_tool_fail_closes_to_most_restrictive_tier() -> None:
    policy = _policy()
    record = policy.evaluate(ToolCall(name="unknown_tool", args={}))
    assert policy.default_tier == "critical"
    assert record.decision is Decision.DENY
    assert record.matched_rules == ("RISK_TIER:critical", "RISK_TIER:default")
    assert "fail-closed" in record.reason


def test_default_tier_is_most_restrictive_even_when_declared_first() -> None:
    policy = RiskTierPolicy(
        tiers=(
            RiskTier(name="blocked", enforcement=Decision.DENY),
            RiskTier(name="open", enforcement=Decision.ALLOW),
        ),
    )
    assert policy.default_tier == "blocked"
    record = policy.evaluate(ToolCall(name="anything", args={}))
    assert record.decision is Decision.DENY


def test_explicit_default_tier_is_honored() -> None:
    policy = _policy(default_tier="high")
    record = policy.evaluate(ToolCall(name="unknown_tool", args={}))
    assert record.decision is Decision.ESCALATE
    assert record.matched_rules == ("RISK_TIER:high", "RISK_TIER:default")


def test_tier_for_resolves_assignments_and_default() -> None:
    policy = _policy()
    assert policy.tier_for("deploy_service").name == "high"
    assert policy.tier_for("deploy_service").requirements == (
        "signed",
        "single-use",
        "human-approval",
    )
    assert policy.tier_for("never_heard_of_it").name == "critical"


# --- validation (misconfiguration is rejected, never silently allowed) -----


def test_requires_at_least_one_tier() -> None:
    with pytest.raises(ValueError, match="at least one tier"):
        RiskTierPolicy(tiers=())


def test_rejects_duplicate_tier_names() -> None:
    with pytest.raises(ValueError, match="duplicate risk tier"):
        RiskTierPolicy(
            tiers=(
                RiskTier(name="low", enforcement=Decision.ALLOW),
                RiskTier(name="low", enforcement=Decision.DENY),
            ),
        )


def test_rejects_tool_referencing_undefined_tier() -> None:
    with pytest.raises(ValueError, match="undefined risk tier"):
        _policy(tool_tiers={"read_file": "nonexistent"})


def test_rejects_undefined_default_tier() -> None:
    with pytest.raises(ValueError, match="undefined risk tier"):
        _policy(default_tier="nonexistent")


def test_rejects_transform_and_bogus_enforcement() -> None:
    with pytest.raises(ValueError, match="allow/escalate/deny"):
        RiskTier(name="weird", enforcement=Decision.TRANSFORM)
    with pytest.raises(ValueError, match="unsupported tier enforcement"):
        RiskTier.from_dict({"name": "weird", "enforcement": "bogus"})


def test_rejects_empty_tier_name() -> None:
    with pytest.raises(ValueError, match="non-empty name"):
        RiskTier(name="  ", enforcement=Decision.DENY)


# --- content-addressed versioning + round-trips -----------------------------


def test_version_is_content_addressed_and_stable() -> None:
    a = _policy()
    b = _policy()
    assert a.version == b.version
    assert a.version.startswith("risk-tier/test-tiers/")

    changed = _policy(tool_tiers={**TOOL_TIERS, "extra_tool": "low"})
    assert changed.version != a.version


def test_dict_and_json_round_trip_preserve_version_and_decisions() -> None:
    original = _policy()
    rebuilt = RiskTierPolicy.from_dict(original.to_dict())
    assert rebuilt.version == original.version

    from_json = RiskTierPolicy.from_json(original.to_json())
    assert from_json.version == original.version
    call = ToolCall(name="drop_database", args={})
    assert from_json.evaluate(call).decision is original.evaluate(call).decision


def test_load_and_dump_round_trip(tmp_path: Path) -> None:
    original = _policy()
    bundle = tmp_path / "tiers.json"
    original.dump(bundle)
    assert RiskTierPolicy.load(bundle).version == original.version


def test_from_json_rejects_non_object_and_missing_tiers() -> None:
    with pytest.raises(ValueError, match="JSON must be an object"):
        RiskTierPolicy.from_json("[1, 2]")
    with pytest.raises(ValueError, match="tiers sequence"):
        RiskTierPolicy.from_dict({"id": "x"})


# --- YAML surface ------------------------------------------------------------


def test_yaml_round_trip(tmp_path: Path) -> None:
    pytest.importorskip("yaml")
    yaml_text = """
id: yaml-risk-tiers
tiers:
  - name: low
    enforcement: allow
  - name: high
    enforcement: escalate
    requirements: [signed, single-use, human-approval]
  - name: critical
    enforcement: deny
tools:
  read_file: low
  deploy_service: high
  drop_database: critical
"""
    policy = YAMLRiskTierPolicy.from_yaml(yaml_text)
    assert policy.policy_id == "yaml-risk-tiers"
    assert policy.default_tier == "critical"
    assert policy.evaluate(ToolCall(name="deploy_service", args={})).decision is (Decision.ESCALATE)

    path = tmp_path / "tiers.yaml"
    policy.dump_yaml(path)
    reloaded = YAMLRiskTierPolicy.load_yaml(path)
    assert reloaded.version == policy.version


def test_yaml_rejects_non_mapping_root() -> None:
    pytest.importorskip("yaml")
    with pytest.raises(ValueError, match="dictionary/object at the root"):
        YAMLRiskTierPolicy.from_yaml("- just\n- a\n- list\n")


# --- kernel dispatch: the executor stays ONE gate ---------------------------


def _kernel(tmp_path: Path, policy: RiskTierPolicy | CompositePolicy) -> Kernel:
    return Kernel(policy=policy, audit=ChainHashAuditStore(tmp_path / "audit.jsonl"))


def test_kernel_dispatch_low_tier_executes_and_is_receipt_logged(tmp_path: Path) -> None:
    k = _kernel(tmp_path, _policy())

    @k.tool("read_file")
    def read_file(path: str) -> str:
        return f"contents of {path}"

    result, receipt = k.dispatch("read_file", {"path": "/tmp/x"})
    assert result == "contents of /tmp/x"
    assert receipt.record.decision is Decision.ALLOW
    assert "RISK_TIER:low" in receipt.record.matched_rules
    assert receipt.audit_hash and receipt.audit_hash != "0" * 64


def test_kernel_dispatch_high_tier_escalates_without_executing(tmp_path: Path) -> None:
    k = _kernel(tmp_path, _policy())
    executed: list[str] = []

    @k.tool("deploy_service")
    def deploy_service(env: str) -> None:
        executed.append(env)

    with pytest.raises(EscalateError) as exc_info:
        k.dispatch("deploy_service", {"env": "prod"})

    assert executed == []  # ESCALATE is non-executable
    assert exc_info.value.record.decision is Decision.ESCALATE
    assert "RISK_TIER:high" in exc_info.value.record.matched_rules


def test_kernel_dispatch_unassigned_tool_fail_closes(tmp_path: Path) -> None:
    k = _kernel(tmp_path, _policy())
    executed: list[str] = []

    @k.tool("brand_new_tool")
    def brand_new_tool() -> None:
        executed.append("ran")

    with pytest.raises(DeniedError) as exc_info:
        k.dispatch("brand_new_tool")

    assert executed == []  # DENY is non-executable
    assert exc_info.value.record.decision is Decision.DENY
    assert "RISK_TIER:default" in exc_info.value.record.matched_rules


def test_composes_with_other_policies_first_non_allow_wins(tmp_path: Path) -> None:
    composite = CompositePolicy([_policy()])
    k = _kernel(tmp_path, composite)

    @k.tool("drop_database")
    def drop_database() -> None:  # pragma: no cover - must never run
        raise AssertionError("side effect must not run")

    with pytest.raises(DeniedError):
        k.dispatch("drop_database")
