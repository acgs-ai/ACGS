"""Unit tests for the YAMLPolicy loader."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from gove_zone.decision import Decision
from gove_zone.tool import ToolCall
from gove_zone.yaml_policy import YAMLPolicy


def test_yaml_policy_from_yaml_valid() -> None:
    """Verify that valid YAML string can be parsed into YAMLPolicy with matching rules."""
    yaml_text = """
id: yaml-agent-boundaries
rules:
  - id: deny-env-read
    effect: deny
    tools:
      - read_env
    reason: Access to system environment variables is prohibited.
  - id: escalate-ssh-write
    effect: escalate
    tools:
      - write_file
    state_contains:
      sensitive_path: .ssh
    reason: SSH credentials modifications require escalation.
"""
    policy = YAMLPolicy.from_yaml(yaml_text)
    assert policy.policy_id == "yaml-agent-boundaries"
    assert len(policy.rules) == 2
    assert policy.rules[0].rule_id == "deny-env-read"
    assert policy.rules[0].effect == Decision.DENY
    assert policy.rules[1].rule_id == "escalate-ssh-write"
    assert policy.rules[1].effect == Decision.ESCALATE

    # Evaluate ALLOW case
    call_allow = ToolCall(name="read_file", args={"path": "/tmp/safe.txt"})
    record_allow = policy.evaluate(call_allow)
    assert record_allow.decision == Decision.ALLOW

    # Evaluate DENY case
    call_deny = ToolCall(name="read_env", args={"var": "SECRET_KEY"})
    record_deny = policy.evaluate(call_deny)
    assert record_deny.decision == Decision.DENY
    assert record_deny.matched_rules == ("deny-env-read",)

    # Evaluate ESCALATE case
    call_esc = ToolCall(
        name="write_file",
        args={"path": "/home/user/.ssh/id_rsa"},
        state={"sensitive_path": ".ssh"},
    )
    record_esc = policy.evaluate(call_esc)
    assert record_esc.decision == Decision.ESCALATE
    assert record_esc.matched_rules == ("escalate-ssh-write",)


def test_yaml_policy_invalid_format() -> None:
    """Verify that malformed YAML or invalid policy schemas raise appropriate errors."""
    # Malformed YAML
    with pytest.raises(ValueError) as exc_info:
        YAMLPolicy.from_yaml("id: [unclosed list")
    assert "Invalid YAML" in str(exc_info.value)

    # Not a dictionary at root
    with pytest.raises(ValueError) as exc_info:
        YAMLPolicy.from_yaml("- rule_1\n- rule_2")
    assert "must define a dictionary" in str(exc_info.value)


def test_yaml_policy_disk_roundtrip() -> None:
    """Verify that YAMLPolicy can be saved to and loaded from disk successfully."""
    yaml_text = """id: test-disk-policy
rules:
  - effect: deny
    id: block-tool
    tools:
    - bad_tool
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "policy.yaml"
        policy = YAMLPolicy.from_yaml(yaml_text)

        # Save to disk
        policy.dump_yaml(path)
        assert path.exists()

        # Load back from disk
        loaded = YAMLPolicy.load_yaml(path)
        assert loaded.policy_id == "test-disk-policy"
        assert len(loaded.rules) == 1
        assert loaded.rules[0].rule_id == "block-tool"
