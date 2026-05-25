"""Tests for gove_zone.setup and the new CLI subcommands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gove_zone import cli
from gove_zone.setup import (
    detect_environment,
    generate_config,
    instructions,
    validate_dependencies,
)


@pytest.fixture
def in_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    monkeypatch.delenv("GOVE_ZONE_AUDIT_PATH", raising=False)
    monkeypatch.delenv("GOVE_ZONE_GATE_MODE", raising=False)
    return tmp_path


def test_detect_environment_reports_project_and_audit_path(in_project: Path) -> None:
    env = detect_environment()
    assert env.project_dir == str(in_project)
    assert env.audit_path == str(in_project / ".gove-zone" / "audit.jsonl")
    assert env.gove_zone_installed is True
    assert env.gate_mode == "observe"


def test_validate_dependencies_ok_when_writable(in_project: Path) -> None:
    report = validate_dependencies()
    assert report.ok is True
    names = {c["name"] for c in report.checks}
    assert {"gove_zone_importable", "integration_adapter_present", "audit_path_writable"} <= names


def test_generate_config_enforce_sets_env(in_project: Path) -> None:
    cfg = generate_config(enforce=True)
    assert cfg["claude_code"]["env"]["GOVE_ZONE_GATE_MODE"] == "enforce"
    hooks = cfg["claude_code"]["settings_fragment"]["hooks"]["PreToolUse"]
    by_matcher = {hook["matcher"]: hook for hook in hooks}
    assert {"Edit|Write|MultiEdit", "Bash"} <= set(by_matcher)
    assert "acgs-emit-receipt.py" in by_matcher["Edit|Write|MultiEdit"]["hooks"][0]["command"]
    assert "acgs-emit-receipt.py" in by_matcher["Bash"]["hooks"][0]["command"]


def test_instructions_render_markdown_with_audit_path(in_project: Path) -> None:
    md = instructions(enforce=False)
    assert "# gove-zone setup" in md
    assert str(in_project / ".gove-zone" / "audit.jsonl") in md
    assert "GOVE_ZONE_GATE_MODE=enforce" in md  # mentioned as the toggle


def test_cli_doctor_passes_in_writable_env(
    in_project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = cli.main(["doctor"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 0
    assert payload["ok"] is True
    assert payload["gate_mode"] == "observe"


def test_cli_setup_markdown_default(in_project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["setup"])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.startswith("# gove-zone setup")


def test_cli_setup_json(in_project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["setup", "--format", "json", "--enforce"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 0
    assert payload["config"]["claude_code"]["env"]["GOVE_ZONE_GATE_MODE"] == "enforce"


def test_cli_gate_emits_receipt(
    in_project: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    event_path = tmp_path / "event.json"
    event_path.write_text(
        json.dumps(
            {
                "tool_name": "Edit",
                "tool_input": {"file_path": "/x", "old_string": "a", "new_string": "b"},
            }
        ),
        encoding="utf-8",
    )
    rc = cli.main(["gate", "--event-file", str(event_path), "--actor", "tester"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 0
    assert payload["gate_mode"] == "observe"
    assert payload["receipt"]["actor"] == "tester"
    assert payload["receipt"]["tool"] == "runtime.Edit"
    assert payload["blocked"] is False


def _write_runtime_secrets_policy_bundle(tmp_path: Path) -> Path:
    bundle_path = tmp_path / "policy.bundle.json"
    bundle_path.write_text(
        json.dumps(
            {
                "id": "runtime-secrets/v1",
                "rules": [
                    {
                        "id": "BLOCK_SECRET_WRITES",
                        "effect": "deny",
                        "tools": ["runtime.file.write"],
                        "path_prefix": "repo/secrets",
                        "reason": "secret paths require reviewer trust",
                        "allow": {"trust_tiers": ["reviewer"]},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return bundle_path


def test_cli_gate_policy_bundle_blocks_denied_runtime_payload(
    in_project: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle_path = _write_runtime_secrets_policy_bundle(tmp_path)
    event_path = tmp_path / "event.json"
    event_path.write_text(
        json.dumps(
            {
                "method": "tools/call",
                "params": {
                    "name": "file.write",
                    "goal": "Write a deploy secret",
                    "arguments": {"path": "repo/secrets/api-key.txt", "content": "secret"},
                    "state": {"trust_tier": "analyst"},
                },
            }
        ),
        encoding="utf-8",
    )

    rc = cli.main(
        [
            "gate",
            "--event-file",
            str(event_path),
            "--actor",
            "agent-framework",
            "--policy-bundle",
            str(bundle_path),
        ]
    )

    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 1
    assert payload["blocked"] is True
    assert payload["decision"] == "deny"
    assert payload["policy_bundle"] == str(bundle_path)
    assert payload["receipt"]["tool"] == "runtime.file.write"
    assert payload["receipt"]["path"] == ["repo", "secrets", "api-key.txt"]
    assert payload["receipt"]["goal"] == "Write a deploy secret"
    assert payload["receipt"]["state_hash"]
    assert payload["receipt"]["matched_rules"] == ["BLOCK_SECRET_WRITES"]


def test_cli_gate_policy_bundle_blocks_openai_chat_tool_calls_shape(
    in_project: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle_path = _write_runtime_secrets_policy_bundle(tmp_path)
    event_path = tmp_path / "event.json"
    event_path.write_text(
        json.dumps(
            {
                "goal": "Persist deploy secret",
                "state": {"trust_tier": "analyst"},
                "tool_calls": [
                    {
                        "id": "call_123",
                        "type": "function",
                        "function": {
                            "name": "file.write",
                            "arguments": json.dumps(
                                {
                                    "path": "repo/secrets/api-key.txt",
                                    "content": "secret",
                                }
                            ),
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    rc = cli.main(
        [
            "gate",
            "--event-file",
            str(event_path),
            "--actor",
            "openai-chat",
            "--policy-bundle",
            str(bundle_path),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["blocked"] is True
    assert payload["decision"] == "deny"
    assert payload["policy_bundle"] == str(bundle_path)
    assert payload["receipt"]["actor"] == "openai-chat"
    assert payload["receipt"]["tool"] == "runtime.file.write"
    assert payload["receipt"]["path"] == ["repo", "secrets", "api-key.txt"]
    assert payload["receipt"]["goal"] == "Persist deploy secret"
    assert payload["receipt"]["state_hash"]
    assert payload["receipt"]["matched_rules"] == ["BLOCK_SECRET_WRITES"]


def test_cli_gate_policy_bundle_allows_langchain_tool_calls_shape(
    in_project: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle_path = _write_runtime_secrets_policy_bundle(tmp_path)
    event_path = tmp_path / "event.json"
    event_path.write_text(
        json.dumps(
            {
                "intent": "Persist deploy secret",
                "context": {"trust_tier": "reviewer"},
                "tool_calls": [
                    {
                        "id": "call_lc_123",
                        "name": "file.write",
                        "args": {
                            "path": "repo/secrets/api-key.txt",
                            "content": "secret",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    rc = cli.main(
        [
            "gate",
            "--event-file",
            str(event_path),
            "--actor",
            "langchain",
            "--policy-bundle",
            str(bundle_path),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["blocked"] is False
    assert payload["decision"] == "allow"
    assert payload["policy_bundle"] == str(bundle_path)
    assert payload["receipt"]["actor"] == "langchain"
    assert payload["receipt"]["tool"] == "runtime.file.write"
    assert payload["receipt"]["path"] == ["repo", "secrets", "api-key.txt"]
    assert payload["receipt"]["goal"] == "Persist deploy secret"
    assert payload["receipt"]["matched_rules"] == ["BLOCK_SECRET_WRITES:allow:trust_tier"]


def test_cli_gate_policy_bundle_allows_exempted_runtime_payload(
    in_project: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle_path = _write_runtime_secrets_policy_bundle(tmp_path)
    event_path = tmp_path / "event.json"
    event_path.write_text(
        json.dumps(
            {
                "name": "file.write",
                "arguments": {"path": "repo/secrets/api-key.txt", "content": "secret"},
                "state": {"trust_tier": "reviewer"},
            }
        ),
        encoding="utf-8",
    )

    rc = cli.main(["gate", "--event-file", str(event_path), "--policy-bundle", str(bundle_path)])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["blocked"] is False
    assert payload["decision"] == "allow"
    assert payload["receipt"]["matched_rules"] == ["BLOCK_SECRET_WRITES:allow:trust_tier"]
