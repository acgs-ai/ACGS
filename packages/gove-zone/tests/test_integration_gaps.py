"""Tests covering the advisor-flagged gaps:

1. ``.claude/settings.json`` actually wires the hook to the matchers the
   adapter code expects — covers the "handler exists but not wired"
   failure class.
2. ``current_gate_mode`` honors the project-level ``.gove-zone/gate.mode``
   file when env var is unset.
3. ``emit_receipt_for_hook`` routes through a caller-supplied
   :class:`Policy`, so DENY / TRANSFORM / ESCALATE are reachable through
   the same adapter contract — not just hardcoded ALLOW.
4. The ``gove-zone enable`` CLI persists the gate mode to the expected
   path.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gove_zone import cli
from gove_zone.audit import ChainHashAuditStore
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.integration import (
    GateMode,
    current_gate_mode,
    emit_receipt_for_hook,
    resolve_gate_mode_path,
)
from gove_zone.policy import Policy, new_event_id
from gove_zone.tool import ToolCall

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def in_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    monkeypatch.delenv("GOVE_ZONE_AUDIT_PATH", raising=False)
    monkeypatch.delenv("GOVE_ZONE_GATE_MODE", raising=False)
    return tmp_path


def test_settings_json_wires_hook_to_edit_and_bash_matchers() -> None:
    settings_path = REPO_ROOT / ".claude" / "settings.json"
    assert settings_path.exists(), f"missing {settings_path}"
    settings = json.loads(settings_path.read_text(encoding="utf-8"))

    pre = settings.get("hooks", {}).get("PreToolUse", [])
    matchers_with_hook: list[str] = []
    for entry in pre:
        for hook in entry.get("hooks", []):
            if "acgs-emit-receipt.py" in hook.get("command", ""):
                matchers_with_hook.append(entry.get("matcher", ""))

    # The hook code classifies Edit|Write|MultiEdit|NotebookEdit AND Bash
    # (autopilot/ralph/team). Settings must wire both surfaces or the
    # Bash classification branches are dead code.
    assert matchers_with_hook, "acgs-emit-receipt.py is not registered in PreToolUse"
    flat = " | ".join(matchers_with_hook)
    assert "Edit" in flat
    assert "Bash" in flat, (
        "Bash matcher missing — hook's autopilot/ralph/team classifier is unreachable. "
        f"Wired matchers: {matchers_with_hook}"
    )


def test_gate_mode_file_fallback(in_project: Path) -> None:
    # Fail-closed default: nothing configured -> ENFORCE (audit R1 / PR-3).
    assert current_gate_mode() is GateMode.ENFORCE
    mode_file = in_project / ".gove-zone" / "gate.mode"
    mode_file.parent.mkdir(parents=True, exist_ok=True)
    mode_file.write_text("enforce\n", encoding="utf-8")
    assert current_gate_mode() is GateMode.ENFORCE
    # Observe is an explicit file-level opt-in, honored as such.
    mode_file.write_text("observe\n", encoding="utf-8")
    assert current_gate_mode() is GateMode.OBSERVE


def test_gate_mode_unknown_values_fail_closed(
    in_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An unrecognized mode anywhere must resolve to ENFORCE, never observe.
    monkeypatch.setenv("GOVE_ZONE_GATE_MODE", "yolo")
    assert current_gate_mode() is GateMode.ENFORCE
    monkeypatch.delenv("GOVE_ZONE_GATE_MODE")
    mode_file = in_project / ".gove-zone" / "gate.mode"
    mode_file.parent.mkdir(parents=True, exist_ok=True)
    mode_file.write_text("garbage\n", encoding="utf-8")
    assert current_gate_mode() is GateMode.ENFORCE
    # A garbage env value falls through to a valid file opt-in.
    monkeypatch.setenv("GOVE_ZONE_GATE_MODE", "yolo")
    mode_file.write_text("observe\n", encoding="utf-8")
    assert current_gate_mode() is GateMode.OBSERVE
    # ... and to a valid file enforce just the same.
    mode_file.write_text("enforce\n", encoding="utf-8")
    assert current_gate_mode() is GateMode.ENFORCE


def test_gate_mode_unreadable_file_fails_closed(
    in_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A gate.mode path that exists but cannot be read as a file (here: it is a
    # directory, which raises OSError on read) must resolve to ENFORCE.
    monkeypatch.delenv("GOVE_ZONE_GATE_MODE", raising=False)
    mode_path = in_project / ".gove-zone" / "gate.mode"
    mode_path.mkdir(parents=True, exist_ok=True)
    assert current_gate_mode() is GateMode.ENFORCE


def test_env_var_overrides_gate_mode_file(
    in_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (in_project / ".gove-zone").mkdir(parents=True, exist_ok=True)
    (in_project / ".gove-zone" / "gate.mode").write_text("enforce", encoding="utf-8")
    monkeypatch.setenv("GOVE_ZONE_GATE_MODE", "observe")
    assert current_gate_mode() is GateMode.OBSERVE


class _AlwaysDenyPolicy(Policy):
    @property
    def version(self) -> str:
        return "test-deny/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.DENY,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("test-deny",),
            reason="test policy denies everything",
        )


def test_emit_receipt_for_hook_accepts_custom_policy_and_emits_deny(
    in_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Under the (new) enforce default, unsigned runtime-hook auditing needs the
    # dev profile; the subject here is the custom-policy DENY emission.
    monkeypatch.setenv("GOVE_ZONE_PROFILE", "dev")
    receipt = emit_receipt_for_hook(
        {"tool_name": "Edit", "tool_input": {"file_path": "/x"}},
        action_kind="edit",
        actor="tester",
        policy=_AlwaysDenyPolicy(),
    )
    assert receipt is not None
    assert receipt.record.decision is Decision.DENY
    assert receipt.record.policy_version == "test-deny/v0"

    store = ChainHashAuditStore(str(in_project / ".gove-zone" / "audit.jsonl"))
    assert store.verify_chain()["valid"] is True


def test_cli_enable_writes_gate_mode_file(
    in_project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = cli.main(["enable", "--enforce"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 0
    assert payload["gate_mode"] == "enforce"
    assert payload["effective"] == "enforce"
    mode_file = in_project / ".gove-zone" / "gate.mode"
    assert mode_file.read_text(encoding="utf-8").strip() == "enforce"

    rc2 = cli.main(["enable", "--observe"])
    assert rc2 == 0
    assert mode_file.read_text(encoding="utf-8").strip() == "observe"


def test_resolve_gate_mode_path_uses_project_dir(in_project: Path) -> None:
    assert resolve_gate_mode_path() == in_project / ".gove-zone" / "gate.mode"
