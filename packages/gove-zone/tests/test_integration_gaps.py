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

import importlib.util
import json
import os
import subprocess
import sys
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
HOOK_PATH = REPO_ROOT / ".claude" / "hooks" / "acgs-emit-receipt.py"


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


# ---------------------------------------------------------------------------
# PR-3b (#111): the hook delegates gate-mode resolution to the library and
# fails CLOSED when the mode is unresolvable; settings.json pins the project
# venv interpreter and the dev profile.
# ---------------------------------------------------------------------------

_EDIT_PAYLOAD = {"tool_name": "Edit", "tool_input": {"file_path": "/tmp/x", "new_string": "y"}}


def _load_hook_module():
    spec = importlib.util.spec_from_file_location("acgs_emit_receipt_hook", HOOK_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_hook_gate_enforce_delegates_to_library(
    in_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hook = _load_hook_module()
    # Library default (post-#110) is enforce — the hook inherits it.
    assert hook._gate_enforce() is True
    # Explicit env observe opt-in is honored through the same resolver.
    monkeypatch.setenv("GOVE_ZONE_GATE_MODE", "observe")
    assert hook._gate_enforce() is False
    # ... and the file-based opt-in too (the old env-only check ignored it).
    monkeypatch.delenv("GOVE_ZONE_GATE_MODE")
    mode_file = in_project / ".gove-zone" / "gate.mode"
    mode_file.parent.mkdir(parents=True, exist_ok=True)
    mode_file.write_text("observe\n", encoding="utf-8")
    assert hook._gate_enforce() is False


def test_hook_fails_closed_when_gate_mode_unresolvable(
    in_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hook = _load_hook_module()
    # Poisoning sys.modules makes `from gove_zone.integration import ...`
    # raise — the unresolvable-mode path must be enforce, never fail-open.
    monkeypatch.setitem(sys.modules, "gove_zone.integration", None)
    assert hook._gate_enforce() is True


def _run_hook(
    tmp_path: Path,
    env_extra: dict[str, str],
    payload: dict[str, object] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GOVE_ZONE_")}
    env["CLAUDE_PROJECT_DIR"] = str(tmp_path)
    env.update(env_extra)
    return subprocess.run(
        [sys.executable, str(HOOK_PATH)],
        input=json.dumps(payload if payload is not None else _EDIT_PAYLOAD),
        text=True,
        capture_output=True,
        env=env,
        timeout=60,
    )


def test_hook_end_to_end_emits_receipt_under_enforce_default(tmp_path: Path) -> None:
    # Dispatcher-level wiring proof: payload → hook process → adapter → audit
    # chain, under the enforce default (no GOVE_ZONE_GATE_MODE anywhere).
    proc = _run_hook(tmp_path, {"GOVE_ZONE_PROFILE": "dev"})
    assert proc.returncode == 0, proc.stderr
    assert (tmp_path / ".gove-zone" / "audit.jsonl").exists()


def test_hook_end_to_end_blocks_on_emission_failure(tmp_path: Path) -> None:
    # The governed gateway must fail closed when it cannot persist the decision;
    # the diagnostic identifies unavailable governance, not an observer-mode issue.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    proc = _run_hook(
        tmp_path,
        {
            "GOVE_ZONE_PROFILE": "dev",
            "GOVE_ZONE_AUDIT_PATH": str(blocker / "child" / "audit.jsonl"),
        },
    )
    assert proc.returncode == 2
    assert "governance unavailable" in proc.stderr


def test_hook_policy_allow_defers_to_host_permissions(tmp_path: Path) -> None:
    """The PreToolUse contract defines ``permissionDecision: "allow"`` as
    bypassing the host permission system, so echoing a policy ALLOW would
    override the explicit deny entries in ``.claude/settings.json`` (e.g.
    ``git add .``). An allowed governance result must defer: receipt anchors
    are emitted, the permission decision is not.
    """
    proc = _run_hook(tmp_path, {"GOVE_ZONE_PROFILE": "dev"})
    assert proc.returncode == 0, proc.stderr
    response = json.loads(proc.stdout)
    block = response["hookSpecificOutput"]
    assert "permissionDecision" not in block
    assert "permissionDecisionReason" not in block
    assert response["gove_zone"]["receipts"], "the decision must still be receipted"


def test_hook_deny_verdict_is_returned_not_deferred(tmp_path: Path) -> None:
    """Wiring proof for the trust-root path rule through the real hook process:
    a governed ``Write`` of ``observe`` into ``.gove-zone/gate.mode`` is denied,
    and the deny (unlike an allow) is delivered to the runtime."""
    payload = {
        "tool_name": "Write",
        "tool_input": {"file_path": ".gove-zone/gate.mode", "content": "observe"},
    }
    proc = _run_hook(tmp_path, {"GOVE_ZONE_PROFILE": "dev"}, payload)
    assert proc.returncode == 0, proc.stderr
    response = json.loads(proc.stdout)
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "gove_zone" not in response
    # Negative path: the gate-mode file was never written by anything here,
    # and the next resolution still fails closed to enforce.
    assert not (tmp_path / ".gove-zone" / "gate.mode").exists()


def test_hook_observe_mode_never_emits_an_explicit_allow(tmp_path: Path) -> None:
    """Observe mode records the real verdict but must not answer ``allow``:
    an explicit allow would bypass the host permission system it is supposed
    to leave in charge during cutover."""
    payload = {
        "tool_name": "Write",
        "tool_input": {"file_path": ".gove-zone/gate.mode", "content": "observe"},
    }
    proc = _run_hook(
        tmp_path,
        {"GOVE_ZONE_PROFILE": "dev", "GOVE_ZONE_GATE_MODE": "observe"},
        payload,
    )
    assert proc.returncode == 0, proc.stderr
    block = json.loads(proc.stdout)["hookSpecificOutput"]
    assert "permissionDecision" not in block
    assert "recorded but not enforced" in proc.stderr


def test_hook_end_to_end_production_without_signer_blocks(tmp_path: Path) -> None:
    # This is why settings.json pins GOVE_ZONE_PROFILE=dev: the governed gateway
    # refuses to construct a production receipt path without a signer.
    proc = _run_hook(tmp_path, {})
    assert proc.returncode == 2
    assert "signer" in proc.stderr


def test_settings_launcher_fails_closed_when_venv_missing(tmp_path: Path) -> None:
    # Behavioral proof for the deployed launcher string itself (not just a
    # substring assert): run the EXACT command from settings.json via bash
    # with a project dir that has no .venv — the guard must exit 2 before
    # any interpreter is exec'd.
    settings = json.loads((REPO_ROOT / ".claude" / "settings.json").read_text(encoding="utf-8"))
    command = next(
        hook["command"]
        for entry in settings.get("hooks", {}).get("PreToolUse", [])
        for hook in entry.get("hooks", [])
        if "acgs-emit-receipt.py" in hook.get("command", "")
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("GOVE_ZONE_")}
    env["CLAUDE_PROJECT_DIR"] = str(tmp_path)  # no .venv here
    proc = subprocess.run(
        ["bash", "-c", command],
        input="",
        text=True,
        capture_output=True,
        env=env,
        timeout=60,
    )
    assert proc.returncode == 2
    assert "venv missing" in proc.stderr


def test_settings_json_pins_venv_python_and_dev_profile() -> None:
    settings = json.loads((REPO_ROOT / ".claude" / "settings.json").read_text(encoding="utf-8"))
    commands = [
        hook.get("command", "")
        for entry in settings.get("hooks", {}).get("PreToolUse", [])
        for hook in entry.get("hooks", [])
        if "acgs-emit-receipt.py" in hook.get("command", "")
    ]
    assert len(commands) >= 2  # Edit|Write|MultiEdit matcher + Bash matcher
    for command in commands:
        assert ".venv/bin/python" in command, command  # interpreter pinned to project venv
        assert "GOVE_ZONE_PROFILE=dev" in command, command  # unsigned auditing acknowledged
        assert "exit 2" in command, command  # missing venv fails closed, not open
