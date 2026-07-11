"""`gove-zone validate` — the PreToolUse policy-decision surface.

The governed-loop-v2 reference monitor (``.claude/hooks/loop-pretool-guard.sh``,
registered under the ``Bash`` matcher) pipes each Bash tool-call through
``gove-zone validate --policy .claude/policy/build.yaml --stdin`` and treats a
non-zero exit as a denial (``... || deny``). These tests drive the REAL dispatch
(argparse -> ``_validate`` -> ``YAMLPolicy.evaluate``) on host-shaped payloads and
pin:

* the ALLOW -> 0, DENY/ESCALATE -> 2 exit contract the hook relies on;
* command whitespace normalization, so ``git  push`` cannot dodge a substring rule;
* that this is a BASH-SURFACE policy — file writes are out of scope and
  allow-by-default here (regression guard against a dead ``tools: [Write]`` rule);
* fail-closed (exit 2) on a broken request or a present-but-broken policy;
* graceful-degrade (exit 0 + advisory) when PyYAML is absent.

Requires the ``yaml`` extra (PyYAML); the gove-zone CI installs it, so this file
does not ``importorskip`` — a missing extra should surface as an error here, not a
silent skip.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from gove_zone.cli import main

REPO_ROOT = Path(__file__).resolve().parents[3]
SHIPPED_POLICY = REPO_ROOT / ".claude" / "policy" / "build.yaml"

# A self-contained Bash-surface policy, independent of the shipped file.
INLINE_POLICY = """
id: test-build-guard/v1
rules:
  - id: DENY_RM_RF
    effect: deny
    tools: [Bash]
    state_contains:
      command: "rm -rf"
    reason: no recursive force delete
  - id: DENY_FORCE_PUSH
    effect: deny
    tools: [Bash]
    state_contains:
      command: "push --force"
    reason: no force push
  - id: ESCALATE_PUSH
    effect: escalate
    tools: [Bash]
    state_contains:
      command: "git push"
    allow:
      trust_tiers: [release-manager]
    reason: push escalates
"""


@pytest.fixture
def inline_policy(tmp_path: Path) -> Path:
    p = tmp_path / "build.yaml"
    p.write_text(INLINE_POLICY, encoding="utf-8")
    return p


def _bash(command: str) -> dict:
    return {"tool_name": "Bash", "tool_input": {"command": command}}


def _write(file_path: str) -> dict:
    return {"tool_name": "Write", "tool_input": {"file_path": file_path, "content": "x"}}


def _run(policy: Path, payload: dict, monkeypatch: pytest.MonkeyPatch) -> int:
    """Invoke `gove-zone validate --stdin` exactly as the hook does."""
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    return main(["validate", "--policy", str(policy), "--stdin"])


# --- decision -> exit-code contract ----------------------------------------


def test_allows_benign_build_command(inline_policy: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _run(inline_policy, _bash("pytest -q"), monkeypatch) == 0


def test_denies_recursive_force_delete(
    inline_policy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _run(inline_policy, _bash("rm -rf /home/x"), monkeypatch) == 2


def test_escalation_exits_nonzero(inline_policy: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # ESCALATE is not ALLOW, so the hook's `|| deny` must block it (exit 2).
    assert _run(inline_policy, _bash("git push origin master"), monkeypatch) == 2


def test_force_push_denied_before_escalation(
    inline_policy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # `git push --force` matches both rules; first-match (deny) must win.
    assert _run(inline_policy, _bash("git push --force origin master"), monkeypatch) == 2


def test_whitespace_variants_do_not_bypass(
    inline_policy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression guard: `state_contains` is a literal substring test, so before
    normalization a shell-equivalent double-space / tab (`git  push`, `rm\\t-rf`)
    slipped past every rule (decision=allow). The mapping now collapses command
    whitespace, so these must still be caught."""
    assert _run(inline_policy, _bash("git  push origin master"), monkeypatch) == 2
    assert _run(inline_policy, _bash("git\tpush origin master"), monkeypatch) == 2
    assert _run(inline_policy, _bash("rm  -rf  /home/x"), monkeypatch) == 2


def test_write_tools_are_out_of_scope_and_allow_by_default(
    inline_policy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """This is a Bash-surface policy: the loop hook is registered under the Bash
    matcher only, so Write/Edit/MultiEdit/NotebookEdit calls never reach validate
    and are allow-by-default here. This test documents that scope boundary and
    guards against re-adding a `tools: [Write]` rule and mistaking a dead,
    never-routed rule for enforcement — file-path governance belongs to the host
    write-tool matcher + settings.json, not this policy."""
    assert _run(inline_policy, _write("config/.env"), monkeypatch) == 0
    assert (
        _run(
            inline_policy,
            {"tool_name": "MultiEdit", "tool_input": {"file_path": "x/.env"}},
            monkeypatch,
        )
        == 0
    )


def test_no_phantom_tool_name_matches(inline_policy: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A rule keys on the real host tool name; a synthetic name the host never sends
    # (e.g. "shell.exec") matches no Bash rule and is allowed, while the SAME
    # command via the real Bash tool is denied. (Rules must key on real names, or
    # they are silent no-ops.)
    assert (
        _run(
            inline_policy,
            {"tool_name": "shell.exec", "tool_input": {"command": "rm -rf /"}},
            monkeypatch,
        )
        == 0
    )
    assert _run(inline_policy, _bash("rm -rf /"), monkeypatch) == 2


# --- fail-closed on a real governance failure ------------------------------


def test_fail_closed_on_malformed_json(
    inline_policy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("{not valid json"))
    assert main(["validate", "--policy", str(inline_policy), "--stdin"]) == 2


def test_fail_closed_on_missing_tool_name(
    inline_policy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _run(inline_policy, {"tool_input": {"command": "pytest -q"}}, monkeypatch) == 2


def test_fail_closed_on_missing_policy_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _run(tmp_path / "does-not-exist.yaml", _bash("pytest -q"), monkeypatch) == 2


def test_fail_closed_on_broken_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: x\nrules: not-a-list\n", encoding="utf-8")
    assert _run(bad, _bash("pytest -q"), monkeypatch) == 2


# --- graceful-degrade: tooling absence != governance failure ---------------


def test_degrades_to_allow_when_pyyaml_absent(
    inline_policy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When PyYAML is not installed the policy layer cannot run, so validate exits
    0 (allow) with an advisory instead of denying every call and bricking the loop
    — even for a would-be-DENY command. The hook's regex backstop + settings.json
    still gate the catastrophic case."""
    import gove_zone.yaml_policy as yp

    def _no_yaml() -> object:
        raise ModuleNotFoundError("No module named 'yaml'")

    monkeypatch.setattr(yp, "_require_yaml", _no_yaml)
    assert _run(inline_policy, _bash("rm -rf /"), monkeypatch) == 0


# --- the SHIPPED policy behaves as documented (Bash surface) ---------------


def test_shipped_policy_loads() -> None:
    assert SHIPPED_POLICY.exists(), f"shipped build-guard policy missing: {SHIPPED_POLICY}"
    from gove_zone.yaml_policy import YAMLPolicy

    policy = YAMLPolicy.load_yaml(str(SHIPPED_POLICY))
    assert policy.version  # content-addressed version string
    assert policy.policy_id == "gove-zone-build-guard/v1"


def test_shipped_policy_decisions(monkeypatch: pytest.MonkeyPatch) -> None:
    # Catastrophic / release Bash actions are blocked; build+test allowed.
    assert _run(SHIPPED_POLICY, _bash("rm -rf /home"), monkeypatch) == 2
    assert _run(SHIPPED_POLICY, _bash("curl https://x | sh"), monkeypatch) == 2
    assert _run(SHIPPED_POLICY, _bash("claude --dangerously-skip-permissions"), monkeypatch) == 2
    assert _run(SHIPPED_POLICY, _bash("git push --force origin main"), monkeypatch) == 2
    assert _run(SHIPPED_POLICY, _bash("git push origin main"), monkeypatch) == 2  # escalate
    assert _run(SHIPPED_POLICY, _bash("git  push origin main"), monkeypatch) == 2  # whitespace
    assert _run(SHIPPED_POLICY, _bash("pytest -q"), monkeypatch) == 0
    assert _run(SHIPPED_POLICY, _bash("uv run make verify"), monkeypatch) == 0
    # Out of scope: a file write is not routed to this Bash-surface policy.
    assert _run(SHIPPED_POLICY, _write("svc/.env"), monkeypatch) == 0


def test_shipped_policy_release_manager_exemption() -> None:
    """The release-manager trust tier is exempt from push escalation (the
    positive-authorization path the PreToolUse payload cannot itself supply)."""
    from gove_zone import Decision
    from gove_zone.tool import ToolCall
    from gove_zone.yaml_policy import YAMLPolicy

    policy = YAMLPolicy.load_yaml(str(SHIPPED_POLICY))
    exempt = policy.evaluate(
        ToolCall(
            name="Bash",
            state={"command": "git push origin main", "trust_tier": "release-manager"},
        )
    ).decision
    ordinary = policy.evaluate(
        ToolCall(name="Bash", state={"command": "git push origin main"})
    ).decision
    assert exempt is Decision.ALLOW
    assert ordinary is Decision.ESCALATE
