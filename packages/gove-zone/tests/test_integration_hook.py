"""Tests for gove_zone.integration — the runtime-hook adapter.

Covers the slice-1 contract:

* Observe-mode (default) returns a Receipt on success and ``None`` on
  internal failure — preserving existing fail-open hook behavior.
* Enforce-mode raises :class:`GateModeError` instead of swallowing failures.
* The receipt anchors into the on-disk audit chain and that chain verifies.
* Audit path resolution honors override > CLAUDE_PROJECT_DIR > cwd.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from gove_zone.audit import ChainHashAuditStore
from gove_zone.integration import (
    GateMode,
    GateModeError,
    _tool_name_and_input_from_payload,
    current_gate_mode,
    emit_receipt_for_hook,
    resolve_audit_path,
    tool_call_from_hook_payload,
    tool_calls_from_hook_payload,
)


@pytest.fixture
def project_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    monkeypatch.delenv("GOVE_ZONE_AUDIT_PATH", raising=False)
    monkeypatch.delenv("GOVE_ZONE_GATE_MODE", raising=False)
    return tmp_path


def _edit_payload() -> dict[str, Any]:
    return {
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "/repo/README.md",
            "old_string": "hello",
            "new_string": "hello world",
        },
    }


def test_tool_call_from_hook_payload_accepts_mcp_tool_call_shape() -> None:
    call = tool_call_from_hook_payload(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "file.write",
                "arguments": {
                    "path": "repo/policy.bundle.json",
                    "content": "deny secrets",
                },
                "state": {"trust_tier": "analyst"},
                "goal": "Publish policy bundle",
            },
        },
        action_kind="mcp",
        actor="mcp-host",
    )

    assert call.name == "runtime.file.write"
    assert call.actor == "mcp-host"
    assert call.path == ("repo", "policy.bundle.json")
    assert call.goal == "Publish policy bundle"
    assert call.state == {"trust_tier": "analyst"}
    assert call.args["action_kind"] == "mcp"
    summary = call.args["summary"]
    assert summary["path"]["type"] == "str"
    assert summary["content"]["len"] == len("deny secrets")
    assert isinstance(summary["content"]["sha256"], str)


def test_tool_call_from_hook_payload_accepts_function_call_json_arguments() -> None:
    call = tool_call_from_hook_payload(
        {
            "type": "function_call",
            "name": "email.send",
            "arguments": json.dumps(
                {
                    "to": "review@example.com",
                    "body": "please review the evidence bundle",
                }
            ),
        },
        action_kind="function-call",
        actor="agent-framework",
    )

    assert call.name == "runtime.email.send"
    assert call.actor == "agent-framework"
    assert call.path == ()
    assert call.args["action_kind"] == "function-call"
    summary = call.args["summary"]
    assert summary["to"]["type"] == "str"
    assert summary["body"]["len"] == len("please review the evidence bundle")


def test_tool_call_from_hook_payload_accepts_openai_tool_calls_shape() -> None:
    call = tool_call_from_hook_payload(
        {
            "goal": "Persist governed launch evidence",
            "state": {"trust_tier": "release-operator"},
            "tool_calls": [
                {
                    "id": "call_123",
                    "type": "function",
                    "function": {
                        "name": "file.write",
                        "arguments": json.dumps(
                            {
                                "path": "dist-release-evidence/manifest.json",
                                "content": "proof",
                            }
                        ),
                    },
                }
            ],
        },
        action_kind="openai-chat-tool-call",
        actor="openai-chat-bridge",
    )

    assert call.name == "runtime.file.write"
    assert call.actor == "openai-chat-bridge"
    assert call.path == ("dist-release-evidence", "manifest.json")
    assert call.goal == "Persist governed launch evidence"
    assert call.state == {"trust_tier": "release-operator"}
    assert call.args["action_kind"] == "openai-chat-tool-call"
    summary = call.args["summary"]
    assert summary["path"]["type"] == "str"
    assert summary["content"]["len"] == len("proof")
    assert isinstance(summary["content"]["sha256"], str)
    assert len(summary["content"]["sha256"]) == 64


def test_tool_call_from_hook_payload_accepts_openai_responses_output_function_call_shape() -> None:
    call = tool_call_from_hook_payload(
        {
            "goal": "Persist governed launch evidence",
            "state": {"trust_tier": "release-operator"},
            "output": [
                {
                    "id": "fc_123",
                    "call_id": "call_123",
                    "type": "function_call",
                    "name": "file.write",
                    "arguments": json.dumps(
                        {
                            "path": "dist-release-evidence/manifest.json",
                            "content": "proof",
                        }
                    ),
                }
            ],
        },
        action_kind="openai-responses-function-call",
        actor="openai-responses-bridge",
    )

    assert call.name == "runtime.file.write"
    assert call.actor == "openai-responses-bridge"
    assert call.path == ("dist-release-evidence", "manifest.json")
    assert call.goal == "Persist governed launch evidence"
    assert call.state == {"trust_tier": "release-operator"}
    assert call.args["action_kind"] == "openai-responses-function-call"
    summary = call.args["summary"]
    assert summary["path"]["type"] == "str"
    assert summary["content"]["len"] == len("proof")
    assert isinstance(summary["content"]["sha256"], str)
    assert len(summary["content"]["sha256"]) == 64


def test_tool_call_from_hook_payload_accepts_nested_openai_response_object() -> None:
    call = tool_call_from_hook_payload(
        {
            "response": {
                "context": {"trust_tier": "reviewer"},
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": "planning"}],
                    },
                    {
                        "type": "function_call",
                        "name": "shell.run",
                        "arguments": json.dumps(
                            {"path": "scripts/verify.sh", "command": "make verify"}
                        ),
                    },
                ],
            }
        },
        action_kind="openai-responses-function-call",
        actor="openai-responses-bridge",
    )

    assert call.name == "runtime.shell.run"
    assert call.path == ("scripts", "verify.sh")
    assert call.state == {"trust_tier": "reviewer"}
    summary = call.args["summary"]
    assert summary["command"]["len"] == len("make verify")


def test_tool_call_from_hook_payload_batches_multiple_openai_responses_function_calls() -> None:
    call = tool_call_from_hook_payload(
        {
            "output": [
                {"type": "function_call", "name": "file.write", "arguments": {"path": "README.md"}},
                {
                    "type": "function_call",
                    "name": "shell.run",
                    "arguments": {"command": "make verify"},
                },
            ]
        },
        action_kind="openai-responses-batch",
        actor="openai-responses-bridge",
    )

    assert call.name == "runtime.responses.output.batch"
    assert call.path == ()
    summary = call.args["summary"]
    assert summary["function_call_count"] == 2
    assert summary["function_call_names"]["type"] == "list"


def test_tool_call_from_hook_payload_accepts_langchain_tool_call_shape() -> None:
    call = tool_call_from_hook_payload(
        {
            "tool_calls": [
                {
                    "name": "shell.run",
                    "args": {
                        "path": "scripts/deploy.sh",
                        "command": "make verify",
                    },
                }
            ],
            "context": {"framework": "langchain"},
        },
        action_kind="langchain-tool-call",
        actor="langchain-bridge",
    )

    assert call.name == "runtime.shell.run"
    assert call.actor == "langchain-bridge"
    assert call.path == ("scripts", "deploy.sh")
    assert call.goal == ""
    assert call.state == {"framework": "langchain"}
    summary = call.args["summary"]
    assert summary["path"]["type"] == "str"
    assert summary["command"]["len"] == len("make verify")


def test_tool_call_from_hook_payload_batches_multiple_tool_calls_without_selecting_one() -> None:
    call = tool_call_from_hook_payload(
        {
            "tool_calls": [
                {
                    "id": "call_file",
                    "function": {"name": "file.write", "arguments": {"path": "README.md"}},
                },
                {"id": "call_shell", "name": "shell.run", "args": {"command": "make verify"}},
            ],
        },
        action_kind="tool-call-batch",
        actor="agent-framework",
    )

    assert call.name == "runtime.tool_calls.batch"
    assert call.path == ()
    summary = call.args["summary"]
    assert summary["tool_call_count"] == 2
    assert summary["tool_call_names"]["type"] == "list"


def test_tool_calls_from_hook_payload_expands_batched_tool_calls_for_policy_gate() -> None:
    calls = tool_calls_from_hook_payload(
        {
            "goal": "Persist governed launch artifacts",
            "state": {"trust_tier": "analyst"},
            "tool_calls": [
                {
                    "id": "call_shell",
                    "type": "function",
                    "function": {
                        "name": "shell.run",
                        "arguments": json.dumps(
                            {"path": "scripts/verify.sh", "command": "make verify"}
                        ),
                    },
                },
                {
                    "id": "call_file",
                    "type": "function",
                    "function": {
                        "name": "file.write",
                        "arguments": json.dumps(
                            {"path": "repo/secrets/api-key.txt", "content": "secret"}
                        ),
                    },
                },
            ],
        },
        action_kind="tool-call-batch",
        actor="openai-chat",
    )

    assert [call.name for call in calls] == ["runtime.shell.run", "runtime.file.write"]
    assert [call.path for call in calls] == [
        ("scripts", "verify.sh"),
        ("repo", "secrets", "api-key.txt"),
    ]
    assert {call.goal for call in calls} == {"Persist governed launch artifacts"}
    assert {call.actor for call in calls} == {"openai-chat"}
    assert all(call.state == {"trust_tier": "analyst"} for call in calls)


def test_tool_calls_from_hook_payload_expands_batched_openai_responses_output() -> None:
    calls = tool_calls_from_hook_payload(
        {
            "response": {
                "intent": "Persist governed launch artifacts",
                "context": {"trust_tier": "analyst"},
                "output": [
                    {
                        "type": "function_call",
                        "name": "shell.run",
                        "arguments": json.dumps(
                            {"path": "scripts/verify.sh", "command": "make verify"}
                        ),
                    },
                    {
                        "type": "function_call",
                        "name": "file.write",
                        "arguments": json.dumps(
                            {"path": "repo/secrets/api-key.txt", "content": "secret"}
                        ),
                    },
                ],
            }
        },
        action_kind="responses-output-batch",
        actor="openai-responses",
    )

    assert [call.name for call in calls] == ["runtime.shell.run", "runtime.file.write"]
    assert [call.path for call in calls] == [
        ("scripts", "verify.sh"),
        ("repo", "secrets", "api-key.txt"),
    ]
    assert {call.goal for call in calls} == {"Persist governed launch artifacts"}
    assert all(call.state == {"trust_tier": "analyst"} for call in calls)


def test_tool_calls_from_hook_payload_returns_malformed_batch_for_unparseable_batch() -> None:
    calls = tool_calls_from_hook_payload(
        {
            "goal": "Persist deploy artifacts",
            "state": {"trust_tier": "analyst"},
            "tool_calls": [
                {
                    "id": "call_without_name",
                    "type": "function",
                    "function": {
                        "arguments": json.dumps({"path": "repo/secrets/api-key.txt"}),
                    },
                },
                "not-a-tool-call",
            ],
        },
        action_kind="tool-call-batch",
        actor="openai-chat",
    )

    assert len(calls) == 1
    call = calls[0]
    assert call.name == "runtime.malformed_batch"
    assert call.goal == "Persist deploy artifacts"
    assert call.state == {"trust_tier": "analyst"}
    summary = call.args["summary"]
    assert summary["batch_shape"] == "tool_calls"
    assert summary["reason"] == "unparseable child tool call in batch"
    assert summary["item_count"] == 2
    assert summary["parseable_count"] == 0


def test_tool_calls_from_hook_payload_returns_malformed_batch_for_responses_output() -> None:
    calls = tool_calls_from_hook_payload(
        {
            "response": {
                "intent": "Persist deploy artifacts",
                "context": {"trust_tier": "analyst"},
                "output": [
                    {
                        "type": "function_call",
                        "name": "shell.run",
                        "arguments": json.dumps({"path": "scripts/verify.sh"}),
                    },
                    {
                        "type": "function_call",
                        "arguments": json.dumps({"path": "repo/secrets/api-key.txt"}),
                    },
                ],
            }
        },
        action_kind="responses-output-batch",
        actor="openai-responses",
    )

    assert len(calls) == 1
    call = calls[0]
    assert call.name == "runtime.malformed_batch"
    assert call.goal == "Persist deploy artifacts"
    assert call.state == {"trust_tier": "analyst"}
    assert call.args["summary"] == {
        "batch_shape": "responses.output",
        "reason": "unparseable function_call output item in batch",
        "item_count": 2,
        "parseable_count": 1,
        "unparseable_count": 1,
    }


def test_observe_mode_appends_receipt_and_chain_verifies(
    project_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Observe is no longer the default — it is an explicit opt-in (PR-3).
    monkeypatch.setenv("GOVE_ZONE_GATE_MODE", "observe")
    receipt = emit_receipt_for_hook(
        _edit_payload(),
        action_kind="edit",
        actor="test-actor",
    )

    assert receipt is not None
    assert receipt.actor == "test-actor"
    assert receipt.record.tool == "runtime.Edit"
    assert receipt.audit_hash and receipt.audit_hash != "0" * 64

    audit_path = project_dir / ".gove-zone" / "audit.jsonl"
    assert audit_path.exists()
    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["decision"] == "allow"
    assert event["matched_rules"] == ["action_kind:edit"]
    assert event["actor"] == "test-actor"
    assert event["path"] == ["repo", "README.md"]
    assert event["decision_request_hash"]

    store = ChainHashAuditStore(str(audit_path))
    verdict = store.verify_chain()
    assert verdict["valid"] is True


def test_default_mode_is_enforce_and_gates_on_failure(
    project_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Audit R1 acceptance: with NO gate mode configured (no env, no file), an
    emission failure is gated — raised, not silently swallowed — proven through
    the adapter entry point, not a unit call."""
    bad = project_dir / "audit-blocker"
    bad.write_text("not a directory")
    monkeypatch.setenv("GOVE_ZONE_AUDIT_PATH", str(bad / "child" / "audit.jsonl"))
    # Dev profile so the production-signer guard does not short-circuit before
    # the emission-failure path; the mode default is what is under test.
    monkeypatch.setenv("GOVE_ZONE_PROFILE", "dev")

    assert current_gate_mode() is GateMode.ENFORCE
    with pytest.raises(GateModeError, match="receipt emission failed under enforce mode"):
        emit_receipt_for_hook(
            _edit_payload(),
            action_kind="edit",
            actor="test-actor",
        )


def test_observe_mode_swallows_internal_failure(
    project_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Force resolve_audit_path -> directory that cannot be created.
    bad = project_dir / "audit-blocker"
    bad.write_text("not a directory")
    monkeypatch.setenv("GOVE_ZONE_AUDIT_PATH", str(bad / "child" / "audit.jsonl"))
    # Observe is no longer the default — it is an explicit opt-in.
    monkeypatch.setenv("GOVE_ZONE_GATE_MODE", "observe")

    assert current_gate_mode() is GateMode.OBSERVE
    result = emit_receipt_for_hook(
        _edit_payload(),
        action_kind="edit",
        actor="test-actor",
    )
    assert result is None  # fail-open


def test_enforce_mode_raises_on_failure(
    project_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bad = project_dir / "audit-blocker"
    bad.write_text("not a directory")
    monkeypatch.setenv("GOVE_ZONE_AUDIT_PATH", str(bad / "child" / "audit.jsonl"))
    monkeypatch.setenv("GOVE_ZONE_GATE_MODE", "enforce")
    # Dev profile so the production-signer guard does not short-circuit before the
    # emission-failure path this test is named for.
    monkeypatch.setenv("GOVE_ZONE_PROFILE", "dev")

    assert current_gate_mode() is GateMode.ENFORCE
    with pytest.raises(GateModeError, match="receipt emission failed under enforce mode"):
        emit_receipt_for_hook(
            _edit_payload(),
            action_kind="edit",
            actor="test-actor",
        )


def test_enforce_mode_production_no_signer_fails_loud(
    project_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ENFORCE + production profile (the default; GOVE_ZONE_PROFILE unset) + no signer
    # threaded into the passive auditor must fail closed LOUD, before any emission.
    monkeypatch.setenv("GOVE_ZONE_GATE_MODE", "enforce")
    monkeypatch.delenv("GOVE_ZONE_PROFILE", raising=False)

    assert current_gate_mode() is GateMode.ENFORCE
    with pytest.raises(GateModeError, match="requires a configured signer"):
        emit_receipt_for_hook(
            _edit_payload(),
            action_kind="edit",
            actor="test-actor",
        )


def test_enforce_mode_dev_profile_emits_unsigned(
    project_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ENFORCE proceeds under the explicit dev profile: the passive auditor emits an
    # unsigned audit-anchor Receipt rather than failing closed (signing stays
    # orthogonal to GateMode).
    monkeypatch.setenv("GOVE_ZONE_GATE_MODE", "enforce")
    monkeypatch.setenv("GOVE_ZONE_PROFILE", "dev")

    assert current_gate_mode() is GateMode.ENFORCE
    receipt = emit_receipt_for_hook(
        _edit_payload(),
        action_kind="edit",
        actor="test-actor",
    )

    assert receipt is not None
    assert (project_dir / ".gove-zone" / "audit.jsonl").exists()


def test_audit_path_resolution_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    explicit = tmp_path / "explicit.jsonl"
    project = tmp_path / "project"
    monkeypatch.setenv("GOVE_ZONE_AUDIT_PATH", str(explicit))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(project))
    assert resolve_audit_path() == explicit

    monkeypatch.delenv("GOVE_ZONE_AUDIT_PATH")
    assert resolve_audit_path() == project / ".gove-zone" / "audit.jsonl"

    monkeypatch.delenv("CLAUDE_PROJECT_DIR")
    monkeypatch.chdir(tmp_path)
    assert resolve_audit_path() == tmp_path / ".gove-zone" / "audit.jsonl"


def test_gate_adapter_appends_mcp_payload_receipt(
    project_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Subject is MCP payload adaptation; dev profile acknowledges unsigned
    # runtime-hook auditing under the (new) enforce default.
    monkeypatch.setenv("GOVE_ZONE_PROFILE", "dev")
    receipt = emit_receipt_for_hook(
        {
            "method": "tools/call",
            "params": {
                "name": "repo.apply_patch",
                "arguments": {"path": "src/gove_zone/integration.py"},
            },
        },
        action_kind="mcp",
        actor="codex-bridge",
    )

    assert receipt is not None
    assert receipt.record.tool == "runtime.repo.apply_patch"
    assert receipt.record.actor == "codex-bridge"
    assert receipt.record.path == ("src", "gove_zone", "integration.py")

    audit_path = project_dir / ".gove-zone" / "audit.jsonl"
    events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    assert events[-1]["tool"] == "runtime.repo.apply_patch"
    assert events[-1]["path"] == ["src", "gove_zone", "integration.py"]


# --- Neutrality: the generic, no-privileged-default parse path -----------------
# These guard the claim that the gate treats every caller the same (see
# docs/INTEGRATION_MATRIX.md and docs/CLAIMS.md "Gate position is
# framework-neutral"). They call the private resolver directly so the
# (name, args) tuple isolates each branch without the runtime.* prefix that
# the public tool_call_from_hook_payload adds via _runtime_context_from_payload.


def test_tool_name_and_input_resolves_top_level_name_args_generic_shape() -> None:
    """Generic bridge payload ``{name, args}`` with no wrapper resolves directly."""
    name, args = _tool_name_and_input_from_payload(
        {"name": "file.write", "args": {"path": "repo/out.txt", "content": "data"}}
    )
    assert name == "file.write"
    assert args == {"path": "repo/out.txt", "content": "data"}


def test_tool_name_and_input_resolves_tool_dict_name_args_generic_shape() -> None:
    """Generic bridge payload ``{tool: {name, args}}`` resolves via the tool dict."""
    name, args = _tool_name_and_input_from_payload(
        {"tool": {"name": "shell.run", "args": {"command": "echo hi"}}}
    )
    assert name == "shell.run"
    assert args == {"command": "echo hi"}


def test_tool_name_and_input_hook_style_wins_over_top_level_name() -> None:
    """Hook style (``tool_name``) is checked first: no runtime is the privileged
    default, but resolution order is deterministic — the hook branch wins even
    when a generic top-level ``name`` is also present."""
    name, args = _tool_name_and_input_from_payload(
        {
            "tool_name": "Edit",
            "tool_input": {"file_path": "/repo/README.md", "new_string": "x"},
            "name": "file.write",
            "args": {"path": "other.txt", "content": "y"},
        }
    )
    assert name == "Edit"
    assert args == {"file_path": "/repo/README.md", "new_string": "x"}
