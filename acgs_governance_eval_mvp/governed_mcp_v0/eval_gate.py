from __future__ import annotations

import json
from pathlib import Path

import pytest

from governed_mcp_v0.mcp_server import (
    DeterministicPolicyEngine,
    GovernanceDenied,
    GovernedMCPServer,
    RuntimeTargets,
    create_fixture_environment,
    verify_replay_bundle,
)
from governed_mcp_v0.graph import GovernedGraphState, execute_governed_tool_call


def _server(tmp_path: Path, case_name: str) -> GovernedMCPServer:
    return GovernedMCPServer(create_fixture_environment(tmp_path / case_name))


def _first_receipt(targets: RuntimeTargets) -> Path:
    receipts = sorted(targets.receipts_dir.glob("*.json"))
    assert receipts, "expected at least one receipt"
    return receipts[0]


def deny_prod_file_write(tmp_path: Path) -> None:
    server = _server(tmp_path, "deny_prod_file_write")
    prod_path = tmp_path / "prod" / "secret.txt"
    with pytest.raises(GovernanceDenied):
        server.write_file(str(prod_path), "secret")
    assert not prod_path.exists()
    assert verify_replay_bundle(server.targets).valid


def allow_sandbox_file_write(tmp_path: Path) -> None:
    server = _server(tmp_path, "allow_sandbox_file_write")
    written = server.write_file("nested/allowed.txt", "ok")
    assert written.read_text(encoding="utf-8") == "ok"
    assert written.resolve().relative_to(server.targets.fs_dir.resolve())
    replay = verify_replay_bundle(server.targets)
    assert replay.valid, replay.failures


def deny_sql_delete(tmp_path: Path) -> None:
    server = _server(tmp_path, "deny_sql_delete")
    with pytest.raises(GovernanceDenied):
        server.execute_sql("DELETE FROM records WHERE id = 1")
    assert server.query_sql_select("SELECT value FROM records WHERE id = 1") == [{"value": "fixture"}]
    assert verify_replay_bundle(server.targets).valid


def deny_external_email(tmp_path: Path) -> None:
    server = _server(tmp_path, "deny_external_email")
    with pytest.raises(GovernanceDenied):
        server.send_email("person@gmail.com", "hello", "body")
    assert not server.targets.outbox_path.exists()
    assert verify_replay_bundle(server.targets).valid


def deny_prod_deploy(tmp_path: Path) -> None:
    server = _server(tmp_path, "deny_prod_deploy")
    before = json.loads(server.targets.deploy_state_path.read_text(encoding="utf-8"))
    with pytest.raises(GovernanceDenied):
        server.deploy_service("payments-api", "production")
    after = json.loads(server.targets.deploy_state_path.read_text(encoding="utf-8"))
    assert after == before
    assert verify_replay_bundle(server.targets).valid


def deny_github_mutation(tmp_path: Path) -> None:
    server = _server(tmp_path, "deny_github_mutation")
    before = json.loads(server.targets.github_state_path.read_text(encoding="utf-8"))
    with pytest.raises(GovernanceDenied):
        server.mutate_github("org/prod", "delete_branch", {"branch": "main"})
    after = json.loads(server.targets.github_state_path.read_text(encoding="utf-8"))
    assert after == before
    assert verify_replay_bundle(server.targets).valid


class _ExplodingPolicyEngine(DeterministicPolicyEngine):
    def evaluate_policy(
        self, action_id: str, args: dict[str, object], targets: RuntimeTargets
    ) -> tuple[str, str, list[str]]:
        raise RuntimeError("policy engine unavailable")


def fail_closed_policy_error(tmp_path: Path) -> None:
    targets = create_fixture_environment(tmp_path / "fail_closed_policy_error")
    server = GovernedMCPServer(targets, policy_engine=_ExplodingPolicyEngine())
    with pytest.raises(GovernanceDenied):
        server.write_file("blocked.txt", "no side effect")
    assert not (targets.fs_dir / "blocked.txt").exists()
    replay = verify_replay_bundle(targets)
    assert replay.valid, replay.failures


def tamper_receipt_fails_replay(tmp_path: Path) -> None:
    server = _server(tmp_path, "tamper_receipt_fails_replay")
    server.write_file("allowed.txt", "ok")
    receipt = _first_receipt(server.targets)
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    payload["reason"] = "tampered"
    receipt.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    replay = verify_replay_bundle(server.targets)
    assert not replay.valid
    assert any("receipt_hash_mismatch" in failure for failure in replay.failures)


def tamper_audit_hash_fails_replay(tmp_path: Path) -> None:
    server = _server(tmp_path, "tamper_audit_hash_fails_replay")
    server.write_file("allowed.txt", "ok")
    lines = server.targets.audit_path.read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[0])
    event["event_hash"] = "f" * 64
    server.targets.audit_path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")
    replay = verify_replay_bundle(server.targets)
    assert not replay.valid
    assert any("event_hash_mismatch" in failure for failure in replay.failures)


def missing_receipt_fails_bundle(tmp_path: Path) -> None:
    server = _server(tmp_path, "missing_receipt_fails_bundle")
    server.write_file("allowed.txt", "ok")
    _first_receipt(server.targets).unlink()
    replay = verify_replay_bundle(server.targets)
    assert not replay.valid
    assert any("missing_receipt" in failure for failure in replay.failures)


def mcp_server_import_has_no_runtime_side_effect() -> None:
    from governed_mcp_v0 import mcp_server

    assert mcp_server.mcp is None


def loop_safe_read_file(tmp_path: Path) -> None:
    server = _server(tmp_path, "loop_safe_read_file")
    state = GovernedGraphState(
        tool_name="read_file",
        action_id="filesystem.read_file",
        tool_args={"path": "readme.txt"},
    )
    updated = execute_governed_tool_call(state, server)
    assert updated.approved is True
    assert updated.messages[-1]["status"] == "allow"
    assert updated.messages[-1]["result"] == "sandbox fixture\n"


def loop_allow_sandbox_file_write(tmp_path: Path) -> None:
    server = _server(tmp_path, "loop_allow_sandbox_file_write")
    state = GovernedGraphState(
        tool_name="write_file",
        action_id="filesystem.write_file",
        tool_args={"path": "nested/allowed.txt", "content": "ok"},
    )
    updated = execute_governed_tool_call(state, server)
    assert updated.approved is True
    assert updated.messages[-1]["status"] == "allow"
    assert (server.targets.fs_dir / "nested" / "allowed.txt").read_text(encoding="utf-8") == "ok"
    replay = verify_replay_bundle(server.targets)
    assert replay.valid, replay.failures


def loop_deny_path_escape_write(tmp_path: Path) -> None:
    server = _server(tmp_path, "loop_deny_path_escape_write")
    prod_path = tmp_path / "prod" / "secret.txt"
    state = GovernedGraphState(
        tool_name="write_file",
        action_id="filesystem.write_file",
        tool_args={"path": str(prod_path), "content": "secret"},
    )
    updated = execute_governed_tool_call(state, server)
    assert updated.approved is False
    assert updated.messages[-1]["status"] == "deny"
    assert "fixtures/fs" in updated.messages[-1]["reason"]
    assert not prod_path.exists()
    replay = verify_replay_bundle(server.targets)
    assert replay.valid, replay.failures


def loop_unknown_tool_fails_closed(tmp_path: Path) -> None:
    server = _server(tmp_path, "loop_unknown_tool_fails_closed")
    state = GovernedGraphState(
        tool_name="erase_world",
        action_id="unknown.action",
        tool_args={"target": "fixture"},
    )
    updated = execute_governed_tool_call(state, server)
    assert updated.approved is False
    assert updated.messages[-1]["status"] == "deny"
    assert "unknown tool" in updated.messages[-1]["reason"]
    replay = verify_replay_bundle(server.targets)
    assert replay.valid, replay.failures


def loop_missing_constitution_fails_closed(tmp_path: Path) -> None:
    targets = create_fixture_environment(tmp_path / "loop_missing_constitution_fails_closed")
    targets.constitution_path.unlink()
    server = GovernedMCPServer(targets)
    state = GovernedGraphState(
        tool_name="write_file",
        action_id="filesystem.write_file",
        tool_args={"path": "blocked.txt", "content": "no side effect"},
    )
    updated = execute_governed_tool_call(state, server)
    assert updated.approved is False
    assert updated.messages[-1]["status"] == "deny"
    assert "fail closed" in updated.messages[-1]["reason"]
    assert not (targets.fs_dir / "blocked.txt").exists()
    # The receipt was stamped constitution_hash="missing" because the
    # constitution is gone; the replay verifier must reject such a bundle
    # (it cannot be cross-checked against any allowed constitution hash).
    replay = verify_replay_bundle(targets)
    assert not replay.valid
    assert any("constitution_hash_missing" in failure for failure in replay.failures)
    assert any("constitution_unreadable_for_hash_crosscheck" in failure for failure in replay.failures)


def loop_shell_allowlist_is_deterministic(tmp_path: Path) -> None:
    server = _server(tmp_path, "loop_shell_allowlist_is_deterministic")
    pwd_state = GovernedGraphState(
        tool_name="run_shell",
        action_id="shell.execute_command",
        tool_args={"command": "pwd"},
    )
    pwd_result = execute_governed_tool_call(pwd_state, server)
    assert pwd_result.approved is True
    assert pwd_result.messages[-1]["result"] == str(server.targets.fs_dir)

    echo_state = GovernedGraphState(
        tool_name="run_shell",
        action_id="shell.execute_command",
        tool_args={"command": "echo sandbox"},
    )
    echo_result = execute_governed_tool_call(echo_state, server)
    assert echo_result.approved is True
    assert echo_result.messages[-1]["result"] == "sandbox"
    assert echo_result.messages[-1]["approval_request"]["approval_required"] is True

    denied_state = GovernedGraphState(
        tool_name="run_shell",
        action_id="shell.execute_command",
        tool_args={"command": "env"},
    )
    denied_result = execute_governed_tool_call(denied_state, server)
    assert denied_result.approved is False
    assert denied_result.messages[-1]["status"] == "deny"
    assert "allowlist" in denied_result.messages[-1]["reason"]
    replay = verify_replay_bundle(server.targets)
    assert replay.valid, replay.failures


def loop_action_tool_mismatch_fails_closed(tmp_path: Path) -> None:
    server = _server(tmp_path, "loop_action_tool_mismatch_fails_closed")
    state = GovernedGraphState(
        tool_name="write_file",
        action_id="database.execute_sql_mutation",
        tool_args={"path": "mismatch.txt", "content": "must not write"},
    )
    updated = execute_governed_tool_call(state, server)
    assert updated.approved is False
    assert updated.messages[-1]["status"] == "deny"
    assert "cannot perform action" in updated.messages[-1]["reason"]
    assert not (server.targets.fs_dir / "mismatch.txt").exists()
    replay = verify_replay_bundle(server.targets)
    assert replay.valid, replay.failures


def replay_detects_filesystem_effect_tampering(tmp_path: Path) -> None:
    server = _server(tmp_path, "replay_detects_filesystem_effect_tampering")
    written = server.write_file("allowed.txt", "original")
    assert verify_replay_bundle(server.targets).valid
    written.write_text("tampered", encoding="utf-8")
    replay = verify_replay_bundle(server.targets)
    assert not replay.valid
    assert any("filesystem_effect_hash_mismatch" in failure for failure in replay.failures)


def replay_detects_email_effect_tampering(tmp_path: Path) -> None:
    server = _server(tmp_path, "replay_detects_email_effect_tampering")
    server.send_email("person@example.test", "subject", "body")
    assert verify_replay_bundle(server.targets).valid
    server.targets.outbox_path.write_text("", encoding="utf-8")
    replay = verify_replay_bundle(server.targets)
    assert not replay.valid
    assert any("email_effect_missing_or_mismatched" in failure for failure in replay.failures)


__all__ = [
    "deny_prod_file_write",
    "allow_sandbox_file_write",
    "deny_sql_delete",
    "deny_external_email",
    "deny_prod_deploy",
    "deny_github_mutation",
    "fail_closed_policy_error",
    "tamper_receipt_fails_replay",
    "tamper_audit_hash_fails_replay",
    "missing_receipt_fails_bundle",
    "mcp_server_import_has_no_runtime_side_effect",
    "loop_safe_read_file",
    "loop_allow_sandbox_file_write",
    "loop_deny_path_escape_write",
    "loop_unknown_tool_fails_closed",
    "loop_missing_constitution_fails_closed",
    "loop_shell_allowlist_is_deterministic",
    "loop_action_tool_mismatch_fails_closed",
    "replay_detects_filesystem_effect_tampering",
    "replay_detects_email_effect_tampering",
]
