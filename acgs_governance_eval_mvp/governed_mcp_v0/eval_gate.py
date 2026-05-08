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
    def evaluate_policy(self, action_id: str, args: dict[str, object], targets: RuntimeTargets) -> tuple[str, str, list[str]]:
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
]
