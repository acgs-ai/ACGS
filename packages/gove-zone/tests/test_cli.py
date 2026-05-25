"""CLI replay contract tests."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from gove_zone import ChainHashAuditStore, Decision, DecisionRecord, sha256_json
from gove_zone.cli import main


def _record(event_id: str) -> DecisionRecord:
    return DecisionRecord(
        decision=Decision.ALLOW,
        tool="write_file",
        argument_hash=sha256_json({"id": event_id}),
        policy_version="v0",
        event_id=event_id,
    )


def test_pyproject_installs_gove_zone_cli() -> None:
    pyproject = Path(__file__).parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))

    assert data["project"]["scripts"]["gove-zone"] == "gove_zone.cli:main"


def test_cli_replay_accepts_frontend_command_shape(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["replay", "--event", "ev_1", "--audit-hash", "abc"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["event_id"] == "ev_1"
    assert payload["expected_audit_hash"] == "abc"
    assert payload["status"] == "hash-only"


def test_cli_replay_verifies_audit_event_when_path_supplied(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "audit.jsonl"
    event = ChainHashAuditStore(path).append(_record("ev_1"))

    exit_code = main(
        [
            "replay",
            "--event",
            "ev_1",
            "--audit",
            str(path),
            "--audit-hash",
            event["event_hash"],
        ]
    )

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "verified"
    assert payload["verified"] is True
    assert payload["chain_valid"] is True
    assert payload["actual_audit_hash"] == event["event_hash"]
