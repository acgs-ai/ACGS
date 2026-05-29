"""CLI replay contract tests."""

from __future__ import annotations

import argparse
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


def test_cli_defines_expected_commands() -> None:
    from gove_zone.cli import build_parser

    parser = build_parser()
    # Find the subparsers action
    subparsers_action = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    commands = list(subparsers_action.choices.keys())
    expected = [
        "doctor",
        "smoke",
        "gate",
        "replay",
        "setup",
        "enable",
        "policy",
        "eval",
        "proofpack",
    ]
    for cmd in expected:
        assert cmd in commands


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


def test_cli_proofpack_generates_files(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Run in tmp_path directory to avoid dirtying local directory
    monkeypatch.chdir(tmp_path)
    exit_code = main(["proofpack"])

    assert exit_code == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["status"] == "pass"

    dist_dir = tmp_path / "dist-govern-zone-proofpack"
    assert dist_dir.is_dir()
    assert (dist_dir / "manifest.json").is_file()
    assert (dist_dir / "audit.jsonl").is_file()
    assert (dist_dir / "verification.json").is_file()
    assert (dist_dir / "conformance-results.json").is_file()
    assert (dist_dir / "limitations.md").is_file()

    receipts_dir = dist_dir / "receipts"
    assert receipts_dir.is_dir()
    assert (receipts_dir / "allowed_receipt.json").is_file()
    assert (receipts_dir / "denied_receipt.json").is_file()
    assert (receipts_dir / "transformed_receipt.json").is_file()

    results = payload["results"]
    assert results["allowed_action_executed"] is True
    assert results["denied_action_blocked"] is True
    assert results["transformed_action_executed"] is True
    assert results["missing_receipt_blocked"] is True
    assert results["tampered_receipt_blocked"] is True
    assert results["audit_chain_verified"] is True


def test_cli_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    """--version is part of complete CLI surface (PR 1 acceptance)."""
    from gove_zone import __version__

    # action=version causes SystemExit(0) after printing to stdout
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0

    out = capsys.readouterr().out
    assert f"gove-zone {__version__}" in out
