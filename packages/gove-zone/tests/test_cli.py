"""CLI replay contract tests."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

from gove_zone import ChainHashAuditStore, Decision, DecisionRecord, sha256_json
from gove_zone.cli import build_parser, main


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


def test_cli_exposes_advertised_commands() -> None:
    parser = build_parser()
    subparsers_action = next(
        action for action in parser._actions if getattr(action, "dest", None) == "command"
    )

    assert set(subparsers_action.choices) >= {
        "doctor",
        "smoke",
        "gate",
        "proofpack",
        "replay",
    }


def test_cli_replay_accepts_frontend_command_shape(capsys) -> None:
    exit_code = main(["replay", "--event", "ev_1", "--audit-hash", "abc"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["event_id"] == "ev_1"
    assert payload["expected_audit_hash"] == "abc"
    assert payload["status"] == "hash-only"


def test_cli_replay_verifies_audit_event_when_path_supplied(
    tmp_path: Path,
    capsys,
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


def test_cli_doctor_reports_alpha_contract(capsys) -> None:
    exit_code = main(["doctor"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"
    assert payload["package"] == "gove-zone"
    assert payload["alpha"] is True
    assert payload["production_certified"] is False
    assert "gate" in payload["commands"]


def test_cli_smoke_proves_allowed_denied_missing_receipt_and_audit(capsys) -> None:
    exit_code = main(["smoke", "--format", "json"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["allowed"]["executed"] is True
    assert payload["denied"]["executed"] is False
    assert payload["missing_receipt"]["blocked"] is True
    assert payload["audit"]["valid"] is True
    assert payload["alpha_limitations"]


def test_cli_gate_emits_receipt_and_blocks_denied_payload(tmp_path: Path, capsys) -> None:
    event = {
        "tool": "message.send",
        "args": {"body": "secret token"},
        "tenant_id": "tenant-alpha",
        "policy_bundle_id": "local-boundary",
        "request_id": "req-gate-deny",
        "declared_goal": "send a governed message",
    }

    exit_code = main(
        [
            "gate",
            "--audit",
            str(tmp_path / "audit.jsonl"),
            "--input-json",
            json.dumps(event),
        ]
    )

    assert exit_code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision"] == "DENY"
    assert payload["receipt"]["tenant_id"] == "tenant-alpha"
    assert payload["receipt"]["audit_event_hash"]
    assert payload["audit"]["valid"] is True


def test_cli_proofpack_writes_conformance_bundle(tmp_path: Path, capsys) -> None:
    output = tmp_path / "proofpack"

    exit_code = main(["proofpack", "--output", str(output)])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "written"
    assert (output / "manifest.json").is_file()
    assert (output / "audit.jsonl").is_file()
    assert (output / "verification.json").is_file()
    assert (output / "conformance-results.json").is_file()
    assert (output / "limitations.md").is_file()
    receipts = list((output / "receipts").glob("*.json"))
    assert receipts

    conformance = json.loads((output / "conformance-results.json").read_text(encoding="utf-8"))
    assert conformance["allowed_valid_receipt"]["passed"] is True
    assert conformance["denied_receipt_blocked"]["passed"] is True
    assert conformance["missing_receipt_blocked"]["passed"] is True
    assert conformance["tampered_receipt_blocked"]["passed"] is True


def test_cli_proofpack_refuses_existing_output_without_force(tmp_path: Path, capsys) -> None:
    output = tmp_path / "proofpack"

    assert main(["proofpack", "--output", str(output)]) == 0
    capsys.readouterr()
    first_events = (output / "audit.jsonl").read_text(encoding="utf-8").splitlines()

    exit_code = main(["proofpack", "--output", str(output)])

    assert exit_code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "blocked"
    assert "already exists" in payload["reason"]
    assert (output / "audit.jsonl").read_text(encoding="utf-8").splitlines() == first_events
