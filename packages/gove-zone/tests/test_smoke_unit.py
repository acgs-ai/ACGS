"""Direct unit tests for :mod:`gove_zone.smoke`.

:func:`run_smoke` is the one-command local proof, so the tests assert on the
report *contract* the release evidence depends on: the three check ids, the
allow/deny sections, the audit verdict, and the retention semantics of the
optional ``audit_path``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gove_zone.smoke import CLAIM_BOUNDARY, run_smoke

EXPECTED_CHECK_IDS = [
    "allow-before-side-effect",
    "deny-before-side-effect",
    "audit-chain-verifies",
]


@pytest.fixture
def report() -> dict:
    """One ephemeral smoke run (no retained audit)."""
    return run_smoke()


# --- report contract ---------------------------------------------------------- #


def test_run_smoke_reports_pass_with_the_claim_boundary(report: dict) -> None:
    assert report["artifactKind"] == "gove-zone-smoke-report"
    assert report["status"] == "pass"
    assert report["claimBoundary"] == CLAIM_BOUNDARY


def test_run_smoke_emits_exactly_the_three_checks_all_passing(report: dict) -> None:
    assert [check["id"] for check in report["checks"]] == EXPECTED_CHECK_IDS
    assert {check["status"] for check in report["checks"]} == {"pass"}
    assert all(check["evidence"] for check in report["checks"])


def test_allow_section_records_the_executed_side_effect(report: dict) -> None:
    allow = report["allow"]
    assert allow["decision"] == "allow"
    assert allow["tool"] == "write_file"
    assert allow["goal"] == "prove allowed side effect"
    assert allow["bytesWritten"] == len("governed hello\n")
    assert allow["auditHash"]


def test_deny_section_records_the_blocked_call(report: dict) -> None:
    deny = report["deny"]
    assert deny["decision"] == "deny"
    assert deny["tool"] == "write_file"
    assert deny["goal"] == "prove denied side effect"
    assert deny["matchedRules"] == ["SMOKE_SECRET_BOUNDARY:keyword:id_rsa"]
    assert deny["auditHash"]


def test_allow_and_deny_are_distinct_links_in_one_chain(report: dict) -> None:
    assert report["allow"]["auditHash"] != report["deny"]["auditHash"]


def test_audit_verdict_covers_both_decisions(report: dict) -> None:
    assert report["audit"] == {**report["audit"], "valid": True, "checked": 2}


# --- audit retention ----------------------------------------------------------- #


def test_default_run_does_not_retain_the_audit_file(report: dict) -> None:
    assert report["auditRetained"] is False
    # The temporary directory is removed once the report is built.
    assert not Path(report["auditPath"]).exists()


def test_explicit_audit_path_is_retained_with_two_chained_events(tmp_path: Path) -> None:
    audit_path = tmp_path / "smoke-audit.jsonl"
    result = run_smoke(audit_path)

    assert result["auditRetained"] is True
    assert result["auditPath"] == str(audit_path)
    events = [json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()]
    assert len(events) == 2
    assert events[1]["previous_hash"] == events[0]["event_hash"]


def test_explicit_audit_path_accepts_a_plain_string(tmp_path: Path) -> None:
    audit_path = tmp_path / "smoke-audit-str.jsonl"
    result = run_smoke(str(audit_path))

    assert result["status"] == "pass"
    assert result["auditRetained"] is True
    assert audit_path.exists()


def test_scratch_side_effects_do_not_leak_into_the_audit_directory(tmp_path: Path) -> None:
    """With an explicit audit path, the allow/deny writes go to a separate
    scratch dir — the evidence directory holds only audit artifacts, never the
    smoke run's own ``allowed.txt``."""
    audit_dir = tmp_path / "evidence"
    audit_dir.mkdir()
    run_smoke(audit_dir / "audit.jsonl")

    assert "allowed.txt" not in {p.name for p in audit_dir.iterdir()}
    assert (audit_dir / "audit.jsonl").exists()


def test_reusing_a_populated_audit_path_fails_closed(tmp_path: Path) -> None:
    """The chain verdict is asserted to hold exactly two decisions, so appending
    a second run onto the same file is a loud failure rather than a silent
    four-event report."""
    audit_path = tmp_path / "reused.jsonl"
    run_smoke(audit_path)

    with pytest.raises(RuntimeError, match="smoke audit chain failed"):
        run_smoke(audit_path)


def test_runs_are_independent_across_distinct_audit_paths(tmp_path: Path) -> None:
    first = run_smoke(tmp_path / "a.jsonl")
    second = run_smoke(tmp_path / "b.jsonl")

    assert first["status"] == second["status"] == "pass"
    assert first["allow"]["auditHash"] != second["allow"]["auditHash"]


def test_missing_audit_parent_directory_is_created(tmp_path: Path) -> None:
    """The audit store creates the evidence directory for the caller."""
    audit_path = tmp_path / "not" / "yet" / "audit.jsonl"

    result = run_smoke(audit_path)

    assert result["status"] == "pass"
    assert audit_path.exists()
