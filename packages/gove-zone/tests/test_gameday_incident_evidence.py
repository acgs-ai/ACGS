"""Test the game-day incident-evidence drill end-to-end.

Runs the shipped ``examples/gameday_incident_evidence.py`` drill as a subprocess
into a ``tmp_path`` output directory (the same way an operator would, per
``test_examples_run.py``), then asserts the persisted bundle is a durable,
sha256-manifested governed incident-evidence bundle:

* the manifest exists and binds every member;
* every member's recomputed sha256 matches the manifest (tamper-evident);
* the DENY receipt is present AND non-executable (decision == "deny");
* the tamper-evident audit chain verifies;
* the human-readable verification-summary.md exists.

This is the wiring proof that the drill actually persists evidence, not just
that it prints a status line.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

_DRILL = Path(__file__).resolve().parent.parent / "examples" / "gameday_incident_evidence.py"


def _run_drill(out_dir: Path) -> dict:
    assert _DRILL.is_file(), f"drill missing: {_DRILL}"
    result = subprocess.run(
        [sys.executable, str(_DRILL), str(out_dir)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, (
        f"drill exited {result.returncode}\n"
        f"--- stdout ---\n{result.stdout[-2000:]}\n"
        f"--- stderr ---\n{result.stderr[-2000:]}"
    )
    # Last stdout line is the single-line JSON status summary.
    last_line = result.stdout.strip().splitlines()[-1]
    return json.loads(last_line)


def test_drill_persists_manifest_hashed_bundle(tmp_path: Path) -> None:
    out_dir = tmp_path / "bundle"
    summary = _run_drill(out_dir)

    assert summary["status"] == "pass"
    assert summary["bundle_dir"] == str(out_dir)

    # --- manifest exists and binds members ---------------------------------
    manifest_path = out_dir / "manifest.json"
    assert manifest_path.is_file(), "bundle manifest.json missing"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    members = manifest["members"]
    assert set(members) == {
        "incident-summary.json",
        "decision-receipts.json",
        "audit-chain.json",
        "verification-summary.md",
    }

    # --- every member's recomputed sha256 matches the manifest -------------
    for name, meta in members.items():
        member = out_dir / name
        assert member.is_file(), f"member missing: {name}"
        recomputed = hashlib.sha256(member.read_bytes()).hexdigest()
        assert recomputed == meta["sha256"], f"sha256 mismatch for {name}"
        assert meta["bytes"] == member.stat().st_size

    # The manifest is NOT a self-referential member.
    assert "manifest.json" not in members

    # --- the DENY receipt is present AND non-executable --------------------
    receipts = json.loads((out_dir / "decision-receipts.json").read_text(encoding="utf-8"))
    deny = receipts["deny_receipt"]
    assert deny["decision"] == "deny"
    # The escalate receipt is captured and stays non-authorizing.
    assert receipts["escalate_receipt"]["decision"] == "escalate"
    # Only the human-approved receipt is an ALLOW, minted by a distinct validator.
    approval = receipts["approval_receipt"]
    assert approval["decision"] == "allow"
    assert approval["validator_id"] != approval["actor"]
    assert summary["deny_blocked"] is True
    assert summary["escalate_auto_execute_blocked"] is True
    assert summary["resume_executed_after_approval"] is True

    # --- the audit chain verifies ------------------------------------------
    audit_chain = json.loads((out_dir / "audit-chain.json").read_text(encoding="utf-8"))
    assert audit_chain["verification"]["valid"] is True
    assert audit_chain["verification"]["checked"] == summary["chain_events"]
    assert summary["chain_valid"] is True

    # --- the human-readable summary exists ---------------------------------
    summary_md = (out_dir / "verification-summary.md").read_text(encoding="utf-8")
    assert "Verification Summary" in summary_md
    assert "PASS" in summary_md
