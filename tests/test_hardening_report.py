"""Tests for scripts/hardening_report.py."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import hardening_report as hr

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "hardening_report.py"


# ---------------------------------------------------------------------------
# ChecklistItem / DrillRecord shape
# ---------------------------------------------------------------------------


def test_checklist_item_icon_for_each_status():
    assert hr.ChecklistItem(1, "x", "pass", "y").icon == "✅"
    assert hr.ChecklistItem(1, "x", "fail", "y").icon == "❌"
    assert hr.ChecklistItem(1, "x", "pending", "y").icon == "⏳"


def test_drill_record_serializes_round_trip():
    rec = hr.DrillRecord(
        drill_type="t",
        drill_id="abc",
        status="passed",
        started="2026-05-11T00:00:00+00:00",
        finished="2026-05-11T00:00:01+00:00",
        events=[{"step": "x", "ok": True}],
    )
    blob = json.loads(json.dumps(rec.to_dict()))
    assert blob["drill_type"] == "t"
    assert blob["events"][0]["ok"] is True


# ---------------------------------------------------------------------------
# Drills against the real repo state
# ---------------------------------------------------------------------------


def test_drill_workflow_schema_passes_against_real_repo():
    rec = hr.drill_workflow_schema(ROOT)
    assert rec.status == "passed", f"events: {rec.events}"
    # At minimum: console, marketing, our 4 new workflows.
    assert len(rec.events) >= 6


def test_drill_lock_integrity_passes_against_real_repo():
    rec = hr.drill_lock_integrity(ROOT)
    assert rec.status == "passed", f"events: {rec.events}"


def test_drill_drift_detection_actually_detects_drift():
    rec = hr.drill_drift_detection(ROOT)
    assert rec.status == "passed", f"events: {rec.events}"
    # The drill should record both baseline_pin and a post-drift verify step.
    steps = [e.get("step") for e in rec.events]
    assert "baseline_pin" in steps
    assert "inject_marker" in steps
    assert "verify_after_drift" in steps


# ---------------------------------------------------------------------------
# Checklist composition
# ---------------------------------------------------------------------------


def test_build_checklist_returns_10_items():
    drills = hr.run_drills(ROOT)
    items = hr.build_checklist(ROOT, drills)
    assert len(items) == 10
    # Numbers are unique 1..10.
    assert sorted(i.number for i in items) == list(range(1, 11))


def test_phase_2_item_reflects_gitmodules_presence(tmp_path: Path):
    """Item 10 is dynamic: pending without .gitmodules, pass with it."""
    # Minimal repo skeleton — only the file under test matters.
    fake_root = tmp_path / "repo"
    fake_root.mkdir()

    # Without .gitmodules → pending.
    items = hr.build_checklist(fake_root, [])
    phase_2 = next(i for i in items if i.number == 10)
    assert phase_2.status == "pending"
    assert "deferred" in phase_2.description.lower()

    # With .gitmodules → pass; evidence cites submodule count.
    (fake_root / ".gitmodules").write_text(
        '[submodule "packages/x"]\n\tpath = packages/x\n\turl = https://example.com/x.git\n'
    )
    items = hr.build_checklist(fake_root, [])
    phase_2 = next(i for i in items if i.number == 10)
    assert phase_2.status == "pass"
    assert "landed" in phase_2.description.lower()
    assert "1 submodule" in phase_2.evidence


def test_phase_1_root_files_pass():
    drills = hr.run_drills(ROOT)
    items = hr.build_checklist(ROOT, drills)
    phase_1 = next(i for i in items if i.number == 1)
    assert phase_1.status == "pass"


def test_workspace_member_item_tracks_current_registry():
    drills = hr.run_drills(ROOT)
    items = hr.build_checklist(ROOT, drills)
    workspace = next(i for i in items if i.number == 3)
    assert workspace.status == "pass"
    assert "8 packages" in workspace.description
    assert "packages/gove-zone" in workspace.evidence
    assert "packages/agent-bus-analyzer" in workspace.evidence
    assert "packages/research-engine" in workspace.evidence
    assert "packages/clinicalguard" in workspace.evidence


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def test_render_report_includes_each_item_with_status():
    drills = hr.run_drills(ROOT)
    items = hr.build_checklist(ROOT, drills)
    text = hr.render_report(items, drills)
    assert "# Monorepo Hardening Report" in text
    for item in items:
        assert item.description in text
    assert "Drill Records" in text


def test_render_report_summarizes_pass_fail_pending_counts():
    items = [
        hr.ChecklistItem(1, "ok", "pass", "x"),
        hr.ChecklistItem(2, "bad", "fail", "x"),
        hr.ChecklistItem(3, "wait", "pending", "x"),
    ]
    text = hr.render_report(items, [])
    assert "1/3 pass" in text
    assert "1 fail" in text
    assert "1 pending" in text


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_persist_drills_writes_one_file_per_drill(tmp_path):
    drills = [
        hr.DrillRecord("t1", "aaa", "passed", "s", "f"),
        hr.DrillRecord("t2", "bbb", "failed", "s", "f"),
    ]
    paths = hr.persist_drills(drills, tmp_path)
    assert len(paths) == 2
    for p in paths:
        assert p.is_file()
        data = json.loads(p.read_text())
        assert "drill_type" in data


def test_persist_report_uses_timestamped_filename(tmp_path):
    path = hr.persist_report("hello", tmp_path)
    assert path.is_file()
    assert path.suffix == ".md"
    assert "hardening-" in path.name
    assert path.read_text() == "hello"


# ---------------------------------------------------------------------------
# CLI exit code
# ---------------------------------------------------------------------------


def test_cli_print_emits_report_and_exits_zero():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--print"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert "Monorepo Hardening Report" in result.stdout
    assert "## Drill Records" in result.stdout
