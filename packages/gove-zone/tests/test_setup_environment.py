"""Guards for ``gove_zone.setup`` — environment detection and preflight checks.

This module is what an operator runs to find out whether the governance kernel
can actually work here. Its failure branches are the useful half: a report that
says "ok" because a check silently swallowed its own error is worse than no
report. Each detection rule and each not-ok branch is pinned below.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gove_zone import setup as setup_mod


# --------------------------------------------------------------------------- #
# Project directory resolution
# --------------------------------------------------------------------------- #
def test_project_dir_prefers_the_injected_environment(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))

    assert setup_mod._project_dir() == tmp_path


def test_project_dir_falls_back_to_the_working_directory(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    monkeypatch.chdir(tmp_path)

    assert setup_mod._project_dir() == Path.cwd()


def test_an_empty_environment_value_falls_back_rather_than_resolving_to_dot(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", "")
    monkeypatch.chdir(tmp_path)

    assert setup_mod._project_dir() == Path.cwd()


# --------------------------------------------------------------------------- #
# Runtime host detection
# --------------------------------------------------------------------------- #
def test_no_markers_detects_no_hosts(tmp_path: Path):
    assert setup_mod._detect_runtime_hosts(tmp_path) == []


def test_a_claude_directory_detects_claude_code(tmp_path: Path):
    (tmp_path / ".claude").mkdir()

    assert setup_mod._detect_runtime_hosts(tmp_path) == ["claude-code"]


@pytest.mark.parametrize("marker", [".codex", "AGENTS.md"])
def test_either_codex_marker_detects_codex(tmp_path: Path, marker: str):
    target = tmp_path / marker
    if marker.startswith("."):
        target.mkdir()
    else:
        target.write_text("agents", encoding="utf-8")

    assert setup_mod._detect_runtime_hosts(tmp_path) == ["codex"]


def test_a_cursor_directory_detects_cursor(tmp_path: Path):
    (tmp_path / ".cursor").mkdir()

    assert setup_mod._detect_runtime_hosts(tmp_path) == ["cursor"]


def test_hosts_are_reported_in_a_stable_order(tmp_path: Path):
    """A report an operator diffs across runs must not reorder itself."""
    for name in (".cursor", ".codex", ".claude"):
        (tmp_path / name).mkdir()

    assert setup_mod._detect_runtime_hosts(tmp_path) == ["claude-code", "codex", "cursor"]


def test_codex_is_not_double_counted_when_both_markers_exist(tmp_path: Path):
    (tmp_path / ".codex").mkdir()
    (tmp_path / "AGENTS.md").write_text("agents", encoding="utf-8")

    assert setup_mod._detect_runtime_hosts(tmp_path) == ["codex"]


# --------------------------------------------------------------------------- #
# Environment report
# --------------------------------------------------------------------------- #
def test_detect_environment_reports_the_installed_kernel(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))

    report = setup_mod.detect_environment()

    assert report.gove_zone_installed is True
    assert report.gove_zone_version
    assert report.project_dir == str(tmp_path)
    assert report.gate_mode in {"enforce", "observe", "off"}


def test_a_nonexistent_project_dir_is_reported_as_none_not_as_a_path(monkeypatch):
    """Reporting a path that does not exist would read as "found it"."""
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", "/definitely/not/here")

    assert setup_mod.detect_environment().project_dir is None


def test_the_report_round_trips_to_a_dict(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))

    payload = setup_mod.detect_environment().to_dict()

    assert payload["cwd"]
    assert "audit_path" in payload
    assert isinstance(payload["runtime_hosts"], list)


def test_an_unimportable_version_is_reported_as_absent(monkeypatch):
    """The probe must degrade to "unknown", never propagate the import error
    into the operator's report."""
    import builtins

    real_import = builtins.__import__

    def _fail(name: str, *args: object, **kwargs: object):
        if name == "gove_zone":
            raise RuntimeError("import machinery is broken")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fail)

    assert setup_mod._gove_zone_version() is None


# --------------------------------------------------------------------------- #
# Writability probe
# --------------------------------------------------------------------------- #
def test_a_writable_audit_path_passes_and_leaves_no_probe_behind(tmp_path: Path):
    check = setup_mod._check_writable(tmp_path / "audit" / "audit.jsonl")

    assert check == {
        "name": "audit_path_writable",
        "ok": True,
        "path": str(tmp_path / "audit" / "audit.jsonl"),
    }
    assert not (tmp_path / "audit" / ".gove-zone-write-probe").exists()


def test_an_unwritable_audit_path_reports_not_ok_with_the_error(tmp_path: Path):
    readonly = tmp_path / "readonly"
    readonly.mkdir()
    readonly.chmod(0o500)
    try:
        check = setup_mod._check_writable(readonly / "audit.jsonl")
    finally:
        readonly.chmod(0o700)

    assert check["ok"] is False
    assert check["name"] == "audit_path_writable"
    assert "error" in check


# --------------------------------------------------------------------------- #
# Dependency validation
# --------------------------------------------------------------------------- #
def test_validate_dependencies_passes_in_a_working_install():
    report = setup_mod.validate_dependencies()

    assert report.ok is True
    assert {c["name"] for c in report.checks} >= {
        "gove_zone_importable",
        "integration_adapter_present",
    }
    assert all(c["ok"] for c in report.checks)


def test_a_missing_integration_adapter_makes_the_report_not_ok(monkeypatch):
    """The adapter is the passive receipt path; without it the kernel is
    installed but cannot emit, and the report must say so."""
    import builtins

    real_import = builtins.__import__

    def _fail(name: str, *args: object, **kwargs: object):
        if name == "gove_zone.integration":
            raise ImportError("no adapter")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fail)

    report = setup_mod.validate_dependencies()

    assert report.ok is False
    failed = next(c for c in report.checks if c["name"] == "integration_adapter_present")
    assert failed["ok"] is False
    assert "fix" in failed or "error" in failed


def test_the_validation_report_round_trips_to_a_dict():
    payload = setup_mod.validate_dependencies().to_dict()

    assert set(payload) == {"ok", "checks"}
    assert isinstance(payload["checks"], list)
