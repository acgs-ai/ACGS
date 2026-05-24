"""Monorepo invariants — locked-in thresholds from docs/PLAN-MONOREPO.md §1.

Every assertion here corresponds to a premise or DoD row that, if it drifts,
silently breaks the workspace. Tests fail loudly when the repo no longer
matches the plan; that is the entire point.
"""
from __future__ import annotations

import json
import subprocess
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def _load_toml(rel: str) -> dict:
    with (ROOT / rel).open("rb") as f:
        return tomllib.load(f)


def _load_json(rel: str) -> dict:
    return json.loads((ROOT / rel).read_text())


def _load_yaml(rel: str) -> dict:
    return yaml.safe_load((ROOT / rel).read_text())


def _is_gitlink(rel: str) -> bool:
    result = subprocess.run(
        ["git", "ls-tree", "HEAD", rel],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.startswith("160000 commit ")


# ---------------------------------------------------------------------------
# §1 Premise 4 — workspace floor is 3.11; per-package floors intentional
# ---------------------------------------------------------------------------

def test_root_python_floor_is_3_11():
    """Workspace floor must be the highest member floor per PRD."""
    root = _load_toml("pyproject.toml")
    assert root["project"]["requires-python"] == ">=3.11"


def test_acgs_lite_published_floor_unchanged():
    """`acgs-lite` ships to PyPI with >=3.10 — must NOT bump locally."""
    pkg = _load_toml("packages/acgs-lite/pyproject.toml")
    assert pkg["project"]["requires-python"] == ">=3.10", (
        "acgs-lite is published to PyPI with requires-python>=3.10. "
        "Workspace floor of 3.11 is local-only by design."
    )


def test_acgs_swarm_floor_drives_workspace_floor():
    """Workspace floor is 3.11 because Acgs-Swarm requires it."""
    pkg = _load_toml("packages/Acgs-Swarm/pyproject.toml")
    assert pkg["project"]["requires-python"] == ">=3.11"


# ---------------------------------------------------------------------------
# §4 Target architecture — workspace member list
# ---------------------------------------------------------------------------

EXPECTED_UV_MEMBERS = {
    "packages/acgs-lite",
    "packages/Acgs-Swarm",
    "packages/gove-zone",
    "packages/agent-bus-analyzer",
    "acgs_governance_eval_mvp",
    "acgs-cft-governance-pack",
}


def test_uv_workspace_members_match_plan():
    root = _load_toml("pyproject.toml")
    declared = set(root["tool"]["uv"]["workspace"]["members"])
    assert declared == EXPECTED_UV_MEMBERS, (
        f"uv workspace members drifted. Expected {EXPECTED_UV_MEMBERS}, got {declared}"
    )


def test_every_uv_member_has_pyproject_on_disk():
    """Initialized workspace members need pyproject.toml; gitlinks may be lazy."""
    root = _load_toml("pyproject.toml")
    members = root["tool"]["uv"]["workspace"]["members"]
    missing = [
        m
        for m in members
        if not (ROOT / m / "pyproject.toml").is_file() and not _is_gitlink(m)
    ]
    assert not missing, f"Members missing pyproject.toml: {missing}"


def test_uv_root_is_virtual_workspace():
    """Root must NOT be a buildable package — `[tool.uv] package = false`."""
    root = _load_toml("pyproject.toml")
    assert root["tool"]["uv"]["package"] is False


# ---------------------------------------------------------------------------
# JS workspace — pnpm pin must match the established acgi-ai version
# ---------------------------------------------------------------------------

def test_packagemanager_pin_matches_acgi_ai():
    root = _load_json("package.json")
    app = _load_json("acgi-ai/package.json")
    assert root["packageManager"] == app["packageManager"], (
        "Root and acgi-ai must agree on pnpm version; mismatch breaks workspace install."
    )


def test_pnpm_workspace_lists_acgi_ai():
    ws = _load_yaml("pnpm-workspace.yaml")
    assert "acgi-ai" in ws["packages"]


def test_pnpm_workspace_lists_enterprise_frontend():
    """The enterprise frontend has package metadata and must join JS installs."""
    ws = _load_yaml("pnpm-workspace.yaml")
    member = "acgs-enterprise-ai-manager/frontend"
    assert member in ws["packages"]
    pkg = _load_json(f"{member}/package.json")
    assert pkg["name"] == "acgs-enterprise-manager-frontend"
    assert "build" in pkg["scripts"]


# ---------------------------------------------------------------------------
# Workflow path filters — CI triggers must match real directories
# ---------------------------------------------------------------------------

WORKFLOW_PATH_PREFIXES = {
    "python-eval-mvp.yml": "acgs_governance_eval_mvp",
    "python-cft-pack.yml": "acgs-cft-governance-pack",
    "python-hermes-bundle.yml": "hermes_acgs_bundle",
    "python-agent-bus-analyzer.yml": "packages/agent-bus-analyzer",
}


def test_workflow_path_filters_point_at_real_dirs():
    """Every path-filtered workflow must trigger against a real top-level dir."""
    for workflow, prefix in WORKFLOW_PATH_PREFIXES.items():
        path = ROOT / ".github" / "workflows" / workflow
        assert path.exists(), f"Missing workflow: {workflow}"
        doc = yaml.safe_load(path.read_text())
        triggers = doc[True]  # YAML parses bare 'on:' as True key
        for event in ("pull_request", "push"):
            paths = triggers[event]["paths"]
            assert any(p.startswith(f"{prefix}/") for p in paths), (
                f"{workflow} {event} paths don't reference {prefix}/"
            )
        assert (ROOT / prefix).is_dir(), f"{prefix} dir referenced by CI does not exist"


def test_constitutional_hash_workflow_pulls_submodules():
    """Hash inventory verifies initialized submodules and reports credential gaps."""
    path = ROOT / ".github/workflows/constitutional-hash.yml"
    doc = yaml.safe_load(path.read_text())
    text = path.read_text()
    steps = doc["jobs"]["verify"]["steps"]
    checkout = next(s for s in steps if s.get("uses", "").startswith("actions/checkout"))
    assert checkout["with"]["submodules"] is False
    assert "git submodule update --init --recursive -- packages/acgs-lite" in text
    assert "--ignore-missing-prefix packages/clinicalguard/" in text


def test_existing_console_and_marketing_workflows_untouched():
    """Phase 1 promised: no edits to acgi-ai deploy workflows."""
    for name in ("console.yml", "marketing.yml"):
        path = ROOT / ".github/workflows" / name
        assert path.exists(), f"Existing workflow vanished: {name}"
        # Spot-check the working-directory pin that anchors the deploy contract.
        if name == "console.yml":
            text = path.read_text()
            assert "working-directory: acgi-ai" in text


def test_archon_harness_lessons_keep_acgs_boundary():
    """Archon lessons must preserve ACGS as governance, not orchestration."""
    text = (ROOT / "docs/design/acgs-archon-workflow-harness-lessons.md").read_text()

    required_phrases = [
        "docs/adr/0001-in-context-procedure-execution-external-runtime-governance.md",
        "docs/design/acgs-phoenix-observability.md",
        "tests/test_monorepo_invariants.py",
        "packages/enhanced_agent_bus` is not present",
        "YAML DAG workflow definitions",
        "Worktree isolation",
        "Workflow run persistence",
        "Provider capability flags",
        "fail-closed runtime gates",
        "tamper-evident evidence",
        "not as a product positioning template",
    ]
    missing = [phrase for phrase in required_phrases if phrase not in text]
    assert not missing, f"Archon lessons missing concrete adoption anchors: {missing}"

    forbidden_claims = [
        "ACGS is an Archon replacement",
        "compliance-certified",
        "regulator-ready",
        "full on-chain",
    ]
    assert not any(claim in text for claim in forbidden_claims), (
        "Archon lessons must not drift into certification or replacement claims."
    )


# ---------------------------------------------------------------------------
# Constitutional-hash lock file shape
# ---------------------------------------------------------------------------

def test_constitutional_hash_lock_is_well_formed():
    lock = _load_json("docs/constitutional-hashes.lock")
    assert isinstance(lock, dict)
    assert "hashes" in lock
    assert isinstance(lock["hashes"], dict)
    for path, hash_ in lock["hashes"].items():
        assert isinstance(path, str) and path
        assert isinstance(hash_, str) and len(hash_) == 16, (
            f"Lock entry {path}: hash must be 16 hex chars, got {hash_!r}"
        )
        int(hash_, 16)  # raises if not hex


# ---------------------------------------------------------------------------
# Turbo pipeline shape — required tasks must exist
# ---------------------------------------------------------------------------

REQUIRED_TURBO_TASKS = {"build", "test", "lint", "typecheck", "dev", "clean"}


def test_turbo_declares_all_required_tasks():
    turbo = _load_json("turbo.json")
    assert REQUIRED_TURBO_TASKS.issubset(turbo["tasks"].keys()), (
        f"Missing turbo tasks: {REQUIRED_TURBO_TASKS - turbo['tasks'].keys()}"
    )


def test_turbo_dev_is_non_cached_persistent():
    """Dev server must not be cached — Turbo would deadlock the persistent process."""
    turbo = _load_json("turbo.json")
    dev = turbo["tasks"]["dev"]
    assert dev["cache"] is False
    assert dev["persistent"] is True
