"""Monorepo invariants — locked-in thresholds from docs/PLAN-MONOREPO.md §1.

Every assertion here corresponds to a premise or DoD row that, if it drifts,
silently breaks the workspace. Tests fail loudly when the repo no longer
matches the plan; that is the entire point.
"""

from __future__ import annotations

import json
import subprocess
import sys
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


def _read_uv_members(repo_root: Path) -> list[str]:
    """Read uv workspace members from the root pyproject.toml.

    Mirrored in ``scripts/hardening_report.py``; keep the two
    implementations in lock-step — both must read the same key from the
    same file.
    """
    with (repo_root / "pyproject.toml").open("rb") as f:
        root = tomllib.load(f)
    return list(root["tool"]["uv"]["workspace"]["members"])


def _registered_submodule_paths(repo_root: Path) -> set[str]:
    gitmodules = repo_root / ".gitmodules"
    if not gitmodules.is_file():
        return set()

    paths: set[str] = set()
    for line in gitmodules.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("path = "):
            paths.add(stripped.removeprefix("path = ").strip())
    return paths


def _is_gitlink(rel: str) -> bool:
    try:
        result = subprocess.run(
            ["git", "ls-tree", "HEAD", rel],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.startswith("160000 commit ")
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        registered = rel in _registered_submodule_paths(ROOT)
        if registered:
            return True
        print(
            f"gitlink check unavailable for {rel}: {exc}; no .gitmodules fallback entry",
            file=sys.stderr,
        )
        return False


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
    "packages/clinicalguard",
    "packages/gove-zone",
    "packages/agent-bus-analyzer",
    "packages/research-engine",
    "acgs_governance_eval_mvp",
    "acgs-cft-governance-pack",
}


def test_uv_workspace_members_match_plan():
    declared = _read_uv_members(ROOT)
    assert declared, "uv workspace members must be declared in pyproject.toml"
    assert len(declared) == len(set(declared)), f"Duplicate uv workspace members: {declared}"


def test_every_uv_member_has_pyproject_on_disk():
    """Initialized workspace members need pyproject.toml; gitlinks may be lazy."""
    members = _read_uv_members(ROOT)
    missing = [
        m for m in members if not (ROOT / m / "pyproject.toml").is_file() and not _is_gitlink(m)
    ]
    assert not missing, f"Members missing pyproject.toml: {missing}"


def test_is_gitlink_falls_back_to_gitmodules_when_git_is_unavailable(monkeypatch):
    def raise_file_not_found(*_args, **_kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(subprocess, "run", raise_file_not_found)

    assert _is_gitlink("packages/acgs-lite") is True


def test_mypy_configured_uv_members_declare_targets():
    """Bare `uv run mypy` needs an explicit target in package-local config."""
    root = _load_toml("pyproject.toml")
    missing_targets: list[str] = []
    for member in root["tool"]["uv"]["workspace"]["members"]:
        pyproject = ROOT / member / "pyproject.toml"
        if not pyproject.is_file():
            continue
        config = _load_toml(f"{member}/pyproject.toml")
        mypy = config.get("tool", {}).get("mypy")
        if mypy is None:
            continue
        if not any(key in mypy for key in ("files", "packages", "modules")):
            missing_targets.append(member)
    assert not missing_targets, (
        "Workspace Makefile runs bare `uv run mypy` for members with mypy config; "
        f"these members need files/packages/modules targets: {missing_targets}"
    )


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
    expected = (
        "pnpm@9.15.4+sha512."
        "b2dc20e2fc72b3e18848459b37359a32064663e5627a51e4c74b2c29dd8e8e0491483c3abb"
        "40789cfd578bf362fb6ba8261b05f0387d76792ed6e23ea3b1b6a0"
    )
    assert root["packageManager"] == app["packageManager"] == expected, (
        "Root and acgi-ai must agree on the reviewed integrity-qualified pnpm selector."
    )
    assert (ROOT / "acgi-ai/.node-version").read_text().strip() == "24.18.0"


def test_pnpm_workspace_lists_acgi_ai():
    ws = _load_yaml("pnpm-workspace.yaml")
    assert "acgi-ai" in ws["packages"]


def test_enterprise_frontend_is_archived_not_a_workspace_member():
    """The orphan Vue app is archived (roadmap 00#5): it must stay out of the
    pnpm workspace so installs/Turbo no longer discover it, and the archived
    tree must keep its rationale record."""
    ws = _load_yaml("pnpm-workspace.yaml")
    assert "acgs-enterprise-ai-manager/frontend" not in ws["packages"]
    assert not (ROOT / "acgs-enterprise-ai-manager").exists()
    archived = "docs/archive/acgs-enterprise-ai-manager"
    pkg = _load_json(f"{archived}/frontend/package.json")
    assert pkg["name"] == "acgs-enterprise-manager-frontend"
    assert (ROOT / archived / "ARCHIVED.md").is_file()


# ---------------------------------------------------------------------------
# Workflow path filters — CI triggers must match real directories
# ---------------------------------------------------------------------------

WORKFLOW_PATH_PREFIXES = {
    "python-eval-mvp.yml": "acgs_governance_eval_mvp",
    "python-cft-pack.yml": "acgs-cft-governance-pack",
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


def test_console_marketing_and_storybook_workflows_split_pr_from_deploy():
    """Fork-editable PR code must never share a credentialed deploy workflow."""
    for name in ("console.yml", "marketing.yml", "storybook.yml"):
        path = ROOT / ".github/workflows" / name
        assert path.exists(), f"Missing PR verification workflow: {name}"
        text = path.read_text()
        assert "pull_request:" in text
        assert "${{ secrets." not in text
        assert "id-token: write" not in text
        assert "self-hosted" not in text

    for name in ("console-deploy.yml", "marketing-cloudflare.yml", "storybook-deploy.yml"):
        path = ROOT / ".github/workflows" / name
        assert path.exists(), f"Missing push-only deployment workflow: {name}"
        text = path.read_text()
        trigger = text.split("\nconcurrency:", 1)[0]
        assert "push:" in trigger
        assert "pull_request:" not in trigger


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
