#!/usr/bin/env python3
"""Hardening sprint report generator.

Walks the monorepo unification DoD from docs/PLAN-MONOREPO.md §2 and emits
a markdown report at `artifacts/hardening_reports/hardening-<ts>.md`. Each
DoD row becomes a `ChecklistItem` with status pass/fail/pending and an
evidence string. The generator runs three live drills along the way:

  1. Drift drill        — inject a marker into a tmp file, confirm detection.
  2. Workflow schema    — every .github/workflows/*.yml parses + has on/jobs.
  3. Lock integrity     — docs/constitutional-hashes.lock parses + has hashes.

Drills produce artifacts under `artifacts/rollback_drills/` so audit can
trace each gate to a captured exercise.

Usage:
    python scripts/hardening_report.py            # write report
    python scripts/hardening_report.py --print    # stdout only, no file
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
import tempfile
import tomllib
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = REPO_ROOT / "artifacts"
REPORTS_DIR = ARTIFACTS_DIR / "hardening_reports"
DRILLS_DIR = ARTIFACTS_DIR / "rollback_drills"


def _read_uv_members(repo_root: Path) -> list[str]:
    """Read uv workspace members from the root pyproject.toml.

    Mirrored in ``tests/test_monorepo_invariants.py``; keep the two
    implementations in lock-step — both must read the same key from the
    same file.
    """
    with (repo_root / "pyproject.toml").open("rb") as f:
        root_proj = tomllib.load(f)
    return list(root_proj["tool"]["uv"]["workspace"]["members"])


@dataclass
class ChecklistItem:
    number: int
    description: str
    status: str  # "pass" | "fail" | "pending"
    evidence: str

    @property
    def icon(self) -> str:
        return {"pass": "✅", "fail": "❌", "pending": "⏳"}.get(self.status, "?")


@dataclass
class DrillRecord:
    drill_type: str
    drill_id: str
    status: str  # "passed" | "failed"
    started: str
    finished: str
    events: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "drill_type": self.drill_type,
            "drill_id": self.drill_id,
            "status": self.status,
            "started": self.started,
            "finished": self.finished,
            "events": self.events,
        }


# ---------------------------------------------------------------------------
# Drills
# ---------------------------------------------------------------------------


def drill_drift_detection(repo_root: Path) -> DrillRecord:
    """Inject a marker into a temp file inside a synthetic git tree and
    confirm the verifier detects the resulting added/changed marker."""
    started = dt.datetime.now(dt.UTC).isoformat()
    drill_id = uuid.uuid4().hex[:12]
    events: list[dict] = []

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td) / "tree"
        td_path.mkdir()
        (td_path / "scripts").mkdir()
        (td_path / "docs").mkdir()
        script_src = repo_root / "scripts" / "verify_constitutional_hashes.py"
        script_dst = td_path / "scripts" / "verify_constitutional_hashes.py"
        script_dst.write_text(script_src.read_text())
        subprocess.run(["git", "init", "-q"], cwd=td_path, check=True)
        subprocess.run(["git", "config", "user.email", "drill@drill"], cwd=td_path, check=True)
        subprocess.run(["git", "config", "user.name", "drill"], cwd=td_path, check=True)
        (td_path / ".gitignore").write_text("scripts/\n")
        subprocess.run(["git", "add", "."], cwd=td_path, check=True)
        subprocess.run(["git", "commit", "-qm", "baseline"], cwd=td_path, check=True)

        # Pin an empty baseline lock.
        result = subprocess.run(
            [sys.executable, str(script_dst), "--update"],
            cwd=td_path,
            capture_output=True,
            text=True,
        )
        events.append({"step": "baseline_pin", "exit": result.returncode})
        if result.returncode != 0:
            return DrillRecord(
                "drift-detection",
                drill_id,
                "failed",
                started,
                dt.datetime.now(dt.UTC).isoformat(),
                [*events, {"step": "abort", "reason": result.stderr}],
            )

        # Inject a synthetic marker.
        (td_path / "policy.py").write_text("# Constitutional Hash: deadbeefcafebabe\nPOLICY = 1\n")
        subprocess.run(["git", "add", "policy.py"], cwd=td_path, check=True)
        subprocess.run(["git", "commit", "-qm", "drift"], cwd=td_path, check=True)
        events.append({"step": "inject_marker", "file": "policy.py", "hash": "deadbeefcafebabe"})

        # Verifier must now fail with exit 1 and report ADDED.
        result = subprocess.run(
            [sys.executable, str(script_dst)],
            cwd=td_path,
            capture_output=True,
            text=True,
        )
        events.append(
            {
                "step": "verify_after_drift",
                "exit": result.returncode,
                "stdout_contains_ADDED": "ADDED" in result.stdout,
            }
        )
        passed = (
            result.returncode == 1 and "ADDED" in result.stdout and "policy.py" in result.stdout
        )

    finished = dt.datetime.now(dt.UTC).isoformat()
    return DrillRecord(
        "drift-detection",
        drill_id,
        "passed" if passed else "failed",
        started,
        finished,
        events,
    )


def drill_workflow_schema(repo_root: Path) -> DrillRecord:
    """Every workflow under .github/workflows/ must parse and declare on/jobs."""
    started = dt.datetime.now(dt.UTC).isoformat()
    drill_id = uuid.uuid4().hex[:12]
    events: list[dict] = []
    all_pass = True

    workflows_dir = repo_root / ".github" / "workflows"
    for wf in sorted(workflows_dir.glob("*.yml")):
        try:
            doc = yaml.safe_load(wf.read_text())
        except yaml.YAMLError as e:
            events.append({"workflow": wf.name, "status": "parse-error", "error": str(e)})
            all_pass = False
            continue
        # YAML parses bare `on:` as True key — accept either.
        has_triggers = "on" in doc or True in doc
        has_jobs = isinstance(doc.get("jobs"), dict) and len(doc["jobs"]) > 0
        ok = has_triggers and has_jobs
        events.append(
            {
                "workflow": wf.name,
                "status": "ok" if ok else "missing-keys",
                "has_triggers": has_triggers,
                "has_jobs": has_jobs,
            }
        )
        if not ok:
            all_pass = False

    finished = dt.datetime.now(dt.UTC).isoformat()
    return DrillRecord(
        "workflow-schema",
        drill_id,
        "passed" if all_pass else "failed",
        started,
        finished,
        events,
    )


def drill_lock_integrity(repo_root: Path) -> DrillRecord:
    """docs/constitutional-hashes.lock must parse and conform to schema."""
    started = dt.datetime.now(dt.UTC).isoformat()
    drill_id = uuid.uuid4().hex[:12]
    events: list[dict] = []
    lock_path = repo_root / "docs" / "constitutional-hashes.lock"

    if not lock_path.exists():
        events.append({"step": "exists", "result": False})
        finished = dt.datetime.now(dt.UTC).isoformat()
        return DrillRecord("lock-integrity", drill_id, "failed", started, finished, events)

    try:
        data = json.loads(lock_path.read_text())
        events.append({"step": "parse", "result": "ok"})
    except json.JSONDecodeError as e:
        events.append({"step": "parse", "result": "fail", "error": str(e)})
        finished = dt.datetime.now(dt.UTC).isoformat()
        return DrillRecord("lock-integrity", drill_id, "failed", started, finished, events)

    has_key = "hashes" in data and isinstance(data["hashes"], dict)
    events.append({"step": "schema", "has_hashes_key": has_key})

    bad_entries = []
    for path, h in data.get("hashes", {}).items():
        if (
            not isinstance(h, str)
            or len(h) != 16
            or not all(c in "0123456789abcdefABCDEF" for c in h)
        ):
            bad_entries.append({"path": path, "hash": h})
    events.append(
        {
            "step": "entry_validation",
            "bad_entries": bad_entries,
            "count": len(data.get("hashes", {})),
        }
    )

    finished = dt.datetime.now(dt.UTC).isoformat()
    passed = has_key and not bad_entries
    return DrillRecord(
        "lock-integrity", drill_id, "passed" if passed else "failed", started, finished, events
    )


# ---------------------------------------------------------------------------
# Checklist (DoD § from docs/PLAN-MONOREPO.md mapped to programmatic checks)
# ---------------------------------------------------------------------------


def build_checklist(repo_root: Path, drills: list[DrillRecord]) -> list[ChecklistItem]:
    items: list[ChecklistItem] = []

    # 1. Root files resolve broken ../../CLAUDE.md references
    claude_exists = (repo_root / "CLAUDE.md").is_file()
    agents_exists = (repo_root / "AGENTS.md").is_file()
    items.append(
        ChecklistItem(
            number=1,
            description="Root CLAUDE.md + AGENTS.md exist (resolve ../../CLAUDE.md refs)",
            status="pass" if (claude_exists and agents_exists) else "fail",
            evidence=f"CLAUDE.md={claude_exists}, AGENTS.md={agents_exists}",
        )
    )

    # 2. Single build command via Make / Turbo / uv workspace
    has_makefile = (repo_root / "Makefile").is_file()
    has_turbo = (repo_root / "turbo.json").is_file()
    has_pnpm_ws = (repo_root / "pnpm-workspace.yaml").is_file()
    has_pyproject = (repo_root / "pyproject.toml").is_file()
    all_present = has_makefile and has_turbo and has_pnpm_ws and has_pyproject
    items.append(
        ChecklistItem(
            number=2,
            description=(
                "Build orchestration installed "
                "(Makefile + turbo.json + pnpm-workspace.yaml + pyproject.toml)"
            ),
            status="pass" if all_present else "fail",
            evidence=(
                f"Makefile={has_makefile}, turbo.json={has_turbo}, "
                f"pnpm-workspace.yaml={has_pnpm_ws}, pyproject.toml={has_pyproject}"
            ),
        )
    )

    # 3. uv workspace member list matches plan
    try:
        import tomllib

        root_proj = tomllib.loads((repo_root / "pyproject.toml").read_text())
        expected = {
            "packages/acgs-lite",
            "packages/Acgs-Swarm",
            "packages/clinicalguard",
            "packages/gove-zone",
            "packages/agent-bus-analyzer",
            "packages/acgs-control-plane",
            "packages/acgs-proofpack-verifier",
            "packages/research-engine",
            "acgs_governance_eval_mvp",
            "acgs-cft-governance-pack",
        }
        declared = set(root_proj["tool"]["uv"]["workspace"]["members"])
        items.append(
            ChecklistItem(
                number=3,
                description=(
                    "uv workspace members match current parent Python registry "
                    f"({len(expected)} packages)"
                ),
                status="pass" if declared == expected else "fail",
                evidence=f"declared={sorted(declared)}",
            )
        )
    except Exception as e:
        items.append(
            ChecklistItem(
                number=3,
                description="uv workspace members",
                status="fail",
                evidence=f"could not parse pyproject.toml: {e}",
            )
        )

    # 4. Per-package CI workflows exist
    expected_workflows = [
        # Parent-tracked Python packages
        "python-eval-mvp.yml",
        "python-cft-pack.yml",
        # Submodule-tracked Python packages (Phase 4 remainder — needs Phase 2)
        "python-acgs-lite.yml",
        "python-acgs-swarm.yml",
        "python-clinicalguard.yml",
        # Cross-cutting
        "constitutional-hash.yml",
    ]
    missing = [w for w in expected_workflows if not (repo_root / ".github/workflows" / w).is_file()]
    items.append(
        ChecklistItem(
            number=4,
            description=(
                "Path-filtered CI for parent-tracked surfaces "
                f"({len(expected_workflows)} workflows)"
            ),
            status="pass" if not missing else "fail",
            evidence=f"missing={missing}" if missing else "all present",
        )
    )

    # 5. Existing acgi-ai workflows untouched
    untouched = (repo_root / ".github/workflows/console.yml").is_file() and (
        repo_root / ".github/workflows/marketing.yml"
    ).is_file()
    items.append(
        ChecklistItem(
            number=5,
            description="Cloud Run + Vercel workflows (console.yml + marketing.yml) preserved",
            status="pass" if untouched else "fail",
            evidence=f"console.yml={'present' if untouched else 'missing'}",
        )
    )

    # 6. Constitutional-hash lock exists + well-formed
    lock_drill = next((d for d in drills if d.drill_type == "lock-integrity"), None)
    items.append(
        ChecklistItem(
            number=6,
            description="Constitutional-hash lock baseline established",
            status="pass" if lock_drill and lock_drill.status == "passed" else "fail",
            evidence=f"drill={lock_drill.status if lock_drill else 'not-run'}",
        )
    )

    # 7. Drift drill (live exercise of the gate)
    drift = next((d for d in drills if d.drill_type == "drift-detection"), None)
    items.append(
        ChecklistItem(
            number=7,
            description="Drift drill: synthetic marker injection detected by verifier",
            status="pass" if drift and drift.status == "passed" else "fail",
            evidence=(
                f"drill={drift.drill_id if drift else 'not-run'}, "
                f"status={drift.status if drift else 'n/a'}"
            ),
        )
    )

    # 8. Workflow schema drill
    schema = next((d for d in drills if d.drill_type == "workflow-schema"), None)
    items.append(
        ChecklistItem(
            number=8,
            description="All workflows parse and declare on:/jobs:",
            status="pass" if schema and schema.status == "passed" else "fail",
            evidence=(
                f"drill={schema.drill_id if schema else 'not-run'}, "
                f"status={schema.status if schema else 'n/a'}"
            ),
        )
    )

    # 9. Plan recorded
    plan_path = repo_root / "docs/PLAN-MONOREPO.md"
    plan_size_kb = plan_path.stat().st_size // 1024 if plan_path.is_file() else 0
    items.append(
        ChecklistItem(
            number=9,
            description="docs/PLAN-MONOREPO.md exists and records the multi-phase plan",
            status="pass" if plan_path.is_file() else "fail",
            evidence=f"size_kb={plan_size_kb}",
        )
    )

    # 10. Phase 2 — submodule registration
    gitmodules = repo_root / ".gitmodules"
    if gitmodules.is_file():
        sm_lines = [
            line
            for line in gitmodules.read_text().splitlines()
            if line.strip().startswith("path = ")
        ]
        items.append(
            ChecklistItem(
                number=10,
                description="Phase 2 (submodule registration) — landed",
                status="pass",
                evidence=f".gitmodules present — {len(sm_lines)} submodule(s) registered",
            )
        )
    else:
        items.append(
            ChecklistItem(
                number=10,
                description="Phase 2 (submodule registration) — deferred",
                status="pending",
                evidence=(
                    ".gitmodules absent — packages/* tracked as nested repos invisible to parent"
                ),
            )
        )

    return items


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def render_report(items: list[ChecklistItem], drills: list[DrillRecord]) -> str:
    now = dt.datetime.now(dt.UTC)
    passes = sum(1 for i in items if i.status == "pass")
    fails = sum(1 for i in items if i.status == "fail")
    pending = sum(1 for i in items if i.status == "pending")

    lines = [
        f"# Monorepo Hardening Report — {now.strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "**Scope:** docs/PLAN-MONOREPO.md Phase 1 + 2 + 4 + 5.",
        "",
        f"**Result:** {passes}/{len(items)} pass · {fails} fail · {pending} pending",
        "",
        "## Checklist",
        "",
        "| # | Status | Item | Evidence |",
        "|---|---|---|---|",
    ]
    for item in items:
        lines.append(
            f"| {item.number} | {item.icon} {item.status} | "
            f"{item.description} | `{item.evidence}` |"
        )

    lines += ["", "## Drill Records", ""]
    for d in drills:
        lines += [
            f"### {d.drill_type} — `{d.drill_id}`",
            "",
            f"- **Status:** {d.status}",
            f"- **Started:** {d.started}",
            f"- **Finished:** {d.finished}",
            f"- **Events:** {len(d.events)}",
            "",
        ]

    lines += [
        "## Artifacts",
        "",
        "Per-drill JSON records are saved under `artifacts/rollback_drills/`. ",
        "This report is at `artifacts/hardening_reports/`. Both directories ",
        "are gitignored by convention — the report is intended as audit evidence ",
        "produced fresh per run, not checked-in state.",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_drills(repo_root: Path) -> list[DrillRecord]:
    return [
        drill_drift_detection(repo_root),
        drill_workflow_schema(repo_root),
        drill_lock_integrity(repo_root),
    ]


def persist_drills(drills: list[DrillRecord], drills_dir: Path) -> list[Path]:
    drills_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for d in drills:
        path = drills_dir / f"drill-{d.drill_id}_{d.drill_type}.json"
        path.write_text(json.dumps(d.to_dict(), indent=2) + "\n")
        paths.append(path)
    return paths


def persist_report(text: str, reports_dir: Path) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.now(dt.UTC).strftime("%Y%m%d-%H%M%S")
    path = reports_dir / f"hardening-{ts}.md"
    path.write_text(text)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--print", action="store_true", help="Print to stdout only; do not write files."
    )
    args = parser.parse_args()

    drills = run_drills(REPO_ROOT)
    items = build_checklist(REPO_ROOT, drills)
    text = render_report(items, drills)

    if args.print:
        sys.stdout.write(text)
        sys.stdout.write("\n")
    else:
        report_path = persist_report(text, REPORTS_DIR)
        drill_paths = persist_drills(drills, DRILLS_DIR)
        print(f"Wrote {report_path.relative_to(REPO_ROOT)}")
        for p in drill_paths:
            print(f"Wrote {p.relative_to(REPO_ROOT)}")

    # Exit code mirrors overall pass: fail if any item is fail (pending tolerated).
    fails = sum(1 for i in items if i.status == "fail")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
