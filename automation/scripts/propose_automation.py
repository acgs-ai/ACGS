#!/usr/bin/env python3
"""Create a reviewable automation proposal from a prompt."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from audit_log import (
    append_event,
)

PROPOSALS_DIR = Path("automation/proposals")
CONTEXT_PATTERNS = (
    "README.md",
    "*/README.md",
    "pyproject.toml",
    "*/pyproject.toml",
    "package.json",
    "*/package.json",
    "docs/*.md",
    "*/docs/*.md",
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    "*/.github/workflows/*.yml",
    "*/.github/workflows/*.yaml",
    "scripts/*.py",
    "*/scripts/*.py",
)
CONTEXT_EXCLUDED_PARTS = {
    ".git",
    ".pytest_cache",
    "node_modules",
    "__pycache__",
    ".omx",
    ".omc",
}
MAX_CONTEXT_FILES = 12
MAX_SUMMARY_CHARS = 160
MAX_CONTEXT_FILE_BYTES = 64_000


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:48].strip("-") or "automation"


def first_summary_line(path: Path) -> str:
    if path.stat().st_size > MAX_CONTEXT_FILE_BYTES:
        return "local file present; skipped summary because file is large"
    if path.name == "package.json":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return "local package.json present"
        name = data.get("name", "unnamed")
        version = data.get("version")
        return f"package {name}" + (f" {version}" if version else "")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        summary = line.strip().lstrip("#").strip()
        if summary:
            return summary[:MAX_SUMMARY_CHARS]
    return "local file present"


def collect_project_context(
    repo_root: Path, limit: int = MAX_CONTEXT_FILES
) -> list[dict[str, str]]:
    context: list[dict[str, str]] = []
    seen: set[Path] = set()
    for pattern in CONTEXT_PATTERNS:
        for path in sorted(repo_root.glob(pattern)):
            if len(context) >= limit:
                return context
            if not path.is_file():
                continue
            relative = path.relative_to(repo_root)
            if any(part in CONTEXT_EXCLUDED_PARTS for part in relative.parts):
                continue
            if relative in seen:
                continue
            seen.add(relative)
            context.append({"path": relative.as_posix(), "summary": first_summary_line(path)})
    return context


def build_proposal(
    prompt: str,
    owner: str,
    *,
    include_context: bool = False,
    repo_root: Path = Path("."),
) -> dict[str, object]:
    created_at = datetime.now(UTC).replace(microsecond=0).isoformat()
    automation_id = f"auto-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{slugify(prompt)[:24]}"
    proposal: dict[str, object] = {
        "id": automation_id,
        "name": prompt[:80],
        "status": "proposed",
        "owner": owner,
        "created_at": created_at,
        "goal": prompt,
        "trigger": "manual",
        "inputs": [],
        "outputs": [],
        "files_touched": [],
        "commands_executed": [],
        "risk_assessment": {
            "risk_level": "unknown",
            "dangerous_commands_reviewed": False,
            "secrets_reviewed": False,
            "protected_branches_reviewed": False,
            "deploy_reviewed": False,
        },
        "rollback_plan": "",
        "acceptance_criteria": [],
        "tests": [],
    }
    if include_context:
        proposal["project_context"] = collect_project_context(repo_root.resolve())
    return proposal


def main() -> int:
    parser = argparse.ArgumentParser(description="Create an automation proposal YAML file.")
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--owner", default="repo-owner")
    parser.add_argument("--output-dir", type=Path, default=PROPOSALS_DIR)
    parser.add_argument("--log-path", type=Path, default=Path("automation/logs/audit.jsonl"))
    parser.add_argument(
        "--include-context",
        action="store_true",
        help="Include bounded summaries from local repo files; never performs network calls.",
    )
    args = parser.parse_args()

    proposal = build_proposal(
        args.prompt,
        args.owner,
        include_context=args.include_context,
        repo_root=Path("."),
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output_path = args.output_dir / f"{proposal['id']}.yaml"
    output_path.write_text(yaml.safe_dump(proposal, sort_keys=False), encoding="utf-8")
    append_event(
        actor=args.owner,
        action="proposal_created",
        automation_id=str(proposal["id"]),
        files_changed=[str(output_path)],
        validation_result="not_run",
        decision="proposed",
        log_path=args.log_path,
    )
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
