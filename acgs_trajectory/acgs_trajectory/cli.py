"""Minimal ingestion CLI (Phase 1).

    acgs-ingest <session.jsonl> --store <dir> [--head-sha SHA] [--dirty]
                [--captured-at ISO8601] [--out record.json]

Deterministic: if --captured-at is omitted it defaults to the epoch so runs are
reproducible; supply the real capture time in production.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from .ingest import ingest_text
from .raw_store import RawStore


def _git_state(cwd: str | None) -> dict:
    if not cwd:
        return {}
    try:
        head = subprocess.check_output(["git", "-C", cwd, "rev-parse", "HEAD"], text=True).strip()
        status = subprocess.check_output(["git", "-C", cwd, "status", "--short"], text=True)
        branch = subprocess.check_output(["git", "-C", cwd, "rev-parse", "--abbrev-ref", "HEAD"], text=True).strip()
        return {"head_sha": head, "dirty": bool(status.strip()), "branch": branch}
    except Exception:
        return {}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="acgs-ingest")
    ap.add_argument("session", help="path to a Claude Code session .jsonl")
    ap.add_argument("--store", help="raw archive root directory")
    ap.add_argument("--head-sha", dest="head_sha")
    ap.add_argument("--dirty", action="store_true")
    ap.add_argument("--repo", help="repo path to auto-detect git head/dirty")
    ap.add_argument("--captured-at", default="1970-01-01T00:00:00Z")
    ap.add_argument("--out", help="write the trajectory record JSON here")
    args = ap.parse_args(argv)

    raw_text = Path(args.session).read_text(encoding="utf-8")

    repo_git: dict = {}
    if args.repo:
        repo_git.update(_git_state(args.repo))
    if args.head_sha:
        repo_git["head_sha"] = args.head_sha
    if args.dirty:
        repo_git["dirty"] = True

    store = RawStore(args.store) if args.store else None
    result = ingest_text(
        raw_text,
        store=store,
        captured_at=args.captured_at,
        repo_git=repo_git or None,
    )

    out = json.dumps(result.record, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")

    print(f"status={result.status} trajectory_id={result.record['trajectory_id']}")
    print(f"reasons={result.reasons}")
    # fail-closed exit code: only a complete record exits 0
    return 0 if result.status == "complete" else 1


if __name__ == "__main__":
    sys.exit(main())
