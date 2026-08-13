#!/usr/bin/env python3
"""Generate the merge-state ledger: docs/INTEGRATION-STATE.md + docs/integration-state.json.

Classifies every remote branch by *content*, not ancestry, because master mixes
squash merges with true merges — `git branch --no-merged` reports squash-merged
branches as unmerged forever. Method (per-branch):

  1. touched = `git diff --name-only BASE...branch`   (merge-base diff: what the
     branch changed relative to where it forked)
  2. If empty -> NO-OP (branch adds nothing).
  3. differing = `git diff --name-only BASE branch -- <touched>` (tip-vs-tip,
     restricted to the touched files). If empty, every blob the branch touched
     is byte-identical on BASE -> LANDED (typically a squash ghost). Otherwise
     STRANDED with `len(differing)` files still differing.

The ledger is regenerable: run this script after `git fetch origin` and commit
the refreshed outputs. PR linkage is best-effort via `gh` and degrades to
"unknown" when the API is unavailable.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

BASE = "origin/master"
MD_OUT = Path("docs/INTEGRATION-STATE.md")
JSON_OUT = Path("docs/integration-state.json")


def git(*args: str) -> str:
    result = subprocess.run(["git", *args], capture_output=True, text=True, check=True)
    return result.stdout


def list_remote_branches() -> list[str]:
    out = git("for-each-ref", "--format=%(refname:short)", "refs/remotes/origin")
    branches = []
    for ref in out.splitlines():
        ref = ref.strip()
        if not ref or ref.endswith("HEAD") or ref == BASE:
            continue
        branches.append(ref)
    return branches


def branch_tip_date(branch: str) -> str:
    return git("log", "-1", "--format=%cI", branch).strip()


def classify(branch: str) -> dict:
    touched = [f for f in git("diff", "--name-only", f"{BASE}...{branch}").splitlines() if f]
    entry = {
        "branch": branch.removeprefix("origin/"),
        "tip_date": branch_tip_date(branch),
        "files_touched": len(touched),
    }
    if not touched:
        entry.update(status="NO-OP", files_differing=0)
        return entry
    differing = [
        f for f in git("diff", "--name-only", BASE, branch, "--", *touched).splitlines() if f
    ]
    if not differing:
        entry.update(status="LANDED", files_differing=0)
    else:
        entry.update(
            status="STRANDED",
            files_differing=len(differing),
            differing_sample=sorted(differing)[:5],
        )
    return entry


def try_open_prs() -> dict[str, int]:
    """Map head branch name -> PR number for open PRs, if `gh` works."""
    try:
        out = subprocess.run(
            [
                "gh",
                "pr",
                "list",
                "--state",
                "open",
                "--limit",
                "500",
                "--json",
                "number,headRefName",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        ).stdout
        return {row["headRefName"]: row["number"] for row in json.loads(out)}
    except Exception:
        return {}


def render_markdown(
    entries: list[dict], base_sha: str, prs: dict[str, int], pr_data_available: bool
) -> str:
    counts = Counter(e["status"] for e in entries)
    stranded = [e for e in entries if e["status"] == "STRANDED"]
    stranded.sort(key=lambda e: (e["files_differing"], e["tip_date"]))
    small_tail = sum(1 for e in stranded if e["files_differing"] <= 2)
    generated = datetime.now(UTC).strftime("%Y-%m-%d")

    lines = [
        "# Integration State Ledger",
        "",
        "<!-- GENERATED FILE — regenerate with `python3 scripts/integration_state.py` -->",
        "",
        f"Base: `{BASE}` @ `{base_sha}` · generated {generated} · "
        f"branches: {len(entries)} total — "
        f"**{counts.get('STRANDED', 0)} STRANDED** "
        f"({small_tail} differ in ≤2 files), "
        f"{counts.get('LANDED', 0)} LANDED (squash ghosts, safe to delete), "
        f"{counts.get('NO-OP', 0)} NO-OP (safe to delete).",
        "",
        "A branch is STRANDED when at least one file it touched still differs",
        "from master (content comparison — ancestry is unreliable under squash",
        "merges). LANDED means every touched blob is byte-identical on master.",
        "",
        "## Stranded branches (smallest diff first — drain these)",
        "",
        "| Branch | Files differing | Tip date | Open PR |",
        "|---|---|---|---|",
    ]
    for e in stranded:
        pr = prs.get(e["branch"])
        pr_cell = f"#{pr}" if pr else ("—" if pr_data_available else "unknown")
        lines.append(
            f"| `{e['branch']}` | {e['files_differing']} | {e['tip_date'][:10]} | {pr_cell} |"
        )
    lines += [
        "",
        "## Reapable branches (content already on master, or no content)",
        "",
        "| Branch | Status | Tip date |",
        "|---|---|---|",
    ]
    for e in entries:
        if e["status"] in ("LANDED", "NO-OP"):
            lines.append(f"| `{e['branch']}` | {e['status']} | {e['tip_date'][:10]} |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if outputs are missing (freshness left to review cadence)",
    )
    args = parser.parse_args()
    if args.check:
        ok = MD_OUT.exists() and JSON_OUT.exists()
        print(f"ledger present: {ok}")
        return 0 if ok else 1

    base_sha = git("rev-parse", "--short", BASE).strip()
    branches = list_remote_branches()
    print(
        f"classifying {len(branches)} remote branches against {BASE} @ {base_sha}", file=sys.stderr
    )

    entries = []
    for i, branch in enumerate(branches, 1):
        try:
            entries.append(classify(branch))
        except subprocess.CalledProcessError as exc:
            entries.append(
                {
                    "branch": branch.removeprefix("origin/"),
                    "status": "ERROR",
                    "error": (exc.stderr or "").strip()[:200],
                    "tip_date": "",
                    "files_touched": 0,
                    "files_differing": 0,
                }
            )
        if i % 50 == 0:
            print(f"  {i}/{len(branches)}", file=sys.stderr)

    prs = try_open_prs()
    pr_data_available = bool(prs)

    counts = Counter(e["status"] for e in entries)
    payload = {
        "base": BASE,
        "base_sha": base_sha,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "summary": dict(counts),
        "pr_data_available": pr_data_available,
        "branches": sorted(entries, key=lambda e: e["branch"]),
    }
    JSON_OUT.parent.mkdir(parents=True, exist_ok=True)
    JSON_OUT.write_text(json.dumps(payload, indent=2) + "\n")
    MD_OUT.write_text(render_markdown(entries, base_sha, prs, pr_data_available))
    print(f"wrote {MD_OUT} and {JSON_OUT}: {dict(counts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
