"""Git transition-path capture (H1).

Proves not just the frozen *state* but the *transition* into it: the diff,
changed-file list, working-tree cleanliness, and tracked inventory between a
parent commit and the freeze commit. Pure + injectable runner so it is unit
testable without a live repo; the real runner shells out to git.

This is a reusable capability. It is intentionally NOT wired into the frozen
Phase 1.1 manifest (that is immutable) — a Phase 2 manifest revision consumes it.
"""

from __future__ import annotations

from typing import Callable

Runner = Callable[[list[str]], str]


def subprocess_runner(repo: str) -> Runner:
    import subprocess

    def run(args: list[str]) -> str:
        return subprocess.check_output(["git", "-C", repo, *args], text=True)

    return run


def git_transition(parent: str, head: str, run: Runner) -> dict:
    """Return a transition-evidence block for parent..head using ``run``."""
    rng = f"{parent}..{head}"
    # `--` terminates option parsing so a ref beginning with `-` can't be read as a flag.
    diff_shortstat = run(["diff", "--shortstat", rng, "--"]).strip()
    name_status = [ln for ln in run(["diff", "--name-status", rng, "--"]).splitlines() if ln.strip()]
    status = run(["status", "--porcelain=v1"]).strip()
    ls_files = [ln for ln in run(["ls-files", "-s"]).splitlines() if ln.strip()]

    changed = []
    for ln in name_status:
        parts = ln.split("\t")
        if len(parts) < 2:
            continue
        change = parts[0]
        entry = {"change": change, "path": parts[-1]}  # for R/C the new path is last
        if change[:1] in ("R", "C") and len(parts) >= 3:
            entry["from"] = parts[1]
        changed.append(entry)
    return {
        "parent": parent,
        "head": head,
        "diff_shortstat": diff_shortstat,
        "changed_files": changed,
        "working_tree_clean": status == "",
        "tracked_file_count": len(ls_files),
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json
    from pathlib import Path

    ap = argparse.ArgumentParser(prog="git-evidence")
    ap.add_argument("parent")
    ap.add_argument("head")
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parents[1]))
    args = ap.parse_args(argv)
    block = git_transition(args.parent, args.head, subprocess_runner(args.repo))
    print(json.dumps(block, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
