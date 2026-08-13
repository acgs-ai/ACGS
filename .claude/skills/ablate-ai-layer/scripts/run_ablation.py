#!/usr/bin/env python3
"""Run the ablation experiment. The agent calls this; the user watches.

Executes the same probe task N times with the AI layer intact and N times with it
stripped, in throwaway git worktrees, and collects the resulting diffs for grading.

Two properties make this safe to run unattended:

  * Your working tree is never modified. Every run happens in a detached worktree
    created from HEAD in a temp directory and deleted afterwards. Nothing is moved
    aside, so there is no restore step that can fail and leave you stripped.
  * Worktrees live OUTSIDE the repo. An agent started inside the repo would walk
    up and find the very CLAUDE.md this script just removed.

Why N runs per arm rather than one: agent runs are nondeterministic. A single
control-vs-stripped pair is a point estimate, and two runs of the SAME arm can
differ more than the two arms differ. Only a rule that behaves consistently across
runs is evidence of anything.

Usage:
  python run_ablation.py <repo> --task-file task.md
  python run_ablation.py <repo> --task-file task.md --runs 3 --scope all
  python run_ablation.py <repo> --task-file task.md --dry-run
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from map_layer import ALWAYS, ONDEMAND, iter_matches  # noqa: E402

CONTROL, STRIPPED = "control", "stripped"


# ---------------------------------------------------------------- git plumbing

def git(args: list[str], cwd: Path, check: bool = True) -> str:
    p = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    if check and p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {p.stderr.strip()}")
    return p.stdout


def repo_root(start: Path) -> Path:
    out = git(["rev-parse", "--show-toplevel"], start).strip()
    return Path(out).resolve()


def head_sha(root: Path) -> str:
    return git(["rev-parse", "HEAD"], root).strip()


def is_dirty(root: Path) -> bool:
    return bool(git(["status", "--porcelain"], root).strip())


def owning_git_root(root: Path, rel: str) -> Path:
    """Nearest ancestor of the target (up to root) that is its own git repo.

    A `.git` entry below root marks a nested repository / submodule boundary:
    files under it belong to THAT repo, and root's tree records only a 160000
    gitlink for the directory."""
    d = (root / rel).parent
    while d != root and root in d.parents:
        if (d / ".git").exists():
            return d
        d = d.parent
    return root


# ---------------------------------------------------------------- the layer

def layer_targets(root: Path, scope: str) -> list[dict]:
    """The artifacts the stripped arm removes. Enforcement is never touched:
    hooks and permissions run as code and spend no attention budget, so removing
    them would change mechanics rather than the variable under test."""
    kinds = {ALWAYS} if scope == "always" else {ALWAYS, ONDEMAND}
    return [i for i in iter_matches(root) if i["kind"] in kinds]


SOURCE_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs", ".rb",
                   ".java", ".kt", ".cs", ".php", ".swift", ".toml", ".json"}
SKIP = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__",
        ".next", "target", ".ablation"}


def build_dependencies(root: Path, targets: list[dict]) -> list[str]:
    """Does the repo's own source read its AI layer? A CLI that imports its skill
    markdown at build time breaks the moment those files go missing, and the user
    reads a compile error as an agent regression."""
    names = {Path(t["path"]).name for t in targets}
    names |= {t["path"] for t in targets}
    hits = []
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix not in SOURCE_SUFFIXES:
            continue
        if any(part in SKIP for part in p.parts):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for n in names:
            if n in text:
                hits.append(f"{p.relative_to(root).as_posix()} references {n}")
                break
    return hits


def stage_agent_changes(wt: Path, removed: list[str]) -> None:
    """Stage ONLY what the agent changed. The stripped arm deleted instruction
    files before the agent ran; those artificial deletions must never enter the
    captured diff — they would count a do-nothing run as "produced changes" and
    pollute the artifacts being graded. So: restore any stripped file the agent
    left missing (a file the agent recreated is an agent change and is kept),
    then stage the remaining paths explicitly. Never `git add -A` (forbidden in
    this repo, and it would sweep the ablation's own removals into the data)."""
    for rel in removed:
        if not (wt / rel).exists():
            git(["checkout", "--quiet", "--", rel], wt, check=False)
    entries = [e for e in git(["status", "--porcelain", "-z"], wt,
                              check=False).split("\0") if e]
    paths: list[str] = []
    i = 0
    while i < len(entries):
        code, path = entries[i][:2], entries[i][3:]
        paths.append(path)
        if code and code[0] in "RC":
            i += 1                      # rename/copy: the next record is the source path
            if i < len(entries):
                paths.append(entries[i])
        i += 1
    if paths:
        git(["add", "--", *paths], wt, check=False)


# ---------------------------------------------------------------- one run

def build_command(model: str | None, runner: str | None) -> tuple[list[str] | str, bool]:
    """Returns (command, use_shell). The prompt always arrives on stdin, never in
    argv: Windows caps a command line at 32,767 chars and a real probe task plus
    its context blows through that as a misleading 'file not found'."""
    if runner:
        return runner, True
    exe = shutil.which("claude")
    if not exe:
        raise RuntimeError(
            "`claude` is not on PATH. Install Claude Code, or pass --runner with the "
            "headless command for your agent (it must read the prompt on stdin).")
    cmd = [exe, "-p", "--output-format", "json", "--permission-mode", "acceptEdits"]
    if model:
        cmd += ["--model", model]
    return cmd, False


def run_one(root: Path, sha: str, arm: str, index: int, prompt: str,
            targets: list[dict], model: str | None, runner: str | None,
            timeout: int, keep: bool) -> dict:
    """One worktree, one agent session, one diff. Fresh worktree per run so runs
    never compound on each other."""
    tmp = Path(tempfile.mkdtemp(prefix=f"ablate-{arm}-{index}-"))
    wt = tmp / "repo"
    rec: dict = {"arm": arm, "index": index, "removed": [], "ok": False}
    started = time.time()
    try:
        git(["worktree", "add", "--detach", "--quiet", str(wt), sha], root)

        if arm == STRIPPED:
            for t in targets:
                f = wt / t["path"]
                if f.exists():
                    f.unlink()
                    rec["removed"].append(t["path"])
            # Drop directories left empty, so nothing looks half-present.
            for t in sorted({str(Path(t["path"]).parent) for t in targets}, reverse=True):
                d = wt / t
                try:
                    if d.is_dir() and not any(d.iterdir()):
                        d.rmdir()
                except OSError:
                    pass

        cmd, use_shell = build_command(model, runner)
        proc = subprocess.run(
            cmd, cwd=str(wt), input=prompt, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, shell=use_shell)

        rec["exit_code"] = proc.returncode
        rec["stderr_tail"] = (proc.stderr or "")[-600:]
        try:
            payload = json.loads(proc.stdout)
            rec["agent_error"] = bool(payload.get("is_error"))
            rec["result_text"] = str(payload.get("result", ""))[:4000]
            rec["cost_usd"] = payload.get("total_cost_usd")
            rec["num_turns"] = payload.get("num_turns")
            usage = payload.get("usage") or {}
            rec["output_tokens"] = usage.get("output_tokens")
        except (json.JSONDecodeError, TypeError):
            # A non-Claude runner may print plain text. Not fatal: the diff is
            # the measurement, the transcript is only context for grading.
            rec["result_text"] = (proc.stdout or "")[:4000]
            rec["agent_error"] = proc.returncode != 0

        stage_agent_changes(wt, rec["removed"])
        rec["diff"] = git(["diff", "--cached"], wt, check=False)
        rec["files_changed"] = [
            l for l in git(["diff", "--cached", "--name-only"], wt, check=False).splitlines() if l]
        rec["ok"] = not rec.get("agent_error") and bool(rec["diff"].strip())
        if not rec["diff"].strip():
            rec["note"] = "agent produced no file changes"
    except subprocess.TimeoutExpired:
        rec["note"] = f"timed out after {timeout}s"
    except Exception as exc:  # a broken run must not sink the other five
        rec["note"] = f"{type(exc).__name__}: {exc}"
    finally:
        rec["duration_s"] = round(time.time() - started, 1)
        if keep:
            rec["worktree_kept"] = str(wt)
        else:
            subprocess.run(["git", "worktree", "remove", "--force", str(wt)],
                           cwd=str(root), capture_output=True, text=True)
            shutil.rmtree(tmp, ignore_errors=True)
            subprocess.run(["git", "worktree", "prune"], cwd=str(root),
                           capture_output=True, text=True)
    return rec


# ---------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run the control and stripped arms of an AI-layer ablation.")
    ap.add_argument("repo", nargs="?", default=".")
    ap.add_argument("--task-file", required=True,
                    help="file holding the probe-task prompt, reused verbatim by every run")
    ap.add_argument("--runs", type=int, default=2, help="runs PER ARM (default 2)")
    ap.add_argument("--scope", choices=["always", "all"], default="always")
    ap.add_argument("--model", default=None)
    ap.add_argument("--jobs", type=int, default=2, help="concurrent runs (default 2)")
    ap.add_argument("--timeout", type=int, default=1800, help="seconds per run")
    ap.add_argument("--runner", default=None,
                    help="shell command for a non-Claude agent; must read the prompt on stdin")
    ap.add_argument("--out", default=None)
    ap.add_argument("--keep-worktrees", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="print the plan, run nothing")
    args = ap.parse_args()

    try:
        root = repo_root(Path(args.repo).resolve())
    except Exception:
        print(f"Not a git repository: {Path(args.repo).resolve()}", file=sys.stderr)
        print("Ablation needs git: the experiment runs in worktrees.", file=sys.stderr)
        return 2

    prompt = Path(args.task_file).read_text(encoding="utf-8").strip()
    if not prompt:
        print("The task file is empty. The probe task decides whether this experiment "
              "can detect anything; it cannot be blank.", file=sys.stderr)
        return 2

    targets = layer_targets(root, args.scope)
    if not targets:
        print(f"No {args.scope}-scope AI layer artifacts under {root}.")
        print("Nothing to ablate, so there is nothing to test.")
        return 1

    # Every worktree below is created FROM `root`, so every stripped/restored
    # target must be owned by that repository. An artifact inside a nested
    # repo/submodule is recorded in root's tree as a 160000 gitlink: a fresh
    # worktree of root contains only an empty directory there, in BOTH arms,
    # so the file can neither be stripped nor present, and a probe task scoped
    # to that package cannot run at all (a broken experiment, not a finding).
    # The real git boundary is detected per target; nested-owned artifacts are
    # excluded here, and probes that target a nested repo must be re-run with
    # that repo as <repo> so the worktrees are created from the nested
    # repository itself (repo_root already resolves it via rev-parse).
    nested: dict[Path, list[str]] = {}
    own_targets = []
    for t in targets:
        owner = owning_git_root(root, t["path"])
        if owner == root:
            own_targets.append(t)
        else:
            nested.setdefault(owner, []).append(t["path"])
    if nested:
        print("\nNESTED GIT BOUNDARY: these artifacts belong to nested repositories and")
        print("are EXCLUDED (a worktree of this repo cannot contain them in either arm):")
        for owner in sorted(nested):
            for path in nested[owner]:
                print(f"          - {path}  (owned by {owner.relative_to(root).as_posix()})")
        # Print a command that is runnable as-is: this script does not live at
        # the repo root, so name its real path (and the absolute nested-repo
        # path, so the command works from any working directory).
        script = Path(__file__).resolve()
        print("        If the probe task works inside one of those packages, re-run with")
        print(f"        that path as <repo> (e.g. `python {script} "
              f"{sorted(nested)[0]} ...`) so worktrees are")
        print("        created from the nested repository itself.")
    targets = own_targets
    if not targets:
        print(f"\nAll {args.scope}-scope artifacts under {root} belong to nested "
              "repositories. Re-run against the nested repo directly.")
        return 1

    sha = head_sha(root)
    print(f"repo    {root}")
    print(f"base    {sha[:12]}" + ("   (WORKING TREE IS DIRTY: worktrees are built from "
                                   "HEAD, so uncommitted edits are NOT under test)"
                                   if is_dirty(root) else ""))
    print(f"scope   {args.scope} ({len(targets)} files stripped in the stripped arm)")
    for t in targets[:12]:
        print(f"          - {t['path']}")
    if len(targets) > 12:
        print(f"          ... and {len(targets) - 12} more")

    deps = build_dependencies(root, targets)
    if deps:
        print("\nBUILD DEPENDENCY WARNING - this repo's own source reads its AI layer:")
        for d in deps[:5]:
            print(f"          {d}")
        print("        The stripped arm may fail to build. That is a broken experiment,")
        print("        not an agent regression. Consider --scope always.")

    total = args.runs * 2
    print(f"\nplan    {args.runs} control + {args.runs} stripped = {total} agent runs, "
          f"{args.jobs} at a time")
    print(f"        model {args.model or '(session default)'}, timeout {args.timeout}s each")
    print("        your working tree is never touched; every run is a throwaway worktree")
    if args.dry_run:
        print("\n--dry-run: nothing executed.")
        return 0

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    # Results default to a location OUTSIDE the repo: this script promises the
    # user's working tree is never touched, so it must not drop artifacts into
    # the tree or edit the tracked .gitignore. Pass --out to choose a spot
    # (if you point it inside the repo, ignoring it is your setup, not ours).
    out = (Path(args.out) if args.out
           else Path(tempfile.gettempdir()) / "ablate-ai-layer" / f"{root.name}-{stamp}")
    out.mkdir(parents=True, exist_ok=True)

    jobs = [(arm, i) for arm in (CONTROL, STRIPPED) for i in range(1, args.runs + 1)]
    print(f"\nrunning {total} sessions, writing to {out}\n")
    records: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futures = {
            pool.submit(run_one, root, sha, arm, i, prompt, targets,
                        args.model, args.runner, args.timeout, args.keep_worktrees): (arm, i)
            for arm, i in jobs
        }
        for fut in concurrent.futures.as_completed(futures):
            arm, i = futures[fut]
            rec = fut.result()
            records.append(rec)
            mark = "ok " if rec["ok"] else "!! "
            print(f"  {mark} {arm}/{i}  {rec['duration_s']}s  "
                  f"{len(rec.get('files_changed') or [])} files  {rec.get('note', '')}")

    records.sort(key=lambda r: (r["arm"], r["index"]))
    for rec in records:
        if rec.get("diff"):
            (out / f"{rec['arm']}-{rec['index']}.diff").write_text(rec["diff"], encoding="utf-8")

    summary = {
        "repo": str(root), "base_sha": sha, "scope": args.scope,
        "runs_per_arm": args.runs, "model": args.model,
        "prompt": prompt, "stripped_files": [t["path"] for t in targets],
        "build_dependency_warnings": deps,
        "runs": [{k: v for k, v in r.items() if k != "diff"} for r in records],
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out / "task.md").write_text(prompt, encoding="utf-8")

    good = [r for r in records if r["ok"]]
    costs = [r.get("cost_usd") for r in records if isinstance(r.get("cost_usd"), (int, float))]
    print(f"\n{len(good)}/{total} runs produced changes")
    if costs:
        print(f"cost    ${sum(costs):.2f} across {len(costs)} runs")
    print(f"results {out}")

    by_arm = {a: [r for r in good if r["arm"] == a] for a in (CONTROL, STRIPPED)}
    if not by_arm[CONTROL] or not by_arm[STRIPPED]:
        print("\nAt least one arm produced nothing usable. Do not grade this: an empty "
              "arm is a broken experiment, not a finding. Check stderr_tail in "
              "summary.json, then re-run.")
        return 1
    if len(good) < total:
        print("\nSome runs failed. Grade only the arms that completed, and say so in "
              "the report: unequal run counts weaken every comparison drawn from them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
