#!/usr/bin/env python3
"""Generate the merge-state ledger: docs/INTEGRATION-STATE.md + docs/integration-state.json.

Classifies every remote branch by *content*, not ancestry, because master mixes
squash merges with true merges — `git branch --no-merged` reports squash-merged
branches as unmerged forever. Method (per-branch):

  1. touched = union over all merge bases (`git merge-base --all`) of
     `git diff --name-only <base> branch` (what the branch changed relative to
     where it forked; unioning covers criss-cross histories where a triple-dot
     diff would silently pick one base)
  2. If empty -> NO-OP (branch adds nothing).
  3. differing = the unrestricted tip-vs-tip diff `git diff --name-only BASE
     branch` intersected with `touched` (paths are never fed back to Git as
     pathspecs). If empty, every blob the branch touched is byte-identical on
     BASE -> LANDED (typically a squash ghost). Otherwise STRANDED with
     `len(differing)` files still differing.

The ledger is regenerable: run this script after `git fetch --prune origin`
(pruning drops remote-tracking refs for branches already deleted upstream, so
they are not inventoried as actionable) and commit the refreshed outputs. PR
linkage is best-effort via `gh` and degrades to "unknown" when the API is
unavailable.
"""

from __future__ import annotations

import argparse
import json
import os
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


def git_bytes(*args: str) -> bytes:
    result = subprocess.run(["git", *args], capture_output=True, check=True)
    return result.stdout


def list_remote_branches() -> list[tuple[str, str]]:
    """Return ``(origin-prefixed name, tip SHA)`` pairs for every remote branch.

    Tip SHAs are captured in a single atomic ref enumeration so a concurrent
    `git fetch` (IDE, another process) cannot move a ref between the moment a
    branch is inventoried and the moment it is classified.

    Names are derived by stripping the fixed ``refs/remotes/`` prefix from the
    full ``%(refname)`` rather than using ``%(refname:short)``: the short form
    is an *ambiguity-dependent* abbreviation, so a local branch literally named
    ``origin/foo`` makes Git render the remote ref as ``remotes/origin/foo``,
    which would break the HEAD/BASE exclusions and PR linkage.

    Output is captured as bytes with a NUL field delimiter and decoded with
    ``os.fsdecode`` (like :func:`diff_names`): Git accepts ref names whose
    bytes are not valid UTF-8, and a strict text decode would raise
    ``UnicodeDecodeError`` and abort the whole scan before per-branch error
    handling runs. Newline is a safe record delimiter because ref names cannot
    contain ASCII control characters.
    """
    out = git_bytes("for-each-ref", "--format=%(refname)%00%(objectname)", "refs/remotes/origin")
    branches = []
    for line in out.split(b"\n"):
        if not line:
            continue
        ref_bytes, _, sha_bytes = line.partition(b"\0")
        ref = os.fsdecode(ref_bytes).removeprefix("refs/remotes/")
        sha = sha_bytes.decode("ascii")
        if ref == "origin/HEAD" or ref == BASE:
            continue
        branches.append((ref, sha))
    return branches


def fetch_refspec_covers_all_heads() -> bool:
    """Return True when `git fetch origin` updates *all* remote heads.

    A `git clone --single-branch` (or otherwise narrowed) checkout has a
    refspec like ``+refs/heads/master:refs/remotes/origin/master``; the
    documented `git fetch --prune origin` step then only refreshes that one
    branch, and enumerating ``refs/remotes/origin`` would silently produce a
    near-empty ledger that overwrites the checked-in inventory.

    Negative refspecs (``^refs/heads/archive/*``) subtract from every positive
    mapping, so a config can contain the full ``refs/heads/*`` entry and still
    omit part of the head namespace. Any exclusion that can intersect
    ``refs/heads/*`` therefore disqualifies the clone.

    Both sides of the mapping are validated: a refspec like
    ``+refs/heads/*:refs/backup/origin/*`` covers every head but never
    refreshes ``refs/remotes/origin/*``, the namespace
    :func:`list_remote_branches` enumerates — a fresh checkout would generate
    an empty ledger and a checkout with old origin refs would classify stale
    tips. Only the canonical ``refs/heads/*:refs/remotes/origin/*`` mapping is
    accepted; any other destination (or a broader ``refs/*`` source, which
    would land heads at ``refs/remotes/origin/heads/*`` and corrupt branch
    names) does not count as coverage.
    """
    try:
        specs = git("config", "--get-all", "remote.origin.fetch").splitlines()
    except subprocess.CalledProcessError:
        return False
    covered = False
    for spec in specs:
        spec = spec.strip()
        if spec.startswith("^"):
            # A refspec pattern holds at most one "*"; the exclusion can
            # intersect refs/heads/* iff its literal prefix lies inside the
            # heads namespace or is itself a prefix of "refs/heads/".
            prefix = spec[1:].split("*", 1)[0]
            if prefix.startswith("refs/heads/") or "refs/heads/".startswith(prefix):
                return False
            continue
        if spec.removeprefix("+") == "refs/heads/*:refs/remotes/origin/*":
            covered = True
    return covered


def branch_tip_date(sha: str) -> str:
    return git("log", "-1", "--format=%cI", sha).strip()


def diff_names(*args: str) -> list[str]:
    """Run `git diff --name-only -z` and return the changed paths.

    NUL-delimited output bypasses `core.quotePath` display quoting, so paths
    with non-ASCII or special characters come back verbatim and can be reused
    as pathspecs (quoted display strings would silently match nothing).

    Output is captured as bytes and decoded with ``os.fsdecode`` (UTF-8 +
    surrogateescape): a historical filename whose bytes are not valid UTF-8
    cannot raise ``UnicodeDecodeError`` and abort the whole scan, and the
    decoding round-trips losslessly back to the original bytes when the path
    is passed as a subprocess argument (argv encodes via ``os.fsencode``).
    """
    out = git_bytes("diff", "--name-only", "-z", "--no-renames", *args)
    return [os.fsdecode(f) for f in out.split(b"\0") if f]


def classify(branch: str, sha: str, base_sha: str) -> dict:
    # Classification uses only the immutable object IDs (base_sha, sha) frozen
    # at scan start — never the mutable ref names — so a fetch racing this scan
    # cannot mix classifications from different revisions or yield a false
    # LANDED from a branch moving between its two diffs.
    #
    # --no-renames: a rename must surface both sides (old path deleted, new path
    # added) so a deletion that never landed on BASE cannot hide behind rename
    # detection collapsing the pair into the new path only.
    #
    # Merge bases are enumerated explicitly instead of using a triple-dot diff:
    # in a criss-cross history with multiple best merge bases, `BASE...sha`
    # silently picks one of them, and a path whose branch state happens to
    # match that chosen base would be dropped from `touched` — misclassifying
    # the branch as NO-OP/LANDED even though the master tip differs. Unioning
    # the per-base diffs keeps every such path in the tip-vs-tip comparison.
    # `merge-base --all` exits non-zero when no common ancestor exists, which
    # the caller records as ERROR.
    merge_bases = git("merge-base", "--all", base_sha, sha).split()
    touched_set: set[str] = set()
    for mb in merge_bases:
        touched_set.update(diff_names(mb, sha))
    touched = sorted(touched_set)
    entry = {
        "branch": branch.removeprefix("origin/"),
        # The classified tip object ID: a reaper must compare it against the
        # live ref before deleting, so a push racing ledger generation cannot
        # make a stale "safe to delete" verdict destroy new commits.
        "tip_sha": sha,
        "tip_date": branch_tip_date(sha),
        "files_touched": len(touched),
    }
    if not touched:
        entry.update(status="NO-OP", files_differing=0)
        return entry
    # The tip-vs-tip diff is computed unrestricted and intersected with the
    # touched set in Python instead of passing the touched paths back to Git
    # as pathspecs. Pathspec parsing is environment-dependent (with
    # GIT_LITERAL_PATHSPECS=1 a ":(literal)" prefix is treated as part of the
    # filename, emptying the diff and falsely marking every branch LANDED),
    # and expanding thousands of paths into argv can exceed the OS
    # command-line limit (E2BIG) and abort the entire scan.
    differing = [f for f in diff_names(base_sha, sha) if f in touched_set]
    if not differing:
        entry.update(status="LANDED", files_differing=0)
    else:
        entry.update(
            status="STRANDED",
            files_differing=len(differing),
            differing_sample=sorted(differing)[:5],
        )
    return entry


def try_open_prs() -> tuple[dict[str, int], bool]:
    """Map head branch name -> PR number for open same-repo PRs targeting master.

    Returns ``(mapping, available)``. ``available`` is False only when the
    ``gh`` query itself failed or could not be proven complete; an empty
    mapping with ``available=True`` means the query succeeded and there are
    genuinely no open PRs. Cross-repository (fork) PRs are excluded because
    their head branch names are not unique to origin refs. The query is
    filtered to PRs based on master: this ledger tracks integration into
    master, so a PR targeting a release or staging branch is not an
    integration route and must not be attached to a branch here. GitHub
    allows at most one open PR per (head, base) pair, so the filter also
    makes the mapping collision-free.

    The query is pinned with ``--repo`` to the repository backing ``origin``
    (the remote whose refs are inventoried): ambient CLI resolution — a
    ``GH_REPO`` override, or a multi-remote checkout resolving to another
    remote — would otherwise "successfully" return an unrelated repository's
    PRs, hiding real origin PRs behind ``—`` and attaching foreign PR numbers
    to matching head names.

    ``--limit`` truncates silently on success, and an omitted PR would render
    a reapable branch as deletable, so the limit is doubled until the response
    is provably complete (fewer rows than requested); if completeness cannot
    be established the mapping degrades to unavailable rather than wrong.
    """
    try:
        origin_url = git("remote", "get-url", "origin").strip()
        limit = 1000
        while True:
            out = subprocess.run(
                [
                    "gh",
                    "pr",
                    "list",
                    "--repo",
                    origin_url,
                    "--state",
                    "open",
                    "--base",
                    BASE.removeprefix("origin/"),
                    "--limit",
                    str(limit),
                    "--json",
                    "number,headRefName,isCrossRepository",
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=True,
            ).stdout
            rows = json.loads(out)
            if len(rows) < limit:
                break
            if limit >= 16000:
                return {}, False
            limit *= 2
        return (
            {
                row["headRefName"]: row["number"]
                for row in rows
                if not row.get("isCrossRepository")
            },
            True,
        )
    except Exception:
        return {}, False


def md_code(text: str) -> str:
    """Render text as an inline code span safe inside a Markdown table row.

    Git accepts branch names containing `|` and backticks; unescaped, a pipe
    splits the table cell and a backtick terminates the code span. Pipes are
    escaped per GFM table rules, and names containing backticks fall back to a
    `<code>` element with HTML escaping.
    """
    text = text.replace("|", "\\|")
    if "`" in text:
        escaped = (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("`", "&#96;")
        )
        return f"<code>{escaped}</code>"
    return f"`{text}`"


def render_markdown(
    entries: list[dict], base_sha: str, prs: dict[str, int], pr_data_available: bool
) -> str:
    counts = Counter(e["status"] for e in entries)
    stranded = [e for e in entries if e["status"] == "STRANDED"]
    stranded.sort(key=lambda e: (e["files_differing"], e["tip_date"]))
    small_tail = sum(1 for e in stranded if e["files_differing"] <= 2)
    generated = datetime.now(UTC).strftime("%Y-%m-%d")

    def pr_cell(branch: str) -> str:
        pr = prs.get(branch)
        return f"#{pr}" if pr else ("—" if pr_data_available else "unknown")

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
        f"{counts.get('NO-OP', 0)} NO-OP (safe to delete), "
        f"{counts.get('ERROR', 0)} ERROR (classification failed).",
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
        lines.append(
            f"| {md_code(e['branch'])} | {e['files_differing']} "
            f"| {e['tip_date'][:10]} | {pr_cell(e['branch'])} |"
        )
    lines += [
        "",
        "## Reapable branches (content already on master, or no content)",
        "",
        "Do **not** delete a branch that still has an open PR (deleting the",
        "remote branch closes it and discards its review context), and verify",
        "the live ref still points at the classified tip SHA before deleting.",
        "",
        "| Branch | Status | Tip SHA | Tip date | Open PR |",
        "|---|---|---|---|---|",
    ]
    for e in entries:
        if e["status"] in ("LANDED", "NO-OP"):
            lines.append(
                f"| {md_code(e['branch'])} | {e['status']} | `{e['tip_sha'][:12]}` "
                f"| {e['tip_date'][:10]} | {pr_cell(e['branch'])} |"
            )
    errors = [e for e in entries if e["status"] == "ERROR"]
    if errors:
        lines += [
            "",
            "## Errors (classification failed: investigate manually)",
            "",
            "| Branch | Error |",
            "|---|---|",
        ]
        for e in errors:
            err = e.get("error", "").replace("\n", " ").replace("|", "\\|")
            lines.append(f"| {md_code(e['branch'])} | {err} |")
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

    if not fetch_refspec_covers_all_heads():
        print(
            "error: remote.origin.fetch does not map refs/heads/* to\n"
            "refs/remotes/origin/* (single-branch, narrowed, or remapped clone) —\n"
            "`git fetch --prune origin` would not refresh the namespace this script\n"
            "enumerates and the ledger would silently omit remote branches.\n"
            "Fix with:\n"
            "  git config remote.origin.fetch '+refs/heads/*:refs/remotes/origin/*'\n"
            "  git fetch --prune origin",
            file=sys.stderr,
        )
        return 1

    # Freeze the base and every branch tip to immutable object IDs up front;
    # all classification below uses only these SHAs (see classify()).
    base_full_sha = git("rev-parse", BASE).strip()
    base_sha = git("rev-parse", "--short", base_full_sha).strip()
    branches = list_remote_branches()
    print(
        f"classifying {len(branches)} remote branches against {BASE} @ {base_sha}", file=sys.stderr
    )

    entries = []
    for i, (branch, sha) in enumerate(branches, 1):
        try:
            entries.append(classify(branch, sha, base_full_sha))
        except subprocess.CalledProcessError as exc:
            # stderr is bytes when the failing call came through git_bytes().
            stderr = exc.stderr or ""
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")
            # `git merge-base --all` fails with *empty* stderr when the branch
            # shares no ancestor with BASE; synthesize a message so the Errors
            # section never renders a blank cell.
            message = stderr.strip() or (
                f"git {' '.join(map(str, exc.cmd[1:3]))} exited {exc.returncode}"
                " (no merge base with BASE?)"
            )
            entries.append(
                {
                    "branch": branch.removeprefix("origin/"),
                    "status": "ERROR",
                    "error": message[:200],
                    "tip_sha": sha,
                    "tip_date": "",
                    "files_touched": 0,
                    "files_differing": 0,
                }
            )
        if i % 50 == 0:
            print(f"  {i}/{len(branches)}", file=sys.stderr)

    prs, pr_data_available = try_open_prs()
    # Preserve PR linkage in the machine-readable ledger too: with
    # pr_data_available=True, a missing "open_pr" key means no open PR.
    for e in entries:
        pr = prs.get(e["branch"])
        if pr is not None:
            e["open_pr"] = pr

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
    # A ref or file name whose bytes are not valid UTF-8 reaches here as a
    # surrogate-escaped str (os.fsdecode). json.dumps escapes those as \udcXX
    # (round-trips through Python's json.loads); the Markdown write would
    # raise UnicodeEncodeError, so escape them visibly instead of aborting.
    JSON_OUT.write_text(json.dumps(payload, indent=2) + "\n")
    MD_OUT.write_text(
        render_markdown(entries, base_sha, prs, pr_data_available),
        errors="backslashreplace",
    )
    print(f"wrote {MD_OUT} and {JSON_OUT}: {dict(counts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
