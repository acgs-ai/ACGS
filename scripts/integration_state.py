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
import re
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

BASE = "origin/master"
# The base's branch name on the remote (refs/heads/<_BASE_BRANCH>), used when
# the reap instructions must reference the authoritative upstream ref rather
# than the local tracking ref.
_BASE_BRANCH = BASE.removeprefix("origin/")
MD_OUT = Path("docs/INTEGRATION-STATE.md")
JSON_OUT = Path("docs/integration-state.json")


# Both helpers pass --no-replace-objects: replacement refs (refs/replace/*)
# rewrite object lookups by default, so a local overlay would make merge-base
# and diff classify the *replacement* commits instead of the immutable objects
# the remote refs actually point at — e.g. a feature tip locally replaced by an
# empty child of master yields two empty diffs and a false NO-OP even though
# the real tip holds a unique file. Classification must see only the objects
# stored in the remote refs, never local rewrites.
#
# --no-replace-objects does NOT disable the legacy graft overlay
# ($GIT_DIR/info/grafts / $GIT_GRAFT_FILE), which rewrites commit *parents*
# during traversal: grafting a branch tip onto a commit with the same tree
# makes merge-base select that parent, empties the touched-path diff, and
# falsely labels the branch NO-OP. There is no CLI flag to ignore grafts, so
# both helpers pin GIT_GRAFT_FILE to the null device (an empty graft list),
# which also overrides any hostile GIT_GRAFT_FILE already in the environment.
_GIT_ENV = {**os.environ, "GIT_GRAFT_FILE": os.devnull}


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", "--no-replace-objects", *args],
        capture_output=True,
        text=True,
        check=True,
        env=_GIT_ENV,
    )
    return result.stdout


def git_bytes(*args: str) -> bytes:
    result = subprocess.run(
        ["git", "--no-replace-objects", *args], capture_output=True, check=True, env=_GIT_ENV
    )
    return result.stdout


def list_remote_branches() -> tuple[list[tuple[str, str]], list[str]]:
    """Return ``(branches, unexpected_symrefs)`` for the origin namespace.

    ``branches`` holds ``(origin-prefixed name, tip SHA)`` pairs for every
    direct (non-symbolic) remote branch. ``unexpected_symrefs`` lists every
    symbolic ref under ``refs/remotes/origin`` other than ``origin/HEAD``; the
    caller must reject the run when it is non-empty. Only ``origin/HEAD`` is a
    legitimate symbolic tracking ref (maintained by ``git clone`` /
    ``git remote set-head``). Any other symbolic ref — in particular a
    symbolic ``origin/master`` — is silently dereferenced by ``rev-parse``
    (symbolic refs are recursively dereferenced by default), so the base and
    every verdict would be computed against whatever branch the alias points
    at, while the documented ``git fetch --prune origin`` never replaces a
    symbolic destination and the prescribed live SHA rechecks compare the
    same alias. Deleting a branch falsely classified NO-OP against its own
    tip would then lose content absent from the real upstream master.

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

    Symbolic-ness is detected via ``%(symref)``, not the literal name
    ``origin/HEAD``: ``refs/heads/HEAD`` is a valid upstream branch name
    (Git's ref-name rules do not reserve ``HEAD`` below ``refs/heads``), so
    when ``refs/remotes/origin/HEAD`` is a direct ref it is a real fetched
    branch and must be inventoried. The symbolic ref maintained by
    ``git clone``/``git remote set-head`` merely aliases the remote's default
    branch, which is enumerated under its own name.
    """
    out = git_bytes(
        "for-each-ref",
        "--format=%(refname)%00%(objectname)%00%(symref)",
        "refs/remotes/origin",
    )
    branches = []
    unexpected_symrefs = []
    for line in out.split(b"\n"):
        if not line:
            continue
        ref_bytes, sha_bytes, symref_bytes = line.split(b"\0", 2)
        ref = os.fsdecode(ref_bytes).removeprefix("refs/remotes/")
        sha = sha_bytes.decode("ascii")
        if symref_bytes:
            if ref != "origin/HEAD":
                unexpected_symrefs.append(ref)
            continue
        if ref == BASE:
            continue
        branches.append((ref, sha))
    return branches, unexpected_symrefs


def upstream_inventory_mismatches(
    branches: list[tuple[str, str]],
) -> tuple[list[str], bool]:
    """Compare origin's live heads with the local inventory, object ID by object ID.

    Returns ``(mismatches, head_collision)``. ``mismatches`` lists every
    disagreement between the authoritative ``ls-remote --heads`` listing and
    the local inventory (plus the base tracking ref): a head present on only
    one side, or present on both sides at different object IDs. The caller
    must reject the run when it is non-empty.

    Enumerating ``refs/remotes/origin`` cannot prove completeness on its own:
    ``git for-each-ref`` silently omits a symbolic tracking ref whose target
    does not exist, and the documented ``git fetch --prune origin`` leaves
    such a dangling destination unchanged even when the upstream branch
    exists, so the branch would be missing from ``branches`` (and from the
    symref gate, which can only reject symrefs the enumeration reports) and
    the ledger would undercount the remote inventory while claiming every
    remote branch was classified. A fetch that simply predates a newly pushed
    branch has the same signature.

    Matching by name alone is not enough either: an upstream branch
    force-pushed after the last fetch keeps its name while a stale local tip
    would be classified, and a base deleted upstream leaves the stale local
    tracking ref silently standing in for a branch that no longer exists —
    every verdict would then be computed against a base origin does not
    hold. Every upstream head must therefore agree with the inventory on its
    exact object ID, the base branch must itself exist upstream, and a local
    tracking ref with no upstream counterpart (a deletion the documented
    fetch would have pruned) is rejected too.

    ``head_collision`` is True when origin has a branch literally named
    ``HEAD`` (``refs/heads/HEAD`` is accepted by Git) that is absent from
    the local inventory: its canonical fetch destination
    ``refs/remotes/origin/HEAD`` collides with the symbolic ref maintained
    by ``git clone``/``git remote set-head``, and when the symbolic ref wins
    the collision the real branch can never be materialized locally. The
    caller distinguishes that case with a dedicated error message because
    refetching cannot fix it.

    Output is captured as bytes and decoded with ``os.fsdecode`` like the
    local ref enumeration: upstream ref names need not be valid UTF-8.
    """
    out = git_bytes("ls-remote", "--heads", "origin")
    upstream: dict[str, str] = {}
    for line in out.split(b"\n"):
        sha, _, ref = line.partition(b"\t")
        if ref.startswith(b"refs/heads/"):
            upstream[os.fsdecode(ref.removeprefix(b"refs/heads/"))] = sha.decode("ascii")
    local = {ref.removeprefix("origin/"): sha for ref, sha in branches}
    # The base is excluded from ``branches`` by design but its
    # verdict-defining object ID must agree with upstream like every other
    # head; origin/HEAD (when direct) is inventoried under its own name.
    # rev-parse cannot be tricked into following a symbolic alias here: the
    # caller runs the symref gate before this check.
    try:
        local[_BASE_BRANCH] = git("rev-parse", "--verify", f"refs/remotes/{BASE}").strip()
    except subprocess.CalledProcessError:
        pass  # absent locally: surfaces against the upstream listing below
    mismatches = []
    for name in sorted(upstream.keys() | local.keys()):
        upstream_sha = upstream.get(name)
        local_sha = local.get(name)
        if upstream_sha == local_sha:
            continue
        if local_sha is None:
            mismatches.append(f"refs/heads/{name}: on origin at {upstream_sha}, absent locally")
        elif upstream_sha is None:
            mismatches.append(f"refs/heads/{name}: inventoried at {local_sha}, absent on origin")
        else:
            mismatches.append(
                f"refs/heads/{name}: on origin at {upstream_sha}, inventoried at {local_sha}"
            )
    if _BASE_BRANCH not in upstream:
        mismatches.append(
            f"refs/heads/{_BASE_BRANCH}: the base branch does not exist on origin"
        )
    head_collision = "HEAD" in upstream and "HEAD" not in local
    return mismatches, head_collision


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
    tips. Only the *forced* canonical mapping
    ``+refs/heads/*:refs/remotes/origin/*`` is accepted: per the refspec
    rules the optional leading ``+`` is what permits a ref update that is not
    a fast-forward, so without it a force-pushed upstream branch leaves its
    tracking ref stale after the documented fetch and the ledger classifies
    an outdated tip as deletable. Any other destination (or a broader
    ``refs/*`` source, which would land heads at
    ``refs/remotes/origin/heads/*`` and corrupt branch names) does not count
    as coverage.

    Additional mappings whose destination lands inside
    ``refs/remotes/origin/*`` (e.g. ``+refs/pull/*/head:refs/remotes/origin/pr/*``)
    also disqualify the clone: they populate the scanned namespace with refs
    that are not remote heads, so ``origin/pr/123`` would be inventoried as a
    real branch and — if classified reapable — the ledger would recommend
    deleting a nonexistent or unrelated ``refs/heads/pr/123``. A refspec with
    no destination only writes ``FETCH_HEAD`` and cannot pollute the
    namespace.
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
        # The leading "+" is required, not optional: without it, git fetch
        # refuses non-fast-forward updates, so a force-pushed upstream branch
        # leaves its tracking ref stale. Classifying that stale tip can mark
        # the branch NO-OP/LANDED (and the local SHA recheck still passes)
        # while the real upstream tip holds unique commits — deleting the
        # branch would discard them. Only the forced canonical mapping counts
        # as coverage; the unforced variant falls through to the destination
        # check below and disqualifies the clone.
        if spec == "+refs/heads/*:refs/remotes/origin/*":
            covered = True
            continue
        # Any other mapping into refs/remotes/origin/* fills the scanned
        # namespace with non-head refs (see docstring). A refspec pattern
        # holds at most one "*"; the destination can intersect the namespace
        # iff its literal prefix lies inside it or is itself a prefix of
        # "refs/remotes/origin/".
        _, _, dst = spec.removeprefix("+").partition(":")
        if not dst:
            continue
        dst_prefix = dst.split("*", 1)[0]
        if dst_prefix.startswith("refs/remotes/origin/") or "refs/remotes/origin/".startswith(
            dst_prefix
        ):
            return False
    return covered


def divergent_push_urls() -> list[str]:
    """Return every push URL of ``origin`` that differs from its fetch URL.

    ``git push origin`` targets ``remote.origin.pushurl`` when configured
    (every configured value, so several push URLs push to several
    repositories), while this script's ref inventory, base resolution, and
    PR snapshot are all served by the fetch URL, and the rendered reap
    chain's ``git ls-remote origin`` and pinned ``gh`` query inspect the
    fetch URL too. With a divergent push URL the chain's final ``git push``
    would delete refs in a repository whose branches, base, and PRs were
    never inspected; a matching tip lease there proves nothing, because the
    lease only pins that repository's ref, not the provenance of the
    verdict. Only a configuration whose every push target equals the fetch
    URL is accepted.

    With no pushurl configured, ``get-url --push --all`` falls back to the
    fetch URL(s), so a default single-URL remote returns an empty list. A
    second ``remote.origin.url`` entry is reported as divergent as well:
    ``git fetch`` reads only the first URL, but ``git push`` targets all of
    them.
    """
    try:
        fetch_url = git("remote", "get-url", "origin").strip()
        push_urls = git("remote", "get-url", "--push", "--all", "origin").splitlines()
    except subprocess.CalledProcessError:
        return ["<unresolvable remote.origin URL>"]
    return [url for url in (u.strip() for u in push_urls) if url and url != fetch_url]


def origin_transport_overrides() -> list[str]:
    """Return origin transport configuration that would subvert or break the reap.

    ``remote.origin.receivepack`` replaces the receive-pack program ``git
    push`` runs on the remote side (see ``git push --receive-pack``), and
    the replacement can hand the push a different repository entirely:
    every URL comparison, ``ls-remote``, selector, and PR check keeps
    inspecting the configured origin URL while the override delivers the
    ref updates somewhere else, so the rendered chain's prechecks would
    prove nothing about the repository actually modified. The rendered
    pushes pin the default program with the command-line option
    ``--receive-pack=git-receive-pack``, which takes precedence over the
    config (a ``-c`` value would not: the key is multi-valued and ``git
    push`` uses the *first* configured value, so the checkout's override
    would still win), and generation additionally refuses to render reap
    instructions from a checkout carrying the override (nothing
    legitimate configures it here).

    ``remote.origin.uploadpack`` is the *read-side* twin: it replaces the
    upload-pack program that serves every fetch and ``ls-remote`` from
    origin (see ``git fetch --upload-pack``), so a wrapper serving another
    repository makes the documented ``git fetch --prune origin``, the
    generation-time ``ls-remote`` completeness gate, and the rendered
    chain's live base check all read repository B while the URL-derived
    selector and the pinned receive-pack still target repository A: a
    branch whose content landed only on B's master would be classified
    LANDED here and then deleted from A, and the archive-tag cleanup could
    later remove its last remaining ref. Generation refuses to run with
    the override set (this gate runs before the first ``ls-remote``; a
    fetch that already populated the inventory from B while the override
    was configured is caught by the exact-object-ID upstream comparison
    once the override is removed), and the rendered chain's ``ls-remote``
    pins ``--upload-pack=git-upload-pack`` so an override configured after
    generation cannot redirect the live base check either.

    ``remote.origin.mirror=true`` makes every ``git push origin`` behave
    as ``git push --mirror``, which cannot be combined with explicit
    refspecs: the rendered chain would pass every precheck and then die
    with ``fatal: --mirror can't be combined with refspecs``, so operators
    could never actually reap a listed branch (and a refspec-less push
    from such a checkout would force-sync *all* refs). The rendered
    pushes clear it with ``-c remote.origin.mirror=false`` and generation
    rejects the configuration outright.

    An unparseable ``remote.origin.mirror`` value is reported as an
    override too: ``git push`` would die on it anyway, so failing closed
    at generation time gives the operator one clear fix.
    """
    overrides = []
    for key in ("remote.origin.receivepack", "remote.origin.uploadpack"):
        try:
            value = git("config", "--get", key).strip()
        except subprocess.CalledProcessError:
            value = ""
        if value:
            overrides.append(f"{key}={value}")
    try:
        mirror = git("config", "--get", "--type=bool", "remote.origin.mirror").strip()
    except subprocess.CalledProcessError as exc:
        # Exit code 1 means the key is unset; anything else (e.g. an
        # unparseable boolean value) is itself a broken override.
        mirror = "false" if exc.returncode == 1 else "true"
    if mirror == "true":
        overrides.append("remote.origin.mirror=true")
    return overrides


def branch_tip_date(sha: str) -> str:
    # --no-show-signature: log.showSignature=true is equivalent to adding
    # --show-signature, which prepends signature status to stdout even with
    # --format=%cI — corrupting the JSON timestamp, the Markdown tip-date
    # column, and stranded-branch sorting.
    return git("log", "-1", "--no-show-signature", "--format=%cI", sha).strip()


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

    ``--ignore-submodules=none`` forces gitlink (mode 160000) changes into the
    output: ``diff.ignoreSubmodules=all`` in the checkout's config would
    otherwise silently drop them, so a branch whose only change is a unique
    submodule-pointer update would come back empty and be advertised as a
    deletable NO-OP in this submodule-heavy monorepo.
    """
    out = git_bytes("diff", "--name-only", "-z", "--no-renames", "--ignore-submodules=none", *args)
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


def repo_selector_from_origin_url(url: str) -> str | None:
    """Derive gh's credential-free ``HOST/OWNER/REPO`` selector from a remote URL.

    ``gh --repo`` also accepts a full URL, but forwarding the output of
    ``git remote get-url origin`` verbatim would place any credentials
    embedded in an HTTPS remote (``https://user:token@host/...``) into the
    ``gh`` process argv, where every local user can read them from the
    process table even when the Git configuration file itself is private.
    Only the host and the two-segment path are kept, so no userinfo can
    survive into the selector.

    A non-default port in a URL-form remote (``https://host:8443/owner/repo``,
    typical for self-hosted GitHub Enterprise) is preserved: ``gh``'s
    ``[HOST/]OWNER/REPO`` selector accepts and honors a port supplied in
    ``HOST``, while discarding it would query the default-port service on the
    same hostname — potentially a *different* GitHub instance — so the PR
    checks could report "no open PRs" for a repository other than the one Git
    fetches from and deletes on. scp-like remotes carry no port (ssh with an
    explicit port must use the ``ssh://host:port/`` URL form, matched above).

    The result is additionally restricted to hostname/repository characters
    plus an optional decimal ``:port`` after the host: the selector is
    rendered into the ledger's copy-paste reap instructions inside a
    double-quoted shell word, where an unvalidated value smuggled through a
    hostile origin URL (e.g. a ``$(...)`` path segment) would otherwise
    execute in the operator's shell.

    Returns ``None`` when the URL does not name a host plus exactly
    ``owner/repo`` (e.g. a local filesystem path), so callers degrade to
    ``pr_data_available=False`` instead of querying a guessed repository.
    """
    m = re.match(
        # scheme://[userinfo@]host[:port]/path
        r"^[A-Za-z][A-Za-z0-9+.-]*://(?:[^/@]*@)?(?P<host>[^/:@]+)(?P<port>:\d+)?/(?P<path>.+)$",
        url,
    ) or re.match(
        # scp-like syntax: [user@]host:path
        r"^(?:[^/@]+@)?(?P<host>[^/:@]+):(?P<path>[^/:].*)$",
        url,
    )
    if m is None:
        return None
    path = m.group("path").rstrip("/").removesuffix(".git")
    port = m.groupdict().get("port") or ""
    selector = f"{m.group('host')}{port}/{path}"
    if re.fullmatch(r"[A-Za-z0-9.-]+(?::\d+)?(?:/[A-Za-z0-9._-]+){2}", selector) is None:
        return None
    return selector


def try_open_prs(repo_selector: str | None) -> tuple[dict[str, int], bool]:
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
    to matching head names. The pin is the credential-free ``HOST/OWNER/REPO``
    selector derived by :func:`repo_selector_from_origin_url` rather than the
    raw origin URL, which may embed credentials that must not appear in argv;
    a ``None`` selector (unparseable origin) degrades to unavailable.

    ``--limit`` truncates silently on success, and an omitted PR would render
    a reapable branch as deletable, so the limit is doubled until the response
    is provably complete (fewer rows than requested); if completeness cannot
    be established the mapping degrades to unavailable rather than wrong.
    """
    if repo_selector is None:
        return {}, False
    try:
        limit = 1000
        while True:
            out = subprocess.run(
                [
                    "gh",
                    "pr",
                    "list",
                    "--repo",
                    repo_selector,
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
    entries: list[dict],
    base_sha: str,
    base_full_sha: str,
    repo_selector: str | None,
    prs: dict[str, int],
    pr_data_available: bool,
) -> str:
    # The reap instructions embed the selector inside a double-quoted shell
    # word; repo_selector_from_origin_url() already restricted it to
    # hostname/repository characters, so it cannot break out of the quotes.
    selector_arg = repo_selector if repo_selector is not None else "<HOST>/<OWNER>/<REPO>"
    # The GraphQL head-PR check needs the selector's components separately:
    # `gh api graphql` takes the host via --hostname and the repository via
    # query variables. The same character restriction applies to each part.
    if repo_selector is not None:
        selector_host, _, selector_path = repo_selector.partition("/")
        selector_owner, _, selector_repo = selector_path.partition("/")
    else:
        selector_host, selector_owner, selector_repo = "<HOST>", "<OWNER>", "<REPO>"
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
        "remote branch closes it and discards its review context). The Open",
        "PR column is a snapshot from generation time, a PR can be opened",
        "afterwards without moving any ref, and local tracking refs go stale",
        "the moment another checkout pushes (they only move on a successful",
        "fetch), so a check-then-delete against local refs can pass and still",
        "destroy fresh commits. Immediately before deleting, run **all",
        "six** checks:",
        "",
        "1. the ledger itself records the pasted branch/tip pair as",
        "   reapable: `--assert-reapable` requires an exact branch and",
        "   full-tip match in `integration-state.json` with a `LANDED` or",
        "   `NO-OP` verdict, and requires the ledger's base to equal the",
        "   base this chain pins (so instructions and data from different",
        "   generations cannot be mixed). Nothing else in the chain reads",
        "   the ledger, so without this check a STRANDED branch pasted with",
        "   its correct tip would pass every remote-side comparison below",
        "   and be deleted while the ledger explicitly says its content",
        "   never landed;",
        "2. `git push origin` targets exactly the repository the other",
        "   checks inspect: `git remote get-url --push --all origin` must",
        "   print exactly the fetch URL. A configured `remote.origin.pushurl`",
        "   (possibly several) makes the push modify repositories other than",
        "   the one answering the `ls-remote` and PR queries, so a matching",
        "   lease there proves nothing about the repository actually being",
        "   modified;",
        "3. the live `origin` still names the repository this ledger",
        "   inventoried. The SHA checks below compare content, not identity:",
        "   a `remote.origin.url` rewritten after generation — commonly to a",
        "   fork holding identical branch and base SHAs — passes every SHA",
        "   comparison while the PR selector baked in at generation time",
        "   still queries the *old* repository, so a branch with an active",
        "   PR in the new origin would be deleted and its review context",
        "   discarded. The selector is re-derived from the live fetch URL",
        "   (`scripts/integration_state.py --print-selector`) and must equal",
        "   the recorded one;",
        "4. an authoritative `git ls-remote` lookup (never the local",
        f"   tracking ref) shows the remote `{_BASE_BRANCH}` still at the",
        "   classified base, compared as the **full** object ID (a later",
        "   commit can share an abbreviated prefix). The lookup pins",
        "   `--upload-pack=git-upload-pack`: a configured",
        "   `remote.origin.uploadpack` replaces the program serving every",
        "   read from origin, so a wrapper serving another repository would",
        "   answer this check (and any refetch) with that repository's refs",
        "   while the pinned receive-pack still delivers the deletion to the",
        "   real origin; the command-line option overrides the config",
        "   (generation additionally rejects checkouts carrying the",
        "   override):",
        "",
        f"   `{base_full_sha}`",
        "",
        "   These verdicts are only valid against that exact base, and if",
        "   master has moved (e.g. a revert removed content that made a",
        "   branch LANDED) a listed branch may now be the last ref holding",
        "   its content;",
        "5. live PR queries report no open PR using the branch as *head*",
        "   and none using it as *base*. The head check must see PRs in",
        "   *other* repositories too: when `origin` is a fork, an open PR",
        "   into an upstream repository has this branch as its head but",
        "   belongs to that base repository, so a `gh pr list` pinned to",
        "   origin returns empty and the deletion would close the active",
        "   PR. The chain therefore asks GraphQL for the ref's associated",
        "   open pull requests (cross-repository ones included, since the",
        "   head ref lives in origin) and requires the count to render",
        "   exactly `0`; a failed query exits non-zero, and a missing ref",
        "   or repository renders nothing rather than `0`, so the chain",
        "   stops whenever the check cannot be completed. A PR using the",
        "   branch as *base* necessarily lives",
        "   in origin itself, so the base check stays a `gh pr list`",
        "   pinned to origin. Both queries use the credential-free",
        "   `HOST/OWNER/REPO` selector of the repository backing `origin`",
        "   (an ambient `GH_REPO` override would silently query another",
        "   repository, and forwarding the raw origin URL would expose",
        "   credentials embedded in an HTTPS remote to the process table",
        "   via argv). A stacked PR that targets the branch keeps it an",
        "   active review base even when the branch has no PR of its own,",
        "   and deleting it would retarget or invalidate the child PR's",
        "   comparison and review context, so both checks must come back",
        "   empty. The branch is passed as one quoted argument (ref names",
        "   may legally contain `;` or `$()`, which an unquoted",
        "   substitution would execute);",
        "6. the deletion pushes with `--atomic`, an expected-value lease on",
        "   the branch ref (`--force-with-lease=<refname>:<expect>` makes",
        "   the server reject the deletion unless the ref still equals",
        "   `<expect>`), an archival tag `refs/tags/reaped/<branch>`",
        "   pointing at the classified tip, created in the same transaction,",
        "   `--no-follow-tags` (`push.followTags=true` would otherwise",
        "   implicitly add every missing annotated tag reachable from the",
        "   pushed tip, publishing unrelated local tags, e.g. a private",
        "   release tag, to origin as a side effect of the reap),",
        "   `--recurse-submodules=no` (`push.recurseSubmodules=on-demand`",
        "   in the checkout's config would otherwise first push changed",
        "   nested submodules to their own remotes, side effects outside",
        "   the atomic transaction that persist even when the branch-tip",
        "   lease then rejects the reap), `-c push.pushOption=`",
        "   (configured `push.pushOption` values are transmitted to the",
        "   server even when none appear on the command line, and",
        "   server-specific options can trigger pre-receive behavior",
        "   beyond the two advertised ref updates; the empty value clears",
        "   the configured list),",
        "   `--receive-pack=git-receive-pack` (a configured",
        "   `remote.origin.receivepack` replaces the receive-pack program",
        "   the push runs on the remote side and can hand the ref updates",
        "   to a different repository entirely, while every URL,",
        "   `ls-remote`, selector, and PR check keeps inspecting the",
        "   configured origin URL; the command-line option pins the",
        "   default program and takes precedence over the config, which",
        "   a `-c` value would not: the key is multi-valued and the push",
        "   uses the *first* configured value), and",
        "   `-c remote.origin.mirror=false` (`remote.origin.mirror=true`",
        "   silently turns the push into a full-mirror update, which",
        "   cannot be combined with explicit refspecs, so the command",
        "   would die with `--mirror can't be combined with refspecs`),",
        "   so the transaction is pinned to exactly",
        "   the two refspecs listed. The tag's source is a per-operation",
        "   temporary ref `refs/reap/src-<tip>`, bound to the recorded",
        "   tip and verified before the push: a refspec source undergoes",
        "   ref-name resolution before object-ID interpretation, so a",
        "   local ref whose short name is exactly the tip SHA would",
        "   silently make the archival tag point at a different object",
        "   while the branch is still deleted. The name is keyed by the",
        "   tip so concurrent reap chains in the same checkout never",
        "   share a scratch ref (a shared name could be rewritten by a",
        "   second chain between this chain's verification and its push,",
        "   archiving the wrong object while the branch lease still",
        "   passes; two chains reaping the same tip write the identical",
        "   value). The ref is written and deleted with `--no-deref`:",
        "   without it, a pre-existing symbolic ref at that name would",
        "   be followed, silently moving and then deleting whatever",
        "   local branch it targets instead of the scratch ref itself.",
        "   A lease can only guard a ref the transaction actually updates:",
        "   Git drops an already-up-to-date refspec from the push before",
        "   leases are evaluated, so a no-op base refspec cannot detect a",
        f"   `{_BASE_BRANCH}` reverted or force-pushed after the `ls-remote`",
        "   check. The atomic tag makes that residual race non-destructive",
        "   instead: whatever happens to the base, the deleted branch's",
        "   content stays reachable under the tag. Delete the tag only",
        f"   after confirming the live `{_BASE_BRANCH}` still holds the",
        "   content, and only with a lease pinning the remote tag to the",
        "   archived tip:",
        "",
        "   ```sh",
        "   git -c remote.origin.mirror=false push \\",
        "     --receive-pack=git-receive-pack \\",
        '     --force-with-lease="refs/tags/reaped/$branch:$tip" \\',
        '     origin ":refs/tags/reaped/$branch"',
        "   ```",
        "",
        "   An unleased deletion would unconditionally discard a tag",
        "   moved meanwhile by a concurrent archival or forced retag,",
        "   losing content unrelated to this completed reap. Never use a",
        "   bare `git push origin --delete`, which deletes",
        "   unconditionally.",
        "",
        "The commands form one `&&` chain because a found PR is successful",
        "output, not a failing exit status: the head-PR count is captured",
        "and required to render exactly `0`, the base-PR list is captured",
        "and required to be empty, the push targets, the ledger verdict,",
        "and the live base SHA are checked explicitly, and any failed",
        "lookup or check stops the chain before the push runs:",
        "",
        "```sh",
        "IFS= read -r branch   # paste the branch name, press Enter",
        "IFS= read -r tip      # paste the branch's full tip SHA",
        "                      # (tip_sha in integration-state.json)",
        f"base={base_full_sha} &&",
        "python3 scripts/integration_state.py \\",
        '  --assert-reapable "$branch" "$tip" "$base" &&',
        '[ "$(git remote get-url --push --all origin)" \\',
        '  = "$(git remote get-url origin)" ] &&',
        '[ "$(python3 scripts/integration_state.py --print-selector)" \\',
        f'  = "{selector_arg}" ] &&',
        '[ "$(git ls-remote --upload-pack=git-upload-pack origin \\',
        f'  refs/heads/{_BASE_BRANCH} | cut -f1)" = "$base" ] &&',
        f'head_prs=$(gh api graphql --hostname "{selector_host}" \\',
        f'  -f owner="{selector_owner}" -f name="{selector_repo}" \\',
        '  -f ref="refs/heads/$branch" \\',
        "  -f query='query($owner:String!,$name:String!,$ref:String!){",
        "    repository(owner:$owner,name:$name){ref(qualifiedName:$ref){",
        "    associatedPullRequests(states:OPEN,first:1){totalCount}}}}' \\",
        "  --jq '.data.repository.ref.associatedPullRequests.totalCount') &&",
        '[ "$head_prs" = "0" ] &&',
        f'base_prs=$(gh pr list --repo "{selector_arg}" --state open \\',
        "  --base \"$branch\" --json number --jq '.[].number') &&",
        '[ -z "$base_prs" ] &&',
        'git update-ref --no-deref "refs/reap/src-$tip" "$tip" &&',
        '[ "$(git rev-parse --verify "refs/reap/src-$tip")" = "$tip" ] &&',
        "git -c push.pushOption= -c remote.origin.mirror=false push --atomic \\",
        "  --no-follow-tags --receive-pack=git-receive-pack \\",
        "  --recurse-submodules=no \\",
        '  --force-with-lease="refs/heads/$branch:$tip" \\',
        '  origin "refs/reap/src-$tip:refs/tags/reaped/$branch" ":refs/heads/$branch" &&',
        'git update-ref --no-deref -d "refs/reap/src-$tip"',
        "```",
        "",
        "If the chain stops early, or the push is rejected (a moved tip,",
        "or a pre-existing `reaped/<branch>` tag at a different commit),",
        "regenerate and reclassify first.",
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
    parser.add_argument(
        "--print-selector",
        action="store_true",
        help="print gh's HOST/OWNER/REPO selector derived from the live"
        " remote.origin.url and exit (the rendered reap chain compares it"
        " against the selector recorded at generation time, so an origin"
        " repointed at another repository — e.g. a fork with identical"
        " SHAs — stops the chain instead of deleting uninspected branches)",
    )
    parser.add_argument(
        "--assert-reapable",
        nargs=3,
        metavar=("BRANCH", "TIP", "BASE"),
        help="exit 0 only when docs/integration-state.json was generated against"
        " exactly the full base object ID BASE and records BRANCH at exactly the"
        " full tip object ID TIP with a LANDED or NO-OP verdict (the rendered"
        " reap chain runs this before any ref update: every other check can pass"
        " for a mispasted STRANDED branch, whose deletion would discard unlanded"
        " content)",
    )
    args = parser.parse_args()
    if args.check:
        ok = MD_OUT.exists() and JSON_OUT.exists()
        print(f"ledger present: {ok}")
        return 0 if ok else 1
    if args.print_selector:
        try:
            url = git("remote", "get-url", "origin").strip()
        except subprocess.CalledProcessError:
            print("error: cannot resolve remote.origin.url", file=sys.stderr)
            return 1
        selector = repo_selector_from_origin_url(url)
        if selector is None:
            print(
                "error: remote.origin.url does not parse to HOST/OWNER/REPO",
                file=sys.stderr,
            )
            return 1
        print(selector)
        return 0
    if args.assert_reapable:
        branch, tip, base = args.assert_reapable
        try:
            payload = json.loads(JSON_OUT.read_text())
        except (OSError, ValueError) as exc:
            print(f"error: cannot read {JSON_OUT}: {exc}", file=sys.stderr)
            return 1
        # The verdicts in the ledger are only meaningful against the base they
        # were computed from; requiring the caller's base to match binds the
        # pasted chain (which pins its own base literal) to the checked-in
        # ledger, so instructions and data from different generations cannot
        # be mixed.
        ledger_base = payload.get("base_full_sha")
        if ledger_base != base:
            print(
                f"error: {JSON_OUT} was generated against base {ledger_base},"
                f" not {base}; regenerate and use the matching instructions",
                file=sys.stderr,
            )
            return 1
        entry = next(
            (e for e in payload.get("branches", []) if e.get("branch") == branch),
            None,
        )
        if entry is None:
            print(f"error: branch {branch!r} is not in {JSON_OUT}", file=sys.stderr)
            return 1
        if entry.get("tip_sha") != tip:
            print(
                f"error: {JSON_OUT} records {branch!r} at tip"
                f" {entry.get('tip_sha')}, not {tip}",
                file=sys.stderr,
            )
            return 1
        if entry.get("status") not in ("LANDED", "NO-OP"):
            print(
                f"error: {JSON_OUT} records {branch!r} as {entry.get('status')},"
                " not LANDED or NO-OP; refusing to treat it as reapable",
                file=sys.stderr,
            )
            return 1
        print(f"reapable: {branch} @ {tip} ({entry['status']})")
        return 0

    if not fetch_refspec_covers_all_heads():
        print(
            "error: remote.origin.fetch does not force-map refs/heads/* to\n"
            "refs/remotes/origin/* (single-branch, narrowed, remapped, or unforced\n"
            "clone), or maps extra refs (e.g. refs/pull/*) into refs/remotes/origin/*\n"
            "— `git fetch --prune origin` would not refresh exactly the namespace this\n"
            "script enumerates (an unforced mapping leaves force-pushed branches\n"
            "stale) and the ledger would omit, invent, or misclassify remote branches.\n"
            "Fix with:\n"
            "  git config --unset-all remote.origin.fetch\n"
            "  git config remote.origin.fetch '+refs/heads/*:refs/remotes/origin/*'\n"
            "  git fetch --prune origin",
            file=sys.stderr,
        )
        return 1

    divergent = divergent_push_urls()
    if divergent:
        listing = "\n".join(f"  {url}" for url in divergent)
        print(
            "error: push URL(s) of origin differ from its fetch URL:\n"
            f"{listing}\n"
            "`git push origin` targets every push URL, while this ledger's ref\n"
            "inventory, base, and PR snapshot (and the rendered reap chain's\n"
            "`ls-remote`/`gh` checks) inspect only the fetch URL, so the reap\n"
            "instructions could delete refs in a repository that was never\n"
            "inspected. Fix with:\n"
            "  git config --unset-all remote.origin.pushurl\n"
            "(and keep a single remote.origin.url), then regenerate.",
            file=sys.stderr,
        )
        return 1

    transport_overrides = origin_transport_overrides()
    if transport_overrides:
        listing = "\n".join(f"  {o}" for o in transport_overrides)
        print(
            "error: origin transport configuration would subvert or break the reap:\n"
            f"{listing}\n"
            "remote.origin.receivepack replaces the receive-pack program `git push`\n"
            "runs on the remote side and can deliver the ref updates to a repository\n"
            "other than the one this ledger's ls-remote/selector/PR checks inspect;\n"
            "remote.origin.uploadpack replaces the upload-pack program serving every\n"
            "fetch and ls-remote, so classification and the live base check could\n"
            "read a repository other than the one the push modifies;\n"
            "remote.origin.mirror=true turns every push into a full-mirror update,\n"
            "which cannot be combined with the reap chain's explicit refspecs. Fix\n"
            "with (whichever applies):\n"
            "  git config --unset-all remote.origin.receivepack\n"
            "  git config --unset-all remote.origin.uploadpack\n"
            "  git config --unset-all remote.origin.mirror\n"
            "then regenerate.",
            file=sys.stderr,
        )
        return 1

    # A shallow clone (even --no-single-branch, which passes the refspec gate
    # above) has every remote tip but not their shared ancestors, so
    # `merge-base --all` finds no merge base and connected branches are all
    # written as ERROR — silently overwriting a valid ledger with an
    # error-heavy one. Refuse to classify until history is complete.
    if git("rev-parse", "--is-shallow-repository").strip() == "true":
        print(
            "error: this repository is shallow — merge-base classification needs\n"
            "complete history or every connected branch degrades to ERROR.\n"
            "Fix with:\n"
            "  git fetch --unshallow origin\n"
            "  git fetch --prune origin",
            file=sys.stderr,
        )
        return 1

    # Enumerate the namespace (and detect symbolic refs) *before* resolving
    # the base: rev-parse recursively dereferences symbolic refs, so a
    # symbolic refs/remotes/origin/master aliased to another tracking ref
    # would silently resolve to that branch's tip, classify the branch as
    # NO-OP against itself, and pass the prescribed live SHA rechecks (which
    # compare the same alias) — while `git fetch --prune origin` never
    # replaces a symbolic destination. The same applies to any other
    # unexpected symbolic tracking ref, so all of them are rejected here.
    branches, unexpected_symrefs = list_remote_branches()
    if unexpected_symrefs:
        listing = "\n".join(f"  refs/remotes/{ref}" for ref in unexpected_symrefs)
        print(
            "error: symbolic ref(s) under refs/remotes/origin other than\n"
            f"origin/HEAD:\n{listing}\n"
            "A symbolic tracking ref is recursively dereferenced, so the base and\n"
            "every verdict would be computed against whatever branch the alias\n"
            "points at, and `git fetch --prune origin` does not replace a symbolic\n"
            "destination. Delete each one and refetch, e.g.:\n"
            "  git symbolic-ref --delete refs/remotes/<name>\n"
            "  git fetch --prune origin",
            file=sys.stderr,
        )
        return 1

    # The symref gate above can only reject symbolic refs the enumeration
    # reports; a symbolic tracking ref whose target is missing is omitted by
    # for-each-ref entirely, and `git fetch --prune origin` leaves such a
    # dangling destination unchanged, so the branch it shadows would silently
    # vanish from the inventory. Name matching alone is not enough either: a
    # branch force-pushed (or the base deleted) upstream after the last fetch
    # keeps its name while the ledger would classify stale or nonexistent
    # objects. Require exact name-to-object-ID agreement between the
    # authoritative upstream heads and the inventory before claiming
    # completeness.
    mismatches, head_collision = upstream_inventory_mismatches(branches)
    if head_collision:
        print(
            "error: the remote has a branch literally named HEAD (refs/heads/HEAD)\n"
            "whose fetch destination collides with the symbolic refs/remotes/origin/HEAD,\n"
            "so it cannot be inventoried and the ledger would silently omit it.\n"
            "Rename or delete the upstream branch, e.g.:\n"
            "  git push origin refs/heads/HEAD:refs/heads/renamed-head\n"
            "  git push origin :refs/heads/HEAD",
            file=sys.stderr,
        )
        return 1
    if mismatches:
        listing = "\n".join(f"  {m}" for m in mismatches)
        print(
            "error: origin's live heads disagree with the local inventory:\n"
            f"{listing}\n"
            "A stale fetch (a branch pushed, force-pushed, or deleted upstream —\n"
            "including the base) or a dangling symbolic tracking ref would make\n"
            "the ledger classify objects other than what origin actually holds.\n"
            "Delete any dangling symbolic tracking ref, refetch, and regenerate:\n"
            "  git symbolic-ref --delete refs/remotes/origin/<name>\n"
            "  git fetch --prune origin",
            file=sys.stderr,
        )
        return 1

    # Freeze the base and every branch tip to immutable object IDs up front;
    # all classification below uses only these SHAs (see classify()).
    #
    # The base is resolved through its full remote ref name: the shorthand
    # "origin/master" is ambiguity-dependent — a local branch literally named
    # refs/heads/origin/master takes precedence in Git's ref-resolution order,
    # so every verdict would be computed against the wrong commit while the
    # ledger labels it as the remote base. A symbolic origin/master cannot be
    # silently followed here: the gate above already rejected every
    # non-HEAD symbolic ref in the namespace.
    base_full_sha = git("rev-parse", "--verify", f"refs/remotes/{BASE}^{{commit}}").strip()
    base_sha = git("rev-parse", "--short", base_full_sha).strip()
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
            # section never renders a blank cell. cmd[2:4] skips the fixed
            # "git --no-replace-objects" prefix the helpers prepend.
            message = stderr.strip() or (
                f"git {' '.join(map(str, exc.cmd[2:4]))} exited {exc.returncode}"
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

    try:
        origin_url = git("remote", "get-url", "origin").strip()
    except subprocess.CalledProcessError:
        origin_url = ""
    repo_selector = repo_selector_from_origin_url(origin_url)
    prs, pr_data_available = try_open_prs(repo_selector)
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
        # Full object ID of the base every verdict was computed against: a
        # reaper must require the live BASE ref to still equal it (and each
        # branch's live ref to equal tip_sha, and a live PR query to report
        # no open PR — a PR opened after generation moves neither ref)
        # before deleting: a base moved by e.g. a revert can turn a LANDED
        # branch back into the sole holder of its content while the branch
        # tip itself is unchanged.
        "base_full_sha": base_full_sha,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "summary": dict(counts),
        # The credential-free HOST[:PORT]/OWNER/REPO identity of the
        # repository whose refs were inventoried and whose PRs were
        # snapshotted (None when the origin URL was unparseable). A reaper
        # must require the selector re-derived from the live origin
        # (--print-selector) to still equal it: an origin repointed after
        # generation — e.g. at a fork with identical SHAs — passes every
        # SHA check while the PR queries inspect the wrong repository.
        "repo_selector": repo_selector,
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
        render_markdown(entries, base_sha, base_full_sha, repo_selector, prs, pr_data_available),
        errors="backslashreplace",
    )
    print(f"wrote {MD_OUT} and {JSON_OUT}: {dict(counts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
