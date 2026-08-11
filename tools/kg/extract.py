#!/usr/bin/env python3
"""Extract a multi-layer knowledge graph of the govern-zone (ACGS) monorepo.

Emits build/graph.json: a label-tagged node list plus a typed relationship
list, ready for tools/kg/load.py to MERGE into Neo4j.

Ingest layers
  A. File spine      — every tracked path, POSIX repo-relative. THE join key.
  B. Semantic        — .understand-anything/knowledge-graph.json (LLM summaries,
                       symbols, layers, guided tour, typed code edges).
  C. Git history     — churn, authorship, recent commits, co-change coupling.
  D. Topology        — uv/pnpm packages, nested-repo submodules.
  E. Governance      — sealed constitutional hashes, ADRs, CI path gates,
                       compliance controls, automation policies, doc links.

Every layer keys on the same `File.key = <repo-relative posix path>` so the
layers actually join instead of forming disconnected islands.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UA_GRAPH = ROOT / ".understand-anything" / "knowledge-graph.json"
UA_META = ROOT / ".understand-anything" / "meta.json"
OUT = Path(__file__).resolve().parent / "build" / "graph.json"

# Recent commits materialised as (:Commit) nodes. Churn/authorship statistics
# are computed over the FULL history regardless of this cap.
RECENT_COMMITS = 400
# Commits touching more than this are release/format sweeps: they blow up
# co-change counts with meaningless pairs.
COCHANGE_MAX_FILES = 25
COCHANGE_MIN_COUNT = 3
COCHANGE_TOP_N = 1200

COMPLEXITY_WEIGHT = {"simple": 1.0, "moderate": 2.0, "complex": 4.0}

UA_FILELIKE = {"file", "document", "config", "pipeline", "service", "resource", "schema"}
UA_EXTRA_LABEL = {
    "document": "Document",
    "config": "Config",
    "pipeline": "Pipeline",
    "service": "Service",
    "resource": "Resource",
    "schema": "Schema",
}
UA_EDGE_TYPE = {
    "contains": "CONTAINS",
    "imports": "IMPORTS",
    "exports": "EXPORTS",
    "tested_by": "TESTED_BY",
    "related": "RELATED_TO",
    "documents": "DOCUMENTS",
    "depends_on": "DEPENDS_ON",
    "configures": "CONFIGURES",
    "calls": "CALLS",
    "defines_schema": "DEFINES_SCHEMA",
    "inherits": "INHERITS",
    "triggers": "TRIGGERS",
    "deploys": "DEPLOYS",
    "serves": "SERVES",
    "routes": "ROUTES",
    "implements": "IMPLEMENTS",
}

LANG_BY_EXT = {
    ".py": "Python",
    ".pyi": "Python",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".rs": "Rust",
    ".md": "Markdown",
    ".mdx": "Markdown",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".json": "JSON",
    ".toml": "TOML",
    ".sh": "Shell",
    ".bash": "Shell",
    ".tf": "Terraform",
    ".css": "CSS",
    ".html": "HTML",
    ".sql": "SQL",
    ".lock": "Lockfile",
    ".txt": "Text",
    ".cfg": "Config",
    ".ini": "Config",
}


# --------------------------------------------------------------------------- #
# graph accumulator
# --------------------------------------------------------------------------- #
class Graph:
    def __init__(self) -> None:
        self.nodes: dict[tuple[str, str], dict] = {}
        self.rels: dict[tuple, dict] = {}

    def node(self, label: str, key: str, extra_labels: tuple[str, ...] = (), **props):
        slot = self.nodes.setdefault(
            (label, key),
            {"label": label, "key": key, "extra": set(), "props": {}},
        )
        slot["extra"].update(extra_labels)
        for k, v in props.items():
            if v is not None:
                slot["props"][k] = v
        return slot

    def has(self, label: str, key: str) -> bool:
        return (label, key) in self.nodes

    def rel(self, rtype, src_label, src_key, dst_label, dst_key, **props):
        if (src_label, src_key) not in self.nodes or (dst_label, dst_key) not in self.nodes:
            return None
        ident = (rtype, src_label, src_key, dst_label, dst_key)
        slot = self.rels.setdefault(
            ident,
            {
                "type": rtype,
                "src_label": src_label,
                "src": src_key,
                "dst_label": dst_label,
                "dst": dst_key,
                "props": {},
            },
        )
        for k, v in props.items():
            if v is not None:
                slot["props"][k] = v
        return slot

    def dump(self) -> dict:
        return {
            "nodes": [
                {
                    "label": n["label"],
                    "key": n["key"],
                    "extra": sorted(n["extra"]),
                    "props": n["props"],
                }
                for n in self.nodes.values()
            ],
            "rels": list(self.rels.values()),
        }


G = Graph()


def run(*args: str) -> str:
    return subprocess.run(args, cwd=ROOT, check=True, text=True, capture_output=True).stdout


def log(msg: str) -> None:
    print(f"[extract] {msg}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# A. File spine
# --------------------------------------------------------------------------- #
def is_test_path(p: str) -> bool:
    base = p.rsplit("/", 1)[-1]
    return (
        "/tests/" in f"/{p}"
        or "/test/" in f"/{p}"
        or base.startswith("test_")
        or base.endswith("_test.py")
        or ".test." in base
        or ".spec." in base
    )


def initialized_submodules() -> list[str]:
    """Submodule paths that are actually checked out here. A leading '-' in
    `git submodule status` means the gitlink is registered but empty."""
    out = []
    try:
        for line in run("git", "submodule", "status").splitlines():
            if line.strip() and line[0] != "-":
                out.append(line[1:].strip().split(" ")[1])
    except subprocess.CalledProcessError:
        pass
    return out


def uninitialized_submodules() -> list[str]:
    """Registered submodule paths with no checkout here — the '-' rows of
    `git submodule status`. Only these can legitimately explain a hash-lock
    entry that is absent from the File spine."""
    out = []
    try:
        for line in run("git", "submodule", "status").splitlines():
            if line.strip() and line[0] == "-":
                out.append(line[1:].strip().split(" ")[1])
    except subprocess.CalledProcessError:
        pass
    return out


def build_spine() -> list[str]:
    """Parent-tracked paths plus, for each checked-out submodule, its own
    tracked paths prefixed with the submodule path. `git ls-files` in the
    parent only yields the gitlink, so without this the whole graph stops at
    the submodule boundary and every submodule-scoped fact silently vanishes.
    """
    tracked = [p for p in run("git", "ls-files").splitlines() if p]
    # Gitlink entries (mode 160000) are directories in the working tree, so
    # testing them with Path.is_file() recorded every initialized submodule
    # pointer as present=false; file_is_live() then rejected it and
    # build_history() silently dropped its aggregate pointer-change
    # statistics even though build_topology() assigns the gitlink and its
    # history to the submodule package. Detect gitlink mode from the index
    # and test directory existence for those paths instead.
    gitlinks = {
        line.split("\t", 1)[1]
        for line in run("git", "ls-files", "-s").splitlines()
        if line.startswith("160000 ") and "\t" in line
    }
    submodule_paths: set[str] = set()
    for sm in initialized_submodules():
        sub = subprocess.run(
            ["git", "-C", str(ROOT / sm), "ls-files"],
            check=False,
            text=True,
            capture_output=True,
        )
        if sub.returncode != 0:
            continue
        sm_files = [f"{sm}/{p}" for p in sub.stdout.splitlines() if p]
        tracked += sm_files
        submodule_paths.update(sm_files)
        log(f"    + {sm}: {len(sm_files)} files")

    for path in tracked:
        ext = os.path.splitext(path)[1].lower()
        G.node(
            "File",
            path,
            name=path.rsplit("/", 1)[-1],
            path=path,
            ext=ext,
            language=LANG_BY_EXT.get(ext, "Other"),
            dir=path.rsplit("/", 1)[0] if "/" in path else ".",
            tracked=True,
            # Derived from the working tree, never assumed: `git ls-files`
            # still lists a tracked file whose unstaged deletion removed it
            # from disk, and recording it as present would let file_is_live()
            # keep resolving citations to it as live Tier B evidence.
            # A gitlink's checkout is a directory, never a regular file.
            present=((ROOT / path).is_dir() if path in gitlinks else (ROOT / path).is_file()),
            is_gitlink=path in gitlinks,
            is_test=is_test_path(path),
            ua_covered=False,
            sealed=False,
            in_submodule=path in submodule_paths,
        )
    log(
        f"A. spine: {len(tracked)} tracked files "
        f"({len(submodule_paths)} inside {len(initialized_submodules())} checked-out submodules)"
    )
    return tracked


# --------------------------------------------------------------------------- #
# B. Semantic layer (understand-anything)
# --------------------------------------------------------------------------- #
def ua_ref(
    ua_id: str, ua_type_by_id: dict[str, str], file_by_id: dict[str, str]
) -> tuple[str, str] | None:
    """Map an understand-anything node id onto our (label, key)."""
    if ua_id in file_by_id:
        return ("File", file_by_id[ua_id])
    t = ua_type_by_id.get(ua_id)
    if t in ("function", "class"):
        return ("Symbol", ua_id)
    if t == "endpoint":
        return ("Endpoint", ua_id)
    return None


def build_semantic(snapshot_key: str) -> None:
    if not UA_GRAPH.exists():
        log("B. semantic: knowledge-graph.json missing — skipped")
        return
    data = json.loads(UA_GRAPH.read_text())
    ua_type_by_id: dict[str, str] = {}
    file_by_id: dict[str, str] = {}

    for n in data["nodes"]:
        nid, ntype = n["id"], n["type"]
        ua_type_by_id[nid] = ntype
        path = n.get("filePath")
        tags = n.get("tags") or []
        summary = n.get("summary")
        cx = n.get("complexity")

        if ntype in UA_FILELIKE and path:
            file_by_id[nid] = path
            extra = (UA_EXTRA_LABEL[ntype],) if ntype in UA_EXTRA_LABEL else ()
            slot = G.node(
                "File",
                path,
                extra_labels=extra,
                name=n.get("name"),
                path=path,
                summary=summary,
                tags=tags,
                complexity=cx,
                complexity_weight=COMPLEXITY_WEIGHT.get(cx, 1.0),
                ua_type=ntype,
                ua_covered=True,
            )
            slot["props"].setdefault("tracked", False)
            # The snapshot can predate a deletion. A semantic-only path is
            # "present" only if it still exists on disk; assuming True minted
            # live-looking nodes for deleted files, which resolve_link() then
            # bound as compliance evidence.
            slot["props"].setdefault("present", (ROOT / path).is_file())
            slot["props"].setdefault("is_test", is_test_path(path))
            slot["props"].setdefault("sealed", False)
            if "ext" not in slot["props"]:
                ext = os.path.splitext(path)[1].lower()
                slot["props"]["ext"] = ext
                slot["props"]["language"] = LANG_BY_EXT.get(ext, "Other")
                slot["props"]["dir"] = path.rsplit("/", 1)[0] if "/" in path else "."
        elif ntype in ("function", "class"):
            lr = n.get("lineRange") or [None, None]
            G.node(
                "Symbol",
                nid,
                extra_labels=(ntype.capitalize(),),
                name=n.get("name"),
                path=path,
                summary=summary,
                tags=tags,
                kind=ntype,
                complexity=cx,
                complexity_weight=COMPLEXITY_WEIGHT.get(cx, 1.0),
                line_start=lr[0],
                line_end=lr[1],
            )
        elif ntype == "endpoint":
            G.node("Endpoint", nid, name=n.get("name"), path=path, summary=summary, tags=tags)

    for e in data["edges"]:
        src = ua_ref(e["source"], ua_type_by_id, file_by_id)
        dst = ua_ref(e["target"], ua_type_by_id, file_by_id)
        if not src or not dst or src == dst:
            continue
        rtype = UA_EDGE_TYPE.get(e["type"], e["type"].upper())
        G.rel(
            rtype,
            src[0],
            src[1],
            dst[0],
            dst[1],
            weight=e.get("weight"),
            source_layer="understand-anything",
        )

    for layer in data.get("layers", []):
        lkey = layer["id"]
        G.node("Layer", lkey, name=layer.get("name"), description=layer.get("description"))
        G.rel("PART_OF_SNAPSHOT", "Layer", lkey, "Snapshot", snapshot_key)
        for nid in layer.get("nodeIds", []):
            ref = ua_ref(nid, ua_type_by_id, file_by_id)
            if ref:
                G.rel("IN_LAYER", ref[0], ref[1], "Layer", lkey)

    prev = None
    for step in data.get("tour", []):
        skey = f"tour:{step['order']:02d}"
        G.node(
            "TourStep",
            skey,
            order=step["order"],
            title=step.get("title"),
            description=step.get("description"),
        )
        if prev:
            G.rel("NEXT", "TourStep", prev, "TourStep", skey)
        prev = skey
        for nid in step.get("nodeIds", []):
            ref = ua_ref(nid, ua_type_by_id, file_by_id)
            if ref:
                G.rel("HIGHLIGHTS", "TourStep", skey, ref[0], ref[1])

    log(
        f"B. semantic: {len(data['nodes'])} ua nodes, {len(data['edges'])} ua edges, "
        f"{len(data.get('layers', []))} layers, {len(data.get('tour', []))} tour steps"
    )


# --------------------------------------------------------------------------- #
# C. Git history
# --------------------------------------------------------------------------- #
def split_rename(path: str) -> tuple[str, str]:
    """A ``--numstat`` rename record -> (origin, destination) full paths.

    Two shapes exist: the brace form ``dir/{old => new}/c.py`` (either side may
    be empty, e.g. ``dir/{ => sub}/c.py``) and the plain form ``old => new``.
    """
    m = re.match(r"^(.*)\{(.*) => (.*)\}(.*)$", path)
    if m:
        pre, old_mid, new_mid, post = m.groups()
        return (
            f"{pre}{old_mid}{post}".replace("//", "/"),
            f"{pre}{new_mid}{post}".replace("//", "/"),
        )
    old, new = path.split(" => ", 1)
    return old, new


def parse_history(repo: str = ".", prefix: str = "") -> list[dict]:
    """Commits of one repo. Submodules are separate histories, so this is
    called once per repo and paths are prefixed back onto the parent's spine."""
    # In a shallow clone `git log` exits 0 with only the retained history, so
    # churn, contributor counts, hotspots, co-change edges, and commit counts
    # would be silently computed from a truncated sample while the generated
    # report claims they cover full history. Called once per repo, so the
    # parent and every initialized submodule are each checked.
    shallow = subprocess.run(
        ["git", "-C", str(ROOT / repo), "rev-parse", "--is-shallow-repository"],
        check=False,
        text=True,
        capture_output=True,
    )
    if shallow.returncode == 0 and shallow.stdout.strip() == "true":
        raise RuntimeError(
            f"repo {repo!r} is a shallow clone: `git log` would return truncated "
            "history while the report claims full-history metrics; run "
            "`git fetch --unshallow` there before extracting"
        )
    proc = subprocess.run(
        [
            "git",
            "-C",
            str(ROOT / repo),
            "log",
            "--no-merges",
            "-M",
            "--numstat",
            "--pretty=format:\x01%H\x1f%at\x1f%an\x1f%ae\x1f%s",
        ],
        check=False,
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        # A partial/filtered checkout or a missing historical object makes
        # `git log` emit what it can and then exit nonzero. Silently returning
        # [] here published a history-free graph as a successful extraction,
        # deleting all churn, contributor, Commit, and TOUCHED evidence.
        raise RuntimeError(
            f"git log failed for repo {repo!r} (exit {proc.returncode}): "
            f"{proc.stderr.strip() or 'no stderr'}"
        )
    raw = proc.stdout
    commits: list[dict] = []
    cur: dict | None = None
    # historical path -> the path it lives at today. The log is newest-first,
    # so a rename record teaches us how every OLDER commit's path maps forward.
    # Rewriting only the rename commit itself dropped all pre-rename commits
    # in build_history() (the old path is absent from the live spine), which
    # materially understated the advertised full-history churn metrics.
    alias: dict[str, str] = {}
    for line in raw.split("\n"):
        if line.startswith("\x01"):
            sha, ts, an, ae, subject = line[1:].split("\x1f", 4)
            cur = {
                "sha": sha,
                "ts": int(ts),
                "author": an,
                "email": ae,
                "subject": subject,
                "repo": repo,
                "files": {},
            }
            commits.append(cur)
        elif line.strip() and cur is not None:
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            add, dele, path = parts
            if " => " in path:  # rename: a/{old => new}/c.py  or  old => new
                old, new = split_rename(path)
                path = alias.get(new, new)
                alias[old] = path  # chained renames collapse onto the live path
            else:
                path = alias.get(path, path)
            cur["files"][prefix + path] = (
                int(add) if add.isdigit() else 0,
                int(dele) if dele.isdigit() else 0,
            )
    return commits


def build_history(commits: list[dict]) -> None:
    stats: dict[str, dict] = defaultdict(
        lambda: {"commits": 0, "add": 0, "dele": 0, "authors": set(), "first": None, "last": None}
    )
    pair_counts: Counter = Counter()

    for c in commits:
        for path, (add, dele) in c["files"].items():
            s = stats[path]
            s["commits"] += 1
            s["add"] += add
            s["dele"] += dele
            # The same stable key Author nodes use below: display names are
            # not identities (one email has committed here as both MartinLyu
            # and dislovelhl), and counting names inflated author_count and
            # hid single-author files from the bus-factor query (Q11).
            s["authors"].add(c["email"])
            s["last"] = max(s["last"] or 0, c["ts"])
            s["first"] = min(s["first"] or c["ts"], c["ts"])
        if 1 < len(c["files"]) <= COCHANGE_MAX_FILES:
            paths = sorted(c["files"])
            for i, a in enumerate(paths):
                for b in paths[i + 1 :]:
                    pair_counts[(a, b)] += 1

    now = datetime.now(UTC).timestamp()

    # Normalize over the population that actually receives hotspot scores:
    # a deleted historical path with the largest churn has no live File node,
    # and letting it set the denominator scaled every live file down until
    # Q5's fixed `hotspot > 0.05` predicate missed the real current hotspots.
    # Node existence alone is not enough: build_semantic() deliberately
    # retains a File node for a path deleted (or index-removed) after the
    # snapshot, with present/tracked recording the truth; that dead node's
    # churn must not set the denominator either, so both the denominator and
    # the scoring loop use the same live-and-tracked predicate.
    def _scores_hotspot(path: str) -> bool:
        return G.has("File", path) and file_is_live(path)

    max_churn = (
        max(
            (s["add"] + s["dele"] for path, s in stats.items() if _scores_hotspot(path)),
            default=1,
        )
        or 1
    )
    for path, s in stats.items():
        if not _scores_hotspot(path):
            continue  # deleted / renamed-away / semantic-retained dead path
        churn = s["add"] + s["dele"]
        slot = G.node(
            "File",
            path,
            commit_count=s["commits"],
            lines_added=s["add"],
            lines_deleted=s["dele"],
            churn=churn,
            author_count=len(s["authors"]),
            first_commit=datetime.fromtimestamp(s["first"], UTC).date().isoformat(),
            last_commit=datetime.fromtimestamp(s["last"], UTC).date().isoformat(),
            days_since_change=round((now - s["last"]) / 86400, 1),
        )
        cw = slot["props"].get("complexity_weight", 1.0)
        slot["props"]["hotspot"] = round((churn / max_churn) * cw, 4)

    for c in commits[:RECENT_COMMITS]:
        repo = c.get("repo", ".")
        # Commit identity is repo-scoped: submodules are independent
        # histories, and a forked or split repository can contain the very
        # same commit object as another. Keying on the SHA alone collapsed
        # such entries into one node — the later G.node() overwrote repo,
        # file_count, and churn while both repositories' TOUCHED edges stayed
        # unioned on it, so REPO_Q and commit provenance described neither
        # repository. The repository plus the full SHA is the graph identity;
        # short_sha stays display-only.
        ckey = f"{repo}:{c['sha']}"
        G.node(
            "Commit",
            ckey,
            sha=c["sha"],
            short_sha=c["sha"][:12],
            subject=c["subject"],
            author=c["author"],
            date=datetime.fromtimestamp(c["ts"], UTC).isoformat(),
            file_count=len(c["files"]),
            churn=sum(a + d for a, d in c["files"].values()),
            repo=repo,
        )
        G.node("Author", c["email"], name=c["author"], email=c["email"])
        G.rel("AUTHORED", "Author", c["email"], "Commit", ckey)
        for path, (add, dele) in c["files"].items():
            G.rel("TOUCHED", "Commit", ckey, "File", path, added=add, deleted=dele)

    kept = 0
    for (a, b), n in pair_counts.most_common():
        if n < COCHANGE_MIN_COUNT or kept >= COCHANGE_TOP_N:
            break
        # Same live-and-tracked predicate as hotspot scoring: a stale semantic
        # snapshot retains a File node for a deleted or index-removed path, so
        # node existence alone let CO_CHANGED edges bind dead paths and Q4
        # (which filters neither present nor tracked) reported package
        # coupling through files absent from a checkout.
        if not (_scores_hotspot(a) and _scores_hotspot(b)):
            continue
        ca, cb = stats[a]["commits"], stats[b]["commits"]
        jaccard = round(n / (ca + cb - n), 4) if (ca + cb - n) else 0.0
        G.rel("CO_CHANGED", "File", a, "File", b, count=n, jaccard=jaccard)
        kept += 1

    log(f"C. history: {len(commits)} commits, {len(stats)} paths touched, {kept} co-change edges")
    return None


# --------------------------------------------------------------------------- #
# D. Topology — packages and submodules
# --------------------------------------------------------------------------- #
SKIP_DIRS = {
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    ".git",
    "__pycache__",
    ".turbo",
    ".next",
    "coverage",
    "htmlcov",
}


def build_topology(tracked: list[str]) -> dict[str, str]:
    submodules: dict[str, dict] = {}
    gm = ROOT / ".gitmodules"
    if gm.exists():
        cur = None
        for line in gm.read_text().splitlines():
            line = line.strip()
            if line.startswith("[submodule"):
                cur = {}
            elif cur is not None and "=" in line:
                k, v = (x.strip() for x in line.split("=", 1))
                cur[k] = v
                if k == "path":
                    submodules[v] = cur
    status = {}
    try:
        for line in run("git", "submodule", "status").splitlines():
            line = line.rstrip()
            if not line:
                continue
            marker, rest = line[0], line[1:].strip()
            sha, path = rest.split(" ", 1)[0], rest.split(" ")[1]
            status[path] = {"initialized": marker != "-", "pinned_sha": sha}
    except subprocess.CalledProcessError:
        pass

    manifests: list[tuple[str, str]] = []
    for path in tracked:
        base = path.rsplit("/", 1)[-1]
        if base in ("pyproject.toml", "package.json") and not any(
            part in SKIP_DIRS for part in path.split("/")
        ):
            manifests.append((path.rsplit("/", 1)[0] if "/" in path else ".", path))

    G.node(
        "Package",
        ".",
        name="govern-zone (root)",
        kind="workspace",
        path=".",
        is_submodule=False,
        initialized=True,
    )

    for pkg_path, manifest in sorted(manifests):
        kind = "python" if manifest.endswith("pyproject.toml") else "node"
        name = pkg_path.rsplit("/", 1)[-1] if pkg_path != "." else "govern-zone (root)"
        slot = G.node(
            "Package",
            pkg_path,
            name=name,
            path=pkg_path,
            is_submodule=pkg_path in submodules,
            initialized=status.get(pkg_path, {}).get("initialized", True),
        )
        kinds = set(slot["props"].get("kinds", []))
        kinds.add(kind)
        slot["props"]["kinds"] = sorted(kinds)
        slot["props"]["kind"] = "+".join(sorted(kinds))
        G.rel("DECLARED_BY", "Package", pkg_path, "File", manifest)

    for sm_path, cfg in submodules.items():
        st = status.get(sm_path, {})
        G.node(
            "Package",
            sm_path,
            extra_labels=("Submodule",),
            name=sm_path.rsplit("/", 1)[-1],
            path=sm_path,
            kind="submodule",
            is_submodule=True,
            url=cfg.get("url"),
            branch=cfg.get("branch"),
            initialized=st.get("initialized", False),
            pinned_sha=st.get("pinned_sha"),
        )

    pkg_paths = sorted(
        (k for (lbl, k) in G.nodes if lbl == "Package" and k != "."),
        key=len,
        reverse=True,
    )
    for p in pkg_paths:
        parent = next((q for q in pkg_paths if q != p and p.startswith(q + "/")), ".")
        G.rel("PART_OF", "Package", p, "Package", parent)

    owner: dict[str, str] = {}
    for lbl, key in list(G.nodes):
        if lbl != "File":
            continue
        # A submodule gitlink's File key IS the package path (no trailing
        # segment), so the prefix test alone assigned every gitlink — and its
        # pointer-change history — to the workspace root.
        pkg = next((p for p in pkg_paths if key == p or key.startswith(p + "/")), ".")
        owner[key] = pkg
        G.nodes[(lbl, key)]["props"]["package"] = pkg
        G.rel("IN_PACKAGE", "File", key, "Package", pkg)

    log(
        f"D. topology: {len(pkg_paths) + 1} packages "
        f"({sum(1 for p in submodules)} submodules, "
        f"{sum(1 for s in status.values() if s['initialized'])} initialized)"
    )
    return owner


# --------------------------------------------------------------------------- #
# E. Governance
# --------------------------------------------------------------------------- #
# Imported, never copied. A hand-duplicated copy of the gate's coverage goes
# stale the day the gate changes, and the graph would then report a governance
# gap that no longer exists — or miss one that does. The marker regex is the
# gate's own for the same reason: a narrower local copy (lowercase-only hex)
# recorded files the real gate accepts — e.g. uppercase markers — as unsealed.
sys.path.insert(0, str(ROOT / "scripts"))
try:
    from verify_constitutional_hashes import MARKER_RE as HASH_MARKER
    from verify_constitutional_hashes import SCAN_EXTENSIONS as HASH_GATED_EXTENSIONS
    from verify_constitutional_hashes import SKIP_FILES as _GATE_SKIP_FILES
except ImportError:  # degrade loudly, never silently
    HASH_MARKER = re.compile(r"Constitutional Hash:[\s`'\"]*([0-9a-fA-F]+)")
    HASH_GATED_EXTENSIONS = set()
    _GATE_SKIP_FILES = frozenset()
    print(
        "[extract] WARNING: scripts/verify_constitutional_hashes.py not importable; "
        "hash_gated flags are meaningless this run",
        file=sys.stderr,
    )

# The gate's own fixture exclusions, plus the lock file itself (it is the
# inventory, not a sealed declaration).
HASH_SKIP = set(_GATE_SKIP_FILES) | {"docs/constitutional-hashes.lock"}

# Filled by build_sealed, published on the (:Snapshot) node: lock entries
# absent from the File spine whose owner is NOT an uninitialized submodule.
# These are genuinely missing sealed files and verify.py fails hard on them.
SEALED_STATS: dict = {}
BINARY_EXT = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".pdf",
    ".zip",
    ".gz",
    ".webp",
    ".svg",
}


def build_sealed(tracked: list[str]) -> None:
    """Two sources of sealing truth, kept distinct.

    1. Live markers scanned out of the working tree — the files a hash-drift
       change would actually break here and now.
    2. docs/constitutional-hashes.lock — the pinned inventory, which on this
       checkout covers only the (uninitialized) submodules. Those get counted
       on the Package node rather than minting phantom :File nodes.
    """
    present = 0
    ungated = 0
    for path in tracked:
        if path in HASH_SKIP or os.path.splitext(path)[1].lower() in BINARY_EXT:
            continue
        f = ROOT / path
        try:
            if not f.is_file():
                continue
            with f.open("r", encoding="utf-8", errors="ignore") as fh:
                # 4KB head window, matching scripts/verify_constitutional_hashes.py:
                # a marker buried mid-file is prose, not a governance declaration.
                m = HASH_MARKER.search(fh.read(4096))
        except OSError:
            continue
        if not m:
            continue
        value = m.group(1)
        gated = os.path.splitext(path)[1].lower() in HASH_GATED_EXTENSIONS
        G.node("Hash", value, extra_labels=("ConstitutionalHash",), value=value)
        G.node(
            "File",
            path,
            sealed=True,
            sealed_hash=value,
            sealed_source="working-tree",
            hash_gated=gated,
        )
        G.rel("SEALED_WITH", "File", path, "Hash", value)
        present += 1
        if not gated:
            ungated += 1

    absent: Counter = Counter()
    missing: list[str] = []
    uninit: list[str] | None = None  # resolved lazily: only absences need it
    lock = ROOT / "docs" / "constitutional-hashes.lock"
    if lock.exists():
        data = json.loads(lock.read_text())
        for path, value in data.get("hashes", {}).items():
            G.node("Hash", value, extra_labels=("ConstitutionalHash",), value=value)
            if G.has("File", path):
                props = G.nodes[("File", path)]["props"]
                live = (
                    props.get("sealed_hash")
                    if props.get("sealed_source") == "working-tree"
                    else None
                )
                G.node("File", path, sealed=True, pinned_hash=value, in_hash_lock=True)
                if live is None:
                    # No live marker observed: the working tree no longer
                    # carries the seal the lock pins. Copying the pin into
                    # sealed_hash made Q3 show the file as sealed with no
                    # drift, hiding exactly the marker-removal drift this
                    # graph exists to expose. Preserve the absence (no
                    # sealed_hash) and record the drift instead.
                    G.node("File", path, sealed_source="hash-lock", hash_drift=True)
                else:
                    # Keep the observed working-tree marker as sealed_hash and
                    # record the mismatch. Overwriting it with the pin hid
                    # exactly the drift this graph exists to expose, while
                    # sealed_source still claimed the value was observed live.
                    G.node("File", path, hash_drift=live != value)
                G.rel("SEALED_WITH", "File", path, "Hash", value)
            else:
                # An absent lock entry is waived only when its owner is a
                # submodule that is genuinely not checked out here — that is
                # the one case where the file's absence says nothing about
                # the seal. Attributing every absence to a package by prefix
                # let a sealed file removed from an initialized submodule's
                # index (or from the parent spine) count as "unavailable
                # submodule", and verify.py then hid a genuinely missing
                # sealed file behind VERIFY: PASS.
                if uninit is None:
                    uninit = uninitialized_submodules()
                sm = next((s for s in uninit if path.startswith(s + "/")), None)
                if sm is not None:
                    absent[sm] += 1
                else:
                    missing.append(path)
        for pkg, n in absent.items():
            if G.has("Package", pkg):
                G.node("Package", pkg, sealed_files_absent=n)
    SEALED_STATS.clear()
    if missing:
        SEALED_STATS["sealed_lock_missing"] = sorted(missing)
        SEALED_STATS["sealed_lock_missing_count"] = len(missing)
    log(
        f"E1. sealed: {present} live markers in the working tree "
        f"({ungated} in file types the hash gate never scans), "
        f"{sum(absent.values())} lock entries in uninitialized submodules, "
        f"{len(missing)} lock entries MISSING outside uninitialized submodules"
    )


ADR_REF = re.compile(r"ADR[- ](\d{4})")
PATH_TOKEN = re.compile(r"`([\w./@-]+/[\w./@-]+)`")
MD_LINK = re.compile(r"\[[^\]]*\]\(([^)\s#]+)")


# The optional `:line` / `:start-end` suffix is INSIDE the capture group so
# findall() returns the full token and resolve_token() can record the cited
# line. Mapping docs write ranges with a hyphen or an en dash (\u2013).
CODE_TOKEN = re.compile(r"`([\w./@-]+\.[A-Za-z0-9]{1,6}(?::\d+(?:[-\u2013]\d+)?)?)`")
_BASENAME_INDEX: dict[str, list[str]] = {}


def basename_index() -> dict[str, list[str]]:
    """basename -> tracked paths. Lets `receipt.py:139` in a compliance table
    resolve to the real file; ambiguous basenames are deliberately dropped."""
    if not _BASENAME_INDEX:
        for lbl, key in G.nodes:
            if lbl == "File":
                _BASENAME_INDEX.setdefault(key.rsplit("/", 1)[-1], []).append(key)
    return _BASENAME_INDEX


_DOC_SCOPE: dict[str, set[str]] = {}


def doc_scope(src: str) -> set[str]:
    """Full repo paths a document names explicitly anywhere in its body.

    A compliance doc usually pins its subject once ("...
    `packages/gove-zone/src/gove_zone/receipt.py`, `DecisionReceipt`") and then
    refers to it by bare basename in every table row. Without that context a
    bare `receipt.py` is 3-way ambiguous across the workspace and gets dropped,
    silently suppressing the document's real citations.
    """
    if src not in _DOC_SCOPE:
        scope: set[str] = set()
        f = ROOT / src
        if f.is_file():
            text = f.read_text(errors="replace")
            # Markdown-link tokens keep their syntax provenance: an
            # unprefixed relative link resolves doc-relative first.
            for toks, is_md in ((PATH_TOKEN.findall(text), False), (MD_LINK.findall(text), True)):
                for tok in set(toks):
                    hit = resolve_link(src, tok.split(":")[0], markdown_link=is_md)
                    if hit:
                        scope.add(hit)
        _DOC_SCOPE[src] = scope
    return _DOC_SCOPE[src]


def resolve_token(
    src: str, token: str, markdown_link: bool = False
) -> tuple[str | None, int | None, str | None]:
    """Resolve a doc token to (path, line, method).

    method is how much the resolution is worth: `path` (explicit and
    unambiguous), `basename` (bare name that happens to be unique in the
    workspace), `basename-docscope` (bare name disambiguated by a full path the
    same document names elsewhere). None when unresolved.

    markdown_link records that the token came from Markdown link syntax, so
    an unprefixed relative form resolves against the source document first.
    """
    line = None
    # A range citation ("receipt.py:132-133", en dash included) resolves to
    # its first line: cited_line points at where the evidence starts.
    m = re.match(r"^(.*?):(\d+)(?:[-\u2013]\d+)?$", token)
    if m:
        token, line = m.group(1), int(m.group(2))
    hit = resolve_link(src, token, markdown_link=markdown_link)
    if hit:
        return hit, line, "path"
    if "/" in token:
        return None, None, None

    cands = [c for c in basename_index().get(token, []) if file_is_live(c)]
    if len(cands) == 1:
        return cands[0], line, "basename"
    if len(cands) > 1:
        scope = doc_scope(src)
        exact = [c for c in cands if c in scope]
        if len(exact) == 1:
            return exact[0], line, "basename-docscope"
        # Fall back to the package the document is clearly about.
        pkgs = {"/".join(p.split("/")[:2]) for p in scope}
        near = [c for c in cands if "/".join(c.split("/")[:2]) in pkgs]
        if len(near) == 1:
            return near[0], line, "basename-docscope"
    return None, None, None


def file_is_live(key: str) -> bool:
    """A File node is usable as live evidence only when it is both on disk
    AND tracked by Git. A semantic-only path whose file was since deleted is
    neither; a path removed from the index but still on disk (tracked=False,
    present=True) will not exist in a checkout, so binding doc links or
    compliance evidence to either would report unversioned or deleted source
    as an implementation. Both flags default to their live value: every
    ingest layer that mints File nodes records them explicitly."""
    props = G.nodes[("File", key)]["props"]
    return bool(props.get("present", True)) and bool(props.get("tracked", True))


def resolve_link(src: str, target: str, markdown_link: bool = False) -> str | None:
    if target.startswith(("http://", "https://", "mailto:")):
        return None
    target = target.split("#")[0].strip()
    if not target:
        return None
    # Docs in this repo cite paths three ways, and only trying one of them
    # silently drops most citations. Repo-root-relative is the dominant style
    # (`packages/gove-zone/src/gove_zone/receipt.py`); resolving that against
    # the citing doc's directory yields `docs/packages/...`, which never exists.
    if target.startswith("/"):
        cands = [target.lstrip("/")]
    elif target.startswith(("./", "../")):
        cands = [os.path.normpath(os.path.join(os.path.dirname(src), target))]
    elif markdown_link:
        # Markdown resolves an unprefixed relative link against the linking
        # document's directory: `[x](COMPARISON.md)` in docs/ means
        # docs/COMPARISON.md. Trying repo-root first bound such links to a
        # same-named root file whenever both exist, leaving the intended
        # target orphaned in Q8 and inflating the wrong document's Q12
        # authority. Repo-root stays as the fallback because many docs
        # still write root-relative paths inside link syntax.
        cands = [
            os.path.normpath(os.path.join(os.path.dirname(src), target)),  # doc-relative
            target,  # repo-root-relative
        ]
    else:
        cands = [
            target,  # repo-root-relative
            os.path.normpath(os.path.join(os.path.dirname(src), target)),  # doc-relative
        ]
    for cand in cands:
        cand = cand.replace("\\", "/")
        if G.has("File", cand) and file_is_live(cand):
            return cand
    return None


def build_adrs() -> None:
    adr_dir = ROOT / "docs" / "adr"
    if not adr_dir.is_dir():
        return
    count = 0
    for f in sorted(adr_dir.glob("*.md")):
        rel = f.relative_to(ROOT).as_posix()
        # An untracked local draft or an index-removed ADR left on disk will
        # not exist in a checkout, so it is not a decision record. The glob
        # still found it, minting an ADR whose DECIDES_ON edges appeared in
        # Q7 and suppressed Q3b's missing-ADR finding for sealed files. Same
        # live-and-tracked predicate the other doc layers apply.
        if not (G.has("File", rel) and file_is_live(rel)):
            log(f"    ! {rel}: not live+tracked, skipped")
            continue
        text = f.read_text(errors="replace")
        m = re.search(r"^#\s+(.+)$", text, re.M)
        title = m.group(1).strip() if m else f.stem
        # A section ends at a blank line, at the next heading, or at end of file.
        # Without the \Z alternative an ADR whose Status is its last section
        # parsed as "Unknown" — a silent field loss, not an error.
        st = re.search(r"^##\s+Status\s*\n+(.+?)(?:\n\s*\n|\n##|\Z)", text, re.M | re.S)
        # The repository's other metadata style is a list item near the top
        # (`- Status: Accepted`, e.g. docs/adr/0008). Recognising only the
        # `## Status` heading recorded those ADRs as Unknown.
        if not st:
            st = re.search(r"^\s*[-*]\s*Status:\s*(.+?)\s*$", text, re.M)
        status_raw = " ".join(st.group(1).split()) if st else "Unknown"
        # An EMPTY Status section runs straight into the next heading, and the
        # capture then holds that heading's text ("## Context"). The derived
        # status is "Unknown" either way, but status_raw is published verbatim
        # as ADR.status_text — recording a neighbouring heading there is
        # fabricated metadata, so treat a heading capture as no status at all.
        if status_raw.startswith("#"):
            status_raw = "Unknown"
        status = next(
            (
                w
                for w in ("Superseded", "Accepted", "Proposed", "Rejected", "Deprecated", "Draft")
                if w.lower() in status_raw.lower()
            ),
            "Unknown",
        )
        dt = re.search(r"^##\s+Date\s*\n+([0-9]{4}-[0-9]{2}-[0-9]{2})", text, re.M)
        # The list-style metadata block pairs `- Status:` with `- Date:`
        # (e.g. docs/adr/0008). Recognising only the `## Date` heading kept
        # extracting the corrected status while silently dropping the date.
        if not dt:
            dt = re.search(r"^\s*[-*]\s*Date:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", text, re.M)
        num = re.match(r"(\d{4})", f.stem)
        akey = f"ADR-{num.group(1)}" if num else f.stem
        G.node(
            "ADR",
            akey,
            name=akey,
            title=title,
            status=status,
            status_text=status_raw[:280],
            date=dt.group(1) if dt else None,
            path=rel,
        )
        G.rel("DOCUMENTED_IN", "ADR", akey, "File", rel)
        count += 1

    for f in sorted(adr_dir.glob("*.md")):
        rel = f.relative_to(ROOT).as_posix()
        # Mirror the ingest gate above: a skipped ADR has no node, so minting
        # RELATES_TO/SUPERSEDES/DECIDES_ON edges from it would dangle.
        if not (G.has("File", rel) and file_is_live(rel)):
            continue
        text = f.read_text(errors="replace")
        num = re.match(r"(\d{4})", f.stem)
        akey = f"ADR-{num.group(1)}" if num else f.stem
        for other in set(ADR_REF.findall(text)):
            okey = f"ADR-{other}"
            if okey != akey and G.has("ADR", okey):
                G.rel("RELATES_TO", "ADR", akey, "ADR", okey)
        for m in re.finditer(r"[Ss]upersedes\s+ADR[- ](\d{4})", text):
            if G.has("ADR", f"ADR-{m.group(1)}"):
                G.rel("SUPERSEDES", "ADR", akey, "ADR", f"ADR-{m.group(1)}")
        for m in re.finditer(r"[Ss]uperseded by\s+ADR[- ](\d{4})", text):
            if G.has("ADR", f"ADR-{m.group(1)}"):
                G.rel("SUPERSEDES", "ADR", f"ADR-{m.group(1)}", "ADR", akey)
        # Markdown-link tokens are resolved with their syntax provenance so
        # an unprefixed relative link binds to the ADR-relative target first.
        backticked = set(PATH_TOKEN.findall(text)) | set(CODE_TOKEN.findall(text))
        for toks, is_md in ((backticked, False), (set(MD_LINK.findall(text)), True)):
            for tok in toks:
                tgt, _, _ = resolve_token(rel, tok, markdown_link=is_md)
                if tgt and tgt != rel:
                    G.rel("DECIDES_ON", "ADR", akey, "File", tgt)
    log(f"E2. adrs: {count} ADRs")


def build_doc_links() -> None:
    n = 0
    for (lbl, key), _slot in list(G.nodes.items()):
        if lbl != "File" or not key.endswith((".md", ".mdx")):
            continue
        # The source document must itself be live: a semantic-retained node
        # for a Markdown file removed from the index but left on disk
        # (tracked=false, present=true) will not exist in a checkout, so its
        # citations must not suppress a target from Q8's orphan report or
        # inflate Q12 authority. Same predicate build_controls() applies to
        # mapping documents.
        f = ROOT / key
        if not f.is_file() or not file_is_live(key):
            continue
        text = f.read_text(errors="replace")
        targets = set()
        # Root documents cite each other as bare backticked filenames
        # (CLAUDE.md says `CONCEPTS.md`): PATH_TOKEN requires a slash and
        # MD_LINK requires link syntax, so those citations vanished and Q8
        # reported the target as orphaned. CODE_TOKEN keeps its optional
        # `:line` suffix inside the capture; strip it before resolving.
        # Markdown-link tokens keep their syntax provenance: Markdown
        # resolves an unprefixed relative link against the linking document,
        # so `[x](COMPARISON.md)` in docs/ must bind to docs/COMPARISON.md
        # even when a same-named root file exists.
        backticked = set(PATH_TOKEN.findall(text))
        backticked |= {tok.split(":")[0] for tok in CODE_TOKEN.findall(text)}
        for toks, is_md in ((backticked, False), (set(MD_LINK.findall(text)), True)):
            for tok in toks:
                tgt = resolve_link(key, tok, markdown_link=is_md)
                if tgt and tgt != key:
                    targets.add(tgt)
        for tgt in targets:
            G.rel("LINKS_TO", "File", key, "File", tgt)
            n += 1
    log(f"E3. doc links: {n} resolved in-repo references")


CONTROL_PATTERNS = [
    # The paragraph (EU) and decimal subcategory (NIST) are optional: the
    # scanned mappings also cite top-level identifiers ("Art. 19", "GOVERN 1"),
    # and requiring the detailed form silently dropped those rows from the
    # Control nodes and every per-framework total derived from them.
    ("EU AI Act", re.compile(r"\bArt(?:icle)?\.?\s*(\d+)(?:\((\d+)\)(?:\(([a-z])\))?)?")),
    ("HIPAA", re.compile(r"§\s*(164\.\d+(?:\([a-z0-9]\))*)")),
    ("NIST AI RMF", re.compile(r"\b(GOVERN|MAP|MEASURE|MANAGE)[-. ](\d+(?:\.\d+)?)\b")),
    ("ISO/IEC 42001", re.compile(r"\b(?:Annex\s+)?(A\.\d+\.\d+(?:\.\d+)?)\b")),
    ("SOC 2", re.compile(r"\b(CC\d\.\d+)\b")),
]
# A scope citing more than this many distinct controls is an index/enumeration,
# not an evidence binding. See ADR-0012 and the compliance tier report.
MAX_CONTROLS_PER_EVIDENCE_SCOPE = 2
# Filled by build_controls, published on the (:Snapshot) node for reports.
CONTROL_STATS: dict[str, int] = {}
# Resolution strength, strongest first: the scalar provenance on a shared
# EVIDENCED_BY edge describes the strongest citation it carries.
METHOD_RANK = {"path": 0, "basename-docscope": 1, "basename": 2}

CONTROL_DOC_HINTS = (
    "mapping",
    "crosswalk",
    "compliance",
    "control",
    "readiness",
    "conformance",
    "eu_ai_act",
    "hipaa",
    "nist",
    "iso",
)


def control_id(framework: str, m: re.Match) -> str:
    if framework == "EU AI Act":
        art, para, lit = m.group(1), m.group(2), m.group(3)
        cid = f"EU AI Act Art {art}"
        if para:
            cid += f"({para})"
        if lit:
            cid += f"({lit})"
        return cid
    if framework == "NIST AI RMF":
        return f"NIST AI RMF {m.group(1)}-{m.group(2)}"
    return f"{framework} {m.group(1)}"


def build_controls() -> None:
    docs = [
        k
        for (lbl, k) in G.nodes
        if lbl == "File" and k.endswith(".md") and any(h in k.lower() for h in CONTROL_DOC_HINTS)
    ]
    controls = 0
    evidences = 0
    enumerations = 0
    by_basename = 0
    for rel in sorted(docs):
        f = ROOT / rel
        # The mapping document is itself provenance: a doc removed from the
        # index but left on disk (tracked=false, present=true) will not exist
        # in a checkout, so scanning it would publish and tier controls
        # sourced from a document the repository does not ship. The source
        # must be live and tracked, exactly like the evidence targets it
        # cites through file_is_live() in resolve_token().
        if not f.is_file() or not file_is_live(rel):
            continue
        # Scope evidence to the paragraph (a table row is its own paragraph),
        # so a control claim binds only to code cited near it.
        for para in re.split(r"\n\s*\n", f.read_text(errors="replace")):
            for line in para.splitlines() if para.lstrip().startswith("|") else [para]:
                hits = set()
                for framework, pat in CONTROL_PATTERNS:
                    for m in pat.finditer(line):
                        hits.add((framework, control_id(framework, m)))
                if not hits:
                    continue
                for framework, cid in hits:
                    if not G.has("Control", cid):
                        controls += 1
                    G.node("Control", cid, name=cid, framework=framework)
                    G.rel("MAPS_TO", "File", rel, "Control", cid)

                # Enumeration guard. A sentence that lists several control ids
                # ("A.2.2, A.3.2, A.6.2.6 ... are listed") is an index, not a
                # binding: attaching every path in it to every control invents
                # evidence. Citations are recorded, evidence is not.
                if len(hits) > MAX_CONTROLS_PER_EVIDENCE_SCOPE:
                    enumerations += 1
                    continue

                evidence: dict[str, list[tuple[int | None, str]]] = {}
                for tok in sorted(set(PATH_TOKEN.findall(line)) | set(CODE_TOKEN.findall(line))):
                    tgt, ln, method = resolve_token(rel, tok)
                    if tgt and tgt != rel:
                        # How the token resolved decides how much it is worth.
                        # An explicit repo path is unambiguous; a bare basename
                        # survives only because it happens to be unique in the
                        # workspace, which is luck, not evidence.
                        # One scope may cite several lines of the same file
                        # (`receipt.py:139`, `:140`, `:141`); keying on the
                        # target alone kept only whichever token a set's hash
                        # order surfaced first, so every distinct location is
                        # accumulated (in sorted-token order, for determinism).
                        locations = evidence.setdefault(tgt, [])
                        if (ln, method) not in locations:
                            locations.append((ln, method))
                        if method != "path":
                            by_basename += 1
                for _framework, cid in hits:
                    for tgt, locations in evidence.items():
                        slot = G.rel("EVIDENCED_BY", "Control", cid, "File", tgt)
                        if slot is None:
                            continue
                        props = slot["props"]
                        # Two documents citing the same file for the same
                        # control share one edge identity, and letting each
                        # call overwrite the scalar provenance kept only
                        # whichever sorted document was processed last. Every
                        # cited location is accumulated on the edge; the
                        # scalars mirror the strongest citation seen.
                        for ln, method in locations:
                            cite = f"{rel}:{ln}" if ln is not None else rel
                            cites = props.setdefault("citations", [])
                            if cite not in cites:
                                cites.append(cite)
                                evidences += 1
                            rank = METHOD_RANK.get(method, len(METHOD_RANK))
                            seen = METHOD_RANK.get(props.get("resolved_by"), len(METHOD_RANK) + 1)
                            if rank < seen:
                                props["cited_in"] = rel
                                props["resolved_by"] = method
                                if ln is not None:
                                    props["cited_line"] = ln
                                else:
                                    props.pop("cited_line", None)
    CONTROL_STATS.update(
        enumeration_scopes_skipped=enumerations,
        evidence_links=evidences,
        evidence_by_basename=by_basename,
    )
    log(
        f"E4. controls: {controls} controls across {len(docs)} mapping docs, "
        f"{evidences} evidence links ({by_basename} resolved by bare basename), "
        f"{enumerations} enumeration scopes skipped"
    )


def glob_to_regex(g: str) -> re.Pattern:
    i, out = 0, ["^"]
    while i < len(g):
        if g.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif g.startswith("**", i):
            out.append(".*")
            i += 2
        elif g[i] == "*":
            out.append("[^/]*")
            i += 1
        elif g[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(g[i]))
            i += 1
    out.append("$")
    return re.compile("".join(out))


def compile_path_filters(patterns: list[str]) -> list[tuple[re.Pattern, bool]]:
    """Compile a workflow `paths` list, keeping `!` exclusions and their order."""
    return [(glob_to_regex(p[1:] if p.startswith("!") else p), p.startswith("!")) for p in patterns]


def match_path_filters(path: str, filters: list[tuple[re.Pattern, bool]]) -> bool:
    """GitHub Actions `paths` semantics: patterns are evaluated in order and
    the LAST matching pattern wins. Dropping the negative patterns (the old
    behavior) minted GATES edges for paths a workflow explicitly excludes,
    e.g. `acgi-ai/infra/**` under a filter list that negates it."""
    verdict = False
    for pattern, negated in filters:
        if pattern.match(path):
            verdict = not negated
    return verdict


# A job-level `if:` that is exactly an event-name equality is decidable at
# extraction time: `github.event_name == 'pull_request'` always passes for a
# pull_request run, so it must not mark that event's coverage conditional.
# saas-beta-p0-evidence.yml pairs such a hosted PR lane with a manual-only
# exact-proof job, and counting raw `if:` fields marked every edge
# conditional, discarding the real hosted PR gate from Q1/Q2. Any other
# expression stays undecidable and therefore conditional.
EVENT_NAME_EQ = re.compile(
    r"^\s*(?:\$\{\{\s*)?github\.event_name\s*==\s*['\"]([\w-]+)['\"]\s*(?:\}\}\s*)?$"
)


def job_guaranteed_for_event(cfg: object, event: str) -> bool:
    """True when a workflow job is guaranteed to execute for a run of ``event``."""
    if not isinstance(cfg, dict) or cfg.get("if") is None:
        return True
    m = EVENT_NAME_EQ.match(str(cfg["if"]))
    return bool(m) and m.group(1) == event


def build_workflows(files: list[str]) -> None:
    try:
        import yaml
    except ImportError:
        log("E5. workflows: pyyaml unavailable — skipped")
        return
    wf_dir = ROOT / ".github" / "workflows"
    if not wf_dir.is_dir():
        return
    gates = 0
    for f in sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))):
        rel = f.relative_to(ROOT).as_posix()
        # GitHub runs workflows from the commit's tree, so an untracked local
        # draft or an index-removed file left on disk is not CI. The glob
        # still found it, minting Workflow/GATES edges that Q1/Q2, the
        # verifier, and the reports presented as real coverage, hiding
        # genuinely ungated source. Same live-and-tracked predicate every
        # other evidence layer applies to its sources.
        if not (G.has("File", rel) and file_is_live(rel)):
            log(f"    ! {rel}: not live+tracked, skipped")
            continue
        try:
            doc = yaml.safe_load(f.read_text(errors="replace")) or {}
        except Exception as exc:  # malformed workflow shouldn't kill the run
            log(f"    ! {rel}: {exc.__class__.__name__}")
            continue
        # PyYAML parses the bare key `on:` as boolean True.
        on = doc.get("on", doc.get(True)) or {}
        if isinstance(on, str):
            on = {on: {}}
        if isinstance(on, list):
            on = {k: {} for k in on}
        triggers = sorted(str(k) for k in on)
        # One ordered filter list per triggering event: push and pull_request
        # may declare different filters, and order matters within each. The
        # matching event(s) are preserved on every GATES edge — collapsing
        # them with any() reported a deploy workflow whose push filter matches
        # ordinary source paths as PR coverage for those paths.
        filters_by_event: dict[str, list[str]] = {}
        for ev in ("push", "pull_request"):
            cfg = on.get(ev) or {}
            if isinstance(cfg, dict) and cfg.get("paths"):
                filters_by_event[ev] = [str(g) for g in cfg["paths"]]
        globs = sorted({g for fl in filters_by_event.values() for g in fl})
        job_cfgs = doc.get("jobs") or {}
        jobs = sorted(job_cfgs.keys())
        # A job-level `if:` can skip the job even when the trigger paths
        # match (tests-root.yml skips its sole job on fork PRs), so a
        # workflow whose every job is conditional does not necessarily
        # execute for a matching change. But conditions are classified per
        # triggering event, not counted syntactically: a job gated on
        # `github.event_name == 'pull_request'` is guaranteed for the
        # pull_request event, and treating it as conditional discarded the
        # real hosted PR gate whenever an event-specific sibling job (a
        # manual-only lane) also declared an `if:`. Each event's verdict is
        # recorded on the GATES edges so Q1/Q2 and the reports can separate
        # guaranteed coverage from coverage that depends on the run context.
        conditional_jobs = sorted(
            name
            for name, cfg in job_cfgs.items()
            if isinstance(cfg, dict) and cfg.get("if") is not None
        )
        all_jobs_conditional = bool(jobs) and len(conditional_jobs) == len(jobs)
        conditional_by_event = {
            ev: bool(jobs)
            and not any(job_guaranteed_for_event(cfg, ev) for cfg in job_cfgs.values())
            for ev in filters_by_event
        }
        # The graph key is the repository-relative workflow path: two workflow
        # files may share one display `name:`, and keying on the name made the
        # second file overwrite the first's node (path, jobs, filters) while
        # both files' GATES edges were attributed to a single workflow,
        # undercounting distinct gates in Q1/Q2. `name` stays display-only.
        wkey = rel
        wname = doc.get("name") or f.stem
        # path_filters is a sorted union kept for cross-event overviews; it
        # loses both event association and pattern order, so each event's
        # filter list is also published verbatim (path_filters_push,
        # path_filters_pull_request). Without those, Q1 showed a push-only
        # deploy filter beside a PR-only filter with no way to tell which
        # event actually gates a given path.
        per_event = {f"path_filters_{ev}": fl for ev, fl in filters_by_event.items()}
        G.node(
            "Workflow",
            wkey,
            extra_labels=("CIGate",),
            name=wname,
            path=rel,
            triggers=triggers,
            path_filters=globs,
            jobs=jobs,
            job_count=len(jobs),
            path_filtered=bool(globs),
            conditional_jobs=conditional_jobs,
            all_jobs_conditional=all_jobs_conditional,
            **per_event,
        )
        G.rel("DEFINED_IN", "Workflow", wkey, "File", rel)
        if not filters_by_event:
            continue
        compiled = {ev: compile_path_filters(fl) for ev, fl in filters_by_event.items()}
        for path in files:
            # Parent workflows gate only ordinary parent-tracked paths. A
            # file inside an initialized submodule's own repository can never
            # appear in a parent PR (the parent only ever changes the
            # gitlink, which is itself a parent-tracked path matched on its
            # own line), so a filter that happens to cover the inner path
            # (packages/Acgs-Swarm/src/...) minted GATES edges that hid the
            # file from Q2 and reported false CI×N coverage.
            slot = G.nodes.get(("File", path))
            if slot is not None and slot["props"].get("in_submodule"):
                continue
            events = sorted(
                ev for ev, filters in compiled.items() if match_path_filters(path, filters)
            )
            if events:
                # conditional_events lists the matching events with no job
                # guaranteed to run; `conditional` summarises the edge (every
                # matching event is conditional). Consumers that prove one
                # event's coverage (Q1/Q2, the reports, the verifier) must
                # test their event against conditional_events, not the
                # summary — a push+pull_request edge whose only guaranteed
                # job is PR-gated is unconditional for PRs but not for push.
                conditional_events = [ev for ev in events if conditional_by_event[ev]]
                G.rel(
                    "GATES",
                    "Workflow",
                    wkey,
                    "File",
                    path,
                    events=events,
                    conditional=len(conditional_events) == len(events),
                    conditional_events=conditional_events,
                )
                gates += 1
    log(
        f"E5. workflows: {sum(1 for (label, _) in G.nodes if label == 'Workflow')} workflows, "
        f"{gates} GATES edges"
    )


def build_policies() -> None:
    roots = [ROOT / "automation" / "policies", ROOT / ".claude" / "policy"]
    extra = [ROOT / "automation" / "constitution.yaml", ROOT / "automation" / "registry.yaml"]
    n = 0
    seen: list[Path] = []
    for r in roots:
        if r.is_dir():
            seen += sorted(
                p for p in r.rglob("*") if p.is_file() and p.suffix in (".yaml", ".yml", ".json")
            )
    seen += [p for p in extra if p.is_file()]
    for p in seen:
        rel = p.relative_to(ROOT).as_posix()
        # Same live-and-tracked source predicate as workflows, ADRs, links,
        # and mapping documents: an untracked local draft, or a policy
        # removed from the index but left on disk, will not exist in a
        # checkout, so this filesystem scan must not mint a current Policy
        # node (or DEFINED_IN, via a semantic-retained File node) for it.
        if not (G.has("File", rel) and file_is_live(rel)):
            continue
        pkey = rel
        G.node(
            "Policy",
            pkey,
            name=p.stem,
            path=rel,
            kind="constitution" if "constitution" in p.stem else "policy",
        )
        G.rel("DEFINED_IN", "Policy", pkey, "File", rel)
        n += 1
    log(f"E6. policies: {n}")


def porcelain_paths(raw: str) -> list[str]:
    """Working-tree paths from ``git status --porcelain -z``.

    The NUL-terminated form is the machine-readable one: paths are never
    quoted, and a rename/copy record is ``XY <destination>`` NUL ``<origin>``
    NUL. Slicing the space-separated v1 line at character three produced
    ``old.py -> new.py``, a string matching no ``File.key``, so the renamed
    destination silently never received ``dirty_at_extract``. The destination
    pathname is the one that exists in the working tree, so it is the one
    recorded; the origin record is consumed and dropped.
    """
    paths: list[str] = []
    entries = iter(raw.split("\0"))
    for entry in entries:
        if not entry:
            continue
        status, path = entry[:2], entry[3:]
        paths.append(path)
        if "R" in status or "C" in status:
            next(entries, None)  # the origin path of a rename/copy record
    return paths


def collect_dirty_paths() -> list[str]:
    """Working-tree dirt across the parent repo AND every initialized
    submodule. The parent's porcelain reports a change inside a submodule only
    as the gitlink path; without descending, the inner File node never receives
    ``dirty_at_extract`` and Q7 silently omits ADRs governing that change."""
    dirty = porcelain_paths(run("git", "status", "--porcelain", "-z"))
    for sm in initialized_submodules():
        sub = subprocess.run(
            ["git", "-C", str(ROOT / sm), "status", "--porcelain", "-z"],
            check=False,
            text=True,
            capture_output=True,
        )
        if sub.returncode == 0:
            dirty.extend(f"{sm}/{p}" for p in porcelain_paths(sub.stdout))
    return dirty


def semantic_snapshot_props(
    head: str, dirty: Sequence[str] = (), tracked: Sequence[str] = ()
) -> dict:
    """Snapshot fields describing the semantic layer.

    Availability is derived from UA_GRAPH — the artifact build_semantic()
    actually loads — never from meta.json. The two are generated together but
    can be independently deleted: metadata without a graph would publish a
    semantic commit (potentially even marking it current) for a layer no query
    can reach, while a graph without metadata is loaded but unverifiable, so
    it must be recorded as stale rather than labelled absent.

    Commit equality alone is not currency: a layer generated at the current
    HEAD still describes the *committed* contents, so a dirty working-tree
    edit to a file the graph analyzed means its summaries and TESTED_BY edges
    no longer match what is being reported. Any dirty path with semantic
    coverage marks the layer stale, and the offending paths are published as
    ``semantic_dirty_paths``. A dirty gitlink is dirt too: a submodule
    checked out at a different commit while the parent HEAD is unchanged
    surfaces in porcelain only as the submodule root path, so a dirty path
    also invalidates its analyzed descendants.

    Coverage of the live tree matters too: a staged new file, or the
    destination of a ``git mv``, is dirty but absent from the snapshot, so
    intersecting dirt with analyzed paths alone still published the layer as
    current while the tracked tree carried code it never analyzed. Dirty
    tracked paths lacking semantic coverage mark the layer stale and are
    published as ``semantic_uncovered_paths``, restricted to extensions the
    snapshot demonstrably analyzes, because dirt in file types the analyzer
    does not process (docs, config) says nothing about the layer's currency.
    """
    loaded = UA_GRAPH.exists()
    if not loaded:
        return {"semantic_layer_loaded": False}
    meta = json.loads(UA_META.read_text()) if UA_META.exists() else {}
    analyzed = {
        n["filePath"]
        for n in json.loads(UA_GRAPH.read_text()).get("nodes", [])
        if n.get("filePath")
    }
    # Exact intersection alone misses a dirty gitlink: an initialized
    # submodule checked out at a different commit is reported by porcelain
    # only as the submodule root path, while every analyzed file beneath it
    # may describe another revision. Any dirty path is therefore treated as
    # invalidating both itself and its analyzed descendants.
    dirty_exact = {p.rstrip("/") for p in dirty}
    dirty_prefixes = tuple(f"{p}/" for p in dirty_exact)
    dirty_analyzed = sorted(p for p in analyzed if p in dirty_exact or p.startswith(dirty_prefixes))
    analyzed_exts = {os.path.splitext(p)[1].lower() for p in analyzed}
    dirty_uncovered = sorted(
        p
        for p in set(tracked).intersection(dirty)
        if p not in analyzed and os.path.splitext(p)[1].lower() in analyzed_exts
    )
    return {
        "semantic_layer_loaded": True,
        "ua_commit": meta.get("gitCommitHash"),
        "ua_analyzed_at": meta.get("lastAnalyzedAt"),
        "ua_analyzed_files": meta.get("analyzedFiles"),
        "semantic_layer_is_stale": meta.get("gitCommitHash") != head
        or bool(dirty_analyzed)
        or bool(dirty_uncovered),
        "semantic_dirty_paths": dirty_analyzed,
        "semantic_uncovered_paths": dirty_uncovered,
    }


# --------------------------------------------------------------------------- #
def main() -> int:
    head = run("git", "rev-parse", "HEAD").strip()
    branch = run("git", "rev-parse", "--abbrev-ref", "HEAD").strip()
    dirty = collect_dirty_paths()
    snapshot_key = head[:12]
    # The spine is built first: semantic staleness needs the tracked path
    # list, so a staged new file (dirty, tracked, uncovered) can mark the
    # layer stale rather than hiding behind the analyzed-paths intersection.
    tracked = build_spine()
    G.node(
        "Snapshot",
        snapshot_key,
        git_head=head,
        git_branch=branch,
        generated_at=datetime.now(UTC).isoformat(),
        dirty_paths=dirty,
        dirty_count=len(dirty),
        **semantic_snapshot_props(head, dirty, tracked),
    )

    build_semantic(snapshot_key)
    # One history per repo — submodules are independent repos — then merged and
    # sorted so "recent commits" is recent across all of them, not per-repo.
    history = parse_history()
    for sm in initialized_submodules():
        sub = parse_history(sm, prefix=f"{sm}/")
        log(f"    + history {sm}: {len(sub)} commits")
        history += sub
    history.sort(key=lambda c: c["ts"], reverse=True)
    build_history(history)
    build_topology(tracked)
    build_sealed(tracked)
    build_adrs()
    build_doc_links()
    build_controls()
    build_workflows(tracked)
    build_policies()

    G.node("Snapshot", snapshot_key, **CONTROL_STATS, **SEALED_STATS)

    # dirty-vs-snapshot honesty flag
    for p in dirty:
        if G.has("File", p):
            G.node("File", p, dirty_at_extract=True)

    out = G.dump()
    out["snapshot"] = snapshot_key
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out))
    by_label = Counter(n["label"] for n in out["nodes"])
    by_rel = Counter(r["type"] for r in out["rels"])
    log(f"wrote {OUT.relative_to(ROOT)}: {len(out['nodes'])} nodes / {len(out['rels'])} rels")
    log("  nodes: " + ", ".join(f"{k}={v}" for k, v in by_label.most_common()))
    log("  rels : " + ", ".join(f"{k}={v}" for k, v in by_rel.most_common()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
