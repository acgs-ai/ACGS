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


def build_spine() -> list[str]:
    """Parent-tracked paths plus, for each checked-out submodule, its own
    tracked paths prefixed with the submodule path. `git ls-files` in the
    parent only yields the gitlink, so without this the whole graph stops at
    the submodule boundary and every submodule-scoped fact silently vanishes.
    """
    tracked = [p for p in run("git", "ls-files").splitlines() if p]
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
            present=True,
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
            slot["props"].setdefault("present", True)
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
def parse_history(repo: str = ".", prefix: str = "") -> list[dict]:
    """Commits of one repo. Submodules are separate histories, so this is
    called once per repo and paths are prefixed back onto the parent's spine."""
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
        return []
    raw = proc.stdout
    commits: list[dict] = []
    cur: dict | None = None
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
                path = re.sub(r"\{[^}]*=> ([^}]*)\}", r"\1", path)
                if " => " in path:
                    path = path.split(" => ")[-1]
                path = path.replace("//", "/")
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
            s["authors"].add(c["author"])
            s["last"] = max(s["last"] or 0, c["ts"])
            s["first"] = min(s["first"] or c["ts"], c["ts"])
        if 1 < len(c["files"]) <= COCHANGE_MAX_FILES:
            paths = sorted(c["files"])
            for i, a in enumerate(paths):
                for b in paths[i + 1 :]:
                    pair_counts[(a, b)] += 1

    now = datetime.now(UTC).timestamp()
    max_churn = max((s["add"] + s["dele"] for s in stats.values()), default=1) or 1
    for path, s in stats.items():
        if not G.has("File", path):
            continue  # deleted / renamed-away path: no live spine node
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
        ckey = c["sha"][:12]
        G.node(
            "Commit",
            ckey,
            sha=c["sha"],
            short_sha=ckey,
            subject=c["subject"],
            author=c["author"],
            date=datetime.fromtimestamp(c["ts"], UTC).isoformat(),
            file_count=len(c["files"]),
            churn=sum(a + d for a, d in c["files"].values()),
            repo=c.get("repo", "."),
        )
        G.node("Author", c["email"], name=c["author"], email=c["email"])
        G.rel("AUTHORED", "Author", c["email"], "Commit", ckey)
        for path, (add, dele) in c["files"].items():
            G.rel("TOUCHED", "Commit", ckey, "File", path, added=add, deleted=dele)

    kept = 0
    for (a, b), n in pair_counts.most_common():
        if n < COCHANGE_MIN_COUNT or kept >= COCHANGE_TOP_N:
            break
        if not (G.has("File", a) and G.has("File", b)):
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
        pkg = next((p for p in pkg_paths if key.startswith(p + "/")), ".")
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
HASH_MARKER = re.compile(r"Constitutional Hash:\s*`?([0-9a-f]{8,64})`?")

# Imported, never copied. A hand-duplicated copy of the gate's coverage goes
# stale the day the gate changes, and the graph would then report a governance
# gap that no longer exists — or miss one that does.
sys.path.insert(0, str(ROOT / "scripts"))
try:
    from verify_constitutional_hashes import SCAN_EXTENSIONS as HASH_GATED_EXTENSIONS
    from verify_constitutional_hashes import SKIP_FILES as _GATE_SKIP_FILES
except ImportError:  # degrade loudly, never silently
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
    lock = ROOT / "docs" / "constitutional-hashes.lock"
    if lock.exists():
        data = json.loads(lock.read_text())
        for path, value in data.get("hashes", {}).items():
            G.node("Hash", value, extra_labels=("ConstitutionalHash",), value=value)
            if G.has("File", path):
                G.node("File", path, sealed=True, sealed_hash=value, in_hash_lock=True)
                G.rel("SEALED_WITH", "File", path, "Hash", value)
            else:
                pkg = next(
                    (p for (lbl, p) in G.nodes if lbl == "Package" and path.startswith(p + "/")),
                    None,
                )
                absent[pkg or "?"] += 1
        for pkg, n in absent.items():
            if G.has("Package", pkg):
                G.node("Package", pkg, sealed_files_absent=n)
    log(
        f"E1. sealed: {present} live markers in the working tree "
        f"({ungated} in file types the hash gate never scans), "
        f"{sum(absent.values())} lock entries in uninitialized submodules"
    )


ADR_REF = re.compile(r"ADR[- ](\d{4})")
PATH_TOKEN = re.compile(r"`([\w./@-]+/[\w./@-]+)`")
MD_LINK = re.compile(r"\[[^\]]*\]\(([^)\s#]+)")


CODE_TOKEN = re.compile(r"`([\w./@-]+\.[A-Za-z0-9]{1,6})(?::\d+)?`")
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
            for tok in set(PATH_TOKEN.findall(text)) | set(MD_LINK.findall(text)):
                hit = resolve_link(src, tok.split(":")[0])
                if hit:
                    scope.add(hit)
        _DOC_SCOPE[src] = scope
    return _DOC_SCOPE[src]


def resolve_token(src: str, token: str) -> tuple[str | None, int | None, str | None]:
    """Resolve a doc token to (path, line, method).

    method is how much the resolution is worth: `path` (explicit and
    unambiguous), `basename` (bare name that happens to be unique in the
    workspace), `basename-docscope` (bare name disambiguated by a full path the
    same document names elsewhere). None when unresolved.
    """
    line = None
    m = re.match(r"^(.*?):(\d+)$", token)
    if m:
        token, line = m.group(1), int(m.group(2))
    hit = resolve_link(src, token)
    if hit:
        return hit, line, "path"
    if "/" in token:
        return None, None, None

    cands = basename_index().get(token, [])
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


def resolve_link(src: str, target: str) -> str | None:
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
    else:
        cands = [
            target,  # repo-root-relative
            os.path.normpath(os.path.join(os.path.dirname(src), target)),  # doc-relative
        ]
    for cand in cands:
        cand = cand.replace("\\", "/")
        if G.has("File", cand):
            return cand
    return None


def build_adrs() -> None:
    adr_dir = ROOT / "docs" / "adr"
    if not adr_dir.is_dir():
        return
    count = 0
    for f in sorted(adr_dir.glob("*.md")):
        rel = f.relative_to(ROOT).as_posix()
        text = f.read_text(errors="replace")
        m = re.search(r"^#\s+(.+)$", text, re.M)
        title = m.group(1).strip() if m else f.stem
        # A section ends at a blank line, at the next heading, or at end of file.
        # Without the \Z alternative an ADR whose Status is its last section
        # parsed as "Unknown" — a silent field loss, not an error.
        st = re.search(r"^##\s+Status\s*\n+(.+?)(?:\n\s*\n|\n##|\Z)", text, re.M | re.S)
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
        toks = (
            set(PATH_TOKEN.findall(text))
            | set(MD_LINK.findall(text))
            | set(CODE_TOKEN.findall(text))
        )
        for tok in toks:
            tgt, _, _ = resolve_token(rel, tok)
            if tgt and tgt != rel:
                G.rel("DECIDES_ON", "ADR", akey, "File", tgt)
    log(f"E2. adrs: {count} ADRs")


def build_doc_links() -> None:
    n = 0
    for (lbl, key), slot in list(G.nodes.items()):
        if lbl != "File" or not key.endswith((".md", ".mdx")):
            continue
        f = ROOT / key
        if not f.is_file():
            continue
        text = f.read_text(errors="replace")
        targets = set()
        for tok in set(MD_LINK.findall(text)) | set(PATH_TOKEN.findall(text)):
            tgt = resolve_link(key, tok)
            if tgt and tgt != key:
                targets.add(tgt)
        for tgt in targets:
            G.rel("LINKS_TO", "File", key, "File", tgt)
            n += 1
    log(f"E3. doc links: {n} resolved in-repo references")


CONTROL_PATTERNS = [
    ("EU AI Act", re.compile(r"Art(?:icle)?\.?\s*(\d+)\((\d+)\)(?:\(([a-z])\))?")),
    ("HIPAA", re.compile(r"§\s*(164\.\d+(?:\([a-z0-9]\))*)")),
    ("NIST AI RMF", re.compile(r"\b(GOVERN|MAP|MEASURE|MANAGE)[-. ](\d+\.\d+)\b")),
    ("ISO/IEC 42001", re.compile(r"\b(?:Annex\s+)?(A\.\d+\.\d+(?:\.\d+)?)\b")),
    ("SOC 2", re.compile(r"\b(CC\d\.\d+)\b")),
]
# A scope citing more than this many distinct controls is an index/enumeration,
# not an evidence binding. See ADR-0012 and the compliance tier report.
MAX_CONTROLS_PER_EVIDENCE_SCOPE = 2
# Filled by build_controls, published on the (:Snapshot) node for reports.
CONTROL_STATS: dict[str, int] = {}

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
        return f"EU AI Act Art {art}({para})" + (f"({lit})" if lit else "")
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
        if not f.is_file():
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

                evidence: dict[str, tuple[int | None, str]] = {}
                for tok in set(PATH_TOKEN.findall(line)) | set(CODE_TOKEN.findall(line)):
                    tgt, ln, method = resolve_token(rel, tok)
                    if tgt and tgt != rel:
                        # How the token resolved decides how much it is worth.
                        # An explicit repo path is unambiguous; a bare basename
                        # survives only because it happens to be unique in the
                        # workspace, which is luck, not evidence.
                        evidence.setdefault(tgt, (ln, method))
                        if method != "path":
                            by_basename += 1
                for framework, cid in hits:
                    for tgt, (ln, method) in evidence.items():
                        G.rel(
                            "EVIDENCED_BY",
                            "Control",
                            cid,
                            "File",
                            tgt,
                            cited_line=ln,
                            cited_in=rel,
                            resolved_by=method,
                        )
                        evidences += 1
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
        globs: list[str] = []
        for ev in ("push", "pull_request"):
            cfg = on.get(ev) or {}
            if isinstance(cfg, dict):
                globs += [g for g in (cfg.get("paths") or []) if not g.startswith("!")]
        globs = sorted(set(globs))
        jobs = sorted((doc.get("jobs") or {}).keys())
        wkey = doc.get("name") or f.stem
        G.node(
            "Workflow",
            wkey,
            extra_labels=("CIGate",),
            name=wkey,
            path=rel,
            triggers=triggers,
            path_filters=globs,
            jobs=jobs,
            job_count=len(jobs),
            path_filtered=bool(globs),
        )
        G.rel("DEFINED_IN", "Workflow", wkey, "File", rel)
        if not globs:
            continue
        pats = [glob_to_regex(g) for g in globs]
        for path in files:
            if any(p.match(path) for p in pats):
                G.rel("GATES", "Workflow", wkey, "File", path)
                gates += 1
    log(
        f"E5. workflows: {sum(1 for (l, _) in G.nodes if l == 'Workflow')} workflows, "
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


# --------------------------------------------------------------------------- #
def main() -> int:
    head = run("git", "rev-parse", "HEAD").strip()
    branch = run("git", "rev-parse", "--abbrev-ref", "HEAD").strip()
    dirty = [l[3:] for l in run("git", "status", "--porcelain").splitlines()]
    ua_meta = json.loads(UA_META.read_text()) if UA_META.exists() else {}
    snapshot_key = head[:12]
    G.node(
        "Snapshot",
        snapshot_key,
        git_head=head,
        git_branch=branch,
        generated_at=datetime.now(UTC).isoformat(),
        ua_commit=ua_meta.get("gitCommitHash"),
        ua_analyzed_at=ua_meta.get("lastAnalyzedAt"),
        ua_analyzed_files=ua_meta.get("analyzedFiles"),
        semantic_layer_is_stale=ua_meta.get("gitCommitHash") != head,
        dirty_paths=dirty,
        dirty_count=len(dirty),
    )

    tracked = build_spine()
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

    G.node("Snapshot", snapshot_key, **CONTROL_STATS)

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
