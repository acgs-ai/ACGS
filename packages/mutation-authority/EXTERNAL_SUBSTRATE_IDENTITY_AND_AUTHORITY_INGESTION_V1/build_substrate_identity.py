#!/usr/bin/env python3
"""Build the canonical substrate identity manifest (Phase A).

Enumerates the fixed critical-object set of the external
COMMERCIAL_BUYER_READINESS_V1 substrate, hashes each object, re-derives the
structural counts from the live registries, and writes ``substrate_identity.json``
into THIS package directory. It never writes into the substrate.

Usage:
    python3 build_substrate_identity.py [SUBSTRATE_ROOT] [--class CLASS]

SUBSTRATE_ROOT defaults to $ACGS_COMMERCIAL_SUBSTRATE_ROOT or the observed
canonical path. CLASS is the identity classification recorded in the manifest;
default EXACT_PRIOR_SUBSTRATE (justified only by path-binding + exact hashes +
exact counts — see REPORT.md).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from _identity import MANIFEST_NAME, build_manifest
from _substrate import resolve_root

HERE = Path(__file__).resolve().parent


def main(argv: list[str]) -> int:
    args = [a for a in argv if a != "-"]
    identity_class = "EXACT_PRIOR_SUBSTRATE"
    if "--class" in args:
        i = args.index("--class")
        identity_class = args[i + 1]
        del args[i : i + 2]
    root = resolve_root(args[0] if args else None)

    if not root.is_dir():
        print(f"FATAL: substrate root not a directory: {root}", file=sys.stderr)
        return 2
    try:
        manifest = build_manifest(root, identity_class)
    except Exception as exc:
        print(f"FATAL: cannot build identity: {exc}", file=sys.stderr)
        return 2

    out = HERE / MANIFEST_NAME
    out.write_text(
        json.dumps(manifest, indent=1, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"substrate_id        : {manifest['substrate_id']}")
    print(f"critical_set_digest : {manifest['critical_set_digest']}")
    print(f"critical_objects    : {manifest['critical_object_count']}")
    print(f"identity_class      : {manifest['identity_class']}")
    print(f"path_binding        : {manifest['path_binding']['verified']}")
    print(f"expected_counts     : {json.dumps(manifest['expected_counts'])}")
    print(f"written             : {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
