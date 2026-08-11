#!/usr/bin/env python3
"""Verify a candidate substrate against the bound identity manifest. Read-only.

Answers "is the substrate at this path the same substrate?" — by bytes, not by
pathname — so a relocated-but-identical substrate confirms and any drift fails
closed. Never writes into the substrate; never regenerates the manifest.

Usage:
    python3 verify_substrate_identity.py [CANDIDATE_ROOT]

Exit codes: 0 IDENTITY_CONFIRMED · 3 IDENTITY_MISMATCH · 4 IDENTITY_UNVERIFIABLE
· 5 SUBSTRATE_DRIFT · 2 manifest missing/unreadable.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from _identity import (
    IDENTITY_CONFIRMED,
    IDENTITY_MISMATCH,
    IDENTITY_UNVERIFIABLE,
    MANIFEST_NAME,
    SUBSTRATE_DRIFT,
    verify_manifest,
)
from _substrate import resolve_root

HERE = Path(__file__).resolve().parent
_EXIT = {
    IDENTITY_CONFIRMED: 0,
    IDENTITY_MISMATCH: 3,
    IDENTITY_UNVERIFIABLE: 4,
    SUBSTRATE_DRIFT: 5,
}


def load_manifest() -> dict:
    p = HERE / MANIFEST_NAME
    if not p.is_file():
        raise FileNotFoundError(f"{MANIFEST_NAME} not found — run build_substrate_identity.py")
    with p.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: list[str]) -> int:
    try:
        manifest = load_manifest()
    except (OSError, ValueError) as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2
    candidate = resolve_root(argv[0] if argv else None)
    result = verify_manifest(manifest, candidate)

    print(f"candidate_root      : {result['candidate_root']}")
    print(f"substrate_id        : {manifest.get('substrate_id')}")
    print(f"state               : {result['state']}")
    print(
        f"critical_set_digest : {'match' if result['critical_set_digest_matches'] else 'MISMATCH'}"
    )
    if result["mismatched"]:
        print(f"mismatched          : {result['mismatched']}")
    if result["absent"]:
        print(f"absent              : {result['absent']}")
    if result["count_drift"]:
        print(f"count_drift         : {json.dumps(result['count_drift'])}")
    return _EXIT.get(result["state"], 6)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
