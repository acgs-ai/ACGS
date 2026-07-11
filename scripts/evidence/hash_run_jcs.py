#!/usr/bin/env python3
"""Print lowercase SHA-256 of RFC 8785 canonical run JSON bytes."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from _common import (
    EvidenceError,
    assert_evidence_runtime,
    canonical_node_evidence_path,
    fail,
    jcs_bytes,
    load_json,
    validate_schema,
    validate_secret_free_run,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    args = parser.parse_args(argv)
    try:
        repo_root = assert_evidence_runtime(require_dependencies=True)
        if not args.run.is_absolute():
            fail("run hash input must be absolute", phase="B6")
        run_path = canonical_node_evidence_path(
            args.run,
            repo_root,
            node_id=args.run.parent.name,
            filename="run.json",
            must_exist=True,
        )
        value = load_json(run_path)
        validate_secret_free_run(value, expected_node=run_path.parent.name)
        validate_schema(value, repo_root / "schemas/evidence/acgs-run-evidence-v1.schema.json")
        print(hashlib.sha256(jcs_bytes(value)).hexdigest())
        return 0
    except EvidenceError as exc:
        print(f"run JCS hash failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
