#!/usr/bin/env python3
"""Deterministic acceptance gate for MUTATION_AUTHORITY_INTEGRATION_V1.

Usage:
    python3 verify_mutation_integration.py

Runs the integration attack suite (A-G), the structural integration
checks, and a full re-run of the kernel suite for compatibility. Prints
ALL CHECKS PASSED only if every check holds. Exit 0 on success, 1 on any
failure. Stdlib only; logical clock; reproducible.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mutation_authority.integration_verification import (
    run_all_integration_checks,
)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="mutation-authority-integ-") as tmp:
        results = run_all_integration_checks(Path(tmp))

    width = max(len(r.name) for r in results)
    failures = 0
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f"[{status}] {result.name.ljust(width)}  {result.detail}")
        if not result.passed:
            failures += 1

    print()
    if failures:
        print(f"{failures} CHECK(S) FAILED")
        return 1
    print("verified coverage: mutations routed through the runtime adapter only")
    print("before: agent → possible mutation → audit afterwards")
    print("after:  agent → intent → authority decision → receipt → effect → evidence")
    print("no valid receipt, no mutation — on every integrated path")
    print()
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
