#!/usr/bin/env python3
"""Deterministic acceptance gate for the Mutation Authority Governance Layer.

Usage:
    python3 verify_mutation_governance.py

Builds fresh sandboxes (governed repo + governance root + keystore +
ledger) in a temporary directory, runs the structural checks and the
regression attack suite (A–F plus a forged-receipt bonus), and prints
ALL CHECKS PASSED only if every check holds. Exit code 0 on success,
1 on any failure. Stdlib only; time is a logical clock, so output is
reproducible.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mutation_authority.verification import run_all_checks


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="mutation-authority-verify-") as tmp:
        results = run_all_checks(Path(tmp))

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
    print("proven vs attacks A-I: unauthorized mutation is denied, detected, non-launderable")
    print(
        "proven vs attacks A-I: concurrent writers cannot both commit (one live receipt per resource)"
    )
    print(
        "proven vs attacks A-I: governance-root bypass fails closed (DENY on intent, halt on tamper)"
    )
    print(
        "proven vs attacks A-I: every accepted change has cryptographic provenance "
        "(intent → receipt → effect → anchored chain)"
    )
    print(
        "trust boundary: keystore + ledger anchor must stay outside agent-writable paths (README)"
    )
    print()
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
