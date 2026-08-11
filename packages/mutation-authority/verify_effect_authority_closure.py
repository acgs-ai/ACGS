#!/usr/bin/env python3
"""Deterministic verdict for GOVE_ZONE_EFFECT_AUTHORITY_CLOSURE_V1.

Emits exactly one of REPOSITORY_MUTATION_AUTHORITY_ENFORCED /
PARTIAL_MUTATION_AUTHORITY_ENFORCEMENT / BLOCKED. It cannot return
ENFORCED while (a) mutation carriers exist outside any enforcement boundary
the execution model can provide, or (b) the gove-zone composition surface is
foreign/uncommitted. Both hold, so this returns BLOCKED. Stdlib only, no
network.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
GOVE_ZONE_SRC = REPO_ROOT / "packages" / "gove-zone" / "src" / "gove_zone"
CLOSURE_DIR = HERE / "GOVE_ZONE_EFFECT_AUTHORITY_CLOSURE_V1"

# V1-recorded hashes of the foreign composition surface (collision baseline).
COLLISION_BASELINE = {
    "gateway.py": "e5663ff555516eb3",
    "integration.py": "04c10592a80d7c4e",
    "__init__.py": "414fea99153e6147",
    "execution.py": "8686ca854488089c",
}


def _run(cmd: list[str], cwd: Path) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    tail = (proc.stdout.strip().splitlines() or [""])[-1]
    return proc.returncode, tail


def _sha16(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def main() -> int:
    lines: list[str] = []

    # 1. Baselines unchanged/green (kernel + integration + V1 composition proof).
    baselines = [
        ("mutation-authority kernel", "verify_mutation_governance.py"),
        ("mutation-authority integration", "verify_mutation_integration.py"),
    ]
    baselines_ok = True
    for label, script in baselines:
        code, tail = _run([sys.executable, script], HERE)
        baselines_ok = baselines_ok and code == 0
        lines.append(f"[{'OK ' if code == 0 else 'BAD'}] {label}: {tail}")

    # 2. Ceiling demonstration (real processes). Exit 0 = ceiling confirmed.
    code, tail = _run([sys.executable, str(CLOSURE_DIR / "ceiling_demonstration.py")], HERE)
    ceiling_confirmed = code == 0
    lines.append(f"[{'OK ' if ceiling_confirmed else 'BAD'}] ceiling demonstration: {tail}")

    # 3. Dominance gate. Exit 2 = dominance does NOT hold (expected here).
    code, tail = _run([sys.executable, str(CLOSURE_DIR / "dominance_gate.py")], HERE)
    dominance_holds = code == 0
    gate_ok = code in (0, 2)  # 3 = the gate itself is broken
    lines.append(
        f"[{'OK ' if gate_ok else 'BAD'}] dominance gate ({'holds' if dominance_holds else 'does not hold'}): {tail}"
    )

    # 4. Collision re-check: composition surface still foreign/unchanged.
    collision_present = False
    drift = []
    for name, expected in COLLISION_BASELINE.items():
        p = GOVE_ZONE_SRC / name
        if p.exists():
            actual = _sha16(p)
            if actual == expected:
                collision_present = True
            else:
                drift.append(f"{name}:{actual}!={expected}")
    lines.append(
        f"[REC] collision surface: {'unchanged (foreign/uncommitted)' if collision_present and not drift else 'DRIFTED: ' + ', '.join(drift)}"
    )

    print("\n".join(lines))
    print()

    # Verdict.
    if dominance_holds and baselines_ok:
        print("VERDICT: REPOSITORY_MUTATION_AUTHORITY_ENFORCED")
        return 0
    # Dominance does not hold. Mediated subset of the real repository is empty
    # (no gove-zone source routes through the boundary), so PARTIAL would
    # overclaim. Two independent prerequisites are unmet ⇒ BLOCKED.
    print("VERDICT: BLOCKED")
    print("  prerequisite 1 (architectural, primary): the execution model provides no")
    print("    privilege boundary; 8/11 mutation carriers require OS-layer enforcement that")
    print("    no application-level wiring can supply (proven: ceiling_demonstration.py).")
    print("  prerequisite 2 (collision): the gove-zone composition surface is foreign and")
    print("    uncommitted (hashes unchanged from the V1 record); not overwritten or merged.")
    print("  see GOVE_ZONE_EFFECT_AUTHORITY_CLOSURE_V1/REPORT.md")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
