#!/usr/bin/env python3
"""Deterministic verdict for GOVE_ZONE_MUTATION_AUTHORITY_WIRING_V1.

This command does NOT print "ALL CHECKS PASSED" and CANNOT return 0 while the
gove-zone wiring is incomplete. It verifies only what is honestly verifiable —
the mutation-authority baseline is unchanged and green, the two-receipt
composition binding is sound, and (the coverage gate) whether gove-zone
actually routes any mutation executor through MutationGateway — and then emits
an explicit verdict.

`gateway dominance` (success criteria #1/#2: every governed gove-zone mutation
path mediated by MutationGateway, execution cannot occur before receipt
validation) is UNVERIFIABLE here: the dominating executor
(gove_zone `execute_with_receipt`, and the in-flight `execution.py`
classifier) is out of scope — foreign, uncommitted, mid-flight — and nothing
in gove-zone imports this package. The coverage gate detects exactly that and
returns INTEGRATION INCOMPLETE. Stdlib only, no network.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
GOVE_ZONE_SRC = REPO_ROOT / "packages" / "gove-zone" / "src" / "gove_zone"
WIRING_DIR = HERE / "GOVE_ZONE_MUTATION_AUTHORITY_WIRING_V1"

# Foreign, in-flight integration targets (the choke-point surface). Their
# presence as uncommitted/untracked work is the collision this run refuses to
# merge into. Recorded, not touched.
COLLISION_TARGETS = [
    GOVE_ZONE_SRC / "gateway.py",
    GOVE_ZONE_SRC / "integration.py",
    GOVE_ZONE_SRC / "execution.py",
    GOVE_ZONE_SRC / "__init__.py",
]


def _run(cmd: list[str], cwd: Path) -> tuple[bool, str]:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    tail = (proc.stdout.strip().splitlines() or [""])[-1]
    return proc.returncode == 0, tail


def main() -> int:
    lines: list[str] = []
    ok = True

    # 1. Baseline: mutation-authority kernel + integration gates unchanged/green.
    for label, script in (
        ("mutation-authority kernel baseline", "verify_mutation_governance.py"),
        ("mutation-authority integration baseline", "verify_mutation_integration.py"),
    ):
        passed, tail = _run([sys.executable, script], HERE)
        lines.append(f"[{'OK ' if passed else 'BAD'}] {label}: {tail}")
        ok = ok and passed

    # 2. Composition binding proof (design-proof on a gove-zone double).
    passed, tail = _run([sys.executable, str(WIRING_DIR / "composition_proof.py")], HERE)
    lines.append(f"[{'OK ' if passed else 'BAD'}] two-receipt composition binding proof: {tail}")
    ok = ok and passed

    # 3. Collision record: the choke-point surface is foreign/in-flight.
    present = [p for p in COLLISION_TARGETS if p.exists()]
    lines.append(
        f"[REC] collision surface present (foreign, not modified): "
        f"{len(present)}/{len(COLLISION_TARGETS)} targets — " + ", ".join(p.name for p in present)
    )

    # 4. COVERAGE GATE (the structural dominance check). If gove-zone genuinely
    #    routed mutation through this package, its source would import it.
    #    Zero references ⇒ MutationGateway mediates nothing in gove-zone ⇒
    #    dominance is NOT established.
    refs = 0
    if GOVE_ZONE_SRC.is_dir():
        for py in GOVE_ZONE_SRC.rglob("*.py"):
            text = py.read_text(encoding="utf-8", errors="replace")
            if "mutation_authority" in text or "MutationGateway" in text:
                refs += 1
    dominance_established = refs > 0
    lines.append(
        f"[{'OK ' if dominance_established else 'GAP'}] gateway dominance: "
        f"{refs} gove-zone source file(s) reference MutationGateway"
        + ("" if dominance_established else " — NOT mediated (no wiring present)")
    )

    print("\n".join(lines))
    print()

    # Verdict. Dominance unproven ⇒ INTEGRATION INCOMPLETE regardless of the
    # green sub-checks. This command never returns 0 while unwired.
    if dominance_established and ok:
        print("gove-zone mutation-authority wiring VERIFIED")
        return 0
    print("INTEGRATION INCOMPLETE: gateway dominance unverifiable (collision + no wiring)")
    print(
        "  reason: the dominating gove-zone executor (execute_with_receipt) and the "
        "in-flight execution.py classifier are foreign/uncommitted and out of scope; "
        "no gove-zone source routes through MutationGateway."
    )
    print("  see GOVE_ZONE_MUTATION_AUTHORITY_WIRING_V1/REPORT.md")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
