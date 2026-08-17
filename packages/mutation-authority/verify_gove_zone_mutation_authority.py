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

import ast
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


def _imports_mutation_authority(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(a.name.split(".")[0] == "mutation_authority" for a in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] == "mutation_authority":
                return True
    return False


def _calls_mutation_gateway(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else None
            if isinstance(func, ast.Attribute):
                name = func.attr
            if name == "MutationGateway":
                return True
    return False


def _invokes_request_mutation(tree: ast.AST) -> bool:
    """True only when the file actually CALLS the effect-time entry point
    (`<gateway>.request_mutation(...)`). Constructing a MutationGateway
    proves availability, not mediation: an executor that builds the gateway
    but never routes its effects through request_mutation() is unwired."""
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "request_mutation"
        ):
            return True
    return False


def _routes_through_gateway(src_dir: Path) -> int:
    """Count gove-zone source files that REALLY wire through this package:
    the file must import mutation_authority, construct MutationGateway, AND
    invoke the effect-time `request_mutation()` call. Construction alone (or
    a bare mention in a comment, docstring, or string, which the old
    substring scan counted) proves nothing about effect-time mediation."""
    refs = 0
    for py in src_dir.rglob("*.py"):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        if (
            _imports_mutation_authority(tree)
            and _calls_mutation_gateway(tree)
            and _invokes_request_mutation(tree)
        ):
            refs += 1
    return refs


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
    #    routed mutation through this package, its source would import it,
    #    instantiate MutationGateway, AND invoke request_mutation() at effect
    #    time — verified at the AST level so comments, docstrings, string
    #    literals, and construction-without-mediation cannot fake wiring.
    #    Zero real references ⇒ MutationGateway mediates nothing in
    #    gove-zone ⇒ dominance is NOT established.
    refs = _routes_through_gateway(GOVE_ZONE_SRC) if GOVE_ZONE_SRC.is_dir() else 0
    dominance_established = refs > 0
    lines.append(
        f"[{'OK ' if dominance_established else 'GAP'}] gateway dominance: "
        f"{refs} gove-zone source file(s) import mutation_authority, construct "
        f"MutationGateway, and invoke request_mutation()"
        + ("" if dominance_established else " — NOT mediated (no effect-time wiring present)")
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
