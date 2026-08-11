#!/usr/bin/env python3
"""Registry-driven dominance / bypass-regression gate (Step 7).

This gate reasons over the machine-checkable mutation-carrier registry, NOT a
grep for a symbol. It answers two questions deterministically:

1. DOMINANCE: does every mutation-capable carrier participate in an effect
   authority boundary (i.e. is it prevented from changing canonical state
   without valid authorization)? Any residual carrier ⇒ dominance does not
   hold ⇒ the gate fails.

2. DETECTION (bypass regression): given a baseline snapshot of known carrier
   ids, is a newly introduced mutation-capable executor detected? A carrier
   that appears without being registered/sanctioned is a bypass ⇒ flagged.

3. SOURCE-LEVEL DETECTION: candidate spawn-capable executors are derived
   from the inspected gove-zone execution surface itself (AST scan for
   process-spawning calls), NOT from the registry the baseline was derived
   from. A registry-vs-registry comparison is circular: a brand-new
   executor added at source level would never appear in either side. Any
   discovered spawn-capable module whose path is not a registered carrier
   entry point is flagged as unregistered.

Negative self-tests inject a synthetic bypass executor (registry level) and
a synthetic spawn-capable source file (source level) and assert the gate
flags both — proving the gate is not vacuous.
"""

from __future__ import annotations

import ast
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mutation_authority.effect_authority import (
    CARRIERS,
    Carrier,
    minimal_dominating_layer,
    validate_registry,
)

GOVE_ZONE_SRC = Path(__file__).resolve().parents[2] / "gove-zone" / "src" / "gove_zone"


def residual_carriers(carriers: tuple[Carrier, ...] = CARRIERS) -> list[Carrier]:
    """Mutation-capable carriers NOT mediated by an effect authority boundary."""
    return [c for c in carriers if not c.sanctioned]


def detect_unregistered(carriers: tuple[Carrier, ...], known_ids: set[str]) -> list[Carrier]:
    """Carriers present but not in the baseline snapshot = newly introduced."""
    return [c for c in carriers if c.id not in known_ids]


def dominance_holds(carriers: tuple[Carrier, ...] = CARRIERS) -> bool:
    return not residual_carriers(carriers)


# -- source-level candidate discovery (independent of the registry) ----------

_SPAWN_CALLEES = frozenset(
    {
        "run",
        "Popen",
        "call",
        "check_call",
        "check_output",
        "system",
        "popen",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "posix_spawn",
        "posix_spawnp",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "fork",
        "forkpty",
    }
)


def _spawns_processes(tree: ast.AST) -> bool:
    """AST-level detection of process-spawning calls (subprocess/os)."""
    direct_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in ("subprocess", "os"):
            for alias in node.names:
                if alias.name in _SPAWN_CALLEES:
                    direct_names.add(alias.asname or alias.name)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                base = func.value
                if (
                    isinstance(base, ast.Name)
                    and base.id in ("subprocess", "os")
                    and func.attr in _SPAWN_CALLEES
                ):
                    return True
            elif isinstance(func, ast.Name) and func.id in direct_names:
                return True
    return False


def discover_spawn_carrier_modules(src_dir: Path) -> list[str]:
    """Candidate executors derived from the inspected execution surface
    itself: every source module that can spawn a process. This inventory is
    independent of the CARRIERS registry, so a new source-level executor
    appears here even though no registry snapshot mentions it."""
    found: list[str] = []
    for py in sorted(src_dir.rglob("*.py")):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        if _spawns_processes(tree):
            found.append(py.relative_to(src_dir).as_posix())
    return found


def registered_entry_modules(carriers: tuple[Carrier, ...] = CARRIERS) -> set[str]:
    """Source-module paths named as entry points by registered carriers."""
    modules: set[str] = set()
    for c in carriers:
        token = c.entry_point.split(":")[0].split()[0]
        if token.endswith(".py"):
            modules.add(token)
    return modules


def unregistered_spawn_carriers(
    src_dir: Path, carriers: tuple[Carrier, ...] = CARRIERS
) -> list[str]:
    """Spawn-capable source modules NOT covered by any registered carrier."""
    if not src_dir.is_dir():
        return []
    registered = registered_entry_modules(carriers)
    return [m for m in discover_spawn_carrier_modules(src_dir) if m not in registered]


# -- negative self-test -----------------------------------------------------


def _injected_bypass_carrier() -> Carrier:
    return Carrier(
        id="INJECTED_bypass_executor",
        entry_point="attacker_module.py:1",
        performer="raw subprocess writing a governed file",
        process_boundary="subprocess",
        actor_identity="unknown",
        target_known=False,
        pre_state_hash_available=False,
        post_state_committed=False,
        authz_can_precede_effect=False,
        required_enforcement_layer="os",
        bypasses_execute_with_receipt=True,
        decidable_before_execution=False,
        sanctioned=False,
        notes="synthetic bypass for the gate's negative self-test",
    )


def self_test_detects_injection() -> tuple[bool, str]:
    baseline = {c.id for c in CARRIERS}
    injected = CARRIERS + (_injected_bypass_carrier(),)
    found = detect_unregistered(injected, baseline)
    if [c.id for c in found] != ["INJECTED_bypass_executor"]:
        return False, f"gate failed to isolate the injected carrier: {[c.id for c in found]}"
    # And an injected UNSANCTIONED carrier must break dominance too.
    if dominance_holds(injected):
        return False, "gate reported dominance despite an injected residual carrier"
    # A sanctioned duplicate must NOT be flagged as residual (no false positive).
    sanctioned_clone = replace(_injected_bypass_carrier(), id="already_known", sanctioned=True)
    if sanctioned_clone in residual_carriers((sanctioned_clone,)):
        return False, "gate false-positived on a sanctioned carrier"
    return True, "gate detects an injected bypass executor and rejects false positives"


def self_test_detects_source_level_bypass() -> tuple[bool, str]:
    """Prove the source-level scan catches a NEW spawn-capable module that no
    registry snapshot mentions, without false-positiving on registered or
    benign modules."""
    with tempfile.TemporaryDirectory(prefix="dominance-gate-selftest-") as tmp:
        src = Path(tmp)
        (src / "new_executor.py").write_text(
            "import subprocess\n\ndef go(cmd):\n    return subprocess.run(cmd)\n",
            encoding="utf-8",
        )
        (src / "executor.py").write_text(
            "import subprocess\n\ndef go(cmd):\n    return subprocess.run(cmd)\n",
            encoding="utf-8",
        )
        (src / "benign.py").write_text(
            "def add(a, b):\n    return a + b\n",
            encoding="utf-8",
        )
        flagged = unregistered_spawn_carriers(src)
        if flagged != ["new_executor.py"]:
            return False, f"source-level scan failed to isolate the new executor: {flagged}"
    return True, "source-level scan flags an unregistered spawn-capable module"


def main() -> int:
    problems = validate_registry()
    if problems:
        print("[BAD] registry invalid:", problems)
        return 3

    residual = residual_carriers()
    holds = dominance_holds()
    layer = minimal_dominating_layer()

    print(f"registry: {len(CARRIERS)} carriers; minimal dominating layer = {layer!r}")
    print(f"dominance holds: {holds}")
    if residual:
        print(f"residual (unmediated) mutation carriers: {len(residual)}")
        for c in residual:
            print(
                f"  - {c.id}  ({c.process_boundary}, needs {c.required_enforcement_layer})  {c.entry_point}"
            )

    # Source-derived candidate inventory (independent of the registry).
    unregistered = unregistered_spawn_carriers(GOVE_ZONE_SRC)
    if GOVE_ZONE_SRC.is_dir():
        print(
            f"source-level spawn scan: {len(unregistered)} unregistered spawn-capable "
            f"module(s) in {GOVE_ZONE_SRC.name}"
        )
        for mod in unregistered:
            print(f"  - {mod}  (spawn-capable, not a registered carrier entry point)")
    else:
        print("source-level spawn scan: gove-zone source tree absent (nothing scanned)")

    ok, detail = self_test_detects_injection()
    print(f"[{'OK ' if ok else 'BAD'}] negative self-test (registry): {detail}")
    if not ok:
        return 3  # the gate itself is broken

    ok, detail = self_test_detects_source_level_bypass()
    print(f"[{'OK ' if ok else 'BAD'}] negative self-test (source-level): {detail}")
    if not ok:
        return 3  # the gate itself is broken

    print()
    if holds and not unregistered:
        print("DOMINANCE HOLDS: every mutation carrier participates in the boundary")
        return 0
    if unregistered:
        print(
            "DOMINANCE DOES NOT HOLD: spawn-capable source modules exist that no "
            f"registered carrier covers: {', '.join(unregistered)}"
        )
        return 2
    print(
        "DOMINANCE DOES NOT HOLD: mutation-capable carriers exist outside any effect "
        f"authority boundary; the minimal layer that could dominate them is {layer!r}, "
        "which the current execution model does not provide."
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
