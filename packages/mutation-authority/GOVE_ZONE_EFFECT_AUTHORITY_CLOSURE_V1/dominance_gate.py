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

A negative self-test injects a synthetic bypass executor and asserts the gate
flags it — proving the gate is not vacuous.
"""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mutation_authority.effect_authority import (
    CARRIERS,
    Carrier,
    minimal_dominating_layer,
    validate_registry,
)


def residual_carriers(carriers: tuple[Carrier, ...] = CARRIERS) -> list[Carrier]:
    """Mutation-capable carriers NOT mediated by an effect authority boundary."""
    return [c for c in carriers if not c.sanctioned]


def detect_unregistered(carriers: tuple[Carrier, ...], known_ids: set[str]) -> list[Carrier]:
    """Carriers present but not in the baseline snapshot = newly introduced."""
    return [c for c in carriers if c.id not in known_ids]


def dominance_holds(carriers: tuple[Carrier, ...] = CARRIERS) -> bool:
    return not residual_carriers(carriers)


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

    ok, detail = self_test_detects_injection()
    print(f"[{'OK ' if ok else 'BAD'}] negative self-test: {detail}")
    if not ok:
        return 3  # the gate itself is broken

    print()
    if holds:
        print("DOMINANCE HOLDS: every mutation carrier participates in the boundary")
        return 0
    print(
        "DOMINANCE DOES NOT HOLD: mutation-capable carriers exist outside any effect "
        f"authority boundary; the minimal layer that could dominate them is {layer!r}, "
        "which the current execution model does not provide."
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
