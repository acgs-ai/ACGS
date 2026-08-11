#!/usr/bin/env python3
"""The exclusivity verdict model, hardened so UNKNOWN can never become VERIFIED.

Before this module, `verify_v3.py` computed its verdict as:

    if registry["agent_is_root_equivalent"]:      -> BLOCKED_ROOT_EQUIVALENCE
    elif not graph closure holds:                 -> BLOCKED_AUTHORITY_EQUIVALENCE
    elif all conditions met:                      -> VERIFIED_EXCLUSIVE_AUTHORITY

`agent_is_root_equivalent` is `bool(root_equivalent_paths)`. `unknown_paths` was
recorded and consumed by nothing, so a host whose only remaining escalation path
was UNKNOWN would have been reported VERIFIED. This module makes exclusivity
require BOTH lists empty:

    root_equivalent_paths == [] AND unknown_privilege_paths == []

and gives uncertainty its own fail-closed verdict, BLOCKED_PRIVILEGE_UNCERTAIN,
so it is never silently folded into a pass and never mistaken for a measured
root-equivalence.

Pure: no I/O, no clock, no host access. Every input is a dict the caller has
already measured. That is what makes the regression suite meaningful.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import privilege_context

VERIFIED = "VERIFIED_EXCLUSIVE_AUTHORITY"
BLOCKED_ROOT = "BLOCKED_ROOT_EQUIVALENCE"
BLOCKED_AUTHORITY = "BLOCKED_AUTHORITY_EQUIVALENCE"
BLOCKED_UNCERTAIN = "BLOCKED_PRIVILEGE_UNCERTAIN"

#: Precedence. A measured escalation outranks an unmeasured one: if the agent
#: demonstrably holds root, saying "uncertain" would understate the finding.
#: Uncertainty outranks a failing condition, because a condition that fails
#: under an unresolved privilege path has not been measured on a known host.
PRECEDENCE = (BLOCKED_ROOT, BLOCKED_AUTHORITY, BLOCKED_UNCERTAIN, VERIFIED)

#: Privilege surfaces that must actually appear in an admissible inventory.
#: Admissibility says the measurement was taken as the host identity; coverage
#: says it was taken *of everything*. An inventory that measured only `groups`
#: from a perfect context is silent about setuid, and silence is not absence --
#: a partial inventory must never be able to improve a verdict.
REQUIRED_SURFACES = (
    "container_runtimes",
    # file capabilities are a distinct surface: `find -perm -4000` is
    # structurally incapable of finding /usr/bin/suexec cap_setuid=ep
    "filecaps",
    "groups",
    "polkit",
    "setuid",
    "sudo",
    "systemd",
)

#: The closure test, in one place, so the documents and the code cannot drift.
EXCLUSIVITY_REQUIRES = (
    "root_equivalent_paths == [] and unknown_privilege_paths == [] and "
    "requires_operator_evidence_paths == [] and every inventory measured in a "
    "host-representative context"
)


CLASS_BUCKET = {
    "ROOT_EQUIVALENT": "root",
    "AUTHORITY_EQUIVALENT": "authority",
    "UNKNOWN": "unknown",
    "REQUIRES_OPERATOR_EVIDENCE": "operator",
}
#: Classifications that are a measured *pass* and confer no escalation. Any
#: classification that is neither one of these nor a CLASS_BUCKET key -- a
#: missing field or a typo such as `ROOT_EQUIVALNT` -- is not silently dropped;
#: it enters the uncertainty bucket, because an unrecognised label is an
#: unmeasured path, not a clean one.
BENIGN_CLASSIFICATIONS = frozenset(
    {"NON_ROOT_EQUIVALENT", "NOT_PRESENT", "PRESENT_NON_ESCALATING"}
)
#: The inventories exclusivity is computed from. Each must be present and
#: admissible independently: a missing registry may not be masked by a clean
#: topology, nor the reverse.
REQUIRED_INVENTORIES = ("ROOT_EQUIVALENCE_REGISTRY", "PRIVILEGE_TOPOLOGY")
#: Every section 16 condition key the verdict must see measured. Absence of any
#: one is uncertainty, never an implicit pass. Condition 18 (repeatability) is
#: the sole exclusion the caller may pass via `ignore_conditions`.
EXPECTED_CONDITIONS = frozenset(f"{n:02d}" for n in range(1, 20))
SUMMARY_KEYS = {
    "root": ("root_equivalent_paths",),
    "authority": ("authority_equivalent_paths",),
    "unknown": ("unknown_paths", "unknown_privilege_paths"),
    "operator": ("requires_operator_evidence_paths",),
}


def _classified_entries(inventory: dict) -> dict[str, dict]:
    entries: dict[str, dict] = {}
    for container in ("mechanisms", "paths"):
        value = inventory.get(container)
        if isinstance(value, dict):
            entries.update(
                (str(path_id), entry) for path_id, entry in value.items() if isinstance(entry, dict)
            )
    return entries


def _derived_classes(inventory: dict) -> dict[str, set[str]]:
    derived = {key: set() for key in SUMMARY_KEYS}
    for path_id, entry in _classified_entries(inventory).items():
        classification = entry.get("classification")
        bucket = CLASS_BUCKET.get(classification)
        if bucket:
            derived[bucket].add(path_id)
        elif classification not in BENIGN_CLASSIFICATIONS:
            # A missing or unrecognised classification is not a pass. Fail it
            # closed into uncertainty so a typo cannot make an entry vanish
            # from every summary and leave the verdict free to go green.
            derived["unknown"].add(path_id)
    return derived


def derive(inventory: dict) -> dict[str, set[str]]:
    """Public fail-closed classification derivation used by readiness gates."""
    return _derived_classes(inventory)


def _declared_summary(inventory: dict, keys: tuple[str, ...]) -> set[str] | None:
    present = [key for key in keys if key in inventory]
    if not present:
        return None
    values: set[str] = set()
    for key in present:
        raw = inventory.get(key)
        if not isinstance(raw, list):
            return {"<invalid-summary-type>"}
        values.update(str(item) for item in raw)
    return values


def context_admissible(inventory: dict | None) -> bool:
    if not isinstance(inventory, dict):
        return False
    return privilege_context.is_host_representative(inventory.get("measurement_context"))


def collect(
    registry: dict | None,
    topology: dict | None,
    *,
    require_context: bool = True,
    surface_registry: dict | None = None,
) -> dict:
    """Derive R/Q/U and coverage from first-class evidence, never summaries."""
    root: set[str] = set()
    authority: set[str] = set()
    unknown: set[str] = set()
    operator: set[str] = set()
    buckets = {
        "root": root,
        "authority": authority,
        "unknown": unknown,
        "operator": operator,
    }
    admissibility: dict[str, bool] = {}
    credential_digests: dict[str, str | None] = {}
    covered: set[str] = set()
    inventories = (
        ("ROOT_EQUIVALENCE_REGISTRY", registry),
        ("PRIVILEGE_TOPOLOGY", topology),
    )

    for name, inventory in inventories:
        if inventory is None:
            # A required inventory that was not supplied is not an absence of
            # findings; it is an absence of measurement. Record it as an
            # unresolved path and an inadmissible inventory so it can never be
            # masked by the other inventory reporting clean.
            unknown.add(f"inventory:{name}_absent")
            admissibility[name] = False
            continue
        ok = context_admissible(inventory) if require_context else True
        digest = privilege_context.credential_digest(inventory.get("measurement_context"))
        credential_digests[name] = digest
        admissibility[name] = ok
        if not ok:
            unknown.add(f"inventory:{name}_credential_not_expected")
            continue

        derived = _derived_classes(inventory)
        for bucket, paths in derived.items():
            buckets[bucket].update(paths)
        for bucket, keys in SUMMARY_KEYS.items():
            declared = _declared_summary(inventory, keys)
            if declared is not None and declared != derived[bucket]:
                unknown.add(f"inventory:{name}_{bucket}_summary_mismatch")

        if surface_registry is None:
            covered.update(
                path_id.split(":", 1)[0]
                for path_id in _classified_entries(inventory)
                if ":" in path_id
            )
        else:
            results = inventory.get("surface_results")
            if not isinstance(results, dict):
                continue
            for surface_id, result in results.items():
                if (
                    isinstance(result, dict)
                    and result.get("status") == "SUCCESS"
                    and result.get("completed") is True
                ):
                    covered.add(str(surface_id))

    non_null_digests = {value for value in credential_digests.values() if value}
    if len(non_null_digests) > 1:
        unknown.add("inventory:credential_cross_inventory_mismatch")

    required = list(REQUIRED_SURFACES)
    if surface_registry is not None:
        raw_surfaces = (
            surface_registry.get("surfaces") if isinstance(surface_registry, dict) else None
        )
        if not isinstance(raw_surfaces, list):
            required = []
            unknown.add("coverage:surface_registry_invalid")
        else:
            required = []
            for entry in raw_surfaces:
                surface_id = entry.get("surface_id") if isinstance(entry, dict) else None
                if (
                    not isinstance(surface_id, str)
                    or not surface_id
                    or entry.get("required") is not True
                ):
                    unknown.add("coverage:surface_registry_invalid")
                    continue
                required.append(surface_id)
                method = entry.get("discovery_method")
                if not isinstance(method, str) or not method.strip():
                    unknown.add(f"coverage:{surface_id}_discovery_method_invalid")

    missing_surfaces = sorted(set(required) - covered)
    unknown.update(f"coverage:{surface}_not_successfully_completed" for surface in missing_surfaces)
    all_expected = bool(admissibility) and all(admissibility.values())
    all_expected = all_expected and len(non_null_digests) == 1 and not missing_surfaces

    return {
        "root_equivalent_paths": sorted(root),
        "authority_equivalent_paths": sorted(authority),
        "unknown_privilege_paths": sorted(unknown),
        "surfaces_covered": sorted(covered),
        "surfaces_required": sorted(required),
        "surfaces_missing": missing_surfaces,
        "every_inventory_host_measured": all_expected,
        "requires_operator_evidence_paths": sorted(operator),
        "unresolved_privilege_paths": sorted(unknown | operator),
        "inventory_admissibility": admissibility,
        "inventory_credential_digests": credential_digests,
    }


def compute(
    registry: dict | None,
    topology: dict | None,
    graph_closure: dict | None,
    conditions: dict | None,
    *,
    ignore_conditions: set[str] | None = None,
    surface_registry: dict | None = None,
) -> dict:
    """Compute the exclusivity verdict. Fails closed on every missing input.

    `ignore_conditions` exists for one legitimate case: condition 18 measures
    repeatability across runs and is not a property of the host, so the caller
    excludes it from the "all conditions met" test exactly as before.
    """
    ignore = ignore_conditions or set()
    paths = collect(registry, topology, surface_registry=surface_registry)
    reasons: list[str] = []

    if registry is None and topology is None:
        return {
            "verdict": BLOCKED_UNCERTAIN,
            "specific_reason": "BLOCKED_PRIVILEGE_UNCERTAIN_NO_INVENTORY",
            "reasons": [
                "no privilege inventory was supplied; absence of "
                "evidence is not evidence of absence"
            ],
            **paths,
            "failed_conditions": [],
            "exclusivity_requires": EXCLUSIVITY_REQUIRES,
        }

    closure_holds = None
    if isinstance(graph_closure, dict):
        node = graph_closure.get("conditions", {}).get("no_path_to_authority_principal", {})
        closure_holds = node.get("holds")

    failed = sorted(
        key
        for key, entry in (conditions or {}).items()
        if key not in ignore and entry.get("met") is not True
    )
    # Every expected condition must be present. A missing key is an unmeasured
    # condition, not a satisfied one: `conditions=None`, `{}`, or an incomplete
    # all-true subset must fail closed rather than reach VERIFIED.
    provided = set(conditions or {})
    missing_conditions = sorted((EXPECTED_CONDITIONS - ignore) - provided)

    if paths["root_equivalent_paths"]:
        verdict = BLOCKED_ROOT
        reasons.append(f"root-equivalent paths measured: {paths['root_equivalent_paths']}")
    elif paths["authority_equivalent_paths"] or closure_holds is False:
        verdict = BLOCKED_AUTHORITY
        reasons.append(
            "an authority-equivalent transition or an open privilege-graph "
            f"path exists: {paths['authority_equivalent_paths']} "
            f"closure_holds={closure_holds}"
        )
    elif paths["unresolved_privilege_paths"]:
        verdict = BLOCKED_UNCERTAIN
        reasons.append(
            "privilege paths remain unresolved; neither UNKNOWN nor "
            "REQUIRES_OPERATOR_EVIDENCE is a pass: "
            f"{paths['unresolved_privilege_paths']}"
        )
    elif closure_holds is None:
        verdict = BLOCKED_UNCERTAIN
        reasons.append(
            "the privilege graph closure was not computed, so "
            "exclusivity is unmeasured rather than established"
        )
    elif missing_conditions:
        verdict = BLOCKED_UNCERTAIN
        reasons.append(
            "required conditions were not measured, so exclusivity is "
            f"unmeasured rather than established: {missing_conditions}"
        )
    elif failed:
        verdict = BLOCKED_AUTHORITY
        reasons.append(f"conditions not met: {failed}")
    else:
        verdict = VERIFIED
        reasons.append(
            "no root-equivalent path, no authority-equivalent "
            "transition, no unresolved privilege path, graph "
            "closed, and every condition met"
        )

    return {
        "verdict": verdict,
        "specific_reason": specific_reason(verdict, paths, failed, missing_conditions),
        "reasons": reasons,
        **paths,
        "graph_closure_holds": closure_holds,
        "failed_conditions": failed,
        "missing_conditions": missing_conditions,
        "exclusivity_requires": EXCLUSIVITY_REQUIRES,
        "precedence": list(PRECEDENCE),
    }


def specific_reason(
    verdict: str, paths: dict, failed: list[str], missing_conditions: list[str] | None = None
) -> str:
    """`BLOCKED_<specific_reason>`: which mechanism, not merely which class.

    Derived from the paths, never chosen by hand -- a verdict a human can spell
    is a verdict a human can spell wrongly.
    """
    if verdict == VERIFIED:
        return "VERIFIED_AUTHORITY_EXCLUSIVE"
    if verdict == BLOCKED_ROOT:
        joined = " ".join(paths["root_equivalent_paths"]).lower()
        for token in ("docker", "lxd", "libvirt", "podman", "containerd", "sudo"):
            if token in joined:
                return f"{BLOCKED_ROOT}_{token.upper()}"
        return BLOCKED_ROOT
    if verdict == BLOCKED_UNCERTAIN:
        unresolved = paths.get("unresolved_privilege_paths", [])
        if any(p.startswith("inventory:") for p in unresolved):
            return f"{BLOCKED_UNCERTAIN}_INVENTORY_NOT_HOST_MEASURED"
        if any(p.startswith("coverage:") for p in unresolved):
            return f"{BLOCKED_UNCERTAIN}_INCOMPLETE_SURFACE_COVERAGE"
        if paths.get("unknown_privilege_paths"):
            return f"{BLOCKED_UNCERTAIN}_UNKNOWN_PATHS"
        if paths.get("requires_operator_evidence_paths"):
            return f"{BLOCKED_UNCERTAIN}_OPERATOR_EVIDENCE_REQUIRED"
        if missing_conditions:
            return f"{BLOCKED_UNCERTAIN}_CONDITIONS_NOT_MEASURED"
        return f"{BLOCKED_UNCERTAIN}_GRAPH_CLOSURE_NOT_COMPUTED"
    if verdict == BLOCKED_AUTHORITY:
        if paths.get("authority_equivalent_paths"):
            return f"{BLOCKED_AUTHORITY}_PRINCIPAL_ASSUMABLE"
        if failed:
            return f"{BLOCKED_AUTHORITY}_CONDITIONS_{'_'.join(failed)}"
        return f"{BLOCKED_AUTHORITY}_GRAPH_OPEN"
    return verdict


def unknown_condition(
    registry: dict | None,
    topology: dict | None,
    *,
    surface_registry: dict | None = None,
) -> dict:
    """The condition `verify_v3.py` was missing, in the shape it stores them."""
    paths = collect(registry, topology, surface_registry=surface_registry)
    unresolved = paths["unresolved_privilege_paths"]
    return {
        "text": "no privilege path is left unresolved (neither UNKNOWN nor "
        "REQUIRES_OPERATOR_EVIDENCE is a pass)",
        "met": not unresolved,
        "evidence": {
            "unresolved_privilege_paths": unresolved,
            "unknown_privilege_paths": paths["unknown_privilege_paths"],
            "requires_operator_evidence_paths": paths["requires_operator_evidence_paths"],
            "count": len(unresolved),
            "inventory_admissibility": paths["inventory_admissibility"],
            "sources": [
                "ROOT_EQUIVALENCE_REGISTRY.json → unknown_paths",
                "PRIVILEGE_TOPOLOGY_FINAL.json → unknown_privilege_paths, "
                "requires_operator_evidence_paths",
            ],
        },
        "cutover_dependent": True,
    }
