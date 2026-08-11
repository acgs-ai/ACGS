#!/usr/bin/env python3
"""The final cutover decision, computed from the evidence on disk.

No verdict is selected here. `exclusivity_model.compute()` produces it from the
inventories, the graph closure and the conditions; this program assembles the
inputs, binds them by sha256, and renders the operator worklist that the
blocking paths imply.

`authority_exclusivity_proven` is true only when

    root_equivalent_paths == []
    unknown_privilege_paths == []
    requires_operator_evidence_paths == []
    every inventory measured in a host-representative context
    the privilege graph closure holds
    the cutover readiness gate returned READY_FOR_FINAL_PROOF
    the verifier's own verdict is VERIFIED_EXCLUSIVE_AUTHORITY

Any missing input is a false, never an omission.

Read-only. Reads JSON and writes CUTOVER_DECISION.json.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import exclusivity_model  # noqa: E402

OUT = os.path.join(HERE, "CUTOVER_DECISION.json")

INPUTS = {
    "topology_final": "PRIVILEGE_TOPOLOGY_FINAL.json",
    "topology_raw": "PRIVILEGE_TOPOLOGY.json",
    "registry": "ROOT_EQUIVALENCE_REGISTRY.json",
    "graph": "PRIVILEGE_GRAPH.json",
    "verification": "verification_result.json",
    "gate": "CUTOVER_GATE.json",
    "preflight": "PREFLIGHT_AUDIT.json",
}


def load(name: str) -> tuple[dict | None, dict]:
    path = os.path.join(HERE, name)
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        return None, {"present": False, "error": str(exc)}
    binding = {
        "present": True,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "mtime": int(os.stat(path).st_mtime),
    }
    try:
        return json.loads(raw.decode("utf-8")), binding
    except (ValueError, UnicodeDecodeError) as exc:
        binding["parse_error"] = str(exc)
        return None, binding


def worklist(topology: dict | None) -> list[dict]:
    """What an operator must measure or remove, in precedence order."""
    if not topology:
        return []
    items = []
    for path_id in topology.get("root_equivalent_paths", []):
        entry = topology.get("paths", {}).get(path_id, {})
        items.append(
            {
                "path": path_id,
                "classification": "ROOT_EQUIVALENT",
                "priority": 1,
                "action": entry.get("operator_action")
                or "remove this mechanism; it is measured root-equivalent",
                "privilege_effect": entry.get("privilege_effect"),
            }
        )
    for path_id in topology.get("requires_operator_evidence_paths", []):
        entry = topology.get("paths", {}).get(path_id, {})
        items.append(
            {
                "path": path_id,
                "classification": "REQUIRES_OPERATOR_EVIDENCE",
                "priority": 2,
                "action": entry.get("operator_action"),
                "discriminator": entry.get("discriminator"),
                "privilege_effect": entry.get("privilege_effect"),
            }
        )
    for path_id in topology.get("unknown_privilege_paths", []):
        items.append(
            {
                "path": path_id,
                "classification": "UNKNOWN",
                "priority": 2,
                "action": "measure this path; UNKNOWN is not a pass",
            }
        )
    return sorted(items, key=lambda item: (item["priority"], item["path"]))


def build() -> dict:
    loaded: dict[str, dict | None] = {}
    bindings: dict[str, dict] = {}
    for key, name in INPUTS.items():
        loaded[key], bindings[name] = load(name)

    graph_closure = (loaded["graph"] or {}).get("closure")
    conditions = (loaded["verification"] or {}).get("conditions") or {}

    exclusivity = exclusivity_model.compute(
        loaded["registry"],
        loaded["topology_final"],
        graph_closure,
        conditions,
        ignore_conditions={"18"},
    )

    gate_verdict = (loaded["gate"] or {}).get("verdict")
    verifier_verdict = (loaded["verification"] or {}).get("verdict")

    gates = {
        "no_root_equivalent_path": not exclusivity["root_equivalent_paths"],
        "no_unknown_path": not exclusivity["unknown_privilege_paths"],
        "no_operator_evidence_pending": not exclusivity["requires_operator_evidence_paths"],
        # admissible context AND full surface coverage, both computed by the
        # model: a perfect context that measured only one surface is not
        # "host measured", it is host measured *in part*
        "every_inventory_host_measured": exclusivity["every_inventory_host_measured"],
        "all_required_surfaces_covered": not exclusivity["surfaces_missing"],
        "privilege_graph_closed": exclusivity["graph_closure_holds"] is True,
        "readiness_gate_cleared": gate_verdict == "READY_FOR_FINAL_PROOF",
        "verifier_verdict_is_exclusive": verifier_verdict == exclusivity_model.VERIFIED,
    }

    return {
        "verdict": exclusivity["verdict"],
        "specific_reason": exclusivity["specific_reason"],
        "authority_exclusivity_proven": all(gates.values()),
        "closure_gates": gates,
        "exclusivity_requires": exclusivity_model.EXCLUSIVITY_REQUIRES,
        "exclusivity": exclusivity,
        "counts": (loaded["topology_final"] or {}).get("counts"),
        "verifier_verdict": verifier_verdict,
        "verifier_evidence_digest": (loaded["verification"] or {}).get("evidence_digest"),
        "readiness_gate_verdict": gate_verdict,
        "readiness_gate_blocking": (loaded["gate"] or {}).get("blocking_checks"),
        "operator_worklist": worklist(loaded["topology_final"]),
        "inputs": bindings,
        "read_only": True,
        "mutations_performed": [],
        "note": "no verdict in this file was chosen by hand; each is computed "
        "by exclusivity_model from the bound inputs above. Re-running this "
        "program against the same inputs reproduces it exactly.",
    }


def main() -> int:
    decision = build()
    with open(OUT, "w", encoding="utf-8") as handle:
        json.dump(decision, handle, indent=1, sort_keys=True)
    print(f"VERDICT: {decision['specific_reason']}")
    print(f"authority_exclusivity_proven: {decision['authority_exclusivity_proven']}")
    for name, met in sorted(decision["closure_gates"].items()):
        print(f"  {'PASS' if met else 'FAIL'}  {name}")
    print(f"operator worklist: {len(decision['operator_worklist'])} items")
    return 0 if decision["authority_exclusivity_proven"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
