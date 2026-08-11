#!/usr/bin/env python3
"""Pure replay of the shipped authority evidence.

This module reads only files beneath its own directory. It never probes the
host, launches Docker, or writes unless the caller explicitly requests output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import exclusivity_model
import privilege_context
import privilege_graph
import verify_v3

HERE = Path(__file__).resolve().parent
INPUTS = (
    "attack_results.json",
    "ROOT_EQUIVALENCE_REGISTRY.json",
    "PRIVILEGE_TOPOLOGY_FINAL.json",
    "AUTHORITY_PRINCIPAL_ANALYSIS.json",
    "PRIVILEGE_GRAPH.json",
    "EXPECTED_CREDENTIAL.json",
    "SURFACE_REGISTRY.json",
)


def _load(name: str) -> dict:
    with (HERE / name).open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{name} must contain a JSON object")
    return value


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(payload).hexdigest()


def replay() -> dict:
    artifacts = {name: _load(name) for name in INPUTS}
    attacks = artifacts["attack_results.json"]
    registry = artifacts["ROOT_EQUIVALENCE_REGISTRY.json"]
    topology = artifacts["PRIVILEGE_TOPOLOGY_FINAL.json"]
    analysis = artifacts["AUTHORITY_PRINCIPAL_ANALYSIS.json"]
    recorded_graph = artifacts["PRIVILEGE_GRAPH.json"]
    expected = artifacts["EXPECTED_CREDENTIAL.json"]
    surfaces = artifacts["SURFACE_REGISTRY.json"]

    errors: list[str] = []
    credential = expected.get("credential")
    expected_digest = _canonical_sha(credential)
    if expected.get("schema") != "expected-linux-credential/v1":
        errors.append("expected credential schema is not v1")
    if expected_digest != privilege_context.EXPECTED_CREDENTIAL_SHA256:
        errors.append("EXPECTED_CREDENTIAL.json does not match pinned digest")

    graph = privilege_graph.build(attacks, registry)
    graph["closure"] = privilege_graph.closure(graph)
    if graph["closure"] != recorded_graph.get("closure"):
        errors.append("recorded privilege graph closure does not recompute")

    conditions = verify_v3.conditions_from(
        attacks,
        registry,
        analysis,
        graph,
        topology,
        surfaces,
    )
    model = exclusivity_model.compute(
        registry,
        topology,
        graph["closure"],
        conditions,
        ignore_conditions={"18"},
        surface_registry=surfaces,
    )
    if errors:
        model["verdict"] = exclusivity_model.BLOCKED_UNCERTAIN
        model["specific_reason"] = "BLOCKED_PRIVILEGE_UNCERTAIN_REPLAY_INTEGRITY"
        model["reasons"] = errors

    derived = {
        "classification_sets": {
            key: model[key]
            for key in (
                "root_equivalent_paths",
                "authority_equivalent_paths",
                "unknown_privilege_paths",
                "requires_operator_evidence_paths",
            )
        },
        "surface_coverage": {
            "required": model["surfaces_required"],
            "covered": model["surfaces_covered"],
            "missing": model["surfaces_missing"],
        },
        "credential_digests": model["inventory_credential_digests"],
        "graph_closure": graph["closure"],
        "conditions": conditions,
        "verdict": model["verdict"],
        "specific_reason": model["specific_reason"],
        "integrity_errors": errors,
        "artifact_hashes": {name: _sha(HERE / name) for name in INPUTS},
    }
    return {
        "schema": "authority-artifact-replay/v1",
        "mode": "PURE_ARTIFACT_REPLAY",
        "host_probe_performed": False,
        "docker_invoked": False,
        "verdict": model["verdict"],
        "specific_reason": model["specific_reason"],
        "derived": derived,
        "evidence_digest": _canonical_sha(derived),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", type=Path)
    parser.add_argument(
        "--verify-shipped",
        action="store_true",
        help="compare recomputation with REPLAY_RESULT.json",
    )
    args = parser.parse_args()
    result = replay()
    if args.verify_shipped:
        shipped = _load("REPLAY_RESULT.json")
        if shipped != result:
            print("REPLAY_RESULT.json does not match pure recomputation")
            return 2
    if args.write:
        output = args.write
        if not output.is_absolute():
            output = HERE / output
        output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verdict"] == exclusivity_model.BLOCKED_ROOT else 2


if __name__ == "__main__":
    raise SystemExit(main())
