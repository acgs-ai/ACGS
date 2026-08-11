"""The V3 verifier. It computes the verdict; no label is authored here.

Section 16 defines exactly one top-level result. But a single label would throw
away the thing V3 actually establishes, so three results are computed and all
three are printed:

    top_level          the section 16 label, from the measurements as they are
    property_split     section 15's A / B / C, which fail independently
    conditional        which of the eighteen conditions would hold after the
                       cutover deltas, each tagged with whether it depends on
                       one

The distinction section 16 insists on -- "architecture impossible" versus
"architecture possible but the current privilege configuration violates its
prerequisites" -- is exactly what the conditional result answers, so it is
computed rather than asserted.

Fails closed. A missing measurement is a failed condition, never a skipped one.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import exclusivity_model  # noqa: E402
import preflight  # noqa: E402
import privilege_graph  # noqa: E402

ATTACK_RESULTS = os.path.join(HERE, "attack_results.json")
TOPOLOGY = os.path.join(HERE, "PRIVILEGE_TOPOLOGY.json")
#: The resolved inventory: four terminal classifications, no UNKNOWN, and a
#: `measurement_context` binding it to the identity it was measured as. This is
#: the file the verdict is computed from; `TOPOLOGY` above is its raw input.
TOPOLOGY_FINAL = os.path.join(HERE, "PRIVILEGE_TOPOLOGY_FINAL.json")
CARRIER_MATRIX = os.path.join(HERE, "carrier_matrix.json")
REGISTRY = os.path.join(HERE, "ROOT_EQUIVALENCE_REGISTRY.json")
SURFACE_REGISTRY = os.path.join(HERE, "SURFACE_REGISTRY.json")
ANALYSIS = os.path.join(HERE, "AUTHORITY_PRINCIPAL_ANALYSIS.json")
RESULT_PATH = os.path.join(HERE, "verification_result.json")
HISTORY_PATH = os.path.join(HERE, "run_history.jsonl")
REQUIRED_IDENTICAL_RUNS = 4

VERIFIED = exclusivity_model.VERIFIED
BLOCKED_ROOT = exclusivity_model.BLOCKED_ROOT
BLOCKED_AUTHORITY = exclusivity_model.BLOCKED_AUTHORITY
BLOCKED_UNCERTAIN = exclusivity_model.BLOCKED_UNCERTAIN
INTEGRATION_BLOCKED = "INTEGRATION_BLOCKED"
PROVABLY_UNREACHABLE = "PROVABLY_UNREACHABLE"
ENV_NOT_EQUIVALENT = "ENVIRONMENT_NOT_EQUIVALENT"

#: Conditions whose failure is caused by the host's privilege configuration
#: rather than by the architecture. Used to compute the conditional result.
CUTOVER_DEPENDENT = {"06", "07", "12", "17", "19"}


def die(label: str, message: str) -> None:
    print(f"VERDICT: {label}")
    print(f"\nverifier could not complete: {message}")
    print("A verdict is not reported from an incomplete measurement.")
    raise SystemExit(2)


def run_stage(name: str, argv: list[str]) -> subprocess.CompletedProcess:
    print(f"[verify] {name}", flush=True)
    return subprocess.run(argv, cwd=HERE, capture_output=True, text=True, timeout=1800)


def conditions_from(
    attacks: dict,
    registry: dict,
    analysis: dict,
    graph: dict,
    topology: dict | None = None,
    surface_registry: dict | None = None,
) -> dict:
    carriers = {entry["carrier"]: entry for entry in attacks["carriers"]}
    attack = attacks["attacks"]
    protocol = attacks["protocol"]
    environment = attacks["environment"]
    selected = analysis["selected_authority_uid"]
    evaluation = analysis["evaluations"][str(selected)]

    def denied(*names) -> bool:
        return all(carriers.get(name, {}).get("verdict") == "DENIED_BY_DAC" for name in names)

    closure = graph["closure"]["conditions"]
    conditions = {}
    conditions["01"] = {
        "text": "a dedicated authority principal exists",
        "met": environment["broker_uid"] != environment["agent_uid"]
        and environment["store_owner_uid"] == environment["broker_uid"],
        "evidence": {
            k: environment[k]
            for k in ("agent_uid", "broker_uid", "decision_uid", "store_owner_uid")
        },
    }
    conditions["02"] = {
        "text": "the authority uid/gid is not agent-delegable",
        "met": evaluation["all_criteria_met"],
        "evidence": {
            "uid": selected,
            "criteria": evaluation["criteria"],
            "newuidmap": evaluation["newuidmap_probe"],
        },
    }
    conditions["03"] = {
        "text": "direct content mutation is denied",
        "met": denied(
            "overwrite",
            "append",
            "truncate",
            "create",
            "shell_redirection",
            "subprocess",
            "mmap_write",
        ),
        "evidence": {
            name: carriers.get(name, {}).get("verdict")
            for name in (
                "overwrite",
                "append",
                "truncate",
                "create",
                "shell_redirection",
                "subprocess",
                "mmap_write",
            )
        },
    }
    conditions["04"] = {
        "text": "direct metadata mutation is denied",
        "met": denied("chmod", "exec_bit_transition", "chown", "utime", "xattr", "acl_change"),
        "evidence": {
            name: carriers.get(name, {}).get("verdict")
            for name in (
                "chmod",
                "exec_bit_transition",
                "chown",
                "utime",
                "xattr",
                "acl_change",
            )
        },
    }
    control_failures = [
        name for name, entry in carriers.items() if entry["verdict"] == "CONTROL_FAILED"
    ]
    not_denied = [name for name, entry in carriers.items() if entry["verdict"] == "NOT_DENIED"]
    conditions["05"] = {
        "text": "all measured mutation carriers are denied",
        "met": not not_denied and not control_failures,
        "evidence": {
            "carriers": len(carriers),
            "not_denied": not_denied,
            "control_failures": control_failures,
        },
    }
    conditions["06"] = {
        "text": "no root-equivalent runtime path exists for the agent",
        "met": not registry["agent_is_root_equivalent"],
        "evidence": {
            "root_equivalent_paths": registry["root_equivalent_paths"],
            "route": registry["docker_access_route"]["routes"],
        },
        "cutover_dependent": True,
    }
    conditions["07"] = {
        "text": "no authority-equivalent uid transition exists",
        "met": closure["no_path_to_authority_principal"]["holds"],
        "evidence": closure["no_path_to_authority_principal"],
        "cutover_dependent": True,
    }
    conditions["08"] = {
        "text": "the subuid/subgid attack is denied",
        "met": attack["D_subuid"]["verdict"] == "DENIED_BY_DAC",
        "evidence": attack["D_subuid"],
    }
    conditions["09"] = {
        "text": "setns cannot obtain authority-equivalent privilege",
        "met": attack["E_setns"]["procfs_route"]["verdict"] == "DENIED_BY_DAC",
        "evidence": attack["E_setns"],
        "note": "the procfs route is the namespace boundary; the docker exec "
        "route is the socket, and is condition 6",
    }
    conditions["10"] = {
        "text": "ptrace / process injection cannot control the authority",
        "met": attack["F_ptrace"]["verdict"] == "DENIED_BY_DAC"
        and attack["F_ptrace"]["control_attached_agent_owned_process"],
        "evidence": attack["F_ptrace"],
    }
    conditions["11"] = {
        "text": "rootless-container root cannot mutate authority state",
        "met": attack["container_roots"]["I_rootless_container_root"]["verdict"] == "DENIED_BY_DAC",
        "evidence": attack["container_roots"]["I_rootless_container_root"],
    }
    conditions["12"] = {
        "text": "the broker code / control plane is not agent-replaceable",
        "met": not attack["J_broker_replacement"]["control_plane_agent_replaceable"],
        "evidence": attack["J_broker_replacement"],
        "cutover_dependent": True,
    }
    unauthorized_denied = [
        name
        for name, entry in protocol.items()
        if isinstance(entry, dict) and name != "POSITIVE_authorized_promotion" and entry.get("pass")
    ]
    conditions["13"] = {
        "text": "unauthorized IPC requests are denied",
        "met": not protocol["failures"],
        "evidence": {
            "cases": len(unauthorized_denied),
            "failures": protocol["failures"],
        },
    }
    conditions["14"] = {
        "text": "a valid authorized request succeeds",
        "met": protocol["POSITIVE_authorized_promotion"]["pass"],
        "evidence": protocol["POSITIVE_authorized_promotion"],
    }
    conditions["15"] = {
        "text": "an authorized operation leaks no reusable mutation authority",
        "met": attacks["leakage"]["all_denied"],
        "evidence": attacks["leakage"],
    }
    conditions["16"] = {
        "text": "workspace / git operations remain functional",
        "met": attacks["workspace_git"]["all_passed"],
        "evidence": {
            "count": attacks["workspace_git"]["count"],
            "failures": attacks["workspace_git"]["failures"],
        },
    }
    conditions["17"] = {
        "text": "the privilege graph contains no unauthorized path to canonical mutation",
        "met": closure["no_unauthorized_path_to_canonical_mutation"]["holds"],
        "evidence": closure["no_unauthorized_path_to_canonical_mutation"],
        "cutover_dependent": True,
    }
    # Condition 18 is filled in by `repeatability()` once the verdict and digest
    # for this run are known; it is the only condition that cannot be evaluated
    # from a single run's measurements.
    #
    # Condition 19 is the hardening added after the cutover preflight found that
    # `registry["unknown_paths"]` was recorded and consumed by nothing: a host
    # whose only remaining escalation path was UNKNOWN would have been reported
    # VERIFIED. It unions the registry's UNKNOWNs with the read-only topology
    # inventory's.
    conditions["19"] = exclusivity_model.unknown_condition(
        registry,
        topology,
        surface_registry=surface_registry,
    )
    return conditions


def repeatability(verdict: str, digest: str) -> dict:
    """Condition 18, evaluated across runs rather than within one.

    Each run appends its verdict and evidence digest. The condition holds when
    the last four entries agree on both. A digest that drifts between runs means
    some measurement is not deterministic, which would undermine every other
    condition computed from it.
    """
    history = []
    if os.path.exists(HISTORY_PATH):
        with open(HISTORY_PATH, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    history.append(json.loads(line))
                except ValueError:
                    continue
    history.append({"verdict": verdict, "evidence_digest": digest})
    with open(HISTORY_PATH, "w", encoding="utf-8") as handle:
        for entry in history[-20:]:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
    window = history[-REQUIRED_IDENTICAL_RUNS:]
    identical = (
        len(window) == REQUIRED_IDENTICAL_RUNS
        and len({entry["verdict"] for entry in window}) == 1
        and len({entry["evidence_digest"] for entry in window}) == 1
    )
    return {
        "text": f"{REQUIRED_IDENTICAL_RUNS} consecutive verifier runs produce the "
        f"same result and evidence digest",
        "met": identical,
        "evidence": {
            "runs_recorded": len(history),
            "window": window,
            "distinct_verdicts": sorted({e["verdict"] for e in window}),
            "distinct_digests": sorted({e["evidence_digest"][:16] for e in window}),
        },
    }


def property_split(conditions: dict, registry: dict) -> dict:
    """Section 15: three properties that fail independently."""
    dac = all(conditions[key]["met"] for key in ("03", "04", "05"))
    # 19 belongs to exclusivity: an unresolved escalation path is exactly the
    # question "can the agent obtain equivalent capability", left unanswered.
    exclusivity = all(
        conditions[key]["met"] for key in ("06", "07", "08", "09", "10", "11", "12", "19")
    )
    liveness = all(conditions[key]["met"] for key in ("13", "14", "15", "16"))
    return {
        "A_dac_effectiveness": {
            "pass": dac,
            "means": "does uid separation make content and metadata mutation fail",
        },
        "B_principal_exclusivity": {
            "pass": exclusivity,
            "means": "can the agent become root, the authority uid, or otherwise "
            "obtain equivalent capability",
            "blocked_by": registry["root_equivalent_paths"],
        },
        "C_governed_liveness": {
            "pass": liveness,
            "means": "can authorized canonical changes still occur through the broker",
        },
        "complete": dac and exclusivity and liveness,
    }


def conditional_result(conditions: dict) -> dict:
    """What would hold after the cutover, computed rather than promised."""
    # 18 is a property of the verifier's own determinism, not of the
    # architecture or of the host's privilege configuration. Counting it as an
    # architectural failure while the run window fills would misreport every
    # run before the fourth.
    failed = [key for key, entry in conditions.items() if entry["met"] is False and key != "18"]
    failed_independent = [key for key in failed if not conditions[key].get("cutover_dependent")]
    failed_cutover = [key for key in failed if conditions[key].get("cutover_dependent")]
    return {
        "failed_now": sorted(failed),
        "repeatability_condition_18_met": conditions["18"]["met"],
        "failed_for_architectural_reasons": sorted(failed_independent),
        "failed_only_because_of_host_privilege_configuration": sorted(failed_cutover),
        "would_hold_after_cutover": not failed_independent,
        "interpretation": (
            "every condition that fails is one the cutover deltas remove. No "
            "condition fails for a reason inherent to the architecture, so the "
            "V2 impossibility is a property of this host's privilege topology "
            "and not of the design."
            if not failed_independent
            else "at least one condition fails for a reason the cutover does not "
            "address; the architecture itself is insufficient as built."
        ),
    }


def evidence_digest(
    attacks: dict,
    registry: dict,
    analysis: dict,
    graph: dict,
    conditions: dict,
    topology: dict | None = None,
) -> str:
    """A digest over the security-relevant surface only.

    Built from an explicit whitelist rather than by filtering volatile keys out
    of the raw JSON. The blacklist approach drifted on every run -- temporary
    paths leak into error strings, pids into diagnostics -- which made condition
    18 unsatisfiable for reasons that had nothing to do with the security
    result. What must be reproducible is the set of verdicts, so that is what is
    hashed.

    The whitelist originally omitted the privilege inventory entirely, and the
    omission was measured rather than suspected: adding the whole `filecaps`
    surface took the inventory from 46 paths to 57 and left this digest
    *bit-identical*, because only condition 19's boolean reached it and that
    boolean did not flip. "Four consecutive runs with the same evidence digest"
    would then have said nothing about whether the same privilege surface was
    measured each time. The inventory's classification summary is verdict-like
    and stable, so it belongs here; the raw evidence blobs (modes, hashes,
    command output) do not, and stay out.
    """
    surface = {
        "carriers": {entry["carrier"]: entry["verdict"] for entry in attacks["carriers"]},
        "attacks": {
            "D_subuid": attacks["attacks"]["D_subuid"]["verdict"],
            "E_setns_procfs": attacks["attacks"]["E_setns"]["procfs_route"]["verdict"],
            "E_setns_docker": attacks["attacks"]["E_setns"]["docker_route"]["verdict"],
            "F_ptrace": attacks["attacks"]["F_ptrace"]["verdict"],
            "F_ptrace_control": attacks["attacks"]["F_ptrace"][
                "control_attached_agent_owned_process"
            ],
            "H_rootful": attacks["attacks"]["container_roots"]["H_rootful_container_root"][
                "verdict"
            ],
            "I_rootless": attacks["attacks"]["container_roots"]["I_rootless_container_root"][
                "verdict"
            ],
            "J1": attacks["attacks"]["J_broker_replacement"]["J1_host_write_to_code"]["verdict"],
            "J2": attacks["attacks"]["J_broker_replacement"]["J2_docker_cp_into_container"][
                "verdict"
            ],
            "K_socket": attacks["attacks"]["K_socket_impersonation"]["verdict"],
            "Q_key": attacks["attacks"]["Q_key_material"]["verdict"],
        },
        "protocol": {
            name: entry.get("pass")
            for name, entry in attacks["protocol"].items()
            if isinstance(entry, dict)
        },
        "leakage": {
            name: entry.get("verdict")
            for name, entry in attacks["leakage"].items()
            if isinstance(entry, dict)
        },
        "git_all_passed": attacks["workspace_git"]["all_passed"],
        "git_check_count": attacks["workspace_git"]["count"],
        "identity_separation": {
            "agent_uid": attacks["environment"]["agent_uid"],
            "broker_uid": attacks["environment"]["broker_uid"],
            "decision_uid": attacks["environment"]["decision_uid"],
        },
        "registry": {
            name: entry["classification"] for name, entry in registry["mechanisms"].items()
        },
        "root_equivalent_paths": sorted(registry["root_equivalent_paths"]),
        "authority_uid": analysis["selected_authority_uid"],
        "graph_edges": sorted(
            f"{entry['from']}|{entry['relation']}|{entry['to']}" for entry in graph["edges"]
        ),
        "graph_closed": graph["closure"]["closed"],
        "conditions": {key: entry["met"] for key, entry in conditions.items() if key != "18"},
        # The privilege inventory, as classifications rather than raw evidence:
        # which surfaces were measured, and every path that blocks, with its
        # terminal state. A run that measured a different surface, or moved a
        # path between terminal states, now produces a different digest.
        "topology": {
            "surfaces": sorted(
                str(path_id).split(":", 1)[0] for path_id in (topology or {}).get("paths", {})
            ),
            "counts": (topology or {}).get("counts"),
            "classifications": {
                path_id: entry.get("classification")
                for path_id, entry in sorted((topology or {}).get("paths", {}).items())
            },
            "measured_as_host_identity": (topology or {})
            .get("measurement_context", {})
            .get("host_representative"),
        },
    }
    return hashlib.sha256(
        json.dumps(surface, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def main() -> int:
    print("=" * 72)
    print("CANONICAL_STATE_PROMOTION_AUTHORITY_V3 verifier")
    print("=" * 72)

    pre = preflight.run()
    if not pre["environment_equivalence"]["equivalent"]:
        die(ENV_NOT_EQUIVALENT, f"{pre['environment_equivalence']['problems']}")

    for stale in (ATTACK_RESULTS, CARRIER_MATRIX):
        if os.path.exists(stale):
            os.unlink(stale)

    registry_run = run_stage(
        "root-equivalence registry",
        [sys.executable, os.path.join(HERE, "root_equivalence.py")],
    )
    if registry_run.returncode != 0 or not os.path.exists(REGISTRY):
        die(BLOCKED_ROOT, f"registry failed: {registry_run.stderr.strip()[:400]}")

    analysis_run = run_stage(
        "authority principal analysis",
        [sys.executable, os.path.join(HERE, "authority_principal.py")],
    )
    if analysis_run.returncode != 0 or not os.path.exists(ANALYSIS):
        die(BLOCKED_ROOT, f"analysis failed: {analysis_run.stderr.strip()[:400]}")

    topology_run = run_stage(
        "privilege topology inventory",
        [sys.executable, os.path.join(HERE, "privilege_topology.py")],
    )
    if topology_run.returncode != 0 or not os.path.exists(TOPOLOGY):
        die(
            BLOCKED_UNCERTAIN,
            f"topology inventory failed: {topology_run.stderr.strip()[:400]}",
        )

    # Resolution turns every UNKNOWN into one of four terminal classifications
    # and stamps the measurement context. rc=1 means "resolved, and something is
    # still blocking" -- that is data, not a stage failure. rc=2 means the
    # process is not measuring the host identity, which is fatal to the verdict.
    resolution_run = run_stage(
        "privilege resolution",
        [sys.executable, os.path.join(HERE, "privilege_resolution.py")],
    )
    if resolution_run.returncode == 2 or not os.path.exists(TOPOLOGY_FINAL):
        die(
            BLOCKED_UNCERTAIN,
            "privilege resolution refused or produced no inventory: "
            f"{(resolution_run.stdout + resolution_run.stderr).strip()[:600]}",
        )

    attacks_run = run_stage(
        "attack suite",
        [sys.executable, os.path.join(HERE, "attack_suite", "run_attacks_v3.py")],
    )
    if attacks_run.returncode != 0 or not os.path.exists(ATTACK_RESULTS):
        die(BLOCKED_ROOT, f"attack suite failed: {attacks_run.stderr.strip()[:600]}")

    with open(ATTACK_RESULTS, encoding="utf-8") as handle:
        attacks = json.load(handle)
    with open(REGISTRY, encoding="utf-8") as handle:
        registry = json.load(handle)
    with open(ANALYSIS, encoding="utf-8") as handle:
        analysis = json.load(handle)

    with open(TOPOLOGY_FINAL, encoding="utf-8") as handle:
        topology = json.load(handle)
    with open(SURFACE_REGISTRY, encoding="utf-8") as handle:
        surface_registry = json.load(handle)

    graph = privilege_graph.build_and_save(attacks, registry)
    conditions = conditions_from(
        attacks,
        registry,
        analysis,
        graph,
        topology,
        surface_registry,
    )
    digest = evidence_digest(attacks, registry, analysis, graph, conditions, topology)
    # Section 16's ordering, now computed by exclusivity_model: root-equivalence
    # dominates everything, then authority-equivalence, then UNRESOLVED privilege
    # paths -- which can no longer be silently absorbed into a VERIFIED verdict.
    exclusivity = exclusivity_model.compute(
        registry,
        topology,
        graph["closure"],
        conditions,
        ignore_conditions={"18"},
        surface_registry=surface_registry,
    )
    verdict = exclusivity["verdict"]

    conditions["18"] = repeatability(verdict, digest)
    split = property_split(conditions, registry)
    conditional = conditional_result(conditions)

    frozen_after = preflight.freeze_prior()
    prior_unchanged = all(
        frozen_after[name]["aggregate_sha256"] == pre["prior_packages"][name]["aggregate_sha256"]
        for name in frozen_after
        if "aggregate_sha256" in frozen_after[name]
    )

    result = {
        "verdict": verdict,
        "property_split": split,
        "conditions": conditions,
        "conditional_result": conditional,
        "privilege_graph_closure": graph["closure"],
        "root_equivalent_paths": registry["root_equivalent_paths"],
        "unknown_paths": registry["unknown_paths"],
        "exclusivity": exclusivity,
        "privilege_topology": {
            "source": os.path.basename(TOPOLOGY_FINAL),
            "counts": topology["counts"],
            "root_equivalent_paths": topology["root_equivalent_paths"],
            "unknown_privilege_paths": topology["unknown_privilege_paths"],
            "requires_operator_evidence_paths": topology.get(
                "requires_operator_evidence_paths", []
            ),
            "not_present_paths": topology.get("not_present_paths", []),
            "measurement_context_host_representative": topology.get("measurement_context", {}).get(
                "host_representative"
            ),
            "measurement_context_fingerprint": topology.get("measurement_context", {}).get(
                "fingerprint_sha256"
            ),
        },
        "selected_authority_uid": analysis["selected_authority_uid"],
        "prior_packages_unchanged": prior_unchanged,
        "environment_equivalence": pre["environment_equivalence"],
        "v2_evidence": pre["v2_evidence_as_read_from_disk"],
        "evidence_digest": digest,
    }
    with open(RESULT_PATH, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True, default=str)

    print()
    print(f"VERDICT: {verdict}")
    print()
    print("Section 16 conditions")
    for key in sorted(conditions):
        entry = conditions[key]
        status = {True: "PASS", False: "FAIL", None: "n/a "}[entry["met"]]
        tag = "  (cutover-dependent)" if entry.get("cutover_dependent") else ""
        print(f"  [{status}] {key}. {entry['text']}{tag}")
    print()
    print("Section 15 property split")
    for name, entry in split.items():
        if name == "complete":
            continue
        print(f"  [{'PASS' if entry['pass'] else 'FAIL'}] {name}")
    print()
    print("Conditional on the cutover deltas")
    print(f"  failed now:                        {conditional['failed_now']}")
    print(f"  failed for architectural reasons:  {conditional['failed_for_architectural_reasons']}")
    print(
        f"  failed only due to host privilege: "
        f"{conditional['failed_only_because_of_host_privilege_configuration']}"
    )
    print(f"  would hold after cutover:          {conditional['would_hold_after_cutover']}")
    print()
    print(f"root-equivalent paths: {exclusivity['root_equivalent_paths']}")
    unresolved = exclusivity["unresolved_privilege_paths"]
    print(
        f"unresolved privilege paths: {len(unresolved)} "
        f"({len(exclusivity['unknown_privilege_paths'])} UNKNOWN + "
        f"{len(exclusivity['requires_operator_evidence_paths'])} "
        f"REQUIRES_OPERATOR_EVIDENCE)"
    )
    print(f"  {unresolved[:4]}{' ...' if len(unresolved) > 4 else ''}")
    print(f"inventory admissibility: {exclusivity['inventory_admissibility']}")
    for reason in exclusivity["reasons"]:
        print(f"  verdict reason: {reason}")
    print(f"privilege graph closed: {graph['closure']['closed']}")
    print(f"prior packages unchanged: {prior_unchanged}")
    print(f"evidence digest: {result['evidence_digest'][:32]}")
    print(f"\nresult written to {RESULT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
