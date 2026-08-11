#!/usr/bin/env python3
"""Cutover readiness gate for CANONICAL_STATE_PROMOTION_AUTHORITY_V3.

History, because it explains the shape of this file. The cutover preflight found
that `verify_v3.py` computed condition 06 from `bool(root_equivalent_paths)`
while `unknown_paths` was recorded and consumed by no condition -- so a host with
Docker removed and `sudo` still UNKNOWN would have been reported
VERIFIED_EXCLUSIVE_AUTHORITY. This gate was written first, outside the verifier,
so the hole could be closed without an unvalidatable edit to it.

That hole is now closed *inside* the verifier: `exclusivity_model` computes the
verdict, condition **19** consumes the unioned UNKNOWN paths, and
`privilege_topology.py` runs as a verifier stage (see `HARDENING_PATCH.diff`).
This gate shares that model, so the two cannot drift on the privilege question.

What the gate still adds, and the verifier does not check:

  * the cutover *readiness* checklist -- authority uid reserved and outside every
    delegation, store/code/IPC owned by it, services running under it;
  * a verdict computed from the read-only inventories alone, with no container
    started, so it can be run on a host mid-cutover;
  * input binding: it records the sha256 of every document it read, because a
    verifier verdict is closure only against the same host state.

Read-only. It opens files and exits.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import exclusivity_model  # noqa: E402

REGISTRY = os.path.join(HERE, "ROOT_EQUIVALENCE_REGISTRY.json")
VERIFICATION = os.path.join(HERE, "verification_result.json")
PREFLIGHT = os.path.join(HERE, "PREFLIGHT_AUDIT.json")
#: Prefer the resolved inventory (four terminal classifications, context-bound).
#: The raw one is the fallback so this gate still runs on a host where
#: resolution has not been executed yet -- and, lacking a measurement context,
#: the raw one is inadmissible to the model, which fails closed.
TOPOLOGY_FINAL = os.path.join(HERE, "PRIVILEGE_TOPOLOGY_FINAL.json")
TOPOLOGY_RAW = os.path.join(HERE, "PRIVILEGE_TOPOLOGY.json")
TOPOLOGY = TOPOLOGY_FINAL if os.path.exists(TOPOLOGY_FINAL) else TOPOLOGY_RAW

READY = "READY_FOR_FINAL_PROOF"
BLOCKED_ROOT = exclusivity_model.BLOCKED_ROOT
BLOCKED_UNCERTAIN = exclusivity_model.BLOCKED_UNCERTAIN
BLOCKED_OTHER = "BLOCKED_OTHER"

#: Precedence. A measured root path outranks an unresolved one, which outranks
#: a readiness item that is merely not done yet.
GATE_PRECEDENCE = (BLOCKED_ROOT, BLOCKED_UNCERTAIN, BLOCKED_OTHER)


def load(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except OSError:
        return None


def input_digests() -> dict:
    """Bind this result to the exact input documents it was computed from.

    The gate has no way to tell a fresh audit from one taken before a rollback,
    so it records what it read instead of pretending to know when it was taken.
    """
    out = {}
    for path in (REGISTRY, VERIFICATION, PREFLIGHT, TOPOLOGY):
        name = os.path.basename(path)
        try:
            with open(path, "rb") as handle:
                data = handle.read()
            out[name] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "mtime": int(os.stat(path).st_mtime),
                "bytes": len(data),
            }
        except OSError as exc:
            out[name] = {"unreadable": str(exc)}
    return out


def check(name: str, state: str, detail: object, blocks: str | None) -> dict:
    return {"check": name, "state": state, "detail": detail, "blocks": blocks}


def evaluate() -> dict:
    registry = load(REGISTRY)
    verification = load(VERIFICATION)
    preflight = load(PREFLIGHT)
    checks: list[dict] = []

    if registry is None:
        return {
            "verdict": BLOCKED_OTHER,
            "checks": [check("registry_present", "MISSING", REGISTRY, BLOCKED_OTHER)],
        }

    # Derived from the per-mechanism terminal states and unioned with the list
    # the registry declares -- not the declared list alone. Reading the summary
    # only would let an edit to that one field clear the check while every
    # mechanism record still said ROOT_EQUIVALENT.
    root_paths = sorted(
        set(registry.get("root_equivalent_paths", [])) | exclusivity_model.derive(registry)["root"]
    )
    checks.append(
        check(
            "no_root_equivalent_mechanism",
            "MET" if not root_paths else "BLOCKED",
            {
                "root_equivalent_paths": root_paths,
                "routes": registry.get("docker_access_route", {}).get("routes"),
            },
            None if not root_paths else BLOCKED_ROOT,
        )
    )

    auth_paths = registry.get("authority_equivalent_paths", [])
    checks.append(
        check(
            "no_authority_equivalent_mechanism",
            "MET" if not auth_paths else "BLOCKED",
            {"authority_equivalent_paths": auth_paths},
            None if not auth_paths else BLOCKED_ROOT,
        )
    )

    # The gap this program exists for. UNKNOWN is not a pass anywhere.
    # Both inventories are unioned by exclusivity_model: the registry probes by
    # executing a container, the topology enumerates the surface read-only, and
    # neither is a superset of the other.
    topology = load(TOPOLOGY)
    paths = exclusivity_model.collect(registry, topology)
    unresolved = paths["unresolved_privilege_paths"]
    checks.append(
        check(
            "no_unresolved_escalation_mechanism",
            "MET" if not unresolved else "UNRESOLVED",
            {
                "unresolved_privilege_paths": unresolved,
                "count": len(unresolved),
                "unknown": paths["unknown_privilege_paths"],
                "requires_operator_evidence": paths["requires_operator_evidence_paths"],
                "from_registry": registry.get("unknown_paths", []),
                "from_topology": (topology or {}).get("unknown_privilege_paths", []),
                "why": "condition 19 now consumes these in verify_v3.py; before "
                "the hardening they were recorded and consumed by nothing, so a "
                "host whose only remaining path was UNKNOWN would have verified. "
                "REQUIRES_OPERATOR_EVIDENCE blocks identically -- renaming an "
                "UNKNOWN does not resolve it.",
            },
            None if not unresolved else BLOCKED_UNCERTAIN,
        )
    )
    checks.append(
        check(
            "every_inventory_host_measured",
            "MET" if paths["every_inventory_host_measured"] else "UNRESOLVED",
            {
                "admissibility": paths["inventory_admissibility"],
                "surfaces_required": paths["surfaces_required"],
                "surfaces_covered": paths["surfaces_covered"],
                "surfaces_missing": paths["surfaces_missing"],
                "topology_source": os.path.basename(TOPOLOGY),
                "why": "two conditions, both required. Admissibility: an "
                "inventory taken inside a sandbox reports "
                "root_equivalent_paths == [] with no host change. Coverage: an "
                "inventory that measured only one surface is silent about the "
                "rest. Silence is not absence in either case",
            },
            None if paths["every_inventory_host_measured"] else BLOCKED_UNCERTAIN,
        )
    )
    checks.append(
        check(
            "privilege_topology_inventory_present",
            "MET" if topology is not None else "MISSING",
            {
                "path": TOPOLOGY,
                "counts": (topology or {}).get("counts"),
                "root_equivalent_paths": (topology or {}).get("root_equivalent_paths"),
            },
            None if topology is not None else BLOCKED_UNCERTAIN,
        )
    )
    # Read through the model, not around it: a path reported by an inventory
    # the model ruled inadmissible is not a finding about this host, and a gate
    # that consumed it directly would disagree with the verifier on identical
    # input -- the drift the shared model exists to prevent. The raw list is
    # still recorded so the disagreement is visible rather than invisible.
    topology_contributed = (
        set((topology or {}).get("root_equivalent_paths", []))
        | exclusivity_model.derive(topology)["root"]
    )
    topo_root = [path for path in paths["root_equivalent_paths"] if path in topology_contributed]
    if topo_root:
        checks.append(
            check(
                "no_root_equivalent_path_in_topology",
                "BLOCKED",
                {
                    "root_equivalent_paths": topo_root,
                    "as_recorded_in_inventory": (topology or {}).get("root_equivalent_paths", []),
                    "inventory_admissible": paths["inventory_admissibility"].get(
                        "PRIVILEGE_TOPOLOGY"
                    ),
                },
                BLOCKED_ROOT,
            )
        )

    if preflight is not None:
        dock = preflight.get("identity", {}).get("docker_group", {})
        in_cred = dock.get("agent_has_gid_in_kernel_credential")
        checks.append(
            check(
                "agent_not_in_docker_group",
                "MET" if in_cred is False else "BLOCKED",
                {
                    "kernel_credential_contains_docker_gid": in_cred,
                    "roster": dock.get("roster_members"),
                },
                None if in_cred is False else BLOCKED_ROOT,
            )
        )
        reachable = preflight.get("docker", {}).get("socket_connect_reachable")
        rootless = preflight.get("docker", {}).get("rootless")
        checks.append(
            check(
                "rootful_daemon_unreachable",
                "MET" if reachable is False else "BLOCKED",
                {"socket_connect_reachable": reachable, "rootless": rootless},
                None if reachable is False else BLOCKED_ROOT,
            )
        )
        sudo = preflight.get("sudo", {}).get("classification")
        checks.append(
            check(
                "sudo_resolved",
                "MET" if sudo == "NOT_PRESENT" else "UNRESOLVED",
                {
                    "classification": sudo,
                    "wheel_in_kernel_credential": preflight.get("identity", {}).get(
                        "wheel_in_kernel_credential"
                    ),
                    "pkexec_present": preflight.get("sudo", {}).get("pkexec_present"),
                    "who_resolves": "administrator; requires reading /etc/sudoers and "
                    "/etc/sudoers.d, both unreadable by the agent",
                },
                None if sudo == "NOT_PRESENT" else BLOCKED_UNCERTAIN,
            )
        )
        res = preflight.get("identity_reservation", {})
        reserved = (
            res.get("authority_uid_940", {}).get("allocated")
            and res.get("decision_uid_941", {}).get("allocated")
            and res.get("940_inside_any_delegation") is False
            and res.get("941_inside_any_delegation") is False
        )
        checks.append(
            check(
                "authority_principal_reserved",
                "MET" if reserved else "PENDING",
                {
                    "uid_940": res.get("authority_uid_940"),
                    "uid_941": res.get("decision_uid_941"),
                    "inside_delegation": {
                        "940": res.get("940_inside_any_delegation"),
                        "941": res.get("941_inside_any_delegation"),
                    },
                },
                None if reserved else BLOCKED_OTHER,
            )
        )
        targets = preflight.get("paths", {}).get("cutover_targets", {})
        owned = {k: v.get("owned_by_authority_uid") for k, v in targets.items()}
        all_owned = bool(targets) and all(owned.values())
        checks.append(
            check(
                "store_code_ipc_owned_by_authority",
                "MET" if all_owned else "PENDING",
                {
                    "paths": targets,
                    "note": "absent is not owned; the V3 demonstration runtime is "
                    "ephemeral (/tmp/cspa3-*), so at-rest ownership of the "
                    "IPC endpoints cannot be observed between runs",
                },
                None if all_owned else BLOCKED_OTHER,
            )
        )
        units = preflight.get("systemd", {})
        under_uid = [
            unit
            for unit in (
                "promotion-authority.service",
                "promotion-decision.service",
                "promotion-broker.service",
            )
            if units.get(unit, {}).get("LoadState") == "loaded" and units.get(unit, {}).get("User")
        ]
        checks.append(
            check(
                "services_run_under_authority_uid",
                "MET" if under_uid else "PENDING",
                {
                    "loaded_units_with_User": under_uid,
                    "note": "while no unit exists the authority is started by the "
                    "agent's own Docker socket, which is itself the blocker",
                },
                None if under_uid else BLOCKED_OTHER,
            )
        )
    else:
        checks.append(check("preflight_present", "MISSING", PREFLIGHT, BLOCKED_OTHER))

    if verification is not None:
        checks.append(
            check(
                "verifier_last_verdict",
                "INFORMATIONAL",
                {
                    "verdict": verification.get("verdict"),
                    "evidence_digest": verification.get("evidence_digest"),
                    "failed_conditions": verification.get("conditional_result", {}).get(
                        "failed_now"
                    ),
                    "would_hold_after_cutover": verification.get("conditional_result", {}).get(
                        "would_hold_after_cutover"
                    ),
                    "caveat": "would_hold_after_cutover is computed from the "
                    "Docker delta alone; it does not account for unknown_paths",
                },
                None,
            )
        )

    blocking = [c for c in checks if c["blocks"]]
    verdict = READY
    for candidate in GATE_PRECEDENCE:
        if any(c["blocks"] == candidate for c in blocking):
            verdict = candidate
            break

    return {
        "verdict": verdict,
        "specific_reason": (
            exclusivity_model.specific_reason(verdict, paths, [])
            if verdict in (BLOCKED_ROOT, BLOCKED_UNCERTAIN)
            else verdict
        ),
        "checks": checks,
        "blocking_checks": [c["check"] for c in blocking],
        "read_only": True,
        "inputs": input_digests(),
        "unenforced_coupling": (
            "verify_v3.py contains no reference to this gate and will print a "
            "verdict whether or not the gate cleared. A "
            "VERIFIED_EXCLUSIVE_AUTHORITY from it is closure only if this gate "
            "returned rc=0 against the same host state -- compare "
            "inputs.PREFLIGHT_AUDIT.json.sha256 with the audit in force when "
            "the verifier ran. The coupling is disclosed, not enforced."
        ),
        "meaning": {
            READY: "every prerequisite is measured met; verify_v3.py may be "
            "re-run and its verdict believed as closure",
            BLOCKED_ROOT: "a root-equivalent path is still measured present",
            BLOCKED_UNCERTAIN: "no root-equivalent path is measured, but at "
            "least one privilege path is UNKNOWN; an unresolved path is not a "
            "pass and closure may not be claimed",
            BLOCKED_OTHER: "no root-equivalence measured, but a prerequisite is "
            "unmet or unresolved; closure may not be claimed",
        }[verdict],
    }


def main() -> int:
    result = evaluate()
    out = os.path.join(HERE, "CUTOVER_GATE.json")
    if "--write" in sys.argv:
        with open(out, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=1, sort_keys=True)
    print(json.dumps(result, indent=1, sort_keys=True))
    print(f"\nVERDICT: {result['verdict']}")
    print(f"blocking: {result['blocking_checks']}")
    return 0 if result["verdict"] == READY else 1


if __name__ == "__main__":
    raise SystemExit(main())
