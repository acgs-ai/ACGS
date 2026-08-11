"""Section 13: the privilege graph, and closure as a reachability property.

Every edge here is either experimentally demonstrated or structurally proven,
and each carries the measurement it came from. Edges are *not* added because
they seem plausible: an edge the attack suite could not demonstrate is absent,
and an attack that succeeded contributes an edge even when that is inconvenient.

Closure is then three reachability questions, computed rather than argued:

    1. no path  agent -> canonical_store  except one through the authorized
       decision -> broker -> bounded effect chain
    2. no path  agent -> authority_principal
    3. no path  agent -> host_root

The `authorized` flag on an edge is what makes question 1 answerable: the
legitimate path exists by design, so the search is for a path avoiding it.
"""

from __future__ import annotations

import json
import os
from collections import deque

HERE = os.path.dirname(os.path.abspath(__file__))
GRAPH_PATH = os.path.join(HERE, "PRIVILEGE_GRAPH.json")

AGENT = "agent_principal"
AUTHORITY = "authority_principal"
HOST_ROOT = "host_root"
AGENT_USERNS_ROOT = "agent_userns_root"
ROOTLESS_ROOT = "rootless_container_root"
ROOTFUL_ROOT = "rootful_container_root"
AUTHORITY_PROCESS = "authority_process"
STORE = "canonical_store"
IPC = "broker_ipc"
WORKSPACE = "workspace"

NODES = [
    AGENT,
    AUTHORITY,
    HOST_ROOT,
    AGENT_USERNS_ROOT,
    ROOTLESS_ROOT,
    ROOTFUL_ROOT,
    AUTHORITY_PROCESS,
    STORE,
    IPC,
    WORKSPACE,
]


def _denied(entry: dict) -> bool:
    return entry.get("verdict") == "DENIED_BY_DAC"


def build(attacks: dict, registry: dict) -> dict:
    edges: list[dict] = []

    def edge(source, relation, target, evidence, demonstrated, authorized=False):
        edges.append(
            {
                "from": source,
                "relation": relation,
                "to": target,
                "evidence": evidence,
                "demonstrated": demonstrated,
                "authorized": authorized,
            }
        )

    attack = attacks["attacks"]
    carriers = {entry["carrier"]: entry for entry in attacks["carriers"]}

    # -- the agent's own reach over canonical state
    direct = [name for name, entry in carriers.items() if entry["verdict"] == "NOT_DENIED"]
    if direct:
        edge(AGENT, "can_write", STORE, f"carriers not denied: {direct}", True)

    # -- the legitimate path, which must exist for property C
    positive = attacks["protocol"]["POSITIVE_authorized_promotion"]
    edge(
        AGENT,
        "can_send_authorized_request",
        IPC,
        "the agent may ask; asking is not authority",
        True,
    )
    edge(
        IPC,
        "can_delegate",
        AUTHORITY_PROCESS,
        "requests are validated before any effect",
        True,
    )
    edge(
        AUTHORITY_PROCESS,
        "can_write",
        STORE,
        f"authorized promotion {positive['before'][:12]} -> {positive['after'][:12]}",
        positive["pass"],
        authorized=True,
    )

    # -- namespace and delegation routes
    subuid = attack["D_subuid"]
    edge(
        AGENT,
        "can_map_uid",
        AGENT_USERNS_ROOT,
        "newuidmap maps the delegated range",
        True,
    )
    if subuid["verdict"] != "DENIED_BY_DAC":
        edge(AGENT_USERNS_ROOT, "can_write", STORE, "subuid remap wrote canonical", True)

    rootless = attack["container_roots"].get("I_rootless_container_root", {})
    edge(
        AGENT,
        "can_control",
        ROOTLESS_ROOT,
        "rootless container runtime available to the agent",
        True,
    )
    if rootless.get("verdict") == "NOT_DENIED":
        edge(
            ROOTLESS_ROOT,
            "can_write",
            STORE,
            "rootless container root mutated canonical",
            True,
        )

    # -- the root-equivalent route
    docker = registry["mechanisms"]["docker_rootful"]
    if docker["classification"] == "ROOT_EQUIVALENT":
        edge(
            AGENT,
            "can_control",
            ROOTFUL_ROOT,
            f"writable rootful docker socket: {registry['docker_access_route']['routes']}",
            True,
        )
        edge(
            ROOTFUL_ROOT,
            "can_impersonate",
            HOST_ROOT,
            "identity uid_map inside the container; chown to an arbitrary uid "
            "succeeded on a host file",
            True,
        )
    rootful = attack["container_roots"]["H_rootful_container_root"]
    if rootful["verdict"] == "EXPECTED_SUCCESS":
        edge(
            HOST_ROOT,
            "can_write",
            STORE,
            "container root wrote and chowned canonical",
            True,
        )
        edge(
            HOST_ROOT,
            "can_impersonate",
            AUTHORITY,
            "root may setuid to any principal",
            False,
        )

    # -- control-plane replacement
    replacement = attack["J_broker_replacement"]
    if replacement["J2_docker_cp_into_container"]["verdict"] == "EXPECTED_SUCCESS":
        # Routed through the container root, not drawn as a direct agent power.
        # `docker cp` is the socket's capability; drawing it agent->authority
        # would imply a replacement power independent of Docker, which is not
        # what was measured, and would survive in the graph after a reviewer
        # removed the group membership.
        edge(
            ROOTFUL_ROOT,
            "can_replace",
            AUTHORITY_PROCESS,
            "docker cp overwrote the authority's code inside the container",
            True,
        )
    if replacement["J1_host_write_to_code"]["verdict"] == "NOT_DENIED":
        # This one *is* a direct agent power: an ordinary write on the host.
        edge(
            AGENT,
            "can_replace",
            AUTHORITY_PROCESS,
            "agent wrote the authority code directory on the host",
            True,
        )

    # -- process control
    ptrace = attack["F_ptrace"]
    if ptrace.get("verdict") == "NOT_DENIED":
        edge(
            AGENT,
            "can_ptrace",
            AUTHORITY_PROCESS,
            "PTRACE_ATTACH from a non-descendant succeeded",
            True,
        )
    setns = attack["E_setns"]
    if setns["procfs_route"]["verdict"] == "NOT_DENIED":
        edge(
            AGENT,
            "can_setns",
            AUTHORITY_PROCESS,
            "namespace handles of the authority were openable",
            True,
        )
    if setns["docker_route"]["verdict"] == "EXPECTED_SUCCESS":
        edge(
            ROOTFUL_ROOT,
            "can_control",
            AUTHORITY_PROCESS,
            "docker exec ran a command inside the authority container",
            True,
        )

    # -- workspace, present so the graph shows what the agent legitimately owns
    edge(AGENT, "can_write", WORKSPACE, "the workspace is agent-owned", True)

    return {"nodes": NODES, "edges": edges}


def _reachable(edges: list[dict], start: str, skip_authorized: bool) -> dict:
    adjacency: dict[str, list[dict]] = {}
    for entry in edges:
        if skip_authorized and entry.get("authorized"):
            continue
        adjacency.setdefault(entry["from"], []).append(entry)
    seen = {start: []}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        for entry in adjacency.get(node, []):
            if entry["to"] in seen:
                continue
            seen[entry["to"]] = seen[node] + [
                f"{entry['from']} --{entry['relation']}--> {entry['to']}"
            ]
            queue.append(entry["to"])
    return seen


def _authorized_chain_present(edges: list[dict]) -> bool:
    """The one path that is supposed to exist, matched edge by edge."""
    required = (
        (AGENT, "can_send_authorized_request", IPC, False),
        (IPC, "can_delegate", AUTHORITY_PROCESS, False),
        (AUTHORITY_PROCESS, "can_write", STORE, True),
    )
    for source, relation, target, authorized in required:
        if not any(
            entry["from"] == source
            and entry["relation"] == relation
            and entry["to"] == target
            and entry["demonstrated"]
            and (entry.get("authorized") is authorized)
            for entry in edges
        ):
            return False
    return True


def closure(graph: dict) -> dict:
    edges = graph["edges"]
    unauthorized = _reachable(edges, AGENT, skip_authorized=True)
    any_path = _reachable(edges, AGENT, skip_authorized=False)

    conditions = {
        "no_unauthorized_path_to_canonical_mutation": {
            "holds": STORE not in unauthorized,
            "path": unauthorized.get(STORE),
        },
        "no_path_to_authority_principal": {
            "holds": AUTHORITY not in any_path,
            "path": any_path.get(AUTHORITY),
        },
        "no_path_to_host_root": {
            "holds": HOST_ROOT not in any_path,
            "path": any_path.get(HOST_ROOT),
        },
        # Checked as a specific chain, not "some path exists". A generic search
        # happily matched agent --can_replace--> authority_process, which is an
        # attack edge; reporting that as the authorized path would have claimed
        # governed liveness on the strength of a control-plane compromise.
        "authorized_path_exists": {
            "holds": _authorized_chain_present(edges),
            "path": [
                "agent_principal --can_send_authorized_request--> broker_ipc",
                "broker_ipc --can_delegate--> authority_process",
                "authority_process --can_write--> canonical_store (authorized)",
            ],
        },
    }
    return {
        "conditions": conditions,
        "closed": all(
            entry["holds"] for name, entry in conditions.items() if name != "authorized_path_exists"
        )
        and conditions["authorized_path_exists"]["holds"],
        "reachable_without_authorization": sorted(unauthorized),
    }


def build_and_save(attacks: dict, registry: dict) -> dict:
    graph = build(attacks, registry)
    graph["closure"] = closure(graph)
    with open(GRAPH_PATH, "w", encoding="utf-8") as handle:
        json.dump(graph, handle, indent=2, sort_keys=True)
    return graph


if __name__ == "__main__":
    with open(os.path.join(HERE, "attack_results.json"), encoding="utf-8") as h:
        attacks = json.load(h)
    with open(os.path.join(HERE, "ROOT_EQUIVALENCE_REGISTRY.json"), encoding="utf-8") as h:
        registry = json.load(h)
    graph = build_and_save(attacks, registry)
    print(json.dumps(graph["closure"], indent=2))
