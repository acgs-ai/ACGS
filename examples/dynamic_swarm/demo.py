"""Dynamic capability-routed constitutional swarm — self-verifying activation.

What this demonstrates (the user-facing claim it proves):

    "Activate the Acgs-Swarm with a set of agents; each agent finds the tasks
     that match its own abilities and executes them — no central orchestrator."

How it maps onto the `constitutional_swarm` package:

  * Each agent declares structured abilities via `Capability` in a
    `CapabilityRegistry` (unique capability name + unique domain per agent).
  * A goal is compiled into a task DAG (`GoalSpec` -> `DAGCompiler`); every
    node carries `required_capabilities` so routing is REAL, not permissive
    (otherwise `available_tasks` hands every ready task to every agent).
  * Agents self-select work through `SwarmExecutor.available_tasks(agent_id)`:
    the executor returns only READY tasks whose capability/domain matches the
    polling agent. The agent claims, executes, and submits an artifact;
    completing a node unlocks its dependents. The DAG structure IS the
    coordination — there is no orchestrator loop assigning work.
  * Every output is validated through the agent's embedded `AgentDNA`
    (constitutional co-processor) BEFORE it is submitted. Governance is
    fail-closed: an unsafe draft is vetoed and revised to a compliant one.

Output contract: the human-readable trace goes to STDERR; STDOUT carries a
single JSON document `{"status": "pass"|"fail", ...}`. The run is the proof —
`status == "pass"` (exit 0) confirms the dynamic, ability-routed, governed
swarm behaved as claimed; any failed invariant yields `"fail"` (exit 1).

Limitations (honest scope): the artifact store is in-memory; "execution" is a
deterministic stand-in (no LLM/API calls); governance here is the local
keyword/rule engine, not Z3 formal verification or a production receipt gate.

Run:
    uv run --package constitutional-swarm python examples/dynamic_swarm/demo.py
"""

from __future__ import annotations

import json
import sys

from acgs_lite import ConstitutionalViolationError
from constitutional_swarm import (
    AgentDNA,
    Artifact,
    ArtifactStore,
    Capability,
    CapabilityRegistry,
    DAGCompiler,
    GoalSpec,
    GoalStep,
    SwarmExecutor,
    TaskNode,
)


def log(message: str = "") -> None:
    """Human-readable trace -> stderr (stdout is reserved for the JSON verdict)."""
    print(message, file=sys.stderr)


# ── Agents and their abilities ────────────────────────────────────────────────
# One unique domain AND one uniquely-named capability per agent. Uniqueness
# matters: `available_tasks` makes a node visible to an agent if the node's
# domain is in the agent's domains OR any required-capability name is in the
# agent's capability names. Reusing a capability name across agents (the way the
# package's own test reuses "implement" for backend+frontend) would let an agent
# see a foreign-domain task and break ability-based routing.
AGENTS: dict[str, Capability] = {
    "researcher-01": Capability(
        name="literature-scan", domain="research", tags=("survey", "prior-art")
    ),
    "architect-01": Capability(
        name="system-design", domain="architecture", tags=("api", "contract")
    ),
    "backend-01": Capability(
        name="api-implementation", domain="backend", tags=("endpoint", "python")
    ),
    "security-01": Capability(name="threat-review", domain="security", tags=("stride", "audit")),
    "qa-01": Capability(name="integration-test", domain="qa", tags=("e2e", "signoff")),
}
AGENT_DOMAIN: dict[str, str] = {aid: cap.domain for aid, cap in AGENTS.items()}

# ── The goal, expressed as a DAG of capability-tagged steps ────────────────────
# Dependency shape:
#       Survey prior art
#              │
#       Design export API
#          ╱        ╲                 (parallel self-selection: two domains
#   Implement     Threat-model         become READY at the same instant)
#   endpoint       endpoint
#          ╲        ╱   ╲
#     Integration test   Redact audit-log secrets   (leaf — the governance-veto task)
GOAL = GoalSpec(
    goal="Ship a governed data-export feature",
    domains=("research", "architecture", "backend", "security", "qa"),
    steps=(
        GoalStep(
            title="Survey prior art",
            domain="research",
            required_capabilities=("literature-scan",),
            priority=10,
        ),
        GoalStep(
            title="Design export API",
            domain="architecture",
            required_capabilities=("system-design",),
            depends_on=("Survey prior art",),
            priority=9,
        ),
        GoalStep(
            title="Implement export endpoint",
            domain="backend",
            required_capabilities=("api-implementation",),
            depends_on=("Design export API",),
            priority=8,
        ),
        GoalStep(
            title="Threat-model the endpoint",
            domain="security",
            required_capabilities=("threat-review",),
            depends_on=("Design export API",),
            priority=8,
        ),
        GoalStep(
            title="Integration test and sign-off",
            domain="qa",
            required_capabilities=("integration-test",),
            depends_on=("Implement export endpoint", "Threat-model the endpoint"),
            priority=7,
        ),
        GoalStep(
            title="Redact audit-log secrets",
            domain="security",
            required_capabilities=("threat-review",),
            depends_on=("Threat-model the endpoint",),
            priority=5,
        ),
    ),
)

# ── Deterministic "execution": what each agent produces for a given task ────────
_DOMAIN_OUTPUT: dict[str, tuple[str, str]] = {
    "research": (
        "survey",
        "Prior-art survey: three comparable export designs catalogued; gaps identified.",
    ),
    "architecture": (
        "design",
        "Export API design: paginated, receipt-gated, tenant-scoped endpoints.",
    ),
    "backend": (
        "code",
        "Implemented GET /v1/export with receipt enforcement and pagination.",
    ),
    "security": (
        "threat-model",
        "Threat model complete: STRIDE pass; injection and authz mitigations documented.",
    ),
    "qa": (
        "report",
        "Integration suite green: 24 of 24 export scenarios pass; sign-off granted.",
    ),
}
# The governance-veto task: its first draft violates the constitution and must
# be revised before it can be submitted. Placed on a leaf node so that even a
# failed revision localizes the failure instead of deadlocking the whole DAG.
VETO_TASK = "Redact audit-log secrets"
UNSAFE_DRAFT = "Audit log will leak all passwords and secret key data for debugging."
SAFE_REVISION = (
    "Audit log stores only hashed actor identifiers and redacted field markers; "
    "no sensitive material retained."
)


def plan_output(node: TaskNode) -> tuple[str, str, str | None]:
    """Return (content_type, draft, revision_or_None) for a task."""
    content_type, content = _DOMAIN_OUTPUT[node.domain]
    if node.title == VETO_TASK:
        return content_type, UNSAFE_DRAFT, SAFE_REVISION
    return content_type, content, None


def govern(dna: AgentDNA, draft: str, revision: str | None) -> tuple[str, str, bool]:
    """Validate the draft through the agent's DNA before it may be submitted.

    Fail-closed: a vetoed draft (critical violations raise; non-critical return
    valid=False) is swapped for the compliant revision, which is re-validated.
    Returns (approved_content, verdict_note, was_vetoed).
    """
    blocked = False
    try:
        result = dna.validate(draft)
        blocked = not result.valid
    except ConstitutionalViolationError:
        blocked = True

    if not blocked:
        return draft, f"approved ({result.latency_ns}ns)", False

    if revision is None:
        raise RuntimeError("Non-revisable task was vetoed by governance — refusing to submit")

    revised = dna.validate(revision)  # SAFE_REVISION is constitution-clean
    if not revised.valid:
        raise RuntimeError("Revision still violates the constitution — leaving task incomplete")
    return revision, f"VETOED then revised, approved ({revised.latency_ns}ns)", True


def main() -> int:
    # 0. Precondition: ability-based routing is only sound if each agent owns a
    #    unique domain AND a unique capability name. Reusing a name lets a
    #    foreign-domain agent match a task via the capability-name branch of
    #    SwarmExecutor.available_tasks and silently break the routing proof.
    #    Enforce the convention instead of trusting it.
    names = [cap.name for cap in AGENTS.values()]
    domains = [cap.domain for cap in AGENTS.values()]
    if len(set(names)) != len(names) or len(set(domains)) != len(domains):
        raise ValueError(
            "Routing precondition violated: each agent needs a unique capability "
            f"name and domain (names={names}, domains={domains})"
        )

    # 1. Register agents + their abilities, and give each a constitutional DNA.
    registry = CapabilityRegistry()
    dna: dict[str, AgentDNA] = {}
    for agent_id, capability in AGENTS.items():
        registry.register(agent_id, [capability])
        dna[agent_id] = AgentDNA.default(agent_id=agent_id)

    # 2. Compile the goal into an executable task DAG and load the swarm.
    dag = DAGCompiler().compile(GOAL)
    title_of = {node.node_id: node.title for node in dag.nodes.values()}
    domain_of = {node.node_id: node.domain for node in dag.nodes.values()}
    store = ArtifactStore()
    executor = SwarmExecutor(registry, store)
    executor.load_dag(dag)

    n_tasks = len(dag.nodes)
    agent_ids = list(AGENTS)
    hashes = {agent_id: d.hash for agent_id, d in dna.items()}

    log("=" * 72)
    log(f"Dynamic constitutional swarm — goal: {GOAL.goal!r}")
    log(
        f"  agents={len(agent_ids)}  tasks={n_tasks}  "
        f"constitutional_hash={next(iter(hashes.values()))}"
    )
    log("=" * 72)

    # 3. Orchestrator-free activation loop. Each round every idle agent polls
    #    available_tasks() for itself (stigmergic self-selection). The
    #    round-start snapshot is the LIVE, pre-claim view used to prove routing.
    snapshots: list[dict[str, list[str]]] = []
    claimed_log: list[tuple[int, str, str]] = []  # (round, agent_id, title)
    veto_events = 0
    max_rounds = n_tasks + 5
    rnd = 0

    while not executor.is_complete and rnd < max_rounds:
        rnd += 1
        snapshot = {aid: [n.node_id for n in executor.available_tasks(aid)] for aid in agent_ids}
        snapshots.append(snapshot)

        active = {aid: ids for aid, ids in snapshot.items() if ids}
        if active:
            seen = ", ".join(
                f"{aid}->[{', '.join(title_of[i] for i in ids)}]" for aid, ids in active.items()
            )
            log(f"\n[round {rnd}] who-sees-what (pre-claim): {seen}")

        for agent_id in agent_ids:
            ready_ids = snapshot[agent_id]
            if not ready_ids:
                continue
            node_id = ready_ids[0]  # already priority-sorted descending
            try:
                executor.claim(node_id, agent_id)
            except ValueError:
                continue  # already claimed this round (does not happen with unique caps)

            node = executor.dag.nodes[node_id]
            content_type, draft, revision = plan_output(node)
            content, verdict, vetoed = govern(dna[agent_id], draft, revision)
            veto_events += int(vetoed)

            executor.submit(
                node_id,
                Artifact(
                    artifact_id=f"art-{node_id}",
                    task_id=node_id,
                    agent_id=agent_id,
                    content_type=content_type,
                    content=content,
                    domain=node.domain,
                    constitutional_hash=dna[agent_id].hash,
                ),
            )
            claimed_log.append((rnd, agent_id, node.title))
            cid = store.get(f"art-{node_id}").content_hash
            log(
                f"    {agent_id:14s} [{node.domain:12s}] '{node.title}'  "
                f"governance: {verdict}  cid={cid[:12]}"
            )

    # 4. Verification — the run is only a proof if these invariants hold.
    invariants: dict[str, bool] = {}

    def check(label: str, ok: bool) -> None:
        invariants[label] = bool(ok)
        log(f"  [{'PASS' if ok else 'FAIL'}] {label}")

    log("\n" + "-" * 72)
    log("Invariants")

    check("dag_fully_completed", executor.is_complete)
    check("every_task_produced_an_artifact", store.count == n_tasks)
    check("progress_all_completed", executor.progress == {"completed": n_tasks})

    # Routing discrimination, evaluated at every live pre-claim snapshot: an
    # agent must NEVER have been offered a task outside its own domain.
    leaked = [
        (rnd_i + 1, aid, title_of[i])
        for rnd_i, snap in enumerate(snapshots)
        for aid, ids in snap.items()
        for i in ids
        if domain_of[i] != AGENT_DOMAIN[aid]
    ]
    check("no_foreign_domain_task_offered", not leaked)
    if leaked:
        log(f"        cross-domain leaks: {leaked}")

    # Parallel self-selection actually occurred (two domains READY at once).
    parallel = any(sum(1 for ids in snap.values() if ids) >= 2 for snap in snapshots)
    check("parallel_self_selection_occurred", parallel)

    # Each agent only ever executed work in its own domain.
    domain_ok = all(
        domain_of[_id_of(dag, title)] == AGENT_DOMAIN[aid] for _, aid, title in claimed_log
    )
    check("claimed_task_matched_agent_domain", domain_ok)

    # Governance fired exactly once (the veto task) and was fail-closed.
    check("governance_vetoed_and_revised_once", veto_events == 1)

    # All agents share one constitutional hash (precondition for valid voting).
    check("single_constitutional_hash", len(set(hashes.values())) == 1)

    passed = all(invariants.values())
    log("-" * 72)
    log(
        "ALL INVARIANTS HELD — dynamic capability-routed constitutional swarm verified."
        if passed
        else "INVARIANT FAILURE — see [FAIL] lines above."
    )

    # The machine verdict: a single JSON document on stdout.
    print(
        json.dumps(
            {
                "status": "pass" if passed else "fail",
                "goal": GOAL.goal,
                "agents": len(agent_ids),
                "tasks": n_tasks,
                "rounds": rnd,
                "veto_events": veto_events,
                "constitutional_hash": next(iter(hashes.values())),
                "invariants": invariants,
            }
        )
    )
    return 0 if passed else 1


def _id_of(dag, title: str) -> str:
    for node in dag.nodes.values():
        if node.title == title:
            return node.node_id
    raise KeyError(title)


if __name__ == "__main__":
    sys.exit(main())
