"""Machine-checkable mutation-carrier registry + dominance computation.

A *carrier* is any mechanism capable of changing canonical governed repository
state. This registry is derived from the gove-zone code trace
(GOVE_ZONE_EFFECT_AUTHORITY_CLOSURE_V1/MUTATION_CARRIER_REGISTRY.md) and is the
authority the dominance gate and the architecture analysis both read.

The central computation is :func:`minimal_dominating_layer`: the weakest
enforcement layer that could mediate EVERY carrier is the *strongest* layer any
single carrier requires. If even one carrier can only be mediated at the OS
layer, then no in-process choke point can make the invariant true — which is
the whole finding of this round.
"""

from __future__ import annotations

from dataclasses import dataclass

# Enforcement layers, ordered weakest → strongest by what they can dominate.
# An in-process choke cannot mediate a subprocess it spawns and then loses
# control of; only an OS-level boundary can deny a same-machine process write.
LAYERS = ("observational", "in_process", "subprocess", "ci", "os")
_LAYER_RANK = {name: i for i, name in enumerate(LAYERS)}


@dataclass(frozen=True)
class Carrier:
    id: str
    entry_point: str
    performer: str
    process_boundary: str  # in_process | subprocess | remote | external
    actor_identity: str  # known | inferred | unknown
    target_known: bool  # is (resource) knowable pre-effect
    pre_state_hash_available: bool
    post_state_committed: bool  # is authorized post-state knowable pre-effect
    authz_can_precede_effect: bool
    # The weakest layer at which this carrier could actually be MEDIATED
    # (prevented), given its process boundary.
    required_enforcement_layer: str
    bypasses_execute_with_receipt: bool
    decidable_before_execution: bool
    sanctioned: bool  # participates in an effect-authority boundary today
    notes: str = ""


# Derived from the code trace. Governance-infrastructure writes (audit/ledger)
# are excluded: they are the governance layer persisting itself, not
# agent-driven canonical source mutation.
CARRIERS: tuple[Carrier, ...] = (
    Carrier(
        id="execute_with_receipt",
        entry_point="executor.py:32",
        performer="tool_fn(**args) @ executor.py:236",
        process_boundary="in_process",
        actor_identity="known",
        target_known=False,  # tool_fn is opaque; resource not surfaced here
        pre_state_hash_available=False,
        post_state_committed=False,
        authz_can_precede_effect=True,
        required_enforcement_layer="in_process",
        bypasses_execute_with_receipt=False,
        decidable_before_execution=True,
        sanctioned=True,
        notes="gove-zone DecisionReceipt gate; dominates ONLY in-process tool_fn effects",
    ),
    Carrier(
        id="governed_executor_execute",
        entry_point="executor.py:338",
        performer="delegates to execute_with_receipt",
        process_boundary="in_process",
        actor_identity="known",
        target_known=False,
        pre_state_hash_available=False,
        post_state_committed=False,
        authz_can_precede_effect=True,
        required_enforcement_layer="in_process",
        bypasses_execute_with_receipt=False,
        decidable_before_execution=True,
        sanctioned=True,
        notes="thin delegate; not a second boundary",
    ),
    Carrier(
        id="universal_gateway_invoke",
        entry_point="gateway.py:458",
        performer="execute_with_receipt @ gateway.py:570",
        process_boundary="in_process",
        actor_identity="known",
        target_known=False,
        pre_state_hash_available=False,
        post_state_committed=False,
        authz_can_precede_effect=True,
        required_enforcement_layer="in_process",
        bypasses_execute_with_receipt=False,
        decidable_before_execution=True,
        sanctioned=True,
        notes="reuses the same choke point",
    ),
    Carrier(
        id="local_process_sandbox",
        entry_point="sandbox.py:235",
        performer="subprocess.run (bwrap best-effort)",
        process_boundary="subprocess",
        actor_identity="known",
        target_known=False,
        pre_state_hash_available=False,
        post_state_committed=False,
        authz_can_precede_effect=True,
        required_enforcement_layer="os",
        bypasses_execute_with_receipt=True,
        decidable_before_execution=False,
        sanctioned=False,
        notes="cleared-env child can mutate FS when bwrap absent; self-declared non-isolating",
    ),
    Carrier(
        id="e2b_sandbox",
        entry_point="sandbox.py:284",
        performer="remote microVM exec",
        process_boundary="remote",
        actor_identity="known",
        target_known=False,
        pre_state_hash_available=False,
        post_state_committed=False,
        authz_can_precede_effect=True,
        required_enforcement_layer="os",
        bypasses_execute_with_receipt=True,
        decidable_before_execution=False,
        sanctioned=False,
        notes="remote effect carrier",
    ),
    Carrier(
        id="mcp_downstream_spawn",
        entry_point="adapters/mcp_gateway.py (stdio_client)",
        performer="subprocess spawn of MCP server",
        process_boundary="subprocess",
        actor_identity="inferred",
        target_known=False,
        pre_state_hash_available=False,
        post_state_committed=False,
        authz_can_precede_effect=True,
        required_enforcement_layer="os",
        bypasses_execute_with_receipt=True,
        decidable_before_execution=False,
        sanctioned=False,
        notes="spawn itself is a separate carrier; its tool calls route back to :540",
    ),
    Carrier(
        id="shell_operator_effects",
        entry_point="Bash tool → shell",
        performer=">, |, cp, mv, $(...) in a shell child",
        process_boundary="subprocess",
        actor_identity="known",
        target_known=False,
        pre_state_hash_available=False,
        post_state_committed=False,
        authz_can_precede_effect=False,
        required_enforcement_layer="os",
        bypasses_execute_with_receipt=True,
        decidable_before_execution=False,
        sanctioned=False,
        notes="execution.py marks these decidable=False; mutate tracked source without a governed binary",
    ),
    Carrier(
        id="lifecycle_scripts",
        entry_point="package manager lifecycle",
        performer="script inside manager process",
        process_boundary="subprocess",
        actor_identity="inferred",
        target_known=False,
        pre_state_hash_available=False,
        post_state_committed=False,
        authz_can_precede_effect=False,
        required_enforcement_layer="os",
        bypasses_execute_with_receipt=True,
        decidable_before_execution=False,
        sanctioned=False,
        notes="run with no callback; ACTION_PACKAGE_LIFECYCLE_ENABLE records enablement only",
    ),
    Carrier(
        id="interactive_terminal_adv9",
        entry_point="interactive shell / any external process",
        performer="arbitrary process",
        process_boundary="external",
        actor_identity="unknown",
        target_known=False,
        pre_state_hash_available=False,
        post_state_committed=False,
        authz_can_precede_effect=False,
        required_enforcement_layer="os",
        bypasses_execute_with_receipt=True,
        decidable_before_execution=False,
        sanctioned=False,
        notes="the named ADV9 residual: not observed at all",
    ),
    Carrier(
        id="direct_filesystem_api",
        entry_point="any in-process code path",
        performer="Path.write_text / open('w') / os.replace",
        process_boundary="in_process",
        actor_identity="known",
        target_known=True,
        pre_state_hash_available=True,
        post_state_committed=False,
        authz_can_precede_effect=True,
        required_enforcement_layer="os",
        bypasses_execute_with_receipt=True,
        decidable_before_execution=True,
        sanctioned=False,
        notes="not routed through the gate; only OS write-denial dominates an in-process raw write",
    ),
    Carrier(
        id="git_mutation",
        entry_point="Bash tool → git",
        performer="git commit/checkout/reset/clean",
        process_boundary="subprocess",
        actor_identity="known",
        target_known=False,
        pre_state_hash_available=False,
        post_state_committed=False,
        authz_can_precede_effect=False,
        required_enforcement_layer="os",
        bypasses_execute_with_receipt=True,
        decidable_before_execution=False,
        sanctioned=False,
        notes="mutates the index/worktree/HEAD via subprocess",
    ),
)


def validate_registry(carriers: tuple[Carrier, ...] = CARRIERS) -> list[str]:
    """Structural checks; returns a list of problems (empty = valid)."""
    problems: list[str] = []
    seen: set[str] = set()
    for c in carriers:
        if c.id in seen:
            problems.append(f"duplicate carrier id: {c.id}")
        seen.add(c.id)
        if c.required_enforcement_layer not in _LAYER_RANK:
            problems.append(f"{c.id}: unknown enforcement layer {c.required_enforcement_layer!r}")
        if c.process_boundary not in ("in_process", "subprocess", "remote", "external"):
            problems.append(f"{c.id}: unknown process boundary {c.process_boundary!r}")
    return problems


def minimal_dominating_layer(carriers: tuple[Carrier, ...] = CARRIERS) -> str:
    """The weakest enforcement layer that can mediate EVERY carrier = the
    strongest layer any single carrier requires."""
    return max(
        carriers, key=lambda c: _LAYER_RANK[c.required_enforcement_layer]
    ).required_enforcement_layer


def carriers_not_dominated_by(
    layer: str, carriers: tuple[Carrier, ...] = CARRIERS
) -> list[Carrier]:
    """Carriers whose required layer is stronger than `layer` — i.e. carriers a
    boundary at `layer` cannot prevent."""
    ceiling = _LAYER_RANK[layer]
    return [c for c in carriers if _LAYER_RANK[c.required_enforcement_layer] > ceiling]


def sanctioned_ids(carriers: tuple[Carrier, ...] = CARRIERS) -> set[str]:
    return {c.id for c in carriers if c.sanctioned}


def mutation_capable_ids(carriers: tuple[Carrier, ...] = CARRIERS) -> set[str]:
    return {c.id for c in carriers}
