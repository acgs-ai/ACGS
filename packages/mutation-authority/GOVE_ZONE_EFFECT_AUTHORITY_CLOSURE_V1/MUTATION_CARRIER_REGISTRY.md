# MUTATION_CARRIER_REGISTRY

Machine-checkable source: `mutation_authority/effect_authority.py` (`CARRIERS`).
This doc is the human view; the module is the authority the dominance gate reads.
Rebuilt from the gove-zone code trace, not from the V1 report.

A **carrier** is any mechanism that can change canonical governed repository
state. Governance-infrastructure writes (audit/ledger persistence) are excluded
— they are the governance layer persisting itself, not agent-driven source
mutation.

## Fields

`process_boundary` ∈ {in_process, subprocess, remote, external} ·
`required_enforcement_layer` = weakest layer that could actually *prevent* this
carrier, given its boundary (in_process < subprocess < ci < os) ·
`bypasses_execute_with_receipt` · `decidable_before_execution` · `sanctioned` =
participates in an effect authority boundary today.

## Registry

| id | entry point | boundary | authz can precede effect? | required layer | bypasses receipt gate? | decidable? | sanctioned? |
|---|---|---|---|---|---|---|---|
| execute_with_receipt | executor.py:236 | in_process | yes | in_process | no | yes | **yes** |
| governed_executor_execute | executor.py:338 | in_process | yes | in_process | no | yes | **yes** |
| universal_gateway_invoke | gateway.py:570 | in_process | yes | in_process | no | yes | **yes** |
| local_process_sandbox | sandbox.py:235 | subprocess | yes | **os** | yes | no | no |
| e2b_sandbox | sandbox.py:284 | remote | yes | **os** | yes | no | no |
| mcp_downstream_spawn | adapters/mcp_gateway.py | subprocess | yes | **os** | yes | no | no |
| shell_operator_effects | Bash → shell | subprocess | no | **os** | yes | **no** | no |
| lifecycle_scripts | pkg-manager lifecycle | subprocess | no | **os** | yes | no | no |
| interactive_terminal_adv9 | any external process | external | no | **os** | yes | no | no |
| direct_filesystem_api | any in-process code | in_process | yes | **os** | yes | yes | no |
| git_mutation | Bash → git | subprocess | no | **os** | yes | no | no |

## Machine-checked facts (from `effect_authority.py`)

```
validate_registry()            → []            (structurally valid)
minimal_dominating_layer()     → 'os'
carriers_not_dominated_by('in_process') → 8 of 11:
  local_process_sandbox, e2b_sandbox, mcp_downstream_spawn, shell_operator_effects,
  lifecycle_scripts, interactive_terminal_adv9, direct_filesystem_api, git_mutation
```

## Reading

- Only 3 carriers (the receipt-gated in-process path) are sanctioned, and they
  share one choke point (`execute_with_receipt`). Their
  `required_enforcement_layer` is `in_process` because they never leave the
  process — an in-process gate CAN prevent them.
- The other 8 carriers cross a process boundary (or are a raw in-process write
  that never calls the gate). Their `required_enforcement_layer` is `os`: once a
  child process or shell holds the governed path, only OS-level write-denial can
  stop it. `direct_filesystem_api` is in-process yet still needs `os`, because
  nothing forces arbitrary in-process code through the gate.
- `minimal_dominating_layer() == 'os'`: the weakest layer that can mediate
  **every** carrier is the strongest any single carrier requires. Since it is
  `os`, no in-process choke point can make the invariant true. This is the
  registry-level statement of the ceiling; `ceiling_demonstration.py` proves it
  empirically with real processes.
