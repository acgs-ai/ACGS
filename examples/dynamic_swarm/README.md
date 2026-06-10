# Dynamic capability-routed constitutional swarm

A self-verifying activation of the `constitutional_swarm` package
(`packages/Acgs-Swarm/`). It activates five agents and lets each one find the
tasks that match its own abilities and execute them — with no central
orchestrator assigning work. Every output is validated through the agent's
embedded constitutional `AgentDNA` before it is submitted.

Run:

```bash
uv run --package constitutional-swarm python examples/dynamic_swarm/demo.py
```

The human-readable round-by-round trace is printed to stderr; stdout carries a
single JSON verdict.

Expected output: JSON on stdout with:

- `status: pass`
- `agents: 5`, `tasks: 6`
- `veto_events: 1` (the one unsafe task was vetoed and revised)
- `constitutional_hash: 608508a9bd224290`
- `invariants`: every entry `true`, including `no_foreign_domain_task_offered`,
  `parallel_self_selection_occurred`, and `governance_vetoed_and_revised_once`

Failure case: routing is enforced only because every task node carries
`required_capabilities` and each agent owns a unique capability name and domain.
If an agent were given a capability that overlaps another domain, the live
pre-claim snapshot would offer it a foreign-domain task, the
`no_foreign_domain_task_offered` invariant would fail, and the demo would emit
`status: fail` and exit non-zero. A vetoed-but-unrevisable governance output
likewise leaves its leaf task incomplete and fails the completion invariant
rather than silently submitting unsafe content.

What is proven: agents self-select work strictly by capability
(`SwarmExecutor.available_tasks`), two domains can proceed in parallel without
cross-domain leakage, completion of a node stigmergically unlocks its
dependents, and the embedded constitution is fail-closed at submit time.

This example is local-only. The artifact store is in-memory, "execution" is a
deterministic stand-in (no LLM or network calls), and governance is the local
keyword/rule engine — not Z3 formal verification or a production receipt gate.
It proves the orchestration and routing contract, not certified governance
assurance.
