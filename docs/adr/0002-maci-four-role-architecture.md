# ADR: MACI Four-Role Architecture for `packages/acgs-lite/`

## Status

Accepted (landed with `MACI-ROADMAP.md` on master, 2026-05-12)

## Context

`packages/acgs-lite/` implements MACI (Monitor-Approve-Control-Inspect), a
separation-of-powers framework for AI agents. The core concern is that a single
agent must not be permitted to both propose an action and validate or execute it
— self-validation defeats the purpose of policy enforcement.

Before this decision was formalised, the enforcement model was partially
implicit: `MACIEnforcer` in
`packages/acgs-lite/src/acgs_lite/maci/enforcer.py` raised
`MACIViolationError` when role boundaries were crossed, but the self-validation
guard was only explicitly invoked in tests, not in the `GovernedAgent.run()`
path. The four roles were present in code but not documented as a named
architectural decision.

`MACI-ROADMAP.md` (workspace root, landed PR #24) formalises the four-role
model, inventories per-role gaps, and defines a sequenced change order. This
ADR records the architectural decision that document embodies.

## Decision

Adopt the MACI four-role architecture as the mandatory separation-of-powers
model for all governed agent execution in `packages/acgs-lite/`.

The four roles are structurally enforced — no single agent identity may occupy
more than one role in a single governed transaction:

| Role | Responsibility | Structural constraint |
|---|---|---|
| **Proposer** | Generate proposed actions | Cannot execute or validate own output |
| **Validator** | Check actions against constitution | Cannot propose or execute |
| **Executor** | Carry out approved actions | Cannot propose or validate |
| **Observer** | Record cryptographic audit trail | Cannot modify decisions |

Quoting `MACI-ROADMAP.md` §4-Role Inventory:

> PROPOSER → (Agent) → VALIDATOR → (ACGS Engine) → EXECUTOR → (System) → OBSERVER → (Audit Log)

The roles are implemented as the `MACIRole` enum in
`packages/acgs-lite/src/acgs_lite/maci/roles.py` (`proposer`, `validator`,
`executor`, `observer`). `MACIEnforcer` in
`packages/acgs-lite/src/acgs_lite/maci/enforcer.py` raises
`MACIViolationError` (defined in
`packages/acgs-lite/src/acgs_lite/errors.py`) when a role boundary is
crossed.

The self-validation guard (`check_no_self_validation`) must be injected
structurally into `GovernedAgent.run()` so that it is enforced at runtime, not
only exercised in test fixtures. This is the highest-priority item in the
`MACI-ROADMAP.md` change order.

## Alternatives considered

### Single-role model with prompt-level separation

Rejected. Prompt-level separation is advisory, not authoritative. A model can
be instructed to behave as a validator, but nothing prevents it from also
executing or proposing unless the runtime enforces role identity. This mirrors
the broader reject in ADR-0001 of prompt-only compliance as sufficient.

### Two-role model (proposer + validator only)

Rejected. Separating proposal from validation is necessary but not sufficient.
Without a distinct Executor role, the Validator can also trigger execution,
collapsing two critical controls into one identity. Without a distinct Observer
role, audit records can be influenced by the same agents that make governance
decisions, undermining tamper-evidence.

### External orchestration framework (LangGraph, CrewAI) for role enforcement

Rejected as the primary mechanism. External graph frameworks add per-node
overhead and framework coupling. MACI role enforcement is a runtime identity
check, not a graph routing problem. As noted in ADR-0001, ACGS governs
execution boundaries; it does not need to be a workflow engine.

## Consequences

Positive:

- No single agent identity can self-approve or self-execute a proposed action.
- `MACIViolationError` provides a structural, catchable signal for role
  violations rather than relying on prompt compliance.
- Role identities can be versioned and audited alongside policy versions.
- The Observer role produces cryptographic audit trail entries that are
  structurally separated from decision-making identities.

Tradeoffs:

- Four distinct identities (or identity tokens) must be managed per governed
  transaction. This adds credential-management overhead.
- The self-validation guard must be injected at the `GovernedAgent.run()` level
  to be structural — test-only injection is insufficient.
- `DelegationRegistry` wildcard (`*`) scope grants must be replaced with an
  allow-list mode to prevent the Executor role from obtaining unrestricted
  authority. Until that gap is closed (MACI-ROADMAP.md item 4), wildcard grants
  are a known residual risk.

Risks:

- Time-of-check to time-of-use (TOCTOU) gap in the Executor role: a proposal
  approved at validation time may become invalid by execution time. Addressed
  by MACI-ROADMAP.md item 3 (pre-execution re-validation hook).
- In-memory-only audit log: the Observer role records events but does not
  persist them outside the process. Addressed by MACI-ROADMAP.md item 5.
- Hardcoded risk-tier signals in `classify_action_risk()` make
  constitution-aligned risk classification impossible without code changes.
  Addressed by MACI-ROADMAP.md item 2.

## References

- `MACI-ROADMAP.md` (workspace root) — canonical gap inventory and change
  order for `packages/acgs-lite/` MACI surface
- `packages/acgs-lite/docs/maci.md` — implementation specification
- `packages/acgs-lite/src/acgs_lite/maci/enforcer.py` — `MACIEnforcer`
- `packages/acgs-lite/src/acgs_lite/maci/roles.py` — `MACIRole` enum
- `packages/acgs-lite/src/acgs_lite/errors.py` — `MACIViolationError`
- `packages/acgs-lite/tests/test_maci.py` — role-boundary test coverage
- `packages/acgs-lite/examples/hackathon_starter_maci.py` — usage example
- ADR-0001 — In-Context Procedure Execution with External Runtime Governance
  (establishes that prompt-only compliance is insufficient)
