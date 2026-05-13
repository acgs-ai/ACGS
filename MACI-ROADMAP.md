# MACI Roadmap — `packages/acgs-lite/`

> **Scope:** This roadmap is anchored exclusively to the MACI surface in
> `packages/acgs-lite/`. No other package is in scope for Phase B/3.
>
> **Evidence base:** `packages/acgs-lite/docs/maci.md`,
> `packages/acgs-lite/tests/test_maci.py`,
> `packages/acgs-lite/examples/hackathon_starter_maci.py`

---

## 4-Role Inventory

MACI (Monitor-Approve-Control-Inspect) enforces separation of powers for AI
agents. The four roles are structurally enforced — no agent can validate its
own output.

Quoting `packages/acgs-lite/docs/maci.md`:

> PROPOSER          VALIDATOR          EXECUTOR          OBSERVER
> (Agent)     -->   (ACGS Engine) -->  (System)    -->   (Audit Log)

| Role | Responsibility | Cannot |
|---|---|---|
| **Proposer** | Generate proposed actions | Execute or validate own output |
| **Validator** | Check actions against constitution | Propose or execute |
| **Executor** | Carry out approved actions | Propose or validate |
| **Observer** | Record cryptographic audit trail | Modify decisions |

Implemented in `packages/acgs-lite/src/acgs_lite/maci/roles.py` as the
`MACIRole` string enum with values `proposer`, `validator`, `executor`,
`observer`. Enforcement is handled by `MACIEnforcer` in
`packages/acgs-lite/src/acgs_lite/maci/enforcer.py`, which raises
`MACIViolationError` (defined in
`packages/acgs-lite/src/acgs_lite/errors.py`) when a role boundary is crossed.

---

## Gaps per Role

### Proposer

- No domain-scoping on initial proposal: `MACIEnforcer.assign_role()` in
  `packages/acgs-lite/src/acgs_lite/maci/enforcer.py` does not accept a
  domain argument. Domain-scoping requires a separate `DomainRoleRegistry`
  call, which creates an inconsistency between the two registry surfaces.
- `classify_action_risk()` keyword signals are hardcoded strings — no YAML-
  driven configuration path exists, making constitution-aligned risk tiers
  impossible without code changes.

### Validator

- Self-validation guard (`check_no_self_validation`) is only explicitly called
  in tests; the `GovernedAgent.run()` path in
  `packages/acgs-lite/src/acgs_lite/governed.py` does not inject this check
  automatically.
- `EscalationTier` thresholds in `recommend_escalation` (
  `packages/acgs-lite/src/acgs_lite/maci/roles.py`) are hardcoded numeric
  boundaries with no per-constitution override hook.

### Executor

- No pre-execution re-validation hook: once a proposal is approved, the
  Executor has no structural mechanism to re-check the constitution before
  acting (time-of-check to time-of-use gap).
- `DelegationRegistry` in
  `packages/acgs-lite/src/acgs_lite/maci/registry.py` allows scope wildcards
  (`*`) that grant unrestricted execution authority; no allow-list mode exists.

### Observer

- Audit log entries in `packages/acgs-lite/src/acgs_lite/audit.py` are
  in-memory only with no persistence path exported from the public API.
- No cross-agent Observer aggregation: each `GovernedAgent` owns its own
  `audit_log`; there is no registry-level view without manual concatenation
  (as shown in
  `packages/acgs-lite/examples/hackathon_starter_maci.py` line 127).

---

## Change Order

The following items are ordered by risk and dependency. Each references the
concrete file(s) to be changed.

1. **Add self-validation guard to `GovernedAgent.run()`**
   File: `packages/acgs-lite/src/acgs_lite/governed.py`
   Inject `MACIEnforcer.check_no_self_validation(proposer_id, validator_id)`
   before the validation step so the guard is structural rather than
   test-only. Required test addition:
   `packages/acgs-lite/tests/test_maci.py` — dispatcher-level test that
   calls `GovernedAgent.run()` with proposer == validator and asserts
   `MACIViolationError` is raised.

2. **Replace hardcoded risk-tier signals with YAML-driven configuration**
   Files: `packages/acgs-lite/src/acgs_lite/maci/roles.py`,
   `packages/acgs-lite/src/acgs_lite/maci/enforcer.py`
   Expose a `risk_signals` parameter on `MACIEnforcer.__init__()` that
   accepts a dict mapping action-signal strings to `ActionRiskTier` values,
   defaulting to the current hardcoded table. This allows constitution YAML
   to override risk classification without code changes.

3. **Add pre-execution re-validation hook to `MACIEnforcer`**
   File: `packages/acgs-lite/src/acgs_lite/maci/enforcer.py`
   Add `MACIEnforcer.pre_execute_check(agent_id, proposal_id)` that re-runs
   the constitution check immediately before execution. Wire it as an
   optional hook in `packages/acgs-lite/src/acgs_lite/governed.py` so
   Executor-role agents call it automatically when `enforce_maci=True`.

4. **Add deny-list mode to `DelegationRegistry`**
   File: `packages/acgs-lite/src/acgs_lite/maci/registry.py`
   Introduce a `strict_scopes` flag on `DelegationRegistry` that disallows
   wildcard (`*`) scope grants and requires explicit scope enumeration. Add
   a corresponding test in `packages/acgs-lite/tests/test_maci.py`.

5. **Export a cross-agent audit aggregator from the public API**
   Files: `packages/acgs-lite/src/acgs_lite/audit.py`,
   `packages/acgs-lite/src/acgs_lite/__init__.py`
   Add `AuditRegistry.merge(*logs)` class method that merges multiple
   `AuditLog` instances into a single chronologically-sorted view. Export
   `AuditRegistry` from the top-level `__init__.py` so callers do not need
   to manually concatenate entries as the hackathon example currently does
   (`packages/acgs-lite/examples/hackathon_starter_maci.py` line 127).
