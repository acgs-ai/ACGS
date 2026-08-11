# ADR-0010: Execution Governance Layer — governed mediation for execution-environment side effects

## Status

Accepted — ratified 2026-08-09 by the P11 implementation directive. D1-D6 hold
as written; D2's action table is implemented in
`packages/gove-zone/src/gove_zone/execution.py`, and the hook cutover is live.

Implementation is **partial by phase**: Phase 0 complete, Phases 1-2 partial,
Phases 3-6 not started. Per `SECURITY_MODEL.md:52-55`, only the controls with
cited tests are `[on-master]`; the rest stay `[proposed]`. The per-criterion
status, including the criteria explicitly **not met**, is
`docs/governance/acgs-vnext-execution-governance-layer.md` §5.

Gate at ratification: `1423 passed, 4 skipped, 1 xfailed`; ruff clean; mypy clean
on the new module.

## Date

2026-08-09 (proposed and ratified)

## Relates to

- ADR-0009 (gove-zone as kernel of record) — this ADR adds no kernel; it wires
  execution-environment side effects into the existing kernel of record.
- ADR-0001 (in-context procedure execution, external runtime governance) —
  **this ADR delivers scope ADR-0001 already declared.** ADR-0001 decided that
  ACGS "should instead govern execution boundaries: tool calls, API calls, file
  writes, **shell commands**, permissions, policy checks, separation-of-duties,
  audit trails, and verifiable evidence," and that "prompt-level governance is
  advisory. Runtime governance is authoritative." Shell commands have been in
  ACGS's declared scope since ADR-0001; they have never been mediated. This ADR
  is therefore not a scope expansion — it is closing a gap between declared and
  implemented scope.
- ADR-0002 (MACI four-role architecture) — **scoped to `packages/acgs-lite/`**,
  where `MACIRole` is a four-role enum. It is *not* the model used here: the
  gove-zone kernel implements a proposer/validator split via `Validator`
  (`receipt.py:99-116`) and enforces `validator_id != expected_actor` at
  `receipt.py:850-869`. This ADR uses the gove-zone mechanism. Do not treat the
  two role models as interchangeable.
- `docs/audits/2026-08-09-npm-artifact-incident.md` — the incident that
  motivated this decision.
- `docs/governance/developer-tool-mutation-governance.md` — the analysis and
  control model. **This ADR supersedes that document's §6 C8**, which proposed a
  new `acgs.mutation.receipt/v1` schema. See D3.
- `docs/SECURITY_MODEL.md` ADV6, ADV9 — the existing adversary rows this
  decision closes against. No new `ADV*` number is minted. See D4.
- `docs/ROADMAP.md:61` (Skill trust, ⬜ PLANNED) — adjacent, not superseded.

## Context

On 2026-08-08 two side effects reached this repository without a Decision
Receipt: an unreviewed 103-package dependency install executed from an
interactive shell, and a developer tool silently rewriting a tracked
configuration file. Both were reconstructed forensically 14 hours later.

Neither is a novel adversary. `docs/SECURITY_MODEL.md:73` already names ADV9,
**out-of-gate executor bypass** — *"Invoke the raw tool / side-effect path and
never reach the governed executor"* — and states its residual verbatim: *"the
kernel cannot stop code paths it is not wired into."* The incident is that
residual, realized. ADV6 (supply-chain attacker) covers the dependency half and
carries its own caveat that the constitutional-hash inventory is currently empty.

The relevant finding is not that governance was absent. It was running. The
audit chain at `.gove-zone/audit.jsonl` was appending throughout the incident
window and is still appending — 381 records at last reading, with three
invariants that hold at every reading:

- `tool`: `runtime.Edit` 251, `runtime.Write` 130, **`runtime.Bash` 0**
- `actor`: `govern-zone-hook` — 100%
- `decision`: `allow` — 100%

The hook *is* wired to `Bash` (`.claude/settings.json:112`) and executes on every
Bash tool call, but `_classify` (`.claude/hooks/acgs-emit-receipt.py:58-69`)
returns `None` for anything outside `Edit`/`Write`/`MultiEdit`/`NotebookEdit`
and three literal substrings, so the call exits unaudited. `_ObserverPolicy`
(`integration.py:583-600`) returns `Decision.ALLOW` unconditionally. Attribution
is a hardcoded fallback (`acgs-emit-receipt.py:111`), and `run_id` is accepted
in both `integration.py` signatures then never passed to the `Receipt`
constructed at `:700-707`.

Critically, the receipt emitted on this path is `Receipt` (`receipt.py:69-96`) —
five fields, **no signature field exists** — not `DecisionReceipt`
(`receipt.py:119-185`, 32 fields). `Receipt` is an audit anchor, not an
authorization token, and `execute_with_receipt` does not accept it
(`executor.py:35`).

Meanwhile `UniversalGateway` (`gateway.py:263`) already implements the complete
Policy → Receipt → Executor loop that ADV9 calls for, with `SealedTool`
(`gateway.py:157-198`) capturing the raw callable in a closure and requiring an
unspent, identity-bound grant from a `contextvars` slot. Any other call path is
audited as a synthesized DENY (`BYPASS_ATTEMPT`) and raises
`BypassAttemptError`. Its consumption ledger is always on for the strong
`UniversalGateway.invoke` path. It is implemented and
tested (`test_universal_gateway.py`, 640 lines).

The gap is therefore **wiring, not capability** — with one genuine exception:
nothing in ACGS can observe a command typed into an interactive terminal, and no
hook matcher can change that.

## Decision

### D1 — The governed decision surface is `UniversalGateway`, not passive emission

Execution-environment side effects are mediated by `UniversalGateway`. The
passive `integration.emit_receipt_for_hook` path is retired from the enforcement
role and retained only as a compatibility auditor during migration (see D6).

For the Claude Code hook specifically, `handle_claude_hook`
(`gateway.py:1022-1109`) replaces `emit_receipt_for_hook`. It evaluates each
proposed call individually, is deny-wins across a batch (`:1068-1070`), maps
`TRANSFORM` to `"ask"` because a hook cannot rewrite runtime arguments
(`:1071-1082`), and mints a real `DecisionReceipt` per allowed call.
The optional `call_factory` may classify and describe calls, but it cannot
choose or replace the gateway-supplied actor; any mismatch denies the entire
batch before evaluation, audit, or receipt minting.

**Boundary statement, to be reproduced wherever this path is described.** On the
hook path `execute_with_receipt` is *not* called — the host runtime performs the
side effect, as `gateway.py:1029-1030` states. The correct wording is *"a minted,
verifiable Decision Receipt for the hook decision."* It is **not**
receipt-gated execution. Only `UniversalGateway.invoke` (`:458-616`) closes the
full loop.

### D2 — Execution-environment mutations are governed tools under a dedicated `execution_boundary`

Surfaces integrated through `register_tool` and `invoke` inherit sealed-tool
bypass detection, the always-on consumption ledger, and actor binding from the
gateway rather than the request body. The hook path performs policy, audit, and
receipt minting only; it does not consume the receipt or use the invocation
ledger because the host runtime executes the side effect.

`execution_boundary` is an existing canonical `DecisionReceipt` field
(`DECISION_RECEIPT_SPEC.md:30`, "boundary where execution is allowed"). This
decision uses it as intended and introduces no new field. Boundary value:
`execution-environment`.

`proposed_action` names follow the existing `runtime.*` convention already in
the audit chain:

| Surface | `proposed_action` |
|---|---|
| Shell command | `env.shell.exec` |
| Package manager invocation | `env.package.invoke` |
| Dependency installation | `env.package.install` |
| Lifecycle-script enablement | `env.package.lifecycle_enable` |
| Git mutation | `env.git.mutate` |
| Artifact generation | `env.artifact.generate` |
| Release publication | `env.release.publish` |

**`env.package.lifecycle_enable` is not a mediated execution point, and must not
be described as one.** Lifecycle scripts run *inside* the package manager's own
process, after fetch, with no callback to any external gate. There is no
decision point between "the manager decided to run this script" and "the script
ran." The only achievable control is the decision taken *before* invoking the
manager: install with scripts disabled (`--ignore-scripts` or the manager's
equivalent), and treat re-enabling them for named packages as a separate,
escalated decision. The action name records that enablement decision — it does
not gate execution.

### D3 — No new receipt schema

`DecisionReceipt` is the only receipt type for governed execution-environment
decisions. Its 32 fields already carry everything required — `actor`,
`proposed_action`, `argument_hash`, `policy_hash`, `decision`, `matched_rules`,
`validator_id`, `authority`, `expires_at`, `previous_audit_hash`,
`audit_event_hash`, `receipt_hash`, and the signature triple — all bound into
`receipt_hash` via `_hash_payload()` (`receipt.py:332-374`), with
`signature_algorithm` and `signing_key_id` inside the hash so downgrade breaks
verification.

**This explicitly supersedes** the `acgs.mutation.receipt/v1` schema proposed in
`docs/governance/developer-tool-mutation-governance.md` §6 C8. A parallel schema
would have been a duplicate concept and is rejected on that basis.

### D4 — No new `ADV*` number; ADV6 and ADV9 are extended in scope

The incident is ADV9 realized and ADV6 exercised. Minting `ADV15` would
duplicate an existing adversary. Instead:

- **ADV9** scope is extended from "raw tool path inside an integrated runtime"
  to include unmediated *execution-environment* paths: interactive shells,
  package managers, and developer tools writing tracked files.
- **ADV6** gains dependency-admission and lifecycle-script execution as named
  attack steps, alongside its existing constitutional-hash caveat.

Per `SECURITY_MODEL.md:52-55`, every control this ADR proposes is tagged
`[proposed]` until it has cited tests in the checkout.

### D5 — Fail-closed is preserved, and unmediated paths are proven absent rather than assumed

The existing invariant is unchanged: **no valid Decision Receipt, no side
effect.** Two additions specific to this layer:

1. **Non-canonical package managers are denied before fetch.** If the repository
   declares `packageManager` and a different manager is invoked, the decision is
   `DENY` at the gate, before any network access or lifecycle execution.
2. **Bypass is measured, not assumed.** `bypass_attempts()` (`gateway.py:730`)
   already returns the audited record of sealed-tool calls made outside a grant.
   Completeness of mediation is an *observable*, and an empty result is evidence
   only when the gate is known to be on the path.

Lifecycle-script execution is treated as irreversible. Removing `node_modules`
reverts artifacts, not execution. Because the execution point itself is
unmediable (D2), the fail-closed position is **scripts disabled by default at
install**, with enablement as a separate escalated decision recorded before the
manager is invoked. There is no retroactive compensation.

### D6 — Migration is additive and observe-first, with a dated enforcement cutover

`GateMode` already provides `OBSERVE` and `ENFORCE` (`integration.py:69-71`).
Each surface migrates in that order, and `OBSERVE` on a surface is time-boxed
with a named owner. An indefinitely-observing gate is the failure mode this ADR
exists to correct, and must not be reintroduced as a permanent state.

### D7 — Structural classification, added at implementation

Not in the original decision set, and the one genuinely new mechanism this ADR
required. Execution surfaces are resolved by **argv prefix** — the invoked binary
and a subcommand drawn from a declared grammar — never by substring match over
command text.

The retired mechanism matched substrings and failed in both directions. It missed
`npm install` entirely (396 audit records, one `runtime.Bash`), and it produced
false positives: the single `runtime.Bash` record in the chain,
`ev_de6629e1f60f41ea`, is a read-only `grep` audited as an `autopilot`
orchestration event because its *search pattern* contained the word.

Three constraints fall out and are enforced in code:

1. **A quoted argument can never promote a command into a governed surface.**
   Tokenization is `shlex` with `punctuation_chars=True`, so an operator is
   recognized only when unquoted.
2. **A subcommand is read only for binaries with a declared grammar, and only
   when the token looks like a subcommand.** Without the second guard the
   "argv prefix" captures the *value* of a value-taking option — a
   `curl -H 'Authorization: Bearer <token>'` puts the bearer token into the
   receipt's `argument_hash`, turning the receipt into an exfiltration channel.
   This was a real defect, caught by
   `test_raw_command_text_is_not_carried_into_the_receipt`.
3. **Bare command wrappers are recognized, but option-bearing wrapper syntax is
   not partially interpreted.** A wrapper option value could otherwise be
   mistaken for the executable. Such commands are bounded as undecidable
   `env.shell.exec` events and denied by
   `deny-unsupported-wrapper-options`; wrapper option values are not copied
   into receipt arguments.

Consequently a command whose effect is not recoverable from its argv prefix — a
redirect, a pipeline, a substitution — is recorded and attributed but **not
assigned a risk tier**. The `unclassified` tier exists to say that in policy data
rather than by silently allowing.

## Consequences

**Accepted:**

- Latency on every mediated shell command and dependency install. The pilot
  threshold of interactive added p95 ≤100ms applies.
- The interactive-terminal path cannot be closed by hooks. It requires a `PATH`
  shim, which a developer can bypass with an absolute path or a container. This
  is stated as a limitation, not engineered around; the shim's value is that
  bypass becomes *deliberate and detectable* rather than routine and invisible.
- Denying non-canonical package managers will occasionally block a legitimate
  ad-hoc action. That is the intended trade; the escape hatch is an explicit,
  receipted `ESCALATE`, not a silent allow.
- More `DENY` and `ESCALATE` decisions raise the availability surface named by
  ADV13 — fail-closed inverts integrity attacks into availability attacks.

**Gained:**

- `runtime.Bash` and `env.*` records enter the audit chain, closing the
  attribution gap that made 14-hour forensic reconstruction necessary.
- Receipts on this path become signable, because `DecisionReceipt` has the
  fields `Receipt` structurally lacks.
- ADV9's residual narrows from "the kernel cannot stop code paths it is not
  wired into" to a named, enumerable set of unmediated paths.

**Not claimed:** no production deployment, no multi-tenant operation, no
external anchoring, no compliance posture. Per `CLAIMS.md:46-48`, no claim
arising from this ADR may appear in public material without a CLAIMS.md row and
a Safe public wording cell.

## Alternatives rejected

### Extend `_classify` in the existing hook to recognize package managers

The cheapest change, and it fails on the substance. It would leave
`_ObserverPolicy` returning `ALLOW` unconditionally, leave the emitted artifact
as the unsignable 5-field `Receipt`, and leave attribution at the hardcoded
fallback. It also cannot see an interactive terminal, so it would close none of
the incident. It would produce records that *look* like governance while
enforcing nothing — the precise condition this ADR corrects.

### Mint a new receipt type for environment mutations

Rejected under the no-duplicate-concepts constraint. `DecisionReceipt` already
carries every needed field, and a second schema would fragment verification,
proof packs, and offline replay.

### Add `ADV15 "unmediated local executor"`

Rejected. ADV9 already names this adversary and already names this residual.
A new row would split one threat across two identifiers and weaken both.

### Git hooks alone, without gateway integration

A `core.hooksPath` guard is genuinely valuable and is part of the plan — but git
hooks fire at commit time. The incident's damage occurred at *install* time, and
nothing was ever committed. Commit-time controls are a backstop, not the gate.

### Wait for the skill-trust pipeline (`ROADMAP.md:61`) to land first

Rejected as sequencing. Skill trust governs agent-invoked capability; this
governs actor-agnostic execution. The incident's dominant actor was a package
manager, which the skill pipeline does not model.

## References

- `docs/audits/2026-08-09-npm-artifact-incident.md`
- `docs/governance/acgs-vnext-execution-governance-layer.md` — architecture,
  threat-model deltas, migration plan, acceptance criteria
- `docs/governance/developer-tool-mutation-governance.md` — prior analysis
  (§6 C8 superseded by D3)
- `docs/SECURITY_MODEL.md` ADV6, ADV9, ADV13; status tags at `:52-55`
- `packages/gove-zone/src/gove_zone/gateway.py` — `UniversalGateway`,
  `SealedTool`, `handle_claude_hook`, `bypass_attempts`
- `packages/gove-zone/src/gove_zone/receipt.py` — `Receipt` vs `DecisionReceipt`
- `packages/gove-zone/src/gove_zone/executor.py` — `execute_with_receipt`
- `docs/CLAIMS.md:46-48` — public wording rule
