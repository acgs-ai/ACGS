# Security model and threat table

Core invariant:

> **No valid Decision Receipt, no side effect.**

Status: candidate-stage local proof (`1.0.0rc1` / Beta source metadata). This
document is a threat model, not release, deployment, or certification evidence.

## Threat table

| Threat | Risk | Current protection | Test coverage / demo | Remaining limitation | Roadmap item |
|---|---|---|---|---|---|
| Missing receipt | Executor runs a side effect with no authorization evidence. | `execute_with_receipt`, `GovernedExecutor`, and `ReceiptVerifier` reject `None`. | `test_executor_refuses_no_receipt`, `gove-zone proofpack`, `examples/tamper_demo`. | Direct tool paths outside the gate can bypass ACGS. | Integration hardening and gateway conformance tests. |
| Malformed receipt | Bad or incomplete evidence is accepted. | Required-field checks fail closed. | `test_executor_refuses_malformed_receipt`, `test_verification_rejects_missing_fields`. | External runtimes must not catch-and-ignore validation errors. | Standard error contracts for adapters. |
| Expired receipt | Old authorization is replayed after its valid period, a signed receipt is pre-minted too far in the verifier's future, a caller tries to widen the future-issuance skew, or the receipt has no valid lifetime because expiry predates issuance. | `expires_at` and `timestamp` are hash-bound and compared as timezone-aware timestamps. Signed receipts and receipt-v2 enforce `timestamp - skew <= now <= expires_at`. The default and maximum skew are both 300 seconds; overrides may only tighten to integer values from 0 through 300. Bool, non-integer, negative, or greater-than-300 skew values fail as `EXPIRY_UNPARSEABLE` before verification, ledger burn, or execution. Liveness failures map to `RECEIPT_EXPIRED` / `EXPIRED` before consumption or side effects. | `test_receipt_expiry.py`, `test_future_issued_receipt_beyond_default_skew_rejects_before_side_effect`, `test_clock_skew_override_can_tighten_but_not_weaken_verification`, `test_receipt_expires_before_issued_rejects_as_liveness_failure`. | Expiry remains optional for legacy receipts unless a strict profile requires it. Host-clock trust remains an operator responsibility; there is no built-in trusted time source or global receipt/nonce revocation service. | Default expiry, default-on single-use profiles, and trusted-time binding. |
| Tampered receipt | Actor/action/policy/expiry/authority fields are edited. | `receipt_hash` recomputation detects edits; signing verifies hash when explicitly configured. | `test_verification_rejects_altered_fields`, `test_receipt_signing.py`, demo output. | Unsigned hashes are recomputable under host compromise; low-level issuance does not auto-provision a signer. | Managed signer/verifier provisioning and key lifecycle. |
| Scoped trust-purpose confusion | A receipt or key for one trust domain is replayed into another domain. | Receipt-v2 trust resolution includes tenant, project, environment, and purpose. The default decision-receipt purpose is `decision-receipt`; platform tenant bootstrap uses `acgs.platform-bootstrap.receipt.v1`. Purpose mismatch, missing purpose, untrusted/revoked/unavailable trust material, and expired trust keys fail closed. | `test_receipt_v2_trust_purpose_defaults_and_custom_scope_passthrough`, `test_receipt_v2_trust_purpose_threads_through_wrappers`, tenant-bootstrap integration tests. | This is scoped key selection, not full PKI or automatic trust distribution. | Managed trust registry and key lifecycle. |
| Non-ALLOW provenance masking | A forged `DENY` or `ESCALATE` receipt hides a wrong actor/action/argument/policy/trust binding behind a generic non-executable refusal. | Signed non-ALLOW receipts are still non-executable, but verifier checks integrity, signature/scoped trust, liveness, actor/action/argument/audit/policy/authority bindings before the final `DENIED_RECEIPT` or `ESCALATED_RECEIPT` refusal. | `test_signed_non_allow_receipts_report_late_binding_before_decision_reason`, `test_signed_non_allow_receipts_report_wrong_args_before_decision_reason`, `test_fully_bound_signed_non_allow_receipts_reject_before_side_effect`. | Only paths that pass `expected_*` values from authenticated runtime context get those bindings checked. | Adapter conformance and runtime-context hardening. |
| Mismatched actor | Receipt issued for one actor is used by another. | Gate requires `expected_actor` from runtime context and checks receipt actor. | `test_maci_role_separation.py`, executor tests. | Actor authentication is integrator-owned. | Identity binding adapters and production auth profile. |
| Mismatched action | Receipt for one tool authorizes another. | `expected_action` check. | `test_decision_receipt.py`, `test_executor_guard.py`. | None inside gate; bypass risk remains outside gate. | Gateway coverage for all tool entrypoints. |
| Argument substitution | Receipt for safe args is reused for dangerous args. | `argument_hash` and exact transform checks. | `test_argument_binding.py`, `test_executor_guard.py`. | Raw args are not stored in audit by default; strong replay needs side-store. | Proof packs with side-store or redaction policy. |
| Self-validation | Agent validates its own authority. | `Validator` role, `DecisionReceipt.from_record` guard, gate actor-anchor check. | `test_maci_role_separation.py`. | Opaque string identity; no built-in IAM. | Integrator identity and signed validator profile. |
| Replay attempt | Old receipt is reused across time/run/context. | Expiry, actor/action/args/tenant/boundary/policy binding; opt-in single-use `ReceiptConsumptionLedger` burns the receipt's audit anchor before execution; workflow ledger for workflow paths. | `test_receipt_expiry.py`, `test_receipt_consumption.py`, workflow tests, replay tests. | The consumption ledger is opt-in (off by default); there is no global receipt/nonce revocation service in the local kernel. | Default-on single-use profile; global receipt/nonce revocation service. |
| Audit-chain tampering | Evidence is edited after the fact. | Hash-chained JSONL with `previous_hash` and `event_hash`; malformed tail fails closed before append. | `test_audit_chain.py`, `test_audit_chain_corruption.py`, tamper demo. | Local JSONL is not WORM/off-host durable. | WORM/SIEM/exportable proof packs. |
| Consumption-ledger tampering | The single-use record is edited (line deleted/reordered/altered/truncated) to un-burn a receipt and re-enable exactly one replay. | Each ledger entry is hash-chained (`previous_hash`/`entry_hash`, mirroring the audit chain), so interior delete/reorder/content-edit is detectable; `verify_ledger()` / `gove-zone verify-ledger` reports it; `seal()` baselines a pre-chaining legacy ledger. Tail truncation is caught by a persisted high-water-mark — opt-in `ReceiptConsumptionLedger(path, checkpoint=True)` advances a `<ledger>.hwm` sidecar that `verify_ledger()` auto-consults. Forged/orphan burns (a `consumed_key` anchoring no real decision) are caught by `reconcile(audit_store)` / `verify-ledger --audit PATH`. (Replay-blocking itself never depends on the chain — it keys on `consumed_key` — so tampering is exposed by the report, not by a silent execution.) Every blocked replay and every failed `verify_ledger()`/`reconcile()` is also surfaced as a WARNING on the `gove_zone.consumption` logger (a logger record only — the SIEM/stderr integration point, never the audit chain) plus a per-instance counter via `observability()`, so a fleet can alert/count rather than only catch the exception. | `test_consumption_tamper.py`, `test_consumption_hwm.py`, `test_consumption_reconcile.py`. | The `.hwm` sidecar and the ledger share storage: an attacker who rewrites both consistently is not stopped (place the sidecar on append-only/off-host storage to raise the bar). `reconcile` trusts the audit chain's `iter_events()` — verify it separately with `verify_chain()`. No global receipt/nonce revocation service. | WORM / off-host placement of the audit chain + HWM sidecar; signed checkpoints. |
| Unsigned dev mode misuse | Local unsigned receipts are marketed as production signing. | Governed gates require signature verification by default; docs and `CLAIM_BOUNDARY` distinguish unsigned local proof from explicitly configured signing. | `test_profile.py`, `test_receipt_signing.py`, `docs/CLAIMS.md`. | Low-level issuance can still be unsigned, and an operator can explicitly set a gate to `require_signature=False`. | Managed signer/verifier provisioning and deployment checks. |
| Policy-bundle substitution | Receipt is evaluated under one policy but executed under another. | Policy bundle id/hash checks; canonical `RuleSetPolicy` export. | `test_policy_bundle_io.py`, `test_tenant_safety.py`. | No active/stale/revoked lifecycle registry. | Signed policy bundles and versioned policy registry. |
| Native control-plane transaction drift | A managed route records a native receipt but commits a different SQL mutation, event/head, outbox row, or consumption state; or treats `DENY`/`ESCALATE` as executable. | The current agent-create route uses explicit distinct receipt issuer and consumption attestation providers; binds the full environment policy hash; records native receipt/event/head/outbox state and `ALLOW` consumption in one SQL transaction; and leaves `DENY`/`ESCALATE` unconsumed and non-executable. | `packages/acgs-control-plane/tests/test_native_agent_transaction_route.py`, `test_exports.py`, `test_native_receipt_ledger.py`, `test_receipts_dashboard.py`. | Only agent creation is on this canonical native path. Twelve legacy unsigned write aliases remain and still block production posture. Provider injection is explicit, but operator environment/provider wiring is incomplete. SQL atomicity does not prove external exactly-once delivery. Native project/environment scope is bound through the event path, not direct receipt columns. | Complete native cutover, provider wiring, trust registry, external delivery reconciliation, and production posture closure. |
| MCP/tool-gateway misuse | MCP connects tools but execution happens before governance. | `integration.py` normalizes MCP/function-call shapes; examples show gateway placement. | `test_integration_hook.py`, `test_integration_gaps.py`, `examples/mcp_tool_gate`. | Adapter shape support is local; production MCP server enforcement must be wired by integrator. | MCP adapter conformance suite. |
| Executor bypass | A caller invokes the raw tool instead of the governed executor. | Architecture docs require direct tools behind gate; tests prove gated paths only. | Integration guide, examples. | Kernel cannot stop code paths it is not wired into. | Gateway wrappers, static checks, deployment profile. |
| Policy evaluation failure | Policy exception accidentally allows execution. | Kernel synthesizes DENY and audits it. | `test_fail_closed.py`. | Hanging policies need configured watchdog. | Secure defaults for `policy_timeout`. |
| Policy timeout/hang | Executor waits forever or eventually allows after stale evaluation. | Optional `policy_timeout` converts timeout to DENY. | `test_fail_closed_gaps.py`. | Timeout is configurable, not globally required. | Secure profile defaults. |
| Audit append failure | Side effect runs without durable evidence. | Kernel raises `AuditError` before execution. | `test_fail_closed.py`, `test_audit_chain_corruption.py`. | Local disk availability and durability are operator concerns. | Durable/off-host audit sink. |
| Step reorder | Every call is individually authorized, but a step runs before a predecessor the approved plan requires — so each receipt is valid while the *sequence* violates the plan. | `WorkflowExecutor.execute_step` step 7 (`workflow.py`) rejects a step whose declared predecessor is absent from the run ledger (`reorder rejected`), **before** the atomic inner gate-and-execute at step 8, so the side effect does not run. The constraint itself is content-addressed: `WorkflowDAG.dag_hash()` hashes each step's action plus its sorted predecessor set, and that hash is bound into both `WorkflowAuthorization` and every `WorkflowStepReceipt` — so ordering is a property of the *signed* object, not only of executor state. | `test_reorder_predecessor_not_run_rejected_tool_not_called`, `test_happy_path_multistep_executes_in_order`, `test_replay_fails_on_predecessor_hash_mismatch`. | Live enforcement reads `WorkflowExecutor.ledger`, which is trusted in-process runtime state, not durable evidence; a fresh executor starts empty. Offline re-checking is `verify_workflow_replay`, which reconstructs the ordering judgment from the chain — but it is a separate call an operator must actually run. Steps invoked outside the workflow executor are not ordered at all. | Durable/off-host workflow ledger; ordering assertions in the proof pack so a third party re-derives them without running the replay call. |
| Predecessor substitution | The right predecessor step id ran, but the step receipt points at a *different* receipt for it — e.g. a discarded or more permissive earlier attempt — so the ordering check passes against evidence that is not what actually executed. | Step 7 also compares `step_receipt.predecessor_receipt_hashes[pred]` against the hash the ledger recorded for that step and rejects on mismatch (`predecessor substitution rejected`). The predecessor hash map is inside `WorkflowStepReceipt._hash_payload`, so editing it invalidates `step_receipt_hash` and, when signing is configured, the envelope signature. | `test_predecessor_substitution_rejected_tool_not_called`, `test_declared_predecessors_mismatch_rejected_tool_not_called`, `test_replay_fails_on_predecessor_hash_mismatch`. | Same ledger-durability limit as reorder. Envelope signing is **opt-in**: `WorkflowExecutor.require_signature` defaults to `False`, and `verify_workflow_replay` passes `require_signature=verifier is not None`, so an unsigned envelope is accepted when no verifier is supplied — hash binding alone is recomputable under host compromise. | Default-on envelope signing profile; signed workflow ledger checkpoints. |
| Cross-workflow / cross-plan step lifting | A validly signed step receipt from one workflow run (or a different approved plan) is presented to another run whose policy or data context differs. | Four independent checks, all before execution: step 4 rejects a `workflow_id` mismatch (`cross-workflow step receipt`); step 4b rejects an envelope presented at a DAG position other than the `step_id` it names; step 5 rejects a `dag_hash` bound to a different plan; and `_verify_authorization` rejects an authorization whose `workflow_id` or `dag_hash` does not match the executor's. | `test_cross_workflow_receipt_rejected_tool_not_called`, `test_step_receipt_for_one_position_rejected_at_another`, `test_dag_altered_rejected_tool_not_called`, `test_step_not_in_plan_rejected_tool_not_called`, `test_cross_plan_workflow_id_rejected_tool_not_called`, `test_cross_plan_dag_hash_rejected_tool_not_called`, `test_step_lifted_to_different_plan_rejected_tool_not_called`. | Workflow ids are integrator-supplied opaque strings; the kernel does not allocate or register them, so two runs that reuse an id are indistinguishable to these checks. | Registered workflow-run identifiers; signed plan registry. |
| Cross-level collusion (plan/step) | Role separation holds at each level in isolation, yet one principal validates the plan and proposes a step under it (or the reverse), so the same party authorizes its own work across levels. | `WorkflowExecutor` maintains `proposers` (seeded `{plan_proposer, runner}`) and `validators` (seeded `{plan_validator_id}`), and `_verify_authorization` check E rejects any step whose candidate actor/validator would make the two sets intersect. Sets are committed only after a step succeeds, so a rejected step cannot pollute them. `verify_workflow_replay` recomputes the same overlap offline from the chain. | `test_cross_level_collusion_plan_validator_is_step_proposer`, `test_cross_level_collusion_step_validator_is_plan_proposer`, `test_cross_level_separation_persists_across_steps`, `test_rejected_step_does_not_pollute_cross_level_state`, `test_runner_is_plan_validator_rejected_tool_not_called`, `test_replay_rejects_cross_level_collusion`. | Separation is over opaque identity strings, as elsewhere in this table: two identities controlled by one human are two principals to the kernel. The runner anchor (`governed.expected_actor`) is executor configuration and is not carried in the chain, so `verify_workflow_replay` cannot re-check the runner's own membership offline. | Integrator identity binding and signed validator profiles; carry the runner anchor into the authorization so replay covers it. |

## Adversary model (ADV1–ADV14)

The threat table above is the **per-mechanism** view: one row per attack technique against
the receipt gate. This section adds the **per-actor** view — the canonical adversary set the
reference monitor is designed against — and reconciles the two so neither drifts from the
other. The frame is deliberate: a reference monitor (Anderson 1972) is sound only if it has
**complete mediation**, is **tamper-proof**, and is **verifiable**; an adversary set lets us
say *who* attacks *which* of those properties and *where* the defense lives.

Claim discipline (mirrors `docs/CLAIMS.md`): every row is tagged by present-state, not by
intent.

- **[on-master]** — a current control with cited tests/fixtures in this checkout.
- **[on-master, partial]** — a real control exists but does not yet close the adversary
  fully; the residual is named.
- **[proposed]** — no current control; the defense is roadmap (named gate/track only).

The `ADV*` prefix is intentional and must **not** be conflated with `COMPARISON.md`'s
`A1–A8` *capability-comparison axes* — a different, unrelated namespace. Gate/track labels
refer to the archived `docs/archive/ROADMAP-ENFORCEMENT-SUBSTRATE.md` (G1 = adoptable
kernel, G2 = trustless evidence, G3 = production proof); `docs/ROADMAP.md` is the roadmap
of record.

| # | Adversary | What they attempt | Closing mechanism | Gate / track | Status | Evidence / mapped threats |
|---|---|---|---|---|---|---|
| ADV1 | Malicious / jailbroken proposer (incl. the LLM) | Emit a dangerous, malformed, mis-actored, or mis-actioned action and have it executed | Complete mediation + deny-by-default; the proposer holds no authority; required-field and actor/action checks fail closed | G1 | [on-master] | `test_fail_closed.py`, `test_decision_receipt.py`, `test_executor_guard.py`, `test_maci_role_separation.py` — *Missing receipt, Malformed receipt, Mismatched actor, Mismatched action, Self-validation* |
| ADV2 | Insider / malicious operator | Execute unreceipted side effects or rewrite history (receipts, audit chain, single-use ledger) after the fact | Tamper-**evidence** today: hash-chained JSONL + hash-chained consumption ledger make edits detectable; signing closes silent receipt edits | G2 / Track C | [on-master, partial] | `test_audit_chain.py`, `test_audit_chain_corruption.py`, `test_consumption_tamper.py`, `test_receipt_signing.py` — *Tampered receipt, Audit-chain tampering, Consumption-ledger tampering*. Residual: detection, not prevention; trustless transparency (inclusion/consistency proofs) is **[proposed]** |
| ADV3 | Compromised host | Subvert the running kernel below the TCB (recompute an unsigned hash, patch the binary) | TEE remote attestation; minimized, measured TCB; reproducible builds bind running binary to audited source | G2 / Track D | [proposed] | attestation quote bound to receipt — net-new. Partly overlaps *Tampered receipt* (an unsigned `receipt_hash` is recomputable under host compromise) |
| ADV4 | Network adversary | Drop / delay / replay / MITM the authorization lookup | Fail-closed on timeout; signed receipts; hash-bound `expires_at`; opt-in single-use ledger | G1 | [on-master, partial] | `test_receipt_expiry.py`, `test_receipt_consumption.py` — *Expired receipt, Replay attempt*. Residual: anti-replay ledger is opt-in/off by default |
| ADV5 | Colluding / cross-tenant | Use another tenant's authority or read its evidence | Tenant isolation in policy/receipt binding; proven non-interference is roadmap | G1 / Track A | [on-master, partial] | `test_tenant_safety.py` — *Policy-bundle substitution, Mismatched actor (cross-tenant)*. Residual: non-interference model-check is **[proposed]** |
| ADV6 | Supply-chain attacker | Poison a dependency, the build, or the constitution (policy bundle) | Constitutional-hash CI + reproducible builds + binary transparency | G2 / Track A | [on-master, partial] | `.github/workflows/constitutional-hash.yml`, `tests/docs/` constitutional-hash checks. Caveat below: the hash inventory is currently empty, so the gate is real plumbing over a no-op inventory; bit-reproducible build check is **[proposed]** |
| ADV7 | Dishonest auditor / verifier | The logging party itself cheats, colludes, or serves a split view | Trustless verification — a third party needs no trust in the logger; ≥2 independent witnesses | G2 / Track C | [proposed] | split-view defense via witnessing — net-new |
| ADV8 | TOCTOU / time-of-use | Change state or arguments between policy check and execution | Pre-execution re-validation + exact-argument binding; the executor re-verifies (and, with a ledger, burns) the receipt immediately before calling the tool | G1 | [on-master] | `test_argument_binding.py`, `test_executor_guard.py` — *Argument substitution, Replay attempt* |
| ADV9 | **Out-of-gate executor bypass** (complete-mediation keystone) | Invoke the raw tool / side-effect path and never reach the governed executor | Adapter/gateway completeness + a static "is the gate wired" check; integration-matrix tiers per runtime | G1 / Track F | [on-master, partial] | `test_integration_gaps.py`, `test_integration_hook.py` — *Executor bypass, MCP/tool-gateway misuse*. Residual: the kernel cannot stop code paths it is not wired into; gateway conformance is partial |
| ADV10 | Profile / signature downgrade | Force a signed gate to accept unsigned, or downgrade `production-strict`→`production`→`dev` | Pin the profile to the verifier; never let the artifact decide whether its own signature is checked; a gate requiring signing with no verifier fails closed | G1 | [on-master] | `test_profile.py`, `test_production_strict.py`, `test_receipt_signing.py`; fixtures `fixtures/proofpacks/sig-downgrade-with-verifier/`, `fixtures/receipts/sig-missing-verifier/` (a downgrade fail-open was found + fixed) — *Unsigned dev mode misuse* |
| ADV11 | Signing-key compromise / key lifecycle | Steal or misuse the Ed25519 key; exploit absent rotation/revocation | Key custody + rotation + an operator-supplied static receipt-signing-key-ID revocation list checked at supported gates and offline proof-pack verification | G2 / Track D | [on-master, partial] | `test_revocation.py`, `test_proofpack_revocation.py`, `test_escalation_resume.py` (the static list is implemented for listed runtime/offline paths). Residual: it is off by default; distribution, key custody, automated rotation, per-receipt/global nonce revocation, and full workflow/plan key-population coverage are **[proposed]** |
| ADV12 | Malicious policy-author / insider certifier | Author a permissive bundle that defeats deny-by-default *within the rules* (the Clark-Wilson certifier role) | Policy→SMT property checks (deny-by-default holds) + signed, reviewed, versioned bundles; certifier ≠ executor as principals | G1 / Track A + Track F | [on-master, partial] | `test_policy_bundle_io.py`, `test_rule_set_policy.py` — *Policy-bundle substitution* (bundle id/hash binding). Residual: SMT property checks and certifier/executor principal separation are **[proposed]** |
| ADV13 | Availability / denial-of-service | Kill the verifier, audit sink, or policy evaluation so a fail-closed gate halts all side effects (fail-closed inverts every integrity attack into an availability attack) | Fail-closed today on every internal failure; SLO / error-budget + degraded-mode policy price the DoS surface | G3 | [on-master, partial] | `test_fail_closed.py`, `test_fail_closed_gaps.py`, `test_audit_fail_closed.py` — *Policy evaluation failure, Policy timeout/hang, Audit append failure*. Residual: availability budget / degraded mode is **[proposed]** |
| ADV14 | Clock / time manipulation | Skew the host clock to extend or void receipt expiry | Trusted time source / signed timestamps; expiry not solely host-clock-bound | G2 | [proposed] | `test_receipt_expiry.py` is host-clock today; trusted-time binding is net-new |

> **ADV2 vs ADV3 boundary.** ADV2 (insider operator) is *privileged-but-policy-bound* — they
> run the deployment but remain subject to the gate and the audit chain; ADV3 (compromised
> host) is *below the TCB* — the kernel binary or its environment is subverted. Many real
> deployments give an insider host access too; the table treats them as distinct **defense
> surfaces** (transparency/witnessing for ADV2, attestation for ADV3), not as disjoint actors.
>
> **Constitutional-hash CI caveat (ADV6).** `.github/workflows/constitutional-hash.yml` runs
> on every PR/push, but its inventory of sealed `# Constitutional Hash:` markers is currently
> empty in the parent-tracked tree — so it presently guards an empty set. ADV6's supply-chain
> defense is real plumbing over a currently no-op gate; populating the inventory is part of
> the remaining work, not a finished control.
>
> **Adversaries without a current named-threat row.** ADV3, ADV7, and ADV14 are **[proposed]**
> and are not yet decomposed into rows of the per-mechanism threat table above; their defenses
> (attestation, witnessing, trusted time) are G2/G3 roadmap work. ADV6 and ADV11 have
> **[on-master, partial]** controls (constitutional-hash CI; the operator-supplied,
> static receipt-signing-key-ID revocation list) but likewise do not yet have dedicated
> threat-table rows — adding those rows is
> tracked follow-up, recorded here so the gap is explicit rather than silent.

### Reconciliation — each named threat maps to ≥1 adversary

Every one of the 25 named threats in the table above is owned by at least one adversary. The
keystone constraint: **Executor bypass maps to ADV9** and must never be dropped, because it is
the complete-mediation property of the reference monitor.

| Named threat | Primary adversary | Also |
|---|---|---|
| Missing receipt | ADV1 | ADV9 |
| Malformed receipt | ADV1 | ADV2 |
| Expired receipt | ADV4 | ADV14 |
| Tampered receipt | ADV2 | ADV3, ADV1 |
| Mismatched actor | ADV1 | ADV5 |
| Mismatched action | ADV1 | — |
| Argument substitution | ADV8 | ADV1 |
| Self-validation | ADV1 | ADV12 |
| Replay attempt | ADV4 | ADV8 |
| Audit-chain tampering | ADV2 | ADV3 |
| Consumption-ledger tampering | ADV2 | ADV3 |
| Unsigned dev mode misuse | ADV10 | — |
| Policy-bundle substitution | ADV12 | ADV5 |
| MCP/tool-gateway misuse | ADV9 | — |
| Executor bypass | ADV9 | — |
| Policy evaluation failure | ADV13 | ADV1 |
| Policy timeout/hang | ADV13 | — |
| Audit append failure | ADV13 | ADV2 |
| Native control-plane transaction drift | ADV8 | ADV2, ADV9, ADV12 |
| Step reorder | ADV1 | ADV8 |
| Predecessor substitution | ADV1 | ADV2 |
| Cross-workflow / cross-plan step lifting | ADV4 | ADV1 |
| Cross-level collusion (plan/step) | ADV1 | ADV12, ADV5 |
| Scoped trust-purpose confusion | ADV5 | ADV11, ADV4 |
| Non-ALLOW provenance masking | ADV1 | ADV7 |

The takeaway the per-actor view makes visible: **thirteen of fourteen adversaries are
systems-and-cryptography problems**, not model-quality problems. ADV1 is the only adversary
the proposing model touches, and even there the defense is structural (deny-by-default,
complete mediation), not a judgment about model output. The
`tests/docs/test_adversary_model.py` invariant locks this section: it fails closed if an
adversary is dropped (especially ADV9), if a named threat loses its mapping, or if a cited
on-master evidence file disappears.

## Deployment hardening — defaults that matter

The governed gates require signature verification by default, but receipt
issuance does not auto-provision a signer. Anti-replay remains opt-in and must be
enabled for a hardened posture; that limitation is explicit in this local
candidate:

- **Gate verification requires a signature by default; issuance does not
  auto-sign.**
  `require_signature` defaults to `True` (`executor.py`, `contracts.py`). The
  low-level receipt constructors need an explicit signer; `signer=None` produces
  an unsigned receipt. A governed gate invoked with no configured trusted
  verifier fails closed loudly — it raises `ProductionProfileError` before the
  tool runs, rather than accepting the unsigned receipt or generating a key
  (`executor.py`, `contracts.py`). To run the explicit unsigned "dev mode", an
  operator must opt in with `require_signature=False`, in which case verification
  checks only the local SHA-256 `receipt_hash`, which is recomputable under host
  compromise (see the *Tampered receipt* and *Unsigned dev mode misuse* rows).
  Production closure needs both explicitly signed issuance and a gate configured
  with `require_signature=True` plus the corresponding trusted verifier
  (`signing.py`, `test_receipt_signing.py`).
- **Scoped trust purpose is part of receipt-v2 key selection.**
  `DecisionReceipt.verify` defaults to the public `decision-receipt` purpose;
  executor wrappers and `ReceiptVerifier` pass that default unless configured
  with a caller-owned `trust_purpose`. The control plane's tenant-bootstrap
  path deliberately uses `acgs.platform-bootstrap.receipt.v1`, so a generic
  runtime key cannot verify a platform-bootstrap receipt and vice versa. A
  blank purpose, wrong-purpose key, revoked key, expired key, or unavailable
  trust registry fails closed before any side effect.
- **Signed and receipt-v2 liveness includes bounded not-before skew.**
  `timestamp` and `expires_at` are both hash-bound. Signed receipts and
  receipt-v2 are valid only when the verifier's time is within
  `timestamp - max_clock_skew_seconds <= now <= expires_at`. The default and
  maximum skew are both 300 seconds. Overrides may only tighten the bound to an
  integer from 0 through 300; a bool, non-integer, negative value, or value over
  300 fails as `EXPIRY_UNPARSEABLE` before receipt verification, ledger burn, or
  side effect. A receipt issued farther in the verifier's future, or one whose
  expiry predates issuance, fails closed as `RECEIPT_EXPIRED` (mapped by wrapper
  contracts to the liveness class `EXPIRED`) before any consumption-ledger burn
  or side effect. `execute_with_receipt`, `GovernedExecutor`, and
  `ReceiptVerifier` thread this bound, with per-call or construction-time
  tighten-only override. The tenant-bootstrap canonical managed-mutation UoW
  pins `DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS` (300 seconds) for its governed SQL
  mutation. This does not add a trusted-time source; the verifier still depends
  on the supplied `now_iso` or the host clock.
- **Anti-replay is opt-in, off by default.** `DecisionReceipt.verify` is
  stateless, so a valid `ALLOW` receipt can be replayed until its `expires_at`
  *unless* the gate carries a single-use ledger. Passing a
  `ReceiptConsumptionLedger` (`consumption.py`) makes the receipt single-use: its
  audit anchor is burned before the side effect, and a replay raises
  `ReceiptAlreadyUsedError` (`test_receipt_consumption.py`). The ledger is now
  hash-chained, so the freshness record is itself tamper-evident (see the
  *Consumption-ledger tampering* row) — but it must be enabled per gate and there
  is still no global receipt/nonce revocation service. `replay.py` is
  *deterministic/audit* replay, not anti-replay enforcement. Mitigations today:
  enable the consumption ledger, set a short `expires_at`, use the workflow ledger
  for workflow paths, and retain side-store proof packs for strong replay. A
  default-on single-use profile and a global receipt/nonce revocation service
  are roadmap.
- **The ledger is bounded without reopening replay.** The single-use record grows
  one line per governed execution; `ReceiptConsumptionLedger.prune` (CLI:
  `gove-zone prune-ledger`) caps it by removing only entries whose receipt has
  *already expired* — safe because an expired receipt fails `verify` check 13
  before `consume` is reached. To keep the clock-set-back posture across a prune,
  it persists a **prune time-watermark** (`<ledger>.pwm` = the latest expiry ever
  removed); `consume` refuses any receipt expiring at or before that watermark, so
  a rolled-back clock cannot replay a pruned-out receipt. Receipts minted without
  an `expires_at` are never prunable. This compares fixed timestamps only, so it
  never rejects a legitimately-fresh receipt under a forward clock. A corrupt
  watermark fails closed and it is advanced write-ahead (crash-safe); its residual
  gap is *deletion* — an attacker who deletes `<ledger>.pwm` and rolls the clock
  back reopens the pruned receipt (same threat class as deleting `.hwm` without
  `checkpoint`), so place both sidecars on protected/append-only storage.

Also operator-tunable and off/optional by default: `expires_at` (there is static
receipt-signing-key revocation when supplied, but no global receipt/nonce
revocation service) and `policy_timeout` (hang → DENY only when configured). Set
both for a hardened deployment.

## Governed-MCP gateway trust boundary

The governed-MCP gateway (`packages/gove-zone/src/gove_zone/adapters/mcp_gateway.py`)
is a transparent stdio proxy that fronts one downstream MCP server and gates its
`tools/call` traffic through the sealed kernel. Its security posture in the
current pilot:

- **Host→gateway hop is assumed trusted (local transport).** The gateway does not
  itself authenticate the host; it derives the session principal from the MCP
  `clientInfo` presented at `initialize` plus the config principal map. That
  principal is only as strong as the local stdio transport's authentication
  (same trust domain — a subprocess the operator launched). This is a documented
  limitation, **not** an end-to-end authenticated-identity claim. A remote /
  multi-tenant deployment would require authenticating that hop before relying on
  the bound principal.
- **Identity never comes from the request body (G4).** The actor bound into every
  receipt is the session principal, held per MCP session (keyed by the session
  object, never a process global), so a forged `actor` field in
  `params.arguments` is ignored and cannot cross between sessions.
- **Principal enforcement is at first `tools/call`, not `initialize`.** The
  low-level MCP `Server` owns the handshake, so an unmapped principal is failed
  closed with a DENY `CallToolResult` at the first governed call rather than by
  rejecting `initialize`. Same fail-closed guarantee, different enforcement point.
- **Fail-closed method surface.** Only `tools/list` (pass-through) and
  `tools/call` (gated) are wired. `sampling/createMessage` (the downstream's
  reverse LLM channel) is denied in the current profile — the runtime
  (`run_stdio_gateway`) constructs the downstream client session with no sampling
  callback, so a downstream sampling request is refused at the gateway and never
  reaches the host. Partner opt-in (which would require bridging downstream→host
  sampling) is a reserved, **not-yet-honoured** follow-up: the `allow_sampling`
  config field is parsed for forward-compatibility but has no effect. Every other
  method is unregistered, so the SDK answers *method-not-found* — never a silent
  forward. Full resources/prompts proxying is likewise a documented follow-up,
  not shipped blind.
- **Single-use by construction.** Every ALLOW forward and every escalation resume
  runs through the receipt gate with one shared `ReceiptConsumptionLedger`; the
  approval's audit anchor is burned before the side effect, so a replay raises
  `ReceiptAlreadyUsedError`.
- **TRANSFORM out of scope.** Config load rejects transform-policy bundles so an
  unrouted TRANSFORM decision cannot silently hard-fail every call at the gate.

**Out-of-band operator surface.** The above covers the MCP-reachable
`tools/call` gate. `approve()` / `resume()` / `pending_descriptor()` are a
second, separate boundary: they are not MCP-reachable at all (`build_server`
registers only `tools/list` + `tools/call`), carry no caller-identity check of
their own, and are actually gated by process/CLI possession of a validator
identity distinct from every mapped principal plus the config signer key — the
same insider/operator trust ADV2 names above, made explicit rather than
implicit. See `docs/design/mcp-gateway-trust-boundaries.md` for the full
treatment, including how bounded-capacity back-pressure (`max_pending` /
`max_pending_per_principal`) turns the previously unbounded `_pending`/
`_approvals` growth into a bounded, audited escalation-availability trade-off.

## Security-sensitive files

- `packages/gove-zone/src/gove_zone/adapters/mcp_gateway.py`
- `packages/gove-zone/src/gove_zone/receipt.py`
- `packages/gove-zone/src/gove_zone/executor.py`
- `packages/gove-zone/src/gove_zone/kernel.py`
- `packages/gove-zone/src/gove_zone/audit.py`
- `packages/gove-zone/src/gove_zone/consumption.py`
- `packages/gove-zone/src/gove_zone/replay.py`
- `packages/gove-zone/src/gove_zone/signing.py`
- `packages/gove-zone/src/gove_zone/policy.py`
- `packages/gove-zone/src/gove_zone/tenant.py`
- `packages/gove-zone/src/gove_zone/integration.py`
- `.claude/hooks/acgs-emit-receipt.py`
- `.claude/settings.json`

## Required security review behavior

Any change to receipt, policy, audit, signing, replay, executor, hook, or adapter code must include:

- negative-path test proving the side effect did not run;
- wiring proof at the dispatcher/gateway boundary;
- claim updates in `docs/CLAIMS.md` if behavior changed;
- explicit note whether unsigned mode or signing mode semantics changed.
