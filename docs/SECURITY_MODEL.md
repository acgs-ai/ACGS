# Security model and threat table

Core invariant:

> **No valid Decision Receipt, no side effect.**

Status: alpha/local proof. This document is a threat model, not a certification claim.

## Threat table

| Threat | Risk | Current protection | Test coverage / demo | Remaining limitation | Roadmap item |
|---|---|---|---|---|---|
| Missing receipt | Executor runs a side effect with no authorization evidence. | `execute_with_receipt`, `GovernedExecutor`, and `ReceiptVerifier` reject `None`. | `test_executor_refuses_no_receipt`, `gove-zone proofpack`, `examples/tamper_demo`. | Direct tool paths outside the gate can bypass ACGS. | Integration hardening and gateway conformance tests. |
| Malformed receipt | Bad or incomplete evidence is accepted. | Required-field checks fail closed. | `test_executor_refuses_malformed_receipt`, `test_verification_rejects_missing_fields`. | External runtimes must not catch-and-ignore validation errors. | Standard error contracts for adapters. |
| Expired receipt | Old authorization is replayed after its valid period. | `expires_at` is hash-bound and compared as a timezone-aware timestamp. | `test_receipt_expiry.py`. | Expiry is optional; no global revocation list. | Secure profile with expiries and revocation. |
| Tampered receipt | Actor/action/policy/expiry/authority fields are edited. | `receipt_hash` recomputation detects edits; signing verifies hash when engaged. | `test_verification_rejects_altered_fields`, `test_receipt_signing.py`, demo output. | Unsigned hashes are recomputable under host compromise. | Signed receipts on by default for secure profile. |
| Mismatched actor | Receipt issued for one actor is used by another. | Gate requires `expected_actor` from runtime context and checks receipt actor. | `test_maci_role_separation.py`, executor tests. | Actor authentication is integrator-owned. | Identity binding adapters and production auth profile. |
| Mismatched action | Receipt for one tool authorizes another. | `expected_action` check. | `test_decision_receipt.py`, `test_executor_guard.py`. | None inside gate; bypass risk remains outside gate. | Gateway coverage for all tool entrypoints. |
| Argument substitution | Receipt for safe args is reused for dangerous args. | `argument_hash` and exact transform checks. | `test_argument_binding.py`, `test_executor_guard.py`. | Raw args are not stored in audit by default; strong replay needs side-store. | Proof packs with side-store or redaction policy. |
| Self-validation | Agent validates its own authority. | `Validator` role, `DecisionReceipt.from_record` guard, gate actor-anchor check. | `test_maci_role_separation.py`. | Opaque string identity; no built-in IAM. | Integrator identity and signed validator profile. |
| Replay attempt | Old receipt is reused across time/run/context. | Expiry, actor/action/args/tenant/boundary/policy binding; opt-in single-use `ReceiptConsumptionLedger` burns the receipt's audit anchor before execution; workflow ledger for workflow paths. | `test_receipt_expiry.py`, `test_receipt_consumption.py`, workflow tests, replay tests. | The consumption ledger is opt-in (off by default); no global nonce/revocation registry in the local kernel. | Default-on single-use profile; global revocation registry. |
| Audit-chain tampering | Evidence is edited after the fact. | Hash-chained JSONL with `previous_hash` and `event_hash`; malformed tail fails closed before append. | `test_audit_chain.py`, `test_audit_chain_corruption.py`, tamper demo. | Local JSONL is not WORM/off-host durable. | WORM/SIEM/exportable proof packs. |
| Consumption-ledger tampering | The single-use record is edited (line deleted/reordered/altered/truncated) to un-burn a receipt and re-enable exactly one replay. | Each ledger entry is hash-chained (`previous_hash`/`entry_hash`, mirroring the audit chain), so interior delete/reorder/content-edit is detectable; `verify_ledger()` / `gove-zone verify-ledger` reports it; `seal()` baselines a pre-chaining legacy ledger. Tail truncation is caught by a persisted high-water-mark — opt-in `ReceiptConsumptionLedger(path, checkpoint=True)` advances a `<ledger>.hwm` sidecar that `verify_ledger()` auto-consults. Forged/orphan burns (a `consumed_key` anchoring no real decision) are caught by `reconcile(audit_store)` / `verify-ledger --audit PATH`. (Replay-blocking itself never depends on the chain — it keys on `consumed_key` — so tampering is exposed by the report, not by a silent execution.) Every blocked replay and every failed `verify_ledger()`/`reconcile()` is also surfaced as a WARNING on the `gove_zone.consumption` logger (a logger record only — the SIEM/stderr integration point, never the audit chain) plus a per-instance counter via `observability()`, so a fleet can alert/count rather than only catch the exception. | The `.hwm` sidecar and the ledger share storage: an attacker who rewrites both consistently is not stopped (place the sidecar on append-only/off-host storage to raise the bar). `reconcile` trusts the audit chain's `iter_events()` — verify it separately with `verify_chain()`. No global revocation registry. | WORM / off-host placement of the audit chain + HWM sidecar; signed checkpoints. |
| Unsigned dev mode misuse | Local unsigned receipts are marketed as production signing. | Docs and `CLAIM_BOUNDARY` identify unsigned local proof; signing mode exists. | `test_receipt_signing.py`, `docs/CLAIMS.md`. | Operator can still deploy unsigned mode if they choose. | Secure profile with signing required by default. |
| Policy-bundle substitution | Receipt is evaluated under one policy but executed under another. | Policy bundle id/hash checks; canonical `RuleSetPolicy` export. | `test_policy_bundle_io.py`, `test_tenant_safety.py`. | No active/stale/revoked lifecycle registry. | Signed policy bundles and versioned policy registry. |
| MCP/tool-gateway misuse | MCP connects tools but execution happens before governance. | `integration.py` normalizes MCP/function-call shapes; examples show gateway placement. | `test_integration_hook.py`, `test_integration_gaps.py`, `examples/mcp_tool_gate`. | Adapter shape support is local; production MCP server enforcement must be wired by integrator. | MCP adapter conformance suite. |
| Executor bypass | A caller invokes the raw tool instead of the governed executor. | Architecture docs require direct tools behind gate; tests prove gated paths only. | Integration guide, examples. | Kernel cannot stop code paths it is not wired into. | Gateway wrappers, static checks, deployment profile. |
| Policy evaluation failure | Policy exception accidentally allows execution. | Kernel synthesizes DENY and audits it. | `test_fail_closed.py`. | Hanging policies need configured watchdog. | Secure defaults for `policy_timeout`. |
| Policy timeout/hang | Executor waits forever or eventually allows after stale evaluation. | Optional `policy_timeout` converts timeout to DENY. | `test_fail_closed_gaps.py`. | Timeout is configurable, not globally required. | Secure profile defaults. |
| Audit append failure | Side effect runs without durable evidence. | Kernel raises `AuditError` before execution. | `test_fail_closed.py`, `test_audit_chain_corruption.py`. | Local disk availability and durability are operator concerns. | Durable/off-host audit sink. |

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
| ADV11 | Signing-key compromise / key lifecycle | Steal or misuse the Ed25519 key; exploit absent rotation/revocation | Key custody + rotation + a revocation registry checked at the gate **and** in the offline proof-pack verifier | G2 / Track D | [on-master, partial] | `test_revocation.py`, `test_proofpack_revocation.py`, `test_escalation_resume.py` (revocation registry now exists, runtime + offline — advances past the roadmap draft). Residual: key custody and automated rotation are **[proposed]** |
| ADV12 | Malicious policy-author / insider certifier | Author a permissive bundle that defeats deny-by-default *within the rules* (the Clark-Wilson certifier role) | Policy→SMT property checks (deny-by-default holds) + signed, reviewed, versioned bundles; certifier ≠ executor as principals | G1 / Track A + Track F | [on-master, partial] | `test_policy_bundle_io.py`, `test_rule_set_policy.py` — *Policy-bundle substitution* (bundle id/hash binding). Residual: SMT property checks and certifier/executor principal separation are **[proposed]** |
| ADV13 | Availability / denial-of-service | Kill the verifier, audit sink, or policy evaluation so a fail-closed gate halts all side effects (fail-closed inverts every integrity attack into an availability attack) | Fail-closed today on every internal failure; SLO / error-budget + degraded-mode policy price the DoS surface | G3 | [on-master, partial] | `test_fail_closed.py`, `test_fail_closed_gaps.py`, `test_audit_fail_closed.py` — *Policy evaluation failure, Policy timeout/hang, Audit append failure*. Residual: availability budget / degraded mode is **[proposed]** |
| ADV14 | Clock / time manipulation | Skew the host clock to extend or void receipt expiry | Trusted time source / signed timestamps; expiry not solely host-clock-bound | G2 | [proposed] | `test_receipt_expiry.py` is host-clock today; trusted-time binding is net-new |

> **ADV2 vs ADV3 boundary.** ADV2 (insider operator) is *privileged-but-policy-bound* — they
> run the deployment but remain subject to the gate and the audit chain; ADV3 (compromised
> host) is *below the TCB* — the kernel binary or its environment is subverted. Many real
> deployments give an insider host access too; the table treats them as distinct **defense
> surfaces** (transparency/witnessing for ADV2, attestation for ADV3), not as disjoint actors.

> **Constitutional-hash CI caveat (ADV6).** `.github/workflows/constitutional-hash.yml` runs
> on every PR/push, but its inventory of sealed `# Constitutional Hash:` markers is currently
> empty in the parent-tracked tree — so it presently guards an empty set. ADV6's supply-chain
> defense is real plumbing over a currently no-op gate; populating the inventory is part of
> the remaining work, not a finished control.

> **Adversaries without a current named-threat row.** ADV3, ADV7, and ADV14 are **[proposed]**
> and are not yet decomposed into rows of the per-mechanism threat table above; their defenses
> (attestation, witnessing, trusted time) are G2/G3 roadmap work. ADV6 and ADV11 have
> **[on-master, partial]** controls (constitutional-hash CI; the signing-key revocation
> registry) but likewise do not yet have dedicated threat-table rows — adding those rows is
> tracked follow-up, recorded here so the gap is explicit rather than silent.

### Reconciliation — each named threat maps to ≥1 adversary

Every one of the 18 named threats in the table above is owned by at least one adversary. The
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

The takeaway the per-actor view makes visible: **thirteen of fourteen adversaries are
systems-and-cryptography problems**, not model-quality problems. ADV1 is the only adversary
the proposing model touches, and even there the defense is structural (deny-by-default,
complete mediation), not a judgment about model output. The
`tests/docs/test_adversary_model.py` invariant locks this section: it fails closed if an
adversary is dropped (especially ADV9), if a named threat loses its mapping, or if a cited
on-master evidence file disappears.

## Deployment hardening — defaults that matter

The kernel ships **secure-by-default for signing**, with one remaining
dev-permissive default (anti-replay) that must be changed for a hardened posture;
that remaining limitation is an accepted limitation of the local alpha, not a bug:

- **Signing is required by default; the secure profile is the default.**
  `require_signature` defaults to `True` (`executor.py`, `contracts.py`). The
  default does **not** auto-sign: a gate invoked with no configured trusted
  verifier fails closed loud — it raises `ProductionProfileError` naming both
  exits rather than emitting an unsigned receipt or auto-generating a key
  (`executor.py`, `contracts.py`). To run the explicit unsigned "dev mode" you
  must opt in with `require_signature=False`, in which case verification checks
  only the local SHA-256 `receipt_hash`, which is recomputable under host
  compromise (see the *Tampered receipt* and *Unsigned dev mode misuse* rows).
  Production closure is `require_signature=True` **with** a trusted verifier
  (`signing.py`, `test_receipt_signing.py`); the default already requires
  signing, so it is the verifier — not the flag — that the operator must supply.
- **Anti-replay is opt-in, off by default.** `DecisionReceipt.verify` is
  stateless, so a valid `ALLOW` receipt can be replayed until its `expires_at`
  *unless* the gate carries a single-use ledger. Passing a
  `ReceiptConsumptionLedger` (`consumption.py`) makes the receipt single-use: its
  audit anchor is burned before the side effect, and a replay raises
  `ReceiptAlreadyUsedError` (`test_receipt_consumption.py`). The ledger is now
  hash-chained, so the freshness record is itself tamper-evident (see the
  *Consumption-ledger tampering* row) — but it must be enabled per gate and there
  is still no global nonce/revocation registry. `replay.py` is
  *deterministic/audit* replay, not anti-replay enforcement. Mitigations today:
  enable the consumption ledger, set a short `expires_at`, use the workflow ledger
  for workflow paths, and retain side-store proof packs for strong replay. A
  default-on single-use profile and a global revocation registry are roadmap.
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

Also operator-tunable and off/optional by default: `expires_at` (no global
revocation list) and `policy_timeout` (hang → DENY only when configured). Set both
for a hardened deployment.

## Governed-MCP gateway trust boundary (alpha)

The governed-MCP gateway (`packages/gove-zone/src/gove_zone/adapters/mcp_gateway.py`)
is a transparent stdio proxy that fronts one downstream MCP server and gates its
`tools/call` traffic through the sealed kernel. Its security posture in the alpha
pilot:

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
  reverse LLM channel) is denied in alpha — the runtime
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
