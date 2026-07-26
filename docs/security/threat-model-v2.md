# gove-zone Threat Model v2 — Runtime Governance Security

Status: **alpha / local proof.** This is a threat model, not a certification claim,
a regulator sign-off, or a production-readiness assertion. It documents what the
current code enforces, what it does not, and where an attacker wins today.

- **Scope:** the `gove-zone` runtime governance kernel (`packages/gove-zone`).
- **Branch analyzed:** `feat/governed-vulnclaw-pentest` (see [§9 Divergence](#9-divergence-from-master)).
  This branch does **not** contain `consumption.py` / `ReceiptConsumptionLedger`; the
  replay gap (§3) is live here and closed on `master`. Every "current defense" below is
  cited from the source *in this worktree*, not from `master`.
- **⚠️ Reality-check (2026-07-08, master @ `7799b9a`; partially refreshed by this
  implementation branch).** This document was written against
  the feature branch. A subsequent verification against `master` found that **several of
  these findings are already closed upstream** — including the §6 Critical (adapter
  bypass) and the §1(b)/§6 `ReceiptVerifier` default — and the §7 audit anchor is added
  (though unwired). This branch also implements the specific §2a empty/unknown-source PQL
  compiler fail-closed defense. Read [§9](#9-divergence-from-master) for the full
  per-finding master status **before acting on any item here.** The genuinely
  master-open items are §4(d) authority-at-gate and §2c bundle-id.
- **Supersedes:** the threat table in [`docs/SECURITY_MODEL.md`](../SECURITY_MODEL.md),
  which this document extends, corrects (see §6, §8), and makes machine-checked via the
  adversary suite.
- **Companion suite:** `packages/gove-zone/tests/adversary/` — every gap named here has a
  live reproducing test, and the taxonomy is enforced by `test_coverage_manifest.py`.

## Core governance invariants

The kernel exists to hold these. Each maps to ≥1 adversarial test (§10).

1. **I1 — No valid Decision Receipt, no side effect.** An executor never runs a
   side effect without a receipt that verifies.
2. **I2 — Receipt integrity.** No field (actor, action, args, tenant, boundary,
   policy, authority, decision, expiry, signature metadata) can be altered without
   detection.
3. **I3 — Bind-to-execution.** The receipt authorizes *exactly* this actor, action,
   arguments, tenant, and execution boundary — no substitution.
4. **I4 — Single authorization semantics.** DENY/ESCALATE never execute; a receipt
   authorizes the scope it was issued for and no more.
5. **I5 — MACI role separation.** The proposer can never validate its own authority.
6. **I6 — Tamper-evident audit.** Every decision is anchored in a hash-chained log
   that fails closed on corruption before any side effect.
7. **I7 — Fail-closed evaluation.** A policy error, timeout, or missing evidence
   yields DENY, never a silent allow.

## Trust model & assumptions

- **In scope:** an adversary who controls the *proposing agent* (can craft arbitrary
  tool calls, receipts, and receipt fields) and, for the audit/forgery surfaces, one
  who obtains *local filesystem write access* to the audit log and receipt store.
- **Out of scope (integrator-owned):** actor authentication/IAM, private-key custody,
  key distribution/PKI, WORM/off-host durability of the audit log, and wiring the gate
  in front of every real tool entrypoint. gove-zone provides the membrane; it does not
  manufacture an authenticated identity or a durable sink the architecture lacks.
- **Two postures:** *dev* (unsigned, `require_signature=False`) is local proof only;
  *secure* (signed, `require_signature=True` + a trusted Ed25519 verifier) is the only
  posture that closes the receipt-forgery residual (§1).

---

## Attack surface

Severity uses: **Critical** (default config → unauthorized side effect), **High**
(no integrator misconfiguration required, or silent loss of a core guarantee),
**Medium** (requires an opt-in the integrator can and should set), **Low/Accepted**
(documented limitation with a mitigation).

### 1. Receipt forgery

**Attack scenario.** `receipt_hash` is a keyless SHA-256 over the canonical receipt
dict (`receipt.py:241-245`, `compute_hash` pops only `receipt_hash`/`signature`). An
adversary who can construct a `DecisionReceipt` sets `decision=ALLOW` with any
actor/action/args, calls `compute_hash()` themselves, stamps the result into
`receipt_hash`, and the receipt "verifies" — because in **unsigned mode** verification
only recomputes that same keyless hash (`receipt.py:386-393`).

**Current defense.** Every security-relevant field *is* bound into the hash — actor,
`proposed_action`, `argument_hash`, `tenant_id`, `execution_boundary`, `policy_hash`,
`authority`, `decision`, `expires_at`, and the signature metadata
`signature_algorithm`/`signing_key_id` (anti-downgrade) — so tampering is caught
(`receipt.py:164-199`, `receipt.py:386-393`). The residual (a hash is *recomputable*)
is closed **only when signing is engaged**: Ed25519 signs `receipt_hash` with a private
key and the gate verifies with the matching public key (`signing.py:1-27`,
`receipt.py:418-433`). `execute_with_receipt` / `GovernedExecutor` default to the secure
posture — `require_signature=True` and a hard `ProductionProfileError` if no verifier is
configured (`executor.py:38,63-64`).
Covered: `test_receipt_signing.py::test_forged_recomputed_receipt_rejected_without_private_key`.

**Missing control.** (a) Unsigned mode has *no* adversarial tripwire proving a
recomputed forgery is accepted — the residual is asserted in prose but never tested, so
a regression that made unsigned mode look "secure" would pass silently. (b) See §6:
`ReceiptVerifier` — a first-class public gate surface — defaults `require_signature=False`,
so an integrator who governs through it gets unsigned-by-default with *no*
`ProductionProfileError` signal.

**Recommended implementation.** Add a live gap test that mints an unsigned recomputed
forgery and asserts it executes today (KNOWN_LIMITATION) plus a HELD test that signed
mode rejects it. Align the `ReceiptVerifier` default with `execute_with_receipt`
(`require_signature=True`) or emit the same production guard.

**Test requirement.** `tests/adversary/test_unsigned_forgery.py` — (i)
`test_unsigned_recomputed_forgery_executes_KNOWN_LIMITATION` (OPEN); (ii)
`test_signed_mode_rejects_recomputed_forgery` (HELD); (iii)
`test_receipt_verifier_default_accepts_unsigned_forgery_KNOWN_GAP` (OPEN, the default-posture inconsistency).

**Severity: Medium** (Critical if an operator ships unsigned mode as production, which
the docs forbid).

### 2. Policy bypass

Three distinct bypasses. §2a was historically High because it needed no integrator error;
this implementation closes that specific compiler omission without changing §2b/§2c.

**2a — PQL/GPA compiler silent fail-open (High, implementation-scoped fix).**
*Attack scenario.* A Celonis/Signavio governance feed is empty, mistyped
(`source["type"]` misspelled), or has a renamed `limits`/`insights` key. The upstream
data-quality fault must not silently yield a policy that permits everything.
*Current defense.* `compile_pql_to_ruleset` rejects missing/unknown source types and each
declared Celonis/Signavio source that compiles to zero rules with `IngestionAdapterError`
(`pql_compiler.py:213-226`). When `graph_spec` is explicitly supplied, the graph must
transpile to at least one rule or `TranspilationError` is raised (`pql_compiler.py:228-232`).
Aggregate zero-rule compilation still raises `StaticVerificationError`
(`pql_compiler.py:234-235`) instead of injecting a no-op `gpa.invalid.tool` placeholder.
Valid graph-only compilation remains supported when the graph contributes at least one real
rule.
*Missing control.* The specific empty/unknown-source silent-fail-open is closed by this
implementation. Source authenticity, freshness, and vendor-side data completeness remain
integrator-owned inputs to the compiler.
*Recommended implementation.* Fail closed on missing/unknown source type and zero compiled
governance rules.
*Test requirement.* Covered by
`tests/adversary/test_pql_silent_fail_open.py`.

**2b — RuleSetPolicy allow-by-default as sole policy (Medium).**
*Attack scenario.* A call matching zero rules in a `RuleSetPolicy` bundle (new tool, path
typo, unanticipated arg shape) executes with no deny/escalate considered.
*Current defense.* By design: `RuleSetPolicy` is a deny/escalate-only overlay and falls
through to ALLOW when nothing matches (`policy.py:499-526`, docstring `policy.py:416-423`).
Positive authorization is meant to be composed under a deny-by-default base via
`CompositePolicy` (`policy.py:529-559`).
*Missing control.* Nothing stops `RuleSetPolicy`/`YAMLPolicy` from being *the* terminal
kernel policy in production; the allow-by-default fall-through is untested as an explicit
posture.
*Recommended implementation.* A construction/lint invariant: refuse a bare `RuleSetPolicy`
as the sole policy unless explicitly marked permissive, or warn when the kernel policy is
`ruleset/*` with no `CompositePolicy` base.
*Test requirement.* `tests/adversary/test_ruleset_default_allow.py::test_unmatched_action_falls_through_to_allow_KNOWN_GAP` (OPEN).

**2c — Unpinned policy-hash / policy-bundle-id downgrade (Medium).**
*Attack scenario.* A caller omits `expected_policy_hash` (and/or `expected_policy_bundle_id`)
at the gate; a receipt minted under an older, more permissive policy is accepted.
*Current defense.* Both bind into `receipt_hash` and *are* checked when pinned
(`receipt.py:586-600`), but both default `None` at every gate
(`executor.py:35`, `contracts.py:216-217`) → the check is skipped by default. The hash
path is proven by `tests/adversary/test_policy_version_downgrade.py`. The **bundle-id**
sibling has *no* adversarial test.
*Missing control.* Bundle-id downgrade has no reproducing test; binding is opt-in, not
default.
*Recommended implementation.* Add a bundle-id gap+held pair mirroring the policy-hash test;
consider making pinning mandatory in the secure profile.
*Test requirement.* `tests/adversary/test_policy_bundle_id_downgrade.py::test_unpinned_gate_accepts_swapped_bundle_id_KNOWN_GAP` (OPEN) + `::test_pinned_bundle_id_rejects_swap` (HELD).

### 3. Replay attacks

**Attack scenario.** A single valid ALLOW receipt authorizes unbounded re-execution
across separate gate calls (or an escalation-approval receipt re-runs its side effect N
times).

**Current defense.** Intra-workflow step replay *is* blocked by the per-run step ledger
(`test_workflow_receipt_chain.py::test_replayed_step_rejected_tool_not_called`). But the
standalone gate is stateless: `execute_with_receipt` is `receipt.verify(...)` then
`return tool_fn(**args)` (`executor.py:72-85`) with nothing that consumes or records the
receipt. `replay.py`/`replay_store.py` are deterministic *audit* replay, not anti-replay
enforcement. No `ReceiptConsumptionLedger` is wired on this branch.

**Missing control.** Single-use / nonce enforcement at the standalone gate.

**Recommended implementation.** A `ReceiptConsumptionLedger` keyed on `receipt_hash`,
consumed inside `execute_with_receipt` *before* `tool_fn`, rejecting the second use.
(This is exactly what `master` ships via `consumption.py`.) Mitigations available today:
short `expires_at` (**opt-in** — `expires_at` is unset by default, so expiry does not
bound replay unless the issuer sets it), workflow ledger for workflow paths, side-store
proof packs.

**Test requirement.** `tests/adversary/test_standalone_receipt_replay.py`
(`::test_standalone_receipt_is_replayable_KNOWN_LIMITATION`, OPEN; xfail
`::test_standalone_receipt_replay_should_be_rejected` flips to xpass when the ledger lands).

**Severity: High** on this branch (default gate re-executes); **closed on master**.

### 4. Privilege escalation

**Attack scenario.** (a) A low-privilege actor uses a receipt to authorize a
higher-privilege operation; (b) an actor validates its own authority; (c) a receipt for
actor X is driven by actor Y; (d) an authority grant (`read-grant` vs `admin-grant`) is
not enforced.

**Current defense.** The *enforced privilege unit* — `proposed_action` (`receipt.py:514`,
check 7) + `argument_hash` (`receipt.py:577-584`, check 10b) + caller-anchored
`expected_actor` (`receipt.py:443-452`, check 2b) — is hash-bound and gate-checked, and
`expected_actor` is **required** by all three gate surfaces (`executor.py:59-62,113-116,146-150`;
`contracts.py:221-224`), so the strong self-validation/cross-actor check is the default,
never silently downgraded to the weak `validator_id==actor` fallback (`receipt.py:454-468`,
2c). Issuance also refuses `validator==proposer` (`receipt.py:283-287`). So (a) action
escalation, (b) self-validation, and (c) cross-actor reuse are **defended and tested**
(`test_maci_role_separation.py`, `test_escalation_resume.py::test_resume_anchors_expected_actor_to_proposer`).

**Missing control (d).** `authority` and `validator_role` are hash-bound (so tampering is
caught) and checkable via `receipt.verify(expected_authority=…, expected_validator_role=…)`
(`receipt.py:602-613`, checks 12b/12c) — but **no gate surface plumbs them**:
`execute_with_receipt` (`executor.py:25-85`), `GovernedExecutor.execute`
(`executor.py:127-168`), and `resume_with_receipt` (`escalation.py`) neither accept nor
forward `expected_authority`/`expected_validator_role`. Any deployment that treats
`authority` as a privilege boundary cannot enforce it at the gate; a correctly
tenant/boundary/actor/action-bound receipt for the *wrong* authority scope passes.

**Recommended implementation.** Add `expected_authority`/`expected_validator_role`
parameters to `execute_with_receipt`, `GovernedExecutor.execute`, and `resume_with_receipt`,
threaded to `receipt.verify()`; optionally a trusted-validator allowlist in the secure
profile so any `validator_id != actor` is not sufficient on its own.

**Test requirement.** `tests/adversary/test_authority_scope_unenforced.py::test_gate_ignores_authority_grant_KNOWN_GAP` (OPEN; existing `test_maci_role_separation.py` exercises `verify()` directly, never the gate).

**Severity: Medium** (latent — not independently exploitable while action binding holds,
but a real escalation vector for authority-scoped deployments).

### 5. Tenant isolation failure

**Attack scenario.** A receipt bound to tenant A / boundary B authorizes an action for
tenant A′ / boundary B′; or one tenant loads another tenant's policy bundle.

**Current defense.** `tenant_id` and `execution_boundary` are hash-bound
(`receipt.py:126,130`) and checked by default at every real gate — both are non-optional
kwargs of `execute_with_receipt` (`executor.py:30-31`) and enforced in `verify`
(`receipt.py:497-511`, checks 5/6). `evaluate_tenant_action` fails closed on tenant
mismatch and blocks cross-tenant bundle loads with `PermissionError`
(`tenant.py:82-90,134-141`). Defended: `test_tenant_safety.py::test_tenant_a_receipt_cannot_authorize_tenant_b_action`, `::test_tenant_a_cannot_load_tenant_b_bundle`.

**Missing control.** None on `tenant_id`/`execution_boundary` (both enforced + tested).
The one tenant-scoped-but-unenforced field is `authority` — same root cause as §4(d),
tracked there. Recommend a HELD adversarial tripwire in the adversary suite so a
regression that dropped either check is caught there too.

**Recommended implementation.** Keep both checks mandatory (they are); add the HELD
adversary test below.

**Test requirement.** `tests/adversary/test_tenant_boundary_isolation.py::test_cross_tenant_and_cross_boundary_both_blocked_HELD` (HELD).

**Severity: Low/Accepted** (defended); authority-scope portion is Medium under §4.

### 6. Adapter / executor bypass

**Attack scenario.** A pentest/adversary agent is stood up the natural, documented way —
`agent = ManagedAgent("vulnclaw")`, then `govern_autogen_tool(agent, "shell", run)` or
`govern_langgraph_tools(tools, agent)`. Every tool call the LLM emits then executes
**unconditionally**: the default policy is `AllowAllPolicy` (ALLOW for everything), the
actor is self-asserted, nothing is signed, and **no receipt is verified**. The word
"govern" in the adapter name is unearned by default.

**Current defense (none on this path).** There are **two disjoint gates**. The
cryptographic gate `execute_with_receipt` (`executor.py:25-85`; `require_signature=True`
default, `expected_actor` required, verifies a receipt before `tool_fn(**args)`) is called
only by `cli.py`/`workflow.py`/`escalation.py`. The framework adapters bind to the
*weaker* `Kernel.dispatch` (`kernel.py:94-165`): `policy.evaluate` → `tool_fn(**args_dict)`
with `actor=self.actor` self-asserted (`kernel.py:130,154`), no signature concept, no
receipt verification. `ManagedAgent.__init__` sets `self.policy = policy or AllowAllPolicy()`
(`agent.py:38`) and `dispatch` → `self._kernel.dispatch(...)` (`agent.py:100`);
`govern_autogen_tool` wires straight into it (`autogen.py:27,38`), as does
`GovernedTool._run` for LangGraph (`langgraph.py:46,52`). At the time of analysis, no
**test module** on the feature branch exercised the framework adapters through their
dispatcher (`test_adapter_bypass.py` in this suite is the first), so the adapter path was
wiring-**unproven**. (Closed on `master`: `test_framework_adapters.py` exercises the
adapters and `ManagedAgent` requires an explicit `policy` — see §9.)

Note the honest non-threats: `integration.py` (`emit_receipt_for_hook`) is a passive
auditor that never calls `tool_fn`; `evaluation.py`/`benchmark_adapters.py` only call
`policy.evaluate` (pure prediction); `api.py /actions/test` is dry-run only.

**Missing control.** (a) `ManagedAgent` should not default to `AllowAllPolicy`; (b) the
adapter surface exposes no signed/verified-receipt option and self-asserts the actor;
(c) no dispatcher-level test walks entry→adapter→side-effect. This class is absent from
the pre-existing 8-class manifest — `signature-stripping` only covers `execute_with_receipt`
refusing unsigned-when-required, which this path never reaches.

**Recommended implementation.** Drop the `AllowAllPolicy` default (require an explicit
policy or fail closed); route adapter execution through `execute_with_receipt`/
`GovernedExecutor`, or make `Kernel` actor caller-supplied and refuse self-assertion; add a
CI grep-guard that fails when an `adapters/*.py` symbol has no inbound test reference
(per `~/.claude/rules/review-handler-wiring.md`).

**Test requirement.** `tests/adversary/test_adapter_bypass.py` —
`::test_managed_agent_default_policy_executes_untrusted_tool_KNOWN_LIMITATION` (OPEN, the
default allow-all bypass) and `::test_adapter_routes_through_gate_when_policy_denies_HELD`
(HELD, the intended gate fires once a real `DenyAllPolicy` is set).

**Severity: Critical** (default-configured "governed" agent executes every tool with no
cryptographic authorization).

### 7. Audit manipulation

**Attack scenario.** An adversary with filesystem write access to the audit JSONL rewrites
the **entire** chain self-consistently — deletes or alters an event and recomputes every
downstream `event_hash`/`previous_hash` from genesis — or truncates the tail and
regenerates a shorter valid chain.

**Current defense.** `verify_chain()` recomputes every `event_hash` and checks
`previous_hash` linkage (`audit.py:210-258`); tail corruption fails closed *before* append
(`audit.py:112-162`, `_read_last_hash_from_disk`; `test_audit_chain_corruption.py`).
Existing tamper tests catch single-field edits
(`test_audit_chain.py::test_chain_detects_tampered_event_hash`, `::test_chain_detects_tampered_previous_hash`).

**Missing control.** The chain is keyless and self-referential — there is **no signature
or external anchor over the chain head**. A *fully self-consistent* rewrite recomputes all
hashes and passes `verify_chain()["valid"] == True`; a truncate-then-regenerate is
indistinguishable from a legitimately short chain. The existing tests only cover
non-recomputed single-line edits, which is *not* the real threat. Tamper-evidence holds
only relative to an independently held copy of the trusted head.

**Recommended implementation.** Periodically sign/notarize `last_hash` outside the store
(external anchor) and compare against a trusted checkpoint at `verify_chain()` call sites;
for durability, a WORM/append-only sink. These are integrator/deployment concerns but the
kernel should surface the checkpoint hook.

**Test requirement.** `tests/adversary/test_audit_full_chain_rewrite.py::test_verify_chain_accepts_self_consistent_full_rewrite_KNOWN_GAP` (OPEN) + `::test_single_field_edit_still_detected_HELD` (HELD).

**Severity: High** (silent, complete audit rewrite with local write access) — an accepted
architectural limitation of a local keyless chain, made explicit rather than hidden.

---

## 8. Corrections to `docs/SECURITY_MODEL.md`

Verified against source in this worktree:

- **Signing default.** `SECURITY_MODEL.md:37-43` states `require_signature` "defaults to
  `False` (`executor.py`, `contracts.py`)." This is **wrong for `executor.py`**:
  `execute_with_receipt` and `GovernedExecutor` default `require_signature=True`
  (`executor.py:38,111`) and raise `ProductionProfileError` without a verifier
  (`executor.py:63-64`). It is correct only for `contracts.py`: `ReceiptVerifier` defaults
  `require_signature=False` (`contracts.py:219`). The two public gate surfaces ship
  **opposite** default postures — a genuine inconsistency (see §1/§6), not a uniform
  "default False."
- **Anti-replay.** `SECURITY_MODEL.md:44-50` correctly states there is no anti-replay
  nonce on this branch. `master` closes this via `consumption.py` (§9).

---

## 9. Divergence from master

This branch (`feat/governed-vulnclaw-pentest`) is ~24 commits ahead of and ~146–196
behind `master`. **Verified against `master` @ `7799b9a` on 2026-07-08** — most findings are
already closed upstream:

| § | Finding | Master status | Master mechanism (file:line @ 7799b9a) |
|---|---|---|---|
| 6 | **Adapter bypass (Critical)** | **CLOSED** | `ManagedAgent.__init__` requires an explicit `policy: Policy` — no `AllowAllPolicy` default (`agent.py:32,39-41`); + B13 `authz_enforce`/`principal_registry` fail-closed principal authz (`kernel.py:70,83-86`); + a dispatcher-level `test_framework_adapters.py`; + a fail-closed negative test (`test_managed_agent.py`, `pytest.raises(TypeError)` on no-policy). Residual (by design, not the Critical): adapters use `Kernel.dispatch` (local unsigned primitive), not `execute_with_receipt` — self-asserted actor unless `authz_enforce=True` is opted in. |
| 1/6 | **`ReceiptVerifier` default `require_signature=False`** | **CLOSED** | `ReceiptVerifier` now defaults `require_signature=True` and raises without a verifier (`contracts.py:235,278`) — consistent with `execute_with_receipt`. The §8 doc-vs-code inconsistency is gone. |
| 2a | **PQL empty/unknown-source fail-open** | **BRANCH FIX** | this implementation rejects missing/unknown source type, per-source zero-rule results, explicit empty graph results, and aggregate zero-rule compilation; merge/CI status is outside this document. |
| 3 | **Standalone replay** | **CLOSED** | `master` ships `consumption.py` / `ReceiptConsumptionLedger` (single-use at the standalone gate); this branch has it only as a stale `.pyc`. |
| 7 | **Audit full-rewrite** | **PARTIAL** | `verify_chain(expected_count, expected_last_hash)` external-anchor hook added (`audit.py`), but **no shipped call site passes an anchor**, so every production path is still keyless — a self-consistent rewrite still verifies. |
| 4d | **Authority not gate-enforced** | **OPEN** | `expected_authority`/`expected_validator_role` are still not threaded through `execute_with_receipt`/`GovernedExecutor.execute`/`resume_with_receipt` (`executor.py:37,40` exposes only `expected_policy_bundle_id`/`require_signature`). |
| 2c | **Bundle-id unpinned** | **OPEN (Low)** | `expected_policy_bundle_id` defaults `None`; no auto-binding analog to `policy_hash`. |
| 2b | **RuleSetPolicy allow-by-default** | **OPEN by design** | documented deny/escalate-list architecture; not a bug. |

**Net still-open on master:** §4d authority-at-gate (Medium), §2c bundle-id (Low), §7
audit-anchor-unwired (Medium, architectural). The adversary tests are written to *flip*
(xfail→xpass, or a KNOWN_GAP assertion inverts) when a defense lands, so they are the
mechanical signal for "gap closed" — but a port to master must **drop/adapt** the
master-closed cases (`ReceiptVerifier`-default forgery) and branch-fixed cases (§2a PQL
empty/unknown-source fail-open) to avoid dead tests.

---

## 10. Invariant → adversarial-test coverage matrix

Success criterion: **every governance invariant has ≥1 adversarial test.** ✔ = a live test
in `packages/gove-zone/tests/` (existing) or `tests/adversary/` (this work).

| Invariant | Surface(s) | Adversarial test(s) | Status |
|---|---|---|---|
| I1 No receipt → no side effect | forgery, adapter, evidence | `test_executor_guard.py::test_executor_refuses_no_receipt`; `test_kernel_dispatch.py::test_every_dispatch_anchors_in_audit_chain`; **`test_adapter_bypass.py`** | DEFENDED at gate; **adapter path OPEN** |
| I2 Receipt integrity | forgery, tenant, policy | `test_receipt_signing.py::test_forged_recomputed_receipt_rejected_without_private_key`; **`test_unsigned_forgery.py`** | signed DEFENDED; unsigned residual pinned |
| I3 Bind-to-execution | forgery, policy, privesc | `test_argument_binding.py`; `test_tenant_safety.py`; `test_policy_version_downgrade.py`; **`test_policy_bundle_id_downgrade.py`**, **`test_authority_scope_unenforced.py`** | action/args/tenant DEFENDED; authority + bundle-id OPEN |
| I4 Single-authorization | replay, policy | `test_standalone_receipt_replay.py`; `test_workflow_receipt_chain.py::test_replayed_step_rejected_tool_not_called` | intra-workflow DEFENDED; standalone OPEN |
| I5 MACI role separation | privesc | `test_maci_role_separation.py::test_issuance_refuses_self_validation`, `::test_gate_refuses_forged_self_validated_receipt` | DEFENDED |
| I6 Tamper-evident audit | audit | `test_audit_chain.py` (single-field); **`test_audit_full_chain_rewrite.py`** | single-edit DEFENDED; full-rewrite OPEN |
| I7 Fail-closed evaluation | policy | `test_fail_closed.py`, `test_fail_closed_gaps.py`; **`test_ruleset_default_allow.py`**, **`test_pql_silent_fail_open.py`** | exception/timeout DEFENDED; PQL empty/unknown-source fail-open branch-fixed; bare `RuleSetPolicy` allow-by-default remains §2b |

Every invariant has ≥1 adversarial test. Every OPEN gap above has a live reproducing test
(a KNOWN_GAP/KNOWN_LIMITATION assertion of current reality) so it cannot be silently
claimed as defended, and the taxonomy is enforced by
`tests/adversary/test_coverage_manifest.py`.

## 11. Prioritized remediation

1. **Adapter bypass (§6, Critical).** Remove `AllowAllPolicy` default; route adapters
   through the cryptographic gate. Highest-leverage: it makes the default "governed" agent
   actually governed.
2. **Replay (§3, High here).** Land / rebase the `ReceiptConsumptionLedger`.
3. **Audit anchoring (§7, High).** External head anchor + checkpoint compare.
4. **Authority at the gate (§4d, Medium).** Plumb `expected_authority`/`expected_validator_role`.
5. **Gate default parity (§1/§6, Medium).** Align `ReceiptVerifier` with the secure default.
6. **Bundle-id + ruleset foot-guns (§2b/§2c, Medium).** Tests landed; add lint/pin defaults.
