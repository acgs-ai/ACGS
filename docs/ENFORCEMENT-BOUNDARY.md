# Enforcement boundary

| | |
|---|---|
| **Status** | Alpha. Not a certification, audit result, or assurance claim. |
| **Evidence ref** | `origin/master` @ `4459d849`, plus branch commits `fc6b39c1` (11-class manifest) and `91c7cb0e` (posture↔evidence checks). Verified 2026-07-28 ([audit/phase0-baseline.md](./audit/phase0-baseline.md)). |
| **Speech permission** | Governed by [claims-map.md](./claims-map.md) |
| **Scope discipline** | Every claim below is scoped per [repository-scope-rule.md](./repository-scope-rule.md) |

> **Corrected after adversarial verification.** An earlier revision of this document
> contained false statements — it denied the existence of an audit-anchor sink and of a
> static gate-wiring check, and it described a hash-coverage gap without the validation
> that closes it. Those are recorded, with counterexamples, in
> [audit/ws-a-verification-findings.md](./audit/ws-a-verification-findings.md) (F-2, F-3,
> F-8). This revision is the corrected one. The findings file is not superseded by it.

This document states where ACGS's enforcement begins and ends. It is written to be
useful to a security reviewer who needs to decide what to trust, so it leads with
what ACGS **cannot** do.

The canonical statement is scoped, and the scope is the whole point:

> For every execution path wired through ACGS: **No valid Decision Receipt, no side effect.**

"Wired through ACGS" is load-bearing. §2 says exactly what it excludes.

Unless a row says otherwise, every statement here is scoped to
**`packages/gove-zone/` at the refs above**, not to the repository as a whole. That
distinction is not pedantry: three of the false statements in the previous revision were
true of `gove-zone` and false of the repository.

---

## 1. What the kernel enforces

For a call that reaches the gate, admission is fail-closed. Ambiguity resolves to deny.

| Enforced | Mechanism | Evidence |
|---|---|---|
| No receipt → no execution | `execute_with_receipt` refuses before invoking `tool_fn` | `executor.py:32`; `test_executor_guard.py::test_executor_refuses_no_receipt` |
| Tampered receipt → no execution | `receipt_hash` is recomputed and compared. The hashed payload is **hand-enumerated** (`_hash_payload`), not "all fields" — see the note below. | `receipt.py:332-377`; `test_executor_guard.py::test_executor_refuses_tampered_receipt` |
| Signature required by default | `require_signature` defaults `True` at all three gate surfaces, and an unrecognized `$GOVE_ZONE_PROFILE` falls back to production rather than downgrading. | `executor.py:50`, `:291`; `contracts.py:272`; `profile.py:230-241` |
| Binding to the exact call | actor, action, canonical arguments, tenant, and execution boundary are required anchors. Four further anchors — `expected_policy_hash`, `expected_project_id`, `expected_environment_id`, `expected_authority` — default to `None` and are checked **only when the caller supplies them**. | `executor.py:32-58`; `test_argument_binding.py`, `test_tenant_safety.py` |
| Expiry | **v2 receipts always require `expires_at`** — the check is `(require_expiry or is_v2)`, so the flag cannot switch it off for v2. For **v1**, `require_expiry` defaults `False`, so a v1 receipt minted with an empty `expires_at` authorizes indefinitely unless the caller opts in. | `receipt.py:1072-1078` (enforcement), `:1102-1110` (liveness window); `executor.py:51`, `:292`, `contracts.py:273` (defaults) |
| Policy failure → deny | An exception in policy evaluation synthesizes DENY and is audited | `test_fail_closed.py` |
| Audit-write failure → deny | Append failure raises before execution | `test_fail_closed.py`, `test_audit_chain_corruption.py` |
| Self-validation refused | Proposer may not validate its own proposal | `receipt.py:414-418`; `test_maci_role_separation.py::test_issuance_refuses_self_validation` |
| Unregistered tool → deny | Unknown tools raise before any audit append | `test_kernel_dispatch.py:84`; `test_universal_gateway.py:162` |
| Direct call to a sealed tool → detected and audited | `SealedTool.__call__` raises `BypassAttemptError` | `gateway.py:118`, `:148`; `test_universal_gateway.py:253` |

### 1.1 What `receipt_hash` covers, precisely

`compute_hash()` hashes `_hash_payload()`, a hand-enumerated dict — **not** a generic
serialization of the dataclass. Four fields (`receipt_schema_version`, `project_id`,
`environment_id`, `trust_epoch`) are included **only when `receipt_schema_version` is
truthy**, i.e. on v2 receipts.

This is not an escalation vector, and the reason is a validation invariant rather than the
hash itself:

- `from_dict` rejects a v1 dict that carries any of the three v2-only fields
  (`receipt.py:250-256`).
- `verify` rejects a v1 receipt holding non-empty values for them (`:677-681`).
- The executor gate reaches that check — `executor.py:208` calls `receipt.verify(...)` — so
  the invariant sits on the enforcement path, not merely on the class.

A v1 receipt is therefore pinned to empty values for all four. Cross-schema mutation is
caught separately: adding or stripping those fields changes the payload's key set, so the
recomputed hash no longer matches the stored `receipt_hash`.

The durable risk is **drift**, not the current field set: a field added to the dataclass is
unbound until someone also adds it to `_hash_payload`, and the golden-vector test would not
notice. Three guards pin this — the v1 key set, the v2 key set, and the downgrade case
(`test_trust_receipt_v2.py`, added in `91c7cb0e`). The drift guard was exercised against an
injected unbound field and fails as intended.

### 1.2 Controls that exist but are not on by default

| Control | Default | Where it *is* mandatory |
|---|---|---|
| Single-use receipts | `consumption_ledger=None` (`executor.py:56`, `:297`, `:354`) | `GovernanceProfile.production_strict` takes it as a **required** keyword; `None` raises `ProductionProfileError` (`profile.py:134-141`, `:62-67`) |
| Liveness / TTL on v1 | `require_expiry=False` | `production_strict` sets `require_expiry=True`; v2 receipts require expiry unconditionally |
| Principal authorization | `authz_enforce=False` (`kernel.py:94-95`) | Fail-closed once paired with a registry (`:107-108`) |
| Policy watchdog timeout | none | Carried by `production_strict`, but it is a **separate wiring seam the caller must connect at kernel construction** — selecting the profile alone leaves it inert (`profile.py:150-174`) |

**A production posture must therefore be selected, not assumed.** `production()` requires a
signature and nothing else; `production_strict()` is the hardened posture. Two of its three
controls activate on selection at the gate; the watchdog does not.

### 1.3 The configuration surface, and where it is not observable

| Setting | Default | Insecure value reachable how | Observable at runtime? |
|---|---|---|---|
| `require_signature` | `True` | `GovernanceProfile.dev()`, or `$GOVE_ZONE_PROFILE=dev` | **No** — no warning, log line, or receipt field records that the unsigned profile was selected |
| `require_expiry` | `False` (v1) | default | No |
| `consumption_ledger` | `None` | default | No |
| `authz_enforce` | `False` | default | No |
| `$GOVE_ZONE_PROFILE` | unset → production | `dev` | Selection itself is explicit; the *consequence* is not surfaced |

Two properties hold. Every insecure mode is **explicit** — it must be selected by a caller
or an operator, never reached by omission — and an unrecognized `$GOVE_ZONE_PROFILE` value
resolves to production rather than downgrading (`profile.py:235-241`).

One does not: **no insecure mode is observable at runtime.** Nothing warns on startup, and
no receipt field records the posture that admitted it, so an unsigned deployment is not
distinguishable from a signed one by inspecting its output. Closing that is WS-B2's
`signature_mode` field plus a startup warning; it is not closed today.

## 2. What the kernel cannot enforce

**An in-process library cannot prevent code in the same process from bypassing it.**
This is a placement fact, not a defect, and no amount of library hardening changes it.

A reference monitor (Anderson, 1972) is sound only with *complete mediation*,
*tamper-proofness*, and *verifiability*. ACGS running in-process has **verifiability**
and, for mediated calls, fail-closed admission. It does **not** have complete mediation
over its host process, and it is not tamper-proof against that process.

Concretely, none of the following is prevented in Mode 1:

- An agent tool body that calls `requests.post` directly, never touching a registered tool.
- An agent holding a shell or interpreter tool that authors its own side-effect code.
- Any code in the process reading the signing key from memory or disk.
- An integrator who simply forgets to route a new effect path through the gate.

**A static wiring check does exist for the last case, and it is CI-enforced** —
`packages/gove-zone/tests/test_gate_wiring_matrix.py`, run by `saas-beta-required.yml:202`.
Its limits, not its absence, are the gap: it asserts that a gate entrypoint is *imported and
called* somewhere in the module (`:170-173`), which is weaker than proving the side effect
is mediated, and it runs only over the examples `docs/INTEGRATION_MATRIX.md` claims as
shipped. Nothing checks integrator code, and nothing fails when a new ungoverned effect path
is added outside that set. All 32 workflows under `.github/workflows/` were swept.

The library's own outbound-effect surface is deliberately narrow — `sandbox.py` (subprocess)
and `gateway.py` (urllib) are the only modules importing network or process primitives. Two
others import `shutil`: `setup.py:106` and `sandbox.py:86` for `shutil.which` (a read), and
`cli.py:501` for `shutil.rmtree`, which is a real destructive filesystem call in the CLI's
own build path. None of this constrains the agent — only ACGS.

## 3. Trust preconditions

Each of these is assumed. When one is violated, the stated guarantee degrades as described.

### 3.1 Correct integration wiring
**Assumed:** every side-effecting path is registered and dispatched through the gate.
**When violated:** the unwired path is simply ungoverned. There is no receipt, no audit
record, and no error — the effect happens and ACGS never observes it. Detection today rests
on `test_gate_wiring_matrix.py::test_shipped_example_routes_through_gate`, whose scope and
assertion strength are described in §2.

### 3.2 Host integrity
**Assumed:** process memory, filesystem, and clock are not attacker-controlled.
**When violated:** signing keys are readable, so receipts can be minted at will; the audit
file can be rewritten; and expiry checks can be defeated by moving the clock, since expiry is
evaluated against the host clock with a configurable skew bound (`max_clock_skew_seconds`,
`executor.py:55`; evaluated at `receipt.py:1102-1110`). A self-consistent full rewrite of the
audit chain passes a keyless `verify_chain()` — see §3.4.

### 3.3 Authenticity of caller-supplied identity context
**Assumed:** the `expected_actor` and principal context handed to the gate are authentic.
**When violated:** actor binding degrades to a string comparison against an attacker-chosen
value. ACGS checks that the receipt's actor matches what the runtime supplied; it does not
establish who that actor is. Role separation inherits this: no validator↔key binding exists
(`validator_id` has zero occurrences in `trust.py`, `authz.py`, `identity.py`, `verifier.py`),
so a holder of the deployment's active signing key can mint a receipt naming any `validator_id`.

### 3.4 An external audit anchor, if truncation detection is required
**Assumed:** the operator persists the chain head where the audit writer cannot rewrite it.
**When violated:** in-chain edits, reorders, and malformed tails are still detected, but
**truncation and full rewrite are not.** `verify_chain(expected_count, expected_last_hash)`
implements the check (`audit.py:308-341`), and this is keyless by design, with the anchor as
an operator duty.

**Scope, corrected:** no call site *inside `packages/gove-zone/src/`* supplies either
argument across its seven call sites, so the **library's own default posture is keyless**.
That is not true of the repository. `packages/acgs-control-plane` implements a full anchor
discipline against gove-zone's own store: `Organization.audit_anchor_count` /
`audit_anchor_hash` (`models.py:57-58`) are updated inside the same transaction as each
persisted receipt under `SELECT … FOR UPDATE` (`governance.py:756-758`), read back for
verification at `app.py:1731` and `:1792`, migration-managed since `0001_legacy_v0.py:31`,
and re-checked at `migration_recovery.py:738`, `:989`, `:1131`.

So the anchor is an exercised operator duty with a shipped reference implementation — it is
simply not one the library performs for you. `test_audit_chain_corruption.py:155` asserts
both directions: keyless verify returns valid on a truncated prefix; anchored verify returns
`length_mismatch` and `last_hash_mismatch`. The residual that no anchor closes — a
self-consistent full rewrite under a keyless verify — is pinned as an explicit `xfail` at
`test_mutation_suite.py:438`.

## 4. Deployment modes

### Mode 1 — in-process library (**development only**)

The kernel runs inside the proposer's process.

**Properties:** evidence generation; fail-closed admission for wired paths; tamper-evident
audit chain (with §3.4's caveat).
**Non-properties:** bypass resistance against a compromised host or an exec-capable agent;
complete mediation.

Sandboxing does not close this gap in the default configuration. `LocalProcessSandbox` uses
`bwrap` whenever it is present (`sandbox.py:86`), but when `bwrap` is absent and
`require_bwrap` is unset it degrades to an ordinary subprocess that the docstring states does
**not** restrict network or filesystem, behind a `UserWarning` (`sandbox.py:87-98`).
`require_bwrap` controls whether that absence is a hard failure — it does not control whether
`bwrap` is used. Containment is therefore real only with `bwrap` installed, and guaranteed
only with `require_bwrap=True`. There is no test exercising the degraded path.

### Mode 2 — reference enforcement topology (**not yet shipped**)

Specified in WS-C; **no `deploy/` directory exists at `4459d849`**. Every Mode 2 property
below is a design target, not an implemented or tested result, and must not be claimed until
UC-C is met.

Intended shape: the agent runs with no ambient credentials on an internal-only network whose
sole reachable service is a broker in a separate trust domain. The broker holds all
side-effect credentials, requires a signed receipt (no unsigned mode), and checks expiry
against its own clock, single-use consumption against its own ledger, and args-hash against
the submitted action. Bypassing governance then means escaping a sandbox and a network policy,
rather than skipping a function call.

## 5. Adversary coverage matrix

Rows are the machine-checked classes in
`packages/gove-zone/tests/adversary/test_coverage_manifest.py` **as of `91c7cb0e`** — not at
`4459d849`, where the manifest has eight classes and a `status` field that can only say
`DEFENDED`. That manifest is the source of truth; this table must not diverge from it.

**Read the `adaptive` column, not `status` alone.** Until 2026-07-28 `status` was
`Literal["DEFENDED"]` and could not express anything else, so any historical claim resting on
it is uninformative by construction.

The manifest vocabulary is `DEFENDED / PARTIAL / BYPASSABLE / UNKNOWN`. This table uses those
words verbatim rather than paraphrases like "out of scope", which collapses `BYPASSABLE`
(defeated, with evidence) and `UNKNOWN` (no evidence either way) — the two states the
widened schema exists to distinguish.

| Adversary class | `status` (Mode 1) | `adaptive` | Notes |
|---|---|---|---|
| forged-authorization | DEFENDED | BYPASSABLE | Signature required by default; adaptive harness still finds a variant |
| replayed-authorization | DEFENDED | BYPASSABLE | Requires a consumption ledger — opt-in at the gate, mandatory under `production_strict` |
| ledger-tampering | DEFENDED | BYPASSABLE | In-chain mutation only; see compromised-host |
| policy-downgrade | DEFENDED | BYPASSABLE | Adaptively bypassable |
| tenant-crossover | DEFENDED | STABLE | |
| signature-stripping | DEFENDED | STABLE | |
| validator-bypass | DEFENDED | BYPASSABLE | Defended by string comparison only; no validator↔key binding exists (§3.3) |
| evidence-omission | DEFENDED | STABLE | |
| negligent-integrator | **PARTIAL** | UNTESTED | Wiring check is CI-enforced but asserts `imported & called` over shipped examples only (§2) |
| compromised-host | **BYPASSABLE** | UNTESTED | Keyless verify accepts a self-consistent rewrite (`xfail` at `test_mutation_suite.py:438`). Mode 2 does not close it — it moves the trust boundary, it does not remove the host |
| exec-capable-agent | **UNKNOWN** | UNTESTED | No test models it in either direction; closing it is the point of Mode 2 |

Five of the eight baseline classes are `adaptive: BYPASSABLE`. An earlier revision of this
table flagged that qualifier on two of them while flagging all three STABLE classes — an
asymmetry that read favorably, seven lines after instructing the reader to read that column.

**Mode 2 is deliberately absent from this table.** The manifest models one deployment. A
projected Mode 2 column inside a table framed as machine-checked would present eleven
unmeasured cells as evidence.

The last three classes concern where the gate *sits* rather than what it checks. None can
reach `DEFENDED` from library code alone.

---

## Related

- [repository-scope-rule.md](./repository-scope-rule.md) — the scoping rule every claim here follows.
- [claims-map.md](./claims-map.md) — what may be said about the above, and with which caveat.
- [CLAIMS.md](./CLAIMS.md) — the claim ledger with per-claim evidence.
- [SECURITY.md](../SECURITY.md) — reporting and current threat-model scope.
- [audit/phase0-baseline.md](./audit/phase0-baseline.md) — the survey these findings come from.
- [audit/ws-a-verification-findings.md](./audit/ws-a-verification-findings.md) — what this document got wrong, and how it was caught.
