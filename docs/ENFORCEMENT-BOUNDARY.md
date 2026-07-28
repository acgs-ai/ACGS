# Enforcement boundary

| | |
|---|---|
| **Status** | Alpha. Not a certification, audit result, or assurance claim. |
| **Evidence ref** | `origin/master` @ `4459d849`, verified 2026-07-28 ([audit/phase0-baseline.md](./audit/phase0-baseline.md)) |
| **Speech permission** | Governed by [claims-map.md](./claims-map.md) |

> **PROVISIONAL — do not cite outward.** An adversarial verification pass found several
> false and unscoped statements in this document. Only the §1 table has been corrected.
> Read [audit/ws-a-verification-findings.md](./audit/ws-a-verification-findings.md) first;
> in particular §3.4 and §2 overstate the absence of an audit anchor and of a static
> gate-wiring check, and the §5 matrix applies its adaptive qualifier asymmetrically.

This document states where ACGS's enforcement begins and ends. It is written to be
useful to a security reviewer who needs to decide what to trust, so it leads with
what ACGS **cannot** do.

The canonical statement is scoped, and the scope is the whole point:

> For every execution path wired through ACGS: **No valid Decision Receipt, no side effect.**

"Wired through ACGS" is load-bearing. §2 says exactly what it excludes.

---

## 1. What the kernel enforces

For a call that reaches the gate, admission is fail-closed. Ambiguity resolves to deny.

| Enforced | Mechanism | Evidence |
|---|---|---|
| No receipt → no execution | `execute_with_receipt` refuses before invoking `tool_fn` | `executor.py:32`; `test_executor_guard.py::test_executor_refuses_no_receipt` |
| Tampered receipt → no execution | `receipt_hash` is recomputed and compared. **The hashed payload is hand-enumerated (`_hash_payload`), not "all fields":** `receipt_schema_version`, `project_id`, `environment_id`, and `trust_epoch` are included **only when `receipt_schema_version` is truthy**, so on a default v1 receipt those four are **not** hash-bound. | `receipt.py:332-377`; `test_executor_guard.py::test_executor_refuses_tampered_receipt` |
| Signature required by default | `require_signature` defaults `True` at all three gate surfaces. **Opt-out exists:** the `dev` profile is "explicitly unsigned (`require_signature=False`)" and is selected by `$GOVE_ZONE_PROFILE`; production is the default when unset. | `executor.py:50`, `executor.py:291`, `contracts.py:272`; `profile.py:18`, `:27-28` |
| Binding to the exact call | actor, action, canonical arguments, tenant, and execution boundary are required anchors. **`expected_policy_hash`, `expected_project_id`, `expected_environment_id`, and `expected_authority` default to `None`** and are checked only when the caller supplies them. | `executor.py:32-58`; `test_argument_binding.py`, `test_tenant_safety.py` |
| Expiry | Checked when present — but **`require_expiry` defaults `False`** (`executor.py:51`, `:292`, `contracts.py:273`), so a v1 receipt minted with an empty `expires_at` authorizes indefinitely. | `receipt.py:1069-1096` |
| Policy failure → deny | An exception in policy evaluation synthesizes DENY and is audited | `test_fail_closed.py` |
| Audit-write failure → deny | Append failure raises before execution | `test_fail_closed.py`, `test_audit_chain_corruption.py` |
| Self-validation refused | Proposer may not validate its own proposal | `receipt.py:414-418`; `test_maci_role_separation.py::test_issuance_refuses_self_validation` |
| Unregistered tool → deny | Unknown tools raise before any audit append | `test_kernel_dispatch.py:84`; `test_universal_gateway.py:162` |
| Direct call to a sealed tool → detected and audited | `SealedTool.__call__` raises `BypassAttemptError` | `gateway.py:118`, `gateway.py:148`; `test_universal_gateway.py:253` |

Two controls exist but are **opt-in**, and are therefore not part of the default posture:

- **Single-use receipts.** A `consumption_ledger` must be supplied; the parameter defaults to `None` (`executor.py:56`, `:297`, `:354`).
- **Principal authorization.** `authz_enforce` defaults `False` (`kernel.py:94-95`), fail-closed when paired with a registry (`:107-108`).

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

Nothing in the repository detects the last case: there is **no static scan and no CI job**
that fails when an ungoverned effect path is added. All 33 workflows were swept.

The library's own effect surface is deliberately narrow — only `sandbox.py` (subprocess) and
`gateway.py` (urllib) import effect primitives — but that constrains ACGS, not the agent.

## 3. Trust preconditions

Each of these is assumed. When one is violated, the stated guarantee degrades as described.

### 3.1 Correct integration wiring
**Assumed:** every side-effecting path is registered and dispatched through the gate.
**When violated:** the unwired path is simply ungoverned. There is no receipt, no audit
record, and no error — the effect happens and ACGS never observes it. Detection today rests
on `test_gate_wiring_matrix.py::test_shipped_example_routes_through_gate`, which covers
shipped examples only, not integrator code.

### 3.2 Host integrity
**Assumed:** process memory, filesystem, and clock are not attacker-controlled.
**When violated:** signing keys are readable, so receipts can be minted at will; the audit
file can be rewritten; and expiry checks can be defeated by moving the clock, since expiry is
evaluated against the host clock (`executor.py:25`, `:128`, `:227`) with a configurable skew
bound (`max_clock_skew_seconds`, `executor.py:55`). A self-consistent full rewrite of the
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
implements the check (`audit.py:308-341`), and no shipped call site supplies either argument
across seven call sites. This is keyless by design with the anchor as an operator duty — it is
not an unwired feature. `test_audit_chain_corruption.py:155` asserts both directions: keyless
verify returns valid on a truncated prefix; anchored verify returns `length_mismatch` and
`last_hash_mismatch`.

## 4. Deployment modes

### Mode 1 — in-process library (**development only**)

The kernel runs inside the proposer's process.

**Properties:** evidence generation; fail-closed admission for wired paths; tamper-evident
audit chain (with §3.4's caveat).
**Non-properties:** bypass resistance against a compromised host or an exec-capable agent;
complete mediation.

Sandboxing does not close this gap in the default configuration. `LocalProcessSandbox` uses
`bwrap` when present, but when `bwrap` is absent and `require_bwrap` is unset it degrades to
an ordinary subprocess that the docstring states does **not** restrict network or filesystem,
behind a `UserWarning` (`sandbox.py:87-98`). Containment is real only with `bwrap` installed
**and** `require_bwrap=True`. There is no test exercising the degraded path.

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
`packages/gove-zone/tests/adversary/test_coverage_manifest.py`. That manifest is the source of
truth; this table must not diverge from it.

**Read the `adaptive` column, not `status` alone.** Until 2026-07-28 `status` was
`Literal["DEFENDED"]` and could not express anything else, so any historical claim resting on
it is uninformative by construction.

| Adversary class | Mode 1 (in-process) | Mode 2 (projected) | Notes |
|---|---|---|---|
| forged-authorization | defended, adaptively bypassable | defended | Signature required by default; adaptive harness still finds a variant |
| replayed-authorization | defended **only with a consumption ledger** | defended | Ledger is opt-in in Mode 1; broker-side in Mode 2 |
| ledger-tampering | detected | detected | In-chain mutation only; see compromised-host |
| policy-downgrade | defended, adaptively bypassable | defended | |
| tenant-crossover | defended | defended | Adaptively stable |
| signature-stripping | defended | defended | Adaptively stable |
| validator-bypass | defended by string comparison | defended by key | No validator↔key binding exists today (§3.3) |
| evidence-omission | defended | defended | Adaptively stable |
| **negligent-integrator** | **partial** | defended | Wiring proven for shipped examples only; no scan detects a new ungoverned path |
| **compromised-host** | **out of scope** | out of scope | Detectable only with an external anchor (§3.4). Mode 2 does not close it either — it moves the trust boundary, it does not remove the host |
| **exec-capable-agent** | **out of scope** | defended | No test models it in either direction today; closing it is the point of Mode 2 |

The last three classes concern where the gate *sits* rather than what it checks. None can
reach "defended" from library code alone.

---

## Related

- [claims-map.md](./claims-map.md) — what may be said about the above, and with which caveat.
- [CLAIMS.md](./CLAIMS.md) — the claim ledger with per-claim evidence.
- [SECURITY.md](../SECURITY.md) — reporting and current threat-model scope.
- [audit/phase0-baseline.md](./audit/phase0-baseline.md) — the survey these findings come from.
