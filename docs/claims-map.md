# Claims map

| | |
|---|---|
| **Purpose** | Canonical speech-permission ledger: for each claim, what may be said, with what caveat, and on what evidence. |
| **Created by** | WS-A of the ACGS Hardening Spec, per §3/A9 (no claims map existed). |
| **Evidence ref** | `origin/master` @ `4459d849`, plus branch commits `fc6b39c1` and `91c7cb0e` where noted per row. Verified 2026-07-28. See [audit/phase0-baseline.md](./audit/phase0-baseline.md). |
| **Scope discipline** | Every row follows [repository-scope-rule.md](./repository-scope-rule.md). |

> **Corrected after adversarial verification.** An earlier revision of this file contained
> three errors: the "splitting row L19" warning was false for the splitting half, the sandbox
> caveat was wrong in one branch, and the adversary-taxonomy row described a manifest state
> that did not exist at this file's own pinned ref. All three are corrected below and recorded
> as F-5, F-7 and the overclaim list in
> [audit/ws-a-verification-findings.md](./audit/ws-a-verification-findings.md).

## Relationship to the existing claim documents — read before editing anything

Three claim documents now exist. They are **not** interchangeable.

| Document | Role | Editable? |
|---|---|---|
| [`CLAIMS.md`](./CLAIMS.md) | The **claim ledger**: what is claimed, its status, evidence, and safe public wording. | **Treat as gate-asserted.** See below. |
| [`CLAIM_AUDIT.md`](./CLAIM_AUDIT.md) | A dated point-in-time audit (Phase 5) with ALLOWED / DOWNGRADE / REMOVE / LEAVE verdicts. | Yes — no test reads it. Its verdicts must be **re-verified**, not copied forward. |
| **This file** | **Speech permission**: SAY / SAY-WITH-CAVEAT / DO-NOT-SAY, plus the unlock condition for each. | Yes. |

> **`CLAIMS.md` is a live tripwire.** Three tests read it, and several assertions are on
> literal strings:
> - `tests/docs/test_docs_and_examples.py:66-71` — must contain `No valid Decision Receipt, no side effect`.
> - `:119-129` — rows must begin `| ` and split to **≥6 cells**; a reshaped table is silently dropped, not caught.
> - `:146-148` — the Status spellings `not claimed` and `roadmap` are read literally.
> - `:152-158` — **backticks are a machine contract**: `` `test_x` `` must resolve to a real test and `` `packages/...` `` to a real path.
> - `:164-175` — must contain `production-certified`, `compliance-certified`, `regulator-approved`, `content moderation`, `sandboxing`, `iam/rbac/pki`, `formal verification`.
> - `test_signing_default_doc_matches_code.py:105-119` — reads `CLAIMS.md` as **one flat lowercased blob** and asserts four substrings, including `does not auto-sign` (which occurs only at row L19). **Removing or rewording that literal reds the build; splitting the row does not** — nothing parses row identity or count.
>
> Add claims to `CLAIMS.md` by appending a well-formed row. Do not restructure it.

## The three axes

- **SAY** — assertable without qualification. Evidence is in-repo and tested.
- **SAY-WITH-CAVEAT** — assertable *only* with the stated caveat attached. Dropping the caveat converts a true statement into a false one.
- **DO-NOT-SAY** — not assertable in any public surface. Permanent unless a listed unlock condition is met.

Unlock conditions are defined in the hardening spec §9 (**UC-A** boundary doc merged; **UC-B** hardened defaults merged and green; **UC-C** reference topology canary green on `master`).

---

## DO-NOT-SAY — permanent

These are permanent. None has an unlock condition, because no engineering work would make them true as phrased.

| Phrasing | Why it is forbidden |
|---|---|
| "HTTPS for AI", "TLS for agents", any protocol-security analogy | Implies a wire protocol with ubiquitous deployment and formal properties. ACGS is a library-level admission layer; the analogy imports guarantees that do not transfer. |
| "tamper-proof" | The chain is **tamper-evident** — it detects modification, it does not prevent it. Established repo vocabulary; `CLAIM_AUDIT.md:33` already ruled on this. |
| "prevents bypass", "cannot be bypassed", "un-bypassable", "impossible to bypass" (unscoped) | Complete mediation does not hold inside the proposer's process. See DO-NOT-SAY note below on the one legitimate exception. |
| "runtime enforcement" (unscoped) | Enforcement is scoped to paths wired through the gate. Unqualified, it asserts complete mediation. |
| "cryptographic authorization" | An unsigned mode still exists (`signature="unsigned_local"`). The phrase claims a property the default data model does not always carry. |
| "production-certified", "compliance-certified", "regulator-approved" | No external evidence exists. Already forbidden by `AGENTS.md:166-167` and asserted by `tests/docs/test_docs_and_examples.py:164-175`. |
| "formally verified" | Formal verification is a roadmap item, explicitly not a result (`README.md:20`). |
| "guaranteed safe", "guarantees safety" | No such guarantee is produced by any control in this repository. |

**Legitimate exception — terms of art in a cited definition.** `SECURITY_MODEL.md:46` uses
"tamper-proof" while quoting Anderson (1972)'s reference-monitor definition. That is a
citation, not a product claim, and `CLAIM_AUDIT.md:28` already ruled it **LEAVE**. Quoting a
definition in order to say which of its properties ACGS does *not* meet is the opposite of
overclaiming. Do not "fix" it.

---

## SAY-WITH-CAVEAT

The caveat is not decoration. Each of these is false without it.

| Claim | Mandatory caveat | Evidence | Unlock |
|---|---|---|---|
| No valid Decision Receipt, no side effect. | **"for every execution path wired through ACGS."** Complete mediation does not hold against a compromised host or an exec-capable agent. | `executor.py:32`; `test_executor_guard.py::test_executor_refuses_no_receipt` | Unqualified form stays locked. **UC-C** unlocks a *topology-scoped* form only. |
| The audit chain is tamper-evident. | **"against in-chain edits, reorder, and a malformed tail. Truncation and full rewrite are detected only when the caller supplies an external anchor."** | `audit.py:308-341`; `test_audit_chain_corruption.py:155` asserts both directions — keyless verify returns valid on a truncated prefix; anchored verify returns `length_mismatch` + `last_hash_mismatch` | **UC-B** |
| Signature verification is required by default. | **"at the three gate surfaces."** Issuance signing still requires an explicit signer; the gate does not auto-sign. | `executor.py:50`, `executor.py:291`, `contracts.py:272` | — (already true; caveat is permanent) |
| Receipts can be made single-use. | **"opt-in at the gate default — a consumption ledger must be supplied. It is *required* under `GovernanceProfile.production_strict`, which raises `ProductionProfileError` when it is `None`."** | `executor.py:56`, `:297`, `:354`; `profile.py:134-141`, `:62-67`; `test_receipt_consumption.py::test_resume_replay_blocked_with_ledger` | **UC-B** |
| A compromised signing key can be revoked. | **"at the live gates, the offline replay path, and the offline proof-pack verifier — via an operator-supplied list. There is no PKI, custody, or automatic distribution."** | `revocation.py` (`RevocationList`, checked before the signature is trusted); `trust.py` `status` ∈ active/retired/revoked | — |
| Signing keys have a lifecycle. | **"operator-declared, not managed."** Rotation is `activated_epoch`/`retired_epoch`; expiry is `not_after`; retired keys still verify historical epochs under `mode="historical"`. | `trust.py`; wired at `executor.py:29`, required for v2 at `:176-178` | — |
| Roles are separated (MACI). | **"by identity string, not by key."** No validator↔key binding exists: `validator_id` has zero occurrences in `trust.py`, `authz.py`, `identity.py`, and `verifier.py`. A holder of the scope's active key can mint a receipt naming any `validator_id`. | `receipt.py:414-418`, `:865`, `:882`; `test_maci_role_separation.py` | WS-D / WS-C4 |
| Tool execution can be sandboxed. | **"only when bwrap is present. `bwrap` is used whenever it is installed (`sandbox.py:86`); `require_bwrap` controls whether its *absence* is a hard failure rather than a degrade to an unrestricted subprocess behind a UserWarning."** Containment is real with bwrap installed, and guaranteed only with `require_bwrap=True`. The degraded path has no test. | `sandbox.py:86`, `:87-98` | **UC-C** |
| Compliance controls are mapped. | **"self-assessment mapping, not an audit result."** 16 controls across EU AI Act, SOC 2, NIST AI RMF, ISO 42001. **ISO 27001 is not covered.** | `compliance/control-mapping.json`; `tests/docs/test_compliance_mapping.py` | — |

---

## SAY

| Claim | Evidence |
|---|---|
| ACGS is alpha. The gove-zone kernel is a separate `1.0.0rc1` line. | `README.md:16-20` |
| The governed executor fails closed without a valid receipt. | `CLAIMS.md:8`; `test_executor_guard.py` |
| Policy-evaluation failure, audit-append failure, and (when configured) policy timeout all resolve to deny. | `test_fail_closed.py`, `test_fail_closed_gaps.py` |
| Receipt fields are hash-bound: actor, action, arguments, policy, expiry all participate in `receipt_hash`. | `receipt.py:332-374` — `_hash_payload()` enumerates the payload **by hand**; it does not pop from the field list. Excluded: `receipt_hash`, `signature` (by construction), plus the four receipt-v2 scoped-trust fields on v1 (validated empty at `receipt.py:255`, `:679`). Drift guarded by `test_trust_receipt_v2.py::test_v1_hash_payload_covers_every_declared_field_except_documented_exclusions` |
| The adversary taxonomy is machine-checked and can express a gap. | `tests/adversary/test_coverage_manifest.py` **as of branch commit `fc6b39c1`** (at `4459d849` it has 8 classes and a `status` that can only say `DEFENDED`) — 11 classes; a posture must cite a test, and `UNKNOWN` may cite none |
| A declared posture is checked against the *kind* of evidence it cites. | `test_coverage_manifest.py` **as of `91c7cb0e`** — `DEFENDED` may not cite a gap-documenting test, `BYPASSABLE` must; the GAP/BOUNDARY kind is derived from the cited test's own `xfail` marker or `_KNOWN_GAP` suffix. **Consistency, not truth** — it cannot show a class is genuinely defended |
| Five of eight adaptively-modelled adversary classes are BYPASSABLE. | `test_coverage_manifest.py` `adaptive` field; `test_adaptive_stability.py::test_adaptive_posture_is_pinned` |

**On reporting adversary coverage:** cite the `adaptive` field, never `status` alone. Until
2026-07-28 `status` was `Literal["DEFENDED"]` and therefore could not express anything else;
any historical claim resting on `status` is uninformative by construction.

---

## Remediation ledger — occurrences found and corrected

A repo-wide sweep at `4459d849`, including a non-English pass, found the following. **All
actionable items are now corrected**; the two `LEAVE` rulings and the archive file stand.
Original phrasing is kept in the table so the change is reviewable.

| File:line | Phrasing | Verdict | Status |
|---|---|---|---|
| `docs/PRODUCT_STRATEGY.md:19` | 如同 TLS 之于传输 ("like TLS is to transport") | **forbidden** — protocol analogy. Found only by a non-English sweep; ASCII greps miss it. | ✅ analogy removed |
| `docs/PRODUCT_STRATEGY.md:30,41,94,111` | 防篡改 (tamper-proof) ×4 | **forbidden** — should be 防篡改可检测 / tamper-evident | ✅ all four → 防篡改可检测 |
| `docs/PRODUCT_STRATEGY.md:16` | 每一个副作用都可治理 ("every side effect governable") | unscoped | ✅ scoped to 接入 ACGS 的执行路径 |
| `docs/strategy/design-partner-kit/ONBOARDING.md:65` | "signed, tamper-proof" | **forbidden** | ✅ → tamper-evident |
| `packages/gove-zone/examples/undeniable-demo/README.md:4` | "tamper-proof evidence" | **forbidden** — shipped example surface | ✅ → tamper-evident |
| `packages/gove-zone/src/gove_zone/adapters/langgraph.py:4` | "ensuring all tool executions pass through policy checks" | unscoped — shipped docstring | ✅ scoped to wrapped tools; unwrapped paths named |
| `docs/hooks-or-runtime/overview.md:3,9` | "governed runtime enforcement" | **forbidden** unscoped | ✅ scoped to wired paths |
| `docs/design/agent-native-architecture-audit.md:77,101,104` | "impossible to bypass", "un-bypassable", "impossible to call un-gated" | **forbidden** unscoped | ✅ all three → closes admission-by-omission, not in-process bypass |
| `docs/design/agent-native-architecture-audit.md:43` | "there is no un-gated execution path" | unscoped | ✅ scoped to registered tools |
| `docs/strategy/mcp-gateway-gap-analysis.md:110` | "No bypass path" | **forbidden** unscoped | ✅ → "through the gateway" |
| `docs/design/acgs-governed-hermes-*.md:17,22` | "intercepts every side-effectful action" | unscoped | ✅ scoped to actions routed through the gate |
| `docs/adr/0001-*.md:20,102` | "for every side-effectful action" | unscoped | **LEAVE** — ADR decision text records an architectural intent at a point in time, not an implemented-state claim. Retroactively amending an accepted ADR is worse practice than the overclaim; supersede it with a new ADR if the intent changes. |
| `docs/crosswalks/PICKEN_BOARD_AI_CYBER_CROSSWALK.md:49` | "A vendor agent cannot act outside its issued receipt." | unscoped | ✅ prefixed "On a path wired through the gate" |
| `docs/archive/ROADMAP-ENFORCEMENT-SUBSTRATE.md:65` | "Tamper-proof (cannot be bypassed or altered)" | archive — record, do not edit | **LEAVE** — archive |
| `docs/SECURITY_MODEL.md:46` | "tamper-proof" inside the Anderson (1972) citation | **LEAVE** — term of art, already ruled at `CLAIM_AUDIT.md:28` | **LEAVE** |

**Re-sweep after correction** (`git grep -in` over `docs/`, `README.md`, and shipped example
surfaces, excluding archive, this file, and `docs/audit/`): the only remaining `tamper-proof`
occurrences are negated disclaimers ("not tamper-proof"), forbidden-word lists, prior-remediation
records, and the Anderson term of art. The only remaining `cannot be bypassed` is
`docs/gove-zone-pypi-readiness.md:102`, which is about a GitHub required-reviewer ruleset, not
ACGS enforcement. Every `production-certified` / `compliance-certified` / `regulator-approved`
hit repo-wide is a negation.

### Known-stale verdicts elsewhere

- **`CLAIM_AUDIT.md:24`** — `| "optional Ed25519 signing" | README, signing.py | Opt-in, accurately scoped |`.
  This predates the gate-default flip and is contradicted by `CLAIMS.md:19`. Issuance signing
  is still opt-in; the *gate requirement* is now the default. Re-verify, do not copy forward.
- **`CLAIMS.md:18`** — evidence column cites `signing.py`, `receipt.py`, `revocation.py` but
  **omits `trust.py`**, understating the lifecycle that now exists. Incomplete, not false; its
  limitation clause still holds because `trust.py` rotation is operator-declared, not automatic.

### Not stale — do not "fix" these

Once "revocation exists" is known, an over-broad sweep will try to correct these. All three remain accurate:

- `CLAIMS.md:15`, `:22` — "no global receipt/nonce revocation service". **Key** revocation is not **per-receipt** revocation.
- `CLAIMS.md:41` — "Identity/key lifecycle is integrator/operator-owned". Consistent with `trust.py`'s own docstring ("no SQL, network, KMS, private-key persistence").

### Vocabulary note

The word **"grace"** does not appear in `trust.py`. The behaviour — a retired key still verifying
epochs before its `retired_epoch` under `mode="historical"` — is real, but "grace period" is
descriptive shorthand, not the source's term. Prefer the source's vocabulary in public surfaces.

---

## Adding a claim

1. Append a well-formed row to `CLAIMS.md` (≥6 cells; backtick every test and path — they are resolved by the gate).
2. Add a row here on the correct axis, with an evidence pointer and, if caveated, the exact mandatory caveat.
3. If the claim needs an unlock condition, reference the UC from the hardening spec §9.
4. Run `uv run python -m pytest tests/docs --import-mode=importlib -q`.

**Freeze protocol.** If a shipped control regresses, every claim resting on it re-freezes to
DO-NOT-SAY until the gate is green again.
