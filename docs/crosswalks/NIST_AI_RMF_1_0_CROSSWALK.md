# Crosswalk — NIST AI RMF 1.0 → gove-zone enforced runtime controls

> **What this is.** A function-by-function mapping from the four core functions of
> the NIST AI Risk Management Framework 1.0 (AI 100-1) — **GOVERN**, **MAP**,
> **MEASURE**, **MANAGE** — onto the enforced runtime controls of gove-zone, the
> receipt-gated execution-legitimacy kernel in this repository.
>
> **What this is NOT.** A self-assessment mapping — not a certification, an
> attestation, a conformity assessment, or an audit result. gove-zone is
> alpha / local-proof software (`docs/SECURITY_MODEL.md`). A row means *"the
> receipt membrane produces evidence toward that outcome at the executor
> boundary."* It does **not** mean adopting gove-zone makes a system AI RMF
> aligned. AI RMF alignment is a property of an organization and its full risk
> management program; gove-zone is one layer of it.

`docs/COMPLIANCE_CROSSWALK.md` already carries a six-row AI RMF summary alongside
NIST CSF 2.0, MITRE ATLAS, and OWASP. **This document does not replace it** — it
extends that summary from six merged rows to all nineteen AI RMF 1.0 categories,
and marks explicitly where there is no runtime enforcement.

---

## Provenance & claim-safety

Read this before citing any row.

- **The NIST side is paraphrased, not quoted.** No published NIST text is
  reproduced here. The AI RMF category structure (GOVERN 1–6, MAP 1–5,
  MEASURE 1–4, MANAGE 1–4) and the one-line intent statements in the
  "AI RMF category (paraphrased intent)" column are this repository's
  restatement, reconstructed from secondary references already in this repo —
  `docs/COMPLIANCE_CROSSWALK.md` and the `frameworks.nist_ai_rmf` scope notes in
  `compliance/control-mapping.json`. They were **not** verified against the
  published AI 100-1 text at authoring time (no network access to nist.gov from
  the authoring environment). **Correct this column against AI 100-1 before
  relying on it externally.** This mirrors the provenance convention used in
  `docs/crosswalks/PICKEN_BOARD_AI_CYBER_CROSSWALK.md`.
- **The gove-zone side is grounded.** Every control name, status, and limitation
  traces to `compliance/control-mapping.json`, the control inventory in
  `docs/COMPLIANCE_CROSSWALK.md`, or a row of `docs/CLAIMS.md`. Every source and
  test path cited below was confirmed present in the working tree at authoring
  time.
- **`compliance/control-mapping.json` is authoritative** for the six requirement
  IDs it already defines (`NIST-AIRMF-GOVERN-1`, `-GOVERN-2`, `-GOVERN-4`,
  `-MAP-1-5`, `-MEASURE-2-4`, `-MANAGE-2-4`). Where a row below carries one of
  those IDs, its **status and limitation are reproduced verbatim from the JSON**.
  Two JSON rows are *joint* — `NIST-AIRMF-MAP-1-5` covers MAP 1 and MAP 5,
  `NIST-AIRMF-MANAGE-2-4` covers MANAGE 2 and MANAGE 4. This document splits each
  across its two categories. The first half of each split carries the JSON status
  and limitation verbatim; the second half (MAP 5, MANAGE 4) is **narrowed to
  `partial`**, and that narrowing is disclosed in the row itself. A narrowing is
  never an upgrade. Beyond those two splits, this document adds coverage for the
  categories the JSON does not address; it does **not** restate, upgrade, or
  override any JSON row. If the two ever disagree, the JSON wins and this file is
  the stale copy.
- **Nothing here is certified.** Not production-certified, not
  compliance-certified, not regulator-approved — see the *not claimed* rows of
  `docs/CLAIMS.md`.

### Divergences to reconcile against AI 100-1

Flagged, not silently corrected — because the authoritative NIST text could not
be consulted from the authoring environment. Each of these is a *possible*
labelling mismatch inside `compliance/control-mapping.json`, and each may equally
be a correct reading this author could not confirm:

| JSON requirement ID | JSON label | Possible mismatch |
|---|---|---|
| `NIST-AIRMF-GOVERN-4` | "GOVERN 1.5 / 4.1 — accountability, transparency, and documentation of AI system decisions" | GOVERN 4 in the paraphrased structure below is about organizational culture (critical thinking, safety-first mindset); the accountability/transparency/documentation intent may sit closer to GOVERN 1 and GOVERN 2. |
| `NIST-AIRMF-MEASURE-2-4` | "MEASURE 2 / MEASURE 4 — evaluate trustworthiness characteristics and track them over time" | "Track over time" reads as MEASURE 3 in the paraphrased structure; MEASURE 4 reads as feedback on the efficacy of the measurement approach itself. |

This table alone is insufficient grounds for changing
`compliance/control-mapping.json`. Verify against AI 100-1 first, then amend the
JSON (the authority) and regenerate any derived artifacts.

---

## Core invariant being mapped

**No valid Decision Receipt, no side effect.** A registered tool executes only
when a receipt passes the full executor gate: it exists; was issued for *this*
caller; is hash-intact (and signature-valid when it claims a signature); is
ALLOW/TRANSFORM (not DENY/ESCALATE/expired); and its tenant, boundary, action,
exact arguments, policy hash + bundle, and audit-event hash all match what the
executor is about to do — minted by a validator distinct from the proposer.
Any failure raises `ReceiptValidationError` **before** the tool runs.
Independently, the kernel guarantees policy-runs-before-effect and fail-closes
(synthesized DENY / `AuditError`) on policy or audit failure.

The control inventory that backs the `Controls` column below lives in
`docs/COMPLIANCE_CROSSWALK.md` § *Control inventory* and in the `controls` block
of `compliance/control-mapping.json`. It is deliberately **not** duplicated here.

### Status vocabulary

Reused verbatim from `compliance/control-mapping.json` so the two files stay
comparable:

- **implemented** — control is on by default and covered by tests in this repository.
- **opt-in** — control exists and is tested but must be explicitly enabled by the integrator.
- **partial** — control contributes evidence toward the requirement but does not satisfy it alone.
- **operator-owned** — requirement is an organizational/operator responsibility; gove-zone only supplies supporting evidence (or none).
- **gap** — requirement is in scope for gove-zone but not yet covered.

Note the distinction: an **operator-owned** row is not a backlog item. It means
the requirement is out of scope for a runtime execution membrane by design. No
row in this crosswalk is classified **gap**.

---

## GOVERN

Cultivating a culture of risk management: policies, accountability, workforce,
and third-party governance.

| AI RMF category (paraphrased intent) | gove-zone contribution | Controls | Evidence (source / test) | Status |
|---|---|---|---|---|
| **GOVERN 1** — policies, processes, and procedures to manage AI risk are in place and enforced | Policy bundles are bound by id + hash into every decision, and policy is evaluated and audited *before* any tool runs; bundle substitution is rejected at the gate | POLICY-TENANT-BIND, POLICY-BEFORE-EXEC | `packages/gove-zone/src/gove_zone/policy.py`, `packages/gove-zone/src/gove_zone/kernel.py` / `packages/gove-zone/tests/test_policy_bundle_io.py`, `packages/gove-zone/tests/test_kernel_dispatch.py` | **implemented** *(JSON `NIST-AIRMF-GOVERN-1`)* — "Runtime policy bundles are not an organizational AI risk management program; they are its enforcement point." |
| **GOVERN 2** — accountability structures, roles, and separation of duties for AI actors | Proposer ≠ validator enforced at receipt issuance *and* again at the gate; the calling identity must equal `receipt.actor`, so no principal can self-authorize | MACI-VALIDATOR-SEP, ACTOR-ANCHOR | `packages/gove-zone/src/gove_zone/receipt.py`, `packages/gove-zone/src/gove_zone/tenant.py` / `packages/gove-zone/tests/test_maci_role_separation.py`, `packages/gove-zone/tests/test_tenant_safety.py` | **implemented** *(JSON `NIST-AIRMF-GOVERN-2`)* — "Actor identity is opaque strings bound into receipts; authentication and IAM are external." |
| **GOVERN 3** — workforce diversity, equity, inclusion, and accessibility in AI risk management | **No runtime evidence — organizational control, out of gove-zone scope.** A runtime execution membrane has no visibility into team composition or hiring practice. | — | — | **operator-owned** |
| **GOVERN 4** — organizational culture and practices that foster critical thinking and a safety-first mindset | Every governed side effect emits a tamper-evident Decision Receipt bound to actor / action / arguments / policy / authority / audit anchor; the default posture is fail-closed rather than fail-open | RECEIPT-REQUIRED, AUDIT-HASHCHAIN | `packages/gove-zone/src/gove_zone/receipt.py`, `packages/gove-zone/src/gove_zone/audit.py` / `packages/gove-zone/tests/test_decision_receipt.py`, `packages/gove-zone/tests/test_audit_chain.py` | **implemented** *(JSON `NIST-AIRMF-GOVERN-4`; see the divergence table — the JSON labels this row "GOVERN 1.5 / 4.1")* — "Every governed side effect emits a tamper-evident Decision Receipt; ungoverned paths emit nothing." |
| **GOVERN 5** — processes for engaging with relevant AI actors and incorporating external feedback | **No runtime evidence — organizational control, out of gove-zone scope.** ESCALATE routes a decision to a human authority (`escalation.py`), but human-in-the-loop approval of one action is an enforcement primitive, not a stakeholder-engagement process. | — *(ESCALATE-HUMAN is a touchpoint, not coverage)* | `packages/gove-zone/src/gove_zone/escalation.py` *(context only)* | **operator-owned** |
| **GOVERN 6** — policies and procedures for third-party AI software, data, and supply-chain risk | A delegated or third-party agent's side effect is gated by exactly the same membrane as a first-party one: it must present a receipt naming it as `actor`, bound to the expected tenant, boundary, action, and arguments. The A2A delegation adapter is contract-level | RECEIPT-REQUIRED, ACTOR-ANCHOR, POLICY-TENANT-BIND | `packages/gove-zone/src/gove_zone/a2a.py`, `packages/gove-zone/src/gove_zone/executor.py` / `packages/gove-zone/tests/test_a2a_delegation.py`, `packages/gove-zone/tests/test_executor_guard.py` | **partial** — supplier due diligence, contractual terms, SBOM, and third-party assessment are operator-owned; the A2A adapter is adapter-mediated and contract-level, not a certified production integration (`docs/CLAIMS.md`, row 29) |

---

## MAP

Establishing context and framing risk.

| AI RMF category (paraphrased intent) | gove-zone contribution | Controls | Evidence (source / test) | Status |
|---|---|---|---|---|
| **MAP 1** — context is established and understood | Each dispatch carries an explicit context tuple bound into the receipt: actor, tenant, execution boundary, action, and exact arguments. Decisions are categorized ALLOW / DENY / ESCALATE / TRANSFORM with bound arguments | DECISION-GATE, ARG-BIND | `packages/gove-zone/src/gove_zone/receipt.py` / `packages/gove-zone/tests/test_argument_binding.py` | **implemented** *(JSON `NIST-AIRMF-MAP-1-5`, first half of a joint row)* — "Decisions are categorized ALLOW/DENY/ESCALATE/TRANSFORM with bound arguments; upstream risk assessment quality is integrator-owned." |
| **MAP 2** — the AI system is categorized | gove-zone categorizes the **action**, not the system: policy bundles support a risk-tier dimension on the proposed action, evaluated before execution | POLICY-TENANT-BIND, POLICY-BEFORE-EXEC | `packages/gove-zone/src/gove_zone/policy.py`, `packages/gove-zone/src/gove_zone/yaml_policy.py` / `packages/gove-zone/tests/test_risk_tier_policy.py` | **partial** — per-action risk tiering is enforced; classifying the *AI system* (its purpose, deployment context, or regulatory class) is operator-owned and happens upstream of the gate |
| **MAP 3** — AI capabilities, targeted usage, goals, and expected benefits and costs are understood | **No runtime evidence — organizational control, out of gove-zone scope.** The membrane sees a proposed action, not the system's intended purpose or its benefit/cost case. | — | — | **operator-owned** |
| **MAP 4** — risks and benefits are mapped for all system components, including third-party software and data | **No runtime evidence — organizational control, out of gove-zone scope.** Gating a third-party agent's *action* (GOVERN 6, MANAGE 3) is not the same as mapping the risks of a component; the mapping is analysis performed before policy is authored. | — | — | **operator-owned** |
| **MAP 5** — impacts to individuals, groups, communities, organizations, and society are characterized | Per-action decisions are recorded with their matched rules, policy hash, and audit anchor, which supplies traceable inputs to an impact assessment | DECISION-GATE, ARG-BIND, AUDIT-HASHCHAIN | `packages/gove-zone/src/gove_zone/receipt.py`, `packages/gove-zone/src/gove_zone/audit.py` / `packages/gove-zone/tests/test_argument_binding.py`, `packages/gove-zone/tests/test_audit_chain.py` | **partial** *(JSON `NIST-AIRMF-MAP-1-5` covers MAP 1 and MAP 5 jointly as **implemented**; this row narrows to MAP 5 only)* — decisions are categorized with bound arguments, but characterizing societal or group-level impact is human analysis on top of the log, and upstream risk-assessment quality is integrator-owned |

---

## MEASURE

Analyzing, assessing, benchmarking, and monitoring AI risk.

| AI RMF category (paraphrased intent) | gove-zone contribution | Controls | Evidence (source / test) | Status |
|---|---|---|---|---|
| **MEASURE 1** — appropriate methods and metrics are identified and applied | An opt-in, **default-OFF** boundary wrapper emits receipt-emission metrics for governed decisions | *(metrics wrapper — not a named control in the inventory)* | `packages/gove-zone/src/gove_zone/metrics.py` / `packages/gove-zone/tests/test_metrics.py` | **opt-in** — the wrapper counts governed decisions; it does **not** define, select, or validate trustworthiness metrics. Choosing the measurement method is operator-owned |
| **MEASURE 2** — AI systems are evaluated for trustworthy characteristics | Deterministic replay re-derives the recorded decision by re-running the recorded policy; the hash chain independently verifies integrity of the record being replayed | REPLAY-VERIFY, AUDIT-HASHCHAIN | `packages/gove-zone/src/gove_zone/replay.py`, `packages/gove-zone/src/gove_zone/replay_store.py`, `packages/gove-zone/src/gove_zone/audit.py` / `packages/gove-zone/tests/test_replay.py`, `packages/gove-zone/tests/test_replay_store.py` | **opt-in** *(JSON `NIST-AIRMF-MEASURE-2-4`)* — audit-only replay is policy-version-only; strong replay of full arguments requires the opt-in side store |
| **MEASURE 3** — mechanisms for tracking identified AI risks over time are in place | The audit store is append-only JSONL with a `previous_hash` → `event_hash` chain under `flock` + fsync, re-walkable with `verify_chain()`; every governed decision lands in time order and tampering is detectable | AUDIT-HASHCHAIN | `packages/gove-zone/src/gove_zone/audit.py` / `packages/gove-zone/tests/test_audit_chain.py`, `packages/gove-zone/tests/test_audit_chain_corruption.py` | **partial** — the chain is a durable, ordered, tamper-evident *record*; risk trending, thresholds, dashboards, and review cadence are operator-owned. See the divergence table: the JSON attributes "track over time" to MEASURE 4 |
| **MEASURE 4** — feedback about the efficacy of measurement is gathered and assessed | **No runtime evidence — organizational control, out of gove-zone scope.** Assessing whether the measurement approach itself is working is a program-level review activity. | — | — | **operator-owned** |

---

## MANAGE

Prioritizing and acting on risk, including response and recovery.

| AI RMF category (paraphrased intent) | gove-zone contribution | Controls | Evidence (source / test) | Status |
|---|---|---|---|---|
| **MANAGE 1** — AI risks are prioritized, responded to, and managed | DENY and ESCALATE decisions are structurally non-executable; ESCALATE turns a dead-end into a resumable path where a **human** approver mints a fresh ALLOW as a distinct MACI validator, re-stamping the argument hash so the approved action cannot be widened at resume | DECISION-GATE, ESCALATE-HUMAN | `packages/gove-zone/src/gove_zone/receipt.py`, `packages/gove-zone/src/gove_zone/escalation.py` / `packages/gove-zone/tests/test_escalation_resume.py` | **partial** — the runtime enforces the response *mechanism*; deciding which risks are high priority is policy authoring, which is operator-owned |
| **MANAGE 2** — strategies to maximize benefits and minimize negative impacts, including fail-safe behavior | Fail-closed on policy exception/timeout (synthesized DENY) and on audit append failure (`AuditError`) — never a silent allow. DENY / ESCALATE / unknown decisions cannot authorize execution; expired and already-consumed receipts are blocked | FAILCLOSED, DECISION-GATE, EXPIRY, ANTI-REPLAY | `packages/gove-zone/src/gove_zone/kernel.py`, `packages/gove-zone/src/gove_zone/receipt.py`, `packages/gove-zone/src/gove_zone/consumption.py` / `packages/gove-zone/tests/test_fail_closed.py`, `packages/gove-zone/tests/test_receipt_expiry.py`, `packages/gove-zone/tests/test_receipt_consumption.py` | **implemented** *(JSON `NIST-AIRMF-MANAGE-2-4`)* — fail-closed and decision gating are default-on; expiry is an opt-in field and anti-replay is an opt-in ledger |
| **MANAGE 3** — risks and benefits from third-party entities are managed | A compromised **issuer signing key** can be revoked at runtime: the gate rejects a receipt whose `signing_key_id` is on the revocation list *before* trusting its signature, independent of verifier-map membership — including in the offline proof-pack verifier, so a key compromised after a pack was minted cannot be verified as valid by a relying party | *(static signing-key-ID revocation — `docs/CLAIMS.md`, row 18)*, ACTOR-ANCHOR | `packages/gove-zone/src/gove_zone/revocation.py`, `packages/gove-zone/src/gove_zone/verifier.py` / `packages/gove-zone/tests/test_revocation.py`, `packages/gove-zone/tests/test_proofpack_revocation.py` | **opt-in** — verbatim from `docs/CLAIMS.md` row 18: *"Issuance signing and the operator-supplied `RevocationList` are opt-in; no PKI, custody, automatic distribution/rotation, per-receipt revocation, or global nonce service."* Scope is issuer/signing key IDs only — not caller credentials, and not the workflow-envelope or plan-authorization key population |
| **MANAGE 4** — risk treatments, including response, recovery, and communication plans, are documented and monitored | Decisions are reconstructable from the hash chain (plus the opt-in side store for full arguments); consumption is at-most-once, so recovery after a crash between burn and execution is a fresh approval, never a silent replay | REPLAY-VERIFY, AUDIT-HASHCHAIN, ANTI-REPLAY | `packages/gove-zone/src/gove_zone/replay.py`, `packages/gove-zone/src/gove_zone/audit.py`, `packages/gove-zone/src/gove_zone/consumption.py` / `packages/gove-zone/tests/test_replay.py`, `packages/gove-zone/tests/test_receipt_consumption.py`, `packages/gove-zone/tests/test_consumption_tamper.py` | **partial** *(JSON `NIST-AIRMF-MANAGE-2-4` covers MANAGE 2 and MANAGE 4 jointly as **implemented**; this row narrows to MANAGE 4 only)* — the runtime supplies replayable evidence and at-most-once semantics; documenting and monitoring the response/recovery/communication plan is operator-owned |

---

## Coverage summary

Counts are of the nineteen AI RMF 1.0 categories as paraphrased above. They
describe **evidence coverage at the executor boundary**, not AI RMF alignment.

| Status | Categories | Count |
|---|---|---|
| implemented | GOVERN 1, GOVERN 2, GOVERN 4, MAP 1, MANAGE 2 | 5 |
| partial | GOVERN 6, MAP 2, MAP 5, MEASURE 3, MANAGE 1, MANAGE 4 | 6 |
| opt-in | MEASURE 1, MEASURE 2, MANAGE 3 | 3 |
| operator-owned (no runtime evidence) | GOVERN 3, GOVERN 5, MAP 3, MAP 4, MEASURE 4 | 5 |
| gap (in scope, not yet covered) | — | 0 |

Read that as: **14 of 19 categories are evidence-bearing at some strength**, and
**5 have no runtime evidence at all** because they are organizational controls a
runtime execution membrane cannot observe. The strongest coverage is
concentrated in GOVERN and MANAGE — the functions about enforcement — and the
weakest in MAP, the function about pre-deployment analysis. That shape is
expected: gove-zone governs *what an already-deployed system is allowed to do*,
not *whether it should have been deployed*.

**Two senses of "gap" — do not conflate them.** In the colloquial sense of
"gove-zone supplies no runtime evidence here", the gaps are the **5**
operator-owned rows (GOVERN 3, GOVERN 5, MAP 3, MAP 4, MEASURE 4), each marked
in-row with the phrase *"no runtime evidence — organizational control, out of
gove-zone scope"*. In the strict `compliance/control-mapping.json` status sense
— *"requirement is in scope for ACGS but not yet covered"*, i.e. a backlog
admission — the count is **0**. Those 5 rows are out of scope by design for a
runtime execution membrane, not unfinished work.

---

## Limitations — what this crosswalk does NOT prove

These are load-bearing. Every row above is bounded by all of the following.

1. **The NIST column is unverified against the source.** Category numbering and
   intent statements are paraphrased from secondary references in this repo, not
   from AI 100-1. A miscounted or misattributed category would silently
   misplace a row. Reconcile before external use — and see the divergence table
   above for two specific suspects.
2. **A mapping row is not satisfaction of a subcategory.** AI RMF categories
   decompose into subcategories (e.g. GOVERN 1.1 … 1.7) that this crosswalk does
   not enumerate. "Contributes evidence toward GOVERN 1" is not "satisfies
   GOVERN 1".
3. **Signing default is fail-closed, not auto-sign.** `require_signature=True`
   is the gate default, and a gate with no configured trusted verifier fails
   closed rather than emitting an unsigned receipt. In the explicit unsigned dev
   mode (`require_signature=False`), verification checks only the recomputable
   SHA-256 `receipt_hash`, which is forgeable under host compromise. Do not
   promote dev mode as production security (`docs/SECURITY_MODEL.md`,
   `docs/CLAIMS.md` row 19).
4. **Anti-replay, full-argument replay, and metrics are opt-in.** Stateless
   verification accepts a valid ALLOW receipt until `expires_at` unless the
   consumption ledger and/or a `ReplaySideStore` are enabled; the metrics
   wrapper is default-OFF. Any MEASURE or MANAGE row depending on these is only
   as strong as the integrator's configuration.
5. **Executor bypass is possible.** Every control binds only to calls routed
   through `GovernedExecutor` / `execute_with_receipt` / kernel `dispatch`. A raw
   tool call the integrator exposes bypasses the membrane entirely — and
   therefore bypasses every row in this document. Handler wiring is
   integrator-owned.
6. **Identity is opaque strings, not IAM/PKI.** Actor authentication, key
   custody, and key distribution are operator responsibilities; the verifier map
   is static with no certificate chain. Two identities controlled by one person
   are two principals to the kernel — so the GOVERN 2 separation-of-duties row
   is only as strong as the external identity system.
7. **Audit is local JSONL — tamper-*evident*, not tamper-*proof*.** Off-host and
   WORM durability, retention, and custody are operator concerns. MEASURE 3 and
   MANAGE 4 inherit that bound.
8. **Revocation is narrow.** Static, operator-supplied, issuer-signing-key-ID
   only. No PKI, no CRL fetch, no rotation, no per-receipt revocation, no global
   nonce service, and the workflow-envelope / plan-authorization key population
   is explicitly not yet covered.
9. **No policy lifecycle registry** beyond id + hash binding — there is no
   active/stale/revoked policy-bundle state machine.
10. **No runtime evidence was executed for this document.** The rows cite
    verification commands and test files; this crosswalk was authored by reading
    source and tests, not by running them. Run the commands below before citing
    a status as current.
11. **Not certified.** Not production-certified, not compliance-certified, not
    regulator-approved. gove-zone complements — and does not replace —
    sandboxing, content moderation, IAM/RBAC/PKI, and is not full formal
    verification — see the *not claimed* rows of `docs/CLAIMS.md`.

---

## How to verify these rows

The six JSON-backed rows carry a runnable `verification_method` in
`compliance/control-mapping.json`. Re-run the mapping's own gate with:

```
python3 compliance/engine.py validate
python3 compliance/engine.py report --run   # executes every row's tests
```

The rows this document adds beyond the JSON cite their test files directly; run
them from the package:

```
uv run --package gove-zone python -m pytest \
  packages/gove-zone/tests/test_risk_tier_policy.py \
  packages/gove-zone/tests/test_a2a_delegation.py \
  packages/gove-zone/tests/test_audit_chain_corruption.py \
  packages/gove-zone/tests/test_metrics.py \
  packages/gove-zone/tests/test_revocation.py \
  packages/gove-zone/tests/test_proofpack_revocation.py \
  packages/gove-zone/tests/test_receipt_consumption.py \
  packages/gove-zone/tests/test_consumption_tamper.py \
  --import-mode=importlib -q
```

> A passing unit test proves the control behaves as specified; it does **not**
> prove the control is wired into an integrator's execution path. See
> limitation 5.

---

## Scope boundary (one sentence)

gove-zone is the *execution-legitimacy layer* — it binds actor, action,
arguments, policy, validator, authority, and audit anchor into one verifiable
decision at the executor boundary — and is explicitly **not** the AI risk
management program that NIST AI RMF 1.0 describes.

---

## Sources

- **Authoritative control mapping:** `compliance/control-mapping.json`
  (`frameworks.nist_ai_rmf`, `controls`, `status_vocabulary`).
- **Existing summary this document extends:** `docs/COMPLIANCE_CROSSWALK.md`.
- **Claim wording ledger:** `docs/CLAIMS.md`.
- **Security posture and known bounds:** `docs/SECURITY_MODEL.md`.
- **Receipt schema:** `docs/DECISION_RECEIPT_SPEC.md`.
- **Style and provenance convention:** `docs/crosswalks/PICKEN_BOARD_AI_CYBER_CROSSWALK.md`,
  `compliance/evidence-pack/frameworks/iso-42001.md`.
- **Control evidence:** `packages/gove-zone/src/gove_zone/*.py` and
  `packages/gove-zone/tests/*.py` as cited per row.
- **Framework:** NIST AI Risk Management Framework 1.0 (NIST AI 100-1),
  functions GOVERN / MAP / MEASURE / MANAGE — **paraphrased, not reproduced;
  see § Provenance & claim-safety.**
