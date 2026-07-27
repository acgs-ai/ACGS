# Crosswalk — Picken Board-Level AI Cyber Governance → ACGS Enforcement Primitives

Maps the control families of Terence Picken's *"The Board Accountability Gap in AI
Cybersecurity: A Proposed Governance Assessment Methodology for AI Cyber Risk at
Board Level"* (SSRN 6613560, 18 Apr 2026) onto the concrete enforcement primitives
of ACGS.

## Provenance & claim-safety

- **Picken side is inferred, not quoted.** The full 16-page methodology is gated
  behind SSRN download and its "proprietary model parameters, coefficients, or
  derivations are **not** disclosed" (per the abstract). The Picken control
  families below are reconstructed from the paper's **abstract keywords** (board
  accountability, vendor dependency, attack surface governance, AI cyber risk) and
  its **reference list** (Companies Act 2006 ss.172/174; GDPR; NIS2 Art 20–21; EU AI
  Act Art 13; ISO/IEC 42001:2023; ISO/IEC 27001; NIST CSF / AI RMF / Cyber AI
  Profile IR 8596; adversarial-ML: Goodfellow, Carlini–Wagner, Barreno, Tramèr).
  Treat the "Picken control" column as *this repo's interpretation*, to be
  corrected against the source PDF.
- **Picken's own status caveat:** the framework is Phase 1 of 3, "pre-empirical",
  all scores "illustrative estimates … pending Phase 2 empirical validation." It is
  a **board assessment methodology**, not a technical control.
- **ACGS side is grounded** in `packages/gove-zone/src/gove_zone/receipt.py`
  (`DecisionReceipt` schema + `verify()`), read at draft time. No ACGS claim here
  should be read as compliance-certified or regulator-approved — ACGS is a **local
  receipt-gated kernel with a tamper-evident JSONL audit chain and opt-in Ed25519
  signing**, and nothing more is claimed.

## The one-line relationship

**Picken governs the *decision to trust an AI system* (boardroom, point-in-time
assessment). ACGS governs *each action the system takes* (runtime, per-dispatch
enforcement).** They occupy different layers of the same governance stack and
compose: a Picken board control asks *"can we evidence this?"*; an ACGS receipt is
the cryptographically replayable artifact that answers it. ACGS supplies the
**evidence substrate** a board-level methodology otherwise lacks — turning
"we assessed AI cyber risk" from a synthetic score into an auditable trail.

No shared lineage: Picken is corporate-governance/legal (JEL G32/G34/K42); ACGS is
runtime code.

---

## Table A — Picken control families → ACGS enforcement primitives

| # | Picken control family (inferred) | Board-level question it asks | ACGS primitive that produces the evidence | Where in code |
|---|---|---|---|---|
| A1 | **Board accountability** (Companies Act ss.172/174 directors' duties; agency theory, Jensen–Meckling) | *Who is answerable for this AI action, and can we prove it wasn't self-authorised?* | **MACI role separation**: `actor` (proposer) is structurally distinct from `validator_id`/`validator_role` (authority). Self-validation is rejected at issuance *and* at the gate. `authority` records the grant conferred. | `receipt.py` `Validator`, `from_record` (self-validation forbidden), `verify()` checks 2b/2c/2d |
| A2 | **Vendor dependency governance** | *Which third-party agent/tool acted, under whose authority, on what?* | Every side effect binds `actor`, `proposed_action`, `tenant_id`, `execution_boundary`, and an `argument_hash` into one hash-bound receipt. A vendor agent cannot act outside its issued receipt. `expected_actor` at the gate stops one caller replaying another's receipt. | `verify()` checks 2b (actor anchor), 5 (tenant), 6 (boundary), 10b (argument binding) |
| A3 | **Attack-surface governance** | *Is every action passing a control, and does the control fail safe?* | **Fail-closed membrane**: no valid Decision Receipt → no side effect. `DENY` and `ESCALATE` receipts can never authorise execution. Missing/empty required fields, unknown decision, or unknown action-tier all raise `ReceiptValidationError`. | `verify()` checks 1, 3, 3a, 4 |
| A4 | **AI cyber-risk assessment / scoring** (the "Picken Diamond") | *What is the residual risk, scored?* | **Not covered by ACGS** — ACGS does not score risk; it enforces per-action policy and records outcomes. ACGS is the *input evidence* to a scoring layer, not the scorer. Complementary, not overlapping. | — (gap; see §Gaps) |
| A5 | **Least-privilege / action scoping** (implied by attack-surface + NIS2 risk measures) | *Was the AI allowed to do exactly this, no more?* | **Argument + transform binding**: an `ALLOW` receipt for `write_file(path=/tmp/safe)` cannot authorise `write_file(path=/etc/shadow)` — executed args must match `argument_hash` exactly; `TRANSFORM` receipts must match the approved transformed set exactly. **Action-tier**: `explore` vs `commit`, with executor-side tier enforcement (fails closed without an authoritative tool-tier registry). | `verify()` checks 10, 10b, 10c, 3b |

## Table B — Regulatory / standards anchors (from Picken's references) → ACGS evidence

ACGS does not *certify* compliance with any of these. It produces artifacts that a
board control mapped to the regime can point to as evidence.

| Regime (Picken ref) | The obligation, in one line | ACGS artifact that supports it |
|---|---|---|
| **NIS2 Directive, Art 20–21** | Management body is responsible for cyber risk-management measures. | MACI `validator`/`authority` binding names the authorising principal per action; audit chain proves the measure ran. |
| **GDPR, Art 5 (accountability) / Art 22** | Demonstrate accountability; govern automated decisions. | Per-action receipt with `decision`, `matched_rules`, `policy_hash`, `previous_audit_hash` → replayable proof of *why* an automated action was allowed/denied. |
| **EU AI Act, Art 13 (transparency)** | Traceability / record-keeping of AI system operation. | Tamper-evident JSONL chain (`previous_audit_hash` → `audit_event_hash`); receipts are the unit of replay. |
| **ISO/IEC 42001:2023 (AI management system)** | Documented, auditable AI operational controls. | `policy_bundle_id` + `policy_version` + `policy_hash` bind each action to a specific policy revision; `expires_at` bounds receipt lifetime. |
| **NIST CSF / AI RMF / Cyber AI Profile (IR 8596)** | Identify-Protect-Detect-Respond over AI risk. | ACGS covers **Protect** (fail-closed gate) and **Detect** (audit chain); does not cover Identify/Respond governance — those stay board-level (Picken's layer). |

## Table C — Adversarial-ML threats (Picken's references) → ACGS coverage boundary

Honest scoping: ACGS governs **actions**, not **model internals**. It does not make
a model robust; it constrains what a compromised or manipulated model is allowed to
*do*.

| Threat (Picken ref) | Does ACGS defend the model? | Does ACGS limit the blast radius? |
|---|---|---|
| Adversarial examples (Goodfellow 2014; Carlini–Wagner 2017) | No — model-layer concern. | Yes — a fooled model still cannot execute an action outside its receipt scope (Table A5). |
| Model / API theft (Tramèr 2016) | No. | Partial — `execution_boundary` + `tenant_id` binding + audit chain make exfiltration actions attributable, not prevented. |
| ML security generally (Barreno 2010) | No. | Yes — fail-closed default: unknown/denied → no side effect. |

---

## Gaps — both directions

**What Picken has that ACGS lacks:**
- A **risk-scoring / assessment methodology** (A4). ACGS enforces and records; it
  does not rate residual risk or produce a board dashboard. If a scoring layer is
  wanted, ACGS receipts are its natural input.
- **Board-process framing** — directors' duties, reporting cadence, accountability
  mapping. Out of scope for a runtime membrane.

**What ACGS has that a board methodology lacks:**
- **Cryptographic, per-action, replayable evidence.** Picken's abstract is
  explicitly synthetic and undisclosed-parameter; ACGS's ethos is the inverse —
  every governance claim must re-derive from a hash-bound receipt. ACGS is the
  falsifiable proof layer under an otherwise unverifiable assessment.
- **Enforcement, not assessment.** A board score is point-in-time; ACGS runs on
  every dispatch and fails closed.

## Honest limitations of this crosswalk

1. Picken control families are reconstructed from abstract + references, not the
   gated methodology. Re-map against the source PDF before relying on it.
2. ACGS "evidence supports regime X" is a mapping claim, **not** a certification.
   ACGS is not compliance-certified or regulator-approved.
3. Signature-based non-repudiation (Ed25519) is **opt-in and off by default** —
   default deployments are unsigned (`signature_algorithm="none"`). The strongest
   evidence claims in Tables A/B hold fully only with a private-key signer + a
   configured public-key verifier + `require_signature=True`.

---

*Sources:* Picken abstract & references — SSRN 6613560 (retrieved via browser,
PDF body gated). ACGS — `packages/gove-zone/src/gove_zone/receipt.py`.
