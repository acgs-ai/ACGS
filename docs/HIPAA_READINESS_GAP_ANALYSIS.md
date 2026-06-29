# HIPAA Readiness Gap Analysis — ACGS

> **Scope, read this first.** This is an **honest internal punch list** of what
> stands between ACGS / gove-zone today and a deployment that could *credibly*
> support a covered entity or business associate under the HIPAA Security Rule.
> It is **not** a compliance assessment, a readiness attestation, or a HIPAA
> certification, and completing every ACGS-side item below would still **not**
> make a deployment "HIPAA compliant" — that remains a property of the
> organization and its full deployment. This document is deliberately explicit
> about which gaps ACGS could close in code and which the covered entity owns
> and no software can discharge.

Companion to [HIPAA_CONTROL_MAPPING.md](HIPAA_CONTROL_MAPPING.md) (the control
mapping this punch list is derived from). Authoritative references:
[45 CFR §164.308 / §164.310 / §164.312 (eCFR)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C)
· [HHS Summary of the Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html).

## How to read this

Every gap is tagged with an **owner**:

- **ACGS** — an engineering gap we could close to strengthen a `partial` row
  toward `supports`. Tracked as roadmap work.
- **Customer** — a deployment, organizational, or legal obligation the covered
  entity owns. ACGS can *produce evidence that supports* it, but cannot
  discharge it.
- **Joint** — requires an ACGS contract/adapter **and** customer wiring.

"Current state" is verified against the codebase, not aspirational.

## A. ACGS-side engineering gaps (the `partial` / `thin` rows)

| # | HIPAA safeguard | Current state (verified) | Gap | Closing action | Owner | Effort |
|---|---|---|---|---|---|---|
| A1 | §164.312(d) Authentication | `expected_actor` is **required and enforced fail-closed** at the executor gate (empty/missing principal raises before any side effect; covered by `tests/test_executor_guard.py`). ACGS *binds* a principal to the decision. | ACGS *consumes* an authenticated principal; it does not *establish* identity (no IAM/SSO/MFA). | Document the authentication contract: how a covered entity wires an OIDC/SSO principal into `expected_actor`, with a worked example. No new enforcement needed — the binding already fails closed. | Joint | S |
| A2 | §164.312(a)(1) Access control | Policy gate (allow/deny/escalate) + fail-closed executor authorize *actions* and bind the expected actor. | Authorizes *actions*, not a full access-control system; encryption/decryption (§164.312(a)(2)(iv)), unique-user-ID, automatic-logoff, emergency-access are out of scope. | Document the access-control boundary explicitly (what ACGS decides vs. what the IAM layer decides). Optionally expose a hook for per-action role checks. | Joint | M |
| A3 | §164.312(e)(1) Transmission security | `signing.py` (Ed25519) signs receipts → integrity/authenticity of decision **artifacts**. | Artifact integrity ≠ channel encryption; ACGS does not provide TLS for ePHI in transit. | Document the TLS-in-transit expectation; optionally add receipt-transit guidance. ACGS will not become a transport-encryption layer. | Customer (TLS) / ACGS (doc) | S |
| A4 | §164.312(b) Audit controls | Hash-chained audit store + single-use Decision Receipts for every gated action (`audit.py`, `receipt.py`); tamper-evidence verified by replay/proof-pack. | No log **retention/WORM** policy, no review/SIEM **export** tooling shipped. | Document a retention + SIEM-export pattern; optionally ship a read-only audit-export adapter. The capture is `supports`-grade; the operational wrap is the gap. | Joint | M |
| A5 | §164.312(c)(1) Integrity | Single-use receipts + hash chain + replay/proof-pack verifier detect tampering of **governed decisions and the audit trail**. | Does not protect the integrity of the **ePHI data store itself** (DB/object store). | Clarify the integrity boundary in the mapping doc (ACGS governs decisions, not the ePHI at rest). No code gap — a scope-clarity gap. | Customer (data store) / ACGS (doc) | S |

**A-row summary.** None of these requires weakening fail-closed behavior, and
none is a code *defect*. A1/A4 are the highest-leverage: both are mostly
documentation + a thin optional adapter that turn an already-real mechanism into
something a covered entity can wire and audit against.

## B. Customer / deployment gaps (ACGS cannot discharge these)

These are owned by the covered entity. ACGS can produce audit evidence that
*supports* several of them, but it does not satisfy the obligation.

| # | Obligation | HIPAA cite | Why software can't supply it |
|---|---|---|---|
| B1 | Signed **Business Associate Agreement (BAA)** | §164.308(b), §164.314(a) | A legal instrument between organizations. |
| B2 | **Encryption at rest** for ePHI | §164.312(a)(2)(iv) | Storage/infra layer, below ACGS. |
| B3 | **TLS / encryption in transit** for ePHI | §164.312(e)(2)(ii) | Transport layer; ACGS signs artifacts, not channels (see A3). |
| B4 | **Identity & authentication** infra (IAM/SSO/MFA) | §164.312(d) | ACGS consumes a principal (see A1); it does not prove identity. |
| B5 | **Administrative safeguards** — risk analysis, workforce training, sanction policy, contingency planning | §164.308 | Organizational process, not software. |
| B6 | **Physical safeguards** — facility access, device/media controls | §164.310 | Physical/operational. |
| B7 | **Breach notification** process | §164.400–414 | Organizational obligation. |
| B8 | **Minimum-necessary** data-layer enforcement | §164.502(b) | Owned by the application/data layer. |

ACGS's hash-chained receipts can be *cited as evidence* in a risk analysis (B5)
or an audit review (B5/A4), but citing evidence is not discharging the duty.

## C. Prioritized punch list — "credibly serve a covered entity"

Ordered for a covered-entity pilot, not for ACGS convenience.

**P0 — blocking before any ePHI touches the system**
- [ ] B1 Signed BAA in place *(customer/legal)*
- [ ] B2 Encryption at rest + B3 TLS in transit for ePHI *(customer/infra)*
- [ ] B4 ↔ A1 IAM/SSO principal wired into `expected_actor` *(joint)* — the
      binding already fails closed; this is the wiring + the contract doc.

**P1 — strengthens ACGS's defensible posture**
- [ ] A1 Authentication-contract doc with a worked OIDC/SSO → `expected_actor` example
- [ ] A4 Audit retention/WORM + SIEM-export pattern documented (optional export adapter)
- [ ] A2 Access-control boundary doc (what ACGS decides vs. the IAM layer)

**P2 — clarity / nice-to-have**
- [ ] A3 Receipt-transit encryption guidance
- [ ] A5 Integrity-boundary clarification (governed decisions vs. ePHI at rest)
- [ ] B8 Minimum-necessary policy examples for the policy gate

## D. Honest readiness verdict

ACGS's defensible HIPAA value is concentrated in **§164.312(b) audit controls**
and **§164.312(c)(1) integrity** — both `supports`-grade and backed by runnable,
tested code. The authentication and access-control rows are `partial` by design:
ACGS governs *what actions execute* and binds *which principal* they ran as
(fail-closed, tested), but it relies on the deployment to *establish* identity
and to encrypt data. The **majority of the Security Rule — every B-row — is owned
by the covered entity** and cannot be closed by ACGS at all.

Any external description of this work must say "technical controls aligned to the
HIPAA Security Rule," never "HIPAA-ready," "HIPAA-certified," or "HIPAA
compliant." Completing the P0/P1 list makes ACGS a *credible governance
component* of a HIPAA-regulated deployment; it does not make ACGS, or the
deployment, HIPAA compliant.

See also: [HIPAA_CONTROL_MAPPING.md](HIPAA_CONTROL_MAPPING.md) ·
[AGENT_STACK_GOVERNANCE.md](AGENT_STACK_GOVERNANCE.md) · [COMPARISON.md](COMPARISON.md).
