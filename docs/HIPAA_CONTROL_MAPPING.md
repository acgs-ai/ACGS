# HIPAA Security Rule — ACGS Control Mapping

> **Scope, read this first.** ACGS / gove-zone and clinicalguard provide
> **technical controls that support** a covered entity's or business associate's
> compliance with the HIPAA Security Rule. They are **not** a HIPAA
> certification, attestation, or regulator approval, and installing them does
> **not** make a system "HIPAA compliant." HIPAA compliance is a property of an
> *organization and its deployment* — it requires a signed Business Associate
> Agreement (BAA), encryption in transit and at rest, identity/authentication
> infrastructure, and administrative and physical safeguards that software alone
> cannot provide. This document maps where ACGS controls *align with* specific
> Security Rule safeguards, and is explicit about what the covered entity still
> owns.

Authoritative references: [45 CFR §164.312 (eCFR)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312)
· [HHS Summary of the Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html).

## What ACGS brings to the table

- **gove-zone** — a receipt-gated governance membrane: policy gate, fail-closed
  executor, hash-chained audit store, single-use Decision Receipts, replay /
  proof-pack verification, and receipt signing.
- **clinicalguard** — a published A2A service for clinical decision support that
  validates proposed clinical actions against a Healthcare AI Constitution,
  exposes a HIPAA-rule checking skill, and writes a tamper-evident hash-chained
  audit trail. *(It checks actions against HIPAA-derived rules; it does not
  certify compliance.)*

## Technical safeguards (§164.312) — mapping

Maturity: **supports** = a runnable, tested control that directly addresses the
safeguard; **partial** = contributes but does not fully satisfy it; **customer**
= the safeguard is primarily the covered entity's deployment/organization to own.

| Security Rule safeguard | ACGS / clinicalguard control | File / evidence | Maturity | What the covered entity still owns |
|---|---|---|---|---|
| **§164.312(b) Audit controls** — record and examine activity in systems with ePHI | Hash-chained audit store + Decision Receipts for every gated action; clinicalguard tamper-evident audit | `packages/gove-zone/src/gove_zone/audit.py`; `packages/gove-zone/src/gove_zone/receipt.py` | **supports** | Log retention/WORM storage, review cadence, SIEM integration |
| **§164.312(c)(1) Integrity** — protect ePHI from improper alteration/destruction | Single-use receipts + hash chain detect tampering; replay / proof-pack verifier | `packages/gove-zone/src/gove_zone/replay.py`; `packages/gove-zone/src/gove_zone/replay_store.py` | **supports** (for governed decisions/audit) | Integrity of the ePHI data store itself (DB/object store) |
| **§164.312(a)(1) Access control** — allow access only to authorized persons/software | Policy gate (allow/deny/escalate) + fail-closed executor binds the *expected actor* before a side effect runs | `packages/gove-zone/src/gove_zone/policy.py`; `packages/gove-zone/src/gove_zone/executor.py` | **partial** (authorizes *actions*; not a full access-control system) | Unique user IDs, automatic logoff, emergency access, encryption/decryption (§164.312(a)(2)) |
| **§164.312(d) Person or entity authentication** | ACGS *consumes* an authenticated principal and binds it to the decision; it does not establish identity | `packages/gove-zone/src/gove_zone/integration.py` (expected-actor binding) | **partial** | The authentication system (IAM/SSO/MFA) that proves who the principal is |
| **§164.312(e)(1) Transmission security** | Receipt signing provides integrity/authenticity of decision artifacts | `packages/gove-zone/src/gove_zone/signing.py` | **partial** (artifact integrity, not channel encryption) | TLS / encryption-in-transit for ePHI itself (§164.312(e)(2)(ii)) |

## What ACGS does **not** provide (the covered entity owns these)

- **A Business Associate Agreement (BAA)** — a legal instrument (§164.308(b),
  §164.314(a)); software cannot supply it.
- **Encryption at rest** and **TLS in transit** for ePHI — deployment/infra.
- **Identity & authentication** (IAM, SSO, MFA) — ACGS consumes a principal, it
  does not authenticate one.
- **Administrative safeguards** (§164.308): risk analysis, workforce training,
  sanction policy, contingency planning.
- **Physical safeguards** (§164.310): facility access, device/media controls.
- **Breach notification** process (§164.400–414) and **minimum-necessary**
  data-layer enforcement.

ACGS produces audit evidence that *supports* several of the above (e.g. a risk
analysis or an audit review can cite the hash-chained receipts), but it does not
discharge the obligation.

## Honest readiness summary

ACGS's strongest, defensible HIPAA value is **§164.312(b) audit controls** and
**§164.312(c)(1) integrity** — both `supports`-grade, backed by runnable code.
Access control and authentication are `partial`: ACGS governs *what actions may
execute*, but relies on the deployment for *who* the actor is and for
encryption. Any external description of this offering must say "technical
controls aligned to the HIPAA Security Rule," never "HIPAA-ready,"
"HIPAA-certified," or "HIPAA compliant."

See also: [AGENT_STACK_GOVERNANCE.md](AGENT_STACK_GOVERNANCE.md) ·
[COMPARISON.md](COMPARISON.md).
