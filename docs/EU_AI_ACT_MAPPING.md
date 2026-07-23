# Decision Receipt → EU AI Act Article 12: evidence toward record-keeping

This document maps the fields and mechanisms of the gove-zone **Decision
Receipt** (`packages/gove-zone/src/gove_zone/receipt.py`, `DecisionReceipt`) to
the record-keeping / logging sub-duties of **Article 12** of the EU AI Act
(Regulation (EU) 2024/1689). It exists so a reviewer can trace, field by field,
which Article 12 obligation a receipt produces *evidence toward* — and, just as
importantly, where a receipt produces **no** such evidence.

> **Scope: evidence toward, not conformance.** This is a field-level traceability
> aid. The phrase used throughout is "evidence **toward** Article 12
> record-keeping". gove-zone is **not** "compliant", "certified", or
> "regulator-approved" — see `CLAIMS.md` rows 27–29 and the non-conformity
> disclaimer at the foot of this page. Article 12 is a *logging-and-traceability*
> obligation; the receipt is one input to satisfying it, never a determination
> that it is satisfied.

Field bindings below cite `receipt.py` by line. Terminology follows
`DECISION_RECEIPT_SPEC.md`; claim wording follows the bounded-claims rule in
`CLAIMS.md`.

## What Article 12 requires (canonical sub-duties)

Article 12 governs **automatic recording of events (logs)** over the lifetime of
a high-risk AI system. The sub-duties below are treated as canonical for this
mapping:

- **Art 12(1)** — Automatic recording of events (logs) throughout the system's
  lifetime, by technical means.
- **Art 12(2)** — Logging capabilities appropriate to the intended purpose,
  enabling a level of traceability appropriate to identify situations that may
  result in risk or substantial modification.
- **Art 12(3)(a)** — Recording of the period of each use (start date/time and end
  date/time of each use).
- **Art 12(3)(b)** — The reference database against which input data has been
  checked by the system.
- **Art 12(3)(c)** — The input data for which the search has led to a match.
- **Art 12(3)(d)** — Identification of the natural persons involved in the
  verification of the results.

(Article numbering follows the consolidated AI Act text. Sub-points (a)–(d) are
the four enumerated logging items; older drafts list them under Art 12(2)(a)–(d).
Both numberings refer to the same four items and are treated as equivalent here.)

## Mapping table

| Sub-duty | Receipt field / mechanism | Evidence toward the duty |
|---|---|---|
| **Art 12(1)** automatic event recording over lifetime | `audit_event_hash` (`receipt.py:141`), `previous_audit_hash` (`receipt.py:140`), `timestamp` (`receipt.py:139`) | Each governed decision appends a hash-chained audit event; the receipt anchors that event. The append-only hash chain (`audit.py`) is the technical means by which events are recorded automatically per decision. **Lifetime coverage is bounded** — see GAP note below. |
| **Art 12(2)** traceability to identify risk / substantial modification | `previous_audit_hash` + `audit_event_hash` (hash chain), `decision` (`receipt.py:134`), `matched_rules` (`receipt.py:135`), `policy_bundle_id` / `policy_version` / `policy_hash` (`receipt.py:132–133`), `transformations` (`receipt.py:137`) | The tamper-evident hash chain plus the bound policy identity and matched rules let a reviewer reconstruct *which policy version produced which decision*, making policy/decision drift (a substantial-modification signal) traceable. `decision` + `matched_rules` record the risk-relevant outcome of each event. |
| **Art 12(3)(a)** period of each use (start/end) | `timestamp` (`receipt.py:139`), `expires_at` (`receipt.py:143`) | `timestamp` is the ISO-8601 issuance (start) time of the governed decision; `expires_at` bounds the receipt's validity window. **PARTIAL** — the receipt records the decision instant and validity bound, not an explicit end-of-execution timestamp; for an end-of-use record an integrator must correlate the result/audit event. See GAP note. |
| **Art 12(3)(b)** reference database input data was checked against | `policy_bundle_id` (`receipt.py:132`), `policy_hash` (`receipt.py:133`), `policy_version` (`receipt.py:132`) | The "reference" the system checks input against is the **policy bundle**, identified and hash-bound by these fields. This maps the *policy* reference, not a biometric/identification reference database. **GAP for the biometric reading** of (b) — see GAP note. |
| **Art 12(3)(c)** input data for which the search led to a match | `argument_hash` (`receipt.py:147`), `matched_rules` (`receipt.py:135`), `proposed_action` (`receipt.py:128`), `subject` (`receipt.py:142`), `transformations` (`receipt.py:137`) | `matched_rules` records *which* policy rules the input matched; `argument_hash` binds the exact input arguments that produced the match (the raw inputs themselves are intentionally hashed, not stored, for minimisation). `proposed_action` and `subject` carry the action/resource the match concerned. |
| **Art 12(3)(d)** natural persons involved in verification of results | `validator_id` (`receipt.py:145`), `validator_role` (`receipt.py:146`), `authority` (`receipt.py:144`), `actor` (`receipt.py:127`), `approval_chain_summary` (`receipt.py:138`) | The MACI role separation records the **validator** (the principal that verified/authorised the result) distinct from the **actor** (proposer). `approval_chain_summary` records the proposer→validator→authority linkage. **Identity is integrator-supplied** — the receipt records the identity strings it is given; it does not itself authenticate a natural person. See GAP note. |

## GAP notes (explicit non-coverage)

These are the points where the receipt does **not** by itself satisfy the
sub-duty, stated plainly so the mapping cannot be read as overclaiming.

- **GAP — Art 12(1) lifetime coverage is not guaranteed by the receipt alone.**
  The receipt anchors per-decision events into a local, append-only JSONL hash
  chain (`audit.py`). It is tamper-evident but **not WORM storage**, and only
  records events for actions routed *through the governed executor*. "Over the
  system's lifetime" requires durable, complete retention that is an
  operator/integrator responsibility, not a property of the receipt schema.
- **GAP — Art 12(3)(a) explicit end-of-use timestamp not covered.** The receipt
  carries the decision `timestamp` and an optional `expires_at` validity bound,
  but no dedicated execution-end timestamp. End-of-use must be derived from the
  correlated result/audit record by the integrator.
- **GAP — Art 12(3)(b) biometric/identification reference database not covered.**
  These fields identify the **policy** reference checked, not a biometric or
  identity reference database. Article 12(3)(b) in its biometric-identification
  reading is **not covered** by gove-zone, which governs action side effects, not
  biometric matching.
- **GAP — Art 12(3)(d) natural-person authentication not covered.**
  `validator_id` / `actor` record identity *strings supplied by the integrator
  runtime* (see `DECISION_RECEIPT_SPEC.md` "Actor binding"). The receipt does not
  authenticate, resolve, or attest the natural person behind an identifier; that
  is an external IAM responsibility (`CLAIMS.md` row 32).
- **GAP — raw input data is hashed, not stored.** `argument_hash` proves *which*
  inputs produced a decision without retaining them. If a sub-duty is read to
  require retention of the raw input data itself, the receipt is intentionally
  insufficient (data minimisation) and a side-store is required (see
  `ROADMAP.md` / replay limitations in `CLAIMS.md` row 17).

## Non-conformity disclaimer

This mapping is **beta** (`1.0.0rc1`) developer documentation. It is **not a
compliance certification, conformity assessment, or legal advice**, and it does
**not** assert that any system using gove-zone conforms to the EU AI Act.

gove-zone provides **logging-duty support** — a structured, tamper-evident
decision record that produces *evidence toward* Article 12 record-keeping. It is
**not** a determination of conformance. Conformance under the EU AI Act depends
on the full system context (intended purpose, deployment, retention, human
oversight, the conformity-assessment route, and obligations beyond Article 12)
and must be assessed by the provider/deployer and, where required, a notified
body. Use this document to trace evidence, not to claim compliance. See
`CLAIMS.md` rows 27–29 ("not production-certified / not compliance-certified /
not regulator-approved").
