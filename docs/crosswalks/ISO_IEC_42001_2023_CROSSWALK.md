# ISO/IEC 42001:2023 crosswalk — evidence toward an AI management system

> **What this is.** A mapping from gove-zone's *enforced runtime controls* to the
> management-system clauses (4–10) and the Annex A control groups of **ISO/IEC
> 42001:2023**, the AI management system (AIMS) standard. It is the ISO 42001
> sibling of `docs/COMPLIANCE_CROSSWALK.md` (NIST AI RMF 1.0, NIST CSF 2.0, MITRE
> ATLAS, OWASP LLM / Agentic AI) and `docs/EU_AI_ACT_MAPPING.md` (EU AI Act
> Article 12).
>
> **What this is NOT.** This is a self-assessment mapping, not a certification,
> attestation, or audit result. gove-zone is **alpha / local-proof** software
> (see `docs/SECURITY_MODEL.md`). ISO 42001 certifies an *organization's*
> management system; a software component cannot itself be ISO 42001 certified.
> Mapping a clause means "the receipt membrane produces *evidence toward* that
> clause's outcome at the executor boundary" — it does **not** mean adopting
> gove-zone makes an organization conformant. Conformity is a property of an
> organization and its full control set, assessed by a certification body;
> gove-zone is one layer (the execution-legitimacy membrane), not the AIMS.

## Relationship to the existing ISO 42001 material in this repo

ISO 42001 is **partially covered already**. `compliance/control-mapping.json`
(framework key `iso_42001`) defines six Annex A requirement rows, rendered into
`compliance/evidence-pack/frameworks/iso-42001.md` as part of the ACGS Compliance
Evidence Pack. That artifact is **generated — do not hand-edit it**; it is
regenerated with `compliance/evidence_pack.py`.

This document does **not** restate or supersede those rows. It:

1. cites `compliance/control-mapping.json` as the authoritative source for the
   six Annex A requirement rows (`ISO42001-A2.2`, `A3.2`, `A6.2.6`, `A6.2.8`,
   `A8.2`, `A9.2`), including their per-row `verification_method` commands; and
2. adds what the generated pack does not cover — the **management-system clauses
   4–10**, including the clauses where gove-zone supplies **no** evidence.

Where this document and the generated pack disagree in wording, the generated
pack's `status` vocabulary and per-row limitations govern for Annex A rows.

## Core invariant being mapped

**No valid Decision Receipt, no side effect.** This receipt-validation claim
describes the receipt-gated execution path, `GovernedExecutor` /
`execute_with_receipt`: there, a registered tool executes only
when a receipt passes the full executor gate: it exists; was issued for *this*
caller (actor anchor); is hash-intact (and signature-valid when it claims a
signature); is ALLOW/TRANSFORM (not DENY/ESCALATE/expired); and its tenant,
boundary, action, and *exact arguments* all match what the executor is about to
do — minted by a validator distinct from the proposer. The receipt's carried
policy hash, policy bundle id, and audit-event hash are compared **only against
caller-supplied expectations** (`expected_policy_hash`,
`expected_policy_bundle_id`, `expected_audit_hash`, all defaulting to `None`,
in which case those comparisons are skipped): a `GovernedExecutor` bound to a
policy derives `expected_policy_hash` automatically, and the escalation gateway
/ governed-MCP gateway pin `expected_audit_hash` at resume, but an integration
relying on the bare defaults gets hash-bound *carried claims*, not
independently gate-enforced bindings. Any failed check raises
`ReceiptValidationError` **before** the tool runs.

**Kernel dispatch is a separate, policy-before-effect path; it is not the
executor gate.** `Kernel.dispatch` (`kernel.py`) evaluates policy and appends
the decision to the audit chain before invoking the registered tool directly,
raises on DENY/ESCALATE, and fail-closes (synthesized DENY / `AuditError`) on
policy or audit failure. But no `DecisionReceipt` passes the executor's actor,
signature, expiry, or receipt-hash gate on this path: the lightweight
`Receipt` it returns is constructed only *after* the tool has run, as a record
of the executed call, not a pre-execution credential. Rows below that cite
`kernel.py` map to these policy-before-effect and fail-closed properties; the
full receipt-validation guarantees above belong to `GovernedExecutor` /
`execute_with_receipt` only.

Evidence: `packages/gove-zone/src/gove_zone/{receipt,executor,kernel,audit,policy,signing,consumption}.py`.

## Control inventory (anchored, not redefined here)

The control identifiers used in the mapping table below are **the inventory in
`docs/COMPLIANCE_CROSSWALK.md` § "Control inventory"** — RECEIPT-REQUIRED,
ACTOR-ANCHOR, HASH-INTEGRITY, SIG-VERIFY, DECISION-GATE, ARG-BIND,
POLICY/TENANT/BOUNDARY/ACTION/AUDIT-BIND, MACI-VALIDATOR-SEP, POLICY-BEFORE-EXEC,
FAILCLOSED-POLICY/AUDIT, AUDIT-HASHCHAIN, EXPIRY, SIG-REQUIRED, ANTI-REPLAY,
REPLAY-VERIFY. Read that table for each control's enforcement statement, evidence
file, and default. It is not duplicated here, so the two crosswalks cannot drift.

**One additional control is cited below.** `ESCALATE-HUMAN` is defined in
`compliance/control-mapping.json`, **not** in the `docs/COMPLIANCE_CROSSWALK.md`
inventory. Its recorded definition says ESCALATE decisions "route to human
authority"; what the runtime actually enforces
(`packages/gove-zone/src/gove_zone/escalation.py`, `approve_escalation()`) is
routing to an **integrator-supplied distinct validator**: the escalation is not
executable until approved, and the only machine-enforced property of the
approver is that its opaque `validator_id` differs from the proposer's. No
authentication or human-credential check is performed, so an integrator may
wire an automated validator; authenticated *human* involvement is
operator-owned (gap 6). The control is used here because the generated ISO
42001 Annex A rows already cite it; it is flagged rather than silently promoted
into the anchor inventory.

### Control-identifier alias map

Two vocabularies for the same controls exist in this repo. A reader
cross-referencing this document against `compliance/evidence-pack/frameworks/iso-42001.md`
needs this table:

| `docs/COMPLIANCE_CROSSWALK.md` identifier (used here) | `compliance/control-mapping.json` identifier |
|---|---|
| POLICY/TENANT/BOUNDARY/ACTION/AUDIT-BIND | `POLICY-TENANT-BIND` |
| FAILCLOSED-POLICY/AUDIT | `FAILCLOSED` |
| *(not in the crosswalk inventory)* | `ESCALATE-HUMAN` |

All other identifiers are spelled identically in both sources.

### Note on signing defaults

Where SIG-REQUIRED appears below, the wording follows `docs/CLAIMS.md` row 19:
`require_signature=True` **is** the default profile, and a gate with no
configured trusted verifier **fails closed** (raises `ProductionProfileError`)
rather than emitting an unsigned receipt — it does **not** auto-sign. Unsigned
"dev mode" is an explicit opt-out via `require_signature=False`. (The
`"opt-in"` default recorded for `SIG-REQUIRED` in `compliance/control-mapping.json`
describes the opt-in nature of *supplying keys*, and reads as contradicting
CLAIMS.md row 19; row 19 and `docs/COMPLIANCE_CROSSWALK.md` limitation 1 are
authoritative for public wording.)

## Mapping to ISO/IEC 42001:2023 clauses

Clause numbers and titles follow the publicly available ISO/IEC 42001:2023
table of contents (Clause 6 ends at 6.3 *planning of changes*; Clause 8
comprises 8.1–8.4 and ends at 8.4 *AI system impact assessment* — there is no
Clause 8.5; Clause 10 comprises 10.1 *continual improvement* and 10.2
*nonconformity and corrective action* — there is no Clause 10.3). **The full
ISO/IEC 42001:2023 published text was not consulted** —
no verbatim clause text is reproduced or paraphrased from the standard, and the
normative requirement wording behind each clause title is not verified against
the published document. Every row is therefore a mapping to the *clause theme*,
not to verified normative requirement text. See "Limitations and gaps".

| Clause | Clause theme | Mapped gove-zone control(s) | Evidence | Limitation |
|---|---|---|---|---|
| **4.1** | Understanding the organization and its context | — | — | No runtime evidence — organizational control, outside gove-zone's scope. Establishing organizational context is a human determination the gate neither performs nor records. |
| **4.2** | Understanding the needs and expectations of interested parties | — | — | No runtime evidence — organizational control, outside gove-zone's scope. |
| **4.3** | Determining the scope of the AI management system | POLICY/TENANT/BOUNDARY/ACTION/AUDIT-BIND | `receipt.py`, `tenant.py`; `tests/test_tenant_safety.py` | Evidence toward the clause theme only. Each governed decision records the tenant and execution boundary it belongs to, making the *technically governed* perimeter explicit and machine-checkable — but the AIMS scope statement (which systems, sites, and functions are in scope) is an organizational declaration. Anything not routed through the gate is outside this evidence entirely (see gap 3). |
| **4.4** | AI management system (establish, implement, maintain, continually improve) | RECEIPT-REQUIRED, POLICY-BEFORE-EXEC, AUDIT-HASHCHAIN | `executor.py`, `kernel.py`, `audit.py`; `tests/test_executor_guard.py`, `tests/test_kernel_dispatch.py` | Evidence toward the clause theme only. gove-zone is an *enforcement and evidence point* that an AIMS can use; it is not the AIMS, and it establishes no processes, interfaces, or management structure of its own. |
| **5.1** | Leadership and commitment | — | — | No runtime evidence — organizational control, outside gove-zone's scope. |
| **5.2** | AI policy | POLICY/TENANT/BOUNDARY/ACTION/AUDIT-BIND, POLICY-BEFORE-EXEC | `policy.py`, `kernel.py`, `receipt.py`; `tests/test_policy_bundle_io.py`, `tests/test_kernel_dispatch.py` | Evidence toward the clause theme only, and the strength of the policy binding differs by path. On the receipt path, the policy bundle is bound by id + version + hash into every issued `DecisionReceipt` (`policy_bundle_id` + `policy_version` + `policy_hash`, `receipt.py`), so *which* bundle authorized a decision is demonstrable from the receipt. On the kernel path, policy is evaluated before any tool runs, but the `Kernel.dispatch` audit record (`DecisionRecord`, `decision.py`) carries `policy_version` only (`Kernel` receives neither a bundle id nor a policy hash), so a kernel audit record demonstrates version-pinned policy-before-effect enforcement, not id/hash binding. The organizational AI policy document, its approval, and its communication are operator-owned. Consistent with `ISO42001-A2.2` in `compliance/control-mapping.json`. |
| **5.3** | Roles, responsibilities and authorities | MACI-VALIDATOR-SEP, ACTOR-ANCHOR | `receipt.py`, `tenant.py`; `tests/test_maci_role_separation.py`, `tests/test_executor_guard.py` | Evidence toward the clause theme only. Proposer ≠ validator is machine-enforced at issuance and again at the gate, and the caller identity must equal `receipt.actor` (no self-authorization). Identity is opaque strings supplied by the integrator runtime — the check proves *distinctness of identifiers*, not authenticated persons or org-chart authority (gap 5). Consistent with `ISO42001-A3.2`. |
| **6.1** | Actions to address risks and opportunities | FAILCLOSED-POLICY/AUDIT, DECISION-GATE | `kernel.py`, `receipt.py`; `tests/test_fail_closed.py`, `tests/test_fail_closed_gaps.py` | Evidence toward the clause theme only. Fail-closed synthesis of DENY on policy exception/timeout and `AuditError` on audit-append failure are *implemented risk responses at the action boundary*; identifying and prioritizing the risks themselves is organizational planning the gate does not perform. |
| **6.2** | AI objectives and planning to achieve them | — | — | No direct mapping identified. Objective-setting is organizational; gove-zone records decisions, not objectives, and forcing a mapping here would overstate. |
| **6.3** | Planning of changes | HASH-INTEGRITY, POLICY/TENANT/BOUNDARY/ACTION/AUDIT-BIND | `receipt.py`, `policy.py`; `tests/test_policy_bundle_io.py`, `tests/test_decision_receipt.py` | Evidence toward the clause theme only. Binding `policy_bundle_id` + `policy_version` + `policy_hash` into every receipt blocks *unauthorized policy substitution at decision time* and makes a policy change visible as a hash change in the audit chain. There is **no policy lifecycle, approval, or revocation registry** beyond id + hash binding (gap 8), so planning and controlling the change itself is operator-owned. |
| **7.1** | Resources | — | — | No runtime evidence — organizational control, outside gove-zone's scope. |
| **7.2** | Competence | — | — | No runtime evidence — organizational control, outside gove-zone's scope. Competence of personnel is not observable at the executor boundary. |
| **7.3** | Awareness | — | — | No runtime evidence — organizational control, outside gove-zone's scope. |
| **7.4** | Communication | — | — | No direct mapping identified. Structured rejection reason codes (`rejection.py`, `tests/test_structured_rejection.py`, `tests/test_gate_reason_codes.py`) communicate a governance outcome to the *calling runtime*, which is caller-facing decision feedback — not the internal/external AIMS communication this clause concerns. Mapping it would be a forced fit. |
| **7.5** | Documented information (creation, update, and control of) | AUDIT-HASHCHAIN, RECEIPT-REQUIRED, HASH-INTEGRITY, SIG-VERIFY, SIG-REQUIRED, REPLAY-VERIFY | `audit.py`, `receipt.py`, `signing.py`, `_locking.py`, `replay.py`, `replay_store.py`; `tests/test_audit_chain.py`, `tests/test_audit_chain_corruption.py`, `tests/test_decision_receipt.py`, `tests/test_receipt_signing.py`, `tests/test_profile.py`, `tests/test_replay.py`, `tests/test_replay_store.py` | Evidence toward the clause theme only, and only for the decision record it produces. Append-only JSONL with `previous_hash`→`event_hash`, `flock` + fsync, and `verify_chain()` re-walk gives *controlled, tamper-evident* documented information; receipt-hash recomputation rejects any *inconsistent* field edit, and a claimed signature must verify (Ed25519). **Unsigned packs get integrity, not authenticated tamper resistance**: `receipt_hash` is an unkeyed SHA-256, so an editor who rewrites bound fields and recomputes the hash produces a self-consistent record that hash binding alone accepts; the bare receipt primitive defaults `require_signature=False`, and offline verification accepts unsigned packs when no trust anchor or signature requirement is supplied. Only a signature verified against an independently obtained trusted key (SIG-VERIFY, enforced via SIG-REQUIRED) rejects a consistent rewrite. Each governed side effect leaves a hash-chained operational record from which the decision can be re-derived — audit-only replay is policy-version-only; strong replay of full arguments requires the opt-in side store (`docs/CLAIMS.md` row 17), and raw arguments are hashed, not stored, by design (gap 9). It is tamper-**evident**, not tamper-**proof**: retention, off-host/WORM durability, and custody are operator-owned (gap 7). |
| **8.1** | Operational planning and control | RECEIPT-REQUIRED, POLICY-BEFORE-EXEC, DECISION-GATE, ARG-BIND | `executor.py`, `kernel.py`, `receipt.py`; `tests/test_executor_guard.py`, `tests/test_argument_binding.py`, `tests/test_kernel_dispatch.py` | Evidence toward the clause theme only, and the strongest fit in this document. Policy is evaluated and audited before any tool runs; DENY/ESCALATE/unknown decisions cannot authorize execution; executed arguments must hash to `argument_hash` (ALLOW) or equal the approved transformed set (TRANSFORM). Bounded by the executor-bypass gap (gap 3). |
| **8.2** | AI risk assessment | — | — | No direct mapping identified. Performing risk assessments at planned intervals is an organizational process; the gate consumes a policy that encodes risk decisions, it does not assess risk. |
| **8.3** | AI risk treatment | FAILCLOSED-POLICY/AUDIT, DECISION-GATE, ESCALATE-HUMAN, EXPIRY, ANTI-REPLAY | `kernel.py`, `receipt.py`, `escalation.py`, `consumption.py`; `tests/test_fail_closed.py`, `tests/test_escalation_resume.py`, `tests/test_receipt_expiry.py`, `tests/test_receipt_consumption.py` | Evidence toward the clause theme only. The receipt membrane *is* a treatment control: DENY is non-executable, ESCALATE is non-executable until resolved and routes to an *integrator-supplied distinct validator* whose approval is itself a governed, audit-chained decision — the runtime enforces only that the approver's opaque `validator_id` differs from the proposer's (no authentication or credential-type check, so proving a *person* approved is an explicit operator-owned requirement; gap 6) — expiries fail closed when set, and single-use enforcement burns a receipt's audit anchor before execution. EXPIRY is an opt-in field and ANTI-REPLAY is an opt-in ledger (gap 4); selecting treatments and accepting residual risk are organizational. `ESCALATE-HUMAN` is a `control-mapping.json` identifier — see the alias map. |
| **8.4** | AI system impact assessment | — | — | No direct mapping identified. Impact assessment is a design-time organizational activity on the AI system as a whole; gove-zone governs individual side effects at execution time and performs no assessment of impacts on individuals or society. |
| **9.1** | Monitoring, measurement, analysis and evaluation | AUDIT-HASHCHAIN, REPLAY-VERIFY | `audit.py`, `replay.py`, `metrics.py`; `tests/test_audit_chain.py`, `tests/test_replay.py`, `tests/test_metrics.py` | Evidence toward the clause theme only. The hash chain plus replay supply the measurable, verifiable inputs a monitoring programme consumes; `metrics.py` derives receipt-emission signals but is **default-OFF** (enabled by `GOVE_ZONE_METRICS`) and deliberately leak-safe (timestamp, decision, tool, `argument_hash`, `event_id` only). Dashboards, alerting thresholds, evaluation criteria, and review cadence are operator-owned. Consistent with `ISO42001-A6.2.6`. |
| **9.2** | Internal audit | AUDIT-HASHCHAIN, REPLAY-VERIFY, HASH-INTEGRITY | `audit.py`, `cli.py`, `verifier.py`, `proofpack.py`; `tests/test_cli.py`, `tests/test_audit_chain_corruption.py`, `tests/test_proofpack_schema.py` | Evidence toward the clause theme only, and narrower than it first appears. What an internal auditor can independently re-check **without system access** is receipt-hash binding and audit-chain integrity. Offline replay is **not** in that set: `compliance/evidence-pack/frameworks/iso-42001.md` records that the shipped pack omits the policy bundle and side store, so offline `acgs proofpack verify` reports the replay as `recorded` — a generator attestation, not an independent re-derivation — unless the material is supplied via `--policy-bundle` / `--side-store`. The same source lists REPLAY-VERIFY, DECISION-GATE, ESCALATE-HUMAN and FAILCLOSED among the controls that ALLOW-only pack does not independently demonstrate. These are **point-in-time local evaluations**; the internal audit programme, auditor independence, and audit scheduling are organizational. |
| **9.3** | Management review | — | — | No runtime evidence — organizational control, outside gove-zone's scope. The audit chain can be an *input* to a management review, but the review itself is a leadership activity the gate neither performs nor records. |
| **10.1** | Continual improvement | — | — | No runtime evidence — organizational control, outside gove-zone's scope. |
| **10.2** | Nonconformity and corrective action | FAILCLOSED-POLICY/AUDIT, DECISION-GATE, ESCALATE-HUMAN, AUDIT-HASHCHAIN, HASH-INTEGRITY | `kernel.py`, `escalation.py`, `audit.py`, `revocation.py`; `tests/test_fail_closed.py`, `tests/test_audit_chain_corruption.py`, `tests/test_escalation_resume.py`, `tests/test_revocation.py` | Evidence toward the clause theme only. A nonconforming action is *detected and blocked at the boundary* rather than corrected after the fact: chain corruption and receipt-hash mismatch are detectable on verify, ESCALATE routes to resolution by an integrator-supplied distinct validator (human involvement is operator-owned; gap 6), and a compromised signing key can be revoked at the gate independently of verifier-map membership. Detection is **on-verify, not continuous**; the corrective-action process, root-cause analysis, and nonconformity register are operator-owned. |
| **Annex A.2** | AI policy (control group) | POLICY/TENANT/BOUNDARY/ACTION/AUDIT-BIND, POLICY-BEFORE-EXEC | `compliance/control-mapping.json` row `ISO42001-A2.2`; `policy.py`; `tests/test_policy_bundle_io.py` | Mapped in the generated evidence pack at status **partial**. See `compliance/evidence-pack/frameworks/iso-42001.md` for the authoritative row and its `verification_method`. Only the `A.2.2` identifier is attested by an in-repo source; other controls in this group are not enumerated (gap 2). |
| **Annex A.3** | Internal organization / AI roles and responsibilities (control group) | MACI-VALIDATOR-SEP, ACTOR-ANCHOR | `compliance/control-mapping.json` row `ISO42001-A3.2`; `receipt.py`, `tenant.py`; `tests/test_maci_role_separation.py`, `tests/test_tenant_safety.py` | Mapped in the generated evidence pack at status **implemented**. Only `A.3.2` is attested in-repo. |
| **Annex A.6** | AI system life cycle (control group) | AUDIT-HASHCHAIN, REPLAY-VERIFY, FAILCLOSED-POLICY/AUDIT, RECEIPT-REQUIRED | `compliance/control-mapping.json` rows `ISO42001-A6.2.6` (partial), `ISO42001-A6.2.8` (implemented); `audit.py`, `replay.py`, `kernel.py` | Mapped in the generated evidence pack. Life-cycle coverage is operation-and-logging only — gove-zone contributes nothing to design, data management, or verification-and-validation controls within this group. Only `A.6.2.6` and `A.6.2.8` are attested in-repo. |
| **Annex A.8** | Information for interested parties (control group) | — *(documentation evidence, no runtime control)* | `compliance/control-mapping.json` row `ISO42001-A8.2`; `docs/DECISION_RECEIPT_SPEC.md`, `docs/SECURITY_MODEL.md`, `docs/CLAIMS.md` | Mapped in the generated evidence pack at status **implemented** with **no ACGS runtime controls** — the evidence is documentation review, not enforcement. Documentation covers the governance component only; whole-system documentation for users is the integrator's. |
| **Annex A.9** | Use of AI systems (control group) | DECISION-GATE, ESCALATE-HUMAN | `compliance/control-mapping.json` row `ISO42001-A9.2`; `receipt.py`, `escalation.py`; `tests/test_escalation_resume.py` | Mapped in the generated evidence pack at status **partial**. Non-executable DENY and ESCALATE-to-distinct-validator (authenticated human involvement is operator-owned; gap 6) are enforcement primitives *inside* a responsible-use process the organization must define. Only `A.9.2` is attested in-repo. |

**Row totals.** 29 rows: 17 with a mapping, 12 with none (`4.1`, `4.2`, `5.1`,
`6.2`, `7.1`, `7.2`, `7.3`, `7.4`, `8.2`, `8.4`, `9.3`, `10.1`).

## Limitations and gaps — do not overstate (read before citing this doc)

These are load-bearing. A mapped row means "contributes evidence toward the
clause theme," bounded by all of the following.

1. **Clause-level theme mapping, not verified against the full ISO 42001
   published text.** The ISO/IEC 42001:2023 standard is a paid publication and
   its full text was not consulted. Clause numbers and titles follow the
   publicly available ISO/IEC 42001:2023 table of contents (6.3 is *planning of
   changes*; Clause 8 is 8.1–8.4, ending at *AI system impact assessment*;
   Clause 10 is 10.1 *continual improvement* and 10.2 *nonconformity and
   corrective action*); no
   normative requirement text is reproduced or paraphrased, and the requirement
   wording behind each title is **not** verified against the published
   document. Verify against a licensed copy before relying on a specific clause
   reference.
2. **Annex A is not fully enumerated.** Only the five control groups whose
   identifiers are attested by an in-repo source (`compliance/control-mapping.json`:
   `A.2.2`, `A.3.2`, `A.6.2.6`, `A.6.2.8`, `A.8.2`, `A.9.2`) are listed. ISO 42001
   Annex A contains further control groups; they are omitted here rather than
   invented, and their omission is **not** a claim that gove-zone has no bearing
   on them.
3. **gove-zone is one layer, not the AI management system.** An AIMS spans
   leadership, competence, planning, communication, and review — none of which a
   runtime membrane can supply. Twelve of the twenty-nine rows above have no
   gove-zone evidence at all, by design.
4. **Executor-bypass is possible.** Controls bind only to calls routed through
   `GovernedExecutor` / `execute_with_receipt` / kernel `dispatch` (the first
   two receipt-gated; kernel `dispatch` is the policy-before-effect path
   described under "Core invariant being mapped", with no receipt gate). A raw tool
   call the integrator exposes bypasses the membrane entirely — handler wiring is
   integrator-owned. `tests/test_gate_wiring_matrix.py` statically checks only
   the examples the integration matrix labels "Shipped + tested"
   (`docs/CLAIMS.md` row 28), not every integrator wiring.
5. **Several cited controls are opt-in, not default-on.** EXPIRY is an opt-in
   receipt field; ANTI-REPLAY (`consumption.py`) and full-argument REPLAY-VERIFY
   (side store) are opt-in; `metrics.py` is default-OFF. Stateless verification
   accepts a valid ALLOW receipt until `expires_at` unless the consumption ledger
   is enabled.
6. **Identity is opaque strings, not IAM/PKI.** Actor authentication, key
   custody/distribution, and revocation of *caller* credentials are operator
   responsibilities; the verifier map is static with no certificate chain.
   `revocation.py` covers **issuer/signing** key ids only — not caller
   credentials, and not the workflow-envelope or plan-authorization key
   population. The identity adapters bundled in `identity.py` are in-memory mocks
   (`docs/CLAIMS.md` row 34): no OAuth/OIDC/SAML exchange, no JWKS/SCIM.
7. **Audit is local JSONL, tamper-evident, not tamper-proof.** Off-host / WORM
   durability, retention periods, and custody are operator concerns. Tamper
   detection is **on-verify**, not continuous monitoring.
8. **No policy lifecycle, approval, or revocation registry** beyond id + hash
   binding — a material bound on the Clause 6.3 (planning of changes) row.
9. **Raw input data is hashed, not stored.** `argument_hash` proves *which*
   inputs produced a decision without retaining them (data minimisation). Where a
   clause is read to require retention of the inputs themselves, the receipt is
   intentionally insufficient and an opt-in side store is required.
10. **No third-party audit, certification, or conformity assessment.** Nothing in
    this document has been reviewed by a certification body, notified body,
    auditor, or regulator. gove-zone is **not** production-certified, **not**
    compliance-certified, and **not** regulator-approved — see the "not claimed"
    rows of `docs/CLAIMS.md` (rows 29–31). ISO 42001 certification is issued to an
    organization by an accredited certification body against its whole AIMS; no
    software component can hold or confer it.

## Scope boundary (one sentence)

gove-zone is the *execution-legitimacy layer* — it binds actor + action +
arguments + policy + validator + authority + audit into one verifiable decision
at the executor boundary — and is explicitly **not** the AI management system
ISO/IEC 42001 describes.

## Safe public wording

"gove-zone's enforced runtime controls produce evidence toward the operational
and record-keeping themes of ISO/IEC 42001:2023 (notably Clauses 6.3, 7.5, 8.1,
8.3, 9.1 and 9.2, and the Annex A controls listed in the ACGS Compliance
Evidence Pack); it is a self-assessment clause-theme mapping, not verified
against the published ISO text, and it is neither an ISO 42001 certification nor
a claim that an adopting organization's AI management system is conformant."

## Sources

- Control inventory anchor: `docs/COMPLIANCE_CROSSWALK.md` § "Control inventory".
- Claim register and safe wording: `docs/CLAIMS.md`, `docs/POSITIONING.md`.
- Sibling crosswalk (EU AI Act Article 12): `docs/EU_AI_ACT_MAPPING.md`.
- Existing ISO 42001 Annex A rows (authoritative, generated):
  `compliance/control-mapping.json` (framework `iso_42001`) →
  `compliance/evidence-pack/frameworks/iso-42001.md`. Regenerate with
  `compliance/evidence_pack.py`; do not hand-edit the rendered file.
- Control evidence: `packages/gove-zone/src/gove_zone/*.py`;
  `packages/gove-zone/tests/test_*.py`; `docs/SECURITY_MODEL.md`;
  `docs/DECISION_RECEIPT_SPEC.md`.
- Framework structure: the publicly available ISO/IEC 42001:2023 table of
  contents (Clauses 4–10, harmonized-structure lineage shared with ISO 9001 /
  ISO 27001). The full ISO/IEC 42001:2023 published text was not consulted.
