# SOC 2 — Trust Services Criteria (2017, with 2022 points of focus)

> Part of the ACGS Compliance Evidence Pack (`acgs/compliance-evidence-pack/v1`). Generated from `compliance/control-mapping.json` — do not hand-edit; regenerate with `compliance/evidence_pack.py`.

> SOC 2 reports on an organization's controls, audited by a CPA firm. ACGS is not SOC 2 attested; these rows identify criteria where ACGS runtime evidence would support an auditor's testing.

Self-assessment mapping, not a certification, attestation, or audit result. gove-zone is alpha / local-proof software. A mapping row means the receipt membrane produces evidence toward the requirement at the executor boundary; it does not mean adopting gove-zone makes a system compliant. Compliance is a property of an organization and its full control set. See docs/COMPLIANCE_CROSSWALK.md and docs/CLAIMS.md rows 27-33.

**Not compliance-certified. Not regulator-approved. Not an audit result.** This is a self-assessment mapping backed by runtime evidence: each row means gove-zone produces evidence toward the requirement at the executor boundary — it does not make an adopting system compliant.

**Coverage:** 8/8 applicable requirements are evidence-bearing (100%); 8 requirements mapped.

## Requirement → control → status

| ID | Requirement | ACGS controls | Status | Limitation |
|---|---|---|---|---|
| SOC2-CC2.1 | CC2.1 — the entity obtains/generates relevant, quality information to support the functioning of internal control | RECEIPT-REQUIRED, AUDIT-HASHCHAIN | implemented | Receipts and the hash chain are audit-quality decision evidence for governed actions only. |
| SOC2-CC4.1 | CC4.1 — ongoing and/or separate evaluations to ascertain whether internal control components are present and functioning | REPLAY-VERIFY, AUDIT-HASHCHAIN | partial | verify_chain / proofpack / replay are point-in-time local evaluations; scheduled evaluation programs are operator-owned. |
| SOC2-CC5.2 | CC5.2 — the entity selects and develops general control activities over technology to support the achievement of objectives | RECEIPT-REQUIRED, POLICY-BEFORE-EXEC, FAILCLOSED | implemented | The receipt gate is a technology control activity; entity-level control selection is organizational. |
| SOC2-CC6.1 | CC6.1 — logical access security software, infrastructure, and architectures over protected information assets | RECEIPT-REQUIRED, ACTOR-ANCHOR, POLICY-TENANT-BIND, SIG-REQUIRED | partial | Access to side effects is receipt-mediated, but actor identity is opaque strings — no IAM/PKI, key custody, or revocation; unsigned mode is the default. |
| SOC2-CC7.2 | CC7.2 — the entity monitors system components for anomalies indicative of malicious acts, natural disasters, and errors | AUDIT-HASHCHAIN, HASH-INTEGRITY | partial | Tampering is detectable (hash chain breaks, receipt hash mismatch); detection is on-verify, not continuous monitoring. |
| SOC2-CC7.3 | CC7.3 — the entity evaluates security events to determine whether they could or have resulted in a failure to meet objectives | DECISION-GATE, FAILCLOSED, ESCALATE-HUMAN | partial | DENY/ESCALATE events carry full decision context for evaluation; incident-response process is operator-owned. |
| SOC2-CC8.1 | CC8.1 — the entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures | POLICY-TENANT-BIND, HASH-INTEGRITY | partial | Policy id+hash binding blocks unauthorized policy substitution at decision time; there is no policy lifecycle/approval registry. |
| SOC2-PI1.2 | PI1.2 — system inputs are processed completely, accurately, and timely as authorized (processing integrity over inputs) | ARG-BIND, DECISION-GATE | implemented | Executed arguments must hash-match the authorized set for governed calls; ungoverned inputs are out of scope. |

## Runtime evidence in this pack

`runtime-evidence/proofpack/` is one real governed action — actor `compliance-officer` proposing `runtime.file.write`, decided **ALLOW** (receipt `ev_91173c10c1094a6c`, unsigned (development posture)) and anchored in a 2-event hash-chained audit log. It is independently re-derivable offline — receipt-hash binding and audit-chain integrity, with no system access — using:

```
acgs proofpack verify compliance/evidence-pack/runtime-evidence/proofpack
```

It is a single reference governed action, not production traffic. An ALLOW action with an integrity-verified receipt and audit chain demonstrates the **recording, binding, and integrity** controls the rows above cite:

| Control demonstrated offline | Requirement rows it substantiates |
|---|---|
| ACTOR-ANCHOR | SOC2-CC6.1 |
| ARG-BIND | SOC2-PI1.2 |
| AUDIT-HASHCHAIN | SOC2-CC2.1, SOC2-CC4.1, SOC2-CC7.2 |
| HASH-INTEGRITY | SOC2-CC7.2, SOC2-CC8.1 |
| POLICY-BEFORE-EXEC | SOC2-CC5.2 |
| POLICY-TENANT-BIND | SOC2-CC6.1, SOC2-CC8.1 |
| RECEIPT-REQUIRED | SOC2-CC2.1, SOC2-CC5.2, SOC2-CC6.1 |

Controls this framework cites that this offline ALLOW-only pack does **not** independently demonstrate (evidence boundary — verify separately): `DECISION-GATE`, `ESCALATE-HUMAN`, `FAILCLOSED`, `REPLAY-VERIFY`, `SIG-REQUIRED`.

> Decision replay was verified at generation time, but the pack omits the policy bundle and side store (retained out-of-band), so offline `acgs proofpack verify` reports the replay as `recorded` — a generator attestation, not an independent re-derivation. Supply the material from `compliance/evidence-inputs/` with `--policy-bundle`/`--side-store` to re-derive it yourself.

Blocking/deny, escalation, signing, expiry, and anti-replay controls require their own governed actions to demonstrate.

## How to verify these rows

Each row's `verification_method` in `compliance/control-mapping.json` is a runnable test command or a named documentation review. Re-run the mapping's own gate with:

```
python3 compliance/engine.py validate
python3 compliance/engine.py report --run   # executes every row's tests
```

## Status vocabulary

- **implemented** — Control is on by default and covered by tests in this repository.
- **opt-in** — Control exists and is tested but must be explicitly enabled by the integrator.
- **partial** — Control contributes evidence toward the requirement but does not satisfy it alone.
- **operator-owned** — Requirement is an organizational/operator responsibility; ACGS only supplies supporting evidence.
- **gap** — Requirement is in scope for ACGS but not yet covered.
- **not-applicable** — Requirement targets system types or obligations outside ACGS scope.
