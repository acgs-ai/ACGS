# ACGS Compliance Evidence Pack

Schema: `acgs/compliance-evidence-pack/v1`  ·  Generated: `2026-01-01T00:00:00+00:00`

Self-assessment mapping, not a certification, attestation, or audit result. gove-zone is alpha / local-proof software. A mapping row means the receipt membrane produces evidence toward the requirement at the executor boundary; it does not mean adopting gove-zone makes a system compliant. Compliance is a property of an organization and its full control set. See docs/COMPLIANCE_CROSSWALK.md and docs/CLAIMS.md rows 27-33.

**Not compliance-certified. Not regulator-approved. Not an audit result.** This is a self-assessment mapping backed by runtime evidence: each row means gove-zone produces evidence toward the requirement at the executor boundary — it does not make an adopting system compliant.

## What this pack is

One self-contained, auditor-facing bundle. It ties mapped requirements from three governance frameworks to concrete runtime evidence from a real governed action. The runtime receipt and audit chain are cryptographically hash-bound (independently re-derivable offline); the framework sheets are indexed by an unsigned SHA-256 manifest that detects corruption and casual edits (see the manifest limitation below).

## Contents

| Artifact | Path | What it is |
|---|---|---|
| EU AI Act Article 12 mapping | `frameworks/eu-ai-act-article-12.md` | Record-keeping (Art. 12 / 19 / 26(6)) requirements → ACGS controls → status |
| ISO/IEC 42001 mapping | `frameworks/iso-42001.md` | Annex A AI-management-system controls → ACGS controls → status |
| SOC 2 evidence | `frameworks/soc2.md` | Trust Services Criteria → ACGS controls → status → runtime evidence |
| Audit export | `runtime-evidence/proofpack/audit-chain.json` | The hash-chained, append-only decision log for the governed action |
| Decision receipt report | `runtime-evidence/proofpack/decision-receipt.json` + `verification-summary.md` | The Decision Receipt and its human-readable report |
| Offline proof pack | `runtime-evidence/proofpack/` | Verify with `acgs proofpack verify <dir>` — no system access needed |
| Integrity manifest | `manifest.json` | SHA-256 + byte length of every file above |

## Readiness at a glance

| Framework | Requirements | Evidence-bearing |
|---|---|---|
| EU AI Act | 7 | 4/6 (67%) |
| ISO/IEC 42001:2023 | 6 | 6/6 (100%) |
| SOC 2 | 8 | 8/8 (100%) |

## The governed action

- **Actor**: `compliance-officer`  ·  **Action**: `runtime.file.write`
- **Decision**: **ALLOW**  ·  **Receipt**: `ev_91173c10c1094a6c`  ·  **Signature**: UNSIGNED (development posture)
- **Audit chain**: 2 event(s), last hash `f60fc833e4e04366…`
- **Replay**: verified at generation (generator attestation); offline `acgs proofpack verify` reports it as `recorded` unless the out-of-band policy bundle + side store are supplied to re-derive it

## How to verify this pack

```
# 1. runtime evidence — offline, no system access
acgs proofpack verify compliance/evidence-pack/runtime-evidence/proofpack
# 2. pack integrity — every file matches its manifest digest
python3 compliance/evidence_pack.py verify compliance/evidence-pack
# 3. mapping schema + evidence paths
python3 compliance/engine.py validate
```

## Provenance and limitations

- The runtime evidence is a **single reference governed action**, committed under `compliance/evidence-inputs/`, not a sample of production traffic.
- An ALLOW action with an integrity-verified receipt + audit chain demonstrates the recording/binding/integrity controls offline. Decision replay was verified at generation time only (a generator attestation): the pack omits the policy bundle + side store, so offline verify reports it as `recorded`, not re-derived. The DENY/ESCALATE fail-closed path, signing, expiry, and anti-replay controls require their own governed actions.
- The `manifest.json` is an **unsigned** integrity index: it detects accidental corruption and casual edits, but a motivated forger who edits a framework sheet and recomputes its manifest entry is not stopped by the manifest alone. The cryptographic anchor is the receipt-hash binding + audit hash-chain inside the proof pack; signing the manifest is a follow-up.
- Audit is local, append-only JSONL: tamper-evident, not tamper-proof. Retention, off-host/WORM durability, and custody (EU AI Act Art. 19 / 26(6)) are operator responsibilities.
- This pack is regenerated, never hand-edited. See `compliance/COMPLIANCE_READINESS_REPORT.md`, `docs/COMPLIANCE_CROSSWALK.md`, and `docs/CLAIMS.md` rows 27-33 for the full standing limitations.
