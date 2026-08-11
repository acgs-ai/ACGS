# EXTERNAL_SUBSTRATE_IDENTITY_AND_AUTHORITY_INGESTION_V1

The smallest durable layer that lets ACGS **identify** the recovered external
`COMMERCIAL_BUYER_READINESS_V1` substrate cryptographically (without copying the
232 GB corpus), **ingest** real externally-evidenced authority identities, and
**deterministically transition** commercial-rights request records from
`ROUTING_REQUIRED` toward `READY_TO_SEND` — but only when sufficient real
authority evidence exists.

It asserts no commercial right. `rights_assertion` stays `null`. With no evidence
on file, every request correctly stays `ROUTING_REQUIRED` — that is the intended
state, not a failure.

## Verdict

**`AUTHORITY_LAYER_READY`** — mechanism built, verified, and fail-closed; no real
authority evidence exists, so 340 requests remain `ROUTING_REQUIRED`
(306 counsel + 34 controller), 0 `READY_TO_SEND`. See `REPORT.md`.

Phase 2 (`REAL_AUTHORITY_EVIDENCE_ONBOARDING_V1`) adds the real-evidence
onboarding pipeline: derived lifecycle
(`DISCOVERED→VALIDATED→INGESTED→ACTIVE→SUPERSEDED/REVOKED`), a human validation
attestation with cryptographic `record_binding` gating all routing, per-class
real-artifact contracts, and 15 further attacks. Routing now uses
lifecycle-ACTIVE records only. See
`ARCHITECTURE_REAL_AUTHORITY_EVIDENCE_ONBOARDING.md`,
`ONBOARDING_MIGRATION_PLAN.md`, `ONBOARDING_VERIFICATION_REPORT.md`; run
`onboard_authority_evidence.py` to onboard a real artifact.

Phase 3 (`VALIDATOR_TRUST_GOVERNANCE_V1`) governs the validator behind the
attestation: registered validator identities with authorized classes and key
lifecycle (register/rotate/revoke/expiry), signed attestations, deterministic
conflict handling, and a revalidation policy — adding derived states
`INVALIDATED`, `CONFLICTED`, `REQUIRES_REVIEW`. An empty validator registry
trusts nobody (production's state). See
`ARCHITECTURE_VALIDATOR_TRUST_GOVERNANCE.md`, `VALIDATOR_TRUST_THREAT_MODEL.md`,
`VALIDATOR_TRUST_VERIFICATION_REPORT.md`; administer validators with
`validator_admin.py`.

Phase 4 (`EXTERNAL_VALIDATOR_ONBOARDING_V1` + `ASYMMETRIC_VALIDATOR_KEYS_V1`)
adds evidence-backed validator onboarding (appointment schema, derived key
ceremony DISCOVERED→APPOINTMENT_PENDING→KEY_BOUND→ACTIVE→ROTATED→REVOKED,
`onboard_validator.py` with six fail-closed gates), a GENESIS-rooted registry
hash chain (rollback defense), and dual-mode signatures (HMAC compatibility +
Ed25519 with in-registry public keys — third-party verifiable). Custody
analysis in `VALIDATOR_REGISTRY_CUSTODY_THREAT_MODEL_V1.md` (no custody
changes implemented). See
`EXTERNAL_VALIDATOR_ONBOARDING_VERIFICATION_REPORT.md`.

## Layout

| File | Role |
|---|---|
| `build_substrate_identity.py` / `verify_substrate_identity.py` | Phase A — bind / re-verify substrate identity (byte-anchored, path-independent, fail-closed on drift) |
| `substrate_identity.json` | the bound identity manifest (Layer B) — `SUBSTRATE_IDENTITY_SCHEMA.json` |
| `AUTHORITY_EVIDENCE_SCHEMA.json` | schema for external authority-evidence records (Layer C) |
| `authority_evidence_registry.jsonl` | the evidence registry — **empty is valid** |
| `ingest_authority_evidence.py` | ingest one record: hash its real source document, validate, dedup, receipt |
| `authority_router.py` | scope-aware mapping of verified evidence → request transitions |
| `authority_receipt.py` | single-use, deterministic, HMAC-signed transition receipts + replay ledger; v2 receipts bind both substrate identity and critical-set digest, and v1 is rejected |
| `verify_authority_state.py` | top verifier — identity + live counts + authority state + Section 23 report + verdict |
| `attack_suite/test_attacks.py` | 32 adversarial attacks + invariants I1–I14 + positive controls |
| `ARCHITECTURE.md` | the A/B/C separation, lifecycle, receipt binding, drift semantics |

## Run

```bash
cd packages/mutation-authority/EXTERNAL_SUBSTRATE_IDENTITY_AND_AUTHORITY_INGESTION_V1

python3 build_substrate_identity.py            # bind identity (writes substrate_identity.json)
python3 verify_substrate_identity.py           # re-verify (exit 0 = IDENTITY_CONFIRMED)
python3 verify_authority_state.py              # full state + verdict
python3 -m pytest attack_suite/test_attacks.py -q
```

Substrate location is `$ACGS_COMMERCIAL_SUBSTRATE_ROOT` or the observed default;
relocation is supported because identity matches by bytes, not by path.

## Invariants (enforced + tested — I1–I14)

No evidenced authority → no `READY_TO_SEND`. Known identity alone is
insufficient. Authority without matching scope is insufficient. Controller
authority never satisfies a counsel-routed request, and counsel authority never
covers assets outside its scope. `READY_TO_SEND` never implies the right exists;
routing resolution never creates a `rights_assertion`. Aggregate counts are
derived from records, never stored. Substrate-identity mismatch blocks every
transition. No fabricated recipient. No receipt → no governed authority
mutation. Revoked/expired authority fails closed. The substrate bytes are never
touched, and no corpus migration is required for correctness.

## What it does not do

It does not copy, import, or migrate the 232 GB corpus; does not modify the
substrate or its permissions; does not invent a controller, counsel, law firm,
recipient, appointment, engagement, consent, right, or clearance; and does not
assert any commercial right. It records what real evidence establishes and
refuses to manufacture the rest.
