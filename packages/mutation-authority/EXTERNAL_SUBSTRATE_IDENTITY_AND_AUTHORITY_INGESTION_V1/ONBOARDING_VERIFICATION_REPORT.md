# REAL_AUTHORITY_EVIDENCE_ONBOARDING_V1 — Verification Report

Date basis: logical instants only (no wall-clock enters any computation).
All output below is literal from this session's runs.

## Production state (unchanged, as required)

```
verify_substrate_identity.py -> IDENTITY_CONFIRMED (exit 0)
verify_authority_state.py    -> VERDICT: AUTHORITY_LAYER_READY
  routing_required 340 (306 counsel + 34 controller) · ready_to_send 0
  routable_authority_records 0
  lifecycle_distribution {DISCOVERED 0, VALIDATED 0, INGESTED 0, ACTIVE 0, SUPERSEDED 0, REVOKED 0}
  rights_assertions 0 · recipients_invented 0 · receipts 0
authority_evidence_registry.jsonl -> 0 bytes (empty by design)
```

No placeholder identity exists outside `[FIXTURE]`-marked test fixtures in
`attack_suite/`. **No readiness of any authority fact is claimed** — only
readiness of the pipeline, and its success condition is that it fails closed.

## Test evidence

```
pytest attack_suite/  -> 56 passed   (41 baseline + 15 onboarding)
ruff check <package>  -> All checks passed!
```

Required attack coverage (each a named test, each fail-closed):

| # | Attack | Test | Outcome |
|---|---|---|---|
| 1 | unsigned/unattested evidence | `test_ob1` | DISCOVERED, 0 routable, 0 ready |
| 2 | expired appointment | `test_ob2` | INGESTED (not ACTIVE), 0 ready |
| 3 | superseded controller | `test_ob3` | SUPERSEDED excluded; only successor routes |
| 4 | scope mismatch | `test_ob4` | ACTIVE but converts nothing |
| 5 | identity drift after validation | `test_ob5` | binding broken → DISCOVERED, 0 ready |
| 6 | evidence replay | `test_ob6` | one logical fact; exactly 2 receipts per resolved request |
| 7 | fabricated authority records | `test_ob7` | rejected pre-lifecycle; no state, never routable |
| 8 | relocation with changed content | `test_ob8` | SUBSTRATE_DIVERGED, 0 transitions |

Plus: counsel-class contract (`test_counsel_with_required_fields…` — scoped
counsel converts exactly its in-scope request), revocation
(`test_revoked_after_activation_fails_closed`), deterministic verification
(`test_deterministic_verification` — identical report bytes and receipt ids on
re-run; `test_attestation_binding_is_deterministic_and_content_sensitive`), and
pipeline exit-code contracts (unattested→4 with registry untouched,
tampered-document→3, attested→0/ACTIVE).

## End-to-end demonstration on the REAL substrate (isolated, `[FIXTURE]`-marked, tmp registry)

The controlled experiment that answers the phase question — identical record,
with and without the human validation attestation:

```
attested   -> lifecycle ACTIVE   -> AUTHORITY_PARTIALLY_ACTIVATED · ready 34 · routing 306
unattested -> lifecycle DISCOVERED -> AUTHORITY_LAYER_READY        · ready 0  · routing 340
production registry after both demos: 0 bytes (untouched)
```

The only difference between 34 conversions and 0 conversions is the human
validation attestation — exactly where the design places the non-mechanical
judgment.

## Answer to the phase question

> Given a real authority artifact, can ACGS safely convert ROUTING_REQUIRED
> into READY_TO_SEND without human interpretation?

**After validation, yes — and before validation, structurally no.** Digest
binding, class/scope/period matching, receipt minting, and count derivation are
deterministic and human-free. The one judgment software must not make — that an
artifact truly constitutes authority — is required exactly once, as a signed
validation attestation cryptographically bound to the record content it
qualified. Drift after that judgment voids it automatically.

## Deliverables

| Deliverable | File(s) |
|---|---|
| 1. Architecture | `ARCHITECTURE_REAL_AUTHORITY_EVIDENCE_ONBOARDING.md` |
| 2. Schema changes | `AUTHORITY_EVIDENCE_SCHEMA.json` (validation block; counsel fields: jurisdiction, appointment_authority, verification_metadata) |
| 3. Ingestion pipeline | `onboard_authority_evidence.py` + `authority_lifecycle.py` (gates, lifecycle, binding) |
| 4. Verifier updates | `verify_authority_state.py` (routes lifecycle-ACTIVE only; lifecycle_distribution + routable count in report) |
| 5. Attack suite | `attack_suite/test_onboarding_attacks.py` (15 tests) |
| 6. Migration plan | `ONBOARDING_MIGRATION_PLAN.md` |
| 7. Verification report | this file |

Baseline modules untouched: `authority_router.py`, `authority_receipt.py`,
`_identity.py`, `_substrate.py`, `_canonical.py`, `_registry.py`,
`ingest_authority_evidence.py` (invoked, not modified),
`build_/verify_substrate_identity.py`. External substrate: read-only,
untouched, identity re-confirmed after every run.
