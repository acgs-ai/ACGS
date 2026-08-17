# REAL_AUTHORITY_EVIDENCE_ONBOARDING_V1 — Architecture

Extension of the trusted `EXTERNAL_SUBSTRATE_IDENTITY_AND_AUTHORITY_INGESTION_V1`
baseline. Nothing in the baseline was redesigned: `authority_router`,
`authority_receipt`, `_identity`, and the ingest path are unchanged mechanisms.
This phase adds the layer that governs how a **real** authority artifact enters
them.

## The question this phase answers

> Given a real authority artifact, can ACGS safely convert `ROUTING_REQUIRED`
> into `READY_TO_SEND` without human interpretation?

**Answer: the conversion is mechanical; the qualification is not — and the
architecture encodes exactly that split.**

- Everything downstream of a *validated* artifact is deterministic and
  human-free: digest binding, class/scope/period matching, receipt minting,
  count derivation. Same inputs → byte-identical report and identical
  receipt ids (`test_deterministic_verification`).
- The single non-mechanical fact — "this document really constitutes this
  authority" — is a legal judgment. It is localized into one artifact, the
  **validation attestation**, written by a human/legal validator and never by
  software. A record without it cannot rise above `DISCOVERED`, so it can never
  route. The system is therefore incapable of converting a request on an
  artifact no human has qualified, and equally incapable of blocking on human
  interpretation *after* qualification.

## Evidence lifecycle (derived, never stored)

```
DISCOVERED ──(human validation attestation with record_binding)──▶ VALIDATED
VALIDATED  ──(receipted, idempotent ingest)──▶ INGESTED
INGESTED   ──(effective_from ≤ instant < effective_until, not revoked/superseded)──▶ ACTIVE
ACTIVE     ──(newer record names it in `supersedes`)──▶ SUPERSEDED
ACTIVE     ──(revoked_at set)──▶ REVOKED
```

`derive_lifecycle_state` computes the state from stored facts on every read.
There is no `lifecycle_state` field to forge — writing one changes nothing
(same defense as the derived aggregate counts, invariant I8). Precedence is
fail-closed: REVOKED ≻ SUPERSEDED ≻ attestation gate ≻ registry membership ≻
temporal effect. **Only ACTIVE records are routing-eligible**
(`active_records`), and `verify_authority_state.compute_state` now routes on
that subset — a schema-valid, in-effect, unattested record is visible in the
report (`lifecycle_distribution.DISCOVERED`) but can never produce a receipt.

## The validation attestation

```json
"validation": {
  "validator_identity": "…",         // the human/legal validator
  "validation_method":  "…",         // what they did
  "validated_at":       "…Z",        // when
  "record_binding":     "<sha256>"   // hash of the record content they reviewed
}
```

`record_binding = sha256(canonical({authority_evidence_id, authority_type,
subject_identity, authority_scope, source_digest, effective_from,
effective_until}))` (`attestation_binding`). Any post-validation change to the
identity, scope, covered period, or underlying document breaks the binding and
the record drops back to `DISCOVERED` — the **identity-drift** defense. The
pipeline prints the expected binding (`--emit-binding`) but never writes the
attestation block itself.

## Per-class real-artifact contract

| Class | Extra required fields | Satisfies routing basis |
|---|---|---|
| `DATA_CONTROLLER` | `issuer_or_appointing_party` | `NO_APPOINTED_CONTROLLER` (34 requests) |
| `COUNSEL_OR_RIGHTS_AUTHORITY` | `jurisdiction`, `appointment_authority`, `verification_metadata` | `NO_EVIDENCED_COUNSEL_IDENTITY` (306 requests, scope-limited) |

A record missing its class fields is a **fabrication shape**: rejected at the
contract gate (`OnboardingError`), counted in no lifecycle state, never
routable (`test_ob7`). Class-crossing is still impossible (baseline I4), and a
counsel identity transitions only the requests inside its evidenced
asset/requirement scope (baseline I5, `test_counsel_with_required_fields…`).

## Pipeline (`onboard_authority_evidence.py`)

```
gate 1  sha256(artifact) == record.source_digest          → else exit 3
gate 2  per-class real-artifact contract                  → else exit 3
gate 3  well-formed attestation with matching binding     → else exit 4 (stays DISCOVERED, registry untouched)
gate 4  receipted idempotent ingest (trusted V1 path)     → conflict exit 3, idempotent exit 0
        then: derived lifecycle state reported (ACTIVE / INGESTED)
```

Duplicate onboarding of the same logical evidence is idempotent (one registry
fact); same id with a different document is a conflict; replayed transitions
are refused by the receipt `ReplayLedger` and identical inputs regenerate
identical receipt ids rather than new authority facts (`test_ob6`).

## Attack coverage added (all fail closed)

1. unsigned/unattested evidence → `DISCOVERED`, 0 routable
2. expired appointment → `INGESTED`, not routable
3. superseded controller → `SUPERSEDED`, only the successor routes
4. scope mismatch → ACTIVE but converts nothing (I3)
5. identity drift after validation → binding broken → `DISCOVERED`
6. evidence replay → single logical fact, no extra receipts
7. fabricated authority record shapes → rejected pre-lifecycle
8. relocation with changed content → `SUBSTRATE_DIVERGED`, 0 transitions
   (relocation with identical bytes still confirms — baseline attack 04)

## Production stance

The production registry stays **empty** until a real artifact arrives. No
placeholder identities exist anywhere outside `[FIXTURE]`-marked test fixtures
in `attack_suite/`. Expected production report today: verdict
`AUTHORITY_LAYER_READY`, `routing_required 340` (306 + 34), `ready_to_send 0`,
`lifecycle_distribution` all zeros, `rights_assertion` null throughout.
Readiness of the *pipeline* is claimed; readiness of any *authority fact* is
not — that requires a real, cryptographically bound, humanly validated
artifact, and until then failing closed **is** the success condition.
