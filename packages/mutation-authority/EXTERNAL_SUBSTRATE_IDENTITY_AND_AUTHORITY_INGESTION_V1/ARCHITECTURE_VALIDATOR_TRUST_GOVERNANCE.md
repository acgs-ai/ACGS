# VALIDATOR_TRUST_GOVERNANCE_V1 — Architecture

Third layer of the authority stack. The baseline
(`EXTERNAL_SUBSTRATE_IDENTITY_AND_AUTHORITY_INGESTION_V1`) proved substrate
identity and receipted routing; the onboarding layer
(`REAL_AUTHORITY_EVIDENCE_ONBOARDING_V1`) made a human validation attestation
the gate to routing. This layer governs the **trust behind the validator**:
who may validate, with which key, for which evidence class, over which period —
and what happens when that trust is forged, expired, rotated, revoked,
contradicted, or stale.

Nothing in the two prior layers was redesigned. `authority_router`,
`authority_receipt`, `_identity`, `authority_lifecycle`, and the ingest path
are unchanged mechanisms; this layer adds `validator_trust.py`,
`validator_admin.py`, a validator registry + keystore, a revalidation policy,
and a governed lifecycle derivation the verifier and pipeline now consult.

## The success condition, mapped to mechanisms

> No authority becomes routable unless:
> (1) evidence identity is verified,
> (2) authorized human validation exists,
> (3) validator authority was valid at validation time,
> (4) binding remains intact,
> (5) lifecycle derivation independently confirms eligibility.

| Clause | Mechanism | Fails closed as |
|---|---|---|
| (1) evidence identity | `source_digest` gate + substrate `critical_set_digest` (I9 ordering: no route before identity) | exit 3 / `SUBSTRATE_DIVERGED`, 0 receipts |
| (2) authorized human validation | attestation + validator REGISTER event with `authorized_classes`; software never writes either | `DISCOVERED` (no attestation) / `INVALIDATED` (unauthorized) |
| (3) valid at validation time | `authority_valid_at(validated_at)` + `key_valid_at(validated_at)` against the event log | `INVALIDATED` |
| (4) binding intact | `record_binding` (record content) + `attestation_signature` (every attestation field) + `event_binding` (registry history) + `key_fingerprint` (keystore) | `DISCOVERED` / `INVALIDATED` |
| (5) independent lifecycle derivation | `derive_governed_state` recomputed from stored facts on every read; only governed-`ACTIVE` routes | any non-ACTIVE state, never routable |

All five are conjunctive and each is independently attacked in the test suite.
The fail-closed root: an **empty validator registry trusts nobody** — a
perfectly signed attestation with no establishable validator authorization
derives `INVALIDATED`. That is production's shipped state.

## Validator identity and key lifecycle

The validator registry (`validator_registry.jsonl`, append-only JSONL,
`VALIDATOR_REGISTRY_SCHEMA.json`) holds three event kinds:

```
REGISTER  identity, authorized_classes, appointment_authority,
          key_id + key_fingerprint, effective_from/until
ROTATE    new key_id + fingerprint from `instant`; the old key's signing
          window closes at that instant (old in-window signatures stay valid)
REVOKE    authority ends at `instant`
```

Every event carries `event_binding = sha256(canonical(event − binding))`.
History is never edited: rotation and revocation are new events, and an
in-place edit breaks the binding, making the validator unverifiable —
privilege escalation by registry tampering is detectable and fail-closed.

Signing keys live in `.validator_keystore/<key_id>` (gitignored, never
committed); the registry stores only fingerprints. Verification checks
`sha256(keystore key) == registered fingerprint` before verifying the HMAC —
a swapped key fails closed.

Registration itself requires a real appointment (`appointment_authority`) —
`validator_admin.py` refuses to run without one and production keeps the
registry empty until a real validator exists. No validator identity is ever
invented by software.

## Attestation verification hardening

`verify_attestation_trust` — ordered, each step fail-closed:

```
metadata completeness (validator_id, key_id, signature present)
→ record_binding matches record content
→ registry loadable and events intact (event_binding)
→ validator REGISTERED and authorized for this evidence class
→ validator authority valid at validated_at
→ key_id current at validated_at (rotation windows)
→ keystore key present + fingerprint match
→ HMAC-SHA256 signature over the full canonical attestation payload
```

The signature payload (`attestation_payload`) covers **every** semantic
attestation field — validator identity, method, instant, binding, disposition,
confirmed scope/period, key id — so altering any of them after signing
invalidates the attestation. Software still never generates a validation
block: the pipeline verifies attestations (gate 3b, exit 5) and prints the
binding a validator must sign (`--emit-binding`), nothing more.

## Governed lifecycle (derived, never stored)

Three states join the onboarding lifecycle — all derived on every read, none
writable:

```
INVALIDATED      an attestation exists but its trust fails structurally:
                 unknown/unauthorized validator, authority or key invalid at
                 validated_at, broken signature, tampered registry, partial
                 metadata, all validators REJECTED
CONFLICTED       trust-valid attestations contradict each other or the record:
                 mixed APPROVED/REJECTED dispositions, a confirmed scope
                 digest ≠ the record's scope, a confirmed period ≠ the
                 record's effective period
REQUIRES_REVIEW  the trust was valid but is now in doubt: validator revoked
                 AFTER issuance, or the record is stale under the
                 revalidation policy — evidence is never deleted
```

Precedence (fail-closed):
`REVOKED ≻ SUPERSEDED ≻ DISCOVERED ≻ INVALIDATED ≻ CONFLICTED ≻
VALIDATED/INGESTED gates ≻ REQUIRES_REVIEW ≻ ACTIVE`.
Only governed-`ACTIVE` records route (`governed_active_records`);
`verify_authority_state.compute_state` and the onboarding pipeline both use
the governed derivation.

Multi-validator review uses `co_validations`: every attestation must be
trust-valid, and deterministic conflict rules (dispositions, confirmed scope,
confirmed period — plain set/equality comparisons, no heuristics) decide
CONFLICTED vs concurrence.

## Freshness and revalidation

`revalidation_policy.json` (operator-set, never invented by software):

- `max_age_days` — governed-ACTIVE records whose `last_verified_at` (fallback:
  newest attestation instant) is older than this at the evaluation instant
  derive `REQUIRES_REVIEW`;
- `minimum_epoch` — records whose `verification_epoch` is below the minimum
  derive `REQUIRES_REVIEW`;
- `require_freshness_fields` — records missing the fields derive
  `REQUIRES_REVIEW`.

A malformed policy file fails closed (nothing counts as fresh). A missing
policy file means freshness is not yet an operator constraint (defaults).
`ACTIVE → REQUIRES_REVIEW` is a derivation change only: the evidence record,
its attestations, and its receipts are all retained; revalidation (a new
`last_verified_at` / epoch, humanly produced) restores routability.

## Commercial/legal boundary

Authority qualification ≠ commercial-rights ownership ≠ licensing permission ≠
contractual entitlement. Structurally enforced:

- an evidence record carrying any commercial-claim field
  (`rights_assertion`, `commercial_rights`, `ownership`, `license`,
  `licensing_permission`, `contractual_entitlement`, `rights_granted`) is
  rejected at the onboarding contract (`OnboardingError`) — it cannot enter
  any lifecycle state;
- routing on fully trust-verified evidence still creates no rights fact:
  substrate `rights_assertion` stays null (I6) and routing mints none (I7),
  re-proven with the trust chain live (`test_vt10`).

## Files

| File | Role |
|---|---|
| `validator_trust.py` | trust verification + governed lifecycle derivation |
| `validator_admin.py` | REGISTER / ROTATE / REVOKE registry administration |
| `validator_registry.jsonl` | append-only validator event log — **empty in production** |
| `.validator_keystore/` | validator signing keys (gitignored) |
| `VALIDATOR_REGISTRY_SCHEMA.json` | event schema |
| `revalidation_policy.json` | operator freshness policy |
| `AUTHORITY_EVIDENCE_SCHEMA.json` | attestation trust fields, `co_validations`, freshness fields |
| `attack_suite/test_validator_trust_attacks.py` | 19 adversarial + positive-control tests |
| `VALIDATOR_TRUST_THREAT_MODEL.md` | threats, trust roots, residual risk |
| `VALIDATOR_TRUST_VERIFICATION_REPORT.md` | verdict + literal gate outputs |
