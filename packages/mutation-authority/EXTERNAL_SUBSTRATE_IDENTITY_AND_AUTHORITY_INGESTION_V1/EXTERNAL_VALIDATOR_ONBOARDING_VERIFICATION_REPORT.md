# EXTERNAL_VALIDATOR_ONBOARDING_V1 + ASYMMETRIC_VALIDATOR_KEYS_V1 — Verification Report

All output literal from this session. Logical instants only. **No external
authority exists: no real validator has been onboarded, both production
registries remain 0 bytes, and no claim of external authority is made.**

## 1. VERDICT

**`AUTHORITY_LAYER_READY`** — unchanged and correct. The onboarding protocol,
the dual-mode signature lane, and the registry hash chain are built, verified,
and fail-closed; with no real validator and no real evidence, nothing routes,
which is the required success state.

```
pytest attack_suite/           -> 96 passed (76 prior + 13 validator-onboarding + 7 asymmetric)
ruff check .                   -> All checks passed!
verify_substrate_identity.py   -> IDENTITY_CONFIRMED (exit 0)
verify_authority_state.py ×2   -> DETERMINISTIC: byte-identical verifier output
                                  VERDICT: AUTHORITY_LAYER_READY
verify_mutation_governance.py  -> ALL CHECKS PASSED
verify_mutation_integration.py -> ALL CHECKS PASSED
validator_registry.jsonl / authority_evidence_registry.jsonl -> 0 bytes each
```

## 2. Exact files changed

New (sha256 of the verified state):

```
05f1cb7515a17fd6…  _ed25519.py                       optional Ed25519 backend (fail-closed absent)
d066a2d79858016c…  validator_onboarding.py           appointment model + ceremony derivation
6ea0d432fe09d5a6…  onboard_validator.py              evidence-backed registration CLI (6 gates)
a0dd58626033dea5…  VALIDATOR_APPOINTMENT_SCHEMA.json appointment record schema
72a0ec9cd034a812…  VALIDATOR_REGISTRY_CUSTODY_THREAT_MODEL_V1.md   custody analysis (no changes implemented)
95542bfa20eda725…  attack_suite/test_validator_onboarding_attacks.py  13 tests
11911ce6b71f9910…  attack_suite/test_asymmetric_keys.py               7 tests
```

Modified:

```
499cfe147d3aecd7…  validator_trust.py    + registry hash chain (GENESIS-rooted prev_event_binding),
                                         + dual-mode dispatch (hmac-sha256 | ed25519),
                                         + attestation_payload_v2 (Ed25519 payload)
e18c022182cfeeed…  validator_admin.py    chain-linked appends
attack_suite/test_onboarding_attacks.py     fixtures chain-linked
attack_suite/test_validator_trust_attacks.py fixtures chain-linked
README.md                                    phase pointer
```

Untouched: all baseline modules (`authority_router`, `authority_receipt`,
`_identity`, `_substrate`, `_canonical`, `_registry`, ingest,
`authority_lifecycle`), the external substrate (read-only, identity
re-confirmed), and both production registries.

## 3. Security properties proven (each by named test)

**Onboarding (Phase 1):**

| Property | Test |
|---|---|
| Self-appointment structurally refused | `test_ova1` |
| Appointment evidence cannot back a second validator (copied identity) | `test_ova2` |
| REGISTER cannot claim more classes than the appointment grants; forged expansion breaks provenance AND the chain | `test_ova3` |
| Expired appointment cannot register | `test_ova4` |
| Revoked appointment (event or period end) derives REVOKED | `test_ova5` |
| Key substitution → ownership unprovable → APPOINTMENT_PENDING, exit 4 | `test_ova6` |
| Registry rollback (mid-history excision) breaks the hash chain: no validator trusted, ceremony never ACTIVE | `test_ova7` |
| Forged onboarding evidence (digest mismatch) refused, registry untouched | `test_ova8` |
| Partial appointment metadata → DISCOVERED, refused | `test_ova9` |
| Conflicting appointments for one validator refused (no silent overwrite) | `test_ova10` |
| Ceremony lifecycle derived, never stored; full ladder DISCOVERED→…→REVOKED | `test_ceremony_ladder_derives_each_state` |
| Onboarded validator's attestations are accepted by the trust layer | `test_onboarded_validator_attestations_are_trusted` |

**Asymmetric keys (Phase 2, dual mode — HMAC compatibility retained, whole
prior suite still runs in HMAC mode):**

| Property | Test |
|---|---|
| Valid Ed25519 signature over the complete v2 payload (validator id, key fingerprint, attestation content, evidence identity + source digest, timestamp, validation class) routes | `test_valid_ed25519_signature_routes` |
| Wrong key fails | `test_wrong_key_fails` |
| Altered payload (any bound field, either side of the binding) fails | `test_altered_payload_fails` |
| Wrong validator id fails | `test_wrong_validator_id_fails` |
| Revoked key fails | `test_revoked_key_fails` |
| Rotated key history remains auditable: in-window old signatures verify forever; post-rotation old-key use refused; successor signs | `test_rotated_key_history_remains_auditable` |
| Algorithm mode confusion (HMAC key, Ed25519 claim) refused pre-crypto | `test_algorithm_mode_confusion_refused` |

Ed25519 verification reads the public key from the registry event —
**no keystore access needed** — closing the third-party-verifiability gap
(prior blocker R2) for records signed in this mode. Backend absent →
verification returns False (fail closed), suite skips cleanly.

## 4. Remaining blockers

1. **No real validator exists** — production registries empty by design;
   onboarding awaits a real appointment artifact. Software cannot produce it.
2. **Tail truncation of the registry** is undetectable from the file alone
   (valid chain prefix). Custody controls R-A (signed registry commits) and
   R-B (witness heads) close it — analyzed, **not implemented** (per scope).
3. **Insider with registry+keystore+evidence write access** can fabricate a
   coherent validator; containment is dual-control (R-C) + anchoring —
   analyzed, not implemented.
4. **HMAC mode** remains keystore-bound (local trust domain) until operators
   migrate validators to Ed25519; both modes verified side by side.
5. `cryptography` is an optional dependency: the package baseline stays
   stdlib-only; Ed25519 lanes fail closed without it.

## 5. Migration readiness assessment

**HMAC → Ed25519: READY at the mechanism level.** Dual verification is live
and tested; registry events carry `key_algorithm`/`public_key`; rotation
provides the migration primitive (ROTATE an HMAC validator to an Ed25519 key —
old HMAC attestations stay auditable in their window, new attestations sign
with Ed25519). Recommended order per validator: onboard/rotate to Ed25519 →
new attestations in v2 payload → HMAC key retires with its window. **Not
migration-complete:** no production validator exists to migrate, and custody
recommendations (R-A/R-B) should land before the first real onboarding so the
registry is anchored from GENESIS. Do not register a real validator until a
real appointment artifact exists and the operator has chosen the custody
posture.
