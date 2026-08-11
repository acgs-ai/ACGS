# VALIDATOR_TRUST_GOVERNANCE_V1 — Threat Model

Scope: the trust chain from a human validator's judgment to a routable
authority record. Assets: the validator registry, the validator keystore, the
attestation blocks, the evidence registry, and the derived lifecycle.

## Adversary capabilities considered

An attacker who can write to the package's data files (registry lines,
keystore files, evidence records, attestation blocks) but cannot break
SHA-256/HMAC-SHA256. Includes a malicious insider trying to make unqualified
evidence route, suppress qualified evidence, or launder an authority record
into a commercial-rights claim.

## Threats and mitigations (each has a named test)

| # | Threat | Mitigation | Derived outcome | Test |
|---|---|---|---|---|
| T1 | Forged validator identity (attestation names an unregistered validator) | registration is the only trust source; empty registry trusts nobody | INVALIDATED, 0 routed | `test_vt1`, `test_empty_validator_registry_trusts_nobody` |
| T2 | Revoked validator signs new evidence | `authority_valid_at(validated_at)` checks REVOKE instants | INVALIDATED | `test_vt2` |
| T3 | Expired validator credentials | registered effective window checked at `validated_at` | INVALIDATED | `test_vt3` |
| T4 | Validator attests outside authorized class | `authorized_classes` on the REGISTER event | INVALIDATED | `test_vt4` |
| T5 | Attestation altered after signing | HMAC over every semantic attestation field | INVALIDATED | `test_vt5` |
| T6 | Conflicting validators (disposition / confirmed scope / confirmed period) | deterministic conflict rules over trust-valid attestations | CONFLICTED, never routed | `test_vt6`, `test_vt6b` |
| T7 | Replayed attestation (copied to another record; old key used post-rotation) | `record_binding` refuses foreign records; key windows close at rotation | DISCOVERED / INVALIDATED | `test_vt7` |
| T8 | Registry tampering / keystore key drift / malformed registry | `event_binding` per event; `key_fingerprint` check; malformed registry taints everything | INVALIDATED | `test_vt8` |
| T9 | Partial validator metadata | completeness gate before any trust conclusion | INVALIDATED | `test_vt9` |
| T10 | Fabricated commercial-rights inference | commercial-claim fields rejected at the onboarding contract; routing mints no rights (I6/I7) | rejected pre-lifecycle / rights count 0 | `test_vt10` |
| T11 | Validator revoked after issuance (doubt, not proof of fraud) | `revoked_after` derives review, evidence retained | REQUIRES_REVIEW, 0 routed | `test_validator_revoked_after_issuance_requires_review` |
| T12 | Stale validation treated as forever-fresh | revalidation policy (age / epoch); malformed policy fails closed | REQUIRES_REVIEW | `test_freshness_*`, `test_malformed_policy_fails_closed` |
| T13 | Software self-attestation | no code path writes a validation block or registry event content; pipeline only verifies and refuses (exit 4/5) | never enters VALIDATED | `test_pipeline_unattested_exits_4…`, `test_pipeline_untrusted_validator_exits_5` |
| T14 | Forged lifecycle state | state is a function, not a field — INVALIDATED/CONFLICTED/REQUIRES_REVIEW included | recomputed on every read | whole suite (no stored state exists to forge) |

## Trust roots (explicit, not hidden)

1. **The registry file + keystore as a unit.** `event_binding` makes in-place
   edits *detectable*, not impossible: an attacker with unrestricted write
   access to BOTH the registry and the keystore could fabricate a coherent
   validator from scratch (new events with valid bindings, new key). The
   binding chain protects against tampering with *recorded* history and
   against partial compromise; full-fabrication resistance requires anchoring
   the registry (commit history, external timestamping, or counter-signing).
   Recorded as a residual risk below.
2. **HMAC symmetric keys.** Verification requires the keystore, so proofs are
   confined to the local operator trust domain — the same model as the
   receipt keystore. Third-party verifiability needs asymmetric signatures
   (Ed25519), stdlib-incompatible today (zero-dependency constraint).
3. **The appointing authority.** `appointment_authority` on REGISTER is
   recorded, not verified against an external source — the same boundary as
   evidence onboarding: software records what real artifacts establish and
   refuses to adjudicate them.

## Residual risks / remaining blockers

- **R1 (accepted, recorded):** full-fabrication of a validator by an attacker
  with write access to registry + keystore (trust root 1). Mitigations
  available when needed: commit the registry (append-only in review), Ed25519
  keys, dual-control registration.
- **R2 (accepted, recorded):** HMAC prevents third parties from verifying
  attestations without keystore access; Ed25519 upgrade path documented.
- **R3 (by design):** the system cannot detect a *humanly wrong* validation
  by a properly authorized, properly signing validator — that is exactly the
  judgment localized to humans; the mitigations are multi-validator
  co-validation (CONFLICTED on disagreement) and revalidation policy.
- **No production validator exists.** The registry is empty; every trust
  chain in this package's history is a `[FIXTURE]` in `attack_suite/`.
