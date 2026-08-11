# VALIDATOR_TRUST_GOVERNANCE_V1 — Verification Report

All output below is literal from this session's runs. Logical instants only —
no wall clock enters any computation.

## VERDICT

**`AUTHORITY_LAYER_READY`** — the trust governance mechanism is built,
verified, and fail-closed. No real validator is registered and no real
authority evidence exists, so nothing routes: that is the required success
condition, not a deficiency. **No production readiness of any authority fact
or validator fact is claimed.**

## Production state (unchanged, as required)

```
verify_substrate_identity.py -> IDENTITY_CONFIRMED (exit 0)
verify_authority_state.py    -> VERDICT: AUTHORITY_LAYER_READY
  routing_required 340 · ready_to_send 0 · routable_authority_records 0
  lifecycle_distribution: all zeros incl. INVALIDATED 0, CONFLICTED 0, REQUIRES_REVIEW 0
  validator_registry_events 0 · registered_validators 0
validator_registry.jsonl          -> 0 bytes (empty by design — trusts nobody)
authority_evidence_registry.jsonl -> 0 bytes (empty by design)
```

Deterministic re-verification: the full production verifier was run twice and
the outputs diffed byte-for-byte:

```
diff v1.txt v2.txt -> DETERMINISTIC: identical verifier output
```

## Test evidence

```
pytest attack_suite/  -> 76 passed   (41 baseline + 16 onboarding + 19 validator-trust)
ruff check .          -> All checks passed!
verify_mutation_governance.py  -> ALL CHECKS PASSED   (kernel baseline)
verify_mutation_integration.py -> ALL CHECKS PASSED   (kernel baseline)
```

### Required adversarial coverage (each fail-closed, each a named test)

| # | Attack | Outcome | Test |
|---|---|---|---|
| 1 | forged validator identity | INVALIDATED, 0 routable, verdict unchanged | `test_vt1` |
| 2 | revoked validator signing new evidence | INVALIDATED | `test_vt2` |
| 3 | expired validator credentials | INVALIDATED | `test_vt3` |
| 4 | unauthorized validator class | INVALIDATED (`unauthorized_validator_class`) | `test_vt4` |
| 5 | altered validation after signing (4 fields tried) | INVALIDATED each | `test_vt5` |
| 6 | conflicting validators | CONFLICTED, 0 ready | `test_vt6`, `test_vt6b` |
| 7 | replayed old attestation (foreign record; rotated-out key) | DISCOVERED / INVALIDATED | `test_vt7` |
| 8 | validator registry tamper / key drift / malformed registry | INVALIDATED (all three variants) | `test_vt8` |
| 9 | partial validator metadata (3 fields tried) | INVALIDATED each | `test_vt9` |
| 10 | fabricated commercial-rights inference | rejected pre-lifecycle; rights_assertions 0 with live routing | `test_vt10` |

Plus: revoked-after-issuance → REQUIRES_REVIEW (evidence retained, 0 routed);
freshness age/epoch demotion → REQUIRES_REVIEW with `last_verified_at`
restoring routability; malformed policy fails closed; empty registry trusts
nobody; admin CLI lifecycle (register → duplicate refused → rotate → revoke,
all event bindings intact, keystore fingerprints match); governed derivation
determinism; and the positive control — the full five-clause trust chain, and
only it, routes (fixture substrate: ACTIVE 1, ready 2,
`AUTHORITY_PARTIALLY_ACTIVATED`, all invariants PASS).

## The success condition, proven

> No authority becomes routable unless (1) evidence identity is verified,
> (2) authorized human validation exists, (3) validator authority was valid at
> validation time, (4) binding remains intact, (5) lifecycle derivation
> independently confirms eligibility.

Each clause is independently attacked and independently blocks routing
(tests above); with all five satisfied, routing occurs deterministically
(`test_positive_control_full_trust_chain_routes`). Clause failure modes never
mint receipts and never create rights facts (I6/I7 re-proven under the trust
layer, `test_vt10`).

## Deliverables

| Deliverable | File(s) |
|---|---|
| Architecture document | `ARCHITECTURE_VALIDATOR_TRUST_GOVERNANCE.md` |
| Schema changes | `VALIDATOR_REGISTRY_SCHEMA.json` (new); `AUTHORITY_EVIDENCE_SCHEMA.json` (attestation trust fields, `co_validations`, `last_verified_at`, `verification_epoch`) |
| Threat model | `VALIDATOR_TRUST_THREAT_MODEL.md` |
| Implementation | `validator_trust.py`, `validator_admin.py`, `revalidation_policy.json`, verifier + pipeline wiring (exit 5 gate) |
| Test results | this file (`attack_suite/test_validator_trust_attacks.py`, 19 tests) |
| Remaining blockers | below |

## Remaining blockers (honest, recorded)

1. **No real validator exists.** The registry stays empty until a real person
   with a real appointment is registered by the operator — software cannot
   and does not invent one.
2. **R1 — registry+keystore full-fabrication** (see threat model): an
   attacker with write access to both files could fabricate a coherent
   validator. Mitigation path: commit the registry, dual-control
   registration, and/or asymmetric keys.
3. **R2 — HMAC trust domain:** attestation proofs verify only with keystore
   access; third-party verifiability needs Ed25519 (violates the current
   zero-dependency constraint; upgrade path documented).
4. Freshness constraints are shipped permissive (`max_age_days: null`,
   `minimum_epoch: 0`) — tightening them is an operator policy decision, not
   a code change.

Baseline modules untouched: `authority_router.py`, `authority_receipt.py`,
`_identity.py`, `_substrate.py`, `_canonical.py`, `_registry.py`,
`ingest_authority_evidence.py`, `build_/verify_substrate_identity.py`.
`authority_lifecycle.py` gained only the commercial-claim rejection; its
derivation is unchanged. External substrate: read-only, untouched, identity
re-confirmed after every run.
