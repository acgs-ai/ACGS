# VALIDATOR_REGISTRY_CUSTODY_THREAT_MODEL_V1

Custody analysis of the validator registry and keystore — the trust root of
the entire authority stack. **Analysis only: no custody changes are
implemented here.** Current in-repo defenses are named as they exist today;
everything else is a recommendation with explicit trade-offs.

## Assets under custody

| Asset | Contains | Compromise yields |
|---|---|---|
| `validator_registry.jsonl` | validator identities, classes, key fingerprints/public keys, appointment provenance, hash chain | ability to define who is trusted |
| `.validator_keystore/` | HMAC secrets, Ed25519 private keys | ability to sign as a validator |
| appointment records + evidence artifacts | the external ground truth | ability to fabricate onboarding provenance |
| `revalidation_policy.json` | freshness constraints | ability to keep stale trust alive |

## Threat analysis

### 1. Registry tampering (in-place edit)

**Defended today.** Every event carries `event_binding`; the chain links each
event to its predecessor (`prev_event_binding`, GENESIS-rooted). In-place
edits, insertions, deletions, and reorderings anywhere in recorded history
break the chain; a broken chain taints the whole registry — no validator is
trusted, nothing routes (`test_ova7`, `test_vt8`).

### 2. Rollback attacks

Two shapes:

- **Mid-history excision** (e.g. deleting a ROTATE or a REVOKE between other
  events): **detected today** — the successor's `prev_event_binding` no longer
  matches (`test_ova7`).
- **Tail truncation** (deleting the newest events, e.g. the final REVOKE, or
  restoring an old copy of the whole file): **NOT detectable from the file
  alone.** The truncated registry is a valid chain prefix. This is the
  fundamental custody gap: append-only files cannot self-prove their own
  length. Mitigation requires an external anchor — see recommendations R-A/R-B.

### 3. Keystore compromise

- HMAC keys: an attacker with keystore read access can sign as any HMAC
  validator; with write access they can substitute keys, which the registry
  fingerprint **detects** (`test_vt8b`), but a read is silent. HMAC keys are
  symmetric: verification capability IS signing capability.
- Ed25519 private keys: theft enables signing as the validator; the public
  key in the registry is unaffected. Rotation (a new ROTATE event) bounds the
  damage window: signatures after the rotation instant under the old key are
  refused (`test_rotated_key_history_remains_auditable`). Detection of theft
  itself is out of band (the validator noticing).
- Preference order: Ed25519 over HMAC (already implemented as dual mode);
  hardware-backed keys over file keys (R-D).

### 4. Insider threats

The critical insider is whoever can write registry + keystore + evidence
files together — today, any operator of this repository. Such an insider can
fabricate a complete coherent validator (valid chain from GENESIS, own key,
self-consistent appointment record with self-made "evidence" bytes). In-file
cryptography cannot distinguish this from a real onboarding: the chain proves
*continuity*, not *authenticity of origin*. Containment is procedural +
structural:

- the onboarding CLI records appointment provenance
  (`appointment_binding`, evidence digests) so a later audit can demand the
  real artifacts behind every REGISTER event;
- self-appointment is structurally refused, so the fabrication needs a forged
  *external* authority, which auditing can pursue;
- the remaining gap is closed only by dual control and external anchoring
  (R-A/R-C), not by more hashing.

### 5. Dual-control requirements (recommended, not implemented)

- **R-C:** registration of a validator should require two distinct humans:
  one supplies the appointment + evidence, another (with separate credentials)
  co-signs the REGISTER event. Schema-ready: a REGISTER event can carry a
  `co_registered_by` block; the verifier would refuse single-signed
  registrations under a `dual_control: true` policy flag.
- Rotation/revocation may stay single-operator (they reduce trust; the
  fail-closed direction), but *un-revoking* must be impossible — it is today:
  there is no UNREVOKE event, and revocation survives anything except tail
  truncation (threat 2).

### 6. Signed registry commits (recommended — R-A)

Commit `validator_registry.jsonl` to version control and require signed
commits (or wrap each append in a signed git commit). Effect: tail truncation
now requires rewriting published history — detectable by any clone;
`git log` becomes the external anchor and independent witness. Cost: registry
becomes repository content (it holds only public material — identities,
fingerprints, public keys — so this is acceptable); operational coupling of
onboarding to git.

### 7. Hardware-backed key storage (recommended — R-D)

Ed25519 private keys in an HSM/TPM/security key (validators sign on their own
hardware; only public keys ever reach this package — the design already
supports this, since Ed25519 verification reads no keystore). Effect: keystore
compromise stops yielding signing capability. Cost: real key-ceremony
logistics; not implementable inside this repository.

### 8. Independent witnesses (recommended — R-B)

Periodically publish the registry head (`event_binding` of the newest event +
event count) to one or more independent channels (a signed tag, a transparency
log, a second repository, a printed record in the appointment file). A
verifier comparing the live registry against any witness detects tail
truncation up to the witness's freshness. Cheapest effective anchor; pairs
with R-A.

## Priority (when custody work is scheduled)

1. R-A signed registry commits — closes rollback (threat 2) with existing infra.
2. R-B witness heads — defense in depth for the same gap, near-zero cost.
3. R-C dual-control registration — the only structural insider containment.
4. R-D hardware keys — strongest, most operationally expensive.

Until implemented, these remain **recorded residual risks**; the in-file
chain + fingerprints + provenance + fail-closed derivation are the current
custody floor, and an empty registry (production today) has nothing to steal.
