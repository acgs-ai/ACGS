# acgs-canary R0 — Implementation Notes

Normative design: `DESIGN.md` (v2.1, APPROVED-WITH-CONDITIONS after two
independent adversarial review rounds; all conditions applied). Where this
document and the design conflict, the design wins; deviations must be
recorded as explicit blockers, never silently reinterpreted.

## 1. Threat model (R0 slice)

Adversaries considered:

| Adversary | Capability | Countermeasure |
|---|---|---|
| Licensee (or downstream holder) trains on / redistributes the data | full access to their variant bytes | covert canaries + overt marks; commitments; ledger; countersignature |
| Ledger tamperer (including a compromised operator account) | rewrite ledger lines | hash chain + canonical encoding + entry hashes; external anchors make rollback detectable |
| Publisher post-hoc fabrication | full control of all publisher-held artifacts | external anchoring (RFC3161/OTS) + licensee countersignature — the only two-sided artifact |
| Signature replayer | valid signatures from other contexts | signatures bind ledger_id + protocol + role + purpose via length-prefixed payloads |
| Secret exfiltration via outputs | reads CLI output, logs, evidence packs | Secret wrapper redaction; exports carry digests only; leak-scan tests |

Explicitly NOT countered (design non-goals, restated):
- prevention of training or redistribution;
- a determined scrubber who rewrites all content;
- framing by the publisher (the publisher can rebuild any variant —
  a canary hit identifies the **custodian set**, not the releaser);
- dilute-pretraining detection (not claimed; trap literature shows
  single-occurrence sequences are mostly non-extractable).

## 2. Trust boundaries

```
┌──────────────────────────────────────────────────────────────┐
│ RESTRICTED STORE (0700, outside any git worktree)            │
│  canary tokens · probe seeds (separate custody prefix)       │
│  selection salt · licensee-ref HMAC key · allocation records │
│  variant manifests · acceptance ledger                       │
└───────────────┬──────────────────────────────────────────────┘
                │ exports: digests & public ids only
┌───────────────▼──────────────────────────────────────────────┐
│ OPERATOR SURFACE (CLI): JSON results, no secret material     │
└───────────────┬──────────────────────────────────────────────┘
                │ anchor bundles (hashes only)
┌───────────────▼──────────────────────────────────────────────┐
│ EXTERNAL: RFC3161 / OpenTimestamps (anchor of record)        │
│ mirrors (supplementary only, publisher-controlled)           │
└──────────────────────────────────────────────────────────────┘
```

- Raw canary values, licensee identity, HMAC keys, and salts never cross
  the store boundary; the tests scan CLI transcripts for the secret field
  markers.
- Probe custody is a separate record prefix (`probe-*`) so dispute-time
  token disclosure does not burn the probe set (design §6.5).
- The in-memory backend is constructible only with a literal test-only
  acknowledgment string — no configuration pathway reaches it.

## 3. State machine (issuance lifecycle)

```
variant.prepared ──issuer signs──▶ issuer-signed ──licensee countersigns──▶ countersigned
      │                                   │                                     │
      └────────── all states: evidence_label = "publisher-testimony" ───────────┘
                                          until an anchor entry covers them ──▶ "anchored"
```

- Transitions are **append-only ledger entries**; prior entries are never
  mutated.
- `completed_t1_issuance` is true only in `countersigned`.
- Anchoring is orthogonal: it upgrades the evidence label, not the state.
- Rollback (deleting newest entries) yields a valid shorter chain by
  construction — this is inherent to hash chains, is covered by a test,
  and is exactly why heads must be anchored externally: a published
  anchor for a head that is no longer present exposes the rollback.

## 4. Operator workflow (R0)

```bash
export ACGS_CANARY_STORE=/secure/canary-store        # 0700, non-repo
acgs-canary pool-init --pool-id agec-v1 --operator you --init-store
acgs-canary pool-generate --tier T0 --count 16 --placements 2
acgs-canary pool-generate --tier T1 --count 64 --placements 3
acgs-canary pool-validate
acgs-canary variant-prepare --tier T1 --shared 8 --unique 16 \
    --source-release release_candidate_v2 --source-tree-sha256 <hash> \
    --issuer-ref issuer:acgs
acgs-canary variant-verify --variant-id vt_…
acgs-canary ledger-init --operator you
acgs-canary ledger-verify
acgs-canary anchor-prepare --out /secure/anchor-bundle.json
# submit the bundle hash to RFC3161/OTS out of band; record evidence
acgs-canary r0-selfcheck   # isolated end-to-end demonstration
```

## 5. Backup and recovery

- The restricted store is plain files: back it up with any encrypted,
  access-controlled mechanism, preserving permissions. A backup is secret
  material — the same handling rules apply.
- Ledger torn tails (crash mid-append) are detected on every verify and
  repaired only by the explicit `recover_torn_tail` operation, which drops
  at most one unparseable trailing line and re-verifies.
- Mid-chain corruption is not repairable — restore from backup and compare
  the head against the latest external anchor.

## 6. Key rotation and compromise

- **Licensee-ref HMAC key**: rotation breaks ref linkability by design;
  rotate only with a recorded mapping migration, or deliberately without
  one (crypto-shredding for erasure requests: destroy key + roster
  mapping to sever linkability).
- **Issuer signing key**: R0 has no organizational key. When it exists,
  compromise handling follows gove-zone's revocation model
  (`gove_zone.revocation`); ledger entries signed before revocation remain
  chained and anchored.
- **Selection salt**: compromise reveals allocation ordering, not tokens.
  Treat as a pool-generation trigger for the next release.

## 7. Canary burn / contamination procedure

1. A canary disclosed in any dispute, or found leaked anywhere, is marked
   `burned` (`pool-burn --confirm`).
2. Burned/contaminated canaries are never selected again (enforced).
3. The burn is an irreversible state transition; the record's history
   remains in the store.
4. T0 budget note (design §6.3b): the global set is small; expect rare,
   aggregated T0 disputes.

## 8. Verification procedure

- `pool-validate`: token digests, probe presence, status/tier legality,
  duplicate detection.
- `variant-verify`: recomputes the canary commitment and placement
  commitment from the store and checks the protocol hash.
- `ledger-verify`: full chain — canonical encoding, hashes, sequence,
  prev-links, signature bindings, duplicate-issuance.
- `r0-selfcheck`: end-to-end isolated run with a tamper case; emits the
  invariant report (all 15 must hold).

## 9. External-anchor limitations

- The anchor of record is external timestamp evidence. A repository or
  Hugging Face mirror is supplementary only: it is owned by the party the
  anchor constrains and is rewritable (owner force-push).
- R0 ships NO production anchor client. `FixtureVerifier` refuses evidence
  marked production; `ProductionAnchorUnavailable` refuses everything.
  No fake TSA or self-signed timestamp can be represented as production
  evidence.
- Anchor evidence states: requested → submitted → confirmed | failed |
  expired_or_invalid. Only confirmed independent evidence, verified, with
  anchor time strictly before the observation time, satisfies the dispute
  test.

## 10. What R0 proves — and does not prove

Proves (locally, with test keys and fixture anchors):
- the mechanisms compose: pool → selection → commitment → manifest →
  ledger → countersignature → anchor bundle;
- tampering, replay, role confusion, truncation, and torn tails are
  detected fail-closed;
- secrets stay behind the store boundary under the tested paths.

Does not prove (normative limits, from the design):
- detection or attribution of any real training run (no claim made);
- anything about the public dataset (untouched by R0);
- a completed commercial issuance (blocked on the organizational key and
  the countersignature flow with a real licensee);
- independence of any evidence not backed by a real external anchor —
  unanchored artifacts are publisher testimony;
- frameproofness against the publisher (custodian set, not releaser);
- coverage of the full 12k corpus (published sample pack only);
- exculpation by absence — a missing canary never proves non-use.

## 11. Prerequisites for R1 and production T1

R1 (public rebuild) — all hard, from design §10:
1. datasheet resolution (token-inject under disclosed processing; no
   undisclosed synthetic records) in the same commit;
2. derived artifacts regenerated over the injected tree + consistency gate;
3. adversarial distinguisher test run, result recorded and hash-anchored;
4. pool-manifest/protocol/attestation hashes RFC3161/OTS-anchored (needs
   no org key; anchor emitter must run standalone);
5. T0 build via the variant builder with the commitment shipped in-tree;
6. card + datasheet disclosure landing in the same release;
7. changelog owns the SHA256SUMS churn; pre-R1 revision stays fetchable
   and is never presented as retired.

Production T1 — additionally:
1. organizational Ed25519 signing key provisioned (custody outside this
   workspace);
2. real RFC3161/OTS anchor client (production adapter);
3. licensee countersignature flow executed with a real counterparty;
4. dispute runbook frozen and hash-anchored before any probe campaign.
