# Rung 3 — Licensee-Keyed Canaries and the Breach Evidence Chain

Design v2.1 · 2026-08-15 · status: APPROVED-WITH-CONDITIONS (round 2), all conditions applied in this revision — see §12 review log
Scope: the published AGEC governance corpus (`dislove/acgsgovernance` on Hugging Face, gated `auto` since 2026-08-15) and its release pipeline (`release_candidate_v2/_build/` in the working bucket).

---

## 0. Scope, stated first

**Rung 3 v1 marks the published ~100-trajectory sample PACKAGE.** The commercially
valuable full corpus (12,442 trajectories) is not published and is **unprotected by
this design** until it has its own T1 delivery channel; the power figures in §6 do
not transfer to a 12k-record delivery (canary density drops ~100×) and must be
re-derived for that channel when it exists.

## 1. Goal and non-goals

**Goal.** When published content surfaces where the license forbids it, produce an
evidence chain from the observation back to an accountable party. The chain differs
by tier, and terminates differently — stated exactly:

**T1 (licensed delivery) — attribution chain:**
```
canary observed
  → canary hash is a leaf in variant commitment C     (Merkle inclusion proof)
  → C is publicly anchored at time T₀ < observation    (anchor file, §5.2)
  → C is bound to variant_id V in the signed ledger    (ledger entry, §5.1)
  → V's tree hash was COUNTERSIGNED by licensee L      (two-sided artifact, §5.3)
  → L's executed license references the same hashes
```
Terminates at: a named, contracted licensee, as a member of the **custodian set**
of that copy — not as proven trainer, and not uniquely (see the frameproofness
non-goal below); custodianship, not intent (§9).

**T0 (public gated copy) — detection chain:**
```
global canary observed
  → leaf in the T0 commitment, shipped inside the public tree itself
  → published corpus (post-R1 revision) was used
```
Terminates at: "some accepting account or downstream copy" — **corpus-level
detection, not attribution.** Gated accounts can be throwaway pseudonyms; T0 never
names a party.

**Non-goals, stated so they cannot be inferred as claims:**

- **No prevention.** Rung 3 converts breach from unobservable toward attributable.
- **No robustness against a determined scrubber.** Verbatim canaries die to
  wholesale paraphrase. The threat model is bulk ingestion and lazy redistribution.
- **Detection power is regime-dependent (§6.3).** Realistic detection is
  fine-tuning on (or heavy duplication of) the pack; single-copy dilution into a
  large pretraining mixture is expected to be **below detection** for most canaries
  — the copyright-trap literature found single-occurrence sequences largely
  non-extractable without ~100–1000× duplication. We duplicate tokens within a
  variant (§6.2) and still claim only the fine-tuning/redistribution regimes.
- **No full collusion resistance in v1** (§6.4).
- **The pre-R1 public copy is unmarked, permanently.** Everyone who downloaded
  before R1 holds unmarked bytes; HF git history keeps the pre-R1 revision
  fetchable by commit even after republication. **Absence of canaries is never
  evidence of non-use** and must never be argued as such.
- **One-sided evidence exists in this design and is named as such.** Every
  publisher-held artifact (pool, ledger, salt, key) is publisher-fabricable in
  principle; its probative value comes only from external anchoring (§5.2) and the
  licensee countersignature (§5.3). Where an artifact lacks those, this document
  does not call it evidence.
- **Not frameproof against the publisher.** The publisher can deterministically
  reconstruct any variant (§8), so a canary hit identifies the **variant**, not
  which member of its custodian set — {the licensee, the publisher, anyone with
  restricted-store access} — released it. Anchoring and countersignature prevent
  fabricating the record; they cannot prove which holder of genuine bytes leaked
  them. Asymmetric fingerprinting (licensee-contributed secret randomness, so the
  publisher never holds the exact marked copy) is the known fix and is out of
  scope v1. Dispute wording names the custodian set accordingly (§9.7).

## 2. Current state and the two constraints that shape everything

1. **One copy for everyone.** A gated HF repo serves identical bytes to every
   accepted account; per-licensee bytes need a separate channel.
2. **The sealed tree is load-bearing.** Variants must be re-sealed releases, never
   patched trees.

Two-tier distribution:

| Tier | Channel | Marking | Acceptance artifact | Chain ends at |
|---|---|---|---|---|
| T0 public-gated | HF repo, gated auto | one global canary set + overt corpus mark | HF click-through record | detection only |
| T1 licensed | private HF repo per licensee, or signed URL | licensee-keyed set + overt variant mark | **executed license agreement citing base_tree_sha256 + VARIANT_MANIFEST hash, countersigned at delivery** | named licensee |

For T1 over signed URLs there is no HF acceptance record; the acceptance artifact is
the contract, by design, in every T1 case (§5.3).

## 3. What a canary is in this corpus

The sample trajectories are **real captured sessions** (Claude Code / Codex /
Cursor), already disclosed by the datasheet and redaction policy as processed and
redacted before publication. That fact constrains the design more than anything
else: fully synthetic records sitting among real captures are exposed to outlier
detection (singleton tool names, incoherent environment fingerprints, implausible
latencies, perplexity), and the datasheet's "real trajectories" description would
become false the moment synthetic records were silently added.

Marking layers, and what each honestly delivers:

**3.1 Overt variant mark (strippable, catches the lazy case).** One schema-valid
field per record — **`provenance_mark`**, named honestly (§11: schema camouflage
buys nothing once §7 discloses marking) — + `VARIANT_MANIFEST.json` at tree root. Trivially removable; most real-world redistribution is verbatim.

**3.2 Token-level canaries inside real records (primary mechanism).** Canary tokens
— unique, high-entropy, never-published strings shaped like the corpus vernacular
(fake paths, fake tool-argument values, fake hashes, distinctive sentences) —
injected into fields of **real trajectories**, under the same processing regime the
datasheet already discloses (redaction/processing pass). The datasheet gains one
sentence: processing includes provenance marking (§7). This keeps the datasheet
true (records remain real captures, disclosed as processed) and removes the
synthetic-record outlier surface: the adversary's distinguisher problem shifts from
"find the fake records" to "find the modified fields inside real records," which is
strictly harder but **not claimed to be hard**:

- Claim made: marking **raises removal effort above verbatim copying**, aligned
  with the §1 threat model. No "statistically camouflaged" claim survives from v1.
- Claim tested, not assumed: §8 adds a pre-release **adversarial distinguisher
  test** — a reviewer without pool knowledge ranks records/fields by suspicion;
  the measured result is the only camouflage statement the card or any dispute may
  cite.

**3.3 In-document canaries.** Worked examples in the documentation are already
invented values; variant builds key them. Documents survive in dumps where JSONL
gets filtered, and token duplication across docs + records (§6.2) is what buys
detection power.

**3.4 Synthetic canary records (optional, disclosed).** If a variant includes fully
synthetic trajectories, their **count is disclosed** in that variant's manifest and
datasheet delta. Undisclosed synthetic records are prohibited — that is the
BLOCKER-2 line: a false datasheet cannot ship from this project.

## 4. Integrity architecture — variants as first-class sealed releases

```
base PACKAGE (canonical, archived, hash recorded)
  + token injections per allocation plan (§6)
  + overt variant mark
  + VARIANT_MANIFEST.json { variant_id, base_tree_sha256, built_at,
                            canary_commitment, allocation_manifest_hash,
                            synthetic_record_count, tier }
  → REGENERATE DERIVED ARTIFACTS over the injected tree
    (labels, verification scan reports — anything computed from trajectory content)
  → regenerate SHA256SUMS + RELEASE_MANIFEST.json (variant-local)
  → verify_release.py: existing gates unchanged and passing; TWO gates added
    (commitment recomputes from the allocated pool hashes;
     derived artifacts are consistent with the injected trajectories)
```

**Derived-artifact regeneration is not optional.** Scan reports and labels computed
over the original trajectories would (a) hand the adversary a mechanical canary
detector — diff trajectory content against its own scan coverage and every injected
field lights up — and (b) ship a sealed release whose internal evidence artifacts
no longer describe its content, exactly the claim inconsistency this project
refuses. Every variant's derived artifacts are re-run (or verifiably reconciled)
over the injected tree, and the added verifier gate checks that consistency.

- `variant_id`: 128-bit random; the artifact carries nothing licensee-identifying.
- **The T0 build goes through the same `build_variant.py` path**, and its
  `VARIANT_MANIFEST.json` — commitment included — **ships inside the public tree**.
  This makes the public HF repo itself the anchor for T0 (§5.2) and closes the
  "T0 commitment exists only in private notes" gap.
- `base_tree_sha256` proves descent: reviewed corpus plus a marked delta, not a fork.

## 5. Ledger, anchoring, and the one two-sided artifact

### 5.1 The ledger (publisher-side record)

Append-only JSONL, hash-chained (gove-zone audit-chain pattern), Ed25519-signed per
entry once the organizational key exists.

```json
{
  "seq": 41,
  "prev": "sha256:…",
  "event": "variant.issued",
  "variant_id": "vt_9f27c4…",
  "tier": "T1",
  "canary_commitment": "merkle:…",
  "allocation_manifest_hash": "sha256:…",
  "base_tree_sha256": "…",
  "licensee_ref": "hmac-sha256:…",
  "acceptance_ref": { "kind": "contract", "doc_hash": "sha256:…" },
  "delivery": { "channel": "hf-private-repo", "ref": "…", "countersign_ref": "sha256:…" },
  "issued_at": "2026-08-15T…Z",
  "sig": "ed25519:…"
}
```

- Personal data stays out: `licensee_ref` is salted-HMAC; acceptance records and
  the licensee roster live beside the salt in the restricted store as
  hash-referenced documents, **never inlined** into the append-only chain.
  De-linking on erasure request = crypto-shredding (destroy salt + mapping);
  roster retention policy documented with the runbook.
- `allocation_manifest_hash` commits the per-canary allocation matrix (which
  canary went to which variants) so §6.4's coalition inference rests on a
  ledgered artifact, not side notes.

### 5.2 External anchoring (answer to publisher self-attestation)

A hash-chained ledger whose only key the publisher holds proves nothing about
*when* an entry existed — the publisher could regenerate and re-sign the whole
chain after an observation. Therefore, on a fixed cadence and at every append:

- **Ledger head hash** stamped via RFC 3161 / OpenTimestamps and mirrored to a
  public anchor file in the HF repo. **The timestamp stamp is the anchor of
  record; the HF file is a convenience mirror** — HF permits owner force-push, so
  a repo the publisher controls cannot be the constraint on the publisher.
- **Pool-manifest hash** anchored at pool creation, before any variant is built.
- **T1 commitment roots** (roots only — no licensee data) anchored at issuance.
- **The frozen probe-protocol document's hash** anchored before any dispute (§9).

The anchor converts "we say this commitment predates the observation" into "a
third-party-timestamped record shows it." Without an anchor, an artifact in this
design is publisher testimony and is labeled as such.

### 5.3 The countersignature (the only two-sided evidence)

At every T1 delivery, the licensee **countersigns the variant tree hash**
(`base_tree_sha256` + `VARIANT_MANIFEST` hash), in the license execution or a
delivery acknowledgment. This single artifact closes both directions at once:

- *Publisher-fabrication:* L's signature over the hashes proves the variant — and
  its commitment — existed before any dispute, independent of every
  publisher-held key.
- *Receipt-denial:* L cannot later claim non-delivery or a different tree.

No T1 issuance without it. It is the highest-value line in this design.

## 6. Allocation, statistics, and collusion

**6.1 Pool.** N ≈ 256 canary tokens generated per corpus release. **Review happens
in plaintext, only inside the restricted boundary** (named store; no CI, no PR
attachments, no reviewer laptops outside the boundary): the scanners run there
(a canary must never be a real path, credential shape, or person), and what exits
is the hash manifest plus a signed reviewer attestation. This resolves the v1
contradiction between "never-on-the-internet" and "reviewed like release content"
— hashes-only review cannot check content; plaintext review outside the boundary
creates the contamination defense ("your own CI logs held the canary").

**6.2 Duplication inside a variant.** Each allocated token appears in **multiple
places** — several records' fields and several documents (§3.3) — because the trap
literature is clear that single-occurrence sequences are mostly non-extractable
from large-scale training. Record-level uniqueness of the marks is preserved;
token-level duplication is the power budget.

**6.3 Power, honestly scoped.** Detection is a pre-registered hypothesis test
(§9): allocated-token probes vs. matched never-shipped controls. The claim is
limited to the regimes where it is defensible — fine-tuning on the pack,
verbatim/near-verbatim redistribution — and the runbook carries an explicit power
analysis in place of v1's "comfortable separation." Dilute-pretraining detection
is *hoped for, not claimed* (§1 non-goals).

**6.3b T0 canary budget.** The T0 global set is small (~16) and every canary
disclosed in a dispute is burned (§9.3) with no replenishment until the next
corpus release. T0 disputes are therefore expected to be rare and aggregated;
the budget is a stated operational constraint, not an incident.

**6.4 Collusion, honestly.** Two T1 licensees diffing trees find the symmetric
difference of their unique subsets, not the shared subset, which still fires on a
merged copy and identifies the coalition's tier. The allocation matrix is
committed per §5.1, so coalition inference later is computable from ledgered
artifacts. Formal traitor-tracing codes remain out of scope v1.

**6.5 Probe custody split.** Probe prefixes are stored **separately** from the
pool (different sub-store, different access grant), so a dispute-time pool
disclosure — or a pool compromise — does not burn the probe set. (Resolves v1
open question 3.)

## 7. Disclosure — accurate per tier, shipped only when true

The card paragraph ships **with R1, not before** (shipping it at R0 would be false
for the whole R0→R1 window and would advertise the unmarked-copy grab). Wording is
tier-accurate:

> The public copy of this dataset carries a global provenance mark; individually
> licensed copies are individually marked. Access requires a recorded terms
> acceptance. Marks are designed to surface under memorization probing of trained
> models. Processing of the sample trajectories includes provenance marking (see
> datasheet). Locating or removing marks does not exempt any user from the license
> terms.

The datasheet's processing section gains the marking sentence in the same commit —
the datasheet must never describe the records as unprocessed captures once marks
are in (§3.2). Disclosure costs detection little in the claimed regimes, deters,
and makes marking a term the accepting click covered.

## 8. Pipeline changes (release tooling)

| Piece | Change |
|---|---|
| `_build/canary_pool.py` (new) | pool + probe generation; plaintext scan inside restricted boundary; exports hash manifest + reviewer attestation |
| `_build/build_variant.py` (new) | base + allocation → injected, re-sealed variant tree; deterministic given (base, allocation, variant_id); **T0 and T1 both build through it** |
| `_build/verify_release.py` | existing gates unchanged and passing on every variant; one added gate: VARIANT_MANIFEST commitment recomputes from allocated pool hashes |
| `_build/ledger.py` (new) | append + chain-verify + sign + **anchor emit** (head hash file + timestamp receipt) |
| adversarial distinguisher test (new, pre-R1 gate) | **measurement-only, declared as such**: any result ships and its number is what the card and disputes may cite — no pass threshold is pretended. The test includes the automated attacks the adversary would run (perplexity outliering, schema/frequency statistics, and the derived-artifact/scan-report diff of §4) plus a pool-blind human reviewer ranking records/fields by suspicion. Protocol and result hashes anchored (§5.2); internal pool-blindness suffices for v1 |
| card / DATASHEET | §7 paragraph + processing-includes-marking sentence, **landing with R1** |
| dispute runbook (new doc) | §9; its hash anchored per §5.2 before any dispute |

All new code under author≠reviewer discipline.

## 9. Dispute runbook (frozen, anchored, summary)

1. **Trigger:** canary token observed (model output, dump, redistribution).
2. **Chain verification first:** ledger chain-verify; confirm the relevant
   commitment's **anchor timestamp precedes the observation**; token → pool hash →
   Merkle path → commitment → ledger entry → (T1) countersigned tree hash.
3. **Contamination exclusion before any training inference:** probe with
   retrieval/browsing disabled where possible, **and archive a web-absence check
   for the token at probe time regardless** (an absence check alone cannot see
   private leak channels feeding RAG); any canary disclosed in a prior dispute is
   **burned** for all future disputes; probe transcripts land in the restricted
   store immediately.
4. **Pre-registered statistics:** the frozen protocol fixes decoding parameters,
   repetition counts, control construction, per-canary thresholds, and
   multiple-comparison handling across k canaries and across repeated disputes —
   before the first probe is run, with the document hash anchored (§5.2).
5. **Lawful collection:** probing a hosted model at scale can breach that API's
   terms; the runbook specifies how probe evidence is gathered lawfully (own
   instance, licensed access, or counsel-approved scope) before any campaign.
6. **Resolve the party (T1 only):** `licensee_ref` + salt → identity; pull the
   contract and countersignature.
7. **Output wording, fixed in advance:** *"content unique to the variant issued to
   L under terms T surfaced in X; L accepted T on D and countersigned the variant
   hash. The custodians of this variant's bytes are L and the publisher's
   restricted store; the publisher's own custody is attested by [restricted-store
   access log / anchor record]."* Custodian set named, not a unique releaser
   (frameproofness non-goal, §1). Custodianship, not intent. A T0 hit is reported
   as corpus-level use, never as attribution to an account.

## 10. Rollout

1. **R0 (now):** this design through review; ledger + anchor tooling built and
   fixture-tested; restricted store provisioned; **no public claims shipped**.
2. **R1 (public rebuild) — preconditions, all hard:**
   - datasheet resolution per §3.2/§3.4 in the same commit (BLOCKER-2 line);
   - derived artifacts (labels, scan reports) regenerated over the injected tree
     and the consistency gate passing (§4);
   - adversarial distinguisher test run, result recorded and hash-anchored
     (measurement-only — the number ships whatever it is);
   - **pool-manifest, protocol, and reviewer-attestation hashes anchored via
     RFC 3161 / OpenTimestamps at R1** — anchoring needs a hash and a stamp, not
     the org key; the attestation is hash-anchored until the key exists (the
     anchor emitter must therefore be runnable standalone at R1, not first at R2);
   - T0 build via `build_variant.py`, commitment shipped in-tree;
   - card + datasheet disclosure lands in this release;
   - changelog owns the SHA256SUMS churn and the versioned re-release; the pre-R1
     revision remains fetchable in HF history — documented, accepted, and never
     presented as retired (no history rewrite: silently editing public history is
     the kind of claim-laundering this project exists to refuse).
3. **R2 (first T1 delivery):** blocked on the organizational Ed25519 key AND the
   countersignature flow. Ledger goes live with entry 1 + first anchor emit.

## 11. Questions resolved in round 2

- Overt-mark field name: **`provenance_mark`, explicit.** Schema camouflage of the
  overt mark buys nothing once §7 discloses marking.
- Anchor cadence: **per-append for issuance events** (T1 is low-volume by
  construction), **daily batch for the head file otherwise.** The runbook's
  "anchor precedes observation" test makes the window the only thing that
  matters; per-append issuance makes it zero where it counts.
- Distinguisher reviewer: **internal pool-blindness suffices for v1** given
  protocol + result hashes are anchored; an external reviewer strengthens
  citability and can be added without design change.

## 12. Review log

- **Round 1 (security-auditor lane, 2026-08-15): REVISE.** B1 self-attested chain
  → §5.2 anchoring + §1 one-sidedness non-goal + §5.3 countersignature. B2
  datasheet falsity → §3.2 token-level primary mechanism + §3.4 disclosure rule +
  R1 hard precondition. M1 camouflage overclaim → claim downgraded to removal-cost
  + distinguisher test as the only citable statement. M2 power → §6.2 duplication,
  §6.3 regime scoping, runbook power analysis. M3 contamination → §9.3 controls,
  burned-canary rule, transcript custody. M4 legacy population → §1 non-goal +
  §10 R1 history decision. M5 chain per tier + countersignature → §1, §2, §5.3.
  M6 pool review contradiction → §6.1 restricted-boundary plaintext review; Q3
  resolved via §6.5 custody split. M7 R0 false disclosure → §7 ships with R1. M8
  "individually marked" overclaim → tier-accurate wording + per-tier chain
  termini. Minors: T0 via build_variant.py in-tree (§4); ledger PII out, hash
  refs + crypto-shredding (§5.1); allocation_manifest_hash ledgered (§5.1);
  wording fixes (§4, §7).
- **Round 2 (same lane, 2026-08-15): APPROVE-WITH-CONDITIONS.** All round-1
  findings verified closed in text. Conditions, all applied in v2.1:
  C1 (MAJOR) not-frameproof-against-publisher non-goal + custodian-set dispute
  wording → §1, §9.7. C2 (MAJOR) derived-artifact regeneration + consistency
  gate → §4, §10 R1. C3 anchor sequencing: pool/protocol/attestation hashes
  RFC3161/OTS-anchored at R1 without the org key → §10. C4 timestamp stamp =
  anchor of record, HF file = mirror (owner force-push) → §5.2. C5 distinguisher
  test declared measurement-only + automated attacks incl. scan-report diff →
  §8. Notes: T0 canary budget (§6.3b), anchor cadence + field name + reviewer
  scope resolved (§11), M3 nit (absence check archived regardless, §9.3).
  Review cycle cap (2) reached; conditions applied without a third round.
