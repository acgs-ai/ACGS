# EXTERNAL_SUBSTRATE_IDENTITY_AND_AUTHORITY_INGESTION_V1 — Architecture

## The three objects, never collapsed (Section 1)

```
A. EXTERNAL DATA SUBSTRATE   232 GB downloaded COMMERCIAL_BUYER_READINESS_V1 bundle
                             read-only; NEVER copied into this repository
        |  bound by (bytes of a 15-object critical set)
        v
B. SUBSTRATE IDENTITY        substrate_identity.json — small, repo-governed,
                             path-independent cryptographic description of A
        |  consulted by (every governed transition binds B.critical_set_digest)
        v
C. AUTHORITY EVIDENCE        externally sourced records establishing a real
                             data controller / counsel identity, each hashing a
                             real source document
```

Enforced separations (never silently crossed):

```
SUBSTRATE BYTES  != SUBSTRATE IDENTITY   (A is 232 GB; B is 15 hashes + counts)
SUBSTRATE IDENTITY != LEGAL AUTHORITY    (B proves "same artifact"; C proves "who")
LEGAL AUTHORITY  != COMMERCIAL RIGHTS    (C says who may be asked; rights_assertion stays null)
ROUTING AUTHORITY != RIGHTS CLEARANCE    (READY_TO_SEND != the right exists — I6)
```

## Data flow

```
build_substrate_identity.py  --reads-->  A (15 critical objects, live registries)
                             --writes-->  B (substrate_identity.json, in THIS package)

ingest_authority_evidence.py --reads-->  a real source document (hashes its bytes)
                             --writes-->  authority_evidence_registry.jsonl (THIS package)
                             --mints -->  an ingestion receipt

verify_authority_state.py    --reads-->  A (read-only), B, C
                             --runs  -->  verify_substrate_identity -> authority_router
                             --emits -->  Section 23 report + one verdict
```

The substrate (A) is only ever read. Every artifact this package produces —
identity manifest, evidence registry, keystore, transition ledger — lives in the
package directory. Invariant **I13** (substrate bytes untouched) is asserted by
re-verifying identity after every run.

## Request lifecycle (Sections 12, 13)

```
ROUTING_REQUIRED
   | verified, in-effect, in-scope authority evidence covers the request
   v  (receipt #1)
ROUTING_RESOLVED
   | send-gates pass (rights_assertion still null, evidence still in effect)
   v  (receipt #2)
READY_TO_SEND
   | external send, only if separately authorized (out of scope here)
   v
SENT
```

A request leaves `ROUTING_REQUIRED` **only** through `authority_router.route`,
and each transition binds a single-use receipt. Aggregate counts
(`ready_to_send`, `routing_required`, the two routing bases) are a **pure
function** of the request records overlaid with these transitions
(`derived_counts`) — never a stored, editable counter (**I8**, Section 11).

## Why a request resolves — the gate (`evidence_covers_request`)

All must hold, or the request stays fail-closed:

| Condition | Invariant |
|---|---|
| evidence `verification_state == AUTHORITY_EVIDENCED` (not merely IDENTITY_EVIDENCED) | I2 |
| authority class matches the routing basis (controller↔`NO_APPOINTED_CONTROLLER`, counsel↔`NO_EVIDENCED_COUNSEL_IDENTITY`) | I4 |
| the evidence scope covers the request's assets **and** requirement | I3, I5 |
| evidence in effect at the decision instant and not revoked/expired | I12 |
| the request currently `ROUTING_REQUIRED` and its `rights_assertion` is null | I7 |

Controller authority can satisfy at most the 34 `NO_APPOINTED_CONTROLLER`
requests; counsel authority at most the 306 `NO_EVIDENCED_COUNSEL_IDENTITY`,
and only within its evidenced scope. Neither class ever crosses to the other.

## Receipt binding (Sections 13, 14)

`receipt_id = sha256(canonical(decision_inputs))` where the decision inputs are
`{request_id, prior_state, new_state, authority_evidence_id, evidence_digest,
authority_scope_digest, substrate_critical_set_digest, policy_version}`. A
receipt is therefore intrinsically bound to exactly one request, transition,
evidence object, evidence-document hash, scope, and substrate identity. Reusing
it anywhere else changes a bound input, so the recomputed `receipt_id` no longer
matches and `verify_receipt` returns False; a `ReplayLedger` additionally
enforces at-most-once. Signatures are HMAC-SHA256 over the canonical body with a
key held in a keystore outside the substrate. `created_at` is a supplied logical
instant — no wall-clock — so receipts are reproducible.

## Identity strength & fail-closed drift (Sections 5, 6, 16)

Identity is `EXACT_PRIOR_SUBSTRATE` justified by three legs — authorship path
binding, exact critical-object hashes, exact count fingerprint — and one
explicit gap: **no VCS lineage** (`vcs_lineage: unavailable`). It never claims
commit ancestry. Because identity is keyed on the *bytes* of the critical set
via relative paths, a relocated-but-identical substrate still confirms
(Section 6); any changed critical object, missing object, or count drift fails
closed (`IDENTITY_MISMATCH` / `IDENTITY_UNVERIFIABLE` / `SUBSTRATE_DRIFT`) and
verification never regenerates the manifest to paper over the change.

## Read-only substrate (Section 17)

The legacy `verify_readiness.py` couples validation with writing child
`verification_report.json` files, which fails on the read-only Downloads mount
(`OSError: [Errno 30]`). This package does its own read-only verification and
never writes into the substrate, so "logic verified" is never confused with
"legacy report emission failed."

## Relationship to mutation-authority

The receipt discipline mirrors the sibling mutation-authority kernel
(canonical-JSON hashing, HMAC signing, single-use binding, keystore outside the
governed tree); `_canonical.py` is vendored byte-for-byte from it. This layer
governs **authority-state** transitions over an external substrate; it neither
weakens nor bypasses the mutation kernel, and it performs **no repository
mutation** (so no mutation receipt is required this round).
