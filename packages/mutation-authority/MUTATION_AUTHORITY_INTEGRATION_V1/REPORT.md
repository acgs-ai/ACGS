# MUTATION_AUTHORITY_INTEGRATION_V1 — Final Report

## What changed

The mutation-authority kernel (previously delivered, 15/15 verified) gained an
integration layer that makes it callable as the canonical mutation
authorization path for ACGS execution governance:

- **Runtime adapter** (`mutation_authority/adapters/runtime.py`) —
  `MutationGateway.request_mutation(context, resource, operation, content)`.
  Converts runtime requests into signed `MutationIntent`s; never mutates state
  itself (its only write path is `EffectBinder.commit`); rejects
  missing/unresolved/incomplete authority context before any intent exists;
  preserves actor identity end-to-end; emits an evidence reference per applied
  mutation. Deterministic: logical clock derived from the ledger head,
  hash-derived nonces, no wall time, no randomness.
- **Evidence graph** (`mutation_authority/evidence_emitter.py`) — one
  **root-key-HMAC-signed** record per committed mutation in
  `evidence_graph.jsonl`, carrying actor, resource, previous hash, new hash,
  decision, receipt id, policy version (hash of the sealed `policy.json` from
  the signed root manifest), an authority chain reference (`ledger_seq` +
  COMMIT `event_hash`), and a signature. Records are looked up from the ledger
  at emission time — the emitter refuses to fabricate evidence for a receipt
  with no COMMIT event; the signature makes a record un-forgeable without
  keystore access.
- **CI enforcement gate** (`mutation_authority/ci_gate.py`) — fail-closed
  verification: root integrity, ledger chain + anchor, genesis↔root binding,
  repository state == ledger-authorized state, per-COMMIT receipt provenance,
  and a COMMIT↔evidence bijection with root-key signature verification,
  per-receipt uniqueness (no duplicate shadowing), and full field
  cross-check (actor, resource, hashes, decision, policy_version, event hash,
  timestamp). The **entire** gate body runs under a fail-closed catch-all —
  any exception (malformed evidence line, schema-violating ledger payload,
  unreadable key) returns `passed=False`; there is no skip path and no raw
  raise.
- **Adversarial integration suite**
  (`mutation_authority/integration_verification.py`, mirrored by
  `integration_tests/test_mutation_boundary_attacks.py`) — attacks A–G plus
  happy path, gateway determinism, and a full kernel-suite re-run.
- **Deterministic acceptance command** — `verify_mutation_integration.py`.
- **Architecture + threat model** — `ARCHITECTURE.md` (this directory).

No existing file in the repository was modified. No workspace registration.
No existing governance layer (gove-zone, constitutional-hash gates, submodule
governance) was rewritten or touched.

## Files added

```
MUTATION_AUTHORITY_INTEGRATION_V1/ARCHITECTURE.md
MUTATION_AUTHORITY_INTEGRATION_V1/REPORT.md
mutation_authority/adapters/__init__.py
mutation_authority/adapters/runtime.py
mutation_authority/evidence_emitter.py
mutation_authority/ci_gate.py
mutation_authority/integration_verification.py
integration_tests/test_mutation_boundary_attacks.py
verify_mutation_integration.py
```

## Trust boundary analysis

Privilege tiers (strongest first):

1. **Keystore tier** — root key, actor keys, ledger anchor checkpoint. Must
   sit outside every agent-writable path. A writer here owns the layer; every
   guarantee below assumes this tier is intact.
2. **Governance-layer files** — ledger + evidence graph. Writable bytes, but
   every tamper mode exercised (edit, truncate, rewrite, delete+regenerate,
   strip evidence, fabricate evidence) is detected and fails closed.
3. **Governed repository** — mutable only through `EffectBinder` with a valid
   receipt; out-of-band writes are detected, attributed by resource, and
   non-launderable (the engine compares disk to the ledger, not to the
   intent).

The adapter adds **no new writable surface**: it holds no state, performs no
filesystem writes, and every one of its outcomes is either a ledger event
(DECISION/COMMIT) or a rejection that leaves zero state change.

## Attack results (literal, from `python3 verify_mutation_integration.py`)

```
[PASS] integrated happy path: adapter → receipt → effect → evidence → gate  APPLIED with receipt + evidence; CI gate green
[PASS] deterministic gateway behavior                                       identical request ⇒ identical verdict; denials emit no evidence
[PASS] ATTACK A: direct filesystem mutation bypass                          gate FAIL (attributed to resource); laundering request DENIED
[PASS] ATTACK B: fake mutation receipt / fabricated evidence                forged receipt REJECTED; unsigned/fabricated evidence fails the gate
[PASS] ATTACK C: valid receipt reused                                       consumed receipt reuse REJECTED; state and gate unaffected
[PASS] ATTACK D: actor scope escalation / impersonation                     out-of-scope DENIED; cross-actor key impersonation DENIED
[PASS] ATTACK E: ledger rollback                                            rollback DETECTED by gate; gateway fails closed on the rolled-back chain
[PASS] ATTACK F: evidence emission removed                                  stripped evidence ⇒ gate FAIL: silent mutation named per COMMIT
[PASS] ATTACK G: runtime adapter bypass                                     no/unresolved/incomplete context REJECTED; binder demands issued receipt
[PASS] ATTACK H: clock-skew receipt-expiry DoS                              count-based clock immune to injected timestamps; victim receipt survives
[PASS] ATTACK I: evidence forgery / duplicate shadowing                     forged record fails root-key signature; duplicate shadowing blocked
[PASS] ATTACK J: ci_gate exception-safety (malformed input)                 malformed evidence and ledger payloads both fail closed (no raw raise)
[PASS] compatibility: full kernel suite re-run                              kernel suite still green (15/15)

ALL CHECKS PASSED
```

Compatibility (also re-run, literal): `python3 verify_mutation_governance.py`
→ `ALL CHECKS PASSED`; `python3 -m pytest tests -q` → `15 passed`;
`python3 -m pytest integration_tests tests -q` → `28 passed`.

Attacks H, I, and J were added after an independent adversarial review of this
integration phase reproduced three real gaps (clock-skew DoS via unauthenticated
ledger timestamps; unsigned evidence records forgeable by anyone with
evidence-file write access; `ci_gate` steps 4–6 not exception-safe). All three
are fixed and are now permanent regression checks.

## Remaining limitations

- **Adoption is voluntary until callers are wired.** The adapter is the
  canonical path *by contract*, not by OS enforcement. gove-zone's executor
  and other runtimes still have to call `MutationGateway` — that wiring is a
  follow-up inside each caller (gove-zone's mutation-relevant modules are
  currently owned by other in-flight sessions and were deliberately not
  touched). Until then, non-integrated code paths remain path (a) of the
  architecture doc: detected and non-launderable, not prevented.
- **Crash window between COMMIT and evidence append.** The mutation lands in
  the ledger first; if the process dies before the evidence append, the gate
  reports a silent mutation until evidence is re-emitted (it is recomputable
  from the ledger — `EvidenceEmitter.emit_for_receipt` reads the COMMIT event,
  so recovery is deterministic). Fail-closed, never fail-open.
- **Single-host, cooperative concurrency.** Ledger append is not multi-process
  locked; interleaving safety comes from pre-state binding + the anchor, and a
  corrupted interleaving halts the layer rather than being exploitable. True
  multi-process deployment should add an advisory lock around decide/commit.
- **HMAC trust anchor.** Symmetric keys; verifiers must hold secrets. Ed25519
  upgrade path documented in the kernel README.

## What is NOT guaranteed

Stated explicitly, per the success criteria:

- **No repository-wide governance claim.** Only mutations routed through the
  runtime adapter (or the kernel pipeline directly) are *authorized*;
  everything else under `governed_prefixes` is *detected and denied
  laundering*, and paths outside `governed_prefixes` are entirely out of
  scope.
- No protection against an attacker who can write the keystore tier (root
  key, actor keys, anchor) — that is the stated boundary, not a gap.
- No OS-level prevention of raw writes to governed files (pair with read-only
  mounts / a broker process for that).
- No claim over gove-zone's own execution-governance guarantees — untouched,
  unchanged, still its own layer.
- Not compliance-certified, not formally verified, not production-certified.
  This is an alpha, production-shaped foundation with a deterministic,
  regression-gated adversarial suite.

## Before / after

```
Before:  agent → possible mutation → audit afterwards
After:   agent → Intent → Authority Decision → Receipt → Effect → Evidence
```

No valid receipt, no mutation — on every integrated path.
