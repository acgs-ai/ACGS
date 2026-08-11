# mutation-authority — Mutation Authority Governance Layer

> **No Valid Mutation Decision Receipt, No Repository State Change.**

Minimal, logically complete governance layer that turns repository mutation
from a filesystem side effect into a **governed state transition**. Built for
multi-agent environments where autonomous sessions race on the same critical
files (the `verify_readiness.py` problem): unclear ownership, invalidated hash
baselines, unprovable integration evidence.

Stdlib only. Zero runtime dependencies. Deterministic (logical clock, no wall
time).

## Verification

```bash
python3 verify_mutation_governance.py   # must print: ALL CHECKS PASSED
python3 -m pytest tests -q              # same suite under pytest
python3 -m pytest tests integration_tests \
    EXTERNAL_SUBSTRATE_IDENTITY_AND_AUTHORITY_INGESTION_V1/attack_suite -q  # full package gate
```

CI: the full package gate runs in `.github/workflows/python-mutation-authority.yml`
(path-filtered) and via the root `make test-py` target.

## Architecture

```
agent
  │  MutationIntent (signed with actor identity key)
  ▼
DecisionEngine ──── reads ──► GovernanceRoot (immutable, manifest-sealed)
  │                           AuditLedger    (append-only hash chain)
  │  ALLOW ⇒ MutationDecisionReceipt (root-signed, single-use, expiring,
  │           bound to exact pre-state hash + existing parent identity)
  ▼
EffectBinder ── the ONLY writer to the governed repository
  │  re-verifies: root integrity, chain integrity, receipt signature,
  │  issuance-in-this-chain, single use, expiry, pre-state hash
  ▼
Filesystem effect (atomic tmp+rename)
  │
  ▼
COMMIT event appended to mutation_ledger.jsonl (hash-chained)
```

### Components

| Module | Responsibility |
|---|---|
| `mutation_authority/root.py` | **Immutable governance root.** `policy.json` + `actors.json` sealed by an HMAC-signed manifest. Signing keys live in a keystore *outside* the governed tree. `verify_integrity()` runs before **every** decision and **every** commit — tampered root ⇒ `RootIntegrityError` ⇒ the layer refuses all decisions (fail closed). |
| `mutation_authority/intent.py` | **Mutation Intent model.** `{actor_identity, resource_path, operation, expected_pre_hash, requested_change_scope, timestamp, task_reference}` + nonce, signed with the actor's key. Direct filesystem mutation is forbidden by construction: agents hold no write path other than `EffectBinder`. |
| `mutation_authority/engine.py` | **Deterministic decision engine.** Fixed check order: actor identity → intent signature → path safety → governance-root protection → governed prefix → scope permission (requested ⊆ actor ownership) → task authority → pre-state binding (disk **==** ledger-authorized state **==** `expected_pre_hash`) → concurrency (one live receipt per resource). First violation wins; every decision — ALLOW **and** DENY — is a ledger event. |
| `mutation_authority/receipt.py` | **Mutation Decision Receipt.** `{receipt_id, intent_hash, decision_hash, actor, resource, allowed_scope, expiry, previous_state_hash, parent_ancestor_path, parent_ancestor_device, parent_ancestor_inode}` signed by the root key. Single-use, expiring, chain-bound. |
| `mutation_authority/effect.py` | **Effect binding.** Opens the signed existing parent (or nearest existing ancestor for nested CREATE) by directory fd, requires its device/inode identity before any effect-time state read, and retains/revalidates the pin through mutation and audit append. Nested parent creation uses no-follow dirfd operations and transactional rollback. |
| `mutation_authority/ledger.py` | **Append-only audit chain** (`mutation_ledger.jsonl`). Each event embeds `prev_event_hash`; genesis binds the root-manifest hash and a baseline snapshot. An **anchor checkpoint** (`{count, head_hash}`, stored with the keystore, outside the governed tree) is updated on every append and re-checked on every chain verification — internal hash-chain consistency proves a self-consistent *prefix*; only the anchor proves *completeness* (no tail truncation, rewrite, or delete-and-regenerate). The genesis→root binding is enforced at runtime by engine and binder, not merely recorded. The ledger — not the filesystem — defines each resource's authorized state. |
| `mutation_authority/state.py` | **Out-of-band mutation detector.** Compares disk to ledger-authorized state; any divergence (modify/create/delete) is an unauthorized mutation. |
| `mutation_authority/verification.py` | Regression attack suite + structural checks, shared by the CLI gate and pytest. |

### Why bypass is impossible, not just forbidden

1. **Detection:** `repository_violations()` compares every governed resource
   against the ledger-derived authorized hash. A direct write is visible as
   `unauthorized_modify` the moment anyone checks.
2. **Non-launderability:** the engine's pre-state check compares disk against
   the **ledger**, not against the intent. An agent that bypassed the engine
   cannot subsequently get *any* mutation approved on that resource — the
   divergence blocks it — so bypass buys nothing durable and is always
   attributable.
3. **Governance root:** intents targeting the root are DENYed *structurally*
   (any path resolving under `root_dir`, independent of policy authoring) and
   by `protected_prefixes` policy, both checked before scope; raw tamper
   breaks the manifest signature and the engine fails closed for *all*
   resources until the root is restored.
4. **Receipts cannot be forged, replayed, or stretched:** root-key signature,
   issuance-in-this-chain check, single-use consumption in the ledger, logical
   expiry, and exact pre-state binding.
5. **The ledger itself cannot be rolled back:** truncating the tail to
   "un-consume" a receipt, rewriting history, or deleting the ledger and
   minting a fresh genesis all diverge from the out-of-tree anchor checkpoint
   and fail closed (attacks H and I in the suite).

### Concurrency model

At most **one live receipt per resource**: issued, unconsumed, unexpired.
A second intent on the same resource is DENYed (`conflicting mutation in
flight`) until the first receipt is consumed or expires. After the winner
commits, the loser's retry carries a stale `expected_pre_hash` and is DENYed
again — it must re-read the new authorized state first. Optimistic concurrency
with deterministic conflict resolution; no lease-only lock, no human in the
loop, no assumption that agents behave.

### Attack suite (regression-gated)

| Attack | Vector | Result |
|---|---|---|
| A | Bypass engine, write file directly | detected as `unauthorized_modify`; laundering intent DENIED |
| B | Valid signature, unauthorized scope | DENY, no receipt |
| C | Two agents race one resource | one ACCEPTED, one DENIED |
| D | Mutate governance root (intent or raw) | DENY / fail-closed `RootIntegrityError` |
| E | Replay consumed receipt | REJECTED, file untouched |
| F | Change file after approval, before commit | REJECTED (pre-state hash mismatch) |
| G (bonus) | Forge/alter a receipt | REJECTED (root signature) |
| H (bonus) | Truncate ledger tail, replay consumed receipt | fail-closed (anchor mismatch), file untouched |
| I (bonus) | Delete ledger, regenerate genesis (history wipe) | re-genesis refused; engine fails closed |

Plus structural checks: happy path, deterministic verifier, chain
tamper-evidence, receipt expiry, per-commit provenance, and runtime
ledger↔root binding.

## Trust model and limits (claim safety)

- **Local receipt-gated mutation kernel** — an alpha, production-shaped
  foundation. Not compliance-certified, not formally verified.
- Signing is HMAC-SHA256 (stdlib). The trust anchor is keystore isolation:
  actor keys, the root key, **and the ledger anchor checkpoint** must live
  outside any path agents can write (separate mount, separate UID, or a
  broker process). An attacker who can write the keystore/anchor owns the
  layer — that is the boundary, state it honestly. Upgrade path: asymmetric
  signatures (Ed25519), mirroring gove-zone's opt-in signing mode, so
  verifiers need no secrets.
- "Append-only" is a *verified property relative to the anchor*, not an
  OS-enforced one. The JSONL file itself is writable bytes; what the layer
  guarantees is that any truncation, rewrite, or regeneration is detected on
  the next chain verification and the layer halts (fail closed). Pair with
  OS-level append-only storage (`chattr +a`, WORM object storage) for
  defense in depth.
- Path matching is case-exact (`fnmatchcase`) everywhere; deploy on
  case-sensitive filesystems, or one physical file can alias two governed
  resource names on case-insensitive platforms.
- Enforcement is *authoritative detection + non-launderability*, not kernel
  MAC. An agent with raw filesystem access can still scribble on disk — but it
  cannot make that scribble authorized, cannot get further mutations approved
  on the contaminated resource, and cannot avoid attribution. OS-level
  enforcement (read-only mounts for agents, EffectBinder behind a privileged
  broker) composes cleanly on top.
- Single-host serialization: ledger append is last-writer-append in one
  process. Multi-process deployment should serialize `decide`/`commit` with an
  advisory lock around the ledger file (the decision logic itself already
  makes interleavings safe: pre-state binding rejects every lost-update
  interleaving).

## Integration target

Replace `agent → filesystem` with:

```
agent → MutationIntent → DecisionEngine → MutationDecisionReceipt
      → EffectBinder → filesystem effect → ledger COMMIT → verification
```

Example:

```python
from pathlib import Path
from mutation_authority import (
    AuditLedger, DecisionEngine, EffectBinder, GovernanceRoot,
    MutationIntent, SignedIntent,
)

root = GovernanceRoot.load(Path("governance"), Path("/secure/keystore"))
# The anchor checkpoint lives OUTSIDE the governed tree (with the keystore);
# without it, tail truncation of the ledger is undetectable. Constructing an
# unanchored ledger requires an explicit allow_unanchored=True opt-in.
ledger = AuditLedger(Path("mutation_ledger.jsonl"), anchor_path=Path("/secure/keystore/ledger.head"))
engine = DecisionEngine(root, ledger, repo_dir=Path("."))
binder = EffectBinder(root, ledger, repo_dir=Path("."))

intent = MutationIntent(
    actor_identity="agent-alpha",
    resource_path="src/verify_readiness.py",
    operation="UPDATE",
    expected_pre_hash="<sha256 of current content>",
    requested_change_scope="src/verify_readiness.py",
    timestamp=now,                 # logical tick
    task_reference="TASK-1234",
    nonce="unique-per-intent",
)
signed = SignedIntent.create(intent, actor_key)

decision = engine.decide(signed, now)
if decision.decision == "ALLOW":
    result = binder.commit(decision.receipt, new_content, now)
```
