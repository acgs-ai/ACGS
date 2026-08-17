# MUTATION_AUTHORITY_INTEGRATION_V1 — Architecture & Threat Model

Status: implemented and verified (`python3 verify_mutation_integration.py` → `ALL CHECKS PASSED`).
Scope claim: **verified coverage of integrated mutation paths only** — paths routed
through the runtime adapter below. This document does NOT claim repository-wide
governance. See REPORT.md §"What is NOT guaranteed".

## 1. Current mutation authority boundary

Delivered in `packages/mutation-authority/` (kernel, previously verified 15/15):

- `GovernanceRoot` — manifest-sealed policy + actor registry; keystore outside governed tree; fail-closed on tamper.
- `DecisionEngine` — deterministic 9-check verifier, ALLOW/DENY, every decision a ledger event.
- `MutationDecisionReceipt` — root-signed, single-use, expiring, pre-state-hash-bound.
- `EffectBinder` — the only writer; re-verifies everything at commit time.
- `AuditLedger` — hash-chained JSONL + out-of-tree anchor checkpoint (truncation/rewrite/wipe fail closed).

The boundary of the kernel is *library-shaped*: it protects any mutation that goes
through it, and detects (non-launderably) any governed-path mutation that does not.

## 2. Existing execution paths (as-is, before V1)

```
(a) agent ──────────────────────────► filesystem            (ungoverned; detected after the fact)
(b) agent ─► gove-zone executor gate ─► side effects        (receipt-gated EXECUTION, not repo mutation)
(c) CI ─► verify scripts (hashes, submodules, manifests)    (post-hoc detection only)
```

Path (b) — `packages/gove-zone` — governs *action execution* with its own
decision receipts and audit chain. It does not authorize *repository state
change* per file. Path (a) is the problem this layer exists for. Path (c) can
detect but not attribute or prevent.

**Boundary note:** `packages/gove-zone/{gateway,integration,execution}.py` are
concurrently owned by other in-flight sessions (dirty in the worktree). V1
therefore ships the adapter contract on the mutation-authority side and does
NOT modify gove-zone. Wiring gove-zone's executor to call this adapter is a
follow-up change inside gove-zone, done by its own lane, against the stable
interface defined here.

## 3. New controlled mutation path (V1)

```
Actor
 ↓   AuthorityContext {actor_id, actor key, task_reference}
Mutation Intent            (adapter builds + signs; CAS pre-hash read)
 ↓
Authority Engine           (DecisionEngine: 9 deterministic checks; DENY ⇒ ledger event, stop)
 ↓
Decision Receipt           (root-signed, single-use, expiring, pre-state-bound)
 ↓
Effect Gateway             (EffectBinder: re-verify all; atomic write)
 ↓
State Change               (exactly the receipt's resource, exactly once)
 ↓
Evidence Graph             (evidence_graph.jsonl record cross-linked to the ledger COMMIT event)
```

Concrete API (`mutation_authority.adapters`):

```python
gateway = MutationGateway(root, ledger, repo_dir, evidence)
ctx = AuthorityContext(actor_id="agent-alpha", actor_key=key_bytes, task_reference="TASK-1")
result = gateway.request_mutation(ctx, "src/verify_readiness.py", "UPDATE", new_content)
# result.status ∈ {APPLIED, DENIED, REJECTED}; APPLIED carries receipt + evidence record
```

Properties enforced by construction:

- The adapter **never mutates state itself**; the only write call is `EffectBinder.commit`, which demands a valid receipt.
- Missing/unknown/inactive authority context is rejected **before** an intent is even built.
- Actor identity is preserved end-to-end: context → intent signature → engine identity check → receipt.actor → ledger COMMIT.actor → evidence.actor. The adapter cannot re-attribute (a context whose key does not match the claimed actor fails the engine's signature check).
- Determinism preserved: logical time is the **ledger event count** (monotonic, advances by exactly one per append), NOT `max(event.timestamp)` — caller-supplied timestamps are untrusted, so a count-based clock cannot be leapt forward by an unauthenticated DENY event to expire other agents' receipts (attack H). Intent nonces are hashes of (actor, resource, chain head, tick). No wall clock, no randomness.

## 4. Trust boundaries

| Zone | Contents | Who may write |
|---|---|---|
| **Governed repository** | source files under `governed_prefixes` | `EffectBinder` only (with valid receipt); anything else = detected unauthorized mutation |
| **Governance root** | `policy.json`, `actors.json`, `manifest.json` | nobody at runtime (bootstrap ceremony only); intents targeting it are structurally DENYed; raw tamper halts the layer |
| **Ledger + evidence graph** | `mutation_ledger.jsonl`, `evidence_graph.jsonl` | appended by engine/binder/emitter; file-level tamper detected via hash chain + anchor + cross-check |
| **Keystore tier (trust anchor)** | root key, actor keys, ledger anchor | outside every agent-writable path. **An attacker who writes here owns the layer.** |

Privilege ordering: keystore ≻ ledger/evidence files ≻ governed repo. Every
attack in the suite that stays below the keystore tier fails closed or is
detected non-launderably.

## 5. Actor identity flow

1. Runtime hands the adapter an `AuthorityContext` (actor id + actor key + task reference).
2. Adapter pre-checks: actor registered and active in the root registry; else `REJECTED: missing/invalid authority context` (no intent created, nothing appended).
3. Intent is signed with the context's key; `DecisionEngine` verifies the signature against the *registry's* key for the claimed identity — a stolen context with a mismatched key fails here.
4. Receipt, ledger COMMIT, and evidence record all carry the same `actor` string; `ci_gate` cross-verifies they agree.

## 6. Receipt lifecycle

```
issued (DECISION/ALLOW event, TTL = policy.receipt_ttl logical ticks)
  ├─ consumed  — exactly one COMMIT event references it; further use ⇒ REJECTED (replay)
  ├─ expired   — now > expiry ⇒ REJECTED; resource conflict window closes
  └─ orphaned  — pre-state changed after issue ⇒ REJECTED at commit (Attack F, kernel suite)
```

At most one live (issued ∧ unconsumed ∧ unexpired) receipt per resource — the
engine denies concurrent intents, which is the concurrency invariant.

## 7. Evidence emission model

`EvidenceEmitter` appends one **root-key-HMAC-signed** record per
**committed** mutation to `evidence_graph.jsonl`:

```json
{
  "evidence_id":          "<hash of body>",
  "actor":                "...",
  "resource":             "...",
  "previous_hash":        "<before_hash>",
  "new_hash":             "<after_hash>",
  "decision":             "ALLOW",
  "receipt_id":           "...",
  "policy_version":       "<sha256 of sealed policy.json from the root manifest>",
  "authority_chain_ref":  {"ledger_seq": N, "ledger_event_hash": "<COMMIT event hash>"},
  "timestamp":            <logical tick>,
  "signature":            "<HMAC(root_key, evidence_id)>"
}
```

**Authenticity:** the record is HMAC-signed with the root key. `evidence_id`
is the content hash (a public reference, not a trust anchor); the signature is
what the gate trusts. A forger with evidence-file write access but no keystore
access can read every body field from the public ledger, but cannot produce a
verifying signature — so a fabricated record is rejected even when it
describes a real COMMIT.

**No silent mutation events:** `ci_gate` enforces a bijection — every ledger
COMMIT must have exactly one matching evidence record, cross-checked field by
field against ledger-derived ground truth (actor, resource, before/after
hashes, decision, policy_version, event hash, timestamp — nothing left
unchecked), and every evidence record must (a) carry a valid root-key
signature, (b) be unique per receipt id (duplicates ⇒ FAIL, so a later forged
record cannot shadow the genuine one), and (c) resolve to a real COMMIT event.
Removed evidence ⇒ FAIL (attack F); forged/duplicate evidence ⇒ FAIL (attack
I). Denials are not evidence records (no mutation happened); they are already
permanent DECISION events in the ledger.

The whole gate runs under a fail-closed catch-all: any exception — malformed
evidence line, schema-violating ledger payload, unreadable key — returns
`GateResult(passed=False)`, never a raw raise and never a skip (attack J).

Evidence is a *projection* of the ledger: if the graph file is lost, it is
recomputable from the chain; if it disagrees with the chain, the chain wins and
the gate fails closed.

## 8. CI enforcement model

`ci_gate.run_ci_gate(root, ledger, repo_dir, evidence)` — deterministic,
fail-closed, ordered checks:

1. Governance-root integrity (manifest signature + sealed file hashes).
2. Ledger chain + anchor (truncation/rewrite/regeneration ⇒ FAIL).
3. Genesis↔root binding.
4. Repository state == ledger-authorized state (any unauthorized mutation ⇒ FAIL, attributed by resource).
5. Every COMMIT has a valid receipt provenance (receipt issued in-chain, fields agree).
6. COMMIT ↔ evidence bijection (see §7).

Any exception during checking is itself a FAIL (fail-closed), never a skip.

## 9. Threat model (integration suite)

| # | Attack | Vector | Expected | Mechanism |
|---|---|---|---|---|
| A | Direct filesystem bypass | raw write to governed file | REJECT | state divergence vs ledger: gate FAIL + next gateway request DENIED, non-launderable |
| B | Fake mutation receipt | fabricate/alter receipt or evidence | REJECT | root-key signature + issued-in-this-chain check; evidence without COMMIT fails bijection |
| C | Valid receipt reused | replay consumed receipt | REJECT | single-use consumption recorded in chain |
| D | Actor scope escalation | actor requests out-of-scope resource; or signs as another actor | REJECT | scope check vs registry; signature vs claimed identity's registered key |
| E | Ledger rollback | truncate tail / delete + regenerate | DETECT | anchor checkpoint mismatch ⇒ fail closed everywhere |
| F | Evidence emission removed | delete evidence record post-commit | REJECT | COMMIT↔evidence bijection in ci_gate |
| G | Runtime adapter bypass | missing authority context; direct EffectBinder call without valid receipt | REJECT | context pre-check; binder demands valid, issued, unconsumed receipt |
| H | Clock-skew DoS | uncredentialed `decide()` injects huge timestamp to expire others' receipts | REJECT | count-based logical clock ignores caller timestamps |
| I | Evidence forgery / shadowing | forged or duplicate evidence record | REJECT | root-key signature + per-receipt uniqueness + full field cross-check |
| J | Gate crash on malformed input | corrupt evidence/ledger payload to bypass a check | FAIL-CLOSED | whole gate wrapped: any exception ⇒ FAIL |

Residual risks and non-guarantees: see REPORT.md.
