# ADR 0007: Authorization Trace Cryptographic Core (Phase 2)

## Status

Accepted (design phase). Implementation tracked separately; this ADR
records the design decisions ratified through 5 rounds of adversarial
CCA review.

Supersedes none. Extends ADR 0005 (Phase 1 trace receipts).

## Context

PR #52 (Phase 1) landed `AuthorizationTrace` with a SHA-256
`receipt.trace_hash`. Two attacks were explicitly deferred and
documented as Phase 2 blockers in that PR's description:

1. **Trace forgery** — `trace_hash` covers structure, not authority.
   A compromised principal can forge any delegation chain.
2. **Cross-context replay** — nothing binds a trace to a specific
   `ActionRequest`.

Phase 2's cryptographic core closes both, and incidentally pulls in
two items previously slated for Phase 3 because they're required to
make the core safe to ship:

- Cross-tenant key isolation
- NFS / distributed-FS lock guard (startup probe)

The design is recorded in
[`docs/design/phase2-trace-crypto.md`](../design/phase2-trace-crypto.md).
This ADR is the durable decision record; the design doc is the
implementation spec.

## Decision

### 1. Signature algorithm: Ed25519 with domain separation

Per-hop signatures using Ed25519 from the `cryptography` library.
Every signing/verification call uses the byte tag

```
DOMAIN_TAG_HOP = b"ACGS.AuthorizationTrace.Hop.v2\0"
```

prepended to the canonical payload bytes. Domain separation prevents
cross-protocol signature reuse if a key is ever (mistakenly) used
elsewhere. The version suffix (`v2`) is bumped on any ABI change.

### 2. Canonical serialization

Phase 2 introduces a strict `canonical_bytes(value) -> bytes`
canonicalizer at
`acgs_governance_eval_mvp/governance/crypto/canonical.py` that
rejects ambiguous inputs (floats, NaN/Infinity, non-string dict keys,
ambiguous datetime/Decimal/bytes types, unnormalized Unicode,
duplicate keys). Phase 1's `sha256_json` keeps its current behavior
for local audit-event hashing; all Phase 2 signing/verification
routes through the new canonicalizer.

A `CanonicalizationError` raised inside the verifier is caught and
surfaced as `AuthorizationTraceIntegrityError` (fail-closed deny),
never an uncaught crash.

### 3. Hop signed payload

Each `principal_chain` hop carries `delegator_id`, `signature`, and
`signing_key_id` on the wire. The signature covers a canonical
payload containing:

- `alg`, `key_version`, `schema_version` (algorithm agility)
- `trace_id`, `parent_workflow_id`, `workflow_id`, `evaluation_policy`
- `hop_index`, `delegator_id`, `delegatee_id`, `role`, `tenant`
- `delegated_at`, `not_after`, `delegation_evidence_hash`
- `action_binding` (see §4)

### 4. Action binding (replay closure)

`action_binding` lives inside every signed hop payload:

```
action_type, tenant, actor_id, resource, inputs_hash, workflow_id,
policy_version, role_version, session_nonce
```

The verifier matches every field against the live `ActionRequest`
plus loaded policy/role bundle versions. Any mismatch fails closed.
Closing the policy-context-bypass attack required including
`policy_version` + `role_version` — these are part of the signature,
so the same probe under a changed policy regime invalidates the
signature.

### 5. KeyEntry metadata + identity binding

`PrincipalKeyStore.get(key_id)` returns a `KeyEntry` (frozen dataclass)
with `{public_key, principal_id, tenant, issuer, valid_from,
valid_to, purposes, revoked_at}`. The verifier enforces:

- `key.principal_id == hop.delegator_id`
- `key.tenant == hop.tenant` (universal; root keys are per-tenant)
- `"trace-delegation" in key.purposes`
- `key.valid_from <= delegated_at <= key.valid_to`
- `key.revoked_at is None or delegated_at < key.revoked_at`

Returning only a public key (as v1 of the design did) allowed any
key holder to claim any delegator identity. Returning metadata closes
the cross-tenant forgery and impersonation attacks.

### 6. Hop expiry + TTL bound

Each hop carries a mandatory signed `not_after`. The verifier
rejects:

- `hop.not_after < now - CLOCK_SKEW_TOLERANCE` (expired)
- `hop.not_after - hop.delegated_at > MAX_TRACE_TTL` (TTL bound)

`MAX_TRACE_TTL` (default 24h) caps how long a single trace can live;
the TTL bound prevents an attacker from minting long-lived hops that
outlast their tombstone-retention window.

### 7. Replay binding: single-event embedded nonce

`session_nonce` (128-bit base64url, per-session) is part of
`action_binding` and therefore signed. The kernel enforces single-use
by embedding the consumed nonce **inside the authorizing
`DecisionRecord` audit event**:

```jsonc
{
  // Phase 1 DecisionRecord fields preserved
  ...,
  "authorization_trace": { ... },
  "nonce_consumed": { "trace_id": "...", "session_nonce": "..." }
}
```

The `nonce_consumed` payload is inside Phase 1's `event_hash`, so
truncating the consuming event breaks `verify_chain()`. No separate
tombstone log. No two-phase commit. One append per authorization,
one fsync, atomic by construction.

**Nonces are consumed only on `allow=true` commits.** Burning on
denies would let an attacker exhaust legitimate nonces by forcing
denies. Documented accepted risk: probe-then-allow under a deliberate
external state shift. Mitigated by the signed `policy_version`
binding (a policy update breaks the signature).

### 8. Verifier flow (normative)

For an authorization the kernel decides to allow:

```
1. acquire LOCK_EX on the audit chain lock-file
2. read-tail from index high-water mark to EOF; merge any newly-
   appended events into the in-memory nonce index
3. check (trace_id, session_nonce) — present → NonceReplayError
4. append DecisionRecord (with nonce_consumed populated); one fsync
5. update index, bump high-water mark
6. release LOCK_EX
```

Verify-only callers (`verify_chain`, query API) hold `LOCK_SH` for
the scan and never consume nonces.

### 9. NFS / distributed-FS startup guard

`ChainHashAuditStore` and the nonce-index init perform a `statfs`-
style probe and refuse to initialize on filesystem types where
`fcntl.flock` is unreliable (nfs without lockd, smb, certain fuse
mounts). Raises `UnsafeAuditStorageError`. Phase 2 ships the
*guard*; an alternate lock substrate is Phase 3+ territory.

### 10. Clock skew

`CLOCK_SKEW_TOLERANCE` defaults to 60 seconds and is configurable. A
backward-skewed verifier clock still rejects expired hops unless the
skew exceeds the tolerance. NTP/chrony is a documented deployment
prerequisite; the runtime emits a startup warning when local time
offset exceeds the tolerance. This is not a cryptographic guarantee;
a truly hostile clock is out of scope.

### 11. Backwards compatibility

None. Phase 1 only landed 24 hours before Phase 2's design. No
external consumers. Phase 1 unsigned traces are explicitly rejected
with `LegacyUnsignedTraceError`. Fixtures are regenerated.

## Out-of-scope (Phase 3 or later)

- KMS / HSM integration
- Key rotation tooling
- Multi-sig root key (Phase 4 — addresses root-key compromise)
- Alternate lock substrate for distributed filesystems
- Production signing-side wiring at the orchestrator (separate PR)
- Trusted-timestamp service (Phase 4+)

## Consequences

**Closed:**

- Trace forgery: closed by per-hop signatures + key→principal binding
- Cross-context replay: closed by signed `action_binding`
- Cross-tenant forgery: closed by universal `key.tenant == hop.tenant`
- Indefinite replay after nonce eviction: closed by mandatory
  `not_after` + TTL bound
- Tombstone-truncation bypass: closed by embedding nonce in audit
  chain event_hash
- Canonicalization DoS: closed by error-handling contract
- Stale-cache concurrency window: closed by in-lock tail-scan from
  index high-water mark

**Accepted risks (documented):**

- Policy-probe replay under fixed `(trace_id, session_nonce)` if
  external state shifts — mitigated by signed `policy_version`,
  short tenant-configurable `MAX_TRACE_TTL`, rate-limit signals on
  `trace_id`
- Clock skew within `CLOCK_SKEW_TOLERANCE` (60s default) — bounded
  forward acceptance window; out-of-band mitigation via NTP
- Compromised orchestrator process exposing root key — deferred to
  Phase 4 multi-sig root

**Operational changes:**

- New file: `governance/crypto/canonical.py`,
  `governance/crypto/principal_keys.py`
- Audit event gains optional `nonce_consumed` field (Phase 1
  `ChainHashAuditStore.append` API unchanged)
- `authorization_trace.schema.json` gains
  `principal_chain[*].{delegator_id, signature, signing_key_id}` and
  `workflow_scope.action_binding` (all required)
- Startup probe refuses init on unreliable filesystems
- Deployment requires NTP/chrony

## Review history

- Round 1 (CCA codex + agy): BLOCK — 11 hard-stops identified
- Round 2: BLOCK → REVISE-AGAIN — 7 narrower contract issues
- Round 3: REVISE-AGAIN — two-event structural issue (DoS + atomicity
  + schema union)
- Round 4: REVISE-AGAIN (agy) / SHIP-DESIGN (codex) — converged on
  collapsing tombstone + decision into one event
- Round 5: **SHIP-DESIGN** (both) — closes the deny-path contract
  and stale-cache window. Two test-phrasing nits noted for the
  implementation PR.

Adversarial-review artifacts under
`.omc/artifacts/ask/{codex,agy}-round-{1..5}-*.md`.
