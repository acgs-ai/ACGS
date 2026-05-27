# Phase 2 — Authorization Trace Cryptographic Core

> Revised after CCA rounds 1-4 (v5 — 2026-05-23). R1 blocked on 11
> hard-stops; R2 surfaced 7 contract issues; R3 surfaced the
> two-event structural issue; v4 collapsed to a single-event design.
> R4 ratified that collapse but surfaced two narrow gaps: (1) the
> deny-path nonce-consumption contract was implicit, and (2) the
> in-memory nonce index could miss just-appended events under
> concurrent process operation. v5 makes the deny contract explicit
> and mandates in-lock tail-scan from the index high-water mark
> before the nonce check. ADR-0007 records the final design.

## Problem statement

Phase 1 (PR #52) landed `AuthorizationTrace` with a SHA-256
`receipt.trace_hash`. Two attacks remain trivial:

1. **Trace forgery** — `trace_hash` covers *structure*, not
   *authority*. Any agent can mint a forged delegation chain.
2. **Cross-context replay** — nothing binds a trace to a specific
   `ActionRequest`. Observed traces can be replayed across resources.

This design closes both with **delegation-hop signatures bound to
verified principal identities**, with **strict action binding** and
**durable single-use nonces** anchored in the audit chain.

## Threat model

Trusted:
- The audit chain (Phase 1 invariants hold).
- The local key store *file integrity* at runtime (file replacement
  detected via boot-time hash; out of scope for this phase: file
  read/write protection — that's OS-level).

Untrusted:
- Any subagent. Even ones the orchestrator delegated to.
- The wire payload between agents and the kernel.
- The audit log file's prior contents (Phase 1 chain hash already
  covers this).
- A compromised orchestrator process is OUT of trust boundary for
  Phase 2 (root-key exfil is Phase 4 multi-sig / HSM territory). The
  Phase 2 design must not silently degrade if root key leaks — it
  must require a constitutional-hash-gated key rotation event.

Out of scope, documented as Phase 3+:
- HSM / KMS integration.
- Hardware-backed keys.
- Multi-sig root.

In scope (revised — pulled in from earlier "Phase 3" line):
- **Cross-tenant key isolation enforcement** — the verifier rejects
  any signature whose key metadata tenant doesn't match the hop
  tenant. Required for ship.
- **NFS / distributed-FS lock guard** — startup probe rejects nonce
  store + audit chain placement on filesystems where `fcntl.flock`
  is unreliable. Phase 2 ships the guard, not the fix.

## Design — delegation signatures

### Algorithm

**Ed25519** with **explicit domain separation**.

Rationale unchanged from v1 (deterministic, small, no parameter
choices). Add: every signing/verification call is over

```
DOMAIN_TAG_HOP = b"ACGS.AuthorizationTrace.Hop.v2\0"
signed_bytes   = DOMAIN_TAG_HOP + canonical_bytes(hop_payload)
signature      = Ed25519(sk, signed_bytes)
```

The tag prevents cross-protocol signature reuse if the same Ed25519
key is ever (mistakenly) used elsewhere. The literal byte string is
versioned (`v2`); future ABI changes bump the tag.

### Canonical serialization

Phase 1's `sha256_json` uses
`json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)`.
That's **not safe for a long-lived signature ABI** (`default=str` can
silently coerce surprising types).

Phase 2 introduces a strict canonicalizer at
`acgs_governance_eval_mvp/governance/crypto/canonical.py`:

```python
def canonical_bytes(value: object) -> bytes:
    """RFC 8785-aligned canonicalizer; raises CanonicalizationError on
    any input that would produce ambiguous bytes:
      - floats (require explicit string for fractional values)
      - NaN, Infinity, -Infinity
      - non-str dict keys
      - ambiguous datetime / Decimal / bytes
      - unnormalized Unicode (NFC normalization mandatory)
      - keys with leading/trailing whitespace
    Numbers: integers only. Booleans pass through.
    Strings: NFC-normalized, no embedded NUL.
    Dicts: keys sorted in code-point order; no duplicates.
    Output: UTF-8 bytes with separators (b",", b":").
    """
```

Phase 1's `sha256_json` keeps its current behavior (it's a local
audit-event hash, not a signature ABI). All Phase 2 signing,
verification, and replay-binding hashing routes through
`canonical_bytes`.

### Per-hop signed payload (v2)

```jsonc
{
  "alg":               "Ed25519",
  "key_version":       1,
  "schema_version":    "phase2-hop-v2",
  "trace_id":          "trace-...",
  "parent_workflow_id": null,
  "workflow_id":       "workflow-...",
  "evaluation_policy": "access-time",
  "hop_index":         0,
  "delegator_id":      "orchestrator-root",
  "delegatee_id":      "codex:gpt-5",
  "role":              "implementation-agent",
  "tenant":            "default",
  "delegated_at":      "2026-05-23T00:00:00+00:00",
  "not_after":         "2026-05-24T00:00:00+00:00",
  "delegation_evidence_hash": "sha256:...",
  "action_binding":    { ...see below... }
}
```

`not_after` is mandatory. Trace verification rejects hops whose
`not_after < now`. Suggested default window: 24h (configurable per
issuer policy).

### Action binding (v2)

```jsonc
"action_binding": {
  "action_type":     "<ActionRequest.action_type>",
  "tenant":          "<ActionRequest.tenant>",
  "actor_id":        "<ActionRequest.actor.id>",
  "resource":        "<ActionRequest.resource>",
  "inputs_hash":     "<ActionRequest.inputs_hash>",
  "workflow_id":     "<repeated for binding>",
  "policy_version":  "<policy-bundle/vN>",
  "role_version":    "<roles-bundle/vN>",
  "session_nonce":   "<base64url 128-bit>"
}
```

The verifier compares every field against the live `ActionRequest` +
loaded policy/role bundle versions. Any mismatch → fail-closed. The
inclusion of `policy_version` + `role_version` closes agy's "context
bypass" attack (replay under a changed policy regime).

### Wire-format hop record

```jsonc
{
  "principal_id":           "codex:gpt-5",
  "role":                   "implementation-agent",
  "tenant":                 "default",
  "delegated_at":           "2026-05-23T00:00:00+00:00",
  "delegation_evidence_hash": "sha256:...",
  "delegator_id":           "orchestrator-root",
  "signing_key_id":         "key-orchestrator-root-2026-05",
  "signature":              "<base64url Ed25519 sig>"
}
```

### Verification path

`AuthorizationTrace.from_dict()` requires, in addition to Phase 1
invariants:

1. Resolve `signing_key_id` via `PrincipalKeyStore.get(key_id)` →
   returns a `KeyEntry` (see below) or raises
   `UnknownSigningKeyError`.
2. **Identity binding** — verify:
   - `key.principal_id == hop.delegator_id` (not the delegatee — the
     delegator attests "I delegate to delegatee_id")
   - **Tenant rule (universal, no exemption)**: `key.tenant ==
     hop.tenant`. Root keys are *not* an exception — each tenant has
     its own `orchestrator-root` key whose `key.principal_id ==
     "orchestrator-root"` and `key.tenant == "<tenant>"`. The
     `orchestrator-root` reservation at index 0 (step 4 below) is a
     *role-identifier* constraint; the tenant binding still applies.
   - `key.purposes` includes `"trace-delegation"`
   - `key.valid_from <= delegated_at <= key.valid_to`
   - `key.revoked_at is None or delegated_at < key.revoked_at`
3. Reconstruct `hop_payload` from trace fields + `workflow_scope` +
   `action_binding`. Compute `signed_bytes = DOMAIN_TAG_HOP +
   canonical_bytes(hop_payload)`. Verify Ed25519 signature against
   `key.public_key`.
4. Chain continuity — `hop[i].delegator_id == hop[i-1].principal_id`;
   index 0 reserved for `orchestrator-root` (or tenant-root); no
   duplicate `hop_index`; principals only repeat if explicitly
   permitted by policy.
5. Expiry — for every hop:
   - `hop.not_after >= now - CLOCK_SKEW_TOLERANCE` (see Clock-skew below)
   - **TTL-bound**: `(hop.not_after - hop.delegated_at) <=
     MAX_TRACE_TTL`. Closes the TTL-mismatch replay window where a
     hop could outlive its tombstone retention.
6. Phase 1 invariants (workflow_scope shape, receipt.trace_hash)
   continue to apply.

### Key store

`acgs_governance_eval_mvp/governance/crypto/principal_keys.py`:

```python
@dataclass(frozen=True)
class KeyEntry:
    key_id: str
    public_key: Ed25519PublicKey  # cryptography lib
    principal_id: str
    tenant: str
    issuer: str          # who attested this key
    valid_from: datetime  # tz-aware UTC
    valid_to: datetime
    purposes: frozenset[str]   # e.g. {"trace-delegation"}
    revoked_at: datetime | None

class PrincipalKeyStore(Protocol):
    def get(self, key_id: str) -> KeyEntry: ...
    # signing-side; reference impl ships for tests, prod wiring later
    def sign(self, key_id: str, payload: bytes) -> bytes: ...
```

File-backed test impl reads JSON `[{key_id, public_key_hex,
principal_id, tenant, issuer, valid_from, valid_to, purposes,
revoked_at}]` from `$ACGS_PRINCIPAL_KEYS`. The file path's
`fcntl.flock`-able status is checked at startup.

Production impl (KMS/HSM) is Phase 3+. The Protocol keeps the
verification path stable across implementations.

## Design — replay binding (durable nonces)

### Threat resolution

Agy + Codex flagged the v1 TTL contradiction. **Resolution: durable
tombstones; replay invalid forever.**

### Nonce-store contract

**Single-event embedding**. There is no separate `nonce.consumed`
event type and no parallel tombstone log. Each authorized
`DecisionRecord` carries the nonce it consumes in a new field:

```jsonc
{
  // ... all Phase 1 DecisionRecord fields ...
  "authorization_trace": { ... },   // Phase 1 R5/R6 field
  "nonce_consumed": {               // NEW in Phase 2
    "trace_id":      "trace-...",
    "session_nonce": "base64url-128bit"
  }
}
```

Consequences:

1. **One append per authorization, one fsync.** No double I/O.
   Latency budget for the nonce check + commit is the same as Phase
   1's single decision-event append plus a bounded tail scan.
2. **Atomicity is structural, not procedural.** Either the entire
   `DecisionRecord` (with `nonce_consumed`) is committed, or none of
   it is. No tombstone-first / business-event-second sequence to
   reason about. No poison-pill nonce burn.
3. **Tombstone integrity inherits Phase 1.** The `nonce_consumed`
   payload is inside the hashed event payload (Phase 1 covers
   everything in `event_hash`). Truncation breaks `verify_chain()`.
4. **Schema clean.** Phase 1's audit event remains a
   `DecisionRecord`-shaped record; the only addition is one new
   optional field. No `event_type` union, no parallel append API.

### Verifier flow (normative)

For each authorization that the kernel chooses to allow, with a
validated `AuthorizationTrace` and a freshly-issued
`(trace_id, session_nonce)` in the trace's `action_binding`:

```
1. acquire LOCK_EX on the audit chain lock-file
2. read-tail-from-high-water-mark: starting at the file offset the
   in-memory nonce index last consumed, scan forward to EOF and
   merge any newly-appended events into the index. This catches
   commits made by other processes while THIS process held no lock.
3. check (trace_id, session_nonce) against the now-current index.
   if present → raise NonceReplayError. fail-closed. release lock.
4. append the DecisionRecord with nonce_consumed populated.
   exactly one fsync. Phase 1 chain-hash invariants apply.
5. update the in-memory index with the just-appended event and bump
   the high-water mark to the new EOF.
6. release LOCK_EX
```

The in-memory index is a fast-path cache for events older than the
high-water mark (rehydrated at startup over `MAX_TRACE_TTL`); events
newer than the watermark must always be merged in-lock before the
nonce check. This closes the stale-cache window where Process B
holds a pre-A-commit cache.

The `(trace_id, session_nonce)` becomes single-use the instant the
event is written; replay of the same pair will find it in the
tail-scan on the next attempt.

Verify-only callers (`verify_chain()`, query API) hold `LOCK_SH` for
the duration of their scan; they never consume nonces and never
contend with each other.

### Deny-path nonce contract

**Nonces are consumed only on `allow=true` commits.** A denied
authorization writes no `nonce_consumed` payload (or writes one in an
unauthorized event that is not appended; either way the wire pair is
not burned).

Rationale:

1. **Avoids deny-induced nonce exhaustion DoS.** If denies burned
   nonces, any attacker who can force the policy gate to deny (bad
   payload, deliberately wrong resource, etc.) could exhaust a
   tenant's nonce supply without ever obtaining a legitimate
   authorization.
2. **Aligns with the contract semantics.** A `(trace_id,
   session_nonce)` is "you have one chance to commit this
   authorization." Denials are not commits.

**Accepted risk (documented):** an attacker that knows a valid
`(trace_id, session_nonce)` can repeatedly retry the same probe
against the policy gate. If external state (database row, time
window, policy version) changes between attempts, an originally-deny
request may flip to allow on a later attempt.

Mitigations are out-of-band:
- Policy engines should be deterministic over `(trace, ActionRequest,
  policy_version, role_version)` — those four are signed into the
  trace, so the same probe under the same policy version always
  produces the same verdict. A policy update is a fresh version,
  which the signed `action_binding.policy_version` will not match.
- High-security tenants can set `MAX_TRACE_TTL` short (e.g., 5 min)
  to bound the probe window.
- Repeated denials for the same `(trace_id, session_nonce)` should
  feed the standard rate-limit/abuse-detection signals; the trace's
  `trace_id` is constant across the probes so it's a natural key.

If a future product requirement is "every evaluation attempt is
single-use" (every denial burns the nonce), it's a different
security contract that should bear its own ADR — not introduced
silently by repurposing this field.

### Canonicalizer error handling

A `CanonicalizationError` raised inside the verifier MUST NOT
propagate as a process crash. The verifier wraps every
`canonical_bytes(...)` invocation:

```python
try:
    signed_bytes = DOMAIN_TAG_HOP + canonical_bytes(hop_payload)
except CanonicalizationError as exc:
    raise AuthorizationTraceIntegrityError(
        "trace contains non-canonicalizable payload") from exc
```

This becomes a fail-closed deny path, not a DoS surface. The
top-level governance handler must already treat
`AuthorizationTraceIntegrityError` as deny.

### Clock-skew handling

The signed `not_after` is a wall-clock timestamp. Out-of-scope:
trusted timestamping service. In-scope: bound the trust we place in
local time.

```
CLOCK_SKEW_TOLERANCE = 60 seconds  # configurable, default
```

- Verifier uses `now - CLOCK_SKEW_TOLERANCE` when checking
  `hop.not_after >= now`. A backward-skewed verifier clock therefore
  *still* rejects an expired hop unless the skew exceeds the
  tolerance.
- Forward-skewed verifier clock: accepts a hop slightly after its
  legitimate window. Bounded by `CLOCK_SKEW_TOLERANCE`.
- **Deployment prerequisite (documented in ADR-0007 and runtime
  startup check):** NTP/chrony synchronization is required. Drift
  beyond tolerance is a configuration error; the runtime emits a
  startup warning if `chronyc tracking` (or equivalent) shows offset
  > tolerance.
- This is not a cryptographic guarantee — it's a deployment contract.
  A truly hostile clock is out of scope for Phase 2.

### Lookup efficiency + crash recovery

Every authorized event carries a `nonce_consumed` payload, so the
nonce-existence check is a single tail-scan of the audit chain
within a bounded window.

1. **Bounded in-memory index** rebuilt on process start: scan
   `audit.jsonl` from the tail, accumulating `(trace_id,
   session_nonce)` pairs from events whose `timestamp >= now -
   MAX_TRACE_TTL`. Stop once a record older than the window is hit,
   since records are append-only and monotonic in time.
2. **Beyond the window**, the verifier relies on the
   `hop.not_after`/`MAX_TRACE_TTL` rule (step 5 above): an expired
   hop is rejected *before* we consult the nonce index. The expiry
   check is the first line; the tombstone is the belt over the
   suspenders. Bounded TTL + signed-`not_after` means an attacker
   can't replay outside the window even if the in-memory index
   doesn't carry the nonce.
3. **Crash recovery** — startup performs:
   - Run `verify_chain()` on `audit.jsonl`. If it returns
     `valid=False` or raises, refuse to start.
   - Rehydrate the bounded nonce index from the tail. Refuse traces
     until rehydration completes (fail-closed during the window).
4. **Disabling rehydration is not an operational lever.** There is no
   feature flag, env var, or admin command that turns it off. The
   only failure mode is "the audit chain itself is broken", and the
   correct response is to stop and investigate, not to bypass the
   index.

`MAX_TRACE_TTL` is a config knob (default 24h); `not_after - delegated_at` is
verifier-rejected if it exceeds the bound.

### NFS/distributed-FS guard

Startup probe at `ChainHashAuditStore` and `NonceStore` init:

```python
def _refuse_unreliable_fs(path: Path) -> None:
    # Statfs-style probe; refuse known-unreliable FS types
    # (nfs without lockd, smb, fuse without flock support).
    fs = _fs_type(path)
    if fs in _UNRELIABLE_FS:
        raise UnsafeAuditStorageError(
            f"audit storage on {fs} is not safe; use local disk")
```

Phase 2 ships the guard. Phase 3+ may add an alternate lock substrate
(e.g., advisory lock via a coordinator).

## Wire-format & schema impact

`authorization_trace.schema.json` additions (all required):

- `principal_chain[*]`: + `delegator_id`, `signature`, `signing_key_id`
- `workflow_scope`: + `action_binding` (object — see fields above)
- New top-level required field: `hop_signatures_version`

`receipt.trace_hash` still covers the full payload, signatures
included. The Phase 1 hash invariant stays.

`DecisionRecord` audit-event additions (Phase 1 schema preserved):

- `nonce_consumed` (optional object, required when the event was
  authorized via a signed trace): `{ trace_id: string,
  session_nonce: string }`. Covered by Phase 1 `event_hash`.

Phase 1's `ChainHashAuditStore.append()` signature does NOT change.
The `DecisionRecord` model gains the optional `nonce_consumed` field;
serialization, hashing, and chain verification flow unchanged.

## Backwards compatibility

None. Phase 1 only landed 24h before this design. No external
consumers. Fixtures get regenerated. Phase 1 unsigned traces are
explicitly rejected with a `LegacyUnsignedTraceError`.

## ADR-0007

Will be opened alongside this PR as
`docs/adr/0007-authz-trace-cryptographic-core.md` capturing:

- Algorithm (Ed25519) and rationale
- Domain-separation tag and version policy
- Canonicalizer scope and what it rejects
- KeyEntry metadata schema + identity-binding rules
- Action-binding field choice rationale
- Nonce-store durable-tombstone semantics + lookup window
- NFS/distributed-FS startup guard
- Out-of-scope items deferred to Phase 3/4

## Test plan (revised)

1. `test_hop_signature_required` — unsigned hop → raises
2. `test_hop_signature_wrong_bytes` — bad sig → raises
3. `test_hop_signature_wrong_key_id` — claimed key_id resolves but
   not the one that signed → raises
4. `test_hop_delegator_principal_mismatch` — key.principal_id !=
   hop.delegator_id → raises
5. `test_hop_cross_tenant_key_rejected` — key.tenant != hop.tenant
   → raises
6. `test_hop_purpose_mismatch` — key purposes lack
   "trace-delegation" → raises
7. `test_hop_key_expired` — delegated_at outside [valid_from,
   valid_to] → raises
8. `test_hop_key_revoked` — delegated_at >= revoked_at → raises
9. `test_hop_not_after_in_past` — verification time > not_after →
   raises
10. `test_chain_continuity_broken` — hop[i].delegator_id !=
    hop[i-1].principal_id → raises
11. `test_chain_root_reserved_at_index_0` — non-root delegator at
    index 0 → raises
12. `test_action_binding_each_field_mismatch` — parameterized
    (resource/inputs_hash/action_type/tenant/actor_id/workflow_id/
    policy_version/role_version) → 8 raises
13. `test_session_nonce_single_use` — replay same (trace_id, nonce)
    inside or outside TTL → raises forever (durable tombstone)
14. `test_nonce_store_rehydrates_after_restart` — restart the
    process, replay attempt still fails
15. `test_unsafe_fs_refuses_init` — mock fs_type to nfs → raises
    `UnsafeAuditStorageError`
16. `test_canonical_bytes_rejects_float` / `_nan` / `_non_str_key` /
    `_unnormalized_unicode` — parameterized canonicalizer rejections
17. `test_domain_tag_mismatch` — sig produced with v1 tag verified
    against v2 → raises
18. `test_full_round_trip_signed` — valid signed trace ↔ wire ↔
    verify
19. `test_hop_ttl_bound_rejected` — `(not_after - delegated_at) >
    MAX_TRACE_TTL` → raises
20. `test_nonce_embedded_in_decision_event` — the authorized
    `DecisionRecord` carries `nonce_consumed = {trace_id,
    session_nonce}` in its payload, and the event_hash covers it;
    chain `verify_chain()` passes
21. `test_nonce_replay_detected_in_tail_scan` — replay of the same
    `(trace_id, session_nonce)` raises `NonceReplayError` on the
    second attempt (no separate tombstone log required)
21b. `test_truncation_of_consuming_event_breaks_verify_chain` —
    drop an event with `nonce_consumed` set from `audit.jsonl`;
    `verify_chain()` reports failure (nonce truncation cannot hide)
22. `test_canonicalizer_failure_is_deny_not_crash` — payload
    triggering `CanonicalizationError` surfaces as
    `AuthorizationTraceIntegrityError`, never an uncaught raise
23. `test_clock_skew_tolerance_backward` — verifier clock −90s vs
    real time, hop `not_after = real_time + 30s` → accepted (within
    60s tolerance)
24. `test_clock_skew_tolerance_exceeded` — verifier clock −120s, hop
    expired by real-time 90s → raises
25. `test_concurrent_verify_during_consume` — multi-process: one
    process holds `LOCK_EX` consuming a nonce; verifiers holding
    `LOCK_SH` block until release; neither observes a partial state
26. `test_denied_action_does_not_burn_nonce` — kernel denies an
    action; subsequent retry with the same `(trace_id,
    session_nonce)` and an unchanged policy_version is accepted on
    the first allow-path attempt. Nonce only burned on commit.
27. `test_concurrent_consume_observed_by_second_process` —
    multi-process: A enters LOCK_EX and commits a nonce; B was
    waiting on LOCK_EX with a stale in-memory index. After A
    releases, B's in-lock tail-scan from the index high-water mark
    surfaces A's commit and B raises `NonceReplayError`. The
    in-memory cache alone (without the tail merge) would have
    missed it.

## Non-goals (unchanged)

- KMS / HSM integration → Phase 3+
- Key rotation tooling → Phase 3
- Multi-sig root → Phase 4
- Alternate-lock-substrate for distributed FS → Phase 3+ (Phase 2
  ships the *guard*, not the *fix*)
- Production orchestrator signing-side wiring — separate PR after
  this design lands and is reviewed

## Open questions (carried forward, narrower than v1)

1. **`MAX_TRACE_TTL` default** — 24h is a reasonable starting point,
   but should it be 1h for the high-security tenant tier? Configurable
   per tenant in `KeyEntry`? Leave as global for v2; revisit if tenant
   isolation needs differ.

2. *(resolved in v3)* Tenant-root keys: per-tenant
   `orchestrator-root` keys. The universal `key.tenant ==
   hop.tenant` rule applies to root keys too; root-ness is a
   role-identifier (`principal_id == "orchestrator-root"`) restricted
   to index-0 hops.

3. *(resolved in v4)* Nonce-store atomicity: the `nonce_consumed`
   payload is embedded in the `DecisionRecord` itself, so the audit
   event and the tombstone are the same append. There is no
   two-phase commit and no poison-pill nonce burn (R3 surfaced both
   issues on the v3 two-event design).
