# SCITT receipt-format spike

**Date:** 2026-05-24
**Branch:** `phase-2-trace-crypto`
**Spike script:** `scripts/scitt_spike.py`

## Verdict

**GO-WITH-CAVEATS.** ACGS audit events round-trip cleanly through a COSE_Sign1 (Ed25519, alg=-8) envelope today. The caveats are about *which* library we adopt for production, not about the format's fitness.

## Round-trip result

`python scripts/scitt_spike.py` exits 0:

```
envelope size: 979 bytes
payload keys : ['action_type', 'actor_id', 'allow', 'authorization_trace', 'decision_id',
                'event_hash', 'nonce_consumed', 'previous_hash', 'reason', 'resource',
                'tenant', 'timestamp']
alg          : EdDSA (-8), kid=scitt-spike-key-1
SCITT spike: round-trip PASS -- ACGS event survives COSE_Sign1 (EdDSA/Ed25519) cleanly
```

The script hand-constructs a realistic `ChainHashAuditStore` event (decision metadata + `nonce_consumed` + `authorization_trace` with one signed hop), encodes it under the Sign1 wire format from RFC 8152 §4.2, decodes, verifies the Ed25519 signature, and confirms `json.dumps(..., sort_keys=True, default=str)` equality. Drift would have been reported per-field.

## Canonical-form gaps

ACGS today uses `sha256_json` (`json.dumps(..., default=str)`) for chain hashing and `governance.crypto.canonical.canonical_bytes` (strict) for hop signing. CBOR canonical encoding (RFC 8949 §4.2) has different rules. Concrete gaps observed against the spike payload:

- **datetime objects:** Today every timestamp in the event is already an ISO 8601 **string** (`"2026-05-24T12:34:56+00:00"`), so it round-trips identically. If any caller ever stuffs a raw `datetime` into a payload, `json.dumps(default=str)` stringifies it but cbor2 would encode it as CBOR tag 0/1 — the JSON-vs-CBOR forms would no longer match a side-by-side hash. **Mitigation:** keep ACGS's existing rule that all timestamps are serialized before hashing.
- **bytes:** `canonical_bytes` rejects raw bytes outright; JSON has no bytes type. CBOR encodes them natively as major type 2. Any future field carrying raw bytes (e.g., a Merkle inclusion proof) would survive COSE round-trip but break the JSON hash chain. **Mitigation:** continue base64url-encoding bytes at the application layer.
- **float / NaN / ±Inf:** Both `canonical_bytes` and (effectively) `sha256_json` reject these; CBOR allows them with deterministic encoding. No drift today because no Phase 2 payload carries floats.
- **non-NFC strings / embedded NUL / non-str map keys:** `canonical_bytes` rejects all three; CBOR permits them. Today's payloads are clean, but a SCITT-receipt code path should reuse `canonical_bytes`-style validation **before** CBOR encoding so the wire form cannot legalize an input the rest of ACGS forbids.
- **map key ordering:** `sha256_json` uses `sort_keys=True`; CBOR canonical (RFC 8949 §4.2.1) orders keys by length-then-lex of their encoded form. For string-only keys the resulting orders usually agree, but the spike does **not** prove this generally — production code should pin `cbor2.dumps(canonical=True)` (currently we use default mode, which is sufficient for round-trip but not for cross-implementation hash agreement).

## Library recommendation

**Used:** hand-rolled COSE_Sign1 on `cbor2==5.9.0` + `cryptography==46.0.3` (both already in the venv, both MIT/Apache-2.0/BSD-3, both actively released within the last 12 months).

**Why not pycose:** not installed in this Python 3.14.4 venv, and `pip install pycose` is risky here — earlier sessions hit pydantic-v1 wheel incompatibilities on 3.14. Did not attempt the install for the spike since the hand-rolled encoder is ~40 lines and the spec section is small.

**Production recommendation:** once we move past the spike, vet **`pycose`** (≥1.1.0) against a Python 3.12/3.13 runtime, or use Microsoft's `scitt-emulator` Python client which embeds its own COSE implementation. Do **not** ship the hand-rolled encoder.

## Transparency Service candidates

- **Microsoft SCITT CCF service** — reference implementation, tracks the IETF draft, runs on Confidential Consortium Framework. Self-hosted; production deployment requires SGX/SEV-SNP confidential compute and CCF operator skill. High fidelity to the spec, high ops cost.
- **DataTrails (managed SaaS)** — commercial Transparency Service, SCITT-aligned, OIDC-based authentication, no infra to run. Vendor lock-in and data-residency concerns for regulated tenants; pricing is per-statement.
- **Sigstore Rekor (adapted)** — mature Merkle transparency log, but Rekor's entry types are not SCITT signed-statement envelopes; would require either a Rekor type extension or running both side-by-side. Drift from the spec means we lose the SCITT interop story.

**RECOMMENDED: Microsoft SCITT CCF**, because ACGS's wedge is regulated-execution evidence and we already need to defend "the audit log is tamper-evident" — a CCF-backed TS is the only option here that gives us a transparency receipt we can hand to an auditor and a path to reproduce verification offline.

## Next milestone scope (`feat/scitt-transparent-receipts`)

- Add a `governance.crypto.scitt` module that wraps an `AuditEvent` in COSE_Sign1 using a vetted library, reusing `canonical_bytes` validation pre-encode and pinning `cbor2.dumps(canonical=True)` so the wire form is reproducible across implementations.
- Wire `ChainHashAuditStore.append(...)` to emit a `.cose` sibling alongside each JSONL line (behind a feature flag), plus a `verify_cose(path)` helper mirroring `verify_chain()`.
- Add a thin Transparency Service client that POSTs the COSE_Sign1 to a Microsoft SCITT CCF endpoint, stores the returned receipt next to the event, and gates "registered" status behind a successful receipt verify on a separate validator agent.
