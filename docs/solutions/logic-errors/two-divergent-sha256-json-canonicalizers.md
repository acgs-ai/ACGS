---
title: Two same-named sha256_json canonicalizers diverge inside acgs_governance_eval_mvp
date: 2026-07-07
category: logic-errors
module: acgs_governance_eval_mvp
problem_type: logic_error
component: hashing/canonicalization
symptoms:
  - "A hash produced by `governance.models.sha256_json` fails verification against `governed_mcp_v0._io.sha256_json` (or vice versa) whenever the payload contains non-ASCII text"
  - "The same dict yields different sha256 hex digests depending on which module hashed it"
  - "`governed_mcp_v0._io.sha256_json` raises TypeError on datetimes/Decimals that `governance.models.sha256_json` hashes silently"
root_cause: divergent_duplicate_implementations
resolution_type: characterization_pin
severity: high
tags: [sha256, canonical-json, ensure-ascii, default-str, receipts, audit-chain, hash-divergence]
---

# Two divergent `sha256_json` implementations — pinned, not unified

## Problem

`acgs_governance_eval_mvp` contains two same-named canonical-JSON hashers:

| | `governance/models.py::sha256_json` | `governed_mcp_v0/_io.py::sha256_json` |
|---|---|---|
| `ensure_ascii` | `False` (raw UTF-8 bytes) | `True` (`\uXXXX` escapes) |
| `default` | `str` (silently coerces anything) | none (raises `TypeError`) |
| non-ASCII payloads | one digest | a DIFFERENT digest |
| ASCII JSON-native payloads | identical digests | identical digests |

Same name, different bytes: if a payload were ever hashed by one module and
verified by the other, verification would fail (or worse, a coerced-to-str
value would hash "successfully" where the strict side would have refused).

## Call-site analysis (2026-07-07)

No cross-module verification exists today. All `governance/*` producers and
verifiers (admission gate/replay, in-memory + JSONL audit chains, dspy,
evaluation) import from `governance.models`; all `governed_mcp_v0/*`
producers and verifiers (server receipts, `verify.py` replay, constitution
registry) import from `governed_mcp_v0._io`. The only cross-boundary import
in `governed_mcp_v0` is `governance.audit.refuse_unreliable_fs` (not a
hasher), and nothing in `governance/` imports `governed_mcp_v0`.

## Resolution: pin, don't merge

Blind unification is FORBIDDEN: persisted receipts and hash-chained audit
JSONL were produced with these exact byte formats; changing either format
breaks verification of existing artifacts.

What landed instead:

- `acgs_governance_eval_mvp/tests/test_sha256_json_divergence.py` —
  characterization tests with golden hashes for the ASCII-agreement case,
  the non-ASCII divergence, and the coerce-vs-raise behavior. Any silent
  format change fails loudly.
- Docstring warnings on both functions naming the divergence and pointing
  at each other.

## Prevention

- Never verify a hash across the `governance` / `governed_mcp_v0` boundary.
- New code needing strict, unambiguous hashing uses
  `governance/crypto/canonical.py::canonical_bytes` (Phase 2 ABI), which
  rejects ambiguity (floats, datetimes, non-NFC strings) instead of coercing.
- Unification remains possible (zero cross-module call sites) but must be
  done as a versioned format migration, not a drive-by rename.
