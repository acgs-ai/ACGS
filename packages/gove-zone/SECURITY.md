# Security

> Status: foundational / Alpha (`0.1.0.dev0`). gove-zone is **not** production-,
> compliance-, or regulator-certified. This document states the security
> boundary honestly — what is enforced and what is explicitly out of scope.

## The security property

gove-zone enforces one invariant:

> **No valid Decision Receipt, no side effect.**

Everything below is in service of that. The single enforcement gate is
`DecisionReceipt.verify` (wrapped by `execute_with_receipt`, `GovernedExecutor`,
and `ReceiptVerifier`). There is no second, weaker path.

## Fail-closed by construction

Execution is refused — never silently allowed — on every one of:

- no receipt, malformed receipt, or tampered receipt (`receipt_hash` mismatch);
- a `DENY` or `ESCALATE` decision;
- tenant mismatch, execution-boundary mismatch, action mismatch;
- policy bundle id / policy hash mismatch;
- an expired receipt (`expires_at` in the past);
- a `TRANSFORM` whose approved arguments do not match the call.

In the issuing kernel: a policy that raises or times out becomes a `DENY`; an
audit-append failure raises `AuditError`. No exception path resolves to "allow"
(`kernel.py`, `test_fail_closed.py`, `test_fail_closed_gaps.py`).

## Tamper-evidence

- Receipts are self-hashing; tenant, boundary, policy hash, and `expires_at` are
  bound into `receipt_hash`, so altering them without re-issuing is detected.
- The audit log is an append-only hash chain; any edit, reorder, or truncation
  fails `verify_chain()` (`test_audit_chain*`, `test_audit_chain_corruption.py`).
- Concurrent audit appends are serialized with `fcntl.flock` + `fsync`.

## Multi-tenant isolation

A receipt or policy bundle issued for one tenant cannot be used by another;
missing tenant identity fails closed (`test_tenant_safety.py`). See
`docs/policy-bundles.md`.

## What gove-zone does NOT do (security non-goals today)

- **No cryptographic signatures.** `signature` is `unsigned_local`. Integrity
  rests on `receipt_hash` + the audit chain, not public-key signatures. A
  process that can compute `receipt_hash` can mint a "valid" local receipt —
  receipt issuance is not yet authenticated. Signed/authenticated receipts are
  roadmap.
- **No durable external audit sink.** The chain is local JSONL. WORM storage,
  SIEM shipping, and off-host append-only durability are roadmap.
- **No bundle lifecycle / revocation.** No active/stale/revoked state, no
  revocation lists.
- **No approval workflow.** `ESCALATE` blocks; it does not yet resolve into an
  authorization.
- **No sandboxing of the side effect itself.** gove-zone decides *whether* and
  *with which arguments* an action runs; it does not contain the blast radius of
  the tool you register. Run tools in your own sandbox.
- **Not a guarantee against a compromised host.** An attacker with write access
  to the audit file + the ability to run the issuer can forge a consistent local
  chain. The chain proves tamper-evidence for *readers*, not unforgeability under
  full host compromise.

## Reporting

This is alpha research software in a monorepo. Report suspected security issues
through the repository's normal issue/security channel. Do not assume any
deployment of gove-zone is production-hardened without independent review.
