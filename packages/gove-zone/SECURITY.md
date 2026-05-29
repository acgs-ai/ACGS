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
- an `ALLOW` whose executed arguments do not hash-match the arguments the
  receipt was issued for, or a `TRANSFORM` whose executed arguments are not
  exactly the approved transformed set (extra, missing, or altered fields);
- a self-validated receipt (validator is the proposer), a missing validator
  identity / role or authority binding, or — when the caller supplies its own
  identity (`expected_actor`) — a receipt issued for a different principal or one
  whose validator is the invoking principal;
- an `approval_chain_summary` that disagrees with the bound validator / proposer
  fields.

In the issuing kernel: a policy that raises or times out becomes a `DENY`; an
audit-append failure raises `AuditError`. No exception path resolves to "allow"
(`kernel.py`, `test_fail_closed.py`, `test_fail_closed_gaps.py`).

## Tamper-evidence

- Receipts are self-hashing; tenant, boundary, policy hash, and `expires_at` are
  bound into `receipt_hash`, so altering them without re-issuing is detected.
- The audit log is an append-only hash chain; any edit, reorder, or truncation
  fails `verify_chain()` (`test_audit_chain*`, `test_audit_chain_corruption.py`).
- Concurrent audit appends are serialized with `fcntl.flock` + `fsync`.

## Role separation (MACI)

A Decision Receipt binds two distinct principals: the **proposer** (`actor` — the
agent that asked for the action) and the **validator** (`validator_id` +
`validator_role` — the authority that approved it), plus the `authority` grant
under which execution is permitted. All three are bound into `receipt_hash`.

Separation is enforced at two points:

- **Issuance.** `DecisionReceipt.from_record` (and `evaluate_tenant_action`)
  refuse to mint a receipt whose validator equals the proposer. A self-validated
  receipt cannot be created through the normal path.
- **The gate.** When the caller passes its own identity as `expected_actor`
  (recommended; `GovernedExecutor` carries it as construction context),
  `verify()` rejects a receipt not issued for that caller and rejects one whose
  validator is the invoking principal. `expected_actor` comes from the caller's
  runtime context, never from the receipt, so a receipt author cannot satisfy it
  by editing receipt fields.

This is the kernel's MACI invariant: *an agent can propose an action but can
never validate its own authority to execute it.*

**Residual (honest scope).** When a caller omits `expected_actor`, the gate falls
back to a weak heuristic that only catches a receipt whose `validator_id` and
`actor` fields are literally identical; a forger who can recompute `receipt_hash`
and sets `actor` to a phantom value while keeping the real proposer as
`validator_id` is not caught on that path. Proposer-binding is therefore only as
strong as the caller supplying `expected_actor`, and ultimately as strong as
authenticated/signed issuance — which remains roadmap (see below). The
separation is enforced-by-verifier and audited; it is **not** cryptographically
unforgeable under host compromise.

## Argument binding

A receipt authorizes a specific tool *with specific arguments*, not the tool in
general. The proposed arguments are hashed (`argument_hash`, bound into
`receipt_hash`) at issuance. At the gate, `execute_with_receipt` passes the
about-to-run arguments as `expected_args`, and `verify()` refuses execution
unless they match: for `ALLOW`, the executed args must hash-match
`argument_hash`; for `TRANSFORM`, they must be exactly the approved transformed
set. A valid receipt for `write_file(path="/tmp/safe")` therefore cannot
authorize `write_file(path="/etc/shadow")`.

This binding is enforced at the gate (`execute_with_receipt` / `GovernedExecutor`
always supply `expected_args`). A bare `DecisionReceipt.verify()` call with
`expected_args=None` skips the argument comparison — verify the gate, or pass
`expected_args`, when checking receipts directly.

## Multi-tenant isolation

A receipt or policy bundle issued for one tenant cannot be used by another;
missing tenant identity fails closed (`test_tenant_safety.py`). See
`docs/policy-bundles.md`.

## Opt-in Ed25519 receipt signing

gove-zone supports asymmetric receipt signing as an opt-in capability. When
engaged, it closes the recomputed-receipt residual: anyone can verify a receipt
with the public key; only the private-key holder can produce a valid signature,
so a recomputed-hash forgery is cryptographically infeasible.

**How to engage.** Issue receipts with a private-key signer and verify at the
gate with the matching public-key verifier plus ``require_signature=True``:

```python
signer  = Ed25519Signer.generate()
receipt = evaluate_tenant_action(…, signer=signer)

verifier = Ed25519Signer.from_public_bytes(signer.public_bytes())
execute_with_receipt(…, verifier=verifier, require_signature=True)
```

A receipt that advertises a signature (``signature_algorithm != "none"``) is
**always** verified cryptographically — presenting it without a verifier is a
hard rejection, regardless of ``require_signature``.

**Default deployments are unsigned.** Without an explicit ``signer`` at issuance
and ``verifier + require_signature=True`` at the gate, receipts remain unsigned
(``signature = "unsigned_local"``); integrity rests on ``receipt_hash`` and the
audit chain as before.

**Residuals not addressed by signing:**
- **Private-key custody.** A compromised signing key lets an attacker issue
  valid-looking receipts. Key custody is the operator's responsibility.
- **Key distribution / trust establishment.** There is no PKI, certificate chain,
  or trust-store bootstrapping. The verifier mapping is static; the operator must
  manage it.
- **Revocation.** A compromised key cannot be revoked; the operator must update
  and redeploy the verifier mapping.

## What gove-zone does NOT do (security non-goals today)

- **No PKI or key lifecycle management.** Ed25519 signing is point-to-point
  (issuer ↔ gate); there is no certificate authority, trust chain, or revocation
  infrastructure. Key distribution and custody are the operator's responsibility.
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
