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
  identity / role or authority binding, or — the gate requires the caller's own
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
- **The gate.** The gate surfaces — `execute_with_receipt`, `GovernedExecutor`,
  and `ReceiptVerifier` — now **require** `expected_actor` (the caller's own
  identity). Omitting it raises (`TypeError` for a missing kwarg,
  `ReceiptValidationError` for an empty string) rather than silently downgrading
  to a weaker check. `verify()` then rejects a receipt not issued for that caller
  and rejects one whose validator is the invoking principal. `expected_actor`
  comes from the caller's runtime context, never from the receipt, so a receipt
  author cannot satisfy it by editing receipt fields. The strong caller-anchored
  check is therefore the default at every gate, not an opt-in.

This is the kernel's MACI invariant: *an agent can propose an action but can
never validate its own authority to execute it.*

**Residual (honest scope).** The weak heuristic — which only catches a receipt
whose `validator_id` and `actor` fields are literally identical — is **no longer
reachable through the gate**: every gated path requires `expected_actor`, so the
strong actor-anchored check always runs. The heuristic survives solely as
residual defense-in-depth for direct `DecisionReceipt.verify()` callers who pass
no `expected_actor`; against that path, a forger who recomputes `receipt_hash`
and sets `actor` to a phantom value while keeping the real proposer as
`validator_id` is still not caught. Requiring the anchor relocates trust to the
integrator: it does **not** manufacture an authenticated proposer identity the
architecture lacks. Unsigned-default proposer-binding is therefore only as strong
as the integrator's external authentication of the caller; the actual
cryptographic closure is **signed issuance** (`require_signature=True` + a
trusted public-key verifier — see *Opt-in Ed25519 receipt signing* below), which
is the recommended production posture. The separation is enforced-by-verifier and
audited; it is **not** cryptographically unforgeable under host compromise on the
unsigned path.

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

## Workflow receipt chaining

`workflow.py` extends the per-action gate to a declared DAG of steps. Each step's
execution is gated by a `WorkflowStepReceipt` that wraps a fully valid inner
`DecisionReceipt` (verified by the unchanged single-action gate) and binds it to
a workflow position. The envelope's `step_receipt_hash` covers `workflow_id`,
`step_id`, sorted predecessors, predecessor receipt hashes, `dag_hash`, the
signing algorithm/key id, **and the inner receipt's `receipt_hash`** — so a
tampered envelope or a swapped inner receipt is detected. `signature` signs that
hash and stays out of it, identical to the inner receipt's discipline.

**Order is load-bearing.** `WorkflowExecutor.execute_step` completes every
envelope check — present, hash, signature (when engaged), workflow binding, DAG
binding (`dag_hash` + step membership + declared-predecessor match), no-replay,
and predecessor satisfaction — **before** the atomic inner gate-and-execute. The
single-action gate verifies-and-executes in one call, so if the inner gate ran
first, a reordered or cross-workflow step's side effect would fire before the
envelope rejection. Every negative-path test asserts the side effect did not run.

**What it proves.** A step ran in the approved order, with approved arguments,
under a valid per-step receipt bound to the approved plan. The per-run `ledger`
(trusted runtime state) is what detects replay, reordering, and
predecessor-substitution.

**Honest scope (residuals).**
- Workflow chaining adds **no** cryptographic guarantee beyond the per-step
  receipts and their envelopes.
- **Plan-level governance is out of scope** for this increment: the DAG is **not**
  a separately proposer≠validator-authorized object. `dag_hash` is a consistency
  binding, not an authority decision over the plan. A future `WorkflowAuthorization`
  receipt with its own MACI separation would govern the DAG itself.
- **Unsigned `verify_workflow_replay()` proves internal chain consistency and
  topological faithfulness, NOT unforgeability**: an attacker who can recompute
  envelope hashes (and re-sign, if they hold the key) can produce a consistent
  chain. Envelope signing (`ReceiptSigner`) is the closure for cross-workflow and
  ordering integrity — and only when engaged — exactly as Ed25519 closes the inner
  recomputed-receipt residual.
- The ledger's substitution/reorder detection rests on it being trusted runtime
  state; offline replay has no ledger and relies on envelope integrity (hashes,
  and signatures when engaged).
- Under host compromise, the same residuals as the single-action gate apply.

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
