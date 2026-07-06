# gove-zone — Threat Model (one page)

> Status: alpha (`0.1.0a1`). This is an honest boundary statement, not a
> certification. For the deep treatment of every property below, see
> [`../SECURITY.md`](../SECURITY.md).

## Scope

This covers the **gove-zone governance plane** — the enforcement kernel inside
the govern-zone / ACGS workspace that sits immediately before a high-risk side
effect. It governs **one decision per action**:

> **No valid Decision Receipt, no side effect.**

It does **not** cover the agent that proposes actions, the tool that performs
them, the host they run on, or the network in between. Those are trust
boundaries you own — see *What you must supply externally*.

## Trust boundaries

1. **Policy-evaluation gate** — every proposed action is evaluated before it
   runs; the gate is `DecisionReceipt.verify` (wrapped by `execute_with_receipt`
   / `GovernedExecutor` / `ReceiptVerifier`). There is no second, weaker path.
2. **Receipt integrity** — tenant, boundary, policy hash, arguments, and expiry
   are bound into `receipt_hash`; signed by default under the production profile.
3. **Audit chain** — an append-only, hash-linked JSONL written *before*
   execution; offline-verifiable.
4. **Role separation (MACI)** — proposer (the requesting agent) and validator
   (the approving authority) are distinct principals, enforced at issuance and
   at the gate.
5. **Tenant isolation** — a receipt or policy bundle issued for one tenant
   cannot execute in another's context.

## 1. What gove-zone prevents

- **Unauthorized execution.** An action runs only if a valid receipt verifies;
  a `DENY`/`ESCALATE`, a missing/expired/tampered receipt, or any evaluation
  error fails closed — never silently allows. [SECURITY.md → *Fail-closed by
  construction*]
- **Argument substitution.** A receipt authorizes a tool *with specific
  arguments*; executed args are hash-checked at the gate. A receipt for
  `write_file(path="/tmp/safe")` cannot authorize `path="/etc/shadow"`.
  [→ *Argument binding*]
- **Silent tampering of the record.** Any edit, reorder, or truncation of the
  audit chain fails `verify_chain()`; an altered receipt fails its `receipt_hash`
  check. [→ *Tamper-evidence*]
- **Receipt forgery (production profile).** Signed Ed25519 receipts make a
  recomputed-hash forgery cryptographically infeasible without the private key.
  [→ *Ed25519 receipt signing*]
- **Self-authorization.** An agent cannot both propose and validate its own
  action; self-validated receipts are rejected at issuance and at the gate.
  [→ *Role separation (MACI)*]
- **Cross-tenant leakage.** One tenant's policy/receipt is rejected in another's
  execution context. [→ *Multi-tenant isolation*]

## 2. What gove-zone does NOT prevent

- **A compromised host.** An attacker who can write the audit file *and* run the
  issuer can forge a consistent local chain. The chain proves tamper-evidence to
  *readers*, not unforgeability under full host compromise.
- **A stolen signing key.** A leaked private key lets an attacker mint
  valid-looking signed receipts. Signing closes forgery-by-recompute, not
  key theft.
- **The blast radius of the tool itself.** gove-zone decides *whether* and *with
  which arguments* an action runs; it does not sandbox the side effect. Run your
  tools in your own sandbox.
- **Approval workflow.** `ESCALATE` blocks the action; it does not yet route to
  or resolve a human approval.
- **Authentication of the caller.** The gate checks a caller-supplied
  `expected_actor`; it does not authenticate identity. On the unsigned (dev)
  path, proposer-binding is only as strong as your external authentication.
- **Compliance / regulatory certification.** Local receipts and smoke proofs are
  readiness evidence, not certification or regulator validation.

[All of the above are enumerated in SECURITY.md → *What gove-zone does NOT do*.]

## 3. What you must supply externally

- **Caller authentication** — establish *who* the actor is; pass it as
  `expected_actor`. gove-zone enforces separation over identities you assert.
- **Key custody, distribution, rotation, and revocation** — production signing
  is point-to-point; there is no PKI, trust store, or revocation list. You hold
  and rotate the keys and the verifier mapping.
- **Tool sandboxing** — contain what an allowed tool can do at the OS/network
  level.
- **Durable / off-host audit storage** — the chain is local JSONL; ship it to
  WORM storage or a SIEM if you need durability beyond the host.
- **Policies** — you author the rules; gove-zone enforces them.
- **Approval routing** — wire `ESCALATE` to your own approval system.

## Operational guidance

- Keep the production profile (the default): signed receipts + a configured
  verifier. A production gate with no verifier fails closed loud
  (`ProductionProfileError`) — configure keys rather than dropping to
  `GovernanceProfile.dev()`.
- Select posture explicitly in deployment via `GOVE_ZONE_PROFILE=production`
  (default) or `dev`.
- Treat the audit JSONL as tamper-evident, not unforgeable, unless signing is
  engaged and keys are protected.
- Verify decisions offline after the fact:
  `gove-zone replay --audit audit.jsonl --event <id>`.
- Never commit private signing keys to source control; rotate keys and audit
  logs on a schedule.
