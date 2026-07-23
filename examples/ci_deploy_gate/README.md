# CI deploy gate example

Shows a CI/CD deployment step protected by a Decision Receipt gate.

Run:

```bash
uv run --package gove-zone python examples/ci_deploy_gate/demo.py
```

Expected output: JSON with `status: "pass"`, `staging_deploy_executed: true`, `prod_deploy_denied: true`, `prod_denial_audited: true`, `prod_policy_rule_retained: true`, and `deploy_count: 1`.

Failure case: a `DENY` receipt for production deployment is presented to the executor. The gate raises `ReceiptValidationError`, the deploy function is not called, and the last audit event is a `DENY` whose matched rules are exactly `receipt.execution.receipt_invalid`.

Two distinct facts, asserted separately so they are not conflated:

- **Why the gate refused**: the executor rejects the receipt because its decision is not
  executable. That is an execution-gate reason (`receipt.execution.receipt_invalid`) and says
  nothing about the policy that produced the `DENY`.
- **Why policy denied**: the original authorization `DecisionRecord` (event `ev_ci_prod`) is
  looked up on the audit chain and still carries its matched rule
  `PROD_REQUIRES_MANUAL_APPROVAL`. The policy cause lives in the authorization record, not in
  the gate's rejection reason.

What is proven: CI can request deployment, but the deploy step itself must enforce the receipt gate.

## How the gate is configured

The demo builds the strict receipt-gate fixture (`build_strict_receipt_gate_fixture`) in a
temporary directory, and both `execute_with_receipt` calls run under it with no opt-outs:

- `require_signature=True` with `verifier=fixture.signer` — both the staging `ALLOW` receipt and
  the production `DENY` receipt are signed at issuance and verified at the gate.
- Each receipt binds to a real audit chain: its policy `DecisionRecord` is appended to
  `fixture.audit` first, and the receipt carries that event's `event_hash` and `previous_hash`.
  The audit store is a chain-hash store with a signed external checkpoint anchor.
- `consumption_store=fixture.consumption_store` — anchored schema-v4 single-use consumption.
- `rejection_audit=fixture.audit` — denials are recorded on the same strict chain.
- `lifecycle_signer=fixture.lifecycle_signer` (a key distinct from the receipt signer) with
  `lifecycle_authority_id="fixture-lifecycle-validator"`.
- `expected_adapter_artifact_digest=adapter_artifact_digest(deployer.deploy)` — the gate refuses
  to run an adapter whose code identity does not match the digest.

This example is local-only. It proves executor placement and failure behavior with a strict,
fully-wired gate. The keys, audit chain, checkpoint anchor, and consumption anchor are
ephemeral and generated in-process for this run: they are not production key custody, not
off-host durability, and not evidence of a deployment. The deploy adapter is an in-process
counter — no environment is contacted and nothing is released. The example does not prove
production deployment, compliance certification, or live framework integration.
