# CI deploy gate example

Shows a CI/CD deployment step protected by a Decision Receipt gate.

Run:

```bash
uv run --package gove-zone python examples/ci_deploy_gate/demo.py
```

Expected output: JSON with `status: "pass"`, `staging_deploy_executed: true`, `prod_deploy_denied: true`, and `deploy_count: 1`.

Failure case: a `DENY` receipt for production deployment is presented to the executor; the deploy function is not called.

What is proven: CI can request deployment, but the deploy step itself must enforce the receipt gate.

This example is local-only. It proves executor placement and failure behavior; it does not prove production deployment, compliance certification, or live framework integration.
