# Governed legal drafting & discovery agent example

Shows a legal drafting/discovery agent — drafting documents, filing court submissions,
accessing attorney-client privileged material, messaging clients, and exporting discovery
sets — governed by gove-zone's call-time policy enforcement and receipt-gated execution.

Run:

```bash
uv run --package gove-zone python examples/governed_legal_drafting/demo.py
```

Expected output: JSON on stdout with `status: "pass"`, `scenarios_run: 10`,
`scenarios_passed: 10`, and `audit_chain_valid: true`. Human-readable scenario diagnostics are
written to stderr; only the final JSON report goes to stdout.

Failure case: a paralegal actor attempts to file a court submission or send a client
communication without attorney sign-off (ESCALATE — requires human approval to resume), access
privileged material outside the matter's ethical-wall scope (DENY), send an unreviewed client
communication (DENY), or export discovery to a privileged shared mount (DENY). In every blocked
case the mock tool's side-effect is asserted to not have run.

What is proven: a legal agent's high-risk actions (court filings, privileged-document access,
client communications, discovery exports) are intercepted at the tool-dispatch membrane and
require a valid, policy-matching Decision Receipt before the underlying mock action executes.

This example is local-only (tempdir-only, unsigned dev-mode receipts). It proves executor
placement and fail-closed behavior for a legal-agent policy shape; it does not prove bar
approval, regulator certification, attorney-supervision-rule compliance, or production
deployment.
