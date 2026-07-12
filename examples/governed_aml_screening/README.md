# Governed AML transaction-screening example

Shows how gove-zone governs an Anti-Money-Laundering (AML) transaction-screening
agent: sanctions/watchlist screening, SAR (Suspicious Activity Report) filing,
fund release, account freezes, and case-report export are all gated behind a
`RuleSetPolicy` and `execute_with_receipt`. No valid Decision Receipt, no side
effect.

Run:

```bash
uv run --package gove-zone python examples/governed_aml_screening/demo.py
```

Expected output: a single line of JSON on stdout with `status: "pass"`,
`scenario_count: 10`, `scenarios_held: 10`, and `audit_chain_valid: true`.
Scenario narration (which rule fired, whether the mock tool's side effect ran)
is printed to stderr, not stdout.

Failure case: a `DENY` or `ESCALATE` receipt is presented to the executor for
a sensitive action (screening a sanctioned counterparty, releasing funds over
the reporting threshold, filing a SAR or freezing an account without the
required approval tier, exporting a report into the regulated-exports mount);
`execute_with_receipt` raises `ReceiptValidationError` and the mock tool's
side-effect flag never flips to `True`.

What is proven: an AML screening agent's side-effecting tools (screen,
file-SAR, release, freeze, export) can be intercepted at the tool-dispatch
membrane and gated by policy before they run, and that ESCALATE decisions
fail closed exactly like DENY until a human resumes them via an out-of-band
approval flow.

## Scenario table

| # | Tool | Actor / tier | Condition | Decision |
|---|------|---------------|-----------|----------|
| 1 | `aml.screen_transaction` | analyst | non-sanctioned counterparty | ALLOW |
| 2 | `aml.screen_transaction` | analyst | sanctioned counterparty | DENY |
| 3 | `aml.file_sar` | analyst | no compliance-officer approval | ESCALATE |
| 4 | `aml.file_sar` | compliance-officer | — | ALLOW |
| 5 | `aml.release_funds` | analyst | over CTR threshold | DENY |
| 6 | `aml.release_funds` | analyst | under CTR threshold | ALLOW |
| 7 | `aml.freeze_account` | analyst | no supervisor sign-off | ESCALATE |
| 8 | `aml.freeze_account` | supervisor | — | ALLOW |
| 9 | `aml.export_report` | analyst | writes into `/mnt/regulated-exports` | DENY |
| 10 | `aml.export_report` | analyst | writes into an approved directory | ALLOW |

This example is local-only, dev-mode (`require_signature=False`) and uses mock
tools. It proves executor placement and fail-closed behavior; it does not
prove production deployment, compliance certification, or regulator approval.
