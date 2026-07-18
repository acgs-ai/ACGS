# gove-zone

**Receipt-gated runtime governance for AI-agent side effects.**

> For every execution path wired through gove-zone: **no valid Decision
> Receipt, no side effect.**

gove-zone is the ACGS monorepo's core Python enforcement kernel. It evaluates a
proposed action before execution, records the decision, and requires a governed
executor to verify the resulting receipt before a side effect can run. It is an
enforcement layer for agents, MCP tools, workflows, CI jobs, and custom
executors—not an agent framework or a sandbox.

> **Current source metadata:** version `1.0.0rc1`, with a Beta classifier.
> The candidate history still requires release reconciliation. These checked-in
> values do not prove that this version was tagged, published on PyPI, deployed
> to production, certified, or independently assured.

## Prove the invariant locally

Prerequisites: Python 3.11+, `uv`, a source checkout, and Bash on Linux/macOS;
on Windows, use WSL or Git Bash for the commands shown. Environment setup may
download dependencies; after they are installed, the proof itself requires no
agent host, production credential, or external service.

From the monorepo root:

```bash
uv run --package gove-zone gove-zone smoke
uv run --extra crypto --package gove-zone python \
  packages/gove-zone/examples/receipt-gated-execution/demo.py
```

The smoke command proves that a safe action is allowed, a sensitive-path write
is denied before execution, and the local audit chain verifies. The signed demo
also exercises missing, tampered, expired, mismatched, and cross-tenant
receipts. Both commands exit non-zero if their assertions fail.

Use `--audit <path>` with `gove-zone smoke` to retain the smoke JSONL as
point-in-time evidence.

## How execution is gated

```text
Proposed action
  → policy decision (or fail-closed DENY)
  → append audit event and issue Decision Receipt
  → governed executor verifies receipt and execution context
  → valid ALLOW/TRANSFORM side effect, or fail-closed block
```

The proposer does not authorize itself. The receipt binds the actor, action,
exact arguments, tenant, policy evidence, and execution context. A missing,
invalid, expired, or mismatched receipt is rejected. A valid receipt is
single-use only when every relevant executor shares a configured
`ReceiptConsumptionLedger`; receipt verification is otherwise stateless.

## When to use it

Use gove-zone when you need:

- a policy decision before a specific tool call executes;
- a fail-closed boundary when governance cannot decide or record evidence;
- machine-verifiable Decision Receipts bound to exact arguments and context;
- hash-chained, tamper-evident local audit evidence and offline chain/event
  verification;
- proposer/validator separation and tenant isolation; or
- optional Ed25519-authenticated receipts.

It does not provide:

- planning or agent orchestration;
- a turnkey human-approval queue or UI;
- a complete IAM, PKI, key-rotation, or revocation service;
- containment against a fully compromised issuer or execution host;
- immutable/WORM audit storage; or
- production, compliance, or regulatory certification.

Use authentication, authorization, sandboxing, key custody, external audit
anchoring, and operational monitoring alongside this kernel.

## Install

### Source checkout

From the monorepo root:

```bash
uv sync --package gove-zone --extra crypto
uv run --package gove-zone gove-zone doctor
uv run --package gove-zone gove-zone smoke
```

Scope `uv sync` to the package. The workspace root is a virtual project, so
root-level `uv sync --all-extras` does not install this package's extras.

### Verified PyPI release

Do not infer PyPI availability from the checked-in version. Only after a release
manager has independently verified a published version, install that exact
version in a clean environment:

```bash
python -m venv .venv
# Activate .venv for your shell, then replace VERIFIED_VERSION below.
python -m pip install --isolated --no-cache-dir \
  --index-url https://pypi.org/simple \
  "gove-zone[crypto]==VERIFIED_VERSION"
gove-zone doctor
gove-zone smoke
```

The release runbook is `docs/RELEASING.md`; the repository-wide readiness
report is `../../docs/gove-zone-pypi-readiness.md`.

## Distribution surface

| Component | Shipped surface |
|---|---|
| `gove_zone` | Decisions, policies, receipts, governed execution, audit, replay, signing, adapters, evaluation, and CLI support |
| `mcp_gateway` | MCP gateway binding included in the wheel |
| Console scripts | `gove-zone`, `gove-zone-api`, and `acgs` |
| Optional extras | `crypto` for Ed25519 support; development extras are defined in package metadata |
| Python | `>=3.11` |
| Audit store | Append-oriented, hash-chained local JSONL with POSIX `fcntl` and Windows `msvcrt` locking paths |

The public SemVer surface is defined in `docs/API_STABILITY.md`. Before a
stable `1.0.0`, the project must finish reconciling that contract with both
wheel packages, all console scripts, and the public API fixture.

## Security-critical deployment contract

- **Use the governed boundary.** Integrate through
  `execute_with_receipt`, `GovernedExecutor`, or a documented adapter that
  reaches the same verification gate. A direct `DecisionReceipt.verify()` call
  is not a complete execution boundary.
- **Configure trusted signatures.** Receipt issuance signs only with an explicit
  signer. Governed executor gates separately require trusted verification by
  default. Without a configured matching verifier, the gate raises before
  calling the tool. Development-only unsigned mode is an explicit opt-out; it
  is not a production default.
- **Configure one-time consumption when required.** Share a
  `ReceiptConsumptionLedger` across every executor that must reject replay.
- **Anchor audit state externally.** The local hash chain detects internal
  edits, but truncating a suffix can leave a consistent prefix. Store the
  expected event count or final hash outside the local file.
- **Retain replay inputs intentionally.** Audit-only replay verifies chain/event
  integrity and policy-version consistency. Re-deriving a decision requires the
  original raw-call side store plus the matching original policy bundle; the
  side store is opt-in because it retains sensitive arguments.
- **Keep secrets out of policy reasons.** Human-readable reasons can reach
  rejection envelopes and audit evidence.
- **Validate each target platform.** Lock implementations have platform-specific
  test coverage, but that is not production deployment evidence.

## Documentation in the source tree

| Goal | Path |
|---|---|
| Architecture | `ARCHITECTURE.md` |
| Security boundary | `SECURITY.md` and `docs/threat-model.md` |
| Governed execution | `docs/governed-execution.md` |
| Decision Receipts | `docs/decision-receipts.md` |
| Audit evidence | `docs/audit-evidence.md` |
| Policy bundles | `docs/policy-bundles.md` |
| API stability | `docs/API_STABILITY.md` |
| Release process | `docs/RELEASING.md` |
| Changelog | `CHANGELOG.md` |

The project website is <https://acgs.ai/>. Public source and issue-tracker links
must be resolved as part of the release decision while this repository remains
private.

## Development checks

From the monorepo root:

```bash
uv run --package gove-zone python -m pytest \
  packages/gove-zone/tests --import-mode=importlib -q
(cd packages/gove-zone && bash scripts/release_check.sh)
```

For documentation changes, also run:

```bash
uv run python -m pytest tests/docs --import-mode=importlib -q
make lint-docs
```

## License

Apache-2.0.
