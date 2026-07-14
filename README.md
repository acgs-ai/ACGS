ACGS / gove-zone is a vendor-neutral, receipt-gated governance layer for AI-agent side effects. It sits at the executor boundary below any agent framework, enforces policy before execution, emits a verifiable Decision Receipt, and makes executors fail closed without a valid receipt.

# ACGS / gove-zone

![status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)
![python: 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)
[![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![docs: acgs.ai](https://img.shields.io/badge/docs-acgs.ai-blue.svg)](https://acgs.ai/docs)
[![GitHub stars](https://img.shields.io/github/stars/dislovelhl/ACGS?style=social)](https://github.com/dislovelhl/ACGS)

> **Core invariant: No valid Decision Receipt, no side effect.**

> Alpha (`gove-zone` reports `0.1.0.dev0`). Badges reflect declared metadata, not a
> production, compliance, or certification claim — see
> [What this repository is not claiming](#what-this-repository-is-not-claiming).

ACGS is not another agent framework, and it is not owned by one. It is the vendor-neutral execution membrane between AI-agent reasoning and real-world change: file writes, API calls, database updates, emails, payments, deployments, MCP tools, shell commands, and any other side effect that should require explicit authority. Because the gate sits *below* whatever framework issued the call, the same policy decision and the same vendor-neutral Decision Receipt format describe a governed action regardless of which framework issued it — across the runtimes ACGS supports, at the proof tiers in [`docs/INTEGRATION_MATRIX.md`](docs/INTEGRATION_MATRIX.md) — and ACGS privileges none of them.

The `gove-zone` package (`packages/gove-zone`, Python module `gove_zone`) is the local governed-runtime kernel inside this ACGS / govern-zone monorepo. Agent frameworks, MCP servers, hook hosts, function-call/tool-call bridges, CI jobs, and custom executors can keep doing orchestration; ACGS answers the narrower question: **is this exact actor allowed to run this exact action with these exact arguments under this exact policy evidence?** See [`docs/INTEGRATION_MATRIX.md`](docs/INTEGRATION_MATRIX.md) for which runtimes are supported, at what proof depth.

## First screen: what to do

| Question | Short answer |
|---|---|
| What is it? | A vendor-neutral, receipt-gated governance layer for AI-agent side effects. |
| What problem does it solve? | Agents can request powerful tools faster than teams can prove authority, policy, auditability, and replay. ACGS moves that proof before execution. |
| Why neutral? | The gate sits at the executor boundary, below whatever framework issued the call, so one policy decision and one common receipt format apply to every caller wired through it — runtime support is tiered, not uniform (see the integration matrix). A single platform governing its own agents has an inherent conflict of interest in offering that even-handedness across rival platforms; ACGS privileges none. See [`docs/INTEGRATION_MATRIX.md`](docs/INTEGRATION_MATRIX.md). |
| Core invariant | **No valid Decision Receipt, no side effect.** |
| Why it matters | Tool calls can mutate files, systems, money, data, or infrastructure. A natural-language model may request an action; the executor must enforce the receipt gate. |
| Proof path | Run the smoke proof, run the receipt-gated execution demo, inspect the proof pack, then tamper with receipts/audit evidence and observe failure. |
| Implemented now | Local kernel, policies, Decision Receipts, executor gate, audit hash chain, replay helpers, signing mode, proof pack, runtime-hook/MCP/function-call adapter shapes, tests. |
| Not claimed yet | Not production-certified, not compliance-certified, not regulator-approved, not a sandbox replacement, not a complete IAM/PKI system, not a full formal-verification system. |

## Run the proof path

From the repository root:

```bash
tmp=$(mktemp -d) && uv run --package gove-zone gove-zone smoke --audit "$tmp/acgs-gove-zone-smoke-audit.jsonl"
uv run --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py
uv run --package gove-zone python examples/tamper_demo/demo.py
uv run python -m pytest tests/docs --import-mode=importlib -q
```

Expected result: the allowed side effect executes, denied/missing/tampered/mismatched receipts fail closed, audit evidence verifies, and tampered evidence fails replay/integrity checks.

For the fastest guided path, start at [`docs/START_HERE.md`](docs/START_HERE.md). For the canonical proof narrative, read [`docs/PROOF_PATH.md`](docs/PROOF_PATH.md). The full documentation index is [`docs/README.md`](docs/README.md).

## What is implemented now

| Capability | Evidence |
|---|---|
| Policy-before-execution dispatch | `packages/gove-zone/src/gove_zone/kernel.py`; `packages/gove-zone/tests/test_fail_closed.py` |
| Decision Receipt schema and validation | `packages/gove-zone/src/gove_zone/receipt.py`; `packages/gove-zone/tests/test_decision_receipt.py` |
| Receipt-gated executor | `packages/gove-zone/src/gove_zone/executor.py`; `packages/gove-zone/tests/test_executor_guard.py` |
| Actor/action/argument/policy binding | `packages/gove-zone/tests/test_argument_binding.py`, `test_tenant_safety.py`, `test_receipt_expiry.py` |
| Tamper-evident audit chain | `packages/gove-zone/src/gove_zone/audit.py`; `packages/gove-zone/tests/test_audit_chain.py`, `test_audit_chain_corruption.py` |
| Replay and side-store re-derivation | `packages/gove-zone/src/gove_zone/replay.py`; `packages/gove-zone/tests/test_replay.py` |
| Opt-in Ed25519 signing | `packages/gove-zone/src/gove_zone/signing.py`; `packages/gove-zone/tests/test_receipt_signing.py` |
| Runtime/MCP/function-call adapter shapes | `packages/gove-zone/src/gove_zone/integration.py`; `packages/gove-zone/tests/test_integration_hook.py`, `test_integration_gaps.py` |
| Local proof pack | `gove-zone proofpack`; `packages/gove-zone/tests/test_cli.py` |

## What this repository is not claiming

ACGS / gove-zone is alpha (`gove-zone` currently reports `0.1.0.dev0`). The local proofs are valuable engineering evidence, but they are not production deployment proof. Do not claim this repository is:

- production-certified;
- compliance-certified;
- regulator-approved;
- not a replacement for content moderation;
- not a replacement for sandboxing;
- not a replacement for IAM/RBAC, SIEM, WORM audit storage, or formal verification;
- not a complete IAM/PKI system or complete key custody, revocation, or access-management system;
- a guarantee that a live agent host is already configured to enforce the gate.

See [`docs/CLAIMS.md`](docs/CLAIMS.md) for the claim ledger and safe public wording.

## Repository map

| Path | Purpose |
|---|---|
| `packages/gove-zone/` | Governed runtime kernel: policy, Decision Receipts, executor gate, audit chain, replay, signing, adapters, CLI. |
| `packages/acgs-lite/` | Published ACGS legitimacy API package; independent nested repo. |
| `packages/Acgs-Swarm/` | Constitutional swarm research; independent nested repo. |
| `acgs_governance_eval_mvp/` | Evaluation/governance MVP surface. |
| `acgs-cft-governance-pack/` | Infrastructure governance pack. |
| `acgi-ai/` | Frontend/console; privileged origin rules apply. |
| `docs/` | Human and agent documentation, claim ledger, architecture, proof path, integration guide. |
| `examples/` | Root runnable governance examples for integrators. |
| `tests/docs/` | Documentation/example smoke tests and link checks. |

## Frontend buyer-evidence gallery

The `acgi-ai/` console ships a dependency-free local buyer-evidence gallery. From
`acgi-ai/`, `pnpm run evidence:build` writes the gallery and `pnpm run test:buyer-evidence`
verifies it covers the receipt proof journey, bus-owned proof source, claim-safe trust
surface, and visual governance workbench without unsupported production claims. This is a
local buyer-evidence artifact — not hosted Storybook, and not production deployment proof.

## Read next

1. [`docs/START_HERE.md`](docs/START_HERE.md) — 10-minute path for humans and agents.
2. [`docs/PROOF_PATH.md`](docs/PROOF_PATH.md) — denied action → receipt → evidence → replay → tamper failure.
3. [`docs/DECISION_RECEIPT_SPEC.md`](docs/DECISION_RECEIPT_SPEC.md) — public contract for integrators.
4. [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) — threat model and current protections.
5. [`docs/INTEGRATION_GUIDE.md`](docs/INTEGRATION_GUIDE.md) — where to put the gate in your stack.
6. [`docs/INTEGRATION_MATRIX.md`](docs/INTEGRATION_MATRIX.md) — supported runtimes by proof tier (shipped / pattern / roadmap).
7. [`AGENTS.md`](AGENTS.md) and [`llms.txt`](llms.txt) — agent-readable operating instructions and navigation index.

## Development status

This checkout is a multi-package monorepo with existing dirty worktree state in multiple packages. Treat package-local instructions and validation commands as authoritative. For documentation-only work, the safe local checks are:

```bash
uv run python -m pytest tests/docs --import-mode=importlib -q
uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q
make lint-docs
```

Use `make verify` for broad root validation when the full mixed workspace is intended to be gated.
