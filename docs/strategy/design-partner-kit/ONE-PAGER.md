# gove-zone — Design Partner One-Pager

**For:** platform / security-engineering teams shipping agentic AI into high-blast-radius environments (offensive security tooling, infra automation, fintech/health ops).

**Status: Alpha (`0.1.0a1`). NOT production-certified, NOT compliance-certified.** This is a design-partner program to prove one invariant together in a real pipeline — not a product purchase. Read the "Honest disclosure" section before the pitch lands.

---

## The problem

Your agent can call `port_scan`, `exploit`, `python_execute`, `write_file`, `http_post`, `db_exec`. Today most stacks **audit after the side effect runs**. When your risk/compliance function asks *"prove this agent could not have exceeded scope,"* a log grep is not proof — it records what happened, not what was authorized, and it can be edited.

For a security-agent team the stakes are sharpest: an autonomous pentest agent that scans the wrong subnet, exploits an out-of-scope host, or executes arbitrary Python on the runner is a legal and operational incident, not a bug.

## The one invariant

> **No valid Decision Receipt, no side effect.**

gove-zone is an execution membrane that sits **below any framework**, at the tool-dispatch boundary. Before a tool runs:

1. Policy is evaluated **before** execution (allow / deny / escalate).
2. The decision is bound — actor + action + arguments + policy + audit evidence — into a signed **Decision Receipt**.
3. The executor runs the side effect **only if the receipt verifies**; DENY/ESCALATE receipts are non-executable.
4. Every decision (including denials) is appended to a tamper-evident hash-chained audit log, replayable and verifiable **offline** by a third party.

Fail-closed is architectural, not a config flag: if policy evaluation, receipt issuance, or audit append fails, the action is denied. There is no exception path that silently allows.

gove-zone is **not** an agent framework and never orchestrates — neutrality is the position. It does not do prompt/content safety (pair it with guardrails) and does not sandbox execution (it decides authorization).

## Proof you can run in 30 seconds

Verified on this repo (`0.1.0a1`, Python 3.13.11, exit 0, re-run 2026-07-03):

```bash
uv run --package gove-zone gove-zone smoke
```

Emits claim-bounded JSON: a safe `write_file` **allowed**, an `id_rsa` path write **denied before any side effect**, both linked in a verifying hash chain. And the flagship security-agent demo — a governed VulnClaw pentest agent across 8 allow/deny scenarios — runs the same way (see `DEMO-RUNBOOK.md`).

## What a pilot involves

- **Scope:** one real external pipeline of yours (a security agent, an MCP tool server, a CI job) wired through the gove-zone gate, running fail-closed.
- **Your effort:** target time-to-first-governed-call **under 1 hour** (see `ONBOARDING.md`, every command verified). Then instrument one metric: **fail-closed external pipelines** (our OMTM) — is the gate actually enforcing deny/escalate in your pipeline?
- **Our effort:** integration support, policy-bundle authoring for your tools, and auditor-ready proof-pack packaging of your receipts.
- **Duration:** short, bounded engagement. You keep everything: Apache-2.0 kernel, your receipts, your audit chain.

## What the partner gets

- A **fail-closed enforcement layer** your agents call before high-risk actions — provable scope limits for offensive-security tooling.
- **Verifiable Decision Receipts** you can hand to your risk/compliance function instead of a log grep.
- An **offline, tamper-evident evidence chain** (hash chain + signed receipts + replay + proof-pack verifier) — checkable by a third party with no access to your systems.
- **Zero runtime dependencies**; the kernel runs inside your own process (near-zero added infra, no data leaves your boundary for the decision).
- Direct influence on the receipt spec and adapter surface while it is still forming.

## Honest disclosure (read this)

- **Alpha, `0.1.0a1`.** Not production-certified, not compliance-certified. Do not present gove-zone to your auditor as a certified control; present it as an evidence-generation mechanism you are piloting.
- The shipped VulnClaw demo governs a **mock** pentest tool (it proves the gate's allow/deny/receipt/tamper behavior against the real gove-zone API — it does not drive live VulnClaw or attack real hosts).
- The dev-mode demos run **unsigned** receipts; the production (signed, Ed25519) profile is demonstrated separately in `undeniable-demo` and requires the `crypto` extra. In-process keypair generation in the demo is pedagogical, **not** real key custody.
- Every capability claim here maps to code and commands we actually ran (`docs/CLAIMS.md` discipline). If it is not proven, it is not claimed.

## Next step

30-minute call → run the demo live (`DEMO-RUNBOOK.md`) → if the invariant lands, we scope one pipeline and target first governed call under an hour.
