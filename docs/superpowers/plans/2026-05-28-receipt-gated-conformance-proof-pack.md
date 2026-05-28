---
title: Receipt-gated conformance proof pack plan
description: Implementation plan for aligning gove-zone CLI, receipts, executor enforcement, adapters, and proof-pack evidence.
---

# Receipt-gated conformance proof pack implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `packages/gove-zone` expose a local, tested receipt-gated execution proof path: no valid Decision Receipt, no side effect.

**Architecture:** Keep the hot path stdlib-only and deterministic. Extend the existing `gove_zone.foundation` contracts for receipt verification and executor authorization, add a small adapter normalization module, and make `gove-zone` CLI commands call those contracts instead of inventing a separate runtime.

**Tech Stack:** Python 3.11, `argparse`, existing `ChainHashAuditStore`, existing policy/kernel primitives, pytest, ruff, mypy.

---

## File map

- Modify `packages/gove-zone/src/gove_zone/foundation.py`: add `audit_event_hash`, approval-chain summary naming, receipt authorization context checks, and audit hash binding.
- Create `packages/gove-zone/src/gove_zone/adapters.py`: normalize MCP, OpenAI/Responses, LangChain, generic, CI/CD, and workflow envelopes into `GovernanceRequest`.
- Modify `packages/gove-zone/src/gove_zone/cli.py`: add `doctor`, `smoke`, `gate`, `proofpack`, and keep `replay`.
- Modify `packages/gove-zone/src/gove_zone/__init__.py`: export adapter and verifier helpers.
- Add/modify tests under `packages/gove-zone/tests/`: lock CLI commands, receipt tamper behavior, executor context blocking, adapter normalization, and proofpack output.
- Modify docs and READMEs: keep alpha language, document implemented commands and limitations.
- Add root `LICENSE`: visible Apache-2.0 boundary.

## Task 1: CLI command contract tests

- [ ] Add tests in `packages/gove-zone/tests/test_cli.py` proving `doctor`, `smoke`, `gate`, `proofpack`, and `replay` are registered.
- [ ] Run the CLI tests and verify they fail because `cli.py` only exposes `replay`.
- [ ] Implement minimal command bodies backed by package contracts.
- [ ] Re-run CLI tests and verify they pass.

## Task 2: Receipt verifier and executor fail-closed tests

- [ ] Add tests for missing receipt fields, unknown decisions, malformed transforms, audit hash mismatch, denied and escalated executor blocking, tenant mismatch, execution-boundary mismatch, and policy hash mismatch.
- [ ] Run the targeted tests and verify they fail for missing behavior.
- [ ] Extend `DecisionReceipt`, verification, and `GovernedExecutor.execute`.
- [ ] Re-run targeted tests and verify they pass.

## Task 3: Adapter normalization tests

- [ ] Add tests for MCP-style, OpenAI Responses-style, LangChain-style, generic JSON, CI/CD, and workflow-step envelopes.
- [ ] Add a test proving unsupported envelopes fail closed.
- [ ] Implement `gove_zone.adapters` with explicit type dispatch and no external dependencies.
- [ ] Re-run adapter tests and verify they pass.

## Task 4: Proof pack tests

- [ ] Add a test that `gove-zone proofpack --output <tmp>` writes `manifest.json`, `receipts/`, `audit.jsonl`, `verification.json`, `conformance-results.json`, and `limitations.md`.
- [ ] Add assertions that the proof pack includes allowed, denied, missing-receipt-blocked, and tampered-receipt-blocked evidence.
- [ ] Implement proofpack generation through the CLI.
- [ ] Re-run proofpack tests and verify they pass.

## Task 5: Documentation and quality gate

- [ ] Update root README and package README so advertised commands match the CLI.
- [ ] Update Decision Receipt, governed execution, operations, security, and architecture docs only where behavior changed.
- [ ] Add `LICENSE` if the root still lacks the Apache-2.0 text.
- [ ] Run `uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q` if `uv` is available.
- [ ] Run `python3 -m pytest packages/gove-zone/tests --import-mode=importlib -q` as fallback if pytest is available.
- [ ] Run direct smoke commands if dependency tooling is missing.
- [ ] Record an `autoresearch-goal` pass/fail verdict with literal evidence.
