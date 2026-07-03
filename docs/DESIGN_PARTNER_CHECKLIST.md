# Design partner checklist

> **Core invariant: No valid Decision Receipt, no side effect.**

A sequenced, end-to-end checklist for a design-partner engagement: from kickoff
to a signed-off, receipt-gated integration with audit evidence off-host. Work
top to bottom — each step points at an existing runbook, example, command, or
test you can run or read. Treat a step as done only when its linked artifact runs
or is reviewed.

## 0. Kickoff

- [ ] Read `docs/START_HERE.md` (10-minute tour) and run the canonical proof in
      `docs/QUICKSTART.md` (single install block + single proof block). Confirm
      the receipt-gated demo prints **`All invariants held`**.
- [ ] Read `docs/SECURITY_MODEL.md` for the threat model and the explicit
      boundary (what gove-zone enforces vs. what you must supply: auth, sandbox,
      key custody).
- [ ] Read `docs/CLAIMS.md` so the team shares a claim-safe vocabulary from day
      one (e.g. "signing is opt-in; unsigned by default").

## 1. Pick one wedge side effect

- [ ] Choose **one** high-risk side effect to gate first (a filesystem write, an
      API call, a deploy step, an MCP `tools/call`). Narrow beats broad.
- [ ] Confirm the wedge fits the placement guidance in
      `docs/INTEGRATION_GUIDE.md` (§"Put the gate before") — the gate sits at the
      executor, immediately before the side effect, never only in a planner.

## 2. Wire the gate at the executor

- [ ] Copy `docs/INTEGRATION_GUIDE.md` §"Your first receipt (self-contained,
      copy-paste)" and run it verbatim with
      `uv run --extra crypto --package gove-zone python <file>.py`. Confirm the
      allowed path executes and the missing-receipt path fails closed.
- [ ] Adapt the matching runnable example to your wedge:
      `examples/python_tool_gate/demo.py` (plain function),
      `examples/mcp_tool_gate/demo.py` (MCP), or
      `examples/agent_framework_gate/demo.py` (framework tool wrapper).
- [ ] If you need a new tool-call shape normalized, follow
      `docs/runbooks/add-a-runtime-adapter.md`; for a reviewed policy bundle,
      follow `docs/runbooks/add-a-policy-bundle.md`.

## 3. Add deny / missing / tampered CI tests

- [ ] Add a **gate-level** (not parser-only) test that a denied decision blocks
      the side effect — model it on
      `packages/gove-zone/tests/test_executor_guard.py`.
- [ ] Add a missing-receipt test (executor refuses with no receipt) — same file
      (`test_executor_refuses_no_receipt`).
- [ ] Add a tampered-receipt test — model it on
      `packages/gove-zone/tests/test_consumption_tamper.py` and
      `examples/tamper_demo/demo.py`.
- [ ] Wire the end-to-end thread into CI — model it on
      `packages/gove-zone/tests/test_end_to_end.py`. A unit test that calls the
      handler directly does not prove the gate is wired into the side-effect
      path.

## 4. Ship audit evidence off-host

- [ ] Generate a local proof pack and inspect the receipts + `audit.jsonl` +
      `verification.json` (commands in `docs/PROOF_PATH.md` §3 and
      `docs/QUICKSTART.md`).
- [ ] Wire the CI/deploy side effect to retain audit evidence — model it on
      `examples/ci_deploy_gate/demo.py`.
- [ ] Forward the append-only audit JSONL to off-host, tamper-evident storage
      (the local chain is hash-chained but not WORM — see `docs/SECURITY_MODEL.md`
      and the `audit-evidence` doc). Confirm a third party can replay-verify the
      chain offline.

## 5. Claims review vs. docs/CLAIMS.md

- [ ] Walk every public claim the partner intends to make against
      `docs/CLAIMS.md`. If a claim is not traceable to code, a test, a demo,
      receipt evidence, replay verification, or roadmap, downgrade it to the
      "Safe public wording" column.
- [ ] Confirm no claim asserts production/compliance certification, default
      signing, or cross-host receipt portability (all explicitly **not claimed**
      or roadmap).

## 6. Success-criteria sign-off

- [ ] Restate the engagement's success criteria in writing and confirm each is
      met by a runnable artifact (a passing CI test, demo output, or retained
      audit evidence) — not by assertion.
- [ ] Capture the literal output of the wedge's deny/missing/tampered tests and
      the receipt-gated demo (`All invariants held`) in the handoff.
- [ ] Joint sign-off: the partner agrees the gate enforces at the executor, the
      failure paths fail closed, the audit evidence is off-host, and the public
      claims match `docs/CLAIMS.md`.
