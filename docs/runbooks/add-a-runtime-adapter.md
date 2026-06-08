# Runbook v0: Add a runtime adapter (tool-call shape)

> **Scope:** how to teach ACGS to recognize one more framework's tool-call
> payload *shape* — the CrewAI / AutoGen / LlamaIndex "good first issues" in
> [`CONTRIBUTING.md`](../../CONTRIBUTING.md). This is a **parser-shape**
> contribution. Wiring a real framework's *execution path* to call the gate is
> a larger, separate effort — see §"Parser shape vs real host adapter".
>
> **Last updated:** 2026-06-07

---

## Purpose

ACGS does not gate by trusting an agent framework. It gates at the executor
boundary: a normalized tool call is evaluated against policy, and a side effect
runs only under a valid Decision Receipt. To support a new framework you make
its raw tool-call payload *recognizable* to the normalizer — you do **not** give
the framework any new authority.

> **Core invariant: No valid Decision Receipt, no side effect.** The gate (the
> executor / CLI), **not** the adapter, enforces this. An adapter only
> translates payload shape. If your parser is never reached by the gate path
> (below), it is dead code — see the handler-wiring rule in
> `~/.claude/rules/review-handler-wiring.md`.

---

## Mental model: there is no adapter registry

A common wrong assumption is that frameworks plug in through a registry. They do
not. Normalization lives in hardcoded branches inside one module:

`packages/gove-zone/src/gove_zone/integration.py`

| Concern | Symbol |
|---|---|
| Single-call shape parsing | `_tool_name_and_input_from_payload` |
| Batch / multi-call expansion | the batch-expansion branches near `_malformed_batch_payload` |
| Single-call public entry | `tool_call_from_hook_payload` |
| Multi-call public entry | `tool_calls_from_hook_payload` |
| Gate evaluation over normalized calls | `emit_receipts_for_hook` / `emit_receipt_for_hook` |

Adding a framework means **extending the parse/expand branches in
`_tool_name_and_input_from_payload` (and the batch expansion path) plus their
tests** — not registering a plugin.

### The inbound path your change sits on

```
framework payload (new shape)
  → gove-zone gate (CLI)            packages/gove-zone/src/gove_zone/cli.py
  → _gate → emit_receipts_for_hook  integration.py
  → tool_calls_from_hook_payload    integration.py
  → _tool_name_and_input_from_payload   ← YOU EXTEND HERE
  → policy evaluation → Decision Receipt (allow / deny / escalate)
  → side effect runs only on a valid receipt
```

Your parser branch is one node on this path. The test that proves it works must
exercise the path, not just the branch (see §"The tests you must add").

---

## Steps

1. **Find the shape.** Capture a real tool-call payload from the target
   framework. Identify where the tool name and the argument dict live in it.
2. **Extend the normalizer.** Add a branch to `_tool_name_and_input_from_payload`
   that returns `(tool_name, args_dict)` for the new shape. Mirror the existing
   branches; do not add a new public function unless the shape needs its own
   entry point.
3. **Handle batches fail-closed.** If the framework can send multiple tool calls
   in one payload, extend the batch-expansion path. A **recognized but
   unparseable** child must become a `runtime.malformed_batch` call
   (`_MALFORMED_BATCH_TOOL_NAME` in `integration.py`), which the gate denies —
   never silently drop it and never let it fall through to "allow". See §"The
   fail-closed rule".
4. **Add the tests** (§ below).
5. **Run the package-local gate** and capture output.

---

## The fail-closed rule

`integration.py` already encodes the rule: when a batch shape is *recognized*
but a child cannot be parsed, it is turned into a synthetic
`runtime.malformed_batch` call (`_malformed_batch_payload`,
`_MALFORMED_BATCH_TOOL_NAME = "runtime.malformed_batch"`) that the decision path
treats as a deny. Your new shape must follow the same rule:

- Unknown / unrecognized shape → not your branch's concern (left unparsed).
- Recognized batch with a bad child → emit `runtime.malformed_batch` (fail
  closed), do **not** drop the child or return a partial success.

Never add a branch that returns "allow"-shaped output on ambiguous input.

---

## The tests you must add

A parser-only unit test is **necessary but not sufficient.** It proves the
branch parses; it does not prove the gate reaches it. Add both:

1. **A CLI-gate enforcement test** — drive a payload of the new shape through the
   `gove-zone gate` path and assert the decision (e.g. a policy-blocked action of
   the new shape returns a blocking / non-zero decision). Mirror the existing
   gate tests in `packages/gove-zone/tests/test_setup.py` (the
   `..._gate_..._tool_calls_shape` and malformed-batch cases).
2. **A malformed-batch negative test** — a recognized-but-unparseable child of
   the new shape fails closed as `runtime.malformed_batch`. Mirror the
   malformed-batch cases in `test_setup.py`.

Optionally also add a direct parser unit test alongside
`packages/gove-zone/tests/test_integration_hook.py`, but it does not replace the
two above.

---

## Parser shape vs real host adapter

This runbook covers making a payload *shape* recognizable. That is the advertised
good-first-issue. It is **not** the same as integrating a live framework so that
its real execution actually stops at the gate before a side effect fires.

A real host adapter additionally requires **proof that the framework's execution
path calls the gate before the raw tool runs.** `integration.py` provides no host
registration, so a parser with no inbound caller is dead code. If you are wiring
a live framework, your change must include that call-site wiring and an
integration test that exercises it — treat it as a separate, larger contribution
and open a discussion issue first.

---

## Run the gate

```bash
uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q
```

Expected: your new gate test and malformed-batch test pass, and no existing test
regresses.

---

## Checklist

- [ ] New branch in `_tool_name_and_input_from_payload` (no registry invented).
- [ ] Batch path handles a bad child as `runtime.malformed_batch` (fail closed).
- [ ] CLI-gate enforcement test for the new shape (not parser-only).
- [ ] Malformed-batch negative test for the new shape.
- [ ] If wiring a *real* framework: call-site proof the gate runs before the side
      effect, plus an integration test.
- [ ] `uv run --package gove-zone python -m pytest packages/gove-zone/tests` passes.
- [ ] No new capability overclaim; wording traces to code (see
      [`docs/CLAIMS.md`](../CLAIMS.md)).
