---
description: Run the headless claim-verification proof pack and interpret the JSON, proposing claim-safe wording downgrades for any failed claim (human-in-the-loop for doc edits).
allowed-tools: Bash(bash scripts/claim_verify_headless.sh*), Bash(scripts/claim_verify_headless.sh*), Read, Grep, Glob
---

# /claim-verify — structured claim verification

Verify that the govern-zone proof commands named in `AGENTS.md` still pass, then
map any failure back to the claim it supports in `docs/CLAIMS.md` and propose
**claim-safe** wording. This command never edits docs on its own — per
`.claude/rules/claim-safety.md`, doc wording changes go through the human loop.

## Step 1 — run the proof pack

```bash
bash scripts/claim_verify_headless.sh
```

This runs (pure bash + python3, no LLM, no network):

| claim name        | proof command |
|-------------------|---------------|
| `root-docs-smoke` | `uv run python -m pytest tests/docs --import-mode=importlib -q` |
| `gove-zone-smoke` | `uv run --package gove-zone gove-zone smoke --audit <tmp>/audit.jsonl` |
| `receipt-demo`    | `uv run --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py` |
| `tamper-demo`     | `uv run --package gove-zone python examples/tamper_demo/demo.py` |

It emits one JSON object to stdout:

```json
{"claims":[{"name":"...","command":"...","exit_code":0,"passed":true}],
 "all_passed":true,"timestamp":"...Z"}
```

The script exits `0` whenever it emitted valid JSON (even if some claims
failed) and `1` only on an internal error. Proof-command output goes to stderr;
parse stdout.

## Step 2 — interpret the JSON

- **`all_passed: true`** → report the timestamp and the passing claim list.
  State plainly: "all four local proof commands passed at `<timestamp>`."
  Do not upgrade wording beyond what the proofs show (still *local* proofs; no
  production/certification claims — see `claim-safety.md` "unsafe wording").

- **any `passed: false`** → for each failing claim:
  1. **Locate the affected wording.** Open `docs/CLAIMS.md` and find the claim
     row/section whose evidence is that proof command (grep for the command,
     the demo path, or the capability name — e.g. `tamper`, `receipt`, `smoke`).
  2. **Propose a claim-safe downgrade.** Because the proof no longer holds, the
     current wording over-claims. Draft replacement text that is honest about
     what is now unverified. Prefer the safe patterns from `claim-safety.md`:
     - "local receipt-gated kernel" / "local proof pack" / "tamper-evident
       JSONL audit chain" over "production-certified" / "guaranteed".
     - Add an explicit limitation: "proof command `<name>` currently failing
       (exit `<code>`) as of `<timestamp>`; claim unverified pending fix."
  3. **Do NOT edit `docs/CLAIMS.md` (or any doc) yourself.** Present the exact
     before/after wording diff and the failing evidence to the human, and ask
     for approval. Doc edits about receipts/policy/audit/signing are
     security-sensitive (`.claude/rules/security-sensitive-files.md`): the
     source/tests must be inspected before any wording change lands.

## Step 3 — report

Summarize: `all_passed`, per-claim exit codes, and (on failure) the proposed
claim-safe wording changes awaiting human approval. Never assert a numeric or
pass/fail result without the literal JSON in hand (`claim-safety.md`).
