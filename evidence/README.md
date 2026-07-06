# evidence/ — governed-loop-v2 runtime state

This directory holds the loop's on-disk state contract. Everything here except this
README, `.gitignore`, and `state.seed.json` is **runtime-only** and git-ignored: the
loop creates it, a stranger verifies it, and it is not committed.

## Files

| File | Committed? | Written by | Meaning |
|---|---|---|---|
| `state.seed.json` | yes | you | Template copied to `state.json` at loop start. |
| `state.json` | no | Executor | Live loop position; refreshed every cycle. Resumable from disk alone. |
| `ledger.jsonl` | no | pretool-guard hook | Append-only, hash-chained decision records. |
| `phase-N.json` | no | Executor (after observer recompute) | Signed exit evidence for phase N. |
| `loop-active` | no | operator | Presence = loop enforcement ON. First line = post-edit verify command. |
| `escalation.md` | no | Executor | Decision-shaped human ask on STALL. |
| `blocks.md` | no | Executor | Specific unblock requests for BLOCKED criteria. |
| `final-report.md` | no | Executor | Written on DONE. |

## phase-N.json schema (what the Stop gate validates)

```json
{
  "phase": 1,
  "exit_criteria": ["<criterion id>", "..."],
  "exit_criteria_met": true,
  "validator_signoff": true,
  "test_results": { "passed": 4, "failed": 0 },
  "artifacts": ["<path>", "..."],
  "ledger_head_hash": "<sha256>",
  "timestamp": "<iso8601>"
}
```

The Stop gate (`.claude/hooks/loop-stop-gate.sh`) blocks turn-end unless
`exit_criteria_met == true AND validator_signoff == true AND test_results.failed == 0`.

## Dormancy

All four loop hooks are inert unless `evidence/loop-active` exists. Ordinary sessions
in this repo run untouched. See `.claude/prompts/loop-v2.md` §ACTIVATION.
