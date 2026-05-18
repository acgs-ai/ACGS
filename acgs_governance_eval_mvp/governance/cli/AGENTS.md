# AGENTS.md — acgs_governance_eval_mvp/governance/cli

## Purpose

Small operator-facing CLIs for inspecting the hash-chained audit store and
replaying historical decisions against the current policy bundle. These are
thin wrappers around `governance.audit.jsonl_chain.ChainHashAuditStore` and
`governance.replay.replay_event` — they exist so an on-call custodian can
answer "what decided this?" and "would today's policies still allow it?"
without writing Python.

## Key Files

- `__init__.py` — Marker module; empty by design so each script stays
  independently invokable via `python -m governance.cli.<script>`
- `replay_event.py` — `python -m governance.cli.replay_event <event_id>` —
  locates the event by ID, loads `governance/roles.json` and the
  `governance/policies/<bundle>` directory, then prints the replay result
- `sample_audit_query.py` — Demonstration query: filter by `--rule-id`,
  `--gate`, `--allow` (true/false), with `--limit` cap; prints matching events
  as indented JSON

## Workflow / Commands

```bash
# Replay one event with explicit paths
python -m governance.cli.replay_event evt-12345 \
  --audit-path .acgs/audit.jsonl \
  --roles-path governance/roles.json \
  --policy-dir governance/policies/2026-05

# Query the chain for denied decisions on a specific rule
python -m governance.cli.sample_audit_query \
  --audit-path .acgs/audit.jsonl \
  --rule-id matter.disclosure \
  --allow false \
  --limit 50
```

## Gotchas / Conventions

- Defaults assume the repo layout: `--audit-path .acgs/audit.jsonl`,
  `--roles-path governance/roles.json`, `--policy-dir governance/policies/2026-05`.
  Override all three when running against a tenant snapshot.
- `replay_event` exits non-zero with `event not found: <id>` if the ID is
  missing; this is the canonical "negative" result for tooling that pipes
  multiple IDs.
- Both scripts emit JSON to stdout with `ensure_ascii=False`. Pipe through
  `jq` for filtering rather than parsing with regex.
- Replays use the **current** policy bundle by default — that is the point.
  To replay against the bundle that was in force at decision time, point
  `--policy-dir` at the archived bundle for that period.
- Treat these CLIs as read-only: neither writes back to the audit store. Any
  decision change observed during replay should be filed as a finding, not
  appended.
