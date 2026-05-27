# AGENTS.md — acgs_governance_eval_mvp/governance/audit

## Purpose

Append-only audit stores for governance decisions. Two interchangeable
backends share the same `append` / `last_hash` / `iter_events` / `query` /
`verify_chain` interface so production code can run against a disk-backed
hash-chain JSONL store and tests can swap in the in-memory variant without
changing call sites. Both backends produce byte-identical `event_hash` values
for identical inputs, so a chain assembled in memory is verifiable on disk and
vice-versa.

## Key Files

- `__init__.py` — Public exports: `InMemoryAuditStore`, `ChainHashAuditStore`
- `jsonl_chain.py` — Disk-backed JSONL with `fcntl` exclusive lock around the
  read-then-write so concurrent appenders can't fork the chain at a shared
  `previous_hash`; canonical event payload hashed via `sha256_json`
- `in_memory.py` — Thread-safe list-backed mirror with identical semantics;
  intended for unit tests that should not touch the filesystem

## Workflow / Commands

```bash
# Run audit-store tests
pytest acgs_governance_eval_mvp/tests -k audit -q

# Replay a single event against the current policy bundle
python -m governance.cli.replay_event <event_id> \
  --audit-path .acgs/audit.jsonl

# Verify the on-disk chain integrity
python -c "from governance.audit import ChainHashAuditStore; \
  s=ChainHashAuditStore('.acgs/audit.jsonl'); print(s.verify_chain())"
```

## Gotchas / Conventions

- `GENESIS_HASH = '0' * 64` is the sentinel `previous_hash` for the first event
  in any chain. Both backends export it; do not redefine it in callers.
- Event payloads are canonicalised before hashing: `event_hash` covers the
  canonical JSON form minus the `event_hash` field itself. Any new field on a
  decision record must round-trip through `sha256_json` cleanly (sorted keys,
  no `NaN`/`Infinity`, UTF-8 strings) or chain verification will fail.
- The disk store's `fcntl.flock` is POSIX-only. On platforms without `fcntl`
  (Windows native CI), use `InMemoryAuditStore` instead — there is no
  cross-platform locking fallback by design.
- Never edit historical entries. Chain verification compares each event's
  `previous_hash` to the prior event's `event_hash`; in-place edits will
  surface as a verify_chain failure, not a silent corruption.
