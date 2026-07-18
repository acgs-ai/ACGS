# Changelog

All notable changes to `gove-zone` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-18

First release. Public API freeze for the `0.1.x` line.

### Added

- **Kernel loop** (`gove_zone.kernel.Kernel`): every registered tool call is
  intercepted before execution — policy evaluation → audit append → execute or
  deny → receipt. No code path executes a tool before the audit append commits.
- **Fail-closed guarantees**: any exception in policy evaluation or audit
  append denies the action (`DeniedError` / `AuditError`). After an ALLOW,
  a tool-execution failure re-raises the original exception and a failure
  record is appended to the chain on a best-effort basis — if that append
  itself fails, the record is dropped and the original exception still
  propagates unmasked. Exercised by `tests/test_fail_closed.py` and
  `tests/test_fail_closed_gaps.py`.
- **Policy watchdog** (`Kernel(policy_timeout=...)`): optional deadline for
  `policy.evaluate`; on timeout the kernel synthesizes a fail-closed DENY
  and a late result from the orphaned evaluation is discarded. Default
  `None` preserves the direct synchronous path.
- **Decision model** (`gove_zone.decision`): `Decision` enum
  (ALLOW / DENY / TRANSFORM / ESCALATE), frozen `DecisionRecord`,
  `canonical_json` / `sha256_json` canonical hashing.
- **Tamper-evident audit chain** (`gove_zone.audit.ChainHashAuditStore`):
  append-only JSONL, SHA-256 hash chain from `GENESIS_HASH`, process-safe via
  `fcntl.flock`, structured `verify_chain()`, strict `iter_events()` that
  raises `AuditChainError` on malformed lines.
- **Policies** (`gove_zone.policy`): `Policy` ABC, `BoundaryPolicy`
  (keyword / pattern matching over canonical JSON of arguments),
  `CompositePolicy` (first non-allow wins), `AllowAllPolicy`, `DenyAllPolicy`.
- **Receipts + replay** (`gove_zone.receipt`, `gove_zone.replay`): receipts
  bind decision records to result digests; `replay_event` / `replay_call`
  re-evaluate recorded calls against a policy and surface divergence.
- **Frontend contract** (`gove_zone.frontend_contract`): maps receipts and
  records to console `GovernedAction` payloads.
- **CLI** (`gove-zone replay`): verify a governed action against an audit
  JSONL chain; JSON evidence on stdout, exit 1 on failed verification.
- **Demo console API** (`gove-zone-api`): stdlib-only read-only HTTP server
  backing the governance console demo (`/api/v1/*`).
- **Typing**: `py.typed` marker; `mypy --strict` clean; zero runtime
  dependencies (pydantic optional via the `schema` extra).

### Platform

- POSIX only (audit locking uses `fcntl`). Windows support is deferred.

[Unreleased]: https://github.com/dislovelhl/govern-zone/tree/master/packages/gove-zone
[0.1.0]: https://github.com/dislovelhl/govern-zone/tree/master/packages/gove-zone
