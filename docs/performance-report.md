# gove-zone Runtime Performance Report

**Date:** 2026-07-07 · **Package:** `packages/gove-zone` (0.1.0a1) · **Benchmark:** [`governed_actions_bench.py`](../packages/gove-zone/benchmarks/governed_actions_bench.py) (run via [`benchmarks/run_gove_zone.sh`](../benchmarks/run_gove_zone.sh))

This report measures the four gove-zone runtime hot paths — receipt validation,
policy evaluation, audit write, and replay verification — at 100 / 1,000 /
100,000 governed actions, before and after an optimization pass covering
hashing, storage, concurrency, and caching. All numbers are from a single
developer workstation (Linux 7.0.13, Fedora 44, Python 3.13.11, x86-64, NVMe
with btrfs `fsync` ≈ 5 ms) and are **indicative, not a controlled environment**.

## Executive summary

| Hot path | Before | After | Change |
|---|---|---|---|
| Replay verification | 44.6 events/s at 10k events (O(n²): 3,372/s at 100 → 432/s at 1k); **100k events extrapolate to ~6 hours** | **~23,900 events/s, flat across scales; 100k events verify in 4.2 s** | ~535× at 10k-event shape; unblocks 100k-scale replay |
| Audit write (bulk) | 192–199 events/s (per-event fsync only path) | **101,206 events/s** via new `append_many` batch API (100k batch) | ~527× for bulk ingest; per-event `append` unchanged by design |
| Concurrent dispatch | n/a (arm added in this pass) | ~190 actions/s with 8 threads vs ~96/s single-thread | ~2× under contention |
| Policy evaluation | ~11–14 µs | ~12 µs | unchanged (within noise) |
| Receipt validation | ~11 µs unsigned / ~93 µs Ed25519-signed | ~11 µs / ~90 µs | unchanged (within noise) |
| End-to-end dispatch | ~10.3–10.6 ms | ~10.3–10.6 ms | unchanged — fsync-bound (see analysis) |

The dominant cost of a governed action on this machine is **durable storage,
not governance logic**: one fsync'd audit append (~5.2 ms) plus one fsync'd
side-store append (~5.1 ms) account for >99% of end-to-end dispatch latency.
All CPU-side governance work (policy scan, hashing, receipt checks) totals
~50–100 µs per action.

Every optimization is behavior-preserving: fail-closed semantics, chain rules,
and receipt validation checks are untouched. Full gate after the pass:
**755 passed / 0 failed / 1 skipped** (`packages/gove-zone/tests` +
`packages/gove-zone/benchmarks`, dev+crypto extras).

## Methodology

- Suite: `packages/gove-zone/benchmarks/governed_actions_bench.py`, new in this
  pass, alongside the existing per-call
  [`overhead_receipt_gate.py`](../packages/gove-zone/benchmarks/overhead_receipt_gate.py).
- Scales: 100 / 1,000 / 100,000 governed actions per arm (baseline also ran
  10,000 to characterize the quadratic replay curve; baseline 100,000 was not
  run because its replay arm extrapolates to ~6 hours).
- Tool body is a near-zero in-memory function, so the membrane dominates; args
  vary per action so every audit event is distinct.
- Audit/side-store files on a real disk (`--audit-dir` under the repo), **not**
  tmpfs — on tmpfs, fsync is nearly free and audit numbers are ~26× faster and
  misleading.
- Each arm self-checks: the boundary policy must deny a forbidden call, a
  tampered receipt must fail validation, and `replay_bundle` must report
  `valid: true` with all events matched (asserted at every scale, including
  100,005/100,005 events matched at n=100k).
- Baseline = master @ `98f6f18`; optimized = this branch @ `47903fb`.
  Raw JSON: `.omc/bench/{baseline,optimized}.json` (local, not committed).

## Results

### Replay verification (`replay_bundle`: chain walk + side-store cross-check + policy re-derivation + byte equivalence)

| Events | Baseline | Optimized |
|---|---|---|
| 100 | 3,372 ev/s (0.031 s) | 18,809 ev/s (0.006 s) |
| 1,000 | 432 ev/s (2.33 s) | 23,716 ev/s (0.042 s) |
| 10,000 | 44.6 ev/s (224.2 s) | — (not re-run; bracketed by 1k/100k) |
| 100,000 | *not feasible (~6 h extrapolated)* | **23,934 ev/s (4.18 s)** |

Baseline throughput fell ~10× for every 10× more events — the signature of an
O(n²) algorithm. Optimized throughput is flat, i.e. O(n).

### Audit write

| Mode | 100 | 1,000 | 100,000 |
|---|---|---|---|
| Per-event fsync (`append`), baseline | 199/s (5.03 ms mean) | 195/s (5.14 ms) | — |
| Per-event fsync (`append`), optimized | 197/s (5.07 ms) | 182/s (5.49 ms) | 192/s (5.20 ms) |
| **Batched (`append_many`), optimized** | 17,335/s | 64,484/s | **101,206/s (9.9 µs/event)** |

Per-event latency is the fsync floor of this disk (~5 ms) and is deliberately
unchanged: each `append` remains individually durable before it returns. The
new `append_many` amortizes one lock acquisition and one fsync across the
batch; its trade-off is documented below.

### Receipt validation (`DecisionReceipt.verify`, full gate-shaped check set)

| Arm | Baseline mean | Optimized mean (n=100k) | Throughput |
|---|---|---|---|
| Unsigned | 11.6–13.8 µs | 11.0 µs (p99 16.6 µs) | ~91,000/s |
| Ed25519-signed | 93.0–94.4 µs | 89.9 µs (p99 131 µs) | ~11,100/s |

Validation is stateless and scale-independent. The signed arm is dominated by
the Ed25519 signature verification itself (~80 µs), which is irreducible
without changing the cryptography.

### Policy evaluation (`BoundaryPolicy`: 3 keywords + 1 regex over canonical args)

~12 µs mean / ~19–21 µs p99 at every scale, before and after (~85,000
evaluations/s). The hashing/caching changes shave redundant work here but the
effect is within run-to-run noise at this payload size.

### End-to-end dispatch and concurrency

| Arm | Baseline | Optimized |
|---|---|---|
| `Kernel.dispatch` (audit + raw-args side store, both fsync'd) | 10.3–10.6 ms (~95/s) | 10.3–10.6 ms (~97/s) |
| Concurrent dispatch, 8 threads, one shared chain | — | ~185–191/s at every scale |

Dispatch is two fsyncs deep, so CPU-side gains do not move it. Eight
concurrent workers roughly double throughput (fsyncs from different files
overlap; the audit chain's exclusive lock correctly serializes chain appends).
Writers needing more than ~190 durable actions/s per chain on comparable
hardware should shard chains per tenant/boundary or batch decision recording
through `append_many`.

## What was optimized

All in `packages/gove-zone/src/gove_zone/`, commit `47903fb`:

1. **Replay (algorithmic, the big win).** `replay_bundle` called
   `ReplaySideStore.get(event_id)` per event, and `get` rescans the whole
   side-store JSONL — O(n²) overall. It now builds a single-pass index
   (last-record-wins, matching `get` semantics). Additionally, the semantic
   check and the byte-equivalence check previously each ran `policy.evaluate`
   (2 evaluations/event); a shared re-derivation helper now runs it **once**
   and feeds both checks — also making the two checks consistent by
   construction.
2. **Storage.** `ChainHashAuditStore.append_many` (new, additive): one lock +
   one fsync per batch, identical chain rules. Trade-off: a crash before the
   batch fsync can lose up to the whole batch (vs. one event for `append`);
   what survives is always a valid chain prefix, and no event is readable
   before it is hash-linked. `ReplaySideStore(durable=False)` (opt-in,
   default unchanged) skips the side store's per-append fsync; the side store
   is non-authoritative by design, and a lost record degrades replay to the
   honest event-only fallback — `replay_bundle` still fail-closes (`valid:
   false`) rather than ever claiming a match it cannot re-derive.
3. **Storage (append fast path).** `append` re-read the chain tail from disk
   on every call. It now reuses the tail hash cached from this instance's own
   previous append when a `stat` size check (under the same exclusive lock)
   shows the file unchanged; any other observation falls back to the
   authoritative tail read. Cross-process interleaving is covered by tests.
4. **Hashing / caching.** `ToolCall` memoizes `argument_hash`, `state_hash`,
   and `decision_request_hash` (a single dispatch previously canonicalized and
   hashed the same args up to 3×); policies and the kernel's fail-closed DENY
   paths route through the cached hash. Caches are per-instance and never
   survive `with_args` (TRANSFORM re-hashes fresh).

## What was *not* changed, deliberately

- Per-event `append` keeps its fsync: an audit event is durable before the
  kernel proceeds. Batch durability is opt-in, never a silent default.
- No weakening of fail-closed behavior, receipt checks, `expected_actor`
  anchoring, chain rules, or DENY/ESCALATE handling. The benchmark itself
  asserts deny-on-forbidden, tamper-rejection, and full replay validity on
  every run.
- Ed25519 verification cost is accepted as the price of signed receipts.

## Verification

- `uv run --package gove-zone --extra dev --extra crypto python -m pytest packages/gove-zone/tests packages/gove-zone/benchmarks --import-mode=importlib -q` → **755 passed, 0 failed, 1 skipped** (junitxml-verified).
- New targeted tests: `tests/test_perf_optimizations.py` (17 tests: batch
  chain validity, cross-instance fast-path fallback for both `append` and
  `append_many`, memoization parity with un-memoized hashes, mid-flight
  mutation divergence in the EXEC_FAILURE record, fsync observed called /
  skipped for the side-store `durable` flag, replay verdicts incl. tamper and
  missing-record fail-closed) and `tests/test_benchmark_harness_smoke.py`
  (harness smoke test, collected by the standard `pytest tests/` gate).
- Adversarial branch review (4 dimensions × 3-perspective verification, 31
  agents): 8 confirmed findings, all addressed or explicitly accepted — the
  `replay_policy_error` mismatch label is restored and pinned by test; the
  kernel's post-execution failure record recomputes the argument hash fresh so
  memoization cannot mask a mid-flight args mutation in the audit trail;
  `append_many` remains intentionally opt-in with no runtime caller.
- Root docs suite: 18 passed. Ruff lint + format clean on `src`, `tests`,
  `benchmarks`.

## Caveats

- Single dev machine; absolute numbers will differ elsewhere. The *shapes*
  (fsync-bound writes, O(n) replay, scale-flat validation) are the durable
  findings.
- fsync cost is filesystem/hardware dependent (~5 ms here on btrfs; tmpfs runs
  are ~26× faster on write paths and should not be quoted).
- The tool body is a no-op, so relative overhead percentages against it are a
  worst case; quote absolute per-action overhead instead.
- `BoundaryPolicy` here is small (4 rules); large rule sets scale policy
  evaluation roughly linearly with rule count and payload size.

## Reproduce

```bash
./benchmarks/run_gove_zone.sh --scales 100 1000 100000 \
  --audit-dir /path/on/real/disk --json results.json
```
