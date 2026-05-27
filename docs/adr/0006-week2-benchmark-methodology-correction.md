# ADR 0006: Week 2 Benchmark Methodology Correction

## Status

Accepted. Supersedes ADR-0005 measurement methodology.

## Context

ADR-0005 accepted the Week-2 authorization-propagation gate with a PASS verdict,
but its benchmark timing method duplicated one aggregate wall-clock value across
all chains:

```python
latencies = [elapsed_total / CONCURRENCY] * CONCURRENCY
```

That per-chain-duplication bug made mean latency and p95 latency identical by
construction. The p95 threshold still passed, but the measurement did not
exercise a real latency distribution and should remain a historical record, not
the canonical benchmark method.

The corrected run still produced a Week-2 PASS verdict.
This correction is still an N=10 in-process Python benchmark. It validates the
local Week-2 gate against real per-chain timings, but it does not validate the
arXiv paper's distributed or multi-agent scaling claims, nor any p95
tail-latency claim at external scale.

## Decision

Per-chain timing via `ThreadPoolExecutor.map` of `_timed_run_one` is the
canonical method for the Week-2 propagation benchmark. Each chain measures its
own Orchestrator -> Planner -> Executor walk, and mean/p95 are computed from the
resulting per-chain distribution.

Measured values from the corrected run:

| Metric | Threshold | Measured |
|---|---:|---:|
| Mean latency overhead | <= 15% | 0.746% |
| p95 latency overhead | <= 25% | -9.269% |
| Token-consumption overhead | <= 10% | 0.571% |
| Heap growth | <= 5MB | 1.546MB |
| Timeout fail-closed latency | <= 500ms | 451.277ms |

Additional corrected benchmark context:

| Metric | Measured |
|---|---:|
| Propagation mean latency | 89.032ms |
| Token baseline mean latency | 88.372ms |
| Propagation p95 latency | 101.189ms |
| Token baseline p95 latency | 111.526ms |
| Propagation token units | 427710 |
| Token baseline token units | 425280 |

The Week-2 verdict is PASS under both the original duplicated-timing method and
the corrected per-chain method.

## Consequences

ADR-0005 remains the historical acceptance record, including the first-run
numbers and their degenerate p95 value.

Future benchmark gates must reference this ADR-0006 method and compute latency
statistics from per-chain timings, not duplicated aggregate wall-clock values.
