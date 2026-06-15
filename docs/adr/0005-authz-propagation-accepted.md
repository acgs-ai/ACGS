# ADR 0005: Accept Authz Propagation for Phase 1 Week 2

## Status

Accepted.

## Context

`ROADMAP.md` requires an independent Week-2 benchmark gate before building the
quarter around the arXiv 2605.05440 authorization-propagation model. The gate
compares propagation overhead against a JWT-style token baseline using a mock
three-agent chain: Orchestrator -> Planner -> Executor, 50KB structured payloads,
and 10 simultaneous in-process chains. Each hop invokes `Kernel.dispatch` on a
registered tool; no kernel public API changed for this gate.

The agy critique in `.omc/artifacts/ask/agy-critique.md` treated the preprint as
single-author and unreplicated, warned against accepting the paper's empirical
claims without replication, and predicted a Codex failure mode: implementing only
happy-path propagation while failing open on policy, audit, or timeout errors.
It set sharper pass/fail criteria for latency, token usage, heap growth, and
network-timeout fail-closed behavior.

## Decision

Accept authorization propagation as the Phase 2 direction for this roadmap. The
benchmark artifact is committed at `.benchmarks/propagation-gate-week2.json` with
verdict `PASS`, regenerable with
`cd packages/gove-zone && uv run --extra dev python -m benchmarks.emit_gate_artifact`.
The latency-overhead metric is noise-dominated — both benchmark arms perform
identical bounded work, so a single run swings widely (observed roughly
-20%..+17% on a loaded machine) and can spuriously trip the threshold. The
committed artifact therefore records the **median of 5 runs**, and the figures
below are descriptive (not re-pinned, to avoid the ADR drifting from the
artifact again).

Measured values (authoritative record: the committed artifact):

| Metric | Threshold | Measured |
|---|---:|---|
| Mean latency overhead | <= 15% | within threshold (timing-dependent; see artifact / ADR-0006) |
| p95 latency overhead | <= 25% | within threshold (timing-dependent; see artifact / ADR-0006) |
| Token-consumption overhead | <= 10% | 0.571% (deterministic) |
| Heap growth | <= 5MB | ~1.6MB (deterministic) |
| Timeout fail-closed latency | <= 500ms | ~451ms (deterministic) |

Additional benchmark context: absolute per-chain latencies are
environment-/load-dependent (~12ms on a quiet machine, 100ms+ under contention)
— see the committed artifact for the current run. The earlier ADR revision quoted
identical mean/p95 latencies; that was the duplication bug corrected in ADR-0006.
Deterministic context that reproduces:

| Metric | Measured |
|---|---:|
| Propagation token units | 427710 |
| Token baseline token units | 425280 |

## Consequences

Phase 2 can proceed with the propagation-backed R5/R6 trace-receipt work. The
receipt-chain integrity caveat remains active: local `fcntl.flock` serialization
does not prove safety on distributed filesystems, so Phase 2 must still document
local-SSD or central-lock-broker constraints before claiming distributed audit
integrity.

The token-based fallback remains a contingency, but this ADR does not activate
the three-week token alternative because the gate passed.

Status: methodology correction recorded in ADR-0006.
