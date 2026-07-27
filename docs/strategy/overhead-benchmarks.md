# Membrane Overhead Benchmarks — gove-zone

> Quantifies the membrane's latency tax — the "overhead is measured, but on one
> machine" entry in [`../research/limitations.md`](../research/limitations.md) §2.
>
> **Status: alpha measurements on a single local dev box, not a controlled
> environment.** These numbers characterize the order of magnitude of the
> membrane's latency tax; they are not a performance certification, an SLA,
> or a claim about your hardware. All figures below were produced by the
> literal runs documented in this file (2026-07-03, working tree at commit
> `0bbadba`, branch `feat/governed-vulnclaw-pentest`).

## What was measured

Per-governed-call latency of the gove-zone membrane versus an ungoverned
direct invocation of the same tool function, via the micro-benchmark
`packages/gove-zone/benchmarks/overhead_receipt_gate.py` (added alongside the
pre-existing propagation benchmarks in the same directory).

Four arms, each timed per-call with `time.perf_counter()`:

| Arm | What one call does |
|---|---|
| `ungoverned_direct` | `tool_fn(**args)` — no governance at all |
| `kernel_dispatch` | `Kernel.dispatch`: policy evaluation (fail-closed), audit-chain append (fsync'd JSONL), tool execution, kernel `Receipt` construction |
| `receipt_gate_unsigned` | Full split membrane: policy decision → audit append → `DecisionReceipt.from_record` (unsigned) → `GovernedExecutor.execute` receipt validation (`require_signature=False`) → tool execution |
| `receipt_gate_signed_ed25519` | Same as above, but the receipt is Ed25519-signed at issuance and cryptographically verified at the gate (`require_signature=True`) |

Fixed conditions:

- Tool body is a near-zero in-memory function (no I/O), so the measured cost
  is the membrane itself, not the tool.
- Policy is a realistic `BoundaryPolicy` (3 forbidden keywords + 1 regex,
  scanned over canonical-JSON args). A sanity pre-check asserts the policy
  actually denies a forbidden call before any timing starts.
- Tool args: 345 bytes of JSON.
- 2,000 timed iterations per arm after 200 warmup iterations.
- p50/p95/p99 via `statistics.quantiles(n=100, method="inclusive")`.

## Machine

- AMD Ryzen 7 7800X3D (8 cores / 16 threads), Fedora Linux, kernel
  7.0.13-200.fc44.x86_64, Python 3.13.11.
- Two storage configurations for the audit chain (every governed call fsyncs
  one JSONL line): **tmpfs** (`/tmp`, RAM-backed) and **NVMe btrfs**
  (`/var/tmp`).

## Exact commands

```bash
# From the monorepo root:
uv run --package gove-zone python packages/gove-zone/benchmarks/overhead_receipt_gate.py \
  --iterations 2000 --warmup 200                       # audit chain on tmpfs (default temp dir)

uv run --package gove-zone python packages/gove-zone/benchmarks/overhead_receipt_gate.py \
  --iterations 2000 --warmup 200 --audit-dir /var/tmp/gove-zone-overhead-XXXX   # NVMe btrfs

# Pre-existing propagation gate (supplementary, see below):
PYTHONPATH=packages/gove-zone uv run --package gove-zone python -c \
  "from benchmarks.test_propagation_overhead import measure_gate; import json; print(json.dumps(measure_gate().to_dict(), indent=2))"
```

## Results — audit chain on tmpfs (RAM-backed)

Membrane compute cost with durable-write cost effectively removed.
Per-call latency, milliseconds (2,000 iterations/arm):

| Arm | mean | p50 | p95 | p99 |
|---|---|---|---|---|
| `ungoverned_direct` | 0.0002 | 0.0002 | 0.0002 | 0.0002 |
| `kernel_dispatch` | 0.0726 | 0.0709 | 0.0801 | 0.1056 |
| `receipt_gate_unsigned` | 0.0962 | 0.0930 | 0.1130 | 0.1422 |
| `receipt_gate_signed_ed25519` | 0.2115 | 0.2080 | 0.2268 | 0.2804 |

Overhead vs ungoverned (ms):

| Arm | p50 | p95 | p99 |
|---|---|---|---|
| `kernel_dispatch` | +0.0707 | +0.0799 | +0.1054 |
| `receipt_gate_unsigned` | +0.0929 | +0.1128 | +0.1420 |
| `receipt_gate_signed_ed25519` | +0.2078 | +0.2266 | +0.2802 |

Signed vs unsigned receipt gate (Ed25519 sign at issuance + verify at gate):
**+0.115 ms p50 / +0.138 ms p99** on this machine.

## Results — audit chain on NVMe (btrfs)

Same benchmark with the fsync'd audit JSONL on real disk. Per-call latency,
milliseconds (2,000 iterations/arm):

| Arm | mean | p50 | p95 | p99 |
|---|---|---|---|---|
| `ungoverned_direct` | 0.0002 | 0.0002 | 0.0002 | 0.0002 |
| `kernel_dispatch` | 5.1977 | 5.4082 | 5.7424 | 8.5925 |
| `receipt_gate_unsigned` | 5.2561 | 5.4879 | 5.8177 | 8.7493 |
| `receipt_gate_signed_ed25519` | 5.4576 | 5.6185 | 5.9469 | 8.8077 |

## Reading the numbers

1. **The membrane's compute cost is sub-millisecond.** Policy decision +
   audit hashing + receipt issuance + gate validation together cost roughly
   0.07–0.21 ms per call at p50 on this box (tmpfs run), depending on whether
   receipts are signed.
2. **Durable audit persistence dominates when it hits real disk.** With the
   audit chain fsync'ing to NVMe btrfs, one governed call costs ~5.4–5.6 ms
   at p50 — ~98% of which is the fsync, not governance logic. Deployments
   that need lower latency can place the audit chain on faster/durable-enough
   media or batch at a different layer; that is an operational trade the
   integrator owns.
3. **Signing is cheap relative to fsync.** Ed25519 issuance + verification
   adds ~0.1–0.2 ms per call; in the disk-backed run it is noise against the
   fsync.
4. **Scale illustration (arithmetic, not a measurement):** for a tool call
   whose own work takes 100 ms (a typical network/LLM-backed tool), +0.21 ms
   of signed-membrane compute is ~0.2% added latency; +5.6 ms with
   disk-fsync'd auditing is ~5.6%.

## Supplementary: pre-existing propagation gate

`benchmarks/test_propagation_overhead.py` measures something different — the
*relative* cost of signed delegation-lineage authorization vs a JWT-style
capability-token baseline across a 3-agent chain (both arms fully governed;
50 KiB payload, concurrency 10, simulated 2 ms tool work per hop). Literal
output from this run:

```json
{
  "mean_latency_overhead_pct": 11.008,
  "p95_latency_overhead_pct": 15.111,
  "token_consumption_overhead_pct": 0.571,
  "heap_growth_mb": 1.701,
  "timeout_fail_closed_ms": 451.279,
  "propagation_mean_ms": 111.329,
  "propagation_p95_ms": 130.059,
  "token_baseline_mean_ms": 100.289,
  "token_baseline_p95_ms": 112.985,
  "concurrency": 10,
  "payload_kb": 50
}
```

Those percentages compare two governed authorization strategies against each
other, not governed vs ungoverned — do not quote them as "membrane overhead."
The `timeout_fail_closed_ms` figure (451 ms against a 450 ms policy watchdog)
shows a hung policy fail-closes on schedule.

## Honest caveats — what these numbers do NOT claim

- **Not a controlled environment.** One desktop, one OS, one Python version,
  background load not isolated, no CPU pinning, no frequency locking. Expect
  different absolute numbers on your hardware; the *shape* (sub-ms compute,
  fsync-dominated durability) is the finding.
- **Worst-case relative framing.** The tool body is near-zero, so any
  percentage overhead vs the 0.0002 ms baseline is astronomically large and
  meaningless. Quote the absolute per-call milliseconds, never a % against a
  no-op.
- **In-process kernel only.** No network hop, no out-of-process policy
  service, no remote KMS signing. A remote signer or policy service would add
  its round-trip on top.
- **Single-threaded latency, not throughput.** No claim about sustained
  receipts/second under concurrency (the audit store serializes appends under
  a file lock; contention was not measured here).
- **No claim of production readiness, certification, or compliance
  approval.** gove-zone is alpha (`0.1.0.dev0`). These are development
  measurements published to quantify the integration-tax assumption, per
  `docs/CLAIMS.md` discipline: every number above comes from a command listed
  in this file, run on 2026-07-03.

## Reproduce

```bash
uv run --package gove-zone python packages/gove-zone/benchmarks/overhead_receipt_gate.py --help
```

The benchmark self-checks before timing: governed and ungoverned arms must
produce identical results, and the boundary policy must actually deny a
forbidden call — if either fails, no numbers are emitted.
