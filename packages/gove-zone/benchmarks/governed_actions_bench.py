"""Governed-actions scaling benchmark: the four runtime hot paths at N actions.

Measures, per scale (default 100 / 1,000 / 100,000 governed actions):

1. ``policy_evaluation``    — ``BoundaryPolicy.evaluate`` latency (pure CPU).
2. ``audit_write``          — ``ChainHashAuditStore.append`` latency (lock +
                              tail-read + fsync'd JSONL write per event), plus
                              a batched ``append_many`` arm when available.
3. ``receipt_validation``   — ``DecisionReceipt.verify`` latency, unsigned and
                              Ed25519-signed (signed arm skipped without the
                              ``crypto`` extra).
4. ``replay_verification``  — ``replay_bundle`` throughput over the full chain
                              (chain walk + side-store cross-check + policy
                              re-derivation + byte equivalence), in events/sec.

An ``end_to_end_dispatch`` arm (``Kernel.dispatch`` with a raw-args side-store)
is included for context: it is the sum a caller actually experiences.

The tool body is a near-zero in-memory function so the membrane dominates.
Arguments vary per action so every audit event is distinct, as in real use.

Run from the repo root::

    uv run --package gove-zone python packages/gove-zone/benchmarks/governed_actions_bench.py

Optional args: ``--scales 100 1000 100000`` ``--audit-dir PATH`` ``--json PATH``.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import platform
import statistics
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from gove_zone import (
    BoundaryPolicy,
    ChainHashAuditStore,
    DecisionReceipt,
    DeniedError,
    Kernel,
    Validator,
)
from gove_zone.errors import ReceiptValidationError, SigningError
from gove_zone.replay import replay_bundle
from gove_zone.replay_store import ReplaySideStore
from gove_zone.tool import ToolCall

TENANT_ID = "tenant-bench"
EXECUTION_BOUNDARY = "bench-local"
POLICY_BUNDLE_ID = "bench-bundle"
PROPOSER = "bench-agent"
VALIDATOR = Validator(validator_id="bench-governor", role="policy-engine")
AUTHORITY = "benchmark-grant"
TOOL_NAME = "write_report"
GOAL = "benchmark governed action scaling"

DEFAULT_SCALES = (100, 1_000, 100_000)


def tool_fn(path: str, content: str) -> dict[str, Any]:
    """Near-zero in-memory tool body (no I/O) so the membrane dominates."""
    return {"path": path, "bytes": len(content)}


def make_args(i: int) -> dict[str, Any]:
    """Distinct-per-action args so every audit event is unique (realistic)."""
    return {
        "path": f"/workspace/reports/item-{i}.md",
        "content": f"governed action payload {i} " * 8,
    }


def make_policy() -> BoundaryPolicy:
    """Realistic string-scan policy: keywords + regex over canonical args."""
    return BoundaryPolicy(
        forbidden_keywords=["~/.ssh", "/etc/shadow", "DROP TABLE"],
        forbidden_patterns=[r"rm\s+-rf\s+/"],
        rule_id="BENCH_BOUNDARY",
    )


@dataclasses.dataclass(frozen=True)
class ArmStats:
    name: str
    iterations: int
    mean_us: float
    p50_us: float
    p95_us: float
    p99_us: float
    total_s: float
    ops_per_s: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "iterations": self.iterations,
            "mean_us": round(self.mean_us, 2),
            "p50_us": round(self.p50_us, 2),
            "p95_us": round(self.p95_us, 2),
            "p99_us": round(self.p99_us, 2),
            "total_s": round(self.total_s, 4),
            "ops_per_s": round(self.ops_per_s, 1),
        }


def _percentile(values: list[float], pct: int) -> float:
    if len(values) < 2:
        return values[0] if values else 0.0
    return statistics.quantiles(values, n=100, method="inclusive")[pct - 1]


def _stats(name: str, latencies: list[float]) -> ArmStats:
    total = sum(latencies)
    return ArmStats(
        name=name,
        iterations=len(latencies),
        mean_us=statistics.fmean(latencies) * 1e6,
        p50_us=_percentile(latencies, 50) * 1e6,
        p95_us=_percentile(latencies, 95) * 1e6,
        p99_us=_percentile(latencies, 99) * 1e6,
        total_s=total,
        ops_per_s=(len(latencies) / total) if total > 0 else 0.0,
    )


def _time_loop(name: str, fn: Callable[[int], Any], n: int, *, warmup: int = 20) -> ArmStats:
    """Time fn(i) for i in range(n), after warmup calls that reuse i=0..warmup."""
    for i in range(warmup):
        fn(-1 - i)  # negative indices: warmup actions, distinct from measured ones
    latencies: list[float] = []
    for i in range(n):
        started = time.perf_counter()
        fn(i)
        latencies.append(time.perf_counter() - started)
    return _stats(name, latencies)


def bench_policy_evaluation(n: int) -> ArmStats:
    policy = make_policy()

    def one(i: int) -> None:
        call = ToolCall(name=TOOL_NAME, args=make_args(i), goal=GOAL, actor=PROPOSER)
        policy.evaluate(call)

    return _time_loop("policy_evaluation", one, n)


def bench_audit_write(n: int, audit_dir: Path, tag: str) -> tuple[ArmStats, ArmStats | None]:
    """Per-event fsync'd appends; plus one batched arm when append_many exists."""
    policy = make_policy()
    store = ChainHashAuditStore(audit_dir / f"audit-write-{tag}.jsonl")

    # Pre-build the records so only store.append is inside the timed window.
    records = []
    for i in range(n):
        call = ToolCall(name=TOOL_NAME, args=make_args(i), goal=GOAL, actor=PROPOSER)
        records.append(policy.evaluate(call))

    def one(i: int) -> None:
        store.append(records[i])

    # Warmup uses separate throwaway records on the same chain.
    warm_call = ToolCall(name=TOOL_NAME, args=make_args(-1), goal=GOAL, actor=PROPOSER)
    for _ in range(5):
        store.append(policy.evaluate(warm_call))
    per_event = _time_loop("audit_write_per_event_fsync", one, n, warmup=0)

    batched: ArmStats | None = None
    if hasattr(store, "append_many"):
        batch_store = ChainHashAuditStore(audit_dir / f"audit-write-batch-{tag}.jsonl")
        batch_records = []
        for i in range(n):
            call = ToolCall(name=TOOL_NAME, args=make_args(i), goal=GOAL, actor=PROPOSER)
            batch_records.append(policy.evaluate(call))
        started = time.perf_counter()
        batch_store.append_many(batch_records)
        elapsed = time.perf_counter() - started
        batched = ArmStats(
            name="audit_write_batched",
            iterations=n,
            mean_us=elapsed / n * 1e6,
            p50_us=elapsed / n * 1e6,
            p95_us=elapsed / n * 1e6,
            p99_us=elapsed / n * 1e6,
            total_s=elapsed,
            ops_per_s=n / elapsed if elapsed > 0 else 0.0,
        )
    return per_event, batched


def _mint_receipt(signer: Any | None, audit_dir: Path, tag: str) -> DecisionReceipt:
    policy = make_policy()
    store = ChainHashAuditStore(audit_dir / f"receipt-mint-{tag}.jsonl")
    call = ToolCall(name=TOOL_NAME, args=make_args(0), goal=GOAL, actor=PROPOSER)
    record = policy.evaluate(call)
    record = dataclasses.replace(record, actor=PROPOSER, goal=GOAL)
    payload = store.append(record)
    return DecisionReceipt.from_record(
        record,
        str(payload["event_hash"]),
        str(payload["previous_hash"]),
        TENANT_ID,
        EXECUTION_BOUNDARY,
        POLICY_BUNDLE_ID,
        policy.version,
        f"req-{tag}",
        validator=VALIDATOR,
        authority=AUTHORITY,
        signer=signer,
    )


def bench_receipt_validation(
    n: int, audit_dir: Path, tag: str
) -> tuple[ArmStats, ArmStats | None, str]:
    """Verify latency: unsigned arm always; Ed25519-signed arm when available.

    Uses the full gate-shaped verify (tenant, boundary, action, args, actor,
    audit anchor) — the same checks ``execute_with_receipt`` performs.
    """
    expected_args = make_args(0)

    unsigned = _mint_receipt(None, audit_dir, f"{tag}-unsigned")

    def verify_unsigned(_: int) -> None:
        unsigned.verify(
            expected_tenant_id=TENANT_ID,
            expected_execution_boundary=EXECUTION_BOUNDARY,
            expected_audit_hash=unsigned.audit_event_hash,
            expected_args=expected_args,
            expected_action=TOOL_NAME,
            expected_actor=PROPOSER,
            require_signature=False,
        )

    unsigned_stats = _time_loop("receipt_validation_unsigned", verify_unsigned, n)

    signed_stats: ArmStats | None = None
    skipped = ""
    try:
        from gove_zone import Ed25519Signer

        signer = Ed25519Signer.generate(key_id="bench-key")
        public = Ed25519Signer.from_public_bytes(signer.public_bytes(), key_id="bench-key")
        verifier = {"bench-key": public}
        signed = _mint_receipt(signer, audit_dir, f"{tag}-signed")

        def verify_signed(_: int) -> None:
            signed.verify(
                expected_tenant_id=TENANT_ID,
                expected_execution_boundary=EXECUTION_BOUNDARY,
                expected_audit_hash=signed.audit_event_hash,
                expected_args=expected_args,
                expected_action=TOOL_NAME,
                expected_actor=PROPOSER,
                verifier=verifier,
                require_signature=True,
            )

        signed_stats = _time_loop("receipt_validation_signed_ed25519", verify_signed, n)
    except SigningError as exc:  # crypto extra not installed
        skipped = str(exc)
    return unsigned_stats, signed_stats, skipped


def bench_dispatch_and_replay(n: int, audit_dir: Path, tag: str) -> tuple[ArmStats, dict[str, Any]]:
    """End-to-end kernel dispatch for N actions, then replay_bundle over the chain."""
    policy = make_policy()
    audit = ChainHashAuditStore(audit_dir / f"dispatch-{tag}.jsonl")
    side = ReplaySideStore(audit_dir / f"dispatch-{tag}-side.jsonl")
    kernel = Kernel(policy=policy, audit=audit, actor=PROPOSER, side_store=side)
    kernel.tool(TOOL_NAME)(tool_fn)

    def one(i: int) -> None:
        kernel.dispatch(TOOL_NAME, make_args(i), goal=GOAL)

    dispatch_stats = _time_loop("end_to_end_dispatch", one, n, warmup=5)

    started = time.perf_counter()
    verdict = replay_bundle(audit, side, policy)
    elapsed = time.perf_counter() - started
    events_total = int(verdict["events_total"])
    replay = {
        "name": "replay_verification",
        "events_total": events_total,
        "valid": bool(verdict["valid"]),
        "events_matched": int(verdict["events_matched"]),
        "total_s": round(elapsed, 4),
        "events_per_s": round(events_total / elapsed, 1) if elapsed > 0 else 0.0,
    }
    if not verdict["valid"]:
        raise AssertionError(f"replay_bundle reported invalid chain in benchmark: {verdict}")
    return dispatch_stats, replay


def bench_concurrent_dispatch(
    n: int, audit_dir: Path, tag: str, threads: int = 8
) -> dict[str, Any]:
    """Throughput of *threads* workers dispatching through ONE kernel/chain.

    All writers serialize on the audit chain's exclusive file lock, so this
    measures how the membrane behaves under contention, not parallel speedup.
    """
    from concurrent.futures import ThreadPoolExecutor

    policy = make_policy()
    audit = ChainHashAuditStore(audit_dir / f"concurrent-{tag}.jsonl")
    kernel = Kernel(policy=policy, audit=audit, actor=PROPOSER)
    kernel.tool(TOOL_NAME)(tool_fn)

    def worker(indices: range) -> None:
        for i in indices:
            kernel.dispatch(TOOL_NAME, make_args(i), goal=GOAL)

    chunk = max(1, n // threads)
    ranges = [range(start, min(start + chunk, n)) for start in range(0, n, chunk)]
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=threads) as pool:
        list(pool.map(worker, ranges))
    elapsed = time.perf_counter() - started
    return {
        "name": "concurrent_dispatch",
        "threads": threads,
        "iterations": n,
        "total_s": round(elapsed, 4),
        "ops_per_s": round(n / elapsed, 1) if elapsed > 0 else 0.0,
    }


def sanity_checks(audit_dir: Path) -> None:
    """Fail fast if the membrane is not enforcing what the benchmark claims."""
    policy = make_policy()
    audit = ChainHashAuditStore(audit_dir / "sanity.jsonl")
    kernel = Kernel(policy=policy, audit=audit, actor=PROPOSER)
    kernel.tool(TOOL_NAME)(tool_fn)

    result, receipt = kernel.dispatch(TOOL_NAME, make_args(0), goal=GOAL)
    assert result == tool_fn(**make_args(0)), "dispatch result mismatch"
    assert receipt.audit_hash, "dispatch produced no audit anchor"

    denied = False
    try:
        kernel.dispatch(TOOL_NAME, {"path": "~/.ssh/id_rsa", "content": "x"}, goal=GOAL)
    except DeniedError:
        denied = True
    assert denied, "boundary policy failed to deny a forbidden call"

    # A tampered receipt must fail validation.
    minted = _mint_receipt(None, audit_dir, "sanity")
    tampered = dataclasses.replace(minted, proposed_action="exfiltrate")
    rejected = False
    try:
        tampered.verify(
            expected_tenant_id=TENANT_ID,
            expected_execution_boundary=EXECUTION_BOUNDARY,
            expected_actor=PROPOSER,
            require_signature=False,
        )
    except ReceiptValidationError:
        rejected = True
    assert rejected, "tampered receipt passed validation"


def run(scales: list[int], audit_dir: Path) -> dict[str, Any]:
    sanity_checks(audit_dir)

    results: list[dict[str, Any]] = []
    for n in scales:
        tag = f"n{n}"
        policy_stats = bench_policy_evaluation(n)
        audit_stats, audit_batched = bench_audit_write(n, audit_dir, tag)
        unsigned_stats, signed_stats, signed_skipped = bench_receipt_validation(n, audit_dir, tag)
        dispatch_stats, replay = bench_dispatch_and_replay(n, audit_dir, tag)
        concurrent = bench_concurrent_dispatch(n, audit_dir, tag)

        metrics: dict[str, Any] = {
            "policy_evaluation": policy_stats.to_dict(),
            "audit_write": audit_stats.to_dict(),
            "receipt_validation_unsigned": unsigned_stats.to_dict(),
            "end_to_end_dispatch": dispatch_stats.to_dict(),
            "replay_verification": replay,
            "concurrent_dispatch": concurrent,
        }
        if audit_batched is not None:
            metrics["audit_write_batched"] = audit_batched.to_dict()
        if signed_stats is not None:
            metrics["receipt_validation_signed_ed25519"] = signed_stats.to_dict()
        if signed_skipped:
            metrics["receipt_validation_signed_skipped"] = signed_skipped
        results.append({"n": n, "metrics": metrics})
        print(f"[governed_actions_bench] scale n={n} done", file=sys.stderr)

    return {
        "benchmark": "governed_actions",
        "scales": results,
        "machine": {
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "processor": platform.processor() or platform.machine(),
        },
        "audit_dir": str(audit_dir),
        "caveats": [
            "single local dev machine, not a controlled environment",
            "near-zero in-memory tool body: absolute overhead is the meaningful "
            "figure; relative % against a no-op tool is a worst case",
            "audit appends fsync a JSONL file per event; storage medium dominates "
            "audit_write and end_to_end_dispatch",
            "receipt_validation re-verifies one representative receipt N times; "
            "verify is stateless so latency does not depend on chain length",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scales", type=int, nargs="+", default=list(DEFAULT_SCALES))
    parser.add_argument(
        "--audit-dir",
        type=Path,
        default=None,
        help="Directory for audit/side-store JSONL files (default: fresh temp dir)",
    )
    parser.add_argument(
        "--json", type=Path, default=None, help="Also write the report to this path"
    )
    args = parser.parse_args()

    if args.audit_dir is not None:
        args.audit_dir.mkdir(parents=True, exist_ok=True)
        report = run(args.scales, args.audit_dir)
    else:
        with tempfile.TemporaryDirectory(prefix="gove-zone-governed-actions-") as tmp:
            report = run(args.scales, Path(tmp))

    text = json.dumps(report, indent=2)
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
