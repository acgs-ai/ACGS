"""Membrane-overhead micro-benchmark: governed vs ungoverned call latency.

Measures the per-call latency tax of the gove-zone membrane against a direct
(ungoverned) invocation of the same tool function. Three governed arms:

1. ``kernel_dispatch`` — the embedded path: ``Kernel.dispatch`` runs policy
   evaluation, fail-closed watchdog synthesis, audit-chain append (fsync'd),
   tool execution, and kernel ``Receipt`` construction.
2. ``receipt_gate_unsigned`` — the full split membrane: policy decision +
   audit append + ``DecisionReceipt.from_record`` (unsigned) + executor-side
   ``GovernedExecutor.execute`` validation (``require_signature=False``).
3. ``receipt_gate_signed`` — same as (2) but receipts are Ed25519-signed at
   issuance and cryptographically verified at the gate
   (``require_signature=True``). Skipped when the ``crypto`` extra is absent.

The tool body is a near-zero in-memory function so the measured latency is
dominated by the membrane itself. That makes the *absolute* per-call overhead
the meaningful number; relative percentages against a no-op tool are a
worst case and should not be quoted alone.

Run from the repo root::

    uv run --package gove-zone python packages/gove-zone/benchmarks/overhead_receipt_gate.py

Optional args: ``--iterations N`` ``--warmup N`` ``--audit-dir PATH``.
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
    GovernedExecutor,
    Kernel,
    Validator,
)
from gove_zone.errors import SigningError
from gove_zone.tool import ToolCall

TENANT_ID = "tenant-bench"
EXECUTION_BOUNDARY = "bench-local"
POLICY_BUNDLE_ID = "bench-bundle"
PROPOSER = "bench-agent"
VALIDATOR = Validator(validator_id="bench-governor", role="policy-engine")
AUTHORITY = "benchmark-grant"
TOOL_NAME = "write_report"
GOAL = "benchmark membrane overhead"

TOOL_ARGS: dict[str, Any] = {
    "path": "/workspace/reports/overhead.md",
    "content": "membrane-overhead benchmark payload " * 8,
}


def tool_fn(path: str, content: str) -> dict[str, Any]:
    """Near-zero in-memory tool body (no I/O) so the membrane dominates."""
    return {"path": path, "bytes": len(content)}


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
    mean_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "iterations": self.iterations,
            "mean_ms": round(self.mean_ms, 4),
            "p50_ms": round(self.p50_ms, 4),
            "p95_ms": round(self.p95_ms, 4),
            "p99_ms": round(self.p99_ms, 4),
        }


def _percentile(values: list[float], pct: int) -> float:
    return statistics.quantiles(values, n=100, method="inclusive")[pct - 1]


def _time_arm(name: str, fn: Callable[[], Any], *, iterations: int, warmup: int) -> ArmStats:
    for _ in range(warmup):
        fn()
    latencies: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        fn()
        latencies.append(time.perf_counter() - started)
    return ArmStats(
        name=name,
        iterations=iterations,
        mean_ms=statistics.fmean(latencies) * 1000,
        p50_ms=_percentile(latencies, 50) * 1000,
        p95_ms=_percentile(latencies, 95) * 1000,
        p99_ms=_percentile(latencies, 99) * 1000,
    )


def make_kernel(audit_dir: Path, tag: str) -> Kernel:
    kernel = Kernel(
        policy=make_policy(),
        audit=ChainHashAuditStore(audit_dir / f"kernel-{tag}.jsonl"),
        actor=PROPOSER,
    )
    kernel.tool(TOOL_NAME)(tool_fn)
    return kernel


def make_receipt_gate_call(
    audit_dir: Path,
    tag: str,
    *,
    signer: Any | None,
    verifier: Any | None,
    require_signature: bool,
) -> Callable[[], Any]:
    """Full split-membrane pipeline for one governed call.

    Per invocation: policy decision -> audit append (fsync) -> receipt
    issuance (optionally Ed25519-signed) -> executor-side receipt validation
    -> tool execution. Mirrors the decide/issue/gate flow documented in
    ``gove_zone.executor``.
    """
    policy = make_policy()
    audit = ChainHashAuditStore(audit_dir / f"gate-{tag}.jsonl")
    executor = GovernedExecutor(
        tenant_id=TENANT_ID,
        execution_boundary=EXECUTION_BOUNDARY,
        expected_actor=PROPOSER,
        verifier=verifier,
        require_signature=require_signature,
    )
    executor.register(TOOL_NAME, tool_fn)
    policy_hash = policy.version  # stable identifier doubling as the bundle hash here
    counter = 0

    def governed_call() -> Any:
        nonlocal counter
        counter += 1
        call = ToolCall(name=TOOL_NAME, args=dict(TOOL_ARGS), goal=GOAL, actor=PROPOSER)
        record = policy.evaluate(call)
        record = dataclasses.replace(record, actor=PROPOSER, goal=GOAL)
        payload = audit.append(record)
        receipt = DecisionReceipt.from_record(
            record,
            str(payload["event_hash"]),
            str(payload["previous_hash"]),
            TENANT_ID,
            EXECUTION_BOUNDARY,
            POLICY_BUNDLE_ID,
            policy_hash,
            f"req-{tag}-{counter}",
            validator=VALIDATOR,
            authority=AUTHORITY,
            signer=signer,
        )
        return executor.execute(
            TOOL_NAME,
            dict(TOOL_ARGS),
            receipt,
            expected_audit_hash=str(payload["event_hash"]),
        )

    return governed_call


def sanity_checks(audit_dir: Path) -> None:
    """Fail fast if any arm is not doing what the benchmark claims."""
    expected = tool_fn(**TOOL_ARGS)

    kernel = make_kernel(audit_dir, "sanity")
    result, receipt = kernel.dispatch(TOOL_NAME, TOOL_ARGS, goal=GOAL)
    assert result == expected, "kernel arm result mismatch"
    assert receipt.audit_hash, "kernel arm produced no audit anchor"

    gate = make_receipt_gate_call(
        audit_dir, "sanity", signer=None, verifier=None, require_signature=False
    )
    assert gate() == expected, "receipt-gate arm result mismatch"

    # The membrane must actually block: a forbidden argument denies.
    denied = False
    try:
        kernel.dispatch(TOOL_NAME, {"path": "~/.ssh/id_rsa", "content": "x"}, goal=GOAL)
    except DeniedError:
        denied = True
    assert denied, "boundary policy failed to deny a forbidden call"


def run(iterations: int, warmup: int, audit_dir: Path) -> dict[str, Any]:
    sanity_checks(audit_dir)

    arms: list[ArmStats] = []
    arms.append(
        _time_arm(
            "ungoverned_direct",
            lambda: tool_fn(**TOOL_ARGS),
            iterations=iterations,
            warmup=warmup,
        )
    )

    kernel = make_kernel(audit_dir, "timed")
    arms.append(
        _time_arm(
            "kernel_dispatch",
            lambda: kernel.dispatch(TOOL_NAME, TOOL_ARGS, goal=GOAL),
            iterations=iterations,
            warmup=warmup,
        )
    )

    arms.append(
        _time_arm(
            "receipt_gate_unsigned",
            make_receipt_gate_call(
                audit_dir, "unsigned", signer=None, verifier=None, require_signature=False
            ),
            iterations=iterations,
            warmup=warmup,
        )
    )

    signed_skipped_reason = ""
    try:
        from gove_zone import Ed25519Signer

        signer = Ed25519Signer.generate(key_id="bench-key")
        verifier = Ed25519Signer.from_public_bytes(signer.public_bytes(), key_id="bench-key")
        arms.append(
            _time_arm(
                "receipt_gate_signed_ed25519",
                make_receipt_gate_call(
                    audit_dir,
                    "signed",
                    signer=signer,
                    verifier={"bench-key": verifier},
                    require_signature=True,
                ),
                iterations=iterations,
                warmup=warmup,
            )
        )
    except SigningError as exc:  # crypto extra not installed
        signed_skipped_reason = str(exc)

    baseline = arms[0]
    overhead = {
        arm.name: {
            "p50_ms": round(arm.p50_ms - baseline.p50_ms, 4),
            "p95_ms": round(arm.p95_ms - baseline.p95_ms, 4),
            "p99_ms": round(arm.p99_ms - baseline.p99_ms, 4),
            "mean_ms": round(arm.mean_ms - baseline.mean_ms, 4),
        }
        for arm in arms[1:]
    }

    return {
        "benchmark": "overhead_receipt_gate",
        "iterations_per_arm": iterations,
        "warmup_per_arm": warmup,
        "tool_args_bytes": len(json.dumps(TOOL_ARGS)),
        "machine": {
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "processor": platform.processor() or platform.machine(),
        },
        "audit_dir": str(audit_dir),
        "arms": [arm.to_dict() for arm in arms],
        "overhead_vs_ungoverned_ms": overhead,
        "signed_arm_skipped": signed_skipped_reason,
        "caveats": [
            "single local dev machine, not a controlled environment",
            "in-process kernel and near-zero tool body: absolute overhead is the "
            "meaningful figure; relative % against a no-op tool is a worst case",
            "audit appends fsync a JSONL file in audit_dir; storage medium matters",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--warmup", type=int, default=200)
    parser.add_argument(
        "--audit-dir",
        type=Path,
        default=None,
        help="Directory for audit JSONL chains (default: fresh temp dir)",
    )
    args = parser.parse_args()

    if args.audit_dir is not None:
        args.audit_dir.mkdir(parents=True, exist_ok=True)
        report = run(args.iterations, args.warmup, args.audit_dir)
    else:
        with tempfile.TemporaryDirectory(prefix="gove-zone-overhead-") as tmp:
            report = run(args.iterations, args.warmup, Path(tmp))

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
