"""Focused contract tests for the local MCP action-gateway benchmark."""

from __future__ import annotations

import importlib.util
import json
import math
import statistics
import subprocess
import sys
from pathlib import Path
from typing import Any

import anyio
import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PACKAGE_ROOT / "benchmarks" / "mcp_action_gateway.py"
REPORT_SCHEMA = "gove-zone.mcp-action-gateway-benchmark/v1"
ERROR_SCHEMA = "gove-zone.mcp-action-gateway-benchmark-error/v1"


def _load_benchmark_module() -> Any:
    spec = importlib.util.spec_from_file_location("mcp_action_gateway_benchmark", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("benchmark module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _fixture_processes() -> set[int]:
    processes: set[int] = set()
    proc = Path("/proc")
    if not proc.is_dir():
        return processes
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            command = (entry / "cmdline").read_bytes()
        except (OSError, PermissionError):
            continue
        if b"gove-zone-mcp-benchmark-" in command:
            processes.add(int(entry.name))
    return processes


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed local interpreter and repository script
        [sys.executable, str(SCRIPT), *arguments],
        cwd=PACKAGE_ROOT,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )


def _nearest_rank_p95(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def _assert_distribution(value: dict[str, Any], samples: int) -> None:
    assert value["unit"] == "ms"
    assert value["sample_count"] == samples
    values = value["values_ms"]
    assert len(values) == samples
    assert all(isinstance(item, int | float) for item in values)
    assert all(math.isfinite(item) and item >= 0 for item in values)
    assert value["min"] == pytest.approx(min(values), abs=1e-6)
    assert value["median"] == pytest.approx(float(statistics.median(values)), abs=1e-6)
    assert value["p95"] == pytest.approx(_nearest_rank_p95(values), abs=1e-6)
    assert value["max"] == pytest.approx(max(values), abs=1e-6)


class _DeterministicIntervalClock:
    """Return adjacent start/stop ticks for a declared sequence of intervals."""

    def __init__(self, durations_ms: list[int]) -> None:
        cursor_ns = 1_000_000_000
        self._ticks: list[int] = []
        for duration_ms in durations_ms:
            self._ticks.extend((cursor_ns, cursor_ns + duration_ms * 1_000_000))
            cursor_ns += (duration_ms + 7) * 1_000_000
        self._index = 0

    def __call__(self) -> int:
        if self._index >= len(self._ticks):
            raise AssertionError("benchmark read more clock ticks than expected")
        value = self._ticks[self._index]
        self._index += 1
        return value

    def assert_exhausted(self) -> None:
        assert self._index == len(self._ticks)


def test_injected_clock_binds_every_raw_sample_and_excludes_warmups() -> None:
    benchmark = _load_benchmark_module()
    # Call order is policy, paired direct/governed operations, then receipt
    # verification. Large, distinct warmup intervals make accidental inclusion
    # visible. Exact raw-value assertions reject an implementation that replaces
    # measured intervals with internally consistent constants.
    clock = _DeterministicIntervalClock(
        [
            99,
            1,
            3,  # policy: warmup, sample 0, sample 1
            50,
            100,  # paired warmup: direct, governed
            10,
            30,  # paired sample 0: direct, governed
            20,
            60,  # paired sample 1: direct, governed
            80,
            2,
            4,  # receipt: warmup, sample 0, sample 1
        ]
    )

    report = anyio.run(benchmark.run_benchmark, 2, 1, clock)
    clock.assert_exhausted()

    measurements = report["measurements"]
    expected = {
        "policy_evaluation_latency": [1.0, 3.0],
        "receipt_verification_latency": [2.0, 4.0],
        "direct_local_fixture_call_latency": [10.0, 20.0],
        "governed_mcp_gateway_call_latency": [30.0, 60.0],
        "computed_gateway_overhead": [20.0, 40.0],
    }
    for name, values in expected.items():
        assert measurements[name]["values_ms"] == values
        _assert_distribution(measurements[name], 2)

    assert report["instrumentation"]["expected_each"] == 3
    assert report["instrumentation"]["paired_record_payloads_identical"] is True
    serialized_samples = [
        sample for measurement in measurements.values() for sample in measurement["values_ms"]
    ]
    assert all(warmup not in serialized_samples for warmup in (50.0, 80.0, 99.0, 100.0))


def test_small_local_benchmark_schema_math_cleanup_and_path_neutrality(tmp_path: Path) -> None:
    before = _fixture_processes()
    output = tmp_path / "benchmark.json"
    completed = _run("--samples", "2", "--warmup", "1", "--output", str(output))

    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert completed.stdout == ""
    assert completed.stderr == ""
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema"] == REPORT_SCHEMA
    assert report["benchmark"] == "mcp_action_gateway"
    assert report["claim_boundary"] == {
        "certification_claimed": False,
        "network_used": False,
        "production_sla_claimed": False,
        "scope": "single-machine local fixture only",
        "statement": (
            "Local engineering evidence only; timings are not production, capacity, "
            "availability, or third-party certification evidence."
        ),
    }
    assert set(report["environment"]) == {"python", "platform", "cpu", "hardware"}
    assert report["configuration"]["samples_per_measurement"] == 2
    assert report["configuration"]["warmup_per_measurement"] == 1
    assert report["configuration"]["concurrency"] == {
        "condition": "serial",
        "concurrent_gateway_calls": 0,
        "fixture_child_processes": 2,
        "in_flight_gateway_calls": 1,
        "runtime_internal_workers_included": True,
    }
    assert report["configuration"]["fixture"] == (
        "separate isolated persistent local stdio children per arm"
    )

    measurements = report["measurements"]
    assert set(measurements) == {
        "policy_evaluation_latency",
        "receipt_verification_latency",
        "governed_mcp_gateway_call_latency",
        "direct_local_fixture_call_latency",
        "computed_gateway_overhead",
    }
    for distribution in measurements.values():
        _assert_distribution(distribution, 2)
    gateway = measurements["governed_mcp_gateway_call_latency"]["values_ms"]
    direct = measurements["direct_local_fixture_call_latency"]["values_ms"]
    overhead = measurements["computed_gateway_overhead"]["values_ms"]
    assert overhead == pytest.approx(
        [round(governed - baseline, 6) for governed, baseline in zip(gateway, direct, strict=True)],
        abs=1e-6,
    )

    assert report["instrumentation"] == {
        "expected_each": 3,
        "reference_policy_metric_evaluations": 3,
        "governed_reference_policy_evaluations": 3,
        "ed25519_receipt_verifications": 3,
        "governed_final_adapter_executions": 3,
        "governed_fixture_writes": 3,
        "direct_fixture_executions": 3,
        "direct_fixture_writes": 3,
        "paired_record_payloads_identical": True,
    }
    assert report["safety"]["unique_gateway_records"] == 3
    assert report["safety"]["unique_direct_records"] == 3
    assert report["safety"]["temporary_state_removed"] is True
    assert report["safety"]["fixture_processes_reaped"] == 2
    serialized = json.dumps(report, sort_keys=True)
    for forbidden in (
        "benchmark-inert-local-token",
        "fixture-downstream-secret",
        ".mcp-private",
        str(tmp_path),
        "/tmp/",
        str(Path.home()),
    ):
        assert forbidden not in serialized
    assert _fixture_processes() == before


def test_durable_fixture_proof_rejects_missing_or_noop_execution(tmp_path: Path) -> None:
    benchmark = _load_benchmark_module()
    ledger = tmp_path / "ledger.jsonl"
    calls = tmp_path / "calls.jsonl"
    expected = ["record-1", "record-2"]

    with pytest.raises(RuntimeError, match="durable writes"):
        benchmark._verified_fixture_counts(
            ledger_path=ledger,
            call_log_path=calls,
            expected_records=expected,
        )

    ledger.write_text(
        "\n".join(json.dumps({"record": record}, sort_keys=True) for record in expected) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="adapter executions"):
        benchmark._verified_fixture_counts(
            ledger_path=ledger,
            call_log_path=calls,
            expected_records=expected,
        )

    calls.write_text(
        "\n".join(json.dumps({"tool": "fixture.write_once"}) for _ in expected) + "\n",
        encoding="utf-8",
    )
    assert benchmark._verified_fixture_counts(
        ledger_path=ledger,
        call_log_path=calls,
        expected_records=expected,
    ) == {"executions": 2, "writes": 2}


def test_instrumentation_wrappers_count_real_policy_and_ed25519_calls() -> None:
    benchmark = _load_benchmark_module()
    measured_policy = benchmark._ReferencePolicy()
    governed_policy = benchmark._ReferencePolicy()
    probe = benchmark._ReferencePolicyProbe(measured_policy)
    probe.install()
    try:
        measured_record = measured_policy.evaluate(
            benchmark.ToolCall(
                name="fixture.write_once",
                args={"record": "measured"},
                actor="benchmark-agent",
            )
        )
        governed_record = governed_policy.evaluate(
            benchmark.ToolCall(
                name="fixture.write_once",
                args={"record": "governed"},
                actor="benchmark-agent",
            )
        )
    finally:
        probe.restore()

    assert measured_record.event_id != governed_record.event_id
    assert probe.measured_evaluations == 1
    assert probe.governed_evaluations == 1

    signer = benchmark.Ed25519Signer.generate("benchmark-test-key")
    verifier = benchmark._CountingEd25519Verifier(
        benchmark.Ed25519Signer.from_public_bytes(
            signer.public_bytes(),
            key_id=signer.key_id,
        )
    )
    payload = b"benchmark receipt hash"
    signature = signer.sign(payload)
    assert verifier.verify(payload, signature) is True
    assert verifier.successful_verifications == 1
    assert verifier.verify(payload + b"-tampered", signature) is False
    assert verifier.successful_verifications == 1


@pytest.mark.parametrize(
    "arguments",
    [
        ("--samples", "0"),
        ("--samples", "251"),
        ("--samples", "not-an-integer"),
        ("--warmup", "-1"),
        ("--warmup", "51"),
        ("--unknown", "value"),
    ],
)
def test_bad_arguments_are_exit_two_json_without_traceback(arguments: tuple[str, ...]) -> None:
    before = _fixture_processes()
    completed = _run(*arguments)

    assert completed.returncode == 2
    assert completed.stderr == ""
    assert "Traceback" not in completed.stdout
    assert json.loads(completed.stdout) == {
        "schema": ERROR_SCHEMA,
        "error": {
            "code": "invalid_arguments",
            "message": "The benchmark configuration was rejected.",
        },
    }
    assert _fixture_processes() == before


def test_output_parent_must_already_be_a_real_directory(tmp_path: Path) -> None:
    missing = tmp_path / "missing" / "report.json"
    completed = _run("--samples", "1", "--warmup", "0", "--output", str(missing))

    assert completed.returncode == 2
    assert completed.stderr == ""
    assert json.loads(completed.stdout)["schema"] == ERROR_SCHEMA
    assert not missing.exists()


def test_oversized_output_component_is_exit_two_path_neutral_json(tmp_path: Path) -> None:
    oversized = tmp_path / ("x" * 300)
    completed = _run("--samples", "1", "--warmup", "0", "--output", str(oversized))

    assert completed.returncode == 2
    assert completed.stderr == ""
    assert len(completed.stdout.splitlines()) == 1
    assert "Traceback" not in completed.stdout
    assert str(oversized) not in completed.stdout
    assert json.loads(completed.stdout) == {
        "schema": ERROR_SCHEMA,
        "error": {
            "code": "invalid_arguments",
            "message": "The benchmark configuration was rejected.",
        },
    }
