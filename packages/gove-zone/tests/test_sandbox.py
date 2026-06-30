"""Unit tests for the sandbox execution providers."""

from __future__ import annotations

import pytest

from gove_zone.sandbox import E2BSandbox, LocalProcessSandbox, SandboxError


def my_sandbox_test_tool(a: int, b: int) -> int:
    """A sample importable tool function for testing sandbox imports."""
    return a + b


def test_local_process_sandbox_restricted_subprocess() -> None:
    """Verify LocalProcessSandbox executes importable functions in a subprocess."""
    sandbox = LocalProcessSandbox(use_bwrap=False)
    res = sandbox.run_tool(my_sandbox_test_tool, {"a": 5, "b": 7})
    assert res == 12


def test_local_process_sandbox_non_importable_closure() -> None:
    """Verify that LocalProcessSandbox falls back to multiprocessing fork for closures."""
    sandbox = LocalProcessSandbox(use_bwrap=False)

    # Closure (not importable at top-level)
    def my_local_closure(x: int) -> int:
        return x * 10

    res = sandbox.run_tool(my_local_closure, {"x": 3})
    assert res == 30


def test_local_process_sandbox_failure_propagation() -> None:
    """Verify that tool failures inside the sandbox raise a SandboxError."""
    sandbox = LocalProcessSandbox(use_bwrap=False)

    def my_failing_tool() -> None:
        raise ValueError("Simulated tool error")

    with pytest.raises(SandboxError) as exc_info:
        sandbox.run_tool(my_failing_tool, {})

    assert "Simulated tool error" in str(exc_info.value)


def test_e2e_sandbox_mock_fallback() -> None:
    """Verify that the E2B sandbox falls back to mock execution when e2b is missing."""
    sandbox = E2BSandbox(api_key="test-api-key")
    res = sandbox.run_tool(my_sandbox_test_tool, {"a": 2, "b": 8})
    assert res == 10


def test_e2e_sandbox_missing_api_key() -> None:
    """Verify that E2B sandbox raises an error if no API key is provided."""
    sandbox = E2BSandbox(api_key=None)
    # Clear env var if set
    import os

    orig_key = os.environ.pop("E2B_API_KEY", None)
    try:
        with pytest.raises(SandboxError) as exc_info:
            sandbox.run_tool(my_sandbox_test_tool, {"a": 1, "b": 2})
        assert "E2B_API_KEY must be configured" in str(exc_info.value)
    finally:
        if orig_key:
            os.environ["E2B_API_KEY"] = orig_key
