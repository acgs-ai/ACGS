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


def test_local_process_sandbox_rejects_closure_by_default() -> None:
    """A non-importable closure cannot be isolated, so it is refused by default.

    Running it would require an in-process fork (no isolation); that must be an
    explicit opt-in, never a silent downgrade.
    """
    sandbox = LocalProcessSandbox(use_bwrap=False)

    def my_local_closure(x: int) -> int:
        return x * 10

    with pytest.raises(SandboxError) as exc_info:
        sandbox.run_tool(my_local_closure, {"x": 3})
    assert "allow_fork=True" in str(exc_info.value)


def test_local_process_sandbox_closure_with_allow_fork() -> None:
    """With allow_fork=True, closures run via the (unisolated) fork path."""
    sandbox = LocalProcessSandbox(use_bwrap=False, allow_fork=True)

    def my_local_closure(x: int) -> int:
        return x * 10

    res = sandbox.run_tool(my_local_closure, {"x": 3})
    assert res == 30


def test_local_process_sandbox_rejects_bound_method_by_default() -> None:
    """Bound methods (e.g. framework tool `_run`) are non-importable → refused."""
    sandbox = LocalProcessSandbox(use_bwrap=False)

    class Tool:
        def run(self, x: int) -> int:
            return x + 1

    with pytest.raises(SandboxError):
        sandbox.run_tool(Tool().run, {"x": 1})


def test_local_process_sandbox_failure_propagation() -> None:
    """A tool that raises inside the sandbox surfaces as SandboxError with its message."""
    # Exercised through the fork path (allow_fork=True) so the child's exception
    # is captured directly; the importable-subprocess path is covered separately.
    sandbox = LocalProcessSandbox(use_bwrap=False, allow_fork=True)

    def failing() -> None:
        raise ValueError("Simulated tool error")

    with pytest.raises(SandboxError) as exc_info:
        sandbox.run_tool(failing, {})

    assert "Simulated tool error" in str(exc_info.value)


def test_e2b_sandbox_refuses_mock_by_default() -> None:
    """Without the e2b package and without allow_mock, run_tool fails closed.

    It must NOT silently run the tool in-process while advertising a remote
    microVM.
    """
    sandbox = E2BSandbox(api_key="test-api-key")
    with pytest.raises(SandboxError) as exc_info:
        sandbox.run_tool(my_sandbox_test_tool, {"a": 2, "b": 8})
    assert "allow_mock=True" in str(exc_info.value)


def test_e2b_sandbox_mock_with_opt_in() -> None:
    """With allow_mock=True, the in-process test fallback runs (no isolation)."""
    sandbox = E2BSandbox(api_key="test-api-key", allow_mock=True)
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


class _FakeE2BExecution:
    def __init__(self, exit_code: int, stdout: str, stderr: str = "") -> None:
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


def _install_fake_e2b(monkeypatch: pytest.MonkeyPatch, execution: _FakeE2BExecution) -> None:
    """Install a fake ``e2b`` module whose Sandbox returns ``execution``."""
    import sys
    import types

    class _FakeCommands:
        def run(self, _cmd: str) -> _FakeE2BExecution:
            return execution

    class _FakeFiles:
        def write(self, _path: str, _content: str) -> None:
            pass

    class _FakeSandbox:
        def __init__(self, api_key: str | None = None) -> None:
            self.commands = _FakeCommands()
            self.files = _FakeFiles()

        def close(self) -> None:
            pass

    fake = types.ModuleType("e2b")
    fake.Sandbox = _FakeSandbox  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "e2b", fake)


def test_e2b_success_envelope_returns_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """A well-formed success envelope after tool stdout noise yields the result."""
    _install_fake_e2b(
        monkeypatch,
        _FakeE2BExecution(
            0, 'tool log line\nGOVE_ZONE_ENVELOPE_V1:{"status": "success", "result": 42}'
        ),
    )
    sandbox = E2BSandbox(api_key="test-api-key")
    assert sandbox.run_tool(my_sandbox_test_tool, {"a": 1, "b": 2}) == 42


@pytest.mark.parametrize(
    "stdout",
    [
        # Non-object JSON payload: _extract_envelope returns None.
        "GOVE_ZONE_ENVELOPE_V1:[1, 2, 3]",
        # Object envelope missing the status key.
        'GOVE_ZONE_ENVELOPE_V1:{"result": 1}',
        # Success envelope missing the result key.
        'GOVE_ZONE_ENVELOPE_V1:{"status": "success"}',
        # Error envelope missing the error key.
        'GOVE_ZONE_ENVELOPE_V1:{"status": "error"}',
    ],
)
def test_e2b_malformed_envelope_is_a_parse_failure(
    monkeypatch: pytest.MonkeyPatch, stdout: str
) -> None:
    """A malformed envelope surfaces as an explicit parse failure, not a KeyError.

    Without the key-presence guards these raised a bare KeyError/TypeError that
    was only caught by the generic wrapper, yielding the misleading message
    "E2B sandbox execution failed: 'status'".
    """
    _install_fake_e2b(monkeypatch, _FakeE2BExecution(0, stdout))
    sandbox = E2BSandbox(api_key="test-api-key")
    with pytest.raises(SandboxError, match="Failed to parse sandbox output"):
        sandbox.run_tool(my_sandbox_test_tool, {"a": 1, "b": 2})


def test_e2b_error_envelope_surfaces_tool_message(monkeypatch: pytest.MonkeyPatch) -> None:
    """A zero-exit error envelope still surfaces the tool's own message."""
    _install_fake_e2b(
        monkeypatch,
        _FakeE2BExecution(0, 'GOVE_ZONE_ENVELOPE_V1:{"status": "error", "error": "tool said no"}'),
    )
    sandbox = E2BSandbox(api_key="test-api-key")
    with pytest.raises(SandboxError, match="tool said no"):
        sandbox.run_tool(my_sandbox_test_tool, {"a": 1, "b": 2})
