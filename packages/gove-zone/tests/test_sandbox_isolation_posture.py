"""Guards for ``LocalProcessSandbox``'s stated isolation posture.

The class documents three postures and the whole security value is that it
never silently pretends to be in a stronger one than it is:

* **bwrap present** — namespace isolation;
* **bwrap requested but absent** — a subprocess with a cleared environment, and
  a ``UserWarning`` so the downgrade is visible; ``require_bwrap=True`` turns
  that downgrade into a hard failure instead;
* **non-importable callable** — cannot be isolated at all (it would ``fork``
  and share the parent's memory, environment and file descriptors), so it is
  refused unless ``allow_fork=True`` is passed explicitly.

``test_sandbox.py`` covers that a closure and a bound method are refused. What
is pinned here is the posture *selection* — the part that decides which of the
three a caller actually gets — plus the argument channel, which must never
interpolate tool-controlled data into executable source.
"""

from __future__ import annotations

import json
import os
import warnings
from pathlib import Path
from types import SimpleNamespace

import pytest

from gove_zone.sandbox import E2BSandbox, LocalProcessSandbox, SandboxError


def echo(value: int) -> int:
    """Module-level (importable) tool, so the subprocess path is usable."""
    return value * 2


def boom() -> None:
    raise ValueError("tool exploded")


def _no_bwrap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("gove_zone.sandbox.shutil.which", lambda name: None)


def _with_bwrap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("gove_zone.sandbox.shutil.which", lambda name: "/usr/bin/bwrap")


# --------------------------------------------------------------------------- #
# Posture selection
# --------------------------------------------------------------------------- #
def test_requiring_bwrap_without_bwrap_fails_closed(monkeypatch: pytest.MonkeyPatch):
    _no_bwrap(monkeypatch)

    with pytest.raises(SandboxError, match="require_bwrap=True but bubblewrap"):
        LocalProcessSandbox(use_bwrap=True, require_bwrap=True)


def test_the_downgrade_to_a_bare_subprocess_is_never_silent(monkeypatch: pytest.MonkeyPatch):
    _no_bwrap(monkeypatch)

    with pytest.warns(UserWarning, match="does NOT restrict network or filesystem access"):
        sandbox = LocalProcessSandbox(use_bwrap=True)

    assert sandbox.use_bwrap is False


def test_requiring_bwrap_succeeds_when_bwrap_is_present(monkeypatch: pytest.MonkeyPatch):
    _with_bwrap(monkeypatch)

    sandbox = LocalProcessSandbox(use_bwrap=True, require_bwrap=True)

    assert sandbox.use_bwrap is True


def test_no_downgrade_warning_when_bwrap_was_never_requested(monkeypatch: pytest.MonkeyPatch):
    """Opting out of bwrap explicitly is a choice, not a surprise — warning here
    would train callers to ignore the warning that matters."""
    _no_bwrap(monkeypatch)

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        sandbox = LocalProcessSandbox(use_bwrap=False)

    assert sandbox.use_bwrap is False


def test_require_bwrap_is_not_consulted_when_bwrap_is_not_requested(
    monkeypatch: pytest.MonkeyPatch,
):
    _no_bwrap(monkeypatch)

    sandbox = LocalProcessSandbox(use_bwrap=False, require_bwrap=True)

    assert sandbox.use_bwrap is False


# --------------------------------------------------------------------------- #
# Sandbox directory lifecycle
# --------------------------------------------------------------------------- #
def test_an_explicit_sandbox_dir_is_used_and_not_owned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _no_bwrap(monkeypatch)

    sandbox = LocalProcessSandbox(use_bwrap=False, sandbox_dir=str(tmp_path))

    assert sandbox.sandbox_dir == str(tmp_path)
    assert sandbox._temp_dir is None  # noqa: SLF001 - lifecycle is the assertion


def test_a_temporary_sandbox_dir_is_created_when_none_is_given(monkeypatch: pytest.MonkeyPatch):
    _no_bwrap(monkeypatch)

    sandbox = LocalProcessSandbox(use_bwrap=False)

    assert os.path.isdir(sandbox.sandbox_dir)
    assert "gove-sandbox-" in sandbox.sandbox_dir


def test_the_temporary_sandbox_dir_is_cleaned_up(monkeypatch: pytest.MonkeyPatch):
    _no_bwrap(monkeypatch)
    sandbox = LocalProcessSandbox(use_bwrap=False)
    path = sandbox.sandbox_dir

    sandbox.__del__()

    assert not os.path.isdir(path)


# --------------------------------------------------------------------------- #
# The argument side-channel
# --------------------------------------------------------------------------- #
def test_arguments_travel_as_json_never_as_interpolated_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Crafted argument values must not be able to alter the runner's code —
    they are written to a JSON side-channel the runner reads, and the runner
    script itself is a static constant."""
    _no_bwrap(monkeypatch)
    sandbox = LocalProcessSandbox(use_bwrap=False, sandbox_dir=str(tmp_path))
    hostile = {"value": "'); import os; os.system('id'); ('"}

    result = sandbox.run_tool(echo, hostile)

    spec = json.loads((tmp_path / "run_tool_spec.json").read_text(encoding="utf-8"))
    script = (tmp_path / "run_tool.py").read_text(encoding="utf-8")
    assert spec["args"] == hostile
    assert "os.system" not in script
    # The payload was handled as data end to end — `str * 2`, not executed.
    assert result == hostile["value"] * 2


def test_non_json_serialisable_arguments_are_refused_before_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _no_bwrap(monkeypatch)
    sandbox = LocalProcessSandbox(use_bwrap=False, sandbox_dir=str(tmp_path))

    with pytest.raises(SandboxError, match="must be JSON-serializable"):
        sandbox.run_tool(echo, {"value": object()})

    assert not (tmp_path / "run_tool_spec.json").exists()


def test_the_runner_script_records_the_module_and_function_to_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _no_bwrap(monkeypatch)
    sandbox = LocalProcessSandbox(use_bwrap=False, sandbox_dir=str(tmp_path))

    assert sandbox.run_tool(echo, {"value": 21}) == 42

    spec = json.loads((tmp_path / "run_tool_spec.json").read_text(encoding="utf-8"))
    assert spec["func"] == "echo"
    assert spec["module"] == __name__


# --------------------------------------------------------------------------- #
# Failure propagation
# --------------------------------------------------------------------------- #
def test_a_tool_exception_on_the_subprocess_path_keeps_its_message(
    monkeypatch: pytest.MonkeyPatch,
):
    """REGRESSION. The runner prints ``{"status": "error", "error": <msg>}`` and
    exits 1. That envelope used to be parsed inside a ``try/except Exception:
    pass``, so the ``raise SandboxError(data["error"])`` was caught by its own
    handler and the message was discarded on every subprocess-path failure —
    the caller saw only ``"exit status 1: "`` with an empty stderr, because the
    runner writes to stdout.

    This test goes through a genuinely importable module-level function, so it
    exercises the subprocess branch rather than the fork branch. That
    distinction is the whole point: the previously existing coverage
    (``test_sandbox.py::test_local_process_sandbox_failure_propagation``) used
    ``allow_fork=True`` and returned the message over a pipe, never touching
    this code.
    """
    _no_bwrap(monkeypatch)
    sandbox = LocalProcessSandbox(use_bwrap=False)

    with pytest.raises(SandboxError, match="tool exploded"):
        sandbox.run_tool(boom, {})


def test_the_subprocess_path_is_what_the_regression_test_exercises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """Guards the guard: if ``boom`` ever stopped being importable, the
    regression test above would silently fall back to the fork path (or be
    refused) and stop testing the branch it names."""
    _no_bwrap(monkeypatch)
    sandbox = LocalProcessSandbox(use_bwrap=False, sandbox_dir=str(tmp_path))
    calls: list[list[str]] = []
    real_run = __import__("subprocess").run

    def _spy(cmd, **kwargs):
        calls.append(cmd)
        return real_run(cmd, **kwargs)

    monkeypatch.setattr("gove_zone.sandbox.subprocess.run", _spy)

    with pytest.raises(SandboxError):
        sandbox.run_tool(boom, {})

    assert calls, "no subprocess was spawned — the fork path ran instead"
    spec = json.loads((tmp_path / "run_tool_spec.json").read_text(encoding="utf-8"))
    assert spec == {"module": __name__, "func": "boom", "args": {}}


def test_a_tool_exception_on_the_fork_path_keeps_its_message(monkeypatch: pytest.MonkeyPatch):
    """The other branch: a non-importable callable returns its message over a
    pipe. Both paths must preserve the diagnostic."""
    _no_bwrap(monkeypatch)
    sandbox = LocalProcessSandbox(use_bwrap=False, allow_fork=True)

    def failing() -> None:
        raise ValueError("tool exploded")

    with pytest.raises(SandboxError, match="tool exploded"):
        sandbox.run_tool(failing, {})


def test_a_crash_with_no_error_envelope_still_reports_exit_status_and_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The fallback is still reachable: an interpreter that dies before the
    runner's own try block produces no envelope, and the exit status plus
    stderr is then the only diagnostic available."""
    _no_bwrap(monkeypatch)
    sandbox = LocalProcessSandbox(use_bwrap=False, sandbox_dir=str(tmp_path))

    class _Completed:
        returncode = 2
        stdout = ""
        stderr = "SyntaxError: invalid syntax"

    monkeypatch.setattr("gove_zone.sandbox.subprocess.run", lambda *a, **k: _Completed())

    with pytest.raises(SandboxError, match="exit status 2: SyntaxError: invalid syntax"):
        sandbox.run_tool(echo, {"value": 1})


def test_a_nonzero_exit_with_unparseable_stdout_falls_back_to_exit_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _no_bwrap(monkeypatch)
    sandbox = LocalProcessSandbox(use_bwrap=False, sandbox_dir=str(tmp_path))

    class _Completed:
        returncode = 1
        stdout = "half a json envelo"
        stderr = "boom"

    monkeypatch.setattr("gove_zone.sandbox.subprocess.run", lambda *a, **k: _Completed())

    with pytest.raises(SandboxError, match="exit status 1: boom"):
        sandbox.run_tool(echo, {"value": 1})


def test_an_error_envelope_missing_its_error_key_falls_back_rather_than_raising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A malformed envelope must not turn into a KeyError escaping run_tool."""
    _no_bwrap(monkeypatch)
    sandbox = LocalProcessSandbox(use_bwrap=False, sandbox_dir=str(tmp_path))

    class _Completed:
        returncode = 1
        stdout = json.dumps({"status": "error"})
        stderr = "no detail"

    monkeypatch.setattr("gove_zone.sandbox.subprocess.run", lambda *a, **k: _Completed())

    with pytest.raises(SandboxError, match="exit status 1: no detail"):
        sandbox.run_tool(echo, {"value": 1})


@pytest.mark.parametrize("payload", ["null", '"a bare string"', "[1, 2]", "42"])
def test_a_zero_exit_with_a_non_envelope_payload_raises_sandbox_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: str
):
    """REGRESSION. On the success path a JSON scalar or array was subscripted
    directly, so a tool that wrote such a payload and exited 0 (e.g. by calling
    ``os._exit`` after printing) escaped a bare ``TypeError`` through
    ``run_tool``. Callers catch ``SandboxError``; anything else bypasses the
    governance layer's error handling entirely.
    """
    _no_bwrap(monkeypatch)
    sandbox = LocalProcessSandbox(use_bwrap=False, sandbox_dir=str(tmp_path))

    class _Completed:
        returncode = 0
        stdout = payload
        stderr = ""

    monkeypatch.setattr("gove_zone.sandbox.subprocess.run", lambda *a, **k: _Completed())

    with pytest.raises(SandboxError, match="Failed to parse sandbox output"):
        sandbox.run_tool(echo, {"value": 1})


def test_a_zero_exit_error_envelope_still_surfaces_its_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Guards the fix above: widening the except to include TypeError must not
    start swallowing the envelope's own error message. ``SandboxError`` is not
    a ``TypeError``/``KeyError``/``ValueError``, so it passes through."""
    _no_bwrap(monkeypatch)
    sandbox = LocalProcessSandbox(use_bwrap=False, sandbox_dir=str(tmp_path))

    class _Completed:
        returncode = 0
        stdout = json.dumps({"status": "error", "error": "tool said no"})
        stderr = ""

    monkeypatch.setattr("gove_zone.sandbox.subprocess.run", lambda *a, **k: _Completed())

    with pytest.raises(SandboxError, match="tool said no"):
        sandbox.run_tool(echo, {"value": 1})


def test_a_non_object_stdout_payload_falls_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _no_bwrap(monkeypatch)
    sandbox = LocalProcessSandbox(use_bwrap=False, sandbox_dir=str(tmp_path))

    class _Completed:
        returncode = 1
        stdout = json.dumps(["not", "an", "object"])
        stderr = "list payload"

    monkeypatch.setattr("gove_zone.sandbox.subprocess.run", lambda *a, **k: _Completed())

    with pytest.raises(SandboxError, match="exit status 1: list payload"):
        sandbox.run_tool(echo, {"value": 1})


def test_unparseable_child_output_is_a_sandbox_error_not_a_silent_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A child that exits 0 having printed something that is not the expected
    envelope must not be read as "no result, therefore fine"."""
    _no_bwrap(monkeypatch)
    sandbox = LocalProcessSandbox(use_bwrap=False, sandbox_dir=str(tmp_path))

    class _Completed:
        returncode = 0
        stdout = "not the envelope"
        stderr = ""

    monkeypatch.setattr("gove_zone.sandbox.subprocess.run", lambda *a, **k: _Completed())

    with pytest.raises(SandboxError, match="Failed to parse sandbox output"):
        sandbox.run_tool(echo, {"value": 1})


def test_a_nonzero_exit_without_an_error_envelope_reports_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _no_bwrap(monkeypatch)
    sandbox = LocalProcessSandbox(use_bwrap=False, sandbox_dir=str(tmp_path))

    class _Completed:
        returncode = 137
        stdout = ""
        stderr = "killed by the kernel"

    monkeypatch.setattr("gove_zone.sandbox.subprocess.run", lambda *a, **k: _Completed())

    with pytest.raises(SandboxError, match="exit status 137: killed by the kernel"):
        sandbox.run_tool(echo, {"value": 1})


def test_a_child_timeout_is_a_sandbox_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import subprocess as _subprocess

    _no_bwrap(monkeypatch)
    sandbox = LocalProcessSandbox(use_bwrap=False, sandbox_dir=str(tmp_path))

    def _timeout(*args: object, **kwargs: object):
        raise _subprocess.TimeoutExpired(cmd="python", timeout=30)

    monkeypatch.setattr("gove_zone.sandbox.subprocess.run", _timeout)

    with pytest.raises(SandboxError, match="timed out after 30 seconds"):
        sandbox.run_tool(echo, {"value": 1})


# --------------------------------------------------------------------------- #
# bwrap command construction
# --------------------------------------------------------------------------- #
def test_the_bwrap_wrapper_unshares_everything_and_binds_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """bwrap is not installed in every environment, so the constructed argv is
    asserted rather than executed — that argv is the isolation guarantee."""
    _with_bwrap(monkeypatch)
    sandbox = LocalProcessSandbox(use_bwrap=True, sandbox_dir=str(tmp_path))
    seen: dict[str, list[str]] = {}

    class _Completed:
        returncode = 0
        stdout = json.dumps({"status": "success", "result": 4})
        stderr = ""

    def _capture(cmd, **kwargs):
        seen["cmd"] = cmd
        seen["env"] = kwargs["env"]
        return _Completed()

    monkeypatch.setattr("gove_zone.sandbox.subprocess.run", _capture)

    assert sandbox.run_tool(echo, {"value": 2}) == 4

    cmd = seen["cmd"]
    assert cmd[0] == "bwrap"
    assert "--unshare-all" in cmd
    assert cmd.count("--ro-bind") >= 3
    # the sandbox dir is the only writable bind
    assert cmd[cmd.index("--bind") + 1] == str(tmp_path)


def test_the_child_environment_is_cleared_of_everything_but_path_and_pythonpath(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Credentials in the parent environment must not reach the tool."""
    _no_bwrap(monkeypatch)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "super-secret")
    sandbox = LocalProcessSandbox(use_bwrap=False, sandbox_dir=str(tmp_path))
    seen: dict[str, dict[str, str]] = {}

    class _Completed:
        returncode = 0
        stdout = json.dumps({"status": "success", "result": None})
        stderr = ""

    def _capture(cmd, **kwargs):
        seen["env"] = kwargs["env"]
        return _Completed()

    monkeypatch.setattr("gove_zone.sandbox.subprocess.run", _capture)
    sandbox.run_tool(echo, {"value": 1})

    assert set(seen["env"]) == {"PATH", "PYTHONPATH"}
    assert "super-secret" not in json.dumps(seen["env"])


# --------------------------------------------------------------------------- #
# Remote provider (E2B) — fail-closed posture and diagnostic preservation
# --------------------------------------------------------------------------- #
def _no_e2b_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make `from e2b import Sandbox` raise, as on a host without the SDK."""
    import builtins

    real_import = builtins.__import__

    def _fail(name: str, *args: object, **kwargs: object):
        if name == "e2b":
            raise ImportError("No module named 'e2b'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fail)


def test_e2b_without_an_api_key_refuses_before_anything_else(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("E2B_API_KEY", raising=False)

    with pytest.raises(SandboxError, match="E2B_API_KEY must be configured"):
        E2BSandbox().run_tool(echo, {"value": 1})


def test_e2b_without_the_sdk_refuses_rather_than_running_in_process(
    monkeypatch: pytest.MonkeyPatch,
):
    """Fail closed: no SDK means no remote isolation, so the tool must not run
    at all. The in-process mock is test-only and opt-in."""
    _no_e2b_sdk(monkeypatch)
    ran: list[int] = []

    def witness(value: int) -> int:
        ran.append(value)
        return value

    with pytest.raises(SandboxError, match="requires the 'e2b' package"):
        E2BSandbox(api_key="k").run_tool(witness, {"value": 1})

    assert ran == [], "tool executed despite the absence of remote isolation"


def test_e2b_mock_runs_in_process_only_when_explicitly_opted_into(
    monkeypatch: pytest.MonkeyPatch,
):
    _no_e2b_sdk(monkeypatch)

    assert E2BSandbox(api_key="k", allow_mock=True).run_tool(echo, {"value": 21}) == 42


def test_e2b_mock_preserves_the_tool_error_message(monkeypatch: pytest.MonkeyPatch):
    _no_e2b_sdk(monkeypatch)

    with pytest.raises(SandboxError, match="tool exploded"):
        E2BSandbox(api_key="k", allow_mock=True).run_tool(boom, {})


def test_e2b_rejects_non_importable_callables(monkeypatch: pytest.MonkeyPatch):
    """The remote runner re-imports by module/function name, so a callable with
    no module cannot be shipped. Refusing beats sending a broken spec."""
    monkeypatch.setitem(__import__("sys").modules, "e2b", _FakeE2BModule(stdout=""))
    anonymous = lambda value: value  # noqa: E731 - the point is that it has no module identity
    anonymous.__module__ = ""

    with pytest.raises(SandboxError, match="requires importable functions"):
        E2BSandbox(api_key="k").run_tool(anonymous, {"value": 1})


class _FakeE2BModule:
    """Minimal stand-in for the ``e2b`` package: `from e2b import Sandbox`."""

    def __init__(self, *, stdout: str, exit_code: int = 0, stderr: str = "", raise_on_run=None):
        module_self = self
        self.closed = False

        class _Files:
            def write(self, path: str, content: str) -> None:
                return None

        class _Commands:
            def run(self, cmd: str):
                if raise_on_run is not None:
                    raise raise_on_run
                return SimpleNamespace(exit_code=exit_code, stdout=stdout, stderr=stderr)

        class Sandbox:  # noqa: N801 - mirrors the SDK's class name
            def __init__(self, api_key: str | None = None) -> None:
                self.files = _Files()
                self.commands = _Commands()

            def close(self) -> None:
                module_self.closed = True

        self.Sandbox = Sandbox


def _install_e2b(monkeypatch: pytest.MonkeyPatch, **kwargs) -> _FakeE2BModule:
    module = _FakeE2BModule(**kwargs)
    monkeypatch.setitem(__import__("sys").modules, "e2b", module)
    return module


def test_e2b_returns_the_remote_result(monkeypatch: pytest.MonkeyPatch):
    module = _install_e2b(monkeypatch, stdout=json.dumps({"status": "success", "result": 42}))

    assert E2BSandbox(api_key="k").run_tool(echo, {"value": 21}) == 42
    assert module.closed is True, "remote VM was not released"


def test_e2b_surfaces_the_remote_tool_error_message(monkeypatch: pytest.MonkeyPatch):
    _install_e2b(monkeypatch, stdout=json.dumps({"status": "error", "error": "remote boom"}))

    with pytest.raises(SandboxError, match="remote boom"):
        E2BSandbox(api_key="k").run_tool(echo, {"value": 1})


def test_e2b_reports_stderr_on_a_nonzero_remote_exit(monkeypatch: pytest.MonkeyPatch):
    _install_e2b(monkeypatch, stdout="", exit_code=3, stderr="remote traceback")

    with pytest.raises(SandboxError, match="Remote E2B execution failed: remote traceback"):
        E2BSandbox(api_key="k").run_tool(echo, {"value": 1})


def test_e2b_releases_the_remote_vm_even_when_the_run_raises(monkeypatch: pytest.MonkeyPatch):
    """The VM is billed and finite; a transport failure must not leak it."""
    module = _install_e2b(monkeypatch, stdout="", raise_on_run=RuntimeError("connection reset"))

    with pytest.raises(SandboxError, match="E2B sandbox execution failed: connection reset"):
        E2BSandbox(api_key="k").run_tool(echo, {"value": 1})

    assert module.closed is True, "remote VM leaked on the error path"
