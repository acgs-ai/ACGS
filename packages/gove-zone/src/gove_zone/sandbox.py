"""Sandbox execution providers for gove-zone.

Provides isolation layers for executing tool calls, including local process
namespace isolation (via bubblewrap/gVisor if available, otherwise restricted
subprocesses) and remote sandbox execution (via E2B microVMs).
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import warnings
from abc import ABC, abstractmethod
from collections.abc import Callable
from pathlib import Path
from typing import Any

from gove_zone.errors import GoveZoneError

# The runner shares stdout with the tool it executes: a tool that logs
# progress (or writes a trailing unterminated line) leaves its output in
# front of the runner's JSON envelope, so parsing the whole stream as JSON
# failed for exactly those tools. The envelope is therefore emitted as the
# final line, prefixed by this marker after a fresh newline, giving the
# parent an unambiguous channel to find it on. json.dumps never emits raw
# newlines, so the envelope always occupies exactly one line.
_ENVELOPE_MARKER = "GOVE_ZONE_ENVELOPE_V1:"

# Static runner executed inside the sandbox. It reads a JSON spec
# ({"module", "func", "args"}) from the path given as argv[1]. No caller- or
# tool-controlled data is ever interpolated into this source, so untrusted
# argument values cannot inject code into the sandboxed process.
_RUNNER_SCRIPT = (
    "import importlib, json, sys\n"
    "with open(sys.argv[1], encoding='utf-8') as _f:\n"
    "    _spec = json.load(_f)\n"
    "try:\n"
    "    _mod = importlib.import_module(_spec['module'])\n"
    "    _func = getattr(_mod, _spec['func'])\n"
    "    _res = _func(**_spec['args'])\n"
    "    _env, _code = json.dumps({'status': 'success', 'result': _res}), 0\n"
    "except Exception as _e:\n"
    "    _env, _code = json.dumps({'status': 'error', 'error': str(_e)}), 1\n"
    "print('\\nGOVE_ZONE_ENVELOPE_V1:' + _env)\n"
    "sys.exit(_code)\n"
)


def _extract_envelope(stdout: str) -> dict[str, Any] | None:
    """Extract the runner's envelope from stdout it shares with the tool.

    The runner emits the envelope as the final line, prefixed with
    :data:`_ENVELOPE_MARKER` after a fresh newline, so any tool output that
    precedes it (including an unterminated partial line) is skipped by
    scanning for the marker's last occurrence. A bare-JSON payload without
    the marker is still accepted for compatibility with envelopes produced
    outside the current runner. Returns ``None`` when no JSON object
    envelope can be located.
    """
    idx = stdout.rfind(_ENVELOPE_MARKER)
    candidate = stdout[idx + len(_ENVELOPE_MARKER) :] if idx != -1 else stdout
    try:
        payload = json.loads(candidate.strip())
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


class SandboxError(GoveZoneError):
    """Raised when sandbox creation or execution fails."""

    pass


class SandboxProvider(ABC):
    """Base class for all sandbox execution providers."""

    @abstractmethod
    def run_tool(self, tool_fn: Callable[..., Any], args: dict[str, Any]) -> Any:
        """Execute a tool function with arguments inside the isolated sandbox."""
        pass


class LocalProcessSandbox(SandboxProvider):
    """Local process sandbox provider.

    Isolation posture — this class does NOT silently pretend to isolate:

    * **bwrap available** (``use_bwrap=True`` and ``bwrap`` on PATH): the tool
      runs in a bubblewrap namespace (network/IPC/mounts unshared, filesystem
      read-only except the sandbox dir). Strongest local isolation.
    * **bwrap requested but absent**: the tool runs in a *separate subprocess*
      with a cleared environment — a weaker guarantee (no network or filesystem
      restriction). A :class:`UserWarning` is emitted so the downgrade is never
      silent; pass ``require_bwrap=True`` to hard-fail instead.
    * **non-importable callable** (lambda, closure, bound method, or a function
      defined in ``__main__``): cannot be isolated at all — it would run
      in-process via ``fork``, sharing the parent's memory, environment
      (including credentials), and file descriptors. This is refused by default
      and only runs when ``allow_fork=True`` is passed explicitly.
    """

    def __init__(
        self,
        use_bwrap: bool = True,
        sandbox_dir: str | None = None,
        *,
        require_bwrap: bool = False,
        allow_fork: bool = False,
    ) -> None:
        bwrap_available = bool(shutil.which("bwrap"))
        if use_bwrap and require_bwrap and not bwrap_available:
            raise SandboxError(
                "require_bwrap=True but bubblewrap ('bwrap') is not installed; "
                "install bubblewrap or set require_bwrap=False to accept weaker "
                "subprocess isolation."
            )
        if use_bwrap and not bwrap_available:
            warnings.warn(
                "LocalProcessSandbox: bubblewrap ('bwrap') not found on PATH — "
                "falling back to a subprocess with a cleared environment, which "
                "does NOT restrict network or filesystem access. Install bwrap "
                "for namespace isolation, or pass require_bwrap=True to fail closed.",
                UserWarning,
                stacklevel=2,
            )
        self.use_bwrap = use_bwrap and bwrap_available
        self.allow_fork = allow_fork
        self._temp_dir = None
        if sandbox_dir:
            self.sandbox_dir = sandbox_dir
        else:
            self._temp_dir = tempfile.TemporaryDirectory(prefix="gove-sandbox-")
            self.sandbox_dir = self._temp_dir.name

    def run_tool(self, tool_fn: Callable[..., Any], args: dict[str, Any]) -> Any:
        """Runs the tool_fn in a separate isolated process."""
        module_name = getattr(tool_fn, "__module__", None)
        func_name = getattr(tool_fn, "__name__", None)
        qualname = getattr(tool_fn, "__qualname__", "")

        if (
            not module_name
            or not func_name
            or func_name == "<lambda>"
            or module_name == "__main__"
            or "<locals>" in qualname
            or "." in qualname  # bound methods (Class.method), nested functions
        ):
            # A non-importable callable cannot be re-imported into an isolated
            # process. The only way to run it is an in-process ``fork`` that
            # shares the parent's memory, environment (including credentials),
            # and file descriptors — i.e. NO real isolation. Refuse unless the
            # caller explicitly opted in via ``allow_fork``.
            if not self.allow_fork:
                raise SandboxError(
                    "LocalProcessSandbox cannot isolate a non-importable callable "
                    "(lambda, closure, bound method, or __main__ function). Define "
                    "the tool at module level for real isolation, or pass "
                    "allow_fork=True to accept in-process execution with NO isolation."
                )
            import multiprocessing

            ctx = multiprocessing.get_context("fork")
            parent_conn, child_conn = ctx.Pipe()

            def child_run() -> None:
                try:
                    res = tool_fn(**args)
                    child_conn.send({"status": "success", "result": res})
                except Exception as e:
                    child_conn.send({"status": "error", "error": str(e)})

            p = ctx.Process(target=child_run)
            p.start()
            p.join(timeout=30)
            if p.is_alive():
                p.terminate()
                raise SandboxError("Local process sandbox execution timed out after 30 seconds")
            if not parent_conn.poll():
                raise SandboxError("Local process sandbox terminated without returning a value")
            data = parent_conn.recv()
            if data["status"] == "error":
                raise SandboxError(data["error"])
            return data["result"]

        # For importable functions, we write a static runner script and pass the
        # module, function, and arguments through a JSON side-channel file. No
        # external / tool-controlled data is ever interpolated into executable
        # source, so crafted argument values cannot alter the runner's code.
        try:
            spec_json = json.dumps({"module": module_name, "func": func_name, "args": args})
        except (TypeError, ValueError) as e:
            raise SandboxError(f"Sandboxed tool arguments must be JSON-serializable: {e}") from e

        runner_script = _RUNNER_SCRIPT
        script_path = os.path.join(self.sandbox_dir, "run_tool.py")
        spec_path = os.path.join(self.sandbox_dir, "run_tool_spec.json")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(runner_script)
        with open(spec_path, "w", encoding="utf-8") as f:
            f.write(spec_json)

        cmd = [sys.executable, script_path, spec_path]

        if self.use_bwrap:
            # Wrap command in bubblewrap to unshare network, IPC, mounts, in read-only sandbox.
            # We bind the virtual environment and system library directories.
            bwrap_cmd = [
                "bwrap",
                "--unshare-all",
                "--dir",
                "/tmp",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                # Bind read-only python library paths and virtual environment
                "--ro-bind",
                "/usr",
                "/usr",
                "--ro-bind",
                "/lib",
                "/lib",
                "--ro-bind",
                "/lib64",
                "/lib64",
                "--ro-bind",
                "/etc/alternatives",
                "/etc/alternatives",
            ]

            # Bind the project / workspace directory read-only so modules can be imported
            cwd = os.getcwd()
            if os.path.exists(cwd):
                bwrap_cmd.extend(["--ro-bind", cwd, cwd])

            # Bind the temp directory where the script is located read-write
            bwrap_cmd.extend(["--bind", self.sandbox_dir, self.sandbox_dir])

            # Add python executable and script
            bwrap_cmd.extend(cmd)
            cmd = bwrap_cmd

        # Get path to gove_zone src directory dynamically
        import gove_zone

        src_path = str(Path(gove_zone.__file__).resolve().parent.parent)
        package_path = str(Path(gove_zone.__file__).resolve().parent.parent.parent)

        # Clear environment variables to prevent leakage of credentials
        clean_env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": (
                src_path + os.pathsep + package_path + os.pathsep + os.environ.get("PYTHONPATH", "")
            ),
        }

        try:
            res = subprocess.run(
                cmd, capture_output=True, text=True, env=clean_env, timeout=30, check=False
            )
        except subprocess.TimeoutExpired as e:
            raise SandboxError("Local process sandbox execution timed out after 30 seconds") from e

        if res.returncode != 0:
            # Prefer the runner's own error envelope — it carries the tool's
            # exception message, which is the only useful diagnostic here (the
            # runner writes the envelope to stdout and exits 1, so stderr is
            # normally empty). The envelope is located via its marker, not by
            # parsing the whole stream: a tool that logged progress to stdout
            # before raising left its output in front of the envelope, the
            # whole-stream parse failed, and the tool's message was lost to
            # the generic exit-status fallback. Fall back to exit status +
            # stderr only when no envelope was produced, e.g. the interpreter
            # died before the runner's own try block.
            #
            # The raise MUST stay outside the parsing block: raising a
            # SandboxError inside a `try`/`except Exception` swallowed it and
            # discarded the tool's message on every failure.
            payload = _extract_envelope(res.stdout)
            if payload is not None and payload.get("status") == "error" and "error" in payload:
                raise SandboxError(str(payload["error"]))
            raise SandboxError(
                f"Sandbox process failed with exit status {res.returncode}: {res.stderr.strip()}"
            )

        # Same marker-based extraction on the success path: tool stdout ahead
        # of the envelope must not turn a successful run into a parse failure.
        # A JSON scalar/array (or a missing status/result key) is not an
        # envelope; without these guards a subscript raised a bare TypeError
        # straight through run_tool, breaking the contract that every sandbox
        # failure surfaces as SandboxError.
        data = _extract_envelope(res.stdout)
        if data is None or "status" not in data:
            raise SandboxError(f"Failed to parse sandbox output: {res.stdout.strip()}")
        if data["status"] == "error":
            if "error" in data:
                raise SandboxError(str(data["error"]))
            raise SandboxError(f"Failed to parse sandbox output: {res.stdout.strip()}")
        if "result" not in data:
            raise SandboxError(f"Failed to parse sandbox output: {res.stdout.strip()}")
        return data["result"]

    def __del__(self) -> None:
        if self._temp_dir:
            with contextlib.suppress(Exception):
                self._temp_dir.cleanup()


class E2BSandbox(SandboxProvider):
    """Remote sandbox provider using E2B.

    Executes code in a remote ephemeral Firecracker microVM.
    Requires `E2B_API_KEY` to be set in the environment or passed.

    If the ``e2b`` package is not installed, ``run_tool`` fails closed by
    raising :class:`SandboxError` — it does NOT silently fall back to running
    the tool in-process. A mock in-process fallback exists only for tests and
    must be opted into with ``allow_mock=True`` (which provides NO isolation).
    """

    def __init__(self, api_key: str | None = None, *, allow_mock: bool = False) -> None:
        self.api_key = api_key or os.environ.get("E2B_API_KEY")
        self.allow_mock = allow_mock
        self._client = None

    def run_tool(self, tool_fn: Callable[..., Any], args: dict[str, Any]) -> Any:
        """Runs the tool function by executing it in the remote E2B MicroVM."""
        if not self.api_key:
            raise SandboxError("E2B_API_KEY must be configured to use E2BSandbox")

        # In case the E2B client SDK is not installed or we are running in tests,
        # we dynamically load/mock E2B operations.
        try:
            from e2b import Sandbox  # type: ignore[import-not-found]
        except ImportError as exc:
            # Fail closed: without the e2b SDK there is no remote isolation. The
            # in-process mock is test-only and must be opted into explicitly.
            if self.allow_mock:
                return self._mock_run_tool(tool_fn, args)
            raise SandboxError(
                "E2BSandbox requires the 'e2b' package for remote microVM "
                "isolation, which is not installed. Install it, or pass "
                "allow_mock=True to run tools in-process with NO isolation "
                "(intended for tests only)."
            ) from exc

        # Write execution code as a script to run in the sandbox
        module_name = getattr(tool_fn, "__module__", None)
        func_name = getattr(tool_fn, "__name__", None)

        if not module_name or not func_name:
            raise SandboxError(
                "E2BSandbox requires importable functions (lambdas/closures not supported)"
            )

        try:
            spec_json = json.dumps({"module": module_name, "func": func_name, "args": args})
        except (TypeError, ValueError) as e:
            raise SandboxError(f"Sandboxed tool arguments must be JSON-serializable: {e}") from e

        try:
            # Connect to/create sandbox VM
            box = Sandbox(api_key=self.api_key)
            try:
                # Write the static runner plus a JSON spec side-channel; no
                # tool-controlled data is interpolated into executable source.
                box.files.write("/home/user/run_tool.py", _RUNNER_SCRIPT)
                box.files.write("/home/user/run_tool_spec.json", spec_json)
                # Run code
                execution = box.commands.run(
                    "python3 /home/user/run_tool.py /home/user/run_tool_spec.json"
                )
            finally:
                # Always release the remote VM, even if a write/run raised.
                box.close()

            if execution.exit_code != 0:
                # Same marker-based extraction as LocalProcessSandbox: the
                # shared runner emits its envelope as a marker-prefixed final
                # line so tool stdout ahead of it cannot mask the diagnostic.
                payload = _extract_envelope(execution.stdout)
                if payload is not None and payload.get("status") == "error" and "error" in payload:
                    raise SandboxError(str(payload["error"]))
                raise SandboxError(f"Remote E2B execution failed: {execution.stderr}")

            data = _extract_envelope(execution.stdout)
            if data is None:
                raise SandboxError(f"Failed to parse sandbox output: {execution.stdout.strip()}")
            if data["status"] == "error":
                raise SandboxError(data["error"])
            return data["result"]
        except Exception as e:
            if isinstance(e, SandboxError):
                raise
            raise SandboxError(f"E2B sandbox execution failed: {e}") from e

    def _mock_run_tool(self, tool_fn: Callable[..., Any], args: dict[str, Any]) -> Any:
        """Fallback mock implementation for local verification."""
        # Execute tool locally but simulate sandbox behavior
        try:
            return tool_fn(**args)
        except Exception as e:
            raise SandboxError(f"Mock E2B sandbox failed executing tool: {e}") from e
