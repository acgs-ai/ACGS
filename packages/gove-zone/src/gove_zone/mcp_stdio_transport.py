"""Fixed, isolated stdio downstream transport for the MCP action gateway."""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import AsyncExitStack, asynccontextmanager, suppress
from datetime import timedelta
from typing import Any

import anyio
from anyio.lowlevel import EventLoopToken
from anyio.streams.text import TextReceiveStream
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import get_default_environment, stdio_client
from mcp.shared.message import SessionMessage

from gove_zone.mcp_gateway import (
    MCPDownstreamCredential,
    MCPDownstreamToolList,
    MCPDownstreamToolResult,
    MCPToolDefinition,
)
from gove_zone.mcp_security import (
    MCPStdioError,
    MCPStdioReasonCode,
    MCPStdioTargetValidator,
    ValidatedMCPOrigin,
    ValidatedMCPStdioTarget,
)
from gove_zone.mcp_transport_codec import safe_call_result
from gove_zone.path_capability import AttestedDirectory, require_attested_directory
from gove_zone.side_effect_kernel import AdapterOutcomeStatus

_CREDENTIAL_META_KEY = "io.acgs/downstream-credential"
_STATE_FD_ENV = "ACGS_FIXTURE_STATE_FD"
_STATE_DEV_ENV = "ACGS_FIXTURE_STATE_DEV"
_STATE_INO_ENV = "ACGS_FIXTURE_STATE_INO"
_CAPABILITY_ENV = frozenset({_STATE_FD_ENV, _STATE_DEV_ENV, _STATE_INO_ENV})
_LEGACY_STATE_ENV = frozenset(
    {"ACGS_FIXTURE_LEDGER", "ACGS_FIXTURE_CALL_LOG", "ACGS_FIXTURE_PID_FILE"}
)


def _require_capability_platform() -> None:
    if (
        os.name != "posix"
        or not sys.platform.startswith("linux")
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
    ):
        raise MCPStdioError(MCPStdioReasonCode.INVALID_TARGET)


async def _wait_for_child(process: anyio.abc.Process) -> None:
    if process.stdin is not None:
        with suppress(anyio.ClosedResourceError, anyio.BrokenResourceError):
            await process.stdin.aclose()
    try:
        with anyio.fail_after(2):
            await process.wait()
        return
    except TimeoutError:
        with suppress(ProcessLookupError):
            process.terminate()
    try:
        with anyio.fail_after(2):
            await process.wait()
        return
    except TimeoutError:
        with suppress(ProcessLookupError):
            process.kill()
    await process.wait()


async def _close_async_resource(resource: anyio.abc.AsyncResource | None) -> None:
    if resource is None:
        return
    with suppress(anyio.ClosedResourceError, anyio.BrokenResourceError):
        await resource.aclose()


@asynccontextmanager
async def _capability_stdio_client(
    server: StdioServerParameters,
    capability: AttestedDirectory,
) -> AsyncIterator[
    tuple[
        anyio.abc.ObjectReceiveStream[SessionMessage | Exception],
        anyio.abc.ObjectSendStream[SessionMessage],
    ]
]:
    """Mirror MCP newline framing while passing exactly one retained state FD."""

    _require_capability_platform()
    require_attested_directory(capability, error_type=MCPStdioError)
    child_fd, identity = capability.duplicate_child_fd()
    environment = dict(server.env or {})
    environment.update(
        {
            _STATE_FD_ENV: str(child_fd),
            _STATE_DEV_ENV: str(identity[0]),
            _STATE_INO_ENV: str(identity[1]),
        }
    )
    try:
        process = await anyio.open_process(
            [server.command, *server.args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=server.cwd,
            env=environment,
            pass_fds=(child_fd,),
        )
    finally:
        os.close(child_fd)

    receive_writer, receive_stream = anyio.create_memory_object_stream[SessionMessage | Exception](
        0
    )
    send_stream, send_reader = anyio.create_memory_object_stream[SessionMessage](0)
    stdout_drained = anyio.Event()
    stderr_drained = anyio.Event()
    child_reaped = False

    async def read_stdout() -> None:
        if process.stdout is None:
            raise RuntimeError("MCP stdio process stdout pipe is unavailable")
        delivery_open = True

        async def deliver(value: SessionMessage | Exception) -> None:
            nonlocal delivery_open
            if not delivery_open:
                return
            try:
                await receive_writer.send(value)
            except (anyio.ClosedResourceError, anyio.BrokenResourceError):
                delivery_open = False

        try:
            async with receive_writer:
                buffer = ""
                async for chunk in TextReceiveStream(
                    process.stdout,
                    encoding=server.encoding,
                    errors=server.encoding_error_handler,
                ):
                    lines = (buffer + chunk).split("\n")
                    buffer = lines.pop()
                    for line in lines:
                        try:
                            message = types.JSONRPCMessage.model_validate_json(line)
                        except Exception as exc:
                            await deliver(exc)
                            continue
                        await deliver(SessionMessage(message))
        except (anyio.ClosedResourceError, anyio.BrokenResourceError):
            pass
        finally:
            stdout_drained.set()

    async def write_stdin() -> None:
        if process.stdin is None:
            raise RuntimeError("MCP stdio process stdin pipe is unavailable")
        try:
            async with send_reader:
                async for session_message in send_reader:
                    payload = (
                        session_message.message.model_dump_json(by_alias=True, exclude_none=True)
                        + "\n"
                    ).encode(server.encoding, errors=server.encoding_error_handler)
                    await process.stdin.send(payload)
        except (anyio.ClosedResourceError, anyio.BrokenResourceError):
            pass

    async def drain_stderr() -> None:
        if process.stderr is None:
            raise RuntimeError("MCP stdio process stderr pipe is unavailable")
        try:
            with suppress(anyio.ClosedResourceError, anyio.BrokenResourceError):
                async for _chunk in process.stderr:
                    pass
        finally:
            stderr_drained.set()

    try:
        async with anyio.create_task_group() as task_group:
            task_group.start_soon(read_stdout)
            task_group.start_soon(write_stdin)
            task_group.start_soon(drain_stderr)
            try:
                yield receive_stream, send_stream
            finally:
                with anyio.CancelScope(shield=True):
                    await _close_async_resource(send_stream)
                    await _close_async_resource(receive_stream)
                    await _wait_for_child(process)
                    child_reaped = True
                    with anyio.move_on_after(2):
                        await stdout_drained.wait()
                        await stderr_drained.wait()
                    await _close_async_resource(receive_writer)
                    await _close_async_resource(send_reader)
                task_group.cancel_scope.cancel()
    finally:
        with anyio.CancelScope(shield=True):
            if not child_reaped:
                await _wait_for_child(process)
            await _close_async_resource(send_stream)
            await _close_async_resource(send_reader)
            await _close_async_resource(receive_stream)
            await _close_async_resource(receive_writer)
            await _close_async_resource(process.stdin)
            await _close_async_resource(process.stdout)
            await _close_async_resource(process.stderr)
            await process.aclose()


class MCPFixedStdioTransport:
    """Own one persistent child session and never reconnect or fall back.

    The class is started on an AnyIO event loop. Its synchronous gateway facade
    may then be called from worker threads, including the executor's dedicated
    timeout thread, by re-entering that exact loop with the captured token.
    """

    def __init__(
        self,
        *,
        validator: MCPStdioTargetValidator,
        server_id: str,
        executable: str,
        argv: Sequence[str],
        cwd: str,
        artifact_path: str,
        environment: Mapping[str, str] | None = None,
        timeout_seconds: float = 2.0,
        state_capability: AttestedDirectory | None = None,
        capability_phase_hook: Any | None = None,
    ) -> None:
        if not isinstance(validator, MCPStdioTargetValidator):
            raise TypeError("validator must be an MCPStdioTargetValidator")
        if type(timeout_seconds) not in (int, float) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._validator = validator
        self._server_id = server_id
        self._executable = executable
        self._argv = tuple(argv)
        self._cwd = cwd
        self._artifact_path = artifact_path
        supplied_environment = dict(environment or {})
        if any(name in supplied_environment for name in _CAPABILITY_ENV):
            raise MCPStdioError(MCPStdioReasonCode.FORBIDDEN_ENVIRONMENT)
        if state_capability is not None:
            require_attested_directory(state_capability, error_type=MCPStdioError)
            if any(name in supplied_environment for name in _LEGACY_STATE_ENV):
                raise MCPStdioError(MCPStdioReasonCode.FORBIDDEN_ENVIRONMENT)
        if capability_phase_hook is not None and not callable(capability_phase_hook):
            raise TypeError("capability_phase_hook must be callable")
        self._environment = get_default_environment()
        self._environment.update(supplied_environment)
        self._timeout_seconds = float(timeout_seconds)
        self._state_capability = state_capability
        self._capability_phase_hook = capability_phase_hook
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None
        self._target: ValidatedMCPStdioTarget | None = None
        self._token: EventLoopToken | None = None
        self._lock: anyio.Lock | None = None
        self._closed = False

    @property
    def target(self) -> ValidatedMCPStdioTarget:
        if self._target is None:
            raise RuntimeError("stdio transport has not been started")
        return self._target

    async def start(self) -> ValidatedMCPStdioTarget:
        if self._stack is not None or self._closed:
            raise RuntimeError("stdio transport is single-use")
        preflight = self._validator.validate(
            server_id=self._server_id,
            executable=self._executable,
            argv=self._argv,
            cwd=self._cwd,
            artifact_path=self._artifact_path,
            environment=self._environment,
            instance_id="preflight-not-an-active-session",
        )
        # This is the last controllable boundary before the path-based exec.
        # The validator reopens and rehashes both interpreter and artifact.
        preflight = self._validator.revalidate(preflight)
        stack = AsyncExitStack()
        try:
            if self._capability_phase_hook is not None:
                self._capability_phase_hook("before-spawn")
            if self._state_capability is not None:
                self._state_capability.checkpoint()
            client = stdio_client if self._state_capability is None else _capability_stdio_client
            streams = await stack.enter_async_context(
                client(
                    StdioServerParameters(
                        command=preflight.executable,
                        args=list(preflight.argv),
                        env=dict(self._environment),
                        cwd=preflight.cwd,
                    ),
                    *(() if self._state_capability is None else (self._state_capability,)),
                )
            )
            session = await stack.enter_async_context(ClientSession(*streams))
            await session.initialize()
            try:
                target = self._validator.validate(
                    server_id=self._server_id,
                    executable=preflight.executable,
                    argv=preflight.argv,
                    cwd=preflight.cwd,
                    artifact_path=preflight.artifact_path,
                    environment=self._environment,
                    instance_id=secrets.token_urlsafe(24),
                )
            except MCPStdioError:
                raise MCPStdioError(MCPStdioReasonCode.ARTIFACT_DRIFT) from None
            if target.launch_digest != preflight.launch_digest:
                raise MCPStdioError(MCPStdioReasonCode.ARTIFACT_DRIFT)
            target = self._validator.revalidate(target)
            if self._state_capability is not None:
                self._state_capability.checkpoint()
        except BaseException:
            await stack.aclose()
            raise
        self._stack = stack
        self._session = session
        self._target = target
        self._token = anyio.lowlevel.current_token()
        self._lock = anyio.Lock()
        return target

    async def aclose(self) -> None:
        stack = self._stack
        self._closed = True
        self._session = None
        self._target = None
        self._stack = None
        if stack is not None:
            await stack.aclose()

    async def __aenter__(self) -> MCPFixedStdioTransport:
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    def list_tools(
        self,
        origin: ValidatedMCPOrigin | ValidatedMCPStdioTarget,
        credential: MCPDownstreamCredential,
    ) -> MCPDownstreamToolList:
        target = self._exact_target(origin)
        token = self._event_loop_token()
        return anyio.from_thread.run(self._list_tools, target, credential, token=token)

    def call_tool(
        self,
        origin: ValidatedMCPOrigin | ValidatedMCPStdioTarget,
        credential: MCPDownstreamCredential,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> MCPDownstreamToolResult:
        target = self._exact_target(origin)
        token = self._event_loop_token()
        return anyio.from_thread.run(
            self._call_tool,
            target,
            credential,
            tool_name,
            dict(arguments),
            token=token,
        )

    def _event_loop_token(self) -> EventLoopToken:
        if self._token is None or self._closed:
            raise RuntimeError("stdio child is unavailable before send")
        return self._token

    def _exact_target(
        self,
        origin: ValidatedMCPOrigin | ValidatedMCPStdioTarget,
    ) -> ValidatedMCPStdioTarget:
        target = self.target
        if not isinstance(origin, ValidatedMCPStdioTarget) or origin != target:
            raise MCPStdioError(MCPStdioReasonCode.SESSION_MISMATCH)
        return target

    def _active(self) -> tuple[ClientSession, anyio.Lock]:
        if self._session is None or self._lock is None or self._closed:
            raise RuntimeError("stdio child is unavailable before send")
        return self._session, self._lock

    @staticmethod
    def _credential_meta(credential: MCPDownstreamCredential) -> dict[str, Any]:
        return {
            _CREDENTIAL_META_KEY: {
                **credential.to_safe_dict(),
                "secret": credential.secret,
            }
        }

    async def _list_tools(
        self,
        target: ValidatedMCPStdioTarget,
        credential: MCPDownstreamCredential,
    ) -> MCPDownstreamToolList:
        session, lock = self._active()
        async with lock:
            if self._state_capability is not None:
                self._state_capability.checkpoint()
            self._validator.revalidate(target)
            params = types.PaginatedRequestParams(
                _meta=types.RequestParams.Meta(**self._credential_meta(credential))
            )
            with anyio.fail_after(self._timeout_seconds):
                result = await session.list_tools(params=params)
        definitions = tuple(
            MCPToolDefinition(
                name=tool.name,
                description=tool.description or "",
                input_schema=tool.inputSchema,
            )
            for tool in result.tools
        )
        return MCPDownstreamToolList(
            definitions,
            transport_binding=target.transport_binding,
        )

    async def _call_tool(
        self,
        target: ValidatedMCPStdioTarget,
        credential: MCPDownstreamCredential,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> MCPDownstreamToolResult:
        session, lock = self._active()
        async with lock:
            if self._state_capability is not None:
                self._state_capability.checkpoint()
            self._validator.revalidate(target)
            try:
                with anyio.fail_after(self._timeout_seconds):
                    result = await session.call_tool(
                        tool_name,
                        arguments,
                        read_timeout_seconds=timedelta(seconds=self._timeout_seconds),
                        meta=self._credential_meta(credential),
                    )
                if self._state_capability is not None:
                    self._state_capability.checkpoint()
            except BaseException as exc:
                if isinstance(exc, anyio.get_cancelled_exc_class()):
                    raise
                return MCPDownstreamToolResult(
                    AdapterOutcomeStatus.UNKNOWN,
                    None,
                    transport_binding=target.transport_binding,
                )
        if result.isError:
            return MCPDownstreamToolResult(
                AdapterOutcomeStatus.UNKNOWN,
                None,
                transport_binding=target.transport_binding,
            )
        payload = safe_call_result(
            result,
            credential,
            reserved_keys=(_CREDENTIAL_META_KEY,),
        )
        if payload is None:
            return MCPDownstreamToolResult(
                AdapterOutcomeStatus.UNKNOWN,
                None,
                transport_binding=target.transport_binding,
            )
        return MCPDownstreamToolResult(
            AdapterOutcomeStatus.CONFIRMED_SUCCEEDED,
            payload,
            transport_binding=target.transport_binding,
        )


__all__ = ["MCPFixedStdioTransport"]
