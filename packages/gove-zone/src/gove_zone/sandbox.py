"""Sandbox execution providers for gove-zone.

Provides isolation layers for executing tool calls, including local process
namespace isolation (via bubblewrap/gVisor if available, otherwise restricted
subprocesses) and remote sandbox execution (via E2B microVMs).
"""

from __future__ import annotations

import ast
import base64
import contextlib
import dis
import hashlib
import hmac
import json
import math
import os
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import types
import weakref
from abc import ABC, abstractmethod
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from gove_zone.errors import GoveZoneError


class SandboxError(GoveZoneError):
    """Raised when sandbox creation or execution fails."""

    pass


_MAX_ARTIFACT_BYTES = 512 * 1024
_MAX_ENVELOPE_BYTES = 1024 * 1024
_MAX_RESPONSE_PAYLOAD_BYTES = 1024 * 1024
_MAX_JSON_DEPTH = 64
_MAX_JSON_NODES = 10_000
_FRAME_MAGIC = b"GZSF"
_FRAME_VERSION = 1
_FRAME_HEADER = struct.Struct(">4sBI")
_FRAME_DIGEST_BYTES = hashlib.sha256().digest_size
_MAX_FRAME_BYTES = _FRAME_HEADER.size + _MAX_RESPONSE_PAYLOAD_BYTES + _FRAME_DIGEST_BYTES + 1


def _copy_exact_json_tree(value: Any) -> Any:
    """Copy an exact built-in JSON tree while rejecting coercion and resource abuse."""
    active: set[int] = set()
    nodes = 0

    def reject(path: str, reason: str) -> None:
        raise SandboxError(f"Sandbox JSON rejected at {path}: {reason}")

    def copy_node(node: Any, depth: int, path: str) -> Any:
        nonlocal nodes
        if depth > _MAX_JSON_DEPTH:
            reject(path, "maximum depth exceeded")
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            reject(path, "maximum node count exceeded")

        node_type = type(node)
        if node is None or node_type is bool or node_type is int or node_type is str:
            return node
        if node_type is float:
            if not math.isfinite(node):
                reject(path, "non-finite number")
            return node
        if node_type is list:
            identity = id(node)
            if identity in active:
                reject(path, "cycle detected")
            active.add(identity)
            try:
                return [
                    copy_node(item, depth + 1, f"{path}[{index}]")
                    for index, item in enumerate(node)
                ]
            finally:
                active.remove(identity)
        if node_type is dict:
            identity = id(node)
            if identity in active:
                reject(path, "cycle detected")
            active.add(identity)
            try:
                copied: dict[str, Any] = {}
                for key, item in node.items():
                    nodes += 1
                    if nodes > _MAX_JSON_NODES:
                        reject(path, "maximum node count exceeded")
                    if type(key) is not str:
                        reject(path, "object key is not an exact string")
                    child_path = f"{path}.{key}" if key.isidentifier() and len(key) <= 64 else path
                    copied[key] = copy_node(item, depth + 1, child_path)
                return copied
            finally:
                active.remove(identity)
        reject(path, "unsupported exact type")

    return copy_node(value, 0, "$")


def _canonical_code_filename(filename: str) -> bytes:
    if type(filename) is not str:
        raise SandboxError("LocalProcessSandbox code filename is unsafe")
    path = Path(filename)
    if not path.is_absolute():
        raise SandboxError("LocalProcessSandbox code filename must be absolute")
    try:
        canonical = path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise SandboxError("LocalProcessSandbox code filename cannot be canonicalized") from exc
    return str(canonical).encode("utf-8", errors="surrogatepass")


def _code_identity_bytes(code: types.CodeType) -> bytes:
    """Serialize stable code identity fields without repr or loader trust."""
    output = bytearray(b"GZCI\x02")

    def add_blob(tag: bytes, blob: bytes) -> None:
        output.extend(tag)
        output.extend(len(blob).to_bytes(8, "big"))
        output.extend(blob)

    def encoded_constant(item: Any) -> bytes:
        item_type = type(item)
        if item is None:
            return b"N"
        if item is Ellipsis:
            return b"E"
        if item_type is bool:
            return b"B1" if item else b"B0"
        if item_type is int:
            int_item = cast(int, item)
            magnitude = abs(int_item)
            encoded = magnitude.to_bytes(max(1, (magnitude.bit_length() + 7) // 8), "big")
            return b"I" + (b"-" if int_item < 0 else b"+") + encoded
        if item_type is float:
            return b"F" + struct.pack(">d", item)
        if item_type is complex:
            return b"X" + struct.pack(">dd", item.real, item.imag)
        if item_type is str:
            return b"S" + cast(str, item).encode("utf-8", errors="surrogatepass")
        if item_type is bytes:
            return b"Y" + cast(bytes, item)
        if item_type is tuple:
            values = [encoded_constant(value) for value in item]
            return b"T" + b"".join(len(value).to_bytes(8, "big") + value for value in values)
        if item_type is frozenset:
            values = sorted(encoded_constant(value) for value in item)
            return b"R" + b"".join(len(value).to_bytes(8, "big") + value for value in values)
        if item_type is types.CodeType:
            return b"C" + _code_identity_bytes(item)
        raise SandboxError("LocalProcessSandbox code contains unsupported constant")

    for number in (
        code.co_argcount,
        code.co_posonlyargcount,
        code.co_kwonlyargcount,
        code.co_nlocals,
        code.co_stacksize,
        code.co_flags,
        code.co_firstlineno,
    ):
        add_blob(b"#", number.to_bytes(8, "big", signed=False))
    add_blob(b"M", code.co_name.encode("utf-8"))
    add_blob(b"Q", code.co_qualname.encode("utf-8"))
    add_blob(b"F", _canonical_code_filename(code.co_filename))
    add_blob(b"O", code.co_code)
    add_blob(b"L", code.co_linetable)
    add_blob(b"l", encoded_constant(tuple(code.co_lines())))
    add_blob(b"p", encoded_constant(tuple(code.co_positions())))
    add_blob(b"E", code.co_exceptiontable)
    add_blob(b"K", encoded_constant(code.co_consts))
    for tag, values in (
        (b"n", code.co_names),
        (b"v", code.co_varnames),
        (b"f", code.co_freevars),
        (b"c", code.co_cellvars),
    ):
        add_blob(tag, b"\0".join(value.encode("utf-8") for value in values))
    return bytes(output)


_DYNAMIC_NAMESPACE_NAMES = frozenset(
    {
        "globals",
        "locals",
        "vars",
        "eval",
        "exec",
        "compile",
        "getattr",
        "setattr",
        "delattr",
        "__import__",
        "__builtins__",
    }
)

_FORBIDDEN_REFLECTION_ATTRIBUTES = frozenset(
    {
        "__globals__",
        "__code__",
        "__closure__",
        "__defaults__",
        "__kwdefaults__",
        "__annotations__",
        "__dict__",
        "__getattribute__",
        "__class__",
        "__mro__",
        "__bases__",
        "__base__",
        "__subclasses__",
        "mro",
        "_getframe",
        "currentframe",
        "f_back",
        "f_builtins",
        "f_code",
        "f_globals",
        "f_lasti",
        "f_lineno",
        "f_locals",
        "f_trace",
        "f_trace_lines",
        "f_trace_opcodes",
        "gi_frame",
        "cr_frame",
        "ag_frame",
        "tb_frame",
        "tb_next",
        "tb_lasti",
        "tb_lineno",
    }
)

_FORBIDDEN_BUILTINS_IMPORTS = _DYNAMIC_NAMESPACE_NAMES | _FORBIDDEN_REFLECTION_ATTRIBUTES


def _reject_forbidden_module_imports(tree: ast.Module) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(
            alias.name == "builtins" or alias.name.startswith("builtins.") for alias in node.names
        ):
            raise SandboxError("unsupported_dynamic_builtins_import")
        if (
            isinstance(node, ast.ImportFrom)
            and node.module == "builtins"
            and any(
                alias.name == "*" or alias.name in _FORBIDDEN_BUILTINS_IMPORTS
                for alias in node.names
            )
        ):
            raise SandboxError("unsupported_dynamic_builtins_import")


def _reject_dynamic_namespace_access(
    function_node: ast.FunctionDef,
    func_name: str,
    *code_objects: types.CodeType,
) -> None:
    parents = {
        child: parent
        for parent in ast.walk(function_node)
        for child in ast.iter_child_nodes(parent)
    }
    for node in ast.walk(function_node):
        if isinstance(node, ast.Name) and node.id in _DYNAMIC_NAMESPACE_NAMES:
            raise SandboxError("unsupported_dynamic_namespace_access")
        if isinstance(node, ast.Attribute) and node.attr in _DYNAMIC_NAMESPACE_NAMES:
            raise SandboxError("unsupported_dynamic_namespace_access")
        if isinstance(node, ast.Attribute) and node.attr in _FORBIDDEN_REFLECTION_ATTRIBUTES:
            raise SandboxError("unsupported_reflection_access")
        if isinstance(node, ast.Name) and node.id == func_name:
            parent = parents.get(node)
            if not (isinstance(parent, ast.Call) and parent.func is node):
                raise SandboxError("unsupported_target_reference")

    pending = list(code_objects)
    while pending:
        code = pending.pop()
        for instruction in dis.get_instructions(code):
            if (
                instruction.opname in {"LOAD_GLOBAL", "LOAD_NAME", "LOAD_ATTR", "LOAD_METHOD"}
                and type(instruction.argval) is str
                and instruction.argval in _DYNAMIC_NAMESPACE_NAMES
            ):
                raise SandboxError("unsupported_dynamic_namespace_access")
            if (
                instruction.opname in {"LOAD_ATTR", "LOAD_METHOD", "LOAD_SUPER_ATTR"}
                and type(instruction.argval) is str
                and instruction.argval in _FORBIDDEN_REFLECTION_ATTRIBUTES
            ):
                raise SandboxError("unsupported_reflection_access")
        pending.extend(item for item in code.co_consts if type(item) is types.CodeType)


def _literal_json_state(node: ast.expr, path: str) -> Any:
    try:
        value = ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError) as exc:
        raise SandboxError(f"LocalProcessSandbox state at {path} is not a JSON literal") from exc
    try:
        return _copy_exact_json_tree(value)
    except SandboxError as exc:
        raise SandboxError(f"LocalProcessSandbox state at {path} is not exact JSON") from exc


def _source_annotations(function_node: ast.FunctionDef, future_annotations: bool) -> dict[str, str]:
    annotations: dict[str, str] = {}
    arguments = [
        *function_node.args.posonlyargs,
        *function_node.args.args,
        *function_node.args.kwonlyargs,
    ]
    if function_node.args.vararg is not None:
        arguments.append(function_node.args.vararg)
    if function_node.args.kwarg is not None:
        arguments.append(function_node.args.kwarg)
    for argument in arguments:
        if argument.annotation is not None:
            annotations[argument.arg] = _canonical_source_annotation(
                argument.annotation, future_annotations
            )
    if function_node.returns is not None:
        annotations["return"] = _canonical_source_annotation(
            function_node.returns, future_annotations
        )
    return annotations


def _canonical_source_annotation(node: ast.expr, future_annotations: bool) -> str:
    if future_annotations:
        return "future:" + ast.unparse(node)
    safe_names = {"bool", "bytes", "dict", "float", "int", "list", "str"}
    if isinstance(node, ast.Name) and node.id in safe_names:
        return "builtin:" + node.id
    if isinstance(node, ast.Constant) and type(node.value) is str:
        return "string:" + node.value
    if isinstance(node, ast.Constant) and node.value is None:
        return "none:"
    raise SandboxError("LocalProcessSandbox source contains an unsafe annotation")


def _canonical_parent_annotation(value: Any, future_annotations: bool) -> str:
    if future_annotations:
        if type(value) is not str:
            raise SandboxError("LocalProcessSandbox runtime annotation state is unsafe")
        return "future:" + value
    builtin_annotations = {
        bool: "builtin:bool",
        bytes: "builtin:bytes",
        dict: "builtin:dict",
        float: "builtin:float",
        int: "builtin:int",
        list: "builtin:list",
        str: "builtin:str",
    }
    for builtin_value, canonical in builtin_annotations.items():
        if value is builtin_value:
            return canonical
    if type(value) is str:
        return "string:" + value
    if value is None:
        return "none:"
    raise SandboxError("LocalProcessSandbox runtime annotation state is unsafe")


def _attest_callable_state(
    tool_fn: Callable[..., Any],
    source: bytes,
    origin: Path,
    func_name: str,
    tree: ast.Module,
) -> str:
    if type(tool_fn) is not types.FunctionType:
        raise SandboxError("LocalProcessSandbox callable must be an exact Python function")
    parent_code = getattr(tool_fn, "__code__", None)
    if type(parent_code) is not types.CodeType:
        raise SandboxError("LocalProcessSandbox callable has no verifiable code identity")
    if tool_fn.__closure__ is not None or parent_code.co_freevars:
        raise SandboxError("LocalProcessSandbox rejects callable closures")
    _reject_forbidden_module_imports(tree)
    try:
        canonical_origin = origin.resolve(strict=True)
        module_code = compile(source, str(canonical_origin), "exec", dont_inherit=True)
    except (OSError, RuntimeError, SyntaxError, ValueError, TypeError) as exc:
        raise SandboxError("LocalProcessSandbox source snapshot cannot be compiled") from exc
    candidates = [
        item
        for item in module_code.co_consts
        if type(item) is types.CodeType
        and item.co_name == func_name
        and item.co_qualname == func_name
    ]
    if len(candidates) != 1:
        raise SandboxError("LocalProcessSandbox cannot locate callable code in source snapshot")
    parent_digest = hashlib.sha256(_code_identity_bytes(parent_code)).digest()
    source_digest = hashlib.sha256(_code_identity_bytes(candidates[0])).digest()
    if not hmac.compare_digest(parent_digest, source_digest):
        raise SandboxError("LocalProcessSandbox callable code identity does not match source")

    function_nodes = [
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == func_name
    ]
    if len(function_nodes) != 1:
        raise SandboxError("LocalProcessSandbox cannot locate top-level function state")
    function_node = function_nodes[0]
    _reject_dynamic_namespace_access(function_node, func_name, parent_code, candidates[0])

    source_defaults = [
        _literal_json_state(node, f"$.defaults[{index}]")
        for index, node in enumerate(function_node.args.defaults)
    ]
    parent_defaults = tool_fn.__defaults__
    if parent_defaults is None:
        copied_defaults: list[Any] = []
    elif type(parent_defaults) is tuple:
        copied_defaults = [_copy_exact_json_tree(value) for value in parent_defaults]
    else:
        raise SandboxError("LocalProcessSandbox runtime defaults state is unsafe")
    if _canonical_json_bytes(source_defaults) != _canonical_json_bytes(copied_defaults):
        raise SandboxError("LocalProcessSandbox runtime defaults differ from source")

    source_kwdefaults = {
        argument.arg: _literal_json_state(node, f"$.kwdefaults.{argument.arg}")
        for argument, node in zip(
            function_node.args.kwonlyargs, function_node.args.kw_defaults, strict=True
        )
        if node is not None
    }
    parent_kwdefaults = tool_fn.__kwdefaults__
    if parent_kwdefaults is None:
        copied_kwdefaults: dict[str, Any] = {}
    elif type(parent_kwdefaults) is dict:
        copied = _copy_exact_json_tree(parent_kwdefaults)
        if type(copied) is not dict:
            raise SandboxError("LocalProcessSandbox runtime kwdefaults state is unsafe")
        copied_kwdefaults = copied
    else:
        raise SandboxError("LocalProcessSandbox runtime kwdefaults state is unsafe")
    if _canonical_json_bytes(source_kwdefaults) != _canonical_json_bytes(copied_kwdefaults):
        raise SandboxError("LocalProcessSandbox runtime kwdefaults differ from source")

    future_annotations = any(
        isinstance(node, ast.ImportFrom)
        and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
        for node in tree.body
    )
    source_annotations = _source_annotations(function_node, future_annotations)
    parent_annotations = tool_fn.__annotations__
    if type(parent_annotations) is not dict or any(
        type(key) is not str for key in parent_annotations
    ):
        raise SandboxError("LocalProcessSandbox runtime annotation state is unsafe")
    canonical_parent_annotations = {
        key: _canonical_parent_annotation(value, future_annotations)
        for key, value in parent_annotations.items()
    }
    if source_annotations != canonical_parent_annotations:
        raise SandboxError("LocalProcessSandbox runtime annotations differ from source")

    literal_globals: dict[str, Any] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                raise SandboxError("unsupported_source_artifact")
            try:
                literal_globals[node.targets[0].id] = _literal_json_state(
                    node.value, f"$.globals.{node.targets[0].id}"
                )
            except SandboxError:
                continue
        elif isinstance(node, ast.AnnAssign):
            if not isinstance(node.target, ast.Name):
                raise SandboxError("unsupported_source_artifact")
            if node.value is None:
                continue
            try:
                literal_globals[node.target.id] = _literal_json_state(
                    node.value, f"$.globals.{node.target.id}"
                )
            except SandboxError:
                continue
        elif isinstance(node, ast.AugAssign):
            raise SandboxError("unsupported_source_artifact")
    for name in sorted(set(parent_code.co_names) & set(literal_globals)):
        parent_globals = tool_fn.__globals__
        if name not in parent_globals:
            raise SandboxError("LocalProcessSandbox referenced global is missing at runtime")
        runtime_value = _copy_exact_json_tree(parent_globals[name])
        if _canonical_json_bytes(runtime_value) != _canonical_json_bytes(literal_globals[name]):
            raise SandboxError("LocalProcessSandbox referenced global differs from source")
    return parent_digest.hex()


def _parse_standalone_source(source: bytes, origin: Path) -> ast.Module:
    try:
        tree = ast.parse(source, filename=str(origin))
    except (SyntaxError, ValueError, TypeError) as exc:
        raise SandboxError("LocalProcessSandbox source snapshot cannot be parsed") from exc
    if any(isinstance(node, ast.ImportFrom) and node.level > 0 for node in ast.walk(tree)):
        raise SandboxError(
            "LocalProcessSandbox standalone snapshot rejects relative imports; "
            "transitive imports are not artifact-bound"
        )
    return tree


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise SandboxError("Sandbox request is not canonical JSON") from exc


def _read_module_snapshot(module_name: str) -> tuple[Path, Path, bytes, bool]:
    """Open and attest a source module, then read an immutable bounded snapshot."""
    if not module_name or not all(part.isidentifier() for part in module_name.split(".")):
        raise SandboxError("LocalProcessSandbox requires a valid importable module name")
    module = sys.modules.get(module_name)
    if module is None:
        raise SandboxError(f"LocalProcessSandbox cannot resolve module {module_name!r}")

    spec = getattr(module, "__spec__", None)
    if (
        getattr(module, "__name__", None) != module_name
        or spec is None
        or getattr(spec, "name", None) != module_name
    ):
        raise SandboxError(f"LocalProcessSandbox module identity does not match {module_name!r}")

    candidate = getattr(spec, "origin", None)
    if not isinstance(candidate, str) or candidate in {"built-in", "frozen"}:
        raise SandboxError(f"LocalProcessSandbox cannot resolve module origin for {module_name!r}")
    candidate_path = Path(candidate)
    if not candidate_path.is_absolute():
        raise SandboxError(
            f"LocalProcessSandbox module origin must be absolute for {module_name!r}"
        )
    try:
        origin = candidate_path.resolve(strict=True)
        origin_lstat = os.lstat(candidate_path)
    except (OSError, RuntimeError) as exc:
        raise SandboxError(
            f"LocalProcessSandbox cannot resolve module origin for {module_name!r}"
        ) from exc
    if candidate_path != origin or stat.S_ISLNK(origin_lstat.st_mode):
        raise SandboxError(f"LocalProcessSandbox rejects symlinked origin for {module_name!r}")
    if not stat.S_ISREG(origin_lstat.st_mode):
        raise SandboxError(f"LocalProcessSandbox module origin is not a file for {module_name!r}")

    module_file = getattr(module, "__file__", None)
    if not isinstance(module_file, str) or not Path(module_file).is_absolute():
        raise SandboxError(f"LocalProcessSandbox module file must be absolute for {module_name!r}")
    try:
        resolved_module_file = Path(module_file).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SandboxError(
            f"LocalProcessSandbox cannot resolve module file for {module_name!r}"
        ) from exc
    if resolved_module_file != origin:
        raise SandboxError(f"LocalProcessSandbox module origin is inconsistent for {module_name!r}")

    module_parts = module_name.split(".")
    if origin.name == "__init__.py":
        package_parts = module_parts
        is_package = True
    elif origin.name == f"{module_parts[-1]}.py":
        package_parts = module_parts[:-1]
        is_package = False
    else:
        raise SandboxError(f"LocalProcessSandbox module origin does not match {module_name!r}")

    import_root = origin.parent
    for expected_part in reversed(package_parts):
        if import_root.name != expected_part:
            raise SandboxError(f"LocalProcessSandbox module origin does not match {module_name!r}")
        import_root = import_root.parent
    try:
        resolved_import_root = import_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SandboxError(
            f"LocalProcessSandbox cannot resolve import root for {module_name!r}"
        ) from exc
    if not resolved_import_root.is_dir():
        raise SandboxError(
            f"LocalProcessSandbox import root is not a directory for {module_name!r}"
        )

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(origin, flags)
    except OSError as exc:
        raise SandboxError(f"LocalProcessSandbox cannot open source for {module_name!r}") from exc
    try:
        opened_stat = os.fstat(source_fd)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise SandboxError(f"LocalProcessSandbox source is not regular for {module_name!r}")
        if (opened_stat.st_dev, opened_stat.st_ino) != (
            origin_lstat.st_dev,
            origin_lstat.st_ino,
        ):
            raise SandboxError(f"LocalProcessSandbox source changed while opening {module_name!r}")
        if opened_stat.st_size > _MAX_ARTIFACT_BYTES:
            raise SandboxError("LocalProcessSandbox source exceeds artifact size limit")
        chunks: list[bytes] = []
        remaining = _MAX_ARTIFACT_BYTES + 1
        while remaining:
            chunk = os.read(source_fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        source = b"".join(chunks)
        if len(source) > _MAX_ARTIFACT_BYTES:
            raise SandboxError("LocalProcessSandbox source exceeds artifact size limit")
        final_stat = os.fstat(source_fd)
        if (
            final_stat.st_size != opened_stat.st_size
            or final_stat.st_mtime_ns != opened_stat.st_mtime_ns
        ):
            raise SandboxError(f"LocalProcessSandbox source changed while reading {module_name!r}")
    finally:
        os.close(source_fd)
    return origin, resolved_import_root, source, is_package


def _read_bounded_frame(read_fd: int) -> bytes:
    data = bytearray()
    try:
        while len(data) < _MAX_FRAME_BYTES:
            chunk = os.read(read_fd, min(64 * 1024, _MAX_FRAME_BYTES - len(data)))
            if not chunk:
                break
            data.extend(chunk)
    finally:
        os.close(read_fd)
    return bytes(data)


def _terminate_process_group(process: subprocess.Popen[bytes], reader: threading.Thread) -> None:
    """Terminate the worker group, close inherited writers, and reap the leader."""
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    reader.join(timeout=0.2)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=0.2)
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    if process.poll() is None:
        process.wait()
    else:
        process.wait()
    reader.join(timeout=1)


def _decode_response_frame(
    frame: bytes, request_digest: str, source_file_digest: str, code_identity_digest: str
) -> Any:
    minimum = _FRAME_HEADER.size + _FRAME_DIGEST_BYTES
    if len(frame) < minimum:
        raise SandboxError("Sandbox response frame is empty or truncated")
    magic, version, payload_length = _FRAME_HEADER.unpack(frame[: _FRAME_HEADER.size])
    if magic != _FRAME_MAGIC or version != _FRAME_VERSION:
        raise SandboxError("Sandbox response frame has invalid magic or version")
    if payload_length > _MAX_RESPONSE_PAYLOAD_BYTES:
        raise SandboxError("Sandbox response payload exceeds size limit")
    expected_length = _FRAME_HEADER.size + payload_length + _FRAME_DIGEST_BYTES
    if len(frame) != expected_length:
        raise SandboxError("Sandbox response frame is truncated or contains extra data")
    payload_end = _FRAME_HEADER.size + payload_length
    payload_bytes = frame[_FRAME_HEADER.size : payload_end]
    supplied_digest = frame[payload_end:]
    expected_digest = hashlib.sha256(frame[:payload_end]).digest()
    if not hmac.compare_digest(supplied_digest, expected_digest):
        raise SandboxError("Sandbox response frame digest mismatch")

    def reject_constant(value: str) -> Any:
        raise ValueError(f"invalid JSON constant {value}")

    try:
        decoded = json.loads(payload_bytes.decode("utf-8"), parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise SandboxError("Sandbox response payload is not strict JSON") from exc
    payload = _copy_exact_json_tree(decoded)
    if type(payload) is not dict:
        raise SandboxError("Sandbox response payload must be an object")
    if payload.get("request_sha256") != request_digest:
        raise SandboxError("Sandbox response request binding mismatch")
    if payload.get("source_file_sha256") != source_file_digest:
        raise SandboxError("Sandbox response source-file binding mismatch")
    if payload.get("code_identity_sha256") != code_identity_digest:
        raise SandboxError("Sandbox response code-identity binding mismatch")
    if payload.get("artifact_scope") != "source_file_only":
        raise SandboxError("Sandbox response artifact scope mismatch")
    if payload.get("dependency_binding") != "unbound_trusted_environment":
        raise SandboxError("Sandbox response dependency scope mismatch")
    status = payload.get("status")
    if status == "error":
        error = payload.get("error")
        if type(error) is not str or not error:
            raise SandboxError("Sandbox error response is malformed")
        raise SandboxError(error)
    if status != "success" or "result" not in payload:
        raise SandboxError("Sandbox success response is malformed")
    return payload["result"]


_ISOLATED_RUNNER = r"""
import base64
import hashlib
import importlib.util
import json
import math
import os
import struct
import sys
import types

MAX_ENVELOPE = 1024 * 1024
MAX_ARTIFACT = 512 * 1024
MAX_PAYLOAD = 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 10000
MAGIC = b"GZSF"
VERSION = 1
HEADER = struct.Struct(">4sBI")

def fail_constant(value):
    raise ValueError("invalid JSON constant")

def exact_tree(value):
    active = set()
    count = [0]
    def visit(node, depth):
        if depth > MAX_DEPTH:
            raise ValueError("JSON depth exceeded")
        count[0] += 1
        if count[0] > MAX_NODES:
            raise ValueError("JSON node count exceeded")
        kind = type(node)
        if node is None or kind is bool or kind is int or kind is str:
            return node
        if kind is float:
            if not math.isfinite(node):
                raise ValueError("non-finite JSON number")
            return node
        if kind is list:
            identity = id(node)
            if identity in active:
                raise ValueError("JSON cycle")
            active.add(identity)
            try:
                return [visit(item, depth + 1) for item in node]
            finally:
                active.remove(identity)
        if kind is dict:
            identity = id(node)
            if identity in active:
                raise ValueError("JSON cycle")
            active.add(identity)
            try:
                copied = {}
                for key, item in node.items():
                    count[0] += 1
                    if count[0] > MAX_NODES or type(key) is not str:
                        raise ValueError("invalid JSON object")
                    copied[key] = visit(item, depth + 1)
                return copied
            finally:
                active.remove(identity)
        raise ValueError("unsupported JSON type")
    return visit(value, 0)

def write_all(fd, data):
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise OSError("short protocol write")
        offset += written

response_fd = int(sys.argv[1])
sys.argv = ["<gove-zone-isolated-runner>"]
raw_request = sys.stdin.buffer.read(MAX_ENVELOPE + 1)
request_digest = hashlib.sha256(raw_request).hexdigest()
source_file_digest = ""
code_identity_digest = ""
try:
    if len(raw_request) > MAX_ENVELOPE:
        raise ValueError("request envelope too large")
    request = exact_tree(json.loads(raw_request.decode("ascii"), parse_constant=fail_constant))
    if type(request) is not dict:
        raise ValueError("request envelope must be an object")
    source_file_digest = request["source_file_sha256"]
    code_identity_digest = request["code_identity_sha256"]
    if type(source_file_digest) is not str or type(code_identity_digest) is not str:
        raise ValueError("invalid source or code identity digest")
    if request["artifact_scope"] != "source_file_only":
        raise ValueError("invalid artifact scope")
    if request["dependency_binding"] != "unbound_trusted_environment":
        raise ValueError("invalid dependency binding")
    source = base64.b64decode(request["source_b64"], validate=True)
    if len(source) > MAX_ARTIFACT:
        raise ValueError("artifact too large")
    if hashlib.sha256(source).hexdigest() != source_file_digest:
        raise ValueError("source file digest mismatch")
    module_name = request["module_name"]
    func_name = request["func_name"]
    origin = request["origin"]
    import_root = request["import_root"]
    is_package = request["is_package"]
    args = request["args"]
    if not (
        type(module_name) is str
        and type(func_name) is str
        and type(origin) is str
        and type(import_root) is str
        and type(is_package) is bool
        and type(args) is dict
    ):
        raise ValueError("invalid request field types")
    sys.path.insert(0, import_root)
    parts = module_name.split(".")
    for index in range(1, len(parts)):
        parent_name = ".".join(parts[:index])
        if parent_name in sys.modules:
            raise ValueError("module parent already loaded")
        parent = types.ModuleType(parent_name)
        parent_path = os.path.join(import_root, *parts[:index])
        parent_spec = importlib.util.spec_from_loader(parent_name, loader=None, is_package=True)
        if parent_spec is None:
            raise ValueError("cannot create parent package")
        parent_spec.submodule_search_locations = [parent_path]
        parent.__spec__ = parent_spec
        parent.__package__ = parent_name
        parent.__path__ = [parent_path]
        sys.modules[parent_name] = parent
    spec = importlib.util.spec_from_loader(
        module_name, loader=None, origin=origin, is_package=is_package
    )
    if spec is None:
        raise ValueError("cannot create snapshot module")
    if is_package:
        spec.submodule_search_locations = [os.path.dirname(origin)]
    module = types.ModuleType(module_name)
    module.__file__ = origin
    module.__loader__ = None
    module.__spec__ = spec
    module.__package__ = module_name if is_package else module_name.rpartition(".")[0]
    if is_package:
        module.__path__ = [os.path.dirname(origin)]
    sys.modules[module_name] = module
    exec(compile(source, origin, "exec"), module.__dict__)
    function = getattr(module, func_name)
    result = exact_tree(function(**args))
    payload = {
        "status": "success",
        "request_sha256": request_digest,
        "source_file_sha256": source_file_digest,
        "code_identity_sha256": code_identity_digest,
        "artifact_scope": "source_file_only",
        "dependency_binding": "unbound_trusted_environment",
        "result": result,
    }
except BaseException as exc:
    payload = {
        "status": "error",
        "request_sha256": request_digest,
        "source_file_sha256": source_file_digest,
        "code_identity_sha256": code_identity_digest,
        "artifact_scope": "source_file_only",
        "dependency_binding": "unbound_trusted_environment",
        "error": str(exc) or type(exc).__name__,
    }

try:
    payload_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    if len(payload_bytes) > MAX_PAYLOAD:
        raise ValueError("response payload too large")
    header = HEADER.pack(MAGIC, VERSION, len(payload_bytes))
    frame = header + payload_bytes + hashlib.sha256(header + payload_bytes).digest()
    write_all(response_fd, frame)
finally:
    os.close(response_fd)
"""


class SandboxProvider(ABC):
    """Base class for all sandbox execution providers."""

    @abstractmethod
    def run_tool(self, tool_fn: Callable[..., Any], args: dict[str, Any]) -> Any:
        """Execute a tool function with arguments inside the isolated sandbox."""
        pass


class LocalProcessSandbox(SandboxProvider):
    """Execute an attested Python source snapshot in an isolated subprocess."""

    def __init__(self, use_bwrap: bool = True, sandbox_dir: str | None = None) -> None:
        self.use_bwrap = use_bwrap
        self._bwrap_path = shutil.which("bwrap") if use_bwrap else None
        self._owns_sandbox_dir = sandbox_dir is None
        self._cleanup_finalizer: weakref.finalize[..., LocalProcessSandbox] | None = None
        if sandbox_dir is not None:
            self.sandbox_dir = sandbox_dir
        else:
            self.sandbox_dir = tempfile.mkdtemp(prefix="gove-sandbox-")
            self._cleanup_finalizer = weakref.finalize(
                self,
                shutil.rmtree,
                self.sandbox_dir,
                ignore_errors=True,
            )

    def close(self) -> None:
        """Release an owned sandbox directory exactly once."""
        finalizer = self._cleanup_finalizer
        if finalizer is not None and finalizer.alive:
            finalizer()

    def __enter__(self) -> LocalProcessSandbox:
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: types.TracebackType | None,
    ) -> None:
        self.close()

    def run_tool(self, tool_fn: Callable[..., Any], args: dict[str, Any]) -> Any:
        """Run an attested source snapshot in a separate isolated process."""
        if self.use_bwrap:
            if self._bwrap_path is None:
                raise SandboxError("LocalProcessSandbox bubblewrap binary is unavailable")
            raise SandboxError(
                "LocalProcessSandbox cannot safely preserve the anonymous protocol FD "
                "through bubblewrap"
            )

        if type(tool_fn) is not types.FunctionType:
            raise SandboxError("unsupported_callable_locator")

        module_name = getattr(tool_fn, "__module__", None)
        func_name = getattr(tool_fn, "__name__", None)
        qualname = getattr(tool_fn, "__qualname__", "")

        if (
            not module_name
            or not func_name
            or func_name == "<lambda>"
            or module_name == "__main__"
            or "<locals>" in qualname
        ):
            raise SandboxError("LocalProcessSandbox requires an importable module-level function")
        module = sys.modules.get(module_name)
        if module is None or getattr(module, func_name, None) is not tool_fn:
            raise SandboxError(
                f"LocalProcessSandbox cannot import {module_name!r}.{func_name} exactly"
            )
        if type(args) is not dict:
            raise SandboxError("LocalProcessSandbox arguments must be an exact dictionary")
        copied_args = _copy_exact_json_tree(args)
        if type(copied_args) is not dict:
            raise SandboxError("LocalProcessSandbox arguments must be an exact dictionary")

        callable_origin, callable_import_root, source, is_package = _read_module_snapshot(
            module_name
        )
        source_tree = _parse_standalone_source(source, callable_origin)
        code_identity_digest = _attest_callable_state(
            tool_fn, source, callable_origin, func_name, source_tree
        )
        source_file_digest = hashlib.sha256(source).hexdigest()
        envelope = {
            "module_name": module_name,
            "func_name": func_name,
            "origin": str(callable_origin),
            "import_root": str(callable_import_root),
            "is_package": is_package,
            "source_b64": base64.b64encode(source).decode("ascii"),
            "source_file_sha256": source_file_digest,
            "code_identity_sha256": code_identity_digest,
            "artifact_scope": "source_file_only",
            "dependency_binding": "unbound_trusted_environment",
            "args": copied_args,
        }
        request_bytes = _canonical_json_bytes(envelope)
        if len(request_bytes) > _MAX_ENVELOPE_BYTES:
            raise SandboxError("LocalProcessSandbox request exceeds envelope size limit")
        request_digest = hashlib.sha256(request_bytes).hexdigest()

        read_fd, write_fd = os.pipe()
        os.set_inheritable(write_fd, True)
        cmd = [sys.executable, "-I", "-c", _ISOLATED_RUNNER, str(write_fd)]
        frame_holder: list[bytes] = []
        read_errors: list[BaseException] = []

        def collect_frame() -> None:
            try:
                frame_holder.append(_read_bounded_frame(read_fd))
            except BaseException as exc:
                read_errors.append(exc)

        reader = threading.Thread(target=collect_frame, name="gove-sandbox-frame", daemon=True)
        try:
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={"PATH": os.environ.get("PATH", "")},
                pass_fds=(write_fd,),
                start_new_session=True,
            )
        except (OSError, ValueError) as exc:
            os.close(read_fd)
            os.close(write_fd)
            raise SandboxError("Local process sandbox failed to start") from exc
        os.close(write_fd)
        reader.start()
        try:
            process.communicate(input=request_bytes, timeout=30)
        except subprocess.TimeoutExpired as exc:
            _terminate_process_group(process, reader)
            raise SandboxError(
                "Local process sandbox execution timed out after 30 seconds"
            ) from exc
        except BaseException:
            _terminate_process_group(process, reader)
            raise

        reader.join(timeout=1)
        try:
            if reader.is_alive():
                raise SandboxError("Local process sandbox response pipe did not close")
            if read_errors:
                raise SandboxError("Local process sandbox response pipe failed") from read_errors[0]
            if process.returncode != 0:
                raise SandboxError(f"Sandbox process failed with exit status {process.returncode}")
            if len(frame_holder) != 1:
                raise SandboxError("Sandbox response frame is unavailable")
            return _decode_response_frame(
                frame_holder[0], request_digest, source_file_digest, code_identity_digest
            )
        except BaseException:
            _terminate_process_group(process, reader)
            raise


def _decode_e2b_success_response(stdout: Any) -> Any:
    invalid_response = "E2BSandbox remote response is invalid"
    if type(stdout) is not str or not stdout.strip():
        raise SandboxError(invalid_response)

    def exact_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if type(key) is not str or key in result:
                raise ValueError("invalid JSON object")
            result[key] = value
        return result

    def reject_nonstandard_constant(_value: str) -> Any:
        raise ValueError("nonstandard JSON constant")

    try:
        response = json.loads(
            stdout,
            object_pairs_hook=exact_object,
            parse_constant=reject_nonstandard_constant,
        )
    except Exception as exc:
        raise SandboxError(invalid_response) from exc
    if type(response) is not dict or set(response) != {"status", "result"}:
        raise SandboxError(invalid_response)
    if type(response["status"]) is not str or response["status"] != "success":
        raise SandboxError(invalid_response)
    return response["result"]


class E2BSandbox(SandboxProvider):
    """Remote sandbox provider using E2B.

    Executes code in a remote ephemeral Firecracker microVM.
    Requires `E2B_API_KEY` to be set in the environment or passed.
    """

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.environ.get("E2B_API_KEY")
        self._client = None

    def run_tool(self, tool_fn: Callable[..., Any], args: dict[str, Any]) -> Any:
        """Runs the tool function by executing it in the remote E2B MicroVM."""
        if not self.api_key:
            raise SandboxError("E2B_API_KEY must be configured to use E2BSandbox")

        try:
            from e2b import Sandbox  # type: ignore[import-not-found]
        except Exception as exc:
            raise SandboxError("E2BSandbox SDK is unavailable") from exc
        if not callable(Sandbox):
            raise SandboxError("E2BSandbox SDK is unavailable")

        # Write execution code as a script to run in the sandbox
        module_name = getattr(tool_fn, "__module__", None)
        func_name = getattr(tool_fn, "__name__", None)

        if not module_name or not func_name:
            raise SandboxError(
                "E2BSandbox requires importable functions (lambdas/closures not supported)"
            )

        code = f"""
import importlib
import json
import sys

try:
    mod = importlib.import_module({module_name!r})
    func = getattr(mod, {func_name!r})
    res = func(**{args!r})
    print(json.dumps({{"status": "success", "result": res}}))
except Exception as e:
    print(json.dumps({{"status": "error", "error": str(e)}}))
    sys.exit(1)
"""
        try:
            # Connect to/create sandbox VM
            box = Sandbox(api_key=self.api_key)
            try:
                # Write file in sandbox
                box.files.write("/home/user/run_tool.py", code)
                # Run code
                execution = box.commands.run("python3 /home/user/run_tool.py")
            finally:
                box.close()

            if execution.exit_code != 0:
                raise SandboxError("E2BSandbox remote execution failed")
            return _decode_e2b_success_response(execution.stdout)
        except TimeoutError as exc:
            raise SandboxError("E2BSandbox remote execution timed out") from exc
        except Exception as exc:
            if isinstance(exc, SandboxError):
                raise
            raise SandboxError("E2BSandbox remote execution failed") from exc
