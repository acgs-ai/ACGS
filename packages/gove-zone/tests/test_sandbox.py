"""Unit and adversarial tests for sandbox execution providers."""

from __future__ import annotations

import gc
import hashlib
import importlib
import importlib.util
import json
import math
import os
import struct
import subprocess
import sys
import warnings
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import gove_zone.sandbox as sandbox_module
from gove_zone.sandbox import E2BSandbox, LocalProcessSandbox, SandboxError


def my_sandbox_test_tool(a: int, b: int) -> int:
    """A sample tool retained for E2B mock tests."""
    return a + b


def _load_source_module(path: Path, module_name: str, *, package: bool = False) -> ModuleType:
    locations = [str(path.parent)] if package else None
    spec = importlib.util.spec_from_file_location(
        module_name, path, submodule_search_locations=locations
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def source_tool_module(tmp_path: Path) -> Iterator[ModuleType]:
    module_name = "sandbox_source_fixture"
    source_path = tmp_path / f"{module_name}.py"
    source_path.write_text(
        """from __future__ import annotations
import json
import os
import subprocess
import sys
from pathlib import Path

RUNTIME_LIMIT = 5

def add(a: int, b: int) -> int:
    return a + b

def fail() -> None:
    raise ValueError("Simulated tool error")

def environment() -> dict[str, str | None]:
    return {
        "pythonpath": os.environ.get("PYTHONPATH"),
        "credential": os.environ.get("SANDBOX_TEST_CREDENTIAL"),
    }

def echo(value):
    return value

def write_marker(marker: str) -> str:
    Path(marker).write_text("unauthorized", encoding="utf-8")
    return "wrote-marker"

def forged_stdout(marker: str) -> None:
    print(json.dumps({"status": "success", "result": "forged"}), flush=True)
    os._exit(0)
    Path(marker).write_text("unauthorized", encoding="utf-8")

def protocol_globals_visible() -> bool:
    names = globals()
    return any(name in names for name in ("response_fd", "request_digest", "artifact_digest"))

def leak_response_fd() -> str:
    subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        close_fds=False,
    )
    return "spawned"

def guarded_state(marker: str, count: int = 5, *, mode: str = "safe") -> int:
    Path(marker).write_text("unauthorized", encoding="utf-8")
    return RUNTIME_LIMIT + count + len(mode)

def exception_table_guard(marker: str) -> str:
    try:
        Path(marker).write_text("unauthorized", encoding="utf-8")
    except OSError:
        return "error"
    return "wrote-marker"

def recursive_sum(value: int) -> int:
    if value <= 0:
        return 0
    return value + recursive_sum(value - 1)
""",
        encoding="utf-8",
    )
    module = _load_source_module(source_path, module_name)
    try:
        yield module
    finally:
        sys.modules.pop(module_name, None)


def test_local_process_sandbox_restricted_subprocess(source_tool_module: ModuleType) -> None:
    sandbox = LocalProcessSandbox(use_bwrap=False)
    assert sandbox.run_tool(source_tool_module.add, {"a": 5, "b": 7}) == 12


def test_local_process_sandbox_rejects_non_importable_closure() -> None:
    sandbox = LocalProcessSandbox(use_bwrap=False)
    calls = 0

    def local_closure(x: int) -> int:
        nonlocal calls
        calls += 1
        return x * 10

    with pytest.raises(SandboxError, match="importable module-level function"):
        sandbox.run_tool(local_closure, {"x": 3})
    assert calls == 0


def test_local_process_sandbox_failure_propagation(source_tool_module: ModuleType) -> None:
    with pytest.raises(SandboxError) as exc_info:
        LocalProcessSandbox(use_bwrap=False).run_tool(source_tool_module.fail, {})
    assert str(exc_info.value) == "Simulated tool error"


def test_local_process_sandbox_external_package_import_root(tmp_path: Path) -> None:
    package_root = tmp_path / "external-root"
    package_dir = package_root / "external_sandbox_tool"
    package_dir.mkdir(parents=True)
    init_path = package_dir / "__init__.py"
    init_path.write_text(
        "def multiply(left: int, right: int) -> int:\n    return left * right\n",
        encoding="utf-8",
    )
    module = _load_source_module(init_path, "external_sandbox_tool", package=True)
    try:
        assert (
            LocalProcessSandbox(use_bwrap=False).run_tool(module.multiply, {"left": 6, "right": 7})
            == 42
        )
    finally:
        sys.modules.pop("external_sandbox_tool", None)


def test_local_process_sandbox_rejects_package_relative_import(tmp_path: Path) -> None:
    root = tmp_path / "package-root"
    package = root / "relative_package_tool"
    package.mkdir(parents=True)
    (package / "helper.py").write_text("VALUE = 43\n", encoding="utf-8")
    init_path = package / "__init__.py"
    init_path.write_text(
        "from .helper import VALUE\ndef read_value() -> int:\n    return VALUE\n",
        encoding="utf-8",
    )
    module = _load_source_module(init_path, "relative_package_tool", package=True)
    try:
        with pytest.raises(SandboxError, match="standalone snapshot rejects relative imports"):
            LocalProcessSandbox(use_bwrap=False).run_tool(module.read_value, {})
    finally:
        sys.modules.pop("relative_package_tool.helper", None)
        sys.modules.pop("relative_package_tool", None)


def test_local_process_sandbox_rejects_namespace_submodule_relative_import(tmp_path: Path) -> None:
    root = tmp_path / "namespace-root"
    namespace = root / "fixture_namespace"
    namespace.mkdir(parents=True)
    (namespace / "helper.py").write_text("VALUE = 47\n", encoding="utf-8")
    (namespace / "tool.py").write_text(
        "from .helper import VALUE\ndef read_value() -> int:\n    return VALUE\n",
        encoding="utf-8",
    )
    sys.path.insert(0, str(root))
    try:
        module = importlib.import_module("fixture_namespace.tool")
        with pytest.raises(SandboxError, match="standalone snapshot rejects relative imports"):
            LocalProcessSandbox(use_bwrap=False).run_tool(module.read_value, {})
    finally:
        sys.path.remove(str(root))
        sys.modules.pop("fixture_namespace.helper", None)
        sys.modules.pop("fixture_namespace.tool", None)
        sys.modules.pop("fixture_namespace", None)


def test_local_process_sandbox_drops_inherited_environment(
    source_tool_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PYTHONPATH", "/polluted/import/root")
    monkeypatch.setenv("SANDBOX_TEST_CREDENTIAL", "must-not-cross-boundary")
    result = LocalProcessSandbox(use_bwrap=False).run_tool(source_tool_module.environment, {})
    assert result == {"pythonpath": None, "credential": None}


def test_local_process_sandbox_import_failure_has_no_local_fallback(
    source_tool_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(source_tool_module.add, "__module__", "missing_sandbox_module")
    with pytest.raises(SandboxError, match="cannot import"):
        LocalProcessSandbox(use_bwrap=False).run_tool(source_tool_module.add, {"a": 1, "b": 2})


def test_local_process_sandbox_rejects_relative_origin_without_side_effect(
    source_tool_module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "relative-origin-marker"
    spec = source_tool_module.__spec__
    assert spec is not None
    assert source_tool_module.__file__ is not None
    monkeypatch.setattr(spec, "origin", Path(source_tool_module.__file__).name)
    with pytest.raises(SandboxError, match="origin must be absolute"):
        LocalProcessSandbox(use_bwrap=False).run_tool(
            source_tool_module.write_marker, {"marker": str(marker)}
        )
    assert not marker.exists()


def test_local_process_sandbox_rejects_top_level_stem_mismatch_without_side_effect(
    source_tool_module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "stem-mismatch-marker"
    wrong_origin = tmp_path / "wrong_module_name.py"
    wrong_origin.write_text("# not approved\n", encoding="utf-8")
    spec = source_tool_module.__spec__
    assert spec is not None
    monkeypatch.setattr(spec, "origin", str(wrong_origin))
    monkeypatch.setattr(source_tool_module, "__file__", str(wrong_origin))
    with pytest.raises(SandboxError, match="origin does not match"):
        LocalProcessSandbox(use_bwrap=False).run_tool(
            source_tool_module.write_marker, {"marker": str(marker)}
        )
    assert not marker.exists()


def test_local_process_sandbox_rejects_custom_loader_without_side_effect(
    source_tool_module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "custom-loader-marker"
    spec = source_tool_module.__spec__
    assert spec is not None
    monkeypatch.setattr(spec, "loader", object())
    monkeypatch.setattr(
        source_tool_module.write_marker, "__code__", source_tool_module.echo.__code__
    )
    with pytest.raises(SandboxError, match="callable code identity does not match"):
        LocalProcessSandbox(use_bwrap=False).run_tool(
            source_tool_module.write_marker, {"marker": str(marker)}
        )
    assert not marker.exists()


class _ReprSideEffect:
    def __init__(self, marker: Path) -> None:
        self.marker = marker

    def __repr__(self) -> str:
        self.marker.write_text("repr-called", encoding="utf-8")
        return "forged"


class _TypeAttributeTrapMeta(type):
    marker: Path | None = None

    def __getattribute__(cls, name: str) -> Any:
        if name == "__name__":
            marker = type.__getattribute__(cls, "marker")
            if marker is not None:
                marker.write_text("type-attribute-read", encoding="utf-8")
        return type.__getattribute__(cls, name)


class _TypeAttributeTrap(metaclass=_TypeAttributeTrapMeta):
    pass


class _LocatorObservationTrap:
    def __init__(self, marker: Path) -> None:
        self.marker = marker

    def __getattribute__(self, name: str) -> Any:
        marker = object.__getattribute__(self, "marker")
        marker.write_text(f"attribute:{name}", encoding="utf-8")
        return object.__getattribute__(self, name)

    def __repr__(self) -> str:
        marker = object.__getattribute__(self, "marker")
        marker.write_text("repr", encoding="utf-8")
        return "locator-observation-trap"

    def __str__(self) -> str:
        marker = object.__getattribute__(self, "marker")
        marker.write_text("str", encoding="utf-8")
        return "locator-observation-trap"


def test_local_process_sandbox_rejects_custom_json_value_without_repr_side_effect(
    source_tool_module: ModuleType, tmp_path: Path
) -> None:
    marker = tmp_path / "repr-marker"
    with pytest.raises(SandboxError) as exc_info:
        LocalProcessSandbox(use_bwrap=False).run_tool(
            source_tool_module.echo, {"value": _ReprSideEffect(marker)}
        )
    assert str(exc_info.value) == "Sandbox JSON rejected at $.value: unsupported exact type"
    assert not marker.exists()


def test_local_process_sandbox_json_rejection_does_not_read_type_attributes(
    source_tool_module: ModuleType, tmp_path: Path
) -> None:
    marker = tmp_path / "type-attribute-marker"
    _TypeAttributeTrapMeta.marker = marker
    try:
        with pytest.raises(
            SandboxError, match=r"JSON rejected at \$\.value: unsupported exact type"
        ):
            LocalProcessSandbox(use_bwrap=False).run_tool(
                source_tool_module.echo, {"value": _TypeAttributeTrap()}
            )
    finally:
        _TypeAttributeTrapMeta.marker = None
    assert not marker.exists()


@pytest.mark.parametrize("value", [(1, 2), b"bytes", Path("path"), math.inf, math.nan])
def test_local_process_sandbox_rejects_non_exact_json_values(
    source_tool_module: ModuleType, value: object
) -> None:
    with pytest.raises(SandboxError):
        LocalProcessSandbox(use_bwrap=False).run_tool(source_tool_module.echo, {"value": value})


def test_local_process_sandbox_rejects_cyclic_json_without_side_effect(
    source_tool_module: ModuleType, tmp_path: Path
) -> None:
    marker = tmp_path / "cycle-marker"
    cycle: list[Any] = []
    cycle.append(cycle)
    with pytest.raises(SandboxError, match="cycle"):
        LocalProcessSandbox(use_bwrap=False).run_tool(
            source_tool_module.write_marker, {"marker": str(marker), "cycle": cycle}
        )
    assert not marker.exists()


def test_local_process_sandbox_rejects_mutated_defaults_without_side_effect(
    source_tool_module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "defaults-marker"
    monkeypatch.setattr(source_tool_module.guarded_state, "__defaults__", (6,))
    with pytest.raises(SandboxError, match="runtime defaults differ from source"):
        LocalProcessSandbox(use_bwrap=False).run_tool(
            source_tool_module.guarded_state, {"marker": str(marker)}
        )
    assert not marker.exists()


def test_local_process_sandbox_rejects_mutated_kwdefaults_without_side_effect(
    source_tool_module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "kwdefaults-marker"
    monkeypatch.setattr(source_tool_module.guarded_state, "__kwdefaults__", {"mode": "changed"})
    with pytest.raises(SandboxError, match="runtime kwdefaults differ from source"):
        LocalProcessSandbox(use_bwrap=False).run_tool(
            source_tool_module.guarded_state, {"marker": str(marker)}
        )
    assert not marker.exists()


def test_local_process_sandbox_rejects_mutated_annotations_without_side_effect(
    source_tool_module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "annotations-marker"
    monkeypatch.setattr(source_tool_module.guarded_state, "__annotations__", {"return": "str"})
    with pytest.raises(SandboxError, match="runtime annotations differ from source"):
        LocalProcessSandbox(use_bwrap=False).run_tool(
            source_tool_module.guarded_state, {"marker": str(marker)}
        )
    assert not marker.exists()


def test_local_process_sandbox_rejects_mutated_literal_global_without_side_effect(
    source_tool_module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "global-marker"
    monkeypatch.setattr(source_tool_module, "RUNTIME_LIMIT", 6)
    with pytest.raises(SandboxError, match="referenced global differs from source"):
        LocalProcessSandbox(use_bwrap=False).run_tool(
            source_tool_module.guarded_state, {"marker": str(marker)}
        )
    assert not marker.exists()


def test_local_process_sandbox_rejects_unsafe_runtime_default_without_repr(
    source_tool_module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "unsafe-default-marker"
    monkeypatch.setattr(
        source_tool_module.guarded_state,
        "__defaults__",
        (_ReprSideEffect(marker),),
    )
    with pytest.raises(SandboxError, match="unsupported exact type"):
        LocalProcessSandbox(use_bwrap=False).run_tool(
            source_tool_module.guarded_state, {"marker": str(marker)}
        )
    assert not marker.exists()


def test_local_process_sandbox_rejects_oversize_source_without_side_effect(
    source_tool_module: ModuleType, tmp_path: Path
) -> None:
    marker = tmp_path / "source-cap-marker"
    source_path = Path(source_tool_module.__file__ or "")
    with source_path.open("ab") as source_file:
        source_file.write(b"#" * (sandbox_module._MAX_ARTIFACT_BYTES + 1))
    with pytest.raises(SandboxError, match="artifact size limit"):
        LocalProcessSandbox(use_bwrap=False).run_tool(
            source_tool_module.write_marker, {"marker": str(marker)}
        )
    assert not marker.exists()


def test_local_process_sandbox_executes_opened_snapshot_not_mutated_path(
    source_tool_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_path = Path(source_tool_module.__file__ or "")
    real_popen = subprocess.Popen

    def mutating_popen(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        source_path.write_text("raise RuntimeError('mutated path executed')\n", encoding="utf-8")
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(sandbox_module.subprocess, "Popen", mutating_popen)
    assert (
        LocalProcessSandbox(use_bwrap=False).run_tool(source_tool_module.add, {"a": 8, "b": 9})
        == 17
    )


def test_local_process_sandbox_rejects_forged_stdout_without_side_effect(
    source_tool_module: ModuleType, tmp_path: Path
) -> None:
    marker = tmp_path / "forged-stdout-marker"
    with pytest.raises(SandboxError, match="empty or truncated"):
        LocalProcessSandbox(use_bwrap=False).run_tool(
            source_tool_module.forged_stdout, {"marker": str(marker)}
        )
    assert not marker.exists()


def _valid_frame(request_digest: str, source_file_digest: str, code_identity_digest: str) -> bytes:
    payload = json.dumps(
        {
            "status": "success",
            "request_sha256": request_digest,
            "source_file_sha256": source_file_digest,
            "code_identity_sha256": code_identity_digest,
            "artifact_scope": "source_file_only",
            "dependency_binding": "unbound_trusted_environment",
            "result": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    header = struct.pack(">4sBI", b"GZSF", 1, len(payload))
    return header + payload + hashlib.sha256(header + payload).digest()


def test_local_process_sandbox_frame_parser_rejects_truncation_extra_and_digest() -> None:
    request_digest = "r" * 64
    source_file_digest = "s" * 64
    code_identity_digest = "c" * 64
    valid = _valid_frame(request_digest, source_file_digest, code_identity_digest)
    malformed = [b"", valid[:-1], valid + b"x", valid + valid]
    digest_mismatch = bytearray(valid)
    digest_mismatch[-1] ^= 1
    malformed.append(bytes(digest_mismatch))
    malformed.append(struct.pack(">4sBI", b"GZSF", 1, 1024 * 1024 + 1) + b"0" * 32)
    for frame in malformed:
        with pytest.raises(SandboxError):
            sandbox_module._decode_response_frame(
                frame, request_digest, source_file_digest, code_identity_digest
            )


def test_local_process_sandbox_frame_parser_rejects_request_and_artifact_rebinding() -> None:
    request_digest = "r" * 64
    source_file_digest = "s" * 64
    code_identity_digest = "c" * 64
    frame = _valid_frame(request_digest, source_file_digest, code_identity_digest)
    with pytest.raises(SandboxError, match="request binding"):
        sandbox_module._decode_response_frame(
            frame, "x" * 64, source_file_digest, code_identity_digest
        )
    with pytest.raises(SandboxError, match="source-file binding"):
        sandbox_module._decode_response_frame(frame, request_digest, "x" * 64, code_identity_digest)
    with pytest.raises(SandboxError, match="code-identity binding"):
        sandbox_module._decode_response_frame(frame, request_digest, source_file_digest, "x" * 64)


def test_local_process_sandbox_request_names_and_scope(
    source_tool_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}
    real_canonical = sandbox_module._canonical_json_bytes

    def capture_envelope(value: Any) -> bytes:
        if type(value) is dict and "source_b64" in value:
            captured.update(value)
        return real_canonical(value)

    monkeypatch.setattr(sandbox_module, "_canonical_json_bytes", capture_envelope)
    result = LocalProcessSandbox(use_bwrap=False).run_tool(source_tool_module.add, {"a": 1, "b": 2})
    assert result == 3
    assert "artifact_sha256" not in captured
    assert captured["artifact_scope"] == "source_file_only"
    assert captured["dependency_binding"] == "unbound_trusted_environment"
    assert len(captured["source_file_sha256"]) == 64
    assert len(captured["code_identity_sha256"]) == 64


def test_local_process_sandbox_leaves_no_runner_or_result_files(
    source_tool_module: ModuleType, tmp_path: Path
) -> None:
    sandbox_dir = tmp_path / "sandbox"
    sandbox_dir.mkdir()
    sandbox = LocalProcessSandbox(use_bwrap=False, sandbox_dir=str(sandbox_dir))
    assert sandbox.run_tool(source_tool_module.add, {"a": 2, "b": 3}) == 5
    assert list(sandbox_dir.iterdir()) == []


def test_local_process_sandbox_owned_directory_close_is_idempotent() -> None:
    sandbox = LocalProcessSandbox(use_bwrap=False)
    sandbox_path = Path(sandbox.sandbox_dir)
    assert sandbox_path.is_dir()
    (sandbox_path / "owned-marker").write_text("fixture", encoding="utf-8")
    sandbox.close()
    assert not sandbox_path.exists()
    sandbox.close()


def test_local_process_sandbox_context_manager_cleans_owned_directory() -> None:
    with LocalProcessSandbox(use_bwrap=False) as sandbox:
        sandbox_path = Path(sandbox.sandbox_dir)
        assert sandbox_path.is_dir()
    assert not sandbox_path.exists()


def test_local_process_sandbox_finalizer_cleans_without_resource_warning() -> None:
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        sandbox = LocalProcessSandbox(use_bwrap=False)
        sandbox_path = Path(sandbox.sandbox_dir)
        assert sandbox_path.is_dir()
        del sandbox
        gc.collect()
    assert not sandbox_path.exists()
    assert not any(issubclass(item.category, ResourceWarning) for item in captured)


def test_local_process_sandbox_never_removes_caller_owned_directory(tmp_path: Path) -> None:
    caller_owned = tmp_path / "caller-owned-sandbox"
    caller_owned.mkdir()
    marker = caller_owned / "marker"
    marker.write_text("fixture", encoding="utf-8")
    with LocalProcessSandbox(use_bwrap=False, sandbox_dir=str(caller_owned)) as sandbox:
        assert sandbox.sandbox_dir == str(caller_owned)
    sandbox.close()
    del sandbox
    gc.collect()
    assert caller_owned.is_dir()
    assert marker.read_text(encoding="utf-8") == "fixture"


def test_local_process_sandbox_rejects_dynamic_protocol_namespace_access(
    source_tool_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    spawn_attempts: list[bool] = []

    def forbid_spawn(*_args: Any, **_kwargs: Any) -> Any:
        spawn_attempts.append(True)
        raise AssertionError("sandbox process must not start")

    monkeypatch.setattr(sandbox_module.subprocess, "Popen", forbid_spawn)
    with pytest.raises(SandboxError) as exc_info:
        LocalProcessSandbox(use_bwrap=False).run_tool(
            source_tool_module.protocol_globals_visible, {}
        )
    assert str(exc_info.value) == "unsupported_dynamic_namespace_access"
    assert spawn_attempts == []


def test_local_process_sandbox_rejects_locator_without_observing_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "locator-observation-marker"
    spawn_attempts: list[bool] = []

    def forbid_spawn(*_args: Any, **_kwargs: Any) -> Any:
        spawn_attempts.append(True)
        raise AssertionError("sandbox process must not start")

    monkeypatch.setattr(sandbox_module.subprocess, "Popen", forbid_spawn)
    with pytest.raises(SandboxError) as exc_info:
        LocalProcessSandbox(use_bwrap=False).run_tool(
            _LocatorObservationTrap(marker),  # type: ignore[arg-type]
            {},
        )
    assert str(exc_info.value) == "unsupported_callable_locator"
    assert not marker.exists()
    assert spawn_attempts == []


def test_local_process_sandbox_binds_exception_table_without_side_effect(
    source_tool_module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "exception-table-marker"
    spawn_attempts: list[bool] = []

    def forbid_spawn(*_args: Any, **_kwargs: Any) -> Any:
        spawn_attempts.append(True)
        raise AssertionError("sandbox process must not start")

    monkeypatch.setattr(sandbox_module.subprocess, "Popen", forbid_spawn)
    original = source_tool_module.exception_table_guard.__code__
    assert original.co_exceptiontable
    monkeypatch.setattr(
        source_tool_module.exception_table_guard,
        "__code__",
        original.replace(co_exceptiontable=b""),
    )
    with pytest.raises(SandboxError, match="code identity does not match"):
        LocalProcessSandbox(use_bwrap=False).run_tool(
            source_tool_module.exception_table_guard, {"marker": str(marker)}
        )
    assert not marker.exists()
    assert spawn_attempts == []


@pytest.mark.parametrize(
    "assignment",
    [
        "LEFT = RIGHT = 1",
        "LEFT, RIGHT = (1, 2)",
        "class Payload:\n    pass\nPAYLOAD = Payload()\nPAYLOAD.value = 1",
        'PAYLOAD = {}\nPAYLOAD["value"] = 1',
    ],
)
def test_local_process_sandbox_rejects_unsupported_top_level_assignment_without_side_effect(
    assignment: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module_name = f"unsupported_assignment_{hashlib.sha256(assignment.encode()).hexdigest()[:12]}"
    source_path = tmp_path / f"{module_name}.py"
    source_path.write_text(
        "from pathlib import Path\n"
        f"{assignment}\n"
        "def target(marker: str) -> str:\n"
        '    Path(marker).write_text("unauthorized", encoding="utf-8")\n'
        '    return "wrote-marker"\n',
        encoding="utf-8",
    )
    module = _load_source_module(source_path, module_name)
    marker = tmp_path / f"{module_name}-marker"
    spawn_attempts: list[bool] = []

    def forbid_spawn(*_args: Any, **_kwargs: Any) -> Any:
        spawn_attempts.append(True)
        raise AssertionError("sandbox process must not start")

    monkeypatch.setattr(sandbox_module.subprocess, "Popen", forbid_spawn)
    try:
        with pytest.raises(SandboxError) as exc_info:
            LocalProcessSandbox(use_bwrap=False).run_tool(module.target, {"marker": str(marker)})
        assert str(exc_info.value) == "unsupported_source_artifact"
    finally:
        sys.modules.pop(module_name, None)
    assert not marker.exists()
    assert spawn_attempts == []


@pytest.mark.parametrize(
    ("body", "expected_reason"),
    [
        ("globals()", "unsupported_dynamic_namespace_access"),
        (
            'from builtins import eval as evaluator\n    evaluator("1")',
            "unsupported_dynamic_builtins_import",
        ),
        (
            '__builtins__.getattr(object(), "__class__")',
            "unsupported_dynamic_namespace_access",
        ),
        (
            "def inner():\n        return locals()\n    inner()",
            "unsupported_dynamic_namespace_access",
        ),
    ],
)
def test_local_process_sandbox_rejects_dynamic_namespace_access_without_side_effect(
    body: str,
    expected_reason: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"dynamic_namespace_{hashlib.sha256(body.encode()).hexdigest()[:12]}"
    source_path = tmp_path / f"{module_name}.py"
    source_path.write_text(
        "from pathlib import Path\n"
        "def target(marker: str) -> str:\n"
        f"    {body}\n"
        '    Path(marker).write_text("unauthorized", encoding="utf-8")\n'
        '    return "wrote-marker"\n',
        encoding="utf-8",
    )
    module = _load_source_module(source_path, module_name)
    marker = tmp_path / f"{module_name}-marker"
    spawn_attempts: list[bool] = []

    def forbid_spawn(*_args: Any, **_kwargs: Any) -> Any:
        spawn_attempts.append(True)
        raise AssertionError("sandbox process must not start")

    monkeypatch.setattr(sandbox_module.subprocess, "Popen", forbid_spawn)
    try:
        with pytest.raises(SandboxError) as exc_info:
            LocalProcessSandbox(use_bwrap=False).run_tool(module.target, {"marker": str(marker)})
        assert str(exc_info.value) == expected_reason
    finally:
        sys.modules.pop(module_name, None)
    assert not marker.exists()
    assert spawn_attempts == []


@pytest.mark.parametrize(
    "module_import",
    [
        "import builtins as runtime_builtins",
        "from builtins import eval as evaluator",
    ],
)
def test_local_process_sandbox_rejects_full_module_dynamic_builtins_import_before_spawn(
    module_import: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module_name = f"dynamic_builtins_{hashlib.sha256(module_import.encode()).hexdigest()[:12]}"
    source_path = tmp_path / f"{module_name}.py"
    source_path.write_text(
        "from pathlib import Path\n"
        f"{module_import}\n"
        "def sibling() -> None:\n"
        "    pass\n"
        "def target(marker: str) -> str:\n"
        '    Path(marker).write_text("unauthorized", encoding="utf-8")\n'
        '    return "wrote-marker"\n',
        encoding="utf-8",
    )
    module = _load_source_module(source_path, module_name)
    marker = tmp_path / f"{module_name}-marker"
    spawn_attempts: list[bool] = []

    def forbid_spawn(*_args: Any, **_kwargs: Any) -> Any:
        spawn_attempts.append(True)
        raise AssertionError("sandbox process must not start")

    monkeypatch.setattr(sandbox_module.subprocess, "Popen", forbid_spawn)
    try:
        with pytest.raises(SandboxError) as exc_info:
            LocalProcessSandbox(use_bwrap=False).run_tool(module.target, {"marker": str(marker)})
        assert str(exc_info.value) == "unsupported_dynamic_builtins_import"
    finally:
        sys.modules.pop(module_name, None)
    assert not marker.exists()
    assert spawn_attempts == []


def test_local_process_sandbox_rejects_nested_reflection_before_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module_name = "nested_reflection_blocker"
    source_path = tmp_path / f"{module_name}.py"
    source_path.write_text(
        "from pathlib import Path\n"
        "def target(marker: str) -> str:\n"
        "    def inspect_target():\n"
        "        return target.__globals__\n"
        "    inspect_target()\n"
        '    Path(marker).write_text("unauthorized", encoding="utf-8")\n'
        '    return "wrote-marker"\n',
        encoding="utf-8",
    )
    module = _load_source_module(source_path, module_name)
    marker = tmp_path / "nested-reflection-marker"
    spawn_attempts: list[bool] = []

    def forbid_spawn(*_args: Any, **_kwargs: Any) -> Any:
        spawn_attempts.append(True)
        raise AssertionError("sandbox process must not start")

    monkeypatch.setattr(sandbox_module.subprocess, "Popen", forbid_spawn)
    try:
        with pytest.raises(SandboxError) as exc_info:
            LocalProcessSandbox(use_bwrap=False).run_tool(module.target, {"marker": str(marker)})
        assert str(exc_info.value) == "unsupported_reflection_access"
    finally:
        sys.modules.pop(module_name, None)
    assert not marker.exists()
    assert spawn_attempts == []


def test_local_process_sandbox_rejects_non_call_target_reference_before_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module_name = "target_reference_blocker"
    source_path = tmp_path / f"{module_name}.py"
    source_path.write_text(
        "from pathlib import Path\n"
        "def target(marker: str) -> str:\n"
        "    alias = target\n"
        '    Path(marker).write_text("unauthorized", encoding="utf-8")\n'
        '    return "wrote-marker" if alias else "unreachable"\n',
        encoding="utf-8",
    )
    module = _load_source_module(source_path, module_name)
    marker = tmp_path / "target-reference-marker"
    spawn_attempts: list[bool] = []

    def forbid_spawn(*_args: Any, **_kwargs: Any) -> Any:
        spawn_attempts.append(True)
        raise AssertionError("sandbox process must not start")

    monkeypatch.setattr(sandbox_module.subprocess, "Popen", forbid_spawn)
    try:
        with pytest.raises(SandboxError) as exc_info:
            LocalProcessSandbox(use_bwrap=False).run_tool(module.target, {"marker": str(marker)})
        assert str(exc_info.value) == "unsupported_target_reference"
    finally:
        sys.modules.pop(module_name, None)
    assert not marker.exists()
    assert spawn_attempts == []


@pytest.mark.parametrize("identity_field", ["filename", "firstlineno", "linetable"])
def test_local_process_sandbox_rejects_location_identity_drift_before_spawn(
    identity_field: str,
    source_tool_module: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / f"{identity_field}-identity-marker"
    spawn_attempts: list[bool] = []

    def forbid_spawn(*_args: Any, **_kwargs: Any) -> Any:
        spawn_attempts.append(True)
        raise AssertionError("sandbox process must not start")

    monkeypatch.setattr(sandbox_module.subprocess, "Popen", forbid_spawn)
    function = source_tool_module.exception_table_guard
    original = function.__code__
    if identity_field == "filename":
        replacement = original.replace(co_filename=str(tmp_path / "different-origin.py"))
    elif identity_field == "firstlineno":
        replacement = original.replace(co_firstlineno=original.co_firstlineno + 1)
    else:
        assert original.co_linetable
        replacement = original.replace(co_linetable=b"")
    monkeypatch.setattr(function, "__code__", replacement)
    with pytest.raises(SandboxError, match="code identity does not match"):
        LocalProcessSandbox(use_bwrap=False).run_tool(function, {"marker": str(marker)})
    assert not marker.exists()
    assert spawn_attempts == []


def test_code_identity_is_deterministic_without_deprecation_warning(
    source_tool_module: ModuleType,
) -> None:
    code = source_tool_module.protocol_globals_visible.__code__
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        first = sandbox_module._code_identity_bytes(code)
        second = sandbox_module._code_identity_bytes(code)
    assert first == second
    assert first.startswith(b"GZCI\x02")
    assert not any(issubclass(item.category, DeprecationWarning) for item in captured)


def test_local_process_sandbox_allows_direct_recursion(
    source_tool_module: ModuleType,
) -> None:
    assert (
        LocalProcessSandbox(use_bwrap=False).run_tool(
            source_tool_module.recursive_sum, {"value": 6}
        )
        == 21
    )


def test_local_process_sandbox_kills_descendant_holding_response_fd(
    source_tool_module: ModuleType,
) -> None:
    with pytest.raises(SandboxError, match="response pipe did not close"):
        LocalProcessSandbox(use_bwrap=False).run_tool(source_tool_module.leak_response_fd, {})


def test_local_process_sandbox_bwrap_fd_path_fails_closed(
    source_tool_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sandbox_module.shutil, "which", lambda _: "/usr/bin/bwrap")
    sandbox = LocalProcessSandbox(use_bwrap=True)
    with pytest.raises(SandboxError, match="cannot safely preserve"):
        sandbox.run_tool(source_tool_module.add, {"a": 1, "b": 2})


def test_local_process_sandbox_missing_bwrap_fails_before_callable(
    source_tool_module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "missing-bwrap-marker"
    monkeypatch.setattr(sandbox_module.shutil, "which", lambda _: None)
    sandbox = LocalProcessSandbox(use_bwrap=True)
    with pytest.raises(SandboxError, match="bubblewrap binary is unavailable"):
        sandbox.run_tool(source_tool_module.write_marker, {"marker": str(marker)})
    assert not marker.exists()


def test_e2e_sandbox_missing_sdk_never_executes_locally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "e2b-missing-sdk-marker"
    local_calls = 0

    def must_not_run() -> str:
        nonlocal local_calls
        local_calls += 1
        marker.write_text("unauthorized", encoding="utf-8")
        return "local-result"

    monkeypatch.setitem(sys.modules, "e2b", None)  # type: ignore[arg-type]
    with pytest.raises(SandboxError) as exc_info:
        E2BSandbox(api_key="fixture-api-key").run_tool(must_not_run, {})
    assert str(exc_info.value) == "E2BSandbox SDK is unavailable"
    assert local_calls == 0
    assert not marker.exists()


def test_e2e_sandbox_available_sdk_uses_remote_client_surface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, str]] = []
    local_calls = 0

    def must_not_run(a: int, b: int) -> int:
        nonlocal local_calls
        local_calls += 1
        return a + b

    class SuccessfulExecution:
        exit_code = 0
        stderr = ""
        stdout = '{"status":"success","result":10}'

    class FakeSandbox:
        def __init__(self, api_key: str) -> None:
            events.append(("init", api_key))
            self.files = self
            self.commands = self

        def write(self, path: str, code: str) -> None:
            assert "must_not_run" in code
            events.append(("write", path))

        def run(self, command: str) -> SuccessfulExecution:
            events.append(("run", command))
            return SuccessfulExecution()

        def close(self) -> None:
            events.append(("close", ""))

    fake_sdk = ModuleType("e2b")
    fake_sdk.__dict__["Sandbox"] = FakeSandbox
    monkeypatch.setitem(sys.modules, "e2b", fake_sdk)

    result = E2BSandbox(api_key="fixture-api-key").run_tool(must_not_run, {"a": 2, "b": 8})

    assert result == 10
    assert local_calls == 0
    assert events == [
        ("init", "fixture-api-key"),
        ("write", "/home/user/run_tool.py"),
        ("run", "python3 /home/user/run_tool.py"),
        ("close", ""),
    ]


@pytest.mark.parametrize(
    ("mode", "expected_reason"),
    [
        ("failure", "E2BSandbox remote execution failed"),
        ("timeout", "E2BSandbox remote execution timed out"),
    ],
)
def test_e2e_sandbox_remote_failure_and_timeout_fail_closed(
    mode: str, expected_reason: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    local_calls = 0

    def must_not_run() -> str:
        nonlocal local_calls
        local_calls += 1
        return "local-result"

    class FailedExecution:
        exit_code = 1
        stderr = "SECRET_REMOTE_FAILURE"
        stdout = ""

    class FakeSandbox:
        def __init__(self, api_key: str) -> None:
            assert api_key == "fixture-api-key"
            self.files = self
            self.commands = self

        def write(self, path: str, code: str) -> None:
            assert path == "/home/user/run_tool.py"
            assert "must_not_run" in code
            events.append("write")

        def run(self, command: str) -> FailedExecution:
            assert command == "python3 /home/user/run_tool.py"
            events.append("run")
            if mode == "timeout":
                raise TimeoutError("SECRET_REMOTE_TIMEOUT")
            return FailedExecution()

        def close(self) -> None:
            events.append("close")

    fake_sdk = ModuleType("e2b")
    fake_sdk.__dict__["Sandbox"] = FakeSandbox
    monkeypatch.setitem(sys.modules, "e2b", fake_sdk)

    with pytest.raises(SandboxError) as exc_info:
        E2BSandbox(api_key="fixture-api-key").run_tool(must_not_run, {})
    assert str(exc_info.value) == expected_reason
    assert "SECRET_REMOTE" not in str(exc_info.value)
    assert local_calls == 0
    assert events == ["write", "run", "close"]


@pytest.mark.parametrize("expected_result", [None, False, 0, "", [], {}])
def test_e2e_sandbox_exact_success_preserves_falsey_json_results(
    expected_result: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    class SuccessfulExecution:
        exit_code = 0
        stderr = ""

        def __init__(self) -> None:
            self.stdout = json.dumps(
                {"status": "success", "result": expected_result},
                separators=(",", ":"),
            )

    class FakeSandbox:
        def __init__(self, api_key: str) -> None:
            assert api_key == "fixture-api-key"
            self.files = self
            self.commands = self

        def write(self, path: str, code: str) -> None:
            assert path == "/home/user/run_tool.py"
            assert "my_sandbox_test_tool" in code

        def run(self, command: str) -> SuccessfulExecution:
            assert command == "python3 /home/user/run_tool.py"
            return SuccessfulExecution()

        def close(self) -> None:
            pass

    fake_sdk = ModuleType("e2b")
    fake_sdk.__dict__["Sandbox"] = FakeSandbox
    monkeypatch.setitem(sys.modules, "e2b", fake_sdk)

    assert (
        E2BSandbox(api_key="fixture-api-key").run_tool(my_sandbox_test_tool, {"a": 2, "b": 8})
        == expected_result
    )


@pytest.mark.parametrize(
    "stdout",
    [
        pytest.param('{"status":"error","result":"SECRET_REMOTE"}', id="error"),
        pytest.param('{"status":"pending","result":"SECRET_REMOTE"}', id="unknown"),
        pytest.param('{"result":1}', id="missing-status"),
        pytest.param('{"status":"success"}', id="missing-result"),
        pytest.param('{"status":1,"result":1}', id="nonstring-status"),
        pytest.param("{", id="malformed"),
        pytest.param("[]", id="nonobject"),
        pytest.param("", id="empty"),
        pytest.param(
            '{"status":"success","result":1,"extra":"SECRET_REMOTE"}',
            id="extra-key",
        ),
        pytest.param(
            '{"status":"success","result":1}{"status":"success","result":2}',
            id="two-json-values",
        ),
        pytest.param(
            'SECRET_REMOTE_LOG\n{"status":"success","result":1}',
            id="log-prefix",
        ),
        pytest.param(
            '{"status":"success","result":1}\nSECRET_REMOTE_TRAILING',
            id="trailing-output",
        ),
        pytest.param(
            '{"status":"success","status":"success","result":1}',
            id="duplicate-key",
        ),
    ],
)
def test_e2e_sandbox_rejects_nonexact_remote_response_without_secret_echo(
    stdout: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    local_calls = 0

    def must_not_run() -> str:
        nonlocal local_calls
        local_calls += 1
        return "local-result"

    class InvalidExecution:
        exit_code = 0
        stderr = "SECRET_REMOTE_STDERR"

        def __init__(self) -> None:
            self.stdout = stdout

    class FakeSandbox:
        def __init__(self, api_key: str) -> None:
            assert api_key == "fixture-api-key"
            self.files = self
            self.commands = self

        def write(self, path: str, code: str) -> None:
            assert path == "/home/user/run_tool.py"
            assert "must_not_run" in code

        def run(self, command: str) -> InvalidExecution:
            assert command == "python3 /home/user/run_tool.py"
            return InvalidExecution()

        def close(self) -> None:
            pass

    fake_sdk = ModuleType("e2b")
    fake_sdk.__dict__["Sandbox"] = FakeSandbox
    monkeypatch.setitem(sys.modules, "e2b", fake_sdk)

    with pytest.raises(SandboxError) as exc_info:
        E2BSandbox(api_key="fixture-api-key").run_tool(must_not_run, {})
    assert str(exc_info.value) == "E2BSandbox remote response is invalid"
    assert "SECRET_REMOTE" not in str(exc_info.value)
    assert local_calls == 0


def test_e2e_sandbox_missing_api_key() -> None:
    sandbox = E2BSandbox(api_key=None)
    original_key = os.environ.pop("E2B_API_KEY", None)
    try:
        with pytest.raises(SandboxError, match="E2B_API_KEY must be configured"):
            sandbox.run_tool(my_sandbox_test_tool, {"a": 1, "b": 2})
    finally:
        if original_key:
            os.environ["E2B_API_KEY"] = original_key
