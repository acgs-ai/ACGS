#!/usr/bin/env python3
"""Validate the assignment-derived closed map of freshly executed runtimes."""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

from _common import (
    CODE_PATHS,
    EXPECTED_BOOTSTRAP_MAP,
    NODE_RE,
    EvidenceError,
    assert_evidence_runtime,
    assignment_tokens,
    canonical_node_evidence_path,
    check_lock_header,
    evidence_root_from_env,
    fail,
    installed_distributions,
    load_json,
    parse_canonical_positive_decimal,
    parse_lock,
    parse_utc,
    sha256_file,
    write_json_exclusive,
)

EVID_KEYS = {
    "schema_version",
    "code",
    "node_id",
    "captured_at_utc",
    "interpreter",
    "interpreter_realpath",
    "module_root",
    "python_version",
    "python_implementation",
    "uv",
    "lock",
    "installed_distributions",
    "modules",
    "bootstrap_record",
    "output_path",
}
PYTHON_KEYS = {
    "schema_version",
    "code",
    "node_id",
    "captured_at_utc",
    "interpreter",
    "interpreter_realpath",
    "module_root",
    "python_version",
    "python_implementation",
    "lock",
    "installed_distributions",
    "pep517_backend",
    "pep660_editable_build",
    "bootstrap_record",
    "output_path",
}
UI_KEYS = {
    "schema_version",
    "code",
    "node_id",
    "captured_at_utc",
    "node",
    "pnpm",
    "module_root",
    "lock",
    "bootstrap_record",
    "output_path",
}


def _manifest_expected_version(manifest: dict[str, Any], manifest_path: Path) -> str | None:
    """Resolve a manifest's expected version, including PEP 621 ``dynamic`` versions.

    Mirrors the same-named helper in ``capture_environment.py``: a static
    ``[project] version`` is returned as-is; a dynamic version sourced from
    ``[tool.hatch.version]`` (``path`` + regex ``pattern``) is read from the
    referenced file, so editable-identity checks resolve a concrete version for
    Hatch-versioned packages (e.g. gove-zone, whose ``project.version`` is absent)
    instead of tripping the B5 mismatch. Returns ``None`` when undeterminable.
    """
    project = manifest.get("project", {})
    static = project.get("version")
    if isinstance(static, str):
        return static
    if "version" not in project.get("dynamic", []):
        return None
    hatch = manifest.get("tool", {}).get("hatch", {}).get("version", {})
    rel_path = hatch.get("path")
    pattern = hatch.get("pattern")
    if not isinstance(rel_path, str) or not isinstance(pattern, str):
        return None
    try:
        text = (manifest_path.parent / rel_path).read_text(encoding="utf-8")
        match = re.search(pattern, text)
    except (OSError, re.error):
        return None
    if match is None:
        return None
    try:
        return match.group("version")
    except (IndexError, re.error):
        return None


def _exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        actual = set(value) if isinstance(value, dict) else set()
        fail(
            f"{label} is not closed; missing={sorted(keys - actual)} extra={sorted(actual - keys)}",
            phase="B5",
        )
    return value


def _load_assignment_map(path: Path) -> dict[str, str]:
    value = load_json(path)
    if not isinstance(value, dict) or len(value) != 28:
        fail("bootstrap assignment map must be a direct closed 28-node object", phase="B5")
    result: dict[str, str] = {}
    for node, assignment in value.items():
        if (
            not isinstance(node, str)
            or NODE_RE.fullmatch(node) is None
            or not isinstance(assignment, str)
        ):
            fail("bootstrap assignment map contains malformed data", phase="B5")
        assignment_tokens(assignment)
        result[node] = assignment
    if result != EXPECTED_BOOTSTRAP_MAP:
        fail("bootstrap map differs from exact reviewed 28-node map", phase="B5")
    return result


def _marker_path(code: str, repo_root: Path) -> Path:
    path, _ = CODE_PATHS[code]
    if code in {"EVID", "CP", "GZ"}:
        return (repo_root / path).parents[1] / (
            ".acgs-evidence-bootstrap.json" if code == "EVID" else ".acgs-product-bootstrap.json"
        )
    return repo_root / path / ".acgs-product-bootstrap.json"


def _runtime_path(code: str, repo_root: Path) -> Path:
    path, _ = CODE_PATHS[code]
    candidate = repo_root / path
    return candidate.parents[1] if code in {"EVID", "CP", "GZ"} else candidate


def _validate_marker(
    code: str,
    identity: dict[str, Any],
    identity_path: Path,
    node: str,
    repo_root: Path,
) -> None:
    record = identity.get("bootstrap_record")
    if not isinstance(record, dict):
        fail(f"{code} bootstrap record missing", phase="B5")
    marker_path = _marker_path(code, repo_root)
    if not os.path.lexists(marker_path) or not marker_path.is_file() or marker_path.is_symlink():
        fail(f"{code} fresh bootstrap marker missing or unsafe: {marker_path}", phase="B5")
    if marker_path.lstat().st_nlink != 1:
        fail(f"{code} fresh bootstrap marker must be uniquely linked", phase="B5")
    marker = load_json(marker_path)
    if marker != record:
        fail(f"{code} identity/marker mismatch", phase="B5")
    expected_marker_keys = {
        "schema_version",
        "node_id",
        "code",
        "captured_at_utc",
        "runtime_root",
        "interpreter",
        "runtime_ctime_ns",
        "lock_sha256",
        "nonce",
    }
    if code in {"EVID", "CP", "GZ"}:
        expected_marker_keys.update(
            {
                "interpreter_realpath",
                "python_version",
                "python_implementation",
                "pyvenv_cfg_sha256",
            }
        )
    else:
        expected_marker_keys.update(
            {"interpreter_realpath", "node_version", "pnpm_executable", "pnpm_version"}
        )
    _exact_keys(marker, expected_marker_keys, f"{code} bootstrap record")
    if marker.get("schema_version") != "acgs-bootstrap-record/v1":
        fail(f"{code} bootstrap record version mismatch", phase="B5")
    if marker.get("node_id") != node or marker.get("code") != code:
        fail(f"{code} retained/copied bootstrap record rejected", phase="B5")
    parse_utc(str(marker.get("captured_at_utc")))
    if marker_path.stat().st_mtime_ns > identity_path.stat().st_mtime_ns:
        fail(f"{code} marker is newer than its captured identity", phase="B5")
    runtime_lexical = _runtime_path(code, repo_root).absolute()
    runtime = runtime_lexical.resolve(strict=True)
    if runtime_lexical != runtime or not runtime.is_dir():
        fail(f"{code} runtime root is symlinked or noncanonical", phase="B5")
    if marker.get("runtime_root") != str(runtime):
        fail(f"{code} runtime root mismatch", phase="B5")
    runtime_ctime_ns = parse_canonical_positive_decimal(
        marker.get("runtime_ctime_ns"), label=f"{code} runtime_ctime_ns"
    )
    if runtime_ctime_ns != runtime.stat().st_ctime_ns:
        fail(f"{code} runtime ctime changed after capture", phase="B5")
    if (
        not isinstance(marker.get("nonce"), str)
        or re.fullmatch(r"[0-9a-f]{64}", marker["nonce"]) is None
    ):
        fail(f"{code} bootstrap nonce is malformed", phase="B5")
    if marker.get("lock_sha256") != identity.get("lock", {}).get("sha256"):
        fail(f"{code} marker and identity lock digests differ", phase="B5")
    if code in {"EVID", "CP", "GZ"}:
        pyvenv = runtime / "pyvenv.cfg"
        if marker.get("pyvenv_cfg_sha256") != sha256_file(pyvenv):
            fail(f"{code} pyvenv identity mismatch", phase="B5")
        if (
            marker.get("interpreter") != identity.get("interpreter")
            or marker.get("interpreter_realpath") != identity.get("interpreter_realpath")
            or marker.get("python_version") != identity.get("python_version")
            or marker.get("python_implementation") != identity.get("python_implementation")
        ):
            fail(f"{code} marker/runtime identity mismatch", phase="B5")
    elif (
        marker.get("interpreter") != identity.get("node", {}).get("executable")
        or marker.get("interpreter_realpath") != identity.get("node", {}).get("executable")
        or marker.get("node_version") != identity.get("node", {}).get("version")
        or marker.get("pnpm_executable") != identity.get("pnpm", {}).get("executable")
        or marker.get("pnpm_version") != identity.get("pnpm", {}).get("version")
    ):
        fail("UI marker/tool identity mismatch", phase="B5")


def _validate_lock(
    code: str,
    identity: dict[str, Any],
    repo_root: Path,
) -> tuple[Path, dict[str, dict[str, Any]]]:
    _, lock_rel = CODE_PATHS[code]
    lock_path = (repo_root / lock_rel).resolve(strict=True)
    lock_identity = identity.get("lock")
    if not isinstance(lock_identity, dict):
        fail(f"{code} lock identity missing", phase="B5")
    expected_keys = {"path", "sha256"} if code == "UI" else {"path", "sha256", "distributions"}
    _exact_keys(lock_identity, expected_keys, f"{code} lock identity")
    if lock_identity.get("path") != lock_rel or lock_identity.get("sha256") != sha256_file(
        lock_path
    ):
        fail(f"{code} lock path/hash mismatch", phase="B5")
    if code == "UI":
        return lock_path, {}
    check_lock_header(lock_path, lock_rel.replace(".lock", ".in"), lock_rel)
    locked = parse_lock(lock_path)
    if lock_identity.get("distributions") != locked:
        fail(f"{code} lock distribution/hash identity mismatch", phase="B5")
    return lock_path, locked


def _live_product_probe(code: str, interpreter: Path) -> dict[str, Any]:
    snippet = r"""
import importlib
import importlib.metadata
import json
import pathlib
import re
import sys

result = {
    "prefix": sys.prefix,
    "executable": sys.executable,
    "python_version": ".".join(str(value) for value in sys.version_info[:3]),
    "python_implementation": sys.implementation.name,
    "modules": {},
    "distributions": {},
}
for distribution in importlib.metadata.distributions():
    name = re.sub(r"[-_.]+", "-", distribution.metadata["Name"]).lower()
    if name in result["distributions"]:
        raise SystemExit(f"duplicate distribution: {name}")
    result["distributions"][name] = {
        "version": distribution.version,
        "location": str(pathlib.Path(distribution.locate_file("")).resolve()),
    }
for module_name, dist in (("editables", "editables"), ("hatchling", "hatchling")):
    module = importlib.import_module(module_name)
    result["modules"][module_name] = {
        "version": importlib.metadata.version(dist),
        "path": str(pathlib.Path(module.__file__).resolve()),
    }
print(json.dumps(result, sort_keys=True, allow_nan=False))
"""
    env = {
        key: value for key, value in os.environ.items() if key not in {"PYTHONPATH", "VIRTUAL_ENV"}
    }
    env.update(
        {
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "UV_OFFLINE": "1",
            "UV_NO_INDEX": "1",
            "UV_NO_CACHE": "1",
        }
    )
    completed = subprocess.run(
        [str(interpreter), "-I", "-c", snippet],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    if completed.returncode != 0:
        fail(f"{code} live product probe failed: {completed.stderr}", phase="B5")
    value = load_json_from_text(completed.stdout)
    if not isinstance(value, dict):
        fail(f"{code} live product probe malformed", phase="B5")
    return value


def load_json_from_text(text: str) -> Any:
    from _common import strict_json_loads

    return strict_json_loads(text)


def _validate_evid(
    identity: dict[str, Any], locked: dict[str, dict[str, Any]], repo_root: Path
) -> None:
    expected_root = (repo_root / ".venv-evidence").resolve(strict=True)
    expected_interpreter = str(repo_root / ".venv-evidence/bin/python")
    if identity.get("interpreter") != expected_interpreter:
        fail("EVID canonical interpreter path mismatch", phase="B5")
    if Path(str(identity.get("interpreter_realpath"))).resolve(strict=True) != (
        expected_root / "bin/python"
    ).resolve(strict=True):
        fail("EVID interpreter realpath mismatch", phase="B5")
    if identity.get("module_root") != str(expected_root):
        fail("EVID module root mismatch", phase="B5")
    current_python = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if identity.get("python_version") != current_python or not current_python.startswith("3.11."):
        fail("EVID Python version mismatch", phase="B5")
    if identity.get("python_implementation") != sys.implementation.name:
        fail("EVID Python implementation mismatch", phase="B5")
    observed_installed = identity.get("installed_distributions")
    if (
        not isinstance(observed_installed, dict)
        or observed_installed != installed_distributions()
        or set(observed_installed) != set(locked)
    ):
        fail("EVID installed distribution identity is fabricated or stale", phase="B5")
    for name, entry in locked.items():
        installed = observed_installed[name]
        location = Path(str(installed.get("location", ""))).resolve(strict=True)
        if installed.get("version") != entry["version"] or not location.is_relative_to(
            expected_root
        ):
            fail(f"EVID installed distribution mismatch: {name}", phase="B5")
    uv = _exact_keys(identity.get("uv"), {"version", "executable"}, "EVID uv identity")
    uv_executable = "/home/martin/.local/bin/uv"
    uv_completed = (
        subprocess.run(
            [uv_executable, "--version"],
            text=True,
            capture_output=True,
            check=False,
            env={**os.environ, "UV_OFFLINE": "1", "UV_NO_INDEX": "1", "UV_NO_CACHE": "1"},
        )
        if Path(uv_executable).is_file()
        else None
    )
    if (
        uv_completed is None
        or uv_completed.returncode != 0
        or re.fullmatch(r"uv 0\.11\.19(?: \([^)]+\))?", uv_completed.stdout.strip()) is None
        or uv.get("version") != "0.11.19"
        or Path(str(uv.get("executable"))).resolve(strict=True)
        != Path(uv_executable).resolve(strict=True)
        or sha256_file(Path(uv_executable))
        != "a00d3a24514fc0403fc232c9c99bf5e542657c38f4ed941e0611731e4cff268b"
    ):
        fail("EVID uv identity mismatch", phase="B5")
    modules = identity.get("modules")
    if not isinstance(modules, dict) or set(modules) != {
        "rfc8785",
        "cryptography",
        "jsonschema",
        "pytest",
    }:
        fail("EVID direct module map mismatch", phase="B5")
    for module_name, module in modules.items():
        _exact_keys(module, {"distribution", "version", "path"}, f"EVID module {module_name}")
        distribution = str(module["distribution"])
        if distribution != module_name or module["version"] != locked[distribution]["version"]:
            fail(f"EVID direct module version mismatch: {module_name}", phase="B5")
        live_module = importlib.import_module(module_name)
        live_path = Path(str(live_module.__file__)).resolve(strict=True)
        if (
            Path(str(module["path"])).resolve(strict=True) != live_path
            or not live_path.is_relative_to(expected_root)
            or importlib.metadata.version(distribution) != module["version"]
        ):
            fail(f"EVID direct module live identity mismatch: {module_name}", phase="B5")
    if modules["rfc8785"]["version"] != "0.1.4":
        fail("EVID must use exact RFC8785 0.1.4", phase="B5")


def _validate_python_product(
    code: str,
    identity: dict[str, Any],
    locked: dict[str, dict[str, Any]],
    repo_root: Path,
) -> None:
    interpreter_rel, _ = CODE_PATHS[code]
    interpreter = repo_root / interpreter_rel
    runtime_root = interpreter.parents[1].resolve(strict=True)
    if identity.get("interpreter") != str(interpreter) or identity.get("module_root") != str(
        runtime_root
    ):
        fail(f"{code} canonical interpreter/module root mismatch", phase="B5")
    if Path(str(identity.get("interpreter_realpath"))).resolve(strict=True) != interpreter.resolve(
        strict=True
    ):
        fail(f"{code} interpreter realpath mismatch", phase="B5")
    backend = _exact_keys(
        identity.get("pep517_backend"),
        {"backend", "distribution", "version", "module_path", "artifact_hashes"},
        f"{code} PEP517 identity",
    )
    if (
        backend.get("backend") != "hatchling.build"
        or backend.get("distribution") != "hatchling"
        or backend.get("version") != locked.get("hatchling", {}).get("version")
        or backend.get("artifact_hashes") != locked.get("hatchling", {}).get("artifact_hashes")
    ):
        fail(f"{code} PEP517 backend closure mismatch", phase="B5")
    helper = _exact_keys(
        identity.get("pep660_editable_build"),
        {"distribution", "version", "module", "module_path", "lock_sha256", "artifact_hashes"},
        f"{code} PEP660 identity",
    )
    lock_sha = identity["lock"]["sha256"]
    if (
        helper.get("distribution") != "editables"
        or helper.get("version") != "0.6"
        or helper.get("module") != "editables"
        or helper.get("lock_sha256") != lock_sha
        or helper.get("artifact_hashes") != locked.get("editables", {}).get("artifact_hashes")
    ):
        fail(f"{code} PEP660 helper identity mismatch", phase="B5")
    for relative in (backend["module_path"], helper["module_path"]):
        relative_path = Path(str(relative))
        if (
            relative_path.is_absolute()
            or str(relative_path) != str(relative)
            or any(part in {".", ".."} for part in relative_path.parts)
            or not (runtime_root / relative_path).resolve(strict=True).is_relative_to(runtime_root)
        ):
            fail(f"{code} backend/helper module path escaped", phase="B5")
    live = _live_product_probe(code, interpreter)
    if (
        Path(str(live.get("prefix"))).resolve(strict=True) != runtime_root
        or Path(str(live.get("executable"))).resolve(strict=True)
        != interpreter.resolve(strict=True)
        or live.get("python_version") != identity.get("python_version")
        or live.get("python_implementation") != identity.get("python_implementation")
        or not str(live.get("python_version", "")).startswith("3.11.")
        or live.get("python_implementation") != "cpython"
    ):
        fail(f"{code} live sys.prefix mismatch", phase="B5")
    modules = live.get("modules", {})
    if live.get("distributions") != identity.get("installed_distributions"):
        fail(f"{code} installed distribution identity is fabricated or stale", phase="B5")
    required_editables = {"gove-zone"} if code == "GZ" else {"gove-zone", "acgs-control-plane"}
    if set(live["distributions"]) != set(locked) | required_editables:
        fail(f"{code} installed distribution set differs from lock plus editables", phase="B5")
    for name, entry in locked.items():
        observed = live["distributions"].get(name, {})
        location = Path(str(observed.get("location", ""))).resolve(strict=True)
        if observed.get("version") != entry["version"] or not location.is_relative_to(runtime_root):
            fail(f"{code} installed locked distribution mismatch: {name}", phase="B5")
    editable_manifests = {
        "gove-zone": repo_root / "packages/gove-zone/pyproject.toml",
        "acgs-control-plane": repo_root / "packages/acgs-control-plane/pyproject.toml",
    }
    for name in required_editables:
        manifest_path = editable_manifests[name]
        expected_version = _manifest_expected_version(
            tomllib.loads(manifest_path.read_text(encoding="utf-8")), manifest_path
        )
        observed = live["distributions"].get(name, {})
        location = Path(str(observed.get("location", ""))).resolve(strict=True)
        if observed.get("version") != expected_version or not location.is_relative_to(runtime_root):
            fail(f"{code} installed editable distribution mismatch: {name}", phase="B5")
    if (
        modules.get("editables", {}).get("version") != "0.6"
        or modules.get("hatchling", {}).get("version") != locked["hatchling"]["version"]
    ):
        fail(f"{code} live helper/backend mismatch", phase="B5")
    if Path(modules["editables"]["path"]).resolve(strict=True) != (
        runtime_root / helper["module_path"]
    ).resolve(strict=True):
        fail(f"{code} copied/fabricated editables path rejected", phase="B5")
    if Path(modules["hatchling"]["path"]).resolve(strict=True) != (
        runtime_root / backend["module_path"]
    ).resolve(strict=True):
        fail(f"{code} copied/fabricated Hatchling path rejected", phase="B5")


def _fnm_probe(command: str, repo_root: Path) -> tuple[str, Path]:
    fnm_raw = shutil.which("fnm")
    if fnm_raw is None:
        fail("fnm is unavailable for live UI validation", phase="B5")
    fnm = Path(fnm_raw).resolve(strict=True)
    env = {
        key: value for key, value in os.environ.items() if key not in {"PYTHONPATH", "VIRTUAL_ENV"}
    }
    located = subprocess.run(
        [str(fnm), "exec", "--using", "24.18.0", "--", "which", command],
        text=True,
        capture_output=True,
        check=False,
        env=env,
        cwd=repo_root / "acgi-ai",
    )
    if located.returncode != 0:
        fail(f"live UI {command} probe failed", phase="B5")
    raw_path = Path(located.stdout.strip())
    if not raw_path.is_absolute() or not raw_path.is_file():
        fail(f"live UI {command} executable is unsafe", phase="B5")
    canonical = raw_path.resolve(strict=True)
    completed = subprocess.run(
        [str(fnm), "exec", "--using", "24.18.0", "--", str(canonical), "--version"],
        text=True,
        capture_output=True,
        check=False,
        env=env,
        cwd=repo_root / "acgi-ai",
    )
    if completed.returncode != 0:
        fail(f"live UI {command} version probe failed", phase="B5")
    return completed.stdout.strip(), canonical


def _validate_ui(identity: dict[str, Any], repo_root: Path) -> None:
    node = _exact_keys(identity.get("node"), {"version", "executable"}, "UI node identity")
    pnpm = _exact_keys(identity.get("pnpm"), {"version", "executable"}, "UI pnpm identity")
    if node.get("version") != "24.18.0" or pnpm.get("version") != "9.15.4":
        fail("UI tool version mismatch", phase="B5")
    lexical_root = (repo_root / "acgi-ai/node_modules").absolute()
    expected_root = lexical_root.resolve(strict=True)
    if lexical_root != expected_root or not expected_root.is_dir():
        fail("UI node_modules is symlinked or noncanonical", phase="B5")
    if identity.get("module_root") != str(expected_root):
        fail("UI module root mismatch", phase="B5")
    observed_node, node_path = _fnm_probe("node", repo_root)
    observed_pnpm, pnpm_path = _fnm_probe("pnpm", repo_root)
    if (
        observed_node != "v24.18.0"
        or observed_pnpm != "9.15.4"
        or node.get("executable") != str(node_path)
        or pnpm.get("executable") != str(pnpm_path)
    ):
        fail("UI live executable/version identity mismatch", phase="B5")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True)
    parser.add_argument("--assignment-map", required=True, type=Path)
    parser.add_argument("--assignment", required=True)
    parser.add_argument("--identity-dir", required=True, type=Path)
    parser.add_argument("--require-fresh-bootstrap-records", action="store_true")
    parser.add_argument("--reject-missing", action="store_true")
    parser.add_argument("--reject-extra", action="store_true")
    parser.add_argument("--reject-unassigned-runtime-paths", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        repo_root = assert_evidence_runtime(require_dependencies=True)
        if not all(
            (
                args.require_fresh_bootstrap_records,
                args.reject_missing,
                args.reject_extra,
                args.reject_unassigned_runtime_paths,
            )
        ):
            fail("all fail-closed identity validation flags are mandatory", phase="B5")
        if NODE_RE.fullmatch(args.node) is None:
            fail("invalid NODE_ID", phase="B5")
        assignment_map_path = (
            args.assignment_map
            if args.assignment_map.is_absolute()
            else repo_root / args.assignment_map
        ).resolve(strict=True)
        expected_map_path = (repo_root / "requirements/saas-beta/bootstrap-by-scope.json").resolve(
            strict=True
        )
        if assignment_map_path != expected_map_path:
            fail("assignment map path is noncanonical", phase="B5")
        assignment_map = _load_assignment_map(assignment_map_path)
        if args.node not in assignment_map or args.assignment != assignment_map[args.node]:
            fail("supplied assignment is narrower/broader than the committed node map", phase="B5")
        tokens = assignment_tokens(args.assignment)

        evidence_root = evidence_root_from_env(repo_root)
        if not args.identity_dir.is_absolute():
            fail("identity directory must be absolute", phase="B5")
        identity_dir = args.identity_dir.resolve(strict=True)
        if identity_dir != evidence_root / args.node:
            fail("identity directory must be the out-of-tree NODE_ID directory", phase="B5")
        output = canonical_node_evidence_path(
            args.output,
            repo_root,
            node_id=args.node,
            filename="environment-identities.json",
            must_exist=False,
        )

        observed_files = {
            path.name.removeprefix("environment-").removesuffix(".json"): path
            for path in identity_dir.glob("environment-*.json")
            if path.name != "environment-identities.json"
        }
        expected_codes = set(tokens)
        missing = expected_codes - set(observed_files)
        extra = set(observed_files) - expected_codes
        if missing or extra:
            fail(
                "environment identity file set mismatch; "
                f"missing={sorted(missing)} extra={sorted(extra)}",
                phase="B5",
            )
        for code in {"EVID", "CP", "GZ", "UI"} - expected_codes:
            runtime = _runtime_path(code, repo_root)
            if os.path.lexists(runtime):
                fail(f"unassigned/retained runtime path rejected: {code}={runtime}", phase="B5")

        identities: dict[str, dict[str, Any]] = {}
        locks: dict[str, dict[str, dict[str, Any]]] = {}
        for code in tokens:
            identity_path = canonical_node_evidence_path(
                observed_files[code],
                repo_root,
                node_id=args.node,
                filename=f"environment-{code}.json",
                must_exist=True,
            )
            identity = load_json(identity_path)
            expected_keys = (
                EVID_KEYS if code == "EVID" else PYTHON_KEYS if code in {"CP", "GZ"} else UI_KEYS
            )
            identity = _exact_keys(identity, expected_keys, f"{code} environment identity")
            if (
                identity.get("schema_version") != "acgs-environment-identity/v1"
                or identity.get("code") != code
                or identity.get("node_id") != args.node
                or identity.get("output_path") != str(identity_path.resolve(strict=True))
                or identity.get("captured_at_utc")
                != identity.get("bootstrap_record", {}).get("captured_at_utc")
            ):
                fail(f"{code} copied/fabricated environment identity rejected", phase="B5")
            parse_utc(str(identity.get("captured_at_utc")))
            _validate_marker(code, identity, identity_path, args.node, repo_root)
            _, locked = _validate_lock(code, identity, repo_root)
            locks[code] = locked
            if code == "EVID":
                _validate_evid(identity, locked, repo_root)
            elif code in {"CP", "GZ"}:
                _validate_python_product(code, identity, locked, repo_root)
            else:
                _validate_ui(identity, repo_root)
            identities[code] = identity

        nonces = [identity["bootstrap_record"]["nonce"] for identity in identities.values()]
        if len(nonces) != len(set(nonces)):
            fail("assigned bootstrap records must have distinct nonces", phase="B5")

        helper_environments: dict[str, dict[str, Any]] = {}
        for code in ("CP", "GZ"):
            if code not in identities:
                continue
            helper = identities[code]["pep660_editable_build"]
            helper_environments[code] = {
                "module_path": helper["module_path"],
                "product_lock_sha256": helper["lock_sha256"],
                "artifact_hashes": helper["artifact_hashes"],
            }
        evid = identities["EVID"]
        cryptography = locks["EVID"].get("cryptography")
        if cryptography is None:
            fail("EVID cryptography lock identity is missing", phase="B5")
        result = {
            "schema_version": "acgs-environment-identities/v1",
            "node_id": args.node,
            "assignment": args.assignment,
            "environment_identities": identities,
            "pep660_editable_build": {
                "distribution": "editables",
                "version": "0.6",
                "module": "editables",
                "environments": helper_environments,
            },
            "ed25519_implementation": {
                "distribution": "cryptography",
                "version": cryptography["version"],
                "module": "cryptography.hazmat.primitives.asymmetric.ed25519",
                "evidence_test_lock_sha256": evid["lock"]["sha256"],
                "artifact_hashes": cryptography["artifact_hashes"],
            },
        }
        write_json_exclusive(output, result)
        print(output)
        return 0
    except (EvidenceError, OSError, subprocess.SubprocessError) as exc:
        print(f"environment identity validation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
