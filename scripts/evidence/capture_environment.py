#!/usr/bin/env python3
"""Capture a live assigned product runtime from the universal EVID interpreter."""

from __future__ import annotations

import argparse
import os
import secrets
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

from _common import (
    CODE_PATHS,
    NODE_RE,
    EvidenceError,
    assert_evidence_runtime,
    canonical_node_evidence_path,
    check_lock_header,
    fail,
    parse_lock,
    sha256_file,
    strict_json_loads,
    utc_now,
    write_bootstrap_identity_exclusive,
)

FNM_EXECUTABLE = Path("/home/martin/.local/share/fnm/fnm")
FNM_SHA256 = "2b8810b610654de6914a17e3235d3948fbd5c7d4712815ac45724c3f06e8966f"

TARGET_SNIPPET = r"""
import importlib
import importlib.metadata
import json
import pathlib
import sys

result = {
    "executable": sys.executable,
    "prefix": sys.prefix,
    "python_version": ".".join(str(v) for v in sys.version_info[:3]),
    "python_implementation": sys.implementation.name,
    "distributions": {},
    "modules": {},
}
for dist in importlib.metadata.distributions():
    name = __import__("re").sub(r"[-_.]+", "-", dist.metadata["Name"]).lower()
    if name in result["distributions"]:
        raise SystemExit(f"duplicate distribution: {name}")
    result["distributions"][name] = {
        "version": dist.version,
        "location": str(pathlib.Path(dist.locate_file("")).resolve()),
    }
for module_name, distribution in (("editables", "editables"), ("hatchling", "hatchling")):
    module = importlib.import_module(module_name)
    result["modules"][module_name] = {
        "distribution": distribution,
        "version": importlib.metadata.version(distribution),
        "path": str(pathlib.Path(module.__file__).resolve()),
    }
print(json.dumps(result, sort_keys=True, allow_nan=False))
"""


def _run_target(interpreter: Path) -> dict[str, Any]:
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("VIRTUAL_ENV", None)
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
        [str(interpreter), "-I", "-c", TARGET_SNIPPET],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    if completed.returncode != 0:
        fail(f"live target interpreter inspection failed: {completed.stderr}", phase="B3")
    value = strict_json_loads(completed.stdout)
    if not isinstance(value, dict):
        fail("live target interpreter returned a non-object", phase="B3")
    return value


def _validate_pep660_lock_contract(
    code: str,
    locked: dict[str, dict[str, Any]],
    required_editables: str,
) -> None:
    helper = locked.get("editables")
    backend = locked.get("hatchling")
    if (
        required_editables != "0.6"
        or not isinstance(helper, dict)
        or helper.get("version") != "0.6"
        or not helper.get("artifact_hashes")
    ):
        fail(f"{code} requires exact hashed first-class editables==0.6", phase="B3")
    if not isinstance(backend, dict) or not backend.get("artifact_hashes"):
        fail(f"{code} lock lacks hashed PEP 517 Hatchling backend closure", phase="B1")


def _capture_python(
    code: str,
    interpreter_arg: Path,
    lock_arg: Path,
    required_editables: str,
    repo_root: Path,
    node_id: str,
    output: Path,
) -> None:
    expected_interpreter_rel, expected_lock_rel = CODE_PATHS[code]
    expected_interpreter_lexical = repo_root / expected_interpreter_rel
    if not interpreter_arg.is_absolute():
        fail(f"{code} interpreter path must be absolute", phase="B3")
    provided_lexical = interpreter_arg
    if str(provided_lexical) != str(expected_interpreter_lexical):
        fail(f"{code} interpreter path must be exactly {expected_interpreter_lexical}", phase="B3")
    if not expected_interpreter_lexical.is_file():
        fail(f"assigned {code} interpreter was not bootstrapped", phase="B3")
    runtime_root = expected_interpreter_lexical.parents[1]
    if runtime_root.absolute() != runtime_root.resolve(strict=True):
        fail(f"{code} venv root must not be a symlink or noncanonical path", phase="B3")

    lock = lock_arg if lock_arg.is_absolute() else repo_root / lock_arg
    lock = lock.resolve(strict=True)
    expected_lock = (repo_root / expected_lock_rel).resolve(strict=True)
    if lock != expected_lock:
        fail(f"{code} lock path mismatch: {lock} != {expected_lock}", phase="B1")
    check_lock_header(lock, expected_lock_rel.replace(".lock", ".in"), expected_lock_rel)
    locked = parse_lock(lock)
    _validate_pep660_lock_contract(code, locked, required_editables)

    observed = _run_target(expected_interpreter_lexical)
    observed_prefix = Path(str(observed.get("prefix", ""))).resolve(strict=True)
    if observed_prefix != runtime_root:
        fail(f"{code} sys.prefix mismatch: {observed_prefix} != {runtime_root}", phase="B3")
    executable_real = Path(str(observed.get("executable", ""))).resolve(strict=True)
    if executable_real != expected_interpreter_lexical.resolve(strict=True):
        fail(f"{code} interpreter executable realpath mismatch", phase="B3")
    distributions = observed.get("distributions")
    if not isinstance(distributions, dict):
        fail(f"{code} target distribution map malformed", phase="B3")
    required_editables = {"gove-zone"} if code == "GZ" else {"gove-zone", "acgs-control-plane"}
    expected_distributions = set(locked) | required_editables
    missing = expected_distributions - set(distributions)
    extra = set(distributions) - expected_distributions
    if missing or extra:
        fail(
            f"{code} installed/lock set mismatch; missing={sorted(missing)} extra={sorted(extra)}",
            phase="B3",
        )
    for name, lock_entry in locked.items():
        observed_entry = distributions.get(name)
        if (
            not isinstance(observed_entry, dict)
            or observed_entry.get("version") != lock_entry["version"]
        ):
            fail(f"{code} locked version mismatch for {name}", phase="B3")
        location = Path(str(observed_entry.get("location", ""))).resolve(strict=True)
        if not location.is_relative_to(runtime_root):
            fail(f"{code} distribution {name} escaped its venv: {location}", phase="B3")
    editable_manifests = {
        "gove-zone": repo_root / "packages/gove-zone/pyproject.toml",
        "acgs-control-plane": repo_root / "packages/acgs-control-plane/pyproject.toml",
    }
    for name in required_editables:
        observed_entry = distributions.get(name)
        manifest = tomllib.loads(editable_manifests[name].read_text(encoding="utf-8"))
        expected_version = manifest.get("project", {}).get("version")
        if (
            not isinstance(observed_entry, dict)
            or not isinstance(expected_version, str)
            or observed_entry.get("version") != expected_version
        ):
            fail(f"{code} required editable identity mismatch: {name}", phase="B4")
        location = Path(str(observed_entry.get("location", ""))).resolve(strict=True)
        if not location.is_relative_to(runtime_root):
            fail(f"{code} editable distribution metadata escaped its venv: {name}", phase="B4")
    modules = observed.get("modules")
    if not isinstance(modules, dict):
        fail(f"{code} target module map malformed", phase="B3")
    editables = modules.get("editables")
    hatchling = modules.get("hatchling")
    if not isinstance(editables, dict) or editables.get("version") != "0.6":
        fail(f"{code} live editables identity mismatch", phase="B3")
    if (
        not isinstance(hatchling, dict)
        or hatchling.get("version") != locked["hatchling"]["version"]
    ):
        fail(f"{code} live Hatchling identity mismatch", phase="B3")
    editables_path = Path(str(editables.get("path", ""))).resolve(strict=True)
    hatchling_path = Path(str(hatchling.get("path", ""))).resolve(strict=True)
    if not editables_path.is_relative_to(runtime_root) or not hatchling_path.is_relative_to(
        runtime_root
    ):
        fail(f"{code} helper/backend module escaped its own venv", phase="B3")

    marker = runtime_root / ".acgs-product-bootstrap.json"
    pyvenv = runtime_root / "pyvenv.cfg"
    if not pyvenv.is_file():
        fail(f"{code} venv lacks pyvenv.cfg", phase="B3")

    def values(runtime_ctime_ns: str) -> tuple[dict[str, Any], dict[str, Any]]:
        marker_record = {
            "schema_version": "acgs-bootstrap-record/v1",
            "node_id": node_id,
            "code": code,
            "captured_at_utc": utc_now(),
            "runtime_root": str(runtime_root),
            "interpreter": str(expected_interpreter_lexical),
            "interpreter_realpath": str(executable_real),
            "python_version": observed["python_version"],
            "python_implementation": observed["python_implementation"],
            "runtime_ctime_ns": runtime_ctime_ns,
            "pyvenv_cfg_sha256": sha256_file(pyvenv),
            "lock_sha256": sha256_file(lock),
            "nonce": secrets.token_hex(32),
        }
        identity = {
            "schema_version": "acgs-environment-identity/v1",
            "code": code,
            "node_id": node_id,
            "captured_at_utc": marker_record["captured_at_utc"],
            "interpreter": str(expected_interpreter_lexical),
            "interpreter_realpath": str(executable_real),
            "module_root": str(runtime_root),
            "python_version": observed["python_version"],
            "python_implementation": observed["python_implementation"],
            "lock": {
                "path": expected_lock_rel,
                "sha256": sha256_file(lock),
                "distributions": locked,
            },
            "installed_distributions": distributions,
            "pep517_backend": {
                "backend": "hatchling.build",
                "distribution": "hatchling",
                "version": hatchling["version"],
                "module_path": str(hatchling_path.relative_to(runtime_root)),
                "artifact_hashes": locked["hatchling"]["artifact_hashes"],
            },
            "pep660_editable_build": {
                "distribution": "editables",
                "version": "0.6",
                "module": "editables",
                "module_path": str(editables_path.relative_to(runtime_root)),
                "lock_sha256": sha256_file(lock),
                "artifact_hashes": locked["editables"]["artifact_hashes"],
            },
            "bootstrap_record": marker_record,
            "output_path": str(output),
        }
        return marker_record, identity

    write_bootstrap_identity_exclusive(marker, output, values)


def _fnm_capture(version: str, command: str, cwd: Path) -> tuple[str, Path, str]:
    fnm = FNM_EXECUTABLE
    if (
        not fnm.is_file()
        or fnm.is_symlink()
        or fnm.resolve(strict=True) != fnm
        or sha256_file(fnm) != FNM_SHA256
    ):
        fail("canonical hash-pinned fnm is required for UI identity capture", phase="B5")
    env = {
        key: value for key, value in os.environ.items() if key not in {"PYTHONPATH", "VIRTUAL_ENV"}
    }
    path_output = subprocess.run(
        [fnm, "exec", "--using", version, "--", "which", command],
        text=True,
        capture_output=True,
        check=False,
        cwd=cwd,
        env=env,
    )
    if path_output.returncode != 0:
        fail(f"cannot resolve canonical {command}: {path_output.stderr}", phase="B5")
    lexical = Path(path_output.stdout.strip())
    executable = lexical.resolve(strict=True)
    if not executable.is_file():
        fail(f"canonical {command} executable is not a regular file", phase="B5")
    completed = subprocess.run(
        [fnm, "exec", "--using", version, "--", str(lexical), "--version"],
        text=True,
        capture_output=True,
        check=False,
        cwd=cwd,
        env=env,
    )
    if completed.returncode != 0:
        fail(f"fnm UI identity command failed: {completed.stderr}", phase="B5")
    return completed.stdout.strip(), executable, sha256_file(executable)


def _capture_ui(
    node_version: str,
    pnpm_version: str,
    lock_arg: Path,
    repo_root: Path,
    node_id: str,
    output: Path,
) -> None:
    if node_version != "24.18.0" or pnpm_version != "9.15.4":
        fail("UI tool identities must be Node 24.18.0 and pnpm 9.15.4", phase="B5")
    node_modules = (repo_root / "acgi-ai/node_modules").absolute()
    if not node_modules.is_dir() or node_modules.resolve(strict=True) != node_modules:
        fail("assigned UI node_modules is absent, retained symlinked, or noncanonical", phase="B5")
    lock = lock_arg if lock_arg.is_absolute() else repo_root / lock_arg
    lock = lock.resolve(strict=True)
    expected_lock = (repo_root / "acgi-ai/pnpm-lock.yaml").resolve(strict=True)
    if lock != expected_lock:
        fail("UI lock path mismatch", phase="B5")
    ui_root = repo_root / "acgi-ai"
    actual_node, node_path, node_sha256 = _fnm_capture(node_version, "node", ui_root)
    actual_pnpm, pnpm_path, pnpm_sha256 = _fnm_capture(node_version, "pnpm", ui_root)
    if actual_node != f"v{node_version}" or actual_pnpm != pnpm_version:
        fail(f"UI live tool version mismatch: node={actual_node} pnpm={actual_pnpm}", phase="B5")
    marker = node_modules / ".acgs-product-bootstrap.json"

    def values(runtime_ctime_ns: str) -> tuple[dict[str, Any], dict[str, Any]]:
        marker_record = {
            "schema_version": "acgs-bootstrap-record/v1",
            "node_id": node_id,
            "code": "UI",
            "captured_at_utc": utc_now(),
            "runtime_root": str(node_modules),
            "interpreter": str(node_path),
            "interpreter_realpath": str(node_path),
            "node_version": node_version,
            "node_sha256": node_sha256,
            "pnpm_executable": str(pnpm_path),
            "pnpm_version": pnpm_version,
            "pnpm_sha256": pnpm_sha256,
            "runtime_ctime_ns": runtime_ctime_ns,
            "lock_sha256": sha256_file(lock),
            "nonce": secrets.token_hex(32),
        }
        identity = {
            "schema_version": "acgs-environment-identity/v1",
            "code": "UI",
            "node_id": node_id,
            "captured_at_utc": marker_record["captured_at_utc"],
            "node": {
                "version": node_version,
                "executable": str(node_path),
                "sha256": node_sha256,
            },
            "pnpm": {
                "version": pnpm_version,
                "executable": str(pnpm_path),
                "sha256": pnpm_sha256,
            },
            "module_root": str(node_modules),
            "lock": {"path": "acgi-ai/pnpm-lock.yaml", "sha256": sha256_file(lock)},
            "bootstrap_record": marker_record,
            "output_path": str(output),
        }
        return marker_record, identity

    write_bootstrap_identity_exclusive(marker, output, values)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", required=True, choices=["CP", "GZ", "UI"])
    parser.add_argument("--interpreter", type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--require-editables")
    parser.add_argument("--node-version")
    parser.add_argument("--pnpm-version")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        repo_root = assert_evidence_runtime(require_dependencies=True)
        if not args.output.is_absolute() or not NODE_RE.fullmatch(args.output.parent.name):
            fail("environment output must be named for its code under exact NODE_ID", phase="B5")
        output = canonical_node_evidence_path(
            args.output,
            repo_root,
            node_id=args.output.parent.name,
            filename=f"environment-{args.code}.json",
            must_exist=False,
        )
        if args.code in {"CP", "GZ"}:
            if args.interpreter is None or args.require_editables is None:
                fail(
                    "Python product capture requires interpreter and editables version", phase="B3"
                )
            if args.node_version is not None or args.pnpm_version is not None:
                fail("Python product capture rejects UI arguments", phase="B3")
            _capture_python(
                args.code,
                args.interpreter,
                args.lock,
                args.require_editables,
                repo_root,
                output.parent.name,
                output,
            )
        else:
            if args.interpreter is not None or args.require_editables is not None:
                fail("UI capture rejects Python product arguments", phase="B5")
            if args.node_version is None or args.pnpm_version is None:
                fail("UI capture requires exact Node and pnpm versions", phase="B5")
            _capture_ui(
                args.node_version,
                args.pnpm_version,
                args.lock,
                repo_root,
                output.parent.name,
                output,
            )
        print(output)
        return 0
    except (EvidenceError, OSError, subprocess.SubprocessError) as exc:
        print(f"environment capture failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
