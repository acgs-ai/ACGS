#!/usr/bin/env python3
"""Verify and record the freshly hash-synced universal EVID interpreter."""

from __future__ import annotations

import argparse
import importlib.metadata
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

from _common import (
    DIRECT_EVIDENCE_MODULES,
    NODE_RE,
    EvidenceError,
    assert_evidence_runtime,
    canonical_distribution_name,
    canonical_node_evidence_path,
    check_lock_header,
    fail,
    sha256_file,
    utc_now,
    verify_installed_against_lock,
    write_bootstrap_identity_exclusive,
)

REQUIREMENT_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:(==|>=)([^,]+))?(?:,<[^,]+)?$")
TRUSTED_UV = Path("/home/martin/.local/bin/uv")
TRUSTED_UV_SHA256 = "a00d3a24514fc0403fc232c9c99bf5e542657c38f4ed941e0611731e4cff268b"


def _check_requirement(requirement: str, locked: dict[str, dict[str, object]]) -> None:
    match = REQUIREMENT_RE.fullmatch(requirement)
    if match is None:
        fail(f"unsupported required identity: {requirement!r}", phase="B2")
    name = canonical_distribution_name(match.group(1))
    if name not in locked:
        fail(f"required distribution is absent from EVID lock: {name}", phase="B2")
    actual = str(locked[name]["version"])
    operator, expected = match.group(2), match.group(3)
    if operator == "==" and actual != expected:
        fail(f"required exact version mismatch: {name} {actual} != {expected}", phase="B2")
    if operator == ">=" and expected is not None:
        try:
            actual_tuple = tuple(int(part) for part in re.findall(r"\d+", actual)[:3])
            expected_tuple = tuple(int(part) for part in re.findall(r"\d+", expected)[:3])
        except ValueError as exc:
            fail(f"cannot compare version for {name}: {exc}", phase="B2")
        if actual_tuple < expected_tuple:
            fail(f"required minimum version mismatch: {name} {actual} < {expected}", phase="B2")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", required=True, choices=["EVID"])
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--expected-interpreter", required=True, type=Path)
    parser.add_argument("--expected-python", required=True)
    parser.add_argument("--expected-uv", required=True)
    parser.add_argument("--expected-uv-executable", required=True, type=Path)
    parser.add_argument("--require-module-root", required=True, type=Path)
    parser.add_argument("--require", action="append", default=[])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        repo_root = assert_evidence_runtime(require_dependencies=True)
        lock = args.lock if args.lock.is_absolute() else repo_root / args.lock
        lock = lock.resolve(strict=True)
        expected_lock = (repo_root / "requirements/saas-beta/evidence-test.lock").resolve(
            strict=True
        )
        if lock != expected_lock:
            fail(f"EVID lock must be exactly {expected_lock}, got {lock}", phase="B1")
        check_lock_header(
            lock,
            "requirements/saas-beta/evidence-test.in",
            "requirements/saas-beta/evidence-test.lock",
        )

        expected_prefix = (repo_root / ".venv-evidence").resolve(strict=True)
        expected_prefix_lexical = repo_root / ".venv-evidence"
        if (
            not args.require_module_root.is_absolute()
            or args.require_module_root != expected_prefix_lexical
        ):
            fail("EVID module-root argument is noncanonical", phase="B2")
        module_root = args.require_module_root.resolve(strict=True)
        if module_root != expected_prefix:
            fail(f"EVID module root is noncanonical: {module_root}", phase="B2")
        expected_lexical = repo_root / ".venv-evidence/bin/python"
        if (
            not args.expected_interpreter.is_absolute()
            or args.expected_interpreter != expected_lexical
        ):
            fail("EVID expected interpreter argument is noncanonical", phase="B2")
        expected_python = args.expected_interpreter.resolve(strict=True)
        canonical_python = expected_lexical.resolve(strict=True)
        if (
            expected_python != canonical_python
            or Path(sys.executable).absolute() != expected_lexical
        ):
            fail("EVID interpreter realpath mismatch", phase="B2")
        if args.expected_python != "3.11" or sys.version_info[:2] != (3, 11):
            fail("EVID Python identity must be exactly major.minor 3.11", phase="B2")

        if args.expected_uv_executable != TRUSTED_UV:
            fail("uv executable argument is noncanonical", phase="B2")
        uv_path = args.expected_uv_executable.resolve(strict=True)
        if uv_path != TRUSTED_UV or sha256_file(uv_path) != TRUSTED_UV_SHA256:
            fail("uv executable identity mismatch", phase="B2")
        completed = subprocess.run(
            [str(uv_path), "--version"],
            text=True,
            capture_output=True,
            check=False,
            env={**os.environ, "UV_OFFLINE": "1", "UV_NO_INDEX": "1", "UV_NO_CACHE": "1"},
        )
        if completed.returncode != 0:
            fail(f"uv identity check failed: {completed.stderr}", phase="B2")
        parts = completed.stdout.strip().split()
        actual_uv = parts[1] if len(parts) >= 2 else ""
        if args.expected_uv != "0.11.19" or actual_uv != args.expected_uv:
            fail(f"uv version mismatch: {actual_uv} != {args.expected_uv}", phase="B2")

        locked, installed = verify_installed_against_lock(lock, expected_prefix)
        required = args.require
        if required != ["rfc8785==0.1.4", "cryptography>=42", "jsonschema", "pytest"]:
            fail("EVID --require list must be the exact reviewed ordered set", phase="B2")
        for requirement in required:
            _check_requirement(requirement, locked)

        modules: dict[str, dict[str, str]] = {}
        for distribution, module_name in DIRECT_EVIDENCE_MODULES.items():
            module = __import__(module_name)
            module_file = Path(str(module.__file__)).resolve(strict=True)
            if not module_file.is_relative_to(expected_prefix):
                fail(f"{module_name} module escaped EVID: {module_file}", phase="B2")
            modules[module_name] = {
                "distribution": distribution,
                "version": importlib.metadata.version(distribution),
                "path": str(module_file),
            }

        if not args.output.is_absolute() or not NODE_RE.fullmatch(args.output.parent.name):
            fail("EVID identity output parent must be the exact NODE_ID", phase="B2")
        output = canonical_node_evidence_path(
            args.output,
            repo_root,
            node_id=args.output.parent.name,
            filename="environment-EVID.json",
            must_exist=False,
        )
        marker = expected_prefix / ".acgs-evidence-bootstrap.json"
        pyvenv = expected_prefix / "pyvenv.cfg"
        if not pyvenv.is_file():
            fail(f"fresh EVID lacks pyvenv.cfg: {pyvenv}", phase="B2")

        def values(runtime_ctime_ns: str) -> tuple[dict[str, object], dict[str, object]]:
            marker_record: dict[str, object] = {
                "schema_version": "acgs-bootstrap-record/v1",
                "node_id": output.parent.name,
                "code": "EVID",
                "captured_at_utc": utc_now(),
                "runtime_root": str(expected_prefix),
                "interpreter": str(repo_root / ".venv-evidence/bin/python"),
                "interpreter_realpath": str(canonical_python),
                "python_version": (
                    f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
                ),
                "python_implementation": sys.implementation.name,
                "runtime_ctime_ns": runtime_ctime_ns,
                "pyvenv_cfg_sha256": sha256_file(pyvenv),
                "lock_sha256": sha256_file(lock),
                "nonce": secrets.token_hex(32),
            }
            identity: dict[str, object] = {
                "schema_version": "acgs-environment-identity/v1",
                "code": "EVID",
                "node_id": output.parent.name,
                "captured_at_utc": marker_record["captured_at_utc"],
                "interpreter": str(repo_root / ".venv-evidence/bin/python"),
                "interpreter_realpath": str(canonical_python),
                "module_root": str(expected_prefix),
                "python_version": marker_record["python_version"],
                "python_implementation": marker_record["python_implementation"],
                "uv": {"version": actual_uv, "executable": str(uv_path)},
                "lock": {
                    "path": "requirements/saas-beta/evidence-test.lock",
                    "sha256": sha256_file(lock),
                    "distributions": locked,
                },
                "installed_distributions": installed,
                "modules": modules,
                "bootstrap_record": marker_record,
                "output_path": str(output),
            }
            return marker_record, identity

        write_bootstrap_identity_exclusive(marker, output, values)
        print(output)
        return 0
    except (EvidenceError, OSError, subprocess.SubprocessError) as exc:
        print(f"environment verification failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
