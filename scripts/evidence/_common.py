"""Shared fail-closed primitives for the SaaS-beta evidence command suite."""

from __future__ import annotations

import base64
import hashlib
import importlib
import importlib.metadata
import json
import math
import os
import re
import site
import stat
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
NODE_RE = re.compile(r"^P[0-7]-[A-Z0-9-]+$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
LOCK_ENTRY_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s;\\]+)(?:\s*;[^\\]+)?\s*\\?$")
LOCK_HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})(?:\s*\\)?$")
PINNED_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.!+_-]*$")
MAX_TRUST_WINDOW = timedelta(days=90)
MAX_COMMAND_ARGUMENT_LENGTH = 4096
JSON_SAFE_INTEGER_MAX = 9_007_199_254_740_991
CANONICAL_POSITIVE_DECIMAL_RE = re.compile(r"^[1-9][0-9]*$")
MAX_CANONICAL_DECIMAL_DIGITS = 32
TRANSCRIPT_RECORD_KEYS = {
    "argv",
    "exit_code",
    "stdout_sha256",
    "stderr_sha256",
    "started_at_utc",
    "finished_at_utc",
    "selectors",
}
EXTENDED_TRANSCRIPT_RECORD_KEYS = TRANSCRIPT_RECORD_KEYS | {
    "cwd_scope",
    "executable_sha256",
    "environment_profile_version_sha256",
    "resolved_executable_identity_sha256",
    "sandbox_executable_sha256",
    "sandbox_profile_version_sha256",
    "sandbox_resolved_identity_sha256",
}
REVIEWED_ENVIRONMENT_PROFILE = {
    "name": "acgs-reviewed-command-environment/v1",
    "inherit_ambient": False,
    "conditional_environment": {
        "uv": {"VIRTUAL_ENV": "{REPO_ROOT}/packages/gove-zone/.venv-beta"},
    },
    "environment": {
        "PATH": "{CWD}/.venv/bin:{REPO_ROOT}/.venv-evidence/bin:/usr/bin:/bin",
        "HOME": "{ISOLATED_ROOT}/home",
        "TMPDIR": "{ISOLATED_ROOT}/tmp",
        "TMP": "{ISOLATED_ROOT}/tmp",
        "TEMP": "{ISOLATED_ROOT}/tmp",
        "XDG_CACHE_HOME": "{ISOLATED_ROOT}/xdg-cache",
        "XDG_CONFIG_HOME": "{ISOLATED_ROOT}/xdg-config",
        "XDG_DATA_HOME": "{ISOLATED_ROOT}/xdg-data",
        "XDG_STATE_HOME": "{ISOLATED_ROOT}/xdg-state",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "UV_OFFLINE": "1",
        "UV_NO_INDEX": "1",
        "UV_NO_CACHE": "1",
        "UV_PYTHON_DOWNLOADS": "never",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "RUFF_CACHE_DIR": "{ISOLATED_ROOT}/ruff",
        "MYPY_CACHE_DIR": "{ISOLATED_ROOT}/mypy",
        "PYTEST_DEBUG_TEMPROOT": "{ISOLATED_ROOT}/pytest-tmp",
        "PYTEST_ADDOPTS": "-o cache_dir={ISOLATED_ROOT}/pytest-cache",
        "COVERAGE_FILE": "{ISOLATED_ROOT}/coverage/.coverage",
    },
}
REVIEWED_ENVIRONMENT_PROFILE_VERSION_SHA256 = hashlib.sha256(
    json.dumps(REVIEWED_ENVIRONMENT_PROFILE, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
REVIEWED_SANDBOX_PROFILE = {
    "name": "acgs-reviewed-command-bwrap/v1",
    "executable": "/usr/bin/bwrap",
    "host_filesystem": "ro-bind-root",
    "writable_paths": ("{ISOLATED_ROOT}",),
    "namespaces": ("user", "ipc", "pid", "uts", "cgroup", "network"),
    "die_with_parent": True,
    "new_session": True,
    "clear_environment": True,
    "cwd": "{CWD}",
}
REVIEWED_SANDBOX_PROFILE_VERSION_SHA256 = hashlib.sha256(
    json.dumps(REVIEWED_SANDBOX_PROFILE, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
BWRAP_EXECUTABLE = Path("/usr/bin/bwrap")
REVIEWED_HOST_EXECUTABLES = {
    "make": Path("/usr/bin/make"),
    "uv": Path("/home") / "martin" / ".local" / "bin" / "uv",
}
REVIEWED_HOST_EXECUTABLE_SHA256 = {
    "uv": "a00d3a24514fc0403fc232c9c99bf5e542657c38f4ed941e0611731e4cff268b",
}
REVIEWED_P0_TRANSCRIPT = (
    (
        "root:EVID-gate",
        (
            ".venv-evidence/bin/python",
            "-m",
            "pytest",
            "-q",
            "tests/saas_beta/test_evidence_bootstrap.py::"
            "test_universal_evidence_interpreter_offline",
        ),
    ),
    ("packages/acgs-control-plane:local-gate", (".venv/bin/ruff", "check", ".")),
    (
        "packages/acgs-control-plane:local-gate",
        (".venv/bin/ruff", "format", "--check", "."),
    ),
    ("packages/acgs-control-plane:local-gate", (".venv/bin/mypy", "src/")),
    ("packages/acgs-control-plane:local-gate", (".venv/bin/pytest", "-q")),
    (
        "packages/gove-zone:local-gate",
        (
            "uv",
            "run",
            "--active",
            "--no-sync",
            "--python",
            "3.11",
            "--package",
            "gove-zone",
            "ruff",
            "check",
            "packages/gove-zone/src",
            "packages/gove-zone/tests",
            "packages/gove-zone/examples",
        ),
    ),
    (
        "packages/gove-zone:local-gate",
        (
            "uv",
            "run",
            "--active",
            "--no-sync",
            "--python",
            "3.11",
            "--package",
            "gove-zone",
            "ruff",
            "format",
            "--check",
            "packages/gove-zone/src",
            "packages/gove-zone/tests",
            "packages/gove-zone/examples",
        ),
    ),
    (
        "packages/gove-zone:local-gate",
        (
            "uv",
            "run",
            "--active",
            "--no-sync",
            "--python",
            "3.11",
            "--package",
            "gove-zone",
            "mypy",
            "packages/gove-zone/src/gove_zone",
        ),
    ),
    (
        "packages/gove-zone:local-gate",
        (
            "uv",
            "run",
            "--active",
            "--no-sync",
            "--python",
            "3.11",
            "--package",
            "gove-zone",
            "python",
            "-m",
            "pytest",
            "packages/gove-zone/tests",
            "--import-mode=importlib",
            "-q",
            "--cov=gove_zone",
            "--cov-fail-under=90",
        ),
    ),
    (
        "root:P0-EVIDENCE-000",
        (
            ".venv-evidence/bin/python",
            "-m",
            "pytest",
            "-q",
            "tests/saas_beta/test_evidence_bootstrap.py::"
            "test_clean_sibling_hash_locked_bootstraps_and_round_trip",
            "tests/saas_beta/test_evidence_bootstrap.py::"
            "test_clean_sibling_rejects_loader_and_git_authority_before_mutation",
            "tests/saas_beta/test_evidence_bootstrap.py::"
            "test_environment_identities_exactly_match_assignment",
            "tests/saas_beta/test_evidence_bootstrap.py::"
            "test_missing_extra_or_retained_environment_rejected",
            "tests/saas_beta/test_evidence_bootstrap.py::"
            "test_pep660_helpers_required_for_assigned_python_scopes",
        ),
    ),
)
REVIEWED_P0_MEMBRANE_TRANSCRIPT = (
    REVIEWED_P0_TRANSCRIPT[0],
    *REVIEWED_P0_TRANSCRIPT[1:5],
    (
        "packages/acgs-control-plane:P0-MEMBRANE-001-exact",
        (
            ".venv/bin/pytest",
            "-q",
            "tests/integration/test_production_posture.py::"
            "test_production_rejects_legacy_unsigned_routes",
            "tests/integration/test_production_posture.py::"
            "test_tenant_bootstrap_and_register_contract_stub_no_mutation",
        ),
    ),
    (
        "root:P0-MEMBRANE-001",
        (
            "packages/acgs-control-plane/.venv/bin/python",
            "-m",
            "pytest",
            "-q",
            "packages/acgs-control-plane/tests/integration/test_production_posture.py::"
            "test_production_rejects_legacy_unsigned_routes",
            "packages/acgs-control-plane/tests/integration/test_production_posture.py::"
            "test_tenant_bootstrap_and_register_contract_stub_no_mutation",
        ),
    ),
)
_GZ_LOCKED_PREFIX = (
    "uv",
    "run",
    "--active",
    "--no-sync",
    "--python",
    "3.11",
    "--package",
    "gove-zone",
)
REVIEWED_P0_CLAIMS_TRANSCRIPT = (
    REVIEWED_P0_TRANSCRIPT[0],
    *REVIEWED_P0_TRANSCRIPT[1:5],
    (
        "packages/acgs-control-plane:P0-MEMBRANE-001-exact",
        (
            ".venv/bin/pytest",
            "-q",
            "tests/integration/test_production_posture.py::"
            "test_production_rejects_legacy_unsigned_routes",
            "tests/integration/test_production_posture.py::"
            "test_tenant_bootstrap_and_register_contract_stub_no_mutation",
        ),
    ),
    *REVIEWED_P0_TRANSCRIPT[5:9],
    (
        "packages/gove-zone:P0-CLAIMS-002-exact",
        (
            *_GZ_LOCKED_PREFIX,
            "python",
            "-m",
            "pytest",
            "-q",
            "packages/gove-zone/tests/test_receipt_signing.py::"
            "test_production_default_no_verifier_fails_loud",
            "packages/gove-zone/tests/test_receipt_signing.py::"
            "test_unsigned_rejected_when_required",
            "packages/gove-zone/tests/test_executor_guard.py::test_executor_refuses_no_receipt",
            "packages/gove-zone/tests/test_executor_guard.py::test_executor_refuses_denied_receipt",
            "packages/gove-zone/tests/test_executor_guard.py::"
            "test_executor_refuses_escalated_receipt",
            "packages/gove-zone/tests/test_receipt_consumption.py::"
            "test_resume_replay_blocked_with_ledger",
            "packages/gove-zone/tests/test_receipt_consumption.py::"
            "test_replay_without_ledger_pins_stateless_gate",
            "packages/gove-zone/tests/test_replay.py::test_replay_call_diverges_when_args_change",
            "packages/gove-zone/tests/test_replay.py::test_side_store_tamper_cross_check",
            "packages/gove-zone/tests/test_acgs_proofpack.py::"
            "test_signed_pack_without_key_fails_closed",
            "packages/gove-zone/tests/test_acgs_proofpack.py::"
            "test_replay_report_status_never_upgrades_validity",
            "packages/gove-zone/tests/test_acgs_proofpack.py::"
            "test_cli_require_signature_rejects_unsigned_pack",
        ),
    ),
    ("root:lint-docs", ("make", "lint-docs")),
    (
        "root:docs-full",
        (
            "packages/acgs-control-plane/.venv/bin/python",
            "-m",
            "pytest",
            "-q",
            "tests/docs",
            "--import-mode=importlib",
        ),
    ),
    (
        "root:P0-CLAIMS-002",
        (
            "packages/acgs-control-plane/.venv/bin/python",
            "-m",
            "pytest",
            "-q",
            "tests/docs/test_saas_beta_claims.py::test_claim_boundaries_and_control_plane_readme",
        ),
    ),
)
REVIEWED_TRANSCRIPTS_BY_NODE = {
    "P0-EVIDENCE-000": REVIEWED_P0_TRANSCRIPT,
    "P0-MEMBRANE-001": REVIEWED_P0_MEMBRANE_TRANSCRIPT,
    "P0-CLAIMS-002": REVIEWED_P0_CLAIMS_TRANSCRIPT,
}
REVIEWED_COMMAND_SELECTORS = {argv: selector for selector, argv in REVIEWED_P0_TRANSCRIPT}
REVIEWED_CWD_SCOPES_BY_NODE = {
    "P0-MEMBRANE-001": (
        "REPO_ROOT",
        "CP",
        "CP",
        "CP",
        "CP",
        "CP",
        "REPO_ROOT",
    ),
    "P0-CLAIMS-002": (
        "REPO_ROOT",
        "CP",
        "CP",
        "CP",
        "CP",
        "CP",
        "REPO_ROOT",
        "REPO_ROOT",
        "REPO_ROOT",
        "REPO_ROOT",
        "REPO_ROOT",
        "REPO_ROOT",
        "REPO_ROOT",
        "REPO_ROOT",
    ),
}
ALLOWED_ASSIGNMENTS = {
    "EVID",
    "EVID+CP",
    "EVID+CP+GZ",
    "EVID+CP+UI",
    "EVID+UI",
    "EVID+CP+GZ+UI",
}
EXPECTED_BOOTSTRAP_MAP = {
    "P0-EVIDENCE-000": "EVID+CP+GZ",
    "P0-MEMBRANE-001": "EVID+CP",
    "P0-CLAIMS-002": "EVID+CP+GZ",
    "P0-GATES-003": "EVID+CP+GZ+UI",
    "P1-MIGRATION-001": "EVID+CP",
    "P1-SCOPE-002": "EVID+CP",
    "P1-LEDGER-003": "EVID+CP",
    "P1-TRUST-004": "EVID+CP+GZ",
    "P2-TENANT-BOOTSTRAP-000": "EVID+CP+GZ",
    "P2-REGISTER-001": "EVID+CP+GZ",
    "P2-IDEMPOTENCY-002": "EVID+CP",
    "P2-VERTICAL-GATE-003": "EVID+CP+GZ",
    "P3-POLICY-001": "EVID+CP",
    "P3-MUTATIONS-002": "EVID+CP+GZ",
    "P3-APPROVAL-003": "EVID+CP+GZ",
    "P4-ENROLLMENT-001": "EVID+CP+GZ",
    "P4-POLICY-SYNC-002": "EVID+CP+GZ",
    "P4-OUTAGE-003": "EVID+CP+GZ",
    "P5-INGEST-001": "EVID+CP+GZ",
    "P5-STORE-002": "EVID+CP",
    "P5-WITNESS-003": "EVID+CP+GZ",
    "P6-BFF-001": "EVID+CP+UI",
    "P6-CONSOLE-002": "EVID+UI",
    "P6-E2E-003": "EVID+CP+GZ+UI",
    "P7-USAGE-001": "EVID+CP",
    "P7-RELIABILITY-002": "EVID+CP+GZ+UI",
    "P7-PROOFPACK-003": "EVID+CP+GZ+UI",
    "P7-BETA-GATE-004": "EVID+CP+GZ+UI",
}
REVIEWED_RUN_METADATA_BY_NODE = {
    node_id: {
        "process_schedule": ("single-process",),
        "clock_source": "system-utc",
        "skipped": (),
        "external": (),
    }
    for node_id in EXPECTED_BOOTSTRAP_MAP
}
ATTESTATION_ROLES = frozenset({"reviewer", "verifier", "claims-reviewer"})
PUBLIC_DESCRIPTOR_FIELDS = frozenset(
    {
        "schema_version",
        "key_id",
        "algorithm",
        "role",
        "principal",
        "public_key_base64url",
    }
)
CUSTODY_ROOT_FIELDS = frozenset(
    {
        "role",
        "canonical_private_root",
        "principal",
        "key_id",
        "public_descriptor_sha256",
        "root_descriptor_sha256",
    }
)
CUSTODY_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "node_id",
        "result",
        "repo_root",
        "evidence_root",
        "roots",
        "equal_or_nested_rejected",
    }
)
CODE_PATHS = {
    "EVID": (".venv-evidence/bin/python", "requirements/saas-beta/evidence-test.lock"),
    "CP": (
        "packages/acgs-control-plane/.venv/bin/python",
        "requirements/saas-beta/cp-test.lock",
    ),
    "GZ": ("packages/gove-zone/.venv-beta/bin/python", "requirements/saas-beta/gz-test.lock"),
    "UI": ("acgi-ai/node_modules", "acgi-ai/pnpm-lock.yaml"),
}
DIRECT_EVIDENCE_MODULES = {
    "rfc8785": "rfc8785",
    "cryptography": "cryptography",
    "jsonschema": "jsonschema",
    "pytest": "pytest",
}
OUTER_EVIDENCE_BASENAMES = {
    "run.json",
    "transcript.jsonl",
    "environment-identities.json",
    "environment-EVID.json",
    "environment-CP.json",
    "environment-GZ.json",
    "environment-UI.json",
    "evidence.freeze",
    "cp-pre-editable.freeze",
    "cp-post-editable.freeze",
    "gz-pre-editable.freeze",
    "gz-post-editable.freeze",
    "cp-editables-version.txt",
    "gz-editables-version.txt",
    "reviewer-public.json",
    "reviewer-root.json",
    "verifier-public.json",
    "verifier-root.json",
    "claims-reviewer-public.json",
    "claims-reviewer-root.json",
    "review-attestation.json",
    "verification-attestation.json",
    "claims-review-attestation.json",
    "trust-roots.json",
    "trust-roots.sha256",
    "claims-trust-roots.json",
    "claims-trust-roots.sha256",
    "attestation-validation.json",
    "claims-attestation-validation.json",
    "custody-preflight.json",
    "claims-custody-preflight.json",
}


class EvidenceError(ValueError):
    """A fail-closed evidence precondition or validation failed."""


def fail(message: str, *, phase: str | None = None) -> NoReturn:
    prefix = f"{phase}: " if phase else ""
    raise EvidenceError(prefix + message)


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[2]


def evidence_root_from_env(repo_root: Path) -> Path:
    raw = os.environ.get("ACGS_EVIDENCE_ROOT")
    if not raw:
        fail("ACGS_EVIDENCE_ROOT is required for evidence commands", phase="B0")
    supplied = Path(raw)
    if not supplied.is_absolute():
        fail("ACGS_EVIDENCE_ROOT must be absolute", phase="B0")
    canonical = supplied.expanduser().resolve(strict=False)
    if str(supplied) != str(canonical):
        fail("ACGS_EVIDENCE_ROOT must already be canonical", phase="B0")
    repository = repo_root.resolve(strict=True)
    if canonical == repository or canonical.is_relative_to(repository):
        fail("ACGS_EVIDENCE_ROOT must remain outside the product repository", phase="B0")
    return canonical


def canonical_node_evidence_path(
    path: Path,
    repo_root: Path,
    *,
    node_id: str,
    filename: str,
    must_exist: bool,
) -> Path:
    evidence_root = evidence_root_from_env(repo_root)
    if not path.is_absolute():
        fail(f"evidence path must be absolute: {path}", phase="B5")
    canonical = path.resolve(strict=must_exist)
    if str(path) != str(canonical):
        fail(f"evidence path must already be canonical: {path}", phase="B5")
    expected = evidence_root / node_id / filename
    if canonical != expected:
        fail(f"evidence path must be exactly {expected}: {canonical}", phase="B5")
    return canonical


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_distribution_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key!r}", phase="B6")
        result[key] = value
    return result


def _finite_float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value):
        fail(f"non-finite JSON number: {raw}", phase="B6")
    return value


def _reject_constant(raw: str) -> NoReturn:
    fail(f"non-standard JSON constant: {raw}", phase="B6")


def _check_unicode_and_numbers(value: Any, path: str = "$") -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            fail(f"unpaired surrogate at {path}", phase="B6")
    elif isinstance(value, float):
        if not math.isfinite(value):
            fail(f"non-finite number at {path}", phase="B6")
    elif type(value) is int and not -JSON_SAFE_INTEGER_MAX <= value <= JSON_SAFE_INTEGER_MAX:
        fail(f"integer outside the RFC 8785 interoperable range at {path}", phase="B6")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_unicode_and_numbers(item, f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _check_unicode_and_numbers(key, f"{path}.<key>")
            _check_unicode_and_numbers(item, f"{path}.{key}")


def strict_json_loads(raw: bytes | str) -> Any:
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            fail(f"invalid UTF-8 JSON: {exc}", phase="B6")
    else:
        text = raw
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_float=_finite_float,
            parse_constant=_reject_constant,
        )
    except EvidenceError:
        raise
    except (json.JSONDecodeError, UnicodeError, ValueError, OverflowError) as exc:
        fail(f"invalid strict JSON: {exc}", phase="B6")
    _check_unicode_and_numbers(value)
    return value


def parse_canonical_positive_decimal(value: Any, *, label: str) -> int:
    """Parse a lossless positive decimal without accepting alternate spellings."""

    if (
        not isinstance(value, str)
        or len(value) > MAX_CANONICAL_DECIMAL_DIGITS
        or CANONICAL_POSITIVE_DECIMAL_RE.fullmatch(value) is None
    ):
        fail(f"{label} must be a canonical positive decimal string", phase="B5")
    return int(value)


def reviewed_node_command(node_id: str, index: int) -> tuple[str, tuple[str, ...], str]:
    """Resolve one exact node/index command without consulting a global union."""

    transcript = REVIEWED_TRANSCRIPTS_BY_NODE.get(node_id)
    scopes = REVIEWED_CWD_SCOPES_BY_NODE.get(node_id)
    if transcript is None or scopes is None:
        fail("node lacks reviewed transcript corpus", phase="B6")
    if type(index) is not int or index < 0 or index >= len(transcript):
        fail("command index is outside the reviewed node contract", phase="B6")
    selector, argv = transcript[index]
    return selector, argv, scopes[index]


def reviewed_cwd(repo: Path, cwd_scope: str) -> Path:
    """Map a closed cwd scope to its canonical repository directory."""

    scopes = {"REPO_ROOT": repo, "CP": repo / "packages/acgs-control-plane"}
    cwd = scopes.get(cwd_scope)
    if cwd is None or not cwd.is_dir():
        fail("command cwd scope is unavailable or noncanonical", phase="B6")
    return cwd.resolve(strict=True)


def reviewed_executable(cwd: Path, argv0: str) -> Path:
    """Resolve a reviewed slash-qualified executable and require a regular target."""

    host_executable = REVIEWED_HOST_EXECUTABLES.get(argv0)
    if host_executable is not None:
        lexical = host_executable
    elif "/" not in argv0 or Path(argv0).is_absolute():
        fail("reviewed executable must be cwd-relative and PATH-independent", phase="B6")
    else:
        lexical = cwd / argv0
    if host_executable is not None and lexical.is_symlink():
        fail("reviewed executable lexical path must not be a symlink", phase="B6")
    try:
        executable = lexical.resolve(strict=True)
    except OSError as exc:
        fail(f"reviewed executable is unavailable: {exc}", phase="B6")
    if not executable.is_file() or executable.is_symlink():
        fail("reviewed executable target must be a regular non-symlink file", phase="B6")
    return executable


def resolved_executable_identity(repo: Path, executable: Path, metadata: os.stat_result) -> str:
    """Hash the resolved target identity without exposing host paths in the record."""

    try:
        path_identity = executable.relative_to(repo).as_posix()
        path_kind = "repo-relative"
    except ValueError:
        path_identity = hashlib.sha256(str(executable).encode()).hexdigest()
        path_kind = "host-path-sha256"
    payload = {
        "profile": "acgs-resolved-executable/v1",
        "path_kind": path_kind,
        "path_identity": path_identity,
        "device": str(metadata.st_dev),
        "inode": str(metadata.st_ino),
        "size": str(metadata.st_size),
        "mtime_ns": str(metadata.st_mtime_ns),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _reviewed_gate(argv: Any, *, expected_node: str | None = None) -> tuple[list[str], str]:
    """Classify one exact, reviewed transcript command; deny every extension."""

    if (
        not isinstance(argv, list)
        or not argv
        or any(
            not isinstance(argument, str)
            or not argument
            or len(argument) > MAX_COMMAND_ARGUMENT_LENGTH
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in argument)
            for argument in argv
        )
    ):
        fail("command argv is outside the reviewed closed contract", phase="B6")
    if expected_node is None or expected_node == "P0-EVIDENCE-000":
        selector = REVIEWED_COMMAND_SELECTORS.get(tuple(argv))
    else:
        transcript = REVIEWED_TRANSCRIPTS_BY_NODE.get(expected_node)
        if transcript is None:
            fail("node lacks reviewed transcript corpus", phase="B6")
        matches = [
            selector for selector, reviewed_argv in transcript if reviewed_argv == tuple(argv)
        ]
        if len(matches) != 1:
            fail("command argv is outside the reviewed node contract", phase="B6")
        selector = matches[0]
    if selector is None:
        fail("command argv is outside the reviewed closed contract", phase="B6")
    return argv, selector


def validate_safe_argv(argv: Any) -> list[str]:
    """Return argv only for the exact reviewed, non-shell gate vocabulary."""

    return _reviewed_gate(argv)[0]


def validate_transcript_record(value: Any, *, expected_node: str | None = None) -> dict[str, Any]:
    """Validate the full immutable command record before any persistence or use."""

    extended_node = expected_node in REVIEWED_CWD_SCOPES_BY_NODE
    required_keys = EXTENDED_TRANSCRIPT_RECORD_KEYS if extended_node else TRANSCRIPT_RECORD_KEYS
    if not isinstance(value, dict) or set(value) != required_keys:
        fail("command record is outside the reviewed closed contract", phase="B6")
    argv, selector = _reviewed_gate(value.get("argv"), expected_node=expected_node)
    if type(value.get("exit_code")) is not int or value["exit_code"] != 0:
        fail("command record is outside the reviewed closed contract", phase="B6")
    if any(
        not isinstance(value.get(name), str) or SHA256_RE.fullmatch(value[name]) is None
        for name in ("stdout_sha256", "stderr_sha256")
    ):
        fail("command record is outside the reviewed closed contract", phase="B6")
    timestamps: list[datetime] = []
    for name in ("started_at_utc", "finished_at_utc"):
        raw = value.get(name)
        if not isinstance(raw, str) or UTC_RE.fullmatch(raw) is None:
            fail("command record is outside the reviewed closed contract", phase="B6")
        try:
            timestamps.append(datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC))
        except ValueError:
            fail("command record is outside the reviewed closed contract", phase="B6")
    if timestamps[1] < timestamps[0] or value.get("selectors") != [selector]:
        fail("command record is outside the reviewed closed contract", phase="B6")
    if extended_node:
        if (
            value.get("cwd_scope") not in {"REPO_ROOT", "CP"}
            or not isinstance(value.get("executable_sha256"), str)
            or SHA256_RE.fullmatch(value["executable_sha256"]) is None
            or value.get("environment_profile_version_sha256")
            != REVIEWED_ENVIRONMENT_PROFILE_VERSION_SHA256
            or not isinstance(value.get("resolved_executable_identity_sha256"), str)
            or SHA256_RE.fullmatch(value["resolved_executable_identity_sha256"]) is None
            or not isinstance(value.get("sandbox_executable_sha256"), str)
            or SHA256_RE.fullmatch(value["sandbox_executable_sha256"]) is None
            or value.get("sandbox_profile_version_sha256")
            != REVIEWED_SANDBOX_PROFILE_VERSION_SHA256
            or not isinstance(value.get("sandbox_resolved_identity_sha256"), str)
            or SHA256_RE.fullmatch(value["sandbox_resolved_identity_sha256"]) is None
        ):
            fail("command execution identity is outside the reviewed node contract", phase="B6")
    value["argv"] = argv
    return value


def validate_node_transcript_sequence(node_id: str, commands: Any) -> None:
    """Require one node's reviewed gates and selectors in exact order."""

    reviewed = REVIEWED_TRANSCRIPTS_BY_NODE.get(node_id)
    scopes = REVIEWED_CWD_SCOPES_BY_NODE.get(node_id)
    if reviewed is None:
        fail("node lacks reviewed transcript corpus", phase="B6")
    if not isinstance(commands, list):
        fail("node transcript differs from the reviewed ordered command corpus", phase="B6")
    observed: list[tuple[str, tuple[str, ...]]] = []
    for index, command in enumerate(commands):
        validated = validate_transcript_record(command, expected_node=node_id)
        observed.append((validated["selectors"][0], tuple(validated["argv"])))
        if scopes is not None and (index >= len(scopes) or validated["cwd_scope"] != scopes[index]):
            fail("node transcript cwd scope differs from reviewed corpus", phase="B6")
    if tuple(observed) != reviewed:
        fail("node transcript differs from the reviewed ordered command corpus", phase="B6")


def validate_node_execution_identities(repo: Path, node_id: str, commands: Any) -> None:
    """Bind extended records to the canonical cwd and current executable bytes."""

    validate_node_transcript_sequence(node_id, commands)
    if node_id not in REVIEWED_CWD_SCOPES_BY_NODE:
        return
    for index, command in enumerate(commands):
        _, argv, cwd_scope = reviewed_node_command(node_id, index)
        cwd = reviewed_cwd(repo, cwd_scope)
        executable = reviewed_executable(cwd, argv[0])
        metadata = executable.stat()
        try:
            sandbox = BWRAP_EXECUTABLE.resolve(strict=True)
        except OSError as exc:
            fail(f"reviewed sandbox executable is unavailable: {exc}", phase="B6")
        sandbox_metadata = sandbox.stat()
        if (
            command["executable_sha256"] != sha256_file(executable)
            or command["environment_profile_version_sha256"]
            != REVIEWED_ENVIRONMENT_PROFILE_VERSION_SHA256
            or command["resolved_executable_identity_sha256"]
            != resolved_executable_identity(repo, executable, metadata)
            or command["sandbox_executable_sha256"] != sha256_file(sandbox)
            or command["sandbox_profile_version_sha256"] != REVIEWED_SANDBOX_PROFILE_VERSION_SHA256
            or command["sandbox_resolved_identity_sha256"]
            != resolved_executable_identity(repo, sandbox, sandbox_metadata)
        ):
            fail("command executable digest differs from current reviewed executable", phase="B6")


def validate_p0_transcript_sequence(commands: Any) -> None:
    """Compatibility entry point for the P0-EVIDENCE-000 corpus."""

    validate_node_transcript_sequence("P0-EVIDENCE-000", commands)


def validate_secret_free_run(value: Any, *, expected_node: str | None = None) -> None:
    """Reapply closed command and run-metadata contracts before schema use or hashing."""

    if (
        not isinstance(value, dict)
        or not isinstance(value.get("commands"), list)
        or not value["commands"]
    ):
        fail("run command metadata is outside the closed safe structure", phase="B6")
    node_id = expected_node if expected_node is not None else value.get("node_id")
    if not isinstance(node_id, str):
        fail("run node identity is outside the closed safe structure", phase="B6")
    for command in value["commands"]:
        validate_transcript_record(command, expected_node=node_id)
    if expected_node is not None and value.get("node_id") != expected_node:
        fail("run node identity differs from its evidence path", phase="B6")
    validate_node_transcript_sequence(node_id, value["commands"])
    reviewed = REVIEWED_RUN_METADATA_BY_NODE.get(node_id)
    determinism = value.get("determinism")
    clock = value.get("clock")
    if (
        reviewed is None
        or not isinstance(determinism, dict)
        or set(determinism) != {"seed", "python_hash_seed", "process_schedule"}
        or determinism.get("process_schedule") != list(reviewed["process_schedule"])
        or not isinstance(clock, dict)
        or set(clock) != {"source", "skew_ms"}
        or clock.get("source") != reviewed["clock_source"]
        or value.get("skipped") != list(reviewed["skipped"])
        or value.get("external") != list(reviewed["external"])
    ):
        fail("run metadata is outside the reviewed closed node contract", phase="B6")


def append_safe_transcript_record(
    path: Path, record: Mapping[str, Any], *, expected_node: str | None = None
) -> None:
    """Validate a command record before its first byte can enter evidence."""

    validated = validate_transcript_record(dict(record), expected_node=expected_node)
    payload = (
        json.dumps(validated, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            fail("transcript output must be a uniquely linked regular file", phase="B6")
        if os.write(fd, payload) != len(payload):
            fail("short transcript record write", phase="B6")
        os.fsync(fd)
    finally:
        os.close(fd)


def load_json(path: Path) -> Any:
    try:
        return strict_json_loads(path.read_bytes())
    except OSError as exc:
        fail(f"cannot read JSON {path}: {exc}", phase="B6")


def write_json_exclusive(path: Path, value: Any, *, mode: int = 0o644) -> None:
    if os.path.lexists(path):
        fail(f"refusing to overwrite evidence output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def write_bootstrap_identity_exclusive(
    marker: Path,
    output: Path,
    value_factory: Callable[[str], tuple[dict[str, Any], dict[str, Any]]],
) -> None:
    """Publish a runtime marker and its outer identity as one owned transaction.

    Creating the marker changes the runtime directory ctime, so the caller's
    factory runs only after the exclusive marker inode exists.  Any later
    failure removes that inode only when it is still the one created here.
    """

    for destination in (marker, output):
        if os.path.lexists(destination):
            fail(f"refusing to overwrite bootstrap output: {destination}")
    if not marker.parent.is_dir() or marker.parent.is_symlink():
        fail(f"bootstrap runtime root is missing or unsafe: {marker.parent}")
    output.parent.mkdir(parents=True, exist_ok=True)

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd: int | None = None
    owned: os.stat_result | None = None
    try:
        fd = os.open(marker, flags, 0o600)
        owned = os.fstat(fd)
        marker_value, identity_value = value_factory(str(marker.parent.stat().st_ctime_ns))
        marker_payload = (
            json.dumps(
                marker_value,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
        if os.write(fd, marker_payload) != len(marker_payload):
            fail(f"short bootstrap marker write: {marker}")
        os.fsync(fd)
        os.close(fd)
        fd = None
        write_json_exclusive(output, identity_value)
    except BaseException as exc:
        if fd is not None:
            os.close(fd)
        try:
            current = marker.lstat()
        except FileNotFoundError:
            current = None
        if (
            owned is not None
            and current is not None
            and (
                current.st_dev,
                current.st_ino,
            )
            == (owned.st_dev, owned.st_ino)
        ):
            marker.unlink()
        if isinstance(exc, EvidenceError):
            raise
        if isinstance(exc, (OSError, TypeError, ValueError)):
            fail(f"bootstrap identity publication failed: {exc}")
        raise


def replace_json(path: Path, value: Any, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
    )
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    if os.path.lexists(temporary):
        fail(f"temporary output already exists: {temporary}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def parse_lock(path: Path) -> dict[str, dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        fail(f"cannot read lock {path}: {exc}", phase="B1")
    if not lines or not lines[0].startswith("# This file was autogenerated by uv"):
        fail(f"lock is not an uv-generated output: {path}", phase="B1")
    entries: dict[str, dict[str, Any]] = {}
    current: str | None = None
    for number, line in enumerate(lines, 1):
        if not line or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            match = LOCK_ENTRY_RE.fullmatch(line)
            if match is None:
                fail(f"unsupported/dynamic lock entry at {path}:{number}: {line!r}", phase="B1")
            name = canonical_distribution_name(match.group(1))
            if PINNED_VERSION_RE.fullmatch(match.group(2)) is None:
                fail(
                    f"lock entry is not an exact static PEP 440-style pin at "
                    f"{path}:{number}: {line!r}",
                    phase="B1",
                )
            if name in entries:
                fail(f"duplicate lock distribution {name} in {path}", phase="B1")
            entries[name] = {"version": match.group(2), "artifact_hashes": []}
            current = name
            continue
        hash_match = LOCK_HASH_RE.search(line.strip())
        if hash_match is not None:
            if current is None:
                fail(f"orphan lock hash at {path}:{number}", phase="B1")
            entries[current]["artifact_hashes"].append(hash_match.group(1))
            continue
        if line.strip().startswith("--hash"):
            fail(f"malformed/non-SHA256 hash at {path}:{number}", phase="B1")
    if not entries:
        fail(f"empty lock: {path}", phase="B1")
    for name, entry in entries.items():
        hashes = entry["artifact_hashes"]
        if (
            not hashes
            or len(hashes) != len(set(hashes))
            or not all(SHA256_RE.fullmatch(h) for h in hashes)
        ):
            fail(f"incomplete or duplicate artifact hashes for {name} in {path}", phase="B1")
        hashes.sort()
    return entries


def check_lock_header(path: Path, expected_input: str, expected_output: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()[:3]
    command = " ".join(line.lstrip("# ") for line in lines[1:])
    required = (
        "uv pip compile",
        "--python-version 3.11",
        "--python-platform x86_64-manylinux_2_28",
        "--exclude-newer 2026-07-10T00:00:00Z",
        "--generate-hashes",
        expected_input,
        f"--output-file {expected_output}",
    )
    missing = [piece for piece in required if piece not in command]
    if missing:
        fail(f"lock toolchain/platform/cutoff header drift in {path}: {missing}", phase="B1")


def installed_distributions() -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for distribution in importlib.metadata.distributions():
        raw_name = distribution.metadata.get("Name")
        if not raw_name:
            continue
        name = canonical_distribution_name(raw_name)
        location = Path(distribution.locate_file("")).resolve()
        if name in result:
            fail(f"duplicate installed distribution identity: {name}", phase="B2")
        result[name] = {"version": distribution.version, "location": str(location)}
    return result


def _module_identity(module_name: str, expected_root: Path) -> dict[str, str]:
    module = importlib.import_module(module_name)
    module_file_raw = getattr(module, "__file__", None)
    if not isinstance(module_file_raw, str):
        fail(f"module has no file identity: {module_name}", phase="B2")
    module_file = Path(module_file_raw).resolve(strict=True)
    root = expected_root.resolve(strict=True)
    if not module_file.is_relative_to(root):
        fail(f"module {module_name} escaped expected root {root}: {module_file}", phase="B2")
    return {"module": module_name, "path": str(module_file)}


def verify_installed_against_lock(
    lock_path: Path,
    expected_root: Path,
    *,
    allowed_extra: Iterable[str] = (),
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, str]]]:
    locked = parse_lock(lock_path)
    installed = installed_distributions()
    allowed = {canonical_distribution_name(name) for name in allowed_extra}
    missing = set(locked) - set(installed)
    extra = set(installed) - set(locked) - allowed
    if missing or extra:
        fail(
            "installed/locked distribution set mismatch; "
            f"missing={sorted(missing)} extra={sorted(extra)}",
            phase="B2",
        )
    for name, entry in locked.items():
        if installed[name]["version"] != entry["version"]:
            fail(
                f"installed version mismatch for {name}: "
                f"{installed[name]['version']} != {entry['version']}",
                phase="B2",
            )
        location = Path(installed[name]["location"]).resolve(strict=True)
        if not location.is_relative_to(expected_root.resolve(strict=True)):
            fail(f"distribution {name} escaped {expected_root}: {location}", phase="B2")
    return locked, installed


def assert_evidence_runtime(*, require_dependencies: bool = True) -> Path:
    repo_root = repo_root_from_script()
    expected_prefix = (repo_root / ".venv-evidence").resolve(strict=True)
    expected_python_lexical = repo_root / ".venv-evidence/bin/python"
    actual_prefix = Path(sys.prefix).resolve(strict=True)
    expected_python = expected_python_lexical.resolve(strict=True)
    actual_python = Path(sys.executable).resolve(strict=True)
    if (
        actual_prefix != expected_prefix
        or actual_python != expected_python
        or Path(sys.executable).absolute() != expected_python_lexical
    ):
        fail(
            f"evidence CLI must run through {repo_root / '.venv-evidence/bin/python'}; "
            f"got executable={sys.executable} prefix={sys.prefix}",
            phase="B2",
        )
    for variable in ("VIRTUAL_ENV", "PYTHONPATH", "PYTHONHOME", "UV_PROJECT_ENVIRONMENT"):
        if os.environ.get(variable):
            fail(f"{variable} must be absent for evidence commands", phase="B0")
    for variable in ("UV_OFFLINE", "UV_NO_INDEX", "UV_NO_CACHE"):
        if os.environ.get(variable) != "1":
            fail(f"{variable}=1 is mandatory after hash sync", phase="B2")
    if site.ENABLE_USER_SITE:
        fail("user site-packages must be disabled", phase="B2")
    if sys.version_info[:2] != (3, 11):
        fail(f"evidence runtime must be Python 3.11, got {sys.version.split()[0]}", phase="B2")
    if require_dependencies:
        lock = repo_root / "requirements/saas-beta/evidence-test.lock"
        check_lock_header(
            lock,
            "requirements/saas-beta/evidence-test.in",
            "requirements/saas-beta/evidence-test.lock",
        )
        locked, _ = verify_installed_against_lock(lock, expected_prefix)
        expected_direct = {
            "rfc8785": "0.1.4",
            "cryptography": locked.get("cryptography", {}).get("version"),
            "jsonschema": locked.get("jsonschema", {}).get("version"),
            "pytest": locked.get("pytest", {}).get("version"),
        }
        if any(value is None for value in expected_direct.values()):
            fail("evidence lock is missing a direct evidence distribution", phase="B1")
        for distribution, module_name in DIRECT_EVIDENCE_MODULES.items():
            if importlib.metadata.version(distribution) != expected_direct[distribution]:
                fail(f"direct evidence version mismatch: {distribution}", phase="B2")
            _module_identity(module_name, expected_prefix)
    return repo_root


def validate_schema(instance: Any, schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # no fallback: this is a declared EVID dependency
        fail(f"declared jsonschema dependency unavailable: {exc}", phase="B6")
    schema = load_json(schema_path)
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(instance)
    except jsonschema.exceptions.SchemaError as exc:
        fail(f"invalid committed schema {schema_path}: {exc.message}", phase="B6")
    except jsonschema.exceptions.ValidationError as exc:
        fail(f"schema rejection at {list(exc.absolute_path)}: {exc.message}", phase="B6")


def jcs_bytes(value: Any) -> bytes:
    try:
        import rfc8785
    except ImportError as exc:  # exact dependency; no alternate implementation
        fail(f"declared RFC 8785 implementation unavailable: {exc}", phase="B6")
    if importlib.metadata.version("rfc8785") != "0.1.4":
        fail("RFC 8785 implementation must be exactly rfc8785==0.1.4", phase="B6")
    _check_unicode_and_numbers(value)
    try:
        result = rfc8785.dumps(value)
    except (ValueError, TypeError, OverflowError) as exc:
        fail(f"RFC 8785 canonicalization failed: {exc}", phase="B6")
    if not isinstance(result, bytes):
        fail("rfc8785.dumps returned a non-byte value", phase="B6")
    return result


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(value: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        fail(f"timestamp must be second-precision UTC Z form: {value!r}")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        fail(f"invalid UTC timestamp {value!r}: {exc}")


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(value: str, *, expected_length: int, label: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        fail(f"{label} must be nonempty unpadded base64url")
    if re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        fail(f"{label} is not base64url")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, UnicodeError) as exc:
        fail(f"invalid {label}: {exc}")
    if len(raw) != expected_length or b64url_encode(raw) != value:
        fail(f"{label} is noncanonical or wrong length")
    return raw


def key_id_for_public(raw_public: bytes) -> str:
    if len(raw_public) != 32:
        fail("Ed25519 public key must be 32 raw bytes")
    return f"ed25519:sha256:{hashlib.sha256(raw_public).hexdigest()}"


def assignment_tokens(assignment: str) -> list[str]:
    if assignment not in ALLOWED_ASSIGNMENTS:
        fail(f"invalid closed bootstrap assignment: {assignment!r}", phase="B5")
    tokens = assignment.split("+")
    if tokens[0] != "EVID" or tokens.count("EVID") != 1 or len(tokens) != len(set(tokens)):
        fail(f"invalid assignment grammar: {assignment!r}", phase="B5")
    return tokens


def ensure_path_outside(path: Path, forbidden_roots: Iterable[Path], label: str) -> Path:
    if not path.is_absolute():
        fail(f"{label} must be absolute")
    canonical = path.expanduser().resolve(strict=False)
    if str(path) != str(canonical):
        fail(f"{label} must already be canonical: {path} != {canonical}")
    for root in forbidden_roots:
        canonical_root = root.expanduser().resolve(strict=False)
        if canonical == canonical_root or canonical.is_relative_to(canonical_root):
            fail(f"{label} must be outside {canonical_root}")
    return canonical


def paths_equal_or_nested(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def read_regular_nofollow(path: Path, label: str, *, max_bytes: int = 4 * 1024 * 1024) -> bytes:
    """Capture one bounded, uniquely linked regular file without following its final path."""

    try:
        before = path.lstat()
    except OSError as exc:
        fail(f"cannot inspect {label}: {exc}", phase="B7")
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_nlink != 1:
        fail(f"{label} must be a uniquely linked regular file", phase="B7")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open {label}: {exc}", phase="B7")
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            fail(f"{label} changed during safe access", phase="B7")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(fd, 64 * 1024):
            size += len(chunk)
            if size > max_bytes:
                fail(f"{label} exceeds the local evidence size bound", phase="B7")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def validate_public_descriptor(value: Any) -> tuple[dict[str, Any], bytes]:
    """Validate the exact public descriptor used by custody and trust consumers."""

    if not isinstance(value, dict) or set(value) != PUBLIC_DESCRIPTOR_FIELDS:
        fail("public-key descriptor is not the exact closed object", phase="B7")
    principal = value.get("principal")
    if (
        value.get("schema_version") != "acgs-attestation-public-key/v1"
        or value.get("algorithm") != "Ed25519"
        or value.get("role") not in ATTESTATION_ROLES
        or not isinstance(principal, str)
        or not principal
        or principal != principal.strip()
        or len(principal) > 256
    ):
        fail("public-key descriptor identity is invalid", phase="B7")
    raw_public = b64url_decode(
        value.get("public_key_base64url"),
        expected_length=32,
        label="Ed25519 public key",
    )
    if value.get("key_id") != key_id_for_public(raw_public):
        fail("public-key descriptor key id mismatch", phase="B7")
    return value, raw_public


def _validate_canonical_private_root(
    raw_path: Any,
    *,
    repo: Path,
    evidence_root: Path,
    role: str,
) -> Path:
    if not isinstance(raw_path, str) or not raw_path:
        fail("private-root descriptor path is malformed", phase="B7")
    supplied = Path(raw_path)
    if not supplied.is_absolute():
        fail("canonical private root must be absolute", phase="B7")
    try:
        canonical = supplied.resolve(strict=True)
        before = supplied.lstat()
    except OSError as exc:
        fail(f"cannot inspect {role} canonical private root: {exc}", phase="B7")
    if str(supplied) != str(canonical):
        fail("canonical private root descriptor is stale or indirect", phase="B7")
    ensure_path_outside(canonical, [repo, evidence_root], f"{role} canonical private root")
    if (
        not stat.S_ISDIR(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o700
    ):
        fail("canonical private root must be a direct mode-0700 directory", phase="B7")
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(canonical, flags)
    except OSError as exc:
        fail(f"cannot open {role} canonical private root: {exc}", phase="B7")
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o700
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            fail("canonical private root changed during metadata validation", phase="B7")
    finally:
        os.close(fd)
    return canonical


def collect_custody_descriptor_bindings(
    *,
    repo: Path,
    evidence_root: Path,
    node_dir: Path,
    expected_roles: set[str],
) -> tuple[list[dict[str, str]], dict[str, dict[str, Any]]]:
    """Reopen exact same-node public/root descriptors and recompute custody predicates.

    This deliberately inspects only root-directory metadata and public descriptor bytes.
    It never derives, lists, opens, or reads a private-key file.
    """

    if not expected_roles or not expected_roles.issubset(ATTESTATION_ROLES):
        fail("custody roles are outside the closed role contract", phase="B7")
    node_id = node_dir.name
    canonical_node = node_dir.resolve(strict=True)
    if (
        NODE_RE.fullmatch(node_id) is None
        or canonical_node != evidence_root / node_id
        or str(node_dir) != str(canonical_node)
    ):
        fail("custody descriptors must belong to one exact evidence node", phase="B7")
    inputs = canonical_node / "custody-inputs"
    if not inputs.is_dir() or inputs.is_symlink():
        fail("same-node custody-inputs directory is missing or indirect", phase="B7")

    bindings: list[dict[str, str]] = []
    public_by_role: dict[str, dict[str, Any]] = {}
    roots: dict[str, Path] = {}
    for role in sorted(expected_roles):
        public_path = inputs / f"{role}-public.json"
        root_path = inputs / f"{role}-root.json"
        public_bytes = read_regular_nofollow(public_path, f"{role} public descriptor")
        root_bytes = read_regular_nofollow(root_path, f"{role} root descriptor")
        public, raw_public = validate_public_descriptor(strict_json_loads(public_bytes))
        root_descriptor = strict_json_loads(root_bytes)
        if (
            public.get("role") != role
            or not isinstance(root_descriptor, dict)
            or set(root_descriptor) != {"schema_version", "role", "canonical_private_root"}
            or root_descriptor.get("schema_version") != "acgs-private-root-descriptor/v1"
            or root_descriptor.get("role") != role
        ):
            fail("same-node custody descriptor role or shape mismatch", phase="B7")
        root = _validate_canonical_private_root(
            root_descriptor.get("canonical_private_root"),
            repo=repo,
            evidence_root=evidence_root,
            role=role,
        )
        roots[role] = root
        bindings.append(
            {
                "role": role,
                "canonical_private_root": str(root),
                "principal": public["principal"],
                "key_id": public["key_id"],
                "public_descriptor_sha256": sha256_bytes(public_bytes),
                "root_descriptor_sha256": sha256_bytes(root_bytes),
            }
        )
        public_by_role[role] = {
            "descriptor": public,
            "raw_public": raw_public,
            "public_descriptor_sha256": sha256_bytes(public_bytes),
            "root_descriptor_sha256": sha256_bytes(root_bytes),
            "canonical_private_root": str(root),
        }
    ordered = sorted(roots.items())
    for index, (_, left) in enumerate(ordered):
        for _, right in ordered[index + 1 :]:
            if paths_equal_or_nested(left, right):
                fail("private roots are equal/nested", phase="B7")
    return bindings, public_by_role


def validate_custody_record(
    path: Path,
    *,
    repo: Path,
    evidence_root: Path,
    node_dir: Path,
    expected_roles: set[str],
    expected_name: str,
) -> tuple[dict[str, Any], str, dict[str, dict[str, Any]]]:
    """Treat a preflight result as a trace and independently reprove its bindings."""

    expected_path = node_dir / expected_name
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        fail("successful same-node custody preflight is missing", phase="B7")
    if path != expected_path or resolved != expected_path:
        fail("custody preflight path is not the exact same-node record", phase="B7")
    raw = read_regular_nofollow(path, "custody preflight")
    value = strict_json_loads(raw)
    bindings, public_by_role = collect_custody_descriptor_bindings(
        repo=repo,
        evidence_root=evidence_root,
        node_dir=node_dir,
        expected_roles=expected_roles,
    )
    if (
        not isinstance(value, dict)
        or set(value) != CUSTODY_RECORD_FIELDS
        or value.get("schema_version") != "acgs-custody-preflight/v1"
        or value.get("node_id") != node_dir.name
        or value.get("result") != "pass"
        or value.get("repo_root") != str(repo)
        or value.get("evidence_root") != str(evidence_root)
        or value.get("equal_or_nested_rejected") is not True
        or not isinstance(value.get("roots"), list)
        or any(
            not isinstance(item, dict) or set(item) != CUSTODY_ROOT_FIELDS
            for item in value["roots"]
        )
        or value["roots"] != bindings
    ):
        fail("custody preflight is stale, altered, or not independently reproducible", phase="B7")
    return value, sha256_bytes(raw), public_by_role


def run_checked(
    argv: list[str], *, cwd: Path | None = None, env: Mapping[str, str] | None = None
) -> str:
    completed = subprocess.run(
        argv,
        cwd=cwd,
        env=None if env is None else dict(env),
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        fail(
            f"command failed ({completed.returncode}): {argv!r}\n"
            f"stdout={completed.stdout}\nstderr={completed.stderr}"
        )
    return completed.stdout


def git_root(cwd: Path | None = None) -> Path:
    output = run_checked(["git", "rev-parse", "--show-toplevel"], cwd=cwd).strip()
    return Path(output).resolve(strict=True)


def verify_git_range(repo: Path, parent: str, product: str, *, require_clean: bool = True) -> None:
    if GIT_SHA1_RE.fullmatch(parent) is None or GIT_SHA1_RE.fullmatch(product) is None:
        fail("P and T must be lowercase 40-hex commit SHAs", phase="B6")
    for value in (parent, product):
        run_checked(["git", "cat-file", "-e", f"{value}^{{commit}}"], cwd=repo)
    if parent == product:
        fail("P and T must identify distinct parent and tested commits", phase="B6")
    run_checked(["git", "merge-base", "--is-ancestor", parent, product], cwd=repo)
    if require_clean:
        status_output = run_checked(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repo
        )
        dirty = []
        for line in status_output.splitlines():
            path_text = line[3:].split(" -> ")[-1]
            if path_text == ".venv-evidence" or path_text.startswith(".venv-evidence/"):
                continue
            if path_text == "packages/acgs-control-plane/.venv" or path_text.startswith(
                "packages/acgs-control-plane/.venv/"
            ):
                continue
            if path_text == "packages/gove-zone/.venv-beta" or path_text.startswith(
                "packages/gove-zone/.venv-beta/"
            ):
                continue
            dirty.append(line)
        if dirty:
            fail(f"product worktree is dirty: {dirty}", phase="B6")
    diff = subprocess.run(
        ["git", "diff", "--check", f"{parent}..{product}"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    if diff.returncode != 0 or diff.stdout or diff.stderr:
        fail(
            f"git diff --check {parent}..{product} failed: {diff.stdout}{diff.stderr}",
            phase="B6",
        )


def reject_outer_evidence_in_product(repo: Path, product: str) -> None:
    listing = run_checked(["git", "ls-tree", "-r", "--name-only", product], cwd=repo)
    offending = [
        path
        for path in listing.splitlines()
        if Path(path).name in OUTER_EVIDENCE_BASENAMES
        and not path.startswith("tests/")
        and not path.startswith("schemas/")
    ]
    if offending:
        fail(f"outer evidence is committed in product T: {offending}", phase="B7")


def validate_sha256(value: str, label: str) -> None:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        fail(f"{label} must be lowercase SHA-256 hex")


def file_mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)
