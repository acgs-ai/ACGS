"""Adversarial contract tests for the product-independent P0 evidence bootstrap."""

from __future__ import annotations

import copy
import hashlib
import importlib.metadata
import inspect
import json
import os
import shutil
import stat
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_SCRIPTS = ROOT / "scripts/evidence"
sys.path.insert(0, str(EVIDENCE_SCRIPTS))

import _common  # noqa: E402
import attest  # noqa: E402
import capture_environment  # noqa: E402
import capture_reviewed_command  # noqa: E402
import generate_run  # noqa: E402
import hash_run_jcs  # noqa: E402
import render_lock_inputs  # noqa: E402
import validate_attestations  # noqa: E402
import validate_environment_identities  # noqa: E402
import validate_run  # noqa: E402

LOCK_ROOT = ROOT / "requirements/saas-beta"
SCHEMA_ROOT = ROOT / "schemas/evidence"
ENVIRONMENT_PROFILE_VERSION_SHA256 = _common.REVIEWED_ENVIRONMENT_PROFILE_VERSION_SHA256
SANDBOX_PROFILE_VERSION_SHA256 = _common.REVIEWED_SANDBOX_PROFILE_VERSION_SHA256
EXPECTED_DIRECT = (
    "rfc8785==0.1.4",
    "cryptography>=42",
    "jsonschema>=4.23,<5",
    "pytest>=8.3,<9",
)


def _evidence_env(evidence_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    for name in (
        "VIRTUAL_ENV",
        "PYTHONPATH",
        "PYTHONHOME",
        "UV_PROJECT_ENVIRONMENT",
        "ACGS_P0_LITERAL_PROVER_INNER_T",
    ):
        env.pop(name, None)
    env.update(
        {
            "ACGS_EVIDENCE_ROOT": str(evidence_root),
            "UV_OFFLINE": "1",
            "UV_NO_INDEX": "1",
            "UV_NO_CACHE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "ACGS_PROCESS_SCHEDULE": '["single-process"]',
            "ACGS_CLOCK_SOURCE": "system-utc",
            "ACGS_SKIPPED_JSON": "[]",
            "ACGS_EXTERNAL_JSON": "[]",
        }
    )
    return env


def _run_evidence(
    script: str,
    *args: str | Path,
    evidence_root: Path,
    expected: int = 0,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        [sys.executable, str(EVIDENCE_SCRIPTS / script), *(str(arg) for arg in args)],
        cwd=ROOT,
        env=_evidence_env(evidence_root),
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == expected, (completed.stdout, completed.stderr)
    return completed


def _json(path: Path) -> dict[str, Any]:
    value = _common.load_json(path)
    assert isinstance(value, dict)
    return value


def _now(offset: timedelta = timedelta()) -> str:
    return (datetime.now(UTC) + offset).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _transcript_record(argv: list[str], selector: str | None = None) -> dict[str, Any]:
    now = _now()
    if selector is None:
        selector = _common.REVIEWED_COMMAND_SELECTORS.get(tuple(argv), "rejected-command-metadata")
    return {
        "argv": argv,
        "exit_code": 0,
        "stdout_sha256": hashlib.sha256(b"stdout").hexdigest(),
        "stderr_sha256": hashlib.sha256(b"stderr").hexdigest(),
        "started_at_utc": now,
        "finished_at_utc": now,
        "selectors": [selector],
    }


def _reviewed_p0_records() -> list[dict[str, Any]]:
    return [
        _transcript_record(list(argv), selector)
        for selector, argv in _common.REVIEWED_P0_TRANSCRIPT
    ]


def _write_reviewed_p0_transcript(path: Path) -> None:
    for record in _reviewed_p0_records():
        _common.append_safe_transcript_record(path, record)


def _reviewed_node_records(node_id: str) -> list[dict[str, Any]]:
    records = []
    scopes = _common.REVIEWED_CWD_SCOPES_BY_NODE.get(node_id)
    for index, (selector, argv) in enumerate(_common.REVIEWED_TRANSCRIPTS_BY_NODE[node_id]):
        record = _transcript_record(list(argv), selector)
        if scopes is not None:
            record.update({"cwd_scope": scopes[index], "executable_sha256": "0" * 64})
            record.update(
                {
                    "environment_profile_version_sha256": (
                        _common.reviewed_environment_profile_sha256(node_id, list(argv))
                    ),
                    "resolved_executable_identity_sha256": "0" * 64,
                    "sandbox_executable_sha256": "0" * 64,
                    "sandbox_profile_version_sha256": (
                        _common.reviewed_sandbox_profile_sha256(node_id, list(argv))
                    ),
                    "sandbox_resolved_identity_sha256": "0" * 64,
                }
            )
            if node_id == "P0-GATES-003" and argv[0] == "fnm":
                record["ui_toolchain_sha256"] = "0" * 64
        records.append(record)
    return records


def _write_raw_transcript(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")


def _unsafe_command_corpus(sentinel: str) -> tuple[list[str], ...]:
    allowed = list(_common.REVIEWED_P0_TRANSCRIPT[0][1])
    return (
        ["env", f"PGPASSWORD={sentinel}", "pytest"],
        ["env", f"PGPASSFILE=/tmp/{sentinel}", "pytest"],
        ["env", f"AUTH={sentinel}", "pytest"],
        ["curl", "--oauth2-bearer", sentinel, "https://example.invalid"],
        ["pytest", "--password", sentinel],
        ["pytest", f"--api-key={sentinel}"],
        ["client", "--password", sentinel],
        ["curl", "-H", f"Authorization: Bearer {sentinel}", "https://example.invalid"],
        ["curl", "-H", f"Cookie: session={sentinel}", "https://example.invalid"],
        ["curl", f"https://user:{sentinel}@example.invalid/path"],
        ["curl", f"https://example.invalid/path?access_token={sentinel}"],
        ["bash", "-c", f"printf {sentinel}"],
        ["sh", "-c", f"printf {sentinel}"],
        ["python", "-c", f"print({sentinel!r})"],
        ["unknown-executable", "--opaque", sentinel],
        [*allowed, "--unknown-option", sentinel],
    )


def _copy_config_repo(tmp_path: Path) -> Path:
    for relative in (
        "requirements/saas-beta/locks.toml",
        "packages/acgs-control-plane/pyproject.toml",
        "packages/gove-zone/pyproject.toml",
    ):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    return tmp_path / "requirements/saas-beta/locks.toml"


def _bootstrap_key_material(tmp_path: Path) -> dict[str, Path]:
    evidence_root = (tmp_path / "evidence").resolve()
    custody = evidence_root / "P0-EVIDENCE-000/custody-inputs"
    node = custody.parent
    reviewer_root = (tmp_path / "private/reviewer").resolve()
    verifier_root = (tmp_path / "private/verifier").resolve()
    custody.mkdir(parents=True)
    reviewer_root.mkdir(parents=True, mode=0o700)
    verifier_root.mkdir(parents=True, mode=0o700)
    os.chmod(reviewer_root, 0o700)
    os.chmod(verifier_root, 0o700)
    paths = {
        "evidence": evidence_root,
        "node": node,
        "reviewer_root": reviewer_root,
        "verifier_root": verifier_root,
        "reviewer_private": reviewer_root / "reviewer.ed25519",
        "verifier_private": verifier_root / "verifier.ed25519",
        "reviewer_public": custody / "reviewer-public.json",
        "verifier_public": custody / "verifier-public.json",
        "reviewer_descriptor": custody / "reviewer-root.json",
        "verifier_descriptor": custody / "verifier-root.json",
    }
    for role in ("reviewer", "verifier"):
        _run_evidence(
            "attest.py",
            "keygen",
            "--root-schema",
            SCHEMA_ROOT / "acgs-private-root-descriptor-v1.schema.json",
            "--algorithm",
            "ed25519",
            "--role",
            role,
            "--principal",
            f"independent-{role}",
            "--private-key",
            paths[f"{role}_private"],
            "--public-descriptor",
            paths[f"{role}_public"],
            "--canonical-private-root",
            paths[f"{role}_root"],
            "--root-descriptor",
            paths[f"{role}_descriptor"],
            evidence_root=evidence_root,
        )
    return paths


def _run_custody_preflight(
    node: Path,
    evidence_root: Path,
    roles: tuple[str, ...] = ("reviewer", "verifier"),
) -> Path:
    path = node / (
        "claims-custody-preflight.json" if "claims-reviewer" in roles else "custody-preflight.json"
    )
    arguments: list[str | Path] = [
        "custody-preflight",
        "--root-schema",
        SCHEMA_ROOT / "acgs-private-root-descriptor-v1.schema.json",
        "--repo-root",
        ROOT,
        "--evidence-root",
        evidence_root,
    ]
    for role in roles:
        arguments.extend(("--root-descriptor", node / "custody-inputs" / f"{role}-root.json"))
    for role in roles:
        arguments.extend(("--require-role", role))
    arguments.extend(("--reject-equal-or-nested", "--output", path))
    _run_evidence(
        "attest.py",
        *arguments,
        evidence_root=evidence_root,
    )
    return path


def test_universal_evidence_interpreter_offline() -> None:
    expected = (ROOT / ".venv-evidence").resolve(strict=True)
    assert Path(sys.prefix).resolve(strict=True) == expected
    assert Path(sys.executable).resolve(strict=True) == (expected / "bin/python").resolve(
        strict=True
    )
    assert sys.version_info[:2] == (3, 11)
    assert os.environ.get("VIRTUAL_ENV") is None
    assert os.environ.get("PYTHONPATH") is None
    assert {
        name: os.environ.get(name) for name in ("UV_OFFLINE", "UV_NO_INDEX", "UV_NO_CACHE")
    } == {
        "UV_OFFLINE": "1",
        "UV_NO_INDEX": "1",
        "UV_NO_CACHE": "1",
    }
    locked, installed = _common.verify_installed_against_lock(
        LOCK_ROOT / "evidence-test.lock", expected
    )
    assert set(locked) == set(installed)
    assert importlib.metadata.version("rfc8785") == "0.1.4"
    for module_name in ("rfc8785", "cryptography", "jsonschema", "pytest"):
        module = __import__(module_name)
        assert Path(module.__file__).resolve(strict=True).is_relative_to(expected)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    expected_class_module = "cryptography.hazmat.primitives.asymmetric.ed25519"
    assert Ed25519PrivateKey.__module__ == expected_class_module
    assert Ed25519PublicKey.__module__ == expected_class_module


def test_lock_model_and_assignment_map_are_exact_closed_contracts() -> None:
    import tomllib

    config = tomllib.loads((LOCK_ROOT / "locks.toml").read_text(encoding="utf-8"))
    assert set(config) == {"schema_version", "meta", "EVID", "CP", "GZ", "bootstrap_by_scope"}
    assert tuple(config["EVID"]["evidence_test"]) == EXPECTED_DIRECT
    assert config["meta"] == {
        "uv_version": "0.11.19",
        "python_version": "3.11",
        "python_platform": "x86_64-manylinux_2_28",
        "exclude_newer": "2026-07-10T00:00:00Z",
    }
    assert config["bootstrap_by_scope"] == _common.EXPECTED_BOOTSTRAP_MAP
    assert _json(LOCK_ROOT / "bootstrap-by-scope.json") == _common.EXPECTED_BOOTSTRAP_MAP
    for code in ("CP", "GZ"):
        assert config[code]["pep517_backend"] == "hatchling.build"
        assert config[code]["pep660_editable_build"] == ["editables==0.6"]


def test_lock_input_renderer_is_byte_deterministic_across_runtime_noise(tmp_path: Path) -> None:
    roots = [tmp_path / "one", tmp_path / "two", tmp_path / "three"]
    envs = (
        {"LC_ALL": "C", "PYTHONHASHSEED": "0", "TZ": "UTC"},
        {"LC_ALL": "C.UTF-8", "PYTHONHASHSEED": "99", "TZ": "Pacific/Honolulu"},
        {"LC_ALL": "C", "PYTHONHASHSEED": "random", "TZ": "Europe/Paris"},
    )
    for output, overrides in zip(roots, envs, strict=True):
        env = _evidence_env(tmp_path / "outer")
        env.update(overrides)
        completed = subprocess.run(
            [
                sys.executable,
                str(EVIDENCE_SCRIPTS / "render_lock_inputs.py"),
                "--config",
                str(LOCK_ROOT / "locks.toml"),
                "--output-root",
                str(output),
            ],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
    for relative in (
        "requirements/saas-beta/evidence-test.in",
        "requirements/saas-beta/cp-test.in",
        "requirements/saas-beta/gz-test.in",
        "requirements/saas-beta/bootstrap-by-scope.json",
    ):
        payloads = [(root / relative).read_bytes() for root in roots]
        assert payloads[0] == payloads[1] == payloads[2] == (ROOT / relative).read_bytes()


@pytest.mark.parametrize(
    ("token", "replacement"),
    (
        (
            'output = "requirements/saas-beta/evidence-test.in"',
            'output = "/tmp/acgs-render-escape.in"',
        ),
        (
            'output = "requirements/saas-beta/evidence-test.in"',
            'output = "requirements/../escape.in"',
        ),
        (
            'output = "requirements/saas-beta/cp-test.in"',
            'output = "requirements/saas-beta/evidence-test.in"',
        ),
    ),
)
def test_renderer_rejects_absolute_traversal_and_collision_before_any_write(
    tmp_path: Path, token: str, replacement: str
) -> None:
    config = _copy_config_repo(tmp_path)
    config.write_text(
        config.read_text(encoding="utf-8").replace(token, replacement, 1),
        encoding="utf-8",
    )
    output = (tmp_path / "output").resolve()
    with pytest.raises(render_lock_inputs.ConfigError, match="output must be exactly"):
        render_lock_inputs.render(config, output)
    assert not output.exists()


def test_renderer_rejects_symlink_parent_and_rolls_back_partial_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _copy_config_repo(tmp_path / "config")
    output = (tmp_path / "symlink-output").resolve()
    outside = tmp_path / "outside"
    output.mkdir()
    outside.mkdir()
    (output / "requirements").symlink_to(outside, target_is_directory=True)
    with pytest.raises(render_lock_inputs.ConfigError, match="symlinked"):
        render_lock_inputs.render(config, output)
    assert list(outside.iterdir()) == []

    rollback = (tmp_path / "rollback-output").resolve()
    originals: dict[Path, bytes] = {}
    for relative in render_lock_inputs.EXPECTED_OUTPUTS.values():
        destination = rollback / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(f"sentinel:{relative}\n".encode())
        originals[destination] = destination.read_bytes()
    real_replace = render_lock_inputs.os.replace
    calls = 0

    def fail_second_replace(source: Path, destination: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected renderer publication failure")
        real_replace(source, destination)

    monkeypatch.setattr(render_lock_inputs.os, "replace", fail_second_replace)
    with pytest.raises(render_lock_inputs.ConfigError, match="injected"):
        render_lock_inputs.render(config, rollback)
    assert {path: path.read_bytes() for path in originals} == originals
    assert not list(rollback.rglob("*.tmp"))
    assert not list(rollback.rglob("*.rollback"))


@pytest.mark.parametrize("direct", EXPECTED_DIRECT)
def test_renderer_rejects_each_missing_or_changed_evidence_direct_input(
    tmp_path: Path, direct: str
) -> None:
    config = _copy_config_repo(tmp_path)
    text = config.read_text(encoding="utf-8")
    config.write_text(text.replace(f'  "{direct}",\n', "", 1), encoding="utf-8")
    with pytest.raises(render_lock_inputs.ConfigError):
        render_lock_inputs.render(config, tmp_path / "out")

    config = _copy_config_repo(tmp_path / "changed")
    text = config.read_text(encoding="utf-8")
    config.write_text(text.replace(direct, direct + ".invalid", 1), encoding="utf-8")
    with pytest.raises(render_lock_inputs.ConfigError):
        render_lock_inputs.render(config, tmp_path / "changed/out")


@pytest.mark.parametrize("code", ("CP", "GZ"))
def test_renderer_rejects_missing_changed_or_dynamic_pep660_and_backend(
    tmp_path: Path, code: str
) -> None:
    for mutation in ("missing", "changed", "backend"):
        root = tmp_path / mutation
        config = _copy_config_repo(root)
        text = config.read_text(encoding="utf-8")
        start = text.index(f"[{code}]")
        end = text.find("\n[", start + 1)
        end = len(text) if end == -1 else end
        section = text[start:end]
        if mutation == "missing":
            section = section.replace('pep660_editable_build = ["editables==0.6"]\n', "")
        elif mutation == "changed":
            section = section.replace("editables==0.6", "editables==0.7")
        else:
            section = section.replace("hatchling.build", "dynamic.backend")
        config.write_text(text[:start] + section + text[end:], encoding="utf-8")
        with pytest.raises(render_lock_inputs.ConfigError):
            render_lock_inputs.render(config, root / "out")


@pytest.mark.parametrize(
    ("name", "input_name"),
    (
        ("evidence-test.lock", "evidence-test.in"),
        ("cp-test.lock", "cp-test.in"),
        ("gz-test.lock", "gz-test.in"),
    ),
)
def test_every_lock_entry_is_pinned_hashed_and_toolchain_bound(name: str, input_name: str) -> None:
    path = LOCK_ROOT / name
    entries = _common.parse_lock(path)
    assert entries
    assert all(entry["version"] and entry["artifact_hashes"] for entry in entries.values())
    assert all(
        len(digest) == 64 and digest == digest.lower()
        for entry in entries.values()
        for digest in entry["artifact_hashes"]
    )
    _common.check_lock_header(
        path,
        f"requirements/saas-beta/{input_name}",
        f"requirements/saas-beta/{name}",
    )


def test_lock_parser_rejects_missing_malformed_duplicate_and_dynamic_hash_state(
    tmp_path: Path,
) -> None:
    original = (LOCK_ROOT / "evidence-test.lock").read_text(encoding="utf-8")
    lines = original.splitlines()
    entry = next(index for index, line in enumerate(lines) if line.startswith("rfc8785=="))
    end = next(
        (i for i in range(entry + 1, len(lines)) if lines[i] and not lines[i][0].isspace()),
        len(lines),
    )

    no_hash = (
        lines[: entry + 1]
        + [line for line in lines[entry + 1 : end] if "--hash" not in line]
        + lines[end:]
    )
    path = tmp_path / "no-hash.lock"
    path.write_text("\n".join(no_hash) + "\n", encoding="utf-8")
    with pytest.raises(_common.EvidenceError, match="incomplete"):
        _common.parse_lock(path)

    malformed = original.replace("--hash=sha256:", "--hash=sha256:g", 1)
    path = tmp_path / "malformed.lock"
    path.write_text(malformed, encoding="utf-8")
    with pytest.raises(_common.EvidenceError):
        _common.parse_lock(path)

    first_hash = next(line for line in lines[entry + 1 : end] if "--hash=sha256:" in line)
    duplicate = [*lines[:end], first_hash, *lines[end:]]
    path = tmp_path / "duplicate.lock"
    path.write_text("\n".join(duplicate) + "\n", encoding="utf-8")
    with pytest.raises(_common.EvidenceError, match="duplicate"):
        _common.parse_lock(path)

    path = tmp_path / "dynamic.lock"
    path.write_text(original + "undeclared @ https://example.invalid/pkg.whl\n", encoding="utf-8")
    with pytest.raises(_common.EvidenceError, match="dynamic"):
        _common.parse_lock(path)


def test_canonical_regeneration_catches_extra_bogus_but_well_formed_hash(tmp_path: Path) -> None:
    canonical = (LOCK_ROOT / "evidence-test.lock").read_text(encoding="utf-8")
    lines = canonical.splitlines()
    entry = next(index for index, line in enumerate(lines) if line.startswith("rfc8785=="))
    end = next(
        (i for i in range(entry + 1, len(lines)) if lines[i] and not lines[i][0].isspace()),
        len(lines),
    )
    mutated = [*lines[:end], "    --hash=sha256:" + "f" * 64, *lines[end:]]
    path = tmp_path / "extra-valid-hash.lock"
    path.write_text("\n".join(mutated) + "\n", encoding="utf-8")
    assert _common.parse_lock(path)  # uv may accept another valid artifact hash.
    assert path.read_bytes() != (LOCK_ROOT / "evidence-test.lock").read_bytes()
    prover = (EVIDENCE_SCRIPTS / "prove_clean_sibling.sh").read_text(encoding="utf-8")
    assert '"$UV_BIN" pip compile' in prover and "cmp --silent" in prover


def test_wrong_toolchain_platform_cutoff_or_partial_lock_rewrite_rejected(tmp_path: Path) -> None:
    canonical = (LOCK_ROOT / "evidence-test.lock").read_text(encoding="utf-8")
    for token, replacement in (
        ("--python-version 3.11", "--python-version 3.12"),
        ("x86_64-manylinux_2_28", "aarch64-manylinux_2_28"),
        ("2026-07-10T00:00:00Z", "2026-07-11T00:00:00Z"),
        ("--generate-hashes", "--no-generate-hashes"),
    ):
        path = tmp_path / hashlib.sha256(token.encode()).hexdigest()
        path.write_text(canonical.replace(token, replacement, 1), encoding="utf-8")
        with pytest.raises(_common.EvidenceError):
            _common.check_lock_header(
                path,
                "requirements/saas-beta/evidence-test.in",
                "requirements/saas-beta/evidence-test.lock",
            )


def test_all_four_json_schemas_are_draft202012_and_payload_objects_are_closed() -> None:
    schemas = sorted(SCHEMA_ROOT.glob("*.schema.json"))
    assert [path.name for path in schemas] == [
        "acgs-attestation-trust-v1.schema.json",
        "acgs-attestation-v1.schema.json",
        "acgs-private-root-descriptor-v1.schema.json",
        "acgs-run-evidence-v1.schema.json",
    ]
    for path in schemas:
        schema = _json(path)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        jsonschema.Draft202012Validator.check_schema(schema)

        schema_path = path

        def visit(value: Any, schema_path: Path = schema_path) -> None:
            if isinstance(value, dict):
                if value.get("type") == "object":
                    assert value.get("additionalProperties") is False, schema_path
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(schema)


@pytest.mark.parametrize(
    "payload",
    (
        b'{"a":1,"a":2}',
        b'{"a":1,"\\u0061":2}',
        b'{"n":NaN}',
        b'{"n":Infinity}',
        b'{"n":-Infinity}',
        b'{"n":1e400}',
        b'{"a":1} trailing',
        b'{"a":"\\ud800"}',
        b'{"a":"\xff"}',
    ),
)
def test_strict_json_rejects_ambiguous_nonfinite_invalid_or_trailing_payloads(
    payload: bytes,
) -> None:
    with pytest.raises(_common.EvidenceError):
        _common.strict_json_loads(payload)


def test_rfc8785_exact_canonical_bytes_and_no_unicode_normalization() -> None:
    assert importlib.metadata.version("rfc8785") == "0.1.4"
    assert _common.jcs_bytes({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    composed = _common.jcs_bytes({"value": "\u00e9"})
    decomposed = _common.jcs_bytes({"value": "e\u0301"})
    assert composed != decomposed
    assert hashlib.sha256(composed).digest() != hashlib.sha256(decomposed).digest()
    maximum = _common.JSON_SAFE_INTEGER_MAX
    assert _common.jcs_bytes({"n": maximum}) == f'{{"n":{maximum}}}'.encode()
    assert _common.jcs_bytes({"n": -maximum}) == f'{{"n":{-maximum}}}'.encode()
    for unsafe in (maximum + 1, -maximum - 1, 10**400):
        with pytest.raises(_common.EvidenceError, match="interoperable range"):
            _common.jcs_bytes({"n": unsafe})
        with pytest.raises(_common.EvidenceError, match="interoperable range"):
            _common.strict_json_loads(f'{{"n":{unsafe}}}')


def test_base64url_and_root_path_primitives_fail_closed(tmp_path: Path) -> None:
    raw = bytes(range(32))
    encoded = _common.b64url_encode(raw)
    assert _common.b64url_decode(encoded, expected_length=32, label="key") == raw
    for invalid in (encoded + "=", "+" + encoded[1:], encoded[:-1], ""):
        with pytest.raises(_common.EvidenceError):
            _common.b64url_decode(invalid, expected_length=32, label="key")
    repo = ROOT.resolve(strict=True)
    with pytest.raises(_common.EvidenceError):
        _common.ensure_path_outside(repo, [repo], "root")
    with pytest.raises(_common.EvidenceError):
        _common.ensure_path_outside(repo / "nested", [repo], "root")
    left = (tmp_path / "left").resolve()
    assert _common.paths_equal_or_nested(left, left / "nested")


def test_keygen_custody_trust_and_signature_round_trip_uses_public_material_only(
    tmp_path: Path,
) -> None:
    paths = _bootstrap_key_material(tmp_path)
    for role in ("reviewer", "verifier"):
        private_path = paths[f"{role}_private"]
        assert private_path.stat().st_size == 32
        assert stat.S_IMODE(private_path.stat().st_mode) == 0o600
        public = _json(paths[f"{role}_public"])
        assert set(public) == _common.PUBLIC_DESCRIPTOR_FIELDS
        descriptor = _json(paths[f"{role}_descriptor"])
        assert set(descriptor) == {"schema_version", "role", "canonical_private_root"}
        assert "private" not in json.dumps(public).lower()
        assert private_path.name not in json.dumps(descriptor)

    held_private: dict[str, Path] = {}
    for role in ("reviewer", "verifier"):
        held = tmp_path / f"held-{role}.ed25519"
        paths[f"{role}_private"].replace(held)
        held_private[role] = held

    preflight = paths["node"] / "custody-preflight.json"
    _run_evidence(
        "attest.py",
        "custody-preflight",
        "--root-schema",
        SCHEMA_ROOT / "acgs-private-root-descriptor-v1.schema.json",
        "--repo-root",
        ROOT,
        "--evidence-root",
        paths["evidence"],
        "--root-descriptor",
        paths["reviewer_descriptor"],
        "--root-descriptor",
        paths["verifier_descriptor"],
        "--require-role",
        "reviewer",
        "--require-role",
        "verifier",
        "--reject-equal-or-nested",
        "--output",
        preflight,
        evidence_root=paths["evidence"],
    )
    assert _json(preflight)["result"] == "pass"

    trust_path = paths["node"] / "trust-roots.json"
    _run_evidence(
        "attest.py",
        "trust-manifest",
        "--schema",
        SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
        "--trust-domain",
        "acgs-saas-beta-local",
        "--public-descriptor",
        paths["reviewer_public"],
        "--public-descriptor",
        paths["verifier_public"],
        "--not-before",
        _now(timedelta(minutes=-1)),
        "--not-after",
        _now(timedelta(days=1)),
        "--output",
        trust_path,
        evidence_root=paths["evidence"],
    )
    trust = _json(trust_path)
    trusted = validate_attestations._validate_trust(
        trust,
        SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
        {"reviewer", "verifier"},
        validation_time=_common.parse_utc(_now()),
    )
    for role, held in held_private.items():
        assert held.is_file() and not paths[f"{role}_private"].exists()
        held.replace(paths[f"{role}_private"])
    parent, product, run_hash = "1" * 40, "2" * 40, "3" * 64
    signed_paths: dict[str, Path] = {}
    for mode, role in (("node-review", "reviewer"), ("node-verification", "verifier")):
        output = paths["node"] / (
            "review-attestation.json" if role == "reviewer" else "verification-attestation.json"
        )
        signed_paths[mode] = output
        _run_evidence(
            "attest.py",
            "sign",
            "--schema",
            SCHEMA_ROOT / "acgs-attestation-v1.schema.json",
            "--mode",
            mode,
            "--role",
            role,
            "--principal",
            f"independent-{role}",
            "--private-key",
            paths[f"{role}_private"],
            "--parent",
            parent,
            "--product",
            product,
            "--run-hash",
            run_hash,
            "--verdict",
            "approve",
            "--timestamp",
            _now(),
            "--output",
            output,
            evidence_root=paths["evidence"],
        )
        result = validate_attestations._validate_envelope(
            _json(output),
            SCHEMA_ROOT / "acgs-attestation-v1.schema.json",
            trusted,
            mode=mode,
            role=role,
            parent=parent,
            product=product,
            run_hash=run_hash,
            forbidden_principals={"author"},
            validation_time=_common.parse_utc(_now()),
        )
        assert result["verdict"] == "approve"
    assert (
        _json(signed_paths["node-review"])["key_id"]
        != _json(signed_paths["node-verification"])["key_id"]
    )


def test_keygen_bundle_is_all_or_none_on_partial_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = tmp_path / "private/reviewer.ed25519"
    public = tmp_path / "evidence/custody-inputs/reviewer-public.json"
    root = tmp_path / "evidence/custody-inputs/reviewer-root.json"
    private.parent.mkdir(parents=True)
    public.parent.mkdir(parents=True)
    real_link = attest.os.link
    calls = 0

    def fail_second_link(source: Path, destination: Path, **kwargs: Any) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected keygen publish failure")
        real_link(source, destination, **kwargs)

    monkeypatch.setattr(attest.os, "link", fail_second_link)
    with pytest.raises(OSError, match="injected"):
        attest._publish_key_bundle(
            private,
            b"p" * 32,
            public,
            {"public": True},
            root,
            {"root": True},
        )
    assert not any(path.exists() for path in (private, public, root))
    assert not list(tmp_path.rglob("*.tmp"))

    sentinel = b"existing-public\n"
    public.write_bytes(sentinel)
    with pytest.raises(_common.EvidenceError, match="must be absent"):
        attest._publish_key_bundle(
            private,
            b"p" * 32,
            public,
            {"public": True},
            root,
            {"root": True},
        )
    assert public.read_bytes() == sentinel
    assert not private.exists() and not root.exists()


def test_custody_rejects_equal_nested_repository_or_evidence_roots(tmp_path: Path) -> None:
    def descriptor(custody: Path, role: str, root: Path) -> Path:
        path = custody / f"{role}-root.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": "acgs-private-root-descriptor/v1",
                    "role": role,
                    "canonical_private_root": str(root),
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    def public_descriptor(custody: Path, role: str, raw: bytes) -> Path:
        path = custody / f"{role}-public.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": "acgs-attestation-public-key/v1",
                    "key_id": _common.key_id_for_public(raw),
                    "algorithm": "Ed25519",
                    "role": role,
                    "principal": f"independent-{role}",
                    "public_key_base64url": _common.b64url_encode(raw),
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    cases = (
        ("equal/nested", (tmp_path / "same").resolve(), (tmp_path / "same").resolve()),
        (
            "equal/nested",
            (tmp_path / "parent").resolve(),
            (tmp_path / "parent/nested").resolve(),
        ),
        ("must be outside", ROOT.resolve(), (tmp_path / "safe").resolve()),
        ("must be outside", None, (tmp_path / "safe-two").resolve()),
    )
    for index, (message, reviewer_raw, verifier) in enumerate(cases):
        evidence = (tmp_path / f"case-{index}/evidence").resolve()
        custody = evidence / "P0-EVIDENCE-000/custody-inputs"
        custody.mkdir(parents=True)
        reviewer = evidence if reviewer_raw is None else reviewer_raw
        for root in {reviewer, verifier}:
            if root not in {ROOT.resolve(), evidence}:
                root.mkdir(parents=True, exist_ok=True, mode=0o700)
                root.chmod(0o700)
        first = descriptor(custody, "reviewer", reviewer)
        second = descriptor(custody, "verifier", verifier)
        public_descriptor(custody, "reviewer", bytes(range(32)))
        public_descriptor(custody, "verifier", bytes(range(1, 33)))
        completed = _run_evidence(
            "attest.py",
            "custody-preflight",
            "--root-schema",
            SCHEMA_ROOT / "acgs-private-root-descriptor-v1.schema.json",
            "--repo-root",
            ROOT,
            "--evidence-root",
            evidence,
            "--root-descriptor",
            first,
            "--root-descriptor",
            second,
            "--require-role",
            "reviewer",
            "--require-role",
            "verifier",
            "--reject-equal-or-nested",
            "--output",
            evidence / "P0-EVIDENCE-000/custody-preflight.json",
            evidence_root=evidence,
            expected=2,
        )
        assert message in completed.stderr
        assert not (evidence / "P0-EVIDENCE-000/custody-preflight.json").exists()


def test_forged_nested_custody_is_rejected_by_trust_and_final_validation(
    tmp_path: Path,
) -> None:
    evidence = (tmp_path / "evidence").resolve()
    node = evidence / "P0-EVIDENCE-000"
    custody = node / "custody-inputs"
    custody.mkdir(parents=True)
    reviewer_root = (tmp_path / "private/shared").resolve()
    verifier_root = reviewer_root / "nested"
    verifier_root.mkdir(parents=True, mode=0o700)
    reviewer_root.chmod(0o700)
    verifier_root.chmod(0o700)

    for role, root in (("reviewer", reviewer_root), ("verifier", verifier_root)):
        _run_evidence(
            "attest.py",
            "keygen",
            "--root-schema",
            SCHEMA_ROOT / "acgs-private-root-descriptor-v1.schema.json",
            "--algorithm",
            "ed25519",
            "--role",
            role,
            "--principal",
            f"independent-{role}",
            "--private-key",
            root / f"{role}.ed25519",
            "--public-descriptor",
            custody / f"{role}-public.json",
            "--canonical-private-root",
            root,
            "--root-descriptor",
            custody / f"{role}-root.json",
            evidence_root=evidence,
        )

    preflight = node / "custody-preflight.json"
    real = _run_evidence(
        "attest.py",
        "custody-preflight",
        "--root-schema",
        SCHEMA_ROOT / "acgs-private-root-descriptor-v1.schema.json",
        "--repo-root",
        ROOT,
        "--evidence-root",
        evidence,
        "--root-descriptor",
        custody / "reviewer-root.json",
        "--root-descriptor",
        custody / "verifier-root.json",
        "--require-role",
        "reviewer",
        "--require-role",
        "verifier",
        "--reject-equal-or-nested",
        "--output",
        preflight,
        evidence_root=evidence,
        expected=2,
    )
    assert "equal/nested" in real.stderr
    assert not preflight.exists()

    forged_roots: list[dict[str, str]] = []
    for role, root in (("reviewer", reviewer_root), ("verifier", verifier_root)):
        public_path = custody / f"{role}-public.json"
        root_path = custody / f"{role}-root.json"
        public = _json(public_path)
        forged_roots.append(
            {
                "role": role,
                "canonical_private_root": str(root),
                "principal": public["principal"],
                "key_id": public["key_id"],
                "public_descriptor_sha256": hashlib.sha256(public_path.read_bytes()).hexdigest(),
                "root_descriptor_sha256": hashlib.sha256(root_path.read_bytes()).hexdigest(),
            }
        )
    preflight.write_text(
        json.dumps(
            {
                "schema_version": "acgs-custody-preflight/v1",
                "node_id": node.name,
                "result": "pass",
                "repo_root": str(ROOT),
                "evidence_root": str(evidence),
                "roots": forged_roots,
                "equal_or_nested_rejected": True,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    trust_path = node / "trust-roots.json"
    trust_attempt = _run_evidence(
        "attest.py",
        "trust-manifest",
        "--schema",
        SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
        "--trust-domain",
        "acgs-saas-beta-local",
        "--public-descriptor",
        custody / "reviewer-public.json",
        "--public-descriptor",
        custody / "verifier-public.json",
        "--not-before",
        _now(timedelta(minutes=-1)),
        "--not-after",
        _now(timedelta(days=1)),
        "--output",
        trust_path,
        evidence_root=evidence,
        expected=2,
    )
    assert "equal/nested" in trust_attempt.stderr
    assert not trust_path.exists()

    keys: list[dict[str, Any]] = []
    for role in ("reviewer", "verifier"):
        public = _json(custody / f"{role}-public.json")
        keys.append(
            {
                "key_id": public["key_id"],
                "algorithm": "Ed25519",
                "role": role,
                "principal": public["principal"],
                "public_key_base64url": public["public_key_base64url"],
                "not_before_utc": _now(timedelta(minutes=-1)),
                "not_after_utc": _now(timedelta(days=1)),
                "status": "trusted",
            }
        )
    trust_path.write_text(
        json.dumps(
            {
                "schema_version": "acgs-attestation-trust/v1",
                "trust_domain": "acgs-saas-beta-local",
                "keys": keys,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (node / "trust-roots.sha256").write_text(
        f"{hashlib.sha256(trust_path.read_bytes()).hexdigest()}  trust-roots.json\n",
        encoding="ascii",
    )
    for name in ("review-attestation.json", "verification-attestation.json"):
        (node / name).write_text("{}\n", encoding="utf-8")
    validation_output = node / "attestation-validation.json"
    final_attempt = _run_evidence(
        "validate_attestations.py",
        "--mode",
        "node-pair",
        "--schema",
        SCHEMA_ROOT / "acgs-attestation-v1.schema.json",
        "--trust-schema",
        SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
        "--expected-parent",
        "1" * 40,
        "--expected-product",
        "2" * 40,
        "--expected-run-hash",
        "3" * 64,
        "--review",
        node / "review-attestation.json",
        "--verification",
        node / "verification-attestation.json",
        "--trust-roots",
        trust_path,
        "--require-distinct-principals",
        "--require-distinct-key-ids",
        "--forbid-principal",
        "node-author",
        "--output",
        validation_output,
        evidence_root=evidence,
        expected=2,
    )
    assert "equal/nested" in final_attempt.stderr
    assert not validation_output.exists()


def test_trust_rejects_duplicate_principal_key_material_role_and_invalid_window(
    tmp_path: Path,
) -> None:
    paths = _bootstrap_key_material(tmp_path / "keys")
    reviewer = _json(paths["reviewer_public"])
    verifier = _json(paths["verifier_public"])
    same_principal = copy.deepcopy(verifier)
    same_principal["principal"] = reviewer["principal"]
    same_material = copy.deepcopy(reviewer)
    same_material["role"] = "verifier"
    same_material["principal"] = "different-verifier"
    for index, (mutation, message) in enumerate(
        ((same_principal, "principal"), (same_material, "key material"))
    ):
        evidence = (tmp_path / f"trust-case-{index}/evidence").resolve()
        node = evidence / "P0-EVIDENCE-000"
        custody = node / "custody-inputs"
        custody.mkdir(parents=True)
        (custody / "reviewer-public.json").write_text(json.dumps(reviewer) + "\n", encoding="utf-8")
        (custody / "verifier-public.json").write_text(json.dumps(mutation) + "\n", encoding="utf-8")
        shutil.copy2(paths["reviewer_descriptor"], custody / "reviewer-root.json")
        shutil.copy2(paths["verifier_descriptor"], custody / "verifier-root.json")
        _run_custody_preflight(node, evidence)
        completed = _run_evidence(
            "attest.py",
            "trust-manifest",
            "--schema",
            SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
            "--trust-domain",
            "acgs-saas-beta-local",
            "--public-descriptor",
            custody / "reviewer-public.json",
            "--public-descriptor",
            custody / "verifier-public.json",
            "--not-before",
            _now(),
            "--not-after",
            _now(timedelta(days=1)),
            "--output",
            node / "trust-roots.json",
            evidence_root=evidence,
            expected=2,
        )
        assert f"duplicate {message} in trust input" in completed.stderr
        assert not (node / "trust-roots.json").exists()

    duplicate_role = {
        "schema_version": "acgs-attestation-trust/v1",
        "trust_domain": "acgs-saas-beta-local",
        "keys": [],
    }
    for public in (reviewer, verifier):
        duplicate_role["keys"].append(
            {
                "key_id": public["key_id"],
                "algorithm": "Ed25519",
                "role": "reviewer",
                "principal": public["principal"],
                "public_key_base64url": public["public_key_base64url"],
                "not_before_utc": _now(timedelta(minutes=-1)),
                "not_after_utc": _now(timedelta(days=1)),
                "status": "trusted",
            }
        )
    with pytest.raises(_common.EvidenceError, match="duplicate identity/material/role"):
        validate_attestations._validate_trust(
            duplicate_role,
            SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
            {"reviewer", "verifier"},
            validation_time=_common.parse_utc(_now()),
        )

    evidence = (tmp_path / "window-case/evidence").resolve()
    node = evidence / "P0-EVIDENCE-000"
    custody = node / "custody-inputs"
    custody.mkdir(parents=True)
    for role, value in (("reviewer", reviewer), ("verifier", verifier)):
        (custody / f"{role}-public.json").write_text(json.dumps(value) + "\n", encoding="utf-8")
        shutil.copy2(paths[f"{role}_descriptor"], custody / f"{role}-root.json")
    _run_custody_preflight(node, evidence)
    completed = _run_evidence(
        "attest.py",
        "trust-manifest",
        "--schema",
        SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
        "--trust-domain",
        "acgs-saas-beta-local",
        "--public-descriptor",
        custody / "reviewer-public.json",
        "--public-descriptor",
        custody / "verifier-public.json",
        "--not-before",
        _now(timedelta(days=1)),
        "--not-after",
        _now(),
        "--output",
        node / "trust-roots.json",
        evidence_root=evidence,
        expected=2,
    )
    assert "not_before < not_after" in completed.stderr
    assert not (node / "trust-roots.json").exists()


def test_trust_window_exactly_90_days_is_accepted_and_every_wider_window_is_rejected(
    tmp_path: Path,
) -> None:
    paths = _bootstrap_key_material(tmp_path)
    _run_custody_preflight(paths["node"], paths["evidence"])
    start = datetime(2026, 7, 10, tzinfo=UTC)

    def stamp(value: datetime) -> str:
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")

    trust_path = paths["node"] / "trust-roots.json"
    _run_evidence(
        "attest.py",
        "trust-manifest",
        "--schema",
        SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
        "--trust-domain",
        "acgs-saas-beta-local",
        "--public-descriptor",
        paths["reviewer_public"],
        "--public-descriptor",
        paths["verifier_public"],
        "--not-before",
        stamp(start),
        "--not-after",
        stamp(start + timedelta(days=90)),
        "--output",
        trust_path,
        evidence_root=paths["evidence"],
    )
    exact = _json(trust_path)
    assert validate_attestations._validate_trust(
        exact,
        SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
        {"reviewer", "verifier"},
        validation_time=start + timedelta(days=1),
    )

    trust_path.unlink()
    over = _run_evidence(
        "attest.py",
        "trust-manifest",
        "--schema",
        SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
        "--trust-domain",
        "acgs-saas-beta-local",
        "--public-descriptor",
        paths["reviewer_public"],
        "--public-descriptor",
        paths["verifier_public"],
        "--not-before",
        stamp(start),
        "--not-after",
        stamp(start + timedelta(days=90, seconds=1)),
        "--output",
        trust_path,
        evidence_root=paths["evidence"],
        expected=2,
    )
    assert "must not exceed 90 days" in over.stderr
    assert not trust_path.exists()

    overbroad = copy.deepcopy(exact)
    for entry in overbroad["keys"]:
        entry["not_before_utc"] = "2020-01-01T00:00:00Z"
        entry["not_after_utc"] = "2099-12-31T23:59:59Z"
    with pytest.raises(_common.EvidenceError, match="exceeds 90 days"):
        validate_attestations._validate_trust(
            overbroad,
            SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
            {"reviewer", "verifier"},
            validation_time=start,
        )

    for not_before, not_after in (
        ("2020-01-01T00:00:00Z", "2020-03-31T00:00:00Z"),
        ("2027-01-01T00:00:00Z", "2027-04-01T00:00:00Z"),
    ):
        inactive = copy.deepcopy(exact)
        for entry in inactive["keys"]:
            entry["not_before_utc"] = not_before
            entry["not_after_utc"] = not_after
        with pytest.raises(_common.EvidenceError, match="not active or expired"):
            validate_attestations._validate_trust(
                inactive,
                SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
                {"reviewer", "verifier"},
                validation_time=start,
            )


def test_final_attestation_validation_rejects_externally_supplied_79_year_trust(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = _bootstrap_key_material(tmp_path)
    evidence = paths["evidence"]
    node = paths["node"]
    monkeypatch.setenv("ACGS_EVIDENCE_ROOT", str(evidence))
    monkeypatch.setattr(validate_attestations, "assert_evidence_runtime", lambda **_: ROOT)
    monkeypatch.setattr(validate_attestations, "validate_schema", lambda *_: None)

    parent, product = "1" * 40, "2" * 40
    run = {
        "node_id": node.name,
        "parent_commit_sha": parent,
        "product_commit_sha": product,
        "commands": _reviewed_p0_records(),
        "determinism": {
            "seed": 20260710,
            "python_hash_seed": "0",
            "process_schedule": ["single-process"],
        },
        "clock": {"source": "system-utc", "skew_ms": 0},
        "skipped": [],
        "external": [],
    }
    (node / "run.json").write_text(json.dumps(run) + "\n", encoding="utf-8")
    run_hash = hashlib.sha256(_common.jcs_bytes(run)).hexdigest()
    for name in ("review-attestation.json", "verification-attestation.json"):
        (node / name).write_text("{}\n", encoding="utf-8")
    _run_custody_preflight(node, evidence)

    trust = {
        "schema_version": "acgs-attestation-trust/v1",
        "trust_domain": "acgs-saas-beta-local",
        "keys": [],
    }
    for role, raw in (("reviewer", bytes(range(32))), ("verifier", bytes(range(1, 33)))):
        trust["keys"].append(
            {
                "key_id": _common.key_id_for_public(raw),
                "algorithm": "Ed25519",
                "role": role,
                "principal": f"independent-{role}",
                "public_key_base64url": _common.b64url_encode(raw),
                "not_before_utc": "2020-01-01T00:00:00Z",
                "not_after_utc": "2099-12-31T23:59:59Z",
                "status": "trusted",
            }
        )
    trust_path = node / "trust-roots.json"
    trust_path.write_text(json.dumps(trust) + "\n", encoding="utf-8")
    (node / "trust-roots.sha256").write_text(
        f"{hashlib.sha256(trust_path.read_bytes()).hexdigest()}  trust-roots.json\n",
        encoding="ascii",
    )
    output = node / "attestation-validation.json"
    result = validate_attestations.main(
        [
            "--mode",
            "node-pair",
            "--schema",
            str(SCHEMA_ROOT / "acgs-attestation-v1.schema.json"),
            "--trust-schema",
            str(SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json"),
            "--expected-parent",
            parent,
            "--expected-product",
            product,
            "--expected-run-hash",
            run_hash,
            "--review",
            str(node / "review-attestation.json"),
            "--verification",
            str(node / "verification-attestation.json"),
            "--trust-roots",
            str(trust_path),
            "--require-distinct-principals",
            "--require-distinct-key-ids",
            "--forbid-principal",
            "node-author",
            "--output",
            str(output),
        ]
    )
    assert result == 2
    assert "exceeds 90 days" in capsys.readouterr().err
    assert not output.exists()


def test_trust_requires_same_node_successful_preflight_and_digest_is_nofollow(
    tmp_path: Path,
) -> None:
    paths = _bootstrap_key_material(tmp_path / "keys")
    missing_preflight = _run_evidence(
        "attest.py",
        "trust-manifest",
        "--schema",
        SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
        "--trust-domain",
        "acgs-saas-beta-local",
        "--public-descriptor",
        paths["reviewer_public"],
        "--public-descriptor",
        paths["verifier_public"],
        "--not-before",
        _now(timedelta(minutes=-1)),
        "--not-after",
        _now(timedelta(days=1)),
        "--output",
        paths["node"] / "trust-roots.json",
        evidence_root=paths["evidence"],
        expected=2,
    )
    assert "successful same-node custody preflight" in missing_preflight.stderr
    assert not (paths["node"] / "trust-roots.json").exists()

    other_node = paths["evidence"] / "P0-MEMBRANE-001/custody-inputs"
    other_node.mkdir(parents=True)
    other_verifier = other_node / "verifier-public.json"
    shutil.copy2(paths["verifier_public"], other_verifier)
    cross_node = _run_evidence(
        "attest.py",
        "trust-manifest",
        "--schema",
        SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
        "--trust-domain",
        "acgs-saas-beta-local",
        "--public-descriptor",
        paths["reviewer_public"],
        "--public-descriptor",
        other_verifier,
        "--not-before",
        _now(timedelta(minutes=-1)),
        "--not-after",
        _now(timedelta(days=1)),
        "--output",
        paths["node"] / "trust-roots.json",
        evidence_root=paths["evidence"],
        expected=2,
    )
    assert "one exact node" in cross_node.stderr

    _run_custody_preflight(paths["node"], paths["evidence"])
    moved_output = other_node.parent / "trust-roots.json"
    moved = _run_evidence(
        "attest.py",
        "trust-manifest",
        "--schema",
        SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
        "--trust-domain",
        "acgs-saas-beta-local",
        "--public-descriptor",
        paths["reviewer_public"],
        "--public-descriptor",
        paths["verifier_public"],
        "--not-before",
        _now(timedelta(minutes=-1)),
        "--not-after",
        _now(timedelta(days=1)),
        "--output",
        moved_output,
        evidence_root=paths["evidence"],
        expected=2,
    )
    assert "exact node path" in moved.stderr
    assert not moved_output.exists()

    digest_root = tmp_path / "digest"
    digest_root.mkdir()
    trust = digest_root / "trust-roots.json"
    trust.write_bytes(b'{"trust":true}\n')
    digest = digest_root / "trust-roots.sha256"
    digest.write_text(f"{hashlib.sha256(trust.read_bytes()).hexdigest()}  trust-roots.json\n")
    snapshot, canonical_digest, observed = validate_attestations._validate_digest(
        trust, "trust-roots.sha256"
    )
    assert snapshot == trust.read_bytes()
    assert canonical_digest == digest
    assert observed == hashlib.sha256(snapshot).hexdigest()
    digest.unlink()
    digest.symlink_to(tmp_path / "missing-digest")
    with pytest.raises(_common.EvidenceError, match="must not be a symlink"):
        validate_attestations._validate_digest(trust, "trust-roots.sha256")


def test_custody_consumers_reject_stale_moved_and_cross_node_descriptors(tmp_path: Path) -> None:
    paths = _bootstrap_key_material(tmp_path)
    _run_custody_preflight(paths["node"], paths["evidence"])
    trust_args: list[str | Path] = [
        "trust-manifest",
        "--schema",
        SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
        "--trust-domain",
        "acgs-saas-beta-local",
        "--public-descriptor",
        paths["reviewer_public"],
        "--public-descriptor",
        paths["verifier_public"],
        "--not-before",
        _now(timedelta(minutes=-1)),
        "--not-after",
        _now(timedelta(days=1)),
        "--output",
        paths["node"] / "trust-roots.json",
    ]

    descriptor_bytes = paths["reviewer_descriptor"].read_bytes()
    alternate_root = (tmp_path / "private/reviewer-moved-target").resolve()
    alternate_root.mkdir(mode=0o700)
    alternate_root.chmod(0o700)
    stale_descriptor = _json(paths["reviewer_descriptor"])
    stale_descriptor["canonical_private_root"] = str(alternate_root)
    paths["reviewer_descriptor"].write_text(json.dumps(stale_descriptor) + "\n", encoding="utf-8")
    stale = _run_evidence(
        "attest.py",
        *trust_args,
        evidence_root=paths["evidence"],
        expected=2,
    )
    assert "stale" in stale.stderr
    assert not (paths["node"] / "trust-roots.json").exists()
    paths["reviewer_descriptor"].write_bytes(descriptor_bytes)

    moved_root = paths["reviewer_root"].with_name("reviewer-relocated")
    paths["reviewer_root"].rename(moved_root)
    try:
        moved = _run_evidence(
            "attest.py",
            *trust_args,
            evidence_root=paths["evidence"],
            expected=2,
        )
        assert "canonical private root" in moved.stderr
        assert not (paths["node"] / "trust-roots.json").exists()
    finally:
        moved_root.rename(paths["reviewer_root"])

    other_node = paths["evidence"] / "P0-MEMBRANE-001"
    shutil.copytree(paths["node"] / "custody-inputs", other_node / "custody-inputs")
    shutil.copy2(paths["node"] / "custody-preflight.json", other_node / "custody-preflight.json")
    cross_output = other_node / "trust-roots.json"
    cross = _run_evidence(
        "attest.py",
        "trust-manifest",
        "--schema",
        SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
        "--trust-domain",
        "acgs-saas-beta-local",
        "--public-descriptor",
        other_node / "custody-inputs/reviewer-public.json",
        "--public-descriptor",
        other_node / "custody-inputs/verifier-public.json",
        "--not-before",
        _now(timedelta(minutes=-1)),
        "--not-after",
        _now(timedelta(days=1)),
        "--output",
        cross_output,
        evidence_root=paths["evidence"],
        expected=2,
    )
    assert "stale" in cross.stderr
    assert not cross_output.exists()


def test_claims_trust_rejects_node_lane_principal_reuse(tmp_path: Path) -> None:
    paths = _bootstrap_key_material(tmp_path)
    claims_root = (tmp_path / "private/claims-reviewer").resolve()
    claims_root.mkdir(mode=0o700)
    os.chmod(claims_root, 0o700)
    custody = paths["node"] / "custody-inputs"
    claims_private = claims_root / "claims-reviewer.ed25519"
    claims_public = custody / "claims-reviewer-public.json"
    claims_descriptor = custody / "claims-reviewer-root.json"
    _run_evidence(
        "attest.py",
        "keygen",
        "--root-schema",
        SCHEMA_ROOT / "acgs-private-root-descriptor-v1.schema.json",
        "--algorithm",
        "ed25519",
        "--role",
        "claims-reviewer",
        "--principal",
        "independent-reviewer",
        "--private-key",
        claims_private,
        "--public-descriptor",
        claims_public,
        "--canonical-private-root",
        claims_root,
        "--root-descriptor",
        claims_descriptor,
        evidence_root=paths["evidence"],
    )
    claims_preflight = paths["node"] / "claims-custody-preflight.json"
    _run_evidence(
        "attest.py",
        "custody-preflight",
        "--root-schema",
        SCHEMA_ROOT / "acgs-private-root-descriptor-v1.schema.json",
        "--repo-root",
        ROOT,
        "--evidence-root",
        paths["evidence"],
        "--root-descriptor",
        paths["reviewer_descriptor"],
        "--root-descriptor",
        paths["verifier_descriptor"],
        "--root-descriptor",
        claims_descriptor,
        "--require-role",
        "reviewer",
        "--require-role",
        "verifier",
        "--require-role",
        "claims-reviewer",
        "--reject-equal-or-nested",
        "--output",
        claims_preflight,
        evidence_root=paths["evidence"],
    )
    output = paths["node"] / "claims-trust-roots.json"
    completed = _run_evidence(
        "attest.py",
        "trust-manifest",
        "--schema",
        SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
        "--trust-domain",
        "acgs-saas-beta-local",
        "--public-descriptor",
        claims_public,
        "--not-before",
        _now(timedelta(minutes=-1)),
        "--not-after",
        _now(timedelta(days=1)),
        "--output",
        output,
        evidence_root=paths["evidence"],
        expected=2,
    )
    assert "reuses a node review lane" in completed.stderr
    assert not output.exists()


def test_attestation_rejects_tamper_extra_padded_untrusted_revoked_expired_and_ptr(
    tmp_path: Path,
) -> None:
    paths = _bootstrap_key_material(tmp_path)
    trust_value = {
        "schema_version": "acgs-attestation-trust/v1",
        "trust_domain": "acgs-saas-beta-local",
        "keys": [],
    }
    for role in ("reviewer", "verifier"):
        public = _json(paths[f"{role}_public"])
        trust_value["keys"].append(
            {
                "key_id": public["key_id"],
                "algorithm": "Ed25519",
                "role": role,
                "principal": public["principal"],
                "public_key_base64url": public["public_key_base64url"],
                "not_before_utc": _now(timedelta(minutes=-1)),
                "not_after_utc": _now(timedelta(days=1)),
                "status": "trusted",
            }
        )
    trusted = validate_attestations._validate_trust(
        trust_value,
        SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
        {"reviewer", "verifier"},
        validation_time=_common.parse_utc(_now()),
    )
    parent, product, run_hash = "1" * 40, "2" * 40, "3" * 64
    output = paths["node"] / "review-attestation.json"
    _run_evidence(
        "attest.py",
        "sign",
        "--schema",
        SCHEMA_ROOT / "acgs-attestation-v1.schema.json",
        "--mode",
        "node-review",
        "--role",
        "reviewer",
        "--principal",
        "independent-reviewer",
        "--private-key",
        paths["reviewer_private"],
        "--parent",
        parent,
        "--product",
        product,
        "--run-hash",
        run_hash,
        "--verdict",
        "approve",
        "--timestamp",
        _now(),
        "--output",
        output,
        evidence_root=paths["evidence"],
    )
    envelope = _json(output)

    def validate(value: dict[str, Any], trust: dict[str, dict[str, Any]] = trusted) -> None:
        validate_attestations._validate_envelope(
            value,
            SCHEMA_ROOT / "acgs-attestation-v1.schema.json",
            trust,
            mode="node-review",
            role="reviewer",
            parent=parent,
            product=product,
            run_hash=run_hash,
            forbidden_principals={"author"},
            validation_time=_common.parse_utc(_now()),
        )

    for field, value in (
        ("parent_commit_sha", "4" * 40),
        ("product_commit_sha", "5" * 40),
        ("run_hash", "6" * 64),
        ("verdict", "reject"),
        ("principal", "author"),
        ("key_id", "ed25519:sha256:" + "0" * 64),
    ):
        mutated = copy.deepcopy(envelope)
        mutated[field] = value
        with pytest.raises(_common.EvidenceError):
            validate(mutated)
    mutated = copy.deepcopy(envelope)
    mutated["signature"] = ("A" if mutated["signature"][0] != "A" else "B") + mutated["signature"][
        1:
    ]
    with pytest.raises(_common.EvidenceError, match="signature"):
        validate(mutated)
    mutated = copy.deepcopy(envelope)
    mutated["signature"] += "="
    with pytest.raises(_common.EvidenceError):
        validate(mutated)
    mutated = copy.deepcopy(envelope)
    mutated["extra"] = True
    with pytest.raises(_common.EvidenceError):
        validate(mutated)
    revoked = copy.deepcopy(trust_value)
    revoked["keys"][0]["status"] = "revoked"
    with pytest.raises(_common.EvidenceError, match="not trusted"):
        validate_attestations._validate_trust(
            revoked,
            SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
            {"reviewer", "verifier"},
            validation_time=_common.parse_utc(_now()),
        )
    expired = copy.deepcopy(trust_value)
    for key in expired["keys"]:
        key["not_before_utc"] = "2000-01-01T00:00:00Z"
        key["not_after_utc"] = "2000-01-02T00:00:00Z"
    with pytest.raises(_common.EvidenceError, match="expired"):
        validate_attestations._validate_trust(
            expired,
            SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
            {"reviewer", "verifier"},
            validation_time=_common.parse_utc(_now()),
        )

    future = copy.deepcopy(envelope)
    future["timestamp_utc"] = _now(timedelta(minutes=6))
    with pytest.raises(_common.EvidenceError, match="future-skew"):
        validate(future)


def test_attestation_future_skew_uses_one_fixed_validation_time_at_exact_boundary(
    tmp_path: Path,
) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    paths = _bootstrap_key_material(tmp_path)
    public = _json(paths["reviewer_public"])
    validation_time = datetime(2026, 7, 10, 12, 0, tzinfo=UTC)
    trust_value = {
        "schema_version": "acgs-attestation-trust/v1",
        "trust_domain": "acgs-saas-beta-local",
        "keys": [
            {
                "key_id": public["key_id"],
                "algorithm": "Ed25519",
                "role": "reviewer",
                "principal": public["principal"],
                "public_key_base64url": public["public_key_base64url"],
                "not_before_utc": "2026-07-01T00:00:00Z",
                "not_after_utc": "2026-09-29T00:00:00Z",
                "status": "trusted",
            }
        ],
    }
    trusted = validate_attestations._validate_trust(
        trust_value,
        SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
        {"reviewer"},
        validation_time=validation_time,
    )
    private = Ed25519PrivateKey.from_private_bytes(paths["reviewer_private"].read_bytes())
    parent, product, run_hash = "1" * 40, "2" * 40, "3" * 64

    def envelope_at(offset: timedelta) -> dict[str, Any]:
        unsigned = {
            "schema_version": "acgs-attestation/v1",
            "algorithm": "Ed25519",
            "mode": "node-review",
            "key_id": public["key_id"],
            "role": "reviewer",
            "principal": public["principal"],
            "parent_commit_sha": parent,
            "product_commit_sha": product,
            "run_hash": run_hash,
            "verdict": "approve",
            "timestamp_utc": (validation_time + offset).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return {
            **unsigned,
            "signature": _common.b64url_encode(private.sign(_common.jcs_bytes(unsigned))),
        }

    accepted = validate_attestations._validate_envelope(
        envelope_at(timedelta(minutes=5)),
        SCHEMA_ROOT / "acgs-attestation-v1.schema.json",
        trusted,
        mode="node-review",
        role="reviewer",
        parent=parent,
        product=product,
        run_hash=run_hash,
        forbidden_principals={"author"},
        validation_time=validation_time,
    )
    assert accepted["timestamp_utc"] == "2026-07-10T12:05:00Z"
    with pytest.raises(_common.EvidenceError, match="five-minute future-skew"):
        validate_attestations._validate_envelope(
            envelope_at(timedelta(minutes=5, seconds=1)),
            SCHEMA_ROOT / "acgs-attestation-v1.schema.json",
            trusted,
            mode="node-review",
            role="reviewer",
            parent=parent,
            product=product,
            run_hash=run_hash,
            forbidden_principals={"author"},
            validation_time=validation_time,
        )


def test_sign_rejects_future_timestamp_without_output(tmp_path: Path) -> None:
    paths = _bootstrap_key_material(tmp_path)
    output = paths["node"] / "review-attestation.json"
    completed = _run_evidence(
        "attest.py",
        "sign",
        "--schema",
        SCHEMA_ROOT / "acgs-attestation-v1.schema.json",
        "--mode",
        "node-review",
        "--role",
        "reviewer",
        "--principal",
        "independent-reviewer",
        "--private-key",
        paths["reviewer_private"],
        "--parent",
        "1" * 40,
        "--product",
        "2" * 40,
        "--run-hash",
        "3" * 64,
        "--verdict",
        "approve",
        "--timestamp",
        _now(timedelta(minutes=6)),
        "--output",
        output,
        evidence_root=paths["evidence"],
        expected=2,
    )
    assert "future-skew" in completed.stderr
    assert not output.exists()


def test_attestation_validation_requires_exact_actual_author_exclusion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    evidence = (tmp_path / "evidence").resolve()
    evidence.mkdir()
    monkeypatch.setenv("ACGS_EVIDENCE_ROOT", str(evidence))
    monkeypatch.setattr(validate_attestations, "assert_evidence_runtime", lambda **_: ROOT)
    base = [
        "--mode",
        "node-pair",
        "--schema",
        str(SCHEMA_ROOT / "acgs-attestation-v1.schema.json"),
        "--trust-schema",
        str(SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json"),
        "--expected-parent",
        "1" * 40,
        "--expected-product",
        "2" * 40,
        "--expected-run-hash",
        "3" * 64,
        "--review",
        str(evidence / "P0-EVIDENCE-000/review-attestation.json"),
        "--verification",
        str(evidence / "P0-EVIDENCE-000/verification-attestation.json"),
        "--trust-roots",
        str(evidence / "P0-EVIDENCE-000/trust-roots.json"),
        "--require-distinct-principals",
        "--require-distinct-key-ids",
        "--output",
        str(evidence / "P0-EVIDENCE-000/attestation-validation.json"),
    ]
    assert validate_attestations.main(base) == 2
    assert "exactly one actual author principal exclusion" in capsys.readouterr().err
    assert validate_attestations.main([*base, "--forbid-principal", " "]) == 2
    assert "unique, nonempty, and trimmed" in capsys.readouterr().err


def test_no_alternate_signature_or_canonicalization_fallback_is_present() -> None:
    sources = "\n".join(
        (EVIDENCE_SCRIPTS / name).read_text(encoding="utf-8")
        for name in ("_common.py", "attest.py", "validate_attestations.py")
    ).lower()
    assert "pynacl" not in sources
    assert "nacl.sign" not in sources
    assert "openssl dgst" not in sources
    assert "pure-python" not in sources
    assert "optional import" not in sources
    assert "rfc8785" in sources
    assert "ed25519privatekey" in sources
    assert "ed25519publickey" in sources


def test_canonical_transcript_capture_rejects_secrets_before_write_and_preserves_safe_argv(
    tmp_path: Path,
) -> None:
    sentinel = "S3ntinel-Capture-Must-Never-Persist"
    rejected = tmp_path / "rejected/transcript.jsonl"
    for unsafe in _unsafe_command_corpus(sentinel):
        with pytest.raises(_common.EvidenceError) as error:
            _common.append_safe_transcript_record(rejected, _transcript_record(unsafe))
        assert sentinel not in str(error.value)
        assert not rejected.exists()
        assert not rejected.parent.exists()

    safe_selector, reviewed_argv = _common.REVIEWED_P0_TRANSCRIPT[0]
    safe_argv = list(reviewed_argv)
    accepted = tmp_path / "accepted/transcript.jsonl"
    _common.append_safe_transcript_record(accepted, _transcript_record(safe_argv, safe_selector))
    command = _common.validate_transcript_record(_json_line(accepted))
    assert command["argv"] == safe_argv
    assert _json_line(accepted)["argv"] == safe_argv


def test_closed_p0_command_corpus_is_exact_ordered_and_contains_no_shell_compounds(
    tmp_path: Path,
) -> None:
    assert len(_common.REVIEWED_P0_TRANSCRIPT) == 10
    assert [selector for selector, _ in _common.REVIEWED_P0_TRANSCRIPT] == [
        "root:EVID-gate",
        *["packages/acgs-control-plane:local-gate"] * 4,
        *["packages/gove-zone:local-gate"] * 4,
        "root:P0-EVIDENCE-000",
    ]
    transcript = tmp_path / "P0-EVIDENCE-000/transcript.jsonl"
    _write_reviewed_p0_transcript(transcript)
    records = generate_run._read_transcript(transcript)
    _common.validate_p0_transcript_sequence(records)
    assert [(record["selectors"][0], tuple(record["argv"])) for record in records] == list(
        _common.REVIEWED_P0_TRANSCRIPT
    )
    assert all(
        "-c" not in argv and argv[0] not in {"bash", "sh", "zsh", "python", "python3"}
        for _, argv in _common.REVIEWED_P0_TRANSCRIPT
    )

    for mutation in (
        records[:-1],
        [*records, records[-1]],
        [records[1], records[0], *records[2:]],
    ):
        with pytest.raises(_common.EvidenceError, match="reviewed ordered command corpus"):
            _common.validate_p0_transcript_sequence(mutation)


def test_p0_membrane_corpus_is_node_bound_exact_and_ordered(tmp_path: Path) -> None:
    node_id = "P0-MEMBRANE-001"
    reviewed = _common.REVIEWED_P0_MEMBRANE_TRANSCRIPT
    records = _reviewed_node_records(node_id)
    transcript = tmp_path / node_id / "transcript.jsonl"
    _write_raw_transcript(transcript, records)

    assert len(reviewed) == 7
    assert [selector for selector, _ in reviewed] == [
        "root:EVID-gate",
        *["packages/acgs-control-plane:local-gate"] * 4,
        "packages/acgs-control-plane:P0-MEMBRANE-001-exact",
        "root:P0-MEMBRANE-001",
    ]
    assert generate_run._read_transcript(transcript, node_id=node_id) == records
    _common.validate_node_transcript_sequence(node_id, records)

    package = records[-2]
    root = records[-1]
    one_test = copy.deepcopy(package)
    one_test["argv"] = one_test["argv"][:-1]
    broad = copy.deepcopy(package)
    broad["argv"] = [".venv/bin/pytest", "-q"]
    filtered = copy.deepcopy(package)
    filtered["argv"] = [*filtered["argv"], "-k", "production"]
    alternate = copy.deepcopy(root)
    alternate["argv"][0] = "python3"
    alternate_path = copy.deepcopy(root)
    alternate_path["argv"][4] = alternate_path["argv"][4].replace(
        "packages/acgs-control-plane/", "./packages/acgs-control-plane/"
    )
    alternate_arg = copy.deepcopy(root)
    alternate_arg["argv"].insert(3, "--disable-warnings")
    selector_mismatch = copy.deepcopy(package)
    selector_mismatch["selectors"] = ["root:P0-MEMBRANE-001"]
    cross_node = _reviewed_p0_records()
    mutations = (
        [],
        cross_node,
        records[1:5],
        [package],
        [root],
        [one_test],
        records[:-1],
        [*records[:-1], package],
        [records[1], records[0], *records[2:]],
        [*records, root],
        [*records, broad],
        [*records[:-2], filtered, root],
        [*records[:-1], alternate],
        [*records[:-1], alternate_path],
        [*records[:-1], alternate_arg],
        [*records[:-2], selector_mismatch, root],
    )
    for index, mutation in enumerate(mutations):
        forged = tmp_path / f"forged-{index}" / node_id / "transcript.jsonl"
        _write_raw_transcript(forged, mutation)
        output = forged.with_name("run.json")
        with pytest.raises(_common.EvidenceError):
            generate_run._read_transcript(forged, node_id=node_id)
        with pytest.raises(_common.EvidenceError):
            _common.validate_secret_free_run(
                {"node_id": node_id, "commands": mutation}, expected_node=node_id
            )
        assert not output.exists()


def test_p0_claims_corpus_is_closed_exact_ordered_and_final_selector_is_last(
    tmp_path: Path,
) -> None:
    node_id = "P0-CLAIMS-002"
    reviewed = _common.REVIEWED_P0_CLAIMS_TRANSCRIPT
    records = _reviewed_node_records(node_id)
    transcript = tmp_path / node_id / "transcript.jsonl"
    _write_raw_transcript(transcript, records)

    assert len(reviewed) == 14
    assert [selector for selector, _ in reviewed] == [
        "root:EVID-gate",
        *["packages/acgs-control-plane:local-gate"] * 4,
        "packages/acgs-control-plane:P0-MEMBRANE-001-exact",
        *["packages/gove-zone:local-gate"] * 4,
        "packages/gove-zone:P0-CLAIMS-002-exact",
        "root:lint-docs",
        "root:docs-full",
        "root:P0-CLAIMS-002",
    ]
    assert _common.REVIEWED_CWD_SCOPES_BY_NODE[node_id] == (
        "REPO_ROOT",
        *["CP"] * 5,
        *["REPO_ROOT"] * 8,
    )
    assert reviewed[-1][1] == (
        "packages/acgs-control-plane/.venv/bin/python",
        "-m",
        "pytest",
        "-q",
        "tests/docs/test_saas_beta_claims.py::test_claim_boundaries_and_control_plane_readme",
    )
    assert all(
        "&&" not in argument and argument not in {"bash", "sh", "zsh", "-c"}
        for _, argv in reviewed
        for argument in argv
    )
    _common.validate_node_transcript_sequence(node_id, records)

    broad_gz = copy.deepcopy(records[10])
    broad_gz["argv"] = [
        *_common._GZ_LOCKED_PREFIX,
        "python",
        "-m",
        "pytest",
        "-q",
        "packages/gove-zone/tests",
    ]
    alternate_interpreter = copy.deepcopy(records[-1])
    alternate_interpreter["argv"][0] = ".venv-evidence/bin/python"
    selector_mismatch = copy.deepcopy(records[10])
    selector_mismatch["selectors"] = ["packages/gove-zone:local-gate"]
    cwd_mismatch = copy.deepcopy(records[10])
    cwd_mismatch["cwd_scope"] = "CP"
    substituted = copy.deepcopy(records[-1])
    substituted["argv"][-1] = "tests/docs/test_signing_default_doc_matches_code.py"
    mutations = (
        [],
        records[:-1],
        records[1:],
        [*records, records[-1]],
        [records[1], records[0], *records[2:]],
        [*records[:10], broad_gz, *records[11:]],
        [*records[:-1], alternate_interpreter],
        [*records[:10], selector_mismatch, *records[11:]],
        [*records[:10], cwd_mismatch, *records[11:]],
        [*records[:-1], substituted],
        _reviewed_node_records("P0-MEMBRANE-001"),
        _reviewed_p0_records(),
    )
    for mutation in mutations:
        with pytest.raises(_common.EvidenceError):
            _common.validate_node_transcript_sequence(node_id, mutation)
        with pytest.raises(_common.EvidenceError):
            _common.validate_secret_free_run(
                {"node_id": node_id, "commands": mutation}, expected_node=node_id
            )


def test_literal_durable_membrane_record_keeps_legacy_profile_contract() -> None:
    record = _reviewed_node_records("P0-MEMBRANE-001")[0]
    # Literal digest copied from the published G002 transcript; never derive it here.
    record["environment_profile_version_sha256"] = (
        "de8c50aa969a9cf4c972ac6af85743dfd2517781f4851730e242535aa4b986f5"
    )
    _common.validate_transcript_record(record, expected_node="P0-MEMBRANE-001")
    forged = {**record, "environment_profile_version_sha256": ENVIRONMENT_PROFILE_VERSION_SHA256}
    with pytest.raises(_common.EvidenceError, match="execution identity"):
        _common.validate_transcript_record(forged, expected_node="P0-MEMBRANE-001")


def test_p0_gates_corpus_is_closed_exact_ordered_and_root_selector_is_last() -> None:
    node_id = "P0-GATES-003"
    reviewed = _common.REVIEWED_P0_GATES_TRANSCRIPT
    records = _reviewed_node_records(node_id)
    assert len(reviewed) == 16
    assert [selector for selector, _ in reviewed] == [
        "root:EVID-gate",
        *["packages/acgs-control-plane:local-gate"] * 4,
        "packages/acgs-control-plane:P0-MEMBRANE-001-exact",
        *["packages/gove-zone:local-gate"] * 4,
        *["acgi-ai:local-gate"] * 5,
        "root:P0-GATES-003",
    ]
    assert _common.REVIEWED_CWD_SCOPES_BY_NODE[node_id] == (
        "REPO_ROOT",
        *["CP"] * 5,
        *["REPO_ROOT"] * 4,
        *["UI"] * 5,
        "REPO_ROOT",
    )
    assert [argv for _, argv in reviewed[10:15]] == [
        (*_common._UI_LOCKED_PREFIX, command)
        for command in ("lint", "build", "test:all", "test:unit", "test:playwright")
    ]
    assert all(
        record["sandbox_profile_version_sha256"]
        == _common.REVIEWED_UI_SANDBOX_PROFILE_VERSION_SHA256
        for record in records[10:15]
    )
    assert reviewed[-1][1][-1] == (
        "tests/saas_beta/test_ci_gate_contract.py::test_all_owned_scope_gates_are_required"
    )
    _common.validate_node_transcript_sequence(node_id, records)

    broad = copy.deepcopy(records[-1])
    broad["argv"][-1] = "tests/saas_beta/test_ci_gate_contract.py"
    substituted = copy.deepcopy(records[13])
    substituted["argv"][-1] = "test:all"
    wrong_cwd = copy.deepcopy(records[10])
    wrong_cwd["cwd_scope"] = "REPO_ROOT"
    mutations = (
        records[:-1],
        [*records, records[-1]],
        [records[1], records[0], *records[2:]],
        [*records[:13], records[14], records[13], records[15]],
        [*records[:-1], broad],
        [*records[:13], substituted, *records[14:]],
        [*records[:10], wrong_cwd, *records[11:]],
        _reviewed_node_records("P0-CLAIMS-002"),
    )
    for mutation in mutations:
        with pytest.raises(_common.EvidenceError):
            _common.validate_node_transcript_sequence(node_id, mutation)
        with pytest.raises(_common.EvidenceError):
            _common.validate_secret_free_run(
                {"node_id": node_id, "commands": mutation}, expected_node=node_id
            )


def test_node_specific_commands_do_not_weaken_baseline_or_cross_node_contract() -> None:
    membrane_only = list(_common.REVIEWED_P0_MEMBRANE_TRANSCRIPT[-1][1])
    assert tuple(membrane_only) not in _common.REVIEWED_COMMAND_SELECTORS
    with pytest.raises(_common.EvidenceError, match="reviewed closed contract"):
        _common.validate_safe_argv(membrane_only)
    with pytest.raises(_common.EvidenceError, match="outside the reviewed node contract"):
        _common.validate_transcript_record(
            _reviewed_node_records("P0-MEMBRANE-001")[-1],
            expected_node="P0-CLAIMS-002",
        )
    with pytest.raises(_common.EvidenceError, match=r"reviewed.*contract"):
        _common.validate_node_transcript_sequence("P0-CLAIMS-002", _reviewed_p0_records())


def test_duplicate_node_argv_cannot_resolve_conflicting_selector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    argv = _common.REVIEWED_P0_MEMBRANE_TRANSCRIPT[0][1]
    monkeypatch.setitem(
        _common.REVIEWED_TRANSCRIPTS_BY_NODE,
        "P0-MEMBRANE-001",
        (("selector:one", argv), ("selector:two", argv)),
    )
    record = _transcript_record(list(argv), "selector:one")
    record.update(
        {
            "cwd_scope": "REPO_ROOT",
            "executable_sha256": "0" * 64,
            "environment_profile_version_sha256": ENVIRONMENT_PROFILE_VERSION_SHA256,
            "resolved_executable_identity_sha256": "0" * 64,
            "sandbox_executable_sha256": "0" * 64,
            "sandbox_profile_version_sha256": SANDBOX_PROFILE_VERSION_SHA256,
            "sandbox_resolved_identity_sha256": "0" * 64,
        }
    )
    with pytest.raises(_common.EvidenceError, match="outside the reviewed node contract"):
        _common.validate_transcript_record(record, expected_node="P0-MEMBRANE-001")


def test_generate_run_cli_rejects_membrane_mutations_and_claims_substitution_without_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = (tmp_path / "evidence").resolve()
    monkeypatch.setenv("ACGS_EVIDENCE_ROOT", str(evidence))
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=True
    ).stdout.strip()
    parent = subprocess.run(
        ["git", "rev-parse", "HEAD^"], cwd=ROOT, text=True, capture_output=True, check=True
    ).stdout.strip()
    monkeypatch.setattr(generate_run, "assert_evidence_runtime", lambda **_kwargs: ROOT)
    monkeypatch.setattr(generate_run, "git_root", lambda: ROOT)
    monkeypatch.setattr(generate_run, "verify_git_range", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        generate_run, "reject_outer_evidence_in_product", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        generate_run, "validate_node_execution_identities", lambda *_args, **_kwargs: None
    )
    real_load_json = generate_run.load_json

    cases = {
        "subset": _reviewed_node_records("P0-MEMBRANE-001")[:-1],
        "reorder": [
            _reviewed_node_records("P0-MEMBRANE-001")[1],
            _reviewed_node_records("P0-MEMBRANE-001")[0],
            *_reviewed_node_records("P0-MEMBRANE-001")[2:],
        ],
        "injection": [
            {
                **_reviewed_node_records("P0-MEMBRANE-001")[0],
                "argv": [".venv-evidence/bin/python", "-c", "print('injected')"],
            },
            *_reviewed_node_records("P0-MEMBRANE-001")[1:],
        ],
        "claims-cross-node": _reviewed_node_records("P0-MEMBRANE-001"),
        "claims-subset": _reviewed_node_records("P0-CLAIMS-002")[:-1],
        "claims-duplicate": [
            *_reviewed_node_records("P0-CLAIMS-002"),
            _reviewed_node_records("P0-CLAIMS-002")[-1],
        ],
        "claims-reorder": [
            _reviewed_node_records("P0-CLAIMS-002")[1],
            _reviewed_node_records("P0-CLAIMS-002")[0],
            *_reviewed_node_records("P0-CLAIMS-002")[2:],
        ],
        "claims-selector-substitution": [
            *_reviewed_node_records("P0-CLAIMS-002")[:-1],
            {
                **_reviewed_node_records("P0-CLAIMS-002")[-1],
                "argv": [
                    "packages/acgs-control-plane/.venv/bin/python",
                    "-m",
                    "pytest",
                    "-q",
                    "tests/docs",
                ],
            },
        ],
    }
    for name, records in cases.items():
        node_id = "P0-CLAIMS-002" if name.startswith("claims-") else "P0-MEMBRANE-001"
        assignment = "EVID+CP+GZ" if node_id == "P0-CLAIMS-002" else "EVID+CP"
        node = evidence / node_id
        node.mkdir(parents=True, exist_ok=True)
        transcript = node / "transcript.jsonl"
        output = node / "run.json"
        _write_raw_transcript(transcript, records)
        identity_bundle = {
            "schema_version": "acgs-environment-identities/v1",
            "node_id": node_id,
            "assignment": assignment,
            "environment_identities": {code: {} for code in assignment.split("+")},
            "pep660_editable_build": {},
            "ed25519_implementation": {},
        }
        identity_path = node / "environment-identities.json"
        identity_path.write_text(json.dumps(identity_bundle), encoding="utf-8")

        def load_json(path: Path, bundle: dict[str, Any] = identity_bundle) -> Any:
            if Path(path).name == "environment-identities.json":
                return bundle
            return real_load_json(path)

        monkeypatch.setattr(generate_run, "load_json", load_json)
        result = generate_run.main(
            [
                "--schema",
                str(SCHEMA_ROOT / "acgs-run-evidence-v1.schema.json"),
                "--node",
                node_id,
                "--parent",
                parent,
                "--product",
                head,
                "--assignment",
                assignment,
                "--environment-identities",
                str(identity_path),
                "--transcript",
                str(transcript),
                "--output",
                str(output),
            ]
        )
        assert result == 2
        assert not output.exists()


def test_capture_launcher_binds_cwd_executable_and_appends_only_after_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    executable = repo / ".venv-evidence/bin/python"
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/sh\nprintf captured\n", encoding="utf-8")
    executable.chmod(0o755)
    transcript = tmp_path / "evidence/P0-MEMBRANE-001/transcript.jsonl"
    monkeypatch.setattr(capture_reviewed_command, "assert_evidence_runtime", lambda **_kw: repo)
    monkeypatch.setattr(capture_reviewed_command, "git_root", lambda: repo)
    monkeypatch.setattr(
        capture_reviewed_command,
        "canonical_node_evidence_path",
        lambda *_args, **_kwargs: transcript,
    )
    monkeypatch.setattr(
        capture_reviewed_command, "_require_safe_parent_chain", lambda *_args, **_kwargs: None
    )
    temp_root = tmp_path / "runtime"
    temp_root.mkdir(mode=0o700)
    assert (
        capture_reviewed_command.main(
            [
                "--node",
                "P0-MEMBRANE-001",
                "--index",
                "0",
                "--transcript",
                str(transcript),
                "--temp-root",
                str(temp_root),
            ]
        )
        == 0
    )
    record = _json_line(transcript)
    assert record["cwd_scope"] == "REPO_ROOT"
    assert record["executable_sha256"] == hashlib.sha256(executable.read_bytes()).hexdigest()
    assert record["selectors"] == ["root:EVID-gate"]

    transcript.unlink()
    executable.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
    assert (
        capture_reviewed_command.main(
            [
                "--node",
                "P0-MEMBRANE-001",
                "--index",
                "0",
                "--transcript",
                str(transcript),
                "--temp-root",
                str(temp_root),
            ]
        )
        == 2
    )
    assert not transcript.exists()


def test_capture_launcher_uses_lexical_venv_and_ignores_ambient_python_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    cp = repo / "packages/acgs-control-plane"
    cp.mkdir(parents=True)
    subprocess.run([sys.executable, "-m", "venv", str(cp / ".venv")], check=True)
    transcript = tmp_path / "evidence/P0-MEMBRANE-001/transcript.jsonl"
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    code = (
        "import os,sys; "
        "assert sys.prefix.endswith('packages/acgs-control-plane/.venv'); "
        "assert 'PYTHONPATH' not in os.environ; "
        "assert os.environ['PYTEST_ADDOPTS'].startswith('-o cache_dir='); "
        "assert 'LD_PRELOAD' not in os.environ"
    )
    monkeypatch.setenv("PYTHONPATH", "/malicious")
    monkeypatch.setenv("PYTEST_ADDOPTS", "--trace")
    monkeypatch.setenv("LD_PRELOAD", "/malicious/preload.so")
    monkeypatch.setattr(capture_reviewed_command, "assert_evidence_runtime", lambda **_kw: repo)
    monkeypatch.setattr(capture_reviewed_command, "git_root", lambda: repo)
    monkeypatch.setattr(
        capture_reviewed_command,
        "canonical_node_evidence_path",
        lambda *_args, **_kwargs: transcript,
    )
    monkeypatch.setattr(
        capture_reviewed_command,
        "reviewed_node_command",
        lambda *_args: ("test:lexical-venv", (".venv/bin/python", "-c", code), "CP"),
    )
    monkeypatch.setattr(
        capture_reviewed_command, "_require_safe_parent_chain", lambda *_args, **_kwargs: None
    )
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        capture_reviewed_command,
        "append_safe_transcript_record",
        lambda _path, record, **_kwargs: captured.update(record),
    )
    tool_state = [
        repo / name for name in (".ruff_cache", ".mypy_cache", ".pytest_cache", ".coverage")
    ]
    before = {path: path.exists() for path in tool_state}
    assert (
        capture_reviewed_command.main(
            [
                "--node",
                "P0-MEMBRANE-001",
                "--index",
                "0",
                "--transcript",
                str(transcript),
                "--temp-root",
                str(runtime),
            ]
        )
        == 0
    )
    assert captured["environment_profile_version_sha256"] == (
        _common.LEGACY_MEMBRANE_ENVIRONMENT_PROFILE_VERSION_SHA256
    )
    assert {path: path.exists() for path in tool_state} == before


def test_capture_claims_final_command_uses_canonical_selector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transcript = tmp_path / "evidence/P0-CLAIMS-002/transcript.jsonl"
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    monkeypatch.setattr(capture_reviewed_command, "assert_evidence_runtime", lambda **_kw: ROOT)
    monkeypatch.setattr(capture_reviewed_command, "git_root", lambda: ROOT)
    monkeypatch.setattr(
        capture_reviewed_command,
        "canonical_node_evidence_path",
        lambda *_args, **_kwargs: transcript,
    )
    monkeypatch.setattr(
        capture_reviewed_command, "_require_safe_parent_chain", lambda *_args, **_kwargs: None
    )
    executed: list[str] = []

    def successful_capture(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        executed.extend(argv)
        return subprocess.CompletedProcess(argv, 0, b"claims selector passed\n", b"")

    monkeypatch.setattr(capture_reviewed_command.subprocess, "run", successful_capture)
    assert (
        capture_reviewed_command.main(
            [
                "--node",
                "P0-CLAIMS-002",
                "--index",
                "13",
                "--transcript",
                str(transcript),
                "--temp-root",
                str(runtime),
            ]
        )
        == 0
    )
    record = _json_line(transcript)
    assert record["selectors"] == ["root:P0-CLAIMS-002"]
    assert tuple(record["argv"]) == _common.REVIEWED_P0_CLAIMS_TRANSCRIPT[-1][1]
    assert (
        "tests/docs/test_saas_beta_claims.py::test_claim_boundaries_and_control_plane_readme"
        in executed
    )


def test_capture_rejects_uv_substitution_between_resolution_and_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    reviewed_uv = tmp_path / "trusted-uv"
    reviewed_uv.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    reviewed_uv.chmod(0o755)
    replacement = tmp_path / "replacement-uv"
    replacement.write_text("#!/bin/sh\nprintf forbidden\n", encoding="utf-8")
    replacement.chmod(0o755)
    transcript = tmp_path / "evidence/P0-CLAIMS-002/transcript.jsonl"
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    monkeypatch.setitem(_common.REVIEWED_HOST_EXECUTABLES, "uv", reviewed_uv)
    monkeypatch.setitem(
        _common.REVIEWED_HOST_EXECUTABLE_SHA256,
        "uv",
        hashlib.sha256(reviewed_uv.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(capture_reviewed_command, "assert_evidence_runtime", lambda **_kw: repo)
    monkeypatch.setattr(capture_reviewed_command, "git_root", lambda: repo)
    monkeypatch.setattr(
        capture_reviewed_command,
        "canonical_node_evidence_path",
        lambda *_args, **_kwargs: transcript,
    )
    monkeypatch.setattr(
        capture_reviewed_command,
        "reviewed_node_command",
        lambda *_args: ("test:uv", ("uv", "--version"), "REPO_ROOT"),
    )
    monkeypatch.setattr(
        capture_reviewed_command, "_require_safe_parent_chain", lambda *_args, **_kwargs: None
    )
    real_reviewed_executable = capture_reviewed_command.reviewed_executable

    def resolve_then_replace(cwd: Path, argv0: str) -> Path:
        resolved = real_reviewed_executable(cwd, argv0)
        replacement.replace(reviewed_uv)
        return resolved

    monkeypatch.setattr(capture_reviewed_command, "reviewed_executable", resolve_then_replace)
    assert (
        capture_reviewed_command.main(
            [
                "--node",
                "P0-CLAIMS-002",
                "--index",
                "10",
                "--transcript",
                str(transcript),
                "--temp-root",
                str(runtime),
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert "reviewed host executable identity mismatch" in captured.err
    assert "forbidden" not in captured.out
    assert not transcript.exists()


@pytest.mark.parametrize("race", ["replace", "mutate"])
def test_capture_launcher_rejects_deterministic_executable_races(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, race: str
) -> None:
    repo = tmp_path / "repo"
    executable = repo / ".venv-evidence/bin/python"
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    transcript = tmp_path / "evidence/P0-MEMBRANE-001/transcript.jsonl"
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    monkeypatch.setattr(capture_reviewed_command, "assert_evidence_runtime", lambda **_kw: repo)
    monkeypatch.setattr(capture_reviewed_command, "git_root", lambda: repo)
    monkeypatch.setattr(
        capture_reviewed_command,
        "canonical_node_evidence_path",
        lambda *_args, **_kwargs: transcript,
    )
    monkeypatch.setattr(
        capture_reviewed_command, "_require_safe_parent_chain", lambda *_args, **_kwargs: None
    )
    real_run = subprocess.run

    def racing_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        completed = real_run(*args, **kwargs)
        if race == "replace":
            replacement = executable.with_suffix(".replacement")
            replacement.write_text("#!/bin/sh\nexit 0\n#replacement\n", encoding="utf-8")
            replacement.chmod(0o755)
            replacement.replace(executable)
        else:
            executable.write_text("#!/bin/sh\nexit 0\n#mutation\n", encoding="utf-8")
            executable.chmod(0o755)
        return completed

    monkeypatch.setattr(capture_reviewed_command.subprocess, "run", racing_run)
    assert (
        capture_reviewed_command.main(
            [
                "--node",
                "P0-MEMBRANE-001",
                "--index",
                "0",
                "--transcript",
                str(transcript),
                "--temp-root",
                str(runtime),
            ]
        )
        == 2
    )
    assert not transcript.exists()


@pytest.mark.parametrize("cleanup_failure", ["noop", "raise"])
def test_capture_launcher_publishes_nothing_when_isolated_cleanup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cleanup_failure: str
) -> None:
    repo = tmp_path / "repo"
    executable = repo / ".venv-evidence/bin/python"
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    transcript = tmp_path / "evidence/P0-MEMBRANE-001/transcript.jsonl"
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    monkeypatch.setattr(capture_reviewed_command, "assert_evidence_runtime", lambda **_kw: repo)
    monkeypatch.setattr(capture_reviewed_command, "git_root", lambda: repo)
    monkeypatch.setattr(
        capture_reviewed_command,
        "canonical_node_evidence_path",
        lambda *_args, **_kwargs: transcript,
    )
    monkeypatch.setattr(
        capture_reviewed_command, "_require_safe_parent_chain", lambda *_args, **_kwargs: None
    )
    if cleanup_failure == "noop":
        monkeypatch.setattr(
            capture_reviewed_command.shutil, "rmtree", lambda *_args, **_kwargs: None
        )
    else:
        monkeypatch.setattr(
            capture_reviewed_command.shutil,
            "rmtree",
            lambda *_args: (_ for _ in ()).throw(OSError("deterministic cleanup failure")),
        )
    assert (
        capture_reviewed_command.main(
            [
                "--node",
                "P0-MEMBRANE-001",
                "--index",
                "0",
                "--transcript",
                str(transcript),
                "--temp-root",
                str(runtime),
            ]
        )
        == 2
    )
    assert not transcript.exists()


def test_capture_launcher_sandbox_denies_ignored_repo_write_and_missing_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    cp = repo / "packages/acgs-control-plane"
    cp.mkdir(parents=True)
    subprocess.run([sys.executable, "-m", "venv", str(cp / ".venv")], check=True)
    transcript = tmp_path / "evidence/P0-MEMBRANE-001/transcript.jsonl"
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    ignored = repo / ".ignored-adversary"
    code = f"from pathlib import Path; Path({str(ignored)!r}).write_text('mutated')"
    monkeypatch.setattr(capture_reviewed_command, "assert_evidence_runtime", lambda **_kw: repo)
    monkeypatch.setattr(capture_reviewed_command, "git_root", lambda: repo)
    monkeypatch.setattr(
        capture_reviewed_command,
        "canonical_node_evidence_path",
        lambda *_args, **_kwargs: transcript,
    )
    monkeypatch.setattr(
        capture_reviewed_command,
        "reviewed_node_command",
        lambda *_args: ("test:write", (".venv/bin/python", "-c", code), "CP"),
    )
    monkeypatch.setattr(
        capture_reviewed_command, "_require_safe_parent_chain", lambda *_args, **_kwargs: None
    )
    args = [
        "--node",
        "P0-MEMBRANE-001",
        "--index",
        "0",
        "--transcript",
        str(transcript),
        "--temp-root",
        str(runtime),
    ]
    assert capture_reviewed_command.main(args) == 2
    assert not ignored.exists() and not transcript.exists()

    monkeypatch.setattr(capture_reviewed_command, "BWRAP_EXECUTABLE", tmp_path / "missing-bwrap")
    assert capture_reviewed_command.main(args) == 2
    assert not ignored.exists() and not transcript.exists()


def test_environment_and_sandbox_profiles_are_complete_and_version_bound() -> None:
    environment = _common.REVIEWED_ENVIRONMENT_PROFILE["environment"]
    assert _common.REVIEWED_ENVIRONMENT_PROFILE["conditional_environment"] == {
        "uv": {"VIRTUAL_ENV": "{REPO_ROOT}/packages/gove-zone/.venv-beta"}
    }
    assert _common.REVIEWED_UI_ENVIRONMENT_PROFILE["conditional_environment"] == {
        "fnm": {
            "FNM_DIR": "{TRUSTED_ROOT}/scratch/fnm",
            "COREPACK_HOME": "{TRUSTED_ROOT}/scratch/corepack",
            "PNPM_HOME": "{TRUSTED_ROOT}/scratch/corepack",
            "PNPM_STORE_DIR": "{ISOLATED_ROOT}/pnpm-store",
            "npm_config_cache": "{ISOLATED_ROOT}/npm-cache",
            "npm_config_userconfig": "{TRUSTED_ROOT}/scratch/npmrc",
            "COREPACK_ENABLE_NETWORK": "0",
            "COREPACK_ENABLE_DOWNLOAD_PROMPT": "0",
            "CI": "1",
            "PLAYWRIGHT_BROWSERS_PATH": "{TRUSTED_ROOT}/scratch/playwright",
        }
    }
    assert _common.REVIEWED_HOST_EXECUTABLES == {
        "fnm": Path("/home/martin/.local/share/fnm/fnm"),
        "make": Path("/usr/bin/make"),
        "uv": Path("/home") / "martin" / ".local" / "bin" / "uv",
    }
    assert _common.REVIEWED_HOST_EXECUTABLE_SHA256 == {
        "fnm": "2b8810b610654de6914a17e3235d3948fbd5c7d4712815ac45724c3f06e8966f",
        "uv": "a00d3a24514fc0403fc232c9c99bf5e542657c38f4ed941e0611731e4cff268b",
    }
    assert set(environment) == {
        "PATH",
        "HOME",
        "TMPDIR",
        "TMP",
        "TEMP",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "LANG",
        "LC_ALL",
        "PYTHONNOUSERSITE",
        "PYTHONDONTWRITEBYTECODE",
        "UV_OFFLINE",
        "UV_NO_INDEX",
        "UV_NO_CACHE",
        "UV_PYTHON_DOWNLOADS",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_NOSYSTEM",
        "RUFF_CACHE_DIR",
        "MYPY_CACHE_DIR",
        "PYTEST_DEBUG_TEMPROOT",
        "PYTEST_ADDOPTS",
        "COVERAGE_FILE",
    }
    assert _common.REVIEWED_SANDBOX_PROFILE == {
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
    assert _common.REVIEWED_UI_SANDBOX_PROFILE["name"] == ("acgs-reviewed-command-bwrap/ui-v3")
    assert set(_common.REVIEWED_UI_HOST_SECRET_PATHS) <= set(
        _common.REVIEWED_UI_SANDBOX_PROFILE["masked_paths"]
    )


def test_reviewed_sandbox_masks_ambient_home_credentials(tmp_path: Path) -> None:
    isolated = tmp_path / "isolated"
    ambient_temp_secret = tmp_path / "ambient-token"
    ambient_temp_secret.write_text("must-not-be-visible\n", encoding="utf-8")
    isolated.mkdir()
    command = capture_reviewed_command._sandbox_command(
        _common.BWRAP_EXECUTABLE,
        isolated,
        ROOT,
        ROOT,
        {"PATH": "/usr/bin:/bin", "HOME": str(isolated)},
        [
            "/usr/bin/python3",
            "-c",
            (
                "from pathlib import Path; "
                "assert not Path('/home/martin/.ssh').exists(); "
                f"assert not Path({str(ambient_temp_secret)!r}).exists(); "
                f"assert Path({str(ROOT / 'AGENTS.md')!r}).is_file()"
            ),
        ],
        ("make", "lint-docs"),
    )
    completed = subprocess.run(command, cwd=ROOT, env={}, capture_output=True, check=False)
    assert completed.returncode == 0, completed.stderr
    masked = {command[index + 1] for index, value in enumerate(command) if value == "--tmpfs"}
    assert {"/home", "/root", "/tmp", "/var/tmp", "/run"} <= masked


def test_reviewed_ui_sandbox_masks_host_secret_configuration(tmp_path: Path) -> None:
    isolated = tmp_path / "isolated"
    isolated.mkdir()
    command = capture_reviewed_command._sandbox_command(
        _common.BWRAP_EXECUTABLE,
        isolated,
        ROOT,
        ROOT,
        {"PATH": "/usr/bin:/bin", "HOME": str(isolated)},
        [
            "/usr/bin/python3",
            "-c",
            (
                "from pathlib import Path; "
                "assert Path('/etc/environment').read_bytes() == b''; "
                "assert Path('/etc/profile').read_bytes() == b''; "
                "assert not any(Path('/etc/ssh').iterdir()); "
                "assert Path('/etc/resolv.conf').is_file(); "
                f"assert Path({str(ROOT / 'AGENTS.md')!r}).is_file()"
            ),
        ],
        ("fnm", "exec", "--using", "24.18.0", "--", "pnpm", "lint"),
    )
    completed = subprocess.run(command, cwd=ROOT, env={}, capture_output=True, check=False)
    assert completed.returncode == 0, completed.stderr
    assert command.count("--ro-bind") >= 3
    assert ["--ro-bind", str(isolated / "host-secret-mask"), "/etc/environment"] in [
        command[index : index + 3] for index in range(len(command) - 2)
    ]
    masked = {command[index + 1] for index, value in enumerate(command) if value == "--tmpfs"}
    assert "/etc/ssh" in masked


def test_ui_capture_preserves_p6_shape_and_requires_gates_hashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    node_modules = repo / "acgi-ai/node_modules"
    node_modules.mkdir(parents=True)
    lock = repo / "acgi-ai/pnpm-lock.yaml"
    lock.write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    node = tmp_path / "node"
    pnpm = tmp_path / "pnpm"
    node.write_bytes(b"node")
    pnpm.write_bytes(b"pnpm")

    def fake_capture(
        _version: str, command: str, _cwd: Path, **_kwargs: Any
    ) -> tuple[str, Path, str]:
        path = node if command == "node" else pnpm
        version = "v24.18.0" if command == "node" else "9.15.4"
        return version, path.resolve(), _common.sha256_file(path)

    captured: list[tuple[dict[str, Any], dict[str, Any]]] = []
    monkeypatch.setattr(capture_environment, "_fnm_capture", fake_capture)
    monkeypatch.setattr(
        capture_environment,
        "write_bootstrap_identity_exclusive",
        lambda _marker, _output, values: captured.append(values("1")),
    )
    for node_id in ("P6-CONSOLE-002", "P0-GATES-003"):
        capture_environment._capture_ui(
            "24.18.0", "9.15.4", lock, repo, node_id, tmp_path / f"{node_id}.json"
        )
    p6_marker, p6_identity = captured[0]
    gates_marker, gates_identity = captured[1]
    assert "node_sha256" not in p6_marker and "sha256" not in p6_identity["node"]
    assert gates_marker["node_sha256"] == gates_identity["node"]["sha256"]
    assert gates_marker["pnpm_sha256"] == gates_identity["pnpm"]["sha256"]
    with pytest.raises(_common.EvidenceError, match="UI node identity"):
        validate_environment_identities._validate_ui(p6_identity, repo, require_hashes=True)


def test_ui_identity_schema_accepts_legacy_and_hashed_tool_shapes() -> None:
    run_schema = _json(SCHEMA_ROOT / "acgs-run-evidence-v1.schema.json")
    validator = jsonschema.Draft202012Validator(
        {
            "$schema": run_schema["$schema"],
            "$ref": "#/$defs/toolIdentity",
            "$defs": run_schema["$defs"],
        }
    )
    validator.validate({"version": "24.18.0", "executable": "/owned/node"})
    validator.validate({"version": "24.18.0", "executable": "/owned/node", "sha256": "a" * 64})
    with pytest.raises(jsonschema.ValidationError):
        validator.validate({"version": "24.18.0", "executable": "/owned/node", "sha256": "bad"})


def test_live_gates_validation_rejects_forged_ui_toolchain_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fnm_dir = tmp_path / "scratch/fnm"
    fnm_dir.mkdir(parents=True)
    monkeypatch.setenv("FNM_DIR", str(fnm_dir))
    monkeypatch.setattr(_common, "validate_node_transcript_sequence", lambda *_args: None)
    monkeypatch.setattr(
        _common,
        "reviewed_node_command",
        lambda *_args: ("acgi-ai:local-gate", (*_common._UI_LOCKED_PREFIX, "lint"), "UI"),
    )
    monkeypatch.setattr(capture_reviewed_command, "_ui_toolchain_digest", lambda *_args: "a" * 64)
    executable = _common.REVIEWED_HOST_EXECUTABLES["fnm"]
    sandbox = _common.BWRAP_EXECUTABLE
    command = {
        "executable_sha256": _common.sha256_file(executable),
        "environment_profile_version_sha256": (
            _common.REVIEWED_UI_ENVIRONMENT_PROFILE_VERSION_SHA256
        ),
        "resolved_executable_identity_sha256": _common.resolved_executable_identity(
            ROOT, executable, executable.stat()
        ),
        "sandbox_executable_sha256": _common.sha256_file(sandbox),
        "sandbox_profile_version_sha256": _common.REVIEWED_UI_SANDBOX_PROFILE_VERSION_SHA256,
        "sandbox_resolved_identity_sha256": _common.resolved_executable_identity(
            ROOT, sandbox, sandbox.stat()
        ),
        "ui_toolchain_sha256": "f" * 64,
    }
    with pytest.raises(_common.EvidenceError, match="UI toolchain digest"):
        _common.validate_node_execution_identities(ROOT, "P0-GATES-003", [command])
    command["ui_toolchain_sha256"] = "a" * 64
    _common.validate_node_execution_identities(ROOT, "P0-GATES-003", [command])


def test_ui_composite_binds_installed_node_modules_realization(tmp_path: Path) -> None:
    realization = tmp_path / "node_modules"
    package = realization / "package/index.js"
    package.parent.mkdir(parents=True)
    package.write_text("first\n", encoding="utf-8")
    before = capture_reviewed_command._tree_digest(realization)
    package.write_text("substituted\n", encoding="utf-8")
    assert capture_reviewed_command._tree_digest(realization) != before
    source = inspect.getsource(capture_reviewed_command._ui_toolchain_digest)
    assert '"node_modules": repo / "acgi-ai/node_modules"' in source
    assert (ROOT / "acgi-ai/pnpm-workspace.yaml").read_text(encoding="utf-8") == (
        "packages:\n  - .\n\nonlyBuiltDependencies:\n  - msw\n"
    )
    assert '"pnpm-workspace.yaml"' in source


def test_capture_launcher_rejects_changed_sandbox_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    executable = repo / ".venv-evidence/bin/python"
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    sandbox = tmp_path / "bwrap"
    shutil.copy2("/usr/bin/bwrap", sandbox)
    transcript = tmp_path / "evidence/P0-MEMBRANE-001/transcript.jsonl"
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    monkeypatch.setattr(capture_reviewed_command, "BWRAP_EXECUTABLE", sandbox)
    monkeypatch.setattr(capture_reviewed_command, "assert_evidence_runtime", lambda **_kw: repo)
    monkeypatch.setattr(capture_reviewed_command, "git_root", lambda: repo)
    monkeypatch.setattr(
        capture_reviewed_command,
        "canonical_node_evidence_path",
        lambda *_args, **_kwargs: transcript,
    )
    monkeypatch.setattr(
        capture_reviewed_command, "_require_safe_parent_chain", lambda *_args, **_kwargs: None
    )
    real_run = subprocess.run

    def mutate_sandbox(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        completed = real_run(*args, **kwargs)
        sandbox.write_bytes(sandbox.read_bytes() + b"mutation")
        sandbox.chmod(0o755)
        return completed

    monkeypatch.setattr(capture_reviewed_command.subprocess, "run", mutate_sandbox)
    assert (
        capture_reviewed_command.main(
            [
                "--node",
                "P0-MEMBRANE-001",
                "--index",
                "0",
                "--transcript",
                str(transcript),
                "--temp-root",
                str(runtime),
            ]
        )
        == 2
    )
    assert not transcript.exists()


def _json_line(path: Path) -> dict[str, Any]:
    value = _common.strict_json_loads(path.read_bytes().strip())
    assert isinstance(value, dict)
    return value


def test_real_transcript_to_generate_run_rejects_secret_contexts_without_run_or_echo(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    evidence = _common.evidence_root_from_env(ROOT)
    node = evidence / "P0-EVIDENCE-000"
    identity_bundle = node / "environment-identities.json"
    assert identity_bundle.is_file(), "P0 actual capture/aggregate setup is required"
    transcript = node / "transcript.jsonl"
    output = node / "run.json"
    assert not transcript.exists() and not output.exists()
    product = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    parent = subprocess.run(
        ["git", "rev-parse", "HEAD^"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    monkeypatch.setattr(generate_run, "verify_git_range", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        generate_run, "reject_outer_evidence_in_product", lambda *_args, **_kwargs: None
    )
    args = [
        "--schema",
        str(SCHEMA_ROOT / "acgs-run-evidence-v1.schema.json"),
        "--node",
        "P0-EVIDENCE-000",
        "--parent",
        parent,
        "--product",
        product,
        "--assignment",
        "EVID+CP+GZ",
        "--environment-identities",
        str(identity_bundle),
        "--transcript",
        str(transcript),
        "--output",
        str(output),
    ]
    sentinel = "S3ntinel-Generate-Must-Never-Persist"
    try:
        for unsafe in _unsafe_command_corpus(sentinel):
            transcript.write_text(json.dumps(_transcript_record(unsafe)) + "\n", encoding="utf-8")
            assert generate_run.main(args) == 2
            captured = capsys.readouterr()
            assert sentinel not in captured.out
            assert sentinel not in captured.err
            assert not output.exists()

        transcript.write_text(
            "".join(json.dumps(record) + "\n" for record in _reviewed_p0_records()),
            encoding="utf-8",
        )
        ambient_names = (
            "ACGS_PROCESS_SCHEDULE",
            "ACGS_CLOCK_SOURCE",
            "ACGS_SKIPPED_JSON",
            "ACGS_EXTERNAL_JSON",
        )
        for name in ambient_names:
            monkeypatch.delenv(name, raising=False)
        for name, value in (
            ("ACGS_PROCESS_SCHEDULE", json.dumps([f"env AUTH={sentinel}"])),
            ("ACGS_CLOCK_SOURCE", f"https://user:{sentinel}@example.invalid"),
            ("ACGS_SKIPPED_JSON", json.dumps([{"code": sentinel}])),
            ("ACGS_EXTERNAL_JSON", json.dumps([{"code": sentinel}])),
        ):
            monkeypatch.setenv(name, value)
            assert generate_run.main(args) == 2
            captured = capsys.readouterr()
            assert sentinel not in captured.out and sentinel not in captured.err
            assert not output.exists()
            monkeypatch.delenv(name)

        assert generate_run.main(args) == 0
        capsys.readouterr()
        default_run = _json(output)
        assert default_run["determinism"]["process_schedule"] == ["single-process"]
        assert default_run["clock"]["source"] == "system-utc"
        assert default_run["skipped"] == [] and default_run["external"] == []
        output.unlink()
        for name, value in (
            ("ACGS_PROCESS_SCHEDULE", '["single-process"]'),
            ("ACGS_CLOCK_SOURCE", "system-utc"),
            ("ACGS_SKIPPED_JSON", "[]"),
            ("ACGS_EXTERNAL_JSON", "[]"),
        ):
            monkeypatch.setenv(name, value)
        assert generate_run.main(args) == 0
        capsys.readouterr()
        assert _json(output)["determinism"]["process_schedule"] == ["single-process"]
    finally:
        transcript.unlink(missing_ok=True)
        output.unlink(missing_ok=True)


def test_hash_run_and_both_final_validators_reject_secret_argv_before_schema_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = _bootstrap_key_material(tmp_path)
    evidence = paths["evidence"]
    node = paths["node"]
    _run_custody_preflight(node, evidence)
    trust_path = node / "trust-roots.json"
    _run_evidence(
        "attest.py",
        "trust-manifest",
        "--schema",
        SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
        "--trust-domain",
        "acgs-saas-beta-local",
        "--public-descriptor",
        paths["reviewer_public"],
        "--public-descriptor",
        paths["verifier_public"],
        "--not-before",
        _now(timedelta(minutes=-1)),
        "--not-after",
        _now(timedelta(days=1)),
        "--output",
        trust_path,
        evidence_root=evidence,
    )
    (node / "trust-roots.sha256").write_text(
        f"{hashlib.sha256(trust_path.read_bytes()).hexdigest()}  trust-roots.json\n",
        encoding="ascii",
    )

    claims_root = (tmp_path / "private/claims-reviewer").resolve()
    claims_root.mkdir(mode=0o700)
    claims_root.chmod(0o700)
    custody = node / "custody-inputs"
    _run_evidence(
        "attest.py",
        "keygen",
        "--root-schema",
        SCHEMA_ROOT / "acgs-private-root-descriptor-v1.schema.json",
        "--algorithm",
        "ed25519",
        "--role",
        "claims-reviewer",
        "--principal",
        "independent-claims-reviewer",
        "--private-key",
        claims_root / "claims-reviewer.ed25519",
        "--public-descriptor",
        custody / "claims-reviewer-public.json",
        "--canonical-private-root",
        claims_root,
        "--root-descriptor",
        custody / "claims-reviewer-root.json",
        evidence_root=evidence,
    )
    _run_custody_preflight(node, evidence, ("reviewer", "verifier", "claims-reviewer"))
    claims_trust_path = node / "claims-trust-roots.json"
    _run_evidence(
        "attest.py",
        "trust-manifest",
        "--schema",
        SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json",
        "--trust-domain",
        "acgs-saas-beta-local",
        "--public-descriptor",
        custody / "claims-reviewer-public.json",
        "--not-before",
        _now(timedelta(minutes=-1)),
        "--not-after",
        _now(timedelta(days=1)),
        "--output",
        claims_trust_path,
        evidence_root=evidence,
    )
    (node / "claims-trust-roots.sha256").write_text(
        f"{hashlib.sha256(claims_trust_path.read_bytes()).hexdigest()}  claims-trust-roots.json\n",
        encoding="ascii",
    )

    monkeypatch.setenv("ACGS_EVIDENCE_ROOT", str(evidence))
    sentinel = "S3ntinel-Consumers-Must-Never-Echo"
    run_path = node / "run.json"
    monkeypatch.setattr(hash_run_jcs, "assert_evidence_runtime", lambda **_: ROOT)
    monkeypatch.setattr(validate_run, "assert_evidence_runtime", lambda **_: ROOT)
    monkeypatch.setattr(validate_run, "git_root", lambda: ROOT)
    for name in ("review-attestation.json", "verification-attestation.json"):
        (node / name).write_text("{}\n", encoding="utf-8")
    claims_attestation = node / "claims-review-attestation.json"
    claims_attestation.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(validate_attestations, "assert_evidence_runtime", lambda **_: ROOT)
    output = node / "attestation-validation.json"
    claims_output = node / "claims-attestation-validation.json"
    validate_run_args = [
        "--schema",
        str(SCHEMA_ROOT / "acgs-run-evidence-v1.schema.json"),
        "--expected-node",
        node.name,
        "--assignment-map",
        str(LOCK_ROOT / "bootstrap-by-scope.json"),
        "--expected-environments",
        "EVID+CP+GZ",
        "--expected-parent",
        "1" * 40,
        "--expected-product",
        "2" * 40,
        str(run_path),
    ]
    node_final_args = [
        "--mode",
        "node-pair",
        "--schema",
        str(SCHEMA_ROOT / "acgs-attestation-v1.schema.json"),
        "--trust-schema",
        str(SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json"),
        "--expected-parent",
        "1" * 40,
        "--expected-product",
        "2" * 40,
        "--expected-run-hash",
        "3" * 64,
        "--review",
        str(node / "review-attestation.json"),
        "--verification",
        str(node / "verification-attestation.json"),
        "--trust-roots",
        str(trust_path),
        "--require-distinct-principals",
        "--require-distinct-key-ids",
        "--forbid-principal",
        "node-author",
        "--output",
        str(output),
    ]
    claims_final_args = [
        "--mode",
        "claims-review",
        "--schema",
        str(SCHEMA_ROOT / "acgs-attestation-v1.schema.json"),
        "--trust-schema",
        str(SCHEMA_ROOT / "acgs-attestation-trust-v1.schema.json"),
        "--expected-parent",
        "1" * 40,
        "--expected-product",
        "2" * 40,
        "--expected-run-hash",
        "3" * 64,
        "--claims-review",
        str(claims_attestation),
        "--trust-roots",
        str(claims_trust_path),
        "--forbid-principal",
        "claims-author",
        "--forbid-principal",
        "independent-reviewer",
        "--forbid-principal",
        "independent-verifier",
        "--output",
        str(claims_output),
    ]

    def assert_all_consumers_reject(run: dict[str, Any]) -> None:
        run_path.write_text(json.dumps(run) + "\n", encoding="utf-8")
        assert hash_run_jcs.main([str(run_path)]) == 2
        captured = capsys.readouterr()
        assert sentinel not in captured.out and sentinel not in captured.err
        assert validate_run.main(validate_run_args) == 2
        captured = capsys.readouterr()
        assert sentinel not in captured.out and sentinel not in captured.err
        assert validate_attestations.main(node_final_args) == 2
        captured = capsys.readouterr()
        assert sentinel not in captured.out and sentinel not in captured.err
        assert not output.exists()
        assert validate_attestations.main(claims_final_args) == 2
        captured = capsys.readouterr()
        assert sentinel not in captured.out and sentinel not in captured.err
        assert not claims_output.exists()

    for unsafe in _unsafe_command_corpus(sentinel):
        assert_all_consumers_reject({"commands": [_transcript_record(unsafe)]})

    closed = {
        "node_id": node.name,
        "commands": _reviewed_p0_records(),
        "determinism": {
            "seed": 20260710,
            "python_hash_seed": "0",
            "process_schedule": ["single-process"],
        },
        "clock": {"source": "system-utc", "skew_ms": 0},
        "skipped": [],
        "external": [],
    }
    mutations: list[dict[str, Any]] = []
    for field, value in (
        ("process_schedule", [f"env AUTH={sentinel}"]),
        ("clock_source", f"https://user:{sentinel}@example.invalid"),
        ("skipped", [{"code": sentinel}]),
        ("external", [{"code": sentinel}]),
    ):
        mutated = copy.deepcopy(closed)
        if field == "process_schedule":
            mutated["determinism"][field] = value
        elif field == "clock_source":
            mutated["clock"]["source"] = value
        else:
            mutated[field] = value
        mutations.append(mutated)
    for container in ("determinism", "clock"):
        mutated = copy.deepcopy(closed)
        mutated[container]["unreviewed"] = sentinel
        mutations.append(mutated)
    for mutated in mutations:
        assert_all_consumers_reject(mutated)


def test_environment_identities_exactly_match_assignment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    committed = validate_environment_identities._load_assignment_map(
        LOCK_ROOT / "bootstrap-by-scope.json"
    )
    assert committed == _common.EXPECTED_BOOTSTRAP_MAP
    assert set(_common.assignment_tokens(committed["P0-EVIDENCE-000"])) == {"EVID", "CP", "GZ"}
    assert set(_common.assignment_tokens(committed["P6-CONSOLE-002"])) == {"EVID", "UI"}
    mutated = dict(committed)
    mutated["P0-MEMBRANE-001"] = "EVID+CP+GZ"
    path = tmp_path / "map.json"
    path.write_text(json.dumps(mutated), encoding="utf-8")
    with pytest.raises(_common.EvidenceError, match="exact reviewed"):
        validate_environment_identities._load_assignment_map(path)

    evidence_root = _common.evidence_root_from_env(ROOT)
    node = evidence_root / "P0-EVIDENCE-000"
    for code in ("EVID", "CP", "GZ"):
        identity_path = node / f"environment-{code}.json"
        identity = _json(identity_path)
        validate_environment_identities._validate_marker(
            code, identity, identity_path, "P0-EVIDENCE-000", ROOT
        )
        _, locked = validate_environment_identities._validate_lock(code, identity, ROOT)
        if code == "EVID":
            validate_environment_identities._validate_evid(identity, locked, ROOT)
            forged = copy.deepcopy(identity)
            forged["interpreter_realpath"] = str(tmp_path / "nonexistent-python")
            with pytest.raises((OSError, _common.EvidenceError)):
                validate_environment_identities._validate_evid(forged, locked, ROOT)
        else:
            validate_environment_identities._validate_python_product(code, identity, locked, ROOT)
            forged = copy.deepcopy(identity)
            forged["python_version"] = "3.11.0-forged"
            with pytest.raises(_common.EvidenceError, match=r"live sys\.prefix"):
                validate_environment_identities._validate_python_product(code, forged, locked, ROOT)
        stale_lock = copy.deepcopy(identity)
        stale_lock["lock"]["sha256"] = "0" * 64
        with pytest.raises(_common.EvidenceError, match="lock path/hash"):
            validate_environment_identities._validate_lock(code, stale_lock, ROOT)

    ui_repo = tmp_path / "ui-repo"
    node_modules = ui_repo / "acgi-ai/node_modules"
    node_modules.mkdir(parents=True)
    node_executable = tmp_path / "node"
    pnpm_executable = tmp_path / "pnpm"
    node_executable.write_text("node", encoding="utf-8")
    pnpm_executable.write_text("pnpm", encoding="utf-8")
    monkeypatch.setattr(
        validate_environment_identities,
        "_fnm_probe",
        lambda command, repo: (
            ("v24.18.0", node_executable.resolve())
            if command == "node"
            else ("9.15.4", pnpm_executable.resolve())
        ),
    )
    ui_identity = {
        "node": {
            "version": "24.18.0",
            "executable": str(node_executable.resolve()),
            "sha256": _common.sha256_file(node_executable),
        },
        "pnpm": {
            "version": "9.15.4",
            "executable": str(pnpm_executable.resolve()),
            "sha256": _common.sha256_file(pnpm_executable),
        },
        "module_root": str(node_modules.resolve()),
    }
    validate_environment_identities._validate_ui(ui_identity, ui_repo)
    forged_ui = copy.deepcopy(ui_identity)
    forged_ui["node"]["executable"] = str(tmp_path / "nonexistent-node")
    with pytest.raises(_common.EvidenceError, match="live executable"):
        validate_environment_identities._validate_ui(forged_ui, ui_repo)

    fake_lock = ui_repo / "acgi-ai/pnpm-lock.yaml"
    fake_lock.write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    marker_path = node_modules / ".acgs-product-bootstrap.json"
    identity_path = tmp_path / "environment-UI.json"
    lock_digest = _common.sha256_file(fake_lock)

    def marker_values(runtime_ctime_ns: str) -> tuple[dict[str, Any], dict[str, Any]]:
        marker = {
            "schema_version": "acgs-bootstrap-record/v1",
            "node_id": "P6-CONSOLE-002",
            "code": "UI",
            "captured_at_utc": _now(),
            "runtime_root": str(node_modules.resolve()),
            "interpreter": str(node_executable.resolve()),
            "interpreter_realpath": str(node_executable.resolve()),
            "node_version": "24.18.0",
            "pnpm_executable": str(pnpm_executable.resolve()),
            "pnpm_version": "9.15.4",
            "runtime_ctime_ns": runtime_ctime_ns,
            "lock_sha256": lock_digest,
            "nonce": "a" * 64,
        }
        identity = {
            "lock": {"sha256": lock_digest},
            "node": ui_identity["node"],
            "pnpm": ui_identity["pnpm"],
            "bootstrap_record": marker,
        }
        return marker, identity

    _common.write_bootstrap_identity_exclusive(marker_path, identity_path, marker_values)
    captured = _json(identity_path)
    validate_environment_identities._validate_marker(
        "UI", captured, identity_path, "P6-CONSOLE-002", ui_repo
    )
    assert captured["bootstrap_record"]["runtime_ctime_ns"] == str(node_modules.stat().st_ctime_ns)
    for malformed, message in (
        (node_modules.stat().st_ctime_ns, "interoperable range"),
        (1, "canonical positive decimal"),
        ("0", "canonical positive decimal"),
        ("01", "canonical positive decimal"),
        ("+1", "canonical positive decimal"),
        ("-1", "canonical positive decimal"),
        (" 1", "canonical positive decimal"),
        ("\N{ARABIC-INDIC DIGIT ONE}", "canonical positive decimal"),
        ("1" * 33, "canonical positive decimal"),
    ):
        forged_ctime = copy.deepcopy(captured)
        forged_ctime["bootstrap_record"]["runtime_ctime_ns"] = malformed
        marker_path.write_text(
            json.dumps(forged_ctime["bootstrap_record"]) + "\n", encoding="utf-8"
        )
        identity_path.write_text(json.dumps(forged_ctime) + "\n", encoding="utf-8")
        with pytest.raises(_common.EvidenceError, match=message):
            validate_environment_identities._validate_marker(
                "UI", forged_ctime, identity_path, "P6-CONSOLE-002", ui_repo
            )
    marker_path.write_text(json.dumps(captured["bootstrap_record"]) + "\n", encoding="utf-8")
    identity_path.write_text(json.dumps(captured) + "\n", encoding="utf-8")
    (node_modules / "ctime-drift").write_text("drift", encoding="utf-8")
    with pytest.raises(_common.EvidenceError, match="ctime changed"):
        validate_environment_identities._validate_marker(
            "UI", captured, identity_path, "P6-CONSOLE-002", ui_repo
        )


def test_actual_p0_capture_reaggregates_generates_and_reaches_final_run_validation(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    evidence = _common.evidence_root_from_env(ROOT)
    node = evidence / "P0-EVIDENCE-000"
    for name in (
        "environment-EVID.json",
        "environment-CP.json",
        "environment-GZ.json",
        "environment-identities.json",
    ):
        assert (node / name).is_file(), f"actual P0 capture setup is missing {name}"
    actual_bundle = _json(node / "environment-identities.json")
    regenerated: dict[str, Any] = {}

    def capture_aggregate(path: Path, value: Any, **_kwargs: Any) -> None:
        regenerated["path"] = path
        regenerated["value"] = value

    monkeypatch.setattr(validate_environment_identities, "write_json_exclusive", capture_aggregate)
    aggregate_args = [
        "--node",
        node.name,
        "--assignment-map",
        str(LOCK_ROOT / "bootstrap-by-scope.json"),
        "--assignment",
        "EVID+CP+GZ",
        "--identity-dir",
        str(node),
        "--require-fresh-bootstrap-records",
        "--reject-missing",
        "--reject-extra",
        "--reject-unassigned-runtime-paths",
        "--output",
        str(node / "environment-identities.json"),
    ]
    assert validate_environment_identities.main(aggregate_args) == 0
    assert regenerated == {
        "path": node / "environment-identities.json",
        "value": actual_bundle,
    }
    capsys.readouterr()

    transcript = node / "transcript.jsonl"
    output = node / "run.json"
    assert not transcript.exists() and not output.exists()
    _write_reviewed_p0_transcript(transcript)
    product = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    parent = subprocess.run(
        ["git", "rev-parse", "HEAD^"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    for module in (generate_run, validate_run):
        monkeypatch.setattr(module, "verify_git_range", lambda *_args, **_kwargs: None)
        monkeypatch.setattr(
            module, "reject_outer_evidence_in_product", lambda *_args, **_kwargs: None
        )
    generate_args = [
        "--schema",
        str(SCHEMA_ROOT / "acgs-run-evidence-v1.schema.json"),
        "--node",
        node.name,
        "--parent",
        parent,
        "--product",
        product,
        "--assignment",
        "EVID+CP+GZ",
        "--environment-identities",
        str(node / "environment-identities.json"),
        "--transcript",
        str(transcript),
        "--output",
        str(output),
    ]
    try:
        monkeypatch.setenv("ACGS_TEST_SEED", str(_common.JSON_SAFE_INTEGER_MAX + 1))
        assert generate_run.main(generate_args) == 2
        assert not output.exists()
        capsys.readouterr()
        monkeypatch.setenv("ACGS_TEST_SEED", str(_common.JSON_SAFE_INTEGER_MAX))
        monkeypatch.setenv("ACGS_CLOCK_SKEW_MS", str(-_common.JSON_SAFE_INTEGER_MAX - 1))
        assert generate_run.main(generate_args) == 2
        assert not output.exists()
        capsys.readouterr()
        monkeypatch.setenv("ACGS_CLOCK_SKEW_MS", str(-_common.JSON_SAFE_INTEGER_MAX))
        assert generate_run.main(generate_args) == 0
        assert (
            validate_run.main(
                [
                    "--schema",
                    str(SCHEMA_ROOT / "acgs-run-evidence-v1.schema.json"),
                    "--expected-node",
                    node.name,
                    "--assignment-map",
                    str(LOCK_ROOT / "bootstrap-by-scope.json"),
                    "--expected-environments",
                    "EVID+CP+GZ",
                    "--expected-parent",
                    parent,
                    "--expected-product",
                    product,
                    str(output),
                ]
            )
            == 0
        )
        run = _json(output)
        assert run["determinism"]["seed"] == _common.JSON_SAFE_INTEGER_MAX
        assert run["determinism"]["process_schedule"] == ["single-process"]
        assert run["clock"]["source"] == "system-utc"
        assert run["clock"]["skew_ms"] == -_common.JSON_SAFE_INTEGER_MAX
        assert run["skipped"] == [] and run["external"] == []
        assert set(run["environment_identities"]) == {"EVID", "CP", "GZ"}
        _common.validate_p0_transcript_sequence(run["commands"])
        for code in ("EVID", "CP", "GZ"):
            marker = run["environment_identities"][code]["bootstrap_record"]
            runtime_ctime_ns = marker["runtime_ctime_ns"]
            assert _common.CANONICAL_POSITIVE_DECIMAL_RE.fullmatch(runtime_ctime_ns)
            assert runtime_ctime_ns == str(Path(marker["runtime_root"]).stat().st_ctime_ns)
            assert {
                "interpreter_realpath",
                "python_version",
                "python_implementation",
            }.issubset(marker)
        assert "RUN_VALIDATION=PASS" in capsys.readouterr().out
        assert hash_run_jcs.main([str(output)]) == 0
        run_hash = capsys.readouterr().out.strip()
        assert _common.SHA256_RE.fullmatch(run_hash)
        assert run_hash == hashlib.sha256(_common.jcs_bytes(run)).hexdigest()

        claims_node = evidence / "P0-CLAIMS-002"
        claims_node.mkdir(exist_ok=True)
        forged_claims = copy.deepcopy(run)
        forged_claims["node_id"] = "P0-CLAIMS-002"
        forged_claims_path = claims_node / "run.json"
        forged_claims_path.write_text(json.dumps(forged_claims) + "\n", encoding="utf-8")
        jsonschema.validate(forged_claims, _json(SCHEMA_ROOT / "acgs-run-evidence-v1.schema.json"))
        assert (
            validate_run.main(
                [
                    "--schema",
                    str(SCHEMA_ROOT / "acgs-run-evidence-v1.schema.json"),
                    "--expected-node",
                    "P0-CLAIMS-002",
                    "--assignment-map",
                    str(LOCK_ROOT / "bootstrap-by-scope.json"),
                    "--expected-environments",
                    "EVID+CP+GZ",
                    "--expected-parent",
                    parent,
                    "--expected-product",
                    product,
                    str(forged_claims_path),
                ]
            )
            == 2
        )
        assert "command record is outside the reviewed closed contract" in capsys.readouterr().err
        assert not (claims_node / "validation-success.json").exists()
        forged_claims_path.unlink()

        membrane_node = evidence / "P0-MEMBRANE-001"
        membrane_node.mkdir(exist_ok=True)
        forged_membrane = copy.deepcopy(run)
        forged_membrane["node_id"] = "P0-MEMBRANE-001"
        forged_membrane["assignment"] = "EVID+CP"
        forged_membrane["commands"] = _reviewed_node_records("P0-MEMBRANE-001")
        forged_membrane["commands"][0], forged_membrane["commands"][1] = (
            forged_membrane["commands"][1],
            forged_membrane["commands"][0],
        )
        forged_membrane["selectors"] = list(
            dict.fromkeys(command["selectors"][0] for command in forged_membrane["commands"])
        )
        forged_membrane_path = membrane_node / "run.json"
        forged_membrane_path.write_text(json.dumps(forged_membrane) + "\n", encoding="utf-8")
        jsonschema.validate(
            forged_membrane, _json(SCHEMA_ROOT / "acgs-run-evidence-v1.schema.json")
        )
        assert (
            validate_run.main(
                [
                    "--schema",
                    str(SCHEMA_ROOT / "acgs-run-evidence-v1.schema.json"),
                    "--expected-node",
                    "P0-MEMBRANE-001",
                    "--assignment-map",
                    str(LOCK_ROOT / "bootstrap-by-scope.json"),
                    "--expected-environments",
                    "EVID+CP",
                    "--expected-parent",
                    parent,
                    "--expected-product",
                    product,
                    str(forged_membrane_path),
                ]
            )
            == 2
        )
        assert not (membrane_node / "validation-success.json").exists()
        forged_membrane_path.unlink()
    finally:
        output.unlink(missing_ok=True)
        transcript.unlink(missing_ok=True)


def test_actual_p6_evid_ui_capture_aggregate_generate_and_final_validation(
    tmp_path: Path,
) -> None:
    product_repo = (tmp_path / "p6-product").resolve()
    product_repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=product_repo, check=True)
    subprocess.run(["git", "config", "user.name", "P6 Evidence Test"], cwd=product_repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "p6-evidence@example.invalid"],
        cwd=product_repo,
        check=True,
    )
    (product_repo / "base.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "base.txt"], cwd=product_repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=product_repo, check=True)
    parent = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=product_repo,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()

    shutil.copytree(
        LOCK_ROOT,
        product_repo / "requirements/saas-beta",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    shutil.copytree(
        SCHEMA_ROOT,
        product_repo / "schemas/evidence",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    shutil.copytree(
        EVIDENCE_SCRIPTS,
        product_repo / "scripts/evidence",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    (product_repo / "acgi-ai").mkdir()
    shutil.copy2(ROOT / "acgi-ai/pnpm-lock.yaml", product_repo / "acgi-ai/pnpm-lock.yaml")
    (product_repo / ".gitignore").write_text(
        ".venv-evidence/\nacgi-ai/node_modules/\n", encoding="utf-8"
    )
    subprocess.run(
        [
            "git",
            "add",
            ".gitignore",
            "requirements",
            "schemas",
            "scripts",
            "acgi-ai/pnpm-lock.yaml",
        ],
        cwd=product_repo,
        check=True,
    )
    subprocess.run(["git", "commit", "-qm", "P6 evidence substrate"], cwd=product_repo, check=True)
    product = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=product_repo,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    assert parent != product

    shutil.copytree(
        ROOT / ".venv-evidence",
        product_repo / ".venv-evidence",
        symlinks=True,
        ignore=shutil.ignore_patterns(".acgs-evidence-bootstrap.json", "__pycache__", "*.pyc"),
    )
    (product_repo / "acgi-ai/node_modules").mkdir()
    evidence = (tmp_path / "p6-evidence").resolve()
    node = evidence / "P6-CONSOLE-002"
    node.mkdir(parents=True)
    evidence_python = product_repo / ".venv-evidence/bin/python"
    env = _evidence_env(evidence)
    fnm = shutil.which("fnm")
    assert fnm is not None
    node_executable = Path(
        subprocess.run(
            [fnm, "exec", "--using", "24.18.0", "--", "which", "node"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
    ).resolve(strict=True)
    corepack = node_executable.with_name("corepack").resolve(strict=True)
    ui_tool_bin = tmp_path / "ui-tool-bin"
    ui_tool_bin.mkdir()
    pnpm_wrapper = ui_tool_bin / "pnpm"
    pnpm_wrapper.write_text(
        f'#!/usr/bin/env bash\nexec "{corepack}" pnpm@9.15.4 "$@"\n',
        encoding="utf-8",
    )
    pnpm_wrapper.chmod(0o755)
    env["PATH"] = f"{ui_tool_bin}:{env['PATH']}"
    env["COREPACK_ENABLE_DOWNLOAD_PROMPT"] = "0"

    def run_script(
        script: str, *args: str | Path, expected: int = 0
    ) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [
                str(evidence_python),
                str(product_repo / "scripts/evidence" / script),
                *(str(value) for value in args),
            ],
            cwd=product_repo,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        assert completed.returncode == expected, (script, completed.stdout, completed.stderr)
        return completed

    run_script(
        "verify_environment.py",
        "--code",
        "EVID",
        "--lock",
        product_repo / "requirements/saas-beta/evidence-test.lock",
        "--expected-interpreter",
        evidence_python,
        "--expected-python",
        "3.11",
        "--expected-uv",
        "0.11.19",
        "--expected-uv-executable",
        "/home/martin/.local/bin/uv",
        "--require-module-root",
        product_repo / ".venv-evidence",
        "--require",
        "rfc8785==0.1.4",
        "--require",
        "cryptography>=42",
        "--require",
        "jsonschema",
        "--require",
        "pytest",
        "--output",
        node / "environment-EVID.json",
    )
    run_script(
        "capture_environment.py",
        "--code",
        "UI",
        "--lock",
        product_repo / "acgi-ai/pnpm-lock.yaml",
        "--node-version",
        "24.18.0",
        "--pnpm-version",
        "9.15.4",
        "--output",
        node / "environment-UI.json",
    )
    run_script(
        "validate_environment_identities.py",
        "--node",
        node.name,
        "--assignment-map",
        product_repo / "requirements/saas-beta/bootstrap-by-scope.json",
        "--assignment",
        "EVID+UI",
        "--identity-dir",
        node,
        "--require-fresh-bootstrap-records",
        "--reject-missing",
        "--reject-extra",
        "--reject-unassigned-runtime-paths",
        "--output",
        node / "environment-identities.json",
    )
    safe_selector, reviewed_argv = _common.REVIEWED_P0_TRANSCRIPT[0]
    safe_argv = list(reviewed_argv)
    _common.append_safe_transcript_record(
        node / "transcript.jsonl",
        _transcript_record(safe_argv, safe_selector),
    )
    rejected = run_script(
        "generate_run.py",
        "--schema",
        product_repo / "schemas/evidence/acgs-run-evidence-v1.schema.json",
        "--node",
        node.name,
        "--parent",
        parent,
        "--product",
        product,
        "--assignment",
        "EVID+UI",
        "--environment-identities",
        node / "environment-identities.json",
        "--transcript",
        node / "transcript.jsonl",
        "--output",
        node / "run.json",
        expected=2,
    )
    assert "node lacks reviewed transcript corpus" in rejected.stderr
    assert not (node / "run.json").exists()
    assert (
        subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=product_repo,
            text=True,
            capture_output=True,
            check=True,
        ).stdout
        == ""
    )


def test_missing_extra_or_retained_environment_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ACGS_EVIDENCE_ROOT", str(tmp_path))
    identity_dir = tmp_path / "P6-CONSOLE-002"
    identity_dir.mkdir()
    monkeypatch.setattr(
        validate_environment_identities,
        "_runtime_path",
        lambda code, repo: tmp_path / f"runtime-{code}",
    )
    common = [
        "--node",
        "P6-CONSOLE-002",
        "--assignment-map",
        str(LOCK_ROOT / "bootstrap-by-scope.json"),
        "--assignment",
        "EVID+UI",
        "--identity-dir",
        str(identity_dir),
        "--require-fresh-bootstrap-records",
        "--reject-missing",
        "--reject-extra",
        "--reject-unassigned-runtime-paths",
        "--output",
        str(identity_dir / "environment-identities.json"),
    ]
    assert validate_environment_identities.main(common) == 2
    for code in ("EVID", "UI"):
        (identity_dir / f"environment-{code}.json").write_text("{}\n", encoding="utf-8")
    (identity_dir / "environment-CP.json").write_text("{}\n", encoding="utf-8")
    assert validate_environment_identities.main(common) == 2
    (identity_dir / "environment-CP.json").unlink()
    retained = tmp_path / "runtime-CP"
    retained.mkdir()
    assert validate_environment_identities.main(common) == 2

    for code in ("EVID", "CP", "GZ", "UI"):
        runtime = tmp_path / f"transaction-{code}"
        runtime.mkdir()
        marker = runtime / (
            ".acgs-evidence-bootstrap.json" if code == "EVID" else ".acgs-product-bootstrap.json"
        )
        output = tmp_path / f"transaction-output-{code}.json"

        def values(
            runtime_ctime_ns: str,
            runtime_path: Path = runtime,
            captured_code: str = code,
        ) -> tuple[dict[str, Any], dict[str, Any]]:
            assert runtime_ctime_ns == str(runtime_path.stat().st_ctime_ns)
            marker_value = {"code": captured_code, "runtime_ctime_ns": runtime_ctime_ns}
            return marker_value, {"bootstrap_record": marker_value}

        output.write_text("existing\n", encoding="utf-8")
        with pytest.raises(_common.EvidenceError, match="refusing to overwrite"):
            _common.write_bootstrap_identity_exclusive(marker, output, values)
        assert not marker.exists() and output.read_text(encoding="utf-8") == "existing\n"
        output.unlink()
        output.symlink_to(tmp_path / f"absent-{code}")
        with pytest.raises(_common.EvidenceError, match="refusing to overwrite"):
            _common.write_bootstrap_identity_exclusive(marker, output, values)
        assert not marker.exists() and output.is_symlink()
        output.unlink()

        with monkeypatch.context() as context:
            context.setattr(
                _common,
                "write_json_exclusive",
                lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    OSError("injected final identity write failure")
                ),
            )
            with pytest.raises(_common.EvidenceError, match="publication failed"):
                _common.write_bootstrap_identity_exclusive(marker, output, values)
        assert not marker.exists() and not output.exists()


def test_pep660_helpers_required_for_assigned_python_scopes(tmp_path: Path) -> None:
    for code, lock_name, input_name in (
        ("CP", "cp-test.lock", "cp-test.in"),
        ("GZ", "gz-test.lock", "gz-test.in"),
    ):
        entries = _common.parse_lock(LOCK_ROOT / lock_name)
        assert entries["editables"]["version"] == "0.6"
        assert entries["editables"]["artifact_hashes"]
        assert "hatchling" in entries and entries["hatchling"]["artifact_hashes"]
        input_text = (LOCK_ROOT / input_name).read_text(encoding="utf-8")
        assert input_text.count("editables==0.6") == 1
        assert "hatchling" in input_text.lower()
        assert 'config[code]["pep660_editable_build"]' not in input_text
        capture_environment._validate_pep660_lock_contract(code, entries, "0.6")

        mutations: list[dict[str, dict[str, Any]]] = []
        for target, field, value in (
            ("editables", "remove", None),
            ("editables", "version", "0.7"),
            ("editables", "artifact_hashes", []),
            ("hatchling", "remove", None),
            ("hatchling", "artifact_hashes", []),
        ):
            mutated = copy.deepcopy(entries)
            if field == "remove":
                mutated.pop(target)
            else:
                mutated[target][field] = value
            mutations.append(mutated)
        for index, mutated in enumerate(mutations):
            side_effect = tmp_path / f"{code}-downstream-{index}"

            def precheck_then_downstream(
                captured_code: str = code,
                candidate: dict[str, dict[str, Any]] = mutated,
                destination: Path = side_effect,
            ) -> None:
                capture_environment._validate_pep660_lock_contract(captured_code, candidate, "0.6")
                destination.write_text("downstream reached", encoding="utf-8")

            with pytest.raises(_common.EvidenceError, match="hashed"):
                precheck_then_downstream()
            assert not side_effect.exists()

        interpreter_rel, _ = _common.CODE_PATHS[code]
        runtime = (ROOT / interpreter_rel).parents[1].resolve(strict=True)
        observed = capture_environment._run_target(ROOT / interpreter_rel)
        for module_name in ("editables", "hatchling"):
            module = observed["modules"][module_name]
            assert Path(module["path"]).resolve(strict=True).is_relative_to(runtime)
        assert observed["modules"]["editables"]["version"] == "0.6"

        for mutation in ("helper", "backend"):
            config = _copy_config_repo(tmp_path / f"{code}-{mutation}")
            text = config.read_text(encoding="utf-8")
            start = text.index(f"[{code}]")
            end = text.find("\n[", start + 1)
            end = len(text) if end == -1 else end
            section = text[start:end]
            section = (
                section.replace('pep660_editable_build = ["editables==0.6"]\n', "")
                if mutation == "helper"
                else section.replace("hatchling.build", "dynamic.backend")
            )
            config.write_text(text[:start] + section + text[end:], encoding="utf-8")
            output = (tmp_path / f"{code}-{mutation}-output").resolve()
            with pytest.raises(render_lock_inputs.ConfigError):
                render_lock_inputs.render(config, output)
            assert not output.exists()


def test_evidence_script_runner_rejects_product_system_and_relative_interpreters() -> None:
    valid = str(ROOT / ".venv-evidence/bin/python")
    base = {"commands": [{"argv": [valid, "scripts/evidence/hash_run_jcs.py", "/tmp/run.json"]}]}
    validate_run._reject_product_evidence_runners(base, ROOT)
    runners = (
        str(ROOT / "packages/acgs-control-plane/.venv/bin/python"),
        str(ROOT / "packages/gove-zone/.venv-beta/bin/python"),
        sys.base_prefix + "/bin/python3",
        "python3",
    )
    for runner in runners:
        run = {
            "commands": [{"argv": [runner, "scripts/evidence/hash_run_jcs.py", "/tmp/run.json"]}]
        }
        with pytest.raises((_common.EvidenceError, FileNotFoundError)):
            validate_run._reject_product_evidence_runners(run, ROOT)


def test_schema_rejects_extra_fields_mode_role_mismatch_and_noncanonical_values() -> None:
    schema = _json(SCHEMA_ROOT / "acgs-attestation-v1.schema.json")
    validator = jsonschema.Draft202012Validator(schema)
    valid = {
        "schema_version": "acgs-attestation/v1",
        "algorithm": "Ed25519",
        "mode": "node-review",
        "key_id": "ed25519:sha256:" + "0" * 64,
        "role": "reviewer",
        "principal": "reviewer-a",
        "parent_commit_sha": "1" * 40,
        "product_commit_sha": "2" * 40,
        "run_hash": "3" * 64,
        "verdict": "approve",
        "timestamp_utc": "2026-07-10T00:00:00Z",
        "signature": "A" * 86,
    }
    validator.validate(valid)
    for field, value in (
        ("role", "verifier"),
        ("algorithm", "RSA"),
        ("parent_commit_sha", "A" * 40),
        ("run_hash", "A" * 64),
        ("timestamp_utc", "2026-07-10T00:00:00+00:00"),
        ("signature", "A" * 86 + "="),
    ):
        mutated = {**valid, field: value}
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(mutated)
    with pytest.raises(jsonschema.ValidationError):
        validator.validate({**valid, "extra": True})


def test_clean_sibling_snapshot_binds_caller_entries(tmp_path: Path) -> None:
    snapshot_script = EVIDENCE_SCRIPTS / "clean_sibling_cleanup.sh"

    def caller_snapshot(directory: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "bash",
                "-c",
                (
                    'source "$1"; exec {fd}<"$2"; '
                    'identity="$(stat -Lc \'%d:%i:%u:%a\' -- "/proc/$$/fd/$fd")"; '
                    'clean_sibling_snapshot_direct_entries "$fd" "$identity" "$2"'
                ),
                "_",
                str(snapshot_script),
                str(directory),
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    snapshot_root = tmp_path / "caller-snapshot"
    snapshot_root.mkdir(mode=0o700)
    regular = snapshot_root / "existing\nraw-name"
    regular.write_bytes(b"before\x00bytes")
    regular.chmod(0o600)
    nested = snapshot_root / "nested"
    nested.mkdir(mode=0o700)
    nested_file = nested / "child\tname"
    nested_file.write_bytes(b"nested-before")
    link = snapshot_root / "link"
    link.symlink_to(regular.name)
    baseline = caller_snapshot(snapshot_root)
    assert baseline.returncode == 0, baseline.stderr
    assert len(baseline.stdout.strip()) == 64

    regular.write_bytes(b"after\x00bytes")
    bytes_changed = caller_snapshot(snapshot_root)
    assert bytes_changed.returncode == 0
    assert bytes_changed.stdout != baseline.stdout
    regular.write_bytes(b"before\x00bytes")

    baseline = caller_snapshot(snapshot_root)
    regular.chmod(0o640)
    mode_changed = caller_snapshot(snapshot_root)
    assert mode_changed.returncode == 0
    assert mode_changed.stdout != baseline.stdout
    regular.chmod(0o600)

    baseline = caller_snapshot(snapshot_root)
    link.unlink()
    link.symlink_to(nested.name)
    target_changed = caller_snapshot(snapshot_root)
    assert target_changed.returncode == 0
    assert target_changed.stdout != baseline.stdout
    link.unlink()
    link.symlink_to(regular.name)

    baseline = caller_snapshot(snapshot_root)
    nested_file.write_bytes(b"nested-after")
    nested_changed = caller_snapshot(snapshot_root)
    assert nested_changed.returncode == 0
    assert nested_changed.stdout != baseline.stdout
    nested_file.write_bytes(b"nested-before")

    fifo = snapshot_root / "unsupported"
    os.mkfifo(fifo)
    unsupported = caller_snapshot(snapshot_root)
    assert unsupported.returncode == 2
    assert "unsupported caller entry type" in unsupported.stderr
    fifo.unlink()


def test_clean_sibling_snapshot_rejects_bound_root_replacement(tmp_path: Path) -> None:
    snapshot_script = EVIDENCE_SCRIPTS / "clean_sibling_cleanup.sh"
    caller = tmp_path / "bound-caller"
    caller.mkdir(mode=0o700)
    caller.chmod(0o700)
    existing = caller / "existing"
    existing.write_bytes(b"before")
    moved = tmp_path / "bound-caller-original"
    command = r"""
source "$1"
exec {root_fd}<"$2"
identity="$(stat -Lc '%d:%i:%u:%a' -- "/proc/$$/fd/$root_fd")"
before="$(clean_sibling_snapshot_direct_entries "$root_fd" "$identity" "$2")" || exit 99
mv -- "$2" "$3"
mkdir -m 700 -- "$2"
printf 'after-root-replace' >"$3/existing"
set +e
observed="$(clean_sibling_snapshot_direct_entries "$root_fd" "$identity" "$2" 2>&1)"
status=$?
set -e
rmdir -- "$2"
mv -- "$3" "$2"
printf 'BEFORE=%s\nOBSERVED=%s\n' "$before" "$observed"
exit "$status"
"""
    replaced = subprocess.run(
        ["bash", "-c", command, "_", str(snapshot_script), str(caller), str(moved)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert replaced.returncode == 2, (replaced.stdout, replaced.stderr)
    assert "path no longer refers to authenticated descriptor" in replaced.stdout
    assert "CLEAN_SIBLING_TECHNICAL=PASS" not in replaced.stdout
    assert existing.read_bytes() == b"after-root-replace"
    assert not moved.exists()


def test_clean_sibling_rejects_loader_and_git_authority_before_mutation(
    tmp_path: Path,
) -> None:
    """The static launcher scrubs loader, shell-function, and Git authority."""
    caller = tmp_path / "caller"
    caller.mkdir(mode=0o700)
    sentinel = caller / "sentinel"
    sentinel.write_bytes(b"unchanged")
    hostile = tmp_path / "hostile.gitconfig"
    marker = tmp_path / "injected-command-ran"
    hostile.write_text(
        f"[core]\n\tfsmonitor = !touch {marker}\n\thooksPath = {tmp_path / 'hooks'}\n",
        encoding="utf-8",
    )
    hostile_home = tmp_path / "hostile-home"
    hostile_home.mkdir()
    shutil.copy2(hostile, hostile_home / ".gitconfig")
    hostile_xdg = tmp_path / "hostile-xdg"
    (hostile_xdg / "git").mkdir(parents=True)
    shutil.copy2(hostile, hostile_xdg / "git/config")
    constructor_marker = tmp_path / "loader-constructor-ran"
    constructor_source = tmp_path / "constructor.c"
    constructor_object = tmp_path / "constructor.so"
    constructor_source.write_text(
        "#include <fcntl.h>\n#include <unistd.h>\n"
        f"__attribute__((constructor)) static void loaded(void) {{ int fd = open("
        f"{json.dumps(str(constructor_marker))}, O_WRONLY|O_CREAT, 0600); "
        'if (fd >= 0) { (void)write(fd, "loaded\\n", 7); (void)close(fd); } }\n',
        encoding="utf-8",
    )
    subprocess.run(
        ["/usr/bin/cc", "-shared", "-fPIC", "-o", str(constructor_object), str(constructor_source)],
        check=True,
    )
    function_marker = tmp_path / "imported-realpath-ran"
    constructor_control = dict(os.environ)
    constructor_control["LD_PRELOAD"] = str(constructor_object)
    subprocess.run(["/bin/true"], env=constructor_control, check=True)
    assert constructor_marker.read_bytes() == b"loaded\n"
    constructor_marker.unlink()
    function_control = dict(os.environ)
    function_control["BASH_FUNC_realpath%%"] = (
        f'() {{ /usr/bin/touch {function_marker}; /usr/bin/realpath "$@"; }}'
    )
    subprocess.run(
        ["/bin/bash", "--noprofile", "--norc", "-c", "realpath /"],
        env=function_control,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    assert function_marker.is_file()
    function_marker.unlink()
    cases = {
        "loader": {"LD_PRELOAD": str(constructor_object)},
        "function": {
            "BASH_FUNC_realpath%%": (
                f'() {{ /usr/bin/touch {function_marker}; /usr/bin/realpath "$@"; }}'
            )
        },
        "global": {"GIT_CONFIG_GLOBAL": str(hostile)},
        "count": {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": f"!touch {marker}",
        },
        "home": {"HOME": str(hostile_home)},
        "xdg": {"XDG_CONFIG_HOME": str(hostile_xdg)},
    }
    for name, injected in cases.items():
        env = _evidence_env(tmp_path / f"unused-{name}")
        env.pop("ACGS_CLEAN_SIBLING_TMP_FD", None)
        for key in tuple(env):
            if key.startswith("LD_") or key.startswith("GIT_"):
                env.pop(key)
        env.update(injected)
        env.update(
            {
                "P": "26d11c2c7a8da37937a7c50c642f18edc75c9345",
                "TMPDIR": str(caller),
            }
        )
        completed = subprocess.run(
            ["scripts/evidence/prove_clean_sibling", "P0-EVIDENCE-000", "0" * 40],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        assert completed.returncode == 2
        assert "CLEAN_SIBLING_TECHNICAL=PASS" not in completed.stdout
        assert "T commit is unavailable" in completed.stderr
        assert sentinel.read_bytes() == b"unchanged"
        assert sorted(path.name for path in caller.iterdir()) == ["sentinel"]
        assert not marker.exists()
        assert not constructor_marker.exists()
        assert not function_marker.exists()


def test_clean_sibling_internal_script_refuses_direct_invocation(tmp_path: Path) -> None:
    env = _evidence_env(tmp_path / "unused")
    env.update({"P": "26d11c2c7a8da37937a7c50c642f18edc75c9345", "TMPDIR": str(tmp_path)})
    completed = subprocess.run(
        [
            "/bin/bash",
            "scripts/evidence/prove_clean_sibling.sh",
            "P0-EVIDENCE-000",
            "0" * 40,
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 2
    assert "requires trusted static launcher" in completed.stderr
    assert "CLEAN_SIBLING_TECHNICAL=PASS" not in completed.stdout


def test_clean_sibling_launcher_requires_explicit_allowlisted_node_and_t(
    tmp_path: Path,
) -> None:
    launcher = EVIDENCE_SCRIPTS / "prove_clean_sibling"
    env = _evidence_env(tmp_path / "unused")
    env["P"] = "1" * 40
    for argv, message in (
        ([], "usage:"),
        (["P0-EVIDENCE-000"], "usage:"),
        (["P0-UNKNOWN-999", "2" * 40], "outside the reviewed attestation allowlist"),
    ):
        completed = subprocess.run(
            [str(launcher), *argv],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        assert completed.returncode == 2
        assert message in completed.stderr
        assert not list(tmp_path.glob("acgs-p0-evidence.*"))

    reached = subprocess.run(
        [str(launcher), "P0-EVIDENCE-000", "0" * 40],
        cwd=ROOT,
        env={
            **_evidence_env(tmp_path / "unused-reachable"),
            "P": "26d11c2c7a8da37937a7c50c642f18edc75c9345",
            "TMPDIR": str(tmp_path),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert reached.returncode == 2
    assert "T commit is unavailable" in reached.stderr
    assert "ambient UI loader/config/auth/proxy variable rejected: NODE_ID" not in reached.stderr
    wrong_gates_parent = subprocess.run(
        [str(launcher), "P0-GATES-003", "0" * 40],
        cwd=ROOT,
        env={
            **_evidence_env(tmp_path / "unused-gates-parent"),
            "P": "26d11c2c7a8da37937a7c50c642f18edc75c9345",
            "TMPDIR": str(tmp_path),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert wrong_gates_parent.returncode == 2
    assert "reviewed parent must be exact 5918828010125ebcedaaf96fb9cd5e109598f2a8" in (
        wrong_gates_parent.stderr
    )


def test_clean_sibling_rejects_available_nonbase_parent_before_mutation(
    tmp_path: Path,
) -> None:
    launcher = EVIDENCE_SCRIPTS / "prove_clean_sibling"
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=True
    ).stdout.strip()
    available_nonbase = subprocess.run(
        ["git", "rev-parse", "HEAD^"], cwd=ROOT, text=True, capture_output=True, check=True
    ).stdout.strip()
    assert available_nonbase != "26d11c2c7a8da37937a7c50c642f18edc75c9345"
    caller = tmp_path / "caller"
    caller.mkdir(mode=0o700)
    completed = subprocess.run(
        [str(launcher), "P0-MEMBRANE-001", head],
        cwd=ROOT,
        env={**_evidence_env(tmp_path / "unused"), "P": available_nonbase, "TMPDIR": str(caller)},
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 2
    assert "reviewed parent must be exact" in completed.stderr
    assert not list(caller.glob("acgs-p0-evidence.*"))


def test_ui_bootstrap_network_and_failure_boundaries_are_fail_closed(
    tmp_path: Path,
) -> None:
    source = (EVIDENCE_SCRIPTS / "prove_clean_sibling.sh").read_text(encoding="utf-8")

    def assert_boundary(candidate: str) -> None:
        normalized = candidate.replace("\\\n    ", "").replace("\\\n      ", "")
        bwrap = candidate.split("  ui_bwrap() {", 1)[1].split("\n  for pair in", 1)[0]
        fetch = (
            'ui_bwrap fetch "$FNM_BIN" exec --using 24.18.0 -- pnpm fetch '
            "--ignore-scripts --frozen-lockfile"
        )
        install = (
            'ui_bwrap offline "$FNM_BIN" exec --using 24.18.0 -- pnpm install --frozen-lockfile'
        )
        assert bwrap.count("--share-net") == 1
        assert "fetch)\n        namespace_args+=(--share-net)" in bwrap
        assert "offline)\n        offline_env+=(--setenv npm_config_offline true " in bwrap
        assert "--setenv PNPM_OFFLINE true)" in bwrap
        assert "install)" not in bwrap
        assert '"${host_secret_masks[@]}"' in bwrap
        assert 'host_secret_masks+=(--ro-bind "$UI_EMPTY_SECRET_MASK" "$secret_path")' in bwrap
        for secret_path in _common.REVIEWED_UI_HOST_SECRET_PATHS:
            assert f"    {secret_path}\n" in candidate
        assert normalized.count(fetch) == 1
        assert normalized.count(install) == 1
        assert f"if ! {fetch}; then\n    ui_bootstrap_failed fetch" in normalized
        assert f"if ! {install}; then\n    ui_bootstrap_failed install" in normalized
        assert normalized.index(fetch) < normalized.index(install)
        completed_index = normalized.find("UI_BOOTSTRAP_COMPLETE=1")
        assert completed_index >= 0
        assert normalized.index(install) < completed_index
        assert '[[ "$ASSIGNMENT" == *UI* && "$UI_BOOTSTRAP_COMPLETE" != 1 ]]' in candidate
        failure_guard = candidate.split("  ui_bootstrap_failed() {", 1)[1].split("\n  }", 1)[0]
        for artifact in (
            "transcript.jsonl",
            "run.json",
            "run.jcs.sha256",
            "validation-success.json",
            "validation-report.json",
        ):
            assert artifact in failure_guard
        assert 'reject_lexists "$NODE_EVIDENCE/$artifact"' in failure_guard

    assert_boundary(source)
    for mutation in (
        source.replace(
            "fetch)\n        namespace_args+=(--share-net)",
            "offline)\n        namespace_args+=(--share-net)",
            1,
        ),
        source.replace("--setenv npm_config_offline true", "--setenv npm_config_offline false", 1),
        source.replace(
            'ui_bwrap offline "$FNM_BIN" exec --using 24.18.0 -- pnpm install',
            'ui_bwrap fetch "$FNM_BIN" exec --using 24.18.0 -- pnpm install',
            1,
        ),
        source.replace("ui_bootstrap_failed install", "true", 1),
        source.replace("UI_BOOTSTRAP_COMPLETE=1", "UI_BOOTSTRAP_COMPLETE=0", 1),
        source.replace("    /etc/environment\n", "    /etc/environment-unmasked\n", 1),
    ):
        with pytest.raises(AssertionError):
            assert_boundary(mutation)

    failure_body = source.split("  ui_bootstrap_failed() {", 1)[1].split("\n  }", 1)[0]
    accepted = (
        "transcript.jsonl",
        "run.json",
        "run.jcs.sha256",
        "validation-success.json",
        "validation-report.json",
    )
    for stage in ("fetch", "install"):
        node_evidence = tmp_path / stage
        node_evidence.mkdir()
        harness = f"""set -euo pipefail
NODE_EVIDENCE="$1"
die() {{ printf '%s\\n' "$1" >&2; exit 2; }}
reject_lexists() {{ [[ ! -e "$1" && ! -L "$1" ]] || exit 97; }}
ui_bootstrap_failed() {{{failure_body}
}}
ui_bootstrap_failed "$2"
"""
        completed = subprocess.run(
            ["/bin/bash", "-c", harness, "ui-bootstrap-test", str(node_evidence), stage],
            text=True,
            capture_output=True,
            check=False,
        )
        assert completed.returncode == 2
        assert f"UI dependency {stage} failed before evidence acceptance" in completed.stderr
        assert all(not (node_evidence / artifact).exists() for artifact in accepted)


def test_ui_pnpm_dispatcher_guard_is_exact_and_fail_closed(tmp_path: Path) -> None:
    source = (EVIDENCE_SCRIPTS / "prove_clean_sibling.sh").read_text(encoding="utf-8")
    expected_sha256 = "7c2a67995976b5b592b611d8b236e3b0633bd654fb49aedd96c6eb7ce04c9cbb"
    expected_target = "../lib/node_modules/corepack/dist/pnpm.js"
    assert f"PNPM_DISPATCHER_SHA256={expected_sha256}" in source
    assert (
        '"$HOST_NODE_ROOT/lib/node_modules/corepack/dist/pnpm.js:$PNPM_DISPATCHER_SHA256"' in source
    )
    assert f"UI_PNPM_LEXICAL_TARGET='{expected_target}'" in source

    guard_body = source.split("  ui_verify_pnpm_dispatcher() {", 1)[1].split(
        "\n  }\n  ui_bwrap() {", 1
    )[0]
    harness = f"""set -euo pipefail
ui_verify_pnpm_dispatcher() {{{guard_body}
}}
ui_verify_pnpm_dispatcher "$@"
"""
    node_root = tmp_path / "installation"
    bin_dir = node_root / "bin"
    dist_dir = node_root / "lib" / "node_modules" / "corepack" / "dist"
    bin_dir.mkdir(parents=True)
    dist_dir.mkdir(parents=True)
    shim = bin_dir / "pnpm"
    dispatcher = dist_dir / "pnpm.js"
    corepack_dispatcher = dist_dir / "corepack.js"
    payload = b"pinned pnpm dispatcher\n"
    dispatcher.write_bytes(payload)
    corepack_dispatcher.write_bytes(payload)
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    shim.symlink_to(expected_target)

    def verify() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "/bin/bash",
                "-c",
                harness,
                "ui-pnpm-dispatcher-test",
                str(shim),
                str(dispatcher),
                expected_target,
                payload_sha256,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    assert verify().returncode == 0

    shim.unlink()
    shim.symlink_to("../lib/node_modules/corepack/dist/corepack.js")
    assert verify().returncode != 0

    shim.unlink()
    shim.symlink_to(expected_target)
    dispatcher.unlink()
    dispatcher.symlink_to("corepack.js")
    assert verify().returncode != 0

    dispatcher.unlink()
    dispatcher.write_bytes(b"tampered dispatcher\n")
    assert verify().returncode != 0


def test_clean_sibling_hash_locked_bootstraps_and_round_trip(tmp_path: Path) -> None:
    prover = EVIDENCE_SCRIPTS / "prove_clean_sibling.sh"
    launcher = EVIDENCE_SCRIPTS / "prove_clean_sibling"
    subprocess.run(["/usr/bin/busybox", "ash", "-n", str(launcher)], check=True)
    subprocess.run(["bash", "-n", str(prover)], check=True)
    subprocess.run(["bash", "-n", str(EVIDENCE_SCRIPTS / "clean_sibling_cleanup.sh")], check=True)
    source = prover.read_text(encoding="utf-8")
    cleanup_source = (EVIDENCE_SCRIPTS / "clean_sibling_cleanup.sh").read_text(encoding="utf-8")
    for phase in ("B0", "B1", "B2", "B3", "B4", "B5", "B6"):
        assert f"phase {phase}" in source
    assert "phase B7" not in source and "phase B8" not in source
    for required in (
        'git -C "$SOURCE_REPO" worktree add --detach',
        "P0_REVIEWED_BASE='26d11c2c7a8da37937a7c50c642f18edc75c9345'",
        'git -C "$SOURCE_REPO" diff --check "$P..$T"',
        "--require-hashes",
        "--offline --no-index --no-cache --no-build-isolation --no-deps",
        "verify_environment.py",
        "capture_environment.py",
        "validate_environment_identities.py",
        "generate_run.py",
        "validate_run.py",
        "hash_run_jcs.py",
    ):
        assert required in source
    assert "CLEAN_SIBLING_TECHNICAL=PASS" in cleanup_source
    assert "attestations=pending-independent-lanes" in cleanup_source
    assert '  exit "$?"\nfi' in source
    assert "  exit 2\nfi" not in source
    assert '"$T^"' not in source
    assert "attest.py" not in source and "PRIVATE_ROOT" not in source
    assert 'ui_bwrap offline "$FNM_BIN" install 24.18.0' in source
    assert 'ui_bwrap offline "$FNM_BIN" exec --using 24.18.0 -- corepack enable' in source
    assert "corepack prepare pnpm@9.15.4" in source
    exact_bootstrap = (
        'ui_bwrap offline "$FNM_BIN" install 24.18.0',
        'ui_bwrap offline "$FNM_BIN" exec --using 24.18.0 -- corepack enable',
        'ui_bwrap offline "$FNM_BIN" exec --using 24.18.0 -- corepack prepare pnpm@9.15.4',
        'ui_bwrap offline "$FNM_BIN" exec --using 24.18.0 -- pnpm install --frozen-lockfile',
    )
    normalized_source = source.replace("\\\n    ", "").replace("\\\n      ", "")
    positions = [normalized_source.index(command) for command in exact_bootstrap]
    assert positions == sorted(positions)
    exact_fetch = (
        'ui_bwrap fetch "$FNM_BIN" exec --using 24.18.0 -- pnpm fetch '
        "--ignore-scripts --frozen-lockfile"
    )
    assert normalized_source.count(exact_fetch) == 1
    assert positions[2] < normalized_source.index(exact_fetch) < positions[3]
    assert "ui_tree_sha256" in source and "copied pnpm tree digest mismatch" in source
    assert "packageManager must match the reviewed pnpm name/version/integrity selector" in source
    for masked_root in ("/home", "/root", "/tmp", "/var/tmp", "/run"):
        assert f"--tmpfs {masked_root}" in source
    assert "bash -c" not in source and "sh -c" not in source and "python -c" not in source
    assert "'root:EVID-gate'" in source
    assert source.count("run_recorded_gate CP") == 4
    assert source.count("run_recorded_gate GZ") == 4
    assert source.count("run_recorded_gate P0") == 1
    assert "P0-EVIDENCE-000) ASSIGNMENT='EVID+CP+GZ'; EXPECTED_RECORDS=10" in source
    assert "P0-MEMBRANE-001) ASSIGNMENT='EVID+CP'; EXPECTED_RECORDS=7" in source
    assert "P0-CLAIMS-002) ASSIGNMENT='EVID+CP+GZ'; EXPECTED_RECORDS=14" in source
    assert "P0-GATES-003) ASSIGNMENT='EVID+CP+GZ+UI'; EXPECTED_RECORDS=16" in source
    assert "capture_reviewed_command.py" in source
    assert "index < EXPECTED_RECORDS" in source
    assert "IFS=: read -r TMP_ROOT_DEVICE" in source
    assert "stat -c '%d:%i:%u:%a' --" in source
    assert "RUFF_NO_CACHE=true" in source
    assert "RUFF_NO_CACHE=1" not in source
    for exact_override in (
        "export ACGS_PROCESS_SCHEDULE='[\"single-process\"]'",
        "export ACGS_CLOCK_SOURCE='system-utc'",
        "export ACGS_SKIPPED_JSON='[]'",
        "export ACGS_EXTERNAL_JSON='[]'",
    ):
        assert exact_override in source
    b6 = source.split("phase B6", 1)[1]
    assert b6.count('cd "$WORKTREE"') == 3
    assert 'SCRATCH_ROOT="$TMP_ROOT/scratch"' in source
    assert 'UV_CACHE_DIR="$SCRATCH_ROOT/uv-cache"' in source
    for scratch_export in (
        'export TMPDIR="$RUNTIME_TMP"',
        'export TMP="$RUNTIME_TMP"',
        'export TEMP="$RUNTIME_TMP"',
        'export HOME="$SCRATCH_ROOT/home"',
        'export XDG_CACHE_HOME="$SCRATCH_ROOT/xdg-cache"',
        'export XDG_CONFIG_HOME="$SCRATCH_ROOT/xdg-config"',
        'export XDG_DATA_HOME="$SCRATCH_ROOT/xdg-data"',
        'export XDG_STATE_HOME="$SCRATCH_ROOT/xdg-state"',
        'export PYTEST_DEBUG_TEMPROOT="$SCRATCH_ROOT/pytest-temp"',
        'export MYPY_CACHE_DIR="$SCRATCH_ROOT/mypy-cache"',
        'export RUFF_CACHE_DIR="$SCRATCH_ROOT/ruff-cache"',
        'export COVERAGE_FILE="$SCRATCH_ROOT/coverage/.coverage"',
        'export UV_PYTHON_INSTALL_DIR="$SCRATCH_ROOT/uv-python"',
        'export UV_PYTHON_BIN_DIR="$SCRATCH_ROOT/uv-python-bin"',
        'export UV_TOOL_DIR="$SCRATCH_ROOT/uv-tools"',
        'export UV_TOOL_BIN_DIR="$SCRATCH_ROOT/uv-tool-bin"',
        'export UV_PYTHON_CACHE_DIR="$SCRATCH_ROOT/uv-python-cache"',
        'export UV_CREDENTIALS_DIR="$SCRATCH_ROOT/uv-credentials"',
    ):
        assert scratch_export in source
    assert source.index('export TMPDIR="$RUNTIME_TMP"') < source.index('"$UV_BIN" --version')
    assert "TMP_PARENT_ENTRIES_BEFORE" in source
    assert "TMP_PARENT_STAT_BEFORE" in source
    assert "reject_lexists" in source
    assert "clean_sibling_cleanup" in source
    assert "RECORDED_GATE=FAIL scope=%s selector=%s exit=%s stderr_sha256=%s" in source
    assert 'cat "$stderr_file"' not in source
    assert 'rm -rf "$SOURCE_REPO' not in source
    assert "git clean" not in source
    assert "git reset --hard" not in source

    inner_t = os.environ.get("ACGS_P0_LITERAL_PROVER_INNER_T")
    if inner_t is not None:
        reviewed_parent = "26d11c2c7a8da37937a7c50c642f18edc75c9345"
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=True
        ).stdout.strip()
        assert inner_t == head
        assert (
            subprocess.run(
                ["git", "merge-base", "--is-ancestor", reviewed_parent, inner_t],
                cwd=ROOT,
                check=False,
            ).returncode
            == 0
        )
        inner_evidence = _common.evidence_root_from_env(ROOT)
        assert inner_evidence == inner_evidence.resolve(strict=True)
        assert not inner_evidence.is_relative_to(ROOT)
        inner_transcript = inner_evidence / "P0-EVIDENCE-000/transcript.jsonl"
        raw_records = inner_transcript.read_bytes().splitlines()
        assert len(raw_records) == 9
        records = [
            _common.validate_transcript_record(_common.strict_json_loads(raw))
            for raw in raw_records
        ]
        assert [(record["selectors"][0], tuple(record["argv"])) for record in records] == list(
            _common.REVIEWED_P0_TRANSCRIPT[:9]
        )
        return

    range_repo = tmp_path / "range-repo"
    range_repo.mkdir()
    subprocess.run(["git", "init", "-q", str(range_repo)], check=True)
    subprocess.run(["git", "config", "user.name", "Evidence Test"], cwd=range_repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "evidence@example.invalid"],
        cwd=range_repo,
        check=True,
    )
    (range_repo / "base.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "base.txt"], cwd=range_repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=range_repo, check=True)
    parent = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=range_repo,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    (range_repo / "first.txt").write_text("first commit has trailing whitespace  \n")
    subprocess.run(["git", "add", "first.txt"], cwd=range_repo, check=True)
    subprocess.run(["git", "commit", "-qm", "first"], cwd=range_repo, check=True)
    prior = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=range_repo,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    (range_repo / "second.txt").write_text("second\n", encoding="utf-8")
    subprocess.run(["git", "add", "second.txt"], cwd=range_repo, check=True)
    subprocess.run(["git", "commit", "-qm", "tested"], cwd=range_repo, check=True)
    tested = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=range_repo,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    assert prior != parent and tested != prior
    assert (
        subprocess.run(
            ["git", "diff", "--check", f"{prior}..{tested}"], cwd=range_repo, check=False
        ).returncode
        == 0
    )
    with pytest.raises(_common.EvidenceError, match="diff --check"):
        _common.verify_git_range(range_repo, parent, tested, require_clean=True)

    bad_args = [
        "--schema",
        str(SCHEMA_ROOT / "acgs-run-evidence-v1.schema.json"),
        "--node",
        "INVALID",
        "--parent",
        "1" * 40,
        "--product",
        "2" * 40,
        "--assignment",
        "EVID",
        "--environment-identities",
        str(tmp_path / "environment-identities.json"),
        "--transcript",
        str(tmp_path / "transcript.jsonl"),
        "--output",
        str(tmp_path / "run.json"),
    ]
    wrong_cwd = subprocess.run(
        [sys.executable, str(EVIDENCE_SCRIPTS / "generate_run.py"), *bad_args],
        cwd=range_repo,
        env=_evidence_env(tmp_path / "outer"),
        text=True,
        capture_output=True,
        check=False,
    )
    assert wrong_cwd.returncode == 2
    assert "cwd must be the product repository root" in wrong_cwd.stderr
    root_reset = subprocess.run(
        [sys.executable, str(EVIDENCE_SCRIPTS / "generate_run.py"), *bad_args],
        cwd=ROOT,
        env=_evidence_env(tmp_path / "outer"),
        text=True,
        capture_output=True,
        check=False,
    )
    assert root_reset.returncode == 2
    assert "invalid NODE_ID" in root_reset.stderr
    assert "cwd must be" not in root_reset.stderr

    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=True
    ).stdout.strip()
    reviewed_parent = "26d11c2c7a8da37937a7c50c642f18edc75c9345"
    omitted_parent_env = _evidence_env(tmp_path / "unused-evidence")
    omitted_parent_env.pop("P", None)
    omitted_parent = subprocess.run(
        [str(launcher), "P0-EVIDENCE-000", head],
        cwd=ROOT,
        env=omitted_parent_env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert omitted_parent.returncode == 2
    assert "P must be exported" in omitted_parent.stderr
    altered_parent_env = dict(omitted_parent_env)
    available_nonbase_parent = subprocess.run(
        ["git", "rev-parse", "HEAD^"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    assert available_nonbase_parent != reviewed_parent
    altered_parent_env["P"] = available_nonbase_parent
    altered_parent = subprocess.run(
        [str(launcher), "P0-EVIDENCE-000", head],
        cwd=ROOT,
        env=altered_parent_env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert altered_parent.returncode == 2
    assert "reviewed parent must be exact" in altered_parent.stderr
    if head != reviewed_parent:
        contained = ROOT / "tests"
        symlink = tmp_path / "tmpdir-link"
        symlink.symlink_to(tmp_path, target_is_directory=True)
        try:
            for supplied, message in (
                ("relative-tmp", "TMPDIR must be absolute"),
                (str(symlink), "non-symlink"),
                (str(contained), "outside source repository"),
            ):
                before = set(tmp_path.glob("acgs-p0-evidence.*"))
                contained_before = set(contained.glob("acgs-p0-evidence.*"))
                env = _evidence_env(tmp_path / "unused-evidence")
                env.update({"P": reviewed_parent, "TMPDIR": supplied})
                completed = subprocess.run(
                    [str(launcher), "P0-EVIDENCE-000", head],
                    cwd=ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                assert completed.returncode == 2
                assert message in completed.stderr
                assert set(tmp_path.glob("acgs-p0-evidence.*")) == before
                assert set(contained.glob("acgs-p0-evidence.*")) == contained_before
        finally:
            assert contained == ROOT / "tests"

    cleanup_repo = tmp_path / "cleanup-repo"
    cleanup_repo.mkdir()
    subprocess.run(["git", "init", "-q", str(cleanup_repo)], check=True)
    subprocess.run(["git", "config", "user.name", "Evidence Test"], cwd=cleanup_repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "evidence@example.invalid"],
        cwd=cleanup_repo,
        check=True,
    )
    (cleanup_repo / "tracked").write_text("tracked\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked"], cwd=cleanup_repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=cleanup_repo, check=True)
    worktrees_before = subprocess.run(
        ["git", "worktree", "list", "--porcelain"],
        cwd=cleanup_repo,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.rstrip("\n")
    status_before = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=cleanup_repo,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.rstrip("\n")
    cleanup_root = tmp_path / "acgs-p0-evidence.injected"
    cleanup_root.mkdir(mode=0o700)
    cleanup_root.chmod(0o700)
    cleanup_worktree = cleanup_root / "product"
    subprocess.run(
        ["git", "worktree", "add", "--detach", str(cleanup_worktree), "HEAD"],
        cwd=cleanup_repo,
        stdout=subprocess.DEVNULL,
        check=True,
    )
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    failure_state = fake_bin / "remove-failed-once"
    real_git = os.environ.get("ACGS_TEST_ORIGINAL_GIT") or shutil.which("git")
    assert real_git is not None
    (fake_bin / "git").write_text(
        "#!/usr/bin/env bash\n"
        'if [[ "$*" == *"worktree remove --force"* && ! -e "$FAILURE_STATE" ]]; then\n'
        '  : >"$FAILURE_STATE"\n'
        "  exit 1\n"
        "fi\n"
        'exec "$REAL_GIT" "$@"\n',
        encoding="utf-8",
    )
    (fake_bin / "git").chmod(0o755)
    cleanup_env = dict(os.environ)
    cleanup_env.update(
        {
            "PATH": f"{fake_bin}:{cleanup_env['PATH']}",
            "REAL_GIT": real_git,
            "FAILURE_STATE": str(failure_state),
            "WORKTREES_BEFORE": worktrees_before,
            "SOURCE_STATUS_BEFORE": status_before,
        }
    )
    cleanup_command = r"""
set -u
source "$1"
SOURCE_REPO="$2"
TMP_PARENT="$3"
TMP_ROOT="$4"
OWNER_MARKER="$TMP_ROOT/.acgs-clean-sibling-owned"
exec {TMP_PARENT_FD}<"$TMP_PARENT"
TMP_PARENT_STAT_BEFORE="$(stat -Lc '%d:%i:%u:%a' -- "/proc/$$/fd/$TMP_PARENT_FD")"
TMP_PARENT_ENTRIES_BEFORE="$(clean_sibling_snapshot_direct_entries \
  "$TMP_PARENT_FD" "$TMP_PARENT_STAT_BEFORE" "$TMP_PARENT")"
IFS=: read -r TMP_ROOT_DEVICE TMP_ROOT_INODE TMP_ROOT_UID _ < <(
  stat -c '%d:%i:%u:%a' -- "$TMP_ROOT"
)
WORKTREE="$TMP_ROOT/product"
WORKTREE_ADDED=1
PROOF_COMPLETE=1
TRANSCRIPT_RECORDS=10
EXPECTED_RECORDS=10
NODE_ID=P0-EVIDENCE-000
ASSIGNMENT=EVID+CP+GZ
P=1111111111111111111111111111111111111111
T=2222222222222222222222222222222222222222
R=3333333333333333333333333333333333333333333333333333333333333333
printf '%s\n' "$$" >"$OWNER_MARKER"
clean_sibling_cleanup 0
exit $?
"""
    cleanup_result = subprocess.run(
        [
            "bash",
            "-c",
            cleanup_command,
            "_",
            str(EVIDENCE_SCRIPTS / "clean_sibling_cleanup.sh"),
            str(cleanup_repo),
            str(tmp_path),
            str(cleanup_root),
        ],
        env=cleanup_env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert cleanup_result.returncode == 2
    assert "cleanup retry after worktree removal failure" not in cleanup_result.stderr
    assert "CLEAN_SIBLING_TECHNICAL=PASS" not in cleanup_result.stdout
    assert not failure_state.exists(), "ambient fake git must never execute"
    assert not cleanup_root.exists()
    assert (
        subprocess.run(
            ["git", "worktree", "list", "--porcelain"],
            cwd=cleanup_repo,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.rstrip("\n")
        == worktrees_before
    )

    status_snapshot = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    ).stdout
    worktrees_snapshot = subprocess.run(
        ["git", "worktree", "list", "--porcelain"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    ).stdout
    candidate_roots = (
        Path("requirements/saas-beta"),
        Path("schemas/evidence"),
        Path("scripts/evidence"),
        Path("tests/saas_beta"),
    )
    candidate_files = sorted(
        relative
        for root in candidate_roots
        for path in (ROOT / root).rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
        for relative in (path.relative_to(ROOT),)
    )
    assert len(candidate_files) == 28
    assert Path("scripts/evidence/capture_reviewed_command.py") in candidate_files
    assert Path("tests/saas_beta/test_ci_gate_contract.py") in candidate_files
    assert Path("tests/saas_beta/test_evidence_bootstrap.py") in candidate_files
    candidate = tmp_path / "literal-prover-candidate"
    caller_parents: list[Path] = []
    added = False
    try:
        subprocess.run(
            ["git", "worktree", "add", "--detach", str(candidate), reviewed_parent],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        added = True
        for relative in candidate_files:
            destination = candidate / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        subprocess.run(
            ["git", "add", "--", *(str(path) for path in candidate_files)],
            cwd=candidate,
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=ACGS Literal Prover Test",
                "-c",
                "user.email=literal-prover@example.invalid",
                "commit",
                "-qm",
                "disposable exact P0 evidence candidate",
            ],
            cwd=candidate,
            check=True,
        )
        product = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=candidate,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        assert product != reviewed_parent
        assert (
            subprocess.run(
                ["git", "status", "--porcelain=v1", "--untracked-files=all"],
                cwd=candidate,
                text=True,
                capture_output=True,
                check=True,
            ).stdout
            == ""
        )
        sentinel = "S3ntinel-Prover-Must-Override-Ambient-Metadata"
        real_git = os.environ.get("ACGS_TEST_ORIGINAL_GIT") or shutil.which("git")
        real_uv = os.environ.get("ACGS_TEST_ORIGINAL_UV") or shutil.which("uv")
        assert real_git is not None and real_uv is not None

        def invoke_literal_prover(case: str) -> tuple[subprocess.CompletedProcess[str], Path]:
            caller = tmp_path / f"literal-prover-tmp-{case}"
            caller.mkdir(mode=0o700)
            caller.chmod(0o700)
            caller_parents.append(caller)
            caller_stat = caller.stat()
            caller_identity = (
                caller_stat.st_dev,
                caller_stat.st_ino,
                stat.S_IMODE(caller_stat.st_mode),
            )
            mutation_cases = {
                "mutate-bytes",
                "mutate-mode",
                "mutate-link",
                "mutate-nested",
                "root-replace",
            }
            if case in mutation_cases:
                (caller / "existing").write_bytes(b"before")
                (caller / "existing").chmod(0o600)
                (caller / "directory").mkdir(mode=0o700)
                (caller / "directory/nested").write_bytes(b"nested-before")
                (caller / "link").symlink_to("existing")
            else:
                assert list(caller.iterdir()) == []

            env = _evidence_env(tmp_path / f"unused-outer-evidence-{case}")
            # Exercise the first-pass guardian even when this test is itself
            # running under the clean-sibling prover.
            env.pop("ACGS_CLEAN_SIBLING_TMP_FD", None)
            env.update(
                {
                    "P": reviewed_parent,
                    "TMPDIR": str(caller.resolve(strict=True)),
                    "ACGS_PROCESS_SCHEDULE": json.dumps([f"env AUTH={sentinel}"]),
                    "ACGS_CLOCK_SOURCE": f"https://user:{sentinel}@example.invalid",
                    "ACGS_SKIPPED_JSON": json.dumps([{"code": sentinel}]),
                    "ACGS_EXTERNAL_JSON": json.dumps([{"code": sentinel}]),
                    "ACGS_TEST_CALLER_TMPDIR": str(caller.resolve(strict=True)),
                    "REAL_GIT": real_git,
                    "REAL_UV": real_uv,
                    "ACGS_TEST_ORIGINAL_GIT": real_git,
                    "ACGS_TEST_ORIGINAL_UV": real_uv,
                    "ACGS_TEST_MUTATION_FILE": str(caller / "existing"),
                    "ACGS_TEST_MUTATION_LINK": str(caller / "link"),
                    "ACGS_TEST_MUTATION_NESTED": str(caller / "directory/nested"),
                }
            )
            if case == "early":
                env.pop("PYTHONDONTWRITEBYTECODE", None)
                env["PYTHONPYCACHEPREFIX"] = str(caller / "hostile-pycache-prefix")
            hostile_uv_roots = {
                name: tmp_path / f"hostile-{case}-{name.lower()}"
                for name in (
                    "UV_PYTHON_INSTALL_DIR",
                    "UV_PYTHON_BIN_DIR",
                    "UV_TOOL_DIR",
                    "UV_TOOL_BIN_DIR",
                    "UV_CACHE_DIR",
                    "UV_PYTHON_CACHE_DIR",
                    "UV_CREDENTIALS_DIR",
                )
            }
            for name, external in hostile_uv_roots.items():
                external.mkdir(mode=0o700)
                env[name] = str(external)
            fake_bin = tmp_path / f"literal-prover-bin-{case}"
            fake_bin.mkdir()
            injection_marker = fake_bin / "triggered"
            env["INJECTION_MARKER"] = str(injection_marker)
            if case in {"success", "early", "leak", *mutation_cases}:
                git_wrapper = """#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${ACGS_TEST_CASE:-}" == success ]]; then
  : >"$INJECTION_MARKER"
  exit 99
fi
if {
  [[ "${ACGS_TEST_CASE:-}" == early ]] ||
    [[ "${ACGS_TEST_CASE:-}" == mutate-* ]] ||
    [[ "${ACGS_TEST_CASE:-}" == root-replace ]]
} &&
  [[ "${3:-}" == worktree && "${4:-}" == add && "${5:-}" == --detach ]]; then
  case "${ACGS_TEST_CASE:-}" in
    mutate-bytes) printf 'after' >"$ACGS_TEST_MUTATION_FILE" ;;
    mutate-mode) chmod 0640 "$ACGS_TEST_MUTATION_FILE" ;;
    mutate-link)
      rm -- "$ACGS_TEST_MUTATION_LINK"
      ln -s directory "$ACGS_TEST_MUTATION_LINK"
      ;;
    mutate-nested) printf 'nested-after' >"$ACGS_TEST_MUTATION_NESTED" ;;
    root-replace)
      original="$ACGS_TEST_CALLER_TMPDIR.bound-original"
      mv -- "$ACGS_TEST_CALLER_TMPDIR" "$original"
      mkdir -m 700 -- "$ACGS_TEST_CALLER_TMPDIR"
      printf 'after-root-replace' >"$original/existing"
      rmdir -- "$ACGS_TEST_CALLER_TMPDIR"
      mv -- "$original" "$ACGS_TEST_CALLER_TMPDIR"
      ;;
  esac
  : >"$INJECTION_MARKER"
  printf 'INJECTED_FAILURE=%s\\n' "${ACGS_TEST_CASE:-}" >&2
  exit 97
fi
if [[ "${ACGS_TEST_CASE:-}" == leak ]] &&
  [[ "${3:-}" == worktree && "${4:-}" == remove && "${5:-}" == --force ]]; then
  printf 'deliberate residue\\n' >"$ACGS_TEST_CALLER_TMPDIR/deliberate-sibling-leak"
fi
exec "$REAL_GIT" "$@"
"""
                (fake_bin / "git").write_text(git_wrapper, encoding="utf-8")
                (fake_bin / "git").chmod(0o755)
            if case in {"mid", "late"}:
                uv_wrapper = """#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${ACGS_TEST_CASE:-}" == mid ]] && [[ "${1:-}" == venv ]] &&
  [[ "${4:-}" == */packages/acgs-control-plane/.venv ]]; then
  : >"$INJECTION_MARKER"
  printf 'INJECTED_FAILURE=mid\\n' >&2
  exit 97
fi
if [[ "${ACGS_TEST_CASE:-}" == late ]]; then
  saw_pytest=0
  saw_target=0
  for argument in "$@"; do
    [[ "$argument" == pytest ]] && saw_pytest=1
    [[ "$argument" == packages/gove-zone/tests ]] && saw_target=1
  done
  if [[ "$saw_pytest" == 1 && "$saw_target" == 1 ]]; then
    : >"$INJECTION_MARKER"
    printf 'INJECTED_FAILURE=late\\n' >&2
    exit 97
  fi
fi
exec "$REAL_UV" "$@"
"""
                (fake_bin / "uv").write_text(uv_wrapper, encoding="utf-8")
                (fake_bin / "uv").chmod(0o755)
            env["PATH"] = f"{fake_bin}:{env['PATH']}"
            env["ACGS_TEST_CASE"] = case
            status_before_case = subprocess.run(
                ["git", "status", "--porcelain=v1", "--untracked-files=all"],
                cwd=candidate,
                text=True,
                capture_output=True,
                check=True,
            ).stdout
            worktrees_before_case = subprocess.run(
                ["git", "worktree", "list", "--porcelain"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=True,
            ).stdout
            completed = subprocess.run(
                ["scripts/evidence/prove_clean_sibling", "P0-EVIDENCE-000", product],
                cwd=candidate,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            assert sentinel not in completed.stdout and sentinel not in completed.stderr
            after_stat = caller.stat()
            assert (
                after_stat.st_dev,
                after_stat.st_ino,
                stat.S_IMODE(after_stat.st_mode),
            ) == caller_identity
            assert (
                subprocess.run(
                    ["git", "status", "--porcelain=v1", "--untracked-files=all"],
                    cwd=candidate,
                    text=True,
                    capture_output=True,
                    check=True,
                ).stdout
                == status_before_case
            )
            assert (
                subprocess.run(
                    ["git", "worktree", "list", "--porcelain"],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=True,
                ).stdout
                == worktrees_before_case
            )
            for external in hostile_uv_roots.values():
                assert list(external.iterdir()) == []
            return completed, caller

        completed, success_parent = invoke_literal_prover("success")
        assert completed.returncode == 0, (completed.stdout, completed.stderr)
        technical = next(
            line
            for line in completed.stdout.splitlines()
            if line.startswith("CLEAN_SIBLING_TECHNICAL=PASS ")
        )
        fields = dict(item.split("=", 1) for item in technical.split()[1:])
        assert fields["P"] == reviewed_parent
        assert fields["T"] == product
        assert _common.SHA256_RE.fullmatch(fields["R"])
        assert fields["records"] == "10"
        assert fields["assignments"] == "EVID+CP+GZ"
        assert fields["attestations"] == "pending-independent-lanes"
        assert not (tmp_path / "literal-prover-bin-success/triggered").exists()
        assert list(success_parent.iterdir()) == []

        # Ambient fake git/uv are deliberately no longer a fault-injection
        # seam: command lookup is closed before the first external tool. The
        # direct cleanup and snapshot tests above retain mutation/race coverage.
        assert (
            subprocess.run(
                ["git", "status", "--porcelain=v1", "--untracked-files=all"],
                cwd=candidate,
                text=True,
                capture_output=True,
                check=True,
            ).stdout
            == ""
        )
    finally:
        if added:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(candidate)],
                cwd=ROOT,
                check=True,
            )
        assert not candidate.exists()
        assert all(list(parent.iterdir()) == [] for parent in caller_parents if parent.exists())
        assert (
            subprocess.run(
                ["git", "worktree", "list", "--porcelain"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=True,
            ).stdout
            == worktrees_snapshot
        )
        assert (
            subprocess.run(
                ["git", "status", "--porcelain=v1", "--untracked-files=all"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=True,
            ).stdout
            == status_snapshot
        )


def test_write_once_outputs_reject_existing_regular_and_dangling_symlink(tmp_path: Path) -> None:
    regular = tmp_path / "regular.json"
    _common.write_json_exclusive(regular, {"one": 1})
    with pytest.raises(_common.EvidenceError):
        _common.write_json_exclusive(regular, {"two": 2})
    dangling = tmp_path / "dangling.json"
    dangling.symlink_to(tmp_path / "absent")
    with pytest.raises(_common.EvidenceError):
        _common.write_json_exclusive(dangling, {"three": 3})


def test_descriptor_safe_cleanup_refuses_substituted_root(tmp_path: Path) -> None:
    """A same-UID substituted deletion target must remain byte-for-byte intact."""
    helper = EVIDENCE_SCRIPTS / "clean_sibling_cleanup.sh"
    parent = tmp_path / "caller"
    parent.mkdir(mode=0o700)
    original = parent / "acgs-p0-evidence.race"
    original.mkdir(mode=0o700)
    original_stat = original.stat()
    (original / ".acgs-clean-sibling-owned").write_text("placeholder\n", encoding="utf-8")
    displaced = parent / "displaced"
    original.rename(displaced)
    victim = parent / "acgs-p0-evidence.race"
    victim.mkdir(mode=0o700)
    (victim / "valuable").write_bytes(b"must-survive")
    command = r"""
set -u
source "$1"
exec {parent_fd}<"$2"
clean_sibling_remove_owned_root "$parent_fd" "$3" "$4" placeholder
"""
    expected = f"{original_stat.st_dev}:{original_stat.st_ino}:{original_stat.st_uid}:700"
    completed = subprocess.run(
        ["bash", "-c", command, "_", str(helper), str(parent), str(victim), expected],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 2
    assert "root identity changed" in completed.stderr
    assert (victim / "valuable").read_bytes() == b"must-survive"
    assert (displaced / ".acgs-clean-sibling-owned").is_file()


def test_uv_identity_does_not_depend_on_ambient_path() -> None:
    verifier = (EVIDENCE_SCRIPTS / "verify_environment.py").read_text(encoding="utf-8")
    validator = (EVIDENCE_SCRIPTS / "validate_environment_identities.py").read_text(
        encoding="utf-8"
    )
    prover = (EVIDENCE_SCRIPTS / "prove_clean_sibling.sh").read_text(encoding="utf-8")
    assert 'shutil.which("uv")' not in verifier
    assert 'shutil.which("uv")' not in validator
    assert '--expected-uv-executable "$UV_BIN"' in prover
    assert "TRUSTED_UV_SHA256" in verifier
    assert "a00d3a24514fc0403fc232c9c99bf5e542657c38f4ed941e0611731e4cff268b" in validator


def test_pinned_uv_execution_is_normalized_only_for_transcript_metadata() -> None:
    prover = (EVIDENCE_SCRIPTS / "prove_clean_sibling.sh").read_text(encoding="utf-8")
    common = (EVIDENCE_SCRIPTS / "_common.py").read_text(encoding="utf-8")
    normalization = 'if argv and argv[0] == "/home/martin/.local/bin/uv":\n    argv[0] = "uv"'
    assert prover.count(normalization) == 1
    assert "/home/martin/.local/bin/uv" not in common
    assert '            "uv",\n            "run",' in common
    reviewed = list(_common.REVIEWED_P0_TRANSCRIPT[5][1])
    assert reviewed[0] == "uv"
    assert _common.validate_safe_argv(reviewed) == reviewed
    with pytest.raises(_common.EvidenceError):
        _common.validate_safe_argv(["/home/martin/.local/bin/uv", *reviewed[1:]])


def test_reviewed_uv_identity_rejects_hostile_home_symlink_and_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trusted = (Path("/home") / "martin" / ".local" / "bin" / "uv").resolve(strict=True)
    monkeypatch.setenv("HOME", str(tmp_path / "hostile-home"))
    assert _common.REVIEWED_HOST_EXECUTABLES["uv"] == trusted
    assert _common.reviewed_executable(ROOT, "uv") == trusted

    lexical_symlink = tmp_path / "uv-symlink"
    lexical_symlink.symlink_to(trusted)
    monkeypatch.setitem(_common.REVIEWED_HOST_EXECUTABLES, "uv", lexical_symlink)
    with pytest.raises(_common.EvidenceError, match="lexical path must not be a symlink"):
        _common.reviewed_executable(ROOT, "uv")

    substituted = tmp_path / "uv-substituted"
    substituted.write_bytes(trusted.read_bytes() + b"substitution")
    substituted.chmod(0o755)
    monkeypatch.setitem(_common.REVIEWED_HOST_EXECUTABLES, "uv", substituted)
    assert _common.reviewed_executable(ROOT, "uv") == substituted
