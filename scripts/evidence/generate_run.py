#!/usr/bin/env python3
"""Generate a closed out-of-tree run record from immutable command transcripts."""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import subprocess
import sys
from itertools import pairwise
from pathlib import Path
from typing import Any

from _common import (
    EXPECTED_BOOTSTRAP_MAP,
    JSON_SAFE_INTEGER_MAX,
    NODE_RE,
    REVIEWED_RUN_METADATA_BY_NODE,
    TRANSCRIPT_RECORD_KEYS,
    EvidenceError,
    assert_evidence_runtime,
    assignment_tokens,
    canonical_node_evidence_path,
    fail,
    git_root,
    load_json,
    parse_utc,
    reject_outer_evidence_in_product,
    sha256_file,
    strict_json_loads,
    utc_now,
    validate_p0_transcript_sequence,
    validate_schema,
    validate_secret_free_run,
    validate_transcript_record,
    verify_git_range,
    write_json_exclusive,
)


def _read_transcript(path: Path) -> list[dict[str, Any]]:
    try:
        raw_lines = path.read_bytes().splitlines()
    except OSError as exc:
        fail(f"cannot read transcript {path}: {exc}", phase="B6")
    if not raw_lines:
        fail("transcript must contain at least one command", phase="B6")
    commands: list[dict[str, Any]] = []
    for number, raw in enumerate(raw_lines, 1):
        if not raw.strip():
            fail(f"blank transcript line {number}", phase="B6")
        value = strict_json_loads(raw)
        if not isinstance(value, dict) or set(value) != TRANSCRIPT_RECORD_KEYS:
            fail(f"transcript line {number} is not a closed command object", phase="B6")
        commands.append(validate_transcript_record(value))
    for earlier, later in pairwise(commands):
        if parse_utc(later["started_at_utc"]) < parse_utc(earlier["started_at_utc"]):
            fail("transcript command ordering is nonmonotonic", phase="B6")
    if path.parent.name == "P0-EVIDENCE-000":
        validate_p0_transcript_sequence(commands)
    return commands


def _closed_json_env(name: str, expected: Any) -> Any:
    raw = os.environ.get(name)
    if raw is None:
        return expected
    try:
        value = strict_json_loads(raw)
    except EvidenceError:
        fail(f"{name} differs from the reviewed closed node contract", phase="B6")
    if value != expected:
        fail(f"{name} differs from the reviewed closed node contract", phase="B6")
    return value


def _container_identity() -> dict[str, str]:
    cgroup = Path("/proc/1/cgroup")
    if cgroup.is_file():
        payload = cgroup.read_bytes()
        return {"kind": "linux-cgroup", "identity": hashlib.sha256(payload).hexdigest()}
    return {"kind": "none", "identity": "not-detected"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", required=True, type=Path)
    parser.add_argument("--node", required=True)
    parser.add_argument("--parent", required=True)
    parser.add_argument("--product", required=True)
    parser.add_argument("--assignment", required=True)
    parser.add_argument("--environment-identities", required=True, type=Path)
    parser.add_argument("--transcript", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        script_repo = assert_evidence_runtime(require_dependencies=True)
        repo = git_root()
        if repo != script_repo:
            fail(
                f"run generation cwd must be the product repository root: {script_repo}", phase="B6"
            )
        if NODE_RE.fullmatch(args.node) is None:
            fail("invalid NODE_ID", phase="B6")
        tokens = assignment_tokens(args.assignment)
        assignment_map = load_json(repo / "requirements/saas-beta/bootstrap-by-scope.json")
        if (
            assignment_map != EXPECTED_BOOTSTRAP_MAP
            or assignment_map.get(args.node) != args.assignment
        ):
            fail("node assignment differs from exact committed bootstrap map", phase="B6")
        verify_git_range(repo, args.parent, args.product, require_clean=True)
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo,
            text=True,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout.strip()
        if head != args.product:
            fail(f"T must be the exact checked-out HEAD: {args.product} != {head}", phase="B6")
        reject_outer_evidence_in_product(repo, args.product)

        schema = args.schema if args.schema.is_absolute() else repo / args.schema
        schema = schema.resolve(strict=True)
        expected_schema = (repo / "schemas/evidence/acgs-run-evidence-v1.schema.json").resolve(
            strict=True
        )
        if schema != expected_schema:
            fail("run schema path is noncanonical", phase="B6")
        environment_path = canonical_node_evidence_path(
            args.environment_identities,
            repo,
            node_id=args.node,
            filename="environment-identities.json",
            must_exist=True,
        )
        transcript_path = canonical_node_evidence_path(
            args.transcript,
            repo,
            node_id=args.node,
            filename="transcript.jsonl",
            must_exist=True,
        )
        output = canonical_node_evidence_path(
            args.output,
            repo,
            node_id=args.node,
            filename="run.json",
            must_exist=False,
        )

        identity_bundle = load_json(environment_path)
        expected_identity_keys = {
            "schema_version",
            "node_id",
            "assignment",
            "environment_identities",
            "pep660_editable_build",
            "ed25519_implementation",
        }
        if not isinstance(identity_bundle, dict) or set(identity_bundle) != expected_identity_keys:
            fail("environment identity bundle is not closed", phase="B6")
        if (
            identity_bundle["schema_version"] != "acgs-environment-identities/v1"
            or identity_bundle["node_id"] != args.node
            or identity_bundle["assignment"] != args.assignment
            or set(identity_bundle["environment_identities"]) != set(tokens)
        ):
            fail("environment identity bundle does not match node assignment", phase="B6")

        commands = _read_transcript(transcript_path)
        selectors: list[str] = []
        for command in commands:
            for selector in command["selectors"]:
                if selector not in selectors:
                    selectors.append(selector)
        if not selectors:
            fail("completion transcript must name at least one selector", phase="B6")

        reviewed_metadata = REVIEWED_RUN_METADATA_BY_NODE.get(args.node)
        if reviewed_metadata is None:
            fail("node lacks reviewed run metadata", phase="B6")
        process_schedule = _closed_json_env(
            "ACGS_PROCESS_SCHEDULE", list(reviewed_metadata["process_schedule"])
        )
        skipped = _closed_json_env("ACGS_SKIPPED_JSON", list(reviewed_metadata["skipped"]))
        external = _closed_json_env("ACGS_EXTERNAL_JSON", list(reviewed_metadata["external"]))
        clock_source = os.environ.get("ACGS_CLOCK_SOURCE", reviewed_metadata["clock_source"])
        if clock_source != reviewed_metadata["clock_source"]:
            fail("ACGS_CLOCK_SOURCE differs from the reviewed closed node contract", phase="B6")
        try:
            seed = int(os.environ.get("ACGS_TEST_SEED", "20260710"))
            python_hash_seed = os.environ.get("PYTHONHASHSEED", "0")
            skew_ms = int(os.environ.get("ACGS_CLOCK_SKEW_MS", "0"))
        except ValueError as exc:
            fail(f"invalid deterministic integer environment: {exc}", phase="B6")
        if not python_hash_seed.isdigit():
            fail("PYTHONHASHSEED must be a decimal integer", phase="B6")
        if not 0 <= seed <= JSON_SAFE_INTEGER_MAX:
            fail("ACGS_TEST_SEED is outside the interoperable integer range", phase="B6")
        if not -JSON_SAFE_INTEGER_MAX <= skew_ms <= JSON_SAFE_INTEGER_MAX:
            fail("ACGS_CLOCK_SKEW_MS is outside the interoperable integer range", phase="B6")

        tree_sha = subprocess.run(
            ["git", "rev-parse", f"{args.product}^{{tree}}"],
            cwd=repo,
            text=True,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout.strip()
        run = {
            "schema_version": "acgs-run-evidence/v1",
            "node_version": 1,
            "node_id": args.node,
            "parent_commit_sha": args.parent,
            "product_commit_sha": args.product,
            "git_tree_sha": tree_sha,
            "assignment": args.assignment,
            "environment_identities": identity_bundle["environment_identities"],
            "pep660_editable_build": identity_bundle["pep660_editable_build"],
            "ed25519_implementation": identity_bundle["ed25519_implementation"],
            "commands": commands,
            "selectors": selectors,
            "determinism": {
                "seed": seed,
                "python_hash_seed": python_hash_seed,
                "process_schedule": process_schedule,
            },
            "clock": {
                "source": clock_source,
                "skew_ms": skew_ms,
            },
            "platform": {
                "os": platform.system().lower(),
                "architecture": platform.machine().lower(),
                "container": _container_identity(),
            },
            "artifacts": [
                {"path": str(environment_path), "sha256": sha256_file(environment_path)},
                {"path": str(transcript_path), "sha256": sha256_file(transcript_path)},
            ],
            "skipped": skipped,
            "external": external,
            "timestamps": {
                "generated_at_utc": utc_now(),
                "transcript_started_at_utc": commands[0]["started_at_utc"],
                "transcript_finished_at_utc": commands[-1]["finished_at_utc"],
            },
        }
        validate_secret_free_run(run, expected_node=args.node)
        validate_schema(run, schema)
        write_json_exclusive(output, run)
        print(output)
        return 0
    except EvidenceError as exc:
        print(f"run generation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
