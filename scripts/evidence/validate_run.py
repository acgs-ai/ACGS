#!/usr/bin/env python3
"""Validate a run record against its node assignment, live locks, and Git range."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Any

from _common import (
    CODE_PATHS,
    EXPECTED_BOOTSTRAP_MAP,
    EvidenceError,
    assert_evidence_runtime,
    assignment_tokens,
    canonical_node_evidence_path,
    fail,
    git_root,
    load_json,
    parse_lock,
    parse_utc,
    reject_outer_evidence_in_product,
    sha256_file,
    validate_schema,
    validate_secret_free_run,
    verify_git_range,
)


def _load_map(path: Path) -> dict[str, str]:
    value = load_json(path)
    if not isinstance(value, dict) or len(value) != 28:
        fail("assignment map must be the exact closed 28-node map", phase="B6")
    for node, assignment in value.items():
        if not isinstance(node, str) or not isinstance(assignment, str):
            fail("assignment map contains non-string data", phase="B6")
        assignment_tokens(assignment)
    if value != EXPECTED_BOOTSTRAP_MAP:
        fail("assignment map differs from exact reviewed 28-node map", phase="B6")
    return value


def _reject_product_evidence_runners(run: dict[str, Any], repo_root: Path) -> None:
    expected_lexical = repo_root / ".venv-evidence/bin/python"
    expected = expected_lexical.resolve(strict=True)
    product_fragments = (
        "packages/acgs-control-plane/.venv/bin/python",
        "packages/gove-zone/.venv-beta/bin/python",
    )
    for command in run["commands"]:
        argv = command["argv"]
        if any(fragment in arg for fragment in product_fragments for arg in argv) and any(
            "scripts/evidence/" in arg for arg in argv
        ):
            fail("product interpreter recorded as evidence-script runner", phase="B6")
        if any("scripts/evidence/" in arg for arg in argv):
            executable = Path(argv[0])
            if (
                not executable.is_absolute()
                or str(executable) != str(expected_lexical)
                or executable.resolve(strict=True) != expected
            ):
                fail("evidence command used a non-EVID interpreter", phase="B6")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", required=True, type=Path)
    parser.add_argument("--expected-node", required=True)
    parser.add_argument("--assignment-map", required=True, type=Path)
    parser.add_argument("--expected-environments", required=True)
    parser.add_argument("--expected-parent", required=True)
    parser.add_argument("--expected-product", required=True)
    parser.add_argument("run", type=Path)
    args = parser.parse_args(argv)
    try:
        script_repo = assert_evidence_runtime(require_dependencies=True)
        repo = git_root()
        if repo != script_repo:
            fail("run validation must execute from REPO_ROOT", phase="B6")
        schema = args.schema if args.schema.is_absolute() else repo / args.schema
        schema = schema.resolve(strict=True)
        if schema != (repo / "schemas/evidence/acgs-run-evidence-v1.schema.json").resolve(
            strict=True
        ):
            fail("run schema path is noncanonical", phase="B6")
        assignment_path = (
            args.assignment_map if args.assignment_map.is_absolute() else repo / args.assignment_map
        ).resolve(strict=True)
        if assignment_path != (repo / "requirements/saas-beta/bootstrap-by-scope.json").resolve(
            strict=True
        ):
            fail("assignment map path is noncanonical", phase="B6")
        assignment_map = _load_map(assignment_path)
        if assignment_map.get(args.expected_node) != args.expected_environments:
            fail("expected environments do not equal committed assignment", phase="B6")
        tokens = assignment_tokens(args.expected_environments)

        run_path = canonical_node_evidence_path(
            args.run,
            repo,
            node_id=args.expected_node,
            filename="run.json",
            must_exist=True,
        )
        run = load_json(run_path)
        validate_secret_free_run(run, expected_node=args.expected_node)
        validate_schema(run, schema)
        timestamps = run["timestamps"]
        generated_at = parse_utc(timestamps["generated_at_utc"])
        transcript_started = parse_utc(timestamps["transcript_started_at_utc"])
        transcript_finished = parse_utc(timestamps["transcript_finished_at_utc"])
        if not transcript_started <= transcript_finished <= generated_at:
            fail("run-level timestamp ordering is invalid", phase="B6")
        if (
            timestamps["transcript_started_at_utc"] != run["commands"][0]["started_at_utc"]
            or timestamps["transcript_finished_at_utc"] != run["commands"][-1]["finished_at_utc"]
        ):
            fail("run-level timestamps differ from immutable transcript bounds", phase="B6")
        if (
            run["node_id"] != args.expected_node
            or run["assignment"] != args.expected_environments
            or run["parent_commit_sha"] != args.expected_parent
            or run["product_commit_sha"] != args.expected_product
        ):
            fail("run node/P/T/assignment binding mismatch", phase="B6")
        if set(run["environment_identities"]) != set(tokens):
            fail("run environment identities are missing or extra", phase="B6")
        for code, identity in run["environment_identities"].items():
            if identity.get("code") != code or identity.get("node_id") != args.expected_node:
                fail(f"run contains copied/fabricated {code} identity", phase="B6")
            source_path = canonical_node_evidence_path(
                run_path.parent / f"environment-{code}.json",
                repo,
                node_id=args.expected_node,
                filename=f"environment-{code}.json",
                must_exist=True,
            )
            if load_json(source_path) != identity:
                fail(
                    f"run contains an identity differing from executed {code} evidence", phase="B6"
                )
            interpreter_rel, lock_rel = CODE_PATHS[code]
            lock_path = (repo / lock_rel).resolve(strict=True)
            if identity["lock"].get("path") != lock_rel or identity["lock"].get(
                "sha256"
            ) != sha256_file(lock_path):
                fail(f"run {code} lock path/hash mismatch", phase="B6")
            if code != "UI" and identity["lock"].get("distributions") != parse_lock(lock_path):
                fail(f"run {code} lock distribution/hash map mismatch", phase="B6")
            if code in {"EVID", "CP", "GZ"} and identity.get("interpreter") != str(
                repo / interpreter_rel
            ):
                fail(f"run {code} interpreter is noncanonical", phase="B6")
        expected_helpers = {code for code in tokens if code in {"CP", "GZ"}}
        if set(run["pep660_editable_build"]["environments"]) != expected_helpers:
            fail("run PEP660 environment map is not assignment-derived", phase="B6")
        if "EVID" in run["pep660_editable_build"]["environments"]:
            fail("EVID cannot appear as a PEP660 product environment", phase="B6")
        for code in expected_helpers:
            source_helper = run["environment_identities"][code]["pep660_editable_build"]
            aggregate = run["pep660_editable_build"]["environments"][code]
            if aggregate != {
                "module_path": source_helper["module_path"],
                "product_lock_sha256": source_helper["lock_sha256"],
                "artifact_hashes": source_helper["artifact_hashes"],
            }:
                fail(f"run {code} PEP660 aggregate differs from live identity", phase="B6")

        evid_lock = repo / "requirements/saas-beta/evidence-test.lock"
        cryptography = parse_lock(evid_lock).get("cryptography")
        ed = run["ed25519_implementation"]
        if (
            cryptography is None
            or ed["distribution"] != "cryptography"
            or ed["module"] != "cryptography.hazmat.primitives.asymmetric.ed25519"
            or ed["version"] != cryptography["version"]
            or ed["artifact_hashes"] != cryptography["artifact_hashes"]
            or ed["evidence_test_lock_sha256"] != sha256_file(evid_lock)
        ):
            fail("run Ed25519 implementation is not EVID lock-bound cryptography", phase="B6")

        identity_bundle_path = canonical_node_evidence_path(
            run_path.parent / "environment-identities.json",
            repo,
            node_id=args.expected_node,
            filename="environment-identities.json",
            must_exist=True,
        )
        identity_bundle = load_json(identity_bundle_path)
        if (
            identity_bundle.get("environment_identities") != run["environment_identities"]
            or identity_bundle.get("pep660_editable_build") != run["pep660_editable_build"]
            or identity_bundle.get("ed25519_implementation") != run["ed25519_implementation"]
        ):
            fail("run identities differ from validated identity bundle", phase="B6")

        artifact_paths: set[str] = set()
        for artifact in run["artifacts"]:
            path = Path(artifact["path"])
            if (
                not path.is_absolute()
                or not path.is_file()
                or path.resolve(strict=True).is_relative_to(repo)
            ):
                fail(f"run artifact path is unsafe/missing: {path}", phase="B6")
            if artifact["sha256"] != sha256_file(path) or str(path) in artifact_paths:
                fail(f"run artifact digest/uniqueness mismatch: {path}", phase="B6")
            artifact_paths.add(str(path))
        if str(identity_bundle_path) not in artifact_paths:
            fail("run artifact list omits environment-identities.json", phase="B6")

        selectors: list[str] = []
        for command in run["commands"]:
            if command["exit_code"] != 0:
                fail("run completion command has nonzero exit", phase="B6")
            if parse_utc(command["finished_at_utc"]) < parse_utc(command["started_at_utc"]):
                fail("run command timestamp order invalid", phase="B6")
            for selector in command["selectors"]:
                if selector not in selectors:
                    selectors.append(selector)
        if selectors != run["selectors"]:
            fail("run selector index differs from immutable command transcript", phase="B6")
        _reject_product_evidence_runners(run, repo)

        verify_git_range(repo, args.expected_parent, args.expected_product, require_clean=True)
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True, stdout=subprocess.PIPE, check=True
        ).stdout.strip()
        tree = subprocess.run(
            ["git", "rev-parse", f"{args.expected_product}^{{tree}}"],
            cwd=repo,
            text=True,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout.strip()
        if head != args.expected_product or run.get("git_tree_sha") != tree:
            fail("run T/tree identity does not match checked-out immutable product", phase="B6")
        reject_outer_evidence_in_product(repo, args.expected_product)
        print(f"RUN_VALIDATION=PASS node={args.expected_node} environments={'+'.join(tokens)}")
        return 0
    except EvidenceError as exc:
        print(f"run validation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
