#!/usr/bin/env python3
"""Validate explicit local trust and Ed25519 attestations over exact (P,T,R)."""

from __future__ import annotations

import argparse
import os
import stat
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from _common import (
    GIT_SHA1_RE,
    MAX_TRUST_WINDOW,
    NODE_RE,
    EvidenceError,
    assert_evidence_runtime,
    b64url_decode,
    ensure_path_outside,
    fail,
    jcs_bytes,
    key_id_for_public,
    load_json,
    parse_utc,
    read_regular_nofollow,
    reject_outer_evidence_in_product,
    sha256_bytes,
    strict_json_loads,
    validate_custody_record,
    validate_schema,
    validate_secret_free_run,
    validate_sha256,
    verify_git_range,
    write_json_exclusive,
)

MODE_CONTRACT = {
    "node-pair": {
        "node-review": "reviewer",
        "node-verification": "verifier",
    },
    "claims-review": {"claims-review": "claims-reviewer"},
}


def _canonical_schema(repo: Path, supplied: Path, name: str) -> Path:
    expected = (repo / "schemas/evidence" / name).resolve(strict=True)
    candidate = supplied if supplied.is_absolute() else repo / supplied
    if candidate.resolve(strict=True) != expected:
        fail(f"schema path is noncanonical: expected {expected}", phase="B7")
    return expected


def _evidence_root(repo: Path) -> Path:
    raw = os.environ.get("ACGS_EVIDENCE_ROOT")
    if not raw:
        fail("ACGS_EVIDENCE_ROOT is required for attestation validation", phase="B7")
    return ensure_path_outside(Path(raw), [repo], "ACGS_EVIDENCE_ROOT")


def _outer_file(path: Path, evidence_root: Path, name: str | None = None) -> Path:
    if not path.is_absolute():
        fail(f"outer evidence path must be absolute: {path}", phase="B7")
    canonical = path.resolve(strict=True)
    if str(path) != str(canonical):
        fail(f"outer evidence path must already be canonical: {path}", phase="B7")
    if canonical == evidence_root or not canonical.is_relative_to(evidence_root):
        fail(f"outer evidence escaped ACGS_EVIDENCE_ROOT: {canonical}", phase="B7")
    if name is not None and canonical.name != name:
        fail(f"outer evidence filename must be {name}: {canonical}", phase="B7")
    metadata = canonical.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        fail(f"outer evidence is not a regular file: {canonical}", phase="B7")
    return canonical


def _output_path(path: Path, evidence_root: Path, parent: Path, name: str) -> Path:
    if not path.is_absolute():
        fail("validation output must be absolute", phase="B7")
    canonical = path.resolve(strict=False)
    if str(path) != str(canonical) or canonical.parent != parent or canonical.name != name:
        fail(f"validation output path is noncanonical: {path}", phase="B7")
    if not canonical.is_relative_to(evidence_root):
        fail("validation output escaped ACGS_EVIDENCE_ROOT", phase="B7")
    return canonical


def _validate_digest(trust_path: Path, digest_name: str) -> tuple[bytes, Path, str]:
    trust_bytes = read_regular_nofollow(trust_path, "trust roots")
    trust_sha256 = sha256_bytes(trust_bytes)
    digest_path = trust_path.with_name(digest_name)
    if digest_path.is_symlink():
        fail("mandatory trust digest must not be a symlink", phase="B7")
    try:
        payload = read_regular_nofollow(digest_path, "trust digest").decode("ascii")
    except UnicodeError as exc:
        fail(f"mandatory trust digest missing/unreadable: {exc}", phase="B7")
    expected = f"{trust_sha256}  {trust_path.name}\n"
    if payload != expected:
        fail("mandatory trust digest is malformed or does not match trust roots", phase="B7")
    canonical_digest = digest_path.resolve(strict=True)
    if canonical_digest.parent != trust_path.parent:
        fail("mandatory trust digest escaped its exact node directory", phase="B7")
    return trust_bytes, canonical_digest, trust_sha256


def _validate_custody_preflight(
    path: Path,
    *,
    repo: Path,
    evidence_root: Path,
    expected_roles: set[str],
) -> tuple[dict[str, Any], str, dict[str, dict[str, Any]]]:
    return validate_custody_record(
        path,
        repo=repo,
        evidence_root=evidence_root,
        node_dir=path.parent,
        expected_roles=expected_roles,
        expected_name=path.name,
    )


def _validate_trust(
    value: Any,
    schema: Path,
    expected_roles: set[str],
    *,
    validation_time: datetime,
) -> dict[str, dict[str, Any]]:
    validate_schema(value, schema)
    if value["trust_domain"] != "acgs-saas-beta-local":
        fail("unexpected trust domain", phase="B7")
    keys: dict[str, dict[str, Any]] = {}
    principals: set[str] = set()
    public_material: set[bytes] = set()
    roles: set[str] = set()
    for entry in value["keys"]:
        raw_public = b64url_decode(
            entry["public_key_base64url"], expected_length=32, label="trusted public key"
        )
        if entry["key_id"] != key_id_for_public(raw_public):
            fail("trusted key id does not match public key", phase="B7")
        not_before = parse_utc(entry["not_before_utc"])
        not_after = parse_utc(entry["not_after_utc"])
        if not_before >= not_after:
            fail("trusted key window has invalid ordering", phase="B7")
        if not_after - not_before > MAX_TRUST_WINDOW:
            fail("trusted key window exceeds 90 days", phase="B7")
        if not (not_before <= validation_time <= not_after):
            fail("trusted key window is not active or expired", phase="B7")
        if entry["status"] != "trusted":
            fail(f"key is not trusted: {entry['key_id']}", phase="B7")
        if (
            entry["key_id"] in keys
            or entry["principal"] in principals
            or raw_public in public_material
            or entry["role"] in roles
        ):
            fail("trust manifest contains duplicate identity/material/role", phase="B7")
        principals.add(entry["principal"])
        public_material.add(raw_public)
        roles.add(entry["role"])
        keys[entry["key_id"]] = {**entry, "_raw_public": raw_public}
    if roles != expected_roles:
        fail(
            f"trust roles differ from exact validation mode: expected={sorted(expected_roles)} "
            f"observed={sorted(roles)}",
            phase="B7",
        )
    return keys


def _validate_envelope(
    envelope: Any,
    schema: Path,
    trust: dict[str, dict[str, Any]],
    *,
    mode: str,
    role: str,
    parent: str,
    product: str,
    run_hash: str,
    forbidden_principals: set[str],
    validation_time: datetime,
) -> dict[str, str]:
    validate_schema(envelope, schema)
    if (
        envelope["mode"] != mode
        or envelope["role"] != role
        or envelope["parent_commit_sha"] != parent
        or envelope["product_commit_sha"] != product
        or envelope["run_hash"] != run_hash
        or envelope["verdict"] != "approve"
    ):
        fail("attestation mode/role/(P,T,R)/verdict mismatch", phase="B7")
    if envelope["principal"] in forbidden_principals:
        fail(f"forbidden attestation principal: {envelope['principal']}", phase="B7")
    trusted = trust.get(envelope["key_id"])
    if trusted is None:
        fail(f"attestation key is untrusted: {envelope['key_id']}", phase="B7")
    if trusted["algorithm"] != "Ed25519" or (trusted["role"], trusted["principal"]) != (
        role,
        envelope["principal"],
    ):
        fail("attestation identity differs from trusted identity", phase="B7")
    signed_at = parse_utc(envelope["timestamp_utc"])
    if not (
        parse_utc(trusted["not_before_utc"]) <= signed_at <= parse_utc(trusted["not_after_utc"])
    ):
        fail("attestation timestamp falls outside trusted key window", phase="B7")
    if signed_at > validation_time + timedelta(minutes=5):
        fail("attestation timestamp exceeds the five-minute future-skew bound", phase="B7")
    signature = b64url_decode(envelope["signature"], expected_length=64, label="signature")
    unsigned = {key: value for key, value in envelope.items() if key != "signature"}

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    public = Ed25519PublicKey.from_public_bytes(trusted["_raw_public"])
    try:
        public.verify(signature, jcs_bytes(unsigned))
    except InvalidSignature:
        fail("Ed25519 signature verification failed", phase="B7")
    return {
        "mode": mode,
        "role": role,
        "principal": envelope["principal"],
        "key_id": envelope["key_id"],
        "verdict": envelope["verdict"],
        "timestamp_utc": envelope["timestamp_utc"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=sorted(MODE_CONTRACT))
    parser.add_argument("--schema", required=True, type=Path)
    parser.add_argument("--trust-schema", required=True, type=Path)
    parser.add_argument("--expected-parent", required=True)
    parser.add_argument("--expected-product", required=True)
    parser.add_argument("--expected-run-hash", required=True)
    parser.add_argument("--review", type=Path)
    parser.add_argument("--verification", type=Path)
    parser.add_argument("--claims-review", type=Path)
    parser.add_argument("--trust-roots", required=True, type=Path)
    parser.add_argument("--require-distinct-principals", action="store_true")
    parser.add_argument("--require-distinct-key-ids", action="store_true")
    parser.add_argument("--forbid-principal", action="append", default=[])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        validation_time = datetime.now(UTC).replace(microsecond=0)
        repo = assert_evidence_runtime(require_dependencies=True)
        evidence_root = _evidence_root(repo)
        schema = _canonical_schema(repo, args.schema, "acgs-attestation-v1.schema.json")
        trust_schema = _canonical_schema(
            repo, args.trust_schema, "acgs-attestation-trust-v1.schema.json"
        )
        if (
            GIT_SHA1_RE.fullmatch(args.expected_parent) is None
            or GIT_SHA1_RE.fullmatch(args.expected_product) is None
            or args.expected_parent == args.expected_product
        ):
            fail("expected P/T must be distinct lowercase 40-hex commits", phase="B7")
        validate_sha256(args.expected_run_hash, "expected R")
        forbidden = set(args.forbid_principal)
        if len(forbidden) != len(args.forbid_principal) or any(
            not item or item != item.strip() for item in forbidden
        ):
            fail("forbidden principals must be unique, nonempty, and trimmed", phase="B7")

        expected_contract = MODE_CONTRACT[args.mode]
        if args.mode == "node-pair":
            if args.review is None or args.verification is None or args.claims_review is not None:
                fail("node-pair requires only review and verification attestations", phase="B7")
            if not args.require_distinct_principals or not args.require_distinct_key_ids:
                fail("node-pair requires distinct-principal and distinct-key-id gates", phase="B7")
            if len(forbidden) != 1:
                fail("node-pair requires exactly one actual author principal exclusion", phase="B7")
            attestation_paths = {
                "node-review": _outer_file(args.review, evidence_root, "review-attestation.json"),
                "node-verification": _outer_file(
                    args.verification, evidence_root, "verification-attestation.json"
                ),
            }
            trust_name = "trust-roots.json"
            digest_name = "trust-roots.sha256"
            output_name = "attestation-validation.json"
        else:
            if (
                args.claims_review is None
                or args.review is not None
                or args.verification is not None
            ):
                fail("claims-review requires only the claims-review attestation", phase="B7")
            if args.require_distinct_principals or args.require_distinct_key_ids:
                fail("claims-review does not accept node-pair distinctness flags", phase="B7")
            if len(forbidden) != 3:
                fail(
                    "claims-review requires exact claims-author/reviewer/verifier exclusions",
                    phase="B7",
                )
            attestation_paths = {
                "claims-review": _outer_file(
                    args.claims_review, evidence_root, "claims-review-attestation.json"
                )
            }
            trust_name = "claims-trust-roots.json"
            digest_name = "claims-trust-roots.sha256"
            output_name = "claims-attestation-validation.json"

        trust_path = _outer_file(args.trust_roots, evidence_root, trust_name)
        common_parent = trust_path.parent
        if (
            NODE_RE.fullmatch(common_parent.name) is None
            or common_parent != evidence_root / common_parent.name
        ):
            fail("trust roots must be in exact ACGS_EVIDENCE_ROOT/<NODE_ID>", phase="B7")
        if any(path.parent != common_parent for path in attestation_paths.values()):
            fail("attestations and trust roots must share one node evidence directory", phase="B7")
        trust_bytes, digest_path, trust_sha256 = _validate_digest(trust_path, digest_name)
        output = _output_path(args.output, evidence_root, common_parent, output_name)
        preflight_name = (
            "custody-preflight.json"
            if args.mode == "node-pair"
            else "claims-custody-preflight.json"
        )
        preflight_path = _outer_file(common_parent / preflight_name, evidence_root, preflight_name)
        preflight_roles = (
            {"reviewer", "verifier"}
            if args.mode == "node-pair"
            else {"reviewer", "verifier", "claims-reviewer"}
        )
        _, preflight_sha256, custody_public = _validate_custody_preflight(
            preflight_path,
            repo=repo,
            evidence_root=evidence_root,
            expected_roles=preflight_roles,
        )

        run_path = _outer_file(common_parent / "run.json", evidence_root, "run.json")
        run = load_json(run_path)
        run_schema = (repo / "schemas/evidence/acgs-run-evidence-v1.schema.json").resolve(
            strict=True
        )
        validate_secret_free_run(run, expected_node=common_parent.name)
        validate_schema(run, run_schema)
        actual_run_hash = sha256_bytes(jcs_bytes(run))
        if (
            actual_run_hash != args.expected_run_hash
            or run["parent_commit_sha"] != args.expected_parent
            or run["product_commit_sha"] != args.expected_product
            or run["node_id"] != common_parent.name
        ):
            fail("run.json does not reproduce expected node/(P,T,R)", phase="B7")

        trust = _validate_trust(
            strict_json_loads(trust_bytes),
            trust_schema,
            set(expected_contract.values()),
            validation_time=validation_time,
        )
        for trusted in trust.values():
            captured = custody_public.get(trusted["role"])
            if (
                captured is None
                or trusted["principal"] != captured["descriptor"]["principal"]
                or trusted["key_id"] != captured["descriptor"]["key_id"]
                or trusted["_raw_public"] != captured["raw_public"]
            ):
                fail("trust manifest differs from current bound custody descriptors", phase="B7")
        if args.mode == "claims-review":
            claims_key = next(iter(trust.values()))
            node_lane_principals: set[str] = set()
            for role in ("reviewer", "verifier"):
                descriptor = custody_public[role]["descriptor"]
                node_lane_principals.add(descriptor["principal"])
                descriptor_raw = custody_public[role]["raw_public"]
                if (
                    descriptor.get("principal") == claims_key["principal"]
                    or descriptor.get("key_id") == claims_key["key_id"]
                    or descriptor_raw == claims_key["_raw_public"]
                ):
                    fail("claims trust identity/key reuses a node review lane", phase="B7")
            if not node_lane_principals.issubset(forbidden):
                fail(
                    "claims exclusions must include exact reviewer/verifier principals",
                    phase="B7",
                )
        validated: list[dict[str, str]] = []
        for mode, role in expected_contract.items():
            validated.append(
                _validate_envelope(
                    load_json(attestation_paths[mode]),
                    schema,
                    trust,
                    mode=mode,
                    role=role,
                    parent=args.expected_parent,
                    product=args.expected_product,
                    run_hash=args.expected_run_hash,
                    forbidden_principals=forbidden,
                    validation_time=validation_time,
                )
            )
        if args.mode == "node-pair":
            if len({item["principal"] for item in validated}) != 2:
                fail("review and verification principals are not distinct", phase="B7")
            if len({item["key_id"] for item in validated}) != 2:
                fail("review and verification key ids are not distinct", phase="B7")

        verify_git_range(repo, args.expected_parent, args.expected_product, require_clean=True)
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo,
            text=True,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout.strip()
        if head != args.expected_product:
            fail("validated T is not the checked-out immutable HEAD", phase="B7")
        reject_outer_evidence_in_product(repo, args.expected_product)

        result = {
            "schema_version": "acgs-attestation-validation/v1",
            "result": "valid",
            "mode": args.mode,
            "parent_commit_sha": args.expected_parent,
            "product_commit_sha": args.expected_product,
            "run_hash": args.expected_run_hash,
            "trust_roots": {
                "path": str(trust_path),
                "sha256": trust_sha256,
                "digest_path": str(digest_path),
            },
            "custody_preflight": {
                "path": str(preflight_path),
                "sha256": preflight_sha256,
            },
            "attestations": sorted(validated, key=lambda item: item["mode"]),
            "validated_at_utc": validation_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        write_json_exclusive(output, result)
        print(f"ATTESTATION_VALIDATION=PASS mode={args.mode}")
        return 0
    except (EvidenceError, OSError, subprocess.SubprocessError) as exc:
        print(f"attestation validation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
