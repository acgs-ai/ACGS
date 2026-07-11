#!/usr/bin/env python3
"""Create lane-separated Ed25519 keys, custody records, trust, and attestations."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from _common import (
    ATTESTATION_ROLES,
    MAX_TRUST_WINDOW,
    NODE_RE,
    EvidenceError,
    assert_evidence_runtime,
    b64url_decode,
    b64url_encode,
    collect_custody_descriptor_bindings,
    ensure_path_outside,
    fail,
    file_mode,
    jcs_bytes,
    key_id_for_public,
    parse_utc,
    validate_custody_record,
    validate_public_descriptor,
    validate_schema,
    validate_sha256,
    write_json_exclusive,
)

ROLES = set(ATTESTATION_ROLES)
MODE_TO_ROLE = {
    "node-review": "reviewer",
    "node-verification": "verifier",
    "claims-review": "claims-reviewer",
}


def _canonical_schema(repo: Path, supplied: Path, name: str) -> Path:
    expected = (repo / "schemas/evidence" / name).resolve(strict=True)
    candidate = supplied if supplied.is_absolute() else repo / supplied
    if candidate.resolve(strict=True) != expected:
        fail(f"schema path is noncanonical: expected {expected}", phase="B6")
    return expected


def _evidence_root(repo: Path) -> Path:
    raw = os.environ.get("ACGS_EVIDENCE_ROOT")
    if not raw:
        fail("ACGS_EVIDENCE_ROOT is required for custody-sensitive commands", phase="B7")
    return ensure_path_outside(Path(raw), [repo], "ACGS_EVIDENCE_ROOT")


def _principal(value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 256:
        fail("principal must be nonempty, trimmed, and no longer than 256 characters", phase="B7")
    return value


def _canonical_output(path: Path, evidence_root: Path, label: str) -> Path:
    if not path.is_absolute():
        fail(f"{label} must be absolute", phase="B7")
    canonical = path.resolve(strict=False)
    if str(path) != str(canonical):
        fail(f"{label} must already be canonical", phase="B7")
    if canonical == evidence_root or not canonical.is_relative_to(evidence_root):
        fail(f"{label} must be beneath ACGS_EVIDENCE_ROOT", phase="B7")
    return canonical


def _public_descriptor(value: Any) -> tuple[dict[str, Any], bytes]:
    return validate_public_descriptor(value)


def _private_root_and_key(
    path: Path, repo: Path, evidence_root: Path, *, must_exist: bool
) -> tuple[Path, Path]:
    if not path.is_absolute():
        fail("private-key path must be absolute", phase="B7")
    canonical = path.resolve(strict=must_exist)
    if str(path) != str(canonical):
        fail("private-key path must already be canonical", phase="B7")
    root = canonical.parent.resolve(strict=True)
    ensure_path_outside(root, [repo, evidence_root], "canonical private root")
    if not root.is_dir() or file_mode(root) != 0o700:
        fail("canonical private root must be a mode-0700 directory", phase="B7")
    if canonical.parent != root:
        fail("private key must be a direct child of its canonical private root", phase="B7")
    if must_exist:
        metadata = canonical.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            fail("private key must be a regular non-symlink file", phase="B7")
        if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1:
            fail("private key must be uniquely linked and mode 0600", phase="B7")
    return root, canonical


def _read_private_key(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            fail("private key changed type or mode during access", phase="B7")
        raw = os.read(fd, 33)
    finally:
        os.close(fd)
    if len(raw) != 32:
        fail("Ed25519 private key must contain exactly 32 raw bytes", phase="B7")
    return raw


def _publish_key_bundle(
    private_key: Path,
    raw_private: bytes,
    public_output: Path,
    public: dict[str, Any],
    root_output: Path,
    root_descriptor: dict[str, Any],
) -> None:
    if len(raw_private) != 32:
        fail("refusing to publish a non-raw Ed25519 private key", phase="B7")
    finals = (private_key, public_output, root_output)
    if any(os.path.lexists(path) for path in finals):
        fail("keygen outputs must be absent before publication", phase="B7")
    token = f"{os.getpid()}-{secrets.token_hex(8)}"
    payloads = {
        private_key: (raw_private, 0o600),
        public_output: (
            (
                json.dumps(public, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
                + "\n"
            ).encode("utf-8"),
            0o644,
        ),
        root_output: (
            (
                json.dumps(
                    root_descriptor,
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=False,
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8"),
            0o644,
        ),
    }
    temporaries: dict[Path, tuple[Path, tuple[int, int]]] = {}
    published: list[Path] = []
    try:
        for final, (payload, mode) in payloads.items():
            temporary = final.with_name(f".{final.name}.{token}.tmp")
            if os.path.lexists(temporary):
                fail(f"keygen temporary path already exists: {temporary}", phase="B7")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(temporary, flags, mode)
            try:
                if os.write(fd, payload) != len(payload):
                    fail(f"short keygen temporary write: {temporary}", phase="B7")
                os.fsync(fd)
                metadata = os.fstat(fd)
                temporaries[final] = (temporary, (metadata.st_dev, metadata.st_ino))
            finally:
                os.close(fd)
        for final in finals:
            temporary, _ = temporaries[final]
            os.link(temporary, final, follow_symlinks=False)
            published.append(final)
        for temporary, _ in temporaries.values():
            temporary.unlink()
        private_metadata = private_key.lstat()
        if (
            not stat.S_ISREG(private_metadata.st_mode)
            or private_metadata.st_nlink != 1
            or stat.S_IMODE(private_metadata.st_mode) != 0o600
        ):
            fail("published private key inode/mode is unsafe", phase="B7")
    except BaseException:
        for final in reversed(published):
            try:
                current = final.lstat()
            except FileNotFoundError:
                continue
            if (current.st_dev, current.st_ino) == temporaries[final][1]:
                final.unlink()
        raise
    finally:
        for temporary, _ in temporaries.values():
            try:
                current = temporary.lstat()
            except FileNotFoundError:
                continue
            final = next(key for key, item in temporaries.items() if item[0] == temporary)
            if (current.st_dev, current.st_ino) == temporaries[final][1]:
                temporary.unlink()


def _keygen(args: argparse.Namespace, repo: Path) -> None:
    if args.algorithm != "ed25519" or args.role not in ROLES:
        fail("keygen accepts only algorithm ed25519 and a closed role", phase="B7")
    principal = _principal(args.principal)
    root_schema = _canonical_schema(
        repo, args.root_schema, "acgs-private-root-descriptor-v1.schema.json"
    )
    evidence_root = _evidence_root(repo)
    supplied_root = ensure_path_outside(
        args.canonical_private_root, [repo, evidence_root], "canonical private root"
    )
    if (
        not supplied_root.exists()
        or not supplied_root.is_dir()
        or file_mode(supplied_root) != 0o700
    ):
        fail("canonical private root must exist as a mode-0700 directory", phase="B7")
    key_root, private_key = _private_root_and_key(
        args.private_key, repo, evidence_root, must_exist=False
    )
    if key_root != supplied_root:
        fail("private key is not a direct child of the declared private root", phase="B7")
    public_output = _canonical_output(args.public_descriptor, evidence_root, "public descriptor")
    root_output = _canonical_output(args.root_descriptor, evidence_root, "root descriptor")
    expected_stem = args.role
    if (
        private_key.name != f"{expected_stem}.ed25519"
        or public_output.name != f"{expected_stem}-public.json"
        or root_output.name != f"{expected_stem}-root.json"
        or public_output.parent != root_output.parent
        or public_output.parent.name != "custody-inputs"
        or NODE_RE.fullmatch(public_output.parent.parent.name) is None
        or public_output.parent
        != evidence_root / public_output.parent.parent.name / "custody-inputs"
    ):
        fail("keygen paths do not match the exact role/custody naming contract", phase="B7")
    if public_output == root_output or any(
        os.path.lexists(path) for path in (private_key, public_output, root_output)
    ):
        fail("keygen outputs must be distinct and absent", phase="B7")

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    raw_public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    public = {
        "schema_version": "acgs-attestation-public-key/v1",
        "key_id": key_id_for_public(raw_public),
        "algorithm": "Ed25519",
        "role": args.role,
        "principal": principal,
        "public_key_base64url": b64url_encode(raw_public),
    }
    root_descriptor = {
        "schema_version": "acgs-private-root-descriptor/v1",
        "role": args.role,
        "canonical_private_root": str(supplied_root),
    }
    validate_schema(root_descriptor, root_schema)
    _publish_key_bundle(
        private_key,
        raw_private,
        public_output,
        public,
        root_output,
        root_descriptor,
    )
    print(f"KEYGEN=PASS role={args.role} key_id={public['key_id']}")


def _custody_preflight(args: argparse.Namespace, repo: Path) -> None:
    _canonical_schema(repo, args.root_schema, "acgs-private-root-descriptor-v1.schema.json")
    evidence_root = _evidence_root(repo)
    declared_repo = args.repo_root.resolve(strict=True)
    declared_evidence = args.evidence_root.resolve(strict=False)
    if str(args.repo_root) != str(declared_repo) or declared_repo != repo:
        fail("--repo-root must be the canonical current repository", phase="B7")
    if str(args.evidence_root) != str(declared_evidence) or declared_evidence != evidence_root:
        fail("--evidence-root must equal canonical ACGS_EVIDENCE_ROOT", phase="B7")
    if not args.reject_equal_or_nested:
        fail("--reject-equal-or-nested is mandatory", phase="B7")
    if not (2 <= len(args.root_descriptor) <= 3):
        fail("custody preflight requires two or three root descriptors", phase="B7")
    if len(args.root_descriptor) != len(set(args.root_descriptor)):
        fail("duplicate root descriptor path", phase="B7")
    required = set(args.require_role)
    if (
        not required
        or len(required) != len(args.require_role)
        or not required.issubset(ROLES)
        or required not in ({"reviewer", "verifier"}, ROLES)
    ):
        fail("custody roles differ from an exact supported role set", phase="B7")
    output = _canonical_output(args.output, evidence_root, "custody preflight output")
    expected_output = (
        "claims-custody-preflight.json"
        if required == {"reviewer", "verifier", "claims-reviewer"}
        else "custody-preflight.json"
    )
    node_dir = output.parent
    if (
        output.name != expected_output
        or NODE_RE.fullmatch(node_dir.name) is None
        or node_dir != evidence_root / node_dir.name
    ):
        fail("custody preflight output name/location is noncanonical", phase="B7")
    expected_descriptors = {node_dir / "custody-inputs" / f"{role}-root.json" for role in required}
    supplied_descriptors = {
        _canonical_output(path, evidence_root, "root descriptor input").resolve(strict=True)
        for path in args.root_descriptor
    }
    if supplied_descriptors != expected_descriptors:
        fail("custody root descriptors are not the exact same-node role paths", phase="B7")
    descriptors, _ = collect_custody_descriptor_bindings(
        repo=repo,
        evidence_root=evidence_root,
        node_dir=node_dir,
        expected_roles=required,
    )
    value = {
        "schema_version": "acgs-custody-preflight/v1",
        "node_id": node_dir.name,
        "result": "pass",
        "repo_root": str(repo),
        "evidence_root": str(evidence_root),
        "roots": descriptors,
        "equal_or_nested_rejected": True,
    }
    write_json_exclusive(output, value)
    print(f"CUSTODY_PREFLIGHT=PASS roles={','.join(sorted(required))}")


def _trust_manifest(args: argparse.Namespace, repo: Path) -> None:
    schema = _canonical_schema(repo, args.schema, "acgs-attestation-trust-v1.schema.json")
    evidence_root = _evidence_root(repo)
    if args.trust_domain != "acgs-saas-beta-local":
        fail("trust domain must be acgs-saas-beta-local", phase="B7")
    not_before = parse_utc(args.not_before)
    not_after = parse_utc(args.not_after)
    if not_before >= not_after:
        fail("trust window must have not_before < not_after", phase="B7")
    if not_after - not_before > MAX_TRUST_WINDOW:
        fail("trust window must not exceed 90 days", phase="B7")
    if not (1 <= len(args.public_descriptor) <= 3):
        fail("trust manifest requires one to three public descriptors", phase="B7")
    if len(args.public_descriptor) != len(set(args.public_descriptor)):
        fail("duplicate public descriptor path", phase="B7")
    supplied_paths = {
        _canonical_output(path, evidence_root, "public descriptor input").resolve(strict=True)
        for path in args.public_descriptor
    }
    node_dirs = {path.parent.parent for path in supplied_paths}
    if len(node_dirs) != 1:
        fail("trust public descriptors must belong to one exact node", phase="B7")
    node_dir = next(iter(node_dirs))
    if (
        NODE_RE.fullmatch(node_dir.name) is None
        or node_dir != evidence_root / node_dir.name
        or any(path.parent != node_dir / "custody-inputs" for path in supplied_paths)
    ):
        fail("trust public descriptors must use exact same-node custody paths", phase="B7")
    roles = {
        path.name[: -len("-public.json")]
        for path in supplied_paths
        if path.name.endswith("-public.json")
    }
    if len(roles) != len(supplied_paths):
        fail("trust public descriptor filenames are outside the closed role contract", phase="B7")
    if roles == {"reviewer", "verifier"}:
        expected_name = "trust-roots.json"
        custody_roles = {"reviewer", "verifier"}
        preflight_name = "custody-preflight.json"
    elif roles == {"claims-reviewer"}:
        expected_name = "claims-trust-roots.json"
        custody_roles = set(ROLES)
        preflight_name = "claims-custody-preflight.json"
    else:
        fail(f"trust input roles are not a closed supported set: {sorted(roles)}", phase="B7")
    expected_paths = {node_dir / "custody-inputs" / f"{role}-public.json" for role in roles}
    if supplied_paths != expected_paths:
        fail("trust public descriptors do not match their exact role paths", phase="B7")
    _, _, custody_public = validate_custody_record(
        node_dir / preflight_name,
        repo=repo,
        evidence_root=evidence_root,
        node_dir=node_dir,
        expected_roles=custody_roles,
        expected_name=preflight_name,
    )

    keys: list[dict[str, Any]] = []
    key_ids: set[str] = set()
    principals: set[str] = set()
    public_values: set[bytes] = set()
    for role in sorted(roles):
        captured = custody_public[role]
        descriptor = captured["descriptor"]
        raw_public = captured["raw_public"]
        if descriptor["principal"] in principals:
            fail("duplicate principal in trust input", phase="B7")
        if raw_public in public_values:
            fail("duplicate key material in trust input", phase="B7")
        if descriptor["key_id"] in key_ids:
            fail("duplicate key id in trust input", phase="B7")
        principals.add(descriptor["principal"])
        public_values.add(raw_public)
        key_ids.add(descriptor["key_id"])
        keys.append(
            {
                "key_id": descriptor["key_id"],
                "algorithm": "Ed25519",
                "role": role,
                "principal": descriptor["principal"],
                "public_key_base64url": descriptor["public_key_base64url"],
                "not_before_utc": args.not_before,
                "not_after_utc": args.not_after,
                "status": "trusted",
            }
        )
    value = {
        "schema_version": "acgs-attestation-trust/v1",
        "trust_domain": args.trust_domain,
        "keys": sorted(keys, key=lambda item: (item["role"], item["key_id"])),
    }
    validate_schema(value, schema)
    output = _canonical_output(args.output, evidence_root, "trust manifest output")
    if output.name != expected_name or output.parent != node_dir:
        fail(
            f"trust manifest output must be exact node path {node_dir / expected_name}",
            phase="B7",
        )
    if roles == {"claims-reviewer"}:
        claims_key = keys[0]
        claims_raw = b64url_decode(
            claims_key["public_key_base64url"],
            expected_length=32,
            label="claims-reviewer public key",
        )
        for node_role in ("reviewer", "verifier"):
            descriptor = custody_public[node_role]["descriptor"]
            raw = custody_public[node_role]["raw_public"]
            if (
                descriptor["principal"] == claims_key["principal"]
                or descriptor["key_id"] == claims_key["key_id"]
                or raw == claims_raw
            ):
                fail("claims trust identity/key reuses a node review lane", phase="B7")
    write_json_exclusive(output, value)
    print(f"TRUST_MANIFEST=PASS keys={len(keys)}")


def _sign(args: argparse.Namespace, repo: Path) -> None:
    schema = _canonical_schema(repo, args.schema, "acgs-attestation-v1.schema.json")
    evidence_root = _evidence_root(repo)
    if MODE_TO_ROLE.get(args.mode) != args.role:
        fail("attestation mode and role mismatch", phase="B7")
    principal = _principal(args.principal)
    if args.parent == args.product:
        fail("attestation P and T must be distinct", phase="B7")
    from _common import GIT_SHA1_RE

    if GIT_SHA1_RE.fullmatch(args.parent) is None or GIT_SHA1_RE.fullmatch(args.product) is None:
        fail("attestation P/T must be lowercase 40-hex commit SHAs", phase="B7")
    validate_sha256(args.run_hash, "attestation R")
    signed_at = parse_utc(args.timestamp)
    if signed_at > datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=5):
        fail("attestation timestamp exceeds the five-minute future-skew bound", phase="B7")
    _, private_path = _private_root_and_key(args.private_key, repo, evidence_root, must_exist=True)
    if private_path.name != f"{args.role}.ed25519":
        fail("private key filename differs from its signing role", phase="B7")
    raw_private = _read_private_key(private_path)

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.from_private_bytes(raw_private)
    raw_public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    unsigned = {
        "schema_version": "acgs-attestation/v1",
        "algorithm": "Ed25519",
        "mode": args.mode,
        "key_id": key_id_for_public(raw_public),
        "role": args.role,
        "principal": principal,
        "parent_commit_sha": args.parent,
        "product_commit_sha": args.product,
        "run_hash": args.run_hash,
        "verdict": args.verdict,
        "timestamp_utc": args.timestamp,
    }
    signed = {**unsigned, "signature": b64url_encode(private.sign(jcs_bytes(unsigned)))}
    validate_schema(signed, schema)
    output = _canonical_output(args.output, evidence_root, "attestation output")
    expected_name = {
        "node-review": "review-attestation.json",
        "node-verification": "verification-attestation.json",
        "claims-review": "claims-review-attestation.json",
    }[args.mode]
    if (
        output.name != expected_name
        or NODE_RE.fullmatch(output.parent.name) is None
        or output.parent != evidence_root / output.parent.name
    ):
        fail(f"attestation output must be exact node path */<NODE>/{expected_name}", phase="B7")
    write_json_exclusive(output, signed)
    print(f"ATTESTATION_SIGN=PASS mode={args.mode} key_id={signed['key_id']}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser("keygen")
    keygen.add_argument("--root-schema", required=True, type=Path)
    keygen.add_argument("--algorithm", required=True)
    keygen.add_argument("--role", required=True, choices=sorted(ROLES))
    keygen.add_argument("--principal", required=True)
    keygen.add_argument("--private-key", required=True, type=Path)
    keygen.add_argument("--public-descriptor", required=True, type=Path)
    keygen.add_argument("--canonical-private-root", required=True, type=Path)
    keygen.add_argument("--root-descriptor", required=True, type=Path)

    custody = subparsers.add_parser("custody-preflight")
    custody.add_argument("--root-schema", required=True, type=Path)
    custody.add_argument("--repo-root", required=True, type=Path)
    custody.add_argument("--evidence-root", required=True, type=Path)
    custody.add_argument("--root-descriptor", action="append", required=True, type=Path)
    custody.add_argument("--require-role", action="append", required=True)
    custody.add_argument("--reject-equal-or-nested", action="store_true")
    custody.add_argument("--output", required=True, type=Path)

    trust = subparsers.add_parser("trust-manifest")
    trust.add_argument("--schema", required=True, type=Path)
    trust.add_argument("--trust-domain", required=True)
    trust.add_argument("--public-descriptor", action="append", required=True, type=Path)
    trust.add_argument("--not-before", required=True)
    trust.add_argument("--not-after", required=True)
    trust.add_argument("--output", required=True, type=Path)

    sign = subparsers.add_parser("sign")
    sign.add_argument("--schema", required=True, type=Path)
    sign.add_argument("--mode", required=True, choices=sorted(MODE_TO_ROLE))
    sign.add_argument("--role", required=True, choices=sorted(ROLES))
    sign.add_argument("--principal", required=True)
    sign.add_argument("--private-key", required=True, type=Path)
    sign.add_argument("--parent", required=True)
    sign.add_argument("--product", required=True)
    sign.add_argument("--run-hash", required=True)
    sign.add_argument("--verdict", required=True, choices=("approve", "reject"))
    sign.add_argument("--timestamp", required=True)
    sign.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        repo = assert_evidence_runtime(require_dependencies=True)
        handlers = {
            "keygen": _keygen,
            "custody-preflight": _custody_preflight,
            "trust-manifest": _trust_manifest,
            "sign": _sign,
        }
        handlers[args.command](args, repo)
        return 0
    except (EvidenceError, OSError) as exc:
        print(f"attestation command failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
