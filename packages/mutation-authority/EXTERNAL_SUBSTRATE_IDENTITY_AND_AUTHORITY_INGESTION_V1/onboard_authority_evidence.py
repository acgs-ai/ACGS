#!/usr/bin/env python3
"""REAL_AUTHORITY_EVIDENCE_ONBOARDING_V1 — controlled onboarding pipeline.

Drives one real authority artifact through the gated lifecycle:

    DISCOVERED --(human validation attestation)--> VALIDATED
    VALIDATED  --(receipted ingest)-->             INGESTED / ACTIVE

Fail-closed gates, in order:
  1. the source document must exist; its sha256 must match the record;
  2. the record must satisfy the per-class real-artifact contract
     (controller: appointing party; counsel: jurisdiction, appointment
     authority, verification metadata);
  3. the record must carry a well-formed validation attestation whose
     `record_binding` matches the record content — the human/legal judgment
     this software refuses to synthesize. Without it the artifact stays
     DISCOVERED and is NOT ingested;
  4. ingest is delegated to the receipted, idempotent V1 ingest path.

`--emit-binding` prints the `record_binding` digest a validator must include in
their attestation. Computing the digest is mechanical; signing the attestation
is not — this tool never writes a `validation` block itself.

Gate 3b (VALIDATOR_TRUST_GOVERNANCE_V1): the attestation's validator must be
registered, authorized for the evidence class, valid at attestation time, and
the attestation signature intact — else exit 5 (registry untouched).

Exit codes: 0 onboarded (or idempotent) · 3 rejected (contract/digest/conflict)
· 4 not validated (stays DISCOVERED) · 5 validator trust failed · 2 operational
error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

import ingest_authority_evidence as ingest
import validator_trust as VT
from _canonical import sha256_hex
from _registry import REGISTRY_NAME, read_registry
from authority_lifecycle import (
    OnboardingError,
    attestation_binding,
    has_valid_attestation,
    revoked_ids_of,
    superseded_ids_of,
    validate_onboarding_record,
)
from authority_receipt import load_or_create_key, require_substrate_binding

HERE = Path(__file__).resolve().parent


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Onboard one real authority artifact.")
    ap.add_argument("--record", required=True, help="JSON evidence record")
    ap.add_argument("--document", required=True, help="the real source artifact (bytes hashed)")
    ap.add_argument("--registry", default=str(HERE / REGISTRY_NAME))
    ap.add_argument("--keystore", default=str(HERE / ".authority_keystore"))
    ap.add_argument("--validator-registry", default=str(HERE / VT.VALIDATOR_REGISTRY_NAME))
    ap.add_argument("--validator-keystore", default=str(HERE / VT.VALIDATOR_KEYSTORE_NAME))
    ap.add_argument(
        "--instant",
        default=None,
        help="logical evaluation instant (ISO-8601 Z) — required for ingestion",
    )
    ap.add_argument(
        "--emit-binding",
        action="store_true",
        help="print the attestation record_binding digest and exit (no ingest)",
    )
    args = ap.parse_args(argv)

    # Ingestion REQUIRES a valid evaluation instant (fail closed). Gate 3b
    # passes the instant through to verify_attestation_trust(), where the
    # attestation_future_dated check only runs when an instant exists — with
    # None, a signed attestation claiming a future validation time would be
    # ingested and could become ACTIVE later without another validation
    # ceremony. Only --emit-binding (no ingest, no trust evaluation) may run
    # without one.
    if not args.emit_binding and VT._parse_z(args.instant) is None:
        print(
            "FATAL: --instant (ISO-8601 Z, e.g. 2026-01-01T00:00:00Z) is required: "
            "attestation future-dating and freshness cannot be evaluated without "
            "an evaluation instant.",
            file=sys.stderr,
        )
        return 2

    rec_path, doc_path = Path(args.record), Path(args.document)
    if not rec_path.is_file():
        print(f"FATAL: record file not found: {rec_path}", file=sys.stderr)
        return 2
    if not doc_path.is_file():
        print(f"FATAL: source artifact not found: {doc_path}", file=sys.stderr)
        return 2

    record = json.loads(rec_path.read_text(encoding="utf-8"))
    doc_digest = sha256_hex(doc_path.read_bytes())

    # Gate 1 — the record must describe exactly this document.
    if record.get("source_digest") in (None, ""):
        record["source_digest"] = doc_digest
    elif record["source_digest"] != doc_digest:
        print(
            f"REJECTED: source_digest {record['source_digest'][:16]}… != "
            f"sha256(artifact) {doc_digest[:16]}…",
            file=sys.stderr,
        )
        return 3

    # Gate 2 — per-class real-artifact contract.
    try:
        validate_onboarding_record(record)
    except OnboardingError as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 3

    if args.emit_binding:
        print(attestation_binding(record))
        return 0

    # Gate 3 — the human validation attestation.
    if not has_valid_attestation(record):
        print("NOT VALIDATED: lifecycle_state = DISCOVERED")
        print(
            "  a well-formed `validation` attestation (validator_identity, "
            "validation_method, validated_at, record_binding) is required before ingest."
        )
        print(f"  expected record_binding: {attestation_binding(record)}")
        print("  this tool never writes the attestation itself — a human validator does.")
        return 4

    # Gate 3b — VALIDATOR_TRUST_GOVERNANCE_V1: the attestation's validator must
    # be registered, authorized for this evidence class, valid at validated_at,
    # and the attestation signature intact. An empty validator registry trusts
    # nobody — fail closed. This tool never writes attestations or registry
    # events; it only verifies them.
    events = VT.load_validator_events(Path(args.validator_registry))
    for att in [record.get("validation"), *(record.get("co_validations") or [])]:
        if att is None:
            continue
        # The onboarding instant is passed through so attestation_future_dated
        # runs: a validated_at in the future of --instant must leave the
        # registry untouched instead of pre-authorizing a later activation.
        ok, reason = VT.verify_attestation_trust(
            record,
            att,
            events=events,
            keystore_dir=Path(args.validator_keystore),
            instant=args.instant,
        )
        if not ok:
            print(f"VALIDATOR TRUST FAILED: {reason}", file=sys.stderr)
            print(
                "  the validator behind this attestation could not be authorized "
                "(registration, class, validity window, key, or signature). "
                "Onboard the validator via onboard_validator.py first.",
                file=sys.stderr,
            )
            return 5

    # Gate 4 — receipted, idempotent ingest via the trusted V1 path. The
    # attested record (with bound source_digest) is passed through a unique
    # temp file (never a deterministic sibling name that could clobber and
    # then delete a user's file) so ingest re-validates exactly what we
    # checked.
    fd, staged_name = tempfile.mkstemp(
        dir=str(rec_path.parent), prefix=rec_path.stem + ".", suffix=".staged.json"
    )
    staged = Path(staged_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True, ensure_ascii=False))
        rc = ingest.main(
            [
                "--record",
                str(staged),
                "--document",
                str(doc_path),
                "--registry",
                args.registry,
                "--keystore",
                args.keystore,
                *(["--instant", args.instant] if args.instant else []),
            ]
        )
    finally:
        staged.unlink(missing_ok=True)
    if rc != 0:
        return rc

    # Report the derived post-ingest lifecycle state.
    registry = read_registry(Path(args.registry))
    sids = superseded_ids_of(registry, args.instant)
    mine = next(
        (r for r in registry if r.get("authority_evidence_id") == record["authority_evidence_id"]),
        record,
    )
    manifest = json.loads((HERE / "substrate_identity.json").read_text(encoding="utf-8"))
    require_substrate_binding(manifest.get("substrate_id"), manifest.get("critical_set_digest"))
    state = VT.derive_governed_state(
        mine,
        instant=args.instant,
        superseded_ids=sids,
        in_registry=True,
        events=events,
        keystore_dir=Path(args.validator_keystore),
        policy=VT.load_policy(HERE / VT.POLICY_NAME),
        receipt_key=load_or_create_key(Path(args.keystore)),
        substrate_identity=manifest["substrate_id"],
        substrate_digest=manifest["critical_set_digest"],
        revoked_ids=revoked_ids_of(registry),
    )
    print(f"lifecycle_state = {state}")
    if state != "ACTIVE":
        print("  (ingested but not ACTIVE at this instant — routing will not use it)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
