#!/usr/bin/env python3
"""Ingest one external authority-evidence record. Idempotent and receipted.

The record names a real source document; this tool hashes that document and
binds the digest into the record, validates the record's shape, refuses to
fabricate anything, mints an ingestion receipt, and appends the record to the
package registry. It NEVER writes into the substrate and NEVER sets a
rights_assertion.

Idempotency (invariant, Section 14): re-ingesting the same
(authority_evidence_id + source_digest) is a no-op that reports the existing
record. The same id with a DIFFERENT source_digest is a conflict and is
rejected — one logical authority fact, not many.

Usage:
    python3 ingest_authority_evidence.py --record REC.json --document DOC \\
        [--registry PATH] [--keystore PATH] [--instant ISO8601]

An empty registry is a valid, correct state; do not ingest fabricated records
to make it non-empty.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import sys
from contextlib import contextmanager
from pathlib import Path

from _canonical import sha256_hex
from _identity import MANIFEST_NAME
from _registry import REGISTRY_NAME, append_record, read_registry
from authority_receipt import load_or_create_key, mint_receipt
from authority_router import validate_evidence

HERE = Path(__file__).resolve().parent


@contextmanager
def _registry_lock(reg_path: Path):
    """Exclusive cross-process lock on a sidecar next to the registry.

    The conflict check (same id, different source_digest), artifact retention,
    and the registry append must be ONE critical section: two concurrent
    ingests that both read the registry before either appended would each
    pass the check and append conflicting records for the same
    authority_evidence_id — exactly the 'one logical authority fact' invariant
    this tool enforces. flock releases on close (and on process death)."""
    reg_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = reg_path.parent / (reg_path.name + ".lock")
    with lock_path.open("a", encoding="utf-8") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Ingest one authority-evidence record.")
    ap.add_argument("--record", required=True, help="JSON file with the evidence record")
    ap.add_argument("--document", required=True, help="the real source document (bytes hashed)")
    ap.add_argument("--registry", default=str(HERE / REGISTRY_NAME))
    ap.add_argument("--keystore", default=str(HERE / ".authority_keystore"))
    ap.add_argument("--instant", default=None, help="logical ingestion instant (ISO8601)")
    args = ap.parse_args(argv)

    rec_path, doc_path = Path(args.record), Path(args.document)
    reg_path = Path(args.registry)
    if not rec_path.is_file():
        print(f"FATAL: record file not found: {rec_path}", file=sys.stderr)
        return 2
    if not doc_path.is_file():
        print(
            f"FATAL: source document not found: {doc_path} (a real source is required)",
            file=sys.stderr,
        )
        return 2

    record = json.loads(rec_path.read_text(encoding="utf-8"))
    doc_digest = sha256_hex(doc_path.read_bytes())

    # Bind / cross-check the source digest against the actual document.
    if record.get("source_digest") in (None, ""):
        record["source_digest"] = doc_digest
    elif record["source_digest"] != doc_digest:
        print(
            f"REJECTED: source_digest {record['source_digest']} != sha256(document) {doc_digest}",
            file=sys.stderr,
        )
        return 3

    try:
        validate_evidence(record)
    except Exception as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 3

    # The conflict check, receipt mint, artifact retention, and registry
    # append form ONE serialized critical section: without it, two concurrent
    # ingests of the same authority_evidence_id with different documents could
    # both pass the read-then-check and both append — a duplicate-id registry
    # the conflict rule exists to prevent.
    with _registry_lock(reg_path):
        existing = read_registry(reg_path)
        for e in existing:
            if e.get("authority_evidence_id") == record["authority_evidence_id"]:
                if e.get("source_digest") == record["source_digest"]:
                    print(
                        f"IDEMPOTENT: {record['authority_evidence_id']} already ingested; "
                        "no change"
                    )
                    return 0
                print(
                    f"REJECTED: {record['authority_evidence_id']} already exists with a "
                    f"different source_digest — one logical authority fact only",
                    file=sys.stderr,
                )
                return 3

        key = load_or_create_key(Path(args.keystore))
        manifest = json.loads((HERE / MANIFEST_NAME).read_text(encoding="utf-8"))
        receipt = mint_receipt(
            key,
            request_id=f"INGEST::{record['authority_evidence_id']}",
            prior_state="ABSENT",
            new_state="INGESTED",
            authority_subject=record["subject_identity"],
            authority_evidence_id=record["authority_evidence_id"],
            evidence_digest=record["source_digest"],
            authority_scope=record["authority_scope"],
            substrate_critical_set_digest=manifest["critical_set_digest"],
            decision="INGEST",
            decision_reason=(
                f"{record['authority_type']} evidence recorded from {record['source_type']}"
            ),
            created_at=args.instant or record.get("effective_from", ""),
        )
        record.setdefault("ingested_by", "ingest_authority_evidence.py")
        record["ingestion_receipt"] = receipt["receipt_id"]
        # Retain the FULL signed receipt on the record: downstream trust
        # derivation re-verifies it against the authority receipt key, so a
        # registry writer cannot fake ingestion with a receipt-shaped string.
        record["ingestion_receipt_record"] = receipt

        # Retain the source-document bytes next to the registry so the digest
        # stays independently re-verifiable: routing eligibility re-hashes the
        # retained artifact (source_artifact_intact) instead of trusting a bare
        # digest string whose source may have moved or changed.
        artifact_dir = reg_path.parent / ".authority_artifacts"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        artifact = artifact_dir / record["source_digest"]
        if not artifact.exists():
            artifact.write_bytes(doc_path.read_bytes())

        append_record(reg_path, record)
    print(f"INGESTED: {record['authority_evidence_id']}")
    print(f"  authority_type   : {record['authority_type']}")
    print(f"  source_digest    : {record['source_digest']}")
    print(f"  ingestion_receipt: {receipt['receipt_id']}")
    print("  note             : recording authority is not asserting a commercial right")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
