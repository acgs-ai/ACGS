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
import os
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from _canonical import sha256_hex
from _identity import MANIFEST_NAME
from _registry import REGISTRY_NAME, append_record, read_registry
from authority_receipt import (
    ReceiptError,
    load_or_create_key,
    mint_receipt,
    require_substrate_binding,
)
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
    # Snapshot the document bytes EXACTLY ONCE: hashing one read and retaining
    # a later re-read is a TOCTOU window in which the file can be swapped,
    # producing a retained artifact that does not match the bound digest.
    doc_bytes = doc_path.read_bytes()
    return ingest_record(
        record,
        doc_bytes,
        registry=Path(args.registry),
        keystore=Path(args.keystore),
        instant=args.instant,
    )


def ingest_record(
    record: dict[str, Any],
    doc_bytes: bytes,
    *,
    registry: Path,
    keystore: Path,
    instant: str | None = None,
) -> int:
    """Ingest an already-loaded record against pinned document bytes.

    Callers that have ALREADY gated a record (the onboarding pipeline) pass
    the object and the document bytes directly. Re-opening a staged pathname
    here would reopen a swap window: a writer to that directory could
    substitute a different, merely schema-valid record between the caller's
    gates and this ingest, minting a receipt for evidence that never passed
    onboarding or validator trust.
    """
    reg_path = registry
    doc_digest = sha256_hex(doc_bytes)

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

    # Identity authorization precedes every registry outcome, including an
    # idempotent no-op. A malformed current manifest must never be reported as
    # successful merely because matching evidence was already recorded.
    try:
        manifest = json.loads((HERE / MANIFEST_NAME).read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ReceiptError("substrate identity manifest must be a JSON object")
        require_substrate_binding(manifest.get("substrate_id"), manifest.get("critical_set_digest"))
    except (OSError, json.JSONDecodeError, ReceiptError) as exc:
        print(f"REJECTED: invalid substrate identity manifest: {exc}", file=sys.stderr)
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
                        f"IDEMPOTENT: {record['authority_evidence_id']} already ingested; no change"
                    )
                    return 0
                print(
                    f"REJECTED: {record['authority_evidence_id']} already exists with a "
                    f"different source_digest — one logical authority fact only",
                    file=sys.stderr,
                )
                return 3

        key = load_or_create_key(keystore)
        receipt = mint_receipt(
            key,
            request_id=f"INGEST::{record['authority_evidence_id']}",
            prior_state="ABSENT",
            new_state="INGESTED",
            authority_subject=record["subject_identity"],
            authority_evidence_id=record["authority_evidence_id"],
            evidence_digest=record["source_digest"],
            authority_scope=record["authority_scope"],
            substrate_identity=manifest["substrate_id"],
            substrate_critical_set_digest=manifest["critical_set_digest"],
            decision="INGEST",
            decision_reason=(
                f"{record['authority_type']} evidence recorded from {record['source_type']}"
            ),
            created_at=instant or record.get("effective_from", ""),
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
        #
        # The store is written through a PINNED directory descriptor with
        # no-follow semantics: a `.authority_artifacts` path replaced by a
        # symlink would be accepted by mkdir(exist_ok=True) and redirect the
        # write outside the store, and a dangling symlink planted at the
        # digest path would be followed by write_bytes() after exists()
        # returned False. O_DIRECTORY|O_NOFOLLOW refuses a symlinked store;
        # O_CREAT|O_EXCL|O_NOFOLLOW against the pinned descriptor refuses any
        # pre-planted digest-path symlink (dangling or not).
        artifact_dir = reg_path.parent / ".authority_artifacts"
        try:
            os.mkdir(artifact_dir)
        except FileExistsError:
            pass
        try:
            dir_fd = os.open(artifact_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as exc:
            print(
                f"FATAL: artifact store is not a real directory (symlinked or "
                f"unreadable) — refusing to retain: {exc}",
                file=sys.stderr,
            )
            return 2
        try:
            try:
                artifact_fd = os.open(
                    record["source_digest"],
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o666,
                    dir_fd=dir_fd,
                )
            except FileExistsError:
                # An entry already occupies the digest path. Only a REGULAR
                # file counts as retained: a pre-planted symlink (dangling or
                # not) is an attempted redirect, not a retained artifact.
                st = os.lstat(record["source_digest"], dir_fd=dir_fd)
                if not stat.S_ISREG(st.st_mode):
                    print(
                        "FATAL: artifact digest path is occupied by a "
                        "non-regular file (pre-planted symlink?) — refusing "
                        "to ingest",
                        file=sys.stderr,
                    )
                    return 2
                # Retained means BYTES-VERIFIED, not merely present: a partial
                # file left by an interrupted earlier write (or a preplanted
                # wrong-content file) would fail source_artifact_intact
                # forever, while every later same-id ingest returns the
                # idempotent path before reaching this code. Re-hash the
                # occupant and atomically repair it from the verified source
                # document (still under the registry lock) before appending.
                rf = os.open(record["source_digest"], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
                with os.fdopen(rf, "rb") as fh:
                    retained_digest = sha256_hex(fh.read())
                if retained_digest != record["source_digest"]:
                    tmp_name = "." + record["source_digest"] + ".repair"
                    try:
                        os.unlink(tmp_name, dir_fd=dir_fd)
                    except FileNotFoundError:
                        pass
                    wf = os.open(
                        tmp_name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o666,
                        dir_fd=dir_fd,
                    )
                    with os.fdopen(wf, "wb") as fh:
                        fh.write(doc_bytes)
                        fh.flush()
                        os.fsync(fh.fileno())
                    os.replace(
                        tmp_name,
                        record["source_digest"],
                        src_dir_fd=dir_fd,
                        dst_dir_fd=dir_fd,
                    )
            except OSError as exc:
                print(
                    f"FATAL: cannot retain source artifact (symlinked digest "
                    f"path?) — refusing to ingest: {exc}",
                    file=sys.stderr,
                )
                return 2
            else:
                with os.fdopen(artifact_fd, "wb") as fh:
                    fh.write(doc_bytes)
        finally:
            os.close(dir_fd)

        append_record(reg_path, record)
    print(f"INGESTED: {record['authority_evidence_id']}")
    print(f"  authority_type   : {record['authority_type']}")
    print(f"  source_digest    : {record['source_digest']}")
    print(f"  ingestion_receipt: {receipt['receipt_id']}")
    print("  note             : recording authority is not asserting a commercial right")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
